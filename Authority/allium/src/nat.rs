//! NAT traversal for relays: authority-brokered UDP hole-punching.
//!
//! Port of Python's `nat.py`. See the Python module's docstring for the full
//! design rationale (registration keep-alive with a directory authority,
//! introducer-brokered `PUNCH_REQUEST`/`PUNCH_NOTIFY`/`PUNCH_REPLY`).
//!
//! Not re-exported at the `allium` crate root: Python's `allium/__init__.py`
//! does not import from `.nat` either, so this module is `pub mod nat;`
//! only (see `lib.rs`).
//!
//! ## Ed25519 signing (written but unverified pending real cargo build)
//!
//! Every message that makes a peer act (`REGISTER`, `REGISTERED`,
//! `PUNCH_NOTIFY`, `PUNCH_REPLY`) is Ed25519-signed. Per the dependency
//! policy, this uses the real `ed25519-dalek` crate (already
//! added to `allium/Cargo.toml` for `handshake.rs`) rather than a hand-rolled
//! implementation -- [`real_sign`], [`real_verify`], [`real_public_of`] are
//! the three small functions that touch it, carefully written against
//! `ed25519-dalek` 2.x's documented `SigningKey`/`VerifyingKey`/`Signer`/
//! `Verifier` API, but unbuildable/untestable in this sandbox (no crates.io
//! access -- see the note atop `Cargo.toml`).
//!
//! Everything else in this module -- wire encode/decode, [`NatRendezvous`]'s
//! and [`NatAgent`]'s registration/rate-limit/replay/TTL state machines --
//! is real-crate-agnostic: [`Ed25519Ops`] bundles the three signing
//! operations as injected closures (the same dependency-injection pattern
//! `crypto.rs`'s `SaltAead` uses for AEAD), so that logic is fully testable
//! here against a fake, deterministic (HMAC-based, insecure) signer -- see
//! the tests module's `recording_fake_ops()`.

#[cfg(test)]
use crate::hashutil::hmac_sha256;
use crate::policy::RateLimiter;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

pub const NAT_MAGIC: &[u8; 4] = b"ALNT";

pub const REGISTER: u8 = 1;
pub const REGISTERED: u8 = 2;
pub const PUNCH_REQUEST: u8 = 3;
pub const PUNCH_NOTIFY: u8 = 4;
pub const PUNCH_REPLY: u8 = 5;
pub const PUNCH: u8 = 6;
/// `REGISTER_CONFIRM` (relay -> authority): not part of the ported Python
/// protocol -- a deliberate addition closing a real gap (see the doc
/// comment on `NatRendezvous::on_register`'s pending-registration state):
/// the original `REGISTER` bound an identity to whatever raw UDP source
/// address a packet arrived from, with no proof the sender actually
/// receives there, unlike the CREATE handshake's own
/// `require_return_routability` check elsewhere in this codebase. A
/// relay running against an authority still on the old two-message
/// (`REGISTER`/`REGISTERED`) protocol will register but never confirm,
/// so it silently stays unreachable for PUNCH -- every node that runs
/// `--behind-nat` must be upgraded together.
pub const REGISTER_CONFIRM: u8 = 7;

pub const STATUS_OK: u8 = 0;
pub const STATUS_TARGET_UNKNOWN: u8 = 1;
pub const STATUS_PEER_UNKNOWN: u8 = 2;
pub const STATUS_RATE_LIMITED: u8 = 3;

/// How often a NAT relay refreshes its registration, in seconds.
pub const REGISTER_INTERVAL: f64 = 15.0;
/// A registration not refreshed within this long is treated as gone.
pub const REGISTRATION_TTL: f64 = 60.0;
/// How long a REGISTER's challenge nonce stays valid, waiting for a
/// matching REGISTER_CONFIRM, before the pending entry is dropped.
/// Generous for a real round trip, short enough to bound how much
/// unconfirmed state (and reflected REGISTERED traffic, see
/// `on_register`'s doc comment) an attacker can keep alive.
pub const PENDING_REGISTRATION_TTL: f64 = 10.0;
/// Signed timestamps further than this from local time are rejected.
pub const MAX_CLOCK_SKEW: f64 = 120.0;
/// Punch datagrams sent per notify.
pub const PUNCH_COUNT: usize = 3;

const NONCE_LEN: usize = 16;
const KEY_LEN: usize = 32;
const SIG_LEN: usize = 64;
const MAX_HOST: usize = 255;
const MAX_REGISTRATIONS: usize = 4096;
const MAX_PENDING_REGISTRATIONS: usize = 4096;

/// Reachability extension mode byte.
pub const MODE_NAT: u8 = 1;

pub type Addr = (String, u16);

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

/// A NAT-traversal message was malformed, unsigned, stale or refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatError {
    pub message: String,
}
impl fmt::Display for NatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for NatError {}
fn err(msg: impl Into<String>) -> NatError {
    NatError { message: msg.into() }
}

// --------------------------------------------------------------------------
// Ed25519 injection point (see module docs)
// --------------------------------------------------------------------------

// `+ Send` (2026-09-26, finding MH2): needed so an `Ed25519Ops`/
// `NatAgent`/`NatRendezvous` can move into the dedicated OS thread
// `directory::register_over_circuit`'s blocking `CircuitBuilder` call
// runs on, the same way `Directory`'s own `clock: Box<dyn Fn() -> f64 +
// Send>` and `handshake::X25519GenFn` already require it. Matches how a
// real `ed25519-dalek`-backed closure (or a plain fn pointer, as this
// module's tests now use) is trivially thread-safe in practice; only the
// trait object's own bound was missing.
pub type SignFn = Box<dyn Fn(&[u8; KEY_LEN], &[u8]) -> [u8; SIG_LEN] + Send>;
pub type VerifyFn = Box<dyn Fn(&[u8; KEY_LEN], &[u8], &[u8; SIG_LEN]) -> bool + Send>;
pub type PublicOfFn = Box<dyn Fn(&[u8; KEY_LEN]) -> [u8; KEY_LEN] + Send>;
/// Security audit fix (2026-09-26, finding MH2 -- PUNCH_NOTIFY/PUNCH_REQUEST/
/// PUNCH_REPLY): the X25519 primitives backing [`seal_static`]/[`open_static`]
/// (recipient-authenticated sealing, for `PUNCH_NOTIFY` between two parties
/// who already know each other's key from `REGISTER`) and
/// [`seal_ephemeral`]/[`open_ephemeral_raw`] (anonymous-sender sealing, for
/// `PUNCH_REQUEST`/`PUNCH_REPLY` -- the same shape as
/// `hiddenservice::seal_introduce`/`open_introduce_raw`, ported here rather
/// than reused directly so this module's own error type and domain-
/// separation labels stay self-contained).
pub type X25519GenFn = Box<dyn Fn() -> [u8; KEY_LEN] + Send>;
pub type X25519PublicFn = Box<dyn Fn(&[u8; KEY_LEN]) -> [u8; KEY_LEN] + Send>;
pub type X25519DhFn = Box<dyn Fn(&[u8; KEY_LEN], &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN], NatError> + Send>;

/// The Ed25519 and X25519 primitives this module needs, injected as
/// closures so [`NatRendezvous`] / [`NatAgent`] logic is testable without
/// real cryptography. Construct with [`Ed25519Ops::real`] for production
/// use (real-crate-backed, unverified in this sandbox).
pub struct Ed25519Ops {
    pub sign: SignFn,
    pub verify: VerifyFn,
    pub public_of: PublicOfFn,
    pub x25519_generate: X25519GenFn,
    pub x25519_public: X25519PublicFn,
    pub x25519_dh: X25519DhFn,
}

impl Ed25519Ops {
    /// Real, `ed25519-dalek`/`x25519-dalek`-backed implementation.
    ///
    /// Written but unverified pending real cargo build (see module docs):
    /// this sandbox cannot fetch `ed25519-dalek`, so this cannot be
    /// compiled/tested here, but was carefully reviewed against its
    /// documented, stable 2.x API (`SigningKey::from_bytes`,
    /// `SigningKey::sign`, `VerifyingKey::from_bytes`, `VerifyingKey::verify`,
    /// the `Signer`/`Verifier` traits from the `signature` crate it
    /// re-exports).
    pub fn real() -> Ed25519Ops {
        Ed25519Ops {
            sign: Box::new(real_sign),
            verify: Box::new(real_verify),
            public_of: Box::new(real_public_of),
            x25519_generate: Box::new(real_x25519_generate),
            x25519_public: Box::new(real_x25519_public),
            x25519_dh: Box::new(real_x25519_dh),
        }
    }
}

fn real_sign(private: &[u8; KEY_LEN], message: &[u8]) -> [u8; SIG_LEN] {
    use ed25519_dalek::{Signer, SigningKey};
    let key = SigningKey::from_bytes(private);
    key.sign(message).to_bytes()
}

fn real_verify(public: &[u8; KEY_LEN], message: &[u8], sig: &[u8; SIG_LEN]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let key = match VerifyingKey::from_bytes(public) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(sig);
    key.verify(message, &signature).is_ok()
}

fn real_public_of(private: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    use ed25519_dalek::SigningKey;
    let key = SigningKey::from_bytes(private);
    key.verifying_key().to_bytes()
}

fn real_x25519_generate() -> [u8; KEY_LEN] {
    use x25519_dalek::StaticSecret;
    StaticSecret::random_from_rng(rand_core::OsRng).to_bytes()
}

fn real_x25519_public(private: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    use x25519_dalek::{PublicKey, StaticSecret};
    PublicKey::from(&StaticSecret::from(*private)).to_bytes()
}

fn real_x25519_dh(private: &[u8; KEY_LEN], peer_public: &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN], NatError> {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(*private);
    let shared = secret.diffie_hellman(&PublicKey::from(*peer_public));
    if !shared.was_contributory() {
        return Err(err("peer public key is unusable (low-order point)"));
    }
    Ok(*shared.as_bytes())
}

// --------------------------------------------------------------------------
// Sealing (PUNCH_NOTIFY/PUNCH_REQUEST/PUNCH_REPLY envelopes)
// --------------------------------------------------------------------------

const L_SEAL: &[u8] = b"allium-nat-seal-v1";
const L_PUNCH_SESSION: &[u8] = b"allium-nat-punch-session-v1";

fn seal_with_shared(shared: &[u8], associated_data: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, NatError> {
    let key: [u8; 32] =
        crate::hashutil::hkdf_sha256(shared, L_SEAL, b"seal-key", 32).try_into().map_err(|_| err("hkdf produced the wrong key length"))?;
    let mut aead = crate::crypto::new_aead("chacha20-poly1305", key, None).map_err(|e| err(e.to_string()))?;
    aead.seal(plaintext, associated_data).map_err(|e| err(e.to_string()))
}

fn open_sealed(shared: &[u8], associated_data: &[u8], sealed: &[u8]) -> Result<Vec<u8>, NatError> {
    let key: [u8; 32] =
        crate::hashutil::hkdf_sha256(shared, L_SEAL, b"seal-key", 32).try_into().map_err(|_| err("hkdf produced the wrong key length"))?;
    let aead = crate::crypto::new_aead("chacha20-poly1305", key, None).map_err(|e| err(e.to_string()))?;
    aead.open(sealed, associated_data).map_err(|_| err("NAT envelope did not authenticate"))
}

/// Static-static ECDH seal, for `PUNCH_NOTIFY`: both the introducer and the
/// recipient relay hold long-term X25519 keys already known to each other
/// (the relay's own, learned from its `REGISTER`; the introducer's, pinned
/// by the relay ahead of time). Only the real `sender_private` holder can
/// produce the shared secret `recipient_public`'s own matching private key
/// requires to open it -- this implicitly authenticates the sender, so no
/// separate signature is needed the way the original plaintext-then-signed
/// protocol used one.
fn seal_static(ops: &Ed25519Ops, sender_private: &[u8; KEY_LEN], recipient_public: &[u8; KEY_LEN], associated_data: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, NatError> {
    let shared = (ops.x25519_dh)(sender_private, recipient_public)?;
    seal_with_shared(&shared, associated_data, plaintext)
}

/// Inverse of [`seal_static`], given the raw recipient private key.
fn open_static(ops: &Ed25519Ops, recipient_private: &[u8; KEY_LEN], sender_public: &[u8; KEY_LEN], associated_data: &[u8], sealed: &[u8]) -> Result<Vec<u8>, NatError> {
    let shared = (ops.x25519_dh)(recipient_private, sender_public)?;
    open_sealed(&shared, associated_data, sealed)
}

/// Try `open_static` against each of several pinned sender keys in turn
/// (authority X25519-key-rotation support, matching the existing
/// `keys: Vec<[u8; KEY_LEN]>` Ed25519 pin list's same "trust any of
/// several currently-valid keys" shape) until one authenticates.
fn open_static_any(ops: &Ed25519Ops, recipient_private: &[u8; KEY_LEN], trusted_sender_keys: &[[u8; KEY_LEN]], associated_data: &[u8], sealed: &[u8]) -> Result<Vec<u8>, NatError> {
    for sender_public in trusted_sender_keys {
        if let Ok(plaintext) = open_static(ops, recipient_private, sender_public, associated_data, sealed) {
            return Ok(plaintext);
        }
    }
    Err(err("NAT envelope did not authenticate against any pinned introducer key"))
}

/// Derive the two AEAD keys for one `PUNCH_REQUEST`/`PUNCH_REPLY` exchange
/// from the raw ECDH shared secret both sides independently compute
/// (`DH(client_ephemeral_private, introducer_public) ==
/// DH(introducer_private, client_ephemeral_public)`) -- separate keys per
/// direction, so sealing the reply never reuses the exact key (and nonce
/// space) that sealed the request.
fn punch_session_keys(shared: &[u8]) -> Result<([u8; 32], [u8; 32]), NatError> {
    let request_key: [u8; 32] =
        crate::hashutil::hkdf_sha256(shared, L_PUNCH_SESSION, b"request", 32).try_into().map_err(|_| err("hkdf produced the wrong key length"))?;
    let reply_key: [u8; 32] =
        crate::hashutil::hkdf_sha256(shared, L_PUNCH_SESSION, b"reply", 32).try_into().map_err(|_| err("hkdf produced the wrong key length"))?;
    Ok((request_key, reply_key))
}

// --------------------------------------------------------------------------
// Descriptor extension
// --------------------------------------------------------------------------

/// `(mode, introducer_identity, introducer_x25519_public, introducer_host,
/// introducer_port)`.
///
/// Security audit fix (2026-09-26, finding MH2): carries the introducer's
/// long-term X25519 key alongside its Ed25519 identity, the same way
/// `REGISTER` now carries a relay's -- `PUNCH_REQUEST`/`PUNCH_REPLY` between
/// a client and this introducer are sealed (see `nat.rs`'s module doc), and
/// the descriptor extension this decodes is already authenticated end to
/// end (the relay's own signed descriptor), so it's a safe place to hand
/// clients a trust anchor for that key without a separate lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reachability {
    pub mode: u8,
    pub introducer_identity: Vec<u8>,
    pub introducer_x25519_public: Vec<u8>,
    pub introducer_host: String,
    pub introducer_port: u16,
}
impl Reachability {
    pub fn introducer_addr(&self) -> Addr {
        (self.introducer_host.clone(), self.introducer_port)
    }
}

fn pack_addr(host: &str, port: u16) -> Result<Vec<u8>, NatError> {
    let raw = host.as_bytes();
    if raw.len() > MAX_HOST {
        return Err(err("host too long"));
    }
    let mut out = Vec::with_capacity(1 + raw.len() + 2);
    out.push(raw.len() as u8);
    out.extend_from_slice(raw);
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

fn unpack_addr(data: &[u8], offset: usize) -> Result<(Addr, usize), NatError> {
    if data.len() < offset + 1 {
        return Err(err("truncated address"));
    }
    let n = data[offset] as usize;
    let offset = offset + 1;
    if data.len() < offset + n + 2 {
        return Err(err("truncated address"));
    }
    let host = std::str::from_utf8(&data[offset..offset + n]).map_err(|_| err("bad address encoding"))?.to_string();
    let port = u16::from_be_bytes([data[offset + n], data[offset + n + 1]]);
    Ok(((host, port), offset + n + 2))
}

/// The value of a descriptor's EXT_REACHABILITY extension for a NAT relay.
pub fn encode_reachability(introducer_identity: &[u8], introducer_x25519_public: &[u8], introducer_host: &str, introducer_port: u16) -> Result<Vec<u8>, NatError> {
    if introducer_identity.len() != KEY_LEN || introducer_x25519_public.len() != KEY_LEN {
        return Err(err("introducer identity/x25519 key must be 32 bytes"));
    }
    let mut out = vec![MODE_NAT];
    out.extend_from_slice(introducer_identity);
    out.extend_from_slice(introducer_x25519_public);
    out.extend(pack_addr(introducer_host, introducer_port)?);
    Ok(out)
}

pub fn decode_reachability(value: &[u8]) -> Result<Reachability, NatError> {
    if value.len() < 1 + KEY_LEN + KEY_LEN + 3 || value[0] != MODE_NAT {
        return Err(err("unsupported reachability extension"));
    }
    let identity = value[1..1 + KEY_LEN].to_vec();
    let x25519_public = value[1 + KEY_LEN..1 + 2 * KEY_LEN].to_vec();
    let ((host, port), end) = unpack_addr(value, 1 + 2 * KEY_LEN)?;
    if end != value.len() {
        return Err(err("trailing bytes in reachability extension"));
    }
    Ok(Reachability { mode: MODE_NAT, introducer_identity: identity, introducer_x25519_public: x25519_public, introducer_host: host, introducer_port: port })
}

// --------------------------------------------------------------------------
// Signing helpers / wire header
// --------------------------------------------------------------------------

const L_REGISTER: &[u8] = b"allium-nat-register-v1";
const L_REGISTERED: &[u8] = b"allium-nat-registered-v1";
const L_REGISTER_CONFIRM: &[u8] = b"allium-nat-register-confirm-v1";

pub fn is_nat_message(datagram: &[u8]) -> bool {
    datagram.len() >= 5 && &datagram[..4] == NAT_MAGIC
}

fn header(msg_type: u8) -> Vec<u8> {
    let mut out = NAT_MAGIC.to_vec();
    out.push(msg_type);
    out
}

fn fresh(ts: f64, now: f64) -> bool {
    (ts - now).abs() <= MAX_CLOCK_SKEW
}

fn label_body(label: &[u8], body: &[u8]) -> Vec<u8> {
    let mut m = label.to_vec();
    m.extend_from_slice(body);
    m
}

// -- REGISTER (relay -> authority) ------------------------------------------

/// Build a signed `REGISTER` datagram. `now` defaults to `identity_private`'s
/// caller-supplied wall-clock reading (Python defaults to `time.time()`;
/// this port always takes it explicitly since a Rust library shouldn't read
/// the system clock implicitly inside a pure encode function).
///
/// Security audit fix (2026-09-26, finding MH2): `x25519_public` is new --
/// the relay's own long-term X25519 encryption key, so the introducer can
/// later seal `PUNCH_NOTIFY` to this relay specifically (see
/// [`seal_static`]). Safe to add here in cleartext-of-the-body-but-signed
/// form: `REGISTER` itself now only ever travels as onion-encrypted
/// circuit payload (see `directory::register_over_circuit`), not a raw UDP
/// datagram, so this key is never exposed to a passive on-path observer
/// either.
pub fn encode_register(identity_private: &[u8; KEY_LEN], x25519_public: &[u8; KEY_LEN], now: f64, ops: &Ed25519Ops) -> Vec<u8> {
    let identity = (ops.public_of)(identity_private);
    let mut body = identity.to_vec();
    body.extend_from_slice(x25519_public);
    body.extend_from_slice(&now.to_be_bytes());
    let sig = (ops.sign)(identity_private, &label_body(L_REGISTER, &body));
    let mut out = header(REGISTER);
    out.extend_from_slice(&body);
    out.extend_from_slice(&sig);
    out
}

fn decode_register(data: &[u8], ops: &Ed25519Ops) -> Result<([u8; KEY_LEN], [u8; KEY_LEN], f64), NatError> {
    let body = &data[5..];
    if body.len() != KEY_LEN + KEY_LEN + 8 + SIG_LEN {
        return Err(err("bad REGISTER length"));
    }
    let mut identity = [0u8; KEY_LEN];
    identity.copy_from_slice(&body[..KEY_LEN]);
    let mut x25519_public = [0u8; KEY_LEN];
    x25519_public.copy_from_slice(&body[KEY_LEN..KEY_LEN + KEY_LEN]);
    let ts = f64::from_be_bytes(body[KEY_LEN + KEY_LEN..KEY_LEN + KEY_LEN + 8].try_into().unwrap());
    let mut sig = [0u8; SIG_LEN];
    sig.copy_from_slice(&body[KEY_LEN + KEY_LEN + 8..]);
    if !(ops.verify)(&identity, &label_body(L_REGISTER, &body[..KEY_LEN + KEY_LEN + 8]), &sig) {
        return Err(err("REGISTER signature invalid"));
    }
    Ok((identity, x25519_public, ts))
}

// -- REGISTERED (authority -> relay) -----------------------------------------

/// `nonce` is the pending-registration challenge the relay must echo back
/// in a `REGISTER_CONFIRM` before `observed` is actually bound to
/// `identity` -- see `NatRendezvous::on_register`'s doc comment.
///
/// Security audit fix (2026-09-26, finding MH2): also carries this
/// authority's own X25519 public key, so the relay can learn (and later
/// republish in its own `EXT_REACHABILITY` extension, see
/// [`NatAgent::reachability_extension`]) the key a client needs to seal a
/// `PUNCH_REQUEST` to this same introducer.
fn encode_registered(authority_private: &[u8; KEY_LEN], authority_x25519_public: &[u8; KEY_LEN], identity: &[u8; KEY_LEN], observed: &Addr, now: f64, nonce: &[u8; NONCE_LEN], ops: &Ed25519Ops) -> Vec<u8> {
    let mut body = identity.to_vec();
    body.extend_from_slice(authority_x25519_public);
    body.extend_from_slice(&now.to_be_bytes());
    body.extend(pack_addr(&observed.0, observed.1).unwrap());
    body.extend_from_slice(nonce);
    body.extend_from_slice(&(ops.public_of)(authority_private));
    let sig = (ops.sign)(authority_private, &label_body(L_REGISTERED, &body));
    let mut out = header(REGISTERED);
    out.extend_from_slice(&body);
    out.extend_from_slice(&sig);
    out
}

// -- REGISTER_CONFIRM (relay -> authority) -----------------------------------

/// Echo `nonce` back, signed by the same identity key `REGISTER` used --
/// proof the relay actually received the `REGISTERED` challenge at the
/// address it claimed, closing the address-spoofing gap `REGISTER` alone
/// has. See `REGISTER_CONFIRM`'s doc comment.
fn encode_register_confirm(identity_private: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], now: f64, ops: &Ed25519Ops) -> Vec<u8> {
    let identity = (ops.public_of)(identity_private);
    let mut body = identity.to_vec();
    body.extend_from_slice(nonce);
    body.extend_from_slice(&now.to_be_bytes());
    let sig = (ops.sign)(identity_private, &label_body(L_REGISTER_CONFIRM, &body));
    let mut out = header(REGISTER_CONFIRM);
    out.extend_from_slice(&body);
    out.extend_from_slice(&sig);
    out
}

fn decode_register_confirm(data: &[u8], ops: &Ed25519Ops) -> Result<([u8; KEY_LEN], [u8; NONCE_LEN], f64), NatError> {
    let body = &data[5..];
    if body.len() != KEY_LEN + NONCE_LEN + 8 + SIG_LEN {
        return Err(err("bad REGISTER_CONFIRM length"));
    }
    let mut identity = [0u8; KEY_LEN];
    identity.copy_from_slice(&body[..KEY_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&body[KEY_LEN..KEY_LEN + NONCE_LEN]);
    let ts = f64::from_be_bytes(body[KEY_LEN + NONCE_LEN..KEY_LEN + NONCE_LEN + 8].try_into().unwrap());
    let mut sig = [0u8; SIG_LEN];
    sig.copy_from_slice(&body[KEY_LEN + NONCE_LEN + 8..]);
    if !(ops.verify)(&identity, &label_body(L_REGISTER_CONFIRM, &body[..KEY_LEN + NONCE_LEN + 8]), &sig) {
        return Err(err("REGISTER_CONFIRM signature invalid"));
    }
    Ok((identity, nonce, ts))
}

/// Return the verified body (without the trailing signer key).
fn decode_signed(data: &[u8], label: &[u8], trusted: &[[u8; KEY_LEN]], ops: &Ed25519Ops) -> Result<Vec<u8>, NatError> {
    if data.len() < 5 + KEY_LEN + SIG_LEN {
        return Err(err("message too short"));
    }
    let body = &data[5..data.len() - SIG_LEN];
    let sig_bytes = &data[data.len() - SIG_LEN..];
    let mut sig = [0u8; SIG_LEN];
    sig.copy_from_slice(sig_bytes);
    let signer = &body[body.len() - KEY_LEN..];
    if !trusted.iter().any(|k| k == signer) {
        return Err(err("message not signed by a trusted authority"));
    }
    let mut signer_key = [0u8; KEY_LEN];
    signer_key.copy_from_slice(signer);
    if !(ops.verify)(&signer_key, &label_body(label, body), &sig) {
        return Err(err("authority signature invalid"));
    }
    Ok(body[..body.len() - KEY_LEN].to_vec())
}

// -- PUNCH_REQUEST (client -> authority) -------------------------------------
//
// Security audit fix (2026-09-26, finding MH2): these three message types
// used to travel as a plaintext body (PUNCH_REQUEST) or an Ed25519-signed
// plaintext body (PUNCH_NOTIFY/PUNCH_REPLY). PUNCH_REQUEST's sender is
// deliberately anonymous (see `on_punch_request`'s doc, unchanged by this
// fix) with no persistent key of any kind, so it can't reuse REGISTER's
// fix (route over an already-authenticated onion circuit) -- it generates
// a fresh, one-time X25519 keypair per request instead and seals to the
// introducer's own pinned public key, the same anonymous-sender ECIES
// shape `hiddenservice::seal_introduce` already uses for INTRODUCE1.
// PUNCH_REPLY reuses the same request/reply session (via
// `punch_session_keys`, a separate derived key per direction so sealing
// the reply never reuses the exact key+nonce space the request used).

/// Returns `(message, nonce, client_ephemeral_private)`.
/// `client_ephemeral_private` is needed later to decrypt the `PUNCH_REPLY`
/// via [`decode_punch_reply`] -- generated fresh here (or supplied, for
/// deterministic tests) and never reused across requests, so issuing a
/// request creates no persistent identity for the requester.
pub fn encode_punch_request(
    target_identity: &[u8],
    peer_identity: &[u8],
    introducer_x25519_public: &[u8; KEY_LEN],
    client_ephemeral_private: Option<[u8; KEY_LEN]>,
    nonce: Option<[u8; NONCE_LEN]>,
    ops: &Ed25519Ops,
) -> Result<(Vec<u8>, [u8; NONCE_LEN], [u8; KEY_LEN]), NatError> {
    let nonce = match nonce {
        Some(n) => n,
        None => random_nonce()?,
    };
    let client_ephemeral_private = client_ephemeral_private.unwrap_or_else(|| (ops.x25519_generate)());
    if target_identity.len() != KEY_LEN || peer_identity.len() != KEY_LEN {
        return Err(err("identities must be 32 bytes"));
    }
    let client_ephemeral_public = (ops.x25519_public)(&client_ephemeral_private);
    let shared = (ops.x25519_dh)(&client_ephemeral_private, introducer_x25519_public)?;
    let (request_key, _reply_key) = punch_session_keys(&shared)?;
    let mut plaintext = target_identity.to_vec();
    plaintext.extend_from_slice(peer_identity);
    let mut ad = nonce.to_vec();
    ad.extend_from_slice(&client_ephemeral_public);
    let mut aead = crate::crypto::new_aead("chacha20-poly1305", request_key, None).map_err(|e| err(e.to_string()))?;
    let sealed = aead.seal(&plaintext, &ad).map_err(|e| err(e.to_string()))?;
    let mut out = header(PUNCH_REQUEST);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&client_ephemeral_public);
    out.extend_from_slice(&sealed);
    Ok((out, nonce, client_ephemeral_private))
}

fn random_nonce() -> Result<[u8; NONCE_LEN], NatError> {
    let mut buf = [0u8; NONCE_LEN];
    crate::osrand::os_random(&mut buf).map_err(|e| err(e.to_string()))?;
    Ok(buf)
}

/// Returns `(nonce, client_ephemeral_public, reply_key, target, peer)`.
/// `reply_key` is handed back so the caller can seal a [`encode_reply`]
/// without recomputing the ECDH a second time.
fn decode_punch_request(data: &[u8], introducer_x25519_private: &[u8; KEY_LEN], ops: &Ed25519Ops) -> Result<([u8; NONCE_LEN], [u8; KEY_LEN], [u8; 32], Vec<u8>, Vec<u8>), NatError> {
    let body = &data[5..];
    if body.len() < NONCE_LEN + KEY_LEN {
        return Err(err("bad PUNCH_REQUEST length"));
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&body[..NONCE_LEN]);
    let mut client_ephemeral_public = [0u8; KEY_LEN];
    client_ephemeral_public.copy_from_slice(&body[NONCE_LEN..NONCE_LEN + KEY_LEN]);
    let sealed = &body[NONCE_LEN + KEY_LEN..];
    let shared = (ops.x25519_dh)(introducer_x25519_private, &client_ephemeral_public)?;
    let (request_key, reply_key) = punch_session_keys(&shared)?;
    let mut ad = nonce.to_vec();
    ad.extend_from_slice(&client_ephemeral_public);
    let aead = crate::crypto::new_aead("chacha20-poly1305", request_key, None).map_err(|e| err(e.to_string()))?;
    let plaintext = aead.open(sealed, &ad).map_err(|_| err("PUNCH_REQUEST did not authenticate"))?;
    if plaintext.len() != 2 * KEY_LEN {
        return Err(err("bad PUNCH_REQUEST plaintext length"));
    }
    let target = plaintext[..KEY_LEN].to_vec();
    let peer = plaintext[KEY_LEN..].to_vec();
    Ok((nonce, client_ephemeral_public, reply_key, target, peer))
}

// -- PUNCH_NOTIFY (authority -> NAT relay) -----------------------------------

/// Seal a `PUNCH_NOTIFY` to `recipient_identity`'s own pinned X25519 key
/// (learned from its `REGISTER`, see [`encode_register`]'s doc). Static-
/// static ECDH between the introducer's and the recipient's long-term
/// keys implicitly authenticates the sender, so no separate signature is
/// needed the way the original plaintext-then-signed protocol used one.
fn encode_notify(ops: &Ed25519Ops, introducer_x25519_private: &[u8; KEY_LEN], recipient_identity: &[u8], recipient_x25519_public: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], peer_addr: &Addr, now: f64) -> Result<Vec<u8>, NatError> {
    let mut plaintext = now.to_be_bytes().to_vec();
    plaintext.extend(pack_addr(&peer_addr.0, peer_addr.1)?);
    let mut ad = nonce.to_vec();
    ad.extend_from_slice(recipient_identity);
    let sealed = seal_static(ops, introducer_x25519_private, recipient_x25519_public, &ad, &plaintext)?;
    let mut out = header(PUNCH_NOTIFY);
    out.extend_from_slice(nonce);
    out.extend_from_slice(recipient_identity);
    out.extend_from_slice(&sealed);
    Ok(out)
}

// -- PUNCH_REPLY (authority -> client) ---------------------------------------

/// Seal a `PUNCH_REPLY` with the `reply_key` [`decode_punch_request`]
/// already derived for this session -- a plain AEAD seal, no fresh ECDH
/// needed (the key is already session-specific and direction-separated).
fn encode_reply(reply_key: &[u8; 32], nonce: &[u8; NONCE_LEN], status: u8, target_addr: Option<&Addr>) -> Result<Vec<u8>, NatError> {
    let addr = match target_addr {
        Some(a) => pack_addr(&a.0, a.1)?,
        None => pack_addr("", 0)?,
    };
    let mut plaintext = vec![status];
    plaintext.extend(addr);
    let mut aead = crate::crypto::new_aead("chacha20-poly1305", *reply_key, None).map_err(|e| err(e.to_string()))?;
    let sealed = aead.seal(&plaintext, nonce).map_err(|e| err(e.to_string()))?;
    let mut out = header(PUNCH_REPLY);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Verify (via AEAD, not a signature -- see the module note above) a
/// `PUNCH_REPLY` and return `(status, Some((host, port)))` (or `(status,
/// None)` when `status != STATUS_OK`). `client_ephemeral_private` is the
/// same one-time key [`encode_punch_request`] generated for this request.
pub fn decode_punch_reply(data: &[u8], client_ephemeral_private: &[u8; KEY_LEN], introducer_x25519_public: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ops: &Ed25519Ops) -> Result<(u8, Option<Addr>), NatError> {
    if !is_nat_message(data) || data[4] != PUNCH_REPLY {
        return Err(err("not a PUNCH_REPLY"));
    }
    let body = &data[5..];
    if body.len() < NONCE_LEN || &body[..NONCE_LEN] != nonce {
        return Err(err("PUNCH_REPLY nonce mismatch"));
    }
    let sealed = &body[NONCE_LEN..];
    let shared = (ops.x25519_dh)(client_ephemeral_private, introducer_x25519_public)?;
    let (_request_key, reply_key) = punch_session_keys(&shared)?;
    let aead = crate::crypto::new_aead("chacha20-poly1305", reply_key, None).map_err(|e| err(e.to_string()))?;
    let plaintext = aead.open(sealed, nonce).map_err(|_| err("PUNCH_REPLY did not authenticate"))?;
    if plaintext.is_empty() {
        return Err(err("truncated PUNCH_REPLY"));
    }
    let status = plaintext[0];
    let (addr, end) = unpack_addr(&plaintext, 1)?;
    if end != plaintext.len() {
        return Err(err("trailing bytes in PUNCH_REPLY"));
    }
    Ok((status, if status == STATUS_OK { Some(addr) } else { None }))
}

// --------------------------------------------------------------------------
// Authority side
// --------------------------------------------------------------------------

pub type Outgoing = Vec<(Vec<u8>, Addr)>;

struct Registration {
    addr: Addr,
    last_seen: f64,
    last_register_ts: f64,
    /// The relay's own long-term X25519 key, learned from its `REGISTER`
    /// (see [`encode_register`]'s doc) -- needed to seal a `PUNCH_NOTIFY`
    /// to this specific relay.
    x25519_public: [u8; KEY_LEN],
}

/// A `REGISTER` that has been signature/freshness-checked but not yet
/// confirmed: `addr` is only a *claim* (the packet's raw UDP source) until
/// a matching `REGISTER_CONFIRM` proves the identity actually received
/// `nonce` there. See `NatRendezvous::on_register`'s doc comment.
struct PendingRegistration {
    addr: Addr,
    nonce: [u8; NONCE_LEN],
    register_ts: f64,
    created_at: f64,
    x25519_public: [u8; KEY_LEN],
}

/// Splits one injected `FnMut` clock into the original plus `n` shared
/// `policy::Clock` handles reading the same source, so a `RateLimiter`
/// refills against the same (possibly fake) time as the owner instead of
/// silently falling back to the real system clock.
fn share_clock(clock: Box<dyn FnMut() -> f64 + Send>) -> (Box<dyn FnMut() -> f64 + Send>, crate::policy::Clock, crate::policy::Clock) {
    let shared = Arc::new(Mutex::new(clock));
    let (a, b, c) = (Arc::clone(&shared), Arc::clone(&shared), shared);
    (
        Box::new(move || (c.lock().unwrap())()),
        Box::new(move || (a.lock().unwrap())()),
        Box::new(move || (b.lock().unwrap())()),
    )
}

/// The introducer role, run by a directory authority.
///
/// Pure logic (besides the injected [`Ed25519Ops`]): [`NatRendezvous::handle`]
/// takes one datagram and returns the datagrams to send, so it is testable
/// without sockets.
pub struct NatRendezvous {
    private: [u8; KEY_LEN],
    pub identity_public: [u8; KEY_LEN],
    /// Security audit fix (2026-09-26, finding MH2): this introducer's own
    /// long-term X25519 encryption key, used to seal `PUNCH_NOTIFY` to
    /// registered relays and to open `PUNCH_REQUEST`/seal `PUNCH_REPLY`
    /// for anonymous clients. Singular (no rotation support), matching
    /// `private`/`identity_public` above -- rotation, if ever needed, is a
    /// separate concern from this fix.
    x25519_private: [u8; KEY_LEN],
    pub x25519_public: [u8; KEY_LEN],
    lookup_relay: Box<dyn Fn(&[u8]) -> Option<Addr> + Send>,
    clock: Box<dyn FnMut() -> f64 + Send>,
    registrations: HashMap<Vec<u8>, Registration>,
    pending: HashMap<Vec<u8>, PendingRegistration>,
    /// Rate-limits `REGISTER` (authenticated, periodic, from a real
    /// relay). Kept separate from `punch_limiter` below -- sharing one
    /// IP-keyed bucket between the two let an attacker flood
    /// `PUNCH_REQUEST`s claiming a real relay's IP (spoofable; see
    /// `on_punch_request`'s own doc comment on that residual risk),
    /// exhausting that IP's bucket so the relay's own `REGISTER` was
    /// silently dropped too -- denying it the ability to register via NAT
    /// punch after its registration TTL expired.
    register_limiter: RateLimiter,
    /// Rate-limits `PUNCH_REQUEST` (anonymous, by design; see
    /// `on_punch_request`'s doc comment) separately from
    /// `register_limiter` above.
    punch_limiter: RateLimiter,
    ops: Ed25519Ops,
}

impl NatRendezvous {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity_private: [u8; KEY_LEN],
        x25519_private: [u8; KEY_LEN],
        lookup_relay: Box<dyn Fn(&[u8]) -> Option<Addr> + Send>,
        clock: Box<dyn FnMut() -> f64 + Send>,
        request_rate: f64,
        request_burst: u32,
        ops: Ed25519Ops,
    ) -> NatRendezvous {
        let identity_public = (ops.public_of)(&identity_private);
        let x25519_public = (ops.x25519_public)(&x25519_private);
        let (clock, register_clock, punch_clock) = share_clock(clock);
        NatRendezvous {
            private: identity_private,
            identity_public,
            x25519_private,
            x25519_public,
            lookup_relay,
            clock,
            registrations: HashMap::new(),
            pending: HashMap::new(),
            register_limiter: RateLimiter::new(request_rate, request_burst, Some(register_clock), None, None).expect("valid default rate/burst"),
            punch_limiter: RateLimiter::new(request_rate, request_burst, Some(punch_clock), None, None).expect("valid default rate/burst"),
            ops,
        }
    }

    pub fn registered_addr(&mut self, identity: &[u8]) -> Option<Addr> {
        let now = (self.clock)();
        let entry = self.registrations.get(identity)?;
        if now - entry.last_seen > REGISTRATION_TTL {
            return None;
        }
        Some(entry.addr.clone())
    }

    fn evict(&mut self) {
        let now = (self.clock)();
        let stale: Vec<Vec<u8>> = self.registrations.iter().filter(|(_, v)| now - v.last_seen > REGISTRATION_TTL).map(|(k, _)| k.clone()).collect();
        for k in stale {
            self.registrations.remove(&k);
        }
        while self.registrations.len() >= MAX_REGISTRATIONS {
            if let Some(oldest) = self.registrations.iter().min_by(|a, b| a.1.last_seen.partial_cmp(&b.1.last_seen).unwrap()).map(|(k, _)| k.clone()) {
                self.registrations.remove(&oldest);
            } else {
                break;
            }
        }
    }

    fn evict_pending(&mut self) {
        let now = (self.clock)();
        let stale: Vec<Vec<u8>> = self.pending.iter().filter(|(_, v)| now - v.created_at > PENDING_REGISTRATION_TTL).map(|(k, _)| k.clone()).collect();
        for k in stale {
            self.pending.remove(&k);
        }
        while self.pending.len() >= MAX_PENDING_REGISTRATIONS {
            if let Some(oldest) = self.pending.iter().min_by(|a, b| a.1.created_at.partial_cmp(&b.1.created_at).unwrap()).map(|(k, _)| k.clone()) {
                self.pending.remove(&oldest);
            } else {
                break;
            }
        }
    }

    pub fn handle(&mut self, data: &[u8], peer: &Addr) -> Outgoing {
        if !is_nat_message(data) {
            return Vec::new();
        }
        let result = match data[4] {
            REGISTER => self.on_register(data, peer),
            REGISTER_CONFIRM => self.on_register_confirm(data, peer),
            PUNCH_REQUEST => self.on_punch_request(data, peer),
            _ => return Vec::new(),
        };
        result.unwrap_or_default()
    }

    /// Signature/freshness-check a `REGISTER` and issue a challenge nonce,
    /// but do *not* bind `identity` to `peer` yet.
    ///
    /// `peer` is the packet's raw UDP source -- genuinely proving nothing
    /// about where the signer actually receives traffic (a real network
    /// path may let a sender spoof an arbitrary source address). Binding
    /// straight from it, the way the original ported protocol did, meant
    /// an attacker holding *any* real signing key (trivial -- they can
    /// generate their own) could register themselves as reachable at a
    /// victim's address, then have a later `PUNCH_REQUEST` naming that
    /// identity as the target make this authority send a `PUNCH_NOTIFY`
    /// toward the victim -- a reflection primitive, using the authority's
    /// own bandwidth to redirect a small amount of traffic toward a third
    /// party of the attacker's choosing. This is the same class of gap
    /// `require_return_routability` closes for the CREATE handshake
    /// elsewhere in this codebase.
    ///
    /// The fix: `identity` only moves from `pending` into `registrations`
    /// (and only then becomes usable as a PUNCH target, via
    /// `registered_addr`/`endpoint`) once `on_register_confirm` sees a
    /// `REGISTER_CONFIRM` echoing this exact nonce back, signed by the
    /// same identity key -- which only someone who actually received this
    /// `REGISTERED` reply at `peer` can produce.
    fn on_register(&mut self, data: &[u8], peer: &Addr) -> Result<Outgoing, NatError> {
        // Unlike `on_punch_request`
        // (below), this never rate-limited at all -- registering only
        // costs an attacker a fresh Ed25519 keypair, so a flood of
        // REGISTERs could (a) cycle through `evict_pending`'s
        // oldest-first eviction fast enough to evict a legitimate NAT'd
        // relay's pending registration before its own `REGISTER_CONFIRM`
        // round trip completes, permanently denying it the ability to
        // register while the flood continues, and (b) spend this
        // authority's CPU on `decode_register`'s Ed25519 verification for
        // every forged request. Checked before decoding (not after, the
        // way `on_punch_request` does it) specifically to avoid paying
        // that verification cost for an already-rate-limited peer.
        // Uses its own `register_limiter`, separate from
        // `on_punch_request`'s `punch_limiter` -- see `register_limiter`'s
        // doc comment for why sharing one bucket was a problem.
        if !self.register_limiter.allow(&peer.0, 1.0) {
            return Err(err("REGISTER rate limited"));
        }
        let (identity, x25519_public, ts) = decode_register(data, &self.ops)?;
        let now = (self.clock)();
        if !fresh(ts, now) {
            return Err(err("stale REGISTER"));
        }
        if let Some(entry) = self.registrations.get(identity.as_slice()) {
            if ts <= entry.last_register_ts {
                return Err(err("replayed REGISTER"));
            }
        }
        self.evict_pending();
        let nonce = random_nonce()?;
        self.pending.insert(identity.to_vec(), PendingRegistration { addr: peer.clone(), nonce, register_ts: ts, created_at: now, x25519_public });
        Ok(vec![(encode_registered(&self.private, &self.x25519_public, &identity, peer, now, &nonce, &self.ops), peer.clone())])
    }

    /// Promote a pending registration to confirmed once its nonce comes
    /// back correctly signed -- see `on_register`'s doc comment for why
    /// this step exists. The confirmed address is the one from the
    /// original `REGISTER`/`PendingRegistration` (the address the nonce
    /// was actually sent to and had to be received at), not
    /// `_requester` (this packet's own source) -- binding to whichever
    /// address the nonce proves receipt at is the whole point; trusting
    /// this packet's raw source again would just reopen the same gap one
    /// step later.
    fn on_register_confirm(&mut self, data: &[u8], _requester: &Addr) -> Result<Outgoing, NatError> {
        let (identity, nonce, ts) = decode_register_confirm(data, &self.ops)?;
        let now = (self.clock)();
        if !fresh(ts, now) {
            return Err(err("stale REGISTER_CONFIRM"));
        }
        let pending = self.pending.get(identity.as_slice()).ok_or_else(|| err("no pending registration for this identity"))?;
        if now - pending.created_at > PENDING_REGISTRATION_TTL {
            self.pending.remove(identity.as_slice());
            return Err(err("pending registration expired"));
        }
        if pending.nonce != nonce {
            return Err(err("REGISTER_CONFIRM nonce mismatch"));
        }
        let addr = pending.addr.clone();
        let register_ts = pending.register_ts;
        let x25519_public = pending.x25519_public;
        self.pending.remove(identity.as_slice());
        if self.registrations.get(identity.as_slice()).is_none() {
            self.evict();
        }
        self.registrations.insert(identity.to_vec(), Registration { addr, last_seen: now, last_register_ts: register_ts, x25519_public });
        Ok(Vec::new())
    }

    /// `(addr, is_nat)` for a relay identity.
    fn endpoint(&mut self, identity: &[u8]) -> (Option<Addr>, bool) {
        if let Some(addr) = self.registered_addr(identity) {
            return (Some(addr), true);
        }
        ((self.lookup_relay)(identity), false)
    }

    /// `PUNCH_REQUEST` is, by design,
    /// unauthenticated and anonymous (see `request_punch`'s doc comment in
    /// the client-side module: any client -- not itself a registered
    /// relay identity -- may ask this authority to introduce `target` and
    /// `peer` to each other). That means `requester` here is exactly as
    /// spoofable as a `REGISTER`'s source used to be, but the
    /// `on_register` fix above (proof-of-receipt before trusting an
    /// address) doesn't transfer to this handler: there is no legitimate
    /// "confirm receipt first, then get real service" round trip to
    /// insert into a one-shot introduction request without either
    /// breaking anonymous clients (who hold no long-term identity to sign
    /// a confirmation with) or adding a full extra round trip to a
    /// latency-sensitive NAT-punch flow. The residual risk is bounded and
    /// deliberately accepted rather than unnoticed: an attacker who spoofs
    /// a victim's address as `requester` can redirect a `PUNCH_REPLY` at
    /// them, capped by the `punch_limiter` token bucket keyed on the
    /// (spoofable) claimed source, and bounded to a small (not classic
    /// DNS/NTP-scale) reply/request size ratio -- verified in
    /// `test_punch_reply_is_not_a_meaningful_amplification_vector` below.
    /// `PUNCH_NOTIFY` (below) is not part of this vector: both of its
    /// recipients (`target_addr`/`peer_addr`) come from
    /// `registered_addr`/`lookup_relay`, never from `requester`, so they
    /// cannot be redirected to a spoofed third party at all.
    ///
    /// Security audit fix (2026-09-26, finding MH2): the rate-limit check
    /// now runs BEFORE decoding/decrypting (matching `on_register`'s own
    /// "check the limiter before paying for expensive work" order) --
    /// decoding a `PUNCH_REQUEST` now costs a real ECDH + AEAD-open, not
    /// just byte-slicing the way the original unencrypted wire format
    /// did, so an unthrottled attacker could otherwise force that cost on
    /// every packet regardless of the limiter. A rate-limited request
    /// gets no reply at all (silently dropped) rather than the previous
    /// `STATUS_RATE_LIMITED` reply -- sending any reply to already-
    /// excessive traffic would reopen exactly the amplification concern
    /// rate limiting exists to bound, and there is no way to construct an
    /// authenticated reply without first paying the decode cost this
    /// check exists to avoid.
    fn on_punch_request(&mut self, data: &[u8], requester: &Addr) -> Result<Outgoing, NatError> {
        if !self.punch_limiter.allow(&requester.0, 1.0) {
            return Ok(Vec::new());
        }
        let (nonce, _client_ephemeral_public, reply_key, target, peer_identity) = decode_punch_request(data, &self.x25519_private, &self.ops)?;
        let target_addr = self.registered_addr(&target);
        let target_addr = match target_addr {
            Some(a) => a,
            None => return Ok(vec![(encode_reply(&reply_key, &nonce, STATUS_TARGET_UNKNOWN, None)?, requester.clone())]),
        };
        let (peer_addr, peer_is_nat) = self.endpoint(&peer_identity);
        let peer_addr = match peer_addr {
            Some(a) => a,
            None => return Ok(vec![(encode_reply(&reply_key, &nonce, STATUS_PEER_UNKNOWN, None)?, requester.clone())]),
        };
        let now = (self.clock)();
        let target_x25519 = self
            .registrations
            .get(target.as_slice())
            .map(|r| r.x25519_public)
            .ok_or_else(|| err("target registration vanished between lookups"))?;
        let mut out: Outgoing = vec![(encode_notify(&self.ops, &self.x25519_private, &target, &target_x25519, &nonce, &peer_addr, now)?, target_addr.clone())];
        if peer_is_nat {
            let peer_x25519 = self
                .registrations
                .get(peer_identity.as_slice())
                .map(|r| r.x25519_public)
                .ok_or_else(|| err("peer registration vanished between lookups"))?;
            out.push((encode_notify(&self.ops, &self.x25519_private, &peer_identity, &peer_x25519, &nonce, &target_addr, now)?, peer_addr));
        }
        out.push((encode_reply(&reply_key, &nonce, STATUS_OK, Some(&target_addr))?, requester.clone()));
        Ok(out)
    }
}

// --------------------------------------------------------------------------
// NAT relay side
// --------------------------------------------------------------------------

/// Runs inside a relay started with `--behind-nat`.
pub struct NatAgent {
    private: [u8; KEY_LEN],
    pub identity_public: [u8; KEY_LEN],
    /// Security audit fix (2026-09-26, finding MH2): this relay's own
    /// long-term X25519 encryption key -- sent in every `REGISTER` (see
    /// [`encode_register`]'s doc) so the introducer can seal `PUNCH_NOTIFY`
    /// to it, and used here to open one.
    x25519_private: [u8; KEY_LEN],
    pub x25519_public: [u8; KEY_LEN],
    pub authority_addr: Addr,
    keys: Vec<[u8; KEY_LEN]>,
    /// The introducer's own pinned X25519 key(s) -- a list, like `keys`
    /// above, so a rotated-in key can be trusted alongside (or instead of)
    /// an older one without breaking an already-registered relay mid-
    /// rotation.
    introducer_x25519_keys: Vec<[u8; KEY_LEN]>,
    clock: Box<dyn FnMut() -> f64 + Send>,
    limiter: RateLimiter,
    ops: Ed25519Ops,
    /// Our public mapping as the introducer last saw it, or `None`.
    pub observed_addr: Option<Addr>,
    /// Which pinned key the introducer actually signed with.
    pub introducer_identity: Option<[u8; KEY_LEN]>,
    /// The introducer's own X25519 public key, as it self-reported in
    /// `REGISTERED` -- see [`reachability_extension`](Self::reachability_extension).
    introducer_x25519_public: Option<[u8; KEY_LEN]>,
    pub punches_sent: usize,
    seen_nonces: HashMap<[u8; NONCE_LEN], f64>,
}

impl NatAgent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity_private: [u8; KEY_LEN],
        x25519_private: [u8; KEY_LEN],
        authority_addr: Addr,
        authority_keys: Vec<[u8; KEY_LEN]>,
        introducer_x25519_keys: Vec<[u8; KEY_LEN]>,
        clock: Box<dyn FnMut() -> f64 + Send>,
        notify_rate: f64,
        notify_burst: u32,
        ops: Ed25519Ops,
    ) -> Result<NatAgent, NatError> {
        if authority_keys.is_empty() {
            return Err(err("a NAT relay must pin its introducer's identity"));
        }
        if introducer_x25519_keys.is_empty() {
            return Err(err("a NAT relay must pin its introducer's X25519 key"));
        }
        let identity_public = (ops.public_of)(&identity_private);
        let x25519_public = (ops.x25519_public)(&x25519_private);
        let (clock, limiter_clock, _) = share_clock(clock);
        Ok(NatAgent {
            private: identity_private,
            identity_public,
            x25519_private,
            x25519_public,
            authority_addr,
            keys: authority_keys,
            introducer_x25519_keys,
            clock,
            limiter: RateLimiter::new(notify_rate, notify_burst, Some(limiter_clock), None, None).expect("valid default rate/burst"),
            ops,
            observed_addr: None,
            introducer_identity: None,
            introducer_x25519_public: None,
            punches_sent: 0,
            seen_nonces: HashMap::new(),
        })
    }

    pub fn register_message(&mut self) -> (Vec<u8>, Addr) {
        let now = (self.clock)();
        (encode_register(&self.private, &self.x25519_public, now, &self.ops), self.authority_addr.clone())
    }

    pub fn reachability_extension(&self) -> Option<Vec<u8>> {
        let id = self.introducer_identity?;
        let x25519 = self.introducer_x25519_public?;
        encode_reachability(&id, &x25519, &self.authority_addr.0, self.authority_addr.1).ok()
    }

    pub fn handle(&mut self, data: &[u8], _peer: &Addr) -> Outgoing {
        if !is_nat_message(data) {
            return Vec::new();
        }
        let result = match data[4] {
            REGISTERED => self.on_registered(data),
            PUNCH_NOTIFY => self.on_notify(data),
            _ => return Vec::new(),
        };
        result.unwrap_or_default()
    }

    /// Records the authority's claimed observed address, and -- see
    /// `REGISTER_CONFIRM`'s doc comment -- echoes the challenge nonce
    /// back so the authority actually binds it, instead of just noting
    /// it locally and leaving the registration permanently pending.
    fn on_registered(&mut self, data: &[u8]) -> Result<Outgoing, NatError> {
        let body = decode_signed(data, L_REGISTERED, &self.keys, &self.ops)?;
        if body.len() < KEY_LEN + KEY_LEN + 8 {
            return Err(err("truncated REGISTERED"));
        }
        if body[..KEY_LEN] != self.identity_public {
            return Err(err("REGISTERED for another identity"));
        }
        let mut introducer_x25519_public = [0u8; KEY_LEN];
        introducer_x25519_public.copy_from_slice(&body[KEY_LEN..KEY_LEN + KEY_LEN]);
        let ts = f64::from_be_bytes(body[KEY_LEN + KEY_LEN..KEY_LEN + KEY_LEN + 8].try_into().unwrap());
        if !fresh(ts, (self.clock)()) {
            return Err(err("stale REGISTERED"));
        }
        let (addr, end) = unpack_addr(&body, KEY_LEN + KEY_LEN + 8)?;
        if body.len() != end + NONCE_LEN {
            return Err(err("trailing bytes"));
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&body[end..end + NONCE_LEN]);
        self.observed_addr = Some(addr);
        let mut signer = [0u8; KEY_LEN];
        signer.copy_from_slice(&data[data.len() - SIG_LEN - KEY_LEN..data.len() - SIG_LEN]);
        self.introducer_identity = Some(signer);
        self.introducer_x25519_public = Some(introducer_x25519_public);
        let now = (self.clock)();
        let confirm = encode_register_confirm(&self.private, &nonce, now, &self.ops);
        Ok(vec![(confirm, self.authority_addr.clone())])
    }

    /// Security audit fix (2026-09-26, finding MH2): opens the sealed
    /// envelope [`encode_notify`] produces instead of verifying a
    /// signature over a plaintext body -- static-static ECDH between this
    /// relay's own pinned `x25519_private` and the introducer's own
    /// pinned `introducer_x25519_keys` implicitly authenticates the
    /// sender (see [`open_static_any`]'s doc), so a failed open is
    /// already "not really from a pinned introducer," matching what the
    /// old signature check rejected.
    fn on_notify(&mut self, data: &[u8]) -> Result<Outgoing, NatError> {
        let body = &data[5..];
        if body.len() < NONCE_LEN + KEY_LEN {
            return Err(err("truncated PUNCH_NOTIFY"));
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&body[..NONCE_LEN]);
        let recipient = &body[NONCE_LEN..NONCE_LEN + KEY_LEN];
        if recipient != self.identity_public {
            return Err(err("PUNCH_NOTIFY for another relay"));
        }
        let sealed = &body[NONCE_LEN + KEY_LEN..];
        let mut ad = nonce.to_vec();
        ad.extend_from_slice(recipient);
        let plaintext = open_static_any(&self.ops, &self.x25519_private, &self.introducer_x25519_keys, &ad, sealed)?;
        if plaintext.len() < 8 {
            return Err(err("truncated PUNCH_NOTIFY plaintext"));
        }
        let ts = f64::from_be_bytes(plaintext[..8].try_into().unwrap());
        let now = (self.clock)();
        if !fresh(ts, now) {
            return Err(err("stale PUNCH_NOTIFY"));
        }
        self.seen_nonces.retain(|_, t| now - *t <= MAX_CLOCK_SKEW * 2.0);
        if self.seen_nonces.contains_key(&nonce) {
            return Err(err("replayed PUNCH_NOTIFY"));
        }
        self.seen_nonces.insert(nonce, now);
        let (peer_addr, end) = unpack_addr(&plaintext, 8)?;
        if end != plaintext.len() {
            return Err(err("trailing bytes"));
        }
        if !self.limiter.allow("notify", 1.0) {
            return Ok(Vec::new());
        }
        let mut punch = header(PUNCH);
        punch.extend_from_slice(&nonce);
        self.punches_sent += PUNCH_COUNT;
        Ok((0..PUNCH_COUNT).map(|_| (punch.clone(), peer_addr.clone())).collect())
    }
}

// --------------------------------------------------------------------------
// Client side
// --------------------------------------------------------------------------
//
// `request_punch` (Python) is a blocking socket helper (send PUNCH_REQUEST,
// wait for PUNCH_REPLY, retry). Its logic beyond socket I/O -- validating a
// reply against the nonce/trusted keys and turning a non-OK status into an
// error -- is exactly `decode_punch_reply` above, already ported and tested.
// The socket loop itself is a thin, blocking `std::net::UdpSocket` wrapper
// with no additional protocol logic of its own to port; omitted here in
// favour of keeping this module's testable surface complete without an
// untestable (socket-timing-dependent) port of the retry loop. A caller
// needing it can build it directly from `encode_punch_request` +
// `decode_punch_reply` + `std::net::UdpSocket`, exactly as the Python
// function does with `socket.socket`.

// (helper re-exported so callers can construct a KEY_LEN-sized identity
// array from a slice without duplicating bounds-checking logic)
pub fn key_from_slice(s: &[u8]) -> Result<[u8; KEY_LEN], NatError> {
    s.try_into().map_err(|_| err(format!("expected a {KEY_LEN}-byte key, got {}", s.len())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    thread_local! {
        static FAKE_SIGS: RefCell<HashMap<(Vec<u8>, Vec<u8>), [u8; SIG_LEN]>> = RefCell::new(HashMap::new());
    }

    /// A fake, deterministic (NOT secure) "Ed25519" used only to exercise
    /// this module's framing/state-machine logic without the real
    /// `ed25519-dalek` crate -- exactly mirroring how `crypto.rs`'s
    /// `fake_cipher` stands in for a real AEAD in its own tests. "public
    /// key" = HMAC-SHA256(private, "pub"); "signature" is built from two
    /// chained HMACs of the message and is also registered in `FAKE_SIGS`
    /// keyed by `(public, message)`, so `verify` -- which has no private
    /// key to recompute from -- can check a claimed signature by lookup
    /// instead. This fakes real asymmetric-signature *behaviour* (sign with
    /// the private half, verify with only the public half) well enough to
    /// exercise every caller in this module, without being a real signature
    /// scheme. Never use this for anything but these tests.
    fn recording_fake_ops() -> Ed25519Ops {
        Ed25519Ops {
            sign: Box::new(|private, message| {
                let mut out = [0u8; SIG_LEN];
                let h1 = hmac_sha256(private, message);
                let h2 = hmac_sha256(&h1, message);
                out[..32].copy_from_slice(&h1);
                out[32..].copy_from_slice(&h2);
                let public = hmac_sha256(private, b"pub");
                FAKE_SIGS.with(|reg| reg.borrow_mut().insert((public.to_vec(), message.to_vec()), out));
                out
            }),
            verify: Box::new(|public, message, sig| {
                FAKE_SIGS.with(|reg| {
                    let reg = reg.borrow();
                    reg.get(&(public.to_vec(), message.to_vec())).map(|s| s == sig).unwrap_or(false)
                })
            }),
            public_of: Box::new(|private| hmac_sha256(private, b"pub")),
            x25519_generate: Box::new(fake_x25519_generate),
            x25519_public: Box::new(fake_x25519_public),
            x25519_dh: Box::new(fake_x25519_dh),
        }
    }

    fn fake_x25519_public(seed: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
        hmac_sha256(b"nat-x25519-pub-fake", seed)
    }
    /// Must be symmetric (`dh(a_priv, b_pub) == dh(b_priv, a_pub)`), same as
    /// real X25519 -- derive both sides' public keys and combine them
    /// order-independently, rather than mixing in `private` directly.
    /// Mirrors `hiddenservice.rs`'s own `fake_x25519_dh`.
    fn fake_x25519_dh(private: &[u8; KEY_LEN], peer_public: &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN], NatError> {
        let own_public = fake_x25519_public(private);
        let (a, b) = if own_public <= *peer_public { (own_public, *peer_public) } else { (*peer_public, own_public) };
        let mut buf = a.to_vec();
        buf.extend_from_slice(&b);
        Ok(hmac_sha256(b"nat-x25519-dh-fake", &buf))
    }
    fn fake_x25519_generate() -> [u8; KEY_LEN] {
        let mut buf = [0u8; KEY_LEN];
        crate::osrand::os_random(&mut buf).unwrap();
        buf
    }

    fn clock_at(t: f64) -> (Box<dyn FnMut() -> f64 + Send>, Arc<Mutex<f64>>) {
        let c = Arc::new(Mutex::new(t));
        let c2 = Arc::clone(&c);
        (Box::new(move || *c2.lock().unwrap()), c)
    }

    #[test]
    fn test_is_nat_message() {
        assert!(is_nat_message(b"ALNT\x01"));
        assert!(!is_nat_message(b"ALNT"));
        assert!(!is_nat_message(b"XXXX\x01"));
    }

    #[test]
    fn test_encode_decode_reachability_round_trip() {
        let identity = [7u8; 32];
        let x25519_public = [8u8; 32];
        let encoded = encode_reachability(&identity, &x25519_public, "1.2.3.4", 9001).unwrap();
        let decoded = decode_reachability(&encoded).unwrap();
        assert_eq!(decoded.mode, MODE_NAT);
        assert_eq!(decoded.introducer_identity, identity.to_vec());
        assert_eq!(decoded.introducer_x25519_public, x25519_public.to_vec());
        assert_eq!(decoded.introducer_addr(), ("1.2.3.4".to_string(), 9001));
    }

    #[test]
    fn test_encode_reachability_rejects_bad_identity_len() {
        assert!(encode_reachability(&[1u8; 10], &[1u8; 32], "h", 1).is_err());
        assert!(encode_reachability(&[1u8; 32], &[1u8; 10], "h", 1).is_err());
    }

    #[test]
    fn test_register_round_trip_with_fake_signer() {
        FAKE_SIGS.with(|r| r.borrow_mut().clear());
        let ops = recording_fake_ops();
        let private = [3u8; KEY_LEN];
        let x25519_public = fake_x25519_public(&[30u8; KEY_LEN]);
        let msg = encode_register(&private, &x25519_public, 1000.0, &ops);
        let (identity, decoded_x25519_public, ts) = decode_register(&msg, &ops).unwrap();
        assert_eq!(identity, (ops.public_of)(&private));
        assert_eq!(decoded_x25519_public, x25519_public);
        assert_eq!(ts, 1000.0);
    }

    #[test]
    fn test_register_rejects_tampered_signature() {
        FAKE_SIGS.with(|r| r.borrow_mut().clear());
        let ops = recording_fake_ops();
        let private = [3u8; KEY_LEN];
        let x25519_public = fake_x25519_public(&[30u8; KEY_LEN]);
        let mut msg = encode_register(&private, &x25519_public, 1000.0, &ops);
        let last = msg.len() - 1;
        msg[last] ^= 0xFF;
        assert!(decode_register(&msg, &ops).is_err());
    }

    #[test]
    fn test_encode_punch_request_and_decode() {
        let ops = recording_fake_ops();
        let target = [1u8; KEY_LEN];
        let peer = [2u8; KEY_LEN];
        let introducer_private = [40u8; KEY_LEN];
        let introducer_public = fake_x25519_public(&introducer_private);
        let (msg, nonce, client_ephemeral_private) = encode_punch_request(&target, &peer, &introducer_public, None, None, &ops).unwrap();
        let (n2, client_ephemeral_public, _reply_key, t2, p2) = decode_punch_request(&msg, &introducer_private, &ops).unwrap();
        assert_eq!(n2, nonce);
        assert_eq!(client_ephemeral_public, (ops.x25519_public)(&client_ephemeral_private));
        assert_eq!(t2, target.to_vec());
        assert_eq!(p2, peer.to_vec());
    }

    #[test]
    fn test_encode_punch_request_rejects_bad_len() {
        let ops = recording_fake_ops();
        let introducer_public = fake_x25519_public(&[40u8; KEY_LEN]);
        assert!(encode_punch_request(&[1u8; 10], &[2u8; KEY_LEN], &introducer_public, None, None, &ops).is_err());
    }

    fn authority_setup() -> (NatRendezvous, [u8; KEY_LEN], [u8; KEY_LEN], Arc<Mutex<f64>>) {
        FAKE_SIGS.with(|r| r.borrow_mut().clear());
        let (clock, t) = clock_at(0.0);
        let authority_private = [9u8; KEY_LEN];
        let authority_x25519_private = [90u8; KEY_LEN];
        let rendezvous = NatRendezvous::new(authority_private, authority_x25519_private, Box::new(|_id| None), clock, 100.0, 100, recording_fake_ops());
        (rendezvous, authority_private, authority_x25519_private, t)
    }

    /// Extract the challenge nonce from a REGISTERED reply, as a relay's
    /// own `NatAgent::on_registered` would. Tests use this to drive the
    /// register -> registered -> confirm round trip explicitly, rather
    /// than going through a full `NatAgent`, so the authority-side state
    /// machine is exercised directly.
    fn nonce_from_registered(msg: &[u8], authority_pub: [u8; KEY_LEN], ops: &Ed25519Ops) -> [u8; NONCE_LEN] {
        let body = decode_signed(msg, L_REGISTERED, &[authority_pub], ops).unwrap();
        let (_, end) = unpack_addr(&body, KEY_LEN + KEY_LEN + 8).unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&body[end..end + NONCE_LEN]);
        nonce
    }

    #[test]
    fn test_rendezvous_register_alone_does_not_bind_the_address() {
        // The core of the fix: REGISTER alone (no confirm) must not make
        // an identity resolvable, since the claimed address is unverified
        // until confirmed -- otherwise this is exactly the reflection gap
        // `on_register`'s doc comment describes.
        let (mut rv, _priv, _x25519_priv, _t) = authority_setup();
        let relay_private = [5u8; KEY_LEN];
        let ops = recording_fake_ops();
        let relay_x25519_public = fake_x25519_public(&relay_private);
        let msg = encode_register(&relay_private, &relay_x25519_public, 0.0, &ops);
        let out = rv.handle(&msg, &("10.0.0.5".to_string(), 4000));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0[4], REGISTERED);
        let identity = (ops.public_of)(&relay_private);
        assert_eq!(rv.registered_addr(&identity), None, "must not be resolvable before REGISTER_CONFIRM");
    }

    #[test]
    fn test_rendezvous_register_then_confirm_binds_the_address() {
        let (mut rv, authority_private, _x25519_priv, _t) = authority_setup();
        let relay_private = [5u8; KEY_LEN];
        let ops = recording_fake_ops();
        let relay_x25519_public = fake_x25519_public(&relay_private);
        let authority_pub = (ops.public_of)(&authority_private);
        let msg = encode_register(&relay_private, &relay_x25519_public, 0.0, &ops);
        let out = rv.handle(&msg, &("10.0.0.5".to_string(), 4000));
        let nonce = nonce_from_registered(&out[0].0, authority_pub, &ops);

        let confirm = encode_register_confirm(&relay_private, &nonce, 0.0, &ops);
        let out2 = rv.handle(&confirm, &("10.0.0.5".to_string(), 4000));
        assert!(out2.is_empty(), "REGISTER_CONFIRM produces no reply");

        let identity = (ops.public_of)(&relay_private);
        assert_eq!(rv.registered_addr(&identity), Some(("10.0.0.5".to_string(), 4000)));
    }

    #[test]
    fn test_rendezvous_confirm_with_wrong_nonce_rejected() {
        let (mut rv, _authority_private, _x25519_priv, _t) = authority_setup();
        let relay_private = [5u8; KEY_LEN];
        let ops = recording_fake_ops();
        let relay_x25519_public = fake_x25519_public(&relay_private);
        let msg = encode_register(&relay_private, &relay_x25519_public, 0.0, &ops);
        rv.handle(&msg, &("10.0.0.5".to_string(), 4000));

        let wrong_nonce = [0xEEu8; NONCE_LEN];
        let confirm = encode_register_confirm(&relay_private, &wrong_nonce, 0.0, &ops);
        rv.handle(&confirm, &("10.0.0.5".to_string(), 4000));

        let identity = (ops.public_of)(&relay_private);
        assert_eq!(rv.registered_addr(&identity), None, "a mismatched nonce must not bind anything");
    }

    /// This is the actual attack `on_register`'s doc comment describes,
    /// proven end to end: an attacker who spoofs REGISTER from a victim's
    /// address, but who can never receive the REGISTERED reply sent
    /// there, can't produce a valid REGISTER_CONFIRM -- so PUNCH targeting
    /// that identity still reports it as unknown, and no PUNCH_NOTIFY is
    /// ever sent toward the victim.
    #[test]
    fn test_rendezvous_unconfirmed_registration_cannot_be_punch_target() {
        let (mut rv, _authority_private, _authority_x25519_private, _t) = authority_setup();
        let attacker_private = [6u8; KEY_LEN];
        let ops = recording_fake_ops();
        let victim_addr = ("203.0.113.9".to_string(), 4000); // the attacker's spoofed source
        let attacker_x25519_public = fake_x25519_public(&attacker_private);

        let msg = encode_register(&attacker_private, &attacker_x25519_public, 0.0, &ops);
        rv.handle(&msg, &victim_addr); // "peer" here is the spoofed victim address
        // The attacker never sees the REGISTERED reply (it went to the
        // victim), so no REGISTER_CONFIRM is ever sent -- simulated here
        // by simply not sending one.

        let target_id = (ops.public_of)(&attacker_private);
        let introducer_x25519_public = rv.x25519_public;
        let (req, nonce, client_ephemeral_private) = encode_punch_request(&target_id, &target_id, &introducer_x25519_public, None, None, &ops).unwrap();
        let out = rv.handle(&req, &("198.51.100.1".to_string(), 1)); // the attacker's real address
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0[4], PUNCH_REPLY);
        let (status, addr) = decode_punch_reply(&out[0].0, &client_ephemeral_private, &introducer_x25519_public, &nonce, &ops).unwrap();
        assert_eq!(status, STATUS_TARGET_UNKNOWN, "an unconfirmed registration must not be usable as a PUNCH target");
        assert_eq!(addr, None);
    }

    /// `on_register` never
    /// checked `register_limiter` at all, so a flood of REGISTERs from one
    /// apparent source could cycle through `evict_pending`'s oldest-first
    /// eviction fast enough to knock a legitimate NAT'd relay's pending
    /// registration out before its own `REGISTER_CONFIRM` round trip
    /// completed. With the clock frozen (no time-based refill), exactly
    /// `request_burst` REGISTERs from one peer must succeed and every one
    /// after that must be silently dropped, matching `on_punch_request`'s
    /// existing rate-limiting behavior.
    #[test]
    fn test_register_is_rate_limited() {
        let (mut rv, _priv, _x25519_priv, _t) = authority_setup(); // request_rate=100.0, request_burst=100
        let relay_private = [5u8; KEY_LEN];
        let ops = recording_fake_ops();
        let relay_x25519_public = fake_x25519_public(&relay_private);
        let msg = encode_register(&relay_private, &relay_x25519_public, 0.0, &ops);
        let peer = ("198.51.100.1".to_string(), 4000);

        let accepted = (0..150).filter(|_| !rv.handle(&msg, &peer).is_empty()).count();
        assert_eq!(accepted, 100, "burst of 100 should be honored, the rest rate-limited");
    }

    /// Regression test for finding M2: `on_register` and `on_punch_request`
    /// used to share one IP-keyed `RateLimiter` bucket, so an attacker
    /// flooding `PUNCH_REQUEST`s while spoofing a real relay's address
    /// could exhaust that bucket and get the relay's own `REGISTER`
    /// -- from that same address -- silently dropped too, denying it the
    /// ability to (re-)register via NAT punch.
    #[test]
    fn test_punch_request_flood_does_not_starve_register_rate_limit() {
        let (mut rv, _priv, _x25519_priv, _t) = authority_setup(); // request_rate=100.0, request_burst=100
        let ops = recording_fake_ops();
        let spoofed_addr = ("198.51.100.7".to_string(), 4242); // claimed as `requester`, not verified
        let target_id = [1u8; KEY_LEN];
        let introducer_x25519_public = rv.x25519_public;

        // Flood PUNCH_REQUESTs from `spoofed_addr` well past its own
        // burst -- before this fix, this drained the same bucket
        // `on_register` read from too.
        for _ in 0..300 {
            let (req, _nonce, _eph) = encode_punch_request(&target_id, &target_id, &introducer_x25519_public, None, None, &ops).unwrap();
            rv.handle(&req, &spoofed_addr);
        }

        // The real relay's own REGISTER, from that same address, must
        // still get its own full, untouched burst -- a separate bucket.
        // Same shape as `test_register_is_rate_limited` above, just
        // preceded by the flood.
        let relay_private = [5u8; KEY_LEN];
        let relay_x25519_public = fake_x25519_public(&relay_private);
        let register_msg = encode_register(&relay_private, &relay_x25519_public, 0.0, &ops);
        let accepted = (0..150).filter(|_| !rv.handle(&register_msg, &spoofed_addr).is_empty()).count();
        assert_eq!(accepted, 100, "REGISTER's own burst must be untouched by an unrelated PUNCH_REQUEST flood on the same address");
    }

    /// Backs the claim in
    /// `on_punch_request`'s doc comment that `PUNCH_REPLY` is not a
    /// meaningful amplification vector -- an off-path attacker spoofing a
    /// victim's address as `requester` gains no real leverage over
    /// sending the victim that many bytes directly, unlike a classic
    /// (10-100x) amplification vector. `reply_key` here is an arbitrary
    /// fixed key -- this test only measures wire-size ratio, not an actual
    /// authenticated round trip (covered elsewhere).
    #[test]
    fn test_punch_reply_is_not_a_meaningful_amplification_vector() {
        let ops = recording_fake_ops();
        let (target, peer) = ([1u8; KEY_LEN], [2u8; KEY_LEN]);
        let introducer_x25519_public = fake_x25519_public(&[40u8; KEY_LEN]);
        let (request, _nonce, _client_ephemeral_private) = encode_punch_request(&target, &peer, &introducer_x25519_public, None, None, &ops).unwrap();

        let reply_key = [0u8; 32];
        let nonce = [0u8; NONCE_LEN];
        let reply = encode_reply(&reply_key, &nonce, STATUS_OK, Some(&("203.0.113.1".to_string(), 9001))).unwrap();

        let ratio = reply.len() as f64 / request.len() as f64;
        assert!(
            ratio < 2.0,
            "PUNCH_REPLY ({} bytes) must not meaningfully amplify PUNCH_REQUEST ({} bytes); ratio={ratio}",
            reply.len(),
            request.len()
        );
    }

    #[test]
    fn test_rendezvous_stale_register_rejected() {
        let (mut rv, _priv, _x25519_priv, t) = authority_setup();
        *t.lock().unwrap() = 1000.0;
        let relay_private = [5u8; KEY_LEN];
        let ops = recording_fake_ops();
        let relay_x25519_public = fake_x25519_public(&relay_private);
        let msg = encode_register(&relay_private, &relay_x25519_public, 0.0, &ops); // ts=0, now=1000, skew too big
        let out = rv.handle(&msg, &("10.0.0.5".to_string(), 4000));
        assert!(out.is_empty());
    }

    #[test]
    fn test_rendezvous_replayed_register_rejected_once_confirmed() {
        let (mut rv, authority_private, _x25519_priv, _t) = authority_setup();
        let relay_private = [5u8; KEY_LEN];
        let ops = recording_fake_ops();
        let relay_x25519_public = fake_x25519_public(&relay_private);
        let authority_pub = (ops.public_of)(&authority_private);
        let msg = encode_register(&relay_private, &relay_x25519_public, 5.0, &ops);
        let out = rv.handle(&msg, &("10.0.0.5".to_string(), 4000));
        assert_eq!(out.len(), 1);
        let nonce = nonce_from_registered(&out[0].0, authority_pub, &ops);
        let confirm = encode_register_confirm(&relay_private, &nonce, 5.0, &ops);
        rv.handle(&confirm, &("10.0.0.5".to_string(), 4000));

        // Same or older ts again, against the now-confirmed registration: replay.
        let msg2 = encode_register(&relay_private, &relay_x25519_public, 5.0, &ops);
        assert!(rv.handle(&msg2, &("10.0.0.5".to_string(), 4000)).is_empty());
    }

    #[test]
    fn test_rendezvous_punch_request_target_unknown() {
        let (mut rv, _authority_private, _x25519_priv, _t) = authority_setup();
        let ops = recording_fake_ops();
        let introducer_x25519_public = rv.x25519_public;
        let (msg, nonce, client_ephemeral_private) = encode_punch_request(&[1u8; KEY_LEN], &[2u8; KEY_LEN], &introducer_x25519_public, None, None, &ops).unwrap();
        let out = rv.handle(&msg, &("1.2.3.4".to_string(), 1));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0[4], PUNCH_REPLY);
        let (status, addr) = decode_punch_reply(&out[0].0, &client_ephemeral_private, &introducer_x25519_public, &nonce, &ops).unwrap();
        assert_eq!(status, STATUS_TARGET_UNKNOWN);
        assert_eq!(addr, None);
    }

    #[test]
    fn test_rendezvous_full_punch_flow_both_registered() {
        let (mut rv, authority_private, _x25519_priv, _t) = authority_setup();
        let ops = recording_fake_ops();
        let authority_pub_early = (ops.public_of)(&authority_private);
        let introducer_x25519_public = rv.x25519_public;
        let target_private = [11u8; KEY_LEN];
        let peer_private = [12u8; KEY_LEN];
        let target_id = (ops.public_of)(&target_private);
        let peer_id = (ops.public_of)(&peer_private);
        let target_x25519_public = fake_x25519_public(&target_private);
        let peer_x25519_public = fake_x25519_public(&peer_private);

        // Register both as NAT relays, and confirm both -- an
        // unconfirmed registration can't be a PUNCH target (see
        // test_rendezvous_unconfirmed_registration_cannot_be_punch_target).
        let reg_t = encode_register(&target_private, &target_x25519_public, 0.0, &ops);
        let out_t = rv.handle(&reg_t, &("10.0.0.1".to_string(), 1111));
        let nonce_t = nonce_from_registered(&out_t[0].0, authority_pub_early, &ops);
        rv.handle(&encode_register_confirm(&target_private, &nonce_t, 0.0, &ops), &("10.0.0.1".to_string(), 1111));

        let reg_p = encode_register(&peer_private, &peer_x25519_public, 0.0, &ops);
        let out_p = rv.handle(&reg_p, &("10.0.0.2".to_string(), 2222));
        let nonce_p = nonce_from_registered(&out_p[0].0, authority_pub_early, &ops);
        rv.handle(&encode_register_confirm(&peer_private, &nonce_p, 0.0, &ops), &("10.0.0.2".to_string(), 2222));

        let (req, nonce, client_ephemeral_private) = encode_punch_request(&target_id, &peer_id, &introducer_x25519_public, None, None, &ops).unwrap();
        let out = rv.handle(&req, &("10.0.0.3".to_string(), 3333));
        // notify target, notify peer (peer is also NAT), reply to requester.
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].0[4], PUNCH_NOTIFY);
        assert_eq!(out[1].0[4], PUNCH_NOTIFY);
        assert_eq!(out[2].0[4], PUNCH_REPLY);
        let (status, addr) = decode_punch_reply(&out[2].0, &client_ephemeral_private, &introducer_x25519_public, &nonce, &ops).unwrap();
        assert_eq!(status, STATUS_OK);
        assert_eq!(addr, Some(("10.0.0.1".to_string(), 1111)));
    }

    #[test]
    fn test_agent_requires_authority_keys() {
        let (clock, _t) = clock_at(0.0);
        let result = NatAgent::new([1u8; KEY_LEN], [10u8; KEY_LEN], ("a".to_string(), 1), vec![], vec![[9u8; KEY_LEN]], clock, 5.0, 20, recording_fake_ops());
        assert!(result.is_err());
    }

    #[test]
    fn test_agent_processes_registered_and_notify() {
        FAKE_SIGS.with(|r| r.borrow_mut().clear());
        let ops_authority = recording_fake_ops();
        let authority_private = [9u8; KEY_LEN];
        let authority_pub = (ops_authority.public_of)(&authority_private);
        let authority_x25519_private = [90u8; KEY_LEN];
        let authority_x25519_public = fake_x25519_public(&authority_x25519_private);

        let (clock, _t) = clock_at(0.0);
        let relay_private = [4u8; KEY_LEN];
        let relay_x25519_private = [40u8; KEY_LEN];
        let mut agent = NatAgent::new(relay_private, relay_x25519_private, ("intro".to_string(), 9), vec![authority_pub], vec![authority_x25519_public], clock, 100.0, 100, recording_fake_ops()).unwrap();

        let relay_id = agent.identity_public;
        let register_nonce = [3u8; NONCE_LEN];
        let registered_msg = encode_registered(&authority_private, &authority_x25519_public, &relay_id, &("5.6.7.8".to_string(), 4321), 0.0, &register_nonce, &ops_authority);
        let confirm_out = agent.handle(&registered_msg, &("intro".to_string(), 9));
        assert_eq!(agent.observed_addr, Some(("5.6.7.8".to_string(), 4321)));
        assert_eq!(agent.introducer_identity, Some(authority_pub));
        assert_eq!(agent.reachability_extension(), encode_reachability(&authority_pub, &authority_x25519_public, "intro", 9).ok());
        // Echoes the challenge nonce back to the authority, per REGISTER_CONFIRM's doc comment.
        assert_eq!(confirm_out.len(), 1);
        assert_eq!(confirm_out[0].0[4], REGISTER_CONFIRM);
        assert_eq!(confirm_out[0].1, ("intro".to_string(), 9));
        let (confirmed_identity, confirmed_nonce, _ts) = decode_register_confirm(&confirm_out[0].0, &ops_authority).unwrap();
        assert_eq!(confirmed_identity, relay_id);
        assert_eq!(confirmed_nonce, register_nonce);

        let nonce = [1u8; NONCE_LEN];
        let relay_x25519_public = fake_x25519_public(&relay_x25519_private);
        let notify_msg = encode_notify(&ops_authority, &authority_x25519_private, &relay_id, &relay_x25519_public, &nonce, &("9.9.9.9".to_string(), 55), 0.0).unwrap();
        let out = agent.handle(&notify_msg, &("intro".to_string(), 9));
        assert_eq!(out.len(), PUNCH_COUNT);
        assert_eq!(agent.punches_sent, PUNCH_COUNT);
        for (msg, addr) in &out {
            assert_eq!(msg[4], PUNCH);
            assert_eq!(addr, &("9.9.9.9".to_string(), 55));
        }
    }

    #[test]
    fn test_agent_rejects_notify_for_another_relay() {
        FAKE_SIGS.with(|r| r.borrow_mut().clear());
        let ops_authority = recording_fake_ops();
        let authority_private = [9u8; KEY_LEN];
        let authority_pub = (ops_authority.public_of)(&authority_private);
        let authority_x25519_private = [90u8; KEY_LEN];
        let authority_x25519_public = fake_x25519_public(&authority_x25519_private);
        let (clock, _t) = clock_at(0.0);
        let mut agent = NatAgent::new([4u8; KEY_LEN], [40u8; KEY_LEN], ("intro".to_string(), 9), vec![authority_pub], vec![authority_x25519_public], clock, 100.0, 100, recording_fake_ops()).unwrap();
        let nonce = [1u8; NONCE_LEN];
        let other_relay_id = [77u8; KEY_LEN];
        let other_relay_x25519_public = fake_x25519_public(&[70u8; KEY_LEN]);
        let notify_msg = encode_notify(&ops_authority, &authority_x25519_private, &other_relay_id, &other_relay_x25519_public, &nonce, &("9.9.9.9".to_string(), 55), 0.0).unwrap();
        let out = agent.handle(&notify_msg, &("intro".to_string(), 9));
        assert!(out.is_empty());
        assert_eq!(agent.punches_sent, 0);
    }

    #[test]
    fn test_agent_rejects_truncated_registered_instead_of_panicking() {
        // A validly-signed REGISTERED whose logical body is empty (just the
        // authority's trailing signer key, no identity/timestamp/address)
        // must be rejected with an error, not slice-index panic -- a
        // compromised/buggy authority can otherwise crash every
        // `--behind-nat` relay with one crafted datagram.
        FAKE_SIGS.with(|r| r.borrow_mut().clear());
        let ops_authority = recording_fake_ops();
        let authority_private = [9u8; KEY_LEN];
        let authority_pub = (ops_authority.public_of)(&authority_private);
        let authority_x25519_public = fake_x25519_public(&[90u8; KEY_LEN]);
        let (clock, _t) = clock_at(0.0);
        let mut agent = NatAgent::new([4u8; KEY_LEN], [40u8; KEY_LEN], ("intro".to_string(), 9), vec![authority_pub], vec![authority_x25519_public], clock, 100.0, 100, recording_fake_ops()).unwrap();

        let short_body = authority_pub.to_vec();
        let sig = (ops_authority.sign)(&authority_private, &label_body(L_REGISTERED, &short_body));
        let mut msg = header(REGISTERED);
        msg.extend_from_slice(&short_body);
        msg.extend_from_slice(&sig);

        let out = agent.handle(&msg, &("intro".to_string(), 9));
        assert!(out.is_empty());
        assert!(agent.observed_addr.is_none());
    }

    /// A `PUNCH_NOTIFY` whose logical body is too short to even contain a
    /// nonce + recipient identity (let alone a sealed payload) must be
    /// rejected with an error, not slice-index panic -- a compromised/
    /// buggy authority can otherwise crash every `--behind-nat` relay with
    /// one crafted datagram.
    #[test]
    fn test_agent_rejects_truncated_notify_instead_of_panicking() {
        FAKE_SIGS.with(|r| r.borrow_mut().clear());
        let authority_x25519_public = fake_x25519_public(&[90u8; KEY_LEN]);
        let (clock, _t) = clock_at(0.0);
        let mut agent = NatAgent::new([4u8; KEY_LEN], [40u8; KEY_LEN], ("intro".to_string(), 9), vec![[9u8; KEY_LEN]], vec![authority_x25519_public], clock, 100.0, 100, recording_fake_ops()).unwrap();

        let mut msg = header(PUNCH_NOTIFY);
        msg.extend_from_slice(&[0u8; NONCE_LEN]); // nonce only -- no recipient identity, no sealed body

        let out = agent.handle(&msg, &("intro".to_string(), 9));
        assert!(out.is_empty());
        assert_eq!(agent.punches_sent, 0);
    }

    #[test]
    fn test_agent_reachability_extension_none_before_registered() {
        let (clock, _t) = clock_at(0.0);
        let agent = NatAgent::new([4u8; KEY_LEN], [40u8; KEY_LEN], ("intro".to_string(), 9), vec![[9u8; KEY_LEN]], vec![[90u8; KEY_LEN]], clock, 5.0, 20, recording_fake_ops()).unwrap();
        assert!(agent.reachability_extension().is_none());
    }
}
