//! Wire framing for Allium's hidden-service control protocol.
//!
//! Everything in [`crate::hiddenservice`] (identities, descriptors,
//! sealing, session crypto) is deliberately transport-agnostic; this
//! module is what puts it on the wire, riding the exact same
//! onion-cell/circuit machinery as everything else in Allium.
//!
//! **Two kinds of circuit carry these messages:**
//!
//! * A service's long-lived circuit to one of its introduction points,
//!   kept open for as long as the service runs. It carries exactly one
//!   `ESTABLISH_INTRO` followed by zero or more `INTRODUCE2` messages, one
//!   per client that shows up over the circuit's lifetime -- unlike a
//!   directory circuit ([`crate::dirwire::DirReassembler`], good for
//!   exactly one request/reply and then discarded), so [`HsReassembler`]
//!   here resets itself after each complete message instead of latching
//!   "finished" forever.
//! * A short-lived circuit either side opens to a rendezvous point: one
//!   `RENDEZVOUS_JOIN` to pair with the other side by a shared cookie,
//!   followed by a back-and-forth of `RENDEZVOUS_DATA` -- opaque bytes the
//!   rendezvous point forwards to the paired circuit without ever
//!   decrypting (a further, independent AEAD layer between client and
//!   service rides inside this opaque payload -- see
//!   [`crate::hiddenservice::HsSession`]).
//!
//! All nine message shapes share one reserved fragment stream id
//! ([`HS_STREAM_ID`]) and are always sent through [`fragment_message`]
//! even when they would fit one cell -- the same deliberate uniformity
//! [`crate::dirwire`] documents, for the same reason.

use std::fmt;

use crate::fragment::{Fragment, FragmentError, Fragmenter, Reassembler, decode_fragment, encode_fragment};

/// A hidden-service control message could not be encoded/decoded. The one
/// error type a caller handling untrusted network input needs to catch --
/// mirrors [`crate::dirwire::DirWireError`]'s own reasoning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HsWireError(pub String);

impl fmt::Display for HsWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for HsWireError {}

fn err(msg: impl Into<String>) -> HsWireError {
    HsWireError(msg.into())
}

/// `(auth_pubkey, client_ephemeral_pub, sealed)` -- [`decode_introduce1`]'s
/// return shape.
pub type Introduce1 = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Unchanging prefix, distinct from `allium::socks`'s `MAGIC` (`ALSM`),
/// `DATAGRAM_MAGIC` (`ALDG`), and [`crate::dirwire::DIR_MAGIC`] (`ALDR`) so
/// none of Allium's framings can ever be confused with each other.
pub const HS_MAGIC: &[u8; 4] = b"ALHS";

/// Fragment stream id reserved for hidden-service control traffic. Safe to
/// hardcode: an intro or rendezvous circuit never carries anything else,
/// so (like [`crate::dirwire::DIR_STREAM_ID`]) there is no multiplexing
/// need.
pub const HS_STREAM_ID: u32 = 0;

pub const ESTABLISH_INTRO: u8 = 1;
pub const ESTABLISH_INTRO_OK: u8 = 2;
pub const ESTABLISH_INTRO_FAIL: u8 = 3;
pub const INTRODUCE1: u8 = 4;
pub const INTRODUCE_ACK: u8 = 5;
pub const INTRODUCE2: u8 = 6;
pub const RENDEZVOUS_JOIN: u8 = 7;
pub const RENDEZVOUS_JOINED: u8 = 8;
pub const RENDEZVOUS_DATA: u8 = 9;

/// Defensive upper bounds on untrusted-input sizes -- unreachable by a
/// well-formed message, so a corrupt/malicious peer gets a clean
/// [`HsWireError`] instead of an oversized allocation.
pub const MAX_HOST_LEN: usize = 255;
pub const MAX_MESSAGE_LEN: usize = 255;
pub const MAX_SEALED_LEN: usize = 4096;
pub const MAX_DATA_LEN: usize = 1 << 20;

const ED25519_KEY_LEN: usize = 32;
const X25519_KEY_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;
const COOKIE_LEN: usize = 32;
/// 4-byte magic + 1-byte message type.
const MESSAGE_HEADER_LEN: usize = 5;

/// Upper bound on one complete reassembled hidden-service message,
/// enforced by [`HsReassembler::push`].
///
/// Without this, `HsReassembler` (like `dirwire::DirReassembler`)
/// accumulated every reassembled byte into an ever-growing `Vec<u8>` with
/// no cap: a peer could hold open one intro/rendezvous circuit and stream
/// an unbounded sequence of small, in-order `Fragment` cells without ever
/// setting FIN, since size limits were only checked once a message was
/// declared complete -- never triggered by such a peer. Pre-authentication
/// remote memory-exhaustion DoS (mirrors the identical fix in
/// `Authority/allium/src/hswire.rs`/`Relays/allium/src/hswire.rs`).
///
/// This module's own worst case is `RENDEZVOUS_DATA` at up to
/// `MAX_DATA_LEN`, plus message-header framing -- not a guessed round
/// number. Any wire-valid message is guaranteed to fit.
const MAX_REASSEMBLED_LEN: usize = MESSAGE_HEADER_LEN + MAX_DATA_LEN;

fn expect(data: &[u8], expected_type: u8, label: &str) -> Result<(), HsWireError> {
    if !data.starts_with(HS_MAGIC) {
        return Err(err(format!("bad hidden-service magic in {label}")));
    }
    if data.len() < MESSAGE_HEADER_LEN {
        return Err(err(format!("{label} shorter than the message header")));
    }
    if data[4] != expected_type {
        return Err(err(format!("{label}: expected message type {expected_type}, got {}", data[4])));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ESTABLISH_INTRO: service -> intro relay
// ---------------------------------------------------------------------------

/// The bytes an ESTABLISH_INTRO's signature covers.
///
/// Binding the timestamp stops a captured ESTABLISH_INTRO from being
/// replayed indefinitely against a different intro relay; the relay
/// enforces freshness (a few minutes) when it checks the signature, not
/// this function -- it only builds the payload the same way on both ends.
///
/// `auth_pubkey`: a service's per-intro-point key
/// ([`crate::hiddenservice::ServiceIdentity::intro_auth_keypair`]), never
/// its real, cross-intro-point identity key.
///
/// # Errors
/// [`HsWireError`] if `auth_pubkey` is not 32 bytes.
pub fn establish_intro_signing_payload(auth_pubkey: &[u8], timestamp: f64) -> Result<Vec<u8>, HsWireError> {
    if auth_pubkey.len() != ED25519_KEY_LEN {
        return Err(err(format!("auth_pubkey must be {ED25519_KEY_LEN} bytes")));
    }
    let mut out = b"allium-hs-establish-intro-v1".to_vec();
    out.extend_from_slice(auth_pubkey);
    out.extend_from_slice(&timestamp.to_be_bytes());
    Ok(out)
}

/// `auth_pubkey`: see [`establish_intro_signing_payload`].
///
/// # Errors
/// [`HsWireError`] if `auth_pubkey` is not 32 bytes or `signature` is not
/// 64 bytes.
pub fn encode_establish_intro(auth_pubkey: &[u8], timestamp: f64, signature: &[u8]) -> Result<Vec<u8>, HsWireError> {
    if auth_pubkey.len() != ED25519_KEY_LEN {
        return Err(err(format!("auth_pubkey must be {ED25519_KEY_LEN} bytes")));
    }
    if signature.len() != ED25519_SIG_LEN {
        return Err(err(format!("signature must be {ED25519_SIG_LEN} bytes")));
    }
    let mut out = HS_MAGIC.to_vec();
    out.push(ESTABLISH_INTRO);
    out.extend_from_slice(auth_pubkey);
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(signature);
    Ok(out)
}

/// Returns `(auth_pubkey, timestamp, signature)`. Not verified here -- the
/// caller checks the signature against [`establish_intro_signing_payload`].
///
/// # Errors
/// [`HsWireError`] on bad magic/type or truncation.
pub fn decode_establish_intro(data: &[u8]) -> Result<(Vec<u8>, f64, Vec<u8>), HsWireError> {
    expect(data, ESTABLISH_INTRO, "establish-intro")?;
    let needed = MESSAGE_HEADER_LEN + ED25519_KEY_LEN + 8 + ED25519_SIG_LEN;
    if data.len() < needed {
        return Err(err("establish-intro truncated"));
    }
    let mut offset = MESSAGE_HEADER_LEN;
    let auth_pubkey = data[offset..offset + ED25519_KEY_LEN].to_vec();
    offset += ED25519_KEY_LEN;
    let timestamp = f64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
    offset += 8;
    let signature = data[offset..offset + ED25519_SIG_LEN].to_vec();
    Ok((auth_pubkey, timestamp, signature))
}

pub fn encode_establish_intro_reply(ok: bool, message: &str) -> Vec<u8> {
    let mut body = message.as_bytes().to_vec();
    body.truncate(MAX_MESSAGE_LEN);
    let msg_type = if ok { ESTABLISH_INTRO_OK } else { ESTABLISH_INTRO_FAIL };
    let mut out = HS_MAGIC.to_vec();
    out.push(msg_type);
    out.push(body.len() as u8);
    out.extend(body);
    out
}

/// # Errors
/// [`HsWireError`] on bad magic/type or truncation.
pub fn decode_establish_intro_reply(data: &[u8]) -> Result<(bool, String), HsWireError> {
    if !data.starts_with(HS_MAGIC) {
        return Err(err("bad hidden-service magic in establish-intro reply"));
    }
    if data.len() < MESSAGE_HEADER_LEN + 1 {
        return Err(err("establish-intro reply truncated before its length"));
    }
    let msg_type = data[4];
    if msg_type != ESTABLISH_INTRO_OK && msg_type != ESTABLISH_INTRO_FAIL {
        return Err(err(format!("not an establish-intro reply: type {msg_type}")));
    }
    let msg_len = data[5] as usize;
    if data.len() < MESSAGE_HEADER_LEN + 1 + msg_len {
        return Err(err("establish-intro reply message truncated"));
    }
    let message = String::from_utf8_lossy(&data[6..6 + msg_len]).into_owned();
    Ok((msg_type == ESTABLISH_INTRO_OK, message))
}

// ---------------------------------------------------------------------------
// INTRODUCE1 / INTRODUCE_ACK: client <-> intro relay
// ---------------------------------------------------------------------------

/// `auth_pubkey` (the intro point's per-intro-point key) and
/// `client_ephemeral_pub` are visible to the intro relay (it needs the
/// former to route, and neither key reveals the service's real identity or
/// a network location); `sealed` is opaque to it -- see
/// [`crate::hiddenservice::seal_introduce`].
///
/// # Errors
/// [`HsWireError`] on a wrong-sized key or an oversized `sealed` envelope.
pub fn encode_introduce1(auth_pubkey: &[u8], client_ephemeral_pub: &[u8], sealed: &[u8]) -> Result<Vec<u8>, HsWireError> {
    if auth_pubkey.len() != ED25519_KEY_LEN {
        return Err(err(format!("auth_pubkey must be {ED25519_KEY_LEN} bytes")));
    }
    if client_ephemeral_pub.len() != X25519_KEY_LEN {
        return Err(err(format!("client_ephemeral_pub must be {X25519_KEY_LEN} bytes")));
    }
    if sealed.len() > MAX_SEALED_LEN {
        return Err(err(format!("sealed envelope is {} bytes, max is {MAX_SEALED_LEN}", sealed.len())));
    }
    let mut out = HS_MAGIC.to_vec();
    out.push(INTRODUCE1);
    out.extend_from_slice(auth_pubkey);
    out.extend_from_slice(client_ephemeral_pub);
    out.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
    out.extend_from_slice(sealed);
    Ok(out)
}

/// Returns `(auth_pubkey, client_ephemeral_pub, sealed)`.
///
/// # Errors
/// [`HsWireError`] on bad magic/type, truncation, or an oversized sealed
/// length.
pub fn decode_introduce1(data: &[u8]) -> Result<Introduce1, HsWireError> {
    expect(data, INTRODUCE1, "introduce1")?;
    let fixed = MESSAGE_HEADER_LEN + ED25519_KEY_LEN + X25519_KEY_LEN + 2;
    if data.len() < fixed {
        return Err(err("introduce1 truncated before its fixed fields"));
    }
    let mut offset = MESSAGE_HEADER_LEN;
    let auth_pubkey = data[offset..offset + ED25519_KEY_LEN].to_vec();
    offset += ED25519_KEY_LEN;
    let client_ephemeral_pub = data[offset..offset + X25519_KEY_LEN].to_vec();
    offset += X25519_KEY_LEN;
    let sealed_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    if sealed_len > MAX_SEALED_LEN || data.len() < offset + sealed_len {
        return Err(err("introduce1 sealed envelope truncated or oversized"));
    }
    let sealed = data[offset..offset + sealed_len].to_vec();
    Ok((auth_pubkey, client_ephemeral_pub, sealed))
}

pub fn encode_introduce_ack(ok: bool, message: &str) -> Vec<u8> {
    let mut body = message.as_bytes().to_vec();
    body.truncate(MAX_MESSAGE_LEN);
    let mut out = HS_MAGIC.to_vec();
    out.push(INTRODUCE_ACK);
    out.push(if ok { 1 } else { 0 });
    out.push(body.len() as u8);
    out.extend(body);
    out
}

/// # Errors
/// [`HsWireError`] on bad magic/type or truncation.
pub fn decode_introduce_ack(data: &[u8]) -> Result<(bool, String), HsWireError> {
    expect(data, INTRODUCE_ACK, "introduce-ack")?;
    if data.len() < MESSAGE_HEADER_LEN + 2 {
        return Err(err("introduce-ack truncated before its status/length"));
    }
    let ok = data[5] == 1;
    let msg_len = data[6] as usize;
    if data.len() < MESSAGE_HEADER_LEN + 2 + msg_len {
        return Err(err("introduce-ack message truncated"));
    }
    let message = String::from_utf8_lossy(&data[7..7 + msg_len]).into_owned();
    Ok((ok, message))
}

// ---------------------------------------------------------------------------
// INTRODUCE2: intro relay -> service (the forwarded envelope)
// ---------------------------------------------------------------------------

/// Same envelope as INTRODUCE1, minus `auth_pubkey` -- the intro relay
/// already knows which service this is by which registered circuit it
/// arrived on, so it is not repeated here.
///
/// # Errors
/// [`HsWireError`] on a wrong-sized key or an oversized `sealed` envelope.
pub fn encode_introduce2(client_ephemeral_pub: &[u8], sealed: &[u8]) -> Result<Vec<u8>, HsWireError> {
    if client_ephemeral_pub.len() != X25519_KEY_LEN {
        return Err(err(format!("client_ephemeral_pub must be {X25519_KEY_LEN} bytes")));
    }
    if sealed.len() > MAX_SEALED_LEN {
        return Err(err(format!("sealed envelope is {} bytes, max is {MAX_SEALED_LEN}", sealed.len())));
    }
    let mut out = HS_MAGIC.to_vec();
    out.push(INTRODUCE2);
    out.extend_from_slice(client_ephemeral_pub);
    out.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
    out.extend_from_slice(sealed);
    Ok(out)
}

/// Returns `(client_ephemeral_pub, sealed)`.
///
/// # Errors
/// [`HsWireError`] on bad magic/type, truncation, or an oversized sealed
/// length.
pub fn decode_introduce2(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), HsWireError> {
    expect(data, INTRODUCE2, "introduce2")?;
    let fixed = MESSAGE_HEADER_LEN + X25519_KEY_LEN + 2;
    if data.len() < fixed {
        return Err(err("introduce2 truncated before its fixed fields"));
    }
    let mut offset = MESSAGE_HEADER_LEN;
    let client_ephemeral_pub = data[offset..offset + X25519_KEY_LEN].to_vec();
    offset += X25519_KEY_LEN;
    let sealed_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    if sealed_len > MAX_SEALED_LEN || data.len() < offset + sealed_len {
        return Err(err("introduce2 sealed envelope truncated or oversized"));
    }
    let sealed = data[offset..offset + sealed_len].to_vec();
    Ok((client_ephemeral_pub, sealed))
}

// ---------------------------------------------------------------------------
// The sealed INTRODUCE1/2 inner plaintext: which rendezvous point, which cookie
// ---------------------------------------------------------------------------

/// The plaintext a client seals inside INTRODUCE1 (see
/// [`crate::hiddenservice::seal_introduce`]) -- which rendezvous point it
/// picked and the cookie both sides will use to pair up there.
///
/// # Errors
/// [`HsWireError`] on a wrong-sized `rp_identity`/`cookie` or an oversized
/// `rp_host`.
pub fn encode_rendezvous_request(rp_identity: &[u8], rp_host: &str, rp_port: u16, cookie: &[u8]) -> Result<Vec<u8>, HsWireError> {
    if rp_identity.len() != ED25519_KEY_LEN {
        return Err(err(format!("rp_identity must be {ED25519_KEY_LEN} bytes")));
    }
    if cookie.len() != COOKIE_LEN {
        return Err(err(format!("cookie must be {COOKIE_LEN} bytes")));
    }
    let host = rp_host.as_bytes();
    if host.len() > MAX_HOST_LEN {
        return Err(err(format!("rp_host is {} bytes, max is {MAX_HOST_LEN}", host.len())));
    }
    let mut out = Vec::new();
    out.extend_from_slice(rp_identity);
    out.push(host.len() as u8);
    out.extend_from_slice(host);
    out.extend_from_slice(&rp_port.to_be_bytes());
    out.extend_from_slice(cookie);
    Ok(out)
}

/// Returns `(rp_identity, rp_host, rp_port, cookie)`.
///
/// # Errors
/// [`HsWireError`] on truncation, an oversized host, or non-UTF-8 host
/// bytes -- this plaintext is only AEAD-authenticated with the service's
/// *public* introduction-encryption key, so any client can craft a
/// well-formed-but-invalid-UTF-8 `rp_host` and reach this decode; it must
/// raise cleanly like every other malformed-field case here.
pub fn decode_rendezvous_request(data: &[u8]) -> Result<(Vec<u8>, String, u16, Vec<u8>), HsWireError> {
    if data.len() < ED25519_KEY_LEN + 1 {
        return Err(err("rendezvous request truncated before host length"));
    }
    let rp_identity = data[..ED25519_KEY_LEN].to_vec();
    let mut offset = ED25519_KEY_LEN;
    let host_len = data[offset] as usize;
    offset += 1;
    if host_len > MAX_HOST_LEN || data.len() < offset + host_len + 2 + COOKIE_LEN {
        return Err(err("rendezvous request truncated or oversized"));
    }
    let rp_host = std::str::from_utf8(&data[offset..offset + host_len])
        .map_err(|_| err("rendezvous request host is not valid UTF-8"))?
        .to_string();
    offset += host_len;
    let rp_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    let cookie = data[offset..offset + COOKIE_LEN].to_vec();
    Ok((rp_identity, rp_host, rp_port, cookie))
}

// ---------------------------------------------------------------------------
// RENDEZVOUS_JOIN / RENDEZVOUS_JOINED: client & service <-> rendezvous point
// ---------------------------------------------------------------------------

/// # Errors
/// [`HsWireError`] if `cookie` is not 32 bytes.
pub fn encode_rendezvous_join(cookie: &[u8]) -> Result<Vec<u8>, HsWireError> {
    if cookie.len() != COOKIE_LEN {
        return Err(err(format!("cookie must be {COOKIE_LEN} bytes")));
    }
    let mut out = HS_MAGIC.to_vec();
    out.push(RENDEZVOUS_JOIN);
    out.extend_from_slice(cookie);
    Ok(out)
}

/// # Errors
/// [`HsWireError`] on bad magic/type or truncation.
pub fn decode_rendezvous_join(data: &[u8]) -> Result<Vec<u8>, HsWireError> {
    expect(data, RENDEZVOUS_JOIN, "rendezvous-join")?;
    if data.len() < MESSAGE_HEADER_LEN + COOKIE_LEN {
        return Err(err("rendezvous-join truncated"));
    }
    Ok(data[MESSAGE_HEADER_LEN..MESSAGE_HEADER_LEN + COOKIE_LEN].to_vec())
}

pub fn encode_rendezvous_joined(ok: bool, message: &str) -> Vec<u8> {
    let mut body = message.as_bytes().to_vec();
    body.truncate(MAX_MESSAGE_LEN);
    let mut out = HS_MAGIC.to_vec();
    out.push(RENDEZVOUS_JOINED);
    out.push(if ok { 1 } else { 0 });
    out.push(body.len() as u8);
    out.extend(body);
    out
}

/// # Errors
/// [`HsWireError`] on bad magic/type or truncation.
pub fn decode_rendezvous_joined(data: &[u8]) -> Result<(bool, String), HsWireError> {
    expect(data, RENDEZVOUS_JOINED, "rendezvous-joined")?;
    if data.len() < MESSAGE_HEADER_LEN + 2 {
        return Err(err("rendezvous-joined truncated before its status/length"));
    }
    let ok = data[5] == 1;
    let msg_len = data[6] as usize;
    if data.len() < MESSAGE_HEADER_LEN + 2 + msg_len {
        return Err(err("rendezvous-joined message truncated"));
    }
    let message = String::from_utf8_lossy(&data[7..7 + msg_len]).into_owned();
    Ok((ok, message))
}

// ---------------------------------------------------------------------------
// RENDEZVOUS_DATA: opaque post-join tunnel bytes
// ---------------------------------------------------------------------------

/// Wraps opaque tunnel bytes (a session handshake message, or
/// [`crate::hiddenservice::HsSession`]-sealed application data) for the
/// rendezvous point to forward untouched. The rendezvous point reads only
/// the magic/type prefix -- never `payload` itself.
///
/// # Errors
/// [`HsWireError`] if `payload` exceeds [`MAX_DATA_LEN`].
pub fn encode_rendezvous_data(payload: &[u8]) -> Result<Vec<u8>, HsWireError> {
    if payload.len() > MAX_DATA_LEN {
        return Err(err(format!("rendezvous data is {} bytes, max is {MAX_DATA_LEN}", payload.len())));
    }
    let mut out = HS_MAGIC.to_vec();
    out.push(RENDEZVOUS_DATA);
    out.extend_from_slice(payload);
    Ok(out)
}

/// # Errors
/// [`HsWireError`] on bad magic/type.
pub fn decode_rendezvous_data(data: &[u8]) -> Result<Vec<u8>, HsWireError> {
    expect(data, RENDEZVOUS_DATA, "rendezvous-data")?;
    Ok(data[MESSAGE_HEADER_LEN..].to_vec())
}

// ---------------------------------------------------------------------------
// Fragmentation (identical shape to crate::dirwire's, independent copy so
// the two protocols never share mutable state)
// ---------------------------------------------------------------------------

/// Split a whole hidden-service control message into wire-ready cell
/// payloads, ready to hand straight to a circuit's send.
pub fn fragment_message(message: &[u8], mtu: usize) -> Vec<Vec<u8>> {
    let fragmenter = Fragmenter::new(mtu, HS_STREAM_ID).expect("mtu is always >= 1 in this module's callers");
    fragmenter.fragment(message).iter().map(encode_fragment).collect()
}

/// Reassembles a *sequence* of hidden-service messages from Fragment cells.
///
/// Unlike [`crate::dirwire::DirReassembler`] (good for exactly one message
/// and then discarded, matching a directory circuit's one-shot use), a
/// hidden-service circuit can carry many messages over its lifetime -- an
/// intro circuit's ESTABLISH_INTRO followed by any number of later
/// INTRODUCE2s, or a rendezvous circuit's RENDEZVOUS_JOIN followed by a
/// stream of RENDEZVOUS_DATA. So [`Self::push`] resets its internal state
/// the moment one message completes, ready for the next -- callers just
/// keep calling it for the life of the circuit rather than discarding it
/// after one result.
pub struct HsReassembler {
    max_pending: usize,
    reassembler: Reassembler,
    buffer: Vec<u8>,
}

impl HsReassembler {
    pub fn new(max_pending: usize) -> Self {
        HsReassembler { max_pending, reassembler: Reassembler::new(HS_STREAM_ID, max_pending), buffer: Vec::new() }
    }

    /// Feed one raw (already fragment-encoded) received cell payload.
    ///
    /// Returns a complete message the moment it becomes whole (after which
    /// this instance is reset and ready for the next one); `None` while
    /// more fragments are still expected.
    ///
    /// Rejects a message once it would exceed [`MAX_REASSEMBLED_LEN`],
    /// before the oversized bytes are ever appended -- matching
    /// `Authority`/`Relays`' own `hswire.rs`, which already had this
    /// check; this crate's copy never did, leaving an intro/rendezvous
    /// circuit's receive loop bounded only by its wall-clock timeout, not
    /// by bytes received, for the life of that timeout. Also resets
    /// internal state on that error (same as on a successful completion),
    /// since -- unlike `dirwire::DirReassembler`, which is one-shot and
    /// discarded by its caller on any error -- an `HsReassembler` is
    /// reused across many messages over one circuit's lifetime, so it
    /// must not be left stuck holding a maxed-out buffer for that
    /// circuit's remaining lifetime.
    ///
    /// # Errors
    /// [`HsWireError`] if `wire_bytes` does not decode as a [`Fragment`]
    /// for [`HS_STREAM_ID`], or if the reassembled message would exceed
    /// [`MAX_REASSEMBLED_LEN`].
    pub fn push(&mut self, wire_bytes: &[u8]) -> Result<Option<Vec<u8>>, HsWireError> {
        let fragment: Fragment =
            decode_fragment(wire_bytes).map_err(|e: FragmentError| err(format!("not a valid hidden-service fragment: {e}")))?;
        let chunk = self.reassembler.push(&fragment).map_err(|e| err(e.to_string()))?;
        if self.buffer.len() + chunk.len() > MAX_REASSEMBLED_LEN {
            self.buffer.clear();
            self.reassembler = Reassembler::new(HS_STREAM_ID, self.max_pending);
            return Err(err(format!("reassembled hidden-service message exceeds {MAX_REASSEMBLED_LEN} bytes; dropping message")));
        }
        self.buffer.extend(chunk);
        if self.reassembler.finished() {
            let message = std::mem::take(&mut self.buffer);
            self.reassembler = Reassembler::new(HS_STREAM_ID, self.max_pending);
            return Ok(Some(message));
        }
        Ok(None)
    }
}

impl Default for HsReassembler {
    fn default() -> Self {
        Self::new(64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn establish_intro_round_trip() {
        let auth_pubkey = [1u8; 32];
        let signature = [2u8; 64];
        let wire = encode_establish_intro(&auth_pubkey, 1_700_000_000.0, &signature).unwrap();
        let (decoded_key, decoded_ts, decoded_sig) = decode_establish_intro(&wire).unwrap();
        assert_eq!(decoded_key, auth_pubkey);
        assert_eq!(decoded_ts, 1_700_000_000.0);
        assert_eq!(decoded_sig, signature);
    }

    #[test]
    fn establish_intro_signing_payload_binds_key_and_timestamp() {
        let key = [3u8; 32];
        let p1 = establish_intro_signing_payload(&key, 100.0).unwrap();
        let p2 = establish_intro_signing_payload(&key, 200.0).unwrap();
        assert_ne!(p1, p2);
        assert!(establish_intro_signing_payload(&[1, 2, 3], 100.0).is_err());
    }

    #[test]
    fn establish_intro_reply_round_trip_ok_and_fail() {
        let wire_ok = encode_establish_intro_reply(true, "welcome");
        assert_eq!(decode_establish_intro_reply(&wire_ok).unwrap(), (true, "welcome".to_string()));

        let wire_fail = encode_establish_intro_reply(false, "rejected");
        assert_eq!(decode_establish_intro_reply(&wire_fail).unwrap(), (false, "rejected".to_string()));
    }

    #[test]
    fn introduce1_round_trip() {
        let auth_pubkey = [4u8; 32];
        let client_ephemeral = [5u8; 32];
        let sealed = vec![9u8; 200];
        let wire = encode_introduce1(&auth_pubkey, &client_ephemeral, &sealed).unwrap();
        let (decoded_auth, decoded_eph, decoded_sealed) = decode_introduce1(&wire).unwrap();
        assert_eq!(decoded_auth, auth_pubkey);
        assert_eq!(decoded_eph, client_ephemeral);
        assert_eq!(decoded_sealed, sealed);
    }

    #[test]
    fn introduce1_rejects_oversized_sealed() {
        let auth_pubkey = [4u8; 32];
        let client_ephemeral = [5u8; 32];
        let sealed = vec![9u8; MAX_SEALED_LEN + 1];
        assert!(encode_introduce1(&auth_pubkey, &client_ephemeral, &sealed).is_err());
    }

    #[test]
    fn introduce_ack_round_trip() {
        let wire = encode_introduce_ack(true, "ok");
        assert_eq!(decode_introduce_ack(&wire).unwrap(), (true, "ok".to_string()));
    }

    #[test]
    fn introduce2_round_trip() {
        let client_ephemeral = [6u8; 32];
        let sealed = vec![7u8; 50];
        let wire = encode_introduce2(&client_ephemeral, &sealed).unwrap();
        let (decoded_eph, decoded_sealed) = decode_introduce2(&wire).unwrap();
        assert_eq!(decoded_eph, client_ephemeral);
        assert_eq!(decoded_sealed, sealed);
    }

    #[test]
    fn rendezvous_request_round_trip() {
        let rp_identity = [8u8; 32];
        let cookie = [9u8; 32];
        let plaintext = encode_rendezvous_request(&rp_identity, "203.0.113.5", 9050, &cookie).unwrap();
        let (decoded_id, decoded_host, decoded_port, decoded_cookie) = decode_rendezvous_request(&plaintext).unwrap();
        assert_eq!(decoded_id, rp_identity);
        assert_eq!(decoded_host, "203.0.113.5");
        assert_eq!(decoded_port, 9050);
        assert_eq!(decoded_cookie, cookie);
    }

    #[test]
    fn rendezvous_request_rejects_wrong_sizes() {
        assert!(encode_rendezvous_request(&[1, 2, 3], "host", 80, &[0u8; 32]).is_err());
        assert!(encode_rendezvous_request(&[1u8; 32], "host", 80, &[0u8; 10]).is_err());
    }

    #[test]
    fn rendezvous_join_round_trip() {
        let cookie = [10u8; 32];
        let wire = encode_rendezvous_join(&cookie).unwrap();
        assert_eq!(decode_rendezvous_join(&wire).unwrap(), cookie);
        assert!(encode_rendezvous_join(&[1, 2, 3]).is_err());
    }

    #[test]
    fn rendezvous_joined_round_trip() {
        let wire = encode_rendezvous_joined(true, "joined");
        assert_eq!(decode_rendezvous_joined(&wire).unwrap(), (true, "joined".to_string()));
    }

    #[test]
    fn rendezvous_data_round_trip() {
        let payload = vec![0xABu8; 1000];
        let wire = encode_rendezvous_data(&payload).unwrap();
        assert_eq!(decode_rendezvous_data(&wire).unwrap(), payload);
    }

    #[test]
    fn rendezvous_data_rejects_oversized_payload() {
        let payload = vec![0u8; MAX_DATA_LEN + 1];
        assert!(encode_rendezvous_data(&payload).is_err());
    }

    #[test]
    fn wrong_message_type_is_rejected() {
        let wire = encode_introduce_ack(true, "ok");
        assert!(decode_introduce1(&wire).is_err());
        assert!(decode_establish_intro(&wire).is_err());
    }

    #[test]
    fn fragment_and_reassemble_single_message() {
        let wire = encode_rendezvous_joined(true, "hello");
        let fragments = fragment_message(&wire, 256);
        assert_eq!(fragments.len(), 1);
        let mut r = HsReassembler::new(64);
        assert_eq!(r.push(&fragments[0]).unwrap(), Some(wire));
    }

    #[test]
    fn hs_reassembler_resets_for_a_sequence_of_messages() {
        let msg1 = encode_establish_intro(&[1u8; 32], 1000.0, &[2u8; 64]).unwrap();
        let msg2 = encode_introduce_ack(false, "busy");
        let msg3 = encode_rendezvous_data(&[7u8; 100]).unwrap();

        let mut r = HsReassembler::new(64);
        for wire in [&msg1, &msg2, &msg3] {
            let fragments = fragment_message(wire, 16); // small mtu forces multiple fragments
            let mut result = None;
            for f in &fragments {
                result = r.push(f).unwrap();
            }
            assert_eq!(result.as_ref(), Some(wire));
        }
    }

    #[test]
    fn hs_reassembler_rejects_garbage_and_wrong_stream() {
        let mut r = HsReassembler::new(64);
        assert!(r.push(&[0u8; 2]).is_err());

        let frag = Fragment { stream_id: 42, offset: 0, fin: true, data: b"x".to_vec() };
        let wire = encode_fragment(&frag);
        assert!(r.push(&wire).is_err());
    }

    /// A stream that never sends FIN must not be allowed to grow its
    /// reassembly buffer without bound -- exactly at the boundary: a
    /// message of precisely `MAX_REASSEMBLED_LEN` bytes must still
    /// reassemble, one byte more must be refused, and (unlike
    /// `dirwire::DirReassembler`, which is one-shot) the instance must
    /// reset and still be able to reassemble a normal message afterward,
    /// since one `HsReassembler` is reused across a circuit's lifetime.
    #[test]
    fn hs_reassembler_rejects_message_exceeding_max_reassembled_len_and_recovers() {
        let mut r = HsReassembler::new(64);
        let first = Fragment { stream_id: HS_STREAM_ID, offset: 0, fin: false, data: vec![0x41u8; MAX_REASSEMBLED_LEN] };
        assert_eq!(r.push(&encode_fragment(&first)).unwrap(), None);
        let second = Fragment { stream_id: HS_STREAM_ID, offset: MAX_REASSEMBLED_LEN as u32, fin: true, data: vec![0x42u8] };
        assert!(r.push(&encode_fragment(&second)).is_err());

        let msg2 = encode_rendezvous_join(&[3u8; COOKIE_LEN]).unwrap();
        let fragments = fragment_message(&msg2, 512);
        let mut result = None;
        for f in &fragments {
            result = r.push(f).unwrap();
        }
        assert_eq!(result.as_ref(), Some(&msg2));
    }
}
