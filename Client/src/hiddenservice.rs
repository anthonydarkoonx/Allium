//! Hidden services: reachable without a public IP, addressed as `x.allium`.
//!
//! Mirrors Tor's onion-service design in spirit, adapted to run entirely
//! over machinery this crate already has (the X25519/Ed25519 circuit
//! crypto, [`crate::directory`]/[`crate::dirwire`]'s directory service, and
//! [`crate::fragment`]) rather than a second protocol stack.
//!
//! **Addressing.** A service's identity is an Ed25519 keypair, exactly like
//! a relay's. Its address is a self-certifying encoding of the public key
//! -- `.allium` instead of `.onion` -- so a typo is caught by a checksum
//! and the address itself is proof of the key, with no certificate
//! authority involved. See [`encode_address`]/[`decode_address`].
//!
//! **Discovery.** A service publishes a signed [`HiddenServiceDescriptor`]
//! listing its introduction points to a directory authority
//! ([`HiddenServiceDirectory`]), keyed by a *blinded* index
//! ([`hs_directory_index`]) rather than its real address, so a directory
//! authority never needs the real identity key to serve a lookup, and a
//! request from one time period cannot be linked to a request from
//! another. As with a relay descriptor, the signature is checked locally
//! by whoever fetches it -- the authority is trusted for availability
//! only, never for integrity (nor, when client authorization is used, for
//! confidentiality -- see [`HiddenServiceDescriptor::create_with_client_auth`]).
//!
//! **Connecting**, in three hops of its own, each reusing an ordinary
//! 3-hop Allium circuit so no single relay ever sees both the client's and
//! the service's real address:
//!
//! 1. **Introduction.** A client builds a circuit to one of the service's
//!    introduction points and sends an INTRODUCE1: which rendezvous point
//!    it picked, a fresh one-time cookie, and a fresh ephemeral X25519
//!    public key, all sealed so only the service can read it
//!    ([`seal_introduce`]) -- the introduction point forwards the envelope
//!    but cannot open it.
//! 2. **Rendezvous.** The service, decrypting the envelope
//!    ([`ServiceIdentity::open_introduce`]), builds its own circuit to the
//!    rendezvous point the client named, and both sides send
//!    RENDEZVOUS_JOIN with the same cookie. The rendezvous point splices
//!    the two circuits, forwarding each side's opaque bytes to the other,
//!    never decrypting either.
//! 3. **Session.** On top of that spliced pipe, client and service run one
//!    more ephemeral-ECDH handshake and derive a session key pair
//!    ([`derive_session_keys`]) used to AEAD-seal every byte from here on
//!    ([`HsSession`]). This is what keeps the rendezvous point -- which
//!    *does* see the spliced traffic pass through it -- from reading any of
//!    it.
//!
//! Allium never parses or serves HTTP itself; a hidden service forwards raw
//! bytes between the session above and a plain local TCP connection.

use std::collections::HashMap;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use digest::{CustomizedInit, Digest as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::osrand;

const ED25519_KEY_LEN: usize = 32;
const X25519_KEY_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;
/// Length of a [`ClientAuthEntry::client_id_hint`] -- see `client_id_hint`.
pub const CLIENT_ID_HINT_LEN: usize = 16;

/// How long a freshly minted HS descriptor stays valid, in seconds.
pub const DEFAULT_HS_DESCRIPTOR_LIFETIME: f64 = 3600.0;
/// Longest `not_after - not_before` span a verifying store accepts, by
/// default (mirrors `allium.directory`'s `MAX_DESCRIPTOR_LIFETIME` fix).
pub const MAX_HS_DESCRIPTOR_LIFETIME: f64 = DEFAULT_HS_DESCRIPTOR_LIFETIME * 24.0;

/// Default cadence at which a service's introduction-encryption key is
/// rotated (mirrors Tor v3's own periodic introduction-key rotation): a
/// key or seed compromise then exposes at most one rotation period of
/// history, not the service's entire lifetime -- see [`ServiceIdentity`].
pub const DEFAULT_INTRODUCTION_KEY_ROTATION: f64 = 24.0 * 3600.0;
/// How long a just-superseded introduction key is still accepted for
/// decrypting an INTRODUCE1 after rotation, so a client working from a
/// not-yet-refreshed cached descriptor is not silently dropped mid-rotation.
pub const DEFAULT_INTRODUCTION_KEY_GRACE: f64 = 3600.0;
/// Hard cap on remembered INTRODUCE envelopes per service. Bounds the
/// memory one service can be made to spend on replay tracking.
pub const DEFAULT_INTRODUCE_REPLAY_ENTRIES: usize = 8192;

const ADDRESS_VERSION: u8 = 1;
const ADDRESS_SUFFIX: &str = ".allium";

/// How often the blinded directory index changes. A day is long enough
/// that a client only needs one HS FETCH per visit-worthy session and a
/// service only needs to republish under a new index once a day, but short
/// enough that a long-lived directory authority cannot build an indefinite
/// history of "this exact index was looked up on these dates" for a single
/// service.
pub const HS_DIRECTORY_INDEX_PERIOD: f64 = 86400.0;

/// Every error this module raises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HiddenServiceError {
    /// An `x.allium` address was malformed or failed its checksum.
    Address(String),
    /// A descriptor's or a control message's signature did not verify.
    SignatureInvalid(String),
    /// A descriptor was outside its validity window when used.
    DescriptorExpired(String),
    /// A descriptor's `not_after - not_before` span exceeds this
    /// directory's [`MAX_HS_DESCRIPTOR_LIFETIME`] (or a caller-supplied
    /// override).
    DescriptorLifetimeTooLong(String),
    /// An INTRODUCE envelope has already been opened once before.
    IntroduceReplayed(String),
    /// A descriptor restricts its introduction points to specific clients,
    /// and the caller gave no key, the wrong key, or the descriptor's
    /// encrypted payload did not decrypt cleanly.
    ClientNotAuthorized(String),
    /// An X25519 Diffie-Hellman input or output was a low-order point (the
    /// all-zero point or one of its seven siblings) -- see
    /// [`x25519_dalek::SharedSecret::was_contributory`]. Rejecting this is
    /// what stops a rendezvous point from forcing a predictable shared
    /// secret.
    NonContributoryKey(String),
    /// The rendezvous handshake's MAC did not verify -- either the
    /// rendezvous point substituted its own ephemeral key without knowing
    /// the service's introduction secret, or the message was corrupted in
    /// transit.
    RendezvousAuthFailed(String),
    /// A filesystem operation on a persisted key (or its containing
    /// directory) failed.
    Io(String),
    /// A [`HiddenServiceDirectory`] already holds `MAX_HS_DESCRIPTORS`
    /// distinct identities; a genuinely new one is refused until one
    /// expires or is pruned. Never raised for a rotation of an identity
    /// already held.
    StoreFull(String),
    /// A rendezvous-session frame was authentic but is one this side already
    /// received (a duplicate or replay). Harmless to drop: nothing is
    /// delivered twice.
    SessionReplay(String),
    /// A rendezvous-session frame was authentic but arrived ahead of the one
    /// expected, so at least one earlier frame was dropped or reordered.
    /// Unrecoverable: the stream would have a hole in it, so the session
    /// must end.
    SessionGap(String),
    /// A frame arrived after the peer's authenticated close, or the
    /// operation is not allowed once this side has closed. Fatal.
    SessionClosed(String),
    /// Any other input-validation failure.
    Other(String),
}

impl std::fmt::Display for HiddenServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HiddenServiceError::Address(m)
            | HiddenServiceError::SignatureInvalid(m)
            | HiddenServiceError::DescriptorExpired(m)
            | HiddenServiceError::DescriptorLifetimeTooLong(m)
            | HiddenServiceError::IntroduceReplayed(m)
            | HiddenServiceError::ClientNotAuthorized(m)
            | HiddenServiceError::NonContributoryKey(m)
            | HiddenServiceError::RendezvousAuthFailed(m)
            | HiddenServiceError::Io(m)
            | HiddenServiceError::StoreFull(m)
            | HiddenServiceError::SessionReplay(m)
            | HiddenServiceError::SessionGap(m)
            | HiddenServiceError::SessionClosed(m)
            | HiddenServiceError::Other(m) => write!(f, "{m}"),
        }
    }
}
impl std::error::Error for HiddenServiceError {}

fn now_unix() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64()
}

fn random_array_32() -> [u8; 32] {
    let v = osrand::bytes(32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

fn x25519_public(seed: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*seed)).to_bytes()
}

// ---------------------------------------------------------------------------
// Addressing
// ---------------------------------------------------------------------------

/// 2-byte checksum binding an identity key to [`ADDRESS_VERSION`]. Purely a
/// typo/corruption catcher (like Tor's own v3 address checksum) -- it is
/// not a security boundary, since the identity key itself is what
/// [`HiddenServiceDescriptor::verify`] actually authenticates.
fn address_checksum(identity_public: &[u8]) -> [u8; 2] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"allium-hs-checksum-v1");
    hasher.update(identity_public);
    hasher.update([ADDRESS_VERSION]);
    let digest = hasher.finalize();
    [digest[0], digest[1]]
}

/// RFC 4648 base32 alphabet, no padding.
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = (buffer >> bits) & 0x1F;
            out.push(BASE32_ALPHABET[index as usize] as char);
        }
    }
    if bits > 0 {
        let index = (buffer << (5 - bits)) & 0x1F;
        out.push(BASE32_ALPHABET[index as usize] as char);
    }
    out
}

fn base32_decode(text: &str) -> Result<Vec<u8>, HiddenServiceError> {
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    for c in text.chars() {
        let upper = c.to_ascii_uppercase();
        let value = BASE32_ALPHABET
            .iter()
            .position(|&b| b as char == upper)
            .ok_or_else(|| HiddenServiceError::Address(format!("not valid base32: {c:?}")))?;
        buffer = (buffer << 5) | value as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

/// Encode a 32-byte Ed25519 public key as an `x.allium` address.
///
/// # Errors
/// [`HiddenServiceError::Address`] if `identity_public` is not 32 bytes.
pub fn encode_address(identity_public: &[u8]) -> Result<String, HiddenServiceError> {
    if identity_public.len() != ED25519_KEY_LEN {
        return Err(HiddenServiceError::Address(format!(
            "identity key must be {ED25519_KEY_LEN} bytes, got {}",
            identity_public.len()
        )));
    }
    let checksum = address_checksum(identity_public);
    let mut payload = Vec::with_capacity(ED25519_KEY_LEN + 3);
    payload.extend_from_slice(identity_public);
    payload.extend_from_slice(&checksum);
    payload.push(ADDRESS_VERSION);
    let label = base32_encode(&payload).to_lowercase();
    Ok(format!("{label}{ADDRESS_SUFFIX}"))
}

/// Decode an `x.allium` address back to its 32-byte identity key.
///
/// # Errors
/// [`HiddenServiceError::Address`] on a bad suffix, malformed base32,
/// wrong length, unknown version, or a checksum that does not match.
pub fn decode_address(address: &str) -> Result<Vec<u8>, HiddenServiceError> {
    let text = address.trim().to_lowercase();
    let label = text
        .strip_suffix(ADDRESS_SUFFIX)
        .ok_or_else(|| HiddenServiceError::Address(format!("address must end with {ADDRESS_SUFFIX:?}: {address:?}")))?;
    if label.is_empty() {
        return Err(HiddenServiceError::Address("empty address label".to_string()));
    }
    let payload = base32_decode(label)?;
    let expected_len = ED25519_KEY_LEN + 2 + 1;
    if payload.len() != expected_len {
        return Err(HiddenServiceError::Address(format!(
            "decoded address is {} bytes, expected {expected_len}",
            payload.len()
        )));
    }
    let identity_public = payload[..ED25519_KEY_LEN].to_vec();
    let checksum = &payload[ED25519_KEY_LEN..ED25519_KEY_LEN + 2];
    let version = payload[ED25519_KEY_LEN + 2];
    if version != ADDRESS_VERSION {
        return Err(HiddenServiceError::Address(format!("unsupported address version {version}")));
    }
    if checksum != address_checksum(&identity_public) {
        return Err(HiddenServiceError::Address("bad checksum -- mistyped or corrupted address?".to_string()));
    }
    Ok(identity_public)
}

// ---------------------------------------------------------------------------
// Directory index blinding
// ---------------------------------------------------------------------------

/// Return the current time-period number for [`hs_directory_index`]. Both
/// client and service call this with no arguments (or the same `period`)
/// and get the same value as long as their clocks agree to within
/// `period` -- no coordination beyond that is needed.
pub fn hs_directory_period(now: Option<f64>, period: Option<f64>) -> i64 {
    let now = now.unwrap_or_else(now_unix);
    let period = period.unwrap_or(HS_DIRECTORY_INDEX_PERIOD);
    (now / period).floor() as i64
}

/// Return the blinded lookup key a client/service uses to address the
/// directory for `identity_public`, instead of the real identity key.
///
/// This is a keyed hash (not reversible to recover `identity_public` from
/// the index alone), so a request from one time period cannot be linked to
/// a request from another period without already knowing
/// `identity_public` -- the directory authority (and anyone who can see
/// requests reach it) never gets a stable, permanent handle for "how often
/// is this exact hidden service looked up."
///
/// # Errors
/// [`HiddenServiceError::Other`] if `identity_public` is not 32 bytes.
pub fn hs_directory_index(identity_public: &[u8], period: Option<i64>) -> Result<[u8; 32], HiddenServiceError> {
    use blake2::Blake2bMac;
    use digest::consts::U32;
    use digest::{FixedOutput, Update};

    if identity_public.len() != ED25519_KEY_LEN {
        return Err(HiddenServiceError::Other(format!(
            "identity key must be {ED25519_KEY_LEN} bytes, got {}",
            identity_public.len()
        )));
    }
    let period = period.unwrap_or_else(|| hs_directory_period(None, None));
    let mut mac = Blake2bMac::<U32>::new_with_salt_and_personal(Some(identity_public), &[], b"allium-hs-diridx")
        .expect("32-byte key and a short persona are within blake2b's limits");
    Update::update(&mut mac, &period.to_be_bytes());
    Ok(FixedOutput::finalize_fixed(mac).into())
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// HKDF-SHA256, the same construction [`crate::handshake`] uses for the
/// per-hop handshake, kept as an independent copy here (rather than a
/// shared helper): the circuit handshake's keys authenticate a *relay
/// identity*, while everything derived here authenticates an
/// *application-level* rendezvous session between client and service --
/// deliberately separate key material even though the primitive is
/// identical.
fn hs_hkdf(shared_secret: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm).expect("HKDF-SHA256 output length is always valid for the lengths this module requests");
    okm
}

/// A compact, collision-resistant identity for one sealed INTRODUCE
/// envelope, remembered by [`ServiceIdentity::open_introduce`]'s replay
/// guard. Hashed rather than stored whole so a remembered entry costs 16
/// bytes instead of the envelope's full length. Both halves are bound in:
/// the sealed bytes carry a fresh random AEAD nonce per sealing, so they
/// already differ between two genuine introductions, and the client's
/// ephemeral public key is included because it is the other half of what
/// the service needs to reproduce the shared secret.
fn introduce_replay_key(client_ephemeral_public: &[u8], sealed: &[u8]) -> [u8; 16] {
    use blake2::Blake2b;
    use digest::consts::U16;
    let mut hasher = Blake2b::<U16>::new_customized(b"allium-intro-rp");
    hasher.update(client_ephemeral_public);
    hasher.update(sealed);
    hasher.finalize().into()
}

/// A minimal replay cache keyed by an `f64`-epoch clock (matching the
/// clock abstraction [`ServiceIdentity`] and [`HiddenServiceDirectory`]
/// use throughout this module), rather than
/// [`crate::reliability::HandshakeReplayGuard`], whose `Clock` trait
/// produces `std::time::Instant` and has no way to represent an arbitrary
/// injected epoch time (what a deterministic rotation/expiry test here
/// needs). Same shape as that guard otherwise: a bounded set of recently
/// seen keys, oldest evicted first past `max_entries`, each entry expiring
/// after `ttl` seconds.
struct ReplayGuard {
    max_entries: usize,
    ttl: f64,
    clock: Arc<dyn Fn() -> f64 + Send + Sync>,
    seen: HashMap<[u8; 16], (u64, f64)>,
    next_seq: u64,
}

impl ReplayGuard {
    fn new(max_entries: usize, ttl: f64, clock: Arc<dyn Fn() -> f64 + Send + Sync>) -> Self {
        ReplayGuard { max_entries: max_entries.max(1), ttl, clock, seen: HashMap::new(), next_seq: 0 }
    }

    fn expire(&mut self) {
        let now = (self.clock)();
        self.seen.retain(|_, (_, seen_at)| now - *seen_at < self.ttl);
    }

    /// Record `key`, returning `true` the first time it is seen (accept
    /// it) and `false` on a repeat (a replay -- reject it).
    fn accept(&mut self, key: [u8; 16]) -> bool {
        self.expire();
        let now = (self.clock)();
        if let Some(entry) = self.seen.get_mut(&key) {
            entry.1 = now;
            return false;
        }
        if self.seen.len() >= self.max_entries {
            if let Some(oldest) = self.seen.iter().min_by_key(|(_, (seq, _))| *seq).map(|(k, _)| *k) {
                self.seen.remove(&oldest);
            }
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.seen.insert(key, (seq, now));
        true
    }
}

/// Redact the home directory out of a path before it goes into an error
/// message an operator might paste into a public bug report. Only the
/// *displayed* string is redacted -- the real path is still used for all
/// file I/O.
fn display_path(path: &Path) -> String {
    if let Ok(home) = std::env::var("HOME") {
        let home_path = Path::new(&home);
        if !home.is_empty() {
            if let Ok(stripped) = path.strip_prefix(home_path) {
                return if stripped.as_os_str().is_empty() {
                    "~".to_string()
                } else {
                    format!("~/{}", stripped.display())
                };
            }
        }
    }
    path.display().to_string()
}

/// Create `path` (if missing) and restrict it to mode 0700. Used for the
/// directory holding a hidden-service or client-auth identity key: a
/// directory left at the ambient umask could be group/world-writable,
/// which would let another local user delete or overwrite the key or
/// hostname file inside it even without being able to read it.
fn ensure_private_dir(path: &Path) -> Result<(), HiddenServiceError> {
    fs::create_dir_all(path)
        .map_err(|e| HiddenServiceError::Io(format!("could not create {}: {e}", display_path(path))))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| HiddenServiceError::Io(format!("could not restrict {} to permissions 0700: {e}", display_path(path))))
}

/// Atomically create `path` containing `data`, mode 0600, no race. Used
/// for a hidden service's identity seed and a client-auth private key.
/// `create_new` makes this fail loudly instead of silently following a
/// symlink or losing a race with another process creating the same path.
fn write_new_secret_file(path: &Path, data: &[u8]) -> Result<(), HiddenServiceError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| HiddenServiceError::Io(format!("could not create {}: {e}", display_path(path))))?;
    if let Err(e) = file.write_all(data) {
        let _ = fs::remove_file(path);
        return Err(HiddenServiceError::Io(format!("could not write {}: {e}", display_path(path))));
    }
    Ok(())
}

/// Atomically overwrite `path` with a freshly rotated key: writes to a
/// same-directory temp file (mode 0600 from creation) and renames it over
/// the target, so a crash mid-rotation leaves either the old key or the
/// new one intact, never a truncated file.
fn persist_intro_key(path: &Path, created_at: f64, seed: &[u8; 32]) -> Result<(), HiddenServiceError> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let suffix = u64::from_be_bytes(osrand::bytes(8).try_into().expect("8 random bytes"));
    let tmp_path = dir.join(format!(".intro_key.{suffix:016x}.tmp"));
    let mut data = Vec::with_capacity(40);
    data.extend_from_slice(&created_at.to_be_bytes());
    data.extend_from_slice(seed);
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| HiddenServiceError::Io(format!("could not create a temp file for {}: {e}", display_path(path))))?;
        if let Err(e) = file.write_all(&data) {
            let _ = fs::remove_file(&tmp_path);
            return Err(HiddenServiceError::Io(format!("could not write a temp file for {}: {e}", display_path(path))));
        }
    }
    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        HiddenServiceError::Io(format!("could not replace {}: {e}", display_path(path)))
    })
}

/// Load a persisted `(seed, created_at)` pair from `path`, creating one on
/// first run. Same on-disk safety properties as [`write_new_secret_file`]
/// -- this is exactly as sensitive a secret as the identity seed it sits
/// beside.
fn load_or_create_intro_key(path: &Path, parent: Option<&Path>) -> Result<([u8; 32], f64), HiddenServiceError> {
    if path.exists() {
        if let Some(p) = parent.filter(|p| !p.as_os_str().is_empty()) {
            ensure_private_dir(p)?;
        }
        let data = fs::read(path).map_err(|e| HiddenServiceError::Io(format!("could not read {}: {e}", display_path(path))))?;
        if data.len() != 40 {
            return Err(HiddenServiceError::Io(format!(
                "{} is not a valid introduction key file; delete it and rerun (a fresh one, and a \
                 fresh descriptor, will be generated)",
                display_path(path)
            )));
        }
        let created_at = f64::from_be_bytes(data[0..8].try_into().unwrap());
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&data[8..40]);
        return Ok((seed, created_at));
    }
    let seed = random_array_32();
    let created_at = now_unix();
    if let Some(p) = parent.filter(|p| !p.as_os_str().is_empty()) {
        ensure_private_dir(p)?;
    }
    let mut data = Vec::with_capacity(40);
    data.extend_from_slice(&created_at.to_be_bytes());
    data.extend_from_slice(&seed);
    write_new_secret_file(path, &data)?;
    Ok((seed, created_at))
}

struct IntroKeyState {
    intro_seed: [u8; 32],
    intro_created_at: f64,
    /// Previous introduction seed, kept only through `grace_period` after
    /// the rotation that superseded it.
    intro_previous_seed: Option<[u8; 32]>,
    /// Absolute deadline (in `clock()` units) past which the previous key
    /// above is discarded -- computed once, from *its own* nominal
    /// `created_at` + `rotation_period` + `grace_period`, not from
    /// whenever rotation happens to next run. This matters because
    /// rotation is detected lazily (on next use, not on a timer): if a
    /// service goes unused for longer than `rotation_period +
    /// grace_period`, the deadline must still land where it nominally
    /// should, not get a fresh grace window just because nobody happened
    /// to notice the rotation on time.
    intro_previous_deadline: Option<f64>,
    /// Set by [`ServiceIdentity::load_or_create`]; `None` means "generated
    /// fresh in memory, not persisted" (e.g. [`ServiceIdentity::generate`]),
    /// so a rotation simply is not written to disk.
    intro_path: Option<PathBuf>,
    /// Remembers which INTRODUCE envelopes have already been opened, so a
    /// captured one cannot be replayed to force repeated circuit builds.
    /// The TTL is the lifetime of the key that could open the envelope --
    /// rotation plus grace -- the exact point past which a replay is
    /// already inert.
    replay: ReplayGuard,
}

impl Drop for IntroKeyState {
    /// Security audit fix (2026-09-26): `intro_seed`/`intro_previous_seed`
    /// are this service's introduction-point X25519 seeds (the latter kept
    /// around for `grace_period` after rotation) -- wipe them on drop
    /// instead of leaving them sitting in freed memory.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.intro_seed.zeroize();
        if let Some(prev) = self.intro_previous_seed.as_mut() {
            prev.zeroize();
        }
    }
}

/// Construction options for [`ServiceIdentity::new`], mirroring the Python
/// original's keyword arguments (Rust has no default-argument syntax, so
/// this plays that role -- use `..Default::default()` for anything not
/// worth overriding).
pub struct ServiceIdentityOptions {
    /// A specific 32-byte X25519 introduction seed to start with; a fresh
    /// random one is generated when `None`.
    pub introduction_seed: Option<[u8; 32]>,
    /// When `introduction_seed` was generated, in `clock()` units;
    /// defaults to "now".
    pub introduction_created_at: Option<f64>,
    /// Seconds an introduction key is used before this service rotates to
    /// a fresh one.
    pub rotation_period: f64,
    /// Seconds a rotated-away key is still accepted for decryption.
    pub grace_period: f64,
    pub introduce_replay_entries: usize,
    /// Injectable time source (an epoch-seconds `f64`), for deterministic
    /// tests.
    pub clock: Option<Arc<dyn Fn() -> f64 + Send + Sync>>,
}

impl Default for ServiceIdentityOptions {
    fn default() -> Self {
        ServiceIdentityOptions {
            introduction_seed: None,
            introduction_created_at: None,
            rotation_period: DEFAULT_INTRODUCTION_KEY_ROTATION,
            grace_period: DEFAULT_INTRODUCTION_KEY_GRACE,
            introduce_replay_entries: DEFAULT_INTRODUCE_REPLAY_ENTRIES,
            clock: None,
        }
    }
}

/// A hidden service's long-term keys: an Ed25519 identity seed, plus a
/// separate, independently generated and periodically rotated X25519
/// "introduction encryption" keypair.
///
/// The Ed25519 key is the service's identity -- it signs descriptors and
/// is what [`encode_address`] turns into the `.allium` address. The
/// introduction-encryption keypair is what [`seal_introduce`]/
/// [`Self::open_introduce`] use to keep an introduction point from reading
/// a client's INTRODUCE1 envelope.
///
/// The introduction key is generated independently of the identity seed
/// (persisted in its own file when loaded via [`Self::load_or_create`], so
/// it is not recoverable from the seed alone) and rotates every
/// `rotation_period`: because the client's ephemeral public key travels in
/// cleartext alongside each sealed INTRODUCE1, deriving the introduction
/// key straight from the permanent identity seed (and never rotating it)
/// would let anyone who recorded historical introduction traffic and later
/// obtained the identity seed retroactively decrypt every past
/// introduction. A rotated-away key is still accepted for `grace_period`
/// afterward (kept in memory only -- not persisted, so a restart does not
/// resurrect it), so a client working from a not-yet-refreshed cached
/// descriptor is not silently dropped mid-rotation.
///
/// Interior mutability: unlike the Python original's plain mutable
/// attributes, this crate's relaying code routinely shares state across
/// OS threads ([`crate::socksproxy`]'s thread-per-connection design), so
/// the rotating/replay state lives behind a [`Mutex`] and every method
/// here takes `&self`.
pub struct ServiceIdentity {
    seed: [u8; 32],
    rotation_period: f64,
    grace_period: f64,
    clock: Arc<dyn Fn() -> f64 + Send + Sync>,
    state: Mutex<IntroKeyState>,
}

impl Drop for ServiceIdentity {
    /// Security audit fix (2026-09-26): `seed` is this hidden service's
    /// long-term Ed25519 identity seed, held for the service's entire
    /// lifetime -- wipe it on drop instead of leaving it sitting in freed
    /// memory. `state`'s introduction seeds are wiped by `IntroKeyState`'s
    /// own `Drop` impl.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.seed.zeroize();
    }
}

impl ServiceIdentity {
    pub fn new(seed: [u8; 32], opts: ServiceIdentityOptions) -> Self {
        let clock = opts.clock.unwrap_or_else(|| Arc::new(now_unix) as Arc<dyn Fn() -> f64 + Send + Sync>);
        let intro_seed = opts.introduction_seed.unwrap_or_else(random_array_32);
        let intro_created_at = opts.introduction_created_at.unwrap_or_else(|| (clock)());
        let replay = ReplayGuard::new(opts.introduce_replay_entries, opts.rotation_period + opts.grace_period, Arc::clone(&clock));
        ServiceIdentity {
            seed,
            rotation_period: opts.rotation_period,
            grace_period: opts.grace_period,
            clock,
            state: Mutex::new(IntroKeyState {
                intro_seed,
                intro_created_at,
                intro_previous_seed: None,
                intro_previous_deadline: None,
                intro_path: None,
                replay,
            }),
        }
    }

    /// Return a fresh, randomly generated identity (not persisted).
    pub fn generate() -> Self {
        Self::new(random_array_32(), ServiceIdentityOptions::default())
    }

    /// Load a persisted 32-byte identity seed from `path` (generating one
    /// on first run, mode 0600, in a directory restricted to 0700 --
    /// mirrors real Tor's own treatment of `HiddenServiceDir`), plus a
    /// separate persisted introduction-encryption key at `path` +
    /// `.intro_key` (which must not be derivable from the identity seed
    /// alone, so it gets its own file rather than living only in memory or
    /// being re-derived from the seed on every load).
    ///
    /// # Errors
    /// [`HiddenServiceError::Io`] on any filesystem failure, or if an
    /// existing key file is not the expected size.
    pub fn load_or_create(path: &Path) -> Result<Self, HiddenServiceError> {
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
        let seed: [u8; 32] = if path.exists() {
            if let Some(p) = parent {
                ensure_private_dir(p)?;
            }
            let data = fs::read(path).map_err(|e| HiddenServiceError::Io(format!("could not read {}: {e}", display_path(path))))?;
            data.try_into()
                .map_err(|_| HiddenServiceError::Io(format!("{} is not a 32-byte key; delete it and rerun", display_path(path))))?
        } else {
            let seed = random_array_32();
            if let Some(p) = parent {
                ensure_private_dir(p)?;
            }
            write_new_secret_file(path, &seed)?;
            seed
        };

        let intro_path = PathBuf::from(format!("{}.intro_key", path.display()));
        let (intro_seed, intro_created_at) = load_or_create_intro_key(&intro_path, parent)?;
        let identity = ServiceIdentity::new(
            seed,
            ServiceIdentityOptions { introduction_seed: Some(intro_seed), introduction_created_at: Some(intro_created_at), ..Default::default() },
        );
        identity.state.lock().unwrap().intro_path = Some(intro_path);
        Ok(identity)
    }

    /// The raw 32-byte Ed25519 seed. Sensitive -- treat like a private key.
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    /// The 32-byte Ed25519 public identity key.
    pub fn identity_public(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.seed).verifying_key().to_bytes()
    }

    /// This service's `x.allium` address.
    pub fn address(&self) -> String {
        encode_address(&self.identity_public()).expect("identity_public is always 32 bytes")
    }

    /// Sign `data` with the Ed25519 identity key.
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.seed).sign(data).to_bytes()
    }

    /// Derive this service's per-introduction-point Ed25519 seed.
    ///
    /// Deterministic (not randomly generated), so both this call and a
    /// later one for the same `relay_identity` -- e.g. across a service
    /// restart -- agree, and a descriptor's [`IntroPoint`] entries stay
    /// valid without needing to persist anything extra. Deriving a
    /// distinct keypair per `relay_identity` keeps the introduction key
    /// unlinkable across different introduction points and reveals
    /// nothing about the real identity to whoever holds it.
    ///
    /// # Errors
    /// [`HiddenServiceError::Other`] if `relay_identity` is not 32 bytes.
    pub fn intro_auth_seed(&self, relay_identity: &[u8]) -> Result<[u8; 32], HiddenServiceError> {
        if relay_identity.len() != ED25519_KEY_LEN {
            return Err(HiddenServiceError::Other(format!(
                "relay_identity must be {ED25519_KEY_LEN} bytes, got {}",
                relay_identity.len()
            )));
        }
        let derived = hs_hkdf(&self.seed, b"allium-hs-intro-auth-v1", relay_identity, 32);
        let mut out = [0u8; 32];
        out.copy_from_slice(&derived);
        Ok(out)
    }

    /// `(auth_seed, auth_public)` for [`Self::intro_auth_seed`]. `auth_public`
    /// is what goes in a descriptor's [`IntroPoint`] in place of the real
    /// identity key; `auth_seed` is what signs `ESTABLISH_INTRO`.
    pub fn intro_auth_keypair(&self, relay_identity: &[u8]) -> Result<([u8; 32], [u8; 32]), HiddenServiceError> {
        let seed = self.intro_auth_seed(relay_identity)?;
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        Ok((seed, public))
    }

    /// Rotate the current key past `rotation_period` and age out an
    /// expired previous one, persisting the new key when this identity was
    /// loaded via [`Self::load_or_create`]. Called before every use of the
    /// introduction key so rotation needs no background timer/task.
    fn maybe_rotate(&self, state: &mut IntroKeyState) -> Result<(), HiddenServiceError> {
        let now = (self.clock)();
        if now - state.intro_created_at > self.rotation_period {
            // Security audit fix (2026-09-26): both reassignments below
            // used to just drop whatever `intro_previous_seed` held --
            // this line overwrites it with the seed that was just
            // superseded (dropping any still-live grace-period seed from
            // an earlier rotation this one raced ahead of), and the grace-
            // expiry branch further down drops it once its deadline
            // passes. Either way this is a live X25519 introduction seed
            // being discarded during ordinary operation, not at this
            // struct's final drop -- `Drop for IntroKeyState` only
            // protects whatever is still resident *then*, so zeroize the
            // outgoing value explicitly at the point it's actually
            // replaced.
            use zeroize::Zeroize;
            if let Some(mut expiring) = state.intro_previous_seed.take() {
                expiring.zeroize();
            }
            state.intro_previous_seed = Some(state.intro_seed);
            state.intro_previous_deadline = Some(state.intro_created_at + self.rotation_period + self.grace_period);
            state.intro_seed = random_array_32();
            state.intro_created_at = now;
            if let Some(path) = state.intro_path.clone() {
                persist_intro_key(&path, state.intro_created_at, &state.intro_seed)?;
            }
        }
        if let Some(deadline) = state.intro_previous_deadline {
            if now > deadline {
                use zeroize::Zeroize;
                if let Some(mut expiring) = state.intro_previous_seed.take() {
                    expiring.zeroize();
                }
                state.intro_previous_deadline = None;
            }
        }
        Ok(())
    }

    /// The 32-byte X25519 public key clients seal an INTRODUCE1 to.
    ///
    /// # Errors
    /// Propagates [`HiddenServiceError::Io`] if a rotation was due and
    /// persisting the new key failed.
    pub fn encryption_public(&self) -> Result<[u8; 32], HiddenServiceError> {
        let mut state = self.state.lock().unwrap();
        self.maybe_rotate(&mut state)?;
        Ok(x25519_public(&state.intro_seed))
    }

    /// Open an INTRODUCE1 envelope sealed with [`seal_introduce`].
    ///
    /// Tries the current introduction key first, then the previous one (if
    /// a rotation happened less than `grace_period` ago). An envelope is
    /// accepted **once** -- a repeat returns
    /// [`HiddenServiceError::IntroduceReplayed`] rather than being opened
    /// again, since a successful decrypt proves only that the envelope was
    /// sealed to this service, never that it is fresh.
    ///
    /// # Errors
    /// [`HiddenServiceError::NonContributoryKey`] if `client_ephemeral_public`
    /// is a low-order point (rejected before any candidate key is tried, so
    /// this never depends on which introduction key happens to be current);
    /// [`HiddenServiceError::SignatureInvalid`] if no candidate key opens
    /// the envelope; [`HiddenServiceError::IntroduceReplayed`] if this
    /// exact envelope has been opened before.
    ///
    /// On success, also returns `intro_secret` -- the raw
    /// `DH(intro_seed, client_ephemeral_public)` shared secret that opened
    /// the envelope. This is a value only the real client (who knows the
    /// ephemeral private key) and the real service (who knows the
    /// introduction seed) can compute; nothing on the wire between here and
    /// the rendezvous point ever exposes it. It is the material the
    /// rendezvous handshake's MAC and session keys are bound to -- see
    /// [`rendezvous_auth_key`] and [`derive_session_keys`].
    pub fn open_introduce(&self, client_ephemeral_public: &[u8], sealed: &[u8]) -> Result<(Vec<u8>, [u8; 32]), HiddenServiceError> {
        if client_ephemeral_public.len() != X25519_KEY_LEN {
            return Err(HiddenServiceError::Other(format!("client_ephemeral_public must be {X25519_KEY_LEN} bytes")));
        }
        let client_pub_arr: [u8; 32] = client_ephemeral_public.try_into().unwrap();
        let client_public = PublicKey::from(client_pub_arr);

        let mut state = self.state.lock().unwrap();
        self.maybe_rotate(&mut state)?;

        let mut candidates = vec![state.intro_seed];
        if let Some(prev) = state.intro_previous_seed {
            candidates.push(prev);
        }
        let mut last_error: Option<HiddenServiceError> = None;
        for seed in candidates {
            let private = StaticSecret::from(seed);
            let public = PublicKey::from(&private).to_bytes();
            let shared = private.diffie_hellman(&client_public);
            // Checked once per candidate key rather than once up front: the
            // point itself is fixed (it is `client_ephemeral_public`, the
            // same input every iteration), so this rejects on the first
            // pass regardless of which introduction key is current -- kept
            // inside the loop only so this stays next to the DH it guards.
            if !shared.was_contributory() {
                return Err(HiddenServiceError::NonContributoryKey(
                    "client ephemeral key is a low-order point; refusing to open the envelope".to_string(),
                ));
            }
            match open_sealed(&shared.to_bytes(), &public, sealed) {
                Ok(plaintext) => {
                    let key = introduce_replay_key(client_ephemeral_public, sealed);
                    if !state.replay.accept(key) {
                        return Err(HiddenServiceError::IntroduceReplayed(
                            "INTRODUCE envelope has already been opened; refusing to build a second \
                             circuit for a replayed introduction"
                                .to_string(),
                        ));
                    }
                    return Ok((plaintext, shared.to_bytes()));
                }
                Err(e) => last_error = Some(e),
            }
        }
        Err(last_error.unwrap_or_else(|| HiddenServiceError::SignatureInvalid("introduce envelope did not authenticate".to_string())))
    }
}

// ---------------------------------------------------------------------------
// Sealing (INTRODUCE1's envelope -- an anonymous "sealed box" to a static key)
// ---------------------------------------------------------------------------

fn seal_with_shared(shared_secret: &[u8], associated_data: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HiddenServiceError> {
    let key = hs_hkdf(shared_secret, b"allium-hs-introduce-v1", b"introduce-key", 32);
    let mut aead = crate::crypto::new_aead("chacha20-poly1305", &key, None).map_err(|e| HiddenServiceError::Other(e.to_string()))?;
    aead.seal(plaintext, associated_data).map_err(|e| HiddenServiceError::Other(e.to_string()))
}

fn open_sealed(shared_secret: &[u8], associated_data: &[u8], sealed: &[u8]) -> Result<Vec<u8>, HiddenServiceError> {
    let key = hs_hkdf(shared_secret, b"allium-hs-introduce-v1", b"introduce-key", 32);
    let aead = crate::crypto::new_aead("chacha20-poly1305", &key, None).map_err(|e| HiddenServiceError::Other(e.to_string()))?;
    aead.open(sealed, associated_data)
        .map_err(|e| HiddenServiceError::SignatureInvalid(format!("introduce envelope did not authenticate: {e}")))
}

/// Seal `plaintext` so only the holder of the matching X25519 private key
/// can read it -- what a client uses to hide the rendezvous details
/// (point, cookie) from the introduction point.
///
/// `client_ephemeral_private` should be fresh per connection attempt; its
/// *public* half must be sent alongside the sealed bytes so the service
/// can redo the same ECDH.
///
/// # Errors
/// [`HiddenServiceError::Other`] if `service_encryption_public` is not 32
/// bytes.
pub fn seal_introduce(
    service_encryption_public: &[u8],
    client_ephemeral_private: &StaticSecret,
    plaintext: &[u8],
) -> Result<Vec<u8>, HiddenServiceError> {
    if service_encryption_public.len() != X25519_KEY_LEN {
        return Err(HiddenServiceError::Other(format!("service_encryption_public must be {X25519_KEY_LEN} bytes")));
    }
    let pub_arr: [u8; 32] = service_encryption_public.try_into().unwrap();
    let shared = client_ephemeral_private.diffie_hellman(&PublicKey::from(pub_arr));
    if !shared.was_contributory() {
        // Only reachable if a service ever published a malformed
        // low-order `encryption_public` in its own descriptor -- the
        // client would only be hurting itself by proceeding, so this fails
        // the same way a bad key length does rather than silently sealing
        // to a predictable secret.
        return Err(HiddenServiceError::NonContributoryKey(
            "service encryption key is a low-order point; refusing to seal an introduction to it".to_string(),
        ));
    }
    seal_with_shared(&shared.to_bytes(), service_encryption_public, plaintext)
}

/// Also returns the raw shared secret (`intro_secret` -- see
/// [`ServiceIdentity::open_introduce`]'s doc), which the client needs
/// afterward to verify the rendezvous handshake MAC and to derive the
/// session keys. [`seal_introduce`] stays as the simple form most callers
/// (and every existing test) want.
///
/// # Errors
/// Same as [`seal_introduce`].
pub fn seal_introduce_with_secret(
    service_encryption_public: &[u8],
    client_ephemeral_private: &StaticSecret,
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), HiddenServiceError> {
    if service_encryption_public.len() != X25519_KEY_LEN {
        return Err(HiddenServiceError::Other(format!("service_encryption_public must be {X25519_KEY_LEN} bytes")));
    }
    let pub_arr: [u8; 32] = service_encryption_public.try_into().unwrap();
    let shared = client_ephemeral_private.diffie_hellman(&PublicKey::from(pub_arr));
    if !shared.was_contributory() {
        return Err(HiddenServiceError::NonContributoryKey(
            "service encryption key is a low-order point; refusing to seal an introduction to it".to_string(),
        ));
    }
    let sealed = seal_with_shared(&shared.to_bytes(), service_encryption_public, plaintext)?;
    Ok((sealed, shared.to_bytes()))
}

/// Inverse of [`seal_introduce`], given the raw X25519 private key
/// directly (mainly for tests; [`ServiceIdentity::open_introduce`] is the
/// normal entry point, since it also handles key rotation and replay
/// detection).
///
/// # Errors
/// [`HiddenServiceError::Other`] if `client_ephemeral_public` is not 32
/// bytes; [`HiddenServiceError::NonContributoryKey`] if it is a low-order
/// point; [`HiddenServiceError::SignatureInvalid`] if the envelope does not
/// authenticate.
pub fn open_introduce(
    service_encryption_private: &StaticSecret,
    client_ephemeral_public: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, HiddenServiceError> {
    if client_ephemeral_public.len() != X25519_KEY_LEN {
        return Err(HiddenServiceError::Other(format!("client_ephemeral_public must be {X25519_KEY_LEN} bytes")));
    }
    let pub_arr: [u8; 32] = client_ephemeral_public.try_into().unwrap();
    let shared = service_encryption_private.diffie_hellman(&PublicKey::from(pub_arr));
    if !shared.was_contributory() {
        return Err(HiddenServiceError::NonContributoryKey(
            "client ephemeral key is a low-order point; refusing to open the envelope".to_string(),
        ));
    }
    let service_encryption_public = PublicKey::from(service_encryption_private).to_bytes();
    open_sealed(&shared.to_bytes(), &service_encryption_public, sealed)
}

// ---------------------------------------------------------------------------
// Post-rendezvous session crypto
// ---------------------------------------------------------------------------

/// Length of the rendezvous handshake message's MAC-authenticated form:
/// `service_ephemeral_public(32) || mac(32)`. See
/// [`rendezvous_auth_key`]/[`rendezvous_mac`].
pub const RENDEZVOUS_HANDSHAKE_LEN: usize = X25519_KEY_LEN + 32;

/// Domain-separation strings for rendezvous authentication.
/// Kept as named constants (rather than inlined at each call site) so the
/// service and client sides are visibly using the exact same bytes.
const RENDEZVOUS_AUTH_SALT: &[u8] = b"allium-hs-rend-auth-v1";
const RENDEZVOUS_MAC_DOMAIN: &[u8] = b"allium-hs-rend-v1";

/// Derive the key that authenticates a rendezvous handshake, from
/// `intro_secret` (`DH(intro_seed, client_ephemeral_public)` -- see
/// [`ServiceIdentity::open_introduce`]/[`seal_introduce_with_secret`]).
/// Only the real client and the real service can compute this: the
/// rendezvous point, which is the party this whole mechanism defends
/// against, never sees `intro_secret` -- the
/// INTRODUCE envelope it forwards is sealed to the service's encryption
/// key and opaque to it.
pub fn rendezvous_auth_key(intro_secret: &[u8]) -> [u8; 32] {
    let raw = hs_hkdf(intro_secret, RENDEZVOUS_AUTH_SALT, b"auth-key", 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    out
}

/// Compute the rendezvous handshake MAC over every value that must not be
/// substitutable: both ephemeral public keys, the service's long-term
/// introduction-encryption key (so a MAC computed for one service can't be
/// replayed against another it also introduces to), the rendezvous cookie,
/// and the rendezvous point's identity (so the MAC is tied to *this*
/// rendezvous, not reusable against a different one the same pair happens
/// to share a cookie collision with -- cookies are random but this costs
/// nothing and removes the assumption).
///
/// # Panics
/// Never in practice: `auth_key` is always the 32-byte output of
/// [`rendezvous_auth_key`], which HMAC-SHA256 accepts as a key of any
/// length.
pub fn rendezvous_mac(
    auth_key: &[u8; 32],
    client_ephemeral_public: &[u8],
    service_ephemeral_public: &[u8],
    encryption_public: &[u8],
    cookie: &[u8],
    rp_identity: &[u8],
) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(auth_key).expect("HMAC-SHA256 accepts a 32-byte key");
    mac.update(RENDEZVOUS_MAC_DOMAIN);
    mac.update(client_ephemeral_public);
    mac.update(service_ephemeral_public);
    mac.update(encryption_public);
    mac.update(cookie);
    mac.update(rp_identity);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// Constant-time check of a received rendezvous MAC against the expected
/// one for the same inputs [`rendezvous_mac`] takes.
///
/// # Errors
/// [`HiddenServiceError::RendezvousAuthFailed`] if the MAC does not match.
#[allow(clippy::too_many_arguments)]
pub fn verify_rendezvous_mac(
    auth_key: &[u8; 32],
    client_ephemeral_public: &[u8],
    service_ephemeral_public: &[u8],
    encryption_public: &[u8],
    cookie: &[u8],
    rp_identity: &[u8],
    received_mac: &[u8],
) -> Result<(), HiddenServiceError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(auth_key).expect("HMAC-SHA256 accepts a 32-byte key");
    mac.update(RENDEZVOUS_MAC_DOMAIN);
    mac.update(client_ephemeral_public);
    mac.update(service_ephemeral_public);
    mac.update(encryption_public);
    mac.update(cookie);
    mac.update(rp_identity);
    mac.verify_slice(received_mac).map_err(|_| {
        HiddenServiceError::RendezvousAuthFailed(
            "rendezvous handshake MAC did not verify -- the rendezvous point may be attempting to \
             impersonate the service (see ALLIUM-H6); refusing to establish a session"
                .to_string(),
        )
    })
}

/// Encode the service's rendezvous handshake message: its ephemeral public
/// key plus the MAC that binds it to the introduction secret.
pub fn encode_rendezvous_handshake(service_ephemeral_public: &[u8; 32], mac: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(RENDEZVOUS_HANDSHAKE_LEN);
    out.extend_from_slice(service_ephemeral_public);
    out.extend_from_slice(mac);
    out
}

/// Inverse of [`encode_rendezvous_handshake`]. Returns
/// `(service_ephemeral_public, mac)`.
///
/// # Errors
/// [`HiddenServiceError::Other`] if `data` is not exactly
/// [`RENDEZVOUS_HANDSHAKE_LEN`] bytes -- deliberately exact rather than
/// "at least", so a service still running the unauthenticated v1 handshake
/// (a bare 32-byte key) is rejected outright by a v2-only client instead of
/// being misread as a truncated v2 message.
pub fn decode_rendezvous_handshake(data: &[u8]) -> Result<([u8; 32], [u8; 32]), HiddenServiceError> {
    if data.len() != RENDEZVOUS_HANDSHAKE_LEN {
        return Err(HiddenServiceError::Other(format!(
            "rendezvous handshake message is {} bytes, expected exactly {RENDEZVOUS_HANDSHAKE_LEN} \
             (service_ephemeral_public || mac) -- a peer using the old unauthenticated v1 handshake \
             cannot be used safely and is refused rather than guessed at",
            data.len()
        )));
    }
    let mut service_ephemeral_public = [0u8; 32];
    service_ephemeral_public.copy_from_slice(&data[..32]);
    let mut mac = [0u8; 32];
    mac.copy_from_slice(&data[32..]);
    Ok((service_ephemeral_public, mac))
}

/// Derive the two directional AEAD keys for a rendezvous session, bound to
/// both the rendezvous ECDH output *and* `intro_secret`: even if a bug
/// elsewhere let an attacker produce a MAC-passing `rendezvous_shared`
/// some other way, they would still need
/// `intro_secret` -- which only the real client and service ever compute --
/// to land on the same session keys. Both sides compute the same pair from
/// the same inputs, one key per direction so neither side ever encrypts and
/// decrypts under the same key. Returns
/// `(key_client_to_service, key_service_to_client)`.
/// Domain-separation label for the session keys. `v3` is the sequenced,
/// direction-bound frame format of [`HsSession`]; `v2` was the unsequenced
/// one. The label change means a `v2` peer and a `v3` peer derive different
/// keys, so a mismatched pair fails cleanly at the first data frame instead
/// of one side misreading the other's framing.
const HS_SESSION_KEY_LABEL: &[u8] = b"allium-hs-session-v3";

pub fn derive_session_keys(rendezvous_shared: &[u8], intro_secret: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut ikm = Vec::with_capacity(rendezvous_shared.len() + intro_secret.len());
    ikm.extend_from_slice(rendezvous_shared);
    ikm.extend_from_slice(intro_secret);
    let c2s = hs_hkdf(&ikm, HS_SESSION_KEY_LABEL, b"client-to-service", 32);
    let s2c = hs_hkdf(&ikm, HS_SESSION_KEY_LABEL, b"service-to-client", 32);
    let mut key_c2s = [0u8; 32];
    key_c2s.copy_from_slice(&c2s);
    let mut key_s2c = [0u8; 32];
    key_s2c.copy_from_slice(&s2c);
    (key_c2s, key_s2c)
}

/// AEAD-sealed duplex session between a client and a service, layered on
/// top of the (already onion-encrypted, but relay-visible) rendezvous
/// tunnel. Every relay along the path, including the rendezvous point that
/// physically forwards these bytes, sees only ciphertext.
///
/// `cookie` (the rendezvous cookie) salts each direction's
/// [`crate::crypto::NonceCounter`] so client and service, who independently
/// start counting from the same key, never collide.
pub struct HsSession {
    send: Mutex<HsSendState>,
    recv: Mutex<HsRecvState>,
    /// Direction byte bound into every frame's associated data: 1 =
    /// client-to-service, 2 = service-to-client.
    send_dir: u8,
    recv_dir: u8,
}

struct HsSendState {
    aead: crate::crypto::SaltAead,
    next_seq: u64,
    closed: bool,
}

struct HsRecvState {
    aead: crate::crypto::SaltAead,
    expected_seq: u64,
    closed: bool,
}

/// What one opened session frame carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HsFrame {
    /// Application bytes.
    Data(Vec<u8>),
    /// The peer's authenticated end-of-stream. Nothing valid follows it.
    Close,
}

const HS_FRAME_DATA: u8 = 0;
const HS_FRAME_CLOSE: u8 = 1;
const HS_DIR_CLIENT_TO_SERVICE: u8 = 1;
const HS_DIR_SERVICE_TO_CLIENT: u8 = 2;
/// kind (1) + sequence number (8), sent in the clear ahead of the sealed body.
const HS_FRAME_HEADER_LEN: usize = 9;

impl HsSession {
    /// # Errors
    /// [`HiddenServiceError::Other`] if either AEAD fails to construct
    /// (wrong key length).
    pub fn new(key_c2s: &[u8], key_s2c: &[u8], cookie: &[u8], is_service: bool) -> Result<Self, HiddenServiceError> {
        let (send_key, recv_key) = if is_service { (key_s2c, key_c2s) } else { (key_c2s, key_s2c) };
        let mut send_salt = cookie.to_vec();
        send_salt.extend_from_slice(if is_service { b"s2c" } else { b"c2s" });
        let nonce_source = crate::crypto::NonceCounter::from_session_bytes(&send_salt);
        let send =
            crate::crypto::new_aead("chacha20-poly1305", send_key, Some(nonce_source)).map_err(|e| HiddenServiceError::Other(e.to_string()))?;
        let recv = crate::crypto::new_aead("chacha20-poly1305", recv_key, None).map_err(|e| HiddenServiceError::Other(e.to_string()))?;
        let (send_dir, recv_dir) =
            if is_service { (HS_DIR_SERVICE_TO_CLIENT, HS_DIR_CLIENT_TO_SERVICE) } else { (HS_DIR_CLIENT_TO_SERVICE, HS_DIR_SERVICE_TO_CLIENT) };
        Ok(HsSession {
            send: Mutex::new(HsSendState { aead: send, next_seq: 0, closed: false }),
            recv: Mutex::new(HsRecvState { aead: recv, expected_seq: 0, closed: false }),
            send_dir,
            recv_dir,
        })
    }

    /// Associated data bound into a frame: direction, kind and sequence
    /// number, so a frame cannot be replayed, reordered, reflected back to
    /// its sender, or relabelled without failing authentication.
    fn frame_aad(dir: u8, kind: u8, seq: u64) -> [u8; 10] {
        let mut aad = [0u8; 10];
        aad[0] = dir;
        aad[1] = kind;
        aad[2..].copy_from_slice(&seq.to_be_bytes());
        aad
    }

    fn seal_frame(&self, kind: u8, plaintext: &[u8]) -> Result<Vec<u8>, HiddenServiceError> {
        let mut send = self.send.lock().unwrap();
        if send.closed {
            return Err(HiddenServiceError::SessionClosed("session already closed by this side; nothing more can be sent".to_string()));
        }
        let seq = send.next_seq;
        let next = seq.checked_add(1).ok_or_else(|| HiddenServiceError::Other("session sequence space exhausted".to_string()))?;
        let aad = Self::frame_aad(self.send_dir, kind, seq);
        let body = send.aead.seal(plaintext, &aad).map_err(|e| HiddenServiceError::Other(e.to_string()))?;
        // Only advance once the frame exists, so a failed seal does not burn a number.
        send.next_seq = next;
        if kind == HS_FRAME_CLOSE {
            send.closed = true;
        }
        let mut out = Vec::with_capacity(HS_FRAME_HEADER_LEN + body.len());
        out.push(kind);
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Encrypt one message for the other side. Frames are numbered in the
    /// order they are sealed, so send them in that order.
    ///
    /// # Errors
    /// [`HiddenServiceError::SessionClosed`] after [`Self::seal_close`].
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, HiddenServiceError> {
        self.seal_frame(HS_FRAME_DATA, plaintext)
    }

    /// Seal this side's authenticated end-of-stream. After it, [`Self::seal`]
    /// is refused, and the peer rejects anything further.
    pub fn seal_close(&self) -> Result<Vec<u8>, HiddenServiceError> {
        self.seal_frame(HS_FRAME_CLOSE, &[])
    }

    /// Whether the peer's authenticated close has been received. A tunnel
    /// that ended while this is still `false` was cut off, not finished.
    pub fn peer_closed(&self) -> bool {
        self.recv.lock().unwrap().closed
    }

    /// Open one frame from the other side, enforcing strict sequencing.
    ///
    /// The frame is authenticated *first* (so a forged frame cannot steer the
    /// session by claiming a sequence number), then its number is checked:
    /// it must be exactly the next expected one. The counter only advances
    /// on success, so a rejected frame changes nothing.
    ///
    /// # Errors
    /// - [`HiddenServiceError::Other`]: too short, unknown kind, or failed
    ///   authentication (tampered, wrong direction, wrong key). Dropped.
    /// - [`HiddenServiceError::SessionReplay`]: authentic but already seen.
    ///   Dropped.
    /// - [`HiddenServiceError::SessionGap`]: authentic but ahead of
    ///   expected (a frame was lost or reordered). Fatal.
    /// - [`HiddenServiceError::SessionClosed`]: arrived after the peer's
    ///   close. Fatal.
    pub fn open_frame(&self, sealed: &[u8]) -> Result<HsFrame, HiddenServiceError> {
        if sealed.len() < HS_FRAME_HEADER_LEN + crate::crypto::SEAL_OVERHEAD {
            return Err(HiddenServiceError::Other(format!("session frame is {} bytes, too short", sealed.len())));
        }
        let kind = sealed[0];
        if kind != HS_FRAME_DATA && kind != HS_FRAME_CLOSE {
            return Err(HiddenServiceError::Other(format!("unknown session frame kind {kind}")));
        }
        let seq = u64::from_be_bytes(sealed[1..HS_FRAME_HEADER_LEN].try_into().expect("8 bytes"));
        let mut recv = self.recv.lock().unwrap();
        let aad = Self::frame_aad(self.recv_dir, kind, seq);
        let plaintext =
            recv.aead.open(&sealed[HS_FRAME_HEADER_LEN..], &aad).map_err(|e| HiddenServiceError::Other(format!("session frame failed authentication: {e}")))?;
        // Authentic from here on: the claimed sequence number is real.
        if recv.closed {
            return Err(HiddenServiceError::SessionClosed("frame arrived after the peer closed the session".to_string()));
        }
        if seq < recv.expected_seq {
            return Err(HiddenServiceError::SessionReplay(format!("frame {seq} was already received (expected {})", recv.expected_seq)));
        }
        if seq > recv.expected_seq {
            return Err(HiddenServiceError::SessionGap(format!(
                "frame {seq} arrived but {} was expected: a frame was dropped or reordered",
                recv.expected_seq
            )));
        }
        if kind == HS_FRAME_CLOSE {
            if !plaintext.is_empty() {
                return Err(HiddenServiceError::Other("close frame carried data".to_string()));
            }
            recv.expected_seq += 1;
            recv.closed = true;
            return Ok(HsFrame::Close);
        }
        recv.expected_seq += 1;
        Ok(HsFrame::Data(plaintext))
    }

    /// Open a data frame from the other side. A close frame is reported as
    /// [`HiddenServiceError::SessionClosed`] (the peer finished cleanly);
    /// use [`Self::open_frame`] to tell that apart from a failure.
    ///
    /// # Errors
    /// See [`Self::open_frame`].
    pub fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, HiddenServiceError> {
        match self.open_frame(sealed)? {
            HsFrame::Data(d) => Ok(d),
            HsFrame::Close => Err(HiddenServiceError::SessionClosed("the peer closed the session".to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Descriptor types
// ---------------------------------------------------------------------------

/// A short, non-reversible tag for a client-auth public key. Lets a client
/// pick out its own [`ClientAuthEntry`] in a descriptor directly, without
/// trying every wrapped key in turn. This is a deliberate, documented
/// limit on privacy, not a bug: what client authorization hides is the
/// *introduction points* from anyone lacking a matching private key, not
/// the list of hints itself.
fn client_id_hint(client_public: &[u8]) -> [u8; CLIENT_ID_HINT_LEN] {
    use blake2::Blake2b;
    use digest::consts::U16;
    let mut hasher = Blake2b::<U16>::new();
    hasher.update(b"allium-hs-clientauth-hint-v1");
    hasher.update(client_public);
    hasher.finalize().into()
}

/// Serialize a list of intro points identically whether they end up in a
/// signed cleartext descriptor or as the plaintext that gets
/// AEAD-encrypted for client authorization. Kept as an independent copy of
/// [`crate::dirwire`]'s very similarly-named wire helper -- that one also
/// enforces the untrusted-input size caps that are the wire-framing
/// module's job, not this one's.
fn encode_intro_points_plaintext(intro_points: &[IntroPoint]) -> Vec<u8> {
    let mut out = (intro_points.len() as u16).to_be_bytes().to_vec();
    for ip in intro_points {
        let host = ip.host.as_bytes();
        out.extend_from_slice(&ip.relay_identity);
        out.extend_from_slice(&(host.len() as u16).to_be_bytes());
        out.extend_from_slice(host);
        out.extend_from_slice(&ip.port.to_be_bytes());
        out.extend_from_slice(&ip.auth_public);
    }
    out
}

/// Inverse of [`encode_intro_points_plaintext`], for a client-auth
/// descriptor's decrypted plaintext (already AEAD-authenticated by the
/// caller, so this only needs to guard against a short/malformed buffer).
fn decode_intro_points_plaintext(data: &[u8]) -> Result<Vec<IntroPoint>, HiddenServiceError> {
    if data.len() < 2 {
        return Err(HiddenServiceError::Other("intro point list truncated before its count".to_string()));
    }
    let count = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut offset = 2;
    let mut points = Vec::with_capacity(count);
    for _ in 0..count {
        if data.len() < offset + ED25519_KEY_LEN + 2 {
            return Err(HiddenServiceError::Other("intro point list truncated".to_string()));
        }
        let relay_identity = data[offset..offset + ED25519_KEY_LEN].to_vec();
        offset += ED25519_KEY_LEN;
        let host_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if data.len() < offset + host_len + 2 {
            return Err(HiddenServiceError::Other("intro point list truncated inside a host".to_string()));
        }
        let host = std::str::from_utf8(&data[offset..offset + host_len])
            .map_err(|_| HiddenServiceError::Other("intro point host is not valid UTF-8".to_string()))?
            .to_string();
        offset += host_len;
        let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        if data.len() < offset + ED25519_KEY_LEN {
            return Err(HiddenServiceError::Other("intro point list truncated before its auth key".to_string()));
        }
        let auth_public = data[offset..offset + ED25519_KEY_LEN].to_vec();
        offset += ED25519_KEY_LEN;
        points.push(IntroPoint { relay_identity, host, port, auth_public });
    }
    Ok(points)
}

/// One relay a service has registered with as an introduction point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntroPoint {
    /// The intro relay's own Ed25519 identity (32 bytes).
    pub relay_identity: Vec<u8>,
    pub host: String,
    pub port: u16,
    /// The per-intro-point Ed25519 public key this service registered
    /// with *this* intro point instead of its real `identity_public`.
    pub auth_public: Vec<u8>,
}

/// One authorized client's wrapped copy of a descriptor's decryption key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAuthEntry {
    /// A short opaque tag derived from the client's own X25519 public key.
    pub client_id_hint: Vec<u8>,
    /// The descriptor's random AEAD key, sealed for this client.
    pub wrapped_key: Vec<u8>,
}

/// A service's self-signed record: who it is and how to reach it.
///
/// Structurally the same idea as [`crate::directory::RelayDescriptor`] --
/// self-signed, keyed by the service's own address rather than a relay
/// identity, and carrying introduction points instead of a single
/// `host`/`port`.
#[derive(Debug, Clone, PartialEq)]
pub struct HiddenServiceDescriptor {
    pub identity_public: Vec<u8>,
    pub encryption_public: Vec<u8>,
    /// Empty (and meaningless) when `client_auth` is non-empty.
    pub intro_points: Vec<IntroPoint>,
    pub not_before: f64,
    pub not_after: f64,
    pub signature: Vec<u8>,
    /// Set instead of `intro_points` when this service restricts who may
    /// see them ("client authorization").
    pub encrypted_intro_points: Vec<u8>,
    /// The service's one-off X25519 public key used to wrap the
    /// descriptor key for each authorized client. Empty when `client_auth`
    /// is empty.
    pub auth_ephemeral_public: Vec<u8>,
    pub client_auth: Vec<ClientAuthEntry>,
    /// Advertises that this service speaks the MAC-authenticated
    /// rendezvous handshake (the unauthenticated version lets the
    /// rendezvous point alone impersonate the service). Part of the
    /// signed payload so a malicious or compromised directory
    /// authority cannot strip it to downgrade an upgraded client back to
    /// the vulnerable v1 handshake -- see [`Self::signing_payload`] and
    /// [`crate::bin`]'s `hsclient`/`hsserver` for the client/service sides.
    pub hs_handshake_v2: bool,
}

impl HiddenServiceDescriptor {
    /// A descriptor with every optional field at its Python-default
    /// (empty signature, no client-auth restriction).
    pub fn new(identity_public: Vec<u8>, encryption_public: Vec<u8>, intro_points: Vec<IntroPoint>, not_before: f64, not_after: f64) -> Self {
        HiddenServiceDescriptor {
            identity_public,
            encryption_public,
            intro_points,
            not_before,
            not_after,
            signature: Vec::new(),
            encrypted_intro_points: Vec::new(),
            auth_ephemeral_public: Vec::new(),
            client_auth: Vec::new(),
            hs_handshake_v2: true,
        }
    }

    /// The exact bytes the signature covers (everything but the
    /// signature). Branches on `client_auth`: with no restriction this is
    /// byte-for-byte the payload from before client authorization existed.
    pub fn signing_payload(&self) -> Vec<u8> {
        // `hs_handshake_v2` is appended as a single trailing byte on *both*
        // branches, after everything the pre-H6-fix payload covered, so a
        // v1 verifier that has not been updated computes a different digest
        // and simply rejects the descriptor rather than silently ignoring
        // the flag -- the flag is authenticated, not advisory, which is
        // what keeps a malicious authority from stripping it to force a
        // downgrade (see the field's doc on `HiddenServiceDescriptor`).
        let v2_byte: u8 = if self.hs_handshake_v2 { 1 } else { 0 };
        if !self.client_auth.is_empty() {
            let mut out = Vec::new();
            out.extend_from_slice(b"allium-hs-descriptor-v1-auth");
            out.extend_from_slice(&self.not_before.to_be_bytes());
            out.extend_from_slice(&self.not_after.to_be_bytes());
            out.extend_from_slice(&self.identity_public);
            out.extend_from_slice(&self.encryption_public);
            out.extend_from_slice(&(self.encrypted_intro_points.len() as u16).to_be_bytes());
            out.extend_from_slice(&self.encrypted_intro_points);
            out.extend_from_slice(&self.auth_ephemeral_public);
            out.extend_from_slice(&(self.client_auth.len() as u16).to_be_bytes());
            for entry in &self.client_auth {
                out.extend_from_slice(&entry.client_id_hint);
                out.extend_from_slice(&(entry.wrapped_key.len() as u16).to_be_bytes());
                out.extend_from_slice(&entry.wrapped_key);
            }
            out.push(v2_byte);
            return out;
        }
        let mut out = Vec::new();
        out.extend_from_slice(b"allium-hs-descriptor-v1");
        out.extend_from_slice(&self.not_before.to_be_bytes());
        out.extend_from_slice(&self.not_after.to_be_bytes());
        out.extend_from_slice(&self.identity_public);
        out.extend_from_slice(&self.encryption_public);
        out.extend_from_slice(&(self.intro_points.len() as u16).to_be_bytes());
        for ip in &self.intro_points {
            let host = ip.host.as_bytes();
            out.extend_from_slice(&ip.relay_identity);
            out.extend_from_slice(&(host.len() as u16).to_be_bytes());
            out.extend_from_slice(host);
            out.extend_from_slice(&ip.port.to_be_bytes());
            out.extend_from_slice(&ip.auth_public);
        }
        out.push(v2_byte);
        out
    }

    /// This descriptor's `x.allium` address.
    ///
    /// # Panics
    /// If `identity_public` is not 32 bytes -- callers that built a
    /// descriptor with a malformed key should check
    /// [`Self::verify`]/length first, exactly as Python's `.address`
    /// property lets `AddressError` propagate.
    pub fn address(&self) -> String {
        encode_address(&self.identity_public).expect("identity_public must be 32 bytes to form an address")
    }

    pub fn is_valid_at(&self, now: f64) -> bool {
        self.not_before <= now && now <= self.not_after
    }

    /// Check the self-signature.
    ///
    /// # Errors
    /// [`HiddenServiceError::SignatureInvalid`] if the signature does not
    /// verify, or the keys are the wrong size.
    pub fn verify(&self) -> Result<(), HiddenServiceError> {
        if self.identity_public.len() != ED25519_KEY_LEN {
            return Err(HiddenServiceError::SignatureInvalid(format!("identity key must be {ED25519_KEY_LEN} bytes")));
        }
        if self.encryption_public.len() != X25519_KEY_LEN {
            return Err(HiddenServiceError::SignatureInvalid(format!("encryption key must be {X25519_KEY_LEN} bytes")));
        }
        if self.signature.len() != ED25519_SIG_LEN {
            return Err(HiddenServiceError::SignatureInvalid("hidden-service descriptor signature did not verify".to_string()));
        }
        let identity: [u8; 32] = self.identity_public.clone().try_into().unwrap();
        let verifying_key =
            VerifyingKey::from_bytes(&identity).map_err(|e| HiddenServiceError::SignatureInvalid(format!("malformed identity key: {e}")))?;
        let sig_bytes: [u8; 64] = self.signature.clone().try_into().unwrap();
        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(&self.signing_payload(), &signature)
            .map_err(|_| HiddenServiceError::SignatureInvalid("hidden-service descriptor signature did not verify".to_string()))
    }

    /// Mint and sign an unrestricted (no client-auth) descriptor from a
    /// service's Ed25519 identity private key and its current X25519
    /// introduction-encryption public key.
    ///
    /// Takes the raw key material directly rather than a
    /// [`ServiceIdentity`] (Python's `create` takes the identity object
    /// itself): `encryption_public` already has to come from
    /// [`ServiceIdentity::encryption_public`] separately (it can fail if a
    /// due key rotation's persist fails), so a caller integrating with a
    /// live `ServiceIdentity` calls that first and passes the result in
    /// here, same as it would supply `identity_private` -- avoiding a
    /// dependency from this free-standing constructor back onto the
    /// higher-level type.
    pub fn create(identity_private: &[u8; 32], encryption_public: Vec<u8>, intro_points: Vec<IntroPoint>, lifetime: f64, now: Option<f64>) -> HiddenServiceDescriptor {
        let now = now.unwrap_or_else(now_unix);
        let key = SigningKey::from_bytes(identity_private);
        let identity_public = key.verifying_key().to_bytes().to_vec();
        let mut unsigned = HiddenServiceDescriptor::new(identity_public, encryption_public, intro_points, now, now + lifetime);
        let signature = key.sign(&unsigned.signing_payload());
        unsigned.signature = signature.to_bytes().to_vec();
        unsigned
    }

    /// Mint and sign a descriptor that restricts its introduction points
    /// to `client_auth_public_keys` ("client authorization"): `intro_points`
    /// is never written to the descriptor in the clear. It is
    /// AEAD-encrypted once under a fresh random key, and that key is
    /// individually wrapped (X25519 ECDH + HKDF) for each authorized
    /// client, so a directory authority storing the result never sees the
    /// plaintext.
    ///
    /// # Errors
    /// [`HiddenServiceError::Other`] if a supplied client public key is
    /// not 32 bytes, or an AEAD operation fails to construct.
    pub fn create_with_client_auth(
        identity_private: &[u8; 32],
        encryption_public: Vec<u8>,
        intro_points: Vec<IntroPoint>,
        lifetime: f64,
        now: Option<f64>,
        client_auth_public_keys: &[[u8; 32]],
    ) -> Result<HiddenServiceDescriptor, HiddenServiceError> {
        let now = now.unwrap_or_else(now_unix);
        let key = SigningKey::from_bytes(identity_private);
        let identity_public = key.verifying_key().to_bytes().to_vec();

        let desc_key = crate::crypto::generate_key();
        let mut aead = crate::crypto::new_aead("chacha20-poly1305", &desc_key, None).map_err(|e| HiddenServiceError::Other(e.to_string()))?;
        let plaintext = encode_intro_points_plaintext(&intro_points);
        let encrypted_intro_points = aead.seal(&plaintext, &identity_public).map_err(|e| HiddenServiceError::Other(e.to_string()))?;

        let ephemeral_private = StaticSecret::from(random_array_32());
        let auth_ephemeral_public = PublicKey::from(&ephemeral_private).to_bytes().to_vec();

        let mut entries = Vec::with_capacity(client_auth_public_keys.len());
        for client_public in client_auth_public_keys {
            let shared = ephemeral_private.diffie_hellman(&PublicKey::from(*client_public));
            let wrap_key = hs_hkdf(&shared.to_bytes(), b"allium-hs-clientauth-v1", b"wrap-key", 32);
            let mut wrap_aead = crate::crypto::new_aead("chacha20-poly1305", &wrap_key, None).map_err(|e| HiddenServiceError::Other(e.to_string()))?;
            let wrapped_key = wrap_aead.seal(&desc_key, &auth_ephemeral_public).map_err(|e| HiddenServiceError::Other(e.to_string()))?;
            entries.push(ClientAuthEntry { client_id_hint: client_id_hint(client_public).to_vec(), wrapped_key });
        }

        let mut unsigned = HiddenServiceDescriptor {
            identity_public,
            encryption_public,
            intro_points: Vec::new(),
            not_before: now,
            not_after: now + lifetime,
            signature: Vec::new(),
            encrypted_intro_points,
            auth_ephemeral_public,
            client_auth: entries,
            hs_handshake_v2: true,
        };
        let signature = key.sign(&unsigned.signing_payload());
        unsigned.signature = signature.to_bytes().to_vec();
        Ok(unsigned)
    }

    /// This descriptor's introduction points, decrypting them first if the
    /// service restricts who may see them.
    ///
    /// Safe to call unconditionally in place of reading `intro_points`
    /// directly: when this descriptor has no client-auth restriction
    /// (`client_auth` empty), `client_auth_private_key` is ignored -- not
    /// even required -- and `intro_points` is returned as-is.
    ///
    /// # Errors
    /// [`HiddenServiceError::ClientNotAuthorized`] if this descriptor
    /// restricts its introduction points to specific clients, and either
    /// no key was given, the given key is not one of them, or the
    /// descriptor's encrypted payload did not decrypt cleanly.
    pub fn intro_points_for(&self, client_auth_private_key: Option<&[u8; 32]>) -> Result<Vec<IntroPoint>, HiddenServiceError> {
        if self.client_auth.is_empty() {
            return Ok(self.intro_points.clone());
        }
        let Some(private_key) = client_auth_private_key else {
            return Err(HiddenServiceError::ClientNotAuthorized(format!(
                "{} only shares its introduction points with authorized clients -- pass a client-auth private key",
                self.address()
            )));
        };
        let priv_secret = StaticSecret::from(*private_key);
        let pub_bytes = PublicKey::from(&priv_secret).to_bytes();
        let hint = client_id_hint(&pub_bytes);
        let entry = self
            .client_auth
            .iter()
            .find(|e| e.client_id_hint.len() == hint.len() && bool::from(e.client_id_hint.as_slice().ct_eq(&hint[..])));
        let Some(entry) = entry else {
            return Err(HiddenServiceError::ClientNotAuthorized(format!("this client is not authorized for {}", self.address())));
        };
        let auth_eph: [u8; 32] = self
            .auth_ephemeral_public
            .clone()
            .try_into()
            .map_err(|_| HiddenServiceError::ClientNotAuthorized(format!("this client is not authorized for {}", self.address())))?;
        let shared = priv_secret.diffie_hellman(&PublicKey::from(auth_eph));
        let wrap_key = hs_hkdf(&shared.to_bytes(), b"allium-hs-clientauth-v1", b"wrap-key", 32);
        let wrap_aead = crate::crypto::new_aead("chacha20-poly1305", &wrap_key, None).map_err(|e| HiddenServiceError::Other(e.to_string()))?;
        let desc_key = wrap_aead
            .open(&entry.wrapped_key, &self.auth_ephemeral_public)
            .map_err(|_| HiddenServiceError::ClientNotAuthorized(format!("this client is not authorized for {}", self.address())))?;
        let aead = crate::crypto::new_aead("chacha20-poly1305", &desc_key, None).map_err(|e| HiddenServiceError::Other(e.to_string()))?;
        let serialized = aead.open(&self.encrypted_intro_points, &self.identity_public).map_err(|_| {
            HiddenServiceError::ClientNotAuthorized(format!("{}'s descriptor did not decrypt cleanly -- corrupt or tampered", self.address()))
        })?;
        decode_intro_points_plaintext(&serialized)
    }
}

/// Load a persisted 32-byte X25519 private key from `path`, generating one
/// (mode 0600, in a directory restricted to 0700) on first use.
///
/// This is the client side of client authorization: the returned key is
/// what [`HiddenServiceDescriptor::intro_points_for`] needs, and
/// [`client_auth_public_key`] derives the public half that gets handed to
/// a service operator to register.
///
/// # Errors
/// [`HiddenServiceError::Io`] on any filesystem failure, or if an existing
/// key file is not the expected size.
pub fn load_or_create_client_auth_key(path: &Path) -> Result<[u8; 32], HiddenServiceError> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    if path.exists() {
        if let Some(p) = parent {
            ensure_private_dir(p)?;
        }
        let data = fs::read(path).map_err(|e| HiddenServiceError::Io(format!("could not read {}: {e}", display_path(path))))?;
        return data
            .try_into()
            .map_err(|_| HiddenServiceError::Io(format!("{} is not a {X25519_KEY_LEN}-byte key; delete it and rerun", display_path(path))));
    }
    let key = random_array_32();
    if let Some(p) = parent {
        ensure_private_dir(p)?;
    }
    write_new_secret_file(path, &key)?;
    Ok(key)
}

/// The 32-byte X25519 public key for a client-auth private key -- what a
/// client hands to a service operator (see
/// [`load_or_create_client_auth_key`]) to be registered.
pub fn client_auth_public_key(client_auth_private_key: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*client_auth_private_key)).to_bytes()
}

/// Hard cap on how many distinct identities a single [`HiddenServiceDirectory`]
/// will hold at once. Security fix: an identity key is free for an
/// attacker to generate, and (unlike the ordinary relay directory, which
/// vets each entry against a signed quorum vote before trusting it --
/// `crate::directory`'s `MAX_DESCRIPTOR_COUNT`/`consensus::compute_consensus`)
/// any self-signed hidden-service descriptor with a fresh identity was
/// accepted here without limit, so a flood of freshly-generated identities
/// could grow this store's memory without bound. Rotating an
/// *already-registered* identity is never blocked by this cap (see
/// [`HiddenServiceDirectory::publish`]), only genuinely new ones once the
/// store is full.
pub const MAX_HS_DESCRIPTORS: usize = 4096;

/// A verifying store of hidden-service descriptors, keyed by address.
///
/// The counterpart to [`crate::directory::Directory`], kept separate
/// (rather than folded into it) because a service address is not a relay
/// identity and callers should never confuse the two lookup spaces.
pub struct HiddenServiceDirectory {
    clock: Arc<dyn Fn() -> f64 + Send + Sync>,
    max_descriptor_lifetime: Option<f64>,
    by_identity: HashMap<Vec<u8>, HiddenServiceDescriptor>,
    /// A second index, keyed by [`hs_directory_index`] rather than the
    /// real identity, so [`Self::get_by_blinded_index`] (what the
    /// wire-facing FETCH handler should use) never needs the real key to
    /// serve a lookup. Populated for the current period *and* the next one
    /// on every publish, so a descriptor published just before a period
    /// boundary is still findable by a client just after it.
    by_blinded_index: HashMap<Vec<u8>, Vec<u8>>,
}

impl HiddenServiceDirectory {
    /// `max_descriptor_lifetime` is the largest `not_after - not_before`
    /// span [`Self::publish`] will accept (see
    /// [`MAX_HS_DESCRIPTOR_LIFETIME`]); `None` disables the check
    /// entirely (not recommended, since revocation here is otherwise only
    /// as strong as every accepted descriptor's own stated expiry).
    ///
    /// # Errors
    /// [`HiddenServiceError::Other`] if `max_descriptor_lifetime` is
    /// `Some` and not positive.
    pub fn new(clock: Option<Arc<dyn Fn() -> f64 + Send + Sync>>, max_descriptor_lifetime: Option<f64>) -> Result<Self, HiddenServiceError> {
        if let Some(m) = max_descriptor_lifetime {
            if m <= 0.0 {
                return Err(HiddenServiceError::Other(format!("max_descriptor_lifetime must be positive (or None to disable), got {m}")));
            }
        }
        Ok(HiddenServiceDirectory {
            clock: clock.unwrap_or_else(|| Arc::new(now_unix) as Arc<dyn Fn() -> f64 + Send + Sync>),
            max_descriptor_lifetime,
            by_identity: HashMap::new(),
            by_blinded_index: HashMap::new(),
        })
    }

    /// Verify and store `descriptor`.
    ///
    /// Returns `true` if accepted, `false` if a newer one is already held.
    ///
    /// # Errors
    /// [`HiddenServiceError::SignatureInvalid`] if the self-signature does
    /// not verify; [`HiddenServiceError::DescriptorLifetimeTooLong`] if
    /// `not_after - not_before` exceeds `max_descriptor_lifetime` (checked
    /// before the expiry check below, since a descriptor can be both
    /// currently valid and absurdly long-lived);
    /// [`HiddenServiceError::DescriptorExpired`] if the validity window
    /// has passed; [`HiddenServiceError::StoreFull`] if this directory
    /// already holds [`MAX_HS_DESCRIPTORS`] identities and `descriptor`'s
    /// is not one of them.
    pub fn publish(&mut self, descriptor: HiddenServiceDescriptor) -> Result<bool, HiddenServiceError> {
        descriptor.verify()?;
        if let Some(max) = self.max_descriptor_lifetime {
            let lifetime = descriptor.not_after - descriptor.not_before;
            if lifetime > max {
                return Err(HiddenServiceError::DescriptorLifetimeTooLong(format!(
                    "descriptor for {} claims a {lifetime:.0}s validity window, longer than the {max:.0}s \
                     this directory accepts -- an unbounded lifetime would be effectively unrevokable since \
                     revocation here is expiry-driven",
                    descriptor.address()
                )));
            }
        }
        let now = (self.clock)();
        if !descriptor.is_valid_at(now) {
            return Err(HiddenServiceError::DescriptorExpired(format!("descriptor for {} is outside its validity window", descriptor.address())));
        }
        if let Some(existing) = self.by_identity.get(&descriptor.identity_public) {
            if existing.not_before > descriptor.not_before {
                return Ok(false);
            }
        } else if self.by_identity.len() >= MAX_HS_DESCRIPTORS {
            // Only a genuinely new identity (not a rotation of one already
            // held, handled above) is refused here -- an existing service
            // renewing its own descriptor must never be evicted just
            // because unrelated flood traffic has since filled the store.
            return Err(HiddenServiceError::StoreFull(format!(
                "this directory already holds {MAX_HS_DESCRIPTORS} hidden-service descriptors (the maximum); refusing a new identity until one expires or is pruned"
            )));
        }
        let identity_public = descriptor.identity_public.clone();
        let period = hs_directory_period(Some(now), None);
        for p in [period, period + 1] {
            let index = hs_directory_index(&identity_public, Some(p))?;
            self.by_blinded_index.insert(index.to_vec(), identity_public.clone());
        }
        self.by_identity.insert(identity_public, descriptor);
        Ok(true)
    }

    /// Return a live descriptor for an identity key, or `None`.
    pub fn get(&self, identity_public: &[u8]) -> Option<&HiddenServiceDescriptor> {
        let descriptor = self.by_identity.get(identity_public)?;
        if !descriptor.is_valid_at((self.clock)()) {
            return None;
        }
        Some(descriptor)
    }

    /// Return a live descriptor for an [`hs_directory_index`] value. This
    /// is what an HS FETCH handler should call instead of [`Self::get`] --
    /// it never needs the real identity key, only the blinded index a
    /// client computed the same way the service did when it last
    /// published.
    pub fn get_by_blinded_index(&self, index: &[u8]) -> Option<&HiddenServiceDescriptor> {
        let identity_public = self.by_blinded_index.get(index)?;
        self.get(identity_public)
    }

    /// Drop expired descriptors, returning how many were removed.
    pub fn prune(&mut self) -> usize {
        let now = (self.clock)();
        let stale: Vec<Vec<u8>> = self.by_identity.iter().filter(|(_, d)| !d.is_valid_at(now)).map(|(k, _)| k.clone()).collect();
        for key in &stale {
            self.by_identity.remove(key);
        }
        if !stale.is_empty() {
            let stale_set: std::collections::HashSet<&Vec<u8>> = stale.iter().collect();
            self.by_blinded_index.retain(|_, identity_public| !stale_set.contains(identity_public));
        }
        stale.len()
    }

    pub fn len(&self) -> usize {
        let now = (self.clock)();
        self.by_identity.values().filter(|d| d.is_valid_at(now)).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn scratch_dir(label: &str) -> PathBuf {
        let n = {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            COUNTER.fetch_add(1, Ordering::Relaxed)
        };
        let dir = std::env::temp_dir().join(format!("allium-hs-test-{label}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn address_round_trips() {
        let identity = [7u8; 32];
        let address = encode_address(&identity).unwrap();
        assert!(address.ends_with(".allium"));
        let decoded = decode_address(&address).unwrap();
        assert_eq!(decoded, identity);
    }

    #[test]
    fn address_rejects_bad_checksum_and_suffix() {
        let identity = [7u8; 32];
        let address = encode_address(&identity).unwrap();
        let mut tampered = address.clone();
        tampered.replace_range(0..1, if address.starts_with('a') { "b" } else { "a" });
        assert!(decode_address(&tampered).is_err());
        assert!(decode_address("not-an-address.com").is_err());
    }

    #[test]
    fn encode_address_rejects_wrong_length() {
        assert!(encode_address(&[1, 2, 3]).is_err());
    }

    #[test]
    fn descriptor_create_and_verify_round_trip() {
        let identity_private = [3u8; 32];
        let descriptor = HiddenServiceDescriptor::create(
            &identity_private,
            vec![9u8; 32],
            vec![IntroPoint { relay_identity: vec![1u8; 32], host: "10.0.0.1".to_string(), port: 9000, auth_public: vec![2u8; 32] }],
            DEFAULT_HS_DESCRIPTOR_LIFETIME,
            Some(1_700_000_000.0),
        );
        descriptor.verify().unwrap();
        let expected_address = encode_address(&descriptor.identity_public).unwrap();
        assert_eq!(descriptor.address(), expected_address);
    }

    #[test]
    fn tampered_intro_auth_public_fails_verification() {
        let identity_private = [3u8; 32];
        let mut descriptor = HiddenServiceDescriptor::create(
            &identity_private,
            vec![9u8; 32],
            vec![IntroPoint { relay_identity: vec![1u8; 32], host: "10.0.0.1".to_string(), port: 9000, auth_public: vec![2u8; 32] }],
            DEFAULT_HS_DESCRIPTOR_LIFETIME,
            Some(1_700_000_000.0),
        );
        descriptor.intro_points[0].auth_public = vec![0xffu8; 32];
        assert!(matches!(descriptor.verify(), Err(HiddenServiceError::SignatureInvalid(_))));
    }

    #[test]
    fn tampered_descriptor_fails_verification() {
        let identity_private = [4u8; 32];
        let mut descriptor = HiddenServiceDescriptor::create(&identity_private, vec![9u8; 32], vec![], DEFAULT_HS_DESCRIPTOR_LIFETIME, Some(1_700_000_000.0));
        descriptor.not_after += 1.0;
        assert!(matches!(descriptor.verify(), Err(HiddenServiceError::SignatureInvalid(_))));
    }

    #[test]
    fn client_auth_signing_payload_differs_from_plain() {
        let mut plain = HiddenServiceDescriptor::new(vec![1; 32], vec![2; 32], vec![], 0.0, 100.0);
        let mut auth = plain.clone();
        auth.client_auth = vec![ClientAuthEntry { client_id_hint: vec![5; 16], wrapped_key: vec![6; 8] }];
        plain.signature = vec![0; 64];
        assert_ne!(plain.signing_payload(), auth.signing_payload());
    }

    #[test]
    fn hs_directory_period_matches_manual_division() {
        assert_eq!(hs_directory_period(Some(0.0), None), 0);
        assert_eq!(hs_directory_period(Some(HS_DIRECTORY_INDEX_PERIOD - 1.0), None), 0);
        assert_eq!(hs_directory_period(Some(HS_DIRECTORY_INDEX_PERIOD), None), 1);
        assert_eq!(hs_directory_period(Some(1000.0), Some(100.0)), 10);
    }

    #[test]
    fn hs_directory_index_is_stable_and_identity_specific() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let idx_a1 = hs_directory_index(&a, Some(5)).unwrap();
        let idx_a2 = hs_directory_index(&a, Some(5)).unwrap();
        let idx_a3 = hs_directory_index(&a, Some(6)).unwrap();
        let idx_b = hs_directory_index(&b, Some(5)).unwrap();
        assert_eq!(idx_a1, idx_a2);
        assert_ne!(idx_a1, idx_a3);
        assert_ne!(idx_a1, idx_b);
        assert!(hs_directory_index(&[1, 2, 3], None).is_err());
    }

    #[test]
    fn seal_and_open_introduce_round_trip() {
        let service_private = StaticSecret::from(random_array_32());
        let service_public = PublicKey::from(&service_private).to_bytes();
        let client_private = StaticSecret::from(random_array_32());
        let plaintext = b"rendezvous point + cookie";
        let sealed = seal_introduce(&service_public, &client_private, plaintext).unwrap();
        let client_public = PublicKey::from(&client_private).to_bytes();
        let opened = open_introduce(&service_private, &client_public, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn open_introduce_rejects_tampered_envelope() {
        let service_private = StaticSecret::from(random_array_32());
        let service_public = PublicKey::from(&service_private).to_bytes();
        let client_private = StaticSecret::from(random_array_32());
        let mut sealed = seal_introduce(&service_public, &client_private, b"hello").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        let client_public = PublicKey::from(&client_private).to_bytes();
        assert!(open_introduce(&service_private, &client_public, &sealed).is_err());
    }

    #[test]
    fn derive_session_keys_are_distinct_and_deterministic() {
        let shared = [42u8; 32];
        let intro_secret = [99u8; 32];
        let (c2s_a, s2c_a) = derive_session_keys(&shared, &intro_secret);
        let (c2s_b, s2c_b) = derive_session_keys(&shared, &intro_secret);
        assert_eq!(c2s_a, c2s_b);
        assert_eq!(s2c_a, s2c_b);
        assert_ne!(c2s_a, s2c_a);
    }

    #[test]
    fn derive_session_keys_bind_the_intro_secret() {
        // Same rendezvous ECDH output, different intro_secret -- as if an
        // attacker who somehow matched the rendezvous shared secret still
        // did not know the client<->service introduction secret. The
        // resulting session keys must differ.
        let shared = [1u8; 32];
        let (c2s_a, s2c_a) = derive_session_keys(&shared, &[2u8; 32]);
        let (c2s_b, s2c_b) = derive_session_keys(&shared, &[3u8; 32]);
        assert_ne!(c2s_a, c2s_b);
        assert_ne!(s2c_a, s2c_b);
    }

    #[test]
    fn hs_session_round_trips_both_directions() {
        let shared = [7u8; 32];
        let intro_secret = [8u8; 32];
        let (key_c2s, key_s2c) = derive_session_keys(&shared, &intro_secret);
        let cookie = b"cookie-0123456789012345678901234";
        let client_session = HsSession::new(&key_c2s, &key_s2c, cookie, false).unwrap();
        let service_session = HsSession::new(&key_c2s, &key_s2c, cookie, true).unwrap();

        let from_client = client_session.seal(b"hello service").unwrap();
        assert_eq!(service_session.open(&from_client).unwrap(), b"hello service");

        let from_service = service_session.seal(b"hello client").unwrap();
        assert_eq!(client_session.open(&from_service).unwrap(), b"hello client");
    }

    #[test]
    fn service_identity_generate_signs_and_addresses() {
        let identity = ServiceIdentity::generate();
        let sig = identity.sign(b"payload");
        let verifying = VerifyingKey::from_bytes(&identity.identity_public()).unwrap();
        verifying.verify(b"payload", &Signature::from_bytes(&sig)).unwrap();
        assert!(identity.address().ends_with(".allium"));
    }

    #[test]
    fn intro_auth_keypair_is_deterministic_and_relay_specific() {
        let identity = ServiceIdentity::generate();
        let relay_a = [1u8; 32];
        let relay_b = [2u8; 32];
        let (seed_a1, pub_a1) = identity.intro_auth_keypair(&relay_a).unwrap();
        let (seed_a2, pub_a2) = identity.intro_auth_keypair(&relay_a).unwrap();
        let (_seed_b, pub_b) = identity.intro_auth_keypair(&relay_b).unwrap();
        assert_eq!(seed_a1, seed_a2);
        assert_eq!(pub_a1, pub_a2);
        assert_ne!(pub_a1, pub_b);
        assert_ne!(pub_a1, identity.identity_public());
    }

    #[test]
    fn service_identity_open_introduce_round_trip_and_replay_rejected() {
        let identity = ServiceIdentity::generate();
        let service_public = identity.encryption_public().unwrap();
        let client_private = StaticSecret::from(random_array_32());
        let client_public = PublicKey::from(&client_private).to_bytes();
        let sealed = seal_introduce(&service_public, &client_private, b"rendezvous info").unwrap();

        let (opened, intro_secret) = identity.open_introduce(&client_public, &sealed).unwrap();
        assert_eq!(opened, b"rendezvous info");
        // The service's DH output must match what the client itself
        // computed sealing the envelope -- this is `intro_secret`, later
        // used to authenticate the rendezvous handshake.
        let expected_secret = client_private.diffie_hellman(&PublicKey::from(service_public)).to_bytes();
        assert_eq!(intro_secret, expected_secret);

        // A second open of the exact same envelope is a replay.
        let err = identity.open_introduce(&client_public, &sealed).unwrap_err();
        assert!(matches!(err, HiddenServiceError::IntroduceReplayed(_)));
    }

    #[test]
    fn service_identity_open_introduce_rejects_low_order_client_key() {
        let identity = ServiceIdentity::generate();
        let service_public = identity.encryption_public().unwrap();
        // One of the eight canonical low-order u-coordinates (the all-zero
        // point).
        let low_order_client_public = [0u8; 32];
        // A real sealed envelope isn't needed -- the contributory check
        // runs before the envelope is even opened.
        let sealed = vec![0u8; 64];
        let _ = service_public;
        let err = identity.open_introduce(&low_order_client_public, &sealed).unwrap_err();
        assert!(matches!(err, HiddenServiceError::NonContributoryKey(_)));
    }

    /// Security audit fix (2026-09-26): a second rotation racing ahead of
    /// the first rotation's own grace-period expiry used to silently drop
    /// the still-live `intro_previous_seed` from that first rotation
    /// un-zeroized (`state.intro_previous_seed = Some(state.intro_seed)`
    /// overwriting it outright). Functionally, this must still behave
    /// exactly as before the fix -- the newest previous key stays usable
    /// for `open_introduce` (proving the overwrite-with-zeroize didn't
    /// corrupt the replacement value), and the oldest one (superseded
    /// twice over) is gone.
    #[test]
    fn double_rotation_before_first_grace_period_expires_still_evicts_correctly() {
        let clock = Arc::new(Mutex::new(1_000_000.0_f64));
        let clock_clone = Arc::clone(&clock);
        let opts = ServiceIdentityOptions {
            rotation_period: 10.0,
            grace_period: 100.0, // long enough that neither rotation below expires on its own
            clock: Some(Arc::new(move || *clock_clone.lock().unwrap())),
            ..Default::default()
        };
        let identity = ServiceIdentity::new(random_array_32(), opts);

        let key1 = identity.encryption_public().unwrap();
        let client1_private = StaticSecret::from(random_array_32());
        let client1_public = PublicKey::from(&client1_private).to_bytes();
        let sealed_for_key1 = seal_introduce(&key1, &client1_private, b"for key1").unwrap();

        *clock.lock().unwrap() += 11.0; // first rotation: key1 -> key2, intro_previous_seed = key1's seed
        let key2 = identity.encryption_public().unwrap();
        assert_ne!(key1, key2);

        *clock.lock().unwrap() += 11.0; // second rotation: key2 -> key3, intro_previous_seed = key2's seed (key1's is now gone)
        let key3 = identity.encryption_public().unwrap();
        assert_ne!(key2, key3);

        // key1's grace window is over (superseded, not just expired by
        // time) -- a message sealed for it can no longer be opened.
        assert!(identity.open_introduce(&client1_public, &sealed_for_key1).is_err());

        // key2 is still within its own grace period (only 11s old, well
        // under the 100s grace_period) -- a message sealed for it must
        // still open, proving `intro_previous_seed` correctly holds key2's
        // seed (not corrupted, not accidentally left as key1's).
        let client2_private = StaticSecret::from(random_array_32());
        let client2_public = PublicKey::from(&client2_private).to_bytes();
        let sealed_for_key2 = seal_introduce(&key2, &client2_private, b"for key2").unwrap();
        let (opened, _secret) = identity.open_introduce(&client2_public, &sealed_for_key2).unwrap();
        assert_eq!(opened, b"for key2");
    }

    #[test]
    fn service_identity_rotates_key_and_honors_grace_period() {
        let clock = Arc::new(Mutex::new(1_000_000.0_f64));
        let clock_clone = Arc::clone(&clock);
        let opts = ServiceIdentityOptions {
            rotation_period: 100.0,
            grace_period: 50.0,
            clock: Some(Arc::new(move || *clock_clone.lock().unwrap())),
            ..Default::default()
        };
        let identity = ServiceIdentity::new(random_array_32(), opts);

        let old_public = identity.encryption_public().unwrap();
        let client_private = StaticSecret::from(random_array_32());
        let client_public = PublicKey::from(&client_private).to_bytes();
        let sealed_before_rotation = seal_introduce(&old_public, &client_private, b"still using old key").unwrap();

        // Advance past rotation_period but within grace_period: the old
        // key must still open an envelope sealed against it.
        *clock.lock().unwrap() += 120.0;
        let new_public = identity.encryption_public().unwrap();
        assert_ne!(old_public, new_public);
        let (opened, _secret) = identity.open_introduce(&client_public, &sealed_before_rotation).unwrap();
        assert_eq!(opened, b"still using old key");

        // Advance well past rotation_period + grace_period: a fresh
        // envelope sealed against the now-ancient old key must fail, since
        // the previous key has been discarded from memory.
        let client_private2 = StaticSecret::from(random_array_32());
        let client_public2 = PublicKey::from(&client_private2).to_bytes();
        let sealed_old = seal_introduce(&old_public, &client_private2, b"old key, too late").unwrap();
        *clock.lock().unwrap() += 1000.0;
        let _ = identity.encryption_public().unwrap(); // trigger another rotation check
        assert!(identity.open_introduce(&client_public2, &sealed_old).is_err());
    }

    #[test]
    fn client_auth_descriptor_round_trip() {
        let identity_private = [11u8; 32];
        let encryption_public = vec![22u8; 32];
        let intro_points = vec![IntroPoint { relay_identity: vec![1u8; 32], host: "10.0.0.5".to_string(), port: 9100, auth_public: vec![2u8; 32] }];

        let client_private = random_array_32();
        let client_public = client_auth_public_key(&client_private);
        let other_private = random_array_32();
        let other_public = client_auth_public_key(&other_private);

        let descriptor = HiddenServiceDescriptor::create_with_client_auth(
            &identity_private,
            encryption_public,
            intro_points.clone(),
            DEFAULT_HS_DESCRIPTOR_LIFETIME,
            Some(1_700_000_000.0),
            &[client_public, other_public],
        )
        .unwrap();
        descriptor.verify().unwrap();
        assert!(descriptor.intro_points.is_empty());
        assert_eq!(descriptor.client_auth.len(), 2);

        let decrypted = descriptor.intro_points_for(Some(&client_private)).unwrap();
        assert_eq!(decrypted, intro_points);

        let decrypted2 = descriptor.intro_points_for(Some(&other_private)).unwrap();
        assert_eq!(decrypted2, intro_points);
    }

    #[test]
    fn client_auth_descriptor_rejects_wrong_or_missing_key() {
        let identity_private = [12u8; 32];
        let intro_points = vec![IntroPoint { relay_identity: vec![3u8; 32], host: "10.0.0.6".to_string(), port: 9200, auth_public: vec![4u8; 32] }];
        let authorized_private = random_array_32();
        let authorized_public = client_auth_public_key(&authorized_private);
        let descriptor = HiddenServiceDescriptor::create_with_client_auth(
            &identity_private,
            vec![22u8; 32],
            intro_points,
            DEFAULT_HS_DESCRIPTOR_LIFETIME,
            Some(1_700_000_000.0),
            &[authorized_public],
        )
        .unwrap();

        assert!(matches!(descriptor.intro_points_for(None), Err(HiddenServiceError::ClientNotAuthorized(_))));

        let unauthorized_private = random_array_32();
        assert!(matches!(descriptor.intro_points_for(Some(&unauthorized_private)), Err(HiddenServiceError::ClientNotAuthorized(_))));
    }

    #[test]
    fn hidden_service_directory_publish_get_and_prune() {
        let clock = Arc::new(Mutex::new(1_000_000.0_f64));
        let clock_clone = Arc::clone(&clock);
        let mut dir = HiddenServiceDirectory::new(Some(Arc::new(move || *clock_clone.lock().unwrap())), None).unwrap();

        let identity_private = [13u8; 32];
        let now = *clock.lock().unwrap();
        let descriptor = HiddenServiceDescriptor::create(&identity_private, vec![22u8; 32], vec![], 3600.0, Some(now));
        let identity_public = descriptor.identity_public.clone();

        assert!(dir.publish(descriptor.clone()).unwrap());
        assert_eq!(dir.get(&identity_public), Some(&descriptor));

        let index = hs_directory_index(&identity_public, Some(hs_directory_period(Some(now), None))).unwrap();
        assert_eq!(dir.get_by_blinded_index(&index), Some(&descriptor));

        // Publishing a strictly older descriptor for the same identity
        // (an out-of-order replay of an earlier publish) is a no-op that
        // reports "not accepted"; the newer one already held is kept.
        let older = HiddenServiceDescriptor::create(&identity_private, vec![22u8; 32], vec![], 3600.0, Some(now - 10.0));
        assert!(!dir.publish(older).unwrap());
        assert_eq!(dir.get(&identity_public), Some(&descriptor));

        // Advance well past its lifetime and prune.
        *clock.lock().unwrap() += 10_000.0;
        assert_eq!(dir.prune(), 1);
        assert_eq!(dir.get(&identity_public), None);
        assert!(dir.is_empty());
    }

    /// Security fix: an attacker can mint identity keys for free, so
    /// nothing before this bounded a flood of freshly-generated identities
    /// from growing `by_identity` without limit. Fills the store to
    /// `MAX_HS_DESCRIPTORS` directly (bypassing `publish`'s signature
    /// check, irrelevant to the cap logic under test, so this doesn't need
    /// to mint and verify thousands of real signatures) and confirms a
    /// genuinely new identity is refused once full, while rotating an
    /// identity already held is never blocked by the cap.
    #[test]
    fn hidden_service_directory_rejects_new_identity_once_full_but_still_allows_rotation() {
        let mut dir = HiddenServiceDirectory::new(Some(Arc::new(|| 2000.0)), None).unwrap();
        let existing_private = [29u8; 32];
        let existing = HiddenServiceDescriptor::create(&existing_private, vec![22u8; 32], vec![], 3600.0, Some(1900.0));
        let existing_identity = existing.identity_public.clone();
        assert!(dir.publish(existing).unwrap());
        for i in 1..MAX_HS_DESCRIPTORS {
            let mut filler = HiddenServiceDescriptor::create(&existing_private, vec![22u8; 32], vec![], 3600.0, Some(1900.0));
            filler.identity_public = format!("filler-{i}").into_bytes();
            dir.by_identity.insert(filler.identity_public.clone(), filler);
        }
        assert_eq!(dir.len(), MAX_HS_DESCRIPTORS);

        // A genuinely new identity is refused once full.
        let newcomer_private = [250u8; 32];
        let newcomer = HiddenServiceDescriptor::create(&newcomer_private, vec![22u8; 32], vec![], 3600.0, Some(1900.0));
        assert!(matches!(dir.publish(newcomer), Err(HiddenServiceError::StoreFull(_))));

        // Rotating an identity already in the store is never blocked by
        // the cap: the existing service must always be able to renew.
        let rotated = HiddenServiceDescriptor::create(&existing_private, vec![22u8; 32], vec![], 3600.0, Some(1950.0));
        assert_eq!(rotated.identity_public, existing_identity);
        assert!(dir.publish(rotated).unwrap());
        assert_eq!(dir.len(), MAX_HS_DESCRIPTORS, "rotation must not change the store's size");
    }

    #[test]
    fn hidden_service_directory_rejects_expired_and_overlong() {
        let mut dir = HiddenServiceDirectory::new(None, Some(100.0)).unwrap();
        let identity_private = [14u8; 32];

        let too_long = HiddenServiceDescriptor::create(&identity_private, vec![22u8; 32], vec![], 200.0, None);
        assert!(matches!(dir.publish(too_long), Err(HiddenServiceError::DescriptorLifetimeTooLong(_))));

        let already_expired = HiddenServiceDescriptor::create(&identity_private, vec![22u8; 32], vec![], 10.0, Some(1_000_000.0));
        assert!(matches!(dir.publish(already_expired), Err(HiddenServiceError::DescriptorExpired(_))));
    }

    #[test]
    fn service_identity_load_or_create_persists_seed_and_intro_key() {
        let dir = scratch_dir("identity");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hs_identity");

        let first = ServiceIdentity::load_or_create(&path).unwrap();
        let second = ServiceIdentity::load_or_create(&path).unwrap();
        assert_eq!(first.identity_public(), second.identity_public());
        assert_eq!(first.encryption_public().unwrap(), second.encryption_public().unwrap());

        // The identity file itself is exactly the raw 32-byte seed.
        let seed_on_disk = fs::read(&path).unwrap();
        assert_eq!(seed_on_disk, first.seed());

        let _ = fs::remove_dir_all(&dir);
    }

    // ---------------------------------------------------------------------
    // MAC-authenticated rendezvous handshake
    // ---------------------------------------------------------------------

    /// End-to-end simulation of the fixed handshake: a client seals an
    /// INTRODUCE request, a service opens it (recovering the same
    /// `intro_secret` the client derived while sealing), and both sides
    /// independently compute the same MAC and the same session keys -- with
    /// no rendezvous point (real or attacker-controlled) involved in any of
    /// this, matching the real protocol where the RP only ever forwards
    /// opaque bytes.
    #[test]
    fn rendezvous_handshake_round_trip_client_and_service_agree() {
        let identity = ServiceIdentity::generate();
        let service_encryption_public = identity.encryption_public().unwrap();

        let client_ephemeral_seed = random_array_32();
        let client_ephemeral = StaticSecret::from(client_ephemeral_seed);
        let client_ephemeral_pub = PublicKey::from(&client_ephemeral).to_bytes();
        let cookie = random_array_32();
        let rp_identity = [0x42u8; 32];

        let rp_request = b"pretend-encoded-rendezvous-request";
        let (sealed, client_intro_secret) =
            seal_introduce_with_secret(&service_encryption_public, &client_ephemeral, rp_request).unwrap();

        let (opened, service_intro_secret) = identity.open_introduce(&client_ephemeral_pub, &sealed).unwrap();
        assert_eq!(opened, rp_request);
        assert_eq!(client_intro_secret, service_intro_secret);

        // Service side: mint its ephemeral key and the MAC.
        let service_ephemeral_seed = random_array_32();
        let service_ephemeral = StaticSecret::from(service_ephemeral_seed);
        let service_ephemeral_pub = PublicKey::from(&service_ephemeral).to_bytes();
        let service_auth_key = rendezvous_auth_key(&service_intro_secret);
        let mac = rendezvous_mac(&service_auth_key, &client_ephemeral_pub, &service_ephemeral_pub, &service_encryption_public, &cookie, &rp_identity);
        let handshake = encode_rendezvous_handshake(&service_ephemeral_pub, &mac);

        // Client side: decode, verify, and derive.
        let (decoded_service_pub, decoded_mac) = decode_rendezvous_handshake(&handshake).unwrap();
        assert_eq!(decoded_service_pub, service_ephemeral_pub);
        let client_auth_key = rendezvous_auth_key(&client_intro_secret);
        verify_rendezvous_mac(&client_auth_key, &client_ephemeral_pub, &decoded_service_pub, &service_encryption_public, &cookie, &rp_identity, &decoded_mac)
            .unwrap();

        let service_side_shared = service_ephemeral.diffie_hellman(&PublicKey::from(client_ephemeral_pub));
        let client_side_shared = client_ephemeral.diffie_hellman(&PublicKey::from(decoded_service_pub));
        assert_eq!(service_side_shared.to_bytes(), client_side_shared.to_bytes());

        let (service_c2s, service_s2c) = derive_session_keys(&service_side_shared.to_bytes(), &service_intro_secret);
        let (client_c2s, client_s2c) = derive_session_keys(&client_side_shared.to_bytes(), &client_intro_secret);
        assert_eq!(service_c2s, client_c2s);
        assert_eq!(service_s2c, client_s2c);
    }

    /// The core H6 scenario: a rendezvous point that never involves the
    /// real service (it answers the join itself and substitutes its own
    /// ephemeral key) cannot produce a MAC the client accepts, because it
    /// never learns `intro_secret` -- the sealed INTRODUCE envelope is
    /// opaque to it.
    #[test]
    fn rogue_rendezvous_point_cannot_forge_the_mac() {
        let identity = ServiceIdentity::generate();
        let service_encryption_public = identity.encryption_public().unwrap();
        let client_ephemeral = StaticSecret::from(random_array_32());
        let client_ephemeral_pub = PublicKey::from(&client_ephemeral).to_bytes();
        let cookie = random_array_32();
        let rp_identity = [0x99u8; 32];

        let (_sealed, client_intro_secret) =
            seal_introduce_with_secret(&service_encryption_public, &client_ephemeral, b"rp-request").unwrap();

        // The rogue RP never opens the envelope (it can't -- it's sealed to
        // the service's key), so the best it can do is invent its own
        // ephemeral key and *some* 32 bytes where the MAC should be.
        let forged_ephemeral = StaticSecret::from(random_array_32());
        let forged_ephemeral_pub = PublicKey::from(&forged_ephemeral).to_bytes();
        let garbage_mac = [0x13u8; 32];
        let handshake = encode_rendezvous_handshake(&forged_ephemeral_pub, &garbage_mac);

        let (decoded_pub, decoded_mac) = decode_rendezvous_handshake(&handshake).unwrap();
        let client_auth_key = rendezvous_auth_key(&client_intro_secret);
        let err =
            verify_rendezvous_mac(&client_auth_key, &client_ephemeral_pub, &decoded_pub, &service_encryption_public, &cookie, &rp_identity, &decoded_mac)
                .unwrap_err();
        assert!(matches!(err, HiddenServiceError::RendezvousAuthFailed(_)));
    }

    /// Even if a rogue RP somehow guessed a correct-looking MAC for a
    /// *different* set of bytes, substituting its own ephemeral key still
    /// fails: the MAC covers `service_ephemeral_public`, so it cannot be
    /// replayed against a different key.
    #[test]
    fn substituted_service_key_is_rejected_even_with_a_valid_mac_for_different_bytes() {
        let identity = ServiceIdentity::generate();
        let service_encryption_public = identity.encryption_public().unwrap();
        let client_ephemeral = StaticSecret::from(random_array_32());
        let client_ephemeral_pub = PublicKey::from(&client_ephemeral).to_bytes();
        let cookie = random_array_32();
        let rp_identity = [7u8; 32];

        let (sealed, client_intro_secret) =
            seal_introduce_with_secret(&service_encryption_public, &client_ephemeral, b"rp-request").unwrap();
        let (_plain, service_intro_secret) = identity.open_introduce(&client_ephemeral_pub, &sealed).unwrap();

        let real_service_ephemeral_pub = PublicKey::from(&StaticSecret::from(random_array_32())).to_bytes();
        let auth_key = rendezvous_auth_key(&service_intro_secret);
        let real_mac = rendezvous_mac(&auth_key, &client_ephemeral_pub, &real_service_ephemeral_pub, &service_encryption_public, &cookie, &rp_identity);

        // Attacker swaps in a different ephemeral key but keeps the
        // genuine MAC bytes from the real handshake it observed on the
        // wire for a *different* session/service.
        let swapped_ephemeral_pub = PublicKey::from(&StaticSecret::from(random_array_32())).to_bytes();
        let client_auth_key = rendezvous_auth_key(&client_intro_secret);
        let err = verify_rendezvous_mac(
            &client_auth_key,
            &client_ephemeral_pub,
            &swapped_ephemeral_pub,
            &service_encryption_public,
            &cookie,
            &rp_identity,
            &real_mac,
        )
        .unwrap_err();
        assert!(matches!(err, HiddenServiceError::RendezvousAuthFailed(_)));
    }

    #[test]
    fn decode_rendezvous_handshake_rejects_the_old_bare_key_v1_shape() {
        // The pre-fix wire shape was exactly the 32-byte ephemeral key with
        // no MAC. A v2-only client must refuse it outright rather than
        // guess at a shorter format.
        let bare_key = [5u8; 32];
        let err = decode_rendezvous_handshake(&bare_key).unwrap_err();
        assert!(matches!(err, HiddenServiceError::Other(_)));
    }

    #[test]
    fn client_side_dh_rejects_low_order_service_key() {
        // Mirrors `service_identity_open_introduce_rejects_low_order_client_key`
        // but for the client's half of the rendezvous DH: a service (or a
        // rogue RP, if it ever got this far) sending a low-order point as
        // its ephemeral key must not be able to force an all-zero shared
        // secret.
        let client_ephemeral = StaticSecret::from(random_array_32());
        let low_order_service_pub = [0u8; 32];
        let shared = client_ephemeral.diffie_hellman(&PublicKey::from(low_order_service_pub));
        assert!(!shared.was_contributory());
    }

    #[test]
    fn descriptor_hs_handshake_v2_flag_is_authenticated() {
        let identity_private = [21u8; 32];
        let with_v2 = HiddenServiceDescriptor::create(&identity_private, vec![9u8; 32], vec![], DEFAULT_HS_DESCRIPTOR_LIFETIME, Some(1_700_000_000.0));
        assert!(with_v2.hs_handshake_v2);
        with_v2.verify().unwrap();

        // Flipping the flag after signing must invalidate the signature --
        // a malicious authority (or anyone else who can touch the bytes in
        // transit) cannot silently downgrade a service by clearing it.
        let mut downgraded = with_v2.clone();
        downgraded.hs_handshake_v2 = false;
        assert!(matches!(downgraded.verify(), Err(HiddenServiceError::SignatureInvalid(_))));
    }

    #[test]
    fn load_or_create_client_auth_key_persists() {
        let dir = scratch_dir("clientauth");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client_auth_key");

        let first = load_or_create_client_auth_key(&path).unwrap();
        let second = load_or_create_client_auth_key(&path).unwrap();
        assert_eq!(first, second);
        assert_eq!(client_auth_public_key(&first), client_auth_public_key(&second));

        let _ = fs::remove_dir_all(&dir);
    }

    // -- HsSession: sequenced, direction-bound frames ---------------------

    fn session_pair() -> (HsSession, HsSession) {
        let (key_c2s, key_s2c) = derive_session_keys(&[7u8; 32], &[8u8; 32]);
        let cookie = b"cookie-0123456789012345678901234";
        (HsSession::new(&key_c2s, &key_s2c, cookie, false).unwrap(), HsSession::new(&key_c2s, &key_s2c, cookie, true).unwrap())
    }

    #[test]
    fn hs_session_many_frames_in_order_both_directions() {
        let (client, service) = session_pair();
        for i in 0..50u8 {
            let up = client.seal(&[i; 10]).unwrap();
            assert_eq!(service.open(&up).unwrap(), vec![i; 10]);
            let down = service.seal(&[i ^ 0xff; 3]).unwrap();
            assert_eq!(client.open(&down).unwrap(), vec![i ^ 0xff; 3]);
        }
    }

    #[test]
    fn hs_session_rejects_a_replayed_frame_and_keeps_working() {
        let (client, service) = session_pair();
        let f0 = client.seal(b"POST /transfer").unwrap();
        let f1 = client.seal(b"next").unwrap();
        assert_eq!(service.open(&f0).unwrap(), b"POST /transfer");
        // a malicious rendezvous point re-sends the same frame: it is not delivered twice
        assert!(matches!(service.open(&f0), Err(HiddenServiceError::SessionReplay(_))));
        // the rejected replay changed nothing: the real next frame still opens
        assert_eq!(service.open(&f1).unwrap(), b"next");
        assert!(matches!(service.open(&f0), Err(HiddenServiceError::SessionReplay(_))));
    }

    #[test]
    fn hs_session_rejects_reordered_frames_as_a_gap_then_accepts_the_right_order() {
        let (client, service) = session_pair();
        let f0 = client.seal(b"first").unwrap();
        let f1 = client.seal(b"second").unwrap();
        assert!(matches!(service.open(&f1), Err(HiddenServiceError::SessionGap(_))));
        // nothing was consumed by the rejected frame
        assert_eq!(service.open(&f0).unwrap(), b"first");
        assert_eq!(service.open(&f1).unwrap(), b"second");
    }

    #[test]
    fn hs_session_detects_a_dropped_frame() {
        let (client, service) = session_pair();
        let f0 = client.seal(b"a").unwrap();
        let _dropped = client.seal(b"b").unwrap();
        let f2 = client.seal(b"c").unwrap();
        assert_eq!(service.open(&f0).unwrap(), b"a");
        // frame 1 never arrives; frame 2 is authentic but ahead of expected
        let err = service.open(&f2).unwrap_err();
        assert!(matches!(err, HiddenServiceError::SessionGap(_)), "{err:?}");
    }

    #[test]
    fn hs_session_close_is_authenticated_and_final() {
        let (client, service) = session_pair();
        let data = client.seal(b"last words").unwrap();
        let close = client.seal_close().unwrap();
        assert!(!service.peer_closed());
        assert_eq!(service.open_frame(&data).unwrap(), HsFrame::Data(b"last words".to_vec()));
        assert!(!service.peer_closed(), "a tunnel that ended before the close frame was cut off");
        assert_eq!(service.open_frame(&close).unwrap(), HsFrame::Close);
        assert!(service.peer_closed());
        // the closing side can send nothing more
        assert!(matches!(client.seal(b"too late"), Err(HiddenServiceError::SessionClosed(_))));
        assert!(matches!(client.seal_close(), Err(HiddenServiceError::SessionClosed(_))));
    }

    #[test]
    fn hs_session_rejects_anything_after_the_peers_close() {
        let (client, service) = session_pair();
        // a second sender with the same keys stands in for an attacker who somehow holds a valid later frame
        let (other_client, _) = session_pair();
        let f0 = client.seal(b"x").unwrap();
        let close = client.seal_close().unwrap();
        other_client.seal(b"a").unwrap();
        other_client.seal(b"b").unwrap();
        let later = other_client.seal(b"c").unwrap(); // sequence 2
        service.open(&f0).unwrap();
        assert_eq!(service.open_frame(&close).unwrap(), HsFrame::Close);
        let err = service.open(&later).unwrap_err();
        assert!(matches!(err, HiddenServiceError::SessionClosed(_)), "{err:?}");
        // open() reports a close frame as SessionClosed too
        let (c2, s2) = session_pair();
        assert!(matches!(s2.open(&c2.seal_close().unwrap()), Err(HiddenServiceError::SessionClosed(_))));
    }

    #[test]
    fn hs_session_rejects_tampering_with_the_header_or_body() {
        let (client, service) = session_pair();
        let good = client.seal(b"payload").unwrap();
        // flip each header byte (kind, then the eight sequence bytes) and a body byte
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0x01;
            assert!(service.open(&bad).is_err(), "tampering with byte {i} was accepted");
        }
        // and the untouched frame still opens afterwards
        assert_eq!(service.open(&good).unwrap(), b"payload");
    }

    #[test]
    fn hs_session_forged_high_sequence_cannot_force_a_fatal_gap() {
        let (client, service) = session_pair();
        let good = client.seal(b"payload").unwrap();
        // someone without the key claims sequence 1000 on an otherwise valid-looking frame
        let mut forged = good.clone();
        forged[1..9].copy_from_slice(&1000u64.to_be_bytes());
        let err = service.open(&forged).unwrap_err();
        assert!(matches!(err, HiddenServiceError::Other(_)), "forgery must fail authentication, not look like a gap: {err:?}");
        assert_eq!(service.open(&good).unwrap(), b"payload");
    }

    #[test]
    fn hs_session_rejects_a_frame_reflected_back_to_its_sender() {
        let (client, service) = session_pair();
        let from_client = client.seal(b"hello").unwrap();
        assert!(client.open(&from_client).is_err());
        let from_service = service.seal(b"hi").unwrap();
        assert!(service.open(&from_service).is_err());
    }

    #[test]
    fn hs_session_rejects_malformed_frames() {
        let (_client, service) = session_pair();
        assert!(service.open(&[]).is_err());
        assert!(service.open(&[0u8; 8]).is_err());
        assert!(service.open(&[0u8; 9 + crate::crypto::SEAL_OVERHEAD - 1]).is_err());
        let mut unknown_kind = vec![0u8; 9 + crate::crypto::SEAL_OVERHEAD + 4];
        unknown_kind[0] = 7;
        assert!(service.open(&unknown_kind).is_err());
    }

    #[test]
    fn session_key_label_was_bumped_so_v2_and_v3_peers_cannot_interoperate() {
        let shared = [7u8; 32];
        let intro = [8u8; 32];
        let mut ikm = shared.to_vec();
        ikm.extend_from_slice(&intro);
        let v2_c2s = hs_hkdf(&ikm, b"allium-hs-session-v2", b"client-to-service", 32);
        let (v3_c2s, _) = derive_session_keys(&shared, &intro);
        assert_ne!(v2_c2s.as_slice(), v3_c2s.as_slice());
    }

    #[test]
    fn hs_session_direction_is_bound_into_every_frame() {
        // With one key for both directions, only the associated data keeps a
        // client's own frame from being accepted when reflected back to it.
        let key = [9u8; 32];
        let cookie = b"cookie-0123456789012345678901234";
        let client = HsSession::new(&key, &key, cookie, false).unwrap();
        let service = HsSession::new(&key, &key, cookie, true).unwrap();
        let from_client = client.seal(b"hello").unwrap();
        // delivered to the other side it opens...
        assert_eq!(service.open(&from_client).unwrap(), b"hello");
        // ...but reflected back to its own sender it must not
        let from_client_2 = client.seal(b"again").unwrap();
        let err = client.open(&from_client_2).unwrap_err();
        assert!(matches!(err, HiddenServiceError::Other(_)), "{err:?}");
    }
}
