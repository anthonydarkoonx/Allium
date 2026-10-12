//! Hidden services: reachable without a public IP, addressed as `x.allium`.
//!
//! Full port of `hiddenservice.py` (see that module's docstring for the
//! design rationale: addressing, discovery, the three-hop
//! introduction/rendezvous/session handshake, and serving). This is where
//! the real [`IntroPoint`]/[`ClientAuthEntry`]/[`HiddenServiceDescriptor`]
//! types now live -- `dirwire.rs`'s previously-local, crypto-free stand-ins
//! (same field names/types) are gone; `dirwire.rs` now imports these directly
//! (see that module's updated docs).
//!
//! **Crypto injection.** Like `nat.rs`'s `Ed25519Ops` and `handshake.rs`'s
//! `HandshakeOps`, every X25519/Ed25519 primitive this module needs is
//! injected via [`HsOps`] rather than called directly, so the descriptor/
//! session/introduction logic is fully testable without a real
//! `ed25519-dalek`/`x25519-dalek` in this sandbox. `HsOps::real()` is a
//! small, independent copy of `handshake.rs`'s `real_x25519_*`/
//! `real_ed25519_*` functions (plus an `ed25519_public_of` `handshake.rs`
//! doesn't need) rather than a reuse of `handshake::HandshakeOps` -- kept
//! independent for the same reason `hswire.rs`/`dirwire.rs` keep their own
//! reassemblers independent: this module has no import-time dependency on
//! `handshake.rs`'s state machine, only on the same well-known crate APIs.
//!
//! **HKDF-SHA256** reuses `crate::hashutil::hkdf_sha256` (the same
//! dependency-free, RFC-5869-verified implementation `handshake.rs`'s key
//! schedule uses), matching Python's `_hs_hkdf`'s call into `cryptography`'s
//! `HKDF(algorithm=SHA256, ...)`.
//!
//! **Keyed BLAKE2b.** `hs_directory_index` needs `hashlib.blake2b(...,
//! key=...)` (Python's stdlib); `crate::blake2` only had the unkeyed form
//! (what `onion.rs` needs), so a `blake2b_keyed` was added there for this
//! one caller, cross-checked against `hashlib.blake2b(..., key=...)` output
//! (see `blake2.rs`'s own tests).
//!
//! **File I/O** (`ServiceIdentity::load_or_create`,
//! `load_or_create_client_auth_key`) targets Unix (`std::os::unix::fs`) for
//! the 0700/0600 permission hardening and `O_EXCL`/atomic-rename semantics
//! Python's version has (this sandbox, and every environment Allium
//! currently targets, is Linux) -- a `cfg(not(unix))` fallback skips the
//! permission hardening rather than failing to compile.

use crate::reliability::HandshakeReplayGuard;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const ADDRESS_VERSION: u8 = 1;
pub const ADDRESS_SUFFIX: &str = ".allium";

pub const DEFAULT_HS_DESCRIPTOR_LIFETIME: f64 = 3600.0;
pub const MAX_HS_DESCRIPTOR_LIFETIME: f64 = DEFAULT_HS_DESCRIPTOR_LIFETIME * 24.0;

pub const DEFAULT_INTRODUCTION_KEY_ROTATION: f64 = 24.0 * 3600.0;
pub const DEFAULT_INTRODUCTION_KEY_GRACE: f64 = 3600.0;
pub const DEFAULT_INTRODUCE_REPLAY_ENTRIES: usize = 8192;

pub const HS_DIRECTORY_INDEX_PERIOD: f64 = 86400.0;

const ED25519_KEY_LEN: usize = 32;
const X25519_KEY_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;
const CLIENT_ID_HINT_LEN: usize = 16;

// ---------------------------------------------------------------------------
// Errors (one-enum-plus-aliases, same pattern as DirectoryError et al.)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HiddenServiceError {
    Generic(String),
    AddressError(String),
    SignatureInvalid(String),
    DescriptorExpired(String),
    DescriptorLifetimeTooLong(String),
    ClientNotAuthorized(String),
    IntroduceReplayed(String),
    StoreFull(String),
    SourceQuotaExceeded(String),
}
impl fmt::Display for HiddenServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HiddenServiceError::Generic(s)
            | HiddenServiceError::AddressError(s)
            | HiddenServiceError::SignatureInvalid(s)
            | HiddenServiceError::DescriptorExpired(s)
            | HiddenServiceError::DescriptorLifetimeTooLong(s)
            | HiddenServiceError::ClientNotAuthorized(s)
            | HiddenServiceError::IntroduceReplayed(s)
            | HiddenServiceError::StoreFull(s)
            | HiddenServiceError::SourceQuotaExceeded(s) => write!(f, "{s}"),
        }
    }
}
impl std::error::Error for HiddenServiceError {}
fn err(msg: impl Into<String>) -> HiddenServiceError {
    HiddenServiceError::Generic(msg.into())
}

/// An `x.allium` address was malformed or failed its checksum.
pub type AddressError = HiddenServiceError;
/// A descriptor's or a control message's signature did not verify.
pub type SignatureInvalid = HiddenServiceError;
/// A descriptor was outside its validity window when used.
pub type DescriptorExpired = HiddenServiceError;
/// A descriptor's validity span exceeds this directory's accepted maximum.
pub type DescriptorLifetimeTooLong = HiddenServiceError;
/// A descriptor restricts its intro points and this client is not one of them.
pub type ClientNotAuthorized = HiddenServiceError;
/// An INTRODUCE envelope has already been opened once before.
pub type IntroduceReplayed = HiddenServiceError;

// ---------------------------------------------------------------------------
// Base32 (RFC 4648), hand-rolled: no new crate for one address codec.
// ---------------------------------------------------------------------------

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_encode_nopad_lower(data: &[u8]) -> String {
    let mut out = String::new();
    let mut bits = 0u32;
    let mut acc: u32 = 0;
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((acc >> bits) & 0x1F) as usize;
            out.push((BASE32_ALPHABET[idx] as char).to_ascii_lowercase());
        }
    }
    if bits > 0 {
        let idx = ((acc << (5 - bits)) & 0x1F) as usize;
        out.push((BASE32_ALPHABET[idx] as char).to_ascii_lowercase());
    }
    out
}

fn base32_decode_nopad(text: &str) -> Result<Vec<u8>, HiddenServiceError> {
    let mut bits = 0u32;
    let mut acc: u32 = 0;
    let mut out = Vec::new();
    for c in text.chars() {
        let upper = c.to_ascii_uppercase();
        let val = BASE32_ALPHABET
            .iter()
            .position(|&x| x as char == upper)
            .ok_or_else(|| err(format!("not valid base32: invalid character {c:?}")))?;
        acc = (acc << 5) | val as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    // Any leftover bits must be zero padding, matching Python's
    // base64.b32decode's own strictness about trailing garbage bits.
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return Err(err("not valid base32: non-zero padding bits"));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Addressing
// ---------------------------------------------------------------------------

fn address_checksum(identity_public: &[u8; ED25519_KEY_LEN]) -> [u8; 2] {
    let mut buf = b"allium-hs-checksum-v1".to_vec();
    buf.extend_from_slice(identity_public);
    buf.push(ADDRESS_VERSION);
    let digest = crate::hashutil::sha256(&buf);
    [digest[0], digest[1]]
}

/// Encode a 32-byte Ed25519 public key as an `x.allium` address.
pub fn encode_address(identity_public: &[u8; ED25519_KEY_LEN]) -> String {
    let checksum = address_checksum(identity_public);
    let mut payload = identity_public.to_vec();
    payload.extend_from_slice(&checksum);
    payload.push(ADDRESS_VERSION);
    format!("{}{}", base32_encode_nopad_lower(&payload), ADDRESS_SUFFIX)
}

/// Decode an `x.allium` address back to its 32-byte identity key.
pub fn decode_address(address: &str) -> Result<[u8; ED25519_KEY_LEN], HiddenServiceError> {
    let text = address.trim().to_lowercase();
    if !text.ends_with(ADDRESS_SUFFIX) {
        return Err(err(format!("address must end with {ADDRESS_SUFFIX:?}: {address:?}")));
    }
    let label = &text[..text.len() - ADDRESS_SUFFIX.len()];
    if label.is_empty() {
        return Err(err("empty address label"));
    }
    let payload = base32_decode_nopad(label)?;
    let expected_len = ED25519_KEY_LEN + 2 + 1;
    if payload.len() != expected_len {
        return Err(err(format!("decoded address is {} bytes, expected {expected_len}", payload.len())));
    }
    let mut identity_public = [0u8; ED25519_KEY_LEN];
    identity_public.copy_from_slice(&payload[..ED25519_KEY_LEN]);
    let checksum = [payload[ED25519_KEY_LEN], payload[ED25519_KEY_LEN + 1]];
    let version = payload[ED25519_KEY_LEN + 2];
    if version != ADDRESS_VERSION {
        return Err(err(format!("unsupported address version {version}")));
    }
    if checksum != address_checksum(&identity_public) {
        return Err(err("bad checksum -- mistyped or corrupted address?"));
    }
    Ok(identity_public)
}

// ---------------------------------------------------------------------------
// Directory index blinding
// ---------------------------------------------------------------------------

/// Current time-period number for [`hs_directory_index`].
pub fn hs_directory_period(now: Option<f64>, period: f64) -> i64 {
    let t = now.unwrap_or_else(now_unix);
    (t / period).floor() as i64
}

fn now_unix() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// The blinded lookup key a client/service uses to address the directory
/// for `identity_public`, instead of the real identity key. See the module
/// docs / Python's docstring for the rationale.
pub fn hs_directory_index(identity_public: &[u8; ED25519_KEY_LEN], period: Option<i64>) -> [u8; 32] {
    let p = period.unwrap_or_else(|| hs_directory_period(None, HS_DIRECTORY_INDEX_PERIOD));
    let data = p.to_be_bytes();
    let digest = crate::blake2::blake2b_keyed(identity_public, &data, 32, b"allium-hs-diridx");
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

// ---------------------------------------------------------------------------
// Crypto injection (see module docs)
// ---------------------------------------------------------------------------

pub type X25519GenFn = Box<dyn Fn() -> [u8; X25519_KEY_LEN] + Send + Sync>;
pub type X25519PublicFn = Box<dyn Fn(&[u8; X25519_KEY_LEN]) -> [u8; X25519_KEY_LEN] + Send + Sync>;
pub type X25519DhFn =
    Box<dyn Fn(&[u8; X25519_KEY_LEN], &[u8; X25519_KEY_LEN]) -> Result<[u8; X25519_KEY_LEN], HiddenServiceError> + Send + Sync>;
pub type Ed25519SignFn = Box<dyn Fn(&[u8; ED25519_KEY_LEN], &[u8]) -> [u8; ED25519_SIG_LEN] + Send + Sync>;
pub type Ed25519VerifyFn = Box<dyn Fn(&[u8; ED25519_KEY_LEN], &[u8], &[u8; ED25519_SIG_LEN]) -> bool + Send + Sync>;
pub type Ed25519PublicOfFn = Box<dyn Fn(&[u8; ED25519_KEY_LEN]) -> [u8; ED25519_KEY_LEN] + Send + Sync>;

/// Every X25519/Ed25519 primitive this module needs, injected as closures.
/// Construct with [`HsOps::real`] for production use (real-crate-backed,
/// unverified in this sandbox -- see module docs).
pub struct HsOps {
    pub x25519_generate: X25519GenFn,
    pub x25519_public: X25519PublicFn,
    pub x25519_dh: X25519DhFn,
    pub ed25519_sign: Ed25519SignFn,
    pub ed25519_verify: Ed25519VerifyFn,
    pub ed25519_public_of: Ed25519PublicOfFn,
}

impl HsOps {
    pub fn real() -> HsOps {
        HsOps {
            x25519_generate: Box::new(real_x25519_generate),
            x25519_public: Box::new(real_x25519_public),
            x25519_dh: Box::new(real_x25519_dh),
            ed25519_sign: Box::new(real_ed25519_sign),
            ed25519_verify: Box::new(real_ed25519_verify),
            ed25519_public_of: Box::new(real_ed25519_public_of),
        }
    }
}

fn real_x25519_generate() -> [u8; X25519_KEY_LEN] {
    use x25519_dalek::StaticSecret;
    StaticSecret::random_from_rng(rand_core::OsRng).to_bytes()
}
fn real_x25519_public(private: &[u8; X25519_KEY_LEN]) -> [u8; X25519_KEY_LEN] {
    use x25519_dalek::{PublicKey, StaticSecret};
    PublicKey::from(&StaticSecret::from(*private)).to_bytes()
}
fn real_x25519_dh(private: &[u8; X25519_KEY_LEN], peer_public: &[u8; X25519_KEY_LEN]) -> Result<[u8; X25519_KEY_LEN], HiddenServiceError> {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(*private);
    let shared = secret.diffie_hellman(&PublicKey::from(*peer_public));
    if !shared.was_contributory() {
        return Err(err("peer public key is unusable (low-order point)"));
    }
    Ok(*shared.as_bytes())
}
fn real_ed25519_sign(private: &[u8; ED25519_KEY_LEN], message: &[u8]) -> [u8; ED25519_SIG_LEN] {
    use ed25519_dalek::{Signer, SigningKey};
    SigningKey::from_bytes(private).sign(message).to_bytes()
}
fn real_ed25519_verify(public: &[u8; ED25519_KEY_LEN], message: &[u8], sig: &[u8; ED25519_SIG_LEN]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let key = match VerifyingKey::from_bytes(public) {
        Ok(k) => k,
        Err(_) => return false,
    };
    key.verify(message, &Signature::from_bytes(sig)).is_ok()
}
fn real_ed25519_public_of(private: &[u8; ED25519_KEY_LEN]) -> [u8; ED25519_KEY_LEN] {
    use ed25519_dalek::SigningKey;
    SigningKey::from_bytes(private).verifying_key().to_bytes()
}

fn hs_hkdf(shared_secret: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    crate::hashutil::hkdf_sha256(shared_secret, salt, info, length)
}

fn key32(v: Vec<u8>) -> Result<[u8; 32], HiddenServiceError> {
    if v.len() != 32 {
        return Err(err(format!("expected a 32-byte key, got {}", v.len())));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

// ---------------------------------------------------------------------------
// File I/O helpers (private dir / atomic secret file, Unix only)
// ---------------------------------------------------------------------------

fn display_path(path: &str) -> String {
    if let Some(home) = std::env::var_os("HOME").and_then(|h| h.into_string().ok()) {
        if !home.is_empty() {
            if path == home {
                return "~".to_string();
            }
            let prefix = format!("{home}/");
            if let Some(rest) = path.strip_prefix(&prefix) {
                return format!("~/{rest}");
            }
        }
    }
    path.to_string()
}

#[cfg(unix)]
fn ensure_private_dir(path: &str) -> Result<(), HiddenServiceError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path).map_err(|e| err(format!("could not create {}: {e}", display_path(path))))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| err(format!("could not restrict {} to permissions 0700: {e}", display_path(path))))
}
#[cfg(not(unix))]
fn ensure_private_dir(path: &str) -> Result<(), HiddenServiceError> {
    std::fs::create_dir_all(path).map_err(|e| err(format!("could not create {}: {e}", display_path(path))))
}

#[cfg(unix)]
fn write_new_secret_file(path: &str, data: &[u8]) -> Result<(), HiddenServiceError> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| err(format!("could not create {}: {e}", display_path(path))))?;
    if let Err(e) = f.write_all(data) {
        let _ = std::fs::remove_file(path);
        return Err(err(format!("could not create {}: {e}", display_path(path))));
    }
    Ok(())
}
#[cfg(not(unix))]
fn write_new_secret_file(path: &str, data: &[u8]) -> Result<(), HiddenServiceError> {
    use std::fs::OpenOptions;
    use std::io::Write;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| err(format!("could not create {}: {e}", display_path(path))))?;
    f.write_all(data).map_err(|e| err(format!("could not create {}: {e}", display_path(path))))
}

fn random_bytes(n: usize) -> Result<Vec<u8>, HiddenServiceError> {
    let mut buf = vec![0u8; n];
    crate::osrand::os_random(&mut buf).map_err(|e| err(e.to_string()))?;
    Ok(buf)
}

const INTRO_KEY_SUFFIX: &str = ".intro_key";
// `>d32s`: big-endian f64 created-at + 32-byte seed.
const INTRO_KEY_FILE_LEN: usize = 8 + 32;

fn load_or_create_intro_key(path: &str, parent: Option<&str>) -> Result<(Vec<u8>, f64), HiddenServiceError> {
    if std::path::Path::new(path).exists() {
        if let Some(p) = parent {
            ensure_private_dir(p)?;
        }
        let data = std::fs::read(path).map_err(|e| err(format!("could not read {}: {e}", display_path(path))))?;
        if data.len() != INTRO_KEY_FILE_LEN {
            return Err(err(format!(
                "{} is not a valid introduction key file; delete it and rerun (a fresh one, and a fresh descriptor, will be generated)",
                display_path(path)
            )));
        }
        let created_at = f64::from_be_bytes(data[..8].try_into().unwrap());
        let seed = data[8..40].to_vec();
        return Ok((seed, created_at));
    }
    let seed = random_bytes(X25519_KEY_LEN)?;
    let created_at = now_unix();
    if let Some(p) = parent {
        ensure_private_dir(p)?;
    }
    let mut buf = created_at.to_be_bytes().to_vec();
    buf.extend_from_slice(&seed);
    write_new_secret_file(path, &buf)?;
    Ok((seed, created_at))
}

fn persist_intro_key(path: &str, created_at: f64, seed: &[u8]) -> Result<(), HiddenServiceError> {
    let directory = std::path::Path::new(path).parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|| ".".to_string());
    let tmp_path = format!("{directory}/.intro_key.{}.tmp", u64::from_be_bytes(random_bytes(8)?.try_into().unwrap()));
    let mut buf = created_at.to_be_bytes().to_vec();
    buf.extend_from_slice(seed);
    write_new_secret_file(&tmp_path, &buf)?;
    std::fs::rename(&tmp_path, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        err(format!("could not persist {}: {e}", display_path(path)))
    })
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// A hidden service's long-term keys: an Ed25519 identity seed, plus a
/// separate, independently generated and periodically rotated X25519
/// "introduction encryption" keypair. See the module/Python docstring for
/// the full security rationale.
pub struct ServiceIdentity {
    seed: [u8; ED25519_KEY_LEN],
    intro_seed: [u8; X25519_KEY_LEN],
    intro_created_at: f64,
    intro_previous_seed: Option<[u8; X25519_KEY_LEN]>,
    intro_previous_deadline: Option<f64>,
    intro_path: Option<String>,
    rotation_period: f64,
    grace_period: f64,
    clock: Arc<dyn Fn() -> f64 + Send + Sync>,
    introduce_replay: HandshakeReplayGuard,
}

impl Drop for ServiceIdentity {
    /// Security audit fix (2026-09-26): `seed` is this hidden service's
    /// long-term Ed25519 identity seed, and `intro_seed`/`intro_previous_seed`
    /// are its introduction-point X25519 seeds (the latter kept around for
    /// `grace_period` after rotation) -- all held for the service's entire
    /// lifetime, wipe them on drop instead of leaving them sitting in freed
    /// memory.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.seed.zeroize();
        self.intro_seed.zeroize();
        if let Some(prev) = self.intro_previous_seed.as_mut() {
            prev.zeroize();
        }
    }
}

pub struct ServiceIdentityOptions {
    pub introduction_seed: Option<[u8; X25519_KEY_LEN]>,
    pub introduction_created_at: Option<f64>,
    pub rotation_period: f64,
    pub grace_period: f64,
    pub introduce_replay_entries: usize,
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

impl ServiceIdentity {
    pub fn new(seed: [u8; ED25519_KEY_LEN], options: ServiceIdentityOptions) -> Result<ServiceIdentity, HiddenServiceError> {
        let clock: Arc<dyn Fn() -> f64 + Send + Sync> = options.clock.unwrap_or_else(|| Arc::new(now_unix));
        let intro_seed = match options.introduction_seed {
            Some(seed) => seed,
            None => key32(random_bytes(X25519_KEY_LEN)?).unwrap(),
        };
        let intro_created_at = options.introduction_created_at.unwrap_or_else(|| clock());
        let clock_for_guard = clock.clone();
        let introduce_replay = HandshakeReplayGuard::new(
            options.introduce_replay_entries,
            Some(options.rotation_period + options.grace_period),
            Box::new(move || clock_for_guard()),
        )
        .map_err(|e| err(e.to_string()))?;
        Ok(ServiceIdentity {
            seed,
            intro_seed,
            intro_created_at,
            intro_previous_seed: None,
            intro_previous_deadline: None,
            intro_path: None,
            rotation_period: options.rotation_period,
            grace_period: options.grace_period,
            clock,
            introduce_replay,
        })
    }

    /// Return a fresh, randomly generated identity.
    pub fn generate() -> Result<ServiceIdentity, HiddenServiceError> {
        let seed = key32(random_bytes(ED25519_KEY_LEN)?).unwrap();
        ServiceIdentity::new(seed, ServiceIdentityOptions::default())
    }

    /// Load a persisted 32-byte identity seed from `path` (generating one on
    /// first run), plus a separate persisted introduction-encryption key at
    /// `path + ".intro_key"`. See module docs.
    pub fn load_or_create(path: &str) -> Result<ServiceIdentity, HiddenServiceError> {
        let parent = std::path::Path::new(path).parent().map(|p| p.to_string_lossy().to_string()).filter(|p| !p.is_empty());
        let seed = if std::path::Path::new(path).exists() {
            if let Some(p) = &parent {
                ensure_private_dir(p)?;
            }
            let data = std::fs::read(path).map_err(|e| err(format!("could not read {}: {e}", display_path(path))))?;
            key32(data).map_err(|_| err(format!("{} is not a 32-byte key; delete it and rerun", display_path(path))))?
        } else {
            let seed = key32(random_bytes(ED25519_KEY_LEN)?).unwrap();
            if let Some(p) = &parent {
                ensure_private_dir(p)?;
            }
            write_new_secret_file(path, &seed)?;
            seed
        };
        let intro_key_path = format!("{path}{INTRO_KEY_SUFFIX}");
        let (intro_seed, intro_created_at) = load_or_create_intro_key(&intro_key_path, parent.as_deref())?;
        let mut identity = ServiceIdentity::new(
            seed,
            ServiceIdentityOptions {
                introduction_seed: Some(key32(intro_seed)?),
                introduction_created_at: Some(intro_created_at),
                ..ServiceIdentityOptions::default()
            },
        )?;
        identity.intro_path = Some(intro_key_path);
        Ok(identity)
    }

    pub fn seed(&self) -> &[u8; ED25519_KEY_LEN] {
        &self.seed
    }

    pub fn identity_public(&self, ops: &HsOps) -> [u8; ED25519_KEY_LEN] {
        (ops.ed25519_public_of)(&self.seed)
    }

    pub fn address(&self, ops: &HsOps) -> String {
        encode_address(&self.identity_public(ops))
    }

    pub fn sign(&self, ops: &HsOps, data: &[u8]) -> [u8; ED25519_SIG_LEN] {
        (ops.ed25519_sign)(&self.seed, data)
    }

    /// Derive this service's per-introduction-point Ed25519 seed.
    pub fn intro_auth_seed(&self, relay_identity: &[u8; ED25519_KEY_LEN]) -> [u8; ED25519_KEY_LEN] {
        let out = hs_hkdf(&self.seed, b"allium-hs-intro-auth-v1", relay_identity, 32);
        key32(out).unwrap()
    }

    /// `(auth_seed, auth_public)` for [`ServiceIdentity::intro_auth_seed`].
    pub fn intro_auth_keypair(&self, ops: &HsOps, relay_identity: &[u8; ED25519_KEY_LEN]) -> ([u8; ED25519_KEY_LEN], [u8; ED25519_KEY_LEN]) {
        let seed = self.intro_auth_seed(relay_identity);
        let public = (ops.ed25519_public_of)(&seed);
        (seed, public)
    }

    /// Security fix (2026-09-26): this used to be `fn maybe_rotate(&mut
    /// self)` with no return value at all, so `let _ =
    /// persist_intro_key(...)` genuinely discarded a persist failure --
    /// directly contradicting its own comment, which claimed the error
    /// "just returns" rather than being silently ignored. It didn't: with
    /// no `Result` in the signature there was nowhere for it to go. A
    /// failed persist after a real in-memory rotation now propagates, the
    /// way Client's own copy of this same method already does and the
    /// original comment always claimed this one did too.
    fn maybe_rotate(&mut self) -> Result<(), HiddenServiceError> {
        let now = (self.clock)();
        if now - self.intro_created_at > self.rotation_period {
            // Security audit fix (2026-09-26): both reassignments below
            // used to just drop whatever `intro_previous_seed` held --
            // this line overwrites it with the seed that was just
            // superseded (dropping any still-live grace-period seed from
            // an earlier rotation this one raced ahead of), and the grace-
            // expiry branch further down drops it once its deadline
            // passes. Either way this is a live X25519 introduction seed
            // being discarded during ordinary operation, not at this
            // struct's final drop -- `Drop for ServiceIdentity` only
            // protects whatever is still resident *then*, so zeroize the
            // outgoing value explicitly at the point it's actually
            // replaced.
            use zeroize::Zeroize;
            if let Some(mut expiring) = self.intro_previous_seed.take() {
                expiring.zeroize();
            }
            self.intro_previous_seed = Some(self.intro_seed);
            self.intro_previous_deadline = Some(self.intro_created_at + self.rotation_period + self.grace_period);
            self.intro_seed = key32(random_bytes(X25519_KEY_LEN)?).unwrap();
            self.intro_created_at = now;
            if let Some(path) = &self.intro_path {
                // Best-effort persist -- matches Python's own behavior of
                // letting an I/O error here propagate (there is no good way
                // to "undo" the in-memory rotation, so this call just
                // returns the error rather than silently ignoring it).
                persist_intro_key(path, self.intro_created_at, &self.intro_seed)?;
            }
        }
        if let Some(deadline) = self.intro_previous_deadline {
            if now > deadline {
                use zeroize::Zeroize;
                if let Some(mut expiring) = self.intro_previous_seed.take() {
                    expiring.zeroize();
                }
                self.intro_previous_deadline = None;
            }
        }
        Ok(())
    }

    /// # Errors
    /// Propagates [`HiddenServiceError::Generic`] if a rotation was due
    /// and persisting the new key failed.
    pub fn encryption_public(&mut self, ops: &HsOps) -> Result<[u8; X25519_KEY_LEN], HiddenServiceError> {
        self.maybe_rotate()?;
        Ok((ops.x25519_public)(&self.intro_seed))
    }

    /// Open an INTRODUCE1 envelope sealed with [`seal_introduce`].
    ///
    /// # Errors
    /// Propagates [`HiddenServiceError::Generic`] if a rotation was due
    /// and persisting the new key failed, in addition to the introduction
    /// -specific errors described below.
    pub fn open_introduce(&mut self, ops: &HsOps, client_ephemeral_public: &[u8; X25519_KEY_LEN], sealed: &[u8]) -> Result<Vec<u8>, HiddenServiceError> {
        self.maybe_rotate()?;
        let mut candidates = vec![self.intro_seed];
        if let Some(prev) = self.intro_previous_seed {
            candidates.push(prev);
        }
        let mut last_error: Option<HiddenServiceError> = None;
        for seed in candidates {
            let public = (ops.x25519_public)(&seed);
            let shared = match (ops.x25519_dh)(&seed, client_ephemeral_public) {
                Ok(s) => s,
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };
            match open_sealed(&shared, &public, sealed) {
                Ok(plaintext) => {
                    let key = ServiceIdentity::introduce_replay_key(client_ephemeral_public, sealed);
                    if !self.introduce_replay.accept(key) {
                        return Err(HiddenServiceError::IntroduceReplayed(
                            "INTRODUCE envelope has already been opened; refusing to build a second circuit for a replayed introduction".to_string(),
                        ));
                    }
                    return Ok(plaintext);
                }
                Err(e) => last_error = Some(e),
            }
        }
        Err(last_error.unwrap_or_else(|| err("no introduction key available")))
    }

    fn introduce_replay_key(client_ephemeral_public: &[u8; X25519_KEY_LEN], sealed: &[u8]) -> Vec<u8> {
        let mut data = client_ephemeral_public.to_vec();
        data.extend_from_slice(sealed);
        crate::blake2::blake2b(&data, 16, b"allium-intro-rp")
    }
}

// ---------------------------------------------------------------------------
// Sealing (INTRODUCE1's envelope)
// ---------------------------------------------------------------------------

fn seal_with_shared(shared_secret: &[u8], associated_data: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HiddenServiceError> {
    let key = key32(hs_hkdf(shared_secret, b"allium-hs-introduce-v1", b"introduce-key", 32))?;
    let mut aead = crate::crypto::new_aead("chacha20-poly1305", key, None).map_err(|e| err(e.to_string()))?;
    aead.seal(plaintext, associated_data).map_err(|e| err(e.to_string()))
}

fn open_sealed(shared_secret: &[u8], associated_data: &[u8], sealed: &[u8]) -> Result<Vec<u8>, HiddenServiceError> {
    let key = key32(hs_hkdf(shared_secret, b"allium-hs-introduce-v1", b"introduce-key", 32))?;
    let aead = crate::crypto::new_aead("chacha20-poly1305", key, None).map_err(|e| err(e.to_string()))?;
    aead.open(sealed, associated_data)
        .map_err(|e| HiddenServiceError::SignatureInvalid(format!("introduce envelope did not authenticate: {e}")))
}

/// Seal `plaintext` so only the holder of the matching X25519 private key
/// can read it.
pub fn seal_introduce(
    ops: &HsOps,
    service_encryption_public: &[u8; X25519_KEY_LEN],
    client_ephemeral_private: &[u8; X25519_KEY_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, HiddenServiceError> {
    let shared = (ops.x25519_dh)(client_ephemeral_private, service_encryption_public)?;
    seal_with_shared(&shared, service_encryption_public, plaintext)
}

/// Inverse of [`seal_introduce`], given the raw X25519 private key directly.
pub fn open_introduce_raw(
    ops: &HsOps,
    service_encryption_private: &[u8; X25519_KEY_LEN],
    client_ephemeral_public: &[u8; X25519_KEY_LEN],
    sealed: &[u8],
) -> Result<Vec<u8>, HiddenServiceError> {
    let shared = (ops.x25519_dh)(service_encryption_private, client_ephemeral_public)?;
    let service_encryption_public = (ops.x25519_public)(service_encryption_private);
    open_sealed(&shared, &service_encryption_public, sealed)
}

// ---------------------------------------------------------------------------
// Post-rendezvous session crypto
// ---------------------------------------------------------------------------

/// Derive `(key_client_to_service, key_service_to_client)` for a rendezvous
/// session.
pub fn derive_session_keys(shared_secret: &[u8]) -> Result<([u8; 32], [u8; 32]), HiddenServiceError> {
    let key_c2s = key32(hs_hkdf(shared_secret, b"allium-hs-session-v1", b"client-to-service", 32))?;
    let key_s2c = key32(hs_hkdf(shared_secret, b"allium-hs-session-v1", b"service-to-client", 32))?;
    Ok((key_c2s, key_s2c))
}

/// AEAD-sealed duplex session between a client and a service.
pub struct HsSession {
    send: crate::crypto::SaltAead,
    recv: crate::crypto::SaltAead,
}

impl HsSession {
    pub fn new(key_c2s: [u8; 32], key_s2c: [u8; 32], cookie: &[u8], is_service: bool) -> Result<HsSession, HiddenServiceError> {
        let (send_key, recv_key) = if is_service { (key_s2c, key_c2s) } else { (key_c2s, key_s2c) };
        let mut send_salt = cookie.to_vec();
        send_salt.extend_from_slice(if is_service { b"s2c" } else { b"c2s" });
        let nonce_source = crate::crypto::NonceCounter::with_defaults(crate::crypto::Session::Bytes(&send_salt))
            .map_err(|e| err(e.to_string()))?;
        let send = crate::crypto::new_aead("chacha20-poly1305", send_key, Some(nonce_source)).map_err(|e| err(e.to_string()))?;
        let recv = crate::crypto::new_aead("chacha20-poly1305", recv_key, None).map_err(|e| err(e.to_string()))?;
        Ok(HsSession { send, recv })
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, HiddenServiceError> {
        self.send.seal(plaintext, b"").map_err(|e| err(e.to_string()))
    }

    pub fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, HiddenServiceError> {
        self.recv.open(sealed, b"").map_err(|e| err(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Descriptor types
// ---------------------------------------------------------------------------

fn client_id_hint(client_public: &[u8; X25519_KEY_LEN]) -> [u8; CLIENT_ID_HINT_LEN] {
    let mut data = b"allium-hs-clientauth-hint-v1".to_vec();
    data.extend_from_slice(client_public);
    let digest = crate::blake2::blake2b(&data, CLIENT_ID_HINT_LEN, b"");
    let mut out = [0u8; CLIENT_ID_HINT_LEN];
    out.copy_from_slice(&digest);
    out
}

/// One relay a service has registered with as an introduction point.
///
/// This is the type `dirwire.rs`'s wire encode/decode now imports directly
/// (its own former local stand-in, field-for-field identical, is gone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntroPoint {
    pub relay_identity: Vec<u8>,
    pub host: String,
    pub port: u16,
    pub auth_public: Vec<u8>,
}

fn encode_intro_points(intro_points: &[IntroPoint]) -> Vec<u8> {
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

fn decode_intro_points(data: &[u8]) -> Result<Vec<IntroPoint>, HiddenServiceError> {
    if data.len() < 2 {
        return Err(err("intro point list truncated before its count"));
    }
    let count = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut offset = 2usize;
    let mut points = Vec::with_capacity(count);
    for _ in 0..count {
        if data.len() < offset + ED25519_KEY_LEN + 2 {
            return Err(err("intro point list truncated"));
        }
        let relay_identity = data[offset..offset + ED25519_KEY_LEN].to_vec();
        offset += ED25519_KEY_LEN;
        let host_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if data.len() < offset + host_len + 2 {
            return Err(err("intro point list truncated inside a host"));
        }
        let host = std::str::from_utf8(&data[offset..offset + host_len])
            .map_err(|_| err("intro point host is not valid UTF-8"))?
            .to_string();
        offset += host_len;
        let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        if data.len() < offset + ED25519_KEY_LEN {
            return Err(err("intro point list truncated before its auth key"));
        }
        let auth_public = data[offset..offset + ED25519_KEY_LEN].to_vec();
        offset += ED25519_KEY_LEN;
        points.push(IntroPoint { relay_identity, host, port, auth_public });
    }
    Ok(points)
}

/// One authorized client's wrapped copy of a descriptor's decryption key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAuthEntry {
    pub client_id_hint: Vec<u8>,
    pub wrapped_key: Vec<u8>,
}

/// A service's self-signed record: who it is and how to reach it.
#[derive(Debug, Clone, PartialEq)]
pub struct HiddenServiceDescriptor {
    pub identity_public: Vec<u8>,
    pub encryption_public: Vec<u8>,
    pub intro_points: Vec<IntroPoint>,
    pub not_before: f64,
    pub not_after: f64,
    pub signature: Vec<u8>,
    pub encrypted_intro_points: Vec<u8>,
    pub auth_ephemeral_public: Vec<u8>,
    pub client_auth: Vec<ClientAuthEntry>,
    /// Mirrors `Client::hiddenservice::HiddenServiceDescriptor::hs_handshake_v2`,
    /// kept in lockstep with the Client crate's copy so a descriptor a
    /// service signs there and the Authority verifies here compute
    /// byte-identical `signing_payload()`s.
    /// The Authority never interprets this flag itself (it only stores and
    /// re-serves descriptors); it exists here purely so the signature
    /// still checks out.
    pub hs_handshake_v2: bool,
}

pub struct CreateHsDescriptorOptions {
    pub lifetime: f64,
    pub now: Option<f64>,
    pub client_auth_public_keys: Vec<[u8; X25519_KEY_LEN]>,
}
impl Default for CreateHsDescriptorOptions {
    fn default() -> Self {
        CreateHsDescriptorOptions { lifetime: DEFAULT_HS_DESCRIPTOR_LIFETIME, now: None, client_auth_public_keys: Vec::new() }
    }
}

impl HiddenServiceDescriptor {
    /// The exact bytes the signature covers (everything but the signature).
    pub fn signing_payload(&self) -> Vec<u8> {
        let v2_byte: u8 = if self.hs_handshake_v2 { 1 } else { 0 };
        if !self.client_auth.is_empty() {
            let mut out = b"allium-hs-descriptor-v1-auth".to_vec();
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
        let mut out = b"allium-hs-descriptor-v1".to_vec();
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

    pub fn address(&self) -> Result<String, HiddenServiceError> {
        Ok(encode_address(&key32(self.identity_public.clone())?))
    }

    pub fn is_valid_at(&self, now: f64) -> bool {
        self.not_before <= now && now <= self.not_after
    }

    /// Check the self-signature.
    pub fn verify(&self, ops: &HsOps) -> Result<(), HiddenServiceError> {
        let identity_public =
            key32(self.identity_public.clone()).map_err(|_| HiddenServiceError::SignatureInvalid(format!("identity key must be {ED25519_KEY_LEN} bytes")))?;
        if self.encryption_public.len() != X25519_KEY_LEN {
            return Err(HiddenServiceError::SignatureInvalid(format!("encryption key must be {X25519_KEY_LEN} bytes")));
        }
        if self.signature.len() != ED25519_SIG_LEN {
            return Err(HiddenServiceError::SignatureInvalid("hidden-service descriptor signature did not verify".to_string()));
        }
        let mut sig = [0u8; ED25519_SIG_LEN];
        sig.copy_from_slice(&self.signature);
        if !(ops.ed25519_verify)(&identity_public, &self.signing_payload(), &sig) {
            return Err(HiddenServiceError::SignatureInvalid("hidden-service descriptor signature did not verify".to_string()));
        }
        Ok(())
    }

    /// Mint and sign a descriptor from a service's identity.
    pub fn create(
        ops: &HsOps,
        identity: &ServiceIdentity,
        intro_points: &[IntroPoint],
        options: CreateHsDescriptorOptions,
    ) -> Result<HiddenServiceDescriptor, HiddenServiceError> {
        let now = options.now.unwrap_or_else(now_unix);
        let identity_public = identity.identity_public(ops).to_vec();

        if options.client_auth_public_keys.is_empty() {
            let mut unsigned = HiddenServiceDescriptor {
                identity_public,
                // encryption_public read once, via a throwaway mutable
                // borrow -- Python's `identity.encryption_public` is a
                // property that also mutates (rotation check), matched here
                // by taking `&ServiceIdentity` at the API boundary and doing
                // the interior read via a short-lived clone of the ops
                // borrow is not possible (identity is `&`, not `&mut`, per
                // this function's signature -- mirroring Python's `create`
                // classmethod, which never mutates its `identity` argument's
                // *visible* state even though the property does internally).
                // Since `&ServiceIdentity` here is immutable, rotation
                // cannot run from inside `create`; callers that need
                // rotation to have run should read `encryption_public`
                // themselves first. This is a minor, documented deviation
                // from Python (whose property mutates through a supposedly
                // read-only attribute access too, just less visibly).
                encryption_public: Vec::new(),
                intro_points: intro_points.to_vec(),
                not_before: now,
                not_after: now + options.lifetime,
                signature: Vec::new(),
                encrypted_intro_points: Vec::new(),
                auth_ephemeral_public: Vec::new(),
                client_auth: Vec::new(),
                hs_handshake_v2: true,
            };
            unsigned.encryption_public = identity_public_encryption(ops, identity)?;
            let signature = identity.sign(ops, &unsigned.signing_payload()).to_vec();
            unsigned.signature = signature;
            return Ok(unsigned);
        }

        let desc_key = crate::crypto::generate_key();
        let mut aead = crate::crypto::new_aead("chacha20-poly1305", desc_key, None).map_err(|e| err(e.to_string()))?;
        let identity_public_arr = key32(identity.identity_public(ops).to_vec())?;
        let encrypted_intro_points = aead.seal(&encode_intro_points(intro_points), &identity_public_arr).map_err(|e| err(e.to_string()))?;

        let ephemeral_private = (ops.x25519_generate)();
        let auth_ephemeral_public = (ops.x25519_public)(&ephemeral_private);

        let mut entries = Vec::new();
        for client_public in &options.client_auth_public_keys {
            let shared = (ops.x25519_dh)(&ephemeral_private, client_public)?;
            let wrap_key = key32(hs_hkdf(&shared, b"allium-hs-clientauth-v1", b"wrap-key", 32))?;
            let mut wrap_aead = crate::crypto::new_aead("chacha20-poly1305", wrap_key, None).map_err(|e| err(e.to_string()))?;
            let wrapped_key = wrap_aead.seal(&desc_key, &auth_ephemeral_public).map_err(|e| err(e.to_string()))?;
            entries.push(ClientAuthEntry { client_id_hint: client_id_hint(client_public).to_vec(), wrapped_key });
        }

        let mut unsigned = HiddenServiceDescriptor {
            identity_public,
            encryption_public: identity_public_encryption(ops, identity)?,
            intro_points: Vec::new(),
            not_before: now,
            not_after: now + options.lifetime,
            signature: Vec::new(),
            encrypted_intro_points,
            auth_ephemeral_public: auth_ephemeral_public.to_vec(),
            client_auth: entries,
            hs_handshake_v2: true,
        };
        let signature = identity.sign(ops, &unsigned.signing_payload()).to_vec();
        unsigned.signature = signature;
        Ok(unsigned)
    }

    /// This descriptor's introduction points, decrypting them first if the
    /// service restricts who may see them.
    pub fn intro_points_for(&self, ops: &HsOps, client_auth_private_key: Option<&[u8; X25519_KEY_LEN]>) -> Result<Vec<IntroPoint>, HiddenServiceError> {
        if self.client_auth.is_empty() {
            return Ok(self.intro_points.clone());
        }
        let priv_key = client_auth_private_key.ok_or_else(|| {
            let addr = self.address().unwrap_or_default();
            HiddenServiceError::ClientNotAuthorized(format!("{addr} only shares its introduction points with authorized clients -- pass a client-auth private key"))
        })?;
        let addr = self.address()?;
        let hint = client_id_hint(&(ops.x25519_public)(priv_key));
        let entry = self
            .client_auth
            .iter()
            .find(|e| e.client_id_hint.as_slice() == hint)
            .ok_or_else(|| HiddenServiceError::ClientNotAuthorized(format!("this client is not authorized for {addr}")))?;

        let auth_ephemeral_public = key32(self.auth_ephemeral_public.clone())?;
        let shared = (ops.x25519_dh)(priv_key, &auth_ephemeral_public)?;
        let wrap_key = key32(hs_hkdf(&shared, b"allium-hs-clientauth-v1", b"wrap-key", 32))?;
        let wrap_aead = crate::crypto::new_aead("chacha20-poly1305", wrap_key, None).map_err(|e| err(e.to_string()))?;
        let desc_key_vec = wrap_aead
            .open(&entry.wrapped_key, &self.auth_ephemeral_public)
            .map_err(|_| HiddenServiceError::ClientNotAuthorized(format!("this client is not authorized for {addr}")))?;
        let desc_key = key32(desc_key_vec)?;
        let aead = crate::crypto::new_aead("chacha20-poly1305", desc_key, None).map_err(|e| err(e.to_string()))?;
        let serialized = aead
            .open(&self.encrypted_intro_points, &self.identity_public)
            .map_err(|_| HiddenServiceError::ClientNotAuthorized(format!("{addr}'s descriptor did not decrypt cleanly -- corrupt or tampered")))?;
        decode_intro_points(&serialized)
    }
}

/// Read `identity.encryption_public` without needing `&mut` at the call
/// site above -- see `create`'s doc comment for why `create` itself takes
/// `&ServiceIdentity`. Clones the identity's rotation-relevant state just
/// long enough to run the same rotation check `encryption_public` would.
fn identity_public_encryption(ops: &HsOps, identity: &ServiceIdentity) -> Result<Vec<u8>, HiddenServiceError> {
    // No rotation persistence here (this never touches `intro_path`
    // mutation through a `&self`-only path) -- if `identity` is due for
    // rotation, the *public key used* still reflects its current
    // (pre-rotation) key, exactly as reading `identity.encryption_public`
    // without first calling `maybe_rotate()` would in a hypothetical
    // non-mutating Python property. Callers that need up-to-date rotation
    // should call `ServiceIdentity::encryption_public(&mut self, ops)`
    // themselves before `create`.
    Ok((ops.x25519_public)(&identity.intro_seed).to_vec())
}

pub fn load_or_create_client_auth_key(path: &str) -> Result<[u8; X25519_KEY_LEN], HiddenServiceError> {
    let parent = std::path::Path::new(path).parent().map(|p| p.to_string_lossy().to_string()).filter(|p| !p.is_empty());
    if std::path::Path::new(path).exists() {
        if let Some(p) = &parent {
            ensure_private_dir(p)?;
        }
        let data = std::fs::read(path).map_err(|e| err(format!("could not read {}: {e}", display_path(path))))?;
        return key32(data).map_err(|_| err(format!("{} is not a {X25519_KEY_LEN}-byte key; delete it and rerun", display_path(path))));
    }
    let key = key32(random_bytes(X25519_KEY_LEN)?).unwrap();
    if let Some(p) = &parent {
        ensure_private_dir(p)?;
    }
    write_new_secret_file(path, &key)?;
    Ok(key)
}

pub fn client_auth_public_key(ops: &HsOps, client_auth_private_key: &[u8; X25519_KEY_LEN]) -> [u8; X25519_KEY_LEN] {
    (ops.x25519_public)(client_auth_private_key)
}

// ---------------------------------------------------------------------------
// HiddenServiceDirectory
// ---------------------------------------------------------------------------

/// Hard cap on how many distinct identities a single [`HiddenServiceDirectory`]
/// will hold at once. Security fix: an identity key is free for an
/// attacker to generate, and (unlike the ordinary relay directory, which
/// vets each entry against a signed quorum vote before trusting it --
/// `crate::directory`'s `MAX_DESCRIPTOR_COUNT`/`compute_consensus`) any
/// self-signed hidden-service descriptor with a fresh identity was
/// accepted here without limit, so a flood of freshly-generated identities
/// could grow this store's memory without bound. Matches
/// `crate::directory`'s own `MAX_DESCRIPTOR_COUNT` in scale. Rotating an
/// *already-registered* identity is never blocked by this cap (see
/// `HiddenServiceDirectory::publish`), only genuinely new ones once the
/// store is full.
pub const MAX_HS_DESCRIPTORS: usize = 4096;

/// Most distinct identities one *source* may hold in the store at once.
/// `MAX_HS_DESCRIPTORS` bounds memory, but alone it lets one attacker use up
/// every slot: identity keys are free, so a flood from a single place fills
/// the store and every honest service is then refused until the flood's
/// descriptors expire. A per-source quota means filling the store takes at
/// least `MAX_HS_DESCRIPTORS / MAX_HS_DESCRIPTORS_PER_SOURCE` distinct sources.
///
/// What counts as a "source" is the caller's choice (the authority passes a
/// network prefix, not a raw address, so extra addresses on one subnet do
/// not buy extra quota). Sized so a real host can run a good number of
/// services; rotating an identity it already holds never counts again.
pub const MAX_HS_DESCRIPTORS_PER_SOURCE: usize = 64;

/// A verifying store of hidden-service descriptors, keyed by address.
pub struct HiddenServiceDirectory {
    clock: Arc<dyn Fn() -> f64 + Send + Sync>,
    max_descriptor_lifetime: Option<f64>,
    by_identity: HashMap<Vec<u8>, HiddenServiceDescriptor>,
    by_blinded_index: HashMap<[u8; 32], Vec<u8>>,
    /// identity -> the source that first published it (only for identities
    /// published with a source; see `publish_from`).
    source_of: HashMap<Vec<u8>, String>,
    /// source -> how many stored identities it published.
    per_source: HashMap<String, usize>,
    ops: HsOps,
}

impl HiddenServiceDirectory {
    pub fn new(clock: Option<Arc<dyn Fn() -> f64 + Send + Sync>>, max_descriptor_lifetime: Option<f64>, ops: HsOps) -> Result<HiddenServiceDirectory, HiddenServiceError> {
        if let Some(m) = max_descriptor_lifetime {
            if m <= 0.0 {
                return Err(err(format!("max_descriptor_lifetime must be positive (or None to disable), got {m}")));
            }
        }
        Ok(HiddenServiceDirectory {
            clock: clock.unwrap_or_else(|| Arc::new(now_unix)),
            max_descriptor_lifetime: max_descriptor_lifetime.or(Some(MAX_HS_DESCRIPTOR_LIFETIME)),
            by_identity: HashMap::new(),
            by_blinded_index: HashMap::new(),
            source_of: HashMap::new(),
            per_source: HashMap::new(),
            ops,
        })
    }

    /// Verify and store `descriptor`. Returns `true` if accepted, `false`
    /// if a newer one is already held.
    pub fn publish(&mut self, descriptor: HiddenServiceDescriptor) -> Result<bool, HiddenServiceError> {
        self.publish_from(descriptor, None)
    }

    /// [`Self::publish`], also charging a *new* identity to `source` (when
    /// given) against [`MAX_HS_DESCRIPTORS_PER_SOURCE`]. Re-publishing or
    /// rotating an identity already held is never charged or refused by the
    /// quota, and stays attributed to the source that first published it.
    pub fn publish_from(&mut self, descriptor: HiddenServiceDescriptor, source: Option<&str>) -> Result<bool, HiddenServiceError> {
        descriptor.verify(&self.ops)?;
        if let Some(max) = self.max_descriptor_lifetime {
            let lifetime = descriptor.not_after - descriptor.not_before;
            if lifetime > max {
                let addr = descriptor.address().unwrap_or_default();
                return Err(HiddenServiceError::DescriptorLifetimeTooLong(format!(
                    "descriptor for {addr} claims a {lifetime}s validity window, longer than the {max}s this directory accepts -- an unbounded lifetime would be effectively unrevokable since revocation here is expiry-driven"
                )));
            }
        }
        let now = (self.clock)();
        if !descriptor.is_valid_at(now) {
            let addr = descriptor.address().unwrap_or_default();
            return Err(HiddenServiceError::DescriptorExpired(format!("descriptor for {addr} is outside its validity window")));
        }
        if let Some(existing) = self.by_identity.get(&descriptor.identity_public) {
            if existing.not_before > descriptor.not_before {
                return Ok(false);
            }
        } else if let Some(src) = source.filter(|src| self.per_source.get(*src).copied().unwrap_or(0) >= MAX_HS_DESCRIPTORS_PER_SOURCE) {
            return Err(HiddenServiceError::SourceQuotaExceeded(format!(
                "source {src} already holds {MAX_HS_DESCRIPTORS_PER_SOURCE} hidden-service descriptors (the per-source maximum); refusing a new identity from it until one expires"
            )));
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
        let identity_arr = key32(identity_public.clone())?;
        let is_new_identity = !self.by_identity.contains_key(&identity_public);
        self.by_identity.insert(identity_public.clone(), descriptor);
        if is_new_identity {
            if let Some(src) = source {
                self.source_of.insert(identity_public.clone(), src.to_string());
                *self.per_source.entry(src.to_string()).or_insert(0) += 1;
            }
        }
        let period = hs_directory_period(Some(now), HS_DIRECTORY_INDEX_PERIOD);
        for p in [period, period + 1] {
            let index = hs_directory_index(&identity_arr, Some(p));
            self.by_blinded_index.insert(index, identity_public.clone());
        }
        Ok(true)
    }

    pub fn get(&self, identity_public: &[u8]) -> Option<&HiddenServiceDescriptor> {
        let d = self.by_identity.get(identity_public)?;
        if !d.is_valid_at((self.clock)()) {
            return None;
        }
        Some(d)
    }

    pub fn get_by_blinded_index(&self, index: &[u8; 32]) -> Option<&HiddenServiceDescriptor> {
        let identity_public = self.by_blinded_index.get(index)?;
        self.get(identity_public)
    }

    /// Drop expired descriptors, returning how many were removed.
    pub fn prune(&mut self) -> usize {
        let now = (self.clock)();
        let stale: Vec<Vec<u8>> = self.by_identity.iter().filter(|(_, d)| !d.is_valid_at(now)).map(|(k, _)| k.clone()).collect();
        for key in &stale {
            self.by_identity.remove(key);
            if let Some(src) = self.source_of.remove(key) {
                if let Some(n) = self.per_source.get_mut(&src) {
                    *n -= 1;
                    if *n == 0 {
                        self.per_source.remove(&src);
                    }
                }
            }
        }
        if !stale.is_empty() {
            self.by_blinded_index.retain(|_, identity_public| !stale.contains(identity_public));
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

// ---------------------------------------------------------------------------
// Version 3: blinded descriptors
// ---------------------------------------------------------------------------

/// What a directory authority holds for one hidden service in one time
/// period: a blinded public key `A'`, a validity window, and an opaque
/// ciphertext, signed by `A'`. It names no identity and its body is encrypted
/// under a key only someone who knows the service's address can derive, so
/// the authority can neither list services nor link a service's periods. See
/// the Client's `hsblind` module for the construction.
///
/// The authority does not (and cannot) check anything but the signature:
/// whether the ciphertext is a real descriptor is for the fetching client to
/// find out.
#[derive(Debug, Clone, PartialEq)]
pub struct BlindedDescriptor {
    pub blinded_public: [u8; 32],
    pub period: i64,
    pub not_before: f64,
    pub not_after: f64,
    pub salt: [u8; crate::dirwire::BLINDED_SALT_LEN],
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}

impl BlindedDescriptor {
    /// The exact bytes the signature covers. **Must stay byte-for-byte the
    /// same as the Client's `hsblind::BlindedDescriptor::signing_payload`**;
    /// a test pins both against a descriptor produced by an independent
    /// implementation.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(19 + 32 + 8 + 8 + 8 + self.salt.len() + 4 + self.ciphertext.len());
        out.extend_from_slice(b"allium-hs-desc3-sig");
        out.extend_from_slice(&self.blinded_public);
        out.extend_from_slice(&self.period.to_be_bytes());
        out.extend_from_slice(&self.not_before.to_be_bytes());
        out.extend_from_slice(&self.not_after.to_be_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn is_valid_at(&self, now: f64) -> bool {
        self.not_before <= now && now <= self.not_after
    }

    /// Check the signature against `blinded_public`.
    pub fn verify(&self, ops: &HsOps) -> Result<(), HiddenServiceError> {
        let bad = || HiddenServiceError::SignatureInvalid("hidden-service descriptor signature did not verify".to_string());
        if self.ciphertext.len() > crate::dirwire::MAX_BLINDED_CIPHERTEXT_LEN {
            return Err(HiddenServiceError::SignatureInvalid(format!(
                "ciphertext is {} bytes, max is {}",
                self.ciphertext.len(),
                crate::dirwire::MAX_BLINDED_CIPHERTEXT_LEN
            )));
        }
        let signature: [u8; ED25519_SIG_LEN] = self.signature.as_slice().try_into().map_err(|_| bad())?;
        if (ops.ed25519_verify)(&self.blinded_public, &self.signing_payload(), &signature) {
            Ok(())
        } else {
            Err(bad())
        }
    }
}

/// Total ciphertext bytes the store will hold. `MAX_HS_DESCRIPTORS` bounds the
/// count, but a sealed descriptor can be hundreds of kilobytes, so the count
/// alone would still allow gigabytes.
pub const MAX_HS_STORE_BYTES: usize = 128 * 1024 * 1024;
/// A service publishes its current and its next period's descriptor, so each
/// service uses two entries; the per-source allowance is doubled to keep the
/// same number of services per source as before.
pub const MAX_BLINDED_PER_SOURCE: usize = MAX_HS_DESCRIPTORS_PER_SOURCE * 2;
/// Longest validity window the blinded store accepts by default. A service
/// publishes a [`DEFAULT_HS_DESCRIPTOR_LIFETIME`] (one hour) descriptor every
/// 20 minutes, so twice that leaves honest services slack while an attacker
/// can no longer park a throwaway entry for a day: with eviction (below), an
/// entry that is not refreshed is gone within two hours.
pub const MAX_BLINDED_DESCRIPTOR_LIFETIME: f64 = DEFAULT_HS_DESCRIPTOR_LIFETIME * 2.0;
/// A republish counts as a *refresh* only if it comes at least this long after
/// the entry's previous counted publish. A real service republishes every 20
/// minutes; a burst of republishes does not make an entry look established.
pub const REFRESH_MIN_GAP_SECS: f64 = 600.0;
/// One in this many entry slots is kept for entries that have not been
/// refreshed yet (newcomers), so established entries can never crowd out every
/// new service.
pub const UNPROVEN_RESERVE_DIVISOR: usize = 4;

/// What the store remembers about an entry besides the descriptor itself.
#[derive(Debug, Clone, Copy)]
struct EntryMeta {
    /// When this key was first stored, by the store's clock. Lost on eviction.
    first_seen: f64,
    /// The last time a publish of this key was counted (see [`REFRESH_MIN_GAP_SECS`]).
    last_counted: f64,
    /// Counted republishes since `first_seen`. Zero means "not yet established".
    refreshes: u32,
}

impl EntryMeta {
    fn proven(&self) -> bool {
        self.refreshes > 0
    }
}

/// A verifying store of blinded descriptors, keyed by blinded public key.
///
/// Every limit the version 2 store had still applies (signature, lifetime,
/// "newer replaces older", a cap on entries, a per-source quota), plus a
/// check that the descriptor's period is the current one or an adjacent one,
/// and a cap on total bytes held.
///
/// **When the store is full a new descriptor evicts others instead of being
/// refused.** Refusing made a flood of throwaway identities a complete outage
/// for every new service for as long as the flood's entries lived. Who is
/// evicted is decided by *tenure*, not by publish time:
///
/// 1. expired entries first;
/// 2. then entries never refreshed (published once, or only in a burst),
///    oldest first -- but only while they number at least a quarter of the
///    entry cap ([`UNPROVEN_RESERVE_DIVISOR`]); below that the reserve is
///    protected and
/// 3. *established* entries (refreshed at least once, [`REFRESH_MIN_GAP_SECS`]
///    or more after the previous publish) go, **shortest tenure first**, so
///    the longest-standing services are the last to be pushed out;
/// 4. and if nothing established is left, never-refreshed entries again.
///
/// A flood of one-shot throwaway identities therefore only ever evicts other
/// throwaways and the newest newcomers: a service that has already been
/// republished stays. The price is that a brand-new service is contested
/// until its second publish (about 20 minutes later), and that a store full
/// of established entries still admits a newcomer by evicting the
/// shortest-tenured one. The per-source quota is still
/// available through [`Self::publish_from`], but the authority does not use
/// it for hidden-service publishes: those arrive over a circuit, so the
/// "source" it sees is the middle relay, not the publisher (see
/// `11.38-hs-quota-report.md`).
pub struct BlindedHsDirectory {
    clock: Arc<dyn Fn() -> f64 + Send + Sync>,
    max_descriptor_lifetime: f64,
    by_key: HashMap<[u8; 32], BlindedDescriptor>,
    /// blinded key -> the source that first published it (only keys published with a source).
    source_of: HashMap<[u8; 32], String>,
    per_source: HashMap<String, usize>,
    stored_bytes: usize,
    max_store_bytes: usize,
    max_entries: usize,
    /// Tenure of every held entry; always has exactly the keys of `by_key`.
    meta: HashMap<[u8; 32], EntryMeta>,
    ops: HsOps,
}

impl BlindedHsDirectory {
    pub fn new(clock: Option<Arc<dyn Fn() -> f64 + Send + Sync>>, max_descriptor_lifetime: Option<f64>, ops: HsOps) -> Result<BlindedHsDirectory, HiddenServiceError> {
        if let Some(m) = max_descriptor_lifetime {
            if m <= 0.0 {
                return Err(err(format!("max_descriptor_lifetime must be positive (or None for the default), got {m}")));
            }
        }
        Ok(BlindedHsDirectory {
            clock: clock.unwrap_or_else(|| Arc::new(now_unix)),
            max_descriptor_lifetime: max_descriptor_lifetime.unwrap_or(MAX_BLINDED_DESCRIPTOR_LIFETIME),
            by_key: HashMap::new(),
            source_of: HashMap::new(),
            per_source: HashMap::new(),
            stored_bytes: 0,
            max_store_bytes: MAX_HS_STORE_BYTES,
            max_entries: MAX_HS_DESCRIPTORS,
            meta: HashMap::new(),
            ops,
        })
    }

    /// Verify and store `descriptor`. Returns `true` if accepted, `false` if a
    /// newer one for the same blinded key is already held.
    pub fn publish(&mut self, descriptor: BlindedDescriptor) -> Result<bool, HiddenServiceError> {
        self.publish_from(descriptor, None)
    }

    /// [`Self::publish`], also charging a *new* blinded key to `source` (when
    /// given) against [`MAX_BLINDED_PER_SOURCE`]. Replacing a key already held
    /// is never charged or refused by the quota.
    pub fn publish_from(&mut self, descriptor: BlindedDescriptor, source: Option<&str>) -> Result<bool, HiddenServiceError> {
        descriptor.verify(&self.ops)?;
        let lifetime = descriptor.not_after - descriptor.not_before;
        if lifetime <= 0.0 || lifetime > self.max_descriptor_lifetime {
            return Err(HiddenServiceError::DescriptorLifetimeTooLong(format!(
                "descriptor claims a {lifetime}s validity window; this directory accepts more than 0 and at most {}s",
                self.max_descriptor_lifetime
            )));
        }
        let now = (self.clock)();
        if !descriptor.is_valid_at(now) {
            return Err(HiddenServiceError::DescriptorExpired("descriptor is outside its validity window".to_string()));
        }
        let current = hs_directory_period(Some(now), HS_DIRECTORY_INDEX_PERIOD);
        if (descriptor.period - current).abs() > 1 {
            return Err(err(format!("descriptor is for period {}, but the current period is {current}; only the current and adjacent periods are accepted", descriptor.period)));
        }

        let new_len = descriptor.ciphertext.len();
        if new_len > self.max_store_bytes {
            return Err(HiddenServiceError::StoreFull(format!(
                "descriptor is {new_len} bytes, more than this directory's whole {}-byte budget",
                self.max_store_bytes
            )));
        }
        let key = descriptor.blinded_public;
        match self.by_key.get(&key) {
            Some(existing) => {
                if existing.not_before > descriptor.not_before {
                    return Ok(false);
                }
            }
            None => {
                if let Some(src) = source.filter(|src| self.per_source.get(*src).copied().unwrap_or(0) >= MAX_BLINDED_PER_SOURCE) {
                    return Err(HiddenServiceError::SourceQuotaExceeded(format!(
                        "source {src} already holds {MAX_BLINDED_PER_SOURCE} hidden-service descriptors (the per-source maximum); refusing a new one from it until one expires"
                    )));
                }
            }
        }
        self.make_room_for(&key, new_len, now);
        let old_len = self.by_key.get(&key).map(|d| d.ciphertext.len());
        self.stored_bytes = self.stored_bytes - old_len.unwrap_or(0) + new_len;
        if old_len.is_none() {
            if let Some(src) = source {
                self.source_of.insert(key, src.to_string());
                *self.per_source.entry(src.to_string()).or_insert(0) += 1;
            }
        }
        match self.meta.get_mut(&key) {
            Some(m) => {
                if now - m.last_counted >= REFRESH_MIN_GAP_SECS {
                    m.refreshes = m.refreshes.saturating_add(1);
                    m.last_counted = now;
                }
            }
            None => {
                self.meta.insert(key, EntryMeta { first_seen: now, last_counted: now, refreshes: 0 });
            }
        }
        self.by_key.insert(key, descriptor);
        Ok(true)
    }

    /// Evict until an entry of `new_len` bytes for `key` fits both the entry
    /// cap and the byte budget. `key` itself is never a victim (replacing it
    /// is accounted for by the caller). Who goes first is [`Self::pick_victim`].
    fn make_room_for(&mut self, key: &[u8; 32], new_len: usize, now: f64) {
        let held_len = self.by_key.get(key).map(|d| d.ciphertext.len());
        let (max_bytes, max_entries) = (self.max_store_bytes, self.max_entries);
        let fits = |count: usize, bytes: usize| {
            count + usize::from(held_len.is_none()) <= max_entries && bytes - held_len.unwrap_or(0) + new_len <= max_bytes
        };
        while !fits(self.by_key.len(), self.stored_bytes) {
            match self.pick_victim(key, now) {
                Some(victim) => self.remove_entry(&victim),
                None => break, // unreachable: new_len <= max_store_bytes was checked
            }
        }
    }

    /// The next entry to evict, never `exclude`. See the type's documentation
    /// for the order; ties break deterministically (publish time, then key).
    fn pick_victim(&self, exclude: &[u8; 32], now: f64) -> Option<[u8; 32]> {
        use std::cmp::Ordering;
        let cmp_f = |a: f64, b: f64| a.partial_cmp(&b).unwrap_or(Ordering::Equal);
        let (mut expired, mut unproven, mut proven): (Option<(f64, [u8; 32])>, Option<(f64, f64, [u8; 32])>, Option<(f64, f64, [u8; 32])>) = (None, None, None);
        let mut unproven_count = 0usize;
        for (k, d) in &self.by_key {
            if k == exclude {
                continue;
            }
            let m = self.meta.get(k).copied().unwrap_or(EntryMeta { first_seen: f64::NEG_INFINITY, last_counted: f64::NEG_INFINITY, refreshes: 0 });
            if !d.is_valid_at(now) {
                // oldest publish first
                if expired.is_none_or(|(nb, ek)| cmp_f(d.not_before, nb).then(k.cmp(&ek)) == Ordering::Less) {
                    expired = Some((d.not_before, *k));
                }
            } else if m.proven() {
                // shortest tenure (latest first_seen) first
                if proven.is_none_or(|(fs, nb, pk)| cmp_f(fs, m.first_seen).then(cmp_f(d.not_before, nb)).then(k.cmp(&pk)) == Ordering::Less) {
                    proven = Some((m.first_seen, d.not_before, *k));
                }
            } else {
                unproven_count += 1;
                // oldest first_seen first
                if unproven.is_none_or(|(fs, nb, uk)| cmp_f(m.first_seen, fs).then(cmp_f(d.not_before, nb)).then(k.cmp(&uk)) == Ordering::Less) {
                    unproven = Some((m.first_seen, d.not_before, *k));
                }
            }
        }
        let reserve = (self.max_entries / UNPROVEN_RESERVE_DIVISOR).max(1);
        if let Some((_, k)) = expired {
            return Some(k);
        }
        if unproven_count >= reserve {
            if let Some((_, _, k)) = unproven {
                return Some(k);
            }
        }
        proven.map(|(_, _, k)| k).or(unproven.map(|(_, _, k)| k))
    }

    /// Drop one entry, releasing its bytes and quota.
    fn remove_entry(&mut self, key: &[u8; 32]) {
        self.meta.remove(key);
        if let Some(d) = self.by_key.remove(key) {
            self.stored_bytes -= d.ciphertext.len();
        }
        if let Some(src) = self.source_of.remove(key) {
            if let Some(n) = self.per_source.get_mut(&src) {
                *n -= 1;
                if *n == 0 {
                    self.per_source.remove(&src);
                }
            }
        }
    }

    /// The live descriptor for a blinded key, if any.
    pub fn get(&self, blinded_public: &[u8; 32]) -> Option<&BlindedDescriptor> {
        let d = self.by_key.get(blinded_public)?;
        d.is_valid_at((self.clock)()).then_some(d)
    }

    /// Drop expired descriptors, releasing their bytes and quota; returns how many.
    pub fn prune(&mut self) -> usize {
        let now = (self.clock)();
        let stale: Vec<[u8; 32]> = self.by_key.iter().filter(|(_, d)| !d.is_valid_at(now)).map(|(k, _)| *k).collect();
        for key in &stale {
            self.remove_entry(key);
        }
        stale.len()
    }

    pub fn len(&self) -> usize {
        let now = (self.clock)();
        self.by_key.values().filter(|d| d.is_valid_at(now)).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as StdHashMap;
    use std::sync::Mutex;

    // -----------------------------------------------------------------
    // Fake, deterministic HsOps, process-global registry (mirrors
    // directory.rs's fake_ops pattern -- shared so descriptors signed by
    // one `fake_ops()` call verify against another's).
    // -----------------------------------------------------------------

    fn sig_registry() -> &'static Mutex<StdHashMap<([u8; 32], Vec<u8>), [u8; 64]>> {
        static REG: std::sync::OnceLock<Mutex<StdHashMap<([u8; 32], Vec<u8>), [u8; 64]>>> = std::sync::OnceLock::new();
        REG.get_or_init(|| Mutex::new(StdHashMap::new()))
    }

    fn fake_ed25519_public_of(seed: &[u8; 32]) -> [u8; 32] {
        crate::hashutil::hmac_sha256(b"ed25519-pub-fake", seed)
    }
    fn fake_ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
        let public = fake_ed25519_public_of(seed);
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&crate::hashutil::hmac_sha256(seed, msg));
        sig[32..].copy_from_slice(&public);
        sig_registry().lock().unwrap().insert((public, msg.to_vec()), sig);
        sig
    }
    fn fake_ed25519_verify(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        sig_registry().lock().unwrap().get(&(*public, msg.to_vec())) == Some(sig)
    }

    fn fake_x25519_public(seed: &[u8; 32]) -> [u8; 32] {
        crate::hashutil::hmac_sha256(b"x25519-pub-fake", seed)
    }
    fn fake_x25519_dh(private: &[u8; 32], peer_public: &[u8; 32]) -> Result<[u8; 32], HiddenServiceError> {
        // Must be symmetric (dh(a_priv, b_pub) == dh(b_priv, a_pub)), same
        // as real X25519 -- derive both sides' public keys and combine them
        // order-independently, rather than mixing in `private` directly.
        let own_public = fake_x25519_public(private);
        let (a, b) = if own_public <= *peer_public { (own_public, *peer_public) } else { (*peer_public, own_public) };
        let mut buf = a.to_vec();
        buf.extend_from_slice(&b);
        Ok(crate::hashutil::hmac_sha256(b"x25519-dh-fake", &buf))
    }
    fn fake_x25519_generate() -> [u8; 32] {
        key32(random_bytes(32).unwrap()).unwrap()
    }

    fn fake_ops() -> HsOps {
        HsOps {
            x25519_generate: Box::new(fake_x25519_generate),
            x25519_public: Box::new(fake_x25519_public),
            x25519_dh: Box::new(fake_x25519_dh),
            ed25519_sign: Box::new(fake_ed25519_sign),
            ed25519_verify: Box::new(fake_ed25519_verify),
            ed25519_public_of: Box::new(fake_ed25519_public_of),
        }
    }

    fn identity(byte: u8) -> ServiceIdentity {
        ServiceIdentity::new([byte; 32], ServiceIdentityOptions::default()).unwrap()
    }

    // -----------------------------------------------------------------
    // Addressing
    // -----------------------------------------------------------------

    #[test]
    fn test_address_round_trip() {
        let key = [7u8; 32];
        let addr = encode_address(&key);
        assert!(addr.ends_with(".allium"));
        assert_eq!(decode_address(&addr).unwrap(), key);
    }

    #[test]
    fn test_address_rejects_bad_suffix() {
        assert!(decode_address("abcdefgh.onion").is_err());
    }

    #[test]
    fn test_address_rejects_bad_checksum() {
        let key = [7u8; 32];
        let mut addr = encode_address(&key);
        // Flip a character inside the label (not the suffix).
        let mut chars: Vec<char> = addr.chars().collect();
        chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
        addr = chars.into_iter().collect();
        assert!(decode_address(&addr).is_err());
    }

    #[test]
    fn test_address_rejects_bad_version() {
        let key = [7u8; 32];
        let mut payload = key.to_vec();
        payload.extend_from_slice(&address_checksum(&key));
        payload.push(99); // bad version
        let label = base32_encode_nopad_lower(&payload);
        let addr = format!("{label}.allium");
        assert!(decode_address(&addr).is_err());
    }

    // -----------------------------------------------------------------
    // Directory index blinding
    // -----------------------------------------------------------------

    #[test]
    fn test_directory_index_stable_within_period() {
        let key = [3u8; 32];
        let a = hs_directory_index(&key, Some(100));
        let b = hs_directory_index(&key, Some(100));
        assert_eq!(a, b);
    }

    #[test]
    fn test_directory_index_differs_across_periods() {
        let key = [3u8; 32];
        assert_ne!(hs_directory_index(&key, Some(100)), hs_directory_index(&key, Some(101)));
    }

    #[test]
    fn test_directory_index_differs_across_identities() {
        assert_ne!(hs_directory_index(&[1u8; 32], Some(1)), hs_directory_index(&[2u8; 32], Some(1)));
    }

    // -----------------------------------------------------------------
    // ServiceIdentity
    // -----------------------------------------------------------------

    #[test]
    fn test_identity_public_and_address() {
        let ops = fake_ops();
        let id = identity(1);
        let addr = id.address(&ops);
        assert!(addr.ends_with(".allium"));
        assert_eq!(decode_address(&addr).unwrap(), id.identity_public(&ops));
    }

    #[test]
    fn test_sign_verify_round_trip() {
        let ops = fake_ops();
        let id = identity(2);
        let sig = id.sign(&ops, b"hello");
        assert!((ops.ed25519_verify)(&id.identity_public(&ops), b"hello", &sig));
    }

    #[test]
    fn test_intro_auth_keypair_deterministic_and_relay_specific() {
        let ops = fake_ops();
        let id = identity(3);
        let (seed_a, pub_a) = id.intro_auth_keypair(&ops, &[9u8; 32]);
        let (seed_a2, pub_a2) = id.intro_auth_keypair(&ops, &[9u8; 32]);
        assert_eq!(seed_a, seed_a2);
        assert_eq!(pub_a, pub_a2);
        let (_, pub_b) = id.intro_auth_keypair(&ops, &[10u8; 32]);
        assert_ne!(pub_a, pub_b);
    }

    #[test]
    fn test_encryption_public_rotates_after_period() {
        let ops = fake_ops();
        let clock = Arc::new(Mutex::new(1000.0f64));
        let clock_clone = clock.clone();
        let mut id = ServiceIdentity::new(
            [4u8; 32],
            ServiceIdentityOptions {
                rotation_period: 10.0,
                grace_period: 5.0,
                clock: Some(Arc::new(move || *clock_clone.lock().unwrap())),
                ..ServiceIdentityOptions::default()
            },
        )
        .unwrap();
        let key1 = id.encryption_public(&ops);
        *clock.lock().unwrap() = 1005.0;
        assert_eq!(id.encryption_public(&ops), key1); // not yet due
        *clock.lock().unwrap() = 1011.0;
        let key2 = id.encryption_public(&ops);
        assert_ne!(key1, key2); // rotated
    }

    /// Security fix: a failed persist of the newly-rotated introduction
    /// key must propagate as an error, not be silently discarded --
    /// before this fix, `maybe_rotate` had no `Result` in its signature at
    /// all, so a `let _ = persist_intro_key(...)` there threw the failure
    /// away regardless of what its own comment claimed.
    #[test]
    fn test_encryption_public_propagates_a_failed_key_persist() {
        let ops = fake_ops();
        let clock = Arc::new(Mutex::new(1000.0f64));
        let clock_clone = clock.clone();
        let mut id = ServiceIdentity::new(
            [4u8; 32],
            ServiceIdentityOptions {
                rotation_period: 10.0,
                grace_period: 5.0,
                clock: Some(Arc::new(move || *clock_clone.lock().unwrap())),
                ..ServiceIdentityOptions::default()
            },
        )
        .unwrap();
        // A rotation with `intro_path` set always tries to persist; point
        // it at a directory that cannot exist so that persist fails.
        id.intro_path = Some("/nonexistent-allium-test-dir-2026-09-26/intro.key".to_string());
        *clock.lock().unwrap() = 1011.0; // past rotation_period
        assert!(matches!(id.encryption_public(&ops), Err(HiddenServiceError::Generic(_))));
    }

    /// Security audit fix (2026-09-26): a second rotation racing ahead of
    /// the first rotation's own grace-period expiry used to silently drop
    /// the still-live `intro_previous_seed` from that first rotation
    /// un-zeroized (`self.intro_previous_seed = Some(self.intro_seed)`
    /// overwriting it outright). Functionally, this must still behave
    /// exactly as before the fix -- the newest previous key stays usable
    /// for `open_introduce` (proving the overwrite-with-zeroize didn't
    /// corrupt the replacement value), and the oldest one (superseded
    /// twice over) is gone.
    #[test]
    fn test_double_rotation_before_first_grace_period_expires_still_evicts_correctly() {
        let ops = fake_ops();
        let clock = Arc::new(Mutex::new(1000.0f64));
        let clock_clone = clock.clone();
        let mut id = ServiceIdentity::new(
            [4u8; 32],
            ServiceIdentityOptions {
                rotation_period: 10.0,
                grace_period: 100.0, // long enough that neither rotation below expires on its own
                clock: Some(Arc::new(move || *clock_clone.lock().unwrap())),
                ..ServiceIdentityOptions::default()
            },
        )
        .unwrap();

        let key1 = id.encryption_public(&ops).unwrap();
        let client1_priv = fake_x25519_generate();
        let client1_pub = (ops.x25519_public)(&client1_priv);
        let sealed_for_key1 = seal_introduce(&ops, &key1, &client1_priv, b"for key1").unwrap();

        *clock.lock().unwrap() = 1011.0; // first rotation: key1 -> key2, intro_previous_seed = key1's seed
        let key2 = id.encryption_public(&ops).unwrap();
        assert_ne!(key1, key2);

        *clock.lock().unwrap() = 1022.0; // second rotation: key2 -> key3, intro_previous_seed = key2's seed (key1's is now gone)
        let key3 = id.encryption_public(&ops).unwrap();
        assert_ne!(key2, key3);

        // key1's grace window is over (superseded, not just expired by
        // time) -- a message sealed for it can no longer be opened.
        assert!(id.open_introduce(&ops, &client1_pub, &sealed_for_key1).is_err());

        // key2 is still within its own grace period (only 11s old, well
        // under the 100s grace_period) -- a message sealed for it must
        // still open, proving `intro_previous_seed` correctly holds key2's
        // seed (not corrupted, not accidentally left as key1's).
        let client2_priv = fake_x25519_generate();
        let client2_pub = (ops.x25519_public)(&client2_priv);
        let sealed_for_key2 = seal_introduce(&ops, &key2, &client2_priv, b"for key2").unwrap();
        let opened = id.open_introduce(&ops, &client2_pub, &sealed_for_key2).unwrap();
        assert_eq!(opened, b"for key2");
    }

    #[test]
    fn test_seal_open_introduce_round_trip() {
        let ops = fake_ops();
        let mut id = identity(5);
        let service_pub = id.encryption_public(&ops).unwrap();
        let client_priv = fake_x25519_generate();
        let client_pub = (ops.x25519_public)(&client_priv);
        let sealed = seal_introduce(&ops, &service_pub, &client_priv, b"rendezvous info").unwrap();
        let opened = id.open_introduce(&ops, &client_pub, &sealed).unwrap();
        assert_eq!(opened, b"rendezvous info");
    }

    #[test]
    fn test_open_introduce_rejects_replay() {
        let ops = fake_ops();
        let mut id = identity(6);
        let service_pub = id.encryption_public(&ops).unwrap();
        let client_priv = fake_x25519_generate();
        let client_pub = (ops.x25519_public)(&client_priv);
        let sealed = seal_introduce(&ops, &service_pub, &client_priv, b"hello").unwrap();
        id.open_introduce(&ops, &client_pub, &sealed).unwrap();
        let result = id.open_introduce(&ops, &client_pub, &sealed);
        assert!(matches!(result, Err(HiddenServiceError::IntroduceReplayed(_))));
    }

    #[test]
    fn test_open_introduce_rejects_wrong_key() {
        let ops = fake_ops();
        let mut id = identity(7);
        let _ = id.encryption_public(&ops);
        let other_service_pub = fake_x25519_public(&[200u8; 32]);
        let client_priv = fake_x25519_generate();
        let sealed = seal_introduce(&ops, &other_service_pub, &client_priv, b"hello").unwrap();
        let client_pub = (ops.x25519_public)(&client_priv);
        assert!(id.open_introduce(&ops, &client_pub, &sealed).is_err());
    }

    // -----------------------------------------------------------------
    // Session crypto
    // -----------------------------------------------------------------

    #[test]
    fn test_hs_session_round_trip_both_directions() {
        let shared = [42u8; 32];
        let (c2s, s2c) = derive_session_keys(&shared).unwrap();
        let cookie = [1u8; 32];
        let mut client = HsSession::new(c2s, s2c, &cookie, false).unwrap();
        let mut service = HsSession::new(c2s, s2c, &cookie, true).unwrap();

        let msg1 = client.seal(b"hi from client").unwrap();
        assert_eq!(service.open(&msg1).unwrap(), b"hi from client");

        let msg2 = service.seal(b"hi from service").unwrap();
        assert_eq!(client.open(&msg2).unwrap(), b"hi from service");
    }

    // -----------------------------------------------------------------
    // Descriptor create/verify
    // -----------------------------------------------------------------

    fn sample_intro_points() -> Vec<IntroPoint> {
        vec![
            IntroPoint { relay_identity: vec![1u8; 32], host: "1.2.3.4".to_string(), port: 9001, auth_public: vec![2u8; 32] },
            IntroPoint { relay_identity: vec![3u8; 32], host: "5.6.7.8".to_string(), port: 9002, auth_public: vec![4u8; 32] },
        ]
    }

    #[test]
    fn test_descriptor_create_verify_round_trip() {
        let ops = fake_ops();
        let id = identity(10);
        let desc = HiddenServiceDescriptor::create(&ops, &id, &sample_intro_points(), CreateHsDescriptorOptions { now: Some(1000.0), ..Default::default() }).unwrap();
        desc.verify(&ops).unwrap();
        assert_eq!(desc.intro_points, sample_intro_points());
        assert!(desc.is_valid_at(1500.0));
        assert!(!desc.is_valid_at(10000.0));
    }

    #[test]
    fn test_descriptor_verify_rejects_tampered_intro_auth_public() {
        let ops = fake_ops();
        let id = identity(10);
        let mut desc = HiddenServiceDescriptor::create(&ops, &id, &sample_intro_points(), CreateHsDescriptorOptions { now: Some(1000.0), ..Default::default() }).unwrap();
        desc.intro_points[0].auth_public = vec![0xffu8; 32];
        assert!(desc.verify(&ops).is_err());
    }

    #[test]
    fn test_descriptor_verify_rejects_foreign_signature() {
        let ops = fake_ops();
        let id_a = identity(11);
        let id_b = identity(12);
        let mut desc = HiddenServiceDescriptor::create(&ops, &id_a, &sample_intro_points(), CreateHsDescriptorOptions { now: Some(1000.0), ..Default::default() }).unwrap();
        desc.signature = id_b.sign(&ops, &desc.signing_payload()).to_vec();
        assert!(desc.verify(&ops).is_err());
    }

    #[test]
    fn test_descriptor_client_auth_round_trip() {
        let ops = fake_ops();
        let id = identity(13);
        let client_priv = fake_x25519_generate();
        let client_pub = (ops.x25519_public)(&client_priv);
        let desc = HiddenServiceDescriptor::create(
            &ops,
            &id,
            &sample_intro_points(),
            CreateHsDescriptorOptions { now: Some(1000.0), client_auth_public_keys: vec![client_pub], ..Default::default() },
        )
        .unwrap();
        desc.verify(&ops).unwrap();
        assert!(desc.intro_points.is_empty());
        assert_eq!(desc.client_auth.len(), 1);

        let points = desc.intro_points_for(&ops, Some(&client_priv)).unwrap();
        assert_eq!(points, sample_intro_points());
    }

    #[test]
    fn test_descriptor_client_auth_rejects_wrong_client() {
        let ops = fake_ops();
        let id = identity(14);
        let client_priv = fake_x25519_generate();
        let client_pub = (ops.x25519_public)(&client_priv);
        let desc = HiddenServiceDescriptor::create(
            &ops,
            &id,
            &sample_intro_points(),
            CreateHsDescriptorOptions { now: Some(1000.0), client_auth_public_keys: vec![client_pub], ..Default::default() },
        )
        .unwrap();
        let wrong_priv = fake_x25519_generate();
        assert!(desc.intro_points_for(&ops, Some(&wrong_priv)).is_err());
    }

    #[test]
    fn test_descriptor_client_auth_requires_key_when_restricted() {
        let ops = fake_ops();
        let id = identity(15);
        let client_priv = fake_x25519_generate();
        let client_pub = (ops.x25519_public)(&client_priv);
        let desc = HiddenServiceDescriptor::create(
            &ops,
            &id,
            &sample_intro_points(),
            CreateHsDescriptorOptions { now: Some(1000.0), client_auth_public_keys: vec![client_pub], ..Default::default() },
        )
        .unwrap();
        assert!(desc.intro_points_for(&ops, None).is_err());
    }

    // -----------------------------------------------------------------
    // HiddenServiceDirectory
    // -----------------------------------------------------------------

    fn make_hs_dir(clock: Arc<dyn Fn() -> f64 + Send + Sync>) -> HiddenServiceDirectory {
        HiddenServiceDirectory::new(Some(clock), None, fake_ops()).unwrap()
    }

    #[test]
    fn test_publish_and_get_round_trip() {
        let ops = fake_ops();
        let id = identity(20);
        let now = Arc::new(|| 2000.0f64);
        let mut dir = make_hs_dir(now.clone());
        let desc = HiddenServiceDescriptor::create(&ops, &id, &sample_intro_points(), CreateHsDescriptorOptions { now: Some(1900.0), ..Default::default() }).unwrap();
        let identity_public = desc.identity_public.clone();
        assert!(dir.publish(desc).unwrap());
        assert!(dir.get(&identity_public).is_some());
        assert_eq!(dir.len(), 1);
    }

    #[test]
    fn test_publish_rejects_bad_signature() {
        let ops = fake_ops();
        let id_a = identity(21);
        let id_b = identity(22);
        let mut dir = make_hs_dir(Arc::new(|| 2000.0f64));
        let mut desc = HiddenServiceDescriptor::create(&ops, &id_a, &sample_intro_points(), CreateHsDescriptorOptions { now: Some(1900.0), ..Default::default() }).unwrap();
        desc.signature = id_b.sign(&ops, &desc.signing_payload()).to_vec();
        assert!(dir.publish(desc).is_err());
    }

    #[test]
    fn test_publish_rejects_expired() {
        let ops = fake_ops();
        let id = identity(23);
        let mut dir = make_hs_dir(Arc::new(|| 100000.0f64));
        let desc = HiddenServiceDescriptor::create(&ops, &id, &sample_intro_points(), CreateHsDescriptorOptions { now: Some(1000.0), ..Default::default() }).unwrap();
        assert!(matches!(dir.publish(desc), Err(HiddenServiceError::DescriptorExpired(_))));
    }

    #[test]
    fn test_publish_rejects_too_long_lifetime() {
        let ops = fake_ops();
        let id = identity(24);
        let mut dir = HiddenServiceDirectory::new(Some(Arc::new(|| 2000.0f64)), Some(100.0), fake_ops()).unwrap();
        let desc = HiddenServiceDescriptor::create(&ops, &id, &sample_intro_points(), CreateHsDescriptorOptions { now: Some(1900.0), lifetime: 10000.0, ..Default::default() }).unwrap();
        assert!(matches!(dir.publish(desc), Err(HiddenServiceError::DescriptorLifetimeTooLong(_))));
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
    fn test_publish_rejects_new_identity_once_the_store_is_full_but_still_allows_rotation() {
        let ops = fake_ops();
        let mut dir = make_hs_dir(Arc::new(|| 2000.0f64));
        let existing =
            HiddenServiceDescriptor::create(&ops, &identity(29), &sample_intro_points(), CreateHsDescriptorOptions { now: Some(1900.0), ..Default::default() }).unwrap();
        let existing_identity = existing.identity_public.clone();
        assert!(dir.publish(existing).unwrap());
        for i in 1..MAX_HS_DESCRIPTORS {
            let mut filler = HiddenServiceDescriptor::create(&ops, &identity(29), &sample_intro_points(), CreateHsDescriptorOptions { now: Some(1900.0), ..Default::default() }).unwrap();
            filler.identity_public = format!("filler-{i}").into_bytes();
            dir.by_identity.insert(filler.identity_public.clone(), filler);
        }
        assert_eq!(dir.len(), MAX_HS_DESCRIPTORS);

        // A genuinely new identity is refused once full.
        let newcomer =
            HiddenServiceDescriptor::create(&ops, &identity(250), &sample_intro_points(), CreateHsDescriptorOptions { now: Some(1900.0), ..Default::default() }).unwrap();
        assert!(matches!(dir.publish(newcomer), Err(HiddenServiceError::StoreFull(_))));

        // Rotating an identity already in the store is never blocked by
        // the cap: the existing service must always be able to renew.
        let rotated =
            HiddenServiceDescriptor::create(&ops, &identity(29), &sample_intro_points(), CreateHsDescriptorOptions { now: Some(1950.0), ..Default::default() }).unwrap();
        assert_eq!(rotated.identity_public, existing_identity);
        assert!(dir.publish(rotated).unwrap());
        assert_eq!(dir.len(), MAX_HS_DESCRIPTORS, "rotation must not change the store's size");
    }

    #[test]
    fn test_publish_newer_not_before_wins() {
        let ops = fake_ops();
        let id = identity(25);
        let mut dir = make_hs_dir(Arc::new(|| 2000.0f64));
        let desc1 = HiddenServiceDescriptor::create(&ops, &id, &sample_intro_points(), CreateHsDescriptorOptions { now: Some(1900.0), ..Default::default() }).unwrap();
        let desc2 = HiddenServiceDescriptor::create(&ops, &id, &sample_intro_points(), CreateHsDescriptorOptions { now: Some(1950.0), ..Default::default() }).unwrap();
        assert!(dir.publish(desc1).unwrap());
        assert!(dir.publish(desc2).unwrap());
        // An older republish (earlier not_before) than what's held now.
        let desc0 = HiddenServiceDescriptor::create(&ops, &id, &sample_intro_points(), CreateHsDescriptorOptions { now: Some(1800.0), ..Default::default() }).unwrap();
        assert!(!dir.publish(desc0).unwrap());
    }

    #[test]
    fn test_get_by_blinded_index() {
        let ops = fake_ops();
        let id = identity(26);
        let now = Arc::new(|| 2000.0f64);
        let mut dir = make_hs_dir(now.clone());
        let desc = HiddenServiceDescriptor::create(&ops, &id, &sample_intro_points(), CreateHsDescriptorOptions { now: Some(1900.0), ..Default::default() }).unwrap();
        let identity_public = key32(desc.identity_public.clone()).unwrap();
        dir.publish(desc).unwrap();
        let index = hs_directory_index(&identity_public, Some(hs_directory_period(Some(2000.0), HS_DIRECTORY_INDEX_PERIOD)));
        assert!(dir.get_by_blinded_index(&index).is_some());
        assert!(dir.get_by_blinded_index(&[0u8; 32]).is_none());
    }

    #[test]
    fn test_prune_removes_expired() {
        let ops = fake_ops();
        let id = identity(27);
        let clock_value = Arc::new(Mutex::new(1950.0f64));
        let clock_clone = clock_value.clone();
        let mut dir = make_hs_dir(Arc::new(move || *clock_clone.lock().unwrap()));
        let desc = HiddenServiceDescriptor::create(&ops, &id, &sample_intro_points(), CreateHsDescriptorOptions { now: Some(1900.0), lifetime: 100.0, ..Default::default() }).unwrap();
        assert!(dir.publish(desc).unwrap());
        assert_eq!(dir.len(), 1);
        *clock_value.lock().unwrap() = 5000.0;
        assert_eq!(dir.prune(), 1);
        assert_eq!(dir.len(), 0);
    }

    // -----------------------------------------------------------------
    // load_or_create* (file I/O)
    // -----------------------------------------------------------------

    #[test]
    fn test_service_identity_load_or_create_persists_and_reloads() {
        let dir = std::env::temp_dir().join(format!("allium-hs-test-{}", u64::from_be_bytes(random_bytes(8).unwrap().try_into().unwrap())));
        let path = dir.join("hs_identity").to_string_lossy().to_string();
        let id1 = ServiceIdentity::load_or_create(&path).unwrap();
        let id2 = ServiceIdentity::load_or_create(&path).unwrap();
        assert_eq!(id1.seed(), id2.seed());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_client_auth_key_load_or_create_persists_and_reloads() {
        let dir = std::env::temp_dir().join(format!("allium-hs-clientauth-test-{}", u64::from_be_bytes(random_bytes(8).unwrap().try_into().unwrap())));
        let path = dir.join("client_auth").to_string_lossy().to_string();
        let key1 = load_or_create_client_auth_key(&path).unwrap();
        let key2 = load_or_create_client_auth_key(&path).unwrap();
        assert_eq!(key1, key2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- per-source quota ------------------------------------------------

    fn quota_desc(ops: &HsOps, n: u8, now: f64) -> HiddenServiceDescriptor {
        HiddenServiceDescriptor::create(ops, &identity(n), &sample_intro_points(), CreateHsDescriptorOptions { now: Some(now), ..Default::default() }).unwrap()
    }

    #[test]
    fn test_per_source_quota_stops_one_source_but_not_another() {
        let ops = fake_ops();
        let mut dir = make_hs_dir(Arc::new(|| 2000.0f64));
        for n in 0..64u8 {
            assert!(dir.publish_from(quota_desc(&ops, n, 1900.0), Some("10.0.0.0/24")).unwrap());
        }
        // the 65th new identity from the same source is refused
        let over = dir.publish_from(quota_desc(&ops, 100, 1900.0), Some("10.0.0.0/24"));
        assert!(matches!(over, Err(HiddenServiceError::SourceQuotaExceeded(_))), "{over:?}");
        assert_eq!(dir.by_identity.len(), 64);
        // a different source is unaffected
        assert!(dir.publish_from(quota_desc(&ops, 100, 1900.0), Some("10.0.1.0/24")).unwrap());
    }

    #[test]
    fn test_quota_never_blocks_republishing_an_identity_already_held() {
        let ops = fake_ops();
        let mut dir = make_hs_dir(Arc::new(|| 2000.0f64));
        for n in 0..64u8 {
            dir.publish_from(quota_desc(&ops, n, 1900.0), Some("10.0.0.0/24")).unwrap();
        }
        // a service at the quota renews its own descriptor (newer not_before)
        assert!(dir.publish_from(quota_desc(&ops, 5, 1950.0), Some("10.0.0.0/24")).unwrap());
        // and the same identity re-published from another source is neither
        // refused nor re-charged to that source
        assert!(dir.publish_from(quota_desc(&ops, 6, 1960.0), Some("10.9.9.0/24")).unwrap());
        assert_eq!(dir.per_source.get("10.9.9.0/24"), None);
        assert_eq!(dir.per_source.get("10.0.0.0/24").copied(), Some(64));
    }

    #[test]
    fn test_prune_releases_the_quota_of_expired_identities() {
        let ops = fake_ops();
        let now = Arc::new(std::sync::Mutex::new(2000.0f64));
        let clock_now = now.clone();
        let mut dir = make_hs_dir(Arc::new(move || *clock_now.lock().unwrap()));
        for n in 0..64u8 {
            dir.publish_from(quota_desc(&ops, n, 1900.0), Some("10.0.0.0/24")).unwrap();
        }
        assert!(dir.publish_from(quota_desc(&ops, 100, 1900.0), Some("10.0.0.0/24")).is_err());
        // time passes beyond every descriptor's lifetime; the next prune frees the quota
        *now.lock().unwrap() = 1900.0 + DEFAULT_HS_DESCRIPTOR_LIFETIME + 10.0;
        assert_eq!(dir.prune(), 64);
        assert!(dir.per_source.is_empty() && dir.source_of.is_empty());
        // read the clock into a local first: holding its lock across publish_from
        // (whose own clock closure takes the same lock) would deadlock
        let later = *now.lock().unwrap();
        assert!(dir.publish_from(quota_desc(&ops, 100, later - 10.0), Some("10.0.0.0/24")).unwrap());
    }

    #[test]
    fn test_quota_accounting_stays_consistent_and_publish_without_source_is_unchanged() {
        let ops = fake_ops();
        let mut dir = make_hs_dir(Arc::new(|| 2000.0f64));
        // plain publish() carries no source, so no quota applies: more than the quota is fine
        for n in 0..(MAX_HS_DESCRIPTORS_PER_SOURCE as u8 + 20) {
            assert!(dir.publish(quota_desc(&ops, n, 1900.0)).unwrap());
        }
        assert!(dir.per_source.is_empty() && dir.source_of.is_empty());
        // mixed use: counts always equal the identities attributed to a source
        let mut other = make_hs_dir(Arc::new(|| 2000.0f64));
        for n in 0..10u8 {
            other.publish_from(quota_desc(&ops, n, 1900.0), Some("a")).unwrap();
        }
        for n in 10..15u8 {
            other.publish_from(quota_desc(&ops, n, 1900.0), Some("b")).unwrap();
        }
        let counted: usize = other.per_source.values().sum();
        assert_eq!(counted, other.source_of.len());
        assert_eq!(counted, other.by_identity.len());
        // an entry inserted around publish() (as an existing test does) has no
        // source record and must not break prune()
        other.by_identity.insert(b"filler".to_vec(), quota_desc(&ops, 200, 1900.0));
        assert_eq!(other.prune(), 0);
    }

    // -- version 3: blinded descriptors ---------------------------------------------

    /// A complete descriptor (key, signature and all) produced by an
    /// independent pure-Python implementation of the construction. The Client
    /// pins the same bytes; this keeps the two crates' signed payloads in step.
    const PYTHON_BLINDED_DESCRIPTOR: &str = "b4b4c5b42cd22f8fb45c4441b1ca49434c87fc080be379d2be855ef3aa2df04d0000000000003039408f44000000000040b1f8800000000002020202020202020202020202020202020202020202020202020202020202020000002803030303030303030303030303030303030303030303030303030303030303030303030303030303f3892768b8f99b0170112690873792749386aab875cac49a194f72f0f609338f3f6628858fba095f649f065fa85542aafd908a6a19ae3d09836548782cb0350b";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn a_descriptor_signed_by_the_independent_implementation_verifies_here() {
        let (d, consumed) = crate::dirwire::decode_blinded_descriptor(&unhex(PYTHON_BLINDED_DESCRIPTOR)).unwrap();
        assert_eq!(consumed, unhex(PYTHON_BLINDED_DESCRIPTOR).len());
        assert_eq!(d.period, 12345);
        assert_eq!((d.not_before, d.not_after), (1000.5, 4600.5));
        d.verify(&HsOps::real()).expect("the Python-produced signature must verify under the Authority's real Ed25519");
        // and any change to a covered field breaks it
        for mutate in [
            |d: &mut BlindedDescriptor| d.period += 1,
            |d: &mut BlindedDescriptor| d.not_after += 1.0,
            |d: &mut BlindedDescriptor| d.not_before -= 1.0,
            |d: &mut BlindedDescriptor| d.salt[0] ^= 1,
            |d: &mut BlindedDescriptor| d.ciphertext[0] ^= 1,
            |d: &mut BlindedDescriptor| d.blinded_public[0] ^= 1,
            |d: &mut BlindedDescriptor| d.signature[0] ^= 1,
        ] {
            let mut t = d.clone();
            mutate(&mut t);
            assert!(t.verify(&HsOps::real()).is_err());
        }
    }

    fn signed(secret: u8, period: i64, not_before: f64, not_after: f64, ct_len: usize) -> BlindedDescriptor {
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::from_bytes(&[secret; 32]);
        let mut d = BlindedDescriptor {
            blinded_public: key.verifying_key().to_bytes(),
            period,
            not_before,
            not_after,
            salt: [secret; crate::dirwire::BLINDED_SALT_LEN],
            ciphertext: vec![secret ^ 0x55; ct_len],
            signature: Vec::new(),
        };
        d.signature = key.sign(&d.signing_payload()).to_bytes().to_vec();
        d
    }

    const NOW3: f64 = 1_700_000_000.0;

    fn period3() -> i64 {
        hs_directory_period(Some(NOW3), HS_DIRECTORY_INDEX_PERIOD)
    }

    fn store3() -> (BlindedHsDirectory, Arc<std::sync::Mutex<f64>>) {
        let now = Arc::new(std::sync::Mutex::new(NOW3));
        let clock = now.clone();
        (BlindedHsDirectory::new(Some(Arc::new(move || *clock.lock().unwrap())), None, HsOps::real()).unwrap(), now)
    }

    #[test]
    fn publish_then_get_round_trips_and_names_no_identity() {
        let (mut dir, _) = store3();
        let d = signed(1, period3(), NOW3 - 10.0, NOW3 + 3000.0, 200);
        assert!(dir.publish(d.clone()).unwrap());
        assert_eq!(dir.get(&d.blinded_public), Some(&d));
        assert_eq!(dir.get(&[0u8; 32]), None);
        assert_eq!(dir.len(), 1);
    }

    #[test]
    fn a_bad_signature_or_tampered_field_is_refused() {
        let (mut dir, _) = store3();
        let good = signed(2, period3(), NOW3 - 10.0, NOW3 + 3000.0, 50);
        for mutate in [
            |d: &mut BlindedDescriptor| d.signature[10] ^= 1,
            |d: &mut BlindedDescriptor| d.ciphertext[0] ^= 1,
            |d: &mut BlindedDescriptor| d.salt[0] ^= 1,
            |d: &mut BlindedDescriptor| d.not_after += 1.0,
            |d: &mut BlindedDescriptor| d.period += 1,
        ] {
            let mut t = good.clone();
            mutate(&mut t);
            assert!(matches!(dir.publish(t), Err(HiddenServiceError::SignatureInvalid(_))));
        }
        // signed by a key other than the one it names
        let mut wrong_key = good.clone();
        wrong_key.blinded_public = signed(3, period3(), 0.0, 1.0, 0).blinded_public;
        assert!(dir.publish(wrong_key).is_err());
        assert!(dir.is_empty());
    }

    #[test]
    fn lifetime_validity_and_period_are_enforced() {
        let (mut dir, _) = store3();
        let p = period3();
        // too long, zero or negative
        assert!(matches!(dir.publish(signed(4, p, NOW3 - 10.0, NOW3 - 10.0 + MAX_HS_DESCRIPTOR_LIFETIME + 1.0, 10)), Err(HiddenServiceError::DescriptorLifetimeTooLong(_))));
        assert!(matches!(dir.publish(signed(4, p, NOW3, NOW3, 10)), Err(HiddenServiceError::DescriptorLifetimeTooLong(_))));
        assert!(matches!(dir.publish(signed(4, p, NOW3 + 100.0, NOW3 + 50.0, 10)), Err(HiddenServiceError::DescriptorLifetimeTooLong(_))));
        // not yet valid / already expired
        assert!(matches!(dir.publish(signed(5, p, NOW3 + 1000.0, NOW3 + 2000.0, 10)), Err(HiddenServiceError::DescriptorExpired(_))));
        assert!(matches!(dir.publish(signed(5, p, NOW3 - 2000.0, NOW3 - 1000.0, 10)), Err(HiddenServiceError::DescriptorExpired(_))));
        // the current and adjacent periods are accepted; others are not
        for (secret, period, ok) in [(6u8, p, true), (7, p + 1, true), (8, p - 1, true), (9, p + 2, false), (10, p - 2, false), (11, p + 1000, false)] {
            assert_eq!(dir.publish(signed(secret, period, NOW3 - 10.0, NOW3 + 3000.0, 10)).is_ok(), ok, "period offset {}", period - p);
        }
    }

    #[test]
    fn a_newer_descriptor_replaces_an_older_one_and_an_older_one_is_ignored() {
        let (mut dir, _) = store3();
        let p = period3();
        let old = signed(12, p, NOW3 - 500.0, NOW3 + 3000.0, 100);
        let newer = signed(12, p, NOW3 - 100.0, NOW3 + 3000.0, 300);
        assert!(dir.publish(old.clone()).unwrap());
        assert!(dir.publish(newer.clone()).unwrap());
        assert_eq!(dir.get(&newer.blinded_public), Some(&newer));
        assert!(!dir.publish(old).unwrap(), "an older one must not displace it");
        assert_eq!(dir.get(&newer.blinded_public), Some(&newer));
        assert_eq!(dir.stored_bytes, 300, "replacing must adjust the byte count");
    }

    #[test]
    fn expiry_hides_a_descriptor_and_prune_releases_its_bytes_and_quota() {
        let (mut dir, now) = store3();
        let d = signed(13, period3(), NOW3 - 10.0, NOW3 + 100.0, 64);
        dir.publish_from(d.clone(), Some("10.0.0.0/24")).unwrap();
        assert_eq!(dir.stored_bytes, 64);
        *now.lock().unwrap() = NOW3 + 200.0;
        assert_eq!(dir.get(&d.blinded_public), None, "expired descriptors are not served");
        assert_eq!(dir.prune(), 1);
        assert_eq!((dir.stored_bytes, dir.by_key.len(), dir.per_source.len(), dir.source_of.len()), (0, 0, 0, 0));
        assert!(dir.meta.is_empty(), "prune also forgets tenure");
    }

    #[test]
    fn a_source_is_limited_and_another_is_not() {
        let p = period3();
        let (mut dir, _) = store3();
        let mut keys = Vec::new();
        for i in 0..=(MAX_BLINDED_PER_SOURCE as u16) {
            use ed25519_dalek::{Signer, SigningKey};
            let mut seed = [0u8; 32];
            seed[..2].copy_from_slice(&i.to_be_bytes());
            let key = SigningKey::from_bytes(&seed);
            let mut d = BlindedDescriptor {
                blinded_public: key.verifying_key().to_bytes(),
                period: p,
                not_before: NOW3 - 10.0,
                not_after: NOW3 + 3000.0,
                salt: [0u8; crate::dirwire::BLINDED_SALT_LEN],
                ciphertext: vec![1u8; 4],
                signature: Vec::new(),
            };
            d.signature = key.sign(&d.signing_payload()).to_bytes().to_vec();
            keys.push(d);
        }
        for d in &keys[..MAX_BLINDED_PER_SOURCE] {
            assert!(dir.publish_from(d.clone(), Some("10.0.0.0/24")).unwrap());
        }
        let over = dir.publish_from(keys[MAX_BLINDED_PER_SOURCE].clone(), Some("10.0.0.0/24"));
        assert!(matches!(over, Err(HiddenServiceError::SourceQuotaExceeded(_))), "{over:?}");
        assert!(dir.publish_from(keys[MAX_BLINDED_PER_SOURCE].clone(), Some("10.0.1.0/24")).unwrap(), "another source is unaffected");
        // replacing a key it already holds is never refused by its quota
        let mut refreshed = keys[0].clone();
        refreshed.not_before += 1.0;
        {
            use ed25519_dalek::{Signer, SigningKey};
            let mut seed = [0u8; 32];
            seed[..2].copy_from_slice(&0u16.to_be_bytes());
            refreshed.signature = SigningKey::from_bytes(&seed).sign(&refreshed.signing_payload()).to_bytes().to_vec();
        }
        assert!(dir.publish_from(refreshed, Some("10.0.0.0/24")).unwrap());
        // publish() with no source carries no quota
        assert!(dir.publish(signed(200, p, NOW3 - 10.0, NOW3 + 3000.0, 4)).unwrap());
    }

    /// A signed descriptor for the `n`-th distinct key (up to 2^32).
    fn signed_n(n: u32, period: i64, not_before: f64, not_after: f64, ct_len: usize) -> BlindedDescriptor {
        use ed25519_dalek::{Signer, SigningKey};
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&n.to_be_bytes());
        seed[31] = 0xA5;
        let key = SigningKey::from_bytes(&seed);
        let mut d = BlindedDescriptor {
            blinded_public: key.verifying_key().to_bytes(),
            period,
            not_before,
            not_after,
            salt: [0u8; crate::dirwire::BLINDED_SALT_LEN],
            ciphertext: vec![1u8; ct_len],
            signature: Vec::new(),
        };
        d.signature = key.sign(&d.signing_payload()).to_bytes().to_vec();
        d
    }

    #[test]
    fn the_byte_budget_bounds_total_storage_by_evicting_the_oldest() {
        let (mut dir, _) = store3();
        dir.max_store_bytes = 1000;
        let p = period3();
        let a = signed(20, p, NOW3 - 30.0, NOW3 + 3000.0, 600);
        let b = signed(21, p, NOW3 - 20.0, NOW3 + 3000.0, 400);
        assert!(dir.publish(a.clone()).unwrap());
        assert!(dir.publish(b.clone()).unwrap());
        assert_eq!(dir.stored_bytes, 1000);
        // 500 more bytes do not fit: the oldest (a, 600 bytes) goes, b stays
        let c = signed(22, p, NOW3 - 10.0, NOW3 + 3000.0, 500);
        assert!(dir.publish(c.clone()).unwrap(), "a full store admits a newcomer by evicting, it does not refuse");
        assert_eq!((dir.get(&a.blinded_public), dir.get(&b.blinded_public)), (None, Some(&b)));
        assert_eq!(dir.get(&c.blinded_public), Some(&c));
        assert_eq!((dir.stored_bytes, dir.by_key.len()), (900, 2));
        // growing an existing entry past the budget evicts others, never itself
        let bigger = signed(22, p, NOW3 - 5.0, NOW3 + 3000.0, 700);
        assert!(dir.publish(bigger.clone()).unwrap());
        assert_eq!(dir.get(&bigger.blinded_public), Some(&bigger));
        assert_eq!(dir.get(&b.blinded_public), None, "b was older than the grown entry and made way");
        assert_eq!(dir.stored_bytes, 700);
        // an entry's own replacement may shrink it
        assert!(dir.publish(signed(22, p, NOW3 - 4.0, NOW3 + 3000.0, 100)).unwrap());
        assert_eq!(dir.stored_bytes, 100);
    }

    #[test]
    fn a_descriptor_bigger_than_the_whole_budget_is_refused_and_evicts_nothing() {
        let (mut dir, _) = store3();
        dir.max_store_bytes = 1000;
        let p = period3();
        let held = signed(30, p, NOW3 - 10.0, NOW3 + 3000.0, 800);
        assert!(dir.publish(held.clone()).unwrap());
        assert!(matches!(dir.publish(signed(31, p, NOW3 - 5.0, NOW3 + 3000.0, 1001)), Err(HiddenServiceError::StoreFull(_))));
        assert_eq!(dir.get(&held.blinded_public), Some(&held), "a refused descriptor must not push anyone out");
        assert_eq!(dir.stored_bytes, 800);
    }

    #[test]
    fn the_entry_cap_defaults_to_the_published_constant() {
        let (dir, _) = store3();
        assert_eq!((dir.max_entries, MAX_HS_DESCRIPTORS), (MAX_HS_DESCRIPTORS, 4096));
    }

    #[test]
    fn a_full_entry_table_admits_a_newcomer_by_evicting_the_oldest_only() {
        let (mut dir, _) = store3();
        dir.max_entries = 20;
        let p = period3();
        // fill to the cap; entry i was published i/2 seconds after entry 0
        for i in 0..20u32 {
            assert!(dir.publish(signed_n(i, p, NOW3 - 3000.0 + i as f64 * 0.5, NOW3 + 3000.0, 4)).unwrap());
        }
        assert_eq!(dir.by_key.len(), 20);
        let honest = signed_n(900_000, p, NOW3 - 1.0, NOW3 + 3000.0, 4);
        assert!(dir.publish(honest.clone()).unwrap(), "a newcomer is not refused just because the table is full");
        assert_eq!(dir.by_key.len(), 20, "the cap still holds");
        assert_eq!(dir.get(&honest.blinded_public), Some(&honest));
        assert_eq!(dir.get(&signed_n(0, p, NOW3 - 3000.0, NOW3 + 3000.0, 4).blinded_public), None, "the oldest entry made way");
        assert!(dir.get(&signed_n(1, p, NOW3 - 3000.0 + 0.5, NOW3 + 3000.0, 4).blinded_public).is_some(), "only one entry was evicted");
    }

    #[test]
    fn a_flood_degrades_a_service_but_never_locks_it_out() {
        let (mut dir, now) = store3();
        dir.max_entries = 50;
        let p = period3();
        let honest_key = signed_n(777, p, NOW3, NOW3 + 3000.0, 4).blinded_public;
        let mut t = NOW3;
        let mut junk = 10_000u32;
        let mut flood = |dir: &mut BlindedHsDirectory, t: f64, count: u32| {
            for i in 0..count {
                junk += 1;
                dir.publish(signed_n(junk, p, t - 4.0 + i as f64 * 0.001, t + 3000.0, 4)).expect("a flood key is never refused either");
            }
        };
        let republish = |dir: &mut BlindedHsDirectory, t: f64| {
            let honest = signed_n(777, p, t - 5.0, t + 3000.0, 4);
            assert!(dir.publish(honest).unwrap(), "the honest republish must always be accepted");
            assert!(dir.get(&honest_key).is_some());
        };
        // round 1: a flood smaller than the table: the service is untouched
        t += 1200.0;
        *now.lock().unwrap() = t;
        republish(&mut dir, t);
        flood(&mut dir, t, 30);
        assert!(dir.get(&honest_key).is_some(), "a flood smaller than the table pushes nobody honest out");
        // round 2: a flood bigger than the whole table: the service is evicted ...
        t += 1200.0;
        *now.lock().unwrap() = t;
        flood(&mut dir, t, 120);
        assert!(dir.get(&honest_key).is_none(), "a flood that turns the whole table over does evict it (degradation)");
        assert_eq!(dir.by_key.len(), 50, "memory stayed bounded throughout");
        // ... and its next republish, 20 minutes later, is accepted again
        t += 1200.0;
        *now.lock().unwrap() = t;
        republish(&mut dir, t);
    }

    #[test]
    fn expired_entries_are_evicted_before_live_ones() {
        let (mut dir, now) = store3();
        dir.max_store_bytes = 1000;
        let p = period3();
        let live_old = signed(40, p, NOW3 - 100.0, NOW3 + 3000.0, 500);
        let soon_dead = signed(41, p, NOW3 - 50.0, NOW3 + 100.0, 500); // published later than live_old
        assert!(dir.publish(live_old.clone()).unwrap());
        assert!(dir.publish(soon_dead.clone()).unwrap());
        *now.lock().unwrap() = NOW3 + 200.0; // soon_dead has now expired; live_old has not
        let newcomer = signed(42, p, NOW3 + 190.0, NOW3 + 3000.0, 500);
        assert!(dir.publish(newcomer.clone()).unwrap());
        assert_eq!(dir.get(&live_old.blinded_public), Some(&live_old), "a live entry is kept");
        assert!(!dir.by_key.contains_key(&soon_dead.blinded_public), "the expired one was the victim, though it was newer");
    }

    #[test]
    fn republishing_a_held_key_into_a_full_table_evicts_nobody() {
        let (mut dir, _) = store3();
        dir.max_entries = 20;
        let p = period3();
        for i in 0..20u32 {
            dir.publish(signed_n(i, p, NOW3 - 3000.0 + i as f64 * 0.5, NOW3 + 3000.0, 4)).unwrap();
        }
        // the oldest key refreshes itself: it stays, and nothing else is pushed out
        let refreshed = signed_n(0, p, NOW3 - 1.0, NOW3 + 3000.0, 4);
        assert!(dir.publish(refreshed.clone()).unwrap());
        assert_eq!(dir.by_key.len(), 20);
        assert_eq!(dir.get(&refreshed.blinded_public), Some(&refreshed));
        assert!(dir.get(&signed_n(1, p, NOW3 - 3000.0 + 0.5, NOW3 + 3000.0, 4).blinded_public).is_some());
    }

    #[test]
    fn evicting_an_entry_releases_its_source_quota() {
        let (mut dir, _) = store3();
        dir.max_store_bytes = 100;
        let p = period3();
        let old = signed(50, p, NOW3 - 30.0, NOW3 + 3000.0, 60);
        assert!(dir.publish_from(old.clone(), Some("10.0.0.0/24")).unwrap());
        assert_eq!(dir.per_source.get("10.0.0.0/24"), Some(&1));
        assert!(dir.publish_from(signed(51, p, NOW3 - 10.0, NOW3 + 3000.0, 60), Some("10.0.1.0/24")).unwrap());
        assert!(!dir.by_key.contains_key(&old.blinded_public));
        assert_eq!(dir.per_source.get("10.0.0.0/24"), None, "the evicted entry no longer counts against its source");
        assert_eq!(dir.per_source.get("10.0.1.0/24"), Some(&1));
        assert_eq!((dir.source_of.len(), dir.stored_bytes), (1, 60));
    }

    #[test]
    fn the_default_lifetime_cap_leaves_room_for_honest_services_but_not_a_day() {
        let (mut dir, _) = store3();
        let p = period3();
        let honest = DEFAULT_HS_DESCRIPTOR_LIFETIME;
        assert!(dir.publish(signed_n(60, p, NOW3 - 10.0, NOW3 - 10.0 + honest, 4)).unwrap(), "the honest one-hour lifetime");
        assert!(dir.publish(signed_n(61, p, NOW3 - 10.0, NOW3 - 10.0 + MAX_BLINDED_DESCRIPTOR_LIFETIME, 4)).unwrap(), "exactly the cap");
        for too_long in [MAX_BLINDED_DESCRIPTOR_LIFETIME + 1.0, MAX_HS_DESCRIPTOR_LIFETIME] {
            let r = dir.publish(signed_n(62, p, NOW3 - 10.0, NOW3 - 10.0 + too_long, 4));
            assert!(matches!(r, Err(HiddenServiceError::DescriptorLifetimeTooLong(_))), "{too_long}s: {r:?}");
        }
        assert_eq!(MAX_BLINDED_DESCRIPTOR_LIFETIME, 7200.0);
    }

    // -- tenure-aware eviction ----------------------------------------------

    fn at(now: &Arc<std::sync::Mutex<f64>>, t: f64) {
        *now.lock().unwrap() = t;
    }

    /// Publish key `n` as seen at time `t` (valid for 50 minutes, newer each time).
    fn pubk(dir: &mut BlindedHsDirectory, n: u32, t: f64) -> bool {
        dir.publish(signed_n(n, period3(), t - 5.0, t + 3000.0, 4)).unwrap()
    }

    fn has(dir: &BlindedHsDirectory, n: u32) -> bool {
        dir.by_key.contains_key(&signed_n(n, period3(), 0.0, 1.0, 4).blinded_public)
    }

    fn meta_of(dir: &BlindedHsDirectory, n: u32) -> Option<EntryMeta> {
        dir.meta.get(&signed_n(n, period3(), 0.0, 1.0, 4).blinded_public).copied()
    }

    fn assert_meta_matches(dir: &BlindedHsDirectory) {
        assert_eq!(dir.meta.len(), dir.by_key.len(), "tenure records and entries must be the same set");
        assert!(dir.by_key.keys().all(|k| dir.meta.contains_key(k)));
    }

    /// A store of `cap` entries holding `honest` services (keys 0..honest) that
    /// were published at the start and refreshed 1200 s later; the clock is
    /// left at that refresh time. Returns the store, the clock and that time.
    fn store_with_established(cap: usize, honest: u32) -> (BlindedHsDirectory, Arc<std::sync::Mutex<f64>>, f64) {
        let (mut dir, now) = store3();
        dir.max_entries = cap;
        for n in 0..honest {
            at(&now, NOW3 + n as f64); // distinct first_seen: key 0 is the most senior
            assert!(pubk(&mut dir, n, NOW3 + n as f64));
        }
        let t = NOW3 + 1200.0;
        at(&now, t);
        for n in 0..honest {
            assert!(pubk(&mut dir, n, t));
            assert!(meta_of(&dir, n).unwrap().proven(), "key {n} was refreshed 20 minutes later");
        }
        (dir, now, t)
    }

    #[test]
    fn services_that_have_been_refreshed_survive_a_flood_that_turns_the_whole_table_over() {
        let (mut dir, now, t) = store_with_established(20, 8);
        at(&now, t + 10.0);
        for i in 0..300u32 {
            pubk(&mut dir, 10_000 + i, t + 10.0);
        }
        assert_eq!(dir.by_key.len(), 20, "memory stayed bounded");
        for n in 0..8 {
            assert!(has(&dir, n), "established service {n} must not be pushed out by one-shot identities");
        }
        assert_eq!(dir.by_key.keys().filter(|k| !dir.meta[*k].proven()).count(), 12, "the flood only evicted other newcomers");
        assert_meta_matches(&dir);
    }

    #[test]
    fn a_burst_of_republishes_does_not_make_an_entry_established_but_one_refresh_after_the_gap_does() {
        let (mut dir, now) = store3();
        dir.max_entries = 20;
        at(&now, NOW3);
        assert!(pubk(&mut dir, 1, NOW3) && pubk(&mut dir, 2, NOW3));
        // key 1 republishes often, but never 10 minutes after its last counted publish
        for dt in [100.0, 200.0, 300.0, 400.0, 500.0, 599.0] {
            at(&now, NOW3 + dt);
            assert!(pubk(&mut dir, 1, NOW3 + dt));
        }
        assert_eq!(meta_of(&dir, 1).unwrap().refreshes, 0, "a burst is not a refresh");
        // key 2 republishes once, after the gap
        at(&now, NOW3 + 601.0);
        assert!(pubk(&mut dir, 2, NOW3 + 601.0));
        assert_eq!(meta_of(&dir, 2).unwrap().refreshes, 1);
        assert_eq!(meta_of(&dir, 2).unwrap().first_seen, NOW3, "tenure keeps counting from the first publish");
        // a flood arrives
        at(&now, NOW3 + 650.0);
        for i in 0..60u32 {
            pubk(&mut dir, 10_000 + i, NOW3 + 650.0);
        }
        assert!(has(&dir, 2), "the refreshed one stays");
        assert!(!has(&dir, 1), "the one that only republished in a burst was treated as a newcomer and evicted");
        assert_meta_matches(&dir);
    }

    #[test]
    fn once_the_newcomer_reserve_is_full_newcomers_are_evicted_oldest_first_and_established_entries_are_untouched() {
        let (mut dir, now, t) = store_with_established(20, 8);
        // 12 newcomers fill the table; the reserve is 20 / 4 = 5, so there are more than enough
        for i in 0..12u32 {
            at(&now, t + 10.0 + i as f64);
            assert!(pubk(&mut dir, 500 + i, t + 10.0 + i as f64));
        }
        assert_eq!(dir.by_key.len(), 20);
        at(&now, t + 100.0);
        assert!(pubk(&mut dir, 900, t + 100.0));
        assert!(!has(&dir, 500), "the oldest newcomer went first");
        assert!(has(&dir, 501) && has(&dir, 511), "the others stayed");
        assert!(pubk(&mut dir, 901, t + 101.0));
        assert!(!has(&dir, 501));
        for n in 0..8 {
            assert!(has(&dir, n));
        }
        assert_meta_matches(&dir);
    }

    #[test]
    fn a_store_full_of_established_entries_still_admits_a_newcomer_by_evicting_the_shortest_tenure() {
        let (mut dir, now, t) = store_with_established(20, 20);
        assert_eq!(dir.by_key.len(), 20);
        at(&now, t + 10.0);
        assert!(pubk(&mut dir, 900, t + 10.0), "newcomers are never turned away");
        assert!(!has(&dir, 19), "the shortest-tenured established service made way");
        assert!(has(&dir, 0) && has(&dir, 18), "the longer-standing ones stayed");
        // the reserve is 5 and only one newcomer is held: the next newcomer again displaces
        // an established entry rather than the first newcomer
        assert!(pubk(&mut dir, 901, t + 11.0));
        assert!(!has(&dir, 18) && has(&dir, 900) && has(&dir, 901));
        assert!(has(&dir, 0), "the longest-standing service is the last to go");
        assert_meta_matches(&dir);
    }

    #[test]
    fn the_newcomer_reserve_is_protected_from_established_entries() {
        let (mut dir, now, t) = store_with_established(20, 18);
        // two newcomers: below the reserve of 5
        at(&now, t + 10.0);
        assert!(pubk(&mut dir, 800, t + 10.0) && pubk(&mut dir, 801, t + 10.0));
        assert_eq!(dir.by_key.len(), 20);
        at(&now, t + 20.0);
        assert!(pubk(&mut dir, 900, t + 20.0));
        assert!(has(&dir, 800) && has(&dir, 801), "the two held newcomers are inside the reserve and stay");
        assert!(!has(&dir, 17), "an established entry (the shortest-tenured) paid for the newcomer instead");
    }

    #[test]
    fn expired_entries_go_before_established_ones_and_before_newcomers() {
        let (mut dir, now) = store3();
        dir.max_entries = 4;
        at(&now, NOW3);
        // key 0 expires at NOW3 + 100; keys 1..=3 live 3000 s
        assert!(dir.publish(signed_n(0, period3(), NOW3 - 5.0, NOW3 + 100.0, 4)).unwrap());
        for n in 1..4 {
            assert!(pubk(&mut dir, n, NOW3));
        }
        at(&now, NOW3 + 650.0);
        for n in 1..4 {
            assert!(pubk(&mut dir, n, NOW3 + 650.0)); // all three refreshed
        }
        assert!(pubk(&mut dir, 900, NOW3 + 651.0));
        assert!(!has(&dir, 0), "the expired entry was the victim");
        assert!(has(&dir, 1) && has(&dir, 2) && has(&dir, 3) && has(&dir, 900));
    }

    #[test]
    fn tenure_is_kept_across_republishes_and_lost_with_the_entry() {
        let (dir, _, _) = store_with_established(20, 3);
        assert_eq!(meta_of(&dir, 0).unwrap().first_seen, NOW3, "republishing does not reset tenure");
        // a table of 3 established services: a newcomer evicts the shortest-tenured one (key 2)
        let (mut dir2, now2, t2) = store_with_established(3, 3);
        at(&now2, t2 + 1.0);
        assert!(pubk(&mut dir2, 900, t2 + 1.0));
        assert!(!has(&dir2, 2) && meta_of(&dir2, 2).is_none(), "an evicted entry's tenure record goes with it");
        // it comes back (evicting someone else) as a brand-new entry
        at(&now2, t2 + 2.0);
        assert!(pubk(&mut dir2, 2, t2 + 2.0));
        let back = meta_of(&dir2, 2).unwrap();
        assert_eq!((back.refreshes, back.first_seen), (0, t2 + 2.0), "coming back is a fresh start, not the old tenure");
        assert_meta_matches(&dir2);
        assert_meta_matches(&dir);
    }

    #[test]
    fn an_attacker_whose_junk_is_also_refreshed_still_cannot_displace_services_that_were_there_first() {
        let (mut dir, now, t0) = store_with_established(20, 8);
        let mut t = t0;
        let mut next = 20_000u32;
        for _round in 0..6 {
            // the attacker mints a batch of fresh identities and keeps each one "established"
            let batch: Vec<u32> = (0..15).map(|_| { next += 1; next }).collect();
            t += 100.0;
            at(&now, t);
            for &n in &batch {
                pubk(&mut dir, n, t);
            }
            t += 650.0;
            at(&now, t);
            for &n in &batch {
                pubk(&mut dir, n, t); // a refresh, 650 s later
            }
            // the honest services keep refreshing on their own schedule
            for n in 0..8 {
                pubk(&mut dir, n, t);
            }
        }
        for n in 0..8 {
            assert!(has(&dir, n), "service {n}, which was here first, must still be held");
            assert_eq!(meta_of(&dir, n).unwrap().first_seen, NOW3 + n as f64, "and it kept its original tenure");
        }
        assert_eq!(dir.by_key.len(), 20);
        assert_meta_matches(&dir);
    }
}
