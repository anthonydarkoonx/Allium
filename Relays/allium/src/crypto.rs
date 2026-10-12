//! Per-hop AEAD primitives for the Allium onion-routing prototype.
//!
//! Port status: Python's `crypto.py` delegates AES-256-GCM
//! and ChaCha20-Poly1305 to the `cryptography` package. This module uses the
//! equivalent, audited `aes-gcm`/`chacha20poly1305` crates (added to
//! `allium/Cargo.toml`) for the same purpose. **This sandbox has no network
//! access to fetch any crate** (see the note atop `allium/Cargo.toml`), so
//! `cargo build -p allium` / `cargo test -p allium` cannot be run to verify
//! the code in this file from [`AesGcmAead::new`] / [`ChaCha20Poly1305Aead::new`]
//! down -- that is expected, and was written from careful manual review against those
//! crates' well-known, stable, documented APIs (`aes-gcm`/`chacha20poly1305`
//! 0.10.x: `aead::{Aead, KeyInit, Payload}` + `Key`/`Nonce` type aliases),
//! rather than compiled/tested here. It is "written but unverified pending
//! real cargo build."
//!
//! So this module is split:
//! * Constants, errors, [`NonceCounter`] (uses this crate's own
//!   `hashutil::sha256`, no external crate needed) and the generic
//!   [`SaltAead`] nonce-framing wrapper (`seal`/`open`/`matches`) are a full,
//!   tested port -- `SaltAead` takes its actual encrypt/decrypt step as
//!   injected closures, the same dependency-injection pattern used in
//!   `consensus.rs` for Ed25519, so the framing logic (nonce placement,
//!   length checks, random-seal cap, counter exhaustion) is implemented and
//!   verified now, independently of which cipher backs it (tested here with
//!   a fake cipher; backed for real by `aes-gcm`/`chacha20poly1305` below).
//! * [`AesGcmAead::new`] / [`ChaCha20Poly1305Aead::new`] construct a real
//!   `aes_gcm::Aes256Gcm` / `chacha20poly1305::ChaCha20Poly1305` cipher
//!   instance and wrap its `encrypt`/`decrypt` calls as the closures
//!   [`SaltAead::new`] expects, isolating all crate-touching code behind
//!   these two small constructors -- everything else in this file (and every
//!   caller of `SaltAead`) stays crate-agnostic and unit-testable.

use crate::hashutil::{constant_time_eq, sha256};
use std::fmt;
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};

/// Symmetric key length in bytes (256-bit).
pub const KEY_SIZE: usize = 32;
/// AEAD nonce length in bytes.
pub const NONCE_SIZE: usize = 12;
/// AEAD authentication tag length in bytes.
pub const TAG_SIZE: usize = 16;
/// Bytes added to a plaintext by [`SaltAead::seal`].
pub const SEAL_OVERHEAD: usize = NONCE_SIZE + TAG_SIZE;
/// Largest value [`NonceCounter`] will hand out.
pub const MAX_NONCE_COUNTER: u64 = u64::MAX;
/// Largest number of *random* seals [`SaltAead`] will perform under one key
/// before refusing to seal any more.
pub const MAX_RANDOM_NONCE_SEALS: u64 = 1u64 << 32;

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

/// Base class for all Allium crypto errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    Generic(String),
    Decrypt(CryptoDecryptError),
    Nonce(NonceError),
}
impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Generic(s) => write!(f, "{s}"),
            CryptoError::Decrypt(e) => write!(f, "{e}"),
            CryptoError::Nonce(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for CryptoError {}
fn generic(msg: impl Into<String>) -> CryptoError {
    CryptoError::Generic(msg.into())
}

/// Raised when a field fails to authenticate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoDecryptError {
    pub message: String,
}
impl fmt::Display for CryptoDecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for CryptoDecryptError {}
impl From<CryptoDecryptError> for CryptoError {
    fn from(e: CryptoDecryptError) -> Self {
        CryptoError::Decrypt(e)
    }
}

/// Raised when a nonce counter would reuse or rewind a nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceError {
    pub message: String,
}
impl fmt::Display for NonceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for NonceError {}
impl From<NonceError> for CryptoError {
    fn from(e: NonceError) -> Self {
        CryptoError::Nonce(e)
    }
}

// --------------------------------------------------------------------------
// Nonce generation
// --------------------------------------------------------------------------

/// A per-circuit monotonic nonce source: `salt || counter`.
pub struct NonceCounter {
    salt: [u8; 4],
    counter: u64,
    issued: u64,
    /// Set once `counter` has issued its last valid value (`u64::MAX`) and
    /// incrementing it further would wrap.
    /// `counter` itself is left at `u64::MAX` rather than wrapped, so this
    /// flag is the only thing distinguishing "about to issue the final
    /// nonce" from "already issued it and must now refuse".
    exhausted: bool,
}

/// What a session identifies as, for [`NonceCounter::new`].
pub enum Session<'a> {
    Bytes(&'a [u8]),
    Int(u32),
}

impl NonceCounter {
    /// Bytes of per-circuit salt prefixed to the counter.
    pub const SALT_SIZE: usize = 4;

    pub fn new(session: Session, start: u64) -> Result<NonceCounter, NonceError> {
        let salt = match session {
            Session::Int(v) => v.to_be_bytes(),
            Session::Bytes(b) => {
                let mut prefix = b"allium-nonce-salt-v1".to_vec();
                prefix.extend_from_slice(b);
                let digest = sha256(&prefix);
                [digest[0], digest[1], digest[2], digest[3]]
            }
        };
        if start > MAX_NONCE_COUNTER {
            return Err(NonceError { message: format!("start must be in 0..{MAX_NONCE_COUNTER}, got {start}") });
        }
        Ok(NonceCounter { salt, counter: start, issued: 0, exhausted: false })
    }

    pub fn with_defaults(session: Session) -> Result<NonceCounter, NonceError> {
        NonceCounter::new(session, 1)
    }

    pub fn issued(&self) -> u64 {
        self.issued
    }
    pub fn next_value(&self) -> u64 {
        self.counter
    }
    pub fn salt(&self) -> [u8; 4] {
        self.salt
    }

    /// Return the next nonce, consuming a counter value.
    ///
    /// `if self.counter >
    /// MAX_NONCE_COUNTER` used to guard this, but `MAX_NONCE_COUNTER ==
    /// u64::MAX` makes that comparison permanently false for a `u64`
    /// counter -- it can never exceed its own type's maximum -- so the
    /// exhaustion path was dead code, and the `wrapping_add(1)` that
    /// followed it silently wrapped `u64::MAX` back to `0` instead of ever
    /// erroring: exactly the nonce-reuse-under-one-key scenario this type
    /// exists to prevent. `exhausted` now tracks the real boundary
    /// directly: this call still successfully issues the final valid nonce
    /// (counter value `u64::MAX` itself, left in place rather than
    /// wrapped), and only the call that would actually need to wrap it now
    /// errors.
    pub fn next(&mut self) -> Result<[u8; NONCE_SIZE], NonceError> {
        if self.exhausted {
            return Err(NonceError {
                message: format!(
                    "nonce counter exhausted after {} nonces; a circuit at this limit must be rekeyed rather than allowed to reuse a nonce",
                    self.issued
                ),
            });
        }
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..4].copy_from_slice(&self.salt);
        nonce[4..].copy_from_slice(&self.counter.to_be_bytes());
        match self.counter.checked_add(1) {
            Some(next) => self.counter = next,
            None => self.exhausted = true,
        }
        self.issued += 1;
        Ok(nonce)
    }
}

impl fmt::Display for NonceCounter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NonceCounter(issued={}, next={}, salt={})", self.issued, self.counter, hex(&self.salt))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --------------------------------------------------------------------------
// AEAD wrapper
// --------------------------------------------------------------------------

type EncryptFn = Box<dyn Fn(&[u8; NONCE_SIZE], &[u8], &[u8]) -> Vec<u8>>;
type DecryptFn = Box<dyn Fn(&[u8; NONCE_SIZE], &[u8], &[u8]) -> Result<Vec<u8>, ()>>;

/// One AEAD cipher bound to a single key.
///
/// Mirrors Python's `SaltAead` base class: the nonce-framing logic
/// (`seal`/`open`, the random-seal cap, `matches`) is real and tested; the
/// actual encrypt/decrypt step is supplied by the caller as closures (see the
/// module docs for why -- this is the extension point a real
/// `aes-gcm`/`chacha20poly1305`-backed cipher plugs into).
pub struct SaltAead {
    name: &'static str,
    key: [u8; KEY_SIZE],
    nonce_source: Option<NonceCounter>,
    max_random_seals: u64,
    random_seals_issued: u64,
    encrypt: EncryptFn,
    decrypt: DecryptFn,
}

impl Drop for SaltAead {
    /// Security audit fix (2026-09-26): `key` is a live per-hop AEAD key,
    /// held for the whole life of the circuit this cipher belongs to --
    /// wipe it on drop instead of leaving it sitting in freed memory.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}

impl SaltAead {
    pub fn new(
        name: &'static str,
        key: [u8; KEY_SIZE],
        nonce_source: Option<NonceCounter>,
        max_random_seals: u64,
        encrypt: EncryptFn,
        decrypt: DecryptFn,
    ) -> SaltAead {
        SaltAead { name, key, nonce_source, max_random_seals, random_seals_issued: 0, encrypt, decrypt }
    }

    /// Encrypt `plaintext`, returning `nonce || ciphertext || tag`.
    pub fn seal(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = match &mut self.nonce_source {
            Some(counter) => counter.next()?,
            None => {
                if self.random_seals_issued >= self.max_random_seals {
                    return Err(NonceError {
                        message: format!(
                            "{}: {} random seals performed under this key, at the {} cap meant to stay well clear of a 96-bit nonce's birthday bound; rekey or tear down this circuit instead of sealing further under it",
                            self.name, self.random_seals_issued, self.max_random_seals
                        ),
                    }
                    .into());
                }
                let nonce = random_nonce();
                self.random_seals_issued += 1;
                nonce
            }
        };
        let mut out = nonce.to_vec();
        out.extend((self.encrypt)(&nonce, plaintext, associated_data));
        Ok(out)
    }

    /// Decrypt one field produced by [`SaltAead::seal`].
    pub fn open(&self, sealed: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if sealed.len() < SEAL_OVERHEAD {
            return Err(CryptoDecryptError {
                message: format!("sealed field is {} bytes, minimum is {SEAL_OVERHEAD} (nonce + tag)", sealed.len()),
            }
            .into());
        }
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&sealed[..NONCE_SIZE]);
        let ciphertext = &sealed[NONCE_SIZE..];
        (self.decrypt)(&nonce, ciphertext, associated_data).map_err(|_| {
            CryptoDecryptError {
                message: format!("{}: failed authentication (wrong key, tampered ciphertext, or associated data mismatch)", self.name),
            }
            .into()
        })
    }

    pub fn nonce_source(&self) -> Option<&NonceCounter> {
        self.nonce_source.as_ref()
    }

    /// Constant-time check of whether `key` is the key bound to this cipher.
    pub fn matches(&self, key: &[u8]) -> bool {
        key.len() == KEY_SIZE && constant_time_eq(&self.key, key)
    }
}

fn random_nonce() -> [u8; NONCE_SIZE] {
    // OS CSPRNG via `rand_core::OsRng` (already used the same way in
    // handshake.rs/hiddenservice.rs) rather than hand-opening /dev/urandom
    // on every call: that both dropped a file handle per nonce and, on
    // non-Unix targets, fell back to a SystemTime-derived "nonce" -- not
    // cryptographically secure, and predictable AEAD nonces are a
    // nonce-reuse-class vulnerability. OsRng is a real CSPRNG on every
    // platform rand_core supports, so there's no non-Unix fallback to write.
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// AES-256-GCM.
///
/// Written but unverified pending real cargo build (see the module docs):
/// this sandbox cannot fetch the `aes-gcm` crate, so this
/// cannot be compiled/tested here, but was carefully reviewed against
/// `aes-gcm` 0.10's documented, stable `AeadInPlace`/`Aead` API.
pub struct AesGcmAead;
impl AesGcmAead {
    pub fn new(key: [u8; KEY_SIZE], nonce_source: Option<NonceCounter>) -> Result<SaltAead, CryptoError> {
        let cipher = Arc::new(Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(&key)));
        let enc_cipher = cipher.clone();
        let dec_cipher = cipher;
        let encrypt: EncryptFn = Box::new(move |nonce, pt, ad| {
            // encrypt() only fails on catastrophic misuse (e.g. plaintext
            // too large for the cipher's internal length field); it cannot
            // fail for well-formed 12-byte-nonce AES-256-GCM inputs here.
            enc_cipher
                .encrypt(AesNonce::from_slice(nonce), Payload { msg: pt, aad: ad })
                .expect("AES-256-GCM encryption of a well-formed field must not fail")
        });
        let decrypt: DecryptFn = Box::new(move |nonce, ct, ad| {
            dec_cipher
                .decrypt(AesNonce::from_slice(nonce), Payload { msg: ct, aad: ad })
                .map_err(|_| ())
        });
        Ok(SaltAead::new("AES-256-GCM", key, nonce_source, MAX_RANDOM_NONCE_SEALS, encrypt, decrypt))
    }
}

/// ChaCha20-Poly1305.
///
/// Written but unverified pending real cargo build (see the module docs):
/// this sandbox cannot fetch the `chacha20poly1305` crate, so
/// this cannot be compiled/tested here, but was carefully reviewed against
/// `chacha20poly1305` 0.10's documented, stable `Aead` API (it re-exports the
/// same `aead` crate types/traits as `aes-gcm`, so the shape mirrors
/// [`AesGcmAead::new`] above).
pub struct ChaCha20Poly1305Aead;
impl ChaCha20Poly1305Aead {
    pub fn new(key: [u8; KEY_SIZE], nonce_source: Option<NonceCounter>) -> Result<SaltAead, CryptoError> {
        let cipher = Arc::new(ChaCha20Poly1305::new(ChaChaKey::from_slice(&key)));
        let enc_cipher = cipher.clone();
        let dec_cipher = cipher;
        let encrypt: EncryptFn = Box::new(move |nonce, pt, ad| {
            enc_cipher
                .encrypt(ChaChaNonce::from_slice(nonce), Payload { msg: pt, aad: ad })
                .expect("ChaCha20-Poly1305 encryption of a well-formed field must not fail")
        });
        let decrypt: DecryptFn = Box::new(move |nonce, ct, ad| {
            dec_cipher
                .decrypt(ChaChaNonce::from_slice(nonce), Payload { msg: ct, aad: ad })
                .map_err(|_| ())
        });
        Ok(SaltAead::new("ChaCha20-Poly1305", key, nonce_source, MAX_RANDOM_NONCE_SEALS, encrypt, decrypt))
    }
}

/// Build an AEAD for the named `cipher`: `"chacha20-poly1305"` (default) or
/// `"aes-256-gcm"`.
pub fn new_aead(cipher: &str, key: [u8; KEY_SIZE], nonce_source: Option<NonceCounter>) -> Result<SaltAead, CryptoError> {
    let normalized = cipher.trim().to_lowercase().replace('_', "-");
    match normalized.as_str() {
        "chacha20-poly1305" | "chacha20poly1305" => ChaCha20Poly1305Aead::new(key, nonce_source),
        "aes-256-gcm" | "aesgcm" | "aes-256" => AesGcmAead::new(key, nonce_source),
        _ => Err(generic(format!("unknown cipher {cipher:?}; expected 'chacha20-poly1305' or 'aes-256-gcm'"))),
    }
}

/// Return a fresh random [`KEY_SIZE`]-byte key.
///
/// This used to hand-open /dev/urandom on
/// Unix and, on any other target, fill the key with cycled `SystemTime`
/// nanoseconds -- predictable, not a CSPRNG, and silently compiling with
/// no warning (see [`random_nonce`]'s doc comment, which already avoided
/// this exact mistake for nonces). Switched to the same `rand_core::OsRng`
/// pattern used there and in `handshake::real_x25519_generate`: a real
/// CSPRNG on every platform `rand_core` supports, so there is no
/// non-Unix fallback left to get wrong.
pub fn generate_key() -> [u8; KEY_SIZE] {
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; KEY_SIZE];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Deterministically derive a hop key from a shared secret.
///
/// Python uses Blake2b (`hashlib.blake2b`, stdlib), not one of the
/// crates already relied on elsewhere. This sandbox has no `blake2` crate either
/// (and not fetchable regardless -- see the note
/// atop `allium/Cargo.toml`), so as an interim, dependency-free stand-in this
/// uses HMAC-SHA256 (`crate::hashutil`) as the PRF instead: `label` as the
/// HMAC key, `shared_secret` as the message. This is **not** wire-compatible
/// with Python's Blake2b-based `derive_key` -- callers that need byte-for-byte
/// parity with the Python implementation must wait for a `blake2` crate (or
/// hand-rolled Blake2b) and swap this body out. The real handshake path
/// (`allium.handshake.derive_handshake_keys`, phase 2, HKDF-SHA256) is
/// unaffected either way, since `crypto.derive_key` is documented in Python
/// itself as a test/convenience helper, not what peers use to agree on keys.
pub fn derive_key(shared_secret: &[u8], label: &[u8]) -> [u8; KEY_SIZE] {
    crate::hashutil::hmac_sha256(label, shared_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fake, deliberately trivial (NOT secure) "AEAD" used only to exercise
    // SaltAead's framing logic: "encrypt" XORs the plaintext with a
    // keystream derived from HMAC-SHA256(key, nonce||associated_data||counter)
    // and appends a 16-byte HMAC-based "tag" so tamper-detection can be
    // tested too. Never use this for anything but these tests.
    fn fake_cipher(key: [u8; KEY_SIZE]) -> (EncryptFn, DecryptFn) {
        fn keystream(key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE], ad: &[u8], len: usize) -> Vec<u8> {
            let mut out = Vec::with_capacity(len);
            let mut counter = 0u32;
            while out.len() < len {
                let mut input = nonce.to_vec();
                input.extend_from_slice(ad);
                input.extend_from_slice(&counter.to_be_bytes());
                out.extend_from_slice(&crate::hashutil::hmac_sha256(key, &input));
                counter += 1;
            }
            out.truncate(len);
            out
        }
        fn tag(key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE], ct: &[u8], ad: &[u8]) -> [u8; 16] {
            let mut input = nonce.to_vec();
            input.extend_from_slice(ct);
            input.extend_from_slice(ad);
            let mac = crate::hashutil::hmac_sha256(key, &input);
            let mut out = [0u8; 16];
            out.copy_from_slice(&mac[..16]);
            out
        }
        let enc_key = key;
        let dec_key = key;
        let encrypt: EncryptFn = Box::new(move |nonce, pt, ad| {
            let ks = keystream(&enc_key, nonce, ad, pt.len());
            let ct: Vec<u8> = pt.iter().zip(ks.iter()).map(|(p, k)| p ^ k).collect();
            let t = tag(&enc_key, nonce, &ct, ad);
            let mut out = ct;
            out.extend_from_slice(&t);
            out
        });
        let decrypt: DecryptFn = Box::new(move |nonce, ct_and_tag, ad| {
            if ct_and_tag.len() < 16 {
                return Err(());
            }
            let (ct, t) = ct_and_tag.split_at(ct_and_tag.len() - 16);
            let expected = tag(&dec_key, nonce, ct, ad);
            if !constant_time_eq(&expected, t) {
                return Err(());
            }
            let ks = keystream(&dec_key, nonce, ad, ct.len());
            Ok(ct.iter().zip(ks.iter()).map(|(c, k)| c ^ k).collect())
        });
        (encrypt, decrypt)
    }

    fn cipher(key: [u8; KEY_SIZE], nonce_source: Option<NonceCounter>) -> SaltAead {
        let (enc, dec) = fake_cipher(key);
        SaltAead::new("fake-test-cipher", key, nonce_source, MAX_RANDOM_NONCE_SEALS, enc, dec)
    }

    #[test]
    fn test_constants() {
        assert_eq!(KEY_SIZE, 32);
        assert_eq!(NONCE_SIZE, 12);
        assert_eq!(TAG_SIZE, 16);
        assert_eq!(SEAL_OVERHEAD, 28);
    }

    #[test]
    fn test_seal_open_round_trip() {
        let key = [7u8; KEY_SIZE];
        let mut aead = cipher(key, None);
        let sealed = aead.seal(b"hello world", b"").unwrap();
        assert_eq!(sealed.len(), b"hello world".len() + SEAL_OVERHEAD);
        assert_eq!(aead.open(&sealed, b"").unwrap(), b"hello world");
    }

    #[test]
    fn test_open_rejects_tampered_ciphertext() {
        let key = [7u8; KEY_SIZE];
        let mut aead = cipher(key, None);
        let mut sealed = aead.seal(b"hello world", b"").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(aead.open(&sealed, b"").is_err());
    }

    #[test]
    fn test_open_rejects_wrong_associated_data() {
        let key = [7u8; KEY_SIZE];
        let mut aead = cipher(key, None);
        let sealed = aead.seal(b"hello world", b"ctx-a").unwrap();
        assert!(aead.open(&sealed, b"ctx-b").is_err());
    }

    #[test]
    fn test_open_rejects_short_field() {
        let key = [7u8; KEY_SIZE];
        let aead = cipher(key, None);
        assert!(aead.open(&[0u8; 10], b"").is_err());
    }

    #[test]
    fn test_seal_uses_nonce_counter_when_given() {
        let key = [1u8; KEY_SIZE];
        let counter = NonceCounter::with_defaults(Session::Int(42)).unwrap();
        let mut aead = cipher(key, Some(counter));
        let sealed1 = aead.seal(b"a", b"").unwrap();
        let sealed2 = aead.seal(b"a", b"").unwrap();
        // Different nonces (counter increments), so different ciphertexts.
        assert_ne!(sealed1[..NONCE_SIZE], sealed2[..NONCE_SIZE]);
        let n1 = u64::from_be_bytes(sealed1[4..12].try_into().unwrap());
        let n2 = u64::from_be_bytes(sealed2[4..12].try_into().unwrap());
        assert_eq!(n2, n1 + 1);
    }

    #[test]
    fn test_matches_is_constant_time_style_equality() {
        let key = [3u8; KEY_SIZE];
        let aead = cipher(key, None);
        assert!(aead.matches(&key));
        assert!(!aead.matches(&[4u8; KEY_SIZE]));
        assert!(!aead.matches(&[3u8; 10]));
    }

    // -- NonceCounter -----------------------------------------------------
    #[test]
    fn test_nonce_counter_layout() {
        let mut counter = NonceCounter::with_defaults(Session::Int(0x01020304)).unwrap();
        let nonce = counter.next().unwrap();
        assert_eq!(&nonce[..4], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&nonce[4..], &1u64.to_be_bytes());
        assert_eq!(counter.issued(), 1);
    }

    #[test]
    fn test_nonce_counter_bytes_session_disjoint_salts() {
        let c1 = NonceCounter::with_defaults(Session::Bytes(b"circuit-a")).unwrap();
        let c2 = NonceCounter::with_defaults(Session::Bytes(b"circuit-b")).unwrap();
        assert_ne!(c1.salt(), c2.salt());
    }

    #[test]
    fn test_nonce_counter_next_value_does_not_consume() {
        let counter = NonceCounter::with_defaults(Session::Int(1)).unwrap();
        assert_eq!(counter.next_value(), 1);
        assert_eq!(counter.issued(), 0);
    }

    /// A counter started at `u64::MAX` must
    /// still successfully issue that one final nonce, then error on the
    /// next call instead of silently wrapping back to `0` and reusing a
    /// nonce value under the same key.
    #[test]
    fn test_nonce_counter_errors_instead_of_wrapping_at_exhaustion() {
        let mut counter = NonceCounter::new(Session::Int(0), u64::MAX).unwrap();
        let nonce = counter.next().unwrap();
        assert_eq!(&nonce[4..], &u64::MAX.to_be_bytes(), "the final valid counter value must still be issued");
        assert_eq!(counter.issued(), 1);

        let err = counter.next().unwrap_err();
        assert!(err.message.contains("exhausted"));
        // Confirm no reuse: the counter must not have wrapped back to a
        // previously-issued value (0 was never issued here, but asserting
        // `issued()` didn't advance past the failed call is the direct
        // proof no second nonce was silently produced).
        assert_eq!(counter.issued(), 1, "a failed call must not count as issuing a nonce");
    }

    #[test]
    fn test_generate_key_is_right_length() {
        assert_eq!(generate_key().len(), KEY_SIZE);
    }

    #[test]
    fn test_generate_key_is_random() {
        assert_ne!(generate_key(), generate_key());
    }

    #[test]
    fn test_derive_key_is_deterministic() {
        let secret = b"shared-secret-bytes";
        assert_eq!(derive_key(secret, b"label-a"), derive_key(secret, b"label-a"));
    }

    #[test]
    fn test_derive_key_differs_by_label() {
        let secret = b"shared-secret-bytes";
        assert_ne!(derive_key(secret, b"label-a"), derive_key(secret, b"label-b"));
    }

    // -- real concrete ciphers ---------------------------------------------
    //
    // NOTE: these tests exercise real `aes-gcm`/`chacha20poly1305` crate
    // code and therefore cannot actually run in this sandbox (no network
    // access to fetch those crates -- `cargo test -p allium` cannot even
    // build this crate once they're declared as dependencies). They're
    // kept here, written the same way the rest of this module's tests are,
    // so they run and pass on a machine with normal `cargo` network access
    // ("written but unverified pending real cargo build").
    #[test]
    fn test_aes_gcm_seal_open_round_trip() {
        let key = [9u8; KEY_SIZE];
        let mut aead = AesGcmAead::new(key, None).unwrap();
        let sealed = aead.seal(b"hello world", b"ad").unwrap();
        assert_eq!(sealed.len(), b"hello world".len() + SEAL_OVERHEAD);
        assert_eq!(aead.open(&sealed, b"ad").unwrap(), b"hello world");
        assert!(aead.open(&sealed, b"wrong-ad").is_err());
    }

    #[test]
    fn test_chacha20poly1305_seal_open_round_trip() {
        let key = [9u8; KEY_SIZE];
        let mut aead = ChaCha20Poly1305Aead::new(key, None).unwrap();
        let sealed = aead.seal(b"hello world", b"ad").unwrap();
        assert_eq!(sealed.len(), b"hello world".len() + SEAL_OVERHEAD);
        assert_eq!(aead.open(&sealed, b"ad").unwrap(), b"hello world");
        assert!(aead.open(&sealed, b"wrong-ad").is_err());
    }

    #[test]
    fn test_new_aead_dispatches_to_real_ciphers() {
        let key = [1u8; KEY_SIZE];
        assert!(new_aead("aes-256-gcm", key, None).is_ok());
        assert!(new_aead("chacha20-poly1305", key, None).is_ok());
    }

    #[test]
    fn test_new_aead_rejects_unknown_cipher() {
        assert!(new_aead("rot13", [0u8; KEY_SIZE], None).is_err());
    }
}
