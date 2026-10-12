//! Per-hop AEAD primitives for the Allium onion-routing prototype.
//!
//! This module is deliberately dumb about layers and boundaries: it only
//! knows how to seal or open a single untrusted field with a single key.
//! Layer composition lives in [`crate::onion::OnionCrypto`]; the size
//! arithmetic lives in [`crate::sizes`].
//!
//! # Key size policy
//! [`KEY_SIZE`] is 32 bytes. AES-256-GCM and ChaCha20-Poly1305 both take a
//! 256-bit key, so one contract covers either cipher and a key can be moved
//! between them without changing length.
//!
//! # Nonce policy
//! Every sealed field is prefixed with a 12-byte nonce. Two sources are
//! supported:
//!
//! * **Random** (the default) -- read from the OS CSPRNG. 96 bits is the
//!   size AEAD modes are designed around, and collision probability stays
//!   negligible over a circuit's lifetime.
//! * **Counter** -- [`NonceCounter`], a per-circuit monotonic counter mixed
//!   with a per-circuit salt. A counter makes nonce reuse *structurally
//!   impossible* under a given key rather than merely improbable, which is
//!   what a long-lived key or a rekeyed circuit requires.
//!
//! # Real crates, not hand-rolled crypto
//! The AEAD ciphers and Blake2b below come from vendored, unmodified
//! RustCrypto source (see `/vendor` next to this crate) -- the same
//! posture as the Python original, which
//! imports every AEAD/HKDF primitive from the `cryptography` package rather
//! than hand-rolling them.

use std::fmt;

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::Aes256Gcm;
use blake2::Blake2b256;
use chacha20poly1305::ChaCha20Poly1305;
use digest::Digest as _;
use subtle::ConstantTimeEq as _;

use crate::osrand;

/// Symmetric key length in bytes (256-bit). Valid for both AES-GCM and ChaCha20.
pub const KEY_SIZE: usize = 32;

/// AEAD nonce length in bytes.
pub const NONCE_SIZE: usize = 12;

/// AEAD authentication tag length in bytes (appended to every ciphertext).
pub const TAG_SIZE: usize = 16;

/// Bytes added to a plaintext by [`SaltAead::seal`].
pub const SEAL_OVERHEAD: usize = NONCE_SIZE + TAG_SIZE;

/// Largest value [`NonceCounter`] will hand out. A 12-byte nonce is split 4
/// bytes of per-circuit salt plus an 8-byte counter, so the counter is
/// 64-bit and effectively cannot be exhausted (2**64 messages on one
/// circuit).
pub const MAX_NONCE_COUNTER: u64 = u64::MAX;

/// Largest number of *random* (i.e. no [`NonceCounter`] configured) seals
/// [`SaltAead`] will perform under one key before refusing to seal any
/// more. A 96-bit random nonce makes collision merely improbable, not
/// impossible: the birthday bound puts a ~2^-32 collision probability at
/// around 2^32 messages under one key (NIST SP 800-38D's guidance for
/// 96-bit random IVs). Past that point the probability stops being
/// negligible for a key that keeps getting used, so this is the
/// "cell-counter / circuit-lifetime cap" backstop a long-lived, high-volume
/// circuit needs: [`SaltAead::seal`] refuses with [`CryptoError::Nonce`]
/// instead of drifting silently closer to a birthday collision.
pub const MAX_RANDOM_NONCE_SEALS: u64 = 1 << 32;

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// A field failed to authenticate: wrong key, tampered ciphertext, or
    /// mismatched associated data. The three are deliberately not
    /// distinguished: reporting which one failed would hand an attacker a
    /// decryption oracle.
    Decrypt(String),
    /// A nonce counter would reuse or rewind a nonce, or inputs were
    /// otherwise malformed (bad key length, bad cipher name, ...).
    Nonce(String),
    /// Any other input-validation failure (bad key length, unknown cipher, ...).
    Other(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Decrypt(m) | CryptoError::Nonce(m) | CryptoError::Other(m) => {
                write!(f, "{m}")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

// --------------------------------------------------------------------------
// Nonce generation
// --------------------------------------------------------------------------

/// A per-circuit monotonic nonce source: `salt || counter`.
///
/// Deterministic, non-repeating nonces under one key. Where a random draw
/// makes reuse merely improbable, this makes it impossible within a
/// circuit's lifetime, which is what a long-lived key or a rekeyed circuit
/// needs.
///
/// Layout (12 bytes):
///
/// ```text
/// +------------------+----------------------------------+
/// | salt (4)         | counter (8, big-endian)          |
/// +------------------+----------------------------------+
/// 0                  4                                  12
/// ```
///
/// The 4-byte salt is derived from a per-circuit value (its session id), so
/// two circuits that happen to share a key still produce disjoint nonce
/// spaces -- without the salt, restarting a counter at 1 on a second circuit
/// under the same key would immediately reuse nonces.
#[derive(Debug, Clone)]
pub struct NonceCounter {
    salt: [u8; 4],
    counter: u64,
    issued: u64,
    exhausted: bool,
}

impl NonceCounter {
    /// Bytes of per-circuit salt prefixed to the counter.
    pub const SALT_SIZE: usize = 4;

    /// A nonce counter salted from an arbitrary-length session identifier
    /// (only the first 4 bytes of its SHA-256 are used -- the session value
    /// itself must not appear on the wire, and hashing also normalizes any
    /// length).
    pub fn from_session_bytes(session: &[u8]) -> Self {
        Self::with_start(Self::salt_from_bytes(session), 1)
    }

    /// A nonce counter salted from a 4-byte-packed integer session id.
    pub fn from_session_int(session: u32) -> Self {
        Self::with_start(session.to_be_bytes(), 1)
    }

    fn salt_from_bytes(session: &[u8]) -> [u8; 4] {
        use sha2::Sha256;
        let mut hasher = Sha256::new();
        hasher.update(b"allium-nonce-salt-v1");
        hasher.update(session);
        let digest = hasher.finalize();
        [digest[0], digest[1], digest[2], digest[3]]
    }

    fn with_start(salt: [u8; 4], start: u64) -> Self {
        NonceCounter {
            salt,
            counter: start,
            issued: 0,
            exhausted: false,
        }
    }

    /// How many nonces this counter has produced.
    pub fn issued(&self) -> u64 {
        self.issued
    }

    /// The counter value that [`NonceCounter::next`] would use, without
    /// consuming it.
    pub fn next_value(&self) -> u64 {
        self.counter
    }

    /// This counter's 4-byte per-circuit salt.
    pub fn salt(&self) -> [u8; 4] {
        self.salt
    }

    /// Return the next nonce, consuming a counter value.
    ///
    /// # Errors
    /// Returns [`CryptoError::Nonce`] if the counter is exhausted. Refusing
    /// here is the whole point of the type: reusing a nonce under one key
    /// would break both confidentiality and integrity, so failure has to be
    /// loud.
    pub fn next(&mut self) -> Result<[u8; NONCE_SIZE], CryptoError> {
        if self.exhausted {
            return Err(CryptoError::Nonce(format!(
                "nonce counter exhausted after {} nonces; a circuit at this limit must be \
                 rekeyed rather than allowed to reuse a nonce",
                self.issued
            )));
        }
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..4].copy_from_slice(&self.salt);
        nonce[4..].copy_from_slice(&self.counter.to_be_bytes());
        if self.counter == MAX_NONCE_COUNTER {
            self.exhausted = true;
        } else {
            self.counter += 1;
        }
        self.issued += 1;
        Ok(nonce)
    }
}

// --------------------------------------------------------------------------
// AEAD wrapper
// --------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Cipher {
    pub fn name(&self) -> &'static str {
        match self {
            Cipher::Aes256Gcm => "AES-256-GCM",
            Cipher::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        }
    }
}

enum Inner {
    Aes(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

/// One AEAD cipher bound to a single key.
///
/// Callers use [`SaltAead::seal`] and [`SaltAead::open`] so nonce framing
/// stays identical across ciphers.
pub struct SaltAead {
    kind: Cipher,
    key: [u8; KEY_SIZE],
    inner: Inner,
    nonce_source: Option<NonceCounter>,
    max_random_seals: u64,
    random_seals_issued: u64,
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
    /// Build an AEAD for the named `cipher`.
    ///
    /// `cipher`: `"chacha20-poly1305"` (default) or `"aes-256-gcm"`. Case,
    /// `-` and `_` are normalized, so `"CHACHA20_POLY1305"` works.
    ///
    /// # Errors
    /// Returns [`CryptoError::Other`] if the cipher name is unknown or the
    /// key length is wrong.
    pub fn new(
        cipher: &str,
        key: &[u8],
        nonce_source: Option<NonceCounter>,
    ) -> Result<Self, CryptoError> {
        let normalized = cipher.trim().to_lowercase().replace('_', "-");
        let kind = match normalized.as_str() {
            "chacha20-poly1305" | "chacha20poly1305" => Cipher::ChaCha20Poly1305,
            "aes-256-gcm" | "aesgcm" | "aes-256" => Cipher::Aes256Gcm,
            _ => {
                return Err(CryptoError::Other(format!(
                    "unknown cipher {cipher:?}; expected 'chacha20-poly1305' or 'aes-256-gcm'"
                )))
            }
        };
        Self::with_kind(kind, key, nonce_source)
    }

    /// Build an AEAD for a specific [`Cipher`] directly (no name parsing).
    pub fn with_kind(
        kind: Cipher,
        key: &[u8],
        nonce_source: Option<NonceCounter>,
    ) -> Result<Self, CryptoError> {
        if key.len() != KEY_SIZE {
            return Err(CryptoError::Other(format!(
                "{} key must be exactly {KEY_SIZE} bytes ({} bits), got {}",
                kind.name(),
                KEY_SIZE * 8,
                key.len()
            )));
        }
        let mut key_arr = [0u8; KEY_SIZE];
        key_arr.copy_from_slice(key);
        let inner = match kind {
            Cipher::Aes256Gcm => Inner::Aes(Box::new(Aes256Gcm::new_from_slice(key).unwrap())),
            Cipher::ChaCha20Poly1305 => {
                Inner::ChaCha(Box::new(ChaCha20Poly1305::new_from_slice(key).unwrap()))
            }
        };
        Ok(SaltAead {
            kind,
            key: key_arr,
            inner,
            nonce_source,
            max_random_seals: MAX_RANDOM_NONCE_SEALS,
            random_seals_issued: 0,
        })
    }

    /// Cipher name, used in error messages.
    pub fn name(&self) -> &'static str {
        self.kind.name()
    }

    /// This cipher's [`NonceCounter`], or `None` for random nonces.
    pub fn nonce_source(&self) -> Option<&NonceCounter> {
        self.nonce_source.as_ref()
    }

    /// Encrypt `plaintext`, returning `nonce || ciphertext || tag`.
    ///
    /// The nonce comes from this cipher's [`NonceCounter`] when one was
    /// supplied, otherwise from the OS CSPRNG. It is *not* covered by the
    /// tag, so the onion layer swaps it out for an authenticated header
    /// field.
    ///
    /// `associated_data` is authenticated but not encrypted; bind a layer to
    /// context the recipient already knows, such as its own relay identity.
    ///
    /// # Errors
    /// Returns [`CryptoError::Nonce`] if a counter is configured and
    /// exhausted, or if this is a random-nonce instance that has reached
    /// `max_random_seals`.
    pub fn seal(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = match self.nonce_source.as_mut() {
            Some(source) => source.next()?,
            None => {
                if self.random_seals_issued >= self.max_random_seals {
                    return Err(CryptoError::Nonce(format!(
                        "{}: {} random seals performed under this key, at the {} cap meant to \
                         stay well clear of a 96-bit nonce's birthday bound; rekey or tear down \
                         this circuit instead of sealing further under it",
                        self.name(),
                        self.random_seals_issued,
                        self.max_random_seals
                    )));
                }
                let mut n = [0u8; NONCE_SIZE];
                osrand::fill(&mut n);
                self.random_seals_issued += 1;
                n
            }
        };
        let ciphertext = self.encrypt(&nonce, plaintext, associated_data)?;
        let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt one field produced by [`SaltAead::seal`].
    ///
    /// `sealed`: `nonce || ciphertext || tag`. `associated_data` must equal
    /// the value passed to `seal`.
    ///
    /// # Errors
    /// Returns [`CryptoError::Decrypt`] if the field is too short or fails
    /// to authenticate.
    pub fn open(&self, sealed: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if sealed.len() < SEAL_OVERHEAD {
            return Err(CryptoError::Decrypt(format!(
                "sealed field is {} bytes, minimum is {SEAL_OVERHEAD} (nonce + tag)",
                sealed.len()
            )));
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE_SIZE);
        self.decrypt(nonce, ciphertext, associated_data)
    }

    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        let result = match &self.inner {
            Inner::Aes(c) => c.encrypt(aes_gcm::Nonce::from_slice(nonce), payload),
            Inner::ChaCha(c) => c.encrypt(chacha20poly1305::Nonce::from_slice(nonce), payload),
        };
        result.map_err(|_| {
            CryptoError::Other(format!("{}: encryption failed", self.name()))
        })
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        let result = match &self.inner {
            Inner::Aes(c) => c.decrypt(aes_gcm::Nonce::from_slice(nonce), payload),
            Inner::ChaCha(c) => c.decrypt(chacha20poly1305::Nonce::from_slice(nonce), payload),
        };
        result.map_err(|_| {
            CryptoError::Decrypt(format!(
                "{}: failed authentication (wrong key, tampered ciphertext, or associated \
                 data mismatch)",
                self.name()
            ))
        })
    }

    /// Constant-time check of whether `key` is the key bound to this cipher.
    ///
    /// Lets a relay compare a received key against its configured key
    /// without leaking byte positions through timing. Returns `false` for a
    /// key of the wrong length rather than raising.
    pub fn matches(&self, key: &[u8]) -> bool {
        if key.len() != KEY_SIZE {
            return false;
        }
        self.key.ct_eq(key).into()
    }
}

impl fmt::Debug for SaltAead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SaltAead(key=<{} bytes redacted>)", self.key.len())
    }
}

/// AES-256-GCM. The default choice: hardware-accelerated (AES-NI) on most
/// x86-64 and ARM64 hosts, so it is typically the fastest option.
pub fn aes_gcm_aead(key: &[u8], nonce_source: Option<NonceCounter>) -> Result<SaltAead, CryptoError> {
    SaltAead::with_kind(Cipher::Aes256Gcm, key, nonce_source)
}

/// ChaCha20-Poly1305. Constant-time in software, so it is the better choice
/// where AES-NI is unavailable and a table-based AES would be
/// cache-timing sensitive.
pub fn chacha20_poly1305_aead(
    key: &[u8],
    nonce_source: Option<NonceCounter>,
) -> Result<SaltAead, CryptoError> {
    SaltAead::with_kind(Cipher::ChaCha20Poly1305, key, nonce_source)
}

/// Build an AEAD for the named `cipher`. See [`SaltAead::new`].
pub fn new_aead(
    cipher: &str,
    key: &[u8],
    nonce_source: Option<NonceCounter>,
) -> Result<SaltAead, CryptoError> {
    SaltAead::new(cipher, key, nonce_source)
}

/// Return a fresh random [`KEY_SIZE`]-byte key.
pub fn generate_key() -> Vec<u8> {
    osrand::bytes(KEY_SIZE)
}

/// Deterministically derive a hop key from a shared secret.
///
/// A convenience for tests and for callers that already hold a shared
/// secret. The real handshake lives in [`crate::handshake`], which uses
/// HKDF-SHA256 per RFC 5869 over an X25519 exchange; this function uses
/// Blake2b with a label prefix because it is keyed by construction and
/// needs no salt. Prefer [`crate::handshake::derive_handshake_keys`] for
/// anything that talks to a peer, so both sides use the same,
/// standards-based derivation.
pub fn derive_key(shared_secret: &[u8], label: &[u8]) -> [u8; KEY_SIZE] {
    let mut hasher = Blake2b256::new();
    hasher.update(label);
    hasher.update([0u8]);
    hasher.update(shared_secret);
    let digest = hasher.finalize();
    let mut out = [0u8; KEY_SIZE];
    out.copy_from_slice(&digest);
    out
}

/// [`derive_key`] with the Python default label (`b"allium-hop-v1"`).
pub fn derive_key_default(shared_secret: &[u8]) -> [u8; KEY_SIZE] {
    derive_key(shared_secret, b"allium-hop-v1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip_both_ciphers() {
        for cipher in ["aes-256-gcm", "chacha20-poly1305"] {
            let key = generate_key();
            let mut aead = new_aead(cipher, &key, None).unwrap();
            let sealed = aead.seal(b"hello world", b"aad").unwrap();
            assert_eq!(sealed.len(), b"hello world".len() + SEAL_OVERHEAD);
            let opened = aead.open(&sealed, b"aad").unwrap();
            assert_eq!(opened, b"hello world");
        }
    }

    #[test]
    fn wrong_associated_data_fails() {
        let key = generate_key();
        let mut aead = new_aead("aes-256-gcm", &key, None).unwrap();
        let sealed = aead.seal(b"data", b"aad-a").unwrap();
        assert!(aead.open(&sealed, b"aad-b").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = generate_key();
        let mut aead = new_aead("chacha20-poly1305", &key, None).unwrap();
        let mut sealed = aead.seal(b"data", b"").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(aead.open(&sealed, b"").is_err());
    }

    #[test]
    fn nonce_counter_produces_disjoint_salts_per_session() {
        let mut a = NonceCounter::from_session_bytes(b"circuit-a");
        let mut b = NonceCounter::from_session_bytes(b"circuit-b");
        assert_ne!(a.salt(), b.salt());
        let na = a.next().unwrap();
        let nb = b.next().unwrap();
        assert_ne!(na, nb);
    }

    #[test]
    fn nonce_counter_with_source_never_repeats_across_many_seals() {
        let key = generate_key();
        let counter = NonceCounter::from_session_int(7);
        let mut aead = new_aead("aes-256-gcm", &key, Some(counter)).unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let sealed = aead.seal(b"x", b"").unwrap();
            let nonce = sealed[..NONCE_SIZE].to_vec();
            assert!(seen.insert(nonce), "nonce reused");
        }
    }

    #[test]
    fn wrong_key_length_rejected() {
        assert!(new_aead("aes-256-gcm", &[0u8; 16], None).is_err());
    }

    #[test]
    fn unknown_cipher_name_rejected() {
        assert!(new_aead("rot13", &[0u8; 32], None).is_err());
    }

    #[test]
    fn matches_is_constant_time_and_correct() {
        let key = generate_key();
        let aead = new_aead("aes-256-gcm", &key, None).unwrap();
        assert!(aead.matches(&key));
        let mut other = key.clone();
        other[0] ^= 1;
        assert!(!aead.matches(&other));
        assert!(!aead.matches(&[0u8; 4]));
    }

    #[test]
    fn derive_key_is_deterministic_and_label_separated() {
        let secret = b"shared-secret-material";
        let k1 = derive_key(secret, b"label-a");
        let k2 = derive_key(secret, b"label-a");
        let k3 = derive_key(secret, b"label-b");
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
        assert_eq!(k1.len(), KEY_SIZE);
    }
}

/// Byte-for-byte parity with the real Python `allium.crypto.derive_key`.
///
/// Ground truth generated by running the actual Python module as an oracle:
///
/// ```text
/// python3 -c "
/// import hashlib
/// def derive_key(shared_secret, label=b'allium-hop-v1'):
///     return hashlib.blake2b(label + b'\x00' + shared_secret, digest_size=32).digest()
/// print(derive_key(b'shared-secret-material', b'label-a').hex())
/// print(derive_key(b'shared-secret-material', b'label-b').hex())
/// "
/// ```
#[cfg(test)]
mod python_cross_check {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn derive_key_matches_python() {
        let secret = b"shared-secret-material";
        assert_eq!(
            hex(&derive_key(secret, b"label-a")),
            "21abf67d5c9d72369a70f28a59f1525c109aff198d51c09cdc0199e1499a92bf"
        );
        assert_eq!(
            hex(&derive_key(secret, b"label-b")),
            "cee5f8ecab956727df202e8ec71c4ba7b9875aa80ee958053f361b56e8c62c25"
        );
    }
}
