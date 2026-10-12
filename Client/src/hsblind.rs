//! Hidden-service descriptors, version 3: blinded keys and an encrypted body.
//!
//! # What this fixes
//!
//! Version 2 descriptors carried the service's identity key in the clear and
//! were indexed by a hash the directory authority could compute from it, so
//! the authority could list every service it held, and link a service's
//! descriptors across time periods (by identity, and also by its constant
//! encryption key and introduction points).
//!
//! # The construction (after Tor's v3 onion services)
//!
//! A service's address is still its Ed25519 identity public key `A`. For each
//! time period `N` there is a *blinded* public key
//!
//! ```text
//!   h  = clamp( SHA-512("allium-hs-blind-v3" || A || N || period_length)[..32] )
//!   A' = h * A                       (a point multiplication)
//!   a' = h * a  (mod L)              (the service's blinded secret scalar)
//! ```
//!
//! * Anyone who knows `A` (the address) can compute `A'` for any period; no
//!   one who does *not* know `A` can get from `A'` back to `A`, or tell that
//!   `A'_N` and `A'_{N+1}` belong to the same service.
//! * Only the holder of the secret `a` can sign for `A'`.
//! * `h` is clamped to a multiple of 8, so any small-order component of a
//!   hostile "address" is cleared and cannot make `A'` degenerate.
//!
//! What the directory authority stores and serves is only
//! `(A', period, not_before, not_after, salt, ciphertext, signature)`:
//! the signature is by the blinded key over everything else, and the
//! ciphertext is the ordinary descriptor (`dirwire::encode_hs_descriptor`,
//! which carries the encryption key, introduction points and any client
//! authorization) sealed under a key derived from `A`. So the authority learns
//! neither the service's identity nor anything inside the descriptor, and
//! consecutive periods share no common bytes.
//!
//! A client with the address derives `A'`, fetches by it, checks the signature
//! against its own `A'`, decrypts with the key from `A`, and finally checks
//! the inner descriptor's own identity signature and that it names `A`.
//!
//! # What this does not do
//!
//! Anyone who knows the address can find and read the descriptor, exactly as
//! with Tor; the protection is against a directory that does *not* know the
//! address. A directory that learns an address learns that service's
//! descriptors for as long as it likes. Client authorization (see
//! `HiddenServiceDescriptor::create_with_client_auth`) is the layer that hides
//! the introduction points from someone who knows only the address.
//!
//! This is a bespoke arrangement of standard primitives (Ed25519, SHA-512,
//! HKDF-SHA256, ChaCha20-Poly1305). It is checked against an independent
//! implementation in the tests, but it has not had outside cryptographic
//! review.

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use ed25519_dalek::hazmat::{raw_sign, ExpandedSecretKey};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha512};
use zeroize::Zeroize;

use crate::hiddenservice::{HiddenServiceDescriptor, HiddenServiceError, HS_DIRECTORY_INDEX_PERIOD};

const BLIND_DOMAIN: &[u8] = b"allium-hs-blind-v3";
const BLIND_PREFIX_DOMAIN: &[u8] = b"allium-hs-blind-prefix-v3";
const SIGNATURE_DOMAIN: &[u8] = b"allium-hs-desc3-sig";
const AAD_DOMAIN: &[u8] = b"allium-hs-desc3-aad";
const KEY_DOMAIN: &[u8] = b"allium-hs-desc3-key";

/// Length of the per-descriptor salt.
pub const SALT_LEN: usize = 32;
/// How far a client's clock may be from the service's and still accept its
/// descriptor: a descriptor is valid from the moment the service published it,
/// so without a margin a client running even a second behind rejects it as "not
/// yet valid", which would defeat looking up the next period to cover skew.
pub const CLOCK_SKEW_TOLERANCE_SECS: f64 = 300.0;
/// The most plaintext an inner descriptor can have on the wire: the largest
/// wire-valid [`dirwire::encode_hs_descriptor`] output (a client-authorized
/// descriptor with every field at its maximum).
pub const MAX_INNER_LEN: usize = (32 + 32 + 1) // identity, encryption key, flags byte
    + 2 + crate::dirwire::MAX_ENCRYPTED_INTRO_POINTS_LEN
    + 32 // authorization ephemeral public key
    + 2
    + crate::dirwire::MAX_CLIENT_AUTH_COUNT * (crate::hiddenservice::CLIENT_ID_HINT_LEN + 2 + crate::dirwire::MAX_WRAPPED_KEY_LEN)
    + 8 + 8 + 64; // not_before, not_after, signature
/// The most ciphertext an outer descriptor can carry.
pub const MAX_CIPHERTEXT_LEN: usize = MAX_INNER_LEN + crate::crypto::SEAL_OVERHEAD;

fn err(msg: impl Into<String>) -> HiddenServiceError {
    HiddenServiceError::Other(msg.into())
}

fn period_length_secs() -> u64 {
    HS_DIRECTORY_INDEX_PERIOD as u64
}

/// The blinding factor `h` for `identity_public` in `period`.
pub fn blinding_factor(identity_public: &[u8; 32], period: i64) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(BLIND_DOMAIN);
    hasher.update(identity_public);
    hasher.update(period.to_be_bytes());
    hasher.update(period_length_secs().to_be_bytes());
    let digest = hasher.finalize();
    let mut h = [0u8; 32];
    h.copy_from_slice(&digest[..32]);
    h[0] &= 248;
    h[31] &= 63;
    h[31] |= 64;
    Scalar::from_bytes_mod_order(h)
}

/// The blinded public key `A'` for the address key `identity_public` in
/// `period`. Needs only the public key, so a client can compute it from an
/// address alone.
///
/// # Errors
/// If `identity_public` is not 32 bytes, not a valid curve point, or not a
/// point of the prime-order subgroup (an honest Ed25519 public key always is),
/// or if the result would be the identity.
pub fn blind_public_key(identity_public: &[u8], period: i64) -> Result<[u8; 32], HiddenServiceError> {
    let identity: [u8; 32] = identity_public.try_into().map_err(|_| err(format!("identity key must be 32 bytes, got {}", identity_public.len())))?;
    let point = CompressedEdwardsY(identity).decompress().ok_or_else(|| err("identity key is not a valid curve point"))?;
    if point.is_identity() || !point.is_torsion_free() {
        return Err(err("identity key is not a valid Ed25519 public key (small-order or mixed-order point)"));
    }
    let blinded = blinding_factor(&identity, period) * point;
    if blinded.is_identity() {
        return Err(err("blinded key is degenerate"));
    }
    Ok(blinded.compress().to_bytes())
}

/// The service's blinded signing key for one period.
pub struct BlindedKeys {
    public: [u8; 32],
    secret: ExpandedSecretKey,
    verifying: VerifyingKey,
}

impl BlindedKeys {
    /// `A'`.
    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    /// An ordinary Ed25519 signature that verifies under [`BlindedKeys::public`].
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        raw_sign::<Sha512>(&self.secret, message, &self.verifying).to_bytes()
    }
}

/// Derive the blinded signing key for `period` from the service's identity
/// seed (the same 32-byte seed its address key comes from).
///
/// The blinded scalar is `a' = h * a (mod L)` where `a` is the identity key's
/// usual clamped scalar; the nonce prefix is re-derived under its own domain
/// so that the blinded key never reuses the identity key's nonce input (the
/// `ed25519-dalek` documentation warns that deriving these values any other
/// way can leak the key).
pub fn blinded_keys(seed: &[u8; 32], period: i64) -> Result<BlindedKeys, HiddenServiceError> {
    let identity_public = SigningKey::from_bytes(seed).verifying_key().to_bytes();
    let mut expanded: [u8; 64] = Sha512::digest(seed).into();
    let base = ExpandedSecretKey::from_bytes(&expanded);
    let h = blinding_factor(&identity_public, period);

    let mut prefix_hasher = Sha512::new();
    prefix_hasher.update(BLIND_PREFIX_DOMAIN);
    prefix_hasher.update(&expanded[32..]);
    let prefix_digest = prefix_hasher.finalize();
    let mut hash_prefix = [0u8; 32];
    hash_prefix.copy_from_slice(&prefix_digest[..32]);
    expanded.zeroize();

    let secret = ExpandedSecretKey { scalar: base.scalar * h, hash_prefix };
    let public = blind_public_key(&identity_public, period)?;
    // The public key computed from `A` alone must be the one this secret
    // scalar corresponds to; if not, something is badly wrong.
    let derived = (&secret.scalar * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE).compress().to_bytes();
    if derived != public {
        return Err(err("blinded secret and blinded public key disagree"));
    }
    let verifying = VerifyingKey::from_bytes(&public).map_err(|e| err(format!("blinded key is not a valid verifying key: {e}")))?;
    Ok(BlindedKeys { public, secret, verifying })
}

/// What the directory authority sees of a hidden service's descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct BlindedDescriptor {
    /// `A'` for `period`.
    pub blinded_public: [u8; 32],
    pub period: i64,
    pub not_before: f64,
    pub not_after: f64,
    /// Fresh per descriptor; feeds the encryption key.
    pub salt: [u8; SALT_LEN],
    /// The inner descriptor, sealed under a key derived from the address.
    pub ciphertext: Vec<u8>,
    /// By the blinded key, over [`BlindedDescriptor::signing_payload`].
    pub signature: Vec<u8>,
}

impl BlindedDescriptor {
    fn header(&self, domain: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(domain.len() + 32 + 8 + 8 + 8 + SALT_LEN);
        out.extend_from_slice(domain);
        out.extend_from_slice(&self.blinded_public);
        out.extend_from_slice(&self.period.to_be_bytes());
        out.extend_from_slice(&self.not_before.to_be_bytes());
        out.extend_from_slice(&self.not_after.to_be_bytes());
        out.extend_from_slice(&self.salt);
        out
    }

    /// The exact bytes the signature covers: every other field.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut out = self.header(SIGNATURE_DOMAIN);
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Associated data for sealing: ties the ciphertext to its key, period,
    /// validity window and salt, so it cannot be moved into another descriptor.
    fn aad(&self) -> Vec<u8> {
        self.header(AAD_DOMAIN)
    }

    pub fn is_valid_at(&self, now: f64) -> bool {
        self.not_before <= now && now <= self.not_after
    }

    /// [`Self::is_valid_at`] with [`CLOCK_SKEW_TOLERANCE_SECS`] of margin each way.
    pub fn is_valid_at_with_skew(&self, now: f64) -> bool {
        self.not_before - CLOCK_SKEW_TOLERANCE_SECS <= now && now <= self.not_after + CLOCK_SKEW_TOLERANCE_SECS
    }

    /// Check the signature against `blinded_public`. This is all the
    /// directory authority can and needs to check.
    ///
    /// # Errors
    /// [`HiddenServiceError::SignatureInvalid`]
    pub fn verify(&self) -> Result<(), HiddenServiceError> {
        let bad = || HiddenServiceError::SignatureInvalid("hidden-service descriptor signature did not verify".to_string());
        if self.ciphertext.len() > MAX_CIPHERTEXT_LEN {
            return Err(HiddenServiceError::SignatureInvalid(format!("ciphertext is {} bytes, max is {MAX_CIPHERTEXT_LEN}", self.ciphertext.len())));
        }
        let signature: [u8; 64] = self.signature.as_slice().try_into().map_err(|_| bad())?;
        let key = VerifyingKey::from_bytes(&self.blinded_public).map_err(|_| bad())?;
        key.verify_strict(&self.signing_payload(), &Signature::from_bytes(&signature)).map_err(|_| bad())
    }
}

fn descriptor_key(identity_public: &[u8; 32], blinded_public: &[u8; 32], period: i64, salt: &[u8; SALT_LEN]) -> [u8; 32] {
    use hkdf::Hkdf;
    let mut hkdf_salt = Vec::with_capacity(SALT_LEN + 32);
    hkdf_salt.extend_from_slice(salt);
    hkdf_salt.extend_from_slice(blinded_public);
    let mut info = Vec::with_capacity(KEY_DOMAIN.len() + 8);
    info.extend_from_slice(KEY_DOMAIN);
    info.extend_from_slice(&period.to_be_bytes());
    let hk = Hkdf::<sha2::Sha256>::new(Some(&hkdf_salt), identity_public);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key).expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

/// Seal `inner` (the service's ordinary descriptor) for `period`: encrypt it
/// under a key derived from the service's address and sign the result with
/// the period's blinded key.
///
/// # Errors
/// If `inner` is not this service's own descriptor, is too large, or any key
/// derivation or encryption step fails.
pub fn seal_descriptor(seed: &[u8; 32], inner: &HiddenServiceDescriptor, period: i64) -> Result<BlindedDescriptor, HiddenServiceError> {
    let identity_public = SigningKey::from_bytes(seed).verifying_key().to_bytes();
    if inner.identity_public.as_slice() != identity_public {
        return Err(err("the inner descriptor does not belong to this identity"));
    }
    let keys = blinded_keys(seed, period)?;
    let plaintext = crate::dirwire::encode_hs_descriptor(inner).map_err(|e| err(e.to_string()))?;

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&crate::osrand::bytes(SALT_LEN));
    let mut outer = BlindedDescriptor {
        blinded_public: keys.public(),
        period,
        not_before: inner.not_before,
        not_after: inner.not_after,
        salt,
        ciphertext: Vec::new(),
        signature: Vec::new(),
    };
    let key = descriptor_key(&identity_public, &outer.blinded_public, period, &salt);
    let mut aead = crate::crypto::new_aead("chacha20-poly1305", &key, None).map_err(|e| err(e.to_string()))?;
    outer.ciphertext = aead.seal(&plaintext, &outer.aad()).map_err(|e| err(e.to_string()))?;
    outer.signature = keys.sign(&outer.signing_payload()).to_vec();
    Ok(outer)
}

/// Open a descriptor fetched for the address key `identity_public` in
/// `period`: confirm it is addressed to the blinded key this client derives
/// itself, check the signature and validity window, decrypt, and check the
/// inner descriptor's own signature and that it names this identity.
///
/// Everything the directory returned is untrusted until this succeeds.
///
/// # Errors
/// [`HiddenServiceError::SignatureInvalid`], [`HiddenServiceError::DescriptorExpired`]
/// or [`HiddenServiceError::Other`] on any mismatch.
pub fn open_descriptor(outer: &BlindedDescriptor, identity_public: &[u8; 32], period: i64, now: f64) -> Result<HiddenServiceDescriptor, HiddenServiceError> {
    let expected = blind_public_key(identity_public, period)?;
    if outer.blinded_public != expected || outer.period != period {
        return Err(HiddenServiceError::SignatureInvalid("the descriptor is not for this address and period".to_string()));
    }
    outer.verify()?;
    if !outer.is_valid_at_with_skew(now) {
        return Err(HiddenServiceError::DescriptorExpired("descriptor is outside its validity window".to_string()));
    }
    let key = descriptor_key(identity_public, &outer.blinded_public, period, &outer.salt);
    let aead = crate::crypto::new_aead("chacha20-poly1305", &key, None).map_err(|e| err(e.to_string()))?;
    let plaintext = aead.open(&outer.ciphertext, &outer.aad()).map_err(|_| err("descriptor did not decrypt -- corrupt, or not for this address"))?;
    let (inner, consumed) = crate::dirwire::decode_hs_descriptor(&plaintext).map_err(|e| err(e.to_string()))?;
    if consumed != plaintext.len() {
        return Err(err("trailing bytes after the inner descriptor"));
    }
    if inner.identity_public.as_slice() != identity_public {
        return Err(HiddenServiceError::SignatureInvalid("the inner descriptor names a different identity".to_string()));
    }
    inner.verify()?;
    if inner.not_before != outer.not_before || inner.not_after != outer.not_after {
        return Err(err("the inner descriptor's validity window differs from the outer one"));
    }
    Ok(inner)
}

/// The periods a client should try, in order: the current one, then the next
/// (a client whose clock runs a little behind the service's is still in the old
/// period while the service has already moved on), then the previous (a client
/// a little ahead is in the new period while the service has not yet
/// republished). A service publishes only its current period.
pub fn periods_to_try(now: f64) -> [i64; 3] {
    let current = crate::hiddenservice::hs_directory_period(Some(now), None);
    [current, current + 1, current - 1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hiddenservice::{ClientAuthEntry, IntroPoint};
    use ed25519_dalek::Verifier as _;

    fn seed(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn identity_of(seed: &[u8; 32]) -> [u8; 32] {
        SigningKey::from_bytes(seed).verifying_key().to_bytes()
    }

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let v: Vec<u8> = (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect();
        v.try_into().unwrap()
    }

    // -- agreement with an independent implementation ---------------------------

    /// Vectors produced by a separate, pure-Python implementation written
    /// directly from RFC 8032 (itself checked against RFC 8032's first test
    /// vector). The Rust must reproduce the identity key, the blinded public
    /// key AND the exact signature bytes.
    const VECTORS: [(u8, i64, &str, &str, &str); 3] = [
        (
            1,
            12345,
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
            "b4b4c5b42cd22f8fb45c4441b1ca49434c87fc080be379d2be855ef3aa2df04d",
            "f22cbcd0e5006fa14b0444c400833502603aa0f20fe5653c61d637a90a46e2d3c9d9fad8fe6d0b9511dfdf5c1e8ae5f7a1ec00cb5d671e3f8f199f744111f40e",
        ),
        (
            7,
            0,
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
            "a1389dd28e58386b0684183209233405f6457d705d4e99861166adeb96a56cc5",
            "150cf7e56def0b21401160d777978b758abda3cdf9355b02b8ca7339f1faab57e0deafd28152c90d21cc6dd53f4cc450e896432f8cd66e7a6069ce47a3279d05",
        ),
        (
            9,
            -3,
            "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
            "7417f15d6c49d7e28b3f184baf65d7e25cca57294d7a53e8e49f9a1a5e5ae316",
            "77f2d56653398cdbf3d6fc2093350db9de07df0da5f8027fb3da8d08730d3b095da388ae91547a49bf5057f0822a1f117a2280c16bd0ddf1ed38a3f7c9b68909",
        ),
    ];

    #[test]
    fn matches_the_independent_python_implementation_exactly() {
        for (seed_byte, period, identity_hex, blinded_hex, sig_hex) in VECTORS {
            let s = seed(seed_byte);
            assert_eq!(identity_of(&s), unhex::<32>(identity_hex), "identity key for seed {seed_byte}");
            // from the public key alone, as a client would
            assert_eq!(blind_public_key(&identity_of(&s), period).unwrap(), unhex::<32>(blinded_hex), "blinded key from the address, period {period}");
            // from the secret, as the service would
            let keys = blinded_keys(&s, period).unwrap();
            assert_eq!(keys.public(), unhex::<32>(blinded_hex));
            let message = format!("allium blinding test message {period}");
            let signature = keys.sign(message.as_bytes());
            assert_eq!(signature, unhex::<64>(sig_hex), "signature bytes, seed {seed_byte} period {period}");
            // and the reference's signature verifies under our code too
            let vk = VerifyingKey::from_bytes(&unhex::<32>(blinded_hex)).unwrap();
            vk.verify_strict(message.as_bytes(), &Signature::from_bytes(&unhex::<64>(sig_hex))).unwrap();
        }
    }

    // -- properties of the blinding itself --------------------------------------

    #[test]
    fn the_public_and_secret_sides_agree_and_signatures_verify() {
        for byte in [3u8, 4, 5] {
            for period in [-1i64, 0, 1, 19_000, 19_001] {
                let s = seed(byte);
                let keys = blinded_keys(&s, period).unwrap();
                assert_eq!(keys.public(), blind_public_key(&identity_of(&s), period).unwrap());
                let sig = keys.sign(b"hello");
                VerifyingKey::from_bytes(&keys.public()).unwrap().verify(b"hello", &Signature::from_bytes(&sig)).unwrap();
            }
        }
    }

    #[test]
    fn different_periods_and_different_services_give_unrelated_blinded_keys() {
        let a = identity_of(&seed(1));
        let b = identity_of(&seed(2));
        let mut seen = std::collections::HashSet::new();
        for period in 0..50 {
            assert!(seen.insert(blind_public_key(&a, period).unwrap()));
            assert!(seen.insert(blind_public_key(&b, period).unwrap()));
        }
        // and a blinded key is not the identity key
        assert!(!seen.contains(&a) && !seen.contains(&b));
    }

    #[test]
    fn a_signature_is_good_only_for_its_own_period() {
        let s = seed(6);
        let one = blinded_keys(&s, 100).unwrap();
        let two = blinded_keys(&s, 101).unwrap();
        let sig = one.sign(b"message");
        assert!(VerifyingKey::from_bytes(&two.public()).unwrap().verify_strict(b"message", &Signature::from_bytes(&sig)).is_err());
        // nor does the identity key's own signature verify under a blinded key
        let identity_sig = SigningKey::from_bytes(&s).sign_for_test(b"message");
        assert!(VerifyingKey::from_bytes(&one.public()).unwrap().verify_strict(b"message", &identity_sig).is_err());
    }

    trait SignForTest {
        fn sign_for_test(&self, message: &[u8]) -> Signature;
    }
    impl SignForTest for SigningKey {
        fn sign_for_test(&self, message: &[u8]) -> Signature {
            use ed25519_dalek::Signer as _;
            self.sign(message)
        }
    }

    #[test]
    fn hostile_identity_keys_are_refused() {
        // not 32 bytes
        assert!(blind_public_key(&[1u8; 31], 0).is_err());
        // the identity point (encodes as 01 00 .. 00)
        let mut identity_point = [0u8; 32];
        identity_point[0] = 1;
        assert!(blind_public_key(&identity_point, 0).is_err());
        // a small-order point of order 2 (0, -1)
        let order_two: [u8; 32] = unhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        assert!(blind_public_key(&order_two, 0).is_err());
        // a valid point plus a torsion component is "mixed order": refuse it
        let honest = CompressedEdwardsY(identity_of(&seed(1))).decompress().unwrap();
        let torsion = CompressedEdwardsY(order_two).decompress().unwrap();
        let mixed = (honest + torsion).compress().to_bytes();
        assert!(blind_public_key(&mixed, 0).is_err());
        // a y with no x on the curve
        let mut off_curve = [2u8; 32];
        off_curve[31] = 0x7f;
        let _ = blind_public_key(&off_curve, 0); // must not panic, whichever way it goes
    }

    // -- sealing and opening ------------------------------------------------------

    fn intro_points() -> Vec<IntroPoint> {
        vec![
            IntroPoint { relay_identity: vec![1u8; 32], host: "198.51.100.7".to_string(), port: 9001, auth_public: vec![2u8; 32] },
            IntroPoint { relay_identity: vec![3u8; 32], host: "203.0.113.9".to_string(), port: 9002, auth_public: vec![4u8; 32] },
        ]
    }

    fn inner(s: &[u8; 32], now: f64) -> HiddenServiceDescriptor {
        HiddenServiceDescriptor::create(s, vec![0x77u8; 32], intro_points(), 3600.0, Some(now))
    }

    const NOW: f64 = 1_700_000_000.0;

    fn period_of(now: f64) -> i64 {
        crate::hiddenservice::hs_directory_period(Some(now), None)
    }

    #[test]
    fn a_sealed_descriptor_opens_for_its_address_and_returns_the_original() {
        let s = seed(8);
        let id = identity_of(&s);
        let original = inner(&s, NOW);
        let period = period_of(NOW);
        let outer = seal_descriptor(&s, &original, period).unwrap();
        outer.verify().unwrap();
        let opened = open_descriptor(&outer, &id, period, NOW + 10.0).unwrap();
        assert_eq!(opened, original);
        assert_eq!(opened.intro_points_for(None).unwrap(), intro_points());
    }

    /// The point of the whole exercise: nothing the directory sees identifies
    /// the service or reveals what is inside.
    #[test]
    fn the_outer_descriptor_contains_no_identity_and_no_plaintext() {
        let s = seed(8);
        let id = identity_of(&s);
        let period = period_of(NOW);
        let original = inner(&s, NOW);
        let outer = seal_descriptor(&s, &original, period).unwrap();
        let mut everything = outer.signing_payload();
        everything.extend_from_slice(&outer.signature);
        let contains = |needle: &[u8]| everything.windows(needle.len()).any(|w| w == needle);
        assert!(!contains(&id), "the identity key must not appear");
        assert!(!contains(&[0x77u8; 32]), "the encryption key must not appear");
        assert!(!contains(b"198.51.100.7") && !contains(b"203.0.113.9"), "intro point hosts must not appear");
        assert!(!contains(&[1u8; 32]) && !contains(&[3u8; 32]), "intro relay identities must not appear");
        assert!(contains(&outer.blinded_public), "(the blinded key itself is, of course, there)");
    }

    #[test]
    fn consecutive_periods_share_no_bytes_a_directory_could_link_them_by() {
        let s = seed(8);
        let period = period_of(NOW);
        let original = inner(&s, NOW);
        let a = seal_descriptor(&s, &original, period).unwrap();
        let b = seal_descriptor(&s, &original, period + 1).unwrap();
        assert_ne!(a.blinded_public, b.blinded_public);
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.ciphertext, b.ciphertext);
        // even re-sealing the very same inner descriptor for the very same period is fresh
        let a2 = seal_descriptor(&s, &original, period).unwrap();
        assert_eq!(a.blinded_public, a2.blinded_public);
        assert_ne!(a.ciphertext, a2.ciphertext);
        // no 16-byte run of ciphertext is common between the two periods
        let runs: std::collections::HashSet<&[u8]> = a.ciphertext.windows(16).collect();
        assert!(!b.ciphertext.windows(16).any(|w| runs.contains(w)));
    }

    #[test]
    fn opening_fails_for_the_wrong_address_period_or_time() {
        let s = seed(8);
        let id = identity_of(&s);
        let period = period_of(NOW);
        let outer = seal_descriptor(&s, &inner(&s, NOW), period).unwrap();
        // wrong address
        assert!(open_descriptor(&outer, &identity_of(&seed(9)), period, NOW).is_err());
        // wrong period
        assert!(open_descriptor(&outer, &id, period + 1, NOW).is_err());
        assert!(open_descriptor(&outer, &id, period - 1, NOW).is_err());
        // outside the validity window
        assert!(matches!(open_descriptor(&outer, &id, period, NOW - 10_000.0), Err(HiddenServiceError::DescriptorExpired(_))));
        assert!(matches!(open_descriptor(&outer, &id, period, NOW + 10_000.0), Err(HiddenServiceError::DescriptorExpired(_))));
    }

    #[test]
    fn every_tampered_field_is_rejected() {
        let s = seed(8);
        let id = identity_of(&s);
        let period = period_of(NOW);
        let good = seal_descriptor(&s, &inner(&s, NOW), period).unwrap();
        open_descriptor(&good, &id, period, NOW).unwrap();
        let mut cases: Vec<(&str, BlindedDescriptor)> = Vec::new();
        let mut c = good.clone();
        c.not_after += 1.0;
        cases.push(("not_after", c));
        let mut c = good.clone();
        c.not_before -= 1.0;
        cases.push(("not_before", c));
        let mut c = good.clone();
        c.salt[0] ^= 1;
        cases.push(("salt", c));
        let mut c = good.clone();
        let last = c.ciphertext.len() - 1;
        c.ciphertext[last] ^= 1;
        cases.push(("ciphertext", c));
        let mut c = good.clone();
        c.signature[0] ^= 1;
        cases.push(("signature", c));
        let mut c = good.clone();
        c.period += 1;
        cases.push(("period", c));
        let mut c = good.clone();
        c.blinded_public[0] ^= 1;
        cases.push(("blinded_public", c));
        for (name, bad) in cases {
            assert!(open_descriptor(&bad, &id, period, NOW).is_err(), "tampering with {name} was accepted");
        }
    }

    /// A directory (or anyone) re-signing someone else's ciphertext under its
    /// own blinded key must not produce something a client accepts for the
    /// original address.
    #[test]
    fn a_ciphertext_cannot_be_moved_to_another_key_or_period() {
        let s = seed(8);
        let id = identity_of(&s);
        let period = period_of(NOW);
        let good = seal_descriptor(&s, &inner(&s, NOW), period).unwrap();
        // an attacker with its own identity re-signs the same ciphertext for the same period
        let attacker = seed(77);
        let keys = blinded_keys(&attacker, period).unwrap();
        let mut moved = good.clone();
        moved.blinded_public = keys.public();
        moved.signature = keys.sign(&moved.signing_payload()).to_vec();
        moved.verify().unwrap(); // a perfectly valid *outer* descriptor...
        assert!(open_descriptor(&moved, &id, period, NOW).is_err(), "...that must still not open for the real address");
        assert!(open_descriptor(&moved, &identity_of(&attacker), period, NOW).is_err(), "nor decrypt for the attacker's own");
    }

    #[test]
    fn an_inner_descriptor_for_another_identity_is_refused() {
        let s = seed(8);
        let other = seed(9);
        assert!(seal_descriptor(&s, &inner(&other, NOW), period_of(NOW)).is_err());
    }

    #[test]
    fn client_authorization_still_works_inside_the_blinded_layer() {
        use x25519_dalek::{PublicKey, StaticSecret};
        let s = seed(8);
        let id = identity_of(&s);
        let period = period_of(NOW);
        let client_private = [0x5Au8; 32];
        let client_public = PublicKey::from(&StaticSecret::from(client_private)).to_bytes();
        let restricted = HiddenServiceDescriptor::create_with_client_auth(&s, vec![0x77u8; 32], intro_points(), 3600.0, Some(NOW), &[client_public]).unwrap();
        let outer = seal_descriptor(&s, &restricted, period).unwrap();
        let opened = open_descriptor(&outer, &id, period, NOW).unwrap();
        // knowing only the address is not enough to see the intro points...
        assert!(opened.intro_points_for(None).is_err());
        assert!(opened.intro_points_for(Some(&[0x11u8; 32])).is_err());
        // ...an authorized client key is
        assert_eq!(opened.intro_points_for(Some(&client_private)).unwrap(), intro_points());
        let _ = ClientAuthEntry { client_id_hint: vec![], wrapped_key: vec![] };
    }

    #[test]
    fn periods_to_try_are_current_then_next_then_previous() {
        let p = period_of(NOW);
        assert_eq!(periods_to_try(NOW), [p, p + 1, p - 1]);
    }

    #[test]
    fn the_size_limits_fit_the_largest_wire_valid_inner_descriptor() {
        // a client-authorized descriptor with every field at its maximum
        let s = seed(8);
        let identity_public = identity_of(&s).to_vec();
        let max = HiddenServiceDescriptor {
            identity_public,
            encryption_public: vec![2u8; 32],
            intro_points: Vec::new(),
            not_before: 1.0,
            not_after: 2.0,
            signature: vec![3u8; 64],
            encrypted_intro_points: vec![4u8; crate::dirwire::MAX_ENCRYPTED_INTRO_POINTS_LEN],
            auth_ephemeral_public: vec![5u8; 32],
            client_auth: (0..crate::dirwire::MAX_CLIENT_AUTH_COUNT)
                .map(|_| ClientAuthEntry { client_id_hint: vec![6u8; crate::hiddenservice::CLIENT_ID_HINT_LEN], wrapped_key: vec![7u8; crate::dirwire::MAX_WRAPPED_KEY_LEN] })
                .collect(),
            hs_handshake_v2: true,
        };
        let wire = crate::dirwire::encode_hs_descriptor(&max).unwrap();
        assert_eq!(wire.len(), MAX_INNER_LEN, "MAX_INNER_LEN must be exactly the largest wire-valid inner descriptor");
        assert_eq!(MAX_CIPHERTEXT_LEN, MAX_INNER_LEN + crate::crypto::SEAL_OVERHEAD);
    }

    /// Anyone who knows the address can derive the decryption key for *any*
    /// blinded key they like, so decrypting is no proof of authenticity. An
    /// attacker re-wrapping a genuine inner descriptor under its own blinded
    /// key (signed, decryptable, perfectly well-formed) must still be refused:
    /// the outer must be signed by the key *the client* derives from the address.
    #[test]
    fn an_outer_signed_by_someone_elses_blinded_key_is_refused_even_though_it_decrypts() {
        let s = seed(8);
        let id = identity_of(&s);
        let period = period_of(NOW);
        let genuine_inner = inner(&s, NOW);
        let attacker_keys = blinded_keys(&seed(77), period).unwrap();
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&crate::osrand::bytes(SALT_LEN));
        let mut forged = BlindedDescriptor {
            blinded_public: attacker_keys.public(),
            period,
            not_before: genuine_inner.not_before,
            not_after: genuine_inner.not_after,
            salt,
            ciphertext: Vec::new(),
            signature: Vec::new(),
        };
        let key = descriptor_key(&id, &forged.blinded_public, period, &salt); // the address is public, so the attacker can do this
        let mut aead = crate::crypto::new_aead("chacha20-poly1305", &key, None).unwrap();
        forged.ciphertext = aead.seal(&crate::dirwire::encode_hs_descriptor(&genuine_inner).unwrap(), &forged.aad()).unwrap();
        forged.signature = attacker_keys.sign(&forged.signing_payload()).to_vec();
        forged.verify().unwrap();
        let err = open_descriptor(&forged, &id, period, NOW).unwrap_err();
        assert!(matches!(err, HiddenServiceError::SignatureInvalid(_)), "{err:?}");
    }

    /// Even a correctly signed, correctly encrypted outer for an address must
    /// not carry another identity's descriptor.
    #[test]
    fn a_descriptor_for_a_different_identity_is_refused_even_under_the_right_blinded_key() {
        let s = seed(8);
        let id = identity_of(&s);
        let period = period_of(NOW);
        let someone_elses = inner(&seed(9), NOW);
        let keys = blinded_keys(&s, period).unwrap();
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&crate::osrand::bytes(SALT_LEN));
        let mut outer = BlindedDescriptor {
            blinded_public: keys.public(),
            period,
            not_before: someone_elses.not_before,
            not_after: someone_elses.not_after,
            salt,
            ciphertext: Vec::new(),
            signature: Vec::new(),
        };
        let key = descriptor_key(&id, &outer.blinded_public, period, &salt);
        let mut aead = crate::crypto::new_aead("chacha20-poly1305", &key, None).unwrap();
        outer.ciphertext = aead.seal(&crate::dirwire::encode_hs_descriptor(&someone_elses).unwrap(), &outer.aad()).unwrap();
        outer.signature = keys.sign(&outer.signing_payload()).to_vec();
        outer.verify().unwrap();
        let err = open_descriptor(&outer, &id, period, NOW).unwrap_err();
        assert!(matches!(err, HiddenServiceError::SignatureInvalid(_)), "{err:?}");
    }

    #[test]
    fn the_descriptor_key_depends_on_every_input() {
        let id = identity_of(&seed(1));
        let blinded = [2u8; 32];
        let salt = [3u8; SALT_LEN];
        let base = descriptor_key(&id, &blinded, 5, &salt);
        assert_ne!(base, descriptor_key(&identity_of(&seed(2)), &blinded, 5, &salt), "identity");
        assert_ne!(base, descriptor_key(&id, &[9u8; 32], 5, &salt), "blinded key");
        assert_ne!(base, descriptor_key(&id, &blinded, 6, &salt), "period");
        assert_ne!(base, descriptor_key(&id, &blinded, 5, &[4u8; SALT_LEN]), "salt");
        assert_eq!(base, descriptor_key(&id, &blinded, 5, &salt), "and it is deterministic");
    }

    #[test]
    fn a_small_clock_skew_is_tolerated_and_a_large_one_is_not() {
        let s = seed(8);
        let id = identity_of(&s);
        let period = period_of(NOW);
        let outer = seal_descriptor(&s, &inner(&s, NOW), period).unwrap();
        // the descriptor is valid from NOW to NOW + 3600
        open_descriptor(&outer, &id, period, NOW - CLOCK_SKEW_TOLERANCE_SECS + 1.0).expect("slightly behind");
        open_descriptor(&outer, &id, period, NOW + 3600.0 + CLOCK_SKEW_TOLERANCE_SECS - 1.0).expect("slightly ahead");
        assert!(matches!(open_descriptor(&outer, &id, period, NOW - CLOCK_SKEW_TOLERANCE_SECS - 1.0), Err(HiddenServiceError::DescriptorExpired(_))));
        assert!(matches!(open_descriptor(&outer, &id, period, NOW + 3600.0 + CLOCK_SKEW_TOLERANCE_SECS + 1.0), Err(HiddenServiceError::DescriptorExpired(_))));
        assert_eq!(CLOCK_SKEW_TOLERANCE_SECS, 300.0, "five minutes: the intended policy, as a literal");
    }
}
