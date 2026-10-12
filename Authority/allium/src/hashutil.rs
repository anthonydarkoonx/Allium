//! SHA-256 / HMAC-SHA256 / HKDF-SHA256 / constant-time compare, backed by
//! the real `sha2`/`hmac`/`hkdf`/`subtle` crates.
//!
//! This used to be a from-scratch FIPS 180-4 SHA-256, RFC 2104 HMAC, RFC
//! 5869 HKDF and a hand-rolled constant-time compare (this sandbox had no
//! network access to crates.io when it was ported -- see the dependency-
//! policy note atop `allium/Cargo.toml`). These aren't incidental: this
//! module backs session-key derivation (`crypto.rs::derive_key`), the
//! handshake/cell header MAC (`handshake.rs`, `onion.rs`), consensus
//! signature verification (`consensus.rs`), and ML-KEM's implicit-rejection
//! compare (`mlkem.rs`) -- all security-critical. Now that the real crates
//! are reachable, this module is a thin wrapper over them instead.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// SHA-256 of `data`, returning the 32-byte digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// HMAC-SHA256(`key`, `data`), returning the 32-byte MAC.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// HKDF-SHA256 extract step (RFC 5869 section 2.2): `PRK = HMAC-SHA256(salt, IKM)`.
pub fn hkdf_sha256_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.into()
}

/// HKDF-SHA256 expand step (RFC 5869 section 2.3): stretch `prk` to `length`
/// bytes of output keying material under domain-separation string `info`.
///
/// # Panics
/// Panics if `length > 255 * 32` (8160 bytes), the RFC 5869 limit for a
/// single-octet-counter, SHA-256-based HKDF -- every caller in this crate
/// asks for at most 32 bytes, so this is unreachable in practice.
pub fn hkdf_sha256_expand(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("HKDF-SHA256 expand: PRK must be at least hash-length");
    let mut out = vec![0u8; length];
    hk.expand(info, &mut out)
        .expect("HKDF-SHA256 expand: length exceeds the 8160-byte RFC 5869 limit");
    out
}

/// HKDF-SHA256 (RFC 5869): extract then expand in one call, matching the
/// shape of `cryptography.hazmat.primitives.kdf.hkdf.HKDF(...).derive(ikm)`
/// that Python's `handshake.py` uses.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let prk = hkdf_sha256_extract(salt, ikm);
    hkdf_sha256_expand(&prk, info, length)
}

/// Constant-time byte-slice comparison (mirrors `hmac.compare_digest`).
///
/// `subtle`'s slice `ConstantTimeEq` impl short-circuits (safely, not in
/// variable time over content) when lengths differ, matching the original
/// hand-rolled behavior.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn test_sha256_empty() {
        assert_eq!(hex(&sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_sha256_abc() {
        assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn test_hmac_sha256_rfc4231_case1() {
        // RFC 4231 test case 1
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = hmac_sha256(&key, data);
        assert_eq!(
            hex(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    // RFC 5869 Appendix A.1 (Test Case 1, HKDF-SHA256 basic).
    #[test]
    fn test_hkdf_sha256_rfc5869_case1() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let okm = hkdf_sha256(&ikm, &salt, &info, 42);
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    // RFC 5869 Appendix A.2 (Test Case 2, longer inputs/outputs).
    #[test]
    fn test_hkdf_sha256_rfc5869_case2() {
        let ikm: Vec<u8> = (0x00..=0x4f).collect();
        let salt: Vec<u8> = (0x60..=0xaf).collect();
        let info: Vec<u8> = (0xb0..=0xff).collect();
        let okm = hkdf_sha256(&ikm, &salt, &info, 82);
        assert_eq!(
            hex(&okm),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
        );
    }

    // RFC 5869 Appendix A.3 (Test Case 3, zero-length salt/info).
    #[test]
    fn test_hkdf_sha256_rfc5869_case3() {
        let ikm = [0x0bu8; 22];
        let okm = hkdf_sha256(&ikm, &[], &[], 42);
        assert_eq!(
            hex(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn test_hkdf_sha256_extract_then_expand_matches_combined() {
        // hkdf_sha256_extract/expand are unused outside this module (the
        // rest of the crate always calls the combined hkdf_sha256), but are
        // kept as public building blocks -- verify they agree with the
        // combined call and, transitively, the RFC 5869 vector above.
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let prk = hkdf_sha256_extract(&salt, &ikm);
        let okm = hkdf_sha256_expand(&prk, &info, 42);
        assert_eq!(okm, hkdf_sha256(&ikm, &salt, &info, 42));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
