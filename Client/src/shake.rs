//! SHAKE128 / SHAKE256 (FIPS 202 extendable-output functions).
//!
//! The vendored `sha3` crate (see `/vendor/hashes/sha3`) doesn't include
//! SHAKE support at the pinned commit: upstream split `Shake128`/`Shake256`
//! out of `sha3` and into their own `shake` crate (RustCrypto/XOFs) as of
//! `sha3` 0.12.0 (see `/vendor/hashes/sha3/CHANGELOG.md`). This module is a
//! thin wrapper around that vendored `shake` crate rather than a from-scratch
//! sponge construction -- it shares the same `keccak`/`sponge-cursor`
//! building blocks already vendored here, just under RustCrypto's own,
//! upstream-tested implementation instead of a hand-rolled one.
//!
//! The known-answer tests below (including the multi-block-absorb boundary
//! cases -- see the "Multi-block ABSORB coverage" section) are kept as a
//! regression/KAT check on this wrapper and its dependency wiring, even
//! though the sponge logic itself now lives upstream.

use digest::{ExtendableOutput, Update};
use shake::{Shake128, Shake256};

/// `hashlib.shake_128(input).digest(out_len)`.
pub fn shake128(input: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    let mut hasher = Shake128::default();
    hasher.update(input);
    hasher.finalize_xof_into(&mut out);
    out
}

/// `hashlib.shake_256(input).digest(out_len)`.
pub fn shake256(input: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    let mut hasher = Shake256::default();
    hasher.update(input);
    hasher.finalize_xof_into(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn shake128_empty_input_matches_hashlib() {
        // python3 -c "import hashlib; print(hashlib.shake_128(b'').hexdigest(32))"
        let out = shake128(b"", 32);
        assert_eq!(
            hex(&out),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
    }

    #[test]
    fn shake256_empty_input_matches_hashlib() {
        // python3 -c "import hashlib; print(hashlib.shake_256(b'').hexdigest(32))"
        let out = shake256(b"", 32);
        assert_eq!(
            hex(&out),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
    }

    #[test]
    fn shake128_abc_matches_hashlib() {
        // python3 -c "import hashlib; print(hashlib.shake_128(b'abc').hexdigest(32))"
        let out = shake128(b"abc", 32);
        assert_eq!(
            hex(&out),
            "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
        );
    }

    #[test]
    fn multi_block_squeeze_matches_hashlib() {
        // python3 -c "import hashlib; print(hashlib.shake_256(b'allium').hexdigest(300)[:64])"
        // (rate is 136 bytes, so a 300-byte digest spans 3 permutation blocks)
        let out = shake256(b"allium", 300);
        assert_eq!(
            hex(&out[..32]),
            "0b4892c6e2a4aaefc9de75013f4d87f60740479f5c53bd74b9adbbb8ec634a84"
        );
    }

    #[test]
    fn output_longer_than_one_block_matches_prefix_of_shorter_request() {
        // Squeezing must be deterministic and prefix-stable: the first 32
        // bytes of a 300-byte digest must equal a direct 32-byte digest.
        let long = shake256(b"allium", 300);
        let short = shake256(b"allium", 32);
        assert_eq!(&long[..32], &short[..]);
    }

    // --- Multi-block ABSORB coverage -------------------------------------
    //
    // Every test above uses an input shorter than one sponge rate (168
    // bytes for SHAKE128, 136 for SHAKE256), so none of them exercise the
    // multi-block absorb path -- only the multi-block squeeze
    // path is covered above. That's exactly the gap flagged against this
    // module: `mlkem::j()` calls `shake256(z || c, 32)` with a 1088-1568
    // byte ML-KEM ciphertext, which spans several absorb blocks on every
    // decapsulation. The tests below close that gap.
    //
    // Each expected digest here was independently cross-checked against
    // two separate SHAKE implementations -- CPython's `hashlib` (its own
    // SHA-3/Keccak module) and OpenSSL 3.0's `EVP_shake128`/`EVP_shake256`
    // -- which agreed exactly, in addition to being checked here against
    // this crate's own implementation.

    /// NIST/Keccak-team canonical long-message test vector: a 1600-bit
    /// (200-byte) message of the repeating byte `0xA3`. This is the
    /// standard "Msg as bit string" example NIST publishes for SHAKE128
    /// (see `shake128_msg1600.pdf` under NIST CSRC's SHA-3 example
    /// values), reproduced here as raw bytes and checked against
    /// independent SHAKE implementations rather than hand-transcribed from
    /// the PDF's bit-string encoding. At 200 bytes it spans two absorb
    /// blocks (rate 168).
    #[test]
    fn shake128_nist_1600bit_long_message_multi_block_absorb() {
        let msg = [0xA3u8; 200];
        let out = shake128(&msg, 64);
        assert_eq!(
            hex(&out),
            "131ab8d2b594946b9c81333f9bb6e0ce75c3b93104fa3469d3917457385da03\
             7cf232ef7164a6d1eb448c8908186ad852d3f85a5cf28da1ab6fe343817197846"
        );
    }

    /// Same canonical 200-byte `0xA3` message for SHAKE256 (rate 136, so
    /// this spans two absorb blocks).
    #[test]
    fn shake256_nist_1600bit_long_message_multi_block_absorb() {
        let msg = [0xA3u8; 200];
        let out = shake256(&msg, 64);
        assert_eq!(
            hex(&out),
            "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a90\
             4d2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b"
        );
    }

    /// Input exactly one rate block (168 bytes for SHAKE128): boundary
    /// check that padding after a single full block is applied correctly
    /// and doesn't spuriously trigger (or fail to trigger) a second block.
    #[test]
    fn shake128_input_exactly_one_rate_block() {
        let msg = [0x00u8; 168];
        let out = shake128(&msg, 32);
        assert_eq!(
            hex(&out),
            "7c00ff4748870cb26da4dc078aff74477ab153fa1191c7b636fea6c01ecc1fab"
        );
    }

    /// Input exactly one rate block (136 bytes for SHAKE256).
    #[test]
    fn shake256_input_exactly_one_rate_block() {
        let msg = [0x00u8; 136];
        let out = shake256(&msg, 32);
        assert_eq!(
            hex(&out),
            "ea947b835fec1f9b0a7eabba901deb7881fd9999a1cbd5ccbb5a9afab7f6fe70"
        );
    }

    /// Input one byte past a full rate block (169 bytes for SHAKE128): the
    /// smallest input that forces exactly two absorb blocks.
    #[test]
    fn shake128_input_one_byte_past_rate_boundary() {
        let msg = [0x61u8; 169];
        let out = shake128(&msg, 32);
        assert_eq!(
            hex(&out),
            "09fc23f3acfd944380db0c7f5b1bde62d3a43c6e4c61ca9cb3dfee54904b36a8"
        );
    }

    /// Input one byte past a full rate block (137 bytes for SHAKE256): the
    /// smallest input that forces exactly two absorb blocks.
    #[test]
    fn shake256_input_one_byte_past_rate_boundary() {
        let msg = [0x61u8; 137];
        let out = shake256(&msg, 32);
        assert_eq!(
            hex(&out),
            "a44e1a438dad6273d540be65ee26386c59588efb09139dc086385d2db0c25782"
        );
    }

    /// Input sized like a real `mlkem::j()` call for an ML-KEM-768
    /// ciphertext: 32-byte `z` followed by a 1088-byte ciphertext `c`,
    /// spanning multiple absorb blocks (rate 136) -- the actual shape of
    /// the security-critical call site this module exists to support.
    #[test]
    fn shake256_mlkem768_ciphertext_sized_input() {
        let mut msg = vec![0u8; 32];
        msg.extend(std::iter::repeat(0x42u8).take(1088));
        let out = shake256(&msg, 32);
        assert_eq!(
            hex(&out),
            "c7bfed95603fc87a4feb41662e3a03f1d49b182e564e939896baa6913699983a"
        );
    }

    /// Same, sized for an ML-KEM-1024 ciphertext (32-byte `z` + 1568-byte
    /// `c`), spanning even more absorb blocks.
    #[test]
    fn shake256_mlkem1024_ciphertext_sized_input() {
        let mut msg = vec![0u8; 32];
        msg.extend(std::iter::repeat(0x42u8).take(1568));
        let out = shake256(&msg, 32);
        assert_eq!(
            hex(&out),
            "a7366ee2370d5ac20da16fe716a9c717d20daaf24a9b5bf8e357e710b9620ed6"
        );
    }
}
