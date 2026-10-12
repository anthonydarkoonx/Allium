//! SHA3-256 / SHA3-512 / SHAKE128 / SHAKE256 (FIPS 202), backed by the
//! `sha3` crate.
//!
//! `mlkem.rs` needs Keccak-family hashes for FIPS 203's H/G/J/PRF
//! functions. This used to be a from-scratch, dependency-free
//! Keccak-f\[1600\] permutation and sponge construction (this sandbox had
//! no network access to crates.io when it was ported), but its only
//! SHAKE128/256 tests were empty-input KATs -- meaning the multi-block
//! *absorb* path was never exercised by any test here, even though every
//! real call in `mlkem.rs` (`h_fn`/`g_fn` on ML-KEM key material, `j_fn`
//! on a 1088-1568 byte ciphertext) drives multiple absorb blocks. Now that
//! a real `sha3` crate is reachable, this module is a thin wrapper over
//! it instead of a hand-rolled sponge.

use sha3::{
    Digest, Sha3_256, Sha3_512, Shake128, Shake256,
    digest::{ExtendableOutput, Update},
};

/// SHA3-256(data): 32-byte digest.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(data).into()
}

/// SHA3-512(data): 64-byte digest.
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    Sha3_512::digest(data).into()
}

/// SHAKE128(data, out_len): arbitrary-length XOF.
pub fn shake128(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    let mut hasher = Shake128::default();
    hasher.update(data);
    hasher.finalize_xof_into(&mut out);
    out
}

/// SHAKE256(data, out_len): arbitrary-length XOF.
pub fn shake256(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    let mut hasher = Shake256::default();
    hasher.update(data);
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
    fn test_sha3_256_empty() {
        // Cross-checked against Python's hashlib.sha3_256(b"").hexdigest().
        assert_eq!(hex(&sha3_256(b"")), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    }

    #[test]
    fn test_sha3_256_abc() {
        assert_eq!(hex(&sha3_256(b"abc")), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    }

    #[test]
    fn test_sha3_512_empty() {
        assert_eq!(
            hex(&sha3_512(b"")),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
    }

    #[test]
    fn test_shake128_empty_32() {
        // Cross-checked against Python's hashlib.shake_128(b"").hexdigest(32).
        assert_eq!(hex(&shake128(b"", 32)), "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    }

    #[test]
    fn test_shake256_empty_32() {
        assert_eq!(hex(&shake256(b"", 32)), "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
    }

    // --- Multi-block ABSORB coverage -------------------------------------
    //
    // Everything above uses inputs far shorter than a single sponge rate,
    // so none of it exercises multi-block absorb -- exactly the gap this
    // module's doc comment flags against the hand-rolled implementation it
    // replaces. `h_fn`/`g_fn`/`j_fn` in `mlkem.rs` all take ML-KEM
    // key/ciphertext-sized input (hundreds to ~1.5KB), spanning several
    // absorb blocks on every real call. These vectors close that gap and
    // are also a regression check on this module's wiring into the real
    // `sha3` crate. Each was independently computed with Python's
    // `hashlib` (an independent implementation).

    /// SHA3-256 rate is 136 bytes; input of exactly one rate block.
    #[test]
    fn sha3_256_input_exactly_one_rate_block() {
        let msg = [0u8; 136];
        assert_eq!(
            hex(&sha3_256(&msg)),
            "e772c9cf9eb9c991cdfcf125001b454fdbc0a95f188d1b4c844aa032ad6e075e"
        );
    }

    /// One byte past a full rate block: smallest input forcing two absorb blocks.
    #[test]
    fn sha3_256_input_one_byte_past_rate_boundary() {
        let msg = [0u8; 137];
        assert_eq!(
            hex(&sha3_256(&msg)),
            "9ed57188470a83b758cd71c00c6cc3beb984b36a6c35864b4e53017b24cf5699"
        );
    }

    /// Sized like a real `h_fn` call on an ML-KEM-768 encapsulation key (1184 bytes).
    #[test]
    fn sha3_256_mlkem768_ek_sized_input() {
        let msg = [0u8; 1184];
        assert_eq!(
            hex(&sha3_256(&msg)),
            "d2c9a283b3d97759100a9a12b3ea90d70e51082b5df280a51cbe6234e4403e60"
        );
    }

    /// SHA3-512 rate is 72 bytes; input of exactly one rate block.
    #[test]
    fn sha3_512_input_exactly_one_rate_block() {
        let msg = [0u8; 72];
        assert_eq!(
            hex(&sha3_512(&msg)),
            "f8d76fdd8a082a67eaab47b5518ac486cb9a90dcb9f3c9efcfd86d5c8b3f1831601d3c8435f84b9e56da91283d5b98040e6e7b2c8dd9aa5bd4ebdf1823a7cf29"
        );
    }

    /// One byte past a full rate block: smallest input forcing two absorb blocks.
    #[test]
    fn sha3_512_input_one_byte_past_rate_boundary() {
        let msg = [0u8; 73];
        assert_eq!(
            hex(&sha3_512(&msg)),
            "4ed8ba5741d94caef309c190bc13d18eb0f16942ebea76dcf0c6db1a35311fc04611313ea7d0ff2228a131cd68a84b3872c93d75700601107b6addeaffaa7a90"
        );
    }

    /// Sized like a real `g_fn` call on an ML-KEM-768 ek (1184 bytes) plus a 32-byte seed.
    #[test]
    fn sha3_512_mlkem768_ek_plus_seed_sized_input() {
        let mut msg = vec![0u8; 1184];
        msg.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            hex(&sha3_512(&msg)),
            "adcac1175563e38c62fd8b989d8aa45adc79954e5d479cf1eef3a6295f18792a3fe52e8a587b94e0397100caf569592b3c898ec92089776c75c9fb0e531ca2d9"
        );
    }

    /// NIST/Keccak-team canonical long-message vector (200 bytes of 0xA3),
    /// spanning two absorb blocks at SHAKE128's 168-byte rate.
    #[test]
    fn shake128_nist_1600bit_long_message_multi_block_absorb() {
        let msg = [0xA3u8; 200];
        assert_eq!(
            hex(&shake128(&msg, 64)),
            "131ab8d2b594946b9c81333f9bb6e0ce75c3b93104fa3469d3917457385da03\
             7cf232ef7164a6d1eb448c8908186ad852d3f85a5cf28da1ab6fe343817197846"
        );
    }

    /// Input exactly one rate block (168 bytes): padding-after-full-block boundary check.
    #[test]
    fn shake128_input_exactly_one_rate_block() {
        let msg = [0u8; 168];
        assert_eq!(
            hex(&shake128(&msg, 32)),
            "7c00ff4748870cb26da4dc078aff74477ab153fa1191c7b636fea6c01ecc1fab"
        );
    }

    /// One byte past a full rate block (169 bytes): smallest input forcing two absorb blocks.
    #[test]
    fn shake128_input_one_byte_past_rate_boundary() {
        let msg = [0x61u8; 169];
        assert_eq!(
            hex(&shake128(&msg, 32)),
            "09fc23f3acfd944380db0c7f5b1bde62d3a43c6e4c61ca9cb3dfee54904b36a8"
        );
    }

    /// Same canonical 200-byte 0xA3 message for SHAKE256 (rate 136).
    #[test]
    fn shake256_nist_1600bit_long_message_multi_block_absorb() {
        let msg = [0xA3u8; 200];
        assert_eq!(
            hex(&shake256(&msg, 64)),
            "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a90\
             4d2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b"
        );
    }

    /// Input exactly one rate block (136 bytes).
    #[test]
    fn shake256_input_exactly_one_rate_block() {
        let msg = [0u8; 136];
        assert_eq!(
            hex(&shake256(&msg, 32)),
            "ea947b835fec1f9b0a7eabba901deb7881fd9999a1cbd5ccbb5a9afab7f6fe70"
        );
    }

    /// One byte past a full rate block (137 bytes): smallest input forcing two absorb blocks.
    #[test]
    fn shake256_input_one_byte_past_rate_boundary() {
        let msg = [0x61u8; 137];
        assert_eq!(
            hex(&shake256(&msg, 32)),
            "a44e1a438dad6273d540be65ee26386c59588efb09139dc086385d2db0c25782"
        );
    }

    /// Sized like a real `j_fn` call on an ML-KEM-768 ciphertext (32-byte z + 1088-byte c).
    #[test]
    fn shake256_mlkem768_ciphertext_sized_input() {
        let mut msg = vec![0u8; 32];
        msg.extend(std::iter::repeat(0x42u8).take(1088));
        assert_eq!(
            hex(&shake256(&msg, 32)),
            "c7bfed95603fc87a4feb41662e3a03f1d49b182e564e939896baa6913699983a"
        );
    }

    /// Sized like a real `prf` call (33-byte input, 64*eta-byte output for eta=3).
    #[test]
    fn shake256_prf_sized_input_and_output() {
        let mut msg = vec![0u8; 32];
        msg.push(1);
        assert_eq!(
            hex(&shake256(&msg, 192))[..64],
            *"d3593e6fc40e08fc4ca6cf6b52a09e576b527af2d50e9b63e6bdbbad3ef37b91"
        );
    }
}
