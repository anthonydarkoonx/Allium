//! Internal, dependency-free BLAKE2b (RFC 7693), unkeyed, with an optional
//! 16-byte personalization string.
//!
//! Not part of Allium's public API. This exists because `onion.py` uses
//! Python's stdlib `hashlib.blake2b(data, digest_size=N,
//! person=b"...").digest()` in two wire-format-relevant spots
//! (`_seq_mask`'s header-sequence masking and `_seal_binding`'s MAC-input
//! digest) -- neither of which is optional for byte-compatibility with the
//! Python peer, and neither of which is in the dependency policy's reserved
//! list of things that must come from a real crate (X25519/Ed25519, AEAD,
//! tokio, clap). BLAKE2b is a straightforward, well-specified sponge-style
//! hash (much closer in risk profile to the `keccak.rs`/`hashutil.rs`
//! primitives already hand-rolled and KAT-verified in this crate than to an
//! AEAD cipher), so it is hand-rolled here the same way, and cross-checked
//! against `hashlib.blake2b`'s own output for a range of inputs, digest
//! sizes and personalization strings.
//!
//! Only the unkeyed, non-salted, non-tree-mode subset RFC 7693 defines is
//! implemented -- exactly what `onion.py` uses. `key`/`salt`/tree parameters
//! are not exposed.

const IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1,
    0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

const BLOCK_SIZE: usize = 128;

#[inline]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn compress(h: &mut [u64; 8], block: &[u8; BLOCK_SIZE], t: u64, last: bool) {
    let mut m = [0u64; 16];
    for i in 0..16 {
        m[i] = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..16].copy_from_slice(&IV);
    v[12] ^= t; // low 64 bits of the byte counter; t_hi is always 0 for our inputs
    v[13] ^= 0; // t_hi
    if last {
        v[14] = !v[14];
    }
    for round in 0..12 {
        let s = &SIGMA[round];
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// BLAKE2b(`data`), unkeyed, truncated to `digest_size` bytes (1..=64), with
/// an optional personalization string (up to 16 bytes; shorter is
/// zero-padded, matching `hashlib.blake2b(..., person=...)`).
///
/// # Panics
/// Panics if `digest_size` is 0 or greater than 64, or `person` is longer
/// than 16 bytes -- every call site in this crate uses a fixed, valid size.
pub fn blake2b(data: &[u8], digest_size: usize, person: &[u8]) -> Vec<u8> {
    assert!((1..=64).contains(&digest_size), "BLAKE2b digest_size must be in 1..=64, got {digest_size}");
    assert!(person.len() <= 16, "BLAKE2b person must be at most 16 bytes, got {}", person.len());

    let mut person16 = [0u8; 16];
    person16[..person.len()].copy_from_slice(person);
    let personal_low = u64::from_le_bytes(person16[..8].try_into().unwrap());
    let personal_high = u64::from_le_bytes(person16[8..16].try_into().unwrap());

    // Parameter block, unkeyed (key_length=0), sequential mode (fanout=1,
    // depth=1), no salt, personalization only -- see RFC 7693 section 2.5.
    let word0 = digest_size as u64 | (0u64 << 8) | (1u64 << 16) | (1u64 << 24);
    let mut h = IV;
    h[0] ^= word0;
    h[6] ^= personal_low;
    h[7] ^= personal_high;

    let mut compressed: u64 = 0;
    let mut remaining = data.len();
    let mut offset = 0usize;
    while remaining > BLOCK_SIZE {
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(&data[offset..offset + BLOCK_SIZE]);
        compressed += BLOCK_SIZE as u64;
        compress(&mut h, &block, compressed, false);
        offset += BLOCK_SIZE;
        remaining -= BLOCK_SIZE;
    }
    let mut last_block = [0u8; BLOCK_SIZE];
    last_block[..remaining].copy_from_slice(&data[offset..offset + remaining]);
    compressed += remaining as u64;
    compress(&mut h, &last_block, compressed, true);

    let mut out = Vec::with_capacity(64);
    for word in h {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out.truncate(digest_size);
    out
}

/// Keyed BLAKE2b(`data`), truncated to `digest_size` bytes (1..=64), with an
/// optional personalization string (up to 16 bytes) and a key (up to 64
/// bytes). Matches `hashlib.blake2b(data, key=key, digest_size=N,
/// person=person).digest()`. Added for `hiddenservice.rs`'s
/// `hs_directory_index` (the only caller in this crate that needs the keyed
/// form; see that module for why) -- everything else in the crate still uses
/// the unkeyed [`blake2b`] above.
///
/// # Panics
/// Panics if `digest_size` is 0 or greater than 64, `person` is longer than
/// 16 bytes, or `key` is longer than 64 bytes.
pub fn blake2b_keyed(key: &[u8], data: &[u8], digest_size: usize, person: &[u8]) -> Vec<u8> {
    assert!((1..=64).contains(&digest_size), "BLAKE2b digest_size must be in 1..=64, got {digest_size}");
    assert!(person.len() <= 16, "BLAKE2b person must be at most 16 bytes, got {}", person.len());
    assert!(key.len() <= 64, "BLAKE2b key must be at most 64 bytes, got {}", key.len());

    let mut person16 = [0u8; 16];
    person16[..person.len()].copy_from_slice(person);
    let personal_low = u64::from_le_bytes(person16[..8].try_into().unwrap());
    let personal_high = u64::from_le_bytes(person16[8..16].try_into().unwrap());

    let word0 = digest_size as u64 | ((key.len() as u64) << 8) | (1u64 << 16) | (1u64 << 24);
    let mut h = IV;
    h[0] ^= word0;
    h[6] ^= personal_low;
    h[7] ^= personal_high;

    // RFC 7693 keyed mode: the (zero-padded-to-one-block) key is prepended
    // to the data as if it were the first block, and the running byte
    // counter includes it.
    let mut full = Vec::with_capacity(if key.is_empty() { 0 } else { BLOCK_SIZE } + data.len());
    if !key.is_empty() {
        let mut kb = [0u8; BLOCK_SIZE];
        kb[..key.len()].copy_from_slice(key);
        full.extend_from_slice(&kb);
    }
    full.extend_from_slice(data);

    let mut compressed: u64 = 0;
    if full.is_empty() {
        let last_block = [0u8; BLOCK_SIZE];
        compress(&mut h, &last_block, compressed, true);
    } else {
        let mut remaining = full.len();
        let mut offset = 0usize;
        while remaining > BLOCK_SIZE {
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&full[offset..offset + BLOCK_SIZE]);
            compressed += BLOCK_SIZE as u64;
            compress(&mut h, &block, compressed, false);
            offset += BLOCK_SIZE;
            remaining -= BLOCK_SIZE;
        }
        let mut last_block = [0u8; BLOCK_SIZE];
        last_block[..remaining].copy_from_slice(&full[offset..offset + remaining]);
        compressed += remaining as u64;
        compress(&mut h, &last_block, compressed, true);
    }

    let mut out = Vec::with_capacity(64);
    for word in h {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out.truncate(digest_size);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // Cross-checked against Python's hashlib.blake2b(..., key=...) (stdlib).
    #[test]
    fn test_keyed_32byte_key_8byte_data() {
        let key: Vec<u8> = (0u8..32u8).collect();
        let data = 12345i64.to_be_bytes();
        assert_eq!(
            hex(&blake2b_keyed(&key, &data, 32, b"allium-hs-diridx")),
            "54b6de8c539483b0595d989bf7040f8f4f641629c1a61767713178c4174223b8"
        );
    }

    #[test]
    fn test_keyed_empty_data() {
        let key: Vec<u8> = (0u8..32u8).collect();
        assert_eq!(
            hex(&blake2b_keyed(&key, b"", 32, b"allium-hs-diridx")),
            "e67c41720dd74042265dd6b2f8ba76d4225c4bc022610757f41180341b5988bd"
        );
    }

    #[test]
    fn test_keyed_64byte_key_no_person() {
        let key = [1u8; 64];
        assert_eq!(hex(&blake2b_keyed(&key, b"hello", 16, b"")), "0c66b54ba81b69b0995111fa290017b8");
    }

    #[test]
    fn test_keyed_short_key_multi_block() {
        let data = b"0123456789".repeat(20);
        assert_eq!(
            hex(&blake2b_keyed(b"short", &data, 32, b"ctx")),
            "8ed0d81af37458e8e1ca6bd57ebec6c6fc0be9687f1f9bd93d5b983cb69f36c6"
        );
    }

    // Cross-checked against Python's hashlib.blake2b (stdlib), e.g.:
    //   hashlib.blake2b(b"", digest_size=4, person=b"allium-seq-mask").hexdigest()
    #[test]
    fn test_empty_digest4_seq_mask_person() {
        assert_eq!(hex(&blake2b(b"", 4, b"allium-seq-mask")), "052f8c9a");
    }

    #[test]
    fn test_empty_digest32_bind_person() {
        assert_eq!(
            hex(&blake2b(b"", 32, b"allium-bind")),
            "6b2539fd71309b095cdce6574bb70f17700b7999f33e28484d5c3267f0a884b0"
        );
    }

    #[test]
    fn test_abc_digest4_seq_mask_person() {
        assert_eq!(hex(&blake2b(b"abc", 4, b"allium-seq-mask")), "c39be9fb");
    }

    #[test]
    fn test_abc_digest32_bind_person() {
        assert_eq!(
            hex(&blake2b(b"abc", 32, b"allium-bind")),
            "882765bc731c34fce39998c0e5bf6c87f42b3f912e1f6361e4d7a505d8b90b33"
        );
    }

    #[test]
    fn test_multi_block_input_digest4() {
        let data = b"0123456789".repeat(13); // 130 bytes, spans 2 blocks
        assert_eq!(hex(&blake2b(&data, 4, b"allium-seq-mask")), "0f37963d");
    }

    #[test]
    fn test_multi_block_input_digest32() {
        let data = b"0123456789".repeat(13);
        assert_eq!(
            hex(&blake2b(&data, 32, b"allium-bind")),
            "ea272526f7566808d9f8ecf03178b98f0018acf913d86bba9fd43f6e669ac372"
        );
    }

    #[test]
    fn test_exact_one_block_input() {
        let data = [b'A'; 128];
        assert_eq!(
            hex(&blake2b(&data, 32, b"allium-bind")),
            "df2350ef21166a1635017ebad516951727d4a6b9d6b2bb0b24a54f7588ae8cbe"
        );
        assert_eq!(hex(&blake2b(&data, 4, b"allium-seq-mask")), "a3a13b9f");
    }

    #[test]
    fn test_no_personalization() {
        assert_eq!(
            hex(&blake2b(b"hello world", 32, b"")),
            "256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610"
        );
    }

    #[test]
    fn test_binary_input_digest4() {
        let data: Vec<u8> = (0u8..32u8).collect();
        assert_eq!(hex(&blake2b(&data, 4, b"allium-seq-mask")), "603b9994");
    }

    #[test]
    fn test_different_person_gives_different_digest() {
        assert_ne!(blake2b(b"same data", 32, b"context-a"), blake2b(b"same data", 32, b"context-b"));
    }

    #[test]
    fn test_digest_size_is_respected() {
        assert_eq!(blake2b(b"x", 4, b"p").len(), 4);
        assert_eq!(blake2b(b"x", 32, b"p").len(), 32);
        assert_eq!(blake2b(b"x", 64, b"p").len(), 64);
    }
}
