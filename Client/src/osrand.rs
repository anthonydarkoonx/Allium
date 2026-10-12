//! A tiny `os.urandom`-equivalent.
//!
//! The Python original pulls every random byte it needs (nonces, keys, ML-KEM
//! seeds, ...) from `os.urandom`, which is the OS CSPRNG. This module is a
//! thin wrapper over the vendored `getrandom` crate, which calls the real
//! `getrandom(2)` syscall on Linux (falling back to `/dev/urandom` only if
//! the syscall is unavailable) instead of hand-opening the device file
//! directly -- `getrandom(2)` works before `/dev/urandom` is mounted and
//! cannot silently return zero bytes early at boot, unlike a raw device-file
//! read. It also covers non-Unix targets for free (e.g. `BCryptGenRandom` on
//! Windows), which the previous hand-rolled, Unix-only version did not.

/// Fill `buf` with cryptographically secure random bytes, `os.urandom`-style.
pub fn fill(buf: &mut [u8]) {
    getrandom::fill(buf).expect("reading OS CSPRNG must not fail");
}

/// Return `n` cryptographically secure random bytes, `os.urandom`-style.
pub fn bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    fill(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_requested_length_and_is_not_all_zero() {
        let a = bytes(32);
        let b = bytes(32);
        assert_eq!(a.len(), 32);
        assert_ne!(a, vec![0u8; 32]);
        assert_ne!(a, b, "two draws should not collide");
    }
}
