//! One shared, hardened OS-CSPRNG draw, used by every module that used to
//! hand-open `/dev/urandom` itself.
//!
//! Security audit fix: this exact "open `/dev/urandom`, `.expect()` on
//! failure" pattern was independently copy-pasted across roughly a dozen
//! call sites in this crate (and `Authority`'s copy of the same modules).
//! Each duplicate had two problems, both already fixed once before in
//! `circuit.rs::os_random` (the only copy ever brought in line) but never
//! generalized: opening a fresh file handle on every single draw is an
//! attacker-amplifiable file-descriptor-exhaustion vector under load, and
//! `.expect()`-panicking on a transient open/read failure crashes the
//! whole process instead of just failing the one operation that needed
//! randomness. This module is the one place that logic now lives;
//! everything else calls [`os_random`] and propagates [`OsRandomError`]
//! into its own local error type.
//!
//! Not exposed outside the crate -- `os_random` and [`OsRandomError`] are
//! `pub(crate)` because only this crate's own modules ever need a raw OS
//! CSPRNG draw; everything with an external caller wraps it in a
//! domain-specific type (a nonce, a key, an id) with its own error type.

use std::io::Read;
use std::sync::{Mutex, OnceLock};

/// A failure opening or reading the OS CSPRNG. Every caller converts this
/// into its own local error type (via `?` and a `From` impl, or a `.map_err`
/// closure) rather than this module choosing one for them.
#[derive(Debug)]
pub(crate) struct OsRandomError(String);

impl std::fmt::Display for OsRandomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for OsRandomError {}

/// The `/dev/urandom` handle [`os_random`] draws from, opened once and
/// reused. Before the first fix this generalizes, every single draw opened
/// (and immediately dropped) a fresh file handle; under sustained load that
/// exhausts file descriptors (an attacker-driven scenario, not just a rare
/// local fault), and each draw was another chance to hit that ceiling.
/// Caching removes that "one open() per draw" amplification: the file is
/// opened at most once per process.
///
/// Only a *successful* open is cached, not the `Result` itself (that would
/// trade the original bug for a different one: a single transient open
/// failure, e.g. an early-boot fd-limit race that clears moments later,
/// would permanently wedge this process's randomness for its entire
/// remaining lifetime). This retries the open on every call until one
/// succeeds, then never opens again -- self-healing on a transient
/// failure, while still eliminating the per-draw amplification.
#[cfg(unix)]
fn urandom_handle() -> Result<&'static Mutex<std::fs::File>, OsRandomError> {
    static HANDLE: OnceLock<Mutex<std::fs::File>> = OnceLock::new();
    if let Some(handle) = HANDLE.get() {
        return Ok(handle);
    }
    let f = std::fs::File::open("/dev/urandom").map_err(|e| OsRandomError(format!("/dev/urandom must be available: {e}")))?;
    // If another thread's concurrent call already won this race, `set`
    // returns the file we just opened back to us as `Err`, which is simply
    // dropped -- `HANDLE.get()` below still returns whichever handle
    // actually landed first, and there is exactly one live cached handle
    // either way.
    let _ = HANDLE.set(Mutex::new(f));
    Ok(HANDLE.get().expect("just set above, or set concurrently by another thread"))
}

/// Draw cryptographically random bytes from the OS CSPRNG into `buf`.
///
/// Every caller of this used to `.expect()` (panicking the whole process)
/// on both opening `/dev/urandom` and reading from it. A transient (or
/// resource-exhaustion-driven) failure here should fail only the one
/// operation that needed randomness, not crash the process.
pub(crate) fn os_random(buf: &mut [u8]) -> Result<(), OsRandomError> {
    #[cfg(unix)]
    {
        // `.unwrap_or_else(PoisonError::into_inner)`, not `.unwrap()`: a
        // poisoned mutex here only means some *other* draw's `read_exact`
        // call panicked while holding it, which reading `/dev/urandom`
        // essentially never does -- and even if it somehow did, a `File`
        // has no invariant a panic mid-read could violate, so recovering
        // the lock and continuing is safe. The whole point of this
        // function is to no longer panic on a resource hiccup, so this
        // shouldn't be the one remaining path that still can.
        let mut handle = urandom_handle()?.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        handle.read_exact(buf).map_err(|e| OsRandomError(format!("reading /dev/urandom failed: {e}")))?;
    }
    #[cfg(not(unix))]
    {
        // `mlkem.rs` already established this crate's correct posture here
        // (this deduplication adopts it, not the other way around): this
        // crate is Linux-only (see `Client/building_directing.txt`), so a
        // non-Unix build has no real CSPRNG source to fall back to. A
        // silent `SystemTime`-based fallback here is not a randomness
        // source, it's a predictable-seed bug waiting for the day someone
        // cross-compiles this without noticing. Refuse to build instead.
        compile_error!(
            "allium::osrand::os_random has no CSPRNG source on non-Unix targets; \
             this crate is Linux-only -- wire a real OS CSPRNG in here before \
             targeting a new platform, do not resurrect the old SystemTime-based \
             fallback"
        );
        #[allow(unreachable_code)]
        let _ = buf;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_random_fills_the_whole_buffer() {
        let mut buf = [0u8; 32];
        os_random(&mut buf).unwrap();
        assert!(buf.iter().any(|&b| b != 0), "extraordinarily unlikely to be all-zero from a real CSPRNG");
    }

    #[test]
    fn os_random_draws_are_not_repeated() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        os_random(&mut a).unwrap();
        os_random(&mut b).unwrap();
        assert_ne!(a, b, "two independent draws collided -- broken or absent randomness");
    }

    #[test]
    fn concurrent_draws_from_many_threads_all_succeed() {
        // Exercises the cached-handle path under real concurrency: several
        // threads racing `urandom_handle()`'s first-open should still each
        // get a valid, distinct draw, not a poisoned lock or a shared
        // handle race.
        let handles: Vec<_> = (0..16)
            .map(|_| {
                std::thread::spawn(|| {
                    let mut buf = [0u8; 8];
                    os_random(&mut buf).unwrap();
                    buf
                })
            })
            .collect();
        let draws: Vec<[u8; 8]> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let unique: std::collections::HashSet<[u8; 8]> = draws.into_iter().collect();
        assert_eq!(unique.len(), 16, "expected 16 distinct draws across 16 threads");
    }
}
