//! SIGINT/SIGTERM handling: the blocking-thread analogue of
//! `allium_cli.py`'s shutdown story.
//!
//! Python gets Ctrl-C for free (the default SIGINT handler raises
//! `KeyboardInterrupt`, which every role's main loop already catches) and
//! adds one explicit handler of its own,
//! `signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)`, so
//! `systemctl stop` (SIGTERM, not SIGINT) goes through the exact same
//! graceful-exit path as Ctrl-C.
//!
//! There is no cooperative-cancellation equivalent to raise here -- every
//! role in this port runs on blocking OS threads, not coroutines -- so
//! both signals instead set a shared, `Send + Sync` "please stop" flag.
//! Every blocking accept/read loop in this binary polls [`should_stop`] on
//! a short timeout instead of blocking forever (the same technique
//! `allium::socksproxy`'s own module doc describes for the same reason),
//! so a signal is noticed promptly without needing to interrupt a syscall
//! -- which raw `signal()`-installed handlers cannot safely do beyond
//! setting a flag anyway (only async-signal-safe operations are allowed
//! inside the handler itself).

use std::sync::atomic::{AtomicBool, Ordering};

static SHOULD_STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_signum: libc::c_int) {
    SHOULD_STOP.store(true, Ordering::SeqCst);
}

/// Install handlers for SIGINT and SIGTERM that set the shared stop flag
/// instead of terminating the process immediately. Idempotent -- safe to
/// call more than once (each role's `cmd_*` entry point calls this once
/// for itself).
pub fn install() {
    unsafe {
        libc::signal(libc::SIGINT, handle_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handle_signal as *const () as libc::sighandler_t);
    }
}

/// Whether a shutdown signal has been received since the process started
/// (or since [`reset_for_test`] was last called).
pub fn should_stop() -> bool {
    SHOULD_STOP.load(Ordering::SeqCst)
}

#[cfg(test)]
pub fn reset_for_test() {
    SHOULD_STOP.store(false, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_handler_sets_the_stop_flag() {
        reset_for_test();
        assert!(!should_stop());
        install();
        unsafe {
            libc::raise(libc::SIGTERM);
        }
        // The handler runs synchronously on `raise`, so no polling delay
        // is needed here.
        assert!(should_stop());
        reset_for_test();
    }
}
