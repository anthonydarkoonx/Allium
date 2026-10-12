//! The Rust analogue of Python's `raise SystemExit(...)`.
//!
//! `allium_cli.py` uses `SystemExit` throughout as "print one clean,
//! operator-facing line and stop" -- never a traceback. `CliExit` is that
//! same control-flow shape: any function that would `raise SystemExit(msg)`
//! in Python instead returns `Err(CliExit::error(msg))`, and `main` is the
//! one place that turns it into a process exit, mirroring how Python's
//! interpreter turns an uncaught `SystemExit` into `sys.exit`.
//!
//! `SystemExit(0)` (a *clean*, successful exit -- see
//! `--print-client-auth-key`'s early return) is `CliExit::clean()`: no
//! message, exit code 0.

use std::fmt;

/// Either an operator-facing error (exit code 1, message on stderr) or a
/// clean early exit (exit code 0, nothing further to print -- the caller
/// already printed whatever it wanted via `say`).
#[derive(Debug, Clone)]
pub struct CliExit {
    pub code: i32,
    pub message: Option<String>,
}

impl CliExit {
    /// `raise SystemExit(msg)`: exit 1, print `msg` to stderr.
    pub fn error(message: impl Into<String>) -> Self {
        CliExit { code: 1, message: Some(message.into()) }
    }

    /// `raise SystemExit(0)`: exit 0, nothing further to print.
    pub fn clean() -> Self {
        CliExit { code: 0, message: None }
    }
}

impl fmt::Display for CliExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.message {
            Some(m) => write!(f, "{m}"),
            None => Ok(()),
        }
    }
}

impl std::error::Error for CliExit {}

impl From<allium::config::ConfigError> for CliExit {
    fn from(e: allium::config::ConfigError) -> Self {
        CliExit::error(format!("--config: {e}"))
    }
}

impl From<allium::alliumrc::AlliumrcError> for CliExit {
    fn from(e: allium::alliumrc::AlliumrcError) -> Self {
        CliExit::error(format!("--config: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_carries_message_and_exit_code_one() {
        let exit = CliExit::error("boom");
        assert_eq!(exit.code, 1);
        assert_eq!(exit.message.as_deref(), Some("boom"));
    }

    #[test]
    fn clean_carries_no_message_and_exit_code_zero() {
        let exit = CliExit::clean();
        assert_eq!(exit.code, 0);
        assert_eq!(exit.message, None);
    }
}
