//! Small, pure, dependency-free helpers used across the CLI (port of the
//! free functions near the top of `allium_cli.py`: `say`, `parse_addr`,
//! `_encode_ack_frame`, the hex trust-key helpers, and the built-in
//! default-authority fallback).

use std::io::Write as _;

use crate::args::Args;
use crate::cli_error::CliExit;

/// A process-wide lock for tests (here and in `apply_config`'s own test
/// module) that read or mutate the `ALLIUM_DEFAULT_AUTHORITY`/
/// `ALLIUM_DEFAULT_TRUST_AUTHORITY` environment variables -- `cargo test`
/// runs tests concurrently by default, and env vars are process-global, so
/// without this two such tests could race and see each other's values.
/// Python's equivalent tests get this for free from `unittest`'s
/// per-test-method env snapshot/restore; Rust has no such isolation, so
/// this lock (plus each test restoring what it changed) stands in for it.
#[cfg(test)]
pub(crate) mod env_test_lock {
    pub static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
}

/// A client-side liveness ping (see `run_client`'s keepalive loop).
/// Deliberately 1 byte: shorter than a fragment header (9 bytes) so it can
/// never be mistaken for real fragmented data, and shorter than the
/// stream/datagram request magic (4 bytes) so it can never be mistaken for
/// a real request either. Its only job is to be *something* that travels
/// the whole circuit, so every hop's idle timer gets refreshed along the
/// way.
pub const KEEPALIVE_PING: &[u8; 1] = b"\x00";

/// Fragment-ack magic, client -> exit: reports how much of a return stream
/// the client has contiguously received, so a missing fragment can be
/// resent instead of leaving a permanent gap.
pub const ACK_MAGIC: &[u8; 4] = b"ALFA";

/// How often the client re-announces its received-so-far watermark for an
/// actively-progressing stream, in bytes.
pub const ACK_EVERY_BYTES: u64 = 8192;

/// Print and flush immediately.
///
/// The relays are often run with stdout redirected to a file, where the
/// OS/libc may block-buffer it -- so a diagnostic that is still sitting in
/// the buffer looks like the code never ran. Flushing makes the
/// two-machine walkthrough trustworthy: what you see is the current state,
/// not the last flush.
pub fn say(message: &str) {
    println!("{message}");
    let _ = std::io::stdout().flush();
}

/// Wire-encode a fragment ack: magic + stream id + contiguous watermark.
pub fn encode_ack_frame(stream_id: u32, offset: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(ACK_MAGIC);
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(&offset.to_be_bytes());
    out
}

/// Ask for a much larger UDP receive buffer than the OS default (port of
/// every client/service circuit socket's `sock.setsockopt(socket.SOL_SOCKET,
/// socket.SO_RCVBUF, 1 << 22)`).
///
/// The return path (exit -> ... -> guard -> this socket) carries bulk data
/// fragments with no sender-side pacing and no retransmission, so a burst
/// can arrive faster than `CircuitTransport::receive` decodes the previous
/// one; a bigger kernel buffer gives a burst somewhere to queue instead of
/// being silently dropped. Best-effort, matching Python's own
/// `except OSError: pass` -- std's `UdpSocket` has no portable
/// `SO_RCVBUF` setter, so this reaches for it directly via the raw fd
/// (also see `transport::wait_readable`, which reaches for `libc::poll`
/// for the same reason: no portable std equivalent).
pub fn set_large_rcvbuf(sock: &std::net::UdpSocket) {
    use std::os::unix::io::AsRawFd;
    let fd = sock.as_raw_fd();
    let value: libc::c_int = 1 << 22;
    // SAFETY: `fd` is a valid, open socket for the lifetime of this call
    // (borrowed from `sock`, which outlives it); `value` is a plain `c_int`
    // whose address and size are passed correctly to `setsockopt`. The
    // return value is deliberately ignored -- this is advisory, not
    // required for correctness (see the doc above).
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// Sleep for `duration`, but wake up early (returning `false`) if `stopping`
/// is set first. Returns `true` if the full duration elapsed without being
/// interrupted. Polls in short (<=150ms) increments so a shutdown signal is
/// noticed promptly rather than after the whole duration -- the same
/// interruptible-sleep role Python's `await asyncio.sleep(...)` raced
/// against a cancellation played, now that there is no task to cancel.
pub fn sleep_or_wake(duration: std::time::Duration, stopping: &std::sync::atomic::AtomicBool) -> bool {
    let deadline = std::time::Instant::now() + duration;
    while std::time::Instant::now() < deadline {
        if stopping.load(std::sync::atomic::Ordering::SeqCst) {
            return false;
        }
        std::thread::sleep(
            std::time::Duration::from_millis(150).min(deadline.saturating_duration_since(std::time::Instant::now())),
        );
    }
    true
}

/// Parse `ip:port` into `(ip, port)`.
///
/// Mirrors Python's `text.rsplit(":", 1)` (splits at the *last* colon, so
/// an IPv6 literal like `::1:9050` still parses as host `::1`, port
/// `9050`) followed by `int(port)`. Unlike Python's arbitrary-precision
/// `int`, this parses the port directly as `u16` (the type every hop
/// address in this crate already uses), so a syntactically-int-but-out-of-
/// range port (e.g. `99999`) is rejected here rather than accepted and
/// left to fail later at bind/connect time.
pub fn parse_addr(text: &str) -> Result<(String, u16), CliExit> {
    let (host, port_text) = text
        .rsplit_once(':')
        .ok_or_else(|| CliExit::error(format!("expected ip:port, got {text:?}")))?;
    let port: u16 = port_text
        .parse()
        .map_err(|_| CliExit::error(format!("expected ip:port, got {text:?}")))?;
    Ok((host.to_string(), port))
}

/// Encode `bytes` as lowercase hex, matching Python's `bytes.hex()`.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Decode a hex string into bytes, matching Python's `bytes.fromhex()`:
/// case-insensitive, requires an even number of hex digits, rejects
/// anything else (including embedded whitespace, which Python's
/// `bytes.fromhex` otherwise tolerates between byte pairs -- not needed
/// here, since every caller already handles whitespace itself via
/// `.strip()`/`.trim()` before this is ever called).
pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(format!("non-hexadecimal number found in fromhex() arg at position {}", bytes.len()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_digit(bytes[i]).ok_or_else(|| {
            format!("non-hexadecimal number found in fromhex() arg at position {i}")
        })?;
        let lo = hex_digit(bytes[i + 1]).ok_or_else(|| {
            format!("non-hexadecimal number found in fromhex() arg at position {}", i + 1)
        })?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Split a `--trust-authority` value into one or more hex identity keys.
///
/// A single deployment's directory authority is usually pinned to one key,
/// but this also accepts a comma-separated list -- e.g. an old and new key
/// both valid during a planned key rotation, or a small quorum of
/// independently-held keys behind one default authority rather than
/// anchoring trust to a single party's single key.
pub fn split_trust_keys(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Validate a TrustGuard/TrustMiddle/TrustExit/TrustAuthority/
/// AuthorityFingerprint value: one or more comma-separated 32-byte hex
/// Ed25519 identity keys. Returns the re-joined, lower-cased, canonical
/// form (matching Python's `.hex()` round trip), or a clean operator-facing
/// error.
pub fn validate_trust_keys(value: &str, label: &str) -> Result<String, CliExit> {
    let mut cleaned = Vec::new();
    for hex_key in split_trust_keys(value) {
        let key_bytes = hex_decode(&hex_key)
            .map_err(|_| CliExit::error(format!("{label} value '{hex_key}' is not valid hex")))?;
        if key_bytes.len() != 32 {
            return Err(CliExit::error(format!(
                "{label} value '{hex_key}' must be a 32-byte Ed25519 identity key ({} bytes given)",
                key_bytes.len()
            )));
        }
        cleaned.push(hex_encode(&key_bytes));
    }
    Ok(cleaned.join(","))
}

// ---------------------------------------------------------------------------
// Built-in default directory authority (optional zero-config bootstrap)
// ---------------------------------------------------------------------------
//
// Empty by default: a network operator who wants this fills in their own
// authority/authorities below (fork this file, or set the environment
// variables before running this binary) -- nothing is silently phoned
// home, and an explicit --authority (CLI or --config) always wins outright
// over anything here regardless.
//
// Each entry is (address, identity_hex_or_none). Only the first entry is
// consulted today -- this is a single fallback address, not yet a
// Tor-style N-way-redundant model.
pub const DEFAULT_AUTHORITIES: &[(&str, Option<&str>)] = &[
    // ("203.0.113.9:9030", Some("the authority's 64-hex-char Ed25519 identity")),
];

/// This build's built-in fallback authority, as `(address, trust_hex)`.
///
/// Checked in this order:
///
/// 1. The `ALLIUM_DEFAULT_AUTHORITY` / `ALLIUM_DEFAULT_TRUST_AUTHORITY`
///    environment variables -- lets an operator point an existing install
///    at a network without editing source at all.
/// 2. The first entry of [`DEFAULT_AUTHORITIES`] above.
///
/// Returns `(None, None)` if neither is set, which is the stock,
/// unmodified state of this file.
pub fn default_authority() -> (Option<String>, Option<String>) {
    default_authority_from(DEFAULT_AUTHORITIES)
}

/// [`default_authority`]'s actual logic, parametrized over the fallback
/// list so it can be unit-tested against entries other than this source
/// tree's (empty, by design) [`DEFAULT_AUTHORITIES`] without needing to
/// mutate a `const` -- Rust has no monkeypatch-equivalent for that, unlike
/// the Python original's tests, which swap `allium_cli.DEFAULT_AUTHORITIES`
/// directly.
fn default_authority_from(defaults: &[(&str, Option<&str>)]) -> (Option<String>, Option<String>) {
    if let Ok(env_address) = std::env::var("ALLIUM_DEFAULT_AUTHORITY") {
        if !env_address.is_empty() {
            let trust_hex = std::env::var("ALLIUM_DEFAULT_TRUST_AUTHORITY")
                .ok()
                .filter(|s| !s.is_empty());
            return (Some(env_address), trust_hex);
        }
    }
    if let Some((address, trust_hex)) = defaults.first() {
        return (Some((*address).to_string()), trust_hex.map(|s| s.to_string()));
    }
    (None, None)
}

/// Fall back to [`default_authority`] when neither `--authority` nor a
/// `--config` file supplied one for this role.
///
/// Only ever fires when `args.authority` is still unset after CLI+config
/// resolution, so an operator's own choice -- of *any* authority, including
/// one that happens to have no --trust-authority of its own -- always wins
/// outright. The paired trust key is only ever attached alongside the
/// default address itself (never bolted onto an operator-chosen address
/// they didn't also choose to pin), and only when they haven't already set
/// their own `--trust-authority` for it.
pub fn apply_default_authority(args: &mut Args) {
    if is_set(&args.authority) {
        return;
    }
    let (address, trust_hex) = default_authority();
    let Some(address) = address else { return };
    args.authority = Some(address);
    if !is_set(&args.trust_authority) {
        if let Some(trust_hex) = trust_hex {
            args.trust_authority = Some(trust_hex);
        }
    }
}

/// `args.authority` may name several authorities, comma-separated
/// (multi-authority quorum -- see `allium::consensus`).
pub fn authority_addresses(args: &Args) -> Vec<String> {
    match &args.authority {
        Some(value) if !value.is_empty() => value
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect(),
        _ => Vec::new(),
    }
}

/// The first configured authority: the one used for things that are not
/// (yet) replicated -- hidden-service descriptors and NAT introduction.
pub fn primary_authority(args: &Args) -> Option<String> {
    authority_addresses(args).into_iter().next()
}

/// Refuse to proceed with an unpinned directory authority.
///
/// An unpinned `--authority` is a real MITM/impersonation vector on its
/// own terms: `--trust-authority` is opt-in, so by default whoever answers
/// at `--authority` is accepted as authoritative, with no way to detect an
/// impostor. `--allow-unpinned-authority` is the explicit, loud opt-out
/// for a single-machine demo/test, where every process is provably the
/// operator's own.
///
/// No-op if `args.authority` is unset (nothing to pin) or
/// `args.trust_authority` is already set (already pinned).
pub fn require_authority_pin(args: &Args, context: &str) -> Result<(), CliExit> {
    if !is_set(&args.authority) || is_set(&args.trust_authority) {
        return Ok(());
    }
    let authority = args.authority.as_deref().unwrap_or("");
    if args.allow_unpinned_authority.unwrap_or(false) {
        say(&format!(
            "{context}: NOTE: --allow-unpinned-authority is set -- the directory \
             authority at {authority} will be trusted on first use, exactly like any \
             other unpinned hop.  Fine for a single-machine demo where every process is \
             provably yours; never for anything real."
        ));
        return Ok(());
    }
    Err(CliExit::error(format!(
        "{context}: --authority {authority} is set without --trust-authority.  An \
         unpinned directory authority is a real MITM/impersonation vector -- see \
         ALLIUM_SECURITY_AUDIT.md in the repo root for the full writeup -- not merely a \
         recommendation, so this is enforced: pass --trust-authority HEX (the \
         authority's own fingerprint, printed when it starts -- 'pin this on the \
         client' in its startup log), or, for a single-machine demo/test where you \
         already know every process is yours, pass --allow-unpinned-authority to \
         proceed without it."
    )))
}

/// Python truthiness for an `Option<String>` CLI/config field: `None` and
/// `Some("")` are both "unset", matching `if args.some_field:` throughout
/// `allium_cli.py`.
pub fn is_set(value: &Option<String>) -> bool {
    matches!(value, Some(v) if !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> Args {
        Args { role: "client".to_string(), ..Args::default() }
    }

    #[test]
    fn parse_addr_splits_at_last_colon() {
        assert_eq!(parse_addr("127.0.0.1:9050").unwrap(), ("127.0.0.1".to_string(), 9050));
        assert_eq!(parse_addr("::1:9050").unwrap(), ("::1".to_string(), 9050));
    }

    #[test]
    fn parse_addr_rejects_missing_colon_or_bad_port() {
        assert!(parse_addr("127.0.0.1").is_err());
        assert!(parse_addr("127.0.0.1:notaport").is_err());
        assert!(parse_addr("127.0.0.1:99999").is_err());
    }

    #[test]
    fn encode_ack_frame_matches_wire_layout() {
        let frame = encode_ack_frame(0x01020304, 0x05060708);
        assert_eq!(&frame[0..4], ACK_MAGIC);
        assert_eq!(&frame[4..8], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&frame[8..12], &[0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0u8, 1, 2, 254, 255];
        assert_eq!(hex_decode(&hex_encode(&bytes)).unwrap(), bytes.to_vec());
        assert_eq!(hex_encode(&[0xAB, 0xCD]), "abcd");
    }

    #[test]
    fn hex_decode_accepts_uppercase_and_rejects_malformed() {
        assert_eq!(hex_decode("AB").unwrap(), vec![0xAB]);
        assert!(hex_decode("abc").is_err()); // odd length
        assert!(hex_decode("zz").is_err()); // not hex
    }

    #[test]
    fn split_trust_keys_trims_and_drops_empties() {
        assert_eq!(split_trust_keys(" aa , , bb "), vec!["aa".to_string(), "bb".to_string()]);
        assert_eq!(split_trust_keys(""), Vec::<String>::new());
    }

    #[test]
    fn validate_trust_keys_accepts_32_byte_keys_and_canonicalizes_case() {
        let key = "AB".repeat(32);
        let result = validate_trust_keys(&key, "TrustGuard").unwrap();
        assert_eq!(result, "ab".repeat(32));
    }

    #[test]
    fn validate_trust_keys_rejects_wrong_length_and_bad_hex() {
        assert!(validate_trust_keys("aabb", "TrustGuard").is_err());
        assert!(validate_trust_keys(&("zz".repeat(32)), "TrustGuard").is_err());
    }

    #[test]
    fn validate_trust_keys_accepts_comma_separated_list() {
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let joined = format!("{a},{b}");
        assert_eq!(validate_trust_keys(&joined, "TrustGuard").unwrap(), joined);
    }

    /// Clears both default-authority env vars and returns the lock guard
    /// that must be held for the rest of the test -- pairs with dropping
    /// the guard (end of scope) to release it for the next test.
    fn clear_default_authority_env() -> std::sync::MutexGuard<'static, ()> {
        let guard = env_test_lock::LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("ALLIUM_DEFAULT_AUTHORITY");
        std::env::remove_var("ALLIUM_DEFAULT_TRUST_AUTHORITY");
        guard
    }

    #[test]
    fn default_authority_is_empty_by_default_without_env_vars() {
        let _guard = clear_default_authority_env();
        assert_eq!(default_authority(), (None, None));
    }

    #[test]
    fn default_authority_env_var_address_with_no_env_trust_key_and_no_constant() {
        let _guard = clear_default_authority_env();
        std::env::set_var("ALLIUM_DEFAULT_AUTHORITY", "203.0.113.9:9030");
        assert_eq!(default_authority(), (Some("203.0.113.9:9030".to_string()), None));
        std::env::remove_var("ALLIUM_DEFAULT_AUTHORITY");
    }

    #[test]
    fn default_authority_env_var_pairs_address_with_its_own_trust_key() {
        let _guard = clear_default_authority_env();
        std::env::set_var("ALLIUM_DEFAULT_AUTHORITY", "203.0.113.9:9030");
        std::env::set_var("ALLIUM_DEFAULT_TRUST_AUTHORITY", "ab".repeat(32));
        assert_eq!(default_authority(), (Some("203.0.113.9:9030".to_string()), Some("ab".repeat(32))));
        std::env::remove_var("ALLIUM_DEFAULT_AUTHORITY");
        std::env::remove_var("ALLIUM_DEFAULT_TRUST_AUTHORITY");
    }

    #[test]
    fn default_authority_empty_string_env_var_is_treated_as_unset() {
        let _guard = clear_default_authority_env();
        std::env::set_var("ALLIUM_DEFAULT_AUTHORITY", "");
        // Falls through to the (empty, in this source tree) constant list,
        // exactly as if the env var had never been set at all.
        assert_eq!(default_authority(), (None, None));
        std::env::remove_var("ALLIUM_DEFAULT_AUTHORITY");
    }

    #[test]
    fn default_authority_env_var_overrides_the_constant_list() {
        let _guard = clear_default_authority_env();
        std::env::set_var("ALLIUM_DEFAULT_AUTHORITY", "10.0.0.9:9030");
        let constant = [("203.0.113.9:9030", Some("cc".repeat(32)))];
        let constant_refs: Vec<(&str, Option<&str>)> =
            constant.iter().map(|(a, t)| (*a, t.as_deref())).collect();
        assert_eq!(default_authority_from(&constant_refs), (Some("10.0.0.9:9030".to_string()), None));
        std::env::remove_var("ALLIUM_DEFAULT_AUTHORITY");
    }

    #[test]
    fn default_authority_constant_list_is_used_when_no_env_var_is_set() {
        let _guard = clear_default_authority_env();
        let trust = "cc".repeat(32);
        let constant: &[(&str, Option<&str>)] = &[("203.0.113.9:9030", Some(trust.as_str()))];
        assert_eq!(default_authority_from(constant), (Some("203.0.113.9:9030".to_string()), Some(trust)));
    }

    #[test]
    fn default_authority_constant_entry_may_have_no_trust_key() {
        let _guard = clear_default_authority_env();
        let constant: &[(&str, Option<&str>)] = &[("203.0.113.9:9030", None)];
        assert_eq!(default_authority_from(constant), (Some("203.0.113.9:9030".to_string()), None));
    }

    #[test]
    fn default_authority_only_the_first_constant_entry_is_consulted() {
        let _guard = clear_default_authority_env();
        let constant: &[(&str, Option<&str>)] =
            &[("203.0.113.9:9030", None), ("198.51.100.7:9030", Some("should never be reached"))];
        assert_eq!(default_authority_from(constant), (Some("203.0.113.9:9030".to_string()), None));
    }

    #[test]
    fn apply_default_authority_never_overrides_an_existing_authority() {
        let _guard = clear_default_authority_env();
        std::env::set_var("ALLIUM_DEFAULT_AUTHORITY", "10.0.0.9:9030");
        let mut args = base_args();
        args.authority = Some("10.0.0.1:9030".to_string());
        args.trust_authority = Some("pinned".to_string());
        apply_default_authority(&mut args);
        assert_eq!(args.authority.as_deref(), Some("10.0.0.1:9030"));
        assert_eq!(args.trust_authority.as_deref(), Some("pinned"));
        std::env::remove_var("ALLIUM_DEFAULT_AUTHORITY");
    }

    #[test]
    fn apply_default_authority_leaves_authority_empty_when_no_default_is_configured() {
        let _guard = clear_default_authority_env();
        let mut args = base_args();
        apply_default_authority(&mut args);
        assert_eq!(args.authority, None);
        assert_eq!(args.trust_authority, None);
    }

    #[test]
    fn apply_default_authority_fills_in_both_authority_and_its_paired_trust_key() {
        let _guard = clear_default_authority_env();
        std::env::set_var("ALLIUM_DEFAULT_AUTHORITY", "203.0.113.9:9030");
        std::env::set_var("ALLIUM_DEFAULT_TRUST_AUTHORITY", "ab".repeat(32));
        let mut args = base_args();
        apply_default_authority(&mut args);
        assert_eq!(args.authority.as_deref(), Some("203.0.113.9:9030"));
        assert_eq!(args.trust_authority.as_deref(), Some("ab".repeat(32).as_str()));
        std::env::remove_var("ALLIUM_DEFAULT_AUTHORITY");
        std::env::remove_var("ALLIUM_DEFAULT_TRUST_AUTHORITY");
    }

    #[test]
    fn apply_default_authority_with_no_trust_key_leaves_trust_authority_empty() {
        let _guard = clear_default_authority_env();
        std::env::set_var("ALLIUM_DEFAULT_AUTHORITY", "203.0.113.9:9030");
        let mut args = base_args();
        apply_default_authority(&mut args);
        assert_eq!(args.authority.as_deref(), Some("203.0.113.9:9030"));
        assert_eq!(args.trust_authority, None);
        std::env::remove_var("ALLIUM_DEFAULT_AUTHORITY");
    }

    #[test]
    fn apply_default_authority_never_overwrites_an_operators_own_trust_authority() {
        // The operator picked *some* authority via the default (no
        // args.authority of their own) but separately pinned their own
        // trust key for it -- the default's paired key must not clobber
        // that, exactly like an operator-chosen address's pin never being
        // touched.
        let _guard = clear_default_authority_env();
        std::env::set_var("ALLIUM_DEFAULT_AUTHORITY", "203.0.113.9:9030");
        std::env::set_var("ALLIUM_DEFAULT_TRUST_AUTHORITY", "ab".repeat(32));
        let mut args = base_args();
        args.trust_authority = Some("operators-own-pin".to_string());
        apply_default_authority(&mut args);
        assert_eq!(args.authority.as_deref(), Some("203.0.113.9:9030"));
        assert_eq!(args.trust_authority.as_deref(), Some("operators-own-pin"));
        std::env::remove_var("ALLIUM_DEFAULT_AUTHORITY");
        std::env::remove_var("ALLIUM_DEFAULT_TRUST_AUTHORITY");
    }

    #[test]
    fn authority_addresses_splits_and_trims_comma_list() {
        let mut args = base_args();
        args.authority = Some(" a:1 , b:2 ".to_string());
        assert_eq!(authority_addresses(&args), vec!["a:1".to_string(), "b:2".to_string()]);
        assert_eq!(primary_authority(&args), Some("a:1".to_string()));
    }

    #[test]
    fn authority_addresses_empty_when_unset() {
        let args = base_args();
        assert!(authority_addresses(&args).is_empty());
        assert_eq!(primary_authority(&args), None);
    }

    #[test]
    fn require_authority_pin_noop_without_authority_or_already_pinned() {
        let args = base_args();
        assert!(require_authority_pin(&args, "client").is_ok());

        let mut args = base_args();
        args.authority = Some("a:1".to_string());
        args.trust_authority = Some("pin".to_string());
        assert!(require_authority_pin(&args, "client").is_ok());
    }

    #[test]
    fn require_authority_pin_errors_when_unpinned_and_not_allowed() {
        let mut args = base_args();
        args.authority = Some("a:1".to_string());
        assert!(require_authority_pin(&args, "client").is_err());
    }

    #[test]
    fn require_authority_pin_allows_explicit_opt_out() {
        let mut args = base_args();
        args.authority = Some("a:1".to_string());
        args.allow_unpinned_authority = Some(true);
        assert!(require_authority_pin(&args, "client").is_ok());
    }
}
