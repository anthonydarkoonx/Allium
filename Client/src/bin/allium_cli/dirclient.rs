//! Directory client: the low-level "talk to --authority" round trip shared
//! by a publishing relay and a fetching client, plus route selection, NAT
//! hole-punch brokering, and persisted-guard bookkeeping (port of the
//! `allium_cli.py` section of the same name).
//!
//! No async runtime is vendored, so every "await
//! `loop.run_in_executor(...)`" in the Python original is just a direct
//! blocking call here; the one place Python used real concurrency
//! (`asyncio.gather` over several authorities' votes) is a `std::thread`
//! per authority, joined at the end -- see [`fetch_relay_directory`].

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::UdpSocket;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use allium::circuit::{Addr, CircuitBuilder, CircuitError, EncryptOptions, DEFAULT_SEND_JITTER};
use allium::consensus::{
    compute_consensus, decode_vote, default_quorum, encode_vote_request, missing_identities, Trust,
    Vote,
};
use allium::directory::{
    Directory, DirectoryError, DirectoryOptions, RelayDescriptor, SelectRouteOptions,
    DESCRIPTOR_VERSION_2,
};
use allium::dirwire::{decode_fetch_reply, encode_fetch_request, fragment_message, DirReassembler, DirWireError};
use allium::fragment::DEFAULT_MTU;
use allium::handshake::HandshakeKeys;
use allium::nat::{request_punch, NatError};

use crate::args::Args;
use crate::cli_error::CliExit;
use crate::helpers::{authority_addresses, parse_addr, primary_authority, say, split_trust_keys};

/// How long one directory round trip (add_hop + send + receive) waits,
/// independent of any circuit's own `--timeout`: a directory exchange is a
/// handful of small cells, never a long-lived interactive session.
pub const DIR_ROUND_TRIP_TIMEOUT: f64 = 5.0;

/// Default: comfortably under `DEFAULT_DESCRIPTOR_LIFETIME` (3600s), so a
/// relay always republishes well before its previous descriptor expires.
pub const DEFAULT_PUBLISH_INTERVAL: f64 = 1200.0;

/// The port a client's first (pre-built) circuit is steered toward before
/// any destination is known: nearly all browsing is HTTPS.
pub const PREEMPTIVE_EXIT_PORT: u16 = 443;

/// A recoverable directory/route-selection failure: something a caller
/// may retry, log, and continue past (matching a bare Python exception
/// caught by `except Exception`/`except OSError`), as opposed to
/// [`CliExit`], which always means "print one line and stop the process."
#[derive(Debug, Clone)]
pub struct DirClientError(pub String);

impl fmt::Display for DirClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for DirClientError {}

impl From<CircuitError> for DirClientError {
    fn from(e: CircuitError) -> Self {
        DirClientError(e.to_string())
    }
}
impl From<DirWireError> for DirClientError {
    fn from(e: DirWireError) -> Self {
        DirClientError(e.to_string())
    }
}
impl From<DirectoryError> for DirClientError {
    fn from(e: DirectoryError) -> Self {
        DirClientError(e.to_string())
    }
}
impl From<std::io::Error> for DirClientError {
    fn from(e: std::io::Error) -> Self {
        DirClientError(e.to_string())
    }
}
impl From<CliExit> for DirClientError {
    fn from(e: CliExit) -> Self {
        DirClientError(e.message.unwrap_or_default())
    }
}

fn hex_prefix(bytes: &[u8], chars: usize) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    hex.chars().take(chars).collect()
}

fn identity_prefix(keys: &HandshakeKeys) -> String {
    match &keys.identity_public {
        Some(id) => format!("{}...", hex_prefix(id, 16)),
        None => "<unauthenticated>".to_string(),
    }
}

/// Open an ephemeral one-hop circuit to a directory authority, send one
/// directory-protocol request, and return the reassembled reply bytes.
///
/// Used by both a publishing relay and a fetching client -- both cases are
/// "make one request of the authority and read back one reply", the same
/// shape as the client's own guard handshake, just one hop instead of
/// three and with no persistent SOCKS session on top.
pub fn dir_round_trip(
    authority_addr_text: &str,
    trusted_authority_keys: Option<&[[u8; 32]]>,
    request_bytes: &[u8],
    label: &str,
) -> Result<Vec<u8>, DirClientError> {
    let authority_addr: Addr = parse_addr(authority_addr_text)?;
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    // Room for a large directory reply to queue while cells are being
    // decrypted one by one. Best-effort: some platforms refuse a large
    // SO_RCVBUF, and that's fine.
    let _ = set_rcvbuf(&sock, 1 << 22);

    let trust_first_use = trusted_authority_keys.is_none();
    if trust_first_use {
        say(&format!(
            "{label}: NOTE: no --trust-authority pin given -- the directory authority's \
             identity will be accepted from whoever answers at {authority_addr_text}; pass \
             --trust-authority HEX for anything real."
        ));
    }
    let mut trusted: HashMap<String, Vec<[u8; 32]>> = HashMap::new();
    if let Some(keys) = trusted_authority_keys {
        trusted.insert("authority".to_string(), keys.to_vec());
    }

    let mut builder = CircuitBuilder::new(
        &sock,
        None,
        Duration::from_secs_f64(DIR_ROUND_TRIP_TIMEOUT),
        Some(trusted),
        trust_first_use,
        false,
        1,
        DEFAULT_SEND_JITTER,
        None,
    )?;
    say(&format!("{label}: contacting directory authority at {authority_addr_text} ..."));
    builder.add_hop("authority", authority_addr.clone(), None, None, None)?;
    for wire_bytes in fragment_message(request_bytes, DEFAULT_MTU) {
        builder.send(&wire_bytes, authority_addr.clone(), EncryptOptions::default())?;
    }

    receive_reassembled(&builder)
}

/// Like [`dir_round_trip`], but routes over an already-built circuit
/// (extending it to `authority_addr` as the final hop) instead of
/// contacting the authority directly -- see the hidden-service flows
/// (Tasks #16/#17), which are the only callers that need this.
pub fn receive_over_circuit(builder: &CircuitBuilder<'_>) -> Result<Vec<u8>, DirClientError> {
    receive_reassembled(builder)
}

fn receive_reassembled(builder: &CircuitBuilder<'_>) -> Result<Vec<u8>, DirClientError> {
    let mut reassembler = DirReassembler::new(64);
    let deadline = Instant::now() + Duration::from_secs_f64((DIR_ROUND_TRIP_TIMEOUT * 4.0).max(10.0));
    loop {
        if Instant::now() >= deadline {
            return Err(DirClientError("directory authority did not answer in time".to_string()));
        }
        match builder.receive(Some(Duration::from_secs_f64(DIR_ROUND_TRIP_TIMEOUT))) {
            Ok(raw) => {
                if let Some(message) = reassembler.push(&raw)? {
                    return Ok(message);
                }
            }
            Err(CircuitError::Io(_)) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

fn set_rcvbuf(sock: &UdpSocket, _bytes: i32) -> std::io::Result<()> {
    // `std::net::UdpSocket` has no portable SO_RCVBUF setter; the Python
    // original's `setsockopt(SO_RCVBUF, 1 << 22)` is a best-effort
    // performance hint (its own failure is already swallowed with `except
    // OSError: pass`), so this is a documented no-op rather than reaching
    // for a raw-fd/libc dependency for a hint the OS is free to ignore
    // anyway.
    let _ = sock;
    Ok(())
}

/// Decoded `--trust-authority` hex keys, or `None` if unset -- mirrors
/// `_trusted_authority_keys` (a `HashSet` rather than a `Vec` since every
/// caller only ever tests membership).
pub fn trusted_authority_keys(args: &Args) -> Option<HashSet<Vec<u8>>> {
    let value = args.trust_authority.as_deref()?;
    if value.is_empty() {
        return None;
    }
    Some(
        split_trust_keys(value)
            .into_iter()
            .filter_map(|hex| crate::helpers::hex_decode(&hex).ok())
            .collect(),
    )
}

fn trusted_authority_keys_fixed(args: &Args) -> Option<Vec<[u8; 32]>> {
    let value = args.trust_authority.as_deref()?;
    if value.is_empty() {
        return None;
    }
    Some(
        split_trust_keys(value)
            .into_iter()
            .filter_map(|hex| crate::helpers::hex_decode(&hex).ok())
            .filter_map(|v| v.try_into().ok())
            .collect(),
    )
}

/// Fetch the current live relay set from `args.authority` into a fresh,
/// local [`Directory`].
///
/// Every returned descriptor is re-verified locally before being trusted
/// -- the point of a self-signed descriptor is exactly that a caller need
/// not take the authority's word for it: [`Directory::publish`] re-checks
/// each Ed25519 signature itself, so the authority can omit entries
/// (censor) or add its own relays, but cannot forge or alter one it
/// didn't sign.
///
/// Single-authority addresses that have already answered a VOTE request
/// with "I don't implement that" are remembered here for the life of the
/// process, so a later call skips straight to legacy FETCH instead of
/// paying a fresh [`DIR_ROUND_TRIP_TIMEOUT`]-second wait on a reply that
/// will never come.
///
/// This matters more than it looks: [`fetch_relay_directory`] is called
/// on every circuit rebuild (see `pool.rs`'s retry path), and a relay
/// that rebuilds circuits often -- e.g. because a target keeps refusing
/// CONNECT -- was paying that timeout on every single retry. Confirmed
/// live: a client hammering short-lived, edge-specific CDN URLs (each
/// valid only briefly) kept losing the race against its own rebuild
/// latency, so the wasted wait wasn't just slow, it was actively causing
/// the next attempt to fail too by the time it landed.
///
/// Deliberately scoped to the single-authority case only (matching
/// exactly the branch below that takes legacy FETCH): a multi-authority
/// quorum's per-address vote support isn't assumed to be uniform, so it
/// is never cached or skipped here.
fn no_vote_authorities() -> &'static Mutex<HashSet<String>> {
    static CACHE: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Security audit fix (2026-09-26, finding #5 -- no vetting before
/// self-declaring "guard"): how long this process must have observed an
/// identity's descriptor before it is eligible to be picked as an
/// *unpinned* guard (see [`Directory`]'s `min_guard_age_seconds` doc). A
/// self-declared role byte in a signed descriptor is not corroborated by
/// anyone else -- the only signal this process can't be fed by the relay
/// itself is its own clock. Long enough that a brand-new identity can't
/// buy guard eligibility with a single fetch cycle (this cache's own
/// lifetime is 30-90 min, see `DIRECTORY_CACHE_BASE_SECS`/`_JITTER_SECS`
/// below), short enough that a small or fresh deployment still bootstraps
/// within part of a day. An explicit `preferred_guard` (a previous
/// session's own persisted pin) is exempt -- see `select_route`'s doc.
const MIN_GUARD_OBSERVATION_AGE_SECS: f64 = 6.0 * 3600.0;

/// Process-lifetime registry of when each relay identity was first
/// observed, keyed the same way `Directory::first_seen` is. Exists
/// outside `Directory` itself because `fetch_relay_directory` builds a
/// brand-new `Directory` object every refresh cycle -- without this, a
/// day-old guard and a brand-new one would look identical to every fresh
/// `Directory`, defeating `MIN_GUARD_OBSERVATION_AGE_SECS` entirely. Never
/// persisted to disk: a process restart starts this history over, but an
/// already-pinned guard (`--state-file`) is unaffected, since pinning
/// bypasses this check -- see `MIN_GUARD_OBSERVATION_AGE_SECS`'s doc.
fn guard_first_seen_registry() -> &'static Mutex<HashMap<Vec<u8>, f64>> {
    static REGISTRY: OnceLock<Mutex<HashMap<Vec<u8>, f64>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn unix_now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

// -- guard-observation history on disk ---------------------------------------
//
// The registry above lives only as long as the process. A one-shot command
// such as `allium service` exits when it cannot pick a route, so on a network
// whose guard has not yet been seen for `MIN_GUARD_OBSERVATION_AGE_SECS` it
// would fail on every start and could never get past the wait. With a state
// file (a client's `--state-file`; for a service the one inside
// `--hidden-service-dir`) the history is also kept in a file beside it, so a
// later start sees how long each relay has really been around.
//
// The file records only when each identity was *first* seen, exactly what the
// in-memory registry records. It is as trustworthy as the private directory
// it lives in (0700, file 0600).

/// Most identities read back from, or written to, a history file.
const MAX_GUARD_HISTORY_ENTRIES: usize = 4096;

/// Where this process keeps its guard-observation history between runs, if it
/// has a state file to put it beside.
fn guard_history_path(args: &Args) -> Option<String> {
    let state = args.state_file.as_deref().filter(|s| !s.is_empty())?;
    Some(format!("{state}.guard-history"))
}

/// One `<identity hex> <first seen, unix seconds>` line per relay, sorted.
fn encode_guard_history(history: &HashMap<Vec<u8>, f64>) -> String {
    let mut lines: Vec<String> = history.iter().map(|(id, first)| format!("{} {}", crate::helpers::hex_encode(id), first)).collect();
    lines.sort();
    let mut out = String::from("# allium guard-observation history: <relay identity hex> <first seen, unix seconds>\n");
    for line in lines.into_iter().take(MAX_GUARD_HISTORY_ENTRIES) {
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// The inverse of [`encode_guard_history`]. Anything malformed is skipped, so a
/// damaged file can only ever *lose* history (making the check stricter),
/// never invent it. A time in the future is clamped to `now`: nothing can have
/// been seen later than now. When an identity appears twice the earlier time
/// wins, matching how the registry itself only ever keeps the earliest.
fn decode_guard_history(text: &str, now: f64) -> HashMap<Vec<u8>, f64> {
    let mut out: HashMap<Vec<u8>, f64> = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(id_hex), Some(first), None) = (fields.next(), fields.next(), fields.next()) else { continue };
        let Ok(id) = crate::helpers::hex_decode(id_hex) else { continue };
        if id.len() != 32 {
            continue;
        }
        let Ok(first) = first.parse::<f64>() else { continue };
        if !first.is_finite() || first < 0.0 {
            continue;
        }
        let first = first.min(now);
        if out.len() >= MAX_GUARD_HISTORY_ENTRIES && !out.contains_key(&id) {
            continue;
        }
        out.entry(id).and_modify(|e| *e = e.min(first)).or_insert(first);
    }
    out
}

/// Fold `from` into `into`, keeping the earliest time per identity. Returns
/// whether `into` changed.
fn merge_first_seen(into: &mut HashMap<Vec<u8>, f64>, from: &HashMap<Vec<u8>, f64>) -> bool {
    let mut changed = false;
    for (id, &first) in from {
        match into.get_mut(id) {
            Some(existing) if *existing <= first => {}
            Some(existing) => {
                *existing = first;
                changed = true;
            }
            None => {
                if into.len() < MAX_GUARD_HISTORY_ENTRIES {
                    into.insert(id.clone(), first);
                    changed = true;
                }
            }
        }
    }
    changed
}

/// Read the history file at `path` (missing or unreadable means none).
fn load_guard_history(path: &str, now: f64) -> HashMap<Vec<u8>, f64> {
    match std::fs::read_to_string(path) {
        Ok(text) => decode_guard_history(&text, now),
        Err(_) => HashMap::new(),
    }
}

pub fn fetch_relay_directory(args: &Args, label: &str) -> Result<Directory, CliExit> {
    let trusted_keys = trusted_authority_keys_fixed(args);
    let addresses = authority_addresses(args);
    let quorum = args
        .authority_quorum
        .map(|q| q as usize)
        .unwrap_or_else(|| default_quorum(addresses.len()));
    if quorum > addresses.len() {
        return Err(CliExit::error(format!(
            "{label}: --authority-quorum {quorum} is more than the {} authority(ies) configured",
            addresses.len()
        )));
    }

    // See `no_vote_authorities`'s doc comment.
    let skip_vote =
        addresses.len() == 1 && no_vote_authorities().lock().unwrap().contains(&addresses[0].to_string());

    let mut votes = Vec::new();
    if !skip_vote {
        // One thread per authority -- the Rust analogue of Python's
        // `asyncio.gather(*(_one_vote(a) for a in addresses))`.
        let vote_results: Vec<Result<Vote, DirClientError>> = std::thread::scope(|scope| {
            let handles: Vec<_> = addresses
                .iter()
                .map(|address| {
                    let trusted_keys = trusted_keys.clone();
                    scope.spawn(move || -> Result<Vote, DirClientError> {
                        let reply = dir_round_trip(address, trusted_keys.as_deref(), &encode_vote_request(), label)?;
                        // `consensus::Trust::Only` borrows `&[Vec<u8>]`;
                        // `trusted_keys` here is `Option<Vec<[u8; 32]>>` (the
                        // fixed-size form `CircuitBuilder` wants), so build the
                        // `Vec<Vec<u8>>` shape `decode_vote` wants on this side.
                        let owned: Vec<Vec<u8>> = trusted_keys.iter().flatten().map(|k| k.to_vec()).collect();
                        let trust = if trusted_keys.is_some() { Trust::Only(&owned) } else { Trust::AllowAny };
                        decode_vote(&reply, trust, None).map_err(|e| DirClientError(e.to_string()))
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap_or_else(|_| Err(DirClientError("vote thread panicked".to_string())))).collect()
        });

        for (address, result) in addresses.iter().zip(vote_results) {
            match result {
                Ok(vote) => votes.push(vote),
                Err(e) => say(&format!("{label}: no usable vote from authority {address} ({e})")),
            }
        }
    }

    let (descriptors, measured, verified_subnets) = if !votes.is_empty() || addresses.len() > 1 {
        let distinct_authorities: HashSet<&Vec<u8>> = votes.iter().map(|v| &v.authority).collect();
        if distinct_authorities.len() < quorum {
            return Err(CliExit::error(format!(
                "{label}: no directory consensus: only {} valid authority vote(s), need {quorum} for a quorum",
                votes.len()
            )));
        }
        // Descriptors are fetched once, from the voting authorities in
        // turn, until every relay a quorum agreed on is covered (normally
        // the first fetch does it). Each one is checked against the
        // votes' digests, so the authority that serves them can't
        // substitute its own.
        let mut pool: Vec<RelayDescriptor> = Vec::new();
        for address in &addresses {
            match dir_round_trip(address, trusted_keys.as_deref(), &encode_fetch_request(DESCRIPTOR_VERSION_2), label)
                .map_err(|e| e.to_string())
                .and_then(|reply| decode_fetch_reply(&reply).map_err(|e| e.to_string()))
            {
                Ok(fetched) => pool.extend(fetched),
                Err(e) => {
                    say(&format!("{label}: descriptor fetch from {address} failed ({e})"));
                    continue;
                }
            }
            match missing_identities(&votes, quorum, &pool) {
                Ok(missing) if missing.is_empty() => break,
                _ => continue,
            }
        }
        compute_consensus(&votes, quorum, &pool).map_err(|e| CliExit::error(format!("{label}: {e}")))?
    } else {
        // A single authority that doesn't speak VOTE yet (an older
        // build, or one we already know doesn't implement it -- see
        // `skip_vote` above): fall back to the legacy unsigned FETCH,
        // which is no weaker than what a one-authority setup always had
        // (the circuit to it is still pinned to --trust-authority).
        no_vote_authorities().lock().unwrap().insert(addresses[0].to_string());
        if skip_vote {
            say(&format!("{label}: authority does not serve signed votes (cached); using legacy FETCH"));
        } else {
            say(&format!("{label}: authority does not serve signed votes; using legacy FETCH"));
        }
        let reply = dir_round_trip(
            &addresses[0],
            trusted_keys.as_deref(),
            &encode_fetch_request(DESCRIPTOR_VERSION_2),
            label,
        )
        .map_err(|e| CliExit::error(e.to_string()))?;
        let descriptors = decode_fetch_reply(&reply)
            .map_err(|e| CliExit::error(format!("{label}: directory authority sent a malformed reply: {e}")))?;
        // No votes at all in this branch (single authority, legacy FETCH
        // only), so there is no quorum to derive a verified subnet from
        // either -- every descriptor here falls back to its self-declared
        // host for subnet-diversity purposes, exactly as risky as the
        // single-authority case already is for everything else.
        (descriptors, HashMap::new(), HashMap::new())
    };

    if !votes.is_empty() {
        say(&format!(
            "{label}: {} of {} authority vote(s) verified; {} relay(s) listed by at least {quorum}",
            votes.len(),
            addresses.len(),
            descriptors.len()
        ));
    }

    let min_guard_age = args.min_guard_age.unwrap_or(MIN_GUARD_OBSERVATION_AGE_SECS);
    if min_guard_age < MIN_GUARD_OBSERVATION_AGE_SECS {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            say(&format!(
                "{label}: WARNING: --min-guard-age {min_guard_age}s is below the default {MIN_GUARD_OBSERVATION_AGE_SECS}s: a relay that has only just appeared in the directory \
                 can be picked as a guard. Fine for a test network; do not use it on a network you do not run."
            ));
        });
    }
    let mut directory = Directory::new(DirectoryOptions { min_guard_age_seconds: Some(min_guard_age), ..Default::default() })
        .map_err(|e| CliExit::error(format!("{label}: {e}")))?;
    directory.set_measured_bandwidth(measured);
    // Seed this fresh `Directory` with this process's accumulated
    // guard-observation history before publishing into it -- see
    // `guard_first_seen_registry`'s doc on why that history has to live
    // outside any single `Directory` instance. When there is a state file,
    // what earlier runs recorded is folded in first.
    let history_path = guard_history_path(args);
    let on_disk = history_path.as_deref().map(|p| load_guard_history(p, unix_now())).unwrap_or_default();
    {
        let mut registry = guard_first_seen_registry().lock().unwrap();
        merge_first_seen(&mut registry, &on_disk);
    }
    directory.set_first_seen(guard_first_seen_registry().lock().unwrap().clone());
    let mut accepted = 0;
    let total = descriptors.len();
    for descriptor in descriptors {
        let verified_subnet = verified_subnets.get(&descriptor.identity_public).copied();
        match directory.publish_verified(descriptor, verified_subnet) {
            Ok(true) => accepted += 1,
            Ok(false) => {}
            Err(e) => say(&format!("{label}: dropped a bad descriptor from the authority ({e})")),
        }
    }
    say(&format!(
        "{label}: directory authority returned {total} descriptor(s), {accepted} verified and live"
    ));
    // Carry forward every identity's earliest-known first_seen (this
    // directory's own `publish_verified` never overwrites one already
    // seeded from the registry -- see `Directory::publish_verified`).
    let mut registry = guard_first_seen_registry().lock().unwrap();
    for (identity, first_seen) in directory.first_seen_snapshot() {
        registry.entry(identity).or_insert(first_seen);
    }
    let snapshot = registry.clone();
    drop(registry);
    if let Some(path) = &history_path {
        // Written even when route selection is about to fail: that first run is
        // exactly the one whose observations the next run needs.
        let mut to_save = on_disk;
        if merge_first_seen(&mut to_save, &snapshot) {
            if let Err(e) = write_atomically(path, &encode_guard_history(&to_save)) {
                say(&format!("{label}: could not save the guard-observation history to {path} ({e}); a later run will start counting again"));
            }
        }
    }
    Ok(directory)
}

/// `fetch_relay_directory` above is a full VOTE+FETCH round
/// trip to every configured authority, made from a freshly bound local
/// socket -- i.e. from the client's real IP. Every caller used to invoke
/// it directly, and there was no cache, so a client building one isolated
/// circuit per destination (`--isolate-by-destination`) or retrying a
/// failed circuit sent the authority a fresh, timestamped "this IP is
/// about to build a circuit" signal before every single one. The impact
/// is real: an activity oracle, timing correlation with a colluding
/// relay, and a local eavesdropper's "new site now" signal.
///
/// The fix kept here is the client-only part that needs no wire-format
/// change: one
/// verified [`Directory`] is kept for the life of the process, behind a
/// jittered validity window, and every caller gets a cloned [`Arc`] to it
/// instead of its own authority round trip. A background/periodic
/// refresh on that timer is decoupled from circuit builds entirely --
/// nothing on the SOCKS-CONNECT critical path ever blocks on it, because
/// the cache is consulted synchronously and only *misses* (first call, or
/// the timer expiring) pay for a fetch.
///
/// (Routing the fetch itself over the guard circuit instead of dialing
/// the authority directly would close the remaining
/// once-per-cache-lifetime exposure too, the same way
/// [`dir_round_trip_over_circuit`] already does for hidden-service
/// descriptors. That needs an already-built circuit to extend from, which
/// doesn't exist yet for the very first fetch of a process, so it is not
/// attempted here; the mitigating factor -- the authority
/// always learns the client's IP once at startup regardless -- still
/// applies.)
struct CachedDirectory {
    directory: Arc<Directory>,
    fetched_at: Instant,
    valid_for: Duration,
    // Tracked separately from `fetched_at`: rate-limiting a forced
    // refresh against the *previous forced refresh* (rather than against
    // the ordinary fetch that populated the cache) matters because a
    // forced refresh is most needed right after a cold-start fetch that
    // turns out to be unusable (e.g. too few relays for a 3-hop route --
    // see `get_or_refresh_directory`). Rate-limiting against `fetched_at`
    // there would block exactly that first, most useful, forced retry,
    // since it always lands within `MIN_FORCED_REFRESH_INTERVAL` of it.
    last_forced_refresh_at: Option<Instant>,
}

fn directory_cache() -> &'static Mutex<Option<CachedDirectory>> {
    static CACHE: OnceLock<Mutex<Option<CachedDirectory>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

/// Base lifetime of a cached directory before a background refresh is
/// due, before jitter.
const DIRECTORY_CACHE_BASE_SECS: f64 = 1800.0; // 30 min
/// Extra, per-fetch-randomized lifetime added on top of the base, so this
/// process's refreshes don't land on a predictable clock and don't all
/// line up with every other client's.
const DIRECTORY_CACHE_JITTER_SECS: f64 = 1800.0; // up to +30 min

/// A route-selection failure against the cached directory (every relay it
/// offered is gone, unreachable, or excluded) is allowed to force one
/// early refresh -- but never more often than this, so a client stuck
/// retrying (exactly the case that motivated this fix) can't turn the
/// forced-refresh path back into a fetch-per-circuit.
const MIN_FORCED_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

fn jittered_cache_lifetime() -> Duration {
    let raw = allium::osrand::bytes(4);
    let fraction = u32::from_le_bytes(raw.try_into().expect("osrand::bytes(4) is always 4 bytes")) as f64
        / u32::MAX as f64;
    Duration::from_secs_f64(DIRECTORY_CACHE_BASE_SECS + fraction * DIRECTORY_CACHE_JITTER_SECS)
}

/// Return the cached directory, fetching (and installing a fresh one)
/// only on a cold start or once the jittered validity window has passed.
/// This is what every ordinary caller (`build_via_authority`,
/// `pick_rendezvous_relay`) should use instead of calling
/// `fetch_relay_directory` directly.
pub fn cached_relay_directory(args: &Args, label: &str) -> Result<Arc<Directory>, CliExit> {
    get_or_refresh_directory(args, label, false)
}

/// Force a refresh ahead of the cache's own timer -- rate-limited by
/// [`MIN_FORCED_REFRESH_INTERVAL`] -- for the one case that needs to jump
/// the queue: route selection came up empty against the currently cached
/// directory. Still returns the (possibly still-cached, if rate-limited)
/// directory rather than erroring, so a caller can just retry selection
/// against whatever this returns.
pub fn refresh_relay_directory(args: &Args, label: &str) -> Result<Arc<Directory>, CliExit> {
    get_or_refresh_directory(args, label, true)
}

/// Pure policy decision behind [`get_or_refresh_directory`]'s cache check,
/// split out so it's unit-testable without a live authority to fetch
/// from: given an existing cache entry and whether this call is a forced
/// (post-selection-failure) refresh, should the cached copy be reused
/// as-is?
fn should_use_cached(cached: &CachedDirectory, force: bool) -> bool {
    let stale = cached.fetched_at.elapsed() >= cached.valid_for;
    if stale {
        return false;
    }
    if !force {
        return true;
    }
    cached
        .last_forced_refresh_at
        .is_some_and(|t| t.elapsed() < MIN_FORCED_REFRESH_INTERVAL)
}

fn get_or_refresh_directory(args: &Args, label: &str, force: bool) -> Result<Arc<Directory>, CliExit> {
    // Held across the fetch itself (not just the cache check) on purpose:
    // this collapses a thundering herd of concurrent callers (e.g. an
    // `--isolate-by-destination` client building several circuits at
    // once on a cold start) into a single authority round trip instead
    // of one per caller, which is the exact failure mode this fix
    // exists to remove. The cost is that a concurrent caller with a
    // still-valid cached copy briefly waits behind a refresh in
    // progress rather than reading it immediately; refreshes are rare
    // (every 30-60 min, or rate-limited on-demand) so that's a fine
    // trade.
    let mut cache = directory_cache().lock().unwrap();
    if let Some(cached) = cache.as_ref() {
        if should_use_cached(cached, force) {
            return Ok(Arc::clone(&cached.directory));
        }
    }
    let directory = Arc::new(fetch_relay_directory(args, label)?);
    let last_forced_refresh_at =
        if force { Some(Instant::now()) } else { cache.as_ref().and_then(|c| c.last_forced_refresh_at) };
    *cache = Some(CachedDirectory {
        directory: Arc::clone(&directory),
        fetched_at: Instant::now(),
        valid_for: jittered_cache_lifetime(),
        last_forced_refresh_at,
    });
    Ok(directory)
}

/// `select_route` with progressively relaxed *preferences*.
///
/// Tries, in order: avoid recently-failed exits AND require an exit whose
/// port summary accepts `exit_port`; then drop the avoid-list; then drop
/// the port requirement. Guard pinning is never relaxed
/// ([`DirectoryError::PreferredGuardUnavailable`] always propagates).
/// Raises the last [`DirectoryError`] if even the unconstrained pick
/// fails. `hard_exclude` identities are excluded at every step (never
/// relaxed).
#[allow(clippy::too_many_arguments)]
pub fn select_route_best_effort(
    directory: &Directory,
    preferred_guard: Option<&[u8]>,
    require_preferred_guard: bool,
    avoid: &HashSet<Vec<u8>>,
    exit_port: Option<u16>,
    hard_exclude: &HashSet<Vec<u8>>,
    require_pq: bool,
) -> Result<Vec<RelayDescriptor>, DirectoryError> {
    let avoid: HashSet<Vec<u8>> = avoid.union(hard_exclude).cloned().collect();

    let mut attempts: Vec<HashSet<Vec<u8>>> = Vec::new();
    if !avoid.is_empty() || exit_port.is_some() {
        attempts.push(avoid.clone());
    }
    let avoid_minus_hard: HashSet<Vec<u8>> = avoid.difference(hard_exclude).cloned().collect();
    if !avoid_minus_hard.is_empty() && exit_port.is_some() {
        attempts.push(hard_exclude.clone());
    }
    attempts.push(hard_exclude.clone());

    let mut last_err: Option<DirectoryError> = None;
    for (index, exclude) in attempts.iter().enumerate() {
        // Only the first two attempts carry an exit-port preference (see
        // the Python original's per-attempt `**extra`); the last one
        // drops it entirely.
        let this_exit_port = if index < attempts.len() - 1 { exit_port } else { None };
        let opts = SelectRouteOptions {
            hops: 3,
            preferred_guard: preferred_guard.map(|p| p.to_vec()),
            require_preferred_guard,
            require_pq,
            exclude_identities: exclude.iter().cloned().collect(),
            exit_port: this_exit_port,
            ..SelectRouteOptions::default()
        };
        match directory.select_route(opts) {
            Ok(route) => return Ok(route),
            Err(DirectoryError::PreferredGuardUnavailable(m)) => {
                return Err(DirectoryError::PreferredGuardUnavailable(m))
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| DirectoryError::Other("no route selection attempt was made".to_string())))
}

/// Hole-punching to a route's NAT hop failed; `identity` names it so the
/// caller can pick a route without it.
#[derive(Debug, Clone)]
pub struct NatHopUnavailable {
    pub identity: Vec<u8>,
    pub message: String,
}

impl fmt::Display for NatHopUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for NatHopUnavailable {}

/// Broker UDP hole-punches for every NAT hop in `route` (a list of
/// descriptors, guard first) and return the `(host, port)` to use for
/// each hop -- a NAT hop's *current* mapping from its introducer rather
/// than the possibly-stale one in its descriptor. See [`allium::nat`].
///
/// ## Authority-pinned punch destination
///
/// A relay's descriptor is self-signed by the relay itself, so it is not
/// trusted for *where to send anything*: a malicious middle or exit could
/// otherwise name itself (or an accomplice) as the introducer and harvest
/// the client's real IP address before the circuit is even built. So the
/// address a `PUNCH_REQUEST` is sent to is never `reach.introducer_addr()`
/// (the relay's claim) -- it is always `authority_addr`, the client's own
/// configured directory authority (see [`crate::helpers::primary_authority`]),
/// and the reply is accepted only if it is signed by a key in
/// `trusted_authorities`, the client's own `--trust-authority` pin. The
/// descriptor's `introducer_identity` is read only to confirm the relay is
/// pointing at an authority this client actually trusts before bothering to
/// punch at all; it never chooses the destination.
///
/// Both `trusted_authorities` and `authority_addr` are required: with
/// either missing there is nothing to pin the punch to, so every NAT hop is
/// refused outright rather than trusting whatever the relay's own
/// descriptor supplied.
pub fn prepare_nat_hops(
    route: &[RelayDescriptor],
    trusted_authorities: Option<&HashSet<Vec<u8>>>,
    authority_addr: Option<&str>,
    label: &str,
) -> Result<Vec<(String, u16)>, NatHopUnavailable> {
    let mut addrs: Vec<(String, u16)> = route.iter().map(|d| d.endpoint()).collect();
    let mut punched = false;
    // Resolved once, outside the loop: the only address any PUNCH_REQUEST
    // is ever sent to. A malformed/unset `--authority` yields `None` here,
    // which then refuses every NAT hop below rather than falling back to
    // the relay's descriptor.
    let pinned_authority: Option<(String, u16)> = authority_addr.and_then(|text| parse_addr(text).ok());

    for (index, descriptor) in route.iter().enumerate() {
        if !descriptor.behind_nat() {
            continue;
        }
        let reach = descriptor.reachability();
        if index == 0 || reach.is_none() {
            return Err(NatHopUnavailable {
                identity: descriptor.identity_public.clone(),
                message: if reach.is_some() {
                    "a NAT relay can't be a circuit's first hop".to_string()
                } else {
                    "NAT relay has an unreadable reachability extension".to_string()
                },
            });
        }
        let reach = reach.unwrap();

        let (trusted, authority_host, authority_port) = match (trusted_authorities, pinned_authority.as_ref()) {
            (Some(trusted), Some((host, port))) => (trusted, host.as_str(), *port),
            _ => {
                return Err(NatHopUnavailable {
                    identity: descriptor.identity_public.clone(),
                    message: "refusing to broker a NAT hole-punch: no pinned --trust-authority key \
                              and configured --authority address (ALLIUM-H1: a relay's own \
                              descriptor can no longer choose who gets contacted)"
                        .to_string(),
                });
            }
        };
        if !trusted.contains(&reach.introducer_identity) {
            return Err(NatHopUnavailable {
                identity: descriptor.identity_public.clone(),
                message: "NAT relay names an introducer this client does not trust".to_string(),
            });
        }
        match request_punch(
            (authority_host, authority_port),
            &reach.introducer_x25519_public,
            &descriptor.identity_public,
            &route[index - 1].identity_public,
            Duration::from_secs_f64(2.0),
            3,
        ) {
            Ok(addr) => {
                say(&format!(
                    "{label}: hole-punched to NAT relay {}... at {}:{}",
                    hex_prefix(&descriptor.identity_public, 16),
                    addr.0,
                    addr.1
                ));
                addrs[index] = addr;
                punched = true;
            }
            Err(NatError(msg)) => {
                return Err(NatHopUnavailable { identity: descriptor.identity_public.clone(), message: msg })
            }
        }
    }
    if punched {
        // Give the punch datagrams a moment to cross both NATs before the
        // previous hop's CREATE follows them.
        std::thread::sleep(Duration::from_millis(150));
    }
    Ok(addrs)
}

/// A selected route plus the resolved (possibly hole-punched) address for
/// each hop, in the same order.
pub type PreparedRoute = (Vec<RelayDescriptor>, Vec<(String, u16)>);

/// Call `select(exclude) -> route` and prepare its NAT hops, excluding any
/// NAT relay whose punch failed and re-selecting (up to `attempts`).
/// Returns `(route, addrs)`.
pub fn select_and_prepare<F>(
    select: F,
    trusted_authorities: Option<&HashSet<Vec<u8>>>,
    authority_addr: Option<&str>,
    label: &str,
    attempts: usize,
) -> Result<PreparedRoute, DirClientError>
where
    F: Fn(&HashSet<Vec<u8>>) -> Result<Vec<RelayDescriptor>, DirectoryError>,
{
    let mut exclude: HashSet<Vec<u8>> = HashSet::new();
    let mut last_err: Option<NatHopUnavailable> = None;
    for _ in 0..attempts.max(1) {
        let route = select(&exclude)?;
        match prepare_nat_hops(&route, trusted_authorities, authority_addr, label) {
            Ok(addrs) => return Ok((route, addrs)),
            Err(e) => {
                say(&format!("{label}: skipping NAT relay {}... ({e})", hex_prefix(&e.identity, 16)));
                exclude.insert(e.identity.clone());
                last_err = Some(e);
            }
        }
    }
    Err(last_err
        .map(|e| DirClientError(e.message))
        .unwrap_or_else(|| DirClientError("no route selection attempts were made".to_string())))
}

/// Return the persisted guard's identity key, or `None`.
///
/// Never panics: a missing file is the normal first-run case (silent),
/// and a present-but-unreadable one (corrupt JSON, wrong shape) is
/// reported as one clean line and then treated the same as "no persisted
/// guard yet" -- a bad state file should degrade to picking a fresh
/// guard, not crash the client.
///
/// A minimal hand-rolled JSON reader is used here rather than vendoring
/// `serde_json`: the persisted shape is exactly one object with a
/// well-known `"guard_identity"` string field (see
/// [`save_persisted_guard`]), so a small purpose-built parser (the same
/// call already made for [`allium::config`]'s TOML subset) is enough.
pub fn load_persisted_guard(state_file: &str) -> Option<Vec<u8>> {
    let text = match std::fs::read_to_string(state_file) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            say(&format!(
                "client: state file {state_file} is unreadable ({e}) -- ignoring it and picking a fresh guard"
            ));
            return None;
        }
    };
    match extract_json_string_field(&text, "guard_identity").and_then(|hex| crate::helpers::hex_decode(&hex).ok()) {
        Some(bytes) => Some(bytes),
        None => {
            say(&format!(
                "client: state file {state_file} is unreadable (malformed guard_identity) -- \
                 ignoring it and picking a fresh guard"
            ));
            None
        }
    }
}

/// Extract `"key": "value"` from a small flat JSON object. Not a general
/// JSON parser -- see [`load_persisted_guard`]'s doc for why a minimal,
/// purpose-scoped reader is enough here.
fn extract_json_string_field(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let key_pos = text.find(&needle)?;
    let after_key = &text[key_pos + needle.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    let open_quote = after_colon.strip_prefix('"')?;
    let end = open_quote.find('"')?;
    Some(open_quote[..end].to_string())
}

/// Persist the chosen guard to `state_file` (atomic replace, so a crash
/// mid-write never leaves a half-written file for the next run to trip
/// over). Best-effort: a write failure (unwritable directory, full disk)
/// is reported as one clean line rather than taking the whole circuit
/// build down over a convenience feature.
pub fn save_persisted_guard(state_file: &str, guard: &RelayDescriptor) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let payload = format!(
        "{{\"guard_identity\": \"{}\", \"guard_address\": \"{}:{}\", \"chosen_at\": {now}}}",
        crate::helpers::hex_encode(&guard.identity_public),
        guard.host,
        guard.port,
    );
    if let Err(e) = write_atomically(state_file, &payload) {
        say(&format!(
            "client: could not save guard state to {state_file} ({e}) -- continuing anyway; a \
             fresh guard will be picked next run"
        ));
    }
}

/// `write_atomically` used to `create_dir_all` the guard-state directory
/// at the ambient umask-derived default mode (typically
/// group/other-readable), unlike the state file itself
/// (correctly 0600 below) -- letting other local users see, via a bare
/// `ls`, that a `state` file exists here (filename/existence only, never
/// its contents). Mirrors `Client/src/hiddenservice.rs`'s own
/// `ensure_private_dir` (0700, `create_dir_all`) -- duplicated here rather
/// than exposed from the library, matching this codebase's established
/// convention for small, module-local helpers (e.g. `expanduser` in
/// `apply_config.rs`/`alliumrc.rs`, `ensure_private_dir` in `hsserver.rs`).
fn ensure_private_dir(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

fn write_atomically(path: &str, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            ensure_private_dir(parent)?;
        }
    }
    let tmp_path = format!("{path}.tmp{}", std::process::id());
    // See the Python original's comment: the mode is baked into file
    // creation itself (0600, O_EXCL) rather than written at the ambient
    // default mode and narrowed afterward, which would leave a window
    // where another local user could read the file.
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        if let Err(e) = f.write_all(contents.as_bytes()) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }
    }
    std::fs::rename(&tmp_path, path)
}

/// Fetch the current live relay set from `args.authority` and pick a
/// 3-hop guard/middle/exit route from it. See [`fetch_relay_directory`]
/// for the verification this relies on.
///
/// When `args.state_file` is set, reuses the previously-persisted guard
/// if it's still live in the fetched directory, and persists whichever
/// guard ends up chosen (the reused one, or a freshly-picked replacement
/// if it's gone) for next time.
///
/// Deliberate improvement over the Python original: `_select_and_prepare`
/// there can raise either a caught `DirectoryError` (turned into a clean
/// `SystemExit`) or, once every retry attempt is exhausted on a NAT relay
/// that never answers, an uncaught `NatHopUnavailable` that propagates as
/// a raw traceback -- an existing gap in the reference implementation.
/// Here both failure shapes are collapsed into one clean operator-facing
/// [`CliExit`] instead.
pub fn fetch_route_from_authority(args: &Args) -> Result<Vec<RelayDescriptor>, CliExit> {
    let directory = fetch_relay_directory(args, "client")?;
    let state_file = args.state_file.clone().filter(|s| !s.is_empty());
    let preferred_guard = state_file.as_deref().and_then(load_persisted_guard);
    let require_pq = args.require_pq.unwrap_or(false);
    let trusted = trusted_authority_keys(args);
    let authority_addr = primary_authority(args);

    let (route, addrs) = select_and_prepare(
        |exclude| {
            select_route_best_effort(
                &directory,
                preferred_guard.as_deref(),
                false,
                &HashSet::new(),
                Some(PREEMPTIVE_EXIT_PORT),
                exclude,
                require_pq,
            )
        },
        trusted.as_ref(),
        authority_addr.as_deref(),
        "client",
        3,
    )
    .map_err(|e| {
        let text = e.to_string();
        let hint = if text.contains("none has been observed for the required") {
            if guard_history_path(args).is_some() {
                " -- this run's observations were saved, so try again after that time has passed, or on a network you run yourself lower --min-guard-age"
            } else {
                " -- give a --state-file (a service: --hidden-service-dir) so the observation history is kept between runs, or on a network you run yourself lower --min-guard-age"
            }
        } else {
            ""
        };
        CliExit::error(format!("client: could not pick a route from the directory: {text}{hint}"))
    })?;

    if let Some(state_file) = &state_file {
        let reused = preferred_guard
            .as_deref()
            .map(|pg| pg == route[0].identity_public.as_slice())
            .unwrap_or(false);
        if preferred_guard.is_some() && !reused {
            // Distinguish this case -- the persisted guard exists but is
            // no longer live -- from an ordinary first run with nothing
            // persisted yet.
            say(&format!(
                "client: NOTE: persisted guard {}... is no longer live -- picked a new one. \
                 If this happens unexpectedly, your former guard may be down or blocked.",
                hex_prefix(preferred_guard.as_deref().unwrap(), 16)
            ));
        }
        say(&format!(
            "client: {} persisted guard {}:{} (identity {}...)",
            if reused { "reusing" } else { "picked a new" },
            route[0].host,
            route[0].port,
            hex_prefix(&route[0].identity_public, 16),
        ));
        save_persisted_guard(state_file, &route[0]);
    }

    // A hop behind NAT is returned with its host/port replaced by the
    // mapping its introducer just punched open (see prepare_nat_hops);
    // every other descriptor is returned untouched. (The replaced copy is
    // only ever used for its endpoint and identity -- its signature no
    // longer covers the new host/port, and nothing re-verifies it.)
    Ok(route
        .into_iter()
        .zip(addrs)
        .map(|(mut d, addr)| {
            if d.behind_nat() {
                d.host = addr.0;
                d.port = addr.1;
            }
            d
        })
        .collect())
}

/// Return `(guard_addr, middle_addr, entry_trust)` for this client/service's
/// own entry hops, fetching a route from the directory if manual
/// guard/middle were not given -- shared by the ordinary exit circuit path
/// and every hidden-service circuit, both of which reach their very
/// different final hops through the same guard/middle. Port of
/// `allium_cli.py`'s `_resolve_entry_hops`.
pub type EntryHops = (Addr, Addr, HashMap<String, Vec<[u8; 32]>>);

pub fn resolve_entry_hops(args: &mut Args) -> Result<EntryHops, CliExit> {
    if !(args.guard.is_some() && args.middle.is_some()) {
        say(&format!(
            "client: no manual guard/middle given -- fetching a route from the directory authority \
             at {} for the entry hops ...",
            args.authority.clone().unwrap_or_default()
        ));
        let route = fetch_route_from_authority(args)?;
        let (guard_d, middle_d) = (&route[0], &route[1]);
        args.guard = Some(format!("{}:{}", guard_d.host, guard_d.port));
        args.middle = Some(format!("{}:{}", middle_d.host, middle_d.port));
        args.kem_keys = [("guard", guard_d), ("middle", middle_d)]
            .into_iter()
            .filter_map(|(hop, d)| d.pq_kem_public().map(|k| (hop.to_string(), k.to_vec())))
            .collect();
        if args.trust_guard.as_deref().unwrap_or("").is_empty() {
            args.trust_guard = Some(crate::helpers::hex_encode(&guard_d.identity_public));
        }
        if args.trust_middle.as_deref().unwrap_or("").is_empty() {
            args.trust_middle = Some(crate::helpers::hex_encode(&middle_d.identity_public));
        }
    }
    let mut entry_trust: HashMap<String, Vec<[u8; 32]>> = HashMap::new();
    for (hop, pin) in [("guard", &args.trust_guard), ("middle", &args.trust_middle)] {
        if let Some(pin) = pin {
            if !pin.is_empty() {
                // `pin` may be a comma-separated list (see
                // `helpers::split_trust_keys`); splitting it here, rather
                // than handing the whole string to `hex_decode`, matters --
                // `hex_decode` fails outright on the separating comma, so a
                // single-`hex_decode` version of this loop would silently
                // leave the hop *unpinned* instead of pinned to several
                // keys, exactly when an operator is mid key-rotation.
                let keys: Vec<[u8; 32]> = split_trust_keys(pin)
                    .iter()
                    .filter_map(|hex| crate::helpers::hex_decode(hex).ok())
                    .filter_map(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
                    .collect();
                if !keys.is_empty() {
                    entry_trust.insert(hop.to_string(), keys);
                }
            }
        }
    }
    let guard_addr = parse_addr(args.guard.as_deref().unwrap_or_default())?;
    let middle_addr = parse_addr(args.middle.as_deref().unwrap_or_default())?;
    Ok((guard_addr, middle_addr, entry_trust))
}

/// Like [`dir_round_trip`], but for hidden-service directory traffic:
/// routes the request over a full guard/middle/authority circuit instead
/// of contacting the authority directly.
///
/// [`dir_round_trip`] builds a
/// single-hop circuit straight to the authority, so a hidden service
/// publishing its descriptor -- or a client resolving a `.allium` address
/// -- would do so from its own source address, in plain view of the
/// authority. Ordinary relay-descriptor publication and the plain
/// relay-directory fetch ([`fetch_relay_directory`]) are left on the
/// one-hop path deliberately (relays are public by definition, and the
/// relay-directory fetch is also how a client bootstraps the very
/// guard/middle this function needs); anything hidden-service-related is
/// routed through this function instead. See the Python original's
/// docstring for the full reasoning.
pub fn dir_round_trip_over_circuit(
    args: &mut Args,
    authority_addr_text: &str,
    authority_trusted: Option<Vec<[u8; 32]>>,
    request_bytes: &[u8],
    label: &str,
) -> Result<Vec<u8>, DirClientError> {
    let (guard_addr, middle_addr, entry_trust) = resolve_entry_hops(args).map_err(|e| DirClientError(e.to_string()))?;
    let authority_addr: Addr = parse_addr(authority_addr_text).map_err(|e| DirClientError(e.to_string()))?;
    let mut trusted = entry_trust;
    if let Some(keys) = authority_trusted {
        trusted.insert("authority".to_string(), keys);
    }

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let hops = vec![("guard".to_string(), guard_addr), ("middle".to_string(), middle_addr), ("authority".to_string(), authority_addr.clone())];
    let builder = build_generic_circuit(&sock, &hops, Duration::from_secs_f64(DIR_ROUND_TRIP_TIMEOUT), 1, Some(trusted), label, None)?;
    let mut builder = builder;
    for wire_bytes in fragment_message(request_bytes, DEFAULT_MTU) {
        builder.send(&wire_bytes, authority_addr.clone(), EncryptOptions::default())?;
    }
    receive_over_circuit(&builder)
}

/// Build an n-hop circuit through arbitrary `(name, addr)` pairs.
///
/// The same shape a guard/middle/exit circuit hand-builds, generalized:
/// the first entry is the direct hop ([`CircuitBuilder::add_hop`]), every
/// following one is an [`CircuitBuilder::extend`] through the circuit so
/// far. Used for a hidden-service client's circuits to an introduction or
/// rendezvous point, and a service's own circuits to its introduction
/// points and to a rendezvous point.
///
/// `trusted`: `{hop_name: [identity, ...]}`. A hop name absent from this
/// mapping is unpinned; this function then explicitly opts that hop into
/// `CircuitBuilder`'s `trust_first_use` (with a NOTE printed) rather than
/// letting it fail, since a caller may legitimately mix pinned hops (an
/// intro/rendezvous point, always pinned to the identity a verified
/// descriptor named) with unpinned ones (a manually-given guard/middle
/// with no `--trust-*` flag).
pub fn build_generic_circuit<'a>(
    sock: &'a UdpSocket,
    hops: &[(String, Addr)],
    timeout: Duration,
    retries: u32,
    trusted: Option<HashMap<String, Vec<[u8; 32]>>>,
    label: &str,
    kem_keys: Option<HashMap<String, Vec<u8>>>,
) -> Result<CircuitBuilder<'a>, DirClientError> {
    if hops.is_empty() {
        return Err(DirClientError("hops must be non-empty".to_string()));
    }
    let trusted = trusted.unwrap_or_default();
    let unpinned: Vec<String> =
        hops.iter().map(|(n, _)| n.clone()).filter(|n| !trusted.contains_key(n)).collect();
    if !unpinned.is_empty() {
        say(&format!(
            "{label}: NOTE: no pin for {} -- any relay presenting a valid signature there is \
             accepted.  Fine for a private LAN test; pin identities for anything real.",
            unpinned.join(", ")
        ));
    }
    let kem_keys: HashMap<String, Vec<u8>> =
        kem_keys.unwrap_or_default().into_iter().filter(|(_, v)| !v.is_empty()).collect();
    let classical: Vec<String> =
        hops.iter().map(|(n, _)| n.clone()).filter(|n| !kem_keys.contains_key(n)).collect();
    if !kem_keys.is_empty() && !classical.is_empty() {
        say(&format!(
            "{label}: NOTE: no post-quantum key known for {} -- classical X25519 handshake for \
             that hop",
            classical.join(", ")
        ));
    }
    let mut builder = CircuitBuilder::new(
        sock,
        None,
        timeout,
        Some(trusted),
        !unpinned.is_empty(),
        false,
        retries,
        DEFAULT_SEND_JITTER,
        Some(kem_keys),
    )?;
    let (first_name, first_addr) = &hops[0];
    say(&format!("{label}: handshaking with {first_name} at {first_addr:?} ..."));
    let keys0 = builder.add_hop(first_name, first_addr.clone(), None, None, None)?;
    say(&format!("{label}:   ok -- {first_name} identity {}", identity_prefix(&keys0)));
    for (name, addr) in &hops[1..] {
        say(&format!("{label}: extending to {name} at {addr:?} ..."));
        let keys = builder.extend(name, addr.clone(), None, None, None)?;
        say(&format!("{label}:   ok -- {name} identity {}", identity_prefix(&keys)));
    }
    Ok(builder)
}

/// [`build_generic_circuit`], but taking (and keeping) ownership of `sock`
/// instead of borrowing it -- wraps the result in [`OwnedCircuit`] so it is
/// `'static` and can outlive the caller's stack frame. Every caller that
/// needs a *long-lived* circuit (one that must keep working from inside an
/// `Onion` closure or a spawned thread, as opposed to `dir_round_trip`'s
/// use-once-and-drop directory circuit) goes through this instead of the
/// borrowing version directly.
pub fn build_generic_circuit_owned(
    sock: UdpSocket,
    hops: Vec<(String, Addr)>,
    timeout: Duration,
    retries: u32,
    trusted: Option<HashMap<String, Vec<[u8; 32]>>>,
    label: String,
    kem_keys: Option<HashMap<String, Vec<u8>>>,
) -> Result<crate::owned_circuit::OwnedCircuit, DirClientError> {
    crate::owned_circuit::OwnedCircuit::new(sock, move |static_sock| {
        build_generic_circuit(static_sock, &hops, timeout, retries, trusted, &label, kem_keys)
    })
}

/// What stopped [`build_circuit`] from producing a usable circuit, in the
/// three shapes `run_client` needs to tell apart -- see its own match on
/// this (the Python original distinguishes these by `except HandshakeTimeout`
/// vs. a bare `except Exception` vs. an uncaught `SystemExit`, which Rust
/// has no exception hierarchy to mirror, hence this explicit enum).
pub enum CircuitBuildOutcome {
    /// A `SystemExit`-equivalent: something the caller should print and
    /// exit the whole process over immediately (e.g. `--require-pq` with
    /// no PQ key known for a hop, or a route-fetch failure).
    Exit(CliExit),
    /// No reply from the guard specifically (Python's `HandshakeTimeout`,
    /// which only `add_hop`'s direct handshake -- never `extend` -- can
    /// raise): `run_client` prints its own specific "is the guard
    /// running?" message for this one case rather than a generic one.
    NoReplyFromGuard,
    /// Anything else: `run_client` prints `circuit build failed: {kind}:
    /// {message}` and returns exit code 1, matching
    /// `type(exc).__name__: {exc}` in the Python original as closely as
    /// Rust's lack of a `type(...).__name__` equivalent allows.
    Failed { kind: &'static str, message: String },
}

impl From<CliExit> for CircuitBuildOutcome {
    fn from(e: CliExit) -> Self {
        CircuitBuildOutcome::Exit(e)
    }
}

impl From<CircuitError> for CircuitBuildOutcome {
    fn from(e: CircuitError) -> Self {
        if matches!(&e, CircuitError::Handshake(allium::handshake::HandshakeError::Timeout(_))) {
            CircuitBuildOutcome::NoReplyFromGuard
        } else {
            CircuitBuildOutcome::Failed { kind: "CircuitError", message: e.to_string() }
        }
    }
}

/// Build the `{hop: [identity, ...]}` map `CircuitBuilder`'s
/// `trusted_identities` expects from `args.trust_guard`/`trust_middle`/
/// `trust_exit` (each already a validated, comma-joined list of 32-byte-hex
/// strings by the time this runs -- see `helpers::validate_trust_keys` and
/// `helpers::split_trust_keys`), plus the list of hops left unpinned.
///
/// Split out from [`build_circuit`] so it can be tested directly against
/// `Args` alone, without a socket or a real `CircuitBuilder` -- the Python
/// original's `test_trust_pinning.py` does the same by swapping in a fake
/// `CircuitBuilder` class to capture what got passed; Rust has no
/// monkeypatch-equivalent, so this pure extraction is the substitute seam.
///
/// This is also where a real, once-shipped bug lived on the Python side:
/// `trusted[hop] = pin` (a bare hex string) instead of `trusted[hop] =
/// [pin]` (a one-element list) -- `CircuitBuilder`/`HandshakeClient`
/// document and require a *list* of acceptable identities per hop, so a
/// bare string there was silently wrong (iterated character-by-character
/// downstream). That specific bug class cannot occur in this port at all:
/// `trusted`'s value type is `Vec<[u8; 32]>`, never a bare `[u8; 32]` or a
/// `String`, so the wrong shape simply does not type-check.
pub(crate) fn build_hop_trusted_identities(
    args: &Args,
) -> (HashMap<String, Vec<[u8; 32]>>, Vec<&'static str>) {
    let mut trusted: HashMap<String, Vec<[u8; 32]>> = HashMap::new();
    for (hop, pin) in [("guard", &args.trust_guard), ("middle", &args.trust_middle), ("exit", &args.trust_exit)] {
        if let Some(pin) = pin {
            if !pin.is_empty() {
                // See `resolve_entry_hops` above: `pin` can hold several
                // comma-separated keys, and feeding the whole string to
                // `hex_decode` in one call (instead of splitting first)
                // fails on the comma and leaves this hop looking unpinned.
                let keys: Vec<[u8; 32]> = split_trust_keys(pin)
                    .iter()
                    .filter_map(|hex| crate::helpers::hex_decode(hex).ok())
                    .filter_map(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
                    .collect();
                if !keys.is_empty() {
                    trusted.insert(hop.to_string(), keys);
                }
            }
        }
    }
    let unpinned: Vec<&'static str> =
        ["guard", "middle", "exit"].into_iter().filter(|h| !trusted.contains_key(*h)).collect();
    (trusted, unpinned)
}

/// Handshake with the guard and EXTEND to middle then exit (port of
/// `allium_cli.py`'s `build_circuit`).
///
/// If `args.guard`/`middle`/`exit_addr` are not all set, they are filled in
/// first by fetching a route from `args.authority` -- see
/// [`fetch_route_from_authority`]. A fetched hop's identity comes from its
/// own self-signed descriptor, so it is pinned automatically (an explicit
/// `--trust-*` still overrides) -- manual mode still requires pinning by
/// hand, exactly as before.
pub fn build_circuit(args: &mut Args, sock: UdpSocket) -> Result<crate::owned_circuit::OwnedCircuit, CircuitBuildOutcome> {
    if !(args.guard.is_some() && args.middle.is_some() && args.exit_addr.is_some()) {
        say(&format!(
            "circuit: no manual guard/middle/exit given -- fetching a route from the directory \
             authority at {} ...",
            args.authority.clone().unwrap_or_default()
        ));
        let route = fetch_route_from_authority(args)?;
        let (guard_d, middle_d, exit_d) = (&route[0], &route[1], &route[2]);
        args.guard = Some(format!("{}:{}", guard_d.host, guard_d.port));
        args.middle = Some(format!("{}:{}", middle_d.host, middle_d.port));
        args.exit_addr = Some(format!("{}:{}", exit_d.host, exit_d.port));
        for (hop, d) in [("guard", guard_d), ("middle", middle_d), ("exit", exit_d)] {
            let slot = match hop {
                "guard" => &mut args.trust_guard,
                "middle" => &mut args.trust_middle,
                _ => &mut args.trust_exit,
            };
            if slot.as_deref().unwrap_or("").is_empty() {
                *slot = Some(crate::helpers::hex_encode(&d.identity_public));
            }
        }
        args.kem_keys = [("guard", guard_d), ("middle", middle_d), ("exit", exit_d)]
            .into_iter()
            .filter_map(|(hop, d)| d.pq_kem_public().map(|k| (hop.to_string(), k.to_vec())))
            .collect();
        say(&format!(
            "circuit: directory picked guard {}, middle {}, exit {} (each identity verified \
             against its own self-signed descriptor)\n",
            args.guard.as_deref().unwrap_or(""),
            args.middle.as_deref().unwrap_or(""),
            args.exit_addr.as_deref().unwrap_or(""),
        ));
    }

    let (trusted, unpinned) = build_hop_trusted_identities(args);
    for hop in ["guard", "middle", "exit"] {
        if let Some(keys) = trusted.get(hop) {
            let pin = crate::helpers::hex_encode(&keys[0]);
            say(&format!("  pinning {hop} to {}...", &pin[..pin.len().min(16)]));
        }
    }
    if !unpinned.is_empty() {
        say(&format!(
            "NOTE: no --trust-* pin for {} -- any relay presenting a valid signature at {} is \
             accepted.  Fine for a private LAN test; pin identities for anything real.\n",
            unpinned.join(", "),
            if unpinned.len() == 1 { "that address" } else { "those addresses" },
        ));
    }

    let classical: Vec<&str> = ["guard", "middle", "exit"].into_iter().filter(|h| !args.kem_keys.contains_key(*h)).collect();
    if !classical.is_empty() && args.require_pq.unwrap_or(false) {
        return Err(CliExit::error(format!(
            "circuit: --require-pq is set but no post-quantum (ML-KEM) key is known for {} -- \
             use --authority so keys come from signed descriptors, or drop --require-pq",
            classical.join(", ")
        ))
        .into());
    }
    if !classical.is_empty() {
        say(
            "NOTE: classical-only (X25519) handshake for {classical}: no ML-KEM key known for that \
             hop. Traffic recorded today could be decrypted by a future quantum computer. Fetching \
             the route with --authority gives every up-to-date relay the hybrid handshake.\n"
                .replace("{classical}", &classical.join(", "))
                .as_str(),
        );
    } else {
        say("circuit: post-quantum hybrid handshake (X25519 + ML-KEM-768) on every hop");
    }

    let guard_addr = parse_addr(args.guard.as_deref().unwrap_or_default()).map_err(CircuitBuildOutcome::from)?;
    let middle_addr = parse_addr(args.middle.as_deref().unwrap_or_default()).map_err(CircuitBuildOutcome::from)?;
    let exit_addr = parse_addr(args.exit_addr.as_deref().unwrap_or_default()).map_err(CircuitBuildOutcome::from)?;
    let timeout = Duration::from_secs_f64(args.timeout.unwrap_or(5.0));
    let retries = args.retries.unwrap_or(0).max(0) as u32;
    let kem_keys = args.kem_keys.clone();
    let trust_first_use = !unpinned.is_empty();

    let owned = crate::owned_circuit::OwnedCircuit::new(sock, |static_sock| {
        let mut builder = CircuitBuilder::new(
            static_sock,
            None,
            timeout,
            Some(trusted),
            trust_first_use,
            false,
            retries,
            DEFAULT_SEND_JITTER,
            Some(kem_keys),
        )?;
        say(&format!("circuit: handshaking with guard at {guard_addr:?} ..."));
        let keys0 = builder.add_hop("guard", guard_addr, None, None, None)?;
        say(&format!("circuit:   ok -- guard identity {}", identity_prefix(&keys0)));
        for (name, addr) in [("middle", middle_addr), ("exit", exit_addr)] {
            say(&format!("circuit: extending to {name} at {addr:?} ..."));
            let keys = builder.extend(name, addr, None, None, None)?;
            say(&format!("circuit:   ok -- {name} identity {}", identity_prefix(&keys)));
        }
        say(&format!(
            "circuit: built {} hops; the client only ever contacted the guard at {:?}.\n",
            builder.hop_count(),
            builder.guard_addr,
        ));
        Ok::<_, CircuitError>(builder)
    })
    .map_err(CircuitBuildOutcome::from)?;

    Ok(owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use allium::directory::CreateOptions;
    use ed25519_dalek::SigningKey;
    use hkdf::Hkdf;
    use sha2::Sha256;
    use std::sync::atomic::{AtomicU64, Ordering};
    use x25519_dalek::{PublicKey, StaticSecret};

    fn scratch_path(name: &str) -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        // A dedicated, test-owned subdirectory -- never the bare system
        // temp root directly, which `write_atomically` now hardens to
        // 0700 and this process typically does not own (e.g. a
        // root-owned `/tmp`), matching the same
        // dedicated-subdirectory convention `hiddenservice.rs`'s own
        // temp-dir tests already use.
        let dir = std::env::temp_dir().join(format!("allium-cli-dirclient-test-{}-{n}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        dir.join(name).to_string_lossy().to_string()
    }

    fn gen_identity() -> [u8; 32] {
        let seed: [u8; 32] = allium::osrand::bytes(32).try_into().unwrap();
        SigningKey::from_bytes(&seed).to_bytes()
    }

    fn make_descriptor(identity_private: &[u8; 32], host: &str, port: u16, roles: &[&str]) -> RelayDescriptor {
        RelayDescriptor::create(
            identity_private,
            vec![7u8; 32],
            host,
            port,
            roles.iter().map(|s| s.to_string()).collect(),
            3600.0,
            None,
            CreateOptions::default(),
        )
        .unwrap()
    }

    #[test]
    fn guard_persistence_round_trips() {
        let path = scratch_path("guard.json");
        let identity_priv = gen_identity();
        let descriptor = make_descriptor(&identity_priv, "1.2.3.4", 9001, &["guard"]);
        save_persisted_guard(&path, &descriptor);
        let loaded = load_persisted_guard(&path).unwrap();
        assert_eq!(loaded, descriptor.identity_public);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn save_persisted_guard_hardens_its_directory_and_file() {
        // The guard-state directory must not be left at the ambient
        // umask default -- other local users could
        // otherwise see, via a bare `ls`, that a `state` file exists here.
        use std::os::unix::fs::PermissionsExt;
        let path = scratch_path("guard.json");
        let identity_priv = gen_identity();
        let descriptor = make_descriptor(&identity_priv, "5.6.7.8", 9002, &["guard"]);
        save_persisted_guard(&path, &descriptor);

        let dir = std::path::Path::new(&path).parent().unwrap();
        let dir_mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "guard-state directory must not be group/other-accessible");
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "guard-state file must not be group/other-readable");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_guard_state_file_is_silently_none() {
        assert_eq!(load_persisted_guard(&scratch_path("nonexistent.json")), None);
    }

    #[test]
    fn corrupt_guard_state_file_degrades_to_none() {
        let path = scratch_path("corrupt.json");
        std::fs::write(&path, "not json at all").unwrap();
        assert_eq!(load_persisted_guard(&path), None);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn prepare_nat_hops_passes_through_a_route_with_no_nat_hops() {
        let g = make_descriptor(&gen_identity(), "1.1.1.1", 1, &["guard"]);
        let m = make_descriptor(&gen_identity(), "2.2.2.2", 2, &["middle"]);
        let e = make_descriptor(&gen_identity(), "3.3.3.3", 3, &["exit"]);
        let route = vec![g.clone(), m.clone(), e.clone()];
        let addrs = prepare_nat_hops(&route, None, None, "test").unwrap();
        assert_eq!(addrs, vec![g.endpoint(), m.endpoint(), e.endpoint()]);
    }

    /// Builds the same sealed `PUNCH_REPLY` wire format as
    /// `allium::nat::request_punch` expects -- duplicated here (rather
    /// than exported from `allium::nat`, whose sealing helpers are
    /// private) because it is test-only tooling for standing in as a fake
    /// directory authority, not part of the public NAT API.
    fn punch_session_keys(shared: &[u8]) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(Some(b"allium-nat-punch-session-v1"), shared);
        let mut request_key = [0u8; 32];
        hk.expand(b"request", &mut request_key).unwrap();
        let mut reply_key = [0u8; 32];
        hk.expand(b"reply", &mut reply_key).unwrap();
        (request_key, reply_key)
    }

    fn seal_punch_reply(introducer_x25519_private: &[u8; 32], client_ephemeral_public: &[u8; 32], nonce: &[u8], status: u8, addr: Option<(&str, u16)>) -> Vec<u8> {
        let secret = StaticSecret::from(*introducer_x25519_private);
        let shared = secret.diffie_hellman(&PublicKey::from(*client_ephemeral_public));
        let (_request_key, reply_key) = punch_session_keys(shared.as_bytes());
        let (host, port) = addr.unwrap_or(("", 0));
        let host_bytes = host.as_bytes();
        let mut plaintext = vec![status];
        plaintext.push(host_bytes.len() as u8);
        plaintext.extend_from_slice(host_bytes);
        plaintext.extend_from_slice(&port.to_be_bytes());
        let mut aead = allium::crypto::new_aead("chacha20-poly1305", &reply_key, None).unwrap();
        let sealed = aead.seal(&plaintext, nonce).unwrap();
        let mut out = allium::nat::NAT_MAGIC.to_vec();
        out.push(allium::nat::PUNCH_REPLY);
        out.extend_from_slice(nonce);
        out.extend_from_slice(&sealed);
        out
    }

    /// Regression test: with no `--trust-authority` pin and no
    /// configured `--authority` address, a NAT hop must be refused
    /// outright, never brokered against whatever introducer the relay's
    /// own (self-signed) descriptor happens to name.
    #[test]
    fn prepare_nat_hops_refuses_a_nat_hop_when_unpinned() {
        let attacker_identity = gen_identity();
        let attacker_pub = SigningKey::from_bytes(&attacker_identity).verifying_key().to_bytes();
        let mut reach = vec![allium::nat::MODE_NAT];
        reach.extend_from_slice(&attacker_pub);
        reach.extend_from_slice(&[0u8; 32]); // introducer_x25519_public, unused -- refused before ever being read
        let host = b"203.0.113.66";
        reach.push(host.len() as u8);
        reach.extend_from_slice(host);
        reach.extend_from_slice(&9999u16.to_be_bytes());

        let g = make_descriptor(&gen_identity(), "1.1.1.1", 1, &["guard"]);
        let m = RelayDescriptor::create(
            &gen_identity(),
            vec![7u8; 32],
            "2.2.2.2",
            2,
            vec!["middle".to_string()],
            3600.0,
            None,
            CreateOptions { extra_extensions: vec![(allium::directory::EXT_REACHABILITY, reach)], ..Default::default() },
        )
        .unwrap();
        let e = make_descriptor(&gen_identity(), "3.3.3.3", 3, &["exit"]);
        let route = vec![g, m, e];

        let err = prepare_nat_hops(&route, None, None, "test").unwrap_err();
        assert!(err.message.contains("refusing to broker"), "unexpected message: {}", err.message);
    }

    /// Regression test: even when a NAT relay's descriptor names a
    /// (trusted-looking) introducer identity at an attacker-chosen
    /// address, the client must only ever contact its own pinned
    /// `--authority` address -- never `reach.introducer_addr()`.
    #[test]
    fn prepare_nat_hops_contacts_the_pinned_authority_not_the_relays_claimed_introducer() {
        let authority_key = SigningKey::from_bytes(&gen_identity());
        let authority_pub = authority_key.verifying_key().to_bytes().to_vec();
        let authority_x25519_private: [u8; 32] = allium::osrand::bytes(32).try_into().unwrap();
        let authority_x25519_public = PublicKey::from(&StaticSecret::from(authority_x25519_private)).to_bytes();
        let authority_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let authority_port = authority_sock.local_addr().unwrap().port();

        // The address the malicious/misconfigured relay's own descriptor
        // claims is the introducer. It must never receive anything.
        let decoy_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let decoy_port = decoy_sock.local_addr().unwrap().port();
        decoy_sock.set_read_timeout(Some(Duration::from_millis(300))).unwrap();

        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 1024];
            let (_n, src) = authority_sock.recv_from(&mut buf).unwrap();
            let nonce = buf[5..5 + 16].to_vec();
            let client_ephemeral_public: [u8; 32] = buf[5 + 16..5 + 16 + 32].try_into().unwrap();
            let reply = seal_punch_reply(&authority_x25519_private, &client_ephemeral_public, &nonce, allium::nat::STATUS_OK, Some(("198.51.100.9", 4242)));
            authority_sock.send_to(&reply, src).unwrap();
        });

        let mut reach = vec![allium::nat::MODE_NAT];
        reach.extend_from_slice(&authority_pub);
        reach.extend_from_slice(&authority_x25519_public);
        let decoy_host = b"127.0.0.1";
        reach.push(decoy_host.len() as u8);
        reach.extend_from_slice(decoy_host);
        reach.extend_from_slice(&decoy_port.to_be_bytes());

        let g = make_descriptor(&gen_identity(), "1.1.1.1", 1, &["guard"]);
        let m = RelayDescriptor::create(
            &gen_identity(),
            vec![7u8; 32],
            "2.2.2.2",
            2,
            vec!["middle".to_string()],
            3600.0,
            None,
            CreateOptions { extra_extensions: vec![(allium::directory::EXT_REACHABILITY, reach)], ..Default::default() },
        )
        .unwrap();
        let e = make_descriptor(&gen_identity(), "3.3.3.3", 3, &["exit"]);
        let route = vec![g, m, e];

        let mut trusted = HashSet::new();
        trusted.insert(authority_pub);
        let authority_addr = format!("127.0.0.1:{authority_port}");

        let addrs = prepare_nat_hops(&route, Some(&trusted), Some(&authority_addr), "test").unwrap();
        assert_eq!(addrs[1], ("198.51.100.9".to_string(), 4242));

        // The decoy address the relay's own descriptor named was never
        // contacted.
        assert!(decoy_sock.recv_from(&mut [0u8; 16]).is_err());

        handle.join().unwrap();
    }

    #[test]
    fn select_and_prepare_returns_immediately_when_nothing_is_behind_nat() {
        let g = make_descriptor(&gen_identity(), "1.1.1.1", 1, &["guard"]);
        let m = make_descriptor(&gen_identity(), "2.2.2.2", 2, &["middle"]);
        let e = make_descriptor(&gen_identity(), "3.3.3.3", 3, &["exit"]);
        let route = vec![g.clone(), m.clone(), e.clone()];
        let (picked, addrs) = select_and_prepare(|_exclude| Ok(route.clone()), None, None, "test", 3).unwrap();
        assert_eq!(picked.len(), 3);
        assert_eq!(addrs[0], g.endpoint());
    }

    #[test]
    fn select_route_best_effort_falls_back_when_no_exit_matches_the_preferred_port() {
        let mut directory = Directory::new(DirectoryOptions::default()).unwrap();
        let g = make_descriptor(&gen_identity(), "1.1.1.1", 1, &["guard"]);
        let m = make_descriptor(&gen_identity(), "2.2.2.2", 2, &["middle"]);
        let e = make_descriptor(&gen_identity(), "3.3.3.3", 3, &["exit"]);
        for d in [g, m, e] {
            directory.publish(d).unwrap();
        }
        // No exit advertises an exit-port summary at all, so a preferred
        // port of 443 should fall back to "any exit" rather than fail.
        let route =
            select_route_best_effort(&directory, None, false, &HashSet::new(), Some(443), &HashSet::new(), false)
                .unwrap();
        assert_eq!(route.len(), 3);
    }

    // -- build_hop_trusted_identities (port of test_trust_pinning.py's
    // BuildCircuitTrustShapeTests) -----------------------------------------

    fn client_args_with_pins(guard: Option<&str>, middle: Option<&str>, exit: Option<&str>) -> Args {
        Args {
            role: "client".to_string(),
            trust_guard: guard.map(|s| s.to_string()),
            trust_middle: middle.map(|s| s.to_string()),
            trust_exit: exit.map(|s| s.to_string()),
            ..Args::default()
        }
    }

    #[test]
    fn a_single_manual_pin_is_wrapped_in_a_list() {
        // This is the exact shape the Python original's build_circuit once
        // got wrong (a bare hex string instead of a one-element list) --
        // see build_hop_trusted_identities's doc for why that specific
        // mistake cannot type-check in this port at all.
        let key = "11".repeat(32);
        let args = client_args_with_pins(Some(&key), None, None);
        let (trusted, unpinned) = build_hop_trusted_identities(&args);
        assert_eq!(trusted.get("guard"), Some(&vec![[0x11u8; 32]]));
        assert_eq!(unpinned, vec!["middle", "exit"]);
    }

    #[test]
    fn all_three_manual_pins_are_each_wrapped() {
        let g = "11".repeat(32);
        let m = "22".repeat(32);
        let e = "33".repeat(32);
        let args = client_args_with_pins(Some(&g), Some(&m), Some(&e));
        let (trusted, unpinned) = build_hop_trusted_identities(&args);
        assert_eq!(trusted.get("guard"), Some(&vec![[0x11u8; 32]]));
        assert_eq!(trusted.get("middle"), Some(&vec![[0x22u8; 32]]));
        assert_eq!(trusted.get("exit"), Some(&vec![[0x33u8; 32]]));
        assert!(unpinned.is_empty());
    }

    #[test]
    fn directory_derived_pin_is_also_wrapped_in_a_list() {
        // build_circuit fills args.trust_guard/middle/exit in from the
        // fetched descriptors' own identity_public *before* this function
        // ever runs (see build_circuit's own body) -- by the time it's
        // called, a directory-derived pin looks exactly like a manual one,
        // so this is the same code path and the same assertion.
        let identity = gen_identity();
        let hex = crate::helpers::hex_encode(&SigningKey::from_bytes(&identity).verifying_key().to_bytes());
        let args = client_args_with_pins(Some(&hex), None, None);
        let (trusted, _unpinned) = build_hop_trusted_identities(&args);
        assert_eq!(trusted.get("guard").map(|v| v.len()), Some(1));
    }

    /// Regression test for bug report H3: a comma-separated pin (the
    /// shape `helpers::validate_trust_keys` accepts, e.g. an old and new
    /// key during a rotation) used to be handed whole to `hex_decode`,
    /// which fails on the comma -- so the hop silently came back
    /// unpinned instead of pinned to every listed key.
    #[test]
    fn a_comma_separated_pin_list_pins_every_key() {
        let g1 = "11".repeat(32);
        let g2 = "22".repeat(32);
        let args = client_args_with_pins(Some(&format!("{g1},{g2}")), None, None);
        let (trusted, unpinned) = build_hop_trusted_identities(&args);
        assert_eq!(trusted.get("guard"), Some(&vec![[0x11u8; 32], [0x22u8; 32]]));
        assert_eq!(unpinned, vec!["middle", "exit"]);
    }

    #[test]
    fn no_pins_at_all_sets_trust_first_use() {
        let args = client_args_with_pins(None, None, None);
        let (trusted, unpinned) = build_hop_trusted_identities(&args);
        assert!(trusted.is_empty());
        assert_eq!(unpinned, vec!["guard", "middle", "exit"]);
        // build_circuit's own `let trust_first_use = !unpinned.is_empty();`
        // -- locked in directly here since that line itself is too small
        // to be worth its own extraction.
        assert!(!unpinned.is_empty());
    }

    // --- Directory cache policy (`should_use_cached`) ---
    //
    // `get_or_refresh_directory` itself always ends in a real
    // `fetch_relay_directory` call (a live UDP round trip), so it isn't
    // unit-testable without an authority to talk to. `should_use_cached`
    // is the pure decision it's built around, and is what actually
    // encodes the fix (a cache hit stays a cache hit; a forced refresh is
    // allowed through unless it repeats too soon) -- test that directly.

    fn empty_directory() -> Directory {
        Directory::new(DirectoryOptions::default()).unwrap()
    }

    fn cached(fetched_at: Instant, valid_for: Duration, last_forced_refresh_at: Option<Instant>) -> CachedDirectory {
        CachedDirectory { directory: Arc::new(empty_directory()), fetched_at, valid_for, last_forced_refresh_at }
    }

    #[test]
    fn fresh_entry_is_reused_for_an_ordinary_call() {
        let entry = cached(Instant::now(), Duration::from_secs(1800), None);
        assert!(should_use_cached(&entry, false));
    }

    #[test]
    fn expired_entry_is_never_reused_ordinary_or_forced() {
        // A 1ms `valid_for` plus a real (short) sleep past it -- rather
        // than subtracting from `Instant::now()` -- so this can't panic
        // on a short-lived CI container whose monotonic clock hasn't
        // been running long, and stands in for the cache's own 30-60
        // minute timer having elapsed.
        let entry = cached(Instant::now(), Duration::from_millis(1), None);
        std::thread::sleep(Duration::from_millis(20));
        assert!(!should_use_cached(&entry, false));
        assert!(!should_use_cached(&entry, true));
    }

    #[test]
    fn first_forced_refresh_after_an_ordinary_fetch_is_never_rate_limited() {
        // This is the bug this test would have caught: a forced refresh
        // is most needed immediately after a cold-start fetch that
        // turned out to be unusable (too few relays for a 3-hop route).
        // If the rate limit were measured against `fetched_at` (the
        // ordinary fetch that *just* happened) instead of against the
        // last *forced* refresh, this always-adjacent-in-time forced
        // call would be incorrectly rate-limited away right when it's
        // needed most.
        let entry = cached(Instant::now(), Duration::from_secs(1800), None);
        assert!(
            !should_use_cached(&entry, true),
            "a forced refresh with no prior forced refresh must never be treated as a cache hit"
        );
    }

    #[test]
    fn a_second_forced_refresh_moments_later_is_rate_limited() {
        let entry = cached(Instant::now(), Duration::from_secs(1800), Some(Instant::now()));
        assert!(
            should_use_cached(&entry, true),
            "a forced refresh immediately after the previous one must be rate-limited (returns the cached copy)"
        );
    }

    #[test]
    fn a_forced_refresh_well_after_the_last_one_is_allowed() {
        // `checked_sub`, not `Instant::now() - duration`: a short-lived CI
        // container's monotonic clock may not have been running long
        // enough to subtract a full `MIN_FORCED_REFRESH_INTERVAL` from,
        // and that would panic rather than fail the assertion. Skip
        // cleanly in that case instead of risking a spurious panic.
        let Some(long_ago) = Instant::now().checked_sub(MIN_FORCED_REFRESH_INTERVAL + Duration::from_secs(1)) else {
            return;
        };
        let entry = cached(Instant::now(), Duration::from_secs(1800), Some(long_ago));
        assert!(!should_use_cached(&entry, true));
    }

    #[test]
    fn jittered_cache_lifetime_stays_within_its_documented_bounds() {
        for _ in 0..20 {
            let d = jittered_cache_lifetime();
            assert!(d.as_secs_f64() >= DIRECTORY_CACHE_BASE_SECS);
            assert!(d.as_secs_f64() <= DIRECTORY_CACHE_BASE_SECS + DIRECTORY_CACHE_JITTER_SECS);
        }
    }

    // -- guard-observation history on disk --------------------------------------

    fn id_of(n: u8) -> Vec<u8> {
        vec![n; 32]
    }

    #[test]
    fn guard_history_round_trips_and_is_written_in_a_stable_order() {
        let history = HashMap::from([(id_of(2), 2000.5), (id_of(1), 1000.0), (id_of(3), 3000.25)]);
        let text = encode_guard_history(&history);
        assert!(text.starts_with('#'), "a human-readable header comes first");
        let ids: Vec<&str> = text.lines().skip(1).map(|l| l.split(' ').next().unwrap()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "sorted, so the file is the same every time");
        assert_eq!(decode_guard_history(&text, 1e12), history);
    }

    #[test]
    fn a_damaged_history_file_can_only_lose_entries_never_invent_them() {
        let good = crate::helpers::hex_encode(&id_of(7));
        let short = crate::helpers::hex_encode(&[7u8; 31]);
        let text = format!(
            "# header\n\n{good} 1000\n\
             nothex 1000\n\
             {short} 1000\n\
             {} abc\n\
             {} NaN\n\
             {} inf\n\
             {} -5\n\
             {} 1000 extra\n\
             {}\n\
             garbage line here\n",
            crate::helpers::hex_encode(&id_of(8)),
            crate::helpers::hex_encode(&id_of(9)),
            crate::helpers::hex_encode(&id_of(10)),
            crate::helpers::hex_encode(&id_of(11)),
            crate::helpers::hex_encode(&id_of(12)),
            crate::helpers::hex_encode(&id_of(13)),
        );
        let got = decode_guard_history(&text, 1e12);
        assert_eq!(got, HashMap::from([(id_of(7), 1000.0)]), "only the one well-formed line survives");
    }

    #[test]
    fn a_time_in_the_future_is_clamped_to_now_and_the_earlier_duplicate_wins() {
        let id = crate::helpers::hex_encode(&id_of(5));
        let other = crate::helpers::hex_encode(&id_of(6));
        let text = format!("{id} 5000\n{id} 1500\n{id} 9000\n{other} 999999\n");
        let got = decode_guard_history(&text, 2000.0);
        assert_eq!(got.get(&id_of(5)), Some(&1500.0), "the earliest time is kept");
        assert_eq!(got.get(&id_of(6)), Some(&2000.0), "nothing can have been seen after now");
    }

    #[test]
    fn a_history_file_is_bounded() {
        let mut text = String::new();
        for i in 0..(MAX_GUARD_HISTORY_ENTRIES + 50) {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&(i as u32).to_be_bytes());
            text.push_str(&format!("{} 100\n", crate::helpers::hex_encode(&id)));
        }
        assert_eq!(decode_guard_history(&text, 1e12).len(), MAX_GUARD_HISTORY_ENTRIES);
        let big: HashMap<Vec<u8>, f64> = (0..(MAX_GUARD_HISTORY_ENTRIES + 50) as u32).map(|i| (i.to_be_bytes().repeat(8), 1.0)).collect();
        assert!(encode_guard_history(&big).lines().count() <= MAX_GUARD_HISTORY_ENTRIES + 1);
    }

    #[test]
    fn merging_keeps_the_earliest_time_and_reports_whether_anything_changed() {
        let mut into = HashMap::from([(id_of(1), 100.0), (id_of(2), 200.0)]);
        assert!(!merge_first_seen(&mut into, &HashMap::from([(id_of(1), 150.0), (id_of(2), 200.0)])), "later or equal times change nothing");
        assert_eq!(into[&id_of(1)], 100.0);
        assert!(merge_first_seen(&mut into, &HashMap::from([(id_of(2), 50.0)])), "an earlier time wins");
        assert_eq!(into[&id_of(2)], 50.0);
        assert!(merge_first_seen(&mut into, &HashMap::from([(id_of(3), 300.0)])), "a new identity is added");
        assert_eq!(into.len(), 3);
    }

    #[test]
    fn the_history_file_sits_beside_the_state_file_and_only_then() {
        let mut args = Args::default();
        assert_eq!(guard_history_path(&args), None, "no state file: memory only, as before");
        args.state_file = Some(String::new());
        assert_eq!(guard_history_path(&args), None);
        args.state_file = Some("/home/u/allium-hs/hs/guard.state".to_string());
        assert_eq!(guard_history_path(&args).as_deref(), Some("/home/u/allium-hs/hs/guard.state.guard-history"));
    }

    #[test]
    fn the_history_file_is_private_atomic_and_missing_means_empty() {
        let path = scratch_path("guard.state.guard-history");
        assert!(load_guard_history(&path, 1e12).is_empty(), "no file yet");
        let first = HashMap::from([(id_of(1), 100.0)]);
        write_atomically(&path, &encode_guard_history(&first)).unwrap();
        assert_eq!(load_guard_history(&path, 1e12), first);
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the history is not readable by other users");
        }
        let second = HashMap::from([(id_of(1), 100.0), (id_of(2), 200.0)]);
        write_atomically(&path, &encode_guard_history(&second)).unwrap();
        assert_eq!(load_guard_history(&path, 1e12), second, "a second save replaces the first");
        let dir = std::path::Path::new(&path).parent().unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().contains(".tmp")).collect();
        assert!(leftovers.is_empty(), "no temporary file is left behind");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The whole point: a relay first seen long enough ago, as recorded by an earlier run,
    /// can be picked as a guard by a later run that has never seen it itself.
    #[test]
    fn history_from_an_earlier_run_makes_a_guard_eligible_in_a_fresh_process() {
        use allium::directory::{Directory, DirectoryOptions, SelectRouteOptions, ROLE_EXIT, ROLE_GUARD};
        let guard = make_descriptor(&gen_identity(), "9.9.9.9", 9001, &[ROLE_GUARD]);
        let exit = make_descriptor(&gen_identity(), "9.9.9.10", 9002, &[ROLE_EXIT]);
        let route = |registry: HashMap<Vec<u8>, f64>| {
            let mut dir = Directory::new(DirectoryOptions { min_guard_age_seconds: Some(MIN_GUARD_OBSERVATION_AGE_SECS), ..Default::default() }).unwrap();
            dir.set_first_seen(registry);
            dir.publish(guard.clone()).unwrap();
            dir.publish(exit.clone()).unwrap();
            dir.select_route(SelectRouteOptions { hops: 2, seed: Some(1), ..Default::default() })
        };
        // a fresh process with no history: the guard was "just seen"
        assert!(route(HashMap::new()).is_err(), "without history a brand-new guard is refused");
        // the earlier run saw it 7 hours ago and wrote it down
        let path = scratch_path("svc.guard-history");
        let seen_then = unix_now() - 7.0 * 3600.0;
        write_atomically(&path, &encode_guard_history(&HashMap::from([(guard.identity_public.clone(), seen_then)]))).unwrap();
        let mut registry = HashMap::new();
        merge_first_seen(&mut registry, &load_guard_history(&path, unix_now()));
        let picked = route(registry).expect("history from the earlier run makes it eligible");
        assert_eq!(picked[0].identity_public, guard.identity_public);
        // and a history written only 1 hour ago is not enough
        write_atomically(&path, &encode_guard_history(&HashMap::from([(guard.identity_public.clone(), unix_now() - 3600.0)]))).unwrap();
        let mut registry = HashMap::new();
        merge_first_seen(&mut registry, &load_guard_history(&path, unix_now()));
        assert!(route(registry).is_err(), "one hour of history is still short of six");
        let _ = std::fs::remove_dir_all(std::path::Path::new(&path).parent().unwrap());
    }

    #[test]
    fn a_lowered_min_guard_age_lets_a_brand_new_guard_through_on_a_test_network() {
        use allium::directory::{Directory, DirectoryOptions, SelectRouteOptions, ROLE_EXIT, ROLE_GUARD};
        let guard = make_descriptor(&gen_identity(), "9.9.9.9", 9001, &[ROLE_GUARD]);
        let exit = make_descriptor(&gen_identity(), "9.9.9.10", 9002, &[ROLE_EXIT]);
        let mut dir = Directory::new(DirectoryOptions { min_guard_age_seconds: Some(0.0), ..Default::default() }).unwrap();
        dir.publish(guard.clone()).unwrap();
        dir.publish(exit).unwrap();
        let picked = dir.select_route(SelectRouteOptions { hops: 2, seed: Some(1), ..Default::default() }).unwrap();
        assert_eq!(picked[0].identity_public, guard.identity_public);
    }
}
