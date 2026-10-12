//! Asynchronous UDP relay node for Allium circuits -- **partial port**.
//!
//! `relay.py` is ~2850 lines: a stateless-peeler-plus-stateful-forwarder
//! design (`allium::onion` supplies the peeler; this module the forwarding
//! half) built around a live `asyncio` UDP event loop (`RelayNode.run`/
//! `_serve_loop`/`handle_create`/`extend_circuit`/`forward_data`/
//! `relay_backward`/`handle_datagram`/...).
//!
//! **What is ported and tested here**: everything in `relay.py` that is
//! pure, synchronous state -- no socket, no `asyncio` -- and therefore
//! fully portable and testable without a real `tokio` build in this
//! sandbox: [`RelayError`] and its aliases, [`derive_relay_identity`],
//! [`CircuitEntry`] (a state-table row, including its reliability
//! bookkeeping -- `accept_seq`/`feed_data`/`pending_ack`/`apply_ack`, which
//! delegate to the already-ported `crate::reliability` types), and
//! [`CircuitTable`] (the two-index lookup/insert/expire table) and
//! [`RelayStats`] (plain counters). These mirror `TestCircuitEntry`,
//! `TestCircuitTable`, `TestRelayStats`, and the pure subset of
//! `TestIdentityPersistence` in `test_relay.py` line for line.
//!
//! **What is deliberately NOT ported in this pass**: `RelayNode` itself --
//! the object that owns a UDP socket, a `HandshakeRelay`, and the
//! `asyncio` event loop, and whose methods (`handle_create`,
//! `register_circuit`, `forward_data`, `deliver`, `extend_circuit`,
//! `relay_extended_backward`, `handle_datagram`, `relay_backward`,
//! `handle_ack`, `_serve_loop`, `run`, `stop`, `_sweeper`) orchestrate the
//! whole peel-swap-forward cycle across live network I/O -- and, in
//! `allium::socksproxy`, `SocksExit` (a mixin over `RelayNode`). Porting
//! `RelayNode` faithfully is a substantially larger undertaking than any
//! other module in this batch: every method above is deeply async,
//! threads five already-ported crates together (`onion`, `handshake`,
//! `createfrag`, `reliability`, `policy`) under real socket I/O, and -- like
//! every `tokio`-touching function elsewhere in this crate -- could not be
//! exercised against a real build in this sandbox even if written. Rather
//! than hand-write ~1900 lines of intricate, un-runnable async orchestration
//! in one pass with no way to catch a wiring mistake, this is left for a
//! dedicated follow-up pass once a real `cargo build`/`cargo test` is
//! available to verify it incrementally (register_circuit/handle_create
//! first, then extend/forward, then the serve loop).
//! `allium::socksproxy`'s `SocksExit` is deferred for the same reason: it
//! is a mixin over `RelayNode` and cannot be ported before it.
//!
//! The four pieces that *are* here are exactly the ones `RelayNode` will be
//! built on top of, so this pass is a real, tested foundation for that
//! follow-up, not a placeholder.

use crate::layer::{decode_ack, encode_ack};
use crate::onion::OnionCrypto;
use crate::reliability::{AckTracker, ReplayWindow, SendWindow, DEFAULT_WINDOW};
use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;

/// Base type for every relay error in this port -- `CircuitNotFound`,
/// `CircuitMismatch`, and `ReplayDetected` are type aliases to it (the same
/// one-type/several-aliases pattern already used by `directory.rs`), since
/// Python's subclassing here exists only so a caller can catch the base
/// class; a message-carrying struct plus `matches!`/`.message` inspection
/// serves every caller in this crate identically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayError {
    pub message: String,
}
impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for RelayError {}
impl RelayError {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

pub type CircuitNotFound = RelayError;
pub type CircuitMismatch = RelayError;
pub type ReplayDetected = RelayError;

fn err(message: impl Into<String>) -> RelayError {
    RelayError::new(message)
}

/// Drop a circuit that has seen no traffic for this long, in seconds.
pub const DEFAULT_IDLE_TIMEOUT: f64 = 300.0;
/// How often the idle sweeper runs, in seconds. Unused by anything ported
/// so far (the sweeper itself lives on the unported `RelayNode`), kept for
/// parity with `relay.py`'s `__all__`.
pub const DEFAULT_CLEANUP_INTERVAL: f64 = 30.0;
/// How long a relay waits for a CREATED reply after relaying a CREATE on
/// behalf of an EXTEND. Unused by anything ported so far.
pub const DEFAULT_EXTEND_TIMEOUT: f64 = 5.0;
/// CREATE cells accepted per source IP per second. Unused by anything
/// ported so far.
pub const DEFAULT_CREATE_RATE: f64 = 20.0;
/// Token-bucket burst capacity paired with [`DEFAULT_CREATE_RATE`]. Unused
/// by anything ported so far.
pub const DEFAULT_CREATE_BURST: u32 = 40;
/// Ack every this many received cells when no hole is open.
pub const DEFAULT_ACK_EVERY: u64 = 4;
/// Length, in bytes, of the per-link backward-authenticity token. Unused
/// by anything ported so far (`CircuitEntry.backward_token`/
/// `outgoing_token` are plain `Option<Vec<u8>>`, with no length check here
/// -- that check lives on the unported `RelayNode`).
pub const LINK_TOKEN_SIZE: usize = 16;

pub const STATE_PENDING: &str = "pending";
pub const STATE_LIVE: &str = "live";
pub const STATE_CLOSED: &str = "closed";

/// `(ip, port)`.
pub type Addr = (String, u16);
/// The state table is keyed by the *incoming* tuple, per the relay contract.
pub type CircuitKeyTuple = (String, u16, u32);

/// Process-wide monotonic reference point, so `CircuitEntry`'s
/// `created_at`/`last_seen` (plain `f64` seconds, directly mutable --
/// `test_expire_idle` relies on assigning `entry.last_seen -= 1000.0`
/// exactly like the Python test does) behave like `time.monotonic()`
/// without pulling in a crate: `std::sync::OnceLock` is standard library,
/// stable, and gives every `CircuitEntry` in the process the same zero
/// point.
fn monotonic_epoch() -> std::time::Instant {
    static EPOCH: OnceLock<std::time::Instant> = OnceLock::new();
    *EPOCH.get_or_init(std::time::Instant::now)
}
fn now() -> f64 {
    monotonic_epoch().elapsed().as_secs_f64()
}

/// Derive a relay's X25519 and Ed25519 private keys from one secret.
///
/// Returns `(x25519_private, ed25519_private)`, each 32 raw bytes.
pub fn derive_relay_identity(master_key: &[u8]) -> Result<([u8; 32], [u8; 32]), RelayError> {
    if master_key.len() < 32 {
        return Err(err(format!("master_key must be at least 32 bytes, got {}", master_key.len())));
    }
    let mut x_input = b"allium-x25519-private-v1".to_vec();
    x_input.extend_from_slice(master_key);
    let x25519_private = crate::blake2::blake2b(&x_input, 32, b"");

    let mut ed_input = b"allium-ed25519-seed-v1".to_vec();
    ed_input.extend_from_slice(master_key);
    let ed25519_seed = crate::blake2::blake2b(&ed_input, 32, b"");

    if ed25519_seed.iter().all(|&b| b == 0) || x25519_private.iter().all(|&b| b == 0) {
        return Err(err("master_key derived a degenerate key; use a different value"));
    }
    let mut xp = [0u8; 32];
    xp.copy_from_slice(&x25519_private);
    let mut ep = [0u8; 32];
    ep.copy_from_slice(&ed25519_seed);
    Ok((xp, ep))
}

/// Derive a relay's identity the way [`derive_relay_identity`] does, but
/// from a hex-encoded master key -- mirrors Python's `derive_relay_identity`
/// accepting either `bytes` or a hex `str` directly; kept as a separate
/// function here since Rust does not have Python's single-parameter
/// str-or-bytes duck typing.
pub fn derive_relay_identity_hex(master_key_hex: &str) -> Result<([u8; 32], [u8; 32]), RelayError> {
    let bytes = hex_decode(master_key_hex).map_err(|e| err(format!("malformed hex master_key: {e}")))?;
    derive_relay_identity(&bytes)
}

/// Cryptographically-random `u32`, for [`CircuitTable::allocate_outgoing_id`]
/// (Python: `secrets.randbelow(1 << 32)`), via [`crate::osrand::os_random`].
fn secure_random_u32() -> Result<u32, RelayError> {
    let mut buf = [0u8; 4];
    crate::osrand::os_random(&mut buf).map_err(|e| err(e.to_string()))?;
    Ok(u32::from_be_bytes(buf))
}

/// Cryptographically-random bytes, for the per-link backward-authenticity
/// token (Python: `os.urandom(LINK_TOKEN_SIZE)`).
fn secure_random_bytes(len: usize) -> Result<Vec<u8>, RelayError> {
    let mut buf = vec![0u8; len];
    crate::osrand::os_random(&mut buf).map_err(|e| err(e.to_string()))?;
    Ok(buf)
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex string".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).ok_or_else(|| "invalid hex digit".to_string())?;
        let lo = (bytes[i + 1] as char).to_digit(16).ok_or_else(|| "invalid hex digit".to_string())?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// CircuitEntry
// ---------------------------------------------------------------------------

/// One row of the relay's state table.
pub struct CircuitEntry {
    pub key: CircuitKeyTuple,
    pub outgoing_addr: Option<Addr>,
    pub outgoing_circuit_id: u32,
    pub hop: OnionCrypto,
    pub hop_index: u32,
    pub is_exit: bool,
    pub state: String,
    pub created_at: f64,
    pub last_seen: f64,
    pub cells_in: u64,
    pub cells_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub replay: ReplayWindow,
    pub replayed: u64,
    pub tracker: AckTracker,
    pub ack_every: u64,
    pub send_window: Option<SendWindow>,
    pub acked: u64,
    pub backward_token: Option<Vec<u8>>,
    pub outgoing_token: Option<Vec<u8>>,
    /// Set once an EXTEND on this circuit has failed
    /// (rejected as private/loopback, or the far end never answered).
    /// `forward_data` refuses a second EXTEND once this is `true`, so a
    /// circuit can no longer be reused to probe a new target after its
    /// first attempt didn't pan out.
    pub extend_failed: bool,
    /// A real, monotonically increasing sequence counter for
    /// cells sent backward (client-bound) on this circuit. Every backward
    /// cell used to be sealed with the fixed value `0`, so its wire bytes
    /// were this hop's PRP (previously XOR mask) output for a known
    /// constant on *every* reply -- a stable per-circuit fingerprint, and
    /// with the old XOR mask, a direct read of the mask itself. See
    /// `CircuitEntry::next_backward_seq`.
    pub backward_seq: u32,
}

/// Options for [`CircuitEntry::new`], mirroring `CircuitEntry.__init__`'s
/// keyword arguments beyond the required `key`/`hop`.
pub struct CircuitEntryOptions {
    pub hop_index: u32,
    pub outgoing_addr: Option<Addr>,
    pub outgoing_circuit_id: Option<u32>,
    pub is_exit: bool,
    pub replay_window: u32,
    pub ack_every: u64,
    pub ack_start: u64,
    pub send_window: bool,
}
impl Default for CircuitEntryOptions {
    fn default() -> Self {
        CircuitEntryOptions {
            hop_index: 0,
            outgoing_addr: None,
            outgoing_circuit_id: None,
            is_exit: false,
            replay_window: DEFAULT_WINDOW,
            ack_every: DEFAULT_ACK_EVERY,
            ack_start: 0,
            send_window: false,
        }
    }
}

impl CircuitEntry {
    pub fn new(key: CircuitKeyTuple, hop: OnionCrypto, options: CircuitEntryOptions) -> Result<CircuitEntry, RelayError> {
        if options.outgoing_addr.is_none() && !options.is_exit {
            return Err(err("a non-exit circuit needs an outgoing_addr; pass is_exit=true to mark this relay as the circuit's last hop"));
        }
        let outgoing_circuit_id = options.outgoing_circuit_id.unwrap_or(key.2);
        let t = now();
        let ack_every = options.ack_every.max(1);
        let tracker = AckTracker::new(options.ack_start, ack_every, 1 << 20, Box::new(now)).map_err(|e| err(e.to_string()))?;
        Ok(CircuitEntry {
            key,
            outgoing_addr: options.outgoing_addr,
            outgoing_circuit_id,
            hop,
            hop_index: options.hop_index,
            is_exit: options.is_exit,
            state: STATE_PENDING.to_string(),
            created_at: t,
            last_seen: t,
            cells_in: 0,
            cells_out: 0,
            bytes_in: 0,
            bytes_out: 0,
            replay: ReplayWindow::new(options.replay_window).map_err(|e| err(e.to_string()))?,
            replayed: 0,
            tracker,
            ack_every,
            send_window: if options.send_window { Some(SendWindow::with_defaults(Box::new(now))) } else { None },
            acked: 0,
            backward_token: None,
            outgoing_token: None,
            extend_failed: false,
            backward_seq: 0,
        })
    }

    /// Return a fresh sequence number for the next backward (client-bound)
    /// cell on this circuit, and advance the counter. Wraps
    /// rather than panics: nothing in the replay/ack logic depends on this
    /// counter never wrapping, only on the PRP masking it not repeating a
    /// wire-visible constant on every reply the way the old fixed `0` did.
    pub fn next_backward_seq(&mut self) -> u32 {
        let seq = self.backward_seq;
        self.backward_seq = self.backward_seq.wrapping_add(1);
        seq
    }

    /// Create an entry with no next hop yet (a placeholder for a finished
    /// handshake with no route agreed).
    pub fn unrouted(key: CircuitKeyTuple, hop: OnionCrypto, hop_index: u32, replay_window: u32, ack_every: u64, ack_start: u64) -> Result<CircuitEntry, RelayError> {
        CircuitEntry::new(
            key,
            hop,
            CircuitEntryOptions { hop_index, outgoing_addr: None, outgoing_circuit_id: None, is_exit: true, replay_window, ack_every, ack_start, send_window: false },
        )
        .map(|mut e| {
            // `is_exit=true` above only to satisfy `new`'s route-or-exit
            // check; an unrouted placeholder is neither routed nor a real
            // exit, so clear it back to false, matching Python's
            // `entry.is_exit = False` in `CircuitEntry.unrouted`.
            e.is_exit = false;
            e
        })
    }

    pub fn accept_seq(&mut self, seq: u64) -> bool {
        if self.replay.accept(seq) {
            true
        } else {
            self.replayed += 1;
            false
        }
    }

    /// Hand an inbound DATA sequence number to the reliability layer;
    /// returns the ack to piggy-back, or empty.
    pub fn feed_data(&mut self, seq: u64) -> Vec<u8> {
        self.tracker.receive(seq);
        match self.tracker.maybe_ack() {
            None => Vec::new(),
            Some(state) => encode_ack(state.cumulative, state.bitmap),
        }
    }

    /// Return an ack even if the policy would not volunteer one.
    pub fn pending_ack(&mut self) -> Vec<u8> {
        let state = self.tracker.force_ack();
        encode_ack(state.cumulative, state.bitmap)
    }

    /// Decode an inbound ack and apply it to this circuit's send window;
    /// returns how many outstanding cells it released.
    pub fn apply_ack(&mut self, payload: &[u8]) -> Result<usize, RelayError> {
        let Some(window) = &mut self.send_window else {
            return Ok(0);
        };
        let state = decode_ack(payload).map_err(|e| err(e.to_string()))?;
        let freed = window.on_ack(state.cumulative, state.bitmap);
        self.acked += 1;
        Ok(freed.len())
    }

    pub fn is_routed(&self) -> bool {
        self.is_exit || self.outgoing_addr.is_some()
    }
    pub fn incoming_addr(&self) -> Addr {
        (self.key.0.clone(), self.key.1)
    }
    pub fn incoming_circuit_id(&self) -> u32 {
        self.key.2
    }
    pub fn age(&self) -> f64 {
        now() - self.created_at
    }
    pub fn idle(&self) -> f64 {
        now() - self.last_seen
    }
    pub fn touch(&mut self) {
        self.last_seen = now();
    }
}

impl PartialEq for CircuitEntry {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}
impl Eq for CircuitEntry {}
impl std::hash::Hash for CircuitEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}
impl fmt::Debug for CircuitEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let destination: String = if self.is_exit { "exit".to_string() } else { format!("{:?}", self.outgoing_addr) };
        write!(
            f,
            "CircuitEntry(in={}:{}#{:#010x} -> out={} out_id={:#010x} state={} cells={}/{})",
            self.key.0, self.key.1, self.key.2, destination, self.outgoing_circuit_id, self.state, self.cells_in, self.cells_out
        )
    }
}

// ---------------------------------------------------------------------------
// CircuitTable
// ---------------------------------------------------------------------------

/// The relay's state table: incoming `(ip, port, circuit_id)` -> route.
pub struct CircuitTable {
    pub by_key: HashMap<CircuitKeyTuple, CircuitEntry>,
    pub by_outgoing: HashMap<(Addr, u32), CircuitKeyTuple>,
    pub idle_timeout: f64,
    pub max_entries: usize,
    /// A hard cap on how
    /// long any circuit stays open regardless of how busy it is, so a
    /// client bug (or a client that has simply never rotated its own
    /// circuits) can't pin one circuit here forever.
    /// `None` (the default) disables this and keeps this table's only
    /// eviction as idle-based, unchanged from before this field existed.
    /// Set directly (there is no constructor parameter for it, to avoid
    /// changing `new`'s signature at every call site) -- see
    /// `RelayNodeOptions::max_circuit_age`.
    pub max_age: Option<f64>,
}

impl CircuitTable {
    pub fn new(idle_timeout: f64, max_entries: usize) -> CircuitTable {
        CircuitTable { by_key: HashMap::new(), by_outgoing: HashMap::new(), idle_timeout, max_entries, max_age: None }
    }
    pub fn with_defaults() -> CircuitTable {
        CircuitTable::new(DEFAULT_IDLE_TIMEOUT, 8192)
    }

    pub fn get(&self, peer_addr: &Addr, circuit_id: u32) -> Result<&CircuitEntry, RelayError> {
        let key = (peer_addr.0.clone(), peer_addr.1, circuit_id);
        match self.by_key.get(&key) {
            Some(e) if e.state != STATE_CLOSED => Ok(e),
            _ => Err(err(format!("no circuit for {}:{}#{:#010x}", key.0, key.1, key.2))),
        }
    }

    pub fn find(&self, peer_addr: &Addr, circuit_id: u32) -> Option<&CircuitEntry> {
        self.get(peer_addr, circuit_id).ok()
    }

    pub fn entry_for_outgoing(&self, outgoing_addr: &Addr, outgoing_circuit_id: u32) -> Option<&CircuitEntry> {
        let key = self.by_outgoing.get(&(outgoing_addr.clone(), outgoing_circuit_id))?;
        self.by_key.get(key)
    }

    pub fn add(&mut self, entry: CircuitEntry) -> Result<&CircuitEntry, RelayError> {
        let existing_outgoing = self.by_key.get(&entry.key).and_then(|e| e.outgoing_addr.clone().map(|a| (a, e.outgoing_circuit_id, e.key.clone())));
        if let Some((addr, id, key)) = existing_outgoing {
            if self.by_outgoing.get(&(addr.clone(), id)) == Some(&key) {
                self.by_outgoing.remove(&(addr, id));
            }
        } else if !self.by_key.contains_key(&entry.key) && self.by_key.len() >= self.max_entries {
            return Err(err(format!("circuit table is full ({} entries); refusing {}:{}#{:#010x}", self.max_entries, entry.key.0, entry.key.1, entry.key.2)));
        }
        let key = entry.key.clone();
        if let Some(addr) = &entry.outgoing_addr {
            self.by_outgoing.insert((addr.clone(), entry.outgoing_circuit_id), key.clone());
        }
        self.by_key.insert(key.clone(), entry);
        Ok(self.by_key.get(&key).unwrap())
    }

    pub fn remove(&mut self, key: &CircuitKeyTuple) -> Option<CircuitEntry> {
        let entry = self.by_key.remove(key)?;
        self.unindex_outgoing(&entry);
        Some(entry)
    }

    fn unindex_outgoing(&mut self, entry: &CircuitEntry) {
        let Some(addr) = &entry.outgoing_addr else { return };
        let outgoing_key = (addr.clone(), entry.outgoing_circuit_id);
        if self.by_outgoing.get(&outgoing_key) == Some(&entry.key) {
            self.by_outgoing.remove(&outgoing_key);
        }
    }

    /// Pick a circuit id for the next hop that no other circuit is using.
    pub fn allocate_outgoing_id(&self, outgoing_addr: &Addr, preferred: Option<u32>) -> Result<u32, RelayError> {
        if let Some(p) = preferred {
            if !self.by_outgoing.contains_key(&(outgoing_addr.clone(), p)) {
                return Ok(p);
            }
        }
        for _ in 0..64 {
            let candidate = secure_random_u32()?;
            if !self.by_outgoing.contains_key(&(outgoing_addr.clone(), candidate)) {
                return Ok(candidate);
            }
        }
        Err(err(format!("could not allocate an outgoing circuit id for {}:{}", outgoing_addr.0, outgoing_addr.1)))
    }

    /// Drop entries idle for longer than the timeout, or (see `max_age`)
    /// simply too old regardless of how recently they were
    /// used; returns the removed entries.
    pub fn expire_idle(&mut self, idle_timeout: Option<f64>) -> Vec<CircuitEntry> {
        let limit = idle_timeout.unwrap_or(self.idle_timeout);
        let max_age = self.max_age;
        let stale: Vec<CircuitKeyTuple> = self
            .by_key
            .values()
            .filter(|e| e.idle() > limit || max_age.map(|m| e.age() > m).unwrap_or(false))
            .map(|e| e.key.clone())
            .collect();
        stale.into_iter().filter_map(|k| self.remove(&k)).collect()
    }

    /// Mark an entry closed and unindex it, keeping the row for accounting.
    pub fn close(&mut self, key: &CircuitKeyTuple) -> Option<&CircuitEntry> {
        if !self.by_key.contains_key(key) {
            return None;
        }
        {
            let entry = self.by_key.get_mut(key).unwrap();
            entry.state = STATE_CLOSED.to_string();
        }
        let entry_snapshot = self.by_key.get(key).map(|e| (e.outgoing_addr.clone(), e.outgoing_circuit_id, e.key.clone()));
        if let Some((Some(addr), id, k)) = entry_snapshot {
            if self.by_outgoing.get(&(addr.clone(), id)) == Some(&k) {
                self.by_outgoing.remove(&(addr, id));
            }
        }
        self.by_key.get(key)
    }

    pub fn clear(&mut self) {
        self.by_key.clear();
        self.by_outgoing.clear();
    }

    pub fn snapshot(&self) -> Vec<&CircuitEntry> {
        self.by_key.values().collect()
    }

    pub fn live_count(&self) -> usize {
        self.by_key.values().filter(|e| e.state != STATE_CLOSED).count()
    }
    pub fn len(&self) -> usize {
        self.by_key.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
    pub fn contains(&self, key: &CircuitKeyTuple) -> bool {
        self.by_key.contains_key(key)
    }
}

impl fmt::Debug for CircuitTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CircuitTable(entries={}, live={}, idle_timeout={})", self.by_key.len(), self.live_count(), self.idle_timeout)
    }
}

// ---------------------------------------------------------------------------
// RelayStats
// ---------------------------------------------------------------------------

/// Counters for monitoring. Plain u64s.
#[derive(Debug, Default, Clone, Copy)]
pub struct RelayStats {
    pub datagrams_in: u64,
    pub datagrams_out: u64,
    pub handshakes_created: u64,
    pub cells_peeled: u64,
    pub cells_forwarded: u64,
    pub cells_delivered: u64,
    pub cells_padded: u64,
    pub acks_received: u64,
    pub cells_acked: u64,
    pub acks_emitted: u64,
    pub dropped_unknown_circuit: u64,
    pub dropped_mismatch: u64,
    pub dropped_undecryptable: u64,
    pub dropped_bad_cell: u64,
    pub dropped_not_data: u64,
    pub dropped_replay: u64,
    pub dropped_bad_ack: u64,
    pub dropped_bad_link_token: u64,
    pub dropped_create_rate_limited: u64,
    pub create_challenges_issued: u64,
    /// Of those, challenges sent in answer to a first fragment (before anything was stored).
    pub create_fragments_challenged: u64,
    /// First fragments that earned no challenge because the global challenge budget was spent.
    pub dropped_challenge_budget: u64,
    pub expired_circuits: u64,
    pub dropped_table_full: u64,
    pub expired_orphan_keys: u64,
    pub dropped_unexpected_error: u64,
}

impl RelayStats {
    pub fn new() -> RelayStats {
        RelayStats::default()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped_unknown_circuit
            + self.dropped_mismatch
            + self.dropped_undecryptable
            + self.dropped_bad_cell
            + self.dropped_not_data
            + self.dropped_replay
            + self.dropped_bad_ack
            + self.dropped_bad_link_token
            + self.dropped_create_rate_limited
            + self.dropped_challenge_budget
            + self.dropped_unexpected_error
    }

    /// Return the counters as a plain map, for JSON logging.
    pub fn as_dict(&self) -> HashMap<&'static str, u64> {
        let mut m = HashMap::new();
        m.insert("datagrams_in", self.datagrams_in);
        m.insert("datagrams_out", self.datagrams_out);
        m.insert("handshakes_created", self.handshakes_created);
        m.insert("cells_peeled", self.cells_peeled);
        m.insert("cells_forwarded", self.cells_forwarded);
        m.insert("cells_delivered", self.cells_delivered);
        m.insert("cells_padded", self.cells_padded);
        m.insert("acks_received", self.acks_received);
        m.insert("cells_acked", self.cells_acked);
        m.insert("acks_emitted", self.acks_emitted);
        m.insert("dropped_unknown_circuit", self.dropped_unknown_circuit);
        m.insert("dropped_mismatch", self.dropped_mismatch);
        m.insert("dropped_undecryptable", self.dropped_undecryptable);
        m.insert("dropped_bad_cell", self.dropped_bad_cell);
        m.insert("dropped_not_data", self.dropped_not_data);
        m.insert("dropped_replay", self.dropped_replay);
        m.insert("dropped_bad_ack", self.dropped_bad_ack);
        m.insert("dropped_bad_link_token", self.dropped_bad_link_token);
        m.insert("dropped_create_rate_limited", self.dropped_create_rate_limited);
        m.insert("create_challenges_issued", self.create_challenges_issued);
        m.insert("create_fragments_challenged", self.create_fragments_challenged);
        m.insert("dropped_challenge_budget", self.dropped_challenge_budget);
        m.insert("expired_circuits", self.expired_circuits);
        m.insert("dropped_table_full", self.dropped_table_full);
        m.insert("expired_orphan_keys", self.expired_orphan_keys);
        m.insert("dropped_unexpected_error", self.dropped_unexpected_error);
        m
    }
}

impl fmt::Display for RelayStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RelayStats(in={}, out={}, peeled={}, fwd={}, delivered={}, dropped={})",
            self.datagrams_in,
            self.datagrams_out,
            self.cells_peeled,
            self.cells_forwarded,
            self.cells_delivered,
            self.dropped()
        )
    }
}

// ---------------------------------------------------------------------------
// RelayNode
// ---------------------------------------------------------------------------
//
// This section (added in a follow-up pass) ports
// `RelayNode` and the module-level `serve_forever`. Per the coordinator's
// explicit instruction, pure decision logic (state transitions, message
// framing, what-to-send decisions) is kept in small synchronous, directly
// unit-testable methods, and every genuinely tokio-touching piece --
// UDP send/recv, `tokio::time::sleep`, `tokio::sync::oneshot` futures used
// to correlate an outgoing CREATE with its CREATED reply, task spawning --
// is isolated behind `// TOKIO-<NAME>-BEGIN/END` sentinel markers, the same
// technique used in `exit.rs`'s eight blocks (see `/tmp/stub6.py`'s
// precedent; this file's counterpart is `/tmp/stub7.py`).
//
// **Concurrency model deviation from Python (documented, deliberate):**
// Python's `RelayNode` runs on a single-threaded `asyncio` event loop, so
// `self` needs no locking even though `_serve_loop`, `_sweeper`, and each
// in-flight `extend_circuit`/`relay_extended_backward`/`relay_backward`
// task all touch the same tables concurrently -- cooperative scheduling
// means only one of them ever runs at a time. This port reproduces exactly
// that model with `Rc<RefCell<RelayNode>>` driven by a `tokio::task::LocalSet`
// (`spawn_local`, not `tokio::spawn`): every task still runs on one OS
// thread, taking turns at `.await` points exactly like `asyncio` does, so
// `RefCell`'s runtime borrow check can never actually trip in practice (the
// same invariant Python leans on implicitly). This avoids forcing every
// field -- including the `Box<dyn FnMut>` hooks below, which have no reason
// to be `Send` -- into `Arc<tokio::sync::Mutex<_>>` for no behavioural gain,
// and keeps the pure methods on `&mut RelayNode` directly, not on some
// lock guard.
//
// **What genuinely could not be exercised for real in this pass:** every
// `TOKIO-*` block below (socket bind/send/recv, the sweeper's `sleep`
// loop, the oneshot-future EXTEND round trip) is, like every other
// tokio-touching function in this crate, written against tokio's stable,
// well-documented API but "unverified pending real cargo build" in this
// sandbox (see Cargo.toml's dependency-policy note) -- the stub-and-restore
// cycle below only proves the *rest* of the crate still compiles and passes
// with these blocks swapped for inert stand-ins, not that the tokio code
// itself is correct. The retry-with-cookie loop inside `_extend_circuit_inner`
// and the CREATE_FRAGMENT hybrid-body path are ported but, for the same
// reason, could not be exercised against a live handshake either.

use crate::cell::{Cell, Command, CELL_SIZE, PAYLOAD_SIZE};
use crate::createfrag::{CreateMessage, CreateReassembler, ExtendReassembler};
use crate::handshake::{create_body_size, CreateBody, HandshakeKeys, HandshakeOps, HandshakeRelay};
use crate::hashutil::constant_time_eq;
use crate::onion::{onion_from_cell, seal_into_cell, OnionError, PeeledLayer};
use crate::policy::RateLimiter;

/// One global allowance for the `CREATE_CHALLENGE` replies a relay sends to first fragments it
/// has not yet verified.
///
/// A challenge costs the relay no per-sender state, but it is still a packet sent to an address
/// the sender chose, so with forged source addresses a relay could be used to bounce traffic at
/// someone else. A challenge is the same size as the request that earns it, so there is no
/// amplification; this caps even the bounce. It is deliberately a single counter, not a table per
/// address: a per-address limiter would itself grow by one entry per forged address.
#[derive(Debug, Clone)]
struct ChallengeBudget {
    tokens: f64,
    last: f64,
}

impl ChallengeBudget {
    /// Challenges per second in the long run (about 19 Mbit/s of full-size cells).
    const RATE: f64 = 2000.0;
    /// Challenges that may go out in one burst.
    const BURST: f64 = 4000.0;

    fn new(now: f64) -> ChallengeBudget {
        ChallengeBudget { tokens: Self::BURST, last: now }
    }

    /// Spend one challenge at time `now`; `false` means the budget is exhausted.
    fn allow(&mut self, now: f64) -> bool {
        let elapsed = (now - self.last).max(0.0);
        self.tokens = Self::BURST.min(self.tokens + elapsed * Self::RATE);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}
use crate::reliability::HandshakeReplayGuard;
use std::cell::RefCell;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;

fn to_socket_addr(addr: &Addr) -> Option<SocketAddr> {
    addr.0.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, addr.1))
}

/// What a fully-synchronous call into [`RelayNode::forward_data`] decided to
/// do. `NeedExtend` is the one case Python handles by firing a background
/// `asyncio.Task` (`loop.create_task(self.extend_circuit(...))`) right
/// inside `forward_data`; this port instead hands the decision back to the
/// caller (the async dispatch shell around [`RelayNode::handle_datagram`]),
/// which is the only place a task can actually be spawned, so the decision
/// itself stays synchronous and testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardOutcome {
    /// Nothing to send (delivered locally, an ack applied, padding dropped).
    Nothing,
    /// `(outgoing datagram, next hop)` -- send this verbatim.
    Send(Vec<u8>, Addr),
    /// An onion-carried EXTEND arrived and needs a background CREATE round
    /// trip; the caller should call [`RelayNode::extend_circuit`].
    NeedExtend { key: CircuitKeyTuple, target_addr: Addr, create_body: Vec<u8> },
}

/// What [`RelayNode::handle_datagram`] decided to do with one datagram.
/// Mirrors Python's `handle_datagram`, whose return shape is already
/// uniform for the synchronous cases (`None` or `(bytes, addr)`); the two
/// cases that need a background task in Python (`EXTENDED`, `RELAY`/
/// `CONNECTED`) get their own variants here for the same reason
/// [`ForwardOutcome::NeedExtend`] does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatagramAction {
    Nothing,
    Reply(Vec<u8>, Addr),
    ScheduleExtend { key: CircuitKeyTuple, target_addr: Addr, create_body: Vec<u8> },
    ScheduleRelayExtendedBackward { cell: Cell, peer_addr: Addr },
    ScheduleRelayBackward { command: Command, cell: Cell, peer_addr: Addr },
    /// A non-cell-sized `ALNT`-prefixed datagram for [`RelayNode::nat_handler`].
    NatMessage(Vec<u8>),
}

/// Constructor options for [`RelayNode::new`], mirroring `RelayNode.__init__`'s
/// keyword arguments.
///
/// `Clone`: sharding builds these
/// options once on the main thread (so `--identity-file`'s
/// load-or-create-key happens exactly once, avoiding a multi-writer race
/// on the key file) and clones them for each shard worker, so every
/// worker's `RelayNode` gets the same identity.
#[derive(Clone)]
pub struct RelayNodeOptions {
    pub static_private: Option<[u8; 32]>,
    pub cipher: String,
    pub idle_timeout: f64,
    /// A hard maximum
    /// circuit lifetime, on top of `idle_timeout`. `None` (the default)
    /// disables it -- see `CircuitTable::max_age`'s doc for why a busy
    /// circuit otherwise never ages out here.
    pub max_circuit_age: Option<f64>,
    /// Reject an EXTEND whose target
    /// is private, loopback, link-local or otherwise non-routable
    /// (`crate::policy::is_private_or_local`), instead of sending a CREATE
    /// there. `false` (the target is checked and rejected) by default;
    /// set `true` only for a loopback test network where relays legitimately
    /// address each other on 127.0.0.1.
    pub allow_private_extend: bool,
    pub max_circuits: usize,
    pub cleanup_interval: f64,
    pub node_name: String,
    pub auto_register: bool,
    pub identity_private: Option<[u8; 32]>,
    pub master_key: Option<Vec<u8>>,
    pub require_identity: bool,
    pub extend_timeout: f64,
    pub handshake_replay_entries: usize,
    pub handshake_replay_ttl: Option<f64>,
    pub create_rate: f64,
    pub create_burst: u32,
    /// The CREATE rate limiter (`create_rate`/
    /// `create_burst`) is keyed by the UDP datagram's source address, which
    /// is trivially spoofable pre-handshake -- an attacker spreading CREATE
    /// cells across forged source IPs gets a fresh token bucket per fake
    /// IP, defeating the limiter and forcing unbounded expensive
    /// asymmetric-crypto processing. `true` by default (matching Python)
    /// so an unverified CREATE gets a cheap `CREATE_CHALLENGE` instead of
    /// the full handshake until its sender proves it can receive traffic
    /// at the address it claims; set `false` only where that round trip
    /// genuinely cannot happen (e.g. a transport that doesn't deliver the
    /// challenge back).
    pub require_return_routability: bool,
    pub cookie_secret: Option<Vec<u8>>,
    pub cookie_window_seconds: f64,
    /// Refuse every EXTEND until
    /// `RelayNode::set_known_relay_addrs` has installed a real set at
    /// least once, instead of leaving the directory-membership check off
    /// (fail-open) until then. `false` by default -- preserving the
    /// original behavior for a caller that deliberately runs with no
    /// directory at all (a closed, manually-wired topology) -- but
    /// `allium-relay-cli`/`allium-authority-cli` both set this `true`
    /// whenever they wire up directory-based EXTEND checking at all
    /// (i.e. whenever `--authority` is configured), closing the window
    /// between process start and the first successful directory fetch,
    /// and the case where the periodic refresher task dies without
    /// anything supervising it -- both of which previously fell open
    /// (accept any non-private EXTEND target) instead of closed.
    pub require_known_relay_addrs: bool,
}
impl Default for RelayNodeOptions {
    fn default() -> Self {
        RelayNodeOptions {
            static_private: None,
            cipher: "chacha20-poly1305".to_string(),
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_circuit_age: None,
            allow_private_extend: false,
            max_circuits: 8192,
            cleanup_interval: DEFAULT_CLEANUP_INTERVAL,
            node_name: "relay".to_string(),
            auto_register: true,
            identity_private: None,
            master_key: None,
            require_identity: false,
            extend_timeout: DEFAULT_EXTEND_TIMEOUT,
            handshake_replay_entries: crate::reliability::DEFAULT_HANDSHAKE_REPLAY_ENTRIES,
            handshake_replay_ttl: Some(crate::reliability::DEFAULT_HANDSHAKE_REPLAY_TTL),
            create_rate: DEFAULT_CREATE_RATE,
            create_burst: DEFAULT_CREATE_BURST,
            require_return_routability: true,
            cookie_secret: None,
            cookie_window_seconds: crate::handshake::DEFAULT_COOKIE_WINDOW_SECONDS,
            require_known_relay_addrs: false,
        }
    }
}

/// The relay's live state: a UDP node that answers CREATE, peels and
/// forwards DATA, and relays EXTEND/EXTENDED. See the module docs above for
/// what is faithfully ported versus simplified/unverified in this pass.
pub struct RelayNode {
    pub handshake: HandshakeRelay,
    handshake_replay: HandshakeReplayGuard,
    create_rate_limiter: RateLimiter,
    challenge_budget: ChallengeBudget,
    pub keys_by_circuit: HashMap<CircuitKeyTuple, HandshakeKeys>,
    keys_created_at: HashMap<CircuitKeyTuple, f64>,
    pending_backward_tokens: HashMap<CircuitKeyTuple, Vec<u8>>,
    pub table: CircuitTable,
    pub stats: RelayStats,
    pub cipher: String,
    pub node_name: String,
    cleanup_interval: f64,
    auto_register: bool,
    extend_timeout: f64,
    /// See `RelayNodeOptions::allow_private_extend`.
    allow_private_extend: bool,
    /// The current set of `(host, port)` addresses a
    /// directory-listed relay may be reached at, refreshed periodically by
    /// the caller (see `RelayNode::set_known_relay_addrs`). `None` --
    /// the default, and what a caller that never calls the setter leaves
    /// this as -- disables the check entirely, matching the pre-existing
    /// (no directory plumbing) behavior; a relay run with no `--authority`
    /// has no consensus to check against, so it stays in that state. This
    /// is on top of, not instead of, the private/loopback filter
    /// and the one-attempt-per-circuit latch, both of which apply
    /// unconditionally either way.
    known_relay_addrs: Option<HashSet<Addr>>,
    /// See `RelayNodeOptions::require_known_relay_addrs`.
    require_known_relay_addrs: bool,
    // TOKIO-SOCK-FIELD-BEGIN
    sock: Option<Rc<tokio::net::UdpSocket>>,
    // TOKIO-SOCK-FIELD-END
    next_hop_resolver: Option<Box<dyn FnMut(u32) -> Option<Addr>>>,
    // TOKIO-PENDING-EXTENDS-FIELD-BEGIN
    pending_extends: HashMap<CircuitKeyTuple, tokio::sync::oneshot::Sender<(Command, Vec<u8>)>>,
    // TOKIO-PENDING-EXTENDS-FIELD-END
    extending: HashSet<CircuitKeyTuple>,
    // TOKIO-TASKS-FIELD-BEGIN
    tasks: Vec<tokio::task::JoinHandle<()>>,
    // TOKIO-TASKS-FIELD-END
    closing: bool,
    /// Optional `(datagram, peer_addr)` sink for raw NAT-traversal messages
    /// (see `allium::nat`), consulted by the caller on a [`DatagramAction::NatMessage`].
    pub nat_handler: Option<Box<dyn FnMut(&[u8], &Addr)>>,
    /// Composition stand-in for Python's `SocksExit(RelayNode)` subclass
    /// overriding `deliver`: since Rust has no method override, an exit
    /// wanting to actually forward delivered payloads (rather than this
    /// port's default log-and-return) installs a callback here instead.
    /// `allium::socksproxy::SocksExit` wires itself in this way.
    pub deliver_fn: Option<Box<dyn FnMut(&CircuitKeyTuple, &PeeledLayer, &[u8])>>,
    /// Composition stand-in for Python's `SocksExit.handle_create` override
    /// (auto-registering every successful handshake as an exit circuit --
    /// the operator's exit policy is "accept every circuit that reaches
    /// this relay"). Called with the peer address and circuit id right
    /// after a `CREATED` reply is produced, from [`RelayNode::handle_create`]
    /// or [`RelayNode::handle_create_reassembled`].
    pub post_create_hook: Option<Box<dyn FnMut(&mut RelayNode, &Addr, u32)>>,
    /// Composition stand-in for Python's `ExitNode._hs_forget_circuit`
    /// (called from `forget_circuit`/`_forget_circuit` to prune
    /// `_hs_intro`/`_hs_pending_rendezvous`/`_hs_partner` entries that named
    /// the circuit being torn down). Called with the key being forgotten,
    /// *before* `forget_circuit`'s own table/key cleanup runs (matching
    /// Python's ordering: the HS bookkeeping lookup still needs
    /// `entry.incoming_circuit_id` etc. to resolve). `Round J`'s
    /// hidden-service relay dispatch (`allium::socksproxy::SocksExit`)
    /// installs this alongside `deliver_fn`/`post_create_hook`.
    pub forget_hook: Option<Box<dyn FnMut(&CircuitKeyTuple)>>,
    /// Mirrors Python's `self.log.warning` call in `handle_datagram` for an
    /// `OnionVersionError` peel failure: the one peel failure an operator
    /// can act on (a peer running an incompatible wire version), and the
    /// one that no amount of retrying will clear -- so it's worth surfacing
    /// above the ordinary per-cell `dropped_undecryptable` stat. This
    /// library crate does no I/O of its own (see this module's other
    /// `_hook`/`_fn` fields for the same composition pattern), so a caller
    /// that wants these surfaced (e.g. `allium-cli`'s `guard`/`middle`/
    /// `exit` roles, via `say`) installs this; `None` (the default) means
    /// silent, matching every hook above. Called with the ready-to-print
    /// message text -- latching (`version_warned`, below) is still done
    /// internally regardless of whether a hook is installed, so installing
    /// one after some cells were already dropped does not replay warnings
    /// for versions already seen.
    pub version_warning_hook: Option<Box<dyn FnMut(&str)>>,
    create_reassembler: CreateReassembler,
    extend_reassembler: ExtendReassembler<CircuitKeyTuple>,
    /// Observed peer protocol versions already warned about once each --
    /// see `version_warning_hook`'s docs and Python's own `_version_warned`
    /// (`relay.py`), which this mirrors: latched so a flood of cells from
    /// an incompatible peer produces one warning, not one per cell.
    version_warned: HashSet<String>,
}

impl RelayNode {
    pub fn new(options: RelayNodeOptions) -> Result<RelayNode, RelayError> {
        let RelayNodeOptions {
            static_private,
            cipher,
            idle_timeout,
            max_circuit_age,
            allow_private_extend,
            max_circuits,
            cleanup_interval,
            node_name,
            auto_register,
            identity_private,
            master_key,
            require_identity,
            extend_timeout,
            handshake_replay_entries,
            handshake_replay_ttl,
            create_rate,
            create_burst,
            require_return_routability,
            cookie_secret,
            cookie_window_seconds,
            require_known_relay_addrs,
        } = options;

        let (static_private, identity_private) = if let Some(mk) = &master_key {
            if static_private.is_some() || identity_private.is_some() {
                return Err(err(
                    "master_key derives both keys; do not also pass static_private or identity_private",
                ));
            }
            let (x, e) = derive_relay_identity(mk)?;
            (Some(x), Some(e))
        } else {
            (static_private, identity_private)
        };

        let handshake = HandshakeRelay::new(
            static_private,
            cipher.clone(),
            false,
            identity_private,
            require_identity,
            require_return_routability,
            cookie_secret,
            cookie_window_seconds,
            HandshakeOps::real(),
        )
        .map_err(|e| err(e.to_string()))?;

        let handshake_replay = HandshakeReplayGuard::new(handshake_replay_entries, handshake_replay_ttl, Box::new(now))
            .map_err(|e| err(e.to_string()))?;
        let create_rate_limiter = RateLimiter::new(create_rate, create_burst, Some(Box::new(now)), None, None)
            .map_err(|e| err(e.to_string()))?;

        let mut table = CircuitTable::new(idle_timeout, max_circuits);
        table.max_age = max_circuit_age;

        let mut node = RelayNode {
            handshake,
            handshake_replay,
            create_rate_limiter,
            challenge_budget: ChallengeBudget::new(now()),
            keys_by_circuit: HashMap::new(),
            keys_created_at: HashMap::new(),
            pending_backward_tokens: HashMap::new(),
            table,
            stats: RelayStats::new(),
            cipher,
            node_name,
            cleanup_interval,
            auto_register,
            extend_timeout,
            allow_private_extend,
            known_relay_addrs: None,
            require_known_relay_addrs,
            sock: None,
            next_hop_resolver: None,
            pending_extends: HashMap::new(),
            extending: HashSet::new(),
            tasks: Vec::new(),
            closing: false,
            nat_handler: None,
            deliver_fn: None,
            post_create_hook: None,
            forget_hook: None,
            version_warning_hook: None,
            create_reassembler: CreateReassembler::new(crate::createfrag::DEFAULT_CREATE_REASSEMBLER_ENTRIES),
            extend_reassembler: ExtendReassembler::new(256),
            version_warned: HashSet::new(),
        };
        // Have an ML-KEM key from the start, so hybrid CREATEs work even for
        // a relay that never publishes.
        node.handshake.rotate_kem_key(false).map_err(|e| RelayError::new(e.to_string()))?;
        Ok(node)
    }

    // -- identity -----------------------------------------------------------

    pub fn public_key(&self) -> [u8; 32] {
        self.handshake.public_key
    }
    pub fn identity_public(&self) -> [u8; 32] {
        self.handshake.identity_public
    }
    pub fn identity_fingerprint(&self) -> String {
        self.identity_public().iter().map(|b| format!("{b:02x}")).collect::<String>()[..16].to_string()
    }
    pub fn sockname(&self) -> Option<Addr> {
        // TOKIO-SOCKNAME-BEGIN
        self.sock.as_ref().and_then(|s| s.local_addr().ok()).map(|a| (a.ip().to_string(), a.port()))
        // TOKIO-SOCKNAME-END
    }

    /// Install (or clear) the set of `(host, port)`
    /// addresses a directory-listed relay is currently reachable at. A
    /// caller with a periodically refreshed consensus/directory (see
    /// `allium-relay-cli`'s `spawn_directory_refresher`, or the
    /// authority's own in-memory `Directory`) calls this each time it
    /// refreshes; `forward_data`'s EXTEND handling then refuses any
    /// target not in the most recently installed set. Passing `None`
    /// (this method is never called at all, or a caller explicitly wants
    /// to turn the check back off) disables the check.
    pub fn set_known_relay_addrs(&mut self, addrs: Option<HashSet<Addr>>) {
        self.known_relay_addrs = addrs;
    }

    // -- circuit lifecycle ----------------------------------------------------

    fn choose_outgoing_id(
        &self,
        outgoing_addr: &Addr,
        requested: Option<u32>,
        existing_addr: Option<&Addr>,
        existing_id: Option<u32>,
        incoming_circuit_id: u32,
    ) -> Result<u32, RelayError> {
        if let Some(req) = requested {
            if self.table.entry_for_outgoing(outgoing_addr, req).is_none() {
                return Ok(req);
            }
            // Falls through to random allocation below, exactly like Python:
            // a taken requested id is not an error, just a reassignment.
        } else if existing_addr == Some(outgoing_addr) {
            return Ok(existing_id.expect("existing_addr implies existing_id"));
        } else if self.table.entry_for_outgoing(outgoing_addr, incoming_circuit_id).is_none() {
            return Ok(incoming_circuit_id);
        }
        self.table.allocate_outgoing_id(outgoing_addr, None)
    }

    /// Insert or update a row of the state table. Returns the row's key
    /// (Python returns the `CircuitEntry` itself; this port returns the key
    /// so callers re-fetch a live `&CircuitEntry`/`&mut CircuitEntry` from
    /// `self.table`, avoiding a borrow tied to `&mut self`).
    pub fn register_circuit(
        &mut self,
        peer_addr: &Addr,
        circuit_id: u32,
        next_hop: Option<&Addr>,
        is_exit: bool,
        outgoing_circuit_id: Option<u32>,
        hop_name: Option<&str>,
        hop_index: Option<u32>,
    ) -> Result<CircuitKeyTuple, RelayError> {
        if next_hop.is_none() && !is_exit {
            return Err(err(
                "register_circuit needs a next_hop, or is_exit=true for the circuit's final hop",
            ));
        }
        let key: CircuitKeyTuple = (peer_addr.0.clone(), peer_addr.1, circuit_id);
        let keys = self.keys_by_circuit.get(&key).cloned();
        let existing = self.table.remove(&key);
        let had_existing = existing.is_some();

        let mut prior_backward_token = None;
        let mut prior_outgoing_token = None;
        let mut prior_outgoing_addr = None;
        let mut prior_outgoing_id = None;

        let (hop, effective_index) = if let Some(mut ex) = existing {
            let effective_index = hop_index.unwrap_or(ex.hop_index);
            ex.hop.hop_index = effective_index as usize;
            prior_backward_token = ex.backward_token.take();
            prior_outgoing_token = ex.outgoing_token.take();
            prior_outgoing_addr = ex.outgoing_addr.clone();
            prior_outgoing_id = Some(ex.outgoing_circuit_id);
            (ex.hop, effective_index)
        } else if let Some(k) = &keys {
            let resolved_index = hop_index.unwrap_or(0);
            let hop = k
                .to_onion_crypto(hop_name.unwrap_or(&self.node_name), resolved_index as usize)
                .map_err(|e| err(e.to_string()))?;
            (hop, resolved_index)
        } else {
            return Err(err(format!(
                "no handshake keys for circuit {circuit_id:#010x}; complete a CREATE handshake for this circuit before registering it"
            )));
        };

        let (outgoing_addr, resolved_id) = if is_exit {
            (None, circuit_id)
        } else {
            let target = next_hop.expect("checked above");
            let addr: Addr = (target.0.clone(), target.1);
            let id = self.choose_outgoing_id(&addr, outgoing_circuit_id, prior_outgoing_addr.as_ref(), prior_outgoing_id, circuit_id)?;
            (Some(addr), id)
        };

        let mut entry = CircuitEntry::new(
            key.clone(),
            hop,
            CircuitEntryOptions {
                hop_index: effective_index,
                outgoing_addr: outgoing_addr.clone(),
                outgoing_circuit_id: Some(resolved_id),
                is_exit,
                ..CircuitEntryOptions::default()
            },
        )?;

        if had_existing {
            entry.backward_token = prior_backward_token;
            entry.outgoing_token = prior_outgoing_token;
        } else {
            entry.backward_token = self.pending_backward_tokens.remove(&key);
        }
        self.table.add(entry)?;
        Ok(key)
    }

    pub fn register_exit_circuit(&mut self, peer_addr: &Addr, circuit_id: u32, hop_index: u32) -> Result<CircuitKeyTuple, RelayError> {
        self.register_circuit(peer_addr, circuit_id, None, true, None, None, Some(hop_index))
    }

    /// Install a callback consulted the first time a DATA cell arrives for a
    /// circuit registered without a next hop: `resolver(circuit_id) -> Addr | None`.
    ///
    /// Unlike a circuit set up through
    /// the normal EXTEND handshake (`extend_circuit_inner`), a circuit
    /// routed via this resolver never exchanges a `outgoing_token` with
    /// its resolved peer -- there is no round trip here to establish one
    /// from. `relay_backward`/`relay_extended_backward` therefore refuse
    /// (fail closed) to relay *any* backward RELAY/CONNECTED/EXTENDED
    /// cell for such a circuit, rather than trusting one that merely
    /// matches the resolved (addr, circuit_id) pair with no cryptographic
    /// proof at all. If a real caller of this API ever needs backward
    /// traffic to work, it will need its own way to establish and record
    /// a shared `outgoing_token` on the resulting `CircuitEntry` before
    /// that works -- this callback alone cannot provide one. Currently
    /// unused by any binary in this workspace.
    pub fn set_next_hop_resolver(&mut self, resolver: Option<Box<dyn FnMut(u32) -> Option<Addr>>>) {
        self.next_hop_resolver = resolver;
    }

    /// Tear down a circuit, dropping its handshake keys too.
    pub fn forget_circuit(&mut self, peer_addr: &Addr, circuit_id: u32) {
        let key: CircuitKeyTuple = (peer_addr.0.clone(), peer_addr.1, circuit_id);
        if let Some(hook) = self.forget_hook.as_mut() {
            hook(&key);
        }
        self.table.close(&key);
        self.keys_by_circuit.remove(&key);
        self.keys_created_at.remove(&key);
        self.pending_backward_tokens.remove(&key);
    }

    // -- control cells --------------------------------------------------------

    fn create_replay_key(&self, circuit_id: u32, payload: &[u8], peer_addr: &Addr) -> Vec<u8> {
        let client_public = CreateBody::unpack(payload).map(|b| b.public_key.to_vec()).unwrap_or_default();
        let mut out = Vec::new();
        out.extend_from_slice(peer_addr.0.as_bytes());
        out.push(0u8);
        out.extend_from_slice(&peer_addr.1.to_be_bytes());
        out.extend_from_slice(&circuit_id.to_be_bytes());
        out.extend_from_slice(&client_public);
        out
    }

    /// Answer a CREATE cell and remember the resulting keys. The reply is
    /// **not** sent here; the caller owns the socket.
    pub fn handle_create(&mut self, datagram: &[u8], peer_addr: &Addr) -> Option<Cell> {
        let cell = Cell::unpack(datagram, true).ok()?;
        if !self.create_rate_limiter.allow(&peer_addr.0, 1.0) {
            self.stats.dropped_create_rate_limited += 1;
            return None;
        }
        let sock_addr = to_socket_addr(peer_addr);
        let reply = self.handshake.respond(datagram, sock_addr).ok()?;
        self.finish_create(cell.circuit_id, &cell.payload, reply, peer_addr)
    }

    /// Same as [`RelayNode::handle_create`], but for a hybrid CREATE
    /// reassembled from `CREATE_FRAGMENT` cells.
    pub fn handle_create_reassembled(&mut self, message: &CreateMessage, peer_addr: &Addr) -> Option<Cell> {
        if !self.create_rate_limiter.allow(&peer_addr.0, 1.0) {
            self.stats.dropped_create_rate_limited += 1;
            return None;
        }
        let sock_addr = to_socket_addr(peer_addr);
        let reply = self.handshake.respond_reassembled(message, sock_addr).ok()?;
        self.finish_create(message.circuit_id, &message.payload, reply, peer_addr)
    }

    /// One `CREATE_FRAGMENT` cell.
    ///
    /// When cookies are required, only a first fragment (index 0) that carries a valid cookie
    /// for the sender's address may start a reassembly entry. A first fragment without one is
    /// answered with a `CREATE_CHALLENGE` and stored nowhere; a later fragment with no entry to
    /// join is dropped silently. So a flood of forged first fragments takes no table space at
    /// all, and a legitimate handshake that is partway through cannot be pushed out by it.
    ///
    /// A client that sends a CREATE for the first time has no cookie, so its first attempt now
    /// gets the challenge on its first fragment instead of after the last one; it retries with
    /// the cookie exactly as before. Fragments of that first attempt that arrive afterwards
    /// are dropped.
    fn handle_create_fragment(&mut self, cell: &Cell, peer_addr: &Addr) -> DatagramAction {
        let mut allow_new = true;
        if self.handshake.requires_return_routability() {
            match CreateReassembler::fragment_parts(cell) {
                None => {
                    self.stats.dropped_bad_cell += 1;
                    return DatagramAction::Nothing;
                }
                Some((0, chunk)) => match self.handshake.admit_first_fragment(chunk, cell.circuit_id, to_socket_addr(peer_addr)) {
                    crate::handshake::FirstFragmentVerdict::Admit => {}
                    crate::handshake::FirstFragmentVerdict::Drop => {
                        self.stats.dropped_bad_cell += 1;
                        return DatagramAction::Nothing;
                    }
                    crate::handshake::FirstFragmentVerdict::Challenge(reply) => {
                        if !self.challenge_budget.allow(now()) {
                            self.stats.dropped_challenge_budget += 1;
                            return DatagramAction::Nothing;
                        }
                        self.stats.create_challenges_issued += 1;
                        self.stats.create_fragments_challenged += 1;
                        return DatagramAction::Reply(reply.pack(), peer_addr.clone());
                    }
                },
                Some(_) => allow_new = false,
            }
        }
        match self.create_reassembler.push_gated(cell, peer_addr.clone(), allow_new) {
            None => DatagramAction::Nothing,
            Some(message) => match self.handle_create_reassembled(&message, peer_addr) {
                Some(reply) => DatagramAction::Reply(reply.pack(), peer_addr.clone()),
                None => DatagramAction::Nothing,
            },
        }
    }

    fn finish_create(&mut self, circuit_id: u32, payload: &[u8], reply: Cell, peer_addr: &Addr) -> Option<Cell> {
        if reply.command == Command::CreateChallenge {
            self.stats.create_challenges_issued += 1;
            return Some(reply);
        }

        let replay_key = self.create_replay_key(circuit_id, payload, peer_addr);
        if !self.handshake_replay.accept(replay_key) {
            self.stats.dropped_replay += 1;
            return None;
        }

        let keys = self.handshake.keys.clone()?;
        let key: CircuitKeyTuple = (peer_addr.0.clone(), peer_addr.1, circuit_id);
        self.keys_by_circuit.insert(key.clone(), keys.clone());
        self.keys_created_at.insert(key.clone(), now());
        self.stats.handshakes_created += 1;

        let mut reply = reply;
        if payload.len() >= create_body_size(payload) + LINK_TOKEN_SIZE {
            let token = payload[payload.len() - LINK_TOKEN_SIZE..].to_vec();
            self.pending_backward_tokens.insert(key.clone(), token.clone());
            let mut new_payload = reply.payload.clone();
            new_payload.extend_from_slice(&token);
            if new_payload.len() > PAYLOAD_SIZE {
                return None;
            }
            reply = Cell::with_command(reply.circuit_id, reply.command, new_payload).ok()?;
        }

        if self.auto_register && self.table.find(peer_addr, circuit_id).is_none() {
            if let Ok(hop) = keys.to_onion_crypto(&self.node_name, 0) {
                if let Ok(mut entry) = CircuitEntry::unrouted(key.clone(), hop, 0, DEFAULT_WINDOW, DEFAULT_ACK_EVERY, 0) {
                    entry.backward_token = self.pending_backward_tokens.remove(&key);
                    if self.table.add(entry).is_err() {
                        self.keys_by_circuit.remove(&key);
                        self.keys_created_at.remove(&key);
                        self.stats.dropped_table_full += 1;
                    }
                }
            }
        }
        if let Some(mut hook) = self.post_create_hook.take() {
            hook(self, peer_addr, circuit_id);
            self.post_create_hook = Some(hook);
        }
        Some(reply)
    }

    fn resolve_outgoing(&mut self, key: &CircuitKeyTuple) -> Option<Addr> {
        let existing_addr = self.table.by_key.get(key)?.outgoing_addr.clone();
        if existing_addr.is_some() {
            return existing_addr;
        }
        let resolver = self.next_hop_resolver.as_mut()?;
        let resolved = resolver(key.2)?;
        let addr: Addr = (resolved.0.clone(), resolved.1);
        let out_id = self.table.allocate_outgoing_id(&addr, None).ok()?;
        let mut entry = self.table.remove(key)?;
        entry.outgoing_addr = Some(addr.clone());
        entry.outgoing_circuit_id = out_id;
        let _ = self.table.add(entry);
        Some(addr)
    }

    // -- DATA cells: peel one layer, swap the circuit id, forward ------------

    /// Peel one layer and produce the datagram to forward (or a decision to
    /// deliver, drop, or schedule a background EXTEND -- see [`ForwardOutcome`]).
    pub fn forward_data(&mut self, datagram: &[u8], peer_addr: &Addr) -> Result<ForwardOutcome, RelayError> {
        self.stats.datagrams_in += 1;
        let cell = match Cell::unpack(datagram, true) {
            Ok(c) => c,
            Err(_) => {
                self.stats.dropped_bad_cell += 1;
                return Ok(ForwardOutcome::Nothing);
            }
        };
        if cell.command != Command::Data {
            self.stats.dropped_not_data += 1;
            return Ok(ForwardOutcome::Nothing);
        }

        let key: CircuitKeyTuple = (peer_addr.0.clone(), peer_addr.1, cell.circuit_id);
        if self.table.find(peer_addr, cell.circuit_id).is_none() {
            self.stats.dropped_unknown_circuit += 1;
            return Err(err(format!("no circuit for {}:{}#{:#010x}", key.0, key.1, key.2)));
        }

        let inner = onion_from_cell(&cell, 0);
        let peeled = match self.table.by_key.get(&key).unwrap().hop.peel(&inner) {
            Ok(p) => p,
            Err(e) => {
                self.stats.dropped_undecryptable += 1;
                // Mirrors relay.py's handle_datagram: an OnionVersionError
                // is the one peel failure an operator can act on (a peer
                // running an incompatible wire version) and the one no
                // retry will ever clear, so it's latched per observed
                // version (self.version_warned/version_warning_hook) and
                // surfaced once per version rather than once per dropped
                // cell -- see this struct's field docs.
                if let OnionError::Version { message, observed } = &e {
                    let key = observed.map(|v| v.to_string()).unwrap_or_else(|| message.clone());
                    if self.version_warned.insert(key) {
                        if let Some(hook) = &mut self.version_warning_hook {
                            hook(message);
                        }
                    }
                }
                return Err(err(format!("circuit {:#010x} did not decrypt at this hop", cell.circuit_id)));
            }
        };

        self.stats.cells_peeled += 1;

        // `touch()`/`cells_in`/`bytes_in`
        // used to run here, before `accept_seq` below -- so a captured
        // cell resubmitted forever kept bumping `last_seen` on every
        // resubmission, even though it was then rejected as a replay a
        // few lines later. That defeated `CircuitTable::expire_idle`'s
        // idle-based reaping (no `max_age` cap by default), letting an
        // attacker pin this circuit's table slot indefinitely and starve
        // legitimate new circuits once the table filled up. Only a cell
        // that actually clears replay detection may refresh liveness or
        // count toward `cells_in`/`bytes_in` now.
        let accepted = self.table.by_key.get_mut(&key).unwrap().accept_seq(peeled.header.seq as u64);
        if !accepted {
            self.stats.dropped_replay += 1;
            return Err(err(format!("circuit {:#010x}: seq {} already seen", cell.circuit_id, peeled.header.seq)));
        }

        {
            let entry = self.table.by_key.get_mut(&key).unwrap();
            entry.cells_in += 1;
            entry.bytes_in += inner.len() as u64;
            entry.touch();
            if entry.state == STATE_PENDING {
                entry.state = STATE_LIVE.to_string();
            }
        }

        let pending_ack = self.table.by_key.get_mut(&key).unwrap().feed_data(peeled.header.seq as u64);
        if !pending_ack.is_empty() {
            self.stats.acks_emitted += 1;
        }

        if peeled.is_ack() {
            return match self.table.by_key.get_mut(&key).unwrap().apply_ack(&peeled.plaintext) {
                Ok(freed) => {
                    self.stats.acks_received += 1;
                    self.stats.cells_acked += freed as u64;
                    Ok(ForwardOutcome::Nothing)
                }
                Err(_) => {
                    self.stats.dropped_bad_ack += 1;
                    Err(err("malformed piggy-backed ack"))
                }
            };
        }

        if peeled.is_padding() {
            self.stats.cells_padded += 1;
            return Ok(ForwardOutcome::Nothing);
        }

        if peeled.is_payload() {
            if !self.table.by_key.get(&key).unwrap().is_exit {
                self.stats.dropped_mismatch += 1;
                return Err(err(format!(
                    "payload layer on circuit {:#010x}, but this relay is not the exit",
                    cell.circuit_id
                )));
            }
            self.stats.cells_delivered += 1;
            {
                let entry = self.table.by_key.get_mut(&key).unwrap();
                entry.cells_out += 1;
                entry.bytes_out += peeled.plaintext.len() as u64;
            }
            self.deliver(&key, &peeled);
            return Ok(ForwardOutcome::Nothing);
        }

        if peeled.is_extend() {
            let entry = self.table.by_key.get(&key).unwrap();
            let is_routed = entry.is_routed();
            // Once an EXTEND on this circuit has failed
            // (below, or in `extend_circuit` after this call returns),
            // `extend_failed` is latched so the client can't try a second
            // target on the same circuit.
            let already_failed = entry.extend_failed;
            if is_routed || already_failed || self.extending.contains(&key) {
                self.stats.dropped_mismatch += 1;
                return Err(err(format!(
                    "circuit {:#010x} is already routed, already failed, or already extending; refusing a second EXTEND",
                    cell.circuit_id
                )));
            }
            let mut create_body = peeled.plaintext.clone();
            if ExtendReassembler::<CircuitKeyTuple>::is_fragment(&create_body) {
                match self.extend_reassembler.push(key.clone(), &create_body) {
                    Some(full) => create_body = full,
                    None => return Ok(ForwardOutcome::Nothing),
                }
            }
            let target_addr = peeled.target_addr.clone().unwrap_or_else(|| (String::new(), 0));

            // Never send a CREATE to a
            // private, loopback, link-local or otherwise non-routable
            // address on the client's say-so. This is on top of, not
            // instead of, the directory check right below: the exit's TCP
            // policy already runs this same check (`ExitPolicy::check_host`),
            // but relay-to-
            // relay EXTEND never did.
            if !self.allow_private_extend && crate::policy::is_private_or_local(&target_addr.0) {
                self.stats.dropped_mismatch += 1;
                self.table.by_key.get_mut(&key).unwrap().extend_failed = true;
                return Err(err(format!(
                    "circuit {:#010x}: EXTEND target {}:{} is private/loopback/local; refusing (ALLIUM-H8)",
                    cell.circuit_id, target_addr.0, target_addr.1
                )));
            }

            // Only extend to an address the current
            // directory actually lists a relay at. `known_relay_addrs` is
            // `None` until a caller has installed a set via
            // `set_known_relay_addrs`. What happens then depends on
            // `require_known_relay_addrs`: with it off (a relay
            // deliberately run with no directory plumbing at all), this
            // falls back to just the private/loopback and one-attempt-per-circuit checks above/below, as
            // before; with it on (every real `allium-relay-cli`/
            // `allium-authority-cli` deployment that has `--authority`
            // configured), a `None` here -- process just started and the
            // first fetch hasn't landed yet, or the periodic refresher
            // task died -- fails closed instead of silently accepting any
            // non-private target.
            match &self.known_relay_addrs {
                Some(known) if !known.contains(&target_addr) => {
                    self.stats.dropped_mismatch += 1;
                    self.table.by_key.get_mut(&key).unwrap().extend_failed = true;
                    return Err(err(format!(
                        "circuit {:#010x}: EXTEND target {}:{} is not in the current directory; refusing (ALLIUM-H8)",
                        cell.circuit_id, target_addr.0, target_addr.1
                    )));
                }
                None if self.require_known_relay_addrs => {
                    self.stats.dropped_mismatch += 1;
                    self.table.by_key.get_mut(&key).unwrap().extend_failed = true;
                    return Err(err(format!(
                        "circuit {:#010x}: EXTEND target {}:{} refused -- no directory has been loaded yet \
                         (require_known_relay_addrs is set); refusing (ALLIUM-H8)",
                        cell.circuit_id, target_addr.0, target_addr.1
                    )));
                }
                _ => {}
            }

            self.extending.insert(key.clone());
            return Ok(ForwardOutcome::NeedExtend { key, target_addr, create_body });
        }

        let next_hop = match self.resolve_outgoing(&key) {
            Some(h) => h,
            None => {
                self.stats.dropped_mismatch += 1;
                return Err(err(format!("circuit {:#010x} has no route yet at {}", cell.circuit_id, self.node_name)));
            }
        };

        let entry_outgoing_addr = self.table.by_key.get(&key).unwrap().outgoing_addr.clone();
        if peeled.next_hop != entry_outgoing_addr {
            self.stats.dropped_mismatch += 1;
            return Err(err(format!("circuit {:#010x}: header next_hop != table", cell.circuit_id)));
        }

        let forwarded = match &peeled.forwarded {
            Some(f) => f.clone(),
            None => {
                self.stats.dropped_mismatch += 1;
                return Err(err(format!("route layer on circuit {:#010x} carried nothing to forward", cell.circuit_id)));
            }
        };

        let out_circuit_id = self.table.by_key.get(&key).unwrap().outgoing_circuit_id;
        let outgoing = seal_into_cell(&forwarded, out_circuit_id, Some(cell.command)).map_err(|e| err(e.to_string()))?;
        {
            let entry = self.table.by_key.get_mut(&key).unwrap();
            entry.cells_out += 1;
            entry.bytes_out += forwarded.len() as u64;
        }
        self.stats.cells_forwarded += 1;
        Ok(ForwardOutcome::Send(outgoing.pack(), next_hop))
    }

    /// Deliver an exit payload locally. The default behaviour logs nothing
    /// (no logger in this port) and returns the payload bytes; installing
    /// [`RelayNode::deliver_fn`] overrides this the way Python's
    /// `SocksExit.deliver` overrides the base class method.
    pub fn deliver(&mut self, key: &CircuitKeyTuple, peeled: &PeeledLayer) -> Vec<u8> {
        let payload = peeled.payload_bytes().unwrap_or_default();
        if let Some(cb) = self.deliver_fn.as_mut() {
            cb(key, peeled, &payload);
        }
        payload
    }

    // -- datagram router --------------------------------------------------

    /// Route one datagram; see [`DatagramAction`] for what the caller does
    /// with the result.
    pub fn handle_datagram(&mut self, datagram: &[u8], peer_addr: &Addr) -> DatagramAction {
        if datagram.len() != CELL_SIZE {
            if datagram.len() >= 4 && &datagram[..4] == b"ALNT" {
                return DatagramAction::NatMessage(datagram.to_vec());
            }
            self.stats.dropped_bad_cell += 1;
            return DatagramAction::Nothing;
        }
        let cell = match Cell::unpack(datagram, true) {
            Ok(c) => c,
            Err(_) => {
                self.stats.dropped_bad_cell += 1;
                return DatagramAction::Nothing;
            }
        };

        match cell.command {
            Command::Create => match self.handle_create(datagram, peer_addr) {
                Some(reply) => DatagramAction::Reply(reply.pack(), peer_addr.clone()),
                None => DatagramAction::Nothing,
            },
            Command::CreateFragment => self.handle_create_fragment(&cell, peer_addr),
            Command::Destroy => {
                let backward_token = self.table.find(peer_addr, cell.circuit_id).map(|e| e.backward_token.clone());
                match backward_token {
                    None => self.stats.dropped_unknown_circuit += 1,
                    Some(Some(tok)) => {
                        if cell.payload.len() != LINK_TOKEN_SIZE || !constant_time_eq(&cell.payload, &tok) {
                            self.stats.dropped_bad_link_token += 1;
                        } else {
                            self.forget_circuit(peer_addr, cell.circuit_id);
                        }
                    }
                    // A circuit
                    // with no `backward_token` at all used to have DESTROY
                    // honored unconditionally here -- no token to check
                    // means nothing was ever compared, so an off-path
                    // attacker who can spoof `peer_addr` (UDP has no
                    // source-address authentication) and guess or observe
                    // `circuit_id` (not secret) could tear down any such
                    // circuit outright. No production caller in this
                    // codebase currently sends a client-generated link
                    // token on its own CREATE (only relay-to-relay EXTEND
                    // does, via `extend_circuit_inner`'s `my_token`), so in
                    // practice every client-facing first hop is in this
                    // token-less state -- making this the live, broadly
                    // reachable path, not an edge case. Fail closed instead:
                    // a token-less circuit can still only be reclaimed via
                    // `expire_idle`'s idle-timeout sweep, exactly as if this
                    // DESTROY had never arrived, rather than letting an
                    // unauthenticated packet end it early.
                    Some(None) => self.stats.dropped_bad_link_token += 1,
                }
                DatagramAction::Nothing
            }
            Command::Data => match self.forward_data(datagram, peer_addr) {
                Ok(ForwardOutcome::Nothing) => DatagramAction::Nothing,
                Ok(ForwardOutcome::Send(bytes, addr)) => DatagramAction::Reply(bytes, addr),
                Ok(ForwardOutcome::NeedExtend { key, target_addr, create_body }) => {
                    DatagramAction::ScheduleExtend { key, target_addr, create_body }
                }
                Err(e) => {
                    // Temporary diagnostic: forward_data's
                    // errors -- including the pre-existing EXTEND
                    // rejections -- were built as full messages but always
                    // discarded here with no logging anywhere, making a
                    // silently-refused EXTEND indistinguishable from a lost
                    // packet. Log it so a rejection actually shows up in
                    // journalctl instead of just incrementing a stat nobody's
                    // watching live.
                    eprintln!("{}: {e}", self.node_name);
                    DatagramAction::Nothing
                }
            },
            Command::Ack => {
                self.handle_ack(&cell, peer_addr);
                DatagramAction::Nothing
            }
            Command::Created | Command::CreateChallenge => {
                // TOKIO-RESOLVE-PENDING-EXTEND-CALL-BEGIN
                self.resolve_pending_extend(&cell, peer_addr);
                // TOKIO-RESOLVE-PENDING-EXTEND-CALL-END
                DatagramAction::Nothing
            }
            Command::Extended => {
                // Both
                // `relay_extended_backward` and `relay_backward` below
                // already drop a cell for an unknown `(peer, circuit_id)`
                // -- but only *after* `serve_loop` has already spawned a
                // task for it and pushed the `JoinHandle` into
                // `node.tasks`, which was never drained except in
                // `stop()`. Checking here, before returning the
                // `Schedule*` action at all, means an attacker who never
                // completed a handshake (no circuit ever existed for this
                // `(peer, circuit_id)`) can no longer make this relay
                // spawn -- and permanently retain -- a task per garbage
                // cell sent.
                if self.table.entry_for_outgoing(peer_addr, cell.circuit_id).is_none() {
                    self.stats.dropped_unknown_circuit += 1;
                    return DatagramAction::Nothing;
                }
                DatagramAction::ScheduleRelayExtendedBackward { cell, peer_addr: peer_addr.clone() }
            }
            Command::Relay | Command::Connected => {
                if self.table.entry_for_outgoing(peer_addr, cell.circuit_id).is_none() {
                    self.stats.dropped_unknown_circuit += 1;
                    return DatagramAction::Nothing;
                }
                DatagramAction::ScheduleRelayBackward { command: cell.command, cell, peer_addr: peer_addr.clone() }
            }
            _ => {
                self.stats.dropped_not_data += 1;
                DatagramAction::Nothing
            }
        }
    }

    /// Apply a standalone ACK cell to the circuit's send window.
    pub fn handle_ack(&mut self, cell: &Cell, peer_addr: &Addr) {
        let key: CircuitKeyTuple = (peer_addr.0.clone(), peer_addr.1, cell.circuit_id);
        let Some(entry) = self.table.by_key.get_mut(&key) else {
            self.stats.dropped_unknown_circuit += 1;
            return;
        };
        if entry.state == STATE_CLOSED {
            self.stats.dropped_unknown_circuit += 1;
            return;
        }
        match entry.apply_ack(&cell.payload) {
            Ok(freed) => {
                entry.last_seen = now();
                self.stats.acks_received += 1;
                self.stats.cells_acked += freed as u64;
            }
            Err(_) => self.stats.dropped_bad_ack += 1,
        }
    }

    /// Route an incoming CREATED/CREATE_CHALLENGE to a pending
    /// [`RelayNode::extend_circuit`] call, waking its oneshot future.
    // TOKIO-RESOLVE-PENDING-EXTEND-BEGIN
    fn resolve_pending_extend(&mut self, cell: &Cell, peer_addr: &Addr) {
        let key: CircuitKeyTuple = (peer_addr.0.clone(), peer_addr.1, cell.circuit_id);
        if let Some(sender) = self.pending_extends.remove(&key) {
            let _ = sender.send((cell.command, cell.payload.clone()));
        } else {
            self.stats.dropped_not_data += 1;
        }
    }
    // TOKIO-RESOLVE-PENDING-EXTEND-END

    // -- circuit extension: relay a CREATE, wrap the CREATED reply backward --

    /// Perform one hop of an EXTEND on behalf of `key`'s predecessor. See
    /// `relay.py`'s `extend_circuit`/`_extend_circuit_inner` for the full
    /// rationale (silent failure, the return-routability cookie retry, the
    /// backward-authenticity token). Runs as a spawned task from the serve
    /// loop, not awaited inline, so the socket stays free to deliver the
    /// CREATED reply this call is waiting on.
    // TOKIO-EXTEND-CIRCUIT-BEGIN
    pub async fn extend_circuit(node: Rc<RefCell<RelayNode>>, key: CircuitKeyTuple, target_addr: Addr, create_body: Vec<u8>) -> bool {
        let result = RelayNode::extend_circuit_inner(node.clone(), &key, &target_addr, create_body).await;
        let mut n = node.borrow_mut();
        n.extending.remove(&key);
        if !result {
            // A failed EXTEND (target never answered,
            // sent a bad reply, etc.) must not leave the circuit free to
            // try a different target next -- `forward_data`'s
            // `already_failed` check is what actually enforces this; this
            // is where the flag gets set for the "it went out but got no
            // usable reply" case (the private/loopback case above sets it
            // itself, before ever getting here).
            if let Some(entry) = n.table.by_key.get_mut(&key) {
                entry.extend_failed = true;
            }
        }
        result
    }

    async fn extend_circuit_inner(node: Rc<RefCell<RelayNode>>, key: &CircuitKeyTuple, target_addr: &Addr, create_body: Vec<u8>) -> bool {
        let (extend_timeout, incoming_addr) = {
            let n = node.borrow();
            (n.extend_timeout, (key.0.clone(), key.1))
        };
        let body = match CreateBody::unpack(&create_body) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let new_circuit_id = body.circuit_id;
        let future_key: CircuitKeyTuple = (target_addr.0.clone(), target_addr.1, new_circuit_id);

        let my_token = match secure_random_bytes(LINK_TOKEN_SIZE) {
            Ok(t) => t,
            Err(_) => return false,
        };
        if create_body.len() + LINK_TOKEN_SIZE > PAYLOAD_SIZE && !body.is_hybrid() {
            return false;
        }

        let mut outgoing_body = create_body.clone();
        let max_attempts = 2;
        let mut raw_reply: Option<Vec<u8>> = None;
        for attempt in 1..=max_attempts {
            let (tx, rx) = tokio::sync::oneshot::channel::<(Command, Vec<u8>)>();
            {
                let mut n = node.borrow_mut();
                n.pending_extends.insert(future_key.clone(), tx);
            }
            let full = {
                let mut f = outgoing_body.clone();
                f.extend_from_slice(&my_token);
                f
            };
            let send_result = if full.len() <= PAYLOAD_SIZE {
                match Cell::with_command(new_circuit_id, Command::Create, full) {
                    Ok(cell) => RelayNode::send_datagram(&node, &cell.pack(), target_addr).await,
                    Err(_) => Ok(()),
                }
            } else {
                match crate::createfrag::fragment_create(new_circuit_id, &full, None) {
                    Ok(cells) => {
                        let mut ok = Ok(());
                        for c in cells {
                            ok = RelayNode::send_datagram(&node, &c.pack(), target_addr).await;
                            if ok.is_err() {
                                break;
                            }
                        }
                        ok
                    }
                    Err(_) => Ok(()),
                }
            };
            if send_result.is_err() {
                node.borrow_mut().pending_extends.remove(&future_key);
                return false;
            }

            let reply = tokio::time::timeout(std::time::Duration::from_secs_f64(extend_timeout.max(0.0)), rx).await;
            node.borrow_mut().pending_extends.remove(&future_key);
            let (reply_command, reply_payload) = match reply {
                Ok(Ok(pair)) => pair,
                _ => return false, // timed out, or the sender was dropped
            };

            if reply_command == Command::CreateChallenge {
                if attempt == max_attempts {
                    return false;
                }
                let challenge = match crate::handshake::ChallengeBody::unpack(&reply_payload) {
                    Ok(c) => c,
                    Err(_) => return false,
                };
                outgoing_body = match crate::handshake::with_cookie(&create_body, &challenge.cookie) {
                    Ok(b) => b,
                    Err(_) => return false,
                };
                continue;
            }
            raw_reply = Some(reply_payload);
            break;
        }

        let raw_reply = match raw_reply {
            Some(r) => r,
            None => return false,
        };
        if raw_reply.len() < LINK_TOKEN_SIZE {
            return false;
        }
        let (created_body, echoed_token) = raw_reply.split_at(raw_reply.len() - LINK_TOKEN_SIZE);
        if !constant_time_eq(echoed_token, &my_token) {
            return false;
        }

        let hop_index = {
            let n = node.borrow();
            n.table.find(&incoming_addr, key.2).map(|e| e.hop_index).unwrap_or(0)
        };
        {
            let mut n = node.borrow_mut();
            if n.register_circuit(&incoming_addr, key.2, Some(target_addr), false, Some(new_circuit_id), None, Some(hop_index)).is_err() {
                return false;
            }
            let Some(routed_entry) = n.table.by_key.get_mut(key) else { return false };
            routed_entry.outgoing_token = Some(my_token.clone());
        }

        let (mut reply_payload, backward_token, incoming_addr2, incoming_circuit_id) = {
            let mut n = node.borrow_mut();
            let Some(routed_entry) = n.table.by_key.get_mut(key) else { return false };
            // A real, advancing backward seq instead of the
            // fixed 0 every reply used to carry.
            let backward_seq = routed_entry.next_backward_seq();
            let payload = match routed_entry.hop.seal_payload(created_body, backward_seq, routed_entry.incoming_addr(), Some(crate::layer::Kind::EXTENDED), None) {
                Ok(p) => p,
                Err(_) => return false,
            };
            (payload, routed_entry.backward_token.clone(), routed_entry.incoming_addr(), routed_entry.incoming_circuit_id())
        };
        if let Some(tok) = &backward_token {
            reply_payload.extend_from_slice(tok);
        }
        if reply_payload.len() > PAYLOAD_SIZE {
            return false;
        }
        let reply_cell = match seal_into_cell(&reply_payload, incoming_circuit_id, Some(Command::Extended)) {
            Ok(c) => c,
            Err(_) => return false,
        };
        RelayNode::send_datagram(&node, &reply_cell.pack(), &incoming_addr2).await.is_ok()
    }

    /// Forward an EXTENDED reply one hop back toward the client. See
    /// `relay.py`'s `relay_extended_backward` for the rationale.
    pub async fn relay_extended_backward(node: Rc<RefCell<RelayNode>>, cell: Cell, peer_addr: Addr) -> bool {
        let (has_token, inner, outgoing_token, hop_seal, incoming_addr, backward_token, incoming_circuit_id) = {
            let mut n = node.borrow_mut();
            let Some(entry) = n.table.entry_for_outgoing(&peer_addr, cell.circuit_id) else {
                n.stats.dropped_unknown_circuit += 1;
                return false;
            };
            let has_token = entry.outgoing_token.is_some();
            let key = entry.key.clone();
            let outgoing_token = entry.outgoing_token.clone();
            let incoming_addr = entry.incoming_addr();
            let backward_token = entry.backward_token.clone();
            let incoming_circuit_id = entry.incoming_circuit_id();
            let inner = onion_from_cell(&cell, if has_token { LINK_TOKEN_SIZE } else { 0 });
            (has_token, inner, outgoing_token, key, incoming_addr, backward_token, incoming_circuit_id)
        };

        let mut inner = inner;
        if has_token {
            if inner.len() < LINK_TOKEN_SIZE {
                node.borrow_mut().stats.dropped_bad_link_token += 1;
                return false;
            }
            let split_at = inner.len() - LINK_TOKEN_SIZE;
            let tag = inner[split_at..].to_vec();
            inner.truncate(split_at);
            if !constant_time_eq(&tag, outgoing_token.as_deref().unwrap_or(&[])) {
                node.borrow_mut().stats.dropped_bad_link_token += 1;
                return false;
            }
        } else {
            // This used to fall through
            // and trust `inner` unconditionally whenever a circuit had no
            // `outgoing_token` -- which, for any entry actually present in
            // `by_outgoing` (this function only ever reaches here via a
            // successful `entry_for_outgoing` lookup), is exclusively the
            // `resolve_outgoing`/`set_next_hop_resolver` path: an
            // extend-routed circuit always has a token by the time it's
            // indexed under its outgoing (addr, circuit_id) (see
            // `extend_circuit_inner`, which sets it in the same
            // non-yielding borrow as the registration that indexes it),
            // and an `is_exit` circuit has no `outgoing_addr` at all so it
            // can never be found by `entry_for_outgoing` in the first
            // place. A resolver-routed circuit has no round trip with its
            // resolved peer to establish a shared token from, so there is
            // nothing sound to check here -- failing closed (reject) is
            // the only safe option, versus the old behavior of accepting
            // any backward RELAY/CONNECTED/EXTENDED cell whose sender
            // merely matched the (spoofable) outgoing (addr, circuit_id)
            // pair, no cryptographic proof required at all.
            node.borrow_mut().stats.dropped_bad_link_token += 1;
            return false;
        }

        let mut wrapped = {
            let mut n = node.borrow_mut();
            let Some(entry) = n.table.by_key.get_mut(&hop_seal) else { return false };
            // A real backward seq, not the fixed 0.
            let backward_seq = entry.next_backward_seq();
            match entry.hop.seal_payload(&inner, backward_seq, incoming_addr.clone(), Some(crate::layer::Kind::EXTENDED), None) {
                Ok(w) => w,
                Err(_) => return false,
            }
        };
        if let Some(tok) = &backward_token {
            wrapped.extend_from_slice(tok);
        }
        if wrapped.len() > PAYLOAD_SIZE {
            return false;
        }
        let out_cell = match seal_into_cell(&wrapped, incoming_circuit_id, Some(Command::Extended)) {
            Ok(c) => c,
            Err(_) => return false,
        };
        RelayNode::send_datagram(&node, &out_cell.pack(), &incoming_addr).await.is_ok()
    }

    /// Relay a return-path RELAY/CONNECTED cell one hop back toward the client.
    pub async fn relay_backward(node: Rc<RefCell<RelayNode>>, command: Command, cell: Cell, peer_addr: Addr) -> bool {
        let (has_token, inner, outgoing_token, hop_key, incoming_addr, backward_token, incoming_circuit_id) = {
            let mut n = node.borrow_mut();
            let Some(entry) = n.table.entry_for_outgoing(&peer_addr, cell.circuit_id) else {
                n.stats.dropped_unknown_circuit += 1;
                return false;
            };
            let has_token = entry.outgoing_token.is_some();
            let key = entry.key.clone();
            let outgoing_token = entry.outgoing_token.clone();
            let incoming_addr = entry.incoming_addr();
            let backward_token = entry.backward_token.clone();
            let incoming_circuit_id = entry.incoming_circuit_id();
            let inner = onion_from_cell(&cell, if has_token { LINK_TOKEN_SIZE } else { 0 });
            (has_token, inner, outgoing_token, key, incoming_addr, backward_token, incoming_circuit_id)
        };
        let mut inner = inner;
        if has_token {
            if inner.len() < LINK_TOKEN_SIZE {
                node.borrow_mut().stats.dropped_bad_link_token += 1;
                return false;
            }
            let split_at = inner.len() - LINK_TOKEN_SIZE;
            let tag = inner[split_at..].to_vec();
            inner.truncate(split_at);
            if !constant_time_eq(&tag, outgoing_token.as_deref().unwrap_or(&[])) {
                node.borrow_mut().stats.dropped_bad_link_token += 1;
                return false;
            }
        } else {
            // See the matching comment in
            // `relay_extended_backward` -- an entry findable here with no
            // `outgoing_token` is exclusively a `resolve_outgoing`-routed
            // circuit, which has no round trip with its resolved peer to
            // establish a shared token from. Fail closed instead of
            // trusting any backward RELAY/CONNECTED cell that merely
            // matches the (spoofable) outgoing (addr, circuit_id) pair.
            node.borrow_mut().stats.dropped_bad_link_token += 1;
            return false;
        }
        let mut wrapped = {
            let mut n = node.borrow_mut();
            let Some(entry) = n.table.by_key.get_mut(&hop_key) else { return false };
            // A real backward seq, not the fixed 0.
            let backward_seq = entry.next_backward_seq();
            match entry.hop.seal_payload(&inner, backward_seq, incoming_addr.clone(), Some(crate::layer::Kind::PAYLOAD), None) {
                Ok(w) => w,
                Err(_) => return false,
            }
        };
        if let Some(tok) = &backward_token {
            wrapped.extend_from_slice(tok);
        }
        if wrapped.len() > PAYLOAD_SIZE {
            return false;
        }
        let outgoing = match seal_into_cell(&wrapped, incoming_circuit_id, Some(command)) {
            Ok(c) => c,
            Err(_) => return false,
        };
        RelayNode::send_datagram(&node, &outgoing.pack(), &incoming_addr).await.is_ok()
    }

    pub(crate) async fn send_datagram(node: &Rc<RefCell<RelayNode>>, datagram: &[u8], addr: &Addr) -> std::io::Result<()> {
        let Some(sock_addr) = to_socket_addr(addr) else {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "unparsable address"));
        };
        // Clone the `Rc<UdpSocket>` handle out from behind a short-lived
        // `RefCell` borrow, then call `send_to` (and await it) with no
        // borrow of `node` held at all -- the same short-lived-lock
        // discipline `exit.rs`'s `pump_stream` established, applied here to
        // sidestep a real soundness trap: a future borrowed from *inside*
        // a `Ref` guard cannot outlive that guard, so the socket is kept as
        // its own `Rc` (cheap to clone, not tied to the node's borrow)
        // rather than reached through `node.borrow().sock.as_ref()` across
        // the `.await` point.
        let Some(sock) = node.borrow().sock.clone() else {
            return Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "socket not bound"));
        };
        sock.send_to(datagram, sock_addr).await?;
        node.borrow_mut().stats.datagrams_out += 1;
        Ok(())
    }
    // TOKIO-EXTEND-CIRCUIT-END

    /// Fire-and-forget send of `[(bytes, addr), ...]` from this relay's own
    /// socket (matters for NAT traversal: the hole a punch opens is for
    /// *this* socket's mapping).
    // TOKIO-SEND-RAW-SOON-BEGIN
    pub fn send_raw_soon(node: &Rc<RefCell<RelayNode>>, messages: Vec<(Vec<u8>, Addr)>) {
        if messages.is_empty() || node.borrow().sock.is_none() {
            return;
        }
        let task_node = node.clone();
        let task = tokio::task::spawn_local(async move {
            for (payload, addr) in messages {
                let _ = RelayNode::send_datagram(&task_node, &payload, &addr).await;
            }
        });
        node.borrow_mut().tasks.push(task);
    }
    // TOKIO-SEND-RAW-SOON-END

    // -- socket plumbing --------------------------------------------------

    // TOKIO-MAKE-SOCKET-BEGIN
    async fn make_socket(bind_addr: &Addr) -> std::io::Result<Rc<tokio::net::UdpSocket>> {
        let addr = to_socket_addr(bind_addr)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "unparsable bind address"))?;
        // Mirrors Python's `_make_socket`: SO_REUSEADDR (so a restart can
        // rebind immediately) and a raised SO_RCVBUF (4MiB). The sender has
        // no pacing beyond the congestion window, so a multi-fragment
        // payload (a video segment can be dozens of fragments) can arrive
        // as a tight back-to-back burst; the default kernel receive buffer
        // is easily overrun by that burst while this event loop is still
        // decrypting/forwarding the previous cell, silently dropping
        // datagrams with no error anywhere -- which then looks like "loss"
        // to the congestion controller and triggers a multiplicative
        // backoff for traffic that was never actually lost on the wire.
        //
        // Also SO_REUSEPORT, so N
        // shard workers (see `allium-relay-cli`'s `main.rs`) can each bind
        // their own socket to this SAME bind_addr. The kernel then
        // load-balances incoming datagrams across the N sockets by a hash
        // of the peer address, so a given client connection -- and every
        // circuit on it -- consistently lands on the same worker for its
        // whole lifetime, with no cross-worker coordination or locking
        // ever needed. A single (non-sharded) caller binding once is
        // unaffected: SO_REUSEPORT only changes behavior when a second
        // socket actually binds the same address.
        use socket2::{Domain, Socket, Type};
        let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
        let sock2 = Socket::new(domain, Type::DGRAM, None)?;
        sock2.set_reuse_address(true)?;
        sock2.set_reuse_port(true)?;
        if let Err(e) = sock2.set_recv_buffer_size(1 << 22) {
            eprintln!(
                "allium: could not raise SO_RCVBUF ({e}); bursty transfers may drop cells under load"
            );
        }
        sock2.set_nonblocking(true)?;
        sock2.bind(&addr.into())?;
        let std_sock: std::net::UdpSocket = sock2.into();
        tokio::net::UdpSocket::from_std(std_sock).map(Rc::new)
    }
    // TOKIO-MAKE-SOCKET-END

    /// Bind the socket and start the background sweeper.
    // TOKIO-START-BEGIN
    pub async fn start(node: &Rc<RefCell<RelayNode>>, bind_addr: Addr) -> std::io::Result<Addr> {
        let sock = RelayNode::make_socket(&bind_addr).await?;
        let cleanup_interval = {
            let mut n = node.borrow_mut();
            n.sock = Some(sock);
            n.cleanup_interval
        };
        if cleanup_interval > 0.0 {
            let sweeper_node = node.clone();
            let task = tokio::task::spawn_local(async move { RelayNode::sweeper(sweeper_node).await });
            node.borrow_mut().tasks.push(task);
        }
        Ok(node.borrow().sockname().expect("just bound"))
    }
    // TOKIO-START-END

    /// Reclaim `keys_by_circuit` entries that never got a table row (see the
    /// module docs on `_keys_created_at` for why this exists). Pure/sync:
    /// unlike the sweeper's `sleep` loop around it, this itself touches no
    /// tokio API.
    fn reclaim_orphaned_keys(&mut self) -> usize {
        if self.keys_created_at.is_empty() {
            return 0;
        }
        let limit = self.table.idle_timeout;
        let t = now();
        let orphaned: Vec<CircuitKeyTuple> = self
            .keys_created_at
            .iter()
            .filter(|(key, created_at)| t - **created_at > limit && !self.table.by_key.contains_key(*key))
            .map(|(k, _)| k.clone())
            .collect();
        for key in &orphaned {
            self.keys_by_circuit.remove(key);
            self.keys_created_at.remove(key);
        }
        orphaned.len()
    }

    /// Drop idle circuits on a timer, so state cannot grow without bound.
    // TOKIO-SWEEPER-BEGIN
    async fn sweeper(node: Rc<RefCell<RelayNode>>) {
        loop {
            let (closing, interval) = {
                let n = node.borrow();
                (n.closing, n.cleanup_interval)
            };
            if closing {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_secs_f64(interval.max(0.0))).await;
            let mut n = node.borrow_mut();
            if n.closing {
                return;
            }
            let expired = n.table.expire_idle(None);
            for entry in &expired {
                n.keys_by_circuit.remove(&entry.key);
                n.keys_created_at.remove(&entry.key);
                // This sweeper used
                // to expire a circuit without ever firing `forget_hook`,
                // even though `RelayNode::forget_circuit` (the
                // explicit-DESTROY path) always does. `SocksExit`'s hook
                // closes the circuit's exit streams and prunes its
                // hidden-service state; without this, an idle-timed-out
                // (as opposed to explicitly destroyed) circuit's exit
                // sockets just stayed open forever. `table.expire_idle`
                // already removed the row itself (unlike `forget_circuit`'s
                // `table.close`, which only marks it closed), so this
                // mirrors the rest of `forget_circuit`'s side effects
                // instead of calling it directly.
                n.pending_backward_tokens.remove(&entry.key);
                if let Some(hook) = n.forget_hook.as_mut() {
                    hook(&entry.key);
                }
            }
            n.stats.expired_circuits += expired.len() as u64;
            let reclaimed = n.reclaim_orphaned_keys();
            n.stats.expired_orphan_keys += reclaimed as u64;
        }
    }
    // TOKIO-SWEEPER-END

    /// Receive datagrams and dispatch them until cancelled/`stop()`.
    // TOKIO-SERVE-LOOP-BEGIN
    // `pub(crate)`, not private: `RelayNode::run` (`start` + this +
    // `stop`) never returns the bound port, which every loopback-UDP
    // integration test (see `relay.rs`'s own 2-hop `EXTEND` test and
    // `socksproxy.rs`'s 3-hop CONNECT test) needs back before it can wire
    // up the next hop or a `CircuitBuilder` -- so those tests call `start`
    // then spawn this directly, exactly like `run` does internally.
    // Round J: widened from `pub(crate)` to `pub` so `allium-cli`'s own
    // integration tests (`hs.rs`, a different crate) can drive several
    // `RelayNode`s concurrently on one `LocalSet` the same way this
    // crate's own `socksproxy.rs`/`relay.rs` loopback tests already do --
    // `RelayNode::run` (already `pub`) bundles `start` + this + `stop`,
    // but a caller that needs the bound ephemeral address back from
    // `start` *before* serving (every loopback test in this codebase
    // does, guard/middle/exit addresses are needed to wire up the next
    // hop) has to call this separately. No behavior change.
    pub async fn serve_loop(node: Rc<RefCell<RelayNode>>) {
        loop {
            if node.borrow().closing {
                return;
            }
            let sock_present = node.borrow().sock.is_some();
            if !sock_present {
                return;
            }
            let mut buf = [0u8; CELL_SIZE];
            // The `Rc<UdpSocket>` handle is cloned out from behind a
            // short-lived `RefCell` borrow (the borrow itself ends here,
            // immediately), then kept alive in this local for the `.await`
            // below -- `recv_from` borrows `sock`, so `sock` must outlive
            // the future, exactly the same trap `send_datagram` documents.
            let sock = node.borrow().sock.clone().expect("checked above");
            match sock.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    let peer_addr: Addr = (peer.ip().to_string(), peer.port());
                    let datagram = &buf[..n];
                    let action = node.borrow_mut().handle_datagram(datagram, &peer_addr);
                    match action {
                        DatagramAction::Nothing => {}
                        DatagramAction::Reply(bytes, addr) => {
                            let _ = RelayNode::send_datagram(&node, &bytes, &addr).await;
                        }
                        // None of
                        // these three `JoinHandle`s are pushed into
                        // `node.tasks` any more. `tasks` was only ever
                        // drained in `stop()`, so for the life of the
                        // process it grew by one entry -- each holding its
                        // task's full future, not just the handle's own 8
                        // bytes -- per cell handled here, with no cap.
                        // Under completely ordinary use (backward traffic
                        // for `ScheduleRelayBackward`/`ScheduleRelayExtendedBackward`,
                        // a legitimate EXTEND for `ScheduleExtend`) that is
                        // already unbounded growth; `Command::Relay`/
                        // `Connected`/`Extended` cells for an unknown
                        // circuit used to make it worse still (fixed just
                        // above, in `handle_datagram`, by dropping those
                        // before ever reaching here) since nothing but
                        // UDP reachability was needed to send them. Not
                        // storing the handle doesn't cancel the task --
                        // dropping a `JoinHandle` detaches it, and it keeps
                        // running to completion in the background exactly
                        // as before -- it just stops retaining its
                        // allocation forever afterward. `tasks` remains for
                        // the sweeper and other long-lived background
                        // tasks, which really do need `stop()` to cancel
                        // them.
                        DatagramAction::ScheduleExtend { key, target_addr, create_body } => {
                            let n2 = node.clone();
                            let _task = tokio::task::spawn_local(async move {
                                RelayNode::extend_circuit(n2, key, target_addr, create_body).await;
                            });
                        }
                        DatagramAction::ScheduleRelayExtendedBackward { cell, peer_addr } => {
                            let n2 = node.clone();
                            let _task = tokio::task::spawn_local(async move {
                                RelayNode::relay_extended_backward(n2, cell, peer_addr).await;
                            });
                        }
                        DatagramAction::ScheduleRelayBackward { command, cell, peer_addr } => {
                            let n2 = node.clone();
                            let _task = tokio::task::spawn_local(async move {
                                RelayNode::relay_backward(n2, command, cell, peer_addr).await;
                            });
                        }
                        DatagramAction::NatMessage(datagram) => {
                            let mut n = node.borrow_mut();
                            if let Some(handler) = n.nat_handler.as_mut() {
                                handler(&datagram, &peer_addr);
                            }
                        }
                    }
                }
                Err(_) => {
                    if node.borrow().closing {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
    }
    // TOKIO-SERVE-LOOP-END

    /// Bind and serve until `stop()` is called.
    // TOKIO-RUN-BEGIN
    pub async fn run(node: Rc<RefCell<RelayNode>>, bind_addr: Addr) {
        if RelayNode::start(&node, bind_addr).await.is_err() {
            return;
        }
        RelayNode::serve_loop(node.clone()).await;
        RelayNode::stop(&node).await;
    }
    // TOKIO-RUN-END

    /// Cancel background tasks and close the socket. Safe to call twice.
    // TOKIO-STOP-BEGIN
    pub async fn stop(node: &Rc<RefCell<RelayNode>>) {
        node.borrow_mut().closing = true;
        let tasks: Vec<tokio::task::JoinHandle<()>> = std::mem::take(&mut node.borrow_mut().tasks);
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        node.borrow_mut().sock = None;
    }
    // TOKIO-STOP-END

    // -- introspection ------------------------------------------------------

    pub fn describe_table(&self) -> String {
        let mut entries: Vec<&CircuitEntry> = self.table.snapshot();
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        let mut lines = vec![format!("{} circuit table ({} live)", self.node_name, self.table.live_count())];
        if entries.is_empty() {
            lines.push("  (empty)".to_string());
        } else {
            for e in entries {
                lines.push(format!("  {e:?}"));
            }
        }
        lines.join("\n")
    }
}

impl fmt::Debug for RelayNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RelayNode(name={:?}, bind={:?}, circuits={}, {})",
            self.node_name,
            self.sockname(),
            self.table.live_count(),
            self.stats
        )
    }
}

/// Bind a [`RelayNode`] and serve until `stop()` is called -- convenience
/// entry point for a standalone relay process.
// TOKIO-SERVE-FOREVER-BEGIN
pub async fn serve_forever(bind_addr: Addr, node_name: String, options: RelayNodeOptions) -> Result<(), RelayError> {
    let mut options = options;
    options.node_name = node_name;
    let node = Rc::new(RefCell::new(RelayNode::new(options)?));
    RelayNode::run(node, bind_addr).await;
    Ok(())
}
// TOKIO-SERVE-FOREVER-END

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_ADDR: (&str, u16) = ("127.0.0.1", 40000);
    const GUARD_ADDR: (&str, u16) = ("127.0.0.1", 9001);
    const MIDDLE_ADDR: (&str, u16) = ("127.0.0.1", 9002);
    const EXIT_ADDR: (&str, u16) = ("127.0.0.1", 9003);
    const CIRCUIT: u32 = 0x0A0B0C0D;

    fn addr(a: (&str, u16)) -> Addr {
        (a.0.to_string(), a.1)
    }
    fn hop() -> OnionCrypto {
        OnionCrypto::with_defaults("guard", rand_key()).unwrap()
    }
    fn rand_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        k
    }

    #[test]
    fn test_requires_a_route_or_exit_flag() {
        let h = hop();
        let e = CircuitEntry::new((CLIENT_ADDR.0.to_string(), CLIENT_ADDR.1, CIRCUIT), h, CircuitEntryOptions::default());
        assert!(e.is_err());
        let h2 = hop();
        let ok = CircuitEntry::new(
            (CLIENT_ADDR.0.to_string(), CLIENT_ADDR.1, CIRCUIT),
            h2,
            CircuitEntryOptions { is_exit: true, ..Default::default() },
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn test_properties() {
        let h = hop();
        let entry = CircuitEntry::new(
            (CLIENT_ADDR.0.to_string(), CLIENT_ADDR.1, CIRCUIT),
            h,
            CircuitEntryOptions { hop_index: 1, outgoing_addr: Some(addr(MIDDLE_ADDR)), outgoing_circuit_id: Some(0x9999), ..Default::default() },
        )
        .unwrap();
        assert_eq!(entry.incoming_addr(), addr(CLIENT_ADDR));
        assert_eq!(entry.incoming_circuit_id(), CIRCUIT);
        assert_eq!(entry.outgoing_addr, Some(addr(MIDDLE_ADDR)));
        assert_eq!(entry.outgoing_circuit_id, 0x9999);
        assert_eq!(entry.state, STATE_PENDING);
        assert!(!entry.is_exit);
        assert!(entry.age() >= 0.0);
        assert!(entry.idle() >= 0.0);
    }

    /// Regression test (acceptance
    /// criterion: "no return-path cell's cleartext header equals a fixed
    /// per-circuit value"). Every backward reply used to seal with the
    /// fixed value 0, so its wire bytes were identical on every reply for
    /// a circuit's whole life. `next_backward_seq` must advance so two
    /// consecutive backward cells produce different wire header bytes.
    #[test]
    fn test_backward_seq_advances_so_consecutive_replies_differ_on_the_wire() {
        let mut entry = CircuitEntry::new(
            (CLIENT_ADDR.0.to_string(), CLIENT_ADDR.1, CIRCUIT),
            hop(),
            CircuitEntryOptions { is_exit: true, ..Default::default() },
        )
        .unwrap();

        assert_eq!(entry.backward_seq, 0, "starts at 0, same as the old fixed value -- the fix is that it advances");
        let first = entry.next_backward_seq();
        let second = entry.next_backward_seq();
        let third = entry.next_backward_seq();
        assert_eq!([first, second, third], [0, 1, 2]);

        // The actual wire-visible check: two backward cells sealed with
        // these two different seq values must produce different header
        // bytes 0..4 -- unlike the old fixed 0, which produced the exact
        // same bytes (the PRP/mask output for input 0) on every reply.
        let sealed_a = entry.hop.seal_payload(b"reply-a", first, entry.incoming_addr(), Some(crate::layer::Kind::PAYLOAD), None).unwrap();
        let sealed_b = entry.hop.seal_payload(b"reply-b", second, entry.incoming_addr(), Some(crate::layer::Kind::PAYLOAD), None).unwrap();
        assert_ne!(&sealed_a[0..4], &sealed_b[0..4], "consecutive backward cells must not share a fixed wire seq");
    }

    #[test]
    fn test_defaults_outgoing_id_to_incoming() {
        let h = hop();
        let entry = CircuitEntry::new(
            (CLIENT_ADDR.0.to_string(), CLIENT_ADDR.1, CIRCUIT),
            h,
            CircuitEntryOptions { outgoing_addr: Some(addr(MIDDLE_ADDR)), ..Default::default() },
        )
        .unwrap();
        assert_eq!(entry.outgoing_circuit_id, CIRCUIT);
    }

    #[test]
    fn test_equality_by_key() {
        let a = CircuitEntry::new((CLIENT_ADDR.0.to_string(), CLIENT_ADDR.1, 7), hop(), CircuitEntryOptions { is_exit: true, ..Default::default() }).unwrap();
        let b = CircuitEntry::new((CLIENT_ADDR.0.to_string(), CLIENT_ADDR.1, 7), hop(), CircuitEntryOptions { is_exit: true, ..Default::default() }).unwrap();
        assert_eq!(a, b);
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h1 = DefaultHasher::new();
        a.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        b.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn test_repr_has_no_key_material() {
        let entry = CircuitEntry::new((CLIENT_ADDR.0.to_string(), CLIENT_ADDR.1, 7), hop(), CircuitEntryOptions { is_exit: true, ..Default::default() }).unwrap();
        let text = format!("{entry:?}");
        assert!(!text.contains(&hex_encode(&entry.hop.layer.mac_key)));
        assert!(text.contains("exit"));
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn make_table() -> CircuitTable {
        CircuitTable::new(60.0, 4)
    }
    fn make_entry(circuit_id: u32, outgoing: (&str, u16), is_exit: bool, out_id: Option<u32>) -> CircuitEntry {
        CircuitEntry::new(
            (CLIENT_ADDR.0.to_string(), CLIENT_ADDR.1, circuit_id),
            hop(),
            CircuitEntryOptions { outgoing_addr: if is_exit { None } else { Some(addr(outgoing)) }, outgoing_circuit_id: out_id, is_exit, ..Default::default() },
        )
        .unwrap()
    }

    #[test]
    fn test_lookup_by_incoming_tuple() {
        let mut t = make_table();
        t.add(make_entry(1, GUARD_ADDR, false, None)).unwrap();
        assert_eq!(t.get(&addr(CLIENT_ADDR), 1).unwrap().incoming_circuit_id(), 1);
    }

    #[test]
    fn test_lookup_is_keyed_on_the_peer_address() {
        let mut t = make_table();
        t.add(make_entry(1, GUARD_ADDR, false, None)).unwrap();
        assert!(t.get(&("127.0.0.1".to_string(), 40001), 1).is_err());
    }

    #[test]
    fn test_unknown_circuit_raises() {
        let t = make_table();
        assert!(t.get(&addr(CLIENT_ADDR), 12345).is_err());
        assert!(t.find(&addr(CLIENT_ADDR), 12345).is_none());
    }

    #[test]
    fn test_closed_circuit_is_not_found() {
        let mut t = make_table();
        let key;
        {
            let e = t.add(make_entry(1, GUARD_ADDR, false, None)).unwrap();
            key = e.key.clone();
        }
        t.close(&key);
        assert!(t.get(&addr(CLIENT_ADDR), 1).is_err());
    }

    #[test]
    fn test_outgoing_index() {
        let mut t = make_table();
        t.add(make_entry(1, MIDDLE_ADDR, false, Some(0x55))).unwrap();
        let found = t.entry_for_outgoing(&addr(MIDDLE_ADDR), 0x55);
        assert!(found.is_some());
        assert_eq!(found.unwrap().incoming_circuit_id(), 1);
        assert!(t.entry_for_outgoing(&addr(MIDDLE_ADDR), 0x56).is_none());
    }

    #[test]
    fn test_remove_cleans_both_indexes() {
        let mut t = make_table();
        t.add(make_entry(1, MIDDLE_ADDR, false, Some(0x55))).unwrap();
        t.remove(&(CLIENT_ADDR.0.to_string(), CLIENT_ADDR.1, 1));
        assert!(t.entry_for_outgoing(&addr(MIDDLE_ADDR), 0x55).is_none());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn test_replace_keeps_indexes_consistent() {
        let mut t = make_table();
        t.add(make_entry(1, MIDDLE_ADDR, false, Some(0x55))).unwrap();
        t.add(make_entry(1, EXIT_ADDR, false, Some(0x66))).unwrap();
        assert_eq!(t.len(), 1);
        assert!(t.entry_for_outgoing(&addr(MIDDLE_ADDR), 0x55).is_none());
        assert!(t.entry_for_outgoing(&addr(EXIT_ADDR), 0x66).is_some());
    }

    #[test]
    fn test_capacity_limit() {
        let mut t = make_table();
        for i in 0..4u32 {
            t.add(make_entry(i + 1, GUARD_ADDR, false, None)).unwrap();
        }
        assert!(t.add(make_entry(99, GUARD_ADDR, false, None)).is_err());
    }

    #[test]
    fn test_replacing_at_capacity_is_allowed() {
        let mut t = make_table();
        for i in 0..4u32 {
            t.add(make_entry(i + 1, GUARD_ADDR, false, None)).unwrap();
        }
        t.add(make_entry(1, GUARD_ADDR, false, None)).unwrap();
        assert_eq!(t.len(), 4);
    }

    #[test]
    fn test_allocate_outgoing_id_honours_a_free_preference() {
        let t = make_table();
        assert_eq!(t.allocate_outgoing_id(&addr(MIDDLE_ADDR), Some(0x1234)).unwrap(), 0x1234);
    }

    #[test]
    fn test_allocate_outgoing_id_avoids_a_collision() {
        let mut t = make_table();
        t.add(make_entry(1, MIDDLE_ADDR, false, Some(0x1234))).unwrap();
        assert_ne!(t.allocate_outgoing_id(&addr(MIDDLE_ADDR), Some(0x1234)).unwrap(), 0x1234);
    }

    #[test]
    fn test_allocate_outgoing_id_is_per_hop() {
        let mut t = make_table();
        t.add(make_entry(1, MIDDLE_ADDR, false, Some(0x1234))).unwrap();
        assert_eq!(t.allocate_outgoing_id(&addr(EXIT_ADDR), Some(0x1234)).unwrap(), 0x1234);
    }

    #[test]
    fn test_expire_idle() {
        let mut t = make_table();
        let key;
        {
            let entry = t.add(make_entry(1, GUARD_ADDR, false, None)).unwrap();
            key = entry.key.clone();
        }
        t.by_key.get_mut(&key).unwrap().last_seen -= 1000.0;
        let expired = t.expire_idle(None);
        assert_eq!(expired.iter().map(|e| e.incoming_circuit_id()).collect::<Vec<_>>(), vec![1]);
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn test_expire_idle_keeps_recent_circuits() {
        let mut t = make_table();
        t.add(make_entry(1, GUARD_ADDR, false, None)).unwrap();
        assert!(t.expire_idle(None).is_empty());
        assert_eq!(t.len(), 1);
    }

    /// A circuit touched right up until the
    /// moment of the check -- so `idle()` never trips the idle-based check
    /// above -- still gets swept once `max_age` is configured and the
    /// circuit has actually existed longer than that, regardless of how
    /// busy it's been. `max_age` defaults to `None` (see
    /// `test_expire_idle_keeps_recent_circuits` above, which never sets
    /// it and is unaffected).
    #[test]
    fn test_expire_idle_also_evicts_by_max_age_even_when_busy() {
        let mut t = make_table();
        t.max_age = Some(500.0);
        let key;
        {
            let entry = t.add(make_entry(1, GUARD_ADDR, false, None)).unwrap();
            key = entry.key.clone();
        }
        // Old, but not idle: only `created_at` moves, `last_seen` stays
        // "now", simulating a circuit that has had continuous traffic.
        t.by_key.get_mut(&key).unwrap().created_at -= 1000.0;
        let expired = t.expire_idle(None);
        assert_eq!(expired.iter().map(|e| e.incoming_circuit_id()).collect::<Vec<_>>(), vec![1]);
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn test_expire_idle_keeps_young_circuits_when_max_age_is_set() {
        let mut t = make_table();
        t.max_age = Some(500.0);
        t.add(make_entry(1, GUARD_ADDR, false, None)).unwrap();
        assert!(t.expire_idle(None).is_empty());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn test_live_count_excludes_closed() {
        let mut t = make_table();
        let key;
        {
            let e = t.add(make_entry(1, GUARD_ADDR, false, None)).unwrap();
            key = e.key.clone();
        }
        assert_eq!(t.live_count(), 1);
        t.close(&key);
        assert_eq!(t.live_count(), 0);
    }

    #[test]
    fn test_clear() {
        let mut t = make_table();
        t.add(make_entry(1, GUARD_ADDR, false, None)).unwrap();
        t.clear();
        assert_eq!(t.len(), 0);
        assert!(t.by_outgoing.is_empty());
    }

    #[test]
    fn test_repr() {
        let mut t = make_table();
        t.add(make_entry(1, GUARD_ADDR, false, None)).unwrap();
        assert!(format!("{t:?}").contains("CircuitTable"));
    }

    #[test]
    fn test_dropped_sums_every_reason() {
        let mut stats = RelayStats::new();
        stats.dropped_bad_cell = 1;
        stats.dropped_not_data = 2;
        stats.dropped_unknown_circuit = 3;
        stats.dropped_mismatch = 4;
        stats.dropped_undecryptable = 5;
        assert_eq!(stats.dropped(), 15);
    }

    #[test]
    fn test_as_dict_lists_every_counter() {
        let data = RelayStats::new().as_dict();
        assert!(data.contains_key("datagrams_in"));
        assert!(data.contains_key("cells_forwarded"));
    }

    #[test]
    fn test_master_key_derives_both_keys_deterministically() {
        let master = [7u8; 32];
        let (x1, e1) = derive_relay_identity(&master).unwrap();
        let (x2, e2) = derive_relay_identity(&master).unwrap();
        assert_eq!(x1, x2);
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_derived_keys_are_independent() {
        let master = [7u8; 32];
        let (x, e) = derive_relay_identity(&master).unwrap();
        assert_ne!(x, e);
    }

    #[test]
    fn test_different_master_keys_give_different_identities() {
        let (x1, _) = derive_relay_identity(&[1u8; 32]).unwrap();
        let (x2, _) = derive_relay_identity(&[2u8; 32]).unwrap();
        assert_ne!(x1, x2);
    }

    #[test]
    fn test_hex_master_key_is_accepted() {
        let hex = "aa".repeat(32);
        let (x1, e1) = derive_relay_identity_hex(&hex).unwrap();
        let (x2, e2) = derive_relay_identity(&[0xaa; 32]).unwrap();
        assert_eq!(x1, x2);
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_short_master_key_rejected() {
        assert!(derive_relay_identity(&[1u8; 16]).is_err());
    }

    #[test]
    fn test_malformed_hex_master_key_rejected() {
        assert!(derive_relay_identity_hex("not-hex").is_err());
    }

    #[test]
    fn test_accept_seq_is_idempotent_and_counted() {
        let mut entry = CircuitEntry::new((CLIENT_ADDR.0.to_string(), CLIENT_ADDR.1, 1), hop(), CircuitEntryOptions { is_exit: true, ..Default::default() }).unwrap();
        assert!(entry.accept_seq(0));
        assert!(!entry.accept_seq(0));
        assert_eq!(entry.replayed, 1);
    }

    #[test]
    fn test_apply_ack_without_send_window_returns_zero() {
        let mut entry = CircuitEntry::new((CLIENT_ADDR.0.to_string(), CLIENT_ADDR.1, 1), hop(), CircuitEntryOptions { is_exit: true, ..Default::default() }).unwrap();
        assert_eq!(entry.apply_ack(&encode_ack(0, 0)).unwrap(), 0);
    }

    #[test]
    fn test_apply_ack_with_send_window_frees_cells() {
        let mut entry =
            CircuitEntry::new((CLIENT_ADDR.0.to_string(), CLIENT_ADDR.1, 1), hop(), CircuitEntryOptions { is_exit: true, send_window: true, ..Default::default() }).unwrap();
        entry.send_window.as_mut().unwrap().append(b"hello").unwrap();
        let freed = entry.apply_ack(&encode_ack(1, 0)).unwrap();
        assert_eq!(freed, 1);
        assert_eq!(entry.acked, 1);
    }

    #[test]
    fn test_feed_data_and_pending_ack_produce_wire_sized_acks() {
        let mut entry = CircuitEntry::new((CLIENT_ADDR.0.to_string(), CLIENT_ADDR.1, 1), hop(), CircuitEntryOptions { is_exit: true, ack_every: 1, ..Default::default() }).unwrap();
        let ack = entry.feed_data(0);
        assert_eq!(ack.len(), crate::layer::ACK_WIRE_SIZE); // 20: 32-bit cumulative + 128-bit bitmap
        let ack2 = entry.pending_ack();
        assert_eq!(ack2.len(), crate::layer::ACK_WIRE_SIZE);
    }

    // -- RelayNode: pure/synchronous coverage -------------------------------
    //
    // These exercise every method of `RelayNode` that does not touch
    // tokio: `register_circuit`/`choose_outgoing_id`, `handle_create`
    // (including the replay guard, the rate limiter, and the
    // backward-authenticity token echo), `forward_data` (DATA peel/forward,
    // ack, padding, payload delivery, and the EXTEND-scheduling decision),
    // `handle_datagram`'s dispatch, and `handle_ack`. Real CREATE cells are
    // built with `HandshakeClient::create_bytes`, exactly as `test_relay.py`
    // does, so these are full handshake-to-forward round trips, not
    // hand-faked cell bytes.

    fn node_options(name: &str) -> RelayNodeOptions {
        // This module's `handle_create` tests build a raw CREATE with no
        // cookie and expect an immediate CREATED -- the return-routability
        // challenge/retry cycle itself is covered separately by
        // `test_handle_create_requires_return_routability_by_default` and
        // `test_handle_create_challenge_then_retry_succeeds` below.
        RelayNodeOptions { node_name: name.to_string(), require_identity: false, require_return_routability: false, ..Default::default() }
    }

    fn client() -> crate::handshake::HandshakeClient {
        crate::handshake::HandshakeClient::new(
            "chacha20-poly1305".to_string(),
            None,
            5.0,
            None,
            true, // trust_first_use: this test has no PKI to pin against
            false,
            None,
            false,
            HandshakeOps::real(),
        )
        .unwrap()
    }

    #[test]
    fn test_register_circuit_needs_a_route_or_exit() {
        let mut node = RelayNode::new(node_options("guard")).unwrap();
        let err = node.register_circuit(&addr(CLIENT_ADDR), CIRCUIT, None, false, None, None, None);
        assert!(err.is_err());
    }

    #[test]
    fn test_register_circuit_rejects_without_a_handshake() {
        let mut node = RelayNode::new(node_options("guard")).unwrap();
        let result = node.register_circuit(&addr(CLIENT_ADDR), CIRCUIT, Some(&addr(MIDDLE_ADDR)), false, None, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_create_establishes_keys_and_auto_registers() {
        let mut node = RelayNode::new(node_options("guard")).unwrap();
        let mut c = client();
        let datagram = c.create_bytes(CIRCUIT, None).unwrap();
        let reply = node.handle_create(&datagram, &addr(CLIENT_ADDR));
        assert!(reply.is_some());
        assert_eq!(reply.unwrap().command, Command::Created);
        let key = (CLIENT_ADDR.0.to_string(), CLIENT_ADDR.1, CIRCUIT);
        assert!(node.keys_by_circuit.contains_key(&key));
        assert!(node.table.contains(&key));
        assert_eq!(node.stats.handshakes_created, 1);
    }

    #[test]
    fn test_default_options_require_return_routability() {
        // The CREATE rate limiter is keyed by a
        // spoofable UDP source address, so this must default on (matching
        // Python and both CLIs) rather than leaving it to each embedder.
        assert!(RelayNodeOptions::default().require_return_routability);
    }

    #[test]
    fn test_handle_create_requires_return_routability_by_default() {
        let mut options = node_options("guard");
        options.require_return_routability = true;
        let mut node = RelayNode::new(options).unwrap();
        let mut c = client();
        let datagram = c.create_bytes(CIRCUIT, None).unwrap();
        let reply = node.handle_create(&datagram, &addr(CLIENT_ADDR)).expect("a CHALLENGE, not a drop");
        assert_eq!(reply.command, Command::CreateChallenge);
        assert_eq!(node.stats.create_challenges_issued, 1);
        // The expensive handshake never ran: no keys were established.
        assert!(node.keys_by_circuit.is_empty());
    }

    #[test]
    fn test_handle_create_challenge_then_retry_succeeds() {
        let mut options = node_options("guard");
        options.require_return_routability = true;
        let mut node = RelayNode::new(options).unwrap();
        let mut c = client();

        let first = c.create_bytes(CIRCUIT, None).unwrap();
        let challenge = node.handle_create(&first, &addr(CLIENT_ADDR)).expect("challenge reply");
        assert_eq!(challenge.command, Command::CreateChallenge);
        let cookie = c.parse_challenge(&challenge.pack(), Some(CIRCUIT)).unwrap();

        let second = c.create_bytes(CIRCUIT, Some(&cookie)).unwrap();
        let reply = node.handle_create(&second, &addr(CLIENT_ADDR)).expect("handshake should now succeed");
        assert_eq!(reply.command, Command::Created);
        let key = (CLIENT_ADDR.0.to_string(), CLIENT_ADDR.1, CIRCUIT);
        assert!(node.keys_by_circuit.contains_key(&key));
        assert_eq!(node.stats.handshakes_created, 1);
    }

    #[test]
    fn test_handle_create_replay_is_rejected() {
        let mut node = RelayNode::new(node_options("guard")).unwrap();
        let mut c = client();
        let datagram = c.create_bytes(CIRCUIT, None).unwrap();
        assert!(node.handle_create(&datagram, &addr(CLIENT_ADDR)).is_some());
        // A byte-identical replay of the same CREATE must be dropped.
        assert!(node.handle_create(&datagram, &addr(CLIENT_ADDR)).is_none());
        assert_eq!(node.stats.dropped_replay, 1);
    }

    #[test]
    fn test_handle_create_rate_limited() {
        let mut options = node_options("guard");
        options.create_rate = 0.0001;
        options.create_burst = 1;
        let mut node = RelayNode::new(options).unwrap();
        let mut c1 = client();
        let mut c2 = client();
        let d1 = c1.create_bytes(CIRCUIT, None).unwrap();
        let d2 = c2.create_bytes(CIRCUIT + 1, None).unwrap();
        assert!(node.handle_create(&d1, &addr(CLIENT_ADDR)).is_some());
        // Same source IP, burst of 1: the second CREATE is throttled before
        // ever reaching the handshake.
        assert!(node.handle_create(&d2, &addr(CLIENT_ADDR)).is_none());
        assert_eq!(node.stats.dropped_create_rate_limited, 1);
    }

    #[test]
    fn test_handle_datagram_create_replies_created() {
        let mut node = RelayNode::new(node_options("guard")).unwrap();
        let mut c = client();
        let datagram = c.create_bytes(CIRCUIT, None).unwrap();
        match node.handle_datagram(&datagram, &addr(CLIENT_ADDR)) {
            DatagramAction::Reply(bytes, to) => {
                assert_eq!(to, addr(CLIENT_ADDR));
                let cell = Cell::unpack(&bytes, true).unwrap();
                assert_eq!(cell.command, Command::Created);
            }
            other => panic!("expected Reply, got {other:?}"),
        }
    }

    #[test]
    fn test_handle_datagram_wrong_size_is_dropped() {
        let mut node = RelayNode::new(node_options("guard")).unwrap();
        let short = vec![0u8; 10];
        assert_eq!(node.handle_datagram(&short, &addr(CLIENT_ADDR)), DatagramAction::Nothing);
        assert_eq!(node.stats.dropped_bad_cell, 1);
    }

    #[test]
    fn test_handle_datagram_nat_message_is_recognised() {
        let mut node = RelayNode::new(node_options("guard")).unwrap();
        let mut punch = b"ALNT".to_vec();
        punch.extend_from_slice(&[1, 2, 3]);
        match node.handle_datagram(&punch, &addr(CLIENT_ADDR)) {
            DatagramAction::NatMessage(bytes) => assert_eq!(bytes, punch),
            other => panic!("expected NatMessage, got {other:?}"),
        }
    }

    /// Complete a real CREATE/CREATED handshake between `node` and a fresh
    /// `HandshakeClient`, returning the client's derived keys (so a test can
    /// build a matching `OnionCrypto` for the client side of the circuit).
    fn establish(node: &mut RelayNode, peer: &Addr, circuit_id: u32) -> HandshakeKeys {
        let mut c = client();
        let datagram = c.create_bytes(circuit_id, None).unwrap();
        let reply = node.handle_create(&datagram, peer).expect("handshake should succeed");
        c.complete(&reply.pack(), Some(circuit_id)).expect("client should accept the CREATED reply")
    }

    /// A replayed cell must not
    /// refresh `last_seen` or bump `cells_in`/`bytes_in` -- otherwise an
    /// attacker who captured one valid cell could resubmit it forever,
    /// keeping the circuit's idle clock permanently reset and defeating
    /// `CircuitTable::expire_idle`'s idle-based reaping.
    #[test]
    fn test_forward_data_replay_does_not_refresh_liveness_or_counters() {
        let mut node = RelayNode::new(node_options("exit")).unwrap();
        let client_keys = establish(&mut node, &addr(CLIENT_ADDR), CIRCUIT);
        node.register_exit_circuit(&addr(CLIENT_ADDR), CIRCUIT, 0).unwrap();

        let mut client_hop = client_keys.to_onion_crypto("client", 0).unwrap();
        let sealed = client_hop.seal_payload(b"hello relay", 0, addr(EXIT_ADDR), None, None).unwrap();
        let cell = seal_into_cell(&sealed, CIRCUIT, Some(Command::Data)).unwrap();
        let packed = cell.pack();

        node.deliver_fn = Some(Box::new(|_key, _peeled, _payload| {}));
        node.forward_data(&packed, &addr(CLIENT_ADDR)).unwrap();

        let key: CircuitKeyTuple = (addr(CLIENT_ADDR).0.clone(), addr(CLIENT_ADDR).1, CIRCUIT);
        let (last_seen_after_first, cells_in_after_first, bytes_in_after_first) = {
            let entry = node.table.by_key.get(&key).unwrap();
            (entry.last_seen, entry.cells_in, entry.bytes_in)
        };

        // Resubmit the exact same cell -- a replay.
        let err = node.forward_data(&packed, &addr(CLIENT_ADDR)).unwrap_err();
        assert!(err.to_string().contains("already seen"));
        assert_eq!(node.stats.dropped_replay, 1);

        let entry = node.table.by_key.get(&key).unwrap();
        assert_eq!(entry.last_seen, last_seen_after_first, "a replayed cell must not refresh last_seen");
        assert_eq!(entry.cells_in, cells_in_after_first, "a replayed cell must not bump cells_in");
        assert_eq!(entry.bytes_in, bytes_in_after_first, "a replayed cell must not bump bytes_in");
    }

    /// A circuit whose outgoing
    /// hop is set without going through the EXTEND handshake -- the only
    /// way this currently happens is the dead `resolve_outgoing`/
    /// `set_next_hop_resolver` path, reproduced here directly via the
    /// same internal `CircuitEntry`/`table.add` mechanism that path uses,
    /// since nothing in this workspace wires it up end-to-end -- has no
    /// `outgoing_token`. A backward RELAY/CONNECTED/EXTENDED cell for
    /// such a circuit must now be rejected outright, not trusted just
    /// because its sender matches the (spoofable) outgoing (addr,
    /// circuit_id) pair.
    #[test]
    fn test_relay_backward_rejects_cells_for_a_token_less_routed_circuit() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("failed to start tokio runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async move {
            let key: CircuitKeyTuple = (addr(CLIENT_ADDR).0.clone(), addr(CLIENT_ADDR).1, CIRCUIT);
            let outgoing_addr = addr(("127.0.0.1", 9500));
            let outgoing_id = 0xF00Du32;

            let mut node = RelayNode::new(node_options("middle")).unwrap();
            let entry = CircuitEntry::new(
                key.clone(),
                hop(),
                CircuitEntryOptions {
                    hop_index: 0,
                    outgoing_addr: Some(outgoing_addr.clone()),
                    outgoing_circuit_id: Some(outgoing_id),
                    is_exit: false,
                    ..CircuitEntryOptions::default()
                },
            )
            .unwrap();
            assert!(entry.outgoing_token.is_none(), "precondition: exactly the token-less state resolve_outgoing leaves a circuit in");
            node.table.add(entry).unwrap();
            let node = Rc::new(RefCell::new(node));

            let forged_extended = Cell::with_command(outgoing_id, Command::Extended, vec![0u8; 16]).unwrap();
            let accepted = RelayNode::relay_extended_backward(node.clone(), forged_extended, outgoing_addr.clone()).await;
            assert!(!accepted, "a token-less routed circuit must reject a backward EXTENDED cell, not trust it");

            let forged_connected = Cell::with_command(outgoing_id, Command::Connected, vec![0u8; 16]).unwrap();
            let accepted2 = RelayNode::relay_backward(node.clone(), Command::Connected, forged_connected, outgoing_addr).await;
            assert!(!accepted2, "a token-less routed circuit must reject a backward CONNECTED cell, not trust it");

            assert_eq!(node.borrow().stats.dropped_bad_link_token, 2);
        });
    }

    /// DESTROY for a circuit whose
    /// entry has no `backward_token` at all must be refused, not honored
    /// unconditionally -- an off-path attacker spoofing `peer_addr` and
    /// guessing/observing `circuit_id` (neither is secret) must not be able
    /// to tear down such a circuit. The registered entry survives, exactly
    /// as if the forged DESTROY had never arrived.
    #[test]
    fn test_destroy_rejects_a_token_less_circuit_instead_of_honoring_it() {
        let mut node = RelayNode::new(node_options("guard")).unwrap();
        let key: CircuitKeyTuple = (addr(CLIENT_ADDR).0.clone(), addr(CLIENT_ADDR).1, CIRCUIT);
        let entry = CircuitEntry::new(key.clone(), hop(), CircuitEntryOptions { hop_index: 0, is_exit: true, ..CircuitEntryOptions::default() }).unwrap();
        assert!(entry.backward_token.is_none(), "precondition: no client-generated link token, exactly the state every real client-facing hop is in today");
        node.table.add(entry).unwrap();

        let forged_destroy = Cell::with_command(CIRCUIT, Command::Destroy, Vec::new()).unwrap();
        node.handle_datagram(&forged_destroy.pack(), &addr(CLIENT_ADDR));

        assert!(node.table.find(&addr(CLIENT_ADDR), CIRCUIT).is_some(), "an unauthenticated DESTROY on a token-less circuit must not tear it down");
        assert_eq!(node.stats.dropped_bad_link_token, 1);
    }

    /// The other half of the same fix: a circuit that *does* have a
    /// `backward_token` (the relay-to-relay EXTEND case) must still honor a
    /// correctly-authenticated DESTROY exactly as before -- this fix only
    /// closes the token-less gap, it does not regress the working case.
    #[test]
    fn test_destroy_honors_a_correctly_authenticated_circuit() {
        let mut node = RelayNode::new(node_options("guard")).unwrap();
        let key: CircuitKeyTuple = (addr(CLIENT_ADDR).0.clone(), addr(CLIENT_ADDR).1, CIRCUIT);
        let mut entry = CircuitEntry::new(key.clone(), hop(), CircuitEntryOptions { hop_index: 0, is_exit: true, ..CircuitEntryOptions::default() }).unwrap();
        let token = vec![7u8; LINK_TOKEN_SIZE];
        entry.backward_token = Some(token.clone());
        node.table.add(entry).unwrap();

        let authenticated_destroy = Cell::with_command(CIRCUIT, Command::Destroy, token).unwrap();
        node.handle_datagram(&authenticated_destroy.pack(), &addr(CLIENT_ADDR));

        assert!(node.table.find(&addr(CLIENT_ADDR), CIRCUIT).is_none(), "a correctly-authenticated DESTROY must still tear the circuit down");
    }

    #[test]
    fn test_forward_data_exit_delivers_payload() {
        let mut node = RelayNode::new(node_options("exit")).unwrap();
        let client_keys = establish(&mut node, &addr(CLIENT_ADDR), CIRCUIT);
        node.register_exit_circuit(&addr(CLIENT_ADDR), CIRCUIT, 0).unwrap();

        let mut client_hop = client_keys.to_onion_crypto("client", 0).unwrap();
        let sealed = client_hop.seal_payload(b"hello relay", 0, addr(EXIT_ADDR), None, None).unwrap();
        let cell = seal_into_cell(&sealed, CIRCUIT, Some(Command::Data)).unwrap();

        let delivered: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(Vec::new()));
        let sink = delivered.clone();
        node.deliver_fn = Some(Box::new(move |_key, _peeled, payload| {
            sink.borrow_mut().extend_from_slice(payload);
        }));

        let outcome = node.forward_data(&cell.pack(), &addr(CLIENT_ADDR)).unwrap();
        assert_eq!(outcome, ForwardOutcome::Nothing);
        assert_eq!(&*delivered.borrow(), b"hello relay");
        assert_eq!(node.stats.cells_delivered, 1);
    }

    #[test]
    fn test_forward_data_payload_at_non_exit_relay_is_rejected() {
        // A middle relay (registered with a next hop, not `is_exit`) must
        // refuse to honour a PAYLOAD layer -- accepting one would let a
        // client turn any relay into an exit merely by addressing it that
        // way, which is exactly the confused-deputy `register_circuit`'s
        // `is_exit` flag exists to prevent.
        let mut node = RelayNode::new(node_options("middle")).unwrap();
        let client_keys = establish(&mut node, &addr(CLIENT_ADDR), CIRCUIT);
        node.register_circuit(&addr(CLIENT_ADDR), CIRCUIT, Some(&addr(EXIT_ADDR)), false, Some(CIRCUIT), None, Some(0)).unwrap();

        let mut client_hop = client_keys.to_onion_crypto("client", 0).unwrap();
        let sealed = client_hop.seal_payload(b"through the middle", 0, addr(EXIT_ADDR), None, None).unwrap();
        let cell = seal_into_cell(&sealed, CIRCUIT, Some(Command::Data)).unwrap();

        let result = node.forward_data(&cell.pack(), &addr(CLIENT_ADDR));
        assert!(result.is_err());
        assert_eq!(node.stats.dropped_mismatch, 1);
    }

    #[test]
    fn test_forward_data_unknown_circuit_is_an_error() {
        let mut node = RelayNode::new(node_options("guard")).unwrap();
        let cell = Cell::with_command(CIRCUIT, Command::Data, vec![0u8; 32]).unwrap();
        let result = node.forward_data(&cell.pack(), &addr(CLIENT_ADDR));
        assert!(result.is_err());
        assert_eq!(node.stats.dropped_unknown_circuit, 1);
    }

    #[test]
    fn test_forward_data_extend_layer_is_scheduled_not_forwarded_inline() {
        // This test's whole point is exercising the
        // EXTEND scheduling path over the loopback test addresses above,
        // so it opts into `allow_private_extend` -- the same override a
        // real operator would use only for a loopback test network. See
        // `test_forward_data_extend_to_a_private_address_is_refused_by_default`
        // below for the coverage of the opposite (production) default.
        let mut options = node_options("guard");
        options.allow_private_extend = true;
        let mut node = RelayNode::new(options).unwrap();
        // `establish` (via `handle_create`'s `auto_register`) leaves the
        // circuit's entry unrouted -- no next hop yet -- which is exactly
        // the state an EXTEND is meant to resolve; registering it with a
        // route first would make `is_routed()` true and the EXTEND branch
        // would (correctly) refuse it as already routed.
        let client_keys = establish(&mut node, &addr(CLIENT_ADDR), CIRCUIT);

        let mut client_hop = client_keys.to_onion_crypto("client", 0).unwrap();
        let mut c2 = client();
        // The EXTEND layer's plaintext is the raw CREATE *body*, matching
        // what `_extend_circuit_inner` later feeds to `CreateBody::unpack`
        // -- not a full packed cell (which carries its own header).
        let create_datagram = c2.create_bytes(CIRCUIT + 1, None).unwrap();
        let create_body = Cell::unpack(&create_datagram, true).unwrap().payload;
        let sealed = client_hop
            .seal_payload(&create_body, 0, addr(MIDDLE_ADDR), Some(crate::layer::Kind::EXTEND), None)
            .unwrap();
        let cell = seal_into_cell(&sealed, CIRCUIT, Some(Command::Data)).unwrap();

        let outcome = node.forward_data(&cell.pack(), &addr(CLIENT_ADDR)).unwrap();
        match outcome {
            ForwardOutcome::NeedExtend { key, target_addr, .. } => {
                assert_eq!(key, (CLIENT_ADDR.0.to_string(), CLIENT_ADDR.1, CIRCUIT));
                assert_eq!(target_addr, addr(MIDDLE_ADDR));
            }
            other => panic!("expected NeedExtend, got {other:?}"),
        }
        // A second EXTEND on the same, now-pending, circuit must be refused
        // rather than starting a second concurrent round trip. A fresh seq
        // is used so the rejection is actually the `_extending` guard, not
        // an incidental replay-window drop of a byte-identical repeat.
        let sealed2 = client_hop
            .seal_payload(&create_body, 1, addr(MIDDLE_ADDR), Some(crate::layer::Kind::EXTEND), None)
            .unwrap();
        let cell2 = seal_into_cell(&sealed2, CIRCUIT, Some(Command::Data)).unwrap();
        let second = node.forward_data(&cell2.pack(), &addr(CLIENT_ADDR));
        assert!(second.is_err());
        assert_eq!(node.stats.dropped_mismatch, 1);
    }

    /// With the production default
    /// (`allow_private_extend: false`, from plain `node_options` with no
    /// override, unlike the two tests above), an EXTEND naming a private/
    /// loopback/link-local target must be refused before any CREATE is
    /// scheduled -- `test_forward_data_extend_layer_is_scheduled_not_forwarded_inline`
    /// above and `test_two_hop_extend_over_real_loopback_udp_sockets` below
    /// only succeed at all because they explicitly opt in.
    #[test]
    fn test_forward_data_extend_to_a_private_address_is_refused_by_default() {
        let mut node = RelayNode::new(node_options("guard")).unwrap();
        let client_keys = establish(&mut node, &addr(CLIENT_ADDR), CIRCUIT);

        let mut client_hop = client_keys.to_onion_crypto("client", 0).unwrap();
        let mut c2 = client();
        let create_datagram = c2.create_bytes(CIRCUIT + 1, None).unwrap();
        let create_body = Cell::unpack(&create_datagram, true).unwrap().payload;
        let sealed = client_hop
            .seal_payload(&create_body, 0, addr(MIDDLE_ADDR), Some(crate::layer::Kind::EXTEND), None)
            .unwrap();
        let cell = seal_into_cell(&sealed, CIRCUIT, Some(Command::Data)).unwrap();

        let result = node.forward_data(&cell.pack(), &addr(CLIENT_ADDR));
        assert!(result.is_err(), "EXTEND to a loopback target must be refused by default");
        assert_eq!(node.stats.dropped_mismatch, 1);

        // The refusal above latches -- a second EXTEND
        // on the same circuit (to a different-looking target) is refused
        // too, rather than letting the client keep probing new targets.
        let sealed2 = client_hop
            .seal_payload(&create_body, 1, addr(EXIT_ADDR), Some(crate::layer::Kind::EXTEND), None)
            .unwrap();
        let cell2 = seal_into_cell(&sealed2, CIRCUIT, Some(Command::Data)).unwrap();
        let second = node.forward_data(&cell2.pack(), &addr(CLIENT_ADDR));
        assert!(second.is_err());
        assert_eq!(node.stats.dropped_mismatch, 2);
    }

    /// Once a directory is installed via
    /// `set_known_relay_addrs`, an EXTEND to an address that directory
    /// doesn't list is refused, on top of (here, with `allow_private_extend`
    /// set so the private/loopback check doesn't also fire and confound
    /// which check actually rejected it) the private/loopback filter.
    #[test]
    fn test_forward_data_extend_to_an_unlisted_address_is_refused_once_directory_is_known() {
        let mut options = node_options("guard");
        options.allow_private_extend = true;
        let mut node = RelayNode::new(options).unwrap();
        node.set_known_relay_addrs(Some(HashSet::from([addr(EXIT_ADDR)])));
        let client_keys = establish(&mut node, &addr(CLIENT_ADDR), CIRCUIT);

        let mut client_hop = client_keys.to_onion_crypto("client", 0).unwrap();
        let mut c2 = client();
        let create_datagram = c2.create_bytes(CIRCUIT + 1, None).unwrap();
        let create_body = Cell::unpack(&create_datagram, true).unwrap().payload;
        // MIDDLE_ADDR is not in the installed set (only EXIT_ADDR is).
        let sealed = client_hop
            .seal_payload(&create_body, 0, addr(MIDDLE_ADDR), Some(crate::layer::Kind::EXTEND), None)
            .unwrap();
        let cell = seal_into_cell(&sealed, CIRCUIT, Some(Command::Data)).unwrap();

        let result = node.forward_data(&cell.pack(), &addr(CLIENT_ADDR));
        assert!(result.is_err(), "EXTEND to an address missing from the known-relays set must be refused");
        assert_eq!(node.stats.dropped_mismatch, 1);
    }

    /// The mirror image of the test above: an EXTEND to an address that
    /// *is* in the installed set still proceeds to `NeedExtend` as usual.
    #[test]
    fn test_forward_data_extend_to_a_listed_address_is_allowed() {
        let mut options = node_options("guard");
        options.allow_private_extend = true;
        let mut node = RelayNode::new(options).unwrap();
        node.set_known_relay_addrs(Some(HashSet::from([addr(MIDDLE_ADDR)])));
        let client_keys = establish(&mut node, &addr(CLIENT_ADDR), CIRCUIT);

        let mut client_hop = client_keys.to_onion_crypto("client", 0).unwrap();
        let mut c2 = client();
        let create_datagram = c2.create_bytes(CIRCUIT + 1, None).unwrap();
        let create_body = Cell::unpack(&create_datagram, true).unwrap().payload;
        let sealed = client_hop
            .seal_payload(&create_body, 0, addr(MIDDLE_ADDR), Some(crate::layer::Kind::EXTEND), None)
            .unwrap();
        let cell = seal_into_cell(&sealed, CIRCUIT, Some(Command::Data)).unwrap();

        let outcome = node.forward_data(&cell.pack(), &addr(CLIENT_ADDR)).unwrap();
        match outcome {
            ForwardOutcome::NeedExtend { target_addr, .. } => assert_eq!(target_addr, addr(MIDDLE_ADDR)),
            other => panic!("expected NeedExtend, got {other:?}"),
        }
    }

    /// `require_known_relay_addrs`: with it
    /// set, an EXTEND is refused while `known_relay_addrs` is still
    /// `None` -- the process-just-started / refresher-never-ran window
    /// that previously fell open (any non-private target accepted)
    /// instead of closed.
    #[test]
    fn test_forward_data_extend_is_refused_before_directory_loads_when_required() {
        let mut options = node_options("guard");
        options.allow_private_extend = true;
        options.require_known_relay_addrs = true;
        let mut node = RelayNode::new(options).unwrap();
        // Deliberately never call set_known_relay_addrs.
        let client_keys = establish(&mut node, &addr(CLIENT_ADDR), CIRCUIT);

        let mut client_hop = client_keys.to_onion_crypto("client", 0).unwrap();
        let mut c2 = client();
        let create_datagram = c2.create_bytes(CIRCUIT + 1, None).unwrap();
        let create_body = Cell::unpack(&create_datagram, true).unwrap().payload;
        let sealed = client_hop
            .seal_payload(&create_body, 0, addr(MIDDLE_ADDR), Some(crate::layer::Kind::EXTEND), None)
            .unwrap();
        let cell = seal_into_cell(&sealed, CIRCUIT, Some(Command::Data)).unwrap();

        let result = node.forward_data(&cell.pack(), &addr(CLIENT_ADDR));
        assert!(result.is_err(), "EXTEND must be refused while no directory has ever been loaded and require_known_relay_addrs is set");
        assert_eq!(node.stats.dropped_mismatch, 1);
    }

    /// Once the directory has loaded (`set_known_relay_addrs` called at
    /// least once), `require_known_relay_addrs` behaves exactly like the
    /// existing `known_relay_addrs`-set checks above -- it only changes
    /// what happens in the still-`None` window, not the steady state.
    #[test]
    fn test_forward_data_extend_works_normally_once_directory_loads_when_required() {
        let mut options = node_options("guard");
        options.allow_private_extend = true;
        options.require_known_relay_addrs = true;
        let mut node = RelayNode::new(options).unwrap();
        node.set_known_relay_addrs(Some(HashSet::from([addr(MIDDLE_ADDR)])));
        let client_keys = establish(&mut node, &addr(CLIENT_ADDR), CIRCUIT);

        let mut client_hop = client_keys.to_onion_crypto("client", 0).unwrap();
        let mut c2 = client();
        let create_datagram = c2.create_bytes(CIRCUIT + 1, None).unwrap();
        let create_body = Cell::unpack(&create_datagram, true).unwrap().payload;
        let sealed = client_hop
            .seal_payload(&create_body, 0, addr(MIDDLE_ADDR), Some(crate::layer::Kind::EXTEND), None)
            .unwrap();
        let cell = seal_into_cell(&sealed, CIRCUIT, Some(Command::Data)).unwrap();

        let outcome = node.forward_data(&cell.pack(), &addr(CLIENT_ADDR)).unwrap();
        match outcome {
            ForwardOutcome::NeedExtend { target_addr, .. } => assert_eq!(target_addr, addr(MIDDLE_ADDR)),
            other => panic!("expected NeedExtend, got {other:?}"),
        }
    }

    /// The library's default (`require_known_relay_addrs: false`, the
    /// pre-existing `node_options` helper) must keep behaving exactly as
    /// before this hardening -- a caller with no directory at all still
    /// gets the permissive, check-off behavior, not a new refusal.
    #[test]
    fn test_forward_data_extend_default_options_stay_permissive_with_no_directory() {
        let mut options = node_options("guard");
        options.allow_private_extend = true;
        assert!(!options.require_known_relay_addrs, "default must remain false, unchanged by this hardening");
        let mut node = RelayNode::new(options).unwrap();
        let client_keys = establish(&mut node, &addr(CLIENT_ADDR), CIRCUIT);

        let mut client_hop = client_keys.to_onion_crypto("client", 0).unwrap();
        let mut c2 = client();
        let create_datagram = c2.create_bytes(CIRCUIT + 1, None).unwrap();
        let create_body = Cell::unpack(&create_datagram, true).unwrap().payload;
        let sealed = client_hop
            .seal_payload(&create_body, 0, addr(MIDDLE_ADDR), Some(crate::layer::Kind::EXTEND), None)
            .unwrap();
        let cell = seal_into_cell(&sealed, CIRCUIT, Some(Command::Data)).unwrap();

        let outcome = node.forward_data(&cell.pack(), &addr(CLIENT_ADDR)).unwrap();
        assert!(matches!(outcome, ForwardOutcome::NeedExtend { .. }), "no directory + require off must still allow EXTEND, matching pre-hardening behavior");
    }

    #[test]
    fn test_choose_outgoing_id_prefers_incoming_id_when_free() {
        let node = RelayNode::new(node_options("guard")).unwrap();
        let id = node.choose_outgoing_id(&addr(MIDDLE_ADDR), None, None, None, CIRCUIT).unwrap();
        assert_eq!(id, CIRCUIT);
    }

    #[test]
    fn test_choose_outgoing_id_reassigns_on_collision() {
        let mut node = RelayNode::new(node_options("guard")).unwrap();
        establish(&mut node, &addr(CLIENT_ADDR), CIRCUIT);
        node.register_circuit(&addr(CLIENT_ADDR), CIRCUIT, Some(&addr(MIDDLE_ADDR)), false, Some(CIRCUIT), None, Some(0)).unwrap();
        // The incoming id (CIRCUIT) is now taken at MIDDLE_ADDR by the
        // circuit above; a second client asking for the same id must be
        // reassigned rather than colliding.
        let id = node.choose_outgoing_id(&addr(MIDDLE_ADDR), None, None, None, CIRCUIT).unwrap();
        assert_ne!(id, CIRCUIT);
    }

    #[test]
    fn test_forget_circuit_drops_keys_too() {
        let mut node = RelayNode::new(node_options("guard")).unwrap();
        establish(&mut node, &addr(CLIENT_ADDR), CIRCUIT);
        let key = (CLIENT_ADDR.0.to_string(), CLIENT_ADDR.1, CIRCUIT);
        assert!(node.keys_by_circuit.contains_key(&key));
        node.forget_circuit(&addr(CLIENT_ADDR), CIRCUIT);
        assert!(!node.keys_by_circuit.contains_key(&key));
        assert_eq!(node.table.by_key.get(&key).unwrap().state, STATE_CLOSED);
    }

    #[test]
    fn test_handle_ack_unknown_circuit_is_dropped() {
        let mut node = RelayNode::new(node_options("guard")).unwrap();
        let cell = Cell::with_command(CIRCUIT, Command::Ack, vec![0u8; 8]).unwrap();
        node.handle_ack(&cell, &addr(CLIENT_ADDR));
        assert_eq!(node.stats.dropped_unknown_circuit, 1);
    }

    #[test]
    fn test_identity_fingerprint_is_16_hex_chars() {
        let node = RelayNode::new(node_options("guard")).unwrap();
        let fp = node.identity_fingerprint();
        assert_eq!(fp.len(), 16);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_describe_table_lists_registered_circuits() {
        let mut node = RelayNode::new(node_options("guard")).unwrap();
        establish(&mut node, &addr(CLIENT_ADDR), CIRCUIT);
        node.register_circuit(&addr(CLIENT_ADDR), CIRCUIT, Some(&addr(MIDDLE_ADDR)), false, Some(CIRCUIT), None, Some(0)).unwrap();
        let described = node.describe_table();
        assert!(described.contains("guard"));
        assert!(described.contains("1 live"));
    }

    #[test]
    fn test_reclaim_orphaned_keys_drops_stale_unregistered_keys() {
        let mut options = node_options("guard");
        options.idle_timeout = -1.0; // already expired the moment it's created
        options.auto_register = false; // CREATE succeeds but leaves no table row
        let mut node = RelayNode::new(options).unwrap();
        establish(&mut node, &addr(CLIENT_ADDR), CIRCUIT);
        let key = (CLIENT_ADDR.0.to_string(), CLIENT_ADDR.1, CIRCUIT);
        assert!(node.keys_by_circuit.contains_key(&key));
        assert!(!node.table.contains(&key));
        let reclaimed = node.reclaim_orphaned_keys();
        assert_eq!(reclaimed, 1);
        assert!(!node.keys_by_circuit.contains_key(&key));
    }

    /// Real, end-to-end, 2-hop `EXTEND`: a real [`crate::circuit::CircuitBuilder`]
    /// (client) talks over real loopback UDP sockets to two real, independently
    /// running [`RelayNode`]s (guard and middle) -- `add_hop` handshakes
    /// directly with the guard, then `extend` asks the guard to relay a CREATE
    /// to the middle and forward the CREATED reply back, exactly the path a
    /// live `client --authority`/`--guard`/`--middle`/`--exit` run drives.
    ///
    /// This is the test that should have existed before the port's second
    /// real-run bug ever shipped: `extend_once` (`circuit.rs`) used to hand
    /// the *raw* peeled CREATED body straight to `HandshakeClient::complete`,
    /// which always re-parses its argument as a wire-framed `Cell` (see
    /// `coerce_cell`'s docs) -- misreading the CREATED body's own leading
    /// bytes as a bogus cell-length header ("declared length 36020 exceeds
    /// the 504-byte payload buffer" in the user's real run). No existing
    /// test ever drove a real guard *relaying* an EXTEND to a real second
    /// hop -- every prior `RelayNode`/`CircuitBuilder` test either stayed at
    /// one hop or exercised `extend`'s pure rejection paths -- so this
    /// specific bug had nothing to catch it. It does now: this test fails
    /// with exactly the user's error message if `extend_once`'s fix is
    /// reverted (verified by hand).
    ///
    /// Both `RelayNode`s use `HandshakeOps::real()` (their only option --
    /// `RelayNode::new` does not take injectable ops), same as
    /// `CircuitBuilder::client_for`'s own `HandshakeOps::real()` -- so this
    /// exercises the *actual* production code path, not a test-only fake
    /// handshake. In this sandbox, "real" ed25519/x25519/AEAD crate bodies
    /// are stubbed (see this crate's stub-and-restore process)
    /// since crates.io is unreachable here, but that stub is applied
    /// uniformly to every `HandshakeOps::real()` call in the whole binary,
    /// so both relays and the client still do one mutually-consistent,
    /// genuine sign/verify/DH/AEAD round trip end-to-end over real sockets
    /// -- this bug (a pure wire-framing/cell-encoding bug, wholly
    /// independent of which crypto backend answers `HandshakeOps::real()`)
    /// reproduces and gets fixed identically either way. On a machine with
    /// real crates.io access this test exercises the actual
    /// `aes-gcm`/`chacha20poly1305`/`x25519-dalek`/`ed25519-dalek` crates
    /// with no changes needed.
    #[test]
    fn test_two_hop_extend_over_real_loopback_udp_sockets() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("failed to start tokio runtime");
        let local = tokio::task::LocalSet::new();
        let result: Result<(), String> = local.block_on(&rt, async move {
            // The guard here really does EXTEND to a
            // loopback address (`middle_addr`, below) -- that's the whole
            // point of this test -- so it needs the same opt-in a real
            // operator would set for a loopback test network.
            let mut guard_options = node_options("guard");
            guard_options.allow_private_extend = true;
            let guard = Rc::new(RefCell::new(RelayNode::new(guard_options).map_err(|e| e.to_string())?));
            let middle = Rc::new(RefCell::new(RelayNode::new(node_options("middle")).map_err(|e| e.to_string())?));

            // Bind both to ephemeral ("...:0") loopback ports and learn the
            // real, OS-assigned port back -- `RelayNode::start` (not `run`,
            // which also blocks forever serving) is exactly the bind-and-
            // report-back step `run` itself uses internally.
            let guard_addr = RelayNode::start(&guard, ("127.0.0.1".to_string(), 0)).await.map_err(|e| e.to_string())?;
            let middle_addr = RelayNode::start(&middle, ("127.0.0.1".to_string(), 0)).await.map_err(|e| e.to_string())?;

            // Drive both relays' real accept/dispatch loop concurrently, on
            // this same cooperative single-thread executor, for as long as
            // this test runs (dropped, not joined, when the test's async
            // block returns -- `RelayNode::stop` is for a graceful shutdown
            // a real process wants, not a unit test that simply ends).
            tokio::task::spawn_local(RelayNode::serve_loop(guard.clone()));
            tokio::task::spawn_local(RelayNode::serve_loop(middle.clone()));

            // `CircuitBuilder` is a deliberately synchronous, blocking-socket
            // client (see circuit.rs's module docs) -- exactly like
            // `allium-cli`'s own `spawn_circuit_pump`, drive it on a
            // dedicated OS thread so it can block on real socket reads while
            // this async task keeps both `RelayNode`s' event loops running
            // concurrently on the main thread.
            let (result_tx, result_rx) = std::sync::mpsc::channel::<Result<HandshakeKeys, String>>();
            std::thread::spawn(move || {
                let outcome = (|| -> Result<HandshakeKeys, String> {
                    let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
                    client_sock.set_read_timeout(Some(std::time::Duration::from_secs(5))).map_err(|e| e.to_string())?;
                    // `trust_first_use: true` -- this test has no PKI to
                    // pin against (same as `relay.rs`'s own `client()` test
                    // helper above); the bug this test targets is a pure
                    // wire-framing bug in `extend_once`, unrelated to
                    // identity pinning (see Round G's tests for that).
                    let mut builder = crate::circuit::CircuitBuilder::new(
                        &client_sock,
                        crate::onion::DEFAULT_CIPHER.to_string(),
                        5.0,
                        None,
                        true,
                        false,
                        crate::circuit::DEFAULT_RETRIES,
                        crate::circuit::DEFAULT_SEND_JITTER,
                        None,
                    )
                    .map_err(|e| e.to_string())?;
                    builder.add_hop("guard", guard_addr, None, None, None).map_err(|e| e.to_string())?;
                    let keys = builder.extend("middle", middle_addr, None, None, None).map_err(|e| e.to_string())?;
                    Ok(keys)
                })();
                let _ = result_tx.send(outcome);
            });

            // Poll for the client thread's result without blocking this
            // async task's own thread synchronously -- that thread is also
            // what's cooperatively driving both `RelayNode`s' `serve_loop`s,
            // so a real (synchronous) block here would starve them.
            loop {
                match result_rx.try_recv() {
                    Ok(Ok(keys)) => {
                        assert_eq!(keys.aead_key_fwd.len(), crate::crypto::KEY_SIZE, "middle-hop handshake keys look malformed");
                        assert_eq!(keys.aead_key_bwd.len(), crate::crypto::KEY_SIZE, "middle-hop handshake keys look malformed");
                        return Ok(());
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        return Err("client thread exited without a result".to_string());
                    }
                }
            }
        });
        result.expect("real 2-hop EXTEND over loopback UDP should succeed");
    }

    // -- #11: the cookie is checked on the first fragment, before anything is stored --

    fn cookie_options(name: &str) -> RelayNodeOptions {
        let mut options = node_options(name);
        options.require_return_routability = true;
        options
    }

    fn hybrid_client(kem_public: &[u8]) -> crate::handshake::HandshakeClient {
        crate::handshake::HandshakeClient::new(
            "chacha20-poly1305".to_string(),
            None,
            5.0,
            None,
            true,
            false,
            Some(kem_public.to_vec()),
            false,
            HandshakeOps::real(),
        )
        .unwrap()
    }

    fn reply_command(action: &DatagramAction) -> Option<Command> {
        match action {
            DatagramAction::Reply(bytes, _) => Cell::unpack(bytes, true).ok().map(|c| c.command),
            _ => None,
        }
    }

    fn reply_bytes(action: DatagramAction) -> Vec<u8> {
        match action {
            DatagramAction::Reply(bytes, _) => bytes,
            other => panic!("expected a reply, got {other:?}"),
        }
    }

    /// A CREATE that needs two fragments. Today a hybrid CREATE (1166 bytes) and even one with
    /// its link token (1182) fits in one cell, so only a forged message is this shape; the table
    /// that holds partial messages exists for it.
    fn multi_fragment_create(c: &mut crate::handshake::HandshakeClient, cookie: Option<&[u8; crate::handshake::COOKIE_SIZE]>) -> Vec<Vec<u8>> {
        let mut full = match c.create(CIRCUIT, cookie).unwrap() {
            crate::handshake::CreateMessage::Fragmented(m) => m.payload,
            _ => panic!("a hybrid client builds a fragmented CREATE"),
        };
        full.extend_from_slice(&[7u8; LINK_TOKEN_SIZE + 200]); // link token plus padding: over one fragment's room
        let cells = crate::createfrag::fragment_create(CIRCUIT, &full, None).unwrap();
        assert_eq!(cells.len(), 2);
        cells.iter().map(|c| c.pack()).collect()
    }

    #[test]
    fn a_first_fragment_without_a_cookie_is_challenged_and_stores_nothing() {
        let mut node = RelayNode::new(cookie_options("guard")).unwrap();
        let kem = node.handshake.kem_public.clone().expect("the relay has an ML-KEM key");
        let mut c = hybrid_client(&kem);
        let dgs = multi_fragment_create(&mut c, None);

        let first = node.handle_datagram(&dgs[0], &addr(CLIENT_ADDR));
        assert_eq!(reply_command(&first), Some(Command::CreateChallenge), "the very first fragment is answered");
        assert!(node.create_reassembler.is_empty(), "and nothing was stored for it");
        assert_eq!((node.stats.create_challenges_issued, node.stats.create_fragments_challenged), (1, 1));
        // the rest of that attempt arrives later and finds nothing to join
        for dg in &dgs[1..] {
            assert!(matches!(node.handle_datagram(dg, &addr(CLIENT_ADDR)), DatagramAction::Nothing));
        }
        assert!(node.create_reassembler.is_empty());
        assert!(node.keys_by_circuit.is_empty(), "no handshake ran");
    }

    #[test]
    fn a_hybrid_create_completes_after_the_challenge_with_one_challenge_only() {
        let mut node = RelayNode::new(cookie_options("guard")).unwrap();
        let kem = node.handshake.kem_public.clone().unwrap();
        let mut c = hybrid_client(&kem);
        let first = multi_fragment_create(&mut c, None);
        let challenge = reply_bytes(node.handle_datagram(&first[0], &addr(CLIENT_ADDR)));
        let cookie = c.parse_challenge(&challenge, Some(CIRCUIT)).unwrap();

        let second = multi_fragment_create(&mut c, Some(&cookie));
        let mut last = DatagramAction::Nothing;
        for (i, dg) in second.iter().enumerate() {
            last = node.handle_datagram(dg, &addr(CLIENT_ADDR));
            if i + 1 < second.len() {
                assert!(matches!(last, DatagramAction::Nothing), "fragment {i} only joins the entry");
                assert_eq!(node.create_reassembler.len(), 1);
            }
        }
        assert_eq!(reply_command(&last), Some(Command::Created), "the last fragment completes the handshake");
        assert!(node.create_reassembler.is_empty());
        assert_eq!(node.stats.handshakes_created, 1);
        assert_eq!(node.stats.create_challenges_issued, 1, "no second challenge: the cookie was good");
        assert!(node.keys_by_circuit.contains_key(&(CLIENT_ADDR.0.to_string(), CLIENT_ADDR.1, CIRCUIT)));
    }

    #[test]
    fn a_flood_of_forged_first_fragments_takes_no_table_space_and_cannot_push_out_a_handshake_in_progress() {
        let mut node = RelayNode::new(cookie_options("guard")).unwrap();
        let kem = node.handshake.kem_public.clone().unwrap();
        let mut c = hybrid_client(&kem);
        let no_cookie = multi_fragment_create(&mut c, None);
        let cookie = c.parse_challenge(&reply_bytes(node.handle_datagram(&no_cookie[0], &addr(CLIENT_ADDR))), Some(CIRCUIT)).unwrap();
        // the legitimate client is partway through: it has delivered its first fragment
        let with_cookie = multi_fragment_create(&mut c, Some(&cookie));
        assert!(matches!(node.handle_datagram(&with_cookie[0], &addr(CLIENT_ADDR)), DatagramAction::Nothing));
        assert_eq!(node.create_reassembler.len(), 1);

        // 5000 first fragments, each "from" a different forged address in a different network
        let mut replies = 0;
        for i in 0..5000u32 {
            let ip = format!("{}.{}.{}.1", 11 + (i / 65025), (i / 255) % 255, i % 255);
            if matches!(node.handle_datagram(&no_cookie[0], &addr((ip.as_str(), 4000))), DatagramAction::Reply(..)) {
                replies += 1;
            }
        }
        assert!(replies > 0, "forged senders are challenged (at their forged addresses)");
        assert_eq!(node.create_reassembler.len(), 1, "the flood stored nothing; the one real entry is still the only one");

        // the legitimate handshake finishes
        let mut last = DatagramAction::Nothing;
        for dg in &with_cookie[1..] {
            last = node.handle_datagram(dg, &addr(CLIENT_ADDR));
        }
        assert_eq!(reply_command(&last), Some(Command::Created), "the handshake in progress was not pushed out");
    }

    #[test]
    fn challenge_replies_are_capped_by_one_global_budget() {
        let mut node = RelayNode::new(cookie_options("guard")).unwrap();
        let kem = node.handshake.kem_public.clone().unwrap();
        let mut c = hybrid_client(&kem);
        let first = multi_fragment_create(&mut c, None)[0].clone();
        let mut replies = 0u64;
        let total = 4600u32;
        for i in 0..total {
            let ip = format!("{}.{}.{}.1", 11 + (i / 65025), (i / 255) % 255, i % 255);
            if matches!(node.handle_datagram(&first, &addr((ip.as_str(), 4000))), DatagramAction::Reply(..)) {
                replies += 1;
            }
        }
        assert!(replies >= ChallengeBudget::BURST as u64, "the burst is allowed: {replies}");
        assert!(replies < total as u64, "but not all of them: {replies}");
        assert_eq!(replies + node.stats.dropped_challenge_budget, total as u64, "every first fragment was either answered or counted");
        assert!(node.create_reassembler.is_empty());
    }

    #[test]
    fn the_challenge_budget_refills_at_its_rate_and_never_beyond_the_burst() {
        let mut b = ChallengeBudget::new(100.0);
        let burst = ChallengeBudget::BURST as usize;
        assert_eq!((0..burst).filter(|_| b.allow(100.0)).count(), burst);
        assert!(!b.allow(100.0), "spent");
        // half a second later: RATE / 2 tokens
        let half = (ChallengeBudget::RATE / 2.0) as usize;
        assert_eq!((0..half + 50).filter(|_| b.allow(100.5)).count(), half);
        // a long idle never banks more than the burst
        assert_eq!((0..burst + 500).filter(|_| b.allow(100_000.0)).count(), burst);
    }

    #[test]
    fn later_fragments_with_no_entry_are_dropped_silently_and_start_nothing() {
        let mut node = RelayNode::new(cookie_options("guard")).unwrap();
        let kem = node.handshake.kem_public.clone().unwrap();
        let mut c = hybrid_client(&kem);
        let dgs = multi_fragment_create(&mut c, None);
        for i in 0..3000u32 {
            let ip = format!("{}.{}.{}.1", 11 + (i / 65025), (i / 255) % 255, i % 255);
            for dg in &dgs[1..] {
                assert!(matches!(node.handle_datagram(dg, &addr((ip.as_str(), 4000))), DatagramAction::Nothing));
            }
        }
        assert!(node.create_reassembler.is_empty(), "orphan fragments never create an entry");
        assert_eq!(node.stats.create_challenges_issued, 0, "and earn no reply");
    }

    #[test]
    fn a_cookie_for_one_address_does_not_admit_another_address() {
        let mut node = RelayNode::new(cookie_options("guard")).unwrap();
        let kem = node.handshake.kem_public.clone().unwrap();
        let mut c = hybrid_client(&kem);
        let first = multi_fragment_create(&mut c, None);
        let cookie = c.parse_challenge(&reply_bytes(node.handle_datagram(&first[0], &addr(("203.0.113.5", 5000)))), Some(CIRCUIT)).unwrap();
        let with_cookie = multi_fragment_create(&mut c, Some(&cookie));
        // from the address it was issued for: admitted
        assert!(matches!(node.handle_datagram(&with_cookie[0], &addr(("203.0.113.5", 5000))), DatagramAction::Nothing));
        assert_eq!(node.create_reassembler.len(), 1);
        // the same bytes from a different address: challenged afresh, no entry
        let other = node.handle_datagram(&with_cookie[0], &addr(("198.51.100.9", 5000)));
        assert_eq!(reply_command(&other), Some(Command::CreateChallenge));
        assert_eq!(node.create_reassembler.len(), 1, "still only the first sender's entry");
    }

    #[test]
    fn a_first_fragment_too_short_to_hold_a_cookie_is_dropped() {
        let mut node = RelayNode::new(cookie_options("guard")).unwrap();
        let cells = crate::createfrag::fragment_create(CIRCUIT, &[0u8; 10], None).unwrap();
        assert!(matches!(node.handle_datagram(&cells[0].pack(), &addr(CLIENT_ADDR)), DatagramAction::Nothing));
        assert!(node.create_reassembler.is_empty());
        assert_eq!(node.stats.dropped_bad_cell, 1);
        assert_eq!(node.stats.create_challenges_issued, 0);
    }

    #[test]
    fn without_the_cookie_requirement_fragments_are_stored_exactly_as_before() {
        let mut node = RelayNode::new(node_options("guard")).unwrap(); // require_return_routability = false
        let kem = node.handshake.kem_public.clone().unwrap();
        let mut c = hybrid_client(&kem);
        let dgs = multi_fragment_create(&mut c, None);
        // even a non-first fragment starts an entry in this mode
        assert!(matches!(node.handle_datagram(&dgs[1], &addr(CLIENT_ADDR)), DatagramAction::Nothing));
        assert_eq!(node.create_reassembler.len(), 1);
        let mut last = DatagramAction::Nothing;
        for (i, dg) in dgs.iter().enumerate() {
            if i != 1 {
                last = node.handle_datagram(dg, &addr(CLIENT_ADDR));
            }
        }
        assert_eq!(reply_command(&last), Some(Command::Created));
        assert_eq!(node.stats.create_challenges_issued, 0);
    }

    #[test]
    fn a_clients_ordinary_single_fragment_hybrid_create_is_challenged_then_succeeds() {
        // The shape a real client sends today: the whole hybrid CREATE in one fragment.
        let mut node = RelayNode::new(cookie_options("guard")).unwrap();
        let kem = node.handshake.kem_public.clone().unwrap();
        let mut c = hybrid_client(&kem);
        let first = c.create_datagrams(CIRCUIT, None).unwrap();
        assert_eq!(first.len(), 1, "a direct hybrid CREATE is one fragment");
        let challenge = node.handle_datagram(&first[0], &addr(CLIENT_ADDR));
        assert_eq!(reply_command(&challenge), Some(Command::CreateChallenge));
        assert_eq!((node.stats.create_fragments_challenged, node.stats.handshakes_created), (1, 0));
        let cookie = c.parse_challenge(&reply_bytes(challenge), Some(CIRCUIT)).unwrap();
        let second = c.create_datagrams(CIRCUIT, Some(&cookie)).unwrap();
        let reply = node.handle_datagram(&second[0], &addr(CLIENT_ADDR));
        assert_eq!(reply_command(&reply), Some(Command::Created));
        assert_eq!((node.stats.create_challenges_issued, node.stats.handshakes_created), (1, 1));
        assert!(node.create_reassembler.is_empty());
    }
}
