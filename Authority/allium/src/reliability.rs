//! UDP reliability primitives: sequence windows, reordering, and SACK.
//!
//! Port of Python's `reliability.py`. Three problems this module solves, all
//! inherent to sending a stream over UDP:
//!
//! 1. **Reordering.** [`ReassemblyBuffer`] holds out-of-order items and
//!    releases them in sequence order.
//! 2. **Duplicates and replays.** [`ReplayWindow`] rejects anything already
//!    seen, or older than the window.
//! 3. **Loss.** [`SendWindow`] implements a minimal Selective Acknowledgment
//!    loop: a cumulative ack plus a bitmask of the holes after it,
//!    retransmitting on timeout and on duplicate acks.
//!
//! No external crate dependencies -- fully testable in this sandbox. Time is
//! represented as `f64` seconds since an arbitrary epoch (mirroring Python's
//! `time.monotonic()`), with an injectable clock closure for deterministic
//! tests, exactly like the Python originals.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

/// Sequence numbers are 32-bit unsigned, matching `LayerHeader.seq`.
pub const SEQ_MODULUS: u64 = 1u64 << 32;
/// How many sequence numbers a replay window tracks by default.
pub const DEFAULT_WINDOW: u32 = 1024;
/// Default retransmission timeout, in seconds.
pub const DEFAULT_RTO: f64 = 1.0;
/// Give up on a segment after this many retransmissions.
pub const DEFAULT_MAX_RETRIES: u32 = 5;
/// How many outstanding handshake requests a [`HandshakeReplayGuard`]
/// remembers by default.
pub const DEFAULT_HANDSHAKE_REPLAY_ENTRIES: usize = 4096;
/// How long, in seconds, a handshake request stays "seen" by default.
pub const DEFAULT_HANDSHAKE_REPLAY_TTL: f64 = 120.0;

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

/// Base class for reliability-layer errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReliabilityError {
    Generic(String),
    NothingToSend(String),
    SendBufferFull(SendBufferFullError),
}
impl fmt::Display for ReliabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReliabilityError::Generic(s) => write!(f, "{s}"),
            ReliabilityError::NothingToSend(s) => write!(f, "{s}"),
            ReliabilityError::SendBufferFull(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for ReliabilityError {}
fn generic(msg: impl Into<String>) -> ReliabilityError {
    ReliabilityError::Generic(msg.into())
}

/// Raised when the unacknowledged backlog exceeds the configured window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendBufferFullError {
    pub message: String,
}
impl fmt::Display for SendBufferFullError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for SendBufferFullError {}
impl From<SendBufferFullError> for ReliabilityError {
    fn from(e: SendBufferFullError) -> Self {
        ReliabilityError::SendBufferFull(e)
    }
}
/// Alias matching Python's `SendBufferFull` exception name.
pub type SendBufferFull = SendBufferFullError;

// --------------------------------------------------------------------------
// A growable bitset (backs `ReplayWindow`'s sliding bitmap)
// --------------------------------------------------------------------------

/// A fixed-capacity bitset supporting the shift-and-set operations
/// [`ReplayWindow`] needs, sized to exactly `bits` bits rather than a
/// single machine word.
///
/// `ReplayWindow`'s bitmap used to be a bare `u64`, but `window` (its width)
/// is caller-configurable and
/// defaults to [`DEFAULT_WINDOW`] (1024) -- `self.bitmap << distance` for
/// `distance` up to `window - 1` (here, up to 1023) shifts a `u64` by more
/// than its own bit width. Rust panics on that in debug builds ("attempt
/// to shift left with overflow") and, in release builds, the shift amount
/// is *not* clamped to zero the way this code's logic needs -- it silently
/// wraps to a small, wrong shift instead, corrupting replay-detection
/// state. Every real circuit hits this: `relay.rs`'s `CircuitEntry`
/// constructs its `ReplayWindow` from `CircuitEntryOptions::replay_window`,
/// which defaults to `DEFAULT_WINDOW`, and `accept_seq` (called on every
/// inbound DATA cell) drives it directly -- so any sequence gap of 64 or
/// more, which ordinary network reordering can produce, was reachable from
/// live traffic. This `Bitset` mirrors the Client crate's own
/// `reliability::Bitset` (already Python-cross-checked there), so `window`
/// values of any size behave correctly instead of only ones that
/// coincidentally fit in one machine word.
struct Bitset {
    words: Vec<u64>,
    bits: usize,
}

impl Bitset {
    fn new(bits: usize) -> Self {
        Bitset { words: vec![0u64; bits.div_ceil(64)], bits }
    }

    fn clear(&mut self) {
        for w in &mut self.words {
            *w = 0;
        }
    }

    fn get(&self, i: usize) -> bool {
        if i >= self.bits {
            return false;
        }
        (self.words[i / 64] >> (i % 64)) & 1 == 1
    }

    fn set(&mut self, i: usize) {
        if i < self.bits {
            self.words[i / 64] |= 1u64 << (i % 64);
        }
    }

    fn mask_to_bits(&mut self) {
        let full_words = self.bits / 64;
        let rem = self.bits % 64;
        if rem != 0 && full_words < self.words.len() {
            let mask = (1u64 << rem) - 1;
            self.words[full_words] &= mask;
        }
        let skip = full_words + usize::from(rem != 0);
        for w in self.words.iter_mut().skip(skip) {
            *w = 0;
        }
    }

    /// Shift left by `n` bits, dropping anything past capacity.
    fn shl_assign(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        if n >= self.bits {
            self.clear();
            return;
        }
        let word_shift = n / 64;
        let bit_shift = n % 64;
        let len = self.words.len();
        if bit_shift == 0 {
            for i in (0..len).rev() {
                self.words[i] = if i >= word_shift { self.words[i - word_shift] } else { 0 };
            }
        } else {
            for i in (0..len).rev() {
                let hi = if i >= word_shift { self.words[i - word_shift] << bit_shift } else { 0 };
                let lo = if i >= word_shift + 1 { self.words[i - word_shift - 1] >> (64 - bit_shift) } else { 0 };
                self.words[i] = hi | lo;
            }
        }
        self.mask_to_bits();
    }
}

// --------------------------------------------------------------------------
// Replay and duplicate suppression
// --------------------------------------------------------------------------

/// Sliding-window duplicate and replay detector.
///
/// Tracks the highest sequence number accepted plus a bitmap of the numbers
/// just below it. A number is accepted once; anything already in the
/// bitmap, or more than `window` behind the high-water mark, is rejected.
pub struct ReplayWindow {
    window: u32,
    high: u64,
    bitmap: Bitset,
    primed: bool,
    pub accepted: u64,
    pub rejected: u64,
}

impl ReplayWindow {
    pub fn new(window: u32) -> Result<ReplayWindow, ReliabilityError> {
        if window < 1 {
            return Err(generic(format!("window must be at least 1, got {window}")));
        }
        Ok(ReplayWindow { window, high: 0, bitmap: Bitset::new(window as usize), primed: false, accepted: 0, rejected: 0 })
    }

    pub fn with_defaults() -> ReplayWindow {
        ReplayWindow::new(DEFAULT_WINDOW).unwrap()
    }

    fn shift(&mut self, distance: u64) {
        if distance >= self.window as u64 {
            self.bitmap.clear();
        } else if distance > 0 {
            self.bitmap.shl_assign(distance as usize);
            self.bitmap.set(distance as usize - 1);
        }
    }

    /// Record `seq` and return whether it is new.
    pub fn accept(&mut self, seq: u64) -> bool {
        let seq = seq % SEQ_MODULUS;
        if !self.primed {
            self.primed = true;
            self.high = seq;
            self.bitmap.clear();
            self.accepted += 1;
            return true;
        }
        let offset = (seq as i128 - self.high as i128).rem_euclid(SEQ_MODULUS as i128) as u64;
        if offset == 0 {
            self.rejected += 1;
            return false;
        }
        if offset >= SEQ_MODULUS / 2 {
            let distance = SEQ_MODULUS - offset;
            if distance > self.window as u64 {
                self.rejected += 1;
                return false;
            }
            if self.bitmap.get(distance as usize - 1) {
                self.rejected += 1;
                return false;
            }
            self.bitmap.set(distance as usize - 1);
            self.accepted += 1;
            return true;
        }
        self.shift(offset);
        self.high = seq;
        self.accepted += 1;
        true
    }

    /// The highest sequence number accepted so far.
    pub fn high(&self) -> u64 {
        self.high
    }

    /// Return `true` if `seq` has already been accepted.
    pub fn seen(&self, seq: u64) -> bool {
        let seq = seq % SEQ_MODULUS;
        if !self.primed {
            return false;
        }
        let offset = (seq as i128 - self.high as i128).rem_euclid(SEQ_MODULUS as i128) as u64;
        if offset == 0 {
            return true;
        }
        if offset >= SEQ_MODULUS / 2 {
            let distance = SEQ_MODULUS - offset;
            if distance > self.window as u64 {
                return true;
            }
            return self.bitmap.get(distance as usize - 1);
        }
        false
    }
}

impl fmt::Display for ReplayWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReplayWindow(window={}, high={}, accepted={}, rejected={})", self.window, self.high, self.accepted, self.rejected)
    }
}

// --------------------------------------------------------------------------
// Handshake replay suppression
// --------------------------------------------------------------------------

/// An opaque, hashable identifier for a handshake request: `(peer_ip,
/// peer_port, circuit_id, client_public_key)` in Python; represented here as
/// a `Vec<u8>` key the caller builds however it likes (e.g. by concatenating
/// the address, circuit id, and public key bytes).
pub type RequestKey = Vec<u8>;

/// Rejects a replayed handshake request (a repeated `CREATE`).
///
/// `last_seen` is the authoritative membership + last-touch-time map, giving
/// O(1) lookup (the previous `Vec<(RequestKey, f64)>` design needed an O(n)
/// linear scan for every single call, plus an O(n) `Vec::remove(0)` shift on
/// every eviction -- a cheap CREATE flood with distinct handshake
/// identifiers turned that into a CPU-amplification DoS vector).
///
/// `order` is an append-only log of every insert/touch, oldest at the
/// front, each tagged with the `next_gen` counter value at the time it was
/// pushed. A touch doesn't move or remove the request's *previous*
/// occurrence in `order` (an O(n) operation for an arbitrary position in a
/// `VecDeque`) -- it just appends a new one and leaves the old one behind
/// as a tombstone. [`Self::peek_live_front`] lazily discards these
/// tombstones (an occurrence is stale the moment `last_seen`'s generation
/// for that key no longer matches the one `order` recorded) the next time
/// anything walks the front of the queue, so eviction and TTL expiry are
/// both a `pop_front` away in the common case. Every push is popped
/// (either as a live entry once evicted/expired, or as a stale tombstone
/// once superseded) at most once over the guard's whole lifetime, so the
/// amortized cost per [`Self::accept`] call is O(1) regardless of how much
/// touching happens -- a plain timestamp couldn't tell a stale occurrence
/// from a live one this cheaply (two touches landing in the same clock
/// tick would be indistinguishable), hence the separate monotonic
/// generation counter instead of comparing `f64` timestamps.
pub struct HandshakeReplayGuard {
    max_entries: usize,
    ttl: Option<f64>,
    clock: Box<dyn FnMut() -> f64>,
    next_gen: u64,
    order: VecDeque<(RequestKey, u64)>,
    last_seen: HashMap<RequestKey, (f64, u64)>,
    pub accepted: u64,
    pub rejected: u64,
}

impl HandshakeReplayGuard {
    pub fn new(max_entries: usize, ttl: Option<f64>, clock: Box<dyn FnMut() -> f64>) -> Result<HandshakeReplayGuard, ReliabilityError> {
        if max_entries < 1 {
            return Err(generic(format!("max_entries must be at least 1, got {max_entries}")));
        }
        if let Some(t) = ttl {
            if t <= 0.0 {
                return Err(generic(format!("ttl must be positive or None, got {t}")));
            }
        }
        Ok(HandshakeReplayGuard {
            max_entries,
            ttl,
            clock,
            next_gen: 0,
            order: VecDeque::new(),
            last_seen: HashMap::new(),
            accepted: 0,
            rejected: 0,
        })
    }

    /// Discard tombstones (occurrences superseded by a later touch, or
    /// belonging to a since-forgotten key) from the front of `order`,
    /// stopping at the first occurrence that is still the authoritative
    /// one for its key. Does not itself remove that live occurrence --
    /// callers decide whether it should be evicted (by TTL or capacity).
    fn peek_live_front(&mut self) -> Option<(RequestKey, f64)> {
        while let Some((key, gen)) = self.order.front() {
            match self.last_seen.get(key) {
                Some(&(ts, g)) if g == *gen => return Some((key.clone(), ts)),
                _ => {
                    self.order.pop_front();
                }
            }
        }
        None
    }

    fn expire(&mut self) {
        let cutoff = match self.ttl {
            Some(t) => (self.clock)() - t,
            None => return,
        };
        while let Some((key, ts)) = self.peek_live_front() {
            if ts < cutoff {
                self.order.pop_front();
                self.last_seen.remove(&key);
            } else {
                break;
            }
        }
    }

    fn evict_oldest_if_full(&mut self) {
        if self.last_seen.len() < self.max_entries {
            return;
        }
        if let Some((key, _)) = self.peek_live_front() {
            self.order.pop_front();
            self.last_seen.remove(&key);
        }
    }

    /// Record `request` and report whether it is new.
    pub fn accept(&mut self, request: RequestKey) -> bool {
        self.expire();
        let now = (self.clock)();
        let gen = self.next_gen;
        self.next_gen += 1;
        if let Some(existing) = self.last_seen.get_mut(&request) {
            *existing = (now, gen);
            self.order.push_back((request, gen));
            self.rejected += 1;
            return false;
        }
        self.evict_oldest_if_full();
        self.last_seen.insert(request.clone(), (now, gen));
        self.order.push_back((request, gen));
        self.accepted += 1;
        true
    }

    /// Return `true` if `request` is currently remembered.
    pub fn seen(&mut self, request: &RequestKey) -> bool {
        self.expire();
        self.last_seen.contains_key(request)
    }

    /// Drop a remembered request, returning whether it was present.
    pub fn forget(&mut self, request: &RequestKey) -> bool {
        self.last_seen.remove(request).is_some()
    }

    /// Forget every remembered request.
    pub fn clear(&mut self) {
        self.order.clear();
        self.last_seen.clear();
    }

    pub fn len(&self) -> usize {
        self.last_seen.len()
    }
    pub fn is_empty(&self) -> bool {
        self.last_seen.is_empty()
    }
}

// --------------------------------------------------------------------------
// Reordering
// --------------------------------------------------------------------------

/// Reorder out-of-order items into sequence order for delivery.
pub struct ReassemblyBuffer<T> {
    pub expected: u64,
    max_pending: usize,
    pending: HashMap<u64, T>,
    pub received: u64,
    pub duplicate: u64,
    pub evicted: u64,
}

impl<T> ReassemblyBuffer<T> {
    pub fn new(start: u64, max_pending: usize) -> Result<ReassemblyBuffer<T>, ReliabilityError> {
        if max_pending < 1 {
            return Err(generic(format!("max_pending must be at least 1, got {max_pending}")));
        }
        Ok(ReassemblyBuffer { expected: start, max_pending, pending: HashMap::new(), received: 0, duplicate: 0, evicted: 0 })
    }

    pub fn with_defaults() -> ReassemblyBuffer<T> {
        ReassemblyBuffer::new(0, 4096).unwrap()
    }

    /// Accept `item` at `seq` and return everything now deliverable, in
    /// ascending sequence order.
    pub fn push(&mut self, seq: u64, item: T) -> Vec<T> {
        if seq < self.expected || self.pending.contains_key(&seq) {
            self.duplicate += 1;
            return Vec::new();
        }
        self.received += 1;
        self.pending.insert(seq, item);

        while self.pending.len() > self.max_pending {
            if let Some(&oldest) = self.pending.keys().min() {
                self.pending.remove(&oldest);
                self.evicted += 1;
            }
        }

        let mut released = Vec::new();
        while let Some(item) = self.pending.remove(&self.expected) {
            released.push(item);
            self.expected += 1;
        }
        released
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn held(&self) -> HashSet<u64> {
        self.pending.keys().copied().collect()
    }

    pub fn has_gap(&self) -> bool {
        !self.pending.is_empty() && !self.pending.contains_key(&self.expected)
    }

    /// Release everything held, in sequence order, and advance `expected`.
    pub fn flush(&mut self) -> Vec<T> {
        if self.pending.is_empty() {
            return Vec::new();
        }
        let highest = *self.pending.keys().max().unwrap();
        let mut keys: Vec<u64> = self.pending.keys().copied().collect();
        keys.sort_unstable();
        let released: Vec<T> = keys.into_iter().map(|k| self.pending.remove(&k).unwrap()).collect();
        self.expected = self.expected.max(highest + 1);
        released
    }

    /// Drop all state and begin expecting `start` again.
    pub fn reset(&mut self, start: u64) {
        self.expected = start;
        self.pending.clear();
    }
}

// --------------------------------------------------------------------------
// Selective acknowledgment
// --------------------------------------------------------------------------

/// Width of the selective-ack bitmap, in bits/cells of lookahead past the
/// cumulative edge. Widened from 32 to 128 -- see [`crate::layer`]'s
/// `LAYER_PROTOCOL_VERSION` doc comment for why -- so it needs to stay in
/// lockstep with [`crate::layer::ACK_WIRE_SIZE`] and the client's own copy
/// of this constant.
pub const SACK_BITS: u32 = 128;

/// Decoded form of a SACK ack: a cumulative edge plus a bitmap of holes.
#[derive(Debug, Clone, Copy)]
pub struct AckState {
    pub cumulative: u32,
    pub bitmap: u128,
}

impl AckState {
    /// `.acked()` refuses to materialize a set larger than this.
    pub const MAX_MATERIALIZABLE_CUMULATIVE: u32 = 1_000_000;

    pub fn new(cumulative: u32, bitmap: u128) -> AckState {
        AckState { cumulative, bitmap }
    }

    pub fn empty() -> AckState {
        AckState { cumulative: 0, bitmap: 0 }
    }

    /// Expand the cumulative edge and bitmap into a set of sequence numbers.
    /// `Err` if `cumulative` exceeds [`Self::MAX_MATERIALIZABLE_CUMULATIVE`].
    pub fn acked(&self) -> Result<HashSet<u64>, ReliabilityError> {
        if self.cumulative > Self::MAX_MATERIALIZABLE_CUMULATIVE {
            return Err(generic(format!(
                "refusing to materialize {} sequence numbers into a set (limit is {}); use is_acked() or covers() instead",
                self.cumulative,
                Self::MAX_MATERIALIZABLE_CUMULATIVE
            )));
        }
        if self.cumulative == 0 && self.bitmap == 0 {
            return Ok(HashSet::new());
        }
        let mut acked: HashSet<u64> = (0..self.cumulative as u64).collect();
        for bit in 0..SACK_BITS {
            if self.bitmap & (1u128 << bit) != 0 {
                acked.insert(self.cumulative as u64 + bit as u64);
            }
        }
        Ok(acked)
    }

    /// Build an ack describing a set of received sequence numbers.
    pub fn from_received(received: impl IntoIterator<Item = u64>) -> AckState {
        let mut numbers: Vec<u64> = received.into_iter().collect::<HashSet<_>>().into_iter().collect();
        numbers.sort_unstable();
        if numbers.is_empty() {
            return AckState::empty();
        }
        let present: HashSet<u64> = numbers.iter().copied().collect();
        let mut cumulative: u64 = 0;
        while present.contains(&cumulative) {
            cumulative += 1;
        }
        if cumulative == 0 {
            let last = *numbers.last().unwrap();
            cumulative = last.saturating_sub(u64::from(SACK_BITS) - 1);
            while cumulative > 0 && present.contains(&(cumulative - 1)) {
                cumulative -= 1;
            }
        }
        let mut bitmap: u128 = 0;
        for &n in &numbers {
            if n >= cumulative {
                let offset = n - cumulative;
                if offset < u64::from(SACK_BITS) {
                    bitmap |= 1u128 << offset;
                }
            }
        }
        AckState::new(cumulative as u32, bitmap)
    }

    /// `true` if this ack says `seq` arrived. O(1).
    pub fn is_acked(&self, seq: u64) -> bool {
        if seq < self.cumulative as u64 {
            return true;
        }
        let offset = seq as i64 - self.cumulative as i64;
        (0..i64::from(SACK_BITS)).contains(&offset) && (self.bitmap & (1u128 << offset)) != 0
    }

    /// `true` if `seq` falls inside the range this ack describes.
    pub fn covers(&self, seq: u64) -> bool {
        (seq < self.cumulative as u64) || ((self.cumulative as u64) <= seq && seq < self.cumulative as u64 + u64::from(SACK_BITS))
    }
}

impl PartialEq for AckState {
    fn eq(&self, other: &Self) -> bool {
        (self.cumulative, self.bitmap) == (other.cumulative, other.bitmap)
    }
}
impl Eq for AckState {}

impl fmt::Display for AckState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let selective = self.bitmap.count_ones();
        write!(f, "AckState(cumulative={}, selective={})", self.cumulative, selective)
    }
}

/// Decides *when* to emit an ack, and never emits a redundant one.
/// How many out-of-order sequence numbers an [`AckTracker`] holds before it
/// gives up on the gap below them. Twice [`SACK_BITS`], so ordinary
/// reordering (which the ack bitmap can describe) never triggers it.
pub const MAX_HELD_BEFORE_GAP_LOST: usize = 2 * SACK_BITS as usize;

pub struct AckTracker {
    buffer: ReassemblyBuffer<()>,
    ack_every: u64,
    clock: Box<dyn FnMut() -> f64>,
    last_pair: Option<(u32, u128)>,
    since_ack: u64,
    hole_reported: bool,
    pub emitted: u64,
    pub suppressed: u64,
    pub timely: u64,
    pub periodic: u64,
}

impl AckTracker {
    pub fn new(start: u64, ack_every: u64, max_pending: usize, clock: Box<dyn FnMut() -> f64>) -> Result<AckTracker, ReliabilityError> {
        if ack_every < 1 {
            return Err(generic(format!("ack_every must be at least 1, got {ack_every}")));
        }
        Ok(AckTracker {
            buffer: ReassemblyBuffer::new(start, max_pending)?,
            ack_every,
            clock,
            last_pair: None,
            since_ack: 0,
            hole_reported: false,
            emitted: 0,
            suppressed: 0,
            timely: 0,
            periodic: 0,
        })
    }

    /// Accept a cell (ordering only; no payload) and return whether it was
    /// newly received.
    pub fn receive(&mut self, seq: u64) {
        let before = self.buffer.received;
        self.buffer.push(seq, ());
        if self.buffer.received > before {
            self.since_ack += 1;
        } else {
            self.suppressed += 1;
        }
        // A gap that is never filled must not grow this set without bound:
        // `current()` (run once per cell, through `maybe_ack`) walks it, so
        // an old hole made every later cell slower than the one before.
        // Found live: on every real circuit the first cell a relay sees is
        // not sequence 0, so the hole was there from the start and a 100 MB
        // download ran at 14, then 6, then 3.6 MB/s as `pending` grew toward
        // its 1M cap. UDP gives no forward retransmit, so a cell that is
        // this far behind is lost for good: declare the gap lost, move the
        // cumulative edge past it, and carry on.
        if self.buffer.pending_count() > MAX_HELD_BEFORE_GAP_LOST {
            let _ = self.buffer.flush();
            self.hole_reported = false;
        }
    }

    /// Describe everything received so far, without emitting an ack.
    ///
    /// Was `AckState::from_received((0..self.buffer.expected).collect::<HashSet<_>>().extend(held))`:
    /// rebuilding and sorting an `expected`-sized set on every call made
    /// this (and therefore `maybe_ack`, called once per received cell)
    /// O(expected) per call, i.e. O(N^2) over a stream of N cells, with no
    /// crafted input needed -- ordinary sustained traffic on one circuit
    /// degraded/stalled it and could starve other circuits sharing the
    /// process. `buffer.expected` is already the cumulative ack edge (by
    /// `ReassemblyBuffer`'s own invariant, `held()` never contains
    /// `expected`), so it never needs to be re-derived by walking every
    /// sequence number below it; only the much smaller, `max_pending`-bounded
    /// `held()` set actually needs inspecting for the selective bitmap.
    /// `expected == 0` (nothing delivered contiguously from the very
    /// start yet) is delegated to `AckState::from_received`, whose own
    /// window-sliding special case for that situation depends only on
    /// `held()` too (since `0..0` is empty) and is left untouched here.
    pub fn current(&self) -> AckState {
        let cumulative = self.buffer.expected;
        if cumulative == 0 {
            return AckState::from_received(self.buffer.held());
        }
        let mut bitmap: u128 = 0;
        for seq in self.buffer.held() {
            if seq >= cumulative {
                let offset = seq - cumulative;
                if offset < u64::from(SACK_BITS) {
                    bitmap |= 1u128 << offset;
                }
            }
        }
        AckState::new(cumulative as u32, bitmap)
    }

    /// Return an ack to send now, or `None` if one is not warranted.
    pub fn maybe_ack(&mut self) -> Option<AckState> {
        if self.buffer.received == 0 {
            self.suppressed += 1;
            return None;
        }
        let state = self.current();
        if self.buffer.has_gap() {
            if self.hole_reported {
                self.suppressed += 1;
                return None;
            }
            self.hole_reported = true;
            return Some(self.emit(state, true));
        }
        self.hole_reported = false;
        if self.since_ack < self.ack_every {
            self.suppressed += 1;
            return None;
        }
        Some(self.emit(state, false))
    }

    /// Return an ack regardless of policy, for a standalone ack cell.
    pub fn force_ack(&mut self) -> AckState {
        let state = self.current();
        self.emit(state, false)
    }

    fn emit(&mut self, state: AckState, timely: bool) -> AckState {
        let pair = (state.cumulative, state.bitmap);
        if Some(pair) == self.last_pair {
            self.suppressed += 1;
            return state;
        }
        self.last_pair = Some(pair);
        self.since_ack = 0;
        self.emitted += 1;
        if timely {
            self.timely += 1;
        } else {
            self.periodic += 1;
        }
        // The caller's clock is exercised the same way the Python class's
        // is (injectable), even though this port doesn't time-stamp acks
        // itself; call it to keep behaviour parity for callers relying on
        // deterministic clock advancement in tests.
        let _ = (self.clock)();
        state
    }

    pub fn expected(&self) -> u64 {
        self.buffer.expected
    }
    pub fn held_count(&self) -> usize {
        self.buffer.pending_count()
    }
}

/// A minimal SACK-based reliable sender over an unreliable datagram layer.
pub struct SendWindow {
    pub rto: f64,
    max_retries: u32,
    max_unacked: usize,
    duplicate_ack_threshold: u32,
    clock: Box<dyn FnMut() -> f64>,
    next_seq: u64,
    /// seq -> (datagram, first_sent_at, last_sent_at, attempts)
    outstanding: HashMap<u64, (Vec<u8>, f64, f64, u32)>,
    acked_set: HashSet<u64>,
    last_ack: Option<(u32, u128)>,
    duplicate_acks: u32,
    pub sent: u64,
    pub acked: u64,
    pub retransmitted: u64,
    pub dropped: u64,
}

impl SendWindow {
    pub fn new(rto: f64, max_retries: u32, max_unacked: usize, duplicate_ack_threshold: u32, clock: Box<dyn FnMut() -> f64>) -> SendWindow {
        SendWindow {
            rto,
            max_retries,
            max_unacked,
            duplicate_ack_threshold,
            clock,
            next_seq: 0,
            outstanding: HashMap::new(),
            acked_set: HashSet::new(),
            last_ack: None,
            duplicate_acks: 0,
            sent: 0,
            acked: 0,
            retransmitted: 0,
            dropped: 0,
        }
    }

    pub fn with_defaults(clock: Box<dyn FnMut() -> f64>) -> SendWindow {
        SendWindow::new(DEFAULT_RTO, DEFAULT_MAX_RETRIES, 1024, 3, clock)
    }

    /// Buffer `datagram` and return its sequence number.
    pub fn append(&mut self, datagram: &[u8]) -> Result<u64, ReliabilityError> {
        if self.outstanding.len() >= self.max_unacked {
            return Err(SendBufferFullError {
                message: format!("{} unacknowledged cells at the {}-cell limit", self.outstanding.len(), self.max_unacked),
            }
            .into());
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        let now = (self.clock)();
        self.outstanding.insert(seq, (datagram.to_vec(), now, now, 0));
        Ok(seq)
    }

    /// Return the cells to transmit now, first-time or retransmitted, in
    /// ascending sequence order. `limit`, if given, caps how many
    /// never-sent-before cells may go out (an already-outstanding cell past
    /// its RTO is always returned regardless of `limit`).
    pub fn due(&mut self, limit: Option<usize>) -> Vec<(u64, Vec<u8>)> {
        let now = (self.clock)();
        let mut out = Vec::new();
        let mut first_sends = 0usize;
        let mut seqs: Vec<u64> = self.outstanding.keys().copied().collect();
        seqs.sort_unstable();
        for seq in seqs {
            let due_now;
            let is_first_send;
            {
                let record = self.outstanding.get(&seq).unwrap();
                let (_, _first_sent, last_sent, attempts) = record;
                if *attempts != 0 && (now - last_sent) < self.rto {
                    continue;
                }
                if *attempts >= self.max_retries {
                    self.outstanding.remove(&seq);
                    self.dropped += 1;
                    continue;
                }
                is_first_send = *attempts == 0;
                if is_first_send {
                    if let Some(l) = limit {
                        if first_sends >= l {
                            continue;
                        }
                    }
                }
                due_now = true;
            }
            if !due_now {
                continue;
            }
            let record = self.outstanding.get_mut(&seq).unwrap();
            record.2 = now;
            record.3 += 1;
            if is_first_send {
                first_sends += 1;
            } else {
                self.retransmitted += 1;
            }
            self.sent += 1;
            out.push((seq, record.0.clone()));
        }
        out
    }

    /// How many cells are still unacknowledged.
    pub fn pending(&self) -> usize {
        self.outstanding.len()
    }

    /// Apply an incoming ack, returning the sequence numbers it freed.
    pub fn on_ack(&mut self, cumulative: u32, bitmap: u128) -> HashSet<u64> {
        let state = AckState::new(cumulative, bitmap);
        let mut freed = HashSet::new();
        let seqs: Vec<u64> = self.outstanding.keys().copied().collect();
        for seq in seqs {
            if state.is_acked(seq) {
                self.outstanding.remove(&seq);
                if !self.acked_set.contains(&seq) {
                    self.acked_set.insert(seq);
                    self.acked += 1;
                    freed.insert(seq);
                }
            }
        }
        let pair = (state.cumulative, state.bitmap);
        if Some(pair) == self.last_ack {
            self.duplicate_acks += 1;
        } else {
            self.last_ack = Some(pair);
            self.duplicate_acks = 0;
        }
        freed
    }

    /// Note a repeated ack; maybe fast-retransmit the cell after its edge.
    pub fn on_duplicate_ack(&mut self) -> Option<u64> {
        self.duplicate_acks += 1;
        if self.duplicate_acks < self.duplicate_ack_threshold {
            return None;
        }
        let cumulative = self.last_ack?.0 as u64;
        let mut seqs: Vec<u64> = self.outstanding.keys().copied().collect();
        seqs.sort_unstable();
        for seq in seqs {
            if seq >= cumulative {
                let now = (self.clock)();
                let record = self.outstanding.get_mut(&seq).unwrap();
                record.1 = now;
                record.2 = now;
                record.3 += 1;
                self.retransmitted += 1;
                self.sent += 1;
                self.duplicate_acks = 0;
                return Some(seq);
            }
        }
        None
    }

    /// Adjust the timeout from an observed round trip, as a simple EWMA.
    pub fn update_rto(&mut self, sample: f64) {
        self.rto = f64::max(0.05, 0.875 * self.rto + 0.125 * f64::max(0.0, sample));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn fake_clock(start: f64) -> (Box<dyn FnMut() -> f64>, Rc<RefCell<f64>>) {
        let t = Rc::new(RefCell::new(start));
        let t2 = t.clone();
        let clock: Box<dyn FnMut() -> f64> = Box::new(move || *t2.borrow());
        (clock, t)
    }

    // -- ReplayWindow -------------------------------------------------
    #[test]
    fn test_replay_window_docstring_example() {
        let mut w = ReplayWindow::with_defaults();
        assert!(w.accept(0));
        assert!(!w.accept(0));
        assert!(w.accept(5));
        assert!(w.accept(1));
        assert!(!w.accept(1));
    }

    #[test]
    fn test_replay_window_rejects_too_old() {
        let mut w = ReplayWindow::new(4).unwrap();
        assert!(w.accept(100));
        assert!(!w.accept(95)); // more than 4 behind
    }

    #[test]
    fn test_replay_window_seen() {
        let mut w = ReplayWindow::with_defaults();
        assert!(!w.seen(0));
        w.accept(0);
        assert!(w.seen(0));
        assert!(!w.seen(1));
    }

    #[test]
    fn test_replay_window_rejects_zero() {
        assert!(ReplayWindow::new(0).is_err());
    }

    /// Before the `Bitset` fix, `shift(distance)` for `distance >= 64`
    /// shifted a bare `u64` by more
    /// than its own bit width -- a debug-build panic ("attempt to shift
    /// left with overflow") or silent state corruption in release. Every
    /// one of these gaps is well within the default window (1024) and
    /// well past the old 64-bit ceiling, so each of these `accept` calls
    /// alone used to be enough to trigger it; this test just needs to
    /// complete without panicking and behave sanely to prove the fix.
    #[test]
    fn test_replay_window_handles_gaps_past_64_bits_without_panicking() {
        let mut w = ReplayWindow::with_defaults(); // window = 1024
        assert!(w.accept(10_000));
        assert!(w.accept(10_100)); // gap of 100: shift(100) would have overflowed a u64
        assert!(w.accept(10_600)); // gap of 500
        assert!(w.accept(11_600)); // gap of 1000, right at the edge of the window
        // A fill-in within the still-live window, behind the new high, must
        // still be tracked correctly (not silently corrupted).
        assert!(w.accept(11_599));
        assert!(!w.accept(11_599), "the fill-in above must now be a duplicate");
        // Definitively past even the 1024-wide window: rejected, not a panic.
        assert!(!w.accept(10_000));
    }

    /// Ported from the Client crate's own `ReplayWindow` test of the same
    /// name, generated against the real Python `allium.reliability`
    /// module -- proves the ported `Bitset` doesn't just avoid panicking
    /// on a multi-word window, it produces the *correct* answer, cross-
    /// checked against an independent reference implementation.
    ///
    /// python3 -c "
    ///   import allium.reliability as r
    ///   w = r.ReplayWindow(window=1024)
    ///   seq = [1000, 500, 1005, 998, 2000, 1500, 1999, 2001, 100, 1970, 3100, 3099, 3200, 2100]
    ///   print([w.accept(s) for s in seq])
    ///   print(w.high, w.accepted, w.rejected)
    /// "
    #[test]
    fn test_replay_window_matches_python_default_window_multiword_bitset() {
        let mut w = ReplayWindow::new(1024).unwrap();
        let seq: [u64; 14] = [1000, 500, 1005, 998, 2000, 1500, 1999, 2001, 100, 1970, 3100, 3099, 3200, 2100];
        let results: Vec<bool> = seq.iter().map(|&s| w.accept(s)).collect();
        assert_eq!(results, vec![true, true, true, true, true, true, true, true, false, true, true, true, true, false]);
        assert_eq!(w.high(), 3200);
        assert_eq!(w.accepted, 12);
        assert_eq!(w.rejected, 2);
    }

    /// Same cross-check for a small, single-word window, to confirm the
    /// `Bitset` refactor didn't change behavior for the case that used to
    /// work fine (window <= 64).
    ///
    /// python3 -c "
    ///   import allium.reliability as r
    ///   w = r.ReplayWindow(window=8)
    ///   seq = [10, 10, 15, 12, 9, 20, 13, 5, 19, 21]
    ///   print([w.accept(s) for s in seq])
    ///   print(w.high, w.accepted, w.rejected)
    ///   print([w.seen(s) for s in [5,9,10,12,13,15,18,19,20,21,2]])
    /// "
    #[test]
    fn test_replay_window_matches_python_small_window() {
        let mut w = ReplayWindow::new(8).unwrap();
        let seq: [u64; 10] = [10, 10, 15, 12, 9, 20, 13, 5, 19, 21];
        let results: Vec<bool> = seq.iter().map(|&s| w.accept(s)).collect();
        assert_eq!(results, vec![true, false, true, true, true, true, true, false, true, true]);
        assert_eq!(w.high(), 21);
        assert_eq!(w.accepted, 8);
        assert_eq!(w.rejected, 2);

        let seen_queries: [u64; 11] = [5, 9, 10, 12, 13, 15, 18, 19, 20, 21, 2];
        let seen: Vec<bool> = seen_queries.iter().map(|&s| w.seen(s)).collect();
        assert_eq!(seen, vec![true, true, true, true, true, true, false, true, true, true, true]);
    }

    /// Property check against a naive, non-bit-tricks reference model
    /// (a plain `Vec<bool>` of "seen" flags), across many pseudo-random
    /// `accept` sequences and a range of window sizes including ones that
    /// aren't a multiple of 64 (exercising `Bitset`'s masking/shifting at
    /// odd boundaries, not just the two golden-vector sizes above).
    #[test]
    fn test_replay_window_matches_naive_model_across_random_sequences() {
        struct Naive {
            window: u64,
            high: Option<u64>,
            seen: std::collections::HashSet<u64>,
        }
        impl Naive {
            fn accept(&mut self, seq: u64) -> bool {
                match self.high {
                    None => {
                        self.high = Some(seq);
                        self.seen.insert(seq);
                        true
                    }
                    Some(high) => {
                        if seq == high || (seq < high && high - seq <= self.window && self.seen.contains(&seq)) {
                            false
                        } else if seq < high && high - seq > self.window {
                            false
                        } else {
                            if seq > high {
                                self.high = Some(seq);
                                self.seen.retain(|&s| seq - s <= self.window);
                            }
                            self.seen.insert(seq);
                            true
                        }
                    }
                }
            }
        }

        // A tiny deterministic PRNG (splitmix64) -- no new dependency, and
        // reproducible if this ever needs to be re-run to chase a failure.
        fn next(state: &mut u64) -> u64 {
            *state = state.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = *state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }

        for &window in &[1u32, 2, 63, 64, 65, 100, 127, 128, 129, 1000, 1024, 1025] {
            let mut rng = 0x243F6A8885A308D3u64 ^ (window as u64);
            let mut w = ReplayWindow::new(window).unwrap();
            let mut naive = Naive { window: window as u64, high: None, seen: std::collections::HashSet::new() };
            let mut cursor: u64 = 10_000;
            for _ in 0..2000 {
                // Mostly small forward/backward jitter around a slowly
                // advancing cursor, matching realistic reordering, plus
                // occasional bigger jumps to exercise multi-word shifts.
                let r = next(&mut rng);
                let delta = (r % 2000) as i64 - 900;
                let seq = (cursor as i64 + delta).max(0) as u64;
                if r % 7 == 0 {
                    cursor = cursor.saturating_add((r >> 8) % 500);
                }
                assert_eq!(w.accept(seq), naive.accept(seq), "window={window}, seq={seq}, cursor={cursor}");
            }
        }
    }

    // -- HandshakeReplayGuard -------------------------------------------
    #[test]
    fn test_handshake_replay_guard_accepts_once() {
        let (clock, _t) = fake_clock(0.0);
        let mut g = HandshakeReplayGuard::new(4096, Some(120.0), clock).unwrap();
        let key: RequestKey = b"peer-a".to_vec();
        assert!(g.accept(key.clone()));
        assert!(!g.accept(key.clone()));
        assert!(g.seen(&key));
    }

    #[test]
    fn test_handshake_replay_guard_ttl_expiry() {
        let (clock, t) = fake_clock(0.0);
        let mut g = HandshakeReplayGuard::new(4096, Some(10.0), clock).unwrap();
        let key: RequestKey = b"peer-a".to_vec();
        assert!(g.accept(key.clone()));
        *t.borrow_mut() = 11.0;
        assert!(g.accept(key)); // expired, treated as fresh
    }

    #[test]
    fn test_handshake_replay_guard_eviction() {
        let (clock, _t) = fake_clock(0.0);
        let mut g = HandshakeReplayGuard::new(2, None, clock).unwrap();
        assert!(g.accept(b"a".to_vec()));
        assert!(g.accept(b"b".to_vec()));
        assert!(g.accept(b"c".to_vec())); // evicts "a"
        assert_eq!(g.len(), 2);
        assert!(!g.seen(&b"a".to_vec()));
    }

    #[test]
    fn test_handshake_replay_guard_forget() {
        let (clock, _t) = fake_clock(0.0);
        let mut g = HandshakeReplayGuard::new(4096, None, clock).unwrap();
        let key: RequestKey = b"peer-a".to_vec();
        g.accept(key.clone());
        assert!(g.forget(&key));
        assert!(!g.forget(&key));
        assert!(g.accept(key)); // no longer remembered, accepted fresh
    }

    #[test]
    fn test_handshake_replay_guard_repeated_touches_of_one_key_stay_bounded() {
        // Regression test for the lazy-tombstone `order` queue: hammering
        // `accept()` on the *same* key over and over (a real replay
        // attacker's exact pattern) must not grow `order` without bound,
        // even when the clock never advances between calls (the case a
        // plain timestamp-equality staleness check would get wrong).
        let (clock, _t) = fake_clock(0.0);
        let mut g = HandshakeReplayGuard::new(4096, Some(120.0), clock).unwrap();
        let key: RequestKey = b"peer-a".to_vec();
        assert!(g.accept(key.clone()));
        for _ in 0..10_000 {
            assert!(!g.accept(key.clone()));
        }
        assert_eq!(g.len(), 1);
        assert!(g.order.len() < 8, "stale touch tombstones should be reaped, not accumulate: {}", g.order.len());
    }

    #[test]
    fn test_handshake_replay_guard_eviction_is_cheap_for_many_distinct_keys() {
        // Regression test for the O(n) `position()` scan + O(n)
        // `Vec::remove(0)` shift this replaced: a flood of distinct
        // handshake identifiers, well past capacity, must run in time
        // roughly linear in the number of calls, not quadratic.
        let (clock, _t) = fake_clock(0.0);
        let mut g = HandshakeReplayGuard::new(4096, None, clock).unwrap();
        let n = 200_000usize;
        let start = std::time::Instant::now();
        for i in 0..n {
            let key: RequestKey = (i as u32).to_be_bytes().to_vec();
            assert!(g.accept(key));
        }
        assert_eq!(g.len(), 4096);
        assert!(start.elapsed() < std::time::Duration::from_secs(5), "accept() looks like it regressed back to O(n) per call");
    }

    // -- ReassemblyBuffer -------------------------------------------------
    #[test]
    fn test_reassembly_buffer_docstring_example() {
        let mut buf: ReassemblyBuffer<Vec<u8>> = ReassemblyBuffer::with_defaults();
        assert_eq!(buf.push(1, b"b".to_vec()), Vec::<Vec<u8>>::new());
        assert_eq!(buf.push(0, b"a".to_vec()), vec![b"a".to_vec(), b"b".to_vec()]);
    }

    #[test]
    fn test_reassembly_buffer_duplicate() {
        let mut buf: ReassemblyBuffer<i32> = ReassemblyBuffer::with_defaults();
        buf.push(0, 10);
        assert_eq!(buf.push(0, 10), Vec::<i32>::new());
        assert_eq!(buf.duplicate, 1);
    }

    #[test]
    fn test_reassembly_buffer_has_gap() {
        let mut buf: ReassemblyBuffer<i32> = ReassemblyBuffer::with_defaults();
        assert!(!buf.has_gap());
        buf.push(1, 1);
        assert!(buf.has_gap());
        buf.push(0, 0);
        assert!(!buf.has_gap());
    }

    #[test]
    fn test_reassembly_buffer_flush() {
        let mut buf: ReassemblyBuffer<i32> = ReassemblyBuffer::with_defaults();
        buf.push(2, 2);
        buf.push(1, 1);
        let flushed = buf.flush();
        assert_eq!(flushed, vec![1, 2]);
        assert_eq!(buf.expected, 3);
    }

    #[test]
    fn test_reassembly_buffer_eviction() {
        let mut buf: ReassemblyBuffer<i32> = ReassemblyBuffer::new(0, 2).unwrap();
        buf.push(1, 1);
        buf.push(2, 2);
        buf.push(3, 3); // evicts oldest pending (1)
        assert_eq!(buf.evicted, 1);
    }

    // -- AckState -------------------------------------------------------
    #[test]
    fn test_ackstate_docstring_example() {
        let a = AckState::new(3, 0b1010);
        assert!(a.is_acked(0));
        assert!(a.is_acked(1));
        assert!(a.is_acked(2));
        assert!(!a.is_acked(3));
        assert!(a.is_acked(4));
        assert!(!a.is_acked(5));
        assert!(a.is_acked(6));
    }

    #[test]
    fn test_ackstate_from_received_contiguous() {
        let a = AckState::from_received(vec![0, 1, 2]);
        assert_eq!(a.cumulative, 3);
        assert_eq!(a.bitmap, 0);
    }

    #[test]
    fn test_ackstate_from_received_with_hole() {
        let a = AckState::from_received(vec![0, 1, 3]);
        assert_eq!(a.cumulative, 2);
        assert!(a.is_acked(3));
        assert!(!a.is_acked(2));
    }

    #[test]
    fn test_ackstate_acked_refuses_huge_cumulative() {
        let a = AckState::new(AckState::MAX_MATERIALIZABLE_CUMULATIVE + 1, 0);
        assert!(a.acked().is_err());
    }

    #[test]
    fn test_ackstate_equality() {
        assert_eq!(AckState::new(3, 5), AckState::new(3, 5));
        assert_ne!(AckState::new(3, 5), AckState::new(3, 6));
    }

    // -- AckTracker -------------------------------------------------------
    #[test]
    fn test_ack_tracker_emits_on_gap() {
        let (clock, _t) = fake_clock(0.0);
        let mut t = AckTracker::new(0, 4, 4096, clock).unwrap();
        t.receive(1); // gap: 0 not seen yet
        let ack = t.maybe_ack();
        assert!(ack.is_some());
        assert_eq!(t.timely, 1);
    }

    #[test]
    fn test_ack_tracker_suppresses_repeat_hole() {
        let (clock, _t) = fake_clock(0.0);
        let mut t = AckTracker::new(0, 4, 4096, clock).unwrap();
        t.receive(1);
        assert!(t.maybe_ack().is_some());
        t.receive(2); // still a gap at 0, same reported hole
        assert!(t.maybe_ack().is_none());
    }

    #[test]
    fn test_ack_tracker_periodic() {
        let (clock, _t) = fake_clock(0.0);
        let mut t = AckTracker::new(0, 2, 4096, clock).unwrap();
        t.receive(0);
        assert!(t.maybe_ack().is_none()); // only 1 since ack, need 2
        t.receive(1);
        assert!(t.maybe_ack().is_some());
    }

    #[test]
    fn test_ack_tracker_no_ack_when_nothing_received() {
        let (clock, _t) = fake_clock(0.0);
        let mut t = AckTracker::new(0, 1, 4096, clock).unwrap();
        assert!(t.maybe_ack().is_none());
    }

    /// `current()`'s O(held) fast path must match what the old
    /// O(expected) `AckState::from_received(0..expected ∪ held)`
    /// implementation produced, including: a cumulative edge that tracks
    /// `expected` once a contiguous prefix exists, a selective bitmap
    /// that only reflects out-of-order items within the SACK window, and
    /// out-of-order items *beyond* the window being silently dropped from
    /// the bitmap rather than corrupting it.
    #[test]
    fn test_ack_tracker_current_matches_naive_after_large_contiguous_prefix() {
        let (clock, _t) = fake_clock(0.0);
        let mut t = AckTracker::new(0, 1_000_000, 4096, clock).unwrap();
        for seq in 0..5_000u64 {
            t.receive(seq);
        }
        // Out-of-order, within the SACK window relative to `expected`.
        t.receive(5_002);
        t.receive(5_010);
        // Out-of-order, past the SACK window: must not appear in the bitmap.
        t.receive(5_200);
        let state = t.current();
        assert_eq!(state.cumulative, 5_000);
        assert!(state.is_acked(5_002));
        assert!(state.is_acked(5_010));
        assert!(!state.is_acked(5_200));
        assert!(!state.covers(5_200));
    }

    #[test]
    fn test_ack_tracker_force_ack() {
        let (clock, _t) = fake_clock(0.0);
        let mut t = AckTracker::new(0, 100, 4096, clock).unwrap();
        t.receive(0);
        let ack = t.force_ack();
        assert_eq!(ack.cumulative, 1);
    }

    // -- SendWindow ---------------------------------------------------
    #[test]
    fn test_send_window_append_and_due() {
        let (clock, _t) = fake_clock(0.0);
        let mut w = SendWindow::with_defaults(clock);
        let seq = w.append(b"hello").unwrap();
        assert_eq!(seq, 0);
        let due = w.due(None);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].0, 0);
        assert_eq!(due[0].1, b"hello");
    }

    #[test]
    fn test_send_window_due_respects_rto() {
        let (clock, t) = fake_clock(0.0);
        let mut w = SendWindow::with_defaults(clock);
        w.append(b"a").unwrap();
        w.due(None); // first send
        assert_eq!(w.due(None).len(), 0); // not yet due for retransmit
        *t.borrow_mut() = 2.0; // past default RTO of 1.0
        assert_eq!(w.due(None).len(), 1);
    }

    #[test]
    fn test_send_window_on_ack_frees_cells() {
        let (clock, _t) = fake_clock(0.0);
        let mut w = SendWindow::with_defaults(clock);
        w.append(b"a").unwrap();
        w.append(b"b").unwrap();
        w.due(None);
        let freed = w.on_ack(2, 0);
        assert_eq!(freed, [0u64, 1u64].into_iter().collect());
        assert_eq!(w.pending(), 0);
    }

    #[test]
    fn test_send_window_buffer_full() {
        let (clock, _t) = fake_clock(0.0);
        let mut w = SendWindow::new(1.0, 5, 1, 3, clock);
        w.append(b"a").unwrap();
        assert!(w.append(b"b").is_err());
    }

    #[test]
    fn test_send_window_dropped_after_max_retries() {
        let (clock, t) = fake_clock(0.0);
        let mut w = SendWindow::new(1.0, 2, 1024, 3, clock);
        w.append(b"a").unwrap();
        w.due(None); // attempt 1
        *t.borrow_mut() = 2.0;
        w.due(None); // attempt 2
        *t.borrow_mut() = 4.0;
        w.due(None); // attempts >= max_retries, dropped
        assert_eq!(w.dropped, 1);
        assert_eq!(w.pending(), 0);
    }

    #[test]
    fn test_send_window_fast_retransmit_on_duplicate_ack() {
        let (clock, _t) = fake_clock(0.0);
        let mut w = SendWindow::new(1.0, 5, 1024, 3, clock);
        w.append(b"a").unwrap();
        w.append(b"b").unwrap();
        w.due(None);
        w.on_ack(0, 0); // establishes last_ack = (0,0), nothing freed
        assert!(w.on_duplicate_ack().is_none());
        assert!(w.on_duplicate_ack().is_none());
        let resend = w.on_duplicate_ack();
        assert_eq!(resend, Some(0));
    }

    #[test]
    fn test_send_window_update_rto() {
        let (clock, _t) = fake_clock(0.0);
        let mut w = SendWindow::with_defaults(clock);
        let before = w.rto;
        w.update_rto(0.1);
        assert!(w.rto < before);
        assert!(w.rto >= 0.05);
    }

    #[test]
    fn test_send_window_due_limit_caps_first_sends_not_retransmits() {
        let (clock, t) = fake_clock(0.0);
        let mut w = SendWindow::with_defaults(clock);
        w.append(b"a").unwrap();
        w.append(b"b").unwrap();
        let due = w.due(Some(1));
        assert_eq!(due.len(), 1); // capped to 1 first-send
        *t.borrow_mut() = 2.0;
        // Both outstanding cells are now past RTO; limit=0 must still
        // return the already-outstanding (never-first-sent) cell whose
        // RTO expired, since it isn't "new load".
        let due2 = w.due(Some(0));
        assert!(due2.iter().any(|(s, _)| *s == 0));
    }

    #[test]
    fn a_gap_that_never_fills_does_not_make_every_later_cell_slower() {
        // The first cell is seq 1, as on a real circuit: seq 0 never arrives.
        let clock: Box<dyn FnMut() -> f64> = Box::new(|| 0.0);
        let mut t = AckTracker::new(0, 4, 1 << 20, clock).unwrap();
        let mut most_held = 0;
        for seq in 1..=5000u64 {
            t.receive(seq);
            most_held = most_held.max(t.held_count());
            let _ = t.maybe_ack();
        }
        assert!(most_held <= MAX_HELD_BEFORE_GAP_LOST + 1, "held set grew to {most_held}");
        assert_eq!(t.expected(), 5001, "the cumulative edge must move past the lost gap");
        assert_eq!(t.held_count(), 0);
    }

    #[test]
    fn one_lost_cell_mid_stream_costs_a_bounded_set_not_a_growing_one() {
        let clock: Box<dyn FnMut() -> f64> = Box::new(|| 0.0);
        let mut t = AckTracker::new(0, 4, 1 << 20, clock).unwrap();
        for seq in 0..100u64 {
            t.receive(seq);
        }
        assert_eq!(t.expected(), 100);
        // seq 100 is lost for good
        let mut most_held = 0;
        for seq in 101..20_000u64 {
            t.receive(seq);
            most_held = most_held.max(t.held_count());
        }
        assert!(most_held <= MAX_HELD_BEFORE_GAP_LOST + 1, "held set grew to {most_held}");
        assert!(t.expected() > 19_000, "tracking must resume after the lost cell, expected={}", t.expected());
    }

    #[test]
    fn ordinary_reordering_inside_the_ack_window_is_not_treated_as_loss() {
        let clock: Box<dyn FnMut() -> f64> = Box::new(|| 0.0);
        let mut t = AckTracker::new(0, 4, 1 << 20, clock).unwrap();
        // 0, then 100 cells arrive before 1 does
        t.receive(0);
        for seq in 2..=101u64 {
            t.receive(seq);
        }
        assert_eq!(t.expected(), 1, "the gap at 1 is still open");
        assert_eq!(t.held_count(), 100);
        t.receive(1);
        assert_eq!(t.expected(), 102, "the late cell closes the gap and releases everything");
        assert_eq!(t.held_count(), 0);
    }
}
