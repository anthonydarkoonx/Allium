//! UDP reliability primitives: sequence windows, reordering, and SACK.
//!
//! Three problems this module solves, all inherent to sending a stream over
//! UDP:
//!
//! 1. **Reordering.** UDP guarantees nothing about order, so a later cell
//!    can arrive first. [`ReassemblyBuffer`] holds out-of-order items and
//!    releases them in sequence order.
//! 2. **Duplicates and replays.** A replayed datagram is indistinguishable
//!    from a fresh one at the socket layer. [`ReplayWindow`] rejects
//!    anything already seen, or older than the window.
//! 3. **Loss.** A dropped cell breaks the whole stream unless something
//!    resends it. [`SendWindow`] implements a minimal Selective
//!    Acknowledgment loop: a cumulative ack plus a bitmask of the holes
//!    after it, retransmitting on timeout and on duplicate acks.
//!
//! This is not congestion control and not flow control (see
//! [`crate::congestion`] for the former). What is deliberately absent:
//!
//! * **No congestion control here.** A cell is sent when one is buffered;
//!   [`SendWindow::max_unacked`] and the application's own rate are the
//!   only brakes. Real congestion control (slow start, AIMD, a loss signal
//!   that reacts to RTT) lives in [`crate::congestion`].
//! * **No flow control.** `max_unacked` is a local memory bound, not a
//!   receiver window: the sender never learns how much the peer can
//!   absorb.
//! * **No stream multiplexing.** One [`SendWindow`] tracks one ordered
//!   stream.
//! * **Bindings are explicit.** The sender returns `(seq, datagram)` and
//!   accepts `(cumulative, bitmap)`; how those reach the wire is the
//!   caller's job, so this module has no socket, no event loop, and no
//!   global state.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;
use std::time::{Duration, Instant};

/// Sequence numbers are 32-bit unsigned, matching `LayerHeader::seq`.
pub const SEQ_MODULUS: u64 = 1u64 << 32;

/// How many sequence numbers a replay window tracks by default.
pub const DEFAULT_WINDOW: u32 = 1024;

/// Default retransmission timeout, in seconds.
pub const DEFAULT_RTO: f64 = 1.0;

/// Give up on a segment after this many retransmissions.
pub const DEFAULT_MAX_RETRIES: u32 = 5;

/// How many outstanding handshake requests a [`HandshakeReplayGuard`]
/// remembers by default. A CREATE is a one-shot request, so this only has
/// to cover requests that are still plausibly in flight -- it is not a
/// stream window.
pub const DEFAULT_HANDSHAKE_REPLAY_ENTRIES: usize = 4096;

/// How long, in seconds, a handshake request stays "seen". Past this a
/// repeat is treated as a fresh request rather than a replay, which bounds
/// memory without opening a practical replay window (the client would have
/// timed out long ago).
pub const DEFAULT_HANDSHAKE_REPLAY_TTL: f64 = 120.0;

/// Errors from the reliability layer.
///
/// The Python original has a small exception hierarchy (`ReliabilityError`
/// base; `NothingToSend`, `SendBufferFull` subclass it). Rust has no
/// hierarchy to subclass, so they are flattened into one enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReliabilityError {
    /// A generic invariant violation (bad constructor arguments, an
    /// unsafe `AckState::acked()` materialization, ...).
    Generic(String),
    /// An ack named a sequence number the window never sent. Declared for
    /// parity with the Python original, which never actually raises it
    /// either (kept as public API surface for a future caller).
    NothingToSend(String),
    /// The unacknowledged backlog exceeds the configured window.
    SendBufferFull(String),
}

impl std::fmt::Display for ReliabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReliabilityError::Generic(m) | ReliabilityError::NothingToSend(m) | ReliabilityError::SendBufferFull(m) => write!(f, "{m}"),
        }
    }
}
impl std::error::Error for ReliabilityError {}

// --------------------------------------------------------------------------
// Injectable clock (mirrors the Python `clock` constructor parameter)
// --------------------------------------------------------------------------

/// A source of monotonic time, injectable for deterministic tests --
/// mirroring the Python original's `clock` constructor parameter
/// (defaulting to `time.monotonic`).
pub trait Clock {
    fn now(&self) -> Instant;
}

/// The real wall clock.
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

impl<C: Clock + ?Sized> Clock for Rc<C> {
    fn now(&self) -> Instant {
        (**self).now()
    }
}

/// A settable clock for tests: starts at `Instant::now()` and only moves
/// when [`ManualClock::advance`] is called.
pub struct ManualClock {
    current: std::cell::Cell<Instant>,
}
impl ManualClock {
    pub fn new() -> Self {
        ManualClock { current: std::cell::Cell::new(Instant::now()) }
    }
    pub fn advance(&self, by: Duration) {
        self.current.set(self.current.get() + by);
    }
}
impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}
impl Clock for ManualClock {
    fn now(&self) -> Instant {
        self.current.get()
    }
}

fn default_clock() -> Box<dyn Clock> {
    Box::new(SystemClock)
}

// --------------------------------------------------------------------------
// A growable bitset (backs `ReplayWindow`'s sliding bitmap)
// --------------------------------------------------------------------------

/// A fixed-capacity bitset supporting the shift-and-set operations
/// [`ReplayWindow`] needs. Python's `_bitmap` is an arbitrary-precision
/// `int`; this is the Rust equivalent sized to exactly `bits` bits, since
/// `window` (the bitmap's width) is caller-configurable and not bounded to
/// 64 bits.
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

    /// Shift left by `n` bits, dropping anything past capacity (matching
    /// Python's `bitmap = (bitmap << n) & ((1 << window) - 1)`).
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
/// Tracks the highest sequence number accepted plus a bitmap of the
/// numbers just below it. A number is accepted once; anything already in
/// the bitmap, or more than `window` behind the high-water mark, is
/// rejected:
///
/// ```text
/// window.accept(0)   -> true    first time
/// window.accept(0)   -> false   duplicate
/// window.accept(5)   -> true    newer, advances the window
/// window.accept(1)   -> true    gap filled inside the window
/// window.accept(1)   -> false   duplicate again
/// ```
///
/// This is deliberately *not* the reordering buffer: it answers "have I
/// seen this?" while [`ReassemblyBuffer`] answers "what order does this go
/// in?".
pub struct ReplayWindow {
    pub window: u32,
    high: u32,
    bitmap: Bitset,
    primed: bool,
    pub accepted: u64,
    pub rejected: u64,
}

impl ReplayWindow {
    /// # Errors
    /// Returns [`ReliabilityError::Generic`] if `window` is zero.
    pub fn new(window: u32) -> Result<Self, ReliabilityError> {
        if window < 1 {
            return Err(ReliabilityError::Generic(format!("window must be at least 1, got {window}")));
        }
        Ok(ReplayWindow { window, high: 0, bitmap: Bitset::new(window as usize), primed: false, accepted: 0, rejected: 0 })
    }

    fn shift(&mut self, distance: u32) {
        if distance >= self.window {
            self.bitmap.clear();
        } else if distance > 0 {
            self.bitmap.shl_assign(distance as usize);
            self.bitmap.set(distance as usize - 1);
        }
    }

    /// Record `seq` and return whether it is new.
    ///
    /// Returns `true` if the number had not been seen, `false` for a
    /// duplicate or a number that has fallen off the back of the window.
    pub fn accept(&mut self, seq: u32) -> bool {
        if !self.primed {
            self.primed = true;
            self.high = seq;
            self.bitmap.clear();
            self.accepted += 1;
            return true;
        }

        let offset = seq.wrapping_sub(self.high);
        if offset == 0 {
            self.rejected += 1;
            return false;
        }
        if offset >= (1u32 << 31) {
            // Behind the high-water mark: a gap fill, or a stale replay.
            let distance = offset.wrapping_neg();
            if distance > self.window {
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

        // Ahead of the high-water mark: advance, dropping anything now too old.
        self.shift(offset);
        self.high = seq;
        self.accepted += 1;
        true
    }

    /// The highest sequence number accepted so far.
    pub fn high(&self) -> u32 {
        self.high
    }

    /// Return `true` if `seq` has already been accepted.
    pub fn seen(&self, seq: u32) -> bool {
        if !self.primed {
            return false;
        }
        let offset = seq.wrapping_sub(self.high);
        if offset == 0 {
            return true;
        }
        if offset >= (1u32 << 31) {
            let distance = offset.wrapping_neg();
            if distance > self.window {
                return true; // too old: treat as already handled
            }
            return self.bitmap.get(distance as usize - 1);
        }
        false
    }
}

// --------------------------------------------------------------------------
// Handshake replay suppression
// --------------------------------------------------------------------------

/// Rejects a replayed handshake request (a repeated CREATE).
///
/// A [`ReplayWindow`] suppresses replayed *DATA* cells by sequence number,
/// but a CREATE carries no sequence number -- it is a one-shot request
/// identified only by what the client put in it. Without a guard, an
/// attacker who captures a CREATE can replay it and make the relay
/// re-establish a circuit with the *same* handshake keys, because the
/// relay derives those keys deterministically from the client's public key
/// and its own private key.
///
/// A request is identified by an opaque key the caller builds -- for a
/// CREATE that is typically `(peer_ip, peer_port, circuit_id,
/// client_public_key)`, exactly the tuple that must not repeat for a
/// genuine new request. Entries expire after `ttl` seconds so memory stays
/// bounded.
///
/// This is deliberately *not* a [`ReplayWindow`]: there is no ordering and
/// no high-water mark, just a set of recent request identities.
pub struct HandshakeReplayGuard<K: Eq + std::hash::Hash + Clone> {
    pub max_entries: usize,
    pub ttl: Option<f64>,
    clock: Box<dyn Clock>,
    seen: HashMap<K, (u64, Instant)>,
    next_seq: u64,
    pub accepted: u64,
    pub rejected: u64,
}

impl<K: Eq + std::hash::Hash + Clone> HandshakeReplayGuard<K> {
    /// # Errors
    /// Returns [`ReliabilityError::Generic`] if `max_entries` is zero or
    /// `ttl` is not positive.
    pub fn new(max_entries: usize, ttl: Option<f64>, clock: Option<Box<dyn Clock>>) -> Result<Self, ReliabilityError> {
        if max_entries < 1 {
            return Err(ReliabilityError::Generic(format!("max_entries must be at least 1, got {max_entries}")));
        }
        if let Some(t) = ttl {
            if t <= 0.0 {
                return Err(ReliabilityError::Generic(format!("ttl must be positive or None, got {t}")));
            }
        }
        Ok(HandshakeReplayGuard {
            max_entries,
            ttl,
            clock: clock.unwrap_or_else(default_clock),
            seen: HashMap::new(),
            next_seq: 0,
            accepted: 0,
            rejected: 0,
        })
    }

    fn expire(&mut self) {
        let Some(ttl) = self.ttl else { return };
        let now = self.clock.now();
        let cutoff = Duration::from_secs_f64(ttl);
        self.seen.retain(|_, (_, seen_at)| now.saturating_duration_since(*seen_at) < cutoff);
    }

    /// Record `request` and report whether it is new.
    ///
    /// Returns `true` the first time a request is seen (process it),
    /// `false` on a repeat (drop it silently).
    pub fn accept(&mut self, request: &K) -> bool {
        self.expire();
        let now = self.clock.now();
        if let Some(entry) = self.seen.get_mut(request) {
            entry.1 = now;
            self.rejected += 1;
            return false;
        }
        if self.seen.len() >= self.max_entries {
            // Evict the oldest surviving entry by insertion order.
            if let Some(oldest) = self.seen.iter().min_by_key(|(_, (seq, _))| *seq).map(|(k, _)| k.clone()) {
                self.seen.remove(&oldest);
            }
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.seen.insert(request.clone(), (seq, now));
        self.accepted += 1;
        true
    }

    /// Return `true` if `request` is currently remembered.
    pub fn seen(&mut self, request: &K) -> bool {
        self.expire();
        self.seen.contains_key(request)
    }

    /// Drop a remembered request, returning whether it was present.
    ///
    /// Used when a circuit is torn down, so a legitimate retry after a
    /// DESTROY is not mistaken for a replay.
    pub fn forget(&mut self, request: &K) -> bool {
        self.seen.remove(request).is_some()
    }

    /// Forget every remembered request.
    pub fn clear(&mut self) {
        self.seen.clear();
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

// --------------------------------------------------------------------------
// Reordering
// --------------------------------------------------------------------------

/// Reorder out-of-order items into sequence order for delivery.
///
/// Feed whatever arrives to [`Self::push`]; it returns the items that are
/// now deliverable, in order. Anything that arrives early is held until
/// the gap before it is filled:
///
/// ```text
/// buf.push(1, b"b")  -> []            held, waiting for 0
/// buf.push(0, b"a")  -> [b"a", b"b"]  the gap filled, both released
/// ```
pub struct ReassemblyBuffer<T> {
    pub expected: u32,
    pub max_pending: usize,
    pending: BTreeMap<u32, T>,
    on_deliver: Option<Box<dyn FnMut(&T)>>,
    pub received: u64,
    pub duplicate: u64,
    pub evicted: u64,
}

impl<T> ReassemblyBuffer<T> {
    /// # Errors
    /// Returns [`ReliabilityError::Generic`] if `max_pending` is zero.
    pub fn new(start: u32, max_pending: usize) -> Result<Self, ReliabilityError> {
        if max_pending < 1 {
            return Err(ReliabilityError::Generic(format!("max_pending must be at least 1, got {max_pending}")));
        }
        Ok(ReassemblyBuffer { expected: start, max_pending, pending: BTreeMap::new(), on_deliver: None, received: 0, duplicate: 0, evicted: 0 })
    }

    pub fn set_on_deliver(&mut self, cb: Box<dyn FnMut(&T)>) {
        self.on_deliver = Some(cb);
    }

    /// Accept `item` at `seq` and return everything now deliverable.
    ///
    /// Returns items, in ascending sequence order, that can now be
    /// delivered. Empty when the item was buffered, was a duplicate, or
    /// was too old to matter.
    pub fn push(&mut self, seq: u32, item: T) -> Vec<T> {
        if seq < self.expected {
            self.duplicate += 1;
            return Vec::new();
        }
        if self.pending.contains_key(&seq) {
            self.duplicate += 1;
            return Vec::new();
        }

        self.received += 1;
        self.pending.insert(seq, item);

        // Bound memory: if a sender never fills a gap, give up on the oldest.
        while self.pending.len() > self.max_pending {
            if let Some((&oldest, _)) = self.pending.iter().next() {
                self.pending.remove(&oldest);
                self.evicted += 1;
            } else {
                break;
            }
        }

        let mut released = Vec::new();
        while let Some(item) = self.pending.remove(&self.expected) {
            released.push(item);
            self.expected = self.expected.wrapping_add(1);
        }

        if let Some(cb) = self.on_deliver.as_mut() {
            for item in &released {
                cb(item);
            }
        }
        released
    }

    /// How many out-of-order items are currently held.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// The sequence numbers currently held.
    pub fn held(&self) -> HashSet<u32> {
        self.pending.keys().copied().collect()
    }

    /// `true` when something is held but `expected` is missing.
    pub fn has_gap(&self) -> bool {
        !self.pending.is_empty() && !self.pending.contains_key(&self.expected)
    }

    /// Release everything held, in sequence order, and advance `expected`.
    pub fn flush(&mut self) -> Vec<T> {
        if self.pending.is_empty() {
            return Vec::new();
        }
        let highest = *self.pending.keys().next_back().expect("checked non-empty above");
        let keys: Vec<u32> = self.pending.keys().copied().collect();
        let mut released = Vec::with_capacity(keys.len());
        for k in keys {
            released.push(self.pending.remove(&k).expect("key just collected from this map"));
        }
        self.expected = self.expected.max(highest.wrapping_add(1));
        if let Some(cb) = self.on_deliver.as_mut() {
            for item in &released {
                cb(item);
            }
        }
        released
    }

    /// Drop all state and begin expecting `start` again.
    pub fn reset(&mut self, start: u32) {
        self.expected = start;
        self.pending.clear();
    }
}

// --------------------------------------------------------------------------
// Selective acknowledgment
// --------------------------------------------------------------------------

/// `.acked()` refuses to materialize a set larger than this. `cumulative`
/// is a plain 32-bit wire field (nothing stops a peer from sending
/// `0xFFFFFFFE`), and building a set of that many entries would try to
/// allocate on the order of 100+ GB from a single ACK cell, before any
/// authentication of the sender has happened.
pub const MAX_MATERIALIZABLE_CUMULATIVE: u64 = 1_000_000;

/// Width of the selective-ack bitmap, in bits/cells of lookahead past the
/// cumulative edge.
///
/// Widened from 32 to 128 (see [`LAYER_PROTOCOL_VERSION`
/// bump][crate::layer::LAYER_PROTOCOL_VERSION] this went with): a 32-bit
/// horizon is far smaller than [`crate::congestion::DEFAULT_MAX_CWND`]
/// (512 cells), so once the congestion window grew large -- exactly when
/// precise loss recovery matters most -- a receiver with gaps spread more
/// than 32 cells apart couldn't describe them in one ack, pushing loss
/// events toward an expensive timeout instead of a cheap selective
/// retransmit. 128 bits doesn't cover the full window either, but it's a
/// 4x wider horizon for the same "one machine word" simplicity.
pub const SACK_BITS: u32 = 128;

/// Decoded form of a SACK ack: a cumulative edge plus a bitmap of holes.
///
/// On the wire an ack is a 32-bit cumulative edge followed by a
/// [`SACK_BITS`]-bit bitmap:
///
/// * `cumulative` -- sequence numbers `0..cumulative` all arrived.
/// * `bitmap` -- bit *i* means `cumulative + i` arrived as well.
///
/// So `cumulative=3, bitmap=0b1010` reports 0, 1, 2 from the edge plus 4
/// and 6 from the bits: seqs 3 and 5 are missing.
#[derive(Debug, Clone, Copy)]
pub struct AckState {
    pub cumulative: u32,
    pub bitmap: u128,
}

impl AckState {
    pub fn new(cumulative: u32, bitmap: u128) -> Self {
        AckState { cumulative, bitmap }
    }

    /// Expand the cumulative edge and bitmap into a set of sequence
    /// numbers. O(cumulative); see [`Self::is_acked`]/[`Self::covers`] for
    /// the O(1) alternatives safe on attacker-controlled input.
    ///
    /// # Errors
    /// Returns [`ReliabilityError::Generic`] if `cumulative` exceeds
    /// [`MAX_MATERIALIZABLE_CUMULATIVE`].
    pub fn acked(&self) -> Result<HashSet<u32>, ReliabilityError> {
        if u64::from(self.cumulative) > MAX_MATERIALIZABLE_CUMULATIVE {
            return Err(ReliabilityError::Generic(format!(
                "refusing to materialize {} sequence numbers into a set (limit is {MAX_MATERIALIZABLE_CUMULATIVE}); \
                 use is_acked() or covers() instead, which are O(1) and safe for an attacker-controlled cumulative value",
                self.cumulative
            )));
        }
        if self.cumulative == 0 && self.bitmap == 0 {
            return Ok(HashSet::new());
        }
        let mut acked: HashSet<u32> = (0..self.cumulative).collect();
        for bit in 0..SACK_BITS {
            if self.bitmap & (1u128 << bit) != 0 {
                acked.insert(self.cumulative + bit);
            }
        }
        Ok(acked)
    }

    /// Build an ack describing a set of received sequence numbers.
    ///
    /// The cumulative edge is the length of the contiguous run starting at
    /// 0, which is the honest answer when the run is unbroken. When there
    /// is a hole, the edge is pulled back so the whole descriptor fits the
    /// [`SACK_BITS`]-bit bitmap.
    pub fn from_received(received: impl IntoIterator<Item = u32>) -> Self {
        let mut numbers: Vec<u32> = received.into_iter().collect();
        numbers.sort_unstable();
        numbers.dedup();
        if numbers.is_empty() {
            return AckState { cumulative: 0, bitmap: 0 };
        }
        let present: HashSet<u32> = numbers.iter().copied().collect();
        let mut cumulative: u32 = 0;
        while present.contains(&cumulative) {
            cumulative += 1;
        }
        if cumulative == 0 {
            // Nothing from 0 upwards, so window the descriptor around the
            // highest number instead of reporting an empty cumulative edge.
            let last = *numbers.last().expect("checked non-empty above");
            cumulative = last.saturating_sub(SACK_BITS - 1);
            while cumulative > 0 && present.contains(&(cumulative - 1)) {
                cumulative -= 1;
            }
        }
        let mut bitmap: u128 = 0;
        for &n in &numbers {
            if n >= cumulative {
                let offset = n - cumulative;
                if offset < SACK_BITS {
                    bitmap |= 1u128 << offset;
                }
            }
        }
        AckState { cumulative, bitmap }
    }

    /// Return `true` if this ack says `seq` arrived. O(1) -- safe to call
    /// with an attacker-controlled `cumulative`/`bitmap`.
    pub fn is_acked(&self, seq: u32) -> bool {
        if seq < self.cumulative {
            return true;
        }
        let offset = seq - self.cumulative;
        offset < SACK_BITS && self.bitmap & (1u128 << offset) != 0
    }

    /// Return `true` if `seq` falls inside the range this ack describes.
    pub fn covers(&self, seq: u32) -> bool {
        if seq < self.cumulative {
            return true;
        }
        u64::from(seq) < u64::from(self.cumulative) + u64::from(SACK_BITS)
    }
}

impl PartialEq for AckState {
    fn eq(&self, other: &Self) -> bool {
        (self.cumulative, self.bitmap) == (other.cumulative, other.bitmap)
    }
}
impl Eq for AckState {}

impl std::fmt::Display for AckState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AckState(cumulative={}, selective={})", self.cumulative, self.bitmap.count_ones())
    }
}

/// Decides *when* to emit an ack, and never emits a redundant one.
///
/// [`ReassemblyBuffer`] knows what arrived; [`AckState`] knows how to
/// describe it. Neither decides whether sending an ack right now is
/// useful, which is what this class is for.
///
/// Two rules, both load-bearing:
///
/// * **Ack on a detected hole, immediately.** A gap is the one case where
///   the sender is waiting for information it cannot infer, so it is
///   reported at once.
/// * **Do not re-ack the same state.** Sending an identical ack is not
///   merely wasteful: [`SendWindow::on_duplicate_ack`] treats repeated
///   acks as *loss evidence* and fast-retransmits. A receiver that acked
///   every cell it received would therefore induce spurious
///   retransmissions of cells that were never lost.
pub struct AckTracker<T> {
    pub buffer: ReassemblyBuffer<T>,
    pub ack_every: u32,
    // Mirrors the Python original's `_clock`: stored on every construction
    // but never actually read by any method there either -- reserved
    // state, kept here only for field-for-field parity.
    #[allow(dead_code)]
    clock: Box<dyn Clock>,
    last_pair: Option<(u32, u128)>,
    since_ack: u32,
    /// Whether the hole currently open has already been reported, so a
    /// recalcitrant gap does not generate an ack on every subsequent cell.
    hole_reported: bool,
    pub emitted: u64,
    pub suppressed: u64,
    pub timely: u64,
    pub periodic: u64,
}

impl<T> AckTracker<T> {
    /// # Errors
    /// Returns [`ReliabilityError::Generic`] if `ack_every` is zero, or
    /// propagates [`ReassemblyBuffer::new`]'s error for `max_pending`.
    pub fn new(start: u32, ack_every: u32, max_pending: usize, clock: Option<Box<dyn Clock>>) -> Result<Self, ReliabilityError> {
        if ack_every < 1 {
            return Err(ReliabilityError::Generic(format!("ack_every must be at least 1, got {ack_every}")));
        }
        Ok(AckTracker {
            buffer: ReassemblyBuffer::new(start, max_pending)?,
            ack_every,
            clock: clock.unwrap_or_else(default_clock),
            last_pair: None,
            since_ack: 0,
            hole_reported: false,
            emitted: 0,
            suppressed: 0,
            timely: 0,
            periodic: 0,
        })
    }

    /// Accept a cell and return whatever is now deliverable in order.
    ///
    /// A cell the buffer rejects as a duplicate or as too old must not
    /// reset the ack counter, otherwise a duplicate would re-arm
    /// `ack_every` and the next [`Self::maybe_ack`] would emit a
    /// descriptor identical to the previous one -- the duplicate-ack
    /// signal that provokes spurious fast retransmits.
    pub fn receive(&mut self, seq: u32, item: T) -> Vec<T> {
        let before = self.buffer.received;
        let released = self.buffer.push(seq, item);
        if self.buffer.received > before {
            self.since_ack += 1;
        } else {
            self.suppressed += 1;
        }
        released
    }

    /// Describe everything received so far, without emitting an ack.
    ///
    /// O(1) (plus the bounded, `max_pending`-capped `held()` set) in the
    /// common case -- deliberately not
    /// `AckState::from_received(0..self.buffer.expected)`, which used to
    /// materialize and sort/dedup a `Vec` of that size on every call.
    /// `ack_every` only gates whether an ack is *emitted*, not whether one
    /// is computed (`maybe_ack`/`force_ack` both call this
    /// unconditionally), so that was O(N) per cell -> O(N^2) total CPU and
    /// allocation over an ordinary, protocol-valid, in-order stream's life
    /// (e.g. a large download), no malformed input required.
    /// `self.buffer.expected` already *is* the honest cumulative edge --
    /// [`ReassemblyBuffer::push`] only ever advances it past a contiguous
    /// run from `start`, and never holds anything below it -- so there is
    /// nothing left to derive from a materialized `0..expected` range.
    ///
    /// The one case that still needs `from_received`'s windowing: nothing
    /// has arrived contiguously from `start` yet (`expected == start`,
    /// i.e. still 0 in every real caller), but out-of-order data is held
    /// far enough past it to fall outside `SACK_BITS` -- a first packet
    /// lost or delayed behind thousands of reordered ones is a real
    /// pattern, not a contrived one. Reporting a bare `(0, 0)` there (as
    /// an earlier version of this fix did) would silently claim nothing
    /// had arrived at all, discarding real progress information a peer
    /// needs for accurate selective retransmission. Delegating to
    /// `from_received(held())` for just this branch is still bounded --
    /// `held()`'s size is capped by `max_pending`, a small fixed
    /// constant, unlike `expected`, which is what actually grew
    /// unboundedly over a stream's life in the original bug.
    pub fn current(&self) -> AckState {
        let cumulative = self.buffer.expected;
        if cumulative == 0 {
            return AckState::from_received(self.buffer.held());
        }
        let mut bitmap: u128 = 0;
        for seq in self.buffer.held() {
            if seq >= cumulative {
                let offset = seq - cumulative;
                if offset < SACK_BITS {
                    bitmap |= 1u128 << offset;
                }
            }
        }
        AckState::new(cumulative, bitmap)
    }

    /// Return an ack to send now, or `None` if one is not warranted.
    pub fn maybe_ack(&mut self) -> Option<AckState> {
        // Nothing has arrived, so there is nothing to report. Emitting the
        // empty descriptor (0, 0) would be worse than useless: it would
        // be cached as the previous ack, and the next *genuine* ack of
        // the same shape would then be suppressed as a duplicate.
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
        state
    }
}

// --------------------------------------------------------------------------
// SendWindow
// --------------------------------------------------------------------------

struct SendRecord {
    datagram: Vec<u8>,
    #[allow(dead_code)] // kept for field-for-field parity with the Python tuple entry
    first_sent: Instant,
    last_sent: Instant,
    attempts: u32,
}

/// A minimal SACK-based reliable sender over an unreliable datagram layer.
///
/// Three recovery mechanisms, in increasing aggressiveness:
///
/// * **cumulative ack** -- everything below the peer's edge is freed at once.
/// * **selective ack (SACK)** -- the bitmap frees individual cells *above*
///   the edge, so one lost cell does not stall the cells behind it.
/// * **fast retransmit** -- `duplicate_ack_threshold` identical acks are
///   treated as evidence that the cell after the edge was lost, so it is
///   resent without waiting out the timeout.
pub struct SendWindow {
    pub rto: f64,
    pub max_retries: u32,
    pub max_unacked: usize,
    pub duplicate_ack_threshold: u32,
    clock: Box<dyn Clock>,
    next_seq: u32,
    outstanding: BTreeMap<u32, SendRecord>,
    acked_set: HashSet<u32>,
    last_ack: Option<(u32, u128)>,
    duplicate_acks: u32,
    pub sent: u64,
    pub acked: u64,
    pub retransmitted: u64,
    pub dropped: u64,
}

impl SendWindow {
    pub fn new(rto: f64, max_retries: u32, max_unacked: usize, duplicate_ack_threshold: u32, clock: Option<Box<dyn Clock>>) -> Self {
        SendWindow {
            rto,
            max_retries,
            max_unacked,
            duplicate_ack_threshold,
            clock: clock.unwrap_or_else(default_clock),
            next_seq: 0,
            outstanding: BTreeMap::new(),
            acked_set: HashSet::new(),
            last_ack: None,
            duplicate_acks: 0,
            sent: 0,
            acked: 0,
            retransmitted: 0,
            dropped: 0,
        }
    }

    /// Buffer `datagram` and return its sequence number.
    ///
    /// # Errors
    /// Returns [`ReliabilityError::SendBufferFull`] if the unacknowledged
    /// backlog is at `max_unacked`.
    pub fn append(&mut self, datagram: &[u8]) -> Result<u32, ReliabilityError> {
        if self.outstanding.len() >= self.max_unacked {
            return Err(ReliabilityError::SendBufferFull(format!(
                "{} unacknowledged cells at the {}-cell limit",
                self.outstanding.len(),
                self.max_unacked
            )));
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let now = self.clock.now();
        self.outstanding.insert(seq, SendRecord { datagram: datagram.to_vec(), first_sent: now, last_sent: now, attempts: 0 });
        Ok(seq)
    }

    /// Return the cells to transmit now, first-time or retransmitted.
    ///
    /// `limit` caps how many cells *never sent before* this call may go
    /// out; a cell that is already outstanding and whose RTO has expired
    /// is always returned regardless of `limit`.
    pub fn due(&mut self, limit: Option<usize>) -> Vec<(u32, Vec<u8>)> {
        let now = self.clock.now();
        let rto = Duration::from_secs_f64(self.rto.max(0.0));
        let mut out = Vec::new();
        let mut first_sends = 0usize;
        let seqs: Vec<u32> = self.outstanding.keys().copied().collect();
        let mut to_drop = Vec::new();

        for seq in seqs {
            let (attempts, last_sent) = {
                let record = self.outstanding.get(&seq).expect("key just collected from this map");
                (record.attempts, record.last_sent)
            };
            if attempts != 0 && now.saturating_duration_since(last_sent) < rto {
                continue;
            }
            if attempts >= self.max_retries {
                to_drop.push(seq);
                self.dropped += 1;
                continue;
            }
            let is_first_send = attempts == 0;
            if is_first_send {
                if let Some(l) = limit {
                    if first_sends >= l {
                        continue;
                    }
                }
            }
            let record = self.outstanding.get_mut(&seq).expect("key just collected from this map");
            record.last_sent = now;
            record.attempts += 1;
            if is_first_send {
                first_sends += 1;
            } else {
                self.retransmitted += 1;
            }
            self.sent += 1;
            out.push((seq, record.datagram.clone()));
        }
        for seq in to_drop {
            self.outstanding.remove(&seq);
        }
        out
    }

    /// How many cells are still unacknowledged.
    pub fn pending(&self) -> usize {
        self.outstanding.len()
    }

    /// Apply an incoming ack, returning the sequence numbers it freed.
    pub fn on_ack(&mut self, cumulative: u32, bitmap: u128) -> HashSet<u32> {
        let state = AckState::new(cumulative, bitmap);
        let mut freed = HashSet::new();
        let seqs: Vec<u32> = self.outstanding.keys().copied().collect();
        for seq in seqs {
            if state.is_acked(seq) {
                self.outstanding.remove(&seq);
                if self.acked_set.insert(seq) {
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
    ///
    /// Returns the sequence number to resend immediately, or `None` when
    /// the threshold has not been reached or nothing is outstanding above
    /// the edge.
    pub fn on_duplicate_ack(&mut self) -> Option<u32> {
        self.duplicate_acks += 1;
        if self.duplicate_acks < self.duplicate_ack_threshold {
            return None;
        }
        let cumulative = self.last_ack?.0;
        let seq = *self.outstanding.range(cumulative..).next()?.0;
        let now = self.clock.now();
        if let Some(record) = self.outstanding.get_mut(&seq) {
            record.first_sent = now;
            record.last_sent = now;
            record.attempts += 1;
        }
        self.retransmitted += 1;
        self.sent += 1;
        self.duplicate_acks = 0;
        Some(seq)
    }

    /// Adjust the timeout from an observed round trip, as a simple EWMA.
    pub fn update_rto(&mut self, sample: f64) {
        self.rto = (0.875 * self.rto + 0.125 * sample.max(0.0)).max(0.05);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_basic_dedup_and_advance() {
        let mut w = ReplayWindow::new(16).unwrap();
        assert!(w.accept(0));
        assert!(!w.accept(0));
        assert!(w.accept(5));
        assert!(w.accept(1));
        assert!(!w.accept(1));
        assert_eq!(w.high(), 5);
    }

    #[test]
    fn replay_window_rejects_too_old() {
        let mut w = ReplayWindow::new(4).unwrap();
        assert!(w.accept(100));
        assert!(!w.accept(90)); // far behind the window
        assert!(w.accept(99));
        assert!(!w.accept(99));
    }

    #[test]
    fn replay_window_seen_matches_accept_without_mutating() {
        let mut w = ReplayWindow::new(8).unwrap();
        w.accept(10);
        assert!(w.seen(10));
        assert!(!w.seen(9));
        w.accept(9);
        assert!(w.seen(9));
    }

    #[test]
    fn replay_window_rejects_zero_window() {
        assert!(ReplayWindow::new(0).is_err());
    }

    #[test]
    fn handshake_replay_guard_dedups_and_evicts_oldest() {
        let mut g: HandshakeReplayGuard<u32> = HandshakeReplayGuard::new(2, None, None).unwrap();
        assert!(g.accept(&1));
        assert!(!g.accept(&1));
        assert!(g.accept(&2));
        // At capacity (2); a third distinct key evicts the oldest (1).
        assert!(g.accept(&3));
        assert_eq!(g.len(), 2);
        assert!(!g.seen(&1));
        assert!(g.seen(&2));
        assert!(g.seen(&3));
    }

    #[test]
    fn handshake_replay_guard_forget_allows_retry() {
        let mut g: HandshakeReplayGuard<u32> = HandshakeReplayGuard::new(10, None, None).unwrap();
        assert!(g.accept(&1));
        assert!(g.forget(&1));
        assert!(g.accept(&1));
    }

    #[test]
    fn handshake_replay_guard_ttl_expiry() {
        let clock = Rc::new(ManualClock::new());
        let mut g: HandshakeReplayGuard<u32> = HandshakeReplayGuard::new(10, Some(5.0), Some(Box::new(clock.clone()))).unwrap();
        assert!(g.accept(&1));
        clock.advance(Duration::from_secs(10));
        // Expired: treated as a fresh request.
        assert!(g.accept(&1));
    }

    #[test]
    fn reassembly_buffer_out_of_order_release() {
        let mut b: ReassemblyBuffer<Vec<u8>> = ReassemblyBuffer::new(0, 16).unwrap();
        assert!(b.push(1, b"b".to_vec()).is_empty());
        assert_eq!(b.push(0, b"a".to_vec()), vec![b"a".to_vec(), b"b".to_vec()]);
    }

    #[test]
    fn reassembly_buffer_evicts_min_key_over_capacity() {
        let mut b: ReassemblyBuffer<u8> = ReassemblyBuffer::new(0, 2).unwrap();
        b.push(5, 5);
        b.push(6, 6);
        b.push(7, 7); // over capacity: evict min (5), not max
        assert_eq!(b.held(), [6, 7].into_iter().collect());
        assert_eq!(b.evicted, 1);
    }

    #[test]
    fn reassembly_buffer_flush_releases_all_and_advances_expected() {
        let mut b: ReassemblyBuffer<u8> = ReassemblyBuffer::new(0, 16).unwrap();
        b.push(2, 2);
        b.push(4, 4);
        let flushed = b.flush();
        assert_eq!(flushed, vec![2, 4]);
        assert_eq!(b.expected, 5);
        assert!(!b.has_gap());
    }

    #[test]
    fn ack_state_from_received_no_holes() {
        let s = AckState::from_received([0, 1, 2, 3]);
        assert_eq!(s.cumulative, 4);
        assert_eq!(s.bitmap, 0);
    }

    #[test]
    fn ack_state_from_received_with_hole() {
        let s = AckState::from_received([0, 1, 3]);
        assert_eq!(s.cumulative, 2);
        assert!(s.is_acked(0));
        assert!(s.is_acked(1));
        assert!(!s.is_acked(2));
        assert!(s.is_acked(3));
    }

    #[test]
    fn ack_state_acked_matches_is_acked_membership() {
        let s = AckState::from_received([0, 1, 3, 5]);
        let materialized = s.acked().unwrap();
        for i in 0..40u32 {
            assert_eq!(materialized.contains(&i), s.is_acked(i), "mismatch at {i}");
        }
    }

    #[test]
    fn ack_state_acked_refuses_huge_cumulative() {
        let s = AckState::new(u32::MAX, 0);
        assert!(s.acked().is_err());
        // is_acked/covers stay O(1)-safe regardless.
        assert!(s.is_acked(0));
        assert!(s.covers(0));
    }

    #[test]
    fn ack_tracker_acks_on_hole_and_suppresses_repeats() {
        let mut t: AckTracker<()> = AckTracker::new(0, 100, 16, None).unwrap();
        t.receive(0, ());
        assert!(t.maybe_ack().is_none()); // no gap, not enough since last ack
        t.receive(2, ()); // creates a gap
        let ack1 = t.maybe_ack().unwrap();
        assert!(t.buffer.has_gap());
        assert_eq!(ack1.cumulative, 1);
        // Same gap, already reported: suppressed.
        assert!(t.maybe_ack().is_none());
    }

    #[test]
    fn ack_tracker_current_matches_from_received_semantics_with_a_hole() {
        let mut t: AckTracker<()> = AckTracker::new(0, 1, 16, None).unwrap();
        t.receive(0, ());
        t.receive(1, ());
        t.receive(3, ()); // held out of order, creates a gap at 2
        let state = t.current();
        let expected = AckState::from_received([0u32, 1, 3]);
        assert_eq!(state, expected);
        assert_eq!(state.cumulative, 2);
        assert!(state.is_acked(3));
        assert!(!state.is_acked(2));
    }

    #[test]
    fn ack_tracker_current_windows_around_far_out_of_order_data_when_nothing_from_zero_arrived() {
        // Regression test: an earlier version of the O(1) `current()` fix
        // dropped `AckState::from_received`'s windowing behavior for the
        // case where seq 0 itself hasn't arrived yet but something held
        // far past it has -- a real pattern (a lost/delayed first packet
        // behind thousands of reordered ones), not a contrived one.
        // Silently reporting `(cumulative=0, bitmap=0)` there would claim
        // nothing had arrived at all, discarding real progress
        // information a peer needs for accurate selective retransmission.
        let mut t: AckTracker<()> = AckTracker::new(0, 1, 8192, None).unwrap();
        t.receive(500, ()); // far beyond SACK_BITS=128, seq 0 never arrives
        let state = t.current();
        let expected = AckState::from_received([500u32]);
        assert_eq!(state, expected);
        assert_ne!(state, AckState::new(0, 0), "must not silently report nothing received");
        assert!(state.is_acked(500));
    }

    #[test]
    fn ack_tracker_current_is_cheap_for_a_long_contiguous_stream() {
        // Regression test for the O(N) `current()` -> O(N^2)-per-stream
        // bug: previously this rebuilt and re-sorted a `Vec` of size
        // `expected` on every call. 200k calls over a stream this long
        // would not finish in any reasonable time under the old
        // implementation; this only exercises correctness + a generous
        // wall-clock bound, not a strict complexity proof.
        let mut t: AckTracker<()> = AckTracker::new(0, 1, 16, None).unwrap();
        let n: u32 = 200_000;
        let start = std::time::Instant::now();
        for seq in 0..n {
            t.receive(seq, ());
            let state = t.current();
            assert_eq!(state.cumulative, seq + 1);
            assert_eq!(state.bitmap, 0);
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(5), "current() looks like it regressed back to O(N) per call");
    }

    #[test]
    fn send_window_basic_append_due_ack_flow() {
        let mut w = SendWindow::new(1.0, 5, 1024, 3, None);
        let seq = w.append(b"hello").unwrap();
        let due = w.due(None);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].0, seq);
        let freed = w.on_ack(seq + 1, 0);
        assert_eq!(freed, [seq].into_iter().collect());
        assert_eq!(w.pending(), 0);
    }

    #[test]
    fn send_window_full_buffer_rejects_append() {
        let mut w = SendWindow::new(1.0, 5, 1, 3, None);
        w.append(b"a").unwrap();
        assert!(w.append(b"b").is_err());
    }

    #[test]
    fn send_window_duplicate_ack_triggers_fast_retransmit() {
        let mut w = SendWindow::new(1.0, 5, 1024, 3, None);
        let s0 = w.append(b"a").unwrap();
        let _s1 = w.append(b"b").unwrap();
        w.due(None); // mark both as sent once
        w.on_ack(s0, 0); // acks s0 only, edge = s0's cumulative boundary... see below
        assert!(w.on_duplicate_ack().is_none());
        assert!(w.on_duplicate_ack().is_none());
        // Third identical-shape duplicate reaches the threshold of 3.
        let resent = w.on_duplicate_ack();
        assert!(resent.is_some());
    }

    #[test]
    fn send_window_update_rto_is_ewma() {
        let mut w = SendWindow::new(1.0, 5, 1024, 3, None);
        w.update_rto(0.2);
        let expected = (0.875 * 1.0f64 + 0.125 * 0.2).max(0.05);
        assert!((w.rto - expected).abs() < 1e-12);
    }
}

#[cfg(test)]
mod python_cross_check {
    use super::*;

    // Ground truth generated by running the real Python `allium.reliability`
    // module against these exact scripted operation sequences (see the
    // accompanying commands in each test).

    #[test]
    fn replay_window_matches_python_small_window() {
        // python3 -c "
        //   import allium.reliability as r
        //   w = r.ReplayWindow(window=8)
        //   seq = [10, 10, 15, 12, 9, 20, 13, 5, 19, 21]
        //   print([w.accept(s) for s in seq])
        //   print(w.high, w.accepted, w.rejected)
        //   print([w.seen(s) for s in [5,9,10,12,13,15,18,19,20,21,2]])
        // "
        let mut w = ReplayWindow::new(8).unwrap();
        let seq = [10, 10, 15, 12, 9, 20, 13, 5, 19, 21];
        let results: Vec<bool> = seq.iter().map(|&s| w.accept(s)).collect();
        assert_eq!(results, vec![true, false, true, true, true, true, true, false, true, true]);
        assert_eq!(w.high(), 21);
        assert_eq!(w.accepted, 8);
        assert_eq!(w.rejected, 2);

        let seen_queries = [5, 9, 10, 12, 13, 15, 18, 19, 20, 21, 2];
        let seen: Vec<bool> = seen_queries.iter().map(|&s| w.seen(s)).collect();
        assert_eq!(seen, vec![true, true, true, true, true, true, false, true, true, true, true]);
    }

    #[test]
    fn replay_window_matches_python_default_window_multiword_bitset() {
        // python3 -c "
        //   import allium.reliability as r
        //   w = r.ReplayWindow(window=1024)
        //   seq = [1000, 500, 1005, 998, 2000, 1500, 1999, 2001, 100, 1970, 3100, 3099, 3200, 2100]
        //   print([w.accept(s) for s in seq])
        //   print(w.high, w.accepted, w.rejected)
        // "
        let mut w = ReplayWindow::new(1024).unwrap();
        let seq = [1000, 500, 1005, 998, 2000, 1500, 1999, 2001, 100, 1970, 3100, 3099, 3200, 2100];
        let results: Vec<bool> = seq.iter().map(|&s| w.accept(s)).collect();
        assert_eq!(results, vec![true, true, true, true, true, true, true, true, false, true, true, true, true, false]);
        assert_eq!(w.high(), 3200);
        assert_eq!(w.accepted, 12);
        assert_eq!(w.rejected, 2);
    }

    #[test]
    fn ack_state_from_received_matches_python() {
        // python3 -c "
        //   import allium.reliability as r
        //   for c in [[], [0,1,2,3,4], [0,1,3], [5,6,7,40], [100,101,102], list(range(34))]:
        //       s = r.AckState.from_received(c)
        //       print(c, '->', s.cumulative, s.bitmap)
        // "  ->  (0,0) / (5,0) / (2,2) / (9,2147483648) / (71,3758096384) / (34,0)
        //
        // The last two cases are where this port now intentionally diverges
        // from the Python reference, because SACK_BITS widened from 32 to
        // 128 (see its doc comment): both inputs have a gap wider than 32
        // between the run-start and the last number, so Python's 32-bit
        // window has to pull `cumulative` forward and silently drop the
        // numbers that fall below it (e.g. for [5,6,7,40], Python's
        // cumulative=9 can't represent 5, 6, or 7 at all -- they're neither
        // covered by the cumulative edge nor representable in the 32-bit
        // bitmap, so that ack quietly loses information about cells that
        // did arrive). With a 128-bit window every number here fits
        // directly in the bitmap, so cumulative stays 0 and nothing is
        // dropped -- a strictly more informative ack, not just a
        // differently-shaped one. The first four cases are unaffected by
        // the window width and still match Python exactly.
        let cases: Vec<(Vec<u32>, u32, u128)> = vec![
            (vec![], 0, 0),
            (vec![0, 1, 2, 3, 4], 5, 0),
            (vec![0, 1, 3], 2, 2),
            (vec![5, 6, 7, 40], 0, (1u128 << 5) | (1u128 << 6) | (1u128 << 7) | (1u128 << 40)), // Python: (9, 2147483648)
            (vec![100, 101, 102], 0, (1u128 << 100) | (1u128 << 101) | (1u128 << 102)),         // Python: (71, 3758096384)
            ((0u32..34).collect(), 34, 0),
        ];
        for (numbers, cumulative, bitmap) in cases {
            let s = AckState::from_received(numbers.clone());
            assert_eq!((s.cumulative, s.bitmap), (cumulative, bitmap), "input {numbers:?}");
        }
    }

    #[test]
    fn send_window_due_and_ack_timing_matches_python() {
        // python3 -c "
        //   import allium.reliability as r
        //   class ManualClock:
        //       def __init__(self): self.t = 0.0
        //       def advance(self, d): self.t += d
        //       def __call__(self): return self.t
        //   clk = ManualClock()
        //   w = r.SendWindow(rto=1.0, max_retries=5, max_unacked=1024,
        //       duplicate_ack_threshold=3, clock=clk)
        //   s0 = w.append(b'aaa'); s1 = w.append(b'bbb')
        //   print(w.due())
        //   clk.advance(0.5); print(w.due())
        //   clk.advance(0.6); print(w.due())
        //   print(sorted(w.on_ack(s1 + 1, 0)), w.pending())
        // "
        let clock = Rc::new(ManualClock::new());
        let mut w = SendWindow::new(1.0, 5, 1024, 3, Some(Box::new(clock.clone())));
        let s0 = w.append(b"aaa").unwrap();
        let s1 = w.append(b"bbb").unwrap();
        assert_eq!((s0, s1), (0, 1));

        let due1 = w.due(None);
        assert_eq!(due1, vec![(0, b"aaa".to_vec()), (1, b"bbb".to_vec())]);

        clock.advance(Duration::from_secs_f64(0.5));
        assert!(w.due(None).is_empty());

        clock.advance(Duration::from_secs_f64(0.6));
        let due3 = w.due(None);
        assert_eq!(due3, vec![(0, b"aaa".to_vec()), (1, b"bbb".to_vec())]);

        let freed = w.on_ack(s1 + 1, 0);
        assert_eq!(freed, [0u32, 1u32].into_iter().collect());
        assert_eq!(w.pending(), 0);
    }

    #[test]
    fn send_window_fast_retransmit_returns_exact_seq_matching_python() {
        // python3 -c "
        //   import allium.reliability as r
        //   w = r.SendWindow(rto=1.0, max_retries=5, max_unacked=1024, duplicate_ack_threshold=3)
        //   a0 = w.append(b'x'); a1 = w.append(b'y')
        //   w.due()
        //   w.on_ack(a0, 0)
        //   print(w.on_duplicate_ack(), w.on_duplicate_ack(), w.on_duplicate_ack())
        // "
        let mut w = SendWindow::new(1.0, 5, 1024, 3, None);
        let a0 = w.append(b"x").unwrap();
        let _a1 = w.append(b"y").unwrap();
        w.due(None);
        w.on_ack(a0, 0);
        assert_eq!(w.on_duplicate_ack(), None);
        assert_eq!(w.on_duplicate_ack(), None);
        assert_eq!(w.on_duplicate_ack(), Some(0));
    }

    #[test]
    fn handshake_replay_guard_matches_python_eviction_and_ttl() {
        // python3 -c "
        //   import allium.reliability as r
        //   class ManualClock:
        //       def __init__(self): self.t = 0.0
        //       def advance(self, d): self.t += d
        //       def __call__(self): return self.t
        //   clk = ManualClock()
        //   g = r.HandshakeReplayGuard(max_entries=3, ttl=10.0, clock=clk)
        //   keys = [('a',), ('b',), ('c',), ('a',), ('d',)]
        //   print([g.accept(k) for k in keys])
        //   print(len(g))
        //   clk.advance(15)
        //   print(g.accept(('a',)))
        // "
        let clock = Rc::new(ManualClock::new());
        let mut g: HandshakeReplayGuard<char> = HandshakeReplayGuard::new(3, Some(10.0), Some(Box::new(clock.clone()))).unwrap();
        let keys = ['a', 'b', 'c', 'a', 'd'];
        let results: Vec<bool> = keys.iter().map(|k| g.accept(k)).collect();
        assert_eq!(results, vec![true, true, true, false, true]);
        assert_eq!(g.len(), 3);
        clock.advance(Duration::from_secs(15));
        assert!(g.accept(&'a'));
    }
}
