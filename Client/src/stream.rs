//! Client-side reliable stream over a Allium circuit.
//!
//! The relay half of the ack loop lives outside this crate; this is the
//! other end, the piece that decides *when to send and when to resend*. It
//! exists so a caller can move bytes over a circuit without hand-driving
//! [`crate::reliability::SendWindow`], which is what a bare demo would
//! otherwise have to do.
//!
//! The division of labour is deliberate:
//!
//! * [`crate::reliability::SendWindow`] owns *what* is outstanding and when
//!   it is due, including retransmission and fast-retransmit.
//! * [`crate::reliability::AckTracker`] owns *when to ack* inbound cells.
//! * This module owns the loop that connects them to a transport, plus the
//!   bookkeeping that is only meaningful once a real circuit is involved.
//! * [`CircuitSession`] is the part that actually runs: it pumps
//!   [`CircuitSender`] on a timer against a live transport, applies inbound
//!   acks, and emits cover traffic while idle. Without it the SACK
//!   machinery is correct but nothing ever calls it.
//!
//! Nothing here opens a socket. A transport is any `FnMut(&[u8])`, so the
//! whole module is testable without a network.
//!
//! # Deviation from the Python original: no `asyncio`
//!
//! Python's `CircuitSession` is an `asyncio.Task`: `run()` is a coroutine
//! that a `start()` call schedules onto whichever event loop is current,
//! and `stop()` cancels it. This crate has no async runtime dependency
//! anywhere -- every other blocking-I/O module in it
//! ([`crate::handshake`], [`crate::circuit`]) uses plain synchronous
//! sockets -- so `CircuitSession` here is a plain synchronous struct
//! instead: [`CircuitSession::run_until`] blocks the calling thread,
//! running exactly the loop body Python's `run()` runs, until a
//! caller-supplied predicate says to stop. There is no implicit background
//! task; a caller that wants this to run concurrently with other work
//! spawns its own thread and calls `run_until` from it, same as it would
//! have to schedule the asyncio task onto a loop in Python. Because the
//! session shares its transport and sender state through `Rc`/`RefCell`
//! (this module has no concurrency of its own to guard against), the whole
//! session must be built and driven on that one thread -- see
//! [`CircuitSession`]'s own docs.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::congestion::CongestionController;
use crate::fragment::{decode_fragment, encode_fragment, Fragmenter, Reassembler, FragmentError};
use crate::layer::{decode_ack, encode_ack};
use crate::reliability::{AckTracker, Clock, ReliabilityError, SendWindow, DEFAULT_MAX_RETRIES, DEFAULT_RTO};

/// Default `max_pending` for the ack tracker's reassembly buffer and the
/// fragment reassembler, matching the Python originals' inline `4096`
/// default (neither module names it as a constant either).
const DEFAULT_MAX_PENDING: usize = 4096;

/// Default `duplicate_ack_threshold` for a [`SendWindow`] built by this
/// module, matching [`crate::reliability::SendWindow`]'s own Python
/// default of `3` (not otherwise overridden by `CircuitSender`).
const DEFAULT_DUPLICATE_ACK_THRESHOLD: u32 = 3;

/// How often [`CircuitSession::run_until`] pumps the send window, in
/// seconds. Well below the default RTO so a retransmission is never late
/// because the timer was coarse.
pub const DEFAULT_PUMP_INTERVAL: Duration = Duration::from_millis(10);

/// How often an idle session emits a cover cell. [`Duration::ZERO`]
/// disables it. Chosen to be slow enough not to burn bandwidth and fast
/// enough that an observer cannot distinguish "idle" from "busy" by
/// silence alone.
pub const DEFAULT_COVER_INTERVAL: Duration = Duration::from_millis(250);

/// A callback taking one outbound datagram, shared between a
/// [`CircuitSender`] and, for [`CircuitSession`], the session itself --
/// mirrors Python's plain callable, which both classes hold the *same*
/// reference to. `Rc<RefCell<..>>` rather than `Arc<Mutex<..>>` because
/// this module is deliberately single-threaded (see the module docs).
pub type Transport = Rc<RefCell<dyn FnMut(&[u8])>>;

/// Wrap a plain closure as a [`Transport`].
pub fn transport(f: impl FnMut(&[u8]) + 'static) -> Transport {
    Rc::new(RefCell::new(f))
}

/// Every error this module can raise.
///
/// The Python original has `StreamError` (base) and `StreamClosed`
/// (raised when a cell is abandoned after exhausting its
/// retransmissions). A malformed inbound ack is also a plain
/// `StreamError`; a full send buffer instead lets the underlying
/// [`ReliabilityError::SendBufferFull`] propagate unwrapped, exactly as
/// Python's `send_chunk` lets `SendBufferFull` (a `ReliabilityError`
/// subclass) propagate past its own `StreamError` checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    /// A malformed ack, or any other generic misuse.
    Generic(String),
    /// A cell has been abandoned after exhausting its retransmissions --
    /// raised by [`CircuitSender::pump`], never by
    /// [`CircuitSession::pump_once`], which catches this and reports it
    /// via the session's `on_drop` callback instead (see
    /// [`CircuitSession`]'s docs) so the stream keeps running.
    Closed(String),
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::Generic(m) | StreamError::Closed(m) => write!(f, "{m}"),
        }
    }
}
impl std::error::Error for StreamError {}

/// The optional knobs [`CircuitSender::new`] takes.
/// [`Default::default`] reproduces the Python constructor's own defaults.
pub struct CircuitSenderOptions {
    pub rto: f64,
    pub max_retries: u32,
    pub max_unacked: usize,
    pub ack_every: u32,
    pub clock: Option<Box<dyn Clock>>,
    pub congestion: Option<CongestionController>,
}

impl Default for CircuitSenderOptions {
    fn default() -> Self {
        CircuitSenderOptions {
            rto: DEFAULT_RTO,
            max_retries: DEFAULT_MAX_RETRIES,
            max_unacked: 1024,
            ack_every: 4,
            clock: None,
            congestion: None,
        }
    }
}

/// Drives one circuit's outbound cell stream and applies inbound acks.
///
/// ```
/// use allium::stream::{transport, CircuitSender, CircuitSenderOptions};
///
/// let sent = std::rc::Rc::new(std::cell::RefCell::new(Vec::<Vec<u8>>::new()));
/// let sent2 = sent.clone();
/// let mut sender = CircuitSender::new(
///     transport(move |d| sent2.borrow_mut().push(d.to_vec())),
///     CircuitSenderOptions::default(),
/// ).unwrap();
/// sender.send_chunk(b"hello").unwrap(); // buffered, not yet sent
/// sender.pump().unwrap();               // send whatever is due now
/// assert_eq!(sent.borrow().len(), 1);
/// ```
pub struct CircuitSender {
    transport: Transport,
    pub window: SendWindow,
    pub tracker: AckTracker<Vec<u8>>,
    pub cc: Option<CongestionController>,
    pub sent_cells: u64,
    drops_seen: u64,
}

impl CircuitSender {
    /// # Errors
    /// Returns [`StreamError::Generic`] if `opts.ack_every` is zero.
    pub fn new(transport: Transport, opts: CircuitSenderOptions) -> Result<Self, StreamError> {
        let window = SendWindow::new(opts.rto, opts.max_retries, opts.max_unacked, DEFAULT_DUPLICATE_ACK_THRESHOLD, opts.clock);
        // `clock` is intentionally not forwarded to the tracker: it takes
        // one, but the tracker's policy is currently counter-based, so
        // passing it would imply a time-based rule that does not exist --
        // see the Python original's matching comment.
        let tracker = AckTracker::new(0, opts.ack_every, DEFAULT_MAX_PENDING, None).map_err(|e| StreamError::Generic(e.to_string()))?;
        Ok(CircuitSender {
            transport,
            window,
            tracker,
            cc: opts.congestion,
            sent_cells: 0,
            drops_seen: 0,
        })
    }

    // -- outbound -----------------------------------------------------------

    /// Buffer one cell's payload and return its sequence number.
    ///
    /// Does not transmit; call [`CircuitSender::pump`] for that, so a
    /// caller can buffer a burst and then release it in one pass rather
    /// than paying the timer check per cell.
    ///
    /// # Errors
    /// Returns [`ReliabilityError::SendBufferFull`] if the unacknowledged
    /// backlog is at its limit. Surfacing this rather than blocking is
    /// what lets a caller apply its own backpressure.
    pub fn send_chunk(&mut self, payload: &[u8]) -> Result<u32, ReliabilityError> {
        self.window.append(payload)
    }

    /// Transmit every cell that is due, first-time or retransmitted.
    ///
    /// Returns how many cells were transmitted, so a caller can
    /// distinguish "nothing to do" from "work happened" without
    /// inspecting the window.
    ///
    /// # Errors
    /// Returns [`StreamError::Closed`] if a cell was abandoned *during
    /// this call*. A drop reported earlier is not re-raised, because a
    /// stream that has already lost one cell can still carry the next:
    /// treating the lifetime total as fatal would make every later
    /// `pump()` fail and the circuit permanently unusable. Sending
    /// happens before the check so that the cells due in this call are
    /// always transmitted.
    pub fn pump(&mut self) -> Result<usize, StreamError> {
        let mut transmitted = 0usize;
        // Congestion gate. `SendWindow::due()` marks every cell it
        // returns as sent (bumping its retransmission timer), so it must
        // be asked for no more cells than will actually be transmitted --
        // otherwise the cells skipped would be silently delayed by a full
        // RTO. Hence a `limit`, not a post-hoc check inside the loop.
        let budget = self.cc.as_ref().map(|cc| cc.cwnd.saturating_sub(cc.in_flight) as usize);
        for (_seq, datagram) in self.window.due(budget) {
            (self.transport.borrow_mut())(&datagram);
            if let Some(cc) = self.cc.as_mut() {
                cc.on_send(1);
            }
            self.sent_cells += 1;
            transmitted += 1;
        }

        let new_drops = self.window.dropped - self.drops_seen;
        self.drops_seen = self.window.dropped;
        if new_drops > 0 {
            if let Some(cc) = self.cc.as_mut() {
                // An abandoned cell is the clearest loss signal there is.
                cc.on_loss(true);
            }
            return Err(StreamError::Closed(format!(
                "{new_drops} cell(s) just abandoned after {} retransmissions; those bytes were dropped and the \
                 caller must not assume they arrived ({} total this stream)",
                self.window.max_retries, self.window.dropped
            )));
        }
        Ok(transmitted)
    }

    // -- inbound --------------------------------------------------------------

    /// Process an inbound DATA cell and return a piggy-backed ack to
    /// send, or an empty vec when the policy says no ack is warranted.
    pub fn on_cell(&mut self, seq: u32, payload: Vec<u8>) -> Vec<u8> {
        self.tracker.receive(seq, payload);
        match self.tracker.maybe_ack() {
            None => Vec::new(),
            Some(state) => encode_ack(state.cumulative, state.bitmap).to_vec(),
        }
    }

    /// Return an ack regardless of policy, for a standalone ack cell.
    pub fn force_ack(&mut self) -> Vec<u8> {
        let state = self.tracker.force_ack();
        encode_ack(state.cumulative, state.bitmap).to_vec()
    }

    /// Apply an inbound ack and return how many cells it freed.
    ///
    /// # Errors
    /// Returns [`StreamError::Generic`] if `payload` is too short to be
    /// an ack. A malformed ack must not be mistaken for a valid one that
    /// frees nothing, because that would stall the stream without any
    /// signal.
    pub fn on_ack(&mut self, payload: &[u8]) -> Result<usize, StreamError> {
        let state = decode_ack(payload).map_err(|e| StreamError::Generic(format!("malformed ack: {e}")))?;
        let freed = self.window.on_ack(state.cumulative, state.bitmap).len();
        if freed > 0 {
            if let Some(cc) = self.cc.as_mut() {
                // A cumulative/SACK ack is positive delivery evidence:
                // open the window. This is what makes the sender grow
                // into available capacity instead of sitting at its
                // initial window forever.
                cc.on_ack(freed as u32);
            }
        }
        Ok(freed)
    }

    /// Note a repeated ack; fast-retransmit the cell after the edge.
    ///
    /// The sender cannot see the ack stream itself, so a caller that
    /// recognises a duplicate must say so explicitly for fast retransmit
    /// to fire. Returns the sequence number to resend, or `None` when the
    /// threshold has not been met.
    pub fn on_duplicate_ack(&mut self) -> Option<u32> {
        self.window.on_duplicate_ack()
    }

    // -- state ------------------------------------------------------------

    /// How many cells are still unacknowledged.
    pub fn pending(&self) -> usize {
        self.window.pending()
    }

    /// `true` when everything sent has been acknowledged.
    pub fn complete(&self) -> bool {
        self.window.pending() == 0
    }
}

impl std::fmt::Debug for CircuitSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CircuitSender(pending={}, sent={}, acked={}, retransmitted={}, received={})",
            self.pending(),
            self.sent_cells,
            self.window.acked,
            self.window.retransmitted,
            self.tracker.buffer.received
        )
    }
}

/// A snapshot of a [`CircuitSession`]'s counters, for logging. Mirrors the
/// Python original's `stats()` dict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionStats {
    pub pumps: u64,
    pub sent_cells: u64,
    pub pending: usize,
    pub acked: u64,
    pub retransmitted: u64,
    pub dropped: u64,
    pub covers_sent: u64,
    pub received: u64,
}

/// The optional knobs [`CircuitSession::new`] takes.
#[derive(Default)]
pub struct SessionOptions {
    /// Callable for cover cells. `None` (the default) uses `transport`
    /// itself for cover traffic too; pass an explicit callable to route
    /// cover cells differently (typically to
    /// [`crate::circuit::CircuitBuilder::send_padding`]). Unlike Python,
    /// which uses one `None` to mean "reuse transport" and needs a
    /// second signal to disable cover traffic entirely, this uses
    /// `cover_interval = Duration::ZERO` for "disabled" and this field
    /// only to mean "route cover cells elsewhere".
    pub cover_transport: Option<Transport>,
    pub pump_interval: Duration,
    pub cover_interval: Duration,
    pub constant_rate: bool,
    /// Called with the drop error when a cell is abandoned, instead of
    /// letting it end the loop. A session that lost a cell can still
    /// carry the next one, so the default (`None`) still keeps running --
    /// this is purely a notification hook.
    pub on_drop: Option<Box<dyn FnMut(&StreamError)>>,
    pub sender: CircuitSenderOptions,
}

/// Drives a [`CircuitSender`] on a timer against a live transport.
///
/// * **pump** -- every `pump_interval`, transmit whatever the send window
///   says is due, including retransmissions. This is what turns a timeout
///   into an actual resend.
/// * **inbound** -- feed a received cell into the tracker and send back
///   the ack it produces, so the peer's window can advance.
/// * **cover** -- while nothing is outstanding, emit cover traffic every
///   `cover_interval`, so an idle circuit is not silent on the wire.
///
/// It never opens a socket: `transport` is any `FnMut(&[u8])`. See the
/// module docs for why this is a synchronous, caller-driven loop rather
/// than an `asyncio` task: build and drive one `CircuitSession` from a
/// single thread (its `Rc`/`RefCell` transport is not [`Send`]); run
/// several independent circuits concurrently by giving each its own
/// thread and its own session.
pub struct CircuitSession {
    pub sender: CircuitSender,
    transport: Transport,
    cover_transport: Option<Transport>,
    pub pump_interval: Duration,
    pub cover_interval: Duration,
    pub constant_rate: bool,
    on_drop: Option<Box<dyn FnMut(&StreamError)>>,
    pub pumps: u64,
    pub covers_sent: u64,
    pub closed: bool,
}

impl CircuitSession {
    /// # Errors
    /// Returns [`StreamError::Generic`] if `opts.pump_interval` is zero,
    /// or if the underlying [`CircuitSender`] fails to build.
    pub fn new(transport: Transport, opts: SessionOptions) -> Result<Self, StreamError> {
        let pump_interval = if opts.pump_interval.is_zero() { DEFAULT_PUMP_INTERVAL } else { opts.pump_interval };
        if pump_interval.is_zero() {
            return Err(StreamError::Generic(format!("pump_interval must be positive, got {pump_interval:?}")));
        }
        let sender = CircuitSender::new(transport.clone(), opts.sender)?;
        Ok(CircuitSession {
            sender,
            transport,
            cover_transport: opts.cover_transport,
            pump_interval,
            cover_interval: opts.cover_interval,
            constant_rate: opts.constant_rate,
            on_drop: opts.on_drop,
            pumps: 0,
            covers_sent: 0,
            closed: false,
        })
    }

    // -- lifecycle ----------------------------------------------------------

    /// One pump pass. Returns cells transmitted.
    ///
    /// A lost cell is not fatal to the session: it is reported via
    /// `on_drop` (if set) and this still returns normally, exactly as
    /// Python's private `_pump_once` swallows `StreamClosed`.
    pub fn pump_once(&mut self) -> usize {
        self.pumps += 1;
        match self.sender.pump() {
            Ok(n) => n,
            Err(e @ StreamError::Closed(_)) => {
                if let Some(cb) = self.on_drop.as_mut() {
                    cb(&e);
                }
                0
            }
            Err(_) => 0,
        }
    }

    /// Emit one cover cell, if cover traffic is enabled (a
    /// `cover_transport` was given, or `transport` doubles as one).
    pub fn cover_once(&mut self) {
        let cover = self.cover_transport.clone().unwrap_or_else(|| self.transport.clone());
        (cover.borrow_mut())(&[]);
        self.covers_sent += 1;
    }

    /// Drive the pump/cover loop on the calling thread until
    /// `should_stop` returns `true`, checked once per iteration.
    ///
    /// Sends one pump immediately rather than waiting a full interval, so
    /// a caller that buffers a chunk then starts the session does not pay
    /// an unnecessary delay before the first transmission.
    ///
    /// When [`CircuitSession::constant_rate`] is set, cover cells are
    /// emitted on a fixed wall-clock schedule in *addition* to the pump
    /// loop, so the wire sees a steady cell rate whether or not the
    /// application is active -- the property a timing observer exploits
    /// is silence that correlates with "the user is idle".
    pub fn run_until<F: FnMut() -> bool>(&mut self, mut should_stop: F) {
        self.closed = false;
        let mut next_cover = Instant::now() + self.cover_interval;
        loop {
            self.pump_once();
            if self.constant_rate && self.cover_interval > Duration::ZERO {
                // Sleep only to the next cover boundary, then emit; this
                // keeps the cover cadence independent of how long a pump
                // took.
                let now = Instant::now();
                let delay = if next_cover > now { next_cover - now } else { Duration::ZERO };
                std::thread::sleep(delay);
                self.cover_once();
                next_cover = Instant::now() + self.cover_interval;
            } else {
                std::thread::sleep(self.pump_interval);
                if self.cover_interval > Duration::ZERO && Instant::now() >= next_cover {
                    self.cover_once();
                    next_cover = Instant::now() + self.cover_interval;
                }
            }
            // Checked once per iteration (see this method's docs), after
            // that iteration's pump/sleep/cover work is already done.
            if should_stop() {
                break;
            }
        }
        self.closed = true;
    }

    // -- inbound --------------------------------------------------------------

    /// Feed an inbound cell in and transmit the ack it produces, if any.
    pub fn on_cell(&mut self, seq: u32, payload: Vec<u8>) {
        let ack = self.sender.on_cell(seq, payload);
        if !ack.is_empty() {
            (self.transport.borrow_mut())(&ack);
        }
    }

    /// Apply an inbound ack to the send window. Returns how many cells it
    /// released.
    pub fn deliver_ack(&mut self, payload: &[u8]) -> Result<usize, StreamError> {
        self.sender.on_ack(payload)
    }

    /// Buffer a payload for transmission; the next pump sends it.
    pub fn send(&mut self, payload: &[u8]) -> Result<u32, ReliabilityError> {
        self.sender.send_chunk(payload)
    }

    /// `true` when everything sent has been acknowledged.
    pub fn complete(&self) -> bool {
        self.sender.complete()
    }

    /// How many cells are still unacknowledged.
    pub fn pending(&self) -> usize {
        self.sender.pending()
    }

    /// A snapshot of the loop's counters, for logging.
    pub fn stats(&self) -> SessionStats {
        SessionStats {
            pumps: self.pumps,
            sent_cells: self.sender.sent_cells,
            pending: self.sender.pending(),
            acked: self.sender.window.acked,
            retransmitted: self.sender.window.retransmitted,
            dropped: self.sender.window.dropped,
            covers_sent: self.covers_sent,
            received: self.sender.tracker.buffer.received,
        }
    }
}

impl std::fmt::Debug for CircuitSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CircuitSession(pumps={}, pending={}, covers={}, closed={})", self.pumps, self.pending(), self.covers_sent, self.closed)
    }
}

/// Layers cell fragmentation over a [`CircuitSender`].
///
/// The plain [`CircuitSender`] moves one cell's worth of bytes per
/// [`CircuitSender::send_chunk`]. This wrapper makes an *arbitrary-size*
/// byte stream transportable by splitting it into fixed-size fragments and
/// reassembling the far end, delegating every reliability concern (loss,
/// reordering, acks) to the underlying sender unchanged -- fragmentation
/// is purely a framing layer on top.
///
/// Outbound [`FragmentedCircuit::send`] fragments and buffers each
/// fragment via the sender's `send_chunk`; inbound
/// [`FragmentedCircuit::feed`] decodes a fragment and returns any
/// newly-contiguous bytes from [`crate::fragment::Reassembler`]. Once an
/// inbound FIN fragment has been consumed in order,
/// [`FragmentedCircuit::finished`] flags end-of-stream.
pub struct FragmentedCircuit {
    pub sender: CircuitSender,
    fragmenter: Fragmenter,
    reassembler: Reassembler,
}

impl FragmentedCircuit {
    /// # Errors
    /// Returns [`FragmentError`] if `mtu` is not usable (see
    /// [`crate::fragment::Fragmenter::new`]).
    pub fn new(sender: CircuitSender, mtu: usize, stream_id: u32) -> Result<Self, FragmentError> {
        Ok(FragmentedCircuit {
            sender,
            fragmenter: Fragmenter::new(mtu, stream_id)?,
            reassembler: Reassembler::new(stream_id, DEFAULT_MAX_PENDING),
        })
    }

    /// `true` once the far end signalled end-of-stream via FIN.
    pub fn finished(&self) -> bool {
        self.reassembler.finished()
    }

    /// Fragment `data` and buffer every fragment.
    ///
    /// Returns the sequence number of the last fragment buffered (the
    /// others are `last - n`; the sender assigns them in order).
    ///
    /// # Errors
    /// Returns [`ReliabilityError::SendBufferFull`] if the unacknowledged
    /// backlog fills partway through -- some fragments may already have
    /// been buffered.
    pub fn send(&mut self, data: &[u8]) -> Result<u32, ReliabilityError> {
        let fragments = self.fragmenter.fragment(data);
        let mut last_seq = 0u32;
        for frag in &fragments {
            last_seq = self.sender.send_chunk(&encode_fragment(frag))?;
        }
        Ok(last_seq)
    }

    /// Feed one inbound fragment's bytes; return newly reassembled data.
    ///
    /// The caller concatenates returns until [`FragmentedCircuit::finished`].
    /// A cell that is not a fragment for *this* stream is ignored
    /// (returns an empty vec): a single-stream reassembler has no use for
    /// another stream's bytes.
    pub fn feed(&mut self, payload: &[u8]) -> Vec<u8> {
        let fragment = match decode_fragment(payload) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        match self.reassembler.push(&fragment) {
            Ok(bytes) => bytes,
            // A valid fragment addressed to a different stream: not ours.
            Err(_) => Vec::new(),
        }
    }

    /// Forward to the sender: transmit whatever is due.
    pub fn pump(&mut self) -> Result<usize, StreamError> {
        self.sender.pump()
    }

    pub fn pending(&self) -> usize {
        self.sender.pending()
    }

    pub fn complete(&self) -> bool {
        self.sender.complete()
    }
}

impl std::fmt::Debug for FragmentedCircuit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "FragmentedCircuit(stream={}, mtu={}, pending={}, finished={})",
            self.fragmenter.stream_id,
            self.fragmenter.mtu,
            self.pending(),
            self.finished()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Wires a "client" `CircuitSender` directly to a "relay" one: every
    /// datagram the client transmits is handed straight to the relay's
    /// `on_cell`/`on_ack` as if it had crossed a lossless network, and
    /// vice versa. No sockets, matching this module's "testable without a
    /// network" design.
    struct Loopback {
        client: CircuitSender,
        relay: CircuitSender,
        client_out: Rc<RefCell<Vec<Vec<u8>>>>,
        // Kept for symmetry / future tests that need to inspect the
        // relay's own transmissions; not every test reads it.
        #[allow(dead_code)]
        relay_out: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    fn loopback() -> Loopback {
        let client_out = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let relay_out = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let c2 = client_out.clone();
        let r2 = relay_out.clone();
        let client = CircuitSender::new(transport(move |d| c2.borrow_mut().push(d.to_vec())), CircuitSenderOptions::default()).unwrap();
        let relay = CircuitSender::new(transport(move |d| r2.borrow_mut().push(d.to_vec())), CircuitSenderOptions::default()).unwrap();
        Loopback { client, relay, client_out, relay_out }
    }

    #[test]
    fn send_chunk_then_pump_transmits_exactly_once() {
        let mut lb = loopback();
        lb.client.send_chunk(b"hello").unwrap();
        let n = lb.client.pump().unwrap();
        assert_eq!(n, 1);
        assert_eq!(lb.client_out.borrow().len(), 1);
        // A second pump with nothing new due sends nothing more.
        assert_eq!(lb.client.pump().unwrap(), 0);
    }

    #[test]
    fn end_to_end_roundtrip_delivers_and_acks() {
        let mut lb = loopback();
        lb.client.send_chunk(b"one").unwrap();
        lb.client.send_chunk(b"two").unwrap();
        lb.client.pump().unwrap();
        assert_eq!(lb.client_out.borrow().len(), 2);

        // Deliver both cells to the relay in order; it acks after
        // ack_every (4 by default) cells or a gap, so force an ack to
        // observe the state directly rather than waiting on the policy.
        let cells: Vec<Vec<u8>> = lb.client_out.borrow_mut().drain(..).collect();
        for (seq, cell) in cells.into_iter().enumerate() {
            lb.relay.on_cell(seq as u32, cell);
        }
        let ack = lb.relay.force_ack();
        assert_eq!(ack.len(), crate::layer::ACK_WIRE_SIZE); // 20: 32-bit cumulative + 128-bit bitmap

        let freed = lb.client.on_ack(&ack).unwrap();
        assert_eq!(freed, 2);
        assert!(lb.client.complete());
    }

    #[test]
    fn malformed_ack_is_rejected() {
        let mut lb = loopback();
        let err = lb.client.on_ack(&[0u8; 3]).unwrap_err();
        assert!(matches!(err, StreamError::Generic(_)));
    }

    #[test]
    fn pump_reports_closed_after_exhausting_retries_and_stream_keeps_working() {
        let dropped = Rc::new(RefCell::new(0u32));
        let d2 = dropped.clone();
        // A transport that never actually delivers anything downstream
        // (no relay wired up) forces every retry to time out.
        let mut sender = CircuitSender::new(
            transport(move |_d| {
                *d2.borrow_mut() += 1;
            }),
            CircuitSenderOptions {
                rto: 0.0, // every due() call re-triggers immediately
                max_retries: 1,
                ..Default::default()
            },
        )
        .unwrap();
        sender.send_chunk(b"x").unwrap();
        sender.pump().unwrap(); // first send
        let err = loop {
            match sender.pump() {
                Ok(_) => continue,
                Err(e) => break e,
            }
        };
        assert!(matches!(err, StreamError::Closed(_)));
        // The stream survives: a fresh chunk can still be sent and pumped.
        sender.send_chunk(b"y").unwrap();
        assert!(sender.pump().is_ok());
    }

    #[test]
    fn fragmented_circuit_round_trips_data_larger_than_one_cell() {
        let sender_out = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let s2 = sender_out.clone();
        let sender = CircuitSender::new(transport(move |d| s2.borrow_mut().push(d.to_vec())), CircuitSenderOptions::default()).unwrap();
        let mut outbound = FragmentedCircuit::new(sender, 8, 42).unwrap();

        let data = b"this message is longer than eight bytes per fragment, easily".to_vec();
        outbound.send(&data).unwrap();
        outbound.pump().unwrap();

        let cells: Vec<Vec<u8>> = sender_out.borrow_mut().drain(..).collect();
        assert!(cells.len() > 1, "message should have needed more than one 8-byte fragment");

        // Feed a matching inbound FragmentedCircuit for the same stream id.
        let sink_sender = CircuitSender::new(transport(|_d| {}), CircuitSenderOptions::default()).unwrap();
        let mut inbound = FragmentedCircuit::new(sink_sender, 8, 42).unwrap();
        let mut recovered = Vec::new();
        for (seq, cell) in cells.into_iter().enumerate() {
            inbound.sender.on_cell(seq as u32, cell.clone());
            recovered.extend(inbound.feed(&cell));
        }
        assert_eq!(recovered, data);
        assert!(inbound.finished());
    }

    #[test]
    fn session_pump_once_transmits_a_buffered_chunk() {
        let out = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let o2 = out.clone();
        let mut session = CircuitSession::new(transport(move |d| o2.borrow_mut().push(d.to_vec())), SessionOptions::default()).unwrap();
        session.send(b"payload").unwrap();
        let n = session.pump_once();
        assert_eq!(n, 1);
        assert_eq!(out.borrow().len(), 1);
    }

    #[test]
    fn session_cover_once_uses_cover_transport_when_given() {
        let main_out = Rc::new(RefCell::new(0u32));
        let cover_out = Rc::new(RefCell::new(0u32));
        let m2 = main_out.clone();
        let c2 = cover_out.clone();
        let mut opts = SessionOptions::default();
        opts.cover_transport = Some(transport(move |_d| *c2.borrow_mut() += 1));
        let mut session = CircuitSession::new(transport(move |_d| *m2.borrow_mut() += 1), opts).unwrap();
        session.cover_once();
        session.cover_once();
        assert_eq!(*cover_out.borrow(), 2);
        assert_eq!(*main_out.borrow(), 0);
        assert_eq!(session.covers_sent, 2);
    }

    #[test]
    fn session_run_until_pumps_and_stops_promptly() {
        let out = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let o2 = out.clone();
        let mut opts = SessionOptions::default();
        opts.pump_interval = Duration::from_millis(5);
        opts.cover_interval = Duration::ZERO; // no cover traffic
        let mut session = CircuitSession::new(transport(move |d| o2.borrow_mut().push(d.to_vec())), opts).unwrap();
        session.send(b"go").unwrap();

        let iterations = Rc::new(RefCell::new(0u32));
        let it2 = iterations.clone();
        session.run_until(move || {
            *it2.borrow_mut() += 1;
            *it2.borrow() >= 3
        });

        assert!(session.closed);
        assert!(session.pumps >= 3);
        assert_eq!(out.borrow().len(), 1); // the one buffered chunk, sent on the first pump
    }

    #[test]
    fn session_on_drop_is_invoked_and_session_keeps_running() {
        let drops = Rc::new(RefCell::new(0u32));
        let d2 = drops.clone();
        let mut opts = SessionOptions::default();
        opts.sender.rto = 0.0;
        opts.sender.max_retries = 0;
        opts.on_drop = Some(Box::new(move |_e| *d2.borrow_mut() += 1));
        let mut session = CircuitSession::new(transport(|_d| {}), opts).unwrap();
        session.send(b"x").unwrap();
        session.pump_once(); // first send
        // Keep pumping until the abandoned-cell notification fires.
        for _ in 0..10 {
            if *drops.borrow() > 0 {
                break;
            }
            session.pump_once();
        }
        assert_eq!(*drops.borrow(), 1);
        // The session is still usable afterwards.
        session.send(b"y").unwrap();
        session.pump_once();
    }
}
