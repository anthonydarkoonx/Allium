//! Client-side reliable stream over an Allium circuit.
//!
//! Full port of `stream.py`. The relay half of the ack loop lives in
//! `relay.rs`; this is the other end, the piece that decides *when to send
//! and when to resend*.
//!
//! * [`crate::reliability::SendWindow`] owns *what* is outstanding and when
//!   it is due.
//! * [`crate::reliability::AckTracker`] owns *when to ack* inbound cells.
//! * [`CircuitSender`] owns the loop that connects them to a transport.
//! * [`CircuitSession`] is the part that actually runs: a background tokio
//!   task that pumps [`CircuitSender`] on a timer against a live transport,
//!   applies inbound acks, and emits cover traffic while idle.
//!
//! Nothing here opens a socket: a transport is any callback taking bytes.
//!
//! **tokio, and what is/isn't verified in this sandbox**: [`CircuitSender`]
//! and [`FragmentedCircuit`] touch no external crate at all and are fully
//! tested here (stub-and-restore, same as every other module). [`CircuitSession`]
//! is real, `tokio`-backed async code (`tokio::task::spawn`,
//! `tokio::time::sleep`, `tokio::sync::Mutex`) written carefully against
//! tokio 1.x's documented, stable API, but -- like the `ed25519-dalek`/
//! `x25519-dalek`/`aes-gcm` code elsewhere in this crate -- **cannot be
//! compiled or executed in this sandbox** (no network access to fetch
//! `tokio`; see the note atop `allium/Cargo.toml`), so it is "written but
//! unverified pending real cargo build." It is excluded
//! from every stub-and-restore pass in this module the same way
//! `crypto::AesGcmAead`/`handshake::HandshakeOps::real` bodies are: replaced
//! with a placeholder for that one verification run, then restored
//! byte-for-byte.
//!
//! **One API deviation from Python, forced by Rust's ownership model**:
//! Python's `CircuitSession` methods (`on_cell`, `deliver_ack`, `send`,
//! `stats`, ...) are called synchronously on the same object the background
//! `asyncio.Task` mutates, because CPython's GIL serializes that access for
//! free. Rust has no equivalent, so [`CircuitSession`]'s shared state
//! (`sender`, counters) lives behind a `tokio::sync::Mutex` that both the
//! background task and every accessor method lock; the accessor methods are
//! therefore `async fn` here where Python's are plain methods.

use crate::congestion::CongestionController;
use crate::fragment::{Fragment, FragmentError, Fragmenter, Reassembler, decode_fragment, encode_fragment};
use crate::layer::{decode_ack, encode_ack};
use crate::reliability::{AckTracker, DEFAULT_MAX_RETRIES, DEFAULT_RTO, DEFAULT_WINDOW, SendWindow};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    Generic(String),
    Closed(String),
}
impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamError::Generic(s) | StreamError::Closed(s) => write!(f, "{s}"),
        }
    }
}
impl std::error::Error for StreamError {}
fn err(msg: impl Into<String>) -> StreamError {
    StreamError::Generic(msg.into())
}

/// The circuit gave up on a cell after exhausting its retransmissions.
pub type StreamClosed = StreamError;

pub type Transport = Box<dyn FnMut(&[u8]) + Send>;

pub struct CircuitSenderOptions {
    pub rto: f64,
    pub max_retries: u32,
    pub max_unacked: usize,
    pub ack_every: u64,
    pub clock: Option<Box<dyn FnMut() -> f64 + Send>>,
    pub congestion: Option<CongestionController>,
}
impl Default for CircuitSenderOptions {
    fn default() -> Self {
        CircuitSenderOptions { rto: DEFAULT_RTO, max_retries: DEFAULT_MAX_RETRIES, max_unacked: 1024, ack_every: 4, clock: None, congestion: None }
    }
}

fn default_clock() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs_f64()
}

/// Drives one circuit's outbound cell stream and applies inbound acks.
pub struct CircuitSender {
    pub window: SendWindow,
    pub tracker: AckTracker,
    pub cc: Option<CongestionController>,
    transport: Transport,
    pub sent_cells: u64,
    drops_seen: u64,
}

impl CircuitSender {
    pub fn new(transport: Transport, options: CircuitSenderOptions) -> Result<CircuitSender, StreamError> {
        let clock1 = options.clock;
        // SendWindow and AckTracker each need their own clock closure; build
        // two independent ones from the same source so both observe the
        // same wall-clock semantics (matching Python passing one `clock`
        // callable to both, since a Python callable can be shared freely).
        let (window_clock, tracker_clock): (Box<dyn FnMut() -> f64 + Send>, Box<dyn FnMut() -> f64>) = match clock1 {
            Some(c) => {
                let shared = Arc::new(std::sync::Mutex::new(c));
                let w = {
                    let shared = shared.clone();
                    let f: Box<dyn FnMut() -> f64 + Send> = Box::new(move || (shared.lock().unwrap())());
                    f
                };
                let t = {
                    let shared = shared.clone();
                    let f: Box<dyn FnMut() -> f64> = Box::new(move || (shared.lock().unwrap())());
                    f
                };
                (w, t)
            }
            None => (Box::new(default_clock), Box::new(default_clock)),
        };
        let window = SendWindow::new(options.rto, options.max_retries, options.max_unacked, 3, window_clock);
        let tracker = AckTracker::new(0, options.ack_every, DEFAULT_WINDOW as usize, tracker_clock).map_err(|e| err(e.to_string()))?;
        Ok(CircuitSender { window, tracker, cc: options.congestion, transport, sent_cells: 0, drops_seen: 0 })
    }

    /// Buffer one cell's payload and return its sequence number.
    pub fn send_chunk(&mut self, payload: &[u8]) -> Result<u64, StreamError> {
        self.window.append(payload).map_err(|e| err(e.to_string()))
    }

    /// Transmit every cell that is due, first-time or retransmitted.
    pub fn pump(&mut self) -> Result<u64, StreamError> {
        let mut transmitted = 0u64;
        let budget = self.cc.as_ref().map(|cc| (cc.cwnd - cc.in_flight).max(0) as usize);
        for (_seq, datagram) in self.window.due(budget) {
            (self.transport)(&datagram);
            if let Some(cc) = &mut self.cc {
                let _ = cc.on_send(1);
            }
            self.sent_cells += 1;
            transmitted += 1;
        }
        let new_drops = self.window.dropped - self.drops_seen;
        self.drops_seen = self.window.dropped;
        if new_drops > 0 {
            if let Some(cc) = &mut self.cc {
                cc.on_loss(true);
            }
            return Err(StreamError::Closed(format!(
                "{new_drops} cell(s) just abandoned after exhausting their retransmissions; those bytes were dropped and the caller must not assume they arrived ({} total this stream)",
                self.window.dropped
            )));
        }
        Ok(transmitted)
    }

    /// Process an inbound DATA cell and return a piggy-backed ack to send.
    pub fn on_cell(&mut self, seq: u64, _payload: &[u8]) -> Vec<u8> {
        self.tracker.receive(seq);
        match self.tracker.maybe_ack() {
            Some(state) => encode_ack(state.cumulative, state.bitmap),
            None => Vec::new(),
        }
    }

    /// Return an ack regardless of policy, for a standalone ack cell.
    pub fn force_ack(&mut self) -> Vec<u8> {
        let state = self.tracker.force_ack();
        encode_ack(state.cumulative, state.bitmap)
    }

    /// Apply an inbound ack and return how many cells it freed.
    pub fn on_ack(&mut self, payload: &[u8]) -> Result<usize, StreamError> {
        let state = decode_ack(payload).map_err(|e| err(format!("malformed ack: {e}")))?;
        let freed = self.window.on_ack(state.cumulative, state.bitmap).len();
        if let Some(cc) = &mut self.cc {
            if freed > 0 {
                let _ = cc.on_ack(freed as i64);
            }
        }
        Ok(freed)
    }

    /// Note a repeated ack; fast-retransmit the cell after the edge.
    pub fn on_duplicate_ack(&mut self) -> Option<u64> {
        self.window.on_duplicate_ack()
    }

    pub fn pending(&self) -> usize {
        self.window.pending()
    }
    pub fn complete(&self) -> bool {
        self.window.pending() == 0
    }
}

impl fmt::Display for CircuitSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CircuitSender(pending={}, sent={}, acked={}, retransmitted={})",
            self.pending(),
            self.sent_cells,
            self.window.acked,
            self.window.retransmitted
        )
    }
}

/// How often the session pumps the send window, in seconds.
pub const DEFAULT_PUMP_INTERVAL: f64 = 0.05;
/// Safety-net timeout for the event-driven pump loop: guards against a
/// missed `Notify` wakeup without reintroducing a meaningful artificial
/// delay, now that sends are normally woken immediately by new data or a
/// freed congestion window rather than by a blind timer. Deliberately much
/// smaller than `DEFAULT_PUMP_INTERVAL` ("a few milliseconds, not 50").
pub const DEFAULT_PUMP_BACKSTOP: Duration = Duration::from_millis(5);
/// How often an idle session emits a cover cell, in seconds. `0` disables.
pub const DEFAULT_COVER_INTERVAL: f64 = 0.25;

pub struct CircuitSessionOptions {
    pub cover_transport: Option<Transport>,
    pub pump_interval: f64,
    pub cover_interval: f64,
    pub constant_rate: bool,
    pub on_drop: Option<Box<dyn FnMut(&StreamError) + Send>>,
    pub sender_options: CircuitSenderOptions,
}
impl Default for CircuitSessionOptions {
    fn default() -> Self {
        CircuitSessionOptions {
            cover_transport: None,
            pump_interval: DEFAULT_PUMP_INTERVAL,
            cover_interval: DEFAULT_COVER_INTERVAL,
            constant_rate: false,
            on_drop: None,
            sender_options: CircuitSenderOptions::default(),
        }
    }
}

struct CircuitSessionState {
    sender: CircuitSender,
    transport_echo: Option<Transport>, // used to send acks produced by on_cell
    cover_transport: Option<Transport>,
    on_drop: Option<Box<dyn FnMut(&StreamError) + Send>>,
    pumps: u64,
    covers_sent: u64,
    closed: bool,
}

// TOKIO-BLOCK-BEGIN (see /tmp/stub5.py -- stub-and-restore replaces this
// whole block with a dependency-free placeholder for one verification run,
// then restores it byte-for-byte; never edit around this marker without
// also checking that script still applies cleanly).

/// Drives a [`CircuitSender`] on a timer against a live transport.
///
/// See the module docs for why its accessor methods are `async fn` here
/// (Python's are plain methods) and for what part of this type is
/// unverified in this sandbox (everything -- it is entirely `tokio`-backed).
pub struct CircuitSession {
    state: Arc<tokio::sync::Mutex<CircuitSessionState>>,
    /// Tier 1 fix: wakes the pump loop as soon as new data is queued
    /// (`send`) or an ack frees congestion-window budget (`deliver_ack`),
    /// instead of it discovering that only on its next timer tick. See
    /// `run`'s doc comment.
    notify: Arc<tokio::sync::Notify>,
    pump_interval: Duration,
    cover_interval: Duration,
    constant_rate: bool,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl CircuitSession {
    pub fn new(transport: Transport, transport_for_acks: Transport, options: CircuitSessionOptions) -> Result<CircuitSession, StreamError> {
        if options.pump_interval <= 0.0 {
            return Err(err(format!("pump_interval must be positive, got {}", options.pump_interval)));
        }
        if options.cover_interval < 0.0 {
            return Err(err(format!("cover_interval must not be negative, got {}", options.cover_interval)));
        }
        let sender = CircuitSender::new(transport, options.sender_options)?;
        let state = CircuitSessionState {
            sender,
            transport_echo: Some(transport_for_acks),
            cover_transport: options.cover_transport,
            on_drop: options.on_drop,
            pumps: 0,
            covers_sent: 0,
            closed: false,
        };
        Ok(CircuitSession {
            state: Arc::new(tokio::sync::Mutex::new(state)),
            notify: Arc::new(tokio::sync::Notify::new()),
            pump_interval: Duration::from_secs_f64(options.pump_interval),
            cover_interval: Duration::from_secs_f64(options.cover_interval),
            constant_rate: options.constant_rate,
            task: None,
        })
    }

    fn pump_once(state: &mut CircuitSessionState) -> u64 {
        state.pumps += 1;
        match state.sender.pump() {
            Ok(n) => n,
            Err(e) => {
                if let Some(cb) = &mut state.on_drop {
                    cb(&e);
                }
                0
            }
        }
    }

    fn cover_once(state: &mut CircuitSessionState) {
        if let Some(cover) = &mut state.cover_transport {
            cover(b"");
            state.covers_sent += 1;
        }
    }

    /// Pump until [`CircuitSession::stop`] cancels this task. Only ever
    /// spawned from within this module (see the call site below) -- plain
    /// private (no `pub` at all) rather than `pub(crate)`, since its
    /// parameter type (`CircuitSessionState`) is itself private to this
    /// module: `pub(crate)` would still be a wider visibility than the type
    /// it takes, which is exactly what the compiler's own
    /// `private_interfaces` warning flags.
    ///
    /// **Tier 1 fix (event-driven wake, not a blind timer)**: the
    /// non-`constant_rate` branch used to unconditionally
    /// `tokio::time::sleep(pump_interval)` between pumps regardless of
    /// whether there was anything new to send -- adding up to a full
    /// `pump_interval` of pure scheduling latency before freshly queued
    /// data (or a freed congestion window) started moving, and forcing a
    /// whole window's worth of cells out in one instant burst per tick.
    /// It now waits on `notify` -- signalled by `send()` (new data
    /// queued) and by `deliver_ack()` when an ack frees window budget --
    /// with a small `backstop_interval` safety-net timeout to guard
    /// against a missed wakeup, so a pump normally fires within about one
    /// tick of becoming legal instead of on a fixed clock.
    /// `constant_rate` cover-traffic timing (genuine anonymity padding,
    /// intentionally independent of data readiness) is untouched.
    async fn run(state: Arc<tokio::sync::Mutex<CircuitSessionState>>, notify: Arc<tokio::sync::Notify>, backstop_interval: Duration, cover_interval: Duration, constant_rate: bool) {
        let mut next_cover = tokio::time::Instant::now() + cover_interval;
        loop {
            {
                let mut s = state.lock().await;
                CircuitSession::pump_once(&mut s);
            }
            if constant_rate && !cover_interval.is_zero() {
                let now = tokio::time::Instant::now();
                let delay = next_cover.saturating_duration_since(now);
                tokio::time::sleep(delay).await;
                {
                    let mut s = state.lock().await;
                    CircuitSession::cover_once(&mut s);
                }
                next_cover = tokio::time::Instant::now() + cover_interval;
            } else {
                tokio::select! {
                    _ = notify.notified() => {}
                    _ = tokio::time::sleep(backstop_interval) => {}
                }
                if !cover_interval.is_zero() && tokio::time::Instant::now() >= next_cover {
                    let mut s = state.lock().await;
                    CircuitSession::cover_once(&mut s);
                    next_cover = tokio::time::Instant::now() + cover_interval;
                }
            }
        }
    }

    /// Start the background pump task.
    pub fn start(&mut self) {
        if self.task.is_some() {
            return;
        }
        let state = self.state.clone();
        let notify = self.notify.clone();
        // Tier 1 fix: the backstop only needs to guard against a missed
        // `Notify` wakeup, not carry the whole schedule the way the old
        // blind sleep did, so it is capped well below the configured
        // pump_interval (which remains the ceiling for a caller that
        // explicitly configured something smaller than
        // DEFAULT_PUMP_BACKSTOP).
        let backstop_interval = self.pump_interval.min(DEFAULT_PUMP_BACKSTOP);
        let cover_interval = self.cover_interval;
        let constant_rate = self.constant_rate;
        self.task = Some(tokio::task::spawn_local(async move {
            CircuitSession::run(state, notify, backstop_interval, cover_interval, constant_rate).await;
        }));
    }

    /// Cancel the background task, if any, and wait for it to finish.
    pub async fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
        self.state.lock().await.closed = true;
    }

    pub async fn on_cell(&self, seq: u64, payload: &[u8]) {
        let mut s = self.state.lock().await;
        let ack = s.sender.on_cell(seq, payload);
        if !ack.is_empty() {
            if let Some(t) = &mut s.transport_echo {
                t(&ack);
            }
        }
    }

    pub async fn deliver_ack(&self, payload: &[u8]) -> Result<usize, StreamError> {
        let result = {
            let mut s = self.state.lock().await;
            s.sender.on_ack(payload)
        };
        // Tier 1 fix: wake the pump loop only when this ack actually freed
        // congestion-window budget -- an ack that freed nothing has
        // nothing new to send.
        if matches!(result, Ok(freed) if freed > 0) {
            self.notify.notify_one();
        }
        result
    }

    pub async fn send(&self, payload: &[u8]) -> Result<u64, StreamError> {
        let result = {
            let mut s = self.state.lock().await;
            s.sender.send_chunk(payload)
        };
        if result.is_ok() {
            // Tier 1 fix: new data queued -- wake the pump loop instead of
            // making it wait out the rest of its backstop timeout.
            self.notify.notify_one();
        }
        result
    }

    pub async fn complete(&self) -> bool {
        self.state.lock().await.sender.complete()
    }

    pub async fn pending(&self) -> usize {
        self.state.lock().await.sender.pending()
    }

    pub async fn closed(&self) -> bool {
        self.state.lock().await.closed
    }
}
// TOKIO-BLOCK-END

/// Layers cell fragmentation over a [`CircuitSender`].
pub struct FragmentedCircuit {
    pub sender: CircuitSender,
    fragmenter: Fragmenter,
    reassembler: Reassembler,
}

impl FragmentedCircuit {
    pub fn new(sender: CircuitSender, mtu: usize, stream_id: u32) -> Result<FragmentedCircuit, StreamError> {
        let fragmenter = Fragmenter::new(mtu, stream_id).map_err(|e| err(e.to_string()))?;
        let reassembler = Reassembler::new(stream_id, 64);
        Ok(FragmentedCircuit { sender, fragmenter, reassembler })
    }

    /// `true` once the far end signalled end-of-stream via FIN.
    pub fn finished(&self) -> bool {
        self.reassembler.finished()
    }

    /// Fragment `data` and buffer every fragment.
    pub fn send(&mut self, data: &[u8]) -> Result<u64, StreamError> {
        let fragments: Vec<Fragment> = self.fragmenter.fragment(data);
        let mut last_seq = 0u64;
        for frag in &fragments {
            last_seq = self.sender.send_chunk(&encode_fragment(frag))?;
        }
        Ok(last_seq)
    }

    /// Feed one inbound fragment's bytes; return newly reassembled data.
    pub fn feed(&mut self, payload: &[u8]) -> Vec<u8> {
        let fragment = match decode_fragment(payload) {
            Ok(f) => f,
            Err(FragmentError { .. }) => return Vec::new(),
        };
        self.reassembler.push(&fragment).unwrap_or_default()
    }

    pub fn pump(&mut self) -> Result<u64, StreamError> {
        self.sender.pump()
    }
    pub fn pending(&self) -> usize {
        self.sender.pending()
    }
    pub fn complete(&self) -> bool {
        self.sender.complete()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn recording_transport() -> (Transport, Arc<Mutex<Vec<Vec<u8>>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let transport: Transport = Box::new(move |data: &[u8]| log2.lock().unwrap().push(data.to_vec()));
        (transport, log)
    }

    fn fixed_clock(value: f64) -> Box<dyn FnMut() -> f64 + Send> {
        Box::new(move || value)
    }

    #[test]
    fn test_send_chunk_and_pump_transmits() {
        let (transport, log) = recording_transport();
        let mut sender = CircuitSender::new(transport, CircuitSenderOptions { clock: Some(fixed_clock(1000.0)), ..Default::default() }).unwrap();
        sender.send_chunk(b"hello").unwrap();
        let n = sender.pump().unwrap();
        assert_eq!(n, 1);
        assert_eq!(log.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_pump_returns_zero_when_nothing_due() {
        let (transport, _log) = recording_transport();
        let mut sender = CircuitSender::new(transport, CircuitSenderOptions { clock: Some(fixed_clock(1000.0)), ..Default::default() }).unwrap();
        assert_eq!(sender.pump().unwrap(), 0);
    }

    #[test]
    fn test_on_cell_returns_ack_bytes_when_due() {
        let (transport, _log) = recording_transport();
        let mut sender = CircuitSender::new(transport, CircuitSenderOptions { ack_every: 1, clock: Some(fixed_clock(1000.0)), ..Default::default() }).unwrap();
        let ack = sender.on_cell(0, b"data");
        assert!(!ack.is_empty());
    }

    #[test]
    fn test_on_ack_frees_cells() {
        let (transport, _log) = recording_transport();
        let mut sender = CircuitSender::new(transport, CircuitSenderOptions { clock: Some(fixed_clock(1000.0)), ..Default::default() }).unwrap();
        sender.send_chunk(b"a").unwrap();
        sender.pump().unwrap();
        assert_eq!(sender.pending(), 1);
        let ack = encode_ack(1, 0);
        let freed = sender.on_ack(&ack).unwrap();
        assert_eq!(freed, 1);
        assert!(sender.complete());
    }

    #[test]
    fn test_on_ack_rejects_malformed() {
        let (transport, _log) = recording_transport();
        let mut sender = CircuitSender::new(transport, CircuitSenderOptions { clock: Some(fixed_clock(1000.0)), ..Default::default() }).unwrap();
        assert!(sender.on_ack(&[1, 2, 3]).is_err());
    }

    #[test]
    fn test_pump_reports_stream_closed_after_drop() {
        let clock_val = Arc::new(Mutex::new(1000.0f64));
        let clock_clone = clock_val.clone();
        let (transport, _log) = recording_transport();
        let clock: Box<dyn FnMut() -> f64 + Send> = Box::new(move || *clock_clone.lock().unwrap());
        let mut sender = CircuitSender::new(transport, CircuitSenderOptions { rto: 1.0, max_retries: 1, clock: Some(clock), ..Default::default() }).unwrap();
        sender.send_chunk(b"x").unwrap();
        sender.pump().unwrap(); // first send, attempts=1
        *clock_val.lock().unwrap() = 1002.0; // past rto, attempts (1) >= max_retries (1) -> dropped
        let result = sender.pump();
        assert!(matches!(result, Err(StreamError::Closed(_))));
    }

    #[test]
    fn test_congestion_gates_pump() {
        let (transport, log) = recording_transport();
        let cc = CongestionController::new(1, 1, 10, 1, 0.5).unwrap();
        let mut sender = CircuitSender::new(transport, CircuitSenderOptions { clock: Some(fixed_clock(1000.0)), congestion: Some(cc), ..Default::default() }).unwrap();
        sender.send_chunk(b"a").unwrap();
        sender.send_chunk(b"b").unwrap();
        let n = sender.pump().unwrap();
        assert_eq!(n, 1); // cwnd=1 caps first pump to one cell
        assert_eq!(log.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_fragmented_circuit_round_trip() {
        let (transport_a, _log_a) = recording_transport();
        let sender_a = CircuitSender::new(transport_a, CircuitSenderOptions { clock: Some(fixed_clock(1000.0)), ..Default::default() }).unwrap();
        let mut circuit_a = FragmentedCircuit::new(sender_a, 4, 7).unwrap();

        let (transport_b, _log_b) = recording_transport();
        let sender_b = CircuitSender::new(transport_b, CircuitSenderOptions { clock: Some(fixed_clock(1000.0)), ..Default::default() }).unwrap();
        let mut circuit_b = FragmentedCircuit::new(sender_b, 4, 7).unwrap();

        circuit_a.send(b"hello world").unwrap();
        // Drain the fragments straight out of the underlying send window
        // (bypassing the transport callback, matching how the test wires
        // circuit_a's fragments directly into circuit_b's `feed`).
        let due = circuit_a.sender.window.due(None);
        let mut reassembled = Vec::new();
        for (_seq, datagram) in due {
            let chunk = circuit_b.feed(&datagram);
            reassembled.extend_from_slice(&chunk);
        }
        assert_eq!(reassembled, b"hello world");
        assert!(circuit_b.finished());
    }

    #[test]
    fn test_fragmented_circuit_feed_ignores_non_fragment() {
        let (transport, _log) = recording_transport();
        let sender = CircuitSender::new(transport, CircuitSenderOptions { clock: Some(fixed_clock(1000.0)), ..Default::default() }).unwrap();
        let mut circuit = FragmentedCircuit::new(sender, 4, 1).unwrap();
        assert_eq!(circuit.feed(b"not a fragment"), Vec::<u8>::new());
    }

    #[test]
    fn test_circuit_sender_rejects_zero_pump_interval_via_session() {
        // Exercises CircuitSessionOptions validation without ever driving
        // the tokio runtime (constructing a CircuitSession does not spawn
        // anything -- only `start()` does).
        let (transport, _log) = recording_transport();
        let (echo, _log2) = recording_transport();
        let result = CircuitSession::new(
            transport,
            echo,
            CircuitSessionOptions { pump_interval: 0.0, sender_options: CircuitSenderOptions { clock: Some(fixed_clock(1000.0)), ..Default::default() }, ..Default::default() },
        );
        assert!(result.is_err());
    }
}
