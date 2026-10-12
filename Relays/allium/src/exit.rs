//! Exit-side egress: open real TCP streams and resolve names at the exit.
//!
//! Full port of `exit.py`. The relay's `deliver` only logs; a real exit must
//! turn a peeled stream request into a genuine outbound TCP connection (or a
//! DNS resolution) and feed the results back along the circuit. This module
//! owns that egress -- socket management and the async plumbing --
//! intentionally separate from the relay so the relay stays socket-free.
//!
//! **What is verified in this sandbox vs. not.** `check_destination`,
//! `Egress::_reply`, `next_stream_id`, `get_stream`/`send_data`/
//! `enable_stream_tracking`, and all of the UDP-association bookkeeping
//! (`_open_association`'s *table* half, `_on_association_datagram`,
//! `_drop_association`, `_reap_stale_associations`, `close_udp_association`)
//! touch no real socket at all -- [`ExitStream`] and [`UDPAssociation`] hold
//! their actual send/close operations behind injected closures precisely so
//! this bookkeeping is testable with a fake transport, and it is fully
//! tested here. `resolve`, `connect`, `handle_datagram`'s socket-opening
//! path, and `_pump_stream` are real `tokio` code (`TcpStream::connect`,
//! `UdpSocket::bind`, `tokio::net::lookup_host`) written against tokio 1.x's
//! documented API, but -- like every other tokio-touching function added in
//! this batch -- **cannot be compiled or executed in this sandbox** (no
//! `tokio` crate access) and is "written but unverified pending real cargo
//! build."
//!
//! `circuit_key` is now
//! `Option<crate::relay::CircuitKeyTuple>` (previous hop host, port, and
//! circuit id -- the same tuple the relay's own state table is keyed by),
//! not a bare `Option<u32>`. Every production caller used to pass `None`
//! for this parameter, which put every stream on every circuit into one
//! shared `(None, stream_id)` namespace: since stream ids are handed out
//! from one process-wide counter and echoed back to the client that opened
//! them, any client could address another circuit's stream by guessing or
//! observing its id and inject data into that circuit's live TCP
//! connection. Keying by the full circuit identity (not just a bare `u32`
//! circuit id, which two different middles could coincidentally reuse)
//! closes that: two different circuits can never collide on the same
//! table key even if they happen to pick the same stream id.

use crate::policy::{AmplificationGuard, ExitPolicy, LeaseTable, PolicyDenied, RateLimitExceeded, RateLimiter, canonical_host};
use crate::socks::{
    ADDR_UNSUPPORTED, COMMAND_UNSUPPORTED, CONNECT, DatagramReply, DatagramRequest, GENERAL_FAILURE, HOST_UNREACHABLE, RESOLVE, SUCCESS,
    StreamReply, StreamRequest, encode_datagram_reply, encode_reply, max_datagram_reply_payload,
};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

pub type CircuitKey = Option<crate::relay::CircuitKeyTuple>;

/// Hard per-circuit and exit-wide
/// caps on live streams. Without these, one circuit (or `RLIMIT_NOFILE`
/// divided among however many circuits an attacker opens) is the only
/// thing bounding how many outbound sockets one client can make this exit
/// hold open. 64 is generous for ordinary browsing (a page plus its
/// subresources rarely needs more than a handful of concurrent
/// connections) while still refusing a client that just keeps CONNECTing.
pub const MAX_STREAMS_PER_CIRCUIT: usize = 64;

/// Exit-wide cap on live streams, independent of `RLIMIT_NOFILE` (which
/// this crate cannot introspect portably without a new dependency): a
/// conservative bound well under typical default open-file limits
/// (usually >= 1024, often much higher), so this is reached first and
/// fails a `CONNECT` cleanly rather than exhausting the process's file
/// descriptors.
pub const MAX_EXIT_STREAMS: usize = 4096;

/// Cap on concurrent in-flight `CONNECT`s (resolve + TCP handshake, not
/// yet an open stream) per circuit. Bounds how many `EGRESS_TIMEOUT`-long unlocked resolves/connects
/// one circuit can have outstanding at once, independent of
/// `MAX_STREAMS_PER_CIRCUIT` (which only counts streams that succeeded).
pub const MAX_INFLIGHT_CONNECTS_PER_CIRCUIT: usize = 16;

/// A stream with no traffic in either direction for this long is closed by
/// [`Egress::close_idle_streams`]: without this, a destination that accepts a connection and then
/// holds it open silently (never sending, never closing) keeps its socket
/// -- and its `MAX_STREAMS_PER_CIRCUIT` slot -- forever.
pub const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// How often [`spawn_idle_stream_sweeper`] checks for idle streams.
const IDLE_STREAM_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Bound on the client-to-destination write queue
/// ([`ExitStream::from_tcp_stream`]'s internal channel). Lower severity
/// than the destination-to-client path (a client can only grow this at
/// its own upload rate, into its own connection), but still
/// unbounded before this fix if the destination stops reading.
const FORWARD_QUEUE_CAPACITY: usize = 256;

/// Bound on how long the exit will wait for DNS resolution or the outbound
/// TCP handshake before giving up and replying `HOST_UNREACHABLE`.
///
/// Without this, an unreachable destination (a silently dropped SYN behind
/// a firewall, a DNS resolver that never answers, a port nothing is
/// listening on) leaves `resolve`/`connect` hanging for however long the
/// OS's own default TCP connect timeout happens to be -- often well over a
/// minute -- with no reply ever sent back along the circuit. From the
/// client's side that is indistinguishable from a genuinely broken hop: no
/// reply arrives, the circuit is declared stalled once `stall_cycles`
/// receive-timeouts pass with an unanswered send outstanding (see
/// `allium-cli`'s `circuit_pool`), and it rebuilds -- onto a fresh circuit
/// that immediately re-issues the same CONNECT against the same
/// unreachable destination and hangs again, forever, with the SOCKS client
/// (e.g. curl) seeing nothing but silence the whole time. Bounding the wait
/// here turns that into a fast, correct `HOST_UNREACHABLE` reply instead.
const EGRESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// An egress operation could not be completed; the wrapped byte is a
/// `socks::Status` code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitEgressError(pub u8);
impl std::fmt::Display for ExitEgressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "exit egress error (status {})", self.0)
    }
}
impl std::error::Error for ExitEgressError {}

/// A live outbound TCP stream at the exit, plus its stream id.
///
/// `send`/`close`/`closed` are injected closures (see the module docs): the
/// real constructor (`connect`, not yet wired to a real `TcpStream` split in
/// this sandbox-unverified pass) wraps `tokio::net::tcp::OwnedWriteHalf`;
/// tests construct one with a fake transport via
/// [`ExitStream::from_parts_for_test`].
pub struct ExitStream {
    pub id: u32,
    send_fn: Box<dyn FnMut(&[u8]) -> Result<(), ExitEgressError> + Send>,
    close_fn: Box<dyn FnMut() + Send>,
    closed_flag: Arc<AtomicBool>,
    // Woken by `close()`. `pump_stream_with` races this against its
    // blocking `read()` -- without it, `close()` only flips `closed_flag`,
    // which a read already parked in `.await` never notices; the pump task
    // (and the `Arc<Mutex<ExitStream>>` clone it owns for its whole
    // lifetime, independent of whatever map entry got removed) then blocks
    // forever on a destination that never sends and never closes,
    // leaking the socket and its file descriptor.
    closed_notify: Arc<tokio::sync::Notify>,
    // TOKIO-READER-FIELD-BEGIN (see /tmp/stub6.py for the verification-only
    // swap of this field's type)
    reader: Option<tokio::net::tcp::OwnedReadHalf>,
    // TOKIO-READER-FIELD-END
    /// Last time this stream saw traffic in either direction. Read by
    /// [`Egress::close_idle_streams`]; updated by [`ExitStream::send`] and by `pump_stream` on
    /// every successful read. A plain `std::sync::Mutex`, not an atomic
    /// timestamp: `Instant` has no portable integer representation, and
    /// this is only ever locked for a trivial read/write, never held
    /// across an `.await`.
    last_active: Arc<Mutex<Instant>>,
}

// TOKIO-EXITSTREAM-CTOR-BEGIN (real-socket constructor and reader; see
// module docs and /tmp/stub6.py -- unverified in this sandbox, no `tokio`
// crate access, but exercised by no test since it needs a live socket)
impl ExitStream {
    /// Construct from a real `tokio::net::TcpStream`. Unverified in this
    /// sandbox (no `tokio`).
    pub fn from_tcp_stream(stream_id: u32, tcp: tokio::net::TcpStream) -> ExitStream {
        let (reader, mut writer) = tcp.into_split();
        let closed_flag = Arc::new(AtomicBool::new(false));
        // Fire-and-forget, matching Python's `asyncio.StreamWriter.write`
        // (buffers internally and never drops what it was handed; errors
        // surface later via `drain`/the connection closing -- see
        // `exit.py`'s `ExitStream.send` docstring). A raw non-blocking
        // `try_write` is *not* an equivalent of that: it can return
        // `WouldBlock` (nothing sent, and this synchronous closure has no
        // way to retry) or accept only part of `data` (a partial write),
        // and either one would silently drop the remainder -- exactly the
        // kind of bug that would show up as "the request went out, nothing
        // ever came back" for any payload landing on the wrong side of that
        // race. Queueing onto an unbounded channel and draining it from a
        // dedicated task with `write_all` (which retries a partial write
        // and actually awaits backpressure) is what makes this closure's
        // "fire-and-forget, buffered" contract true rather than aspirational.
        // Bounded, not
        // `unbounded_channel`, so a destination that stops reading (and
        // therefore stops draining this queue via `write_all` below)
        // cannot make client uploads pile up here without limit --
        // `send_fn` below reports the queue-full case as an error instead
        // of accepting the data anyway.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(FORWARD_QUEUE_CAPACITY);
        tokio::task::spawn(async move {
            use tokio::io::AsyncWriteExt as _;
            while let Some(chunk) = rx.recv().await {
                if writer.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });
        let send_fn: Box<dyn FnMut(&[u8]) -> Result<(), ExitEgressError> + Send> = Box::new(move |data: &[u8]| match tx.try_send(data.to_vec()) {
            Ok(()) => Ok(()),
            // Full (destination isn't draining fast enough) or Closed
            // (the writer task already gave up): either way, stop
            // accepting data for this stream rather than growing this
            // queue without bound. `Egress::send_data` treats an `Err`
            // here as "the stream is gone" and tears it down.
            Err(_) => Err(ExitEgressError(GENERAL_FAILURE)),
        });
        let closed_flag2 = closed_flag.clone();
        let closed_notify = Arc::new(tokio::sync::Notify::new());
        let closed_notify2 = closed_notify.clone();
        let close_fn: Box<dyn FnMut() + Send> = Box::new(move || {
            closed_flag2.store(true, Ordering::SeqCst);
            closed_notify2.notify_waiters();
        });
        ExitStream { id: stream_id, send_fn, close_fn, closed_flag, closed_notify, reader: Some(reader), last_active: Arc::new(Mutex::new(Instant::now())) }
    }
    // TOKIO-EXITSTREAM-CTOR-END

    /// Construct with a fake transport, for tests that exercise
    /// `Egress::get_stream`/`send_data`/`enable_stream_tracking` without a
    /// real socket.
    pub fn from_parts_for_test(
        stream_id: u32,
        send_fn: Box<dyn FnMut(&[u8]) -> Result<(), ExitEgressError> + Send>,
        close_fn: Box<dyn FnMut() + Send>,
    ) -> ExitStream {
        ExitStream {
            id: stream_id,
            send_fn,
            close_fn,
            closed_flag: Arc::new(AtomicBool::new(false)),
            closed_notify: Arc::new(tokio::sync::Notify::new()),
            reader: None,
            last_active: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Queue `data` toward the remote peer.
    pub fn send(&mut self, data: &[u8]) -> Result<(), ExitEgressError> {
        self.touch();
        (self.send_fn)(data)
    }

    /// Record traffic just seen in either direction, for
    /// [`Egress::close_idle_streams`].
    fn touch(&self) {
        *self.last_active.lock().unwrap() = Instant::now();
    }

    /// How long since this stream last saw traffic in either direction.
    fn idle_for(&self) -> Duration {
        self.last_active.lock().unwrap().elapsed()
    }

    // TOKIO-RECV-BEGIN (unverified in this sandbox, no `tokio`; exercised by
    // no test since it needs a live socket -- see /tmp/stub6.py)
    /// Read up to `n` bytes; empty means the peer closed the stream.
    /// Unverified in this sandbox: only ever populated by
    /// [`ExitStream::from_tcp_stream`].
    pub async fn recv(&mut self, n: usize) -> Vec<u8> {
        use tokio::io::AsyncReadExt as _;
        match &mut self.reader {
            Some(r) => {
                let mut buf = vec![0u8; n];
                match r.read(&mut buf).await {
                    Ok(read) => {
                        buf.truncate(read);
                        buf
                    }
                    Err(_) => Vec::new(),
                }
            }
            None => Vec::new(),
        }
    }
    // TOKIO-RECV-END

    pub fn close(&mut self) {
        (self.close_fn)();
    }

    pub fn closed(&self) -> bool {
        self.closed_flag.load(Ordering::SeqCst)
    }

    /// A handle `pump_stream_with` can `.await` outside this stream's
    /// lock, to notice a `close()` called from another task while a read
    /// is parked.
    fn closed_notify(&self) -> Arc<tokio::sync::Notify> {
        self.closed_notify.clone()
    }
}

/// Exit-side state for one SOCKS5 UDP ASSOCIATE session. See `exit.py`'s
/// `UDPAssociation` docstring for the rationale (`circuit_key` is part of the table key, not just
/// `association_id`, which the client chooses unauthenticated).
pub struct UDPAssociation {
    pub circuit_key: CircuitKey,
    pub association_id: u32,
    send_fn: Box<dyn FnMut(&[u8], &str, u16) + Send>,
    close_fn: Option<Box<dyn FnMut() + Send>>,
    pub lease_token: Vec<u8>,
    pub emit: Box<dyn FnMut(&[u8]) + Send>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub closed: bool,
}

impl UDPAssociation {
    pub fn new(
        circuit_key: CircuitKey,
        association_id: u32,
        send_fn: Box<dyn FnMut(&[u8], &str, u16) + Send>,
        close_fn: Option<Box<dyn FnMut() + Send>>,
        lease_token: Vec<u8>,
        emit: Box<dyn FnMut(&[u8]) + Send>,
    ) -> UDPAssociation {
        UDPAssociation { circuit_key, association_id, send_fn, close_fn, lease_token, emit, bytes_sent: 0, bytes_received: 0, closed: false }
    }

    /// The key this association's bytes are tracked under in an
    /// `AmplificationGuard`. Prefixed so it can never collide with a TCP
    /// `ExitStream.id`.
    pub fn amp_key(&self) -> String {
        format!("udp:{:?}:{}", self.circuit_key, self.association_id)
    }

    pub fn send(&mut self, host: &str, port: u16, payload: &[u8]) {
        (self.send_fn)(payload, host, port);
        self.bytes_sent += payload.len() as u64;
    }

    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        if let Some(f) = &mut self.close_fn {
            f();
        }
    }
}

impl std::fmt::Debug for UDPAssociation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UDPAssociation(id={}, sent={}, received={}, closed={})", self.association_id, self.bytes_sent, self.bytes_received, self.closed)
    }
}

/// A custom resolver closure, as `Arc`-shared rather than `Box`-owned --
/// see the `resolver` field's docs (needs to be cloned out and used with
/// no `Egress` lock held).
type ResolverFn = dyn Fn(&str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<(String, u16)>> + Send>> + Send + Sync;

/// What the unlocked resolve phase of a UDP datagram needs, snapshotted
/// from `Egress` under a short lock (see [`Egress::handle_datagram_shared`]).
struct DatagramPrep {
    /// Whether a policy or rate limiter is configured, i.e. whether the
    /// destination must be resolved and re-checked at all.
    filtering: bool,
    policy: Option<Arc<ExitPolicy>>,
    rate_limiter: Option<Arc<Mutex<RateLimiter>>>,
    resolver: Option<Arc<ResolverFn>>,
}

/// Opens outbound streams and resolves names on behalf of the exit.
pub struct Egress {
    // `Arc`-wrapped, not `Box`/bare, for `policy`, `resolver` and
    // `rate_limiter`. `connect`
    // and `handle_request`'s RESOLVE path need to snapshot these out from
    // under a short-lived lock and then run the actual resolve/connect
    // (each up to `EGRESS_TIMEOUT`) with *no* `Egress` lock held, so every
    // other circuit's own CONNECT/RESOLVE/`send_data` keeps going instead
    // of queuing up behind one slow or blackholed destination. `Arc` makes
    // that snapshot a cheap clone instead of requiring `ExitPolicy`/
    // `RateLimiter`/the resolver closure to be `Clone` themselves.
    resolver: Option<Arc<ResolverFn>>,
    pub policy: Option<Arc<ExitPolicy>>,
    pub rate_limiter: Option<Arc<Mutex<RateLimiter>>>,
    // `Arc<Mutex<_>>`, not a bare `Mutex<_>` like `rate_limiter`: unlike
    // every other field here, this needs to be reachable *without* holding
    // `&mut Egress` at all -- see `pump_stream`'s docs (this round's fix
    // for a real deadlock: `handle_request`'s CONNECT path used to hold
    // the whole `Egress` behind `SocksExit`'s `tokio::sync::Mutex<Egress>`
    // for a stream's entire lifetime, which meant the *same* stream's own
    // later `send_data` calls -- for its own body data -- could never
    // acquire that same lock and would hang forever).
    pub amplification: Option<Arc<Mutex<AmplificationGuard>>>,
    next_stream_id: u32,
    pub streams: HashMap<(CircuitKey, u32), Weak<Mutex<ExitStream>>>,
    track_streams: bool,
    pub udp_associations: HashMap<(CircuitKey, u32), UDPAssociation>,
    pub lease_table: LeaseTable,
    /// Per-circuit count of `CONNECT`s currently resolving/connecting
    /// (not yet a tracked stream, and not yet failed) -- this is the
    /// `MAX_INFLIGHT_CONNECTS_PER_CIRCUIT` cap. Entries are
    /// removed once they hit zero, so this never grows unboundedly on its
    /// own the way an unguarded per-key counter map could.
    in_flight_connects: HashMap<CircuitKey, usize>,
}

impl Egress {
    pub fn new(
        resolver: Option<Box<dyn Fn(&str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<(String, u16)>> + Send>> + Send + Sync>>,
        policy: Option<ExitPolicy>,
        rate_limiter: Option<RateLimiter>,
        amplification: Option<AmplificationGuard>,
        lease_table: Option<LeaseTable>,
    ) -> Egress {
        Egress {
            resolver: resolver.map(Arc::from),
            policy: policy.map(Arc::new),
            rate_limiter: rate_limiter.map(|r| Arc::new(Mutex::new(r))),
            amplification: amplification.map(|a| Arc::new(Mutex::new(a))),
            next_stream_id: 0,
            streams: HashMap::new(),
            track_streams: false,
            udp_associations: HashMap::new(),
            lease_table: lease_table.unwrap_or_else(LeaseTable::with_defaults),
            in_flight_connects: HashMap::new(),
        }
    }

    /// Return the live stream for `(circuit_key, stream_id)`, or `None`.
    /// See the Python docstring for the rationale.
    pub fn get_stream(&mut self, stream_id: u32, circuit_key: CircuitKey) -> Option<Arc<Mutex<ExitStream>>> {
        let key = (circuit_key, stream_id);
        let weak = self.streams.get(&key)?;
        let stream = weak.upgrade();
        match stream {
            Some(s) => {
                if s.lock().unwrap().closed() {
                    self.streams.remove(&key);
                    None
                } else {
                    Some(s)
                }
            }
            None => {
                self.streams.remove(&key);
                None
            }
        }
    }

    /// Start recording opened streams so [`Egress::send_data`] can find
    /// them. Off by default.
    pub fn enable_stream_tracking(&mut self) {
        self.track_streams = true;
    }

    fn track(&mut self, circuit_key: CircuitKey, stream: &Arc<Mutex<ExitStream>>) {
        if self.track_streams {
            let id = stream.lock().unwrap().id;
            self.streams.insert((circuit_key, id), Arc::downgrade(stream));
        }
    }

    /// Drop `streams` entries whose `ExitStream` has already been dropped
    /// (every other owner gone). `streams` only ever holds `Weak`
    /// references, so nothing here closes a live socket -- this just keeps
    /// the table (and therefore [`Egress::stream_count_for`] and the
    /// `MAX_EXIT_STREAMS` check in [`Egress::connect`]) from counting
    /// streams that no longer exist.
    fn prune_dead_streams(&mut self) {
        self.streams.retain(|_, weak| weak.strong_count() > 0);
    }

    /// How many *live* streams `circuit_key` currently holds. Call
    /// [`Egress::prune_dead_streams`] first if the count needs to reflect
    /// reality rather than an upper bound.
    fn stream_count_for(&self, circuit_key: &CircuitKey) -> usize {
        self.streams.keys().filter(|(k, _)| k == circuit_key).count()
    }

    /// Close and forget every live stream belonging to `circuit_key`.
    /// Stream lifetime was never
    /// tied to circuit lifetime, so a destroyed or expired circuit's exit
    /// sockets stayed open (and counted against `MAX_STREAMS_PER_CIRCUIT`)
    /// indefinitely. Called from `SocksExit`'s `forget_hook`, which fires
    /// on both an explicit DESTROY and idle-circuit expiry.
    pub fn close_circuit_streams(&mut self, circuit_key: &CircuitKey) {
        let keys: Vec<(CircuitKey, u32)> = self.streams.keys().filter(|(k, _)| k == circuit_key).cloned().collect();
        for key in keys {
            if let Some(weak) = self.streams.remove(&key) {
                if let Some(stream) = weak.upgrade() {
                    stream.lock().unwrap().close();
                }
            }
        }
    }

    /// Close every stream idle for longer than `idle`. Returns how many
    /// were closed. Without this, a
    /// destination that accepts a connection and then never sends or
    /// closes it keeps that socket (and its per-circuit slot) open for the
    /// life of the process, even though the circuit itself may still be
    /// perfectly healthy.
    pub fn close_idle_streams(&mut self, idle: Duration) -> usize {
        self.prune_dead_streams();
        let stale: Vec<(CircuitKey, u32)> = self
            .streams
            .iter()
            .filter_map(|(key, weak)| {
                let stream = weak.upgrade()?;
                let past_idle = stream.lock().unwrap().idle_for() > idle;
                past_idle.then(|| key.clone())
            })
            .collect();
        let n = stale.len();
        for key in &stale {
            if let Some(weak) = self.streams.remove(key) {
                if let Some(stream) = weak.upgrade() {
                    stream.lock().unwrap().close();
                }
            }
        }
        n
    }

    /// Write client data to an open stream; `false` if it is gone.
    pub fn send_data(&mut self, stream_id: u32, data: &[u8], circuit_key: CircuitKey) -> bool {
        let stream = match self.get_stream(stream_id, circuit_key.clone()) {
            Some(s) => s,
            None => return false,
        };
        let mut guard = stream.lock().unwrap();
        let result = guard.send(data);
        if result.is_err() {
            // Most commonly the bounded forward queue is full (the
            // destination stopped reading -- see `ExitStream::from_tcp_stream`)
            // or the writer task already gave up. Either way, close it explicitly rather than
            // just forgetting it here: forgetting alone leaves the socket
            // itself open (and holding a `MAX_STREAMS_PER_CIRCUIT` slot)
            // for as long as `pump_stream`'s read side happens to keep
            // going.
            guard.close();
            drop(guard);
            self.streams.remove(&(circuit_key, stream_id));
            return false;
        }
        true
    }

    pub fn next_stream_id(&mut self) -> u32 {
        self.next_stream_id += 1;
        self.next_stream_id
    }

    /// Apply the exit policy and rate limiter to one destination.
    pub fn check_destination(&self, host: &str, port: u16, udp: bool) -> Result<(), CheckDestinationError> {
        if let Some(policy) = &self.policy {
            policy.check(host, port, udp).map_err(CheckDestinationError::Policy)?;
        }
        if let Some(limiter) = &self.rate_limiter {
            limiter.lock().unwrap().check(&canonical_host(host), 1.0).map_err(CheckDestinationError::RateLimit)?;
        }
        Ok(())
    }

    // TOKIO-RESOLVE-CONNECT-BEGIN (unverified in this sandbox, no `tokio`;
    // exercised by no test since these need real sockets -- see /tmp/stub6.py)
    /// Resolve `host` at the exit. Unverified in this sandbox (no `tokio`).
    pub async fn resolve(&self, host: &str) -> Option<(String, u16)> {
        resolve_snapshot(&self.resolver, host).await
    }

    /// Open a TCP stream to `host:port`.
    ///
    /// Free function taking `egress` by `&Rc<tokio::sync::Mutex<_>>`, not
    /// `&mut self`. The old
    /// `&mut self` method held the whole `Egress` (`SocksExit`'s shared
    /// `tokio::sync::Mutex<Egress>`) for its *entire* body, including the
    /// resolve and the TCP handshake, each boundable only up to
    /// `EGRESS_TIMEOUT` (10s) -- in production, worse: the installed
    /// custom resolver had no timeout applied to it at all (see
    /// `resolve_snapshot`'s fix), so a non-answering authoritative server
    /// could hold the lock indefinitely. Every other circuit's own
    /// CONNECT, RESOLVE, and `send_data` share that same lock, so one
    /// client CONNECTing to a blackholed address stalled every other
    /// client on the exit. This only takes the lock for the short
    /// synchronous bits (the policy/rate-limit check, reserving an
    /// in-flight-connect slot, and -- on success -- allocating/tracking
    /// the stream); the resolve and the connect itself run with no lock
    /// held at all.
    pub async fn connect(egress: &Rc<tokio::sync::Mutex<Egress>>, host: &str, port: u16, circuit_key: CircuitKey) -> Result<Arc<Mutex<ExitStream>>, ExitEgressError> {
        let (policy, rate_limiter, resolver) = {
            let mut e = egress.lock().await;
            if e.policy.is_some() || e.rate_limiter.is_some() {
                if e.check_destination(host, port, false).is_err() {
                    return Err(ExitEgressError(COMMAND_UNSUPPORTED));
                }
            }
            // Cap concurrent
            // in-flight (resolving/connecting, not yet open) streams per
            // circuit, independent of `MAX_STREAMS_PER_CIRCUIT` (which
            // only counts streams that already succeeded) -- otherwise one
            // circuit could still queue unboundedly many concurrent
            // `EGRESS_TIMEOUT`-long unlocked resolves/connects.
            let count = e.in_flight_connects.entry(circuit_key.clone()).or_insert(0);
            if *count >= MAX_INFLIGHT_CONNECTS_PER_CIRCUIT {
                return Err(ExitEgressError(GENERAL_FAILURE));
            }
            *count += 1;
            (e.policy.clone(), e.rate_limiter.clone(), e.resolver.clone())
        };

        // No `Egress` lock held from here until the re-lock below: the
        // resolve and the TCP connect can each take up to `EGRESS_TIMEOUT`
        // without blocking any other circuit.
        let connect_result = Egress::connect_tcp(host, port, &policy, &rate_limiter, &resolver).await;

        let mut e = egress.lock().await;
        if let Some(count) = e.in_flight_connects.get_mut(&circuit_key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                e.in_flight_connects.remove(&circuit_key);
            }
        }
        let tcp = connect_result?;
        // Enforce the stream caps
        // here, at track time, not before the unlocked resolve/connect --
        // other CONNECTs on this circuit (or elsewhere on the exit) could
        // have pushed the count over the limit while this one was
        // resolving.
        e.prune_dead_streams();
        if e.streams.len() >= MAX_EXIT_STREAMS || e.stream_count_for(&circuit_key) >= MAX_STREAMS_PER_CIRCUIT {
            return Err(ExitEgressError(GENERAL_FAILURE));
        }
        let id = e.next_stream_id();
        let stream = Arc::new(Mutex::new(ExitStream::from_tcp_stream(id, tcp)));
        e.track(circuit_key, &stream);
        Ok(stream)
    }

    /// The unlocked half of [`Egress::connect`]: resolve (if a policy or
    /// rate limiter is set, re-checking each against the resolved
    /// address) and open the TCP stream. Touches no `Egress` state at
    /// all, by design -- see `connect`'s own docs.
    async fn connect_tcp(
        host: &str,
        port: u16,
        policy: &Option<Arc<ExitPolicy>>,
        rate_limiter: &Option<Arc<Mutex<RateLimiter>>>,
        resolver: &Option<Arc<ResolverFn>>,
    ) -> Result<tokio::net::TcpStream, ExitEgressError> {
        let mut connect_host = host.to_string();
        if policy.is_some() || rate_limiter.is_some() {
            let resolved = resolve_snapshot(resolver, host).await.ok_or(ExitEgressError(HOST_UNREACHABLE))?;
            if let Some(policy) = policy {
                // `policy.check`
                // here re-checks `deny_hosts` against `resolved.0` (an IP
                // string), which a hostname-form `deny_hosts` entry (e.g.
                // "evil.example") can never literally equal -- but that is
                // not a bypass: `connect`'s own `check_destination` call,
                // just above this function in the call chain, already
                // evaluated `deny_hosts` against `host` (the original,
                // unresolved hostname) before resolution ever started, so
                // a hostname-form deny entry is caught there. This
                // re-check's actual job (like the policy/rate-limit
                // resolved-IP re-checks elsewhere in this function) is
                // catching a hostname that *resolves* somewhere the
                // pre-check couldn't have known about (private/local
                // ranges, or an IP-literal `deny_hosts` entry) -- a
                // DNS-rebinding-style gap, not the hostname-matching case.
                policy.check(&resolved.0, port, false).map_err(|_| ExitEgressError(COMMAND_UNSUPPORTED))?;
            }
            if let Some(rate_limiter) = rate_limiter {
                // `check_destination`
                // (called by `connect`, above, before this function ever
                // runs) only ever rate-limited on the pre-resolution
                // hostname string -- an attacker who controls many
                // hostnames/subdomains resolving to the same real target
                // IP got an independent token bucket per hostname string,
                // defeating the "per single destination address" throttle
                // this limiter is documented to provide (see
                // `AmplificationGuard`'s doc comment). Mirrors the policy
                // check just above: the hostname-keyed check in
                // `check_destination` is a cheap fast-path rejection layered
                // on top of, not a substitute for, this authoritative
                // resolved-IP check.
                rate_limiter.lock().unwrap().check(&canonical_host(&resolved.0), 1.0).map_err(|_| ExitEgressError(COMMAND_UNSUPPORTED))?;
            }
            connect_host = resolved.0;
        }
        // Bounded: a destination that silently drops the SYN (a firewalled
        // port, a dead host) must not hang this call forever -- see
        // `EGRESS_TIMEOUT`'s docs. Both the outer (timed-out) and inner
        // (connect refused/unreachable) failures collapse to the same
        // `HOST_UNREACHABLE` reply the caller already sends on any connect
        // error.
        tokio::time::timeout(EGRESS_TIMEOUT, tokio::net::TcpStream::connect((connect_host.as_str(), port)))
            .await
            .map_err(|_| ExitEgressError(HOST_UNREACHABLE))?
            .map_err(|_| ExitEgressError(HOST_UNREACHABLE))
    }
    // TOKIO-RESOLVE-CONNECT-END

    // -- UDP ASSOCIATE egress ------------------------------------------

    // TOKIO-HANDLE-DATAGRAM-BEGIN (calls resolve/open_association, both
    // stubbed alongside it; exercised by no test -- see /tmp/stub6.py)
    /// Relay one UDP datagram request to its destination. See the Python
    /// docstring: this never emits an error reply (UDP has no reliable
    /// error-signalling channel; a refusal is a silent drop).
    ///
    /// This `&mut self` form holds the `Egress` for the whole call,
    /// including the DNS resolve, so a caller that shares the `Egress`
    /// behind `SocksExit`'s `tokio::sync::Mutex` must use
    /// [`Egress::handle_datagram_shared`] instead, which does the same work
    /// without holding the lock across the resolve.
    pub async fn handle_datagram(&mut self, request: &DatagramRequest, emit: Box<dyn FnMut(&[u8]) + Send>, circuit_key: CircuitKey) {
        let Some(prep) = self.datagram_prepare(request) else { return };
        let send_host = if prep.filtering {
            match Egress::datagram_resolve(&request.host, request.port, &prep).await {
                Some(host) => host,
                None => return,
            }
        } else {
            request.host.clone()
        };
        self.datagram_deliver(request, send_host, emit, circuit_key).await;
    }

    /// [`Egress::handle_datagram`] for an `Egress` shared behind
    /// `SocksExit`'s `tokio::sync::Mutex`: the lock is held only for the
    /// short synchronous bookkeeping at either end, never across the DNS
    /// resolve (up to `EGRESS_TIMEOUT`).
    ///
    /// Holding it across the resolve let one client's datagram to a name
    /// whose nameserver never answers stall every other circuit's CONNECT,
    /// RESOLVE and `send_data`, which all share that lock -- the same defect
    /// `Egress::connect` already fixed for TCP. Because the lock no longer
    /// serialises these, each circuit's concurrent unlocked resolves are
    /// bounded here (`MAX_INFLIGHT_CONNECTS_PER_CIRCUIT`, shared with TCP
    /// connects, which is the same kind of work); a datagram over that bound
    /// is silently dropped, as UDP allows.
    pub async fn handle_datagram_shared(
        egress: &Rc<tokio::sync::Mutex<Egress>>,
        request: &DatagramRequest,
        emit: Box<dyn FnMut(&[u8]) + Send>,
        circuit_key: CircuitKey,
    ) {
        let prep = {
            let mut e = egress.lock().await;
            let Some(prep) = e.datagram_prepare(request) else { return };
            if prep.filtering {
                let count = e.in_flight_connects.entry(circuit_key.clone()).or_insert(0);
                if *count >= MAX_INFLIGHT_CONNECTS_PER_CIRCUIT {
                    return;
                }
                *count += 1;
            }
            prep
        };

        // No `Egress` lock held from here until the re-lock below.
        let send_host = if prep.filtering {
            let resolved = Egress::datagram_resolve(&request.host, request.port, &prep).await;
            let mut e = egress.lock().await;
            if let Some(count) = e.in_flight_connects.get_mut(&circuit_key) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    e.in_flight_connects.remove(&circuit_key);
                }
            }
            drop(e);
            match resolved {
                Some(host) => host,
                None => return,
            }
        } else {
            request.host.clone()
        };

        egress.lock().await.datagram_deliver(request, send_host, emit, circuit_key).await;
    }

    /// Phase one: everything that needs `&mut Egress` but no network.
    /// Returns `None` for a silent drop (the destination is refused up
    /// front), otherwise a snapshot of what the unlocked resolve needs.
    fn datagram_prepare(&mut self, request: &DatagramRequest) -> Option<DatagramPrep> {
        self.lease_table.reap();
        self.reap_stale_associations();

        let filtering = self.policy.is_some() || self.rate_limiter.is_some();
        if filtering && self.check_destination(&request.host, request.port, true).is_err() {
            return None;
        }
        Some(DatagramPrep { filtering, policy: self.policy.clone(), rate_limiter: self.rate_limiter.clone(), resolver: self.resolver.clone() })
    }

    /// Phase two: resolve the destination and re-check the policy and rate
    /// limit against the *resolved* address. Touches no `Egress` state, so
    /// it can run with no lock held. `None` means refuse (silently).
    async fn datagram_resolve(host: &str, port: u16, prep: &DatagramPrep) -> Option<String> {
        let resolved = resolve_snapshot(&prep.resolver, host).await?;
        if let Some(policy) = &prep.policy {
            if policy.check(&resolved.0, port, true).is_err() {
                return None;
            }
        }
        if let Some(limiter) = &prep.rate_limiter {
            // See the matching fix in `connect_tcp` -- the hostname-keyed
            // check in phase one (`check_destination`) is only a fast path
            // layered on top of this authoritative resolved-IP check, which
            // is what actually enforces the "per single destination
            // address" UDP throttle this limiter is documented to provide.
            if limiter.lock().unwrap().check(&canonical_host(&resolved.0), 1.0).is_err() {
                return None;
            }
        }
        Some(resolved.0)
    }

    /// Phase three: open (or reuse) the UDP association and send. The
    /// association is looked up *here*, after the resolve, not before it: a
    /// concurrent datagram on the same association may have opened or
    /// dropped it while this one was resolving.
    async fn datagram_deliver(&mut self, request: &DatagramRequest, send_host: String, mut emit: Box<dyn FnMut(&[u8]) + Send>, circuit_key: CircuitKey) {
        let association_id = request.association_id;
        let key = (circuit_key.clone(), association_id);

        let mut have_association = self.udp_associations.contains_key(&key);
        if have_association {
            let token = self.udp_associations.get(&key).unwrap().lease_token.clone();
            if self.lease_table.valid(&token) {
                self.lease_table.renew(&token);
            } else {
                self.drop_association(&key);
                have_association = false;
            }
        }

        if !have_association {
            match self.open_association(circuit_key, association_id, emit).await {
                Some(_) => {}
                None => return,
            }
        } else {
            self.udp_associations.get_mut(&key).unwrap().emit = std::mem::replace(&mut emit, Box::new(|_| {}));
        }

        if let Some(amp) = &self.amplification {
            let amp_key = self.udp_associations.get(&key).unwrap().amp_key();
            amp.lock().unwrap().track_request(&amp_key, request.payload.len() as i64);
        }

        if let Some(association) = self.udp_associations.get_mut(&key) {
            association.send(&send_host, request.port, &request.payload);
        }
    }
    // TOKIO-HANDLE-DATAGRAM-END

    // TOKIO-OPEN-ASSOCIATION-BEGIN (socket half only; the table bookkeeping
    // is shared with the fully-tested path via
    // Egress::insert_association_for_test, which stays outside this block --
    // see /tmp/stub6.py)
    /// Open a fresh UDP relay socket and lease for
    /// `(circuit_key, association_id)`. Unverified in this sandbox (no
    /// `tokio`) for the socket half; the table bookkeeping below it is
    /// shared with the fully-tested path via [`Egress::insert_association_for_test`].
    async fn open_association(&mut self, circuit_key: CircuitKey, association_id: u32, emit: Box<dyn FnMut(&[u8]) + Send>) -> Option<()> {
        let socket = tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await.ok()?;
        let socket = Arc::new(socket);
        let send_socket = socket.clone();
        let send_fn: Box<dyn FnMut(&[u8], &str, u16) + Send> = Box::new(move |payload: &[u8], host: &str, port: u16| {
            let socket = send_socket.clone();
            let payload = payload.to_vec();
            let target = format!("{host}:{port}");
            // Fire-and-forget: spawn the actual send so this closure (called
            // synchronously from `UDPAssociation::send`) never blocks.
            tokio::task::spawn(async move {
                if let Ok(addr) = target.parse::<std::net::SocketAddr>() {
                    let _ = socket.send_to(&payload, addr).await;
                }
            });
        });
        let lease = self.lease_table.issue(("udp-association".to_string(), association_id as u16), None).ok()?;
        let key = (circuit_key.clone(), association_id);
        let association = UDPAssociation::new(circuit_key, association_id, send_fn, None, lease.token, emit);
        self.udp_associations.insert(key, association);
        Some(())
    }
    // TOKIO-OPEN-ASSOCIATION-END

    /// Test-only equivalent of [`Egress::open_association`] that never
    /// touches a real socket, so `handle_datagram`'s association-reuse and
    /// bookkeeping logic can be exercised without `tokio`.
    #[cfg(test)]
    fn insert_association_for_test(&mut self, circuit_key: CircuitKey, association_id: u32, send_fn: Box<dyn FnMut(&[u8], &str, u16) + Send>, emit: Box<dyn FnMut(&[u8]) + Send>) {
        let lease = self.lease_table.issue(("udp-association".to_string(), association_id as u16), None).unwrap();
        let key = (circuit_key.clone(), association_id);
        let association = UDPAssociation::new(circuit_key, association_id, send_fn, None, lease.token, emit);
        self.udp_associations.insert(key, association);
    }

    /// Handle one inbound reply on a UDP association's relay socket.
    pub fn on_association_datagram(&mut self, circuit_key: CircuitKey, association_id: u32, addr_host: &str, addr_port: u16, data: &[u8]) {
        let key = (circuit_key, association_id);
        let amp_key = match self.udp_associations.get(&key) {
            Some(a) if !a.closed => a.amp_key(),
            _ => return,
        };
        if let Some(association) = self.udp_associations.get_mut(&key) {
            association.bytes_received += data.len() as u64;
        }
        if let Some(amp) = &self.amplification {
            if !amp.lock().unwrap().allow_response(&amp_key, data.len() as i64) {
                return;
            }
        }
        if data.len() as i64 > max_datagram_reply_payload() {
            return;
        }
        let reply = DatagramReply { association_id, host: addr_host.to_string(), port: addr_port, payload: data.to_vec() };
        let encoded = match encode_datagram_reply(&reply) {
            Ok(e) => e,
            Err(_) => return,
        };
        if let Some(association) = self.udp_associations.get_mut(&key) {
            (association.emit)(&encoded);
        }
    }

    fn drop_association(&mut self, key: &(CircuitKey, u32)) {
        if let Some(mut association) = self.udp_associations.remove(key) {
            if let Some(amp) = &self.amplification {
                amp.lock().unwrap().forget(&association.amp_key());
            }
            self.lease_table.release(&association.lease_token);
            association.close();
        }
    }

    /// Drop every UDP association whose lease has lapsed, not just one.
    /// Returns how many were dropped.
    pub fn reap_stale_associations(&mut self) -> usize {
        let stale: Vec<(CircuitKey, u32)> = self.udp_associations.iter().filter(|(_, a)| !self.lease_table.valid(&a.lease_token)).map(|(k, _)| k.clone()).collect();
        let n = stale.len();
        for key in &stale {
            self.drop_association(key);
        }
        n
    }

    /// Explicitly tear down one UDP association. Returns whether one existed.
    pub fn close_udp_association(&mut self, association_id: u32, circuit_key: CircuitKey) -> bool {
        let key = (circuit_key, association_id);
        let existed = self.udp_associations.contains_key(&key);
        self.drop_association(&key);
        existed
    }

    // TOKIO-HANDLE-REQUEST-BEGIN (calls resolve/connect/pump_stream, all
    // stubbed alongside it; exercised by no test -- see /tmp/stub6.py)
    /// Process one stream request and emit its reply via `emit`. Unverified
    /// in this sandbox for the CONNECT path (calls `connect`/`_pump_stream`);
    /// the RESOLVE path and reply-shape logic are pure and could be tested
    /// with a fake resolver (see `reply_for_status`/`reply_for_address`,
    /// which this delegates to and which the test module exercises
    /// directly).
    ///
    /// Free function taking `egress` by `&Rc<tokio::sync::Mutex<_>>`, not
    /// `&mut self`, same reason
    /// as [`Egress::connect`] (see its docs): both the RESOLVE and the
    /// CONNECT path here used to hold the whole `Egress` lock across a
    /// resolve, stalling every other circuit's own requests behind one
    /// slow lookup. `emit` now returns `bool` (queued vs. not) rather than
    /// `()`: [`Egress::pump_stream`]
    /// uses that to stop reading from (and close) a stream whose return
    /// path can't keep up, instead of queuing every byte the destination
    /// sends regardless of whether the client is still receiving it.
    pub async fn handle_request(
        egress: &Rc<tokio::sync::Mutex<Egress>>,
        request: &StreamRequest,
        mut emit: Box<dyn FnMut(&[u8]) -> bool + Send>,
        on_connected: Option<Box<dyn FnOnce(&StreamRequest, u32) + Send>>,
        circuit_key: CircuitKey,
    ) {
        if request.kind == RESOLVE {
            let (policy, rate_limiter, resolver) = {
                let e = egress.lock().await;
                (e.policy.clone(), e.rate_limiter.clone(), e.resolver.clone())
            };
            // Security audit fix (2026-09-26): this branch never checked
            // the rate limiter at all -- CONNECT/UDP both do, both before
            // and after resolution (finding 12's fix; see `connect_tcp`),
            // but RESOLVE was left entirely unbounded, letting a client
            // force unlimited real DNS lookups through this exit's
            // resolver regardless of `--rate-limit`. Pre-resolution
            // fast-path check on the requested hostname; deliberately
            // *not* routed through `check_destination` (which also
            // enforces the TCP/UDP port allow-list -- meaningless for a
            // bare RESOLVE, which names no port).
            if let Some(rate_limiter) = &rate_limiter {
                if rate_limiter.lock().unwrap().check(&canonical_host(&request.host), 1.0).is_err() {
                    let _ = emit(&reply_for_status(request, COMMAND_UNSUPPORTED));
                    return;
                }
            }
            // No lock held across the resolve itself -- see this fn's docs.
            let resolved = match resolve_snapshot(&resolver, &request.host).await {
                Some(r) => r,
                None => {
                    let _ = emit(&reply_for_status(request, HOST_UNREACHABLE));
                    return;
                }
            };
            if let Some(policy) = &policy {
                if !policy.host_allowed(&resolved.0) {
                    let _ = emit(&reply_for_status(request, COMMAND_UNSUPPORTED));
                    return;
                }
            }
            if let Some(rate_limiter) = &rate_limiter {
                // Authoritative resolved-IP re-check, mirroring
                // `connect_tcp`'s identical fix (finding 12): the
                // pre-check above is keyed on the (attacker-controlled)
                // hostname string, which a different-hostname-same-IP
                // trick would otherwise let bypass the throttle entirely.
                if rate_limiter.lock().unwrap().check(&canonical_host(&resolved.0), 1.0).is_err() {
                    let _ = emit(&reply_for_status(request, COMMAND_UNSUPPORTED));
                    return;
                }
            }
            let _ = emit(&reply_for_address(request, SUCCESS, &resolved));
            return;
        }

        if request.kind == CONNECT {
            let stream = match Egress::connect(egress, &request.host, request.port, circuit_key).await {
                Ok(s) => s,
                Err(e) => {
                    let status = if e.0 == 0 { GENERAL_FAILURE } else { e.0 };
                    let _ = emit(&reply_for_status(request, status));
                    return;
                }
            };
            let id = stream.lock().unwrap().id;
            if let Some(cb) = on_connected {
                cb(request, id);
            }
            let _ = emit(&reply_for_stream(request, SUCCESS, id));
            // Spawned, not `.await`-ed inline like Python's own
            // `await self._pump_stream(...)` -- a deliberate deviation, not
            // a straight port. Python needs no lock at all here: asyncio's
            // single-threaded cooperative scheduler lets any number of
            // `_serve_request`/`_pump_stream` coroutines interleave freely
            // over the same `Egress` object with nothing enforcing
            // exclusivity. Rust's borrow checker has no such thing --
            // `&mut Egress` access from concurrent tasks needs a real lock
            // -- so this port's composition layer (`SocksExit`) wraps
            // `Egress` in a `tokio::sync::Mutex`. Spawning `pump_stream` as
            // its own task lets `handle_request` return right after the
            // stream opens, matching what Python gets for free from having
            // no lock to hold in the first place.
            //
            // No `AmplificationGuard` tracking here: unlike UDP ASSOCIATE
            // (which really can be abused for reflection -- a spoofed
            // source gets a reply it never asked for), a CONNECT stream
            // requires a real TCP handshake with the client's own address,
            // so there is no third party to reflect traffic at. Wiring the
            // same ratio-based guard into this path (as a regression once
            // did) refuses to relay any ordinary response more than
            // `DEFAULT_MAX_AMPLIFICATION` (10x) larger than the request --
            // true of nearly every real HTTP response, download, or
            // stream, not just an attack.
            tokio::task::spawn_local(Egress::pump_stream(stream, emit));
            return;
        }

        let _ = emit(&reply_for_status(request, ADDR_UNSUPPORTED));
    }
    // TOKIO-HANDLE-REQUEST-END

    // TOKIO-PUMP-STREAM-BEGIN (exercised by no test -- see /tmp/stub6.py)
    /// Relay inbound bytes from the stream toward the client. Unverified in
    /// this sandbox (real socket reads via a real `TcpStream`'s read half),
    /// but the locking discipline itself does not depend on `tokio` and is
    /// deliberate: holding a `std::sync::MutexGuard` across an `.await`
    /// would be unsound (the guard is not safely held across a suspension
    /// point in general, and clippy correctly flags it), so instead of
    /// switching `ExitStream`'s wrapper to `tokio::sync::Mutex` -- which
    /// would force every other, currently-synchronous, fully-tested
    /// `Egress`/`ExitStream` method (`get_stream`, `send_data`, `track`,
    /// and every test using them) to become `async fn` for no benefit to
    /// those call sites -- this takes the `reader` out of the `ExitStream`
    /// under a short-lived lock, reads from it with no lock held, and puts
    /// it back under another short-lived lock. This mirrors `exit.py`'s
    /// `_pump_stream` (read, close-and-forget on EOF, amplification check,
    /// emit) while keeping `std::sync::Mutex` everywhere else in this file.
    ///
    /// A free function, not a `&mut self` method: see `handle_request`'s
    /// call site docs (this round's deadlock fix) for why this can no
    /// longer hold any lock on the enclosing `Egress` at all -- it runs as
    /// its own spawned task for as long as the real outbound connection
    /// stays open. No `AmplificationGuard` tracking (see the call site's
    /// doc comment for why a CONNECT stream is not a reflection vector).
    async fn pump_stream(stream: Arc<Mutex<ExitStream>>, mut emit: Box<dyn FnMut(&[u8]) -> bool + Send>) {
        Egress::pump_stream_with(stream, &mut emit, EMIT_BACKPRESSURE_POLL, EMIT_BACKPRESSURE_MAX_WAIT).await
    }

    /// Hand `chunk` to `emit`, waiting while it refuses.
    ///
    /// `emit` refuses when the return path already holds as much of this
    /// stream as it may (see `SocksExit`'s in-flight chunk cap). That means
    /// "slow down", not "give up": the destination socket is read no faster
    /// than the client can take the data, because nothing is read while this
    /// waits and the destination's own TCP window fills. Only a return path
    /// that makes no room at all for `max_wait` is treated as dead, and
    /// then the caller closes the stream. Returns whether `chunk` was taken.
    async fn emit_with_backpressure(emit: &mut Box<dyn FnMut(&[u8]) -> bool + Send>, chunk: &[u8], poll: std::time::Duration, max_wait: std::time::Duration) -> bool {
        let mut waited = std::time::Duration::ZERO;
        loop {
            if emit(chunk) {
                return true;
            }
            if waited >= max_wait {
                return false;
            }
            tokio::time::sleep(poll).await;
            waited += poll;
        }
    }

    async fn pump_stream_with(stream: Arc<Mutex<ExitStream>>, emit: &mut Box<dyn FnMut(&[u8]) -> bool + Send>, poll: std::time::Duration, max_wait: std::time::Duration) {
        loop {
            let (reader, notify, already_closed) = {
                let mut s = stream.lock().unwrap();
                (s.reader.take(), s.closed_notify(), s.closed())
            };
            // `close()` (from `close_idle_streams`, `close_circuit_streams`
            // or a send error, all called from other tasks) may already
            // have fired before this iteration started, or may fire while
            // the read below is parked -- either way, stop pumping rather
            // than reading on, which would otherwise keep this task (and
            // the `Arc<Mutex<ExitStream>>`, and the socket it holds) alive
            // forever against a destination that never sends and never
            // closes.
            if already_closed {
                let mut s = stream.lock().unwrap();
                s.reader = reader;
                return;
            }
            let (chunk, reader, closed_elsewhere) = match reader {
                Some(mut r) => {
                    use tokio::io::AsyncReadExt as _;
                    let mut buf = vec![0u8; 4096];
                    tokio::select! {
                        result = r.read(&mut buf) => match result {
                            Ok(n) => {
                                buf.truncate(n);
                                (buf, Some(r), false)
                            }
                            Err(_) => (Vec::new(), Some(r), false),
                        },
                        () = notify.notified() => (Vec::new(), Some(r), true),
                    }
                }
                // No real reader attached (e.g. a test-constructed stream):
                // nothing to pump, matches an already-closed/EOF stream.
                None => (Vec::new(), None, false),
            };
            if closed_elsewhere {
                let mut s = stream.lock().unwrap();
                s.reader = reader;
                return;
            }
            {
                let mut s = stream.lock().unwrap();
                s.reader = reader;
                if !chunk.is_empty() {
                    // Count a
                    // destination-to-client read as activity too, not just
                    // client-to-destination `send`s, so
                    // `Egress::close_idle_streams` doesn't time out a
                    // stream that's actively (if one-directionally)
                    // in use.
                    s.touch();
                }
            }

            if chunk.is_empty() {
                stream.lock().unwrap().close();
                // An empty chunk is EOF -- signal it downstream with one
                // empty `emit` call, exactly like this port's forward
                // direction already treats an empty read (see
                // `SocksServer::relay_stream`'s own `Ok(Ok(0)) => break`,
                // whose fragment-side counterpart is
                // `SocksExit::send_backward` turning an empty payload into
                // a single FIN fragment). Deviation from Python's
                // `_pump_stream`, which never calls `emit` here at all and
                // instead relies on `_serve_request`'s `finally` block to
                // send the FIN once `_pump_stream` (awaited inline there)
                // returns -- not available to this port's `pump_stream`,
                // which runs as its own spawned task specifically so it
                // does *not* hold `handle_request`'s caller's lock for the
                // stream's whole lifetime (see `handle_request`'s own docs
                // for that fix); emitting the EOF marker from inside
                // `pump_stream` itself is this port's equivalent trigger.
                // Best-effort: the stream is already closing either way,
                // so a full return channel here just means the FIN itself
                // is lost, not that anything grows unboundedly.
                // The FIN gets the same patience as data: with the return
                // path full, dropping it would leave the client waiting for
                // an end-of-stream that never comes.
                let _ = Egress::emit_with_backpressure(emit, &[], poll, max_wait).await;
                break;
            }

            // This is the actual
            // throttle. `emit` returns `false` once its caller's per-stream
            // in-flight/return-path capacity is exhausted (see
            // `SocksExit::serve_request`'s emit closure); previously
            // nothing here slowed the read loop at all; a destination
            // sending at line rate into a client that never acks would
            // just keep piling 4 KiB chunks into memory as fast as the
            // socket could deliver them. A refusal now pauses the read
            // (see `emit_with_backpressure`); the stream is closed only if
            // the return path stays full for `EMIT_BACKPRESSURE_MAX_WAIT`.
            // Closing on the first refusal truncated every download fast
            // enough to fill the cap -- any file larger than a couple of
            // MB from a fast origin.
            if !Egress::emit_with_backpressure(emit, &chunk, poll, max_wait).await {
                stream.lock().unwrap().close();
                break;
            }
        }
    }
    // TOKIO-PUMP-STREAM-END
}

/// How often [`Egress::emit_with_backpressure`] retries a refused chunk.
const EMIT_BACKPRESSURE_POLL: std::time::Duration = std::time::Duration::from_millis(5);

/// How long a stream's return path may refuse every chunk before the stream
/// is closed as dead. Matches the exit's own send-window wait
/// (`RETURN_WINDOW_MAX_WAIT`): a client that has stopped acking entirely.
const EMIT_BACKPRESSURE_MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// Resolve `host` using `resolver` if set, else the OS resolver -- the
/// unlocked half of [`Egress::resolve`]/[`Egress::connect`]/
/// `Egress::handle_request`'s RESOLVE path.
///
/// This closes a gap a previous fix only partially addressed: the timeout
/// used to be applied only in the no-custom-resolver branch (`if let
/// Some(resolver) = &self.resolver { return resolver(host).await; }`, with
/// no bound at all). `allium-relay-cli`'s `cmd_exit` *always* installs a
/// custom resolver (a thin wrapper around `tokio::net::lookup_host`) --
/// every production exit was taking the unbounded branch on every single
/// RESOLVE and every CONNECT's implicit resolve. Wrapping the whole match
/// in one `timeout` bounds both branches identically.
async fn resolve_snapshot(resolver: &Option<Arc<ResolverFn>>, host: &str) -> Option<(String, u16)> {
    match resolver {
        Some(resolver) => tokio::time::timeout(EGRESS_TIMEOUT, resolver(host)).await.ok()?,
        None => {
            let target = format!("{host}:0");
            let mut addrs = tokio::time::timeout(EGRESS_TIMEOUT, tokio::net::lookup_host(&target)).await.ok()?.ok()?;
            let addr = addrs.next()?;
            Some((addr.ip().to_string(), addr.port()))
        }
    }
}

/// Periodically close streams idle for longer than [`STREAM_IDLE_TIMEOUT`].
/// Call once, right after
/// [`SocksExit::install`] wires `egress` in; runs for the life of the
/// process, like the other background tasks `install` spawns
/// (`retransmit_sweep`, the backward-pump loop).
pub fn spawn_idle_stream_sweeper(egress: Rc<tokio::sync::Mutex<Egress>>) {
    tokio::task::spawn_local(async move {
        loop {
            tokio::time::sleep(IDLE_STREAM_SWEEP_INTERVAL).await;
            egress.lock().await.close_idle_streams(STREAM_IDLE_TIMEOUT);
        }
    });
}

#[derive(Debug, Clone)]
pub enum CheckDestinationError {
    Policy(PolicyDenied),
    RateLimit(RateLimitExceeded),
}
impl std::fmt::Display for CheckDestinationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckDestinationError::Policy(e) => write!(f, "{e}"),
            CheckDestinationError::RateLimit(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for CheckDestinationError {}

fn reply_for_status(request: &StreamRequest, status: u8) -> Vec<u8> {
    encode_reply(&StreamReply { request_id: request.request_id, status, stream_id: 0, address: None }).unwrap_or_default()
}
fn reply_for_stream(request: &StreamRequest, status: u8, stream_id: u32) -> Vec<u8> {
    encode_reply(&StreamReply { request_id: request.request_id, status, stream_id, address: None }).unwrap_or_default()
}
fn reply_for_address(request: &StreamRequest, status: u8, address: &(String, u16)) -> Vec<u8> {
    encode_reply(&StreamReply { request_id: request.request_id, status, stream_id: 0, address: Some(address.clone()) }).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ExitPolicy;
    use std::sync::Mutex as StdMutex;

    fn recording_send() -> (Box<dyn FnMut(&[u8]) -> Result<(), ExitEgressError> + Send>, Arc<StdMutex<Vec<Vec<u8>>>>) {
        let log = Arc::new(StdMutex::new(Vec::new()));
        let log2 = log.clone();
        let f: Box<dyn FnMut(&[u8]) -> Result<(), ExitEgressError> + Send> = Box::new(move |data: &[u8]| {
            log2.lock().unwrap().push(data.to_vec());
            Ok(())
        });
        (f, log)
    }

    #[test]
    fn test_next_stream_id_increments() {
        let mut egress = Egress::new(None, None, None, None, None);
        assert_eq!(egress.next_stream_id(), 1);
        assert_eq!(egress.next_stream_id(), 2);
        assert_eq!(egress.next_stream_id(), 3);
    }

    #[test]
    fn test_stream_tracking_off_by_default() {
        let mut egress = Egress::new(None, None, None, None, None);
        let (send_fn, _log) = recording_send();
        let stream = Arc::new(Mutex::new(ExitStream::from_parts_for_test(1, send_fn, Box::new(|| {}))));
        egress.track(None, &stream);
        assert!(egress.get_stream(1, None).is_none());
    }

    #[test]
    fn test_stream_tracking_and_get_stream() {
        let mut egress = Egress::new(None, None, None, None, None);
        egress.enable_stream_tracking();
        let (send_fn, _log) = recording_send();
        let stream = Arc::new(Mutex::new(ExitStream::from_parts_for_test(1, send_fn, Box::new(|| {}))));
        egress.track(None, &stream);
        assert!(egress.get_stream(1, None).is_some());
        // A different circuit_key must not find it.
        assert!(egress.get_stream(1, Some(("10.0.0.2".to_string(), 9001, 99))).is_none());
    }

    #[test]
    fn test_send_data_isolated_by_circuit_key() {
        // Regression test: two
        // different circuits opening a stream with the SAME stream id must
        // never collide, and a client on one circuit must never be able to
        // write into a stream opened by another circuit -- even one it can
        // correctly guess or observe the numeric stream id of.
        let mut egress = Egress::new(None, None, None, None, None);
        egress.enable_stream_tracking();
        let circuit_a: CircuitKey = Some(("10.0.0.1".to_string(), 9001, 1));
        let circuit_b: CircuitKey = Some(("10.0.0.2".to_string(), 9001, 2));

        let (send_fn_a, log_a) = recording_send();
        let stream_a = Arc::new(Mutex::new(ExitStream::from_parts_for_test(1, send_fn_a, Box::new(|| {}))));
        egress.track(circuit_a.clone(), &stream_a);

        // Circuit B opens its own stream, which the exit-wide counter hands
        // the SAME numeric id (1) -- exactly the collision a shared global
        // counter + a shared namespace used to allow.
        let (send_fn_b, log_b) = recording_send();
        let stream_b = Arc::new(Mutex::new(ExitStream::from_parts_for_test(1, send_fn_b, Box::new(|| {}))));
        egress.track(circuit_b.clone(), &stream_b);

        // Circuit B sends data tagged with stream id 1: it must land on
        // ITS OWN stream, never on circuit A's.
        assert!(egress.send_data(1, b"from-b", circuit_b.clone()));
        assert_eq!(log_b.lock().unwrap()[0], b"from-b");
        assert!(log_a.lock().unwrap().is_empty(), "circuit B's data must never reach circuit A's stream");

        // Both circuits still reach their own stream by their own key...
        assert!(egress.get_stream(1, circuit_a.clone()).is_some());
        assert!(egress.get_stream(1, circuit_b).is_some());
        // ...but a third, untracked circuit guessing the same numeric
        // stream id finds nothing -- the wrong circuit key alone stops it,
        // even though the numeric id it guessed is exactly right.
        let circuit_c: CircuitKey = Some(("10.0.0.3".to_string(), 9001, 3));
        assert!(egress.get_stream(1, circuit_c).is_none());
    }

    #[test]
    fn test_get_stream_returns_none_after_drop() {
        let mut egress = Egress::new(None, None, None, None, None);
        egress.enable_stream_tracking();
        let (send_fn, _log) = recording_send();
        let stream = Arc::new(Mutex::new(ExitStream::from_parts_for_test(1, send_fn, Box::new(|| {}))));
        egress.track(None, &stream);
        drop(stream);
        assert!(egress.get_stream(1, None).is_none());
    }

    #[test]
    fn test_send_data_writes_and_returns_true() {
        let mut egress = Egress::new(None, None, None, None, None);
        egress.enable_stream_tracking();
        let (send_fn, log) = recording_send();
        let stream = Arc::new(Mutex::new(ExitStream::from_parts_for_test(1, send_fn, Box::new(|| {}))));
        egress.track(None, &stream);
        assert!(egress.send_data(1, b"hello", None));
        assert_eq!(log.lock().unwrap()[0], b"hello");
    }

    #[test]
    fn test_send_data_returns_false_when_stream_unknown() {
        let mut egress = Egress::new(None, None, None, None, None);
        assert!(!egress.send_data(42, b"x", None));
    }

    #[test]
    fn test_send_data_false_on_write_error() {
        let mut egress = Egress::new(None, None, None, None, None);
        egress.enable_stream_tracking();
        let send_fn: Box<dyn FnMut(&[u8]) -> Result<(), ExitEgressError> + Send> = Box::new(|_| Err(ExitEgressError(GENERAL_FAILURE)));
        let stream = Arc::new(Mutex::new(ExitStream::from_parts_for_test(1, send_fn, Box::new(|| {}))));
        egress.track(None, &stream);
        assert!(!egress.send_data(1, b"x", None));
        assert!(egress.get_stream(1, None).is_none());
    }

    #[test]
    fn test_check_destination_denies_private_by_default() {
        let policy = ExitPolicy::new(&[80], &[], false, false, &[]).unwrap();
        let egress = Egress::new(None, Some(policy), None, None, None);
        assert!(egress.check_destination("127.0.0.1", 80, false).is_err());
    }

    #[test]
    fn test_check_destination_allows_ordinary_host() {
        let policy = ExitPolicy::new(&[80], &[], false, false, &[]).unwrap();
        let egress = Egress::new(None, Some(policy), None, None, None);
        assert!(egress.check_destination("93.184.216.34", 80, false).is_ok());
    }

    /// A resolver stub for the two regression tests below: always
    /// resolves to the same fixed address, regardless of the hostname
    /// asked for -- simulating many different hostnames pointed at one
    /// real destination.
    fn same_ip_resolver() -> Arc<ResolverFn> {
        Arc::new(|_host: &str| Box::pin(async { Some(("127.0.0.1".to_string(), 1)) }))
    }

    /// Two different hostnames
    /// that resolve to the same real destination must not each get an
    /// independent rate-limit bucket in `Egress::connect_tcp` -- that
    /// would let an attacker who controls many hostnames pointed at one
    /// victim IP defeat the "per single destination address" throttle
    /// entirely by rotating which hostname it uses per `CONNECT`.
    #[tokio::test]
    async fn test_connect_tcp_rate_limits_by_resolved_address_not_hostname() {
        let resolver = same_ip_resolver();
        // burst=1 at a near-zero refill rate: the second `check` call for
        // the same key, an instant later, must still be denied.
        let limiter = Arc::new(Mutex::new(RateLimiter::new(0.0001, 1, None, None, None).unwrap()));

        // First hostname: consumes the resolved IP's one token. Port 1 on
        // loopback has nothing listening, so the actual TCP connect fails
        // fast (connection refused) regardless -- what matters is *why*
        // it failed.
        let first = Egress::connect_tcp("host-one.example", 1, &None, &Some(limiter.clone()), &Some(resolver.clone())).await;
        if let Err(code) = &first {
            assert_ne!(*code, ExitEgressError(COMMAND_UNSUPPORTED), "the first attempt must not itself be rate-limited");
        }

        // A completely different hostname, resolving to the very same
        // address: must now be rejected by the resolved-IP rate limit,
        // not handed a fresh bucket just because the hostname differs.
        let second = Egress::connect_tcp("host-two.example", 1, &None, &Some(limiter), &Some(resolver)).await;
        assert_eq!(
            second.err(),
            Some(ExitEgressError(COMMAND_UNSUPPORTED)),
            "a different hostname resolving to the same address must be rate-limited, not given a fresh bucket"
        );
    }

    /// Same property as above, for the UDP `handle_datagram` path.
    #[tokio::test]
    async fn test_handle_datagram_rate_limits_by_resolved_address_not_hostname() {
        let limiter = RateLimiter::new(0.0001, 1, None, None, None).unwrap();
        let mut egress = Egress::new(Some(resolver_boxed()), None, Some(limiter), None, None);
        let circuit_key: CircuitKey = None;

        for (i, host) in ["host-one.example", "host-two.example"].into_iter().enumerate() {
            let request = DatagramRequest { association_id: i as u32, host: host.to_string(), port: 1, payload: vec![0u8], bytes_sent: 0 };
            egress.handle_datagram(&request, Box::new(|_reply: &[u8]| {}), circuit_key.clone()).await;
        }

        // The second, different-hostname-same-address datagram must have
        // been dropped by the resolved-IP rate limit before an
        // association was ever opened for it.
        assert!(egress.udp_associations.contains_key(&(circuit_key.clone(), 0)), "the first datagram must not itself be rate-limited");
        assert!(
            !egress.udp_associations.contains_key(&(circuit_key, 1)),
            "a different hostname resolving to the same address must be rate-limited, not given a fresh bucket"
        );
    }

    /// A boxed resolver closure matching `Egress::new`'s expected type,
    /// always resolving to the same fixed address (see `same_ip_resolver`).
    fn resolver_boxed() -> Box<dyn Fn(&str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<(String, u16)>> + Send>> + Send + Sync> {
        Box::new(|_host: &str| Box::pin(async { Some(("127.0.0.1".to_string(), 1)) }))
    }

    /// Security audit fix (2026-09-26): `handle_request`'s RESOLVE branch
    /// used to apply no rate limiting at all, unlike CONNECT/UDP -- a
    /// client could force unlimited real DNS lookups through this exit's
    /// resolver. Same property as the CONNECT/UDP tests above: two
    /// different hostnames resolving to the same address must share one
    /// rate-limit bucket, not each get their own.
    #[tokio::test]
    async fn test_handle_request_resolve_rate_limits_by_resolved_address_not_hostname() {
        let limiter = RateLimiter::new(0.0001, 1, None, None, None).unwrap();
        let egress = Rc::new(tokio::sync::Mutex::new(Egress::new(Some(resolver_boxed()), None, Some(limiter), None, None)));

        let statuses = Arc::new(StdMutex::new(Vec::new()));
        for (i, host) in ["host-one.example", "host-two.example"].into_iter().enumerate() {
            let request = StreamRequest { kind: RESOLVE, request_id: i as u32, host: host.to_string(), port: 0, bytes_sent: 0 };
            let statuses = statuses.clone();
            let emit: Box<dyn FnMut(&[u8]) -> bool + Send> = Box::new(move |data: &[u8]| {
                if let Ok(reply) = crate::socks::decode_reply(data) {
                    statuses.lock().unwrap().push(reply.status);
                }
                true
            });
            Egress::handle_request(&egress, &request, emit, None, None).await;
        }

        let statuses = statuses.lock().unwrap();
        assert_eq!(statuses[0], SUCCESS, "the first RESOLVE must not itself be rate-limited");
        assert_eq!(
            statuses[1], COMMAND_UNSUPPORTED,
            "a different hostname resolving to the same address must be rate-limited, not given a fresh bucket"
        );
    }

    /// Regression test: enabling `AmplificationGuard::with_defaults()` on
    /// `Egress` (as `cmd_exit` now does, closing finding H4) must not
    /// gate a plain CONNECT/`pump_stream` response -- unlike UDP
    /// ASSOCIATE, a CONNECT stream requires a real TCP handshake with the
    /// client's own address, so there is no reflection to guard against,
    /// and the guard's ratio (10x over a 64-byte floor) is trivially
    /// exceeded by any ordinary download. This used to close the stream
    /// after roughly the first 4 KiB read, silently truncating every real
    /// response of any size.
    #[test]
    fn test_connect_response_is_not_truncated_by_the_amplification_guard() {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind origin listener");
        let addr = listener.local_addr().expect("origin local_addr");
        let big = vec![0x42u8; 200_000]; // far more than 10x a tiny request
        let big2 = big.clone();
        let origin_thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("origin accept");
            let mut buf = [0u8; 16];
            let _ = stream.read(&mut buf).expect("origin read");
            stream.write_all(&big2).expect("origin write");
            let _ = stream.flush();
            let _ = stream.shutdown(std::net::Shutdown::Write);
        });

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("failed to start tokio runtime");
        let local = tokio::task::LocalSet::new();
        let received = local.block_on(&rt, async move {
            let policy = ExitPolicy::new(&[addr.port()], &[], false, true, &[]).unwrap();
            let egress = Egress::new(None, Some(policy), None, Some(AmplificationGuard::with_defaults()), None);
            let egress = Rc::new(tokio::sync::Mutex::new(egress));
            egress.lock().await.enable_stream_tracking();

            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            let mut done_tx = Some(done_tx);
            let received = Arc::new(StdMutex::new(Vec::new()));
            let received2 = received.clone();
            let emit: Box<dyn FnMut(&[u8]) -> bool + Send> = Box::new(move |data: &[u8]| {
                received2.lock().unwrap().extend_from_slice(data);
                if data.is_empty() {
                    if let Some(tx) = done_tx.take() {
                        let _ = tx.send(());
                    }
                }
                true
            });
            let request = StreamRequest { kind: CONNECT, request_id: 1, host: "127.0.0.1".to_string(), port: addr.port(), bytes_sent: 4 };
            let stream_id = Arc::new(StdMutex::new(None));
            let stream_id2 = stream_id.clone();
            let on_connected: Box<dyn FnOnce(&StreamRequest, u32) + Send> = Box::new(move |_req, id| {
                *stream_id2.lock().unwrap() = Some(id);
            });
            Egress::handle_request(&egress, &request, emit, Some(on_connected), None).await;
            let id = stream_id.lock().unwrap().expect("CONNECT must have succeeded and reported its stream id");
            // Forward the client's small request payload to the origin,
            // exactly like a real circuit's `send_data` would -- this is
            // what unblocks the origin's own read and lets it send its
            // (much larger) response back through `pump_stream`.
            assert!(egress.lock().await.send_data(id, b"GET /\r\n\r\n", None), "send_data must find the just-opened stream");

            tokio::time::timeout(std::time::Duration::from_secs(5), done_rx).await.expect("pump_stream never reached EOF").unwrap();
            let out = received.lock().unwrap().clone();
            out
        });
        origin_thread.join().expect("origin thread panicked");

        // The first `emit` call is the encoded `StreamReply` for the
        // opened stream, followed by raw response chunks, then a final
        // empty EOF marker -- so the accumulated bytes are at least the
        // full response plus that small header, not truncated partway
        // through by a 10x-ratio cutoff.
        assert!(received.len() >= big.len(), "response was truncated: got {} bytes, expected at least {}", received.len(), big.len());
    }

    #[test]
    fn test_udp_association_bookkeeping_send_and_amp_tracking() {
        let mut egress = Egress::new(None, None, None, Some(AmplificationGuard::with_defaults()), None);
        let sent_log = Arc::new(StdMutex::new(Vec::new()));
        let sent_log2 = sent_log.clone();
        let send_fn: Box<dyn FnMut(&[u8], &str, u16) + Send> = Box::new(move |payload: &[u8], host: &str, port: u16| {
            sent_log2.lock().unwrap().push((payload.to_vec(), host.to_string(), port));
        });
        let emitted = Arc::new(StdMutex::new(Vec::new()));
        let emitted2 = emitted.clone();
        let emit: Box<dyn FnMut(&[u8]) + Send> = Box::new(move |data: &[u8]| emitted2.lock().unwrap().push(data.to_vec()));
        egress.insert_association_for_test(None, 1, send_fn, emit);
        {
            let assoc = egress.udp_associations.get_mut(&(None, 1)).unwrap();
            assoc.send("1.2.3.4", 53, b"query");
            assert_eq!(assoc.bytes_sent, 5);
        }
        assert_eq!(sent_log.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_on_association_datagram_emits_reply() {
        let mut egress = Egress::new(None, None, None, None, None);
        let emitted = Arc::new(StdMutex::new(Vec::new()));
        let emitted2 = emitted.clone();
        let emit: Box<dyn FnMut(&[u8]) + Send> = Box::new(move |data: &[u8]| emitted2.lock().unwrap().push(data.to_vec()));
        egress.insert_association_for_test(None, 1, Box::new(|_, _, _| {}), emit);
        egress.on_association_datagram(None, 1, "5.6.7.8", 53, b"answer");
        assert_eq!(emitted.lock().unwrap().len(), 1);
        let decoded = crate::socks::decode_datagram_reply(&emitted.lock().unwrap()[0]).unwrap();
        assert_eq!(decoded.payload, b"answer");
        assert_eq!(decoded.host, "5.6.7.8");
    }

    #[test]
    fn test_on_association_datagram_ignores_unknown_association() {
        let mut egress = Egress::new(None, None, None, None, None);
        // No panic, no emit -- just silently ignored (an
        // unauthenticated association_id alone must never route anything).
        egress.on_association_datagram(None, 999, "5.6.7.8", 53, b"x");
    }

    #[test]
    fn test_close_udp_association_returns_existed() {
        let mut egress = Egress::new(None, None, None, None, None);
        assert!(!egress.close_udp_association(1, None));
        egress.insert_association_for_test(None, 1, Box::new(|_, _, _| {}), Box::new(|_| {}));
        assert!(egress.close_udp_association(1, None));
        assert!(egress.udp_associations.is_empty());
    }

    #[test]
    fn test_reap_stale_associations_drops_expired() {
        let lease_table = LeaseTable::new(0.001, None).unwrap();
        let mut egress = Egress::new(None, None, None, None, Some(lease_table));
        egress.insert_association_for_test(None, 1, Box::new(|_, _, _| {}), Box::new(|_| {}));
        std::thread::sleep(std::time::Duration::from_millis(5));
        let dropped = egress.reap_stale_associations();
        assert_eq!(dropped, 1);
        assert!(egress.udp_associations.is_empty());
    }

    #[test]
    fn test_reply_for_status_round_trips() {
        let req = StreamRequest { kind: CONNECT, request_id: 5, host: "h".to_string(), port: 1, bytes_sent: 0 };
        let bytes = reply_for_status(&req, GENERAL_FAILURE);
        let decoded = crate::socks::decode_reply(&bytes).unwrap();
        assert_eq!(decoded.request_id, 5);
        assert_eq!(decoded.status, GENERAL_FAILURE);
        assert!(decoded.address.is_none());
    }

    #[test]
    fn test_reply_for_address_round_trips() {
        let req = StreamRequest { kind: RESOLVE, request_id: 6, host: "example.com".to_string(), port: 0, bytes_sent: 0 };
        let bytes = reply_for_address(&req, SUCCESS, &("93.184.216.34".to_string(), 0));
        let decoded = crate::socks::decode_reply(&bytes).unwrap();
        assert_eq!(decoded.address, Some(("93.184.216.34".to_string(), 0)));
    }

    #[test]
    fn test_amp_key_includes_circuit_key_and_association_id() {
        let a1 = UDPAssociation::new(Some(("10.0.0.1".to_string(), 9001, 1)), 1, Box::new(|_, _, _| {}), None, vec![], Box::new(|_| {}));
        let a2 = UDPAssociation::new(Some(("10.0.0.1".to_string(), 9001, 2)), 1, Box::new(|_, _, _| {}), None, vec![], Box::new(|_| {}));
        assert_ne!(a1.amp_key(), a2.amp_key());
    }

    // -- handle_datagram_shared: no lock across the resolve ---------------

    type TestResolver = Box<dyn Fn(&str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<(String, u16)>> + Send>> + Send + Sync>;

    /// A resolver that blocks until `release` is set to `true`, counting how
    /// many lookups have started (a stand-in for a nameserver that never answers).
    fn blocking_resolver(release: tokio::sync::watch::Receiver<bool>, started: Arc<std::sync::atomic::AtomicUsize>) -> TestResolver {
        Box::new(move |_host: &str| {
            let mut release = release.clone();
            let started = started.clone();
            Box::pin(async move {
                started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = release.wait_for(|released| *released).await;
                Some(("127.0.0.1".to_string(), 1))
            })
        })
    }

    fn permissive_limiter() -> RateLimiter {
        RateLimiter::new(1000.0, 1000, None, None, None).unwrap()
    }

    fn datagram_to(host: &str, association_id: u32) -> DatagramRequest {
        DatagramRequest { association_id, host: host.to_string(), port: 1, payload: vec![0u8], bytes_sent: 0 }
    }

    /// The defect: the datagram path held the egress lock across the DNS
    /// resolve, so one blocked lookup stalled every other circuit's
    /// CONNECT/RESOLVE/`send_data`. While a resolve is blocked, another
    /// circuit must be able to take the lock.
    #[tokio::test]
    async fn test_handle_datagram_shared_does_not_hold_the_egress_lock_across_a_blocked_resolve() {
        let (release_tx, release_rx) = tokio::sync::watch::channel(false);
        let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let egress = Rc::new(tokio::sync::Mutex::new(Egress::new(Some(blocking_resolver(release_rx, started.clone())), None, Some(permissive_limiter()), None, None)));

        let request = datagram_to("slow.example", 1);
        let datagram = Egress::handle_datagram_shared(&egress, &request, Box::new(|_reply: &[u8]| {}), None);
        let probe = async {
            while started.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
            // the resolve is now blocked; someone else needs the egress
            let got = tokio::time::timeout(std::time::Duration::from_millis(500), egress.lock()).await;
            assert!(got.is_ok(), "the egress lock was held across a blocked DNS resolve");
            drop(got);
            release_tx.send(true).unwrap();
        };
        tokio::join!(datagram, probe);

        // and once the resolve completes the datagram still goes out
        assert!(egress.lock().await.udp_associations.contains_key(&(None, 1)));
    }

    /// Without the lock serialising them, one circuit's blocked resolves must
    /// be bounded (and released again), or a flood of datagrams to
    /// unanswerable names becomes unbounded concurrent lookups.
    #[tokio::test]
    async fn test_handle_datagram_shared_bounds_a_circuits_concurrent_resolves_and_releases_them() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let (release_tx, release_rx) = tokio::sync::watch::channel(false);
                let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let egress = Rc::new(tokio::sync::Mutex::new(Egress::new(Some(blocking_resolver(release_rx, started.clone())), None, Some(permissive_limiter()), None, None)));

                let mut handles = Vec::new();
                for i in 0..(MAX_INFLIGHT_CONNECTS_PER_CIRCUIT as u32 + 8) {
                    let egress = egress.clone();
                    handles.push(tokio::task::spawn_local(async move {
                        Egress::handle_datagram_shared(&egress, &datagram_to("slow.example", i), Box::new(|_reply: &[u8]| {}), None).await;
                    }));
                }
                // let every task run up to its blocked resolve (or its drop)
                for _ in 0..50 {
                    tokio::task::yield_now().await;
                }
                assert_eq!(started.load(std::sync::atomic::Ordering::SeqCst), MAX_INFLIGHT_CONNECTS_PER_CIRCUIT, "only the per-circuit bound may be resolving at once");
                assert_eq!(egress.lock().await.in_flight_connects.get(&None), Some(&MAX_INFLIGHT_CONNECTS_PER_CIRCUIT));

                release_tx.send(true).unwrap();
                for h in handles {
                    h.await.unwrap();
                }
                assert!(egress.lock().await.in_flight_connects.is_empty(), "every resolve must release its slot, however it ended");
            })
            .await;
    }

    #[tokio::test]
    async fn test_handle_datagram_shared_releases_its_slot_when_the_resolve_fails() {
        let resolver: TestResolver = Box::new(|_host: &str| Box::pin(async { None }));
        let egress = Rc::new(tokio::sync::Mutex::new(Egress::new(Some(resolver), None, Some(permissive_limiter()), None, None)));
        Egress::handle_datagram_shared(&egress, &datagram_to("nxdomain.example", 1), Box::new(|_reply: &[u8]| {}), None).await;
        let e = egress.lock().await;
        assert!(e.in_flight_connects.is_empty(), "a failed resolve must not leak its in-flight slot");
        assert!(e.udp_associations.is_empty(), "nothing is sent for a name that does not resolve");
    }

    /// Two datagrams on one association resolving at the same time must end
    /// up sharing one association: it is looked up after the resolve, under
    /// the lock, so the second sees the first's.
    #[tokio::test]
    async fn test_handle_datagram_shared_concurrent_datagrams_share_one_association() {
        let egress = Rc::new(tokio::sync::Mutex::new(Egress::new(Some(resolver_boxed()), None, Some(permissive_limiter()), None, None)));
        let (a, b) = (datagram_to("one.example", 7), datagram_to("two.example", 7));
        tokio::join!(
            Egress::handle_datagram_shared(&egress, &a, Box::new(|_r: &[u8]| {}), None),
            Egress::handle_datagram_shared(&egress, &b, Box::new(|_r: &[u8]| {}), None),
        );
        assert_eq!(egress.lock().await.udp_associations.len(), 1);
    }

    /// The resolved-address rate limit still applies on the shared path.
    #[tokio::test]
    async fn test_handle_datagram_shared_still_rate_limits_by_resolved_address() {
        let limiter = RateLimiter::new(0.0001, 1, None, None, None).unwrap();
        let egress = Rc::new(tokio::sync::Mutex::new(Egress::new(Some(resolver_boxed()), None, Some(limiter), None, None)));
        for (i, host) in ["host-one.example", "host-two.example"].into_iter().enumerate() {
            Egress::handle_datagram_shared(&egress, &datagram_to(host, i as u32), Box::new(|_r: &[u8]| {}), None).await;
        }
        let e = egress.lock().await;
        assert!(e.udp_associations.contains_key(&(None, 0)), "the first datagram must not itself be rate-limited");
        assert!(!e.udp_associations.contains_key(&(None, 1)), "a different hostname resolving to the same address must share the bucket");
    }

    // ---- backpressure: a slow return path pauses the read, it does not end the stream ----

    fn rt_local() -> (tokio::runtime::Runtime, tokio::task::LocalSet) {
        (tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap(), tokio::task::LocalSet::new())
    }

    #[test]
    fn emit_with_backpressure_waits_out_a_refusal() {
        let (rt, local) = rt_local();
        let calls = Arc::new(StdMutex::new(0u32));
        let c = calls.clone();
        let mut emit: Box<dyn FnMut(&[u8]) -> bool + Send> = Box::new(move |_| {
            let mut n = c.lock().unwrap();
            *n += 1;
            *n > 5 // refuse the first five attempts
        });
        let taken = local.block_on(&rt, Egress::emit_with_backpressure(&mut emit, b"x", std::time::Duration::from_millis(1), std::time::Duration::from_secs(5)));
        assert!(taken);
        assert_eq!(*calls.lock().unwrap(), 6);
    }

    #[test]
    fn emit_with_backpressure_gives_up_only_after_the_full_wait() {
        let (rt, local) = rt_local();
        let calls = Arc::new(StdMutex::new(0u32));
        let c = calls.clone();
        let mut emit: Box<dyn FnMut(&[u8]) -> bool + Send> = Box::new(move |_| {
            *c.lock().unwrap() += 1;
            false
        });
        let started = std::time::Instant::now();
        let taken = local.block_on(&rt, Egress::emit_with_backpressure(&mut emit, b"x", std::time::Duration::from_millis(2), std::time::Duration::from_millis(100)));
        assert!(!taken, "a return path that never makes room must end in a refusal");
        assert!(started.elapsed() >= std::time::Duration::from_millis(100), "must wait the whole allowance before giving up");
        assert!(*calls.lock().unwrap() >= 40, "must keep retrying while it waits");
    }

    /// The real bug: an origin that sends faster than the client takes data
    /// filled the in-flight cap, and the first refusal closed the stream, so
    /// every download past a couple of MB was cut off.
    #[test]
    fn a_fast_origin_into_a_slow_return_path_is_delivered_in_full() {
        const TOTAL: usize = 3 * 1024 * 1024;
        const CAP: usize = 4; // chunks the return path will hold at once
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let origin = std::thread::spawn(move || {
            use std::io::Write;
            let (mut conn, _) = listener.accept().unwrap();
            let data: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();
            conn.write_all(&data).unwrap();
        });
        let (rt, local) = rt_local();
        let (got, eof) = local.block_on(&rt, async move {
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let stream = Arc::new(StdMutex::new(ExitStream::from_tcp_stream(1, tcp)));
            let inflight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let received = Arc::new(StdMutex::new(Vec::<u8>::new()));
            let eof = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (queue_tx, mut queue_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
            // The slow return path: takes one chunk per millisecond.
            let (inf2, rec2, eof2) = (inflight.clone(), received.clone(), eof.clone());
            let drain = tokio::task::spawn_local(async move {
                while let Some(chunk) = queue_rx.recv().await {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    if chunk.is_empty() {
                        eof2.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                    rec2.lock().unwrap().extend_from_slice(&chunk);
                    inf2.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                }
            });
            let inf3 = inflight.clone();
            let mut emit: Box<dyn FnMut(&[u8]) -> bool + Send> = Box::new(move |chunk: &[u8]| {
                if inf3.load(std::sync::atomic::Ordering::SeqCst) >= CAP {
                    return false;
                }
                inf3.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                queue_tx.send(chunk.to_vec()).is_ok()
            });
            Egress::pump_stream_with(stream, &mut emit, std::time::Duration::from_millis(1), std::time::Duration::from_secs(20)).await;
            drop(emit);
            let _ = drain.await;
            let got = received.lock().unwrap().clone();
            (got, eof.load(std::sync::atomic::Ordering::SeqCst))
        });
        origin.join().unwrap();
        assert_eq!(got.len(), TOTAL, "the download was cut short");
        assert!(got.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8), "bytes arrived out of order or corrupted");
        assert!(eof, "the end-of-stream marker must still arrive");
    }

    /// A return path that never makes room is still cut loose in the end.
    #[test]
    fn a_dead_return_path_still_closes_the_stream() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let origin = std::thread::spawn(move || {
            use std::io::Write;
            let (mut conn, _) = listener.accept().unwrap();
            let _ = conn.write_all(&vec![7u8; 64 * 1024]);
            std::thread::sleep(std::time::Duration::from_millis(500));
        });
        let (rt, local) = rt_local();
        let closed = local.block_on(&rt, async move {
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let stream = Arc::new(StdMutex::new(ExitStream::from_tcp_stream(1, tcp)));
            let mut emit: Box<dyn FnMut(&[u8]) -> bool + Send> = Box::new(|_| false);
            let s2 = stream.clone();
            tokio::time::timeout(std::time::Duration::from_secs(5), Egress::pump_stream_with(s2, &mut emit, std::time::Duration::from_millis(1), std::time::Duration::from_millis(50)))
                .await
                .expect("pump_stream must give up on a dead return path");
            let c = stream.lock().unwrap().closed_flag.load(std::sync::atomic::Ordering::SeqCst);
            c
        });
        origin.join().unwrap();
        assert!(closed, "the stream must be closed once the return path is judged dead");
    }

    /// Regression test for bug report H1: `close()` called from another
    /// task (as `close_idle_streams`/`close_circuit_streams`/`send_data`'s
    /// error path all do, each from a different task than the one running
    /// `pump_stream`) must unblock a read that is already parked waiting
    /// on a destination that never sends and never closes. Before the
    /// `closed_notify` link, `close()` only flipped a flag nothing here
    /// checked until the next read returned -- which, against exactly
    /// this kind of silent destination, was never.
    #[test]
    fn close_from_another_task_interrupts_a_stream_blocked_on_read() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let origin = std::thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            // Silent and open for longer than this test's own timeout
            // below, so `pump_stream_with` can only return by noticing
            // the external `close()`, never by reading EOF.
            std::thread::sleep(std::time::Duration::from_secs(2));
            drop(conn);
        });
        let (rt, local) = rt_local();
        local.block_on(&rt, async move {
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let stream = Arc::new(StdMutex::new(ExitStream::from_tcp_stream(1, tcp)));
            let mut emit: Box<dyn FnMut(&[u8]) -> bool + Send> = Box::new(|_| true);
            let s2 = stream.clone();
            let pump = Egress::pump_stream_with(s2, &mut emit, std::time::Duration::from_millis(1), std::time::Duration::from_secs(5));
            let closer = async {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                stream.lock().unwrap().close();
            };
            tokio::time::timeout(std::time::Duration::from_millis(500), async {
                tokio::join!(pump, closer);
            })
            .await
            .expect("close() from another task must unblock a pump stuck reading forever, not leak it");
        });
        origin.join().unwrap();
    }
}
