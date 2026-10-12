//! `--isolate-by-destination`: a small pool of extra circuits built on top
//! of [`crate::dirclient::build_generic_circuit_owned`], plus the
//! return-path pump every circuit (primary and pool-built alike) needs.
//! Port of `allium_cli.py`'s `pump_return_path`/`_PooledCircuit`/
//! `_isolation_key`/`CircuitPool`.
//!
//! Real stream isolation is an orchestration problem, not a protocol one
//! -- see the Python original's `CircuitPool` docstring for the full
//! picture (reused as the doc for [`CircuitPool`] below almost verbatim;
//! nothing about the *design* changes in this port, only the concurrency
//! primitives: `asyncio.Lock` becomes [`std::sync::Mutex`], `asyncio.Task`
//! becomes [`std::thread::spawn`] plus a per-circuit stop flag (Rust has no
//! `task.cancel()`), and `asyncio.create_task` becomes that same spawn.

use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use allium::directory::{Directory, RelayDescriptor};
use allium::socks::{DATAGRAM_MAGIC, MAGIC};
use allium::socksproxy::{Onion, SocksError, SocksServer, REPLY_GENERAL};

use crate::args::Args;
use crate::dirclient::{
    build_generic_circuit_owned, cached_relay_directory, refresh_relay_directory, select_and_prepare,
    select_route_best_effort, trusted_authority_keys,
};
use crate::helpers::{hex_decode, parse_addr, primary_authority, say, split_trust_keys};
use crate::transport::CircuitTransport;

/// Continuously read return cells off one circuit and route them into the
/// SOCKS server they belong to. Runs as its own thread per circuit (the
/// primary's, spawned by `run_client` itself, and every isolated one this
/// pool builds) -- see the Python original's docstring for why: a stream's
/// reply only ever arrives on the circuit its request went out on, and the
/// one shared `server` needs a copy of this loop feeding it from every open
/// circuit.
///
/// Stops when either `stopping` (shared -- set once, at overall shutdown)
/// or `own_stop` (this one circuit's own flag, set when *this* circuit
/// specifically is retired/evicted/closed early) is set. Checked once per
/// `transport.receive` call, which itself never blocks longer than
/// `timeout` -- so a stop is noticed within one `receive` call, not
/// instantly but never more than `timeout` late either.
pub fn pump_return_path(
    transport: Arc<CircuitTransport>,
    onion: Onion,
    server: Arc<SocksServer>,
    timeout: Duration,
    stopping: Arc<AtomicBool>,
    own_stop: Arc<AtomicBool>,
    label: String,
) {
    while !stopping.load(Ordering::SeqCst) && !own_stop.load(Ordering::SeqCst) {
        let received = match transport.receive(timeout) {
            Ok(r) => r,
            // Idle: no return traffic within this slice -- keep waiting.
            // (`CircuitTransport::receive` already swallows every
            // recoverable circuit-level read error internally and only
            // ever surfaces a timeout here -- see its own doc.)
            Err(_) => continue,
        };
        if received.payload.is_empty() {
            // The exit's end-of-stream marker: nothing to write, but close
            // the application's socket so a request/response client stops
            // waiting for a reply that is done.
            for finished_id in transport.take_finished_streams() {
                if server.close_stream(finished_id, Some(&onion)) {
                    say(&format!("{label}: exit finished stream {finished_id}, closed it"));
                }
            }
            continue;
        }
        if received.payload.starts_with(MAGIC) {
            server.deliver_reply(&received.payload, Some(&onion));
        } else if received.payload.starts_with(DATAGRAM_MAGIC) {
            server.deliver_datagram_reply(&received.payload);
        } else {
            server.write_to_stream(received.stream_id.unwrap_or(0), &received.payload, Some(&onion));
            // Data and FIN can share one read, so check for the marker
            // after writing: the data must reach the client before we
            // close it.
            for finished_id in transport.take_finished_streams() {
                if server.close_stream(finished_id, Some(&onion)) {
                    say(&format!("{label}: exit finished stream {finished_id}, closed it"));
                }
            }
        }
    }
}

/// Wrap `transport` in the one [`Onion`] callable everything else in this
/// module (and `run_client`) compares by `Arc` pointer identity: always
/// clone *this* `Arc`, never build a second closure over the same
/// transport, or pointer-identity lookups (`stream_started`,
/// `SocksServer::close_stream`'s `circuit_key`, ...) silently stop matching.
pub fn make_onion(transport: Arc<CircuitTransport>) -> Onion {
    Arc::new(move |payload: &[u8]| transport.send(payload))
}

/// Like [`make_onion`], but for UDP ASSOCIATE datagrams: wraps
/// [`CircuitTransport::send_datagram`] (a whole, unfragmented `ALDG`
/// frame) rather than [`CircuitTransport::send`]. Unlike `make_onion`'s
/// result, callers don't need to reuse one stable `Arc` for this one --
/// nothing keys on a datagram onion's pointer identity (a datagram reply
/// is matched by `association_id`, not by which circuit delivered it), so
/// [`CircuitPool::datagram_onion_for`] builds a fresh one on every call.
fn make_datagram_onion(transport: Arc<CircuitTransport>) -> Onion {
    Arc::new(move |payload: &[u8]| transport.send_datagram(payload))
}

/// One isolated circuit's bookkeeping: its transport, its onion callable,
/// the thread pumping its return path, and when it was last handed to a new
/// stream. Port of `allium_cli.py`'s `_PooledCircuit`.
pub struct PooledCircuit {
    pub transport: Arc<CircuitTransport>,
    pub onion: Onion,
    stop: Arc<AtomicBool>,
    pump: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// When this circuit was built. Never updated after construction --
    /// see [`Self::expired`] ("dirtiness" used to mean idle
    /// time since the *last* stream, so a continuously busy circuit, and
    /// in particular the primary, could live forever).
    first_used: Instant,
    last_used: Mutex<Instant>,
    active_streams: AtomicI64,
    pending_close: AtomicBool,
    closed: AtomicBool,
    /// Test-only override for `exit_identity()` -- the tests in this file
    /// build their transports from a real but zero-hop `CircuitBuilder`
    /// (see `tests::fake_transport`), which has no real exit identity of
    /// its own. `RetryOnionTests`/`PolicyRetryTests`'s equivalents need one
    /// anyway (to prove a failed exit gets avoided on the replacement
    /// route), so this lets a test hand a `PooledCircuit` a known identity
    /// directly -- the same role Python's `_Builder(exit_identity)` fake
    /// plays for `_PooledCircuit`.
    #[cfg(test)]
    test_exit_identity: Mutex<Option<Vec<u8>>>,
}

impl PooledCircuit {
    fn new(transport: Arc<CircuitTransport>, onion: Onion, stop: Arc<AtomicBool>, pump: Option<std::thread::JoinHandle<()>>) -> Arc<Self> {
        let now = Instant::now();
        Arc::new(PooledCircuit {
            transport,
            onion,
            stop,
            pump: Mutex::new(pump),
            first_used: now,
            last_used: Mutex::new(now),
            active_streams: AtomicI64::new(0),
            pending_close: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            #[cfg(test)]
            test_exit_identity: Mutex::new(None),
        })
    }

    /// The last hop's verified identity -- delegates to the real
    /// transport, except in test builds where `set_test_exit_identity` has
    /// pinned one directly (see that field's doc).
    fn exit_identity(&self) -> Option<Vec<u8>> {
        #[cfg(test)]
        {
            if let Some(id) = self.test_exit_identity.lock().unwrap().clone() {
                return Some(id);
            }
        }
        self.transport.exit_identity()
    }

    #[cfg(test)]
    pub(crate) fn set_test_exit_identity(&self, id: Vec<u8>) {
        *self.test_exit_identity.lock().unwrap() = Some(id);
    }

    fn touch(&self) {
        *self.last_used.lock().unwrap() = Instant::now();
    }

    /// Age-based, not idle-based -- a circuit stops taking new
    /// streams once it has existed for `max_dirtiness` seconds, matching
    /// Tor's `MaxCircuitDirtiness`. `last_used` (see `touch`) still drives
    /// LRU eviction among non-expired circuits; it no longer has any part
    /// in whether a circuit is dirty, since a busy circuit's idle time
    /// never grows and would otherwise never trip this check.
    fn expired(&self, max_dirtiness: f64) -> bool {
        max_dirtiness > 0.0 && self.first_used.elapsed().as_secs_f64() >= max_dirtiness
    }

    fn acquire(&self) {
        self.active_streams.fetch_add(1, Ordering::SeqCst);
    }

    fn release(&self) {
        let prev = self.active_streams.fetch_sub(1, Ordering::SeqCst);
        if prev <= 0 {
            self.active_streams.store(0, Ordering::SeqCst);
        }
        if self.pending_close.load(Ordering::SeqCst) && self.active_streams.load(Ordering::SeqCst) == 0 {
            self.do_close();
        }
    }

    fn close(&self, force: bool) {
        if self.active_streams.load(Ordering::SeqCst) > 0 && !force {
            self.pending_close.store(true, Ordering::SeqCst);
            return;
        }
        self.do_close();
    }

    fn do_close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.pending_close.store(false, Ordering::SeqCst);
        // No `pump_task.cancel()` equivalent for a real OS thread: setting
        // this flag is what makes `pump_return_path` notice and return on
        // its own, within at most one `transport.receive` timeout slice
        // (see that function's doc). The socket itself has no explicit
        // close call here -- `CircuitTransport`/`OwnedCircuit` own it and
        // release it when the last `Arc<CircuitTransport>` referencing
        // this circuit (this struct's own, plus any onion closures still
        // live) is dropped.
        self.stop.store(true, Ordering::SeqCst);
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn active_stream_count(&self) -> i64 {
        self.active_streams.load(Ordering::SeqCst)
    }
}

/// A short, hand-picked list of multi-part public suffixes: a hostname
/// ending in one of these keeps three labels in [`base_domain`] instead of
/// two (`shop.example.co.uk` -> `example.co.uk`, not `co.uk` itself).
///
/// This is *not* a real Public Suffix List -- a full PSL is a few thousand
/// entries that need periodic updates, and pulling one in means vendoring
/// either the list or a crate (`publicsuffix`/`psl`) plus its own
/// dependency tree, which this project avoids everywhere else (see
/// `Cargo.toml`'s fully-vendored, hand-picked dependency set). Getting an
/// uncommon suffix wrong here only ever changes isolation *grouping* (a
/// perf/UX knob -- see `base_domain`'s doc), never which relays or keys
/// are trusted, so a miss on a TLD not in this list is an accepted,
/// documented gap rather than a security problem: worst case, two
/// subdomains of the same real site that should share a circuit get
/// isolated from each other instead, which is just the old (correct, if
/// wasteful) per-hostname behavior for that one case.
const MULTI_PART_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "gov.uk", "ac.uk", "net.uk", "sch.uk", "co.jp", "ne.jp", "or.jp", "ac.jp", "com.au", "net.au", "org.au", "edu.au",
    "gov.au", "co.nz", "org.nz", "govt.nz", "com.br", "net.br", "org.br", "co.in", "net.in", "org.in", "gov.in", "com.cn", "net.cn",
    "org.cn", "gov.cn", "co.za", "org.za", "com.mx", "com.ar", "com.sg", "com.hk", "co.kr", "or.kr",
];

/// Group `host` down to its registrable ("base") domain for isolation
/// purposes: `i.ytimg.com` and `rr3---sn-4g5e6nze.googlevideo.com` still
/// get different circuits (they're different sites' CDNs), but
/// `geo.dailymotion.com`, `consent.dailymotion.com`,
/// `static.neon-ssr.dailymotion.com` and bare `dailymotion.com` all
/// collapse onto the same one.
///
/// Fix (isolate-by-destination slowdown finding): before this, isolation
/// grouped by *exact* hostname, and a single page load can easily touch a
/// dozen-plus subdomains of one real site -- CDN edges, consent banners,
/// hashed asset hosts, analytics. Isolating each of those separately
/// multiplies circuit-build cost (a full directory fetch + 3-hop
/// handshake per circuit, see [`CircuitPool::build_isolated_real`])
/// without buying any real separation, since they all belong to the same
/// party anyway -- a live log showed 5 distinct `*.ipleak.net` and
/// `*.dailymotion.com` subdomains each building their own circuit for
/// what was really 2 sites. This grouping is the same "first-party
/// domain" isolation Tor Browser itself uses, for the same reason.
fn base_domain(host: &str) -> String {
    // IP literals (v4 or v6) have no registrable-domain concept -- leave
    // them alone rather than mangling them by splitting on '.'/':'.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host.to_string();
    }
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() <= 2 {
        return host.to_string();
    }
    let last_two = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    let take = if MULTI_PART_SUFFIXES.contains(&last_two.as_str()) && labels.len() >= 3 { 3 } else { 2 };
    labels[labels.len() - take..].join(".")
}

/// Normalize a CONNECT/RESOLVE destination into a `CircuitPool` key:
/// case-insensitive, strips one trailing '.' so a fully-qualified domain
/// name isn't treated as a different destination from the bare one, then
/// groups by [`base_domain`] so subdomains of the same real site share one
/// circuit -- see that function's doc for why.
pub fn isolation_key(host: &str) -> String {
    let mut host = host.trim().to_lowercase();
    if host.ends_with('.') && !host.ends_with("..") {
        host.pop();
    }
    base_domain(&host)
}

#[derive(Clone, PartialEq, Eq)]
enum PrimaryKey {
    Unclaimed,
    Key(String),
    /// A retry moved the primary's key to a replacement circuit: the
    /// primary stays open (its owner, `run_client`, tears it down) but no
    /// longer takes new streams for any key.
    Detached,
}

/// The outcome slot every concurrent `onion_for` miss on the same brand-new
/// key races to find or create -- see `onion_for`'s dedup comment for why
/// this exists: without it, two SOCKS streams to a not-yet-cached host that
/// both arrive before the first circuit finishes building would each start
/// their own full build (directory fetch + 3-hop handshake over a WAN
/// link), wasting one of the two builds entirely. Confirmed live: a log
/// showed `www.youtube.com`'s whole build sequence (contact authority ->
/// vote timeout -> handshake with guard/middle/exit) appear twice,
/// interleaved, for what should have been one circuit.
///
/// The loser (whichever thread finds a slot already here) just waits on
/// the winner's result via the `Condvar` instead of racing a second build.
enum BuildOutcome {
    InProgress,
    Done(Result<Arc<PooledCircuit>, String>),
}

struct BuildSlot {
    outcome: Mutex<BuildOutcome>,
    cond: Condvar,
}

struct PoolState {
    avoid_exits: HashMap<Vec<u8>, Instant>,
    avoid_exit_ports: HashMap<(Vec<u8>, u16), Instant>,
    port_circuits: HashMap<(String, u16), Arc<PooledCircuit>>,
    /// Keys currently being built by `onion_for` -- see `BuildSlot`'s doc.
    /// Removed the moment the build finishes, atomically with inserting
    /// the result into `by_key` (or discarding it, on failure), so no
    /// caller can ever observe a state where a key is in neither map nor
    /// `building` while a build for it is genuinely still in flight.
    building: HashMap<String, Arc<BuildSlot>>,
    retired: Vec<Arc<PooledCircuit>>,
    primary: Arc<PooledCircuit>,
    primary_key: PrimaryKey,
    by_key: HashMap<String, Arc<PooledCircuit>>,
    /// Replacement-circuit builds per destination (isolation key, or
    /// key + port for exit-policy rebuilds) inside the last
    /// [`REBUILD_WINDOW_SECONDS`] -- see [`MAX_REBUILDS_PER_WINDOW`].
    rebuilds: HashMap<String, Vec<Instant>>,
    /// When a "giving up on this destination" note was last printed per
    /// key, so a browser hammering a dead host doesn't flood the log.
    rebuild_denied_logged: HashMap<String, Instant>,
}

pub const DEFAULT_MAX_DIRTINESS: f64 = 600.0;
/// How many isolated circuits (on top of the primary) this pool keeps open
/// at once before LRU-evicting the least recently used one.
///
/// Fix (isolate-by-destination slowdown finding): this was 8, which is far
/// below what one real page load touches. A live `--isolate-by-destination`
/// session browsing exactly three sites (YouTube, Dailymotion, ipleak.net)
/// hit 17 distinct isolation keys -- every CDN/consent/analytics subdomain
/// gets its own key (`isolation_key` groups by base domain now, which cuts
/// this down a lot, but a busy page can still easily clear a couple dozen
/// distinct *sites*). With a cap of 8, hosts still in active use were
/// getting LRU-evicted and then fully rebuilt (directory fetch + 3-hop
/// handshake, all over a WAN link) the next time the page touched them --
/// `ipleak.net` alone rebuilt 5 times in that one session. Raised to 32,
/// which comfortably covers ordinary browsing; each held-open circuit costs
/// one UDP socket and one pump thread on the client, which is cheap.
pub const DEFAULT_MAX_CIRCUITS: usize = 32;
const AVOID_EXIT_SECONDS: f64 = 600.0;

/// Cap on replacement circuits per destination (fix: CONNECT retry loop).
///
/// `SocksServer` already limits one CONNECT to `--connect-attempts` tries,
/// but a browser simply re-issues the CONNECT when it fails -- a video
/// page asked for the same unreachable `googlevideo.com` edge ~20 times in
/// a row, and each request tore down its key's circuit and built a fresh
/// one (directory fetch + 3-hop handshake) every time. Rebuilding cannot
/// help when the destination itself is the problem, and a burst of
/// identical circuit builds is itself a recognisable traffic pattern.
/// After this many rebuilds for one destination inside
/// [`REBUILD_WINDOW_SECONDS`], `retry_onion` stops building and fails the
/// request instead, keeping the existing circuit, until the window moves on.
const MAX_REBUILDS_PER_WINDOW: usize = 3;
const REBUILD_WINDOW_SECONDS: f64 = 60.0;

/// A test-only stand-in for [`CircuitPool::build_isolated_real`] -- see
/// [`CircuitPool::set_test_build`].
#[cfg(test)]
type TestBuildFn = Box<dyn Fn(&str, std::collections::HashSet<Vec<u8>>, Option<u16>) -> Result<Arc<PooledCircuit>, String> + Send + Sync>;

/// Builds and caches extra circuits for `--isolate-by-destination`. Port of
/// `allium_cli.py`'s `CircuitPool` -- see the module doc for the
/// concurrency-primitive mapping and the Python original's own class
/// docstring (reproduced in spirit throughout this file's comments) for
/// the design this follows unchanged.
pub struct CircuitPool {
    args: Args,
    isolate: bool,
    max_circuits: usize,
    max_dirtiness: f64,
    stopping: Arc<AtomicBool>,
    server: Mutex<Option<Arc<SocksServer>>>,
    state: Mutex<PoolState>,
    /// Test-only override for `build_isolated` -- see `set_test_build`'s
    /// doc and `build_isolated`'s own dispatch. Mirrors Python's
    /// `pool._build_isolated = lambda key, **_kw: ...` monkeypatch: what's
    /// under test in `mod tests` below is purely this pool's own
    /// bookkeeping (which key gets which circuit, LRU eviction, deferred
    /// close, retry replacement), never a real handshake.
    #[cfg(test)]
    test_build: Mutex<Option<TestBuildFn>>,
}

impl CircuitPool {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        args: Args,
        primary_transport: Arc<CircuitTransport>,
        primary_onion: Onion,
        stopping: Arc<AtomicBool>,
        isolate: bool,
    ) -> Self {
        let primary = PooledCircuit::new(primary_transport, primary_onion, Arc::new(AtomicBool::new(false)), None);
        CircuitPool {
            args,
            isolate,
            max_circuits: DEFAULT_MAX_CIRCUITS,
            max_dirtiness: DEFAULT_MAX_DIRTINESS,
            stopping,
            server: Mutex::new(None),
            state: Mutex::new(PoolState {
                avoid_exits: HashMap::new(),
                avoid_exit_ports: HashMap::new(),
                port_circuits: HashMap::new(),
                building: HashMap::new(),
                retired: Vec::new(),
                primary,
                primary_key: PrimaryKey::Unclaimed,
                by_key: HashMap::new(),
                rebuilds: HashMap::new(),
                rebuild_denied_logged: HashMap::new(),
            }),
            #[cfg(test)]
            test_build: Mutex::new(None),
        }
    }

    /// Test-only constructor: takes an already-built primary
    /// [`PooledCircuit`] directly (so a test can pin its `exit_identity`
    /// beforehand -- see [`PooledCircuit::set_test_exit_identity`]) rather
    /// than having `new` build a fresh internal one from a bare
    /// transport/onion pair, and exposes `max_circuits`/`max_dirtiness`
    /// (fixed constants for every real caller) as parameters, matching
    /// Python's `CircuitPool(..., max_circuits=1)`-style test kwargs.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_for_test(
        args: Args,
        primary: Arc<PooledCircuit>,
        stopping: Arc<AtomicBool>,
        isolate: bool,
        max_circuits: usize,
        max_dirtiness: f64,
    ) -> Self {
        CircuitPool {
            args,
            isolate,
            max_circuits,
            max_dirtiness,
            stopping,
            server: Mutex::new(None),
            state: Mutex::new(PoolState {
                avoid_exits: HashMap::new(),
                avoid_exit_ports: HashMap::new(),
                port_circuits: HashMap::new(),
                building: HashMap::new(),
                retired: Vec::new(),
                primary,
                primary_key: PrimaryKey::Unclaimed,
                by_key: HashMap::new(),
                rebuilds: HashMap::new(),
                rebuild_denied_logged: HashMap::new(),
            }),
            test_build: Mutex::new(None),
        }
    }

    /// Substitute a fake for [`Self::build_isolated_real`] -- see
    /// `test_build`'s field doc.
    #[cfg(test)]
    pub(crate) fn set_test_build(
        &self,
        f: impl Fn(&str, std::collections::HashSet<Vec<u8>>, Option<u16>) -> Result<Arc<PooledCircuit>, String> + Send + Sync + 'static,
    ) {
        *self.test_build.lock().unwrap() = Some(Box::new(f));
    }

    /// Wire in the `SocksServer` this pool's circuits' return-path pumps
    /// deliver into. Called once, right after `server` exists -- before
    /// `server.spawn()` ever lets a real connection reach `onion_for`.
    pub fn attach(&self, server: Arc<SocksServer>) {
        *self.server.lock().unwrap() = Some(server);
    }

    /// The pool key a stream to `host` lands on.
    ///
    /// `scope` is the SOCKS connection's authentication tag
    /// (`socksproxy::socks_auth_scope`), `None` for an unauthenticated
    /// connection. It is folded in *regardless* of `--isolate-by-destination`:
    /// an application that bothered to send credentials asked for its
    /// traffic to be kept apart, and that holds even when the operator
    /// turned destination isolation off for speed.
    fn key(&self, host: &str, scope: Option<&str>) -> String {
        let destination = if self.isolate { isolation_key(host) } else { "*".to_string() };
        match scope {
            Some(scope) => format!("{scope}|{destination}"),
            None => destination,
        }
    }

    fn server(&self) -> Arc<SocksServer> {
        self.server.lock().unwrap().clone().expect("attach() is always called before onion_for can run")
    }

    fn spawn_pump(&self, transport: Arc<CircuitTransport>, onion: Onion, stop: Arc<AtomicBool>, label: String) -> std::thread::JoinHandle<()> {
        let server = self.server();
        let timeout = Duration::from_secs_f64(self.args.timeout.unwrap_or(5.0));
        let stopping = Arc::clone(&self.stopping);
        std::thread::spawn(move || pump_return_path(transport, onion, server, timeout, stopping, stop, label))
    }

    /// `SocksServer`'s `onion_router` hook: return the onion callable the
    /// stream to `host` should use, reusing an already-open circuit when
    /// one fits and building a fresh one otherwise.
    pub fn onion_for(&self, host: &str, port: u16, scope: Option<&str>) -> Result<Onion, SocksError> {
        Ok(self.resolve_pooled(host, port, scope)?.onion.clone())
    }

    /// `SocksServer`'s `onion_datagram_router` hook: same resolution as
    /// [`Self::onion_for`] (same cache, same isolation key, same
    /// age-based rotation and eviction), but wraps the resolved circuit's
    /// transport for a *datagram* send instead of handing back the
    /// stream onion. Resolved fresh per UDP packet -- see
    /// `on_client_datagram`'s doc for why that's fine here even though
    /// `onion_for`'s result is meant to be cached and reused per stream.
    ///
    /// Before this existed, `run_client` wired every UDP ASSOCIATE
    /// datagram straight to the primary transport, bypassing this pool -- and therefore
    /// `--isolate-by-destination` and the pool's rotation/eviction --
    /// entirely, for the whole process's lifetime.
    pub fn datagram_onion_for(&self, host: &str, port: u16, scope: Option<&str>) -> Result<Onion, SocksError> {
        Ok(make_datagram_onion(Arc::clone(&self.resolve_pooled(host, port, scope)?.transport)))
    }

    /// Shared resolution behind [`Self::onion_for`] and
    /// [`Self::datagram_onion_for`]: the circuit `host`/`port` should use,
    /// reusing an already-open one when it fits and building a fresh one
    /// otherwise. Returns the whole [`PooledCircuit`] rather than an
    /// [`Onion`] so a caller can pick which of its callables (stream vs.
    /// datagram) it actually wants.
    fn resolve_pooled(&self, host: &str, port: u16, scope: Option<&str>) -> Result<Arc<PooledCircuit>, SocksError> {
        let key = self.key(host, scope);
        let mut state = self.state.lock().unwrap();

        let port_key = (key.clone(), port);
        if let Some(by_port) = state.port_circuits.get(&port_key).cloned() {
            if by_port.expired(self.max_dirtiness) {
                state.port_circuits.remove(&port_key);
                self.evict(&mut state, by_port);
            } else {
                by_port.touch();
                return Ok(by_port);
            }
        }

        if state.primary_key == PrimaryKey::Unclaimed {
            state.primary_key = PrimaryKey::Key(key.clone());
            state.primary.touch();
            return Ok(Arc::clone(&state.primary));
        }
        if state.primary_key == PrimaryKey::Key(key.clone()) {
            // The primary used to be exempt from expiry entirely, so
            // with isolation off (the default) one circuit
            // carried a whole session's traffic indefinitely. Once it
            // ages out, detach it -- `run_client` keeps it open and
            // tears it down at shutdown, same as a failed-retry detach
            // (see `retry_onion`) -- and fall through to build this key
            // a fresh pooled circuit, same as any other key would get.
            if state.primary.expired(self.max_dirtiness) {
                state.primary_key = PrimaryKey::Detached;
            } else {
                state.primary.touch();
                return Ok(Arc::clone(&state.primary));
            }
        }

        if let Some(pooled) = state.by_key.get(&key).cloned() {
            if pooled.expired(self.max_dirtiness) {
                state.by_key.remove(&key);
                self.evict(&mut state, pooled);
            } else {
                pooled.touch();
                return Ok(pooled);
            }
        }

        // Dedup concurrent first-time builds for the same key: if another
        // thread is already building `key` (it missed every cache above
        // just like we did, and got here first), join its in-flight build
        // instead of racing a second one -- see `BuildSlot`'s doc.
        if let Some(slot) = state.building.get(&key).cloned() {
            drop(state);
            return self.await_build(host, &slot);
        }

        if state.by_key.len() >= self.max_circuits {
            if let Some(lru_key) = state.by_key.iter().min_by_key(|(_, v)| *v.last_used.lock().unwrap()).map(|(k, _)| k.clone()) {
                let victim = state.by_key.remove(&lru_key).unwrap();
                self.evict(&mut state, victim);
            }
        }

        let slot = Arc::new(BuildSlot { outcome: Mutex::new(BuildOutcome::InProgress), cond: Condvar::new() });
        state.building.insert(key.clone(), Arc::clone(&slot));
        let avoid = self.active_avoid(&mut state, None);
        drop(state);

        let result = self.build_isolated(&key, avoid, Some(port));
        self.publish_build(&key, &slot, result.clone());
        match result {
            Ok(pooled) => Ok(pooled),
            Err(e) => {
                say(&format!("client: could not build an isolated circuit for {host}: {e}"));
                Err(SocksError(REPLY_GENERAL))
            }
        }
    }

    /// Block until the in-flight build behind `slot` finishes, then return
    /// its result -- the "loser" side of the dedup in `resolve_pooled`.
    /// See `BuildSlot`'s doc.
    fn await_build(&self, host: &str, slot: &Arc<BuildSlot>) -> Result<Arc<PooledCircuit>, SocksError> {
        let mut outcome = slot.outcome.lock().unwrap();
        while matches!(*outcome, BuildOutcome::InProgress) {
            outcome = slot.cond.wait(outcome).unwrap();
        }
        match &*outcome {
            BuildOutcome::Done(Ok(pooled)) => Ok(Arc::clone(pooled)),
            BuildOutcome::Done(Err(e)) => {
                say(&format!("client: could not build an isolated circuit for {host}: an in-flight build this stream was waiting on failed: {e}"));
                Err(SocksError(REPLY_GENERAL))
            }
            BuildOutcome::InProgress => unreachable!("the wait loop above only exits once the outcome is Done"),
        }
    }

    /// Publish a finished build's result to `slot` (waking anyone blocked
    /// in `await_build` on it) and, on success, hand the pool ownership of
    /// the new circuit under `key` -- the "winner" side of the dedup in
    /// `onion_for`. Removing `key` from `state.building` and inserting it
    /// into `state.by_key` happen under the same lock acquisition, so a
    /// caller who takes the state lock right after this returns always
    /// sees one consistent view: either the build is still `building`, or
    /// its result is already in `by_key` -- never a gap where it's in
    /// neither and a caller must go build a third circuit for `key`.
    fn publish_build(&self, key: &str, slot: &Arc<BuildSlot>, result: Result<Arc<PooledCircuit>, String>) {
        {
            let mut state = self.state.lock().unwrap();
            state.building.remove(key);
            if let Ok(pooled) = &result {
                state.by_key.insert(key.to_string(), Arc::clone(pooled));
            }
        }
        *slot.outcome.lock().unwrap() = BuildOutcome::Done(result);
        slot.cond.notify_all();
    }

    fn active_avoid(&self, state: &mut PoolState, port: Option<u16>) -> std::collections::HashSet<Vec<u8>> {
        let now = Instant::now();
        state.avoid_exits.retain(|_, expiry| *expiry > now);
        state.avoid_exit_ports.retain(|_, expiry| *expiry > now);
        let mut avoid: std::collections::HashSet<Vec<u8>> = state.avoid_exits.keys().cloned().collect();
        if let Some(port) = port {
            if port != 0 {
                for (identity, p) in state.avoid_exit_ports.keys() {
                    if *p == port {
                        avoid.insert(identity.clone());
                    }
                }
            }
        }
        avoid
    }

    fn find_circuit(&self, state: &PoolState, onion: &Onion) -> Option<Arc<PooledCircuit>> {
        if Arc::ptr_eq(&state.primary.onion, onion) {
            return Some(Arc::clone(&state.primary));
        }
        for pooled in state.by_key.values().chain(state.port_circuits.values()).chain(state.retired.iter()) {
            if Arc::ptr_eq(&pooled.onion, onion) {
                return Some(Arc::clone(pooled));
            }
        }
        None
    }

    fn current_for_key(&self, state: &PoolState, key: &str) -> Option<Arc<PooledCircuit>> {
        if state.primary_key == PrimaryKey::Key(key.to_string()) {
            return Some(Arc::clone(&state.primary));
        }
        state.by_key.get(key).cloned()
    }

    /// Take a circuit out of service because it is over cap or stale, and
    /// close it -- unless a stream is still sending on it, in which case
    /// the close is deferred (see `PooledCircuit::close`/`release`) and the
    /// circuit is parked in `retired` so `stream_finished`/`find_circuit`
    /// can still reach it to finish that deferred close later.
    fn evict(&self, state: &mut PoolState, pooled: Arc<PooledCircuit>) {
        pooled.close(false);
        if !pooled.is_closed() {
            self.retire(state, pooled);
        }
    }

    fn retire(&self, state: &mut PoolState, pooled: Arc<PooledCircuit>) {
        state.retired.push(pooled);
        let mut keep = Vec::new();
        for old in state.retired.drain(..) {
            if old.active_stream_count() > 0 {
                keep.push(old);
            } else if old.expired(self.max_dirtiness) {
                old.close(false);
            } else {
                keep.push(old);
            }
        }
        let over = keep.len() as i64 - self.max_circuits as i64;
        if over > 0 {
            let mut still_keep = Vec::new();
            let mut over = over;
            for old in keep {
                if over > 0 && old.active_stream_count() == 0 {
                    old.close(false);
                    over -= 1;
                } else {
                    still_keep.push(old);
                }
            }
            keep = still_keep;
        }
        state.retired = keep;
    }

    /// `SocksServer`'s `onion_stream_started` hook.
    pub fn stream_started(&self, onion: &Onion) {
        let state = self.state.lock().unwrap();
        if let Some(pooled) = self.find_circuit(&state, onion) {
            pooled.acquire();
        }
    }

    /// `SocksServer`'s `onion_stream_finished` hook.
    pub fn stream_finished(&self, onion: &Onion) {
        let mut state = self.state.lock().unwrap();
        let Some(pooled) = self.find_circuit(&state, onion) else { return };
        pooled.release();
        if pooled.is_closed() {
            state.retired.retain(|p| !Arc::ptr_eq(p, &pooled));
        }
    }

    /// Every transport this pool currently has assigned to a key, plus any
    /// retired circuit still carrying a live stream -- for
    /// `_keepalive_loop` to ping. See the Python original's docstring for
    /// why a replaced (retired-but-still-busy) circuit still needs
    /// keepalives too.
    pub fn live_transports(&self) -> Vec<Arc<CircuitTransport>> {
        let state = self.state.lock().unwrap();
        let mut out = Vec::new();
        // A detached primary (aged out, or replaced after a failed
        // retry) with nothing left on it doesn't need keeping alive --
        // `run_client` still owns and will close it at
        // shutdown, but there's no reason to keep pinging it in the
        // meantime.
        if state.primary_key != PrimaryKey::Detached || state.primary.active_stream_count() > 0 {
            out.push(Arc::clone(&state.primary.transport));
        }
        out.extend(state.by_key.values().map(|p| Arc::clone(&p.transport)));
        out.extend(state.port_circuits.values().map(|p| Arc::clone(&p.transport)));
        for pooled in &state.retired {
            if pooled.active_stream_count() > 0 && !pooled.is_closed() {
                out.push(Arc::clone(&pooled.transport));
            }
        }
        out
    }

    /// `SocksServer`'s `onion_retry` hook: a CONNECT/RESOLVE to `host`
    /// failed on the circuit whose onion is `failed_onion`; return a
    /// different circuit to retry it on. See the Python original's
    /// docstring for the exit-policy-vs-anything-else distinction this
    /// preserves in full.
    pub fn retry_onion(&self, host: &str, port: u16, scope: Option<&str>, failed_onion: Option<Onion>, reason: Option<&str>) -> Result<Option<Onion>, SocksError> {
        let key = self.key(host, scope);
        let policy = reason == Some("exit-policy") && port > 0;
        let mut state = self.state.lock().unwrap();

        let port_key = (key.clone(), port);
        let current = if policy { state.port_circuits.get(&port_key).cloned() } else { None }.or_else(|| self.current_for_key(&state, &key));
        let failed = match &failed_onion {
            Some(onion) => self.find_circuit(&state, onion),
            None => current.clone(),
        };
        if let (Some(current), Some(failed)) = (&current, &failed) {
            if !Arc::ptr_eq(current, failed) {
                current.touch();
                return Ok(Some(current.onion.clone()));
            }
        }

        let exit_identity = failed.as_ref().and_then(|f| f.exit_identity());
        let expiry = Instant::now() + Duration::from_secs_f64(AVOID_EXIT_SECONDS);
        if let Some(identity) = &exit_identity {
            if policy {
                state.avoid_exit_ports.insert((identity.clone(), port), expiry);
            } else {
                state.avoid_exits.insert(identity.clone(), expiry);
            }
        }

        if policy {
            // Same dedup as the general path below, just against a
            // separate building-key namespace (`state.building` is a flat
            // `String` map shared with `onion_for`'s and the general
            // retry path's own base-domain keys, so a distinct suffix
            // keeps a port-policy rebuild from colliding with an
            // unrelated ordinary build for the same host).
            let building_key = format!("{key}\u{0}port{port}");
            if !state.building.contains_key(&building_key) && !Self::take_rebuild_budget(&mut state, &building_key, host, port) {
                return Ok(None);
            }
            if let Some(slot) = state.building.get(&building_key).cloned() {
                drop(state);
                return self.await_build(host, &slot).map(|pooled| Some(pooled.onion.clone()));
            }
            say(&format!("client: exit refused port {port} for {host} -- building a circuit through an exit that accepts it"));
            if let Some(old) = state.port_circuits.remove(&port_key) {
                self.retire(&mut state, old);
            }
            if state.port_circuits.len() >= self.max_circuits {
                if let Some(lru) = state.port_circuits.iter().min_by_key(|(_, v)| *v.last_used.lock().unwrap()).map(|(k, _)| k.clone()) {
                    let victim = state.port_circuits.remove(&lru).unwrap();
                    self.evict(&mut state, victim);
                }
            }
            let avoid = self.active_avoid(&mut state, Some(port));
            let slot = Arc::new(BuildSlot { outcome: Mutex::new(BuildOutcome::InProgress), cond: Condvar::new() });
            state.building.insert(building_key.clone(), Arc::clone(&slot));
            drop(state);
            let result = self.build_isolated(&key, avoid, Some(port));
            // `publish_build` only writes `by_key`, not `port_circuits`,
            // so this path publishes to the slot and the port-keyed table
            // itself, mirroring `publish_build`'s own two steps (drop
            // `building`, insert the result, then wake any waiters) rather
            // than reusing it directly.
            {
                let mut state = self.state.lock().unwrap();
                state.building.remove(&building_key);
                if let Ok(pooled) = &result {
                    state.port_circuits.insert(port_key.clone(), Arc::clone(pooled));
                }
            }
            *slot.outcome.lock().unwrap() = BuildOutcome::Done(result.clone());
            slot.cond.notify_all();
            return match result {
                Ok(pooled) => Ok(Some(pooled.onion.clone())),
                Err(e) => {
                    say(&format!("client: could not build a replacement circuit for {host}: {e}"));
                    Err(SocksError(REPLY_GENERAL))
                }
            };
        }

        // Budget check before anything is retired: when the budget is
        // spent, the key keeps the circuit it has (so the browser's next
        // attempt reuses it instead of triggering yet another build), and
        // this request fails fast.
        if !state.building.contains_key(&key) && !Self::take_rebuild_budget(&mut state, &key, host, port) {
            return Ok(None);
        }

        let is_primary = current.as_ref().map(|c| Arc::ptr_eq(c, &state.primary)).unwrap_or(false);
        if is_primary {
            state.primary_key = PrimaryKey::Detached;
        } else if let Some(current) = &current {
            if state.by_key.get(&key).map(|c| Arc::ptr_eq(c, current)).unwrap_or(false) {
                state.by_key.remove(&key);
                self.retire(&mut state, Arc::clone(current));
            }
        }

        // Dedup concurrent retries for the same key -- the exact same
        // hazard `onion_for`'s own `state.building` check exists to guard
        // against (see `BuildSlot`'s doc), just reached from the retry
        // path instead of a first-ever visit. Without this: base-domain
        // isolation grouping routinely puts many concurrent CONNECTs on
        // one shared circuit (e.g. a video page's dozen parallel
        // `googlevideo.com` CDN edges), so when that one circuit dies,
        // every one of those streams calls `retry_onion` with the same
        // `current == failed` circuit at nearly the same moment -- the
        // `Arc::ptr_eq` early-return above only helps a *later* straggler
        // that arrives after some earlier retry already finished
        // replacing the circuit, not this pack of near-simultaneous
        // callers, who all fall through here together. Confirmed live: a
        // log showed a dozen interleaved `googlevideo.com` handshake
        // sequences racing at once for what should have been one
        // replacement circuit, each competing for the same guard/middle/
        // exit and starving every one of them out.
        if let Some(slot) = state.building.get(&key).cloned() {
            drop(state);
            return self.await_build(host, &slot).map(|pooled| Some(pooled.onion.clone()));
        }

        if state.by_key.len() >= self.max_circuits {
            if let Some(lru_key) = state.by_key.iter().min_by_key(|(_, v)| *v.last_used.lock().unwrap()).map(|(k, _)| k.clone()) {
                let victim = state.by_key.remove(&lru_key).unwrap();
                self.evict(&mut state, victim);
            }
        }
        say(&format!("client: CONNECT to {host}:{port} failed on its circuit -- retrying on a fresh one"));
        let exit_port = if port > 0 { Some(port) } else { None };
        let avoid = self.active_avoid(&mut state, exit_port);
        let slot = Arc::new(BuildSlot { outcome: Mutex::new(BuildOutcome::InProgress), cond: Condvar::new() });
        state.building.insert(key.clone(), Arc::clone(&slot));
        drop(state);
        let result = self.build_isolated(&key, avoid, exit_port);
        self.publish_build(&key, &slot, result.clone());
        match result {
            Ok(pooled) => Ok(Some(pooled.onion.clone())),
            Err(e) => {
                say(&format!("client: could not build a replacement circuit for {host}: {e}"));
                Err(SocksError(REPLY_GENERAL))
            }
        }
    }

    /// Spend one replacement build for `budget_key` if its budget allows
    /// (see [`MAX_REBUILDS_PER_WINDOW`]); `false` means "give up for now".
    fn take_rebuild_budget(state: &mut PoolState, budget_key: &str, host: &str, port: u16) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs_f64(REBUILD_WINDOW_SECONDS);
        // Drop expired entries everywhere so these maps stay bounded.
        state.rebuilds.retain(|_, times| {
            times.retain(|t| now.duration_since(*t) < window);
            !times.is_empty()
        });
        state.rebuild_denied_logged.retain(|_, t| now.duration_since(*t) < window);

        let times = state.rebuilds.entry(budget_key.to_string()).or_default();
        if times.len() < MAX_REBUILDS_PER_WINDOW {
            times.push(now);
            return true;
        }
        if !state.rebuild_denied_logged.contains_key(budget_key) {
            state.rebuild_denied_logged.insert(budget_key.to_string(), now);
            say(&format!(
                "client: {host}:{port} still failing after {MAX_REBUILDS_PER_WINDOW} fresh circuits in {REBUILD_WINDOW_SECONDS:.0}s -- \
                 not building more for now (the destination or exit is likely the problem, not the circuit)"
            ));
        }
        false
    }

    /// Build (or hand back a test double for) one isolated circuit.
    /// Dispatches to a test override when one is set (see `set_test_build`);
    /// otherwise the real thing, [`Self::build_isolated_real`].
    fn build_isolated(&self, key: &str, avoid: std::collections::HashSet<Vec<u8>>, exit_port: Option<u16>) -> Result<Arc<PooledCircuit>, String> {
        #[cfg(test)]
        {
            if let Some(f) = self.test_build.lock().unwrap().as_ref() {
                return f(key, avoid, exit_port);
            }
        }
        self.build_isolated_real(key, avoid, exit_port)
    }

    fn build_isolated_real(&self, key: &str, avoid: std::collections::HashSet<Vec<u8>>, exit_port: Option<u16>) -> Result<Arc<PooledCircuit>, String> {
        let args = &self.args;
        let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        crate::helpers::set_large_rcvbuf(&sock);
        let timeout = Duration::from_secs_f64(args.timeout.unwrap_or(5.0));
        sock.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
        let label = format!("isolated[{key}]");
        let retries = args.retries.unwrap_or(0).max(0) as u32;

        let owned = if args.authority.is_some() {
            self.build_via_authority(sock, &label, &avoid, exit_port).map_err(|e| e.to_string())?
        } else {
            let mut trusted = HashMap::new();
            for (hop, pin) in [("guard", &args.trust_guard), ("middle", &args.trust_middle), ("exit", &args.trust_exit)] {
                if let Some(pin) = pin {
                    // `pin` may be a validated comma-separated list (see
                    // `helpers::split_trust_keys`); decoding the whole
                    // string as one hex blob fails on the comma and
                    // silently leaves the hop unpinned.
                    let keys: Vec<[u8; 32]> = split_trust_keys(pin)
                        .iter()
                        .filter_map(|hex| hex_decode(hex).ok())
                        .filter_map(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
                        .collect();
                    if !keys.is_empty() {
                        trusted.insert(hop.to_string(), keys);
                    }
                }
            }
            let guard = parse_addr(args.guard.as_deref().unwrap_or_default()).map_err(|e| e.to_string())?;
            let middle = parse_addr(args.middle.as_deref().unwrap_or_default()).map_err(|e| e.to_string())?;
            let exit = parse_addr(args.exit_addr.as_deref().unwrap_or_default()).map_err(|e| e.to_string())?;
            build_generic_circuit_owned(
                sock,
                vec![("guard".to_string(), guard), ("middle".to_string(), middle), ("exit".to_string(), exit)],
                timeout,
                retries,
                Some(trusted),
                label.clone(),
                Some(args.kem_keys.clone()),
            )
            .map_err(|e| e.to_string())?
        };

        let transport = Arc::new(CircuitTransport::new(owned, !args.no_congestion.unwrap_or(false)));
        let onion = make_onion(Arc::clone(&transport));
        let stop = Arc::new(AtomicBool::new(false));
        let pump = self.spawn_pump(Arc::clone(&transport), onion.clone(), Arc::clone(&stop), label);
        Ok(PooledCircuit::new(transport, onion, stop, Some(pump)))
    }

    fn build_via_authority(
        &self,
        sock: UdpSocket,
        label: &str,
        avoid: &std::collections::HashSet<Vec<u8>>,
        exit_port: Option<u16>,
    ) -> Result<crate::owned_circuit::OwnedCircuit, String> {
        let args = &self.args;
        // This used to be `fetch_relay_directory`, a full authority round
        // trip made fresh from the client's real IP on *every* call --
        // i.e. on every isolated circuit this pool
        // builds. `cached_relay_directory` returns the same process-wide,
        // periodically-refreshed `Directory` to every caller instead; see
        // its doc comment in `dirclient.rs` for the full reasoning.
        let directory: Arc<Directory> = cached_relay_directory(args, label).map_err(|e| e.to_string())?;
        // `trust_guard` may be a validated comma-separated list; take the
        // first key rather than feeding the whole string to `hex_decode`,
        // which fails on the comma and silently drops the preferred guard.
        let preferred_guard: Option<[u8; 32]> = args
            .trust_guard
            .as_deref()
            .and_then(|h| split_trust_keys(h).into_iter().next())
            .and_then(|h| hex_decode(&h).ok())
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
        let require_pq = args.require_pq.unwrap_or(false);

        // This used to pass `None` here, meaning every NAT hop on this
        // path (every `--isolate-by-destination` circuit, and every
        // retry/replacement circuit even with isolation off) was
        // punched with no authority pin at all -- the reply was "verified"
        // against a key the relay itself supplied. Route it through the
        // same pin and configured authority address the primary path uses.
        let trusted_authorities = trusted_authority_keys(args);
        let authority_addr = primary_authority(args);

        let try_select = |directory: &Directory| {
            select_and_prepare(
                |exclude| {
                    select_route_best_effort(
                        directory,
                        preferred_guard.as_ref().map(|g| g.as_slice()),
                        preferred_guard.is_some(),
                        avoid,
                        exit_port,
                        exclude,
                        require_pq,
                    )
                },
                trusted_authorities.as_ref(),
                authority_addr.as_deref(),
                label,
                3,
            )
        };

        let (route, addrs) = match try_select(&directory) {
            Ok(result) => result,
            Err(first_err) => {
                // The cached directory may be stale enough that nothing
                // usable is left in it (churned-out guards, etc). Force
                // one early, rate-limited refresh (see
                // `refresh_relay_directory`) and retry against that
                // before giving up -- this is the only path that ever
                // jumps ahead of the cache's own timer.
                say(&format!(
                    "{label}: route selection failed against the cached directory ({first_err}); \
                     forcing a directory refresh and retrying once"
                ));
                let directory = refresh_relay_directory(args, label).map_err(|e| e.to_string())?;
                try_select(&directory).map_err(|e| e.to_string())?
            }
        };

        let (guard_d, middle_d, exit_d): (&RelayDescriptor, &RelayDescriptor, &RelayDescriptor) = (&route[0], &route[1], &route[2]);
        let mut trusted = HashMap::new();
        trusted.insert("guard".to_string(), vec![<[u8; 32]>::try_from(guard_d.identity_public.as_slice()).map_err(|_| "bad guard identity")?]);
        trusted.insert("middle".to_string(), vec![<[u8; 32]>::try_from(middle_d.identity_public.as_slice()).map_err(|_| "bad middle identity")?]);
        trusted.insert("exit".to_string(), vec![<[u8; 32]>::try_from(exit_d.identity_public.as_slice()).map_err(|_| "bad exit identity")?]);

        let hops = vec![
            ("guard".to_string(), addrs[0].clone()),
            ("middle".to_string(), addrs[1].clone()),
            ("exit".to_string(), addrs[2].clone()),
        ];
        let mut kem_keys = HashMap::new();
        for (hop, d) in [("guard", guard_d), ("middle", middle_d), ("exit", exit_d)] {
            if let Some(pq) = d.pq_kem_public() {
                kem_keys.insert(hop.to_string(), pq.to_vec());
            }
        }
        build_generic_circuit_owned(
            sock,
            hops,
            Duration::from_secs_f64(self.args.timeout.unwrap_or(5.0)),
            self.args.retries.unwrap_or(0).max(0) as u32,
            Some(trusted),
            label.to_string(),
            Some(kem_keys),
        )
        .map_err(|e| e.to_string())
    }

    /// Close every circuit this pool built (never the primary -- its owner,
    /// `run_client`, closes that one itself). Force-closes: this is
    /// teardown, so there is no later `release()` left to finish a
    /// deferred close.
    ///
    /// The join loop below must run *before* `by_key`/`port_circuits` are
    /// cleared, not after -- clearing
    /// first (as this used to) left the join loop always iterating empty
    /// collections, so every pump thread spawned for an isolated or
    /// port-retry circuit was unconditionally leaked for the process
    /// lifetime instead of actually being joined. Benign on process exit
    /// (not a hang), but defeats the intended graceful shutdown.
    ///
    /// The handles are collected under `state`'s lock, but every
    /// `.join()` itself now happens *after* the lock is
    /// released, not while still holding it. `pump_return_path`'s read
    /// only rechecks its stop flag once per blocking read (up to the full
    /// configured `--timeout`, several seconds by default), so a pump
    /// thread can take a while to notice `close(true)` and actually exit;
    /// joining N of them sequentially while `state` stayed locked would
    /// have meant any other thread needing that same lock during shutdown
    /// could block for the sum of all of them, not just the first.
    pub fn aclose(&self) {
        let handles: Vec<std::thread::JoinHandle<()>> = {
            let mut state = self.state.lock().unwrap();
            for pooled in state.by_key.values() {
                pooled.close(true);
            }
            for pooled in state.port_circuits.values() {
                pooled.close(true);
            }
            for pooled in &state.retired {
                pooled.close(true);
            }
            let handles = state
                .by_key
                .values()
                .chain(state.port_circuits.values())
                .filter_map(|pooled| pooled.pump.lock().unwrap().take())
                .collect();
            state.by_key.clear();
            state.port_circuits.clear();
            state.retired.clear();
            handles
        };
        for handle in handles {
            let _ = handle.join();
        }
    }
}

/// Port of `tests/test_circuit_pool.py` -- `CircuitPool`'s and
/// `isolation_key`'s own bookkeeping (which key gets the primary circuit,
/// when a fresh one gets built, when an idle one expires, and the
/// least-recently-used eviction once the pool is at capacity).
///
/// Like the Python original, these deliberately never build a real
/// multi-hop circuit -- see `fake_transport`/`fake_pooled` and
/// `CircuitPool::set_test_build` -- so what's under test is purely the
/// pool's own bookkeeping. The real handshake path already has its own
/// coverage elsewhere (`hsserver.rs`, `hsclient.rs`, `dirclient.rs`,
/// `circuit.rs`); nothing here needs to re-prove that it works.
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ------------------------------------------------------------------
    // Test doubles
    // ------------------------------------------------------------------

    /// A cheap-to-build, genuinely real `CircuitTransport`: backed by a
    /// zero-hop `CircuitBuilder` over a bound loopback socket (no
    /// handshake, no network I/O -- the same trick `owned_circuit.rs`'s
    /// own tests use). Rust's `PooledCircuit::transport` is a concrete
    /// `Arc<CircuitTransport>`, not swappable for a fake type the way
    /// Python's `_PooledCircuit.transport` is any object with a `.send`
    /// method -- this is the cheapest thing that still type-checks there.
    fn fake_transport() -> Arc<CircuitTransport> {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let owned = crate::owned_circuit::OwnedCircuit::new(sock, |s| {
            allium::circuit::CircuitBuilder::new(s, None, Duration::from_millis(50), None, true, false, 0, 0.0, None)
        })
        .unwrap();
        Arc::new(CircuitTransport::new(owned, false))
    }

    /// A `PooledCircuit`-shaped stand-in cheap enough to build by the
    /// dozen: a real (if zero-hop) transport, no pump thread (`None`,
    /// exactly like Python's fakes' `pump_task=None`) -- port of
    /// `test_circuit_pool.py`'s `_fake_pooled`.
    fn fake_pooled() -> Arc<PooledCircuit> {
        let transport = fake_transport();
        let onion = make_onion(Arc::clone(&transport));
        PooledCircuit::new(transport, onion, Arc::new(AtomicBool::new(false)), None)
    }

    fn test_pool(isolate: bool) -> (CircuitPool, Arc<PooledCircuit>) {
        test_pool_with_limits(isolate, DEFAULT_MAX_CIRCUITS, DEFAULT_MAX_DIRTINESS)
    }

    fn test_pool_with_limits(isolate: bool, max_circuits: usize, max_dirtiness: f64) -> (CircuitPool, Arc<PooledCircuit>) {
        let primary = fake_pooled();
        let pool = CircuitPool::new_for_test(
            Args::default(),
            Arc::clone(&primary),
            Arc::new(AtomicBool::new(false)),
            isolate,
            max_circuits,
            max_dirtiness,
        );
        (pool, primary)
    }

    /// Claims the primary with `primary.example`, then builds one isolated
    /// circuit per host in `hosts` (via a `set_test_build` that records
    /// each into the returned map) -- port of `test_circuit_pool.py`'s
    /// `CircuitLifecycleTests._fill`.
    fn fill(pool: &CircuitPool, hosts: &[&str]) -> HashMap<String, Arc<PooledCircuit>> {
        let made: Arc<Mutex<HashMap<String, Arc<PooledCircuit>>>> = Arc::new(Mutex::new(HashMap::new()));
        {
            let made = Arc::clone(&made);
            pool.set_test_build(move |key, _avoid, _port| {
                let pooled = fake_pooled();
                made.lock().unwrap().insert(key.to_string(), Arc::clone(&pooled));
                Ok(pooled)
            });
        }
        pool.onion_for("primary.example", 443, None).unwrap(); // claims the primary
        for host in hosts {
            pool.onion_for(host, 443, None).unwrap();
        }
        let result = made.lock().unwrap().clone();
        result
    }

    // ------------------------------------------------------------------
    // isolation_key
    // ------------------------------------------------------------------

    #[test]
    fn isolation_key_case_insensitive() {
        assert_eq!(isolation_key("Example.COM"), isolation_key("example.com"));
    }

    #[test]
    fn isolation_key_trailing_dot_stripped() {
        assert_eq!(isolation_key("example.com."), "example.com");
    }

    #[test]
    fn isolation_key_ip_literal_untouched_besides_case() {
        assert_eq!(isolation_key("203.0.113.5"), "203.0.113.5");
    }

    #[test]
    fn isolation_key_ipv6_literal_untouched() {
        assert_eq!(isolation_key("::1"), "::1");
        assert_eq!(isolation_key("2001:DB8::1"), "2001:db8::1");
    }

    #[test]
    fn isolation_key_distinct_base_domains_are_distinct_keys() {
        assert_ne!(isolation_key("a.example.com"), isolation_key("b.other.com"));
    }

    /// The isolate-by-destination-slowdown fix: subdomains of the same real
    /// site now share one circuit instead of each getting its own -- see
    /// `base_domain`'s doc for why (this is the behavior change that used
    /// to make `isolation_key_distinct_hosts_are_distinct_keys` pass; it no
    /// longer should, so this test replaces it).
    #[test]
    fn isolation_key_groups_subdomains_of_the_same_base_domain() {
        assert_eq!(isolation_key("a.example.com"), isolation_key("b.example.com"));
        assert_eq!(isolation_key("geo.dailymotion.com"), isolation_key("dailymotion.com"));
        assert_eq!(isolation_key("rr3---sn-4g5e6nze.googlevideo.com"), isolation_key("rr2---sn-4g5ednkz.googlevideo.com"));
        // Different real sites still get different keys.
        assert_ne!(isolation_key("www.youtube.com"), isolation_key("i.ytimg.com"));
    }

    #[test]
    fn isolation_key_multi_part_suffix_keeps_three_labels() {
        assert_eq!(isolation_key("shop.example.co.uk"), "example.co.uk");
        assert_ne!(isolation_key("a.example.co.uk"), isolation_key("a.other.co.uk"));
        // Not in the (deliberately short) suffix list: falls back to the
        // last two labels, same as any other two-label domain -- a
        // documented, accepted miss (see `MULTI_PART_SUFFIXES`'s doc).
        assert_eq!(isolation_key("shop.example.tokyo.jp"), "tokyo.jp");
    }

    // ------------------------------------------------------------------
    // CircuitPool::onion_for
    // ------------------------------------------------------------------

    #[test]
    fn first_destination_claims_the_already_built_primary() {
        // No `set_test_build` at all: if the pool tried to build anything
        // for the very first destination, `build_isolated_real` would run
        // and fail (no guard/middle/exit configured) -- so this passing at
        // all is already proof nothing was built.
        let (pool, primary) = test_pool(true);
        let onion = pool.onion_for("example.com", 443, None).unwrap();
        assert!(Arc::ptr_eq(&onion, &primary.onion));
    }

    /// SOCKS username/password scopes keep circuits apart on their own,
    /// even with `--no-isolate-by-destination`: the same destination under
    /// two credential pairs gets two circuits, and the same pair reuses
    /// its circuit.
    #[test]
    fn socks_auth_scope_isolates_even_with_destination_isolation_off() {
        let (pool, primary) = test_pool(false);
        let built = Arc::new(Mutex::new(Vec::new()));
        {
            let built = Arc::clone(&built);
            pool.set_test_build(move |key, _avoid, _port| {
                built.lock().unwrap().push(key.to_string());
                Ok(fake_pooled())
            });
        }
        let unscoped = pool.onion_for("example.com", 443, None).unwrap(); // claims the primary
        let alice = pool.onion_for("example.com", 443, Some("auth:alice")).unwrap();
        let bob = pool.onion_for("example.com", 443, Some("auth:bob")).unwrap();
        let alice_again = pool.onion_for("other.example", 80, Some("auth:alice")).unwrap();

        assert!(Arc::ptr_eq(&unscoped, &primary.onion));
        assert!(!Arc::ptr_eq(&alice, &primary.onion));
        assert!(!Arc::ptr_eq(&alice, &bob), "different credentials must never share a circuit");
        assert!(Arc::ptr_eq(&alice, &alice_again), "with destination isolation off, one scope is one circuit");
        assert_eq!(*built.lock().unwrap(), vec!["auth:alice|*".to_string(), "auth:bob|*".to_string()]);
        // The key never carries the credentials themselves, only the tag
        // the proxy derived from them.
        assert!(built.lock().unwrap().iter().all(|k| k.starts_with("auth:")));
    }

    /// With destination isolation on, scope and destination combine: one
    /// scope visiting two sites gets two circuits, and two scopes visiting
    /// one site get two circuits.
    #[test]
    fn socks_auth_scope_combines_with_destination_isolation() {
        let (pool, _primary) = test_pool(true);
        pool.onion_for("first.example", 443, None).unwrap(); // claims the primary
        pool.set_test_build(|_key, _avoid, _port| Ok(fake_pooled()));

        let a_site1 = pool.onion_for("site1.example", 443, Some("auth:a")).unwrap();
        let a_site2 = pool.onion_for("site2.example", 443, Some("auth:a")).unwrap();
        let b_site1 = pool.onion_for("site1.example", 443, Some("auth:b")).unwrap();
        let a_site1_again = pool.onion_for("www.site1.example", 80, Some("auth:a")).unwrap();

        assert!(!Arc::ptr_eq(&a_site1, &a_site2));
        assert!(!Arc::ptr_eq(&a_site1, &b_site1));
        assert!(Arc::ptr_eq(&a_site1, &a_site1_again));
        // A retry for a scoped stream stays within its scope's key.
        let replacement = pool.retry_onion("site1.example", 443, Some("auth:a"), Some(a_site1.clone()), None).unwrap().unwrap();
        assert!(!Arc::ptr_eq(&replacement, &a_site1));
        assert!(Arc::ptr_eq(&pool.onion_for("site1.example", 443, Some("auth:a")).unwrap(), &replacement));
        assert!(Arc::ptr_eq(&pool.onion_for("site1.example", 443, Some("auth:b")).unwrap(), &b_site1), "another scope is untouched by the retry");
    }

    #[test]
    fn second_distinct_destination_gets_a_fresh_circuit() {
        let (pool, primary) = test_pool(true);
        pool.onion_for("first.example", 443, None).unwrap(); // claims the primary

        let built = Arc::new(Mutex::new(Vec::new()));
        {
            let built = Arc::clone(&built);
            pool.set_test_build(move |key, _avoid, _port| {
                built.lock().unwrap().push(key.to_string());
                Ok(fake_pooled())
            });
        }
        let onion = pool.onion_for("second.example", 443, None).unwrap();

        assert_eq!(*built.lock().unwrap(), vec!["second.example".to_string()]);
        assert!(!Arc::ptr_eq(&onion, &primary.onion));
    }

    #[test]
    fn repeat_visits_to_the_same_isolated_destination_reuse_it() {
        let (pool, _primary) = test_pool(true);
        pool.onion_for("first.example", 443, None).unwrap(); // claims the primary

        let build_count = Arc::new(Mutex::new(0u32));
        {
            let build_count = Arc::clone(&build_count);
            pool.set_test_build(move |_key, _avoid, _port| {
                *build_count.lock().unwrap() += 1;
                Ok(fake_pooled())
            });
        }
        let onion_1 = pool.onion_for("second.example", 443, None).unwrap();
        let onion_2 = pool.onion_for("second.example", 80, None).unwrap(); // same host, different port
        let onion_3 = pool.onion_for("SECOND.EXAMPLE.", 443, None).unwrap(); // same key, different spelling

        assert_eq!(*build_count.lock().unwrap(), 1);
        assert!(Arc::ptr_eq(&onion_1, &onion_2));
        assert!(Arc::ptr_eq(&onion_2, &onion_3));
    }

    #[test]
    fn repeat_visits_to_the_primarys_destination_reuse_it_within_its_dirtiness_window() {
        // A generous `max_dirtiness`: within it, repeat visits to the
        // primary's own key keep reusing it, same as any other
        // not-yet-expired circuit would.
        let (pool, primary) = test_pool_with_limits(true, DEFAULT_MAX_CIRCUITS, DEFAULT_MAX_DIRTINESS);
        let onion_1 = pool.onion_for("first.example", 443, None).unwrap();
        let onion_2 = pool.onion_for("first.example", 443, None).unwrap();
        assert!(Arc::ptr_eq(&onion_1, &primary.onion));
        assert!(Arc::ptr_eq(&onion_2, &primary.onion));
    }

    /// Regression test: the primary is no longer exempt from
    /// `max_dirtiness` -- once it ages out, a repeat visit to its own key
    /// detaches it (it stays open, owned by `run_client`, but takes no
    /// more streams) and gets a fresh pooled circuit instead, exactly
    /// like `idle_isolated_circuit_expires_and_is_rebuilt` below does for
    /// an ordinary key.
    #[test]
    fn aged_out_primary_is_detached_and_replaced_with_a_fresh_circuit() {
        // Not 0.0, which disables expiry entirely (see
        // `PooledCircuit::expired`) -- a vanishingly small positive value
        // instead means "dirty almost the instant it's built".
        let (pool, primary) = test_pool_with_limits(true, DEFAULT_MAX_CIRCUITS, 1e-9);
        let onion_1 = pool.onion_for("first.example", 443, None).unwrap(); // claims the primary
        assert!(Arc::ptr_eq(&onion_1, &primary.onion));

        let built = Arc::new(Mutex::new(Vec::new()));
        {
            let built = Arc::clone(&built);
            pool.set_test_build(move |key, _avoid, _port| {
                built.lock().unwrap().push(key.to_string());
                Ok(fake_pooled())
            });
        }
        std::thread::sleep(Duration::from_millis(10)); // let a nonzero amount of time pass
        let onion_2 = pool.onion_for("first.example", 443, None).unwrap(); // primary is dirty -> detached, rebuilt

        assert_eq!(*built.lock().unwrap(), vec!["first.example".to_string()]);
        assert!(!Arc::ptr_eq(&onion_2, &primary.onion));

        // The now-detached, streamless primary no longer needs keepalives.
        assert!(pool.live_transports().iter().all(|t| !Arc::ptr_eq(t, &primary.transport)));
    }

    #[test]
    fn idle_isolated_circuit_expires_and_is_rebuilt() {
        let (pool, _primary) = test_pool_with_limits(true, DEFAULT_MAX_CIRCUITS, 1e-9);
        pool.onion_for("first.example", 443, None).unwrap(); // claims the primary

        let built = Arc::new(Mutex::new(Vec::new()));
        {
            let built = Arc::clone(&built);
            pool.set_test_build(move |key, _avoid, _port| {
                built.lock().unwrap().push(key.to_string());
                Ok(fake_pooled())
            });
        }
        let onion_1 = pool.onion_for("second.example", 443, None).unwrap();
        std::thread::sleep(Duration::from_millis(10)); // let a nonzero amount of time pass
        let onion_2 = pool.onion_for("second.example", 443, None).unwrap(); // already "dirty" -> rebuilt

        assert_eq!(*built.lock().unwrap(), vec!["second.example".to_string(), "second.example".to_string()]);
        assert!(!Arc::ptr_eq(&onion_1, &onion_2));
    }

    #[test]
    fn cap_evicts_the_least_recently_used_isolated_circuit() {
        let (pool, _primary) = test_pool_with_limits(true, 1, DEFAULT_MAX_DIRTINESS);
        pool.onion_for("first.example", 443, None).unwrap(); // claims the primary

        let built = Arc::new(Mutex::new(Vec::new()));
        let fakes: Arc<Mutex<HashMap<String, Arc<PooledCircuit>>>> = Arc::new(Mutex::new(HashMap::new()));
        {
            let built = Arc::clone(&built);
            let fakes = Arc::clone(&fakes);
            pool.set_test_build(move |key, _avoid, _port| {
                built.lock().unwrap().push(key.to_string());
                let pooled = fake_pooled();
                fakes.lock().unwrap().insert(key.to_string(), Arc::clone(&pooled));
                Ok(pooled)
            });
        }
        pool.onion_for("second.example", 443, None).unwrap(); // 1st isolated circuit (fills the cap)
        pool.onion_for("third.example", 443, None).unwrap(); // over cap -> evicts "second.example"

        assert_eq!(*built.lock().unwrap(), vec!["second.example".to_string(), "third.example".to_string()]);
        // `PooledCircuit::close` (called by the eviction) is this test's
        // outside-in proof the evicted circuit was actually torn down, not
        // just dropped from the map.
        let fakes = fakes.lock().unwrap();
        assert!(fakes["second.example"].is_closed());
        assert!(!fakes["third.example"].is_closed());
        let state = pool.state.lock().unwrap();
        assert!(!state.by_key.contains_key("second.example"));
        assert!(state.by_key.contains_key("third.example"));
    }

    /// The isolate-by-destination-slowdown fix's concurrency piece: two
    /// real threads racing `onion_for` for the same brand-new key must
    /// share one build, not each start their own. Unlike this file's other
    /// tests (all single-threaded, sequential calls -- fine for proving
    /// the pool's *bookkeeping*, but incapable of exercising a race at
    /// all), this one uses real `std::thread`s and holds the fake build
    /// open with a condvar until both threads have had a chance to reach
    /// it, so a regression back to the old "drop the lock, then build"
    /// shape would show up here as `build_count == 2`.
    #[test]
    fn concurrent_first_visits_to_a_new_key_share_one_build() {
        let (pool, _primary) = test_pool(true);
        pool.onion_for("first.example", 443, None).unwrap(); // claims the primary

        let build_count = Arc::new(Mutex::new(0u32));
        let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        {
            let build_count = Arc::clone(&build_count);
            let release = Arc::clone(&release);
            pool.set_test_build(move |_key, _avoid, _port| {
                *build_count.lock().unwrap() += 1;
                let (lock, cvar) = &*release;
                let mut done = lock.lock().unwrap();
                while !*done {
                    let (guard, result) = cvar.wait_timeout(done, Duration::from_secs(2)).unwrap();
                    done = guard;
                    if result.timed_out() {
                        break;
                    }
                }
                Ok(fake_pooled())
            });
        }

        let pool = Arc::new(pool);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let pool = Arc::clone(&pool);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    pool.onion_for("second.example", 443, None).unwrap()
                })
            })
            .collect();

        // Give both threads a beat to reach the (deliberately slow) build
        // before releasing it.
        std::thread::sleep(Duration::from_millis(150));
        {
            let (lock, cvar) = &*release;
            *lock.lock().unwrap() = true;
            cvar.notify_all();
        }
        let onions: Vec<Onion> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        assert_eq!(*build_count.lock().unwrap(), 1);
        assert!(Arc::ptr_eq(&onions[0], &onions[1]));
    }

    #[test]
    fn aclose_closes_only_pool_built_circuits_not_the_primary() {
        let (pool, primary) = test_pool(true);
        pool.onion_for("first.example", 443, None).unwrap(); // claims the primary

        pool.set_test_build(move |_key, _avoid, _port| Ok(fake_pooled()));
        pool.onion_for("second.example", 443, None).unwrap();
        let isolated = Arc::clone(pool.state.lock().unwrap().by_key.get("second.example").unwrap());

        pool.aclose();

        assert!(isolated.is_closed());
        assert!(!primary.is_closed());
        assert!(pool.state.lock().unwrap().by_key.is_empty());
    }

    /// `aclose()` used to call `by_key.clear()`/`port_circuits.clear()`
    /// *before* the loop meant to join those same circuits' pump threads,
    /// so that loop always
    /// iterated empty collections and every real pump thread was
    /// unconditionally leaked (its `JoinHandle` never taken, never
    /// joined). This is the regression test: a `PooledCircuit` with a real
    /// pump `JoinHandle` must have that handle actually taken (and thus
    /// joined) by `aclose()`, not left sitting in the pool-built circuit's
    /// `pump` slot.
    #[test]
    fn aclose_joins_pool_built_circuits_pump_threads() {
        let (pool, _primary) = test_pool(true);
        let transport = fake_transport();
        let onion = make_onion(Arc::clone(&transport));
        let handle = std::thread::spawn(|| {});
        let pooled = PooledCircuit::new(transport, onion, Arc::new(AtomicBool::new(false)), Some(handle));
        pool.state.lock().unwrap().by_key.insert("isolated.example".to_string(), Arc::clone(&pooled));

        pool.aclose();

        assert!(pooled.pump.lock().unwrap().is_none(), "aclose must take (and join) the pump handle, not leak it");
    }

    /// `aclose()` must release `state`'s lock before joining pump
    /// threads, not hold it across every blocking
    /// `.join()`. Otherwise any other thread needing that same lock during
    /// shutdown would block for as long as the slowest pump thread takes
    /// to notice its stop flag and actually exit -- which can be the full
    /// configured `--timeout` per thread, not an instant.
    #[test]
    fn aclose_releases_the_lock_before_joining_a_slow_pump_thread() {
        let (pool, _primary) = test_pool(true);
        let pool = Arc::new(pool);

        // A pump thread that will not exit until explicitly released,
        // standing in for a real one still blocked in its read loop.
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let _ = release_rx.recv();
        });
        let transport = fake_transport();
        let onion = make_onion(Arc::clone(&transport));
        let pooled = PooledCircuit::new(transport, onion, Arc::new(AtomicBool::new(false)), Some(handle));
        pool.state.lock().unwrap().by_key.insert("slow.example".to_string(), pooled);

        let aclose_pool = Arc::clone(&pool);
        let aclose_thread = std::thread::spawn(move || aclose_pool.aclose());
        // Give aclose() time to start and reach its (still-blocked) join.
        std::thread::sleep(Duration::from_millis(100));

        // If the lock were still held at this point, this probe would
        // block until aclose() -- and its join of the still-blocked pump
        // thread -- finished, which never happens on its own since the
        // pump thread is waiting on `release_rx`. Bounded so a real
        // regression fails this test instead of hanging the suite.
        let (probe_tx, probe_rx) = std::sync::mpsc::channel();
        let probe_pool = Arc::clone(&pool);
        std::thread::spawn(move || {
            let _guard = probe_pool.state.lock().unwrap();
            let _ = probe_tx.send(());
        });
        let acquired_promptly = probe_rx.recv_timeout(Duration::from_secs(2)).is_ok();

        // Clean up regardless of the assertion outcome, so a failure here
        // doesn't leave a permanently-blocked background thread behind.
        let _ = release_tx.send(());
        let _ = aclose_thread.join();

        assert!(acquired_promptly, "state's lock must be released while aclose() is still joining a slow pump thread");
    }

    // ------------------------------------------------------------------
    // CircuitPool::retry_onion
    // ------------------------------------------------------------------

    #[test]
    fn retry_replaces_primary_for_every_later_stream_when_not_isolating() {
        let (pool, primary) = test_pool(false);
        primary.set_test_exit_identity(vec![b'E'; 32]);
        let claimed = pool.onion_for("a.example", 443, None).unwrap();
        assert!(Arc::ptr_eq(&claimed, &primary.onion));

        let avoids: Arc<Mutex<Vec<HashSet<Vec<u8>>>>> = Arc::new(Mutex::new(Vec::new()));
        {
            let avoids = Arc::clone(&avoids);
            pool.set_test_build(move |_key, avoid, _port| {
                avoids.lock().unwrap().push(avoid);
                Ok(fake_pooled())
            });
        }
        let new_onion = pool.retry_onion("a.example", 443, None, Some(primary.onion.clone()), None).unwrap().unwrap();
        assert!(!Arc::ptr_eq(&new_onion, &primary.onion));
        // The failed exit is avoided for the replacement route.
        assert!(avoids.lock().unwrap()[0].contains(&vec![b'E'; 32]));
        // Without isolation, a *different* host now also uses the replacement.
        let later = pool.onion_for("b.example", 443, None).unwrap();
        assert!(Arc::ptr_eq(&later, &new_onion));
    }

    #[test]
    fn concurrent_failures_on_same_circuit_build_only_one_replacement() {
        let (pool, primary) = test_pool(false);
        primary.set_test_exit_identity(vec![b'E'; 32]);
        pool.onion_for("a.example", 443, None).unwrap();

        let builds = Arc::new(Mutex::new(Vec::new()));
        {
            let builds = Arc::clone(&builds);
            pool.set_test_build(move |key, _avoid, _port| {
                builds.lock().unwrap().push(key.to_string());
                Ok(fake_pooled())
            });
        }
        let first = pool.retry_onion("a.example", 443, None, Some(primary.onion.clone()), None).unwrap().unwrap();
        let second = pool.retry_onion("a.example", 443, None, Some(primary.onion.clone()), None).unwrap().unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(builds.lock().unwrap().len(), 1);
    }

    #[test]
    fn replaced_pool_circuit_is_retired_not_closed() {
        let (pool, _primary) = test_pool(true);
        pool.onion_for("first.example", 443, None).unwrap(); // claims the primary

        let made: Arc<Mutex<Vec<Arc<PooledCircuit>>>> = Arc::new(Mutex::new(Vec::new()));
        {
            let made = Arc::clone(&made);
            pool.set_test_build(move |_key, _avoid, _port| {
                let pooled = fake_pooled();
                made.lock().unwrap().push(Arc::clone(&pooled));
                Ok(pooled)
            });
        }
        let isolated = pool.onion_for("second.example", 443, None).unwrap();
        let first_made = Arc::clone(&made.lock().unwrap()[0]);
        let replacement = pool.retry_onion("second.example", 443, None, Some(isolated.clone()), None).unwrap().unwrap();
        assert!(!Arc::ptr_eq(&replacement, &isolated));
        assert!(!first_made.is_closed()); // still serving its open streams
        assert!(pool.state.lock().unwrap().retired.iter().any(|p| Arc::ptr_eq(p, &first_made)));

        pool.aclose();
        assert!(first_made.is_closed());
    }

    #[test]
    fn repeated_failures_for_one_destination_stop_building_new_circuits() {
        let (pool, _primary) = test_pool(true);
        pool.onion_for("first.example", 443, None).unwrap(); // claims the primary

        let builds = Arc::new(Mutex::new(0usize));
        {
            let builds = Arc::clone(&builds);
            pool.set_test_build(move |_key, _avoid, _port| {
                *builds.lock().unwrap() += 1;
                Ok(fake_pooled())
            });
        }
        let mut failing = pool.onion_for("video.example", 443, None).unwrap();
        let builds_before = *builds.lock().unwrap();

        // Each failure on the destination's current circuit rebuilds it,
        // up to the per-window budget ...
        for _ in 0..MAX_REBUILDS_PER_WINDOW {
            failing = pool.retry_onion("video.example", 443, None, Some(failing.clone()), None).unwrap().expect("within budget");
        }
        assert_eq!(*builds.lock().unwrap() - builds_before, MAX_REBUILDS_PER_WINDOW);

        // ... then the pool gives up instead of building yet another one,
        // and keeps the circuit the key already has.
        assert!(pool.retry_onion("video.example", 443, None, Some(failing.clone()), None).unwrap().is_none());
        assert_eq!(*builds.lock().unwrap() - builds_before, MAX_REBUILDS_PER_WINDOW);
        assert!(Arc::ptr_eq(&pool.onion_for("video.example", 443, None).unwrap(), &failing));

        // Other destinations are unaffected.
        let other = pool.onion_for("other.example", 443, None).unwrap();
        assert!(pool.retry_onion("other.example", 443, None, Some(other), None).unwrap().is_some());
    }

    #[test]
    fn repeated_exit_policy_refusals_stop_building_port_circuits() {
        let (pool, primary) = test_pool(false);
        primary.set_test_exit_identity(vec![b'E'; 32]);
        pool.onion_for("voice.example", 2087, None).unwrap(); // claims the primary

        let builds = Arc::new(Mutex::new(0usize));
        {
            let builds = Arc::clone(&builds);
            pool.set_test_build(move |_key, _avoid, _port| {
                *builds.lock().unwrap() += 1;
                Ok(fake_pooled())
            });
        }
        let mut failing = primary.onion.clone();
        for _ in 0..MAX_REBUILDS_PER_WINDOW {
            failing = pool
                .retry_onion("voice.example", 2087, None, Some(failing.clone()), Some("exit-policy"))
                .unwrap()
                .expect("within budget");
        }
        assert!(pool.retry_onion("voice.example", 2087, None, Some(failing), Some("exit-policy")).unwrap().is_none());
        assert_eq!(*builds.lock().unwrap(), MAX_REBUILDS_PER_WINDOW);
    }

    // ------------------------------------------------------------------
    // CircuitPool::retry_onion, reason == "exit-policy"
    // ------------------------------------------------------------------

    #[test]
    fn policy_refusal_builds_a_port_circuit_and_keeps_the_shared_one() {
        let (pool, primary) = test_pool(false);
        primary.set_test_exit_identity(vec![b'E'; 32]);
        pool.onion_for("a.example", 22, None).unwrap(); // claims the primary

        type Call = (HashSet<Vec<u8>>, Option<u16>);
        let calls: Arc<Mutex<Vec<Call>>> = Arc::new(Mutex::new(Vec::new()));
        {
            let calls = Arc::clone(&calls);
            pool.set_test_build(move |_key, avoid, port| {
                calls.lock().unwrap().push((avoid, port));
                Ok(fake_pooled())
            });
        }
        let ssh = pool.retry_onion("a.example", 22, None, Some(primary.onion.clone()), Some("exit-policy")).unwrap().unwrap();
        {
            let calls = calls.lock().unwrap();
            assert_eq!(calls[0].1, Some(22));
            assert!(calls[0].0.contains(&vec![b'E'; 32]));
        }
        // Same host+port now uses the port circuit ...
        assert!(Arc::ptr_eq(&pool.onion_for("a.example", 22, None).unwrap(), &ssh));
        // ... every other port still rides the shared primary, and the
        // refusing exit is NOT avoided for other ports.
        assert!(Arc::ptr_eq(&pool.onion_for("a.example", 443, None).unwrap(), &primary.onion));
        assert!(Arc::ptr_eq(&pool.onion_for("b.example", 80, None).unwrap(), &primary.onion));
        let avoid_443 = {
            let mut state = pool.state.lock().unwrap();
            pool.active_avoid(&mut state, Some(443))
        };
        assert!(!avoid_443.contains(&vec![b'E'; 32]));
    }

    // ------------------------------------------------------------------
    // Eviction/close lifecycle: closed promptly, unless a stream is still
    // sending on it, in which case the close is deferred until it finishes.
    // ------------------------------------------------------------------

    #[test]
    fn eviction_defers_the_close_while_a_stream_is_still_sending() {
        let (pool, _primary) = test_pool_with_limits(true, 1, DEFAULT_MAX_DIRTINESS);
        let made = fill(&pool, &["second.example"]);
        let busy = Arc::clone(&made["second.example"]);
        // A stream starts relaying on it -- exactly what `_relay_stream`
        // signals through `onion_stream_started`.
        pool.stream_started(&busy.onion);
        assert_eq!(busy.active_stream_count(), 1);

        pool.onion_for("third.example", 443, None).unwrap(); // over cap -> evicts `busy`

        // Not closed: its socket is still being sent on. It is out of
        // service (no new stream can be routed to it) but parked,
        // findable, and waiting for its last stream.
        assert!(!busy.is_closed());
        assert!(busy.pending_close.load(Ordering::SeqCst));
        assert!(!pool.state.lock().unwrap().by_key.contains_key("second.example"));
        assert!(pool.state.lock().unwrap().retired.iter().any(|p| Arc::ptr_eq(p, &busy)));

        // ... and the moment that stream finishes, it really does close.
        pool.stream_finished(&busy.onion);
        assert!(busy.is_closed());
        assert!(!pool.state.lock().unwrap().retired.iter().any(|p| Arc::ptr_eq(p, &busy)));
    }

    #[test]
    fn eviction_of_an_idle_circuit_closes_it_instead_of_leaking() {
        // The regression the deferral introduced: with nothing sending on
        // an evicted circuit, nothing would ever call release() to finish
        // a deferred close, so the socket stayed open indefinitely -- an
        // unbounded leak wearing `max_circuits`' clothes.
        let (pool, _primary) = test_pool_with_limits(true, 1, DEFAULT_MAX_DIRTINESS);
        let made = fill(&pool, &["second.example"]);
        let idle = Arc::clone(&made["second.example"]);
        assert_eq!(idle.active_stream_count(), 0);

        pool.onion_for("third.example", 443, None).unwrap(); // over cap -> evicts `idle`

        assert!(idle.is_closed());
        assert!(!idle.pending_close.load(Ordering::SeqCst));
        // Nothing parked: an idle eviction leaves no bookkeeping behind.
        assert!(pool.state.lock().unwrap().retired.is_empty());
    }

    #[test]
    fn expired_idle_circuit_is_closed_when_its_key_comes_back() {
        // Same rule on the dirtiness path: a stale circuit nobody is using
        // is closed as it is replaced, not left open.
        let (pool, _primary) = test_pool_with_limits(true, DEFAULT_MAX_CIRCUITS, 1e-9);
        let made = fill(&pool, &["second.example"]);
        let stale = Arc::clone(&made["second.example"]);
        std::thread::sleep(Duration::from_millis(10)); // let a nonzero amount of time pass

        pool.onion_for("second.example", 443, None).unwrap(); // dirty -> rebuilt

        assert!(stale.is_closed());
        assert!(pool.state.lock().unwrap().retired.is_empty());
    }

    #[test]
    fn busy_retired_circuit_still_gets_keepalives() {
        // A retired circuit is being phased out, so it does not need to
        // stay *fresh* -- unless a stream is still on it, in which case a
        // quiet five minutes would have the relays prune it out from
        // under that stream (the silent-stall bug, reached by another
        // route).
        let (pool, _primary) = test_pool_with_limits(true, 1, DEFAULT_MAX_DIRTINESS);
        let made = fill(&pool, &["second.example"]);
        let busy = Arc::clone(&made["second.example"]);
        pool.stream_started(&busy.onion);
        pool.onion_for("third.example", 443, None).unwrap(); // retires `busy`, still in use
        assert!(pool.live_transports().iter().any(|t| Arc::ptr_eq(t, &busy.transport)));

        pool.stream_finished(&busy.onion); // closes it for real
        assert!(!pool.live_transports().iter().any(|t| Arc::ptr_eq(t, &busy.transport)));
    }

    #[test]
    fn aclose_closes_even_a_circuit_with_a_live_stream() {
        // Teardown has no later release() to defer to: nothing would ever
        // finish a deferred close, so a busy circuit must close outright.
        let (pool, _primary) = test_pool(true);
        let made = fill(&pool, &["second.example"]);
        let busy = Arc::clone(&made["second.example"]);
        pool.stream_started(&busy.onion);

        pool.aclose();

        assert!(busy.is_closed());
    }
}
