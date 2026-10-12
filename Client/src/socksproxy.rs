//! A local SOCKS5 server that tunnels TCP (and, opt-in, UDP) through an
//! Allium circuit (Rust port of `socksproxy.py`).
//!
//! An unmodified application points its SOCKS5 proxy at `127.0.0.1:9050`,
//! and this server translates SOCKS5 into Allium stream requests, sends
//! them through the circuit via an `onion` callback, and relays replies
//! back -- without the application ever knowing it is not talking to a
//! real SOCKS proxy.
//!
//! Supported:
//!
//! * **CONNECT** (RFC 1928 command `0x01`) -- open a TCP stream through the
//!   exit.
//! * **CONNECT to a `.allium` address** -- routed through
//!   [`SocksServerOptions::hidden_service_connect`] instead of an ordinary
//!   exit circuit, so a browser or `curl` pointed at this proxy can just
//!   visit a `.allium` hostname like any other site.
//! * **RESOLVE** (Tor's extension, command `0xF0`) -- resolve a domain at
//!   the exit, so the client's own resolver is never used.
//! * **UDP ASSOCIATE** (command `0x03`) -- relays UDP datagrams through the
//!   circuit, opt-in via [`SocksServerOptions::allow_udp`] and scoped to
//!   v1: each datagram must fit one onion cell whole (no SOCKS5 `FRAG`
//!   support, no [`crate::fragment`] routing), IPv4 destinations only.
//!
//! # Architectural deviation from the Python original
//!
//! Python's `SocksServer` is built on `asyncio`: one event loop, cooperative
//! coroutines, `asyncio.start_server`. This crate has no async runtime
//! anywhere (the same precedent set by [`crate::circuit`], [`crate::handshake`]
//! and [`crate::stream`]'s `CircuitSession`), so this module uses **blocking
//! I/O with a thread per connection**: [`std::net::TcpListener`] plus one
//! [`std::thread`] per accepted client, and a dedicated relay thread per UDP
//! ASSOCIATE. Where Python polls with `asyncio.wait(..., timeout=...)` to
//! let a coroutine notice external state (a stream the exit has closed)
//! without blocking forever, this crate sets a short socket read timeout and
//! loops -- the same technique, translated to a blocking thread.
//!
//! `onion` and friends become `Arc<dyn Fn(...) + Send + Sync>` ([`Onion`])
//! rather than Python's plain callables, since they are invoked from
//! whichever thread happens to be relaying at the time. `deliver_reply`,
//! `write_to_stream`, `deliver_data` and `close_stream` are unchanged in
//! spirit: still the API "whoever owns the circuit socket" calls from
//! *its* thread to feed return-path data into this server, without this
//! module ever touching a circuit socket itself.
//!
//! # Stream isolation
//!
//! Every per-stream map here (`writers`, `reassemblers`, `pending_write`,
//! `closed_streams`, `client_gone`) is keyed by `(onion, stream_id)`, not
//! `stream_id` alone. `stream_id` is chosen by the untrusted exit and is
//! typically a small per-circuit counter, so two isolated circuits (see
//! [`SocksServerOptions::onion_router`]) can both hand out `stream_id = 1`;
//! keying on the bare id would let a malicious or colluding exit on one
//! circuit read or inject into the *other* circuit's stream. The `onion`
//! callable that resolved a stream's CONNECT is stable and distinct per
//! circuit, so it doubles as that missing circuit key ([`OnionKey`], keyed
//! by `Arc` pointer identity).

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use blake2::Blake2b;
use digest::consts::U16;
use digest::{CustomizedInit, Digest as _};

use crate::fragment::{decode_fragment, encode_fragment, Fragment, Reassembler, DEFAULT_MTU};
use crate::socks::{
    self, decode_reply, encode_datagram_request, encode_request, DatagramRequest, StreamReply,
    StreamRequest, ADDR_UNSUPPORTED, COMMAND_UNSUPPORTED, CONNECT, CONNECTION_REFUSED,
    GENERAL_FAILURE, HOST_UNREACHABLE, RESOLVE, SUCCESS, TTL_EXPIRED,
};

/// Default SOCKS5 listen port (`9050`, matching the Python default and the
/// usual Tor convention).
pub const DEFAULT_SOCKS_PORT: u16 = 9050;

/// The one SOCKS protocol version this server speaks.
pub const SOCKS_VERSION: u8 = 0x05;

/// After this many forward fragments sent back-to-back for one stream,
/// [`SocksServer`] pauses briefly, so a large local read cannot outrun a
/// relay's single-threaded receive-decrypt-forward loop. See
/// `allium_cli.py`'s matching `SEND_PACE_EVERY` on the return path.
const SEND_PACE_EVERY: u32 = 24;
const SEND_PACE_DELAY: Duration = Duration::from_millis(3);

/// How long to wait for the exit's CONNECTED/RESOLVED reply before giving
/// up on one circuit.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Total CONNECT/RESOLVE attempts (first try + retries on fresh circuits)
/// when an [`SocksServerOptions::onion_retry`] hook is supplied.
pub const DEFAULT_MAX_CONNECT_ATTEMPTS: u32 = 3;

/// Default bound for [`Reassembler::new`]'s `max_pending`, matching
/// Python's `Reassembler(stream_id=...)` default.
const DEFAULT_MAX_PENDING: usize = 4096;

/// Return-path state is driven by the exit-supplied `stream_id`, so an exit
/// (or anything that can inject cells on a circuit) can invent stream ids
/// at will. Every per-stream table below is therefore bounded, so a
/// hostile exit cannot grow this process's memory without limit.
///
/// Most bytes ever held for one stream that has no registered writer yet.
/// Legitimate early data (arriving between the CONNECT reply and the relay
/// loop registering its writer) is tiny and short-lived.
const MAX_PENDING_WRITE_PER_STREAM: usize = 256 * 1024;
/// Most streams that may hold early data at once (worst case
/// `MAX_PENDING_WRITE_STREAMS * MAX_PENDING_WRITE_PER_STREAM` = 16 MiB).
const MAX_PENDING_WRITE_STREAMS: usize = 64;
/// Most entries in each of `closed_streams` / `client_gone` (id markers
/// only, a few tens of bytes each). At the cap new markers are refused
/// instead of evicting live ones.
const MAX_STREAM_MARKERS: usize = 65_536;
/// Most live reassemblers in `deliver_data`'s table.
const MAX_REASSEMBLERS: usize = 1024;
/// Longest a write to a client's local socket may block before that
/// stream is dropped. Bounds how long a client that stops reading can hold
/// up whichever caller (the relay loop, a return-path delivery) is writing
/// to it; `write_to_stream`/`deliver_data`/`flush_pending` already avoid
/// blocking every *other* stream while this one is stuck, but the one
/// write itself still needs a limit.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Is this Allium stream status worth retrying on a *different* circuit?
///
/// Each is plausibly specific to the exit (or the path to it) rather than
/// the destination: a timeout, an exit-side error, a DNS failure at that
/// exit, or `COMMAND_UNSUPPORTED` (an exit-policy denial -- another exit
/// may allow it). `CONNECTION_REFUSED` is deliberately excluded: the
/// destination itself answered "no". `ADDR_UNSUPPORTED` is a property of
/// the request, not the path.
pub fn is_retryable(status: u8) -> bool {
    matches!(status, GENERAL_FAILURE | HOST_UNREACHABLE | TTL_EXPIRED | COMMAND_UNSUPPORTED)
}

/// SOCKS5 command bytes (RFC 1928).
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;
/// Tor's "resolve this name" extension command.
pub const CMD_RESOLVE: u8 = 0xF0;

/// Address type bytes.
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

/// SOCKS5 reply codes (RFC 1928), a superset of the stream status codes.
pub const REPLY_SUCCEEDED: u8 = 0x00;
pub const REPLY_GENERAL: u8 = 0x01;
pub const REPLY_NOT_ALLOWED: u8 = 0x02;
pub const REPLY_NET_UNREACHABLE: u8 = 0x03;
pub const REPLY_HOST_UNREACHABLE: u8 = 0x04;
pub const REPLY_CONN_REFUSED: u8 = 0x05;
pub const REPLY_TTL_EXPIRED: u8 = 0x06;
pub const REPLY_CMD_UNSUPPORTED: u8 = 0x07;
pub const REPLY_ADDR_UNSUPPORTED: u8 = 0x08;

/// Named SOCKS5 reply codes (RFC 1928), mirroring Python's `ReplyCode`.
pub struct ReplyCode;
impl ReplyCode {
    pub const SUCCEEDED: u8 = REPLY_SUCCEEDED;
    pub const GENERAL: u8 = REPLY_GENERAL;
    pub const NOT_ALLOWED: u8 = REPLY_NOT_ALLOWED;
    pub const NET_UNREACHABLE: u8 = REPLY_NET_UNREACHABLE;
    pub const HOST_UNREACHABLE: u8 = REPLY_HOST_UNREACHABLE;
    pub const CONN_REFUSED: u8 = REPLY_CONN_REFUSED;
    pub const TTL_EXPIRED: u8 = REPLY_TTL_EXPIRED;
    pub const CMD_UNSUPPORTED: u8 = REPLY_CMD_UNSUPPORTED;
    pub const ADDR_UNSUPPORTED: u8 = REPLY_ADDR_UNSUPPORTED;
}

/// A SOCKS5 negotiation failure, carrying the RFC 1928 reply code to send
/// back to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocksError(pub u8);

impl std::fmt::Display for SocksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SOCKS5 error (reply code {:#04x})", self.0)
    }
}
impl std::error::Error for SocksError {}

/// A [`SocksServer`] constructor argument was invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);
impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ConfigError {}

fn status_to_socks(status: u8) -> u8 {
    match status {
        SUCCESS => REPLY_SUCCEEDED,
        GENERAL_FAILURE => REPLY_GENERAL,
        HOST_UNREACHABLE => REPLY_HOST_UNREACHABLE,
        CONNECTION_REFUSED => REPLY_CONN_REFUSED,
        TTL_EXPIRED => REPLY_TTL_EXPIRED,
        COMMAND_UNSUPPORTED => REPLY_CMD_UNSUPPORTED,
        ADDR_UNSUPPORTED => REPLY_ADDR_UNSUPPORTED,
        _ => REPLY_GENERAL,
    }
}

/// Parse a SOCKS5 address (`ATYP` + payload). `data` begins with the ATYP
/// byte. Returns `(host, port, consumed)`.
fn parse_address(data: &[u8]) -> Result<(String, u16, usize), SocksError> {
    if data.is_empty() {
        return Err(SocksError(REPLY_GENERAL));
    }
    match data[0] {
        ATYP_IPV4 => {
            if data.len() < 7 {
                return Err(SocksError(REPLY_GENERAL));
            }
            let host = format!("{}.{}.{}.{}", data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((host, port, 7))
        }
        ATYP_DOMAIN => {
            if data.len() < 2 {
                return Err(SocksError(REPLY_GENERAL));
            }
            let length = data[1] as usize;
            if data.len() < 2 + length + 2 {
                return Err(SocksError(REPLY_GENERAL));
            }
            let host = String::from_utf8_lossy(&data[2..2 + length]).into_owned();
            let port = u16::from_be_bytes([data[2 + length], data[2 + length + 1]]);
            Ok((host, port, 2 + length + 2))
        }
        ATYP_IPV6 => {
            if data.len() < 19 {
                return Err(SocksError(REPLY_GENERAL));
            }
            let raw = &data[1..17];
            let host = (0..16)
                .step_by(2)
                .map(|i| format!("{:02x}{:02x}", raw[i], raw[i + 1]))
                .collect::<Vec<_>>()
                .join(":");
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((host, port, 19))
        }
        _ => Err(SocksError(REPLY_ADDR_UNSUPPORTED)),
    }
}

/// Encode a reply address: an IPv4/IPv6 literal, or a domain otherwise.
fn encode_address(host: &str, port: u16) -> Vec<u8> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                let mut out = vec![ATYP_IPV4];
                out.extend_from_slice(&v4.octets());
                out.extend_from_slice(&port.to_be_bytes());
                out
            }
            IpAddr::V6(v6) => {
                let mut out = vec![ATYP_IPV6];
                out.extend_from_slice(&v6.octets());
                out.extend_from_slice(&port.to_be_bytes());
                out
            }
        }
    } else {
        let raw = host.as_bytes();
        let mut out = vec![ATYP_DOMAIN, raw.len() as u8];
        out.extend_from_slice(raw);
        out.extend_from_slice(&port.to_be_bytes());
        out
    }
}

/// A callable that sends already-encoded bytes through a circuit. Cloned
/// cheaply (it is an `Arc`) and called from whichever thread is relaying
/// at the time, so it must be `Send + Sync`.
pub type Onion = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// `(host, port, scope)`: `scope` is the connection's isolation tag from
/// SOCKS5 username/password authentication (see [`socks_auth_scope`]), or
/// `None` when the client authenticated with NO AUTHENTICATION. Two
/// requests with different scopes must never share a circuit, whatever
/// their destinations.
type OnionRouterFn = dyn Fn(&str, u16, Option<&str>) -> Result<Onion, SocksError> + Send + Sync;
/// `(host, port, scope, failed_onion, reason)` -- `scope` as for
/// [`OnionRouterFn`].
type OnionRetryFn =
    dyn Fn(&str, u16, Option<&str>, Option<Onion>, Option<&str>) -> Result<Option<Onion>, SocksError> + Send + Sync;

/// SOCKS5 authentication methods this proxy negotiates (RFC 1928 §3).
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERNAME_PASSWORD: u8 = 0x02;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
/// RFC 1929 username/password sub-negotiation version.
const USERPASS_VERSION: u8 = 0x01;

/// Turn RFC 1929 credentials into a circuit-isolation tag.
///
/// This proxy never *checks* a username or password -- any pair is
/// accepted. What the pair buys is isolation: everything an application
/// sends under one `(username, password)` rides circuits no other pair's
/// streams ever touch, whatever their destinations (Tor's
/// `IsolateSOCKSAuth`). A browser's per-container or per-tab proxy
/// credentials, or two programs given two different passwords, therefore
/// cannot be linked at the exit by sharing a circuit -- the one thing
/// `--isolate-by-destination` on its own cannot prevent for a destination
/// both of them visit.
///
/// Only a digest leaves this function: the credentials themselves are
/// never stored in a pool key, a log line, or a circuit label. Each field
/// is length-prefixed so `("ab", "c")` and `("a", "bc")` differ.
pub fn socks_auth_scope(username: &[u8], password: &[u8]) -> String {
    let mut hasher = Blake2b::<U16>::new_customized(b"allium-socksauth");
    hasher.update((username.len() as u32).to_be_bytes());
    hasher.update(username);
    hasher.update((password.len() as u32).to_be_bytes());
    hasher.update(password);
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("auth:{hex}")
}
type StreamHookFn = dyn Fn(&Onion) + Send + Sync;

/// Duck-typed hidden-service tunnel: a caller's introduction+rendezvous
/// machinery, wired in as `hidden_service_connect`'s return value.
///
/// Unlike Python's `async def send/receive` pair (which never truly run
/// concurrently, since `asyncio` is single-threaded), this trait's methods
/// take `&self` and may be called concurrently from two real OS threads
/// (see [`SocksServer`]'s module doc): an implementation is responsible for
/// its own internal synchronization.
pub trait HiddenServiceConnection: Send + Sync {
    /// Send one already-framed chunk into the tunnel.
    fn send(&self, data: &[u8]) -> io::Result<()>;
    /// Wait up to `timeout` for the next chunk. `Ok(None)` means nothing
    /// arrived in time -- *not* end of tunnel, matching Python's
    /// `receive(timeout=...)` raising `OSError` for the same case (an
    /// interactive session may sit idle between requests).
    fn receive(&self, timeout: Duration) -> io::Result<Option<Vec<u8>>>;
    /// Tear the tunnel down.
    fn close(&self);
}

type HiddenServiceConnectFn =
    dyn Fn(&str, u16) -> Result<Arc<dyn HiddenServiceConnection>, SocksError> + Send + Sync;

/// Wraps an [`Onion`] so it can be used as a `HashMap`/`HashSet` key by
/// `Arc` pointer identity (see the module doc's "Stream isolation"
/// section) rather than by comparing the closures' behavior, which Rust
/// cannot do.
#[derive(Clone)]
struct OnionKey(Onion);
impl std::fmt::Debug for OnionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OnionKey({:p})", Arc::as_ptr(&self.0))
    }
}
impl PartialEq for OnionKey {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for OnionKey {}
impl Hash for OnionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (Arc::as_ptr(&self.0) as *const () as usize).hash(state);
    }
}

type StreamKey = (OnionKey, u32);

/// Client-side state for one live SOCKS5 UDP ASSOCIATE session.
///
/// One of these exists per successful UDP ASSOCIATE command, for the
/// lifetime of the TCP control connection that requested it (RFC 1928 §7).
/// It owns its own relay socket, its own id namespace (`association_id`,
/// unrelated to any `stream_id`), and its own byte counters.
pub struct UdpAssociation {
    pub association_id: u32,
    pub control_peer: Option<SocketAddr>,
    pub socket: UdpSocket,
    /// The control connection's isolation tag (see [`socks_auth_scope`]),
    /// applied to every datagram it relays.
    scope: Option<Arc<str>>,
    client_udp_addr: Mutex<Option<SocketAddr>>,
    created_at: Instant,
    last_activity: Mutex<Instant>,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    closed: AtomicBool,
}

impl UdpAssociation {
    fn new(association_id: u32, control_peer: Option<SocketAddr>, socket: UdpSocket, scope: Option<Arc<str>>) -> Self {
        let now = Instant::now();
        UdpAssociation {
            association_id,
            control_peer,
            socket,
            scope,
            client_udp_addr: Mutex::new(None),
            created_at: now,
            last_activity: Mutex::new(now),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        }
    }

    pub fn client_udp_addr(&self) -> Option<SocketAddr> {
        *self.client_udp_addr.lock().unwrap()
    }

    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    pub fn last_activity(&self) -> Instant {
        *self.last_activity.lock().unwrap()
    }

    fn touch(&self) {
        *self.last_activity.lock().unwrap() = Instant::now();
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

/// Constructor options for [`SocksServer`], mirroring Python's keyword
/// arguments (Rust has no keyword arguments, so this is a builder-style
/// struct: start from [`Default::default`] and set only what you need).
pub struct SocksServerOptions {
    pub host: String,
    pub port: u16,
    /// Answer UDP ASSOCIATE with a real relay bootstrap instead of an
    /// error. Off by default: a UDP relay is an egress-capable facility.
    pub allow_udp: bool,
    pub mtu: usize,
    /// A separate callable for datagrams, so a caller whose transport
    /// distinguishes "send one stream cell" from "send one whole datagram
    /// frame" can wire each to its own method. Used as the fallback when
    /// `onion_datagram_router` is `None` (e.g. in tests with a single
    /// fixed circuit); defaults to the primary `onion` when this is also
    /// `None`.
    pub onion_datagram: Option<Onion>,
    /// Per-destination routing for UDP ASSOCIATE datagrams, mirroring
    /// `onion_router` below but resolved fresh for *every* datagram (each
    /// SOCKS5 UDP packet carries its own destination, unlike a stream's
    /// single CONNECT). When set, `on_client_datagram` calls this with
    /// the datagram's own `(host, port)` instead of using the fixed
    /// `onion_datagram` callable.
    ///
    /// Without this, every UDP ASSOCIATE datagram rode whichever single
    /// circuit `onion_datagram` was constructed
    /// with -- bypassing `--isolate-by-destination` and the pool's
    /// age-based rotation entirely, for the whole process lifetime. See
    /// `CircuitPool::datagram_onion_for`.
    pub onion_datagram_router: Option<Arc<OnionRouterFn>>,
    /// Routes a `.allium` CONNECT target to a caller's hidden-service
    /// introduction+rendezvous machinery instead of the ordinary exit path.
    pub hidden_service_connect: Option<Arc<HiddenServiceConnectFn>>,
    /// Stream isolation: consulted once per new CONNECT/RESOLVE, in place
    /// of the single shared `onion`, so different destinations (or
    /// applications) can ride different circuits.
    pub onion_router: Option<Arc<OnionRouterFn>>,
    /// Automatic retry on a new circuit: `(host, port, failed_onion,
    /// reason) -> Ok(Some(fresh_onion))` to retry, `Ok(None)` to give up.
    /// `reason` is `"exit-policy"` when the exit refused the port, else
    /// `"timeout"`, `"circuit"` or `"exit-error"`.
    pub onion_retry: Option<Arc<OnionRetryFn>>,
    /// Lifecycle hooks so whoever supplied `onion_router` (a circuit pool,
    /// in practice) knows when a stream handed one of its circuits
    /// actually starts/stops using it.
    pub onion_stream_started: Option<Arc<StreamHookFn>>,
    pub onion_stream_finished: Option<Arc<StreamHookFn>>,
    pub max_connect_attempts: u32,
    pub connect_timeout: Duration,
    pub retry_connect_timeout: Option<Duration>,
}

impl Default for SocksServerOptions {
    fn default() -> Self {
        SocksServerOptions {
            host: "127.0.0.1".to_string(),
            port: DEFAULT_SOCKS_PORT,
            allow_udp: false,
            mtu: DEFAULT_MTU,
            onion_datagram: None,
            onion_datagram_router: None,
            hidden_service_connect: None,
            onion_router: None,
            onion_retry: None,
            onion_stream_started: None,
            onion_stream_finished: None,
            max_connect_attempts: DEFAULT_MAX_CONNECT_ATTEMPTS,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            retry_connect_timeout: None,
        }
    }
}

/// A local SOCKS5 -> Allium proxy (see module docs).
///
/// Always held behind an `Arc` ([`SocksServer::new`] returns one): several
/// of its methods spawn threads that need their own handle back into the
/// server (a UDP relay's reader thread, an accept loop's per-connection
/// threads).
pub struct SocksServer {
    onion: Onion,
    onion_datagram: Onion,
    onion_datagram_router: Option<Arc<OnionRouterFn>>,
    hidden_service_connect: Option<Arc<HiddenServiceConnectFn>>,
    onion_router: Option<Arc<OnionRouterFn>>,
    onion_retry: Option<Arc<OnionRetryFn>>,
    onion_stream_started: Arc<StreamHookFn>,
    onion_stream_finished: Arc<StreamHookFn>,
    host: String,
    port: u16,
    allow_udp: bool,
    mtu: usize,
    max_connect_attempts: u32,
    connect_timeout: Duration,
    retry_connect_timeout: Duration,

    retries_attempted: AtomicU64,
    retries_succeeded: AtomicU64,

    /// The onion `onion_router` resolved for a request still awaiting its
    /// reply, keyed by request_id.
    request_onion: Mutex<HashMap<u32, Onion>>,
    /// The circuit every in-flight request_id was actually sent on --
    /// unlike `request_onion` (only populated when stream isolation
    /// resolved a specific circuit), this is filled for *every* pending
    /// request so `deliver_reply` can reject a reply that arrives on the
    /// wrong circuit. Without this, a hostile exit that can predict or
    /// observe another circuit's request_id could spoof a reply into it.
    expected_circuit: Mutex<HashMap<u32, Onion>>,
    /// CONNECT/RESOLVE requests in flight, keyed by request_id -> a
    /// one-shot channel `deliver_reply` completes.
    pending: Mutex<HashMap<u32, std::sync::mpsc::Sender<StreamReply>>>,

    udp_associations: Mutex<HashMap<u32, Arc<UdpAssociation>>>,

    reassemblers: Mutex<HashMap<StreamKey, Reassembler>>,
    writers: Mutex<HashMap<StreamKey, TcpStream>>,
    pending_write: Mutex<HashMap<StreamKey, Vec<u8>>>,
    closed_streams: Mutex<HashSet<StreamKey>>,
    client_gone: Mutex<HashSet<StreamKey>>,
}

impl SocksServer {
    /// Build a new server. Does not bind a socket yet -- see [`Self::spawn`].
    ///
    /// # Errors
    /// Returns [`ConfigError`] if `options.max_connect_attempts < 1`.
    pub fn new(onion: Onion, options: SocksServerOptions) -> Result<Arc<Self>, ConfigError> {
        if options.max_connect_attempts < 1 {
            return Err(ConfigError("max_connect_attempts must be at least 1".to_string()));
        }
        let onion_datagram = options.onion_datagram.unwrap_or_else(|| onion.clone());
        // Without a retry hook, retrying would just hit the same circuit
        // again, so no retry is attempted at all -- exactly pre-feature
        // behavior.
        let max_connect_attempts =
            if options.onion_retry.is_some() { options.max_connect_attempts } else { 1 };
        let retry_connect_timeout = options.retry_connect_timeout.unwrap_or(options.connect_timeout);
        Ok(Arc::new(SocksServer {
            onion,
            onion_datagram,
            onion_datagram_router: options.onion_datagram_router,
            hidden_service_connect: options.hidden_service_connect,
            onion_router: options.onion_router,
            onion_retry: options.onion_retry,
            onion_stream_started: options.onion_stream_started.unwrap_or_else(|| Arc::new(|_: &Onion| {})),
            onion_stream_finished: options.onion_stream_finished.unwrap_or_else(|| Arc::new(|_: &Onion| {})),
            host: options.host,
            port: options.port,
            allow_udp: options.allow_udp,
            mtu: options.mtu.max(1),
            max_connect_attempts,
            connect_timeout: options.connect_timeout,
            retry_connect_timeout,
            retries_attempted: AtomicU64::new(0),
            retries_succeeded: AtomicU64::new(0),
            request_onion: Mutex::new(HashMap::new()),
            expected_circuit: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            udp_associations: Mutex::new(HashMap::new()),
            reassemblers: Mutex::new(HashMap::new()),
            writers: Mutex::new(HashMap::new()),
            pending_write: Mutex::new(HashMap::new()),
            closed_streams: Mutex::new(HashSet::new()),
            client_gone: Mutex::new(HashSet::new()),
        }))
    }

    pub fn address(&self) -> (String, u16) {
        (self.host.clone(), self.port)
    }

    /// How many CONNECT/RESOLVE requests needed a retry (diagnostics/tests).
    pub fn retries_attempted(&self) -> u64 {
        self.retries_attempted.load(Ordering::Relaxed)
    }

    /// How many of those retries then succeeded (diagnostics/tests).
    pub fn retries_succeeded(&self) -> u64 {
        self.retries_succeeded.load(Ordering::Relaxed)
    }

    /// Drawn from a CSPRNG, not a counter: the id is visible to (and can be
    /// legitimately used in a reply by) any exit relay serving a request on
    /// this proxy, and a small sequential value would let a hostile exit
    /// predict a request_id concurrently in flight on another, unrelated
    /// circuit and forge a reply into it. `deliver_reply` additionally
    /// binds each reply to the circuit its request_id was actually sent
    /// on, so this is defense in depth against prediction, not the only
    /// guard.
    fn alloc_request_id(&self) -> u32 {
        let bytes = crate::osrand::bytes(4);
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    /// Drawn from a CSPRNG, not a counter: the id is carried in the clear
    /// in every datagram frame, and a small sequential value would let
    /// anyone on this proxy guess a live association id and inject into
    /// (or hijack replies from) a session they should not be able to
    /// address. 32-bit, matching the wire format's `u32` field.
    fn alloc_association_id(&self) -> u32 {
        let bytes = crate::osrand::bytes(4);
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn write_reply(&self, stream: &mut TcpStream, code: u8, host: &str, port: u16) -> Result<(), SocksError> {
        let mut out = vec![SOCKS_VERSION, code, 0x00];
        out.extend_from_slice(&encode_address(host, port));
        stream.write_all(&out).map_err(|_| SocksError(REPLY_GENERAL))
    }

    // -- deliver a reply coming back from the circuit ----------------------

    /// Feed a CONNECTED/RESOLVED reply (from the circuit) back into pending
    /// stream setup. Called by whoever owns the circuit socket.
    ///
    /// `circuit_key` identifies which circuit this reply actually arrived
    /// on (`None` defaults to the primary circuit, matching
    /// `close_stream`/`write_to_stream`/`deliver_data`'s convention). A
    /// reply is only ever allowed to complete the request_id it names if it
    /// arrived on the same circuit that request_id was sent on -- otherwise
    /// it is dropped. Without this, a request_id alone would be enough for
    /// any exit relay serving *some* circuit on this proxy to complete (or
    /// spoof) a reply for a completely different, unrelated circuit.
    pub fn deliver_reply(&self, payload: &[u8], circuit_key: Option<&Onion>) {
        let reply = match decode_reply(payload) {
            Ok(r) => r,
            Err(_) => return,
        };
        if let Some(expected) = self.expected_circuit.lock().unwrap().get(&reply.request_id) {
            let actual = circuit_key.unwrap_or(&self.onion);
            if !Arc::ptr_eq(expected, actual) {
                return;
            }
        }
        if let Some(tx) = self.pending.lock().unwrap().remove(&reply.request_id) {
            let _ = tx.send(reply);
        }
    }

    // -- accepting connections ----------------------------------------------

    /// Bind and start accepting SOCKS5 connections in a background thread.
    ///
    /// Each accepted connection is handled on its own thread (this crate's
    /// blocking-I/O translation of Python's `asyncio.start_server`). Drop
    /// or call [`SocksServerHandle::stop`] on the returned handle to stop
    /// accepting and join the accept thread.
    pub fn spawn(self: Arc<Self>) -> io::Result<SocksServerHandle> {
        let listener = TcpListener::bind((self.host.as_str(), self.port))?;
        listener.set_nonblocking(true)?;
        let local_addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = stop.clone();
        let server = self;
        let accept_thread = thread::spawn(move || {
            loop {
                if stop_for_thread.load(Ordering::SeqCst) {
                    break;
                }
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        let _ = stream.set_nodelay(true);
                        let server = server.clone();
                        thread::spawn(move || server.handle_client(stream));
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => thread::sleep(Duration::from_millis(20)),
                }
            }
        });
        Ok(SocksServerHandle { local_addr, stop, accept_thread: Some(accept_thread) })
    }

    fn handle_client(self: &Arc<Self>, stream: TcpStream) {
        let mut reply_stream = match stream.try_clone() {
            Ok(s) => s,
            Err(_) => return,
        };
        if let Err(err) = self.negotiate_and_connect(stream) {
            let _ = self.write_reply(&mut reply_stream, err.0, "0.0.0.0", 0);
            let _ = reply_stream.shutdown(std::net::Shutdown::Both);
        }
    }

    fn negotiate_and_connect(self: &Arc<Self>, mut stream: TcpStream) -> Result<(), SocksError> {
        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting).map_err(|_| SocksError(REPLY_GENERAL))?;
        let (version, nmethods) = (greeting[0], greeting[1]);
        if version != SOCKS_VERSION {
            return Err(SocksError(REPLY_GENERAL));
        }
        let mut methods = vec![0u8; nmethods as usize];
        stream.read_exact(&mut methods).map_err(|_| SocksError(REPLY_GENERAL))?;
        // Username/password is preferred over "no authentication" whenever
        // the client offers it, because it is what carries an isolation
        // scope (see `socks_auth_scope`); a client that offers both is one
        // that has credentials it wants used.
        let scope: Option<Arc<str>> = if methods.contains(&METHOD_USERNAME_PASSWORD) {
            stream.write_all(&[SOCKS_VERSION, METHOD_USERNAME_PASSWORD]).map_err(|_| SocksError(REPLY_GENERAL))?;
            Some(self.negotiate_userpass(&mut stream)?)
        } else if methods.contains(&METHOD_NO_AUTH) {
            stream.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).map_err(|_| SocksError(REPLY_GENERAL))?;
            None
        } else {
            let _ = stream.write_all(&[SOCKS_VERSION, METHOD_NONE_ACCEPTABLE]);
            return Err(SocksError(REPLY_GENERAL));
        };

        let mut head = [0u8; 4];
        stream.read_exact(&mut head).map_err(|_| SocksError(REPLY_GENERAL))?;
        let (version, cmd, _rsv, atyp) = (head[0], head[1], head[2], head[3]);
        if version != SOCKS_VERSION {
            return Err(SocksError(REPLY_GENERAL));
        }

        let addr_payload = self.read_address_body(&mut stream, atyp)?;
        let mut full = Vec::with_capacity(1 + addr_payload.len());
        full.push(atyp);
        full.extend_from_slice(&addr_payload);
        let (host, port, _consumed) = parse_address(&full)?;

        match cmd {
            CMD_CONNECT => self.do_connect(stream, host, port, scope),
            CMD_RESOLVE => self.do_resolve(stream, host, scope),
            CMD_UDP_ASSOCIATE => self.do_udp_associate(stream, host, port, scope),
            _ => Err(SocksError(REPLY_CMD_UNSUPPORTED)),
        }
    }

    /// RFC 1929 sub-negotiation: read `ver ulen uname plen passwd`, accept
    /// any credentials, and return their isolation scope. A malformed
    /// exchange is answered with a failure status, after which the client
    /// is expected to close (RFC 1929 §2).
    fn negotiate_userpass(&self, stream: &mut TcpStream) -> Result<Arc<str>, SocksError> {
        let fail = |stream: &mut TcpStream| {
            let _ = stream.write_all(&[USERPASS_VERSION, 0x01]);
            SocksError(REPLY_GENERAL)
        };
        let mut head = [0u8; 2];
        if stream.read_exact(&mut head).is_err() || head[0] != USERPASS_VERSION {
            return Err(fail(stream));
        }
        let mut username = vec![0u8; head[1] as usize];
        let mut plen = [0u8; 1];
        if stream.read_exact(&mut username).is_err() || stream.read_exact(&mut plen).is_err() {
            return Err(fail(stream));
        }
        let mut password = vec![0u8; plen[0] as usize];
        if stream.read_exact(&mut password).is_err() {
            return Err(fail(stream));
        }
        stream.write_all(&[USERPASS_VERSION, 0x00]).map_err(|_| SocksError(REPLY_GENERAL))?;
        Ok(Arc::from(socks_auth_scope(&username, &password)))
    }

    fn read_address_body(&self, stream: &mut TcpStream, atyp: u8) -> Result<Vec<u8>, SocksError> {
        match atyp {
            ATYP_IPV4 => {
                let mut b = [0u8; 6];
                stream.read_exact(&mut b).map_err(|_| SocksError(REPLY_GENERAL))?;
                Ok(b.to_vec())
            }
            ATYP_IPV6 => {
                let mut b = [0u8; 18];
                stream.read_exact(&mut b).map_err(|_| SocksError(REPLY_GENERAL))?;
                Ok(b.to_vec())
            }
            ATYP_DOMAIN => {
                let mut lenb = [0u8; 1];
                stream.read_exact(&mut lenb).map_err(|_| SocksError(REPLY_GENERAL))?;
                let mut rest = vec![0u8; lenb[0] as usize + 2];
                stream.read_exact(&mut rest).map_err(|_| SocksError(REPLY_GENERAL))?;
                let mut out = vec![lenb[0]];
                out.extend_from_slice(&rest);
                Ok(out)
            }
            _ => Err(SocksError(REPLY_ADDR_UNSUPPORTED)),
        }
    }

    // -- command handlers -----------------------------------------------

    fn forward_request(&self, request: &StreamRequest) -> Result<(), SocksError> {
        let onion = self
            .request_onion
            .lock()
            .unwrap()
            .get(&request.request_id)
            .cloned()
            .unwrap_or_else(|| self.onion.clone());
        let encoded = encode_request(request).map_err(|_| SocksError(REPLY_GENERAL))?;
        onion(&encoded);
        Ok(())
    }

    /// Send the request and block until its reply arrives (or fail).
    ///
    /// When this server has `onion_router`, it is resolved *before* the
    /// request goes out, so the first cell of a new stream already rides
    /// whichever circuit was chosen for it.
    ///
    /// `onion`: an already-resolved onion to send this request through,
    /// bypassing `onion_router` -- used by the retry path, which has
    /// already asked `onion_retry` for a fresh circuit.
    ///
    /// Returns `(reply, onion)` -- `onion` is the resolved onion for a
    /// request that used `onion_router` or an explicit `onion`, `None` in
    /// the plain single-circuit case.
    fn await_reply(
        &self,
        request: StreamRequest,
        onion: Option<Onion>,
        timeout: Duration,
        scope: Option<&str>,
    ) -> Result<(StreamReply, Option<Onion>), SocksError> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.pending.lock().unwrap().insert(request.request_id, tx);

        if let Some(o) = onion {
            self.request_onion.lock().unwrap().insert(request.request_id, o);
        } else if let Some(router) = &self.onion_router {
            match router(&request.host, request.port, scope) {
                Ok(o) => {
                    self.request_onion.lock().unwrap().insert(request.request_id, o);
                }
                Err(e) => {
                    self.pending.lock().unwrap().remove(&request.request_id);
                    return Err(e);
                }
            }
        }

        // Record which circuit this request_id is actually going out on --
        // independent of `request_onion` above (which stays `None`/absent
        // in the plain single-circuit case) -- so `deliver_reply` can
        // reject a reply arriving on any other circuit for as long as this
        // request_id is pending. See H-2.
        let bound_circuit =
            self.request_onion.lock().unwrap().get(&request.request_id).cloned().unwrap_or_else(|| self.onion.clone());
        self.expected_circuit.lock().unwrap().insert(request.request_id, bound_circuit);

        // Hold the circuit for the send-and-wait below: without this, the
        // pool this onion came from could evict and close it between
        // forward_request and the reply arriving, and onion() would raise
        // into a thread with nobody catching an OS-level "bad descriptor".
        let held = self.request_onion.lock().unwrap().get(&request.request_id).cloned();
        if let Some(h) = &held {
            (self.onion_stream_started)(h);
        }

        let result = (|| -> Result<StreamReply, SocksError> {
            self.forward_request(&request)?;
            match rx.recv_timeout(timeout) {
                Ok(reply) => Ok(reply),
                Err(_) => {
                    self.pending.lock().unwrap().remove(&request.request_id);
                    Err(SocksError(REPLY_TTL_EXPIRED))
                }
            }
        })();

        let resolved_onion = self.request_onion.lock().unwrap().remove(&request.request_id);
        self.expected_circuit.lock().unwrap().remove(&request.request_id);
        if let Some(h) = &held {
            (self.onion_stream_finished)(h);
        }
        result.map(|reply| (reply, resolved_onion))
    }

    /// Best-effort "which circuit did that timed-out attempt use?". A
    /// failed attempt through `onion_router` can't hand its circuit back
    /// (`await_reply` always pops it), so `None` tells `onion_retry` "the
    /// circuit currently assigned to this destination".
    fn current_onion_guess(&self) -> Option<Onion> {
        if self.onion_router.is_some() {
            None
        } else {
            Some(self.onion.clone())
        }
    }

    /// Issue a CONNECT/RESOLVE, retrying on a fresh circuit on failure.
    ///
    /// Only the *setup* phase is retried: until the reply arrives nothing
    /// has been written back to the SOCKS client, so moving to another
    /// circuit is invisible to the application.
    fn request_with_retry(
        &self,
        kind: u8,
        host: &str,
        port: u16,
        scope: Option<&str>,
    ) -> Result<(StreamReply, Option<Onion>), SocksError> {
        let mut failed_onion: Option<Onion> = None;
        let mut reason: Option<&'static str> = None;
        let mut last_code = REPLY_GENERAL;

        for attempt in 0..self.max_connect_attempts {
            let mut onion_override = None;
            if attempt > 0 {
                self.retries_attempted.fetch_add(1, Ordering::Relaxed);
                let retry_fn = self.onion_retry.as_ref().expect(
                    "max_connect_attempts is forced to 1 when onion_retry is None",
                );
                match retry_fn(host, port, scope, failed_onion.clone(), reason) {
                    Ok(Some(o)) => onion_override = Some(o),
                    Ok(None) => break,
                    Err(e) => {
                        last_code = e.0;
                        continue;
                    }
                }
            }
            let request_id = self.alloc_request_id();
            let timeout = if attempt == 0 { self.connect_timeout } else { self.retry_connect_timeout };
            let request = StreamRequest::new(kind, request_id, host, port);
            match self.await_reply(request, onion_override.clone(), timeout, scope) {
                Ok((reply, used_onion)) => {
                    let ok = reply.status == SUCCESS && (kind != RESOLVE || reply.address.is_some());
                    if ok {
                        if attempt > 0 {
                            self.retries_succeeded.fetch_add(1, Ordering::Relaxed);
                        }
                        return Ok((reply, used_onion));
                    }
                    last_code = status_to_socks(reply.status);
                    if !is_retryable(reply.status) {
                        return Err(SocksError(last_code));
                    }
                    failed_onion = Some(used_onion.unwrap_or_else(|| self.onion.clone()));
                    // COMMAND_UNSUPPORTED from an exit on CONNECT is its
                    // exit-policy refusal: a property of (exit, port), not
                    // the circuit.
                    reason = Some(
                        if reply.status == COMMAND_UNSUPPORTED && kind == CONNECT {
                            "exit-policy"
                        } else {
                            "exit-error"
                        },
                    );
                }
                Err(e) => {
                    last_code = e.0;
                    if last_code != REPLY_TTL_EXPIRED && last_code != REPLY_GENERAL {
                        return Err(e);
                    }
                    failed_onion = onion_override.clone().or_else(|| self.current_onion_guess());
                    reason = Some(if last_code == REPLY_TTL_EXPIRED { "timeout" } else { "circuit" });
                }
            }
        }
        Err(SocksError(last_code))
    }

    fn do_connect(self: &Arc<Self>, mut stream: TcpStream, host: String, port: u16, scope: Option<Arc<str>>) -> Result<(), SocksError> {
        if host.to_ascii_lowercase().ends_with(".allium") {
            return self.do_connect_hidden_service(stream, host, port);
        }
        let (reply, onion) = self.request_with_retry(CONNECT, &host, port, scope.as_deref())?;
        // `circuit_key` doubles as this stream's isolation key below, not
        // just its send callable.
        let circuit_key = onion.unwrap_or_else(|| self.onion.clone());
        // Claim the circuit before the reply write below, so there is no
        // instant where the circuit looks unused and can be evicted.
        (self.onion_stream_started)(&circuit_key);
        let result = (|| -> Result<(), SocksError> {
            self.write_reply(&mut stream, REPLY_SUCCEEDED, "0.0.0.0", 0)?;
            self.relay_stream(reply.stream_id, stream, circuit_key.clone())
        })();
        (self.onion_stream_finished)(&circuit_key);
        result
    }

    /// CONNECT to a `.allium` address: the hidden-service path. Never
    /// touches `onion`/`await_reply`/`relay_stream` -- a hidden-service
    /// session is a separate pair of circuits the caller's
    /// `hidden_service_connect` hook builds, not a stream request sent
    /// down whatever circuit `onion` already talks to. `port` is accepted
    /// (SOCKS5 requires one) but unused, since Allium has one address per
    /// hidden service rather than Tor's per-virtual-port routing.
    fn do_connect_hidden_service(
        &self,
        mut stream: TcpStream,
        host: String,
        port: u16,
    ) -> Result<(), SocksError> {
        let hook = self.hidden_service_connect.as_ref().ok_or(SocksError(REPLY_HOST_UNREACHABLE))?;
        let connection = hook(&host, port)?;
        self.write_reply(&mut stream, REPLY_SUCCEEDED, "0.0.0.0", 0)?;
        self.relay_hidden_service(connection, stream)
    }

    /// Bridge a SOCKS client's raw TCP bytes with a hidden-service tunnel.
    ///
    /// No stream id, fragmentation, or `onion` callback here (unlike
    /// [`Self::relay_stream`]) -- `connection` is already a self-contained
    /// duplex channel, so this just pumps bytes both ways on two threads
    /// until either side finishes, then tears both down.
    fn relay_hidden_service(
        &self,
        connection: Arc<dyn HiddenServiceConnection>,
        stream: TcpStream,
    ) -> Result<(), SocksError> {
        let stop = Arc::new(AtomicBool::new(false));

        let mut reader = stream.try_clone().map_err(|_| SocksError(REPLY_GENERAL))?;
        reader.set_read_timeout(Some(Duration::from_millis(500))).ok();
        let mut writer = stream.try_clone().map_err(|_| SocksError(REPLY_GENERAL))?;

        let stop1 = stop.clone();
        let conn1 = connection.clone();
        let client_to_service = thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            loop {
                if stop1.load(Ordering::SeqCst) {
                    break;
                }
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if conn1.send(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(ref e)
                        if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
                    {
                        continue
                    }
                    Err(_) => break,
                }
            }
            stop1.store(true, Ordering::SeqCst);
        });

        let stop2 = stop.clone();
        let conn2 = connection.clone();
        let service_to_client = thread::spawn(move || {
            loop {
                if stop2.load(Ordering::SeqCst) {
                    break;
                }
                match conn2.receive(Duration::from_secs(2)) {
                    Ok(Some(data)) if !data.is_empty() => {
                        if writer.write_all(&data).is_err() {
                            break;
                        }
                    }
                    Ok(_) => continue, // timeout, or an empty read: keep polling
                    // The peer closed cleanly (`UnexpectedEof`), or the session's
                    // integrity is gone -- a frame was lost or reordered
                    // (`InvalidData`). Continuing would hang or corrupt the stream.
                    Err(e) if matches!(e.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::InvalidData) => break,
                    Err(_) => continue, // decode/crypto hiccup: not the end of the session
                }
            }
            stop2.store(true, Ordering::SeqCst);
        });

        let _ = client_to_service.join();
        let _ = service_to_client.join();
        connection.close();
        let _ = stream.shutdown(std::net::Shutdown::Both);
        Ok(())
    }

    fn do_resolve(&self, mut stream: TcpStream, host: String, scope: Option<Arc<str>>) -> Result<(), SocksError> {
        let (reply, _onion) = self.request_with_retry(RESOLVE, &host, 0, scope.as_deref())?;
        let (addr_host, addr_port) = reply.address.unwrap_or(("0.0.0.0".to_string(), 0));
        self.write_reply(&mut stream, REPLY_SUCCEEDED, &addr_host, addr_port)?;
        // A RESOLVE is request/response: nothing follows, so close cleanly.
        let _ = stream.shutdown(std::net::Shutdown::Both);
        Ok(())
    }

    /// Bind a UDP relay socket and answer with its address (RFC 1928 §7).
    ///
    /// The client then sends UDP datagrams to the returned address; each
    /// one is encapsulated as a single, whole `DatagramRequest` cell (v1
    /// has no SOCKS5 UDP fragmentation) and injected via a dedicated
    /// datagram send -- **never** through the stream-fragment path. The
    /// TCP control connection stays open for the association's lifetime
    /// (RFC 1928 §7: it terminates when this connection does).
    fn do_udp_associate(self: &Arc<Self>, mut stream: TcpStream, _host: String, _port: u16, scope: Option<Arc<str>>) -> Result<(), SocksError> {
        if !self.allow_udp {
            return Err(SocksError(REPLY_CMD_UNSUPPORTED));
        }
        let relay_socket = UdpSocket::bind((self.host.as_str(), 0)).map_err(|_| SocksError(REPLY_GENERAL))?;
        let recv_clone = relay_socket.try_clone().map_err(|_| SocksError(REPLY_GENERAL))?;
        recv_clone.set_read_timeout(Some(Duration::from_millis(500))).ok();

        let association_id = self.alloc_association_id();
        let peer = stream.peer_addr().ok();
        let association = Arc::new(UdpAssociation::new(association_id, peer, relay_socket, scope));
        self.udp_associations.lock().unwrap().insert(association_id, association.clone());

        let bind_addr = association.socket.local_addr().map_err(|_| SocksError(REPLY_GENERAL))?;
        self.write_reply(&mut stream, REPLY_SUCCEEDED, &bind_addr.ip().to_string(), bind_addr.port())?;

        let server = self.clone();
        let assoc_for_thread = association.clone();
        let relay_thread = thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            loop {
                if assoc_for_thread.is_closed() {
                    break;
                }
                match recv_clone.recv_from(&mut buf) {
                    Ok((n, addr)) => server.on_client_datagram(association_id, &buf[..n], addr),
                    Err(ref e)
                        if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
                    {
                        continue
                    }
                    Err(_) => break,
                }
            }
        });

        // Block until the control connection closes.
        let mut sink = [0u8; 4096];
        loop {
            match stream.read(&mut sink) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        association.close();
        self.udp_associations.lock().unwrap().remove(&association_id);
        let _ = relay_thread.join();
        Ok(())
    }

    // -- UDP ASSOCIATE relay ------------------------------------------------

    /// Encapsulate a SOCKS-client UDP datagram and inject it into the
    /// circuit.
    ///
    /// v1 scope: a datagram is sent as one *whole* onion cell, never
    /// fragmented or reassembled. Anything this cannot carry that way is
    /// dropped, not queued or split: a fragmented SOCKS5 UDP datagram
    /// (`FRAG != 0`), a non-IPv4 `ATYP`, a payload too large for one cell,
    /// or a datagram for an unknown/closed association.
    ///
    /// The source-address check pins `client_udp_addr` on first use (so no
    /// later packet, from anywhere, can redirect this association's
    /// replies) and, once pinned or if `control_peer` is known, requires
    /// the source IP to match -- port intentionally excluded, since RFC
    /// 1928 §7 allows the client's UDP source port to differ from its TCP
    /// control connection's.
    fn on_client_datagram(&self, association_id: u32, data: &[u8], addr: SocketAddr) {
        let association = match self.udp_associations.lock().unwrap().get(&association_id).cloned() {
            Some(a) => a,
            None => return,
        };
        if association.is_closed() {
            return;
        }
        {
            let client_addr = association.client_udp_addr.lock().unwrap();
            if let Some(pinned) = *client_addr {
                if addr.ip() != pinned.ip() {
                    return; // does not match the pinned client
                }
            } else if let Some(peer) = association.control_peer {
                if addr.ip() != peer.ip() {
                    return; // first packet claiming this association is off-host
                }
            }
        }
        if data.len() < 4 || data[0] != 0 || data[1] != 0 {
            return; // not a valid SOCKS5 UDP request
        }
        if data[2] != 0 {
            return; // fragmented SOCKS5 UDP datagrams are not supported (v1)
        }
        if data[3] != ATYP_IPV4 {
            return; // v1 datagram framing is IPv4-only
        }
        let (host, port, consumed) = match parse_address(&data[3..]) {
            Ok(v) => v,
            Err(_) => return,
        };
        let payload = &data[3 + consumed..];
        if payload.len() as i64 > socks::max_datagram_request_payload() {
            return; // too large for one cell; v1 has no datagram fragmentation
        }
        {
            let mut client_addr = association.client_udp_addr.lock().unwrap();
            if client_addr.is_none() {
                *client_addr = Some(addr);
            }
        }
        association.touch();
        association.bytes_sent.fetch_add(payload.len() as u64, Ordering::Relaxed);
        // Route each datagram to the circuit for *its own* destination,
        // same as a stream's CONNECT, instead of
        // a single fixed `onion_datagram` shared by the whole process --
        // see `onion_datagram_router`'s doc. Resolved fresh per datagram
        // (not cached on the association) because a later packet on the
        // same association can name a different destination, and because
        // the pool's own rotation/eviction means "the circuit for this
        // host" can change between two packets anyway.
        let onion = if let Some(router) = &self.onion_datagram_router {
            match router(&host, port, association.scope.as_deref()) {
                Ok(o) => o,
                Err(_) => return, // no circuit available for this destination right now; drop
            }
        } else {
            self.onion_datagram.clone()
        };
        let request = DatagramRequest {
            association_id,
            host,
            port,
            payload: payload.to_vec(),
            bytes_sent: payload.len() as u32,
        };
        if let Ok(encoded) = encode_datagram_request(&request) {
            (onion)(&encoded);
        }
    }

    /// Feed a `DatagramReply` (from the circuit) back to its SOCKS client,
    /// rebuilding the SOCKS5 UDP response header. Returns `true` if the
    /// reply was written to the client's UDP socket.
    pub fn deliver_datagram_reply(&self, payload: &[u8]) -> bool {
        let reply = match socks::decode_datagram_reply(payload) {
            Ok(r) => r,
            Err(_) => return false,
        };
        let association = match self.udp_associations.lock().unwrap().get(&reply.association_id).cloned() {
            Some(a) => a,
            None => return false,
        };
        if association.is_closed() {
            return false;
        }
        let client_addr = match association.client_udp_addr() {
            Some(a) => a,
            None => return false, // never heard from this client; nowhere to reply
        };
        let ip: std::net::Ipv4Addr = match reply.host.parse() {
            Ok(ip) => ip,
            Err(_) => return false,
        };
        let mut datagram = vec![0, 0, 0, ATYP_IPV4];
        datagram.extend_from_slice(&ip.octets());
        datagram.extend_from_slice(&reply.port.to_be_bytes());
        datagram.extend_from_slice(&reply.payload);
        association.bytes_received.fetch_add(reply.payload.len() as u64, Ordering::Relaxed);
        association.touch();
        association.socket.send_to(&datagram, client_addr).is_ok()
    }

    // -- established CONNECT stream relay -----------------------------------

    /// Relay an established CONNECT stream in both directions.
    ///
    /// Outbound bytes are fragmented across cells (mirroring the offset
    /// bookkeeping `Fragmenter` cannot do on its own here, since it always
    /// numbers a call from offset 0: a long-lived connection's data
    /// arrives from several separate reads, and each must be numbered
    /// against the *whole* stream, not restart at zero). Return bytes
    /// arrive via [`Self::write_to_stream`]/[`Self::deliver_data`], called
    /// by whoever owns the circuit socket.
    fn relay_stream(&self, stream_id: u32, mut reader: TcpStream, onion: Onion) -> Result<(), SocksError> {
        let key: StreamKey = (OnionKey(onion.clone()), stream_id);
        let writer_clone = reader.try_clone().map_err(|_| SocksError(REPLY_GENERAL))?;
        // A write timeout, not just releasing `self.writers` around the
        // write (see `write_to_stream`'s doc comment): without one, a
        // client that stops reading still blocks whichever caller is
        // writing to it for as long as the kernel's send buffer stays
        // full, which is however long the client cares to leave its
        // socket open.
        writer_clone.set_write_timeout(Some(WRITE_TIMEOUT)).ok();
        self.writers.lock().unwrap().insert(key.clone(), writer_clone);
        self.flush_pending(&onion, stream_id);
        if self.closed_streams.lock().unwrap().remove(&key) {
            // The exit already finished this stream; do not start a relay loop.
            if let Some(w) = self.writers.lock().unwrap().remove(&key) {
                let _ = w.shutdown(std::net::Shutdown::Both);
            }
            return Ok(());
        }

        let mut offset: u32 = 0;
        (self.onion_stream_started)(&onion);
        reader.set_read_timeout(Some(Duration::from_millis(250))).ok();
        let mut buf = vec![0u8; 4096];
        loop {
            if self.closed_streams.lock().unwrap().contains(&key) {
                break;
            }
            match reader.read(&mut buf) {
                Ok(0) => break, // the client stopped sending
                Ok(n) => {
                    let mut remaining = &buf[..n];
                    let mut sent_in_burst: u32 = 0;
                    while !remaining.is_empty() {
                        let take = remaining.len().min(self.mtu);
                        let (chunk, rest) = remaining.split_at(take);
                        let frag = Fragment { stream_id, offset, fin: false, data: chunk.to_vec() };
                        onion(&encode_fragment(&frag));
                        offset += chunk.len() as u32;
                        remaining = rest;
                        sent_in_burst += 1;
                        if sent_in_burst % SEND_PACE_EVERY == 0 {
                            thread::sleep(SEND_PACE_DELAY);
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                    continue; // poll again so a stream the exit closed can interrupt this loop
                }
                Err(_) => break, // connection reset or similar
            }
        }
        // The read loop ends when the client stops *sending*; the writer
        // stays registered (not removed here) until close_stream is
        // called, so the exit's still-arriving reply is not dropped.
        self.closed_streams.lock().unwrap().remove(&key);
        (self.onion_stream_finished)(&onion);
        Ok(())
    }

    fn flush_pending(&self, onion: &Onion, stream_id: u32) {
        let key: StreamKey = (OnionKey(onion.clone()), stream_id);
        let data = match self.pending_write.lock().unwrap().remove(&key) {
            Some(d) if !d.is_empty() => d,
            _ => return,
        };
        // `try_clone()` under the lock, then write on the clone with the
        // lock released: `write_all` blocks on the client's socket, and a
        // client that stops reading must not be able to stall every other
        // stream waiting on `self.writers` while this one is stuck (see
        // `write_to_stream`'s doc comment for the full scenario).
        let cloned = self.writers.lock().unwrap().get(&key).and_then(|w| w.try_clone().ok());
        if let Some(mut w) = cloned {
            if w.write_all(&data).is_err() {
                self.drop_client(&key);
            }
        }
    }

    fn drop_client(&self, key: &StreamKey) {
        self.writers.lock().unwrap().remove(key);
        self.reassemblers.lock().unwrap().remove(key);
        self.pending_write.lock().unwrap().remove(key);
        let mut gone = self.client_gone.lock().unwrap();
        if gone.len() < MAX_STREAM_MARKERS {
            gone.insert(key.clone());
        }
    }

    /// Close a client stream once the exit says its response has ended.
    ///
    /// `circuit_key` identifies which circuit's copy of this stream id to
    /// close (see the module doc's "Stream isolation" section);
    /// `None` defaults to the server's primary `onion`.
    pub fn close_stream(&self, stream_id: u32, circuit_key: Option<&Onion>) -> bool {
        let key: StreamKey = (OnionKey(circuit_key.cloned().unwrap_or_else(|| self.onion.clone())), stream_id);
        let writer = self.writers.lock().unwrap().remove(&key);
        // Remember the id even when no writer is registered yet: the exit
        // can signal end-of-stream before the CONNECT reply has been
        // processed into a relay loop.
        {
            let mut closed = self.closed_streams.lock().unwrap();
            if closed.len() < MAX_STREAM_MARKERS {
                closed.insert(key.clone());
            }
        }
        self.client_gone.lock().unwrap().remove(&key);
        match writer {
            None => false,
            Some(mut w) => {
                let _ = w.flush();
                let _ = w.shutdown(std::net::Shutdown::Both);
                true
            }
        }
    }

    /// Write already-reassembled return bytes to *one* stream's client.
    ///
    /// Unlike [`Self::deliver_data`], `payload` is not a fragment -- the
    /// caller has already decoded and reassembled it. `circuit_key`
    /// disambiguates which circuit's stream id this is (`None` defaults
    /// to the server's primary `onion`). Data that arrives before this
    /// stream's writer is registered is buffered and flushed once the
    /// stream starts, rather than dropped.
    ///
    /// Returns `true` if the payload was written now (buffering counts as
    /// not-yet-written).
    pub fn write_to_stream(&self, stream_id: u32, payload: &[u8], circuit_key: Option<&Onion>) -> bool {
        if payload.is_empty() {
            return false;
        }
        let key: StreamKey = (OnionKey(circuit_key.cloned().unwrap_or_else(|| self.onion.clone())), stream_id);
        if self.client_gone.lock().unwrap().contains(&key) {
            return false; // discarded, deliberately not buffered: nobody will ever read it
        }
        // Clone the registered socket handle under the lock, then write on
        // the clone with the lock released. `write_all` blocks until the
        // client's kernel socket buffer has room; holding `self.writers`
        // across that write would mean one client that stops reading (a
        // paused download, a throttled tab) blocks every other stream's
        // `write_to_stream`/`deliver_data`/`flush_pending`, plus
        // `close_stream`, which all take the same lock -- i.e. one slow
        // client freezing the whole proxy. `TcpStream::try_clone` gives an
        // independent handle to the same socket, so this never changes
        // what `writers` itself holds registered for `key`.
        let cloned = self.writers.lock().unwrap().get(&key).map(|w| w.try_clone());
        match cloned {
            None => {
                let mut pending = self.pending_write.lock().unwrap();
                let held = pending.get(&key).map_or(0, Vec::len);
                let new_stream = !pending.contains_key(&key);
                if held + payload.len() > MAX_PENDING_WRITE_PER_STREAM
                    || (new_stream && pending.len() >= MAX_PENDING_WRITE_STREAMS)
                {
                    // Not a stream this client is waiting on (or one that
                    // is not draining): stop buffering for it and discard
                    // what it already holds.
                    drop(pending);
                    self.drop_client(&key);
                    return false;
                }
                pending.entry(key).or_default().extend_from_slice(payload);
                false
            }
            Some(Ok(mut w)) => match w.write_all(payload) {
                Ok(()) => true,
                Err(_) => {
                    self.drop_client(&key);
                    false
                }
            },
            Some(Err(_)) => {
                self.drop_client(&key);
                false
            }
        }
    }

    /// Reassemble a return-path fragment and write it to the SOCKS client.
    ///
    /// `circuit_key` disambiguates which circuit's stream id this is
    /// (`None` defaults to the server's primary `onion`). Returns the
    /// bytes that were written (empty when the fragment was buffered, was
    /// for an unknown stream, or the client socket is gone).
    pub fn deliver_data(&self, stream_id: u32, payload: &[u8], circuit_key: Option<&Onion>) -> Vec<u8> {
        let key: StreamKey = (OnionKey(circuit_key.cloned().unwrap_or_else(|| self.onion.clone())), stream_id);
        if self.client_gone.lock().unwrap().contains(&key) {
            return Vec::new();
        }
        let frag = match decode_fragment(payload) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let data = {
            let mut reassemblers = self.reassemblers.lock().unwrap();
            if !reassemblers.contains_key(&key) && reassemblers.len() >= MAX_REASSEMBLERS {
                return Vec::new(); // table full: ignore fragments for new, unknown streams
            }
            let reassembler =
                reassemblers.entry(key.clone()).or_insert_with(|| Reassembler::new(stream_id, DEFAULT_MAX_PENDING));
            match reassembler.push(&frag) {
                Ok(d) => d,
                Err(_) => return Vec::new(),
            }
        };
        if !data.is_empty() {
            // See `write_to_stream`'s doc comment: clone the handle under
            // the lock and write on the clone, so a stalled client can't
            // hold up every other stream's writer lookups and writes.
            let cloned = self.writers.lock().unwrap().get(&key).map(|w| w.try_clone());
            match cloned {
                None => return Vec::new(),
                Some(Ok(mut w)) => {
                    if w.write_all(&data).is_err() {
                        self.drop_client(&key);
                        return Vec::new();
                    }
                }
                Some(Err(_)) => {
                    self.drop_client(&key);
                    return Vec::new();
                }
            }
        }
        data
    }
}

/// Handle to a running [`SocksServer::spawn`] accept loop.
///
/// Dropping it (or calling [`Self::stop`]) stops accepting new connections
/// and joins the accept thread; connections already relaying are left to
/// finish on their own.
pub struct SocksServerHandle {
    pub local_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    accept_thread: Option<thread::JoinHandle<()>>,
}

impl SocksServerHandle {
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.accept_thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for SocksServerHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.accept_thread.take() {
            let _ = t.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socks::{decode_request, encode_reply, DatagramReply};
    use std::net::Ipv4Addr;
    use std::sync::mpsc;

    fn poll_until<F: FnMut() -> bool>(mut pred: F, timeout: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if pred() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        false
    }

    // -- pure helpers -----------------------------------------------------

    #[test]
    fn parse_and_encode_address_round_trip_ipv4() {
        let encoded = encode_address("93.184.216.34", 443);
        let (host, port, consumed) = parse_address(&encoded).unwrap();
        assert_eq!(host, "93.184.216.34");
        assert_eq!(port, 443);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn parse_and_encode_address_round_trip_domain() {
        let encoded = encode_address("example.com", 80);
        assert_eq!(encoded[0], ATYP_DOMAIN);
        let (host, port, consumed) = parse_address(&encoded).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn parse_and_encode_address_round_trip_ipv6() {
        let encoded = encode_address("::1", 22);
        assert_eq!(encoded[0], ATYP_IPV6);
        let (host, port, _) = parse_address(&encoded).unwrap();
        assert_eq!(host, "0000:0000:0000:0000:0000:0000:0000:0001");
        assert_eq!(port, 22);
    }

    #[test]
    fn parse_address_rejects_empty_and_unknown_atyp() {
        assert!(parse_address(&[]).is_err());
        assert_eq!(parse_address(&[0xEE]).unwrap_err().0, REPLY_ADDR_UNSUPPORTED);
    }

    #[test]
    fn status_to_socks_maps_known_and_unknown_statuses() {
        assert_eq!(status_to_socks(SUCCESS), REPLY_SUCCEEDED);
        assert_eq!(status_to_socks(HOST_UNREACHABLE), REPLY_HOST_UNREACHABLE);
        assert_eq!(status_to_socks(200), REPLY_GENERAL);
    }

    #[test]
    fn retryable_statuses_match_python_set() {
        assert!(is_retryable(GENERAL_FAILURE));
        assert!(is_retryable(HOST_UNREACHABLE));
        assert!(is_retryable(TTL_EXPIRED));
        assert!(is_retryable(COMMAND_UNSUPPORTED));
        assert!(!is_retryable(CONNECTION_REFUSED));
        assert!(!is_retryable(ADDR_UNSUPPORTED));
        assert!(!is_retryable(SUCCESS));
    }

    #[test]
    fn onion_key_identity_is_by_arc_pointer() {
        let a: Onion = Arc::new(|_: &[u8]| {});
        let b: Onion = Arc::new(|_: &[u8]| {});
        let a2 = a.clone();
        assert_eq!(OnionKey(a.clone()), OnionKey(a2));
        assert_ne!(OnionKey(a), OnionKey(b));
    }

    #[test]
    fn new_rejects_zero_max_connect_attempts() {
        let onion: Onion = Arc::new(|_: &[u8]| {});
        let mut opts = SocksServerOptions::default();
        opts.max_connect_attempts = 0;
        assert!(SocksServer::new(onion, opts).is_err());
    }

    // -- request_with_retry (no sockets) -----------------------------------

    #[test]
    fn request_with_retry_succeeds_on_fresh_circuit_after_local_timeout() {
        let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let cap2 = captured.clone();
        let secondary: Onion = Arc::new(move |d: &[u8]| cap2.lock().unwrap().push(d.to_vec()));
        let secondary_for_retry = secondary.clone();

        // The primary onion is a black hole: it never triggers a reply, so
        // the first attempt must time out locally.
        let primary: Onion = Arc::new(|_d: &[u8]| {});

        let mut opts = SocksServerOptions::default();
        opts.connect_timeout = Duration::from_millis(120);
        opts.onion_retry = Some(Arc::new(move |_host: &str, _port: u16, _scope: Option<&str>, _failed: Option<Onion>, _reason: Option<&str>| {
            Ok(Some(secondary_for_retry.clone()))
        }));
        let server = SocksServer::new(primary, opts).unwrap();

        let server2 = server.clone();
        let cap_watch = captured.clone();
        let secondary_for_reply = secondary.clone();
        let responder = thread::spawn(move || {
            assert!(poll_until(|| !cap_watch.lock().unwrap().is_empty(), Duration::from_secs(2)));
            let raw = cap_watch.lock().unwrap().pop().unwrap();
            let req = decode_request(&raw).unwrap();
            let reply = StreamReply { request_id: req.request_id, status: SUCCESS, stream_id: 42, address: None };
            server2.deliver_reply(&encode_reply(&reply).unwrap(), Some(&secondary_for_reply));
        });

        let (reply, used_onion) = server.request_with_retry(CONNECT, "example.com", 443, None).unwrap();
        assert_eq!(reply.status, SUCCESS);
        assert_eq!(reply.stream_id, 42);
        assert!(used_onion.is_some());
        assert_eq!(server.retries_attempted(), 1);
        assert_eq!(server.retries_succeeded(), 1);
        responder.join().unwrap();
    }

    /// A reply naming the right `request_id` but arriving on the wrong
    /// circuit (as a hostile exit on some *other* circuit could forge,
    /// since `request_id` alone used to be both predictable and the only
    /// check) must be dropped, not used to complete a request pending on
    /// a different circuit.
    #[test]
    fn deliver_reply_ignores_reply_from_the_wrong_circuit() {
        let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let cap2 = captured.clone();
        // The primary circuit never replies on its own -- every reply in
        // this test is injected explicitly via `deliver_reply`.
        let primary: Onion = Arc::new(move |d: &[u8]| cap2.lock().unwrap().push(d.to_vec()));
        let mut opts = SocksServerOptions::default();
        opts.connect_timeout = Duration::from_secs(2);
        let server = SocksServer::new(primary, opts).unwrap();

        let server2 = server.clone();
        let responder = thread::spawn(move || server2.request_with_retry(CONNECT, "example.com", 443, None));

        assert!(poll_until(|| !captured.lock().unwrap().is_empty(), Duration::from_secs(2)));
        let raw = captured.lock().unwrap().remove(0);
        let request_id = decode_request(&raw).unwrap().request_id;
        let reply = StreamReply { request_id, status: SUCCESS, stream_id: 7, address: None };
        let encoded = encode_reply(&reply).unwrap();

        // A different circuit than the one this request was sent on.
        let wrong_circuit: Onion = Arc::new(|_: &[u8]| {});
        server.deliver_reply(&encoded, Some(&wrong_circuit));

        // The forged delivery must not have consumed the pending request:
        // delivering the same reply on the correct (primary) circuit right
        // after still succeeds.
        server.deliver_reply(&encoded, None);

        let (reply, _used_onion) = responder.join().unwrap().unwrap();
        assert_eq!(reply.status, SUCCESS);
        assert_eq!(reply.stream_id, 7);
    }

    #[test]
    fn request_with_retry_without_retry_hook_fails_once() {
        let onion: Onion = Arc::new(|_d: &[u8]| {});
        let mut opts = SocksServerOptions::default();
        opts.connect_timeout = Duration::from_millis(80);
        let server = SocksServer::new(onion, opts).unwrap();
        let err = match server.request_with_retry(CONNECT, "example.com", 443, None) {
            Err(e) => e,
            Ok(_) => panic!("expected a timeout error"),
        };
        assert_eq!(err.0, REPLY_TTL_EXPIRED);
        assert_eq!(server.retries_attempted(), 0);
    }

    // -- request_with_retry, scripted-reply scenarios (port of
    // test_connect_retry.py) -------------------------------------------------
    //
    // Mirrors Python's `_FakeCircuit`, which closes over a mutable
    // `server_ref = [None]` cell populated with the real server only after
    // it's constructed (a `SocksServer` needs its onion up front, but a
    // scripted onion here needs the server to call `deliver_reply` on --
    // neither can exist first). `SocksCell` is the Rust equivalent of that
    // same lazily-populated cell: cloned into every onion at construction
    // time, then `set()` once with the real server right after
    // `SocksServer::new` returns, before any request is ever sent.
    type SocksCell = Arc<std::sync::OnceLock<Arc<SocksServer>>>;

    /// An onion that answers every request it's handed with a scripted
    /// `status`, records each request it decoded, and (if `silent`) never
    /// replies at all -- so the caller's `connect_timeout` fires instead.
    fn scripted_reply_onion(
        server_cell: SocksCell,
        status: u8,
        stream_id: u32,
        silent: bool,
        requests: Arc<Mutex<Vec<crate::socks::StreamRequest>>>,
    ) -> Onion {
        // Same self-referential-cell trick as `server_cell`: `deliver_reply`
        // now needs to know which circuit a reply "arrived on" (H-2), and
        // the answer is "this very onion" -- but the closure can't capture
        // its own `Arc` before it exists, so it looks itself up here once
        // it's been set right after construction.
        let self_cell: Arc<std::sync::OnceLock<Onion>> = Arc::new(std::sync::OnceLock::new());
        let self_cell_for_closure = self_cell.clone();
        let onion: Onion = Arc::new(move |payload: &[u8]| {
            let Ok(request) = decode_request(payload) else {
                return; // stream data fragment, not a request
            };
            requests.lock().unwrap().push(request.clone());
            if silent {
                return;
            }
            let reply = if request.kind == socks::RESOLVE {
                StreamReply {
                    request_id: request.request_id,
                    status,
                    stream_id: 0,
                    address: if status == SUCCESS { Some(("198.51.100.7".to_string(), 0)) } else { None },
                }
            } else {
                StreamReply { request_id: request.request_id, status, stream_id, address: None }
            };
            let server = server_cell.get().expect("server constructed before any request is sent");
            server.deliver_reply(&encode_reply(&reply).unwrap(), self_cell_for_closure.get());
        });
        self_cell.set(onion.clone()).ok();
        onion
    }

    #[test]
    fn request_with_retry_policy_denial_is_retried_on_a_new_circuit() {
        let cell: SocksCell = Arc::new(std::sync::OnceLock::new());
        let first_requests = Arc::new(Mutex::new(Vec::new()));
        let second_requests = Arc::new(Mutex::new(Vec::new()));
        let first = scripted_reply_onion(cell.clone(), COMMAND_UNSUPPORTED, 5, false, first_requests.clone());
        let second = scripted_reply_onion(cell.clone(), SUCCESS, 5, false, second_requests.clone());

        let retry_calls: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let calls_for_retry = retry_calls.clone();
        let mut opts = SocksServerOptions::default();
        opts.onion_retry = Some(Arc::new(move |_h: &str, _p: u16, _scope: Option<&str>, _failed: Option<Onion>, reason: Option<&str>| {
            *calls_for_retry.lock().unwrap() += 1;
            assert_eq!(reason, Some("exit-policy"));
            Ok(Some(second.clone()))
        }));
        let server = SocksServer::new(first, opts).unwrap();
        cell.set(server.clone()).ok();

        let (reply, _used) = server.request_with_retry(CONNECT, "video.example", 443, None).unwrap();
        assert_eq!(reply.status, SUCCESS);
        assert_eq!(first_requests.lock().unwrap().len(), 1);
        assert_eq!(second_requests.lock().unwrap().len(), 1);
        assert_eq!(*retry_calls.lock().unwrap(), 1);
        assert_eq!(server.retries_attempted(), 1);
        assert_eq!(server.retries_succeeded(), 1);
    }

    #[test]
    fn request_with_retry_connection_refused_is_not_retried() {
        let cell: SocksCell = Arc::new(std::sync::OnceLock::new());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let refusing = scripted_reply_onion(cell.clone(), CONNECTION_REFUSED, 0, false, requests);

        let retry_calls: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let calls_for_retry = retry_calls.clone();
        let mut opts = SocksServerOptions::default();
        opts.onion_retry = Some(Arc::new(move |_h: &str, _p: u16, _scope: Option<&str>, _failed: Option<Onion>, _reason: Option<&str>| {
            *calls_for_retry.lock().unwrap() += 1;
            Ok(Some(Arc::new(|_d: &[u8]| {}) as Onion))
        }));
        let server = SocksServer::new(refusing, opts).unwrap();
        cell.set(server.clone()).ok();

        let err = match server.request_with_retry(CONNECT, "video.example", 443, None) {
            Err(e) => e,
            Ok(_) => panic!("expected a refusal error"),
        };
        assert_eq!(err.0, REPLY_CONN_REFUSED);
        assert_eq!(*retry_calls.lock().unwrap(), 0, "a refusal must not be retried at all");
        assert_eq!(server.retries_attempted(), 0);
    }

    #[test]
    fn request_with_retry_gives_up_after_max_attempts() {
        // max_connect_attempts=3 means 3 total attempts (1 initial + 2
        // retries): three failing circuits are scripted for those, plus a
        // fourth that *would* succeed but must never be reached, since
        // only 2 retry calls ever happen.
        let cell: SocksCell = Arc::new(std::sync::OnceLock::new());
        let discard = || Arc::new(Mutex::new(Vec::new()));
        let failing0 = scripted_reply_onion(cell.clone(), GENERAL_FAILURE, 0, false, discard());
        let failing1 = scripted_reply_onion(cell.clone(), GENERAL_FAILURE, 0, false, discard());
        let failing2 = scripted_reply_onion(cell.clone(), GENERAL_FAILURE, 0, false, discard());
        let never_reached = Arc::new(Mutex::new(Vec::new()));
        let unreached = scripted_reply_onion(cell.clone(), SUCCESS, 5, false, never_reached.clone());

        let retry_calls: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let calls_for_retry = retry_calls.clone();
        let sequence: Arc<Mutex<Vec<Onion>>> = Arc::new(Mutex::new(vec![failing1, failing2, unreached]));
        let mut opts = SocksServerOptions::default();
        opts.max_connect_attempts = 3;
        opts.onion_retry = Some(Arc::new(move |_h: &str, _p: u16, _scope: Option<&str>, _failed: Option<Onion>, _reason: Option<&str>| {
            *calls_for_retry.lock().unwrap() += 1;
            Ok(Some(sequence.lock().unwrap().remove(0)))
        }));
        let server = SocksServer::new(failing0, opts).unwrap();
        cell.set(server.clone()).ok();

        let err = match server.request_with_retry(CONNECT, "video.example", 443, None) {
            Err(e) => e,
            Ok(_) => panic!("expected the attempts to be exhausted"),
        };
        assert_ne!(err.0, REPLY_SUCCEEDED);
        // 3 attempts total means only 2 retries -- the third scripted
        // circuit (the one that would have succeeded) is never reached.
        assert_eq!(*retry_calls.lock().unwrap(), 2);
        assert!(never_reached.lock().unwrap().is_empty());
    }

    #[test]
    fn request_with_retry_resolve_is_retried_too() {
        let cell: SocksCell = Arc::new(std::sync::OnceLock::new());
        let first_requests = Arc::new(Mutex::new(Vec::new()));
        let second_requests = Arc::new(Mutex::new(Vec::new()));
        let first = scripted_reply_onion(cell.clone(), GENERAL_FAILURE, 0, false, first_requests);
        let second = scripted_reply_onion(cell.clone(), SUCCESS, 0, false, second_requests);

        let mut opts = SocksServerOptions::default();
        opts.onion_retry = Some(Arc::new(move |_h: &str, _p: u16, _scope: Option<&str>, _failed: Option<Onion>, _reason: Option<&str>| {
            Ok(Some(second.clone()))
        }));
        let server = SocksServer::new(first, opts).unwrap();
        cell.set(server.clone()).ok();

        let (reply, _used) = server.request_with_retry(socks::RESOLVE, "video.example", 0, None).unwrap();
        assert_eq!(reply.status, SUCCESS);
    }

    #[test]
    fn request_with_retry_timeout_with_retries_exhausted_reports_ttl_expired() {
        let cell: SocksCell = Arc::new(std::sync::OnceLock::new());
        let silent_requests = Arc::new(Mutex::new(Vec::new()));
        let silent_a = scripted_reply_onion(cell.clone(), SUCCESS, 0, true, silent_requests.clone());
        let silent_b = scripted_reply_onion(cell.clone(), SUCCESS, 0, true, silent_requests);

        let mut opts = SocksServerOptions::default();
        opts.connect_timeout = Duration::from_millis(100);
        opts.retry_connect_timeout = Some(Duration::from_millis(100));
        opts.max_connect_attempts = 2;
        opts.onion_retry = Some(Arc::new(move |_h: &str, _p: u16, _scope: Option<&str>, _failed: Option<Onion>, _reason: Option<&str>| {
            Ok(Some(silent_b.clone()))
        }));
        let server = SocksServer::new(silent_a, opts).unwrap();
        cell.set(server.clone()).ok();

        let err = match server.request_with_retry(CONNECT, "video.example", 443, None) {
            Err(e) => e,
            Ok(_) => panic!("expected a timeout error"),
        };
        assert_eq!(err.0, REPLY_TTL_EXPIRED);
    }

    #[test]
    fn request_with_retry_reason_distinguishes_policy_from_timeout() {
        let cell: SocksCell = Arc::new(std::sync::OnceLock::new());
        let denied_requests = Arc::new(Mutex::new(Vec::new()));
        let silent_requests = Arc::new(Mutex::new(Vec::new()));
        let ok_requests = Arc::new(Mutex::new(Vec::new()));
        let denied = scripted_reply_onion(cell.clone(), COMMAND_UNSUPPORTED, 0, false, denied_requests);
        let silent = scripted_reply_onion(cell.clone(), SUCCESS, 5, true, silent_requests);
        let ok = scripted_reply_onion(cell.clone(), SUCCESS, 5, false, ok_requests);

        let reasons: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
        let reasons_for_retry = reasons.clone();
        let sequence: Arc<Mutex<Vec<Onion>>> = Arc::new(Mutex::new(vec![silent, ok]));
        let mut opts = SocksServerOptions::default();
        opts.connect_timeout = Duration::from_millis(150);
        opts.onion_retry = Some(Arc::new(move |_h: &str, _p: u16, _scope: Option<&str>, _failed: Option<Onion>, reason: Option<&str>| {
            reasons_for_retry.lock().unwrap().push(reason.map(|s| s.to_string()));
            Ok(Some(sequence.lock().unwrap().remove(0)))
        }));
        let server = SocksServer::new(denied, opts).unwrap();
        cell.set(server.clone()).ok();

        let (reply, _used) = server.request_with_retry(CONNECT, "x", 22, None).unwrap();
        assert_eq!(reply.status, SUCCESS);
        assert_eq!(
            *reasons.lock().unwrap(),
            vec![Some("exit-policy".to_string()), Some("timeout".to_string())]
        );
    }

    // -- end-to-end CONNECT over a real TCP loopback -------------------------

    #[test]
    fn connect_relay_round_trips_request_and_reply() {
        let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let cap2 = captured.clone();
        let onion: Onion = Arc::new(move |d: &[u8]| cap2.lock().unwrap().push(d.to_vec()));
        let mut opts = SocksServerOptions::default();
        opts.port = 0;
        let server = SocksServer::new(onion, opts).unwrap();
        let handle = server.clone().spawn().unwrap();

        let mut client = TcpStream::connect(handle.local_addr).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(resp, [0x05, 0x00]);

        let host = b"example.com";
        let mut req = vec![0x05, CMD_CONNECT, 0x00, ATYP_DOMAIN, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).unwrap();

        assert!(poll_until(|| !captured.lock().unwrap().is_empty(), Duration::from_secs(2)));
        let raw = captured.lock().unwrap().remove(0);
        let request = decode_request(&raw).unwrap();
        assert_eq!(request.host, "example.com");
        assert_eq!(request.port, 443);
        let reply = StreamReply { request_id: request.request_id, status: SUCCESS, stream_id: 7, address: None };
        server.deliver_reply(&encode_reply(&reply).unwrap(), None);

        let mut head = [0u8; 4];
        client.read_exact(&mut head).unwrap();
        assert_eq!(head[1], REPLY_SUCCEEDED);
        let mut tail = [0u8; 6]; // 0.0.0.0:0 bound address
        client.read_exact(&mut tail).unwrap();

        // Forward direction: the SOCKS client's bytes should be fragmented
        // and sent through the onion callback.
        client.write_all(b"hello").unwrap();
        assert!(poll_until(|| captured.lock().unwrap().len() >= 1, Duration::from_secs(2)));
        let frag_bytes = captured.lock().unwrap().remove(0);
        let frag = decode_fragment(&frag_bytes).unwrap();
        assert_eq!(frag.stream_id, 7);
        assert_eq!(frag.offset, 0);
        assert!(!frag.fin);
        assert_eq!(frag.data, b"hello");

        // Return direction: deliver_data should write reassembled bytes
        // straight to the client's socket.
        let reply_frag = Fragment { stream_id: 7, offset: 0, fin: true, data: b"world".to_vec() };
        let written = server.deliver_data(7, &encode_fragment(&reply_frag), None);
        assert_eq!(written, b"world");

        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 16];
        let n = client.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"world");

        assert!(server.close_stream(7, None));
        handle.stop();
    }

    #[test]
    fn resolve_relay_round_trips() {
        let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let cap2 = captured.clone();
        let onion: Onion = Arc::new(move |d: &[u8]| cap2.lock().unwrap().push(d.to_vec()));
        let mut opts = SocksServerOptions::default();
        opts.port = 0;
        let server = SocksServer::new(onion, opts).unwrap();
        let handle = server.clone().spawn().unwrap();

        let server2 = server.clone();
        let cap_watch = captured.clone();
        let responder = thread::spawn(move || {
            assert!(poll_until(|| !cap_watch.lock().unwrap().is_empty(), Duration::from_secs(2)));
            let raw = cap_watch.lock().unwrap().remove(0);
            let req = decode_request(&raw).unwrap();
            let reply = StreamReply {
                request_id: req.request_id,
                status: SUCCESS,
                stream_id: 0,
                address: Some(("93.184.216.34".to_string(), 0)),
            };
            server2.deliver_reply(&encode_reply(&reply).unwrap(), None);
        });

        let mut client = TcpStream::connect(handle.local_addr).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut m = [0u8; 2];
        client.read_exact(&mut m).unwrap();
        let host = b"example.com";
        let mut req = vec![0x05, CMD_RESOLVE, 0x00, ATYP_DOMAIN, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&0u16.to_be_bytes());
        client.write_all(&req).unwrap();

        let mut head = [0u8; 4];
        client.read_exact(&mut head).unwrap();
        assert_eq!(head[1], REPLY_SUCCEEDED);
        let mut addr4 = [0u8; 4];
        client.read_exact(&mut addr4).unwrap();
        assert_eq!(addr4, [93, 184, 216, 34]);

        responder.join().unwrap();
        handle.stop();
    }

    #[test]
    fn udp_associate_relays_client_datagram_and_reply() {
        let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let cap2 = captured.clone();
        let onion: Onion = Arc::new(|_d: &[u8]| {});
        let mut opts = SocksServerOptions::default();
        opts.port = 0;
        opts.allow_udp = true;
        opts.onion_datagram = Some(Arc::new(move |d: &[u8]| cap2.lock().unwrap().push(d.to_vec())));
        let server = SocksServer::new(onion, opts).unwrap();
        let handle = server.clone().spawn().unwrap();

        let mut client = TcpStream::connect(handle.local_addr).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut m = [0u8; 2];
        client.read_exact(&mut m).unwrap();
        // UDP ASSOCIATE, ATYP IPv4, 0.0.0.0:0.
        client.write_all(&[0x05, CMD_UDP_ASSOCIATE, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).unwrap();
        let mut head = [0u8; 4];
        client.read_exact(&mut head).unwrap();
        assert_eq!(head[1], REPLY_SUCCEEDED);
        let mut addr4 = [0u8; 4];
        client.read_exact(&mut addr4).unwrap();
        let mut portb = [0u8; 2];
        client.read_exact(&mut portb).unwrap();
        let bound = SocketAddr::from((Ipv4Addr::new(addr4[0], addr4[1], addr4[2], addr4[3]), u16::from_be_bytes(portb)));

        let udp_client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut dgram = vec![0, 0, 0, ATYP_IPV4, 93, 184, 216, 34, 0, 80];
        dgram.extend_from_slice(b"ping");
        udp_client.send_to(&dgram, bound).unwrap();

        assert!(poll_until(|| !captured.lock().unwrap().is_empty(), Duration::from_secs(2)));
        let encoded = captured.lock().unwrap().remove(0);
        let decoded = socks::decode_datagram_request(&encoded).unwrap();
        assert_eq!(decoded.payload, b"ping");
        assert_eq!(decoded.host, "93.184.216.34");
        assert_eq!(decoded.port, 80);

        let reply = DatagramReply {
            association_id: decoded.association_id,
            host: "93.184.216.34".to_string(),
            port: 80,
            payload: b"pong".to_vec(),
        };
        let encoded_reply = socks::encode_datagram_reply(&reply).unwrap();
        assert!(server.deliver_datagram_reply(&encoded_reply));

        udp_client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 512];
        let (n, _from) = udp_client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..3], &[0, 0, 0]);
        assert_eq!(buf[3], ATYP_IPV4);
        assert_eq!(&buf[4..8], &[93, 184, 216, 34]);
        assert_eq!(&buf[10..n], b"pong");

        let _ = client.shutdown(std::net::Shutdown::Both);
        handle.stop();
    }

    // -- hidden-service CONNECT ---------------------------------------------

    struct EchoConnection {
        inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
        to_echo: Mutex<mpsc::Sender<Vec<u8>>>,
    }
    impl HiddenServiceConnection for EchoConnection {
        fn send(&self, data: &[u8]) -> io::Result<()> {
            self.to_echo
                .lock()
                .unwrap()
                .send(data.to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }
        fn receive(&self, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
            match self.inbound.lock().unwrap().recv_timeout(timeout) {
                Ok(v) => Ok(Some(v)),
                Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
                }
            }
        }
        fn close(&self) {}
    }

    #[test]
    fn hidden_service_connect_relays_bytes_both_ways() {
        let (to_echo_tx, to_echo_rx) = mpsc::channel::<Vec<u8>>();
        let (reply_tx, reply_rx) = mpsc::channel::<Vec<u8>>();
        thread::spawn(move || {
            while let Ok(data) = to_echo_rx.recv() {
                if reply_tx.send(data).is_err() {
                    break;
                }
            }
        });
        let connection: Arc<dyn HiddenServiceConnection> =
            Arc::new(EchoConnection { inbound: Mutex::new(reply_rx), to_echo: Mutex::new(to_echo_tx) });

        let onion: Onion = Arc::new(|_d: &[u8]| {});
        let mut opts = SocksServerOptions::default();
        opts.port = 0;
        let conn_for_hook = connection.clone();
        opts.hidden_service_connect =
            Some(Arc::new(move |_host: &str, _port: u16| Ok(conn_for_hook.clone())));
        let server = SocksServer::new(onion, opts).unwrap();
        let handle = server.spawn().unwrap();

        let mut client = TcpStream::connect(handle.local_addr).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut m = [0u8; 2];
        client.read_exact(&mut m).unwrap();
        let host = b"service.allium";
        let mut req = vec![0x05, CMD_CONNECT, 0x00, ATYP_DOMAIN, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&80u16.to_be_bytes());
        client.write_all(&req).unwrap();
        let mut head = [0u8; 4];
        client.read_exact(&mut head).unwrap();
        assert_eq!(head[1], REPLY_SUCCEEDED);
        let mut tail = [0u8; 6];
        client.read_exact(&mut tail).unwrap();

        client.write_all(b"hello service").unwrap();
        client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello service");

        let _ = client.shutdown(std::net::Shutdown::Both);
        handle.stop();
    }

    #[test]
    fn hidden_service_connect_without_hook_is_refused() {
        let onion: Onion = Arc::new(|_d: &[u8]| {});
        let opts = SocksServerOptions::default();
        let server = SocksServer::new(onion, opts).unwrap();

        // A real (if otherwise unused) TCP connection, so `do_connect_hidden_service`
        // has a genuine socket to (not) write a reply to.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client_side = TcpStream::connect(addr).unwrap();
        let (server_side, _peer) = listener.accept().unwrap();
        drop(client_side);

        let err = server.do_connect_hidden_service(server_side, "svc.allium".to_string(), 80).unwrap_err();
        assert_eq!(err.0, REPLY_HOST_UNREACHABLE);
    }

    fn socks5_connect_request(host: &str, port: u16) -> Vec<u8> {
        let hostb = host.as_bytes();
        let mut req = vec![0x05, CMD_CONNECT, 0x00, ATYP_DOMAIN, hostb.len() as u8];
        req.extend_from_slice(hostb);
        req.extend_from_slice(&port.to_be_bytes());
        req
    }

    fn socks5_handshake(client: &mut TcpStream) {
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut m = [0u8; 2];
        client.read_exact(&mut m).unwrap();
        assert_eq!(m, [0x05, 0x00]);
    }

    /// RFC 1929 handshake: offer both NO AUTH and USERNAME/PASSWORD, expect
    /// the server to pick the latter, then send the credentials.
    fn socks5_userpass_handshake(client: &mut TcpStream, username: &[u8], password: &[u8]) {
        client.write_all(&[0x05, 0x02, METHOD_NO_AUTH, METHOD_USERNAME_PASSWORD]).unwrap();
        let mut m = [0u8; 2];
        client.read_exact(&mut m).unwrap();
        assert_eq!(m, [0x05, METHOD_USERNAME_PASSWORD], "username/password must be preferred when offered");
        let mut sub = vec![USERPASS_VERSION, username.len() as u8];
        sub.extend_from_slice(username);
        sub.push(password.len() as u8);
        sub.extend_from_slice(password);
        client.write_all(&sub).unwrap();
        let mut status = [0u8; 2];
        client.read_exact(&mut status).unwrap();
        assert_eq!(status, [USERPASS_VERSION, 0x00], "any credentials are accepted");
    }

    /// A server whose `onion_router` records the scope of every request
    /// and whose "exit" answers every CONNECT with success, so a full
    /// SOCKS5 exchange completes over a real socket.
    fn scope_recording_server() -> (Arc<SocksServer>, SocksServerHandle, Arc<Mutex<Vec<Option<String>>>>) {
        let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let cap2 = captured.clone();
        let onion: Onion = Arc::new(move |d: &[u8]| cap2.lock().unwrap().push(d.to_vec()));
        let scopes: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));

        let mut opts = SocksServerOptions::default();
        opts.port = 0;
        let scopes_for_router = scopes.clone();
        let onion_for_router = onion.clone();
        opts.onion_router = Some(Arc::new(move |_host: &str, _port: u16, scope: Option<&str>| {
            scopes_for_router.lock().unwrap().push(scope.map(str::to_string));
            Ok(onion_for_router.clone())
        }));
        let server = SocksServer::new(onion.clone(), opts).unwrap();
        let handle = server.clone().spawn().unwrap();

        // The fake exit: answer each captured CONNECT as soon as it appears.
        let server2 = server.clone();
        let onion = onion.clone();
        thread::spawn(move || {
            let mut answered = 0usize;
            loop {
                let next = captured.lock().unwrap().get(answered).cloned();
                match next {
                    Some(raw) => {
                        if let Ok(req) = decode_request(&raw) {
                            let reply =
                                StreamReply { request_id: req.request_id, status: SUCCESS, stream_id: answered as u32 + 1, address: None };
                            server2.deliver_reply(&encode_reply(&reply).unwrap(), Some(&onion));
                        }
                        answered += 1;
                    }
                    None => thread::sleep(Duration::from_millis(5)),
                }
                if answered >= 8 {
                    break;
                }
            }
        });
        (server, handle, scopes)
    }

    #[test]
    fn userpass_auth_is_preferred_and_scopes_the_router() {
        let (_server, handle, scopes) = scope_recording_server();

        let connect = |username: &[u8], password: &[u8]| {
            let mut client = TcpStream::connect(handle.local_addr).unwrap();
            client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            socks5_userpass_handshake(&mut client, username, password);
            client.write_all(&socks5_connect_request("example.com", 443)).unwrap();
            assert_eq!(read_reply_head(&mut client), REPLY_SUCCEEDED);
            let _ = client.shutdown(std::net::Shutdown::Both);
        };
        connect(b"alice", b"one");
        connect(b"bob", b"two");
        connect(b"alice", b"one");
        // And an unauthenticated connection, which carries no scope.
        {
            let mut client = TcpStream::connect(handle.local_addr).unwrap();
            client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            socks5_handshake(&mut client);
            client.write_all(&socks5_connect_request("example.com", 443)).unwrap();
            assert_eq!(read_reply_head(&mut client), REPLY_SUCCEEDED);
        }

        assert!(poll_until(|| scopes.lock().unwrap().len() == 4, Duration::from_secs(3)));
        let scopes = scopes.lock().unwrap().clone();
        assert_eq!(scopes[0].as_deref(), Some(socks_auth_scope(b"alice", b"one").as_str()));
        assert_ne!(scopes[0], scopes[1], "different credentials must give different scopes");
        assert_eq!(scopes[0], scopes[2], "the same credentials must give the same scope");
        assert_eq!(scopes[3], None, "NO AUTH carries no scope");
        // The scope is a digest: the credentials themselves never appear.
        let tag = scopes[0].as_deref().unwrap();
        assert!(tag.starts_with("auth:") && !tag.contains("alice") && !tag.contains("one"));
        handle.stop();
    }

    #[test]
    fn socks_auth_scope_is_length_prefixed_and_stable() {
        assert_eq!(socks_auth_scope(b"ab", b"c"), socks_auth_scope(b"ab", b"c"));
        assert_ne!(socks_auth_scope(b"ab", b"c"), socks_auth_scope(b"a", b"bc"));
        assert_ne!(socks_auth_scope(b"", b""), socks_auth_scope(b"x", b""));
        assert_eq!(socks_auth_scope(b"u", b"p").len(), "auth:".len() + 32);
    }

    #[test]
    fn malformed_userpass_subnegotiation_is_refused() {
        let (_server, handle, scopes) = scope_recording_server();
        let mut client = TcpStream::connect(handle.local_addr).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        client.write_all(&[0x05, 0x01, METHOD_USERNAME_PASSWORD]).unwrap();
        let mut m = [0u8; 2];
        client.read_exact(&mut m).unwrap();
        assert_eq!(m, [0x05, METHOD_USERNAME_PASSWORD]);
        // Wrong sub-negotiation version byte.
        client.write_all(&[0x05, 1, b'a', 1, b'b']).unwrap();
        let mut status = [0u8; 2];
        client.read_exact(&mut status).unwrap();
        assert_eq!(status, [USERPASS_VERSION, 0x01]);
        // No request was ever routed, and the connection is torn down
        // (after `handle_client`'s generic failure reply, same as any
        // other negotiation failure).
        let mut rest = [0u8; 64];
        let mut drained = 0;
        loop {
            match client.read(&mut rest) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    drained += n;
                    assert!(drained <= 10, "nothing beyond one failure reply may follow a refused sub-negotiation");
                }
            }
        }
        assert!(scopes.lock().unwrap().is_empty());
        handle.stop();
    }

    #[test]
    fn no_acceptable_method_is_refused() {
        let (_server, handle, _scopes) = scope_recording_server();
        let mut client = TcpStream::connect(handle.local_addr).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        client.write_all(&[0x05, 0x01, 0x01]).unwrap(); // GSSAPI only
        let mut m = [0u8; 2];
        client.read_exact(&mut m).unwrap();
        assert_eq!(m, [0x05, METHOD_NONE_ACCEPTABLE]);
        handle.stop();
    }

    /// Read one whole SOCKS5 reply (RFC 1928 6): the 4-byte header plus the
    /// `0.0.0.0:0` IPv4 address+port tail every reply in this proxy is
    /// written with (see `write_reply`'s default). Returns the reply code.
    fn read_reply_head(client: &mut TcpStream) -> u8 {
        let mut head = [0u8; 4];
        client.read_exact(&mut head).unwrap();
        let mut tail = [0u8; 6];
        client.read_exact(&mut tail).unwrap();
        head[1]
    }

    /// A `HiddenServiceConnection` stand-in that records every `send()`,
    /// serves `receive()` from a channel (an empty channel times out and
    /// yields `Ok(None)`, exactly like a real idle tunnel), and tracks
    /// whether `close()` was ever called -- the same duck-typed shape
    /// Python's `FakeHiddenServiceConnection` has.
    struct RecordingConnection {
        sent: Mutex<Vec<u8>>,
        inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
        closed: Arc<AtomicBool>,
    }
    impl HiddenServiceConnection for RecordingConnection {
        fn send(&self, data: &[u8]) -> io::Result<()> {
            self.sent.lock().unwrap().extend_from_slice(data);
            Ok(())
        }
        fn receive(&self, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
            match self.inbound.lock().unwrap().recv_timeout(timeout) {
                Ok(v) => Ok(Some(v)),
                Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
                Err(mpsc::RecvTimeoutError::Disconnected) => Ok(None),
            }
        }
        fn close(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn hidden_service_connect_never_touches_the_ordinary_onion_path() {
        let onion_calls: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let calls_for_onion = onion_calls.clone();
        let onion: Onion = Arc::new(move |d: &[u8]| calls_for_onion.lock().unwrap().push(d.to_vec()));

        let hidden_calls: Arc<Mutex<Vec<(String, u16)>>> = Arc::new(Mutex::new(Vec::new()));
        let calls_for_hook = hidden_calls.clone();
        let (_tx, rx) = mpsc::channel::<Vec<u8>>();
        let connection: Arc<dyn HiddenServiceConnection> = Arc::new(RecordingConnection {
            sent: Mutex::new(Vec::new()),
            inbound: Mutex::new(rx),
            closed: Arc::new(AtomicBool::new(false)),
        });

        let mut opts = SocksServerOptions::default();
        opts.port = 0;
        opts.hidden_service_connect = Some(Arc::new(move |host: &str, port: u16| {
            calls_for_hook.lock().unwrap().push((host.to_string(), port));
            Ok(connection.clone())
        }));
        let server = SocksServer::new(onion, opts).unwrap();
        let handle = server.spawn().unwrap();

        let mut client = TcpStream::connect(handle.local_addr).unwrap();
        socks5_handshake(&mut client);
        client.write_all(&socks5_connect_request("abcxyz.allium", 80)).unwrap();
        assert_eq!(read_reply_head(&mut client), REPLY_SUCCEEDED);
        assert_eq!(*hidden_calls.lock().unwrap(), vec![("abcxyz.allium".to_string(), 80)]);
        assert!(onion_calls.lock().unwrap().is_empty(), "a .allium CONNECT must never go through the exit path");

        let _ = client.shutdown(std::net::Shutdown::Both);
        handle.stop();
    }

    #[test]
    fn hidden_service_receive_timeout_does_not_end_the_session() {
        // The relay's service->client thread polls `receive()` on a fixed
        // 2s timeout; an empty channel must yield `Ok(None)` and the loop
        // must keep going, not tear the session down, so data pushed
        // shortly after still gets delivered -- exactly like a real
        // hidden-service tunnel sitting idle for a moment.
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let connection: Arc<dyn HiddenServiceConnection> = Arc::new(RecordingConnection {
            sent: Mutex::new(Vec::new()),
            inbound: Mutex::new(rx),
            closed: Arc::new(AtomicBool::new(false)),
        });

        let onion: Onion = Arc::new(|_d: &[u8]| {});
        let mut opts = SocksServerOptions::default();
        opts.port = 0;
        let conn_for_hook = connection.clone();
        opts.hidden_service_connect = Some(Arc::new(move |_h: &str, _p: u16| Ok(conn_for_hook.clone())));
        let server = SocksServer::new(onion, opts).unwrap();
        let handle = server.spawn().unwrap();

        let mut client = TcpStream::connect(handle.local_addr).unwrap();
        socks5_handshake(&mut client);
        client.write_all(&socks5_connect_request("abcxyz.allium", 80)).unwrap();
        assert_eq!(read_reply_head(&mut client), REPLY_SUCCEEDED);

        // Let at least one receive() attempt start (and, most likely, time
        // out) before any data is pushed.
        thread::sleep(Duration::from_millis(200));
        tx.send(b"still alive".to_vec()).unwrap();

        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"still alive");

        let _ = client.shutdown(std::net::Shutdown::Both);
        handle.stop();
    }

    #[test]
    fn hidden_service_client_closing_ends_relay_and_closes_connection() {
        let (_tx, rx) = mpsc::channel::<Vec<u8>>();
        let closed = Arc::new(AtomicBool::new(false));
        let connection: Arc<dyn HiddenServiceConnection> =
            Arc::new(RecordingConnection { sent: Mutex::new(Vec::new()), inbound: Mutex::new(rx), closed: closed.clone() });

        let onion: Onion = Arc::new(|_d: &[u8]| {});
        let mut opts = SocksServerOptions::default();
        opts.port = 0;
        let conn_for_hook = connection.clone();
        opts.hidden_service_connect = Some(Arc::new(move |_h: &str, _p: u16| Ok(conn_for_hook.clone())));
        let server = SocksServer::new(onion, opts).unwrap();
        let handle = server.spawn().unwrap();

        let mut client = TcpStream::connect(handle.local_addr).unwrap();
        socks5_handshake(&mut client);
        client.write_all(&socks5_connect_request("abcxyz.allium", 80)).unwrap();
        assert_eq!(read_reply_head(&mut client), REPLY_SUCCEEDED);

        let _ = client.shutdown(std::net::Shutdown::Both);
        drop(client);

        // Teardown is bounded by the service->client thread's own 2s
        // receive() timeout, not instant.
        assert!(poll_until(|| closed.load(Ordering::SeqCst), Duration::from_secs(4)));
        handle.stop();
    }

    #[test]
    fn hidden_service_hook_exception_is_a_clean_socks_failure_not_a_crash() {
        let onion: Onion = Arc::new(|_d: &[u8]| {});
        let mut opts = SocksServerOptions::default();
        opts.port = 0;
        opts.hidden_service_connect = Some(Arc::new(|_h: &str, _p: u16| Err(SocksError(REPLY_HOST_UNREACHABLE))));
        let server = SocksServer::new(onion, opts).unwrap();
        let handle = server.spawn().unwrap();

        let mut client = TcpStream::connect(handle.local_addr).unwrap();
        socks5_handshake(&mut client);
        client.write_all(&socks5_connect_request("abcxyz.allium", 80)).unwrap();
        assert_eq!(read_reply_head(&mut client), REPLY_HOST_UNREACHABLE);
        let _ = client.shutdown(std::net::Shutdown::Both);

        // One failed .allium lookup must never take the proxy down --
        // the next connection still gets a normal greeting.
        let mut client2 = TcpStream::connect(handle.local_addr).unwrap();
        socks5_handshake(&mut client2);
        let _ = client2.shutdown(std::net::Shutdown::Both);

        handle.stop();
    }

    #[test]
    fn hidden_service_target_port_is_accepted_but_unused() {
        // SOCKS5 requires a port; Allium has one address per service (no
        // per-virtual-port routing), so whatever port a browser defaults
        // to must not matter -- it's threaded through to the hook only.
        let hidden_calls: Arc<Mutex<Vec<(String, u16)>>> = Arc::new(Mutex::new(Vec::new()));
        let calls_for_hook = hidden_calls.clone();
        let (_tx, rx) = mpsc::channel::<Vec<u8>>();
        let connection: Arc<dyn HiddenServiceConnection> = Arc::new(RecordingConnection {
            sent: Mutex::new(Vec::new()),
            inbound: Mutex::new(rx),
            closed: Arc::new(AtomicBool::new(false)),
        });

        let onion: Onion = Arc::new(|_d: &[u8]| {});
        let mut opts = SocksServerOptions::default();
        opts.port = 0;
        opts.hidden_service_connect = Some(Arc::new(move |host: &str, port: u16| {
            calls_for_hook.lock().unwrap().push((host.to_string(), port));
            Ok(connection.clone())
        }));
        let server = SocksServer::new(onion, opts).unwrap();
        let handle = server.spawn().unwrap();

        let mut client = TcpStream::connect(handle.local_addr).unwrap();
        socks5_handshake(&mut client);
        client.write_all(&socks5_connect_request("abcxyz.allium", 443)).unwrap();
        assert_eq!(read_reply_head(&mut client), REPLY_SUCCEEDED);
        assert_eq!(*hidden_calls.lock().unwrap(), vec![("abcxyz.allium".to_string(), 443)]);

        let _ = client.shutdown(std::net::Shutdown::Both);
        handle.stop();
    }

    #[test]
    fn hidden_service_case_insensitive_suffix_match() {
        let hidden_calls: Arc<Mutex<Vec<(String, u16)>>> = Arc::new(Mutex::new(Vec::new()));
        let calls_for_hook = hidden_calls.clone();
        let (_tx, rx) = mpsc::channel::<Vec<u8>>();
        let connection: Arc<dyn HiddenServiceConnection> = Arc::new(RecordingConnection {
            sent: Mutex::new(Vec::new()),
            inbound: Mutex::new(rx),
            closed: Arc::new(AtomicBool::new(false)),
        });

        let onion: Onion = Arc::new(|_d: &[u8]| {});
        let mut opts = SocksServerOptions::default();
        opts.port = 0;
        opts.hidden_service_connect = Some(Arc::new(move |host: &str, port: u16| {
            calls_for_hook.lock().unwrap().push((host.to_string(), port));
            Ok(connection.clone())
        }));
        let server = SocksServer::new(onion, opts).unwrap();
        let handle = server.spawn().unwrap();

        let mut client = TcpStream::connect(handle.local_addr).unwrap();
        socks5_handshake(&mut client);
        client.write_all(&socks5_connect_request("ABCXYZ.ALLIUM", 80)).unwrap();
        assert_eq!(read_reply_head(&mut client), REPLY_SUCCEEDED);
        // The original casing is preserved through to the hook -- only the
        // ".allium" suffix match itself is case-insensitive.
        assert_eq!(*hidden_calls.lock().unwrap(), vec![("ABCXYZ.ALLIUM".to_string(), 80)]);

        let _ = client.shutdown(std::net::Shutdown::Both);
        handle.stop();
    }

    #[test]
    fn test_write_to_unknown_stream_is_capped_per_stream() {
        let server = SocksServer::new(Arc::new(|_d: &[u8]| {}), SocksServerOptions::default()).unwrap();
        // Early data below the cap is still buffered (legitimate race).
        assert!(!server.write_to_stream(5, &[1u8; 1024], None));
        assert_eq!(server.pending_write.lock().unwrap().len(), 1);
        // A stream that keeps pushing past the cap is dropped and no
        // longer buffered.
        let chunk = vec![0u8; 64 * 1024];
        for _ in 0..8 {
            server.write_to_stream(5, &chunk, None);
        }
        assert!(server.pending_write.lock().unwrap().is_empty());
        assert_eq!(server.client_gone.lock().unwrap().len(), 1);
        // And further data for it is discarded, not buffered.
        assert!(!server.write_to_stream(5, &chunk, None));
        assert!(server.pending_write.lock().unwrap().is_empty());
    }

    #[test]
    fn test_write_to_many_unknown_streams_is_bounded() {
        let server = SocksServer::new(Arc::new(|_d: &[u8]| {}), SocksServerOptions::default()).unwrap();
        for id in 0..10_000u32 {
            server.write_to_stream(id, &[7u8; 512], None);
        }
        let pending = server.pending_write.lock().unwrap();
        // the intended policy as literals, not the constants under test
        assert!(pending.len() <= 64, "{} streams buffered", pending.len());
        let bytes: usize = pending.values().map(Vec::len).sum();
        assert!(bytes <= 16 * 1024 * 1024, "{bytes} bytes buffered");
        assert!(server.client_gone.lock().unwrap().len() <= 65_536);
    }

    #[test]
    fn test_stream_markers_and_reassemblers_are_bounded() {
        let server = SocksServer::new(Arc::new(|_d: &[u8]| {}), SocksServerOptions::default()).unwrap();
        for id in 0..(MAX_STREAM_MARKERS as u32 + 5_000) {
            server.close_stream(id, None);
        }
        assert!(server.closed_streams.lock().unwrap().len() <= MAX_STREAM_MARKERS);
        for id in 0..(MAX_REASSEMBLERS as u32 + 500) {
            let frag = Fragment { stream_id: id, offset: 9, fin: false, data: vec![1] };
            server.deliver_data(id, &encode_fragment(&frag), None);
        }
        assert!(server.reassemblers.lock().unwrap().len() <= MAX_REASSEMBLERS);
    }

    // -- hidden-service session end: clean close / lost frame vs harmless drop --

    /// A tunnel that plays back a fixed script of `receive` results, then idles.
    struct ScriptedConnection {
        script: Mutex<std::collections::VecDeque<io::Result<Option<Vec<u8>>>>>,
    }
    impl HiddenServiceConnection for ScriptedConnection {
        fn send(&self, _data: &[u8]) -> io::Result<()> {
            Ok(())
        }
        fn receive(&self, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
            match self.script.lock().unwrap().pop_front() {
                Some(r) => r,
                None => {
                    thread::sleep(timeout.min(Duration::from_millis(20)));
                    Ok(None)
                }
            }
        }
        fn close(&self) {}
    }

    /// Connect a SOCKS client to `service.allium:80` through `connection`.
    fn scripted_hs_client(script: Vec<io::Result<Option<Vec<u8>>>>) -> (TcpStream, SocksServerHandle) {
        let connection: Arc<dyn HiddenServiceConnection> =
            Arc::new(ScriptedConnection { script: Mutex::new(script.into_iter().collect()) });
        let onion: Onion = Arc::new(|_d: &[u8]| {});
        let mut opts = SocksServerOptions::default();
        opts.port = 0;
        opts.hidden_service_connect = Some(Arc::new(move |_host: &str, _port: u16| Ok(connection.clone())));
        let server = SocksServer::new(onion, opts).unwrap();
        let handle = server.spawn().unwrap();
        let mut client = TcpStream::connect(handle.local_addr).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut m = [0u8; 2];
        client.read_exact(&mut m).unwrap();
        let host = b"service.allium";
        let mut req = vec![0x05, CMD_CONNECT, 0x00, ATYP_DOMAIN, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&80u16.to_be_bytes());
        client.write_all(&req).unwrap();
        let mut head = [0u8; 4];
        client.read_exact(&mut head).unwrap();
        assert_eq!(head[1], REPLY_SUCCEEDED);
        let mut tail = [0u8; 6];
        client.read_exact(&mut tail).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        (client, handle)
    }

    fn read_until_eof(client: &mut TcpStream) -> (Vec<u8>, bool) {
        let started = Instant::now();
        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            match client.read(&mut buf) {
                Ok(0) => return (got, true),
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(_) => return (got, false), // timed out: the session did not end
            }
            if started.elapsed() > Duration::from_secs(3) {
                return (got, false);
            }
        }
    }

    #[test]
    fn hidden_service_session_ends_when_the_peer_closes_cleanly() {
        let (mut client, handle) = scripted_hs_client(vec![
            Ok(Some(b"data".to_vec())),
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the service closed the session")),
        ]);
        let (got, ended) = read_until_eof(&mut client);
        assert_eq!(got, b"data");
        assert!(ended, "a clean close from the peer must end the session");
        handle.stop();
    }

    #[test]
    fn hidden_service_session_ends_when_a_frame_was_lost() {
        let (mut client, handle) = scripted_hs_client(vec![
            Ok(Some(b"before".to_vec())),
            Err(io::Error::new(io::ErrorKind::InvalidData, "frame 5 arrived but 3 was expected")),
            Ok(Some(b"must not be delivered".to_vec())),
        ]);
        let (got, ended) = read_until_eof(&mut client);
        assert_eq!(got, b"before", "nothing after the integrity failure may be delivered");
        assert!(ended, "a lost or reordered frame must end the session, not hang it");
        handle.stop();
    }

    #[test]
    fn hidden_service_session_survives_a_dropped_replayed_or_forged_frame() {
        let (mut client, handle) = scripted_hs_client(vec![
            Err(io::Error::other("frame 0 was already received")),
            Ok(Some(b"after".to_vec())),
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed")),
        ]);
        let (got, ended) = read_until_eof(&mut client);
        assert_eq!(got, b"after", "a harmless dropped frame must not end the session");
        assert!(ended);
        handle.stop();
    }
}
