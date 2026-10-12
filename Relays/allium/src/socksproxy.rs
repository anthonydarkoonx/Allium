//! A local SOCKS5 server that tunnels TCP through an Allium circuit --
//! **partial port**.
//!
//! `socksproxy.py` is ~1700 lines built around a live `asyncio` TCP/UDP
//! server (`SocksServer.start`/`_handle_client`/`_negotiate_and_connect`/
//! `_do_connect`/`_relay_stream`/`_do_udp_associate`/
//! `_relay_hidden_service`, plus automatic per-attempt circuit retry in
//! `_request_with_retry`/`_await_reply`) and a `SocksExit` mixin over
//! `allium::relay::RelayNode`.
//!
//! **What is ported and tested here**: everything that is pure protocol
//! logic or synchronous return-path bookkeeping, independent of the live
//! negotiation loop -- [`SocksError`], [`ReplyCode`] and the `REPLY_*`/
//! `CMD_*`/`ATYP_*` constants, [`status_to_socks`], [`parse_address`]/
//! [`encode_address`] (RFC 1928 address codec), [`RETRYABLE_STATUSES`]/
//! [`is_retryable`], [`UdpAssociation`] (client-side UDP ASSOCIATE
//! bookkeeping, closures for its transport exactly like `exit.rs`'s
//! `UDPAssociation`), and [`SocksServer`]'s return-path bookkeeping --
//! `deliver_data`/`write_to_stream`/`close_stream`/`flush_pending`, keyed
//! by `(circuit_key, stream_id)`, exactly as `exit.rs` keys by
//! `(circuit_key, stream_id)` -- these mirror `TestAddressCodec`,
//! `TestUdpAssociate`'s pure parts, `TestDeliverData`, and
//! `TestWriteToStream` in `test_socksproxy.py`.
//!
//! Also ported, in a follow-up pass once `allium::relay::RelayNode` was
//! real (see this file's `SocksExit` section further down and `relay.rs`'s
//! module docs): [`SocksExit`], the exit-side composition wiring a
//! `RelayNode` to a `crate::exit::Egress`.
//!
//! **One deviation from Python, matching `exit.rs`'s `CircuitKey`**: Python
//! keys these dicts by the `onion` *callable itself* (object identity).
//! Rust closures are not `Eq`/`Hash`, so this port uses an opaque
//! `CircuitKey` (`u64`) the caller assigns per circuit instead -- the same
//! isolation guarantee (two different keys can never collide), just an
//! explicit token rather than borrowed identity. [`SocksServer::default_key`]
//! is the "no `onion_router`, single shared circuit" key every pre-isolation
//! call site used, mirroring `self._onion` as the default in Python.
//!
//! **`SocksServer`'s live per-connection orchestration is now also
//! ported** -- `start`/`stop`/`with_options`, `_handle_client` ->
//! `handle_client`, `_negotiate_and_connect`, `_do_connect`/
//! `_do_connect_hidden_service`/`_do_resolve`/`_do_udp_associate`,
//! `_relay_stream`/`_relay_hidden_service`, and the automatic-retry state
//! machine `_request_with_retry` -> `request_with_retry`/`_await_reply` ->
//! `await_reply`. Same methodology as `RelayNode`/`SocksExit`: pure
//! protocol/decision logic (`negotiate_no_auth`, `reply_is_ok`,
//! `is_hidden_service_host`, the retry-reason classifiers,
//! `on_client_datagram`) is synchronous and unit-tested; every
//! tokio-touching piece is isolated inside a sentinel-marked block (plus a
//! few one-line sentinel-wrapped struct fields) further down, unverified
//! pending a real `cargo build` outside this sandbox -- see that section's
//! own doc comment for the concurrency model and the deliberate simplifications
//! (an opaque `CircuitKey` in place of `onion_router`/`onion_retry`'s
//! closures, and a simplified hidden-service relay bridge built on a
//! `HsTunnel` trait with no in-tree implementation yet).

use crate::fragment::{decode_fragment, encode_fragment, Fragment, Reassembler};
use crate::socks::{ADDR_UNSUPPORTED, COMMAND_UNSUPPORTED, CONNECTION_REFUSED, GENERAL_FAILURE, HOST_UNREACHABLE, MAX_ADDR_LEN, SUCCESS, TTL_EXPIRED};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

pub const DEFAULT_SOCKS_PORT: u16 = 9050;
pub const SOCKS_VERSION: u8 = 0x05;

/// How long to wait for the exit's CONNECTED/RESOLVED reply before giving
/// up on a circuit. Unused by anything ported so far (the wait itself
/// lives on the unported `SocksServer::_await_reply`).
pub const DEFAULT_CONNECT_TIMEOUT: f64 = 30.0;
/// Total CONNECT/RESOLVE attempts when an `onion_retry` hook is supplied.
/// Unused by anything ported so far.
pub const DEFAULT_MAX_CONNECT_ATTEMPTS: u32 = 3;

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

/// Named SOCKS5 reply codes (RFC 1928).
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

/// A SOCKS5 negotiation failure, carrying the reply code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocksError(pub u8);
impl fmt::Display for SocksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SOCKS5 error (reply code {})", self.0)
    }
}
impl std::error::Error for SocksError {}

/// Exit statuses worth retrying on a *different* circuit -- see
/// `socksproxy.py`'s module docs for the rationale per status.
pub fn retryable_statuses() -> HashSet<u8> {
    [GENERAL_FAILURE, HOST_UNREACHABLE, TTL_EXPIRED, COMMAND_UNSUPPORTED].into_iter().collect()
}
pub fn is_retryable(status: u8) -> bool {
    matches!(status, GENERAL_FAILURE | HOST_UNREACHABLE | TTL_EXPIRED | COMMAND_UNSUPPORTED)
}

/// Map an Allium stream status to a SOCKS5 reply code.
pub fn status_to_socks(status: u8) -> u8 {
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

/// Parse a SOCKS5 address (ATYP + payload). `data` begins with the ATYP
/// byte. Returns `(host, port, consumed)`.
pub fn parse_address(data: &[u8]) -> Result<(String, u16, usize), SocksError> {
    if data.is_empty() {
        return Err(SocksError(REPLY_GENERAL));
    }
    let atyp = data[0];
    match atyp {
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
            let host = String::from_utf8_lossy(&data[2..2 + length]).to_string();
            let port = u16::from_be_bytes([data[2 + length], data[3 + length]]);
            Ok((host, port, 2 + length + 2))
        }
        ATYP_IPV6 => {
            if data.len() < 19 {
                return Err(SocksError(REPLY_GENERAL));
            }
            let raw = &data[1..17];
            let host = (0..16).step_by(2).map(|i| format!("{:02x}{:02x}", raw[i], raw[i + 1])).collect::<Vec<_>>().join(":");
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((host, port, 19))
        }
        _ => Err(SocksError(REPLY_ADDR_UNSUPPORTED)),
    }
}

/// Encode a reply address: IPv4/IPv6 literal, or a domain otherwise.
pub fn encode_address(host: &str, port: u16) -> Vec<u8> {
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        let mut out = vec![ATYP_IPV4];
        out.extend_from_slice(&v4.octets());
        out.extend_from_slice(&port.to_be_bytes());
        return out;
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        let mut out = vec![ATYP_IPV6];
        out.extend_from_slice(&v6.octets());
        out.extend_from_slice(&port.to_be_bytes());
        return out;
    }
    let raw = host.as_bytes();
    let mut out = vec![ATYP_DOMAIN, raw.len().min(MAX_ADDR_LEN) as u8];
    out.extend_from_slice(&raw[..raw.len().min(MAX_ADDR_LEN)]);
    out.extend_from_slice(&port.to_be_bytes());
    out
}

/// Client-side state for one live SOCKS5 UDP ASSOCIATE session.
///
/// `send_fn`/`close_fn` are injected closures, exactly like `exit.rs`'s
/// `UDPAssociation`: the real transport (an `asyncio.DatagramTransport` in
/// Python, a real `tokio::net::UdpSocket` here) is not wired up in this
/// pass (see the module docs), so this struct's own bookkeeping --
/// `touch`/`close`/byte counters/the pinned `client_udp_addr` -- is fully
/// testable without one.
pub struct UdpAssociation {
    pub association_id: u32,
    pub control_peer: Option<(String, u16)>,
    pub client_udp_addr: Option<(String, u16)>,
    pub created_at: f64,
    pub last_activity: f64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub closed: bool,
    close_fn: Option<Box<dyn FnMut() + Send>>,
}

impl UdpAssociation {
    pub fn new(association_id: u32, control_peer: Option<(String, u16)>, close_fn: Option<Box<dyn FnMut() + Send>>, now: f64) -> UdpAssociation {
        UdpAssociation { association_id, control_peer, client_udp_addr: None, created_at: now, last_activity: now, bytes_sent: 0, bytes_received: 0, closed: false, close_fn }
    }

    pub fn touch(&mut self, now: f64) {
        self.last_activity = now;
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

impl fmt::Debug for UdpAssociation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UdpAssociation(id={}, client={:?}, sent={}, received={})", self.association_id, self.client_udp_addr, self.bytes_sent, self.bytes_received)
    }
}

/// Opaque per-circuit token -- see the module docs' "One deviation from
/// Python" note. `None` in a method's `circuit_key` parameter means "use
/// [`SocksServer::default_key`]", mirroring Python's `circuit_key or
/// self._onion`.
pub type CircuitKey = u64;

/// A writer-shaped sink for return-path bytes: `write(data)`, injected so
/// this bookkeeping is testable without a real socket -- the equivalent of
/// Python's duck-typed `writer.write(...)` (an `asyncio.StreamWriter` or a
/// test double, per `socksproxy.py`'s own tests).
pub type Writer = Box<dyn FnMut(&[u8]) + Send>;

/// The subset of `SocksServer` that is pure, synchronous return-path
/// bookkeeping -- see the module docs for what is and is not ported.
pub struct SocksServer {
    default_key: CircuitKey,
    mtu: usize,
    writers: HashMap<(CircuitKey, u32), Writer>,
    reassemblers: HashMap<(CircuitKey, u32), Reassembler>,
    pending_write: HashMap<(CircuitKey, u32), Vec<u8>>,
    closed_streams: HashSet<(CircuitKey, u32)>,
    client_gone: HashSet<(CircuitKey, u32)>,

    // -- live per-connection negotiation/relay loop state; see the
    // "SocksServer -- live per-connection negotiation/relay loop" section
    // further down for what uses each of these. --
    host: String,
    port: u16,
    allow_udp: bool,
    max_connect_attempts: u32,
    connect_timeout_secs: f64,
    retry_connect_timeout_secs: f64,
    next_request_id: u32,
    next_circuit_key_counter: CircuitKey,
    pub retries_attempted: u64,
    pub retries_succeeded: u64,
    onion_datagram: Option<Onion>,
    onion_registry: HashMap<CircuitKey, Onion>,
    onion_router: Option<OnionRouterFn>,
    onion_retry: Option<OnionRetryFn>,
    hidden_service_connect: Option<HiddenServiceConnectFn>,
    onion_stream_started: Option<Box<dyn FnMut(CircuitKey)>>,
    onion_stream_finished: Option<Box<dyn FnMut(CircuitKey)>>,
    request_onion: HashMap<u32, CircuitKey>,
    udp_associations: HashMap<u32, UdpAssociation>,
    // TOKIO-PENDING-FIELD-BEGIN
    pending: HashMap<u32, tokio::sync::oneshot::Sender<crate::socks::StreamReply>>,
    // TOKIO-PENDING-FIELD-END
    // TOKIO-LISTENER-FIELD-BEGIN
    tcp_listener: Option<Rc<tokio::net::TcpListener>>,
    accept_task: Option<tokio::task::JoinHandle<()>>,
    // TOKIO-LISTENER-FIELD-END
    // TOKIO-UDPSOCKS-FIELD-BEGIN
    udp_sockets: HashMap<u32, Rc<tokio::net::UdpSocket>>,
    // TOKIO-UDPSOCKS-FIELD-END
}

impl SocksServer {
    pub fn new(mtu: usize) -> SocksServer {
        SocksServer {
            default_key: 0,
            mtu,
            writers: HashMap::new(),
            reassemblers: HashMap::new(),
            pending_write: HashMap::new(),
            closed_streams: HashSet::new(),
            client_gone: HashSet::new(),
            host: "127.0.0.1".to_string(),
            port: DEFAULT_SOCKS_PORT,
            allow_udp: false,
            max_connect_attempts: 1,
            connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT,
            retry_connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT,
            next_request_id: 0,
            next_circuit_key_counter: 0,
            retries_attempted: 0,
            retries_succeeded: 0,
            onion_datagram: None,
            onion_registry: HashMap::new(),
            onion_router: None,
            onion_retry: None,
            hidden_service_connect: None,
            onion_stream_started: None,
            onion_stream_finished: None,
            request_onion: HashMap::new(),
            udp_associations: HashMap::new(),
            pending: HashMap::new(),
            tcp_listener: None,
            accept_task: None,
            udp_sockets: HashMap::new(),
        }
    }

    /// The key every call site that predates stream isolation used, and
    /// that every `circuit_key: None` argument below resolves to.
    pub fn default_key(&self) -> CircuitKey {
        self.default_key
    }

    fn resolve_key(&self, circuit_key: Option<CircuitKey>) -> CircuitKey {
        circuit_key.unwrap_or(self.default_key)
    }

    /// Register a writer for a stream (test/harness hook -- in the full
    /// port this happens as a side effect of `_relay_stream` starting).
    pub fn register_writer(&mut self, circuit_key: Option<CircuitKey>, stream_id: u32, writer: Writer) {
        let key = (self.resolve_key(circuit_key), stream_id);
        self.writers.insert(key, writer);
    }

    fn live_writer(&mut self, key: (CircuitKey, u32)) -> bool {
        self.writers.contains_key(&key)
    }

    fn drop_client(&mut self, key: (CircuitKey, u32)) {
        self.writers.remove(&key);
        self.reassemblers.remove(&key);
        self.pending_write.remove(&key);
        self.client_gone.insert(key);
    }

    /// Close a client stream once the exit says its response has ended.
    pub fn close_stream(&mut self, stream_id: u32, circuit_key: Option<CircuitKey>) -> bool {
        let key = (self.resolve_key(circuit_key), stream_id);
        let had_writer = self.writers.remove(&key).is_some();
        self.closed_streams.insert(key);
        self.client_gone.remove(&key);
        if had_writer {
            self.flush_pending(key.0, stream_id);
        }
        had_writer
    }

    /// Write already-reassembled return bytes to *one* stream's client.
    /// Returns `true` if written now (buffering counts as not-yet-written).
    pub fn write_to_stream(&mut self, stream_id: u32, payload: &[u8], circuit_key: Option<CircuitKey>) -> bool {
        if payload.is_empty() {
            return false;
        }
        let key = (self.resolve_key(circuit_key), stream_id);
        if self.client_gone.contains(&key) {
            return false;
        }
        if !self.live_writer(key) {
            self.pending_write.entry(key).or_default().extend_from_slice(payload);
            return false;
        }
        if let Some(w) = self.writers.get_mut(&key) {
            w(payload);
        }
        true
    }

    /// Hand a stream's buffered early return data to its newly started
    /// client connection.
    pub fn flush_pending(&mut self, circuit_key: CircuitKey, stream_id: u32) {
        let key = (circuit_key, stream_id);
        let Some(data) = self.pending_write.remove(&key) else {
            return;
        };
        if data.is_empty() {
            return;
        }
        if !self.live_writer(key) {
            self.drop_client(key);
            return;
        }
        if let Some(w) = self.writers.get_mut(&key) {
            w(&data);
        }
    }

    /// Reassemble a return-path fragment and write it to the SOCKS client.
    /// Returns the bytes that were written (empty when buffered, unknown,
    /// or the client socket is gone).
    pub fn deliver_data(&mut self, stream_id: u32, payload: &[u8], circuit_key: Option<CircuitKey>) -> Vec<u8> {
        let key = (self.resolve_key(circuit_key), stream_id);
        if self.client_gone.contains(&key) {
            return Vec::new();
        }
        if !self.reassemblers.contains_key(&key) {
            self.reassemblers.insert(key, Reassembler::new(stream_id, 1024));
        }
        let frag: Fragment = match decode_fragment(payload) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let data = {
            let reassembler = self.reassemblers.get_mut(&key).unwrap();
            match reassembler.push(&frag) {
                Ok(d) => d,
                Err(_) => return Vec::new(),
            }
        };
        if !data.is_empty() {
            if !self.live_writer(key) {
                // Mirror `write_to_stream`'s fallback: `_relay_stream`
                // (this port's client-side CONNECT relay loop) never
                // registers a `writers` entry at all -- it polls
                // `pending_write` itself each iteration instead (see its
                // doc comment) -- so a live writer is normally *never*
                // present for an ordinary CONNECT stream. Before this fix,
                // that meant every reassembled return-path chunk was
                // silently dropped here instead of being buffered for
                // `_relay_stream` to pick up, which was the final root
                // cause of a live 3-hop CONNECT stream hanging forever
                // even after the exit's forward/backward fragment framing
                // was fixed: bytes reached the client's UDP socket but
                // `deliver_data` threw them away before `_relay_stream`
                // ever saw them.
                self.pending_write.entry(key).or_default().extend_from_slice(&data);
                return data;
            }
            if let Some(w) = self.writers.get_mut(&key) {
                w(&data);
            }
        }
        data
    }

    /// Fragment `payload` for `stream_id` at this server's configured MTU
    /// -- the pure half of `_relay_stream`'s outbound path (chunking and
    /// framing only; actually sending each chunk through `onion` and
    /// pacing large bursts is part of the un-ported live relay loop).
    pub fn fragment_outbound(&self, stream_id: u32, offset: u32, payload: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut off = offset;
        let mut remaining = payload;
        while !remaining.is_empty() {
            let take = remaining.len().min(self.mtu);
            let (chunk, rest) = remaining.split_at(take);
            out.push(encode_fragment(&Fragment { stream_id, offset: off, fin: false, data: chunk.to_vec() }));
            off += chunk.len() as u32;
            remaining = rest;
        }
        out
    }
}

// ---------------------------------------------------------------------------
// SocksExit
// ---------------------------------------------------------------------------
//
// Added in a follow-up pass now that `allium::relay`'s
// `RelayNode` is real. Python's `SocksExit` is a mixin
// (`class MyExit(SocksExit, RelayNode): pass`) overriding `RelayNode`'s
// `deliver`/`handle_create`; Rust has no method override, so this is wired
// by composition instead, through the two hooks `RelayNode` added
// specifically for this (`deliver_fn`, `post_create_hook`) -- the same
// pattern already used for `RelayNode::deliver_fn` in `relay.rs` itself.
//
// **Egress concurrency, a deliberate deviation from a naive port:** Python's
// `Egress` is touched from multiple concurrently-running `asyncio` tasks
// (one per in-flight stream/datagram request) with no explicit lock, since
// `asyncio` guarantees only one coroutine actually runs at a time and
// `Egress`'s own `await` points are its only yield points. A direct port
// to `Rc<RefCell<Egress>>` would reproduce that only until two requests
// overlap: `RefCell::borrow_mut()` held across an `.await` (which
// `Egress::handle_request`/`handle_datagram` both need) panics the moment a
// second task tries to borrow while the first is still suspended inside
// its own await. `Rc<tokio::sync::Mutex<Egress>>` is used instead --
// `tokio::sync::Mutex` is async-aware and can be held across an `.await`,
// so a second concurrent request queues instead of panicking (each request
// still runs to completion before the next starts touching `Egress`,
// serialised rather than truly concurrent, a real but non-unsound
// simplification worth calling out).
//
// **What could not be exercised for real in this pass:** everything below
// is, like the rest of this crate's tokio-touching code, written against
// stable, well-documented `tokio` APIs but unverified pending a real
// `cargo build` outside this sandbox -- see the sentinel block below and
// its stub script.

use crate::cell::Command;
use crate::exit::Egress;
use crate::hswire::HsReassembler;
use crate::layer::Kind;
use crate::onion::seal_into_cell;
use crate::relay::{CircuitKeyTuple, RelayNode};
use crate::socks::{decode_ack_frame, decode_datagram_request, decode_request, DatagramRequest, StreamRequest, ACK_MAGIC, DATAGRAM_MAGIC, MAGIC};
use std::cell::RefCell;
use std::rc::Rc;

/// A stream body fragment reassembler cannot be allowed to grow without
/// bound (a client could send fragments under an endless number of
/// `stream_id`s and never `FIN`); mirrors `allium_cli.py`'s
/// `_MAX_PENDING_STREAM_REASSEMBLERS`.
const MAX_PENDING_STREAM_REASSEMBLERS: usize = 4096;
/// Most reassemblers one circuit may hold. A circuit can have at most
/// `crate::exit::MAX_STREAMS_PER_CIRCUIT` live streams; the extra headroom
/// covers streams that closed but are still draining.
const MAX_STREAM_REASSEMBLERS_PER_CIRCUIT: usize = 128;
/// Most bytes one stream's reassembler may hold *out of order*.
const MAX_STREAM_REASSEMBLER_BYTES: usize = 1024 * 1024;
/// Most out-of-order bytes held across every stream reassembler.
const MAX_STREAM_REASSEMBLY_BYTES: usize = 64 * 1024 * 1024;
/// A reassembler untouched this long may be purged when the table is full.
const STREAM_REASSEMBLER_IDLE: Duration = Duration::from_secs(120);

struct StreamReassemblerEntry {
    reassembler: Reassembler,
    buffered: usize,
    last_used: Instant,
}

/// Per-`(circuit, stream_id)` reassembly for an exit's inbound stream data.
///
/// `stream_id` is chosen by the (untrusted) client, so this table is
/// bounded per circuit, in total, and in buffered bytes. A live reassembler
/// is never evicted to make room: dropping its position would corrupt, or
/// let a later retransmission replay, a real stream. Under pressure only
/// finished or long-idle entries are purged, and a fragment that still
/// does not fit is dropped.
#[derive(Default)]
struct StreamReassemblers {
    map: HashMap<(CircuitKeyTuple, u32), StreamReassemblerEntry>,
    per_circuit: HashMap<CircuitKeyTuple, usize>,
    buffered_total: usize,
}

impl StreamReassemblers {
    /// Feed one fragment. Returns newly contiguous bytes (empty if the
    /// fragment was buffered, was a duplicate, or was dropped by a bound).
    fn push(&mut self, key: &CircuitKeyTuple, fragment: &Fragment) -> Vec<u8> {
        let entry_key = (key.clone(), fragment.stream_id);
        if !self.map.contains_key(&entry_key) {
            if self.per_circuit.get(key).copied().unwrap_or(0) >= MAX_STREAM_REASSEMBLERS_PER_CIRCUIT {
                return Vec::new();
            }
            if self.map.len() >= MAX_PENDING_STREAM_REASSEMBLERS {
                self.purge_stale();
                if self.map.len() >= MAX_PENDING_STREAM_REASSEMBLERS {
                    return Vec::new();
                }
            }
            self.map.insert(
                entry_key.clone(),
                StreamReassemblerEntry {
                    reassembler: Reassembler::with_defaults(fragment.stream_id),
                    buffered: 0,
                    last_used: Instant::now(),
                },
            );
            *self.per_circuit.entry(key.clone()).or_insert(0) += 1;
        }
        let total = self.buffered_total;
        let entry = self.map.get_mut(&entry_key).expect("entry just ensured");
        // An in-order fragment is consumed at once, so only fragments that
        // would be *buffered* count against the byte bounds.
        let would_buffer = fragment.offset != entry.reassembler.expected_offset();
        if would_buffer
            && (entry.buffered + fragment.data.len() > MAX_STREAM_REASSEMBLER_BYTES
                || total + fragment.data.len() > MAX_STREAM_REASSEMBLY_BYTES)
        {
            return Vec::new();
        }
        entry.last_used = Instant::now();
        let out = entry.reassembler.push(fragment).unwrap_or_default();
        let now_buffered = entry.reassembler.pending_bytes();
        self.buffered_total = self.buffered_total - entry.buffered + now_buffered;
        entry.buffered = now_buffered;
        let finished = entry.reassembler.finished();
        if finished {
            // Free this stream's slot the moment it completes, rather than
            // waiting for `purge_stale` (only run once the *global* table
            // is full). Without this, a normal client that reuses one
            // circuit for more than `MAX_STREAM_REASSEMBLERS_PER_CIRCUIT`
            // streams in a row gets its requests silently dropped from
            // stream 129 on, even though every earlier stream on that
            // circuit has long since finished.
            self.buffered_total -= now_buffered;
            self.map.remove(&entry_key);
            if let Some(n) = self.per_circuit.get_mut(key) {
                *n -= 1;
                if *n == 0 {
                    self.per_circuit.remove(key);
                }
            }
        }
        out
    }

    /// Drop everything a forgotten circuit was holding.
    fn forget_circuit(&mut self, key: &CircuitKeyTuple) {
        self.per_circuit.remove(key);
        let mut freed = 0;
        self.map.retain(|(k, _), e| {
            if k == key {
                freed += e.buffered;
                false
            } else {
                true
            }
        });
        self.buffered_total -= freed;
    }

    /// Remove finished or long-idle reassemblers (only called under pressure).
    fn purge_stale(&mut self) {
        let now = Instant::now();
        let mut freed = 0;
        let mut dropped: Vec<CircuitKeyTuple> = Vec::new();
        self.map.retain(|(k, _), e| {
            let stale = e.reassembler.finished() || now.duration_since(e.last_used) > STREAM_REASSEMBLER_IDLE;
            if stale {
                freed += e.buffered;
                dropped.push(k.clone());
            }
            !stale
        });
        self.buffered_total -= freed;
        for k in dropped {
            if let Some(n) = self.per_circuit.get_mut(&k) {
                *n -= 1;
                if *n == 0 {
                    self.per_circuit.remove(&k);
                }
            }
        }
    }
}

// Round J: hidden-service intro/rendezvous relay dispatch constants --
// mirror `allium_cli.py`'s `_HS_ESTABLISH_INTRO_FRESHNESS`/
// `_MAX_PENDING_HS_REASSEMBLERS`/`_MAX_HS_INTRO_REGISTRATIONS`/
// `_MAX_HS_PENDING_RENDEZVOUS` exactly.
const HS_ESTABLISH_INTRO_FRESHNESS: f64 = 300.0;
const MAX_PENDING_HS_REASSEMBLERS: usize = 4096;
/// Most bytes held across every hidden-service reassembler on this relay
/// (in-order plus out-of-order). Non-joined circuits are additionally held
/// to `crate::hswire::MAX_CONTROL_MESSAGE_LEN` each.
const MAX_HS_REASSEMBLY_BYTES: usize = 64 * 1024 * 1024;
const MAX_HS_INTRO_REGISTRATIONS: usize = 4096;
const MAX_HS_PENDING_RENDEZVOUS: usize = 4096;
/// Most introduction-point registrations one circuit may hold. An honest
/// service registers one key per intro circuit; nothing is gained by
/// letting a single circuit pin hundreds.
const MAX_HS_INTRO_PER_CIRCUIT: usize = 4;
/// Most rendezvous joins one circuit may have waiting at once (an honest
/// rendezvous circuit joins exactly one cookie).
const MAX_HS_PENDING_RENDEZVOUS_PER_CIRCUIT: usize = 2;
/// A rendezvous join still waiting for its partner after this long is
/// abandoned: both sides give up after about 30 seconds, so anything older
/// is stale (or hostile) and must not hold a slot or block a newcomer.
const HS_PENDING_RENDEZVOUS_MAX_AGE_SECS: f64 = 90.0;

/// Sustained and burst
/// budget for one registered intro point's INTRODUCE1 traffic, applied per
/// `auth_pubkey`. Without this, forwarding an INTRODUCE1 costs this relay
/// almost nothing but can trigger a full rendezvous-circuit build on the
/// service -- see `hs_handle_introduce1`.
const INTRODUCE1_RATE_PER_SEC: f64 = 5.0;
const INTRODUCE1_BURST_TOKENS: f64 = 20.0;

/// The shared bucket above has no per-sender
/// sub-limit, so any anonymous client that knows a service's public intro
/// point (trivial -- it's in the descriptor) can alone consume the whole
/// shared budget and deny legitimate introductions to that service. This
/// smaller, tighter bucket is checked per (auth_pubkey, sending circuit)
/// -- see `hs_handle_introduce1`, which requires *both* this and the
/// shared bucket to allow an INTRODUCE1 through.
const INTRODUCE1_PER_SENDER_RATE_PER_SEC: f64 = 1.0;
const INTRODUCE1_PER_SENDER_BURST_TOKENS: f64 = 4.0;
/// Analogous to `MAX_HS_INTRO_REGISTRATIONS` for `intro_rate`, sized
/// larger since this map has one entry per (service, sender) pair rather
/// than one per service.
const MAX_HS_INTRO_PER_SENDER_LIMITERS: usize = 16384;

/// A small token bucket. Continuously refills at `rate_per_sec`
/// tokens/second up to `burst_tokens`; each forwarded INTRODUCE1 spends
/// one token. One instance per registered `auth_pubkey` (the shared
/// budget), and a second, tighter one per (`auth_pubkey`, sending
/// circuit) pair.
struct IntroRateLimiter {
    tokens: f64,
    last: f64,
    rate_per_sec: f64,
    burst_tokens: f64,
}

impl IntroRateLimiter {
    fn new(now: f64, rate_per_sec: f64, burst_tokens: f64) -> Self {
        IntroRateLimiter { tokens: burst_tokens, last: now, rate_per_sec, burst_tokens }
    }

    /// Refill for the elapsed time, then try to spend one token. Returns
    /// whether this INTRODUCE1 is allowed through.
    fn allow(&mut self, now: f64) -> bool {
        let elapsed = (now - self.last).max(0.0);
        self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.burst_tokens);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl HsRelayState {
    /// Feed one stream-0 fragment for `key`'s reassembler under the size
    /// bounds. A circuit that has not joined a rendezvous may hold only a
    /// control message's worth; the whole relay is held to
    /// `MAX_HS_REASSEMBLY_BYTES`; at the entry cap the biggest holder is
    /// evicted (most likely the one abusing the table), not an arbitrary
    /// entry that may be a legitimate peer's.
    fn hs_push(&mut self, key: &CircuitKeyTuple, payload: &[u8]) -> Option<Vec<u8>> {
        if !self.reassemblers.contains_key(key) && self.reassemblers.len() >= MAX_PENDING_HS_REASSEMBLERS {
            let biggest = self.reassemblers.iter().max_by_key(|(_, r)| r.buffered_bytes()).map(|(k, _)| k.clone());
            if let Some(k) = biggest {
                self.hs_drop_reassembler(&k);
            }
        }
        if self.reassembly_bytes + payload.len() > MAX_HS_REASSEMBLY_BYTES {
            return None;
        }
        let limit = if self.partner.contains_key(key) {
            crate::hswire::MAX_REASSEMBLED_LEN
        } else {
            crate::hswire::MAX_CONTROL_MESSAGE_LEN
        };
        let reassembler = self.reassemblers.entry(key.clone()).or_insert_with(HsReassembler::with_defaults);
        let before = reassembler.buffered_bytes();
        let result = reassembler.push_limited(payload, limit);
        let after = reassembler.buffered_bytes();
        self.reassembly_bytes = self.reassembly_bytes - before + after;
        match result {
            Ok(Some(m)) => Some(m),
            _ => None, // more fragments to come, or a malformed/oversized message: dropped
        }
    }

    /// Remove `key`'s reassembler and release the bytes it held.
    fn hs_drop_reassembler(&mut self, key: &CircuitKeyTuple) {
        if let Some(r) = self.reassemblers.remove(key) {
            self.reassembly_bytes -= r.buffered_bytes();
        }
    }
}

/// This relay's hidden-service intro/rendezvous state -- port of
/// `allium_cli.py`'s `ExitNode._hs_intro`/`_hs_pending_rendezvous`/
/// `_hs_partner`/`_hs_reassemblers` (kept as one struct here rather than
/// four separate fields on `SocksExit`, since `SocksExit` itself is a
/// zero-sized composition marker with no fields at all -- see its own
/// docs). `partner` is keyed by the *full* `CircuitKeyTuple` on both
/// sides (Python keys `_hs_partner` by the bare `incoming_circuit_id`,
/// which is unique only per predecessor address -- using the full tuple
/// here is strictly safer, not a protocol change, matching this file's
/// existing `CircuitKey` deviation elsewhere).
#[derive(Default)]
struct HsRelayState {
    reassemblers: HashMap<CircuitKeyTuple, HsReassembler>,
    /// Sum of `buffered_bytes()` over `reassemblers`; kept in step by
    /// `hs_push` and `hs_drop_reassembler`.
    reassembly_bytes: usize,
    /// per-intro-point auth pubkey -> the intro circuit that registered it.
    intro: HashMap<Vec<u8>, CircuitKeyTuple>,
    /// per-intro-point auth pubkey -> its INTRODUCE1 token bucket. Entries are added lazily on
    /// first INTRODUCE1 and removed alongside `intro` in `forget_hook`;
    /// `hs_handle_introduce1` also caps this map's own size the same way
    /// `hs_handle_establish_intro` caps `intro`, since an `intro` entry can
    /// be evicted (MAX_HS_INTRO_REGISTRATIONS) out from under a still-open
    /// circuit, which would otherwise orphan its rate-limiter entry here.
    intro_rate: HashMap<Vec<u8>, IntroRateLimiter>,
    /// (auth pubkey, sending circuit) -> that sender's own tighter
    /// INTRODUCE1 token bucket. Same
    /// lifecycle/cap discipline as `intro_rate`: capped at
    /// `MAX_HS_INTRO_PER_SENDER_LIMITERS`, evicting an arbitrary entry
    /// when full, and cleaned up in `forget_hook` both when the
    /// auth_pubkey's registration goes away and when the sending circuit
    /// itself does.
    intro_rate_per_sender: HashMap<(Vec<u8>, CircuitKeyTuple), IntroRateLimiter>,
    /// rendezvous cookie -> the first circuit to RENDEZVOUS_JOIN with it,
    /// waiting for the second.
    pending_rendezvous: HashMap<Vec<u8>, (CircuitKeyTuple, f64)>,
    /// circuit key -> the *other* side's circuit key, once a rendezvous
    /// pair has joined -- how RENDEZVOUS_DATA finds its partner.
    partner: HashMap<CircuitKeyTuple, CircuitKeyTuple>,
}

impl HsRelayState {
    /// Register `auth_pubkey` as served over circuit `key`.
    ///
    /// Bounded so that registering is never a way to push an honest service
    /// out: one circuit may hold at most [`MAX_HS_INTRO_PER_CIRCUIT`]; and
    /// when the table is full a newcomer is admitted only by evicting a
    /// registration from a circuit that holds *strictly more* than the
    /// newcomer's circuit would after registering -- i.e. from whoever is
    /// hoarding -- never from an equal or a smaller holder. If no hoarder
    /// exists the newcomer is refused. (The previous behaviour evicted an
    /// arbitrary entry, which could be a legitimate service's.)
    ///
    /// Re-registering a key on the circuit that already holds it is a no-op.
    /// Registering a key held by another circuit moves it (a service that
    /// reconnected before the old circuit was forgotten); the signature on
    /// ESTABLISH_INTRO already proved the caller owns the key.
    fn register_intro(&mut self, auth_pubkey: Vec<u8>, key: &CircuitKeyTuple) -> Result<(), &'static str> {
        if self.intro.get(&auth_pubkey) == Some(key) {
            return Ok(());
        }
        let held_by_key = self.intro.values().filter(|v| *v == key).count();
        if held_by_key >= MAX_HS_INTRO_PER_CIRCUIT {
            return Err("too many registrations on this circuit");
        }
        if !self.intro.contains_key(&auth_pubkey) && self.intro.len() >= MAX_HS_INTRO_REGISTRATIONS {
            let mut counts: HashMap<&CircuitKeyTuple, usize> = HashMap::new();
            for v in self.intro.values() {
                *counts.entry(v).or_insert(0) += 1;
            }
            let hoarder = counts.into_iter().max_by_key(|(_, n)| *n).filter(|(_, n)| *n > held_by_key + 1).map(|(c, _)| c.clone());
            let Some(hoarder) = hoarder else {
                return Err("introduction table full");
            };
            let victim = self.intro.iter().find(|(_, v)| **v == hoarder).map(|(k, _)| k.clone());
            if let Some(victim) = victim {
                self.drop_intro(&victim);
            }
        }
        self.intro.insert(auth_pubkey, key.clone());
        Ok(())
    }

    /// Remove one registration and every rate-limiter entry tied to it.
    fn drop_intro(&mut self, auth_pubkey: &[u8]) {
        self.intro.remove(auth_pubkey);
        self.intro_rate.remove(auth_pubkey);
        self.intro_rate_per_sender.retain(|(a, _), _| a.as_slice() != auth_pubkey);
    }

    /// Take the circuit waiting on `cookie`, if one is waiting and not stale.
    fn take_pending_rendezvous(&mut self, cookie: &[u8], now: f64) -> Option<CircuitKeyTuple> {
        let (first, at) = self.pending_rendezvous.remove(cookie)?;
        if now - at > HS_PENDING_RENDEZVOUS_MAX_AGE_SECS {
            return None; // abandoned: do not pair a live join with a dead one
        }
        Some(first)
    }

    /// Record `key` as waiting on `cookie`, within the same kind of bounds:
    /// a per-circuit cap, stale entries purged first, and a full table
    /// refuses the newcomer instead of evicting someone else's wait.
    fn register_pending_rendezvous(&mut self, cookie: Vec<u8>, key: &CircuitKeyTuple, now: f64) -> Result<(), &'static str> {
        if self.pending_rendezvous.values().filter(|(c, _)| c == key).count() >= MAX_HS_PENDING_RENDEZVOUS_PER_CIRCUIT {
            return Err("too many pending joins on this circuit");
        }
        if self.pending_rendezvous.len() >= MAX_HS_PENDING_RENDEZVOUS {
            self.pending_rendezvous.retain(|_, (_, at)| now - *at <= HS_PENDING_RENDEZVOUS_MAX_AGE_SECS);
            if self.pending_rendezvous.len() >= MAX_HS_PENDING_RENDEZVOUS {
                return Err("rendezvous table full");
            }
        }
        self.pending_rendezvous.insert(cookie, (key.clone(), now));
        Ok(())
    }

    /// Whether an INTRODUCE1 from `sender` naming `auth_pubkey` should be
    /// forwarded: pure decision logic pulled out of `hs_handle_introduce1`
    /// so it's testable without a tokio runtime or a real circuit. Checks
    /// (and, on success, spends from) the per-sender bucket *before* the
    /// shared per-`auth_pubkey` bucket, so
    /// a sender who has already exhausted their own share never drains
    /// the shared budget other senders of the same service depend on.
    fn allow_introduce1(&mut self, auth_pubkey: &[u8], sender: &CircuitKeyTuple, now: f64) -> bool {
        let sender_key = (auth_pubkey.to_vec(), sender.clone());
        if !self.intro_rate_per_sender.contains_key(&sender_key) && self.intro_rate_per_sender.len() >= MAX_HS_INTRO_PER_SENDER_LIMITERS {
            if let Some(oldest) = self.intro_rate_per_sender.keys().next().cloned() {
                self.intro_rate_per_sender.remove(&oldest);
            }
        }
        let per_sender_allowed = self
            .intro_rate_per_sender
            .entry(sender_key)
            .or_insert_with(|| IntroRateLimiter::new(now, INTRODUCE1_PER_SENDER_RATE_PER_SEC, INTRODUCE1_PER_SENDER_BURST_TOKENS))
            .allow(now);
        if !per_sender_allowed {
            return false;
        }

        if !self.intro_rate.contains_key(auth_pubkey) && self.intro_rate.len() >= MAX_HS_INTRO_REGISTRATIONS {
            if let Some(oldest) = self.intro_rate.keys().next().cloned() {
                self.intro_rate.remove(&oldest);
            }
        }
        self.intro_rate
            .entry(auth_pubkey.to_vec())
            .or_insert_with(|| IntroRateLimiter::new(now, INTRODUCE1_RATE_PER_SEC, INTRODUCE1_BURST_TOKENS))
            .allow(now)
    }
}

// ---------------------------------------------------------------------------
// Backward-path reliability (retransmit on loss)
// ---------------------------------------------------------------------------
//
// Fix (found live: a Rust-relay-only YouTube regression -- video stalled or
// never loaded through this port's relays, but played fine through the
// Python original's, same client, same network, same VPS). Root cause:
// `send_backward` fired every returned-data fragment over UDP once, with
// nothing tracking whether it ever arrived. Hop to hop this protocol's
// transport is plain UDP -- real loss happens on a real WAN link -- and
// Python's exit recovers a lost fragment itself (`ExitNode._retransmit_buffers`/
// `_retransmit_sweep`, below); this port's didn't, so any one lost
// fragment left a permanent gap in the client's reassembler and the whole
// stream just hung. A handful of small requests (a page shell, a
// thumbnail) rarely hit this; a video, made of hundreds of fragments,
// hits it reliably.
//
// The client's half of this was already fully built and just waiting for
// an exit that uses it: `allium_cli::helpers::encode_ack_frame`/
// `CircuitTransport::send_ack`/`force_ack` already send real `ACK_MAGIC`
// frames reporting a stream's contiguous-received watermark. This section
// is the missing exit-side half: buffer every sent fragment, prune it on
// ack, and periodically resend whatever timed out unacked -- a faithful
// port of `allium_cli.py`'s `ExitNode._retransmit_buffers`/
// `_buffer_for_retransmit`/`_handle_ack`/`_retransmit_sweep`/
// `RETURN_WINDOW_FRAGMENTS`.

/// How long the exit waits for a returned-data fragment to be acked
/// before assuming it was lost and resending it. Generous headroom over a
/// real end-to-end round trip, not a tight estimate: a spuriously early
/// retransmit costs a few wasted bytes, too long a wait just delays
/// recovery from a real loss. Port of `allium_cli.py`'s `RETRANSMIT_TIMEOUT`
/// (2.5s).
const RETRANSMIT_TIMEOUT: Duration = Duration::from_millis(2500);

/// How often [`SocksExit::retransmit_sweep`] wakes to look for a timed-out
/// fragment -- half of [`RETRANSMIT_TIMEOUT`], matching
/// `_retransmit_sweep`'s own sleep, so a fragment is never more than half
/// a timeout late in being noticed.
const RETRANSMIT_SWEEP_INTERVAL: Duration = Duration::from_millis(1250);

/// Give up retransmitting a fragment after this many attempts -- a client
/// that vanished (rather than merely being slow) must not be retried
/// forever. Port of `RETRANSMIT_MAX_ATTEMPTS`.
const RETRANSMIT_MAX_ATTEMPTS: u32 = 8;

/// Hard cap on unacknowledged fragments buffered per `(circuit, stream)`,
/// bounding memory if acks stop arriving entirely. Port of
/// `RETRANSMIT_MAX_PENDING`. Well above [`RETURN_WINDOW_FRAGMENTS`], so
/// eviction here is a last resort, never the normal case.
const RETRANSMIT_MAX_PENDING: usize = 4096;

/// Send window: [`SocksExit::send_backward`] stops putting *new*
/// fragments in flight on a stream once this many are unacknowledged, and
/// resumes as acks free space. Without this, a lost fragment freezes the
/// client's cumulative ack while the exit keeps sending regardless, the
/// unacked backlog blows through [`RETRANSMIT_MAX_PENDING`], and eviction
/// starts dropping fragments the client is still waiting on -- large
/// downloads then stall or arrive truncated. Port of
/// `RETURN_WINDOW_FRAGMENTS`.
const RETURN_WINDOW_FRAGMENTS: usize = 2048;

/// Longest [`SocksExit::send_backward`] waits for window space before
/// sending anyway -- a client that stopped acking entirely must not wedge
/// this wait forever. Port of `RETURN_WINDOW_MAX_WAIT`.
///
/// **Deviation from `allium_cli.py`**: Python schedules one task per
/// `_send_backward` call, so one stream waiting on window space never
/// blocks another's. This port's backward sends are drained by one single
/// consumer task (see `install`'s `backward_rx` loop), so a wait here
/// delays every other circuit's return traffic too. Left at Python's own
/// generous value anyway, because reaching this wait at all requires a
/// client that has *stopped acking entirely* -- ordinary loss recovers via
/// retransmit without ever touching the window -- and 2048 fragments of
/// headroom makes that already rare. A future fix should either give each
/// stream its own send task or shorten this considerably.
const RETURN_WINDOW_MAX_WAIT: Duration = Duration::from_secs(30);

/// How often [`SocksExit::send_backward`]'s send-window wait re-checks
/// for freed space.
const RETURN_WINDOW_POLL: Duration = Duration::from_millis(10);

/// The actual backpressure knob.
/// [`SocksExit::install`]'s `emit` closure (shared by every stream's
/// `Egress::handle_request`/`pump_stream`) refuses to queue more than this
/// many not-yet-fully-sent chunks for one `(circuit, stream)` at a time --
/// `Egress::pump_stream` treats a refusal as "the return path can't keep
/// up" and closes the stream instead of reading (and holding in memory)
/// more of the destination's data. A chunk counts as outstanding from the
/// moment `emit` queues it until `SocksExit::send_backward` finishes
/// sending it (including any `RETURN_WINDOW_FRAGMENTS` wait for a fragment
/// that itself doesn't get acked), so this bounds not just the exit-wide
/// channel below but the *whole* pipeline a stalled client's data can pile
/// up in -- fixing "the exit reads the destination socket as fast as it
/// delivers and queues every chunk on an unbounded channel; nothing slows
/// the read side when the return path is stalled". At `DEFAULT_MTU`-sized
/// (well under 4 KiB) chunks, this caps one stream's outstanding backward
/// data at a few hundred KB.
const MAX_INFLIGHT_BACKWARD_CHUNKS_PER_STREAM: usize = 64;

/// Exit-wide cap on the backward-pump channel [`SocksExit::install`]
/// creates -- a bounded `mpsc::channel`, not `unbounded_channel`, so total
/// exit memory for not-yet-dispatched backward chunks has a hard ceiling
/// independent of [`MAX_INFLIGHT_BACKWARD_CHUNKS_PER_STREAM`] (which only
/// bounds any *one* stream). Comfortably above what ordinary concurrent
/// traffic needs; only reached if something is already wrong (e.g. the
/// consumer loop itself falling behind).
const BACKWARD_CHANNEL_CAPACITY: usize = 4096;

/// After this many fragments sent back to back (a fresh burst or a
/// retransmit sweep), pause briefly so a downstream single-threaded
/// relay's receive-decrypt-forward loop gets a chance to drain its socket
/// instead of the burst outrunning it and dropping a cell. Not real
/// congestion control -- no feedback loop, just a fixed breather. Port of
/// `SEND_PACE_EVERY`/`SEND_PACE_DELAY`.
const SEND_PACE_EVERY: u32 = 24;
const SEND_PACE_DELAY: Duration = Duration::from_millis(3);

/// One already-sent backward-path fragment, kept until acked or given up
/// on. Port of `allium_cli.py`'s `_retransmit_buffers` value tuple
/// `[encoded, first_sent_at, last_sent_at, attempts, entry]` -- `entry`
/// (the live circuit-table row) isn't kept here: every resend re-looks-up
/// the circuit fresh by key instead (see [`SocksExit::send_backward_sealed`]),
/// so nothing needs to pin a (possibly since-expired) circuit reference.
struct RetransmitEntry {
    encoded: Vec<u8>,
    last_sent: Instant,
    attempts: u32,
}

/// Per-`(circuit, stream)` retransmit state for this exit's backward
/// path. Port of `allium_cli.py`'s `ExitNode._retransmit_buffers`/
/// `_fin_offsets`, grouped into one struct (rather than two parallel
/// tables) since every real use site needs both together.
#[derive(Default)]
struct RetransmitState {
    /// `(circuit key, stream id) -> offset -> that fragment's retransmit
    /// bookkeeping`. The inner table is a `BTreeMap`, not a `HashMap` like
    /// Python's plain `dict`, so [`SocksExit::buffer_for_retransmit`]'s
    /// over-capacity eviction can find the *newest* offset in O(log n)
    /// via `keys().next_back()` instead of a linear scan.
    pending: HashMap<(CircuitKeyTuple, u32), BTreeMap<u32, RetransmitEntry>>,
    /// `(circuit key, stream id) -> the offset its buffered FIN fragment
    /// carries`, so the client's final cumulative ack (which names the
    /// byte *after* the FIN, not the FIN's own placeholder offset) still
    /// releases it. Port of `_fin_offsets`.
    fin_offsets: HashMap<(CircuitKeyTuple, u32), u32>,
}

/// Composition stand-in for Python's `class MyExit(SocksExit, RelayNode)`.
/// [`SocksExit::install`] wires a [`RelayNode`] to route delivered payloads
/// through `egress` and to auto-register every successful handshake as an
/// exit circuit -- see the module docs above for the concurrency model.
pub struct SocksExit;

impl SocksExit {
    /// Turn `node` into a SOCKS-capable exit backed by `egress`.
    // TOKIO-INSTALL-BEGIN
    pub fn install(node: &Rc<RefCell<RelayNode>>, egress: Rc<tokio::sync::Mutex<Egress>>) {
        // Bounded, not
        // `unbounded_channel` -- see `BACKWARD_CHANNEL_CAPACITY`'s docs.
        // Each item also now carries the sending stream's in-flight-chunk
        // counter (see `MAX_INFLIGHT_BACKWARD_CHUNKS_PER_STREAM`), which
        // this loop's spawned per-item task decrements once
        // `send_backward` actually finishes with it.
        let (backward_tx, mut backward_rx) = tokio::sync::mpsc::channel::<(CircuitKeyTuple, u32, Vec<u8>, Arc<AtomicUsize>)>(BACKWARD_CHANNEL_CAPACITY);
        let sink_node = node.clone();
        // Per-`(circuit key, stream_id)` next-send offset for the
        // fragmenting half of `send_backward` -- mirrors `allium_cli.py`'s
        // `ExitNode._return_offsets`.
        let offsets: Rc<RefCell<HashMap<(CircuitKeyTuple, u32), u32>>> = Rc::new(RefCell::new(HashMap::new()));
        // Backward-path reliability state (buffered unacked fragments plus
        // each stream's buffered-FIN offset) -- mirrors `allium_cli.py`'s
        // `ExitNode._retransmit_buffers`/`_fin_offsets`. Shared by the
        // pump task below (buffers what it sends), `retransmit_sweep`
        // (resends what times out), and `deliver`'s `ACK_MAGIC` branch
        // (prunes what gets acked).
        let retransmit: Rc<RefCell<RetransmitState>> = Rc::new(RefCell::new(RetransmitState::default()));
        let pump_retransmit = retransmit.clone();
        // Per-`(circuit key, stream_id)` send lock, serializing
        // `send_backward` calls *within* a stream while leaving different
        // streams (even on the same circuit) free to send concurrently --
        // mirrors `allium_cli.py`'s own `ExitNode._return_locks` (see its
        // docstring for the exact fragment-offset race this exists to
        // close: two sends for the same stream racing on the shared
        // per-stream offset if left unserialized).
        //
        // **Why this pump doesn't just drain `backward_rx` straight into
        // `send_backward` the way it looks like it should**: `send_backward`
        // can genuinely suspend for a long time now -- the send-window wait
        // this round's retransmission fix added (`RETURN_WINDOW_MAX_WAIT`,
        // up to 30s) blocks until acks free up space. A single task
        // draining one shared channel for the *whole exit process* means
        // that wait, or any real per-fragment send latency, would stall
        // every other circuit's backward traffic behind it too -- not just
        // other streams on the same circuit, every circuit this exit
        // serves. Confirmed live: once several concurrent CONNECTs shared
        // one circuit (routine under base-domain isolation grouping) and
        // that circuit's return path backed up, unrelated CONNECTs on
        // *other* circuits started timing out and retrying, because their
        // CONNECTED replies -- which travel over this same channel -- were
        // stuck in line behind it. Spawning each channel item onto its own
        // task the moment it's received keeps the pump loop itself
        // non-blocking (immediately back to `recv().await`), while the
        // per-stream lock above still gives each individual stream the
        // same in-order guarantee the single shared task used to provide
        // for free.
        let return_locks: Rc<RefCell<HashMap<(CircuitKeyTuple, u32), Rc<tokio::sync::Mutex<()>>>>> = Rc::new(RefCell::new(HashMap::new()));
        tokio::task::spawn_local(async move {
            while let Some((key, stream_id, payload, inflight)) = backward_rx.recv().await {
                let node = sink_node.clone();
                let offsets = offsets.clone();
                let retransmit = pump_retransmit.clone();
                let locks = return_locks.clone();
                let lock = {
                    let mut table = locks.borrow_mut();
                    table.entry((key.clone(), stream_id)).or_insert_with(|| Rc::new(tokio::sync::Mutex::new(()))).clone()
                };
                let is_fin = payload.is_empty();
                tokio::task::spawn_local(async move {
                    let _serialize = lock.lock().await;
                    SocksExit::send_backward(&node, &key, stream_id, &payload, &offsets, &retransmit).await;
                    drop(_serialize);
                    // This chunk is
                    // fully sent (or has been handed off to
                    // `RetransmitState` for the acker/`retransmit_sweep` to
                    // manage from here) -- release its
                    // `MAX_INFLIGHT_BACKWARD_CHUNKS_PER_STREAM` slot so
                    // `Egress::pump_stream` can queue more of this stream's
                    // data.
                    inflight.fetch_sub(1, AtomicOrdering::AcqRel);
                    if is_fin {
                        // Mirrors `_send_end_of_stream`'s own
                        // `self._return_locks.pop(key, None)` -- otherwise
                        // this table grows by one entry for every stream
                        // this exit ever opens, for as long as the process
                        // runs.
                        locks.borrow_mut().remove(&(key, stream_id));
                    }
                });
            }
        });
        // Port of `allium_cli.py`'s `start()` adding `_retransmit_sweep` to
        // its background task list alongside the idle-circuit sweeper --
        // this crate's `install` has no equivalent task list to append to
        // (`RelayNode`'s own idle sweeper is started elsewhere), so this
        // is spawned directly, for the process's lifetime, exactly like
        // the backward-pump task just above.
        let sweep_node = node.clone();
        let sweep_retransmit = retransmit.clone();
        tokio::task::spawn_local(async move {
            SocksExit::retransmit_sweep(sweep_node, sweep_retransmit).await;
        });
        // Close streams idle for
        // longer than `STREAM_IDLE_TIMEOUT`, for the process's lifetime,
        // exactly like the two background tasks just above.
        crate::exit::spawn_idle_stream_sweeper(egress.clone());

        // Cloned before `egress`
        // moves into `deliver_egress` below, so `forget_hook` (set up
        // further down) can close a forgotten circuit's exit streams.
        let forget_egress = egress.clone();
        let deliver_egress = egress;
        let deliver_tx = backward_tx;
        // Reassembles a stream's body-data fragments (see `deliver`'s
        // fragment-decoding fallthrough below); mirrors `allium_cli.py`'s
        // `ExitNode._reassemblers`, one `Reassembler` per `(circuit key,
        // stream_id)` pair.
        let reassemblers: Rc<RefCell<StreamReassemblers>> = Rc::new(RefCell::new(StreamReassemblers::default()));
        let forget_reassemblers = reassemblers.clone();
        // Round J: this relay's hidden-service intro/rendezvous state --
        // see `HsRelayState`'s own docs. Any exit-capable relay can serve
        // as an introduction or rendezvous point (matches Python's
        // `ExitNode`, which handles both ordinary exit traffic and hidden-
        // service control traffic in the same `deliver` override), so this
        // is wired in unconditionally alongside the ordinary egress state
        // rather than needing its own separate `install`.
        let hs_state: Rc<RefCell<HsRelayState>> = Rc::new(RefCell::new(HsRelayState::default()));
        let deliver_node = node.clone();
        let deliver_hs_state = hs_state.clone();
        let deliver_retransmit = retransmit;
        node.borrow_mut().deliver_fn = Some(Box::new(move |key, _peeled, payload| {
            SocksExit::deliver(
                deliver_node.clone(),
                deliver_egress.clone(),
                deliver_tx.clone(),
                key.clone(),
                payload.to_vec(),
                reassemblers.clone(),
                deliver_hs_state.clone(),
                deliver_retransmit.clone(),
            );
        }));

        node.borrow_mut().post_create_hook = Some(Box::new(|n, peer_addr, circuit_id| {
            // Best-effort, silent on failure (a full table or similar): the
            // handshake itself already succeeded and a CREATED reply was
            // already sent, matching Python's "warn and continue" -- this
            // port has no logger wired in to warn through, consistent with
            // every other silent drop in this crate's relay path.
            let _ = n.register_exit_circuit(peer_addr, circuit_id, 0);
        }));

        // Round J: port of `ExitNode._hs_forget` -- otherwise `hs_intro`/
        // `pending_rendezvous`/`partner` would grow for as long as the
        // process runs, since nothing in this protocol sends an explicit
        // "I'm done" message; this is the only thing that prunes them,
        // fired from `RelayNode::forget_circuit` (the idle-timeout sweeper,
        // or an explicit DESTROY) exactly like Python's own call site.
        let forget_hs_state = hs_state;
        node.borrow_mut().forget_hook = Some(Box::new(move |key| {
            forget_reassemblers.borrow_mut().forget_circuit(key);
            let mut s = forget_hs_state.borrow_mut();
            s.hs_drop_reassembler(key);
            if let Some(partner) = s.partner.remove(key) {
                s.partner.remove(&partner);
            }
            // Drop this auth_pubkey's rate
            // limiter along with its registration, so `intro_rate` never
            // outgrows `intro`.
            let mut closing: Vec<Vec<u8>> = Vec::new();
            for (auth_pubkey, registered_key) in s.intro.iter() {
                if registered_key == key {
                    closing.push(auth_pubkey.clone());
                }
            }
            for auth_pubkey in &closing {
                s.intro_rate.remove(auth_pubkey);
            }
            s.intro.retain(|_, v| v != key);
            s.pending_rendezvous.retain(|_, (c, _)| c != key);
            // Drop this circuit's per-sender
            // sub-limiters too -- both the ones tied to an auth_pubkey it
            // was registered as an intro point for (just forgotten above),
            // and any where this circuit was itself the *sender* of
            // INTRODUCE1s to some other service.
            s.intro_rate_per_sender.retain(|(auth_pubkey, sender), _| sender != key && !closing.contains(auth_pubkey));

            // Stream lifetime was
            // never tied to circuit lifetime, so a destroyed or expired
            // circuit's exit sockets (and their `MAX_STREAMS_PER_CIRCUIT`
            // slots) stayed open indefinitely. `forget_hook` itself is a
            // synchronous `FnMut`, but closing streams needs the
            // `tokio::sync::Mutex<Egress>` lock, so that part runs as its
            // own short-lived spawned task -- `key` is already gone from
            // `RelayNode`'s own tables by the time `forget_circuit`
            // returns, so a client could not usefully race this to reopen
            // a stream under the same key.
            let egress = forget_egress.clone();
            let key = key.clone();
            tokio::task::spawn_local(async move {
                egress.lock().await.close_circuit_streams(&Some(key));
            });
        }));
    }

    fn deliver(
        node: Rc<RefCell<RelayNode>>,
        egress: Rc<tokio::sync::Mutex<Egress>>,
        backward: tokio::sync::mpsc::Sender<(CircuitKeyTuple, u32, Vec<u8>, Arc<AtomicUsize>)>,
        key: CircuitKeyTuple,
        payload: Vec<u8>,
        reassemblers: Rc<RefCell<StreamReassemblers>>,
        hs_state: Rc<RefCell<HsRelayState>>,
        retransmit: Rc<RefCell<RetransmitState>>,
    ) {
        // Datagram magic is checked first, exactly like Python's `deliver`,
        // so a UDP datagram request can never be misparsed as a stream
        // request.
        if payload.starts_with(DATAGRAM_MAGIC) {
            if let Ok(request) = decode_datagram_request(&payload) {
                let e = egress;
                let tx = backward;
                tokio::task::spawn_local(async move {
                    SocksExit::serve_datagram(e, tx, key, request).await;
                });
                return;
            }
        }
        if payload.starts_with(MAGIC) {
            if let Ok(request) = decode_request(&payload) {
                tokio::task::spawn_local(async move {
                    SocksExit::serve_request(egress, backward, key, request).await;
                });
                return;
            }
        }
        if payload.starts_with(ACK_MAGIC) {
            // A client fragment-ack: local bookkeeping only, no I/O, so
            // handled inline rather than spawned -- matches Python's own
            // `_handle_ack`, called synchronously from `deliver` alongside
            // its other branches.
            SocksExit::handle_ack(&retransmit, &key, &payload);
            return;
        }
        // Neither a control request, a UDP datagram, nor an ack: this is a fragment
        // of an already-open stream's body (see `allium_cli.py`'s
        // `ExitNode.deliver`, whose fragment-reassembly-and-forward step
        // this mixin's `deliver` was missing entirely -- the reason a
        // CONNECT stream's body never reached its real outbound TCP
        // connection, however successfully the initial CONNECT itself
        // negotiated). Reassemble per `(key, stream_id)`, exactly like the
        // client's own `SocksServer::deliver_data`, and forward newly
        // contiguous bytes into the egress.
        let Ok(fragment) = decode_fragment(&payload) else {
            // Not a request, a datagram, or a fragment -- nothing to do,
            // matching `RelayNode::deliver`'s own log-and-return default
            // that already ran before this hook was called.
            return;
        };
        if fragment.stream_id == 0 {
            // Hidden-service control traffic (`HS_STREAM_ID`, Round J):
            // reassembled per *circuit* (like `AuthorityNode`'s own
            // reassemblers), not per stream id the way `reassemblers`
            // above is -- every intro/rendezvous circuit reuses the same
            // `HS_STREAM_ID=0`, so keying by that alone would merge
            // unrelated circuits' fragments. See `deliver_hs` for the
            // dispatch this used to be entirely missing.
            tokio::task::spawn_local(async move {
                SocksExit::deliver_hs(node, key, payload, hs_state).await;
            });
            return;
        }
        let data = reassemblers.borrow_mut().push(&key, &fragment);
        if !data.is_empty() {
            let stream_id = fragment.stream_id;
            // This used to
            // pass `None`, putting every circuit's streams into one shared
            // namespace so any client could inject into any other client's
            // stream by guessing its id. `key` (this fragment's own
            // circuit) is what actually identifies which circuit this data
            // belongs to.
            let circuit_key = key.clone();
            tokio::task::spawn_local(async move {
                let _ = egress.lock().await.send_data(stream_id, &data, Some(circuit_key));
            });
        }
    }

    // -----------------------------------------------------------------
    // Round J: hidden-service intro/rendezvous relay dispatch. Port of
    // `allium_cli.py`'s `ExitNode._handle_hs_message` and its four
    // `_hs_handle_*` methods -- any exit-capable relay this port runs
    // (`allium-cli`'s `exit` role) can also serve as a hidden service's
    // introduction point or as a client's/service's rendezvous point;
    // Python's single `ExitNode.deliver` override handles ordinary exit
    // traffic and hidden-service control traffic side by side, which this
    // `SocksExit` mixin now does too.
    // -----------------------------------------------------------------

    async fn deliver_hs(node: Rc<RefCell<RelayNode>>, key: CircuitKeyTuple, payload: Vec<u8>, hs_state: Rc<RefCell<HsRelayState>>) {
        let message = {
            let mut s = hs_state.borrow_mut();
            match s.hs_push(&key, &payload) {
                Some(m) => m,
                None => return, // more fragments to come, or dropped (malformed or over a bound)
            }
        };
        if message.len() < 5 || !message.starts_with(crate::hswire::HS_MAGIC) {
            return;
        }
        match message[4] {
            crate::hswire::ESTABLISH_INTRO => SocksExit::hs_handle_establish_intro(&node, key, &message, &hs_state).await,
            crate::hswire::INTRODUCE1 => SocksExit::hs_handle_introduce1(&node, key, &message, &hs_state).await,
            crate::hswire::RENDEZVOUS_JOIN => SocksExit::hs_handle_rendezvous_join(&node, key, &message, &hs_state).await,
            crate::hswire::RENDEZVOUS_DATA => SocksExit::hs_handle_rendezvous_data(&node, key, message, &hs_state).await,
            _ => {} // unexpected message type here: silently ignored, matching Python's log-and-return
        }
    }

    /// Fragment and send one whole hidden-service message to `key`'s
    /// predecessor -- the HS analogue of `send_backward_sealed`'s
    /// magic-prefixed whole-message path, except an HS control message
    /// always starts a *fresh* fragment sequence at offset 0 (mirrors
    /// Python's `_hs_send`/`hs_fragment_message`), unlike ordinary stream
    /// body data's persistent per-`(circuit, stream_id)` offset in
    /// `send_backward`.
    async fn hs_send(node: &Rc<RefCell<RelayNode>>, key: &CircuitKeyTuple, message: &[u8]) {
        for wire_bytes in crate::hswire::fragment_message_default(message) {
            SocksExit::send_backward_sealed(node, key, &wire_bytes).await;
        }
    }

    async fn hs_handle_establish_intro(node: &Rc<RefCell<RelayNode>>, key: CircuitKeyTuple, message: &[u8], hs_state: &Rc<RefCell<HsRelayState>>) {
        let Ok((auth_pubkey, timestamp, signature)) = crate::hswire::decode_establish_intro(message) else { return };
        let now = now_secs();
        if (now - timestamp).abs() > HS_ESTABLISH_INTRO_FRESHNESS {
            SocksExit::hs_send(node, &key, &crate::hswire::encode_establish_intro_reply(false, "stale timestamp")).await;
            return;
        }
        let Ok(payload) = crate::hswire::establish_intro_signing_payload(&auth_pubkey, timestamp) else { return };
        let auth_pubkey_arr: Result<[u8; 32], _> = auth_pubkey.as_slice().try_into();
        let sig_arr: Result<[u8; 64], _> = signature.as_slice().try_into();
        let (Ok(auth_pubkey_arr), Ok(sig_arr)) = (auth_pubkey_arr, sig_arr) else {
            SocksExit::hs_send(node, &key, &crate::hswire::encode_establish_intro_reply(false, "bad signature")).await;
            return;
        };
        let ops = crate::hiddenservice::HsOps::real();
        if !(ops.ed25519_verify)(&auth_pubkey_arr, &payload, &sig_arr) {
            SocksExit::hs_send(node, &key, &crate::hswire::encode_establish_intro_reply(false, "bad signature")).await;
            return;
        }
        let registered = hs_state.borrow_mut().register_intro(auth_pubkey, &key);
        if let Err(reason) = registered {
            SocksExit::hs_send(node, &key, &crate::hswire::encode_establish_intro_reply(false, reason)).await;
            return;
        }
        SocksExit::hs_send(node, &key, &crate::hswire::encode_establish_intro_reply(true, "registered")).await;
    }

    async fn hs_handle_introduce1(node: &Rc<RefCell<RelayNode>>, key: CircuitKeyTuple, message: &[u8], hs_state: &Rc<RefCell<HsRelayState>>) {
        let Ok((auth_pubkey, client_ephemeral_pub, sealed)) = crate::hswire::decode_introduce1(message) else { return };
        let target = hs_state.borrow().intro.get(&auth_pubkey).cloned();
        let Some(target) = target else {
            SocksExit::hs_send(node, &key, &crate::hswire::encode_introduce_ack(false, "no such service registered here")).await;
            return;
        };

        // A registered
        // service is now rate-limited per `auth_pubkey`, so this intro
        // point can't be used to hand the service an unbounded stream of
        // INTRODUCE2s (and, downstream, rendezvous circuits it has to
        // build) at near-zero cost to whoever is sending INTRODUCE1s.
        //
        // That shared budget alone has no
        // per-sender sub-limit, so it's checked here only *after* a
        // tighter, per-(auth_pubkey, sending circuit) bucket -- computed
        // and spent first -- also allows it, so a single sender who has
        // already exhausted their own share can't keep draining the
        // shared budget out from under every other client of the same
        // service.
        let now = now_secs();
        let allowed = hs_state.borrow_mut().allow_introduce1(&auth_pubkey, &key, now);
        if !allowed {
            SocksExit::hs_send(node, &key, &crate::hswire::encode_introduce_ack(false, "rate limited")).await;
            return;
        }

        let Ok(introduce2) = crate::hswire::encode_introduce2(&client_ephemeral_pub, &sealed) else { return };
        SocksExit::hs_send(node, &target, &introduce2).await;
        SocksExit::hs_send(node, &key, &crate::hswire::encode_introduce_ack(true, "forwarded")).await;
    }

    async fn hs_handle_rendezvous_join(node: &Rc<RefCell<RelayNode>>, key: CircuitKeyTuple, message: &[u8], hs_state: &Rc<RefCell<HsRelayState>>) {
        let Ok(cookie) = crate::hswire::decode_rendezvous_join(message) else { return };
        let now = now_secs();
        let first = {
            let mut s = hs_state.borrow_mut();
            match s.take_pending_rendezvous(&cookie, now) {
                Some(first) => Ok(Some(first)),
                None => s.register_pending_rendezvous(cookie, &key, now).map(|()| None),
            }
        };
        let first = match first {
            Ok(first) => first,
            Err(reason) => {
                SocksExit::hs_send(node, &key, &crate::hswire::encode_rendezvous_joined(false, reason)).await;
                return;
            }
        };
        let Some(first) = first else {
            SocksExit::hs_send(node, &key, &crate::hswire::encode_rendezvous_joined(true, "waiting for the other side")).await;
            return;
        };
        {
            let mut s = hs_state.borrow_mut();
            s.partner.insert(key.clone(), first.clone());
            s.partner.insert(first.clone(), key.clone());
        }
        SocksExit::hs_send(node, &first, &crate::hswire::encode_rendezvous_joined(true, "joined")).await;
        SocksExit::hs_send(node, &key, &crate::hswire::encode_rendezvous_joined(true, "joined")).await;
    }

    async fn hs_handle_rendezvous_data(node: &Rc<RefCell<RelayNode>>, key: CircuitKeyTuple, message: Vec<u8>, hs_state: &Rc<RefCell<HsRelayState>>) {
        // Opaque post-join tunnel bytes, forwarded to the paired circuit
        // untouched -- this relay never decrypts `message` (the session
        // cipher inside it, `hiddenservice::HsSession`, is between the
        // client and the service only).
        let partner = hs_state.borrow().partner.get(&key).cloned();
        let Some(partner) = partner else { return };
        SocksExit::hs_send(node, &partner, &message).await;
    }

    async fn serve_request(
        egress: Rc<tokio::sync::Mutex<Egress>>,
        backward: tokio::sync::mpsc::Sender<(CircuitKeyTuple, u32, Vec<u8>, Arc<AtomicUsize>)>,
        key: CircuitKeyTuple,
        request: StreamRequest,
    ) {
        // The fragment stream id a reply travels under has to be one the
        // client can predict -- see `allium_cli.py`'s `ExitNode._handle_request`
        // (`stream_id = request.request_id` docstring): it starts as the
        // request's own id (all that is known before the egress opens a
        // real stream -- covers the CONNECTED/FAILURE control reply below,
        // whose own magic-prefixed framing makes its `stream_id` moot
        // anyway) and switches, via `on_connected`, to the egress's real
        // stream id the moment one exists -- the same id
        // `reply_for_stream` hands the client in the CONNECTED reply, and
        // therefore the same id the client's own `relay_stream` fragments
        // its forward body data under (see `do_connect`/`do_connect_relay`:
        // `reply.stream_id`). Every real body byte in either direction is
        // fragmented under that one shared id.
        let sid = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(request.request_id));
        let emit_sid = sid.clone();
        let emit_key = key.clone();
        // This stream's in-flight
        // backward-chunk count -- see `MAX_INFLIGHT_BACKWARD_CHUNKS_PER_STREAM`.
        // Incremented here before queueing, decremented by `install`'s
        // backward-pump loop once `send_backward` actually finishes with
        // the chunk.
        let inflight = Arc::new(AtomicUsize::new(0));
        let emit_inflight = inflight.clone();
        let emit: Box<dyn FnMut(&[u8]) -> bool + Send> = Box::new(move |reply: &[u8]| {
            if emit_inflight.load(AtomicOrdering::Acquire) >= MAX_INFLIGHT_BACKWARD_CHUNKS_PER_STREAM {
                return false;
            }
            emit_inflight.fetch_add(1, AtomicOrdering::AcqRel);
            // The egress calls `emit` synchronously from inside
            // `handle_request`/`pump_stream`; queueing onto the channel
            // here (rather than sending straight away) matches Python's
            // own `emit` scheduling the send as a separate task so the
            // egress's read loop is never blocked by the return-path
            // socket send. `try_send`, not `send().await`: this closure is
            // synchronous (it runs inside `Egress::pump_stream`'s tight
            // read loop, with no `Egress` lock held to release by
            // `.await`ing here), and a full channel is itself a valid
            // "can't keep up" signal this returns `false` for.
            let ok = backward.try_send((emit_key.clone(), emit_sid.load(std::sync::atomic::Ordering::SeqCst), reply.to_vec(), emit_inflight.clone())).is_ok();
            if !ok {
                emit_inflight.fetch_sub(1, AtomicOrdering::AcqRel);
            }
            ok
        });
        let on_connected: Box<dyn FnOnce(&StreamRequest, u32) + Send> = Box::new(move |_req, opened_id| {
            sid.store(opened_id, std::sync::atomic::Ordering::SeqCst);
        });
        // Track this stream
        // under its own circuit's key, not `None`, so it can never be
        // reached from a different circuit -- see `exit.rs`'s
        // `CircuitKey` docs.
        //
        // `Egress::handle_request`
        // is now a free function taking `&egress` rather than a `&mut
        // self` method behind `egress.lock().await` -- see its docs for
        // why holding that lock across a whole CONNECT/RESOLVE used to
        // stall every other circuit.
        Egress::handle_request(&egress, &request, emit, Some(on_connected), Some(key)).await;
    }

    async fn serve_datagram(
        egress: Rc<tokio::sync::Mutex<Egress>>,
        backward: tokio::sync::mpsc::Sender<(CircuitKeyTuple, u32, Vec<u8>, Arc<AtomicUsize>)>,
        key: CircuitKeyTuple,
        request: DatagramRequest,
    ) {
        // A datagram reply always goes out whole (`ALDG`-magic-prefixed,
        // caught by `send_backward` before its fragmenting path even looks
        // at a stream id) -- see `allium_cli.py`'s `_handle_datagram`
        // docstring ("never fragmented"). `0` is therefore never load-bearing.
        // Clone `key` before
        // it's moved into `emit` below, so the UDP association this opens
        // is tracked under its own circuit rather than the shared `None`
        // key every association used to collapse into.
        let circuit_key = key.clone();
        // A UDP reply is a single one-off send, not a stream of chunks, so
        // this gets its own throwaway in-flight counter rather than
        // sharing `MAX_INFLIGHT_BACKWARD_CHUNKS_PER_STREAM` bookkeeping
        // with anything -- there is nothing else to serialize it against.
        let inflight = Arc::new(AtomicUsize::new(0));
        let emit: Box<dyn FnMut(&[u8]) + Send> = Box::new(move |reply: &[u8]| {
            // Matches `install`'s backward-pump loop, which unconditionally
            // decrements this counter once it finishes with the item --
            // increment first so that stays balanced, even though nothing
            // here ever reads it back.
            inflight.fetch_add(1, AtomicOrdering::AcqRel);
            let _ = backward.try_send((key.clone(), 0, reply.to_vec(), inflight.clone()));
        });
        // Not `egress.lock().await.handle_datagram(..)`: that holds the lock across the
        // DNS resolve, so one unanswered lookup would stall every other circuit's CONNECT,
        // RESOLVE and `send_data`. See `Egress::handle_datagram_shared`.
        Egress::handle_datagram_shared(&egress, &request, emit, Some(circuit_key)).await;
    }

    /// Send `payload` backward toward this circuit's predecessor -- the
    /// exit's half of the return path; intermediate relays add their own
    /// layers via `RelayNode::relay_backward`.
    ///
    /// A control frame (`ALSM`/`ALDG`-prefixed: a CONNECTED/FAILURE/RESOLVE
    /// reply or a UDP datagram reply) always goes out whole, identified by
    /// its magic prefix, never by size -- both are bounded by construction
    /// to fit one cell. Everything else is a stream's ordinary body data,
    /// which is **always** fragmented (`crate::fragment::encode_fragment`),
    /// however small, using `stream_id` and a per-`(circuit, stream_id)`
    /// send offset threaded through from `offsets` -- exactly mirroring
    /// what `SocksServer::relay_stream` already does for the *forward*
    /// direction. Before this fix, this method sent every reply -- control
    /// or data -- as one opaque, unframed blob; the client's own return-path
    /// dispatch (`cmd_client`'s drain loop / Python's `pump_return_path`)
    /// only ever recognises a magic-prefixed control reply or *fragment-
    /// encoded* body data, so a CONNECT stream's actual body bytes were
    /// silently misparsed (or, if `decode_fragment` happened to reject
    /// them outright, silently dropped) the moment they reached the
    /// client -- the other half, alongside the exit's missing forward-path
    /// reassembly (see `deliver`'s own docs), of why a real CONNECT stream
    /// went out fine but nothing ever came back.
    ///
    /// **Reliability**: every data (and FIN) fragment sent here is also
    /// buffered via [`SocksExit::buffer_for_retransmit`] until the
    /// client's ack releases it (see [`SocksExit::handle_ack`]), and
    /// [`SocksExit::retransmit_sweep`] resends whatever goes too long
    /// unacked -- port of `allium_cli.py`'s own `_send_backward` calling
    /// `_buffer_for_retransmit` on every fragment it sends. A UDP
    /// datagram reply (`DATAGRAM_MAGIC`-prefixed, sent whole below) is the
    /// one exception left unbuffered, matching Python: `_send_backward`
    /// there never calls `_buffer_for_retransmit` for the whole-message
    /// magic-prefixed path either, since a datagram reply has no fragment
    /// offset for an ack to name in the first place.
    async fn send_backward(
        node: &Rc<RefCell<RelayNode>>,
        key: &CircuitKeyTuple,
        stream_id: u32,
        payload: &[u8],
        offsets: &Rc<RefCell<HashMap<(CircuitKeyTuple, u32), u32>>>,
        retransmit: &Rc<RefCell<RetransmitState>>,
    ) {
        if payload.starts_with(DATAGRAM_MAGIC) || payload.starts_with(MAGIC) {
            SocksExit::send_backward_sealed(node, key, payload).await;
            return;
        }
        let offset_key = (key.clone(), stream_id);
        let offset = offsets.borrow().get(&offset_key).copied().unwrap_or(0);
        if payload.is_empty() {
            // The exit's end-of-stream marker (`exit.rs`'s `pump_stream`
            // emits one empty chunk on EOF): a single FIN fragment with no
            // data, at the current offset -- matches
            // `allium_cli.py`'s `_send_end_of_stream`. Sent first, *then*
            // recorded as this stream's `fin_offsets` entry and buffered,
            // in that order, matching Python: a FIN lost right at the end
            // must still be recoverable, since the client only closes the
            // application socket once it has every byte.
            let encoded = crate::fragment::encode_fragment(&crate::fragment::Fragment::new(stream_id, offset, true, Vec::new()));
            SocksExit::send_backward_sealed(node, key, &encoded).await;
            retransmit.borrow_mut().fin_offsets.insert(offset_key, offset);
            SocksExit::buffer_for_retransmit(retransmit, key, stream_id, offset, encoded);
            return;
        }
        let mtu = crate::fragment::DEFAULT_MTU;
        let mut offset = offset;
        let mut remaining = payload;
        let mut sent_in_burst: u32 = 0;
        while !remaining.is_empty() {
            // Send window: wait for acks to free space before putting more
            // *new* data in flight, so a lost fragment's cumulative-ack
            // stall doesn't let the unacked backlog blow through
            // `RETRANSMIT_MAX_PENDING` and start evicting fragments the
            // client is still waiting on. Port of `_send_backward`'s own
            // wait loop guarding `RETURN_WINDOW_FRAGMENTS` -- see
            // `RETURN_WINDOW_MAX_WAIT`'s docs for this port's one
            // deviation (the wait here blocks every other circuit's
            // return traffic too, since backward sends are drained by one
            // single-consumer task).
            let mut waited = Duration::ZERO;
            while retransmit.borrow().pending.get(&offset_key).map(BTreeMap::len).unwrap_or(0) >= RETURN_WINDOW_FRAGMENTS && waited < RETURN_WINDOW_MAX_WAIT {
                tokio::time::sleep(RETURN_WINDOW_POLL).await;
                waited += RETURN_WINDOW_POLL;
            }
            let take = remaining.len().min(mtu);
            let (chunk, rest) = remaining.split_at(take);
            let encoded = crate::fragment::encode_fragment(&crate::fragment::Fragment::new(stream_id, offset, false, chunk.to_vec()));
            SocksExit::send_backward_sealed(node, key, &encoded).await;
            SocksExit::buffer_for_retransmit(retransmit, key, stream_id, offset, encoded);
            offset += chunk.len() as u32;
            remaining = rest;
            // Same pacing a resend burst gets in `retransmit_sweep`, for
            // the same reason: a big multi-fragment reply must not outrun
            // a downstream single-threaded relay's receive-decrypt-forward
            // loop. Port of `SEND_PACE_EVERY`/`SEND_PACE_DELAY`.
            sent_in_burst += 1;
            if sent_in_burst % SEND_PACE_EVERY == 0 {
                tokio::time::sleep(SEND_PACE_DELAY).await;
            }
        }
        offsets.borrow_mut().insert(offset_key, offset);
    }

    /// Seal one already-framed backward payload (a whole control/datagram
    /// reply, or one already-encoded body fragment) in this exit's onion
    /// layer and send it to the predecessor. Split out from
    /// [`SocksExit::send_backward`] so its magic-prefixed whole-message
    /// path and its fragmenting body-data path share this one seal-and-send
    /// step rather than duplicating it.
    async fn send_backward_sealed(node: &Rc<RefCell<RelayNode>>, key: &CircuitKeyTuple, payload: &[u8]) {
        let (mut wrapped, incoming_addr, incoming_circuit_id, backward_token) = {
            let mut n = node.borrow_mut();
            let Some(entry) = n.table.by_key.get_mut(key) else { return };
            let incoming_addr = entry.incoming_addr();
            let incoming_circuit_id = entry.incoming_circuit_id();
            let backward_token = entry.backward_token.clone();
            // A real backward seq, not the fixed 0.
            let backward_seq = entry.next_backward_seq();
            let wrapped = match entry.hop.seal_payload(payload, backward_seq, incoming_addr.clone(), Some(Kind::PAYLOAD), None) {
                Ok(w) => w,
                Err(_) => return,
            };
            (wrapped, incoming_addr, incoming_circuit_id, backward_token)
        };
        if let Some(tok) = &backward_token {
            wrapped.extend_from_slice(tok);
        }
        let outgoing = match seal_into_cell(&wrapped, incoming_circuit_id, Some(Command::Relay)) {
            Ok(c) => c,
            Err(_) => return,
        };
        let _ = RelayNode::send_datagram(node, &outgoing.pack(), &incoming_addr).await;
    }

    /// Remember one already-sent backward-path data (or FIN) fragment so
    /// [`SocksExit::retransmit_sweep`] can resend it if it never gets
    /// acked. Port of `allium_cli.py`'s `ExitNode._buffer_for_retransmit`.
    /// Synchronous -- only touches local `RefCell` state, no I/O -- so it
    /// is safe to call with the `RefCell` borrowed nowhere else on the
    /// stack (every call site below does).
    fn buffer_for_retransmit(retransmit: &Rc<RefCell<RetransmitState>>, key: &CircuitKeyTuple, stream_id: u32, offset: u32, encoded: Vec<u8>) {
        let mut state = retransmit.borrow_mut();
        let pending = state.pending.entry((key.clone(), stream_id)).or_default();
        pending.insert(
            offset,
            RetransmitEntry {
                encoded,
                last_sent: Instant::now(),
                attempts: 0,
            },
        );
        if pending.len() > RETRANSMIT_MAX_PENDING {
            // Evict the *newest* fragment, never the oldest -- see
            // `RetransmitEntry`'s own docs for why (the client's ack is
            // cumulative, so the lowest unacked offset is the one most
            // likely still needed).
            if let Some(&newest) = pending.keys().next_back() {
                pending.remove(&newest);
            }
        }
    }

    /// A client fragment-ack (`ACK_MAGIC`-prefixed, decoded by
    /// [`decode_ack_frame`]): drop any now-acknowledged fragments from the
    /// retransmit buffer. `offset` is a cumulative watermark, so every
    /// buffered fragment below it -- and the buffered FIN, once its own
    /// offset is covered -- is safe to drop outright. Port of
    /// `allium_cli.py`'s `ExitNode._handle_ack`. Synchronous, like
    /// [`SocksExit::buffer_for_retransmit`] above.
    fn handle_ack(retransmit: &Rc<RefCell<RetransmitState>>, key: &CircuitKeyTuple, payload: &[u8]) {
        let Ok((stream_id, offset)) = decode_ack_frame(payload) else { return };
        let mut state = retransmit.borrow_mut();
        let entry_key = (key.clone(), stream_id);
        let fin_offset = state.fin_offsets.get(&entry_key).copied();
        let now_empty = match state.pending.get_mut(&entry_key) {
            Some(pending) => {
                let acked: Vec<u32> = pending
                    .keys()
                    .copied()
                    .filter(|&off| off < offset || (fin_offset == Some(off) && offset >= off))
                    .collect();
                for off in acked {
                    pending.remove(&off);
                }
                pending.is_empty()
            }
            None => return,
        };
        if now_empty {
            state.pending.remove(&entry_key);
            state.fin_offsets.remove(&entry_key);
        }
    }

    /// Periodically resend any buffered backward-path fragment that has
    /// gone too long without being acked. Port of `allium_cli.py`'s
    /// `ExitNode._retransmit_sweep` -- spawned once per exit in
    /// [`SocksExit::install`], for the lifetime of the process (this port
    /// has no `_closing` shutdown flag to check against, matching every
    /// other background task `install` spawns, e.g. the idle-circuit
    /// sweeper).
    async fn retransmit_sweep(node: Rc<RefCell<RelayNode>>, retransmit: Rc<RefCell<RetransmitState>>) {
        loop {
            tokio::time::sleep(RETRANSMIT_SWEEP_INTERVAL).await;
            // One `now` for the whole sweep, exactly like `_retransmit_sweep`'s
            // own single `time.monotonic()` call -- a fragment's staleness is
            // judged relative to when this sweep started, not to whenever its
            // own turn in the loop below happens to come up.
            let now = Instant::now();
            let mut resent_in_sweep: u32 = 0;
            // Snapshot the keys before iterating: resending below awaits
            // `send_backward_sealed`, a real suspension point, so nothing may
            // hold a `RefCell` borrow across it.
            let keys: Vec<(CircuitKeyTuple, u32)> = retransmit.borrow().pending.keys().cloned().collect();
            for entry_key in keys {
                let due: Vec<Vec<u8>> = {
                    let mut state = retransmit.borrow_mut();
                    let Some(pending) = state.pending.get_mut(&entry_key) else { continue };
                    let offsets: Vec<u32> = pending.keys().copied().collect();
                    let mut due = Vec::new();
                    for offset in offsets {
                        let Some(record) = pending.get_mut(&offset) else { continue };
                        if now.duration_since(record.last_sent) < RETRANSMIT_TIMEOUT {
                            continue;
                        }
                        if record.attempts >= RETRANSMIT_MAX_ATTEMPTS {
                            // The client is most likely gone, not merely
                            // slow -- retrying forever would just leak
                            // memory onto a dead stream.
                            pending.remove(&offset);
                            continue;
                        }
                        record.last_sent = now;
                        record.attempts += 1;
                        due.push(record.encoded.clone());
                    }
                    due
                };
                for encoded in due {
                    SocksExit::send_backward_sealed(&node, &entry_key.0, &encoded).await;
                    resent_in_sweep += 1;
                    // Same pacing a fresh burst gets in `send_backward` --
                    // and for the same reason: an un-acked backlog resent in
                    // one sweep must not monopolize the event loop for long
                    // enough to delay, or drop, an unrelated circuit's
                    // freshly-arriving cell.
                    if resent_in_sweep % SEND_PACE_EVERY == 0 {
                        tokio::time::sleep(SEND_PACE_DELAY).await;
                    }
                }
                let mut state = retransmit.borrow_mut();
                let is_empty = state.pending.get(&entry_key).map(|p| p.is_empty()).unwrap_or(true);
                if is_empty {
                    state.pending.remove(&entry_key);
                    state.fin_offsets.remove(&entry_key);
                }
            }
        }
    }
    // TOKIO-INSTALL-END
}


// ---------------------------------------------------------------------------
// SocksServer -- live per-connection negotiation/relay loop
// ---------------------------------------------------------------------------
//
// Ported in a follow-up pass (the "What is deliberately NOT
// ported" note in the module docs above is now stale -- this closes that
// gap). Same methodology as `RelayNode`/`SocksExit`: pure protocol/decision
// logic lives in small synchronous, unit-tested functions and methods below;
// every genuinely tokio-touching piece (TCP accept, byte reads off a client
// socket, UDP sockets, timeouts/retry waits) is isolated inside
// `// TOKIO-*-BEGIN`/`-END` sentinel blocks and verified only via the
// stub-and-restore cycle (see the crate root docs), not a real `cargo
// build` -- no crates.io access in this sandbox.
//
// **Concurrency model**: `Rc<RefCell<SocksServer>>` state plus
// `tokio::task::spawn_local` under a `LocalSet`, one task per client TCP
// connection -- matches `relay.rs`/`SocksExit`'s reasoning exactly (mirrors
// Python's single-threaded cooperative `asyncio`).
//
// **Circuit references, extending this file's existing `CircuitKey`
// deviation**: `onion_router`/`onion_retry` resolve to an opaque
// `CircuitKey`, not a closure -- the caller registers the real send
// callable for a key with [`SocksServer::register_onion`] (mirroring
// `register_writer`) before handing that key back from either hook. This
// keeps the same "explicit token instead of borrowed identity" reasoning
// the module docs give for `CircuitKey` itself.
//
// **Hidden-service tunnels**: `_relay_hidden_service`'s `connection` is
// modeled as the [`HsTunnel`] trait (`send`/`receive`/`close`). No
// implementation of it ships in this crate -- `allium_cli.py`'s own
// hidden-service client/tunnel builder is a separate piece of scope --
// so `hidden_service_connect` is a hook a caller wires up later; left
// `None` (the default), a `.allium` CONNECT is refused with
// `REPLY_HOST_UNREACHABLE`, exactly matching Python's behavior when its own
// `hidden_service_connect` constructor argument is omitted.
//
// **Simplifications from the Python original** (all documented at their
// point of use below): the automatic-retry state machine, negotiation, and
// CONNECT/RESOLVE/UDP-ASSOCIATE paths are ported closely; the
// hidden-service relay bridge is a simplified single-loop pump rather than
// Python's two-coroutines-plus-`asyncio.wait` structure, since it is built
// on a trait with no in-tree implementation to test against.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};
// TOKIO-SOCKS-LIVE-USE-BEGIN
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
// TOKIO-SOCKS-LIVE-USE-END

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// A circuit's send callable -- mirrors Python's `onion`/`onion_datagram`
/// (called synchronously to push one datagram into a circuit).
pub type Onion = Rc<RefCell<dyn FnMut(&[u8])>>;

/// `onion_router(host, port) -> CircuitKey` -- resolve which registered
/// circuit a new destination should use. Returns a [`CircuitKey`] rather
/// than a closure -- see the module docs above.
pub type OnionRouterFn = Rc<dyn Fn(String, u16) -> BoxFuture<'static, Result<CircuitKey, SocksError>>>;
/// `onion_retry(host, port, failed_key, reason) -> Option<CircuitKey>` --
/// ask for a fresh circuit after a failed attempt; `Ok(None)` means "give
/// up, no more circuits available".
pub type OnionRetryFn = Rc<
    dyn Fn(String, u16, Option<CircuitKey>, &'static str) -> BoxFuture<'static, Result<Option<CircuitKey>, SocksError>>,
>;
/// `hidden_service_connect(host, port) -> HsTunnel` -- build a
/// hidden-service duplex tunnel for a `.allium` CONNECT.
pub type HiddenServiceConnectFn = Rc<dyn Fn(String, u16) -> BoxFuture<'static, Result<Rc<RefCell<dyn HsTunnel>>, SocksError>>>;

/// A live hidden-service duplex tunnel -- the minimal surface
/// `_relay_hidden_service` needs. No implementation ships in this crate yet
/// (see the module docs above).
pub trait HsTunnel {
    fn send(&mut self, data: Vec<u8>) -> BoxFuture<'_, std::io::Result<()>>;
    fn receive(&mut self, timeout: Duration) -> BoxFuture<'_, std::io::Result<Vec<u8>>>;
    fn close(&mut self);
}

/// A 32-bit value from the OS CSPRNG, via the crate-wide [`crate::osrand::os_random`].
///
/// Security audit fix (2026-09-26, RNG-helper dedup): this used to hand-open
/// `/dev/urandom` locally and, on failure, silently fall back to a
/// `SystemTime`-derived value -- worse than the panic-on-failure pattern
/// every other copy of this duplication had, since association ids are
/// security-sensitive (see [`SocksServer::alloc_association_id`]'s doc) and
/// a silent downgrade to guessable randomness fails quietly instead of
/// loudly. Now propagates the failure like every other caller of
/// `os_random` in this crate.
fn secure_random_u32() -> Result<u32, crate::osrand::OsRandomError> {
    let mut buf = [0u8; 4];
    crate::osrand::os_random(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

/// Configuration for [`SocksServer::with_options`] -- mirrors
/// `SocksServer.__init__`'s keyword arguments.
pub struct SocksServerOptions {
    pub onion: Onion,
    pub host: String,
    pub port: u16,
    pub allow_udp: bool,
    pub mtu: usize,
    pub onion_datagram: Option<Onion>,
    pub hidden_service_connect: Option<HiddenServiceConnectFn>,
    pub onion_router: Option<OnionRouterFn>,
    pub onion_retry: Option<OnionRetryFn>,
    pub onion_stream_started: Option<Box<dyn FnMut(CircuitKey)>>,
    pub onion_stream_finished: Option<Box<dyn FnMut(CircuitKey)>>,
    pub max_connect_attempts: u32,
    pub connect_timeout: f64,
    pub retry_connect_timeout: Option<f64>,
}

impl SocksServerOptions {
    /// Mirrors the Python constructor's required-positional `onion`
    /// argument plus every other parameter's default.
    pub fn new(onion: Onion) -> SocksServerOptions {
        SocksServerOptions {
            onion,
            host: "127.0.0.1".to_string(),
            port: DEFAULT_SOCKS_PORT,
            allow_udp: false,
            mtu: crate::fragment::DEFAULT_MTU,
            onion_datagram: None,
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

impl SocksServer {
    /// Build a live server -- the constructor used by `allium-cli`'s
    /// client/socks-proxy role. [`SocksServer::new`] remains for the
    /// pure-bookkeeping-only tests that predate this pass.
    pub fn with_options(options: SocksServerOptions) -> SocksServer {
        let mut server = SocksServer::new(options.mtu);
        server.host = options.host;
        server.port = options.port;
        server.allow_udp = options.allow_udp;
        // Mirrors Python: a retry is only ever attempted when `onion_retry`
        // is supplied; otherwise `max_connect_attempts` is forced to 1 so
        // the loop in `request_with_retry` never even considers a second
        // attempt.
        server.max_connect_attempts = if options.onion_retry.is_some() { options.max_connect_attempts.max(1) } else { 1 };
        server.connect_timeout_secs = options.connect_timeout;
        server.retry_connect_timeout_secs = options.retry_connect_timeout.unwrap_or(options.connect_timeout);
        server.onion_datagram = options.onion_datagram;
        server.hidden_service_connect = options.hidden_service_connect;
        server.onion_router = options.onion_router;
        server.onion_retry = options.onion_retry;
        server.onion_stream_started = options.onion_stream_started;
        server.onion_stream_finished = options.onion_stream_finished;
        let default_key = server.default_key();
        server.onion_registry.insert(default_key, options.onion);
        server
    }

    /// `(host, port)` this server is (or will be) listening on.
    pub fn address(&self) -> (String, u16) {
        (self.host.clone(), self.port)
    }

    fn alloc_request_id(&mut self) -> u32 {
        self.next_request_id += 1;
        self.next_request_id
    }

    /// Allocate a fresh UDP association id from `/dev/urandom`, not a
    /// counter -- see `socksproxy.py`'s `_alloc_association_id` docstring:
    /// a small sequential id would let anyone who can reach this proxy's
    /// UDP relay guess a live association id belonging to someone else.
    fn alloc_association_id(&self) -> Result<u32, crate::osrand::OsRandomError> {
        secure_random_u32()
    }

    /// Register the send-callable a [`CircuitKey`] returned by
    /// `onion_router`/`onion_retry` refers to. Must be called before that
    /// key is handed back from either hook -- mirrors
    /// [`SocksServer::register_writer`]'s pattern.
    pub fn register_onion(&mut self, key: CircuitKey, onion: Onion) {
        self.onion_registry.insert(key, onion);
    }

    /// Mint a fresh [`CircuitKey`] for a caller (e.g. a circuit pool) that
    /// wants to hand one back from `onion_router`/`onion_retry`.
    pub fn next_circuit_key(&mut self) -> CircuitKey {
        self.next_circuit_key_counter += 1;
        self.next_circuit_key_counter
    }

    fn resolve_onion(&self, key: Option<CircuitKey>) -> Option<Onion> {
        self.onion_registry.get(&self.resolve_key(key)).cloned()
    }

    /// `_current_onion_guess`: best-effort "which circuit did that
    /// timed-out attempt use?" -- `None` when `onion_router` is set (its
    /// per-request key was already popped on the way out, see
    /// `await_reply`'s `finally`), `Some(default_key)` otherwise (the
    /// single-circuit case, where there is only ever one answer).
    fn current_onion_guess(&self) -> Option<CircuitKey> {
        if self.onion_router.is_some() {
            None
        } else {
            Some(self.default_key())
        }
    }

    /// SOCKS5 method-negotiation decision: true iff "no auth" (0x00) is
    /// one of the offered methods -- this server supports nothing else.
    pub fn negotiate_no_auth(methods: &[u8]) -> bool {
        methods.contains(&0x00)
    }

    /// Whether a stream reply counts as success for `kind` -- mirrors
    /// `_request_with_retry`'s `ok` check (a RESOLVE additionally needs a
    /// resolved address).
    pub fn reply_is_ok(kind: u8, reply: &crate::socks::StreamReply) -> bool {
        reply.status == crate::socks::SUCCESS && (kind != crate::socks::RESOLVE || reply.address.is_some())
    }

    /// Classify a local failure (a reply timeout vs. a circuit lookup/build
    /// failure) for `onion_retry`'s `reason` argument.
    fn retry_reason_for_local_failure(last_code: u8) -> &'static str {
        if last_code == REPLY_TTL_EXPIRED { "timeout" } else { "circuit" }
    }

    /// Classify an exit-reported retryable failure for `onion_retry`'s
    /// `reason` argument: a `COMMAND_UNSUPPORTED` on CONNECT is the exit's
    /// policy refusing this destination/port (a property of the exit, not
    /// the circuit); anything else retryable is treated as a generic
    /// exit-side error.
    fn retry_reason_for_exit_status(status: u8, kind: u8) -> &'static str {
        if status == COMMAND_UNSUPPORTED && kind == crate::socks::CONNECT { "exit-policy" } else { "exit-error" }
    }

    /// Whether `host` is a `.allium` hidden-service address (case-insensitive).
    pub fn is_hidden_service_host(host: &str) -> bool {
        host.to_ascii_lowercase().ends_with(".allium")
    }

    /// Build a SOCKS5 UDP relay header (RFC 1928 SS7): `RSV FRAG ATYP DST.ADDR
    /// DST.PORT`, IPv4-only -- mirrors `deliver_datagram_reply`'s header.
    fn socks5_udp_header(ip: std::net::Ipv4Addr, port: u16) -> Vec<u8> {
        let mut out = vec![0x00, 0x00, 0x00, ATYP_IPV4];
        out.extend_from_slice(&ip.octets());
        out.extend_from_slice(&port.to_be_bytes());
        out
    }

    /// `_on_client_datagram`: encapsulate one SOCKS5-UDP datagram from the
    /// client and inject it into the circuit via `onion_datagram`. Returns
    /// `true` if it was forwarded; every rejection case documented in
    /// Python (fragmented, non-IPv4, oversize, unknown/closed association,
    /// off-host sender) silently drops instead, matching ordinary UDP
    /// semantics -- see the Python docstring this ports.
    pub fn on_client_datagram(&mut self, association_id: u32, data: &[u8], src_host: &str, now: f64) -> bool {
        let has_pinned;
        let expected_host;
        {
            let Some(association) = self.udp_associations.get(&association_id) else { return false };
            if association.closed {
                return false;
            }
            has_pinned = association.client_udp_addr.is_some();
            expected_host = if has_pinned {
                association.client_udp_addr.as_ref().map(|(h, _)| h.clone())
            } else {
                association.control_peer.as_ref().map(|(h, _)| h.clone())
            };
        }
        if let Some(expected) = expected_host {
            if src_host != expected {
                return false;
            }
        }
        if data.len() < 4 || data[0] != 0 || data[1] != 0 {
            return false;
        }
        if data[2] != 0 {
            return false; // fragmented SOCKS5 UDP datagrams unsupported (v1)
        }
        if data[3] != ATYP_IPV4 {
            return false; // v1 datagram framing is IPv4-only
        }
        let (host, port, consumed) = match parse_address(&data[3..]) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let payload = &data[3 + consumed..];
        if payload.len() as i64 > crate::socks::max_datagram_request_payload() {
            return false;
        }
        let request = crate::socks::DatagramRequest {
            association_id,
            host,
            port,
            payload: payload.to_vec(),
            bytes_sent: payload.len() as u32,
        };
        let encoded = match crate::socks::encode_datagram_request(&request) {
            Ok(e) => e,
            Err(_) => return false,
        };
        {
            let association = self.udp_associations.get_mut(&association_id).unwrap();
            if association.client_udp_addr.is_none() {
                association.client_udp_addr = Some((src_host.to_string(), 0));
            }
            association.touch(now);
            association.bytes_sent += payload.len() as u64;
        }
        let Some(onion) = self.onion_datagram.clone().or_else(|| self.onion_registry.get(&self.default_key()).cloned()) else {
            return false;
        };
        (*onion.borrow_mut())(&encoded);
        true
    }

    // -- everything below this point touches a real tokio socket/timer ----

    // TOKIO-SOCKS-LIVE-BEGIN

    /// `start`: bind the TCP listener and spawn the accept loop.
    pub async fn start(server: &Rc<RefCell<SocksServer>>) -> std::io::Result<(String, u16)> {
        let (host, port) = { let s = server.borrow(); (s.host.clone(), s.port) };
        let listener = tokio::net::TcpListener::bind((host.as_str(), port)).await?;
        let local = listener.local_addr()?;
        {
            let mut s = server.borrow_mut();
            s.port = local.port();
        }
        let listener = Rc::new(listener);
        let sv = server.clone();
        let accept_listener = listener.clone();
        let handle = tokio::task::spawn_local(async move {
            loop {
                match accept_listener.accept().await {
                    Ok((stream, _peer)) => {
                        let conn_server = sv.clone();
                        tokio::task::spawn_local(async move {
                            SocksServer::handle_client(conn_server, stream).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        });
        let mut s = server.borrow_mut();
        s.tcp_listener = Some(listener);
        s.accept_task = Some(handle);
        Ok((host, local.port()))
    }

    /// `stop`: close the listener (aborting the accept loop) and every live
    /// UDP association.
    pub async fn stop(server: &Rc<RefCell<SocksServer>>) {
        let (listener, task) = {
            let mut s = server.borrow_mut();
            (s.tcp_listener.take(), s.accept_task.take())
        };
        if let Some(task) = task {
            task.abort();
        }
        drop(listener);
        let ids: Vec<u32> = { server.borrow().udp_associations.keys().cloned().collect() };
        for id in ids {
            let mut s = server.borrow_mut();
            if let Some(a) = s.udp_associations.get_mut(&id) {
                a.close();
            }
        }
        let mut s = server.borrow_mut();
        s.udp_associations.clear();
        s.udp_sockets.clear();
    }

    /// `deliver_reply`: feed a decoded CONNECT/RESOLVE reply back into
    /// whichever `await_reply` call is still waiting on it.
    pub fn deliver_reply(server: &Rc<RefCell<SocksServer>>, payload: &[u8]) -> bool {
        let Ok(reply) = crate::socks::decode_reply(payload) else { return false };
        let sender = server.borrow_mut().pending.remove(&reply.request_id);
        match sender {
            Some(tx) => tx.send(reply).is_ok(),
            None => false,
        }
    }

    /// `deliver_datagram_reply`: feed a decoded datagram reply back to its
    /// SOCKS client over the real UDP relay socket.
    pub fn deliver_datagram_reply(server: &Rc<RefCell<SocksServer>>, payload: &[u8], now: f64) -> bool {
        let Ok(reply) = crate::socks::decode_datagram_reply(payload) else { return false };
        let Ok(ip) = reply.host.parse::<std::net::Ipv4Addr>() else { return false };
        let mut s = server.borrow_mut();
        let client_addr = {
            let Some(association) = s.udp_associations.get(&reply.association_id) else { return false };
            if association.closed {
                return false;
            }
            let Some(addr) = association.client_udp_addr.clone() else { return false };
            addr
        };
        let Some(socket) = s.udp_sockets.get(&reply.association_id).cloned() else { return false };
        let header = SocksServer::socks5_udp_header(ip, reply.port);
        let mut datagram = header;
        datagram.extend_from_slice(&reply.payload);
        let target: std::net::SocketAddr = match format!("{}:{}", client_addr.0, client_addr.1).parse() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let sent = socket.try_send_to(&datagram, target).is_ok();
        if sent {
            if let Some(association) = s.udp_associations.get_mut(&reply.association_id) {
                association.bytes_received += reply.payload.len() as u64;
                association.touch(now);
            }
        }
        sent
    }

    async fn handle_client(server: Rc<RefCell<SocksServer>>, stream: tokio::net::TcpStream) {
        let peer = stream.peer_addr().ok();
        let (mut reader, mut writer) = stream.into_split();
        match SocksServer::negotiate_and_connect(&server, &mut reader, &mut writer, peer).await {
            Ok(()) => {}
            Err(SocksError(code)) => {
                let _ = SocksServer::write_reply(&mut writer, code, "0.0.0.0", 0).await;
                let _ = writer.flush().await;
                let _ = writer.shutdown().await;
            }
        }
    }

    async fn write_reply(writer: &mut OwnedWriteHalf, code: u8, host: &str, port: u16) -> std::io::Result<()> {
        let mut out = vec![SOCKS_VERSION, code, 0x00];
        out.extend_from_slice(&encode_address(host, port));
        writer.write_all(&out).await
    }

    async fn read_address_body(reader: &mut OwnedReadHalf, atyp: u8) -> Result<Vec<u8>, SocksError> {
        match atyp {
            ATYP_IPV4 => {
                let mut buf = [0u8; 6];
                reader.read_exact(&mut buf).await.map_err(|_| SocksError(REPLY_GENERAL))?;
                Ok(buf.to_vec())
            }
            ATYP_IPV6 => {
                let mut buf = [0u8; 18];
                reader.read_exact(&mut buf).await.map_err(|_| SocksError(REPLY_GENERAL))?;
                Ok(buf.to_vec())
            }
            ATYP_DOMAIN => {
                let mut len_buf = [0u8; 1];
                reader.read_exact(&mut len_buf).await.map_err(|_| SocksError(REPLY_GENERAL))?;
                let length = len_buf[0] as usize;
                let mut rest = vec![0u8; length + 2];
                reader.read_exact(&mut rest).await.map_err(|_| SocksError(REPLY_GENERAL))?;
                let mut out = vec![length as u8];
                out.extend_from_slice(&rest);
                Ok(out)
            }
            _ => Err(SocksError(REPLY_ADDR_UNSUPPORTED)),
        }
    }

    async fn negotiate_and_connect(
        server: &Rc<RefCell<SocksServer>>,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        peer: Option<std::net::SocketAddr>,
    ) -> Result<(), SocksError> {
        let mut greeting = [0u8; 2];
        reader.read_exact(&mut greeting).await.map_err(|_| SocksError(REPLY_GENERAL))?;
        let (version, nmethods) = (greeting[0], greeting[1]);
        if version != SOCKS_VERSION {
            return Err(SocksError(REPLY_GENERAL));
        }
        let mut methods = vec![0u8; nmethods as usize];
        reader.read_exact(&mut methods).await.map_err(|_| SocksError(REPLY_GENERAL))?;
        if !SocksServer::negotiate_no_auth(&methods) {
            let _ = writer.write_all(&[SOCKS_VERSION, 0xFF]).await;
            let _ = writer.flush().await;
            return Err(SocksError(REPLY_GENERAL));
        }
        writer.write_all(&[SOCKS_VERSION, 0x00]).await.map_err(|_| SocksError(REPLY_GENERAL))?;
        writer.flush().await.map_err(|_| SocksError(REPLY_GENERAL))?;

        let mut head = [0u8; 4];
        reader.read_exact(&mut head).await.map_err(|_| SocksError(REPLY_GENERAL))?;
        let (version, cmd, atyp) = (head[0], head[1], head[3]);
        if version != SOCKS_VERSION {
            return Err(SocksError(REPLY_GENERAL));
        }
        let body = SocksServer::read_address_body(reader, atyp).await?;
        let mut full = vec![atyp];
        full.extend_from_slice(&body);
        let (host, port, _consumed) = parse_address(&full)?;

        match cmd {
            CMD_CONNECT => SocksServer::do_connect(server, reader, writer, host, port).await,
            CMD_RESOLVE => SocksServer::do_resolve(server, writer, host).await,
            CMD_UDP_ASSOCIATE => SocksServer::do_udp_associate(server, reader, writer, peer).await,
            _ => Err(SocksError(REPLY_CMD_UNSUPPORTED)),
        }
    }

    async fn forward_request(server: &Rc<RefCell<SocksServer>>, request: &crate::socks::StreamRequest, key: Option<CircuitKey>) -> Result<(), SocksError> {
        let onion = server.borrow().resolve_onion(key);
        let Some(onion) = onion else { return Err(SocksError(REPLY_GENERAL)) };
        let encoded = crate::socks::encode_request(request).map_err(|_| SocksError(REPLY_GENERAL))?;
        (*onion.borrow_mut())(&encoded);
        Ok(())
    }

    async fn await_reply(
        server: &Rc<RefCell<SocksServer>>,
        request: crate::socks::StreamRequest,
        onion: Option<CircuitKey>,
        timeout_secs: f64,
    ) -> Result<(crate::socks::StreamReply, Option<CircuitKey>), SocksError> {
        let request_id = request.request_id;
        let (tx, rx) = tokio::sync::oneshot::channel();
        server.borrow_mut().pending.insert(request_id, tx);
        let resolved_key = if let Some(k) = onion {
            server.borrow_mut().request_onion.insert(request_id, k);
            Some(k)
        } else {
            let router = server.borrow().onion_router.clone();
            match router {
                Some(router) => match router(request.host.clone(), request.port).await {
                    Ok(k) => {
                        server.borrow_mut().request_onion.insert(request_id, k);
                        Some(k)
                    }
                    Err(e) => {
                        server.borrow_mut().pending.remove(&request_id);
                        return Err(e);
                    }
                },
                None => None,
            }
        };
        let held = resolved_key;
        if let Some(k) = held {
            if let Some(cb) = server.borrow_mut().onion_stream_started.as_mut() {
                cb(k);
            }
        }
        let outcome = {
            let sent = SocksServer::forward_request(server, &request, resolved_key).await;
            if let Err(e) = sent {
                server.borrow_mut().pending.remove(&request_id);
                Err(e)
            } else {
                let timeout = Duration::from_secs_f64(timeout_secs.max(0.0));
                match tokio::time::timeout(timeout, rx).await {
                    Ok(Ok(reply)) => Ok(reply),
                    Ok(Err(_)) => {
                        server.borrow_mut().pending.remove(&request_id);
                        Err(SocksError(REPLY_GENERAL))
                    }
                    Err(_) => {
                        server.borrow_mut().pending.remove(&request_id);
                        Err(SocksError(REPLY_TTL_EXPIRED))
                    }
                }
            }
        };
        let popped = server.borrow_mut().request_onion.remove(&request_id);
        if let Some(k) = held {
            if let Some(cb) = server.borrow_mut().onion_stream_finished.as_mut() {
                cb(k);
            }
        }
        outcome.map(|reply| (reply, popped))
    }

    async fn request_with_retry(
        server: &Rc<RefCell<SocksServer>>,
        kind: u8,
        host: String,
        port: u16,
    ) -> Result<(crate::socks::StreamReply, Option<CircuitKey>), SocksError> {
        let (max_attempts, connect_timeout, retry_timeout) = {
            let s = server.borrow();
            (s.max_connect_attempts, s.connect_timeout_secs, s.retry_connect_timeout_secs)
        };
        let mut failed_key: Option<CircuitKey> = None;
        let mut reason: &'static str = "circuit";
        let mut last_code = REPLY_GENERAL;
        for attempt in 0..max_attempts {
            let mut key: Option<CircuitKey> = None;
            if attempt > 0 {
                server.borrow_mut().retries_attempted += 1;
                let retry_fn = server.borrow().onion_retry.clone();
                let Some(retry_fn) = retry_fn else { break };
                match retry_fn(host.clone(), port, failed_key, reason).await {
                    Ok(Some(k)) => key = Some(k),
                    Ok(None) => break,
                    Err(e) => {
                        last_code = e.0;
                        continue;
                    }
                }
            }
            let request_id = server.borrow_mut().alloc_request_id();
            let timeout = if attempt == 0 { connect_timeout } else { retry_timeout };
            let request = crate::socks::StreamRequest { kind, request_id, host: host.clone(), port, bytes_sent: 0 };
            match SocksServer::await_reply(server, request, key, timeout).await {
                Ok((reply, used_key)) => {
                    if SocksServer::reply_is_ok(kind, &reply) {
                        if attempt > 0 {
                            server.borrow_mut().retries_succeeded += 1;
                        }
                        return Ok((reply, used_key));
                    }
                    last_code = status_to_socks(reply.status);
                    if !is_retryable(reply.status) {
                        return Err(SocksError(last_code));
                    }
                    failed_key = used_key.or(key).or_else(|| server.borrow().current_onion_guess());
                    reason = SocksServer::retry_reason_for_exit_status(reply.status, kind);
                }
                Err(e) => {
                    last_code = e.0;
                    if last_code != REPLY_TTL_EXPIRED && last_code != REPLY_GENERAL {
                        return Err(e);
                    }
                    failed_key = key.or_else(|| server.borrow().current_onion_guess());
                    reason = SocksServer::retry_reason_for_local_failure(last_code);
                }
            }
        }
        Err(SocksError(last_code))
    }

    async fn do_connect(
        server: &Rc<RefCell<SocksServer>>,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        host: String,
        port: u16,
    ) -> Result<(), SocksError> {
        if SocksServer::is_hidden_service_host(&host) {
            return SocksServer::do_connect_hidden_service(server, reader, writer, host, port).await;
        }
        let (reply, onion_key) = SocksServer::request_with_retry(server, crate::socks::CONNECT, host, port).await?;
        let circuit_key = onion_key.or_else(|| Some(server.borrow().default_key()));
        if let Some(k) = circuit_key {
            if let Some(cb) = server.borrow_mut().onion_stream_started.as_mut() {
                cb(k);
            }
        }
        let result = SocksServer::do_connect_relay(server, reader, writer, reply.stream_id, circuit_key).await;
        if let Some(k) = circuit_key {
            if let Some(cb) = server.borrow_mut().onion_stream_finished.as_mut() {
                cb(k);
            }
        }
        result
    }

    /// The success-path body of `do_connect`, split out so the
    /// `onion_stream_started`/`onion_stream_finished` pair around it (see
    /// `do_connect`) does not need an inner `async {}` block capturing
    /// `&mut` reader/writer references -- simpler to reason about than
    /// relying on implicit reborrow-through-capture in an anonymous async
    /// block.
    async fn do_connect_relay(
        server: &Rc<RefCell<SocksServer>>,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        stream_id: u32,
        circuit_key: Option<CircuitKey>,
    ) -> Result<(), SocksError> {
        SocksServer::write_reply(writer, REPLY_SUCCEEDED, "0.0.0.0", 0).await.map_err(|_| SocksError(REPLY_GENERAL))?;
        writer.flush().await.map_err(|_| SocksError(REPLY_GENERAL))?;
        SocksServer::relay_stream(server, stream_id, reader, writer, circuit_key).await;
        Ok(())
    }

    async fn do_connect_hidden_service(
        server: &Rc<RefCell<SocksServer>>,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        host: String,
        port: u16,
    ) -> Result<(), SocksError> {
        let connector = server.borrow().hidden_service_connect.clone();
        let Some(connector) = connector else { return Err(SocksError(REPLY_HOST_UNREACHABLE)) };
        let connection = connector(host, port).await?;
        SocksServer::write_reply(writer, REPLY_SUCCEEDED, "0.0.0.0", 0).await.map_err(|_| SocksError(REPLY_GENERAL))?;
        writer.flush().await.map_err(|_| SocksError(REPLY_GENERAL))?;
        SocksServer::relay_hidden_service(connection, reader, writer).await;
        Ok(())
    }

    /// Simplified relative to Python's `_relay_hidden_service` (see the
    /// module docs' "Simplifications" note): a single poll loop rather than
    /// two coroutines raced with `asyncio.wait`, since `HsTunnel` has no
    /// in-tree implementation to test the extra complexity against yet.
    async fn relay_hidden_service(connection: Rc<RefCell<dyn HsTunnel>>, reader: &mut OwnedReadHalf, writer: &mut OwnedWriteHalf) {
        let mut buf = [0u8; 4096];
        loop {
            tokio::select! {
                read = reader.read(&mut buf) => {
                    match read {
                        Ok(0) => break,
                        Err(_) => break,
                        Ok(n) => {
                            // Named guard, not a temporary -- `.send()`'s
                            // returned future borrows `&mut self` from it,
                            // and a temporary `RefMut` would be dropped
                            // before that future is polled (the same
                            // soundness trap documented in `relay.rs`'s
                            // module docs for a `RefCell`-borrowed socket).
                            let mut guard = connection.borrow_mut();
                            let fut = guard.send(buf[..n].to_vec());
                            if fut.await.is_err() {
                                break;
                            }
                        }
                    }
                }
                recv = async {
                    let mut guard = connection.borrow_mut();
                    let fut = guard.receive(Duration::from_secs(2));
                    fut.await
                } => {
                    match recv {
                        Ok(data) if !data.is_empty() => {
                            if writer.write_all(&data).await.is_err() {
                                break;
                            }
                            let _ = writer.flush().await;
                        }
                        Ok(_) => continue,
                        Err(_) => continue,
                    }
                }
            }
        }
        connection.borrow_mut().close();
        let _ = writer.shutdown().await;
    }

    async fn do_resolve(server: &Rc<RefCell<SocksServer>>, writer: &mut OwnedWriteHalf, host: String) -> Result<(), SocksError> {
        let (reply, _onion) = SocksServer::request_with_retry(server, crate::socks::RESOLVE, host, 0).await?;
        let (addr_host, addr_port) = reply.address.unwrap_or_else(|| ("0.0.0.0".to_string(), 0));
        SocksServer::write_reply(writer, REPLY_SUCCEEDED, &addr_host, addr_port).await.map_err(|_| SocksError(REPLY_GENERAL))?;
        writer.flush().await.map_err(|_| SocksError(REPLY_GENERAL))?;
        let _ = writer.shutdown().await;
        Ok(())
    }

    async fn do_udp_associate(
        server: &Rc<RefCell<SocksServer>>,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        peer: Option<std::net::SocketAddr>,
    ) -> Result<(), SocksError> {
        let (allow_udp, host) = {
            let s = server.borrow();
            (s.allow_udp, s.host.clone())
        };
        if !allow_udp {
            return Err(SocksError(REPLY_CMD_UNSUPPORTED));
        }
        let udp = tokio::net::UdpSocket::bind((host.as_str(), 0)).await.map_err(|_| SocksError(REPLY_GENERAL))?;
        let local = udp.local_addr().map_err(|_| SocksError(REPLY_GENERAL))?;
        let association_id = server.borrow().alloc_association_id().map_err(|_| SocksError(REPLY_GENERAL))?;
        let udp = Rc::new(udp);
        let control_peer = peer.map(|p| (p.ip().to_string(), p.port()));
        {
            let mut s = server.borrow_mut();
            s.udp_sockets.insert(association_id, udp.clone());
            s.udp_associations.insert(association_id, UdpAssociation::new(association_id, control_peer, None, now_secs()));
        }
        SocksServer::write_reply(writer, REPLY_SUCCEEDED, &local.ip().to_string(), local.port())
            .await
            .map_err(|_| SocksError(REPLY_GENERAL))?;
        writer.flush().await.map_err(|_| SocksError(REPLY_GENERAL))?;

        let sv = server.clone();
        let pump_udp = udp.clone();
        let pump = tokio::task::spawn_local(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match pump_udp.recv_from(&mut buf).await {
                    Ok((n, addr)) => {
                        let data = buf[..n].to_vec();
                        sv.borrow_mut().on_client_datagram(association_id, &data, &addr.ip().to_string(), now_secs());
                    }
                    Err(_) => break,
                }
            }
        });

        // The TCP control connection stays open for the lifetime of the
        // UDP association (RFC 1928 SS7); when it closes, tear the relay
        // down.
        let mut scratch = [0u8; 256];
        loop {
            match reader.read(&mut scratch).await {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
        pump.abort();
        let mut s = server.borrow_mut();
        s.udp_sockets.remove(&association_id);
        if let Some(a) = s.udp_associations.get_mut(&association_id) {
            a.close();
        }
        s.udp_associations.remove(&association_id);
        Ok(())
    }

    /// `_relay_stream`: relay bytes both ways for an established CONNECT
    /// stream. Return-path bytes arrive via `deliver_data`/`write_to_stream`
    /// (already ported, pure), which call into whatever writer was
    /// registered via `register_writer` for `(circuit_key, stream_id)` --
    /// this function is what registers that writer for the lifetime of the
    /// relay loop.
    async fn relay_stream(
        server: &Rc<RefCell<SocksServer>>,
        stream_id: u32,
        reader: &mut OwnedReadHalf,
        writer: &mut OwnedWriteHalf,
        circuit_key: Option<CircuitKey>,
    ) {
        let key = (server.borrow().resolve_key(circuit_key), stream_id);
        // Registering a real writer here would need `Writer` (`FnMut(&[u8])
        // + Send`) to reach this task's `OwnedWriteHalf` -- instead this
        // loop polls `write_to_stream`'s pending buffer itself on each
        // iteration, avoiding a second indirection through the closure
        // storage that `register_writer` exists for (that storage remains
        // available for a caller who wants to feed this stream's return
        // data from a different task).
        let mut offset: u32 = 0;
        loop {
            {
                let mut s = server.borrow_mut();
                if s.closed_streams.contains(&key) {
                    break;
                }
                if let Some(pending) = s.pending_write.remove(&key) {
                    if !pending.is_empty() {
                        drop(s);
                        if writer.write_all(&pending).await.is_err() {
                            break;
                        }
                        let _ = writer.flush().await;
                        continue;
                    }
                }
            }
            let mut buf = [0u8; 4096];
            let read = tokio::time::timeout(Duration::from_millis(250), reader.read(&mut buf)).await;
            let data = match read {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => buf[..n].to_vec(),
                Ok(Err(_)) => break,
                Err(_) => continue, // poll timeout; loop to re-check closed_streams
            };
            let onion = server.borrow().resolve_onion(circuit_key);
            let Some(onion) = onion else { break };
            let mtu = server.borrow().mtu;
            let mut remaining = data.as_slice();
            // No artificial pacing here (previously: a forced 5ms sleep
            // every 8 fragments, which hard-capped this direction around
            // ~3.2 Mbit/s regardless of link quality). Pacing is left
            // entirely to the congestion controller's can_send() gate,
            // matching the Python port.
            while !remaining.is_empty() {
                let take = remaining.len().min(mtu);
                let (chunk, rest) = remaining.split_at(take);
                let frag = encode_fragment(&Fragment { stream_id, offset, fin: false, data: chunk.to_vec() });
                (*onion.borrow_mut())(&frag);
                offset += chunk.len() as u32;
                remaining = rest;
            }
        }
        server.borrow_mut().closed_streams.remove(&key);
        // The read loop ending does not, by itself, mean the reply is
        // fully delivered -- return data keeps arriving via
        // `deliver_data`/`write_to_stream` until the exit's own
        // `close_stream` signal, exactly as in Python.
    }

    // TOKIO-SOCKS-LIVE-END
}

fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fragment::Fragmenter;

    // -- INTRODUCE1 rate limiting -------

    #[test]
    fn intro_rate_limiter_allows_burst_then_throttles_and_refills() {
        let mut limiter = IntroRateLimiter::new(0.0, 5.0, 3.0);
        assert!(limiter.allow(0.0));
        assert!(limiter.allow(0.0));
        assert!(limiter.allow(0.0));
        assert!(!limiter.allow(0.0), "burst of 3 must be exhausted by the 4th immediate call");
        // At 5 tokens/sec, 0.5s refills 2.5 tokens -- enough for two more.
        assert!(limiter.allow(0.5));
        assert!(limiter.allow(0.5));
        assert!(!limiter.allow(0.5));
    }

    #[test]
    fn allow_introduce1_lets_a_single_sender_exhaust_only_its_own_sub_budget() {
        // Even though the shared per-service
        // budget (burst 20) has plenty of room left, one sender alone
        // must be capped by its own tighter per-sender budget (burst 4).
        let mut state = HsRelayState::default();
        let auth_pubkey = vec![1u8; 32];
        let sender: CircuitKeyTuple = ("10.0.0.1".to_string(), 9001, 1);
        for _ in 0..INTRODUCE1_PER_SENDER_BURST_TOKENS as usize {
            assert!(state.allow_introduce1(&auth_pubkey, &sender, 0.0));
        }
        assert!(!state.allow_introduce1(&auth_pubkey, &sender, 0.0), "sender's own sub-budget must now be exhausted");
        // The shared bucket was only ever spent by this same sender, so
        // it isn't exhausted -- confirming the sub-limit is what's
        // actually binding here, not the shared one.
        assert!(state.intro_rate.get(&auth_pubkey).unwrap().tokens > 0.0);
    }

    #[test]
    fn allow_introduce1_gives_each_sender_its_own_sub_budget() {
        // A second, distinct sender of the same service must not be
        // blocked by the first sender's exhausted per-sender bucket.
        let mut state = HsRelayState::default();
        let auth_pubkey = vec![2u8; 32];
        let sender_a: CircuitKeyTuple = ("10.0.0.1".to_string(), 9001, 1);
        let sender_b: CircuitKeyTuple = ("10.0.0.2".to_string(), 9001, 2);
        for _ in 0..INTRODUCE1_PER_SENDER_BURST_TOKENS as usize {
            assert!(state.allow_introduce1(&auth_pubkey, &sender_a, 0.0));
        }
        assert!(!state.allow_introduce1(&auth_pubkey, &sender_a, 0.0));
        assert!(state.allow_introduce1(&auth_pubkey, &sender_b, 0.0), "a different sender must have its own budget");
    }

    #[test]
    fn allow_introduce1_still_enforces_the_shared_budget_across_senders() {
        // The shared-budget enforcement must still hold: many
        // distinct senders (each well within their own per-sender budget)
        // must still collectively be capped by the shared per-service
        // budget (burst 20).
        let mut state = HsRelayState::default();
        let auth_pubkey = vec![3u8; 32];
        for i in 0..INTRODUCE1_BURST_TOKENS as u32 {
            let sender: CircuitKeyTuple = (format!("10.0.{}.1", i / 256), (i % 65535) as u16 + 1, i);
            assert!(state.allow_introduce1(&auth_pubkey, &sender, 0.0));
        }
        let one_more: CircuitKeyTuple = ("10.9.9.9".to_string(), 9999, 9999);
        assert!(!state.allow_introduce1(&auth_pubkey, &one_more, 0.0), "the shared budget must now be exhausted");
    }

    #[test]
    fn allow_introduce1_caps_the_per_sender_map_size() {
        let mut state = HsRelayState::default();
        let auth_pubkey = vec![4u8; 32];
        for i in 0..MAX_HS_INTRO_PER_SENDER_LIMITERS + 10 {
            let sender: CircuitKeyTuple = ("10.0.0.1".to_string(), (i % 65535) as u16, i as u32);
            state.allow_introduce1(&auth_pubkey, &sender, 0.0);
        }
        assert!(state.intro_rate_per_sender.len() <= MAX_HS_INTRO_PER_SENDER_LIMITERS);
    }

    #[test]
    fn test_ipv4_parse() {
        let mut data = vec![ATYP_IPV4, 93, 184, 216, 34];
        data.extend_from_slice(&80u16.to_be_bytes());
        let (host, port, consumed) = parse_address(&data).unwrap();
        assert_eq!(host, "93.184.216.34");
        assert_eq!(port, 80);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_domain_parse() {
        let mut data = vec![ATYP_DOMAIN, 11];
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&443u16.to_be_bytes());
        let (host, port, _) = parse_address(&data).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_unknown_atyp_is_rejected() {
        assert!(parse_address(&[0x99]).is_err());
    }

    #[test]
    fn test_encode_address_round_trips_ipv4() {
        let encoded = encode_address("93.184.216.34", 80);
        let (host, port, _) = parse_address(&encoded).unwrap();
        assert_eq!(host, "93.184.216.34");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_encode_address_domain() {
        let encoded = encode_address("example.com", 443);
        let (host, port, _) = parse_address(&encoded).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_status_to_socks_mapping() {
        assert_eq!(status_to_socks(SUCCESS), REPLY_SUCCEEDED);
        assert_eq!(status_to_socks(HOST_UNREACHABLE), REPLY_HOST_UNREACHABLE);
        assert_eq!(status_to_socks(255), REPLY_GENERAL);
    }

    #[test]
    fn test_retryable_statuses() {
        assert!(is_retryable(GENERAL_FAILURE));
        assert!(is_retryable(COMMAND_UNSUPPORTED));
        assert!(!is_retryable(CONNECTION_REFUSED));
        assert!(!is_retryable(ADDR_UNSUPPORTED));
    }

    #[test]
    fn test_udp_association_touch_and_close() {
        let mut a = UdpAssociation::new(1, None, None, 0.0);
        a.touch(5.0);
        assert_eq!(a.last_activity, 5.0);
        a.close();
        assert!(a.closed);
        a.close(); // idempotent
        assert!(a.closed);
    }

    #[test]
    fn test_reassembles_fragments_and_writes_to_the_writer() {
        let mut server = SocksServer::new(8);
        let payload = "return path data!".repeat(5).into_bytes();
        let fragments = Fragmenter::new(8, 3).unwrap().fragment(&payload);
        let written = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let w2 = written.clone();
        server.register_writer(None, 3, Box::new(move |d: &[u8]| w2.lock().unwrap().extend_from_slice(d)));
        for frag in &fragments {
            server.deliver_data(3, &encode_fragment(frag), None);
        }
        assert_eq!(*written.lock().unwrap(), payload);
    }

    #[test]
    fn test_returns_the_bytes_written() {
        let mut server = SocksServer::new(8);
        server.register_writer(None, 1, Box::new(|_| {}));
        let frags = Fragmenter::new(8, 1).unwrap().fragment(b"hello");
        let mut out = Vec::new();
        for frag in &frags {
            out.extend_from_slice(&server.deliver_data(1, &encode_fragment(frag), None));
        }
        assert_eq!(out, b"hello");
    }

    /// Round I: `deliver_data` for a stream with no *registered* writer
    /// (i.e. no prior `register_writer` call) must **buffer** the
    /// reassembled bytes into `pending_write` and still return them --
    /// not silently drop them, which is what this test originally
    /// asserted (a direct, but stale, port of `deliver_data`'s Python
    /// behaviour, which really does return `b""` when `_live_writer` is
    /// `None`). The Rust `_relay_stream` port (`SocksServer::relay_stream`)
    /// deliberately never calls `register_writer` at all -- unlike
    /// Python's `_relay_stream`, which does register a real
    /// `asyncio.StreamWriter` -- and instead polls `pending_write` itself
    /// each loop iteration (see `relay_stream`'s own doc comment). Without
    /// this buffering fallback, every return-path chunk for an ordinary
    /// CONNECT stream was silently thrown away here before `relay_stream`
    /// ever got a chance to see it -- the final link in the real 3-hop
    /// CONNECT hang chased down in
    /// `test_three_hop_connect_stream_over_real_loopback_udp_and_tcp`.
    /// A stream is only ever really "unknown" once its client is marked
    /// gone (`client_gone`), which is covered separately by
    /// `test_close_stream_flushes_pending_and_reports_existed` and friends.
    #[test]
    fn test_data_for_a_stream_with_no_registered_writer_is_buffered_not_dropped() {
        let mut server = SocksServer::new(8);
        let payload = vec![b'x'; 20];
        let frags = Fragmenter::new(8, 9).unwrap().fragment(&payload);
        let mut out = Vec::new();
        for frag in &frags {
            out.extend_from_slice(&server.deliver_data(9, &encode_fragment(frag), None));
        }
        assert_eq!(out, payload, "reassembled bytes should be returned, not dropped, when no writer is registered");
        // And they must actually have landed in `pending_write`, ready for
        // `relay_stream`'s own poll loop (or `flush_pending`) to pick up --
        // not just handed back to this call's return value and lost.
        let key = (server.resolve_key(None), 9);
        assert_eq!(server.pending_write.get(&key).map(|v| v.as_slice()), Some(payload.as_slice()));
    }

    #[test]
    fn test_ignores_non_fragment() {
        let mut server = SocksServer::new(8);
        assert_eq!(server.deliver_data(1, b"short", None), Vec::<u8>::new());
    }

    #[test]
    fn test_deliver_data_colliding_stream_ids_on_different_circuits_do_not_cross_wire() {
        let mut server = SocksServer::new(64);
        let onion_a: CircuitKey = 1;
        let onion_b: CircuitKey = 2;
        let a = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let b = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let a2 = a.clone();
        let b2 = b.clone();
        server.register_writer(Some(onion_a), 1, Box::new(move |d: &[u8]| a2.lock().unwrap().extend_from_slice(d)));
        server.register_writer(Some(onion_b), 1, Box::new(move |d: &[u8]| b2.lock().unwrap().extend_from_slice(d)));
        for frag in &Fragmenter::new(64, 1).unwrap().fragment(b"circuit A's secret") {
            server.deliver_data(1, &encode_fragment(frag), Some(onion_a));
        }
        for frag in &Fragmenter::new(64, 1).unwrap().fragment(b"circuit B's secret") {
            server.deliver_data(1, &encode_fragment(frag), Some(onion_b));
        }
        assert_eq!(*a.lock().unwrap(), b"circuit A's secret");
        assert_eq!(*b.lock().unwrap(), b"circuit B's secret");
    }

    #[test]
    fn test_writes_only_to_the_named_stream() {
        let mut server = SocksServer::new(8);
        let a = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let b = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let a2 = a.clone();
        let b2 = b.clone();
        server.register_writer(None, 1, Box::new(move |d: &[u8]| a2.lock().unwrap().extend_from_slice(d)));
        server.register_writer(None, 2, Box::new(move |d: &[u8]| b2.lock().unwrap().extend_from_slice(d)));
        server.write_to_stream(1, b"reply for A", None);
        assert_eq!(*a.lock().unwrap(), b"reply for A");
        assert_eq!(*b.lock().unwrap(), b"");
    }

    #[test]
    fn test_data_for_each_stream_stays_independent() {
        let mut server = SocksServer::new(8);
        let a = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let b = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let a2 = a.clone();
        let b2 = b.clone();
        server.register_writer(None, 1, Box::new(move |d: &[u8]| a2.lock().unwrap().extend_from_slice(d)));
        server.register_writer(None, 2, Box::new(move |d: &[u8]| b2.lock().unwrap().extend_from_slice(d)));
        server.write_to_stream(2, b"for B", None);
        server.write_to_stream(1, b"for A", None);
        server.write_to_stream(2, b" again", None);
        assert_eq!(*a.lock().unwrap(), b"for A");
        assert_eq!(*b.lock().unwrap(), b"for B again");
    }

    #[test]
    fn test_early_data_is_buffered_per_stream_not_shared() {
        let mut server = SocksServer::new(8);
        server.write_to_stream(1, b"early for A", None);
        server.write_to_stream(2, b"early for B", None);

        let b = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let b2 = b.clone();
        server.register_writer(None, 2, Box::new(move |d: &[u8]| b2.lock().unwrap().extend_from_slice(d)));
        let key = server.default_key();
        server.flush_pending(key, 2);
        assert_eq!(*b.lock().unwrap(), b"early for B");

        let a = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let a2 = a.clone();
        server.register_writer(None, 1, Box::new(move |d: &[u8]| a2.lock().unwrap().extend_from_slice(d)));
        server.flush_pending(key, 1);
        assert_eq!(*a.lock().unwrap(), b"early for A");
    }

    #[test]
    fn test_write_to_stream_with_no_writer_buffers_and_returns_false() {
        let mut server = SocksServer::new(8);
        assert!(!server.write_to_stream(5, b"data", None));
        let key = (server.default_key(), 5);
        assert_eq!(server.pending_write.get(&key).unwrap(), b"data");
    }

    #[test]
    fn test_write_to_stream_colliding_stream_ids_on_different_circuits_do_not_cross_wire() {
        let mut server = SocksServer::new(8);
        let onion_a: CircuitKey = 1;
        let onion_b: CircuitKey = 2;
        let a = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let b = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let a2 = a.clone();
        let b2 = b.clone();
        server.register_writer(Some(onion_a), 1, Box::new(move |d: &[u8]| a2.lock().unwrap().extend_from_slice(d)));
        server.register_writer(Some(onion_b), 1, Box::new(move |d: &[u8]| b2.lock().unwrap().extend_from_slice(d)));
        server.write_to_stream(1, b"for A", Some(onion_a));
        server.write_to_stream(1, b"for B", Some(onion_b));
        assert_eq!(*a.lock().unwrap(), b"for A");
        assert_eq!(*b.lock().unwrap(), b"for B");
    }

    #[test]
    fn test_close_stream_flushes_pending_and_reports_existed() {
        let mut server = SocksServer::new(8);
        assert!(!server.close_stream(1, None));
        let a = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let a2 = a.clone();
        server.register_writer(None, 1, Box::new(move |d: &[u8]| a2.lock().unwrap().extend_from_slice(d)));
        assert!(server.close_stream(1, None));
    }

    #[test]
    fn test_fragment_outbound_reassembles() {
        let server = SocksServer::new(4);
        let chunks = server.fragment_outbound(7, 0, b"hello world");
        let mut reassembler = Reassembler::new(7, 1024);
        let mut out = Vec::new();
        for c in &chunks {
            let frag = decode_fragment(c).unwrap();
            out.extend_from_slice(&reassembler.push(&frag).unwrap());
        }
        // Not FIN-marked (matches `_relay_stream`'s own chunks, whose FIN
        // is decided by the live loop, not this pure chunker), so the
        // reassembler will not have released the tail without one more
        // explicit flush in the real relay loop -- this test only checks
        // the chunker's byte-level correctness via a manual concatenation.
        let mut direct = Vec::new();
        for c in &chunks {
            let frag = decode_fragment(c).unwrap();
            direct.extend_from_slice(&frag.data);
        }
        assert_eq!(direct, b"hello world");
    }

    // -- SocksServer live-loop: pure decision logic ------------------------

    #[test]
    fn test_negotiate_no_auth() {
        assert!(SocksServer::negotiate_no_auth(&[0x02, 0x00, 0x01]));
        assert!(!SocksServer::negotiate_no_auth(&[0x02, 0x01]));
        assert!(!SocksServer::negotiate_no_auth(&[]));
    }

    #[test]
    fn test_reply_is_ok_connect() {
        let reply = crate::socks::StreamReply { request_id: 1, status: SUCCESS, stream_id: 5, address: None };
        assert!(SocksServer::reply_is_ok(crate::socks::CONNECT, &reply));
        let bad = crate::socks::StreamReply { request_id: 1, status: crate::socks::GENERAL_FAILURE, stream_id: 5, address: None };
        assert!(!SocksServer::reply_is_ok(crate::socks::CONNECT, &bad));
    }

    #[test]
    fn test_reply_is_ok_resolve_needs_address() {
        let no_addr = crate::socks::StreamReply { request_id: 1, status: SUCCESS, stream_id: 0, address: None };
        assert!(!SocksServer::reply_is_ok(crate::socks::RESOLVE, &no_addr));
        let with_addr = crate::socks::StreamReply {
            request_id: 1,
            status: SUCCESS,
            stream_id: 0,
            address: Some(("93.184.216.34".to_string(), 0)),
        };
        assert!(SocksServer::reply_is_ok(crate::socks::RESOLVE, &with_addr));
    }

    #[test]
    fn test_retry_reason_for_local_failure() {
        assert_eq!(SocksServer::retry_reason_for_local_failure(REPLY_TTL_EXPIRED), "timeout");
        assert_eq!(SocksServer::retry_reason_for_local_failure(REPLY_GENERAL), "circuit");
    }

    #[test]
    fn test_retry_reason_for_exit_status() {
        assert_eq!(
            SocksServer::retry_reason_for_exit_status(COMMAND_UNSUPPORTED, crate::socks::CONNECT),
            "exit-policy"
        );
        assert_eq!(
            SocksServer::retry_reason_for_exit_status(COMMAND_UNSUPPORTED, crate::socks::RESOLVE),
            "exit-error"
        );
        assert_eq!(
            SocksServer::retry_reason_for_exit_status(GENERAL_FAILURE, crate::socks::CONNECT),
            "exit-error"
        );
    }

    #[test]
    fn test_is_hidden_service_host() {
        assert!(SocksServer::is_hidden_service_host("abc123.allium"));
        assert!(SocksServer::is_hidden_service_host("ABC123.ALLIUM"));
        assert!(!SocksServer::is_hidden_service_host("example.com"));
    }

    #[test]
    fn test_socks5_udp_header() {
        let header = SocksServer::socks5_udp_header(std::net::Ipv4Addr::new(1, 2, 3, 4), 80);
        assert_eq!(header, vec![0x00, 0x00, 0x00, ATYP_IPV4, 1, 2, 3, 4, 0, 80]);
    }

    #[test]
    fn test_with_options_registers_default_onion() {
        let sent = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let sent2 = sent.clone();
        let onion: Onion = Rc::new(RefCell::new(move |data: &[u8]| sent2.borrow_mut().push(data.to_vec())));
        let mut options = SocksServerOptions::new(onion);
        options.port = 0;
        let server = SocksServer::with_options(options);
        let (host, port) = server.address();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 0);
        let resolved = server.resolve_onion(None).expect("default onion registered");
        (*resolved.borrow_mut())(b"hi");
        assert_eq!(sent.borrow().as_slice(), &[b"hi".to_vec()]);
    }

    #[test]
    fn test_current_onion_guess_without_router() {
        let onion: Onion = Rc::new(RefCell::new(|_: &[u8]| {}));
        let server = SocksServer::with_options(SocksServerOptions::new(onion));
        assert_eq!(server.current_onion_guess(), Some(server.default_key()));
    }

    #[test]
    fn test_on_client_datagram_rejects_fragmented() {
        let sent = Rc::new(RefCell::new(0u32));
        let sent2 = sent.clone();
        let onion: Onion = Rc::new(RefCell::new(move |_: &[u8]| *sent2.borrow_mut() += 1));
        let mut options = SocksServerOptions::new(Rc::new(RefCell::new(|_: &[u8]| {})));
        options.allow_udp = true;
        options.onion_datagram = Some(onion);
        let mut server = SocksServer::with_options(options);
        server.udp_associations.insert(1, UdpAssociation::new(1, None, None, 0.0));
        let mut datagram = vec![0x00, 0x00, 0x01, ATYP_IPV4]; // FRAG=1: unsupported
        datagram.extend_from_slice(&[93, 184, 216, 34]);
        datagram.extend_from_slice(&80u16.to_be_bytes());
        assert!(!server.on_client_datagram(1, &datagram, "127.0.0.1", 0.0));
        assert_eq!(*sent.borrow(), 0);
    }

    #[test]
    fn test_on_client_datagram_forwards_valid_ipv4() {
        let sent = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let sent2 = sent.clone();
        let onion: Onion = Rc::new(RefCell::new(move |data: &[u8]| sent2.borrow_mut().push(data.to_vec())));
        let mut options = SocksServerOptions::new(Rc::new(RefCell::new(|_: &[u8]| {})));
        options.allow_udp = true;
        options.onion_datagram = Some(onion);
        let mut server = SocksServer::with_options(options);
        server.udp_associations.insert(7, UdpAssociation::new(7, None, None, 0.0));
        let mut datagram = vec![0x00, 0x00, 0x00, ATYP_IPV4];
        datagram.extend_from_slice(&[93, 184, 216, 34]);
        datagram.extend_from_slice(&80u16.to_be_bytes());
        datagram.extend_from_slice(b"payload");
        assert!(server.on_client_datagram(7, &datagram, "127.0.0.1", 1.0));
        assert_eq!(sent.borrow().len(), 1);
        let assoc = server.udp_associations.get(&7).unwrap();
        assert_eq!(assoc.client_udp_addr, Some(("127.0.0.1".to_string(), 0)));
        assert_eq!(assoc.bytes_sent, 7);
    }

    #[test]
    fn test_on_client_datagram_unknown_association_dropped() {
        let mut options = SocksServerOptions::new(Rc::new(RefCell::new(|_: &[u8]| {})));
        options.allow_udp = true;
        let mut server = SocksServer::with_options(options);
        let datagram = vec![0x00, 0x00, 0x00, ATYP_IPV4, 1, 2, 3, 4, 0, 80];
        assert!(!server.on_client_datagram(999, &datagram, "127.0.0.1", 0.0));
    }

    #[test]
    fn test_on_client_datagram_off_host_pinned_sender_rejected() {
        let mut options = SocksServerOptions::new(Rc::new(RefCell::new(|_: &[u8]| {})));
        options.allow_udp = true;
        let mut server = SocksServer::with_options(options);
        server.udp_associations.insert(
            3,
            UdpAssociation::new(3, Some(("10.0.0.5".to_string(), 4000)), None, 0.0),
        );
        let datagram = vec![0x00, 0x00, 0x00, ATYP_IPV4, 1, 2, 3, 4, 0, 80];
        // First packet claims off-host: control_peer is 10.0.0.5, this one
        // is from a different address entirely.
        assert!(!server.on_client_datagram(3, &datagram, "10.0.0.9", 0.0));
    }

    #[test]
    fn test_register_onion_and_next_circuit_key() {
        let mut options = SocksServerOptions::new(Rc::new(RefCell::new(|_: &[u8]| {})));
        options.port = 0;
        let mut server = SocksServer::with_options(options);
        let key = server.next_circuit_key();
        assert_ne!(key, server.default_key());
        let onion: Onion = Rc::new(RefCell::new(|_: &[u8]| {}));
        server.register_onion(key, onion);
        assert!(server.resolve_onion(Some(key)).is_some());
    }

    /// Real, end-to-end, 3-hop SOCKS5 CONNECT: a real [`SocksServer`],
    /// wired to a real, blocking [`crate::circuit::CircuitBuilder`] client
    /// pump (its own OS thread, exactly like `allium-cli`'s
    /// `spawn_circuit_pump`/`cmd_client`), drives a CONNECT stream through
    /// three real, independently running [`RelayNode`]s (guard, middle,
    /// exit -- all real loopback UDP, all real crypto) whose exit is a real
    /// [`SocksExit`]-composed relay backed by a real
    /// [`crate::exit::Egress`] opening a real outbound TCP connection to a
    /// real local TCP listener (standing in for a destination like
    /// ipleak.net). A "curl-equivalent" raw SOCKS5 client, also on its own
    /// OS thread, negotiates the CONNECT, writes a small payload standing
    /// in for a TLS ClientHello, and reads back whatever the origin sent --
    /// exactly the path the user's live `curl --socks5-hostname` hang sat
    /// somewhere on.
    ///
    /// This is the natural next rung up from `relay.rs`'s 2-hop `EXTEND`
    /// test: that one proved circuit *setup* end-to-end; this one proves
    /// the *data path* end-to-end, in both directions, through a real
    /// 3-hop circuit.
    ///
    /// **What this test caught (Round I):** with neither of this round's
    /// two fixes applied, this test hangs (the client thread's final
    /// `read` times out) exactly like the user's live `curl`:
    ///
    /// 1. `Egress::enable_stream_tracking()` was never called anywhere
    ///    outside this crate's own unit tests -- `allium-cli`'s `cmd_exit`
    ///    built an `Egress` and handed it straight to `SocksExit::install`
    ///    without it (see `allium_cli.py`'s `ExitNode.__init__`, which
    ///    calls it unconditionally). Without it, `Egress::track` never
    ///    records an opened stream, so `Egress::send_data` can *never* find
    ///    it again -- moot until fix 2 below, since nothing called
    ///    `send_data` at all, but it would have silently swallowed every
    ///    byte on its own even after fix 2.
    /// 2. `SocksExit::deliver` (this file) only ever recognised a bare
    ///    stream/datagram *request* (`ALSM`/`ALDG`-prefixed); every byte of
    ///    a stream's actual body -- fragment-encoded via
    ///    `crate::fragment::encode_fragment`, with neither magic prefix --
    ///    fell through to "neither shape matched: nothing to do" and was
    ///    silently dropped. `allium_cli.py`'s real, live exit
    ///    (`ExitNode.deliver`) reassembles exactly these fragments per
    ///    `(circuit, stream_id)` and forwards the result to
    ///    `egress.send_data`; this mixin's `deliver` -- ported from the
    ///    library's demo-only `SocksExit`, not from `ExitNode` -- never
    ///    grew that step. This alone fully explains "CONNECT succeeds,
    ///    then nothing ever comes back": the exit's outbound TCP connection
    ///    opened successfully (the CONNECT reply the client got proves
    ///    that), but the ClientHello bytes behind it never left the exit at
    ///    all.
    ///
    /// A third, narrower bug in the same area (verified separately, not by
    /// this test, since it needs a payload that survives a `WouldBlock`/
    /// partial-write race to distinguish from fix 2 alone): `exit.rs`'s
    /// `ExitStream::from_tcp_stream` used to write outbound bytes with a
    /// raw non-blocking `try_write` and discard its result, silently
    /// dropping anything it didn't accept in one call -- unlike Python's
    /// `asyncio.StreamWriter.write`, which buffers internally and never
    /// drops what it was handed. Fixed alongside the above by queueing onto
    /// an unbounded channel and draining it with `write_all` from a
    /// dedicated task.
    #[test]
    fn test_three_hop_connect_stream_over_real_loopback_udp_and_tcp() {
        use std::io::{Read as _, Write as _};

        // A real TCP "origin" (stand-in for ipleak.net): accept one
        // connection, read whatever arrives, echo it back prefixed with a
        // marker, then close -- enough to prove bytes travelled all the way
        // through the real 3-hop circuit and back.
        let origin_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind origin listener");
        let origin_addr = origin_listener.local_addr().expect("origin local_addr");
        let origin_thread = std::thread::spawn(move || {
            let (mut stream, _) = origin_listener.accept().expect("origin accept");
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).expect("origin read");
            let mut reply = b"ECHO:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            stream.write_all(&reply).expect("origin write");
            let _ = stream.flush();
            let _ = stream.shutdown(std::net::Shutdown::Write);
        });

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("failed to start tokio runtime");
        let local = tokio::task::LocalSet::new();
        let result: Result<Vec<u8>, String> = local.block_on(&rt, async move {
            // This test builds a real 3-hop circuit
            // entirely over 127.0.0.1, so -- like every other loopback-based
            // test in relay.rs (see e.g.
            // test_forward_data_extend_layer_is_scheduled_not_forwarded_inline)
            // -- it opts into `allow_private_extend`, the same override a
            // real operator would use only for a loopback test network. The
            // production default (`false`) is unaffected.
            let node_options = |name: &str| crate::relay::RelayNodeOptions {
                node_name: name.to_string(),
                require_identity: false,
                allow_private_extend: true,
                // Not what this test is about (the challenge/cookie retry
                // cycle is covered directly in relay.rs's own tests); keep
                // this end-to-end SOCKS test to a single CREATE round trip.
                require_return_routability: false,
                ..Default::default()
            };
            let guard = Rc::new(RefCell::new(RelayNode::new(node_options("guard")).map_err(|e| e.to_string())?));
            let middle = Rc::new(RefCell::new(RelayNode::new(node_options("middle")).map_err(|e| e.to_string())?));
            let exit_node = Rc::new(RefCell::new(RelayNode::new(node_options("exit")).map_err(|e| e.to_string())?));

            let guard_addr = RelayNode::start(&guard, ("127.0.0.1".to_string(), 0)).await.map_err(|e| e.to_string())?;
            let middle_addr = RelayNode::start(&middle, ("127.0.0.1".to_string(), 0)).await.map_err(|e| e.to_string())?;
            let exit_addr = RelayNode::start(&exit_node, ("127.0.0.1".to_string(), 0)).await.map_err(|e| e.to_string())?;

            // Real `Egress`, no policy/rate-limiter (the origin is a bare
            // IP:port, so no DNS resolution is needed either) -- wired to
            // the exit exactly like `allium-cli`'s `cmd_exit`, including
            // this round's `enable_stream_tracking` fix.
            let egress = crate::exit::Egress::new(None, None, None, None, None);
            let egress = Rc::new(tokio::sync::Mutex::new(egress));
            egress.lock().await.enable_stream_tracking();
            SocksExit::install(&exit_node, egress);

            tokio::task::spawn_local(RelayNode::serve_loop(guard.clone()));
            tokio::task::spawn_local(RelayNode::serve_loop(middle.clone()));
            tokio::task::spawn_local(RelayNode::serve_loop(exit_node.clone()));

            // Client-side circuit pump: a real, blocking `CircuitBuilder`
            // on its own OS thread -- see `allium-cli`'s
            // `spawn_circuit_pump` for the pattern this mirrors exactly,
            // down to the 0.2s poll interval and (like that function) is
            // built *inside* the spawned thread's own closure, not moved
            // in from outside: `CircuitBuilder` borrows the crypto
            // implementations it is given (`OnionCrypto` composed with
            // boxed `dyn Fn` trait objects, per `crypto.rs`'s `SaltAead`),
            // which are not `Send`, so it can only ever exist on the
            // thread that will actually use it.
            let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
            let (out_tx, out_rx) = std::sync::mpsc::channel::<Vec<u8>>();
            let (incoming_tx, mut incoming_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
            let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
            let pump_guard_addr = guard_addr.clone();
            let pump_middle_addr = middle_addr.clone();
            let pump_exit_addr = exit_addr.clone();
            std::thread::spawn(move || {
                let mut builder = match crate::circuit::CircuitBuilder::new(
                    &client_sock,
                    crate::onion::DEFAULT_CIPHER.to_string(),
                    5.0,
                    None,
                    true, // trust_first_use: this test has no PKI to pin against.
                    false,
                    crate::circuit::DEFAULT_RETRIES,
                    crate::circuit::DEFAULT_SEND_JITTER,
                    None,
                ) {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e.to_string()));
                        return;
                    }
                };
                let build_result = (|| -> Result<(), String> {
                    builder.add_hop("guard", pump_guard_addr, None, None, None).map_err(|e| e.to_string())?;
                    builder.extend("middle", pump_middle_addr, None, None, None).map_err(|e| e.to_string())?;
                    builder.extend("exit", pump_exit_addr.clone(), None, None, None).map_err(|e| e.to_string())?;
                    Ok(())
                })();
                let ok = build_result.is_ok();
                let _ = ready_tx.send(build_result);
                if !ok {
                    return;
                }
                loop {
                    while let Ok(payload) = out_rx.try_recv() {
                        let _ = builder.send(&payload, &pump_exit_addr);
                    }
                    match builder.receive(Some(0.2)) {
                        Ok(data) => {
                            if incoming_tx.send(data).is_err() {
                                break;
                            }
                        }
                        Err(_) => {}
                    }
                }
            });
            // A blocking `std::sync::mpsc::Receiver::recv()` here would
            // stall this whole single-threaded executor -- guard/middle/
            // exit's `serve_loop` tasks are cooperatively scheduled on
            // this SAME thread (see `LocalSet::block_on`), so nothing
            // would ever answer the pump thread's CREATE and this would
            // deadlock rather than time out. Poll instead, exactly like
            // the 2-hop `EXTEND` test's own client-thread result channel.
            loop {
                match ready_rx.try_recv() {
                    Ok(Ok(())) => break,
                    Ok(Err(e)) => return Err(e),
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        return Err("circuit pump thread exited before reporting readiness".to_string());
                    }
                }
            }

            let onion_tx = out_tx.clone();
            let onion: Onion = Rc::new(RefCell::new(move |data: &[u8]| {
                let _ = onion_tx.send(data.to_vec());
            }));
            let mut options = SocksServerOptions::new(onion);
            options.host = "127.0.0.1".to_string();
            options.port = 0;
            let server = Rc::new(RefCell::new(SocksServer::with_options(options)));
            let (_host, socks_port) = SocksServer::start(&server).await.map_err(|e| e.to_string())?;

            // Drain the circuit's return-path bytes into the server --
            // exactly `cmd_client`'s dispatch loop.
            let drain_server = server.clone();
            tokio::task::spawn_local(async move {
                while let Some(data) = incoming_rx.recv().await {
                    if data.starts_with(MAGIC) {
                        SocksServer::deliver_reply(&drain_server, &data);
                    } else if let Ok(frag) = crate::fragment::decode_fragment(&data) {
                        drain_server.borrow_mut().deliver_data(frag.stream_id, &data, None);
                    }
                }
            });

            // "curl-equivalent": a raw, blocking SOCKS5 client on its own
            // OS thread, driving a real CONNECT through the whole stack
            // above.
            let (client_result_tx, client_result_rx) = std::sync::mpsc::channel::<Result<Vec<u8>, String>>();
            std::thread::spawn(move || {
                let outcome = (|| -> Result<Vec<u8>, String> {
                    let mut sock = std::net::TcpStream::connect(("127.0.0.1", socks_port)).map_err(|e| e.to_string())?;
                    sock.set_read_timeout(Some(std::time::Duration::from_secs(10))).map_err(|e| e.to_string())?;

                    sock.write_all(&[SOCKS_VERSION, 0x01, 0x00]).map_err(|e| e.to_string())?;
                    let mut greeting_reply = [0u8; 2];
                    sock.read_exact(&mut greeting_reply).map_err(|e| e.to_string())?;
                    if greeting_reply != [SOCKS_VERSION, 0x00] {
                        return Err(format!("unexpected greeting reply: {greeting_reply:?}"));
                    }

                    let origin_ip = match origin_addr.ip() {
                        std::net::IpAddr::V4(v4) => v4.octets(),
                        other => return Err(format!("origin address is not IPv4: {other:?}")),
                    };
                    let mut request = vec![SOCKS_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4];
                    request.extend_from_slice(&origin_ip);
                    request.extend_from_slice(&origin_addr.port().to_be_bytes());
                    sock.write_all(&request).map_err(|e| e.to_string())?;

                    // Fixed 10-byte reply: `do_connect_relay` always
                    // replies with an ATYP_IPV4 "0.0.0.0:0" address,
                    // regardless of what the request used.
                    let mut connect_reply = [0u8; 10];
                    sock.read_exact(&mut connect_reply).map_err(|e| e.to_string())?;
                    if connect_reply[1] != SUCCESS {
                        return Err(format!("CONNECT failed with status {}", connect_reply[1]));
                    }

                    // Stand-in for a TLS ClientHello: this is the byte range
                    // that never made it to the origin before this round's
                    // fixes.
                    let client_hello_stand_in = b"CLIENT-HELLO-STAND-IN";
                    sock.write_all(client_hello_stand_in).map_err(|e| e.to_string())?;

                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).map_err(|e| e.to_string())?;
                    Ok(buf[..n].to_vec())
                })();
                let _ = client_result_tx.send(outcome);
            });

            loop {
                match client_result_rx.try_recv() {
                    Ok(outcome) => return outcome,
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        return Err("curl-equivalent client thread exited without a result".to_string());
                    }
                }
            }
        });

        let received = result.expect("real 3-hop SOCKS5 CONNECT stream over loopback UDP/TCP should succeed");
        assert_eq!(received, b"ECHO:CLIENT-HELLO-STAND-IN".to_vec(), "the origin's reply did not make it back through the circuit unchanged");
        origin_thread.join().expect("origin server thread panicked");
    }

    // -- StreamReassemblers bounds (hostile client inventing stream ids) --

    fn ck(n: u32) -> CircuitKeyTuple {
        (format!("10.0.{}.1", n / 256), (n % 60000) as u16 + 1, n)
    }

    #[test]
    fn test_stream_reassemblers_deliver_in_order_and_reorder() {
        let mut t = StreamReassemblers::default();
        let k = ck(1);
        // out of order first: buffered, nothing delivered yet
        assert!(t.push(&k, &Fragment::new(9, 5, true, b"world".to_vec())).is_empty());
        assert_eq!(t.buffered_total, 5);
        // the gap fills: both chunks come out in order
        assert_eq!(t.push(&k, &Fragment::new(9, 0, false, b"hello".to_vec())), b"helloworld".to_vec());
        assert_eq!(t.buffered_total, 0);
    }

    /// Regression test for bug report H2: a circuit that finishes one
    /// stream after another must never run out of slots, even well past
    /// `MAX_STREAM_REASSEMBLERS_PER_CIRCUIT` streams, because a finished
    /// stream's slot is freed immediately rather than only when the
    /// *global* table fills up.
    #[test]
    fn test_stream_reassemblers_finished_stream_frees_its_slot_immediately() {
        let mut t = StreamReassemblers::default();
        let k = ck(1);
        for id in 1..=(MAX_STREAM_REASSEMBLERS_PER_CIRCUIT as u32 * 10) {
            let out = t.push(&k, &Fragment::new(id, 0, true, b"x".to_vec()));
            assert_eq!(out, b"x".to_vec(), "stream {id} should be delivered, not dropped for lack of a slot");
            // Each single-fragment, in-order, FIN'd stream completes and
            // frees its slot the moment it is pushed.
            assert!(!t.map.contains_key(&(k.clone(), id)));
        }
        assert_eq!(t.per_circuit.get(&k), None);
        assert_eq!(t.buffered_total, 0);
    }

    #[test]
    fn test_stream_reassemblers_cap_per_circuit() {
        let mut t = StreamReassemblers::default();
        let k = ck(1);
        // many invented stream ids on one circuit, offsets that never start at 0
        for id in 1..=1000u32 {
            t.push(&k, &Fragment::new(id, 1, false, vec![0u8; 1000]));
        }
        assert_eq!(t.per_circuit.get(&k).copied(), Some(MAX_STREAM_REASSEMBLERS_PER_CIRCUIT));
        assert!(t.buffered_total <= MAX_STREAM_REASSEMBLERS_PER_CIRCUIT * 1000);
        // a different circuit is unaffected by the first one's flood
        assert!(!t.push(&ck(2), &Fragment::new(1, 0, false, b"ok".to_vec())).is_empty());
    }

    #[test]
    fn test_stream_reassemblers_cap_bytes_per_stream_but_not_in_order_data() {
        let mut t = StreamReassemblers::default();
        let k = ck(1);
        let chunk = vec![1u8; 1000];
        // out-of-order chunks (a hole at offset 0) fill up to the per-stream cap...
        for i in 0..5000u32 {
            t.push(&k, &Fragment::new(3, 1 + i * 1000, false, chunk.clone()));
        }
        let held = t.map.get(&(k.clone(), 3)).unwrap().buffered;
        assert!(held <= MAX_STREAM_REASSEMBLER_BYTES, "held {held}");
        assert_eq!(t.buffered_total, held);
        // ...but an in-order stream on the same circuit is never blocked
        let mut off = 0u32;
        for _ in 0..50 {
            let out = t.push(&k, &Fragment::new(4, off, false, chunk.clone()));
            assert_eq!(out.len(), 1000);
            off += 1000;
        }
    }

    #[test]
    fn test_stream_reassemblers_total_entries_bounded_across_circuits() {
        let mut t = StreamReassemblers::default();
        // many circuits, each below its own cap, together past the global cap
        'outer: for c in 0..200u32 {
            for id in 1..=MAX_STREAM_REASSEMBLERS_PER_CIRCUIT as u32 {
                t.push(&ck(c), &Fragment::new(id, 1, false, vec![0u8; 10]));
                if t.map.len() > MAX_PENDING_STREAM_REASSEMBLERS {
                    break 'outer;
                }
            }
        }
        assert!(t.map.len() <= MAX_PENDING_STREAM_REASSEMBLERS);
        // a live reassembler is not evicted to make room: the first entry is still there
        assert!(t.map.contains_key(&(ck(0), 1)));
    }

    #[test]
    fn test_stream_reassemblers_forget_circuit_frees_everything() {
        let mut t = StreamReassemblers::default();
        let k = ck(7);
        for id in 1..=20u32 {
            t.push(&k, &Fragment::new(id, 1, false, vec![0u8; 100]));
        }
        t.push(&ck(8), &Fragment::new(1, 1, false, vec![0u8; 100]));
        assert_eq!(t.buffered_total, 2100);
        t.forget_circuit(&k);
        assert_eq!(t.map.len(), 1);
        assert!(t.per_circuit.get(&k).is_none());
        assert_eq!(t.buffered_total, 100);
    }

    #[test]
    fn test_stream_reassemblers_purge_finished_under_pressure() {
        let mut t = StreamReassemblers::default();
        // fill the table with finished single-fragment streams spread over circuits
        let mut n = 0u32;
        'fill: for c in 0..200u32 {
            for id in 1..=MAX_STREAM_REASSEMBLERS_PER_CIRCUIT as u32 {
                t.push(&ck(c), &Fragment::new(id, 0, true, b"x".to_vec()));
                n += 1;
                if t.map.len() == MAX_PENDING_STREAM_REASSEMBLERS {
                    break 'fill;
                }
            }
        }
        assert!(n >= MAX_PENDING_STREAM_REASSEMBLERS as u32);
        // table is full of finished entries: a new stream on a fresh circuit
        // purges them and is accepted
        assert_eq!(t.push(&ck(9999), &Fragment::new(1, 0, true, b"new".to_vec())), b"new".to_vec());
        assert!(t.map.len() < MAX_PENDING_STREAM_REASSEMBLERS);
    }

    // -- HsRelayState::hs_push bounds (hostile peer streaming stream-0 junk) --

    fn hs_frag(offset: u32, fin: bool, len: usize) -> Vec<u8> {
        encode_fragment(&Fragment::new(0, offset, fin, vec![9u8; len]))
    }

    #[test]
    fn test_hs_push_largest_legitimate_control_message_still_completes() {
        let mut s = HsRelayState::default();
        let k = ck(1);
        let msg = crate::hswire::encode_introduce1(&[1u8; 32], &[2u8; 32], &vec![3u8; 4096]).unwrap();
        assert!(msg.len() <= crate::hswire::MAX_CONTROL_MESSAGE_LEN);
        assert!(crate::hswire::MAX_CONTROL_MESSAGE_LEN <= 16 * 1024, "the control-message cap must stay small");
        let mut done = None;
        for wire in crate::hswire::fragment_message_default(&msg) {
            if let Some(m) = s.hs_push(&k, &wire) {
                done = Some(m);
            }
        }
        assert_eq!(done.as_deref(), Some(msg.as_slice()));
        assert_eq!(s.reassembly_bytes, 0);
    }

    #[test]
    fn test_hs_push_non_joined_circuit_is_held_to_control_message_size() {
        let mut s = HsRelayState::default();
        let k = ck(1);
        // in-order, never FIN: stops accumulating at the control-message cap
        let mut off = 0u32;
        for _ in 0..200 {
            s.hs_push(&k, &hs_frag(off, false, 1000));
            off += 1000;
        }
        let held = s.reassemblers.get(&k).map_or(0, |r| r.buffered_bytes());
        assert!(held <= 8 * 1024, "held {held}"); // the intended policy, as a literal, not the constant under test
        assert_eq!(s.reassembly_bytes, held);
    }

    #[test]
    fn test_hs_push_out_of_order_bytes_count_against_the_cap() {
        let mut s = HsRelayState::default();
        let k = ck(1);
        // a hole at offset 0 keeps everything out of order
        for i in 0..200u32 {
            s.hs_push(&k, &hs_frag(1 + i * 1000, false, 1000));
        }
        let held = s.reassemblers.get(&k).map_or(0, |r| r.buffered_bytes());
        assert!(held <= 8 * 1024, "held {held}"); // the intended policy, as a literal, not the constant under test
        assert_eq!(s.reassembly_bytes, held);
    }

    #[test]
    fn test_hs_push_joined_circuit_may_carry_large_rendezvous_data() {
        let mut s = HsRelayState::default();
        let (a, b) = (ck(1), ck(2));
        s.partner.insert(a.clone(), b.clone());
        s.partner.insert(b, a.clone());
        let payload = vec![5u8; 200 * 1024];
        let msg = crate::hswire::encode_rendezvous_data(&payload).unwrap();
        let mut done = None;
        for wire in crate::hswire::fragment_message_default(&msg) {
            if let Some(m) = s.hs_push(&a, &wire) {
                done = Some(m);
            }
        }
        assert_eq!(done.as_deref(), Some(msg.as_slice()));
        assert_eq!(s.reassembly_bytes, 0);
    }

    #[test]
    fn test_hs_push_entry_cap_evicts_the_biggest_holder_and_keeps_bytes_consistent() {
        let mut s = HsRelayState::default();
        // one circuit holds noticeably more than the rest
        s.hs_push(&ck(0), &hs_frag(1, false, 6000));
        for c in 1..MAX_PENDING_HS_REASSEMBLERS as u32 {
            s.hs_push(&ck(c), &hs_frag(1, false, 10));
        }
        assert_eq!(s.reassemblers.len(), MAX_PENDING_HS_REASSEMBLERS);
        // a new circuit arrives at the cap: the big holder goes, not a small peer
        s.hs_push(&ck(99_999), &hs_frag(1, false, 10));
        assert_eq!(s.reassemblers.len(), MAX_PENDING_HS_REASSEMBLERS);
        assert!(!s.reassemblers.contains_key(&ck(0)));
        assert!(s.reassemblers.contains_key(&ck(1)));
        let sum: usize = s.reassemblers.values().map(|r| r.buffered_bytes()).sum();
        assert_eq!(s.reassembly_bytes, sum);
    }

    #[test]
    fn test_hs_drop_reassembler_releases_bytes() {
        let mut s = HsRelayState::default();
        s.hs_push(&ck(1), &hs_frag(1, false, 500));
        s.hs_push(&ck(2), &hs_frag(1, false, 300));
        assert_eq!(s.reassembly_bytes, 800);
        s.hs_drop_reassembler(&ck(1));
        assert_eq!(s.reassembly_bytes, 300);
        s.hs_drop_reassembler(&ck(1)); // idempotent
        assert_eq!(s.reassembly_bytes, 300);
    }

    // -- intro registrations and pending rendezvous: bounded, no arbitrary eviction --

    fn akey(n: u32) -> Vec<u8> {
        n.to_be_bytes().to_vec()
    }

    #[test]
    fn test_one_circuit_may_hold_only_a_few_intro_registrations() {
        let mut s = HsRelayState::default();
        let a = ck(1);
        for n in 0..4u32 {
            assert!(s.register_intro(akey(n), &a).is_ok());
        }
        assert_eq!(s.register_intro(akey(99), &a), Err("too many registrations on this circuit"));
        assert!(!s.intro.contains_key(&akey(99)));
        // another circuit is unaffected
        assert!(s.register_intro(akey(100), &ck(2)).is_ok());
    }

    #[test]
    fn test_reregistering_is_idempotent_and_a_reconnecting_service_moves_its_key() {
        let mut s = HsRelayState::default();
        let (old, new) = (ck(1), ck(2));
        s.register_intro(akey(7), &old).unwrap();
        s.register_intro(akey(7), &old).unwrap();
        assert_eq!(s.intro.len(), 1);
        // the same service comes back on a new circuit before the old one is forgotten
        s.register_intro(akey(7), &new).unwrap();
        assert_eq!(s.intro.get(&akey(7)), Some(&new));
        assert_eq!(s.intro.len(), 1);
    }

    #[test]
    fn test_full_intro_table_evicts_from_a_hoarder_never_from_an_honest_service() {
        let mut s = HsRelayState::default();
        let hoarder = ck(0);
        for n in 0..4u32 {
            s.register_intro(akey(n), &hoarder).unwrap();
            s.intro_rate.insert(akey(n), IntroRateLimiter::new(0.0, 1.0, 1.0));
        }
        // the rest of the table is honest services, one registration per circuit
        for n in 4..MAX_HS_INTRO_REGISTRATIONS as u32 {
            s.register_intro(akey(n), &ck(n)).unwrap();
        }
        assert_eq!(s.intro.len(), MAX_HS_INTRO_REGISTRATIONS);
        // a new honest service arrives at a full table: it gets in...
        let newcomer = akey(1_000_000);
        s.register_intro(newcomer.clone(), &ck(1_000_000)).unwrap();
        assert!(s.intro.contains_key(&newcomer));
        assert_eq!(s.intro.len(), MAX_HS_INTRO_REGISTRATIONS);
        // ...and what was evicted came from the hoarder, with its limiter state
        assert_eq!((0..4u32).filter(|n| s.intro.contains_key(&akey(*n))).count(), 3);
        assert_eq!((0..4u32).filter(|n| s.intro_rate.contains_key(&akey(*n))).count(), 3);
        for n in 4..MAX_HS_INTRO_REGISTRATIONS as u32 {
            assert!(s.intro.contains_key(&akey(n)), "honest service {n} was evicted");
        }
    }

    #[test]
    fn test_full_intro_table_of_equal_holders_refuses_the_newcomer_and_evicts_nobody() {
        let mut s = HsRelayState::default();
        for n in 0..MAX_HS_INTRO_REGISTRATIONS as u32 {
            s.register_intro(akey(n), &ck(n)).unwrap();
        }
        assert_eq!(s.register_intro(akey(9_999_999), &ck(9_999_999)), Err("introduction table full"));
        assert_eq!(s.intro.len(), MAX_HS_INTRO_REGISTRATIONS);
        assert!((0..MAX_HS_INTRO_REGISTRATIONS as u32).all(|n| s.intro.contains_key(&akey(n))));
    }

    #[test]
    fn test_drop_intro_releases_every_limiter_tied_to_the_key() {
        let mut s = HsRelayState::default();
        s.register_intro(akey(1), &ck(1)).unwrap();
        s.intro_rate.insert(akey(1), IntroRateLimiter::new(0.0, 1.0, 1.0));
        s.intro_rate_per_sender.insert((akey(1), ck(9)), IntroRateLimiter::new(0.0, 1.0, 1.0));
        s.intro_rate_per_sender.insert((akey(2), ck(9)), IntroRateLimiter::new(0.0, 1.0, 1.0));
        s.drop_intro(&akey(1));
        assert!(s.intro.is_empty() && s.intro_rate.is_empty());
        assert_eq!(s.intro_rate_per_sender.len(), 1, "only the dropped key's sender limiters go");
    }

    #[test]
    fn test_pending_rendezvous_pairs_a_fresh_join_and_ignores_an_abandoned_one() {
        let mut s = HsRelayState::default();
        s.register_pending_rendezvous(akey(1), &ck(1), 1000.0).unwrap();
        assert_eq!(s.take_pending_rendezvous(&akey(1), 1010.0), Some(ck(1)));
        assert_eq!(s.take_pending_rendezvous(&akey(1), 1011.0), None, "taken once");
        // a join nobody ever answered is stale after the max age and must not pair with a live one
        s.register_pending_rendezvous(akey(2), &ck(2), 1000.0).unwrap();
        assert_eq!(s.take_pending_rendezvous(&akey(2), 1000.0 + HS_PENDING_RENDEZVOUS_MAX_AGE_SECS + 1.0), None);
        assert!(s.pending_rendezvous.is_empty());
    }

    #[test]
    fn test_pending_rendezvous_is_capped_per_circuit() {
        let mut s = HsRelayState::default();
        for n in 0..2u32 {
            s.register_pending_rendezvous(akey(n), &ck(1), 1000.0).unwrap();
        }
        assert_eq!(s.register_pending_rendezvous(akey(9), &ck(1), 1000.0), Err("too many pending joins on this circuit"));
        assert!(s.register_pending_rendezvous(akey(10), &ck(2), 1000.0).is_ok());
    }

    #[test]
    fn test_full_pending_table_never_evicts_a_fresh_wait_but_recovers_from_stale_ones() {
        let mut s = HsRelayState::default();
        // fill with fresh joins, one per circuit
        for n in 0..MAX_HS_PENDING_RENDEZVOUS as u32 {
            s.register_pending_rendezvous(akey(n), &ck(n), 1000.0).unwrap();
        }
        // everything is fresh: a newcomer is refused and nobody's wait is dropped
        assert_eq!(s.register_pending_rendezvous(akey(5_000_000), &ck(5_000_000), 1010.0), Err("rendezvous table full"));
        assert_eq!(s.pending_rendezvous.len(), MAX_HS_PENDING_RENDEZVOUS);
        assert!(s.pending_rendezvous.contains_key(&akey(0)));
        // later, the old entries are stale: they are purged and the newcomer gets in
        let later = 1000.0 + HS_PENDING_RENDEZVOUS_MAX_AGE_SECS + 1.0;
        assert!(s.register_pending_rendezvous(akey(5_000_000), &ck(5_000_000), later).is_ok());
        assert_eq!(s.pending_rendezvous.len(), 1);
    }
}
