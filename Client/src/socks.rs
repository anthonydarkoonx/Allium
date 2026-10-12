//! End-to-end stream and address-resolution framing for the Allium exit.
//!
//! This module owns the *framing* only -- the bytes a client puts inside an
//! onion cell to ask the exit to open a stream or resolve a name, and the
//! bytes the exit sends back. It does not own sockets: a SOCKS5 server
//! (see [`crate::socksproxy`]) and the exit's own TCP egress sit on top of
//! this, exactly as [`crate::onion`] sits below [`crate::circuit`].
//!
//! Two request kinds share one cell, and one reply kind answers both.
//!
//! * **CONNECT** -- open a TCP stream to `host:port` (or `ip:port`).
//! * **RESOLVE** -- resolve a domain name to an address *at the exit*, so
//!   the client's local DNS resolver is never consulted and no DNS query
//!   ever leaks from the client's own network.
//!
//! A request is a small big-endian struct; the reply echoes the request id
//! and carries a status plus either an address (RESOLVE) or a stream id
//! (CONNECT).
//!
//! These primitives are deliberately independent of SOCKS5 so that a
//! future non-SOCKS entrypoint can reuse them; the SOCKS proxy translates
//! SOCKS5 commands into these.
//!
//! # Datagram (SOCKS5 UDP ASSOCIATE) framing
//!
//! A UDP datagram is *not* a stream. It has no offset, no reassembly, and
//! no FIN: one client-sent packet must become exactly one exit-sent packet
//! (or none, if it is dropped), with its own boundary preserved end to
//! end. Reusing [`StreamRequest`]/[`crate::fragment::Fragment`] for this
//! would either force a datagram through
//! [`crate::fragment::Fragmenter`]/[`crate::fragment::Reassembler`]
//! (silently merging or splitting datagram boundaries the way TCP streams
//! may, which UDP must never do) or overload a stream id to mean two
//! incompatible things. So datagrams get their own magic, their own
//! message types, and their own codec, carried as a single, whole,
//! unfragmented onion-cell payload -- v1 has no SOCKS5 UDP fragmentation
//! support (FRAG must be 0; see [`crate::socksproxy`]).
//!
//! Wire format (big-endian), request direction (client -> exit):
//!
//! ```text
//! +------+------+--------------+-----------+------+------------+-------------+---------+
//! | MAGIC| type | association  | dest addr | dest | bytes_sent | payload_len | payload |
//! | 4    | 1    | id (4)       | (4, IPv4) | port |     (4)    |     (2)     |variable |
//! |      |      |              |           | (2)  |            |             |         |
//! +------+------+--------------+-----------+------+------------+-------------+---------+
//! ```
//!
//! Wire format, reply direction (exit -> client):
//!
//! ```text
//! +------+------+--------------+-----------+------+-------------+---------+
//! | MAGIC| type | association  | src addr  | src  | payload_len | payload |
//! | 4    | 1    | id (4)       | (4, IPv4) | port |     (2)     |variable |
//! |      |      |              |           | (2)  |             |         |
//! +------+------+--------------+-----------+------+-------------+---------+
//! ```
//!
//! `bytes_sent` is carried *explicitly* in the request -- unlike
//! [`StreamRequest`], whose decoder invents [`DEFAULT_REQUEST_BYTES`] when
//! the field is absent from the wire. That default exists only because
//! the stream frame never had room budgeted for a real count; the
//! datagram frame does, so the amplification guard's baseline is always
//! the client's own reported volume, never a guessed floor.
//!
//! v1 scope: IPv4 only (the address field is a fixed 4 raw bytes, not the
//! length-prefixed [`pack_addr`] form used for streams -- a datagram has
//! no hostname to carry, only a literal destination), no SOCKS5 UDP
//! fragmentation, and a payload bounded well under one cell's user-data
//! budget (see [`MAX_DATAGRAM_PAYLOAD`]).

use std::net::Ipv4Addr;
use std::str::FromStr;

use crate::sizes::{user_data_budget, HOP_COUNT};

/// Unchanging prefix on every request/reply, so a cell carrying stream
/// framing can never be mistaken for raw user data even if a caller
/// forgets to set the layer kind.
pub const MAGIC: &[u8; 4] = b"ALSM";

/// Kind of an end-to-end stream request.
pub const CONNECT: u8 = 1;
pub const RESOLVE: u8 = 2;

/// Reply statuses. Deliberately small so a client can map them to SOCKS5
/// reply codes without ambiguity.
pub const SUCCESS: u8 = 0;
pub const GENERAL_FAILURE: u8 = 1;
pub const HOST_UNREACHABLE: u8 = 4;
pub const CONNECTION_REFUSED: u8 = 5;
pub const TTL_EXPIRED: u8 = 6;
pub const COMMAND_UNSUPPORTED: u8 = 7;
pub const ADDR_UNSUPPORTED: u8 = 8;

/// Byte width of the length field for a hostname or address.
pub const MAX_ADDR_LEN: usize = 255;

/// Every error this module can raise: a bad magic, an unknown kind, an
/// out-of-range field, or a truncated/malformed frame. The Python
/// original raises a plain `ValueError` for all of these; this crate
/// gives that one error type a name, matching the convention established
/// elsewhere in this port for a module with no exception hierarchy of its
/// own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramingError(pub String);

impl std::fmt::Display for FramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for FramingError {}

/// Closed set of stream-request kinds.
pub struct RequestKind;
impl RequestKind {
    pub const CONNECT: u8 = CONNECT;
    pub const RESOLVE: u8 = RESOLVE;

    pub fn name(value: u8) -> String {
        match value {
            CONNECT => "CONNECT".to_string(),
            RESOLVE => "RESOLVE".to_string(),
            other => format!("UNKNOWN({other})"),
        }
    }
}

/// Closed set of reply statuses.
pub struct Status;
impl Status {
    pub const SUCCESS: u8 = SUCCESS;
    pub const GENERAL_FAILURE: u8 = GENERAL_FAILURE;
    pub const HOST_UNREACHABLE: u8 = HOST_UNREACHABLE;
    pub const CONNECTION_REFUSED: u8 = CONNECTION_REFUSED;
    pub const TTL_EXPIRED: u8 = TTL_EXPIRED;
    pub const COMMAND_UNSUPPORTED: u8 = COMMAND_UNSUPPORTED;
    pub const ADDR_UNSUPPORTED: u8 = ADDR_UNSUPPORTED;

    pub fn name(value: u8) -> String {
        match value {
            SUCCESS => "SUCCESS".to_string(),
            GENERAL_FAILURE => "GENERAL_FAILURE".to_string(),
            HOST_UNREACHABLE => "HOST_UNREACHABLE".to_string(),
            CONNECTION_REFUSED => "CONNECTION_REFUSED".to_string(),
            TTL_EXPIRED => "TTL_EXPIRED".to_string(),
            COMMAND_UNSUPPORTED => "COMMAND_UNSUPPORTED".to_string(),
            ADDR_UNSUPPORTED => "ADDR_UNSUPPORTED".to_string(),
            other => format!("UNKNOWN({other})"),
        }
    }
}

/// A parsed end-to-end stream request.
///
/// `bytes_sent`: how many payload bytes the client is likely to send for
/// this stream. Used by the exit's amplification guard as the baseline
/// the response is measured against. Defaults to a conservative small
/// value ([`DEFAULT_REQUEST_BYTES`]) so a caller that does not track it
/// still gets protection rather than an unenforceable zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRequest {
    /// [`CONNECT`] or [`RESOLVE`].
    pub kind: u8,
    /// Caller-chosen id echoed in the reply, so a caller with many
    /// outstanding requests can match them.
    pub request_id: u32,
    /// The destination hostname, or a textual IPv4/IPv6 address.
    pub host: String,
    /// The destination port. Meaningless for RESOLVE, kept 0.
    pub port: u16,
    pub bytes_sent: u32,
}

impl StreamRequest {
    /// [`StreamRequest`] with `bytes_sent` at its Python-default of `0`.
    pub fn new(kind: u8, request_id: u32, host: impl Into<String>, port: u16) -> Self {
        StreamRequest { kind, request_id, host: host.into(), port, bytes_sent: 0 }
    }
}

/// A parsed reply to a stream request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamReply {
    /// The id echoed from the request.
    pub request_id: u32,
    /// A [`Status`] value.
    pub status: u8,
    /// For a successful CONNECT, the id the exit assigned to the stream
    /// (used to route RELAY cells). `0` otherwise.
    pub stream_id: u32,
    /// For a successful RESOLVE, the `(ip, port)` answered. `None`
    /// otherwise.
    pub address: Option<(String, u16)>,
}

impl StreamReply {
    /// [`StreamReply`] with `stream_id: 0, address: None` (Python's
    /// defaults).
    pub fn new(request_id: u32, status: u8) -> Self {
        StreamReply { request_id, status, stream_id: 0, address: None }
    }
}

/// Pack `host:port` into a length-prefixed 6+byte form.
///
/// The address is carried as a length-prefixed string (so a hostname, an
/// IPv4 literal, or a bracketed IPv6 literal all fit), followed by a
/// 2-byte port.
///
/// # Errors
/// Returns [`FramingError`] if `host` is longer than [`MAX_ADDR_LEN`]
/// bytes once UTF-8 encoded.
pub fn pack_addr(host: &str, port: u16) -> Result<Vec<u8>, FramingError> {
    let raw = host.as_bytes();
    if raw.len() > MAX_ADDR_LEN {
        return Err(FramingError(format!("host is {} bytes, max is {MAX_ADDR_LEN}", raw.len())));
    }
    let mut out = Vec::with_capacity(1 + raw.len() + 2);
    out.push(raw.len() as u8);
    out.extend_from_slice(raw);
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

/// Unpack a [`pack_addr`] blob, returning `((host, port), consumed)`.
///
/// # Errors
/// Returns [`FramingError`] if `data` is empty, truncated, or the host
/// bytes are not valid UTF-8.
pub fn unpack_addr(data: &[u8]) -> Result<((String, u16), usize), FramingError> {
    if data.is_empty() {
        return Err(FramingError("empty address blob".to_string()));
    }
    let host_len = data[0] as usize;
    if data.len() < 1 + host_len + 2 {
        return Err(FramingError("truncated address blob".to_string()));
    }
    let host = String::from_utf8(data[1..1 + host_len].to_vec()).map_err(|e| FramingError(format!("invalid utf-8 in address: {e}")))?;
    let port = u16::from_be_bytes([data[1 + host_len], data[1 + host_len + 1]]);
    Ok(((host, port), 1 + host_len + 2))
}

/// Serialize a [`StreamRequest`] into cell-payload bytes.
///
/// # Errors
/// Returns [`FramingError`] if the host is too long (see [`pack_addr`]).
pub fn encode_request(req: &StreamRequest) -> Result<Vec<u8>, FramingError> {
    let addr = pack_addr(&req.host, req.port)?;
    let mut out = Vec::with_capacity(4 + 6 + addr.len());
    out.extend_from_slice(MAGIC);
    out.push(addr.len() as u8);
    out.push(req.kind);
    out.extend_from_slice(&req.request_id.to_be_bytes());
    out.extend_from_slice(&addr);
    Ok(out)
}

/// Default request-volume baseline assumed when a request frame does not
/// carry one. Non-zero on purpose: an unenforceable zero would disable
/// the exit's amplification guard, whereas a conservative floor keeps it
/// active for callers that do not track their own byte counts.
pub const DEFAULT_REQUEST_BYTES: u32 = 64;

/// Parse bytes produced by [`encode_request`].
///
/// The frame does not carry a byte-count baseline, so `bytes_sent` is set
/// to [`DEFAULT_REQUEST_BYTES`]: a conservative floor that keeps the
/// exit's amplification guard enforceable. A caller that knows its own
/// volume should override the field after decoding.
///
/// # Errors
/// Returns [`FramingError`] on a bad magic, an unknown kind, or a
/// malformed frame.
pub fn decode_request(data: &[u8]) -> Result<StreamRequest, FramingError> {
    if !data.starts_with(MAGIC) {
        return Err(FramingError("bad stream magic".to_string()));
    }
    if data.len() < 4 + 6 {
        return Err(FramingError("stream frame too short".to_string()));
    }
    let addr_len = data[4] as usize;
    let kind = data[5];
    let request_id = u32::from_be_bytes([data[6], data[7], data[8], data[9]]);
    if kind != CONNECT && kind != RESOLVE {
        return Err(FramingError(format!("unknown request kind {kind}")));
    }
    let end = (10 + addr_len).min(data.len());
    let addr_blob = &data[10..end];
    let ((host, port), consumed) = unpack_addr(addr_blob)?;
    if consumed != addr_len {
        return Err(FramingError("address length mismatch".to_string()));
    }
    Ok(StreamRequest { kind, request_id, host, port, bytes_sent: DEFAULT_REQUEST_BYTES })
}

/// Serialize a [`StreamReply`] into cell-payload bytes.
///
/// # Errors
/// Returns [`FramingError`] if `reply.address` is set but its host is too
/// long (see [`pack_addr`]).
pub fn encode_reply(reply: &StreamReply) -> Result<Vec<u8>, FramingError> {
    let body = match &reply.address {
        Some((host, port)) => {
            let addr = pack_addr(host, *port)?;
            let mut b = Vec::with_capacity(1 + addr.len());
            b.push(addr.len() as u8);
            b.extend_from_slice(&addr);
            b
        }
        None => vec![0u8],
    };
    let mut out = Vec::with_capacity(4 + 9 + body.len());
    out.extend_from_slice(MAGIC);
    out.push(reply.status);
    out.extend_from_slice(&reply.request_id.to_be_bytes());
    out.extend_from_slice(&reply.stream_id.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Parse bytes produced by [`encode_reply`].
///
/// # Errors
/// Returns [`FramingError`] on a bad magic or a malformed frame.
pub fn decode_reply(data: &[u8]) -> Result<StreamReply, FramingError> {
    if !data.starts_with(MAGIC) {
        return Err(FramingError("bad stream magic".to_string()));
    }
    // 4 (magic) + 9 (status/request_id/stream_id) + 1 (the addr_len byte
    // read right below, unconditionally -- even a reply with no address
    // at all still carries it, encoded as 0x00; see `encode_reply`'s
    // `body`).
    if data.len() < 4 + 9 + 1 {
        return Err(FramingError("stream reply too short".to_string()));
    }
    let status = data[4];
    let request_id = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
    let stream_id = u32::from_be_bytes([data[9], data[10], data[11], data[12]]);
    let addr_len = data[13] as usize;
    let address = if addr_len != 0 {
        let ((host, port), consumed) = unpack_addr(&data[14..])?;
        if consumed != addr_len {
            return Err(FramingError("reply address length mismatch".to_string()));
        }
        Some((host, port))
    } else {
        None
    };
    Ok(StreamReply { request_id, status, stream_id, address })
}

// ---------------------------------------------------------------------------
// Datagram (SOCKS5 UDP ASSOCIATE) framing
// ---------------------------------------------------------------------------

/// Unchanging prefix on every datagram request/reply. Distinct from
/// [`MAGIC`] (`b"ALSM"`, the stream framing) so a dispatcher can always
/// tell a datagram frame from a stream frame -- or from a bare
/// stream-data fragment, which carries no magic at all -- before decoding
/// anything.
pub const DATAGRAM_MAGIC: &[u8; 4] = b"ALDG";

/// Datagram message types.
pub const DATAGRAM_REQUEST: u8 = 1;
pub const DATAGRAM_REPLY: u8 = 2;

/// Fixed header size (magic included, payload excluded), request
/// direction: `type(1) + association_id(4) + addr(4) + port(2) +
/// bytes_sent(4) + payload_len(2)`, plus the 4-byte magic.
pub const DATAGRAM_REQUEST_HEADER_SIZE: usize = 4 + (1 + 4 + 4 + 2 + 4 + 2);

/// Fixed header size (magic included, payload excluded), reply
/// direction: `type(1) + association_id(4) + addr(4) + port(2) +
/// payload_len(2)`, plus the 4-byte magic. Smaller than the request
/// header (no `bytes_sent`).
pub const DATAGRAM_REPLY_HEADER_SIZE: usize = 4 + (1 + 4 + 4 + 2 + 2);

/// The one-cell user-data budget a datagram frame must fit inside: v1 has
/// no SOCKS5 UDP fragmentation, so a datagram that does not fit in a
/// single onion cell cannot be carried at all (see
/// [`crate::sizes::user_data_budget`], which derives this from the real
/// 1192-byte cell, AEAD overhead, and per-hop header cost for the standard
/// 3-hop circuit -- not a guessed round number).
fn single_cell_budget() -> i64 {
    user_data_budget(HOP_COUNT, crate::cell::PAYLOAD_SIZE).expect("HOP_COUNT and PAYLOAD_SIZE are always valid")
}

/// Largest payload [`encode_datagram_request`] will accept: the
/// single-cell budget minus this direction's exact header size.
pub fn max_datagram_request_payload() -> i64 {
    single_cell_budget() - DATAGRAM_REQUEST_HEADER_SIZE as i64
}

/// Largest payload [`encode_datagram_reply`] will accept: the single-cell
/// budget minus this direction's exact header size. The reply header is
/// smaller (no `bytes_sent`), so this is a few bytes larger than the
/// request bound.
pub fn max_datagram_reply_payload() -> i64 {
    single_cell_budget() - DATAGRAM_REPLY_HEADER_SIZE as i64
}

/// The bound both directions actually promise a caller who wants one
/// number: a datagram of at most this many bytes is guaranteed to survive
/// an out-and-back round trip (request *and* reply) without ever needing
/// fragmentation. Equal to the smaller of the two direction-specific
/// bounds above (the request bound, since its header carries the extra
/// `bytes_sent` field).
pub fn max_datagram_payload() -> i64 {
    max_datagram_request_payload().min(max_datagram_reply_payload())
}

/// A parsed UDP datagram, client -> exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramRequest {
    /// The SOCKS5 UDP ASSOCIATE session this datagram belongs to. Chosen
    /// by the client-side proxy and stable for the lifetime of one UDP
    /// ASSOCIATE; this is the *only* thing that lets one circuit
    /// multiplex several concurrent UDP associations.
    pub association_id: u32,
    /// The destination IPv4 address, dotted-quad text.
    pub host: String,
    /// The destination UDP port.
    pub port: u16,
    /// The datagram body, at most [`max_datagram_request_payload`] bytes.
    pub payload: Vec<u8>,
    /// How many payload bytes this datagram carries, tracked explicitly
    /// (not defaulted) so the exit's amplification guard has a real
    /// baseline for this association.
    pub bytes_sent: u32,
}

/// A parsed UDP datagram, exit -> client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramReply {
    /// Echoes the request's association id, so the client-side proxy can
    /// route the reply to the right UDP ASSOCIATE session without any
    /// other state.
    pub association_id: u32,
    /// The source IPv4 address the reply actually arrived from (not
    /// necessarily the address the request was sent to -- a UDP peer may
    /// answer from a different address).
    pub host: String,
    /// The source UDP port.
    pub port: u16,
    /// The datagram body, at most [`max_datagram_reply_payload`] bytes.
    pub payload: Vec<u8>,
}

/// Pack a dotted-quad IPv4 literal into its 4 raw bytes.
///
/// # Errors
/// Returns [`FramingError`] if `host` is not a valid IPv4 literal
/// (including a hostname or an IPv6 literal -- v1 datagram framing is
/// IPv4 only).
pub fn pack_ipv4(host: &str) -> Result<[u8; 4], FramingError> {
    Ipv4Addr::from_str(host).map(|a| a.octets()).map_err(|_| FramingError(format!("not a valid IPv4 address: {host:?}")))
}

/// Unpack 4 raw bytes into a dotted-quad IPv4 literal.
///
/// # Errors
/// Returns [`FramingError`] if `data` is not exactly 4 bytes.
pub fn unpack_ipv4(data: &[u8]) -> Result<String, FramingError> {
    if data.len() != 4 {
        return Err(FramingError(format!("IPv4 address must be 4 bytes, got {}", data.len())));
    }
    Ok(Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string())
}

/// Whether `data` starts with the datagram magic.
///
/// Cheap enough to call before any other framing check -- a caller that
/// dispatches on shape should check this (or the equivalent inline
/// `starts_with`) *before* trying [`crate::fragment::decode_fragment`],
/// exactly as it already checks the stream [`MAGIC`] first: a datagram
/// frame must never be misparsed as a stream fragment or vice versa.
pub fn is_datagram_frame(data: &[u8]) -> bool {
    data.starts_with(DATAGRAM_MAGIC)
}

/// Serialize a [`DatagramRequest`] into cell-payload bytes.
///
/// # Errors
/// Returns [`FramingError`] on a non-IPv4 host, or a payload larger than
/// [`max_datagram_request_payload`].
pub fn encode_datagram_request(req: &DatagramRequest) -> Result<Vec<u8>, FramingError> {
    let max = max_datagram_request_payload();
    if req.payload.len() as i64 > max {
        return Err(FramingError(format!(
            "datagram payload is {} bytes, max is {max} (the single-cell budget minus this frame's header)",
            req.payload.len()
        )));
    }
    let addr = pack_ipv4(&req.host)?;
    let mut out = Vec::with_capacity(DATAGRAM_REQUEST_HEADER_SIZE + req.payload.len());
    out.extend_from_slice(DATAGRAM_MAGIC);
    out.push(DATAGRAM_REQUEST);
    out.extend_from_slice(&req.association_id.to_be_bytes());
    out.extend_from_slice(&addr);
    out.extend_from_slice(&req.port.to_be_bytes());
    out.extend_from_slice(&req.bytes_sent.to_be_bytes());
    out.extend_from_slice(&(req.payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&req.payload);
    Ok(out)
}

/// Parse bytes produced by [`encode_datagram_request`].
///
/// # Errors
/// Returns [`FramingError`] on a bad magic, wrong message type, or a
/// truncated frame.
pub fn decode_datagram_request(data: &[u8]) -> Result<DatagramRequest, FramingError> {
    if !data.starts_with(DATAGRAM_MAGIC) {
        return Err(FramingError("bad datagram magic".to_string()));
    }
    let header_size = DATAGRAM_REQUEST_HEADER_SIZE - DATAGRAM_MAGIC.len();
    if data.len() < DATAGRAM_MAGIC.len() + header_size {
        return Err(FramingError("datagram request frame too short".to_string()));
    }
    let mut o = DATAGRAM_MAGIC.len();
    let msg_type = data[o];
    o += 1;
    let association_id = u32::from_be_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
    o += 4;
    let addr = &data[o..o + 4];
    o += 4;
    let port = u16::from_be_bytes([data[o], data[o + 1]]);
    o += 2;
    let bytes_sent = u32::from_be_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
    o += 4;
    let payload_len = u16::from_be_bytes([data[o], data[o + 1]]) as usize;
    o += 2;
    if msg_type != DATAGRAM_REQUEST {
        return Err(FramingError(format!("not a datagram request (type {msg_type})")));
    }
    let payload = &data[o..(o + payload_len).min(data.len())];
    if payload.len() != payload_len {
        return Err(FramingError("datagram request payload truncated".to_string()));
    }
    Ok(DatagramRequest {
        association_id,
        host: unpack_ipv4(addr)?,
        port,
        payload: payload.to_vec(),
        bytes_sent,
    })
}

/// Serialize a [`DatagramReply`] into cell-payload bytes.
///
/// # Errors
/// Returns [`FramingError`] on a non-IPv4 host, or a payload larger than
/// [`max_datagram_reply_payload`].
pub fn encode_datagram_reply(reply: &DatagramReply) -> Result<Vec<u8>, FramingError> {
    let max = max_datagram_reply_payload();
    if reply.payload.len() as i64 > max {
        return Err(FramingError(format!(
            "datagram payload is {} bytes, max is {max} (the single-cell budget minus this frame's header)",
            reply.payload.len()
        )));
    }
    let addr = pack_ipv4(&reply.host)?;
    let mut out = Vec::with_capacity(DATAGRAM_REPLY_HEADER_SIZE + reply.payload.len());
    out.extend_from_slice(DATAGRAM_MAGIC);
    out.push(DATAGRAM_REPLY);
    out.extend_from_slice(&reply.association_id.to_be_bytes());
    out.extend_from_slice(&addr);
    out.extend_from_slice(&reply.port.to_be_bytes());
    out.extend_from_slice(&(reply.payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&reply.payload);
    Ok(out)
}

/// Parse bytes produced by [`encode_datagram_reply`].
///
/// # Errors
/// Returns [`FramingError`] on a bad magic, wrong message type, or a
/// truncated frame.
pub fn decode_datagram_reply(data: &[u8]) -> Result<DatagramReply, FramingError> {
    if !data.starts_with(DATAGRAM_MAGIC) {
        return Err(FramingError("bad datagram magic".to_string()));
    }
    let header_size = DATAGRAM_REPLY_HEADER_SIZE - DATAGRAM_MAGIC.len();
    if data.len() < DATAGRAM_MAGIC.len() + header_size {
        return Err(FramingError("datagram reply frame too short".to_string()));
    }
    let mut o = DATAGRAM_MAGIC.len();
    let msg_type = data[o];
    o += 1;
    let association_id = u32::from_be_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
    o += 4;
    let addr = &data[o..o + 4];
    o += 4;
    let port = u16::from_be_bytes([data[o], data[o + 1]]);
    o += 2;
    let payload_len = u16::from_be_bytes([data[o], data[o + 1]]) as usize;
    o += 2;
    if msg_type != DATAGRAM_REPLY {
        return Err(FramingError(format!("not a datagram reply (type {msg_type})")));
    }
    let payload = &data[o..(o + payload_len).min(data.len())];
    if payload.len() != payload_len {
        return Err(FramingError("datagram reply payload truncated".to_string()));
    }
    Ok(DatagramReply { association_id, host: unpack_ipv4(addr)?, port, payload: payload.to_vec() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_addr_round_trips() {
        let packed = pack_addr("example.com", 443).unwrap();
        let ((host, port), consumed) = unpack_addr(&packed).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(consumed, packed.len());
    }

    #[test]
    fn pack_addr_rejects_oversized_host() {
        let host = "a".repeat(MAX_ADDR_LEN + 1);
        assert!(pack_addr(&host, 80).is_err());
    }

    #[test]
    fn unpack_addr_rejects_empty_and_truncated() {
        assert!(unpack_addr(&[]).is_err());
        assert!(unpack_addr(&[5, b'h', b'i']).is_err()); // claims 5 bytes, has 2 + no port
    }

    #[test]
    fn request_round_trips_and_fills_default_bytes_sent() {
        let req = StreamRequest::new(CONNECT, 0xAABBCCDD, "example.com", 8080);
        let encoded = encode_request(&req).unwrap();
        let decoded = decode_request(&encoded).unwrap();
        assert_eq!(decoded.kind, CONNECT);
        assert_eq!(decoded.request_id, 0xAABBCCDD);
        assert_eq!(decoded.host, "example.com");
        assert_eq!(decoded.port, 8080);
        assert_eq!(decoded.bytes_sent, DEFAULT_REQUEST_BYTES);
    }

    #[test]
    fn decode_request_rejects_bad_magic_and_unknown_kind() {
        assert!(decode_request(b"XXXX\x00\x01\x00\x00\x00\x00").is_err());
        let mut bad_kind = Vec::new();
        bad_kind.extend_from_slice(MAGIC);
        bad_kind.extend_from_slice(&[0, 99, 0, 0, 0, 0]); // kind=99
        assert!(decode_request(&bad_kind).is_err());
    }

    #[test]
    fn reply_round_trips_with_and_without_address() {
        let reply = StreamReply { request_id: 7, status: SUCCESS, stream_id: 42, address: None };
        let encoded = encode_reply(&reply).unwrap();
        assert_eq!(decode_reply(&encoded).unwrap(), reply);

        let reply_with_addr = StreamReply { request_id: 7, status: SUCCESS, stream_id: 0, address: Some(("10.0.0.1".to_string(), 53)) };
        let encoded = encode_reply(&reply_with_addr).unwrap();
        assert_eq!(decode_reply(&encoded).unwrap(), reply_with_addr);
    }

    #[test]
    fn decode_reply_rejects_truncated_frame_instead_of_panicking() {
        // 4 (magic) + 9 (status/ids) + 0 -- exactly one byte short of the
        // addr_len byte this decoder always reads. A regression here
        // would be an index panic, not a clean error.
        let mut short = Vec::new();
        short.extend_from_slice(MAGIC);
        short.extend_from_slice(&[0u8; 9]);
        assert!(decode_reply(&short).is_err());
    }

    #[test]
    fn kind_and_status_names_cover_known_and_unknown_values() {
        assert_eq!(RequestKind::name(CONNECT), "CONNECT");
        assert_eq!(RequestKind::name(RESOLVE), "RESOLVE");
        assert_eq!(RequestKind::name(200), "UNKNOWN(200)");
        assert_eq!(Status::name(SUCCESS), "SUCCESS");
        assert_eq!(Status::name(ADDR_UNSUPPORTED), "ADDR_UNSUPPORTED");
        assert_eq!(Status::name(250), "UNKNOWN(250)");
    }

    #[test]
    fn ipv4_pack_unpack_round_trips_and_rejects_non_ipv4() {
        let packed = pack_ipv4("192.168.1.42").unwrap();
        assert_eq!(packed, [192, 168, 1, 42]);
        assert_eq!(unpack_ipv4(&packed).unwrap(), "192.168.1.42");
        assert!(pack_ipv4("not-an-ip").is_err());
        assert!(pack_ipv4("::1").is_err());
        assert!(unpack_ipv4(&[1, 2, 3]).is_err());
    }

    #[test]
    fn is_datagram_frame_distinguishes_from_stream_magic() {
        assert!(is_datagram_frame(DATAGRAM_MAGIC));
        assert!(!is_datagram_frame(MAGIC));
        assert!(!is_datagram_frame(b"anything else"));
    }

    #[test]
    fn datagram_request_round_trips() {
        let req = DatagramRequest {
            association_id: 0x11223344,
            host: "203.0.113.9".to_string(),
            port: 53,
            payload: b"dns query bytes".to_vec(),
            bytes_sent: 128,
        };
        let encoded = encode_datagram_request(&req).unwrap();
        assert_eq!(decode_datagram_request(&encoded).unwrap(), req);
    }

    #[test]
    fn datagram_reply_round_trips() {
        let reply = DatagramReply {
            association_id: 0x11223344,
            host: "203.0.113.9".to_string(),
            port: 53,
            payload: b"dns reply bytes".to_vec(),
        };
        let encoded = encode_datagram_reply(&reply).unwrap();
        assert_eq!(decode_datagram_reply(&encoded).unwrap(), reply);
    }

    #[test]
    fn datagram_request_rejects_oversized_payload() {
        let too_big = vec![0u8; (max_datagram_request_payload() + 1) as usize];
        let req = DatagramRequest { association_id: 1, host: "1.2.3.4".to_string(), port: 1, payload: too_big, bytes_sent: 0 };
        assert!(encode_datagram_request(&req).is_err());
    }

    #[test]
    fn datagram_request_rejects_non_ipv4_host() {
        let req = DatagramRequest { association_id: 1, host: "example.com".to_string(), port: 1, payload: Vec::new(), bytes_sent: 0 };
        assert!(encode_datagram_request(&req).is_err());
    }

    #[test]
    fn decode_datagram_request_rejects_wrong_type_and_bad_magic() {
        assert!(decode_datagram_request(b"XXXX").is_err());
        let reply = DatagramReply { association_id: 1, host: "1.2.3.4".to_string(), port: 1, payload: Vec::new() };
        let encoded = encode_datagram_reply(&reply).unwrap();
        // A reply frame handed to the request decoder: right magic, wrong
        // message type.
        assert!(decode_datagram_request(&encoded).is_err());
    }

    #[test]
    fn max_datagram_payload_is_the_smaller_of_the_two_directions() {
        assert_eq!(max_datagram_payload(), max_datagram_request_payload().min(max_datagram_reply_payload()));
        assert!(max_datagram_reply_payload() > max_datagram_request_payload());
    }

    mod python_cross_check {
        use super::*;

        // Ground truth obtained by running the real Python module:
        //
        //   python3 -c "
        //   from allium.socks import StreamRequest, encode_request
        //   req = StreamRequest(kind=1, request_id=0x01020304, host='example.com', port=8080)
        //   print(encode_request(req).hex())
        //   "
        #[test]
        fn encode_request_wire_bytes_match_python() {
            let req = StreamRequest::new(CONNECT, 0x0102_0304, "example.com", 8080);
            let encoded = encode_request(&req).unwrap();
            assert_eq!(
                hex::encode(&encoded),
                "414c534d0e01010203040b6578616d706c652e636f6d1f90"
            );
        }

        // python3 -c "
        // from allium.socks import StreamReply, encode_reply
        // r = StreamReply(request_id=0x0a0b0c0d, status=0, stream_id=99, address=None)
        // print(encode_reply(r).hex())
        // "
        #[test]
        fn encode_reply_wire_bytes_match_python() {
            let reply = StreamReply { request_id: 0x0a0b_0c0d, status: 0, stream_id: 99, address: None };
            let encoded = encode_reply(&reply).unwrap();
            assert_eq!(hex::encode(&encoded), "414c534d000a0b0c0d0000006300");
        }

        // python3 -c "
        // from allium.socks import DatagramRequest, encode_datagram_request
        // r = DatagramRequest(association_id=0x0a0b0c0d, host='203.0.113.9', port=53, payload=b'hi', bytes_sent=7)
        // print(encode_datagram_request(r).hex())
        // "
        #[test]
        fn encode_datagram_request_wire_bytes_match_python() {
            let req = DatagramRequest {
                association_id: 0x0a0b_0c0d,
                host: "203.0.113.9".to_string(),
                port: 53,
                payload: b"hi".to_vec(),
                bytes_sent: 7,
            };
            let encoded = encode_datagram_request(&req).unwrap();
            assert_eq!(hex::encode(&encoded), "414c4447010a0b0c0dcb00710900350000000700026869");
        }

        // python3 -c "
        // from allium.socks import MAX_DATAGRAM_REQUEST_PAYLOAD, MAX_DATAGRAM_REPLY_PAYLOAD, MAX_DATAGRAM_PAYLOAD
        // print(MAX_DATAGRAM_REQUEST_PAYLOAD, MAX_DATAGRAM_REPLY_PAYLOAD, MAX_DATAGRAM_PAYLOAD)
        // "  ->  254 258 254 (under the old PAYLOAD_SIZE = 504)
        //
        // Recomputed by hand for the current cell-size upgrade (PAYLOAD_SIZE
        // 504 -> 1184, see cell.rs and the matching note in createfrag.rs)
        // and the 0xA4 layer format (no inner header per intermediate
        // hop, see sizes.rs):
        // single_cell_budget() = user_data_budget(HOP_COUNT=3, PAYLOAD_SIZE=1184)
        //   = 1184 - 3*(ROUTE_HEADER_SIZE=29 + SEAL_OVERHEAD=28) = 1013
        // max_datagram_request_payload = 1013 - 21 = 992
        // max_datagram_reply_payload   = 1013 - 17 = 996
        // max_datagram_payload         = min(992, 996) = 992
        #[test]
        fn datagram_payload_budgets_match_python() {
            assert_eq!(DATAGRAM_REQUEST_HEADER_SIZE, 21);
            assert_eq!(DATAGRAM_REPLY_HEADER_SIZE, 17);
            assert_eq!(max_datagram_request_payload(), 992);
            assert_eq!(max_datagram_reply_payload(), 996);
            assert_eq!(max_datagram_payload(), 992);
        }

        mod hex {
            pub fn encode(data: &[u8]) -> String {
                data.iter().map(|b| format!("{b:02x}")).collect()
            }
        }
    }
}
