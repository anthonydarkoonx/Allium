//! End-to-end stream and address-resolution framing for the Allium exit.
//!
//! Full port of `socks.py`. Pure wire framing (no crypto, no sockets, no new
//! crate) -- the SOCKS5 server in `socksproxy.rs` and the exit's TCP egress
//! in `exit.rs` sit on top of this, exactly as Python's do.
//!
//! Two request kinds share one cell ([`CONNECT`]/[`RESOLVE`], framed as
//! [`StreamRequest`]/[`StreamReply`]), plus a wholly separate SOCKS5 UDP
//! ASSOCIATE datagram codec ([`DatagramRequest`]/[`DatagramReply`], its own
//! magic and message types -- see the "Datagram framing" section below for
//! why it must never share the stream codec's fragmentation machinery).
//!
//! **One deviation from Python**: Python's `MAX_DATAGRAM_REQUEST_PAYLOAD`/
//! `MAX_DATAGRAM_REPLY_PAYLOAD`/`MAX_DATAGRAM_PAYLOAD` are plain module-level
//! constants, computed once at import time from `sizes.user_data_budget`.
//! Rust has no non-const way to run a function at static-init time without
//! `once_cell`/`lazy_static` (not in the dependency policy's crate list), so
//! these are functions ([`max_datagram_request_payload`]/
//! [`max_datagram_reply_payload`]/[`max_datagram_payload`]) instead --
//! same values, recomputed cheaply on each call rather than cached.

use crate::sizes::{HOP_COUNT, user_data_budget_default};
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksError {
    pub message: String,
}
impl fmt::Display for SocksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for SocksError {}
fn err(msg: impl Into<String>) -> SocksError {
    SocksError { message: msg.into() }
}

pub const MAGIC: &[u8; 4] = b"ALSM";

pub const CONNECT: u8 = 1;
pub const RESOLVE: u8 = 2;

pub const SUCCESS: u8 = 0;
pub const GENERAL_FAILURE: u8 = 1;
pub const HOST_UNREACHABLE: u8 = 4;
pub const CONNECTION_REFUSED: u8 = 5;
pub const TTL_EXPIRED: u8 = 6;
pub const COMMAND_UNSUPPORTED: u8 = 7;
pub const ADDR_UNSUPPORTED: u8 = 8;

pub const MAX_ADDR_LEN: usize = 255;

/// Closed set of stream-request kinds.
pub struct RequestKind;
impl RequestKind {
    pub const CONNECT: u8 = CONNECT;
    pub const RESOLVE: u8 = RESOLVE;
    pub fn name(value: u8) -> String {
        match value {
            CONNECT => "CONNECT".to_string(),
            RESOLVE => "RESOLVE".to_string(),
            _ => format!("UNKNOWN({value})"),
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
            _ => format!("UNKNOWN({value})"),
        }
    }
}

/// A parsed end-to-end stream request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRequest {
    pub kind: u8,
    pub request_id: u32,
    pub host: String,
    pub port: u16,
    pub bytes_sent: u32,
}

/// A parsed reply to a stream request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamReply {
    pub request_id: u32,
    pub status: u8,
    pub stream_id: u32,
    pub address: Option<(String, u16)>,
}

/// Pack `host:port` into a length-prefixed 6+byte form.
pub fn pack_addr(host: &str, port: u16) -> Result<Vec<u8>, SocksError> {
    let raw = host.as_bytes();
    if raw.len() > MAX_ADDR_LEN {
        return Err(err(format!("host is {} bytes, max is {MAX_ADDR_LEN}", raw.len())));
    }
    let mut out = vec![raw.len() as u8];
    out.extend_from_slice(raw);
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

/// Unpack a [`pack_addr`] blob, returning `((host, port), consumed)`.
pub fn unpack_addr(data: &[u8]) -> Result<((String, u16), usize), SocksError> {
    if data.is_empty() {
        return Err(err("empty address blob"));
    }
    let host_len = data[0] as usize;
    if data.len() < 1 + host_len + 2 {
        return Err(err("truncated address blob"));
    }
    let host = std::str::from_utf8(&data[1..1 + host_len]).map_err(|_| err("address host is not valid UTF-8"))?.to_string();
    let port = u16::from_be_bytes([data[1 + host_len], data[1 + host_len + 1]]);
    Ok(((host, port), 1 + host_len + 2))
}

pub fn encode_request(req: &StreamRequest) -> Result<Vec<u8>, SocksError> {
    let addr = pack_addr(&req.host, req.port)?;
    let mut out = MAGIC.to_vec();
    out.push(addr.len() as u8);
    out.push(req.kind);
    out.extend_from_slice(&req.request_id.to_be_bytes());
    out.extend_from_slice(&addr);
    Ok(out)
}

/// Default request-volume baseline assumed when a request frame does not
/// carry one.
pub const DEFAULT_REQUEST_BYTES: u32 = 64;

pub fn decode_request(data: &[u8]) -> Result<StreamRequest, SocksError> {
    if !data.starts_with(MAGIC) {
        return Err(err("bad stream magic"));
    }
    if data.len() < 4 + 6 {
        return Err(err("stream frame too short"));
    }
    let addr_len = data[4] as usize;
    let kind = data[5];
    let request_id = u32::from_be_bytes([data[6], data[7], data[8], data[9]]);
    if kind != CONNECT && kind != RESOLVE {
        return Err(err(format!("unknown request kind {kind}")));
    }
    if data.len() < 10 + addr_len {
        return Err(err("stream frame too short"));
    }
    let addr_blob = &data[10..10 + addr_len];
    let ((host, port), consumed) = unpack_addr(addr_blob)?;
    if consumed != addr_len {
        return Err(err("address length mismatch"));
    }
    Ok(StreamRequest { kind, request_id, host, port, bytes_sent: DEFAULT_REQUEST_BYTES })
}

pub fn encode_reply(reply: &StreamReply) -> Result<Vec<u8>, SocksError> {
    let body = if let Some((host, port)) = &reply.address {
        let addr = pack_addr(host, *port)?;
        let mut b = vec![addr.len() as u8];
        b.extend_from_slice(&addr);
        b
    } else {
        vec![0u8]
    };
    let mut out = MAGIC.to_vec();
    out.push(reply.status);
    out.extend_from_slice(&reply.request_id.to_be_bytes());
    out.extend_from_slice(&reply.stream_id.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn decode_reply(data: &[u8]) -> Result<StreamReply, SocksError> {
    if !data.starts_with(MAGIC) {
        return Err(err("bad stream magic"));
    }
    if data.len() < 4 + 9 + 1 {
        return Err(err("stream reply too short"));
    }
    let status = data[4];
    let request_id = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
    let stream_id = u32::from_be_bytes([data[9], data[10], data[11], data[12]]);
    let addr_len = data[13] as usize;
    let address = if addr_len != 0 {
        let ((host, port), consumed) = unpack_addr(&data[14..])?;
        if consumed != addr_len {
            return Err(err("reply address length mismatch"));
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

pub const DATAGRAM_MAGIC: &[u8; 4] = b"ALDG";

pub const DATAGRAM_REQUEST: u8 = 1;
pub const DATAGRAM_REPLY: u8 = 2;

// `type(1) + association_id(4) + addr(4) + port(2) + bytes_sent(4) + payload_len(2)`.
const DATAGRAM_REQUEST_STRUCT_LEN: usize = 1 + 4 + 4 + 2 + 4 + 2;
// `type(1) + association_id(4) + addr(4) + port(2) + payload_len(2)`.
const DATAGRAM_REPLY_STRUCT_LEN: usize = 1 + 4 + 4 + 2 + 2;

pub const DATAGRAM_REQUEST_HEADER_SIZE: usize = 4 + DATAGRAM_REQUEST_STRUCT_LEN;
pub const DATAGRAM_REPLY_HEADER_SIZE: usize = 4 + DATAGRAM_REPLY_STRUCT_LEN;

fn single_cell_budget() -> i64 {
    let _ = HOP_COUNT; // used implicitly by user_data_budget_default's default hop count
    user_data_budget_default()
}

/// Largest payload [`encode_datagram_request`] will accept.
pub fn max_datagram_request_payload() -> i64 {
    single_cell_budget() - DATAGRAM_REQUEST_HEADER_SIZE as i64
}
/// Largest payload [`encode_datagram_reply`] will accept.
pub fn max_datagram_reply_payload() -> i64 {
    single_cell_budget() - DATAGRAM_REPLY_HEADER_SIZE as i64
}
/// The bound both directions promise: a datagram of at most this many bytes
/// survives an out-and-back round trip without needing fragmentation.
pub fn max_datagram_payload() -> i64 {
    max_datagram_request_payload().min(max_datagram_reply_payload())
}

/// A parsed UDP datagram, client -> exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramRequest {
    pub association_id: u32,
    pub host: String,
    pub port: u16,
    pub payload: Vec<u8>,
    pub bytes_sent: u32,
}

/// A parsed UDP datagram, exit -> client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramReply {
    pub association_id: u32,
    pub host: String,
    pub port: u16,
    pub payload: Vec<u8>,
}

/// Pack a dotted-quad IPv4 literal into its 4 raw bytes.
pub fn pack_ipv4(host: &str) -> Result<[u8; 4], SocksError> {
    let addr = Ipv4Addr::from_str(host).map_err(|_| err(format!("not a valid IPv4 address: {host:?}")))?;
    Ok(addr.octets())
}

/// Unpack 4 raw bytes into a dotted-quad IPv4 literal.
pub fn unpack_ipv4(data: &[u8]) -> Result<String, SocksError> {
    if data.len() != 4 {
        return Err(err(format!("IPv4 address must be 4 bytes, got {}", data.len())));
    }
    Ok(Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string())
}

/// Whether `data` starts with the datagram magic.
pub fn is_datagram_frame(data: &[u8]) -> bool {
    data.starts_with(DATAGRAM_MAGIC)
}

pub fn encode_datagram_request(req: &DatagramRequest) -> Result<Vec<u8>, SocksError> {
    let max_payload = max_datagram_request_payload();
    if req.payload.len() as i64 > max_payload {
        return Err(err(format!(
            "datagram payload is {} bytes, max is {max_payload} (the single-cell budget minus this frame's header)",
            req.payload.len()
        )));
    }
    let addr = pack_ipv4(&req.host)?;
    let mut out = DATAGRAM_MAGIC.to_vec();
    out.push(DATAGRAM_REQUEST);
    out.extend_from_slice(&req.association_id.to_be_bytes());
    out.extend_from_slice(&addr);
    out.extend_from_slice(&req.port.to_be_bytes());
    out.extend_from_slice(&req.bytes_sent.to_be_bytes());
    out.extend_from_slice(&(req.payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&req.payload);
    Ok(out)
}

pub fn decode_datagram_request(data: &[u8]) -> Result<DatagramRequest, SocksError> {
    if !data.starts_with(DATAGRAM_MAGIC) {
        return Err(err("bad datagram magic"));
    }
    if data.len() < 4 + DATAGRAM_REQUEST_STRUCT_LEN {
        return Err(err("datagram request frame too short"));
    }
    let mut o = 4usize;
    let msg_type = data[o];
    o += 1;
    let association_id = u32::from_be_bytes(data[o..o + 4].try_into().unwrap());
    o += 4;
    let addr = &data[o..o + 4];
    o += 4;
    let port = u16::from_be_bytes([data[o], data[o + 1]]);
    o += 2;
    let bytes_sent = u32::from_be_bytes(data[o..o + 4].try_into().unwrap());
    o += 4;
    let payload_len = u16::from_be_bytes([data[o], data[o + 1]]) as usize;
    o += 2;
    if msg_type != DATAGRAM_REQUEST {
        return Err(err(format!("not a datagram request (type {msg_type})")));
    }
    if data.len() < o + payload_len {
        return Err(err("datagram request payload truncated"));
    }
    let payload = data[o..o + payload_len].to_vec();
    Ok(DatagramRequest { association_id, host: unpack_ipv4(addr)?, port, payload, bytes_sent })
}

pub fn encode_datagram_reply(reply: &DatagramReply) -> Result<Vec<u8>, SocksError> {
    let max_payload = max_datagram_reply_payload();
    if reply.payload.len() as i64 > max_payload {
        return Err(err(format!(
            "datagram payload is {} bytes, max is {max_payload} (the single-cell budget minus this frame's header)",
            reply.payload.len()
        )));
    }
    let addr = pack_ipv4(&reply.host)?;
    let mut out = DATAGRAM_MAGIC.to_vec();
    out.push(DATAGRAM_REPLY);
    out.extend_from_slice(&reply.association_id.to_be_bytes());
    out.extend_from_slice(&addr);
    out.extend_from_slice(&reply.port.to_be_bytes());
    out.extend_from_slice(&(reply.payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&reply.payload);
    Ok(out)
}

pub fn decode_datagram_reply(data: &[u8]) -> Result<DatagramReply, SocksError> {
    if !data.starts_with(DATAGRAM_MAGIC) {
        return Err(err("bad datagram magic"));
    }
    if data.len() < 4 + DATAGRAM_REPLY_STRUCT_LEN {
        return Err(err("datagram reply frame too short"));
    }
    let mut o = 4usize;
    let msg_type = data[o];
    o += 1;
    let association_id = u32::from_be_bytes(data[o..o + 4].try_into().unwrap());
    o += 4;
    let addr = &data[o..o + 4];
    o += 4;
    let port = u16::from_be_bytes([data[o], data[o + 1]]);
    o += 2;
    let payload_len = u16::from_be_bytes([data[o], data[o + 1]]) as usize;
    o += 2;
    if msg_type != DATAGRAM_REPLY {
        return Err(err(format!("not a datagram reply (type {msg_type})")));
    }
    if data.len() < o + payload_len {
        return Err(err("datagram reply payload truncated"));
    }
    let payload = data[o..o + payload_len].to_vec();
    Ok(DatagramReply { association_id, host: unpack_ipv4(addr)?, port, payload })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_unpack_addr_round_trip() {
        let packed = pack_addr("example.com", 443).unwrap();
        let ((host, port), consumed) = unpack_addr(&packed).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(consumed, packed.len());
    }

    #[test]
    fn test_pack_addr_rejects_too_long_host() {
        let host = "a".repeat(300);
        assert!(pack_addr(&host, 80).is_err());
    }

    #[test]
    fn test_unpack_addr_rejects_empty() {
        assert!(unpack_addr(&[]).is_err());
    }

    #[test]
    fn test_unpack_addr_rejects_truncated() {
        assert!(unpack_addr(&[5, b'a', b'b']).is_err());
    }

    #[test]
    fn test_request_round_trip_connect() {
        let req = StreamRequest { kind: CONNECT, request_id: 42, host: "10.0.0.1".to_string(), port: 8080, bytes_sent: 0 };
        let encoded = encode_request(&req).unwrap();
        let decoded = decode_request(&encoded).unwrap();
        assert_eq!(decoded.kind, CONNECT);
        assert_eq!(decoded.request_id, 42);
        assert_eq!(decoded.host, "10.0.0.1");
        assert_eq!(decoded.port, 8080);
        assert_eq!(decoded.bytes_sent, DEFAULT_REQUEST_BYTES);
    }

    #[test]
    fn test_request_round_trip_resolve() {
        let req = StreamRequest { kind: RESOLVE, request_id: 7, host: "example.com".to_string(), port: 0, bytes_sent: 0 };
        let encoded = encode_request(&req).unwrap();
        let decoded = decode_request(&encoded).unwrap();
        assert_eq!(decoded.kind, RESOLVE);
        assert_eq!(decoded.host, "example.com");
    }

    #[test]
    fn test_decode_request_rejects_bad_magic() {
        assert!(decode_request(b"XXXX\x00\x00\x00\x00\x00\x00").is_err());
    }

    #[test]
    fn test_decode_request_rejects_unknown_kind() {
        let req = StreamRequest { kind: 99, request_id: 1, host: "h".to_string(), port: 1, bytes_sent: 0 };
        // Build manually since encode_request doesn't validate kind.
        let addr = pack_addr(&req.host, req.port).unwrap();
        let mut out = MAGIC.to_vec();
        out.push(addr.len() as u8);
        out.push(99);
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&addr);
        assert!(decode_request(&out).is_err());
    }

    #[test]
    fn test_reply_round_trip_with_address() {
        let reply = StreamReply { request_id: 1, status: SUCCESS, stream_id: 0, address: Some(("93.184.216.34".to_string(), 443)) };
        let encoded = encode_reply(&reply).unwrap();
        let decoded = decode_reply(&encoded).unwrap();
        assert_eq!(decoded, reply);
    }

    #[test]
    fn test_reply_round_trip_without_address() {
        let reply = StreamReply { request_id: 2, status: SUCCESS, stream_id: 5, address: None };
        let encoded = encode_reply(&reply).unwrap();
        let decoded = decode_reply(&encoded).unwrap();
        assert_eq!(decoded, reply);
    }

    #[test]
    fn test_decode_reply_rejects_truncated() {
        let reply = StreamReply { request_id: 2, status: SUCCESS, stream_id: 5, address: None };
        let encoded = encode_reply(&reply).unwrap();
        assert!(decode_reply(&encoded[..encoded.len() - 1]).is_err());
    }

    #[test]
    fn test_datagram_request_round_trip() {
        let req = DatagramRequest { association_id: 99, host: "1.2.3.4".to_string(), port: 53, payload: b"hello".to_vec(), bytes_sent: 5 };
        let encoded = encode_datagram_request(&req).unwrap();
        assert!(is_datagram_frame(&encoded));
        let decoded = decode_datagram_request(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn test_datagram_reply_round_trip() {
        let reply = DatagramReply { association_id: 99, host: "5.6.7.8".to_string(), port: 53, payload: b"world".to_vec() };
        let encoded = encode_datagram_reply(&reply).unwrap();
        assert!(is_datagram_frame(&encoded));
        let decoded = decode_datagram_reply(&encoded).unwrap();
        assert_eq!(decoded, reply);
    }

    #[test]
    fn test_datagram_request_rejects_oversized_payload() {
        let max = max_datagram_request_payload() as usize;
        let req = DatagramRequest { association_id: 1, host: "1.2.3.4".to_string(), port: 1, payload: vec![0u8; max + 1], bytes_sent: 0 };
        assert!(encode_datagram_request(&req).is_err());
    }

    #[test]
    fn test_datagram_reply_rejects_oversized_payload() {
        let max = max_datagram_reply_payload() as usize;
        let reply = DatagramReply { association_id: 1, host: "1.2.3.4".to_string(), port: 1, payload: vec![0u8; max + 1] };
        assert!(encode_datagram_reply(&reply).is_err());
    }

    #[test]
    fn test_pack_unpack_ipv4_round_trip() {
        let packed = pack_ipv4("192.168.1.1").unwrap();
        assert_eq!(packed, [192, 168, 1, 1]);
        assert_eq!(unpack_ipv4(&packed).unwrap(), "192.168.1.1");
    }

    #[test]
    fn test_pack_ipv4_rejects_hostname() {
        assert!(pack_ipv4("example.com").is_err());
    }

    #[test]
    fn test_is_datagram_frame() {
        assert!(is_datagram_frame(DATAGRAM_MAGIC));
        assert!(!is_datagram_frame(MAGIC));
    }

    #[test]
    fn test_max_datagram_payload_is_smaller_bound() {
        assert_eq!(max_datagram_payload(), max_datagram_request_payload().min(max_datagram_reply_payload()));
        assert!(max_datagram_payload() > 0);
    }

    #[test]
    fn test_decode_datagram_request_rejects_bad_magic() {
        assert!(decode_datagram_request(b"XXXX").is_err());
    }

    #[test]
    fn test_decode_datagram_reply_rejects_bad_magic() {
        assert!(decode_datagram_reply(b"XXXX").is_err());
    }
}
