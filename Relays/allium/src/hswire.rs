//! Wire framing for Allium's hidden-service control protocol.
//!
//! Port of Python's `hswire.py`. See that module's docstring for the full
//! design rationale (two kinds of circuit -- a service's long-lived intro
//! circuit, and a short-lived rendezvous circuit -- both riding the same
//! onion-cell/circuit machinery and fragment-stream framing `dirwire.rs`
//! uses). Self-contained: builds only on `fragment.rs` (already ported),
//! same as Python's `hswire.py` importing only `.fragment` -- no dependency
//! on `hiddenservice.py`/`directory.rs` at all, unlike `dirwire.rs`'s
//! hidden-service half.

use crate::fragment::{Fragment, FragmentError, Fragmenter, Reassembler, decode_fragment, encode_fragment};
use std::fmt;

/// A hidden-service control message could not be encoded/decoded. The one
/// exception type a caller handling untrusted network input needs to catch
/// -- mirrors `dirwire::DirWireError`'s own reasoning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HsWireError {
    pub message: String,
}
impl fmt::Display for HsWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for HsWireError {}
fn err(msg: impl Into<String>) -> HsWireError {
    HsWireError { message: msg.into() }
}

/// Unchanging prefix, distinct from `socks::MAGIC` (`ALSM`),
/// `DATAGRAM_MAGIC` (`ALDG`), and `dirwire::DIR_MAGIC` (`ALDR`) so none of
/// Allium's framings can ever be confused with each other.
pub const HS_MAGIC: &[u8; 4] = b"ALHS";

/// Fragment stream id reserved for hidden-service control traffic.
pub const HS_STREAM_ID: u32 = 0;

pub const ESTABLISH_INTRO: u8 = 1;
pub const ESTABLISH_INTRO_OK: u8 = 2;
pub const ESTABLISH_INTRO_FAIL: u8 = 3;
pub const INTRODUCE1: u8 = 4;
pub const INTRODUCE_ACK: u8 = 5;
pub const INTRODUCE2: u8 = 6;
pub const RENDEZVOUS_JOIN: u8 = 7;
pub const RENDEZVOUS_JOINED: u8 = 8;
pub const RENDEZVOUS_DATA: u8 = 9;

const MAX_HOST_LEN: usize = 255;
const MAX_MESSAGE_LEN: usize = 255;
const MAX_SEALED_LEN: usize = 4096;
const MAX_DATA_LEN: usize = 1 << 20;

const ED25519_KEY_LEN: usize = 32;
const X25519_KEY_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;
const COOKIE_LEN: usize = 32;
const MESSAGE_HEADER_LEN: usize = 5;

/// Upper bound on one complete reassembled hidden-service message,
/// enforced by [`HsReassembler::push`].
///
/// Without this, `HsReassembler` (like `dirwire::DirReassembler`)
/// accumulated every reassembled byte into an ever-growing `Vec<u8>` with
/// no cap: a peer could hold open one intro/rendezvous circuit and stream
/// an unbounded sequence of small, in-order `Fragment` cells without ever
/// setting FIN, since size limits were only checked once a message was
/// declared complete -- never triggered by such a peer. Pre-authentication
/// remote memory-exhaustion DoS.
///
/// This module's own worst case is `RENDEZVOUS_DATA` at up to
/// `MAX_DATA_LEN`, plus message-header framing -- not a guessed round
/// number. Any wire-valid message is guaranteed to fit.
pub(crate) const MAX_REASSEMBLED_LEN: usize = MESSAGE_HEADER_LEN + MAX_DATA_LEN;

/// Largest hidden-service *control* message (everything except
/// `RENDEZVOUS_DATA`): `INTRODUCE1`/`INTRODUCE2` carry up to
/// `MAX_SEALED_LEN` bytes sealed plus two 32-byte keys and framing, about
/// 4.2 KB; the rest are far smaller. A relay can therefore hold circuits
/// that have not joined a rendezvous to this much instead of the 1 MiB
/// `RENDEZVOUS_DATA` allowance.
pub(crate) const MAX_CONTROL_MESSAGE_LEN: usize = 8 * 1024;

fn expect(data: &[u8], expected_type: u8, label: &str) -> Result<(), HsWireError> {
    if !data.starts_with(HS_MAGIC) {
        return Err(err(format!("bad hidden-service magic in {label}")));
    }
    if data.len() < MESSAGE_HEADER_LEN {
        return Err(err(format!("{label} shorter than the message header")));
    }
    if data[4] != expected_type {
        return Err(err(format!("{label}: expected message type {expected_type}, got {}", data[4])));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ESTABLISH_INTRO: service -> intro relay
// ---------------------------------------------------------------------------

/// The bytes an ESTABLISH_INTRO's signature covers.
pub fn establish_intro_signing_payload(auth_pubkey: &[u8], timestamp: f64) -> Result<Vec<u8>, HsWireError> {
    if auth_pubkey.len() != ED25519_KEY_LEN {
        return Err(err(format!("auth_pubkey must be {ED25519_KEY_LEN} bytes")));
    }
    let mut out = b"allium-hs-establish-intro-v1".to_vec();
    out.extend_from_slice(auth_pubkey);
    out.extend_from_slice(&timestamp.to_be_bytes());
    Ok(out)
}

pub fn encode_establish_intro(auth_pubkey: &[u8], timestamp: f64, signature: &[u8]) -> Result<Vec<u8>, HsWireError> {
    if auth_pubkey.len() != ED25519_KEY_LEN {
        return Err(err(format!("auth_pubkey must be {ED25519_KEY_LEN} bytes")));
    }
    if signature.len() != ED25519_SIG_LEN {
        return Err(err(format!("signature must be {ED25519_SIG_LEN} bytes")));
    }
    let mut out = HS_MAGIC.to_vec();
    out.push(ESTABLISH_INTRO);
    out.extend_from_slice(auth_pubkey);
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(signature);
    Ok(out)
}

/// Returns `(auth_pubkey, timestamp, signature)`. Not verified here -- the
/// caller checks the signature against [`establish_intro_signing_payload`].
pub fn decode_establish_intro(data: &[u8]) -> Result<(Vec<u8>, f64, Vec<u8>), HsWireError> {
    expect(data, ESTABLISH_INTRO, "establish-intro")?;
    let needed = MESSAGE_HEADER_LEN + ED25519_KEY_LEN + 8 + ED25519_SIG_LEN;
    if data.len() < needed {
        return Err(err("establish-intro truncated"));
    }
    let mut offset = MESSAGE_HEADER_LEN;
    let auth_pubkey = data[offset..offset + ED25519_KEY_LEN].to_vec();
    offset += ED25519_KEY_LEN;
    let timestamp = f64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
    offset += 8;
    let signature = data[offset..offset + ED25519_SIG_LEN].to_vec();
    Ok((auth_pubkey, timestamp, signature))
}

pub fn encode_establish_intro_reply(ok: bool, message: &str) -> Vec<u8> {
    let mut body = message.as_bytes().to_vec();
    body.truncate(MAX_MESSAGE_LEN);
    let msg_type = if ok { ESTABLISH_INTRO_OK } else { ESTABLISH_INTRO_FAIL };
    let mut out = HS_MAGIC.to_vec();
    out.push(msg_type);
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    out
}

pub fn decode_establish_intro_reply(data: &[u8]) -> Result<(bool, String), HsWireError> {
    if !data.starts_with(HS_MAGIC) {
        return Err(err("bad hidden-service magic in establish-intro reply"));
    }
    if data.len() < MESSAGE_HEADER_LEN + 1 {
        return Err(err("establish-intro reply truncated before its length"));
    }
    let msg_type = data[4];
    if msg_type != ESTABLISH_INTRO_OK && msg_type != ESTABLISH_INTRO_FAIL {
        return Err(err(format!("not an establish-intro reply: type {msg_type}")));
    }
    let msg_len = data[5] as usize;
    if data.len() < MESSAGE_HEADER_LEN + 1 + msg_len {
        return Err(err("establish-intro reply message truncated"));
    }
    let message = String::from_utf8_lossy(&data[6..6 + msg_len]).into_owned();
    Ok((msg_type == ESTABLISH_INTRO_OK, message))
}

// ---------------------------------------------------------------------------
// INTRODUCE1 / INTRODUCE_ACK: client <-> intro relay
// ---------------------------------------------------------------------------

pub fn encode_introduce1(auth_pubkey: &[u8], client_ephemeral_pub: &[u8], sealed: &[u8]) -> Result<Vec<u8>, HsWireError> {
    if auth_pubkey.len() != ED25519_KEY_LEN {
        return Err(err(format!("auth_pubkey must be {ED25519_KEY_LEN} bytes")));
    }
    if client_ephemeral_pub.len() != X25519_KEY_LEN {
        return Err(err(format!("client_ephemeral_pub must be {X25519_KEY_LEN} bytes")));
    }
    if sealed.len() > MAX_SEALED_LEN {
        return Err(err(format!("sealed envelope is {} bytes, max is {MAX_SEALED_LEN}", sealed.len())));
    }
    let mut out = HS_MAGIC.to_vec();
    out.push(INTRODUCE1);
    out.extend_from_slice(auth_pubkey);
    out.extend_from_slice(client_ephemeral_pub);
    out.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
    out.extend_from_slice(sealed);
    Ok(out)
}

/// Returns `(auth_pubkey, client_ephemeral_pub, sealed)`.
pub fn decode_introduce1(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), HsWireError> {
    expect(data, INTRODUCE1, "introduce1")?;
    let fixed = MESSAGE_HEADER_LEN + ED25519_KEY_LEN + X25519_KEY_LEN + 2;
    if data.len() < fixed {
        return Err(err("introduce1 truncated before its fixed fields"));
    }
    let mut offset = MESSAGE_HEADER_LEN;
    let auth_pubkey = data[offset..offset + ED25519_KEY_LEN].to_vec();
    offset += ED25519_KEY_LEN;
    let client_ephemeral_pub = data[offset..offset + X25519_KEY_LEN].to_vec();
    offset += X25519_KEY_LEN;
    let sealed_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    if sealed_len > MAX_SEALED_LEN || data.len() < offset + sealed_len {
        return Err(err("introduce1 sealed envelope truncated or oversized"));
    }
    let sealed = data[offset..offset + sealed_len].to_vec();
    Ok((auth_pubkey, client_ephemeral_pub, sealed))
}

pub fn encode_introduce_ack(ok: bool, message: &str) -> Vec<u8> {
    let mut body = message.as_bytes().to_vec();
    body.truncate(MAX_MESSAGE_LEN);
    let mut out = HS_MAGIC.to_vec();
    out.push(INTRODUCE_ACK);
    out.push(if ok { 1 } else { 0 });
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    out
}

pub fn decode_introduce_ack(data: &[u8]) -> Result<(bool, String), HsWireError> {
    expect(data, INTRODUCE_ACK, "introduce-ack")?;
    if data.len() < MESSAGE_HEADER_LEN + 2 {
        return Err(err("introduce-ack truncated before its status/length"));
    }
    let ok = data[5] == 1;
    let msg_len = data[6] as usize;
    if data.len() < MESSAGE_HEADER_LEN + 2 + msg_len {
        return Err(err("introduce-ack message truncated"));
    }
    let message = String::from_utf8_lossy(&data[7..7 + msg_len]).into_owned();
    Ok((ok, message))
}

// ---------------------------------------------------------------------------
// INTRODUCE2: intro relay -> service (the forwarded envelope)
// ---------------------------------------------------------------------------

pub fn encode_introduce2(client_ephemeral_pub: &[u8], sealed: &[u8]) -> Result<Vec<u8>, HsWireError> {
    if client_ephemeral_pub.len() != X25519_KEY_LEN {
        return Err(err(format!("client_ephemeral_pub must be {X25519_KEY_LEN} bytes")));
    }
    if sealed.len() > MAX_SEALED_LEN {
        return Err(err(format!("sealed envelope is {} bytes, max is {MAX_SEALED_LEN}", sealed.len())));
    }
    let mut out = HS_MAGIC.to_vec();
    out.push(INTRODUCE2);
    out.extend_from_slice(client_ephemeral_pub);
    out.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
    out.extend_from_slice(sealed);
    Ok(out)
}

/// Returns `(client_ephemeral_pub, sealed)`.
pub fn decode_introduce2(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), HsWireError> {
    expect(data, INTRODUCE2, "introduce2")?;
    let fixed = MESSAGE_HEADER_LEN + X25519_KEY_LEN + 2;
    if data.len() < fixed {
        return Err(err("introduce2 truncated before its fixed fields"));
    }
    let mut offset = MESSAGE_HEADER_LEN;
    let client_ephemeral_pub = data[offset..offset + X25519_KEY_LEN].to_vec();
    offset += X25519_KEY_LEN;
    let sealed_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    if sealed_len > MAX_SEALED_LEN || data.len() < offset + sealed_len {
        return Err(err("introduce2 sealed envelope truncated or oversized"));
    }
    let sealed = data[offset..offset + sealed_len].to_vec();
    Ok((client_ephemeral_pub, sealed))
}

// ---------------------------------------------------------------------------
// The sealed INTRODUCE1/2 inner plaintext: which rendezvous point, which cookie
// ---------------------------------------------------------------------------

pub fn encode_rendezvous_request(rp_identity: &[u8], rp_host: &str, rp_port: u16, cookie: &[u8]) -> Result<Vec<u8>, HsWireError> {
    if rp_identity.len() != ED25519_KEY_LEN {
        return Err(err(format!("rp_identity must be {ED25519_KEY_LEN} bytes")));
    }
    if cookie.len() != COOKIE_LEN {
        return Err(err(format!("cookie must be {COOKIE_LEN} bytes")));
    }
    let host = rp_host.as_bytes();
    if host.len() > MAX_HOST_LEN {
        return Err(err(format!("rp_host is {} bytes, max is {MAX_HOST_LEN}", host.len())));
    }
    let mut out = Vec::new();
    out.extend_from_slice(rp_identity);
    out.push(host.len() as u8);
    out.extend_from_slice(host);
    out.extend_from_slice(&rp_port.to_be_bytes());
    out.extend_from_slice(cookie);
    Ok(out)
}

/// Returns `(rp_identity, rp_host, rp_port, cookie)`.
pub fn decode_rendezvous_request(data: &[u8]) -> Result<(Vec<u8>, String, u16, Vec<u8>), HsWireError> {
    if data.len() < ED25519_KEY_LEN + 1 {
        return Err(err("rendezvous request truncated before host length"));
    }
    let rp_identity = data[..ED25519_KEY_LEN].to_vec();
    let mut offset = ED25519_KEY_LEN;
    let host_len = data[offset] as usize;
    offset += 1;
    if host_len > MAX_HOST_LEN || data.len() < offset + host_len + 2 + COOKIE_LEN {
        return Err(err("rendezvous request truncated or oversized"));
    }
    // SECURITY: this plaintext is only AEAD-authenticated with the
    // service's *public* introduction-encryption key, so any client can
    // craft a well-formed-but-invalid-UTF-8 rp_host and reach this decode --
    // it must raise HsWireError like every other malformed-field case,
    // never a raw UTF-8 panic/replacement-silently-succeeding.
    let rp_host = std::str::from_utf8(&data[offset..offset + host_len])
        .map_err(|_| err("rendezvous request host is not valid UTF-8"))?
        .to_string();
    offset += host_len;
    let rp_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    let cookie = data[offset..offset + COOKIE_LEN].to_vec();
    Ok((rp_identity, rp_host, rp_port, cookie))
}

// ---------------------------------------------------------------------------
// RENDEZVOUS_JOIN / RENDEZVOUS_JOINED: client & service <-> rendezvous point
// ---------------------------------------------------------------------------

pub fn encode_rendezvous_join(cookie: &[u8]) -> Result<Vec<u8>, HsWireError> {
    if cookie.len() != COOKIE_LEN {
        return Err(err(format!("cookie must be {COOKIE_LEN} bytes")));
    }
    let mut out = HS_MAGIC.to_vec();
    out.push(RENDEZVOUS_JOIN);
    out.extend_from_slice(cookie);
    Ok(out)
}

pub fn decode_rendezvous_join(data: &[u8]) -> Result<Vec<u8>, HsWireError> {
    expect(data, RENDEZVOUS_JOIN, "rendezvous-join")?;
    if data.len() < MESSAGE_HEADER_LEN + COOKIE_LEN {
        return Err(err("rendezvous-join truncated"));
    }
    Ok(data[MESSAGE_HEADER_LEN..MESSAGE_HEADER_LEN + COOKIE_LEN].to_vec())
}

pub fn encode_rendezvous_joined(ok: bool, message: &str) -> Vec<u8> {
    let mut body = message.as_bytes().to_vec();
    body.truncate(MAX_MESSAGE_LEN);
    let mut out = HS_MAGIC.to_vec();
    out.push(RENDEZVOUS_JOINED);
    out.push(if ok { 1 } else { 0 });
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    out
}

pub fn decode_rendezvous_joined(data: &[u8]) -> Result<(bool, String), HsWireError> {
    expect(data, RENDEZVOUS_JOINED, "rendezvous-joined")?;
    if data.len() < MESSAGE_HEADER_LEN + 2 {
        return Err(err("rendezvous-joined truncated before its status/length"));
    }
    let ok = data[5] == 1;
    let msg_len = data[6] as usize;
    if data.len() < MESSAGE_HEADER_LEN + 2 + msg_len {
        return Err(err("rendezvous-joined message truncated"));
    }
    let message = String::from_utf8_lossy(&data[7..7 + msg_len]).into_owned();
    Ok((ok, message))
}

// ---------------------------------------------------------------------------
// RENDEZVOUS_DATA: opaque post-join tunnel bytes
// ---------------------------------------------------------------------------

/// Wraps opaque tunnel bytes for the rendezvous point to forward untouched.
/// The rendezvous point reads only the magic/type prefix -- never `payload`
/// itself.
pub fn encode_rendezvous_data(payload: &[u8]) -> Result<Vec<u8>, HsWireError> {
    if payload.len() > MAX_DATA_LEN {
        return Err(err(format!("rendezvous data is {} bytes, max is {MAX_DATA_LEN}", payload.len())));
    }
    let mut out = HS_MAGIC.to_vec();
    out.push(RENDEZVOUS_DATA);
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn decode_rendezvous_data(data: &[u8]) -> Result<Vec<u8>, HsWireError> {
    expect(data, RENDEZVOUS_DATA, "rendezvous-data")?;
    Ok(data[MESSAGE_HEADER_LEN..].to_vec())
}

// ---------------------------------------------------------------------------
// Fragmentation (identical shape to dirwire's, independent copy so the two
// protocols never share mutable state)
// ---------------------------------------------------------------------------

/// Split a whole hidden-service control message into wire-ready cell
/// payloads, ready to hand straight to a `CircuitBuilder`'s `send`.
pub fn fragment_message(message: &[u8], mtu: usize) -> Result<Vec<Vec<u8>>, FragmentError> {
    let fragments = Fragmenter::new(mtu, HS_STREAM_ID)?.fragment(message);
    Ok(fragments.iter().map(encode_fragment).collect())
}

/// [`fragment_message`] with the default 256-byte mtu, matching Python's
/// `mtu: int = 256` default argument.
pub fn fragment_message_default(message: &[u8]) -> Vec<Vec<u8>> {
    fragment_message(message, 256).expect("default mtu is always valid")
}

/// Reassembles a *sequence* of hidden-service messages from Fragment cells.
///
/// Unlike `dirwire::DirReassembler` (good for exactly one message and then
/// discarded, matching a directory circuit's one-shot use), a
/// hidden-service circuit can carry many messages over its lifetime -- so
/// [`HsReassembler::push`] resets its internal state the moment one message
/// completes, ready for the next.
pub struct HsReassembler {
    max_pending: usize,
    reassembler: Reassembler,
    buffer: Vec<u8>,
}

impl HsReassembler {
    pub fn new(max_pending: usize) -> HsReassembler {
        HsReassembler { max_pending, reassembler: Reassembler::new(HS_STREAM_ID, max_pending), buffer: Vec::new() }
    }

    pub fn with_defaults() -> HsReassembler {
        HsReassembler::new(64)
    }

    /// Feed one raw (already fragment-encoded) received cell payload.
    /// Returns the complete message the moment it becomes whole (after
    /// which this instance is reset and ready for the next one); `None`
    /// while more fragments are still expected.
    ///
    /// Rejects a message once it would exceed [`MAX_REASSEMBLED_LEN`],
    /// before the oversized bytes are ever appended -- see that
    /// constant's doc comment for why this check exists. Also resets
    /// internal state on that error (same as on a successful completion),
    /// since -- unlike `dirwire::DirReassembler`, which is one-shot and
    /// discarded by its caller on any error -- an `HsReassembler` is
    /// reused across many messages over one circuit's lifetime, so it
    /// must not be left stuck holding a maxed-out buffer for that
    /// circuit's remaining lifetime.
    pub fn push(&mut self, wire_bytes: &[u8]) -> Result<Option<Vec<u8>>, HsWireError> {
        self.push_limited(wire_bytes, MAX_REASSEMBLED_LEN)
    }

    /// Bytes held right now: in-order bytes of the message being built plus
    /// out-of-order chunks waiting on a gap.
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len() + self.reassembler.pending_bytes()
    }

    /// [`Self::push`] with a caller-chosen cap (at most
    /// [`MAX_REASSEMBLED_LEN`]) on the bytes this reassembler may hold, in
    /// order *and* out of order. A relay uses a small cap for a circuit
    /// that has not joined a rendezvous, since only `RENDEZVOUS_DATA` can
    /// legitimately be large. Exceeding the cap drops the message and
    /// resets the reassembler, exactly like the `MAX_REASSEMBLED_LEN` case.
    pub fn push_limited(&mut self, wire_bytes: &[u8], max_len: usize) -> Result<Option<Vec<u8>>, HsWireError> {
        let max_len = max_len.min(MAX_REASSEMBLED_LEN);
        let fragment: Fragment = decode_fragment(wire_bytes).map_err(|e| err(format!("not a valid hidden-service fragment: {e}")))?;
        // A fragment that is not the next in order is buffered, not
        // consumed, so it has to count against the cap before it is stored.
        if fragment.offset != self.reassembler.expected_offset() && self.buffered_bytes() + fragment.data.len() > max_len {
            self.buffer.clear();
            self.reassembler = Reassembler::new(HS_STREAM_ID, self.max_pending);
            return Err(err(format!("hidden-service message buffered out of order exceeds {max_len} bytes; dropping message")));
        }
        let chunk = self.reassembler.push(&fragment).map_err(|e| err(e.to_string()))?;
        if self.buffer.len() + chunk.len() > max_len {
            self.buffer.clear();
            self.reassembler = Reassembler::new(HS_STREAM_ID, self.max_pending);
            return Err(err(format!(
                "reassembled hidden-service message exceeds {max_len} bytes; dropping message"
            )));
        }
        self.buffer.extend_from_slice(&chunk);
        if self.reassembler.finished() {
            let message = std::mem::take(&mut self.buffer);
            self.reassembler = Reassembler::new(HS_STREAM_ID, self.max_pending);
            return Ok(Some(message));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_establish_intro_signing_payload_binds_key_and_timestamp() {
        let key = [7u8; ED25519_KEY_LEN];
        let p1 = establish_intro_signing_payload(&key, 100.0).unwrap();
        let p2 = establish_intro_signing_payload(&key, 101.0).unwrap();
        assert_ne!(p1, p2);
        assert!(establish_intro_signing_payload(&[1u8; 4], 0.0).is_err());
    }

    #[test]
    fn test_establish_intro_round_trip() {
        let key = [7u8; ED25519_KEY_LEN];
        let sig = [9u8; ED25519_SIG_LEN];
        let encoded = encode_establish_intro(&key, 12345.5, &sig).unwrap();
        let (k, ts, s) = decode_establish_intro(&encoded).unwrap();
        assert_eq!(k, key.to_vec());
        assert_eq!(ts, 12345.5);
        assert_eq!(s, sig.to_vec());
    }

    #[test]
    fn test_establish_intro_reply_round_trip_ok_and_fail() {
        let ok_encoded = encode_establish_intro_reply(true, "welcome");
        assert_eq!(decode_establish_intro_reply(&ok_encoded).unwrap(), (true, "welcome".to_string()));
        let fail_encoded = encode_establish_intro_reply(false, "busy");
        assert_eq!(decode_establish_intro_reply(&fail_encoded).unwrap(), (false, "busy".to_string()));
    }

    #[test]
    fn test_introduce1_round_trip() {
        let auth = [1u8; ED25519_KEY_LEN];
        let eph = [2u8; X25519_KEY_LEN];
        let sealed = vec![9u8; 100];
        let encoded = encode_introduce1(&auth, &eph, &sealed).unwrap();
        let (a, e, s) = decode_introduce1(&encoded).unwrap();
        assert_eq!(a, auth.to_vec());
        assert_eq!(e, eph.to_vec());
        assert_eq!(s, sealed);
    }

    #[test]
    fn test_introduce1_rejects_oversized_sealed() {
        let auth = [1u8; ED25519_KEY_LEN];
        let eph = [2u8; X25519_KEY_LEN];
        let sealed = vec![0u8; MAX_SEALED_LEN + 1];
        assert!(encode_introduce1(&auth, &eph, &sealed).is_err());
    }

    #[test]
    fn test_introduce_ack_round_trip() {
        let encoded = encode_introduce_ack(true, "ok");
        assert_eq!(decode_introduce_ack(&encoded).unwrap(), (true, "ok".to_string()));
    }

    #[test]
    fn test_introduce2_round_trip_has_no_auth_pubkey() {
        let eph = [3u8; X25519_KEY_LEN];
        let sealed = vec![5u8; 50];
        let encoded = encode_introduce2(&eph, &sealed).unwrap();
        assert_eq!(encoded.len(), MESSAGE_HEADER_LEN + X25519_KEY_LEN + 2 + sealed.len());
        let (e, s) = decode_introduce2(&encoded).unwrap();
        assert_eq!(e, eph.to_vec());
        assert_eq!(s, sealed);
    }

    #[test]
    fn test_rendezvous_request_round_trip() {
        let rp_identity = [4u8; ED25519_KEY_LEN];
        let cookie = [8u8; COOKIE_LEN];
        let encoded = encode_rendezvous_request(&rp_identity, "10.0.0.5", 9001, &cookie).unwrap();
        let (id, host, port, c) = decode_rendezvous_request(&encoded).unwrap();
        assert_eq!(id, rp_identity.to_vec());
        assert_eq!(host, "10.0.0.5");
        assert_eq!(port, 9001);
        assert_eq!(c, cookie.to_vec());
    }

    #[test]
    fn test_rendezvous_request_rejects_bad_utf8_host_cleanly() {
        let rp_identity = [4u8; ED25519_KEY_LEN];
        let mut data = rp_identity.to_vec();
        data.push(1); // host_len = 1
        data.push(0xFF); // invalid UTF-8 byte
        data.extend_from_slice(&9001u16.to_be_bytes());
        data.extend_from_slice(&[0u8; COOKIE_LEN]);
        assert!(decode_rendezvous_request(&data).is_err());
    }

    #[test]
    fn test_rendezvous_join_round_trip() {
        let cookie = [6u8; COOKIE_LEN];
        let encoded = encode_rendezvous_join(&cookie).unwrap();
        assert_eq!(decode_rendezvous_join(&encoded).unwrap(), cookie.to_vec());
        assert!(encode_rendezvous_join(&[0u8; 5]).is_err());
    }

    #[test]
    fn test_rendezvous_joined_round_trip() {
        let encoded = encode_rendezvous_joined(true, "paired");
        assert_eq!(decode_rendezvous_joined(&encoded).unwrap(), (true, "paired".to_string()));
    }

    #[test]
    fn test_rendezvous_data_round_trip_is_opaque() {
        let payload = vec![0xABu8; 1000];
        let encoded = encode_rendezvous_data(&payload).unwrap();
        assert_eq!(decode_rendezvous_data(&encoded).unwrap(), payload);
    }

    #[test]
    fn test_rendezvous_data_rejects_oversized() {
        let payload = vec![0u8; MAX_DATA_LEN + 1];
        assert!(encode_rendezvous_data(&payload).is_err());
    }

    #[test]
    fn test_wrong_message_type_is_rejected() {
        let encoded = encode_rendezvous_join(&[1u8; COOKIE_LEN]).unwrap();
        assert!(decode_rendezvous_joined(&encoded).is_err());
    }

    #[test]
    fn test_bad_magic_is_rejected() {
        let mut encoded = encode_rendezvous_join(&[1u8; COOKIE_LEN]).unwrap();
        encoded[0] = b'X';
        assert!(decode_rendezvous_join(&encoded).is_err());
    }

    #[test]
    fn test_fragment_message_and_hs_reassembler_round_trip_one_message() {
        let message = vec![0x42u8; 2000]; // bigger than the 256-byte default mtu
        let datagrams = fragment_message_default(&message);
        assert!(datagrams.len() > 1);
        let mut reassembler = HsReassembler::with_defaults();
        let mut result = None;
        for datagram in &datagrams {
            result = reassembler.push(datagram).unwrap();
        }
        assert_eq!(result.unwrap(), message);
    }

    #[test]
    fn test_hs_reassembler_resets_and_accepts_a_second_message() {
        let m1 = encode_rendezvous_join(&[1u8; COOKIE_LEN]).unwrap();
        let m2 = encode_rendezvous_data(&[2u8; 10]).unwrap();
        let mut reassembler = HsReassembler::with_defaults();

        let d1 = fragment_message_default(&m1);
        let mut r1 = None;
        for datagram in &d1 {
            r1 = reassembler.push(datagram).unwrap();
        }
        assert_eq!(r1.unwrap(), m1);

        let d2 = fragment_message_default(&m2);
        let mut r2 = None;
        for datagram in &d2 {
            r2 = reassembler.push(datagram).unwrap();
        }
        assert_eq!(r2.unwrap(), m2);
    }

    #[test]
    fn test_hs_reassembler_rejects_garbage() {
        let mut reassembler = HsReassembler::with_defaults();
        assert!(reassembler.push(b"not a fragment").is_err());
    }

    /// A stream that never sends FIN must not be allowed to grow its
    /// reassembly buffer without bound -- exactly at the boundary: a
    /// message of precisely `MAX_REASSEMBLED_LEN` bytes must still
    /// reassemble, one byte more must be refused, and (unlike
    /// `dirwire::DirReassembler`, which is one-shot) the instance must
    /// reset and still be able to reassemble a normal message afterward,
    /// since one `HsReassembler` is reused across a circuit's lifetime.
    #[test]
    fn test_hs_reassembler_rejects_message_exceeding_max_reassembled_len_and_recovers() {
        let mut reassembler = HsReassembler::with_defaults();
        let first = Fragment::new(HS_STREAM_ID, 0, false, vec![0x41u8; MAX_REASSEMBLED_LEN]);
        assert_eq!(reassembler.push(&encode_fragment(&first)).unwrap(), None);
        let second = Fragment::new(HS_STREAM_ID, MAX_REASSEMBLED_LEN as u32, true, vec![0x42u8]);
        assert!(reassembler.push(&encode_fragment(&second)).is_err());

        let m2 = encode_rendezvous_join(&[3u8; COOKIE_LEN]).unwrap();
        let d2 = fragment_message_default(&m2);
        let mut r2 = None;
        for datagram in &d2 {
            r2 = reassembler.push(datagram).unwrap();
        }
        assert_eq!(r2.unwrap(), m2);
    }
}
