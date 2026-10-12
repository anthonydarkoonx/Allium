//! NAT traversal, client side: ask the authority to open a hole to a relay.
//!
//! When a route contains a relay that sits behind NAT (its descriptor
//! carries a [`crate::directory::EXT_REACHABILITY`] extension), the client
//! asks the pinned directory authority to broker a UDP hole-punch toward
//! it before extending the circuit, using [`request_punch`].
//!
//! Security audit fix (2026-09-26, finding MH2): `PUNCH_REQUEST`/
//! `PUNCH_REPLY` used to be a plaintext body / an Ed25519-signed plaintext
//! body. Both are now sealed with an AEAD keyed off X25519 ECDH, matching
//! `Relays/allium/src/nat.rs`'s rewrite (which this must stay wire-
//! compatible with): the client generates a fresh, one-time X25519
//! keypair per request (so issuing one creates no persistent identity for
//! the requester -- the same anonymous-sender shape
//! `hiddenservice::seal_introduce`/`open_introduce_raw` uses for
//! INTRODUCE1) and derives two session keys from its ECDH with the
//! introducer's long-term, pinned X25519 key (carried in the relay
//! descriptor's `EXT_REACHABILITY` extension, alongside the introducer's
//! Ed25519 identity this client already pins via `--trust-authority`) --
//! one for sealing the request, one for the introducer to seal its reply,
//! so the two directions of one exchange never reuse a key+nonce space.
//! Trust in the reply's authenticity comes from the client already
//! pinning the introducer's identity and only accepting X25519 keys that
//! arrived bound to it, not from a signature.

use std::fmt;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::new_aead;
use crate::osrand;

pub const NAT_MAGIC: &[u8; 4] = b"ALNT";

pub const PUNCH_REQUEST: u8 = 3;
pub const PUNCH_REPLY: u8 = 5;

pub const STATUS_OK: u8 = 0;

const NONCE_LEN: usize = 16;
const KEY_LEN: usize = 32;

/// Reachability extension ([`crate::directory::EXT_REACHABILITY`]) mode byte.
pub const MODE_NAT: u8 = 1;

/// A NAT-traversal message was malformed, unauthenticated, stale or refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatError(pub String);

impl fmt::Display for NatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for NatError {}

fn err(msg: impl Into<String>) -> NatError {
    NatError(msg.into())
}

// ---------------------------------------------------------------------------
// Descriptor extension
// ---------------------------------------------------------------------------

/// `(mode, introducer_identity, introducer_x25519_public, introducer_host,
/// introducer_port)`, decoded from a relay descriptor's `EXT_REACHABILITY`
/// extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reachability {
    pub mode: u8,
    pub introducer_identity: Vec<u8>,
    pub introducer_x25519_public: Vec<u8>,
    pub introducer_host: String,
    pub introducer_port: u16,
}

impl Reachability {
    pub fn introducer_addr(&self) -> (String, u16) {
        (self.introducer_host.clone(), self.introducer_port)
    }
}

fn unpack_addr(data: &[u8], offset: usize) -> Result<((String, u16), usize), NatError> {
    if data.len() < offset + 1 {
        return Err(err("truncated address"));
    }
    let n = data[offset] as usize;
    let offset = offset + 1;
    if data.len() < offset + n + 2 {
        return Err(err("truncated address"));
    }
    let host = std::str::from_utf8(&data[offset..offset + n]).map_err(|_| err("bad address encoding"))?.to_string();
    let port = u16::from_be_bytes([data[offset + n], data[offset + n + 1]]);
    Ok(((host, port), offset + n + 2))
}

/// # Errors
/// [`NatError`] if `value` is too short, not mode [`MODE_NAT`], or has
/// trailing bytes past its address field.
pub fn decode_reachability(value: &[u8]) -> Result<Reachability, NatError> {
    if value.len() < 1 + KEY_LEN + KEY_LEN + 3 || value[0] != MODE_NAT {
        return Err(err("unsupported reachability extension"));
    }
    let identity = value[1..1 + KEY_LEN].to_vec();
    let x25519_public = value[1 + KEY_LEN..1 + 2 * KEY_LEN].to_vec();
    let ((host, port), end) = unpack_addr(value, 1 + 2 * KEY_LEN)?;
    if end != value.len() {
        return Err(err("trailing bytes in reachability extension"));
    }
    Ok(Reachability { mode: MODE_NAT, introducer_identity: identity, introducer_x25519_public: x25519_public, introducer_host: host, introducer_port: port })
}

// ---------------------------------------------------------------------------
// X25519 / sealing helpers
// ---------------------------------------------------------------------------

const L_PUNCH_SESSION: &[u8] = b"allium-nat-punch-session-v1";

pub fn is_nat_message(datagram: &[u8]) -> bool {
    datagram.len() >= 5 && &datagram[..4] == NAT_MAGIC
}

fn header(msg_type: u8) -> Vec<u8> {
    let mut out = NAT_MAGIC.to_vec();
    out.push(msg_type);
    out
}

/// HKDF-SHA256 (RFC 5869): extract then expand in one call. Mirrors
/// `Relays/allium/src/hashutil.rs`'s `hkdf_sha256` (same argument order)
/// and this crate's own `hiddenservice.rs::hs_hkdf`.
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm).expect("HKDF-SHA256 output length is always valid for the lengths this module requests");
    okm
}

fn x25519_generate() -> [u8; KEY_LEN] {
    osrand::bytes(KEY_LEN).try_into().expect("32 random bytes")
}

fn x25519_public(private: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    PublicKey::from(&StaticSecret::from(*private)).to_bytes()
}

fn x25519_dh(private: &[u8; KEY_LEN], peer_public: &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN], NatError> {
    let secret = StaticSecret::from(*private);
    let shared = secret.diffie_hellman(&PublicKey::from(*peer_public));
    if !shared.was_contributory() {
        return Err(err("peer public key is unusable (low-order point)"));
    }
    Ok(*shared.as_bytes())
}

/// Derive the two AEAD keys for one `PUNCH_REQUEST`/`PUNCH_REPLY` exchange
/// from the raw ECDH shared secret both sides independently compute --
/// separate keys per direction, so sealing the reply never reuses the
/// exact key (and nonce space) that sealed the request. Mirrors
/// `Relays/allium/src/nat.rs`'s `punch_session_keys` exactly (same labels,
/// same output order) -- this is the wire-compatibility surface between
/// the two crates.
fn punch_session_keys(shared: &[u8]) -> Result<([u8; KEY_LEN], [u8; KEY_LEN]), NatError> {
    let request_key: [u8; KEY_LEN] =
        hkdf_sha256(shared, L_PUNCH_SESSION, b"request", KEY_LEN).try_into().map_err(|_| err("hkdf produced the wrong key length"))?;
    let reply_key: [u8; KEY_LEN] =
        hkdf_sha256(shared, L_PUNCH_SESSION, b"reply", KEY_LEN).try_into().map_err(|_| err("hkdf produced the wrong key length"))?;
    Ok((request_key, reply_key))
}

// -- PUNCH_REQUEST (client -> authority) -------------------------------------

/// Returns `(message, nonce, client_ephemeral_private)`.
/// `client_ephemeral_private` is needed later to decrypt the `PUNCH_REPLY`
/// via [`decode_punch_reply`] -- generated fresh here (or supplied, for
/// deterministic tests) and never reused across requests, so issuing a
/// request creates no persistent identity for the requester.
///
/// # Errors
/// [`NatError`] if `target_identity`/`peer_identity` are not 32 bytes.
pub fn encode_punch_request(
    target_identity: &[u8],
    peer_identity: &[u8],
    introducer_x25519_public: &[u8; KEY_LEN],
    client_ephemeral_private: Option<[u8; KEY_LEN]>,
    nonce: Option<[u8; NONCE_LEN]>,
) -> Result<(Vec<u8>, [u8; NONCE_LEN], [u8; KEY_LEN]), NatError> {
    if target_identity.len() != KEY_LEN || peer_identity.len() != KEY_LEN {
        return Err(err("identities must be 32 bytes"));
    }
    let nonce = match nonce {
        Some(n) => n,
        None => osrand::bytes(NONCE_LEN).try_into().expect("16 random bytes"),
    };
    let client_ephemeral_private = client_ephemeral_private.unwrap_or_else(x25519_generate);
    let client_ephemeral_public = x25519_public(&client_ephemeral_private);
    let shared = x25519_dh(&client_ephemeral_private, introducer_x25519_public)?;
    let (request_key, _reply_key) = punch_session_keys(&shared)?;
    let mut plaintext = target_identity.to_vec();
    plaintext.extend_from_slice(peer_identity);
    let mut ad = nonce.to_vec();
    ad.extend_from_slice(&client_ephemeral_public);
    let mut aead = new_aead("chacha20-poly1305", &request_key, None).map_err(|e| err(e.to_string()))?;
    let sealed = aead.seal(&plaintext, &ad).map_err(|e| err(e.to_string()))?;
    let mut out = header(PUNCH_REQUEST);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&client_ephemeral_public);
    out.extend_from_slice(&sealed);
    Ok((out, nonce, client_ephemeral_private))
}

// -- PUNCH_REPLY (authority -> client) ---------------------------------------

/// Verify (via AEAD, not a signature -- see the module doc) a `PUNCH_REPLY`
/// and return `(status, (host, port) or None)`. `client_ephemeral_private`
/// is the same one-time key [`encode_punch_request`] generated for this
/// request.
///
/// # Errors
/// [`NatError`] on bad magic/type, a nonce mismatch, a reply that doesn't
/// authenticate under this session's derived key, or a malformed body.
pub fn decode_punch_reply(data: &[u8], client_ephemeral_private: &[u8; KEY_LEN], introducer_x25519_public: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN]) -> Result<(u8, Option<(String, u16)>), NatError> {
    if !is_nat_message(data) || data[4] != PUNCH_REPLY {
        return Err(err("not a PUNCH_REPLY"));
    }
    let body = &data[5..];
    if body.len() < NONCE_LEN || &body[..NONCE_LEN] != nonce {
        return Err(err("PUNCH_REPLY nonce mismatch"));
    }
    let sealed = &body[NONCE_LEN..];
    let shared = x25519_dh(client_ephemeral_private, introducer_x25519_public)?;
    let (_request_key, reply_key) = punch_session_keys(&shared)?;
    let aead = new_aead("chacha20-poly1305", &reply_key, None).map_err(|e| err(e.to_string()))?;
    let plaintext = aead.open(sealed, nonce).map_err(|_| err("PUNCH_REPLY did not authenticate"))?;
    if plaintext.is_empty() {
        return Err(err("truncated PUNCH_REPLY"));
    }
    let status = plaintext[0];
    let (addr, end) = unpack_addr(&plaintext, 1)?;
    if end != plaintext.len() {
        return Err(err("trailing bytes in PUNCH_REPLY"));
    }
    Ok((status, if status == STATUS_OK { Some(addr) } else { None }))
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// Blocking helper: ask the introducer to punch `target` open toward `peer`
/// and return the target's current public `(host, port)`.
///
/// `introducer_x25519_public` is the introducer's pinned X25519 key -- see
/// this module's doc comment on where it comes from and why it's trusted.
///
/// # Errors
/// [`NatError`] on refusal, a bad key, or no answer within
/// `timeout * attempts`.
pub fn request_punch(
    introducer_addr: (&str, u16),
    introducer_x25519_public: &[u8],
    target_identity: &[u8],
    peer_identity: &[u8],
    timeout: Duration,
    attempts: usize,
) -> Result<(String, u16), NatError> {
    let introducer_x25519_public: [u8; KEY_LEN] =
        introducer_x25519_public.try_into().map_err(|_| err("introducer x25519 key must be 32 bytes"))?;
    let (message, nonce, client_ephemeral_private) = encode_punch_request(target_identity, peer_identity, &introducer_x25519_public, None, None)?;
    let is_v6 = introducer_addr.0.contains(':');
    let bind_addr = if is_v6 { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(bind_addr).map_err(|e| err(format!("could not open a UDP socket: {e}")))?;

    let mut last_error: Option<String> = None;
    for _ in 0..attempts.max(1) {
        sock.send_to(&message, introducer_addr).map_err(|e| err(format!("could not send PUNCH_REQUEST: {e}")))?;
        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; 1024];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            if sock.set_read_timeout(Some(remaining)).is_err() {
                break;
            }
            match sock.recv_from(&mut buf) {
                Ok((n, _src)) => match decode_punch_reply(&buf[..n], &client_ephemeral_private, &introducer_x25519_public, &nonce) {
                    Ok((status, addr)) => {
                        if status != STATUS_OK {
                            return Err(err(format!("introducer refused the punch (status {status})")));
                        }
                        return Ok(addr.expect("STATUS_OK always carries an address"));
                    }
                    Err(e) => {
                        last_error = Some(e.0);
                        continue;
                    }
                },
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => break,
                Err(e) => {
                    last_error = Some(e.to_string());
                    break;
                }
            }
        }
    }
    Err(err(format!(
        "no answer from introducer {}:{}: {}",
        introducer_addr.0,
        introducer_addr.1,
        last_error.unwrap_or_else(|| "timeout".to_string())
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn build_reachability(identity: &[u8], x25519_public: &[u8], host: &str, port: u16) -> Vec<u8> {
        let mut out = vec![MODE_NAT];
        out.extend_from_slice(identity);
        out.extend_from_slice(x25519_public);
        let host_bytes = host.as_bytes();
        out.push(host_bytes.len() as u8);
        out.extend_from_slice(host_bytes);
        out.extend_from_slice(&port.to_be_bytes());
        out
    }

    #[test]
    fn decode_reachability_round_trip() {
        let identity = [1u8; 32];
        let x25519_pub = [6u8; 32];
        let raw = build_reachability(&identity, &x25519_pub, "198.51.100.9", 9050);
        let decoded = decode_reachability(&raw).unwrap();
        assert_eq!(decoded.mode, MODE_NAT);
        assert_eq!(decoded.introducer_identity, identity.to_vec());
        assert_eq!(decoded.introducer_x25519_public, x25519_pub.to_vec());
        assert_eq!(decoded.introducer_addr(), ("198.51.100.9".to_string(), 9050));
    }

    #[test]
    fn decode_reachability_rejects_bad_mode_and_trailing_bytes() {
        let identity = [1u8; 32];
        let x25519_pub = [6u8; 32];
        let mut raw = build_reachability(&identity, &x25519_pub, "10.0.0.1", 1234);
        raw[0] = 9;
        assert!(decode_reachability(&raw).is_err());

        let mut raw2 = build_reachability(&identity, &x25519_pub, "10.0.0.1", 1234);
        raw2.push(0xFF);
        assert!(decode_reachability(&raw2).is_err());
    }

    #[test]
    fn is_nat_message_checks_magic_and_length() {
        assert!(is_nat_message(b"ALNTx"));
        assert!(!is_nat_message(b"ALNT"));
        assert!(!is_nat_message(b"XXXXx"));
    }

    #[test]
    fn punch_request_round_trip_nonce() {
        let target = [1u8; 32];
        let peer = [2u8; 32];
        let introducer_x25519_public = x25519_public(&[50u8; KEY_LEN]);
        let (msg, nonce, client_ephemeral_private) = encode_punch_request(&target, &peer, &introducer_x25519_public, None, None).unwrap();
        assert_eq!(nonce.len(), NONCE_LEN);
        assert!(msg.starts_with(NAT_MAGIC));
        assert_eq!(msg[4], PUNCH_REQUEST);
        assert_ne!(client_ephemeral_private, [0u8; KEY_LEN]);

        let fixed_nonce = [7u8; NONCE_LEN];
        let (msg2, nonce2, _priv2) = encode_punch_request(&target, &peer, &introducer_x25519_public, None, Some(fixed_nonce)).unwrap();
        assert_eq!(nonce2, fixed_nonce);
        assert!(msg2.len() == msg.len());
    }

    #[test]
    fn encode_punch_request_rejects_wrong_length_identities() {
        let introducer_x25519_public = x25519_public(&[50u8; KEY_LEN]);
        assert!(encode_punch_request(&[1, 2, 3], &[2u8; 32], &introducer_x25519_public, None, None).is_err());
    }

    /// Deliberately duplicated rather than calling `encode_punch_request`
    /// for the encrypt side -- opens the sealed request the way the
    /// introducer (`Relays::nat::decode_punch_request`) independently
    /// would, so a bug shared between `encode_punch_request` and
    /// `decode_punch_reply` (this module's own two halves) wouldn't be
    /// masked by only ever round-tripping through itself.
    #[test]
    fn encode_punch_request_can_be_opened_the_way_the_introducer_would() {
        let target = [1u8; 32];
        let peer = [2u8; 32];
        let introducer_x25519_private = [50u8; KEY_LEN];
        let introducer_x25519_public = x25519_public(&introducer_x25519_private);
        let (msg, nonce, client_ephemeral_private) = encode_punch_request(&target, &peer, &introducer_x25519_public, None, None).unwrap();

        let body = &msg[5..];
        assert_eq!(&body[..NONCE_LEN], &nonce);
        let client_ephemeral_public: [u8; KEY_LEN] = body[NONCE_LEN..NONCE_LEN + KEY_LEN].try_into().unwrap();
        assert_eq!(client_ephemeral_public, x25519_public(&client_ephemeral_private));
        let sealed = &body[NONCE_LEN + KEY_LEN..];

        let shared = x25519_dh(&introducer_x25519_private, &client_ephemeral_public).unwrap();
        let (request_key, _reply_key) = punch_session_keys(&shared).unwrap();
        let mut ad = nonce.to_vec();
        ad.extend_from_slice(&client_ephemeral_public);
        let aead = new_aead("chacha20-poly1305", &request_key, None).unwrap();
        let plaintext = aead.open(sealed, &ad).unwrap();
        assert_eq!(&plaintext[..KEY_LEN], &target);
        assert_eq!(&plaintext[KEY_LEN..], &peer);
    }

    /// Simulate the introducer's side of `encode_reply` -- deliberately
    /// hand-rolled rather than calling into `Relays`' `nat.rs` (this crate
    /// can't depend on it), so these tests exercise this module's wire
    /// format against an independent implementation of the same math.
    fn authority_seal_reply(introducer_x25519_private: &[u8; KEY_LEN], client_ephemeral_public: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], status: u8, addr: Option<(&str, u16)>) -> Vec<u8> {
        let shared = x25519_dh(introducer_x25519_private, client_ephemeral_public).unwrap();
        let (_request_key, reply_key) = punch_session_keys(&shared).unwrap();
        let (host, port) = addr.unwrap_or(("", 0));
        let host_bytes = host.as_bytes();
        let mut plaintext = vec![status];
        plaintext.push(host_bytes.len() as u8);
        plaintext.extend_from_slice(host_bytes);
        plaintext.extend_from_slice(&port.to_be_bytes());
        let mut aead = new_aead("chacha20-poly1305", &reply_key, None).unwrap();
        let sealed = aead.seal(&plaintext, nonce).unwrap();
        let mut out = header(PUNCH_REPLY);
        out.extend_from_slice(nonce);
        out.extend_from_slice(&sealed);
        out
    }

    #[test]
    fn decode_punch_reply_round_trip_ok_and_refused() {
        let introducer_x25519_private = [9u8; KEY_LEN];
        let introducer_x25519_public = x25519_public(&introducer_x25519_private);
        let client_ephemeral_private = [21u8; KEY_LEN];
        let client_ephemeral_public = x25519_public(&client_ephemeral_private);
        let nonce = [3u8; NONCE_LEN];

        let ok_wire = authority_seal_reply(&introducer_x25519_private, &client_ephemeral_public, &nonce, STATUS_OK, Some(("203.0.113.5", 4321)));
        let (status, addr) = decode_punch_reply(&ok_wire, &client_ephemeral_private, &introducer_x25519_public, &nonce).unwrap();
        assert_eq!(status, STATUS_OK);
        assert_eq!(addr, Some(("203.0.113.5".to_string(), 4321)));

        let refused_wire = authority_seal_reply(&introducer_x25519_private, &client_ephemeral_public, &nonce, 1, None);
        let (status2, addr2) = decode_punch_reply(&refused_wire, &client_ephemeral_private, &introducer_x25519_public, &nonce).unwrap();
        assert_eq!(status2, 1);
        assert_eq!(addr2, None);
    }

    #[test]
    fn decode_punch_reply_rejects_wrong_introducer_key_and_wrong_nonce() {
        let introducer_x25519_private = [9u8; KEY_LEN];
        let other_x25519_public = x25519_public(&[10u8; KEY_LEN]);
        let client_ephemeral_private = [21u8; KEY_LEN];
        let client_ephemeral_public = x25519_public(&client_ephemeral_private);
        let nonce = [3u8; NONCE_LEN];
        let wire = authority_seal_reply(&introducer_x25519_private, &client_ephemeral_public, &nonce, STATUS_OK, Some(("203.0.113.5", 4321)));

        // A reply sealed by one introducer key doesn't authenticate against
        // a different one -- the ECDH shared secret, and so the derived
        // AEAD key, differs.
        assert!(decode_punch_reply(&wire, &client_ephemeral_private, &other_x25519_public, &nonce).is_err());

        let introducer_x25519_public = x25519_public(&introducer_x25519_private);
        let wrong_nonce = [4u8; NONCE_LEN];
        assert!(decode_punch_reply(&wire, &client_ephemeral_private, &introducer_x25519_public, &wrong_nonce).is_err());
    }

    #[test]
    fn request_punch_end_to_end_over_loopback() {
        let introducer_x25519_private = [11u8; KEY_LEN];
        let introducer_x25519_public = x25519_public(&introducer_x25519_private);

        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let mut buf = [0u8; 1024];
            let (n, src) = server.recv_from(&mut buf).unwrap();
            assert!(is_nat_message(&buf[..n]));
            assert_eq!(buf[4], PUNCH_REQUEST);
            let nonce: [u8; NONCE_LEN] = buf[5..5 + NONCE_LEN].try_into().unwrap();
            let client_ephemeral_public: [u8; KEY_LEN] = buf[5 + NONCE_LEN..5 + NONCE_LEN + KEY_LEN].try_into().unwrap();
            let reply = authority_seal_reply(&introducer_x25519_private, &client_ephemeral_public, &nonce, STATUS_OK, Some(("198.51.100.42", 5555)));
            server.send_to(&reply, src).unwrap();
        });

        let target = [1u8; 32];
        let peer = [2u8; 32];
        let result = request_punch(("127.0.0.1", server_addr.port()), &introducer_x25519_public, &target, &peer, Duration::from_secs(2), 3).unwrap();
        assert_eq!(result, ("198.51.100.42".to_string(), 5555));
        handle.join().unwrap();
    }

    #[test]
    fn request_punch_times_out_with_no_responder() {
        // Bind a socket just to reserve an address that nothing is
        // listening on for replies, then drop it so nothing answers.
        let placeholder = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = placeholder.local_addr().unwrap();
        drop(placeholder);

        let introducer_x25519_public = x25519_public(&[12u8; KEY_LEN]);
        let result = request_punch(("127.0.0.1", addr.port()), &introducer_x25519_public, &[1u8; 32], &[2u8; 32], Duration::from_millis(100), 1);
        assert!(result.is_err());
    }
}
