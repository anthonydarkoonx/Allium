//! Wire framing for Allium's directory protocol.
//!
//! Port of Python's `dirwire.py`. See that module's docstring for the full
//! design rationale (rides an ordinary one-hop `circuit::CircuitBuilder`
//! circuit to the authority, framed as `fragment::Fragment` cells on a
//! reserved stream id, always fragmented even when a message would fit in
//! one cell).
//!
//! ## Hidden-service descriptor shapes
//!
//! Python's `dirwire.py` imports `ClientAuthEntry`/`HiddenServiceDescriptor`/
//! `IntroPoint` from `.hiddenservice`. **Updated once `hiddenservice.rs`
//! landed**: this module now imports the same three names from
//! [`crate::hiddenservice`] directly. They previously lived as local,
//! crypto-free stand-in structs defined right here (field-for-field
//! identical to Python's `NamedTuple`s), while `hiddenservice.rs` was still
//! Phase 4/not yet ported; that gap is closed now, the stand-ins are gone,
//! and this file's wire encode/decode logic needed no changes at all to
//! make the swap (it only ever touched these types' fields, never
//! signed/verified them -- that was always `hiddenservice.rs`'s job in both
//! languages, exactly as planned).
//!
//! The relay-descriptor half (`encode_descriptor`/`decode_descriptor`,
//! PUBLISH/FETCH framing) uses the real, already-ported
//! [`crate::directory::RelayDescriptor`] throughout -- no stand-in needed,
//! since `directory.rs` (Phase 3, earlier in this same batch) already
//! landed.

use crate::directory::{DESCRIPTOR_VERSION_1, DESCRIPTOR_VERSION_2, RelayDescriptor};
use crate::fragment::{FragmentError, Fragmenter, Reassembler, decode_fragment, encode_fragment};
use crate::hiddenservice::{BlindedDescriptor, ClientAuthEntry, HiddenServiceDescriptor, IntroPoint};
use std::fmt;

/// A directory-protocol message could not be encoded/decoded. Always what
/// this module raises on bad input -- never a raw index/parse panic -- so a
/// caller that must handle "the peer sent garbage" has exactly one
/// exception type to catch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirWireError {
    pub message: String,
}
impl fmt::Display for DirWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for DirWireError {}
fn err(msg: impl Into<String>) -> DirWireError {
    DirWireError { message: msg.into() }
}

/// Unchanging prefix on every directory-protocol message (after
/// reassembly). Distinct from `socks::MAGIC` (`ALSM`)/`DATAGRAM_MAGIC`
/// (`ALDG`) and `hswire::HS_MAGIC` (`ALHS`).
pub const DIR_MAGIC: &[u8; 4] = b"ALDR";

/// Fragment stream id reserved for directory-protocol traffic.
pub const DIR_STREAM_ID: u32 = 0;

pub const PUBLISH_REQUEST: u8 = 1;
pub const PUBLISH_REPLY: u8 = 2;
pub const FETCH_REQUEST: u8 = 3;
pub const FETCH_REPLY: u8 = 4;
pub const HS_PUBLISH_REQUEST: u8 = 5;
pub const HS_PUBLISH_REPLY: u8 = 6;
pub const HS_FETCH_REQUEST: u8 = 7;
pub const HS_FETCH_REPLY: u8 = 8;
/// A FETCH from a client that understands v2 descriptors. Answered with an
/// ordinary FETCH_REPLY that may contain v2 descriptors. A plain
/// FETCH_REQUEST (what every pre-v2 client sends) is answered with the v1
/// descriptors only.
pub const FETCH_REQUEST_V2: u8 = 9;
/// Version 3 hidden-service messages (blinded key, encrypted descriptor). New
/// types rather than a flag on the old ones, so there is never doubt which
/// kind of descriptor a message carries. The version 2 types (5-8) are no
/// longer served: a v2 descriptor carries the service's identity in the clear.
/// (Numbered from 20: types 10 and 11 are the consensus `VOTE_REQUEST` /
/// `VOTE_REPLY`, which share this `ALDR` message namespace; an earlier numbering
/// of 10 to 13 made the authority answer a publish with a signed vote.)
pub const HS3_PUBLISH_REQUEST: u8 = 20;
pub const HS3_PUBLISH_REPLY: u8 = 21;
pub const HS3_FETCH_REQUEST: u8 = 22;
pub const HS3_FETCH_REPLY: u8 = 23;

const ROLES_LEN_V2_FLAG: u16 = 0x8000;
const MAX_EXTENSION_COUNT: usize = 16;
const MAX_EXTENSION_VALUE_LEN: usize = 2048;

const MAX_HOST_LEN: usize = 255;
const MAX_ROLES_LEN: usize = 128;
const MAX_MESSAGE_LEN: usize = 255;
/// The most descriptors one FETCH_REPLY can carry. Also the default for
/// `Directory`'s `max_descriptors`, so an authority's live set can always
/// be served in full -- see `Directory::serving_set` for what happens if
/// an operator raises the cap past this.
pub const MAX_DESCRIPTOR_COUNT: usize = 4096;
const MAX_INTRO_POINT_COUNT: usize = 32;
const X25519_KEY_LEN: usize = 32;
const CLIENT_ID_HINT_LEN: usize = 16;
const MAX_CLIENT_AUTH_COUNT: usize = 64;
const MAX_WRAPPED_KEY_LEN: usize = 4096;
const MAX_ENCRYPTED_INTRO_POINTS_LEN: usize = 65535;

const ED25519_KEY_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;
/// identity_public + static_public + host_len(2) + port(2) + roles_len(2).
const DESCRIPTOR_HEADER_LEN: usize = ED25519_KEY_LEN * 2 + 2 + 2 + 2;
/// not_before(8) + not_after(8) + signature(64).
const DESCRIPTOR_TRAILER_LEN: usize = 8 + 8 + ED25519_SIG_LEN;
/// 4-byte magic + 1-byte message type.
const MESSAGE_HEADER_LEN: usize = 5;

/// Upper bound on one complete reassembled directory-protocol message,
/// enforced by [`DirReassembler::push`].
///
/// Without this, `DirReassembler`/`HsReassembler` accumulated every
/// reassembled byte into an ever-growing `Vec<u8>` with no cap at all: a
/// peer could open one directory circuit and stream an unbounded sequence
/// of small, in-order `Fragment` cells without ever setting FIN, since
/// size limits (e.g. `MAX_DESCRIPTOR_COUNT`) were only checked once a
/// message was declared *complete* -- which the peer could simply never
/// trigger. That is a pre-authentication remote memory-exhaustion DoS,
/// most severe here since this is the directory authority itself
/// (mirrors the identical fix in
/// `Relays/allium/src/dirwire.rs`).
///
/// This bound is not a guessed round number: it is this module's own
/// worst case, computed from the constants above -- a FETCH_REPLY
/// carrying `MAX_DESCRIPTOR_COUNT` descriptors, each at its own maximum
/// encoded size (host + roles + every extension at
/// `MAX_EXTENSION_VALUE_LEN`), plus message/count/length-prefix framing.
/// Any wire-valid message is guaranteed to fit; anything larger cannot be
/// a real message and is rejected as soon as it's seen, not just once
/// "complete".
const MAX_REASSEMBLED_LEN: usize = MESSAGE_HEADER_LEN
    + 2 // descriptor count (u16)
    + MAX_DESCRIPTOR_COUNT
        * (2 // per-descriptor length prefix (u16)
            + DESCRIPTOR_HEADER_LEN
            + MAX_HOST_LEN
            + MAX_ROLES_LEN
            + DESCRIPTOR_TRAILER_LEN
            + 1 // extension count byte
            + MAX_EXTENSION_COUNT * (1 + 2 + MAX_EXTENSION_VALUE_LEN));

/// Salt in a blinded descriptor (must match the Client's `hsblind::SALT_LEN`).
pub const BLINDED_SALT_LEN: usize = 32;
/// AEAD nonce + tag added by sealing (must match the Client's
/// `crypto::SEAL_OVERHEAD`: 12-byte nonce + 16-byte tag).
const BLINDED_SEAL_OVERHEAD: usize = 12 + 16;
/// The largest wire-valid *inner* (decrypted) descriptor: a client-authorized
/// descriptor with every field at its maximum. The authority never sees it
/// decrypted; it only bounds how large a sealed one can be.
const MAX_INNER_DESCRIPTOR_LEN: usize = (ED25519_KEY_LEN + X25519_KEY_LEN + 1) // identity, encryption key, flags byte
    + 2 + MAX_ENCRYPTED_INTRO_POINTS_LEN      // intro-points length + blob
    + X25519_KEY_LEN                          // auth ephemeral public
    + 2                                       // client-auth count
    + MAX_CLIENT_AUTH_COUNT * (CLIENT_ID_HINT_LEN + 2 + MAX_WRAPPED_KEY_LEN)
    + 8 + 8 + ED25519_SIG_LEN;                // not_before, not_after, signature
/// The most ciphertext a blinded descriptor may carry.
pub const MAX_BLINDED_CIPHERTEXT_LEN: usize = MAX_INNER_DESCRIPTOR_LEN + BLINDED_SEAL_OVERHEAD;
/// blinded_public(32) + period(8) + not_before(8) + not_after(8) + salt(32) + ciphertext length(4).
const BLINDED_FIXED_LEN: usize = 32 + 8 + 8 + 8 + BLINDED_SALT_LEN + 4;
/// The largest wire-valid version 3 publish request.
const MAX_HS3_PUBLISH_LEN: usize = MESSAGE_HEADER_LEN + BLINDED_FIXED_LEN + MAX_BLINDED_CIPHERTEXT_LEN + ED25519_SIG_LEN;
/// The largest wire-valid version 2 publish request (no longer served, but
/// still decoded far enough to refuse politely).
const MAX_HS2_PUBLISH_LEN: usize = MESSAGE_HEADER_LEN + MAX_INNER_DESCRIPTOR_LEN;

/// Upper bound on one complete *request* a directory authority receives
/// (`PUBLISH`, `HS_PUBLISH`, `HS3_PUBLISH`, `FETCH`, `VOTE_REQUEST`, `HS_FETCH`,
/// `HS3_FETCH`, NAT registration), enforced by [`DirReassembler::push_limited`].
///
/// [`MAX_REASSEMBLED_LEN`] is sized for the largest *reply* (4096
/// descriptors, about 137 MB) and is right for a client reading one. An
/// authority never legitimately receives anything near that, yet it keeps
/// up to 256 reassemblers, so using it for requests let one unauthenticated
/// peer pin hundreds of MB per circuit.
///
/// Derived the same way as [`MAX_REASSEMBLED_LEN`], from this module's own
/// constants: the largest wire-valid request is a version 3 hidden-service
/// publish whose ciphertext is a sealed, client-authorized descriptor at its
/// maximum. Every wire-valid request fits.
pub const MAX_REQUEST_REASSEMBLED_LEN: usize = if MAX_HS3_PUBLISH_LEN > MAX_HS2_PUBLISH_LEN { MAX_HS3_PUBLISH_LEN } else { MAX_HS2_PUBLISH_LEN };

// ---------------------------------------------------------------------------
// Relay descriptors
// ---------------------------------------------------------------------------

/// Serialize a [`RelayDescriptor`] for the wire.
pub fn encode_descriptor(d: &RelayDescriptor) -> Result<Vec<u8>, DirWireError> {
    let host = d.host.as_bytes();
    if host.len() > MAX_HOST_LEN {
        return Err(err(format!("host is {} bytes, max is {MAX_HOST_LEN}", host.len())));
    }
    let mut roles: Vec<&str> = d.roles.iter().map(|s| s.as_str()).collect();
    roles.sort_unstable();
    let roles_str = roles.join(",");
    let roles_bytes = roles_str.as_bytes();
    if roles_bytes.len() > MAX_ROLES_LEN {
        return Err(err(format!("roles is {} bytes, max is {MAX_ROLES_LEN}", roles_bytes.len())));
    }
    if d.identity_public.len() != ED25519_KEY_LEN {
        return Err(err(format!("identity_public must be {ED25519_KEY_LEN} bytes")));
    }
    if d.static_public.len() != ED25519_KEY_LEN {
        return Err(err(format!("static_public must be {ED25519_KEY_LEN} bytes")));
    }
    if d.signature.len() != ED25519_SIG_LEN {
        return Err(err(format!("signature must be {ED25519_SIG_LEN} bytes")));
    }
    if d.version == DESCRIPTOR_VERSION_2 {
        if d.extensions.len() > MAX_EXTENSION_COUNT {
            return Err(err(format!("at most {MAX_EXTENSION_COUNT} extensions")));
        }
        let mut ext_bytes = vec![d.extensions.len() as u8];
        for (ext_type, value) in &d.extensions {
            if value.len() > MAX_EXTENSION_VALUE_LEN {
                return Err(err(format!("extension {ext_type} out of bounds")));
            }
            ext_bytes.push(*ext_type);
            ext_bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
            ext_bytes.extend_from_slice(value);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&d.identity_public);
        out.extend_from_slice(&d.static_public);
        out.extend_from_slice(&(host.len() as u16).to_be_bytes());
        out.extend_from_slice(&d.port.to_be_bytes());
        out.extend_from_slice(&((roles_bytes.len() as u16) | ROLES_LEN_V2_FLAG).to_be_bytes());
        out.extend_from_slice(host);
        out.extend_from_slice(roles_bytes);
        out.extend_from_slice(&d.not_before.to_be_bytes());
        out.extend_from_slice(&d.not_after.to_be_bytes());
        out.extend_from_slice(&ext_bytes);
        out.extend_from_slice(&d.signature);
        return Ok(out);
    }
    if d.version != DESCRIPTOR_VERSION_1 {
        return Err(err(format!("unknown descriptor version {}", d.version)));
    }
    let mut out = Vec::new();
    out.extend_from_slice(&d.identity_public);
    out.extend_from_slice(&d.static_public);
    out.extend_from_slice(&(host.len() as u16).to_be_bytes());
    out.extend_from_slice(&d.port.to_be_bytes());
    out.extend_from_slice(&(roles_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(host);
    out.extend_from_slice(roles_bytes);
    out.extend_from_slice(&d.not_before.to_be_bytes());
    out.extend_from_slice(&d.not_after.to_be_bytes());
    out.extend_from_slice(&d.signature);
    Ok(out)
}

/// Parse one descriptor from the front of `data`. Returns `(descriptor,
/// consumed)`. The descriptor's self-signature is **not** verified here --
/// that is [`RelayDescriptor::verify`]'s job.
pub fn decode_descriptor(data: &[u8]) -> Result<(RelayDescriptor, usize), DirWireError> {
    if data.len() < DESCRIPTOR_HEADER_LEN {
        return Err(err("descriptor truncated before its fixed header"));
    }
    let identity_public: [u8; ED25519_KEY_LEN] = data[..ED25519_KEY_LEN].try_into().unwrap();
    let static_public: [u8; ED25519_KEY_LEN] = data[ED25519_KEY_LEN..ED25519_KEY_LEN * 2].try_into().unwrap();
    let mut offset = ED25519_KEY_LEN * 2;
    let host_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    let port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
    let mut roles_len = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
    offset += 6;
    let mut version = DESCRIPTOR_VERSION_1;
    if roles_len & ROLES_LEN_V2_FLAG != 0 {
        version = DESCRIPTOR_VERSION_2;
        roles_len &= !ROLES_LEN_V2_FLAG;
    }
    let roles_len = roles_len as usize;
    if host_len > MAX_HOST_LEN {
        return Err(err(format!("descriptor host_len {host_len} exceeds max {MAX_HOST_LEN}")));
    }
    if roles_len > MAX_ROLES_LEN {
        return Err(err(format!("descriptor roles_len {roles_len} exceeds max {MAX_ROLES_LEN}")));
    }
    let needed = offset + host_len + roles_len + DESCRIPTOR_TRAILER_LEN;
    if data.len() < needed {
        return Err(err("descriptor truncated before its variable fields"));
    }
    let host = std::str::from_utf8(&data[offset..offset + host_len])
        .map_err(|_| err("descriptor host is not valid UTF-8"))?
        .to_string();
    offset += host_len;
    let roles_bytes = &data[offset..offset + roles_len];
    offset += roles_len;
    if !roles_bytes.is_ascii() {
        return Err(err("descriptor roles field is not valid ASCII"));
    }
    let roles_str = std::str::from_utf8(roles_bytes).map_err(|_| err("descriptor roles field is not valid ASCII"))?;
    let roles: Vec<String> = roles_str.split(',').filter(|r| !r.is_empty()).map(|s| s.to_string()).collect();
    let not_before = f64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
    let not_after = f64::from_be_bytes(data[offset + 8..offset + 16].try_into().unwrap());
    offset += 16;
    let mut extensions: Vec<(u8, Vec<u8>)> = Vec::new();
    if version == DESCRIPTOR_VERSION_2 {
        if data.len() < offset + 1 {
            return Err(err("v2 descriptor truncated before its extension count"));
        }
        let count = data[offset] as usize;
        offset += 1;
        if count > MAX_EXTENSION_COUNT {
            return Err(err(format!("v2 descriptor claims {count} extensions, max {MAX_EXTENSION_COUNT}")));
        }
        for _ in 0..count {
            if data.len() < offset + 3 {
                return Err(err("v2 descriptor truncated inside an extension header"));
            }
            let ext_type = data[offset];
            let ext_len = u16::from_be_bytes([data[offset + 1], data[offset + 2]]) as usize;
            offset += 3;
            if ext_len > MAX_EXTENSION_VALUE_LEN {
                return Err(err(format!("extension {ext_type} is {ext_len} bytes, too long")));
            }
            if data.len() < offset + ext_len {
                return Err(err("v2 descriptor truncated inside an extension value"));
            }
            extensions.push((ext_type, data[offset..offset + ext_len].to_vec()));
            offset += ext_len;
        }
        if data.len() < offset + ED25519_SIG_LEN {
            return Err(err("v2 descriptor truncated before its signature"));
        }
    }
    let signature = data[offset..offset + ED25519_SIG_LEN].to_vec();
    offset += ED25519_SIG_LEN;
    let descriptor = RelayDescriptor {
        identity_public,
        static_public,
        host,
        port,
        roles,
        not_before,
        not_after,
        signature,
        version,
        extensions,
    };
    Ok((descriptor, offset))
}

fn expect(data: &[u8], expected_type: u8, label: &str) -> Result<(), DirWireError> {
    if !data.starts_with(DIR_MAGIC) {
        return Err(err(format!("bad directory magic in {label}")));
    }
    if data.len() < MESSAGE_HEADER_LEN {
        return Err(err(format!("{label} shorter than the message header")));
    }
    if data[4] != expected_type {
        return Err(err(format!("{label}: expected message type {expected_type}, got {}", data[4])));
    }
    Ok(())
}

/// A relay's PUBLISH request: its own signed descriptor.
pub fn encode_publish_request(descriptor: &RelayDescriptor) -> Result<Vec<u8>, DirWireError> {
    let mut out = DIR_MAGIC.to_vec();
    out.push(PUBLISH_REQUEST);
    out.extend_from_slice(&encode_descriptor(descriptor)?);
    Ok(out)
}

pub fn decode_publish_request(data: &[u8]) -> Result<RelayDescriptor, DirWireError> {
    expect(data, PUBLISH_REQUEST, "publish request")?;
    let (descriptor, _consumed) = decode_descriptor(&data[MESSAGE_HEADER_LEN..])?;
    Ok(descriptor)
}

/// The authority's answer to a PUBLISH: accepted or not, plus why.
pub fn encode_publish_reply(ok: bool, message: &str) -> Vec<u8> {
    let mut body = message.as_bytes().to_vec();
    body.truncate(MAX_MESSAGE_LEN);
    let mut out = DIR_MAGIC.to_vec();
    out.push(PUBLISH_REPLY);
    out.push(if ok { 1 } else { 0 });
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    out
}

pub fn decode_publish_reply(data: &[u8]) -> Result<(bool, String), DirWireError> {
    expect(data, PUBLISH_REPLY, "publish reply")?;
    if data.len() < MESSAGE_HEADER_LEN + 2 {
        return Err(err("publish reply truncated before its status/length"));
    }
    let ok = data[5] == 1;
    let msg_len = data[6] as usize;
    if data.len() < MESSAGE_HEADER_LEN + 2 + msg_len {
        return Err(err("publish reply message truncated"));
    }
    let message = String::from_utf8_lossy(&data[7..7 + msg_len]).into_owned();
    Ok((ok, message))
}

/// A FETCH request: no body, just "send me the current live set". `version
/// == DESCRIPTOR_VERSION_2` (default) asks for every descriptor including
/// v2 ones; `DESCRIPTOR_VERSION_1` is the legacy request an older client
/// sends.
pub fn encode_fetch_request(version: u32) -> Vec<u8> {
    let mut out = DIR_MAGIC.to_vec();
    out.push(if version == DESCRIPTOR_VERSION_1 { FETCH_REQUEST } else { FETCH_REQUEST_V2 });
    out
}

/// [`encode_fetch_request`] with `DESCRIPTOR_VERSION_2` (Python's default
/// argument).
pub fn encode_fetch_request_default() -> Vec<u8> {
    encode_fetch_request(DESCRIPTOR_VERSION_2)
}

/// Validate a FETCH request frame, returning the descriptor version the
/// requester understands (1 or 2).
pub fn decode_fetch_request(data: &[u8]) -> Result<u32, DirWireError> {
    if data.starts_with(DIR_MAGIC) && data.len() >= MESSAGE_HEADER_LEN && data[4] == FETCH_REQUEST_V2 {
        return Ok(DESCRIPTOR_VERSION_2);
    }
    expect(data, FETCH_REQUEST, "fetch request")?;
    Ok(DESCRIPTOR_VERSION_1)
}

/// The authority's answer to a FETCH: every live descriptor it holds.
pub fn encode_fetch_reply(descriptors: &[RelayDescriptor]) -> Result<Vec<u8>, DirWireError> {
    if descriptors.len() > MAX_DESCRIPTOR_COUNT {
        return Err(err(format!("cannot encode {} descriptors in one reply (max {MAX_DESCRIPTOR_COUNT})", descriptors.len())));
    }
    let mut out = DIR_MAGIC.to_vec();
    out.push(FETCH_REPLY);
    out.extend_from_slice(&(descriptors.len() as u16).to_be_bytes());
    for d in descriptors {
        let encoded = encode_descriptor(d)?;
        out.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
        out.extend_from_slice(&encoded);
    }
    Ok(out)
}

/// Parse a FETCH reply into its list of descriptors. Every entry is parsed
/// with [`decode_descriptor`] (wire-shape only -- signatures are not
/// checked here); a caller should run each result through
/// `Directory::publish` to actually verify and use it.
pub fn decode_fetch_reply(data: &[u8]) -> Result<Vec<RelayDescriptor>, DirWireError> {
    expect(data, FETCH_REPLY, "fetch reply")?;
    if data.len() < MESSAGE_HEADER_LEN + 2 {
        return Err(err("fetch reply truncated before its descriptor count"));
    }
    let count = u16::from_be_bytes([data[5], data[6]]) as usize;
    if count > MAX_DESCRIPTOR_COUNT {
        return Err(err(format!("fetch reply claims {count} descriptors, max is {MAX_DESCRIPTOR_COUNT}")));
    }
    let mut offset = 7;
    let mut descriptors = Vec::with_capacity(count);
    for _ in 0..count {
        if data.len() < offset + 2 {
            return Err(err("fetch reply truncated before a descriptor length"));
        }
        let desc_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if data.len() < offset + desc_len {
            return Err(err("fetch reply truncated inside a descriptor"));
        }
        let (descriptor, consumed) = decode_descriptor(&data[offset..offset + desc_len])?;
        if consumed != desc_len {
            return Err(err("fetch reply descriptor length field did not match its content"));
        }
        descriptors.push(descriptor);
        offset += desc_len;
    }
    Ok(descriptors)
}

// ---------------------------------------------------------------------------
// Hidden-service descriptors: published to and fetched from the same
// authority, over the same one-hop directory circuit, as the relay
// descriptors above. FETCH here is deliberately by-address only (no "list
// every hidden service" operation, unlike relay FETCH's whole-live-set
// reply). `IntroPoint`/`ClientAuthEntry`/`HiddenServiceDescriptor` are
// imported from `crate::hiddenservice` -- see the module docs above.
// ---------------------------------------------------------------------------

const HS_FLAG_PLAIN: u8 = 0x00;
const HS_FLAG_CLIENT_AUTH: u8 = 0x01;
/// Bit of the flag byte that carries `hs_handshake_v2` -- see the matching
/// constant in the Client crate's `dirwire.rs` for why this is a bit on the
/// existing flag byte rather than a new field in the wire layout.
const HS_FLAG_HANDSHAKE_V2: u8 = 0x02;

fn encode_intro_points_wire(intro_points: &[IntroPoint]) -> Result<Vec<u8>, DirWireError> {
    if intro_points.len() > MAX_INTRO_POINT_COUNT {
        return Err(err(format!("{} intro points exceeds max {MAX_INTRO_POINT_COUNT}", intro_points.len())));
    }
    let mut out = (intro_points.len() as u16).to_be_bytes().to_vec();
    for ip in intro_points {
        if ip.relay_identity.len() != ED25519_KEY_LEN {
            return Err(err(format!("intro point relay_identity must be {ED25519_KEY_LEN} bytes")));
        }
        if ip.auth_public.len() != ED25519_KEY_LEN {
            return Err(err(format!("intro point auth_public must be {ED25519_KEY_LEN} bytes")));
        }
        let host = ip.host.as_bytes();
        if host.len() > MAX_HOST_LEN {
            return Err(err(format!("intro point host is {} bytes, max is {MAX_HOST_LEN}", host.len())));
        }
        out.extend_from_slice(&ip.relay_identity);
        out.extend_from_slice(&(host.len() as u16).to_be_bytes());
        out.extend_from_slice(host);
        out.extend_from_slice(&ip.port.to_be_bytes());
        out.extend_from_slice(&ip.auth_public);
    }
    Ok(out)
}

/// Serialize a [`HiddenServiceDescriptor`].
pub fn encode_hs_descriptor(d: &HiddenServiceDescriptor) -> Result<Vec<u8>, DirWireError> {
    if d.identity_public.len() != ED25519_KEY_LEN {
        return Err(err(format!("identity_public must be {ED25519_KEY_LEN} bytes")));
    }
    if d.encryption_public.len() != X25519_KEY_LEN {
        return Err(err(format!("encryption_public must be {X25519_KEY_LEN} bytes")));
    }
    if d.signature.len() != ED25519_SIG_LEN {
        return Err(err(format!("signature must be {ED25519_SIG_LEN} bytes")));
    }

    let mut out = d.identity_public.clone();
    out.extend_from_slice(&d.encryption_public);

    if !d.client_auth.is_empty() {
        if d.auth_ephemeral_public.len() != X25519_KEY_LEN {
            return Err(err(format!("auth_ephemeral_public must be {X25519_KEY_LEN} bytes")));
        }
        if d.encrypted_intro_points.len() > MAX_ENCRYPTED_INTRO_POINTS_LEN {
            return Err(err(format!(
                "encrypted_intro_points is {} bytes, max is {MAX_ENCRYPTED_INTRO_POINTS_LEN}",
                d.encrypted_intro_points.len()
            )));
        }
        if d.client_auth.len() > MAX_CLIENT_AUTH_COUNT {
            return Err(err(format!("{} authorized clients exceeds max {MAX_CLIENT_AUTH_COUNT}", d.client_auth.len())));
        }
        out.push(HS_FLAG_CLIENT_AUTH | if d.hs_handshake_v2 { HS_FLAG_HANDSHAKE_V2 } else { 0 });
        out.extend_from_slice(&(d.encrypted_intro_points.len() as u16).to_be_bytes());
        out.extend_from_slice(&d.encrypted_intro_points);
        out.extend_from_slice(&d.auth_ephemeral_public);
        out.extend_from_slice(&(d.client_auth.len() as u16).to_be_bytes());
        for entry in &d.client_auth {
            if entry.client_id_hint.len() != CLIENT_ID_HINT_LEN {
                return Err(err(format!("client_id_hint must be {CLIENT_ID_HINT_LEN} bytes")));
            }
            if entry.wrapped_key.len() > MAX_WRAPPED_KEY_LEN {
                return Err(err(format!("wrapped_key is {} bytes, max is {MAX_WRAPPED_KEY_LEN}", entry.wrapped_key.len())));
            }
            out.extend_from_slice(&entry.client_id_hint);
            out.extend_from_slice(&(entry.wrapped_key.len() as u16).to_be_bytes());
            out.extend_from_slice(&entry.wrapped_key);
        }
    } else {
        out.push(HS_FLAG_PLAIN | if d.hs_handshake_v2 { HS_FLAG_HANDSHAKE_V2 } else { 0 });
        out.extend_from_slice(&encode_intro_points_wire(&d.intro_points)?);
    }

    out.extend_from_slice(&d.not_before.to_be_bytes());
    out.extend_from_slice(&d.not_after.to_be_bytes());
    out.extend_from_slice(&d.signature);
    Ok(out)
}

/// Parse one HS descriptor from the front of `data`. Returns `(descriptor,
/// consumed)`.
pub fn decode_hs_descriptor(data: &[u8]) -> Result<(HiddenServiceDescriptor, usize), DirWireError> {
    let header_len = ED25519_KEY_LEN + X25519_KEY_LEN + 1;
    if data.len() < header_len {
        return Err(err("hs descriptor truncated before its fixed header"));
    }
    let identity_public = data[..ED25519_KEY_LEN].to_vec();
    let encryption_public = data[ED25519_KEY_LEN..ED25519_KEY_LEN + X25519_KEY_LEN].to_vec();
    let mut offset = ED25519_KEY_LEN + X25519_KEY_LEN;
    let flag = data[offset];
    let hs_handshake_v2 = flag & HS_FLAG_HANDSHAKE_V2 != 0;
    let flag = flag & !HS_FLAG_HANDSHAKE_V2;
    offset += 1;

    let mut intro_points: Vec<IntroPoint> = Vec::new();
    let mut encrypted_intro_points: Vec<u8> = Vec::new();
    let mut auth_ephemeral_public: Vec<u8> = Vec::new();
    let mut client_auth: Vec<ClientAuthEntry> = Vec::new();

    if flag == HS_FLAG_PLAIN {
        if data.len() < offset + 2 {
            return Err(err("hs descriptor truncated before its intro point count"));
        }
        let intro_count = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if intro_count > MAX_INTRO_POINT_COUNT {
            return Err(err(format!("hs descriptor claims {intro_count} intro points, max is {MAX_INTRO_POINT_COUNT}")));
        }
        for _ in 0..intro_count {
            if data.len() < offset + ED25519_KEY_LEN + 2 {
                return Err(err("hs descriptor truncated inside an intro point"));
            }
            let relay_identity = data[offset..offset + ED25519_KEY_LEN].to_vec();
            offset += ED25519_KEY_LEN;
            let host_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            if host_len > MAX_HOST_LEN || data.len() < offset + host_len + 2 {
                return Err(err("hs descriptor intro point truncated or oversized"));
            }
            let host = std::str::from_utf8(&data[offset..offset + host_len])
                .map_err(|_| err("hs descriptor intro point host is not valid UTF-8"))?
                .to_string();
            offset += host_len;
            let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            if data.len() < offset + ED25519_KEY_LEN {
                return Err(err("hs descriptor truncated inside an intro point's auth key"));
            }
            let auth_public = data[offset..offset + ED25519_KEY_LEN].to_vec();
            offset += ED25519_KEY_LEN;
            intro_points.push(IntroPoint { relay_identity, host, port, auth_public });
        }
    } else if flag == HS_FLAG_CLIENT_AUTH {
        if data.len() < offset + 2 {
            return Err(err("hs descriptor truncated before its encrypted intro point length"));
        }
        let encrypted_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if encrypted_len > MAX_ENCRYPTED_INTRO_POINTS_LEN || data.len() < offset + encrypted_len {
            return Err(err("hs descriptor encrypted intro points truncated or oversized"));
        }
        encrypted_intro_points = data[offset..offset + encrypted_len].to_vec();
        offset += encrypted_len;
        if data.len() < offset + X25519_KEY_LEN {
            return Err(err("hs descriptor truncated before its auth ephemeral key"));
        }
        auth_ephemeral_public = data[offset..offset + X25519_KEY_LEN].to_vec();
        offset += X25519_KEY_LEN;
        if data.len() < offset + 2 {
            return Err(err("hs descriptor truncated before its client-auth count"));
        }
        let auth_count = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if auth_count > MAX_CLIENT_AUTH_COUNT {
            return Err(err(format!("hs descriptor claims {auth_count} authorized clients, max is {MAX_CLIENT_AUTH_COUNT}")));
        }
        for _ in 0..auth_count {
            if data.len() < offset + CLIENT_ID_HINT_LEN + 2 {
                return Err(err("hs descriptor truncated inside a client-auth entry"));
            }
            let client_id_hint = data[offset..offset + CLIENT_ID_HINT_LEN].to_vec();
            offset += CLIENT_ID_HINT_LEN;
            let wrapped_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            if wrapped_len > MAX_WRAPPED_KEY_LEN || data.len() < offset + wrapped_len {
                return Err(err("hs descriptor client-auth entry truncated or oversized"));
            }
            let wrapped_key = data[offset..offset + wrapped_len].to_vec();
            offset += wrapped_len;
            client_auth.push(ClientAuthEntry { client_id_hint, wrapped_key });
        }
    } else {
        return Err(err(format!("hs descriptor has an unknown flag byte {flag:?}")));
    }

    let trailer_len = 8 + 8 + ED25519_SIG_LEN;
    if data.len() < offset + trailer_len {
        return Err(err("hs descriptor truncated before its trailer"));
    }
    let not_before = f64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
    let not_after = f64::from_be_bytes(data[offset + 8..offset + 16].try_into().unwrap());
    offset += 16;
    let signature = data[offset..offset + ED25519_SIG_LEN].to_vec();
    offset += ED25519_SIG_LEN;

    let descriptor = HiddenServiceDescriptor {
        identity_public,
        encryption_public,
        intro_points,
        not_before,
        not_after,
        signature,
        encrypted_intro_points,
        auth_ephemeral_public,
        client_auth,
        hs_handshake_v2,
    };
    Ok((descriptor, offset))
}

/// A service's PUBLISH request: its own signed HS descriptor.
pub fn encode_hs_publish_request(descriptor: &HiddenServiceDescriptor) -> Result<Vec<u8>, DirWireError> {
    let mut out = DIR_MAGIC.to_vec();
    out.push(HS_PUBLISH_REQUEST);
    out.extend_from_slice(&encode_hs_descriptor(descriptor)?);
    Ok(out)
}

pub fn decode_hs_publish_request(data: &[u8]) -> Result<HiddenServiceDescriptor, DirWireError> {
    expect(data, HS_PUBLISH_REQUEST, "hs publish request")?;
    let (descriptor, _consumed) = decode_hs_descriptor(&data[MESSAGE_HEADER_LEN..])?;
    Ok(descriptor)
}

pub fn encode_hs_publish_reply(ok: bool, message: &str) -> Vec<u8> {
    let mut body = message.as_bytes().to_vec();
    body.truncate(MAX_MESSAGE_LEN);
    let mut out = DIR_MAGIC.to_vec();
    out.push(HS_PUBLISH_REPLY);
    out.push(if ok { 1 } else { 0 });
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    out
}

pub fn decode_hs_publish_reply(data: &[u8]) -> Result<(bool, String), DirWireError> {
    expect(data, HS_PUBLISH_REPLY, "hs publish reply")?;
    if data.len() < MESSAGE_HEADER_LEN + 2 {
        return Err(err("hs publish reply truncated before its status/length"));
    }
    let ok = data[5] == 1;
    let msg_len = data[6] as usize;
    if data.len() < MESSAGE_HEADER_LEN + 2 + msg_len {
        return Err(err("hs publish reply message truncated"));
    }
    let message = String::from_utf8_lossy(&data[7..7 + msg_len]).into_owned();
    Ok((ok, message))
}

/// A FETCH request for one specific service, by its 32-byte identity key.
pub fn encode_hs_fetch_request(address_identity: &[u8]) -> Result<Vec<u8>, DirWireError> {
    if address_identity.len() != ED25519_KEY_LEN {
        return Err(err(format!("address_identity must be {ED25519_KEY_LEN} bytes")));
    }
    let mut out = DIR_MAGIC.to_vec();
    out.push(HS_FETCH_REQUEST);
    out.extend_from_slice(address_identity);
    Ok(out)
}

/// Returns the requested 32-byte identity key.
pub fn decode_hs_fetch_request(data: &[u8]) -> Result<Vec<u8>, DirWireError> {
    expect(data, HS_FETCH_REQUEST, "hs fetch request")?;
    if data.len() < MESSAGE_HEADER_LEN + ED25519_KEY_LEN {
        return Err(err("hs fetch request truncated"));
    }
    Ok(data[MESSAGE_HEADER_LEN..MESSAGE_HEADER_LEN + ED25519_KEY_LEN].to_vec())
}

/// The authority's answer: the descriptor if it has a live one, else
/// `None` -- carried as a found flag rather than an error.
pub fn encode_hs_fetch_reply(descriptor: Option<&HiddenServiceDescriptor>) -> Result<Vec<u8>, DirWireError> {
    match descriptor {
        None => {
            let mut out = DIR_MAGIC.to_vec();
            out.push(HS_FETCH_REPLY);
            out.push(0);
            Ok(out)
        }
        Some(d) => {
            let encoded = encode_hs_descriptor(d)?;
            let mut out = DIR_MAGIC.to_vec();
            out.push(HS_FETCH_REPLY);
            out.push(1);
            out.extend_from_slice(&encoded);
            Ok(out)
        }
    }
}

pub fn decode_hs_fetch_reply(data: &[u8]) -> Result<Option<HiddenServiceDescriptor>, DirWireError> {
    expect(data, HS_FETCH_REPLY, "hs fetch reply")?;
    if data.len() < MESSAGE_HEADER_LEN + 1 {
        return Err(err("hs fetch reply truncated before its found flag"));
    }
    if data[5] == 0 {
        return Ok(None);
    }
    let (descriptor, _consumed) = decode_hs_descriptor(&data[MESSAGE_HEADER_LEN + 1..])?;
    Ok(Some(descriptor))
}

// ---------------------------------------------------------------------------
// Fragmentation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Version 3 hidden-service descriptors (blinded key, encrypted body)
// ---------------------------------------------------------------------------

/// Serialize a [`BlindedDescriptor`]: `blinded_public || period || not_before
/// || not_after || salt || ciphertext_len(u32) || ciphertext || signature`.
/// Nothing in it identifies the service.
pub fn encode_blinded_descriptor(d: &BlindedDescriptor) -> Result<Vec<u8>, DirWireError> {
    if d.signature.len() != ED25519_SIG_LEN {
        return Err(err(format!("signature must be {ED25519_SIG_LEN} bytes")));
    }
    if d.ciphertext.len() > MAX_BLINDED_CIPHERTEXT_LEN {
        return Err(err(format!("ciphertext is {} bytes, max is {MAX_BLINDED_CIPHERTEXT_LEN}", d.ciphertext.len())));
    }
    let mut out = Vec::with_capacity(BLINDED_FIXED_LEN + d.ciphertext.len() + ED25519_SIG_LEN);
    out.extend_from_slice(&d.blinded_public);
    out.extend_from_slice(&d.period.to_be_bytes());
    out.extend_from_slice(&d.not_before.to_be_bytes());
    out.extend_from_slice(&d.not_after.to_be_bytes());
    out.extend_from_slice(&d.salt);
    out.extend_from_slice(&(d.ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(&d.ciphertext);
    out.extend_from_slice(&d.signature);
    Ok(out)
}

/// Parse one blinded descriptor from the front of `data`; returns it and the
/// bytes consumed. Strict: the declared ciphertext length is checked against
/// the maximum before anything is allocated, the whole thing must be present,
/// and the validity times must be finite.
pub fn decode_blinded_descriptor(data: &[u8]) -> Result<(BlindedDescriptor, usize), DirWireError> {
    if data.len() < BLINDED_FIXED_LEN {
        return Err(err("blinded descriptor truncated before its fixed header"));
    }
    let mut blinded_public = [0u8; 32];
    blinded_public.copy_from_slice(&data[..32]);
    let period = i64::from_be_bytes(data[32..40].try_into().expect("8 bytes"));
    let not_before = f64::from_be_bytes(data[40..48].try_into().expect("8 bytes"));
    let not_after = f64::from_be_bytes(data[48..56].try_into().expect("8 bytes"));
    if !not_before.is_finite() || !not_after.is_finite() {
        return Err(err("blinded descriptor validity times must be finite"));
    }
    let mut salt = [0u8; BLINDED_SALT_LEN];
    salt.copy_from_slice(&data[56..56 + BLINDED_SALT_LEN]);
    let ct_len = u32::from_be_bytes(data[BLINDED_FIXED_LEN - 4..BLINDED_FIXED_LEN].try_into().expect("4 bytes")) as usize;
    if ct_len > MAX_BLINDED_CIPHERTEXT_LEN {
        return Err(err(format!("blinded descriptor ciphertext of {ct_len} bytes exceeds the maximum of {MAX_BLINDED_CIPHERTEXT_LEN}")));
    }
    let total = BLINDED_FIXED_LEN + ct_len + ED25519_SIG_LEN;
    if data.len() < total {
        return Err(err("blinded descriptor truncated before its ciphertext and signature"));
    }
    let ciphertext = data[BLINDED_FIXED_LEN..BLINDED_FIXED_LEN + ct_len].to_vec();
    let signature = data[BLINDED_FIXED_LEN + ct_len..total].to_vec();
    Ok((BlindedDescriptor { blinded_public, period, not_before, not_after, salt, ciphertext, signature }, total))
}

/// A service's PUBLISH request carrying a version 3 descriptor.
pub fn encode_hs3_publish_request(descriptor: &BlindedDescriptor) -> Result<Vec<u8>, DirWireError> {
    let mut out = DIR_MAGIC.to_vec();
    out.push(HS3_PUBLISH_REQUEST);
    out.extend(encode_blinded_descriptor(descriptor)?);
    Ok(out)
}

pub fn decode_hs3_publish_request(data: &[u8]) -> Result<BlindedDescriptor, DirWireError> {
    expect(data, HS3_PUBLISH_REQUEST, "hs3 publish request")?;
    let (descriptor, consumed) = decode_blinded_descriptor(&data[MESSAGE_HEADER_LEN..])?;
    if MESSAGE_HEADER_LEN + consumed != data.len() {
        return Err(err("trailing bytes after the descriptor in an hs3 publish request"));
    }
    Ok(descriptor)
}

pub fn encode_hs3_publish_reply(ok: bool, message: &str) -> Vec<u8> {
    let mut body = message.as_bytes().to_vec();
    body.truncate(MAX_MESSAGE_LEN);
    let mut out = DIR_MAGIC.to_vec();
    out.push(HS3_PUBLISH_REPLY);
    out.push(if ok { 1 } else { 0 });
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    out
}

pub fn decode_hs3_publish_reply(data: &[u8]) -> Result<(bool, String), DirWireError> {
    expect(data, HS3_PUBLISH_REPLY, "hs3 publish reply")?;
    if data.len() < MESSAGE_HEADER_LEN + 2 {
        return Err(err("hs3 publish reply truncated before its status/length"));
    }
    let ok = data[5] == 1;
    let msg_len = data[6] as usize;
    if data.len() < MESSAGE_HEADER_LEN + 2 + msg_len {
        return Err(err("hs3 publish reply message truncated"));
    }
    Ok((ok, String::from_utf8_lossy(&data[7..7 + msg_len]).into_owned()))
}

/// A FETCH request for one blinded key; the directory is told nothing else.
pub fn encode_hs3_fetch_request(blinded_public: &[u8; 32]) -> Vec<u8> {
    let mut out = DIR_MAGIC.to_vec();
    out.push(HS3_FETCH_REQUEST);
    out.extend_from_slice(blinded_public);
    out
}

pub fn decode_hs3_fetch_request(data: &[u8]) -> Result<[u8; 32], DirWireError> {
    expect(data, HS3_FETCH_REQUEST, "hs3 fetch request")?;
    if data.len() != MESSAGE_HEADER_LEN + 32 {
        return Err(err("hs3 fetch request must be exactly a header and a 32-byte blinded key"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&data[MESSAGE_HEADER_LEN..]);
    Ok(out)
}

/// The authority's answer: the descriptor if it holds a live one for that
/// blinded key, else `None` (an ordinary outcome, so a flag, not an error).
pub fn encode_hs3_fetch_reply(descriptor: Option<&BlindedDescriptor>) -> Result<Vec<u8>, DirWireError> {
    let mut out = DIR_MAGIC.to_vec();
    out.push(HS3_FETCH_REPLY);
    match descriptor {
        None => out.push(0),
        Some(d) => {
            out.push(1);
            out.extend(encode_blinded_descriptor(d)?);
        }
    }
    Ok(out)
}

pub fn decode_hs3_fetch_reply(data: &[u8]) -> Result<Option<BlindedDescriptor>, DirWireError> {
    expect(data, HS3_FETCH_REPLY, "hs3 fetch reply")?;
    if data.len() < MESSAGE_HEADER_LEN + 1 {
        return Err(err("hs3 fetch reply truncated before its found flag"));
    }
    if data[5] == 0 {
        return Ok(None);
    }
    let (descriptor, consumed) = decode_blinded_descriptor(&data[MESSAGE_HEADER_LEN + 1..])?;
    if MESSAGE_HEADER_LEN + 1 + consumed != data.len() {
        return Err(err("trailing bytes after the descriptor in an hs3 fetch reply"));
    }
    Ok(Some(descriptor))
}

/// Split a whole directory-protocol message into wire-ready cell payloads.
pub fn fragment_message(message: &[u8], mtu: usize) -> Result<Vec<Vec<u8>>, FragmentError> {
    let fragments = Fragmenter::new(mtu, DIR_STREAM_ID)?.fragment(message);
    Ok(fragments.iter().map(encode_fragment).collect())
}

/// [`fragment_message`] with the default 256-byte mtu, matching Python's
/// `mtu: int = 256` default argument.
pub fn fragment_message_default(message: &[u8]) -> Vec<Vec<u8>> {
    fragment_message(message, 256).expect("default mtu is always valid")
}

/// Reassembles one directory-protocol message from its Fragment cells. A
/// thin, purpose-built wrapper around `fragment::Reassembler` fixed to
/// [`DIR_STREAM_ID`]: unlike the raw `Reassembler` (which returns only the
/// newly contiguous bytes on each `push`), this accumulates them and hands
/// back one complete message exactly once.
pub struct DirReassembler {
    reassembler: Reassembler,
    buffer: Vec<u8>,
}

impl DirReassembler {
    pub fn new(max_pending: usize) -> DirReassembler {
        DirReassembler { reassembler: Reassembler::new(DIR_STREAM_ID, max_pending), buffer: Vec::new() }
    }
    pub fn with_defaults() -> DirReassembler {
        DirReassembler::new(64)
    }

    /// `true` once [`DirReassembler::push`] has returned the complete
    /// message.
    pub fn finished(&self) -> bool {
        self.reassembler.finished()
    }

    /// Feed one raw (already fragment-encoded) received cell payload.
    /// Returns the complete reassembled message the moment it becomes
    /// whole; `None` while more fragments are still expected.
    ///
    /// Rejects a stream once it would exceed [`MAX_REASSEMBLED_LEN`],
    /// before the oversized bytes are ever appended -- see that
    /// constant's doc comment for why this check exists.
    pub fn push(&mut self, wire_bytes: &[u8]) -> Result<Option<Vec<u8>>, DirWireError> {
        self.push_limited(wire_bytes, MAX_REASSEMBLED_LEN)
    }

    /// Bytes held right now: the in-order message so far plus any
    /// out-of-order chunks waiting on a gap.
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len() + self.reassembler.pending_bytes()
    }

    /// [`Self::push`] with a caller-chosen cap on the reassembled message
    /// (use [`MAX_REQUEST_REASSEMBLED_LEN`] on the authority's request
    /// path). Out-of-order bytes count against the cap too, since they are
    /// held in memory just like in-order ones.
    pub fn push_limited(&mut self, wire_bytes: &[u8], max_len: usize) -> Result<Option<Vec<u8>>, DirWireError> {
        let fragment = decode_fragment(wire_bytes).map_err(|e| err(format!("not a valid directory-protocol fragment: {e}")))?;
        if fragment.offset != self.reassembler.expected_offset() && self.buffered_bytes() + fragment.data.len() > max_len {
            return Err(err(format!("directory message buffered out of order exceeds {max_len} bytes; dropping stream")));
        }
        let chunk = self.reassembler.push(&fragment).map_err(|e| err(e.to_string()))?;
        if self.buffer.len() + chunk.len() > max_len {
            return Err(err(format!(
                "reassembled directory message exceeds {max_len} bytes; dropping stream"
            )));
        }
        self.buffer.extend_from_slice(&chunk);
        if self.reassembler.finished() {
            return Ok(Some(self.buffer.clone()));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_descriptor(version: u32, extensions: Vec<(u8, Vec<u8>)>) -> RelayDescriptor {
        RelayDescriptor {
            identity_public: [1u8; ED25519_KEY_LEN],
            static_public: [2u8; ED25519_KEY_LEN],
            host: "10.0.0.1".to_string(),
            port: 9001,
            roles: vec!["exit".to_string(), "guard".to_string()],
            not_before: 1000.0,
            not_after: 2000.0,
            signature: vec![3u8; ED25519_SIG_LEN],
            version,
            extensions,
        }
    }

    #[test]
    fn test_encode_decode_descriptor_v1_round_trip() {
        let d = make_descriptor(DESCRIPTOR_VERSION_1, Vec::new());
        let encoded = encode_descriptor(&d).unwrap();
        let (decoded, consumed) = decode_descriptor(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, d);
    }

    #[test]
    fn test_encode_decode_descriptor_v2_with_extensions_round_trip() {
        let d = make_descriptor(DESCRIPTOR_VERSION_2, vec![(1, vec![0u8; 8]), (3, vec![9u8; 32])]);
        let encoded = encode_descriptor(&d).unwrap();
        let (decoded, consumed) = decode_descriptor(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, d);
    }

    #[test]
    fn test_decode_descriptor_rejects_truncated_input() {
        let d = make_descriptor(DESCRIPTOR_VERSION_1, Vec::new());
        let encoded = encode_descriptor(&d).unwrap();
        assert!(decode_descriptor(&encoded[..encoded.len() - 5]).is_err());
    }

    /// Regression test for bug report H7: valid (non-ASCII) UTF-8 in the
    /// roles field used to decode here, even though the Client's copy of
    /// this decoder rejects it -- so one such descriptor, stored by this
    /// authority and returned in every FETCH reply, failed the whole
    /// reply for every client. The authority and the client must now
    /// agree on what a valid descriptor looks like.
    #[test]
    fn test_decode_descriptor_rejects_non_ascii_roles() {
        let mut d = make_descriptor(DESCRIPTOR_VERSION_1, Vec::new());
        d.roles = vec!["\u{e9}xit".to_string()]; // valid UTF-8, not ASCII
        let encoded = encode_descriptor(&d).unwrap();
        assert!(decode_descriptor(&encoded).is_err());
    }

    #[test]
    fn test_publish_request_round_trip() {
        let d = make_descriptor(DESCRIPTOR_VERSION_1, Vec::new());
        let encoded = encode_publish_request(&d).unwrap();
        let decoded = decode_publish_request(&encoded).unwrap();
        assert_eq!(decoded, d);
    }

    #[test]
    fn test_publish_reply_round_trip() {
        let encoded = encode_publish_reply(true, "accepted");
        assert_eq!(decode_publish_reply(&encoded).unwrap(), (true, "accepted".to_string()));
        let encoded2 = encode_publish_reply(false, "nope");
        assert_eq!(decode_publish_reply(&encoded2).unwrap(), (false, "nope".to_string()));
    }

    #[test]
    fn test_fetch_request_v1_and_v2() {
        let v1 = encode_fetch_request(DESCRIPTOR_VERSION_1);
        assert_eq!(decode_fetch_request(&v1).unwrap(), DESCRIPTOR_VERSION_1);
        let v2 = encode_fetch_request_default();
        assert_eq!(decode_fetch_request(&v2).unwrap(), DESCRIPTOR_VERSION_2);
    }

    #[test]
    fn test_fetch_reply_round_trip_multiple_descriptors() {
        let d1 = make_descriptor(DESCRIPTOR_VERSION_1, Vec::new());
        let d2 = make_descriptor(DESCRIPTOR_VERSION_2, vec![(1, vec![0u8; 8])]);
        let encoded = encode_fetch_reply(&[d1.clone(), d2.clone()]).unwrap();
        let decoded = decode_fetch_reply(&encoded).unwrap();
        assert_eq!(decoded, vec![d1, d2]);
    }

    #[test]
    fn test_expect_rejects_wrong_type_and_bad_magic() {
        let encoded = encode_publish_reply(true, "");
        assert!(decode_fetch_reply(&encoded).is_err());
        let mut bad_magic = encoded.clone();
        bad_magic[0] = b'X';
        assert!(decode_publish_reply(&bad_magic).is_err());
    }

    fn make_intro(seed: u8) -> IntroPoint {
        IntroPoint { relay_identity: vec![seed; ED25519_KEY_LEN], host: "10.1.2.3".to_string(), port: 9050, auth_public: vec![seed + 1; ED25519_KEY_LEN] }
    }

    fn make_hs_descriptor_plain() -> HiddenServiceDescriptor {
        HiddenServiceDescriptor {
            identity_public: vec![1u8; ED25519_KEY_LEN],
            encryption_public: vec![2u8; X25519_KEY_LEN],
            intro_points: vec![make_intro(10), make_intro(20)],
            not_before: 100.0,
            not_after: 200.0,
            signature: vec![3u8; ED25519_SIG_LEN],
            encrypted_intro_points: Vec::new(),
            auth_ephemeral_public: Vec::new(),
            client_auth: Vec::new(),
            hs_handshake_v2: true,
        }
    }

    fn make_hs_descriptor_client_auth() -> HiddenServiceDescriptor {
        HiddenServiceDescriptor {
            identity_public: vec![1u8; ED25519_KEY_LEN],
            encryption_public: vec![2u8; X25519_KEY_LEN],
            intro_points: Vec::new(),
            not_before: 100.0,
            not_after: 200.0,
            signature: vec![3u8; ED25519_SIG_LEN],
            encrypted_intro_points: vec![9u8; 200],
            auth_ephemeral_public: vec![4u8; X25519_KEY_LEN],
            client_auth: vec![
                ClientAuthEntry { client_id_hint: vec![5u8; CLIENT_ID_HINT_LEN], wrapped_key: vec![6u8; 64] },
                ClientAuthEntry { client_id_hint: vec![7u8; CLIENT_ID_HINT_LEN], wrapped_key: vec![8u8; 64] },
            ],
            hs_handshake_v2: true,
        }
    }

    #[test]
    fn test_encode_decode_hs_descriptor_plain_round_trip() {
        let d = make_hs_descriptor_plain();
        let encoded = encode_hs_descriptor(&d).unwrap();
        let (decoded, consumed) = decode_hs_descriptor(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, d);
    }

    #[test]
    fn test_encode_decode_hs_descriptor_client_auth_round_trip() {
        let d = make_hs_descriptor_client_auth();
        let encoded = encode_hs_descriptor(&d).unwrap();
        let (decoded, consumed) = decode_hs_descriptor(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, d);
    }

    #[test]
    fn test_decode_hs_descriptor_rejects_unknown_flag() {
        let d = make_hs_descriptor_plain();
        let mut encoded = encode_hs_descriptor(&d).unwrap();
        // Flag byte sits right after identity_public || encryption_public.
        encoded[ED25519_KEY_LEN + X25519_KEY_LEN] = 0x7F;
        assert!(decode_hs_descriptor(&encoded).is_err());
    }

    #[test]
    fn test_hs_publish_request_round_trip() {
        let d = make_hs_descriptor_plain();
        let encoded = encode_hs_publish_request(&d).unwrap();
        assert_eq!(decode_hs_publish_request(&encoded).unwrap(), d);
    }

    #[test]
    fn test_hs_fetch_request_round_trip() {
        let identity = vec![9u8; ED25519_KEY_LEN];
        let encoded = encode_hs_fetch_request(&identity).unwrap();
        assert_eq!(decode_hs_fetch_request(&encoded).unwrap(), identity);
        assert!(encode_hs_fetch_request(&[1u8; 5]).is_err());
    }

    #[test]
    fn test_hs_fetch_reply_found_and_not_found() {
        let d = make_hs_descriptor_plain();
        let found = encode_hs_fetch_reply(Some(&d)).unwrap();
        assert_eq!(decode_hs_fetch_reply(&found).unwrap(), Some(d));
        let not_found = encode_hs_fetch_reply(None).unwrap();
        assert_eq!(decode_hs_fetch_reply(&not_found).unwrap(), None);
    }

    #[test]
    fn test_fragment_message_and_dir_reassembler_round_trip() {
        let d = make_descriptor(DESCRIPTOR_VERSION_2, vec![(1, vec![0u8; 8])]);
        let message = encode_publish_request(&d).unwrap();
        let datagrams = fragment_message(&message, 32).unwrap();
        assert!(datagrams.len() > 1);
        let mut reassembler = DirReassembler::with_defaults();
        let mut result = None;
        for datagram in &datagrams {
            assert!(!reassembler.finished());
            result = reassembler.push(datagram).unwrap();
        }
        assert!(reassembler.finished());
        let reassembled = result.unwrap();
        assert_eq!(decode_publish_request(&reassembled).unwrap(), d);
    }

    #[test]
    fn test_dir_reassembler_rejects_garbage() {
        let mut reassembler = DirReassembler::with_defaults();
        assert!(reassembler.push(b"not a fragment").is_err());
    }

    /// A stream that never sends FIN must not be allowed to grow its
    /// reassembly buffer without bound -- exactly at the boundary: a
    /// message of precisely `MAX_REASSEMBLED_LEN` bytes must still
    /// reassemble (no legitimate maximal message is rejected), but one
    /// byte more must be refused immediately, not only once "complete".
    #[test]
    fn test_dir_reassembler_rejects_message_exceeding_max_reassembled_len() {
        let mut reassembler = DirReassembler::with_defaults();
        let first = crate::fragment::Fragment::new(DIR_STREAM_ID, 0, false, vec![0x41u8; MAX_REASSEMBLED_LEN]);
        assert_eq!(reassembler.push(&encode_fragment(&first)).unwrap(), None);
        let second = crate::fragment::Fragment::new(DIR_STREAM_ID, MAX_REASSEMBLED_LEN as u32, true, vec![0x42u8]);
        assert!(reassembler.push(&encode_fragment(&second)).is_err());
    }

    #[test]
    fn test_request_cap_fits_the_largest_wire_valid_hs_publish() {
        // the largest wire-valid version 3 publish: a maximum-size sealed descriptor
        let max = BlindedDescriptor {
            blinded_public: [1u8; 32],
            period: 19_700,
            not_before: 1.0,
            not_after: 2.0,
            salt: [2u8; BLINDED_SALT_LEN],
            ciphertext: vec![3u8; MAX_BLINDED_CIPHERTEXT_LEN],
            signature: vec![4u8; ED25519_SIG_LEN],
        };
        let wire = encode_hs3_publish_request(&max).unwrap();
        // the cap is exactly the largest wire-valid request: it fits, with no slack to hide a miscount
        assert_eq!(wire.len(), MAX_REQUEST_REASSEMBLED_LEN);
        // and a relay PUBLISH at its maximum is far smaller
        assert!(MAX_REQUEST_REASSEMBLED_LEN < MAX_REASSEMBLED_LEN / 100);
        // the old (version 2) publish fits under it too, so it can still be refused politely
        assert!(MAX_HS2_PUBLISH_LEN <= MAX_REQUEST_REASSEMBLED_LEN);
        // the ciphertext bound is the inner maximum plus the sealing overhead
        assert_eq!(MAX_BLINDED_CIPHERTEXT_LEN, MAX_INNER_DESCRIPTOR_LEN + BLINDED_SEAL_OVERHEAD);
    }

    #[test]
    fn test_dir_reassembler_request_cap_rejects_oversize_but_accepts_a_real_request() {
        let max_wire = vec![0xABu8; MAX_REQUEST_REASSEMBLED_LEN];
        // in-order, never FIN: the cap trips instead of buffering without bound
        let mut r = DirReassembler::with_defaults();
        let mut off = 0u32;
        let mut tripped = false;
        for _ in 0..(MAX_REQUEST_REASSEMBLED_LEN / 1000 + 50) {
            let f = crate::fragment::Fragment::new(DIR_STREAM_ID, off, false, vec![1u8; 1000]);
            if r.push_limited(&encode_fragment(&f), MAX_REQUEST_REASSEMBLED_LEN).is_err() {
                tripped = true;
                break;
            }
            off += 1000;
        }
        assert!(tripped);
        assert!(r.buffered_bytes() <= MAX_REQUEST_REASSEMBLED_LEN);
        // a complete message right at the cap still goes through
        let mut r = DirReassembler::with_defaults();
        let mut done = None;
        for f in crate::fragment::Fragmenter::new(1000, DIR_STREAM_ID).unwrap().fragment(&max_wire) {
            if let Some(m) = r.push_limited(&encode_fragment(&f), MAX_REQUEST_REASSEMBLED_LEN).unwrap() {
                done = Some(m);
            }
        }
        assert_eq!(done.unwrap().len(), MAX_REQUEST_REASSEMBLED_LEN);
    }

    // -- version 3 (blinded) messages --------------------------------------------

    fn sample_blinded(ct_len: usize) -> BlindedDescriptor {
        BlindedDescriptor {
            blinded_public: [1u8; 32],
            period: 19_700,
            not_before: 1000.5,
            not_after: 4600.5,
            salt: [2u8; BLINDED_SALT_LEN],
            ciphertext: vec![3u8; ct_len],
            signature: vec![4u8; 64],
        }
    }

    #[test]
    fn blinded_descriptor_and_every_hs3_message_round_trip() {
        for ct_len in [0usize, 1, 100, 5000] {
            let d = sample_blinded(ct_len);
            let wire = encode_blinded_descriptor(&d).unwrap();
            let (back, consumed) = decode_blinded_descriptor(&wire).unwrap();
            assert_eq!(consumed, wire.len());
            assert_eq!(back, d);
        }
        let d = sample_blinded(300);
        assert_eq!(decode_hs3_publish_request(&encode_hs3_publish_request(&d).unwrap()).unwrap(), d);
        assert_eq!(decode_hs3_publish_reply(&encode_hs3_publish_reply(true, "stored")).unwrap(), (true, "stored".to_string()));
        assert_eq!(decode_hs3_fetch_request(&encode_hs3_fetch_request(&[9u8; 32])).unwrap(), [9u8; 32]);
        assert_eq!(decode_hs3_fetch_reply(&encode_hs3_fetch_reply(Some(&d)).unwrap()).unwrap(), Some(d));
        assert_eq!(decode_hs3_fetch_reply(&encode_hs3_fetch_reply(None).unwrap()).unwrap(), None);
    }

    /// Every truncation of every message must be a clean error, never a panic.
    #[test]
    fn truncated_hs3_messages_are_clean_errors() {
        let d = sample_blinded(40);
        let messages: Vec<(&str, Vec<u8>, fn(&[u8]) -> bool)> = vec![
            ("publish", encode_hs3_publish_request(&d).unwrap(), |b| decode_hs3_publish_request(b).is_err()),
            ("fetch reply", encode_hs3_fetch_reply(Some(&d)).unwrap(), |b| decode_hs3_fetch_reply(b).is_err()),
            ("fetch request", encode_hs3_fetch_request(&[1u8; 32]), |b| decode_hs3_fetch_request(b).is_err()),
            ("publish reply", encode_hs3_publish_reply(true, "hello"), |b| decode_hs3_publish_reply(b).is_err()),
        ];
        for (name, wire, fails) in messages {
            for cut in 0..wire.len() {
                assert!(fails(&wire[..cut]), "{name} truncated to {cut} of {} bytes was accepted", wire.len());
            }
        }
    }

    #[test]
    fn hs3_decoding_refuses_oversize_trailing_and_non_finite_input() {
        let mut wire = encode_blinded_descriptor(&sample_blinded(10)).unwrap();
        wire[BLINDED_FIXED_LEN - 4..BLINDED_FIXED_LEN].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_blinded_descriptor(&wire).is_err());
        assert!(encode_blinded_descriptor(&sample_blinded(MAX_BLINDED_CIPHERTEXT_LEN + 1)).is_err());
        let mut publish = encode_hs3_publish_request(&sample_blinded(10)).unwrap();
        publish.push(0);
        assert!(decode_hs3_publish_request(&publish).is_err());
        let mut reply = encode_hs3_fetch_reply(Some(&sample_blinded(10))).unwrap();
        reply.push(0);
        assert!(decode_hs3_fetch_reply(&reply).is_err());
        for offset in [40usize, 48] {
            for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
                let mut w = encode_blinded_descriptor(&sample_blinded(10)).unwrap();
                w[offset..offset + 8].copy_from_slice(&bad.to_be_bytes());
                assert!(decode_blinded_descriptor(&w).is_err());
            }
        }
        let good = encode_hs3_fetch_request(&[1u8; 32]);
        let mut wrong_type = good.clone();
        wrong_type[4] = HS_FETCH_REQUEST;
        assert!(decode_hs3_fetch_request(&wrong_type).is_err());
        let mut long = good;
        long.push(0);
        assert!(decode_hs3_fetch_request(&long).is_err());
    }

    /// Every message type in the shared `ALDR` namespace must be unique. Types
    /// are defined in two modules (here and `consensus`), so a collision cannot
    /// be seen from either alone: a version 3 publish once shared a number
    /// with the vote request and was answered with a vote.
    #[test]
    fn all_message_types_in_the_aldr_namespace_are_distinct() {
        let types: [(&str, u8); 17] = [
            ("PUBLISH_REQUEST", PUBLISH_REQUEST),
            ("PUBLISH_REPLY", PUBLISH_REPLY),
            ("FETCH_REQUEST", FETCH_REQUEST),
            ("FETCH_REPLY", FETCH_REPLY),
            ("HS_PUBLISH_REQUEST", HS_PUBLISH_REQUEST),
            ("HS_PUBLISH_REPLY", HS_PUBLISH_REPLY),
            ("HS_FETCH_REQUEST", HS_FETCH_REQUEST),
            ("HS_FETCH_REPLY", HS_FETCH_REPLY),
            ("FETCH_REQUEST_V2", FETCH_REQUEST_V2),
            ("HS3_PUBLISH_REQUEST", HS3_PUBLISH_REQUEST),
            ("HS3_PUBLISH_REPLY", HS3_PUBLISH_REPLY),
            ("HS3_FETCH_REQUEST", HS3_FETCH_REQUEST),
            ("HS3_FETCH_REPLY", HS3_FETCH_REPLY),
            ("VOTE_REQUEST", crate::consensus::VOTE_REQUEST),
            ("VOTE_REPLY", crate::consensus::VOTE_REPLY),
            ("(spare 1)", 200),
            ("(spare 2)", 201),
        ];
        let mut seen = std::collections::HashMap::new();
        for (name, value) in types {
            if let Some(other) = seen.insert(value, name) {
                panic!("message type {value} is used by both {other} and {name}");
            }
        }
    }
}
