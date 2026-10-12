//! Wire framing for Allium's directory protocol.
//!
//! This is how a relay publishes its signed descriptor to a directory
//! authority, and how a client (or another relay) fetches the current live
//! set back. [`crate::directory`] already has a complete, tested
//! `RelayDescriptor`/`Directory`; this module is what puts one on the wire.
//!
//! **Transport.** In the Python original this rides the same onion-cell/
//! circuit machinery as everything else in Allium. This crate doesn't
//! reproduce `circuit.py`'s directory-specific glue here -- this module only
//! covers the framing (encode/decode of messages, and fragmentation over
//! [`crate::fragment`]), exactly like `dirwire.py` itself does.
//!
//! **Framing.** Every message -- request or reply -- is carried as one or
//! more [`crate::fragment::Fragment`] cells on a reserved stream id
//! ([`DIR_STREAM_ID`]), reassembled by [`DirReassembler`]. This is
//! deliberate uniformity, not just convenience: a small request happens to
//! fit in one fragment today, but special-casing "never fragmented" would
//! silently break the moment a descriptor's host or role list grew past one
//! cell. Reassembly handles one fragment or many identically, so there is
//! no size threshold to get wrong here.
//!
//! **Message shapes** (`DIR_MAGIC` prefixes every one, so a reassembled blob
//! can be sanity-checked before dispatch):
//!
//! ```text
//! PUBLISH_REQUEST  (relay -> authority): one RelayDescriptor
//! PUBLISH_REPLY    (authority -> relay): ok flag + a short message
//! FETCH_REQUEST    (client/relay -> authority): empty body
//! FETCH_REPLY      (authority -> caller): count + that many descriptors
//! ```
//!
//! Hidden-service descriptors get their own PUBLISH/FETCH pair
//! (`HS_PUBLISH_*`/`HS_FETCH_*`), over the same magic/reassembly machinery,
//! but FETCH is deliberately by-address only (no "list every hidden
//! service" operation) -- an authority that could be asked to enumerate
//! every `.allium` address it knows about would be a much bigger privacy
//! leak than a directory of *relays*, which are already meant to be public.
//!
//! **Trust model**, unchanged from [`crate::directory`]: a descriptor is
//! self-signed by the relay's own Ed25519 identity, so its authenticity
//! does not depend on the authority being honest -- only on the signature
//! verifying, which is the caller's job (typically
//! [`crate::directory::Directory::publish`]), not this module's:
//! [`decode_descriptor`]/[`decode_hs_descriptor`] only parse the wire
//! shape.

use std::fmt;

use crate::directory::{DESCRIPTOR_VERSION_1, DESCRIPTOR_VERSION_2, RelayDescriptor};
use crate::fragment::{Fragment, FragmentError, Fragmenter, Reassembler, decode_fragment, encode_fragment};
use crate::hiddenservice::{ClientAuthEntry, HiddenServiceDescriptor, IntroPoint};

/// A directory-protocol message could not be encoded/decoded.
///
/// Always what this module returns on bad input -- never a raw slice-index
/// panic -- so a caller that must handle "the peer sent garbage" has
/// exactly one error type to match on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirWireError(pub String);

impl fmt::Display for DirWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for DirWireError {}

fn err(msg: impl Into<String>) -> DirWireError {
    DirWireError(msg.into())
}

/// Unchanging prefix on every directory-protocol message (after
/// reassembly). Distinct from `allium::socks`'s `MAGIC` (`ALSM`) and
/// `DATAGRAM_MAGIC` (`ALDG`) so the framings can never be confused.
pub const DIR_MAGIC: &[u8; 4] = b"ALDR";

/// Fragment stream id reserved for directory-protocol traffic. Safe to
/// hardcode to a single fixed value: a directory circuit (opened solely to
/// publish or fetch) carries exactly one logical request/reply and nothing
/// else -- unlike an app circuit, which multiplexes many concurrent SOCKS
/// streams and so needs per-stream ids.
pub const DIR_STREAM_ID: u32 = 0;

pub const PUBLISH_REQUEST: u8 = 1;
pub const PUBLISH_REPLY: u8 = 2;
pub const FETCH_REQUEST: u8 = 3;
pub const FETCH_REPLY: u8 = 4;
/// Hidden-service descriptor publish/fetch -- same authority, same
/// `DIR_MAGIC`/[`DirReassembler`] machinery as the relay PUBLISH/FETCH pair
/// above, just a different descriptor shape and (for FETCH) looked up by
/// address rather than returned as the whole live set.
pub const HS_PUBLISH_REQUEST: u8 = 5;
pub const HS_PUBLISH_REPLY: u8 = 6;
pub const HS_FETCH_REQUEST: u8 = 7;
pub const HS_FETCH_REPLY: u8 = 8;
/// A FETCH from a client that understands v2 descriptors (see
/// [`ROLES_LEN_V2_FLAG`]). Answered with an ordinary FETCH_REPLY that may
/// contain v2 descriptors. A plain FETCH_REQUEST (type 3, what every
/// pre-v2 client sends) is answered with the v1 descriptors only, so an old
/// client's parser is never handed a format it would reject -- the one
/// migration path for the schema bump.
pub const FETCH_REQUEST_V2: u8 = 9;
/// Version 3 hidden-service messages: the blinded, encrypted descriptors of
/// [`crate::hsblind`]. New message types rather than a new flag on the old
/// ones, so there is never any doubt which kind of descriptor a message
/// carries, and an authority that only speaks the old types answers them
/// with "unknown", not a misparse.
/// (Numbered from 20: types 10 and 11 are the consensus `VOTE_REQUEST` /
/// `VOTE_REPLY`, which share this `ALDR` message namespace; an earlier numbering
/// of 10 to 13 made the authority answer a publish with a signed vote.)
pub const HS3_PUBLISH_REQUEST: u8 = 20;
pub const HS3_PUBLISH_REPLY: u8 = 21;
pub const HS3_FETCH_REQUEST: u8 = 22;
pub const HS3_FETCH_REPLY: u8 = 23;

/// v2 descriptors reuse the v1 wire layout with this bit set in the
/// `roles_len` field (which never exceeds [`MAX_ROLES_LEN`] = 128 in v1),
/// followed by the signed extension block before the signature. A v1
/// decoder sees an out-of-range `roles_len` and fails cleanly with a
/// [`DirWireError`] instead of misparsing.
pub const ROLES_LEN_V2_FLAG: u16 = 0x8000;
pub const MAX_EXTENSION_COUNT: usize = 16;
pub const MAX_EXTENSION_VALUE_LEN: usize = 2048;

/// Defensive upper bounds on untrusted-input sizes. None of these are
/// reachable by a well-formed message; they exist so a corrupt or
/// malicious peer gets a clean [`DirWireError`] instead of an oversized
/// allocation or a slow parse.
pub const MAX_HOST_LEN: usize = 255;
pub const MAX_ROLES_LEN: usize = 128;
pub const MAX_MESSAGE_LEN: usize = 255;
pub const MAX_DESCRIPTOR_COUNT: usize = 4096;
pub const MAX_INTRO_POINT_COUNT: usize = 32;
const X25519_KEY_LEN: usize = 32;
/// Client-authorization fields (see [`crate::hiddenservice::ClientAuthEntry`]).
pub const CLIENT_ID_HINT_LEN: usize = 16;
pub const MAX_CLIENT_AUTH_COUNT: usize = 64;
pub const MAX_WRAPPED_KEY_LEN: usize = 4096;
pub const MAX_ENCRYPTED_INTRO_POINTS_LEN: usize = 65535;

const ED25519_KEY_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;
/// identity_public + static_public + host_len(2) + port(2) + roles_len(2)
/// -- the fixed part of a descriptor's header, before the variable-length
/// host/roles fields.
const DESCRIPTOR_HEADER_LEN: usize = ED25519_KEY_LEN * 2 + 2 + 2 + 2;
/// not_before(8) + not_after(8) + signature(64), the fixed trailer after
/// the variable-length roles field (v1; v2 inserts the extension block
/// before the signature -- see [`decode_descriptor`]).
const DESCRIPTOR_TRAILER_LEN: usize = 8 + 8 + ED25519_SIG_LEN;
/// 4-byte magic + 1-byte message type: the header every message shares.
const MESSAGE_HEADER_LEN: usize = 5;

/// Serialize a [`RelayDescriptor`] for the wire.
///
/// # Errors
/// Returns [`DirWireError`] if any field is an unexpected size (a 32-byte
/// identity/static key, a 64-byte Ed25519 signature, or a host/roles string
/// within the bounds above) -- always on the local, about-to-be-signed-or-
/// already-signed descriptor a caller passes in, never on untrusted network
/// input (see [`decode_descriptor`] for that side).
pub fn encode_descriptor(d: &RelayDescriptor) -> Result<Vec<u8>, DirWireError> {
    let host = d.host.as_bytes();
    if host.len() > MAX_HOST_LEN {
        return Err(err(format!("host is {} bytes, max is {MAX_HOST_LEN}", host.len())));
    }
    let mut sorted_roles = d.roles.clone();
    sorted_roles.sort();
    let roles = sorted_roles.join(",");
    let roles_bytes = roles.as_bytes();
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

    let mut out = Vec::new();
    out.extend_from_slice(&d.identity_public);
    out.extend_from_slice(&d.static_public);
    out.extend_from_slice(&(host.len() as u16).to_be_bytes());
    out.extend_from_slice(&d.port.to_be_bytes());

    if d.version == DESCRIPTOR_VERSION_2 {
        if d.extensions.len() > MAX_EXTENSION_COUNT {
            return Err(err(format!("at most {MAX_EXTENSION_COUNT} extensions")));
        }
        out.extend_from_slice(&(roles_bytes.len() as u16 | ROLES_LEN_V2_FLAG).to_be_bytes());
        out.extend_from_slice(host);
        out.extend_from_slice(roles_bytes);
        out.extend_from_slice(&d.not_before.to_be_bytes());
        out.extend_from_slice(&d.not_after.to_be_bytes());
        out.push(d.extensions.len() as u8);
        for (ext_type, value) in &d.extensions {
            if value.len() > MAX_EXTENSION_VALUE_LEN {
                return Err(err(format!("extension {ext_type} out of bounds")));
            }
            out.push(*ext_type);
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
            out.extend_from_slice(value);
        }
        out.extend_from_slice(&d.signature);
        return Ok(out);
    }
    if d.version != DESCRIPTOR_VERSION_1 {
        return Err(err(format!("unknown descriptor version {}", d.version)));
    }
    out.extend_from_slice(&(roles_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(host);
    out.extend_from_slice(roles_bytes);
    out.extend_from_slice(&d.not_before.to_be_bytes());
    out.extend_from_slice(&d.not_after.to_be_bytes());
    out.extend_from_slice(&d.signature);
    Ok(out)
}

/// Parse one descriptor from the front of `data`.
///
/// Returns `(descriptor, consumed)` -- `consumed` is how many bytes of
/// `data` the descriptor actually used, so a caller packing more than one
/// (see [`decode_fetch_reply`]) can advance correctly. The descriptor's
/// self-signature is **not** verified here -- that is
/// [`RelayDescriptor::verify`]'s job (or `Directory::publish`'s, which
/// calls it); this function only parses the wire shape.
///
/// # Errors
/// Returns [`DirWireError`] on any truncated or oversized field. Every
/// bound check happens before the corresponding slice, so malicious/corrupt
/// `data` can only ever produce a clean [`DirWireError`], never a panic.
pub fn decode_descriptor(data: &[u8]) -> Result<(RelayDescriptor, usize), DirWireError> {
    if data.len() < DESCRIPTOR_HEADER_LEN {
        return Err(err("descriptor truncated before its fixed header"));
    }
    let identity_public = data[..ED25519_KEY_LEN].to_vec();
    let static_public = data[ED25519_KEY_LEN..ED25519_KEY_LEN * 2].to_vec();
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
    let roles: Vec<String> = roles_str.split(',').filter(|r| !r.is_empty()).map(|r| r.to_string()).collect();
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
    out.extend(encode_descriptor(descriptor)?);
    Ok(out)
}

/// Parse a PUBLISH request. Returns [`DirWireError`] on a malformed frame.
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
    out.extend(body);
    out
}

/// Parse a PUBLISH reply, returning `(ok, message)`.
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

/// A FETCH request: no body, just "send me the current live set".
///
/// `version = DESCRIPTOR_VERSION_2` (the typical default) asks for every
/// descriptor including v2 ones; `version = DESCRIPTOR_VERSION_1` is the
/// legacy request an older client sends.
pub fn encode_fetch_request(version: u8) -> Vec<u8> {
    let mut out = DIR_MAGIC.to_vec();
    if version == DESCRIPTOR_VERSION_1 {
        out.push(FETCH_REQUEST);
    } else {
        out.push(FETCH_REQUEST_V2);
    }
    out
}

/// Validate a FETCH request frame, returning the descriptor version the
/// requester understands (1 or 2). Returns [`DirWireError`] if malformed.
pub fn decode_fetch_request(data: &[u8]) -> Result<u8, DirWireError> {
    if data.starts_with(DIR_MAGIC) && data.len() >= MESSAGE_HEADER_LEN && data[4] == FETCH_REQUEST_V2 {
        return Ok(DESCRIPTOR_VERSION_2);
    }
    expect(data, FETCH_REQUEST, "fetch request")?;
    Ok(DESCRIPTOR_VERSION_1)
}

/// The authority's answer to a FETCH: every live descriptor it holds.
pub fn encode_fetch_reply(descriptors: &[RelayDescriptor]) -> Result<Vec<u8>, DirWireError> {
    if descriptors.len() > MAX_DESCRIPTOR_COUNT {
        return Err(err(format!(
            "cannot encode {} descriptors in one reply (max {MAX_DESCRIPTOR_COUNT})",
            descriptors.len()
        )));
    }
    let mut out = DIR_MAGIC.to_vec();
    out.push(FETCH_REPLY);
    out.extend_from_slice(&(descriptors.len() as u16).to_be_bytes());
    for d in descriptors {
        let encoded = encode_descriptor(d)?;
        out.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
        out.extend(encoded);
    }
    Ok(out)
}

/// Parse a FETCH reply into its list of descriptors.
///
/// Every entry is parsed with [`decode_descriptor`] (wire-shape only --
/// signatures are not checked here); a caller should run each result
/// through [`crate::directory::Directory::publish`] to actually verify and
/// use it.
///
/// Each descriptor is length-prefixed, so one malformed entry (for example
/// one an authority stored before it validated a field this client is
/// stricter about) is skipped rather than failing the whole reply --
/// otherwise a single bad descriptor stored anywhere would stop every
/// client from fetching the directory at all. A length field that doesn't
/// match its content still fails the whole reply, since at that point
/// framing itself cannot be trusted to stay in sync.
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
        if let Ok((descriptor, consumed)) = decode_descriptor(&data[offset..offset + desc_len]) {
            if consumed == desc_len {
                descriptors.push(descriptor);
            }
        }
        offset += desc_len;
    }
    Ok(descriptors)
}

// ---------------------------------------------------------------------------
// Hidden-service descriptors: published to and fetched from the same
// authority, over the same DIR_MAGIC/DirReassembler machinery, as the relay
// descriptors above -- see `crate::hiddenservice` for what a
// HiddenServiceDescriptor actually authenticates and why. FETCH here is
// deliberately by-address only.
// ---------------------------------------------------------------------------

/// Descriptor flag byte: plain, cleartext intro points (today's format).
const HS_FLAG_PLAIN: u8 = 0x00;
/// Descriptor flag byte: intro points AEAD-encrypted for a fixed set of
/// authorized clients.
const HS_FLAG_CLIENT_AUTH: u8 = 0x01;
/// Bit of the flag byte that carries [`HiddenServiceDescriptor::hs_handshake_v2`].
/// Independent of [`HS_FLAG_CLIENT_AUTH`]
/// (which selects the branch below), so it is combined with `|` on encode
/// and masked off with `& HS_FLAG_CLIENT_AUTH` before comparing the branch
/// selector -- a service can advertise the MAC-authenticated rendezvous
/// handshake regardless of whether it also restricts its introduction
/// points to specific clients.
const HS_FLAG_HANDSHAKE_V2: u8 = 0x02;

/// The intro-point-list wire shape shared by the plain descriptor body
/// below -- kept local to this module (rather than shared with
/// `crate::hiddenservice`) because this one also enforces the
/// untrusted-input size caps ([`MAX_HOST_LEN`], [`MAX_INTRO_POINT_COUNT`])
/// that are this module's job, not the crypto module's.
fn encode_intro_points_wire(intro_points: &[IntroPoint]) -> Result<Vec<u8>, DirWireError> {
    if intro_points.len() > MAX_INTRO_POINT_COUNT {
        return Err(err(format!(
            "{} intro points exceeds max {MAX_INTRO_POINT_COUNT}",
            intro_points.len()
        )));
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
///
/// Layout is `identity_public || encryption_public || flag` followed by
/// either the plain intro-point list (`flag == 0x00`, today's original
/// shape) or the client-auth fields (`flag == 0x01`: the encrypted
/// intro-point blob, the service's auth ephemeral key, and one wrapped key
/// per authorized client). Either way the trailer is the same:
/// `not_before || not_after || signature`.
///
/// # Errors
/// Returns [`DirWireError`] on an unexpected field size, or more intro
/// points/authorized clients than this module allows.
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

    let mut out = Vec::new();
    out.extend_from_slice(&d.identity_public);
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
            return Err(err(format!(
                "{} authorized clients exceeds max {MAX_CLIENT_AUTH_COUNT}",
                d.client_auth.len()
            )));
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
                return Err(err(format!(
                    "wrapped_key is {} bytes, max is {MAX_WRAPPED_KEY_LEN}",
                    entry.wrapped_key.len()
                )));
            }
            out.extend_from_slice(&entry.client_id_hint);
            out.extend_from_slice(&(entry.wrapped_key.len() as u16).to_be_bytes());
            out.extend_from_slice(&entry.wrapped_key);
        }
    } else {
        out.push(HS_FLAG_PLAIN | if d.hs_handshake_v2 { HS_FLAG_HANDSHAKE_V2 } else { 0 });
        out.extend(encode_intro_points_wire(&d.intro_points)?);
    }

    out.extend_from_slice(&d.not_before.to_be_bytes());
    out.extend_from_slice(&d.not_after.to_be_bytes());
    out.extend_from_slice(&d.signature);
    Ok(out)
}

/// Parse one HS descriptor from the front of `data`.
///
/// Returns `(descriptor, consumed)`, mirroring [`decode_descriptor`]. The
/// signature is **not** verified here -- that is
/// [`HiddenServiceDescriptor::verify`]'s job.
///
/// # Errors
/// Returns [`DirWireError`] on any truncated or oversized field, an unknown
/// flag byte, or a corrupt claimed count.
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
            return Err(err(format!(
                "hs descriptor claims {intro_count} intro points, max is {MAX_INTRO_POINT_COUNT}"
            )));
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
            return Err(err(format!(
                "hs descriptor claims {auth_count} authorized clients, max is {MAX_CLIENT_AUTH_COUNT}"
            )));
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
        return Err(err(format!("hs descriptor has an unknown flag byte {flag}")));
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
    out.extend(encode_hs_descriptor(descriptor)?);
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
    out.extend(body);
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

/// A FETCH request for one specific service, by its 32-byte identity key
/// ([`crate::hiddenservice::decode_address`] gets you this from an
/// `x.allium` string).
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
/// `None` -- carried as a found flag rather than an error, since "no such
/// service, or it just expired" is an ordinary, expected outcome.
pub fn encode_hs_fetch_reply(descriptor: Option<&HiddenServiceDescriptor>) -> Result<Vec<u8>, DirWireError> {
    let mut out = DIR_MAGIC.to_vec();
    out.push(HS_FETCH_REPLY);
    match descriptor {
        None => {
            out.push(0);
        }
        Some(d) => {
            out.push(1);
            out.extend(encode_hs_descriptor(d)?);
        }
    }
    Ok(out)
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
// Version 3 hidden-service descriptors (blinded key, encrypted body)
// ---------------------------------------------------------------------------

/// blinded_public(32) + period(8) + not_before(8) + not_after(8) + salt(32) + ciphertext length(4).
const BLINDED_FIXED_LEN: usize = 32 + 8 + 8 + 8 + crate::hsblind::SALT_LEN + 4;

/// Serialize a [`BlindedDescriptor`](crate::hsblind::BlindedDescriptor):
/// `blinded_public || period || not_before || not_after || salt ||
/// ciphertext_len(u32) || ciphertext || signature`. Nothing in it identifies
/// the service.
pub fn encode_blinded_descriptor(d: &crate::hsblind::BlindedDescriptor) -> Result<Vec<u8>, DirWireError> {
    if d.signature.len() != ED25519_SIG_LEN {
        return Err(err(format!("signature must be {ED25519_SIG_LEN} bytes")));
    }
    if d.ciphertext.len() > crate::hsblind::MAX_CIPHERTEXT_LEN {
        return Err(err(format!("ciphertext is {} bytes, max is {}", d.ciphertext.len(), crate::hsblind::MAX_CIPHERTEXT_LEN)));
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
/// and the validity times must be finite numbers.
pub fn decode_blinded_descriptor(data: &[u8]) -> Result<(crate::hsblind::BlindedDescriptor, usize), DirWireError> {
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
    let mut salt = [0u8; crate::hsblind::SALT_LEN];
    salt.copy_from_slice(&data[56..56 + crate::hsblind::SALT_LEN]);
    let ct_len = u32::from_be_bytes(data[BLINDED_FIXED_LEN - 4..BLINDED_FIXED_LEN].try_into().expect("4 bytes")) as usize;
    if ct_len > crate::hsblind::MAX_CIPHERTEXT_LEN {
        return Err(err(format!("blinded descriptor ciphertext of {ct_len} bytes exceeds the maximum of {}", crate::hsblind::MAX_CIPHERTEXT_LEN)));
    }
    let total = BLINDED_FIXED_LEN + ct_len + ED25519_SIG_LEN;
    if data.len() < total {
        return Err(err("blinded descriptor truncated before its ciphertext and signature"));
    }
    let ciphertext = data[BLINDED_FIXED_LEN..BLINDED_FIXED_LEN + ct_len].to_vec();
    let signature = data[BLINDED_FIXED_LEN + ct_len..total].to_vec();
    Ok((crate::hsblind::BlindedDescriptor { blinded_public, period, not_before, not_after, salt, ciphertext, signature }, total))
}

/// A service's PUBLISH request carrying a version 3 descriptor.
pub fn encode_hs3_publish_request(descriptor: &crate::hsblind::BlindedDescriptor) -> Result<Vec<u8>, DirWireError> {
    let mut out = DIR_MAGIC.to_vec();
    out.push(HS3_PUBLISH_REQUEST);
    out.extend(encode_blinded_descriptor(descriptor)?);
    Ok(out)
}

pub fn decode_hs3_publish_request(data: &[u8]) -> Result<crate::hsblind::BlindedDescriptor, DirWireError> {
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
    out.extend(body);
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

/// A FETCH request for one blinded key. The directory is told nothing but
/// `A'`: it cannot tell which address this is, or that it is the same
/// service as last period's request.
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
pub fn encode_hs3_fetch_reply(descriptor: Option<&crate::hsblind::BlindedDescriptor>) -> Result<Vec<u8>, DirWireError> {
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

pub fn decode_hs3_fetch_reply(data: &[u8]) -> Result<Option<crate::hsblind::BlindedDescriptor>, DirWireError> {
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
///
/// Each returned entry is already [`encode_fragment`]-wrapped and ready to
/// hand straight to a circuit's send. Always goes through
/// [`crate::fragment::Fragmenter`], even for a message that would fit in
/// one fragment -- see this module's doc comment for why a size-based
/// shortcut here specifically is the thing to avoid.
pub fn fragment_message(message: &[u8], mtu: usize) -> Vec<Vec<u8>> {
    let fragmenter = Fragmenter::new(mtu, DIR_STREAM_ID).expect("mtu is always >= 1 in this module's callers");
    fragmenter.fragment(message).iter().map(encode_fragment).collect()
}

/// Hard upper bound on a reassembled directory-protocol message, mirroring
/// `Authority`/`Relays`' own `dirwire.rs::MAX_REASSEMBLED_LEN` (this Client
/// crate only ever reassembles a FETCH_REPLY over [`DIR_STREAM_ID`], never
/// the HS-descriptor messages the other two crates' copy of this constant
/// also has to size for -- see [`crate::hswire::HsReassembler`] for that).
///
/// Without this, [`DirReassembler::push`] accumulated every reassembled
/// byte into an ever-growing `Vec<u8>` with no cap at all: a directory
/// authority (or anything else this crate dials for a FETCH round trip)
/// could answer with an endless stream of small, in-order fragments
/// without ever setting FIN -- the receive loop is bounded only by a
/// wall-clock timeout, not by bytes received, so memory would grow
/// unbounded for the life of that timeout. Sized the same way as the
/// other two crates' copy: a FETCH_REPLY carrying `MAX_DESCRIPTOR_COUNT`
/// descriptors, each at its own maximum encoded size, plus framing. Any
/// wire-valid message is guaranteed to fit; anything larger cannot be a
/// real message and is rejected as soon as it's seen, not just once
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

/// Reassembles one directory-protocol message from its Fragment cells.
///
/// A thin, purpose-built wrapper around [`crate::fragment::Reassembler`]
/// fixed to [`DIR_STREAM_ID`]: unlike the raw `Reassembler` (which returns
/// only the newly contiguous bytes on each [`Self::push`]), this
/// accumulates them and hands back one complete message exactly once,
/// which is all a directory request/reply round trip ever needs.
pub struct DirReassembler {
    reassembler: Reassembler,
    buffer: Vec<u8>,
}

impl DirReassembler {
    pub fn new(max_pending: usize) -> Self {
        DirReassembler { reassembler: Reassembler::new(DIR_STREAM_ID, max_pending), buffer: Vec::new() }
    }

    /// `true` once [`Self::push`] has returned the complete message.
    pub fn finished(&self) -> bool {
        self.reassembler.finished()
    }

    /// Feed one raw (already fragment-encoded) received cell payload.
    ///
    /// Returns the complete reassembled message, the moment it becomes
    /// whole; `None` while more fragments are still expected.
    ///
    /// Rejects a stream once it would exceed [`MAX_REASSEMBLED_LEN`],
    /// before the oversized bytes are ever appended -- see that
    /// constant's doc comment for why this check exists.
    ///
    /// # Errors
    /// Returns [`DirWireError`] if `wire_bytes` does not even decode as a
    /// [`Fragment`], or is for a different stream than [`DIR_STREAM_ID`] --
    /// always on untrusted input, so this is the one error type a caller
    /// needs to handle.
    pub fn push(&mut self, wire_bytes: &[u8]) -> Result<Option<Vec<u8>>, DirWireError> {
        let fragment: Fragment =
            decode_fragment(wire_bytes).map_err(|e: FragmentError| err(format!("not a valid directory-protocol fragment: {e}")))?;
        let chunk = self.reassembler.push(&fragment).map_err(|e| err(e.to_string()))?;
        if self.buffer.len() + chunk.len() > MAX_REASSEMBLED_LEN {
            return Err(err(format!("reassembled directory message exceeds {MAX_REASSEMBLED_LEN} bytes; dropping stream")));
        }
        self.buffer.extend(chunk);
        if self.reassembler.finished() {
            return Ok(Some(std::mem::take(&mut self.buffer)));
        }
        Ok(None)
    }
}

impl Default for DirReassembler {
    fn default() -> Self {
        Self::new(64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::CreateOptions;

    fn make_descriptor(version: u8) -> RelayDescriptor {
        let identity_private = [7u8; 32];
        let static_public = vec![9u8; 32];
        RelayDescriptor::create(
            &identity_private,
            static_public,
            "198.51.100.7",
            9001,
            vec!["guard".to_string(), "middle".to_string()],
            3600.0,
            None,
            CreateOptions { version: Some(version), ..Default::default() },
        )
        .unwrap()
    }

    #[test]
    fn descriptor_round_trip_v1() {
        let d = make_descriptor(DESCRIPTOR_VERSION_1);
        let encoded = encode_descriptor(&d).unwrap();
        let (decoded, consumed) = decode_descriptor(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, d);
    }

    #[test]
    fn descriptor_round_trip_v2_with_extensions() {
        let identity_private = [11u8; 32];
        let static_public = vec![13u8; 32];
        let d = RelayDescriptor::create(
            &identity_private,
            static_public,
            "203.0.113.9",
            9002,
            vec!["exit".to_string()],
            3600.0,
            None,
            CreateOptions { bandwidth: Some(5_000_000), ..Default::default() },
        )
        .unwrap();
        assert_eq!(d.version, DESCRIPTOR_VERSION_2);
        assert!(!d.extensions.is_empty());
        let encoded = encode_descriptor(&d).unwrap();
        let (decoded, consumed) = decode_descriptor(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, d);
        assert_eq!(decoded.bandwidth(), 5_000_000);
    }

    #[test]
    fn decode_descriptor_rejects_truncated_header() {
        let err = decode_descriptor(&[1, 2, 3]).unwrap_err();
        assert!(err.0.contains("truncated"));
    }

    #[test]
    fn decode_descriptor_rejects_oversized_host_len() {
        let mut data = vec![0u8; ED25519_KEY_LEN * 2];
        data.extend_from_slice(&65000u16.to_be_bytes()); // host_len
        data.extend_from_slice(&0u16.to_be_bytes()); // port
        data.extend_from_slice(&0u16.to_be_bytes()); // roles_len
        let err = decode_descriptor(&data).unwrap_err();
        assert!(err.0.contains("host_len"));
    }

    #[test]
    fn publish_request_round_trip() {
        let d = make_descriptor(DESCRIPTOR_VERSION_1);
        let wire = encode_publish_request(&d).unwrap();
        let decoded = decode_publish_request(&wire).unwrap();
        assert_eq!(decoded, d);
    }

    #[test]
    fn publish_request_rejects_wrong_magic() {
        let mut wire = encode_publish_request(&make_descriptor(DESCRIPTOR_VERSION_1)).unwrap();
        wire[0] = b'X';
        let err = decode_publish_request(&wire).unwrap_err();
        assert!(err.0.contains("magic"));
    }

    #[test]
    fn publish_request_rejects_wrong_type() {
        let mut wire = encode_publish_request(&make_descriptor(DESCRIPTOR_VERSION_1)).unwrap();
        wire[4] = FETCH_REQUEST;
        let err = decode_publish_request(&wire).unwrap_err();
        assert!(err.0.contains("expected message type"));
    }

    #[test]
    fn publish_reply_round_trip() {
        let wire = encode_publish_reply(true, "accepted");
        let (ok, message) = decode_publish_reply(&wire).unwrap();
        assert!(ok);
        assert_eq!(message, "accepted");

        let wire2 = encode_publish_reply(false, "rejected: subnet rate limit");
        let (ok2, message2) = decode_publish_reply(&wire2).unwrap();
        assert!(!ok2);
        assert_eq!(message2, "rejected: subnet rate limit");
    }

    #[test]
    fn fetch_request_round_trip_v1_and_v2() {
        let wire_v1 = encode_fetch_request(DESCRIPTOR_VERSION_1);
        assert_eq!(decode_fetch_request(&wire_v1).unwrap(), DESCRIPTOR_VERSION_1);

        let wire_v2 = encode_fetch_request(DESCRIPTOR_VERSION_2);
        assert_eq!(decode_fetch_request(&wire_v2).unwrap(), DESCRIPTOR_VERSION_2);
    }

    #[test]
    fn fetch_reply_round_trip_multiple_descriptors() {
        let d1 = make_descriptor(DESCRIPTOR_VERSION_1);
        let identity_private2 = [21u8; 32];
        let d2 = RelayDescriptor::create(
            &identity_private2,
            vec![22u8; 32],
            "192.0.2.4",
            9003,
            vec!["exit".to_string()],
            3600.0,
            None,
            CreateOptions { bandwidth: Some(1000), ..Default::default() },
        )
        .unwrap();
        let wire = encode_fetch_reply(&[d1.clone(), d2.clone()]).unwrap();
        let decoded = decode_fetch_reply(&wire).unwrap();
        assert_eq!(decoded, vec![d1, d2]);
    }

    #[test]
    fn fetch_reply_empty_round_trip() {
        let wire = encode_fetch_reply(&[]).unwrap();
        let decoded = decode_fetch_reply(&wire).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn fetch_reply_rejects_truncated_descriptor() {
        let d = make_descriptor(DESCRIPTOR_VERSION_1);
        let mut wire = encode_fetch_reply(&[d]).unwrap();
        wire.truncate(wire.len() - 5);
        let err = decode_fetch_reply(&wire).unwrap_err();
        assert!(err.0.contains("truncated"));
    }

    /// Regression test for bug report H7: one malformed descriptor
    /// (stored by an authority or relay less strict than this client --
    /// see the matching test in `Authority`/`Relays`' `dirwire.rs`) used
    /// to fail the *whole* reply, so no client could fetch a directory
    /// that held even a single such entry anywhere in it. Framing is
    /// length-prefixed, so one bad entry can be skipped without losing
    /// sync with the rest of the reply.
    #[test]
    fn fetch_reply_skips_one_malformed_descriptor_instead_of_failing() {
        let good = make_descriptor(DESCRIPTOR_VERSION_1);
        let mut bad = make_descriptor(DESCRIPTOR_VERSION_1);
        bad.roles = vec!["\u{e9}xit".to_string()]; // valid UTF-8, not ASCII
        let wire = encode_fetch_reply(&[good.clone(), bad]).unwrap();
        let decoded = decode_fetch_reply(&wire).unwrap();
        assert_eq!(decoded, vec![good]);
    }

    fn make_hs_descriptor() -> HiddenServiceDescriptor {
        let identity_private = [3u8; 32];
        let encryption_public = vec![4u8; 32];
        let intro_points = vec![IntroPoint {
            relay_identity: vec![5u8; 32],
            host: "198.51.100.9".to_string(),
            port: 9050,
            auth_public: vec![6u8; 32],
        }];
        HiddenServiceDescriptor::create(&identity_private, encryption_public, intro_points, 3600.0, None)
    }

    #[test]
    fn hs_descriptor_round_trip_plain() {
        let d = make_hs_descriptor();
        let encoded = encode_hs_descriptor(&d).unwrap();
        let (decoded, consumed) = decode_hs_descriptor(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, d);
    }

    #[test]
    fn hs_descriptor_round_trip_client_auth() {
        let mut d = make_hs_descriptor();
        d.intro_points.clear();
        d.encrypted_intro_points = vec![0xAA; 100];
        d.auth_ephemeral_public = vec![0xBB; 32];
        d.client_auth = vec![
            ClientAuthEntry { client_id_hint: vec![1u8; 16], wrapped_key: vec![2u8; 48] },
            ClientAuthEntry { client_id_hint: vec![3u8; 16], wrapped_key: vec![4u8; 48] },
        ];
        let encoded = encode_hs_descriptor(&d).unwrap();
        let (decoded, consumed) = decode_hs_descriptor(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, d);
    }

    #[test]
    fn hs_descriptor_rejects_unknown_flag() {
        let d = make_hs_descriptor();
        let mut encoded = encode_hs_descriptor(&d).unwrap();
        encoded[64] = 0x42; // the flag byte, right after the two 32-byte keys
        let err = decode_hs_descriptor(&encoded).unwrap_err();
        assert!(err.0.contains("unknown flag"));
    }

    #[test]
    fn hs_publish_request_round_trip() {
        let d = make_hs_descriptor();
        let wire = encode_hs_publish_request(&d).unwrap();
        let decoded = decode_hs_publish_request(&wire).unwrap();
        assert_eq!(decoded, d);
    }

    #[test]
    fn hs_publish_reply_round_trip() {
        let wire = encode_hs_publish_reply(true, "ok");
        assert_eq!(decode_hs_publish_reply(&wire).unwrap(), (true, "ok".to_string()));
    }

    #[test]
    fn hs_fetch_request_round_trip() {
        let identity = vec![9u8; 32];
        let wire = encode_hs_fetch_request(&identity).unwrap();
        let decoded = decode_hs_fetch_request(&wire).unwrap();
        assert_eq!(decoded, identity);
    }

    #[test]
    fn hs_fetch_request_rejects_wrong_length() {
        let err = encode_hs_fetch_request(&[1, 2, 3]).unwrap_err();
        assert!(err.0.contains("32 bytes"));
    }

    #[test]
    fn hs_fetch_reply_round_trip_found_and_not_found() {
        let d = make_hs_descriptor();
        let wire_found = encode_hs_fetch_reply(Some(&d)).unwrap();
        assert_eq!(decode_hs_fetch_reply(&wire_found).unwrap(), Some(d));

        let wire_not_found = encode_hs_fetch_reply(None).unwrap();
        assert_eq!(decode_hs_fetch_reply(&wire_not_found).unwrap(), None);
    }

    #[test]
    fn fragment_and_reassemble_small_message_one_fragment() {
        let wire = encode_publish_reply(true, "ok");
        let fragments = fragment_message(&wire, 256);
        assert_eq!(fragments.len(), 1);
        let mut r = DirReassembler::new(64);
        let out = r.push(&fragments[0]).unwrap();
        assert_eq!(out, Some(wire));
        assert!(r.finished());
    }

    #[test]
    fn fragment_and_reassemble_large_message_many_fragments() {
        let d = make_descriptor(DESCRIPTOR_VERSION_1);
        let mut descriptors = Vec::new();
        for _ in 0..20 {
            descriptors.push(d.clone());
        }
        let wire = encode_fetch_reply(&descriptors).unwrap();
        let fragments = fragment_message(&wire, 64);
        assert!(fragments.len() > 1, "expected multiple fragments for a large message");

        let mut r = DirReassembler::new(64);
        let mut result = None;
        for (i, frag) in fragments.iter().enumerate() {
            let out = r.push(frag).unwrap();
            if i + 1 < fragments.len() {
                assert!(out.is_none());
            } else {
                result = out;
            }
        }
        assert_eq!(result, Some(wire));
    }

    #[test]
    fn fragment_and_reassemble_out_of_order() {
        let wire = encode_publish_reply(false, "rejected");
        let fragments = fragment_message(&wire, 5);
        assert!(fragments.len() > 1);
        let mut r = DirReassembler::new(64);
        // Feed in reverse order.
        let mut result = None;
        for frag in fragments.iter().rev() {
            result = r.push(frag).unwrap();
        }
        assert_eq!(result, Some(wire));
    }

    #[test]
    fn dir_reassembler_rejects_garbage() {
        let mut r = DirReassembler::new(64);
        let err = r.push(&[0u8; 2]).unwrap_err();
        assert!(err.0.contains("not a valid"));
    }

    #[test]
    fn dir_reassembler_rejects_wrong_stream() {
        let frag = Fragment { stream_id: 999, offset: 0, fin: true, data: b"x".to_vec() };
        let wire = encode_fragment(&frag);
        let mut r = DirReassembler::new(64);
        let err = r.push(&wire).unwrap_err();
        assert!(err.0.contains("does not match"));
    }

    #[test]
    fn dir_reassembler_rejects_message_exceeding_max_reassembled_len() {
        let mut r = DirReassembler::new(64);
        let first = Fragment { stream_id: DIR_STREAM_ID, offset: 0, fin: false, data: vec![0x41u8; MAX_REASSEMBLED_LEN] };
        assert_eq!(r.push(&encode_fragment(&first)).unwrap(), None);
        let second = Fragment { stream_id: DIR_STREAM_ID, offset: MAX_REASSEMBLED_LEN as u32, fin: true, data: vec![0x42u8] };
        assert!(r.push(&encode_fragment(&second)).is_err());
    }

    // -- version 3 (blinded) messages -------------------------------------------

    fn sample_blinded(ct_len: usize) -> crate::hsblind::BlindedDescriptor {
        crate::hsblind::BlindedDescriptor {
            blinded_public: [1u8; 32],
            period: 19_700,
            not_before: 1000.5,
            not_after: 4600.5,
            salt: [2u8; crate::hsblind::SALT_LEN],
            ciphertext: vec![3u8; ct_len],
            signature: vec![4u8; 64],
        }
    }

    #[test]
    fn blinded_descriptor_round_trips() {
        for ct_len in [0usize, 1, 100, 5000] {
            let d = sample_blinded(ct_len);
            let wire = encode_blinded_descriptor(&d).unwrap();
            let (back, consumed) = decode_blinded_descriptor(&wire).unwrap();
            assert_eq!(consumed, wire.len());
            assert_eq!(back, d);
        }
        let extreme = sample_blinded(crate::hsblind::MAX_CIPHERTEXT_LEN);
        let wire = encode_blinded_descriptor(&extreme).unwrap();
        assert_eq!(decode_blinded_descriptor(&wire).unwrap().0, extreme);
    }

    #[test]
    fn every_hs3_message_round_trips() {
        let d = sample_blinded(300);
        assert_eq!(decode_hs3_publish_request(&encode_hs3_publish_request(&d).unwrap()).unwrap(), d);
        assert_eq!(decode_hs3_publish_reply(&encode_hs3_publish_reply(true, "stored")).unwrap(), (true, "stored".to_string()));
        assert_eq!(decode_hs3_publish_reply(&encode_hs3_publish_reply(false, "nope")).unwrap(), (false, "nope".to_string()));
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
        // a declared ciphertext far over the maximum is refused before anything is allocated
        let mut wire = encode_blinded_descriptor(&sample_blinded(10)).unwrap();
        wire[BLINDED_FIXED_LEN - 4..BLINDED_FIXED_LEN].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_blinded_descriptor(&wire).is_err());
        // the maximum is allowed, one over is not
        assert!(encode_blinded_descriptor(&sample_blinded(crate::hsblind::MAX_CIPHERTEXT_LEN + 1)).is_err());
        // trailing bytes after a descriptor in a whole message
        let mut publish = encode_hs3_publish_request(&sample_blinded(10)).unwrap();
        publish.push(0);
        assert!(decode_hs3_publish_request(&publish).is_err());
        let mut reply = encode_hs3_fetch_reply(Some(&sample_blinded(10))).unwrap();
        reply.push(0);
        assert!(decode_hs3_fetch_reply(&reply).is_err());
        // non-finite validity times
        for (offset, name) in [(40usize, "not_before"), (48, "not_after")] {
            for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
                let mut w = encode_blinded_descriptor(&sample_blinded(10)).unwrap();
                w[offset..offset + 8].copy_from_slice(&bad.to_be_bytes());
                assert!(decode_blinded_descriptor(&w).is_err(), "{name} = {bad} accepted");
            }
        }
        // wrong message type and bad magic
        let good = encode_hs3_fetch_request(&[1u8; 32]);
        let mut wrong_type = good.clone();
        wrong_type[4] = HS_FETCH_REQUEST;
        assert!(decode_hs3_fetch_request(&wrong_type).is_err());
        let mut bad_magic = good;
        bad_magic[0] ^= 1;
        assert!(decode_hs3_fetch_request(&bad_magic).is_err());
        // a fetch request is exactly header + 32 bytes
        let mut long = encode_hs3_fetch_request(&[1u8; 32]);
        long.push(0);
        assert!(decode_hs3_fetch_request(&long).is_err());
    }

    /// Nothing identifying survives onto the wire: build a real descriptor for
    /// a real identity and check its publish message for the identity key, the
    /// inner contents and the address.
    #[test]
    fn a_real_hs3_publish_message_names_neither_the_service_nor_its_contents() {
        use crate::hiddenservice::{HiddenServiceDescriptor, IntroPoint};
        let seed = [0x42u8; 32];
        let identity = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let intro = vec![IntroPoint { relay_identity: vec![7u8; 32], host: "192.0.2.55".to_string(), port: 9001, auth_public: vec![8u8; 32] }];
        let inner = HiddenServiceDescriptor::create(&seed, vec![0x99u8; 32], intro, 3600.0, Some(1_700_000_000.0));
        let period = crate::hiddenservice::hs_directory_period(Some(1_700_000_000.0), None);
        let outer = crate::hsblind::seal_descriptor(&seed, &inner, period).unwrap();
        let wire = encode_hs3_publish_request(&outer).unwrap();
        let contains = |needle: &[u8]| wire.windows(needle.len()).any(|w| w == needle);
        assert!(!contains(&identity));
        assert!(!contains(crate::hiddenservice::encode_address(&identity).unwrap().as_bytes()));
        assert!(!contains(&[0x99u8; 32]) && !contains(b"192.0.2.55") && !contains(&[7u8; 32]) && !contains(&[8u8; 32]));
        // and the request a client sends names only the blinded key
        let request = encode_hs3_fetch_request(&outer.blinded_public);
        assert!(!request.windows(32).any(|w| w == identity));
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
