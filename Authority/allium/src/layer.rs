//! The header that frames each onion layer.
//!
//! A header is 29 bytes in two parts. The *wire* part is cleartext -- what
//! a relay must read before it can decrypt anything -- and is bound to the
//! layer as AEAD associated data. The *sealed* part is the first 7 bytes
//! of the layer's AEAD plaintext, so only the relay holding this hop's key
//! learns what kind of layer this is or which address it names:
//!
//! ```text
//! wire (cleartext, 22 bytes -- WIRE_HEADER_SIZE)
//! +-------+--------+------------+-----+-----------+
//! | seq   | length | reserved   | ver | mac       |
//! | 4     | 2      | 4          | 1   | 11        |
//! +-------+--------+------------+-----+-----------+
//!   0       4        6            10    11       (22)
//!
//! sealed (inside the AEAD ciphertext, 7 bytes -- SEALED_HEADER_SIZE)
//! +------+--------+
//! | kind | addr   |   ... followed by the layer's body
//! | 1    | 6      |
//! +------+--------+
//!   0      1      (7)
//! ```
//!
//! Layer format `0xA3` and earlier put `kind` and `addr` in the cleartext
//! part, so every link showed a passive observer the address of the hop
//! *after* the one it was tapping -- and on the middle-to-exit link, the
//! final destination. Moving those seven bytes under the AEAD is what
//! format `0xA4` is. This file must frame layers byte-for-byte like the
//! Client crate's `layer.rs`; keep the two in step.

use crate::hashutil::{constant_time_eq, hmac_sha256};
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

pub use crate::sizes::{HEADER_FORMAT, ROUTE_HEADER_SIZE, SEALED_HEADER_FORMAT, SEALED_HEADER_SIZE, WIRE_HEADER_SIZE};

pub const MAC_SIZE: usize = 32;
pub const MAC_TRUNCATED_SIZE: usize = 11;
pub const HEADER_LENGTH_SIZE: usize = 2;
pub const FINAL_ADDR_SIZE: usize = 6;

/// Largest value the 2-byte header length can express.
pub const HEADER_MAX_PAYLOAD: u32 = 0xFFFF;

/// Version of the layer wire format this build speaks.
///
/// Bumped to `0xA2`: the header
/// layout is unchanged, but the value placed in the `seq` field
/// (`onion.rs`'s per-hop mask) changed from a linear XOR to a keyed PRP,
/// so a peer on the old scheme and one on the new scheme compute different
/// wire `seq` values for the same logical cell and must not be allowed to
/// silently "authenticate" against each other's headers.
///
/// Bumped again to `0xA3`: the selective-ack bitmap carried in an ACK
/// layer's payload widened from 32 to 128 bits (see
/// `crate::reliability::SACK_BITS`), changing [`ACK_WIRE_SIZE`] from 8 to
/// 20 bytes. The header field itself is unchanged, but a node still on
/// the 8-byte ack payload and one now on the 20-byte one would otherwise
/// silently misparse each other's ack cells instead of failing loudly.
/// Every node that runs the ack/congestion layer (client and exit) must
/// upgrade together.
///
/// Bumped to `0xA4`: `kind` and `addr` moved out of the cleartext header
/// and into the AEAD plaintext (see the module doc), the redundant inner
/// header a ROUTE layer used to carry is gone, and the wire header shrank
/// from 29 to 22 bytes -- so the `ver` byte itself moved from offset 11 to
/// offset 10. An `0xA3` cell has a reserved zero at offset 10, so this
/// build reads it as version `0x00` and rejects it cleanly.
pub const LAYER_PROTOCOL_VERSION: u8 = 0xA4;

/// Every build that predates `0xA4` writes something at or below this at
/// the `ver` offset: `0xA1`..`0xA3` had reserved zero bytes there, and the
/// builds before versioning had a hop ordinal one byte further along.
const MAX_UNVERSIONED: u8 = 0x0F;
const RESERVED_HOP_ID: u32 = 0;
/// Offset of the `ver` byte within the wire header.
const VERSION_OFFSET: usize = 4 + 2 + 4;
/// Placeholders [`LayerHeader::unpack`] leaves in the sealed-part fields
/// until [`LayerHeader::unpack_sealed`] fills them in. Kind 0 is not a
/// defined kind, so an unsealed header cannot pass for a real one.
const UNSEALED_KIND: u8 = 0;
const UNSEALED_ADDR: (&str, u16) = ("0.0.0.0", 0);

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

/// Raised when a layer header is malformed or fails its integrity check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderError {
    Malformed(String),
    Version(LayerVersionError),
}
impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderError::Malformed(s) => write!(f, "{s}"),
            HeaderError::Version(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for HeaderError {}
impl From<LayerVersionError> for HeaderError {
    fn from(e: LayerVersionError) -> Self {
        HeaderError::Version(e)
    }
}

fn malformed(msg: impl Into<String>) -> HeaderError {
    HeaderError::Malformed(msg.into())
}

/// Raised when a header declares a layer format this build cannot read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerVersionError {
    pub message: String,
    pub observed: u8,
}
impl fmt::Display for LayerVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for LayerVersionError {}

fn version_mismatch_message(observed: u8) -> String {
    if observed <= MAX_UNVERSIONED {
        format!(
            "peer speaks a pre-0xA4 layer format (ver byte {observed:#04x}), \
             this build speaks {LAYER_PROTOCOL_VERSION:#04x}. Older formats put \
             the layer kind and address in the cleartext header and keep their \
             version byte one offset further along, so the two sides frame \
             layers differently and every cell between them fails to parse. \
             This is not an attack: upgrade the peer, or run this node on the \
             older build. Every node on a circuit must speak the same layer \
             format -- there is no mixed-version mode."
        )
    } else {
        format!(
            "peer speaks layer format {observed:#04x}, this build speaks \
             {LAYER_PROTOCOL_VERSION:#04x}. Every node on a circuit must speak the \
             same layer format; align the builds on both sides."
        )
    }
}

// --------------------------------------------------------------------------
// Kind
// --------------------------------------------------------------------------

/// Layer kinds. Plain constants, unlike cell commands, because relays must be
/// able to read an unknown kind and act on it rather than reject the datagram.
pub struct Kind;
impl Kind {
    pub const ROUTE: u8 = 1;
    pub const PAYLOAD: u8 = 2;
    pub const ACK: u8 = 3;
    pub const EXTEND: u8 = 4;
    pub const EXTENDED: u8 = 5;
    pub const PADDING: u8 = 6;

    pub fn name(value: u8) -> String {
        match value {
            Kind::ROUTE => "ROUTE".to_string(),
            Kind::PAYLOAD => "PAYLOAD".to_string(),
            Kind::ACK => "ACK".to_string(),
            Kind::EXTEND => "EXTEND".to_string(),
            Kind::EXTENDED => "EXTENDED".to_string(),
            Kind::PADDING => "PADDING".to_string(),
            other => format!("UNKNOWN({other})"),
        }
    }

    pub fn is_known(value: u8) -> bool {
        matches!(value, Kind::ROUTE | Kind::PAYLOAD | Kind::ACK | Kind::EXTEND | Kind::EXTENDED | Kind::PADDING)
    }
}

// --------------------------------------------------------------------------
// Address helpers
// --------------------------------------------------------------------------

fn encode_addr(addr: &(String, u16)) -> Result<[u8; 6], HeaderError> {
    let ip = Ipv4Addr::from_str(&addr.0)
        .map_err(|e| malformed(format!("could not parse IPv4 address {:?}: {e}", addr.0)))?;
    let mut out = [0u8; 6];
    out[..4].copy_from_slice(&ip.octets());
    out[4..].copy_from_slice(&addr.1.to_be_bytes());
    Ok(out)
}

fn decode_addr(raw: &[u8]) -> Result<(String, u16), HeaderError> {
    if raw.len() != FINAL_ADDR_SIZE {
        return Err(malformed(format!("address field must be {FINAL_ADDR_SIZE} bytes, got {}", raw.len())));
    }
    let ip = Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]);
    let port = u16::from_be_bytes([raw[4], raw[5]]);
    Ok((ip.to_string(), port))
}

// --------------------------------------------------------------------------
// LayerHeader
// --------------------------------------------------------------------------

const PADDED_FLAG: u8 = 0x80;
const MAX_KIND: u8 = PADDED_FLAG - 1;

/// The 29-byte header framing one onion layer: 22 bytes on the wire ahead
/// of the ciphertext, 7 bytes sealed at the front of the plaintext.
#[derive(Debug, Clone)]
pub struct LayerHeader {
    pub seq: u32,
    /// Sealed: only readable after the layer has been decrypted.
    pub kind: u8,
    /// Sealed, like `kind`.
    pub next_hop: (String, u16),
    pub mac: Vec<u8>,
    /// How many bytes of AEAD ciphertext follow the wire header.
    pub length: u32,
    /// Carried in the sealed `kind` byte's top bit.
    pub padded: bool,
    addr_bytes: [u8; 6],
}

/// Kinds whose address slot names a real target rather than a next relay.
const TARGET_KINDS: [u8; 4] = [Kind::PAYLOAD, Kind::EXTEND, Kind::EXTENDED, Kind::PADDING];

impl LayerHeader {
    /// Build a new header. `mac` may be empty (still to be computed).
    pub fn new(
        seq: u32,
        kind: u8,
        next_hop: (String, u16),
        mac: Vec<u8>,
        length: Option<u32>,
        padded: bool,
    ) -> Result<LayerHeader, HeaderError> {
        if kind > MAX_KIND {
            return Err(malformed(format!("kind {kind} out of range 0..{MAX_KIND}")));
        }
        let addr_bytes = encode_addr(&next_hop)?;
        if !mac.is_empty() && mac.len() != MAC_TRUNCATED_SIZE {
            return Err(malformed(format!("mac must be {MAC_TRUNCATED_SIZE} bytes, got {}", mac.len())));
        }
        let length = length.unwrap_or(ROUTE_HEADER_SIZE as u32);
        if length > HEADER_MAX_PAYLOAD {
            return Err(malformed(format!("length {length} out of range 0..{HEADER_MAX_PAYLOAD}")));
        }
        Ok(LayerHeader { seq, kind, next_hop, mac, length, padded, addr_bytes })
    }

    pub fn is_route(&self) -> bool {
        self.kind == Kind::ROUTE
    }

    /// The target address carried by a PAYLOAD, EXTEND, EXTENDED, or PADDING layer.
    pub fn target_addr(&self) -> Result<(String, u16), HeaderError> {
        if !TARGET_KINDS.contains(&self.kind) {
            return Err(malformed(format!(
                "layer kind {} has no target address; only PAYLOAD, EXTEND, EXTENDED, and PADDING layers carry one",
                Kind::name(self.kind)
            )));
        }
        Ok(self.next_hop.clone())
    }

    /// Serialize the cleartext part to [`WIRE_HEADER_SIZE`] (22) bytes:
    /// seq, length, reserved, ver, mac. `kind`, `padded` and the address
    /// are *not* here -- see [`LayerHeader::pack_sealed`].
    pub fn pack(&self, seq_override: Option<u32>) -> Vec<u8> {
        let seq = seq_override.unwrap_or(self.seq);
        let mut mac_field = [0u8; MAC_TRUNCATED_SIZE];
        mac_field[..self.mac.len()].copy_from_slice(&self.mac);

        let mut out = Vec::with_capacity(WIRE_HEADER_SIZE);
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&(self.length as u16).to_be_bytes());
        out.extend_from_slice(&RESERVED_HOP_ID.to_be_bytes());
        debug_assert_eq!(out.len(), VERSION_OFFSET);
        out.push(LAYER_PROTOCOL_VERSION);
        out.extend_from_slice(&mac_field);
        out
    }

    /// Serialize the sealed part to [`SEALED_HEADER_SIZE`] (7) bytes: the
    /// `kind` byte with `padded` in its top bit, then the 6-byte address.
    /// The sealer puts these at the front of the plaintext it encrypts.
    pub fn pack_sealed(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SEALED_HEADER_SIZE);
        out.push(self.kind | if self.padded { PADDED_FLAG } else { 0 });
        out.extend_from_slice(&self.addr_bytes);
        out
    }

    /// Serialize the wire part with the MAC field zeroed, as input to the
    /// MAC computation and as the layer's AEAD associated data.
    pub fn pack_unsigned(&self, seq_override: Option<u32>) -> Vec<u8> {
        let mut this = self.clone();
        this.mac = Vec::new();
        this.pack(seq_override)
    }

    /// Parse the leading 22 bytes of `data` into a [`LayerHeader`].
    ///
    /// Only the cleartext fields are known at this point; `kind`, `padded`
    /// and `next_hop` are placeholders (kind `0`, `0.0.0.0:0`) until the
    /// caller has decrypted the layer and handed its plaintext to
    /// [`LayerHeader::unpack_sealed`]. The version byte is checked before
    /// anything else.
    pub fn unpack(data: &[u8]) -> Result<LayerHeader, HeaderError> {
        if data.len() < WIRE_HEADER_SIZE {
            return Err(malformed(format!(
                "need at least {WIRE_HEADER_SIZE} bytes for a layer header, got {}",
                data.len()
            )));
        }
        let seq = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]) as u32;
        let _reserved = u32::from_be_bytes([data[6], data[7], data[8], data[9]]);
        let version = data[VERSION_OFFSET];
        let mac = data[VERSION_OFFSET + 1..VERSION_OFFSET + 1 + MAC_TRUNCATED_SIZE].to_vec();

        if version != LAYER_PROTOCOL_VERSION {
            return Err(LayerVersionError { message: version_mismatch_message(version), observed: version }.into());
        }
        let next_hop = (UNSEALED_ADDR.0.to_string(), UNSEALED_ADDR.1);
        LayerHeader::new(seq, UNSEALED_KIND, next_hop, mac, Some(length), false)
    }

    /// Fill in `kind`, `padded` and `next_hop` from the leading
    /// [`SEALED_HEADER_SIZE`] bytes of a decrypted layer's plaintext.
    pub fn unpack_sealed(&mut self, plaintext: &[u8]) -> Result<(), HeaderError> {
        if plaintext.len() < SEALED_HEADER_SIZE {
            return Err(malformed(format!(
                "need at least {SEALED_HEADER_SIZE} bytes for the sealed part of a layer header, got {}",
                plaintext.len()
            )));
        }
        let sealed_kind = plaintext[0];
        let addr = &plaintext[1..1 + FINAL_ADDR_SIZE];
        self.padded = sealed_kind & PADDED_FLAG != 0;
        self.kind = sealed_kind & MAX_KIND;
        self.next_hop = decode_addr(addr)?;
        self.addr_bytes.copy_from_slice(addr);
        Ok(())
    }

    /// Return the truncated HMAC-SHA256 over this header and `sealed`.
    pub fn compute_mac(&self, mac_key: &[u8], sealed: &[u8], seq_override: Option<u32>) -> Vec<u8> {
        let mut input = self.pack_unsigned(seq_override);
        input.extend_from_slice(sealed);
        let digest = hmac_sha256(mac_key, &input);
        digest[..MAC_TRUNCATED_SIZE].to_vec()
    }

    /// Constant-time check of `self.mac` against the recomputed value.
    pub fn verify_mac(&self, mac_key: &[u8], sealed: &[u8], seq_override: Option<u32>) -> bool {
        if self.mac.len() != MAC_TRUNCATED_SIZE {
            return false;
        }
        constant_time_eq(&self.mac, &self.compute_mac(mac_key, sealed, seq_override))
    }

    /// Return a copy of this header with a valid MAC attached.
    pub fn signed(&self, mac_key: &[u8], sealed: &[u8], seq_override: Option<u32>) -> LayerHeader {
        let mut clone = LayerHeader::new(
            self.seq,
            self.kind,
            self.next_hop.clone(),
            Vec::new(),
            Some(self.length),
            self.padded,
        )
        .expect("cloning a valid header cannot fail");
        clone.mac = clone.compute_mac(mac_key, sealed, seq_override);
        clone
    }
}

impl PartialEq for LayerHeader {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq && self.kind == other.kind && self.next_hop == other.next_hop
    }
}
impl Eq for LayerHeader {}

impl fmt::Display for LayerHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LayerHeader(seq={}, kind={}, addr={:?}, padded={})",
            self.seq,
            Kind::name(self.kind),
            self.next_hop,
            self.padded
        )
    }
}

// --------------------------------------------------------------------------
// Acknowledgements
// --------------------------------------------------------------------------

/// An ack is a 32-bit cumulative edge followed by a
/// `crate::reliability::SACK_BITS`-bit (128-bit) selective-ack bitmap:
/// 4 + 16 = 20 bytes.
pub const ACK_WIRE_SIZE: usize = 20;
pub const ACK_FORMAT: &str = ">I16s";

/// A decoded acknowledgement: a cumulative edge and a selective-ack bitmap.
///
/// Canonical definition lives in `crate::reliability::AckState` (Phase 2);
/// re-exported here under `layer::AckState` since that's where Python's
/// `layer.decode_ack` / `layer.encode_ack` live and what they return/accept.
pub use crate::reliability::AckState;

/// Serialize an acknowledgement into [`ACK_WIRE_SIZE`] (20) bytes.
pub fn encode_ack(cumulative: u32, bitmap: u128) -> Vec<u8> {
    let mut out = Vec::with_capacity(ACK_WIRE_SIZE);
    out.extend_from_slice(&cumulative.to_be_bytes());
    out.extend_from_slice(&bitmap.to_be_bytes());
    out
}

/// Parse an ack from the first [`ACK_WIRE_SIZE`] bytes of `data`.
pub fn decode_ack(data: &[u8]) -> Result<AckState, HeaderError> {
    if data.len() < ACK_WIRE_SIZE {
        return Err(malformed(format!("need at least {ACK_WIRE_SIZE} bytes for an ack, got {}", data.len())));
    }
    let cumulative = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let bitmap = u128::from_be_bytes(data[4..20].try_into().expect("checked len >= ACK_WIRE_SIZE (20) above"));
    Ok(AckState::new(cumulative, bitmap))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop() -> (String, u16) {
        ("10.0.0.1".to_string(), 9001)
    }

    #[test]
    fn test_header_size_is_29() {
        let h = LayerHeader::new(1, Kind::ROUTE, hop(), Vec::new(), None, false).unwrap();
        assert_eq!(h.pack(None).len(), WIRE_HEADER_SIZE);
        assert_eq!(h.pack_sealed().len(), SEALED_HEADER_SIZE);
        assert_eq!(WIRE_HEADER_SIZE + SEALED_HEADER_SIZE, ROUTE_HEADER_SIZE);
    }

    #[test]
    fn test_pack_unpack_roundtrip() {
        let h = LayerHeader::new(42, Kind::ROUTE, hop(), vec![0u8; 11], Some(100), false).unwrap();
        let packed = h.pack(None);
        let mut back = LayerHeader::unpack(&packed).unwrap();
        // Only the cleartext fields are known before the sealed part is
        // applied, and the placeholder kind must not look like a real one.
        assert_eq!(back.length, 100);
        assert!(!Kind::is_known(back.kind));
        back.unpack_sealed(&h.pack_sealed()).unwrap();
        assert_eq!(back, h);
        assert_eq!(back.next_hop, hop());
    }

    /// Byte-for-byte layout fixture, shared with the Client crate's
    /// `layer.rs` (`plain_route_header_matches_layout`): the two crates
    /// must frame identically.
    #[test]
    fn test_wire_layout_matches_client_crate() {
        let h = LayerHeader::new(42, Kind::ROUTE, hop(), vec![7u8; 11], None, false).unwrap();
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(hex(&h.pack(None)), "0000002a001d00000000a40707070707070707070707");
        assert_eq!(hex(&h.pack_sealed()), "010a0000012329");
    }

    #[test]
    fn test_wire_header_carries_no_kind_or_address() {
        let h = LayerHeader::new(1, Kind::PAYLOAD, ("203.0.113.9".to_string(), 443), Vec::new(), None, true).unwrap();
        let packed = h.pack(None);
        for window in packed.windows(2) {
            assert_ne!(window, [0xcb, 0x00]);
            assert_ne!(window, [0x01, 0xbb]);
        }
        assert!(!packed.contains(&(Kind::PAYLOAD | PADDED_FLAG)));
        assert_eq!(h.pack_sealed(), vec![0x82, 0xcb, 0x00, 0x71, 0x09, 0x01, 0xbb]);
    }

    #[test]
    fn test_pack_writes_protocol_version() {
        let h = LayerHeader::new(1, Kind::ROUTE, hop(), Vec::new(), None, false).unwrap();
        let packed = h.pack(None);
        assert_eq!(packed[VERSION_OFFSET], LAYER_PROTOCOL_VERSION);
    }

    #[test]
    fn test_unpack_rejects_wrong_version() {
        let h = LayerHeader::new(1, Kind::ROUTE, hop(), Vec::new(), None, false).unwrap();
        let mut packed = h.pack(None);
        packed[VERSION_OFFSET] = 0x01;
        let err = LayerHeader::unpack(&packed).unwrap_err();
        assert!(matches!(err, HeaderError::Version(_)));
    }

    /// A `0xA3` header has its version at offset 11 and a reserved zero at
    /// offset 10, where this build looks: refused as a version mismatch,
    /// not misparsed.
    #[test]
    fn test_unpack_rejects_pre_0xa4_header_as_version_mismatch() {
        let mut legacy = [0u8; 29];
        legacy[4] = Kind::ROUTE;
        legacy[11] = 0xA3;
        match LayerHeader::unpack(&legacy).unwrap_err() {
            HeaderError::Version(v) => {
                assert_eq!(v.observed, 0x00);
                assert!(v.message.contains("pre-0xA4"), "{}", v.message);
            }
            other => panic!("expected Version error, got {other:?}"),
        }
    }

    #[test]
    fn test_unpack_rejects_short_data() {
        assert!(LayerHeader::unpack(&[0u8; 10]).is_err());
        let h = LayerHeader::new(1, Kind::ROUTE, hop(), Vec::new(), None, false).unwrap();
        let mut back = LayerHeader::unpack(&h.pack(None)).unwrap();
        assert!(back.unpack_sealed(&[0u8; 6]).is_err());
    }

    #[test]
    fn test_padded_flag_roundtrips() {
        let h = LayerHeader::new(1, Kind::PAYLOAD, hop(), Vec::new(), None, true).unwrap();
        let mut back = LayerHeader::unpack(&h.pack(None)).unwrap();
        back.unpack_sealed(&h.pack_sealed()).unwrap();
        assert!(back.padded);
        assert_eq!(back.kind, Kind::PAYLOAD);
    }

    #[test]
    fn test_kind_out_of_range_rejected() {
        assert!(LayerHeader::new(1, 0x80, hop(), Vec::new(), None, false).is_err());
    }

    #[test]
    fn test_reserved_bytes_are_zero_on_wire() {
        let h = LayerHeader::new(1, Kind::ROUTE, hop(), Vec::new(), None, false).unwrap();
        let packed = h.pack(None);
        assert_eq!(&packed[6..10], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_target_addr_for_payload() {
        let h = LayerHeader::new(1, Kind::PAYLOAD, hop(), Vec::new(), None, false).unwrap();
        assert_eq!(h.target_addr().unwrap(), hop());
    }

    #[test]
    fn test_target_addr_rejected_for_route() {
        let h = LayerHeader::new(1, Kind::ROUTE, hop(), Vec::new(), None, false).unwrap();
        assert!(h.target_addr().is_err());
    }

    #[test]
    fn test_compute_and_verify_mac() {
        let h = LayerHeader::new(1, Kind::ROUTE, hop(), Vec::new(), None, false).unwrap();
        let key = b"a-secret-mac-key";
        let sealed = b"sealed-payload-bytes";
        let signed = h.signed(key, sealed, None);
        assert!(signed.verify_mac(key, sealed, None));
        assert!(!signed.verify_mac(b"wrong-key-------", sealed, None));
    }

    #[test]
    fn test_verify_mac_fails_on_tampered_sealed() {
        let h = LayerHeader::new(1, Kind::ROUTE, hop(), Vec::new(), None, false).unwrap();
        let key = b"a-secret-mac-key";
        let signed = h.signed(key, b"original", None);
        assert!(!signed.verify_mac(key, b"tampered", None));
    }

    #[test]
    fn test_verify_mac_false_for_missing_mac() {
        let h = LayerHeader::new(1, Kind::ROUTE, hop(), Vec::new(), None, false).unwrap();
        assert!(!h.verify_mac(b"key", b"sealed", None));
    }

    #[test]
    fn test_equality_ignores_mac_and_length() {
        let a = LayerHeader::new(1, Kind::ROUTE, hop(), vec![1u8; 11], Some(50), false).unwrap();
        let b = LayerHeader::new(1, Kind::ROUTE, hop(), vec![2u8; 11], Some(99), true).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_kind_name_known_and_unknown() {
        assert_eq!(Kind::name(Kind::ROUTE), "ROUTE");
        assert_eq!(Kind::name(200), "UNKNOWN(200)");
        assert!(Kind::is_known(Kind::PADDING));
        assert!(!Kind::is_known(99));
    }

    #[test]
    fn test_encode_ack_roundtrip() {
        let raw = encode_ack(4, 0b01);
        assert_eq!(raw.len(), ACK_WIRE_SIZE);
        let state = decode_ack(&raw).unwrap();
        assert_eq!(state.cumulative, 4);
        assert_eq!(state.bitmap, 1);
    }

    #[test]
    fn test_decode_ack_ignores_trailing_bytes() {
        let mut raw = encode_ack(9, 3);
        raw.extend_from_slice(&[9, 9, 9]);
        let state = decode_ack(&raw).unwrap();
        assert_eq!(state.cumulative, 9);
        assert_eq!(state.bitmap, 3);
    }

    #[test]
    fn test_decode_ack_rejects_short_data() {
        assert!(decode_ack(&[0u8; 4]).is_err());
    }
}
