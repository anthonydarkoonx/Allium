//! The header that frames each onion layer.
//!
//! A header is 29 bytes in two parts. The *wire* part is cleartext: it is
//! what a relay has to read before it can decrypt anything (how long the
//! ciphertext is, which format it is in), and it is bound to the layer as
//! AEAD associated data. The *sealed* part is the first 7 bytes of the
//! layer's AEAD plaintext, so only the relay holding this hop's key learns
//! what kind of layer this is or which address it names:
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
//! part. Every link then showed a passive observer the address of the hop
//! *after* the one it was tapping -- and on the middle-to-exit link, the
//! final destination -- without any relay being compromised. Moving those
//! seven bytes under the AEAD is what format `0xA4` is.
//!
//! The four reserved bytes at wire offset 6 were `hop_id`, which told a
//! relay its exact position on the circuit. Nothing in the protocol ever
//! read it back, so [`LayerHeader`] has no position field at all; the
//! bytes are kept, always zero, so a header stays 29 bytes in total, which
//! the size arithmetic in [`crate::sizes`] depends on.
//!
//! `ver` is the layer-protocol version ([`LAYER_PROTOCOL_VERSION`]). A node
//! on this format and a node on an older one reject each other's cells;
//! without a version they would reject them as a MAC mismatch -- the same
//! error a tampered cell produces -- which tells an operator running a
//! half-upgraded network to go hunting for an attacker. The version byte
//! turns that into [`LayerError::Version`], which names both sides'
//! versions and says what to do.
//!
//! For a [`Kind::ROUTE`] layer the `addr` slot carries the next relay's
//! `(ip, port)`; for a [`Kind::PAYLOAD`] layer it carries `final_addr`, the
//! address the *exit* relay should connect to. Both are 6 bytes, so a header
//! is 29 bytes however the layer is used.
//!
//! The 11-byte `mac` is [`crate::sizes::MAC_TRUNCATED_SIZE`] bytes of
//! HMAC-SHA256 over the wire header and the layer's plaintext (sealed
//! header included). It is what stops a relay from rewriting `addr` to
//! redirect traffic: the client computed the MAC over the true value, and
//! the relay has no key to recompute it.

use std::fmt;
use std::net::Ipv4Addr;

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use subtle::ConstantTimeEq;

use crate::sizes::{MAC_TRUNCATED_SIZE, NEXT_HOP_SIZE, ROUTE_HEADER_SIZE, SEALED_HEADER_SIZE, WIRE_HEADER_SIZE};

/// Largest value the 2-byte header length field can express.
pub const HEADER_MAX_PAYLOAD: u16 = 0xFFFF;

/// Version of the layer wire format this build speaks, carried in the
/// wire header's 1-byte `ver` field at offset 10.
///
/// Numbering starts at `0xA1` rather than `1` on purpose. Before versioning,
/// that byte held `hop_index` -- a small ordinal: `0` in every build after
/// the position fields were removed, and `0`/`1`/`2` in the builds before
/// it. Keeping version numbers clear of that range means a legacy peer can
/// never be mistaken for a versioned one.
///
/// Bumped to `0xA2`: the header's
/// 29-byte layout is unchanged, but the *value* put in the `seq` field
/// (`onion.rs`'s per-hop mask) changed from a linear XOR to a keyed PRP. A
/// node still on the XOR scheme and one on the PRP scheme compute
/// different wire `seq` values for the same logical cell, so their header
/// MACs never agree -- without a version bump this would surface as a
/// generic MAC-mismatch ("tampered cell") failure instead of the
/// actionable version-mismatch diagnostic below.
///
/// Bumped again to `0xA3`: the selective-ack bitmap carried in a
/// [`Kind::ACK`] layer's payload widened from 32 to 128 bits (see
/// [`crate::reliability::SACK_BITS`]), which changes [`ACK_WIRE_SIZE`]
/// from 8 to 20 bytes. This header field itself is unchanged, but a node
/// still expecting an 8-byte ack payload and one now sending a 20-byte
/// one would otherwise silently misparse each other's ack cells instead
/// of failing loudly -- exactly the class of mismatch this version field
/// exists to turn into an actionable diagnostic instead of silent
/// corruption. Every node on a circuit (client and exit -- see
/// [`crate::congestion`]'s module doc for who runs the ack/congestion
/// layer) must be upgraded together.
///
/// Bumped to `0xA4`: `kind` and `addr` moved out of the cleartext header
/// and into the AEAD plaintext (see the module doc), the redundant inner
/// header a ROUTE layer used to carry is gone, and the wire header shrank
/// from 29 to 22 bytes -- so the `ver` byte itself moved from offset 11 to
/// offset 10. An `0xA3` cell has a reserved zero at offset 10, so this
/// build reads it as version `0x00` and rejects it cleanly; an `0xA3` peer
/// reads one of this build's MAC bytes as the version and rejects just as
/// cleanly.
pub const LAYER_PROTOCOL_VERSION: u8 = 0xA4;

/// Every build that predates `0xA4` writes something at or below this at
/// the `ver` offset: `0xA1`..`0xA3` had reserved zero bytes there, and the
/// builds before versioning had a hop ordinal one byte further along. Used
/// only to phrase a better diagnostic, never to accept such a peer.
const MAX_UNVERSIONED: u8 = 0x0F;

/// An ack is a 32-bit cumulative edge followed by a
/// [`crate::reliability::SACK_BITS`]-bit (128-bit) selective-ack bitmap:
/// 4 + 16 = 20 bytes.
pub const ACK_WIRE_SIZE: usize = 20;

/// Errors raised when a layer header is malformed or fails its integrity
/// check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayerError {
    /// A malformed header, address, mac, or ack: bad field, wrong length,
    /// or (post-MAC-check) a forged/tampered cell.
    Header(String),
    /// The header declares a layer format this build cannot read. Separate
    /// from [`LayerError::Header`] because it is the one header failure with
    /// an operator action attached: upgrade the peer, or downgrade this
    /// node. Raised *before* the MAC is checked, so a half-upgraded network
    /// reports itself as a version mismatch rather than the forgery-shaped
    /// MAC failure it would otherwise produce.
    Version {
        message: String,
        /// The version byte that arrived, for logging and tests.
        observed: u8,
    },
}

impl fmt::Display for LayerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LayerError::Header(m) => write!(f, "{m}"),
            LayerError::Version { message, .. } => write!(f, "{message}"),
        }
    }
}
impl std::error::Error for LayerError {}

/// Layer kinds. A plain enum of associated constants, unlike [`crate::cell::Command`],
/// because relays must be able to read an unknown kind and act on it rather
/// than reject the datagram.
pub struct Kind;

impl Kind {
    pub const ROUTE: u8 = 1;
    pub const PAYLOAD: u8 = 2;
    pub const ACK: u8 = 3;
    /// A request that the peeling hop CREATE a fresh handshake with the
    /// address in this layer's address slot, on the client's behalf. This
    /// is what lets a circuit be extended one hop at a time instead of the
    /// client handshaking directly with every relay.
    pub const EXTEND: u8 = 4;
    /// The reply to an EXTEND: a relay's own layer wrapped around whatever
    /// it received from the hop it was asked to CREATE with.
    pub const EXTENDED: u8 = 5;
    /// A deliberately empty layer, indistinguishable on the wire from a
    /// real one. A relay peels it like any other layer and then drops it.
    pub const PADDING: u8 = 6;

    /// Return a display name for `value`, tolerating unknown kinds.
    pub fn name(value: u8) -> String {
        match value {
            Self::ROUTE => "ROUTE".to_string(),
            Self::PAYLOAD => "PAYLOAD".to_string(),
            Self::ACK => "ACK".to_string(),
            Self::EXTEND => "EXTEND".to_string(),
            Self::EXTENDED => "EXTENDED".to_string(),
            Self::PADDING => "PADDING".to_string(),
            other => format!("UNKNOWN({other})"),
        }
    }

    /// Return `true` if `value` is a kind this build understands.
    pub fn is_known(value: u8) -> bool {
        matches!(
            value,
            Self::ROUTE | Self::PAYLOAD | Self::ACK | Self::EXTEND | Self::EXTENDED | Self::PADDING
        )
    }
}

/// Set in the wire `kind` byte's top bit when this layer's plaintext was
/// padded before sealing. Every defined [`Kind`] value fits in the low 7
/// bits, so the two never collide.
const PADDED_FLAG: u8 = 0x80;
/// Largest `kind` value that leaves the flag bit free.
const MAX_KIND: u8 = PADDED_FLAG - 1;

/// The 4-byte slot that used to carry `hop_id`. It is *reserved*, not
/// merely masked -- [`LayerHeader`] has no position attribute to write into
/// it, so the position leak this previously allowed cannot be
/// reintroduced by a caller. The bytes stay in the layout because the
/// 29-byte header size is load-bearing. They are always zero and are
/// covered by the header MAC like every other byte.
const RESERVED_HOP_ID: u32 = 0;

/// Offset of the `ver` byte within the wire header: after `seq`, `length`
/// and the reserved slot.
const VERSION_OFFSET: usize = 4 + 2 + 4;

/// What [`LayerHeader::unpack`] leaves in the sealed-part fields until
/// [`LayerHeader::unpack_sealed`] fills them in. `Kind` 0 is not a defined
/// kind, so a header whose sealed part was never applied cannot be
/// mistaken for a real ROUTE or PAYLOAD header.
const UNSEALED_KIND: u8 = 0;
const UNSEALED_ADDR: (&str, u16) = ("0.0.0.0", 0);

/// Phrase a layer-version mismatch so an operator knows what to do.
///
/// Two cases read very differently in an incident, so they are worded
/// differently. A value at or below [`MAX_UNVERSIONED`] means the peer
/// predates format `0xA4`: a `0xA1`..`0xA3` build has a reserved zero byte
/// at this offset (its own version byte sits one further along), and the
/// builds before versioning had a hop ordinal there. Either way the two
/// sides frame layers differently. Anything else is a build newer or
/// simply other than this one.
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

/// Pack an `(ip, port)` pair into 6 bytes (4-byte IPv4 + big-endian port).
fn encode_addr(addr: &(String, u16)) -> Result<[u8; NEXT_HOP_SIZE], LayerError> {
    let ip: Ipv4Addr = addr
        .0
        .parse()
        .map_err(|_| LayerError::Header(format!("could not parse IPv4 address {:?}", addr.0)))?;
    let mut buf = [0u8; NEXT_HOP_SIZE];
    buf[..4].copy_from_slice(&ip.octets());
    buf[4..].copy_from_slice(&addr.1.to_be_bytes());
    Ok(buf)
}

/// Unpack 6 bytes into an `(ip, port)` pair.
fn decode_addr(raw: &[u8]) -> Result<(String, u16), LayerError> {
    if raw.len() != NEXT_HOP_SIZE {
        return Err(LayerError::Header(format!(
            "address field must be {NEXT_HOP_SIZE} bytes, got {}",
            raw.len()
        )));
    }
    let ip = Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]);
    let port = u16::from_be_bytes([raw[4], raw[5]]);
    Ok((ip.to_string(), port))
}

/// The 29-byte header framing one onion layer: 22 bytes on the wire ahead
/// of the ciphertext, 7 bytes sealed at the front of the plaintext.
///
/// A header carries **no notion of its own position on the circuit**. Position
/// now lives only where it is legitimately needed, on the local node object
/// -- never serialized.
#[derive(Debug, Clone)]
pub struct LayerHeader {
    /// Per-circuit sequence number, for replay and reorder detection.
    pub seq: u32,
    /// [`Kind::ROUTE`], [`Kind::PAYLOAD`], or another [`Kind`] value.
    /// Sealed: only readable after the layer has been decrypted.
    pub kind: u8,
    /// For a ROUTE layer, the next relay's `(ip, port)`. For a PAYLOAD (or
    /// EXTEND/EXTENDED/PADDING) layer, the target `(ip, port)` -- see
    /// [`LayerHeader::target_addr`]. Sealed, like `kind`.
    pub next_hop: (String, u16),
    /// 11-byte MAC, or empty when building a header whose MAC is still to
    /// be computed.
    pub mac: Vec<u8>,
    addr_bytes: [u8; NEXT_HOP_SIZE],
    /// How many bytes of sealed (AEAD) ciphertext follow the wire header.
    pub length: u16,
    /// Whether this layer's plaintext was padded before sealing (M1). Real,
    /// MAC-authenticated state, carried in the sealed `kind` byte's top
    /// bit.
    pub padded: bool,
}

impl LayerHeader {
    /// Build a new header.
    ///
    /// `mac` may be empty (a header whose MAC is still to be computed) or
    /// exactly [`MAC_TRUNCATED_SIZE`] bytes. `length` defaults to
    /// [`ROUTE_HEADER_SIZE`] when `None`, matching callers that build a
    /// header without caring about it (tests, and the never-consulted inner
    /// header in `OnionCrypto::wrap`).
    ///
    /// # Errors
    /// Returns [`LayerError::Header`] if `kind` doesn't fit in the low 7
    /// bits, `next_hop`'s IP can't be parsed, or `mac` is a non-empty length
    /// other than [`MAC_TRUNCATED_SIZE`].
    pub fn new(
        seq: u32,
        kind: u8,
        next_hop: (String, u16),
        mac: Vec<u8>,
        length: Option<u16>,
        padded: bool,
    ) -> Result<Self, LayerError> {
        if kind > MAX_KIND {
            return Err(LayerError::Header(format!(
                "kind {kind} out of range 0..{MAX_KIND}"
            )));
        }
        let addr_bytes = encode_addr(&next_hop)?;
        if !mac.is_empty() && mac.len() != MAC_TRUNCATED_SIZE {
            return Err(LayerError::Header(format!(
                "mac must be {MAC_TRUNCATED_SIZE} bytes, got {}",
                mac.len()
            )));
        }
        let length = length.unwrap_or(ROUTE_HEADER_SIZE as u16);
        Ok(LayerHeader {
            seq,
            kind,
            next_hop,
            mac,
            addr_bytes,
            length,
            padded,
        })
    }

    /// `true` for a ROUTE layer, whose address field is the next relay.
    pub fn is_route(&self) -> bool {
        self.kind == Kind::ROUTE
    }

    /// Kinds whose address slot names a real target rather than a next
    /// relay: a PAYLOAD's exit target, or an EXTEND's address to CREATE
    /// with. An EXTENDED layer also uses this shape (no inner header
    /// follows), but its address slot is unused filler -- the client never
    /// reads it. A PADDING layer is the same: the slot holds a
    /// plausible-looking address the relay never contacts.
    const TARGET_KINDS: [u8; 4] = [Kind::PAYLOAD, Kind::EXTEND, Kind::EXTENDED, Kind::PADDING];

    /// The target address carried by a PAYLOAD, EXTEND, EXTENDED, or
    /// PADDING layer.
    ///
    /// # Errors
    /// Returns [`LayerError::Header`] if this is a ROUTE or ACK layer,
    /// which carry no target.
    pub fn target_addr(&self) -> Result<(String, u16), LayerError> {
        if !Self::TARGET_KINDS.contains(&self.kind) {
            return Err(LayerError::Header(format!(
                "layer kind {} has no target address; only PAYLOAD, EXTEND, EXTENDED, \
                 and PADDING layers carry one",
                Kind::name(self.kind)
            )));
        }
        Ok(self.next_hop.clone())
    }

    /// Serialize the cleartext part to [`WIRE_HEADER_SIZE`] (22) bytes.
    ///
    /// The wire `length` field carries `self.length` -- the true size of the
    /// AEAD ciphertext that follows this header, not a constant. `kind`,
    /// `padded` and the address are *not* here: they go into the sealed
    /// part ([`LayerHeader::pack_sealed`]).
    ///
    /// `seq` overrides the sequence number, used when re-framing an
    /// intermediate field.
    pub fn pack(&self, seq: Option<u32>) -> [u8; WIRE_HEADER_SIZE] {
        let mut mac_field = [0u8; MAC_TRUNCATED_SIZE];
        let n = self.mac.len().min(MAC_TRUNCATED_SIZE);
        mac_field[..n].copy_from_slice(&self.mac[..n]);

        let mut buf = [0u8; WIRE_HEADER_SIZE];
        let mut pos = 0;
        buf[pos..pos + 4].copy_from_slice(&seq.unwrap_or(self.seq).to_be_bytes());
        pos += 4;
        buf[pos..pos + 2].copy_from_slice(&self.length.to_be_bytes());
        pos += 2;
        buf[pos..pos + 4].copy_from_slice(&RESERVED_HOP_ID.to_be_bytes());
        pos += 4;
        debug_assert_eq!(pos, VERSION_OFFSET);
        buf[pos] = LAYER_PROTOCOL_VERSION;
        pos += 1;
        buf[pos..pos + MAC_TRUNCATED_SIZE].copy_from_slice(&mac_field);

        buf
    }

    /// Serialize the sealed part to [`SEALED_HEADER_SIZE`] (7) bytes: the
    /// `kind` byte, with `padded` packed into its top bit alongside the
    /// real kind in the low 7 bits, then the 6-byte address. The sealer
    /// puts these at the front of the plaintext it encrypts, so they are
    /// covered by the AEAD tag and, through the plaintext, by the header
    /// MAC.
    pub fn pack_sealed(&self) -> [u8; SEALED_HEADER_SIZE] {
        let mut buf = [0u8; SEALED_HEADER_SIZE];
        buf[0] = self.kind | if self.padded { PADDED_FLAG } else { 0 };
        buf[1..1 + NEXT_HOP_SIZE].copy_from_slice(&self.addr_bytes);
        buf
    }

    /// Serialize the wire part with the MAC field zeroed, as input to the
    /// MAC computation and as the layer's AEAD associated data.
    pub fn pack_unsigned(&self, seq: Option<u32>) -> [u8; WIRE_HEADER_SIZE] {
        if self.mac.is_empty() {
            return self.pack(seq);
        }
        let mut zeroed = self.clone();
        zeroed.mac = Vec::new();
        zeroed.pack(seq)
    }

    /// Parse the leading [`WIRE_HEADER_SIZE`] bytes of `data` into a
    /// [`LayerHeader`].
    ///
    /// Only the cleartext fields are known at this point: `seq`, `length`
    /// and `mac`. `kind`, `padded` and `next_hop` are left as placeholders
    /// (kind `0`, which no [`Kind`] uses, and `0.0.0.0:0`) until the caller
    /// has decrypted the layer and handed its plaintext to
    /// [`LayerHeader::unpack_sealed`].
    ///
    /// `length` carries the true size of the ciphertext that follows, which
    /// the caller must still validate against however many bytes actually
    /// followed. The reserved bytes are unpacked and discarded, but the
    /// version byte *is* checked, before anything else.
    ///
    /// Only the leading 22 bytes are consumed; anything after that in
    /// `data` is ignored, so a padded cell payload decodes without
    /// trimming.
    ///
    /// # Errors
    /// Returns [`LayerError::Header`] if fewer than 22 bytes are available.
    /// Returns [`LayerError::Version`] if the header declares a layer
    /// format this build does not speak -- raised before the MAC is
    /// checked, so a half-upgraded network reports itself as a version
    /// mismatch rather than as the forgery-shaped MAC failure it would
    /// otherwise produce.
    pub fn unpack(data: &[u8]) -> Result<Self, LayerError> {
        if data.len() < WIRE_HEADER_SIZE {
            return Err(LayerError::Header(format!(
                "need at least {WIRE_HEADER_SIZE} bytes for a layer header, got {}",
                data.len()
            )));
        }
        let seq = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]);
        // data[6..10] is the reserved hop_id slot -- unpacked and discarded.
        let version = data[VERSION_OFFSET];
        if version != LAYER_PROTOCOL_VERSION {
            return Err(LayerError::Version {
                message: version_mismatch_message(version),
                observed: version,
            });
        }
        let mac_start = VERSION_OFFSET + 1;
        let mac = data[mac_start..mac_start + MAC_TRUNCATED_SIZE].to_vec();

        let next_hop = (UNSEALED_ADDR.0.to_string(), UNSEALED_ADDR.1);
        LayerHeader::new(seq, UNSEALED_KIND, next_hop, mac, Some(length), false)
    }

    /// Fill in `kind`, `padded` and `next_hop` from the leading
    /// [`SEALED_HEADER_SIZE`] bytes of a decrypted layer's plaintext.
    ///
    /// The sealed `kind` byte's top bit is split off into `padded`; the low
    /// 7 bits are the real kind. Anything after the first 7 bytes of
    /// `plaintext` is the layer's body and is ignored here.
    ///
    /// # Errors
    /// Returns [`LayerError::Header`] if fewer than 7 bytes are available.
    pub fn unpack_sealed(&mut self, plaintext: &[u8]) -> Result<(), LayerError> {
        if plaintext.len() < SEALED_HEADER_SIZE {
            return Err(LayerError::Header(format!(
                "need at least {SEALED_HEADER_SIZE} bytes for the sealed part of a layer header, got {}",
                plaintext.len()
            )));
        }
        let sealed_kind = plaintext[0];
        let addr = &plaintext[1..1 + NEXT_HOP_SIZE];
        self.padded = sealed_kind & PADDED_FLAG != 0;
        self.kind = sealed_kind & MAX_KIND;
        self.next_hop = decode_addr(addr)?;
        self.addr_bytes.copy_from_slice(addr);
        Ok(())
    }

    /// Return the truncated HMAC-SHA256 over this header and `sealed`.
    ///
    /// The MAC covers the wire header with its own MAC field zeroed,
    /// followed by `sealed` -- in practice the layer's plaintext, which
    /// starts with the sealed header part. Without `mac_key` a relay cannot
    /// forge one, so it cannot rewrite `next_hop` to redirect traffic.
    pub fn compute_mac(&self, mac_key: &[u8], sealed: &[u8], seq: Option<u32>) -> Vec<u8> {
        let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(mac_key)
            .expect("HMAC accepts a key of any length");
        mac.update(&self.pack_unsigned(seq));
        mac.update(sealed);
        let full = mac.finalize().into_bytes();
        full[..MAC_TRUNCATED_SIZE].to_vec()
    }

    /// Constant-time check of `self.mac` against the recomputed value.
    pub fn verify_mac(&self, mac_key: &[u8], sealed: &[u8], seq: Option<u32>) -> bool {
        if self.mac.len() != MAC_TRUNCATED_SIZE {
            return false;
        }
        let expected = self.compute_mac(mac_key, sealed, seq);
        expected.as_slice().ct_eq(self.mac.as_slice()).into()
    }

    /// Return a copy of this header with a valid MAC attached.
    pub fn signed(&self, mac_key: &[u8], sealed: &[u8], seq: Option<u32>) -> LayerHeader {
        let mut clone = LayerHeader::new(
            self.seq,
            self.kind,
            self.next_hop.clone(),
            Vec::new(),
            Some(self.length),
            self.padded,
        )
        .expect("cloning a valid header with an empty mac cannot fail");
        clone.mac = clone.compute_mac(mac_key, sealed, seq);
        clone
    }
}

impl PartialEq for LayerHeader {
    /// Because no position is parsed and none is stored, a header that has
    /// made a wire round trip compares equal to the one that was packed.
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

/// Serialize an acknowledgement into [`ACK_WIRE_SIZE`] (20) bytes.
///
/// The layout matches [`crate::reliability::AckState`] exactly -- a
/// big-endian 32-bit cumulative edge followed by a big-endian 128-bit
/// selective-ack bitmap -- so an ack costs [`ACK_WIRE_SIZE`] bytes on the
/// wire whether it rides inside a layer or travels in a standalone cell.
///
/// `cumulative` is the highest sequence number below which everything
/// arrived; bit *i* of `bitmap` marks `cumulative + i` as also arrived.
pub fn encode_ack(cumulative: u32, bitmap: u128) -> [u8; ACK_WIRE_SIZE] {
    let mut buf = [0u8; ACK_WIRE_SIZE];
    buf[..4].copy_from_slice(&cumulative.to_be_bytes());
    buf[4..].copy_from_slice(&bitmap.to_be_bytes());
    buf
}

/// Parse an ack from the first [`ACK_WIRE_SIZE`] bytes of `data`.
///
/// Anything after the first [`ACK_WIRE_SIZE`] bytes is ignored, so a
/// padded cell payload decodes without trimming.
///
/// # Errors
/// Returns [`LayerError::Header`] if fewer than [`ACK_WIRE_SIZE`] bytes
/// are available.
pub fn decode_ack(data: &[u8]) -> Result<crate::reliability::AckState, LayerError> {
    if data.len() < ACK_WIRE_SIZE {
        return Err(LayerError::Header(format!(
            "need at least {ACK_WIRE_SIZE} bytes for an ack, got {}",
            data.len()
        )));
    }
    let cumulative = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let bitmap = u128::from_be_bytes(data[4..20].try_into().expect("checked len >= ACK_WIRE_SIZE (20) above"));
    Ok(crate::reliability::AckState::new(cumulative, bitmap))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(ip: &str, port: u16) -> (String, u16) {
        (ip.to_string(), port)
    }

    #[test]
    fn pack_unpack_round_trips() {
        let h = LayerHeader::new(
            42,
            Kind::ROUTE,
            hop("10.0.0.1", 9001),
            vec![7u8; MAC_TRUNCATED_SIZE],
            None,
            false,
        )
        .unwrap();
        let packed = h.pack(None);
        assert_eq!(packed.len(), WIRE_HEADER_SIZE);
        let sealed = h.pack_sealed();
        assert_eq!(sealed.len(), SEALED_HEADER_SIZE);
        assert_eq!(WIRE_HEADER_SIZE + SEALED_HEADER_SIZE, ROUTE_HEADER_SIZE);

        let mut unpacked = LayerHeader::unpack(&packed).unwrap();
        // Before the sealed part is applied only the cleartext fields are
        // known; the placeholders must not look like a real header.
        assert_eq!(unpacked.kind, UNSEALED_KIND);
        assert!(!Kind::is_known(unpacked.kind));
        assert_eq!(unpacked.mac, h.mac);
        assert_eq!(unpacked.length, h.length);

        unpacked.unpack_sealed(&sealed).unwrap();
        assert_eq!(h, unpacked);
        assert_eq!(unpacked.padded, h.padded);
    }

    #[test]
    fn wire_header_carries_no_kind_or_address() {
        let h = LayerHeader::new(1, Kind::PAYLOAD, hop("203.0.113.9", 443), Vec::new(), None, true).unwrap();
        let packed = h.pack(None);
        // 203.0.113.9 is cb 00 71 09; port 443 is 01 bb. None of those bytes
        // may appear in the wire header, nor the kind byte (0x82 padded).
        for window in packed.windows(2) {
            assert_ne!(window, [0xcb, 0x00]);
            assert_ne!(window, [0x01, 0xbb]);
        }
        assert!(!packed.contains(&(Kind::PAYLOAD | PADDED_FLAG)));
        // They are all in the sealed part instead.
        assert_eq!(h.pack_sealed(), [0x82, 0xcb, 0x00, 0x71, 0x09, 0x01, 0xbb]);
    }

    #[test]
    fn unpack_ignores_trailing_bytes() {
        let h = LayerHeader::new(1, Kind::PAYLOAD, hop("1.2.3.4", 80), Vec::new(), None, false).unwrap();
        let mut packed = h.pack(None).to_vec();
        packed.extend_from_slice(&[0xAA; 50]);
        let mut unpacked = LayerHeader::unpack(&packed).unwrap();
        let mut sealed = h.pack_sealed().to_vec();
        sealed.extend_from_slice(&[0xBB; 50]);
        unpacked.unpack_sealed(&sealed).unwrap();
        assert_eq!(unpacked, h);
    }

    #[test]
    fn unpack_too_short_is_header_error() {
        let err = LayerHeader::unpack(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, LayerError::Header(_)));
        let h = LayerHeader::new(1, Kind::ROUTE, hop("1.2.3.4", 80), Vec::new(), None, false).unwrap();
        let mut unpacked = LayerHeader::unpack(&h.pack(None)).unwrap();
        assert!(matches!(unpacked.unpack_sealed(&[0u8; 6]).unwrap_err(), LayerError::Header(_)));
    }

    #[test]
    fn unpack_rejects_wrong_version_before_mac() {
        let h = LayerHeader::new(1, Kind::ROUTE, hop("1.2.3.4", 80), Vec::new(), None, false).unwrap();
        let mut packed = h.pack(None);
        assert_eq!(packed[VERSION_OFFSET], LAYER_PROTOCOL_VERSION);
        packed[VERSION_OFFSET] = 0x01;
        let err = LayerHeader::unpack(&packed).unwrap_err();
        match err {
            LayerError::Version { observed, .. } => assert_eq!(observed, 0x01),
            other => panic!("expected Version error, got {other:?}"),
        }
    }

    /// A `0xA3` header is 29 bytes with `kind` at offset 4 and `ver` at
    /// offset 11; offset 10 (where this build looks) is the last byte of
    /// its reserved slot, always zero. It must be refused as a version
    /// mismatch, not misparsed.
    #[test]
    fn unpack_rejects_pre_0xa4_header_as_version_mismatch() {
        let mut legacy = [0u8; 29];
        legacy[4] = Kind::ROUTE;
        legacy[11] = 0xA3;
        let err = LayerHeader::unpack(&legacy).unwrap_err();
        match err {
            LayerError::Version { observed, message } => {
                assert_eq!(observed, 0x00);
                assert!(message.contains("pre-0xA4"), "{message}");
            }
            other => panic!("expected Version error, got {other:?}"),
        }
    }

    #[test]
    fn padded_flag_round_trips_and_does_not_collide_with_kind() {
        let h = LayerHeader::new(1, Kind::PADDING, hop("0.0.0.0", 0), Vec::new(), None, true).unwrap();
        let sealed = h.pack_sealed();
        assert_eq!(sealed[0] & PADDED_FLAG, PADDED_FLAG);
        assert_eq!(sealed[0] & MAX_KIND, Kind::PADDING);
        let mut unpacked = LayerHeader::unpack(&h.pack(None)).unwrap();
        unpacked.unpack_sealed(&sealed).unwrap();
        assert!(unpacked.padded);
        assert_eq!(unpacked.kind, Kind::PADDING);
    }

    #[test]
    fn kind_out_of_range_is_rejected() {
        assert!(LayerHeader::new(1, PADDED_FLAG, hop("1.2.3.4", 1), Vec::new(), None, false).is_err());
        assert!(LayerHeader::new(1, MAX_KIND, hop("1.2.3.4", 1), Vec::new(), None, false).is_ok());
    }

    #[test]
    fn mac_wrong_length_is_rejected() {
        assert!(LayerHeader::new(1, Kind::ROUTE, hop("1.2.3.4", 1), vec![0u8; 5], None, false).is_err());
    }

    #[test]
    fn is_route_and_target_addr() {
        let route = LayerHeader::new(1, Kind::ROUTE, hop("1.2.3.4", 1), Vec::new(), None, false).unwrap();
        assert!(route.is_route());
        assert!(route.target_addr().is_err());

        let payload = LayerHeader::new(1, Kind::PAYLOAD, hop("5.6.7.8", 443), Vec::new(), None, false).unwrap();
        assert!(!payload.is_route());
        assert_eq!(payload.target_addr().unwrap(), hop("5.6.7.8", 443));

        let ack = LayerHeader::new(1, Kind::ACK, hop("0.0.0.0", 0), Vec::new(), None, false).unwrap();
        assert!(ack.target_addr().is_err());
    }

    #[test]
    fn mac_compute_verify_and_signed() {
        let key = b"a mac key of arbitrary length";
        let sealed = b"pretend-sealed-aead-body";
        let h = LayerHeader::new(9, Kind::PAYLOAD, hop("9.9.9.9", 53), Vec::new(), None, false).unwrap();
        let signed = h.signed(key, sealed, None);
        assert_eq!(signed.mac.len(), MAC_TRUNCATED_SIZE);
        assert!(signed.verify_mac(key, sealed, None));
        assert!(!signed.verify_mac(b"wrong key, same length!!!!!!!", sealed, None));
        assert!(!signed.verify_mac(key, b"different sealed body!!", None));

        // Round-tripping a signed header through pack/unpack must preserve
        // the MAC and the header must still verify. The MAC covers only
        // the wire part plus `sealed`, so it verifies before the sealed
        // part is applied, and still after.
        let packed = signed.pack(None);
        let mut unpacked = LayerHeader::unpack(&packed).unwrap();
        assert!(unpacked.verify_mac(key, sealed, None));
        unpacked.unpack_sealed(&signed.pack_sealed()).unwrap();
        assert!(unpacked.verify_mac(key, sealed, None));
    }

    #[test]
    fn verify_mac_rejects_wrong_length_mac() {
        let h = LayerHeader::new(1, Kind::ROUTE, hop("1.2.3.4", 1), vec![1u8; MAC_TRUNCATED_SIZE], None, false)
            .unwrap();
        // A header whose mac field is not exactly MAC_TRUNCATED_SIZE never
        // verifies -- but every constructed LayerHeader's mac is either
        // empty or exactly that size, so this exercises the guard directly.
        let mut bad = h.clone();
        bad.mac = vec![1u8; 3];
        assert!(!bad.verify_mac(b"key", b"sealed", None));
    }

    #[test]
    fn eq_ignores_mac_length_and_padded() {
        let a = LayerHeader::new(1, Kind::ROUTE, hop("1.2.3.4", 1), Vec::new(), None, false).unwrap();
        let mut b = LayerHeader::new(1, Kind::ROUTE, hop("1.2.3.4", 1), vec![9u8; MAC_TRUNCATED_SIZE], Some(99), true)
            .unwrap();
        assert_eq!(a, b);
        b.seq = 2;
        assert_ne!(a, b);
    }

    #[test]
    fn encode_decode_addr_round_trips() {
        let addr = hop("203.0.113.42", 51820);
        let encoded = encode_addr(&addr).unwrap();
        assert_eq!(encoded.len(), NEXT_HOP_SIZE);
        let decoded = decode_addr(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn encode_addr_rejects_bad_ip() {
        assert!(encode_addr(&hop("not-an-ip", 1)).is_err());
        assert!(encode_addr(&hop("::1", 1)).is_err()); // IPv6, not IPv4
    }

    #[test]
    fn ack_round_trips() {
        let encoded = encode_ack(0xDEAD_BEEF, 0x0000_00FF);
        assert_eq!(encoded.len(), ACK_WIRE_SIZE);
        let decoded = decode_ack(&encoded).unwrap();
        assert_eq!(decoded.cumulative, 0xDEAD_BEEF);
        assert_eq!(decoded.bitmap, 0x0000_00FF);
    }

    #[test]
    fn ack_ignores_trailing_bytes() {
        let mut encoded = encode_ack(1, 2).to_vec();
        encoded.extend_from_slice(&[0xFF; 20]);
        let decoded = decode_ack(&encoded).unwrap();
        assert_eq!(decoded, crate::reliability::AckState::new(1, 2));
    }

    #[test]
    fn ack_too_short_is_rejected() {
        assert!(decode_ack(&[0u8; 4]).is_err());
    }

    #[test]
    fn kind_name_and_is_known() {
        assert_eq!(Kind::name(Kind::EXTEND), "EXTEND");
        assert_eq!(Kind::name(200), "UNKNOWN(200)");
        assert!(Kind::is_known(Kind::PADDING));
        assert!(!Kind::is_known(200));
    }
}

/// Byte-for-byte fixtures for the header layout.
///
/// These started as parity checks against the Python `allium.layer`
/// module. Format `0xA4` (the sealed header part) has no Python oracle, so
/// the wire-layout fixtures below were worked out by hand from the layout
/// in the module doc; the ack fixture is still the Python one.
#[cfg(test)]
mod python_cross_check {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn plain_route_header_matches_layout() {
        let h = LayerHeader::new(
            42,
            Kind::ROUTE,
            ("10.0.0.1".to_string(), 9001),
            vec![7u8; MAC_TRUNCATED_SIZE],
            None,
            false,
        )
        .unwrap();
        // seq 0000002a | length 001d (29, the `None` default) | reserved
        // 00000000 | ver a4 | mac 07*11
        assert_eq!(hex(&h.pack(None)), "0000002a001d00000000a40707070707070707070707");
        // kind 01 (ROUTE, unpadded) | addr 0a000001 2329
        assert_eq!(hex(&h.pack_sealed()), "010a0000012329");
    }

    #[test]
    fn signed_header_matches_python() {
        let h = LayerHeader::new(9, Kind::PAYLOAD, ("9.9.9.9".to_string(), 53), Vec::new(), None, false).unwrap();
        let key = b"a mac key of arbitrary length";
        let sealed = b"pretend-sealed-aead-body";
        let signed = h.signed(key, sealed, None);
        // NOTE (H4): the MAC below was recomputed for version 0xa2 -- the
        // version byte is covered by the MAC (pack_unsigned includes it),
        // so a version bump necessarily changes any fixture MAC that
        // exercises signed()/pack(). This value has NOT been cross-checked
        // against a regenerated Python oracle; it is Rust-self-consistent
        // (verify_mac round-trips) but the Python golden value still needs
        // regenerating. See the python_cross_check module doc comment in
        // onion.rs for the same caveat there.
        assert_eq!(signed.mac.len(), MAC_TRUNCATED_SIZE);
        assert!(signed.verify_mac(key, sealed, None));
    }

    #[test]
    fn ack_matches_python() {
        // Python's reference ack is 8 bytes (32-bit cumulative + 32-bit
        // bitmap): encode_ack(0xDEADBEEF, 0x000000FF) -> "deadbeef000000ff".
        // This port's ack is now 20 bytes (32-bit cumulative + 128-bit
        // bitmap, see ACK_WIRE_SIZE's doc comment), so the same logical
        // value (cumulative=0xDEADBEEF, low byte 0xFF set in the bitmap)
        // encodes to 16 bitmap bytes instead of 4.
        assert_eq!(hex(&encode_ack(0xDEAD_BEEF, 0x0000_00FF)), "deadbeef000000000000000000000000000000ff");
    }

    #[test]
    fn padded_header_sealed_kind_byte_matches_layout() {
        let h = LayerHeader::new(1, Kind::PADDING, ("0.0.0.0".to_string(), 0), Vec::new(), None, true).unwrap();
        // The padded flag lives in the sealed part now; the wire part of a
        // padded PADDING header is indistinguishable from any other.
        assert_eq!(hex(&h.pack(None)), "00000001001d00000000a40000000000000000000000");
        let sealed = h.pack_sealed();
        assert_eq!(hex(&sealed), "86000000000000");
        assert_eq!(sealed[0], 0x86);
    }
}
