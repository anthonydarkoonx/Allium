//! Onion encryption and peeling for Allium circuits.
//!
//! Port of Python's `onion.py`. See that module's docstring for the client/
//! relay roles: [`OnionCrypto::encrypt_onion`] wraps a payload in one layer
//! per relay (innermost/exit first); [`OnionCrypto::peel_layer`] removes
//! exactly one layer with a relay's own key.
//!
//! No external crate: this module's only non-`hashutil` dependency is the
//! hand-rolled, KAT-verified `crate::blake2` (BLAKE2b, RFC 7693) added
//! alongside it, needed because `onion.py` uses `hashlib.blake2b` (with a
//! personalization string) for the wire-format-relevant values `seq_prp_key`
//! (the per-hop sequence-number PRP key; the round function is also
//! blake2b-based) and `_seal_binding` (the
//! MAC-input digest that ties a ROUTE layer's header to the exact
//! ciphertext it travelled with). Neither is in the dependency policy's
//! reserved list of things that must come from a real crate (X25519/
//! Ed25519, AEAD, tokio, clap) -- BLAKE2b is a straightforward hash
//! function, not a chosen-plaintext-sensitive cipher, so it is hand-rolled
//! the same way `hashutil.rs`/`keccak.rs` already are. See `blake2.rs`'s
//! module docs.
//!
//! `seq_prp_key` was a plain XOR mask (`_seq_mask`) before switching to a
//! keyed PRP: XOR let a passive observer on two links cancel the mask
//! entirely and match cells by the *difference* between two seq values,
//! with no need to ever learn the mask itself, so it is now a keyed
//! Feistel PRP instead (`seq_prp_forward`/`seq_prp_inverse`).
//!
//! Deviation from Python: `OnionCrypto`'s encrypt-side methods (`seal_payload`,
//! `wrap`, and therefore `encrypt_onion`) take `&mut self`/`&mut OnionCrypto`,
//! since `crypto::SaltAead::seal` needs `&mut self` (it advances the nonce
//! counter or random-seal budget); the peel-side methods (`peel_layer`,
//! `peel`) take `&self`, since `SaltAead::open` does. Python's methods make
//! no such distinction (Python has no borrow checker), so `encrypt_onion`
//! here takes `hops: &mut [OnionCrypto]` rather than a `Sequence`.

use crate::cell::{Cell, CellError, Command, PAYLOAD_SIZE};
use crate::crypto::{CryptoError, KEY_SIZE, SEAL_OVERHEAD, SaltAead, derive_key, new_aead};
use crate::layer::{HeaderError, Kind, LayerHeader, ROUTE_HEADER_SIZE, SEALED_HEADER_SIZE, WIRE_HEADER_SIZE};
use crate::sizes::{OnionTooLargeError, RoutePlan, onion_size};
use std::fmt;

/// AEAD used unless a node is constructed with another one.
pub const DEFAULT_CIPHER: &str = "chacha20-poly1305";

// --------------------------------------------------------------------------
// Exceptions
// --------------------------------------------------------------------------

/// Base class for all onion layer errors.
///
/// Python distinguishes `OnionBuildError` / `OnionPeelError` /
/// `OnionVersionError` (a subclass of `OnionPeelError`) as separate
/// exception classes; ported here as one enum (same pattern as
/// `handshake::HandshakeError`) with `OnionBuildError`/`OnionPeelError`/
/// `OnionVersionError` as type aliases, since Rust has no exception
/// hierarchy to mirror and every existing `match` on the enum still sees
/// every variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnionError {
    Build(String),
    Peel(String),
    /// The one peel failure that is not an attack: the peer's layer format
    /// is one this build cannot read. `observed` is the version byte seen,
    /// when known.
    Version { message: String, observed: Option<u8> },
}
impl fmt::Display for OnionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OnionError::Build(s) => write!(f, "{s}"),
            OnionError::Peel(s) => write!(f, "{s}"),
            OnionError::Version { message, .. } => write!(f, "{message}"),
        }
    }
}
impl std::error::Error for OnionError {}
fn build_err(msg: impl Into<String>) -> OnionError {
    OnionError::Build(msg.into())
}
fn peel_err(msg: impl Into<String>) -> OnionError {
    OnionError::Peel(msg.into())
}

pub type OnionBuildError = OnionError;
pub type OnionPeelError = OnionError;
pub type OnionVersionError = OnionError;

impl From<CryptoError> for OnionError {
    fn from(e: CryptoError) -> Self {
        OnionError::Build(e.to_string())
    }
}
impl From<OnionTooLargeError> for OnionError {
    fn from(e: OnionTooLargeError) -> Self {
        OnionError::Build(e.to_string())
    }
}
impl From<HeaderError> for OnionError {
    fn from(e: HeaderError) -> Self {
        match e {
            HeaderError::Version(v) => OnionError::Version { message: v.message, observed: Some(v.observed) },
            HeaderError::Malformed(s) => OnionError::Peel(s),
        }
    }
}
impl From<crate::sizes::SizesError> for OnionError {
    fn from(e: crate::sizes::SizesError) -> Self {
        OnionError::Build(e.to_string())
    }
}

// --------------------------------------------------------------------------
// Data classes
// --------------------------------------------------------------------------

/// One hop's key material.
///
/// `aead`/`open_aead`: these used to be a
/// single `aead` field, one AEAD instance used for *both* directions of
/// traffic through this hop (sealing this side's own outgoing data, and
/// opening the peer's incoming data). That was safe only as long as
/// nonces stayed random (this crate's only production nonce source --
/// `crypto::SaltAead`'s `nonce_source: None` path): a future switch to
/// counter-based nonces (already supported via `crypto::NonceCounter`)
/// could then silently reuse a `(key, nonce)` pair across the two
/// directions, which is catastrophic for any AEAD. Splitting the key
/// itself removes that risk regardless of how nonces are chosen later:
/// `aead` is this side's own seal key, `open_aead` is the peer's --
/// [`OnionCrypto::new`]'s two key parameters, threaded from
/// `handshake::HandshakeKeys`'s now-separate `aead_key_fwd`/
/// `aead_key_bwd`, decide which is which per hop role.
pub struct Layer {
    pub name: String,
    pub aead: SaltAead,
    pub open_aead: SaltAead,
    pub mac_key: [u8; KEY_SIZE],
    pub cipher: String,
}

impl Drop for Layer {
    /// Security audit fix (2026-09-26): `mac_key` is held for the whole
    /// life of the circuit this hop belongs to -- wipe it on drop instead
    /// of leaving it sitting in freed memory. `aead`/`open_aead` zeroize
    /// their own keys via `SaltAead`'s own `Drop` impl.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.mac_key.zeroize();
    }
}

impl Layer {
    pub fn new(name: impl Into<String>, aead: SaltAead, open_aead: SaltAead, mac_key: [u8; KEY_SIZE], cipher: impl Into<String>) -> Layer {
        Layer { name: name.into(), aead, open_aead, mac_key, cipher: cipher.into() }
    }

    /// Build a layer from raw keys, constructing both AEADs via [`new_aead`].
    /// `seal_key`/`open_key` may be the same key for a caller that
    /// genuinely doesn't need direction separation (see [`Layer::from_key`]).
    pub fn from_keys(name: impl Into<String>, seal_key: [u8; KEY_SIZE], open_key: [u8; KEY_SIZE], mac_key: [u8; KEY_SIZE], cipher: &str) -> Result<Layer, OnionError> {
        let aead = new_aead(cipher, seal_key, None)?;
        let open_aead = new_aead(cipher, open_key, None)?;
        Ok(Layer::new(name, aead, open_aead, mac_key, cipher))
    }

    /// [`Layer::from_keys`] with the same key both ways -- for a caller
    /// (tests, or any context with only one flow of traffic through this
    /// layer) that doesn't need direction separation. The real handshake
    /// path (`handshake::HandshakeKeys::to_layer`) always uses
    /// [`Layer::from_keys`] with genuinely distinct keys.
    pub fn from_key(name: impl Into<String>, key: [u8; KEY_SIZE], mac_key: [u8; KEY_SIZE], cipher: &str) -> Result<Layer, OnionError> {
        Layer::from_keys(name, key, key, mac_key, cipher)
    }

    /// Derive both keys for a hop from one handshake secret. Test-only
    /// helper (uses `crypto::derive_key`'s test-oriented derivation, not
    /// the real handshake's HKDF); the real handshake path never calls
    /// this.
    pub fn derive(name: impl Into<String>, shared_secret: &[u8], cipher: &str) -> Result<Layer, OnionError> {
        let aead_key = derive_key(shared_secret, b"allium-aead-key-v1");
        let mac_key = derive_key(shared_secret, b"allium-header-mac-v1");
        Layer::from_key(name, aead_key, mac_key, cipher)
    }
}

/// What a relay gets back from [`OnionCrypto::peel`].
pub struct PeeledLayer {
    pub header: LayerHeader,
    pub plaintext: Vec<u8>,
    pub forwarded: Option<Vec<u8>>,
    pub sealed: Vec<u8>,
    pub next_hop: Option<(String, u16)>,
    pub target_addr: Option<(String, u16)>,
}

impl PeeledLayer {
    /// `true` when this relay is the exit hop (no next relay).
    pub fn is_terminal(&self) -> bool {
        self.next_hop.is_none()
    }
    pub fn is_payload(&self) -> bool {
        self.header.kind == Kind::PAYLOAD
    }
    pub fn is_ack(&self) -> bool {
        self.header.kind == Kind::ACK
    }
    pub fn is_extend(&self) -> bool {
        self.header.kind == Kind::EXTEND
    }
    pub fn is_extended(&self) -> bool {
        self.header.kind == Kind::EXTENDED
    }
    pub fn is_padding(&self) -> bool {
        self.header.kind == Kind::PADDING
    }

    /// Return user data, raising if this layer is not a PAYLOAD layer.
    pub fn payload_bytes(&self) -> Result<Vec<u8>, OnionError> {
        if !self.is_payload() {
            return Err(peel_err(format!("{} layer carries no user payload", Kind::name(self.header.kind))));
        }
        if self.header.padded {
            Ok(strip_plaintext_padding(&self.plaintext))
        } else {
            Ok(self.plaintext.clone())
        }
    }
}

// --------------------------------------------------------------------------
// OnionCrypto -- one node's view of a circuit
// --------------------------------------------------------------------------

/// Seals layers as a client, or peels exactly one as a relay.
pub struct OnionCrypto {
    pub name: String,
    pub layer: Layer,
    pub cipher: String,
    pub hop_index: usize,
    pub aad_context: Vec<u8>,
    seq_prp_key: [u8; 32],
}

impl Drop for OnionCrypto {
    /// Security audit fix (finding L3): `seq_prp_key` is held for the
    /// whole life of the circuit this hop belongs to, exactly like
    /// `layer.mac_key` (already zeroized by `Layer`'s own `Drop`, which
    /// still runs on this struct's `layer` field after this) -- wipe it
    /// on drop too instead of leaving it sitting in freed memory.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.seq_prp_key.zeroize();
    }
}

/// Number of Feistel rounds in the sequence-number PRP
/// (replacing the earlier XOR mask). See the matching comment in the Client crate's
/// `onion.rs` for the full rationale: an XOR mask let a passive two-link
/// observer cancel it out entirely (`wire_a XOR wire_b == seq_a XOR seq_b`
/// on every hop, regardless of the mask), which a keyed non-linear PRP
/// does not.
const SEQ_PRP_ROUNDS: u8 = 4;

/// Derive this hop's key for the sequence-number PRP from its own
/// `mac_key`, independent of the AEAD key and the header MAC key:
/// `blake2b(mac_key, digest_size=32, person=b"allium-seqprp-k1")`.
/// (blake2b's personalization field caps at 16 bytes, hence the
/// compressed spelling.)
fn compute_seq_prp_key(mac_key: &[u8]) -> [u8; 32] {
    let bytes = crate::blake2::blake2b(mac_key, 32, b"allium-seqprp-k1");
    bytes.try_into().expect("blake2b(.., 32, ..) returns exactly 32 bytes")
}

/// One Feistel round function: keyed, round-separated, 16 bits out.
fn seq_prp_round_fn(key: &[u8; 32], round: u8, half: u16) -> u16 {
    let mut input = Vec::with_capacity(35);
    input.extend_from_slice(key);
    input.push(round);
    input.extend_from_slice(&half.to_be_bytes());
    let digest = crate::blake2::blake2b(&input, 2, b"allium-seqprp-rf");
    u16::from_be_bytes(digest.try_into().expect("blake2b(.., 2, ..) returns exactly 2 bytes"))
}

/// Encrypt `seq` through the keyed Feistel network.
fn seq_prp_forward(key: &[u8; 32], seq: u32) -> u32 {
    let mut l = (seq >> 16) as u16;
    let mut r = seq as u16;
    for round in 0..SEQ_PRP_ROUNDS {
        let new_l = r;
        let new_r = l ^ seq_prp_round_fn(key, round, r);
        l = new_l;
        r = new_r;
    }
    ((l as u32) << 16) | (r as u32)
}

/// Invert [`seq_prp_forward`]: apply the same round functions in reverse
/// round order.
fn seq_prp_inverse(key: &[u8; 32], seq: u32) -> u32 {
    let mut l = (seq >> 16) as u16;
    let mut r = seq as u16;
    for round in (0..SEQ_PRP_ROUNDS).rev() {
        let new_r = l;
        let new_l = r ^ seq_prp_round_fn(key, round, l);
        l = new_l;
        r = new_r;
    }
    ((l as u32) << 16) | (r as u32)
}

impl OnionCrypto {
    /// `seal_key`/`open_key`: previously
    /// one `key` used for both directions -- see [`Layer`]'s doc comment
    /// for why that's no longer the case. `seal_key` encrypts this side's
    /// own outgoing traffic through this hop; `open_key` decrypts the
    /// peer's incoming traffic. Pass the same value for both if direction
    /// separation genuinely doesn't apply (e.g. [`OnionCrypto::with_defaults`]).
    pub fn new(
        name: impl Into<String>,
        seal_key: [u8; KEY_SIZE],
        open_key: [u8; KEY_SIZE],
        mac_key: Option<[u8; KEY_SIZE]>,
        cipher: &str,
        hop_index: usize,
        aad_context: Vec<u8>,
    ) -> Result<OnionCrypto, OnionError> {
        let name = name.into();
        let mac_key = mac_key.unwrap_or_else(|| derive_key(&seal_key, b"allium-header-mac-v1"));
        let aead = new_aead(cipher, seal_key, None).map_err(|e| build_err(format!("{name}: {e}")))?;
        let open_aead = new_aead(cipher, open_key, None).map_err(|e| build_err(format!("{name}: {e}")))?;
        // A per-hop-key-derived keyed PRP applied to `seq` before it
        // ever reaches the wire -- see the module docs (this replaces the
        // earlier XOR mask, which did not resist cross-link correlation).
        let seq_prp_key = compute_seq_prp_key(&mac_key);
        Ok(OnionCrypto {
            name: name.clone(),
            layer: Layer::new(name, aead, open_aead, mac_key, cipher),
            cipher: cipher.to_string(),
            hop_index,
            aad_context,
            seq_prp_key,
        })
    }

    /// [`OnionCrypto::new`] with the same key both ways -- for a caller
    /// (tests, mostly) that doesn't need direction separation. The real
    /// handshake path (`handshake::HandshakeKeys::to_onion_crypto`) always
    /// uses [`OnionCrypto::new`] with genuinely distinct keys.
    pub fn with_defaults(name: impl Into<String>, key: [u8; KEY_SIZE]) -> Result<OnionCrypto, OnionError> {
        OnionCrypto::new(name, key, key, None, DEFAULT_CIPHER, 0, Vec::new())
    }

    fn mask_seq(&self, seq: u32) -> u32 {
        seq_prp_forward(&self.seq_prp_key, seq)
    }
    // Unlike XOR, masking and unmasking are different operations now --
    // kept as a distinct function so call sites still read correctly.
    fn unmask_seq(&self, seq: u32) -> u32 {
        seq_prp_inverse(&self.seq_prp_key, seq)
    }

    // ------------------------------------------------------------------
    // Client side
    // ------------------------------------------------------------------

    fn seal(&mut self, header: &LayerHeader, plaintext: &[u8], seq: u32) -> Result<Vec<u8>, OnionError> {
        let mut aad = header.pack_unsigned(Some(seq));
        aad.extend_from_slice(&self.aad_context);
        self.layer.aead.seal(plaintext, &aad).map_err(OnionError::from_crypto_seal)
    }

    /// Frame one layer: seal `body` behind `header`'s sealed part, sign,
    /// and emit `wire header || ciphertext`.
    ///
    /// The AEAD plaintext is the header's sealed part (kind, padded flag,
    /// address) followed by `body`, so nothing on the wire says what kind
    /// of layer this is or where it is headed. The MAC covers that same
    /// plaintext plus, for a ROUTE layer, a digest of the ciphertext
    /// (`seal_binding`), which ties the header to the blob it travelled
    /// with. Must match the Client crate's `OnionCrypto::frame` byte for
    /// byte.
    fn frame(&mut self, mut header: LayerHeader, body: &[u8], wire_seq: u32) -> Result<Vec<u8>, OnionError> {
        let mut plaintext = header.pack_sealed();
        plaintext.extend_from_slice(body);
        let length = plaintext.len() + SEAL_OVERHEAD;
        if length > crate::layer::HEADER_MAX_PAYLOAD as usize {
            return Err(build_err(format!("sealed layer is {length} bytes, which does not fit the 16-bit layer header length field")));
        }
        header.length = length as u32;

        let sealed = self.seal(&header, &plaintext, wire_seq)?;
        let mac_input = self.mac_input(&plaintext, &header, &sealed);
        let signed = header.signed(&self.layer.mac_key, &mac_input, Some(wire_seq));
        let mut out = signed.pack(Some(wire_seq));
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Build the *innermost* sealed field: the user data, headed for the exit.
    pub fn seal_payload(&mut self, user_data: &[u8], seq: u32, final_addr: (String, u16), kind: Option<u8>, pad_to: Option<usize>) -> Result<Vec<u8>, OnionError> {
        let mut actually_padded = false;
        let mut user_data = user_data.to_vec();
        if let Some(target) = pad_to {
            let padded_data = pad_plaintext(&user_data, target)?;
            actually_padded = padded_data.len() != user_data.len();
            user_data = padded_data;
        }
        let wire_seq = self.mask_seq(seq);
        let header = LayerHeader::new(wire_seq, kind.unwrap_or(Kind::PAYLOAD), final_addr, Vec::new(), None, actually_padded)?;
        self.frame(header, &user_data, wire_seq)
    }

    /// Wrap `sealed_inner` in this hop's layer, headed for `next_hop`.
    ///
    /// The layer's plaintext is this header's sealed part (naming
    /// `next_hop`) followed by `sealed_inner`, the next relay's complete
    /// frame, which the receiving relay forwards untouched.
    pub fn wrap(&mut self, sealed_inner: &[u8], next_hop: (String, u16), seq: u32) -> Result<Vec<u8>, OnionError> {
        let wire_seq = self.mask_seq(seq);
        let header = LayerHeader::new(wire_seq, Kind::ROUTE, next_hop, Vec::new(), None, false)?;
        self.frame(header, sealed_inner, wire_seq)
    }

    // ------------------------------------------------------------------
    // Top-level client API
    // ------------------------------------------------------------------

    /// Onion-encrypt `payload` under one key per hop, applying one layer per
    /// hop, innermost (exit) first. `hops` are in route order (guard first).
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt_onion(payload: &[u8], hops: &mut [OnionCrypto], route: &RoutePlan, seq: u32, check_size: bool, per_hop_seq: bool, hop_seq_base: Option<u32>, kind: Option<u8>, pad_to: Option<usize>) -> Result<Vec<u8>, OnionError> {
        if hops.is_empty() {
            return Err(build_err("an onion needs at least one hop"));
        }
        if route.len() != hops.len() {
            return Err(build_err(format!("route has {} addresses but {} keys were given; they must match one-to-one", route.len(), hops.len())));
        }
        if check_size {
            let effective_len = pad_to.unwrap_or(payload.len());
            onion_size(effective_len as i64, hops.len() as i64)?;
        }

        let last = hops.len() - 1;
        let base = hop_seq_base.unwrap_or(seq);
        let layer_seq = |index: usize| -> u32 {
            if !per_hop_seq {
                return seq;
            }
            // Peel order is guard (index 0) first, so it takes the lowest
            // value and the exit the highest.
            (base.wrapping_sub((last - index) as u32)) & 0xFFFF_FFFF
        };

        let mut sealed = hops[last].seal_payload(payload, layer_seq(last), route.final_addr.clone(), kind, pad_to)?;
        for index in (0..last).rev() {
            let next = route.next_hop(index).expect("index < hops.len() so next_hop exists");
            sealed = hops[index].wrap(&sealed, next, layer_seq(index))?;
        }
        Ok(sealed)
    }

    // ------------------------------------------------------------------
    // Relay side
    // ------------------------------------------------------------------

    /// Verify and open one layer. The returned header has its sealed part
    /// (kind, address) applied; for a ROUTE layer `forwarded` is the next
    /// relay's complete frame, for every other kind `plaintext` is the
    /// layer's body.
    fn open(&self, received: &[u8]) -> Result<OpenedLayer, OnionError> {
        // The smallest well-formed layer: wire header, then a ciphertext
        // holding at least the sealed header part and nothing else.
        const MIN_LAYER: usize = ROUTE_HEADER_SIZE + SEAL_OVERHEAD;
        const MIN_BODY: usize = SEALED_HEADER_SIZE + SEAL_OVERHEAD;
        if received.len() < MIN_LAYER {
            return Err(peel_err(format!("sealed field is {} bytes, minimum is {MIN_LAYER}", received.len())));
        }
        let mut header = match LayerHeader::unpack(received) {
            Ok(h) => h,
            Err(HeaderError::Version(v)) => return Err(OnionError::Version { message: format!("{}: {}", self.name, v.message), observed: Some(v.observed) }),
            Err(HeaderError::Malformed(s)) => return Err(peel_err(format!("malformed layer header: {s}"))),
        };

        if (header.length as usize) < MIN_BODY {
            return Err(peel_err(format!("declared body length {} is smaller than the {MIN_BODY}-byte minimum (sealed header part plus AEAD overhead)", header.length)));
        }
        if WIRE_HEADER_SIZE + header.length as usize > received.len() {
            return Err(peel_err(format!("declared body length {} exceeds the {} bytes available", header.length, received.len() - WIRE_HEADER_SIZE)));
        }
        let payload = received[WIRE_HEADER_SIZE..WIRE_HEADER_SIZE + header.length as usize].to_vec();

        let mut aad = header.pack_unsigned(Some(header.seq));
        aad.extend_from_slice(&self.aad_context);
        let plaintext = self.layer.open_aead.open(&payload, &aad).map_err(|e| match e {
            CryptoError::Decrypt(_) => peel_err(format!("{}: {}", self.name, e)),
            other => peel_err(format!("{}: {}", self.name, other)),
        })?;

        // The AEAD has authenticated the plaintext, so its leading sealed
        // header part -- the layer's kind and address -- can be read to
        // decide what the MAC input looks like. `MIN_BODY` guaranteed the
        // bytes are there.
        header.unpack_sealed(&plaintext).map_err(|e| peel_err(format!("{}: malformed sealed header: {e}", self.name)))?;

        let mac_input = self.mac_input(&plaintext, &header, &payload);
        let mac_expected = header.compute_mac(&self.layer.mac_key, &mac_input, Some(header.seq));
        if !crate::hashutil::constant_time_eq(&mac_expected, &header.mac) {
            return Err(peel_err(format!("{}: header MAC mismatch; next_hop may have been tampered with", self.name)));
        }

        // H4: only once the header has authenticated, recover the true,
        // monotonic sequence number from its wire PRP.
        header.seq = self.unmask_seq(header.seq);

        let body = plaintext[SEALED_HEADER_SIZE..].to_vec();

        if header.kind == Kind::ROUTE {
            // The body *is* the next relay's frame: its wire header, then
            // its ciphertext. Forward it verbatim.
            if body.len() < MIN_LAYER {
                return Err(peel_err(format!("route layer body is {} bytes; too short to hold an inner frame", body.len())));
            }
            return Ok(OpenedLayer { header, plaintext: body.clone(), payload, forwarded: body });
        }

        if matches!(header.kind, Kind::PAYLOAD | Kind::EXTEND | Kind::EXTENDED | Kind::PADDING) {
            return Ok(OpenedLayer { header, plaintext: body, payload, forwarded: Vec::new() });
        }

        Err(peel_err(format!(
            "{}: unknown layer kind {}; this build understands {} (ROUTE), {} (PAYLOAD), {} (EXTEND), {} (EXTENDED), and {} (PADDING)",
            self.name, header.kind, Kind::ROUTE, Kind::PAYLOAD, Kind::EXTEND, Kind::EXTENDED, Kind::PADDING
        )))
    }

    fn mac_input(&self, plaintext: &[u8], header: &LayerHeader, payload: &[u8]) -> Vec<u8> {
        if header.kind == Kind::ROUTE {
            let mut out = plaintext.to_vec();
            out.extend_from_slice(&seal_binding(payload));
            out
        } else {
            plaintext.to_vec()
        }
    }

    /// Decrypt exactly one layer with this node's key.
    ///
    /// Returns `(inner, header)`: `inner` is the next hop's sealed field, or
    /// the user data when this is the exit hop.
    pub fn peel_layer(&self, received: &[u8]) -> Result<(Vec<u8>, LayerHeader), OnionError> {
        let opened = self.open(received)?;
        if matches!(opened.header.kind, Kind::PAYLOAD | Kind::EXTEND | Kind::EXTENDED | Kind::PADDING) {
            Ok((opened.plaintext, opened.header))
        } else {
            Ok((opened.forwarded, opened.header))
        }
    }

    /// Like [`OnionCrypto::peel_layer`], but returns every detail of the peel.
    pub fn peel(&self, received: &[u8]) -> Result<PeeledLayer, OnionError> {
        let opened = self.open(received)?;
        if matches!(opened.header.kind, Kind::PAYLOAD | Kind::EXTEND | Kind::EXTENDED | Kind::PADDING) {
            let target_addr = opened.header.target_addr().ok();
            return Ok(PeeledLayer { header: opened.header, plaintext: opened.plaintext, forwarded: None, sealed: opened.payload, next_hop: None, target_addr });
        }
        // Where to forward came out of this layer's own sealed header part.
        let next_hop = opened.header.next_hop.clone();
        Ok(PeeledLayer {
            header: opened.header,
            plaintext: opened.forwarded.clone(),
            forwarded: Some(opened.forwarded),
            sealed: opened.payload,
            next_hop: Some(next_hop),
            target_addr: None,
        })
    }

    // ------------------------------------------------------------------
    // Cell integration
    // ------------------------------------------------------------------

    /// Build the innermost layer for a single-hop circuit. Returns the raw
    /// sealed field, not padded to the cell payload buffer.
    pub fn initial_payload(&mut self, payload: &[u8], seq: u32, final_addr: (String, u16), kind: Option<u8>, pad_to: Option<usize>) -> Result<Vec<u8>, OnionError> {
        let sealed = self.seal_payload(payload, seq, final_addr, kind, pad_to)?;
        if sealed.len() > PAYLOAD_SIZE {
            return Err(OnionTooLargeError { message: format!("sealed layer is {} bytes, cell payload buffer is {}", sealed.len(), PAYLOAD_SIZE) }.into());
        }
        Ok(sealed)
    }
}

// A private helper struct for `OnionCrypto::open`'s return value. `header`
// already has its sealed part applied, so a ROUTE layer's next hop is
// `header.next_hop`; `forwarded` is that layer's body (the next relay's
// frame) and is empty for a terminal kind.
struct OpenedLayer {
    header: LayerHeader,
    plaintext: Vec<u8>,
    payload: Vec<u8>,
    forwarded: Vec<u8>,
}

impl OnionError {
    fn from_crypto_seal(e: CryptoError) -> OnionError {
        build_err(e.to_string())
    }
}

// --------------------------------------------------------------------------
// Plaintext length padding
// --------------------------------------------------------------------------

/// Size of one trailing-padding entry: 2 length bytes + 1 marker byte.
pub const TRAILING_PAD_ENTRY_SIZE: usize = 3;
/// Largest padding [`pad_plaintext`] can encode (2-byte length).
pub const MAX_PLAINTEXT_PADDING: usize = (1 << 16) - 1;
const PAD_MARKER: u8 = 0x80;

/// Pad `data` with trailing bytes so the result is exactly `target` long.
pub fn pad_plaintext(data: &[u8], target: usize) -> Result<Vec<u8>, OnionError> {
    if target < data.len() {
        return Err(build_err(format!("cannot pad {} bytes into {target}: padding never shrinks", data.len())));
    }
    if target == data.len() {
        return Ok(data.to_vec());
    }
    let overhead = TRAILING_PAD_ENTRY_SIZE;
    if target - data.len() < overhead {
        return Err(build_err(format!("target {target} leaves no room for the {overhead}-byte padding header needed by {} bytes of data", data.len())));
    }
    let pad_len = target - data.len() - overhead;
    if pad_len > MAX_PLAINTEXT_PADDING {
        return Err(build_err(format!("padding of {pad_len} bytes exceeds the {MAX_PLAINTEXT_PADDING}-byte limit the 2-byte length field can describe")));
    }
    let mut out = data.to_vec();
    out.extend(std::iter::repeat(0u8).take(pad_len));
    out.extend_from_slice(&(pad_len as u16).to_be_bytes());
    out.push(PAD_MARKER);
    Ok(out)
}

/// Remove padding added by [`pad_plaintext`]. Call only on data already
/// known to have been padded (see [`crate::layer::LayerHeader::padded`]).
pub fn strip_plaintext_padding(data: &[u8]) -> Vec<u8> {
    if data.len() < TRAILING_PAD_ENTRY_SIZE {
        return data.to_vec();
    }
    if data[data.len() - 1] != PAD_MARKER {
        return data.to_vec();
    }
    let pad_len = u16::from_be_bytes([data[data.len() - 3], data[data.len() - 2]]) as usize;
    let overhead = TRAILING_PAD_ENTRY_SIZE + pad_len;
    if overhead > data.len() {
        // Marker matched by accident, or the record is corrupt.
        return data.to_vec();
    }
    let body_len = data.len() - overhead;
    data[..body_len].to_vec()
}

/// Return a fixed-size digest of a sealed blob, for folding into a MAC.
fn seal_binding(sealed: &[u8]) -> Vec<u8> {
    crate::blake2::blake2b(sealed, 32, b"allium-bind")
}

/// Zero-pad a raw sealed field to `size` bytes, to be put in a cell.
pub fn pad_payload(data: &[u8], size: usize) -> Result<Vec<u8>, OnionError> {
    if data.len() > size {
        return Err(OnionTooLargeError { message: format!("sealed field is {} bytes, cannot pad down to {size}", data.len()) }.into());
    }
    let mut out = data.to_vec();
    out.resize(size, 0);
    Ok(out)
}

/// Pack an onion into a [`Cell`] for transmission. `command` defaults to
/// `Command::Data`.
pub fn seal_into_cell(onion: &[u8], circuit_id: u32, command: Option<Command>) -> Result<Cell, OnionError> {
    if onion.len() > PAYLOAD_SIZE {
        return Err(OnionTooLargeError { message: format!("sealed onion is {} bytes, cell payload buffer is {}", onion.len(), PAYLOAD_SIZE) }.into());
    }
    let padded = pad_payload(onion, PAYLOAD_SIZE)?;
    let command = command.unwrap_or(Command::Data);
    Cell::new(circuit_id, command as i64, padded).map_err(|e: CellError| build_err(e.to_string()))
}

/// Return how many of `buffer`'s leading bytes are a real onion: the wire
/// header plus the ciphertext length it declares. Anything past that is
/// cell-level zero padding.
fn leading_onion_length(buffer: &[u8]) -> usize {
    if buffer.len() < WIRE_HEADER_SIZE {
        return buffer.len();
    }
    let header = match LayerHeader::unpack(buffer) {
        Ok(h) => h,
        Err(_) => return buffer.len(),
    };
    let total = WIRE_HEADER_SIZE + header.length as usize;
    if total > buffer.len() {
        return buffer.len();
    }
    total
}

/// Extract the sealed onion from a received [`Cell`]. `trailer` keeps extra
/// bytes past the onion the header describes (e.g. a backward-authenticity
/// link token appended by a relay); `0` is right for a plain onion cell.
pub fn onion_from_cell(cell: &Cell, trailer: usize) -> Vec<u8> {
    let payload = &cell.payload;
    let end = leading_onion_length(payload) + trailer;
    payload[..end.min(payload.len())].to_vec()
}

/// Peel every layer in sequence and return the exit's user payload.
pub fn peel_circuit(onion: &[u8], hops: &[OnionCrypto]) -> Result<Vec<u8>, OnionError> {
    let mut current = onion.to_vec();
    for hop in hops {
        let (next, _header) = hop.peel_layer(&current)?;
        current = next;
    }
    Ok(current)
}

/// Like [`peel_circuit`], but returns a tuple per hop for inspection:
/// `(header, next_hop, data, target_addr)`.
#[allow(clippy::type_complexity)]
pub fn peel_circuit_verbose(onion: &[u8], hops: &[OnionCrypto]) -> Result<Vec<(LayerHeader, Option<(String, u16)>, Vec<u8>, Option<(String, u16)>)>, OnionError> {
    let mut current = onion.to_vec();
    let mut trace = Vec::new();
    for hop in hops {
        let peeled = hop.peel(&current)?;
        let data = peeled.forwarded.clone().unwrap_or_else(|| peeled.plaintext.clone());
        trace.push((peeled.header, peeled.next_hop.clone(), peeled.plaintext.clone(), peeled.target_addr.clone()));
        current = data;
    }
    Ok(trace)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(name: &str, key: [u8; KEY_SIZE]) -> OnionCrypto {
        OnionCrypto::with_defaults(name, key).unwrap()
    }

    fn addr(ip: &str, port: u16) -> (String, u16) {
        (ip.to_string(), port)
    }

    fn make_circuit() -> (OnionCrypto, OnionCrypto, OnionCrypto, RoutePlan) {
        let guard = hop("guard", [1u8; KEY_SIZE]);
        let middle = hop("middle", [2u8; KEY_SIZE]);
        let exit = hop("exit", [3u8; KEY_SIZE]);
        let route = RoutePlan::new(vec![addr("10.0.0.1", 9001), addr("10.0.0.2", 9002), addr("10.0.0.3", 9003)], addr("93.184.216.34", 80), PAYLOAD_SIZE as i64).unwrap();
        (guard, middle, exit, route)
    }

    #[test]
    fn test_onion_crypto_setup_rejects_unknown_cipher() {
        let key = [1u8; KEY_SIZE];
        assert!(OnionCrypto::new("guard", key, key, None, "rot13", 0, Vec::new()).is_err());
    }

    #[test]
    fn test_layer_from_key_and_derive() {
        let key = [9u8; KEY_SIZE];
        let mac_key = [8u8; KEY_SIZE];
        let l1 = Layer::from_key("guard", key, mac_key, DEFAULT_CIPHER).unwrap();
        assert_eq!(l1.name, "guard");
        let l2 = Layer::derive("guard", b"shared-secret-bytes", DEFAULT_CIPHER).unwrap();
        assert_eq!(l2.cipher, DEFAULT_CIPHER);
    }

    #[test]
    fn test_client_seal_and_relay_peel_single_hop() {
        let mut g = hop("guard", [1u8; KEY_SIZE]);
        let sealed = g.seal_payload(b"hello", 0, addr("93.184.216.34", 80), None, None).unwrap();
        let (inner, header) = g.peel_layer(&sealed).unwrap();
        assert_eq!(inner, b"hello");
        assert_eq!(header.kind, Kind::PAYLOAD);
    }

    /// `OnionCrypto`'s seal key
    /// (this side's own outgoing traffic) and open key (the peer's
    /// incoming traffic) must be genuinely independent, not the same key
    /// used both ways. Confirmed here with deliberately different
    /// seal/open keys: data one instance sealed must *not* be openable by
    /// that same instance (which opens with the *other* key) -- if
    /// seal/open ever collapsed back to one shared key, this would
    /// incorrectly succeed -- but must be openable by the peer's own
    /// instance, whose seal/open keys are swapped.
    #[test]
    fn test_seal_and_peel_require_matching_directional_keys() {
        let seal_key = [1u8; KEY_SIZE];
        let open_key = [2u8; KEY_SIZE];
        // Explicit, shared mac_key (as the real handshake path always
        // provides -- see `HandshakeKeys::to_onion_crypto`): letting it
        // fall back to `derive_key(&seal_key, ..)` would give `g` and
        // `peer` *different* mac_keys too (each derived from its own,
        // different seal_key), which would fail the header MAC check for
        // a reason unrelated to what this test is actually checking.
        let mac_key = [3u8; KEY_SIZE];
        let mut g = OnionCrypto::new("guard", seal_key, open_key, Some(mac_key), DEFAULT_CIPHER, 0, Vec::new()).unwrap();
        let sealed = g.seal_payload(b"hello", 0, addr("93.184.216.34", 80), None, None).unwrap();
        assert!(g.peel_layer(&sealed).is_err(), "sealing and opening with different keys must not round-trip");

        let peer = OnionCrypto::new("guard-peer", open_key, seal_key, Some(mac_key), DEFAULT_CIPHER, 0, Vec::new()).unwrap();
        let (inner, header) = peer.peel_layer(&sealed).unwrap();
        assert_eq!(inner, b"hello");
        assert_eq!(header.kind, Kind::PAYLOAD);
    }

    #[test]
    fn test_three_hop_encrypt_and_peel_recovers_payload() {
        let (mut guard, mut middle, mut exit, route) = make_circuit();
        let _ = (&mut guard, &mut middle, &mut exit);
        let mut hops_enc = [
            OnionCrypto::with_defaults("guard", [1u8; KEY_SIZE]).unwrap(),
            OnionCrypto::with_defaults("middle", [2u8; KEY_SIZE]).unwrap(),
            OnionCrypto::with_defaults("exit", [3u8; KEY_SIZE]).unwrap(),
        ];
        let onion = OnionCrypto::encrypt_onion(b"GET / HTTP/1.1", &mut hops_enc, &route, 0, true, false, None, None, None).unwrap();

        let (middle_sealed, h1) = guard.peel_layer(&onion).unwrap();
        assert_eq!(h1.kind, Kind::ROUTE);
        let (exit_sealed, h2) = middle.peel_layer(&middle_sealed).unwrap();
        assert_eq!(h2.kind, Kind::ROUTE);
        let (payload, h3) = exit.peel_layer(&exit_sealed).unwrap();
        assert_eq!(h3.kind, Kind::PAYLOAD);
        assert_eq!(payload, b"GET / HTTP/1.1");
    }

    #[test]
    fn test_each_relay_learns_only_its_own_next_hop() {
        let (guard, middle, _exit, route) = make_circuit();
        let mut hops_enc = [
            OnionCrypto::with_defaults("guard", [1u8; KEY_SIZE]).unwrap(),
            OnionCrypto::with_defaults("middle", [2u8; KEY_SIZE]).unwrap(),
            OnionCrypto::with_defaults("exit", [3u8; KEY_SIZE]).unwrap(),
        ];
        let onion = OnionCrypto::encrypt_onion(b"data", &mut hops_enc, &route, 0, true, false, None, None, None).unwrap();
        let peeled_guard = guard.peel(&onion).unwrap();
        assert_eq!(peeled_guard.next_hop, Some(addr("10.0.0.2", 9002)));
        let peeled_middle = middle.peel(peeled_guard.forwarded.as_ref().unwrap()).unwrap();
        assert_eq!(peeled_middle.next_hop, Some(addr("10.0.0.3", 9003)));
    }

    #[test]
    fn test_peel_rejects_tampered_ciphertext() {
        let mut g = hop("guard", [1u8; KEY_SIZE]);
        let mut sealed = g.seal_payload(b"hello", 0, addr("1.2.3.4", 1), None, None).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(g.peel_layer(&sealed).is_err());
    }

    #[test]
    fn test_peel_rejects_wrong_key() {
        let mut g = hop("guard", [1u8; KEY_SIZE]);
        let other = hop("guard", [9u8; KEY_SIZE]);
        let sealed = g.seal_payload(b"hello", 0, addr("1.2.3.4", 1), None, None).unwrap();
        assert!(other.peel_layer(&sealed).is_err());
    }

    #[test]
    fn test_peel_rejects_truncated_field() {
        let g = hop("guard", [1u8; KEY_SIZE]);
        assert!(g.peel_layer(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_peel_layer_type_error_is_avoided_via_slice() {
        // Rust's type system already prevents passing a non-byte-slice, so
        // this covers the analogous "malformed short buffer" case instead.
        let g = hop("guard", [1u8; KEY_SIZE]);
        assert!(g.peel_layer(&[]).is_err());
    }

    #[test]
    fn test_seq_masking_hides_true_seq_on_wire_but_recovers_it() {
        let mut g = hop("guard", [1u8; KEY_SIZE]);
        let sealed = g.seal_payload(b"x", 42, addr("1.2.3.4", 1), None, None).unwrap();
        let wire_seq = u32::from_be_bytes([sealed[0], sealed[1], sealed[2], sealed[3]]);
        assert_ne!(wire_seq, 42); // masked on the wire
        let (_inner, header) = g.peel_layer(&sealed).unwrap();
        assert_eq!(header.seq, 42); // recovered after authentication
    }

    #[test]
    fn test_different_hops_have_different_seq_masks() {
        let g = hop("guard", [1u8; KEY_SIZE]);
        let m = hop("middle", [2u8; KEY_SIZE]);
        assert_ne!(g.seq_prp_key, m.seq_prp_key);
    }

    /// Regression test: the old XOR
    /// mask let two forward cells' wire values on one link cancel the mask
    /// entirely (`wire_a ^ wire_b == seq_a ^ seq_b`), and that exact
    /// difference reappeared on every other hop regardless of its mask.
    /// The keyed PRP must not reproduce that invariant.
    #[test]
    fn test_forward_seq_has_no_cross_hop_xor_relationship() {
        let (guard, middle, _exit, route) = make_circuit();
        let mut hops_a = [
            OnionCrypto::with_defaults("guard", [1u8; KEY_SIZE]).unwrap(),
            OnionCrypto::with_defaults("middle", [2u8; KEY_SIZE]).unwrap(),
            OnionCrypto::with_defaults("exit", [3u8; KEY_SIZE]).unwrap(),
        ];
        let mut hops_b = [
            OnionCrypto::with_defaults("guard", [1u8; KEY_SIZE]).unwrap(),
            OnionCrypto::with_defaults("middle", [2u8; KEY_SIZE]).unwrap(),
            OnionCrypto::with_defaults("exit", [3u8; KEY_SIZE]).unwrap(),
        ];
        let onion_a = OnionCrypto::encrypt_onion(b"x", &mut hops_a, &route, 5, true, false, None, None, None).unwrap();
        let onion_b = OnionCrypto::encrypt_onion(b"x", &mut hops_b, &route, 6, true, false, None, None, None).unwrap();

        let link1_xor = u32::from_be_bytes([onion_a[0], onion_a[1], onion_a[2], onion_a[3]])
            ^ u32::from_be_bytes([onion_b[0], onion_b[1], onion_b[2], onion_b[3]]);

        let (inner_a, _) = guard.peel_layer(&onion_a).unwrap();
        let (inner_b, _) = guard.peel_layer(&onion_b).unwrap();
        let link2_xor = u32::from_be_bytes([inner_a[0], inner_a[1], inner_a[2], inner_a[3]])
            ^ u32::from_be_bytes([inner_b[0], inner_b[1], inner_b[2], inner_b[3]]);

        assert_ne!(link1_xor, link2_xor, "XOR-difference invariant survived across hops -- H4 not fixed");
        assert_ne!(link1_xor, 5 ^ 6, "guard-link wire values still leak the true seq XOR-difference");
        assert_ne!(link2_xor, 5 ^ 6, "middle-link wire values still leak the true seq XOR-difference");
    }

    /// Regression test: the PRP
    /// round-trips across the 32-bit domain, including edge values a wrong
    /// round count or bit order most often gets wrong.
    #[test]
    fn test_seq_prp_round_trips() {
        let key = compute_seq_prp_key(b"some mac key");
        for seq in [0u32, 1, 42, 0x0000_FFFF, 0xFFFF_0000, 0xFFFF_FFFF, 0x1234_5678, u32::MAX / 2] {
            assert_eq!(seq_prp_inverse(&key, seq_prp_forward(&key, seq)), seq, "PRP did not round-trip for seq={seq:#x}");
        }
    }

    #[test]
    fn test_ack_kind_seals_but_peel_layer_rejects_it() {
        // Matches onion.py's `_open`: only ROUTE and the PAYLOAD/EXTEND/
        // EXTENDED/PADDING terminal group are handled by `open`/`peel_layer`.
        // Kind.ACK can still be *sealed* (acks travel as their own datagrams,
        // not through the onion peel path), but peeling one here is a "this
        // build doesn't understand this kind" error, not a round trip.
        let mut g = hop("guard", [1u8; KEY_SIZE]);
        let sealed = g.seal_payload(b"\x00\x00\x00\x01\x00\x00\x00\x00", 0, addr("1.2.3.4", 1), Some(Kind::ACK), None).unwrap();
        let err = g.peel_layer(&sealed).unwrap_err();
        assert!(matches!(err, OnionError::Peel(_)));
    }

    #[test]
    fn test_padding_round_trip_sets_padded_flag() {
        let mut g = hop("guard", [1u8; KEY_SIZE]);
        let sealed = g.seal_payload(b"hi", 0, addr("1.2.3.4", 1), None, Some(200)).unwrap();
        let peeled = g.peel(&sealed).unwrap();
        assert!(peeled.header.padded);
        assert_eq!(peeled.payload_bytes().unwrap(), b"hi");
    }

    #[test]
    fn test_no_padding_when_pad_to_equals_length() {
        let mut g = hop("guard", [1u8; KEY_SIZE]);
        let sealed = g.seal_payload(b"hello", 0, addr("1.2.3.4", 1), None, Some(5)).unwrap();
        let peeled = g.peel(&sealed).unwrap();
        assert!(!peeled.header.padded);
    }

    #[test]
    fn test_pad_plaintext_and_strip_round_trip() {
        let padded = pad_plaintext(b"hi", 200).unwrap();
        assert_eq!(padded.len(), 200);
        assert_eq!(strip_plaintext_padding(&padded), b"hi");
    }

    #[test]
    fn test_pad_plaintext_exact_fit_is_unchanged() {
        let padded = pad_plaintext(b"hi", 2).unwrap();
        assert_eq!(padded, b"hi");
    }

    #[test]
    fn test_pad_plaintext_rejects_shrink() {
        assert!(pad_plaintext(b"hello", 2).is_err());
    }

    #[test]
    fn test_pad_plaintext_rejects_no_room_for_header() {
        assert!(pad_plaintext(b"hello", 6).is_err());
    }

    #[test]
    fn test_strip_plaintext_padding_leaves_unpadded_data_alone() {
        assert_eq!(strip_plaintext_padding(b"short"), b"short");
    }

    #[test]
    fn test_seal_into_cell_and_onion_from_cell_round_trip() {
        let mut g = hop("guard", [1u8; KEY_SIZE]);
        let sealed = g.seal_payload(b"payload-bytes", 0, addr("1.2.3.4", 1), None, None).unwrap();
        let cell = seal_into_cell(&sealed, 0xAABBCCDD, None).unwrap();
        assert_eq!(cell.payload.len(), PAYLOAD_SIZE);
        let recovered = onion_from_cell(&cell, 0);
        assert_eq!(recovered, sealed);
    }

    #[test]
    fn test_seal_into_cell_rejects_oversized_onion() {
        assert!(seal_into_cell(&vec![0u8; PAYLOAD_SIZE + 1], 1, None).is_err());
    }

    #[test]
    fn test_pad_payload_rejects_oversized() {
        assert!(pad_payload(&vec![0u8; PAYLOAD_SIZE + 1], PAYLOAD_SIZE).is_err());
    }

    #[test]
    fn test_peel_circuit_full_route() {
        let (guard, middle, exit, route) = make_circuit();
        let mut hops_enc = [
            OnionCrypto::with_defaults("guard", [1u8; KEY_SIZE]).unwrap(),
            OnionCrypto::with_defaults("middle", [2u8; KEY_SIZE]).unwrap(),
            OnionCrypto::with_defaults("exit", [3u8; KEY_SIZE]).unwrap(),
        ];
        let onion = OnionCrypto::encrypt_onion(b"payload", &mut hops_enc, &route, 0, true, false, None, None, None).unwrap();
        let hops = [guard, middle, exit];
        let payload = peel_circuit(&onion, &hops).unwrap();
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn test_peel_circuit_verbose_traces_each_hop() {
        let (guard, middle, exit, route) = make_circuit();
        let mut hops_enc = [
            OnionCrypto::with_defaults("guard", [1u8; KEY_SIZE]).unwrap(),
            OnionCrypto::with_defaults("middle", [2u8; KEY_SIZE]).unwrap(),
            OnionCrypto::with_defaults("exit", [3u8; KEY_SIZE]).unwrap(),
        ];
        let onion = OnionCrypto::encrypt_onion(b"payload", &mut hops_enc, &route, 0, true, false, None, None, None).unwrap();
        let hops = [guard, middle, exit];
        let trace = peel_circuit_verbose(&onion, &hops).unwrap();
        assert_eq!(trace.len(), 3);
        assert_eq!(trace[0].1, Some(addr("10.0.0.2", 9002)));
        assert_eq!(trace[2].3, Some(addr("93.184.216.34", 80)));
    }

    #[test]
    fn test_encrypt_onion_rejects_mismatched_route_length() {
        let mut hops_enc = [OnionCrypto::with_defaults("guard", [1u8; KEY_SIZE]).unwrap()];
        let route = RoutePlan::new(vec![addr("1.2.3.4", 1), addr("5.6.7.8", 2)], addr("9.9.9.9", 3), PAYLOAD_SIZE as i64).unwrap();
        assert!(OnionCrypto::encrypt_onion(b"x", &mut hops_enc, &route, 0, true, false, None, None, None).is_err());
    }

    #[test]
    fn test_encrypt_onion_rejects_oversized_payload_when_checked() {
        let mut hops_enc = [OnionCrypto::with_defaults("guard", [1u8; KEY_SIZE]).unwrap()];
        let route = RoutePlan::new(vec![addr("1.2.3.4", 1)], addr("9.9.9.9", 3), PAYLOAD_SIZE as i64).unwrap();
        let huge = vec![0u8; PAYLOAD_SIZE];
        assert!(OnionCrypto::encrypt_onion(&huge, &mut hops_enc, &route, 0, true, false, None, None, None).is_err());
    }

    #[test]
    fn test_per_hop_seq_advances_from_guard_to_exit() {
        let (guard, middle, exit, route) = make_circuit();
        let mut hops_enc = [
            OnionCrypto::with_defaults("guard", [1u8; KEY_SIZE]).unwrap(),
            OnionCrypto::with_defaults("middle", [2u8; KEY_SIZE]).unwrap(),
            OnionCrypto::with_defaults("exit", [3u8; KEY_SIZE]).unwrap(),
        ];
        let onion = OnionCrypto::encrypt_onion(b"data", &mut hops_enc, &route, 10, true, true, Some(10), None, None).unwrap();
        let (middle_sealed, h_guard) = guard.peel_layer(&onion).unwrap();
        let (exit_sealed, h_middle) = middle.peel_layer(&middle_sealed).unwrap();
        let (_payload, h_exit) = exit.peel_layer(&exit_sealed).unwrap();
        assert!(h_guard.seq < h_middle.seq);
        assert!(h_middle.seq < h_exit.seq);
    }

    #[test]
    fn test_version_error_is_distinguishable() {
        let mut g = hop("guard", [1u8; KEY_SIZE]);
        let mut sealed = g.seal_payload(b"x", 0, addr("1.2.3.4", 1), None, None).unwrap();
        assert_eq!(sealed[10], crate::layer::LAYER_PROTOCOL_VERSION);
        sealed[10] = 0x01; // corrupt the version byte (offset 10 in the wire header)
        let err = g.peel_layer(&sealed).unwrap_err();
        assert!(matches!(err, OnionError::Version { .. }));
    }

    /// The point of format 0xA4: no cleartext byte of a sealed onion names
    /// a hop or the destination. Every address on the route is checked
    /// against the bytes *outside* each layer's ciphertext at every hop.
    #[test]
    fn test_wire_headers_leak_no_addresses() {
        let (guard, middle, _exit, route) = make_circuit();
        let mut hops_enc = [
            OnionCrypto::with_defaults("guard", [1u8; KEY_SIZE]).unwrap(),
            OnionCrypto::with_defaults("middle", [2u8; KEY_SIZE]).unwrap(),
            OnionCrypto::with_defaults("exit", [3u8; KEY_SIZE]).unwrap(),
        ];
        let onion = OnionCrypto::encrypt_onion(b"data", &mut hops_enc, &route, 0, true, false, None, None, None).unwrap();

        let mut addr_bytes: Vec<[u8; 6]> = Vec::new();
        for (ip, port) in route.hops.iter().chain(std::iter::once(&route.final_addr)) {
            let octets: Vec<u8> = ip.split('.').map(|o| o.parse().unwrap()).collect();
            let mut b = [0u8; 6];
            b[..4].copy_from_slice(&octets);
            b[4..].copy_from_slice(&port.to_be_bytes());
            addr_bytes.push(b);
        }
        let assert_clean = |wire: &[u8], link: &str| {
            for a in &addr_bytes {
                assert!(!wire.windows(6).any(|w| w == a), "{link}: wire header contains address {a:?}");
            }
        };

        assert_clean(&onion[..WIRE_HEADER_SIZE], "client->guard");
        let (to_middle, _) = guard.peel_layer(&onion).unwrap();
        assert_clean(&to_middle[..WIRE_HEADER_SIZE], "guard->middle");
        let (to_exit, _) = middle.peel_layer(&to_middle).unwrap();
        assert_clean(&to_exit[..WIRE_HEADER_SIZE], "middle->exit");
    }

    #[test]
    fn test_initial_payload_rejects_oversized_result() {
        let mut g = hop("guard", [1u8; KEY_SIZE]);
        let huge = vec![0u8; PAYLOAD_SIZE];
        assert!(g.initial_payload(&huge, 0, addr("1.2.3.4", 1), None, None).is_err());
    }
}
