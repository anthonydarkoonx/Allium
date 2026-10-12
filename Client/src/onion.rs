//! Onion encryption and peeling for Allium circuits.
//!
//! Two roles, two entry points:
//!
//! **Client** -- [`OnionCrypto::encrypt_onion`] wraps a payload in one layer
//! per relay. Layer 1 (Guard) is applied *last* so it is outermost, i.e.
//! peeled first:
//!
//! ```text
//! seal_payload(user_data, exit)   ->  inner     (for the Exit)
//! wrap(next_hop=n, inner)         ->  middle    (for the Middle)
//! wrap(next_hop=g, middle)        ->  onion     (for the Guard)
//! ```
//!
//! **Relay** -- [`OnionCrypto::peel_layer`] removes exactly one layer with
//! the relay's own key and returns the *inner* blob unchanged. The relay
//! never learns how many hops remain, who they are, or what the final
//! target is unless it is the exit:
//!
//! ```text
//! onion  --[Guard key]-->  middle --[Middle key]-->  inner --[Exit key]-->  user data
//! ```

use blake2::Blake2b;
use digest::consts::{U2, U32};
use digest::{CustomizedInit, Digest as _};
use subtle::ConstantTimeEq;

use crate::cell::{Cell, Command, PAYLOAD_SIZE};
use crate::crypto::{self, CryptoError, SaltAead, KEY_SIZE, SEAL_OVERHEAD};
use crate::layer::{Kind, LayerError, LayerHeader};
use crate::sizes::{onion_size, RoutePlan, SizesError, ROUTE_HEADER_SIZE, SEALED_HEADER_SIZE, WIRE_HEADER_SIZE};

/// AEAD used unless a node is constructed with another one.
pub const DEFAULT_CIPHER: &str = "chacha20-poly1305";

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

/// Errors from building or peeling an onion layer.
///
/// The Python original splits this into `OnionBuildError` (client side),
/// `OnionPeelError` (relay side, deliberately coarse: an authentication
/// failure, a truncated field, and a short header all surface the same way
/// so a relay cannot be used as a decryption oracle), and
/// `OnionVersionError` (a subclass of the peel error, for the one failure
/// an operator can act on). Rust has no exception hierarchy to subclass, so
/// they are flattened into one enum; callers that only care about "was this
/// a version mismatch" match on [`OnionError::Version`] directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnionError {
    /// Raised on the client side when a layer cannot be built: an oversized
    /// payload, too many or too few hops, or a malformed route.
    Build(String),
    /// Raised on the relay side when a layer cannot be peeled.
    Peel(String),
    /// The peer's layer format is one this build cannot read -- see
    /// [`crate::layer::LayerError::Version`].
    Version { message: String, observed: u8 },
    /// A sealed field, or the sealed onion itself, does not fit the space
    /// available (the cell payload buffer, or a caller-supplied `pad_to`).
    /// Kept distinct from [`OnionError::Build`] because the Python original
    /// raises a separate `allium.sizes.OnionTooLargeError` for this case,
    /// not `OnionBuildError`.
    TooLarge(String),
}

impl std::fmt::Display for OnionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OnionError::Build(m) | OnionError::Peel(m) | OnionError::TooLarge(m) => write!(f, "{m}"),
            OnionError::Version { message, .. } => write!(f, "{message}"),
        }
    }
}
impl std::error::Error for OnionError {}

impl From<SizesError> for OnionError {
    fn from(e: SizesError) -> Self {
        match e {
            SizesError::OnionTooLarge(m) => OnionError::TooLarge(m),
            SizesError::Value(m) => OnionError::Build(m),
        }
    }
}

fn layer_error_to_build(e: LayerError) -> OnionError {
    match e {
        LayerError::Header(m) => OnionError::Build(m),
        LayerError::Version { message, observed } => OnionError::Version { message, observed },
    }
}

// --------------------------------------------------------------------------
// Data classes
// --------------------------------------------------------------------------

/// One hop's key material.
///
/// Args mirror the Python constructor: `name` is `"guard"`, `"middle"` or
/// `"exit"`, used only for error messages; `aead` seals and opens this
/// hop's layer; `mac_key` is [`KEY_SIZE`] bytes for the header MAC, kept
/// distinct from the AEAD key (two independent keys from one hop's key
/// agreement, rather than one key doing both jobs).
/// `aead`/`open_aead`: these used to be a single `aead` field, one AEAD
/// instance used for *both* directions of
/// traffic through this hop (sealing this side's own outgoing data, and
/// opening the peer's incoming data). That was safe only as long as
/// nonces stayed random (this crate's only production nonce source): a
/// future switch to counter-based nonces could then silently reuse a
/// `(key, nonce)` pair across the two directions, which is catastrophic
/// for any AEAD. Splitting the key itself removes that risk regardless of
/// how nonces are chosen later: `aead` is this side's own seal key,
/// `open_aead` is the peer's -- [`OnionCrypto::new`]'s two key parameters,
/// threaded from `handshake::HandshakeKeys`'s now-separate
/// `aead_key_fwd`/`aead_key_bwd`, decide which is which per hop role.
pub struct Layer {
    pub name: String,
    pub aead: SaltAead,
    pub open_aead: SaltAead,
    pub mac_key: Vec<u8>,
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
    /// Build a layer directly from two constructed AEADs.
    ///
    /// # Errors
    /// Returns [`OnionError::Build`] if `mac_key` is not exactly
    /// [`KEY_SIZE`] bytes.
    pub fn new(name: String, aead: SaltAead, open_aead: SaltAead, mac_key: Vec<u8>, cipher: String) -> Result<Self, OnionError> {
        if mac_key.len() != KEY_SIZE {
            return Err(OnionError::Build(format!(
                "{name}: mac_key must be exactly {KEY_SIZE} bytes, got {}",
                mac_key.len()
            )));
        }
        Ok(Layer { name, aead, open_aead, mac_key, cipher })
    }

    /// Build a layer from raw keys, constructing both AEADs via
    /// [`crate::crypto::new_aead`]. `seal_key`/`open_key` may be the same
    /// key for a caller that genuinely doesn't need direction separation
    /// (see [`Layer::from_key`]).
    pub fn from_keys(name: String, seal_key: &[u8], open_key: &[u8], mac_key: Vec<u8>, cipher: String) -> Result<Self, OnionError> {
        let aead = crypto::new_aead(&cipher, seal_key, None).map_err(|e| OnionError::Build(format!("{name}: {e}")))?;
        let open_aead = crypto::new_aead(&cipher, open_key, None).map_err(|e| OnionError::Build(format!("{name}: {e}")))?;
        Self::new(name, aead, open_aead, mac_key, cipher)
    }

    /// [`Layer::from_keys`] with the same key both ways -- for a caller
    /// (tests, or any context with only one flow of traffic through this
    /// layer) that doesn't need direction separation. The real handshake
    /// path (`handshake::HandshakeKeys::to_layer`) always uses
    /// [`Layer::from_keys`] with genuinely distinct keys.
    pub fn from_key(name: String, key: &[u8], mac_key: Vec<u8>, cipher: String) -> Result<Self, OnionError> {
        Self::from_keys(name, key, key, mac_key, cipher)
    }

    /// Derive both keys for a hop from one handshake secret. Test-only
    /// helper (uses `crypto::derive_key`'s test-oriented derivation, not
    /// the real handshake's HKDF); the real handshake path never calls
    /// this.
    ///
    /// Splits the secret with domain-separated labels so the AEAD key and
    /// the MAC key are independent.
    pub fn derive(name: String, shared_secret: &[u8], cipher: String) -> Result<Self, OnionError> {
        let aead_key = crypto::derive_key(shared_secret, b"allium-aead-key-v1");
        let mac_key = crypto::derive_key(shared_secret, b"allium-header-mac-v1");
        Self::from_key(name, &aead_key, mac_key.to_vec(), cipher)
    }
}

impl std::fmt::Debug for Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Layer(name={:?}, cipher={:?}, keys=<redacted>)", self.name, self.cipher)
    }
}

/// What [`OnionCrypto::open_layer`] found inside a ROUTE layer versus a
/// terminal one. In both cases the layer's sealed header part has already
/// been split off into the returned [`LayerHeader`].
enum OpenedBody {
    /// A ROUTE layer: `forwarded` is the next relay's complete sealed
    /// frame, to pass on untouched. Where to send it is the header's
    /// `next_hop`.
    Route { forwarded: Vec<u8> },
    /// A PAYLOAD, EXTEND, EXTENDED, or PADDING layer: nothing follows but
    /// the plaintext itself.
    Terminal { plaintext: Vec<u8> },
}

/// What a relay gets back from [`OnionCrypto::peel`].
pub struct PeeledLayer {
    /// The hop's own header.
    pub header: LayerHeader,
    /// For a ROUTE layer, the next hop's forwarded sealed field; for a
    /// terminal layer, the user data (or inner payload) bound for
    /// `target_addr`.
    pub plaintext: Vec<u8>,
    /// The layer still wrapped for the next hop. `None` on the exit hop;
    /// for a ROUTE layer it equals the received sealed field with the
    /// inner header stripped -- a relay forwards the ciphertext untouched.
    pub forwarded: Option<Vec<u8>>,
    /// The exact sealed field this relay received.
    pub sealed: Vec<u8>,
    /// `(ip, port)` of the next relay, or `None` when this is the exit hop.
    pub next_hop: Option<(String, u16)>,
    /// For a terminal layer, the `(ip, port)` the exit should connect to
    /// (or the ack/extend/padding target); `None` for a ROUTE layer.
    pub target_addr: Option<(String, u16)>,
}

impl PeeledLayer {
    /// `true` when this relay is the exit hop (no next relay).
    pub fn is_terminal(&self) -> bool {
        self.next_hop.is_none()
    }
    /// `true` when the plaintext is user data rather than a next-hop address.
    pub fn is_payload(&self) -> bool {
        self.header.kind == Kind::PAYLOAD
    }
    /// `true` when this layer carries an acknowledgement.
    ///
    /// Kept for parity with the Python original's `is_ack` property. Note
    /// that [`OnionCrypto::open_layer`] never actually produces a
    /// [`PeeledLayer`] with `kind == Kind::ACK` -- like the Python
    /// original, an ACK-kind layer is rejected by `open_layer` with
    /// "unknown layer kind" before a `PeeledLayer` could be built (ACK
    /// layers are recognized one level up, by whoever calls `peel`).
    pub fn is_ack(&self) -> bool {
        self.header.kind == Kind::ACK
    }
    /// `true` when this layer asks the peeling hop to CREATE a new hop.
    pub fn is_extend(&self) -> bool {
        self.header.kind == Kind::EXTEND
    }
    /// `true` when this layer is a reply to an EXTEND.
    pub fn is_extended(&self) -> bool {
        self.header.kind == Kind::EXTENDED
    }
    /// `true` when this layer is shaped traffic to be discarded.
    pub fn is_padding(&self) -> bool {
        self.header.kind == Kind::PADDING
    }

    /// Return user data, raising if this layer is not a PAYLOAD layer.
    ///
    /// Strips padding ([`strip_plaintext_padding`]) only when
    /// `header.padded` says the sender actually applied it, rather than
    /// sniffing every payload's tail for a marker byte that real,
    /// unpadded data can also happen to end with.
    ///
    /// # Errors
    /// Returns [`OnionError::Peel`] if the layer is not a PAYLOAD layer.
    pub fn payload_bytes(&self) -> Result<Vec<u8>, OnionError> {
        if !self.is_payload() {
            return Err(OnionError::Peel(format!(
                "{} layer carries no user payload",
                Kind::name(self.header.kind)
            )));
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
///
/// One instance per node: the client holds one for each hop it is building
/// toward, and a relay holds a single instance bound to its own identity.
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

/// Number of Feistel rounds in the sequence-number PRP (replacing the
/// earlier XOR mask). This obfuscates a 32-bit field, not a general-purpose
/// message, so it does not need to resist large-scale cryptanalysis -- it
/// only needs no exploitable algebraic relationship between what the same
/// logical cell looks like at one hop versus another. Four rounds give full
/// diffusion between both 16-bit halves, which an XOR mask (equivalent to a
/// zero-round, linear "PRP") never provided: XORing the wire values of two
/// forward cells cancelled the mask entirely and reproduced the true seq
/// difference identically on every hop, which is exactly how the
/// cross-link correlation attack in H4 worked.
const SEQ_PRP_ROUNDS: u8 = 4;

/// Derive this hop's key for the sequence-number PRP from its own
/// `mac_key`, independent of the AEAD key and the header MAC key:
/// `blake2b(mac_key, digest_size=32, person=b"allium-seqprp-k1")`. Two
/// different hops derive two unrelated PRP keys from independent
/// key-agreement outputs. (blake2b's personalization field caps at 16
/// bytes, hence the compressed spelling.)
fn compute_seq_prp_key(mac_key: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new_customized(b"allium-seqprp-k1");
    hasher.update(mac_key);
    hasher.finalize().into()
}

/// One Feistel round function: keyed, round-separated, 16 bits out. Doesn't
/// need to be invertible itself -- only the Feistel structure built from it
/// does.
fn seq_prp_round_fn(key: &[u8; 32], round: u8, half: u16) -> u16 {
    let mut hasher = Blake2b::<U2>::new_customized(b"allium-seqprp-rf");
    hasher.update(&key[..]);
    let round_and_half: [u8; 3] = [round, (half >> 8) as u8, half as u8];
    hasher.update(&round_and_half[..]);
    let digest = hasher.finalize();
    u16::from_be_bytes(digest.into())
}

/// Encrypt `seq` through the keyed Feistel network: split into two 16-bit
/// halves and apply [`SEQ_PRP_ROUNDS`] rounds in order.
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

/// Invert [`seq_prp_forward`]: undo a Feistel network by applying the same
/// round functions in reverse round order. Unlike XOR, masking and
/// unmasking are genuinely different operations here.
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

/// A fixed-size digest of a sealed blob, for folding into a MAC.
///
/// Hashing to a constant 32 bytes keeps the MAC input length independent of
/// the blob's size, and keeps MAC computation cheap on large outer layers.
fn seal_binding(sealed: &[u8]) -> [u8; 32] {
    let mut hasher = blake2::Blake2b256::new_customized(b"allium-bind");
    hasher.update(sealed);
    hasher.finalize().into()
}

/// Build the byte string a layer's header MAC authenticates.
///
/// `plaintext` is the whole AEAD plaintext, sealed header part first, so
/// the layer's kind and address are always covered. For a ROUTE layer a
/// digest of the sealed blob follows, binding the header to the ciphertext
/// it travels with. For a terminal layer it is just the plaintext: the exit
/// has no inner layer to bind, and its header MAC already covers the
/// payload.
fn mac_input(kind: u8, plaintext: &[u8], payload: &[u8]) -> Vec<u8> {
    if kind == Kind::ROUTE {
        let mut v = plaintext.to_vec();
        v.extend_from_slice(&seal_binding(payload));
        v
    } else {
        plaintext.to_vec()
    }
}

fn to_u16_len(n: usize, what: &str) -> Result<u16, OnionError> {
    u16::try_from(n).map_err(|_| {
        OnionError::Build(format!(
            "{what} is {n} bytes, which does not fit the 16-bit layer header length field"
        ))
    })
}

impl OnionCrypto {
    /// Build a node's view of one hop.
    ///
    /// `seal_key`/`open_key`: previously one `key` used for both
    /// directions -- see [`Layer`]'s doc comment
    /// for why that's no longer the case. `seal_key` encrypts this side's
    /// own outgoing traffic through this hop; `open_key` decrypts the
    /// peer's incoming traffic. Pass the same value for both if direction
    /// separation genuinely doesn't apply.
    ///
    /// `mac_key` defaults to `derive_key(seal_key, b"allium-header-mac-v1")`
    /// when `None`, which keeps a demonstration call working, but
    /// production code should pass an independently derived key so the
    /// AEAD and MAC secrets differ.
    ///
    /// # Errors
    /// Returns [`OnionError::Build`] if the keys are the wrong length or
    /// the cipher is unknown.
    pub fn new(
        name: impl Into<String>,
        seal_key: &[u8],
        open_key: &[u8],
        mac_key: Option<Vec<u8>>,
        cipher: Option<&str>,
        hop_index: usize,
        aad_context: Option<Vec<u8>>,
    ) -> Result<Self, OnionError> {
        let name = name.into();
        let cipher = cipher.unwrap_or(DEFAULT_CIPHER).to_string();
        let mac_key = mac_key.unwrap_or_else(|| crypto::derive_key(seal_key, b"allium-header-mac-v1").to_vec());
        let layer = Layer::from_keys(name.clone(), seal_key, open_key, mac_key, cipher.clone())?;
        let seq_prp_key = compute_seq_prp_key(&layer.mac_key);
        Ok(OnionCrypto {
            name,
            layer,
            cipher,
            hop_index,
            aad_context: aad_context.unwrap_or_default(),
            seq_prp_key,
        })
    }

    /// Obfuscate `seq` through this hop's keyed PRP before it reaches a
    /// wire header. Because the PRP is keyed per hop and non-linear,
    /// there is no way to combine two
    /// wire values -- from the same hop or different hops -- to recover a
    /// relationship between their true `seq` values without the key,
    /// unlike the previous XOR mask.
    fn mask_seq(&self, seq: u32) -> u32 {
        seq_prp_forward(&self.seq_prp_key, seq)
    }

    /// Invert [`OnionCrypto::mask_seq`]. Unlike XOR, masking and unmasking
    /// are different operations -- kept as a distinct function so call
    /// sites still read correctly.
    fn unmask_seq(&self, seq: u32) -> u32 {
        seq_prp_inverse(&self.seq_prp_key, seq)
    }

    // ------------------------------------------------------------------
    // Client side
    // ------------------------------------------------------------------

    /// Seal `plaintext` under this layer's key, binding the wire header as
    /// AAD.
    ///
    /// The header's MAC field is zeroed for the AAD so the MAC can be
    /// computed over the sealed field afterwards.
    fn seal_(&mut self, header: &LayerHeader, plaintext: &[u8], seq: u32) -> Result<Vec<u8>, OnionError> {
        let mut aad = header.pack_unsigned(Some(seq)).to_vec();
        aad.extend_from_slice(&self.aad_context);
        self.layer
            .aead
            .seal(plaintext, &aad)
            .map_err(|e: CryptoError| OnionError::Build(format!("{}: {e}", self.name)))
    }

    /// Frame one layer: seal `body` behind `header`'s sealed part, sign,
    /// and emit `wire header || ciphertext`.
    ///
    /// `header` must carry everything but `length` and `mac`. The plaintext
    /// handed to the AEAD is the header's sealed part (kind, padded flag,
    /// address) followed by `body`, so nothing on the wire says what kind
    /// of layer this is or where it is headed. The MAC is computed over
    /// that same plaintext -- the relay has to recompute it after
    /// decrypting, and can only do that over bytes it knows -- plus, for a
    /// ROUTE layer, a digest of the ciphertext, which binds the header to
    /// the blob it travelled with so a relay cannot detach the header and
    /// re-attach it to a different ciphertext it happens to hold.
    fn frame(&mut self, mut header: LayerHeader, body: &[u8], wire_seq: u32, what: &str) -> Result<Vec<u8>, OnionError> {
        let mut plaintext = header.pack_sealed().to_vec();
        plaintext.extend_from_slice(body);
        header.length = to_u16_len(plaintext.len() + SEAL_OVERHEAD, what)?;

        let sealed = self.seal_(&header, &plaintext, wire_seq)?;
        let mac_input_bytes = mac_input(header.kind, &plaintext, &sealed);
        let signed = header.signed(&self.layer.mac_key, &mac_input_bytes, Some(wire_seq));
        let mut out = signed.pack(Some(wire_seq)).to_vec();
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Build the *innermost* sealed field: the user data, headed for the exit.
    ///
    /// This is the layer the Exit relay peels last. The header's sealed
    /// part carries the exit's target address in its 6-byte address slot.
    ///
    /// `kind` overrides the layer kind -- pass [`Kind::ACK`] to build an
    /// acknowledgement travelling *back* along the circuit. `pad_to` pads
    /// `user_data` to exactly this many bytes *before* sealing (see
    /// [`pad_plaintext`]), marking the header `padded` so the receiver
    /// recovers the real length with [`PeeledLayer::payload_bytes`].
    ///
    /// # Errors
    /// Returns [`OnionError::Build`] if `pad_to` cannot accommodate
    /// `user_data`, or if the sealed length does not fit the header's
    /// 16-bit length field.
    pub fn seal_payload(
        &mut self,
        user_data: &[u8],
        seq: u32,
        final_addr: (String, u16),
        kind: Option<u8>,
        pad_to: Option<usize>,
    ) -> Result<Vec<u8>, OnionError> {
        let mut actually_padded = false;
        let user_data = if let Some(target) = pad_to {
            let padded_data = pad_plaintext(user_data, target)?;
            actually_padded = padded_data.len() != user_data.len();
            padded_data
        } else {
            user_data.to_vec()
        };

        // H2: mask `seq` with this hop's own key material before it ever
        // reaches a header.
        let wire_seq = self.mask_seq(seq);
        let header = LayerHeader::new(
            wire_seq,
            kind.unwrap_or(Kind::PAYLOAD),
            final_addr,
            Vec::new(),
            None,
            actually_padded,
        )
        .map_err(layer_error_to_build)?;
        self.frame(header, &user_data, wire_seq, "sealed payload length")
    }

    /// Wrap `sealed_inner` in this hop's layer, headed for `next_hop`.
    ///
    /// The layer's plaintext is this header's sealed part (naming
    /// `next_hop`) followed by `sealed_inner`, the next relay's complete
    /// frame. The receiving relay decrypts, reads the address to learn
    /// where to send next, and forwards `sealed_inner` untouched.
    ///
    /// Returns a sealed field longer than its input, so layers must be
    /// applied from the inside out.
    ///
    /// # Errors
    /// Returns [`OnionError::Build`] if the wrapped length does not fit the
    /// header's 16-bit length field.
    pub fn wrap(&mut self, sealed_inner: &[u8], next_hop: (String, u16), seq: u32) -> Result<Vec<u8>, OnionError> {
        // H2: mask `seq` with this hop's own key material.
        let wire_seq = self.mask_seq(seq);
        let header = LayerHeader::new(wire_seq, Kind::ROUTE, next_hop, Vec::new(), None, false)
            .map_err(layer_error_to_build)?;
        self.frame(header, sealed_inner, wire_seq, "wrapped layer length")
    }

    // ------------------------------------------------------------------
    // Top-level client API
    // ------------------------------------------------------------------

    /// Return hop names in the order layers must be applied to a payload.
    ///
    /// Reverses the route: the exit is innermost and sealed first, the
    /// guard is outermost and sealed last, so the guard's layer is peeled
    /// first.
    pub fn encryption_order(hops: &[OnionCrypto]) -> Vec<String> {
        hops.iter().rev().map(|hop| hop.name.clone()).collect()
    }

    /// Onion-encrypt `payload` under one key per hop.
    ///
    /// Applies one layer per hop, innermost first, so the layer order on
    /// the wire is the reverse of `hops`:
    ///
    /// ```text
    /// hops = [guard, middle, exit]
    /// encrypt_onion(payload, hops, route)
    ///     == guard.wrap(middle.wrap(exit.seal_payload(payload)))
    /// ```
    ///
    /// `per_hop_seq` stamps a *different* sequence number on each layer
    /// (see the Python docstring for the exact numbering); `hop_seq_base`
    /// is the sequence number for the innermost (exit) layer, defaulting
    /// to `seq`. `kind` overrides the innermost layer's [`Kind`] (default
    /// [`Kind::PAYLOAD`]); `pad_to` pads `payload` before sealing.
    ///
    /// `per_hop_seq`/`hop_seq_base` are kept for API compatibility but no
    /// longer carry any of the
    /// protection this module relies on. They used to stamp each hop with
    /// a fixed linear offset from one base value -- itself trivially
    /// linkable (the offsets are public and constant) -- and no production
    /// caller ever set `per_hop_seq: true` anyway, so every layer got the
    /// *same* `seq`. Hop-to-hop unlinkability now comes entirely from
    /// [`OnionCrypto::mask_seq`]'s per-hop keyed PRP: even with the same
    /// `seq` on every layer (the default, and effectively the only
    /// production path), each hop's independently-keyed PRP output is
    /// unrelated to every other hop's, so a passive observer gains nothing
    /// from seeing the same logical cell's wire bytes on two different
    /// links.
    ///
    /// # Errors
    /// Returns [`OnionError::Build`] if the hop list is empty or the route
    /// length does not match the hop count. Returns [`OnionError::TooLarge`]
    /// if `check_size` and the payload does not fit.
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt_onion(
        payload: &[u8],
        hops: &mut [OnionCrypto],
        route: &RoutePlan,
        seq: u32,
        check_size: bool,
        per_hop_seq: bool,
        hop_seq_base: Option<u32>,
        kind: Option<u8>,
        pad_to: Option<usize>,
    ) -> Result<Vec<u8>, OnionError> {
        if hops.is_empty() {
            return Err(OnionError::Build("an onion needs at least one hop".into()));
        }
        if route.hop_count() != hops.len() {
            return Err(OnionError::Build(format!(
                "route has {} addresses but {} keys were given; they must match one-to-one",
                route.hop_count(),
                hops.len()
            )));
        }
        if check_size {
            let effective_len = pad_to.unwrap_or(payload.len());
            onion_size(effective_len, hops.len())?;
        }

        let last = hops.len() - 1;
        let base = hop_seq_base.unwrap_or(seq);
        let layer_seq = |index: usize| -> u32 {
            if !per_hop_seq {
                return seq;
            }
            // Peel order is guard (index 0) first, so it takes the lowest
            // value and the exit the highest: the numbers advance with
            // time. Matches Python's `(base - (last - index)) % 2**32`.
            base.wrapping_sub((last - index) as u32)
        };

        let mut sealed = hops[last].seal_payload(
            payload,
            layer_seq(last),
            route.final_addr.clone(),
            kind,
            pad_to,
        )?;
        for index in (0..last).rev() {
            let next_hop = route
                .next_hop(index)
                .map_err(|e| OnionError::Build(e.to_string()))?
                .cloned()
                .expect("index < last always has a next hop");
            sealed = hops[index].wrap(&sealed, next_hop, layer_seq(index))?;
        }
        Ok(sealed)
    }

    // ------------------------------------------------------------------
    // Relay side
    // ------------------------------------------------------------------

    /// Verify and open one layer, returning its header (sealed part
    /// applied), the opened body, and the sealed field this relay
    /// received.
    fn open_layer(&self, received: &[u8]) -> Result<(LayerHeader, OpenedBody, Vec<u8>), OnionError> {
        // The smallest well-formed layer: wire header, then a ciphertext
        // holding at least the sealed header part and nothing else.
        const MIN_LAYER: usize = ROUTE_HEADER_SIZE + SEAL_OVERHEAD;
        const MIN_BODY: usize = SEALED_HEADER_SIZE + SEAL_OVERHEAD;
        if received.len() < MIN_LAYER {
            return Err(OnionError::Peel(format!(
                "sealed field is {} bytes, minimum is {MIN_LAYER}",
                received.len()
            )));
        }
        let mut header = LayerHeader::unpack(received).map_err(|e| match e {
            // Ordered before the generic handler below: a version mismatch
            // flattened into the coarse "malformed header" message is
            // exactly the opaque failure this field exists to stop.
            LayerError::Version { message, observed } => OnionError::Version {
                message: format!("{}: {message}", self.name),
                observed,
            },
            LayerError::Header(m) => OnionError::Peel(format!("malformed layer header: {m}")),
        })?;

        // H1: `header.length` is the true size of the ciphertext that
        // follows the wire header; anything past it in `received` is
        // wire-level zero padding and must never be handed to the AEAD.
        if (header.length as usize) < MIN_BODY {
            return Err(OnionError::Peel(format!(
                "declared body length {} is smaller than the {MIN_BODY}-byte minimum \
                 (sealed header part plus AEAD overhead)",
                header.length
            )));
        }
        if WIRE_HEADER_SIZE + header.length as usize > received.len() {
            return Err(OnionError::Peel(format!(
                "declared body length {} exceeds the {} bytes available",
                header.length,
                received.len() - WIRE_HEADER_SIZE
            )));
        }
        let payload = received[WIRE_HEADER_SIZE..WIRE_HEADER_SIZE + header.length as usize].to_vec();

        // The AAD was built over the unsigned wire header, so recompute it
        // the same way rather than trusting the MAC bytes that arrived.
        let mut aad = header.pack_unsigned(Some(header.seq)).to_vec();
        aad.extend_from_slice(&self.aad_context);
        let plaintext = self
            .layer
            .open_aead
            .open(&payload, &aad)
            .map_err(|e| OnionError::Peel(format!("{}: {e}", self.name)))?;

        // The AEAD has authenticated the plaintext, so its leading sealed
        // header part -- the layer's kind and address -- can be trusted
        // enough to decide what the MAC input looks like. `MIN_BODY`
        // guaranteed the bytes are there.
        header
            .unpack_sealed(&plaintext)
            .map_err(|e| OnionError::Peel(format!("{}: malformed sealed header: {e}", self.name)))?;

        let mac_input_bytes = mac_input(header.kind, &plaintext, &payload);
        let mac_expected = header.compute_mac(&self.layer.mac_key, &mac_input_bytes, Some(header.seq));
        // The MAC is verified over the decrypted plaintext (plus, for
        // ROUTE layers, the sealed blob) -- the same value the sealer
        // signed.
        if !bool::from(mac_expected.as_slice().ct_eq(header.mac.as_slice())) {
            return Err(OnionError::Peel(format!(
                "{}: header MAC mismatch; next_hop may have been tampered with",
                self.name
            )));
        }

        // H2: only once the header has authenticated does this recover the
        // true, monotonic sequence number from its wire mask.
        header.seq = self.unmask_seq(header.seq);

        let body = plaintext[SEALED_HEADER_SIZE..].to_vec();

        if header.kind == Kind::ROUTE {
            // The body *is* the next relay's frame: its wire header, then
            // its ciphertext. Forward it verbatim.
            if body.len() < MIN_LAYER {
                return Err(OnionError::Peel(format!(
                    "route layer body is {} bytes; too short to hold an inner frame",
                    body.len()
                )));
            }
            return Ok((header, OpenedBody::Route { forwarded: body }, payload));
        }

        // PAYLOAD, EXTEND, EXTENDED, and PADDING are all terminal,
        // single-field kinds: nothing follows but the body itself.
        if matches!(header.kind, Kind::PAYLOAD | Kind::EXTEND | Kind::EXTENDED | Kind::PADDING) {
            return Ok((header, OpenedBody::Terminal { plaintext: body }, payload));
        }

        Err(OnionError::Peel(format!(
            "{}: unknown layer kind {}; this build understands {} (ROUTE), {} (PAYLOAD), \
             {} (EXTEND), {} (EXTENDED), and {} (PADDING)",
            self.name,
            header.kind,
            Kind::ROUTE,
            Kind::PAYLOAD,
            Kind::EXTEND,
            Kind::EXTENDED,
            Kind::PADDING
        )))
    }

    /// Decrypt exactly one layer with this node's key.
    ///
    /// The workhorse for a relay: hand it whatever arrived and it returns
    /// the inner blob plus this hop's own header. `inner` is the next
    /// hop's sealed field, or the user data when this is the exit hop. It
    /// is *raw*: pad it to [`crate::cell::PAYLOAD_SIZE`] with
    /// [`pad_payload`] before packing it into a cell to forward.
    ///
    /// # Errors
    /// Returns [`OnionError::Peel`] (or [`OnionError::Version`]) if the
    /// layer is truncated, malformed, or fails to authenticate.
    pub fn peel_layer(&self, received: &[u8]) -> Result<(Vec<u8>, LayerHeader), OnionError> {
        let (header, body, _payload) = self.open_layer(received)?;
        match body {
            OpenedBody::Terminal { plaintext } => Ok((plaintext, header)),
            OpenedBody::Route { forwarded, .. } => Ok((forwarded, header)),
        }
    }

    /// Like [`OnionCrypto::peel_layer`], but returns every detail of the peel.
    ///
    /// # Errors
    /// As for [`OnionCrypto::peel_layer`].
    pub fn peel(&self, received: &[u8]) -> Result<PeeledLayer, OnionError> {
        let (header, body, payload) = self.open_layer(received)?;
        match body {
            OpenedBody::Terminal { plaintext } => {
                // Every terminal kind (PAYLOAD, EXTEND, EXTENDED, PADDING)
                // is one of `LayerHeader::TARGET_KINDS`, so `target_addr`
                // always succeeds here.
                let target_addr = header.next_hop.clone();
                Ok(PeeledLayer {
                    header,
                    plaintext,
                    forwarded: None,
                    sealed: payload,
                    next_hop: None,
                    target_addr: Some(target_addr),
                })
            }
            OpenedBody::Route { forwarded } => {
                // `forwarded` is the data to forward; the address to send
                // it to came out of this layer's sealed header part.
                let next_hop = header.next_hop.clone();
                Ok(PeeledLayer {
                    header,
                    plaintext: forwarded.clone(),
                    forwarded: Some(forwarded),
                    sealed: payload,
                    next_hop: Some(next_hop),
                    target_addr: None,
                })
            }
        }
    }

    // ------------------------------------------------------------------
    // Cell integration
    // ------------------------------------------------------------------

    /// Build the innermost layer for a single-hop circuit.
    ///
    /// Returns the raw sealed field, *not* padded to the cell buffer:
    /// padding is applied when the field is packed into a cell (see
    /// [`pad_payload`]), and [`OnionCrypto::peel_layer`] expects a bare
    /// sealed field.
    ///
    /// # Errors
    /// Returns [`OnionError::TooLarge`] if the sealed result exceeds the
    /// cell payload buffer.
    pub fn initial_payload(
        &mut self,
        payload: &[u8],
        seq: u32,
        final_addr: (String, u16),
        kind: Option<u8>,
        pad_to: Option<usize>,
    ) -> Result<Vec<u8>, OnionError> {
        let sealed = self.seal_payload(payload, seq, final_addr, kind, pad_to)?;
        if sealed.len() > PAYLOAD_SIZE {
            return Err(OnionError::TooLarge(format!(
                "sealed layer is {} bytes, cell payload buffer is {PAYLOAD_SIZE}",
                sealed.len()
            )));
        }
        Ok(sealed)
    }
}

// --------------------------------------------------------------------------
// Plaintext length padding
// --------------------------------------------------------------------------

/// Size of one trailing-padding entry: 2 length bytes + 1 marker byte.
pub const TRAILING_PAD_ENTRY_SIZE: usize = 3;

/// Largest padding [`pad_plaintext`] can encode (2-byte length).
pub const MAX_PLAINTEXT_PADDING: usize = (1 << 16) - 1;

/// Marker byte written before the padding length. Chosen to be unlikely to
/// match the last byte of real user data, which makes accidental agreement
/// vanishingly improbable while keeping the check cheap.
const PAD_MARKER: u8 = 0x80;

/// Pad `data` with trailing bytes so the result is exactly `target` long.
///
/// This is length hiding at the *plaintext* level. The padding is
/// self-describing so the length is recoverable after decryption: the last
/// three bytes are `[n_hi, n_lo, marker]`, where `n` is how many padding
/// bytes precede them.
///
/// # Errors
/// Returns [`OnionError::Build`] if `target` is smaller than `data`
/// (padding cannot shrink data), or if the required padding exceeds
/// [`MAX_PLAINTEXT_PADDING`].
pub fn pad_plaintext(data: &[u8], target: usize) -> Result<Vec<u8>, OnionError> {
    if target < data.len() {
        return Err(OnionError::Build(format!(
            "cannot pad {} bytes into {target}: padding never shrinks",
            data.len()
        )));
    }
    if target == data.len() {
        // Nothing to do. A zero-byte pad would be ambiguous with an
        // unpadded field, so an exact fit is left alone and reported as
        // unpadded.
        return Ok(data.to_vec());
    }
    let overhead = TRAILING_PAD_ENTRY_SIZE;
    let pad_len = target
        .checked_sub(data.len())
        .and_then(|d| d.checked_sub(overhead))
        .ok_or_else(|| {
            OnionError::Build(format!(
                "target {target} leaves no room for the {overhead}-byte padding header needed by \
                 {} bytes of data",
                data.len()
            ))
        })?;
    if pad_len > MAX_PLAINTEXT_PADDING {
        return Err(OnionError::Build(format!(
            "padding of {pad_len} bytes exceeds the {MAX_PLAINTEXT_PADDING}-byte limit the \
             2-byte length field can describe"
        )));
    }
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(data);
    out.extend(std::iter::repeat(0u8).take(pad_len));
    out.extend_from_slice(&(pad_len as u16).to_be_bytes());
    out.push(PAD_MARKER);
    Ok(out)
}

/// Remove padding added by [`pad_plaintext`].
///
/// Call this only on data you already
/// know was padded -- for example because [`LayerHeader::padded`] said so
/// ([`PeeledLayer::payload_bytes`] does exactly that). This function cannot
/// tell padded data from real data that merely happens to end the same
/// way: roughly 1 in 256 unpadded binary payloads ends in the marker byte
/// with a length that also happens to fit, and calling this unconditionally
/// on data that was never padded will silently truncate those.
pub fn strip_plaintext_padding(data: &[u8]) -> Vec<u8> {
    if data.len() < TRAILING_PAD_ENTRY_SIZE {
        return data.to_vec();
    }
    if data[data.len() - 1] != PAD_MARKER {
        return data.to_vec();
    }
    let pad_len = u16::from_be_bytes([data[data.len() - 3], data[data.len() - 2]]) as usize;
    let body_len = match data.len().checked_sub(TRAILING_PAD_ENTRY_SIZE + pad_len) {
        Some(n) => n,
        // Marker matched by accident, or the record is corrupt. Returning
        // the input unchanged is the safe choice.
        None => return data.to_vec(),
    };
    data[..body_len].to_vec()
}

/// Zero-pad a raw sealed field to `size` bytes, to be put in a cell.
///
/// A relay receives the *whole* [`crate::cell::PAYLOAD_SIZE`]-byte cell
/// payload but forwards only the next hop's sealed field, which is
/// shorter. Padding is unambiguous because the layer header's MAC covers
/// the true plaintext length.
///
/// # Errors
/// Returns [`OnionError::TooLarge`] if `data` is longer than `size`.
pub fn pad_payload(data: &[u8], size: usize) -> Result<Vec<u8>, OnionError> {
    if data.len() > size {
        return Err(OnionError::TooLarge(format!(
            "sealed field is {} bytes, cannot pad down to {size}",
            data.len()
        )));
    }
    let mut out = data.to_vec();
    out.resize(size, 0);
    Ok(out)
}

/// [`pad_payload`] with the default cell payload size.
pub fn pad_payload_default(data: &[u8]) -> Result<Vec<u8>, OnionError> {
    pad_payload(data, PAYLOAD_SIZE)
}

/// Pack an onion into a [`Cell`] for transmission.
///
/// The onion is zero-padded to the
/// full [`PAYLOAD_SIZE`] *here*, before it ever reaches [`Cell`], so
/// `Cell.length` is always the same constant regardless of the real
/// onion's size or how many layers have already been peeled off it.
///
/// # Errors
/// Returns [`OnionError::TooLarge`] if `onion` exceeds the cell payload buffer.
pub fn seal_into_cell(onion: &[u8], circuit_id: u32, command: Option<Command>) -> Result<Cell, OnionError> {
    if onion.len() > PAYLOAD_SIZE {
        return Err(OnionError::TooLarge(format!(
            "sealed onion is {} bytes, cell payload buffer is {PAYLOAD_SIZE}",
            onion.len()
        )));
    }
    let padded = pad_payload_default(onion)?;
    Cell::new(circuit_id, command.unwrap_or(Command::Data), padded)
        .map_err(|e| OnionError::Build(e.to_string()))
}

/// Return how many of `buffer`'s leading bytes are a real onion.
///
/// `buffer` starts with a layer's wire header -- every onion does -- whose
/// (per-layer, not wire-constant) `length` field says how many bytes of
/// ciphertext follow it. Anything past `WIRE_HEADER_SIZE + header.length`
/// is wire-level zero padding added so the cell stays a fixed size, and
/// must not be mistaken for real content.
///
/// Falls back to `buffer.len()` if the header cannot be parsed or declares
/// a length that does not fit, so a malformed or hand-built buffer
/// degrades to "no trimming" rather than raising here.
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

/// Extract the sealed onion from a received [`Cell`].
///
/// `trailer` is extra bytes to keep *after* the onion the header
/// describes -- for a cell whose sender appended something opaque to the
/// onion itself, which the header's own `length` has no way to know
/// about. `0` is right for every plain onion cell.
pub fn onion_from_cell(cell: &Cell, trailer: usize) -> Vec<u8> {
    let payload = &cell.payload;
    let end = (leading_onion_length(payload) + trailer).min(payload.len());
    payload[..end].to_vec()
}

/// Peel every layer in sequence and return the exit's user payload.
///
/// Convenience for tests and for a client decrypting its own return
/// traffic. A real relay peels only its own layer with
/// [`OnionCrypto::peel_layer`] and forwards the rest.
///
/// # Errors
/// Returns an error if any layer fails to authenticate.
pub fn peel_circuit(onion: &[u8], hops: &[OnionCrypto]) -> Result<Vec<u8>, OnionError> {
    let mut current = onion.to_vec();
    for hop in hops {
        let (inner, _header) = hop.peel_layer(&current)?;
        current = inner;
    }
    Ok(current)
}

/// One hop's trace entry from [`peel_circuit_verbose`]:
/// `(header, next_hop, data, target_addr)`.
pub type PeelTrace = (LayerHeader, Option<(String, u16)>, Vec<u8>, Option<(String, u16)>);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_plaintext_round_trips() {
        let padded = pad_plaintext(b"hi", 200).unwrap();
        assert_eq!(padded.len(), 200);
        assert_eq!(strip_plaintext_padding(&padded), b"hi");
    }

    #[test]
    fn pad_plaintext_exact_fit_is_unpadded() {
        let padded = pad_plaintext(b"hello", 5).unwrap();
        assert_eq!(padded, b"hello");
    }

    #[test]
    fn pad_plaintext_rejects_shrink() {
        assert!(pad_plaintext(b"hello world", 3).is_err());
    }

    #[test]
    fn pad_plaintext_rejects_no_room_for_header() {
        // 1 byte of data, target 3: only 2 bytes free, but the trailer needs 3.
        assert!(pad_plaintext(b"h", 3).is_err());
    }

    #[test]
    fn strip_plaintext_padding_is_noop_on_unpadded_data() {
        let data = b"just some ordinary bytes";
        assert_eq!(strip_plaintext_padding(data), data);
    }

    #[test]
    fn pad_payload_round_trips_and_rejects_oversize() {
        let padded = pad_payload(b"abc", 10).unwrap();
        assert_eq!(padded.len(), 10);
        assert_eq!(&padded[..3], b"abc");
        assert!(pad_payload(b"way too long for a tiny buffer", 5).is_err());
    }

    fn hop(name: &str, key: &[u8], mac: &[u8], index: usize) -> OnionCrypto {
        OnionCrypto::new(name, key, key, Some(mac.to_vec()), Some("chacha20-poly1305"), index, None).unwrap()
    }

    #[test]
    fn encrypt_and_peel_circuit_round_trips() {
        let guard = hop("guard", &[1u8; 32], &[2u8; 32], 0);
        let middle = hop("middle", &[3u8; 32], &[4u8; 32], 1);
        let exit_ = hop("exit", &[5u8; 32], &[6u8; 32], 2);

        let route = RoutePlan::new(
            vec![
                ("10.0.0.1".to_string(), 1000),
                ("10.0.0.2".to_string(), 2000),
                ("10.0.0.3".to_string(), 3000),
            ],
            ("93.184.216.34".to_string(), 443),
            crate::cell::PAYLOAD_SIZE,
        )
        .unwrap();

        let mut hops = [
            OnionCrypto::new("guard", &[1u8; 32], &[1u8; 32], Some(vec![2u8; 32]), Some("chacha20-poly1305"), 0, None).unwrap(),
            OnionCrypto::new("middle", &[3u8; 32], &[3u8; 32], Some(vec![4u8; 32]), Some("chacha20-poly1305"), 1, None).unwrap(),
            OnionCrypto::new("exit", &[5u8; 32], &[5u8; 32], Some(vec![6u8; 32]), Some("chacha20-poly1305"), 2, None).unwrap(),
        ];
        let onion = OnionCrypto::encrypt_onion(b"round trip payload", &mut hops, &route, 7, true, false, None, None, None)
            .unwrap();

        // Peeling with independently-built OnionCrypto instances (same keys)
        // must reach the same payload.
        let (inner1, h1) = guard.peel_layer(&onion).unwrap();
        assert!(h1.is_route());
        let (inner2, h2) = middle.peel_layer(&inner1).unwrap();
        assert!(h2.is_route());
        let (payload, h3) = exit_.peel_layer(&inner2).unwrap();
        assert_eq!(h3.kind, Kind::PAYLOAD);
        assert_eq!(payload, b"round trip payload");

        // peel_circuit gives the same answer end to end.
        let hops2 = [
            hop("guard", &[1u8; 32], &[2u8; 32], 0),
            hop("middle", &[3u8; 32], &[4u8; 32], 1),
            hop("exit", &[5u8; 32], &[6u8; 32], 2),
        ];
        assert_eq!(peel_circuit(&onion, &hops2).unwrap(), b"round trip payload");
    }

    #[test]
    fn test_seal_and_peel_require_matching_directional_keys() {
        let seal_key = [1u8; 32];
        let open_key = [2u8; 32];
        // Explicit, shared mac_key (as the real handshake path always
        // provides -- see `HandshakeKeys::to_onion_crypto`): letting it
        // fall back to a key derived from each instance's own (different)
        // seal_key would fail the header MAC check for a reason unrelated
        // to what this test is actually checking.
        let mac_key = vec![3u8; 32];
        let mut g =
            OnionCrypto::new("guard", &seal_key, &open_key, Some(mac_key.clone()), Some(DEFAULT_CIPHER), 0, None).unwrap();
        let sealed = g.seal_payload(b"hello", 0, ("93.184.216.34".to_string(), 80), None, None).unwrap();
        assert!(g.peel_layer(&sealed).is_err(), "sealing and opening with different keys must not round-trip");

        let peer =
            OnionCrypto::new("guard-peer", &open_key, &seal_key, Some(mac_key), Some(DEFAULT_CIPHER), 0, None).unwrap();
        let (inner, header) = peer.peel_layer(&sealed).unwrap();
        assert_eq!(inner, b"hello");
        assert_eq!(header.kind, Kind::PAYLOAD);
    }

    #[test]
    fn tampered_onion_fails_to_authenticate() {
        let mut hops = [
            OnionCrypto::new("guard", &[9u8; 32], &[9u8; 32], Some(vec![8u8; 32]), None, 0, None).unwrap(),
        ];
        let route =
            RoutePlan::new(vec![("1.2.3.4".to_string(), 80)], ("5.6.7.8".to_string(), 443), crate::cell::PAYLOAD_SIZE)
                .unwrap();
        let mut onion =
            OnionCrypto::encrypt_onion(b"data", &mut hops, &route, 1, true, false, None, None, None).unwrap();
        onion[40] ^= 0xFF;
        let guard = hop("guard", &[9u8; 32], &[8u8; 32], 0);
        assert!(guard.peel_layer(&onion).is_err());
    }

    #[test]
    fn seal_into_cell_and_onion_from_cell_round_trip() {
        let onion = vec![0xABu8; 100];
        let cell = seal_into_cell(&onion, 0x1234, None).unwrap();
        assert_eq!(cell.payload.len(), PAYLOAD_SIZE);
        // Without a real LayerHeader at the front, leading_onion_length
        // falls back to the whole buffer.
        assert_eq!(onion_from_cell(&cell, 0).len(), PAYLOAD_SIZE);
    }

    /// Regression test.
    ///
    /// Reproduces the correlation attack (two onions built with adjacent
    /// `seq` values, guard layer peeled off both, XOR the leading 4 bytes
    /// on each link) but asserts the *opposite* outcome:
    /// with the old XOR mask, `be32(A[0..4]) ^ be32(B[0..4])` equalled
    /// `be32(A'[0..4]) ^ be32(B'[0..4])` equalled `5 ^ 6` on both links --
    /// an exact, keyless cross-link correlator. With the new per-hop PRP,
    /// that XOR-difference invariant must not survive peeling one layer.
    #[test]
    fn forward_seq_has_no_cross_hop_xor_relationship() {
        let route = RoutePlan::new(
            vec![("10.0.0.1".to_string(), 1000), ("10.0.0.2".to_string(), 2000)],
            ("93.184.216.34".to_string(), 443),
            crate::cell::PAYLOAD_SIZE,
        )
        .unwrap();

        let mut hops_a = [
            hop("guard", &[1u8; 32], &[2u8; 32], 0),
            hop("middle", &[3u8; 32], &[4u8; 32], 1),
        ];
        let mut hops_b = [
            hop("guard", &[1u8; 32], &[2u8; 32], 0),
            hop("middle", &[3u8; 32], &[4u8; 32], 1),
        ];

        let onion_a = OnionCrypto::encrypt_onion(b"x", &mut hops_a, &route, 5, true, false, None, None, None).unwrap();
        let onion_b = OnionCrypto::encrypt_onion(b"x", &mut hops_b, &route, 6, true, false, None, None, None).unwrap();

        let wire_a = u32::from_be_bytes(onion_a[0..4].try_into().unwrap());
        let wire_b = u32::from_be_bytes(onion_b[0..4].try_into().unwrap());
        let link1_xor = wire_a ^ wire_b;

        let guard = hop("guard", &[1u8; 32], &[2u8; 32], 0);
        let (inner_a, _) = guard.peel_layer(&onion_a).unwrap();
        let (inner_b, _) = guard.peel_layer(&onion_b).unwrap();
        let wire_a2 = u32::from_be_bytes(inner_a[0..4].try_into().unwrap());
        let wire_b2 = u32::from_be_bytes(inner_b[0..4].try_into().unwrap());
        let link2_xor = wire_a2 ^ wire_b2;

        // The true seq difference (5 ^ 6 == 3) must not appear identically
        // on both links -- that identical-XOR-difference invariant is
        // exactly what let a passive two-link observer match cells with no
        // keys and no timing analysis.
        assert_ne!(link1_xor, link2_xor, "XOR-difference invariant survived across hops -- H4 not fixed");
        assert_ne!(link1_xor, 5 ^ 6, "guard-link wire values still leak the true seq XOR-difference");
        assert_ne!(link2_xor, 5 ^ 6, "middle-link wire values still leak the true seq XOR-difference");
    }

    /// Regression test: masking is no longer its own inverse, and
    /// unmasking recovers the exact original
    /// seq for values spanning the 32-bit domain (including both halves
    /// zero/max, which a buggy Feistel round count or bit order most often
    /// gets wrong).
    #[test]
    fn seq_prp_round_trips() {
        let key = compute_seq_prp_key(b"some mac key");
        for seq in [0u32, 1, 42, 0x0000_FFFF, 0xFFFF_0000, 0xFFFF_FFFF, 0x1234_5678, u32::MAX / 2] {
            let masked = seq_prp_forward(&key, seq);
            assert_eq!(seq_prp_inverse(&key, masked), seq, "PRP did not round-trip for seq={seq:#x}");
        }
    }

    /// A backward reply sealed with a fixed input (the old constant `0`)
    /// must not equal the PRP key or otherwise be recoverable as a raw
    /// mask: two different hops' PRP outputs for input 0 must differ, same
    /// as with any other input.
    #[test]
    fn seq_prp_of_zero_still_differs_per_hop() {
        let key_g = compute_seq_prp_key(&[2u8; 32]);
        let key_m = compute_seq_prp_key(&[4u8; 32]);
        assert_ne!(seq_prp_forward(&key_g, 0), seq_prp_forward(&key_m, 0));
    }
}

/// Byte-for-byte parity with the real Python `allium.onion` module.
///
/// Ground truth generated by running the actual Python module as an
/// oracle: three hops (guard/middle/exit) with fixed keys, a fixed route,
/// `chacha20-poly1305`, `seq=42`:
///
/// ```text
/// guard = OnionCrypto('guard', bytes(range(32)), bytes([0xAA]*32), cipher='chacha20-poly1305', hop_index=0)
/// middle = OnionCrypto('middle', bytes(range(32,64)), bytes([0xBB]*32), cipher='chacha20-poly1305', hop_index=1)
/// exit_ = OnionCrypto('exit', bytes(range(64,96)), bytes([0xCC]*32), cipher='chacha20-poly1305', hop_index=2)
/// route = RoutePlan([('10.0.0.1', 9001), ('10.0.0.2', 9002), ('10.0.0.3', 9003)],
///                    final_addr=('93.184.216.34', 443))
/// onion = OnionCrypto.encrypt_onion(b'hello world', [guard, middle, exit_], route, seq=42)
/// ```
///
/// Since AEAD sealing uses a random nonce, the ciphertext bytes themselves
/// are not reproducible -- but a sealed field embeds its own nonce, so
/// Python's *output* onion can be fed to the Rust implementation and must
/// peel to the exact same headers and payload, which is what this checks
/// (full interop, not just matching internals).
///
/// This fixture was generated by a Python oracle running the build that
/// predates every later format change -- the `seq` masking scheme (XOR,
/// not the PRP), the `LAYER_PROTOCOL_VERSION` byte (`0xa1`), and now the
/// `0xA4` header split, which moved `kind` and the address under the AEAD
/// and the version byte from offset 11 to offset 10. A version mismatch is
/// caught in `LayerHeader::unpack` *before* the MAC is ever checked, so
/// this build correctly refuses to peel this fixture at all -- it cannot
/// be patched by editing the version byte, either, since the header MAC
/// and the AEAD AAD both cover `pack_unsigned`, which always re-packs the
/// *current* build's layout; a patched byte would only trade a clean
/// version error for an AEAD or MAC failure.
/// `peels_a_python_built_onion_byte_for_byte` below is repurposed to check
/// exactly that clean-rejection behaviour -- the deployment-safety
/// property the version byte exists for (an unupgraded peer's cells are
/// rejected as a version mismatch, not treated as tampering and not
/// silently accepted with a wrong `seq` or a misread address). Full
/// byte-for-byte parity needs a fresh fixture from an oracle that speaks
/// format `0xA4`.
#[cfg(test)]
mod python_cross_check {
    use super::*;

    #[test]
    fn peels_a_python_built_onion_byte_for_byte() {
        // Pre-H4 fixture: a 29-byte cleartext header with kind=0x01 at
        // offset 4 and ver=0xa1 at offset 11 (hex chars 22-23,
        // "...00a1 0a00..."). Offset 10 -- where an 0xA4 build reads the
        // version -- is the last reserved byte, 0x00.
        let onion_hex = "8c126cda0100d300000000a10a000002232a1eefc41ce36c52136a5f0e8f9342e415b8cea66fe41c1a2398ffb1b6111507c0c83e78b1c1ad3de0756ba5095ee4830d51b527b62b99e157a7ba6a16df2aad1e0ba714654017cce4ad2ac9a8e85d664a31a37175af06106af51b95ce5fa1f0f63dd5f1da91fc537c17d847308ce4f30039fa44e75e8d457abd959196eec4386af0160d3451aa2a125f1720374b0374d82d31ca70f6681f27f1762b100ba7b4a489be76523d523f4e4470b290a9b5bece5f8e0ee976fae1bb059d530cb1e6727172cae39b6b33cc50fa6bff9c477ca5b203069a2ed07f473dc27c81a37f05";
        let onion = hex_to_bytes(onion_hex);
        assert_eq!(onion.len(), 240);
        assert_eq!(onion[11], 0xa1, "fixture's embedded protocol version; update this test if the fixture changes");
        assert_eq!(onion[10], 0x00, "fixture's reserved byte at the 0xA4 version offset");

        let guard_key: Vec<u8> = (0u8..32).collect();
        let guard_mac = vec![0xAAu8; 32];
        let guard =
            OnionCrypto::new("guard", &guard_key, &guard_key, Some(guard_mac), Some("chacha20-poly1305"), 0, None).unwrap();

        let err = guard.peel_layer(&onion).unwrap_err();
        match err {
            OnionError::Version { observed, .. } => assert_eq!(observed, 0x00),
            other => panic!("expected a clean Version rejection of the pre-0xA4 fixture, got {other:?}"),
        }
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}

/// Like [`peel_circuit`], but returns a trace entry per hop for inspection.
///
/// Useful for asserting in tests that each relay learned only its own next
/// hop and nothing about the hops after it.
///
/// # Errors
/// Returns an error if any layer fails to authenticate.
pub fn peel_circuit_verbose(onion: &[u8], hops: &[OnionCrypto]) -> Result<Vec<PeelTrace>, OnionError> {
    let mut current = onion.to_vec();
    let mut trace = Vec::with_capacity(hops.len());
    for hop in hops {
        let peeled = hop.peel(&current)?;
        trace.push((
            peeled.header.clone(),
            peeled.next_hop.clone(),
            peeled.plaintext.clone(),
            peeled.target_addr.clone(),
        ));
        // A route layer forwards its sealed field; the exit yields user data.
        current = peeled.forwarded.unwrap_or(peeled.plaintext);
    }
    Ok(trace)
}
