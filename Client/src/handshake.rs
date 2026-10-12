//! X25519 (+ optional ML-KEM-768 hybrid) handshake for Allium circuits.
//!
//! Establishes one hop's symmetric keys over UDP using a two-message
//! exchange built on the existing 1192-byte cell:
//!
//! ```text
//! Client                                        Relay
//!   |  CREATE  cell                                 |
//!   |  version, type, circuit_id, client_pub        |
//!   |  client_nonce (AEAD sealed)                   |
//!   |---------------------------------------------->|
//!   |                                               |  generate EPHEMERAL X25519 keypair
//!   |                                               |  shared = DH(relay_eph_priv,  client_pub)
//!   |                                               |       || DH(relay_static_priv, client_pub)
//!   |                                               |  salt = random 16 bytes
//!   |  CREATED cell                                 |  verifier = HKDF(shared, salt, transcript)
//!   |  version, type, circuit_id,                   |
//!   |    relay_static_pub, relay_ephemeral_pub, salt|
//!   |  verifier, relay_nonce (AEAD sealed)          |
//!   |<----------------------------------------------|
//!   |  recompute + compare verifier (constant time) |
//! ```
//!
//! Both sides then derive four independent keys from the same combined DH
//! secret (`aead_key`, `mac_key`, a handshake-body key, and a handshake IV),
//! each an independent HKDF-SHA256 expansion with a distinct `info` label.
//!
//! # Forward secrecy
//! The shared secret combines *two* DH terms, not one:
//! `shared = DH(client_eph, relay_eph) || DH(client_eph, relay_static)`.
//! The relay generates a fresh, one-time X25519 keypair for every
//! handshake and discards its private half the moment
//! [`HandshakeRelay::respond`] returns, so a later compromise of the
//! relay's static key cannot retroactively recompute a past session's
//! keys -- only future sessions (where the static key is used again) are
//! at risk. This mirrors Tor's `ntor` handshake.
//!
//! # Why the response carries a verifier rather than a hash
//! A plain hash of the relay's public key proves nothing to a passive
//! observer. The verifier here is an HKDF extraction keyed by the combined
//! DH secret, so only a peer holding both matching private keys can
//! produce one -- it is both key confirmation and an active-attacker
//! detector.
//!
//! # Post-quantum hybrid (handshake version 3)
//! A hybrid mode adds ML-KEM-768 ([`crate::mlkem`], FIPS 203) *alongside*
//! the two X25519 terms: `shared = DH(eph,eph) || DH(eph,static) || K`,
//! where `K` is the ML-KEM shared secret the client encapsulated to the
//! relay's current ML-KEM key. `kem_key_id || SHA-256(ciphertext)` is
//! appended to the transcript, so the verifier and the relay's signature
//! commit to exactly this encapsulation -- there is no silent downgrade.
//! The hybrid CREATE body ([`HYBRID_CREATE_BODY_SIZE`]) is larger than one
//! cell, so it travels as several `CREATE_FRAGMENT` cells on the wire
//! ([`crate::createfrag`]) -- see [`HandshakeMessage::fragments`].
//!
//! # What this handshake does NOT provide on its own
//! X25519 key agreement alone is unauthenticated. A real deployment must
//! pin relay identity keys (Ed25519) -- [`HandshakeClient`]'s mandatory
//! `trusted_identities`/`trust_first_use` enforces this.

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::cell::{Cell, CellError, Command, CELL_SIZE, MAX_PAYLOAD_SIZE};
use crate::crypto::{self, CryptoError, KEY_SIZE, NONCE_SIZE, SEAL_OVERHEAD};
use crate::mlkem;
use crate::onion::{Layer, OnionCrypto, OnionError, DEFAULT_CIPHER};
use crate::osrand;

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------

/// Protocol version carried in every handshake body.
pub const HANDSHAKE_VERSION: u8 = 2;
/// The post-quantum hybrid CREATE: the version-2 body followed by
/// `kem_key_id || ML-KEM-768 ciphertext`.
pub const HANDSHAKE_VERSION_HYBRID: u8 = 3;
/// Which of the relay's (rotating) ML-KEM keys a hybrid CREATE encapsulated
/// to -- [`crate::mlkem::key_id`] of the encapsulation key.
pub const KEM_KEY_ID_SIZE: usize = 8;

/// X25519 public (and private) key length.
pub const PUBLIC_KEY_SIZE: usize = 32;
/// Salt length in the relay's response.
pub const SALT_SIZE: usize = 16;
/// Verifier length: one SHA-256-sized HKDF output.
pub const VERIFIER_SIZE: usize = 32;
/// Ed25519 identity public key length, and the signature over the transcript.
pub const IDENTITY_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;

/// Message types, distinct from the cell [`Command`] so a relay can talk to
/// peers using a different cell command numbering.
pub const MSG_CREATE: u8 = 1;
pub const MSG_CREATED: u8 = 2;
/// A [`ChallengeBody`] -- the cheap, stateless reply to an unproven CREATE.
pub const MSG_CHALLENGE: u8 = 3;

/// Default socket timeout for [`HandshakeClient::handshake`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Length, in bytes, of a return-routability cookie: an HMAC-SHA256 output
/// truncated to this size.
pub const COOKIE_SIZE: usize = 16;
/// How long a cookie remains acceptable, in seconds, once issued.
pub const DEFAULT_COOKIE_WINDOW_SECONDS: f64 = 300.0;

/// `version(1) + type(1) + circuit_id(4) + public_key(32) + nonce(NONCE_SIZE) + cookie(COOKIE_SIZE)`.
pub const CREATE_BODY_SIZE: usize = 1 + 1 + 4 + PUBLIC_KEY_SIZE + NONCE_SIZE + COOKIE_SIZE;
/// A version-3 (hybrid) CREATE body: the version-2 fields, then the key id
/// and the ML-KEM ciphertext.
pub const HYBRID_CREATE_BODY_SIZE: usize = CREATE_BODY_SIZE + KEM_KEY_ID_SIZE + mlkem::CIPHERTEXT_SIZE;
/// `version(1) + type(1) + circuit_id(4) + relay_static_pub(32) + relay_ephemeral_pub(32) +
/// salt(16) + verifier(32) + identity(32) + signature(64) + nonce(NONCE_SIZE)`.
pub const CREATED_BODY_SIZE: usize =
    1 + 1 + 4 + PUBLIC_KEY_SIZE + PUBLIC_KEY_SIZE + SALT_SIZE + VERIFIER_SIZE + IDENTITY_KEY_SIZE + SIGNATURE_SIZE + NONCE_SIZE;
/// `version(1) + type(1) + circuit_id(4) + cookie(COOKIE_SIZE)`.
pub const CHALLENGE_BODY_SIZE: usize = 1 + 1 + 4 + COOKIE_SIZE;
/// Largest handshake body that fits inside one cell payload.
///
/// Fix (cell-size duplicate-constant finding): this used to be an
/// independent hardcoded `504`, disconnected from `cell::PAYLOAD_SIZE`. If
/// the cell size were ever resized without also updating this literal, the
/// handshake code would keep validating CREATED messages against the old,
/// smaller size -- a silent circuit-setup correctness bug. It now follows
/// `cell::PAYLOAD_SIZE`, the single source of truth, the same pattern
/// `sizes.rs` already used correctly.
pub const MAX_HANDSHAKE_PAYLOAD: usize = crate::cell::PAYLOAD_SIZE;

/// Byte offset of the fixed-position nonce field within a serialized CREATE
/// body. Not `CREATE_BODY_SIZE - NONCE_SIZE` because `cookie` follows
/// `nonce` rather than being the last field.
const CREATE_NONCE_OFFSET: usize = CREATE_BODY_SIZE - COOKIE_SIZE - NONCE_SIZE;

// HKDF domain-separation labels. Each expansion yields exactly KEY_SIZE
// bytes (or as noted) and is bound to the transcript's public values.
//
// Split from one `HKDF_AEAD` label into direction-separated `_FWD`/`_BWD`
// ones -- see `onion::Layer`'s doc comment for the full rationale (a
// future switch to counter-based
// nonces could otherwise silently reuse a nonce across the two
// directions under one shared key). "Forward" = client-to-relay,
// "backward" = relay-to-client.
const HKDF_AEAD_FWD: &[u8] = b"allium-aead-key-fwd-v1";
const HKDF_AEAD_BWD: &[u8] = b"allium-aead-key-bwd-v1";
const HKDF_MAC: &[u8] = b"allium-header-mac-v1";
const HKDF_HS_KEY: &[u8] = b"allium-handshake-key-v1";
const HKDF_HS_IV: &[u8] = b"allium-handshake-iv-v1";
const HKDF_VERIFY: &[u8] = b"allium-handshake-verify-v1";

/// The fixed body length implied by a CREATE payload's version byte --
/// what precedes any relay-appended trailer.
pub fn create_body_size(payload: &[u8]) -> usize {
    if !payload.is_empty() && payload[0] == HANDSHAKE_VERSION_HYBRID {
        HYBRID_CREATE_BODY_SIZE
    } else {
        CREATE_BODY_SIZE
    }
}

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

/// Errors from the handshake.
///
/// The Python original has a small exception hierarchy
/// (`HandshakeError` base; `HandshakeTimeout`, `HandshakeRejected`,
/// `VerificationError`, `RelayAuthenticationError` all subclass it). Rust
/// has no hierarchy to subclass, so they are flattened into one enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// A generic failure: bad arguments, or misuse of the API (e.g.
    /// completing a handshake that was never started).
    Handshake(String),
    /// No reply arrived within the timeout, or a cookie-retry budget was
    /// exhausted.
    Timeout(String),
    /// The peer replied with a well-formed but unusable message: wrong
    /// version, wrong message type, mismatched circuit id.
    Rejected(String),
    /// The peer's verifier did not match the locally computed one --
    /// the MITM detector for the key exchange.
    Verification(String),
    /// The relay could not prove it holds a pinned identity key.
    RelayAuthentication(String),
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Handshake(m)
            | HandshakeError::Timeout(m)
            | HandshakeError::Rejected(m)
            | HandshakeError::Verification(m)
            | HandshakeError::RelayAuthentication(m) => write!(f, "{m}"),
        }
    }
}
impl std::error::Error for HandshakeError {}

impl From<CellError> for HandshakeError {
    fn from(e: CellError) -> Self {
        HandshakeError::Rejected(e.to_string())
    }
}

// --------------------------------------------------------------------------
// HKDF and small helpers
// --------------------------------------------------------------------------

/// Expand `shared_secret` with HKDF-SHA256 under a domain-separated `info`.
fn hkdf_expand(shared_secret: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA256 output length is always valid for the lengths this module requests");
    okm
}

fn random_array<const N: usize>() -> [u8; N] {
    let v = osrand::bytes(N);
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    out
}

fn hex_prefix(bytes: &[u8], n: usize) -> String {
    bytes.iter().take(n).map(|b| format!("{b:02x}")).collect()
}

// --------------------------------------------------------------------------
// Derived keys
// --------------------------------------------------------------------------

/// Which side of a handshake a [`HandshakeKeys`] was derived for --
/// decides which of `aead_key_fwd`/`aead_key_bwd` [`HandshakeKeys::to_onion_crypto`]/
/// [`HandshakeKeys::to_layer`] use to seal vs. open. See `onion::Layer`'s
/// doc comment for why the two AEAD keys are separate at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeRole {
    /// This side sends the forward (client-to-relay) direction and opens
    /// the backward (relay-to-client) direction.
    Client,
    /// This side sends the backward (relay-to-client) direction and opens
    /// the forward (client-to-relay) direction.
    Relay,
}

/// The key material one hop's handshake produces.
#[derive(Clone)]
pub struct HandshakeKeys {
    /// The raw X25519 (+ML-KEM, if hybrid) output. Kept for damage
    /// assessment and for deriving further keys; not used directly as a
    /// cipher key.
    pub shared_secret: Vec<u8>,
    /// The relay's 16-byte salt (echoed by the client).
    pub salt: Vec<u8>,
    /// [`KEY_SIZE`] bytes for payload sealing, client-to-relay direction.
    /// Was one shared `aead_key` used for both directions -- see
    /// `onion::Layer`'s doc comment.
    pub aead_key_fwd: Vec<u8>,
    /// [`KEY_SIZE`] bytes for payload sealing, relay-to-client direction.
    pub aead_key_bwd: Vec<u8>,
    /// [`KEY_SIZE`] bytes for layer header MACs.
    pub mac_key: Vec<u8>,
    role: HandshakeRole,
    /// The AEAD name both sides agreed on.
    pub cipher: String,
    /// The circuit this handshake belongs to.
    pub circuit_id: u32,
    /// The relay's X25519 public key, or `None` client-side before the
    /// reply is processed.
    pub relay_public: Option<[u8; PUBLIC_KEY_SIZE]>,
    /// The confirmed verifier, once both sides agree.
    pub verifier: Vec<u8>,
    // Mirrors the Python original's `_hs_key`/`_hs_iv`: derived and stored
    // on every `HandshakeKeys`, but not read anywhere in that module either
    // (nor anywhere else in the upstream package) -- reserved state, kept
    // here only for field-for-field parity.
    #[allow(dead_code)]
    hs_key: Vec<u8>,
    #[allow(dead_code)]
    hs_iv: Vec<u8>,
    /// The relay's verified Ed25519 identity, or `None` when the handshake
    /// did not authenticate one (anonymous mode).
    pub identity_public: Option<[u8; IDENTITY_KEY_SIZE]>,
}

impl Drop for HandshakeKeys {
    /// Security audit fix (2026-09-26): every field here that's actual key
    /// material -- the raw DH/KEM shared secret and every key derived from
    /// it -- is wiped on drop instead of being left sitting in freed
    /// memory. `salt`/`cipher`/`circuit_id`/`relay_public`/`verifier`/
    /// `identity_public` are not secret (public values or a proof, not a
    /// key) and are left alone.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.shared_secret.zeroize();
        self.aead_key_fwd.zeroize();
        self.aead_key_bwd.zeroize();
        self.mac_key.zeroize();
        self.hs_key.zeroize();
        self.hs_iv.zeroize();
    }
}

impl std::fmt::Debug for HandshakeKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HandshakeKeys(circuit_id={:#010x}, cipher={:?}, relay_authenticated={}, keys=<redacted>)",
            self.circuit_id,
            self.cipher,
            self.identity_public.is_some()
        )
    }
}

impl HandshakeKeys {
    /// `true` when this hop's relay identity was cryptographically verified.
    pub fn relay_is_authenticated(&self) -> bool {
        self.identity_public.is_some()
    }

    /// This side's own (seal, open) AEAD key pair, per `self.role` --
    /// see `onion::Layer`'s doc comment.
    fn directional_keys(&self) -> (&[u8], &[u8]) {
        match self.role {
            HandshakeRole::Client => (&self.aead_key_fwd, &self.aead_key_bwd),
            HandshakeRole::Relay => (&self.aead_key_bwd, &self.aead_key_fwd),
        }
    }

    /// Return an [`OnionCrypto`] bound to these keys, ready to seal or peel
    /// DATA layers.
    pub fn to_onion_crypto(&self, name: &str, hop_index: usize) -> Result<OnionCrypto, OnionError> {
        let (seal_key, open_key) = self.directional_keys();
        OnionCrypto::new(name, seal_key, open_key, Some(self.mac_key.clone()), Some(&self.cipher), hop_index, None)
    }

    /// Return a [`Layer`] for use with `wrap`/`seal_payload`.
    pub fn to_layer(&self, name: &str) -> Result<Layer, OnionError> {
        let (seal_key, open_key) = self.directional_keys();
        Layer::from_keys(name.to_string(), seal_key, open_key, self.mac_key.clone(), self.cipher.clone())
    }

    /// A stable 16-byte identifier for this session. Both sides compute the
    /// same value -- an HKDF expansion over the shared secret, so it works
    /// as a map key without revealing the keys.
    pub fn session_id(&self) -> [u8; 16] {
        let v = hkdf_expand(&self.shared_secret, &self.salt, b"allium-session-id-v1", 16);
        let mut out = [0u8; 16];
        out.copy_from_slice(&v);
        out
    }
}

/// Expand a DH (+ optional ML-KEM) secret into the keys a hop uses.
///
/// Each key is an independent HKDF-SHA256 expansion under its own `info`
/// label, so possessing one reveals nothing about the others.
/// `handshake_secret` is the input for the handshake-body keys, defaulting
/// to `shared_secret`.
///
/// `role` decides which of the two derived AEAD keys this side seals
/// with vs. opens with -- see
/// [`HandshakeRole`] and `onion::Layer`'s doc comment. Both sides derive
/// the *same* `aead_key_fwd`/`aead_key_bwd` values from the same shared
/// secret regardless of role; only `to_onion_crypto`/`to_layer`'s use of
/// them differs.
#[allow(clippy::too_many_arguments)]
pub fn derive_handshake_keys(
    shared_secret: &[u8],
    salt: &[u8],
    circuit_id: u32,
    cipher: &str,
    relay_public: Option<[u8; PUBLIC_KEY_SIZE]>,
    verifier: Vec<u8>,
    handshake_secret: Option<&[u8]>,
    identity_public: Option<[u8; IDENTITY_KEY_SIZE]>,
    role: HandshakeRole,
) -> HandshakeKeys {
    let hs_secret = handshake_secret.unwrap_or(shared_secret);
    HandshakeKeys {
        shared_secret: shared_secret.to_vec(),
        salt: salt.to_vec(),
        aead_key_fwd: hkdf_expand(shared_secret, salt, HKDF_AEAD_FWD, KEY_SIZE),
        aead_key_bwd: hkdf_expand(shared_secret, salt, HKDF_AEAD_BWD, KEY_SIZE),
        mac_key: hkdf_expand(shared_secret, salt, HKDF_MAC, KEY_SIZE),
        role,
        cipher: cipher.to_string(),
        circuit_id,
        relay_public,
        verifier,
        hs_key: hkdf_expand(hs_secret, salt, HKDF_HS_KEY, KEY_SIZE),
        hs_iv: hkdf_expand(hs_secret, salt, HKDF_HS_IV, NONCE_SIZE),
        identity_public,
    }
}

/// Return a fresh 32-byte Ed25519 private key, for a relay to persist.
pub fn generate_identity_key() -> [u8; 32] {
    random_array::<32>()
}

/// Return the Ed25519 public key for a 32-byte private key.
pub fn identity_public_from_private(private: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(private).verifying_key().to_bytes()
}

// --------------------------------------------------------------------------
// Body codecs
// --------------------------------------------------------------------------

fn read_array<const N: usize>(data: &[u8], offset: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&data[offset..offset + N]);
    out
}

/// The public part of a CREATE payload: `version, type, circuit_id, public_key, cookie`.
///
/// The client nonce is *not* part of this fixed body in the Python sense
/// of being a validated field; it travels at its fixed offset
/// ([`CREATE_NONCE_OFFSET`]) but [`CreateBody`] does not carry it, mirroring
/// how the Python original leaves it to be read from the raw payload
/// directly (see [`with_cookie`]).
pub struct CreateBody {
    pub version: u8,
    pub msg_type: u8,
    pub circuit_id: u32,
    pub public_key: [u8; PUBLIC_KEY_SIZE],
    /// A [`COOKIE_SIZE`]-byte return-routability cookie, or all zero bytes
    /// on a first attempt.
    pub cookie: [u8; COOKIE_SIZE],
    /// Hybrid (version 3) only: which relay ML-KEM key, and the ciphertext.
    pub kem_key_id: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
}

impl CreateBody {
    pub fn is_hybrid(&self) -> bool {
        self.version == HANDSHAKE_VERSION_HYBRID
    }

    /// `true` when this body carries a non-empty return-routability cookie.
    /// An all-zero cookie is what a first attempt looks like, and is never
    /// treated as valid by [`HandshakeRelay`]'s cookie check.
    pub fn has_cookie(&self) -> bool {
        self.cookie != [0u8; COOKIE_SIZE]
    }

    /// Parse a CREATE body, discarding the trailing nonce bytes.
    ///
    /// # Errors
    /// Returns [`HandshakeError::Rejected`] if the buffer is short or the
    /// version is unsupported.
    pub fn unpack(data: &[u8]) -> Result<Self, HandshakeError> {
        if data.len() < CREATE_BODY_SIZE {
            return Err(HandshakeError::Rejected(format!(
                "CREATE body needs {CREATE_BODY_SIZE} bytes, got {}",
                data.len()
            )));
        }
        let version = data[0];
        let msg_type = data[1];
        let circuit_id = u32::from_be_bytes(read_array(data, 2));
        let public_key = read_array(data, 6);
        let cookie = read_array(data, CREATE_NONCE_OFFSET + NONCE_SIZE);

        if version == HANDSHAKE_VERSION_HYBRID {
            if data.len() < HYBRID_CREATE_BODY_SIZE {
                return Err(HandshakeError::Rejected(format!(
                    "hybrid CREATE body needs {HYBRID_CREATE_BODY_SIZE} bytes, got {}",
                    data.len()
                )));
            }
            let kem_key_id = data[CREATE_BODY_SIZE..CREATE_BODY_SIZE + KEM_KEY_ID_SIZE].to_vec();
            let kem_ciphertext = data[CREATE_BODY_SIZE + KEM_KEY_ID_SIZE..HYBRID_CREATE_BODY_SIZE].to_vec();
            return Ok(CreateBody {
                version,
                msg_type,
                circuit_id,
                public_key,
                cookie,
                kem_key_id,
                kem_ciphertext,
            });
        }
        if version != HANDSHAKE_VERSION {
            return Err(HandshakeError::Rejected(format!(
                "unsupported handshake version {version}, expected {HANDSHAKE_VERSION} or {HANDSHAKE_VERSION_HYBRID}"
            )));
        }
        Ok(CreateBody {
            version,
            msg_type,
            circuit_id,
            public_key,
            cookie,
            kem_key_id: Vec::new(),
            kem_ciphertext: Vec::new(),
        })
    }
}

fn pack_create_body(
    version: u8,
    msg_type: u8,
    circuit_id: u32,
    public_key: &[u8; PUBLIC_KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    cookie: &[u8; COOKIE_SIZE],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(CREATE_BODY_SIZE);
    out.push(version);
    out.push(msg_type);
    out.extend_from_slice(&circuit_id.to_be_bytes());
    out.extend_from_slice(public_key);
    out.extend_from_slice(nonce);
    out.extend_from_slice(cookie);
    out
}

/// Return `raw_create_body` with its fixed cookie field replaced by `cookie`.
///
/// Used to retry a CREATE after a [`ChallengeBody`] reply, without
/// disturbing anything else in the body -- notably the client's real
/// nonce. Any bytes in `raw_create_body` past [`CREATE_BODY_SIZE`] (such as
/// a relay-appended trailer) are preserved unchanged.
///
/// # Errors
/// Returns [`HandshakeError::Handshake`] if `raw_create_body` is shorter
/// than [`CREATE_BODY_SIZE`].
pub fn with_cookie(raw_create_body: &[u8], cookie: &[u8; COOKIE_SIZE]) -> Result<Vec<u8>, HandshakeError> {
    if raw_create_body.len() < CREATE_BODY_SIZE {
        return Err(HandshakeError::Handshake(format!(
            "raw_create_body must be at least {CREATE_BODY_SIZE} bytes, got {}",
            raw_create_body.len()
        )));
    }
    let prefix_end = CREATE_BODY_SIZE - COOKIE_SIZE;
    let mut out = raw_create_body[..prefix_end].to_vec();
    out.extend_from_slice(cookie);
    out.extend_from_slice(&raw_create_body[CREATE_BODY_SIZE..]);
    Ok(out)
}

/// The public part of a CREATED payload.
///
/// `public_key` is the relay's long-term (static) X25519 public key.
/// `ephemeral_public` is a fresh key generated for *this* handshake only,
/// combined with `public_key` for forward secrecy. `identity_public` and
/// `signature` authenticate the relay; an all-zero signature is what an
/// unauthenticated relay produces.
pub struct CreatedBody {
    pub version: u8,
    pub msg_type: u8,
    pub circuit_id: u32,
    pub public_key: [u8; PUBLIC_KEY_SIZE],
    pub ephemeral_public: [u8; PUBLIC_KEY_SIZE],
    pub salt: [u8; SALT_SIZE],
    pub verifier: [u8; VERIFIER_SIZE],
    pub identity_public: [u8; IDENTITY_KEY_SIZE],
    pub signature: [u8; SIGNATURE_SIZE],
}

impl CreatedBody {
    /// `true` when the body actually carries a signature to check.
    pub fn is_authenticated(&self) -> bool {
        self.signature != [0u8; SIGNATURE_SIZE]
    }

    /// Serialize the fixed body (relay nonce is sealed separately and
    /// appended by the caller).
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CREATED_BODY_SIZE);
        out.push(self.version);
        out.push(self.msg_type);
        out.extend_from_slice(&self.circuit_id.to_be_bytes());
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.ephemeral_public);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.verifier);
        out.extend_from_slice(&self.identity_public);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&[0u8; NONCE_SIZE]);
        out
    }

    /// Parse a CREATED body.
    ///
    /// # Errors
    /// Returns [`HandshakeError::Rejected`] if the buffer is short or the
    /// version is unsupported.
    pub fn unpack(data: &[u8]) -> Result<Self, HandshakeError> {
        if data.len() < CREATED_BODY_SIZE {
            return Err(HandshakeError::Rejected(format!(
                "CREATED body needs {CREATED_BODY_SIZE} bytes, got {}",
                data.len()
            )));
        }
        let version = data[0];
        let msg_type = data[1];
        let circuit_id = u32::from_be_bytes(read_array(data, 2));
        let public_key = read_array::<PUBLIC_KEY_SIZE>(data, 6);
        let ephemeral_public = read_array::<PUBLIC_KEY_SIZE>(data, 6 + PUBLIC_KEY_SIZE);
        let salt_off = 6 + 2 * PUBLIC_KEY_SIZE;
        let salt = read_array::<SALT_SIZE>(data, salt_off);
        let verifier_off = salt_off + SALT_SIZE;
        let verifier = read_array::<VERIFIER_SIZE>(data, verifier_off);
        let identity_off = verifier_off + VERIFIER_SIZE;
        let identity_public = read_array::<IDENTITY_KEY_SIZE>(data, identity_off);
        let signature_off = identity_off + IDENTITY_KEY_SIZE;
        let signature = read_array::<SIGNATURE_SIZE>(data, signature_off);

        if version != HANDSHAKE_VERSION {
            return Err(HandshakeError::Rejected(format!(
                "unsupported handshake version {version}, expected {HANDSHAKE_VERSION}"
            )));
        }
        Ok(CreatedBody {
            version,
            msg_type,
            circuit_id,
            public_key,
            ephemeral_public,
            salt,
            verifier,
            identity_public,
            signature,
        })
    }
}

/// The entire CREATE_CHALLENGE payload: `version, type, circuit_id, cookie`.
///
/// Sent by [`HandshakeRelay`] instead of a CREATED reply when
/// `require_return_routability` is set and the CREATE did not carry a
/// valid cookie. Deliberately the smallest, cheapest-to-build message in
/// this module.
pub struct ChallengeBody {
    pub version: u8,
    pub msg_type: u8,
    pub circuit_id: u32,
    pub cookie: [u8; COOKIE_SIZE],
}

impl ChallengeBody {
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CHALLENGE_BODY_SIZE);
        out.push(self.version);
        out.push(self.msg_type);
        out.extend_from_slice(&self.circuit_id.to_be_bytes());
        out.extend_from_slice(&self.cookie);
        out
    }

    /// # Errors
    /// Returns [`HandshakeError::Rejected`] if the buffer is short or the
    /// version is unsupported.
    pub fn unpack(data: &[u8]) -> Result<Self, HandshakeError> {
        if data.len() < CHALLENGE_BODY_SIZE {
            return Err(HandshakeError::Rejected(format!(
                "CHALLENGE body needs {CHALLENGE_BODY_SIZE} bytes, got {}",
                data.len()
            )));
        }
        let version = data[0];
        let msg_type = data[1];
        let circuit_id = u32::from_be_bytes(read_array(data, 2));
        let cookie = read_array(data, 6);
        if version != HANDSHAKE_VERSION {
            return Err(HandshakeError::Rejected(format!(
                "unsupported handshake version {version}, expected {HANDSHAKE_VERSION}"
            )));
        }
        Ok(ChallengeBody { version, msg_type, circuit_id, cookie })
    }
}

/// `(circuit_id, command, payload)` -- a CREATE that doesn't fit in a
/// [`Cell`] (the hybrid one).
pub struct HandshakeMessage {
    pub circuit_id: u32,
    pub command: Command,
    pub payload: Vec<u8>,
}

impl HandshakeMessage {
    /// The 1192-byte `CREATE_FRAGMENT` cells that actually go on the wire.
    ///
    /// # Errors
    /// Returns [`HandshakeError::Handshake`] if the payload needs more
    /// than [`crate::createfrag::MAX_FRAGMENTS`] fragments.
    pub fn fragments(&self) -> Result<Vec<Cell>, HandshakeError> {
        crate::createfrag::fragment_create(self.circuit_id, &self.payload, None).map_err(|e| HandshakeError::Handshake(e.to_string()))
    }

    pub fn datagrams(&self) -> Result<Vec<[u8; CELL_SIZE]>, HandshakeError> {
        Ok(self.fragments()?.iter().map(Cell::pack).collect())
    }
}

/// Either a CREATE that fits in a single cell, or one too large for one
/// cell and sent as `CREATE_FRAGMENT`s instead. Which variant a given
/// handshake gets depends on body size, not on whether it's classical or
/// hybrid -- see [`HandshakeClient::create`].
pub enum CreateMessage {
    Cell(Cell),
    Fragmented(HandshakeMessage),
}

impl CreateMessage {
    pub fn circuit_id(&self) -> u32 {
        match self {
            CreateMessage::Cell(c) => c.circuit_id,
            CreateMessage::Fragmented(m) => m.circuit_id,
        }
    }

    /// Every 1192-byte datagram of this CREATE (one cell if the body fits;
    /// several `CREATE_FRAGMENT` cells otherwise -- see
    /// [`HandshakeMessage::fragments`]).
    pub fn datagrams(&self) -> Result<Vec<[u8; CELL_SIZE]>, HandshakeError> {
        match self {
            CreateMessage::Cell(c) => Ok(vec![c.pack()]),
            CreateMessage::Fragmented(m) => m.datagrams(),
        }
    }

    /// The CREATE body, regardless of which variant this is -- mirrors
    /// Python's duck-typed `.payload` attribute (both `Cell` and
    /// `HandshakeMessage` carry one), used by [`crate::circuit`] to decide
    /// whether the body fits a single EXTEND layer or must travel as
    /// several `EXTEND` fragments (see [`crate::createfrag::fragment_extend_payload`]).
    pub fn payload(&self) -> &[u8] {
        match self {
            CreateMessage::Cell(c) => &c.payload,
            CreateMessage::Fragmented(m) => &m.payload,
        }
    }
}

// --------------------------------------------------------------------------
// Transcript and verifier
// --------------------------------------------------------------------------

/// Build the canonical byte string a handshake is bound to.
///
/// Every public value of the exchange goes in, in a fixed order and with
/// fixed widths, so both sides hash exactly the same bytes.
/// `circuit_id || client_pub || relay_pub || relay_ephemeral_pub ||
/// client_nonce || relay_nonce || cipher || pq_binding || relay_identity_pub`.
///
/// `relay_identity_public` was added later:
/// this transcript used to omit the relay's identity entirely (matching
/// the original Python `allium.handshake.compute_verifier`, which has the
/// same gap -- see `compute_verifier_and_signing_payload_match_python`'s
/// doc comment below), so the *verifier* (which only proves DH-secret
/// agreement) passed regardless of what `identity_public`/`signature` a
/// `CREATED` reply carried. An on-path attacker who intercepted a genuine,
/// fully-signed `CREATED` reply could zero out just its 96-byte
/// `identity_public`/`signature` fields -- leaving
/// `public_key`/`ephemeral_public`/`salt`/`verifier` untouched -- and the
/// client's verifier check would still pass, silently downgrading an
/// authenticatable relay to "anonymous" for any client configured with
/// `allow_anonymous_relay=true`. Folding the relay's claimed identity (the
/// real key, or the `[0u8; IDENTITY_KEY_SIZE]` placeholder when genuinely
/// absent -- `CreatedBody`'s field is always populated either way, so this
/// changes no wire format) into the transcript means the verifier itself
/// now depends on it: tampering with `identity_public` after the relay
/// computed `verifier` over the real value makes the client's recomputed
/// `expected` verifier mismatch, failing the handshake outright instead of
/// falling through to the anonymous-relay branch.
#[allow(clippy::too_many_arguments)]
fn transcript(
    circuit_id: u32,
    client_public: &[u8],
    relay_public: &[u8],
    relay_ephemeral_public: &[u8],
    client_nonce: &[u8],
    relay_nonce: &[u8],
    cipher: &str,
    pq_binding: &[u8],
    relay_identity_public: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&circuit_id.to_be_bytes());
    out.extend_from_slice(client_public);
    out.extend_from_slice(relay_public);
    out.extend_from_slice(relay_ephemeral_public);
    out.extend_from_slice(client_nonce);
    out.extend_from_slice(relay_nonce);
    out.extend_from_slice(cipher.as_bytes());
    out.extend_from_slice(pq_binding);
    out.extend_from_slice(relay_identity_public);
    out
}

/// Transcript extension for a hybrid handshake.
fn pq_binding(kem_key_id: &[u8], kem_ciphertext: &[u8]) -> Vec<u8> {
    let mut out = b"allium-pq-hybrid-mlkem768-v1".to_vec();
    out.extend_from_slice(kem_key_id);
    out.extend_from_slice(&Sha256::digest(kem_ciphertext));
    out
}

/// Derive the handshake verifier from the DH secret and the transcript.
///
/// This is a keyed HKDF extraction, not a plain hash: producing it
/// requires knowing both private keys behind `shared_secret`.
///
/// `relay_identity_public` is passed straight through to [`transcript`]
/// -- see its doc comment for why the
/// verifier must depend on the relay's claimed identity. Every caller
/// passes the same `identity_public` bytes that end up in the wire-level
/// `CreatedBody` (the real key, or the all-zero placeholder when there
/// genuinely is none), so this changes no wire format, only what the
/// verifier itself is computed over.
#[allow(clippy::too_many_arguments)]
pub fn compute_verifier(
    shared_secret: &[u8],
    salt: &[u8],
    circuit_id: u32,
    client_public: &[u8],
    relay_public: &[u8],
    relay_ephemeral_public: &[u8],
    client_nonce: &[u8],
    relay_nonce: &[u8],
    cipher: &str,
    pq_binding: &[u8],
    relay_identity_public: &[u8],
) -> [u8; VERIFIER_SIZE] {
    let t = transcript(
        circuit_id,
        client_public,
        relay_public,
        relay_ephemeral_public,
        client_nonce,
        relay_nonce,
        cipher,
        pq_binding,
        relay_identity_public,
    );
    let mut info = HKDF_VERIFY.to_vec();
    info.extend_from_slice(&t);
    let out = hkdf_expand(shared_secret, salt, &info, VERIFIER_SIZE);
    let mut arr = [0u8; VERIFIER_SIZE];
    arr.copy_from_slice(&out);
    arr
}

/// Build the byte string a relay signs with its Ed25519 identity key.
///
/// Covers the whole transcript *plus* the verifier and the identity key
/// itself, so a signature cannot be lifted onto a different exchange, a
/// different relay key, or a different identity statement.
/// `verifier || identity_public || transcript` (`transcript` itself now
/// also folds in `identity_public` -- see its doc comment -- so it appears
/// twice here; harmless, and left as-is rather than restructured, to keep
/// this already-correct signing step's byte layout stable).
#[allow(clippy::too_many_arguments)]
pub fn signing_payload(
    shared_secret: &[u8],
    salt: &[u8],
    circuit_id: u32,
    client_public: &[u8],
    relay_public: &[u8],
    relay_ephemeral_public: &[u8],
    client_nonce: &[u8],
    relay_nonce: &[u8],
    cipher: &str,
    verifier: &[u8],
    identity_public: &[u8],
    pq_binding: &[u8],
) -> Vec<u8> {
    // `shared_secret`/`salt` are unused directly here (the Python signature
    // keeps them for a uniform argument list with `compute_verifier`); kept
    // for API parity.
    let _ = (shared_secret, salt);
    let mut out = verifier.to_vec();
    out.extend_from_slice(identity_public);
    out.extend_from_slice(&transcript(
        circuit_id,
        client_public,
        relay_public,
        relay_ephemeral_public,
        client_nonce,
        relay_nonce,
        cipher,
        pq_binding,
        identity_public,
    ));
    out
}

/// Verify a relay's Ed25519 signature over the handshake transcript.
///
/// # Errors
/// Returns [`HandshakeError::RelayAuthentication`] if the signature does
/// not verify, or the key or signature is the wrong length.
#[allow(clippy::too_many_arguments)]
pub fn verify_relay_signature(
    signature: &[u8; SIGNATURE_SIZE],
    identity_public: &[u8; IDENTITY_KEY_SIZE],
    shared_secret: &[u8],
    salt: &[u8],
    circuit_id: u32,
    client_public: &[u8],
    relay_public: &[u8],
    relay_ephemeral_public: &[u8],
    client_nonce: &[u8],
    relay_nonce: &[u8],
    cipher: &str,
    verifier: &[u8],
    pq_binding: &[u8],
) -> Result<(), HandshakeError> {
    let payload = signing_payload(
        shared_secret,
        salt,
        circuit_id,
        client_public,
        relay_public,
        relay_ephemeral_public,
        client_nonce,
        relay_nonce,
        cipher,
        verifier,
        identity_public,
        pq_binding,
    );
    let verifying_key = VerifyingKey::from_bytes(identity_public)
        .map_err(|e| HandshakeError::RelayAuthentication(format!("malformed identity key: {e}")))?;
    let sig = Signature::from_bytes(signature);
    // `verify_strict`, not `verify`: also rejects non-canonical/malleable
    // signatures (small-order `R`, non-reduced `S`) that plain `verify`
    // accepts. Not currently exploitable here (this signature isn't
    // batched or used as a unique token), but this is a handshake identity
    // check, not a place to leave that malleability margin open.
    verifying_key.verify_strict(&payload, &sig).map_err(|_| {
        HandshakeError::RelayAuthentication(
            "relay signature did not verify against the presented identity key; the transcript, \
             verifier, or identity key was altered"
                .to_string(),
        )
    })
}

// --------------------------------------------------------------------------
// Client
// --------------------------------------------------------------------------

struct PendingCreate {
    circuit_id: u32,
    client_nonce: [u8; NONCE_SIZE],
    kem_shared: Vec<u8>,
    pq_binding: Vec<u8>,
    private: StaticSecret,
}

fn coerce_cell(message: &[u8]) -> Result<Cell, HandshakeError> {
    Cell::from_bytes(message, false).map_err(|e| HandshakeError::Rejected(format!("unparseable datagram: {e}")))
}

/// Read datagrams from `sock` until one arrives from `expected_addr`.
///
/// Reading exactly one datagram and giving up on the first one that isn't
/// the expected reply would let an off-path attacker who only knows the
/// client's UDP port abort a handshake with a single spoofed packet.
/// Comparing the source address and continuing to wait removes that as a
/// denial-of-service lever.
fn recv_from(sock: &UdpSocket, expected_addr: SocketAddr, timeout: Duration) -> Result<Vec<u8>, HandshakeError> {
    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(HandshakeError::Timeout("timed out waiting for a reply from the expected source".into()));
        }
        sock.set_read_timeout(Some(deadline - now))
            .map_err(|e| HandshakeError::Timeout(e.to_string()))?;
        let mut buf = [0u8; CELL_SIZE];
        match sock.recv_from(&mut buf) {
            Ok((n, addr)) => {
                if addr != expected_addr {
                    continue;
                }
                return Ok(buf[..n].to_vec());
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Err(HandshakeError::Timeout(
                    "timed out waiting for a reply from the expected source".into(),
                ));
            }
            Err(e) => return Err(HandshakeError::Timeout(e.to_string())),
        }
    }
}

/// Client side of the X25519 handshake.
///
/// Pinning is mandatory: [`HandshakeClient::new`] refuses to build a
/// client unless you either pass `trusted_identities` or explicitly set
/// `trust_first_use=true`.
///
/// Reusing one instance for several circuits is safe: [`HandshakeClient::create`]
/// rotates the ephemeral key per circuit, so two circuits built from the
/// same client carry unrelated public keys and cannot be linked to each
/// other.
pub struct HandshakeClient {
    pub cipher: String,
    private: StaticSecret,
    pub public_key: [u8; PUBLIC_KEY_SIZE],
    timeout: Duration,
    key_used: bool,
    pending: Option<PendingCreate>,
    trusted_identities: Option<HashSet<[u8; IDENTITY_KEY_SIZE]>>,
    pub trust_first_use: bool,
    pub allow_anonymous_relay: bool,
    /// The verified identity of the last relay, once
    /// [`HandshakeClient::complete`] succeeds.
    pub relay_identity: Option<[u8; IDENTITY_KEY_SIZE]>,
    /// The derived keys, once [`HandshakeClient::complete`] has succeeded.
    pub keys: Option<HandshakeKeys>,
    kem_public: Option<Vec<u8>>,
    require_pq: bool,
}

impl Drop for HandshakeClient {
    /// Security audit fix (2026-09-26): `private` is `StaticSecret`, which
    /// already zeroizes itself on drop, as does `pending.private` (same
    /// type). `pending.kem_shared` is a plain `Vec<u8>` -- the ML-KEM
    /// hybrid shared secret, live key material -- with no such
    /// self-zeroizing wrapper, so it needs wiping explicitly here. Covers
    /// the case where this `HandshakeClient` is dropped with an
    /// abandoned, never-completed handshake still pending (a completed
    /// one already had it wiped explicitly in `complete_cell()` itself,
    /// right after its last use, since this struct-level `Drop` only
    /// protects what's still resident at *this* moment, not material
    /// already discarded earlier during ordinary use).
    fn drop(&mut self) {
        if let Some(pending) = self.pending.as_mut() {
            use zeroize::Zeroize;
            pending.kem_shared.zeroize();
        }
    }
}

impl std::fmt::Debug for HandshakeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HandshakeClient(cipher={:?}, public_key={}..., trust_first_use={}, keys=<redacted>)",
            self.cipher,
            hex_prefix(&self.public_key, 8),
            self.trust_first_use
        )
    }
}

impl HandshakeClient {
    /// Build a new client.
    ///
    /// `static_private` seeds the *first* circuit only; every circuit
    /// after that rotates. `trusted_identities` are the Ed25519 public
    /// keys this client accepts as relays; `trust_first_use=true` accepts
    /// whichever relay presents a well-formed, self-consistent signature
    /// instead (appropriate for a test or throwaway local circuit only).
    /// `kem_public` is the relay's ML-KEM-768 encapsulation key, when a
    /// hybrid CREATE should be built; `require_pq` refuses to fall back to
    /// a classical-only handshake when it is absent.
    ///
    /// # Errors
    /// Returns [`HandshakeError::Handshake`] if neither
    /// `trusted_identities` nor `trust_first_use` was given, `kem_public`
    /// is the wrong length, or `require_pq` is set without a `kem_public`.
    pub fn new(
        cipher: Option<&str>,
        static_private: Option<[u8; 32]>,
        timeout: Duration,
        trusted_identities: Option<Vec<[u8; IDENTITY_KEY_SIZE]>>,
        trust_first_use: bool,
        allow_anonymous_relay: bool,
        kem_public: Option<Vec<u8>>,
        require_pq: bool,
    ) -> Result<Self, HandshakeError> {
        let private = match static_private {
            Some(bytes) => StaticSecret::from(bytes),
            None => StaticSecret::from(random_array::<32>()),
        };
        let public_key = PublicKey::from(&private).to_bytes();

        let trusted = trusted_identities.map(|v| v.into_iter().collect::<HashSet<_>>());
        if trusted.is_none() && !trust_first_use {
            return Err(HandshakeError::Handshake(
                "HandshakeClient requires pinned relay identities (trusted_identities=[...]) or an \
                 explicit trust_first_use=true opt-out. Leaving both unset used to silently trust any \
                 relay presenting a valid signature, which is exactly how an on-path attacker or a \
                 rogue relay squatting the address could stand in for the real hop -- that is no \
                 longer the default. Pass trust_first_use=true only if this really is a test or a \
                 throwaway local circuit."
                    .to_string(),
            ));
        }

        if let Some(kp) = &kem_public {
            if kp.len() != mlkem::ENCAPSULATION_KEY_SIZE {
                return Err(HandshakeError::Handshake(format!(
                    "kem_public must be {} bytes, got {}",
                    mlkem::ENCAPSULATION_KEY_SIZE,
                    kp.len()
                )));
            }
        }
        if require_pq && kem_public.is_none() {
            return Err(HandshakeError::Handshake(
                "require_pq is set but no kem_public was provided; refusing to build a client that \
                 could only ever fall back to a classical-only handshake"
                    .to_string(),
            ));
        }

        Ok(HandshakeClient {
            cipher: cipher.unwrap_or(DEFAULT_CIPHER).to_string(),
            private,
            public_key,
            timeout,
            key_used: false,
            pending: None,
            trusted_identities: trusted,
            trust_first_use,
            allow_anonymous_relay,
            relay_identity: None,
            keys: None,
            kem_public,
            require_pq,
        })
    }

    /// Rotate the ephemeral key for a circuit: keep it if this is a cookie
    /// retry for the circuit already in flight, otherwise mint a fresh one
    /// (except for the very first circuit, which reuses the pair the
    /// constructor built -- the one `static_private` pins for reproducible
    /// tests).
    fn next_private(&mut self, circuit_id: u32) -> StaticSecret {
        if let Some(p) = &self.pending {
            if p.circuit_id == circuit_id {
                return p.private.clone();
            }
        }
        let private = if self.key_used {
            StaticSecret::from(random_array::<32>())
        } else {
            self.private.clone()
        };
        self.key_used = true;
        self.private = private.clone();
        self.public_key = PublicKey::from(&private).to_bytes();
        private
    }

    /// Build the CREATE message carrying this client's public key.
    ///
    /// `cookie` is a return-routability cookie obtained from a prior
    /// [`ChallengeBody`] (see [`HandshakeClient::parse_challenge`]), or
    /// `None` for a first attempt.
    ///
    /// # Errors
    /// Returns [`HandshakeError::Handshake`] if `require_pq` is set but no
    /// `kem_public` was configured, or if the relay's ML-KEM key is unusable.
    pub fn create(&mut self, circuit_id: u32, cookie: Option<[u8; COOKIE_SIZE]>) -> Result<CreateMessage, HandshakeError> {
        let cookie = cookie.unwrap_or([0u8; COOKIE_SIZE]);
        let private = self.next_private(circuit_id);

        let client_nonce = random_array::<NONCE_SIZE>();
        let hybrid = self.kem_public.is_some();
        if self.require_pq && !hybrid {
            return Err(HandshakeError::Handshake(
                "require_pq is set but no kem_public was provided; refusing to fall back to a \
                 classical-only handshake"
                    .to_string(),
            ));
        }

        let mut body_bytes = pack_create_body(
            if hybrid { HANDSHAKE_VERSION_HYBRID } else { HANDSHAKE_VERSION },
            MSG_CREATE,
            circuit_id,
            &self.public_key,
            &client_nonce,
            &cookie,
        );
        let mut kem_shared = Vec::new();
        let mut binding = Vec::new();
        if hybrid {
            let kem_public = self.kem_public.as_ref().expect("hybrid implies kem_public is set");
            let (ciphertext, shared) = mlkem::encapsulate(kem_public, None)
                .map_err(|e| HandshakeError::Handshake(format!("relay ML-KEM key is unusable: {e}")))?;
            let key_id = mlkem::key_id(kem_public);
            body_bytes.extend_from_slice(&key_id);
            body_bytes.extend_from_slice(&ciphertext);
            binding = pq_binding(&key_id, &ciphertext);
            kem_shared = shared;
        }

        // Security audit fix (2026-09-26): this assignment used to just
        // overwrite `self.pending` outright -- if `create()` is ever
        // called again before a prior handshake's `complete()` (e.g. a
        // caller retrying the same circuit after a timeout), the
        // superseded pending's own `kem_shared` was dropped un-zeroized
        // right here (`private`'s own `StaticSecret` type already
        // zeroizes itself on drop, so it was never at risk the same way),
        // the same gap as `complete_cell()`'s own `self.pending = None`
        // had before its fix.
        if let Some(mut old_pending) = self.pending.take() {
            use zeroize::Zeroize;
            old_pending.kem_shared.zeroize();
        }
        self.pending = Some(PendingCreate { circuit_id, client_nonce, kem_shared, pq_binding: binding, private });

        // Fragment only when the body actually doesn't fit in one cell --
        // not just because this is a hybrid handshake. Under the current
        // cell size (`MAX_PAYLOAD_SIZE` = 1184) and ML-KEM-768 ciphertext
        // size, a hybrid body is ~1162 bytes and fits in a single cell just
        // like the classical path; fragmentation is reserved for whichever
        // body (classical or hybrid) actually exceeds the budget, e.g. a
        // future larger KEM parameter set.
        if body_bytes.len() <= MAX_PAYLOAD_SIZE {
            let cell = Cell::new(circuit_id, Command::Create, body_bytes)?;
            Ok(CreateMessage::Cell(cell))
        } else {
            Ok(CreateMessage::Fragmented(HandshakeMessage {
                circuit_id,
                command: Command::Create,
                payload: body_bytes,
            }))
        }
    }

    /// Extract the cookie from a CREATE_CHALLENGE reply.
    ///
    /// # Errors
    /// Returns [`HandshakeError::Rejected`] on a wrong command, circuit
    /// id, or protocol version.
    pub fn parse_challenge(&self, message: &[u8], circuit_id: Option<u32>) -> Result<[u8; COOKIE_SIZE], HandshakeError> {
        let cell = coerce_cell(message)?;
        if let Some(cid) = circuit_id {
            if cell.circuit_id != cid {
                return Err(HandshakeError::Rejected(format!(
                    "circuit id mismatch: expected {cid}, got {}",
                    cell.circuit_id
                )));
            }
        }
        if cell.command != Command::CreateChallenge {
            return Err(HandshakeError::Rejected(format!(
                "expected a CREATE_CHALLENGE cell, got {}",
                cell.command.name()
            )));
        }
        let body = ChallengeBody::unpack(&cell.payload)?;
        if body.circuit_id != cell.circuit_id {
            return Err(HandshakeError::Rejected(format!(
                "body circuit id {} does not match {}",
                body.circuit_id, cell.circuit_id
            )));
        }
        Ok(body.cookie)
    }

    /// Verify the relay's CREATED reply and derive the shared keys.
    ///
    /// In order: check the cell command and circuit id, parse the body,
    /// compute the combined DH secret, recompute the verifier and compare
    /// it in constant time (this is where a man-in-the-middle is caught),
    /// authenticate the relay's identity, then derive the four HKDF keys.
    ///
    /// # Errors
    /// Returns [`HandshakeError::Handshake`] if [`HandshakeClient::create`]
    /// was not called for this circuit. Returns
    /// [`HandshakeError::Rejected`] on a wrong command, circuit id,
    /// message type, or protocol version. Returns
    /// [`HandshakeError::Verification`] if the verifier does not match,
    /// the sealed nonce fails to open, or the relay's public key is a
    /// low-order point. Returns [`HandshakeError::RelayAuthentication`] if
    /// the relay cannot prove a trusted identity.
    pub fn complete(&mut self, message: &[u8], circuit_id: Option<u32>) -> Result<HandshakeKeys, HandshakeError> {
        let cell = coerce_cell(message)?;
        self.complete_cell(&cell, circuit_id)
    }

    /// Identical to [`Self::complete`], but takes an already-parsed
    /// [`Cell`] directly instead of a raw datagram. This mirrors Python's
    /// duck-typed `complete(message, ...)`, which accepts either a `Cell`
    /// object or raw bytes (`HandshakeClient._coerce_cell`) -- callers such
    /// as `circuit.py`'s `_extend_once` pass an already-constructed `Cell`
    /// peeled from an onion layer, not a packed datagram.
    pub fn complete_cell(&mut self, cell: &Cell, circuit_id: Option<u32>) -> Result<HandshakeKeys, HandshakeError> {
        let circuit_id = match circuit_id {
            Some(c) => c,
            None => match &self.pending {
                Some(p) => p.circuit_id,
                None => {
                    return Err(HandshakeError::Handshake(
                        "no pending handshake; call create() first or pass circuit_id".to_string(),
                    ))
                }
            },
        };
        let matches_pending = matches!(&self.pending, Some(p) if p.circuit_id == circuit_id);
        if !matches_pending {
            return Err(HandshakeError::Handshake(format!(
                "no pending handshake for circuit {circuit_id:#010x}: call create(circuit_id) on this \
                 client first, and use the same circuit id for both calls. (A completed handshake \
                 clears the pending state, so a client cannot be reused for a second circuit without \
                 calling create() again.)"
            )));
        }
        // Security audit fix (2026-09-26): this used to `.clone()` each
        // field off a borrow and leave `self.pending` for the caller's
        // later `self.pending = None` to drop -- on every exit path
        // (success or error) that dropped `kem_shared` un-zeroized
        // (`private`'s own `StaticSecret` type already zeroizes itself on
        // drop, so it was never at risk the same way), regardless of
        // `HandshakeClient`'s own `Drop` impl, since that only protects
        // whatever is still resident *at final struct drop*, not material
        // discarded earlier during ordinary use. `.take()` moves the
        // original out (clearing `self.pending` to `None` immediately),
        // so this function now owns the only copy and can zeroize
        // `kem_shared` explicitly right after its last use below, on
        // every exit path.
        let pending = self.pending.take().expect("just matched Some above");
        let PendingCreate { client_nonce, kem_shared, pq_binding: pq_binding_bytes, private, .. } = pending;
        // Security audit fix (2026-09-26, follow-up): an earlier version of
        // this fix zeroized `kem_shared` at one specific point (right
        // before its last use), reasoning that covered "every exit path
        // from there on" -- but there are several early-return validation
        // checks (cell circuit-id/command, `CreatedBody::unpack`, body
        // type/circuit-id) *between* binding it and that point, each of
        // which would skip the zeroize entirely on a malformed/wrong-
        // circuit-id reply from a remote peer. `Zeroizing<T>` wipes on
        // drop regardless of *which* exit path fires -- including ones
        // added later without anyone re-auditing where the manual zeroize
        // call was -- so it doesn't depend on this function's control flow
        // staying the way it looked when the zeroize point was chosen.
        // (`private`'s own `StaticSecret` type already zeroizes itself on
        // drop, so it needs no wrapper.)
        let kem_shared = zeroize::Zeroizing::new(kem_shared);
        let client_public = PublicKey::from(&private).to_bytes();

        if cell.circuit_id != circuit_id {
            return Err(HandshakeError::Rejected(format!(
                "circuit id mismatch: expected {circuit_id}, got {}",
                cell.circuit_id
            )));
        }
        if cell.command != Command::Created {
            return Err(HandshakeError::Rejected(format!("expected a CREATED cell, got {}", cell.command.name())));
        }

        let body = CreatedBody::unpack(&cell.payload)?;
        if body.msg_type != MSG_CREATED {
            return Err(HandshakeError::Rejected(format!(
                "expected message type {MSG_CREATED}, got {}",
                body.msg_type
            )));
        }
        if body.circuit_id != circuit_id {
            return Err(HandshakeError::Rejected(format!(
                "body circuit id {} does not match {circuit_id}",
                body.circuit_id
            )));
        }

        let relay_public_key = PublicKey::from(body.public_key);
        let relay_ephemeral_key = PublicKey::from(body.ephemeral_public);
        // Two DH terms, concatenated: the ephemeral one gives the derived
        // keys forward secrecy, the static one is what the Ed25519
        // signature below authenticates back to a pinned identity.
        let shared_eph = private.diffie_hellman(&relay_ephemeral_key);
        let shared_static = private.diffie_hellman(&relay_public_key);
        if !shared_eph.was_contributory() || !shared_static.was_contributory() {
            return Err(HandshakeError::Verification("relay public key is unusable (low-order point)".to_string()));
        }
        let mut shared_secret = shared_eph.to_bytes().to_vec();
        shared_secret.extend_from_slice(&shared_static.to_bytes());
        // Hybrid: the ML-KEM secret is a third input to every derived key.
        shared_secret.extend_from_slice(&kem_shared);

        let relay_nonce = self.open_relay_nonce(&cell.payload, &body, &shared_secret, circuit_id)?;

        let expected = compute_verifier(
            &shared_secret,
            &body.salt,
            circuit_id,
            &client_public,
            &body.public_key,
            &body.ephemeral_public,
            &client_nonce,
            &relay_nonce,
            &self.cipher,
            &pq_binding_bytes,
            &body.identity_public,
        );
        if !bool::from(expected.as_slice().ct_eq(body.verifier.as_slice())) {
            return Err(HandshakeError::Verification(
                "handshake verifier mismatch: the peer does not hold the private keys for the public \
                 keys it sent (possible man-in-the-middle), or the handshake was tampered with"
                    .to_string(),
            ));
        }

        // Key exchange is now proven sound, but nothing yet ties the
        // responder to a relay identity.
        self.authenticate_relay(&body, &shared_secret, circuit_id, &client_nonce, &relay_nonce, &pq_binding_bytes, &client_public)?;

        let keys = derive_handshake_keys(
            &shared_secret,
            &body.salt,
            circuit_id,
            &self.cipher,
            Some(body.public_key),
            expected.to_vec(),
            None,
            self.relay_identity,
            HandshakeRole::Client,
        );
        self.keys = Some(keys.clone());
        // `self.pending` is already `None` -- the `.take()` above moved it
        // out at the start of this call.
        Ok(keys)
    }

    fn authenticate_relay(
        &mut self,
        body: &CreatedBody,
        shared_secret: &[u8],
        circuit_id: u32,
        client_nonce: &[u8],
        relay_nonce: &[u8],
        pq_binding_bytes: &[u8],
        client_public: &[u8; PUBLIC_KEY_SIZE],
    ) -> Result<(), HandshakeError> {
        if !body.is_authenticated() {
            // An anonymous relay can never satisfy a pin, so with pins
            // configured it is refused outright -- `allow_anonymous_relay`
            // is only honoured when there is nothing to pin against.
            // (Honouring it here let an impostor with its own key and no
            // identity bypass a client told to talk only to specific relays.)
            if let Some(trusted) = &self.trusted_identities {
                return Err(HandshakeError::RelayAuthentication(format!(
                    "relay presented no identity, but this client is pinned to {} identity key(s); an \
                     anonymous relay can never satisfy a pin, so it is refused even with \
                     allow_anonymous_relay=true",
                    trusted.len()
                )));
            }
            if self.allow_anonymous_relay {
                self.relay_identity = None;
                return Ok(());
            }
            return Err(HandshakeError::RelayAuthentication(
                "relay presented no identity signature; refusing an unauthenticated relay (pass \
                 allow_anonymous_relay=true only to interoperate with a legacy peer during migration)"
                    .to_string(),
            ));
        }

        // Verify the signature before consulting the trust set, so an
        // untrusted key produces the same error shape as a forged one.
        verify_relay_signature(
            &body.signature,
            &body.identity_public,
            shared_secret,
            &body.salt,
            circuit_id,
            client_public,
            &body.public_key,
            &body.ephemeral_public,
            client_nonce,
            relay_nonce,
            &self.cipher,
            &body.verifier,
            pq_binding_bytes,
        )?;

        if let Some(trusted) = &self.trusted_identities {
            if !trusted.contains(&body.identity_public) {
                return Err(HandshakeError::RelayAuthentication(format!(
                    "relay identity {}... is not in the pinned trust set of {} key(s); an impostor \
                     presenting its own valid keypair lands here",
                    hex_prefix(&body.identity_public, 8),
                    trusted.len()
                )));
            }
        }

        self.relay_identity = Some(body.identity_public);
        Ok(())
    }

    /// Unseal the relay's nonce from the tail of the CREATED payload.
    ///
    /// # Errors
    /// Returns [`HandshakeError::Verification`] if the field is absent or
    /// fails to authenticate.
    fn open_relay_nonce(
        &self,
        payload: &[u8],
        _body: &CreatedBody,
        shared_secret: &[u8],
        circuit_id: u32,
    ) -> Result<[u8; NONCE_SIZE], HandshakeError> {
        let sealed = if payload.len() > CREATED_BODY_SIZE { &payload[CREATED_BODY_SIZE..] } else { &[][..] };
        if sealed.len() < SEAL_OVERHEAD {
            return Err(HandshakeError::Verification("CREATED payload is missing the sealed relay nonce".to_string()));
        }
        let hs_key = hkdf_expand(shared_secret, b"allium-handshake-salt-pre-v1", HKDF_HS_KEY, KEY_SIZE);
        let mut aad = circuit_id.to_be_bytes().to_vec();
        aad.extend_from_slice(b"allium-handshake-nonce-v1");
        let aead = crypto::new_aead(&self.cipher, &hs_key, None)
            .map_err(|e: CryptoError| HandshakeError::Verification(format!("could not open the relay nonce: {e}")))?;
        let nonce = aead.open(sealed, &aad).map_err(|e| {
            HandshakeError::Verification(format!(
                "could not open the relay nonce: the CREATED cell was not produced by a peer holding \
                 the matching private key ({e})"
            ))
        })?;
        if nonce.len() != NONCE_SIZE {
            return Err(HandshakeError::Verification(format!("relay nonce must be {NONCE_SIZE} bytes, got {}", nonce.len())));
        }
        Ok(read_array(&nonce, 0))
    }

    /// Run the full handshake over a UDP socket and return the shared keys.
    ///
    /// Sends the CREATE message, waits for the reply, verifies it, and
    /// derives the keys. Cooperates with a relay's return-routability
    /// check: if the reply is a CREATE_CHALLENGE rather than a CREATED,
    /// this retries (up to `max_cookie_retries` times) with the echoed
    /// cookie before giving up.
    ///
    /// # Errors
    /// Returns [`HandshakeError::Timeout`] if no reply arrives, or the
    /// retry budget is exhausted on repeated challenges.
    pub fn handshake(
        &mut self,
        sock: &UdpSocket,
        relay_addr: SocketAddr,
        circuit_id: u32,
        max_cookie_retries: u32,
    ) -> Result<HandshakeKeys, HandshakeError> {
        let mut cookie: Option<[u8; COOKIE_SIZE]> = None;
        let attempts = max_cookie_retries + 1;
        for attempt in 1..=attempts {
            let message = self.create(circuit_id, cookie)?;
            for datagram in message.datagrams()? {
                sock.send_to(&datagram, relay_addr).map_err(|e| HandshakeError::Timeout(e.to_string()))?;
            }
            let datagram = recv_from(sock, relay_addr, self.timeout)?;
            let reply_cell = coerce_cell(&datagram)?;
            if reply_cell.command == Command::CreateChallenge {
                if attempt == attempts {
                    return Err(HandshakeError::Timeout(format!(
                        "{relay_addr} kept issuing return-routability challenges past {attempts} \
                         attempt(s); giving up"
                    )));
                }
                cookie = Some(self.parse_challenge(&datagram, Some(circuit_id))?);
                continue;
            }
            return self.complete(&datagram, Some(circuit_id));
        }
        unreachable!("loop always returns or errors before exhausting attempts")
    }
}

// --------------------------------------------------------------------------
// Relay
// --------------------------------------------------------------------------

/// Derive a return-routability cookie: HMAC-SHA256, truncated to
/// [`COOKIE_SIZE`].
///
/// A pure function of its inputs -- no state stored anywhere.
fn cookie_for(secret: &[u8], source_ip: &str, window: i64) -> [u8; COOKIE_SIZE] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret).expect("HMAC accepts a key of any length");
    mac.update(source_ip.as_bytes());
    mac.update(&window.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; COOKIE_SIZE];
    out.copy_from_slice(&digest[..COOKIE_SIZE]);
    out
}

fn unix_time_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs_f64()
}

/// Relay side of the X25519 handshake.
///
/// Holds a long-term X25519 private key and answers CREATE cells with
/// CREATED. The relay keeps no per-circuit state between messages:
/// everything needed to answer is in the CREATE cell.
pub struct HandshakeRelay {
    private: StaticSecret,
    pub public_key: [u8; PUBLIC_KEY_SIZE],
    pub cipher: String,
    respond_to_bad_requests: bool,
    identity_private: SigningKey,
    pub identity_public: [u8; IDENTITY_KEY_SIZE],
    /// Declared for parity with the Python original, whose constructor
    /// always generates an identity key when none is given -- so the
    /// "refuse to answer without one" branch in `respond` can never
    /// actually fire there either. Kept as a field so callers can inspect
    /// the configured intent even though it is currently inert.
    pub require_identity: bool,
    /// Keys from the most recent successful handshake.
    pub keys: Option<HandshakeKeys>,
    require_return_routability: bool,
    cookie_secret: Vec<u8>,
    cookie_window_seconds: f64,
    /// ML-KEM decapsulation keys by key id, with their creation time.
    kem_keys: HashMap<[u8; KEM_KEY_ID_SIZE], (Vec<u8>, Instant)>,
    /// The newest ML-KEM encapsulation key -- what the relay advertises in
    /// its descriptor. `None` until [`HandshakeRelay::rotate_kem_key`] runs.
    pub kem_public: Option<Vec<u8>>,
    kem_created_at: Option<Instant>,
}

impl Drop for HandshakeRelay {
    /// Security audit fix (2026-09-26): `private`/`identity_private` are
    /// `x25519_dalek::StaticSecret`/`ed25519_dalek::SigningKey`, which
    /// already zeroize themselves on drop. `kem_keys` retains rotated-out
    /// ML-KEM decapsulation keys for `KEM_KEY_RETENTION` (~75 minutes)
    /// after rotation, and `cookie_secret` is a rotated anti-DoS MAC
    /// pepper; neither type zeroizes on its own, so wipe both here.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.cookie_secret.zeroize();
        for (decap_key, _created_at) in self.kem_keys.values_mut() {
            decap_key.zeroize();
        }
    }
}

impl HandshakeRelay {
    /// How long a relay keeps accepting a rotated-out ML-KEM key: long
    /// enough for any descriptor that advertised it to have expired, plus
    /// slack for clock skew and slow clients. Also the post-quantum
    /// forward-secrecy window.
    pub const KEM_KEY_RETENTION: f64 = 3600.0 + 900.0;
    /// Never rotate more often than this, however often the relay republishes.
    pub const KEM_MIN_ROTATION: f64 = 600.0;
    const KEM_MAX_KEYS: usize = 16;

    /// Build a new relay.
    ///
    /// A fresh X25519 and Ed25519 identity key are generated when omitted
    /// -- convenient for tests, but a real relay must persist both.
    ///
    /// # Errors
    /// Returns [`HandshakeError::Handshake`] if `cookie_window_seconds` is
    /// not positive.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        static_private: Option<[u8; 32]>,
        cipher: Option<&str>,
        respond_to_bad_requests: bool,
        identity_private: Option<[u8; 32]>,
        require_identity: bool,
        require_return_routability: bool,
        cookie_secret: Option<Vec<u8>>,
        cookie_window_seconds: f64,
    ) -> Result<Self, HandshakeError> {
        let private = match static_private {
            Some(b) => StaticSecret::from(b),
            None => StaticSecret::from(random_array::<32>()),
        };
        let public_key = PublicKey::from(&private).to_bytes();

        let identity_private = match identity_private {
            Some(b) => SigningKey::from_bytes(&b),
            None => SigningKey::from_bytes(&random_array::<32>()),
        };
        let identity_public = identity_private.verifying_key().to_bytes();

        let cookie_secret = cookie_secret.unwrap_or_else(|| osrand::bytes(32));
        if cookie_window_seconds <= 0.0 {
            return Err(HandshakeError::Handshake(format!(
                "cookie_window_seconds must be positive, got {cookie_window_seconds}"
            )));
        }

        Ok(HandshakeRelay {
            private,
            public_key,
            cipher: cipher.unwrap_or(DEFAULT_CIPHER).to_string(),
            respond_to_bad_requests,
            identity_private,
            identity_public,
            require_identity,
            keys: None,
            require_return_routability,
            cookie_secret,
            cookie_window_seconds,
            kem_keys: HashMap::new(),
            kem_public: None,
            kem_created_at: None,
        })
    }

    // -- post-quantum key management ----------------------------------

    /// Generate a fresh ML-KEM-768 keypair and make it the advertised one.
    ///
    /// Older keys stay usable for [`Self::KEM_KEY_RETENTION`] seconds, then
    /// are discarded. With `force=false` this is a no-op until the current
    /// key is [`Self::KEM_MIN_ROTATION`] seconds old.
    pub fn rotate_kem_key(&mut self, force: bool) -> Vec<u8> {
        let now = Instant::now();
        if !force {
            if let (Some(kp), Some(created)) = (&self.kem_public, self.kem_created_at) {
                if now.duration_since(created) < Duration::from_secs_f64(Self::KEM_MIN_ROTATION) {
                    return kp.clone();
                }
            }
        }
        let (ek, dk) = mlkem::generate_keypair();
        self.kem_keys.insert(mlkem::key_id(&ek), (dk, now));
        self.kem_public = Some(ek.clone());
        self.kem_created_at = Some(now);
        self.prune_kem_keys(now);
        ek
    }

    /// Prune keys older than [`Self::KEM_KEY_RETENTION`] (never the
    /// current one), then, if still over [`Self::KEM_MAX_KEYS`], evict the
    /// single oldest non-current key by creation time.
    ///
    /// The Python original evicts the first non-current key in dict
    /// iteration order, which happens to be the oldest given Python's
    /// insertion-ordered dicts; this evicts by creation time directly,
    /// which is the same result without relying on map iteration order.
    /// Security audit fix (2026-09-26): `retain`'s closure only sees kept
    /// entries, so the version of this that used it couldn't zeroize what
    /// it filtered out -- and the second loop's `.remove()` just dropped
    /// the evicted `(decap_key, created_at)` pair too. Both are a live
    /// ML-KEM decapsulation key discarded during ordinary key rotation
    /// over a long-running process's life, not at this struct's final
    /// drop (`Drop for HandshakeRelay` only protects keys still resident
    /// in `kem_keys` *then*). Collect stale keys first, then remove and
    /// zeroize each explicitly, matching the collect-then-remove shape
    /// `Relays`/`Authority`'s copy of this method already uses.
    fn prune_kem_keys(&mut self, now: Instant) {
        use zeroize::Zeroize;
        let current = self.kem_public.as_ref().map(|ek| mlkem::key_id(ek));
        let retention = Duration::from_secs_f64(Self::KEM_KEY_RETENTION);
        let stale: Vec<[u8; KEM_KEY_ID_SIZE]> = self
            .kem_keys
            .iter()
            .filter(|(kid, (_, created))| Some(**kid) != current && now.duration_since(*created) > retention)
            .map(|(kid, _)| *kid)
            .collect();
        for kid in stale {
            if let Some((mut decap_key, _)) = self.kem_keys.remove(&kid) {
                decap_key.zeroize();
            }
        }
        while self.kem_keys.len() > Self::KEM_MAX_KEYS {
            let oldest = self
                .kem_keys
                .iter()
                .filter(|(kid, _)| Some(**kid) != current)
                .min_by_key(|(_, (_, created))| *created)
                .map(|(kid, _)| *kid);
            match oldest {
                Some(kid) => {
                    if let Some((mut decap_key, _)) = self.kem_keys.remove(&kid) {
                        decap_key.zeroize();
                    }
                }
                None => break,
            }
        }
    }

    // -- return-routability cookie --------------------------------------

    /// Check `cookie` against the current and previous time window for
    /// `source_ip`. Accepting two windows tolerates a legitimate retry
    /// that lands just after a window rolls over.
    fn verify_cookie(&self, cookie: &[u8; COOKIE_SIZE], source_ip: &str) -> bool {
        let now_window = (unix_time_secs() / self.cookie_window_seconds).floor() as i64;
        for window in [now_window, now_window - 1] {
            let expected = cookie_for(&self.cookie_secret, source_ip, window);
            if bool::from(expected.as_slice().ct_eq(cookie.as_slice())) {
                return true;
            }
        }
        false
    }

    /// Build the cheap CREATE_CHALLENGE reply for an unproven CREATE.
    fn issue_challenge(&self, circuit_id: u32, source_ip: &str) -> Result<Cell, HandshakeError> {
        let window = (unix_time_secs() / self.cookie_window_seconds).floor() as i64;
        let cookie = cookie_for(&self.cookie_secret, source_ip, window);
        let body = ChallengeBody { version: HANDSHAKE_VERSION, msg_type: MSG_CHALLENGE, circuit_id, cookie };
        Ok(Cell::new(circuit_id, Command::CreateChallenge, body.pack())?)
    }

    // -- message processing ----------------------------------------------

    /// Answer a CREATE message with a CREATED (or, if
    /// `require_return_routability` is set and the request did not carry a
    /// valid cookie, a cheap CREATE_CHALLENGE) cell.
    ///
    /// `peer_addr` is purely diagnostic when `require_return_routability`
    /// is off (the default); when it is on, this is load-bearing -- the
    /// cookie is checked against it, and omitting it is rejected.
    ///
    /// # Errors
    /// Returns [`HandshakeError::Rejected`] on an unusable request, or
    /// when `require_return_routability` is set but `peer_addr` is `None`.
    pub fn respond(&mut self, message: &[u8], peer_addr: Option<SocketAddr>) -> Result<Cell, HandshakeError> {
        let cell = coerce_cell(message)?;
        self.respond_parts(cell.circuit_id, cell.command, &cell.payload, peer_addr)
    }

    /// Answer a CREATE that arrived as several `CREATE_FRAGMENT` cells and
    /// was reassembled by a [`crate::createfrag::CreateReassembler`] --
    /// the hybrid (post-quantum) CREATE's body is larger than one cell
    /// payload, so it cannot travel as a single [`Cell`] the way
    /// [`Self::respond`] expects. Otherwise identical to [`Self::respond`].
    ///
    /// # Errors
    /// As for [`Self::respond`].
    pub fn respond_reassembled(&mut self, message: &crate::createfrag::CreateMessage, peer_addr: Option<SocketAddr>) -> Result<Cell, HandshakeError> {
        self.respond_parts(message.circuit_id, message.command, &message.payload, peer_addr)
    }

    fn respond_parts(&mut self, circuit_id: u32, command: Command, payload: &[u8], peer_addr: Option<SocketAddr>) -> Result<Cell, HandshakeError> {
        if command != Command::Create {
            return Err(HandshakeError::Rejected(format!("expected a CREATE cell, got {}", command.name())));
        }

        let body = CreateBody::unpack(payload)?;
        if body.msg_type != MSG_CREATE {
            return Err(HandshakeError::Rejected(format!("expected message type {MSG_CREATE}, got {}", body.msg_type)));
        }
        if body.circuit_id != circuit_id {
            return Err(HandshakeError::Rejected(format!(
                "body circuit id {} disagrees with the cell header ({circuit_id})",
                body.circuit_id
            )));
        }

        // The client nonce occupies its fixed slot ahead of the cookie field.
        let client_nonce = &payload[CREATE_NONCE_OFFSET..CREATE_NONCE_OFFSET + NONCE_SIZE];

        // Cheap per-source-IP gate before any of the expensive work below.
        if self.require_return_routability {
            let peer = peer_addr.ok_or_else(|| {
                HandshakeError::Rejected(
                    "require_return_routability is set but no peer_addr was supplied; the cookie \
                     cannot be checked without the sender's address"
                        .to_string(),
                )
            })?;
            let source_ip = peer.ip().to_string();
            if !body.has_cookie() || !self.verify_cookie(&body.cookie, &source_ip) {
                return self.issue_challenge(circuit_id, &source_ip);
            }
        }

        // Hybrid: decapsulate after the cookie gate above, so an unproven
        // source can't make this relay spend ML-KEM work either.
        let mut kem_shared = Vec::new();
        let mut pq_binding_bytes = Vec::new();
        if body.is_hybrid() {
            let key_id: [u8; KEM_KEY_ID_SIZE] =
                body.kem_key_id.as_slice().try_into().expect("CreateBody::unpack always sizes this correctly");
            let entry = self
                .kem_keys
                .get(&key_id)
                .ok_or_else(|| HandshakeError::Rejected("hybrid CREATE names an unknown ML-KEM key".to_string()))?;
            kem_shared = mlkem::decapsulate(&entry.0, &body.kem_ciphertext)
                .map_err(|e| HandshakeError::Rejected(format!("bad ML-KEM ciphertext: {e}")))?;
            pq_binding_bytes = pq_binding(&body.kem_key_id, &body.kem_ciphertext);
        }

        let client_public_key = PublicKey::from(body.public_key);

        // A fresh keypair, used for this handshake only and discarded once
        // this method returns.
        let ephemeral_private = StaticSecret::from(random_array::<32>());
        let ephemeral_public = PublicKey::from(&ephemeral_private).to_bytes();
        let shared_eph = ephemeral_private.diffie_hellman(&client_public_key);
        let shared_static = self.private.diffie_hellman(&client_public_key);
        if !shared_eph.was_contributory() || !shared_static.was_contributory() {
            return Err(HandshakeError::Rejected("client public key is unusable (low-order point)".to_string()));
        }
        let mut shared_secret = shared_eph.to_bytes().to_vec();
        shared_secret.extend_from_slice(&shared_static.to_bytes());
        shared_secret.extend_from_slice(&kem_shared);

        let salt = random_array::<SALT_SIZE>();
        let relay_nonce = random_array::<NONCE_SIZE>();
        let verifier = compute_verifier(
            &shared_secret,
            &salt,
            circuit_id,
            &body.public_key,
            &self.public_key,
            &ephemeral_public,
            client_nonce,
            &relay_nonce,
            &self.cipher,
            &pq_binding_bytes,
            &self.identity_public,
        );

        // Seal the relay nonce under a key the client can reach before it
        // trusts the salt.
        let hs_key = hkdf_expand(&shared_secret, b"allium-handshake-salt-pre-v1", HKDF_HS_KEY, KEY_SIZE);
        let mut aad = circuit_id.to_be_bytes().to_vec();
        aad.extend_from_slice(b"allium-handshake-nonce-v1");
        let mut aead = crypto::new_aead(&self.cipher, &hs_key, None).map_err(|e| HandshakeError::Rejected(e.to_string()))?;
        let sealed_nonce = aead.seal(&relay_nonce, &aad).map_err(|e| HandshakeError::Rejected(e.to_string()))?;

        // Sign the transcript so the client can tie this reply to a relay
        // identity.
        let signature: [u8; SIGNATURE_SIZE] = self
            .identity_private
            .try_sign(&signing_payload(
                &shared_secret,
                &salt,
                circuit_id,
                &body.public_key,
                &self.public_key,
                &ephemeral_public,
                client_nonce,
                &relay_nonce,
                &self.cipher,
                &verifier,
                &self.identity_public,
                &pq_binding_bytes,
            ))
            .map_err(|e| HandshakeError::Rejected(format!("failed to sign handshake transcript: {e}")))?
            .to_bytes();

        let created_body = CreatedBody {
            version: HANDSHAKE_VERSION,
            msg_type: MSG_CREATED,
            circuit_id: circuit_id,
            public_key: self.public_key,
            ephemeral_public,
            salt,
            verifier,
            identity_public: self.identity_public,
            signature,
        }
        .pack();
        let mut payload = created_body;
        payload.extend_from_slice(&sealed_nonce);
        if payload.len() > MAX_HANDSHAKE_PAYLOAD {
            return Err(HandshakeError::Rejected(format!(
                "CREATED payload is {} bytes, exceeding the {MAX_HANDSHAKE_PAYLOAD}-byte cell payload",
                payload.len()
            )));
        }

        let keys = derive_handshake_keys(
            &shared_secret,
            &salt,
            circuit_id,
            &self.cipher,
            Some(self.public_key),
            verifier.to_vec(),
            None,
            Some(self.identity_public),
            HandshakeRole::Relay,
        );
        self.keys = Some(keys);

        Ok(Cell::new(circuit_id, Command::Created, payload)?)
    }

    // -- socket convenience ------------------------------------------------

    /// Build a DESTROY cell for an unusable CREATE.
    pub fn reject_cell(&self, circuit_id: u32) -> Cell {
        Cell::new(circuit_id, Command::Destroy, Vec::new()).expect("an empty payload always fits a cell")
    }

    /// Receive one datagram, answer it, and return `(reply, peer)`.
    ///
    /// Returns `Ok(None)` when the datagram is unusable, so a caller can
    /// simply keep looping. Never returns a protocol error for malformed
    /// input: a relay must not die because a scanner sent it garbage.
    pub fn serve_once(&mut self, sock: &UdpSocket) -> Result<Option<(Cell, SocketAddr)>, HandshakeError> {
        let mut buf = [0u8; CELL_SIZE];
        let (n, peer) = sock.recv_from(&mut buf).map_err(|e| HandshakeError::Handshake(e.to_string()))?;
        let datagram = &buf[..n];
        let reply = match self.respond(datagram, Some(peer)) {
            Ok(r) => r,
            Err(HandshakeError::Rejected(_)) => {
                if self.respond_to_bad_requests {
                    // Echo back the circuit id the client actually used, not
                    // a hardcoded 0, so the DESTROY tells the client
                    // something about the request it just made.
                    let circuit_id = Cell::from_bytes(datagram, false).map(|c| c.circuit_id).unwrap_or(0);
                    self.reject_cell(circuit_id)
                } else {
                    return Ok(None);
                }
            }
            Err(_) => return Ok(None),
        };
        sock.send_to(&reply.pack(), peer).map_err(|e| HandshakeError::Handshake(e.to_string()))?;
        Ok(Some((reply, peer)))
    }

    /// Answer CREATE cells until `max_requests` have been handled (or
    /// forever, if `None`). Returns the number of CREATED cells sent.
    pub fn serve_forever(&mut self, sock: &UdpSocket, max_requests: Option<u64>) -> u64 {
        let mut handled = 0u64;
        loop {
            if let Some(max) = max_requests {
                if handled >= max {
                    break;
                }
            }
            match self.serve_once(sock) {
                Ok(Some(_)) => handled += 1,
                Ok(None) => {}
                // The socket was closed or errored under us (a shutdown
                // race); treat it as a signal to stop rather than a crash.
                Err(_) => break,
            }
        }
        handled
    }
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn fixed_client(trusted: Option<Vec<[u8; IDENTITY_KEY_SIZE]>>, trust_first_use: bool, allow_anonymous_relay: bool) -> HandshakeClient {
        HandshakeClient::new(None, None, DEFAULT_TIMEOUT, trusted, trust_first_use, allow_anonymous_relay, None, false)
            .expect("valid client config")
    }

    fn fixed_relay() -> HandshakeRelay {
        HandshakeRelay::new(None, None, false, None, false, false, None, DEFAULT_COOKIE_WINDOW_SECONDS).expect("valid relay config")
    }

    #[test]
    fn client_requires_pinning_or_trust_first_use() {
        let err = HandshakeClient::new(None, None, DEFAULT_TIMEOUT, None, false, false, None, false).unwrap_err();
        assert!(matches!(err, HandshakeError::Handshake(_)));
    }

    #[test]
    fn challenge_body_round_trips() {
        let body = ChallengeBody { version: HANDSHAKE_VERSION, msg_type: MSG_CHALLENGE, circuit_id: 7, cookie: [3u8; COOKIE_SIZE] };
        let packed = body.pack();
        assert_eq!(packed.len(), CHALLENGE_BODY_SIZE);
        let parsed = ChallengeBody::unpack(&packed).unwrap();
        assert_eq!(parsed.circuit_id, 7);
        assert_eq!(parsed.cookie, [3u8; COOKIE_SIZE]);
    }

    #[test]
    fn with_cookie_only_replaces_the_cookie_field() {
        let raw = pack_create_body(HANDSHAKE_VERSION, MSG_CREATE, 1, &[9u8; PUBLIC_KEY_SIZE], &[1u8; NONCE_SIZE], &[0u8; COOKIE_SIZE]);
        let replaced = with_cookie(&raw, &[0xCCu8; COOKIE_SIZE]).unwrap();
        assert_eq!(replaced.len(), raw.len());
        assert_eq!(&replaced[..CREATE_BODY_SIZE - COOKIE_SIZE], &raw[..CREATE_BODY_SIZE - COOKIE_SIZE]);
        assert_eq!(&replaced[CREATE_BODY_SIZE - COOKIE_SIZE..], &[0xCCu8; COOKIE_SIZE][..]);
    }

    #[test]
    fn classical_handshake_round_trip_in_process() {
        let mut relay = fixed_relay();
        let relay_identity = relay.identity_public;
        let mut client = fixed_client(Some(vec![relay_identity]), false, false);

        let msg = client.create(42, None).unwrap();
        let create_cell = match msg {
            CreateMessage::Cell(c) => c,
            CreateMessage::Fragmented(_) => panic!("classical handshake must not fragment"),
        };
        let created_cell = relay.respond(&create_cell.pack(), None).unwrap();
        let keys = client.complete(&created_cell.pack(), Some(42)).unwrap();
        let relay_keys = relay.keys.clone().unwrap();

        assert_eq!(keys.aead_key_fwd, relay_keys.aead_key_fwd);
        assert_eq!(keys.aead_key_bwd, relay_keys.aead_key_bwd);
        assert_eq!(keys.mac_key, relay_keys.mac_key);
        assert_eq!(keys.verifier, relay_keys.verifier);
        assert_eq!(keys.session_id(), relay_keys.session_id());
        assert!(keys.relay_is_authenticated());
        assert_eq!(keys.relay_public, Some(relay.public_key));
        assert_eq!(client.relay_identity, Some(relay_identity));
    }

    #[test]
    fn explicit_empty_trusted_identities_means_trust_no_one() {
        // `Some(vec![])` must not be treated like `None` (trust-first-use
        // territory) -- an operator who explicitly pins to nothing is
        // pinning to *nothing*, not opting out of pinning. Construction
        // succeeds (an empty allow-list is a valid, if useless-on-its-own,
        // config), but a real handshake against it must be rejected.
        let mut relay = fixed_relay();
        let mut client = fixed_client(Some(Vec::new()), false, false);

        let msg = client.create(42, None).unwrap();
        let create_cell = match msg {
            CreateMessage::Cell(c) => c,
            CreateMessage::Fragmented(_) => panic!("classical handshake must not fragment"),
        };
        let created_cell = relay.respond(&create_cell.pack(), None).unwrap();
        let err = client.complete(&created_cell.pack(), Some(42)).unwrap_err();
        assert!(
            matches!(err, HandshakeError::RelayAuthentication(_)),
            "expected a RelayAuthentication error, got {err:?}"
        );
    }

    #[test]
    fn onion_crypto_derived_from_both_sides_interoperates() {
        let mut relay = fixed_relay();
        let mut client = fixed_client(None, true, false);

        let msg = client.create(1, None).unwrap();
        let create_cell = match msg {
            CreateMessage::Cell(c) => c,
            _ => unreachable!(),
        };
        let created_cell = relay.respond(&create_cell.pack(), None).unwrap();
        let client_keys = client.complete(&created_cell.pack(), Some(1)).unwrap();
        let relay_keys = relay.keys.clone().unwrap();

        let mut client_onion = client_keys.to_onion_crypto("client-hop", 0).unwrap();
        let relay_onion = relay_keys.to_onion_crypto("relay-hop", 0).unwrap();

        let sealed = client_onion.seal_payload(b"hello relay", 0, ("0.0.0.0".to_string(), 0), None, None).unwrap();
        let peeled = relay_onion.peel(&sealed).unwrap();
        assert_eq!(peeled.payload_bytes().unwrap(), b"hello relay".to_vec());
    }

    #[test]
    fn tampered_verifier_is_rejected() {
        let mut relay = fixed_relay();
        let relay_identity = relay.identity_public;
        let mut client = fixed_client(Some(vec![relay_identity]), false, false);

        let msg = client.create(5, None).unwrap();
        let create_cell = match msg {
            CreateMessage::Cell(c) => c,
            _ => unreachable!(),
        };
        let created_cell = relay.respond(&create_cell.pack(), None).unwrap();
        let mut payload = created_cell.payload.clone();
        // The verifier sits right after the two public keys and the salt.
        let verifier_off = 6 + 2 * PUBLIC_KEY_SIZE + SALT_SIZE;
        payload[verifier_off] ^= 0xFF;
        let tampered = Cell::new(created_cell.circuit_id, Command::Created, payload).unwrap();

        let err = client.complete(&tampered.pack(), Some(5)).unwrap_err();
        assert!(matches!(err, HandshakeError::Verification(_)));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let mut relay = fixed_relay();
        let relay_identity = relay.identity_public;
        let mut client = fixed_client(Some(vec![relay_identity]), false, false);

        let msg = client.create(6, None).unwrap();
        let create_cell = match msg {
            CreateMessage::Cell(c) => c,
            _ => unreachable!(),
        };
        let created_cell = relay.respond(&create_cell.pack(), None).unwrap();
        let mut payload = created_cell.payload.clone();
        let signature_off = 6 + 2 * PUBLIC_KEY_SIZE + SALT_SIZE + VERIFIER_SIZE + IDENTITY_KEY_SIZE;
        payload[signature_off] ^= 0xFF;
        let tampered = Cell::new(created_cell.circuit_id, Command::Created, payload).unwrap();

        let err = client.complete(&tampered.pack(), Some(6)).unwrap_err();
        assert!(matches!(err, HandshakeError::RelayAuthentication(_)));
    }

    /// Regression test: an on-path attacker who intercepts a genuine,
    /// fully-signed CREATED reply and zeroes out just its
    /// `identity_public`/`signature` fields -- leaving
    /// `public_key`/`ephemeral_public`/`salt`/`verifier` untouched -- must
    /// now fail the verifier check outright, even against a client
    /// configured with `allow_anonymous_relay = true` *and* a pinned
    /// identity for this exact relay. Before the fix, this silently
    /// downgraded to an unauthenticated, un-pinned relay
    /// (`client.relay_identity = None`) instead of erroring, because the
    /// verifier never depended on `identity_public`/`signature` at all.
    #[test]
    fn stripping_identity_and_signature_fails_verification_even_with_anonymous_relay_allowed() {
        let mut relay = fixed_relay();
        let relay_identity = relay.identity_public;
        let mut client = fixed_client(Some(vec![relay_identity]), false, true); // allow_anonymous_relay = true

        let msg = client.create(11, None).unwrap();
        let create_cell = match msg {
            CreateMessage::Cell(c) => c,
            _ => unreachable!(),
        };
        let created_cell = relay.respond(&create_cell.pack(), None).unwrap();
        let mut body = CreatedBody::unpack(&created_cell.payload).unwrap();
        assert!(body.is_authenticated(), "the relay always signs; this reply must start out authenticated");

        // The attack: strip identity + signature, leaving every other
        // field -- crucially `verifier`, `public_key`, `ephemeral_public`
        // -- exactly as the relay sent them.
        body.identity_public = [0u8; IDENTITY_KEY_SIZE];
        body.signature = [0u8; SIGNATURE_SIZE];
        let mut tampered_payload = body.pack();
        tampered_payload.truncate(CREATED_BODY_SIZE);
        tampered_payload.extend_from_slice(&created_cell.payload[CREATED_BODY_SIZE..]); // real sealed nonce, untouched
        let tampered_cell = Cell::new(created_cell.circuit_id, Command::Created, tampered_payload).unwrap();

        let err = client.complete(&tampered_cell.pack(), Some(11)).unwrap_err();
        assert!(
            matches!(err, HandshakeError::Verification(_)),
            "expected a verifier mismatch, got {err:?} -- a silent Ok() here would mean the downgrade attack still works"
        );
    }

    #[test]
    fn untrusted_relay_identity_is_rejected() {
        let mut relay = fixed_relay();
        // Pin a trust set that does NOT include this relay's real identity.
        let some_other_identity = generate_identity_key();
        let other_public = identity_public_from_private(&some_other_identity);
        let mut client = fixed_client(Some(vec![other_public]), false, false);

        let msg = client.create(9, None).unwrap();
        let create_cell = match msg {
            CreateMessage::Cell(c) => c,
            _ => unreachable!(),
        };
        let created_cell = relay.respond(&create_cell.pack(), None).unwrap();
        let err = client.complete(&created_cell.pack(), Some(9)).unwrap_err();
        assert!(matches!(err, HandshakeError::RelayAuthentication(_)));
    }

    /// Build a genuinely anonymous CREATED reply: an X25519-only relay
    /// that never had an Ed25519 identity computes its verifier over the
    /// `[0u8; IDENTITY_KEY_SIZE]` placeholder *from the start*, the same
    /// way `HandshakeRelay::respond` computes it over a real identity --
    /// rather than (as the two tests below used to do, before this fix)
    /// taking an already-signed reply from a real
    /// relay and stripping its identity/signature after the fact, which is
    /// indistinguishable from the exact downgrade attack that fix closes.
    /// Manually replicates `HandshakeRelay::respond_parts`'s DH/verifier/
    /// seal steps (classical-only; no cookie, no hybrid) because
    /// `HandshakeRelay` itself always generates and uses a real identity
    /// key (see its own doc comments) -- there is no live "genuinely
    /// anonymous" relay code path to call into.
    fn respond_anonymously(create_payload: &[u8], circuit_id: u32) -> Cell {
        let body = CreateBody::unpack(create_payload).unwrap();
        let client_nonce = &create_payload[CREATE_NONCE_OFFSET..CREATE_NONCE_OFFSET + NONCE_SIZE];
        let client_public_key = PublicKey::from(body.public_key);

        let relay_private = StaticSecret::from(random_array::<32>());
        let relay_public = PublicKey::from(&relay_private).to_bytes();
        let ephemeral_private = StaticSecret::from(random_array::<32>());
        let ephemeral_public = PublicKey::from(&ephemeral_private).to_bytes();
        let shared_eph = ephemeral_private.diffie_hellman(&client_public_key);
        let shared_static = relay_private.diffie_hellman(&client_public_key);
        let mut shared_secret = shared_eph.to_bytes().to_vec();
        shared_secret.extend_from_slice(&shared_static.to_bytes());

        let salt = random_array::<SALT_SIZE>();
        let relay_nonce = random_array::<NONCE_SIZE>();
        let no_identity = [0u8; IDENTITY_KEY_SIZE];
        let verifier = compute_verifier(
            &shared_secret,
            &salt,
            circuit_id,
            &body.public_key,
            &relay_public,
            &ephemeral_public,
            client_nonce,
            &relay_nonce,
            DEFAULT_CIPHER,
            b"",
            &no_identity,
        );

        let hs_key = hkdf_expand(&shared_secret, b"allium-handshake-salt-pre-v1", HKDF_HS_KEY, KEY_SIZE);
        let mut aad = circuit_id.to_be_bytes().to_vec();
        aad.extend_from_slice(b"allium-handshake-nonce-v1");
        let mut aead = crypto::new_aead(DEFAULT_CIPHER, &hs_key, None).unwrap();
        let sealed_nonce = aead.seal(&relay_nonce, &aad).unwrap();

        let mut payload = CreatedBody {
            version: HANDSHAKE_VERSION,
            msg_type: MSG_CREATED,
            circuit_id,
            public_key: relay_public,
            ephemeral_public,
            salt,
            verifier,
            identity_public: no_identity,
            signature: [0u8; SIGNATURE_SIZE],
        }
        .pack();
        payload.extend_from_slice(&sealed_nonce);
        Cell::new(circuit_id, Command::Created, payload).unwrap()
    }

    #[test]
    fn anonymous_relay_reply_rejected_unless_explicitly_allowed() {
        let mut client = fixed_client(None, true, false); // allow_anonymous_relay = false

        let msg = client.create(11, None).unwrap();
        let create_cell = match msg {
            CreateMessage::Cell(c) => c,
            _ => unreachable!(),
        };
        let anon_cell = respond_anonymously(&create_cell.payload, 11);

        let err = client.complete(&anon_cell.pack(), Some(11)).unwrap_err();
        assert!(matches!(err, HandshakeError::RelayAuthentication(_)));
    }

    /// A client pinned to specific relay identities must never accept a
    /// relay that presents none: an anonymous relay can by definition not
    /// satisfy a pin. `allow_anonymous_relay` used to override that, so a
    /// man-in-the-middle answering with its own key and no identity was
    /// accepted by a client that had been told to talk only to relay X.
    #[test]
    fn anonymous_relay_is_refused_when_pins_are_configured_even_if_anonymous_relays_are_allowed() {
        let pinned_to = [7u8; IDENTITY_KEY_SIZE];
        let mut client = fixed_client(Some(vec![pinned_to]), false, true); // pinned AND allow_anonymous_relay = true

        let msg = client.create(21, None).unwrap();
        let create_cell = match msg {
            CreateMessage::Cell(c) => c,
            _ => unreachable!(),
        };
        // an impostor with its own key and no identity answers
        let anon_cell = respond_anonymously(&create_cell.payload, 21);

        let err = client.complete(&anon_cell.pack(), Some(21)).unwrap_err();
        assert!(matches!(err, HandshakeError::RelayAuthentication(_)), "expected a pin failure, got {err:?}");
        assert_eq!(client.relay_identity, None);
    }

    #[test]
    fn anonymous_relay_reply_accepted_when_allowed() {
        let mut client = fixed_client(None, true, true); // allow_anonymous_relay = true

        let msg = client.create(12, None).unwrap();
        let create_cell = match msg {
            CreateMessage::Cell(c) => c,
            _ => unreachable!(),
        };
        let anon_cell = respond_anonymously(&create_cell.payload, 12);

        let keys = client.complete(&anon_cell.pack(), Some(12)).unwrap();
        assert!(!keys.relay_is_authenticated());
        assert_eq!(client.relay_identity, None);
    }

    #[test]
    fn hybrid_create_fits_single_cell_and_completes_a_full_handshake() {
        // The relay must actually have a post-quantum key to encapsulate
        // to, and require_pq forces the client to build the hybrid path.
        let mut relay = fixed_relay();
        let kem_public = relay.rotate_kem_key(true);
        let relay_identity = relay.identity_public;

        let mut client =
            HandshakeClient::new(None, None, DEFAULT_TIMEOUT, Some(vec![relay_identity]), false, false, Some(kem_public), true).unwrap();

        let msg = client.create(13, None).unwrap();
        // Under the current cell size (MAX_PAYLOAD_SIZE = 1184) and
        // ML-KEM-768 ciphertext size, a hybrid body (~1162 bytes) fits in
        // one cell, exactly like the classical path -- see
        // HandshakeClient::create's size-based Cell/Fragmented choice.
        let create_cell = match msg {
            CreateMessage::Cell(c) => c,
            CreateMessage::Fragmented(_) => panic!("hybrid CREATE body fits one cell at the current KEM/cell sizes"),
        };
        assert_eq!(create_cell.command, Command::Create);

        let created_cell = relay.respond(&create_cell.pack(), None).unwrap();
        let keys = client.complete(&created_cell.pack(), Some(13)).unwrap();
        let relay_keys = relay.keys.clone().unwrap();

        assert_eq!(keys.aead_key_fwd, relay_keys.aead_key_fwd);
        assert_eq!(keys.aead_key_bwd, relay_keys.aead_key_bwd);
        assert_eq!(keys.mac_key, relay_keys.mac_key);
        assert_eq!(keys.verifier, relay_keys.verifier);
        assert!(keys.relay_is_authenticated());
        // The shared secret is three DH-ish terms concatenated (two X25519
        // + one ML-KEM); confirm it actually is longer than the classical
        // two-term case, i.e. the hybrid term was really mixed in.
        assert_eq!(keys.shared_secret.len(), 32 + 32 + crate::mlkem::SHARED_SECRET_SIZE);
    }

    #[test]
    fn hybrid_create_fragments_reassembles_and_completes_a_full_handshake_when_body_exceeds_one_cell() {
        use crate::createfrag::CreateReassembler;

        // Today's hybrid body fits one cell (see the test above), so this
        // exercises the CREATE_FRAGMENT + CreateReassembler pipeline the
        // way a future, larger KEM parameter set would actually need it:
        // take a real hybrid CREATE body and pad it past the single-cell
        // budget. CreateBody::unpack only reads up to HYBRID_CREATE_BODY_SIZE
        // and ignores anything past it, so the relay parses the padded body
        // identically to the unpadded one -- this isolates fragmentation and
        // reassembly from everything else, without faking the crypto.
        let mut relay = fixed_relay();
        let kem_public = relay.rotate_kem_key(true);
        let relay_identity = relay.identity_public;

        let mut client =
            HandshakeClient::new(None, None, DEFAULT_TIMEOUT, Some(vec![relay_identity]), false, false, Some(kem_public), true).unwrap();

        let msg = client.create(13, None).unwrap();
        let real_body = msg.payload().to_vec();
        assert!(real_body.len() <= MAX_PAYLOAD_SIZE, "sanity: today's real hybrid body fits one cell");

        let mut padded_body = real_body;
        padded_body.extend(std::iter::repeat(0u8).take(MAX_PAYLOAD_SIZE));
        assert!(padded_body.len() > MAX_PAYLOAD_SIZE, "padding must force fragmentation");

        let fragmented = HandshakeMessage { circuit_id: 13, command: Command::Create, payload: padded_body };
        let cells = fragmented.fragments().unwrap();
        assert!(cells.len() > 1, "the padded body must need more than one cell");
        for cell in &cells {
            assert_eq!(cell.command, Command::CreateFragment);
        }

        // The relay side: feed every CREATE_FRAGMENT cell to a reassembler,
        // exactly as a real relay would before it ever sees a whole CREATE.
        let mut reassembler = CreateReassembler::new(16, None);
        let mut reassembled = None;
        for cell in &cells {
            reassembled = reassembler.push(cell, ("10.0.0.9".to_string(), 4000));
        }
        let reassembled = reassembled.expect("every fragment delivered: reassembly must complete");
        assert_eq!(reassembled.circuit_id, 13);

        let created_cell = relay.respond_reassembled(&reassembled, None).unwrap();
        // client.complete() only consumes the CREATED reply and the
        // client's own pending state from create() -- it never re-reads
        // the (padded) CREATE body -- so completion is unaffected by the
        // padding used to force fragmentation above.
        let keys = client.complete(&created_cell.pack(), Some(13)).unwrap();
        let relay_keys = relay.keys.clone().unwrap();

        assert_eq!(keys.aead_key_fwd, relay_keys.aead_key_fwd);
        assert_eq!(keys.aead_key_bwd, relay_keys.aead_key_bwd);
        assert_eq!(keys.mac_key, relay_keys.mac_key);
        assert_eq!(keys.verifier, relay_keys.verifier);
        assert!(keys.relay_is_authenticated());
        assert_eq!(keys.shared_secret.len(), 32 + 32 + crate::mlkem::SHARED_SECRET_SIZE);
    }

    #[test]
    fn full_handshake_over_udp_sockets_end_to_end() {
        let relay_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay_sock.local_addr().unwrap();
        relay_sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut relay = fixed_relay();
        let relay_identity = relay.identity_public;

        let handle = thread::spawn(move || {
            let (_reply, _peer) = relay.serve_once(&relay_sock).unwrap().expect("relay answers CREATE");
            relay
        });

        let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut client = fixed_client(Some(vec![relay_identity]), false, false);
        let keys = client.handshake(&client_sock, relay_addr, 100, 0).unwrap();

        let mut relay = handle.join().unwrap();
        let relay_keys = relay.keys.take().unwrap();
        assert_eq!(keys.aead_key_fwd, relay_keys.aead_key_fwd);
        assert_eq!(keys.aead_key_bwd, relay_keys.aead_key_bwd);
        assert_eq!(keys.mac_key, relay_keys.mac_key);
        assert_eq!(keys.verifier, relay_keys.verifier);
        assert!(keys.relay_is_authenticated());
    }

    #[test]
    fn cookie_retry_flow_succeeds_over_udp_sockets() {
        let relay_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay_sock.local_addr().unwrap();
        relay_sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut relay =
            HandshakeRelay::new(None, None, false, None, false, true, None, DEFAULT_COOKIE_WINDOW_SECONDS).unwrap();
        let relay_identity = relay.identity_public;

        let handle = thread::spawn(move || {
            // First CREATE has no valid cookie -> CREATE_CHALLENGE.
            let (challenge, peer1) = relay.serve_once(&relay_sock).unwrap().expect("relay answers with a challenge");
            assert_eq!(challenge.command, Command::CreateChallenge);
            // Retried CREATE echoes the cookie -> CREATED.
            let (created, peer2) = relay.serve_once(&relay_sock).unwrap().expect("relay answers CREATE with cookie");
            assert_eq!(created.command, Command::Created);
            assert_eq!(peer1, peer2);
            relay
        });

        let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut client = fixed_client(Some(vec![relay_identity]), false, false);
        let keys = client.handshake(&client_sock, relay_addr, 200, 1).unwrap();

        let mut relay = handle.join().unwrap();
        let relay_keys = relay.keys.take().unwrap();
        assert_eq!(keys.aead_key_fwd, relay_keys.aead_key_fwd);
        assert_eq!(keys.aead_key_bwd, relay_keys.aead_key_bwd);
        assert_eq!(keys.verifier, relay_keys.verifier);
    }

    #[test]
    fn ephemeral_key_rotates_between_independent_circuits() {
        let mut client = fixed_client(None, true, false);
        let first = match client.create(1, None).unwrap() {
            CreateMessage::Cell(c) => c.payload,
            _ => unreachable!(),
        };
        // A different circuit id, no pending retry: the public key must change.
        let second = match client.create(2, None).unwrap() {
            CreateMessage::Cell(c) => c.payload,
            _ => unreachable!(),
        };
        let first_pub = &first[6..6 + PUBLIC_KEY_SIZE];
        let second_pub = &second[6..6 + PUBLIC_KEY_SIZE];
        assert_ne!(first_pub, second_pub);
    }

    #[test]
    fn ephemeral_key_is_stable_across_a_cookie_retry_of_the_same_circuit() {
        let mut client = fixed_client(None, true, false);
        let first = match client.create(3, None).unwrap() {
            CreateMessage::Cell(c) => c.payload,
            _ => unreachable!(),
        };
        // Same circuit id, simulating a cookie retry: the public key (and
        // nonce, since `_pending` is untouched) must stay the same.
        let retry = match client.create(3, Some([1u8; COOKIE_SIZE])).unwrap() {
            CreateMessage::Cell(c) => c.payload,
            _ => unreachable!(),
        };
        let first_pub = &first[6..6 + PUBLIC_KEY_SIZE];
        let retry_pub = &retry[6..6 + PUBLIC_KEY_SIZE];
        assert_eq!(first_pub, retry_pub);
    }
}

#[cfg(test)]
mod python_cross_check {
    use super::*;

    mod hex {
        pub fn encode(bytes: impl AsRef<[u8]>) -> String {
            bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
        }
    }

    // Ground truth generated by running the real Python `allium.handshake`
    // module (see the accompanying commands): every function exercised here
    // is a pure function of its arguments, so fixed inputs produce
    // reproducible output we can hardcode.

    #[test]
    fn compute_verifier_and_signing_payload_no_longer_match_vulnerable_python() {
        // Historical ground truth (before this fix) was generated by
        // running the real Python `allium.handshake` module:
        //
        // python3 -c "
        //   import allium.handshake as h
        //   shared_secret = bytes(range(32))*3
        //   salt = bytes([0xAA]*16)
        //   circuit_id = 0xDEADBEEF
        //   client_public = bytes([1]*32)
        //   relay_public = bytes([2]*32)
        //   relay_ephemeral_public = bytes([3]*32)
        //   client_nonce = bytes(range(12))
        //   relay_nonce = bytes(range(12,24))
        //   cipher = 'chacha20-poly1305'
        //   pq_binding = b''
        //   v = h.compute_verifier(shared_secret, salt, circuit_id, client_public,
        //       relay_public, relay_ephemeral_public, client_nonce, relay_nonce, cipher, pq_binding)
        //   sp = h.signing_payload(shared_secret, salt, circuit_id, client_public, relay_public,
        //       relay_ephemeral_public, client_nonce, relay_nonce, cipher, v, bytes([9]*32), pq_binding)
        //   keys = h.derive_handshake_keys(shared_secret, salt, circuit_id, cipher, relay_public, v, None, None)
        // "
        //
        // `compute_verifier`/`transcript` grew a `relay_identity_public`
        // parameter (see their doc comments) so the
        // verifier can no longer be satisfied after an on-path attacker
        // strips a `CREATED` reply's identity/signature to force an
        // anonymous-relay downgrade. The upstream Python `compute_verifier`
        // has this exact same gap (note its call above takes no identity
        // parameter at all) and was not available to patch from this Rust
        // port, so this Rust implementation now deliberately diverges from
        // it -- this test's hex constants below are regenerated from this
        // fixed Rust implementation itself (verified deterministic/stable
        // across runs), not from a live Python cross-check, and this test
        // is renamed accordingly. Interop with an unpatched Python peer (or
        // a Rust relay predating this fix) is intentionally broken by this
        // change; that is the point of the fix, not a bug in it.
        let mut shared_secret = Vec::new();
        for _ in 0..3 {
            shared_secret.extend((0u8..32).collect::<Vec<u8>>());
        }
        let salt = [0xAAu8; 16];
        let circuit_id: u32 = 0xDEADBEEF;
        let client_public = [1u8; 32];
        let relay_public = [2u8; 32];
        let relay_ephemeral_public = [3u8; 32];
        let client_nonce: Vec<u8> = (0u8..12).collect();
        let relay_nonce: Vec<u8> = (12u8..24).collect();
        let cipher = "chacha20-poly1305";
        let pq_binding: &[u8] = b"";
        let identity_public = [9u8; 32];

        let verifier = compute_verifier(
            &shared_secret,
            &salt,
            circuit_id,
            &client_public,
            &relay_public,
            &relay_ephemeral_public,
            &client_nonce,
            &relay_nonce,
            cipher,
            pq_binding,
            &identity_public,
        );
        assert_eq!(verifier.len(), 32);
        assert_eq!(hex::encode(verifier), "cecc5d909b41d33a3bbfd32400655919dcc5633c68a55dcfdef626e1b7e68d1f");

        let sp = signing_payload(
            &shared_secret,
            &salt,
            circuit_id,
            &client_public,
            &relay_public,
            &relay_ephemeral_public,
            &client_nonce,
            &relay_nonce,
            cipher,
            &verifier,
            &identity_public,
            pq_binding,
        );
        assert_eq!(sp.len(), 205 + 32);
        assert_eq!(
            hex::encode(&sp),
            "cecc5d909b41d33a3bbfd32400655919dcc5633c68a55dcfdef626e1b7e68d1f0909090909090909090909090909090909090909090909090909090909090909deadbeef010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303000102030405060708090a0b0c0d0e0f101112131415161763686163686132302d706f6c79313330350909090909090909090909090909090909090909090909090909090909090909"
        );

        let keys = derive_handshake_keys(
            &shared_secret,
            &salt,
            circuit_id,
            cipher,
            Some(relay_public),
            verifier.to_vec(),
            None,
            None,
            HandshakeRole::Client,
        );
        // Second divergence point in this same test: the single
        // `aead_key` HKDF label was split into
        // `aead_key_fwd`/`aead_key_bwd` (see `HKDF_AEAD_FWD`/`HKDF_AEAD_BWD`)
        // so a relay's forward and backward traffic never share an AEAD
        // key. The vulnerable Python reference above only ever derives one
        // `aead_key`, so these two hex constants have no Python
        // counterpart to cross-check against; they are this fixed Rust
        // implementation's own deterministic output.
        assert_eq!(hex::encode(&keys.aead_key_fwd), "a6cbdb87f30fe8642871333e58b4bf343f2335bd8b36a3721cd133628ce9ca4a");
        assert_eq!(hex::encode(&keys.aead_key_bwd), "8e18f9ed44837675ca7e9ec9e8753fe359505afc1ff83b8a68c2a27acda10ea3");
        assert_eq!(hex::encode(&keys.mac_key), "6a22600bebf42b6a8c207b18c0f809bf8d0de51b170f1ef69406687275ecf4fa");
    }

    #[test]
    fn create_body_wire_bytes_match_python() {
        // python3 -c "
        //   import struct, allium.handshake as h
        //   raw = struct.pack(h.CREATE_BODY_FORMAT, h.HANDSHAKE_VERSION, h.MSG_CREATE,
        //       0xAABBCCDD, bytes(range(32)), bytes(range(100,112)), bytes([7]*16))
        // "
        let public_key: [u8; 32] = {
            let mut a = [0u8; 32];
            for i in 0..32u8 {
                a[i as usize] = i;
            }
            a
        };
        let nonce: [u8; NONCE_SIZE] = {
            let mut a = [0u8; NONCE_SIZE];
            for i in 0..NONCE_SIZE {
                a[i] = 100 + i as u8;
            }
            a
        };
        let cookie = [7u8; COOKIE_SIZE];
        let raw = pack_create_body(HANDSHAKE_VERSION, MSG_CREATE, 0xAABBCCDD, &public_key, &nonce, &cookie);
        assert_eq!(raw.len(), CREATE_BODY_SIZE);
        assert_eq!(
            hex::encode(&raw),
            "0201aabbccdd000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f6465666768696a6b6c6d6e6f07070707070707070707070707070707"
        );

        let with_new_cookie = with_cookie(&raw, &[0xCCu8; COOKIE_SIZE]).unwrap();
        assert_eq!(
            hex::encode(&with_new_cookie),
            "0201aabbccdd000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f6465666768696a6b6c6d6e6fcccccccccccccccccccccccccccccccc"
        );
    }

    #[test]
    fn created_body_wire_bytes_match_python() {
        // python3 -c "
        //   import allium.handshake as h
        //   cb = h.CreatedBody(circuit_id=0x11223344, public_key=bytes([0x10]*32),
        //       ephemeral_public=bytes([0x20]*32), salt=bytes([0x30]*16),
        //       verifier=bytes([0x40]*32), identity_public=bytes([0x50]*32),
        //       signature=bytes([0x60]*64))
        // "
        let body = CreatedBody {
            version: HANDSHAKE_VERSION,
            msg_type: MSG_CREATED,
            circuit_id: 0x11223344,
            public_key: [0x10u8; 32],
            ephemeral_public: [0x20u8; 32],
            salt: [0x30u8; 16],
            verifier: [0x40u8; 32],
            identity_public: [0x50u8; 32],
            signature: [0x60u8; 64],
        };
        let packed = body.pack();
        assert_eq!(packed.len(), CREATED_BODY_SIZE);
        assert_eq!(
            hex::encode(&packed),
            "02021122334410101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030304040404040404040404040404040404040404040404040404040404040404040505050505050505050505050505050505050505050505050505050505050505060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060000000000000000000000000"
        );
    }

    #[test]
    fn challenge_body_wire_bytes_match_python() {
        // python3 -c "
        //   import allium.handshake as h
        //   chb = h.ChallengeBody(circuit_id=0x99887766, cookie=bytes([0xEE]*16))
        // "
        let body = ChallengeBody { version: HANDSHAKE_VERSION, msg_type: MSG_CHALLENGE, circuit_id: 0x99887766, cookie: [0xEEu8; COOKIE_SIZE] };
        let packed = body.pack();
        assert_eq!(packed.len(), CHALLENGE_BODY_SIZE);
        assert_eq!(hex::encode(&packed), "020399887766eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    }
}
