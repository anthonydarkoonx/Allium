//! X25519 (+ optional ML-KEM-768 hybrid) handshake for Allium circuits.
//!
//! Port of Python's `handshake.py`. See that module's docstring for the full
//! protocol rationale (forward secrecy via a combined ephemeral+static DH
//! secret, the verifier-as-key-confirmation design, and the post-quantum
//! hybrid mode). This port covers the module's cryptographic core -- the
//! HKDF key schedule, the `CREATE`/`CREATED`/`CREATE_CHALLENGE` wire codecs,
//! the transcript/verifier/signature functions, and identity-key generation
//! -- which has no dependency on the not-yet-ported `allium.onion` module.
//!
//! ## What is NOT ported here, and why
//!
//! Python's `HandshakeClient`/`HandshakeRelay` classes (the stateful,
//! blocking-socket handshake drivers) are **not** ported in this pass.
//! Both classes, and `HandshakeKeys.to_onion_crypto`/`to_layer`, depend on
//! `allium.onion.{OnionCrypto, Layer}` -- a Phase 3 module (`onion.py` is
//! listed *after* `handshake.py` in the intended dependency order, but
//! `handshake.py` itself `import`s from `.onion`, so that ordering cannot
//! be satisfied literally; porting a `HandshakeClient`/`HandshakeRelay`
//! faithfully means either fabricating `OnionCrypto`'s wire format ahead of
//! reading `onion.py` -- which risks getting it wrong and having to redo
//! this module -- or reading `onion.py` out of its stated order). Deferring
//! `HandshakeClient`/`HandshakeRelay`/`HandshakeKeys::to_onion_crypto`/
//! `HandshakeKeys::to_layer` to land alongside `onion.rs` (Phase 3) is the
//! smaller, more honest change; everything below is complete, tested, and
//! is exactly what those classes will be built on top of.
//! `circuit.rs` (also Phase 2 in name) has the same `onion.py` dependency
//! and is deferred for the same reason.
//!
//! ## Ed25519 (written but unverified pending real cargo build)
//!
//! [`verify_relay_signature`], [`generate_identity_key`], and
//! [`identity_public_from_private`] are the only functions here that touch
//! Ed25519 -- via the real `ed25519-dalek` crate (already added to
//! `allium/Cargo.toml` for `nat.rs`), carefully written against its
//! documented, stable 2.x API but unbuildable/untestable in this sandbox
//! (no crates.io access -- see the note atop `Cargo.toml`). Everything
//! else in this module -- the HKDF key schedule (built on
//! `hashutil::hkdf_sha256`, RFC 5869, per the dependency policy), the wire
//! codecs, and the transcript/verifier functions -- touches no external
//! crate and is fully tested here.

use crate::cell::{CELL_SIZE, Cell, Command};
use crate::createfrag::{CreateFragError, fragment_create};
use crate::crypto::{KEY_SIZE, NONCE_SIZE, SEAL_OVERHEAD, new_aead};
use crate::hashutil::{constant_time_eq, hkdf_sha256};
use crate::onion::{Layer, OnionCrypto};
use std::fmt;
use std::net::{SocketAddr, UdpSocket};

/// Protocol version carried in every handshake body.
pub const HANDSHAKE_VERSION: u8 = 2;
/// The post-quantum hybrid CREATE version.
pub const HANDSHAKE_VERSION_HYBRID: u8 = 3;
/// Which of the relay's (rotating) ML-KEM keys a hybrid CREATE encapsulated to.
pub const KEM_KEY_ID_SIZE: usize = 8;
/// X25519 public (and private) key length.
pub const PUBLIC_KEY_SIZE: usize = 32;
/// Salt length in the relay's response.
pub const SALT_SIZE: usize = 16;
/// Verifier length: one SHA-256-sized HKDF output.
pub const VERIFIER_SIZE: usize = 32;
/// Ed25519 identity public key length.
pub const IDENTITY_KEY_SIZE: usize = 32;
/// Ed25519 signature length.
pub const SIGNATURE_SIZE: usize = 64;

pub const MSG_CREATE: u8 = 1;
pub const MSG_CREATED: u8 = 2;
pub const MSG_CHALLENGE: u8 = 3;

pub const VERSION_SIZE: usize = 1;
pub const TYPE_SIZE: usize = 1;
pub const CIRCUIT_ID_SIZE: usize = 4;

/// Default socket timeout, in seconds.
pub const DEFAULT_TIMEOUT: f64 = 5.0;

/// Length, in bytes, of a return-routability cookie.
pub const COOKIE_SIZE: usize = 16;
/// How long a cookie remains acceptable, in seconds, once issued.
pub const DEFAULT_COOKIE_WINDOW_SECONDS: f64 = 300.0;

/// `version || type || circuit_id || client_pub || nonce || cookie`.
pub const CREATE_BODY_SIZE: usize = VERSION_SIZE + TYPE_SIZE + CIRCUIT_ID_SIZE + PUBLIC_KEY_SIZE + NONCE_SIZE + COOKIE_SIZE;

/// A version-3 (hybrid) CREATE body: the version-2 fields, then the key id
/// and the ML-KEM-768 ciphertext.
pub const HYBRID_CREATE_BODY_SIZE: usize = CREATE_BODY_SIZE + KEM_KEY_ID_SIZE + crate::mlkem::CIPHERTEXT_SIZE;

/// `version || type || circuit_id || relay_static_pub || relay_ephemeral_pub
/// || salt || verifier || identity || signature || nonce`.
pub const CREATED_BODY_SIZE: usize =
    VERSION_SIZE + TYPE_SIZE + CIRCUIT_ID_SIZE + PUBLIC_KEY_SIZE + PUBLIC_KEY_SIZE + SALT_SIZE + VERIFIER_SIZE + IDENTITY_KEY_SIZE + SIGNATURE_SIZE + NONCE_SIZE;

/// `version || type || circuit_id || cookie`.
pub const CHALLENGE_BODY_SIZE: usize = VERSION_SIZE + TYPE_SIZE + CIRCUIT_ID_SIZE + COOKIE_SIZE;
/// Where the return-routability cookie sits in a raw CREATE body, and so in the
/// first chunk of a fragmented one (chunk 0 is the start of the body).
pub const CREATE_COOKIE_OFFSET: usize = CREATE_BODY_SIZE - COOKIE_SIZE;

/// Largest handshake body that fits inside one cell payload.
///
/// This used to be an
/// independent hardcoded `504`, disconnected from `cell::PAYLOAD_SIZE`. If
/// the cell size were ever resized without also updating this literal, the
/// handshake code would keep validating CREATED messages against the old,
/// smaller size -- a silent circuit-setup correctness bug. It now follows
/// `cell::PAYLOAD_SIZE`, the single source of truth, the same pattern
/// `sizes.rs` already used correctly.
pub const MAX_HANDSHAKE_PAYLOAD: usize = crate::cell::PAYLOAD_SIZE;

// Split from one `HKDF_AEAD` label into
// direction-separated `_FWD`/`_BWD` ones -- see `onion::Layer`'s doc
// comment for the full rationale (a future switch to counter-based
// nonces could otherwise silently reuse a nonce across the two
// directions under one shared key). "Forward" = client-to-relay,
// "backward" = relay-to-client, matching this crate's existing
// `backward_token`/`relay_backward`/`next_backward_seq` naming.
const HKDF_AEAD_FWD: &[u8] = b"allium-aead-key-fwd-v1";
const HKDF_AEAD_BWD: &[u8] = b"allium-aead-key-bwd-v1";
const HKDF_MAC: &[u8] = b"allium-header-mac-v1";
const HKDF_HS_KEY: &[u8] = b"allium-handshake-key-v1";
const HKDF_HS_IV: &[u8] = b"allium-handshake-iv-v1";
const HKDF_VERIFY: &[u8] = b"allium-handshake-verify-v1";

/// The fixed body length implied by a CREATE payload's version byte.
pub fn create_body_size(payload: &[u8]) -> usize {
    if !payload.is_empty() && payload[0] == HANDSHAKE_VERSION_HYBRID {
        HYBRID_CREATE_BODY_SIZE
    } else {
        CREATE_BODY_SIZE
    }
}

// --------------------------------------------------------------------------
// HandshakeMessage
// --------------------------------------------------------------------------

/// `(circuit_id, command, payload)` -- a CREATE that doesn't fit in one
/// [`Cell`] (the hybrid one). [`HandshakeMessage::fragments`] gives the
/// 1192-byte cells that actually go on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeMessage {
    pub circuit_id: u32,
    pub command: Command,
    pub payload: Vec<u8>,
}

impl HandshakeMessage {
    pub fn new(circuit_id: u32, command: Command, payload: Vec<u8>) -> HandshakeMessage {
        HandshakeMessage { circuit_id, command, payload }
    }

    pub fn fragments(&self) -> Result<Vec<Cell>, CreateFragError> {
        fragment_create(self.circuit_id, &self.payload, None)
    }

    pub fn datagrams(&self) -> Result<Vec<Vec<u8>>, CreateFragError> {
        Ok(self.fragments()?.iter().map(|c| c.pack()).collect())
    }
}

// --------------------------------------------------------------------------
// Exceptions
// --------------------------------------------------------------------------

/// Base class for every handshake failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    Generic(String),
    Timeout(String),
    Rejected(String),
    Verification(String),
    RelayAuthentication(String),
}
impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::Generic(s)
            | HandshakeError::Timeout(s)
            | HandshakeError::Rejected(s)
            | HandshakeError::Verification(s)
            | HandshakeError::RelayAuthentication(s) => write!(f, "{s}"),
        }
    }
}
impl std::error::Error for HandshakeError {}
fn generic(msg: impl Into<String>) -> HandshakeError {
    HandshakeError::Generic(msg.into())
}
fn rejected(msg: impl Into<String>) -> HandshakeError {
    HandshakeError::Rejected(msg.into())
}

/// Raised when no reply arrives within the socket timeout.
pub type HandshakeTimeout = HandshakeError;
/// Raised when a peer replies with a well-formed but unusable message.
pub type HandshakeRejected = HandshakeError;
/// Raised when the peer's verifier does not match the locally computed one.
pub type VerificationError = HandshakeError;
/// Raised when a relay cannot prove it holds a pinned identity key.
pub type RelayAuthenticationError = HandshakeError;

// --------------------------------------------------------------------------
// Derived keys
// --------------------------------------------------------------------------

/// Expand `shared_secret` with HKDF-SHA256 under a domain-separated `info`.
fn hkdf(shared_secret: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    hkdf_sha256(shared_secret, salt, info, length)
}

/// The key material one hop's handshake produces.
///
/// `to_onion_crypto`/`to_layer` (Python) are deferred to Phase 3 alongside
/// `onion.rs` -- see the module docs.
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

#[derive(Clone, Debug)]
pub struct HandshakeKeys {
    pub shared_secret: Vec<u8>,
    pub salt: Vec<u8>,
    /// Was one shared `aead_key` used for
    /// both directions -- see `onion::Layer`'s doc comment. `_fwd` is the
    /// client-to-relay key, `_bwd` is relay-to-client.
    pub aead_key_fwd: [u8; KEY_SIZE],
    pub aead_key_bwd: [u8; KEY_SIZE],
    pub mac_key: [u8; KEY_SIZE],
    role: HandshakeRole,
    pub cipher: String,
    pub circuit_id: u32,
    pub relay_public: Option<Vec<u8>>,
    pub verifier: Vec<u8>,
    handshake_key: Vec<u8>,
    handshake_iv: Vec<u8>,
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
        self.handshake_key.zeroize();
        self.handshake_iv.zeroize();
    }
}

impl HandshakeKeys {
    /// `true` when this hop's relay identity was cryptographically verified.
    pub fn relay_is_authenticated(&self) -> bool {
        self.identity_public.is_some()
    }

    /// A stable 16-byte identifier for this session (both sides compute the
    /// same value; safe to use as a map key, since it is an HKDF expansion
    /// over the shared secret rather than the secret itself).
    pub fn session_id(&self) -> Vec<u8> {
        hkdf(&self.shared_secret, &self.salt, b"allium-session-id-v1", 16)
    }

    pub fn handshake_key(&self) -> &[u8] {
        &self.handshake_key
    }
    pub fn handshake_iv(&self) -> &[u8] {
        &self.handshake_iv
    }

    /// This side's own (seal, open) AEAD key pair, per `self.role` --
    /// see `onion::Layer`'s doc comment.
    fn directional_keys(&self) -> ([u8; KEY_SIZE], [u8; KEY_SIZE]) {
        match self.role {
            HandshakeRole::Client => (self.aead_key_fwd, self.aead_key_bwd),
            HandshakeRole::Relay => (self.aead_key_bwd, self.aead_key_fwd),
        }
    }

    /// Return an [`OnionCrypto`] bound to these keys, ready to seal or peel
    /// DATA layers.
    pub fn to_onion_crypto(&self, name: impl Into<String>, hop_index: usize) -> Result<OnionCrypto, HandshakeError> {
        let (seal_key, open_key) = self.directional_keys();
        OnionCrypto::new(name, seal_key, open_key, Some(self.mac_key), &self.cipher, hop_index, Vec::new())
            .map_err(|e| generic(e.to_string()))
    }

    /// Return a [`Layer`] for use with `wrap`/`seal_payload`.
    pub fn to_layer(&self, name: impl Into<String>) -> Result<Layer, HandshakeError> {
        let (seal_key, open_key) = self.directional_keys();
        Layer::from_keys(name, seal_key, open_key, self.mac_key, &self.cipher).map_err(|e| generic(e.to_string()))
    }
}

// --------------------------------------------------------------------------
// Body codecs
// --------------------------------------------------------------------------

/// The public part of a `CREATE` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateBody {
    pub version: u8,
    pub msg_type: u8,
    pub circuit_id: u32,
    pub public_key: [u8; PUBLIC_KEY_SIZE],
    pub cookie: [u8; COOKIE_SIZE],
    pub kem_key_id: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
}

impl CreateBody {
    pub fn new(circuit_id: u32, public_key: [u8; PUBLIC_KEY_SIZE], version: u8, msg_type: u8, cookie: Option<[u8; COOKIE_SIZE]>, kem_key_id: Vec<u8>, kem_ciphertext: Vec<u8>) -> CreateBody {
        CreateBody { version, msg_type, circuit_id, public_key, cookie: cookie.unwrap_or([0u8; COOKIE_SIZE]), kem_key_id, kem_ciphertext }
    }

    pub fn is_hybrid(&self) -> bool {
        self.version == HANDSHAKE_VERSION_HYBRID
    }

    /// `true` when this body carries a non-empty return-routability cookie.
    pub fn has_cookie(&self) -> bool {
        self.cookie != [0u8; COOKIE_SIZE]
    }

    /// Serialize the fixed body ([`CREATE_BODY_SIZE`] bytes). The nonce
    /// field is always written as all zeros -- the real client nonce is
    /// AEAD-sealed separately and travels alongside this fixed body, not
    /// inside it (see [`with_cookie`]'s docs for why).
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CREATE_BODY_SIZE);
        out.push(self.version);
        out.push(self.msg_type);
        out.extend_from_slice(&self.circuit_id.to_be_bytes());
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&[0u8; NONCE_SIZE]);
        out.extend_from_slice(&self.cookie);
        out
    }

    /// Parse a `CREATE` body, discarding the trailing nonce bytes.
    pub fn unpack(data: &[u8]) -> Result<CreateBody, HandshakeError> {
        if data.len() < CREATE_BODY_SIZE {
            return Err(rejected(format!("CREATE body needs {CREATE_BODY_SIZE} bytes, got {}", data.len())));
        }
        let version = data[0];
        let msg_type = data[1];
        let circuit_id = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        let mut public_key = [0u8; PUBLIC_KEY_SIZE];
        public_key.copy_from_slice(&data[6..6 + PUBLIC_KEY_SIZE]);
        let nonce_off = 6 + PUBLIC_KEY_SIZE;
        let cookie_off = nonce_off + NONCE_SIZE;
        let mut cookie = [0u8; COOKIE_SIZE];
        cookie.copy_from_slice(&data[cookie_off..cookie_off + COOKIE_SIZE]);

        if version == HANDSHAKE_VERSION_HYBRID {
            if data.len() < HYBRID_CREATE_BODY_SIZE {
                return Err(rejected(format!("hybrid CREATE body needs {HYBRID_CREATE_BODY_SIZE} bytes, got {}", data.len())));
            }
            let key_id = data[CREATE_BODY_SIZE..CREATE_BODY_SIZE + KEM_KEY_ID_SIZE].to_vec();
            let ciphertext = data[CREATE_BODY_SIZE + KEM_KEY_ID_SIZE..HYBRID_CREATE_BODY_SIZE].to_vec();
            return Ok(CreateBody::new(circuit_id, public_key, version, msg_type, Some(cookie), key_id, ciphertext));
        }
        if version != HANDSHAKE_VERSION {
            return Err(rejected(format!("unsupported handshake version {version}, expected {HANDSHAKE_VERSION} or {HANDSHAKE_VERSION_HYBRID}")));
        }
        Ok(CreateBody::new(circuit_id, public_key, version, msg_type, Some(cookie), Vec::new(), Vec::new()))
    }
}

/// Return `raw_create_body` with its fixed cookie field replaced by `cookie`.
///
/// Used to retry a `CREATE` after a [`ChallengeBody`] reply, without
/// disturbing anything else in the body -- notably the client's real nonce,
/// which [`CreateBody`] itself cannot round-trip ([`CreateBody::pack`]
/// always writes an all-zero nonce placeholder; only the raw bytes a client
/// actually sent carry the real one). Any bytes in `raw_create_body` past
/// [`CREATE_BODY_SIZE`] (such as a relay's EXTEND backward-authenticity
/// trailer) are preserved unchanged.
pub fn with_cookie(raw_create_body: &[u8], cookie: &[u8; COOKIE_SIZE]) -> Result<Vec<u8>, HandshakeError> {
    if raw_create_body.len() < CREATE_BODY_SIZE {
        return Err(generic(format!("raw_create_body must be at least {CREATE_BODY_SIZE} bytes, got {}", raw_create_body.len())));
    }
    let prefix_end = CREATE_BODY_SIZE - COOKIE_SIZE;
    let mut out = raw_create_body[..prefix_end].to_vec();
    out.extend_from_slice(cookie);
    out.extend_from_slice(&raw_create_body[CREATE_BODY_SIZE..]);
    Ok(out)
}

/// The public part of a `CREATED` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        circuit_id: u32,
        public_key: [u8; PUBLIC_KEY_SIZE],
        ephemeral_public: [u8; PUBLIC_KEY_SIZE],
        salt: [u8; SALT_SIZE],
        verifier: [u8; VERIFIER_SIZE],
        identity_public: Option<[u8; IDENTITY_KEY_SIZE]>,
        signature: Option<[u8; SIGNATURE_SIZE]>,
        version: u8,
        msg_type: u8,
    ) -> CreatedBody {
        CreatedBody {
            version,
            msg_type,
            circuit_id,
            public_key,
            ephemeral_public,
            salt,
            verifier,
            identity_public: identity_public.unwrap_or([0u8; IDENTITY_KEY_SIZE]),
            signature: signature.unwrap_or([0u8; SIGNATURE_SIZE]),
        }
    }

    /// `true` when the body actually carries a signature to check.
    pub fn is_authenticated(&self) -> bool {
        self.signature != [0u8; SIGNATURE_SIZE]
    }

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

    pub fn unpack(data: &[u8]) -> Result<CreatedBody, HandshakeError> {
        if data.len() < CREATED_BODY_SIZE {
            return Err(rejected(format!("CREATED body needs {CREATED_BODY_SIZE} bytes, got {}", data.len())));
        }
        let version = data[0];
        let msg_type = data[1];
        let circuit_id = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        let mut off = 6;
        let mut public_key = [0u8; PUBLIC_KEY_SIZE];
        public_key.copy_from_slice(&data[off..off + PUBLIC_KEY_SIZE]);
        off += PUBLIC_KEY_SIZE;
        let mut ephemeral_public = [0u8; PUBLIC_KEY_SIZE];
        ephemeral_public.copy_from_slice(&data[off..off + PUBLIC_KEY_SIZE]);
        off += PUBLIC_KEY_SIZE;
        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(&data[off..off + SALT_SIZE]);
        off += SALT_SIZE;
        let mut verifier = [0u8; VERIFIER_SIZE];
        verifier.copy_from_slice(&data[off..off + VERIFIER_SIZE]);
        off += VERIFIER_SIZE;
        let mut identity_public = [0u8; IDENTITY_KEY_SIZE];
        identity_public.copy_from_slice(&data[off..off + IDENTITY_KEY_SIZE]);
        off += IDENTITY_KEY_SIZE;
        let mut signature = [0u8; SIGNATURE_SIZE];
        signature.copy_from_slice(&data[off..off + SIGNATURE_SIZE]);

        if version != HANDSHAKE_VERSION {
            return Err(rejected(format!("unsupported handshake version {version}, expected {HANDSHAKE_VERSION}")));
        }
        Ok(CreatedBody::new(circuit_id, public_key, ephemeral_public, salt, verifier, Some(identity_public), Some(signature), version, msg_type))
    }
}

/// The entire `CREATE_CHALLENGE` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeBody {
    pub version: u8,
    pub msg_type: u8,
    pub circuit_id: u32,
    pub cookie: [u8; COOKIE_SIZE],
}

impl ChallengeBody {
    pub fn new(circuit_id: u32, cookie: [u8; COOKIE_SIZE], version: u8, msg_type: u8) -> ChallengeBody {
        ChallengeBody { version, msg_type, circuit_id, cookie }
    }

    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CHALLENGE_BODY_SIZE);
        out.push(self.version);
        out.push(self.msg_type);
        out.extend_from_slice(&self.circuit_id.to_be_bytes());
        out.extend_from_slice(&self.cookie);
        out
    }

    pub fn unpack(data: &[u8]) -> Result<ChallengeBody, HandshakeError> {
        if data.len() < CHALLENGE_BODY_SIZE {
            return Err(rejected(format!("CHALLENGE body needs {CHALLENGE_BODY_SIZE} bytes, got {}", data.len())));
        }
        let version = data[0];
        let msg_type = data[1];
        let circuit_id = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        let mut cookie = [0u8; COOKIE_SIZE];
        cookie.copy_from_slice(&data[6..6 + COOKIE_SIZE]);
        if version != HANDSHAKE_VERSION {
            return Err(rejected(format!("unsupported handshake version {version}, expected {HANDSHAKE_VERSION}")));
        }
        Ok(ChallengeBody::new(circuit_id, cookie, version, msg_type))
    }
}

// --------------------------------------------------------------------------
// Transcript and verifier
// --------------------------------------------------------------------------

/// Build the canonical byte string a handshake is bound to.
///
/// `relay_identity_public` was added because
/// this transcript used to omit the relay's identity entirely, so the
/// *verifier* (which only proves DH-secret agreement) passed regardless of
/// what `identity_public`/`signature` a `CREATED` reply carried. An on-path
/// attacker who intercepted a genuine, fully-signed `CREATED` reply could
/// zero out just its 96-byte `identity_public`/`signature` fields --
/// leaving `public_key`/`ephemeral_public`/`salt`/`verifier` untouched --
/// and the client's verifier check would still pass, silently downgrading
/// an authenticatable relay to "anonymous" for any client configured with
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
pub fn pq_binding(kem_key_id: &[u8], kem_ciphertext: &[u8]) -> Vec<u8> {
    let mut out = b"allium-pq-hybrid-mlkem768-v1".to_vec();
    out.extend_from_slice(kem_key_id);
    out.extend_from_slice(&crate::hashutil::sha256(kem_ciphertext));
    out
}

/// Derive the handshake verifier from the DH secret and the transcript.
///
/// `relay_identity_public` is passed
/// straight through to [`transcript`] -- see its doc comment for why the
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
    pq_binding_bytes: &[u8],
    relay_identity_public: &[u8],
) -> [u8; VERIFIER_SIZE] {
    let t = transcript(circuit_id, client_public, relay_public, relay_ephemeral_public, client_nonce, relay_nonce, cipher, pq_binding_bytes, relay_identity_public);
    let mut info = HKDF_VERIFY.to_vec();
    info.extend_from_slice(&t);
    let out = hkdf(shared_secret, salt, &info, VERIFIER_SIZE);
    let mut v = [0u8; VERIFIER_SIZE];
    v.copy_from_slice(&out);
    v
}

/// Build the byte string a relay signs with its Ed25519 identity key:
/// `verifier || identity_public || transcript` (`transcript` itself now
/// also folds in `identity_public` -- see its doc comment -- so it appears
/// twice here; harmless, and left as-is rather than restructured, to keep
/// this already-correct signing step's byte layout stable).
#[allow(clippy::too_many_arguments)]
pub fn signing_payload(circuit_id: u32, client_public: &[u8], relay_public: &[u8], relay_ephemeral_public: &[u8], client_nonce: &[u8], relay_nonce: &[u8], cipher: &str, verifier: &[u8], identity_public: &[u8], pq_binding_bytes: &[u8]) -> Vec<u8> {
    let mut out = verifier.to_vec();
    out.extend_from_slice(identity_public);
    out.extend_from_slice(&transcript(circuit_id, client_public, relay_public, relay_ephemeral_public, client_nonce, relay_nonce, cipher, pq_binding_bytes, identity_public));
    out
}

/// Verify a relay's Ed25519 signature over the handshake transcript.
///
/// Written but unverified pending real cargo build (see module docs): uses
/// the real `ed25519-dalek` crate, carefully reviewed against its
/// documented, stable 2.x `VerifyingKey`/`Verifier` API but unbuildable in
/// this sandbox.
#[allow(clippy::too_many_arguments)]
pub fn verify_relay_signature(
    signature: &[u8; SIGNATURE_SIZE],
    identity_public: &[u8; IDENTITY_KEY_SIZE],
    circuit_id: u32,
    client_public: &[u8],
    relay_public: &[u8],
    relay_ephemeral_public: &[u8],
    client_nonce: &[u8],
    relay_nonce: &[u8],
    cipher: &str,
    verifier: &[u8],
    pq_binding_bytes: &[u8],
) -> Result<(), HandshakeError> {
    let payload = signing_payload(circuit_id, client_public, relay_public, relay_ephemeral_public, client_nonce, relay_nonce, cipher, verifier, identity_public, pq_binding_bytes);
    use ed25519_dalek::{Signature, VerifyingKey};
    let key = VerifyingKey::from_bytes(identity_public)
        .map_err(|e| HandshakeError::RelayAuthentication(format!("malformed identity key: {e}")))?;
    let sig = Signature::from_bytes(signature);
    // `verify_strict`, not `verify`: also rejects non-canonical/malleable
    // signatures (small-order `R`, non-reduced `S`) that plain `verify`
    // accepts. Not currently exploitable here (this signature isn't
    // batched or used as a unique token), but this is a handshake identity
    // check, not a place to leave that malleability margin open.
    key.verify_strict(&payload, &sig).map_err(|_| {
        HandshakeError::RelayAuthentication(
            "relay signature did not verify against the presented identity key; the transcript, verifier, or identity key was altered".to_string(),
        )
    })
}

/// Expand a DH secret into the keys a hop uses.
///
/// `role` decides which of the two
/// derived AEAD keys this side seals with vs. opens with -- see
/// [`HandshakeRole`] and `onion::Layer`'s doc comment. Both sides derive
/// the *same* `aead_key_fwd`/`aead_key_bwd` values from the same shared
/// secret regardless of role; only `to_onion_crypto`/`to_layer`'s use of
/// them differs.
#[allow(clippy::too_many_arguments)]
pub fn derive_handshake_keys(
    shared_secret: Vec<u8>,
    salt: Vec<u8>,
    circuit_id: u32,
    cipher: String,
    relay_public: Option<Vec<u8>>,
    verifier: Vec<u8>,
    handshake_secret: Option<Vec<u8>>,
    identity_public: Option<[u8; IDENTITY_KEY_SIZE]>,
    role: HandshakeRole,
) -> HandshakeKeys {
    let hs_secret = handshake_secret.unwrap_or_else(|| shared_secret.clone());
    let aead_key_fwd_v = hkdf(&shared_secret, &salt, HKDF_AEAD_FWD, KEY_SIZE);
    let aead_key_bwd_v = hkdf(&shared_secret, &salt, HKDF_AEAD_BWD, KEY_SIZE);
    let mac_key_v = hkdf(&shared_secret, &salt, HKDF_MAC, KEY_SIZE);
    let mut aead_key_fwd = [0u8; KEY_SIZE];
    aead_key_fwd.copy_from_slice(&aead_key_fwd_v);
    let mut aead_key_bwd = [0u8; KEY_SIZE];
    aead_key_bwd.copy_from_slice(&aead_key_bwd_v);
    let mut mac_key = [0u8; KEY_SIZE];
    mac_key.copy_from_slice(&mac_key_v);
    HandshakeKeys {
        shared_secret,
        salt: salt.clone(),
        aead_key_fwd,
        aead_key_bwd,
        mac_key,
        role,
        cipher,
        circuit_id,
        relay_public,
        verifier,
        handshake_key: hkdf(&hs_secret, &salt, HKDF_HS_KEY, KEY_SIZE),
        handshake_iv: hkdf(&hs_secret, &salt, HKDF_HS_IV, NONCE_SIZE),
        identity_public,
    }
}

/// Normalise pinned identity keys (raw bytes or hex strings) to a set of
/// 32-byte values. `None` means "trust any well-formed signature" (a
/// test-only mode), matching Python's `_normalise_identities`.
pub fn normalise_identities(keys: Option<&[&str]>) -> Result<Option<Vec<[u8; IDENTITY_KEY_SIZE]>>, HandshakeError> {
    let keys = match keys {
        None => return Ok(None),
        Some(k) => k,
    };
    let mut out = Vec::new();
    for entry in keys {
        let bytes = hex_decode(entry).map_err(|e| generic(format!("malformed hex identity key: {e}")))?;
        if bytes.len() != IDENTITY_KEY_SIZE {
            return Err(generic(format!("identity key must be {IDENTITY_KEY_SIZE} bytes, got {}", bytes.len())));
        }
        let mut arr = [0u8; IDENTITY_KEY_SIZE];
        arr.copy_from_slice(&bytes);
        out.push(arr);
    }
    Ok(Some(out))
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex string".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Return a fresh 32-byte Ed25519 private key, for a relay to persist.
///
/// Written but unverified pending real cargo build (see module docs).
pub fn generate_identity_key() -> [u8; 32] {
    use ed25519_dalek::SigningKey;
    let mut seed = [0u8; 32];
    fill_random(&mut seed);
    // A `SigningKey`'s raw bytes constructor accepts any 32-byte seed (per
    // RFC 8032, any 32-byte string is a valid Ed25519 private key), so this
    // is only round-tripped to confirm shape, not to validate the seed --
    // matching Python's `Ed25519PrivateKey.generate().private_bytes_raw()`.
    let _ = SigningKey::from_bytes(&seed);
    seed
}

/// Return the Ed25519 public key for a 32-byte private key.
///
/// Written but unverified pending real cargo build (see module docs).
pub fn identity_public_from_private(private: &[u8; 32]) -> [u8; 32] {
    use ed25519_dalek::SigningKey;
    SigningKey::from_bytes(private).verifying_key().to_bytes()
}

// This used to hand-open /dev/urandom on
// Unix and, on any other target, fill `buf` with cycled `SystemTime`
// nanoseconds -- predictable, not a CSPRNG, and silently compiling with no
// warning. This backs handshake nonces/salts and the relay's own
// Ed25519/X25519 identity-key seeds (via
// `generate_identity_key`/`real_x25519_generate`'s callers), so a
// predictable value here is a full key-compromise bug, not just a weak
// nonce. Switched to `rand_core::OsRng` -- already a real dependency of
// this crate, and already used the same way by `real_x25519_generate`
// (below) and `crypto::random_nonce` -- which is a real CSPRNG on every
// platform `rand_core` supports, so there is no non-Unix fallback left to
// get wrong.
fn fill_random(buf: &mut [u8]) {
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(buf);
}

// --------------------------------------------------------------------------
// Injected X25519 + Ed25519 primitives (same pattern as nat::Ed25519Ops)
// --------------------------------------------------------------------------

pub type X25519GenFn = Box<dyn Fn() -> [u8; PUBLIC_KEY_SIZE] + Send>;
pub type X25519PublicFn = Box<dyn Fn(&[u8; PUBLIC_KEY_SIZE]) -> [u8; PUBLIC_KEY_SIZE] + Send>;
pub type X25519DhFn = Box<dyn Fn(&[u8; PUBLIC_KEY_SIZE], &[u8; PUBLIC_KEY_SIZE]) -> Result<[u8; PUBLIC_KEY_SIZE], HandshakeError> + Send>;
pub type Ed25519SignFn = Box<dyn Fn(&[u8; IDENTITY_KEY_SIZE], &[u8]) -> [u8; SIGNATURE_SIZE] + Send>;
pub type Ed25519VerifyFn = Box<dyn Fn(&[u8; IDENTITY_KEY_SIZE], &[u8], &[u8; SIGNATURE_SIZE]) -> bool + Send>;
pub type Ed25519PublicFn = Box<dyn Fn(&[u8; IDENTITY_KEY_SIZE]) -> [u8; IDENTITY_KEY_SIZE] + Send>;

/// Every X25519/Ed25519 primitive [`HandshakeClient`]/[`HandshakeRelay`]
/// need, injected as closures -- the same dependency-injection pattern as
/// `nat::Ed25519Ops`, extended here to X25519 too, since with the stateful
/// classes now in scope there is finally a state machine for it to buy
/// testability for (see the module docs' "Injection pattern" note, written
/// before these classes existed). Construct with [`HandshakeOps::real`] for
/// production use (real-crate-backed, unverified in this sandbox); tests use
/// a deterministic fake so the whole client/relay handshake state machine
/// runs end-to-end without a real X25519/Ed25519 implementation.
pub struct HandshakeOps {
    pub x25519_generate: X25519GenFn,
    pub x25519_public: X25519PublicFn,
    pub x25519_dh: X25519DhFn,
    pub ed25519_sign: Ed25519SignFn,
    pub ed25519_verify: Ed25519VerifyFn,
    /// Derives the Ed25519 identity public key from its private key.
    ///
    /// Must agree with whatever key space `ed25519_sign`/`ed25519_verify`
    /// actually operate in: a relay's `identity_public` (what it publishes
    /// and what it signs `CREATED` bodies with under) has to be *this*
    /// function's output, not some other derivation, or a correctly-signed
    /// message will never verify against the public key the peer was
    /// handed. [`HandshakeOps::real`] uses the real
    /// [`identity_public_from_private`]; a test/fake `HandshakeOps` must
    /// supply a matching fake derivation consistent with its own fake
    /// `ed25519_sign`/`ed25519_verify` (see the test-only
    /// `fake_handshake_ops` below for why: before this field existed,
    /// `HandshakeRelay::new` always called the *real* function here
    /// regardless of which ops were injected, so a relay built with fake
    /// sign/verify ops still published a real-crate-derived
    /// `identity_public` that its own fake signatures could never match --
    /// harmless under this crate's crypto-stub sandbox pass, which stubbed
    /// this free function out too, but a guaranteed
    /// `RelayAuthentication` failure against the real `ed25519-dalek`
    /// crate on every handshake that used the test fakes).
    pub ed25519_public: Ed25519PublicFn,
}

impl HandshakeOps {
    /// Real, `x25519-dalek`/`ed25519-dalek`-backed implementation.
    ///
    /// Written but unverified pending real cargo build (see module docs):
    /// this sandbox cannot fetch either crate, so this cannot be
    /// compiled/tested here, but was carefully reviewed against their
    /// documented, stable 2.x APIs (`StaticSecret`/`PublicKey`/
    /// `diffie_hellman`/`SharedSecret::was_contributory` for X25519;
    /// `SigningKey`/`VerifyingKey`/`Signer`/`Verifier` for Ed25519 -- the
    /// same API [`verify_relay_signature`] already uses).
    pub fn real() -> HandshakeOps {
        HandshakeOps {
            x25519_generate: Box::new(real_x25519_generate),
            x25519_public: Box::new(real_x25519_public),
            x25519_dh: Box::new(real_x25519_dh),
            ed25519_sign: Box::new(real_ed25519_sign),
            ed25519_verify: Box::new(real_ed25519_verify),
            ed25519_public: Box::new(identity_public_from_private),
        }
    }
}

fn real_x25519_generate() -> [u8; PUBLIC_KEY_SIZE] {
    use x25519_dalek::StaticSecret;
    StaticSecret::random_from_rng(rand_core::OsRng).to_bytes()
}
fn real_x25519_public(private: &[u8; PUBLIC_KEY_SIZE]) -> [u8; PUBLIC_KEY_SIZE] {
    use x25519_dalek::{PublicKey, StaticSecret};
    PublicKey::from(&StaticSecret::from(*private)).to_bytes()
}
fn real_x25519_dh(private: &[u8; PUBLIC_KEY_SIZE], peer_public: &[u8; PUBLIC_KEY_SIZE]) -> Result<[u8; PUBLIC_KEY_SIZE], HandshakeError> {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(*private);
    let shared = secret.diffie_hellman(&PublicKey::from(*peer_public));
    if !shared.was_contributory() {
        return Err(HandshakeError::Verification("peer public key is unusable (low-order point)".to_string()));
    }
    Ok(*shared.as_bytes())
}
fn real_ed25519_sign(private: &[u8; IDENTITY_KEY_SIZE], message: &[u8]) -> [u8; SIGNATURE_SIZE] {
    use ed25519_dalek::{Signer, SigningKey};
    SigningKey::from_bytes(private).sign(message).to_bytes()
}
fn real_ed25519_verify(public: &[u8; IDENTITY_KEY_SIZE], message: &[u8], sig: &[u8; SIGNATURE_SIZE]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let key = match VerifyingKey::from_bytes(public) {
        Ok(k) => k,
        Err(_) => return false,
    };
    // `verify_strict`, not `verify` -- see the other call site's comment.
    key.verify_strict(message, &Signature::from_bytes(sig)).is_ok()
}

fn random_nonce() -> [u8; NONCE_SIZE] {
    let mut n = [0u8; NONCE_SIZE];
    fill_random(&mut n);
    n
}
fn random_salt() -> [u8; SALT_SIZE] {
    let mut s = [0u8; SALT_SIZE];
    fill_random(&mut s);
    s
}
/// Seconds since this process's first call -- only ever used for
/// differences (rotation ages, TTLs), same as Python's `time.monotonic()`.
fn monotonic_now() -> f64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_secs_f64()
}
fn now_unix_seconds() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs_f64()
}

/// Pack a raw `CREATE` fixed body carrying the *real* client nonce --
/// deliberately not [`CreateBody::pack`], which always writes an all-zero
/// nonce placeholder (see that method's docs): building an actual `CREATE`
/// to send needs the real nonce in the wire bytes.
fn pack_create_body_raw(version: u8, msg_type: u8, circuit_id: u32, public_key: &[u8; PUBLIC_KEY_SIZE], nonce: &[u8; NONCE_SIZE], cookie: &[u8; COOKIE_SIZE]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CREATE_BODY_SIZE);
    out.push(version);
    out.push(msg_type);
    out.extend_from_slice(&circuit_id.to_be_bytes());
    out.extend_from_slice(public_key);
    out.extend_from_slice(nonce);
    out.extend_from_slice(cookie);
    out
}

/// Offset of the client nonce within a packed `CREATE` fixed body.
const CREATE_NONCE_OFFSET: usize = CREATE_BODY_SIZE - COOKIE_SIZE - NONCE_SIZE;

/// Accept a raw datagram and parse it as a [`Cell`].
///
/// Deviation from Python: `_coerce_cell` there also accepts an
/// already-constructed `Cell` object (duck typing); every caller here
/// instead takes `&[u8]` directly (a test builds one with `cell.pack()`),
/// since Rust needs one concrete parameter type. Functionally identical.
fn coerce_cell(message: &[u8]) -> Result<Cell, HandshakeError> {
    Cell::from_bytes(message, true).map_err(|e| rejected(format!("unparseable datagram: {e}")))
}

// --------------------------------------------------------------------------
// Client
// --------------------------------------------------------------------------

/// Read datagrams from `sock` until one arrives from `expected_addr`, or
/// `timeout` elapses.
///
/// See Python's `_recv_from` docs:
/// accepting only a datagram whose source matches `expected_addr` closes off
/// a single-spoofed-packet denial-of-service against a handshake in flight.
fn recv_from(sock: &UdpSocket, expected_addr: SocketAddr, timeout: f64, size: usize) -> std::io::Result<Vec<u8>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs_f64(timeout.max(0.0));
    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out waiting for a reply from the expected source"));
        }
        sock.set_read_timeout(Some(deadline - now))?;
        let mut buf = vec![0u8; size];
        let (n, addr) = sock.recv_from(&mut buf)?;
        if addr != expected_addr {
            continue;
        }
        buf.truncate(n);
        return Ok(buf);
    }
}

/// What [`HandshakeClient::create`] returns: a classical `CREATE` is one
/// plain [`Cell`]; a hybrid one is several `CREATE_FRAGMENT` cells (see
/// Python's `create`, which returns a bare `Cell` or a `HandshakeMessage`
/// depending on `hybrid`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateMessage {
    Single(Cell),
    Fragmented(HandshakeMessage),
}

impl CreateMessage {
    pub fn circuit_id(&self) -> u32 {
        match self {
            CreateMessage::Single(c) => c.circuit_id,
            CreateMessage::Fragmented(m) => m.circuit_id,
        }
    }

    /// Every datagram this message needs on the wire.
    pub fn datagrams(&self) -> Result<Vec<Vec<u8>>, CreateFragError> {
        match self {
            CreateMessage::Single(c) => Ok(vec![c.pack()]),
            CreateMessage::Fragmented(m) => m.datagrams(),
        }
    }

    /// The raw CREATE body bytes, regardless of variant -- what
    /// `circuit::CircuitBuilder::extend` sends through an EXTEND layer
    /// instead of over the wire directly (Python's `create_cell.payload`
    /// works the same way across its `Cell | HandshakeMessage` return).
    pub fn payload(&self) -> &[u8] {
        match self {
            CreateMessage::Single(c) => &c.payload,
            CreateMessage::Fragmented(m) => &m.payload,
        }
    }
}

/// Client side of the X25519 (+ optional ML-KEM-768 hybrid) handshake.
///
/// Port of Python's `HandshakeClient`. Pinning is mandatory: [`HandshakeClient::new`]
/// returns a [`HandshakeError`] unless `trusted_identities` is given or
/// `trust_first_use` is explicitly set.
pub struct HandshakeClient {
    pub cipher: String,
    private: [u8; PUBLIC_KEY_SIZE],
    pub public_key: [u8; PUBLIC_KEY_SIZE],
    timeout: f64,
    /// `(circuit_id, client_nonce, kem_shared, pq_binding, private_key)`.
    pending: Option<(u32, [u8; NONCE_SIZE], Vec<u8>, Vec<u8>, [u8; PUBLIC_KEY_SIZE])>,
    key_used: bool,
    trusted_identities: Option<Vec<[u8; IDENTITY_KEY_SIZE]>>,
    pub trust_first_use: bool,
    pub allow_anonymous_relay: bool,
    pub relay_identity: Option<[u8; IDENTITY_KEY_SIZE]>,
    pub keys: Option<HandshakeKeys>,
    kem_public: Option<Vec<u8>>,
    require_pq: bool,
    ops: HandshakeOps,
}

impl Drop for HandshakeClient {
    /// Security audit fix (2026-09-26): `private` is this circuit's ephemeral
    /// X25519 private key, held until the circuit is torn down. `pending`'s
    /// private key and ML-KEM shared secret are the same kind of live key
    /// material, stashed mid-handshake -- covers the case where this
    /// `HandshakeClient` is dropped with an abandoned, never-completed
    /// handshake still pending (a completed one already had both wiped
    /// explicitly in `complete()` itself, right after each field's last
    /// use, since this struct-level `Drop` only protects what's still
    /// resident at *this* moment, not material already discarded earlier
    /// during ordinary use).
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.private.zeroize();
        if let Some((_, _, pending_kem_shared, _, pending_private)) = self.pending.as_mut() {
            pending_kem_shared.zeroize();
            pending_private.zeroize();
        }
    }
}

impl HandshakeClient {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cipher: String,
        static_private: Option<[u8; PUBLIC_KEY_SIZE]>,
        timeout: f64,
        trusted_identities: Option<Vec<[u8; IDENTITY_KEY_SIZE]>>,
        trust_first_use: bool,
        allow_anonymous_relay: bool,
        kem_public: Option<Vec<u8>>,
        require_pq: bool,
        ops: HandshakeOps,
    ) -> Result<HandshakeClient, HandshakeError> {
        if trusted_identities.is_none() && !trust_first_use {
            return Err(generic(
                "HandshakeClient requires pinned relay identities (trusted_identities=[...]) or an explicit trust_first_use=true opt-out. Leaving both unset used to silently trust any relay presenting a valid signature; that is no longer the default. Pass trust_first_use=true only if this really is a test or a throwaway local circuit.",
            ));
        }
        if let Some(kp) = &kem_public {
            if kp.len() != crate::mlkem::ENCAPSULATION_KEY_SIZE {
                return Err(generic(format!("kem_public must be {} bytes, got {}", crate::mlkem::ENCAPSULATION_KEY_SIZE, kp.len())));
            }
        }
        if require_pq && kem_public.is_none() {
            return Err(generic("require_pq is set but no kem_public was provided; refusing to build a client that could only ever fall back to a classical-only handshake"));
        }
        let private = static_private.unwrap_or_else(|| (ops.x25519_generate)());
        let public_key = (ops.x25519_public)(&private);
        Ok(HandshakeClient {
            cipher,
            private,
            public_key,
            timeout,
            pending: None,
            key_used: false,
            trusted_identities,
            trust_first_use,
            allow_anonymous_relay,
            relay_identity: None,
            keys: None,
            kem_public,
            require_pq,
            ops,
        })
    }

    // -- message construction -----------------------------------------------

    /// Build the `CREATE` message carrying this client's public key. Rotates
    /// the ephemeral key per circuit (see Python's `create` docs on why).
    pub fn create(&mut self, circuit_id: u32, cookie: Option<&[u8; COOKIE_SIZE]>) -> Result<CreateMessage, HandshakeError> {
        let cookie_bytes = cookie.copied().unwrap_or([0u8; COOKIE_SIZE]);
        let client_nonce = random_nonce();
        let hybrid = self.kem_public.is_some();
        if self.require_pq && !hybrid {
            return Err(generic("require_pq is set but no kem_public was provided; refusing to fall back to a classical-only handshake"));
        }

        let private = if let Some(p) = &self.pending {
            if p.0 == circuit_id { p.4 } else { (self.ops.x25519_generate)() }
        } else if self.key_used {
            (self.ops.x25519_generate)()
        } else {
            self.private
        };
        self.key_used = true;
        self.private = private;
        self.public_key = (self.ops.x25519_public)(&private);

        let mut body_bytes = pack_create_body_raw(
            if hybrid { HANDSHAKE_VERSION_HYBRID } else { HANDSHAKE_VERSION },
            MSG_CREATE,
            circuit_id,
            &self.public_key,
            &client_nonce,
            &cookie_bytes,
        );
        let mut kem_shared = Vec::new();
        let mut binding = Vec::new();
        if hybrid {
            let kem_public = self.kem_public.as_ref().unwrap();
            let (ciphertext, shared) = crate::mlkem::encapsulate(kem_public, None).map_err(|e| generic(format!("relay ML-KEM key is unusable: {e}")))?;
            let key_id = crate::mlkem::key_id(kem_public);
            body_bytes.extend_from_slice(&key_id);
            body_bytes.extend_from_slice(&ciphertext);
            binding = pq_binding(&key_id, &ciphertext);
            kem_shared = shared;
        }
        // Security audit fix (2026-09-26): this assignment used to just
        // overwrite `self.pending` outright -- if `create()` is ever
        // called again before a prior handshake's `complete()` (e.g. a
        // caller retrying the same circuit after a timeout), the
        // superseded pending tuple's own `kem_shared`/`private` were
        // dropped un-zeroized right here, the same gap as `complete()`'s
        // own `self.pending = None` had before its fix.
        if let Some((_, _, mut old_kem_shared, _, mut old_private)) = self.pending.take() {
            use zeroize::Zeroize;
            old_kem_shared.zeroize();
            old_private.zeroize();
        }
        self.pending = Some((circuit_id, client_nonce, kem_shared, binding, private));
        if hybrid {
            Ok(CreateMessage::Fragmented(HandshakeMessage::new(circuit_id, Command::Create, body_bytes)))
        } else {
            Ok(CreateMessage::Single(Cell::with_command(circuit_id, Command::Create, body_bytes).map_err(|e| generic(e.to_string()))?))
        }
    }

    /// The packed classical `CREATE` datagram. Errors on a hybrid CREATE
    /// (several datagrams) -- use [`HandshakeClient::create_datagrams`].
    pub fn create_bytes(&mut self, circuit_id: u32, cookie: Option<&[u8; COOKIE_SIZE]>) -> Result<Vec<u8>, HandshakeError> {
        match self.create(circuit_id, cookie)? {
            CreateMessage::Single(cell) => Ok(cell.pack()),
            CreateMessage::Fragmented(_) => Err(generic("create_bytes: classical only; a hybrid CREATE is several datagrams -- use create_datagrams")),
        }
    }

    /// Every datagram of this client's `CREATE`.
    pub fn create_datagrams(&mut self, circuit_id: u32, cookie: Option<&[u8; COOKIE_SIZE]>) -> Result<Vec<Vec<u8>>, HandshakeError> {
        let message = self.create(circuit_id, cookie)?;
        message.datagrams().map_err(|e| generic(e.to_string()))
    }

    /// Extract the cookie from a `CREATE_CHALLENGE` reply.
    pub fn parse_challenge(&self, message: &[u8], circuit_id: Option<u32>) -> Result<[u8; COOKIE_SIZE], HandshakeError> {
        let cell = coerce_cell(message)?;
        if let Some(cid) = circuit_id {
            if cell.circuit_id != cid {
                return Err(rejected(format!("circuit id mismatch: expected {cid}, got {}", cell.circuit_id)));
            }
        }
        if cell.command != Command::CreateChallenge {
            return Err(rejected(format!("expected a CREATE_CHALLENGE cell, got {}", cell.command.name())));
        }
        let body = ChallengeBody::unpack(&cell.payload)?;
        if body.circuit_id != cell.circuit_id {
            return Err(rejected(format!("body circuit id {} does not match {}", body.circuit_id, cell.circuit_id)));
        }
        Ok(body.cookie)
    }

    // -- message processing --------------------------------------------------

    /// Verify the relay's `CREATED` reply and derive the shared keys.
    pub fn complete(&mut self, message: &[u8], circuit_id: Option<u32>) -> Result<HandshakeKeys, HandshakeError> {
        let circuit_id = match (circuit_id, &self.pending) {
            (Some(c), _) => c,
            (None, Some(p)) => p.0,
            (None, None) => return Err(generic("no pending handshake; call create() first or pass circuit_id")),
        };
        // Security audit fix (2026-09-26): this used to `.clone()` the
        // pending tuple and leave `self.pending` for the caller's later
        // `self.pending = None` to drop -- on every exit path (success or
        // error) that dropped `kem_shared`/`private` (this circuit's own
        // ephemeral key, separate from `self.private`) un-zeroized,
        // regardless of `HandshakeClient`'s own `Drop` impl, since that
        // only ever protects whatever is still resident *at final struct
        // drop*, not material discarded earlier during ordinary use.
        // `.take()` on a guard-matched borrow moves the original out
        // (clearing `self.pending` to `None` immediately, same as the
        // unmatched branch leaving it untouched for a retry), so this
        // function now owns the only copy and can zeroize it explicitly
        // right after each field's last use below, on every exit path.
        let pending = match &self.pending {
            Some(p) if p.0 == circuit_id => self.pending.take().expect("just matched Some above"),
            _ => {
                return Err(generic(format!(
                    "no pending handshake for circuit {circuit_id:#010x}: call create(circuit_id) on this client first, and use the same circuit id for both calls."
                )));
            }
        };
        let (_, client_nonce, kem_shared, pq_binding_bytes, private) = pending;
        // Security audit fix (2026-09-26, follow-up): an earlier version of
        // this fix zeroized `private`/`kem_shared` at one specific point
        // (right before their last use), reasoning that covered "every
        // exit path from there on" -- but there are several early-return
        // validation checks (`coerce_cell`, cell circuit-id/command,
        // `CreatedBody::unpack`, body type/circuit-id) *between* binding
        // these and that point, each of which would skip the zeroize
        // entirely on a malformed/wrong-circuit-id reply from a remote
        // peer. `Zeroizing<T>` wipes on drop regardless of *which* exit
        // path fires -- including ones added later without anyone
        // re-auditing where the manual zeroize call was -- so it doesn't
        // depend on this function's control flow staying the way it looked
        // when the zeroize point was chosen.
        let kem_shared = zeroize::Zeroizing::new(kem_shared);
        let private = zeroize::Zeroizing::new(private);
        let client_public = (self.ops.x25519_public)(&private);

        let cell = coerce_cell(message)?;
        if cell.circuit_id != circuit_id {
            return Err(rejected(format!("circuit id mismatch: expected {circuit_id}, got {}", cell.circuit_id)));
        }
        if cell.command != Command::Created {
            return Err(rejected(format!("expected a CREATED cell, got {}", cell.command.name())));
        }

        let body = CreatedBody::unpack(&cell.payload)?;
        if body.msg_type != MSG_CREATED {
            return Err(rejected(format!("expected message type {MSG_CREATED}, got {}", body.msg_type)));
        }
        if body.circuit_id != circuit_id {
            return Err(rejected(format!("body circuit id {} does not match {circuit_id}", body.circuit_id)));
        }

        let dh_ephemeral = (self.ops.x25519_dh)(&private, &body.ephemeral_public)
            .map_err(|e| HandshakeError::Verification(format!("relay public key is unusable (low-order point): {e}")))?;
        let dh_static = (self.ops.x25519_dh)(&private, &body.public_key)
            .map_err(|e| HandshakeError::Verification(format!("relay public key is unusable (low-order point): {e}")))?;
        let mut shared_secret = Vec::with_capacity(64 + kem_shared.len());
        shared_secret.extend_from_slice(&dh_ephemeral);
        shared_secret.extend_from_slice(&dh_static);
        shared_secret.extend_from_slice(&kem_shared);

        let relay_nonce = self.open_relay_nonce(&cell.payload, &shared_secret, circuit_id)?;

        let expected = compute_verifier(&shared_secret, &body.salt, circuit_id, &client_public, &body.public_key, &body.ephemeral_public, &client_nonce, &relay_nonce, &self.cipher, &pq_binding_bytes, &body.identity_public);
        if !constant_time_eq(&expected, &body.verifier) {
            return Err(HandshakeError::Verification(
                "handshake verifier mismatch: the peer does not hold the private keys for the public keys it sent (possible man-in-the-middle), or the handshake was tampered with".to_string(),
            ));
        }

        self.authenticate_relay(&body, circuit_id, &client_nonce, &relay_nonce, &pq_binding_bytes, &client_public)?;

        let keys = derive_handshake_keys(shared_secret, body.salt.to_vec(), circuit_id, self.cipher.clone(), Some(body.public_key.to_vec()), body.verifier.to_vec(), None, self.relay_identity, HandshakeRole::Client);
        self.keys = Some(keys.clone());
        // `self.pending` is already `None` -- the `.take()` above moved it
        // out at the start of this call.
        Ok(keys)
    }

    #[allow(clippy::too_many_arguments)]
    fn authenticate_relay(&mut self, body: &CreatedBody, circuit_id: u32, client_nonce: &[u8], relay_nonce: &[u8], pq_binding_bytes: &[u8], client_public: &[u8; PUBLIC_KEY_SIZE]) -> Result<(), HandshakeError> {
        if !body.is_authenticated() {
            // An anonymous relay can never satisfy a pin, so with pins
            // configured it is refused outright -- `allow_anonymous_relay`
            // is only honoured when there is nothing to pin against.
            // (Honouring it here let an impostor with its own key and no
            // identity bypass a client told to talk only to specific relays.)
            if let Some(trusted) = &self.trusted_identities {
                return Err(HandshakeError::RelayAuthentication(format!(
                    "relay presented no identity, but this client is pinned to {} identity key(s); an anonymous relay can never satisfy a pin, so it is refused even with allow_anonymous_relay=true",
                    trusted.len()
                )));
            }
            if self.allow_anonymous_relay {
                self.relay_identity = None;
                return Ok(());
            }
            return Err(HandshakeError::RelayAuthentication(
                "relay presented no identity signature; refusing an unauthenticated relay (pass allow_anonymous_relay=true only to interoperate with a legacy peer during migration)".to_string(),
            ));
        }

        let payload = signing_payload(circuit_id, client_public, &body.public_key, &body.ephemeral_public, client_nonce, relay_nonce, &self.cipher, &body.verifier, &body.identity_public, pq_binding_bytes);
        if !(self.ops.ed25519_verify)(&body.identity_public, &payload, &body.signature) {
            return Err(HandshakeError::RelayAuthentication(
                "relay signature did not verify against the presented identity key; the transcript, verifier, or identity key was altered".to_string(),
            ));
        }
        if let Some(trusted) = &self.trusted_identities {
            if !trusted.contains(&body.identity_public) {
                return Err(HandshakeError::RelayAuthentication(format!(
                    "relay identity is not in the pinned trust set of {} key(s); an impostor presenting its own valid keypair lands here",
                    trusted.len()
                )));
            }
        }
        self.relay_identity = Some(body.identity_public);
        Ok(())
    }

    /// Unseal the relay's nonce from the tail of the `CREATED` payload.
    fn open_relay_nonce(&self, payload: &[u8], shared_secret: &[u8], circuit_id: u32) -> Result<[u8; NONCE_SIZE], HandshakeError> {
        let sealed = &payload[CREATED_BODY_SIZE..];
        if sealed.len() < SEAL_OVERHEAD {
            return Err(HandshakeError::Verification("CREATED payload is missing the sealed relay nonce".to_string()));
        }
        let hs_key_v = hkdf(shared_secret, b"allium-handshake-salt-pre-v1", HKDF_HS_KEY, KEY_SIZE);
        let mut hs_key = [0u8; KEY_SIZE];
        hs_key.copy_from_slice(&hs_key_v);
        let mut aad = circuit_id.to_be_bytes().to_vec();
        aad.extend_from_slice(b"allium-handshake-nonce-v1");
        let aead = new_aead(&self.cipher, hs_key, None)
            .map_err(|e| HandshakeError::Verification(format!("could not open the relay nonce: {e}")))?;
        let nonce = aead.open(sealed, &aad).map_err(|e| {
            HandshakeError::Verification(format!("could not open the relay nonce: the CREATED cell was not produced by a peer holding the matching private key ({e})"))
        })?;
        if nonce.len() != NONCE_SIZE {
            return Err(HandshakeError::Verification(format!("relay nonce must be {NONCE_SIZE} bytes, got {}", nonce.len())));
        }
        let mut out = [0u8; NONCE_SIZE];
        out.copy_from_slice(&nonce);
        Ok(out)
    }

    // -- socket convenience ---------------------------------------------------

    /// Run the full handshake over a UDP socket and return the shared keys.
    pub fn handshake(&mut self, sock: &UdpSocket, relay_addr: SocketAddr, circuit_id: u32, max_cookie_retries: u32) -> Result<HandshakeKeys, HandshakeError> {
        let mut cookie: Option<[u8; COOKIE_SIZE]> = None;
        let attempts = max_cookie_retries + 1;
        for attempt in 1..=attempts {
            let message = self.create(circuit_id, cookie.as_ref())?;
            for datagram in message.datagrams().map_err(|e| generic(e.to_string()))? {
                sock.send_to(&datagram, relay_addr).map_err(|e| generic(format!("send failed: {e}")))?;
            }
            let datagram = recv_from(sock, relay_addr, self.timeout, CELL_SIZE)
                .map_err(|_| HandshakeError::Timeout(format!("no reply from {relay_addr} within {}s", self.timeout)))?;

            let reply_cell = coerce_cell(&datagram)?;
            if reply_cell.command == Command::CreateChallenge {
                if attempt == attempts {
                    return Err(HandshakeError::Timeout(format!(
                        "{relay_addr} kept issuing return-routability challenges past {attempts} attempt(s); giving up"
                    )));
                }
                cookie = Some(self.parse_challenge(&datagram, Some(circuit_id))?);
                continue;
            }
            return self.complete(&datagram, Some(circuit_id));
        }
        unreachable!("loop always returns or errors on its last iteration")
    }
}

// --------------------------------------------------------------------------
// Relay
// --------------------------------------------------------------------------

/// What a relay does with the first fragment of a fragmented CREATE, decided
/// without keeping any state (see [`HandshakeRelay::admit_first_fragment`]).
#[derive(Debug)]
pub enum FirstFragmentVerdict {
    /// The cookie is valid for this sender: start (or continue) a reassembly entry.
    Admit,
    /// No valid cookie: answer with this `CREATE_CHALLENGE` and store nothing.
    Challenge(Cell),
    /// Unusable (too short to hold a cookie, or the sender's address is unknown): drop it.
    Drop,
}

/// Derive a return-routability cookie: HMAC-SHA256, truncated to
/// [`COOKIE_SIZE`]. A pure function of its inputs, so [`HandshakeRelay`]
/// needs no per-issued-cookie state (see Python's `_cookie_for` docs).
fn cookie_for(secret: &[u8], source_ip: &str, window: i64) -> [u8; COOKIE_SIZE] {
    let mut msg = source_ip.as_bytes().to_vec();
    msg.extend_from_slice(&window.to_be_bytes());
    let mac = crate::hashutil::hmac_sha256(secret, &msg);
    let mut out = [0u8; COOKIE_SIZE];
    out.copy_from_slice(&mac[..COOKIE_SIZE]);
    out
}

/// Relay side of the X25519 (+ optional ML-KEM-768 hybrid) handshake.
///
/// Holds a long-term X25519 private key and answers `CREATE` cells with
/// `CREATED`. Keeps no per-circuit state between messages (see Python's
/// `HandshakeRelay` docs).
pub struct HandshakeRelay {
    private: [u8; PUBLIC_KEY_SIZE],
    pub public_key: [u8; PUBLIC_KEY_SIZE],
    pub cipher: String,
    respond_to_bad_requests: bool,
    identity_private: [u8; IDENTITY_KEY_SIZE],
    pub identity_public: [u8; IDENTITY_KEY_SIZE],
    pub require_identity: bool,
    pub keys: Option<HandshakeKeys>,
    require_return_routability: bool,
    cookie_secret: Vec<u8>,
    cookie_window_seconds: f64,
    /// `key_id -> (decapsulation_key, created_monotonic)`.
    kem_keys: std::collections::HashMap<[u8; KEM_KEY_ID_SIZE], (Vec<u8>, f64)>,
    pub kem_public: Option<Vec<u8>>,
    kem_created_at: f64,
    ops: HandshakeOps,
}

impl Drop for HandshakeRelay {
    /// Security audit fix (2026-09-26): `private`/`identity_private` are
    /// this relay's own long-term X25519/Ed25519 private keys, held for
    /// the entire process lifetime -- the highest-value target in this
    /// crate for a memory-disclosure bug elsewhere in the process.
    /// `kem_keys` additionally retains rotated-out ML-KEM decapsulation
    /// keys for `KEM_KEY_RETENTION` (~75 minutes) after rotation, so those
    /// are wiped too. `cookie_secret` is lower-value (a rotated anti-DoS
    /// MAC pepper, not a real key) but cheap to include.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.private.zeroize();
        self.identity_private.zeroize();
        self.cookie_secret.zeroize();
        for (decap_key, _created_at) in self.kem_keys.values_mut() {
            decap_key.zeroize();
        }
    }
}

impl HandshakeRelay {
    /// How long a relay keeps accepting a rotated-out ML-KEM key.
    pub const KEM_KEY_RETENTION: f64 = 3600.0 + 900.0;
    /// Never rotate more often than this.
    pub const KEM_MIN_ROTATION: f64 = 600.0;
    const KEM_MAX_KEYS: usize = 16;

    /// This relay's own Ed25519 identity private key -- needed by a caller
    /// that signs something on the relay's behalf outside the handshake
    /// itself, e.g. [`crate::directory::RelayDescriptor::create`] when
    /// publishing this relay's descriptor to a directory authority. Kept
    /// private everywhere else in this module (every *handshake* signature
    /// already goes through [`HandshakeOps::ed25519_sign`] internally, so
    /// nothing here needs to read it back out) -- this accessor exists
    /// solely for that one external use.
    pub fn identity_private_key(&self) -> &[u8; IDENTITY_KEY_SIZE] {
        &self.identity_private
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        static_private: Option<[u8; PUBLIC_KEY_SIZE]>,
        cipher: String,
        respond_to_bad_requests: bool,
        identity_private: Option<[u8; IDENTITY_KEY_SIZE]>,
        require_identity: bool,
        require_return_routability: bool,
        cookie_secret: Option<Vec<u8>>,
        cookie_window_seconds: f64,
        ops: HandshakeOps,
    ) -> Result<HandshakeRelay, HandshakeError> {
        if cookie_window_seconds <= 0.0 {
            return Err(generic(format!("cookie_window_seconds must be positive, got {cookie_window_seconds}")));
        }
        let private = static_private.unwrap_or_else(|| (ops.x25519_generate)());
        let public_key = (ops.x25519_public)(&private);
        // A relay with no identity key generates one, so the handshake still
        // works; `require_identity` only matters for whether its *absence*
        // is fatal -- which, since one is always generated here, never
        // triggers (matching Python's own always-generates-one behaviour).
        let identity_private = identity_private.unwrap_or_else(generate_identity_key);
        // Must go through `ops.ed25519_public`, not the free
        // `identity_public_from_private` function directly: the published
        // identity key has to live in the same key space `ops.ed25519_sign`/
        // `ops.ed25519_verify` actually sign/verify in (see `Ed25519PublicFn`'s
        // docs on `HandshakeOps` for why this matters).
        let identity_public = (ops.ed25519_public)(&identity_private);
        let cookie_secret = cookie_secret.unwrap_or_else(|| {
            let mut s = vec![0u8; 32];
            fill_random(&mut s);
            s
        });
        Ok(HandshakeRelay {
            private,
            public_key,
            cipher,
            respond_to_bad_requests,
            identity_private,
            identity_public,
            require_identity,
            keys: None,
            require_return_routability,
            cookie_secret,
            cookie_window_seconds,
            kem_keys: std::collections::HashMap::new(),
            kem_public: None,
            kem_created_at: 0.0,
            ops,
        })
    }

    // -- post-quantum key management ------------------------------------------

    /// Generate a fresh ML-KEM-768 keypair and make it the advertised one.
    pub fn rotate_kem_key(&mut self, force: bool) -> Result<Vec<u8>, HandshakeError> {
        let now = monotonic_now();
        if !force {
            if let Some(kp) = &self.kem_public {
                if now - self.kem_created_at < Self::KEM_MIN_ROTATION {
                    return Ok(kp.clone());
                }
            }
        }
        let (ek, dk) = crate::mlkem::generate_keypair().map_err(|e| generic(e.to_string()))?;
        let kid = crate::mlkem::key_id(&ek);
        self.kem_keys.insert(kid, (dk, now));
        self.kem_public = Some(ek.clone());
        self.kem_created_at = now;
        self.prune_kem_keys(now);
        Ok(ek)
    }

    /// Security audit fix (2026-09-26): every `.remove()` below used to
    /// just drop the evicted `(decap_key, created_at)` pair -- a live
    /// ML-KEM decapsulation key, un-zeroized, same gap as the struct-level
    /// `Drop for HandshakeRelay` impl (which only protects keys still
    /// resident in `kem_keys` at final struct drop, not ones already
    /// pruned during ordinary key rotation over a long-running process's
    /// life). Zeroize each evicted key explicitly instead of letting it
    /// drop bare.
    fn prune_kem_keys(&mut self, now: f64) {
        use zeroize::Zeroize;
        let current = self.kem_public.as_ref().map(|ek| crate::mlkem::key_id(ek));
        let stale: Vec<[u8; KEM_KEY_ID_SIZE]> = self
            .kem_keys
            .iter()
            .filter(|(kid, (_, created))| Some(**kid) != current && now - created > Self::KEM_KEY_RETENTION)
            .map(|(kid, _)| *kid)
            .collect();
        for kid in stale {
            if let Some((mut decap_key, _)) = self.kem_keys.remove(&kid) {
                decap_key.zeroize();
            }
        }
        while self.kem_keys.len() > Self::KEM_MAX_KEYS {
            match self.kem_keys.keys().find(|k| Some(**k) != current).copied() {
                Some(k) => {
                    if let Some((mut decap_key, _)) = self.kem_keys.remove(&k) {
                        decap_key.zeroize();
                    }
                }
                None => break,
            }
        }
    }

    // -- return-routability cookie --------------------------------------------

    fn verify_cookie(&self, cookie: &[u8; COOKIE_SIZE], source_ip: &str) -> bool {
        let now_window = (now_unix_seconds() / self.cookie_window_seconds).floor() as i64;
        for window in [now_window, now_window - 1] {
            if constant_time_eq(&cookie_for(&self.cookie_secret, source_ip, window), cookie) {
                return true;
            }
        }
        false
    }

    fn issue_challenge(&self, circuit_id: u32, source_ip: &str) -> Cell {
        let window = (now_unix_seconds() / self.cookie_window_seconds).floor() as i64;
        let cookie = cookie_for(&self.cookie_secret, source_ip, window);
        let body = ChallengeBody::new(circuit_id, cookie, HANDSHAKE_VERSION, MSG_CHALLENGE);
        Cell::with_command(circuit_id, Command::CreateChallenge, body.pack()).expect("a CHALLENGE body always fits in one cell")
    }

    /// Whether this relay demands a valid return-routability cookie before it
    /// will answer a CREATE.
    pub fn requires_return_routability(&self) -> bool {
        self.require_return_routability
    }

    /// Check the cookie in the first chunk of a fragmented CREATE, **before**
    /// anything is stored for it.
    ///
    /// The cookie is a keyed hash of the sender's IP address and a time window,
    /// so it can be checked with no per-sender state, and it sits at a fixed
    /// place in the first chunk ([`CREATE_COOKIE_OFFSET`]). Without this check a
    /// flood of first fragments from forged addresses each took a slot in the
    /// reassembly table, because the cookie used to be checked only once a
    /// CREATE had been fully reassembled. Now a sender that has not proved it
    /// can receive packets at its address gets a challenge and no table entry.
    ///
    /// `Admit` when the relay does not require cookies at all. The full CREATE
    /// still has its cookie checked again after reassembly.
    pub fn admit_first_fragment(&self, first_chunk: &[u8], circuit_id: u32, peer_addr: Option<SocketAddr>) -> FirstFragmentVerdict {
        if !self.require_return_routability {
            return FirstFragmentVerdict::Admit;
        }
        let Some(addr) = peer_addr else { return FirstFragmentVerdict::Drop };
        if first_chunk.len() < CREATE_BODY_SIZE {
            return FirstFragmentVerdict::Drop;
        }
        let source_ip = addr.ip().to_string();
        let mut cookie = [0u8; COOKIE_SIZE];
        cookie.copy_from_slice(&first_chunk[CREATE_COOKIE_OFFSET..CREATE_COOKIE_OFFSET + COOKIE_SIZE]);
        if cookie != [0u8; COOKIE_SIZE] && self.verify_cookie(&cookie, &source_ip) {
            return FirstFragmentVerdict::Admit;
        }
        FirstFragmentVerdict::Challenge(self.issue_challenge(circuit_id, &source_ip))
    }

    // -- message processing ----------------------------------------------------

    /// Answer a `CREATE` cell with a `CREATED` cell (or, when
    /// `require_return_routability` is set and no valid cookie was
    /// presented, a cheap `CREATE_CHALLENGE`).
    pub fn respond(&mut self, message: &[u8], peer_addr: Option<SocketAddr>) -> Result<Cell, HandshakeError> {
        let cell = coerce_cell(message)?;
        self.respond_message(cell.circuit_id, cell.command, &cell.payload, peer_addr)
    }

    /// Same as [`HandshakeRelay::respond`], but for a hybrid `CREATE`
    /// reassembled from several `CREATE_FRAGMENT` cells
    /// ([`crate::createfrag::CreateReassembler`]) rather than one bare
    /// [`Cell`] -- its payload (over 1KB for a hybrid body) does not fit
    /// [`Cell`]'s 1184-byte cap. Deviation from Python: `_coerce_cell` there
    /// duck-types a `Cell` or a reassembled message interchangeably; Rust
    /// needs two concrete entry points instead, both delegating to the same
    /// [`HandshakeRelay::respond_message`] core.
    pub fn respond_reassembled(&mut self, message: &crate::createfrag::CreateMessage, peer_addr: Option<SocketAddr>) -> Result<Cell, HandshakeError> {
        self.respond_message(message.circuit_id, message.command, &message.payload, peer_addr)
    }

    fn respond_message(&mut self, circuit_id: u32, command: Command, raw_payload: &[u8], peer_addr: Option<SocketAddr>) -> Result<Cell, HandshakeError> {
        if command != Command::Create {
            return Err(rejected(format!("expected a CREATE cell, got {}", command.name())));
        }
        let body = CreateBody::unpack(raw_payload)?;
        if body.msg_type != MSG_CREATE {
            return Err(rejected(format!("expected message type {MSG_CREATE}, got {}", body.msg_type)));
        }
        if body.circuit_id != circuit_id {
            return Err(rejected(format!("body circuit id {} disagrees with the cell header ({circuit_id})", body.circuit_id)));
        }
        if raw_payload.len() < CREATE_NONCE_OFFSET + NONCE_SIZE {
            return Err(rejected("CREATE payload too short to carry a client nonce"));
        }
        let mut client_nonce = [0u8; NONCE_SIZE];
        client_nonce.copy_from_slice(&raw_payload[CREATE_NONCE_OFFSET..CREATE_NONCE_OFFSET + NONCE_SIZE]);
        let cell_circuit_id = circuit_id;

        if self.require_return_routability {
            let addr = peer_addr.ok_or_else(|| rejected("require_return_routability is set but no peer_addr was supplied; the cookie cannot be checked without the sender's address"))?;
            let source_ip = addr.ip().to_string();
            if !body.has_cookie() || !self.verify_cookie(&body.cookie, &source_ip) {
                return Ok(self.issue_challenge(cell_circuit_id, &source_ip));
            }
        }

        let mut kem_shared: Vec<u8> = Vec::new();
        let mut pq_binding_bytes: Vec<u8> = Vec::new();
        if body.is_hybrid() {
            let key_id: [u8; KEM_KEY_ID_SIZE] = body.kem_key_id[..].try_into().map_err(|_| rejected("malformed ML-KEM key id"))?;
            let entry = self.kem_keys.get(&key_id).cloned().ok_or_else(|| rejected("hybrid CREATE names an unknown ML-KEM key"))?;
            kem_shared = crate::mlkem::decapsulate(&entry.0, &body.kem_ciphertext).map_err(|e| rejected(format!("bad ML-KEM ciphertext: {e}")))?;
            pq_binding_bytes = pq_binding(&key_id, &body.kem_ciphertext);
        }

        let ephemeral_private = (self.ops.x25519_generate)();
        let ephemeral_public = (self.ops.x25519_public)(&ephemeral_private);
        let dh_ephemeral = (self.ops.x25519_dh)(&ephemeral_private, &body.public_key)
            .map_err(|e| rejected(format!("client public key is unusable (low-order point): {e}")))?;
        let dh_static = (self.ops.x25519_dh)(&self.private, &body.public_key)
            .map_err(|e| rejected(format!("client public key is unusable (low-order point): {e}")))?;
        let mut shared_secret = Vec::with_capacity(64 + kem_shared.len());
        shared_secret.extend_from_slice(&dh_ephemeral);
        shared_secret.extend_from_slice(&dh_static);
        shared_secret.extend_from_slice(&kem_shared);

        let salt = random_salt();
        let relay_nonce = random_nonce();
        let verifier = compute_verifier(&shared_secret, &salt, cell_circuit_id, &body.public_key, &self.public_key, &ephemeral_public, &client_nonce, &relay_nonce, &self.cipher, &pq_binding_bytes, &self.identity_public);

        let hs_key_v = hkdf(&shared_secret, b"allium-handshake-salt-pre-v1", HKDF_HS_KEY, KEY_SIZE);
        let mut hs_key = [0u8; KEY_SIZE];
        hs_key.copy_from_slice(&hs_key_v);
        let mut aad = cell_circuit_id.to_be_bytes().to_vec();
        aad.extend_from_slice(b"allium-handshake-nonce-v1");
        let mut aead = new_aead(&self.cipher, hs_key, None).map_err(|e| generic(e.to_string()))?;
        let sealed_nonce = aead.seal(&relay_nonce, &aad).map_err(|e| generic(e.to_string()))?;

        // `self.identity_private` is always set (see `new`'s docs), so this
        // relay always signs; the `require_identity` flag is kept for API
        // parity with Python (which guards against a `None` identity key
        // that, here, can never occur) but has nothing left to gate.
        let payload = signing_payload(cell_circuit_id, &body.public_key, &self.public_key, &ephemeral_public, &client_nonce, &relay_nonce, &self.cipher, &verifier, &self.identity_public, &pq_binding_bytes);
        let signature = (self.ops.ed25519_sign)(&self.identity_private, &payload);

        let created_body = CreatedBody::new(cell_circuit_id, self.public_key, ephemeral_public, salt, verifier, Some(self.identity_public), Some(signature), HANDSHAKE_VERSION, MSG_CREATED).pack();
        let mut payload = created_body;
        payload.extend_from_slice(&sealed_nonce);
        if payload.len() > MAX_HANDSHAKE_PAYLOAD {
            return Err(rejected(format!("CREATED payload is {} bytes, exceeding the {MAX_HANDSHAKE_PAYLOAD}-byte cell payload", payload.len())));
        }

        let keys = derive_handshake_keys(shared_secret, salt.to_vec(), cell_circuit_id, self.cipher.clone(), Some(self.public_key.to_vec()), verifier.to_vec(), None, Some(self.identity_public), HandshakeRole::Relay);
        self.keys = Some(keys);
        Cell::with_command(cell_circuit_id, Command::Created, payload).map_err(|e| generic(e.to_string()))
    }

    // -- socket convenience ---------------------------------------------------

    /// Build a `DESTROY` cell for an unusable `CREATE`.
    pub fn reject_cell(&self, circuit_id: u32) -> Cell {
        Cell::with_command(circuit_id, Command::Destroy, Vec::new()).expect("an empty DESTROY body always fits in one cell")
    }

    /// Receive one datagram, answer it, and return `(reply, peer)`. Never
    /// raises on malformed input; returns `Ok(None)` instead.
    pub fn serve_once(&mut self, sock: &UdpSocket) -> std::io::Result<Option<(Cell, SocketAddr)>> {
        let mut buf = vec![0u8; CELL_SIZE];
        let (n, peer) = sock.recv_from(&mut buf)?;
        buf.truncate(n);
        let reply = match self.respond(&buf, Some(peer)) {
            Ok(r) => r,
            Err(_) => {
                if self.respond_to_bad_requests {
                    let circuit_id = Cell::from_bytes(&buf, true).map(|c| c.circuit_id).unwrap_or(0);
                    self.reject_cell(circuit_id)
                } else {
                    return Ok(None);
                }
            }
        };
        sock.send_to(&reply.pack(), peer)?;
        Ok(Some((reply, peer)))
    }

    /// Answer `CREATE` cells until `max_requests` have been handled (or
    /// forever, when `None`). Returns the number of `CREATED` cells sent.
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
                Err(_) => break,
            }
        }
        handled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    // -- fake HandshakeOps, same recording pattern as nat::recording_fake_ops --

    thread_local! {
        static X25519_REGISTRY: RefCell<HashMap<[u8; PUBLIC_KEY_SIZE], [u8; PUBLIC_KEY_SIZE]>> = RefCell::new(HashMap::new());
        static FAKE_ED_SIGS: RefCell<HashMap<(Vec<u8>, Vec<u8>), [u8; SIGNATURE_SIZE]>> = RefCell::new(HashMap::new());
    }

    fn clear_fake_registries() {
        X25519_REGISTRY.with(|r| r.borrow_mut().clear());
        FAKE_ED_SIGS.with(|r| r.borrow_mut().clear());
    }

    /// A deterministic, insecure X25519+Ed25519 stand-in: `x25519_public`
    /// registers `pub -> priv` so `x25519_dh` can look up the peer's private
    /// half and produce a *symmetric* shared secret (an HMAC of the two
    /// private keys, sorted) -- the same DH property a real implementation
    /// guarantees. `ed25519_sign`/`ed25519_verify` mirror
    /// `nat::recording_fake_ops`: sign registers `(public, message) -> sig`,
    /// verify looks it up. Never use this for anything but tests.
    fn fake_handshake_ops() -> HandshakeOps {
        HandshakeOps {
            x25519_generate: Box::new(|| {
                let mut private = [0u8; PUBLIC_KEY_SIZE];
                fill_random(&mut private);
                private
            }),
            x25519_public: Box::new(|private| {
                let public = crate::hashutil::hmac_sha256(b"x25519-pub-fake", private);
                X25519_REGISTRY.with(|r| r.borrow_mut().insert(public, *private));
                public
            }),
            x25519_dh: Box::new(|private, peer_public| {
                if *peer_public == [0u8; PUBLIC_KEY_SIZE] {
                    return Err(HandshakeError::Verification("peer public key is unusable (low-order point)".to_string()));
                }
                let peer_private = X25519_REGISTRY.with(|r| r.borrow().get(peer_public).copied());
                let mut parts: Vec<Vec<u8>> = vec![private.to_vec(), peer_private.map(|p| p.to_vec()).unwrap_or_else(|| peer_public.to_vec())];
                parts.sort();
                let mut msg = Vec::new();
                for p in &parts {
                    msg.extend_from_slice(p);
                }
                Ok(crate::hashutil::hmac_sha256(b"x25519-dh-fake", &msg))
            }),
            ed25519_sign: Box::new(|private, message| {
                let public = crate::hashutil::hmac_sha256(b"ed25519-pub-fake", private);
                let mac1 = crate::hashutil::hmac_sha256(private, message);
                let mac2 = crate::hashutil::hmac_sha256(private, &mac1);
                let mut sig = [0u8; SIGNATURE_SIZE];
                sig[..32].copy_from_slice(&mac1);
                sig[32..].copy_from_slice(&mac2);
                FAKE_ED_SIGS.with(|r| r.borrow_mut().insert((public.to_vec(), message.to_vec()), sig));
                sig
            }),
            ed25519_verify: Box::new(|public, message, sig| {
                FAKE_ED_SIGS.with(|r| r.borrow().get(&(public.to_vec(), message.to_vec())) == Some(sig))
            }),
            // Must match `ed25519_sign`'s own `public` derivation above
            // (`hmac_sha256(b"ed25519-pub-fake", private)`) -- this is the
            // key space `HandshakeRelay::new` now derives `identity_public`
            // in via `ops.ed25519_public`, so it has to be the same fake
            // derivation the fake sign/verify closures use internally, not
            // the real `identity_public_from_private`.
            ed25519_public: Box::new(|private| crate::hashutil::hmac_sha256(b"ed25519-pub-fake", private)),
        }
    }

    fn client_with(trusted: Option<Vec<[u8; IDENTITY_KEY_SIZE]>>) -> HandshakeClient {
        let trust_first_use = trusted.is_none();
        HandshakeClient::new(DEFAULT_CIPHER_FOR_TESTS.to_string(), None, 1.0, trusted, trust_first_use, false, None, false, fake_handshake_ops()).unwrap()
    }

    fn relay_with_identity(identity_private: [u8; IDENTITY_KEY_SIZE]) -> HandshakeRelay {
        HandshakeRelay::new(None, DEFAULT_CIPHER_FOR_TESTS.to_string(), false, Some(identity_private), false, false, None, DEFAULT_COOKIE_WINDOW_SECONDS, fake_handshake_ops()).unwrap()
    }

    const DEFAULT_CIPHER_FOR_TESTS: &str = "chacha20-poly1305";

    #[test]
    fn test_client_relay_round_trip_derives_matching_keys() {
        clear_fake_registries();
        let mut relay = relay_with_identity([9u8; IDENTITY_KEY_SIZE]);
        let mut client = client_with(Some(vec![relay.identity_public]));

        let create = client.create(0x1234, None).unwrap();
        let datagram = match &create {
            CreateMessage::Single(c) => c.pack(),
            CreateMessage::Fragmented(_) => panic!("classical CREATE should not fragment"),
        };
        let created = relay.respond(&datagram, Some("127.0.0.1:9000".parse().unwrap())).unwrap();
        let keys = client.complete(&created.pack(), Some(0x1234)).unwrap();

        assert_eq!(keys.aead_key_fwd, relay.keys.as_ref().unwrap().aead_key_fwd);
        assert_eq!(keys.aead_key_bwd, relay.keys.as_ref().unwrap().aead_key_bwd);
        assert_eq!(keys.mac_key, relay.keys.as_ref().unwrap().mac_key);
        assert!(keys.relay_is_authenticated());
        assert_eq!(client.relay_identity, Some(relay.identity_public));
    }

    #[test]
    fn test_untrusted_relay_identity_is_rejected() {
        clear_fake_registries();
        let mut relay = relay_with_identity([1u8; IDENTITY_KEY_SIZE]);
        // Pinned to a *different* identity than the relay actually holds.
        let mut client = client_with(Some(vec![[2u8; IDENTITY_KEY_SIZE]]));

        let create = client.create(1, None).unwrap();
        let datagram = match &create {
            CreateMessage::Single(c) => c.pack(),
            CreateMessage::Fragmented(_) => panic!(),
        };
        let created = relay.respond(&datagram, None).unwrap();
        let err = client.complete(&created.pack(), Some(1)).unwrap_err();
        assert!(matches!(err, HandshakeError::RelayAuthentication(_)));
    }

    #[test]
    fn test_tampered_created_body_fails_verification() {
        clear_fake_registries();
        let mut relay = relay_with_identity([3u8; IDENTITY_KEY_SIZE]);
        let mut client = client_with(Some(vec![relay.identity_public]));

        let create = client.create(7, None).unwrap();
        let datagram = match &create {
            CreateMessage::Single(c) => c.pack(),
            CreateMessage::Fragmented(_) => panic!(),
        };
        let created = relay.respond(&datagram, None).unwrap();
        let mut tampered = created.pack();
        // Flip a byte inside the CREATED body (well before the trailing
        // sealed-nonce field), which should break the verifier check.
        tampered[20] ^= 0xFF;
        let err = client.complete(&tampered, Some(7)).unwrap_err();
        assert!(matches!(err, HandshakeError::Verification(_)));
    }

    /// An on-path attacker who
    /// intercepts a genuine, fully-signed CREATED reply and zeroes out
    /// just its `identity_public`/`signature` fields -- leaving
    /// `public_key`/`ephemeral_public`/`salt`/`verifier` untouched -- must
    /// now fail the verifier check outright, even against a client
    /// configured with `allow_anonymous_relay = true` *and* a pinned
    /// identity for this exact relay. Before the fix, this silently
    /// downgraded to an unauthenticated, un-pinned relay
    /// (`relay_identity = None`) instead of erroring, because the
    /// verifier never depended on `identity_public`/`signature` at all.
    #[test]
    fn test_stripping_identity_and_signature_fails_verification_even_with_anonymous_relay_allowed() {
        clear_fake_registries();
        let mut relay = relay_with_identity([6u8; IDENTITY_KEY_SIZE]);
        let mut client = HandshakeClient::new(
            DEFAULT_CIPHER_FOR_TESTS.to_string(),
            None,
            1.0,
            Some(vec![relay.identity_public]), // pinned to the real relay
            false,
            true, // allow_anonymous_relay: the exact setting the attack abuses
            None,
            false,
            fake_handshake_ops(),
        )
        .unwrap();

        let create = client.create(11, None).unwrap();
        let datagram = match &create {
            CreateMessage::Single(c) => c.pack(),
            CreateMessage::Fragmented(_) => panic!(),
        };
        let created = relay.respond(&datagram, None).unwrap();
        let mut body = CreatedBody::unpack(&created.payload).unwrap();
        assert!(body.is_authenticated(), "the relay always signs; this reply must start out authenticated");

        // The attack: strip identity + signature, leaving every other
        // field -- crucially `verifier`, `public_key`, `ephemeral_public`
        // -- exactly as the relay sent them.
        body.identity_public = [0u8; IDENTITY_KEY_SIZE];
        body.signature = [0u8; SIGNATURE_SIZE];
        let mut tampered_payload = body.pack();
        tampered_payload.truncate(CREATED_BODY_SIZE);
        tampered_payload.extend_from_slice(&created.payload[CREATED_BODY_SIZE..]); // real sealed nonce, untouched
        let tampered_cell = Cell::with_command(created.circuit_id, created.command, tampered_payload).unwrap();

        let err = client.complete(&tampered_cell.pack(), Some(11)).unwrap_err();
        assert!(
            matches!(err, HandshakeError::Verification(_)),
            "expected a verifier mismatch, got {err:?} -- a silent Ok() here would mean the downgrade attack still works"
        );
    }

    #[test]
    fn test_wrong_circuit_id_in_complete_is_rejected() {
        clear_fake_registries();
        let mut relay = relay_with_identity([4u8; IDENTITY_KEY_SIZE]);
        let mut client = client_with(Some(vec![relay.identity_public]));

        let create = client.create(42, None).unwrap();
        let datagram = match &create {
            CreateMessage::Single(c) => c.pack(),
            CreateMessage::Fragmented(_) => panic!(),
        };
        let created = relay.respond(&datagram, None).unwrap();
        let err = client.complete(&created.pack(), Some(43)).unwrap_err();
        assert!(matches!(err, HandshakeError::Generic(_) | HandshakeError::Rejected(_)));
    }

    #[test]
    fn test_relay_rejects_wrong_command() {
        clear_fake_registries();
        let mut relay = relay_with_identity([5u8; IDENTITY_KEY_SIZE]);
        let bogus = Cell::with_command(1, Command::Destroy, Vec::new()).unwrap();
        let err = relay.respond(&bogus.pack(), None).unwrap_err();
        assert!(matches!(err, HandshakeError::Rejected(_)));
    }

    #[test]
    fn test_relay_reject_cell_echoes_circuit_id() {
        let relay = relay_with_identity([6u8; IDENTITY_KEY_SIZE]);
        let destroy = relay.reject_cell(0xAABBCCDD);
        assert_eq!(destroy.command, Command::Destroy);
        assert_eq!(destroy.circuit_id, 0xAABBCCDD);
    }

    #[test]
    fn test_return_routability_challenge_then_retry_succeeds() {
        clear_fake_registries();
        let mut relay = HandshakeRelay::new(None, DEFAULT_CIPHER_FOR_TESTS.to_string(), false, Some([7u8; IDENTITY_KEY_SIZE]), false, true, Some(b"cookie-secret-32-bytes-long!!!!".to_vec()), 300.0, fake_handshake_ops()).unwrap();
        let mut client = client_with(Some(vec![relay.identity_public]));
        let peer: SocketAddr = "127.0.0.1:9001".parse().unwrap();

        let create1 = client.create(5, None).unwrap();
        let datagram1 = match &create1 {
            CreateMessage::Single(c) => c.pack(),
            CreateMessage::Fragmented(_) => panic!(),
        };
        let reply1 = relay.respond(&datagram1, Some(peer)).unwrap();
        assert_eq!(reply1.command, Command::CreateChallenge);

        let cookie = client.parse_challenge(&reply1.pack(), Some(5)).unwrap();
        let create2 = client.create(5, Some(&cookie)).unwrap();
        let datagram2 = match &create2 {
            CreateMessage::Single(c) => c.pack(),
            CreateMessage::Fragmented(_) => panic!(),
        };
        let reply2 = relay.respond(&datagram2, Some(peer)).unwrap();
        assert_eq!(reply2.command, Command::Created);
        let keys = client.complete(&reply2.pack(), Some(5)).unwrap();
        assert_eq!(keys.aead_key_fwd.len(), KEY_SIZE);
        assert_eq!(keys.aead_key_bwd.len(), KEY_SIZE);
    }

    #[test]
    fn test_client_without_trust_config_is_rejected() {
        let result = HandshakeClient::new(DEFAULT_CIPHER_FOR_TESTS.to_string(), None, 1.0, None, false, false, None, false, fake_handshake_ops());
        assert!(matches!(result, Err(HandshakeError::Generic(_))));
    }

    #[test]
    fn test_require_pq_without_kem_public_is_rejected() {
        let result = HandshakeClient::new(DEFAULT_CIPHER_FOR_TESTS.to_string(), None, 1.0, None, true, false, None, true, fake_handshake_ops());
        assert!(matches!(result, Err(HandshakeError::Generic(_))));
    }

    #[test]
    fn test_ephemeral_key_rotates_per_circuit() {
        clear_fake_registries();
        let mut client = client_with(None);
        client.create(1, None).unwrap();
        let pub1 = client.public_key;
        client.create(2, None).unwrap();
        let pub2 = client.public_key;
        assert_ne!(pub1, pub2);
    }

    #[test]
    fn test_cookie_retry_reuses_same_key_for_same_circuit() {
        clear_fake_registries();
        let mut client = client_with(None);
        client.create(9, None).unwrap();
        let pub1 = client.public_key;
        // Same circuit id, with a cookie this time: must be the same key.
        client.create(9, Some(&[1u8; COOKIE_SIZE])).unwrap();
        let pub2 = client.public_key;
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn test_relay_serve_once_answers_and_echoes_via_socket() {
        clear_fake_registries();
        let mut relay = relay_with_identity([11u8; IDENTITY_KEY_SIZE]);
        let mut client = client_with(Some(vec![relay.identity_public]));

        let relay_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay_sock.local_addr().unwrap();
        let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        client_sock.connect(relay_addr).unwrap();
        let client_addr = client_sock.local_addr().unwrap();

        let create = client.create_bytes(21, None).unwrap();
        client_sock.send(&create).unwrap();

        let (reply, peer) = relay.serve_once(&relay_sock).unwrap().unwrap();
        assert_eq!(peer, client_addr);
        assert_eq!(reply.command, Command::Created);

        let mut buf = [0u8; CELL_SIZE];
        let n = client_sock.recv(&mut buf).unwrap();
        let keys = client.complete(&buf[..n], Some(21)).unwrap();
        assert_eq!(keys.aead_key_fwd.len(), KEY_SIZE);
        assert_eq!(keys.aead_key_bwd.len(), KEY_SIZE);
    }

    #[test]
    fn test_handshake_over_socket_end_to_end() {
        // `HandshakeClient::handshake` blocks on the socket until a reply
        // arrives, so exercising it end-to-end needs the relay answered from
        // a second thread -- but this test module's fake X25519/Ed25519 ops
        // record state in a `thread_local!` (deliberately, so parallel
        // `cargo test` runs of *different* tests never see each other's
        // registrations; see `clear_fake_registries`), which a second OS
        // thread would not share. Reproduce `handshake`'s send/receive
        // sequence directly on this one thread instead -- same wire
        // exchange, same eventual call to `complete`, without a private
        // sub-cover of `handshake`'s own retry loop (covered separately by
        // `test_return_routability_challenge_then_retry_succeeds`).
        clear_fake_registries();
        let mut relay = relay_with_identity([12u8; IDENTITY_KEY_SIZE]);
        let mut client = client_with(Some(vec![relay.identity_public]));

        let relay_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay_sock.local_addr().unwrap();
        let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();

        for datagram in client.create_datagrams(99, None).unwrap() {
            client_sock.send_to(&datagram, relay_addr).unwrap();
        }
        let (_reply, _peer) = relay.serve_once(&relay_sock).unwrap().unwrap();
        let mut buf = [0u8; CELL_SIZE];
        let (n, from) = client_sock.recv_from(&mut buf).unwrap();
        assert_eq!(from, relay_addr);
        let keys = client.complete(&buf[..n], Some(99)).unwrap();
        assert_eq!(keys.aead_key_fwd.len(), KEY_SIZE);
        assert_eq!(keys.aead_key_bwd.len(), KEY_SIZE);
    }

    #[test]
    fn test_to_onion_crypto_and_to_layer_build_working_hops() {
        clear_fake_registries();
        let mut relay = relay_with_identity([13u8; IDENTITY_KEY_SIZE]);
        let mut client = client_with(Some(vec![relay.identity_public]));

        let create = client.create(3, None).unwrap();
        let datagram = match &create {
            CreateMessage::Single(c) => c.pack(),
            CreateMessage::Fragmented(_) => panic!(),
        };
        let created = relay.respond(&datagram, None).unwrap();
        let client_keys = client.complete(&created.pack(), Some(3)).unwrap();
        let relay_keys = relay.keys.as_ref().unwrap();

        let mut client_hop = client_keys.to_onion_crypto("guard", 0).unwrap();
        let relay_hop = relay_keys.to_onion_crypto("guard", 0).unwrap();
        let sealed = client_hop.seal_payload(b"hello", 0, ("1.2.3.4".to_string(), 80), None, None).unwrap();
        let (inner, _header) = relay_hop.peel_layer(&sealed).unwrap();
        assert_eq!(inner, b"hello");

        let client_layer = client_keys.to_layer("guard").unwrap();
        assert_eq!(client_layer.mac_key, client_keys.mac_key);
    }

    #[test]
    fn test_relay_reject_cell_via_serve_once_on_bad_request() {
        clear_fake_registries();
        let mut relay = HandshakeRelay::new(None, DEFAULT_CIPHER_FOR_TESTS.to_string(), true, Some([14u8; IDENTITY_KEY_SIZE]), false, false, None, DEFAULT_COOKIE_WINDOW_SECONDS, fake_handshake_ops()).unwrap();
        let relay_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay_sock.local_addr().unwrap();
        let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        client_sock.connect(relay_addr).unwrap();

        let bogus = Cell::with_command(55, Command::Destroy, Vec::new()).unwrap();
        client_sock.send(&bogus.pack()).unwrap();
        let (reply, _peer) = relay.serve_once(&relay_sock).unwrap().unwrap();
        assert_eq!(reply.command, Command::Destroy);
        assert_eq!(reply.circuit_id, 55);
    }

    #[test]
    fn test_rotate_kem_key_respects_min_rotation_unless_forced() {
        let mut relay = relay_with_identity([15u8; IDENTITY_KEY_SIZE]);
        let first = relay.rotate_kem_key(true).unwrap();
        let again = relay.rotate_kem_key(false).unwrap();
        assert_eq!(first, again); // too soon since KEM_MIN_ROTATION hasn't elapsed
        let forced = relay.rotate_kem_key(true).unwrap();
        assert_ne!(first, forced);
    }

    #[test]
    fn test_hybrid_handshake_round_trip() {
        clear_fake_registries();
        let mut relay = relay_with_identity([16u8; IDENTITY_KEY_SIZE]);
        let kem_public = relay.rotate_kem_key(true).unwrap();
        let mut client = HandshakeClient::new(DEFAULT_CIPHER_FOR_TESTS.to_string(), None, 1.0, Some(vec![relay.identity_public]), false, false, Some(kem_public), true, fake_handshake_ops()).unwrap();

        let create = client.create(77, None).unwrap();
        let datagrams = create.datagrams().unwrap();
        assert!(!datagrams.is_empty());
        // Reassemble via the same fragment machinery a relay would use.
        let mut reassembler = crate::createfrag::CreateReassembler::new(16);
        let mut reassembled: Option<crate::createfrag::CreateMessage> = None;
        for d in &datagrams {
            let cell = Cell::from_bytes(d, true).unwrap();
            if let Some(msg) = reassembler.push(&cell, ("127.0.0.1".to_string(), 9000)) {
                reassembled = Some(msg);
            }
        }
        let reassembled = reassembled.expect("hybrid CREATE should reassemble");

        let created = relay.respond_reassembled(&reassembled, None).unwrap();
        let keys = client.complete(&created.pack(), Some(77)).unwrap();
        assert_eq!(keys.aead_key_fwd, relay.keys.as_ref().unwrap().aead_key_fwd);
        assert_eq!(keys.aead_key_bwd, relay.keys.as_ref().unwrap().aead_key_bwd);
    }

    #[test]
    fn test_constants() {
        assert_eq!(HANDSHAKE_VERSION, 2);
        assert_eq!(HANDSHAKE_VERSION_HYBRID, 3);
        assert_eq!(PUBLIC_KEY_SIZE, 32);
        assert_eq!(SALT_SIZE, 16);
        assert_eq!(VERIFIER_SIZE, 32);
        assert_eq!(IDENTITY_KEY_SIZE, 32);
        assert_eq!(SIGNATURE_SIZE, 64);
        assert_eq!(COOKIE_SIZE, 16);
    }

    #[test]
    fn test_create_body_size_matches_python_struct_layout() {
        // version(1) + type(1) + circuit_id(4) + pub(32) + nonce(12) + cookie(16) = 66
        assert_eq!(CREATE_BODY_SIZE, 1 + 1 + 4 + 32 + NONCE_SIZE + 16);
    }

    #[test]
    fn test_created_body_size_matches_python_struct_layout() {
        assert_eq!(CREATED_BODY_SIZE, 1 + 1 + 4 + 32 + 32 + 16 + 32 + 32 + 64 + NONCE_SIZE);
    }

    #[test]
    fn test_create_body_pack_unpack_round_trip() {
        let body = CreateBody::new(0x01020304, [7u8; PUBLIC_KEY_SIZE], HANDSHAKE_VERSION, MSG_CREATE, None, Vec::new(), Vec::new());
        let packed = body.pack();
        assert_eq!(packed.len(), CREATE_BODY_SIZE);
        let parsed = CreateBody::unpack(&packed).unwrap();
        assert_eq!(parsed.circuit_id, 0x01020304);
        assert_eq!(parsed.public_key, [7u8; PUBLIC_KEY_SIZE]);
        assert!(!parsed.has_cookie());
    }

    #[test]
    fn test_create_body_with_cookie_has_cookie_true() {
        let cookie = [9u8; COOKIE_SIZE];
        let body = CreateBody::new(1, [1u8; PUBLIC_KEY_SIZE], HANDSHAKE_VERSION, MSG_CREATE, Some(cookie), Vec::new(), Vec::new());
        assert!(body.has_cookie());
        assert_eq!(CreateBody::unpack(&body.pack()).unwrap().cookie, cookie);
    }

    #[test]
    fn test_create_body_rejects_short_buffer() {
        assert!(CreateBody::unpack(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_create_body_rejects_bad_version() {
        let mut packed = CreateBody::new(1, [1u8; PUBLIC_KEY_SIZE], HANDSHAKE_VERSION, MSG_CREATE, None, Vec::new(), Vec::new()).pack();
        packed[0] = 99;
        assert!(CreateBody::unpack(&packed).is_err());
    }

    #[test]
    fn test_hybrid_create_body_round_trip() {
        let key_id = vec![1u8; KEM_KEY_ID_SIZE];
        let ciphertext = vec![2u8; crate::mlkem::CIPHERTEXT_SIZE];
        let body = CreateBody::new(5, [3u8; PUBLIC_KEY_SIZE], HANDSHAKE_VERSION_HYBRID, MSG_CREATE, None, key_id.clone(), ciphertext.clone());
        assert!(body.is_hybrid());
        let mut packed = body.pack();
        packed.extend_from_slice(&key_id);
        packed.extend_from_slice(&ciphertext);
        assert_eq!(packed.len(), HYBRID_CREATE_BODY_SIZE);
        let parsed = CreateBody::unpack(&packed).unwrap();
        assert_eq!(parsed.kem_key_id, key_id);
        assert_eq!(parsed.kem_ciphertext, ciphertext);
        assert_eq!(create_body_size(&packed), HYBRID_CREATE_BODY_SIZE);
    }

    #[test]
    fn test_with_cookie_replaces_only_cookie_field() {
        let original_cookie = [0u8; COOKIE_SIZE];
        let body = CreateBody::new(7, [4u8; PUBLIC_KEY_SIZE], HANDSHAKE_VERSION, MSG_CREATE, Some(original_cookie), Vec::new(), Vec::new());
        let mut raw = body.pack();
        raw.extend_from_slice(b"trailer-bytes"); // simulates a relay-appended trailer
        let new_cookie = [5u8; COOKIE_SIZE];
        let updated = with_cookie(&raw, &new_cookie).unwrap();
        assert_eq!(&updated[updated.len() - 13..], b"trailer-bytes");
        let parsed = CreateBody::unpack(&updated).unwrap();
        assert_eq!(parsed.cookie, new_cookie);
        assert_eq!(parsed.public_key, [4u8; PUBLIC_KEY_SIZE]); // untouched
    }

    #[test]
    fn test_with_cookie_rejects_short_body() {
        assert!(with_cookie(&[0u8; 4], &[0u8; COOKIE_SIZE]).is_err());
    }

    #[test]
    fn test_created_body_pack_unpack_round_trip() {
        let body = CreatedBody::new(9, [1u8; PUBLIC_KEY_SIZE], [2u8; PUBLIC_KEY_SIZE], [3u8; SALT_SIZE], [4u8; VERIFIER_SIZE], Some([5u8; IDENTITY_KEY_SIZE]), Some([6u8; SIGNATURE_SIZE]), HANDSHAKE_VERSION, MSG_CREATED);
        assert!(body.is_authenticated());
        let packed = body.pack();
        assert_eq!(packed.len(), CREATED_BODY_SIZE);
        let parsed = CreatedBody::unpack(&packed).unwrap();
        assert_eq!(parsed, body);
    }

    #[test]
    fn test_created_body_anonymous_relay_not_authenticated() {
        let body = CreatedBody::new(1, [1u8; PUBLIC_KEY_SIZE], [1u8; PUBLIC_KEY_SIZE], [1u8; SALT_SIZE], [1u8; VERIFIER_SIZE], None, None, HANDSHAKE_VERSION, MSG_CREATED);
        assert!(!body.is_authenticated());
    }

    #[test]
    fn test_challenge_body_round_trip() {
        let body = ChallengeBody::new(3, [8u8; COOKIE_SIZE], HANDSHAKE_VERSION, MSG_CHALLENGE);
        let packed = body.pack();
        assert_eq!(packed.len(), CHALLENGE_BODY_SIZE);
        assert_eq!(ChallengeBody::unpack(&packed).unwrap(), body);
    }

    #[test]
    fn test_transcript_changes_with_every_component() {
        let base = transcript(1, b"a", b"b", b"c", b"d", b"e", "chacha20-poly1305", b"", b"id1");
        assert_ne!(base, transcript(2, b"a", b"b", b"c", b"d", b"e", "chacha20-poly1305", b"", b"id1"));
        assert_ne!(base, transcript(1, b"x", b"b", b"c", b"d", b"e", "chacha20-poly1305", b"", b"id1"));
        assert_ne!(base, transcript(1, b"a", b"b", b"c", b"d", b"e", "aes-256-gcm", b"", b"id1"));
        assert_ne!(base, transcript(1, b"a", b"b", b"c", b"d", b"e", "chacha20-poly1305", b"pq", b"id1"));
        // The relay's claimed
        // identity must affect the transcript too, so the verifier can't
        // be satisfied after an attacker strips/alters it in transit.
        assert_ne!(base, transcript(1, b"a", b"b", b"c", b"d", b"e", "chacha20-poly1305", b"", b"id2"));
    }

    #[test]
    fn test_compute_verifier_is_deterministic_and_sensitive() {
        let v1 = compute_verifier(b"secret", b"salt1234567890ab", 1, b"cp", b"rp", b"rep", b"cn", b"rn", "chacha20-poly1305", b"", b"id1");
        let v2 = compute_verifier(b"secret", b"salt1234567890ab", 1, b"cp", b"rp", b"rep", b"cn", b"rn", "chacha20-poly1305", b"", b"id1");
        assert_eq!(v1, v2);
        let v3 = compute_verifier(b"different-secret", b"salt1234567890ab", 1, b"cp", b"rp", b"rep", b"cn", b"rn", "chacha20-poly1305", b"", b"id1");
        assert_ne!(v1, v3);
        // A different claimed
        // relay identity, everything else held constant, must produce a
        // different verifier.
        let v4 = compute_verifier(b"secret", b"salt1234567890ab", 1, b"cp", b"rp", b"rep", b"cn", b"rn", "chacha20-poly1305", b"", b"id2");
        assert_ne!(v1, v4);
    }

    #[test]
    fn test_signing_payload_starts_with_verifier_then_identity() {
        let verifier = [1u8; VERIFIER_SIZE];
        let identity = [2u8; IDENTITY_KEY_SIZE];
        let payload = signing_payload(1, b"cp", b"rp", b"rep", b"cn", b"rn", "chacha20-poly1305", &verifier, &identity, b"");
        assert_eq!(&payload[..VERIFIER_SIZE], &verifier);
        assert_eq!(&payload[VERIFIER_SIZE..VERIFIER_SIZE + IDENTITY_KEY_SIZE], &identity);
    }

    #[test]
    fn test_derive_handshake_keys_are_independent() {
        let keys = derive_handshake_keys(b"shared".to_vec(), b"salt1234567890ab".to_vec(), 1, "chacha20-poly1305".to_string(), None, Vec::new(), None, None, HandshakeRole::Client);
        assert_ne!(keys.aead_key_fwd, keys.mac_key);
        assert_ne!(keys.aead_key_bwd, keys.mac_key);
        // The forward and backward
        // AEAD keys must be independent of each other, not just of mac_key.
        assert_ne!(keys.aead_key_fwd, keys.aead_key_bwd);
        assert_ne!(keys.aead_key_fwd.to_vec(), keys.handshake_key().to_vec());
        assert_ne!(keys.aead_key_bwd.to_vec(), keys.handshake_key().to_vec());
        assert_eq!(keys.handshake_iv().len(), NONCE_SIZE);
        assert!(!keys.relay_is_authenticated());
    }

    #[test]
    fn test_derive_handshake_keys_deterministic() {
        let k1 = derive_handshake_keys(b"shared".to_vec(), b"salt1234567890ab".to_vec(), 1, "chacha20-poly1305".to_string(), None, Vec::new(), None, None, HandshakeRole::Client);
        let k2 = derive_handshake_keys(b"shared".to_vec(), b"salt1234567890ab".to_vec(), 1, "chacha20-poly1305".to_string(), None, Vec::new(), None, None, HandshakeRole::Client);
        assert_eq!(k1.aead_key_fwd, k2.aead_key_fwd);
        assert_eq!(k1.aead_key_bwd, k2.aead_key_bwd);
        assert_eq!(k1.mac_key, k2.mac_key);
    }

    #[test]
    fn test_derive_handshake_keys_with_identity() {
        let identity = [9u8; IDENTITY_KEY_SIZE];
        let keys = derive_handshake_keys(b"shared".to_vec(), b"salt1234567890ab".to_vec(), 1, "chacha20-poly1305".to_string(), None, Vec::new(), None, Some(identity), HandshakeRole::Client);
        assert!(keys.relay_is_authenticated());
        assert_eq!(keys.identity_public, Some(identity));
    }

    #[test]
    fn test_session_id_is_16_bytes_and_deterministic() {
        let keys = derive_handshake_keys(b"shared".to_vec(), b"salt1234567890ab".to_vec(), 1, "chacha20-poly1305".to_string(), None, Vec::new(), None, None, HandshakeRole::Client);
        let id1 = keys.session_id();
        let id2 = keys.session_id();
        assert_eq!(id1.len(), 16);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_normalise_identities_none_means_trust_any() {
        assert_eq!(normalise_identities(None).unwrap(), None);
    }

    #[test]
    fn test_normalise_identities_hex_round_trip() {
        let hex = "0101010101010101010101010101010101010101010101010101010101010101"; // 34 bytes -> too long, adjust
        let _ = hex; // placeholder to keep imports tidy if unused paths change
        let good_hex = "01".repeat(IDENTITY_KEY_SIZE);
        let result = normalise_identities(Some(&[good_hex.as_str()])).unwrap().unwrap();
        assert_eq!(result, vec![[1u8; IDENTITY_KEY_SIZE]]);
    }

    #[test]
    fn test_normalise_identities_rejects_bad_length() {
        assert!(normalise_identities(Some(&["0101"])).is_err());
    }

    #[test]
    fn test_normalise_identities_rejects_bad_hex() {
        assert!(normalise_identities(Some(&["not-hex-at-all-zz"])).is_err());
    }

    #[test]
    fn test_create_body_size_helper() {
        let v2 = CreateBody::new(1, [0u8; PUBLIC_KEY_SIZE], HANDSHAKE_VERSION, MSG_CREATE, None, Vec::new(), Vec::new()).pack();
        assert_eq!(create_body_size(&v2), CREATE_BODY_SIZE);
    }

    #[test]
    fn test_handshake_message_fragments_and_datagrams() {
        let msg = HandshakeMessage::new(1, Command::Create, vec![0u8; 10]);
        let fragments = msg.fragments().unwrap();
        assert_eq!(fragments.len(), 1); // small payload, fits in one CREATE_FRAGMENT
        let datagrams = msg.datagrams().unwrap();
        assert_eq!(datagrams.len(), fragments.len());
    }

    /// A client pinned to specific relay identities must never accept a
    /// relay that presents none, even with `allow_anonymous_relay = true`:
    /// an anonymous relay can by definition not satisfy a pin, and honouring
    /// the flag here let an impostor with its own key and no identity bypass
    /// the pin entirely. Exercises `authenticate_relay` directly, since a
    /// genuine reply whose identity is merely stripped already fails the
    /// verifier before this check is reached.
    #[test]
    fn test_anonymous_relay_is_refused_when_pins_are_configured_even_if_anonymous_relays_are_allowed() {
        clear_fake_registries();
        let mut relay = relay_with_identity([6u8; IDENTITY_KEY_SIZE]);
        let mut anonymous_body = || {
            let mut probe = HandshakeClient::new(DEFAULT_CIPHER_FOR_TESTS.to_string(), None, 1.0, None, true, false, None, false, fake_handshake_ops()).unwrap();
            let create = probe.create(11, None).unwrap();
            let datagram = match &create {
                CreateMessage::Single(c) => c.pack(),
                CreateMessage::Fragmented(_) => panic!(),
            };
            let created = relay.respond(&datagram, None).unwrap();
            let mut body = CreatedBody::unpack(&created.payload).unwrap();
            body.identity_public = [0u8; IDENTITY_KEY_SIZE];
            body.signature = [0u8; SIGNATURE_SIZE];
            assert!(!body.is_authenticated());
            body
        };
        let client = |pins: Option<Vec<[u8; IDENTITY_KEY_SIZE]>>, allow_anonymous: bool| {
            HandshakeClient::new(DEFAULT_CIPHER_FOR_TESTS.to_string(), None, 1.0, pins.clone(), pins.is_none(), allow_anonymous, None, false, fake_handshake_ops()).unwrap()
        };
        let pq = [0u8; 0];
        let client_public = [0u8; PUBLIC_KEY_SIZE];

        // pinned + anonymous allowed: refused (this is the bypass)
        let mut pinned_and_allowed = client(Some(vec![[6u8; IDENTITY_KEY_SIZE]]), true);
        let err = pinned_and_allowed.authenticate_relay(&anonymous_body(), 11, &[0u8; NONCE_SIZE], &[0u8; NONCE_SIZE], &pq, &client_public).unwrap_err();
        assert!(matches!(err, HandshakeError::RelayAuthentication(_)), "{err:?}");
        assert_eq!(pinned_and_allowed.relay_identity, None);
        // pinned + anonymous not allowed: refused, as before
        let mut pinned = client(Some(vec![[6u8; IDENTITY_KEY_SIZE]]), false);
        assert!(pinned.authenticate_relay(&anonymous_body(), 11, &[0u8; NONCE_SIZE], &[0u8; NONCE_SIZE], &pq, &client_public).is_err());
        // unpinned + not allowed: refused, as before
        let mut unpinned_strict = client(None, false);
        assert!(unpinned_strict.authenticate_relay(&anonymous_body(), 11, &[0u8; NONCE_SIZE], &[0u8; NONCE_SIZE], &pq, &client_public).is_err());
        // unpinned + allowed: still accepted, as the legacy-interop flag intends
        let mut unpinned_lenient = client(None, true);
        assert!(unpinned_lenient.authenticate_relay(&anonymous_body(), 11, &[0u8; NONCE_SIZE], &[0u8; NONCE_SIZE], &pq, &client_public).is_ok());
        assert_eq!(unpinned_lenient.relay_identity, None);
    }
}
