//! allium: byte-compatible Rust port of the Allium UDP onion-routing protocol.

mod hashutil;
mod keccak;
mod blake2;
mod osrand;

pub mod cell;
pub mod sizes;
pub mod layer;
pub mod config;
pub mod fragment;

pub use fragment::{
    DEFAULT_MTU, FLAG_FIN, Fragment, FragmentError, Fragmenter, Reassembler, decode_fragment,
    encode_fragment,
};
// Python's `allium/__init__.py` imports `fragment.HEADER_SIZE` renamed to
// `FRAGMENT_HEADER_SIZE` at the package level, since `cell.HEADER_SIZE` (7,
// the cell header) already occupies the unqualified name there. Mirror that.
pub use fragment::HEADER_SIZE as FRAGMENT_HEADER_SIZE;

pub mod createfrag;
pub mod congestion;

pub mod consensus;
pub mod policy;
pub mod mlkem;
pub mod crypto;
pub mod reliability;
// nat.py is not re-exported by allium/__init__.py either -- pub mod only,
// same as config/createfrag/consensus/mlkem.
pub mod nat;
pub mod handshake;
pub mod onion;
pub mod circuit;
pub mod directory;
// hswire.py is not re-exported by allium/__init__.py either (same as
// nat.py/config.py/createfrag.py/consensus.py/mlkem.py) -- pub mod only.
pub mod hswire;
// dirwire.py is not re-exported by allium/__init__.py either (same as
// hswire.py/nat.py/config.py/createfrag.py/consensus.py/mlkem.py) -- pub mod
// only.
pub mod dirwire;
// hiddenservice.py is not re-exported by allium/__init__.py either (same as
// dirwire.py/hswire.py/nat.py/config.py/createfrag.py/consensus.py/
// mlkem.py) -- pub mod only.
pub mod hiddenservice;
pub mod stream;
pub mod socks;
pub mod exit;
// alliumrc.py is not re-exported by allium/__init__.py either (same as
// config.py/nat.py/createfrag.py/consensus.py/mlkem.py/dirwire.py/
// hswire.py/hiddenservice.py) -- pub mod only.
pub mod alliumrc;
pub mod relay;

// relay.py -- see relay.rs's module docs for exactly what's ported
// (RelayNode itself, including every tokio-touching method, sentinel-block
// isolated and stub-and-restore verified).
// __init__.py's `from .relay import (...)` is now re-exported in full.
pub use relay::{
    Addr, CircuitEntry, CircuitKeyTuple, CircuitMismatch, CircuitNotFound, CircuitTable,
    DEFAULT_ACK_EVERY, DEFAULT_CLEANUP_INTERVAL, DEFAULT_CREATE_BURST, DEFAULT_CREATE_RATE,
    DEFAULT_EXTEND_TIMEOUT, DEFAULT_IDLE_TIMEOUT, DatagramAction, ForwardOutcome,
    LINK_TOKEN_SIZE, RelayError, RelayNode, RelayNodeOptions, RelayStats, ReplayDetected,
    STATE_CLOSED, STATE_LIVE, STATE_PENDING, derive_relay_identity, derive_relay_identity_hex,
    serve_forever,
};

pub mod socksproxy;

// socksproxy.py -- `SocksExit` (a composition wrapper over
// `relay::RelayNode`) and `SocksServer` (including its live
// per-connection negotiation/relay loop -- `start`/`stop`/`with_options`/
// the CONNECT/RESOLVE/UDP-ASSOCIATE paths, sentinel-block isolated and
// stub-and-restore verified exactly like `relay.rs`) are both now ported.
// See socksproxy.rs's module docs for the small remaining simplifications
// (the hidden-service relay bridge's `HsTunnel` trait has no in-tree
// implementation yet).
pub use socksproxy::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CMD_BIND, CMD_CONNECT, CMD_RESOLVE, CMD_UDP_ASSOCIATE,
    DEFAULT_SOCKS_PORT, HiddenServiceConnectFn, HsTunnel, Onion, OnionRetryFn, OnionRouterFn,
    REPLY_SUCCEEDED, ReplyCode, SOCKS_VERSION, SocksError, SocksExit, SocksServer,
    SocksServerOptions, UdpAssociation,
};

pub use stream::{
    DEFAULT_COVER_INTERVAL, DEFAULT_PUMP_INTERVAL, CircuitSender, CircuitSession,
    FragmentedCircuit, StreamClosed, StreamError,
};

pub use exit::{Egress, ExitEgressError, ExitStream, UDPAssociation};

pub use socks::{
    ADDR_UNSUPPORTED, COMMAND_UNSUPPORTED, CONNECT, CONNECTION_REFUSED, DATAGRAM_MAGIC,
    DATAGRAM_REPLY, DATAGRAM_REPLY_HEADER_SIZE, DATAGRAM_REQUEST, DATAGRAM_REQUEST_HEADER_SIZE,
    GENERAL_FAILURE, HOST_UNREACHABLE, MAGIC, MAX_ADDR_LEN, RESOLVE, SUCCESS, TTL_EXPIRED,
    DatagramReply, DatagramRequest, RequestKind, Status, StreamReply, StreamRequest,
    decode_datagram_reply, decode_datagram_request, decode_reply, decode_request,
    encode_datagram_reply, encode_datagram_request, encode_reply, encode_request,
    is_datagram_frame, max_datagram_payload, max_datagram_reply_payload,
    max_datagram_request_payload, pack_addr, pack_ipv4, unpack_addr, unpack_ipv4,
};

pub use directory::{
    CURRENT_DESCRIPTOR_VERSION, DESCRIPTOR_VERSION_1, DESCRIPTOR_VERSION_2, DEFAULT_DESCRIPTOR_LIFETIME,
    DIR_ROUND_TRIP_TIMEOUT, EXT_BANDWIDTH, EXT_EXIT_PORTS, EXT_FAMILY, EXT_PQ_KEM, EXT_REACHABILITY,
    MAX_DESCRIPTOR_LIFETIME, MAX_SELF_REPORTED_BANDWIDTH, ROLE_EXIT, ROLE_GUARD, ROLE_MIDDLE,
    UNMEASURED_BANDWIDTH_WEIGHT, DescriptorExpired, DescriptorLifetimeTooLong, DescriptorMalformed,
    AuthorityService, Directory, DirectoryError, PreferredGuardUnavailable, RelayDescriptor,
    SelectRouteOptions, SignatureInvalid, SybilRateLimited, dir_round_trip, dir_round_trip_over_circuit,
    fetch_relay_directory, ports_to_ranges, register_over_circuit,
};

pub use onion::{
    DEFAULT_CIPHER, MAX_PLAINTEXT_PADDING, TRAILING_PAD_ENTRY_SIZE, Layer, OnionBuildError,
    OnionCrypto, OnionError, OnionPeelError, OnionVersionError, PeeledLayer, onion_from_cell,
    pad_payload, pad_plaintext, peel_circuit, peel_circuit_verbose, seal_into_cell,
    strip_plaintext_padding,
};

pub use handshake::{
    CHALLENGE_BODY_SIZE, CIRCUIT_ID_SIZE, CREATED_BODY_SIZE, CREATE_BODY_SIZE, CreateMessage,
    DEFAULT_COOKIE_WINDOW_SECONDS, DEFAULT_TIMEOUT, HANDSHAKE_VERSION, HANDSHAKE_VERSION_HYBRID,
    HandshakeClient, HandshakeOps, HandshakeRelay, IDENTITY_KEY_SIZE, KEM_KEY_ID_SIZE,
    MAX_HANDSHAKE_PAYLOAD, PUBLIC_KEY_SIZE, SALT_SIZE, SIGNATURE_SIZE, TYPE_SIZE, VERIFIER_SIZE,
    ChallengeBody, CreateBody, CreatedBody, HandshakeError, HandshakeKeys, HandshakeMessage,
    HandshakeRejected, HandshakeTimeout, RelayAuthenticationError, VerificationError,
    compute_verifier, create_body_size, derive_handshake_keys, generate_identity_key,
    identity_public_from_private, signing_payload, verify_relay_signature, with_cookie,
};

pub use circuit::{
    CircuitBuildError, CircuitBuilder, DEFAULT_RETRIES, DEFAULT_SEND_JITTER, ExtendRejected,
    ExtendTimeout, HandshakeAttemptsExhausted, MAX_SEND_JITTER, RETRY_BACKOFF_BASE,
    RETRY_JITTER_FRACTION, jitter_delay, retry_sleep_seconds,
};

pub use crypto::{
    KEY_SIZE, NONCE_SIZE, SEAL_OVERHEAD, TAG_SIZE, AesGcmAead, ChaCha20Poly1305Aead,
    CryptoDecryptError, CryptoError, NonceCounter, NonceError, SaltAead, derive_key,
    generate_key, new_aead,
};

pub use policy::{
    DEFAULT_ALLOWED_TCP_PORTS, DEFAULT_ALLOWED_UDP_PORTS, DEFAULT_LEASE_TIMEOUT,
    DEFAULT_MAX_AMPLIFICATION, DEFAULT_UDP_BURST, DEFAULT_UDP_RATE, AmplificationExceeded,
    AmplificationGuard, ExitPolicy, LeaseTable, PolicyDenied, PolicyError, RateLimitExceeded,
    RateLimiter, SessionLease, is_private_or_local,
};
// Python exposes `BLOCKED_AMPLIFICATION_PORTS` as a plain dict constant; here
// it is a function (a `HashMap` needs runtime init), re-exported under the
// same SCREAMING_SNAKE_CASE name for parity with the Python API.
#[allow(non_snake_case)]
pub use policy::blocked_amplification_ports as BLOCKED_AMPLIFICATION_PORTS;

pub use reliability::{
    DEFAULT_HANDSHAKE_REPLAY_ENTRIES, DEFAULT_HANDSHAKE_REPLAY_TTL, DEFAULT_MAX_RETRIES,
    DEFAULT_RTO, DEFAULT_WINDOW, SEQ_MODULUS, AckState, AckTracker, HandshakeReplayGuard,
    ReassemblyBuffer, ReliabilityError, ReplayWindow, SendBufferFull, SendWindow,
};

pub use congestion::{
    DEFAULT_INITIAL_CWND, DEFAULT_INITIAL_RTO, DEFAULT_MAX_CWND, DEFAULT_MAX_RTO,
    DEFAULT_MIN_CWND, DEFAULT_MIN_RTO, DEFAULT_RTT_ALPHA, DEFAULT_RTT_BETA,
    CongestionController, CongestionError, RttEstimator,
};

pub use sizes::{
    HOP_COUNT, PER_LAYER_OVERHEAD, ROUTE_HEADER_SIZE, RoutePlan, OnionTooLargeError,
    onion_size, user_data_budget,
};

pub use layer::{
    ACK_WIRE_SIZE, HEADER_FORMAT, LAYER_PROTOCOL_VERSION, HeaderError, Kind, LayerHeader,
    LayerVersionError, decode_ack, encode_ack,
};

pub use cell::{
    CELL_SIZE, HEADER_SIZE, HEADER_WITH_RESERVED_SIZE, IPV4_SAFE_MTU, IPV6_SAFE_MTU,
    MAX_CELL_SIZE, MAX_PAYLOAD_SIZE, PAYLOAD_SIZE,
    Cell, CellError, CellSizeError, Command, InvalidCommandError, MtuError,
    assert_mtu_safe, datagram_size, fits_without_fragmentation,
};
