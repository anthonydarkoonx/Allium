//! A signed relay directory: discovery without a central server.
//!
//! Port of Python's `directory.py`. See that module's docstring for the full
//! design rationale (self-signed [`RelayDescriptor`]s, an optional
//! trusted-authority allowlist, revocation/rotation via the validity window).
//!
//! ## Ed25519 (written but unverified pending real cargo build)
//!
//! [`RelayDescriptor::create`]/[`RelayDescriptor::verify`] need Ed25519
//! sign/verify. Per the dependency policy, this reuses
//! [`crate::nat::Ed25519Ops`] -- the same injected-closures type `nat.rs`
//! already defined for exactly this purpose -- rather than duplicating a
//! second copy of the same three `ed25519-dalek`-backed functions. This is a
//! deliberate signature deviation from Python (whose `create`/`verify` take
//! no such parameter, since `cryptography` is just imported and called
//! directly): both methods here take `&Ed25519Ops` explicitly, and
//! [`Directory`] stores one (`Ed25519Ops::real()` for production,
//! injectable for tests) so `Directory::publish` doesn't need it threaded
//! through every call site either. See `nat.rs`'s module docs for why the
//! three underlying functions are unbuildable/untestable in this sandbox
//! but everything built on top of them (here: `signing_payload`,
//! `check_structure`, `is_valid_at`, all of `Directory`'s selection/rate-limit
//! logic) is fully tested against a fake, deterministic signer.
//!
//! `_subnet_key`'s IPv4/IPv6 `/16`/`/32` classification is hand-rolled here
//! (`subnet_key`) rather than using a crate: `std::net::{Ipv4Addr,Ipv6Addr}`
//! parsing plus a manual prefix mask covers exactly what Python's
//! `ipaddress` module does for this one use.
//!
//! `_route_rng`'s production path (`seed=None`) draws straight from
//! `/dev/urandom`, matching Python's `secrets.SystemRandom` (every draw a
//! fresh OS CSPRNG output, nothing to recover state from). The seeded path
//! (`seed=Some(_)`, test-only in both languages) is **not** a bit-for-bit
//! port of Python's seeded `random.Random` (Mersenne Twister) -- reproducing
//! that PRNG exactly would be a large, load-bearing-nowhere undertaking; the
//! Rust port instead uses its own small, reproducible splitmix64-based PRNG
//! for the same purpose (deterministic route selection in a test), a
//! documented deviation.

use crate::cell::Command;
use crate::circuit::{Addr, CircuitBuilder, DEFAULT_SEND_JITTER};
use crate::consensus::{Trusted, Vote, compute_consensus, decode_vote, default_quorum, encode_vote_request, missing_identities};
use crate::dirwire::{
    DirReassembler, decode_fetch_reply, decode_fetch_request, decode_publish_request, encode_fetch_reply,
    encode_fetch_request_default, encode_publish_reply, fragment_message_default,
};
use crate::layer::Kind;
use crate::nat::{Ed25519Ops, NatError, Reachability, decode_reachability};
use crate::onion::{DEFAULT_CIPHER, seal_into_cell};
use crate::relay::{CircuitKeyTuple, RelayNode};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, UdpSocket};
use std::rc::Rc;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Descriptor schema v2 constants
// ---------------------------------------------------------------------------

pub const DESCRIPTOR_VERSION_1: u32 = 1;
pub const DESCRIPTOR_VERSION_2: u32 = 2;
pub const CURRENT_DESCRIPTOR_VERSION: u32 = DESCRIPTOR_VERSION_2;

/// Self-reported sustainable throughput, bytes/second (u64, big-endian).
pub const EXT_BANDWIDTH: u8 = 1;
/// Exit port summary: u16 count, then that many (u16 lo, u16 hi) ranges.
pub const EXT_EXIT_PORTS: u8 = 2;
/// Family: concatenated 32-byte Ed25519 identities, sorted.
pub const EXT_FAMILY: u8 = 3;
/// NAT reachability (see [`crate::nat`]).
pub const EXT_REACHABILITY: u8 = 4;
/// The relay's current ML-KEM-768 encapsulation key (1184 bytes).
pub const EXT_PQ_KEM: u8 = 5;
const PQ_KEM_LEN: usize = 1184;

const MAX_EXTENSIONS: usize = 16;
const MAX_EXTENSION_LEN: usize = 2048;
const MAX_FAMILY: usize = 32;

/// Selection weight for a relay with no bandwidth information at all.
pub const UNMEASURED_BANDWIDTH_WEIGHT: u64 = 20_000;
/// Ceiling on a self-reported bandwidth's selection weight, bytes/second.
pub const MAX_SELF_REPORTED_BANDWIDTH: u64 = 12_500_000;

/// How long a freshly minted descriptor stays valid, in seconds.
pub const DEFAULT_DESCRIPTOR_LIFETIME: f64 = 3600.0;
/// Longest `not_after - not_before` span a [`Directory`] accepts by default.
pub const MAX_DESCRIPTOR_LIFETIME: f64 = DEFAULT_DESCRIPTOR_LIFETIME * 24.0;

pub const ROLE_GUARD: &str = "guard";
pub const ROLE_MIDDLE: &str = "middle";
pub const ROLE_EXIT: &str = "exit";

const DEFAULT_SUBNET_PREFIX_V4: u8 = 16;
const DEFAULT_SUBNET_PREFIX_V6: u8 = 32;

const KEY_LEN: usize = 32;
const SIG_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Base class for every directory failure (one-enum-plus-aliases, same
/// pattern as `HandshakeError`/`OnionError`/`CircuitBuildError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryError {
    Generic(String),
    SignatureInvalid(String),
    DescriptorExpired(String),
    DescriptorMalformed(String),
    DescriptorLifetimeTooLong(String),
    PreferredGuardUnavailable(String),
    SybilRateLimited(String),
    /// The directory holds `max_descriptors` live relays, every one of
    /// them has republished at least once, and a brand-new identity
    /// asked to be added. See [`Directory::make_room`].
    DirectoryFull(String),
}
impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DirectoryError::Generic(s)
            | DirectoryError::SignatureInvalid(s)
            | DirectoryError::DescriptorExpired(s)
            | DirectoryError::DescriptorMalformed(s)
            | DirectoryError::DescriptorLifetimeTooLong(s)
            | DirectoryError::PreferredGuardUnavailable(s)
            | DirectoryError::SybilRateLimited(s)
            | DirectoryError::DirectoryFull(s) => write!(f, "{s}"),
        }
    }
}
impl std::error::Error for DirectoryError {}

/// A descriptor's signature did not verify against its advertised identity.
pub type SignatureInvalid = DirectoryError;
/// A descriptor was outside its validity window when used.
pub type DescriptorExpired = DirectoryError;
/// A descriptor's version or signed extension block is structurally invalid.
pub type DescriptorMalformed = DirectoryError;
/// A descriptor's validity span exceeds this directory's accepted maximum.
pub type DescriptorLifetimeTooLong = DirectoryError;
/// `select_route` was asked to keep a specific guard that is not live.
pub type PreferredGuardUnavailable = DirectoryError;
/// A brand-new identity was refused for exceeding its subnet's rate limit.
pub type SybilRateLimited = DirectoryError;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Collapse an iterable of port numbers into sorted inclusive ranges.
pub fn ports_to_ranges(ports: &[u16]) -> Vec<(u16, u16)> {
    let mut ordered: Vec<u16> = ports.iter().copied().filter(|&p| p > 0).collect();
    ordered.sort_unstable();
    ordered.dedup();
    let mut ranges: Vec<(u16, u16)> = Vec::new();
    for port in ordered {
        if let Some(last) = ranges.last_mut() {
            if port == last.1 + 1 {
                last.1 = port;
                continue;
            }
        }
        ranges.push((port, port));
    }
    ranges
}

fn encode_ext_bandwidth(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn encode_ext_exit_ports(ranges: &[(u16, u16)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + ranges.len() * 4);
    out.extend_from_slice(&(ranges.len() as u16).to_be_bytes());
    for (lo, hi) in ranges {
        out.extend_from_slice(&lo.to_be_bytes());
        out.extend_from_slice(&hi.to_be_bytes());
    }
    out
}

fn encode_ext_family(identities: &[[u8; KEY_LEN]]) -> Vec<u8> {
    let mut sorted: Vec<[u8; KEY_LEN]> = identities.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut out = Vec::with_capacity(sorted.len() * KEY_LEN);
    for k in sorted {
        out.extend_from_slice(&k);
    }
    out
}

fn parse_exit_ports(raw: &[u8]) -> Result<Vec<(u16, u16)>, DirectoryError> {
    if raw.len() < 2 {
        return Err(DirectoryError::DescriptorMalformed("exit port summary truncated".to_string()));
    }
    let count = u16::from_be_bytes([raw[0], raw[1]]) as usize;
    if raw.len() != 2 + 4 * count {
        return Err(DirectoryError::DescriptorMalformed("exit port summary length mismatch".to_string()));
    }
    let mut ranges = Vec::with_capacity(count);
    let mut previous_hi: u16 = 0;
    for i in 0..count {
        let off = 2 + 4 * i;
        let lo = u16::from_be_bytes([raw[off], raw[off + 1]]);
        let hi = u16::from_be_bytes([raw[off + 2], raw[off + 3]]);
        if lo < 1 || hi < lo || lo <= previous_hi {
            return Err(DirectoryError::DescriptorMalformed(
                "exit port ranges must be sorted, non-empty and non-overlapping".to_string(),
            ));
        }
        previous_hi = hi;
        ranges.push((lo, hi));
    }
    Ok(ranges)
}

/// A grouping key for a host's address block (see `subnet_key`).
///
/// `pub`: also used by `consensus.rs`, which carries each authority's own
/// observed subnet per relay as part of its signed vote (see
/// `Vote::entries`), so a client can tell whether two relays are actually
/// on the same network without trusting either relay's own self-declared
/// `host`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubnetKey {
    V4([u8; 2]),
    V6([u8; 4]),
}

/// Return `host`'s address-block grouping key, or `None` if it isn't a plain
/// IPv4/IPv6 literal (a hostname stays unclassifiable and unrestricted).
/// `DEFAULT_SUBNET_PREFIX_V4`/`_V6` (16 and 32 bits) are exactly 2 and 4
/// whole octets, so the grouping key is simply that many leading octets.
fn subnet_key(host: &str) -> Option<SubnetKey> {
    debug_assert_eq!(DEFAULT_SUBNET_PREFIX_V4, 16);
    debug_assert_eq!(DEFAULT_SUBNET_PREFIX_V6, 32);
    match host.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(SubnetKey::V4([o[0], o[1]]))
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            Some(SubnetKey::V6([o[0], o[1], o[2], o[3]]))
        }
    }
}

fn now_unix() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64()
}

// ---------------------------------------------------------------------------
// RelayDescriptor
// ---------------------------------------------------------------------------

/// A relay's self-signed record: who it is, where, and what it will do.
///
/// The signature covers every field (see [`RelayDescriptor::signing_payload`]).
#[derive(Debug, Clone, PartialEq)]
pub struct RelayDescriptor {
    pub identity_public: [u8; KEY_LEN],
    pub static_public: [u8; KEY_LEN],
    pub host: String,
    pub port: u16,
    pub roles: Vec<String>,
    pub not_before: f64,
    pub not_after: f64,
    pub signature: Vec<u8>,
    pub version: u32,
    /// v2 only: `(type, value)` pairs sorted by type, all signed.
    pub extensions: Vec<(u8, Vec<u8>)>,
}

/// Optional extensions for [`RelayDescriptor::create`], mirroring Python's
/// keyword-only arguments.
#[derive(Debug, Clone, Default)]
pub struct CreateOptions {
    pub bandwidth: Option<u64>,
    pub exit_ports: Option<Vec<u16>>,
    pub family: Option<Vec<[u8; KEY_LEN]>>,
    pub pq_kem_public: Option<Vec<u8>>,
    pub extra_extensions: Vec<(u8, Vec<u8>)>,
    pub version: Option<u32>,
}

impl RelayDescriptor {
    pub fn extension(&self, ext_type: u8) -> Option<&[u8]> {
        self.extensions.iter().find(|(t, _)| *t == ext_type).map(|(_, v)| v.as_slice())
    }

    /// Advertised bytes/second, or 0 if not advertised.
    pub fn bandwidth(&self) -> u64 {
        match self.extension(EXT_BANDWIDTH) {
            Some(raw) if raw.len() == 8 => u64::from_be_bytes(raw.try_into().unwrap()),
            _ => 0,
        }
    }

    /// Accepted TCP port ranges, or `None` when unknown.
    pub fn exit_port_ranges(&self) -> Option<Vec<(u16, u16)>> {
        let raw = self.extension(EXT_EXIT_PORTS)?;
        Some(parse_exit_ports(raw).unwrap_or_default())
    }

    /// Identities this relay *declares* as family (not necessarily mutual).
    pub fn family(&self) -> Vec<[u8; KEY_LEN]> {
        match self.extension(EXT_FAMILY) {
            Some(raw) if !raw.is_empty() && raw.len() % KEY_LEN == 0 => {
                raw.chunks(KEY_LEN).map(|c| c.try_into().unwrap()).collect()
            }
            _ => Vec::new(),
        }
    }

    /// Decoded `EXT_REACHABILITY`, or `None` for a directly reachable relay.
    pub fn reachability(&self) -> Option<Reachability> {
        let raw = self.extension(EXT_REACHABILITY)?;
        decode_reachability(raw).ok()
    }

    /// The relay's advertised ML-KEM-768 encapsulation key, or `None`.
    pub fn pq_kem_public(&self) -> Option<&[u8]> {
        match self.extension(EXT_PQ_KEM) {
            Some(raw) if raw.len() == PQ_KEM_LEN => Some(raw),
            _ => None,
        }
    }

    /// Whether this relay is only reachable via hole-punching.
    pub fn behind_nat(&self) -> bool {
        self.extension(EXT_REACHABILITY).is_some()
    }

    /// `Some(true)`/`Some(false)` from the port summary, `None` if unknown.
    pub fn allows_exit_port(&self, port: u16) -> Option<bool> {
        let ranges = self.exit_port_ranges()?;
        Some(ranges.iter().any(|&(lo, hi)| lo <= port && port <= hi))
    }

    /// The exact bytes the signature covers (everything but the signature).
    pub fn signing_payload(&self) -> Vec<u8> {
        if self.version == DESCRIPTOR_VERSION_2 {
            return self.signing_payload_v2();
        }
        let host = self.host.as_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(b"allium-descriptor-v1");
        out.extend_from_slice(&(host.len() as u16).to_be_bytes());
        out.extend_from_slice(host);
        out.extend_from_slice(&(self.port).to_be_bytes());
        out.extend_from_slice(&self.not_before.to_be_bytes());
        out.extend_from_slice(&self.not_after.to_be_bytes());
        out.extend_from_slice(&self.identity_public);
        out.extend_from_slice(&self.static_public);
        out.extend_from_slice(sorted_roles(&self.roles).as_bytes());
        out
    }

    fn signing_payload_v2(&self) -> Vec<u8> {
        let host = self.host.as_bytes();
        let roles = sorted_roles(&self.roles);
        let roles = roles.as_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(b"allium-descriptor-v2");
        out.extend_from_slice(&self.identity_public);
        out.extend_from_slice(&self.static_public);
        out.extend_from_slice(&(host.len() as u16).to_be_bytes());
        out.extend_from_slice(host);
        out.extend_from_slice(&(self.port).to_be_bytes());
        out.extend_from_slice(&(roles.len() as u16).to_be_bytes());
        out.extend_from_slice(roles);
        out.extend_from_slice(&self.not_before.to_be_bytes());
        out.extend_from_slice(&self.not_after.to_be_bytes());
        out.push(self.extensions.len() as u8);
        for (ext_type, value) in &self.extensions {
            out.push(*ext_type);
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
            out.extend_from_slice(value);
        }
        out
    }

    /// Validate version and extension block (not the signature).
    pub fn check_structure(&self) -> Result<(), DirectoryError> {
        if self.version != DESCRIPTOR_VERSION_1 && self.version != DESCRIPTOR_VERSION_2 {
            return Err(DirectoryError::DescriptorMalformed(format!("unknown descriptor version {}", self.version)));
        }
        if self.version == DESCRIPTOR_VERSION_1 {
            if !self.extensions.is_empty() {
                return Err(DirectoryError::DescriptorMalformed("a v1 descriptor cannot carry extensions".to_string()));
            }
            return Ok(());
        }
        if self.extensions.len() > MAX_EXTENSIONS {
            return Err(DirectoryError::DescriptorMalformed(format!("more than {MAX_EXTENSIONS} extensions")));
        }
        let mut previous: i32 = -1;
        for (ext_type, value) in &self.extensions {
            let ext_type_i = *ext_type as i32;
            if ext_type_i <= previous {
                return Err(DirectoryError::DescriptorMalformed("extension types must be strictly increasing".to_string()));
            }
            previous = ext_type_i;
            if value.len() > MAX_EXTENSION_LEN {
                return Err(DirectoryError::DescriptorMalformed(format!("extension {ext_type} is too long")));
            }
            if *ext_type == EXT_BANDWIDTH && value.len() != 8 {
                return Err(DirectoryError::DescriptorMalformed("bandwidth extension must be 8 bytes".to_string()));
            }
            if *ext_type == EXT_EXIT_PORTS {
                parse_exit_ports(value)?;
            }
            if *ext_type == EXT_PQ_KEM && value.len() != PQ_KEM_LEN {
                return Err(DirectoryError::DescriptorMalformed(format!("ML-KEM key must be {PQ_KEM_LEN} bytes")));
            }
            if *ext_type == EXT_REACHABILITY {
                decode_reachability(value)
                    .map_err(|e: NatError| DirectoryError::DescriptorMalformed(format!("bad reachability extension: {e}")))?;
            }
            if *ext_type == EXT_FAMILY {
                if value.len() % KEY_LEN != 0 || value.len() / KEY_LEN > MAX_FAMILY {
                    return Err(DirectoryError::DescriptorMalformed(format!(
                        "family extension must be up to {MAX_FAMILY} 32-byte identities"
                    )));
                }
                let members: Vec<&[u8]> = value.chunks(KEY_LEN).collect();
                let mut sorted_unique: Vec<&[u8]> = members.clone();
                sorted_unique.sort_unstable();
                sorted_unique.dedup();
                if members != sorted_unique {
                    return Err(DirectoryError::DescriptorMalformed("family members must be sorted and unique".to_string()));
                }
                if members.iter().any(|m| *m == self.identity_public) {
                    return Err(DirectoryError::DescriptorMalformed("a relay cannot list itself as family".to_string()));
                }
            }
        }
        Ok(())
    }

    /// Whether the descriptor is inside its validity window.
    pub fn is_valid_at(&self, now: Option<f64>) -> bool {
        let now = now.unwrap_or_else(now_unix);
        self.not_before <= now && now <= self.not_after
    }

    /// Check the self-signature.
    pub fn verify(&self, ops: &Ed25519Ops) -> Result<(), DirectoryError> {
        if self.identity_public.len() != KEY_LEN {
            return Err(DirectoryError::SignatureInvalid(format!("identity key must be {KEY_LEN} bytes")));
        }
        if self.static_public.len() != KEY_LEN {
            return Err(DirectoryError::SignatureInvalid(format!("static key must be {KEY_LEN} bytes")));
        }
        self.check_structure()?;
        if self.signature.len() != SIG_LEN {
            return Err(DirectoryError::SignatureInvalid("descriptor signature did not verify".to_string()));
        }
        let mut sig = [0u8; SIG_LEN];
        sig.copy_from_slice(&self.signature);
        if !(ops.verify)(&self.identity_public, &self.signing_payload(), &sig) {
            return Err(DirectoryError::SignatureInvalid("descriptor signature did not verify".to_string()));
        }
        Ok(())
    }

    /// Mint and sign a descriptor from a relay's Ed25519 private key.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        ops: &Ed25519Ops,
        identity_private: &[u8; KEY_LEN],
        static_public: &[u8; KEY_LEN],
        host: &str,
        port: u16,
        roles: &[&str],
        lifetime: f64,
        now: Option<f64>,
        options: CreateOptions,
    ) -> Result<RelayDescriptor, DirectoryError> {
        let now = now.unwrap_or_else(now_unix);
        let identity_public = (ops.public_of)(identity_private);
        let mut extensions: Vec<(u8, Vec<u8>)> = Vec::new();
        if let Some(bandwidth) = options.bandwidth {
            extensions.push((EXT_BANDWIDTH, encode_ext_bandwidth(bandwidth)));
        }
        if let Some(ports) = &options.exit_ports {
            extensions.push((EXT_EXIT_PORTS, encode_ext_exit_ports(&ports_to_ranges(ports))));
        }
        if let Some(family) = &options.family {
            let members: Vec<[u8; KEY_LEN]> = family.iter().copied().filter(|m| *m != identity_public).collect();
            if !members.is_empty() {
                extensions.push((EXT_FAMILY, encode_ext_family(&members)));
            }
        }
        if let Some(pq) = &options.pq_kem_public {
            extensions.push((EXT_PQ_KEM, pq.clone()));
        }
        for (t, v) in &options.extra_extensions {
            extensions.push((*t, v.clone()));
        }
        extensions.sort_by_key(|(t, _)| *t);
        let version = options.version.unwrap_or(CURRENT_DESCRIPTOR_VERSION);
        if version == DESCRIPTOR_VERSION_1 && !extensions.is_empty() {
            return Err(DirectoryError::DescriptorMalformed("a v1 descriptor cannot carry extensions".to_string()));
        }
        let unsigned = RelayDescriptor {
            identity_public,
            static_public: *static_public,
            host: host.to_string(),
            port,
            roles: roles.iter().map(|s| s.to_string()).collect(),
            not_before: now,
            not_after: now + lifetime,
            signature: Vec::new(),
            version,
            extensions,
        };
        unsigned.check_structure()?;
        let signature = (ops.sign)(identity_private, &unsigned.signing_payload());
        Ok(RelayDescriptor { signature: signature.to_vec(), ..unsigned })
    }

    /// The relay's `(host, port)`.
    pub fn endpoint(&self) -> (String, u16) {
        (self.host.clone(), self.port)
    }
}

fn sorted_roles(roles: &[String]) -> String {
    let mut r: Vec<&str> = roles.iter().map(|s| s.as_str()).collect();
    r.sort_unstable();
    r.join(",")
}

impl fmt::Display for RelayDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RelayDescriptor(v{} {}:{}, roles={:?}, valid_until={:.0})",
            self.version, self.host, self.port, self.roles, self.not_after
        )
    }
}

// ---------------------------------------------------------------------------
// Route RNG (see module docs: seeded path is a documented deviation)
// ---------------------------------------------------------------------------

/// A small, reproducible PRNG for the seeded (test-only) route-selection
/// path -- NOT a port of Python's seeded `random.Random`/Mersenne Twister
/// (see module docs). splitmix64.
struct SeededRng {
    state: u64,
}
impl SeededRng {
    fn new(seed: u64) -> SeededRng {
        SeededRng { state: seed }
    }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn random(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn choice_index(&mut self, len: usize) -> usize {
        (self.next_u64() as usize) % len
    }
}

enum RouteRng {
    Seeded(SeededRng),
    Secure,
}
impl RouteRng {
    fn new(seed: Option<u64>) -> RouteRng {
        match seed {
            Some(s) => RouteRng::Seeded(SeededRng::new(s)),
            None => RouteRng::Secure,
        }
    }
    fn random(&mut self) -> Result<f64, DirectoryError> {
        match self {
            RouteRng::Seeded(r) => Ok(r.random()),
            RouteRng::Secure => {
                let mut buf = [0u8; 8];
                secure_random(&mut buf)?;
                Ok((u64::from_be_bytes(buf) >> 11) as f64 / (1u64 << 53) as f64)
            }
        }
    }
    fn choice_index(&mut self, len: usize) -> Result<usize, DirectoryError> {
        match self {
            RouteRng::Seeded(r) => Ok(r.choice_index(len)),
            RouteRng::Secure => {
                let mut buf = [0u8; 8];
                secure_random(&mut buf)?;
                Ok((u64::from_be_bytes(buf) as usize) % len)
            }
        }
    }
}

fn secure_random(buf: &mut [u8]) -> Result<(), DirectoryError> {
    crate::osrand::os_random(buf).map_err(|e| DirectoryError::Generic(e.to_string()))
}

// ---------------------------------------------------------------------------
// Directory
// ---------------------------------------------------------------------------

/// A verifying store of relay descriptors.
pub struct Directory {
    authorities: std::collections::HashSet<[u8; KEY_LEN]>,
    clock: Box<dyn Fn() -> f64 + Send>,
    by_identity: HashMap<[u8; KEY_LEN], RelayDescriptor>,
    max_new_identities_per_subnet: Option<u32>,
    subnet_window_seconds: f64,
    max_descriptor_lifetime: Option<f64>,
    subnet_new_identity_log: HashMap<SubnetKey, Vec<f64>>,
    /// The address block a descriptor's
    /// identity was actually seen publishing from (`publish_from`'s
    /// `source_addr`, the verified peer address of the directory
    /// circuit), keyed by identity. Both anti-Sybil defenses --
    /// `check_subnet_rate` and `select_take`'s `enforce_subnet_diversity`
    /// -- prefer this over the self-declared `descriptor.host` when it's
    /// available, since a relay's own descriptor is just another claim an
    /// operator running many "identities" can lie about. Updated on every
    /// publish that supplies a classifiable source address; never cleared,
    /// so a since-removed identity's last-known subnet lingers harmlessly
    /// (same non-cleanup precedent as `measured_bandwidth` below).
    verified_subnet: HashMap<[u8; KEY_LEN], SubnetKey>,
    measured_bandwidth: HashMap<[u8; KEY_LEN], u64>,
    /// Security audit fix (2026-09-26, finding #5 -- no vetting before
    /// self-declaring "guard"): wall-clock time this identity was first
    /// seen (self-populated on every publish, or seeded externally via
    /// [`Self::set_first_seen`] from a caller that persists it across
    /// [`Directory`] rebuilds -- this object's own lifetime is usually one
    /// fetch cycle, so without an external seed this is only ever "first
    /// seen by *this* `Directory` instance"). Never cleared, same
    /// non-cleanup precedent as `measured_bandwidth` above.
    first_seen: HashMap<[u8; KEY_LEN], f64>,
    /// When set, [`Self::select_route`]'s *unpinned* guard pick (never an
    /// explicit `preferred_guard`, which already carries its own trust --
    /// see the doc on `select_route`) is restricted to guards whose
    /// `first_seen` age is at least this many seconds. `None` (the
    /// default) disables the check entirely, matching every other
    /// existing `Directory` the way this codebase's tests already
    /// construct one.
    min_guard_age_seconds: Option<f64>,
    /// Identities this directory will accept as a relay's
    /// `EXT_REACHABILITY` introducer. Empty means
    /// unset/not configured -- every reachability extension is accepted
    /// as long as it merely parses (the pre-existing, permissive
    /// behavior), so an authority that hasn't been given its own
    /// identity via [`DirectoryOptions::known_introducers`] doesn't
    /// silently start rejecting every NAT-relay descriptor. See
    /// `allium-authority-cli`'s `cmd_authority`, which populates this
    /// with the authority's own identity.
    known_introducers: std::collections::HashSet<[u8; KEY_LEN]>,
    /// Hard ceiling on how many identities `by_identity` may hold at
    /// once. `None` disables it. See [`Self::make_room`] for what happens
    /// at the ceiling, and `DirectoryOptions::max_descriptors` for why the
    /// default is what it is.
    max_descriptors: Option<usize>,
    /// Ceiling on how many *live* identities may share one address block
    /// (the same `SubnetKey` the publish-rate limiter uses) at once.
    /// `None` disables it. The rate limiter bounds how *fast* a block can
    /// mint identities; this bounds how *many* it can hold open, so a
    /// block that drip-feeds under the rate limit for a day still cannot
    /// own more than this many slots of `max_descriptors`.
    max_live_identities_per_subnet: Option<u32>,
    /// Identities that have published at least twice -- i.e. come back to
    /// refresh a descriptor this directory already held. A relay that is
    /// actually running does this every lifetime; an identity minted
    /// once to fill a slot never does. [`Self::make_room`] evicts only
    /// from the never-refreshed set, which is what makes a flood of
    /// throwaway identities crowd out *itself* rather than the relays
    /// that were here first. Never cleared, same precedent as
    /// `measured_bandwidth`.
    republished: std::collections::HashSet<[u8; KEY_LEN]>,
    ops: Ed25519Ops,
}

/// Constructor options for [`Directory::new`], mirroring Python's
/// keyword-only `__init__` arguments.
pub struct DirectoryOptions {
    pub authorities: Vec<[u8; KEY_LEN]>,
    pub clock: Option<Box<dyn Fn() -> f64 + Send>>,
    pub max_new_identities_per_subnet: Option<u32>,
    pub subnet_window_seconds: f64,
    pub max_descriptor_lifetime: Option<f64>,
    /// See [`Directory`]'s field of the same name. Defaults to
    /// [`crate::dirwire::MAX_DESCRIPTOR_COUNT`] (4096), the most a
    /// FETCH_REPLY can carry: before this cap existed, an open authority
    /// pushed past that many live descriptors stopped answering FETCH and
    /// VOTE *entirely* (`encode_fetch_reply` failed, the error was
    /// `.ok()`-ed into silence), so one attacker with a few address
    /// blocks and a day of patience took every client offline. `None`
    /// disables the cap.
    pub max_descriptors: Option<usize>,
    /// See [`Directory`]'s field of the same name. Defaults to 64.
    pub max_live_identities_per_subnet: Option<u32>,
    /// See [`Directory`]'s field of the same name. Leave empty to keep
    /// the old permissive behavior;
    /// `allium-authority-cli` sets this to the authority's own identity.
    pub known_introducers: Vec<[u8; KEY_LEN]>,
    /// See [`Directory`]'s `min_guard_age_seconds` field doc. `None`
    /// (default) disables the check, preserving every existing caller's
    /// behavior; a live deployment opts in explicitly.
    pub min_guard_age_seconds: Option<f64>,
    pub ops: Ed25519Ops,
}
impl Default for DirectoryOptions {
    fn default() -> DirectoryOptions {
        DirectoryOptions {
            authorities: Vec::new(),
            clock: None,
            max_new_identities_per_subnet: Some(32),
            subnet_window_seconds: 3600.0,
            max_descriptor_lifetime: Some(MAX_DESCRIPTOR_LIFETIME),
            max_descriptors: Some(crate::dirwire::MAX_DESCRIPTOR_COUNT),
            max_live_identities_per_subnet: Some(64),
            known_introducers: Vec::new(),
            min_guard_age_seconds: None,
            ops: Ed25519Ops::real(),
        }
    }
}

impl Directory {
    pub fn new(options: DirectoryOptions) -> Result<Directory, DirectoryError> {
        if let Some(m) = options.max_new_identities_per_subnet {
            if m < 1 {
                return Err(DirectoryError::Generic(format!(
                    "max_new_identities_per_subnet must be at least 1 (or None to disable), got {m}"
                )));
            }
        }
        if let Some(m) = options.max_descriptor_lifetime {
            if m <= 0.0 {
                return Err(DirectoryError::Generic(format!(
                    "max_descriptor_lifetime must be positive (or None to disable), got {m}"
                )));
            }
        }
        if let Some(m) = options.max_descriptors {
            if m < 1 {
                return Err(DirectoryError::Generic(
                    "max_descriptors must be at least 1 (or None to disable), got 0".to_string(),
                ));
            }
        }
        if let Some(m) = options.max_live_identities_per_subnet {
            if m < 1 {
                return Err(DirectoryError::Generic(
                    "max_live_identities_per_subnet must be at least 1 (or None to disable), got 0".to_string(),
                ));
            }
        }
        Ok(Directory {
            authorities: options.authorities.into_iter().collect(),
            clock: options.clock.unwrap_or_else(|| Box::new(now_unix)),
            by_identity: HashMap::new(),
            max_new_identities_per_subnet: options.max_new_identities_per_subnet,
            subnet_window_seconds: options.subnet_window_seconds,
            max_descriptor_lifetime: options.max_descriptor_lifetime,
            subnet_new_identity_log: HashMap::new(),
            verified_subnet: HashMap::new(),
            measured_bandwidth: HashMap::new(),
            first_seen: HashMap::new(),
            min_guard_age_seconds: options.min_guard_age_seconds,
            known_introducers: options.known_introducers.into_iter().collect(),
            max_descriptors: options.max_descriptors,
            max_live_identities_per_subnet: options.max_live_identities_per_subnet,
            republished: std::collections::HashSet::new(),
            ops: options.ops,
        })
    }

    pub fn set_measured_bandwidth(&mut self, measurements: &[([u8; KEY_LEN], u64)]) {
        self.measured_bandwidth = measurements.iter().map(|(k, v)| (*k, *v)).collect();
    }

    /// Seed `first_seen` from a caller-maintained, externally persisted
    /// registry (this `Directory` object's own lifetime is normally one
    /// fetch cycle -- see the field's doc). Entries for identities this
    /// directory has not published yet are harmless no-ops until it does.
    pub fn set_first_seen(&mut self, entries: impl IntoIterator<Item = ([u8; KEY_LEN], f64)>) {
        self.first_seen = entries.into_iter().collect();
    }

    /// A snapshot of `first_seen`, for a caller to merge into its own
    /// persistent registry so this history survives past this `Directory`
    /// object's lifetime (see [`Self::set_first_seen`]).
    pub fn first_seen_snapshot(&self) -> HashMap<[u8; KEY_LEN], f64> {
        self.first_seen.clone()
    }

    /// Whether `d` has been observed long enough to be picked as an
    /// *unpinned* guard -- see `min_guard_age_seconds`'s doc. Always `true`
    /// when the check is disabled.
    fn guard_eligible(&self, d: &RelayDescriptor) -> bool {
        match self.min_guard_age_seconds {
            None => true,
            Some(min_age) => self.first_seen.get(&d.identity_public).is_some_and(|first| (self.clock)() - first >= min_age),
        }
    }

    /// The bandwidth weight `select_route` gives `descriptor`.
    pub fn selection_weight(&self, descriptor: &RelayDescriptor) -> u64 {
        if let Some(measured) = self.measured_bandwidth.get(&descriptor.identity_public) {
            return (*measured).max(1);
        }
        let advertised = descriptor.bandwidth();
        if advertised == 0 {
            return UNMEASURED_BANDWIDTH_WEIGHT;
        }
        advertised.min(MAX_SELF_REPORTED_BANDWIDTH).max(1)
    }

    /// Identities in `descriptor`'s *effective* family: itself, plus every
    /// live relay it declares that declares it back.
    pub fn family_of(&self, descriptor: &RelayDescriptor) -> std::collections::HashSet<[u8; KEY_LEN]> {
        let mut members = std::collections::HashSet::new();
        members.insert(descriptor.identity_public);
        for identity in descriptor.family() {
            if let Some(other) = self.get(&identity) {
                if other.family().contains(&descriptor.identity_public) {
                    members.insert(identity);
                }
            }
        }
        members
    }

    pub fn authorities(&self) -> &std::collections::HashSet<[u8; KEY_LEN]> {
        &self.authorities
    }

    fn check_subnet_rate(&mut self, descriptor: &RelayDescriptor, source_addr: Option<&str>, now: f64) -> Result<(), DirectoryError> {
        let limit = match self.max_new_identities_per_subnet {
            Some(l) => l as usize,
            None => return Ok(()),
        };
        if self.by_identity.contains_key(&descriptor.identity_public) {
            return Ok(());
        }
        // Classify by the verified source
        // address of this publish connection when we have one, never by
        // the self-declared `descriptor.host` alone -- otherwise a single
        // operator can mint unlimited "new identities" past this limiter
        // just by writing a different host string into each self-signed
        // descriptor. Falls back to `descriptor.host` only when no source
        // address was supplied (local/offline re-verification, e.g.
        // `fetch_relay_directory`), which never was network-authenticated
        // to begin with.
        let subnet = match subnet_key(source_addr.unwrap_or(&descriptor.host)) {
            Some(s) => s,
            None => return Ok(()),
        };
        let window_start = now - self.subnet_window_seconds;
        let log = self.subnet_new_identity_log.entry(subnet).or_default();
        log.retain(|t| *t > window_start);
        if log.len() >= limit {
            return Err(DirectoryError::SybilRateLimited(format!(
                "this address block has already published {} new identities in the last {}s (limit {limit}); this is not a rotation of a known identity",
                log.len(),
                self.subnet_window_seconds
            )));
        }
        log.push(now);
        Ok(())
    }

    /// Verify and store `descriptor`. Returns whether it was accepted (`false`
    /// only for a stale/older record for an identity already held).
    ///
    /// Equivalent to [`Self::publish_from`] with no known source address --
    /// prefer that when one is actually available (see its doc).
    pub fn publish(&mut self, descriptor: RelayDescriptor) -> Result<bool, DirectoryError> {
        self.publish_from(descriptor, None)
    }

    /// Like [`Self::publish`], but `source_addr` is the verified peer
    /// address this descriptor's publish request actually arrived from --
    /// e.g. the one-hop directory circuit's own registered peer address,
    /// which a client cannot forge without completing a real (and, with
    /// `require_return_routability`, cookie-verified) handshake from that
    /// address. Used instead of the self-declared `descriptor.host` for
    /// this directory's anti-Sybil subnet checks;
    /// pass `None` only when no such address exists (a purely local
    /// re-verification of an already-vetted descriptor, e.g.
    /// `fetch_relay_directory`).
    pub fn publish_from(&mut self, descriptor: RelayDescriptor, source_addr: Option<&str>) -> Result<bool, DirectoryError> {
        let now = self.validate_descriptor(&descriptor)?;
        if let Some(existing) = self.by_identity.get(&descriptor.identity_public) {
            // A rotation of an identity already held never has to clear
            // the capacity checks below: it takes no new slot.
            if existing.not_before > descriptor.not_before {
                return Ok(false);
            }
            self.republished.insert(descriptor.identity_public);
        } else {
            // A brand-new identity has to earn a slot. Checked before the
            // rate limiter so a refusal here doesn't also charge the
            // block's rate budget.
            self.check_live_subnet_cap(&descriptor, source_addr, now)?;
            self.make_room(now)?;
            self.check_subnet_rate(&descriptor, source_addr, now)?;
        }
        if let Some(subnet) = source_addr.and_then(subnet_key) {
            self.verified_subnet.insert(descriptor.identity_public, subnet);
        }
        self.first_seen.entry(descriptor.identity_public).or_insert(now);
        self.by_identity.insert(descriptor.identity_public, descriptor);
        Ok(true)
    }

    /// Refuse a *new* identity whose address block already holds
    /// `max_live_identities_per_subnet` live relays. Classified the same
    /// way as [`Self::check_subnet_rate`]: by the verified source address
    /// when there is one, by the self-declared host otherwise.
    fn check_live_subnet_cap(&self, descriptor: &RelayDescriptor, source_addr: Option<&str>, now: f64) -> Result<(), DirectoryError> {
        let Some(limit) = self.max_live_identities_per_subnet else { return Ok(()) };
        let Some(subnet) = subnet_key(source_addr.unwrap_or(&descriptor.host)) else { return Ok(()) };
        let live = self
            .by_identity
            .values()
            .filter(|d| d.is_valid_at(Some(now)) && self.subnet_of(d) == Some(subnet))
            .count();
        if live >= limit as usize {
            return Err(DirectoryError::SybilRateLimited(format!(
                "this address block already has {live} live relays registered (limit {limit}); \
                 a new identity from it is refused until one of them expires"
            )));
        }
        Ok(())
    }

    /// Free a slot for a new identity if the directory is at
    /// `max_descriptors`, or say why it can't.
    ///
    /// Expired descriptors go first -- they would have gone at the next
    /// prune anyway. If the directory is still full, the victim is the
    /// never-republished identity with the shortest tenure (latest
    /// `first_seen`). A running relay refreshes its descriptor every
    /// lifetime and so leaves the never-republished set after its first
    /// refresh; an identity minted once to fill a slot never does. So a
    /// flood of throwaway identities can only ever push out *other*
    /// throwaway identities, newest first, and a genuine new relay still
    /// gets in by displacing one of them. Only when every held identity
    /// has proven itself by refreshing is a newcomer refused outright.
    fn make_room(&mut self, now: f64) -> Result<(), DirectoryError> {
        let Some(max) = self.max_descriptors else { return Ok(()) };
        if self.by_identity.len() < max {
            return Ok(());
        }
        self.by_identity.retain(|_, d| d.is_valid_at(Some(now)));
        if self.by_identity.len() < max {
            return Ok(());
        }
        let tenure_start = |k: &[u8; KEY_LEN]| self.first_seen.get(k).copied().unwrap_or(f64::NEG_INFINITY);
        let victim = self
            .by_identity
            .keys()
            .filter(|k| !self.republished.contains(*k))
            .max_by(|a, b| {
                tenure_start(a)
                    .partial_cmp(&tenure_start(b))
                    .unwrap_or(std::cmp::Ordering::Equal)
                    // Deterministic among equal timestamps.
                    .then_with(|| a.cmp(b))
            })
            .copied();
        match victim {
            Some(k) => {
                self.by_identity.remove(&k);
                Ok(())
            }
            None => Err(DirectoryError::DirectoryFull(format!(
                "this directory already holds its maximum of {max} relays, all of which have refreshed \
                 their descriptors at least once; a new identity is refused until one of them expires"
            ))),
        }
    }

    /// The live descriptors this authority serves and votes on, at most
    /// `limit` of them, sorted by endpoint.
    ///
    /// With the default `max_descriptors` the limit is never reached and
    /// this is just [`Self::all`]. If an operator raises the cap past what
    /// one FETCH_REPLY can carry, this keeps the reply encodable instead
    /// of letting the encode error turn into no reply at all, preferring
    /// the relays with the longest record: republished ones before
    /// never-republished ones, earliest `first_seen` first. FETCH and VOTE
    /// must go through the same function so the digests a client checks
    /// against the vote are those of the descriptors it was sent.
    pub fn serving_set(&self, limit: usize) -> Vec<&RelayDescriptor> {
        let mut found = self.all();
        if found.len() <= limit {
            return found;
        }
        let tenure_start = |d: &RelayDescriptor| self.first_seen.get(&d.identity_public).copied().unwrap_or(f64::INFINITY);
        found.sort_by(|a, b| {
            let ra = self.republished.contains(&a.identity_public);
            let rb = self.republished.contains(&b.identity_public);
            rb.cmp(&ra)
                .then_with(|| tenure_start(a).partial_cmp(&tenure_start(b)).unwrap_or(std::cmp::Ordering::Equal))
                .then_with(|| a.endpoint().cmp(&b.endpoint()))
        });
        found.truncate(limit);
        found.sort_by(|a, b| a.endpoint().cmp(&b.endpoint()));
        found
    }

    /// Shared prefix of [`Self::publish_from`]/[`Self::publish_verified`]:
    /// signature, trusted-authority membership (if configured), the
    /// known-introducer check, and lifetime/expiry checks. Returns the
    /// current clock reading, which both callers need next.
    fn validate_descriptor(&self, descriptor: &RelayDescriptor) -> Result<f64, DirectoryError> {
        descriptor.verify(&self.ops)?;
        if !self.authorities.is_empty() && !self.authorities.contains(&descriptor.identity_public) {
            return Err(DirectoryError::SignatureInvalid("descriptor identity is not a trusted directory authority".to_string()));
        }
        // A relay's `EXT_REACHABILITY` introducer is otherwise just
        // another claim in a self-signed descriptor -- nothing stopped a
        // relay from naming itself, an accomplice, or any other made-up
        // identity/address as the introducer a client would later be told
        // to hole-punch through. `check_structure` only ever confirmed
        // the extension *parses*. When this directory has been given a
        // known-introducer set (see `Directory`'s field doc), reject
        // anything that names an introducer outside it, rather than
        // merely storing and serving it to every client that fetches this
        // descriptor.
        if !self.known_introducers.is_empty() {
            if let Some(reach) = descriptor.reachability() {
                let identity: Option<[u8; KEY_LEN]> = reach.introducer_identity.as_slice().try_into().ok();
                let allowed = matches!(identity, Some(id) if self.known_introducers.contains(&id));
                if !allowed {
                    return Err(DirectoryError::DescriptorMalformed(format!(
                        "reachability extension for {}:{} names an introducer this directory does not recognize as a known authority",
                        descriptor.host, descriptor.port
                    )));
                }
            }
        }
        if let Some(max_lifetime) = self.max_descriptor_lifetime {
            let lifetime = descriptor.not_after - descriptor.not_before;
            if lifetime > max_lifetime {
                return Err(DirectoryError::DescriptorLifetimeTooLong(format!(
                    "descriptor for {}:{} claims a {lifetime}s validity window, longer than the {max_lifetime}s this directory accepts",
                    descriptor.host, descriptor.port
                )));
            }
        }
        let now = (self.clock)();
        if !descriptor.is_valid_at(Some(now)) {
            return Err(DirectoryError::DescriptorExpired(format!(
                "descriptor for {}:{} is outside its validity window",
                descriptor.host, descriptor.port
            )));
        }
        Ok(now)
    }

    /// Verify and store `descriptor` using a quorum-verified subnet
    /// (aggregated across a quorum of authorities' own votes, via
    /// `consensus::compute_consensus`), rather than a raw per-connection
    /// source address.
    ///
    /// This is what [`fetch_relay_directory`] uses: it has no live network
    /// connection to each relay to observe an address from directly, the
    /// way an authority does at PUBLISH time -- only the quorum-of-
    /// authorities' own independent observations, each carried in their
    /// signed vote and aggregated by [`crate::consensus::compute_consensus`]
    /// before this is ever called. A single authority's claim alone is
    /// never trusted, matching the same Byzantine-tolerance already
    /// applied to descriptor digests and measured bandwidth.
    ///
    /// Unlike [`Self::publish_from`], this never applies
    /// [`Self::check_subnet_rate`]: that mechanism bounds how fast an
    /// authority accepts brand-new identities live over the wire, which
    /// has no meaning when merely reconstructing an already-quorum-agreed
    /// view of the network.
    pub(crate) fn publish_verified(&mut self, descriptor: RelayDescriptor, verified_subnet: Option<SubnetKey>) -> Result<bool, DirectoryError> {
        let now = self.validate_descriptor(&descriptor)?;
        if let Some(existing) = self.by_identity.get(&descriptor.identity_public) {
            if existing.not_before > descriptor.not_before {
                return Ok(false);
            }
        }
        if let Some(subnet) = verified_subnet {
            self.verified_subnet.insert(descriptor.identity_public, subnet);
        }
        self.first_seen.entry(descriptor.identity_public).or_insert(now);
        self.by_identity.insert(descriptor.identity_public, descriptor);
        Ok(true)
    }

    /// This directory's own currently-recorded verified subnet for
    /// `identity`, if any -- used by an authority's own vote-signing to
    /// report what it has itself observed (see `consensus::Vote::entries`).
    pub(crate) fn verified_subnet_of(&self, identity: &[u8; KEY_LEN]) -> Option<SubnetKey> {
        self.verified_subnet.get(identity).copied()
    }

    /// Drop a relay by identity key, returning whether it was present.
    pub fn remove(&mut self, identity_public: &[u8; KEY_LEN]) -> bool {
        self.by_identity.remove(identity_public).is_some()
    }

    /// Drop expired descriptors, returning how many were removed.
    pub fn prune(&mut self) -> usize {
        let now = (self.clock)();
        let stale: Vec<[u8; KEY_LEN]> = self
            .by_identity
            .iter()
            .filter(|(_, d)| !d.is_valid_at(Some(now)))
            .map(|(k, _)| *k)
            .collect();
        for k in &stale {
            self.by_identity.remove(k);
        }
        stale.len()
    }

    /// Return a live descriptor for an identity, or `None`.
    pub fn get(&self, identity_public: &[u8; KEY_LEN]) -> Option<&RelayDescriptor> {
        let d = self.by_identity.get(identity_public)?;
        if !d.is_valid_at(Some((self.clock)())) {
            return None;
        }
        Some(d)
    }

    /// Live descriptors whose roles include `role`, sorted by endpoint.
    pub fn by_role(&self, role: &str) -> Vec<&RelayDescriptor> {
        let now = (self.clock)();
        let mut found: Vec<&RelayDescriptor> = self
            .by_identity
            .values()
            .filter(|d| d.roles.iter().any(|r| r == role) && d.is_valid_at(Some(now)))
            .collect();
        found.sort_by(|a, b| a.endpoint().cmp(&b.endpoint()));
        found
    }

    /// Every live descriptor, sorted by endpoint.
    pub fn all(&self) -> Vec<&RelayDescriptor> {
        let now = (self.clock)();
        let mut found: Vec<&RelayDescriptor> = self.by_identity.values().filter(|d| d.is_valid_at(Some(now))).collect();
        found.sort_by(|a, b| a.endpoint().cmp(&b.endpoint()));
        found
    }

    pub fn len(&self) -> usize {
        self.all().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `d`'s address-block grouping key for subnet-diversity purposes:
    /// the verified subnet it was last seen publishing from when known,
    /// falling back to its self-declared `host`
    /// only for a descriptor this directory never saw published (e.g. one
    /// loaded via `publish` with no source address).
    fn subnet_of(&self, d: &RelayDescriptor) -> Option<SubnetKey> {
        self.verified_subnet.get(&d.identity_public).copied().or_else(|| subnet_key(&d.host))
    }

    /// Options for [`Directory::select_route`], mirroring Python's
    /// keyword-only arguments.
    #[allow(clippy::too_many_arguments)]
    pub fn select_route(&self, options: SelectRouteOptions) -> Result<Vec<RelayDescriptor>, DirectoryError> {
        let hops = options.hops;
        if hops < 1 {
            return Err(DirectoryError::Generic(format!("hops must be at least 1, got {hops}")));
        }
        let mut rng = RouteRng::new(options.seed);
        let guards: Vec<&RelayDescriptor> = self.by_role(ROLE_GUARD).into_iter().filter(|d| !d.behind_nat()).collect();
        let exits: Vec<&RelayDescriptor> = self.by_role(ROLE_EXIT);
        let middles: Vec<&RelayDescriptor> = self.by_role(ROLE_MIDDLE);

        let mut chosen: Vec<RelayDescriptor> = Vec::new();
        let mut used: std::collections::HashSet<[u8; KEY_LEN]> = options.exclude_identities.iter().copied().collect();
        let mut used_subnets: std::collections::HashSet<SubnetKey> = std::collections::HashSet::new();

        let mut pinned_guard: Option<RelayDescriptor> = None;
        if let Some(preferred) = options.preferred_guard {
            pinned_guard = guards.iter().find(|d| d.identity_public == preferred).map(|d| (*d).clone());
            if pinned_guard.is_none() && options.require_preferred_guard {
                return Err(DirectoryError::PreferredGuardUnavailable(
                    "preferred guard is not among the currently live guards".to_string(),
                ));
            }
        }
        if let Some(pg) = &pinned_guard {
            if options.require_pq && pg.pq_kem_public().is_none() {
                if options.require_preferred_guard {
                    return Err(DirectoryError::PreferredGuardUnavailable(
                        "preferred guard does not advertise a post-quantum key".to_string(),
                    ));
                }
                pinned_guard = None;
            }
        }
        if let Some(pg) = pinned_guard {
            self.mark_used(&mut used, &pg);
            if let Some(subnet) = self.subnet_of(&pg) {
                used_subnets.insert(subnet);
            }
            chosen.push(pg);
        } else {
            // Security audit fix (2026-09-26, finding #5): a *pinned*
            // preferred guard (handled above) already carries its own
            // trust basis -- typically a previous session's own choice,
            // persisted to disk -- so it is exempt. An unpinned pick,
            // picking a guard for the first time with nothing but its own
            // self-declared "guard" role to go on, is exactly the case
            // this vets: restrict the pool to guards this directory has
            // actually observed for `min_guard_age_seconds`, when set.
            let vetted_guards: Vec<&RelayDescriptor> = guards.iter().copied().filter(|d| self.guard_eligible(d)).collect();
            if vetted_guards.is_empty() && !guards.is_empty() && self.min_guard_age_seconds.is_some() {
                return Err(DirectoryError::Generic(format!(
                    "{} self-declared guard(s) are live, but none has been observed for the required {:.0}s yet -- a brand-new identity cannot claim the guard role on day one; try again once this directory has accumulated guard history",
                    guards.len(),
                    self.min_guard_age_seconds.unwrap(),
                )));
            }
            self.select_take(&options, &mut rng, &mut used, &mut used_subnets, &mut chosen, &vetted_guards, "guard")?;
        }
        for _ in 0..hops.saturating_sub(2) {
            self.select_take(&options, &mut rng, &mut used, &mut used_subnets, &mut chosen, &middles, "middle")?;
        }
        if hops >= 2 {
            self.select_take(&options, &mut rng, &mut used, &mut used_subnets, &mut chosen, &exits, "exit")?;
        }
        Ok(chosen)
    }

    fn mark_used(&self, used: &mut std::collections::HashSet<[u8; KEY_LEN]>, pick: &RelayDescriptor) {
        used.insert(pick.identity_public);
        used.extend(self.family_of(pick));
    }

    fn pick_weighted(&self, options: &SelectRouteOptions, rng: &mut RouteRng, candidates: &[&RelayDescriptor]) -> Result<RelayDescriptor, DirectoryError> {
        if !options.weight_by_bandwidth {
            let idx = rng.choice_index(candidates.len())?;
            return Ok(candidates[idx].clone());
        }
        let weights: Vec<u64> = candidates.iter().map(|d| self.selection_weight(d)).collect();
        let all_same = weights.iter().all(|w| *w == weights[0]);
        if all_same {
            let idx = rng.choice_index(candidates.len())?;
            return Ok(candidates[idx].clone());
        }
        let total: u64 = weights.iter().sum();
        let point = rng.random()? * (total as f64);
        let mut running: u64 = 0;
        for (d, w) in candidates.iter().zip(weights.iter()) {
            running += w;
            if point < running as f64 {
                return Ok((*d).clone());
            }
        }
        Ok(candidates[candidates.len() - 1].clone())
    }

    #[allow(clippy::too_many_arguments)]
    fn select_take(
        &self,
        options: &SelectRouteOptions,
        rng: &mut RouteRng,
        used: &mut std::collections::HashSet<[u8; KEY_LEN]>,
        used_subnets: &mut std::collections::HashSet<SubnetKey>,
        chosen: &mut Vec<RelayDescriptor>,
        pool: &[&RelayDescriptor],
        label: &str,
    ) -> Result<(), DirectoryError> {
        let mut candidates: Vec<&RelayDescriptor> = pool.iter().copied().filter(|d| !used.contains(&d.identity_public)).collect();
        if options.require_pq {
            candidates.retain(|d| d.pq_kem_public().is_some());
        }
        if label == "exit" {
            if let Some(port) = options.exit_port {
                let accepting: Vec<&RelayDescriptor> = candidates.iter().copied().filter(|d| d.allows_exit_port(port) == Some(true)).collect();
                let unknown: Vec<&RelayDescriptor> = candidates.iter().copied().filter(|d| d.allows_exit_port(port).is_none()).collect();
                candidates = if !accepting.is_empty() { accepting } else { unknown };
                if candidates.is_empty() {
                    return Err(DirectoryError::Generic(format!("no live exit accepts port {port}")));
                }
            }
        }
        if candidates.is_empty() {
            return Err(DirectoryError::Generic(format!("no live relay available for the {label} position")));
        }
        if options.enforce_subnet_diversity {
            let diverse: Vec<&RelayDescriptor> = candidates
                .iter()
                .copied()
                .filter(|d| match self.subnet_of(d) {
                    Some(s) => !used_subnets.contains(&s),
                    None => true,
                })
                .collect();
            if !diverse.is_empty() {
                candidates = diverse;
            }
        }
        let pick = self.pick_weighted(options, rng, &candidates)?;
        self.mark_used(used, &pick);
        if let Some(subnet) = self.subnet_of(&pick) {
            used_subnets.insert(subnet);
        }
        chosen.push(pick);
        Ok(())
    }
}

impl fmt::Debug for Directory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Directory(relays={}, authorities={})", self.by_identity.len(), self.authorities.len())
    }
}

// ---------------------------------------------------------------------------
// Directory client: fetching a live relay set from a `--authority`
// ---------------------------------------------------------------------------
//
// Port of `allium_cli.py`'s `_dir_round_trip`/`fetch_relay_directory`
// (the "legacy FETCH" path -- see this module's own docs below for the one
// deliberate scope reduction from Python's full N-of-M signed-vote quorum
// consensus, which this port does not reproduce).
//
// **Written but unverified pending real cargo build** (see the crate's
// top-level README.md): this is `tokio`-free (it reuses `CircuitBuilder`,
// the same synchronous, blocking-socket client `allium-cli`'s `client`
// subcommand already builds its 3-hop circuit with -- see `circuit.rs`'s
// module docs for why that's a deliberate design choice, not an
// oversight), but it has never been run against a live authority in this
// sandbox.

/// Generous ceiling on one directory round trip (one-hop handshake, send,
/// receive), independent of any circuit's own `--timeout`: a directory
/// exchange is a handful of small cells, never a long-lived interactive
/// session. Matches `allium_cli.py`'s `DIR_ROUND_TRIP_TIMEOUT`.
pub const DIR_ROUND_TRIP_TIMEOUT: f64 = 5.0;

/// Open an ephemeral one-hop circuit to `authority_addr`, send one
/// directory-protocol request, and return the reassembled reply bytes.
///
/// Mirrors Python's `_dir_round_trip`: a fresh UDP socket per call (bound to
/// an OS-assigned ephemeral port, closed when this returns), a
/// [`CircuitBuilder`] with one hop named `"authority"` (so `trusted`, if
/// given, pins that hop's identity the same way a client's guard/middle/exit
/// hops are pinned), the request fragmented via
/// [`fragment_message_default`], and the reply reassembled via
/// [`DirReassembler`]. `trusted == None` means `trust_first_use` for this
/// one hop -- exactly as risky as it sounds; see [`fetch_relay_directory`]
/// and `allium-cli`'s `--allow-unpinned-authority` flag, which is the only
/// caller allowed to pass `None` here without the operator having said so
/// explicitly.
///
/// Timeouts match Python exactly: the one-hop handshake gets
/// [`DIR_ROUND_TRIP_TIMEOUT`] (5s) with one retry (two attempts total, via
/// `CircuitBuilder`'s own `retries` parameter); the overall
/// receive-and-reassemble loop gets `max(DIR_ROUND_TRIP_TIMEOUT * 4, 10.0)`
/// (20s) wall-clock, polling `receive` with a `DIR_ROUND_TRIP_TIMEOUT`
/// (5s) timeout each iteration and silently retrying on a bare timeout or a
/// foreign/malformed datagram (matching Python's `except OSError: continue`).
pub fn dir_round_trip(authority_addr: &Addr, trusted: Option<Vec<[u8; KEY_LEN]>>, request_bytes: &[u8]) -> Result<Vec<u8>, DirectoryError> {
    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| DirectoryError::Generic(format!("could not open a UDP socket for the directory round trip: {e}")))?;
    let trust_first_use = trusted.is_none();
    let mut trusted_map: HashMap<String, Vec<[u8; KEY_LEN]>> = HashMap::new();
    if let Some(keys) = trusted {
        trusted_map.insert("authority".to_string(), keys);
    }
    let mut builder = CircuitBuilder::new(
        &sock,
        DEFAULT_CIPHER.to_string(),
        DIR_ROUND_TRIP_TIMEOUT,
        Some(trusted_map),
        trust_first_use,
        false,
        1,
        DEFAULT_SEND_JITTER,
        None,
    )
    .map_err(|e| DirectoryError::Generic(e.to_string()))?;
    builder
        .add_hop("authority", authority_addr.clone(), None, None, None)
        .map_err(|e| DirectoryError::Generic(format!("directory authority handshake failed: {e}")))?;
    for wire_bytes in fragment_message_default(request_bytes) {
        builder
            .send(&wire_bytes, authority_addr)
            .map_err(|e| DirectoryError::Generic(format!("send to directory authority failed: {e}")))?;
    }
    receive_and_reassemble(&builder)
}

/// Shared by [`dir_round_trip`]/[`dir_round_trip_over_circuit`]/
/// [`register_over_circuit`]: poll `builder` for reply fragments until a
/// complete message reassembles or the overall deadline passes. Factored
/// out (2026-09-26) rather than copied a third time.
fn receive_and_reassemble(builder: &CircuitBuilder) -> Result<Vec<u8>, DirectoryError> {
    let mut reassembler = DirReassembler::with_defaults();
    let deadline = Instant::now() + Duration::from_secs_f64((DIR_ROUND_TRIP_TIMEOUT * 4.0).max(10.0));
    loop {
        if Instant::now() >= deadline {
            return Err(DirectoryError::Generic("directory authority did not answer in time".to_string()));
        }
        let raw = match builder.receive(Some(DIR_ROUND_TRIP_TIMEOUT)) {
            Ok(r) => r,
            Err(_) => continue, // timeout, or a foreign/malformed datagram: keep polling
        };
        match reassembler.push(&raw) {
            Ok(Some(message)) => return Ok(message),
            Ok(None) => continue, // more fragments still to come
            Err(e) => return Err(DirectoryError::Generic(format!("malformed directory reply fragment: {e}"))),
        }
    }
}

/// Security audit fix (2026-09-26, finding H1 -- Authority-crate directory
/// queries leak the querier's real IP): like [`dir_round_trip`], but routes
/// the request over a full multi-hop circuit instead of contacting the
/// destination directly. [`dir_round_trip`] (and [`fetch_relay_directory`],
/// which is built on it) stays one-hop *by design* -- mirrors the Client
/// crate's own `dirclient::dir_round_trip_over_circuit` doc, which gives
/// the same reasoning: relays are public by definition, and the plain
/// relay-directory fetch is also how a caller bootstraps the very hops
/// this function needs, so it can't depend on itself. But `HS_FETCH_REQUEST`/
/// `HS_PUBLISH_REQUEST` traffic carries a blinded hidden-service index
/// specifically so the raw identity isn't exposed -- a one-hop circuit to
/// the authority defeats that by exposing the querier's real IP directly
/// to whoever answers instead. This crate's own client-side directory code
/// (`dir_round_trip`/`fetch_relay_directory`) had no anonymized path at
/// all, unlike the Client crate; this closes that gap.
///
/// `hops` is the full path in order, `(name, addr)` per hop, ending at the
/// destination. `trusted` pins whichever hop names it contains; any name
/// absent from it is opted into trust-first-use for that hop alone --
/// `CircuitBuilder`'s per-hop `trusted_identities` check
/// (`HandshakeClient::complete`) always enforces a hop's own pin when one
/// exists, regardless of this blanket flag, so mixing pinned and unpinned
/// hops in the same circuit is safe.
pub fn dir_round_trip_over_circuit(
    hops: &[(String, Addr)],
    trusted: Option<HashMap<String, Vec<[u8; KEY_LEN]>>>,
    request_bytes: &[u8],
) -> Result<Vec<u8>, DirectoryError> {
    let (first_name, first_addr) = hops.first().ok_or_else(|| DirectoryError::Generic("hops must be non-empty".to_string()))?;
    let final_addr = &hops.last().expect("checked non-empty above").1;
    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| DirectoryError::Generic(format!("could not open a UDP socket for the directory round trip: {e}")))?;
    let trusted = trusted.unwrap_or_default();
    let trust_first_use = hops.iter().any(|(name, _)| !trusted.contains_key(name));
    let mut builder = CircuitBuilder::new(
        &sock,
        DEFAULT_CIPHER.to_string(),
        DIR_ROUND_TRIP_TIMEOUT,
        Some(trusted),
        trust_first_use,
        false,
        1,
        DEFAULT_SEND_JITTER,
        None,
    )
    .map_err(|e| DirectoryError::Generic(e.to_string()))?;
    builder
        .add_hop(first_name, first_addr.clone(), None, None, None)
        .map_err(|e| DirectoryError::Generic(format!("directory circuit first-hop handshake failed: {e}")))?;
    for (name, addr) in &hops[1..] {
        builder
            .extend(name, addr.clone(), None, None, None)
            .map_err(|e| DirectoryError::Generic(format!("directory circuit extend to {name} failed: {e}")))?;
    }
    for wire_bytes in fragment_message_default(request_bytes) {
        builder
            .send(&wire_bytes, final_addr)
            .map_err(|e| DirectoryError::Generic(format!("send to directory authority failed: {e}")))?;
    }
    receive_and_reassemble(&builder)
}

/// Security audit fix (2026-09-26, finding MH2 -- NAT-rendezvous protocol
/// is entirely plaintext): drive a `REGISTER`/`REGISTERED`/
/// `REGISTER_CONFIRM` exchange with `agent`'s configured introducer over a
/// one-hop onion circuit, instead of `NatAgent`'s original raw-UDP
/// transport. See [`AuthorityService::install_full`]'s doc for the
/// matching server-side change and the full rationale.
///
/// `agent` already knows how to build the wire bytes
/// ([`crate::nat::NatAgent::register_message`]) and parse a reply
/// ([`crate::nat::NatAgent::handle`]) -- this only supplies the transport,
/// exactly the same split [`dir_round_trip`] has from
/// [`fetch_relay_directory`]. `trusted` pins the introducer's identity
/// (`None` is `trust_first_use`, as risky as it sounds -- same caveat as
/// [`dir_round_trip`]'s own `trusted` parameter).
pub fn register_over_circuit(agent: &mut crate::nat::NatAgent, trusted: Option<Vec<[u8; KEY_LEN]>>) -> Result<(), DirectoryError> {
    let (register_bytes, introducer_addr) = agent.register_message();
    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| DirectoryError::Generic(format!("could not open a UDP socket for NAT registration: {e}")))?;
    let trust_first_use = trusted.is_none();
    let mut trusted_map: HashMap<String, Vec<[u8; KEY_LEN]>> = HashMap::new();
    if let Some(keys) = trusted {
        trusted_map.insert("introducer".to_string(), keys);
    }
    let mut builder = CircuitBuilder::new(
        &sock,
        DEFAULT_CIPHER.to_string(),
        DIR_ROUND_TRIP_TIMEOUT,
        Some(trusted_map),
        trust_first_use,
        false,
        1,
        DEFAULT_SEND_JITTER,
        None,
    )
    .map_err(|e| DirectoryError::Generic(e.to_string()))?;
    builder
        .add_hop("introducer", introducer_addr.clone(), None, None, None)
        .map_err(|e| DirectoryError::Generic(format!("NAT registration circuit handshake failed: {e}")))?;

    for wire_bytes in fragment_message_default(&register_bytes) {
        builder.send(&wire_bytes, &introducer_addr).map_err(|e| DirectoryError::Generic(format!("send REGISTER failed: {e}")))?;
    }
    let registered_bytes = receive_and_reassemble(&builder)?;

    // `NatAgent::handle` is the same pure `data -> Outgoing` state machine
    // regardless of transport; a *valid* `REGISTERED` reply always produces
    // exactly one `REGISTER_CONFIRM` to send back (see `on_registered`'s
    // doc) -- `handle` itself silently swallows a malformed/rejected
    // reply into an empty `Outgoing` (unchanged, pre-existing behavior),
    // so an empty result here specifically (a `REGISTERED`-shaped message
    // was just received) means that swallowed failure, not "nothing to
    // reply with".
    let confirm_messages = agent.handle(&registered_bytes, &introducer_addr);
    if confirm_messages.is_empty() {
        return Err(DirectoryError::Generic("introducer's REGISTERED reply was rejected (malformed, stale, or for another identity)".to_string()));
    }
    for (bytes, _addr) in confirm_messages {
        for wire_bytes in fragment_message_default(&bytes) {
            builder
                .send(&wire_bytes, &introducer_addr)
                .map_err(|e| DirectoryError::Generic(format!("send REGISTER_CONFIRM failed: {e}")))?;
        }
    }
    Ok(())
}

/// Client-side, process-lifetime memory of which single-authority addresses
/// have already answered a VOTE request with "I don't implement that" (an
/// older build, or a legacy-FETCH-only deployment), so a later call skips
/// straight to legacy FETCH instead of paying a fresh
/// [`DIR_ROUND_TRIP_TIMEOUT`]-second wait on a vote reply that will never
/// come. Mirrors `allium_cli`'s `dirclient::no_vote_authorities` --
/// deliberately scoped to the single-authority case only, same as there: a
/// multi-authority quorum's per-address vote support isn't assumed uniform,
/// so it is never cached or skipped for that case.
fn no_vote_authorities() -> &'static Mutex<HashSet<Addr>> {
    static CACHE: OnceLock<Mutex<HashSet<Addr>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Fetch the current live relay set from one or more directory authorities
/// into a fresh, local [`Directory`], verified against a quorum of signed
/// votes.
///
/// **The problem a single unsigned FETCH has**: descriptors are
/// self-signed, so an authority cannot *forge* a relay -- but a caller that
/// trusts exactly one authority for its view of the network can still be
/// censored (handed only the relays that authority likes) or Sybil-flooded
/// (padded with relays it runs itself), and an attacker who compromises or
/// MITMs that one authority controls the caller's entire view of the
/// network with nothing else to catch it.
///
/// **The fix**: every configured authority is asked (in parallel, one
/// ephemeral one-hop circuit each) for a `VOTE_REPLY` -- a compact,
/// Ed25519-signed list of `(relay identity, descriptor digest, optional
/// bandwidth measurement)` covering everything that authority currently
/// considers live, verified here against the pinned `trusted` key set (or,
/// with no pin, whichever key answers -- exactly as risky as an unpinned
/// single-hop `dir_round_trip` always is). A relay is used only once at
/// least [`default_quorum`] distinct authorities' votes name it with a
/// matching descriptor digest ([`compute_consensus`]), so a minority of
/// compromised/malicious authorities can neither inject relays nor hide
/// one the honest majority lists. Descriptors themselves are still fetched
/// with the ordinary unsigned `FETCH` (cheap, and pointless to forge: a
/// descriptor not named by a quorum of votes, or whose digest doesn't
/// match, is dropped by [`compute_consensus`] regardless of who served it),
/// from each address in turn until every identity a quorum agreed on has a
/// matching descriptor in hand.
///
/// Every returned descriptor is re-verified locally before being trusted
/// (via [`Directory::publish_verified`], which re-checks each descriptor's
/// own Ed25519 signature) on top of the above -- the authority can still
/// omit entries (censor, up to a minority) but cannot forge or alter one it
/// didn't sign the private key for. A descriptor that fails to verify is
/// dropped, not fatal to the whole fetch.
///
/// A lone configured authority that doesn't answer `VOTE_REQUEST` at all
/// (an older build, or a deliberately legacy-FETCH-only deployment) falls
/// back to the unsigned legacy `FETCH` -- no weaker than a one-authority
/// setup always was, since the circuit to it is still pinned by `trusted`
/// when given. A *multi*-authority deployment never takes this fallback:
/// if fewer than a quorum of configured authorities answer a vote, the
/// fetch fails loudly rather than silently trusting whichever one did.
pub fn fetch_relay_directory(addresses: &[Addr], trusted: Option<Vec<[u8; KEY_LEN]>>) -> Result<Directory, DirectoryError> {
    if addresses.is_empty() {
        return Err(DirectoryError::Generic("no directory authority address given".to_string()));
    }

    let quorum = default_quorum(addresses.len() as i64) as usize;
    let skip_vote = addresses.len() == 1 && no_vote_authorities().lock().unwrap().contains(&addresses[0]);

    let mut votes: Vec<Vote> = Vec::new();
    if !skip_vote {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
        votes = std::thread::scope(|scope| {
            let handles: Vec<_> = addresses
                .iter()
                .map(|addr| {
                    let trusted = trusted.clone();
                    scope.spawn(move || -> Option<Vote> {
                        let reply = dir_round_trip(addr, trusted.clone(), &encode_vote_request()).ok()?;
                        let ops = Ed25519Ops::real();
                        let trust = match &trusted {
                            Some(keys) => Trusted::Keys(keys.as_slice()),
                            None => Trusted::AllowAnySigner,
                        };
                        decode_vote(&reply, trust, now, |pk, sig, msg| (ops.verify)(pk, msg, sig)).ok()
                    })
                })
                .collect();
            handles.into_iter().filter_map(|h| h.join().ok().flatten()).collect()
        });
    }

    let (descriptors, measured, verified_subnets): (Vec<RelayDescriptor>, BTreeMap<[u8; KEY_LEN], u64>, BTreeMap<[u8; KEY_LEN], SubnetKey>) = if !votes.is_empty() || addresses.len() > 1 {
        let distinct_authorities: HashSet<[u8; KEY_LEN]> = votes.iter().map(|v| v.authority).collect();
        if distinct_authorities.len() < quorum {
            return Err(DirectoryError::Generic(format!(
                "no directory consensus: only {} valid authority vote(s), need {quorum} for a quorum",
                distinct_authorities.len()
            )));
        }
        // Descriptors are fetched once, from the voting authorities in
        // turn, until every relay a quorum agreed on is covered (normally
        // the first fetch does it). Each one is checked against the
        // votes' digests, so the authority that serves them can't
        // substitute its own.
        let mut pool: Vec<RelayDescriptor> = Vec::new();
        for addr in addresses {
            match dir_round_trip(addr, trusted.clone(), &encode_fetch_request_default())
                .map_err(|e| e.to_string())
                .and_then(|reply| decode_fetch_reply(&reply).map_err(|e| e.to_string()))
            {
                Ok(fetched) => pool.extend(fetched),
                Err(_) => continue,
            }
            match missing_identities(&votes, quorum, &pool) {
                Ok(missing) if missing.is_empty() => break,
                _ => continue,
            }
        }
        compute_consensus(&votes, quorum, &pool).map_err(|e| DirectoryError::Generic(e.to_string()))?
    } else {
        // A single authority that doesn't speak VOTE yet (an older build,
        // or one we already know doesn't implement it -- see
        // `no_vote_authorities`'s doc comment): fall back to the legacy
        // unsigned FETCH, which is no weaker than what a one-authority
        // setup always had (the circuit to it is still pinned to
        // `trusted` when given).
        no_vote_authorities().lock().unwrap().insert(addresses[0].clone());
        let reply_bytes = dir_round_trip(&addresses[0], trusted.clone(), &encode_fetch_request_default())?;
        let descriptors = decode_fetch_reply(&reply_bytes)
            .map_err(|e| DirectoryError::Generic(format!("directory authority sent a malformed reply: {e}")))?;
        // No votes at all in this branch (single authority, legacy FETCH
        // only), so there is no quorum to derive a verified subnet from
        // either -- every descriptor here falls back to its self-declared
        // host for subnet-diversity purposes, exactly as risky as the
        // single-authority case already is for everything else.
        (descriptors, BTreeMap::new(), BTreeMap::new())
    };

    let mut directory = Directory::new(DirectoryOptions::default())?;
    directory.set_measured_bandwidth(&measured.into_iter().collect::<Vec<_>>());
    for descriptor in descriptors {
        let verified_subnet = verified_subnets.get(&descriptor.identity_public).copied();
        // A bad/unverifiable descriptor is dropped, not fatal.
        let _ = directory.publish_verified(descriptor, verified_subnet);
    }
    Ok(directory)
}

// ---------------------------------------------------------------------------
// Authority-side: serving FETCH/PUBLISH over the network
// ---------------------------------------------------------------------------
//
// Port of `allium_cli.py`'s `AuthorityNode.handle_create`/`deliver`/
// `_handle_message`/`_handle_publish`/`_handle_fetch`/`_reply`/`_emit_cell`
// -- the same "composition instead of subclassing" pattern
// [`crate::socksproxy::SocksExit`] already uses to turn a plain
// [`RelayNode`] into a SOCKS-capable exit. [`AuthorityService::install`]
// does the same for the directory protocol: a directory circuit is always
// exactly one hop (the client calls `CircuitBuilder::add_hop` alone, never
// `extend`), so the authority is always the terminal hop, `hop_index = 0`
// -- structurally the one-hop cousin of `SocksExit`'s own hop-2-of-3
// registration.
//
// **Deliberate scope reduction from Python**: only `PUBLISH_REQUEST` and
// `FETCH_REQUEST` are served (mirroring [`fetch_relay_directory`]'s own
// legacy-FETCH-only client side above); `VOTE_REQUEST` and the
// hidden-service `HS_PUBLISH_REQUEST`/`HS_FETCH_REQUEST` message types are
// not dispatched here (Python's `_handle_vote`/`_handle_hs_publish`/
// `_handle_hs_fetch`). No reply pacing (Python's `DIR_REPLY_PACE_EVERY`/
// `DIR_REPLY_PACE_DELAY`) -- every reply fragment is sent back-to-back;
// fine for a demo-scale directory, a real deployment serving many
// ML-KEM-bearing descriptors would want the pacing back.
//
// **Written but unverified pending real cargo build** (see the crate's
// top-level README.md): `tokio`-touching (`spawn_local`), like the rest of
// this crate's async code, and never exercised against a live network in
// this sandbox.

/// Defensive bound on how many directory circuits can be mid-reassembly at
/// once, matching Python's `_MAX_PENDING_DIR_REASSEMBLERS`: a flood of
/// circuits that each send a partial request and never finish would
/// otherwise grow this table without limit.
const MAX_PENDING_DIR_REASSEMBLERS: usize = 256;
/// Most in-flight requests one peer address may hold at once. Return
/// routability (on by default) means the peer has to be a real address, so
/// this bounds what any one host can pin.
const MAX_PENDING_DIR_REASSEMBLERS_PER_PEER: usize = 8;

/// How often the authority drops expired relay and hidden-service
/// descriptors. Nothing ran `prune()` in production, so expired entries
/// held their slots until restart.
const AUTHORITY_PRUNE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
/// Periodic housekeeping for an authority, driven from the request path (no
/// background task, so it works wherever `deliver` does).
///
/// There is deliberately no per-peer limit on hidden-service publishes: they
/// arrive over a guard/middle/authority circuit, so the peer address is the
/// middle relay's, and limiting by it blocks honest services behind a busy or
/// attacked middle while charging the publisher nothing (see
/// `11.38-hs-quota-report.md`). The store bounds itself by evicting the
/// descriptors with the least tenure instead (`BlindedHsDirectory`).
#[derive(Default)]
struct AuthorityMaintenance {
    last_prune: Option<std::time::Instant>,
}

impl AuthorityMaintenance {
    /// Drop expired descriptors, at most once per [`AUTHORITY_PRUNE_INTERVAL`].
    fn maybe_prune(
        &mut self,
        directory: &Rc<RefCell<Directory>>,
        hs_directory: Option<&Rc<RefCell<crate::hiddenservice::BlindedHsDirectory>>>,
    ) {
        let now = std::time::Instant::now();
        if self.last_prune.is_some_and(|t| now.duration_since(t) < AUTHORITY_PRUNE_INTERVAL) {
            return;
        }
        self.last_prune = Some(now);
        directory.borrow_mut().prune();
        if let Some(hsd) = hs_directory {
            hsd.borrow_mut().prune();
        }
    }
}

/// In-flight request reassembly for the authority, keyed by the *full*
/// circuit key (peer address, port, circuit id). It used to be keyed by the
/// circuit id alone, so two peers that happened to use the same id shared a
/// reassembler and one could feed fragments into the other's request.
///
/// Bounded three ways: [`MAX_REQUEST_REASSEMBLED_LEN`] per request, a cap
/// per peer address, and a global entry cap at which the biggest holder is
/// evicted (most likely the abuser) instead of an arbitrary entry.
#[derive(Default)]
struct DirRequestReassemblers {
    map: HashMap<CircuitKeyTuple, DirReassembler>,
    per_peer: HashMap<String, usize>,
}

impl DirRequestReassemblers {
    /// Feed one fragment for `key`'s request. Returns the whole message
    /// once complete (and forgets the reassembler). A malformed or
    /// oversize request, or one refused by a bound, yields `None`.
    fn push(&mut self, key: &CircuitKeyTuple, payload: &[u8]) -> Option<Vec<u8>> {
        if !self.map.contains_key(key) {
            if self.per_peer.get(&key.0).copied().unwrap_or(0) >= MAX_PENDING_DIR_REASSEMBLERS_PER_PEER {
                return None;
            }
            if self.map.len() >= MAX_PENDING_DIR_REASSEMBLERS {
                let biggest = self.map.iter().max_by_key(|(_, r)| r.buffered_bytes()).map(|(k, _)| k.clone());
                if let Some(k) = biggest {
                    self.forget(&k);
                }
            }
            self.map.insert(key.clone(), DirReassembler::with_defaults());
            *self.per_peer.entry(key.0.clone()).or_insert(0) += 1;
        }
        let reassembler = self.map.get_mut(key).expect("just ensured above");
        match reassembler.push_limited(payload, crate::dirwire::MAX_REQUEST_REASSEMBLED_LEN) {
            Ok(Some(message)) => {
                self.forget(key);
                Some(message)
            }
            Ok(None) => None, // still reassembling
            Err(_) => {
                self.forget(key); // malformed or oversize: drop the whole in-flight request
                None
            }
        }
    }

    /// Drop `key`'s in-flight request, if any.
    fn forget(&mut self, key: &CircuitKeyTuple) {
        if self.map.remove(key).is_some() {
            if let Some(n) = self.per_peer.get_mut(&key.0) {
                *n -= 1;
                if *n == 0 {
                    self.per_peer.remove(&key.0);
                }
            }
        }
    }
}

/// Composition stand-in for Python's `class AuthorityNode(RelayNode)`.
/// [`AuthorityService::install`] turns a plain [`RelayNode`] into a
/// directory authority backed by `directory`: every one-hop circuit
/// terminating at this relay is auto-registered (like `SocksExit`'s own
/// `post_create_hook`), and a `PUBLISH`/`FETCH` request delivered on it is
/// reassembled (a request or reply can span several cells), dispatched into
/// `directory`, and answered.
pub struct AuthorityService;

impl AuthorityService {
    /// Original entry point: a directory authority that serves only
    /// `PUBLISH`/`FETCH` (relay descriptors), matching every existing
    /// caller. Delegates to [`AuthorityService::install_with_hs`] with no
    /// hidden-service directory, so `HS_PUBLISH_REQUEST`/`HS_FETCH_REQUEST`
    /// go unanswered exactly as they did before this hook existed.
    pub fn install(node: &Rc<RefCell<RelayNode>>, directory: Rc<RefCell<Directory>>) {
        AuthorityService::install_with_hs(node, directory, None);
    }

    /// Like [`AuthorityService::install`], but additionally serves
    /// `HS_PUBLISH_REQUEST`/`HS_FETCH_REQUEST` (Round J) out of
    /// `hs_directory` when one is given -- the wire types this uses
    /// (`crate::dirwire::{encode,decode}_hs_{publish,fetch}_{request,reply}`)
    /// and the storage (`crate::hiddenservice::BlindedHsDirectory`) both
    /// already existed and were already tested; this is the first thing
    /// that actually drives them over the network. Mirrors
    /// `allium_cli.py`'s `AuthorityNode._handle_hs_publish`/`_handle_hs_fetch`.
    pub fn install_with_hs(node: &Rc<RefCell<RelayNode>>, directory: Rc<RefCell<Directory>>, hs_directory: Option<Rc<RefCell<crate::hiddenservice::BlindedHsDirectory>>>) {
        AuthorityService::install_full(node, directory, hs_directory, None);
    }

    /// Like [`AuthorityService::install_with_hs`], but additionally serves
    /// NAT-rendezvous `REGISTER`/`REGISTER_CONFIRM` out of `nat_rendezvous`
    /// when one is given.
    ///
    /// Security audit fix (2026-09-26, finding MH2 -- NAT-rendezvous
    /// protocol is entirely plaintext): `nat::NatRendezvous`/`NatAgent`
    /// were always transport-agnostic pure state machines (`handle(data,
    /// peer) -> Outgoing`, no socket of their own), but the only transport
    /// ever wired up for them was a raw, unencrypted UDP datagram straight
    /// to this relay's own bind address -- broadcasting a relay's
    /// permanent identity, bound to its real IP, in the clear on every
    /// registration. Routing `REGISTER`/`REGISTER_CONFIRM` over the same
    /// one-hop onion circuit `PUBLISH`/`FETCH` already use fixes that: the
    /// wire bytes `NatRendezvous`/`NatAgent` already produce are unchanged
    /// (no wire-format redesign), only the transport is -- they now travel
    /// as onion-encrypted circuit payload, indistinguishable on the wire
    /// from any other directory traffic, instead of a raw, recognizably-
    /// magic-prefixed UDP datagram. `PUNCH_REQUEST`/`PUNCH_NOTIFY`/
    /// `PUNCH_REPLY` are out of scope for this fix (the requesting client
    /// there is intentionally anonymous, with no persistent key to
    /// authenticate a circuit with) and are unaffected.
    pub fn install_full(
        node: &Rc<RefCell<RelayNode>>,
        directory: Rc<RefCell<Directory>>,
        hs_directory: Option<Rc<RefCell<crate::hiddenservice::BlindedHsDirectory>>>,
        nat_rendezvous: Option<Rc<RefCell<crate::nat::NatRendezvous>>>,
    ) {
        let reassemblers: Rc<RefCell<DirRequestReassemblers>> = Rc::new(RefCell::new(DirRequestReassemblers::default()));
        let forget_reassemblers = reassemblers.clone();
        let maintenance: Rc<RefCell<AuthorityMaintenance>> = Rc::new(RefCell::new(AuthorityMaintenance::default()));

        // A circuit that goes away (idle timeout or DESTROY) must not leave
        // a half-received request behind. Chain onto any hook already set.
        let mut previous_forget_hook = node.borrow_mut().forget_hook.take();
        node.borrow_mut().forget_hook = Some(Box::new(move |key| {
            if let Some(previous) = previous_forget_hook.as_mut() {
                previous(key);
            }
            forget_reassemblers.borrow_mut().forget(key);
        }));

        let deliver_node = node.clone();
        let deliver_directory = directory;
        let deliver_hs_directory = hs_directory;
        let deliver_nat_rendezvous = nat_rendezvous;
        let deliver_reassemblers = reassemblers;
        node.borrow_mut().deliver_fn = Some(Box::new(move |key, _peeled, payload| {
            AuthorityService::deliver(
                deliver_node.clone(),
                deliver_directory.clone(),
                deliver_hs_directory.clone(),
                deliver_nat_rendezvous.clone(),
                deliver_reassemblers.clone(),
                maintenance.clone(),
                key.clone(),
                payload.to_vec(),
            );
        }));

        node.borrow_mut().post_create_hook = Some(Box::new(|n, peer_addr, circuit_id| {
            // hop_index = 0: the authority is always the only hop in a
            // directory circuit, unlike an exit's hop_index = 2 of a
            // normal 3-hop app circuit. Best-effort/silent on failure,
            // matching `SocksExit::install`'s own hook.
            let _ = n.register_exit_circuit(peer_addr, circuit_id, 0);
        }));
    }

    /// Store a version 3 hidden-service publish and encode the reply.
    ///
    /// Nothing about the delivering peer is used: a publish arrives over a
    /// guard/middle/authority circuit, so that peer is the middle relay, not
    /// the publisher. Charging a rate limit or quota to it would block honest
    /// services behind a busy or attacked middle while costing a flooding
    /// publisher nothing. A full store evicts by tenure (never-refreshed entries and the
    /// shortest-tenured ones first) instead
    /// of refusing (`BlindedHsDirectory`); see `11.38-hs-quota-report.md`.
    fn answer_hs3_publish(hsd: &Rc<RefCell<crate::hiddenservice::BlindedHsDirectory>>, blinded: crate::hiddenservice::BlindedDescriptor) -> Vec<u8> {
        match hsd.borrow_mut().publish(blinded) {
            Ok(_accepted) => crate::dirwire::encode_hs3_publish_reply(true, ""),
            Err(e) => crate::dirwire::encode_hs3_publish_reply(false, &e.to_string()),
        }
    }

    fn deliver(
        node: Rc<RefCell<RelayNode>>,
        directory: Rc<RefCell<Directory>>,
        hs_directory: Option<Rc<RefCell<crate::hiddenservice::BlindedHsDirectory>>>,
        nat_rendezvous: Option<Rc<RefCell<crate::nat::NatRendezvous>>>,
        reassemblers: Rc<RefCell<DirRequestReassemblers>>,
        maintenance: Rc<RefCell<AuthorityMaintenance>>,
        key: CircuitKeyTuple,
        payload: Vec<u8>,
    ) {
        let message = reassemblers.borrow_mut().push(&key, &payload);
        let Some(message) = message else { return };
        maintenance.borrow_mut().maybe_prune(&directory, hs_directory.as_ref());

        tokio::task::spawn_local(async move {
            let reply_bytes: Option<Vec<u8>> = if crate::consensus::decode_vote_request(&message).is_ok() {
                // VOTE_REQUEST (fix: this used to fall through to `None`, so
                // every client waited out its full directory timeout and then
                // dropped to the unsigned legacy FETCH). Answer with a vote
                // listing every live relay's identity + descriptor digest,
                // signed by this authority's own Ed25519 identity -- the same
                // key clients pin with --trust-authority -- so a client can
                // reject any descriptor that doesn't match what was signed.
                AuthorityService::encode_signed_vote(&node, &directory)
            } else if let Ok(descriptor) = decode_publish_request(&message) {
                // `key.0` is this one-hop directory
                // circuit's own verified peer address, not anything the
                // descriptor itself claims -- see `Directory::publish_from`.
                let outcome = directory.borrow_mut().publish_from(descriptor, Some(key.0.as_str()));
                match outcome {
                    Ok(_accepted) => Some(encode_publish_reply(true, "")),
                    Err(e) => Some(encode_publish_reply(false, &e.to_string())),
                }
            } else if decode_fetch_request(&message).is_ok() {
                // `serving_set`, not `all`: a reply that cannot be encoded
                // is silently no reply (`.ok()` below), which is how an
                // over-full open authority used to take every client
                // offline at once.
                let descriptors: Vec<RelayDescriptor> =
                    directory.borrow().serving_set(crate::dirwire::MAX_DESCRIPTOR_COUNT).into_iter().cloned().collect();
                encode_fetch_reply(&descriptors).ok()
            } else if let Ok(blinded) = crate::dirwire::decode_hs3_publish_request(&message) {
                // A version 3 (blinded, encrypted) descriptor: the authority
                // can check only its signature. With no `hs_directory`
                // configured (the plain `install` entry point) this goes
                // unanswered, like every other unrecognised request.
                hs_directory.as_ref().map(|hsd| Self::answer_hs3_publish(hsd, blinded))
            } else if let Ok(blinded_key) = crate::dirwire::decode_hs3_fetch_request(&message) {
                // The request carries only the blinded key for one period:
                // the authority learns neither which address this is nor
                // that it is the same service as last period's request.
                hs_directory.as_ref().and_then(|hsd| crate::dirwire::encode_hs3_fetch_reply(hsd.borrow().get(&blinded_key)).ok())
            } else if message.starts_with(crate::dirwire::DIR_MAGIC) && message.get(4) == Some(&crate::dirwire::HS_PUBLISH_REQUEST) {
                // A version 2 descriptor names the service in the clear and
                // is indexed by a hash this authority can compute, so it is
                // no longer stored. Say so, so the operator knows to upgrade
                // (the service otherwise just sees its publishes vanish).
                hs_directory.as_ref().map(|_| {
                    crate::dirwire::encode_hs_publish_reply(
                        false,
                        "hidden-service descriptor version 2 is no longer accepted (it names the service in the clear); upgrade the service to publish version 3",
                    )
                })
            } else if message.starts_with(crate::dirwire::DIR_MAGIC) && message.get(4) == Some(&crate::dirwire::HS_FETCH_REQUEST) {
                // ...and it cannot be looked up either: "not found".
                hs_directory.as_ref().and_then(|_| crate::dirwire::encode_hs_fetch_reply(None).ok())
            } else if crate::nat::is_nat_message(&message) {
                // Security audit fix (2026-09-26, finding MH2): REGISTER/
                // REGISTER_CONFIRM arriving as onion-encrypted circuit
                // payload instead of a raw UDP datagram -- see
                // `AuthorityService::install_full`'s doc. `NatRendezvous`
                // is peer-agnostic transport-wise, so `key`'s own verified
                // peer address (the same one `publish_from` above trusts)
                // is what it uses for the return-routability check
                // `on_register` already performs; no `hs_directory`-style
                // "goes unanswered" fallback is needed here since a
                // message this codebase itself never routes at all when
                // `nat_rendezvous` is `None`.
                nat_rendezvous.as_ref().and_then(|nr| {
                    nr.borrow_mut().handle(&message, &(key.0.clone(), key.1)).into_iter().next().map(|(bytes, _addr)| bytes)
                })
            } else {
                None // neither shape matched: nothing to answer, matches Python's fall-through
            };
            let Some(reply_bytes) = reply_bytes else { return };
            for wire_bytes in fragment_message_default(&reply_bytes) {
                AuthorityService::send_backward(&node, &key, &wire_bytes).await;
            }
        });
    }

    /// Build this authority's signed VOTE_REPLY over its current relay set
    /// (see `consensus::encode_vote`). Measured bandwidth is not tracked
    /// here, so every entry carries 0 ("unmeasured"), which clients treat
    /// as "fall back to the descriptor's own weighting". Each entry also
    /// carries this authority's own `verified_subnet_of` for that relay --
    /// the subnet its address was actually observed publishing from, not
    /// anything the relay's own descriptor claims -- so a quorum of these
    /// votes lets a client derive a verified subnet for anti-collusion
    /// route diversity without ever connecting to the relay itself (see
    /// `Directory::publish_verified`).
    fn encode_signed_vote(node: &Rc<RefCell<RelayNode>>, directory: &Rc<RefCell<Directory>>) -> Option<Vec<u8>> {
        let (identity_private, identity_public) = {
            let n = node.borrow();
            (*n.handshake.identity_private_key(), n.identity_public())
        };
        // The same set FETCH serves (see `deliver`), so the digests in
        // this vote are those of the descriptors a client will be sent.
        let entries: Vec<(RelayDescriptor, u64, Option<SubnetKey>)> = {
            let dir = directory.borrow();
            dir.serving_set(crate::dirwire::MAX_DESCRIPTOR_COUNT)
                .into_iter()
                .cloned()
                .map(|d| { let subnet = dir.verified_subnet_of(&d.identity_public); (d, 0u64, subnet) })
                .collect()
        };
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&identity_private);
        crate::consensus::encode_vote(
            identity_public,
            &entries,
            now,
            crate::consensus::DEFAULT_VOTE_LIFETIME,
            |message: &[u8]| {
                use ed25519_dalek::Signer;
                signing_key.sign(message).to_bytes()
            },
        )
        .ok()
    }

    /// Seal one reply fragment in this authority's own layer and send it
    /// back to its one predecessor. Identical in shape to
    /// `SocksExit::send_backward` (both are "one-hop node answers its only
    /// predecessor"), kept as its own copy rather than shared so each stays
    /// self-contained, matching that type's own style.
    async fn send_backward(node: &Rc<RefCell<RelayNode>>, key: &CircuitKeyTuple, payload: &[u8]) {
        let (mut wrapped, incoming_addr, incoming_circuit_id, backward_token) = {
            let mut n = node.borrow_mut();
            let Some(entry) = n.table.by_key.get_mut(key) else { return };
            let incoming_addr = entry.incoming_addr();
            let incoming_circuit_id = entry.incoming_circuit_id();
            let backward_token = entry.backward_token.clone();
            let wrapped = match entry.hop.seal_payload(payload, 0, incoming_addr.clone(), Some(Kind::PAYLOAD), None) {
                Ok(w) => w,
                Err(_) => return,
            };
            (wrapped, incoming_addr, incoming_circuit_id, backward_token)
        };
        if let Some(tok) = &backward_token {
            wrapped.extend_from_slice(tok);
        }
        let outgoing = match seal_into_cell(&wrapped, incoming_circuit_id, Some(Command::Relay)) {
            Ok(c) => c,
            Err(_) => return,
        };
        let _ = RelayNode::send_datagram(node, &outgoing.pack(), &incoming_addr).await;
    }
}

/// Options for [`Directory::select_route`], mirroring Python's keyword-only
/// arguments (see `directory.py`'s docstring for what each one means).
pub struct SelectRouteOptions {
    pub hops: usize,
    pub seed: Option<u64>,
    pub preferred_guard: Option<[u8; KEY_LEN]>,
    pub enforce_subnet_diversity: bool,
    pub require_preferred_guard: bool,
    pub exclude_identities: Vec<[u8; KEY_LEN]>,
    pub exit_port: Option<u16>,
    pub weight_by_bandwidth: bool,
    pub require_pq: bool,
}
impl Default for SelectRouteOptions {
    fn default() -> SelectRouteOptions {
        SelectRouteOptions {
            hops: 3,
            seed: None,
            preferred_guard: None,
            enforce_subnet_diversity: true,
            require_preferred_guard: false,
            exclude_identities: Vec::new(),
            exit_port: None,
            weight_by_bandwidth: true,
            require_pq: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashutil::hmac_sha256;
    use std::collections::HashMap as StdHashMap;
    use std::sync::{Arc, Mutex};

    /// Deterministic, insecure fake `Ed25519Ops` -- the same recording
    /// pattern as `handshake.rs`'s `fake_handshake_ops`/`nat.rs`'s
    /// `recording_fake_ops`.
    /// A process-global (not per-call) registry: `RelayDescriptor::create`
    /// and `Directory`'s own stored `ops` each get their own `fake_ops()`
    /// instance in these tests (there's no way to `Clone` an `Ed25519Ops`,
    /// which holds boxed closures), but a signature made with one instance
    /// must still verify against another -- so the registry itself must be
    /// shared across every `fake_ops()` call, not private to each one.
    fn fake_ops_registry() -> &'static Mutex<StdHashMap<(Vec<u8>, Vec<u8>), [u8; 64]>> {
        static REGISTRY: std::sync::OnceLock<Mutex<StdHashMap<(Vec<u8>, Vec<u8>), [u8; 64]>>> = std::sync::OnceLock::new();
        REGISTRY.get_or_init(|| Mutex::new(StdHashMap::new()))
    }

    fn fake_ops() -> Ed25519Ops {
        Ed25519Ops {
            sign: Box::new(move |private, message| {
                let public = hmac_sha256(b"dir-test-ed25519-pub", private);
                let mac1 = hmac_sha256(private, message);
                let mac2 = hmac_sha256(private, &mac1);
                let mut sig = [0u8; 64];
                sig[..32].copy_from_slice(&mac1);
                sig[32..].copy_from_slice(&mac2);
                fake_ops_registry().lock().unwrap().insert((public.to_vec(), message.to_vec()), sig);
                sig
            }),
            verify: Box::new(move |public, message, sig| {
                fake_ops_registry().lock().unwrap().get(&(public.to_vec(), message.to_vec())) == Some(sig)
            }),
            public_of: Box::new(|private| hmac_sha256(b"dir-test-ed25519-pub", private)),
            x25519_generate: Box::new(fake_x25519_generate),
            x25519_public: Box::new(fake_x25519_public),
            x25519_dh: Box::new(fake_x25519_dh),
        }
    }

    fn fake_x25519_public(seed: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
        hmac_sha256(b"dir-test-x25519-pub-fake", seed)
    }
    /// Must be symmetric (`dh(a_priv, b_pub) == dh(b_priv, a_pub)`), same as
    /// real X25519 -- mirrors `nat.rs`'s own `fake_x25519_dh`.
    fn fake_x25519_dh(private: &[u8; KEY_LEN], peer_public: &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN], NatError> {
        let own_public = fake_x25519_public(private);
        let (a, b) = if own_public <= *peer_public { (own_public, *peer_public) } else { (*peer_public, own_public) };
        let mut buf = a.to_vec();
        buf.extend_from_slice(&b);
        Ok(hmac_sha256(b"dir-test-x25519-dh-fake", &buf))
    }
    fn fake_x25519_generate() -> [u8; KEY_LEN] {
        let mut buf = [0u8; KEY_LEN];
        crate::osrand::os_random(&mut buf).unwrap();
        buf
    }

    fn identity(byte: u8) -> [u8; KEY_LEN] {
        [byte; KEY_LEN]
    }

    fn make_descriptor(ops: &Ed25519Ops, host: &str, port: u16, roles: &[&str], now: f64, identity_private: [u8; KEY_LEN]) -> RelayDescriptor {
        RelayDescriptor::create(ops, &identity_private, &[7u8; KEY_LEN], host, port, roles, DEFAULT_DESCRIPTOR_LIFETIME, Some(now), CreateOptions::default()).unwrap()
    }

    const NOW: f64 = 1_000_000.0;

    #[test]
    fn test_create_produces_a_verifiable_descriptor() {
        let ops = fake_ops();
        let d = make_descriptor(&ops, "10.0.0.1", 9001, &[ROLE_MIDDLE], NOW, identity(1));
        d.verify(&ops).unwrap();
        assert_eq!(d.identity_public.len(), 32);
        assert!(d.is_valid_at(Some(NOW + 1.0)));
    }

    #[test]
    fn test_signature_covers_the_host() {
        let ops = fake_ops();
        let d = make_descriptor(&ops, "10.0.0.1", 9001, &[ROLE_MIDDLE], NOW, identity(1));
        let tampered = RelayDescriptor { host: "10.9.9.9".to_string(), ..d };
        assert!(tampered.verify(&ops).is_err());
    }

    #[test]
    fn test_signature_covers_the_port() {
        let ops = fake_ops();
        let d = make_descriptor(&ops, "10.0.0.1", 9001, &[ROLE_MIDDLE], NOW, identity(1));
        let tampered = RelayDescriptor { port: 9002, ..d };
        assert!(tampered.verify(&ops).is_err());
    }

    #[test]
    fn test_a_foreign_signature_is_rejected() {
        let ops = fake_ops();
        let a = make_descriptor(&ops, "10.0.0.1", 9001, &[ROLE_MIDDLE], NOW, identity(1));
        let b = make_descriptor(&ops, "10.0.0.2", 9002, &[ROLE_MIDDLE], NOW, identity(2));
        let swapped = RelayDescriptor { signature: b.signature, ..a };
        assert!(swapped.verify(&ops).is_err());
    }

    #[test]
    fn test_v1_descriptor_rejects_extensions() {
        let mut d = RelayDescriptor {
            identity_public: identity(1),
            static_public: identity(2),
            host: "10.0.0.1".to_string(),
            port: 1,
            roles: vec![ROLE_MIDDLE.to_string()],
            not_before: NOW,
            not_after: NOW + 10.0,
            signature: vec![0u8; 64],
            version: DESCRIPTOR_VERSION_1,
            extensions: vec![(EXT_BANDWIDTH, vec![0; 8])],
        };
        assert!(matches!(d.check_structure(), Err(DirectoryError::DescriptorMalformed(_))));
        d.extensions.clear();
        d.check_structure().unwrap();
    }

    #[test]
    fn test_v2_bandwidth_round_trips() {
        let ops = fake_ops();
        let mut opts = CreateOptions::default();
        opts.bandwidth = Some(5_000_000);
        let d = RelayDescriptor::create(&ops, &identity(1), &identity(9), "10.0.0.1", 1, &[ROLE_EXIT], 100.0, Some(NOW), opts).unwrap();
        d.verify(&ops).unwrap();
        assert_eq!(d.bandwidth(), 5_000_000);
    }

    #[test]
    fn test_v2_exit_ports_round_trip_and_allows_exit_port() {
        let ops = fake_ops();
        let mut opts = CreateOptions::default();
        opts.exit_ports = Some(vec![80, 443, 8080]);
        let d = RelayDescriptor::create(&ops, &identity(1), &identity(9), "10.0.0.1", 1, &[ROLE_EXIT], 100.0, Some(NOW), opts).unwrap();
        d.verify(&ops).unwrap();
        assert_eq!(d.allows_exit_port(80), Some(true));
        assert_eq!(d.allows_exit_port(22), Some(false));
    }

    #[test]
    fn test_v2_family_excludes_self() {
        let ops = fake_ops();
        let identity_public = (ops.public_of)(&identity(1));
        let mut opts = CreateOptions::default();
        opts.family = Some(vec![identity(2), identity_public]);
        let d = RelayDescriptor::create(&ops, &identity(1), &identity(9), "10.0.0.1", 1, &[ROLE_EXIT], 100.0, Some(NOW), opts).unwrap();
        d.verify(&ops).unwrap();
        assert_eq!(d.family(), vec![identity(2)]);
    }

    /// A fixed clock reading comfortably inside `[NOW, NOW + lifetime]` even
    /// for a descriptor minted a few seconds after `NOW` (several tests
    /// mint a second descriptor at `NOW + 1`/`NOW + 10` to exercise
    /// rotation) -- not the real wall clock, since every test descriptor's
    /// validity window is minted around `NOW`, nowhere near the real
    /// current time.
    const TEST_CLOCK: f64 = NOW + 1800.0;

    fn make_dir(authorities: Vec<[u8; KEY_LEN]>, ops: Ed25519Ops) -> Directory {
        Directory::new(DirectoryOptions { authorities, ops, clock: Some(Box::new(|| TEST_CLOCK)), ..Default::default() }).unwrap()
    }

    #[test]
    fn test_publish_accepts_and_get_returns_it() {
        let ops = fake_ops();
        let mut dir = make_dir(vec![], fake_ops());
        let d = make_descriptor(&ops, "10.0.0.1", 9001, &[ROLE_MIDDLE], NOW, identity(1));
        assert!(dir.publish(d.clone()).unwrap());
        assert_eq!(dir.get(&d.identity_public).unwrap().host, "10.0.0.1");
    }

    #[test]
    fn test_publish_rejects_expired() {
        let ops = fake_ops();
        let mut dir = Directory::new(DirectoryOptions { ops: fake_ops(), clock: Some(Box::new(|| NOW + 100_000.0)), ..Default::default() }).unwrap();
        let d = make_descriptor(&ops, "10.0.0.1", 9001, &[ROLE_MIDDLE], NOW, identity(1));
        assert!(matches!(dir.publish(d), Err(DirectoryError::DescriptorExpired(_))));
    }

    #[test]
    fn test_publish_rejects_untrusted_identity_under_authorities() {
        let ops = fake_ops();
        let mut dir = make_dir(vec![identity(99)], fake_ops());
        let d = make_descriptor(&ops, "10.0.0.1", 9001, &[ROLE_MIDDLE], NOW, identity(1));
        assert!(matches!(dir.publish(d), Err(DirectoryError::SignatureInvalid(_))));
    }

    #[test]
    fn test_publish_rejects_too_long_lifetime() {
        let ops = fake_ops();
        let d = make_descriptor(&ops, "10.0.0.1", 9001, &[ROLE_MIDDLE], NOW, identity(1));
        let too_long = RelayDescriptor { not_after: d.not_before + MAX_DESCRIPTOR_LIFETIME * 2.0, ..d.clone() };
        // Re-sign since not_after changed (signature covers everything).
        let resigned = RelayDescriptor { signature: (ops.sign)(&identity(1), &too_long.signing_payload()).to_vec(), ..too_long };
        let mut dir = make_dir(vec![], fake_ops());
        assert!(matches!(dir.publish(resigned), Err(DirectoryError::DescriptorLifetimeTooLong(_))));
    }

    #[test]
    fn test_publish_rotation_replaces_older_not_newer() {
        let ops = fake_ops();
        let mut dir = make_dir(vec![], fake_ops());
        let d1 = make_descriptor(&ops, "10.0.0.1", 9001, &[ROLE_MIDDLE], NOW, identity(1));
        let d2 = make_descriptor(&ops, "10.0.0.2", 9001, &[ROLE_MIDDLE], NOW + 10.0, identity(1));
        let key = d1.identity_public;
        assert!(dir.publish(d1.clone()).unwrap());
        assert!(dir.publish(d2.clone()).unwrap());
        assert_eq!(dir.get(&key).unwrap().host, "10.0.0.2");
        // An older record than what's held must not clobber it.
        assert!(!dir.publish(d1).unwrap());
        assert_eq!(dir.get(&key).unwrap().host, "10.0.0.2");
    }

    #[test]
    fn test_sybil_rate_limit_blocks_new_identities_same_subnet() {
        let ops = fake_ops();
        let mut dir = Directory::new(DirectoryOptions {
            ops: fake_ops(),
            max_new_identities_per_subnet: Some(2),
            clock: Some(Box::new(|| TEST_CLOCK)),
            ..Default::default()
        })
        .unwrap();
        for i in 1..=2u8 {
            let d = make_descriptor(&ops, "10.0.0.1", 9000 + i as u16, &[ROLE_MIDDLE], NOW, identity(i));
            assert!(dir.publish(d).unwrap());
        }
        let d3 = make_descriptor(&ops, "10.0.0.1", 9003, &[ROLE_MIDDLE], NOW, identity(3));
        assert!(matches!(dir.publish(d3), Err(DirectoryError::SybilRateLimited(_))));
    }

    #[test]
    fn test_sybil_rate_limit_does_not_block_rotation() {
        let ops = fake_ops();
        let mut dir = Directory::new(DirectoryOptions {
            ops: fake_ops(),
            max_new_identities_per_subnet: Some(1),
            clock: Some(Box::new(|| TEST_CLOCK)),
            ..Default::default()
        })
        .unwrap();
        let d1 = make_descriptor(&ops, "10.0.0.1", 9001, &[ROLE_MIDDLE], NOW, identity(1));
        assert!(dir.publish(d1).unwrap());
        let d1b = make_descriptor(&ops, "10.0.0.1", 9002, &[ROLE_MIDDLE], NOW + 1.0, identity(1));
        assert!(dir.publish(d1b).unwrap());
    }

    #[test]
    fn test_sybil_rate_limit_classifies_by_verified_source_not_self_declared_host() {
        // Two "new identities" that each claim a
        // completely different self-declared host, but were actually both
        // published from the same real address block, must still count
        // against that block's limit -- otherwise the self-signed `host`
        // field alone lets one operator mint unlimited identities.
        let ops = fake_ops();
        let mut dir = Directory::new(DirectoryOptions {
            ops: fake_ops(),
            max_new_identities_per_subnet: Some(2),
            clock: Some(Box::new(|| TEST_CLOCK)),
            ..Default::default()
        })
        .unwrap();
        for i in 1..=2u8 {
            let host = format!("{i}.{i}.{i}.{i}");
            let d = make_descriptor(&ops, &host, 9000 + i as u16, &[ROLE_MIDDLE], NOW, identity(i));
            assert!(dir.publish_from(d, Some("10.0.0.1")).unwrap());
        }
        let d3 = make_descriptor(&ops, "99.99.99.99", 9003, &[ROLE_MIDDLE], NOW, identity(3));
        assert!(matches!(dir.publish_from(d3, Some("10.0.0.1")), Err(DirectoryError::SybilRateLimited(_))));
    }

    #[test]
    fn test_sybil_rate_limit_without_source_addr_falls_back_to_declared_host() {
        // `publish` (no known source, e.g. a purely local re-verification)
        // keeps classifying by `descriptor.host`, same as before this fix.
        let ops = fake_ops();
        let mut dir = Directory::new(DirectoryOptions {
            ops: fake_ops(),
            max_new_identities_per_subnet: Some(2),
            clock: Some(Box::new(|| TEST_CLOCK)),
            ..Default::default()
        })
        .unwrap();
        for i in 1..=2u8 {
            let d = make_descriptor(&ops, "10.0.0.1", 9000 + i as u16, &[ROLE_MIDDLE], NOW, identity(i));
            assert!(dir.publish(d).unwrap());
        }
        let d3 = make_descriptor(&ops, "10.0.0.1", 9003, &[ROLE_MIDDLE], NOW, identity(3));
        assert!(matches!(dir.publish(d3), Err(DirectoryError::SybilRateLimited(_))));
    }

    // -- max_descriptors / make_room ------------------------------------

    /// A directory capped at `max` with the rate limiter and per-subnet
    /// cap out of the way, so only the global cap is under test. Each
    /// identity `i` gets its own /16 so the subnet checks never fire.
    fn capped_dir(max: usize) -> Directory {
        Directory::new(DirectoryOptions {
            ops: fake_ops(),
            clock: Some(Box::new(|| TEST_CLOCK)),
            max_descriptors: Some(max),
            max_new_identities_per_subnet: None,
            max_live_identities_per_subnet: None,
            ..Default::default()
        })
        .unwrap()
    }

    /// The public identity `fill` registers for private seed `identity(i)`.
    fn pubkey(ops: &Ed25519Ops, i: u8) -> [u8; KEY_LEN] {
        make_descriptor(ops, "0.0.0.0", 1, &[ROLE_MIDDLE], NOW, identity(i)).identity_public
    }

    fn fill(dir: &mut Directory, ops: &Ed25519Ops, ids: std::ops::RangeInclusive<u8>, not_before: f64) {
        for i in ids {
            let d = make_descriptor(ops, &format!("10.{i}.0.1"), 9000, &[ROLE_MIDDLE], not_before, identity(i));
            assert!(dir.publish(d).unwrap(), "identity {i} should be accepted");
        }
    }

    #[test]
    fn test_cap_evicts_the_newest_never_republished_identity() {
        let ops = fake_ops();
        // A clock that ticks on every read, so identities 1..3 get
        // strictly increasing `first_seen` stamps in arrival order.
        let ticks = std::sync::Arc::new(std::sync::Mutex::new(0.0f64));
        let mut dir = Directory::new(DirectoryOptions {
            ops: fake_ops(),
            clock: Some(Box::new(move || {
                let mut t = ticks.lock().unwrap();
                *t += 1.0;
                TEST_CLOCK + *t
            })),
            max_descriptors: Some(3),
            max_new_identities_per_subnet: None,
            max_live_identities_per_subnet: None,
            ..Default::default()
        })
        .unwrap();
        fill(&mut dir, &ops, 1..=3, NOW);
        assert_eq!(dir.len(), 3);

        // A fourth identity gets in by pushing out identity 3, the one
        // with the shortest tenure that never came back to refresh.
        let d4 = make_descriptor(&ops, "10.4.0.1", 9000, &[ROLE_MIDDLE], NOW, identity(4));
        assert!(dir.publish(d4).unwrap());
        assert_eq!(dir.len(), 3);
        assert!(dir.get(&pubkey(&ops, 1)).is_some());
        assert!(dir.get(&pubkey(&ops, 2)).is_some());
        assert!(dir.get(&pubkey(&ops, 3)).is_none(), "the newest never-refreshed identity is the one evicted");
        assert!(dir.get(&pubkey(&ops, 4)).is_some());
    }

    #[test]
    fn test_cap_never_evicts_an_identity_that_has_refreshed() {
        let ops = fake_ops();
        let mut dir = capped_dir(2);
        fill(&mut dir, &ops, 1..=2, NOW);
        // Identity 2 refreshes: it is now a proven relay.
        let d2b = make_descriptor(&ops, "10.2.0.1", 9000, &[ROLE_MIDDLE], NOW + 1.0, identity(2));
        assert!(dir.publish(d2b).unwrap());

        // The newcomer displaces identity 1 (never refreshed), not 2.
        let d3 = make_descriptor(&ops, "10.3.0.1", 9000, &[ROLE_MIDDLE], NOW, identity(3));
        assert!(dir.publish(d3).unwrap());
        assert!(dir.get(&pubkey(&ops, 1)).is_none());
        assert!(dir.get(&pubkey(&ops, 2)).is_some());
        assert!(dir.get(&pubkey(&ops, 3)).is_some());
    }

    #[test]
    fn test_cap_refuses_newcomer_when_every_held_identity_has_refreshed() {
        let ops = fake_ops();
        let mut dir = capped_dir(2);
        fill(&mut dir, &ops, 1..=2, NOW);
        fill(&mut dir, &ops, 1..=2, NOW + 1.0); // both refresh
        let d3 = make_descriptor(&ops, "10.3.0.1", 9000, &[ROLE_MIDDLE], NOW, identity(3));
        let err = dir.publish(d3).unwrap_err();
        assert!(matches!(err, DirectoryError::DirectoryFull(_)), "{err}");
        assert_eq!(dir.len(), 2);
        // ...but a rotation of a held identity is always accepted: it
        // takes no new slot.
        let d1c = make_descriptor(&ops, "10.1.0.1", 9000, &[ROLE_MIDDLE], NOW + 2.0, identity(1));
        assert!(dir.publish(d1c).unwrap());
    }

    #[test]
    fn test_cap_frees_expired_descriptors_before_evicting_live_ones() {
        let ops = fake_ops();
        // A clock we can advance past identity 1's expiry.
        let now = std::sync::Arc::new(std::sync::Mutex::new(TEST_CLOCK));
        let clock_now = now.clone();
        let mut dir = Directory::new(DirectoryOptions {
            ops: fake_ops(),
            clock: Some(Box::new(move || *clock_now.lock().unwrap())),
            max_descriptors: Some(2),
            max_new_identities_per_subnet: None,
            max_live_identities_per_subnet: None,
            ..Default::default()
        })
        .unwrap();
        // Identity 1 is short-lived; identity 2 has refreshed (protected).
        let d1 = make_descriptor(&ops, "10.1.0.1", 9000, &[ROLE_MIDDLE], NOW, identity(1));
        let short = RelayDescriptor { not_after: TEST_CLOCK + 10.0, ..d1.clone() };
        let short = RelayDescriptor { signature: (ops.sign)(&identity(1), &short.signing_payload()).to_vec(), ..short };
        assert!(dir.publish(short).unwrap());
        fill(&mut dir, &ops, 2..=2, NOW);
        fill(&mut dir, &ops, 2..=2, NOW + 1.0);

        *now.lock().unwrap() = TEST_CLOCK + 20.0; // identity 1 has expired
        let d3 = make_descriptor(&ops, "10.3.0.1", 9000, &[ROLE_MIDDLE], NOW, identity(3));
        assert!(dir.publish(d3).unwrap(), "the expired slot is reclaimed, nothing live is evicted");
        assert!(dir.get(&pubkey(&ops, 2)).is_some());
        assert!(dir.get(&pubkey(&ops, 3)).is_some());
    }

    #[test]
    fn test_live_subnet_cap_bounds_one_address_block() {
        let ops = fake_ops();
        let mut dir = Directory::new(DirectoryOptions {
            ops: fake_ops(),
            clock: Some(Box::new(|| TEST_CLOCK)),
            max_new_identities_per_subnet: None, // only the live cap under test
            max_live_identities_per_subnet: Some(2),
            ..Default::default()
        })
        .unwrap();
        for i in 1..=2u8 {
            let d = make_descriptor(&ops, &format!("{i}.{i}.{i}.{i}"), 9000, &[ROLE_MIDDLE], NOW, identity(i));
            assert!(dir.publish_from(d, Some("10.0.0.1")).unwrap());
        }
        // Third identity from the same verified block: refused, however
        // different its self-declared host.
        let d3 = make_descriptor(&ops, "99.99.99.99", 9000, &[ROLE_MIDDLE], NOW, identity(3));
        assert!(matches!(dir.publish_from(d3, Some("10.0.0.1")), Err(DirectoryError::SybilRateLimited(_))));
        // A different block is unaffected...
        let d4 = make_descriptor(&ops, "99.99.99.98", 9000, &[ROLE_MIDDLE], NOW, identity(4));
        assert!(dir.publish_from(d4, Some("10.1.0.1")).unwrap());
        // ...and so is a rotation of an identity the block already holds.
        let d1b = make_descriptor(&ops, "1.1.1.1", 9001, &[ROLE_MIDDLE], NOW + 1.0, identity(1));
        assert!(dir.publish_from(d1b, Some("10.0.0.1")).unwrap());
    }

    #[test]
    fn test_serving_set_truncates_to_longest_record_first() {
        let ops = fake_ops();
        let mut dir = capped_dir(10);
        fill(&mut dir, &ops, 1..=4, NOW);
        // Identity 4 is the only one to refresh; it outranks the rest
        // regardless of arrival order.
        fill(&mut dir, &ops, 4..=4, NOW + 1.0);
        assert_eq!(dir.serving_set(10).len(), 4, "under the limit, everything is served");
        let served: Vec<[u8; KEY_LEN]> = dir.serving_set(2).iter().map(|d| d.identity_public).collect();
        assert_eq!(served.len(), 2);
        assert!(served.contains(&pubkey(&ops, 4)), "the refreshed relay is always kept");
        assert!(served.iter().all(|id| dir.get(id).is_some()));
    }

    #[test]
    fn test_cap_option_rejects_zero() {
        assert!(Directory::new(DirectoryOptions { ops: fake_ops(), max_descriptors: Some(0), ..Default::default() }).is_err());
        assert!(Directory::new(DirectoryOptions { ops: fake_ops(), max_live_identities_per_subnet: Some(0), ..Default::default() }).is_err());
    }

    #[test]
    fn test_select_route_diversity_uses_verified_subnet_not_self_declared_host() {
        // `enforce_subnet_diversity` must also key off
        // the verified publish source, not `descriptor.host` -- otherwise
        // an operator can claim unrelated self-signed `host` fields for
        // relays that actually sit behind the same real address block and
        // still pass as "diverse" route hops.
        let ops = fake_ops();
        let mut dir = make_dir(vec![], fake_ops());

        let guard = make_descriptor(&ops, "9.9.9.9", 1, &[ROLE_GUARD], NOW, identity(1));
        let guard_id = guard.identity_public;
        dir.publish_from(guard, Some("10.0.0.1")).unwrap();

        // Same verified subnet as the guard, despite an unrelated
        // self-declared host.
        let exit_same_subnet = make_descriptor(&ops, "1.1.1.1", 2, &[ROLE_EXIT], NOW, identity(2));
        dir.publish_from(exit_same_subnet, Some("10.0.0.9")).unwrap();

        // A genuinely different verified subnet.
        let exit_diff = make_descriptor(&ops, "2.2.2.2", 3, &[ROLE_EXIT], NOW, identity(3));
        let exit_diff_id = exit_diff.identity_public;
        dir.publish_from(exit_diff, Some("20.0.0.5")).unwrap();

        let route = dir
            .select_route(SelectRouteOptions { hops: 2, preferred_guard: Some(guard_id), require_preferred_guard: true, ..Default::default() })
            .unwrap();
        assert_eq!(route.len(), 2);
        assert_eq!(route[0].identity_public, guard_id);
        assert_eq!(route[1].identity_public, exit_diff_id);
    }

    /// Security fix: the same anti-collusion property as the test above,
    /// but through `publish_verified` -- what `fetch_relay_directory`
    /// actually calls with a quorum-of-authorities-agreed subnet (see
    /// `consensus::compute_consensus`), since a client building its
    /// directory this way has no live connection to each relay to derive
    /// a `publish_from`-style source address from directly.
    #[test]
    fn test_select_route_diversity_uses_quorum_verified_subnet() {
        let ops = fake_ops();
        let mut dir = make_dir(vec![], fake_ops());

        let guard = make_descriptor(&ops, "9.9.9.9", 1, &[ROLE_GUARD], NOW, identity(1));
        let guard_id = guard.identity_public;
        dir.publish_verified(guard, Some(SubnetKey::V4([10, 0]))).unwrap();

        // Same quorum-verified subnet as the guard, despite an unrelated
        // self-declared host -- exactly the collusion this fix closes.
        let exit_same_subnet = make_descriptor(&ops, "1.1.1.1", 2, &[ROLE_EXIT], NOW, identity(2));
        dir.publish_verified(exit_same_subnet, Some(SubnetKey::V4([10, 0]))).unwrap();

        // A genuinely different quorum-verified subnet.
        let exit_diff = make_descriptor(&ops, "2.2.2.2", 3, &[ROLE_EXIT], NOW, identity(3));
        let exit_diff_id = exit_diff.identity_public;
        dir.publish_verified(exit_diff, Some(SubnetKey::V4([20, 0]))).unwrap();

        let route = dir
            .select_route(SelectRouteOptions { hops: 2, preferred_guard: Some(guard_id), require_preferred_guard: true, ..Default::default() })
            .unwrap();
        assert_eq!(route.len(), 2);
        assert_eq!(route[0].identity_public, guard_id);
        assert_eq!(route[1].identity_public, exit_diff_id, "the same-subnet colluding exit must be skipped in favor of the genuinely diverse one");
    }

    /// Without any quorum-verified subnet at all (e.g. `publish_verified`
    /// called with `None`, matching a single-authority legacy-FETCH
    /// fallback with no votes to aggregate), `subnet_of` must fall back to
    /// the self-declared host exactly as it always did -- this fix must
    /// not make diversity checking *more* permissive than before when
    /// there's genuinely no verified data to use.
    #[test]
    fn test_select_route_falls_back_to_self_declared_host_without_a_verified_subnet() {
        let ops = fake_ops();
        let mut dir = make_dir(vec![], fake_ops());

        let guard = make_descriptor(&ops, "9.9.9.9", 1, &[ROLE_GUARD], NOW, identity(1));
        let guard_id = guard.identity_public;
        dir.publish_verified(guard, None).unwrap();

        let exit_same_host_subnet = make_descriptor(&ops, "9.9.9.9", 2, &[ROLE_EXIT], NOW, identity(2));
        dir.publish_verified(exit_same_host_subnet, None).unwrap();

        let exit_diff = make_descriptor(&ops, "2.2.2.2", 3, &[ROLE_EXIT], NOW, identity(3));
        let exit_diff_id = exit_diff.identity_public;
        dir.publish_verified(exit_diff, None).unwrap();

        let route = dir
            .select_route(SelectRouteOptions { hops: 2, preferred_guard: Some(guard_id), require_preferred_guard: true, ..Default::default() })
            .unwrap();
        assert_eq!(route.len(), 2);
        assert_eq!(route[0].identity_public, guard_id);
        assert_eq!(route[1].identity_public, exit_diff_id, "same self-declared host as the guard must still be skipped when no verified subnet exists for either");
    }

    /// A clock a test can advance after construction, for simulating the
    /// passage of time between a publish and a later `select_route` call
    /// -- `Directory`'s own clock closure must be `Send`, so this uses
    /// `Arc<Mutex<f64>>` rather than the `Rc<RefCell<_>>` some other
    /// modules' tests use for the same purpose.
    fn movable_clock(start: f64) -> (Box<dyn Fn() -> f64 + Send>, Arc<Mutex<f64>>) {
        let now = Arc::new(Mutex::new(start));
        let reader = Arc::clone(&now);
        (Box::new(move || *reader.lock().unwrap()), now)
    }

    /// Security audit fix (2026-09-26, finding #5 -- no vetting before
    /// self-declaring "guard"): with `min_guard_age_seconds` set, a guard
    /// published moments ago must not be picked for an unpinned guard
    /// slot -- a brand-new identity cannot claim the guard role on day
    /// one just by setting the role byte in its own signed descriptor.
    #[test]
    fn test_select_route_guard_vetting_rejects_a_brand_new_guard() {
        let ops = fake_ops();
        let (clock, _now) = movable_clock(NOW);
        let mut dir = Directory::new(DirectoryOptions { ops: fake_ops(), clock: Some(clock), min_guard_age_seconds: Some(3600.0), ..Default::default() }).unwrap();
        dir.publish(make_descriptor(&ops, "9.9.9.9", 1, &[ROLE_GUARD], NOW, identity(1))).unwrap();
        dir.publish(make_descriptor(&ops, "9.9.9.10", 2, &[ROLE_EXIT], NOW, identity(2))).unwrap();

        let err = dir.select_route(SelectRouteOptions { hops: 2, seed: Some(1), ..Default::default() }).unwrap_err();
        assert!(matches!(err, DirectoryError::Generic(_)), "expected a vetting-specific error, got {err:?}");
    }

    /// Same setup, but the clock advances past `min_guard_age_seconds`
    /// before the route is built -- the guard is now eligible.
    #[test]
    fn test_select_route_guard_vetting_accepts_a_guard_once_old_enough() {
        let ops = fake_ops();
        let (clock, now) = movable_clock(NOW);
        let mut dir = Directory::new(DirectoryOptions { ops: fake_ops(), clock: Some(clock), min_guard_age_seconds: Some(3600.0), ..Default::default() }).unwrap();
        let guard = make_descriptor(&ops, "9.9.9.9", 1, &[ROLE_GUARD], NOW, identity(1));
        let guard_id = guard.identity_public;
        dir.publish(guard).unwrap();
        dir.publish(make_descriptor(&ops, "9.9.9.10", 2, &[ROLE_EXIT], NOW, identity(2))).unwrap();

        *now.lock().unwrap() += 3600.0;
        let route = dir.select_route(SelectRouteOptions { hops: 2, seed: Some(1), ..Default::default() }).unwrap();
        assert_eq!(route[0].identity_public, guard_id);
    }

    /// An explicit `preferred_guard` already carries its own trust basis
    /// (normally a previous session's own persisted choice) and must not
    /// be re-vetted from scratch -- otherwise every client restart would
    /// forget its already-established guard relationship and hard-fail
    /// route building until a fresh `min_guard_age_seconds` window elapses
    /// all over again.
    #[test]
    fn test_select_route_guard_vetting_exempts_an_explicit_preferred_guard() {
        let ops = fake_ops();
        let (clock, _now) = movable_clock(NOW);
        let mut dir = Directory::new(DirectoryOptions { ops: fake_ops(), clock: Some(clock), min_guard_age_seconds: Some(3600.0), ..Default::default() }).unwrap();
        let guard = make_descriptor(&ops, "9.9.9.9", 1, &[ROLE_GUARD], NOW, identity(1));
        let guard_id = guard.identity_public;
        dir.publish(guard).unwrap();
        dir.publish(make_descriptor(&ops, "9.9.9.10", 2, &[ROLE_EXIT], NOW, identity(2))).unwrap();

        let route = dir
            .select_route(SelectRouteOptions { hops: 2, seed: Some(1), preferred_guard: Some(guard_id), require_preferred_guard: true, ..Default::default() })
            .unwrap();
        assert_eq!(route[0].identity_public, guard_id);
    }

    /// `set_first_seen`/`first_seen_snapshot` round-trip: a caller that
    /// persists guard-observation history across `Directory` rebuilds
    /// (this object's own lifetime is normally one fetch cycle) can seed
    /// it back in, and a guard already old enough per the seeded history
    /// is immediately eligible even though this particular `Directory`
    /// instance just published it for the first time.
    #[test]
    fn test_first_seen_seeded_externally_makes_a_guard_immediately_eligible() {
        let ops = fake_ops();
        let (clock, _now) = movable_clock(NOW);
        let mut dir = Directory::new(DirectoryOptions { ops: fake_ops(), clock: Some(clock), min_guard_age_seconds: Some(3600.0), ..Default::default() }).unwrap();
        let guard = make_descriptor(&ops, "9.9.9.9", 1, &[ROLE_GUARD], NOW, identity(1));
        let guard_id = guard.identity_public;
        dir.set_first_seen(vec![(guard_id, NOW - 7200.0)]);
        dir.publish(guard).unwrap();
        dir.publish(make_descriptor(&ops, "9.9.9.10", 2, &[ROLE_EXIT], NOW, identity(2))).unwrap();

        let route = dir.select_route(SelectRouteOptions { hops: 2, seed: Some(1), ..Default::default() }).unwrap();
        assert_eq!(route[0].identity_public, guard_id);
        assert_eq!(dir.first_seen_snapshot().get(&guard_id), Some(&(NOW - 7200.0)), "publish must not overwrite an externally seeded, earlier first_seen");
    }

    #[test]
    fn test_select_route_picks_distinct_guard_middle_exit() {
        let ops = fake_ops();
        let mut dir = make_dir(vec![], fake_ops());
        dir.publish(make_descriptor(&ops, "10.0.1.1", 1, &[ROLE_GUARD], NOW, identity(1))).unwrap();
        dir.publish(make_descriptor(&ops, "10.0.2.1", 2, &[ROLE_MIDDLE], NOW, identity(2))).unwrap();
        dir.publish(make_descriptor(&ops, "10.0.3.1", 3, &[ROLE_EXIT], NOW, identity(3))).unwrap();
        let route = dir.select_route(SelectRouteOptions { hops: 3, seed: Some(42), ..Default::default() }).unwrap();
        assert_eq!(route.len(), 3);
        let ids: std::collections::HashSet<_> = route.iter().map(|d| d.identity_public).collect();
        assert_eq!(ids.len(), 3);
        assert!(route[0].roles.contains(&ROLE_GUARD.to_string()));
        assert!(route[2].roles.contains(&ROLE_EXIT.to_string()));
    }

    #[test]
    fn test_select_route_fails_with_insufficient_relays() {
        let dir = make_dir(vec![], fake_ops());
        assert!(dir.select_route(SelectRouteOptions { hops: 3, ..Default::default() }).is_err());
    }

    #[test]
    fn test_select_route_preferred_guard_used_when_live() {
        let ops = fake_ops();
        let mut dir = make_dir(vec![], fake_ops());
        dir.publish(make_descriptor(&ops, "10.0.1.1", 1, &[ROLE_GUARD], NOW, identity(1))).unwrap();
        dir.publish(make_descriptor(&ops, "10.0.1.2", 2, &[ROLE_GUARD], NOW, identity(2))).unwrap();
        dir.publish(make_descriptor(&ops, "10.0.3.1", 3, &[ROLE_EXIT], NOW, identity(3))).unwrap();
        let preferred = (ops.public_of)(&identity(2));
        let route = dir
            .select_route(SelectRouteOptions { hops: 2, seed: Some(1), preferred_guard: Some(preferred), ..Default::default() })
            .unwrap();
        assert_eq!(route[0].identity_public, preferred);
    }

    #[test]
    fn test_select_route_require_preferred_guard_raises_when_absent() {
        let ops = fake_ops();
        let mut dir = make_dir(vec![], fake_ops());
        dir.publish(make_descriptor(&ops, "10.0.1.1", 1, &[ROLE_GUARD], NOW, identity(1))).unwrap();
        dir.publish(make_descriptor(&ops, "10.0.3.1", 3, &[ROLE_EXIT], NOW, identity(3))).unwrap();
        let result = dir.select_route(SelectRouteOptions {
            hops: 2,
            preferred_guard: Some(identity(200)),
            require_preferred_guard: true,
            ..Default::default()
        });
        assert!(matches!(result, Err(DirectoryError::PreferredGuardUnavailable(_))));
    }

    #[test]
    fn test_select_route_excludes_identities() {
        let ops = fake_ops();
        let mut dir = make_dir(vec![], fake_ops());
        dir.publish(make_descriptor(&ops, "10.0.1.1", 1, &[ROLE_GUARD], NOW, identity(1))).unwrap();
        dir.publish(make_descriptor(&ops, "10.0.1.2", 2, &[ROLE_GUARD], NOW, identity(2))).unwrap();
        dir.publish(make_descriptor(&ops, "10.0.3.1", 3, &[ROLE_EXIT], NOW, identity(3))).unwrap();
        let excluded = (ops.public_of)(&identity(1));
        let route = dir
            .select_route(SelectRouteOptions { hops: 2, seed: Some(7), exclude_identities: vec![excluded], ..Default::default() })
            .unwrap();
        assert_ne!(route[0].identity_public, excluded);
    }

    #[test]
    fn test_select_route_exit_port_filters() {
        let ops = fake_ops();
        let mut dir = make_dir(vec![], fake_ops());
        dir.publish(make_descriptor(&ops, "10.0.1.1", 1, &[ROLE_GUARD], NOW, identity(1))).unwrap();
        let mut opts = CreateOptions::default();
        opts.exit_ports = Some(vec![443]);
        let exit_443 = RelayDescriptor::create(&ops, &identity(3), &identity(9), "10.0.3.1", 3, &[ROLE_EXIT], DEFAULT_DESCRIPTOR_LIFETIME, Some(NOW), opts).unwrap();
        dir.publish(exit_443).unwrap();
        let route = dir.select_route(SelectRouteOptions { hops: 2, seed: Some(3), exit_port: Some(443), ..Default::default() }).unwrap();
        assert_eq!(route[1].allows_exit_port(443), Some(true));

        let result = dir.select_route(SelectRouteOptions { hops: 2, seed: Some(3), exit_port: Some(9999), ..Default::default() });
        assert!(result.is_err());
    }

    #[test]
    fn test_prune_removes_expired() {
        let ops = fake_ops();
        // A shared, advanceable clock: publish while it reads NOW (inside
        // the descriptor's validity window), then move it forward past
        // `not_after` and confirm `prune()` drops the now-expired entry.
        let clock_value = Arc::new(Mutex::new(NOW));
        let clock_for_dir = clock_value.clone();
        let mut dir = Directory::new(DirectoryOptions {
            ops: fake_ops(),
            clock: Some(Box::new(move || *clock_for_dir.lock().unwrap())),
            ..Default::default()
        })
        .unwrap();
        let d = make_descriptor(&ops, "10.0.0.1", 1, &[ROLE_MIDDLE], NOW, identity(1));
        let key = d.identity_public;
        assert!(dir.publish(d).unwrap());
        assert!(dir.get(&key).is_some());
        *clock_value.lock().unwrap() = NOW + DEFAULT_DESCRIPTOR_LIFETIME + 100.0;
        assert!(dir.get(&key).is_none());
        assert_eq!(dir.prune(), 1);
        assert_eq!(dir.len(), 0);
    }

    #[test]
    fn test_ports_to_ranges_collapses_consecutive() {
        assert_eq!(ports_to_ranges(&[80, 81, 82, 443]), vec![(80, 82), (443, 443)]);
    }

    #[test]
    fn test_subnet_key_groups_v4_by_16() {
        assert_eq!(subnet_key("10.0.1.1"), subnet_key("10.0.2.2"));
        assert_ne!(subnet_key("10.0.1.1"), subnet_key("10.1.1.1"));
        assert_eq!(subnet_key("not-an-ip"), None);
    }

    // -- fetch_relay_directory / dir_round_trip: pure-logic edges only --
    // the actual network round trip needs a live authority and is not
    // exercised here; see this module's own docs on `dir_round_trip` for
    // what remains "written but unverified pending a live
    // network".

    #[test]
    fn test_fetch_relay_directory_rejects_empty_address_list() {
        // Pure logic, no network: `fetch_relay_directory` checks this
        // before ever opening a socket. A real network round trip (a live
        // authority actually answering) is not exercised by this test
        // suite -- see this module's own docs on `dir_round_trip` for
        // what remains "written but unverified pending a
        // live network" (a real per-address round trip can take up to
        // ~20s on failure per `DIR_ROUND_TRIP_TIMEOUT`'s own docs, far too
        // slow for this crate's otherwise-instant unit test suite).
        let err = fetch_relay_directory(&[], None).unwrap_err();
        assert!(matches!(err, DirectoryError::Generic(_)));
    }

    /// Security audit fix (2026-09-26, finding H1): pure logic, no network
    /// -- see `test_fetch_relay_directory_rejects_empty_address_list`'s own
    /// doc for why a real round trip isn't exercised here; a real 2-hop
    /// round trip through an actual second relay to a live authority is
    /// exercised by `allium-authority-cli`'s own
    /// `test_dir_round_trip_over_circuit_reaches_a_real_authority_through_a_real_relay_hop`.
    #[test]
    fn test_dir_round_trip_over_circuit_rejects_empty_hops() {
        let err = dir_round_trip_over_circuit(&[], None, b"irrelevant").unwrap_err();
        assert!(matches!(err, DirectoryError::Generic(_)));
    }

    /// The authority must answer VOTE_REQUEST with a vote that verifies
    /// against its own pinned identity (the `--trust-authority` key) and
    /// lists each live relay under the exact descriptor digest a client
    /// will recompute from the FETCH reply.
    #[test]
    fn test_authority_signs_a_vote_clients_can_verify() {
        let options = crate::relay::RelayNodeOptions { master_key: Some(vec![42u8; 32]), ..Default::default() };
        let node = Rc::new(RefCell::new(RelayNode::new(options).unwrap()));
        let authority_public = node.borrow().identity_public();

        let directory = Rc::new(RefCell::new(Directory::new(DirectoryOptions::default()).unwrap()));
        let ops = Ed25519Ops::real();
        let descriptor = RelayDescriptor::create(
            &ops, &[9u8; KEY_LEN], &[7u8; KEY_LEN], "8.8.8.8", 9003, &["exit"],
            DEFAULT_DESCRIPTOR_LIFETIME, None, CreateOptions::default(),
        )
        .unwrap();
        assert_eq!(directory.borrow_mut().publish(descriptor.clone()).unwrap(), true);

        let vote_bytes = AuthorityService::encode_signed_vote(&node, &directory).expect("vote must encode");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
        let verify = |public: &[u8; 32], sig: &[u8; 64], message: &[u8]| {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            VerifyingKey::from_bytes(public)
                .map(|k| k.verify(message, &Signature::from_bytes(sig)).is_ok())
                .unwrap_or(false)
        };
        let vote = crate::consensus::decode_vote(
            &vote_bytes,
            crate::consensus::Trusted::Keys(&[authority_public]),
            now,
            verify,
        )
        .expect("vote must verify against the authority's own identity");
        assert_eq!(vote.authority, authority_public);
        assert_eq!(vote.entries.len(), 1);
        assert_eq!(vote.entries[0].0.to_vec(), descriptor.identity_public.to_vec());
        assert_eq!(vote.entries[0].1, crate::consensus::descriptor_digest(&descriptor));

        // A vote from some other key must be rejected by a client pinned
        // to this authority.
        let other = crate::consensus::decode_vote(&vote_bytes, crate::consensus::Trusted::Keys(&[[1u8; 32]]), now, verify);
        assert!(other.is_err());
    }

    // -- `Directory::publish` rejects a relay's self-signed
    // `EXT_REACHABILITY` introducer unless it names an identity this
    // directory was configured to recognize. -------------------------

    fn reachability_extension(introducer_identity: &[u8; KEY_LEN], host: &str, port: u16) -> Vec<u8> {
        let mut out = vec![crate::nat::MODE_NAT];
        out.extend_from_slice(introducer_identity);
        out.extend_from_slice(&[0u8; KEY_LEN]); // introducer_x25519_public, not exercised by this test
        let host_bytes = host.as_bytes();
        out.push(host_bytes.len() as u8);
        out.extend_from_slice(host_bytes);
        out.extend_from_slice(&port.to_be_bytes());
        out
    }

    fn descriptor_with_reachability(ops: &Ed25519Ops, introducer_identity: &[u8; KEY_LEN]) -> RelayDescriptor {
        let reach = reachability_extension(introducer_identity, "203.0.113.9", 4242);
        RelayDescriptor::create(
            ops,
            &identity(1),
            &[7u8; KEY_LEN],
            "10.0.0.1",
            9001,
            &[ROLE_MIDDLE],
            DEFAULT_DESCRIPTOR_LIFETIME,
            Some(NOW),
            CreateOptions { extra_extensions: vec![(EXT_REACHABILITY, reach)], ..Default::default() },
        )
        .unwrap()
    }

    /// The pre-existing, permissive behavior must survive unchanged for a
    /// directory that hasn't opted into `known_introducers`: any
    /// reachability extension that merely parses is still accepted.
    #[test]
    fn publish_accepts_any_reachability_extension_when_known_introducers_is_unset() {
        let ops = fake_ops();
        let d = descriptor_with_reachability(&ops, &identity(99));
        let mut dir = Directory::new(DirectoryOptions { ops: fake_ops(), clock: Some(Box::new(|| NOW)), ..Default::default() }).unwrap();
        assert!(dir.publish(d).unwrap());
    }

    /// Once configured, a descriptor naming an introducer outside
    /// `known_introducers` is rejected -- a relay can no longer send a
    /// client to an arbitrary self-declared address by simply claiming it
    /// as the NAT introducer.
    #[test]
    fn publish_rejects_a_reachability_extension_naming_an_unknown_introducer() {
        let ops = fake_ops();
        let d = descriptor_with_reachability(&ops, &identity(66));
        let mut dir = Directory::new(DirectoryOptions {
            ops: fake_ops(),
            clock: Some(Box::new(|| NOW)),
            known_introducers: vec![identity(9)],
            ..Default::default()
        })
        .unwrap();
        assert!(matches!(dir.publish(d), Err(DirectoryError::DescriptorMalformed(_))));
    }

    /// A descriptor naming a `known_introducers` entry -- e.g. this
    /// authority's own identity, as `allium-authority-cli` configures --
    /// still publishes normally.
    #[test]
    fn publish_accepts_a_reachability_extension_naming_a_known_introducer() {
        let ops = fake_ops();
        let authority_identity = identity(9);
        let d = descriptor_with_reachability(&ops, &authority_identity);
        let mut dir = Directory::new(DirectoryOptions {
            ops: fake_ops(),
            clock: Some(Box::new(|| NOW)),
            known_introducers: vec![authority_identity],
            ..Default::default()
        })
        .unwrap();
        assert!(dir.publish(d).unwrap());
    }

    // -- DirRequestReassemblers: bounded, per-peer, keyed by the full circuit key --

    fn dir_key(host: &str, circuit_id: u32) -> CircuitKeyTuple {
        (host.to_string(), 9001, circuit_id)
    }

    fn dir_frag(offset: u32, fin: bool, data: Vec<u8>) -> Vec<u8> {
        crate::fragment::encode_fragment(&crate::fragment::Fragment::new(crate::dirwire::DIR_STREAM_ID, offset, fin, data))
    }

    #[test]
    fn test_dir_requests_from_different_peers_with_the_same_circuit_id_do_not_mix() {
        let mut t = DirRequestReassemblers::default();
        let (a, b) = (dir_key("10.0.0.1", 7), dir_key("10.0.0.2", 7));
        // two peers, same circuit id, each sends half of its own request
        assert!(t.push(&a, &dir_frag(0, false, b"AAAA".to_vec())).is_none());
        assert!(t.push(&b, &dir_frag(0, false, b"BBBB".to_vec())).is_none());
        let done_a = t.push(&a, &dir_frag(4, true, b"aaaa".to_vec())).unwrap();
        let done_b = t.push(&b, &dir_frag(4, true, b"bbbb".to_vec())).unwrap();
        assert_eq!(done_a, b"AAAAaaaa".to_vec());
        assert_eq!(done_b, b"BBBBbbbb".to_vec());
        assert!(t.map.is_empty());
        assert!(t.per_peer.is_empty());
    }

    #[test]
    fn test_dir_request_over_the_request_cap_is_dropped_not_buffered_forever() {
        let mut t = DirRequestReassemblers::default();
        let k = dir_key("10.0.0.1", 1);
        let mut off = 0u32;
        let mut dropped = false;
        for _ in 0..(crate::dirwire::MAX_REQUEST_REASSEMBLED_LEN / 1000 + 50) {
            t.push(&k, &dir_frag(off, false, vec![0u8; 1000]));
            off += 1000;
            if !t.map.contains_key(&k) {
                dropped = true;
                break;
            }
        }
        assert!(dropped, "an endless non-FIN request must be cut off at the request cap");
        assert!(t.per_peer.is_empty());
    }

    #[test]
    fn test_dir_requests_are_capped_per_peer_address() {
        let mut t = DirRequestReassemblers::default();
        for id in 0..100u32 {
            t.push(&dir_key("10.0.0.1", id), &dir_frag(0, false, vec![1u8; 100]));
        }
        assert_eq!(t.per_peer.get("10.0.0.1").copied(), Some(MAX_PENDING_DIR_REASSEMBLERS_PER_PEER));
        // another peer is unaffected by the first one's flood
        assert!(t.push(&dir_key("10.0.0.2", 1), &dir_frag(0, true, b"hi".to_vec())).is_some());
    }

    #[test]
    fn test_dir_requests_global_cap_evicts_the_biggest_holder() {
        let mut t = DirRequestReassemblers::default();
        // one peer pins a lot; many others each hold a little
        t.push(&dir_key("9.9.9.9", 0), &dir_frag(0, false, vec![1u8; 50_000]));
        let mut n = 0u32;
        'fill: for host in 0..MAX_PENDING_DIR_REASSEMBLERS as u32 {
            t.push(&dir_key(&format!("10.1.{}.{}", host / 256, host % 256), 1), &dir_frag(0, false, vec![1u8; 10]));
            n += 1;
            if t.map.len() == MAX_PENDING_DIR_REASSEMBLERS {
                break 'fill;
            }
        }
        assert!(n > 0 && t.map.len() == MAX_PENDING_DIR_REASSEMBLERS);
        t.push(&dir_key("10.200.0.1", 1), &dir_frag(0, false, vec![1u8; 10]));
        assert_eq!(t.map.len(), MAX_PENDING_DIR_REASSEMBLERS);
        assert!(!t.map.contains_key(&dir_key("9.9.9.9", 0)), "the big holder is the one evicted");
        assert!(t.per_peer.get("9.9.9.9").is_none());
    }

    #[test]
    fn test_dir_forget_circuit_drops_a_half_received_request() {
        let mut t = DirRequestReassemblers::default();
        let k = dir_key("10.0.0.1", 3);
        t.push(&k, &dir_frag(0, false, vec![1u8; 100]));
        assert!(t.map.contains_key(&k));
        t.forget(&k);
        assert!(t.map.is_empty() && t.per_peer.is_empty());
        t.forget(&k); // idempotent
        assert!(t.per_peer.is_empty());
    }

    // -- AuthorityMaintenance: periodic prune --

    #[test]
    fn test_maybe_prune_runs_once_per_interval() {
        use crate::hiddenservice::BlindedHsDirectory;
        let directory = Rc::new(RefCell::new(Directory::new(DirectoryOptions::default()).unwrap()));
        let hsd = Rc::new(RefCell::new(BlindedHsDirectory::new(None, None, crate::hiddenservice::HsOps::real()).unwrap()));
        let mut m = AuthorityMaintenance::default();
        m.maybe_prune(&directory, Some(&hsd));
        let first = m.last_prune.expect("first call prunes");
        m.maybe_prune(&directory, Some(&hsd));
        assert_eq!(m.last_prune, Some(first), "a second call inside the interval does nothing");
    }

    #[test]
    fn test_hs3_publishes_are_not_rate_limited_or_charged_to_the_delivering_peer() {
        use crate::hiddenservice::{hs_directory_period, BlindedDescriptor, BlindedHsDirectory, HsOps, HS_DIRECTORY_INDEX_PERIOD, MAX_BLINDED_PER_SOURCE};
        use ed25519_dalek::{Signer, SigningKey};
        const NOW: f64 = 1_700_000_000.0;
        let hsd = Rc::new(RefCell::new(BlindedHsDirectory::new(Some(std::sync::Arc::new(|| NOW)), None, HsOps::real()).unwrap()));
        let period = hs_directory_period(Some(NOW), HS_DIRECTORY_INDEX_PERIOD);
        // Every one of these arrives through the same middle relay. The old
        // limiter allowed a burst of 16 and the old quota 128 per network;
        // more than both must all be stored, since the middle's address says
        // nothing about who published.
        let total = MAX_BLINDED_PER_SOURCE as u32 + 40;
        for n in 0..total {
            let mut seed = [7u8; 32];
            seed[..4].copy_from_slice(&n.to_be_bytes());
            let key = SigningKey::from_bytes(&seed);
            let mut d = BlindedDescriptor {
                blinded_public: key.verifying_key().to_bytes(),
                period,
                not_before: NOW - 10.0,
                not_after: NOW + 3000.0,
                salt: [0u8; crate::dirwire::BLINDED_SALT_LEN],
                ciphertext: vec![1u8; 8],
                signature: Vec::new(),
            };
            d.signature = key.sign(&d.signing_payload()).to_bytes().to_vec();
            let reply = AuthorityService::answer_hs3_publish(&hsd, d);
            assert_eq!(crate::dirwire::decode_hs3_publish_reply(&reply).unwrap(), (true, String::new()), "publish {n} was refused");
        }
        assert_eq!(hsd.borrow().len(), total as usize);
    }
}
