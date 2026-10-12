//! A signed relay directory: discovery without a central server (Rust port
//! of `directory.py`).
//!
//! * A [`RelayDescriptor`] is **self-signed** by the relay's own Ed25519
//!   identity key. The signature covers every field ([`RelayDescriptor::signing_payload`]),
//!   so a descriptor is valid iff it verifies against the identity key it
//!   advertises -- no central authority has to vouch for it.
//! * A [`Directory`] is just a gatherer of these: it accepts any descriptor
//!   whose signature verifies and whose validity window has not passed, and
//!   serves relays for circuit selection.
//! * An optional set of trusted authority keys can be supplied
//!   ([`DirectoryOptions::authorities`]) to restrict acceptance to an
//!   allowlist of relay identities.
//!
//! Revocation and rotation fall out of the validity window: a descriptor
//! has `not_before`/`not_after`, so a relay rotates by publishing a new one
//! and lets the old expire.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Descriptor schema v1: signed fixed fields, no extensions.
pub const DESCRIPTOR_VERSION_1: u8 = 1;
/// Descriptor schema v2: v1 fields plus a signed, typed extension list.
pub const DESCRIPTOR_VERSION_2: u8 = 2;
pub const CURRENT_DESCRIPTOR_VERSION: u8 = DESCRIPTOR_VERSION_2;

/// Self-reported sustainable throughput, bytes/second (u64, big-endian).
pub const EXT_BANDWIDTH: u8 = 1;
/// Exit port summary: u16 count, then that many (u16 lo, u16 hi) inclusive
/// ranges, sorted and non-overlapping.
pub const EXT_EXIT_PORTS: u8 = 2;
/// Family: concatenated 32-byte Ed25519 identities of other relays run by
/// the same operator, sorted.
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
/// Ceiling on a *self-reported* bandwidth's selection weight, bytes/second.
pub const MAX_SELF_REPORTED_BANDWIDTH: u64 = 12_500_000; // 100 Mbit/s

/// How long a freshly minted descriptor stays valid, in seconds.
pub const DEFAULT_DESCRIPTOR_LIFETIME: f64 = 3600.0;
/// Longest `not_after - not_before` span a [`Directory`] accepts by default.
pub const MAX_DESCRIPTOR_LIFETIME: f64 = DEFAULT_DESCRIPTOR_LIFETIME * 24.0;

pub const ROLE_GUARD: &str = "guard";
pub const ROLE_MIDDLE: &str = "middle";
pub const ROLE_EXIT: &str = "exit";

/// Default IPv4 prefix length two relays must differ in to count as
/// "diverse" for subnet-key grouping (the same granularity real Tor's path
/// selection uses).
const SUBNET_PREFIX_V4: u32 = 16;
/// Equivalent granularity for IPv6.
const SUBNET_PREFIX_V6: u32 = 32;

/// Every error this module raises, mirroring Python's exception hierarchy
/// (`DirectoryError` and its subclasses) as one enum with a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryError {
    /// A descriptor's signature did not verify against its advertised
    /// identity (also raised for a wrong-size key).
    SignatureInvalid(String),
    /// A descriptor was outside its validity window when used.
    DescriptorExpired(String),
    /// A descriptor's version or signed extension block is structurally
    /// invalid.
    DescriptorMalformed(String),
    /// A descriptor's `not_after - not_before` span exceeds the directory's
    /// configured maximum.
    DescriptorLifetimeTooLong(String),
    /// A *new* identity was refused because its address block already
    /// published as many other new identities as this directory allows
    /// within the current window.
    SybilRateLimited(String),
    /// `select_route` was asked to keep a specific guard
    /// (`require_preferred_guard`), but it is not among the currently live
    /// guards.
    PreferredGuardUnavailable(String),
    /// Any other directory error (bad constructor argument, no live relay
    /// for a requested position, and so on).
    Other(String),
}

impl std::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirectoryError::SignatureInvalid(m)
            | DirectoryError::DescriptorExpired(m)
            | DirectoryError::DescriptorMalformed(m)
            | DirectoryError::DescriptorLifetimeTooLong(m)
            | DirectoryError::SybilRateLimited(m)
            | DirectoryError::PreferredGuardUnavailable(m)
            | DirectoryError::Other(m) => write!(f, "{m}"),
        }
    }
}
impl std::error::Error for DirectoryError {}

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
    let mut out = Vec::with_capacity(2 + 4 * ranges.len());
    out.extend_from_slice(&(ranges.len() as u16).to_be_bytes());
    for &(lo, hi) in ranges {
        out.extend_from_slice(&lo.to_be_bytes());
        out.extend_from_slice(&hi.to_be_bytes());
    }
    out
}

fn encode_ext_family(identities: &[Vec<u8>]) -> Vec<u8> {
    let mut members: Vec<Vec<u8>> = identities.to_vec();
    members.sort();
    members.dedup();
    members.into_iter().flatten().collect()
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
        let lo = u16::from_be_bytes([raw[2 + 4 * i], raw[3 + 4 * i]]);
        let hi = u16::from_be_bytes([raw[4 + 4 * i], raw[5 + 4 * i]]);
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

fn now_unix() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64()
}

/// A relay's self-signed record: who it is, where, and what it will do.
///
/// The signature covers every field (see [`Self::signing_payload`]), so a
/// descriptor cannot be edited in flight -- not its address, not its keys,
/// not its expiry.
///
/// Fields use `Vec<u8>`/`String` rather than fixed-size types so a
/// descriptor can be *constructed* with a malformed key (mirroring
/// Python's untyped tuple fields); [`Self::verify`]/[`Self::check_structure`]
/// are where a wrong size is actually caught.
#[derive(Debug, Clone, PartialEq)]
pub struct RelayDescriptor {
    pub identity_public: Vec<u8>,
    pub static_public: Vec<u8>,
    pub host: String,
    pub port: u16,
    pub roles: Vec<String>,
    pub not_before: f64,
    pub not_after: f64,
    pub signature: Vec<u8>,
    pub version: u8,
    /// `(type, value)`, sorted by type, all signed (v2 only).
    pub extensions: Vec<(u8, Vec<u8>)>,
}

impl RelayDescriptor {
    /// A descriptor with `signature: vec![]`, `version: 1`, `extensions: []`
    /// -- Python's field defaults for a hand-built (not [`Self::create`]d)
    /// descriptor.
    pub fn new(
        identity_public: Vec<u8>,
        static_public: Vec<u8>,
        host: impl Into<String>,
        port: u16,
        roles: Vec<String>,
        not_before: f64,
        not_after: f64,
    ) -> Self {
        RelayDescriptor {
            identity_public,
            static_public,
            host: host.into(),
            port,
            roles,
            not_before,
            not_after,
            signature: Vec::new(),
            version: DESCRIPTOR_VERSION_1,
            extensions: Vec::new(),
        }
    }

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

    /// Accepted TCP port ranges, or `None` when unknown (v1, or no summary
    /// advertised). A malformed summary decodes as `Some(vec![])`, matching
    /// Python's `except DescriptorMalformed: return ()`.
    pub fn exit_port_ranges(&self) -> Option<Vec<(u16, u16)>> {
        let raw = self.extension(EXT_EXIT_PORTS)?;
        Some(parse_exit_ports(raw).unwrap_or_default())
    }

    /// Identities this relay *declares* as family (not necessarily mutual
    /// -- see [`Directory::family_of`]).
    pub fn family(&self) -> HashSet<Vec<u8>> {
        match self.extension(EXT_FAMILY) {
            Some(raw) if !raw.is_empty() && raw.len() % 32 == 0 => {
                raw.chunks_exact(32).map(|c| c.to_vec()).collect()
            }
            _ => HashSet::new(),
        }
    }

    /// The relay's advertised ML-KEM-768 encapsulation key, or `None` (a v1
    /// descriptor, or a relay without post-quantum support).
    pub fn pq_kem_public(&self) -> Option<&[u8]> {
        match self.extension(EXT_PQ_KEM) {
            Some(raw) if raw.len() == PQ_KEM_LEN => Some(raw),
            _ => None,
        }
    }

    /// Decoded `EXT_REACHABILITY` ([`crate::nat::Reachability`]), or `None`
    /// for a directly reachable relay (or an unparseable value).
    pub fn reachability(&self) -> Option<crate::nat::Reachability> {
        let raw = self.extension(EXT_REACHABILITY)?;
        crate::nat::decode_reachability(raw).ok()
    }

    /// Whether this relay is only reachable via hole-punching. Such relays
    /// are never picked as guards.
    pub fn behind_nat(&self) -> bool {
        self.extension(EXT_REACHABILITY).is_some()
    }

    /// `Some(true)`/`Some(false)` from the port summary, `None` if unknown.
    pub fn allows_exit_port(&self, port: u16) -> Option<bool> {
        let ranges = self.exit_port_ranges()?;
        Some(ranges.iter().any(|&(lo, hi)| lo <= port && port <= hi))
    }

    fn signing_payload_v1(&self) -> Vec<u8> {
        let host = self.host.as_bytes();
        let mut roles = self.roles.clone();
        roles.sort();
        let roles_joined = roles.join(",");
        let mut out = Vec::new();
        out.extend_from_slice(b"allium-descriptor-v1");
        out.extend_from_slice(&(host.len() as u16).to_be_bytes());
        out.extend_from_slice(host);
        out.extend_from_slice(&self.port.to_be_bytes());
        out.extend_from_slice(&self.not_before.to_be_bytes());
        out.extend_from_slice(&self.not_after.to_be_bytes());
        out.extend_from_slice(&self.identity_public);
        out.extend_from_slice(&self.static_public);
        out.extend_from_slice(roles_joined.as_bytes());
        out
    }

    fn signing_payload_v2(&self) -> Vec<u8> {
        let host = self.host.as_bytes();
        let mut roles = self.roles.clone();
        roles.sort();
        let roles_joined = roles.join(",");
        let roles_bytes = roles_joined.as_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(b"allium-descriptor-v2");
        out.extend_from_slice(&self.identity_public);
        out.extend_from_slice(&self.static_public);
        out.extend_from_slice(&(host.len() as u16).to_be_bytes());
        out.extend_from_slice(host);
        out.extend_from_slice(&self.port.to_be_bytes());
        out.extend_from_slice(&(roles_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(roles_bytes);
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

    /// The exact bytes the signature covers (everything but the signature).
    pub fn signing_payload(&self) -> Vec<u8> {
        if self.version == DESCRIPTOR_VERSION_2 {
            self.signing_payload_v2()
        } else {
            self.signing_payload_v1()
        }
    }

    /// Validate version and extension block (not the signature).
    pub fn check_structure(&self) -> Result<(), DirectoryError> {
        if self.version != DESCRIPTOR_VERSION_1 && self.version != DESCRIPTOR_VERSION_2 {
            return Err(DirectoryError::DescriptorMalformed(format!(
                "unknown descriptor version {}",
                self.version
            )));
        }
        if self.version == DESCRIPTOR_VERSION_1 {
            if !self.extensions.is_empty() {
                return Err(DirectoryError::DescriptorMalformed(
                    "a v1 descriptor cannot carry extensions".to_string(),
                ));
            }
            return Ok(());
        }
        if self.extensions.len() > MAX_EXTENSIONS {
            return Err(DirectoryError::DescriptorMalformed(format!(
                "more than {MAX_EXTENSIONS} extensions"
            )));
        }
        let mut previous: i32 = -1;
        for (ext_type, value) in &self.extensions {
            let ext_type_i = *ext_type as i32;
            if ext_type_i <= previous {
                return Err(DirectoryError::DescriptorMalformed(
                    "extension types must be strictly increasing".to_string(),
                ));
            }
            previous = ext_type_i;
            if value.len() > MAX_EXTENSION_LEN {
                return Err(DirectoryError::DescriptorMalformed(format!(
                    "extension {ext_type} is too long"
                )));
            }
            if *ext_type == EXT_BANDWIDTH && value.len() != 8 {
                return Err(DirectoryError::DescriptorMalformed(
                    "bandwidth extension must be 8 bytes".to_string(),
                ));
            }
            if *ext_type == EXT_EXIT_PORTS {
                parse_exit_ports(value)?;
            }
            if *ext_type == EXT_PQ_KEM && value.len() != PQ_KEM_LEN {
                return Err(DirectoryError::DescriptorMalformed(format!(
                    "ML-KEM key must be {PQ_KEM_LEN} bytes"
                )));
            }
            if *ext_type == EXT_REACHABILITY {
                if let Err(exc) = crate::nat::decode_reachability(value) {
                    return Err(DirectoryError::DescriptorMalformed(format!(
                        "bad reachability extension: {exc}"
                    )));
                }
            }
            if *ext_type == EXT_FAMILY {
                if value.len() % 32 != 0 || value.len() / 32 > MAX_FAMILY {
                    return Err(DirectoryError::DescriptorMalformed(format!(
                        "family extension must be up to {MAX_FAMILY} 32-byte identities"
                    )));
                }
                let members: Vec<&[u8]> = value.chunks_exact(32).collect();
                let mut sorted_unique: Vec<&[u8]> = members.clone();
                sorted_unique.sort();
                sorted_unique.dedup();
                if members != sorted_unique {
                    return Err(DirectoryError::DescriptorMalformed(
                        "family members must be sorted and unique".to_string(),
                    ));
                }
                if members.contains(&self.identity_public.as_slice()) {
                    return Err(DirectoryError::DescriptorMalformed(
                        "a relay cannot list itself as family".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn is_valid_at(&self, now: f64) -> bool {
        self.not_before <= now && now <= self.not_after
    }

    /// Check the self-signature.
    ///
    /// # Errors
    /// [`DirectoryError::SignatureInvalid`] if the signature does not
    /// verify against `identity_public`, the keys are the wrong size, or
    /// [`DirectoryError::DescriptorMalformed`] from [`Self::check_structure`].
    pub fn verify(&self) -> Result<(), DirectoryError> {
        if self.identity_public.len() != 32 {
            return Err(DirectoryError::SignatureInvalid(format!(
                "identity key must be 32 bytes, got {}",
                self.identity_public.len()
            )));
        }
        if self.static_public.len() != 32 {
            return Err(DirectoryError::SignatureInvalid(format!(
                "static key must be 32 bytes, got {}",
                self.static_public.len()
            )));
        }
        self.check_structure()?;
        let identity: [u8; 32] = self.identity_public.clone().try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&identity)
            .map_err(|e| DirectoryError::SignatureInvalid(format!("malformed identity key: {e}")))?;
        if self.signature.len() != 64 {
            return Err(DirectoryError::SignatureInvalid(
                "descriptor signature did not verify".to_string(),
            ));
        }
        let sig_bytes: [u8; 64] = self.signature.clone().try_into().unwrap();
        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(&self.signing_payload(), &signature)
            .map_err(|_| DirectoryError::SignatureInvalid("descriptor signature did not verify".to_string()))
    }

    /// Mint and sign a descriptor from a relay's Ed25519 private key.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        identity_private: &[u8; 32],
        static_public: Vec<u8>,
        host: impl Into<String>,
        port: u16,
        roles: Vec<String>,
        lifetime: f64,
        now: Option<f64>,
        opts: CreateOptions,
    ) -> Result<RelayDescriptor, DirectoryError> {
        let now = now.unwrap_or_else(now_unix);
        let key = SigningKey::from_bytes(identity_private);
        let identity_public = key.verifying_key().to_bytes().to_vec();

        let mut extensions: Vec<(u8, Vec<u8>)> = Vec::new();
        if let Some(bw) = opts.bandwidth {
            extensions.push((EXT_BANDWIDTH, encode_ext_bandwidth(bw)));
        }
        if let Some(ranges) = &opts.exit_port_ranges {
            extensions.push((EXT_EXIT_PORTS, encode_ext_exit_ports(&ports_to_ranges(
                &ranges.iter().flat_map(|&(lo, hi)| lo..=hi).collect::<Vec<u16>>(),
            ))));
        }
        if let Some(family) = &opts.family {
            let members: Vec<Vec<u8>> =
                family.iter().filter(|m| m.as_slice() != identity_public.as_slice()).cloned().collect();
            if !members.is_empty() {
                extensions.push((EXT_FAMILY, encode_ext_family(&members)));
            }
        }
        if let Some(pq) = &opts.pq_kem_public {
            extensions.push((EXT_PQ_KEM, pq.clone()));
        }
        for (t, v) in &opts.extra_extensions {
            extensions.push((*t, v.clone()));
        }
        extensions.sort_by_key(|(t, _)| *t);

        let version = opts.version.unwrap_or(CURRENT_DESCRIPTOR_VERSION);
        if version == DESCRIPTOR_VERSION_1 && !extensions.is_empty() {
            return Err(DirectoryError::DescriptorMalformed(
                "a v1 descriptor cannot carry extensions".to_string(),
            ));
        }

        let mut unsigned = RelayDescriptor {
            identity_public,
            static_public,
            host: host.into(),
            port,
            roles,
            not_before: now,
            not_after: now + lifetime,
            signature: Vec::new(),
            version,
            extensions,
        };
        unsigned.check_structure()?;
        let signature = key.sign(&unsigned.signing_payload());
        unsigned.signature = signature.to_bytes().to_vec();
        Ok(unsigned)
    }

    pub fn endpoint(&self) -> (String, u16) {
        (self.host.clone(), self.port)
    }
}

/// Optional [`RelayDescriptor::create`] arguments (Rust has no keyword
/// arguments, so this groups Python's `bandwidth`/`exit_ports`/`family`/
/// `pq_kem_public`/`extra_extensions`/`version` into one struct).
#[derive(Debug, Clone, Default)]
pub struct CreateOptions {
    pub bandwidth: Option<u64>,
    /// Already-collapsed `(lo, hi)` ranges (call [`ports_to_ranges`] first
    /// if you only have individual port numbers).
    pub exit_port_ranges: Option<Vec<(u16, u16)>>,
    pub family: Option<Vec<Vec<u8>>>,
    pub pq_kem_public: Option<Vec<u8>>,
    pub extra_extensions: Vec<(u8, Vec<u8>)>,
    pub version: Option<u8>,
}

/// Return a hashable "address block" grouping key for `host`, or `None` if
/// it can't be classified (a hostname stays unrestricted).
fn subnet_key(host: &str) -> Option<IpAddr> {
    let address: IpAddr = host.parse().ok()?;
    match address {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4) & (u32::MAX << (32 - SUBNET_PREFIX_V4));
            Some(IpAddr::V4(Ipv4Addr::from(bits)))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6) & (u128::MAX << (128 - SUBNET_PREFIX_V6));
            Some(IpAddr::V6(Ipv6Addr::from(bits)))
        }
    }
}

/// Constructor options for [`Directory`].
pub struct DirectoryOptions {
    /// Trusted Ed25519 identity keys. When non-empty, a descriptor is
    /// accepted only when its identity is one of these. Empty (the
    /// default) accepts any correctly self-signed descriptor.
    pub authorities: Vec<Vec<u8>>,
    /// Cap on how many never-seen-before identities [`Directory::publish`]
    /// will accept from the same address block within
    /// `subnet_window_seconds`. `None` disables the check.
    pub max_new_identities_per_subnet: Option<u32>,
    pub subnet_window_seconds: f64,
    /// Largest `not_after - not_before` span [`Directory::publish`] will
    /// accept. `None` disables the check.
    pub max_descriptor_lifetime: Option<f64>,
    /// Injectable time source, for deterministic tests.
    pub clock: Option<Arc<dyn Fn() -> f64 + Send + Sync>>,
    /// Security audit fix (2026-09-26, finding #5 -- no vetting before
    /// self-declaring "guard"): when set, [`Directory::select_route`]'s
    /// *unpinned* guard pick is restricted to guards this directory has
    /// observed (via `first_seen`, see [`Directory::set_first_seen`]) for
    /// at least this many seconds. `None` (the default) disables the
    /// check, preserving every existing caller's behavior.
    pub min_guard_age_seconds: Option<f64>,
}

impl Default for DirectoryOptions {
    fn default() -> Self {
        DirectoryOptions {
            authorities: Vec::new(),
            max_new_identities_per_subnet: Some(32),
            subnet_window_seconds: 3600.0,
            max_descriptor_lifetime: Some(MAX_DESCRIPTOR_LIFETIME),
            clock: None,
            min_guard_age_seconds: None,
        }
    }
}

/// A verifying store of relay descriptors.
pub struct Directory {
    authorities: HashSet<Vec<u8>>,
    clock: Arc<dyn Fn() -> f64 + Send + Sync>,
    by_identity: HashMap<Vec<u8>, RelayDescriptor>,
    max_new_identities_per_subnet: Option<u32>,
    subnet_window_seconds: f64,
    max_descriptor_lifetime: Option<f64>,
    subnet_new_identity_log: HashMap<IpAddr, Vec<f64>>,
    measured_bandwidth: HashMap<Vec<u8>, u64>,
    /// A relay's quorum-verified subnet (aggregated across a quorum of
    /// authorities' own votes, via `consensus::compute_consensus`),
    /// keyed by identity. Used by [`Self::subnet_of`] in preference to a
    /// relay's self-declared `host` for anti-collusion route diversity --
    /// see [`Self::publish_verified`].
    verified_subnet: HashMap<Vec<u8>, IpAddr>,
    /// Security audit fix (2026-09-26, finding #5 -- no vetting before
    /// self-declaring "guard"): wall-clock time this identity was first
    /// seen (self-populated on every publish, or seeded externally via
    /// [`Self::set_first_seen`] from a caller that persists it across
    /// `Directory` rebuilds -- this object's own lifetime is normally one
    /// fetch cycle). Never cleared, same non-cleanup precedent as
    /// `measured_bandwidth` above.
    first_seen: HashMap<Vec<u8>, f64>,
    min_guard_age_seconds: Option<f64>,
}

impl Directory {
    pub fn new(options: DirectoryOptions) -> Result<Self, DirectoryError> {
        if let Some(n) = options.max_new_identities_per_subnet {
            if n < 1 {
                return Err(DirectoryError::Other(format!(
                    "max_new_identities_per_subnet must be at least 1 (or None to disable), got {n}"
                )));
            }
        }
        if let Some(l) = options.max_descriptor_lifetime {
            if l <= 0.0 {
                return Err(DirectoryError::Other(format!(
                    "max_descriptor_lifetime must be positive (or None to disable), got {l}"
                )));
            }
        }
        Ok(Directory {
            authorities: options.authorities.into_iter().collect(),
            clock: options.clock.unwrap_or_else(|| Arc::new(now_unix)),
            by_identity: HashMap::new(),
            max_new_identities_per_subnet: options.max_new_identities_per_subnet,
            subnet_window_seconds: options.subnet_window_seconds,
            max_descriptor_lifetime: options.max_descriptor_lifetime,
            subnet_new_identity_log: HashMap::new(),
            measured_bandwidth: HashMap::new(),
            verified_subnet: HashMap::new(),
            first_seen: HashMap::new(),
            min_guard_age_seconds: options.min_guard_age_seconds,
        })
    }

    fn now(&self) -> f64 {
        (self.clock)()
    }

    /// Install authority-measured bandwidths (`identity -> bytes/second`).
    /// Overrides a relay's self-reported figure and is not subject to
    /// [`MAX_SELF_REPORTED_BANDWIDTH`].
    pub fn set_measured_bandwidth(&mut self, measurements: HashMap<Vec<u8>, u64>) {
        self.measured_bandwidth = measurements;
    }

    /// Seed `first_seen` from a caller-maintained, externally persisted
    /// registry (this `Directory` object's own lifetime is normally one
    /// fetch cycle -- see the field's doc). Entries for identities this
    /// directory has not published yet are harmless no-ops until it does.
    pub fn set_first_seen(&mut self, entries: HashMap<Vec<u8>, f64>) {
        self.first_seen = entries;
    }

    /// A snapshot of `first_seen`, for a caller to merge into its own
    /// persistent registry so this history survives past this `Directory`
    /// object's lifetime (see [`Self::set_first_seen`]).
    pub fn first_seen_snapshot(&self) -> HashMap<Vec<u8>, f64> {
        self.first_seen.clone()
    }

    /// Whether `d` has been observed long enough to be picked as an
    /// *unpinned* guard -- see `min_guard_age_seconds`'s doc. Always `true`
    /// when the check is disabled.
    fn guard_eligible(&self, d: &RelayDescriptor) -> bool {
        match self.min_guard_age_seconds {
            None => true,
            Some(min_age) => self.first_seen.get(&d.identity_public).is_some_and(|&first| self.now() - first >= min_age),
        }
    }

    /// The bandwidth weight [`Self::select_route`] gives `descriptor`.
    pub fn selection_weight(&self, descriptor: &RelayDescriptor) -> u64 {
        if let Some(&measured) = self.measured_bandwidth.get(&descriptor.identity_public) {
            return measured.max(1);
        }
        let advertised = descriptor.bandwidth();
        if advertised == 0 {
            return UNMEASURED_BANDWIDTH_WEIGHT;
        }
        advertised.clamp(1, MAX_SELF_REPORTED_BANDWIDTH)
    }

    /// Identities in `descriptor`'s *effective* family: itself, plus every
    /// live relay it declares that declares it back.
    pub fn family_of(&self, descriptor: &RelayDescriptor) -> HashSet<Vec<u8>> {
        let mut members = HashSet::new();
        members.insert(descriptor.identity_public.clone());
        for identity in descriptor.family() {
            if let Some(other) = self.get(&identity) {
                if other.family().contains(&descriptor.identity_public) {
                    members.insert(identity);
                }
            }
        }
        members
    }

    pub fn authorities(&self) -> &HashSet<Vec<u8>> {
        &self.authorities
    }

    fn check_subnet_rate(&mut self, descriptor: &RelayDescriptor, now: f64) -> Result<(), DirectoryError> {
        let limit = match self.max_new_identities_per_subnet {
            Some(l) => l as usize,
            None => return Ok(()),
        };
        if self.by_identity.contains_key(&descriptor.identity_public) {
            return Ok(()); // a rotation, not a new identity
        }
        let subnet = match subnet_key(&descriptor.host) {
            Some(s) => s,
            None => return Ok(()),
        };
        let window_start = now - self.subnet_window_seconds;
        let log = self.subnet_new_identity_log.entry(subnet).or_default();
        log.retain(|&t| t > window_start);
        if log.len() >= limit {
            return Err(DirectoryError::SybilRateLimited(format!(
                "{subnet} has already published {} new identities in the last {}s (limit {limit}); \
                 this is not a rotation of a known identity",
                log.len(),
                self.subnet_window_seconds
            )));
        }
        log.push(now);
        Ok(())
    }

    /// Shared prefix of [`Self::publish`]/[`Self::publish_verified`]:
    /// signature, trusted-authority membership (if configured), and
    /// lifetime/expiry checks. Returns the current clock reading, which
    /// both callers need next.
    fn validate_descriptor(&self, descriptor: &RelayDescriptor) -> Result<f64, DirectoryError> {
        descriptor.verify()?;
        if !self.authorities.is_empty() && !self.authorities.contains(&descriptor.identity_public) {
            return Err(DirectoryError::SignatureInvalid(
                "descriptor identity is not a trusted directory authority".to_string(),
            ));
        }
        if let Some(max_lifetime) = self.max_descriptor_lifetime {
            let lifetime = descriptor.not_after - descriptor.not_before;
            if lifetime > max_lifetime {
                return Err(DirectoryError::DescriptorLifetimeTooLong(format!(
                    "descriptor for {}:{} claims a {lifetime}s validity window, longer than the {max_lifetime}s \
                     this directory accepts",
                    descriptor.host, descriptor.port
                )));
            }
        }
        let now = self.now();
        if !descriptor.is_valid_at(now) {
            return Err(DirectoryError::DescriptorExpired(format!(
                "descriptor for {}:{} is outside its validity window",
                descriptor.host, descriptor.port
            )));
        }
        Ok(now)
    }

    /// Verify and store `descriptor`. Returns `true` if accepted, `false`
    /// if it was stale (an older descriptor than one already held for that
    /// identity).
    pub fn publish(&mut self, descriptor: RelayDescriptor) -> Result<bool, DirectoryError> {
        let now = self.validate_descriptor(&descriptor)?;
        self.check_subnet_rate(&descriptor, now)?;
        if let Some(existing) = self.by_identity.get(&descriptor.identity_public) {
            if existing.not_before > descriptor.not_before {
                return Ok(false); // an older record must not clobber a newer one
            }
        }
        self.first_seen.entry(descriptor.identity_public.clone()).or_insert(now);
        self.by_identity.insert(descriptor.identity_public.clone(), descriptor);
        Ok(true)
    }

    /// Verify and store `descriptor` using a quorum-verified subnet
    /// (aggregated across a quorum of authorities' own votes, via
    /// `consensus::compute_consensus`), rather than any locally-observed
    /// source address -- a client has no live connection to each relay to
    /// derive one from directly, the way an authority does at PUBLISH
    /// time; only the quorum-of-authorities' own independent
    /// observations, each carried in their signed vote. A single
    /// authority's claim alone is never trusted, matching the same
    /// Byzantine-tolerance already applied to descriptor digests and
    /// measured bandwidth.
    ///
    /// Unlike [`Self::publish`], this never applies
    /// [`Self::check_subnet_rate`]: that mechanism bounds how fast a
    /// directory accepts brand-new identities live over the wire, which
    /// has no meaning when merely reconstructing an already-quorum-agreed
    /// view of the network from a FETCH reply.
    pub fn publish_verified(&mut self, descriptor: RelayDescriptor, verified_subnet: Option<IpAddr>) -> Result<bool, DirectoryError> {
        let now = self.validate_descriptor(&descriptor)?;
        if let Some(existing) = self.by_identity.get(&descriptor.identity_public) {
            if existing.not_before > descriptor.not_before {
                return Ok(false);
            }
        }
        if let Some(subnet) = verified_subnet {
            self.verified_subnet.insert(descriptor.identity_public.clone(), subnet);
        }
        self.first_seen.entry(descriptor.identity_public.clone()).or_insert(now);
        self.by_identity.insert(descriptor.identity_public.clone(), descriptor);
        Ok(true)
    }

    /// `descriptor`'s address-block grouping key for anti-collusion route
    /// diversity: this directory's own quorum-verified subnet for it if
    /// one is on file (see [`Self::publish_verified`]), falling back to
    /// its self-declared `host` only when there is none -- e.g. a
    /// single-authority legacy-FETCH deployment with no quorum to derive
    /// one from, or a descriptor installed via the plain [`Self::publish`].
    fn subnet_of(&self, descriptor: &RelayDescriptor) -> Option<IpAddr> {
        self.verified_subnet.get(&descriptor.identity_public).copied().or_else(|| subnet_key(&descriptor.host))
    }

    /// Drop a relay by identity key, returning whether it was present.
    pub fn remove(&mut self, identity_public: &[u8]) -> bool {
        self.by_identity.remove(identity_public).is_some()
    }

    /// Drop expired descriptors, returning how many were removed.
    pub fn prune(&mut self) -> usize {
        let now = self.now();
        let stale: Vec<Vec<u8>> = self
            .by_identity
            .iter()
            .filter(|(_, d)| !d.is_valid_at(now))
            .map(|(k, _)| k.clone())
            .collect();
        for key in &stale {
            self.by_identity.remove(key);
        }
        stale.len()
    }

    /// Return a live descriptor for an identity, or `None`.
    pub fn get(&self, identity_public: &[u8]) -> Option<&RelayDescriptor> {
        let d = self.by_identity.get(identity_public)?;
        if d.is_valid_at(self.now()) {
            Some(d)
        } else {
            None
        }
    }

    /// Live descriptors whose roles include `role`, sorted by endpoint.
    pub fn by_role(&self, role: &str) -> Vec<RelayDescriptor> {
        let now = self.now();
        let mut found: Vec<RelayDescriptor> = self
            .by_identity
            .values()
            .filter(|d| d.roles.iter().any(|r| r == role) && d.is_valid_at(now))
            .cloned()
            .collect();
        found.sort_by_key(|a| a.endpoint());
        found
    }

    /// Every live descriptor, sorted by endpoint.
    pub fn all(&self) -> Vec<RelayDescriptor> {
        let now = self.now();
        let mut found: Vec<RelayDescriptor> =
            self.by_identity.values().filter(|d| d.is_valid_at(now)).cloned().collect();
        found.sort_by_key(|a| a.endpoint());
        found
    }

    pub fn len(&self) -> usize {
        self.all().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Pick a guard/middle/exit route from live descriptors. See
    /// [`SelectRouteOptions`] for the knobs Python passes as keyword
    /// arguments.
    pub fn select_route(&self, opts: SelectRouteOptions) -> Result<Vec<RelayDescriptor>, DirectoryError> {
        if opts.hops < 1 {
            return Err(DirectoryError::Other(format!("hops must be at least 1, got {}", opts.hops)));
        }
        let mut rng = RouteRng::new(opts.seed);
        // A relay behind NAT is only reachable after hole-punching brokered
        // for a *relay* peer, so it can never be a hop a client contacts
        // directly.
        let guards: Vec<RelayDescriptor> = self.by_role(ROLE_GUARD).into_iter().filter(|d| !d.behind_nat()).collect();
        let exits = self.by_role(ROLE_EXIT);
        let middles = self.by_role(ROLE_MIDDLE);

        let mut chosen: Vec<RelayDescriptor> = Vec::new();
        let mut used: HashSet<Vec<u8>> = opts.exclude_identities.iter().cloned().collect();
        let mut used_subnets: HashSet<IpAddr> = HashSet::new();

        let pick_weighted = |candidates: &[RelayDescriptor], rng: &mut RouteRng| -> RelayDescriptor {
            if !opts.weight_by_bandwidth {
                return rng.choice(candidates).clone();
            }
            let weights: Vec<u64> = candidates.iter().map(|d| self.selection_weight(d)).collect();
            if weights.iter().all(|&w| w == weights[0]) {
                return rng.choice(candidates).clone();
            }
            let total: u64 = weights.iter().sum();
            let point = rng.random_f64() * total as f64;
            let mut running: u64 = 0;
            for (descriptor, weight) in candidates.iter().zip(weights.iter()) {
                running += weight;
                if point < running as f64 {
                    return descriptor.clone();
                }
            }
            candidates.last().unwrap().clone()
        };

        let mark_used = |used: &mut HashSet<Vec<u8>>, pick: &RelayDescriptor| {
            used.insert(pick.identity_public.clone());
            used.extend(self.family_of(pick));
        };

        let take = |pool: &[RelayDescriptor],
                        label: &str,
                        used: &mut HashSet<Vec<u8>>,
                        used_subnets: &mut HashSet<IpAddr>,
                        chosen: &mut Vec<RelayDescriptor>,
                        rng: &mut RouteRng|
         -> Result<(), DirectoryError> {
            let mut candidates: Vec<RelayDescriptor> =
                pool.iter().filter(|d| !used.contains(&d.identity_public)).cloned().collect();
            if opts.require_pq {
                candidates.retain(|d| d.pq_kem_public().is_some());
            }
            if label == "exit" {
                if let Some(exit_port) = opts.exit_port {
                    let accepting: Vec<RelayDescriptor> =
                        candidates.iter().filter(|d| d.allows_exit_port(exit_port) == Some(true)).cloned().collect();
                    let unknown: Vec<RelayDescriptor> =
                        candidates.iter().filter(|d| d.allows_exit_port(exit_port).is_none()).cloned().collect();
                    candidates = if !accepting.is_empty() { accepting } else { unknown };
                    if candidates.is_empty() {
                        return Err(DirectoryError::Other(format!("no live exit accepts port {exit_port}")));
                    }
                }
            }
            if candidates.is_empty() {
                return Err(DirectoryError::Other(format!("no live relay available for the {label} position")));
            }
            if opts.enforce_subnet_diversity {
                let diverse: Vec<RelayDescriptor> = candidates
                    .iter()
                    .filter(|d| match self.subnet_of(d) {
                        Some(s) => !used_subnets.contains(&s),
                        None => true, // unclassifiable host: never blocks selection
                    })
                    .cloned()
                    .collect();
                // Fall back to the full pool rather than fail a circuit
                // build when diversity can't be had here.
                if !diverse.is_empty() {
                    candidates = diverse;
                }
            }
            let pick = pick_weighted(&candidates, rng);
            mark_used(used, &pick);
            if let Some(subnet) = self.subnet_of(&pick) {
                used_subnets.insert(subnet);
            }
            chosen.push(pick);
            Ok(())
        };

        let mut pinned_guard: Option<RelayDescriptor> = None;
        if let Some(preferred) = &opts.preferred_guard {
            pinned_guard = guards.iter().find(|d| &d.identity_public == preferred).cloned();
            if pinned_guard.is_none() && opts.require_preferred_guard {
                return Err(DirectoryError::PreferredGuardUnavailable(format!(
                    "preferred guard {}... is not among the currently live guards",
                    hex_prefix(preferred, 8)
                )));
            }
        }
        if let Some(guard) = &pinned_guard {
            if opts.require_pq && guard.pq_kem_public().is_none() {
                if opts.require_preferred_guard {
                    return Err(DirectoryError::PreferredGuardUnavailable(
                        "preferred guard does not advertise a post-quantum key".to_string(),
                    ));
                }
                pinned_guard = None;
            }
        }
        if let Some(guard) = pinned_guard {
            mark_used(&mut used, &guard);
            if let Some(subnet) = self.subnet_of(&guard) {
                used_subnets.insert(subnet);
            }
            chosen.push(guard);
        } else {
            // Security audit fix (2026-09-26, finding #5): a *pinned*
            // preferred guard (handled above) already carries its own
            // trust basis -- typically a previous session's own choice,
            // persisted via `--state-file` -- so it is exempt. An unpinned
            // pick, picking a guard for the first time with nothing but
            // its own self-declared "guard" role to go on, is exactly the
            // case this vets: restrict the pool to guards this directory
            // has actually observed for `min_guard_age_seconds`, when set.
            let vetted_guards: Vec<RelayDescriptor> = guards.iter().filter(|d| self.guard_eligible(d)).cloned().collect();
            if vetted_guards.is_empty() && !guards.is_empty() && self.min_guard_age_seconds.is_some() {
                return Err(DirectoryError::Other(format!(
                    "{} self-declared guard(s) are live, but none has been observed for the required {:.0}s yet -- a brand-new identity cannot claim the guard role on day one; try again once this directory has accumulated guard history",
                    guards.len(),
                    self.min_guard_age_seconds.unwrap(),
                )));
            }
            take(&vetted_guards, "guard", &mut used, &mut used_subnets, &mut chosen, &mut rng)?;
        }
        for index in 0..opts.hops.saturating_sub(2) {
            let label = format!("middle {}", index + 1);
            take(&middles, &label, &mut used, &mut used_subnets, &mut chosen, &mut rng)?;
        }
        if opts.hops >= 2 {
            take(&exits, "exit", &mut used, &mut used_subnets, &mut chosen, &mut rng)?;
        }
        Ok(chosen)
    }
}

fn hex_prefix(bytes: &[u8], chars: usize) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    hex.chars().take(chars).collect()
}

/// [`Directory::select_route`]'s options (Rust has no keyword arguments).
#[derive(Clone)]
pub struct SelectRouteOptions {
    pub hops: u32,
    /// Deterministic route selection for tests. Leave `None` in
    /// production -- it switches from a CSPRNG to a reproducible xorshift
    /// PRNG (see [`RouteRng`]), which is predictable.
    pub seed: Option<u64>,
    pub preferred_guard: Option<Vec<u8>>,
    pub enforce_subnet_diversity: bool,
    pub require_preferred_guard: bool,
    pub exclude_identities: Vec<Vec<u8>>,
    pub exit_port: Option<u16>,
    pub weight_by_bandwidth: bool,
    pub require_pq: bool,
}

impl Default for SelectRouteOptions {
    fn default() -> Self {
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

/// Path-selection RNG: a CSPRNG in production (`seed: None`), or a
/// reproducible xorshift64* generator when `seed` is given for a test.
/// Unlike Python's `random.Random`, this makes no promise of bit-for-bit
/// parity with CPython's Mersenne Twister -- the seeded mode exists only
/// so a Rust test can assert on a specific, reproducible route.
enum RouteRng {
    Secure,
    Seeded(u64),
}

impl RouteRng {
    fn new(seed: Option<u64>) -> Self {
        match seed {
            Some(s) => RouteRng::Seeded(s ^ 0x9E3779B97F4A7C15 | 1),
            None => RouteRng::Secure,
        }
    }

    fn next_u64(&mut self) -> u64 {
        match self {
            RouteRng::Secure => {
                let bytes = crate::osrand::bytes(8);
                u64::from_le_bytes(bytes.try_into().unwrap())
            }
            RouteRng::Seeded(state) => {
                *state ^= *state << 13;
                *state ^= *state >> 7;
                *state ^= *state << 17;
                *state
            }
        }
    }

    fn random_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }

    fn choice<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        let idx = (self.next_u64() % items.len() as u64) as usize;
        &items[idx]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn identity_key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn make_descriptor(seed: u8, host: &str, roles: &[&str]) -> RelayDescriptor {
        RelayDescriptor::create(
            &identity_key(seed),
            vec![seed; 32],
            host,
            9000,
            roles.iter().map(|s| s.to_string()).collect(),
            DEFAULT_DESCRIPTOR_LIFETIME,
            None, // valid from "now" under the default real-time clock
            CreateOptions::default(),
        )
        .unwrap()
    }

    fn build_reachability(identity: &[u8], x25519_public: &[u8], host: &str, port: u16) -> Vec<u8> {
        let mut out = vec![crate::nat::MODE_NAT];
        out.extend_from_slice(identity);
        out.extend_from_slice(x25519_public);
        let host_bytes = host.as_bytes();
        out.push(host_bytes.len() as u8);
        out.extend_from_slice(host_bytes);
        out.extend_from_slice(&port.to_be_bytes());
        out
    }

    #[test]
    fn reachability_round_trips_through_extension_and_behind_nat_is_true() {
        let introducer_identity = vec![9u8; 32];
        let introducer_x25519_public = vec![8u8; 32];
        let raw = build_reachability(&introducer_identity, &introducer_x25519_public, "198.51.100.9", 9050);
        let d = RelayDescriptor::create(
            &identity_key(6),
            vec![6; 32],
            "10.0.0.6",
            9000,
            vec![ROLE_MIDDLE.to_string()],
            DEFAULT_DESCRIPTOR_LIFETIME,
            Some(1_700_000_000.0),
            CreateOptions {
                extra_extensions: vec![(EXT_REACHABILITY, raw)],
                ..Default::default()
            },
        )
        .unwrap();
        d.check_structure().unwrap();
        assert!(d.behind_nat());
        let reach = d.reachability().unwrap();
        assert_eq!(reach.mode, crate::nat::MODE_NAT);
        assert_eq!(reach.introducer_identity, introducer_identity);
        assert_eq!(reach.introducer_x25519_public, introducer_x25519_public);
        assert_eq!(reach.introducer_host, "198.51.100.9");
        assert_eq!(reach.introducer_port, 9050);
    }

    #[test]
    fn descriptor_without_reachability_is_not_behind_nat() {
        let d = make_descriptor(7, "10.0.0.7", &[ROLE_GUARD]);
        assert!(!d.behind_nat());
        assert!(d.reachability().is_none());
    }

    #[test]
    fn malformed_reachability_extension_fails_check_structure() {
        // Wrong mode byte (0 instead of MODE_NAT) makes this unparseable by
        // `nat::decode_reachability`. `create` runs `check_structure`
        // internally, so the malformed extension is rejected up front.
        let result = RelayDescriptor::create(
            &identity_key(8),
            vec![8; 32],
            "10.0.0.8",
            9000,
            vec![ROLE_MIDDLE.to_string()],
            DEFAULT_DESCRIPTOR_LIFETIME,
            Some(1_700_000_000.0),
            CreateOptions {
                extra_extensions: vec![(EXT_REACHABILITY, vec![0u8; 40])],
                ..Default::default()
            },
        );
        assert!(matches!(result, Err(DirectoryError::DescriptorMalformed(_))));

        // The `reachability()` accessor swallows a bad extension into
        // `None` rather than panicking, exercised directly on a
        // hand-built (not `create`d) descriptor that skips validation.
        let d = RelayDescriptor::new(
            vec![8; 32],
            vec![8; 32],
            "10.0.0.8",
            9000,
            vec![ROLE_MIDDLE.to_string()],
            1_700_000_000.0,
            1_700_100_000.0,
        );
        let mut d = d;
        d.version = DESCRIPTOR_VERSION_2;
        d.extensions = vec![(EXT_REACHABILITY, vec![0u8; 40])];
        assert!(matches!(d.check_structure(), Err(DirectoryError::DescriptorMalformed(_))));
        assert!(d.reachability().is_none());
    }

    #[test]
    fn ports_to_ranges_collapses_and_sorts() {
        assert_eq!(ports_to_ranges(&[80, 81, 82, 443, 0]), vec![(80, 82), (443, 443)]);
        assert_eq!(ports_to_ranges(&[]), Vec::<(u16, u16)>::new());
    }

    #[test]
    fn create_and_verify_round_trip_v1_and_v2() {
        let d2 = make_descriptor(1, "10.0.0.1", &[ROLE_MIDDLE]);
        assert_eq!(d2.version, DESCRIPTOR_VERSION_2);
        d2.verify().unwrap();

        let d1 = RelayDescriptor::create(
            &identity_key(2),
            vec![2; 32],
            "10.0.0.2",
            9001,
            vec![ROLE_GUARD.to_string()],
            DEFAULT_DESCRIPTOR_LIFETIME,
            Some(1_700_000_000.0),
            CreateOptions { version: Some(DESCRIPTOR_VERSION_1), ..Default::default() },
        )
        .unwrap();
        assert_eq!(d1.version, DESCRIPTOR_VERSION_1);
        d1.verify().unwrap();
    }

    #[test]
    fn tampered_descriptor_fails_verification() {
        let mut d = make_descriptor(3, "10.0.0.3", &[ROLE_EXIT]);
        d.port = 1;
        assert!(matches!(d.verify(), Err(DirectoryError::SignatureInvalid(_))));
    }

    #[test]
    fn v1_descriptor_with_extensions_is_malformed() {
        let mut d = RelayDescriptor::create(
            &identity_key(4),
            vec![4; 32],
            "10.0.0.4",
            9000,
            vec![ROLE_MIDDLE.to_string()],
            DEFAULT_DESCRIPTOR_LIFETIME,
            None,
            CreateOptions { bandwidth: Some(1000), ..Default::default() },
        )
        .unwrap();
        assert!(!d.extensions.is_empty());
        d.version = DESCRIPTOR_VERSION_1;
        assert!(matches!(d.check_structure(), Err(DirectoryError::DescriptorMalformed(_))));
    }

    #[test]
    fn bandwidth_and_exit_ports_extensions_round_trip() {
        let d = RelayDescriptor::create(
            &identity_key(5),
            vec![5; 32],
            "10.0.0.5",
            9000,
            vec![ROLE_EXIT.to_string()],
            DEFAULT_DESCRIPTOR_LIFETIME,
            Some(1_700_000_000.0),
            CreateOptions {
                bandwidth: Some(5_000_000),
                exit_port_ranges: Some(vec![(80, 80), (443, 443)]),
                ..Default::default()
            },
        )
        .unwrap();
        d.verify().unwrap();
        assert_eq!(d.bandwidth(), 5_000_000);
        assert_eq!(d.allows_exit_port(80), Some(true));
        assert_eq!(d.allows_exit_port(22), Some(false));
    }

    #[test]
    fn publish_accepts_and_rotates() {
        let mut dir = Directory::new(DirectoryOptions::default()).unwrap();
        let d = RelayDescriptor::create(
            &identity_key(6),
            vec![6; 32],
            "10.0.1.1",
            9000,
            vec![ROLE_MIDDLE.to_string()],
            DEFAULT_DESCRIPTOR_LIFETIME,
            Some(now_unix() - 100.0), // in the past, so a later `not_before` sorts after it
            CreateOptions::default(),
        )
        .unwrap();
        assert!(dir.publish(d.clone()).unwrap());
        assert!(dir.get(&d.identity_public).is_some());

        // A newer descriptor for the same identity replaces the old one.
        let newer = RelayDescriptor::create(
            &identity_key(6),
            vec![6; 32],
            "10.0.1.2",
            9002,
            vec![ROLE_MIDDLE.to_string()],
            DEFAULT_DESCRIPTOR_LIFETIME,
            None, // "now", strictly after `d`'s not_before
            CreateOptions::default(),
        )
        .unwrap();
        assert!(dir.publish(newer.clone()).unwrap());
        assert_eq!(dir.get(&d.identity_public).unwrap().host, "10.0.1.2");

        // An older one must not clobber the newer.
        assert!(!dir.publish(d).unwrap());
        assert_eq!(dir.get(&newer.identity_public).unwrap().host, "10.0.1.2");
    }

    #[test]
    fn publish_rejects_expired_and_untrusted() {
        let d = make_descriptor(7, "10.0.2.1", &[ROLE_EXIT]); // valid from "now" for DEFAULT_DESCRIPTOR_LIFETIME
        let far_future: Arc<dyn Fn() -> f64 + Send + Sync> =
            Arc::new(|| now_unix() + DEFAULT_DESCRIPTOR_LIFETIME + 10_000.0);
        let mut dir = Directory::new(DirectoryOptions { clock: Some(far_future), ..Default::default() }).unwrap();
        assert!(matches!(dir.publish(d), Err(DirectoryError::DescriptorExpired(_))));

        let mut authority_dir = Directory::new(DirectoryOptions {
            authorities: vec![vec![9u8; 32]],
            ..Default::default()
        })
        .unwrap();
        let untrusted = make_descriptor(8, "10.0.2.2", &[ROLE_EXIT]);
        assert!(matches!(authority_dir.publish(untrusted), Err(DirectoryError::SignatureInvalid(_))));
    }

    #[test]
    fn subnet_rate_limit_blocks_new_identities_but_not_rotation() {
        let mut dir = Directory::new(DirectoryOptions {
            max_new_identities_per_subnet: Some(1),
            ..Default::default()
        })
        .unwrap();
        let first = make_descriptor(10, "203.0.113.1", &[ROLE_MIDDLE]);
        assert!(dir.publish(first.clone()).unwrap());
        let second = make_descriptor(11, "203.0.113.2", &[ROLE_MIDDLE]);
        assert!(matches!(dir.publish(second), Err(DirectoryError::SybilRateLimited(_))));

        // Rotating the *same* identity is never rate-limited.
        let rotated = RelayDescriptor::create(
            &identity_key(10),
            vec![10; 32],
            "203.0.113.9",
            9000,
            vec![ROLE_MIDDLE.to_string()],
            DEFAULT_DESCRIPTOR_LIFETIME,
            None, // "now", at or after `first`'s not_before
            CreateOptions::default(),
        )
        .unwrap();
        assert!(dir.publish(rotated).unwrap());
        let _ = first;
    }

    #[test]
    fn select_route_picks_distinct_guard_middle_exit() {
        let mut dir = Directory::new(DirectoryOptions::default()).unwrap();
        for i in 0..3u8 {
            dir.publish(make_descriptor(20 + i, &format!("10.1.{i}.1"), &[ROLE_GUARD])).unwrap();
            dir.publish(make_descriptor(30 + i, &format!("10.2.{i}.1"), &[ROLE_MIDDLE])).unwrap();
            dir.publish(make_descriptor(40 + i, &format!("10.3.{i}.1"), &[ROLE_EXIT])).unwrap();
        }
        let route = dir
            .select_route(SelectRouteOptions { hops: 3, seed: Some(42), ..Default::default() })
            .unwrap();
        assert_eq!(route.len(), 3);
        assert!(route[0].roles.iter().any(|r| r == ROLE_GUARD));
        assert!(route[1].roles.iter().any(|r| r == ROLE_MIDDLE));
        assert!(route[2].roles.iter().any(|r| r == ROLE_EXIT));
        let identities: HashSet<&Vec<u8>> = route.iter().map(|d| &d.identity_public).collect();
        assert_eq!(identities.len(), 3);
    }

    /// Security fix: `select_route`'s subnet-diversity check must key off
    /// a quorum-verified subnet (via `publish_verified`, what
    /// `dirclient::fetch_relay_directory` actually calls with a
    /// quorum-of-authorities-agreed subnet from `consensus::
    /// compute_consensus`), not the relay's own self-declared `host` --
    /// otherwise two colluding relays publishing unrelated self-signed
    /// `host` fields, while actually on the same real subnet, sail
    /// straight through as "diverse".
    #[test]
    fn select_route_diversity_uses_quorum_verified_subnet_not_self_declared_host() {
        let mut dir = Directory::new(DirectoryOptions::default()).unwrap();

        let guard = make_descriptor(60, "9.9.9.9", &[ROLE_GUARD]);
        let guard_id = guard.identity_public.clone();
        dir.publish_verified(guard, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)))).unwrap();

        // Same quorum-verified subnet as the guard, despite an unrelated
        // self-declared host -- exactly the collusion this fix closes.
        let exit_same_subnet = make_descriptor(61, "1.1.1.1", &[ROLE_EXIT]);
        dir.publish_verified(exit_same_subnet, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)))).unwrap();

        // A genuinely different quorum-verified subnet, needed too since
        // `select_route` also needs a middle to complete a 2-hop route --
        // reuse the exit set for both by asking for 2 hops with only a
        // guard and two exits published.
        let exit_diff = make_descriptor(62, "2.2.2.2", &[ROLE_EXIT]);
        let exit_diff_id = exit_diff.identity_public.clone();
        dir.publish_verified(exit_diff, Some(IpAddr::V4(Ipv4Addr::new(20, 0, 0, 0)))).unwrap();

        let route = dir
            .select_route(SelectRouteOptions {
                hops: 2,
                preferred_guard: Some(guard_id.clone()),
                require_preferred_guard: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(route.len(), 2);
        assert_eq!(route[0].identity_public, guard_id);
        assert_eq!(route[1].identity_public, exit_diff_id, "the same-subnet colluding exit must be skipped in favor of the genuinely diverse one");
    }

    /// Without any quorum-verified subnet at all (e.g. plain `publish`,
    /// or `publish_verified` with `None`), diversity must fall back to
    /// the self-declared host exactly as before -- this fix must not make
    /// diversity checking *more* permissive when there's genuinely no
    /// verified data to use.
    #[test]
    fn select_route_falls_back_to_self_declared_host_without_a_verified_subnet() {
        let mut dir = Directory::new(DirectoryOptions::default()).unwrap();

        let guard = make_descriptor(63, "9.9.9.9", &[ROLE_GUARD]);
        let guard_id = guard.identity_public.clone();
        dir.publish(guard).unwrap();

        let exit_same_host_subnet = make_descriptor(64, "9.9.9.9", &[ROLE_EXIT]);
        dir.publish(exit_same_host_subnet).unwrap();

        let exit_diff = make_descriptor(65, "2.2.2.2", &[ROLE_EXIT]);
        let exit_diff_id = exit_diff.identity_public.clone();
        dir.publish(exit_diff).unwrap();

        let route = dir
            .select_route(SelectRouteOptions {
                hops: 2,
                preferred_guard: Some(guard_id.clone()),
                require_preferred_guard: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(route.len(), 2);
        assert_eq!(route[0].identity_public, guard_id);
        assert_eq!(route[1].identity_public, exit_diff_id, "same self-declared host as the guard must still be skipped when no verified subnet exists for either");
    }

    /// A clock a test can advance after construction, for simulating the
    /// passage of time between a publish and a later `select_route` call.
    /// Starts a few seconds ahead of the real current time -- comfortably
    /// past any `make_descriptor`-built descriptor's `not_before` (which
    /// is minted from a separate, slightly later real-time read of its
    /// own, unlike the other two crates' tests, which use a fixed
    /// constant for both) -- while staying well inside its validity
    /// window.
    fn movable_clock() -> (Arc<dyn Fn() -> f64 + Send + Sync>, Arc<Mutex<f64>>) {
        let now = Arc::new(Mutex::new(now_unix() + 5.0));
        let reader = Arc::clone(&now);
        (Arc::new(move || *reader.lock().unwrap()) as Arc<dyn Fn() -> f64 + Send + Sync>, now)
    }

    /// Security audit fix (2026-09-26, finding #5 -- no vetting before
    /// self-declaring "guard"): with `min_guard_age_seconds` set, a guard
    /// published moments ago must not be picked for an unpinned guard
    /// slot -- a brand-new identity cannot claim the guard role on day
    /// one just by setting the role byte in its own signed descriptor.
    #[test]
    fn select_route_guard_vetting_rejects_a_brand_new_guard() {
        let (clock, _now) = movable_clock();
        let mut dir = Directory::new(DirectoryOptions { clock: Some(clock), min_guard_age_seconds: Some(1800.0), ..Default::default() }).unwrap();
        dir.publish(make_descriptor(70, "9.9.9.9", &[ROLE_GUARD])).unwrap();
        dir.publish(make_descriptor(71, "9.9.9.10", &[ROLE_EXIT])).unwrap();

        let err = dir.select_route(SelectRouteOptions { hops: 2, seed: Some(1), ..Default::default() }).unwrap_err();
        assert!(matches!(err, DirectoryError::Other(_)), "expected a vetting-specific error, got {err:?}");
    }

    /// Same setup, but the clock advances past `min_guard_age_seconds`
    /// (staying within the descriptor's own validity window) before the
    /// route is built -- the guard is now eligible.
    #[test]
    fn select_route_guard_vetting_accepts_a_guard_once_old_enough() {
        let (clock, now) = movable_clock();
        let mut dir = Directory::new(DirectoryOptions { clock: Some(clock), min_guard_age_seconds: Some(1800.0), ..Default::default() }).unwrap();
        let guard = make_descriptor(72, "9.9.9.9", &[ROLE_GUARD]);
        let guard_id = guard.identity_public.clone();
        dir.publish(guard).unwrap();
        dir.publish(make_descriptor(73, "9.9.9.10", &[ROLE_EXIT])).unwrap();

        *now.lock().unwrap() += 1800.0;
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
    fn select_route_guard_vetting_exempts_an_explicit_preferred_guard() {
        let (clock, _now) = movable_clock();
        let mut dir = Directory::new(DirectoryOptions { clock: Some(clock), min_guard_age_seconds: Some(1800.0), ..Default::default() }).unwrap();
        let guard = make_descriptor(74, "9.9.9.9", &[ROLE_GUARD]);
        let guard_id = guard.identity_public.clone();
        dir.publish(guard).unwrap();
        dir.publish(make_descriptor(75, "9.9.9.10", &[ROLE_EXIT])).unwrap();

        let route = dir
            .select_route(SelectRouteOptions {
                hops: 2,
                seed: Some(1),
                preferred_guard: Some(guard_id.clone()),
                require_preferred_guard: true,
                ..Default::default()
            })
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
    fn first_seen_seeded_externally_makes_a_guard_immediately_eligible() {
        let (clock, now) = movable_clock();
        let start = *now.lock().unwrap();
        let mut dir = Directory::new(DirectoryOptions { clock: Some(clock), min_guard_age_seconds: Some(1800.0), ..Default::default() }).unwrap();
        let guard = make_descriptor(76, "9.9.9.9", &[ROLE_GUARD]);
        let guard_id = guard.identity_public.clone();
        dir.set_first_seen(HashMap::from([(guard_id.clone(), start - 3600.0)]));
        dir.publish(guard).unwrap();
        dir.publish(make_descriptor(77, "9.9.9.10", &[ROLE_EXIT])).unwrap();

        let route = dir.select_route(SelectRouteOptions { hops: 2, seed: Some(1), ..Default::default() }).unwrap();
        assert_eq!(route[0].identity_public, guard_id);
        assert_eq!(dir.first_seen_snapshot().get(&guard_id), Some(&(start - 3600.0)), "publish must not overwrite an externally seeded, earlier first_seen");
    }

    #[test]
    fn select_route_respects_preferred_guard_and_exclusions() {
        let mut dir = Directory::new(DirectoryOptions::default()).unwrap();
        let guard = make_descriptor(50, "10.4.0.1", &[ROLE_GUARD]);
        dir.publish(guard.clone()).unwrap();
        dir.publish(make_descriptor(51, "10.4.1.1", &[ROLE_GUARD])).unwrap();
        dir.publish(make_descriptor(52, "10.5.0.1", &[ROLE_MIDDLE])).unwrap();
        dir.publish(make_descriptor(53, "10.6.0.1", &[ROLE_EXIT])).unwrap();

        let route = dir
            .select_route(SelectRouteOptions {
                hops: 3,
                seed: Some(1),
                preferred_guard: Some(guard.identity_public.clone()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(route[0].identity_public, guard.identity_public);

        let err = dir.select_route(SelectRouteOptions {
            hops: 3,
            seed: Some(1),
            preferred_guard: Some(vec![0xFF; 32]),
            require_preferred_guard: true,
            ..Default::default()
        });
        assert!(matches!(err, Err(DirectoryError::PreferredGuardUnavailable(_))));
    }

    #[test]
    fn select_route_excluded_exit_is_never_picked() {
        let mut dir = Directory::new(DirectoryOptions::default()).unwrap();
        let guard = make_descriptor(1, "10.1.0.1", &[ROLE_GUARD]);
        let middle = make_descriptor(2, "10.2.0.1", &[ROLE_MIDDLE]);
        let bad_exit = make_descriptor(3, "10.3.0.1", &[ROLE_EXIT]);
        let good_exit = make_descriptor(4, "10.4.0.1", &[ROLE_EXIT]);
        for d in [guard, middle, bad_exit.clone(), good_exit.clone()] {
            dir.publish(d).unwrap();
        }
        // No `seed` here (a real CSPRNG pick each time, matching Python's
        // real `secrets`-backed default) -- run it enough times that a
        // route selection bug (rather than a fixed seed's luck) would show.
        for _ in 0..30 {
            let route = dir
                .select_route(SelectRouteOptions {
                    exclude_identities: vec![bad_exit.identity_public.clone()],
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(route.last().unwrap().identity_public, good_exit.identity_public);
        }
    }

    #[test]
    fn select_route_excluding_every_exit_raises() {
        let mut dir = Directory::new(DirectoryOptions::default()).unwrap();
        let guard = make_descriptor(1, "10.1.0.1", &[ROLE_GUARD]);
        let middle = make_descriptor(2, "10.2.0.1", &[ROLE_MIDDLE]);
        let only_exit = make_descriptor(3, "10.3.0.1", &[ROLE_EXIT]);
        for d in [guard, middle, only_exit.clone()] {
            dir.publish(d).unwrap();
        }
        let err = dir.select_route(SelectRouteOptions {
            exclude_identities: vec![only_exit.identity_public],
            ..Default::default()
        });
        assert!(err.is_err());
    }

    #[test]
    fn select_route_preferred_guard_is_never_excluded() {
        // A guard that is *both* preferred *and* explicitly excluded must
        // still be picked -- `exclude_identities` is meant to steer away
        // from a circuit's own already-used relays on a retry, never to
        // override an operator's persisted/pinned guard choice.
        let mut dir = Directory::new(DirectoryOptions::default()).unwrap();
        let guard = make_descriptor(1, "10.1.0.1", &[ROLE_GUARD]);
        let middle = make_descriptor(2, "10.2.0.1", &[ROLE_MIDDLE]);
        let exit = make_descriptor(3, "10.3.0.1", &[ROLE_EXIT]);
        for d in [guard.clone(), middle, exit] {
            dir.publish(d).unwrap();
        }
        let route = dir
            .select_route(SelectRouteOptions {
                preferred_guard: Some(guard.identity_public.clone()),
                exclude_identities: vec![guard.identity_public.clone()],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(route[0].identity_public, guard.identity_public);
    }

    #[test]
    fn select_route_family_exclusion_and_exit_port_filter() {
        let mut dir = Directory::new(DirectoryOptions::default()).unwrap();
        // Two mutually-declared family members as guards; only one should
        // ever be usable in a route that also needs a distinct middle.
        let a_identity = identity_key(60);
        let b_identity = identity_key(61);
        let guard_a = RelayDescriptor::create(
            &a_identity,
            vec![60; 32],
            "10.7.0.1",
            9000,
            vec![ROLE_GUARD.to_string(), ROLE_MIDDLE.to_string()],
            DEFAULT_DESCRIPTOR_LIFETIME,
            None,
            CreateOptions { family: Some(vec![b_identity.to_vec()]), ..Default::default() },
        )
        .unwrap();
        let guard_b = RelayDescriptor::create(
            &b_identity,
            vec![61; 32],
            "10.7.1.1",
            9000,
            vec![ROLE_GUARD.to_string(), ROLE_MIDDLE.to_string()],
            DEFAULT_DESCRIPTOR_LIFETIME,
            None,
            CreateOptions { family: Some(vec![a_identity.to_vec()]), ..Default::default() },
        )
        .unwrap();
        dir.publish(guard_a.clone()).unwrap();
        dir.publish(guard_b.clone()).unwrap();
        dir.publish(make_descriptor(62, "10.8.0.1", &[ROLE_MIDDLE])).unwrap();
        let exit_with_port = RelayDescriptor::create(
            &identity_key(63),
            vec![63; 32],
            "10.9.0.1",
            9000,
            vec![ROLE_EXIT.to_string()],
            DEFAULT_DESCRIPTOR_LIFETIME,
            None,
            CreateOptions { exit_port_ranges: Some(vec![(443, 443)]), ..Default::default() },
        )
        .unwrap();
        dir.publish(exit_with_port.clone()).unwrap();
        dir.publish(make_descriptor(64, "10.9.1.1", &[ROLE_EXIT])).unwrap();

        // hops=2 forces guard+exit only, so family exclusion for the
        // *middle* role doesn't come into play; exercise exit_port instead.
        let route = dir
            .select_route(SelectRouteOptions {
                hops: 2,
                seed: Some(7),
                exit_port: Some(443),
                enforce_subnet_diversity: false,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(route.last().unwrap().identity_public, exit_with_port.identity_public);
    }

    #[test]
    fn select_route_fails_when_no_relay_available() {
        let dir = Directory::new(DirectoryOptions::default()).unwrap();
        assert!(dir.select_route(SelectRouteOptions::default()).is_err());
    }

    #[test]
    fn prune_removes_expired_descriptors() {
        let time = Arc::new(std::sync::Mutex::new(1_700_000_000.0f64));
        let time_for_clock = time.clone();
        let clock: Arc<dyn Fn() -> f64 + Send + Sync> = Arc::new(move || *time_for_clock.lock().unwrap());
        let mut dir = Directory::new(DirectoryOptions { clock: Some(clock), ..Default::default() }).unwrap();

        let d = RelayDescriptor::create(
            &identity_key(70),
            vec![70; 32],
            "10.10.0.1",
            9000,
            vec![ROLE_MIDDLE.to_string()],
            10.0, // short lifetime
            Some(1_700_000_000.0),
            CreateOptions::default(),
        )
        .unwrap();
        assert!(dir.publish(d).unwrap());
        assert_eq!(dir.len(), 1);

        // Advance the clock past not_after and prune.
        *time.lock().unwrap() = 1_700_000_100.0;
        assert_eq!(dir.prune(), 1);
        assert_eq!(dir.len(), 0);
    }
}
