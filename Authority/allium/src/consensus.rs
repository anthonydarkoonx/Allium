//! Multi-authority directory consensus: signed votes and a client-side quorum.
//!
//! Port status / deviations from `allium/consensus.py`:
//!
//! * **Updated once `directory.rs` landed**: this module now uses the real
//!   [`crate::directory::RelayDescriptor`] everywhere it used to use a local
//!   `RelayDescriptorStub` stand-in. That stand-in is gone.
//! * **Updated once `dirwire.rs` landed**: [`descriptor_digest`] now hashes
//!   the real `dirwire::encode_descriptor` wire encoding (SHA-256, matching
//!   Python's `consensus.descriptor_digest` exactly), and
//!   `encode_vote_request`/`decode_vote_request` now use the real
//!   `dirwire::DIR_MAGIC` (`b"ALDR"`) instead of a local placeholder. Both
//!   placeholders are gone.
//! * Python's `consensus.py` signs/verifies votes with `cryptography`'s
//!   Ed25519 (this sandbox has no network access to fetch `ed25519-dalek` --
//!   see the note atop `allium/Cargo.toml`). [`encode_vote`]/[`decode_vote`]
//!   take the Ed25519 sign/verify step as injected closures (`sign`/`verify`)
//!   instead of calling a crate directly, so the wire framing (the part with
//!   real logic to port) is implemented and tested now; a real build wires
//!   in `ed25519-dalek` closures once fetchable.
//!
//! Everything else (`default_quorum`, `compute_consensus`,
//! `missing_identities`, the `Vote` shape, and the vote wire *framing*) is a
//! full, tested port.

use crate::dirwire::{encode_descriptor, DIR_MAGIC};
use crate::directory::{RelayDescriptor, SubnetKey};
use crate::hashutil::sha256;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

/// Directory-protocol message types (see `allium::dirwire` for 1-9, phase 3).
pub const VOTE_REQUEST: u8 = 10;
pub const VOTE_REPLY: u8 = 11;

pub const DEFAULT_VOTE_LIFETIME: f64 = 600.0;
pub const MAX_VOTE_CLOCK_SKEW: f64 = 120.0;

const LABEL: &[u8] = b"allium-vote-v1";
const KEY_LEN: usize = 32;
const SIG_LEN: usize = 64;
const MAX_ENTRIES: usize = 8192;
/// `identity (32) + descriptor_digest (32) + measured_bandwidth (8) +
/// observed_subnet (1 tag byte + 4 payload bytes, see
/// `encode_subnet`/`decode_subnet`)`.
const ENTRY_LEN: usize = 32 + 32 + 8 + 5;

const SUBNET_TAG_NONE: u8 = 0;
const SUBNET_TAG_V4: u8 = 1;
const SUBNET_TAG_V6: u8 = 2;

/// Fixed 5-byte wire form of an authority's own observed subnet for one
/// relay (see [`Vote::entries`]): a tag byte plus 4 payload bytes, using
/// only the first 2 for `SubnetKey::V4`.
fn encode_subnet(subnet: Option<SubnetKey>) -> [u8; 5] {
    let mut out = [0u8; 5];
    match subnet {
        None => out[0] = SUBNET_TAG_NONE,
        Some(SubnetKey::V4(octets)) => {
            out[0] = SUBNET_TAG_V4;
            out[1..3].copy_from_slice(&octets);
        }
        Some(SubnetKey::V6(octets)) => {
            out[0] = SUBNET_TAG_V6;
            out[1..5].copy_from_slice(&octets);
        }
    }
    out
}

/// Inverse of [`encode_subnet`]. An unrecognized tag decodes as `None`
/// (forward-compatible: a future tag a peer doesn't understand yet just
/// means "no usable subnet claim from this authority"), not an error --
/// this is attestation data, not protocol framing, so being unable to use
/// one authority's claim must never fail parsing the whole vote.
fn decode_subnet(raw: &[u8; 5]) -> Option<SubnetKey> {
    match raw[0] {
        SUBNET_TAG_V4 => Some(SubnetKey::V4([raw[1], raw[2]])),
        SUBNET_TAG_V6 => Some(SubnetKey::V6([raw[1], raw[2], raw[3], raw[4]])),
        _ => None,
    }
}

/// A vote was malformed, unsigned, untrusted, or out of its window; or too
/// few valid votes were available to reach quorum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusError {
    pub message: String,
}
impl fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for ConsensusError {}
fn err(msg: impl Into<String>) -> ConsensusError {
    ConsensusError { message: msg.into() }
}

/// Explicit opt-in to skip authority pinning in [`decode_vote`].
///
/// Mirrors Python's `trusted=ALLOW_ANY_SIGNER` sentinel object: passing this
/// variant is the only way to accept a vote from any signer, so it can only
/// happen on purpose.
pub enum Trusted<'a> {
    Keys(&'a [[u8; 32]]),
    AllowAnySigner,
}

/// SHA-256 of the descriptor's exact wire encoding.
///
/// Matches Python's `consensus.descriptor_digest`: `hashlib.sha256(
/// dirwire.encode_descriptor(descriptor)).digest()`. A descriptor that
/// fails to encode (shouldn't happen for anything `RelayDescriptor::create`
/// produced) digests as SHA-256 of the empty string, so this function stays
/// infallible like Python's (which never raises here in practice either).
pub fn descriptor_digest(descriptor: &RelayDescriptor) -> [u8; 32] {
    let wire = encode_descriptor(descriptor).unwrap_or_default();
    sha256(&wire)
}

pub fn encode_vote_request() -> Vec<u8> {
    let mut out = DIR_MAGIC.to_vec();
    out.push(VOTE_REQUEST);
    out
}

pub fn decode_vote_request(data: &[u8]) -> Result<(), ConsensusError> {
    if !data.starts_with(DIR_MAGIC) || data.len() < 5 || data[4] != VOTE_REQUEST {
        return Err(err("not a vote request"));
    }
    Ok(())
}

/// One authority's signed vote.
#[derive(Debug, Clone, PartialEq)]
pub struct Vote {
    pub authority: [u8; 32],
    pub valid_after: f64,
    pub valid_until: f64,
    /// `(identity, descriptor_digest, measured_bandwidth_or_0,
    /// observed_subnet)`. `observed_subnet` is this authority's own
    /// `Directory::verified_subnet_of` for the relay at vote-signing time
    /// -- i.e. the subnet its address was actually seen publishing from,
    /// not anything the relay's own descriptor claims. `None` when this
    /// authority has never itself received a live PUBLISH from that relay
    /// (e.g. it only learned of it from another authority).
    pub entries: Vec<([u8; 32], [u8; 32], u64, Option<SubnetKey>)>,
}

/// Build and sign a VOTE_REPLY message from `(descriptor, bandwidth,
/// observed_subnet)` triples.
///
/// `sign(message) -> signature` stands in for Ed25519 signing (see module
/// docs); `authority_public` is that key's 32-byte public key.
pub fn encode_vote(
    authority_public: [u8; 32],
    entries: &[(RelayDescriptor, u64, Option<SubnetKey>)],
    now: f64,
    lifetime: f64,
    sign: impl Fn(&[u8]) -> [u8; 64],
) -> Result<Vec<u8>, ConsensusError> {
    if entries.len() > MAX_ENTRIES {
        return Err(err(format!("too many entries ({})", entries.len())));
    }
    let mut body = Vec::new();
    body.extend_from_slice(&authority_public);
    body.extend_from_slice(&now.to_be_bytes());
    body.extend_from_slice(&(now + lifetime).to_be_bytes());
    body.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for (descriptor, bandwidth, observed_subnet) in entries {
        body.extend_from_slice(&descriptor.identity_public);
        body.extend_from_slice(&descriptor_digest(descriptor));
        body.extend_from_slice(&bandwidth.to_be_bytes());
        body.extend_from_slice(&encode_subnet(*observed_subnet));
    }
    let mut to_sign = LABEL.to_vec();
    to_sign.extend_from_slice(&body);
    let signature = sign(&to_sign);

    let mut out = DIR_MAGIC.to_vec();
    out.push(VOTE_REPLY);
    out.extend_from_slice(&body);
    out.extend_from_slice(&signature);
    Ok(out)
}

/// Parse and verify a VOTE_REPLY.
///
/// `verify(authority_key, signature, message) -> bool` stands in for Ed25519
/// verification (see module docs).
pub fn decode_vote(
    data: &[u8],
    trusted: Trusted,
    now: f64,
    verify: impl Fn(&[u8; 32], &[u8; 64], &[u8]) -> bool,
) -> Result<Vote, ConsensusError> {
    if !data.starts_with(DIR_MAGIC) || data.len() < 5 + SIG_LEN || data[4] != VOTE_REPLY {
        return Err(err("not a vote"));
    }
    let body = &data[5..data.len() - SIG_LEN];
    let signature_slice = &data[data.len() - SIG_LEN..];
    if body.len() < KEY_LEN + 18 || signature_slice.len() != SIG_LEN {
        return Err(err("vote truncated"));
    }
    let mut authority = [0u8; 32];
    authority.copy_from_slice(&body[..KEY_LEN]);

    match trusted {
        Trusted::AllowAnySigner => {}
        Trusted::Keys(keys) => {
            if !keys.contains(&authority) {
                return Err(err("vote signed by an authority this client does not trust"));
            }
        }
    }

    let mut signature = [0u8; 64];
    signature.copy_from_slice(signature_slice);
    let mut to_verify = LABEL.to_vec();
    to_verify.extend_from_slice(body);
    if !verify(&authority, &signature, &to_verify) {
        return Err(err("vote signature invalid"));
    }

    let valid_after = f64::from_be_bytes(body[KEY_LEN..KEY_LEN + 8].try_into().unwrap());
    let valid_until = f64::from_be_bytes(body[KEY_LEN + 8..KEY_LEN + 16].try_into().unwrap());
    let count = u16::from_be_bytes([body[KEY_LEN + 16], body[KEY_LEN + 17]]) as usize;

    if !(valid_after - MAX_VOTE_CLOCK_SKEW <= now && now <= valid_until + MAX_VOTE_CLOCK_SKEW) {
        return Err(err("vote is outside its validity window"));
    }
    if count > MAX_ENTRIES {
        return Err(err("vote has too many entries"));
    }
    let offset = KEY_LEN + 18;
    if body.len() != offset + count * ENTRY_LEN {
        return Err(err("vote length does not match its entry count"));
    }
    let mut entries = Vec::with_capacity(count);
    let mut pos = offset;
    for _ in 0..count {
        let mut identity = [0u8; 32];
        identity.copy_from_slice(&body[pos..pos + KEY_LEN]);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&body[pos + KEY_LEN..pos + 2 * KEY_LEN]);
        let bandwidth_end = pos + 2 * KEY_LEN + 8;
        let bandwidth = u64::from_be_bytes(body[pos + 2 * KEY_LEN..bandwidth_end].try_into().unwrap());
        let subnet_raw: [u8; 5] = body[bandwidth_end..pos + ENTRY_LEN].try_into().unwrap();
        let observed_subnet = decode_subnet(&subnet_raw);
        pos += ENTRY_LEN;
        entries.push((identity, digest, bandwidth, observed_subnet));
    }
    Ok(Vote { authority, valid_after, valid_until, entries })
}

/// A strict majority of the configured authorities.
pub fn default_quorum(authority_count: i64) -> i64 {
    (authority_count / 2 + 1).max(1)
}

/// Combine verified votes and fetched descriptors into
/// `(descriptors, measured_bandwidth, verified_subnet)`.
///
/// `verified_subnet` is populated the same Byzantine-tolerant way as
/// `measured_bandwidth`: a relay's identity only gets an entry when at
/// least `quorum` distinct authorities' votes agree on the *same*
/// observed subnet for it, so a single colluding or mistaken authority
/// can never inject a false verified subnet on its own.
pub fn compute_consensus(
    votes: &[Vote],
    quorum: usize,
    descriptors: &[RelayDescriptor],
) -> Result<(Vec<RelayDescriptor>, BTreeMap<[u8; 32], u64>, BTreeMap<[u8; 32], SubnetKey>), ConsensusError> {
    let mut distinct: BTreeMap<[u8; 32], &Vote> = BTreeMap::new();
    for vote in votes {
        distinct.entry(vote.authority).or_insert(vote);
    }
    if distinct.len() < quorum {
        return Err(err(format!("only {} valid authority vote(s), need {quorum} for a quorum", distinct.len())));
    }

    let mut voters: BTreeMap<[u8; 32], HashSet<[u8; 32]>> = BTreeMap::new();
    let mut digests: BTreeMap<[u8; 32], HashSet<[u8; 32]>> = BTreeMap::new();
    let mut measurements: BTreeMap<[u8; 32], Vec<u64>> = BTreeMap::new();
    let mut subnet_votes: BTreeMap<[u8; 32], HashMap<SubnetKey, HashSet<[u8; 32]>>> = BTreeMap::new();

    for vote in distinct.values() {
        let mut seen_here: HashSet<[u8; 32]> = HashSet::new();
        for (identity, digest, bandwidth, observed_subnet) in &vote.entries {
            if !seen_here.insert(*identity) {
                continue;
            }
            voters.entry(*identity).or_default().insert(vote.authority);
            digests.entry(*identity).or_default().insert(*digest);
            if *bandwidth != 0 {
                measurements.entry(*identity).or_default().push(*bandwidth);
            }
            if let Some(subnet) = observed_subnet {
                subnet_votes.entry(*identity).or_default().entry(*subnet).or_default().insert(vote.authority);
            }
        }
    }

    let agreed: HashSet<[u8; 32]> =
        voters.iter().filter(|(_, who)| who.len() >= quorum).map(|(id, _)| *id).collect();

    let mut chosen: BTreeMap<[u8; 32], RelayDescriptor> = BTreeMap::new();
    for descriptor in descriptors {
        let identity = descriptor.identity_public;
        if !agreed.contains(&identity) {
            continue;
        }
        if !digests.get(&identity).map(|d| d.contains(&descriptor_digest(descriptor))).unwrap_or(false) {
            continue;
        }
        let replace = match chosen.get(&identity) {
            None => true,
            Some(current) => descriptor.not_before > current.not_before,
        };
        if replace {
            chosen.insert(identity, descriptor.clone());
        }
    }

    let mut measured: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for (identity, mut values) in measurements {
        if values.len() >= quorum && agreed.contains(&identity) {
            values.sort_unstable();
            measured.insert(identity, median(&values));
        }
    }

    let mut verified_subnet: BTreeMap<[u8; 32], SubnetKey> = BTreeMap::new();
    for (identity, by_subnet) in &subnet_votes {
        if !agreed.contains(identity) {
            continue;
        }
        // At most one subnet value can reach `quorum` distinct authorities
        // (quorum is a strict majority), so the first one found is the
        // only one that ever will be.
        if let Some((subnet, _)) = by_subnet.iter().find(|(_, who)| who.len() >= quorum) {
            verified_subnet.insert(*identity, *subnet);
        }
    }

    let mut result: Vec<RelayDescriptor> = chosen.into_values().collect();
    result.sort_by(|a, b| a.host.cmp(&b.host));
    Ok((result, measured, verified_subnet))
}

/// Security fix (2026-09-26): for an *even* count, this used to average
/// the two middle values (matching Python's `statistics.median`), which is
/// only Byzantine-robust when there are enough samples that no single
/// authority's report lands in the averaged pair. That's never true at the
/// realistic small-deployment count of exactly 2 measurements (a 2- or
/// 3-authority setup): one authority reporting an extreme value there --
/// lying, or simply a bug -- pulls the "median" arbitrarily far from the
/// honest report, and the addition itself had no overflow guard (two
/// large `u64` bandwidth figures summing past `u64::MAX` would wrap or
/// panic). Returning the *lower* of the two middle values instead of their
/// mean fixes both: the result is always one of the values an authority
/// actually reported (never a synthesized blend that can be pushed
/// arbitrarily high), so no addition is needed at all, and a lying
/// authority can only ever pull a relay's measured weight *down* toward
/// its own report, never inflate it -- the more consequential direction to
/// defend, since inflating a relay's own measured bandwidth is what
/// attracts it disproportionate traffic.
fn median(sorted: &[u64]) -> u64 {
    let n = sorted.len();
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        sorted[n / 2 - 1]
    }
}

/// Identities a quorum agrees on but for which `descriptors` has no
/// vote-matching descriptor yet.
pub fn missing_identities(
    votes: &[Vote],
    quorum: usize,
    descriptors: &[RelayDescriptor],
) -> Result<HashSet<[u8; 32]>, ConsensusError> {
    let (have, _, _) = compute_consensus(votes, quorum, descriptors)?;
    let got: HashSet<[u8; 32]> = have.iter().map(|d| d.identity_public).collect();

    let mut distinct: BTreeMap<[u8; 32], &Vote> = BTreeMap::new();
    for vote in votes {
        distinct.entry(vote.authority).or_insert(vote);
    }
    let mut counts: BTreeMap<[u8; 32], HashSet<[u8; 32]>> = BTreeMap::new();
    for vote in distinct.values() {
        for (identity, _digest, _bw, _subnet) in &vote.entries {
            counts.entry(*identity).or_default().insert(vote.authority);
        }
    }
    Ok(counts.into_iter().filter(|(_, who)| who.len() >= quorum).map(|(id, _)| id).filter(|id| !got.contains(id)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fake, NOT cryptographically meaningful "signing" scheme used only to
    // exercise the wire framing in tests: HMAC-SHA256 keyed by a 32-byte
    // "private key", padded to 64 bytes to match Ed25519's signature length.
    // Tamper-detection still works because any bit flip in the signed bytes
    // changes the HMAC. Swap for real ed25519-dalek closures in production.
    fn fake_sign(private: [u8; 32]) -> impl Fn(&[u8]) -> [u8; 64] {
        move |msg: &[u8]| {
            let mac = crate::hashutil::hmac_sha256(&private, msg);
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(&mac);
            sig[32..].copy_from_slice(&mac);
            sig
        }
    }

    fn fake_verify() -> impl Fn(&[u8; 32], &[u8; 64], &[u8]) -> bool {
        move |authority: &[u8; 32], sig: &[u8; 64], msg: &[u8]| {
            let mac = crate::hashutil::hmac_sha256(authority, msg);
            crate::hashutil::constant_time_eq(&sig[..32], &mac)
        }
    }

    // consensus.rs never verifies a descriptor's signature (that already
    // happened when each authority itself ran `Directory::publish` on it --
    // see the module docs), so the fields these tests don't read
    // (`static_public`, `signature`, `roles`, `port`, `version`,
    // `extensions`, `not_after`) are just filled with harmless placeholders.
    fn relay(host: &str, identity: [u8; 32], not_before: f64) -> RelayDescriptor {
        RelayDescriptor {
            identity_public: identity,
            static_public: [0u8; 32],
            host: host.to_string(),
            port: 9000,
            roles: vec!["middle".to_string()],
            not_before,
            not_after: not_before + 3600.0,
            signature: vec![0u8; 64],
            version: 1,
            extensions: Vec::new(),
        }
    }

    fn id_from(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    // -- codec -----------------------------------------------------
    #[test]
    fn test_round_trip_and_signature() {
        let auth_priv = id_from(1);
        let auth_pub = auth_priv; // fake scheme: "public key" == "private key" byte pattern
        let r1 = relay("10.0.0.1", id_from(2), 1000.0);
        let r2 = relay("10.0.0.2", id_from(3), 1000.0);
        let encoded = encode_vote(
            auth_pub,
            &[(r1.clone(), 500, Some(SubnetKey::V4([10, 0]))), (r2.clone(), 0, None)],
            1000.0,
            DEFAULT_VOTE_LIFETIME,
            fake_sign(auth_priv),
        )
        .unwrap();
        let vote = decode_vote(&encoded, Trusted::Keys(&[auth_pub]), 1000.0, fake_verify()).unwrap();
        assert_eq!(vote.authority, auth_pub);
        assert_eq!(vote.entries.iter().map(|(_, _, bw, _)| *bw).collect::<Vec<_>>(), vec![500, 0]);
        assert_eq!(vote.entries[0].0, r1.identity_public);
        assert_eq!(vote.entries[0].1, descriptor_digest(&r1));
        assert_eq!(vote.entries[0].3, Some(SubnetKey::V4([10, 0])));
        assert_eq!(vote.entries[1].3, None);
    }

    #[test]
    fn test_untrusted_signer_rejected() {
        let auth_priv = id_from(5);
        let other_pub = id_from(9);
        let encoded = encode_vote(auth_priv, &[], 1000.0, DEFAULT_VOTE_LIFETIME, fake_sign(auth_priv)).unwrap();
        assert!(decode_vote(&encoded, Trusted::Keys(&[other_pub]), 1000.0, fake_verify()).is_err());
    }

    #[test]
    fn test_tampered_vote_rejected() {
        let auth_priv = id_from(1);
        let r = relay("10.0.0.1", id_from(2), 1000.0);
        let mut encoded = encode_vote(auth_priv, &[(r, 5, None)], 1000.0, DEFAULT_VOTE_LIFETIME, fake_sign(auth_priv)).unwrap();
        encoded[60] ^= 0xFF;
        assert!(decode_vote(&encoded, Trusted::Keys(&[auth_priv]), 1000.0, fake_verify()).is_err());
    }

    #[test]
    fn test_expired_vote_rejected() {
        let auth_priv = id_from(1);
        let encoded = encode_vote(auth_priv, &[], 0.0, 60.0, fake_sign(auth_priv)).unwrap();
        assert!(decode_vote(&encoded, Trusted::Keys(&[auth_priv]), 10_000.0, fake_verify()).is_err());
    }

    #[test]
    fn test_default_quorum_is_majority() {
        let got: Vec<i64> = (1..=5).map(default_quorum).collect();
        assert_eq!(got, vec![1, 2, 2, 3, 3]);
    }

    // -- compute_consensus -----------------------------------------------------
    fn vote(authority: [u8; 32], entries: Vec<(RelayDescriptor, u64)>) -> Vote {
        Vote {
            authority,
            valid_after: 0.0,
            valid_until: 1e18,
            entries: entries.into_iter().map(|(d, bw)| (d.identity_public, descriptor_digest(&d), bw, None)).collect(),
        }
    }

    fn honest_set() -> Vec<RelayDescriptor> {
        (1..=3).map(|i| relay(&format!("10.0.0.{i}"), id_from(i), 1000.0)).collect()
    }

    #[test]
    fn test_one_bad_authority_cannot_inject_a_relay() {
        let auths: Vec<[u8; 32]> = (10..13).map(id_from).collect();
        let honest = honest_set();
        let sybil = relay("66.6.6.6", id_from(99), 1000.0);
        let mut votes = vec![
            vote(auths[0], honest.iter().map(|d| (d.clone(), 0)).collect()),
            vote(auths[1], honest.iter().map(|d| (d.clone(), 0)).collect()),
        ];
        let mut third: Vec<(RelayDescriptor, u64)> = honest.iter().map(|d| (d.clone(), 0)).collect();
        third.push((sybil.clone(), 0));
        votes.push(vote(auths[2], third));

        let mut all_descriptors = honest.clone();
        all_descriptors.push(sybil.clone());
        let (chosen, _, _) = compute_consensus(&votes, 2, &all_descriptors).unwrap();
        let ids: HashSet<[u8; 32]> = chosen.iter().map(|d| d.identity_public).collect();
        assert!(!ids.contains(&sybil.identity_public));
        let expected: HashSet<[u8; 32]> = honest.iter().map(|d| d.identity_public).collect();
        assert_eq!(ids, expected);
    }

    #[test]
    fn test_one_bad_authority_cannot_hide_a_relay() {
        let auths: Vec<[u8; 32]> = (10..13).map(id_from).collect();
        let honest = honest_set();
        let votes = vec![
            vote(auths[0], honest.iter().map(|d| (d.clone(), 0)).collect()),
            vote(auths[1], honest.iter().map(|d| (d.clone(), 0)).collect()),
            vote(auths[2], vec![(honest[0].clone(), 0)]),
        ];
        let (chosen, _, _) = compute_consensus(&votes, 2, &honest).unwrap();
        assert_eq!(chosen.len(), 3);
    }

    /// Security fix: `verified_subnet` must be Byzantine-tolerant the same
    /// way `measured_bandwidth` already is -- a single lying (or merely
    /// mistaken) authority must never be able to inject a false verified
    /// subnet for a relay on its own. Two of three authorities agree the
    /// relay actually publishes from `10.0.0.0/16`; the third claims a
    /// different subnet entirely (either lying to hide a Sybil, or lying
    /// to falsely implicate an honest relay as colluding with another).
    #[test]
    fn test_verified_subnet_needs_quorum_agreement() {
        let auths: Vec<[u8; 32]> = (10..13).map(id_from).collect();
        let target = relay("relay.example", id_from(1), 1000.0);
        let real_subnet = SubnetKey::V4([10, 0]);
        let fake_subnet = SubnetKey::V4([66, 6]);
        let entry_with = |subnet: SubnetKey| (target.identity_public, descriptor_digest(&target), 0u64, Some(subnet));
        let votes = vec![
            Vote { authority: auths[0], valid_after: 0.0, valid_until: 1e18, entries: vec![entry_with(real_subnet)] },
            Vote { authority: auths[1], valid_after: 0.0, valid_until: 1e18, entries: vec![entry_with(real_subnet)] },
            Vote { authority: auths[2], valid_after: 0.0, valid_until: 1e18, entries: vec![entry_with(fake_subnet)] },
        ];
        let (_chosen, _measured, verified) = compute_consensus(&votes, 2, &[target.clone()]).unwrap();
        assert_eq!(verified.get(&target.identity_public), Some(&real_subnet), "quorum (2 of 3) must win, not the lone dissenting authority");
    }

    /// No single subnet claim reaching quorum (a genuine 50/50 split, or
    /// simply no authority having ever observed this relay publish live)
    /// must leave the relay with no verified subnet at all, rather than
    /// picking one arbitrarily -- the caller then falls back to the
    /// self-declared host, exactly as if no authority had voted on this
    /// at all.
    #[test]
    fn test_verified_subnet_absent_without_any_quorum() {
        let auths: Vec<[u8; 32]> = (10..12).map(id_from).collect();
        let target = relay("relay.example", id_from(1), 1000.0);
        let entry_with = |subnet: SubnetKey| (target.identity_public, descriptor_digest(&target), 0u64, Some(subnet));
        let votes = vec![
            Vote { authority: auths[0], valid_after: 0.0, valid_until: 1e18, entries: vec![entry_with(SubnetKey::V4([10, 0]))] },
            Vote { authority: auths[1], valid_after: 0.0, valid_until: 1e18, entries: vec![entry_with(SubnetKey::V4([20, 0]))] },
        ];
        let (_chosen, _measured, verified) = compute_consensus(&votes, 2, &[target.clone()]).unwrap();
        assert_eq!(verified.get(&target.identity_public), None);
    }

    #[test]
    fn test_duplicate_votes_from_one_authority_count_once() {
        let sybil = relay("66.6.6.6", id_from(99), 1000.0);
        let bad = vote(id_from(12), vec![(sybil.clone(), 0)]);
        let votes = vec![bad.clone(), bad.clone(), bad];
        assert!(compute_consensus(&votes, 2, &[sybil]).is_err());
    }

    #[test]
    fn test_median_bandwidth_resists_one_liar() {
        let target = relay("10.0.0.1", id_from(1), 1000.0);
        let auths: Vec<[u8; 32]> = (10..13).map(id_from).collect();
        let votes = vec![
            vote(auths[0], vec![(target.clone(), 1000)]),
            vote(auths[1], vec![(target.clone(), 1200)]),
            vote(auths[2], vec![(target.clone(), 1_000_000_000_000)]),
        ];
        let (_chosen, measured, _) = compute_consensus(&votes, 2, &[target.clone()]).unwrap();
        assert_eq!(measured[&target.identity_public], 1200);
    }

    /// Security fix: with exactly 2 measurements (the realistic case for a
    /// 2- or 3-authority deployment, since `default_quorum` never exceeds
    /// the number of authorities), averaging them -- the old behavior --
    /// let one lying authority pull the result arbitrarily far from the
    /// honest report, and could overflow `u64` outright. The lower of the
    /// two must win instead, bounding the result to an actually-reported
    /// value and defeating the inflate-your-own-bandwidth attack.
    #[test]
    fn test_median_bandwidth_even_count_picks_lower_not_average() {
        let target = relay("10.0.0.1", id_from(1), 1000.0);
        let auths: Vec<[u8; 32]> = (10..12).map(id_from).collect();
        let votes = vec![vote(auths[0], vec![(target.clone(), 1000)]), vote(auths[1], vec![(target.clone(), u64::MAX)])];
        let (_chosen, measured, _) = compute_consensus(&votes, 2, &[target.clone()]).unwrap();
        assert_eq!(measured[&target.identity_public], 1000, "a lying authority must not be able to inflate the measured bandwidth beyond the honest report");
    }

    #[test]
    fn test_measurement_needs_quorum() {
        let target = relay("10.0.0.1", id_from(1), 1000.0);
        let auths: Vec<[u8; 32]> = (10..13).map(id_from).collect();
        let votes = vec![
            vote(auths[0], vec![(target.clone(), 1_000_000_000)]),
            vote(auths[1], vec![(target.clone(), 0)]),
            vote(auths[2], vec![(target.clone(), 0)]),
        ];
        let (_chosen, measured, _) = compute_consensus(&votes, 2, &[target.clone()]).unwrap();
        assert!(!measured.contains_key(&target.identity_public));
    }

    #[test]
    fn test_newest_descriptor_wins() {
        let k = id_from(7);
        let old = relay("10.9.9.9", k, 900.0);
        let new = relay("10.9.9.10", k, 1000.0);
        let auths: Vec<[u8; 32]> = (10..12).map(id_from).collect();
        let votes = vec![vote(auths[0], vec![(old.clone(), 0)]), vote(auths[1], vec![(new.clone(), 0)])];
        let (chosen, _, _) = compute_consensus(&votes, 2, &[old, new]).unwrap();
        assert_eq!(chosen[0].host, "10.9.9.10");
    }

    #[test]
    fn test_descriptor_not_named_by_any_vote_is_ignored() {
        let k = id_from(7);
        let voted = relay("10.9.9.10", k, 1000.0);
        let substituted = relay("10.66.6.6", k, 1005.0);
        let auths: Vec<[u8; 32]> = (10..13).map(id_from).collect();
        let votes: Vec<Vote> = auths.iter().map(|&a| vote(a, vec![(voted.clone(), 0)])).collect();
        let (chosen, _, _) = compute_consensus(&votes, 2, &[substituted, voted]).unwrap();
        assert_eq!(chosen.iter().map(|d| d.host.clone()).collect::<Vec<_>>(), vec!["10.9.9.10".to_string()]);
    }

    #[test]
    fn test_missing_identities_reports_undescribed_agreed_relays() {
        let target = relay("10.0.0.1", id_from(1), 1000.0);
        let auths: Vec<[u8; 32]> = (10..12).map(id_from).collect();
        let votes = vec![vote(auths[0], vec![(target.clone(), 0)]), vote(auths[1], vec![(target.clone(), 0)])];
        let missing = missing_identities(&votes, 2, &[]).unwrap();
        assert!(missing.contains(&target.identity_public));
        let missing2 = missing_identities(&votes, 2, &[target.clone()]).unwrap();
        assert!(!missing2.contains(&target.identity_public));
    }

    #[test]
    fn test_short_vote_reply_does_not_panic() {
        for len in 0..=(5 + SIG_LEN) {
            let mut data = vec![0u8; len];
            if len >= 5 {
                data[..4].copy_from_slice(DIR_MAGIC);
                data[4] = VOTE_REPLY;
            }
            assert!(decode_vote(&data, Trusted::AllowAnySigner, 1000.0, fake_verify()).is_err());
        }
    }
}
