//! Multi-authority directory consensus: signed votes and a client-side quorum.
//!
//! **The problem.** Descriptors are self-signed, so a directory authority
//! cannot *forge* a relay -- but a client that trusts exactly one authority
//! for its view of the network can still be censored (handed only the
//! relays the authority likes) or Sybil-flooded (padded with relays the
//! authority runs itself). Once more than one party runs an authority,
//! nothing stops any one of them doing that to every client that happens to
//! ask it.
//!
//! **The fix.** Every authority answers a `VOTE_REQUEST` with a **vote**:
//! for every relay it currently considers live, the relay's identity, the
//! SHA-256 digest of the exact descriptor it holds, and an optional
//! bandwidth measurement -- inside a short validity window,
//! Ed25519-signed with the authority's own identity key (the same key
//! clients already pin). Votes are compact (72 bytes per relay); the
//! descriptors themselves are fetched once, from any one authority, with
//! the ordinary [`crate::dirwire`] FETCH.
//!
//! A client asks *all* of its configured authorities for votes, keeps only
//! votes that verify against a pinned key (one per key), and computes the
//! consensus itself ([`compute_consensus`]):
//!
//! * a relay is used only if at least `quorum` distinct authorities list
//!   it (typically a majority of the configured authorities -- see
//!   [`default_quorum`]), so a minority of authorities can neither inject
//!   relays nor -- as long as the honest majority lists a relay -- hide it;
//! * a fetched descriptor is used only if its digest appears in at least
//!   one verified vote, so whichever authority served the descriptors
//!   cannot slip in a different one; when votes name different (all
//!   validly self-signed) descriptors for the same relay -- a republish
//!   racing the fetch -- the newest (`not_before`) wins;
//! * a relay's bandwidth weight is the **median** of the authorities'
//!   measurements for it, used only when at least `quorum` authorities
//!   measured it -- so one authority cannot inflate or starve a relay's
//!   share of traffic beyond what the honest ones report.
//!
//! This is intentionally simpler than a full authority-to-authority voting
//! protocol (there is no single consensus document co-signed by all
//! authorities): every client computes the same majority function over the
//! same signed inputs, which gives the property that matters -- no single
//! authority can lie to clients -- without authorities having to
//! coordinate with each other at all.
//!
//! **Deviation from the Python original: trusting a vote's signer.**
//! Python's `decode_vote(data, trusted=ALLOW_ANY_SIGNER, ...)` defaults
//! `trusted` to an explicit sentinel object (so the caller must either
//! name that sentinel or pass real authority keys), and separately guards
//! against a caller passing `None` by mistake (which raises, rather than
//! silently behaving like the sentinel). Rust's type system makes the
//! mistaken-`None` case unreachable by construction: [`decode_vote`] takes
//! a [`Trust`] enum with exactly two variants, [`Trust::AllowAny`] (the
//! same explicit opt-in as Python's sentinel) and [`Trust::Only`] (a
//! pinned key set), so there is no "unset" state to accidentally end up
//! in.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::dirwire::{self, DirWireError};
use crate::directory::RelayDescriptor;

/// Directory-protocol message types (see [`crate::dirwire`] for 1-9).
pub const VOTE_REQUEST: u8 = 10;
pub const VOTE_REPLY: u8 = 11;

/// A vote is minted on demand and only valid briefly: a replayed old vote
/// (say, one listing a relay since removed) is worthless.
pub const DEFAULT_VOTE_LIFETIME: f64 = 600.0;
pub const MAX_VOTE_CLOCK_SKEW: f64 = 120.0;

const LABEL: &[u8] = b"allium-vote-v1";
const KEY_LEN: usize = 32;
const SIG_LEN: usize = 64;
const MAX_ENTRIES: usize = 8192;
/// identity(32) + descriptor_digest(32) + bandwidth(8) + observed_subnet
/// (1 tag byte + 4 payload bytes, see `encode_subnet`/`decode_subnet`).
/// Wire-compatible with Relays'/Authority's `consensus.rs`: an authority
/// that signs votes and a client that decodes them must agree on this
/// exact layout.
const ENTRY_LEN: usize = 32 + 32 + 8 + 5;

const SUBNET_TAG_NONE: u8 = 0;
const SUBNET_TAG_V4: u8 = 1;
const SUBNET_TAG_V6: u8 = 2;

/// Fixed 5-byte wire form of an authority's own observed subnet for one
/// relay (see [`Vote::entries`]): a tag byte plus 4 payload bytes, using
/// only the first 2 for an IPv4 subnet. `subnet` is expected to already be
/// masked to the grouping prefix (see `crate::directory`'s `subnet_key`),
/// so only the leading bytes ever carry real information.
fn encode_subnet(subnet: Option<IpAddr>) -> [u8; 5] {
    let mut out = [0u8; 5];
    match subnet {
        None => out[0] = SUBNET_TAG_NONE,
        Some(IpAddr::V4(v4)) => {
            out[0] = SUBNET_TAG_V4;
            out[1..3].copy_from_slice(&v4.octets()[..2]);
        }
        Some(IpAddr::V6(v6)) => {
            out[0] = SUBNET_TAG_V6;
            out[1..5].copy_from_slice(&v6.octets()[..4]);
        }
    }
    out
}

/// Inverse of [`encode_subnet`]. An unrecognized tag decodes as `None`
/// (forward-compatible: a future tag a peer doesn't understand yet just
/// means "no usable subnet claim from this authority"), not an error --
/// this is attestation data, not protocol framing, so being unable to use
/// one authority's claim must never fail parsing the whole vote.
fn decode_subnet(raw: &[u8; 5]) -> Option<IpAddr> {
    match raw[0] {
        SUBNET_TAG_V4 => Some(IpAddr::V4(Ipv4Addr::new(raw[1], raw[2], 0, 0))),
        SUBNET_TAG_V6 => Some(IpAddr::V6(Ipv6Addr::new(
            u16::from_be_bytes([raw[1], raw[2]]),
            u16::from_be_bytes([raw[3], raw[4]]),
            0,
            0,
            0,
            0,
            0,
            0,
        ))),
        _ => None,
    }
}

/// A vote was malformed, unsigned, untrusted, or out of its window; or too
/// few valid votes were available to reach quorum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusError(pub String);

impl fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ConsensusError {}

impl From<DirWireError> for ConsensusError {
    fn from(e: DirWireError) -> Self {
        ConsensusError(e.0)
    }
}

fn err(msg: impl Into<String>) -> ConsensusError {
    ConsensusError(msg.into())
}

/// Per-identity measured bandwidth (the median of what each authority
/// reported), keyed by relay identity -- [`compute_consensus`]'s second
/// return value.
pub type MeasuredBandwidth = std::collections::HashMap<Vec<u8>, u64>;

fn now_unix() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock before 1970").as_secs_f64()
}

/// One authority's signed statement about the currently-live relay set.
#[derive(Debug, Clone, PartialEq)]
pub struct Vote {
    pub authority: Vec<u8>,
    pub valid_after: f64,
    pub valid_until: f64,
    /// `(identity, descriptor_digest, measured_bandwidth_or_0,
    /// observed_subnet)` per relay. `observed_subnet` is this authority's
    /// own record of the subnet the relay's address was actually seen
    /// publishing from, not anything the relay's own descriptor claims;
    /// `None` when this authority never itself received a live PUBLISH
    /// from that relay.
    pub entries: Vec<(Vec<u8>, Vec<u8>, u64, Option<IpAddr>)>,
}

// `f64` fields mean `Vote` can't derive `Eq`/`Hash`; `PartialEq` above is
// enough for tests and callers that compare a decoded vote to what they
// encoded.

/// SHA-256 of the descriptor's exact wire encoding.
///
/// # Errors
/// Returns [`DirWireError`] if the descriptor cannot be encoded (an
/// unexpected field size) -- see [`crate::dirwire::encode_descriptor`].
pub fn descriptor_digest(descriptor: &RelayDescriptor) -> Result<[u8; 32], DirWireError> {
    let encoded = dirwire::encode_descriptor(descriptor)?;
    Ok(Sha256::digest(encoded).into())
}

/// A bare `VOTE_REQUEST`: "send me your current vote."
pub fn encode_vote_request() -> Vec<u8> {
    let mut out = dirwire::DIR_MAGIC.to_vec();
    out.push(VOTE_REQUEST);
    out
}

/// Validate a `VOTE_REQUEST` frame.
///
/// # Errors
/// Returns [`ConsensusError`] if the frame is not a well-formed vote
/// request.
pub fn decode_vote_request(data: &[u8]) -> Result<(), ConsensusError> {
    if !data.starts_with(dirwire::DIR_MAGIC) || data.len() < 5 || data[4] != VOTE_REQUEST {
        return Err(err("not a vote request"));
    }
    Ok(())
}

/// Build and sign a `VOTE_REPLY` message from `(descriptor, bandwidth)`
/// pairs (only each descriptor's identity and digest go on the wire).
///
/// # Errors
/// Returns [`ConsensusError`] if there are more than [`MAX_ENTRIES`]
/// entries, or a descriptor fails to encode.
pub fn encode_vote(
    authority_private: &[u8; 32],
    entries: &[(RelayDescriptor, u64, Option<IpAddr>)],
    now: Option<f64>,
    lifetime: f64,
) -> Result<Vec<u8>, ConsensusError> {
    let now = now.unwrap_or_else(now_unix);
    let key = SigningKey::from_bytes(authority_private);
    if entries.len() > MAX_ENTRIES {
        return Err(err(format!("too many entries ({})", entries.len())));
    }
    let mut body = key.verifying_key().to_bytes().to_vec();
    body.extend_from_slice(&now.to_be_bytes());
    body.extend_from_slice(&(now + lifetime).to_be_bytes());
    body.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for (descriptor, bandwidth, observed_subnet) in entries {
        if descriptor.identity_public.len() != KEY_LEN {
            return Err(err(format!("identity_public must be {KEY_LEN} bytes")));
        }
        body.extend_from_slice(&descriptor.identity_public);
        body.extend_from_slice(&descriptor_digest(descriptor)?);
        body.extend_from_slice(&bandwidth.to_be_bytes());
        body.extend_from_slice(&encode_subnet(*observed_subnet));
    }
    let mut to_sign = LABEL.to_vec();
    to_sign.extend_from_slice(&body);
    let signature = key.sign(&to_sign);
    let mut out = dirwire::DIR_MAGIC.to_vec();
    out.push(VOTE_REPLY);
    out.extend_from_slice(&body);
    out.extend_from_slice(&signature.to_bytes());
    Ok(out)
}

/// Which authority signatures [`decode_vote`] should accept.
///
/// There is no "unset"/default state: a caller must name either
/// [`Trust::AllowAny`] (Python's `ALLOW_ANY_SIGNER` sentinel -- an explicit
/// opt-in to skip authority pinning, e.g. for a test or a throwaway demo
/// setup) or [`Trust::Only`] with the pinned authority identities. See the
/// module doc's "Deviation from the Python original" note.
pub enum Trust<'a> {
    AllowAny,
    Only(&'a [Vec<u8>]),
}

/// Parse and verify a `VOTE_REPLY`.
///
/// The signature is checked regardless of `trusted`; `trusted` only gates
/// *which* signers are accepted.
///
/// # Errors
/// Returns [`ConsensusError`] on any problem: bad magic/type, truncation,
/// an untrusted signer, an invalid signature, or a validity window that
/// does not (allowing [`MAX_VOTE_CLOCK_SKEW`]) contain `now`.
pub fn decode_vote(data: &[u8], trusted: Trust<'_>, now: Option<f64>) -> Result<Vote, ConsensusError> {
    if !data.starts_with(dirwire::DIR_MAGIC) || data.len() < 5 || data[4] != VOTE_REPLY {
        return Err(err("not a vote"));
    }
    if data.len() < 5 + SIG_LEN {
        return Err(err("vote truncated"));
    }
    let body = &data[5..data.len() - SIG_LEN];
    let signature_bytes = &data[data.len() - SIG_LEN..];
    if body.len() < KEY_LEN + 18 {
        return Err(err("vote truncated"));
    }
    let authority = body[..KEY_LEN].to_vec();
    if let Trust::Only(keys) = &trusted {
        if !keys.iter().any(|k| k.as_slice() == authority.as_slice()) {
            return Err(err("vote signed by an authority this client does not trust"));
        }
    }
    let authority_key: [u8; KEY_LEN] =
        authority.clone().try_into().expect("authority slice is exactly KEY_LEN bytes");
    let verifying_key =
        VerifyingKey::from_bytes(&authority_key).map_err(|_| err("vote signature invalid"))?;
    let sig_array: [u8; SIG_LEN] = signature_bytes.try_into().expect("signature slice is exactly SIG_LEN bytes");
    let signature = Signature::from_bytes(&sig_array);
    let mut to_verify = LABEL.to_vec();
    to_verify.extend_from_slice(body);
    verifying_key.verify(&to_verify, &signature).map_err(|_| err("vote signature invalid"))?;

    let valid_after = f64::from_be_bytes(body[KEY_LEN..KEY_LEN + 8].try_into().unwrap());
    let valid_until = f64::from_be_bytes(body[KEY_LEN + 8..KEY_LEN + 16].try_into().unwrap());
    let count = u16::from_be_bytes([body[KEY_LEN + 16], body[KEY_LEN + 17]]) as usize;
    let now = now.unwrap_or_else(now_unix);
    if !(valid_after - MAX_VOTE_CLOCK_SKEW <= now && now <= valid_until + MAX_VOTE_CLOCK_SKEW) {
        return Err(err("vote is outside its validity window"));
    }
    if count > MAX_ENTRIES {
        return Err(err("vote has too many entries"));
    }
    let offset0 = KEY_LEN + 18;
    if body.len() != offset0 + count * ENTRY_LEN {
        return Err(err("vote length does not match its entry count"));
    }
    let mut entries = Vec::with_capacity(count);
    let mut offset = offset0;
    for _ in 0..count {
        let identity = body[offset..offset + KEY_LEN].to_vec();
        let digest = body[offset + KEY_LEN..offset + 2 * KEY_LEN].to_vec();
        let bandwidth_end = offset + 2 * KEY_LEN + 8;
        let bandwidth = u64::from_be_bytes(body[offset + 2 * KEY_LEN..bandwidth_end].try_into().unwrap());
        let subnet_raw: [u8; 5] = body[bandwidth_end..offset + ENTRY_LEN].try_into().unwrap();
        let observed_subnet = decode_subnet(&subnet_raw);
        offset += ENTRY_LEN;
        entries.push((identity, digest, bandwidth, observed_subnet));
    }
    Ok(Vote { authority, valid_after, valid_until, entries })
}

/// A strict majority of the configured authorities.
pub fn default_quorum(authority_count: usize) -> usize {
    (authority_count / 2 + 1).max(1)
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
fn median(mut values: Vec<u64>) -> u64 {
    values.sort_unstable();
    let n = values.len();
    if n % 2 == 1 {
        values[n / 2]
    } else {
        values[n / 2 - 1]
    }
}

/// Combine verified votes and fetched descriptors into
/// `(descriptors, measured_bandwidth)`.
///
/// Only one vote per authority identity counts (the first seen). A relay
/// is returned if at least `quorum` authorities list its identity *and*
/// one of `descriptors` for it has a digest some vote named (the newest
/// such descriptor, by `not_before`, wins). For relays that at least
/// `quorum` authorities *measured* (nonzero bandwidth), the median
/// measurement is returned.
///
/// # Errors
/// Returns [`ConsensusError`] if fewer than `quorum` distinct valid votes
/// are given, or a descriptor fails to encode.
pub fn compute_consensus(
    votes: &[Vote],
    quorum: usize,
    descriptors: &[RelayDescriptor],
) -> Result<(Vec<RelayDescriptor>, MeasuredBandwidth, std::collections::HashMap<Vec<u8>, IpAddr>), ConsensusError> {
    use std::collections::{HashMap, HashSet};

    let mut distinct: HashMap<Vec<u8>, &Vote> = HashMap::new();
    for vote in votes {
        distinct.entry(vote.authority.clone()).or_insert(vote);
    }
    if distinct.len() < quorum {
        return Err(err(format!(
            "only {} valid authority vote(s), need {quorum} for a quorum",
            distinct.len()
        )));
    }

    let mut voters: HashMap<Vec<u8>, HashSet<Vec<u8>>> = HashMap::new();
    let mut digests: HashMap<Vec<u8>, HashSet<Vec<u8>>> = HashMap::new();
    let mut measurements: HashMap<Vec<u8>, Vec<u64>> = HashMap::new();
    let mut subnet_votes: HashMap<Vec<u8>, HashMap<IpAddr, HashSet<Vec<u8>>>> = HashMap::new();

    for vote in distinct.values() {
        let mut seen_here: HashSet<Vec<u8>> = HashSet::new();
        for (identity, digest, bandwidth, observed_subnet) in &vote.entries {
            if seen_here.contains(identity) {
                continue; // one listing per relay per authority
            }
            seen_here.insert(identity.clone());
            voters.entry(identity.clone()).or_default().insert(vote.authority.clone());
            digests.entry(identity.clone()).or_default().insert(digest.clone());
            if *bandwidth != 0 {
                measurements.entry(identity.clone()).or_default().push(*bandwidth);
            }
            if let Some(subnet) = observed_subnet {
                subnet_votes.entry(identity.clone()).or_default().entry(*subnet).or_default().insert(vote.authority.clone());
            }
        }
    }

    let agreed: HashSet<Vec<u8>> = voters.iter().filter(|(_, who)| who.len() >= quorum).map(|(i, _)| i.clone()).collect();

    let mut chosen: HashMap<Vec<u8>, RelayDescriptor> = HashMap::new();
    for descriptor in descriptors {
        let identity = descriptor.identity_public.clone();
        if !agreed.contains(&identity) {
            continue;
        }
        let digest = descriptor_digest(descriptor)?.to_vec();
        let Some(known_digests) = digests.get(&identity) else { continue };
        if !known_digests.contains(&digest) {
            continue;
        }
        match chosen.get(&identity) {
            Some(current) if descriptor.not_before <= current.not_before => {}
            _ => {
                chosen.insert(identity, descriptor.clone());
            }
        }
    }

    let measured: HashMap<Vec<u8>, u64> = measurements
        .into_iter()
        .filter(|(identity, values)| values.len() >= quorum && agreed.contains(identity))
        .map(|(identity, values)| (identity, median(values)))
        .collect();

    // Byzantine-tolerant the same way `measured` is: a relay's identity
    // only gets a verified subnet when at least `quorum` distinct
    // authorities' votes agree on the *same* observed subnet for it, so a
    // single colluding or mistaken authority can never inject a false
    // verified subnet on its own. At most one subnet value can reach
    // `quorum` distinct authorities (quorum is a strict majority), so the
    // first one found meeting it is the only one that ever will.
    let verified_subnet: HashMap<Vec<u8>, IpAddr> = subnet_votes
        .into_iter()
        .filter(|(identity, _)| agreed.contains(identity))
        .filter_map(|(identity, by_subnet)| {
            by_subnet.into_iter().find(|(_, who)| who.len() >= quorum).map(|(subnet, _)| (identity, subnet))
        })
        .collect();

    let mut result: Vec<RelayDescriptor> = chosen.into_values().collect();
    result.sort_by_key(|d| d.endpoint());
    Ok((result, measured, verified_subnet))
}

/// Identities a quorum agrees on but for which `descriptors` has no
/// vote-matching descriptor yet -- i.e. whether another FETCH is needed.
///
/// # Errors
/// Propagates whatever [`compute_consensus`] returns.
pub fn missing_identities(
    votes: &[Vote],
    quorum: usize,
    descriptors: &[RelayDescriptor],
) -> Result<std::collections::HashSet<Vec<u8>>, ConsensusError> {
    use std::collections::{HashMap, HashSet};

    let (have, _, _) = compute_consensus(votes, quorum, descriptors)?;
    let got: HashSet<Vec<u8>> = have.iter().map(|d| d.identity_public.clone()).collect();

    let mut distinct: HashMap<Vec<u8>, &Vote> = HashMap::new();
    for vote in votes {
        distinct.entry(vote.authority.clone()).or_insert(vote);
    }
    let mut counts: HashMap<Vec<u8>, HashSet<Vec<u8>>> = HashMap::new();
    for vote in distinct.values() {
        for (identity, _digest, _bw, _subnet) in &vote.entries {
            counts.entry(identity.clone()).or_default().insert(vote.authority.clone());
        }
    }
    Ok(counts.into_iter().filter(|(identity, who)| who.len() >= quorum && !got.contains(identity)).map(|(i, _)| i).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::CreateOptions;

    fn make_descriptor(identity_private: &[u8; 32], not_before: f64, host: &str) -> RelayDescriptor {
        RelayDescriptor::create(
            identity_private,
            vec![9u8; 32],
            host,
            9001,
            vec!["guard".to_string()],
            3600.0,
            Some(not_before),
            CreateOptions::default(),
        )
        .unwrap()
    }

    fn authority_keys(n: u8) -> Vec<[u8; 32]> {
        (0..n).map(|i| [i.wrapping_add(1); 32]).collect()
    }

    fn authority_pubkey(private: &[u8; 32]) -> Vec<u8> {
        SigningKey::from_bytes(private).verifying_key().to_bytes().to_vec()
    }

    #[test]
    fn vote_request_round_trip() {
        let wire = encode_vote_request();
        assert!(decode_vote_request(&wire).is_ok());
        assert!(decode_vote_request(b"garbage").is_err());
    }

    #[test]
    fn vote_round_trip_and_signature_checks() {
        let auth_priv = [1u8; 32];
        let d = make_descriptor(&[2u8; 32], 1000.0, "198.51.100.1");
        let wire = encode_vote(&auth_priv, &[(d.clone(), 5000, Some(IpAddr::V4(Ipv4Addr::new(198, 51, 0, 0))))], Some(1000.0), DEFAULT_VOTE_LIFETIME).unwrap();

        let pubkey = authority_pubkey(&auth_priv);
        let vote = decode_vote(&wire, Trust::Only(std::slice::from_ref(&pubkey)), Some(1050.0)).unwrap();
        assert_eq!(vote.authority, pubkey);
        assert_eq!(vote.entries.len(), 1);
        assert_eq!(vote.entries[0].0, d.identity_public);
        assert_eq!(vote.entries[0].2, 5000);
        assert_eq!(vote.entries[0].3, Some(IpAddr::V4(Ipv4Addr::new(198, 51, 0, 0))));

        // AllowAny accepts any signer, including an untrusted one.
        let vote2 = decode_vote(&wire, Trust::AllowAny, Some(1050.0)).unwrap();
        assert_eq!(vote2, vote);

        // Untrusted signer is rejected under Only.
        let other_pubkey = authority_pubkey(&[3u8; 32]);
        let err = decode_vote(&wire, Trust::Only(std::slice::from_ref(&other_pubkey)), Some(1050.0)).unwrap_err();
        assert!(err.0.contains("does not trust"));

        // Tampered body fails signature verification.
        let mut tampered = wire.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        let err2 = decode_vote(&tampered, Trust::AllowAny, Some(1050.0)).unwrap_err();
        assert!(err2.0.contains("signature"));
    }

    #[test]
    fn vote_outside_validity_window_is_rejected() {
        let auth_priv = [4u8; 32];
        let d = make_descriptor(&[5u8; 32], 1000.0, "198.51.100.2");
        let wire = encode_vote(&auth_priv, &[(d, 0, None)], Some(1000.0), 60.0).unwrap();
        // Far past valid_until + skew.
        let err = decode_vote(&wire, Trust::AllowAny, Some(1000.0 + 60.0 + MAX_VOTE_CLOCK_SKEW + 1.0)).unwrap_err();
        assert!(err.0.contains("validity window"));
    }

    #[test]
    fn default_quorum_is_strict_majority() {
        assert_eq!(default_quorum(0), 1);
        assert_eq!(default_quorum(1), 1);
        assert_eq!(default_quorum(2), 2);
        assert_eq!(default_quorum(3), 2);
        assert_eq!(default_quorum(4), 3);
        assert_eq!(default_quorum(5), 3);
    }

    #[test]
    fn compute_consensus_requires_quorum_of_votes() {
        let err = compute_consensus(&[], 1, &[]).unwrap_err();
        assert!(err.0.contains("need 1"));
    }

    #[test]
    fn compute_consensus_picks_relay_only_with_quorum_agreement() {
        let identity_priv = [6u8; 32];
        let d = make_descriptor(&identity_priv, 1000.0, "198.51.100.3");
        let digest = descriptor_digest(&d).unwrap().to_vec();

        let other_priv = [66u8; 32];
        let other = make_descriptor(&other_priv, 1000.0, "198.51.100.30");
        let other_digest = descriptor_digest(&other).unwrap().to_vec();

        let auth_privs = authority_keys(3);
        let auth_pubkeys: Vec<Vec<u8>> = auth_privs.iter().map(authority_pubkey).collect();

        // 3 distinct authority votes clear the overall quorum of 2, but
        // only 1 of them lists `d` -- not enough per-relay agreement for
        // `d` to be included, even though `other` (listed by 2) is.
        let votes = vec![
            Vote {
                authority: auth_pubkeys[0].clone(),
                valid_after: 1000.0,
                valid_until: 2000.0,
                entries: vec![(d.identity_public.clone(), digest.clone(), 1000, None)],
            },
            Vote {
                authority: auth_pubkeys[1].clone(),
                valid_after: 1000.0,
                valid_until: 2000.0,
                entries: vec![(other.identity_public.clone(), other_digest.clone(), 1000, None)],
            },
            Vote {
                authority: auth_pubkeys[2].clone(),
                valid_after: 1000.0,
                valid_until: 2000.0,
                entries: vec![(other.identity_public.clone(), other_digest.clone(), 1000, None)],
            },
        ];
        let (result, measured, _verified_subnet) = compute_consensus(&votes, 2, &[d.clone(), other.clone()]).unwrap();
        assert_eq!(result, vec![other.clone()]);
        assert!(!measured.contains_key(&d.identity_public));
        assert_eq!(measured.get(&other.identity_public), Some(&1000));

        // Now have 2 of 3 authorities vote for `d` too -- it clears quorum 2.
        let votes2 = vec![
            Vote {
                authority: auth_pubkeys[0].clone(),
                valid_after: 1000.0,
                valid_until: 2000.0,
                entries: vec![(d.identity_public.clone(), digest.clone(), 1000, None)],
            },
            Vote {
                authority: auth_pubkeys[1].clone(),
                valid_after: 1000.0,
                valid_until: 2000.0,
                entries: vec![(d.identity_public.clone(), digest, 1000, None)],
            },
        ];
        let (result2, measured2, _verified_subnet2) = compute_consensus(&votes2, 2, std::slice::from_ref(&d)).unwrap();
        assert_eq!(result2.len(), 1);
        assert_eq!(result2[0], d);
        assert_eq!(measured2.get(&d.identity_public), Some(&1000));
    }

    /// Security fix: `verified_subnet` must be Byzantine-tolerant the same
    /// way `measured_bandwidth` already is -- a single lying (or merely
    /// mistaken) authority must never be able to inject a false verified
    /// subnet for a relay on its own. Two of three authorities agree the
    /// relay actually publishes from `198.51.0.0/16`; the third claims a
    /// different subnet entirely.
    #[test]
    fn compute_consensus_verified_subnet_needs_quorum_agreement() {
        let identity_priv = [11u8; 32];
        let d = make_descriptor(&identity_priv, 1000.0, "relay.example");
        let digest = descriptor_digest(&d).unwrap().to_vec();
        let auth_pubkeys: Vec<Vec<u8>> = authority_keys(3).iter().map(authority_pubkey).collect();
        let real_subnet = IpAddr::V4(Ipv4Addr::new(198, 51, 0, 0));
        let fake_subnet = IpAddr::V4(Ipv4Addr::new(66, 6, 0, 0));
        let entry_with = |subnet: IpAddr| (d.identity_public.clone(), digest.clone(), 0u64, Some(subnet));
        let votes = vec![
            Vote { authority: auth_pubkeys[0].clone(), valid_after: 1000.0, valid_until: 2000.0, entries: vec![entry_with(real_subnet)] },
            Vote { authority: auth_pubkeys[1].clone(), valid_after: 1000.0, valid_until: 2000.0, entries: vec![entry_with(real_subnet)] },
            Vote { authority: auth_pubkeys[2].clone(), valid_after: 1000.0, valid_until: 2000.0, entries: vec![entry_with(fake_subnet)] },
        ];
        let (_result, _measured, verified_subnet) = compute_consensus(&votes, 2, std::slice::from_ref(&d)).unwrap();
        assert_eq!(verified_subnet.get(&d.identity_public), Some(&real_subnet), "quorum (2 of 3) must win, not the lone dissenting authority");
    }

    /// No single subnet claim reaching quorum must leave the relay with no
    /// verified subnet at all, rather than picking one arbitrarily -- the
    /// caller then falls back to the self-declared host.
    #[test]
    fn compute_consensus_verified_subnet_absent_without_any_quorum() {
        let identity_priv = [12u8; 32];
        let d = make_descriptor(&identity_priv, 1000.0, "relay.example");
        let digest = descriptor_digest(&d).unwrap().to_vec();
        let auth_pubkeys: Vec<Vec<u8>> = authority_keys(2).iter().map(authority_pubkey).collect();
        let entry_with = |subnet: IpAddr| (d.identity_public.clone(), digest.clone(), 0u64, Some(subnet));
        let votes = vec![
            Vote {
                authority: auth_pubkeys[0].clone(),
                valid_after: 1000.0,
                valid_until: 2000.0,
                entries: vec![entry_with(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)))],
            },
            Vote {
                authority: auth_pubkeys[1].clone(),
                valid_after: 1000.0,
                valid_until: 2000.0,
                entries: vec![entry_with(IpAddr::V4(Ipv4Addr::new(20, 0, 0, 0)))],
            },
        ];
        let (_result, _measured, verified_subnet) = compute_consensus(&votes, 2, std::slice::from_ref(&d)).unwrap();
        assert_eq!(verified_subnet.get(&d.identity_public), None);
    }

    #[test]
    fn compute_consensus_picks_newest_matching_descriptor() {
        let identity_priv = [7u8; 32];
        let older = make_descriptor(&identity_priv, 1000.0, "198.51.100.4");
        let newer = make_descriptor(&identity_priv, 2000.0, "198.51.100.5");
        let older_digest = descriptor_digest(&older).unwrap().to_vec();
        let newer_digest = descriptor_digest(&newer).unwrap().to_vec();

        let auth_pubkeys: Vec<Vec<u8>> = authority_keys(2).iter().map(authority_pubkey).collect();
        let votes = vec![
            Vote {
                authority: auth_pubkeys[0].clone(),
                valid_after: 1000.0,
                valid_until: 3000.0,
                entries: vec![(older.identity_public.clone(), newer_digest.clone(), 0, None)],
            },
            Vote {
                authority: auth_pubkeys[1].clone(),
                valid_after: 1000.0,
                valid_until: 3000.0,
                entries: vec![(older.identity_public.clone(), newer_digest.clone(), 0, None)],
            },
        ];
        // Both descriptors are supplied; only `newer`'s digest was voted for.
        let (result, _measured, _verified_subnet) = compute_consensus(&votes, 2, &[older, newer.clone()]).unwrap();
        assert_eq!(result, vec![newer]);
        let _ = older_digest; // silence unused warning if reordered
    }

    #[test]
    fn compute_consensus_ignores_duplicate_votes_from_same_authority() {
        let identity_priv = [8u8; 32];
        let d = make_descriptor(&identity_priv, 1000.0, "198.51.100.6");
        let digest = descriptor_digest(&d).unwrap().to_vec();
        let pubkey = authority_pubkey(&[9u8; 32]);
        // Two "votes" from the same authority identity: only the first counts.
        let votes = vec![
            Vote {
                authority: pubkey.clone(),
                valid_after: 1000.0,
                valid_until: 2000.0,
                entries: vec![(d.identity_public.clone(), digest.clone(), 500, None)],
            },
            Vote {
                authority: pubkey.clone(),
                valid_after: 1000.0,
                valid_until: 2000.0,
                entries: vec![(d.identity_public.clone(), digest.clone(), 999, None)],
            },
        ];
        // quorum 2 can never be reached with one distinct authority.
        let err = compute_consensus(&votes, 2, &[d]).unwrap_err();
        assert!(err.0.contains("only 1"));
    }

    #[test]
    fn missing_identities_reports_voted_but_undescribed_relays() {
        let identity_priv = [10u8; 32];
        let d = make_descriptor(&identity_priv, 1000.0, "198.51.100.10");
        let digest = descriptor_digest(&d).unwrap().to_vec();
        let auth_pubkeys: Vec<Vec<u8>> = authority_keys(2).iter().map(authority_pubkey).collect();
        let votes = vec![
            Vote {
                authority: auth_pubkeys[0].clone(),
                valid_after: 1000.0,
                valid_until: 2000.0,
                entries: vec![(d.identity_public.clone(), digest.clone(), 0, None)],
            },
            Vote {
                authority: auth_pubkeys[1].clone(),
                valid_after: 1000.0,
                valid_until: 2000.0,
                entries: vec![(d.identity_public.clone(), digest, 0, None)],
            },
        ];
        // No descriptors supplied -- the identity is agreed on but missing.
        let missing = missing_identities(&votes, 2, &[]).unwrap();
        assert!(missing.contains(&d.identity_public));

        // Once supplied, it is no longer missing.
        let missing2 = missing_identities(&votes, 2, &[d]).unwrap();
        assert!(missing2.is_empty());
    }

    #[test]
    fn median_odd_counts_pick_the_true_middle_value() {
        assert_eq!(median(vec![5]), 5);
        assert_eq!(median(vec![1, 2, 4]), 2);
        assert_eq!(median(vec![10, 20, 30, 40, 50]), 30);
    }

    /// Security fix: an even count must pick the *lower* of the two middle
    /// values, not their average -- averaging (the old, Python-matching
    /// behavior) let one lying authority pull the result arbitrarily far
    /// from the honest report at the realistic 2-measurement count, and
    /// could overflow `u64` outright.
    #[test]
    fn median_even_counts_pick_the_lower_middle_value_not_the_average() {
        assert_eq!(median(vec![1, 3]), 1);
        assert_eq!(median(vec![1, 2, 3, 4]), 2);
        assert_eq!(median(vec![1000, u64::MAX]), 1000, "a lying authority must not be able to inflate the measured bandwidth beyond the honest report");
    }
}
