//! Hidden services, client side: `.allium` descriptor lookup, the
//! introduction+rendezvous handshake, and `--fetch-onion`. Port of the
//! matching section of `allium_cli.py` (`fetch_hs_descriptor`,
//! `_resolve_entry_hops` [see `crate::dirclient`], `_pick_rendezvous_relay`,
//! `HiddenServiceConnection`, `connect_hidden_service`,
//! `_http_response_complete`, `run_fetch_onion`).
//!
//! See `allium::hiddenservice`'s module doc for the three-step
//! introduction/rendezvous/session protocol this drives; nothing about
//! that protocol changes in this port, only (as in every other command
//! module) `asyncio`/coroutines become direct blocking calls.

use std::collections::HashSet;
use std::io;
use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use x25519_dalek::{PublicKey, StaticSecret};

use allium::circuit::{Addr, CircuitBuilder, EncryptOptions};
use allium::directory::{Directory, RelayDescriptor, ROLE_EXIT};
use allium::dirwire::{decode_hs3_fetch_reply, encode_hs3_fetch_request};
use allium::hsblind::{blind_public_key, open_descriptor, periods_to_try};
use allium::hiddenservice::{
    decode_address, decode_rendezvous_handshake, derive_session_keys, load_or_create_client_auth_key,
    rendezvous_auth_key, seal_introduce_with_secret, verify_rendezvous_mac, HiddenServiceDescriptor, HiddenServiceError, HsFrame,
    HsSession, IntroPoint,
};
use allium::hswire::{
    decode_introduce_ack, decode_rendezvous_data, decode_rendezvous_joined, encode_introduce1, encode_rendezvous_data,
    encode_rendezvous_join, encode_rendezvous_request, fragment_message, HsReassembler,
};
use allium::osrand;
use allium::socksproxy::HiddenServiceConnection;

use crate::args::Args;
use crate::cli_error::CliExit;
use crate::dirclient::{
    build_generic_circuit, build_generic_circuit_owned, cached_relay_directory, dir_round_trip_over_circuit, refresh_relay_directory,
    resolve_entry_hops,
};
use crate::helpers::{hex_encode, primary_authority, say, split_trust_keys};
use crate::owned_circuit::OwnedCircuit;

fn now_unix() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// An index into a slice of length `n`, unpredictable in the same sense a
/// key is (not merely "unlikely to repeat") -- see the Python original's
/// comments on `secrets.SystemRandom` vs. the plain `random` module for why
/// an anonymity-relevant pick (which relay becomes a rendezvous point)
/// needs a CSPRNG. A small modulo bias against `u64::MAX` is an accepted,
/// negligible simplification here rather than pulling in rejection
/// sampling for a CLI-only relay pick.
fn secure_index(n: usize) -> usize {
    debug_assert!(n > 0);
    let bytes = osrand::bytes(8);
    let v = u64::from_le_bytes(bytes.try_into().expect("osrand::bytes(8) is always 8 bytes"));
    (v % n as u64) as usize
}

fn authority_trusted_keys(args: &Args) -> Option<Vec<[u8; 32]>> {
    let value = args.trust_authority.as_deref()?;
    if value.is_empty() {
        return None;
    }
    let keys: Vec<[u8; 32]> = split_trust_keys(value)
        .into_iter()
        .filter_map(|hex| crate::helpers::hex_decode(&hex).ok())
        .filter_map(|v| v.try_into().ok())
        .collect();
    if keys.is_empty() {
        None
    } else {
        Some(keys)
    }
}

fn hs_send_on_builder(builder: &mut CircuitBuilder<'_>, final_addr: Addr, message: &[u8]) -> io::Result<()> {
    for wire_bytes in fragment_message(message, allium::fragment::DEFAULT_MTU) {
        builder.send(&wire_bytes, final_addr.clone(), EncryptOptions::default()).map_err(|e| io::Error::other(e.to_string()))?;
    }
    Ok(())
}

pub(crate) fn hs_send_over_builder(circuit: &OwnedCircuit, message: &[u8]) -> io::Result<()> {
    let final_addr = {
        let b = circuit.lock();
        b.addrs.last().cloned().expect("a live hidden-service circuit always has at least one hop")
    };
    let mut b = circuit.lock();
    hs_send_on_builder(&mut b, final_addr, message)
}

/// Block until one complete hidden-service message arrives on `builder`,
/// using a caller-supplied, persistent [`HsReassembler`] -- unlike a
/// directory round trip's one-shot reassembler, an intro or rendezvous
/// circuit is not thrown away after one reply.
///
/// Note this deliberately does *not* swallow a decode error from
/// `reassembler.push` (unlike the socket-level "nothing arrived yet"
/// timeout, which is retried): a malformed message is not transient, and
/// the Python original lets exactly this one propagate uncaught too.
fn hs_receive_message_on_builder(builder: &CircuitBuilder<'_>, reassembler: &mut HsReassembler, timeout: f64) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs_f64((timeout * 4.0).max(10.0));
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "no reply within timeout"));
        }
        let raw = match builder.receive(Some(Duration::from_secs_f64(timeout))) {
            Ok(raw) => raw,
            Err(_) => continue,
        };
        match reassembler.push(&raw) {
            Ok(Some(message)) => return Ok(message),
            Ok(None) => continue,
            Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
        }
    }
}

pub(crate) fn hs_receive_message(circuit: &OwnedCircuit, reassembler: &mut HsReassembler, timeout: f64) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs_f64((timeout * 4.0).max(10.0));
    // Matches `CircuitTransport::receive`'s shape (see `transport.rs`'s doc
    // there for the full write-up): the old version of this function took
    // `circuit.lock()` and then blocked *inside* that lock for up to
    // `timeout` per iteration, retrying immediately on every timeout for as
    // long as the caller kept pumping (exactly `serve_rendezvous`'s
    // `to_local` thread, which calls this back-to-back for the life of a
    // hidden-service rendezvous tunnel). `std::sync::Mutex` is not
    // FIFO-fair, so a concurrent sender on the same `OwnedCircuit` (here,
    // `to_session`'s `hs_send_over_builder`, carrying the local server's
    // response back through the circuit) could lose the race for the lock
    // indefinitely -- a real, reproducible hang, not just added latency.
    // The fix is the same one already applied there: wait for the socket to
    // become readable via a raw `poll(2)` (`wait_readable`) *without*
    // holding the lock, and only take it once for a short, already-likely-
    // ready `receive` call.
    const READ_SLICE: Duration = Duration::from_millis(250);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "no reply within timeout"));
        }
        if !crate::transport::wait_readable(circuit.raw_fd(), remaining)? {
            continue; // plain timeout on this wait -- recheck the overall deadline
        }
        let raw = {
            let b = circuit.lock();
            b.receive(Some(READ_SLICE))
        };
        let raw = match raw {
            Ok(raw) => raw,
            Err(_) => continue,
        };
        match reassembler.push(&raw) {
            Ok(Some(message)) => return Ok(message),
            Ok(None) => continue,
            Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
        }
    }
}

/// Fetch, verify, and return a live descriptor for `address_text` (an
/// `x.allium` address) from `args.authority`. Verification happens
/// locally -- the authority is trusted for availability only, never for
/// integrity.
/// What one directory lookup for one period told the client.
#[derive(Debug, PartialEq)]
enum Lookup {
    /// A verified, decrypted descriptor for the address.
    Found(HiddenServiceDescriptor),
    /// The directory holds nothing for that period's blinded key.
    NotFound,
    /// It held a descriptor but its validity window has passed (try the next
    /// period: a stale copy is what a clock skew near a period boundary looks like).
    Expired,
}

/// The blinded keys to ask the directory for, in order, with their periods:
/// the current period first (the normal case, so most lookups reveal a single
/// key), then the next and the previous (a clock that runs a little ahead of or
/// behind the service's).
fn lookup_plan(identity_public: &[u8; 32], now: f64) -> Result<Vec<(i64, [u8; 32])>, String> {
    periods_to_try(now).into_iter().map(|period| blind_public_key(identity_public, period).map(|key| (period, key)).map_err(|e| e.to_string())).collect()
}

/// Interpret the directory's reply to a version 3 fetch for `period`. The
/// reply is untrusted: it is accepted only if it is addressed to the blinded
/// key this client derived from the address, is signed by it, decrypts under
/// the key derived from the address, and its inner descriptor is signed by the
/// identity and names it.
///
/// # Errors
/// A malformed reply, or one that fails any of those checks. An *expired*
/// descriptor is not an error, see [`Lookup::Expired`].
fn interpret_fetch_reply(reply: &[u8], identity_public: &[u8; 32], period: i64, now: f64) -> Result<Lookup, String> {
    let outer = decode_hs3_fetch_reply(reply).map_err(|e| format!("directory authority sent a malformed hs3 fetch reply: {e}"))?;
    let Some(outer) = outer else { return Ok(Lookup::NotFound) };
    match open_descriptor(&outer, identity_public, period, now) {
        Ok(inner) => Ok(Lookup::Found(inner)),
        Err(HiddenServiceError::DescriptorExpired(_)) => Ok(Lookup::Expired),
        Err(e) => Err(format!("the descriptor failed verification: {e}")),
    }
}

pub fn fetch_hs_descriptor(args: &mut Args, address_text: &str) -> Result<HiddenServiceDescriptor, CliExit> {
    if args.authority.is_none() {
        return Err(CliExit::error(
            "client: reaching a .allium address requires --authority (or client.authority in --config) to look up its descriptor",
        ));
    }
    let identity_public =
        decode_address(address_text).map_err(|e| CliExit::error(format!("client: bad hidden-service address {address_text:?}: {e}")))?;
    let identity: [u8; 32] = identity_public.as_slice().try_into().map_err(|_| CliExit::error("client: address does not hold a 32-byte identity key"))?;

    let authority_trusted = authority_trusted_keys(args);
    let authority = primary_authority(args).unwrap_or_default();
    let now = now_unix();
    let mut found: Option<HiddenServiceDescriptor> = None;
    for (period, blinded_key) in lookup_plan(&identity, now).map_err(|e| CliExit::error(format!("client: {e}")))? {
        // One circuit per lookup: the directory sees only a blinded key for one
        // period, and separate lookups do not share a circuit.
        let reply_bytes = dir_round_trip_over_circuit(args, &authority, authority_trusted.clone(), &encode_hs3_fetch_request(&blinded_key), "client")
            .map_err(|e| CliExit::error(format!("client: {e}")))?;
        match interpret_fetch_reply(&reply_bytes, &identity, period, now).map_err(|e| CliExit::error(format!("client: {address_text}: {e}")))? {
            Lookup::Found(descriptor) => {
                found = Some(descriptor);
                break;
            }
            Lookup::NotFound | Lookup::Expired => continue,
        }
    }
    let mut descriptor =
        found.ok_or_else(|| CliExit::error(format!("client: the directory authority has no live descriptor for {address_text}")))?;

    if !descriptor.client_auth.is_empty() {
        let key_file = args.client_auth_key_file.clone();
        let Some(key_file) = key_file.filter(|s| !s.is_empty()) else {
            return Err(CliExit::error(format!(
                "client: {address_text} requires client authorization -- pass --client-auth-key-file PATH \
                 (the same key you registered with the service operator; see 'client --print-client-auth-key')"
            )));
        };
        let client_private_key =
            load_or_create_client_auth_key(std::path::Path::new(&key_file)).map_err(|e| CliExit::error(format!("client: {e}")))?;
        let decrypted =
            descriptor.intro_points_for(Some(&client_private_key)).map_err(|e| CliExit::error(format!("client: {e}")))?;
        descriptor.intro_points = decrypted;
    }

    if descriptor.intro_points.is_empty() {
        return Err(CliExit::error(format!("client: {address_text} published no introduction points")));
    }
    say(&format!("client: fetched a verified descriptor for {address_text} ({} introduction point(s))", descriptor.intro_points.len()));
    Ok(descriptor)
}

/// Pick a live exit-capable relay to act as rendezvous point. Any exit can
/// serve this role. Excludes the relays already used for this connection's
/// other circuits where possible, falling back to the full set if that
/// leaves nothing to choose from.
/// Choose one of a descriptor's introduction points, trusting only what this
/// client's own verified directory vouches for.
///
/// A descriptor is written by the service, so its `host`, `port` and
/// `relay_identity` are whatever the service says. Dialing them as given
/// would let a malicious service point every visitor at a node of its
/// choosing, outside the directory, and pin that node's identity from the
/// same descriptor -- the node would then learn the IP of the middle relay
/// each visitor's circuit extends from (a stepping stone to finding the
/// visitor's guard).
///
/// So each intro point is kept only if its `relay_identity` is a live relay
/// in `directory` that an honest service could have chosen -- an exit-capable
/// relay not behind NAT, exactly the rule the service itself applies when it
/// picks introduction points (and when it validates a rendezvous point) --
/// and the address returned is the *directory's*, never the descriptor's.
/// `auth_public` is the one field only the service can supply, so it is kept.
///
/// Returns `None` if no intro point qualifies.
fn pick_intro_point(directory: &Directory, intro_points: &[IntroPoint]) -> Option<(IntroPoint, RelayDescriptor)> {
    let mut eligible: Vec<(IntroPoint, RelayDescriptor)> = intro_points
        .iter()
        .filter_map(|ip| {
            let relay = directory.get(&ip.relay_identity)?;
            if !relay.roles.iter().any(|r| r == ROLE_EXIT) || relay.behind_nat() {
                return None;
            }
            let vouched = IntroPoint {
                relay_identity: relay.identity_public.clone(),
                host: relay.host.clone(),
                port: relay.port,
                auth_public: ip.auth_public.clone(),
            };
            Some((vouched, relay.clone()))
        })
        .collect();
    if eligible.is_empty() {
        return None;
    }
    // Which introduction point a client picks is exactly as anonymity-
    // relevant as guard/middle/exit selection, so it gets the same CSPRNG
    // pick as `pick_rendezvous_relay`.
    let idx = secure_index(eligible.len());
    Some(eligible.swap_remove(idx))
}

fn pick_rendezvous_relay(args: &mut Args, exclude_identities: &HashSet<Vec<u8>>) -> Result<RelayDescriptor, CliExit> {
    // Was `fetch_relay_directory`, a fresh authority round trip from the
    // client's real IP on every hidden-service connection.
    // Use the shared, periodically-refreshed cache instead (see its doc
    // comment in `dirclient.rs`).
    let directory = cached_relay_directory(args, "client")?;
    let reachable: Vec<RelayDescriptor> = directory.by_role(ROLE_EXIT).into_iter().filter(|d| !d.behind_nat()).collect();
    let mut candidates: Vec<RelayDescriptor> = reachable.iter().filter(|d| !exclude_identities.contains(&d.identity_public)).cloned().collect();
    if candidates.is_empty() {
        candidates = reachable;
    }
    if candidates.is_empty() {
        return Err(CliExit::error("client: no live exit-capable relay available to act as a rendezvous point"));
    }
    let idx = secure_index(candidates.len());
    Ok(candidates.swap_remove(idx))
}

/// A live, end-to-end encrypted tunnel to a hidden service. `send`/
/// `receive` move plaintext bytes (e.g. raw HTTP) -- the rendezvous circuit
/// underneath and the [`HsSession`] sealing/opening every message are both
/// hidden behind this. Port of `allium_cli.py`'s `HiddenServiceConnection`
/// class, renamed to avoid colliding with
/// [`allium::socksproxy::HiddenServiceConnection`] (the trait this
/// implements).
struct HsConnection {
    circuit: OwnedCircuit,
    session: HsSession,
    reassembler: Mutex<HsReassembler>,
}

impl HiddenServiceConnection for HsConnection {
    fn send(&self, data: &[u8]) -> io::Result<()> {
        let sealed = self.session.seal(data).map_err(io::Error::other)?;
        let message = encode_rendezvous_data(&sealed).map_err(io::Error::other)?;
        hs_send_over_builder(&self.circuit, &message)
    }

    fn receive(&self, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
        let mut reassembler = self.reassembler.lock().unwrap();
        match hs_receive_message(&self.circuit, &mut reassembler, timeout.as_secs_f64()) {
            Ok(message) => {
                let sealed = decode_rendezvous_data(&message).map_err(io::Error::other)?;
                match self.session.open_frame(&sealed) {
                    Ok(HsFrame::Data(plaintext)) => Ok(Some(plaintext)),
                    // The service finished cleanly: end the session.
                    Ok(HsFrame::Close) => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the service closed the session")),
                    // A frame was lost or reordered, or data followed a close: the stream
                    // can no longer be trusted, so this is fatal, not a hiccup.
                    Err(HiddenServiceError::SessionGap(m)) | Err(HiddenServiceError::SessionClosed(m)) => {
                        Err(io::Error::new(io::ErrorKind::InvalidData, m))
                    }
                    // A replayed, forged or garbled frame: dropped, nothing delivered; the
                    // session carries on.
                    Err(e) => Err(io::Error::other(e)),
                }
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn close(&self) {
        // Tell the service we are finished, authenticated, so it can tell a
        // clean end from a tunnel that was cut off. Best effort: the circuit
        // may already be gone.
        if let Ok(sealed) = self.session.seal_close() {
            if let Ok(message) = encode_rendezvous_data(&sealed) {
                let _ = hs_send_over_builder(&self.circuit, &message);
            }
        }
        // No explicit socket close: `OwnedCircuit` releases its socket when
        // this connection (and every `Arc` clone of it) is dropped, and
        // every blocking read here already bounds itself to a short
        // timeout (see `hs_receive_message`) rather than ever blocking
        // indefinitely -- so there is no pending call for an eager close to
        // need to interrupt, unlike Python's `self._sock.close()`, whose
        // job is exactly that interruption on a socket with no such bound.
    }
}

/// The introduction-point decision in [`connect_hidden_service`], with the
/// directory refresh passed in so it can be tested without a live authority.
///
/// Tries the cached directory first. Only if no introduction point qualifies
/// there does it call `refresh` -- exactly once -- and try again against what
/// that returns. If nothing qualifies even then, it refuses rather than dial
/// an address the descriptor supplied itself (see [`pick_intro_point`]). A
/// failed refresh is returned as is.
fn choose_intro_point<F>(cached: &Directory, intro_points: &[IntroPoint], refresh: F) -> Result<(IntroPoint, RelayDescriptor), CliExit>
where
    F: FnOnce() -> Result<Arc<Directory>, CliExit>,
{
    if let Some(picked) = pick_intro_point(cached, intro_points) {
        return Ok(picked);
    }
    let refreshed = refresh()?;
    pick_intro_point(&refreshed, intro_points).ok_or_else(|| {
        CliExit::error(
            "client: none of this service's introduction points is a relay this client's directory vouches for \
             (not listed, not exit-capable, or behind NAT); refusing to dial an address the descriptor supplied itself",
        )
    })
}

/// Perform the full introduction+rendezvous handshake for a `.allium`
/// address and return a ready tunnel. Opens two short-lived circuits of
/// its own -- one to an introduction point, one to a rendezvous point --
/// each through this client's own guard/middle, exactly like any other
/// circuit it builds.
pub fn connect_hidden_service(args: &Args, address_text: &str) -> Result<Arc<dyn HiddenServiceConnection>, CliExit> {
    let mut args = args.clone();
    let descriptor = fetch_hs_descriptor(&mut args, address_text)?;
    let (guard_addr, middle_addr, entry_trust) = resolve_entry_hops(&mut args)?;

    let timeout = args.timeout.unwrap_or(5.0);
    let timeout_dur = Duration::from_secs_f64(timeout);
    let retries = args.retries.unwrap_or(0).max(0) as u32;

    // Only introduction points this client's own verified directory vouches
    // for are used, at the directory's address (see `pick_intro_point`). A
    // relay the cached directory has not seen yet gets one forced (rate-
    // limited) refresh before the descriptor is given up on.
    let directory = cached_relay_directory(&args, "client")?;
    let (intro, _intro_relay) = choose_intro_point(&directory, &descriptor.intro_points, || refresh_relay_directory(&args, "client"))?;
    let intro_identity: [u8; 32] =
        intro.relay_identity.as_slice().try_into().map_err(|_| CliExit::error("client: intro point identity is not 32 bytes"))?;
    let mut intro_trust = entry_trust.clone();
    intro_trust.insert("intro".to_string(), vec![intro_identity]);

    let intro_sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| CliExit::error(format!("client: {e}")))?;
    let intro_hops = vec![
        ("guard".to_string(), guard_addr.clone()),
        ("middle".to_string(), middle_addr.clone()),
        ("intro".to_string(), (intro.host.clone(), intro.port)),
    ];
    let mut intro_builder = build_generic_circuit(&intro_sock, &intro_hops, timeout_dur, retries, Some(intro_trust), "client-intro", Some(args.kem_keys.clone()))
        .map_err(|e| CliExit::error(format!("client: {e}")))?;

    let client_ephemeral_seed: [u8; 32] = osrand::bytes(32).try_into().expect("osrand::bytes(32) is always 32 bytes");
    let client_ephemeral = StaticSecret::from(client_ephemeral_seed);
    let client_ephemeral_pub = PublicKey::from(&client_ephemeral).to_bytes();
    let cookie = osrand::bytes(32);

    let rp_descriptor = pick_rendezvous_relay(&mut args, &HashSet::from([intro.relay_identity.clone()]))?;
    let rp_request = encode_rendezvous_request(&rp_descriptor.identity_public, &rp_descriptor.host, rp_descriptor.port, &cookie)
        .map_err(|e| CliExit::error(format!("client: {e}")))?;
    // `intro_secret` is the same `DH(client_ephemeral, descriptor.encryption_public)`
    // the service reproduces from the sealed envelope in
    // `ServiceIdentity::open_introduce` -- the rendezvous handshake is
    // authenticated against it, since it is a value the rendezvous
    // point (unlike the intro point or the service) never sees.
    let (sealed, intro_secret) = seal_introduce_with_secret(&descriptor.encryption_public, &client_ephemeral, &rp_request)
        .map_err(|e| CliExit::error(format!("client: {e}")))?;

    say(&format!("client: sending INTRODUCE1 via {}:{} (rendezvous at {}:{}) ...", intro.host, intro.port, rp_descriptor.host, rp_descriptor.port));
    let introduce1 = encode_introduce1(&intro.auth_public, &client_ephemeral_pub, &sealed).map_err(|e| CliExit::error(format!("client: {e}")))?;
    hs_send_on_builder(&mut intro_builder, (intro.host.clone(), intro.port), &introduce1).map_err(|e| CliExit::error(format!("client: {e}")))?;
    let mut ack_reassembler = HsReassembler::new(64);
    let ack_message = hs_receive_message_on_builder(&intro_builder, &mut ack_reassembler, timeout).map_err(|e| CliExit::error(format!("client: {e}")))?;
    let (ok, msg) = decode_introduce_ack(&ack_message).map_err(|e| CliExit::error(format!("client: bad INTRODUCE_ACK: {e}")))?;
    if !ok {
        return Err(CliExit::error(format!("client: introduction refused: {msg}")));
    }
    say(&format!("client: introduction point forwarded the request ({msg})"));
    drop(intro_builder);
    drop(intro_sock);

    let mut rp_trust = entry_trust;
    let rp_identity: [u8; 32] =
        rp_descriptor.identity_public.as_slice().try_into().map_err(|_| CliExit::error("client: rendezvous identity is not 32 bytes"))?;
    rp_trust.insert("rendezvous".to_string(), vec![rp_identity]);
    let mut kem_keys = args.kem_keys.clone();
    if let Some(pq) = rp_descriptor.pq_kem_public() {
        kem_keys.insert("rendezvous".to_string(), pq.to_vec());
    }
    let rendezvous_sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| CliExit::error(format!("client: {e}")))?;
    let rendezvous_hops = vec![
        ("guard".to_string(), guard_addr),
        ("middle".to_string(), middle_addr),
        ("rendezvous".to_string(), (rp_descriptor.host.clone(), rp_descriptor.port)),
    ];
    let owned = build_generic_circuit_owned(rendezvous_sock, rendezvous_hops, timeout_dur, retries, Some(rp_trust), "client-rendezvous".to_string(), Some(kem_keys))
        .map_err(|e| CliExit::error(format!("client: {e}")))?;

    let mut reassembler = HsReassembler::new(64);
    say(&format!("client: joining rendezvous with cookie {}...", &hex_encode(&cookie)[..12.min(hex_encode(&cookie).len())]));
    hs_send_over_builder(&owned, &encode_rendezvous_join(&cookie).map_err(|e| CliExit::error(format!("client: {e}")))?)
        .map_err(|e| CliExit::error(format!("client: {e}")))?;
    let mut joined_message = hs_receive_message(&owned, &mut reassembler, timeout).map_err(|e| CliExit::error(format!("client: {e}")))?;
    let (mut ok, mut msg) = decode_rendezvous_joined(&joined_message).map_err(|e| CliExit::error(format!("client: {e}")))?;
    if ok && msg.to_lowercase().contains("waiting") {
        say("client: waiting for the service to join the rendezvous ...");
        joined_message = hs_receive_message(&owned, &mut reassembler, 30.0).map_err(|e| CliExit::error(format!("client: {e}")))?;
        (ok, msg) = decode_rendezvous_joined(&joined_message).map_err(|e| CliExit::error(format!("client: {e}")))?;
    }
    if !ok {
        return Err(CliExit::error(format!("client: rendezvous failed: {msg}")));
    }
    say(&format!("client: rendezvous joined ({msg}) -- waiting for the service's session key ..."));

    let handshake_message = hs_receive_message(&owned, &mut reassembler, 30.0).map_err(|e| CliExit::error(format!("client: {e}")))?;
    let handshake_payload = decode_rendezvous_data(&handshake_message).map_err(|e| CliExit::error(format!("client: {e}")))?;
    // Reject the old bare-32-byte-key handshake outright rather than
    // accepting it -- a rendezvous point that never involves the real
    // service can send exactly that, and (before this fix) fully
    // impersonate the service to the client. `decode_rendezvous_handshake`
    // requires the MAC-authenticated v2 shape.
    let (service_ephemeral_pub, received_mac) = decode_rendezvous_handshake(&handshake_payload).map_err(|e| {
        CliExit::error(format!(
            "client: {e} -- refusing to fall back to the unauthenticated handshake (see ALLIUM-H6)"
        ))
    })?;
    let auth_key = rendezvous_auth_key(&intro_secret);
    verify_rendezvous_mac(
        &auth_key,
        &client_ephemeral_pub,
        &service_ephemeral_pub,
        &descriptor.encryption_public,
        &cookie,
        &rp_descriptor.identity_public,
        &received_mac,
    )
    .map_err(|e| CliExit::error(format!("client: {e}")))?;
    let shared = client_ephemeral.diffie_hellman(&PublicKey::from(service_ephemeral_pub));
    if !shared.was_contributory() {
        return Err(CliExit::error(
            "client: service ephemeral key is a low-order point; refusing to establish a session".to_string(),
        ));
    }
    let (key_c2s, key_s2c) = derive_session_keys(&shared.to_bytes(), &intro_secret);
    let session = HsSession::new(&key_c2s, &key_s2c, &cookie, false).map_err(|e| CliExit::error(format!("client: {e}")))?;
    say("client: session established -- end-to-end encrypted with the service, authenticated, and opaque even to the rendezvous point\n");

    Ok(Arc::new(HsConnection { circuit: owned, session, reassembler: Mutex::new(reassembler) }))
}

/// Whether an HTTP/1.1 response buffer looks fully received: a real web
/// server sets its own `Content-Length`, so a one-shot fetch can stop the
/// instant that many body bytes have arrived rather than waiting out an
/// idle timeout on every request. Falls back to `false` (keep reading) if
/// a response is missing the header.
fn http_response_complete(buf: &[u8]) -> bool {
    let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let body = &buf[header_end + 4..];
    let header_text = String::from_utf8_lossy(&buf[..header_end]);
    for line in header_text.split("\r\n").skip(1) {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case("content-length") {
                return match value.trim().parse::<usize>() {
                    Ok(expected) => body.len() >= expected,
                    Err(_) => false,
                };
            }
        }
    }
    false
}

/// `client --fetch-onion ADDRESS`: one HTTP GET through the full
/// introduction+rendezvous path, printing the response.
pub fn run_fetch_onion(args: &mut Args, address_text: &str) -> Result<i32, CliExit> {
    let connection = connect_hidden_service(args, address_text)?;
    let result = run_fetch_onion_body(&connection, args, address_text);
    connection.close();
    result
}

fn run_fetch_onion_body(connection: &Arc<dyn HiddenServiceConnection>, args: &Args, address_text: &str) -> Result<i32, CliExit> {
    let path = args.fetch_onion_path.clone().unwrap_or_else(|| "/".to_string());
    let request = format!("GET {path} HTTP/1.1\r\nHost: {address_text}\r\nConnection: close\r\n\r\n").into_bytes();
    connection.send(&request).map_err(|e| CliExit::error(format!("client: {e}")))?;
    say("client: request sent, waiting for the response ...");

    let mut response: Vec<u8> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs_f64((args.timeout.unwrap_or(5.0) * 4.0).max(15.0));
    while Instant::now() < deadline {
        match connection.receive(Duration::from_secs_f64(2.0)) {
            Ok(Some(chunk)) => {
                if chunk.is_empty() {
                    break;
                }
                response.extend_from_slice(&chunk);
                if http_response_complete(&response) {
                    break;
                }
            }
            Ok(None) | Err(_) => break,
        }
    }

    say(&"=".repeat(68));
    say(&format!("HIDDEN-SERVICE RESPONSE ({} bytes):", response.len()));
    say(&"=".repeat(68));
    say(&String::from_utf8_lossy(&response));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use allium::directory::{CreateOptions, DirectoryOptions, EXT_REACHABILITY};
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;

    fn relay(host: &str, port: u16, roles: &[&str], nat: bool) -> RelayDescriptor {
        let seed: [u8; 32] = allium::osrand::bytes(32).try_into().unwrap();
        let identity_private = SigningKey::from_bytes(&seed).to_bytes();
        let options = if nat {
            // a real reachability extension: mode, introducer identity, introducer x25519 key, host, port
            let mut reach = vec![allium::nat::MODE_NAT];
            reach.extend_from_slice(&[9u8; 32]);
            reach.extend_from_slice(&[0u8; 32]);
            let introducer_host = b"203.0.113.66";
            reach.push(introducer_host.len() as u8);
            reach.extend_from_slice(introducer_host);
            reach.extend_from_slice(&9999u16.to_be_bytes());
            CreateOptions { extra_extensions: vec![(EXT_REACHABILITY, reach)], ..Default::default() }
        } else {
            CreateOptions::default()
        };
        RelayDescriptor::create(&identity_private, vec![7u8; 32], host, port, roles.iter().map(|r| r.to_string()).collect(), 3600.0, None, options).unwrap()
    }

    fn directory_with(relays: &[&RelayDescriptor]) -> Directory {
        let mut d = Directory::new(DirectoryOptions::default()).unwrap();
        for r in relays {
            d.publish((*r).clone()).unwrap();
        }
        d
    }

    fn intro_point_for(relay: &RelayDescriptor, claimed_host: &str, claimed_port: u16) -> IntroPoint {
        IntroPoint { relay_identity: relay.identity_public.clone(), host: claimed_host.to_string(), port: claimed_port, auth_public: vec![5u8; 32] }
    }

    #[test]
    fn intro_point_outside_the_directory_is_never_dialed() {
        let listed = relay("1.1.1.1", 9001, &["exit"], false);
        let attacker = relay("6.6.6.6", 9001, &["exit"], false); // a real, well-formed relay -- just not in our directory
        let directory = directory_with(&[&listed]);
        let points = vec![intro_point_for(&attacker, "6.6.6.6", 9001)];
        assert!(pick_intro_point(&directory, &points).is_none());
    }

    #[test]
    fn the_directorys_address_is_used_not_the_one_the_descriptor_claims() {
        let honest = relay("1.1.1.1", 9001, &["exit"], false);
        let directory = directory_with(&[&honest]);
        // the descriptor names the honest relay's identity but a different address
        let points = vec![intro_point_for(&honest, "6.6.6.6", 31337)];
        let (picked, relay) = pick_intro_point(&directory, &points).unwrap();
        assert_eq!((picked.host.as_str(), picked.port), ("1.1.1.1", 9001));
        assert_eq!((relay.host.as_str(), relay.port), ("1.1.1.1", 9001));
        assert_eq!(picked.relay_identity, honest.identity_public);
        // the one field only the service can supply is kept
        assert_eq!(picked.auth_public, vec![5u8; 32]);
    }

    #[test]
    fn a_hostile_intro_point_among_honest_ones_is_never_chosen() {
        let a = relay("1.1.1.1", 9001, &["exit"], false);
        let b = relay("2.2.2.2", 9002, &["exit"], false);
        let attacker = relay("6.6.6.6", 9001, &["exit"], false);
        let directory = directory_with(&[&a, &b]);
        let points = vec![intro_point_for(&attacker, "6.6.6.6", 9001), intro_point_for(&a, "1.1.1.1", 9001), intro_point_for(&b, "2.2.2.2", 9002)];
        let mut seen = HashSet::new();
        for _ in 0..200 {
            let (picked, _) = pick_intro_point(&directory, &points).unwrap();
            assert_ne!(picked.host, "6.6.6.6");
            seen.insert(picked.host);
        }
        assert_eq!(seen.len(), 2, "both honest intro points should get picked over many tries: {seen:?}");
    }

    #[test]
    fn only_exit_capable_relays_not_behind_nat_qualify() {
        let non_exit = relay("1.1.1.1", 9001, &["guard", "middle"], false);
        let natted = relay("2.2.2.2", 9002, &["exit"], true);
        assert!(natted.behind_nat() && !non_exit.behind_nat());
        let directory = directory_with(&[&non_exit, &natted]);
        let points = vec![intro_point_for(&non_exit, "1.1.1.1", 9001), intro_point_for(&natted, "2.2.2.2", 9002)];
        assert!(pick_intro_point(&directory, &points).is_none());
    }

    #[test]
    fn an_expired_directory_entry_does_not_qualify() {
        let honest = relay("1.1.1.1", 9001, &["exit"], false);
        let now = Arc::new(Mutex::new(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64()));
        let clock_now = now.clone();
        let mut directory = Directory::new(DirectoryOptions { clock: Some(Arc::new(move || *clock_now.lock().unwrap())), ..Default::default() }).unwrap();
        directory.publish(honest.clone()).unwrap();
        let points = vec![intro_point_for(&honest, "1.1.1.1", 9001)];
        assert!(pick_intro_point(&directory, &points).is_some());
        // read the clock into a local first, then move it past the descriptor's lifetime
        let later = *now.lock().unwrap() + 7200.0;
        *now.lock().unwrap() = later;
        assert!(pick_intro_point(&directory, &points).is_none());
    }

    #[test]
    fn no_intro_points_means_none() {
        let directory = directory_with(&[&relay("1.1.1.1", 9001, &["exit"], false)]);
        assert!(pick_intro_point(&directory, &[]).is_none());
    }

    // -- choose_intro_point: the cached directory, one forced refresh, then refusal --

    /// A refresh source that counts how often it is called.
    fn counting_refresh(result: Result<Arc<Directory>, CliExit>) -> (impl FnOnce() -> Result<Arc<Directory>, CliExit>, Arc<std::sync::atomic::AtomicUsize>) {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = calls.clone();
        (
            move || {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                result
            },
            calls,
        )
    }

    fn calls_of(c: &Arc<std::sync::atomic::AtomicUsize>) -> usize {
        c.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[test]
    fn a_vouched_intro_point_in_the_cached_directory_costs_no_refresh() {
        let honest = relay("1.1.1.1", 9001, &["exit"], false);
        let cached = directory_with(&[&honest]);
        let points = vec![intro_point_for(&honest, "6.6.6.6", 31337)];
        let (refresh, calls) = counting_refresh(Err(CliExit::error("must not be called")));
        let (picked, _) = choose_intro_point(&cached, &points, refresh).unwrap();
        assert_eq!(calls_of(&calls), 0, "no directory fetch when the cached one already vouches for an intro point");
        assert_eq!((picked.host.as_str(), picked.port), ("1.1.1.1", 9001), "the directory's address, not the descriptor's");
    }

    #[test]
    fn a_relay_the_cache_has_not_seen_gets_exactly_one_refresh_and_then_the_refreshed_address_is_dialed() {
        let new_relay = relay("2.2.2.2", 9002, &["exit"], false);
        let cached = directory_with(&[&relay("1.1.1.1", 9001, &["exit"], false)]); // does not list new_relay yet
        let refreshed = Arc::new(directory_with(&[&new_relay]));
        let points = vec![intro_point_for(&new_relay, "6.6.6.6", 31337)];
        let (refresh, calls) = counting_refresh(Ok(refreshed));
        let (picked, relay_used) = choose_intro_point(&cached, &points, refresh).unwrap();
        assert_eq!(calls_of(&calls), 1);
        assert_eq!((picked.host.as_str(), picked.port), ("2.2.2.2", 9002), "the refreshed directory's address, never the descriptor's 6.6.6.6");
        assert_eq!(relay_used.identity_public, new_relay.identity_public);
    }

    #[test]
    fn when_even_the_refreshed_directory_does_not_vouch_it_refuses_after_exactly_one_refresh() {
        let attacker = relay("6.6.6.6", 9001, &["exit"], false);
        let cached = directory_with(&[&relay("1.1.1.1", 9001, &["exit"], false)]);
        let refreshed = Arc::new(directory_with(&[&relay("1.1.1.1", 9001, &["exit"], false), &relay("3.3.3.3", 9003, &["exit"], false)]));
        let points = vec![intro_point_for(&attacker, "6.6.6.6", 9001)];
        let (refresh, calls) = counting_refresh(Ok(refreshed));
        let err = choose_intro_point(&cached, &points, refresh).unwrap_err();
        assert_eq!(calls_of(&calls), 1, "one forced refresh, not a retry loop");
        let msg = err.message.unwrap_or_default();
        assert!(msg.contains("refusing to dial an address the descriptor supplied itself"), "{msg}");
        assert_ne!(err.code, 0);
    }

    #[test]
    fn a_still_cached_directory_returned_by_a_rate_limited_refresh_is_judged_again_and_refuses() {
        // `refresh_relay_directory` may hand back the same cached directory when it is rate limited.
        let attacker = relay("6.6.6.6", 9001, &["exit"], false);
        let cached = Arc::new(directory_with(&[&relay("1.1.1.1", 9001, &["exit"], false)]));
        let points = vec![intro_point_for(&attacker, "6.6.6.6", 9001)];
        let (refresh, calls) = counting_refresh(Ok(cached.clone()));
        assert!(choose_intro_point(&cached, &points, refresh).is_err());
        assert_eq!(calls_of(&calls), 1);
    }

    #[test]
    fn a_failed_refresh_is_reported_as_is_not_turned_into_a_dial() {
        let attacker = relay("6.6.6.6", 9001, &["exit"], false);
        let cached = directory_with(&[&relay("1.1.1.1", 9001, &["exit"], false)]);
        let points = vec![intro_point_for(&attacker, "6.6.6.6", 9001)];
        let (refresh, calls) = counting_refresh(Err(CliExit::error("client: could not reach the authority")));
        let err = choose_intro_point(&cached, &points, refresh).unwrap_err();
        assert_eq!(calls_of(&calls), 1);
        assert_eq!(err.message.as_deref(), Some("client: could not reach the authority"));
    }

    #[test]
    fn a_descriptor_with_no_intro_points_forces_one_refresh_then_refuses() {
        let cached = directory_with(&[&relay("1.1.1.1", 9001, &["exit"], false)]);
        let (refresh, calls) = counting_refresh(Ok(Arc::new(directory_with(&[&relay("1.1.1.1", 9001, &["exit"], false)]))));
        assert!(choose_intro_point(&cached, &[], refresh).is_err());
        assert_eq!(calls_of(&calls), 1);
    }

    // -- version 3 lookup: plan, reply interpretation, and a simulated directory --

    const T: f64 = 1_700_000_000.0;

    fn seed() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn identity() -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&seed()).verifying_key().to_bytes()
    }

    fn points() -> Vec<IntroPoint> {
        vec![IntroPoint { relay_identity: vec![1u8; 32], host: "198.51.100.7".to_string(), port: 9001, auth_public: vec![2u8; 32] }]
    }

    /// What the service publishes at time `at`: the sealed descriptor for that period.
    fn published_at(at: f64) -> (HiddenServiceDescriptor, allium::hsblind::BlindedDescriptor) {
        let inner = HiddenServiceDescriptor::create(&seed(), vec![9u8; 32], points(), 3600.0, Some(at));
        let period = allium::hiddenservice::hs_directory_period(Some(at), None);
        let outer = allium::hsblind::seal_descriptor(&seed(), &inner, period).unwrap();
        (inner, outer)
    }

    /// A directory that just maps blinded key -> descriptor, and the lookup
    /// loop `fetch_hs_descriptor` runs against it (minus the circuit).
    fn lookup(directory: &HashMap<[u8; 32], allium::hsblind::BlindedDescriptor>, now: f64) -> Result<Option<HiddenServiceDescriptor>, String> {
        for (period, key) in lookup_plan(&identity(), now)? {
            let reply = allium::dirwire::encode_hs3_fetch_reply(directory.get(&key)).unwrap();
            match interpret_fetch_reply(&reply, &identity(), period, now)? {
                Lookup::Found(d) => return Ok(Some(d)),
                Lookup::NotFound | Lookup::Expired => continue,
            }
        }
        Ok(None)
    }

    #[test]
    fn the_lookup_plan_is_current_then_next_then_previous_with_distinct_blinded_keys() {
        let plan = lookup_plan(&identity(), T).unwrap();
        let p = allium::hiddenservice::hs_directory_period(Some(T), None);
        assert_eq!(plan.iter().map(|(period, _)| *period).collect::<Vec<_>>(), [p, p + 1, p - 1]);
        for (period, key) in &plan {
            assert_eq!(*key, blind_public_key(&identity(), *period).unwrap());
            assert_ne!(*key, identity(), "the identity key is never what is asked for");
        }
        let distinct: std::collections::HashSet<_> = plan.iter().map(|(_, k)| *k).collect();
        assert_eq!(distinct.len(), 3);
    }

    #[test]
    fn a_client_finds_the_service_and_gets_back_exactly_what_it_published() {
        let (inner, outer) = published_at(T);
        let directory = HashMap::from([(outer.blinded_public, outer)]);
        assert_eq!(lookup(&directory, T + 30.0).unwrap(), Some(inner));
    }

    #[test]
    fn a_client_whose_clock_is_a_period_ahead_or_behind_still_finds_it() {
        let (inner, outer) = published_at(T);
        let directory = HashMap::from([(outer.blinded_public, outer)]);
        let period = allium::hiddenservice::HS_DIRECTORY_INDEX_PERIOD;
        // within the descriptor's one-hour window, a client one period ahead or behind
        assert_eq!(lookup(&directory, T + 600.0 + period).unwrap_or(None), None, "a day later it has expired and must not be served");
        // clock behind: its "next" period is the service's current one
        let behind = (T / period).floor() * period - 1.0; // last second of the previous period, as the service's period starts
        let (inner_b, outer_b) = published_at(behind + 2.0); // service just crossed into the new period
        let dir_b = HashMap::from([(outer_b.blinded_public, outer_b)]);
        assert_eq!(lookup(&dir_b, behind).unwrap(), Some(inner_b), "client still in the old period finds the new one via 'next'");
        // clock ahead: the client has crossed the boundary, the service has not republished yet
        let ahead_start = (T / period).ceil() * period;
        let (inner_a, outer_a) = published_at(ahead_start - 60.0);
        let dir_a = HashMap::from([(outer_a.blinded_public, outer_a)]);
        assert_eq!(lookup(&dir_a, ahead_start + 5.0).unwrap(), Some(inner_a), "client already in the new period finds the old one via 'previous'");
        let _ = inner;
    }

    #[test]
    fn a_client_two_periods_off_finds_nothing_rather_than_something_stale() {
        let (_, outer) = published_at(T);
        let directory = HashMap::from([(outer.blinded_public, outer)]);
        let period = allium::hiddenservice::HS_DIRECTORY_INDEX_PERIOD;
        assert_eq!(lookup(&directory, T + 2.0 * period).unwrap(), None);
        assert_eq!(lookup(&directory, T - 2.0 * period).unwrap(), None);
    }

    #[test]
    fn interpreting_a_reply_distinguishes_not_found_expired_and_hostile() {
        let (inner, outer) = published_at(T);
        let period = outer.period;
        let reply = |d: Option<&allium::hsblind::BlindedDescriptor>| allium::dirwire::encode_hs3_fetch_reply(d).unwrap();
        assert_eq!(interpret_fetch_reply(&reply(Some(&outer)), &identity(), period, T + 1.0).unwrap(), Lookup::Found(inner));
        assert_eq!(interpret_fetch_reply(&reply(None), &identity(), period, T).unwrap(), Lookup::NotFound);
        assert_eq!(interpret_fetch_reply(&reply(Some(&outer)), &identity(), period, T + 100_000.0).unwrap(), Lookup::Expired);
        // hostile or broken replies are errors, never "keep looking"
        let mut tampered = outer.clone();
        let last = tampered.ciphertext.len() - 1;
        tampered.ciphertext[last] ^= 1;
        assert!(interpret_fetch_reply(&reply(Some(&tampered)), &identity(), period, T).is_err());
        assert!(interpret_fetch_reply(&reply(Some(&outer)), &identity(), period + 1, T).is_err(), "a descriptor for another period");
        let other = ed25519_dalek::SigningKey::from_bytes(&[0x43u8; 32]).verifying_key().to_bytes();
        assert!(interpret_fetch_reply(&reply(Some(&outer)), &other, period, T).is_err(), "a descriptor for another address");
        assert!(interpret_fetch_reply(b"not a reply", &identity(), period, T).is_err());
        assert!(interpret_fetch_reply(&[], &identity(), period, T).is_err());
    }
}
