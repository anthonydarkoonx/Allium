//! Hidden services, service side: descriptor publication, introduction-point
//! establishment, INTRODUCE2/rendezvous handling, and forwarding to the
//! local server behind `--hidden-service-port`. Port of the matching
//! section of `allium_cli.py` (`IntroCircuit`, `_register_intro_point`,
//! `_intro_receive_loop`, `_forward_tcp_to_session`, `_forward_session_to_tcp`,
//! `_serve_rendezvous`, `_publish_hs_descriptor`, `run_service`).
//!
//! Every `asyncio.create_task` in the Python original becomes a real
//! `std::thread::spawn` here. Unlike an asyncio task, a spawned thread is
//! never silently garbage-collected if nothing keeps its `JoinHandle` --
//! so, unlike Python's `_intro_receive_loop` (which has to keep a
//! `rendezvous_tasks` set purely to stop that from happening), this port's
//! per-introduction rendezvous threads are simply fire-and-forget: the
//! `JoinHandle` is dropped and the thread keeps running on its own,
//! exactly matching the Python original's actual shutdown behavior (those
//! tasks are never explicitly joined at shutdown there either -- see
//! `run_service`'s `finally` block, which only tears down the long-lived
//! intro circuits and the publish loop).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use x25519_dalek::{PublicKey, StaticSecret};

use allium::circuit::{Addr, EncryptOptions};
use allium::directory::{Directory, RelayDescriptor, ROLE_EXIT};
use allium::hiddenservice::{
    derive_session_keys, encode_rendezvous_handshake, rendezvous_auth_key, rendezvous_mac, HiddenServiceDescriptor, HiddenServiceError,
    HsFrame, HsSession, IntroPoint, ServiceIdentity,
};
use allium::hswire::{
    decode_establish_intro_reply, decode_introduce2, decode_rendezvous_data, decode_rendezvous_joined,
    decode_rendezvous_request, encode_establish_intro, encode_rendezvous_data, encode_rendezvous_join,
    establish_intro_signing_payload, HsReassembler, HS_MAGIC, INTRODUCE2,
};
use allium::osrand;

use crate::args::Args;
use crate::cli_error::CliExit;
use allium::dirwire::{decode_hs3_publish_reply, encode_hs3_publish_request};

use crate::dirclient::{build_generic_circuit_owned, dir_round_trip_over_circuit, fetch_relay_directory, resolve_entry_hops};
use crate::helpers::{parse_addr, primary_authority, say, sleep_or_wake, split_trust_keys, KEEPALIVE_PING};
use crate::hsclient::{hs_receive_message, hs_send_over_builder};
use crate::owned_circuit::OwnedCircuit;
use crate::vanguards::{Chooser, OsChooser, Vanguards};

fn now_unix() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn secure_index(n: usize) -> usize {
    debug_assert!(n > 0);
    let bytes = osrand::bytes(8);
    let v = u64::from_le_bytes(bytes.try_into().expect("osrand::bytes(8) is always 8 bytes"));
    (v % n as u64) as usize
}

/// Mirrors `allium::hiddenservice`'s own private `_ensure_private_dir`
/// (mode 0700, `create_dir_all`) -- duplicated here rather than exposed
/// from the library, matching this codebase's established convention for
/// small, module-local helpers (e.g. `expanduser` in `apply_config.rs`/
/// `alliumrc.rs`).
fn ensure_private_dir(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// One long-lived circuit to an introduction point: the built circuit, the
/// relay it registered with, and the per-intro-point auth key it
/// registered under (see `ServiceIdentity::intro_auth_keypair` -- never
/// the service's real identity key).
struct IntroCircuit {
    circuit: OwnedCircuit,
    descriptor: RelayDescriptor,
    auth_public: Vec<u8>,
}

/// Cap on rendezvous circuits this service will have in flight at once.
/// Each INTRODUCE2 used to spawn an unbounded
/// thread; a client (or a colluding intro relay) flooding introductions
/// could grow the service's thread/socket count without limit. This is a
/// coarse, cheap backstop -- it does not by itself fix per-intro-point
/// rate limiting (that is relay-side; see the relay's INTRODUCE1 limiters).
const MAX_CONCURRENT_RENDEZVOUS: usize = 32;

/// Most of those slots one rendezvous point may hold at once. A hostile
/// client names the rendezvous point in its introduction and simply never
/// joins, pinning a slot for the full peer wait; without this, naming one
/// relay over and over fills every slot. With it, a single relay can hold
/// only this many, so clogging the service takes several distinct relays.
///
/// Trade-off: in a network with very few exit-capable relays this also
/// caps honest concurrency at `exits * MAX_RENDEZVOUS_PER_RP`. It does not
/// stop an attacker who names many different relays -- only a per-
/// introduction cost (proof of work) can -- but it removes the cheapest
/// version of the attack.
const MAX_RENDEZVOUS_PER_RP: usize = 8;

/// How long the service waits for the client to join a rendezvous the
/// service has already joined. The client builds its own circuit in the
/// meantime, so this is generous.
const RENDEZVOUS_PEER_WAIT_SECS: f64 = 30.0;
/// The same wait once the service is more than half full: a client that
/// has not joined by now is far more likely hostile than slow, and every
/// slot it holds is one an honest client cannot have. Shedding sooner
/// under load cuts what each hostile introduction costs the service.
const RENDEZVOUS_PEER_WAIT_UNDER_LOAD_SECS: f64 = 10.0;

/// How long to wait for the peer's join given how many rendezvous are
/// currently in flight.
fn rendezvous_peer_wait_secs(in_flight: usize) -> f64 {
    if in_flight * 2 > MAX_CONCURRENT_RENDEZVOUS {
        RENDEZVOUS_PEER_WAIT_UNDER_LOAD_SECS
    } else {
        RENDEZVOUS_PEER_WAIT_SECS
    }
}

/// In-flight rendezvous accounting: a total, and a count per rendezvous
/// point (by identity).
#[derive(Default)]
struct RendezvousSlots {
    inner: std::sync::Mutex<RendezvousSlotsInner>,
}

#[derive(Default)]
struct RendezvousSlotsInner {
    total: usize,
    per_rp: HashMap<Vec<u8>, usize>,
}

impl RendezvousSlots {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Claim a slot for a rendezvous at `rp_identity`, or `None` if the
    /// service is full or that relay already holds its share. The returned
    /// guard frees the slot when dropped, on every exit path.
    fn try_acquire(self: &Arc<Self>, rp_identity: &[u8]) -> Option<RendezvousSlotGuard> {
        let mut inner = self.inner.lock().unwrap();
        if inner.total >= MAX_CONCURRENT_RENDEZVOUS || inner.per_rp.get(rp_identity).copied().unwrap_or(0) >= MAX_RENDEZVOUS_PER_RP {
            return None;
        }
        inner.total += 1;
        *inner.per_rp.entry(rp_identity.to_vec()).or_insert(0) += 1;
        Some(RendezvousSlotGuard { slots: Arc::clone(self), rp_identity: rp_identity.to_vec() })
    }

    fn in_flight(&self) -> usize {
        self.inner.lock().unwrap().total
    }
}

/// Frees one rendezvous slot (and its relay's share) when the handling
/// thread ends, on every exit path (`serve_rendezvous` returns early in
/// several places) including a panic unwind.
struct RendezvousSlotGuard {
    slots: Arc<RendezvousSlots>,
    rp_identity: Vec<u8>,
}

impl Drop for RendezvousSlotGuard {
    fn drop(&mut self) {
        let mut inner = self.slots.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.total = inner.total.saturating_sub(1);
        if let Some(n) = inner.per_rp.get_mut(&self.rp_identity) {
            *n -= 1;
            if *n == 0 {
                inner.per_rp.remove(&self.rp_identity);
            }
        }
    }
}

/// Why an introduction is not served.
#[derive(Debug, PartialEq, Eq)]
enum IntroductionRefusal {
    /// The sealed request names a relay that is not a live, exit-capable relay
    /// that is not behind NAT in the directory.
    UnknownRendezvousPoint,
    /// The service is full, or that relay already holds its share of slots.
    NoFreeSlot,
}

/// Decide whether to serve an introduction that names `rp_identity`: the
/// directory must vouch for it as an honest service could have chosen (live,
/// exit-capable, not behind NAT) *before* any slot is taken, so a relay the
/// directory does not list can never occupy one. On success the returned
/// descriptor carries the directory's address, which is the one to dial -- the
/// host and port in the client's sealed request are never used -- and the
/// guard holds the slot until it is dropped.
fn admit_introduction(
    directory: &Directory,
    slots: &Arc<RendezvousSlots>,
    rp_identity: &[u8],
) -> Result<(RelayDescriptor, RendezvousSlotGuard), IntroductionRefusal> {
    let rp_descriptor = directory
        .get(rp_identity)
        .filter(|d| d.roles.iter().any(|r| r == ROLE_EXIT) && !d.behind_nat())
        .cloned()
        .ok_or(IntroductionRefusal::UnknownRendezvousPoint)?;
    let slot = slots.try_acquire(rp_identity).ok_or(IntroductionRefusal::NoFreeSlot)?;
    Ok((rp_descriptor, slot))
}

/// How long `serve_rendezvous` waits for the client to join, given the slots
/// currently in flight (its own included).
fn peer_wait_for(slots: &RendezvousSlots) -> f64 {
    rendezvous_peer_wait_secs(slots.in_flight())
}

/// introduction point for `identity`.
#[allow(clippy::too_many_arguments)]
fn register_intro_point(
    args: &Args,
    guard_addr: Addr,
    middle_addr: Addr,
    entry_trust: &HashMap<String, Vec<[u8; 32]>>,
    identity: &ServiceIdentity,
    relay_descriptor: &RelayDescriptor,
    directory: &Directory,
    vanguards: &VanguardState,
) -> Result<IntroCircuit, String> {
    let intro_identity: [u8; 32] =
        relay_descriptor.identity_public.as_slice().try_into().map_err(|_| "intro relay identity is not 32 bytes".to_string())?;

    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let timeout = Duration::from_secs_f64(args.timeout.unwrap_or(5.0));
    let retries = args.retries.unwrap_or(0).max(0) as u32;
    // guard, a layer-2 vanguard, a layer-3 vanguard, then the intro relay: the
    // intro relay is picked from the directory, so it may well be one an
    // attacker runs, and must not sit next to one fixed middle relay.
    let path = plan_hs_path(
        "intro",
        now_unix(),
        &mut OsChooser,
        directory,
        vanguards,
        args.allow_short_rendezvous.unwrap_or(false),
        entry_trust,
        &args.kem_keys,
        guard_addr,
        middle_addr,
        intro_identity,
        (relay_descriptor.host.clone(), relay_descriptor.port),
        relay_descriptor.pq_kem_public().map(|pq| pq.to_vec()),
    )?;
    let owned = build_generic_circuit_owned(sock, path.hops, timeout, retries, Some(path.trust), "service-intro".to_string(), Some(path.kem_keys))
        .map_err(|e| e.to_string())?;

    // Sign and register with a key derived just for this intro point,
    // never the real identity_public -- this is what
    // keeps this specific relay (and the directory, which only ever sees
    // this same derived key in the descriptor) from learning which hidden
    // service it is serving.
    let (auth_seed, auth_public) = identity.intro_auth_keypair(&relay_descriptor.identity_public).map_err(|e| e.to_string())?;
    let now = now_unix();
    let payload = establish_intro_signing_payload(&auth_public, now).map_err(|e| e.to_string())?;
    let signature = SigningKey::from_bytes(&auth_seed).sign(&payload).to_bytes();
    let message = encode_establish_intro(&auth_public, now, &signature).map_err(|e| e.to_string())?;
    hs_send_over_builder(&owned, &message).map_err(|e| e.to_string())?;
    let mut reassembler = HsReassembler::new(64);
    let reply = hs_receive_message(&owned, &mut reassembler, args.timeout.unwrap_or(5.0)).map_err(|e| e.to_string())?;
    let (ok, msg) = decode_establish_intro_reply(&reply).map_err(|e| e.to_string())?;
    if !ok {
        return Err(format!("introduction point {}:{} refused: {msg}", relay_descriptor.host, relay_descriptor.port));
    }
    say(&format!("service: registered as an introduction point at {}:{} ({msg})", relay_descriptor.host, relay_descriptor.port));
    Ok(IntroCircuit { circuit: owned, descriptor: relay_descriptor.clone(), auth_public: auth_public.to_vec() })
}

/// Read INTRODUCE2 messages off one intro circuit until `stopping` is set,
/// spawning a rendezvous handler thread for each one. Also sends a
/// periodic keepalive so this long-lived circuit's idle timer at every hop
/// stays fresh.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
fn intro_receive_loop(
    args: Arc<Args>,
    identity: Arc<ServiceIdentity>,
    intro: Arc<IntroCircuit>,
    entry_trust: HashMap<String, Vec<[u8; 32]>>,
    guard_addr: Addr,
    middle_addr: Addr,
    stopping: Arc<AtomicBool>,
    // The current directory, used to validate every client-named
    // rendezvous point before this service's fixed guard/middle are ever
    // told to contact it. Without this, any client can name an address it
    // controls and get the middle relay to connect out to it.
    directory: Arc<Directory>,
    inflight_rendezvous: Arc<RendezvousSlots>,
    vanguards: Arc<VanguardState>,
) {
    let mut reassembler = HsReassembler::new(64);
    let mut last_keepalive = Instant::now();
    let keepalive_interval = args.keepalive_interval.filter(|v| *v > 0.0);

    while !stopping.load(Ordering::SeqCst) {
        let raw = {
            let b = intro.circuit.lock();
            b.receive(Some(Duration::from_secs_f64(2.0)))
        };
        let raw = match raw {
            Ok(raw) => raw,
            Err(_) => {
                if let Some(interval) = keepalive_interval {
                    if last_keepalive.elapsed().as_secs_f64() >= interval {
                        let final_addr = {
                            let b = intro.circuit.lock();
                            b.addrs.last().cloned()
                        };
                        if let Some(final_addr) = final_addr {
                            let mut b = intro.circuit.lock();
                            let _ = b.send(KEEPALIVE_PING, final_addr, EncryptOptions::default());
                        }
                        last_keepalive = Instant::now();
                    }
                }
                continue;
            }
        };
        let message = match reassembler.push(&raw) {
            Ok(Some(m)) => m,
            Ok(None) => continue,
            Err(e) => {
                say(&format!("service: bad message on intro circuit: {e}"));
                continue;
            }
        };
        if !message.starts_with(HS_MAGIC) || message.len() < 5 || message[4] != INTRODUCE2 {
            continue;
        }
        let (client_ephemeral_pub, sealed) = match decode_introduce2(&message) {
            Ok(v) => v,
            Err(e) => {
                say(&format!("service: could not process an introduce2: {e}"));
                continue;
            }
        };
        let (plaintext, intro_secret) = match identity.open_introduce(&client_ephemeral_pub, &sealed) {
            Ok(v) => v,
            Err(e) => {
                say(&format!("service: could not process an introduce2: {e}"));
                continue;
            }
        };
        let (rp_identity, rp_host, rp_port, cookie) = match decode_rendezvous_request(&plaintext) {
            Ok(v) => v,
            Err(e) => {
                say(&format!("service: could not process an introduce2: {e}"));
                continue;
            }
        };
        // The sealed request names a relay by identity, host and port,
        // but that request comes from the client -- who is the adversary
        // here. Trusting rp_host/rp_port (or even
        // just rp_identity without checking its role/reachability) means
        // this service's fixed middle relay can be made to open a circuit
        // to any address the client picks. Require a live, non-NAT,
        // exit-capable directory entry for rp_identity, and use *its*
        // address, never the client-supplied one.
        //
        // `directory` is only the snapshot this loop was started with --
        // relying on it alone means every introduction is refused once that
        // snapshot's descriptors age out of their validity window (an hour
        // by default), even though the service keeps publishing. Refresh
        // against the same periodically-updated directory `serve_rendezvous`
        // already uses, falling back to the start-up snapshot only when a
        // refresh isn't available yet.
        let live_directory = crate::dirclient::cached_relay_directory(&args, "service").ok();
        let directory_for_lookup: &Directory = live_directory.as_deref().unwrap_or(&directory);

        // Bound how many rendezvous circuits this service builds at once,
        // so a burst of introductions (real
        // or forged by a colluding intro relay) can't grow threads/sockets
        // without limit. The directory is checked first, so a relay it does
        // not vouch for never takes a slot (see `admit_introduction`).
        let (rp_descriptor, slot) = match admit_introduction(directory_for_lookup, &inflight_rendezvous, &rp_identity) {
            Ok(admitted) => admitted,
            Err(IntroductionRefusal::UnknownRendezvousPoint) => {
                say(&format!(
                    "service: introduction named a rendezvous point not in the directory ({rp_host}:{rp_port}); dropping"
                ));
                continue;
            }
            Err(IntroductionRefusal::NoFreeSlot) => {
                say("service: too many rendezvous circuits already in flight (or this rendezvous point already holds its share); dropping introduction");
                continue;
            }
        };

        say(&format!("service: received an introduction -- rendezvous at {}:{}", rp_descriptor.host, rp_descriptor.port));
        let args = Arc::clone(&args);
        let identity = Arc::clone(&identity);
        let entry_trust = entry_trust.clone();
        let guard_addr = guard_addr.clone();
        let middle_addr = middle_addr.clone();
        let slots_for_wait = Arc::clone(&inflight_rendezvous);
        let directory_for_thread = Arc::clone(&directory);
        let vanguards_for_thread = Arc::clone(&vanguards);
        let rp_host = rp_descriptor.host.clone();
        let rp_port = rp_descriptor.port;
        std::thread::spawn(move || {
            let _slot = slot;
            serve_rendezvous(
                &args,
                &identity,
                guard_addr,
                middle_addr,
                entry_trust,
                rp_identity,
                rp_host,
                rp_port,
                cookie,
                client_ephemeral_pub,
                intro_secret,
                slots_for_wait,
                directory_for_thread,
                vanguards_for_thread,
            )
        });
    }
}

/// Read bytes from the local web server and seal+send each chunk over the
/// rendezvous tunnel, until the local connection closes or `stop` is set
/// by the other direction. `reader`'s read timeout is what lets this poll
/// `stop` instead of blocking forever on a connection with no new data --
/// the Python original relies on `task.cancel()` for the same effect,
/// which a real OS thread has no equivalent of.
/// `send` is the tunnel-side sink for a sealed, wire-encoded chunk --
/// `hs_send_over_builder` bound to a live circuit at the real call site in
/// [`serve_rendezvous`], or (in tests) a fake that just records what it was
/// given, exactly mirroring how the Python original's
/// `test_hs_forwarding.py` monkeypatches `_hs_send_over_builder` to isolate
/// this function's own sealing/ordering/EOF logic from a real circuit.
fn forward_tcp_to_session(
    mut reader: TcpStream,
    session: Arc<HsSession>,
    mut send: impl FnMut(&[u8]) -> std::io::Result<()>,
    stop: Arc<AtomicBool>,
) {
    let _ = reader.set_read_timeout(Some(Duration::from_millis(500)));
    let mut buf = [0u8; 65536];
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match reader.read(&mut buf) {
            Ok(0) => {
                // The local server finished its response: say so with an
                // authenticated close, so the client can tell a clean end
                // from a tunnel that was cut off. Best effort.
                if let Ok(sealed) = session.seal_close() {
                    if let Ok(message) = encode_rendezvous_data(&sealed) {
                        let _ = send(&message);
                    }
                }
                break;
            }
            Ok(n) => {
                let sealed = match session.seal(&buf[..n]) {
                    Ok(s) => s,
                    Err(e) => {
                        say(&format!("service: local connection -> tunnel forwarding stopped: {e}"));
                        break;
                    }
                };
                let message = match encode_rendezvous_data(&sealed) {
                    Ok(m) => m,
                    Err(e) => {
                        say(&format!("service: local connection -> tunnel forwarding stopped: {e}"));
                        break;
                    }
                };
                if let Err(e) = send(&message) {
                    say(&format!("service: local connection -> tunnel forwarding stopped: {e}"));
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => {
                say(&format!("service: local connection -> tunnel forwarding stopped: {e}"));
                break;
            }
        }
    }
    stop.store(true, Ordering::SeqCst);
}

/// Read RENDEZVOUS_DATA messages off the tunnel, unseal them, and write the
/// plaintext to the local web server, until the tunnel closes/errors or
/// `stop` is set by the other direction.
///
/// `receive` is the tunnel-side source of one already-reassembled message
/// (`Err` means "nothing arrived within this pass's deadline", not
/// necessarily the end of the tunnel) -- `hs_receive_message` bound to a
/// live circuit and a persistent [`HsReassembler`] at the real call site,
/// or (in tests) a fake queue, mirroring the Python original's
/// `test_hs_forwarding.py` monkeypatching `_hs_receive_message` for the
/// same reason given on [`forward_tcp_to_session`].
fn forward_session_to_tcp(
    mut writer: TcpStream,
    session: Arc<HsSession>,
    mut receive: impl FnMut(f64) -> std::io::Result<Vec<u8>>,
    timeout: f64,
    stop: Arc<AtomicBool>,
) {
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let message = match receive(timeout) {
            Ok(m) => m,
            // Nothing arrived within this pass's deadline -- not
            // necessarily the end of the tunnel, just idle; loop back to
            // re-check `stop`.
            Err(_) => continue,
        };
        let sealed = match decode_rendezvous_data(&message) {
            Ok(s) => s,
            Err(e) => {
                say(&format!("service: session decrypt failed: {e}"));
                break;
            }
        };
        let plaintext = match session.open_frame(&sealed) {
            Ok(HsFrame::Data(p)) => p,
            // The client finished cleanly: end its request body and stop.
            Ok(HsFrame::Close) => {
                let _ = writer.shutdown(std::net::Shutdown::Write);
                break;
            }
            // An authentic frame we already have: dropped, nothing delivered twice.
            Err(HiddenServiceError::SessionReplay(m)) => {
                say(&format!("service: ignoring a replayed session frame: {m}"));
                continue;
            }
            Err(e) => {
                say(&format!("service: session decrypt failed: {e}"));
                break;
            }
        };
        if let Err(e) = writer.write_all(&plaintext) {
            say(&format!("service: tunnel -> local connection forwarding stopped: {e}"));
            break;
        }
    }
    stop.store(true, Ordering::SeqCst);
}

/// The service's two persistent vanguard layers and where they are saved.
///
/// Every circuit this service builds to a relay it does not control -- its
/// introduction circuits and each rendezvous circuit -- goes guard, layer-2
/// relay, layer-3 relay, far end; see [`crate::vanguards`] for why, and for
/// how the layers rotate. This wraps the layers in a lock (circuits are built
/// from several threads) and saves them whenever they change.
struct VanguardState {
    inner: std::sync::Mutex<Vanguards>,
    path: Option<String>,
}

impl VanguardState {
    /// Load the layers from `path` (an absent or damaged file gives empty
    /// layers, drawn afresh on first use). `None` keeps them in memory only,
    /// so they are re-drawn on every restart.
    fn new(path: Option<String>) -> Self {
        let layers = path.as_deref().map(Vanguards::load).unwrap_or_default();
        VanguardState { inner: std::sync::Mutex::new(layers), path }
    }

    /// Bring the layers up to date against `directory`, save them if they
    /// changed, and pick the two middle hops for one circuit to the given
    /// far end. `None` if the network cannot supply a valid pair.
    #[allow(clippy::too_many_arguments)]
    fn pick(
        &self,
        now: f64,
        rng: &mut dyn Chooser,
        directory: &Directory,
        guard: &[[u8; 32]],
        guard_host: &str,
        target_identity: &[u8; 32],
        target_host: &str,
    ) -> Option<(RelayDescriptor, RelayDescriptor)> {
        let mut layers = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if layers.refresh(now, &directory.all(), guard, rng) {
            if let Some(path) = &self.path {
                if let Err(e) = layers.save(path) {
                    say(&format!("service: could not save vanguard state to {path} ({e}); the layers will be re-drawn after a restart"));
                }
            }
        }
        layers.pick_path(now, directory, guard_host, target_identity, target_host, rng)
    }
}

/// Where the service's guard is kept: `guard.state` in `--hidden-service-dir`,
/// unless a state file was set explicitly. `None` if there is nowhere to keep it.
fn service_guard_state_path(args: &Args) -> Option<String> {
    if args.state_file.as_deref().is_some_and(|f| !f.is_empty()) {
        return None; // an explicit state file wins; nothing to set
    }
    args.hidden_service_dir.as_deref().filter(|d| !d.is_empty()).map(|dir| std::path::Path::new(dir).join("guard.state").to_string_lossy().into_owned())
}

/// Where to keep the vanguard layers: next to the service's other state in
/// `--hidden-service-dir`, else beside `--state-file`, else nowhere (with a
/// note, since an un-persisted layer is re-drawn on every restart).
fn vanguard_state_path(args: &Args) -> Option<String> {
    if let Some(dir) = args.hidden_service_dir.as_deref().filter(|d| !d.is_empty()) {
        return Some(std::path::Path::new(dir).join("vanguards.state").to_string_lossy().into_owned());
    }
    if let Some(state_file) = args.state_file.as_deref().filter(|f| !f.is_empty()) {
        return Some(format!("{state_file}.vanguards"));
    }
    None
}

/// Everything needed to build one hidden-service circuit: the hops in order,
/// the identity pins and the post-quantum keys by hop name.
struct HsPath {
    hops: Vec<(String, Addr)>,
    trust: HashMap<String, Vec<[u8; 32]>>,
    kem_keys: HashMap<String, Vec<u8>>,
}

/// Plan a circuit from this service to `target_hop`'s relay (`"intro"` or
/// `"rendezvous"`): the guard, **a layer-2 vanguard, a layer-3 vanguard**,
/// then the target. See [`crate::vanguards`] for why the two middle hops come
/// from small persistent layers rather than being fixed or fresh each time.
///
/// If the network cannot supply a valid pair (too few relays, or too
/// clustered) this fails, rather than quietly building the shorter path that
/// puts the far end directly next to one fixed middle relay -- unless
/// `allow_short` (`--allow-short-rendezvous`) was given, in which case it
/// builds guard, middle, target.
#[allow(clippy::too_many_arguments)]
fn plan_hs_path(
    target_hop: &str,
    now: f64,
    rng: &mut dyn Chooser,
    directory: &Directory,
    vanguards: &VanguardState,
    allow_short: bool,
    entry_trust: &HashMap<String, Vec<[u8; 32]>>,
    kem_keys: &HashMap<String, Vec<u8>>,
    guard_addr: Addr,
    middle_addr: Addr,
    target_identity: [u8; 32],
    target_addr: Addr,
    target_kem: Option<Vec<u8>>,
) -> Result<HsPath, String> {
    let mut trust = entry_trust.clone();
    trust.insert(target_hop.to_string(), vec![target_identity]);
    let mut kem_keys = kem_keys.clone();
    if let Some(pq) = target_kem {
        kem_keys.insert(target_hop.to_string(), pq);
    }
    let guard_ids: Vec<[u8; 32]> = entry_trust.get("guard").cloned().unwrap_or_default();

    let mut hops = vec![("guard".to_string(), guard_addr.clone())];
    match vanguards.pick(now, rng, directory, &guard_ids, &guard_addr.0, &target_identity, &target_addr.0) {
        Some((second, third)) => {
            for (name, relay) in [("vanguard-2", &second), ("vanguard-3", &third)] {
                let identity = <[u8; 32]>::try_from(relay.identity_public.as_slice()).expect("vanguards are 32-byte identities");
                trust.insert(name.to_string(), vec![identity]);
                if let Some(pq) = relay.pq_kem_public() {
                    kem_keys.insert(name.to_string(), pq.to_vec());
                }
                hops.push((name.to_string(), (relay.host.clone(), relay.port)));
            }
        }
        None if allow_short => {
            say(&format!(
                "service: WARNING: no valid vanguard pair is available for the {target_hop} circuit; building the short path through the fixed middle relay because --allow-short-rendezvous is set. A hostile relay at the far end can learn this service's middle relay."
            ));
            hops.push(("middle".to_string(), middle_addr));
        }
        None => {
            return Err(format!(
                "no valid pair of vanguard relays is available for the {target_hop} circuit (too few relays outside the guard and the target, or too many in the same network). \
                 Refusing the short path through one fixed middle relay, which lets a hostile relay at the far end learn it; add more relays, or pass --allow-short-rendezvous to accept that risk"
            ));
        }
    }
    hops.push((target_hop.to_string(), target_addr));
    Ok(HsPath { hops, trust, kem_keys })
}

#[allow(clippy::too_many_arguments)]
fn serve_rendezvous(
    args: &Args,
    identity: &ServiceIdentity,
    guard_addr: Addr,
    middle_addr: Addr,
    entry_trust: HashMap<String, Vec<[u8; 32]>>,
    rp_identity: Vec<u8>,
    rp_host: String,
    rp_port: u16,
    cookie: Vec<u8>,
    client_ephemeral_pub: Vec<u8>,
    intro_secret: [u8; 32],
    slots: Arc<RendezvousSlots>,
    directory: Arc<Directory>,
    vanguards: Arc<VanguardState>,
) {
    let Ok(rp_identity_arr) = <[u8; 32]>::try_from(rp_identity.as_slice()) else {
        say("service: rendezvous handling failed: rendezvous relay identity is not 32 bytes");
        return;
    };
    // The directory used to draw and check the vanguard layers: the cached one
    // (refreshed periodically, so a long-running service notices relays coming
    // and going), falling back to the snapshot taken at start-up.
    let live_directory = crate::dirclient::cached_relay_directory(args, "service").ok();
    let directory_for_layers: &Directory = live_directory.as_deref().unwrap_or(&directory);
    let path = match plan_hs_path(
        "rendezvous",
        now_unix(),
        &mut OsChooser,
        directory_for_layers,
        &vanguards,
        args.allow_short_rendezvous.unwrap_or(false),
        &entry_trust,
        &args.kem_keys,
        guard_addr,
        middle_addr,
        rp_identity_arr,
        (rp_host, rp_port),
        None,
    ) {
        Ok(p) => p,
        Err(e) => {
            say(&format!("service: rendezvous handling failed: {e}"));
            return;
        }
    };
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            say(&format!("service: rendezvous handling failed: {e}"));
            return;
        }
    };
    let timeout = args.timeout.unwrap_or(5.0);
    let timeout_dur = Duration::from_secs_f64(timeout);
    let retries = args.retries.unwrap_or(0).max(0) as u32;
    let owned = match build_generic_circuit_owned(sock, path.hops, timeout_dur, retries, Some(path.trust), "service-rendezvous".to_string(), Some(path.kem_keys)) {
        Ok(o) => o,
        Err(e) => {
            say(&format!("service: rendezvous handling failed: {e}"));
            return;
        }
    };

    let mut reassembler = HsReassembler::new(64);
    let join = match encode_rendezvous_join(&cookie) {
        Ok(j) => j,
        Err(e) => {
            say(&format!("service: rendezvous handling failed: {e}"));
            return;
        }
    };
    if let Err(e) = hs_send_over_builder(&owned, &join) {
        say(&format!("service: rendezvous handling failed: {e}"));
        return;
    }
    let joined = match hs_receive_message(&owned, &mut reassembler, timeout) {
        Ok(j) => j,
        Err(e) => {
            say(&format!("service: rendezvous handling failed: {e}"));
            return;
        }
    };
    let (mut ok, mut msg) = match decode_rendezvous_joined(&joined) {
        Ok(v) => v,
        Err(e) => {
            say(&format!("service: rendezvous handling failed: {e}"));
            return;
        }
    };
    // Which side's RENDEZVOUS_JOIN reaches the rendezvous point first is a
    // race -- see the Python original's long comment. An initial "waiting"
    // is not the final answer here either.
    if ok && msg.to_lowercase().contains("waiting") {
        let joined = match hs_receive_message(&owned, &mut reassembler, peer_wait_for(&slots)) {
            Ok(j) => j,
            Err(e) => {
                say(&format!("service: rendezvous handling failed: {e}"));
                return;
            }
        };
        (ok, msg) = match decode_rendezvous_joined(&joined) {
            Ok(v) => v,
            Err(e) => {
                say(&format!("service: rendezvous handling failed: {e}"));
                return;
            }
        };
    }
    if !ok {
        say(&format!("service: rendezvous point refused the join: {msg}"));
        return;
    }

    // The bare ephemeral key this used to send let the rendezvous point
    // alone impersonate the service (it can answer the RENDEZVOUS_JOIN
    // itself and never involve the real service at all).
    // The MAC below is keyed by `intro_secret`, which only the real client
    // and this service ever compute -- the rendezvous point forwards the
    // sealed INTRODUCE envelope but cannot open it, so it never learns
    // this value.
    let Ok(client_pub_arr) = <[u8; 32]>::try_from(client_ephemeral_pub.as_slice()) else {
        say("service: rendezvous handling failed: client ephemeral key is not 32 bytes");
        return;
    };
    let encryption_public = match identity.encryption_public() {
        Ok(k) => k,
        Err(e) => {
            say(&format!("service: rendezvous handling failed: {e}"));
            return;
        }
    };
    let service_ephemeral_seed: [u8; 32] = osrand::bytes(32).try_into().expect("osrand::bytes(32) is always 32 bytes");
    let service_ephemeral = StaticSecret::from(service_ephemeral_seed);
    let service_ephemeral_pub = PublicKey::from(&service_ephemeral).to_bytes();
    let auth_key = rendezvous_auth_key(&intro_secret);
    let mac = rendezvous_mac(&auth_key, &client_ephemeral_pub, &service_ephemeral_pub, &encryption_public, &cookie, &rp_identity);
    let handshake_payload = encode_rendezvous_handshake(&service_ephemeral_pub, &mac);
    let handshake = match encode_rendezvous_data(&handshake_payload) {
        Ok(h) => h,
        Err(e) => {
            say(&format!("service: rendezvous handling failed: {e}"));
            return;
        }
    };
    if let Err(e) = hs_send_over_builder(&owned, &handshake) {
        say(&format!("service: rendezvous handling failed: {e}"));
        return;
    }
    let shared = service_ephemeral.diffie_hellman(&PublicKey::from(client_pub_arr));
    if !shared.was_contributory() {
        // Belt-and-suspenders: `identity.open_introduce` already rejected
        // this exact `client_pub_arr` as a low-order point before this
        // thread was ever spawned (low-order-ness is a property of the
        // peer's public key, so it does not depend on which clamped X25519
        // scalar -- the intro seed there, this fresh ephemeral here -- it
        // is multiplied by). Kept anyway so this function never relies on
        // that invariant holding across a future refactor.
        say("service: rendezvous handling failed: client ephemeral key is a low-order point");
        return;
    }
    let (key_c2s, key_s2c) = derive_session_keys(&shared.to_bytes(), &intro_secret);
    let session = match HsSession::new(&key_c2s, &key_s2c, &cookie, true) {
        Ok(s) => s,
        Err(e) => {
            say(&format!("service: rendezvous handling failed: {e}"));
            return;
        }
    };

    let Ok((local_host, local_port)) = parse_addr(args.hidden_service_port.as_deref().unwrap_or_default()) else {
        say("service: rendezvous handling failed: bad --hidden-service-port");
        return;
    };
    let local_stream = (local_host.as_str(), local_port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .and_then(|addr| TcpStream::connect_timeout(&addr, timeout_dur).ok());
    let Some(local_stream) = local_stream else {
        say(&format!("service: could not reach local server at {local_host}:{local_port}"));
        return;
    };
    say(&format!("service: forwarding rendezvous traffic to {local_host}:{local_port}"));

    let reader = match local_stream.try_clone() {
        Ok(r) => r,
        Err(e) => {
            say(&format!("service: rendezvous handling failed: {e}"));
            return;
        }
    };
    let writer = local_stream;

    let stop = Arc::new(AtomicBool::new(false));
    let circuit = Arc::new(owned);
    let session = Arc::new(session);

    let to_session = {
        let circuit = Arc::clone(&circuit);
        let session = Arc::clone(&session);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            forward_tcp_to_session(reader, session, move |message| hs_send_over_builder(&circuit, message), stop)
        })
    };
    let to_local = {
        let circuit = Arc::clone(&circuit);
        let session = Arc::clone(&session);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut reassembler = HsReassembler::new(64);
            forward_session_to_tcp(
                writer,
                session,
                move |timeout| hs_receive_message(&circuit, &mut reassembler, timeout),
                2.0,
                stop,
            )
        })
    };
    // Either direction finishing (local server closed the connection, the
    // tunnel errored out, ...) means this rendezvous is over: each
    // function sets `stop` in its own `finally`-equivalent before
    // returning, so once one thread has ended, `stop` is already set and
    // the other notices it within one of its own short polls -- joining
    // both here is what "tear down both directions" becomes without an
    // `asyncio.wait(FIRST_COMPLETED)` to reach for.
    let _ = to_session.join();
    stop.store(true, Ordering::SeqCst);
    let _ = to_local.join();
    say("service: rendezvous session closed");
}

/// Build the version 3 publish request for the service's *current* period.
///
/// The ordinary descriptor (encryption key, introduction points, any client
/// authorization) is created and signed as before, then sealed under a key
/// derived from the service's address and signed by this period's blinded key
/// (see `allium::hsblind`), so the directory authority is handed a blinded key
/// and a ciphertext and nothing that names the service.
///
/// Only the current period is published. Clients look up the current, then the
/// next, then the previous period, which covers a clock a little off either
/// way; publishing a second key alongside this one would let the authority link
/// the two by their timing.
///
/// Returns the inner descriptor, the sealed one, and the encoded request.
pub(crate) fn build_publish_request(
    seed: &[u8; 32],
    encryption_public: Vec<u8>,
    intro_points: &[IntroPoint],
    client_auth_keys: &[[u8; 32]],
    now: f64,
) -> Result<(HiddenServiceDescriptor, allium::hsblind::BlindedDescriptor, Vec<u8>), String> {
    let inner = if client_auth_keys.is_empty() {
        HiddenServiceDescriptor::create(seed, encryption_public, intro_points.to_vec(), allium::hiddenservice::DEFAULT_HS_DESCRIPTOR_LIFETIME, Some(now))
    } else {
        HiddenServiceDescriptor::create_with_client_auth(
            seed,
            encryption_public,
            intro_points.to_vec(),
            allium::hiddenservice::DEFAULT_HS_DESCRIPTOR_LIFETIME,
            Some(now),
            client_auth_keys,
        )
        .map_err(|e| e.to_string())?
    };
    let period = allium::hiddenservice::hs_directory_period(Some(now), None);
    let outer = allium::hsblind::seal_descriptor(seed, &inner, period).map_err(|e| e.to_string())?;
    let request = encode_hs3_publish_request(&outer).map_err(|e| e.to_string())?;
    Ok((inner, outer, request))
}

/// Periodically mint a fresh descriptor from this service's current
/// introduction points and publish it to the directory authority, over a
/// full circuit (never contacting the authority directly -- see
/// `dir_round_trip_over_circuit`'s doc). Runs until `stopping` is set.
fn publish_hs_descriptor(args: &Args, identity: &ServiceIdentity, intro_circuits: &[Arc<IntroCircuit>], stopping: &AtomicBool) {
    let interval = if args.publish_interval.unwrap_or(0.0) > 0.0 { args.publish_interval.unwrap() } else { crate::dirclient::DEFAULT_PUBLISH_INTERVAL };
    while !stopping.load(Ordering::SeqCst) {
        let intro_points: Vec<IntroPoint> = intro_circuits
            .iter()
            .map(|c| IntroPoint {
                relay_identity: c.descriptor.identity_public.clone(),
                host: c.descriptor.host.clone(),
                port: c.descriptor.port,
                auth_public: c.auth_public.clone(),
            })
            .collect();
        let result: Result<(), String> = (|| {
            let encryption_public = identity.encryption_public().map_err(|e| e.to_string())?.to_vec();
            let now = now_unix();
            let client_keys: Vec<[u8; 32]> = args.client_auth_keys.iter().filter_map(|k| <[u8; 32]>::try_from(k.as_slice()).ok()).collect();
            let (descriptor, outer, request) = build_publish_request(&identity.seed(), encryption_public, &intro_points, &client_keys, now)?;
            let authority_trusted = authority_trusted_keys(args);
            let mut args_for_round_trip = args.clone();
            let authority = primary_authority(args).unwrap_or_default();
            let reply = dir_round_trip_over_circuit(&mut args_for_round_trip, &authority, authority_trusted, &request, "service").map_err(|e| e.to_string())?;
            let (ok, message) = decode_hs3_publish_reply(&reply).map_err(|e| e.to_string())?;
            if ok {
                if !descriptor.client_auth.is_empty() {
                    say(&format!(
                        "service: published descriptor for {} (period {}, {} intro point(s), encrypted for {} authorized client(s)); next publish in {interval}s",
                        descriptor.address(),
                        outer.period,
                        intro_points.len(),
                        descriptor.client_auth.len()
                    ));
                } else {
                    say(&format!(
                        "service: published descriptor for {} (period {}, {} intro point(s)); next publish in {interval}s",
                        descriptor.address(),
                        outer.period,
                        intro_points.len()
                    ));
                }
            } else {
                say(&format!("service: authority REFUSED the descriptor: {message}"));
            }
            Ok(())
        })();
        if let Err(e) = result {
            say(&format!("service: could not reach the directory authority: {e}"));
        }
        if !sleep_or_wake(Duration::from_secs_f64(interval), stopping) {
            break;
        }
    }
}

fn authority_trusted_keys(args: &Args) -> Option<Vec<[u8; 32]>> {
    let value = args.trust_authority.as_deref()?;
    if value.is_empty() {
        return None;
    }
    let keys: Vec<[u8; 32]> = split_trust_keys(value).into_iter().filter_map(|hex| crate::helpers::hex_decode(&hex).ok()).filter_map(|v| v.try_into().ok()).collect();
    if keys.is_empty() {
        None
    } else {
        Some(keys)
    }
}

pub fn cmd_service(args: &Args) -> Result<(), CliExit> {
    let mut args = args.clone();
    run_service(&mut args)
}

fn run_service(args: &mut Args) -> Result<(), CliExit> {
    if args.authority.is_none() {
        return Err(CliExit::error(
            "service: --authority is required (or service.authority in --config) -- a hidden service is only \
             reachable through a directory authority's introduction-point lookup",
        ));
    }
    let (local_host, local_port) = parse_addr(args.hidden_service_port.as_deref().unwrap_or_default())?;

    let identity_file = args.identity_file.clone().unwrap_or_default();
    let identity = ServiceIdentity::load_or_create(std::path::Path::new(&identity_file)).map_err(|e| CliExit::error(format!("service: {e}")))?;
    say(&format!("service: address is {}", identity.address()));

    if let Some(hidden_service_dir) = args.hidden_service_dir.clone().filter(|s| !s.is_empty()) {
        let dir_path = std::path::Path::new(&hidden_service_dir);
        // This used to downgrade a chmod failure to a logged warning and
        // keep running with an
        // unhardened directory -- fatal now, matching
        // `ServiceIdentity::load_or_create`'s own identical hardening
        // step (`ensure_private_dir(p)?` in the library), which already
        // treats this as unrecoverable.
        ensure_private_dir(dir_path)
            .map_err(|e| CliExit::error(format!("service: could not restrict {hidden_service_dir} to permissions 0700: {e}")))?;
        let hostname_path = dir_path.join("hostname");
        match std::fs::write(&hostname_path, format!("{}\n", identity.address())) {
            Ok(()) => say(&format!("service: wrote {}", hostname_path.display())),
            Err(e) => say(&format!("service: could not write {}: {e}", hostname_path.display())),
        }
    }
    say(&format!(
        "service: forwarding to local server at {local_host}:{local_port} (make sure something -- nginx, Apache, a dev \
         server, ... -- is actually listening there)"
    ));

    // The guard is the first layer of the service's vanguards and only protects
    // anything if it survives a restart. It persists through a state file, but
    // the service command has no `--state-file` (that option is client-only), so
    // keep it in the service's own private directory.
    if let Some(path) = service_guard_state_path(args) {
        args.state_file = Some(path);
    }
    let (guard_addr, middle_addr, entry_trust) = resolve_entry_hops(args)?;
    if args.state_file.as_deref().filter(|f| !f.is_empty()).is_none() {
        say("service: NOTE: no --hidden-service-dir, so this service's guard is picked afresh on every start; pass --hidden-service-dir to keep it (a guard that changes with every restart gives an attacker a fresh chance each time)");
    }
    let vanguards_path = vanguard_state_path(args);
    match &vanguards_path {
        Some(path) => say(&format!("service: vanguard layers are kept in {path}")),
        None => say("service: NOTE: no --hidden-service-dir, so the vanguard layers are kept in memory only and are re-drawn on every start"),
    }
    let vanguards = Arc::new(VanguardState::new(vanguards_path));

    // Kept alive (as `directory_shared` below) for the lifetime of the
    // service, so every rendezvous point named in an incoming INTRODUCE2
    // can be checked against it, not just the introduction points chosen
    // here at startup.
    let directory = fetch_relay_directory(args, "service")?;
    let mut candidates: Vec<RelayDescriptor> = directory.by_role(ROLE_EXIT).into_iter().filter(|d| !d.behind_nat()).collect();
    if candidates.is_empty() {
        return Err(CliExit::error("service: no live exit-capable relay available to serve as an introduction point"));
    }
    // Which relays become this service's introduction points is
    // anonymity-relevant in the same way guard/middle/exit selection is,
    // so this needs a CSPRNG shuffle -- see `secure_index`'s doc.
    let mut shuffled = Vec::with_capacity(candidates.len());
    while !candidates.is_empty() {
        let idx = secure_index(candidates.len());
        shuffled.push(candidates.swap_remove(idx));
    }
    candidates = shuffled;
    let intro_count = args.intro_count.unwrap_or(3).max(1) as usize;
    let chosen = &candidates[..intro_count.min(candidates.len())];

    let mut intro_circuits: Vec<Arc<IntroCircuit>> = Vec::new();
    for relay_descriptor in chosen {
        match register_intro_point(args, guard_addr.clone(), middle_addr.clone(), &entry_trust, &identity, relay_descriptor, &directory, &vanguards) {
            Ok(circuit) => intro_circuits.push(Arc::new(circuit)),
            Err(e) => say(&format!("service: could not register at {}:{}: {e}", relay_descriptor.host, relay_descriptor.port)),
        }
    }
    if intro_circuits.is_empty() {
        return Err(CliExit::error("service: could not register with any introduction point"));
    }

    let stopping = Arc::new(AtomicBool::new(false));
    let identity = Arc::new(identity);
    let args_shared = Arc::new(args.clone());
    // Shared across every intro circuit's receive loop, so each one
    // validates rendezvous points against the same directory snapshot,
    // and every rendezvous thread across all intro points counts against
    // one shared in-flight cap.
    let directory_shared = Arc::new(directory);
    let inflight_rendezvous = RendezvousSlots::new();

    let mut receive_handles = Vec::new();
    for circuit in &intro_circuits {
        let args_shared = Arc::clone(&args_shared);
        let identity = Arc::clone(&identity);
        let circuit = Arc::clone(circuit);
        let entry_trust = entry_trust.clone();
        let guard_addr = guard_addr.clone();
        let middle_addr = middle_addr.clone();
        let stopping = Arc::clone(&stopping);
        let directory_shared = Arc::clone(&directory_shared);
        let inflight_rendezvous = Arc::clone(&inflight_rendezvous);
        let vanguards = Arc::clone(&vanguards);
        receive_handles.push(std::thread::spawn(move || {
            intro_receive_loop(
                args_shared,
                identity,
                circuit,
                entry_trust,
                guard_addr,
                middle_addr,
                stopping,
                directory_shared,
                inflight_rendezvous,
                vanguards,
            )
        }));
    }

    let publish_handle = {
        let args_for_publish = args.clone();
        let identity = Arc::clone(&identity);
        let intro_circuits = intro_circuits.clone();
        let stopping = Arc::clone(&stopping);
        std::thread::spawn(move || publish_hs_descriptor(&args_for_publish, &identity, &intro_circuits, &stopping))
    };

    say(&"=".repeat(68));
    say(&format!("Hidden service ready:  {}", identity.address()));
    say(&"=".repeat(68));
    let publish_interval = if args.publish_interval.unwrap_or(0.0) > 0.0 { args.publish_interval.unwrap() } else { crate::dirclient::DEFAULT_PUBLISH_INTERVAL };
    say(&format!(
        "Reachable through {} introduction point(s) once the directory authority has this descriptor (up to {publish_interval}s).",
        intro_circuits.len()
    ));
    say("Ctrl-C to stop.\n");

    crate::signals::install();
    while !crate::signals::should_stop() {
        std::thread::sleep(Duration::from_millis(150));
    }
    stopping.store(true, Ordering::SeqCst);

    let _ = publish_handle.join();
    for handle in receive_handles {
        let _ = handle.join();
    }
    Ok(())
}

// -- forward_tcp_to_session / forward_session_to_tcp (port of
// test_hs_forwarding.py) ----------------------------------------------------
//
// The Python original monkeypatches `_hs_send_over_builder`/
// `_hs_receive_message` to isolate these two functions' own sealing/
// unsealing, ordering and EOF/decrypt-failure handling from a real circuit
// -- this port's `send`/`receive` closure parameters (see each function's
// doc) are the same seam, exercised the same way, against a real local TCP
// connection exactly like the Python tests use (so the real `std::net`
// read/write behaviour is exercised, not just the crypto).
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn ensure_private_dir_creates_and_hardens_to_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("allium-hs-dir-test-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&dir);
        ensure_private_dir(&dir).expect("directory creation should succeed");
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "hidden-service directory must not be group/other-accessible");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_private_dir_fails_loudly_when_the_path_is_blocked_by_a_file() {
        // `run_service` propagates this failure as fatal
        // (`ensure_private_dir(dir_path)...?`) instead of
        // just logging a warning and continuing with an unhardened
        // directory -- this confirms the failure this depends on is a
        // real, detectable `Err`, not something that silently no-ops.
        let blocker = std::env::temp_dir().join(format!("allium-hs-dir-test-blocker-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_file(&blocker);
        std::fs::write(&blocker, b"not a directory").unwrap();
        let attempted_subdir = blocker.join("hidden_service");
        assert!(ensure_private_dir(&attempted_subdir).is_err());
        let _ = std::fs::remove_file(&blocker);
    }

    fn fresh_sessions() -> (HsSession, HsSession) {
        let secret = allium::osrand::bytes(32);
        let intro_secret = allium::osrand::bytes(32);
        let (key_c2s, key_s2c) = derive_session_keys(&secret, &intro_secret);
        let cookie = allium::osrand::bytes(32);
        let service = HsSession::new(&key_c2s, &key_s2c, &cookie, true).unwrap();
        let client = HsSession::new(&key_c2s, &key_s2c, &cookie, false).unwrap();
        (service, client)
    }

    #[test]
    fn forward_tcp_to_session_reads_until_eof_and_seals_each_chunk_in_order() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut sock, _peer) = listener.accept().unwrap();
            sock.write_all(b"chunk-one-").unwrap();
            sock.write_all(b"chunk-two").unwrap();
            // Dropping `sock` here half-closes the connection, so the
            // reader below sees a clean EOF once it has both chunks.
        });
        let reader = TcpStream::connect(addr).unwrap();
        server.join().unwrap();

        let (service_session, client_session) = fresh_sessions();
        let sealed_messages: Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = sealed_messages.clone();
        let stop = Arc::new(AtomicBool::new(false));

        forward_tcp_to_session(
            reader,
            Arc::new(service_session),
            move |message: &[u8]| {
                capture.lock().unwrap().push(message.to_vec());
                Ok(())
            },
            stop.clone(),
        );

        assert!(stop.load(Ordering::SeqCst));
        let sealed = sealed_messages.lock().unwrap();
        assert!(!sealed.is_empty(), "expected at least one sealed chunk");

        // Each captured message is a RENDEZVOUS_DATA-wrapped, sealed chunk
        // -- decrypting all of them and concatenating must reproduce
        // exactly what the local peer wrote, in order, regardless of how
        // TCP happened to chunk the bytes.
        //
        // The very last message must be the authenticated close, and
        // nothing may follow it.
        let mut plaintext = Vec::new();
        let (last, data_messages) = sealed.split_last().unwrap();
        for message in data_messages {
            let payload = decode_rendezvous_data(message).unwrap();
            plaintext.extend(client_session.open(&payload).unwrap());
        }
        assert_eq!(plaintext, b"chunk-one-chunk-two");
        let close = decode_rendezvous_data(last).unwrap();
        assert_eq!(client_session.open_frame(&close).unwrap(), HsFrame::Close);
        assert!(client_session.peer_closed());
    }

    #[test]
    fn forward_tcp_to_session_empty_read_sends_only_an_authenticated_close() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (sock, _peer) = listener.accept().unwrap();
            drop(sock); // closes immediately: zero bytes, then EOF
        });
        let reader = TcpStream::connect(addr).unwrap();
        server.join().unwrap();

        let (service_session, client_session) = fresh_sessions();
        let sealed_messages: Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = sealed_messages.clone();
        let stop = Arc::new(AtomicBool::new(false));

        forward_tcp_to_session(
            reader,
            Arc::new(service_session),
            move |message: &[u8]| {
                capture.lock().unwrap().push(message.to_vec());
                Ok(())
            },
            stop.clone(),
        );

        assert!(stop.load(Ordering::SeqCst));
        // no data was sealed; the only thing sent is the authenticated close
        let sent = sealed_messages.lock().unwrap();
        assert_eq!(sent.len(), 1);
        let close = decode_rendezvous_data(&sent[0]).unwrap();
        assert_eq!(client_session.open_frame(&close).unwrap(), HsFrame::Close);
    }

    #[test]
    fn forward_session_to_tcp_decrypts_and_writes_to_local_connection_in_order() {
        let (service_session, client_session) = fresh_sessions();
        let expected = b"GET / HTTP/1.1\r\nHost: x.allium\r\n\r\n".to_vec();
        let msg1 = encode_rendezvous_data(&client_session.seal(b"GET / HTTP/1.1\r\n").unwrap()).unwrap();
        let msg2 = encode_rendezvous_data(&client_session.seal(b"Host: x.allium\r\n\r\n").unwrap()).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let expected_len = expected.len();
        let server = thread::spawn(move || {
            let (mut sock, _peer) = listener.accept().unwrap();
            let mut received = Vec::new();
            let mut buf = [0u8; 4096];
            while received.len() < expected_len {
                let n = sock.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
            }
            received
        });

        let writer = TcpStream::connect(addr).unwrap();

        let mut queue = vec![msg1, msg2];
        let receive = move |_timeout: f64| -> std::io::Result<Vec<u8>> {
            if !queue.is_empty() {
                Ok(queue.remove(0))
            } else {
                // Give the server thread a moment to receive and return
                // before this is called again, mirroring the Python fake's
                // "give the event loop a chance to run" sleep.
                thread::sleep(Duration::from_millis(5));
                Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "no more fake messages"))
            }
        };

        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_loop = stop.clone();
        let handle = thread::spawn(move || {
            forward_session_to_tcp(writer, Arc::new(service_session), receive, 0.01, stop_for_loop);
        });

        let received = server.join().unwrap();
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert_eq!(received, expected);
    }

    #[test]
    fn forward_session_to_tcp_decrypt_failure_stops_the_loop() {
        let (service_session, _client_session) = fresh_sessions();
        // Sealed under a completely different session -- service_session
        // must fail to open it.
        let (_other_service, other_client) = fresh_sessions();
        let bad_message = encode_rendezvous_data(&other_client.seal(b"not for you").unwrap()).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut sock, _peer) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_millis(500))).ok();
            let mut buf = [0u8; 4096];
            match sock.read(&mut buf) {
                Ok(n) => buf[..n].to_vec(),
                Err(_) => Vec::new(),
            }
        });
        let writer = TcpStream::connect(addr).unwrap();

        let mut queue = vec![bad_message];
        let receive = move |_timeout: f64| -> std::io::Result<Vec<u8>> {
            if !queue.is_empty() {
                Ok(queue.remove(0))
            } else {
                Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "empty"))
            }
        };

        let stop = Arc::new(AtomicBool::new(false));
        forward_session_to_tcp(writer, Arc::new(service_session), receive, 0.01, stop.clone());
        assert!(stop.load(Ordering::SeqCst));

        let received = server.join().unwrap();
        assert!(received.is_empty());
    }

    /// Run `forward_session_to_tcp` over `messages`, returning what the local
    /// server received (until it saw EOF) and the session, to inspect afterwards.
    fn run_session_to_tcp(messages: Vec<Vec<u8>>, service_session: HsSession) -> (Vec<u8>, Arc<HsSession>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut sock, _peer) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(3))).ok();
            let mut received = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match sock.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => received.extend_from_slice(&buf[..n]),
                }
            }
            received
        });
        let writer = TcpStream::connect(addr).unwrap();
        let mut queue = messages;
        let receive = move |_timeout: f64| -> std::io::Result<Vec<u8>> {
            if !queue.is_empty() {
                Ok(queue.remove(0))
            } else {
                thread::sleep(Duration::from_millis(5));
                Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "no more fake messages"))
            }
        };
        let session = Arc::new(service_session);
        let stop = Arc::new(AtomicBool::new(false));
        // a watchdog so a regression that hangs the loop fails instead of stalling the suite
        let watchdog_stop = stop.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(4));
            watchdog_stop.store(true, Ordering::SeqCst);
        });
        let for_loop = session.clone();
        let stop_for_loop = stop.clone();
        let handle = thread::spawn(move || forward_session_to_tcp(writer, for_loop, receive, 0.01, stop_for_loop));
        let received = server.join().unwrap();
        handle.join().unwrap();
        (received, session)
    }

    fn data_message(client: &HsSession, bytes: &[u8]) -> Vec<u8> {
        encode_rendezvous_data(&client.seal(bytes).unwrap()).unwrap()
    }

    #[test]
    fn forward_session_to_tcp_delivers_a_replayed_frame_only_once_and_ends_on_close() {
        let (service_session, client_session) = fresh_sessions();
        let m0 = data_message(&client_session, b"POST /transfer ");
        let m1 = data_message(&client_session, b"amount=1");
        let close = encode_rendezvous_data(&client_session.seal_close().unwrap()).unwrap();
        // a malicious rendezvous point replays the first frame mid-stream
        let (received, session) = run_session_to_tcp(vec![m0.clone(), m0, m1, close], service_session);
        assert_eq!(received, b"POST /transfer amount=1", "the replayed request must not reach the local server twice");
        assert!(session.peer_closed(), "the authenticated close was seen");
    }

    #[test]
    fn forward_session_to_tcp_stops_when_a_frame_is_missing() {
        let (service_session, client_session) = fresh_sessions();
        let m0 = data_message(&client_session, b"part one ");
        let _lost = data_message(&client_session, b"part two ");
        let m2 = data_message(&client_session, b"part three");
        let (received, session) = run_session_to_tcp(vec![m0, m2], service_session);
        assert_eq!(received, b"part one ", "data after a hole in the stream must not be delivered");
        assert!(!session.peer_closed());
    }

    #[test]
    fn forward_session_to_tcp_does_not_deliver_frames_after_a_close() {
        let (service_session, client_session) = fresh_sessions();
        let (attacker_view, _) = fresh_sessions();
        let m0 = data_message(&client_session, b"done");
        let close = encode_rendezvous_data(&client_session.seal_close().unwrap()).unwrap();
        // frames that could only be injected after the close (sequence 2)
        attacker_view.seal(b"x").unwrap();
        attacker_view.seal(b"y").unwrap();
        let injected = data_message(&attacker_view, b"INJECTED");
        let (received, session) = run_session_to_tcp(vec![m0, close, injected], service_session);
        assert_eq!(received, b"done");
        assert!(session.peer_closed());
    }

    // -- rendezvous slots: total cap, per-relay share, release on every path --

    #[test]
    fn rendezvous_slots_one_relay_cannot_hold_more_than_its_share() {
        let slots = RendezvousSlots::new();
        let rp = vec![1u8; 32];
        let held: Vec<_> = (0..MAX_RENDEZVOUS_PER_RP).map(|_| slots.try_acquire(&rp).expect("within its share")).collect();
        assert!(slots.try_acquire(&rp).is_none(), "a relay named over and over cannot take more than its share");
        // other relays still get slots (the guard is kept alive so its slot stays counted)
        let other = slots.try_acquire(&[2u8; 32]);
        assert!(other.is_some());
        assert_eq!(slots.in_flight(), held.len() + 1);
    }

    #[test]
    fn rendezvous_slots_total_cap_holds_across_many_relays() {
        let slots = RendezvousSlots::new();
        let mut held = Vec::new();
        for i in 0..MAX_CONCURRENT_RENDEZVOUS {
            held.push(slots.try_acquire(&[(i % 250) as u8; 32]).expect("room left"));
        }
        assert_eq!(held.len(), MAX_CONCURRENT_RENDEZVOUS);
        assert_eq!(slots.in_flight(), MAX_CONCURRENT_RENDEZVOUS);
        assert!(slots.try_acquire(&[251u8; 32]).is_none());
    }

    #[test]
    fn rendezvous_slot_is_released_when_its_guard_drops_and_the_relays_share_with_it() {
        let slots = RendezvousSlots::new();
        let rp = vec![3u8; 32];
        let guards: Vec<_> = (0..MAX_RENDEZVOUS_PER_RP).map(|_| slots.try_acquire(&rp).unwrap()).collect();
        assert!(slots.try_acquire(&rp).is_none());
        drop(guards);
        assert_eq!(slots.in_flight(), 0);
        assert!(slots.inner.lock().unwrap().per_rp.is_empty(), "no per-relay counts left behind");
        assert!(slots.try_acquire(&rp).is_some());
    }

    #[test]
    fn rendezvous_slot_is_released_when_the_handling_thread_panics() {
        let slots = RendezvousSlots::new();
        let guard = slots.try_acquire(&[4u8; 32]).unwrap();
        let result = std::thread::spawn(move || {
            let _slot = guard;
            panic!("rendezvous handler blew up");
        })
        .join();
        assert!(result.is_err());
        assert_eq!(slots.in_flight(), 0, "a panicking handler must not leak its slot");
    }

    #[test]
    fn rendezvous_peer_wait_is_shorter_once_the_service_is_more_than_half_full() {
        assert_eq!(rendezvous_peer_wait_secs(0), RENDEZVOUS_PEER_WAIT_SECS);
        assert_eq!(rendezvous_peer_wait_secs(MAX_CONCURRENT_RENDEZVOUS / 2), RENDEZVOUS_PEER_WAIT_SECS);
        assert_eq!(rendezvous_peer_wait_secs(MAX_CONCURRENT_RENDEZVOUS / 2 + 1), RENDEZVOUS_PEER_WAIT_UNDER_LOAD_SECS);
        assert_eq!(rendezvous_peer_wait_secs(MAX_CONCURRENT_RENDEZVOUS), RENDEZVOUS_PEER_WAIT_UNDER_LOAD_SECS);
        // intended policy as literals: 30 s normally, 10 s under load
        assert_eq!((RENDEZVOUS_PEER_WAIT_SECS, RENDEZVOUS_PEER_WAIT_UNDER_LOAD_SECS), (30.0, 10.0));
    }

    // -- admitting an introduction: directory first, then a slot -------------

    fn rp_relay(host: &str, port: u16, roles: &[&str], nat: bool) -> RelayDescriptor {
        use allium::directory::{CreateOptions, EXT_REACHABILITY};
        let seed: [u8; 32] = allium::osrand::bytes(32).try_into().unwrap();
        let identity_private = SigningKey::from_bytes(&seed).to_bytes();
        let options = if nat {
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

    fn exit_relay(host: &str, port: u16) -> RelayDescriptor {
        rp_relay(host, port, &["exit"], false)
    }

    #[test]
    fn a_listed_exit_relay_is_admitted_at_the_directorys_address_and_holds_a_slot_until_dropped() {
        let honest = exit_relay("1.1.1.1", 9001);
        let directory = dir_of(&[&honest]);
        let slots = RendezvousSlots::new();
        let (rp, guard) = admit_introduction(&directory, &slots, &honest.identity_public).ok().expect("admitted");
        assert_eq!((rp.host.as_str(), rp.port), ("1.1.1.1", 9001), "the directory's address is what gets dialed");
        assert_eq!(slots.in_flight(), 1);
        drop(guard);
        assert_eq!(slots.in_flight(), 0, "the slot is released when the handling thread's guard drops");
    }

    #[test]
    fn a_relay_the_directory_does_not_list_is_refused_and_never_takes_a_slot() {
        let listed = exit_relay("1.1.1.1", 9001);
        let outsider = exit_relay("6.6.6.6", 9001); // well-formed, just not in the directory
        let directory = dir_of(&[&listed]);
        let slots = RendezvousSlots::new();
        for _ in 0..200 {
            let r = admit_introduction(&directory, &slots, &outsider.identity_public);
            assert_eq!(r.err(), Some(IntroductionRefusal::UnknownRendezvousPoint));
        }
        assert_eq!(slots.in_flight(), 0, "hostile introductions naming unlisted relays hold nothing");
        assert!(slots.inner.lock().unwrap().per_rp.is_empty());
        assert!(admit_introduction(&directory, &slots, &listed.identity_public).is_ok(), "an honest introduction is still served");
    }

    #[test]
    fn relays_that_are_not_exit_capable_or_are_behind_nat_are_refused() {
        let non_exit = rp_relay("1.1.1.1", 9001, &["guard", "middle"], false);
        let natted = rp_relay("2.2.2.2", 9002, &["exit"], true);
        assert!(natted.behind_nat());
        let directory = dir_of(&[&non_exit, &natted]);
        let slots = RendezvousSlots::new();
        for relay in [&non_exit, &natted] {
            assert_eq!(admit_introduction(&directory, &slots, &relay.identity_public).err(), Some(IntroductionRefusal::UnknownRendezvousPoint));
        }
        assert_eq!(slots.in_flight(), 0);
    }

    #[test]
    fn the_directory_is_checked_before_the_slots() {
        // Fill the service. An unlisted relay is still reported as unlisted (it was never a slot
        // question), and a listed one is reported as having no slot.
        let listed: Vec<RelayDescriptor> = (0..4).map(|i| exit_relay(&format!("1.1.1.{}", i + 1), 9001)).collect();
        let outsider = exit_relay("6.6.6.6", 9001);
        let directory = dir_of(&listed.iter().collect::<Vec<_>>());
        let slots = RendezvousSlots::new();
        let mut held = Vec::new();
        for relay in &listed {
            for _ in 0..MAX_RENDEZVOUS_PER_RP {
                held.push(admit_introduction(&directory, &slots, &relay.identity_public).ok().expect("room left"));
            }
        }
        assert_eq!(slots.in_flight(), MAX_CONCURRENT_RENDEZVOUS, "4 relays x their share fill the service");
        assert_eq!(admit_introduction(&directory, &slots, &outsider.identity_public).err(), Some(IntroductionRefusal::UnknownRendezvousPoint));
        assert_eq!(admit_introduction(&directory, &slots, &listed[0].identity_public).err(), Some(IntroductionRefusal::NoFreeSlot));
        assert_eq!(slots.in_flight(), MAX_CONCURRENT_RENDEZVOUS, "refusals took nothing");
    }

    #[test]
    fn one_hostile_relay_named_over_and_over_cannot_take_more_than_its_share_but_honest_ones_still_get_in() {
        let hostile = exit_relay("1.1.1.1", 9001); // a real listed exit that a client names and never joins
        let honest = exit_relay("2.2.2.2", 9002);
        let directory = dir_of(&[&hostile, &honest]);
        let slots = RendezvousSlots::new();
        let mut held = Vec::new();
        for _ in 0..MAX_RENDEZVOUS_PER_RP {
            held.push(admit_introduction(&directory, &slots, &hostile.identity_public).ok().expect("within its share"));
        }
        for _ in 0..50 {
            assert_eq!(admit_introduction(&directory, &slots, &hostile.identity_public).err(), Some(IntroductionRefusal::NoFreeSlot));
        }
        held.push(admit_introduction(&directory, &slots, &honest.identity_public).ok().expect("another relay is unaffected"));
        assert_eq!(slots.in_flight(), MAX_RENDEZVOUS_PER_RP + 1);
        // when the hostile relay's waits end, its share comes back
        held.drain(..MAX_RENDEZVOUS_PER_RP);
        assert!(admit_introduction(&directory, &slots, &hostile.identity_public).is_ok());
    }

    #[test]
    fn the_wait_for_the_clients_join_shortens_as_real_slots_fill_and_recovers_as_they_free() {
        let relays: Vec<RelayDescriptor> = (0..4).map(|i| exit_relay(&format!("1.1.1.{}", i + 1), 9001)).collect();
        let directory = dir_of(&relays.iter().collect::<Vec<_>>());
        let slots = RendezvousSlots::new();
        assert_eq!(peer_wait_for(&slots), RENDEZVOUS_PEER_WAIT_SECS);
        let mut held = Vec::new();
        // fill to exactly half the service: still the generous wait
        'fill: for relay in &relays {
            for _ in 0..MAX_RENDEZVOUS_PER_RP {
                if held.len() == MAX_CONCURRENT_RENDEZVOUS / 2 {
                    break 'fill;
                }
                held.push(admit_introduction(&directory, &slots, &relay.identity_public).ok().unwrap());
            }
        }
        assert_eq!((slots.in_flight(), peer_wait_for(&slots)), (MAX_CONCURRENT_RENDEZVOUS / 2, RENDEZVOUS_PEER_WAIT_SECS));
        // one more slot (counting the one being waited on) and a client that has not joined is shed sooner
        held.push(admit_introduction(&directory, &slots, &relays[3].identity_public).ok().unwrap());
        assert_eq!(peer_wait_for(&slots), RENDEZVOUS_PEER_WAIT_UNDER_LOAD_SECS);
        // load drops again: back to the generous wait
        held.pop();
        assert_eq!(peer_wait_for(&slots), RENDEZVOUS_PEER_WAIT_SECS);
    }

    // -- vanguard paths: guard, layer 2, layer 3, far end ----------------------

    /// Deterministic chooser for tests.
    struct Seeded(u64);
    impl Chooser for Seeded {
        fn below(&mut self, n: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % n as u64) as usize
        }
    }

    fn dir_relay(host: &str, port: u16) -> RelayDescriptor {
        use allium::directory::CreateOptions;
        let seed: [u8; 32] = allium::osrand::bytes(32).try_into().unwrap();
        let identity_private = SigningKey::from_bytes(&seed).to_bytes();
        RelayDescriptor::create(&identity_private, vec![7u8; 32], host, port, vec!["middle".to_string()], 86_400.0, None, CreateOptions::default()).unwrap()
    }

    fn dir_of(relays: &[&RelayDescriptor]) -> Directory {
        let mut d = Directory::new(allium::directory::DirectoryOptions::default()).unwrap();
        for r in relays {
            d.publish((*r).clone()).unwrap();
        }
        d
    }

    fn id32(d: &RelayDescriptor) -> [u8; 32] {
        d.identity_public.as_slice().try_into().unwrap()
    }

    /// A network: a guard, the old fixed middle, a far-end relay, and `extras`
    /// other relays, each in its own /16.
    struct Net {
        guard: RelayDescriptor,
        middle: RelayDescriptor,
        far: RelayDescriptor,
        all: Vec<RelayDescriptor>,
    }

    fn net(extras: usize) -> Net {
        let guard = dir_relay("1.1.1.1", 9001);
        let middle = dir_relay("2.2.2.2", 9002);
        let far = dir_relay("3.3.3.3", 9003);
        let mut all = vec![guard.clone(), middle.clone(), far.clone()];
        all.extend((0..extras).map(|i| dir_relay(&format!("{}.{}.0.1", 20 + i / 200, i % 200 + 1), 9100 + i as u16)));
        Net { guard, middle, far, all }
    }

    fn plan(n: &Net, vanguards: &VanguardState, now: f64, rng: &mut dyn Chooser, allow_short: bool, target_hop: &str) -> Result<HsPath, String> {
        let directory = dir_of(&n.all.iter().collect::<Vec<_>>());
        let entry_trust: HashMap<String, Vec<[u8; 32]>> = HashMap::from([("guard".to_string(), vec![id32(&n.guard)]), ("middle".to_string(), vec![id32(&n.middle)])]);
        plan_hs_path(
            target_hop,
            now,
            rng,
            &directory,
            vanguards,
            allow_short,
            &entry_trust,
            &HashMap::new(),
            (n.guard.host.clone(), n.guard.port),
            (n.middle.host.clone(), n.middle.port),
            id32(&n.far),
            (n.far.host.clone(), n.far.port),
            None,
        )
    }

    const NOW: f64 = 2_000_000.0;

    #[test]
    fn the_path_is_guard_layer2_layer3_far_end_with_every_hop_pinned() {
        let n = net(30);
        let state = VanguardState::new(None);
        let path = plan(&n, &state, NOW, &mut Seeded(1), false, "rendezvous").unwrap();
        let names: Vec<&str> = path.hops.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["guard", "vanguard-2", "vanguard-3", "rendezvous"]);
        assert_eq!(path.hops[0].1, (n.guard.host.clone(), n.guard.port));
        assert_eq!(path.hops[3].1, (n.far.host.clone(), n.far.port));
        for name in ["guard", "vanguard-2", "vanguard-3", "rendezvous"] {
            assert_eq!(path.trust.get(name).map(Vec::len), Some(1), "hop {name} must be pinned");
        }
        assert_eq!(path.trust["rendezvous"], vec![id32(&n.far)]);
        // the vanguards are dialed at the directory's address for the pinned identity
        for name in ["vanguard-2", "vanguard-3"] {
            let hop = path.hops.iter().find(|(h, _)| h == name).unwrap();
            let relay = n.all.iter().find(|d| id32(d) == path.trust[name][0]).expect("a directory relay");
            assert_eq!(hop.1, (relay.host.clone(), relay.port));
        }
    }

    /// The old fixed "middle" slot is gone from every path (the relay that used
    /// to fill it may still turn up as an ordinary vanguard), and no relay
    /// appears twice in one path.
    #[test]
    fn there_is_no_fixed_middle_slot_and_no_hop_repeats() {
        let n = net(30);
        let state = VanguardState::new(None);
        for seed in 0..200u64 {
            let path = plan(&n, &state, NOW, &mut Seeded(seed + 1), false, "rendezvous").unwrap();
            assert!(!path.hops.iter().any(|(name, _)| name == "middle"), "the fixed middle must not be a hop");
            assert!(!path.trust.contains_key("middle") || path.hops.iter().all(|(name, _)| name != "middle"));
            let ids: Vec<[u8; 32]> = ["guard", "vanguard-2", "vanguard-3", "rendezvous"].iter().map(|h| path.trust[*h][0]).collect();
            assert_eq!(ids.iter().collect::<std::collections::HashSet<_>>().len(), 4, "hops must all differ");
        }
    }

    /// The property that makes this worth doing: however many circuits are
    /// built within the layers' lifetime, only a small, fixed set of relays
    /// ever appears in the two middle positions -- not a fresh draw each time.
    #[test]
    fn many_circuits_only_ever_touch_the_small_persistent_layers() {
        let n = net(60);
        let state = VanguardState::new(None);
        let mut layer2 = std::collections::HashSet::new();
        let mut layer3 = std::collections::HashSet::new();
        for i in 0..1000u64 {
            // all within the shortest layer-3 lifetime (30 minutes)
            let path = plan(&n, &state, NOW + i as f64, &mut Seeded(i + 7), false, if i % 2 == 0 { "rendezvous" } else { "intro" }).unwrap();
            layer2.insert(path.trust["vanguard-2"][0]);
            layer3.insert(path.trust["vanguard-3"][0]);
        }
        assert!(layer2.len() <= crate::vanguards::L2_TARGET, "{} distinct layer-2 relays", layer2.len());
        assert!(layer3.len() <= crate::vanguards::L3_TARGET, "{} distinct layer-3 relays", layer3.len());
        assert!(layer2.is_disjoint(&layer3));
    }

    #[test]
    fn intro_circuits_get_the_same_treatment_and_pin_the_intro_relay_with_its_pq_key() {
        let n = net(30);
        let state = VanguardState::new(None);
        let directory = dir_of(&n.all.iter().collect::<Vec<_>>());
        let entry_trust: HashMap<String, Vec<[u8; 32]>> = HashMap::from([("guard".to_string(), vec![id32(&n.guard)])]);
        let path = plan_hs_path(
            "intro",
            NOW,
            &mut Seeded(5),
            &directory,
            &state,
            false,
            &entry_trust,
            &HashMap::new(),
            (n.guard.host.clone(), n.guard.port),
            (n.middle.host.clone(), n.middle.port),
            id32(&n.far),
            (n.far.host.clone(), n.far.port),
            Some(vec![9u8; 4]),
        )
        .unwrap();
        let names: Vec<&str> = path.hops.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["guard", "vanguard-2", "vanguard-3", "intro"]);
        assert_eq!(path.kem_keys.get("intro"), Some(&vec![9u8; 4]));
        assert_eq!(path.trust["intro"], vec![id32(&n.far)]);
    }

    /// A restart must not re-draw layers that have not expired.
    #[test]
    fn a_restart_keeps_the_same_layers() {
        let n = net(40);
        let dir = std::env::temp_dir().join(format!("allium-vg-restart-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("vanguards.state").to_string_lossy().into_owned();

        let first = VanguardState::new(Some(path.clone()));
        for i in 0..50u64 {
            plan(&n, &first, NOW + i as f64, &mut Seeded(i + 1), false, "rendezvous").unwrap();
        }
        let saved = first.inner.lock().unwrap().clone();
        assert!(!saved.l2.is_empty() && !saved.l3.is_empty());
        drop(first);

        let second = VanguardState::new(Some(path.clone())); // "restart"
        assert_eq!(*second.inner.lock().unwrap(), saved, "the layers must come back from disk exactly");
        for i in 0..50u64 {
            plan(&n, &second, NOW + 300.0 + i as f64, &mut Seeded(i + 9999), false, "rendezvous").unwrap();
        }
        assert_eq!(*second.inner.lock().unwrap(), saved, "using them after a restart must not re-draw anything that has not expired");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_network_too_small_for_vanguards_is_refused_unless_explicitly_allowed() {
        let n = net(0); // guard, middle and the far end only
        let state = VanguardState::new(None);
        let err = plan(&n, &state, NOW, &mut Seeded(1), false, "rendezvous").err().expect("must refuse by default");
        assert!(err.contains("--allow-short-rendezvous"), "the error must name the override: {err}");
        let path = plan(&n, &state, NOW, &mut Seeded(1), true, "rendezvous").unwrap();
        let names: Vec<&str> = path.hops.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["guard", "middle", "rendezvous"], "the opt-in builds the old short path");
        assert!(!path.trust.contains_key("vanguard-2"));
    }

    #[test]
    fn the_state_file_lives_in_the_service_directory_else_beside_the_state_file() {
        let mut args = Args::default();
        assert_eq!(vanguard_state_path(&args), None);
        args.state_file = Some("/var/lib/allium/state".to_string());
        assert_eq!(vanguard_state_path(&args).as_deref(), Some("/var/lib/allium/state.vanguards"));
        args.hidden_service_dir = Some("/var/lib/allium/hs".to_string());
        assert_eq!(vanguard_state_path(&args).as_deref(), Some("/var/lib/allium/hs/vanguards.state"));
        args.hidden_service_dir = Some(String::new());
        assert_eq!(vanguard_state_path(&args).as_deref(), Some("/var/lib/allium/state.vanguards"), "an empty directory setting counts as unset");
    }

    #[test]
    fn four_hops_still_leave_room_in_each_cell_for_data() {
        let three = allium::sizes::user_data_budget(3, allium::cell::PAYLOAD_SIZE).unwrap();
        let four = allium::sizes::user_data_budget(4, allium::cell::PAYLOAD_SIZE).unwrap();
        assert!(four < three && four > 700, "four hops leave {four} bytes per cell (three leave {three})");
    }

    // -- version 3 publish ---------------------------------------------------------

    fn publish_intro_points() -> Vec<IntroPoint> {
        vec![IntroPoint { relay_identity: vec![1u8; 32], host: "198.51.100.7".to_string(), port: 9001, auth_public: vec![2u8; 32] }]
    }

    fn service_identity(seed: &[u8; 32]) -> [u8; 32] {
        SigningKey::from_bytes(seed).verifying_key().to_bytes()
    }

    const PUBLISH_NOW: f64 = 1_700_000_000.0;

    #[test]
    fn the_publish_request_is_for_the_current_period_and_opens_for_the_address() {
        let seed = [0x42u8; 32];
        let (inner, outer, request) = build_publish_request(&seed, vec![9u8; 32], &publish_intro_points(), &[], PUBLISH_NOW).unwrap();
        let period = allium::hiddenservice::hs_directory_period(Some(PUBLISH_NOW), None);
        assert_eq!(outer.period, period, "only the current period is published");
        let decoded = allium::dirwire::decode_hs3_publish_request(&request).unwrap();
        assert_eq!(decoded, outer);
        let opened = allium::hsblind::open_descriptor(&decoded, &service_identity(&seed), period, PUBLISH_NOW + 5.0).unwrap();
        assert_eq!(opened, inner);
        assert_eq!(opened.intro_points_for(None).unwrap(), publish_intro_points());
    }

    #[test]
    fn the_publish_request_names_neither_the_service_nor_what_it_says() {
        let seed = [0x42u8; 32];
        let identity = service_identity(&seed);
        let (inner, _, request) = build_publish_request(&seed, vec![0x99u8; 32], &publish_intro_points(), &[], PUBLISH_NOW).unwrap();
        let contains = |needle: &[u8]| request.windows(needle.len()).any(|w| w == needle);
        assert!(!contains(&identity));
        assert!(!contains(inner.address().as_bytes()));
        assert!(!contains(&[0x99u8; 32]), "the encryption key");
        assert!(!contains(b"198.51.100.7"), "an intro point host");
        assert!(!contains(&[1u8; 32]) && !contains(&[2u8; 32]), "intro point keys");
    }

    #[test]
    fn publishes_in_different_periods_share_nothing_a_directory_could_link() {
        let seed = [0x42u8; 32];
        let day = allium::hiddenservice::HS_DIRECTORY_INDEX_PERIOD;
        let (_, a, req_a) = build_publish_request(&seed, vec![9u8; 32], &publish_intro_points(), &[], PUBLISH_NOW).unwrap();
        let (_, b, req_b) = build_publish_request(&seed, vec![9u8; 32], &publish_intro_points(), &[], PUBLISH_NOW + day).unwrap();
        assert_ne!(a.blinded_public, b.blinded_public);
        assert_ne!(a.period, b.period);
        // not even a 16-byte run is common to the two requests apart from the fixed header
        let runs: std::collections::HashSet<&[u8]> = req_a[5..].windows(16).collect();
        assert!(!req_b[5..].windows(16).any(|w| runs.contains(w)), "two periods' publishes share bytes");
    }

    #[test]
    fn client_authorization_survives_the_blinded_publish() {
        use x25519_dalek::{PublicKey, StaticSecret};
        let seed = [0x42u8; 32];
        let client_private = [0x5Au8; 32];
        let client_public = PublicKey::from(&StaticSecret::from(client_private)).to_bytes();
        let (inner, outer, _) = build_publish_request(&seed, vec![9u8; 32], &publish_intro_points(), &[client_public], PUBLISH_NOW).unwrap();
        assert_eq!(inner.client_auth.len(), 1);
        let opened = allium::hsblind::open_descriptor(&outer, &service_identity(&seed), outer.period, PUBLISH_NOW).unwrap();
        assert!(opened.intro_points_for(None).is_err(), "knowing only the address does not reveal the intro points");
        assert_eq!(opened.intro_points_for(Some(&client_private)).unwrap(), publish_intro_points());
    }

    #[test]
    fn the_services_guard_is_kept_in_its_private_directory() {
        let mut args = Args::default();
        assert_eq!(service_guard_state_path(&args), None, "nowhere to keep it");
        args.hidden_service_dir = Some("/var/lib/allium/hs".to_string());
        assert_eq!(service_guard_state_path(&args).as_deref(), Some("/var/lib/allium/hs/guard.state"));
        args.hidden_service_dir = Some(String::new());
        assert_eq!(service_guard_state_path(&args), None, "an empty directory setting counts as unset");
        // an explicit state file is left alone
        args.hidden_service_dir = Some("/var/lib/allium/hs".to_string());
        args.state_file = Some("/elsewhere/state".to_string());
        assert_eq!(service_guard_state_path(&args), None);
    }
}
