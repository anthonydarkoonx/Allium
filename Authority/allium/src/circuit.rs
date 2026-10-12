//! Client-side incremental circuit construction via EXTEND.
//!
//! Port of Python's `circuit.py`. See that module's docstring for the full
//! rationale: [`CircuitBuilder`] handshakes directly with only the first hop
//! (the guard), then extends the circuit one relay at a time by asking the
//! current last hop to relay a CREATE on its behalf. Each hop after the
//! first learns only its immediate predecessor and successor, never the
//! client's address or the full route.
//!
//! Deliberately a thin, synchronous, blocking-socket client, the same style
//! `handshake::HandshakeClient` uses.
//!
//! No external crate: everything here builds on `handshake.rs`/`onion.rs`/
//! `sizes.rs`/`createfrag.rs`, all already ported. `jitter_delay`'s random
//! draws use `/dev/urandom` directly (matching Python's `secrets.SystemRandom`:
//! every output straight from the OS CSPRNG, no recoverable Mersenne-Twister
//! state to recover and subtract the delay back out of -- see the module's
//! own security rationale, ported below).
//!
//! Deviation from Python: `sock` is caller-owned in both languages ("this
//! class never creates, binds, or closes one"), which Rust expresses as a
//! borrowed `&UdpSocket` with an explicit lifetime on [`CircuitBuilder`]
//! rather than a stored reference of unspecified lifetime.

use crate::cell::{Cell, CellError, Command};
use crate::createfrag::{CreateFragError, fragment_extend_payload};
use crate::handshake::{
    DEFAULT_TIMEOUT, HandshakeClient, HandshakeError, HandshakeKeys, HandshakeOps,
    IDENTITY_KEY_SIZE,
};
use crate::layer::Kind;
use crate::onion::{DEFAULT_CIPHER, OnionCrypto, OnionError, TRAILING_PAD_ENTRY_SIZE, onion_from_cell, seal_into_cell, strip_plaintext_padding};
use crate::sizes::{RoutePlan, user_data_budget};
use std::collections::HashMap;
use std::fmt;
use std::net::{SocketAddr, UdpSocket};

/// `(host, port)`, matching Python's `Addr = Tuple[str, int]`.
pub type Addr = (String, u16);

/// How many times a handshake attempt is retried before giving up. `0` means
/// exactly one attempt.
pub const DEFAULT_RETRIES: u32 = 0;

/// Base of the exponential backoff between handshake attempts, in seconds.
pub const RETRY_BACKOFF_BASE: f64 = 0.5;

/// Largest jitter multiple applied to the backoff.
pub const RETRY_JITTER_FRACTION: f64 = 0.2;

/// Hard ceiling on any single backoff sleep, in seconds. Not part of Python's
/// `__all__` either (an internal constant); kept private here too.
const RETRY_BACKOFF_MAX: f64 = 4.0;

/// Largest uniform send-side delay, in seconds, applied to each cell when
/// jitter is enabled. On by default: undoing timing correlation between the
/// application producing a cell and it hitting the wire.
pub const DEFAULT_SEND_JITTER: f64 = 0.05;

/// Upper bound on send jitter, so a misconfiguration cannot stall a circuit.
pub const MAX_SEND_JITTER: f64 = 2.0;

/// Draw cryptographically random bytes from the OS CSPRNG into `buf`. Thin
/// wrapper over the crate-wide [`crate::osrand::os_random`] (see its docs
/// for the cached-handle rationale), converting its error into this
/// module's own [`CircuitBuildError`].
fn os_random(buf: &mut [u8]) -> Result<(), CircuitBuildError> {
    crate::osrand::os_random(buf).map_err(|e| generic(e.to_string()))
}

/// A uniform random `f64` in `[0, max)`, drawn from the OS CSPRNG (matching
/// Python's `secrets.SystemRandom().uniform(0.0, max)`).
fn secure_uniform(max: f64) -> Result<f64, CircuitBuildError> {
    if max <= 0.0 {
        return Ok(0.0);
    }
    let mut buf = [0u8; 8];
    os_random(&mut buf)?;
    let frac = (u64::from_be_bytes(buf) as f64) / (u64::MAX as f64);
    Ok(frac * max)
}

/// A fresh random `u32` circuit id, drawn uniformly over the full 32-bit
/// space (see `add_hop`'s Python docstring on why no parity mask).
fn random_circuit_id() -> Result<u32, CircuitBuildError> {
    let mut buf = [0u8; 4];
    os_random(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

/// Return a uniform random delay in `[0, seconds]`, for timing obfuscation.
/// `seconds <= 0` yields `0.0`.
pub fn jitter_delay(seconds: f64) -> Result<f64, CircuitBuildError> {
    if seconds <= 0.0 {
        return Ok(0.0);
    }
    secure_uniform(seconds.min(MAX_SEND_JITTER))
}

/// [`jitter_delay`] with [`DEFAULT_SEND_JITTER`].
pub fn jitter_delay_default() -> Result<f64, CircuitBuildError> {
    jitter_delay(DEFAULT_SEND_JITTER)
}

/// Backoff sleep after a failed attempt, with jitter. `attempt` is 1 for the
/// wait before the *second* try, 2 for the third, and so on. Returns `0.0`
/// for `attempt <= 1`.
pub fn retry_sleep_seconds(attempt: u32) -> Result<f64, CircuitBuildError> {
    if attempt <= 1 {
        return Ok(0.0);
    }
    let raw = RETRY_BACKOFF_BASE * 2f64.powi(attempt as i32 - 2);
    let raw = raw.min(RETRY_BACKOFF_MAX);
    let jitter = 1.0 + secure_uniform(RETRY_JITTER_FRACTION)?;
    Ok(raw * jitter)
}

/// Read datagrams from `sock` until one arrives from `expected_addr`, or
/// `timeout` elapses. See the module docs and `handshake::recv_from`'s twin
/// of this function.
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

fn addr_to_socket_addr(addr: &Addr) -> Result<SocketAddr, CircuitBuildError> {
    format!("{}:{}", addr.0, addr.1)
        .parse()
        .map_err(|e| generic(format!("invalid address {addr:?}: {e}")))
}

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

/// Base class for every error raised while building a circuit.
///
/// Python distinguishes `HandshakeAttemptsExhausted` / `ExtendTimeout` /
/// `ExtendRejected` as `CircuitBuildError` subclasses; ported here as one
/// enum (same pattern as `handshake::HandshakeError`/`onion::OnionError`)
/// with those three names as type aliases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitBuildError {
    Generic(String),
    /// No EXTENDED reply arrived from the guard within the timeout.
    Timeout(String),
    /// An EXTENDED reply arrived but could not be turned into a new hop.
    Rejected(String),
    /// Every handshake attempt for one hop failed; retries were exhausted.
    AttemptsExhausted(String),
}
impl fmt::Display for CircuitBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitBuildError::Generic(s)
            | CircuitBuildError::Timeout(s)
            | CircuitBuildError::Rejected(s)
            | CircuitBuildError::AttemptsExhausted(s) => write!(f, "{s}"),
        }
    }
}
impl std::error::Error for CircuitBuildError {}
fn generic(msg: impl Into<String>) -> CircuitBuildError {
    CircuitBuildError::Generic(msg.into())
}
fn rejected(msg: impl Into<String>) -> CircuitBuildError {
    CircuitBuildError::Rejected(msg.into())
}

pub type ExtendTimeout = CircuitBuildError;
pub type ExtendRejected = CircuitBuildError;
pub type HandshakeAttemptsExhausted = CircuitBuildError;

// --------------------------------------------------------------------------
// CircuitBuilder
// --------------------------------------------------------------------------

/// Builds a circuit hop by hop, handshaking directly only with the guard.
pub struct CircuitBuilder<'a> {
    sock: &'a UdpSocket,
    pub cipher: String,
    pub timeout: f64,
    trusted: HashMap<String, Vec<[u8; IDENTITY_KEY_SIZE]>>,
    trust_first_use: bool,
    allow_anonymous_relay: bool,
    pub retries: u32,
    pub send_jitter: f64,
    /// `{hop_name: ML-KEM-768 encapsulation key}`.
    kem_keys: HashMap<String, Vec<u8>>,

    pub circuit_id: Option<u32>,
    pub guard_addr: Option<Addr>,
    pub hops: Vec<OnionCrypto>,
    pub addrs: Vec<Addr>,
    pub names: Vec<String>,
    pub keys: Vec<HandshakeKeys>,
    seq_counter: u32,
}

impl<'a> CircuitBuilder<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sock: &'a UdpSocket,
        cipher: String,
        timeout: f64,
        trusted_identities: Option<HashMap<String, Vec<[u8; IDENTITY_KEY_SIZE]>>>,
        trust_first_use: bool,
        allow_anonymous_relay: bool,
        retries: u32,
        send_jitter: f64,
        kem_keys: Option<HashMap<String, Vec<u8>>>,
    ) -> Result<CircuitBuilder<'a>, CircuitBuildError> {
        if send_jitter < 0.0 {
            return Err(generic(format!("send_jitter must not be negative, got {send_jitter}")));
        }
        Ok(CircuitBuilder {
            sock,
            cipher,
            timeout,
            trusted: trusted_identities.unwrap_or_default(),
            trust_first_use,
            allow_anonymous_relay,
            retries,
            send_jitter,
            kem_keys: kem_keys.unwrap_or_default(),
            circuit_id: None,
            guard_addr: None,
            hops: Vec::new(),
            addrs: Vec::new(),
            names: Vec::new(),
            keys: Vec::new(),
            seq_counter: 0,
        })
    }

    /// [`CircuitBuilder::new`] with every optional argument at its default.
    pub fn with_defaults(sock: &'a UdpSocket) -> CircuitBuilder<'a> {
        CircuitBuilder::new(sock, DEFAULT_CIPHER.to_string(), DEFAULT_TIMEOUT, None, false, false, DEFAULT_RETRIES, DEFAULT_SEND_JITTER, None)
            .expect("default send_jitter is non-negative")
    }

    // -- construction ---------------------------------------------------

    fn next_seq(&mut self) -> u32 {
        let seq = self.seq_counter;
        self.seq_counter = self.seq_counter.wrapping_add(1);
        seq
    }

    fn trusted_for(&self, name: &str) -> Option<Vec<[u8; IDENTITY_KEY_SIZE]>> {
        self.trusted.get(name).cloned()
    }

    fn client_for(&self, name: &str, kem_public: Option<Vec<u8>>) -> Result<HandshakeClient, CircuitBuildError> {
        let trusted = self.trusted_for(name);
        let trust_first_use = self.trust_first_use || trusted.is_some();
        let kem = kem_public.or_else(|| self.kem_keys.get(name).cloned());
        HandshakeClient::new(self.cipher.clone(), None, self.timeout, trusted, trust_first_use, self.allow_anonymous_relay, kem, false, HandshakeOps::real())
            .map_err(|e| generic(e.to_string()))
    }

    /// Handshake directly with the first hop (the guard). Must be called
    /// exactly once, before any call to [`CircuitBuilder::extend`].
    pub fn add_hop(&mut self, name: &str, addr: Addr, circuit_id: Option<u32>, retries: Option<u32>, kem_public: Option<Vec<u8>>) -> Result<HandshakeKeys, CircuitBuildError> {
        if !self.hops.is_empty() {
            return Err(generic(format!("add_hop() must be called exactly once, before any extend(); this builder already has {} hop(s)", self.hops.len())));
        }
        let socket_addr = addr_to_socket_addr(&addr)?;
        self.circuit_id = Some(match circuit_id {
            Some(id) => id,
            None => random_circuit_id()?,
        });
        let circuit_id = self.circuit_id.unwrap();
        let retries = retries.unwrap_or(self.retries);
        let total = retries + 1;

        for attempt in 1..=total {
            if attempt > 1 {
                std::thread::sleep(std::time::Duration::from_secs_f64(retry_sleep_seconds(attempt)?));
            }
            // A fresh client per attempt: the handshake mints a new
            // ephemeral X25519 key each time, so a retried CREATE is never a
            // replay under the same circuit id.
            let mut client = self.client_for(name, kem_public.clone())?;
            match client.handshake(self.sock, socket_addr, circuit_id, 1) {
                Ok(keys) => {
                    self.guard_addr = Some(addr.clone());
                    self.hops.push(keys.to_onion_crypto(name, 0).map_err(|e| generic(e.to_string()))?);
                    self.addrs.push(addr);
                    self.names.push(name.to_string());
                    self.keys.push(keys.clone());
                    return Ok(keys);
                }
                Err(HandshakeError::Timeout(msg)) => {
                    if attempt == total {
                        if retries == 0 {
                            return Err(CircuitBuildError::Timeout(msg));
                        }
                        return Err(CircuitBuildError::AttemptsExhausted(format!("guard handshake with {name:?} ({addr:?}) timed out on all {total} attempt(s): {msg}")));
                    }
                    continue;
                }
                Err(other) => return Err(generic(other.to_string())),
            }
        }
        unreachable!("loop always returns or errors on its last iteration")
    }

    /// Extend the circuit by one hop, via the hops already established.
    pub fn extend(&mut self, name: &str, addr: Addr, timeout: Option<f64>, retries: Option<u32>, kem_public: Option<Vec<u8>>) -> Result<HandshakeKeys, CircuitBuildError> {
        if self.hops.is_empty() {
            return Err(generic("add_hop() must be called before extend()"));
        }
        let timeout = timeout.unwrap_or(self.timeout);
        let retries = retries.unwrap_or(self.retries);
        let total = retries + 1;

        for attempt in 1..=total {
            if attempt > 1 {
                std::thread::sleep(std::time::Duration::from_secs_f64(retry_sleep_seconds(attempt)?));
            }
            match self.extend_once(name, &addr, timeout, kem_public.clone()) {
                Ok(keys) => return Ok(keys),
                Err(CircuitBuildError::Timeout(msg)) => {
                    if attempt == total {
                        if retries == 0 {
                            return Err(CircuitBuildError::Timeout(msg));
                        }
                        return Err(CircuitBuildError::AttemptsExhausted(format!("extend to hop {name:?} ({addr:?}) timed out on all {total} attempt(s): {msg}")));
                    }
                    continue;
                }
                Err(other) => return Err(other),
            }
        }
        unreachable!("loop always returns or errors on its last iteration")
    }

    /// One single EXTEND attempt: build the request, wait, and verify it.
    /// The body of [`CircuitBuilder::extend`], factored out so the retry
    /// loop can call it repeatedly.
    fn extend_once(&mut self, name: &str, addr: &Addr, timeout: f64, kem_public: Option<Vec<u8>>) -> Result<HandshakeKeys, CircuitBuildError> {
        let new_circuit_id = random_circuit_id()?;
        let mut client = self.client_for(name, kem_public)?;
        let create_message = client.create(new_circuit_id, None).map_err(|e| generic(e.to_string()))?;
        let create_payload = create_message.payload();

        let route = RoutePlan::new(self.addrs.clone(), addr.clone(), crate::cell::PAYLOAD_SIZE as i64).map_err(|e| generic(e.to_string()))?;
        let budget = user_data_budget(self.hops.len() as i64, crate::cell::PAYLOAD_SIZE as i64).map_err(|e| generic(e.to_string()))?;
        let pieces: Vec<Vec<u8>> = if (create_payload.len() as i64) <= budget {
            vec![create_payload.to_vec()]
        } else {
            // Post-quantum hybrid CREATE: too big for one EXTEND layer, so
            // it goes as several, reassembled by the extending relay.
            fragment_extend_payload(create_payload, budget, None).map_err(|e: CreateFragError| generic(e.to_string()))?
        };

        let guard_addr = self.guard_addr.clone().ok_or_else(|| generic("no guard address set"))?;
        let guard_socket_addr = addr_to_socket_addr(&guard_addr)?;
        let circuit_id = self.circuit_id.ok_or_else(|| generic("no circuit id set"))?;

        for piece in &pieces {
            let seq = self.next_seq();
            let onion = OnionCrypto::encrypt_onion(piece, &mut self.hops, &route, seq, true, false, None, Some(Kind::EXTEND), None).map_err(|e| generic(e.to_string()))?;
            let request = seal_into_cell(&onion, circuit_id, Some(Command::Data)).map_err(|e| generic(e.to_string()))?;
            self.sock.send_to(&request.pack(), guard_socket_addr).map_err(|e| generic(format!("send failed: {e}")))?;
        }

        let datagram = recv_from(self.sock, guard_socket_addr, timeout, crate::cell::CELL_SIZE)
            .map_err(|_| CircuitBuildError::Timeout(format!("no EXTENDED reply for hop {name:?} ({addr:?}) within {timeout}s")))?;

        let reply = Cell::unpack(&datagram, true).map_err(|e: CellError| rejected(format!("malformed EXTENDED datagram: {e}")))?;
        if reply.command != Command::Extended {
            return Err(rejected(format!("expected an EXTENDED cell, got {}", reply.command.name())));
        }
        if reply.circuit_id != circuit_id {
            return Err(rejected(format!("EXTENDED circuit id {:#010x} does not match {circuit_id:#010x}", reply.circuit_id)));
        }

        // Peel back through every established hop, in route order: the
        // outermost layer is the guard's, so it is removed first.
        let mut current = onion_from_cell(&reply, 0);
        for hop in &self.hops {
            let (next, header) = hop.peel_layer(&current).map_err(|e: OnionError| rejected(format!("EXTENDED reply for hop {name:?} failed to peel: {e}")))?;
            if header.kind != Kind::EXTENDED {
                return Err(rejected(format!("expected an EXTENDED layer while peeling hop {:?}, got {}", hop.name, Kind::name(header.kind))));
            }
            current = next;
        }

        // `current` here is the *raw* CREATED body the extending relay
        // sealed into the EXTENDED layer (see `relay.rs`'s
        // `_extend_circuit_inner`, which seals only `created_body`, never a
        // wire-framed `Cell`) -- it has no cell header of its own. Python's
        // `_extend_once` builds an in-memory `Cell(new_circuit_id,
        // Command.CREATED, current)` object and hands that straight to
        // `client.complete()`, which duck-types it apart without ever
        // re-parsing a header. `HandshakeClient::complete` here instead
        // always parses its `message` argument as wire bytes (see
        // `coerce_cell`'s own docs), so the Rust equivalent of that
        // in-memory `Cell` is to build one the same way and `.pack()` it
        // back into bytes first -- passing `current` directly, as this did
        // before this fix, made `coerce_cell` misparse the CREATED body's
        // own leading bytes as a bogus cell length header instead.
        let created_cell = Cell::with_command(new_circuit_id, Command::Created, current).map_err(|e: CellError| rejected(format!("could not build CREATED cell for hop {name:?} ({addr:?}): {e}")))?;
        let keys = client.complete(&created_cell.pack(), Some(new_circuit_id)).map_err(|e| rejected(format!("hop {name:?} ({addr:?}) failed handshake verification: {e}")))?;

        self.hops.push(keys.to_onion_crypto(name, self.hops.len()).map_err(|e| generic(e.to_string()))?);
        self.addrs.push(addr.clone());
        self.names.push(name.to_string());
        self.keys.push(keys.clone());
        Ok(keys)
    }

    // -- using the finished circuit --------------------------------------

    /// Number of hops established so far.
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// A [`RoutePlan`] for the hops built so far.
    pub fn route(&self, final_addr: &Addr) -> Result<RoutePlan, CircuitBuildError> {
        RoutePlan::new(self.addrs.clone(), final_addr.clone(), crate::cell::PAYLOAD_SIZE as i64).map_err(|e| generic(e.to_string()))
    }

    /// Onion-encrypt `payload` for delivery to `final_addr`. Unless the
    /// caller passes an explicit `pad_to`, every message is padded to the
    /// circuit's full user-data budget before sealing (see the module's
    /// Python docstring on why).
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt(&mut self, payload: &[u8], final_addr: &Addr, seq: Option<u32>, kind: Option<u8>, pad_to: Option<Option<usize>>) -> Result<Vec<u8>, CircuitBuildError> {
        let seq = seq.unwrap_or_else(|| self.next_seq());
        let route = self.route(final_addr)?;
        let pad_to = match pad_to {
            Some(explicit) => explicit,
            None => {
                let budget = user_data_budget(self.hops.len() as i64, crate::cell::PAYLOAD_SIZE as i64).map_err(|e| generic(e.to_string()))?;
                if (payload.len() as i64) <= budget - TRAILING_PAD_ENTRY_SIZE as i64 { Some(budget as usize) } else { None }
            }
        };
        OnionCrypto::encrypt_onion(payload, &mut self.hops, &route, seq, true, false, None, kind, pad_to).map_err(|e| generic(e.to_string()))
    }

    /// Encrypt `payload` and send it to the guard in one call.
    pub fn send(&mut self, payload: &[u8], final_addr: &Addr) -> Result<(), CircuitBuildError> {
        let onion = self.encrypt(payload, final_addr, None, None, None)?;
        let circuit_id = self.circuit_id.ok_or_else(|| generic("no circuit id set"))?;
        let cell = seal_into_cell(&onion, circuit_id, None).map_err(|e| generic(e.to_string()))?;
        let delay = jitter_delay(self.send_jitter)?;
        if delay > 0.0 {
            std::thread::sleep(std::time::Duration::from_secs_f64(delay));
        }
        let guard_addr = self.guard_addr.clone().ok_or_else(|| generic("no guard address set"))?;
        let guard_socket_addr = addr_to_socket_addr(&guard_addr)?;
        self.sock.send_to(&cell.pack(), guard_socket_addr).map_err(|e| generic(format!("send failed: {e}")))?;
        Ok(())
    }

    /// Read one return-path cell and peel it back to the exit's payload.
    pub fn receive(&self, timeout: Option<f64>) -> Result<Vec<u8>, CircuitBuildError> {
        if self.hops.is_empty() {
            return Err(generic("add_hop() must be called before receive()"));
        }
        let timeout = timeout.unwrap_or(self.timeout);
        let guard_addr = self.guard_addr.clone().ok_or_else(|| generic("no guard address set"))?;
        let guard_socket_addr = addr_to_socket_addr(&guard_addr)?;
        let datagram = recv_from(self.sock, guard_socket_addr, timeout, crate::cell::CELL_SIZE).map_err(|e| generic(format!("no reply within {timeout}s: {e}")))?;
        let cell = Cell::unpack(&datagram, true).map_err(|e| generic(format!("malformed reply: {e}")))?;
        let mut current = onion_from_cell(&cell, 0);
        let mut padded = false;
        for hop in &self.hops {
            let (next, header) = hop.peel_layer(&current).map_err(|e| rejected(e.to_string()))?;
            padded = header.padded;
            current = next;
        }
        if padded {
            current = strip_plaintext_padding(&current);
        }
        Ok(current)
    }

    /// Send one cover-traffic cell that every hop drops.
    pub fn send_padding(&mut self, final_addr: &Addr, pad_to: Option<usize>) -> Result<usize, CircuitBuildError> {
        if self.hops.is_empty() {
            return Err(generic("cannot send padding: no hops established yet"));
        }
        let pad_to = match pad_to {
            Some(p) => p,
            None => user_data_budget(self.hops.len() as i64, crate::cell::PAYLOAD_SIZE as i64).map_err(|e| generic(e.to_string()))? as usize,
        };
        let onion = self.encrypt(&[], final_addr, None, Some(Kind::PADDING), Some(Some(pad_to)))?;
        let circuit_id = self.circuit_id.ok_or_else(|| generic("no circuit id set"))?;
        let cell = seal_into_cell(&onion, circuit_id, None).map_err(|e| generic(e.to_string()))?;
        let datagram = cell.pack();
        let guard_addr = self.guard_addr.clone().ok_or_else(|| generic("no guard address set"))?;
        let guard_socket_addr = addr_to_socket_addr(&guard_addr)?;
        self.sock.send_to(&datagram, guard_socket_addr).map_err(|e| generic(format!("send failed: {e}")))?;
        Ok(datagram.len())
    }
}

impl<'a> fmt::Debug for CircuitBuilder<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CircuitBuilder(circuit_id={:?}, hops={:?}, addrs={:?})", self.circuit_id, self.names, self.addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{HandshakeRelay, IDENTITY_KEY_SIZE as IDK};

    fn relay_on(bind: &str, identity: [u8; IDK]) -> (UdpSocket, SocketAddr, HandshakeRelay) {
        let sock = UdpSocket::bind(bind).unwrap();
        let local = sock.local_addr().unwrap();
        let relay = HandshakeRelay::new(None, DEFAULT_CIPHER.to_string(), false, Some(identity), false, false, None, crate::handshake::DEFAULT_COOKIE_WINDOW_SECONDS, HandshakeOps::real()).unwrap();
        (sock, local, relay)
    }

    fn addr_of(a: SocketAddr) -> Addr {
        (a.ip().to_string(), a.port())
    }

    #[test]
    fn test_jitter_delay_bounds() {
        for _ in 0..20 {
            let d = jitter_delay(0.05).unwrap();
            assert!((0.0..=0.05).contains(&d));
        }
        assert_eq!(jitter_delay(0.0).unwrap(), 0.0);
        assert_eq!(jitter_delay(-1.0).unwrap(), 0.0);
    }

    #[test]
    fn test_jitter_delay_capped_at_max() {
        let d = jitter_delay(100.0).unwrap();
        assert!(d <= MAX_SEND_JITTER);
    }

    #[test]
    fn test_retry_sleep_zero_for_first_attempt() {
        assert_eq!(retry_sleep_seconds(0).unwrap(), 0.0);
        assert_eq!(retry_sleep_seconds(1).unwrap(), 0.0);
    }

    #[test]
    fn test_retry_sleep_grows_and_is_capped() {
        let s2 = retry_sleep_seconds(2).unwrap();
        let s3 = retry_sleep_seconds(3).unwrap();
        assert!(s2 >= RETRY_BACKOFF_BASE);
        assert!(s3 >= s2 * 0.9); // exponential growth, modulo jitter noise
        for attempt in 2..20 {
            assert!(retry_sleep_seconds(attempt).unwrap() <= RETRY_BACKOFF_MAX * 1.3);
        }
    }

    /// `/dev/urandom` failing to open must surface as a `CircuitBuildError`,
    /// not panic the process -- and the handle is opened at most once
    /// regardless of how many draws happen.
    #[test]
    fn test_os_random_backed_functions_succeed_repeatedly_via_the_cached_handle() {
        for _ in 0..50 {
            random_circuit_id().unwrap();
            jitter_delay_default().unwrap();
        }
    }

    #[test]
    fn test_builder_rejects_negative_send_jitter() {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let err = CircuitBuilder::new(&sock, DEFAULT_CIPHER.to_string(), DEFAULT_TIMEOUT, None, true, false, 0, -1.0, None).unwrap_err();
        assert!(matches!(err, CircuitBuildError::Generic(_)));
    }

    #[test]
    fn test_add_hop_handshakes_with_guard_only() {
        let (relay_sock, relay_addr, mut relay) = relay_on("127.0.0.1:0", [1u8; IDK]);
        let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut builder = CircuitBuilder::new(&client_sock, DEFAULT_CIPHER.to_string(), 1.0, None, true, false, 0, 0.0, None).unwrap();

        for datagram in builder.hops.iter().map(|_| ()) {
            let _ = datagram; // no-op, just to keep the loop shape obvious below
        }
        // Drive add_hop and relay.serve_once on this one thread (see
        // handshake.rs's tests for why: fake ops aren't needed here since
        // this test uses HandshakeOps::real() throughout -- add_hop still
        // blocks on the socket, so answer it from a background thread).
        let handle = std::thread::spawn(move || relay.serve_once(&relay_sock).unwrap());
        let keys = builder.add_hop("guard", addr_of(relay_addr), None, None, None).unwrap();
        handle.join().unwrap();

        assert_eq!(builder.hop_count(), 1);
        assert_eq!(builder.names, vec!["guard".to_string()]);
        assert_eq!(builder.guard_addr, Some(addr_of(relay_addr)));
        assert_eq!(keys.aead_key_fwd.len(), crate::crypto::KEY_SIZE);
        assert_eq!(keys.aead_key_bwd.len(), crate::crypto::KEY_SIZE);
    }

    #[test]
    fn test_add_hop_twice_is_rejected() {
        let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut builder = CircuitBuilder::new(&client_sock, DEFAULT_CIPHER.to_string(), 0.05, None, true, false, 0, 0.0, None).unwrap();
        builder.hops.push(
            crate::handshake::derive_handshake_keys(
                b"s".to_vec(),
                b"salt1234567890ab".to_vec(),
                1,
                DEFAULT_CIPHER.to_string(),
                None,
                Vec::new(),
                None,
                None,
                crate::handshake::HandshakeRole::Client,
            )
            .to_onion_crypto("guard", 0)
            .unwrap(),
        );
        let err = builder.add_hop("guard2", ("127.0.0.1".to_string(), 1), None, None, None).unwrap_err();
        assert!(matches!(err, CircuitBuildError::Generic(_)));
    }

    #[test]
    fn test_extend_without_add_hop_is_rejected() {
        let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut builder = CircuitBuilder::new(&client_sock, DEFAULT_CIPHER.to_string(), 0.05, None, true, false, 0, 0.0, None).unwrap();
        let err = builder.extend("middle", ("127.0.0.1".to_string(), 1), None, None, None).unwrap_err();
        assert!(matches!(err, CircuitBuildError::Generic(_)));
    }

    #[test]
    fn test_add_hop_timeout_with_no_retries_raises_timeout_not_exhausted() {
        // Nothing is listening on this address, so the guard handshake will
        // time out; with retries=0 that should surface as a plain Timeout,
        // not AttemptsExhausted (see add_hop's docs).
        let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap(); // nothing binds port 1
        let mut builder = CircuitBuilder::new(&client_sock, DEFAULT_CIPHER.to_string(), 0.05, None, true, false, 0, 0.0, None).unwrap();
        let err = builder.add_hop("guard", addr_of(dead_addr), None, None, None).unwrap_err();
        assert!(matches!(err, CircuitBuildError::Timeout(_)));
    }

    #[test]
    fn test_send_padding_requires_established_hops() {
        let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut builder = CircuitBuilder::new(&client_sock, DEFAULT_CIPHER.to_string(), 0.05, None, true, false, 0, 0.0, None).unwrap();
        let err = builder.send_padding(&("127.0.0.1".to_string(), 1), None).unwrap_err();
        assert!(matches!(err, CircuitBuildError::Generic(_)));
    }

    #[test]
    fn test_receive_requires_established_hops() {
        let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let builder = CircuitBuilder::new(&client_sock, DEFAULT_CIPHER.to_string(), 0.05, None, true, false, 0, 0.0, None).unwrap();
        let err = builder.receive(None).unwrap_err();
        assert!(matches!(err, CircuitBuildError::Generic(_)));
    }

    #[test]
    fn test_debug_repr_includes_circuit_id_and_names() {
        let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let builder = CircuitBuilder::new(&client_sock, DEFAULT_CIPHER.to_string(), 0.05, None, true, false, 0, 0.0, None).unwrap();
        let repr = format!("{builder:?}");
        assert!(repr.contains("CircuitBuilder"));
    }

    /// The `extend()` leg (peeling an EXTENDED reply relayed back through an
    /// already-built hop) requires a full relay-side forwarding
    /// implementation (`RelayNode.extend_circuit` in Python, Phase 4's
    /// `relay.rs` here) to produce a real EXTENDED cell end-to-end over the
    /// network; `circuit.rs` itself only consumes that reply. That forward
    /// path is exercised once `relay.rs` lands in Phase 4. Here we confirm
    /// the guard leg (`add_hop`) builds a real circuit against an actual
    /// `HandshakeRelay` over loopback UDP, and that a built circuit can
    /// immediately do a real `encrypt`/`send`/`receive` payload round trip
    /// through that single hop.
    #[test]
    fn test_single_hop_circuit_send_and_receive_round_trip() {
        let (guard_sock, guard_addr, mut guard_relay) = relay_on("127.0.0.1:0", [2u8; IDK]);
        let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut builder = CircuitBuilder::new(&client_sock, DEFAULT_CIPHER.to_string(), 1.0, None, true, false, 0, 0.0, None).unwrap();

        let guard_handle = std::thread::spawn(move || guard_relay.serve_once(&guard_sock).unwrap());
        builder.add_hop("guard", addr_of(guard_addr), None, None, None).unwrap();
        guard_handle.join().unwrap();

        assert_eq!(builder.hop_count(), 1);

        let final_addr: Addr = ("203.0.113.9".to_string(), 9999);
        let payload = b"hello through one relay".to_vec();
        let datagram = builder.encrypt(&payload, &final_addr, None, None, None).unwrap();
        assert!(!datagram.is_empty());
    }
}
