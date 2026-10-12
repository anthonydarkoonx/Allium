//! Client-side incremental circuit construction via EXTEND.
//!
//! Without this module, a client has to handshake directly with every relay
//! on its route (what the rest of this library still allows). That means
//! every relay learns the client's real address, and the client has to
//! already know how to reach the middle and exit relays over the network --
//! neither of which holds for a real onion-routing deployment, where a
//! client should only ever need to *route through* its guard.
//!
//! [`CircuitBuilder`] fixes that: it handshakes directly with only the first
//! hop, then extends the circuit one relay at a time by asking the current
//! last hop to relay a CREATE on its behalf (the server-side forwarding
//! logic that answers an EXTEND lives outside this crate -- see the module
//! docs on [`CircuitBuilder::extend`]). Each hop after the first learns only
//! its immediate predecessor and successor -- never the client's address,
//! never the full route.
//!
//! ```no_run
//! use std::net::UdpSocket;
//! use std::time::Duration;
//! use allium::circuit::{CircuitBuilder, EncryptOptions};
//! use allium::handshake::DEFAULT_TIMEOUT;
//!
//! let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
//! let mut builder = CircuitBuilder::new(
//!     &sock, None, DEFAULT_TIMEOUT, None, true, false, 0, 0.0, None,
//! ).unwrap();
//! # let guard_addr = ("127.0.0.1".to_string(), 9001);
//! # let middle_addr = ("127.0.0.1".to_string(), 9002);
//! # let target_addr = ("93.184.216.34".to_string(), 443);
//! builder.add_hop("guard", guard_addr, None, None, None).unwrap();
//! builder.extend("middle", middle_addr, None, None, None).unwrap();
//! builder.send(b"hello", target_addr, EncryptOptions::default()).unwrap();
//! ```
//!
//! This is deliberately a thin, synchronous, blocking-socket client -- the
//! same style [`crate::handshake::HandshakeClient`] already uses -- rather
//! than an async API: a client builds one circuit at a time and can afford
//! to wait for each hop in turn, unlike a relay, which must keep serving
//! other circuits while an EXTEND it issued is in flight.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use crate::cell::{Cell, CellError, Command, PAYLOAD_SIZE};
use crate::createfrag::{fragment_extend_payload, CreateFragError};
use crate::handshake::{
    HandshakeClient, HandshakeError, HandshakeKeys, IDENTITY_KEY_SIZE,
};
use crate::layer::{Kind, LayerHeader};
use crate::onion::{
    onion_from_cell, seal_into_cell, strip_plaintext_padding, OnionCrypto, OnionError,
    DEFAULT_CIPHER, TRAILING_PAD_ENTRY_SIZE,
};
use crate::osrand;
use crate::sizes::{user_data_budget, RoutePlan, SizesError};

/// An `(ip, port)` pair. Mirrors Python's `Addr = Tuple[str, int]`: a
/// hostname or a numeric address, resolved lazily (like a Python
/// `socket.sendto` call resolves it) wherever it is actually used for I/O.
pub type Addr = (String, u16);

/// How many times a handshake attempt is retried before giving up. `0`
/// means exactly one attempt, which is the pre-retry behaviour and the
/// safest default for a lossless local test. A real deployment over a
/// lossy path should pass a positive value.
pub const DEFAULT_RETRIES: u32 = 0;

/// Base of the exponential backoff between handshake attempts, in seconds.
/// The wait after attempt *n* is `base * 2**(n-1)` (so base, 2*base,
/// 4*base, ...), capped, and multiplied by a random jitter factor to avoid
/// synchronising retries across many clients.
pub const RETRY_BACKOFF_BASE: f64 = 0.5;

/// Largest jitter multiple applied to the backoff, so the real sleep is
/// uniform in `[1.0, 1.0 + RETRY_JITTER_FRACTION]` times the computed
/// backoff. Jitter is load-bearing for a transport that must not reveal
/// timing; without it, many clients that all lost a packet at once would
/// retry in lockstep.
pub const RETRY_JITTER_FRACTION: f64 = 0.2;

/// Hard ceiling on any single backoff sleep, in seconds. A relay that is
/// simply down should be abandoned quickly in a test; a real deployment
/// would raise it.
pub const RETRY_BACKOFF_MAX: f64 = 4.0;

/// Largest uniform send-side delay, in seconds, applied to each cell when
/// jitter is enabled. This is a *timing-attack* defence, distinct from the
/// backoff jitter above: it decorrelates the moment a cell enters the
/// network from the moment the application produced it, so an observer
/// cannot use inter-packet timing to fingerprint behaviour. `0` disables
/// it.
///
/// On by default: 50ms is small enough not to be noticeable on an
/// interactive session but enough to blur single-cell timing; pass
/// `send_jitter=0.0` to [`CircuitBuilder::new`] explicitly for a
/// latency-sensitive caller that wants the old behaviour.
pub const DEFAULT_SEND_JITTER: f64 = 0.05;

/// Upper bound on send jitter, so a misconfiguration cannot stall a
/// circuit.
pub const MAX_SEND_JITTER: f64 = 2.0;

// `jitter_delay` and `retry_sleep_seconds` exist specifically to
// decorrelate wire-visible timing from the moment the application acted,
// which is a defence against
// a *timing* adversary. A non-cryptographic PRNG would be the wrong tool
// for that: its internal state is recoverable from a bounded number of
// outputs, after which every future (and past) jitter value it produced
// becomes predictable and the delay can be subtracted back out, undoing
// the defence exactly when it matters. This draws every jitter byte from
// [`osrand`] (the OS CSPRNG), which keeps no recoverable state -- the same
// reasoning `allium.directory._route_rng` applies to path selection.
fn random_unit_f64() -> f64 {
    // 53 bits of precision, matching the width Python's
    // `random.Random.random()` produces -- there is no cross-check target
    // here (the value is intentionally unpredictable on both sides), this
    // just keeps the distribution comparable.
    let raw = osrand::bytes(8);
    let mut v: u64 = 0;
    for b in raw {
        v = (v << 8) | b as u64;
    }
    let bits53 = v >> (64 - 53);
    (bits53 as f64) / ((1u64 << 53) as f64)
}

fn uniform(low: f64, high: f64) -> f64 {
    if high <= low {
        return low;
    }
    low + (high - low) * random_unit_f64()
}

/// Return a uniform random delay in `[0, seconds]`, for timing
/// obfuscation.
///
/// `seconds` is the ceiling; `0` (or below) yields `0.0`.
pub fn jitter_delay(seconds: f64) -> f64 {
    if seconds <= 0.0 {
        return 0.0;
    }
    uniform(0.0, seconds.min(MAX_SEND_JITTER))
}

/// Backoff sleep after a failed attempt, with jitter.
///
/// `attempt` is 1 for the wait before the *second* try, 2 for the third,
/// and so on. Returns `0.0` for `attempt <= 1` (the caller should not
/// sleep at all before a second try is even warranted). The value is
/// `base * 2**(attempt-2)`, capped at [`RETRY_BACKOFF_MAX`], then scaled by
/// a uniform `[1, 1 + jitter]` factor.
///
/// A free function (rather than a method) so tests can call it directly
/// and so the timing policy stays in exactly one place.
pub fn retry_sleep_seconds(attempt: u32) -> f64 {
    if attempt <= 1 {
        return 0.0;
    }
    let raw = RETRY_BACKOFF_BASE * 2f64.powi(attempt as i32 - 2);
    let raw = raw.min(RETRY_BACKOFF_MAX);
    let jitter = 1.0 + uniform(0.0, RETRY_JITTER_FRACTION);
    raw * jitter
}

fn random_circuit_id() -> u32 {
    let mut buf = [0u8; 4];
    osrand::fill(&mut buf);
    u32::from_be_bytes(buf)
}

fn resolve(addr: &Addr) -> io::Result<SocketAddr> {
    (addr.0.as_str(), addr.1)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("could not resolve {addr:?}")))
}

/// Read datagrams from `sock` until one arrives from `expected_addr`.
///
/// Forged cells fail authentication, so accepting a datagram from any
/// source is not a confidentiality break
/// -- but a caller that reads one datagram and gives up on the first one
/// that isn't what it expected lets an off-path attacker who only knows
/// the client's UDP port abort a circuit build with a single spoofed
/// packet, no reply from the real peer required. Comparing the source
/// address and continuing to wait removes that as a denial-of-service
/// lever.
fn recv_from(sock: &UdpSocket, expected_addr: SocketAddr, timeout: Duration) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "timed out waiting for a reply from the expected source"));
        }
        sock.set_read_timeout(Some(deadline - now))?;
        let mut buf = [0u8; crate::cell::CELL_SIZE];
        match sock.recv_from(&mut buf) {
            Ok((n, addr)) => {
                if addr != expected_addr {
                    // Not from the peer we sent to -- forged or stray
                    // traffic. Drop it silently and keep waiting for the
                    // real one within whatever budget remains.
                    continue;
                }
                return Ok(buf[..n].to_vec());
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "timed out waiting for a reply from the expected source"));
            }
            Err(e) => return Err(e),
        }
    }
}

/// Every error [`CircuitBuilder`] can raise.
///
/// The Python original has a small exception hierarchy
/// (`CircuitBuildError` base; `HandshakeAttemptsExhausted`,
/// `ExtendTimeout`, `ExtendRejected` all subclass it, and a raw
/// [`HandshakeError`] subclass can also propagate straight through an
/// unretried failure). Rust has no hierarchy to subclass, so they are
/// flattened into one enum, matching the [`HandshakeError`] pattern used
/// elsewhere in this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitError {
    /// Generic circuit-build misuse: called out of order, or a bad
    /// argument.
    Build(String),
    /// Every attempt for one hop timed out and `retries` were exhausted
    /// (`retries > 0`). Rust has no exception chaining, so unlike
    /// Python's `__cause__` the final timeout's message is folded into
    /// this one rather than attached separately.
    AttemptsExhausted(String),
    /// No EXTENDED reply arrived from the guard within the timeout. This
    /// is deliberately the *only* failure signal EXTEND produces: a relay
    /// that refuses, or a target that never answers, or a network that
    /// drops the request, all look identical to the client -- silence.
    ExtendTimeout(String),
    /// An EXTENDED reply arrived but could not be turned into a new hop:
    /// a reply that fails to peel through the hops built so far (wrong
    /// key, tampered bytes, a corrupt datagram), or a well-formed CREATED
    /// body that fails its own handshake verification.
    ExtendRejected(String),
    /// A raw handshake failure that propagates without being retried:
    /// Python raises the underlying `HandshakeError` subclass directly
    /// here rather than wrapping it (a rejection, a verification or
    /// relay-authentication failure, or the guard's own timeout once
    /// `retries == 0`).
    Handshake(HandshakeError),
    /// The local socket failed outside of a retried handshake/EXTEND
    /// attempt (Python lets the raw `OSError` propagate here too).
    Io(String),
}

impl std::fmt::Display for CircuitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitError::Build(m)
            | CircuitError::AttemptsExhausted(m)
            | CircuitError::ExtendTimeout(m)
            | CircuitError::ExtendRejected(m)
            | CircuitError::Io(m) => write!(f, "{m}"),
            CircuitError::Handshake(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for CircuitError {}

impl From<HandshakeError> for CircuitError {
    fn from(e: HandshakeError) -> Self {
        CircuitError::Handshake(e)
    }
}
impl From<OnionError> for CircuitError {
    fn from(e: OnionError) -> Self {
        CircuitError::Build(e.to_string())
    }
}
impl From<CellError> for CircuitError {
    fn from(e: CellError) -> Self {
        CircuitError::Build(e.to_string())
    }
}
impl From<SizesError> for CircuitError {
    fn from(e: SizesError) -> Self {
        CircuitError::Build(e.to_string())
    }
}
impl From<CreateFragError> for CircuitError {
    fn from(e: CreateFragError) -> Self {
        CircuitError::Build(e.to_string())
    }
}

/// The optional knobs [`OnionCrypto::encrypt_onion`] takes, bundled up
/// since Rust has no `**kwargs`. Mirrors [`CircuitBuilder::encrypt`]'s
/// Python `**kwargs` forwarding: [`Default::default`] reproduces
/// `encrypt_onion`'s own Python defaults (`check_size=True`, everything
/// else unset), *not* Rust's usual all-zero `Default`.
#[derive(Debug, Clone)]
pub struct EncryptOptions {
    /// Overrides [`CircuitBuilder`]'s own sequence counter. `None` (the
    /// default via [`CircuitBuilder::encrypt`]) gets a fresh value from
    /// the builder.
    pub seq: Option<u32>,
    /// Raise up front when the payload cannot fit one cell, rather than
    /// failing later on an oversized intermediate field.
    pub check_size: bool,
    /// Stamp a *different* sequence number on each layer.
    pub per_hop_seq: bool,
    /// The sequence number for the innermost (exit) layer when
    /// `per_hop_seq` is set; defaults to `seq`.
    pub hop_seq_base: Option<u32>,
    /// Overrides the innermost layer's [`Kind`] (default
    /// [`Kind::PAYLOAD`]).
    pub kind: Option<u8>,
    /// Pads the payload to this many bytes before sealing.
    pub pad_to: Option<usize>,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        EncryptOptions {
            seq: None,
            check_size: true,
            per_hop_seq: false,
            hop_seq_base: None,
            kind: None,
            pad_to: None,
        }
    }
}

/// Builds a circuit hop by hop, handshaking directly only with the guard.
///
/// # Attributes
/// `circuit_id`: the id used for every cell on the client<->guard link --
/// the handshake, every EXTEND/EXTENDED exchange, and eventually ordinary
/// DATA. Set by [`CircuitBuilder::add_hop`].
/// `guard_addr`: the guard's resolved address; every cell this builder
/// sends, regardless of which hop it is ultimately headed for, goes here.
/// `hops`: the established hops' [`OnionCrypto`] instances, in route
/// order. `addrs`/`names`/`keys` run parallel to `hops`.
pub struct CircuitBuilder<'a> {
    sock: &'a UdpSocket,
    /// `{hop_name: ML-KEM-768 encapsulation key}` -- hops listed here get
    /// the post-quantum hybrid handshake; a per-call `kem_public` on
    /// [`CircuitBuilder::add_hop`]/[`CircuitBuilder::extend`] wins.
    kem_keys: HashMap<String, Vec<u8>>,
    pub cipher: String,
    pub timeout: Duration,
    pub retries: u32,
    pub send_jitter: f64,
    trusted: HashMap<String, Vec<[u8; IDENTITY_KEY_SIZE]>>,
    trust_first_use: bool,
    allow_anonymous_relay: bool,

    pub circuit_id: Option<u32>,
    pub guard_addr: Option<SocketAddr>,
    pub hops: Vec<OnionCrypto>,
    pub addrs: Vec<Addr>,
    pub names: Vec<String>,
    pub keys: Vec<HandshakeKeys>,
    /// Monotonic counter, one fresh value per cell this builder ever
    /// seals (each EXTEND request and every payload sent via
    /// [`CircuitBuilder::encrypt`]). Every hop but the guard gets its
    /// table entry -- and with it a fresh replay window -- re-created
    /// each time it is (re-)registered, but the guard is registered
    /// exactly once and then keeps the same window for the rest of the
    /// circuit's life; reusing a `seq` would make the guard reject every
    /// cell after the first as a replay. A single incrementing counter,
    /// shared by every cell regardless of which hop it is ultimately
    /// headed for, is the simplest sequence no hop's window will ever see
    /// twice.
    seq_counter: u32,
}

impl<'a> CircuitBuilder<'a> {
    /// Build a circuit builder around an already-bound `sock`, owned by
    /// the caller: this never creates, binds, or closes it.
    ///
    /// # Errors
    /// Returns [`CircuitError::Build`] if `send_jitter` is negative.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sock: &'a UdpSocket,
        cipher: Option<&str>,
        timeout: Duration,
        trusted_identities: Option<HashMap<String, Vec<[u8; IDENTITY_KEY_SIZE]>>>,
        trust_first_use: bool,
        allow_anonymous_relay: bool,
        retries: u32,
        send_jitter: f64,
        kem_keys: Option<HashMap<String, Vec<u8>>>,
    ) -> Result<Self, CircuitError> {
        if send_jitter < 0.0 {
            return Err(CircuitError::Build(format!("send_jitter must not be negative, got {send_jitter}")));
        }
        Ok(CircuitBuilder {
            sock,
            kem_keys: kem_keys.unwrap_or_default(),
            cipher: cipher.unwrap_or(DEFAULT_CIPHER).to_string(),
            timeout,
            retries,
            send_jitter,
            trusted: trusted_identities.unwrap_or_default(),
            trust_first_use,
            allow_anonymous_relay,
            circuit_id: None,
            guard_addr: None,
            hops: Vec::new(),
            addrs: Vec::new(),
            names: Vec::new(),
            keys: Vec::new(),
            seq_counter: 0,
        })
    }

    // -- construction -----------------------------------------------------

    fn next_seq(&mut self) -> u32 {
        let seq = self.seq_counter;
        self.seq_counter = self.seq_counter.wrapping_add(1);
        seq
    }

    fn trusted_for(&self, name: &str) -> Option<Vec<[u8; IDENTITY_KEY_SIZE]>> {
        self.trusted.get(name).cloned()
    }

    fn client_for(&self, name: &str, kem_public: Option<Vec<u8>>) -> Result<HandshakeClient, CircuitError> {
        let kem = kem_public.or_else(|| self.kem_keys.get(name).cloned());
        Ok(HandshakeClient::new(
            Some(self.cipher.as_str()),
            None,
            self.timeout,
            self.trusted_for(name),
            self.trust_first_use,
            self.allow_anonymous_relay,
            kem,
            false,
        )?)
    }

    /// Handshake directly with the first hop (the guard).
    ///
    /// Must be called exactly once, before any call to
    /// [`CircuitBuilder::extend`]. This is the only hop the client ever
    /// contacts directly; every later one is reached through `extend`.
    ///
    /// `retries` (how many extra attempts to make after a timeout)
    /// defaults to the builder-wide [`CircuitBuilder::retries`] when
    /// `None`. Only a timeout retries; a rejection or authentication
    /// failure raises immediately. Each retry uses a fresh ephemeral key.
    ///
    /// # Errors
    /// Returns [`CircuitError::Build`] if a hop has already been added.
    /// Returns [`CircuitError::Handshake`] on the final attempt's timeout,
    /// on a malformed or mismatched reply, if the guard cannot prove it
    /// holds its private key, or if identity pinning is configured for
    /// this hop and the guard's signature does not match. Returns
    /// [`CircuitError::AttemptsExhausted`] if `retries > 0` and every
    /// attempt timed out.
    pub fn add_hop(
        &mut self,
        name: &str,
        addr: Addr,
        circuit_id: Option<u32>,
        retries: Option<u32>,
        kem_public: Option<Vec<u8>>,
    ) -> Result<HandshakeKeys, CircuitError> {
        if !self.hops.is_empty() {
            return Err(CircuitError::Build(format!(
                "add_hop() must be called exactly once, before any extend(); this builder already has {} hop(s)",
                self.hops.len()
            )));
        }
        let resolved = resolve(&addr).map_err(|e| CircuitError::Build(e.to_string()))?;
        let cid = circuit_id.unwrap_or_else(random_circuit_id);
        self.circuit_id = Some(cid);
        let retries = retries.unwrap_or(self.retries);
        let total = retries + 1;

        for attempt in 1..=total {
            if attempt > 1 {
                std::thread::sleep(Duration::from_secs_f64(retry_sleep_seconds(attempt)));
            }
            // A fresh client per attempt: the handshake mints a new
            // ephemeral X25519 key each time, so a retried CREATE is a
            // new request (never a replay) and never reuses a key under
            // the same circuit id.
            let mut client = self.client_for(name, kem_public.clone())?;
            match client.handshake(self.sock, resolved, cid, 1) {
                Ok(keys) => {
                    self.guard_addr = Some(resolved);
                    self.hops.push(keys.to_onion_crypto(name, 0)?);
                    self.addrs.push(addr);
                    self.names.push(name.to_string());
                    self.keys.push(keys.clone());
                    return Ok(keys);
                }
                Err(HandshakeError::Timeout(msg)) => {
                    if attempt == total {
                        if retries == 0 {
                            return Err(CircuitError::Handshake(HandshakeError::Timeout(msg)));
                        }
                        return Err(CircuitError::AttemptsExhausted(format!(
                            "guard handshake with {name:?} ({addr:?}) timed out on all {total} attempt(s): {msg}"
                        )));
                    }
                    continue;
                }
                Err(e) => return Err(CircuitError::Handshake(e)),
            }
        }
        unreachable!("loop always returns or errors before exhausting attempts")
    }

    /// Extend the circuit by one hop, via the hops already established.
    ///
    /// Sends an onion-wrapped EXTEND request through every hop built so
    /// far (a no-op wrapping for the very first extend, since only the
    /// guard is established), addressed -- like every cell this builder
    /// ever sends -- to [`CircuitBuilder::guard_addr`]. Waits for the
    /// matching EXTENDED reply, peels it back through the same hops in
    /// order, and completes the new hop's handshake from the recovered
    /// CREATED body. Answering the EXTEND is the current last hop's job
    /// (server-side relay-forwarding logic, outside this crate); this
    /// method only speaks the client side of that exchange.
    ///
    /// `retries` (how many extra attempts after a timeout) defaults to
    /// the builder-wide default when `None`. Only a timeout triggers a
    /// retry: a rejection, verification failure, or authentication
    /// failure is raised immediately. Each retry uses a *fresh* ephemeral
    /// X25519 key, so a retried CREATE is never mistaken by a relay for a
    /// replay. Backoff between attempts is exponential with jitter; see
    /// [`retry_sleep_seconds`].
    ///
    /// # Errors
    /// Returns [`CircuitError::Build`] if [`CircuitBuilder::add_hop`] has
    /// not been called yet. Returns [`CircuitError::ExtendRejected`] if a
    /// reply arrives but cannot be turned into a verified new hop --
    /// never retried, since a discarded, tampered, or mismatched reply is
    /// not transient loss. Returns [`CircuitError::ExtendTimeout`] if the
    /// final attempt times out with `retries == 0`. Returns
    /// [`CircuitError::AttemptsExhausted`] if `retries > 0` and every
    /// attempt timed out.
    pub fn extend(
        &mut self,
        name: &str,
        addr: Addr,
        timeout: Option<Duration>,
        retries: Option<u32>,
        kem_public: Option<Vec<u8>>,
    ) -> Result<HandshakeKeys, CircuitError> {
        if self.hops.is_empty() {
            return Err(CircuitError::Build("add_hop() must be called before extend()".to_string()));
        }
        let timeout = timeout.unwrap_or(self.timeout);
        let retries = retries.unwrap_or(self.retries);
        let total = retries + 1;

        for attempt in 1..=total {
            if attempt > 1 {
                std::thread::sleep(Duration::from_secs_f64(retry_sleep_seconds(attempt)));
            }
            match self.extend_once(name, &addr, timeout, kem_public.clone()) {
                Ok(keys) => return Ok(keys),
                Err(CircuitError::ExtendTimeout(msg)) => {
                    if attempt == total {
                        if retries == 0 {
                            return Err(CircuitError::ExtendTimeout(msg));
                        }
                        return Err(CircuitError::AttemptsExhausted(format!(
                            "extend to hop {name:?} ({addr:?}) timed out on all {total} attempt(s): {msg}"
                        )));
                    }
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!("loop always returns or errors before exhausting attempts")
    }

    /// One single EXTEND attempt: build the request, wait, and verify it.
    ///
    /// The body of [`CircuitBuilder::extend`], factored out so the retry
    /// loop can call it repeatedly. Each invocation mints a fresh
    /// ephemeral client key and a fresh circuit id, both of which are
    /// required for a retry to be safe: a byte-identical repeated CREATE
    /// would be dropped by the relay's handshake replay guard, and
    /// reusing the same key across a retry would be a nonce-reuse hazard.
    fn extend_once(
        &mut self,
        name: &str,
        addr: &Addr,
        timeout: Duration,
        kem_public: Option<Vec<u8>>,
    ) -> Result<HandshakeKeys, CircuitError> {
        // See add_hop()'s matching comment: no `| 1` parity mask here
        // either -- uniform over the full 32-bit space.
        let new_circuit_id = random_circuit_id();
        let mut client = self.client_for(name, kem_public)?;
        let create_message = client.create(new_circuit_id, None)?;

        let route = RoutePlan::new(self.addrs.clone(), addr.clone(), PAYLOAD_SIZE)?;
        let budget = user_data_budget(self.hops.len(), PAYLOAD_SIZE)?;
        let payload = create_message.payload();
        let pieces: Vec<Vec<u8>> = if (payload.len() as i64) <= budget {
            vec![payload.to_vec()]
        } else {
            // Post-quantum hybrid CREATE: too big for one EXTEND layer,
            // so it goes as several, reassembled by the extending relay
            // (crate::createfrag).
            fragment_extend_payload(payload, budget.max(0) as usize, None)?
        };

        let circuit_id = self.circuit_id.expect("add_hop() already checked to have run");
        let guard_addr = self.guard_addr.expect("add_hop() already checked to have run");

        for piece in &pieces {
            let seq = self.next_seq();
            let onion = OnionCrypto::encrypt_onion(piece, &mut self.hops, &route, seq, true, false, None, Some(Kind::EXTEND), None)?;
            let request = seal_into_cell(&onion, circuit_id, Some(Command::Data))?;
            self.sock.send_to(&request.pack(), guard_addr).map_err(|e| CircuitError::Io(e.to_string()))?;
        }

        // M3: only ever a datagram that actually came from the guard --
        // see `recv_from`.
        let datagram = recv_from(self.sock, guard_addr, timeout).map_err(|e| {
            CircuitError::ExtendTimeout(format!("no EXTENDED reply for hop {name:?} ({addr:?}) within {timeout:?}: {e}"))
        })?;

        let reply = Cell::unpack(&datagram, true).map_err(|e| CircuitError::ExtendRejected(format!("malformed EXTENDED datagram: {e}")))?;
        if reply.command != Command::Extended {
            return Err(CircuitError::ExtendRejected(format!("expected an EXTENDED cell, got {}", reply.command.name())));
        }
        if reply.circuit_id != circuit_id {
            return Err(CircuitError::ExtendRejected(format!(
                "EXTENDED circuit id {:#010x} does not match {circuit_id:#010x}",
                reply.circuit_id
            )));
        }

        // Peel back through every established hop, in route order: the
        // outermost layer is the guard's (added last, by whichever hop is
        // relaying this reply backward), so it is removed first.
        let mut current = onion_from_cell(&reply, 0);
        for hop in &self.hops {
            match hop.peel_layer(&current) {
                Ok((inner, header)) => {
                    current = inner;
                    if header.kind != Kind::EXTENDED {
                        return Err(CircuitError::ExtendRejected(format!(
                            "expected an EXTENDED layer while peeling hop {:?}, got {}",
                            hop.name,
                            Kind::name(header.kind)
                        )));
                    }
                }
                Err(e) => {
                    return Err(CircuitError::ExtendRejected(format!("EXTENDED reply for hop {name:?} failed to peel: {e}")));
                }
            }
        }

        let created_cell = Cell::new(new_circuit_id, Command::Created, current)?;
        let keys = client
            .complete_cell(&created_cell, Some(new_circuit_id))
            .map_err(|e| CircuitError::ExtendRejected(format!("hop {name:?} ({addr:?}) failed handshake verification: {e}")))?;

        self.hops.push(keys.to_onion_crypto(name, self.hops.len())?);
        self.addrs.push(addr.clone());
        self.names.push(name.to_string());
        self.keys.push(keys.clone());
        Ok(keys)
    }

    // -- using the finished circuit ----------------------------------------

    /// Number of hops established so far.
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// A [`RoutePlan`] for the hops built so far.
    pub fn route(&self, final_addr: Addr) -> Result<RoutePlan, CircuitError> {
        Ok(RoutePlan::new(self.addrs.clone(), final_addr, PAYLOAD_SIZE)?)
    }

    /// Onion-encrypt `payload` for delivery to `final_addr`.
    ///
    /// A thin wrapper around [`OnionCrypto::encrypt_onion`] using the
    /// hops and addresses this builder has established. Pass an explicit
    /// `opts.seq` to override the builder's own counter (for example, to
    /// match a value chosen by higher-level stream code); by default each
    /// call gets a fresh one, which matters for any hop besides the last
    /// -- see [`CircuitBuilder`]'s `seq_counter` docs.
    ///
    /// Unless `opts.pad_to` is set (including explicitly to `None`, which
    /// this can't distinguish from "unset" -- pass a [`EncryptOptions`]
    /// with `pad_to: None` and everything else at its default to opt out
    /// deliberately once the padding heuristic below has already run),
    /// every message is padded to the circuit's full
    /// [`crate::sizes::user_data_budget`] before sealing. Without this, a
    /// message's true length is visible in each peeled layer's (per-hop,
    /// non-wire-constant) `LayerHeader.length` field even though the
    /// outer cell itself is already a fixed size -- every relay on the
    /// circuit could otherwise tell short messages from long ones, and a
    /// control frame from a full data cell, purely by size. A payload
    /// already within [`TRAILING_PAD_ENTRY_SIZE`] bytes of the budget is
    /// left at its natural length instead of padded, since
    /// [`crate::onion::pad_plaintext`] has no room left for its trailer
    /// at that size and this is already indistinguishable in practice
    /// from the largest possible message.
    pub fn encrypt(&mut self, payload: &[u8], final_addr: Addr, mut opts: EncryptOptions) -> Result<Vec<u8>, CircuitError> {
        if opts.seq.is_none() {
            opts.seq = Some(self.next_seq());
        }
        if opts.pad_to.is_none() {
            let budget = user_data_budget(self.hops.len(), PAYLOAD_SIZE)?;
            if (payload.len() as i64) <= budget - TRAILING_PAD_ENTRY_SIZE as i64 {
                opts.pad_to = Some(budget.max(0) as usize);
            }
        }
        let route = self.route(final_addr)?;
        Ok(OnionCrypto::encrypt_onion(
            payload,
            &mut self.hops,
            &route,
            opts.seq.expect("set above"),
            opts.check_size,
            opts.per_hop_seq,
            opts.hop_seq_base,
            opts.kind,
            opts.pad_to,
        )?)
    }

    /// Encrypt `payload` and send it to the guard in one call.
    ///
    /// Pass `opts.pad_to` to hide the message length; see
    /// [`crate::onion::pad_plaintext`].
    ///
    /// When [`CircuitBuilder::send_jitter`] is positive, a uniform random
    /// delay in `[0, send_jitter]` precedes the send, so the time a cell
    /// hits the wire is decorrelated from the time the application
    /// produced it -- a timing side-channel defence (see
    /// [`jitter_delay`]).
    pub fn send(&mut self, payload: &[u8], final_addr: Addr, opts: EncryptOptions) -> Result<(), CircuitError> {
        let jitter = self.send_jitter;
        self.send_with_jitter(payload, final_addr, opts, jitter)
    }

    /// Like [`send`](Self::send) but with no jitter delay, whatever
    /// [`CircuitBuilder::send_jitter`] is set to.
    ///
    /// For cells whose timing is already fixed by something the observer
    /// sees anyway, such as the ack for a cell that just arrived. Jitter
    /// there hides nothing, and because the receive thread sends the ack
    /// while holding the circuit, a delay stops all reading: downloads
    /// were capped near 0.4 MB/s by 8 KB acks each waiting up to 50 ms.
    pub fn send_unjittered(&mut self, payload: &[u8], final_addr: Addr, opts: EncryptOptions) -> Result<(), CircuitError> {
        self.send_with_jitter(payload, final_addr, opts, 0.0)
    }

    fn send_with_jitter(&mut self, payload: &[u8], final_addr: Addr, opts: EncryptOptions, send_jitter: f64) -> Result<(), CircuitError> {
        let onion = self.encrypt(payload, final_addr, opts)?;
        let circuit_id = self
            .circuit_id
            .ok_or_else(|| CircuitError::Build("add_hop() must be called before send()".to_string()))?;
        let cell = seal_into_cell(&onion, circuit_id, None)?;
        let delay = jitter_delay(send_jitter);
        if delay > 0.0 {
            std::thread::sleep(Duration::from_secs_f64(delay));
        }
        let guard_addr = self.guard_addr.expect("circuit_id set implies guard_addr is set");
        self.sock.send_to(&cell.pack(), guard_addr).map_err(|e| CircuitError::Io(e.to_string()))?;
        Ok(())
    }

    /// Read one return-path cell and peel it back to the exit's payload.
    ///
    /// The mirror of [`CircuitBuilder::send`]: the exit (or a relay
    /// adding a backward layer) seals a reply with each hop's key, and
    /// this peels them all off in route order to recover the innermost
    /// plaintext -- the payload the exit produced. This is what turns the
    /// one-way transport into the bidirectional stream a SOCKS5 proxy
    /// needs.
    ///
    /// `timeout` defaults to [`CircuitBuilder::timeout`].
    ///
    /// # Errors
    /// Returns [`CircuitError::Build`] if no hops are established.
    /// Returns [`CircuitError::Io`] if no cell arrives within the
    /// timeout. Returns [`CircuitError::Build`] if the returned cell
    /// fails to authenticate (tampered or a wrong-direction cell) or
    /// fails to parse.
    pub fn receive(&self, timeout: Option<Duration>) -> Result<Vec<u8>, CircuitError> {
        if self.hops.is_empty() {
            return Err(CircuitError::Build("add_hop() must be called before receive()".to_string()));
        }
        let timeout = timeout.unwrap_or(self.timeout);
        let guard_addr = self.guard_addr.expect("hops established implies guard_addr is set");
        // M3: only ever a datagram that actually came from the guard.
        let datagram = recv_from(self.sock, guard_addr, timeout).map_err(|e| CircuitError::Io(e.to_string()))?;
        let cell = Cell::unpack(&datagram, true)?;
        // Security audit fix (finding L6): `extend_once` already checks
        // this for an EXTENDED reply; `receive()` never did, for any
        // other reply. Low risk today (each circuit uses its own
        // ephemeral socket, matched against `guard_addr` above), but
        // still a real gap in defense-in-depth against a guard that
        // mixes up circuit ids, or a future refactor sharing one socket
        // across circuits.
        let circuit_id = self.circuit_id.expect("hops established implies circuit_id is set");
        if cell.circuit_id != circuit_id {
            return Err(CircuitError::Build(format!(
                "received cell circuit id {:#010x} does not match this circuit's {circuit_id:#010x}",
                cell.circuit_id
            )));
        }
        let mut current = onion_from_cell(&cell, 0);
        let mut header: Option<LayerHeader> = None;
        for hop in &self.hops {
            let (inner, h) = hop.peel_layer(&current)?;
            current = inner;
            header = Some(h);
        }
        // Strip padding only when the innermost header says it was
        // applied, rather than sniffing every reply's tail.
        if let Some(h) = header {
            if h.padded {
                current = strip_plaintext_padding(&current);
            }
        }
        Ok(current)
    }

    /// Send one cover-traffic cell that every hop drops.
    ///
    /// An idle circuit is otherwise silent on the wire, so an observer
    /// can see exactly when a client is talking and can correlate
    /// circuit setup and teardown with the traffic that follows. This
    /// emits a cell identical in shape to a real one -- same 1192 bytes,
    /// same layers, authenticated by the same keys -- whose innermost
    /// layer is [`Kind::PADDING`], so the exit discards it instead of
    /// delivering anything.
    ///
    /// `final_addr` is the address the innermost layer names. It is
    /// never contacted, because the layer kind is PADDING rather than
    /// PAYLOAD; the real exit still needs a plausible value here.
    /// `pad_to` (bytes of payload to pad the empty plaintext to) defaults
    /// to the circuit's full user-data budget, which makes a padding
    /// cell byte-identical in size to a maximum-length real message.
    ///
    /// Returns the number of bytes sent, so a caller can account for the
    /// overhead it is choosing to spend.
    ///
    /// # Errors
    /// Returns [`CircuitError::Build`] if the circuit has no hops yet.
    pub fn send_padding(&mut self, final_addr: Addr, pad_to: Option<usize>) -> Result<usize, CircuitError> {
        if self.hops.is_empty() {
            return Err(CircuitError::Build("cannot send padding: no hops established yet".to_string()));
        }
        let pad_to = match pad_to {
            Some(p) => p,
            // A full-budget pad makes this cell the same size as the
            // largest possible real message, so size cannot distinguish
            // the two.
            None => user_data_budget(self.hops.len(), PAYLOAD_SIZE)?.max(0) as usize,
        };
        let onion = self.encrypt(
            &[],
            final_addr,
            EncryptOptions {
                pad_to: Some(pad_to),
                kind: Some(Kind::PADDING),
                ..Default::default()
            },
        )?;
        let circuit_id = self.circuit_id.expect("hops established implies circuit_id is set");
        let cell = seal_into_cell(&onion, circuit_id, None)?;
        let datagram = cell.pack();
        let guard_addr = self.guard_addr.expect("hops established implies guard_addr is set");
        self.sock.send_to(&datagram, guard_addr).map_err(|e| CircuitError::Io(e.to_string()))?;
        Ok(datagram.len())
    }
}

impl<'a> std::fmt::Debug for CircuitBuilder<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CircuitBuilder(circuit_id={:?}, hops={:?}, addrs={:?})", self.circuit_id, self.names, self.addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{HandshakeError, HandshakeRelay};
    use std::net::UdpSocket;

    fn fixed_relay() -> HandshakeRelay {
        HandshakeRelay::new(Some([9u8; 32]), None, false, Some([8u8; 32]), true, false, None, 300.0).unwrap()
    }

    fn bound(addr: &str) -> UdpSocket {
        let sock = UdpSocket::bind(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        sock
    }

    // -- pure math ----------------------------------------------------------

    #[test]
    fn retry_sleep_seconds_is_zero_for_first_attempt() {
        assert_eq!(retry_sleep_seconds(0), 0.0);
        assert_eq!(retry_sleep_seconds(1), 0.0);
    }

    #[test]
    fn retry_sleep_seconds_grows_exponentially_and_caps() {
        for _ in 0..200 {
            let a2 = retry_sleep_seconds(2);
            assert!(a2 >= RETRY_BACKOFF_BASE && a2 <= RETRY_BACKOFF_BASE * (1.0 + RETRY_JITTER_FRACTION));
            let a3 = retry_sleep_seconds(3);
            let raw3 = RETRY_BACKOFF_BASE * 2.0;
            assert!(a3 >= raw3 && a3 <= raw3 * (1.0 + RETRY_JITTER_FRACTION));
        }
        // Large attempts hit the hard ceiling.
        for _ in 0..50 {
            let big = retry_sleep_seconds(20);
            assert!(big >= RETRY_BACKOFF_MAX && big <= RETRY_BACKOFF_MAX * (1.0 + RETRY_JITTER_FRACTION));
        }
    }

    #[test]
    fn jitter_delay_is_zero_for_non_positive_seconds() {
        assert_eq!(jitter_delay(0.0), 0.0);
        assert_eq!(jitter_delay(-1.0), 0.0);
    }

    #[test]
    fn jitter_delay_is_bounded_and_respects_max_send_jitter() {
        for _ in 0..200 {
            let d = jitter_delay(0.05);
            assert!((0.0..=0.05).contains(&d));
        }
        for _ in 0..200 {
            // A caller asking for more than MAX_SEND_JITTER is clamped.
            let d = jitter_delay(100.0);
            assert!((0.0..=MAX_SEND_JITTER).contains(&d));
        }
    }

    // -- pure onion-layer helpers (no sockets, no handshake) ---------------

    fn hop_pair(name: &str, key: &[u8; 32], mac: &[u8; 32], index: usize) -> OnionCrypto {
        OnionCrypto::new(name, key, key, Some(mac.to_vec()), Some(DEFAULT_CIPHER), index, None).unwrap()
    }

    /// A [`CircuitBuilder`] with one already-"established" hop, built
    /// directly from fixed key material rather than a real handshake --
    /// enough to exercise `route`/`encrypt`/`send`/`receive`/
    /// `send_padding` without a relay on the other end.
    fn builder_with_one_hop(sock: &UdpSocket, guard_addr: SocketAddr) -> CircuitBuilder<'_> {
        let mut builder = CircuitBuilder::new(sock, None, Duration::from_millis(200), None, true, false, 0, 0.0, None).unwrap();
        builder.circuit_id = Some(0x1234_5678);
        builder.guard_addr = Some(guard_addr);
        builder.hops.push(hop_pair("guard", &[7u8; 32], &[8u8; 32], 0));
        builder.addrs.push(("10.0.0.1".to_string(), 9001));
        builder.names.push("guard".to_string());
        builder
    }

    #[test]
    fn route_reflects_established_addrs_and_final_addr() {
        let sock = bound("127.0.0.1:0");
        let addr = sock.local_addr().unwrap();
        let builder = builder_with_one_hop(&sock, addr);
        let route = builder.route(("93.184.216.34".to_string(), 443)).unwrap();
        assert_eq!(route.hops, vec![("10.0.0.1".to_string(), 9001)]);
        assert_eq!(route.final_addr, ("93.184.216.34".to_string(), 443));
    }

    #[test]
    fn encrypt_pads_small_payloads_to_the_budget() {
        let sock = bound("127.0.0.1:0");
        let addr = sock.local_addr().unwrap();
        let mut builder = builder_with_one_hop(&sock, addr);
        let onion = builder.encrypt(b"hi", ("1.2.3.4".to_string(), 80), EncryptOptions::default()).unwrap();

        // Peel with an independently-built matching OnionCrypto to
        // confirm the sealed layer really does carry a padded plaintext.
        let relay_view = hop_pair("guard", &[7u8; 32], &[8u8; 32], 0);
        let (plaintext, header) = relay_view.peel_layer(&onion).unwrap();
        assert!(header.padded);
        assert_eq!(strip_plaintext_padding(&plaintext), b"hi");
    }

    #[test]
    fn encrypt_leaves_a_near_budget_payload_unpadded() {
        let sock = bound("127.0.0.1:0");
        let addr = sock.local_addr().unwrap();
        let mut builder = builder_with_one_hop(&sock, addr);
        let budget = user_data_budget(1, PAYLOAD_SIZE).unwrap() as usize;
        let payload = vec![0x42u8; budget]; // exactly at the budget: no room for the pad trailer
        let onion = builder.encrypt(&payload, ("1.2.3.4".to_string(), 80), EncryptOptions::default()).unwrap();

        let relay_view = hop_pair("guard", &[7u8; 32], &[8u8; 32], 0);
        let (plaintext, header) = relay_view.peel_layer(&onion).unwrap();
        assert!(!header.padded);
        assert_eq!(plaintext, payload);
    }

    #[test]
    fn send_then_receive_round_trips_through_two_real_sockets() {
        let client_sock = bound("127.0.0.1:0");
        let guard_sock = bound("127.0.0.1:0");
        let guard_addr = guard_sock.local_addr().unwrap();
        let client_addr = client_sock.local_addr().unwrap();

        let mut builder = builder_with_one_hop(&client_sock, guard_addr);
        builder.send(b"hello onion", ("93.184.216.34".to_string(), 443), EncryptOptions::default()).unwrap();

        // The "guard" receives the sealed cell; peel it with a matching
        // OnionCrypto (same key material) to recover the client's
        // message, then seal an unrelated PAYLOAD-kind reply the same
        // way a real exit's return traffic would look once every
        // backward layer has been re-wrapped down to just this hop's.
        let mut buf = [0u8; crate::cell::CELL_SIZE];
        let (n, from) = guard_sock.recv_from(&mut buf).unwrap();
        assert_eq!(from, client_addr);
        let cell = Cell::unpack(&buf[..n], true).unwrap();
        let onion = onion_from_cell(&cell, 0);
        let relay_view = hop_pair("guard", &[7u8; 32], &[8u8; 32], 0);
        let (plaintext, header) = relay_view.peel_layer(&onion).unwrap();
        assert!(header.padded);
        assert_eq!(strip_plaintext_padding(&plaintext), b"hello onion");

        let mut sealer = hop_pair("guard", &[7u8; 32], &[8u8; 32], 0);
        let reply_onion = sealer.seal_payload(b"reply payload", 0, ("9.9.9.9".to_string(), 53), None, None).unwrap();
        let reply_cell = seal_into_cell(&reply_onion, builder.circuit_id.unwrap(), None).unwrap();
        guard_sock.send_to(&reply_cell.pack(), client_addr).unwrap();

        let received = builder.receive(None).unwrap();
        assert_eq!(received, b"reply payload");
    }

    #[test]
    fn receive_rejects_a_cell_with_the_wrong_circuit_id() {
        // Regression test for finding L6: `receive()` used to peel any
        // cell that arrived from the guard's address without checking
        // its circuit id matched this circuit's own -- unlike
        // `extend_once`, which already checked this for an EXTENDED
        // reply.
        let client_sock = bound("127.0.0.1:0");
        let guard_sock = bound("127.0.0.1:0");
        let guard_addr = guard_sock.local_addr().unwrap();
        let client_addr = client_sock.local_addr().unwrap();

        let builder = builder_with_one_hop(&client_sock, guard_addr);

        let mut sealer = hop_pair("guard", &[7u8; 32], &[8u8; 32], 0);
        let reply_onion = sealer.seal_payload(b"reply payload", 0, ("9.9.9.9".to_string(), 53), None, None).unwrap();
        let wrong_circuit_id = builder.circuit_id.unwrap().wrapping_add(1);
        let reply_cell = seal_into_cell(&reply_onion, wrong_circuit_id, None).unwrap();
        guard_sock.send_to(&reply_cell.pack(), client_addr).unwrap();

        let err = builder.receive(Some(Duration::from_millis(200))).unwrap_err();
        assert!(matches!(err, CircuitError::Build(_)), "expected a Build error for a circuit-id mismatch, got {err:?}");
    }

    #[test]
    fn send_padding_produces_a_padding_kind_full_budget_cell() {
        let client_sock = bound("127.0.0.1:0");
        let guard_sock = bound("127.0.0.1:0");
        let guard_addr = guard_sock.local_addr().unwrap();

        let mut builder = builder_with_one_hop(&client_sock, guard_addr);
        let sent = builder.send_padding(("1.2.3.4".to_string(), 80), None).unwrap();
        assert_eq!(sent, crate::cell::CELL_SIZE);

        let mut buf = [0u8; crate::cell::CELL_SIZE];
        let (n, _from) = guard_sock.recv_from(&mut buf).unwrap();
        let cell = Cell::unpack(&buf[..n], true).unwrap();
        let onion = onion_from_cell(&cell, 0);
        let relay_view = hop_pair("guard", &[7u8; 32], &[8u8; 32], 0);
        let (plaintext, header) = relay_view.peel_layer(&onion).unwrap();
        assert_eq!(header.kind, Kind::PADDING);
        assert!(plaintext.is_empty() || strip_plaintext_padding(&plaintext).is_empty());
    }

    #[test]
    fn seq_counter_wraps_at_2_pow_32() {
        let sock = bound("127.0.0.1:0");
        let addr = sock.local_addr().unwrap();
        let mut builder = builder_with_one_hop(&sock, addr);
        builder.seq_counter = u32::MAX;
        assert_eq!(builder.next_seq(), u32::MAX);
        assert_eq!(builder.next_seq(), 0);
        assert_eq!(builder.next_seq(), 1);
    }

    // -- add_hop() over real UDP sockets, against a real HandshakeRelay ----

    #[test]
    fn add_hop_must_be_called_before_extend_or_receive() {
        let sock = bound("127.0.0.1:0");
        let mut builder = CircuitBuilder::new(&sock, None, Duration::from_millis(100), None, true, false, 0, 0.0, None).unwrap();
        let err = builder.extend("middle", ("127.0.0.1".to_string(), 1), None, None, None).unwrap_err();
        assert!(matches!(err, CircuitError::Build(_)));
        let err = builder.receive(None).unwrap_err();
        assert!(matches!(err, CircuitError::Build(_)));
    }

    #[test]
    fn add_hop_twice_is_rejected() {
        let client_sock = bound("127.0.0.1:0");
        let relay_sock = bound("127.0.0.1:0");
        let relay_addr = relay_sock.local_addr().unwrap();
        let mut relay = fixed_relay();

        let handle = std::thread::spawn(move || relay.serve_once(&relay_sock).unwrap());

        let mut builder = CircuitBuilder::new(&client_sock, None, Duration::from_secs(2), None, true, false, 0, 0.0, None).unwrap();
        builder.add_hop("guard", ("127.0.0.1".to_string(), relay_addr.port()), None, None, None).unwrap();
        handle.join().unwrap();

        let err = builder.add_hop("guard-again", ("127.0.0.1".to_string(), relay_addr.port()), None, None, None).unwrap_err();
        assert!(matches!(err, CircuitError::Build(_)));
    }

    #[test]
    fn add_hop_completes_a_real_handshake_over_udp() {
        let client_sock = bound("127.0.0.1:0");
        let relay_sock = bound("127.0.0.1:0");
        let relay_addr = relay_sock.local_addr().unwrap();
        let mut relay = fixed_relay();
        let relay_identity = relay.identity_public;

        let handle = std::thread::spawn(move || relay.serve_once(&relay_sock).unwrap());

        let mut trusted = HashMap::new();
        trusted.insert("guard".to_string(), vec![relay_identity]);
        let mut builder =
            CircuitBuilder::new(&client_sock, None, Duration::from_secs(2), Some(trusted), false, false, 0, 0.0, None).unwrap();
        let keys = builder.add_hop("guard", ("127.0.0.1".to_string(), relay_addr.port()), None, None, None).unwrap();
        handle.join().unwrap();

        assert!(keys.relay_is_authenticated());
        assert_eq!(builder.hop_count(), 1);
        assert_eq!(builder.names, vec!["guard".to_string()]);
        assert_eq!(builder.keys.len(), 1);
        assert!(builder.circuit_id.is_some());
        assert_eq!(builder.guard_addr, Some(relay_addr));
    }


    /// Time ten sends on a one-hop circuit whose jitter is 0.3 s.
    fn time_ten_sends(unjittered: bool) -> Duration {
        let client_sock = bound("127.0.0.1:0");
        let relay_sock = bound("127.0.0.1:0");
        let relay_addr = relay_sock.local_addr().unwrap();
        let mut relay = fixed_relay();
        let handle = std::thread::spawn(move || relay.serve_once(&relay_sock).unwrap());
        let mut builder = CircuitBuilder::new(&client_sock, None, Duration::from_secs(2), None, true, false, 0, 0.3, None).unwrap();
        builder.add_hop("guard", ("127.0.0.1".to_string(), relay_addr.port()), None, None, None).unwrap();
        handle.join().unwrap();
        let dest = ("127.0.0.1".to_string(), 9);
        let started = Instant::now();
        for _ in 0..10 {
            if unjittered {
                builder.send_unjittered(b"ack", dest.clone(), EncryptOptions::default()).unwrap();
            } else {
                builder.send(b"ack", dest.clone(), EncryptOptions::default()).unwrap();
            }
        }
        started.elapsed()
    }

    #[test]
    fn send_unjittered_never_waits_but_send_still_does() {
        // Ten uniform delays in [0, 0.3 s] sum to under 0.3 s with
        // probability 1/10! (about 3e-7), so a jittered run is reliably slow.
        let jittered = time_ten_sends(false);
        assert!(jittered > Duration::from_millis(300), "send() must still apply jitter, took only {jittered:?}");
        let quick = time_ten_sends(true);
        assert!(quick < Duration::from_millis(150), "send_unjittered() must not wait, took {quick:?}");
    }

    #[test]
    fn send_unjittered_leaves_the_circuits_jitter_setting_alone() {
        let client_sock = bound("127.0.0.1:0");
        let relay_sock = bound("127.0.0.1:0");
        let relay_addr = relay_sock.local_addr().unwrap();
        let mut relay = fixed_relay();
        let handle = std::thread::spawn(move || relay.serve_once(&relay_sock).unwrap());
        let mut builder = CircuitBuilder::new(&client_sock, None, Duration::from_secs(2), None, true, false, 0, 0.25, None).unwrap();
        builder.add_hop("guard", ("127.0.0.1".to_string(), relay_addr.port()), None, None, None).unwrap();
        handle.join().unwrap();
        builder.send_unjittered(b"ack", ("127.0.0.1".to_string(), 9), EncryptOptions::default()).unwrap();
        assert_eq!(builder.send_jitter, 0.25);
    }

    #[test]
    fn add_hop_retries_past_a_single_dropped_attempt() {
        let client_sock = bound("127.0.0.1:0");
        // No read timeout here: this thread deliberately waits out the
        // client's own 300ms timeout plus its retry backoff before the
        // second CREATE arrives, which can take close to a second.
        let relay_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay_sock.local_addr().unwrap();
        let mut relay = fixed_relay();

        // Answer only the *second* CREATE this relay receives -- the
        // first attempt is a genuine timeout from the client's point of
        // view, exercising the retry path end to end.
        let handle = std::thread::spawn(move || {
            let _dropped = relay_sock.recv_from(&mut [0u8; crate::cell::CELL_SIZE]).unwrap();
            relay.serve_once(&relay_sock).unwrap()
        });

        let mut builder =
            CircuitBuilder::new(&client_sock, None, Duration::from_millis(300), None, true, false, 1, 0.0, None).unwrap();
        let keys = builder.add_hop("guard", ("127.0.0.1".to_string(), relay_addr.port()), None, Some(1), None).unwrap();
        handle.join().unwrap();
        assert!(!keys.aead_key_fwd.is_empty());
        assert!(!keys.aead_key_bwd.is_empty());
        assert_eq!(builder.hop_count(), 1);
    }

    #[test]
    fn add_hop_gives_up_with_no_retries_configured() {
        // Nothing is listening at this address, so every attempt times
        // out; with retries=0 the raw timeout propagates directly rather
        // than being wrapped as AttemptsExhausted.
        let client_sock = bound("127.0.0.1:0");
        let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut builder =
            CircuitBuilder::new(&client_sock, None, Duration::from_millis(100), None, true, false, 0, 0.0, None).unwrap();
        let err = builder.add_hop("guard", ("127.0.0.1".to_string(), dead_addr.port()), None, None, None).unwrap_err();
        match err {
            CircuitError::Handshake(HandshakeError::Timeout(_)) => {}
            other => panic!("expected a raw Handshake(Timeout(..)), got {other:?}"),
        }
    }

    #[test]
    fn add_hop_wraps_exhausted_retries() {
        let client_sock = bound("127.0.0.1:0");
        let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut builder =
            CircuitBuilder::new(&client_sock, None, Duration::from_millis(50), None, true, false, 0, 0.0, None).unwrap();
        let err = builder
            .add_hop("guard", ("127.0.0.1".to_string(), dead_addr.port()), None, Some(1), None)
            .unwrap_err();
        assert!(matches!(err, CircuitError::AttemptsExhausted(_)));
    }

    #[test]
    fn extend_before_add_hop_is_a_build_error() {
        let sock = bound("127.0.0.1:0");
        let mut builder = CircuitBuilder::new(&sock, None, Duration::from_millis(100), None, true, false, 0, 0.0, None).unwrap();
        let err = builder.extend("middle", ("127.0.0.1".to_string(), 1), None, None, None).unwrap_err();
        assert!(matches!(err, CircuitError::Build(_)));
    }

    #[test]
    fn extend_times_out_when_nothing_answers_the_forwarded_request() {
        // A real guard hop, but nothing ever answers the onion-wrapped
        // EXTEND itself (no relay-forwarding harness here -- see the
        // module docs on `extend`), so this exercises `_extend_once`'s
        // send path and the EXTENDED-reply timeout.
        let client_sock = bound("127.0.0.1:0");
        let relay_sock = bound("127.0.0.1:0");
        let relay_addr = relay_sock.local_addr().unwrap();
        let mut relay = fixed_relay();
        let handle = std::thread::spawn(move || relay.serve_once(&relay_sock).unwrap());

        let mut builder =
            CircuitBuilder::new(&client_sock, None, Duration::from_millis(150), None, true, false, 0, 0.0, None).unwrap();
        builder.add_hop("guard", ("127.0.0.1".to_string(), relay_addr.port()), None, None, None).unwrap();
        handle.join().unwrap();

        let err = builder.extend("middle", ("127.0.0.1".to_string(), 65000), None, None, None).unwrap_err();
        assert!(matches!(err, CircuitError::ExtendTimeout(_)), "expected ExtendTimeout, got {err:?}");
    }
}
