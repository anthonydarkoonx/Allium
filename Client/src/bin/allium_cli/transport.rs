//! Bridges `allium::socksproxy::SocksServer`'s byte-oriented `Onion`
//! callback to a real circuit (port of `allium_cli.py`'s `CircuitTransport`).
//!
//! Owns the socket and the built circuit (through [`OwnedCircuit`], which
//! is what makes this `'static` and therefore usable from inside an
//! `Onion = Arc<dyn Fn(&[u8]) + Send + Sync>` closure and from a spawned
//! `std::thread`), fragments outgoing payloads, applies congestion control,
//! and reads return-path cells back off the wire.
//!
//! Python serializes every access to the shared socket with one
//! `threading.RLock`, but only ever holds it for a quick non-blocking
//! read+peel -- the actual *wait* for the socket to become readable
//! happens separately, via `select.select`, with the lock not held at
//! all. This uses [`OwnedCircuit`]'s own `Mutex`, and matches that same
//! shape via a raw `poll(2)` wait that also does not hold the lock -- see
//! [`CircuitTransport::receive`]'s doc for why that distinction still
//! matters on real OS threads (an earlier version of this method tried to
//! approximate it by only *bounding* each locked wait to a short slice
//! instead, which sounds equivalent but is not: see the doc there for the
//! deadlock/starvation that produced).

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use allium::circuit::EncryptOptions;
use allium::congestion::CongestionController;
use allium::fragment::{decode_fragment, FragmentError, Reassembler};
use allium::socks::{DATAGRAM_MAGIC, MAGIC};

use crate::helpers::{encode_ack_frame, ACK_EVERY_BYTES};
use crate::owned_circuit::OwnedCircuit;

/// Matches `allium::socksproxy`'s own reassembler bound, so a return-path
/// stream cannot be made to buffer more out-of-order data than the SOCKS
/// server itself would tolerate for a forward one.
const MAX_PENDING: usize = 4096;

/// Most distinct stream ids `receive` will track reassembly state for at
/// once (matches `allium::socksproxy`'s own `MAX_REASSEMBLERS`). A fragment
/// is exit-chosen data this client did not initiate, so nothing here ties
/// a stream id back to a CONNECT this client actually sent -- without a
/// cap, a malicious exit can keep minting fresh stream ids (each good for
/// up to `MAX_PENDING` buffered chunks across `reassemblers`,
/// `ack_progress` and `last_acked`) and the tables grow without bound
/// until the client is killed for memory use.
const MAX_RETURN_REASSEMBLERS: usize = 1024;

/// One return-path read's outcome: `stream_id` is `None` for a whole
/// control/datagram frame (see the field doc on the Python original this
/// mirrors -- [`CircuitTransport::receive`]).
pub struct Received {
    pub stream_id: Option<u32>,
    pub payload: Vec<u8>,
}

pub struct CircuitTransport {
    circuit: OwnedCircuit,
    congestion: Option<Mutex<CongestionController>>,
    pub sent_cells: AtomicU64,
    pub received_cells: AtomicU64,
    pub window_overruns: AtomicU64,
    /// Stream ids the exit has signalled as finished (FIN received),
    /// consumed and cleared by `pump_return_path` as it notices each one.
    finished_streams: Mutex<std::collections::HashSet<u32>>,
    reassemblers: Mutex<HashMap<u32, Reassembler>>,
    ack_progress: Mutex<HashMap<u32, u64>>,
    last_acked: Mutex<HashMap<u32, u64>>,
    /// Bounded, insertion-ordered (a `Vec` of keys alongside the map, same
    /// as Python's `dict` insertion order) record of recently-completed
    /// streams' final byte counts.
    completed: Mutex<(HashMap<u32, u64>, Vec<u32>)>,
}

impl CircuitTransport {
    pub fn new(circuit: OwnedCircuit, congestion: bool) -> Self {
        let congestion = if congestion {
            Some(Mutex::new(
                CongestionController::new(4, allium::congestion::DEFAULT_MIN_CWND, 256, 1, 0.5)
                    .expect("4 initial / 1..=256 cwnd bounds are always valid"),
            ))
        } else {
            None
        };
        CircuitTransport {
            circuit,
            congestion,
            sent_cells: AtomicU64::new(0),
            received_cells: AtomicU64::new(0),
            window_overruns: AtomicU64::new(0),
            finished_streams: Mutex::new(std::collections::HashSet::new()),
            reassemblers: Mutex::new(HashMap::new()),
            ack_progress: Mutex::new(HashMap::new()),
            last_acked: Mutex::new(HashMap::new()),
            completed: Mutex::new((HashMap::new(), Vec::new())),
        }
    }

    fn final_addr(&self) -> allium::circuit::Addr {
        let builder = self.circuit.lock();
        builder.addrs.last().cloned().expect("a live transport always wraps a fully built circuit")
    }

    /// Send one cell's worth of bytes through the circuit.
    ///
    /// **No fragmentation happens here** -- see the Python original's
    /// docstring, word for word true here too: the caller (`SocksServer`'s
    /// relay loop) already fragments application bytes before calling
    /// this.
    ///
    /// The congestion window is advisory, not a blocking gate: this can run
    /// on the same thread whose own progress is what would reopen the
    /// window (acks arrive via the receive-pump thread, a different one --
    /// still, blocking here on a full window would let one slow circuit
    /// wedge whichever caller thread is relaying on it). When the window is
    /// full the cell is still sent, but counted so the operator can see the
    /// overrun.
    pub fn send(&self, payload: &[u8]) {
        if let Some(congestion) = &self.congestion {
            let c = congestion.lock().unwrap();
            if !c.can_send() {
                self.window_overruns.fetch_add(1, Ordering::Relaxed);
            }
        }
        let final_addr = self.final_addr();
        {
            let mut builder = self.circuit.lock();
            // Best-effort, matching every other send site in this binary:
            // a circuit send failing here surfaces to the caller as no
            // return traffic ever arriving, exactly as it would in Python
            // (an uncaught OSError there propagates out of `send`, and
            // every caller already treats "nothing comes back" as the
            // normal failure mode for a dead circuit).
            let _ = builder.send(payload, final_addr, EncryptOptions::default());
            self.sent_cells.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(congestion) = &self.congestion {
            congestion.lock().unwrap().on_send(1);
        }
    }

    /// Send a stream control frame (CONNECT/RESOLVE) unfragmented.
    /// Identical wire behavior to [`Self::send`] today; kept as its own
    /// method (matching Python) so a future change to `send`'s
    /// fragmentation-adjacent bookkeeping does not silently also apply to
    /// control frames.
    pub fn send_stream_request(&self, payload: &[u8]) {
        let final_addr = self.final_addr();
        let mut builder = self.circuit.lock();
        let _ = builder.send(payload, final_addr, EncryptOptions::default());
        self.sent_cells.fetch_add(1, Ordering::Relaxed);
    }

    /// Send one UDP datagram request/reply frame through the circuit,
    /// deliberately not via [`Self::send`] -- see the Python original's
    /// docstring: a datagram must reach the wire as exactly the one whole
    /// `ALDG` frame it was encoded as, never run through a `Fragmenter`.
    pub fn send_datagram(&self, payload: &[u8]) {
        let final_addr = self.final_addr();
        let mut builder = self.circuit.lock();
        let _ = builder.send(payload, final_addr, EncryptOptions::default());
        self.sent_cells.fetch_add(1, Ordering::Relaxed);
    }

    fn send_ack(&self, stream_id: u32, offset: u64) {
        let final_addr = self.final_addr();
        let mut builder = self.circuit.lock();
        // No jitter: see `CircuitBuilder::send_unjittered`.
        let _ = builder.send_unjittered(&encode_ack_frame(stream_id, offset as u32), final_addr, EncryptOptions::default());
        self.sent_cells.fetch_add(1, Ordering::Relaxed);
    }

    /// Ack whatever has been received for `stream_id` right now, regardless
    /// of [`Self::receive`]'s usual ack-every-`ACK_EVERY_BYTES` policy --
    /// see the Python original's docstring for why a caller that is done
    /// with a stream needs this to stop the exit's blind retransmits
    /// promptly instead of waiting out its retry timer.
    pub fn force_ack(&self, stream_id: u32) {
        let progress = *self.ack_progress.lock().unwrap().get(&stream_id).unwrap_or(&0);
        let last = *self.last_acked.lock().unwrap().get(&stream_id).unwrap_or(&0);
        if progress == 0 || progress <= last {
            return;
        }
        self.send_ack(stream_id, progress);
        self.last_acked.lock().unwrap().insert(stream_id, progress);
    }

    /// Read one return-path cell, peeled back to the exit's payload.
    ///
    /// Python's version waits for the socket to become readable via
    /// `select.select` *without* holding its lock, taking the lock only
    /// for the quick non-blocking read+peel that follows -- specifically
    /// so a slow receive timeout could never starve a sender sharing the
    /// same lock (a real bug on the event-loop thread there).
    ///
    /// An earlier version of this method tried to reach the same goal
    /// without a `select`-on-`UdpSocket` equivalent by instead *bounding*
    /// each locked wait to a short (250ms) slice, on the theory that a
    /// sender would then be blocked "for at most one slice, not the whole
    /// timeout". That reasoning has a hole: this method's caller
    /// (`pump_return_path`) calls it again immediately on every timeout,
    /// for as long as the circuit lives, so in practice this thread
    /// re-takes the lock again within a handful of instructions of
    /// releasing it -- essentially always holding it. `std::sync::Mutex`
    /// is not FIFO-fair, so a sender thread parked waiting on the same
    /// lock can lose that race indefinitely: on a live VPS-connected
    /// client this was observed (via `gdb`'s `thread apply all bt`) as an
    /// unbounded hang, with the pump thread genuinely blocked inside the
    /// `recvfrom()` syscall while holding the lock, and a SOCKS thread
    /// blocked in `Mutex::lock_contended` unable to get in edgewise to
    /// send a new CONNECT. No single lock hold was ever too long; the gaps
    /// between them just never landed a waiter.
    ///
    /// The fix restores Python's actual shape: [`wait_readable`] blocks on
    /// a raw `poll(2)` of the socket's fd, *without* touching
    /// `self.circuit` at all, so a sender can take the lock at any point
    /// during that wait, however long it runs. The lock is only taken
    /// once the fd is (very likely) readable, for a short bounded
    /// `builder.receive` call that should return near-instantly -- the
    /// bound still matters for the rarer case where what arrived was
    /// stray traffic from an unexpected sender, which
    /// `CircuitBuilder::receive`/`recv_from` discard and loop past
    /// internally (see their own "M3" doc).
    pub fn receive(&self, timeout: Duration) -> std::io::Result<Received> {
        let deadline = Instant::now() + timeout.max(Duration::from_millis(50));
        const READ_SLICE: Duration = Duration::from_millis(250);
        let raw = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "no return traffic within timeout"));
            }
            if !wait_readable(self.circuit.raw_fd(), remaining)? {
                continue; // plain timeout on this wait -- recheck the overall deadline
            }
            let attempt = {
                let builder = self.circuit.lock();
                builder.receive(Some(READ_SLICE))
            };
            match attempt {
                Ok(raw) => break raw,
                Err(_) => continue,
            }
        };
        self.received_cells.fetch_add(1, Ordering::Relaxed);

        if raw.starts_with(MAGIC) {
            return Ok(Received { stream_id: None, payload: raw });
        }
        if raw.starts_with(DATAGRAM_MAGIC) {
            return Ok(Received { stream_id: None, payload: raw });
        }
        let fragment = match decode_fragment(&raw) {
            Ok(f) => f,
            Err(FragmentError(_)) => return Ok(Received { stream_id: None, payload: raw }),
        };

        {
            let completed = self.completed.lock().unwrap();
            if let Some(&final_progress) = completed.0.get(&fragment.stream_id) {
                drop(completed);
                self.send_ack(fragment.stream_id, final_progress);
                return Ok(Received { stream_id: Some(fragment.stream_id), payload: Vec::new() });
            }
        }

        let mut reassemblers = self.reassemblers.lock().unwrap();
        if !reassemblers.contains_key(&fragment.stream_id) && reassemblers.len() >= MAX_RETURN_REASSEMBLERS {
            // Table full of distinct stream ids: refuse to track a new one
            // rather than grow without bound (see `MAX_RETURN_REASSEMBLERS`).
            // A live stream already being reassembled is never evicted to
            // make room -- dropping its position would corrupt it.
            return Ok(Received { stream_id: Some(fragment.stream_id), payload: Vec::new() });
        }
        let reassembler = reassemblers.entry(fragment.stream_id).or_insert_with(|| Reassembler::new(fragment.stream_id, MAX_PENDING));
        let data = match reassembler.push(&fragment) {
            Ok(data) => data,
            Err(FragmentError(_)) => {
                return Ok(Received { stream_id: Some(fragment.stream_id), payload: Vec::new() });
            }
        };

        let mut ack_progress = self.ack_progress.lock().unwrap();
        let progress = if !data.is_empty() {
            let p = ack_progress.get(&fragment.stream_id).copied().unwrap_or(0) + data.len() as u64;
            ack_progress.insert(fragment.stream_id, p);
            p
        } else {
            ack_progress.get(&fragment.stream_id).copied().unwrap_or(0)
        };
        drop(ack_progress);

        let finished = reassembler.finished();
        if finished {
            self.finished_streams.lock().unwrap().insert(fragment.stream_id);
        }

        let last_acked = self.last_acked.lock().unwrap();
        let last = last_acked.get(&fragment.stream_id).copied().unwrap_or(0);
        if progress.saturating_sub(last) >= ACK_EVERY_BYTES || fragment.fin || finished {
            drop(last_acked);
            self.send_ack(fragment.stream_id, progress);
            self.last_acked.lock().unwrap().insert(fragment.stream_id, progress);
        }

        if finished {
            reassemblers.remove(&fragment.stream_id);
            self.ack_progress.lock().unwrap().remove(&fragment.stream_id);
            self.last_acked.lock().unwrap().remove(&fragment.stream_id);
            drop(reassemblers);
            let mut completed = self.completed.lock().unwrap();
            completed.0.insert(fragment.stream_id, progress);
            completed.1.push(fragment.stream_id);
            while completed.1.len() > 1024 {
                let oldest = completed.1.remove(0);
                completed.0.remove(&oldest);
            }
        }

        Ok(Received { stream_id: Some(fragment.stream_id), payload: data })
    }

    /// Take (and clear) the stream ids the exit has signalled finished
    /// since the last call -- `pump_return_path`'s counterpart to Python's
    /// direct `transport.finished_streams` iterate-and-discard loop.
    pub fn take_finished_streams(&self) -> Vec<u32> {
        let mut set = self.finished_streams.lock().unwrap();
        let ids: Vec<u32> = set.drain().collect();
        ids
    }

    /// Exposed for tests exercising a `CircuitTransport` end to end
    /// without a real network (asserting a fake/local circuit's shape).
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn hop_count(&self) -> usize {
        self.circuit.lock().hop_count()
    }

    /// The last hop's verified identity (used by `CircuitPool::retry_onion`
    /// to remember which exit to avoid). `None` only if `hop_count() == 0`,
    /// which never happens for a live transport.
    pub fn exit_identity(&self) -> Option<Vec<u8>> {
        self.circuit.lock().keys.last().and_then(|k| k.identity_public.map(|id| id.to_vec()))
    }

    pub fn congestion_snapshot(&self) -> Option<(u32, u64)> {
        self.congestion.as_ref().map(|c| {
            let c = c.lock().unwrap();
            (c.cwnd, c.loss_events)
        })
    }
}

/// Block until `fd` has data waiting to be read, or `timeout` elapses --
/// deliberately a free function taking a raw fd, not a method on anything
/// that holds a lock, so it is structurally impossible to call this while
/// holding `self.circuit`. See [`CircuitTransport::receive`]'s doc for why
/// that separation is the actual fix for the deadlock/starvation bug found
/// there.
///
/// Returns `Ok(true)` once the fd is readable, `Ok(false)` on a plain
/// timeout, and only errs on a genuine unrecoverable `poll(2)` failure --
/// `EINTR` (a signal arriving mid-wait; this binary installs a `SIGINT`/
/// `SIGTERM` handler, see `signals.rs`) is retried internally against the
/// same overall deadline rather than surfaced as an error.
pub(crate) fn wait_readable(fd: RawFd, timeout: Duration) -> std::io::Result<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        // `poll(2)`'s timeout is milliseconds, `i32`, with `-1` meaning
        // "forever" -- clamp so a large `remaining` can never accidentally
        // become that (or overflow), rather than genuinely wait forever.
        let millis = remaining.as_millis().min(i32::MAX as u128 - 1) as i32;
        let mut fds = [libc::pollfd { fd, events: libc::POLLIN, revents: 0 }];
        // SAFETY: `fds` is a correctly-sized, live array for the duration
        // of this call, and `poll` only reads/writes through the pointer
        // and length given here.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, millis) };
        if ready < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if ready == 0 {
            return Ok(false);
        }
        // Readable, or the socket hit an error/hangup condition
        // (`POLLERR`/`POLLHUP`, which `poll` always reports regardless of
        // the requested `events`) -- either way, hand off to the real
        // `recv_from` rather than trying to diagnose the fd here.
        return Ok(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    use allium::circuit::{CircuitBuilder, CircuitError};
    use allium::handshake::HandshakeRelay;

    /// A real one-hop `OwnedCircuit`, built against a real (if
    /// single-shot) [`HandshakeRelay`] over loopback -- deliberately *not*
    /// the zero-hop fixture `pool.rs`'s tests use (`CircuitBuilder::new`
    /// with no `add_hop`), because a zero-hop builder's `receive` returns
    /// `Err(CircuitError::Build(_))` immediately without ever touching the
    /// socket (see its own doc), which would make the regression test
    /// below vacuous: it needs a `guard_addr` actually set so `receive`
    /// genuinely calls into `recv_from`/`libc::poll` and can genuinely
    /// block, exactly like the live deadlock this guards against.
    fn one_hop_owned_circuit() -> crate::owned_circuit::OwnedCircuit {
        one_hop_owned_circuit_with_jitter(0.0)
    }

    fn one_hop_owned_circuit_with_jitter(jitter: f64) -> crate::owned_circuit::OwnedCircuit {
        let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        relay_sock.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let relay_addr = relay_sock.local_addr().unwrap();
        let mut relay = HandshakeRelay::new(Some([9u8; 32]), None, false, Some([8u8; 32]), true, false, None, 300.0).unwrap();

        let handshake = std::thread::spawn(move || relay.serve_once(&relay_sock).unwrap());

        let owned = crate::owned_circuit::OwnedCircuit::new(client_sock, |s| {
            let mut builder = CircuitBuilder::new(s, None, Duration::from_secs(2), None, true, false, 0, jitter, None)?;
            builder.add_hop("guard", ("127.0.0.1".to_string(), relay_addr.port()), None, None, None)?;
            Ok::<_, CircuitError>(builder)
        })
        .unwrap();

        handshake.join().unwrap();
        owned
    }

    /// Regression test for the live deadlock diagnosed via `gdb`: a
    /// `receive()`-pumping thread (standing in for `pump_return_path`,
    /// which really does call `receive` back-to-back for as long as the
    /// circuit lives) must never starve a concurrent `send()` out of the
    /// shared circuit lock, no matter how long or how often `receive`
    /// itself blocks waiting for return traffic that never arrives.
    ///
    /// Under the old "bound each locked wait to a short slice" design
    /// this test reliably reproduced the bug: `send()` routinely took
    /// several seconds (in practice, however long the test's overall
    /// timeout budget allowed) to get the lock, because the pump thread
    /// re-took it again within nanoseconds of releasing it, every single
    /// time, and `std::sync::Mutex` gave the waiting `send()` no
    /// fairness guarantee against that. With the fix (waiting for
    /// readability via `libc::poll` *outside* the lock), `send()` should
    /// get in essentially immediately.
    #[test]
    fn receive_pump_does_not_starve_a_concurrent_send() {
        let owned = one_hop_owned_circuit();
        let transport = Arc::new(CircuitTransport::new(owned, false));

        // Nothing ever arrives on `client_sock` after the handshake (the
        // relay only ever answers once, via `serve_once`), so every
        // `receive()` call here times out and the loop immediately
        // starts another -- exactly `pump_return_path`'s real shape.
        let pump_transport = Arc::clone(&transport);
        let stop = Arc::new(AtomicBool::new(false));
        let pump_stop = Arc::clone(&stop);
        let pump = std::thread::spawn(move || {
            while !pump_stop.load(Ordering::Relaxed) {
                // 2s, not the 5s `run_client` actually defaults to
                // (`args.timeout`) -- long enough to clearly reproduce
                // the starvation under the old design (a `send()` stuck
                // behind it would take close to this long, not just a
                // few stray milliseconds), short enough to keep this
                // test's worst case (waiting out one in-flight call
                // after `stop` is set, below) fast.
                let _ = pump_transport.receive(Duration::from_secs(2));
            }
        });

        // Give the pump thread time to actually be inside its receive
        // loop (and therefore holding, or about to re-take, the lock)
        // before racing it.
        std::thread::sleep(Duration::from_millis(200));

        let start = Instant::now();
        transport.send(b"hello");
        let elapsed = start.elapsed();

        stop.store(true, Ordering::Relaxed);
        pump.join().unwrap();

        assert!(
            elapsed < Duration::from_secs(1),
            "send() took {elapsed:?} to acquire the circuit lock while a receive-pump \
             thread was running -- this is the starvation/deadlock bug `receive`'s doc \
             describes, not just slowness",
        );
    }

    /// Downloads were capped near 0.4 MB/s because each ack, sent from the
    /// thread that reads incoming cells, waited out the send jitter first.
    #[test]
    fn acks_are_not_delayed_by_send_jitter_but_other_sends_still_are() {
        let transport = CircuitTransport::new(one_hop_owned_circuit_with_jitter(0.3), false);
        let started = Instant::now();
        for i in 0..10 {
            transport.send_ack(1, i * 8192);
        }
        let acks = started.elapsed();
        assert!(acks < Duration::from_millis(150), "ten acks took {acks:?}: they are being jittered");
        // Same transport, same jitter setting: an ordinary send still waits
        // (ten uniform delays in [0, 0.3 s] total under 0.3 s with probability ~3e-7).
        let started = Instant::now();
        for _ in 0..10 {
            transport.send_datagram(b"not an ack");
        }
        let data = started.elapsed();
        assert!(data > Duration::from_millis(300), "ordinary sends must keep their jitter, took only {data:?}");
    }
}
