//! End-to-end congestion control for an Allium circuit.
//!
//! The reliability layer ([`crate::reliability`]) answers *"was this cell
//! lost?"*; this module answers the harder question *"how fast may I
//! send?"*. It is deliberately **end-to-end**: only the client and the
//! exit run it. Intermediate relays forward cells blindly and keep no
//! per-stream state, which is exactly the property the protocol requires
//! -- a middle hop that managed congestion state would learn where streams
//! start and stop, and would have to hold per-flow bookkeeping for traffic
//! it cannot decrypt.
//!
//! Two pieces, the standard pair:
//!
//! * [`RttEstimator`] -- smoothed round-trip time and variance
//!   (Jacobson/Karels, the algorithm TCP still uses), yielding an adaptive
//!   retransmission timeout.
//! * [`CongestionController`] -- AIMD: additive increase, multiplicative
//!   decrease. Slow start doubles the window per RTT until the first
//!   loss, then congestion avoidance grows it slowly, and every loss
//!   event backs it off. A [`CongestionController::can_send`] gate caps
//!   how many cells may be in flight, so a sender queues rather than
//!   floods.
//!
//! Everything here is pure bookkeeping, fully unit-testable without a
//! network, matching the rest of the library.
//!
//! One deliberate departure from the reference implementation:
//! [`CongestionController::on_loss`]'s timeout path backs `cwnd` off to a
//! quarter of its pre-loss value instead of collapsing it straight to
//! `min_cwnd` (plain RFC 5681). A hard collapse-to-floor is fine for a bulk
//! transfer, but on a real-time stream (e.g. video) it turns one ordinary
//! loss event into several seconds of near-zero throughput while slow
//! start climbs back up -- a visible stall. See the doc comment on
//! `on_loss` for the reasoning and the recovery-time math.

use crate::reliability::DEFAULT_RTO;

/// Initial congestion window, in cells. Small but not one: starting at one
/// makes a short circuit's setup pathologically slow (every RTT moves one
/// cell).
pub const DEFAULT_INITIAL_CWND: u32 = 4;

/// Floor on cwnd, so a burst of losses can never drive the window to zero
/// and deadlock the stream.
pub const DEFAULT_MIN_CWND: u32 = 1;

/// Ceiling on cwnd, bounding in-flight memory regardless of how clean the
/// path is.
pub const DEFAULT_MAX_CWND: u32 = 512;

/// Initial RTO before any RTT sample exists.
pub const DEFAULT_INITIAL_RTO: f64 = DEFAULT_RTO;

/// RFC 6298 floors the RTO at one second in TCP; on a single-circuit
/// datagram transport that is far too slow, so the floor is much lower
/// here.
pub const DEFAULT_MIN_RTO: f64 = 0.05;

/// Cap on the RTO, so one very delayed ack cannot stall a stream for
/// minutes.
pub const DEFAULT_MAX_RTO: f64 = 30.0;

/// SRTT smoothing weight (RFC 6298's alpha).
pub const DEFAULT_RTT_ALPHA: f64 = 0.125;

/// RTTVAR smoothing weight (RFC 6298's beta).
pub const DEFAULT_RTT_BETA: f64 = 0.25;

/// A congestion-control invariant was violated (bad constructor arguments,
/// or a negative RTT sample).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CongestionError(pub String);

impl std::fmt::Display for CongestionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for CongestionError {}

/// Smoothed RTT and variance, and the retransmission timeout they imply.
///
/// Implements RFC 6298's estimator:
///
/// ```text
/// first sample:   srtt = r, rttvar = r / 2
/// later samples:  rttvar = (1-beta) * rttvar + beta * |srtt - r|
///                 srtt   = (1-alpha) * srtt + alpha * r
///
/// rto = srtt + 4 * rttvar,  clamped to [min_rto, max_rto]
/// ```
pub struct RttEstimator {
    pub alpha: f64,
    pub beta: f64,
    pub min_rto: f64,
    pub max_rto: f64,
    initial_rto: f64,
    srtt: Option<f64>,
    rttvar: Option<f64>,
    /// How many RTT samples have been fed in.
    pub samples: u64,
}

impl RttEstimator {
    /// # Errors
    /// Returns [`CongestionError`] if `alpha`/`beta` are outside `(0, 1]`,
    /// `min_rto` is not positive, or `max_rto < min_rto`.
    pub fn new(alpha: f64, beta: f64, min_rto: f64, max_rto: f64, initial_rto: f64) -> Result<Self, CongestionError> {
        if !(0.0 < alpha && alpha <= 1.0) {
            return Err(CongestionError(format!("alpha must be in (0, 1], got {alpha}")));
        }
        if !(0.0 < beta && beta <= 1.0) {
            return Err(CongestionError(format!("beta must be in (0, 1], got {beta}")));
        }
        if min_rto <= 0.0 {
            return Err(CongestionError(format!("min_rto must be positive, got {min_rto}")));
        }
        if max_rto < min_rto {
            return Err(CongestionError(format!("max_rto {max_rto} must be >= min_rto {min_rto}")));
        }
        Ok(RttEstimator { alpha, beta, min_rto, max_rto, initial_rto, srtt: None, rttvar: None, samples: 0 })
    }

    /// Convenience constructor matching the Python defaults.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_RTT_ALPHA, DEFAULT_RTT_BETA, DEFAULT_MIN_RTO, DEFAULT_MAX_RTO, DEFAULT_INITIAL_RTO)
            .expect("the module's own defaults are always valid")
    }

    /// Smoothed RTT, or `None` before the first sample.
    pub fn srtt(&self) -> Option<f64> {
        self.srtt
    }

    /// RTT variance, or `None` before the first sample.
    pub fn rttvar(&self) -> Option<f64> {
        self.rttvar
    }

    /// Feed one RTT measurement, in seconds.
    ///
    /// # Errors
    /// Returns [`CongestionError`] if `rtt` is negative.
    pub fn sample(&mut self, rtt: f64) -> Result<(), CongestionError> {
        if rtt < 0.0 {
            return Err(CongestionError(format!("rtt must not be negative, got {rtt}")));
        }
        self.samples += 1;
        match self.srtt {
            None => {
                self.srtt = Some(rtt);
                self.rttvar = Some(rtt / 2.0);
            }
            Some(srtt) => {
                let rttvar = self.rttvar.expect("srtt and rttvar are always set together");
                self.rttvar = Some((1.0 - self.beta) * rttvar + self.beta * (srtt - rtt).abs());
                self.srtt = Some((1.0 - self.alpha) * srtt + self.alpha * rtt);
            }
        }
        Ok(())
    }

    /// The current retransmission timeout, in seconds.
    pub fn rto(&self) -> f64 {
        match (self.srtt, self.rttvar) {
            (Some(srtt), Some(rttvar)) => {
                let raw = srtt + 4.0 * rttvar;
                raw.clamp(self.min_rto, self.max_rto)
            }
            _ => self.initial_rto.clamp(self.min_rto, self.max_rto),
        }
    }
}

/// AIMD congestion window: additive increase, multiplicative decrease.
///
/// The window counts *cells in flight*, not bytes, and gates how many
/// unacknowledged cells may be outstanding at once:
///
/// * **Slow start** until the first loss: each ack grows cwnd by a whole
///   cell, which doubles it per RTT.
/// * **Congestion avoidance** after that: cwnd grows by
///   `increase_per_rtt` cells per RTT, so it is linear rather than
///   exponential.
/// * **Multiplicative decrease** on every loss: a timeout backs cwnd off
///   to a quarter of its pre-loss value (floored at `min_cwnd`) and
///   re-enters slow start; a fast-retransmit loss halves it.
pub struct CongestionController {
    pub cwnd: u32,
    pub min_cwnd: u32,
    pub max_cwnd: u32,
    pub increase_per_rtt: u32,
    pub decrease_factor: f64,
    pub in_flight: u32,
    pub slow_start: bool,
    pub loss_events: u64,
    avoid_accum: f64,
}

impl CongestionController {
    /// # Errors
    /// Returns [`CongestionError`] if `min_cwnd`/`max_cwnd`/`initial_cwnd`
    /// are inconsistent, or `decrease_factor` is outside `(0, 1)`.
    pub fn new(initial_cwnd: u32, min_cwnd: u32, max_cwnd: u32, increase_per_rtt: u32, decrease_factor: f64) -> Result<Self, CongestionError> {
        if min_cwnd < 1 {
            return Err(CongestionError(format!("min_cwnd must be at least 1, got {min_cwnd}")));
        }
        if max_cwnd < min_cwnd {
            return Err(CongestionError(format!("max_cwnd {max_cwnd} must be >= min_cwnd {min_cwnd}")));
        }
        if !(min_cwnd <= initial_cwnd && initial_cwnd <= max_cwnd) {
            return Err(CongestionError(format!("initial_cwnd {initial_cwnd} must be within [{min_cwnd}, {max_cwnd}]")));
        }
        if !(0.0 < decrease_factor && decrease_factor < 1.0) {
            return Err(CongestionError(format!("decrease_factor must be in (0, 1), got {decrease_factor}")));
        }
        Ok(CongestionController {
            cwnd: initial_cwnd,
            min_cwnd,
            max_cwnd,
            increase_per_rtt: increase_per_rtt.max(1),
            decrease_factor,
            in_flight: 0,
            slow_start: true,
            loss_events: 0,
            avoid_accum: 0.0,
        })
    }

    /// Convenience constructor matching the Python defaults.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_INITIAL_CWND, DEFAULT_MIN_CWND, DEFAULT_MAX_CWND, 1, 0.5).expect("the module's own defaults are always valid")
    }

    /// Whether another cell may be put in flight right now.
    pub fn can_send(&self) -> bool {
        self.in_flight < self.cwnd
    }

    /// Record `count` cells handed to the transport.
    pub fn on_send(&mut self, count: u32) {
        // Saturating, not a bare `+=` -- see `on_ack`'s matching fix and
        // doc comment below. An
        // extreme `count` must not wrap `in_flight`, which would falsely
        // satisfy `can_send`'s `in_flight < cwnd` forever after.
        self.in_flight = self.in_flight.saturating_add(count);
    }

    /// Record `count` cells acknowledged, and grow the window.
    ///
    /// In slow start cwnd grows by the number of cells acked (doubling per
    /// RTT); in congestion avoidance it grows by `increase_per_rtt` per
    /// RTT, accumulated fractionally so a partial RTT still counts.
    ///
    /// `cwnd + count`/`cwnd + whole` are now saturating. `count` is a
    /// public parameter with no
    /// upper bound enforced by this type itself -- the only production
    /// caller happens to bound it via a small local default, but nothing
    /// here relied on that, so a directly-called `on_ack(u32::MAX)` used
    /// to be able to overflow (panicking in a debug build, wrapping `cwnd`
    /// in release) instead of simply clamping to `max_cwnd` like every
    /// ordinary count already does via the `.min(self.max_cwnd)` just
    /// after it.
    pub fn on_ack(&mut self, count: u32) {
        self.in_flight = self.in_flight.saturating_sub(count);
        if count == 0 {
            return;
        }
        if self.slow_start {
            self.cwnd = self.max_cwnd.min(self.cwnd.saturating_add(count));
            return;
        }
        self.avoid_accum += f64::from(self.increase_per_rtt) * f64::from(count) / f64::from(self.cwnd.max(1));
        let whole = self.avoid_accum as u32;
        if whole > 0 {
            self.avoid_accum -= f64::from(whole);
            self.cwnd = self.max_cwnd.min(self.cwnd.saturating_add(whole));
        }
    }

    /// Record a loss event and back the window off.
    ///
    /// A timeout is treated more conservatively than a triple-duplicate
    /// ack: it backs cwnd off to a quarter of its pre-loss value (floored
    /// at `min_cwnd`) and slow start resumes. Plain RFC 5681 collapses all
    /// the way to `min_cwnd` here instead; this is deliberately softer --
    /// see the module doc comment. A hard collapse to `min_cwnd=1` needs
    /// roughly `log2(target_cwnd)` RTTs of slow-start doubling to recover
    /// (e.g. ~6-7 RTTs to climb back to the window a real-time stream
    /// needs), during which throughput is far below what the stream
    /// requires -- a stall. Backing off to `cwnd/4` instead needs only
    /// ~2 RTTs to regain the same window, at the cost of being a bit more
    /// aggressive than RFC 5681 immediately after a timeout. A
    /// fast-retransmit loss event still halves the window and leaves slow
    /// start for good, unchanged.
    pub fn on_loss(&mut self, timeout: bool) {
        self.loss_events += 1;
        if timeout {
            self.cwnd = self.min_cwnd.max(self.cwnd / 4);
            self.slow_start = true;
            // Slow start grows cwnd by whole cells per ack and never
            // touches `avoid_accum`, so any fractional progress left over
            // from a *previous* congestion-avoidance phase would
            // otherwise sit here unused until avoidance is re-entered
            // later -- at which point it would grant an extra fraction of
            // a cell's worth of increase that this timeout never earned.
            self.avoid_accum = 0.0;
        } else {
            self.cwnd = self.min_cwnd.max((f64::from(self.cwnd) * self.decrease_factor) as u32);
            self.slow_start = false;
        }
        // Cells lost in flight are no longer in flight.
        self.in_flight = self.in_flight.min(self.cwnd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtt_estimator_first_sample_sets_srtt_and_half_rttvar() {
        let mut e = RttEstimator::with_defaults();
        e.sample(0.2).unwrap();
        assert_eq!(e.srtt(), Some(0.2));
        assert_eq!(e.rttvar(), Some(0.1));
    }

    #[test]
    fn rtt_estimator_rejects_negative_sample() {
        let mut e = RttEstimator::with_defaults();
        assert!(e.sample(-0.1).is_err());
    }

    #[test]
    fn rtt_estimator_rto_before_any_sample_is_initial() {
        let e = RttEstimator::new(0.125, 0.25, 0.05, 30.0, 1.0).unwrap();
        assert_eq!(e.rto(), 1.0);
    }

    #[test]
    fn rtt_estimator_rejects_bad_constructor_args() {
        assert!(RttEstimator::new(0.0, 0.25, 0.05, 30.0, 1.0).is_err());
        assert!(RttEstimator::new(0.125, 1.5, 0.05, 30.0, 1.0).is_err());
        assert!(RttEstimator::new(0.125, 0.25, 0.0, 30.0, 1.0).is_err());
        assert!(RttEstimator::new(0.125, 0.25, 1.0, 0.5, 1.0).is_err());
    }

    #[test]
    fn congestion_controller_slow_start_doubles_per_rtt() {
        let mut c = CongestionController::with_defaults();
        assert_eq!(c.cwnd, DEFAULT_INITIAL_CWND);
        c.on_send(4);
        c.on_ack(4);
        assert_eq!(c.cwnd, 8);
        assert!(c.slow_start);
    }

    #[test]
    fn congestion_controller_timeout_backs_off_to_a_quarter_of_cwnd() {
        let mut c = CongestionController::with_defaults();
        c.on_send(4);
        c.on_ack(4); // cwnd = 8, still slow start
        c.on_loss(true);
        assert_eq!(c.cwnd, 2); // 8 / 4, not a collapse to DEFAULT_MIN_CWND
        assert!(c.slow_start);
    }

    #[test]
    fn congestion_controller_timeout_backoff_still_floors_at_min_cwnd() {
        let mut c = CongestionController::with_defaults();
        // cwnd starts at DEFAULT_INITIAL_CWND = 4; 4 / 4 = 1, already at
        // the floor, so this also covers the case where cwnd/4 would
        // otherwise round below min_cwnd.
        c.on_loss(true);
        assert_eq!(c.cwnd, DEFAULT_MIN_CWND);
        assert!(c.slow_start);
    }

    #[test]
    fn congestion_controller_fast_retransmit_halves_and_leaves_slow_start() {
        let mut c = CongestionController::with_defaults();
        c.on_send(4);
        c.on_ack(4); // cwnd = 8
        c.on_loss(false);
        assert_eq!(c.cwnd, 4);
        assert!(!c.slow_start);
    }

    #[test]
    fn congestion_controller_can_send_gate() {
        let mut c = CongestionController::with_defaults();
        assert!(c.can_send());
        c.on_send(DEFAULT_INITIAL_CWND);
        assert!(!c.can_send());
    }

    #[test]
    fn congestion_controller_rejects_bad_constructor_args() {
        assert!(CongestionController::new(4, 0, 512, 1, 0.5).is_err());
        assert!(CongestionController::new(4, 8, 4, 1, 0.5).is_err());
        assert!(CongestionController::new(1000, 1, 512, 1, 0.5).is_err());
        assert!(CongestionController::new(4, 1, 512, 1, 1.0).is_err());
    }

    /// `on_ack`'s window-growth arithmetic must saturate, not overflow,
    /// for an extreme `count` -- the only
    /// production caller happens to bound `count` via a small local
    /// default, but the type itself enforces no such bound, and a debug
    /// build panics on a raw overflowing `+`. In slow start, `cwnd + count`
    /// must clamp at `max_cwnd`, same as any ordinary count would.
    #[test]
    fn congestion_controller_on_ack_saturates_in_slow_start() {
        let mut c = CongestionController::with_defaults();
        assert!(c.slow_start);
        c.on_ack(u32::MAX);
        assert_eq!(c.cwnd, DEFAULT_MAX_CWND);
    }

    /// Same property, in the congestion-avoidance (post-slow-start) branch.
    #[test]
    fn congestion_controller_on_ack_saturates_past_slow_start() {
        let mut c = CongestionController::new(DEFAULT_INITIAL_CWND, DEFAULT_MIN_CWND, DEFAULT_MAX_CWND, 1000, 0.5).unwrap();
        c.slow_start = false;
        c.on_ack(u32::MAX);
        assert_eq!(c.cwnd, DEFAULT_MAX_CWND);
    }

    /// `on_send`'s own accumulation must saturate too: an extreme `count`
    /// must not wrap `in_flight`, which would falsely satisfy `can_send`'s
    /// `in_flight < cwnd` forever after.
    #[test]
    fn congestion_controller_on_send_saturates() {
        let mut c = CongestionController::with_defaults();
        c.on_send(u32::MAX);
        c.on_send(1);
        assert_eq!(c.in_flight, u32::MAX);
    }
}

#[cfg(test)]
mod python_cross_check {
    use super::*;

    #[test]
    fn congestion_controller_matches_python_trace() {
        // python3 -c "
        //   import allium.congestion as c
        //   cc = c.CongestionController()
        //   print(cc.cwnd)
        //   cc.on_send(4); cc.on_ack(4); print(cc.cwnd, cc.slow_start)
        //   cc.on_send(8); cc.on_ack(8); print(cc.cwnd, cc.slow_start)
        //   cc.on_loss(False); print(cc.cwnd, cc.slow_start)
        //   cc.on_send(3); cc.on_ack(1); cc.on_ack(1); cc.on_ack(1); print(cc.cwnd)
        //   cc.on_loss(True); print(cc.cwnd, cc.slow_start)
        // "  ->  4 / 8 True / 16 True / 8 False / 8 / 1 True
        //
        // The final line is where this port now intentionally diverges
        // from the Python reference: Python's on_loss(True) (a plain RFC
        // 5681 timeout collapse) drops cwnd straight to 1. This build
        // instead backs off to cwnd/4 on a timeout -- see on_loss's doc
        // comment -- because a hard collapse-to-floor causes multi-second
        // stalls on a real-time stream after a single loss event. Every
        // other line in this trace still matches Python exactly.
        let mut cc = CongestionController::with_defaults();
        assert_eq!(cc.cwnd, 4);
        cc.on_send(4);
        cc.on_ack(4);
        assert_eq!(cc.cwnd, 8);
        assert!(cc.slow_start);
        cc.on_send(8);
        cc.on_ack(8);
        assert_eq!(cc.cwnd, 16);
        assert!(cc.slow_start);
        cc.on_loss(false);
        assert_eq!(cc.cwnd, 8);
        assert!(!cc.slow_start);
        cc.on_send(3);
        cc.on_ack(1);
        cc.on_ack(1);
        cc.on_ack(1);
        assert_eq!(cc.cwnd, 8);
        cc.on_loss(true);
        assert_eq!(cc.cwnd, 2); // Python: 1 -- see comment above.
        assert!(cc.slow_start);
    }

    #[test]
    fn rtt_estimator_matches_python_trace() {
        // python3 -c "
        //   import allium.congestion as c
        //   e = c.RttEstimator()
        //   for sample in [0.2, 0.25, 0.15, 0.3]:
        //       e.sample(sample)
        //       print(round(e.srtt,6), round(e.rttvar,6), round(e.rto,6))
        // "
        let mut e = RttEstimator::with_defaults();
        let samples = [0.2, 0.25, 0.15, 0.3];
        let expected = [(0.2, 0.1, 0.6), (0.20625, 0.0875, 0.55625), (0.199219, 0.079688, 0.517969), (0.211816, 0.084961, 0.55166)];
        for (&s, &(srtt, rttvar, rto)) in samples.iter().zip(expected.iter()) {
            e.sample(s).unwrap();
            assert!((e.srtt().unwrap() - srtt).abs() < 1e-5);
            assert!((e.rttvar().unwrap() - rttvar).abs() < 1e-5);
            assert!((e.rto() - rto).abs() < 1e-5);
        }
    }
}
