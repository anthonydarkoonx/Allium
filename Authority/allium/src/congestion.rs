//! End-to-end congestion control for an Allium circuit.

use std::fmt;

/// Initial congestion window, in cells.
pub const DEFAULT_INITIAL_CWND: i64 = 4;
/// Floor on cwnd.
pub const DEFAULT_MIN_CWND: i64 = 1;
/// Ceiling on cwnd. Raised from 256 -> 512 to match the Python port's fix,
/// tuned for a low-loss but higher-RTT (~90ms average, single-VPS) path
/// where 256 cells x 275B/cell capped throughput around 6 Mbps. Revisit
/// downward if real deployments show loss/memory pressure at the higher
/// window.
pub const DEFAULT_MAX_CWND: i64 = 512;

/// Initial RTO before any RTT sample exists. Mirrors
/// `crate::reliability::DEFAULT_RTO` (now ported, Phase 2).
pub const DEFAULT_INITIAL_RTO: f64 = crate::reliability::DEFAULT_RTO;
/// Floor on the computed RTO.
pub const DEFAULT_MIN_RTO: f64 = 0.05;
/// Ceiling on the computed RTO.
pub const DEFAULT_MAX_RTO: f64 = 30.0;
/// SRTT smoothing weight (RFC 6298's alpha).
pub const DEFAULT_RTT_ALPHA: f64 = 0.125;
/// RTTVAR smoothing weight (RFC 6298's beta).
pub const DEFAULT_RTT_BETA: f64 = 0.25;

/// A congestion-control invariant was violated.
#[derive(Debug, Clone, PartialEq)]
pub struct CongestionError {
    pub message: String,
}
impl fmt::Display for CongestionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for CongestionError {}
fn err(msg: impl Into<String>) -> CongestionError {
    CongestionError { message: msg.into() }
}

/// Smoothed RTT and variance, and the retransmission timeout they imply.
pub struct RttEstimator {
    pub alpha: f64,
    pub beta: f64,
    pub min_rto: f64,
    pub max_rto: f64,
    initial_rto: f64,
    srtt: Option<f64>,
    rttvar: Option<f64>,
    pub samples: u64,
}

impl RttEstimator {
    pub fn new(alpha: f64, beta: f64, min_rto: f64, max_rto: f64, initial_rto: f64) -> Result<RttEstimator, CongestionError> {
        if !(0.0 < alpha && alpha <= 1.0) {
            return Err(err(format!("alpha must be in (0, 1], got {alpha}")));
        }
        if !(0.0 < beta && beta <= 1.0) {
            return Err(err(format!("beta must be in (0, 1], got {beta}")));
        }
        if min_rto <= 0.0 {
            return Err(err(format!("min_rto must be positive, got {min_rto}")));
        }
        if max_rto < min_rto {
            return Err(err(format!("max_rto {max_rto} must be >= min_rto {min_rto}")));
        }
        Ok(RttEstimator { alpha, beta, min_rto, max_rto, initial_rto, srtt: None, rttvar: None, samples: 0 })
    }

    pub fn with_defaults() -> RttEstimator {
        RttEstimator::new(DEFAULT_RTT_ALPHA, DEFAULT_RTT_BETA, DEFAULT_MIN_RTO, DEFAULT_MAX_RTO, DEFAULT_INITIAL_RTO)
            .unwrap()
    }

    pub fn srtt(&self) -> Option<f64> {
        self.srtt
    }
    pub fn rttvar(&self) -> Option<f64> {
        self.rttvar
    }

    /// Feed one RTT measurement, in seconds.
    pub fn sample(&mut self, rtt: f64) -> Result<(), CongestionError> {
        if rtt < 0.0 {
            return Err(err(format!("rtt must not be negative, got {rtt}")));
        }
        self.samples += 1;
        match self.srtt {
            None => {
                self.srtt = Some(rtt);
                self.rttvar = Some(rtt / 2.0);
            }
            Some(srtt) => {
                let rttvar = self.rttvar.unwrap();
                let new_rttvar = (1.0 - self.beta) * rttvar + self.beta * (srtt - rtt).abs();
                let new_srtt = (1.0 - self.alpha) * srtt + self.alpha * rtt;
                self.rttvar = Some(new_rttvar);
                self.srtt = Some(new_srtt);
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

impl fmt::Display for RttEstimator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.srtt {
            None => write!(f, "RttEstimator(no samples yet)"),
            Some(srtt) => write!(
                f,
                "RttEstimator(srtt={:.4}, rttvar={:.4}, rto={:.4}, samples={})",
                srtt,
                self.rttvar.unwrap(),
                self.rto(),
                self.samples
            ),
        }
    }
}

/// AIMD congestion window: additive increase, multiplicative decrease.
pub struct CongestionController {
    pub cwnd: i64,
    pub min_cwnd: i64,
    pub max_cwnd: i64,
    pub increase_per_rtt: i64,
    pub decrease_factor: f64,
    pub in_flight: i64,
    pub slow_start: bool,
    pub loss_events: u64,
    avoid_accum: f64,
}

impl CongestionController {
    pub fn new(
        initial_cwnd: i64,
        min_cwnd: i64,
        max_cwnd: i64,
        increase_per_rtt: i64,
        decrease_factor: f64,
    ) -> Result<CongestionController, CongestionError> {
        if min_cwnd < 1 {
            return Err(err(format!("min_cwnd must be at least 1, got {min_cwnd}")));
        }
        if max_cwnd < min_cwnd {
            return Err(err(format!("max_cwnd {max_cwnd} must be >= min_cwnd {min_cwnd}")));
        }
        if !(min_cwnd <= initial_cwnd && initial_cwnd <= max_cwnd) {
            return Err(err(format!("initial_cwnd {initial_cwnd} must be within [{min_cwnd}, {max_cwnd}]")));
        }
        if !(0.0 < decrease_factor && decrease_factor < 1.0) {
            return Err(err(format!("decrease_factor must be in (0, 1), got {decrease_factor}")));
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

    pub fn with_defaults() -> CongestionController {
        CongestionController::new(DEFAULT_INITIAL_CWND, DEFAULT_MIN_CWND, DEFAULT_MAX_CWND, 1, 0.5).unwrap()
    }

    /// Whether another cell may be put in flight right now.
    pub fn can_send(&self) -> bool {
        self.in_flight < self.cwnd
    }

    /// Record `count` cells handed to the transport.
    pub fn on_send(&mut self, count: i64) -> Result<(), CongestionError> {
        if count < 0 {
            return Err(err(format!("count must not be negative, got {count}")));
        }
        // `count` is a public, caller-supplied `i64` with no upper bound
        // enforced here -- see `on_ack`'s matching fix and doc comment below.
        // Saturating keeps
        // `in_flight` merely very large instead of wrapping negative,
        // which would otherwise falsely satisfy `can_send`'s `in_flight <
        // cwnd` check forever after.
        self.in_flight = self.in_flight.saturating_add(count);
        Ok(())
    }

    /// Record `count` cells acknowledged, and grow the window.
    ///
    /// Every arithmetic op on `count` below is now saturating. `count` is a
    /// public parameter with
    /// no upper bound enforced by this type itself -- the only production
    /// caller (`stream.rs`) happens to bound it via a small local
    /// `max_unacked` default, but nothing here relied on that, so a
    /// directly-called `on_ack(i64::MAX)` used to be able to overflow
    /// `self.cwnd + count` (panicking in a debug build, wrapping `cwnd`
    /// negative in release) instead of simply clamping to `max_cwnd` like
    /// every ordinary count already does via the `.min(self.max_cwnd)`
    /// just after it.
    pub fn on_ack(&mut self, count: i64) -> Result<(), CongestionError> {
        if count < 0 {
            return Err(err(format!("count must not be negative, got {count}")));
        }
        self.in_flight = self.in_flight.saturating_sub(count).max(0);
        if count == 0 {
            return Ok(());
        }
        if self.slow_start {
            self.cwnd = self.max_cwnd.min(self.cwnd.saturating_add(count));
            return Ok(());
        }
        self.avoid_accum += (self.increase_per_rtt.saturating_mul(count)) as f64 / (self.cwnd.max(1)) as f64;
        let whole = self.avoid_accum as i64;
        if whole != 0 {
            self.avoid_accum -= whole as f64;
            self.cwnd = self.max_cwnd.min(self.cwnd.saturating_add(whole));
        }
        Ok(())
    }

    /// Record a loss event and back the window off.
    ///
    /// A timeout backs cwnd off to a quarter of its pre-loss value
    /// (floored at `min_cwnd`) and re-enters slow start, rather than
    /// plain RFC 5681's hard collapse to `min_cwnd`. A full collapse needs
    /// ~log2(target_cwnd) RTTs of slow-start doubling to recover -- a
    /// multi-second throughput valley on a real-time stream (e.g. video)
    /// after a single loss event. Backing off to cwnd/4 recovers the same
    /// window in ~2 RTTs instead, at the cost of being a bit more
    /// aggressive than RFC 5681 immediately after a timeout. A
    /// fast-retransmit loss event still halves the window and leaves slow
    /// start for good, unchanged.
    pub fn on_loss(&mut self, timeout: bool) {
        self.loss_events += 1;
        if timeout {
            self.cwnd = self.min_cwnd.max(self.cwnd / 4);
            self.slow_start = true;
            self.avoid_accum = 0.0;
        } else {
            self.cwnd = self.min_cwnd.max((self.cwnd as f64 * self.decrease_factor) as i64);
            self.slow_start = false;
        }
        self.in_flight = self.in_flight.min(self.cwnd);
    }
}

impl fmt::Display for CongestionController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CongestionController(cwnd={}, in_flight={}, slow_start={}, loss_events={})",
            self.cwnd, self.in_flight, self.slow_start, self.loss_events
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- RttEstimator -----------------------------------------------------
    #[test]
    fn test_no_samples_uses_the_initial_rto() {
        let est = RttEstimator::new(DEFAULT_RTT_ALPHA, DEFAULT_RTT_BETA, DEFAULT_MIN_RTO, DEFAULT_MAX_RTO, 2.0).unwrap();
        assert_eq!(est.rto(), 2.0);
        assert_eq!(est.srtt(), None);
        assert_eq!(est.samples, 0);
    }

    #[test]
    fn test_first_sample_sets_srtt_and_half_variance() {
        let mut est = RttEstimator::new(DEFAULT_RTT_ALPHA, DEFAULT_RTT_BETA, 0.001, DEFAULT_MAX_RTO, DEFAULT_INITIAL_RTO).unwrap();
        est.sample(0.2).unwrap();
        assert_eq!(est.srtt(), Some(0.2));
        assert_eq!(est.rttvar(), Some(0.1));
        assert!((est.rto() - 0.6).abs() < 1e-9);
        assert_eq!(est.samples, 1);
    }

    #[test]
    fn test_steady_samples_converge_to_the_rtt() {
        let mut est = RttEstimator::new(DEFAULT_RTT_ALPHA, DEFAULT_RTT_BETA, 0.001, DEFAULT_MAX_RTO, DEFAULT_INITIAL_RTO).unwrap();
        for _ in 0..50 {
            est.sample(0.1).unwrap();
        }
        assert!((est.srtt().unwrap() - 0.1).abs() < 1e-3);
        assert!(est.rttvar().unwrap() < 0.01);
        assert!(est.rto() < 0.2);
    }

    #[test]
    fn test_a_spike_widens_the_rto() {
        let mut est = RttEstimator::new(DEFAULT_RTT_ALPHA, DEFAULT_RTT_BETA, 0.001, DEFAULT_MAX_RTO, DEFAULT_INITIAL_RTO).unwrap();
        for _ in 0..20 {
            est.sample(0.1).unwrap();
        }
        let calm = est.rto();
        est.sample(1.0).unwrap();
        assert!(est.rto() > calm);
    }

    #[test]
    fn test_rto_is_clamped_to_the_floor() {
        let mut est = RttEstimator::new(DEFAULT_RTT_ALPHA, DEFAULT_RTT_BETA, 0.5, DEFAULT_MAX_RTO, DEFAULT_INITIAL_RTO).unwrap();
        for _ in 0..50 {
            est.sample(0.001).unwrap();
        }
        assert_eq!(est.rto(), 0.5);
    }

    #[test]
    fn test_rto_is_clamped_to_the_ceiling() {
        let mut est = RttEstimator::new(DEFAULT_RTT_ALPHA, DEFAULT_RTT_BETA, 0.01, 5.0, DEFAULT_INITIAL_RTO).unwrap();
        est.sample(100.0).unwrap();
        assert_eq!(est.rto(), 5.0);
    }

    #[test]
    fn test_negative_sample_is_rejected() {
        let mut est = RttEstimator::with_defaults();
        assert!(est.sample(-0.1).is_err());
    }

    #[test]
    fn test_bad_parameters_are_rejected() {
        assert!(RttEstimator::new(0.0, DEFAULT_RTT_BETA, DEFAULT_MIN_RTO, DEFAULT_MAX_RTO, DEFAULT_INITIAL_RTO).is_err());
        assert!(RttEstimator::new(1.5, DEFAULT_RTT_BETA, DEFAULT_MIN_RTO, DEFAULT_MAX_RTO, DEFAULT_INITIAL_RTO).is_err());
        assert!(RttEstimator::new(DEFAULT_RTT_ALPHA, 0.0, DEFAULT_MIN_RTO, DEFAULT_MAX_RTO, DEFAULT_INITIAL_RTO).is_err());
        assert!(RttEstimator::new(DEFAULT_RTT_ALPHA, DEFAULT_RTT_BETA, 0.0, DEFAULT_MAX_RTO, DEFAULT_INITIAL_RTO).is_err());
        assert!(RttEstimator::new(DEFAULT_RTT_ALPHA, DEFAULT_RTT_BETA, 1.0, 0.5, DEFAULT_INITIAL_RTO).is_err());
    }

    #[test]
    fn test_display_reports_state() {
        let mut est = RttEstimator::new(DEFAULT_RTT_ALPHA, DEFAULT_RTT_BETA, 0.001, DEFAULT_MAX_RTO, DEFAULT_INITIAL_RTO).unwrap();
        assert!(format!("{est}").contains("no samples"));
        est.sample(0.1).unwrap();
        assert!(format!("{est}").contains("srtt="));
    }

    // -- CongestionController -----------------------------------------------------
    #[test]
    fn test_defaults() {
        let c = CongestionController::with_defaults();
        assert_eq!(c.cwnd, DEFAULT_INITIAL_CWND);
        assert_eq!(c.min_cwnd, DEFAULT_MIN_CWND);
        assert_eq!(c.max_cwnd, DEFAULT_MAX_CWND);
        assert!(c.slow_start);
    }

    #[test]
    fn test_can_send_gates_on_in_flight() {
        let mut c = CongestionController::new(2, DEFAULT_MIN_CWND, DEFAULT_MAX_CWND, 1, 0.5).unwrap();
        assert!(c.can_send());
        c.on_send(1).unwrap();
        assert!(c.can_send());
        c.on_send(1).unwrap();
        assert!(!c.can_send());
        c.on_ack(1).unwrap();
        assert!(c.can_send());
    }

    #[test]
    fn test_slow_start_doubles_per_rtt() {
        let mut c = CongestionController::new(4, DEFAULT_MIN_CWND, 1000, 1, 0.5).unwrap();
        for _ in 0..4 {
            c.on_send(1).unwrap();
            c.on_ack(1).unwrap();
        }
        assert_eq!(c.cwnd, 8);
        assert!(c.slow_start);
    }

    #[test]
    fn test_fast_retransmit_halves_and_leaves_slow_start() {
        let mut c = CongestionController::new(16, DEFAULT_MIN_CWND, 1000, 1, 0.5).unwrap();
        c.on_loss(false);
        assert_eq!(c.cwnd, 8);
        assert!(!c.slow_start);
    }

    #[test]
    fn test_timeout_backs_off_to_a_quarter_of_cwnd_and_restarts_slow_start() {
        let mut c = CongestionController::new(32, DEFAULT_MIN_CWND, 1000, 1, 0.5).unwrap();
        c.on_loss(false); // cwnd = 16
        c.on_loss(true);
        assert_eq!(c.cwnd, 4); // 16 / 4, not a collapse to c.min_cwnd
        assert!(c.slow_start);
    }

    #[test]
    fn test_timeout_backoff_still_floors_at_min_cwnd() {
        let mut c = CongestionController::new(DEFAULT_INITIAL_CWND, DEFAULT_MIN_CWND, DEFAULT_MAX_CWND, 1, 0.5).unwrap();
        // cwnd starts at DEFAULT_INITIAL_CWND = 4; 4 / 4 = 1, already at
        // the floor, so this also covers cwnd/4 rounding below min_cwnd.
        c.on_loss(true);
        assert_eq!(c.cwnd, DEFAULT_MIN_CWND);
        assert!(c.slow_start);
    }

    #[test]
    fn test_window_growth_is_linear_in_congestion_avoidance() {
        let mut c = CongestionController::new(8, DEFAULT_MIN_CWND, 100000, 1, 0.5).unwrap();
        c.on_loss(false);
        let before = c.cwnd;
        for _ in 0..c.cwnd {
            c.on_send(1).unwrap();
            c.on_ack(1).unwrap();
        }
        assert_eq!(c.cwnd, before + 1);
    }

    #[test]
    fn test_window_is_capped() {
        let mut c = CongestionController::new(4, DEFAULT_MIN_CWND, 16, 1, 0.5).unwrap();
        for _ in 0..1000 {
            c.on_send(1).unwrap();
            c.on_ack(1).unwrap();
        }
        assert_eq!(c.cwnd, 16);
    }

    #[test]
    fn test_timeout_resets_the_avoidance_accumulator() {
        // Numbers below reflect the cwnd/4 timeout backoff (see on_loss's
        // doc comment), not a collapse to min_cwnd: after on_loss(true)
        // cwnd is 50/4=12 rather than 1, so the values this test checks
        // are larger than they'd be under a hard collapse. The property
        // being tested -- that avoid_accum doesn't leak stale fractional
        // progress across a timeout -- is unaffected by that change.
        let mut c = CongestionController::new(100, DEFAULT_MIN_CWND, 100000, 1, 0.5).unwrap();
        c.on_loss(false);
        assert_eq!(c.cwnd, 50);
        c.on_ack(49).unwrap();
        assert_eq!(c.cwnd, 50);

        c.on_loss(true); // cwnd = max(1, 50/4) = 12
        c.on_ack(49).unwrap(); // slow start: 12 + 49 = 61
        assert_eq!(c.cwnd, 61);
        c.on_loss(false); // fast retransmit halve: (61 * 0.5) as i64 = 30
        assert_eq!(c.cwnd, 30);

        c.on_ack(1).unwrap();
        assert_eq!(c.cwnd, 30);
    }

    #[test]
    fn test_window_never_falls_below_the_floor() {
        let mut c = CongestionController::new(4, 2, 64, 1, 0.5).unwrap();
        for _ in 0..20 {
            c.on_loss(false);
        }
        assert_eq!(c.cwnd, 2);
    }

    #[test]
    fn test_loss_reduces_in_flight() {
        let mut c = CongestionController::new(8, DEFAULT_MIN_CWND, 64, 1, 0.5).unwrap();
        for _ in 0..8 {
            c.on_send(1).unwrap();
        }
        assert_eq!(c.in_flight, 8);
        c.on_loss(true);
        assert_eq!(c.in_flight, c.cwnd);
    }

    #[test]
    fn test_ack_reduces_in_flight() {
        let mut c = CongestionController::new(4, DEFAULT_MIN_CWND, DEFAULT_MAX_CWND, 1, 0.5).unwrap();
        c.on_send(3).unwrap();
        c.on_ack(2).unwrap();
        assert_eq!(c.in_flight, 1);
    }

    #[test]
    fn test_zero_counts_are_allowed() {
        let mut c = CongestionController::with_defaults();
        c.on_send(0).unwrap();
        c.on_ack(0).unwrap();
        assert_eq!(c.in_flight, 0);
    }

    #[test]
    fn test_negative_counts_are_rejected() {
        let mut c = CongestionController::with_defaults();
        assert!(c.on_send(-1).is_err());
        assert!(c.on_ack(-1).is_err());
    }

    /// `on_ack`'s window-growth arithmetic must saturate, not overflow, for
    /// an extreme `count` -- the only
    /// production caller happens to bound `count` via a small local
    /// default, but the type itself enforces no such bound, and a debug
    /// build panics on a raw overflowing `+`. In slow start, `cwnd + count`
    /// must clamp at `max_cwnd`, same as any ordinary count would.
    #[test]
    fn test_on_ack_saturates_instead_of_overflowing_in_slow_start() {
        let mut c = CongestionController::with_defaults();
        assert!(c.slow_start);
        c.on_ack(i64::MAX).unwrap();
        assert_eq!(c.cwnd, DEFAULT_MAX_CWND);
    }

    /// Same property, in the congestion-avoidance (post-slow-start) branch,
    /// where the multiplication `increase_per_rtt * count` could also
    /// overflow before this fix.
    #[test]
    fn test_on_ack_saturates_instead_of_overflowing_past_slow_start() {
        let mut c = CongestionController::new(DEFAULT_INITIAL_CWND, DEFAULT_MIN_CWND, DEFAULT_MAX_CWND, 1000, 0.5).unwrap();
        c.slow_start = false;
        c.on_ack(i64::MAX).unwrap();
        assert_eq!(c.cwnd, DEFAULT_MAX_CWND);
    }

    /// `on_ack`'s `in_flight` bookkeeping must saturate too: an extreme
    /// `count` handed to `on_ack` before it, must not underflow `in_flight`
    /// on the way to being clamped at 0.
    #[test]
    fn test_on_ack_in_flight_saturates_instead_of_underflowing() {
        let mut c = CongestionController::with_defaults();
        c.on_send(5).unwrap();
        c.on_ack(i64::MAX).unwrap();
        assert_eq!(c.in_flight, 0);
    }

    /// `on_send`'s own accumulation must saturate too, for the same reason:
    /// an extreme `count` must not wrap `in_flight` negative, which would
    /// falsely satisfy `can_send`'s `in_flight < cwnd` forever after.
    #[test]
    fn test_on_send_saturates_instead_of_overflowing() {
        let mut c = CongestionController::with_defaults();
        c.on_send(i64::MAX).unwrap();
        c.on_send(1).unwrap();
        assert_eq!(c.in_flight, i64::MAX);
        assert!(c.in_flight >= 0);
    }

    #[test]
    fn test_controller_bad_parameters_are_rejected() {
        assert!(CongestionController::new(DEFAULT_INITIAL_CWND, 0, DEFAULT_MAX_CWND, 1, 0.5).is_err());
        assert!(CongestionController::new(DEFAULT_INITIAL_CWND, 8, 4, 1, 0.5).is_err());
        assert!(CongestionController::new(100, DEFAULT_MIN_CWND, 8, 1, 0.5).is_err());
        assert!(CongestionController::new(DEFAULT_INITIAL_CWND, DEFAULT_MIN_CWND, DEFAULT_MAX_CWND, 1, 0.0).is_err());
        assert!(CongestionController::new(DEFAULT_INITIAL_CWND, DEFAULT_MIN_CWND, DEFAULT_MAX_CWND, 1, 1.0).is_err());
    }

    #[test]
    fn test_loss_events_are_counted() {
        let mut c = CongestionController::with_defaults();
        c.on_loss(false);
        c.on_loss(true);
        assert_eq!(c.loss_events, 2);
    }

    #[test]
    fn test_display_reports_the_window() {
        assert!(format!("{}", CongestionController::with_defaults()).contains("cwnd="));
    }
}
