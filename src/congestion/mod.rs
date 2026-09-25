//! Basic congestion/rate control.
//!
//! A deliberately small, TCP-inspired controller that responds to live loss
//! and RTT measurements. It maintains a congestion window (in **bytes**) and a
//! smoothed RTT, and exposes three things to the tunnel's send loop:
//!
//! - [`CongestionController::may_send`] — the admission test (window + pacer).
//! - [`CongestionController::on_send`] — reserve one packet in flight.
//! - [`CongestionController::on_ack_with_rtt`] — retire acked bytes, grow the
//!   window, refresh the RTT sample, and re-derive the pacing rate.
//!
//! Why bytes and not packets: a packet-counting window cannot tell a 1400-byte
//! bulk packet from a 64-byte ping reply, so a window of "4 packets" is
//! anywhere between 300 B and 5 KB of actual in-flight data depending on the
//! workload. Every derived quantity (pacing rate, drop decision) then inherits
//! that error. Accounting in bytes makes the window a real bandwidth-delay
//! product and lets the pacer be expressed in bytes/second, which is the only
//! way to keep a lossy link from being flooded by a burst of back-to-back
//! datagrams.
//!
//! This is a building block, not a high-performance design — phase 1 wants
//! correct, well-behaved control; a BBR-style controller can slot in later.

use std::time::{Duration, Instant};

/// Minimum congestion window (bytes). Two full-size datagrams: enough for a
/// request/response exchange on a path with one packet in flight each way.
pub const MIN_CWND_BYTES: u64 = 2 * 1300;
/// Initial congestion window (bytes). RFC 6928's IW10 is the reference for a
/// modern safe initial burst; 10 * 1300 keeps that burst size while being
/// expressed in bytes.
pub const INITIAL_CWND_BYTES: u64 = 10 * 1300;
/// Initial slow-start threshold (bytes), 64 full-size datagrams.
pub const INITIAL_SSTHRESH_BYTES: u64 = 64 * 1300;
/// Default MTU assumption used when the tunnel does not report one.
pub const DEFAULT_MTU: u32 = 1400;
/// Minimum pacing rate (bytes/second). Below this the pacer degenerates into a
/// one-packet-at-a-time trickle, which is still strictly better than dropping.
const MIN_PACING_RATE: f64 = 8_000.0;
/// Upper bound on the pacing rate, so a pathological cwnd/srtt cannot produce
/// an enormous sleep dividend. 5 Gbit/s.
const MAX_PACING_RATE: f64 = 625_000_000.0;
/// Initial smoothed RTT fallback (ms).
const INITIAL_RTT_MS: u64 = 100;
/// Initial pacing rate (bytes/second) used until the first RTT sample lands.
/// Deliberately conservative: ~1 Mbit/s.
const INITIAL_PACING_RATE: f64 = 125_000.0;

#[derive(Debug, Clone)]
pub struct CongestionController {
    /// Congestion window in **bytes**.
    pub cwnd: u64,
    /// Slow-start threshold in bytes.
    pub ssthresh: u64,
    /// Bytes currently in flight (outstanding, unacked).
    pub in_flight: u64,
    /// Smoothed RTT (Karn/Allman EWMA), used for RTO and pacing.
    pub srtt: Duration,
    /// Smoothed RTT variance (Jacobson).
    pub rttvar: Duration,
    /// Retransmission timeout.
    pub rto: Duration,
    /// Last measured loss ratio (for stats).
    pub last_loss: f64,
    /// Current pacing rate in bytes/second (`cwnd / srtt`, floored and capped).
    pub pacing_rate: f64,
    /// Time at which the next packet may leave under the pacer. `None` = the
    /// pacer has no credit outstanding (send immediately).
    next_send_at: Option<Instant>,
    /// MTU used to convert a byte window into a packet-count estimate.
    pub mtu: u32,
}

impl Default for CongestionController {
    fn default() -> Self {
        Self::new()
    }
}

impl CongestionController {
    pub fn new() -> Self {
        Self {
            cwnd: INITIAL_CWND_BYTES,
            ssthresh: INITIAL_SSTHRESH_BYTES,
            in_flight: 0,
            srtt: Duration::from_millis(INITIAL_RTT_MS),
            rttvar: Duration::from_millis(INITIAL_RTT_MS / 2),
            rto: Duration::from_millis(INITIAL_RTT_MS * 2),
            last_loss: 0.0,
            pacing_rate: INITIAL_PACING_RATE,
            next_send_at: None,
            mtu: DEFAULT_MTU,
        }
    }

    /// Set the MTU that turns a byte window into a packet-count estimate.
    /// Called by the tunnel once it knows the device MTU.
    pub fn set_mtu(&mut self, mtu: u32) {
        if mtu > 0 {
            self.mtu = mtu;
        }
    }

    /// The packet count currently in flight, derived from bytes.
    pub fn in_flight_packets(&self) -> u64 {
        self.in_flight.div_ceil(self.mtu.max(1) as u64)
    }

    /// The window expressed in packets at the current MTU (for stats/labels).
    pub fn cwnd_packets(&self) -> f64 {
        self.cwnd as f64 / self.mtu.max(1) as f64
    }

    /// Additional **bytes** the sender may dispatch right now under the
    /// congestion window alone (ignores pacing).
    pub fn send_budget(&self) -> u64 {
        self.cwnd.saturating_sub(self.in_flight)
    }

    /// Release `bytes` in-flight without growing the window. Used for sent
    /// records finalized as lost by ACK-window or timeout resolution.
    pub fn release(&mut self, bytes: u64) {
        self.in_flight = self.in_flight.saturating_sub(bytes);
    }

    pub fn refund_send_bytes(&mut self, bytes: u64) {
        self.release(bytes);
        if let Some(next) = self.next_send_at {
            let delay = Duration::from_secs_f64(bytes.max(1) as f64 / self.pacing_rate);
            self.next_send_at = next.checked_sub(delay);
        }
    }

    /// Release `n` in-flight *packets* (converted to bytes at the current MTU).
    /// Packet-count wrapper retained for callers that do not track bytes.
    pub fn release_packets(&mut self, n: u64) {
        self.release(n.saturating_mul(self.mtu as u64));
    }

    /// Admission test for one packet of `len` bytes: is there window budget,
    /// and has the pacer granted credit for it?
    ///
    /// The window check is a *byte* comparison, so a single large packet cannot
    /// slip past a window that is nearly exhausted. The pacer check guarantees
    /// that a burst of back-to-back TUN reads is spread over one RTT instead of
    /// being dumped into the path at once — that burst is what turns a mildly
    /// lossy link into visible packet loss once an upstream queue overflows.
    pub fn may_send(&mut self, len: usize) -> bool {
        let need = (len as u64).max(1);
        if need > self.send_budget() {
            return false;
        }
        let now = Instant::now();
        match self.next_send_at {
            Some(t) if now < t => false,
            _ => {
                self.advance_pacer(now, need);
                true
            }
        }
    }

    /// When the pacer will next grant credit, or `None` if it has credit right
    /// now. The tunnel parks a packet until this instant rather than dropping
    /// it, which turns rate limiting into delay instead of loss.
    pub fn next_send_deadline(&self) -> Option<Instant> {
        let next = self.next_send_at?;
        let now = Instant::now();
        if next > now { Some(next) } else { None }
    }

    /// Reset the pacer's credit, discarding any accumulated delay debt. Called
    /// when the sender has been idle (nothing in flight and nothing parked), so
    /// the next packet leaves immediately instead of paying off a stale
    /// schedule.
    pub fn reset_pacer(&mut self) {
        self.next_send_at = None;
    }

    /// Reserve window + pacing credit for an FEC parity packet that belongs to
    /// an already-admitted data group. Checks the window budget only: when the
    /// window is full the parity is expendable redundancy and the caller
    /// should skip it (returning `false`). When there is budget, the bytes are
    /// reserved via [`on_send_bytes`](Self::on_send_bytes) and the pacer's
    /// schedule is advanced so the *next* data packet is delayed by the
    /// parity's airtime — total wire traffic (data + parity) is what the pacer
    /// paces. Unlike [`may_send`](Self::may_send), a pacer debt never refuses
    /// parity: dropping redundancy because of pacing would disable FEC exactly
    /// when the path is busy, while still sending it keeps protection and lets
    /// the pacer spread the following data instead.
    pub fn try_send_parity(&mut self, len: usize) -> bool {
        let need = (len as u64).max(1);
        if need > self.send_budget() {
            return false;
        }
        self.on_send_bytes(len);
        self.advance_pacer(Instant::now(), need);
        true
    }

    /// Set the window directly while keeping the derived pacing rate
    /// consistent. Assigning `cwnd` in place leaves `pacing_rate` stale, which
    /// strands the pacer with an interval derived from the previous window.
    pub fn set_cwnd(&mut self, bytes: u64) {
        self.cwnd = bytes.max(MIN_CWND_BYTES);
        self.recompute_pacing_rate();
    }

    /// Advance the pacer's next-departure time by this packet's airtime at the
    /// current rate. Called only when a packet is actually admitted.
    fn advance_pacer(&mut self, now: Instant, len: u64) {
        let rate = self.pacing_rate.clamp(MIN_PACING_RATE, MAX_PACING_RATE);
        let interval = Duration::from_secs_f64((len as f64) / rate);
        let base = match self.next_send_at {
            Some(t) if t > now => t,
            _ => now,
        };
        // Cap the hole we are willing to dig. If the pacer has fallen more than
        // one RTT behind (because the window was closed and nothing was
        // admitted), do not make the sender pay off that debt in one go;
        // restart from now. Without this, an idle period followed by a burst
        // would be throttled for the whole accumulated debt.
        let max_debt = self.srtt.max(Duration::from_millis(1));
        let next = base + interval;
        self.next_send_at = Some(if next.saturating_duration_since(now) > max_debt {
            now + interval
        } else {
            next
        });
    }

    /// How long the caller should wait before retrying `may_send` for a packet
    /// of `len` bytes. `None` means "send now". The tunnel uses this to park the
    /// send loop when pacing—not loss—is what is holding it back, so a paced
    /// sender holds the packet instead of silently dropping it.
    pub fn pacing_delay(&self, len: usize) -> Option<Duration> {
        let t = self.next_send_at?;
        let now = Instant::now();
        let delay = t.saturating_duration_since(now);
        if delay.is_zero() {
            return None;
        }
        if (len as u64).max(1) > self.send_budget() {
            // Window-limited as well; the caller has to wait for acks, not for
            // the pacer. Report no pacing delay.
            return None;
        }
        Some(delay)
    }

    /// Reserve one packet slot in flight (at the current MTU).
    pub fn on_send(&mut self) {
        self.on_send_bytes(self.mtu as usize);
    }

    /// Reserve `len` bytes in flight. Used by the send path so the window
    /// accounting matches what was actually put on the wire.
    pub fn on_send_bytes(&mut self, len: usize) {
        self.in_flight = self
            .in_flight
            .saturating_add((len as u64).max(1))
            .min(self.cwnd.max(1));
    }

    /// Acknowledge `n` previously-in-flight packets and grow the window.
    /// Packet-count wrapper retained for callers that do not track bytes.
    pub fn on_ack(&mut self, n: u64) {
        if n == 0 {
            return;
        }
        self.on_ack_bytes(n.saturating_mul(self.mtu as u64));
    }

    /// Retire acked bytes and grow the window (no RTT sample).
    pub fn on_ack_bytes(&mut self, bytes: u64) {
        self.ack_common(bytes);
    }

    /// Retire acked bytes and grow the window, using the delivered packet's RTT
    /// as a fresh sample.
    ///
    /// This is the single most important feedback path: before it existed, the
    /// ONLY RTT samples came from the 500 ms Ping/Pong probe, so a burst of data
    /// had no way to enlarge the window until the next ping tick — the window
    /// stayed pinned at its initial value no matter how fast the path actually
    /// was.
    pub fn on_ack_with_rtt(&mut self, bytes: u64, sample: Duration) {
        self.on_rtt_sample(sample);
        self.ack_common(bytes);
    }

    fn ack_common(&mut self, bytes: u64) {
        let n = bytes.max(1);
        self.in_flight = self.in_flight.saturating_sub(n);
        if self.cwnd < self.ssthresh {
            // slow start: one extra byte per byte acked (doubling per RTT)
            self.cwnd = self.cwnd.saturating_add(n);
        } else {
            // congestion avoidance: ~+1 MSS per RTT
            let mss = self.mtu.max(1) as f64;
            let added = (n as f64) * mss / (self.cwnd.max(1) as f64);
            self.cwnd = self.cwnd.saturating_add(added as u64);
        }
        self.recompute_pacing_rate();
    }

    /// Signal loss(es). `lost` packets were lost; `total` were sent in the
    /// window they came from. Triggers multiplicative decrease.
    ///
    /// This adjusts the window only; the tunnel's ACK reconciliation path owns
    /// exact-byte slot retirement for both acknowledged and lost records.
    pub fn on_loss(&mut self, lost: u64, total: u64) {
        if total == 0 || lost == 0 {
            return;
        }
        self.last_loss = (lost as f64 / total as f64).clamp(0.0, 1.0);
        // Multiplicative decrease with a loss-proportional factor. A pure
        // halving per loss event over-reacts when a single packet is lost out
        // of a large batch (the common case on a link with a couple of percent
        // of ambient loss): the window collapses, throughput dies, and
        // recovery from a low cwnd is slow. Scaling the reduction by how bad
        // the loss actually was keeps a one-off loss cheap while still backing
        // off hard on sustained loss.
        let ratio = self.last_loss;
        let factor = (1.0 - ratio * 0.5).clamp(0.5, 0.875);
        let reduced = (self.cwnd as f64 * factor) as u64;
        self.ssthresh = reduced.max(MIN_CWND_BYTES);
        self.cwnd = self.ssthresh;
        self.recompute_pacing_rate();
    }

    /// Apply a fresh RTT sample (the time between send and ack for one packet).
    /// Uses the classic Jacobson/Karels SRTT/RTTVAR update and sets RTO.
    pub fn on_rtt_sample(&mut self, rtt: Duration) {
        let r = rtt.as_nanos() as i64;
        let s = self.srtt.as_nanos() as i64;
        let v = self.rttvar.as_nanos() as i64;
        // RTTVAR = (1 - beta)*RTTVAR + beta*|SRTT - R|, beta = 1/4
        let diff = (s - r).abs();
        let new_v = (3 * v + diff) / 4;
        // SRTT = (7/8)*SRTT + (1/8)*R
        let new_s = (7 * s + r) / 8;
        self.srtt = Duration::from_nanos(new_s.max(1_000) as u64);
        self.rttvar = Duration::from_nanos(new_v.max(1_000) as u64);
        // RTO = SRTT + max(G, 4*RTTVAR), G = 1ms granularity.
        let g = 1_000_000i64;
        let rto_ns = new_s + 4 * new_v;
        let rto_ns = rto_ns.max(new_s + g);
        self.rto = Duration::from_nanos(rto_ns.max(1_000_000) as u64);
        self.recompute_pacing_rate();
    }

    /// Re-derive the pacing rate from the current window and SRTT. The rate is
    /// the bandwidth that exactly drains one window per RTT — the classic
    /// `cwnd / srtt` pacing rule.
    fn recompute_pacing_rate(&mut self) {
        let srtt = self.srtt.as_secs_f64().max(1e-6);
        let rate = self.cwnd as f64 / srtt;
        self.pacing_rate = rate.clamp(MIN_PACING_RATE, MAX_PACING_RATE);
    }

    /// The current retransmission timeout for reliable control packets.
    pub fn rto(&self) -> Duration {
        self.rto
    }

    /// Current smoothed RTT.
    pub fn srtt(&self) -> Duration {
        self.srtt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_start_then_decrease() {
        let mut c = CongestionController::new();
        for _ in 0..10 {
            c.on_send();
            c.on_ack(1);
        }
        let cw = c.cwnd;
        assert!(
            cw > INITIAL_CWND_BYTES,
            "slow start should grow window: {cw}"
        );
        c.on_loss(2, 10);
        assert!(c.cwnd < cw, "loss should shrink window");
        assert_eq!(c.ssthresh, c.cwnd, "ssthresh follows the reduced window");
        assert!(c.ssthresh >= MIN_CWND_BYTES);
    }

    #[test]
    fn rtt_smooths() {
        let mut c = CongestionController::new();
        for _ in 0..20 {
            c.on_rtt_sample(Duration::from_millis(50));
        }
        assert!(c.srtt.as_millis() <= 60);
        assert!(c.rto.as_millis() >= 50);
    }

    #[test]
    fn send_budget_never_negative() {
        let mut c = CongestionController::new();
        // Exhaust the byte window by sending without acking.
        while c.send_budget() > 0 {
            c.on_send();
        }
        assert_eq!(c.send_budget(), 0, "budget clamped at 0");
        // Sending beyond the window keeps it at 0 and never underflows.
        c.on_send();
        assert_eq!(c.send_budget(), 0, "budget still 0 after over-send");
        assert_eq!(c.in_flight, c.cwnd, "in-flight pinned at the window");
    }

    #[test]
    fn on_ack_releases_in_flight() {
        let mut c = CongestionController::new();
        c.on_send();
        c.on_send();
        c.on_send();
        assert_eq!(c.in_flight, 3 * DEFAULT_MTU as u64);
        c.on_ack(2);
        assert_eq!(
            c.in_flight, DEFAULT_MTU as u64,
            "two acks release two MTUs of in-flight"
        );
        assert!(c.cwnd > INITIAL_CWND_BYTES, "slow start grew window");
    }

    #[test]
    fn refund_restores_window_and_pacing_credit() {
        let mut c = CongestionController::new();
        assert!(c.may_send(1000));
        c.on_send_bytes(1000);
        assert_eq!(c.in_flight, 1000);
        assert!(c.pacing_delay(1000).is_some());

        c.refund_send_bytes(1000);

        assert_eq!(c.in_flight, 0);
        assert!(c.pacing_delay(1000).is_none());
    }

    #[test]
    fn on_ack_zero_is_noop() {
        let mut c = CongestionController::new();
        c.on_send();
        let cw = c.cwnd;
        c.on_ack(0);
        assert_eq!(c.in_flight, DEFAULT_MTU as u64, "in-flight unchanged");
        assert_eq!(c.cwnd, cw, "window unchanged on 0 acks");
    }

    #[test]
    fn on_loss_shrinks_window_and_sets_ssthresh() {
        let mut c = CongestionController::new();
        // Grow the window first.
        for _ in 0..20 {
            c.on_send();
            c.on_ack(1);
        }
        let cw_before = c.cwnd;
        let in_flight_before = c.in_flight;
        c.on_loss(4, 10);
        assert!(c.cwnd < cw_before, "window must shrink on loss");
        assert_eq!(c.ssthresh, c.cwnd);
        assert_eq!(
            c.in_flight, in_flight_before,
            "on_loss adjusts the window only; slot lifetime belongs to ack resolution"
        );
    }

    #[test]
    fn on_loss_with_zero_total_is_noop() {
        let mut c = CongestionController::new();
        let cw = c.cwnd;
        c.on_loss(5, 0);
        assert_eq!(c.cwnd, cw, "loss with total=0 is a no-op");
    }

    #[test]
    fn on_loss_with_zero_lost_is_noop() {
        let mut c = CongestionController::new();
        let cw = c.cwnd;
        c.on_loss(0, 10);
        assert_eq!(c.cwnd, cw, "a clean batch must not shrink the window");
    }

    #[test]
    fn on_loss_does_not_go_below_min_cwnd() {
        let mut c = CongestionController::new();
        c.cwnd = 3;
        c.on_loss(1, 4);
        assert_eq!(c.cwnd, MIN_CWND_BYTES, "cwnd clamped to MIN_CWND_BYTES");
    }

    #[test]
    fn small_loss_is_gentler_than_total_loss() {
        let mut a = CongestionController::new();
        let mut b = CongestionController::new();
        a.on_loss(1, 100); // 1% loss
        b.on_loss(100, 100); // 100% loss
        assert!(
            a.cwnd > b.cwnd,
            "a one-in-a-hundred loss must not collapse the window like total loss"
        );
    }

    #[test]
    fn congestion_avoidance_grows_slower_than_slow_start() {
        let mut c = CongestionController::new();
        // Push past ssthresh into congestion avoidance.
        c.ssthresh = 64 * 1300;
        c.cwnd = c.ssthresh;
        let cw0 = c.cwnd;
        for _ in 0..10 {
            c.on_ack(1);
        }
        let cw_ca = c.cwnd;
        // CA growth is ~1 MSS per RTT, so 10 1-packet acks add well under an
        // MSS and far less than the slow-start doubling those same 10 acks
        // would have produced.
        assert!(
            cw_ca - cw0 < DEFAULT_MTU as u64,
            "CA growth should be < 1 MSS: {}",
            cw_ca - cw0
        );
        assert!(cw_ca > cw0, "CA still grows");
    }

    #[test]
    fn slow_start_doubles_on_batch_ack() {
        let mut c = CongestionController::new();
        let cw0 = c.cwnd;
        c.on_send();
        c.on_ack(1); // +1 MTU
        assert_eq!(c.cwnd, cw0 + DEFAULT_MTU as u64);
        // Batch ack of 4 at once: +4 MTU.
        for _ in 0..4 {
            c.on_send();
        }
        c.on_ack(4);
        assert_eq!(
            c.cwnd,
            cw0 + 5 * DEFAULT_MTU as u64,
            "batch ack adds n MTUs in slow start"
        );
    }

    #[test]
    fn rto_is_srtt_plus_max_granularity_4rttvar() {
        let mut c = CongestionController::new();
        // Feed stable samples so srtt and rttvar converge.
        for _ in 0..50 {
            c.on_rtt_sample(Duration::from_millis(100));
        }
        // srtt ~100ms, rttvar ~ small. RTO >= srtt + 4*rttvar >= srtt + 1ms.
        assert!(c.rto >= c.srtt, "RTO must be >= SRTT");
        assert!(c.rto.as_millis() >= 100, "RTO at least the srtt");
    }

    #[test]
    fn rto_never_below_1ms() {
        let mut c = CongestionController::new();
        // Feed very small samples.
        for _ in 0..50 {
            c.on_rtt_sample(Duration::from_micros(10));
        }
        assert!(c.rto.as_nanos() >= 1_000_000, "RTO floor is 1ms");
    }

    #[test]
    fn srtt_never_zero() {
        let mut c = CongestionController::new();
        c.on_rtt_sample(Duration::from_nanos(1));
        assert!(c.srtt.as_nanos() > 0, "srtt must never be zero");
    }

    #[test]
    fn in_flight_saturating_sub_on_ack() {
        let mut c = CongestionController::new();
        c.on_send();
        // Ack more than in-flight: saturates to 0, no underflow.
        c.on_ack(100);
        assert_eq!(c.in_flight, 0);
    }

    #[test]
    fn release_drops_in_flight_without_growing_window() {
        let mut c = CongestionController::new();
        c.on_send();
        c.on_send();
        let cw = c.cwnd;
        c.release(DEFAULT_MTU as u64);
        assert_eq!(c.in_flight, DEFAULT_MTU as u64);
        assert_eq!(c.cwnd, cw, "release must not grow the window");
        // Releasing more than in-flight saturates to 0.
        c.release(u64::MAX / 2);
        assert_eq!(c.in_flight, 0);
    }

    #[test]
    fn pacer_limits_a_burst_to_the_pacing_rate() {
        let mut c = CongestionController::new();
        // A tight RTT makes the derived rate high; a large window means the
        // window never binds. The first packet always goes immediately.
        c.on_rtt_sample(Duration::from_millis(20));
        c.cwnd = 200 * DEFAULT_MTU as u64;
        assert!(c.may_send(DEFAULT_MTU as usize), "first packet is admitted");
        // The very next packet must be refused: the pacer has not yet granted
        // credit for it, even though the window has room for hundreds.
        assert!(
            !c.may_send(DEFAULT_MTU as usize),
            "second back-to-back packet must wait for the pacer"
        );
        assert!(
            c.send_budget() > 100 * DEFAULT_MTU as u64,
            "the refusal must come from pacing, not from the window"
        );
    }

    #[test]
    fn pacing_delay_reports_when_pacing_holds_a_packet() {
        let mut c = CongestionController::new();
        c.on_rtt_sample(Duration::from_millis(20));
        c.cwnd = 200 * DEFAULT_MTU as u64;
        assert!(c.may_send(DEFAULT_MTU as usize));
        // Window-limited is not pacing-limited: no RTT sample -> slow default
        // rate, but the packet still fits, so we get a pacing delay.
        let delay = c.pacing_delay(DEFAULT_MTU as usize);
        assert!(
            delay.is_some_and(|d| d > Duration::ZERO),
            "pacing delay must be reported for a paced packet"
        );
    }

    #[test]
    fn pacing_delay_is_none_when_window_limited() {
        let mut c = CongestionController::new();
        // Fill the window completely.
        while c.send_budget() > 0 {
            c.on_send();
        }
        assert!(
            c.pacing_delay(DEFAULT_MTU as usize).is_none(),
            "a window-limited sender must wait for acks, not for the pacer"
        );
    }

    #[test]
    fn pacing_does_not_refuse_packets_after_an_idle_period() {
        let mut c = CongestionController::new();
        c.on_rtt_sample(Duration::from_millis(20));
        // Use the setter so the derived pacing rate follows the window; a bare
        // `cwnd = ...` would leave the pacer throttling at the old rate.
        c.set_cwnd(200 * DEFAULT_MTU as u64);
        assert!(c.may_send(DEFAULT_MTU as usize));
        // Simulate an idle gap longer than the pacing interval: the pacer must
        // not accumulate an unbounded debt that throttles the next packet.
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            c.may_send(DEFAULT_MTU as usize),
            "after an idle gap the pacer must grant credit again"
        );
    }

    #[test]
    fn ack_with_rtt_folds_in_a_fresh_sample() {
        let mut c = CongestionController::new();
        // The default SRTT is 100ms; a stream of 30ms acks must pull it down
        // without any ping tick being involved.
        for _ in 0..50 {
            c.on_ack_with_rtt(DEFAULT_MTU as u64, Duration::from_millis(30));
        }
        assert!(
            c.srtt < Duration::from_millis(100),
            "data acks must feed the RTT estimator: {:?}",
            c.srtt
        );
        assert!(
            c.pacing_rate > INITIAL_PACING_RATE,
            "a lower RTT must raise the pacing rate: {}",
            c.pacing_rate
        );
    }

    #[test]
    fn parity_consumes_window_and_pacing_credit() {
        let mut c = CongestionController::new();
        c.on_rtt_sample(Duration::from_millis(20));
        c.set_cwnd(200 * DEFAULT_MTU as u64);
        let budget_before = c.send_budget();
        assert!(c.try_send_parity(DEFAULT_MTU as usize));
        assert_eq!(
            c.send_budget(),
            budget_before - DEFAULT_MTU as u64,
            "parity must reserve window budget like data"
        );
        // The parity's airtime must hold back the next packet even though the
        // window still has room: total wire traffic is what the pacer paces.
        assert!(
            !c.may_send(DEFAULT_MTU as usize),
            "parity must advance the pacer schedule"
        );
    }

    #[test]
    fn parity_refused_when_window_full() {
        let mut c = CongestionController::new();
        while c.send_budget() > 0 {
            c.on_send();
        }
        assert!(
            !c.try_send_parity(DEFAULT_MTU as usize),
            "full window must skip expendable parity"
        );
        assert_eq!(c.in_flight, c.cwnd, "refused parity reserves nothing");
    }

    #[test]
    fn parity_not_refused_by_pacer_debt() {
        let mut c = CongestionController::new();
        c.on_rtt_sample(Duration::from_millis(20));
        c.set_cwnd(200 * DEFAULT_MTU as u64);
        // Put the pacer into debt with a data packet first.
        assert!(c.may_send(DEFAULT_MTU as usize));
        // Parity belonging to that group must still go out (window has room):
        // pacing debt delays the *next* data, it never drops redundancy.
        assert!(
            c.try_send_parity(DEFAULT_MTU as usize),
            "pacer debt must not refuse parity"
        );
    }

    #[test]
    fn pacing_rate_tracks_window_over_srtt() {
        let mut c = CongestionController::new();
        c.set_mtu(1000);
        c.cwnd = 1000 * 1000;
        c.on_rtt_sample(Duration::from_millis(100));
        assert!(
            (c.pacing_rate - 10_000_000.0).abs() < 1.0,
            "rate should be cwnd/srtt = 10 MB/s, got {}",
            c.pacing_rate
        );
    }
}
