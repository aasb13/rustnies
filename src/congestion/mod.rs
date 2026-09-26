//! Congestion / rate control.
//!
//! [`CongestionControl`] is the seam behind the sender's rate limiting,
//! selected by name from `[congestion] algorithm` via
//! [`build_congestion`]. The default is [`tcp::CongestionController`], a
//! deliberately small TCP-inspired controller; [`NoCongestionControl`] turns
//! rate limiting off entirely.
//!
//! # Why this is not negotiated
//!
//! Congestion control is the one swappable protocol part that is **purely
//! local**. A congestion window describes only what *this* sender has put on
//! the wire and what has come back; it is invisible to the peer, so there is
//! nothing to agree on. Each side therefore uses its own `[congestion]` setting
//! and the tunnel reads its own [`CongestionSnapshot`] for stats. Every other
//! swappable part (cipher, transport, FEC scheme) is shared state that the
//! handshake negotiates — see [`crate::protocol::profile`].
//!
//! # Why bytes and not packets
//!
//! A packet-counting window cannot tell a 1400-byte bulk packet from a 64-byte
//! ping reply, so a window of "4 packets" is anywhere between 300 B and 5 KB of
//! actual in-flight data depending on the workload. Every derived quantity
//! (pacing rate, drop decision) then inherits that error. Accounting in bytes
//! makes the window a real bandwidth-delay product and lets the pacer be
//! expressed in bytes/second, which is the only way to keep a lossy link from
//! being flooded by a burst of back-to-back datagrams.
//!
//! This is a building block, not a high-performance design — a BBR-style
//! controller implements this same trait and slots in without touching the
//! tunnel.

use std::time::{Duration, Instant};

pub mod tcp;

pub use tcp::{
    CongestionController, DEFAULT_MTU, INITIAL_CWND_BYTES, INITIAL_SSTHRESH_BYTES, MIN_CWND_BYTES,
};

/// Read-only view of a controller's state, for stats and logs.
///
/// Taking a snapshot rather than exposing the controller's fields keeps the
/// concrete controller's internals private to [`tcp`] and lets a future
/// implementation report whatever it can without changing the tunnel.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CongestionSnapshot {
    /// Congestion window in bytes.
    pub cwnd: u64,
    /// Bytes currently in flight (outstanding, unacked).
    pub in_flight: u64,
    /// Current pacing rate in bytes/second.
    pub pacing_rate: f64,
    /// Last measured loss ratio in `[0, 1]`.
    pub last_loss: f64,
    /// Smoothed RTT.
    pub srtt: Duration,
    /// Retransmission timeout for reliable control packets.
    pub rto: Duration,
}

/// A swappable congestion / rate controller.
///
/// The contract is deliberately narrow: the tunnel asks *may I send this many
/// bytes* and then reports what happened. Everything the controller does
/// internally (window growth, pacing schedule, loss response) is its own
/// business, which is what lets a BBR-style implementation drop in.
///
/// Two rules keep the tunnel's own accounting correct:
///
/// * [`try_send_parity`](Self::try_send_parity) is a *separate* admission test
///   from [`may_send`](Self::may_send). Parity belongs to an already-admitted
///   data group, and must never be refused for pacing reasons — dropping
///   redundancy because of pacing would disable FEC exactly when the path is
///   busy.
/// * Every path that sends bytes must have a matching
///   [`refund_send_bytes`](Self::refund_send_bytes) or
///   [`release`](Self::release) when the datagram is dropped after admission,
///   otherwise the window leaks credit.
pub trait CongestionControl: Send + 'static {
    /// Config name, e.g. `"tcp-reno"`. Must match the name accepted by
    /// [`select_congestion`].
    fn name(&self) -> &'static str;

    /// Set the MTU that turns a byte window into a packet-count estimate.
    /// Called by the tunnel once it knows the device MTU.
    fn set_mtu(&mut self, mtu: u32);

    /// Additional **bytes** the sender may dispatch right now under the
    /// congestion window alone (ignoring pacing). `0` means the window is
    /// exhausted; the caller must wait for acks rather than drop.
    fn send_budget(&self) -> u64;

    /// Admission test for one packet of `len` bytes: is there window budget,
    /// and has the pacer granted credit for it?
    fn may_send(&mut self, len: usize) -> bool;

    /// When the pacer will next grant credit, or `None` if it has credit right
    /// now. The tunnel parks a packet until this instant rather than dropping
    /// it, which turns rate limiting into delay instead of loss.
    fn next_send_deadline(&self) -> Option<Instant>;

    /// Reserve `len` bytes in flight, after an admission check passed.
    fn on_send_bytes(&mut self, len: usize);

    /// Give back `bytes` reserved by [`on_send_bytes`](Self::on_send_bytes) for
    /// a datagram that was dropped after admission (encrypt failure, MTU
    /// overflow, socket error), without growing the window.
    fn refund_send_bytes(&mut self, bytes: u64);

    /// Admission test for an FEC parity packet belonging to an already-admitted
    /// data group. `false` means the window is full and the caller should skip
    /// the parity.
    fn try_send_parity(&mut self, len: usize) -> bool;

    /// Release `bytes` in flight as lost, without growing the window.
    fn release(&mut self, bytes: u64);

    /// Retire `bytes` acked and grow the window, with no RTT sample.
    fn on_ack_bytes(&mut self, bytes: u64);

    /// Retire `bytes` acked, grow the window, and take `sample` as a fresh RTT
    /// measurement.
    fn on_ack_with_rtt(&mut self, bytes: u64, sample: Duration);

    /// Signal that `lost` of `total` sent packets were lost, so the controller
    /// can back off. Only adjusts the window; the tunnel owns exact-byte slot
    /// retirement.
    fn on_loss(&mut self, lost: u64, total: u64);

    /// Apply a fresh RTT sample (time between sending and acking one packet).
    fn on_rtt_sample(&mut self, rtt: Duration);

    /// Force the congestion window to `bytes`, clamped to the implementation's
    /// own floor.
    ///
    /// An operations/testing hook rather than part of the feedback loop: the
    /// tunnel never calls it during normal operation, only the daemon at
    /// startup and tests that need a known window. Implementations that have no
    /// notion of a byte window ignore it.
    fn set_cwnd(&mut self, bytes: u64);

    /// Current state, for stats and logs.
    fn snapshot(&self) -> CongestionSnapshot;
}

/// Rate limiting disabled: an unbounded window and no pacer.
///
/// Every TUN read is dispatched as fast as it arrives. This is the right
/// choice on a path where the bottleneck is the peer's receive rate rather than
/// the local path (e.g. a wired LAN), and the wrong one on a shared or lossy
/// path, where an unbounded sender turns into queueing delay, bufferbloat and
/// then loss. It is a diagnostic and lab aid, not a default.
///
/// The retransmission timeout still needs a value even with no window, so
/// [`NoCongestionControl::rto`] returns a fixed conservative constant.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoCongestionControl;

/// RTO used by [`NoCongestionControl`]: long enough to absorb a burst without
/// being long enough to stall a `Close` for long.
const NO_CC_RTO: Duration = Duration::from_millis(1000);

impl CongestionControl for NoCongestionControl {
    fn name(&self) -> &'static str {
        CONGESTION_NONE
    }

    fn set_mtu(&mut self, _mtu: u32) {}

    fn send_budget(&self) -> u64 {
        u64::MAX
    }

    fn may_send(&mut self, _len: usize) -> bool {
        true
    }

    fn next_send_deadline(&self) -> Option<Instant> {
        None
    }

    fn on_send_bytes(&mut self, _len: usize) {}

    fn refund_send_bytes(&mut self, _bytes: u64) {}

    fn try_send_parity(&mut self, _len: usize) -> bool {
        true
    }

    fn release(&mut self, _bytes: u64) {}

    fn on_ack_bytes(&mut self, _bytes: u64) {}

    fn on_ack_with_rtt(&mut self, _bytes: u64, _sample: Duration) {}

    fn on_loss(&mut self, _lost: u64, _total: u64) {}

    fn on_rtt_sample(&mut self, _rtt: Duration) {}

    fn set_cwnd(&mut self, _bytes: u64) {}

    fn snapshot(&self) -> CongestionSnapshot {
        CongestionSnapshot {
            cwnd: u64::MAX,
            in_flight: 0,
            pacing_rate: f64::INFINITY,
            last_loss: 0.0,
            srtt: Duration::ZERO,
            rto: NO_CC_RTO,
        }
    }
}

/// Default congestion algorithm name, used when `[congestion] algorithm` is
/// unset.
pub const DEFAULT_CONGESTION: &str = "tcp-reno";
/// Config name that disables congestion control.
pub const CONGESTION_NONE: &str = "none";

/// Selectable congestion controllers, resolved by name from config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionKind {
    /// The TCP-inspired slow-start / multiplicative-decrease controller.
    TcpReno,
    /// No window, no pacer.
    None,
}

impl CongestionKind {
    /// The name this kind is selected by (and reports from
    /// [`CongestionControl::name`]).
    pub fn name(self) -> &'static str {
        match self {
            CongestionKind::TcpReno => DEFAULT_CONGESTION,
            CongestionKind::None => CONGESTION_NONE,
        }
    }

    /// Construct the boxed controller.
    pub fn build(self) -> Box<dyn CongestionControl> {
        match self {
            CongestionKind::TcpReno => Box::new(tcp::CongestionController::new()),
            CongestionKind::None => Box::new(NoCongestionControl),
        }
    }
}

/// Resolve a congestion controller by config name.
///
/// An unknown name is a hard error rather than a silent fallback to
/// [`DEFAULT_CONGESTION`]: silently rate-limiting (or not) differently from
/// what the operator asked for is worse than refusing to start, and unlike the
/// cipher/FEC selectors this one is local so a typo is the only likely cause.
pub fn select_congestion(name: &str) -> Result<CongestionKind, UnknownCongestion> {
    match name.trim() {
        "" | DEFAULT_CONGESTION | "tcp" => Ok(CongestionKind::TcpReno),
        CONGESTION_NONE | "off" | "disabled" => Ok(CongestionKind::None),
        other => Err(UnknownCongestion {
            name: other.to_string(),
            supported: [DEFAULT_CONGESTION, CONGESTION_NONE].join(", "),
        }),
    }
}

/// Build a boxed controller from a config name, defaulting on an empty string.
pub fn build_congestion(name: &str) -> Result<Box<dyn CongestionControl>, UnknownCongestion> {
    Ok(select_congestion(name)?.build())
}

/// A config name that does not match any [`CongestionControl`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown congestion algorithm {name:?}; supported: {supported}")]
pub struct UnknownCongestion {
    /// The rejected config name.
    pub name: String,
    /// The comma-separated list of supported names, for the error message.
    pub supported: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_congestion_recognises_names() {
        assert_eq!(
            select_congestion(DEFAULT_CONGESTION).unwrap(),
            CongestionKind::TcpReno
        );
        assert_eq!(select_congestion("").unwrap(), CongestionKind::TcpReno);
        assert_eq!(select_congestion("tcp").unwrap(), CongestionKind::TcpReno);
        assert_eq!(
            select_congestion(CONGESTION_NONE).unwrap(),
            CongestionKind::None
        );
        assert_eq!(select_congestion("off").unwrap(), CongestionKind::None);
    }

    #[test]
    fn select_congestion_rejects_unknown_hard() {
        let err = select_congestion("bbr").unwrap_err();
        assert_eq!(err.name, "bbr");
        assert!(err.supported.contains(DEFAULT_CONGESTION));
        assert!(build_congestion("bbr").is_err());
    }

    #[test]
    fn names_are_stable() {
        for kind in [CongestionKind::TcpReno, CongestionKind::None] {
            assert_eq!(kind.build().name(), kind.name());
        }
    }

    #[test]
    fn default_controller_starts_with_a_usable_window() {
        let cc = build_congestion("").unwrap();
        assert!(cc.send_budget() > 0);
        let s = cc.snapshot();
        assert_eq!(s.cwnd, INITIAL_CWND_BYTES);
        assert_eq!(s.in_flight, 0);
        assert!(s.pacing_rate > 0.0);
    }

    #[test]
    fn no_cc_never_refuses_and_tracks_no_in_flight() {
        let mut cc = build_congestion(CONGESTION_NONE).unwrap();
        assert!(cc.may_send(usize::MAX / 2));
        assert!(cc.try_send_parity(1000));
        assert_eq!(cc.next_send_deadline(), None);
        assert_eq!(cc.send_budget(), u64::MAX);
        cc.on_send_bytes(1400);
        cc.on_loss(10, 100);
        cc.on_ack_with_rtt(1400, Duration::from_millis(5));
        let s = cc.snapshot();
        assert_eq!(s.in_flight, 0);
        assert_eq!(s.last_loss, 0.0);
        assert!(s.rto > Duration::ZERO);
    }

    #[test]
    fn tcp_controller_admits_then_refuses_at_the_window() {
        let mut cc = build_congestion(DEFAULT_CONGESTION).unwrap();
        assert!(cc.may_send(1300));
        cc.on_send_bytes(1300);
        // Drain the window directly (the pacer would otherwise refuse first),
        // then the next packet must be refused rather than dropped silently.
        while cc.send_budget() > 0 {
            cc.on_send_bytes(1300);
        }
        assert_eq!(cc.send_budget(), 0);
        assert!(!cc.may_send(1));
    }

    #[test]
    fn refund_restores_window_credit() {
        let mut cc = build_congestion(DEFAULT_CONGESTION).unwrap();
        let before = cc.send_budget();
        assert!(cc.may_send(1400));
        cc.on_send_bytes(1400);
        assert_eq!(cc.send_budget(), before - 1400);
        cc.refund_send_bytes(1400);
        assert_eq!(cc.send_budget(), before);
    }

    #[test]
    fn snapshot_tracks_ack_growth() {
        let mut cc = build_congestion(DEFAULT_CONGESTION).unwrap();
        let before = cc.snapshot().cwnd;
        cc.on_send_bytes(1300);
        cc.on_ack_with_rtt(1300, Duration::from_millis(20));
        assert_eq!(cc.snapshot().in_flight, 0);
        assert!(cc.snapshot().cwnd > before, "ack should grow the window");
        assert!(cc.snapshot().srtt > Duration::ZERO);
    }

    #[test]
    fn loss_backs_the_window_off() {
        let mut cc = build_congestion(DEFAULT_CONGESTION).unwrap();
        let before = cc.snapshot().cwnd;
        cc.on_loss(10, 100);
        assert!(cc.snapshot().cwnd < before);
        assert!(cc.snapshot().last_loss > 0.0);
    }

    #[test]
    fn parity_never_refused_for_pacing() {
        // try_send_parity checks the window only: a pacer debt must not
        // disable FEC on a busy path.
        let mut cc = build_congestion(DEFAULT_CONGESTION).unwrap();
        assert!(cc.try_send_parity(256));
        assert!(cc.snapshot().in_flight > 0);
    }
}
