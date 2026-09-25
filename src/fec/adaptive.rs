//! Adaptive FEC controller.
//!
//! [`AdaptiveFec`] watches the measured packet-loss ratio and RTT and picks a
//! `k`/`m` pair (`k` source symbols, `m` parity symbols per FEC group) that
//! keeps expected post-FEC residual loss low while bounding overhead.
//!
//! Policy:
//! - As measured loss rises, `m` increases (more redundancy). As loss falls,
//!   `m` decreases. Hysteresis bands prevent flapping.
//! - `k = 1` by default so that **every** packet is its own complete FEC group.
//!   This eliminates the partial-group problem: with `k > 1`, sparse traffic
//!   (e.g. ICMP pings at 1 pkt/s) never fills a group, so the early-flush tick
//!   sends it with **zero** parity. With `k = 1`, every packet gets `m`
//!   parity copies immediately, regardless of traffic rate.
//! - `m` is clamped to `[min_m, max_m]` and `k + m <= 255` (GF(256) limit).
//!   `min_m` is a floor that can be reached, not a permanent minimum: on a
//!   clean link the EMA drives `m` down to `min_m` (which defaults to 1, i.e.
//!   100% overhead), and ramps back up the moment sustained loss is observed.
//!
//! This is intentionally a simple, transparent policy. It is the *only* place
//! that decides FEC parameters, so future smarter controllers can replace it.

use std::time::Duration;

/// FEC parameters chosen by the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecParams {
    pub k: u8,
    pub m: u8,
}

impl FecParams {
    pub fn overhead(&self) -> f64 {
        if self.k == 0 {
            0.0
        } else {
            self.m as f64 / self.k as f64
        }
    }
}

/// Adaptive FEC controller.
#[derive(Debug, Clone)]
pub struct AdaptiveFec {
    /// Source symbols per group.
    pub k: u8,
    /// Minimum/maximum parity symbols.
    pub min_m: u8,
    pub max_m: u8,
    /// Loss thresholds (fractions in `[0,1]`). When the smoothed loss is above
    /// `up[i]`, use at least `i+1` parities. When below `down[i]`, drop back.
    pub up: Vec<f64>,
    pub down: Vec<f64>,
    /// Current parity count.
    pub current_m: u8,
    /// EMA-smoothed loss ratio.
    pub smoothed_loss: f64,
    /// EMA smoothing factor (0..1).
    pub ema_alpha: f64,
}

impl AdaptiveFec {
    /// A sensible default tuned for reliability on unstable links.
    ///
    /// `k = 1` so every packet is its own FEC group (no partial groups,
    /// no latency waiting for group fill). `min_m = 1` lets a clean link
    /// relax to a single parity twin (100% overhead instead of 200%): with
    /// `k = 1` and `m = 1`, an isolated single-datagram loss is recoverable
    /// (residual loss `p^2`, so 0.5% wire loss becomes ~0.0025% after FEC),
    /// while a 2-datagram burst is not — the controller ramps back to `m = 2`
    /// within a handful of packets when it sees real loss, so bursty links
    /// still get the `p^3` protection. `current_m` starts at 2 so the first
    /// packets go out with burst protection before any loss samples exist;
    /// the EMA then earns its way down to 1 on consistently clean links
    /// (smoothed loss below the lowest `down` band). `max_m = 4` caps overhead
    /// at 400% (any 1 of 5 copies surviving ~80% underlying loss): enough to
    /// ride out the kind of burst loss the tunnel is designed for, without
    /// the self-inflicted flood that a much larger ceiling caused on lossy
    /// links (the old `max_m = 20` could amplify a modest real loss into 2000%
    /// overhead, which saturated the link and produced *more* loss). The loss
    /// input is true wire-loss fed from FEC recovery and unrecoverable-group
    /// eviction, so these thresholds see real loss rather than an artifact of
    /// a stuck ack window. `ema_alpha = 0.25` reacts within a handful of
    /// packets so a sudden loss spike ramps redundancy quickly.
    ///
    /// `min_m` must stay >= 1 (not 0): with `m = 0` no RX FEC group is ever
    /// recorded, so a lost packet leaves no recovery/eviction signal and the
    /// controller could never learn to ramp back up. `m = 1` is the lowest
    /// floor that preserves the loss-feedback loop.
    pub fn default_for_vpn() -> Self {
        let up = vec![0.05, 0.12, 0.22, 0.35];
        let down = up.iter().map(|u| u * 0.6).collect();
        Self {
            k: 1,
            min_m: 1,
            max_m: 4,
            up,
            down,
            current_m: 2,
            smoothed_loss: 0.0,
            ema_alpha: 0.25,
        }
    }

    /// Build a controller with custom parameters, generating threshold
    /// bands that span `[~0.03, ~0.89]` across `max_m` bands. Used when the
    /// user overrides FEC settings via `[fec]` in the config file.
    pub fn with_params(k: u8, min_m: u8, max_m: u8, initial_m: u8, ema_alpha: f64) -> Self {
        let n_bands = max_m.max(1) as usize;
        let up: Vec<f64> = (0..n_bands)
            .map(|i| {
                if n_bands <= 1 {
                    0.03
                } else {
                    0.03 + (0.89 - 0.03) * (i as f64 / (n_bands - 1) as f64)
                }
            })
            .collect();
        let down = up.iter().map(|u| u * 0.7).collect();
        Self {
            k,
            min_m,
            max_m,
            up,
            down,
            current_m: initial_m,
            smoothed_loss: 0.0,
            ema_alpha,
        }
    }

    /// Feed a fresh loss-ratio sample (in `[0,1]`) and return the new params.
    pub fn observe(&mut self, loss: f64) -> FecParams {
        self.smoothed_loss = self.smoothed_loss * (1.0 - self.ema_alpha) + loss * self.ema_alpha;
        let s = self.smoothed_loss;
        // Try to increase: pick the highest band whose `up` threshold we
        // cross, so a single large loss sample can jump straight to the
        // appropriate redundancy level.
        for (i, t) in self.up.iter().enumerate() {
            let want_m = (i + 1) as u8;
            if s > *t {
                self.current_m = want_m.min(self.max_m);
            }
        }
        // Try to decrease: from current band down to the lowest band whose
        // `down` threshold we are below.
        for i in (0..self.up.len()).rev() {
            let band_m = (i + 1) as u8;
            if band_m < self.current_m && s < self.down[i] {
                self.current_m = band_m.max(self.min_m);
            }
        }
        // If we're below the lowest band's down-threshold, drop all the way to
        // the minimum parity (the loop above can only reach band 1, not 0).
        if !self.down.is_empty() && s < self.down[0] {
            self.current_m = self.min_m;
        }
        // Clamp.
        if self.current_m > self.max_m {
            self.current_m = self.max_m;
        }
        if self.current_m < self.min_m {
            self.current_m = self.min_m;
        }
        let m = self.current_m;
        // Ensure k + m <= 255 (always true with our defaults, but be safe).
        let k = self.k.min(255 - m);
        FecParams { k, m }
    }

    /// Feed a loss sample for a group that could **not** be recovered (too
    /// many erasures for the current parity count). This is the strongest
    /// loss signal: the current redundancy was insufficient, so the
    /// controller should increase `m` aggressively. The loss ratio is
    /// `lost / total`, clamped to `[0, 1]`.
    pub fn observe_unrecoverable(&mut self, lost: u64, total: u64) -> FecParams {
        if total == 0 {
            return self.params();
        }
        let loss = (lost as f64 / total as f64).clamp(0.0, 1.0);
        self.observe(loss)
    }

    /// Current parameters without mutating state.
    pub fn params(&self) -> FecParams {
        let m = self.current_m;
        let k = self.k.min(255 - m);
        FecParams { k, m }
    }

    /// Estimate the time a full FEC group takes to accumulate at the given
    /// inter-packet spacing — used by the tunnel to decide group boundaries.
    pub fn group_accumulation_time(&self, inter_packet: Duration) -> Duration {
        inter_packet * (self.k as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scales_up_and_down() {
        let mut f = AdaptiveFec::default_for_vpn();
        // Feed sustained total loss so the EMA catches up to the max band.
        for _ in 0..40 {
            f.observe(1.0);
        }
        let p0 = f.params();
        assert_eq!(p0.m, f.max_m, "sustained loss should reach max parity");
        for _ in 0..80 {
            f.observe(0.0);
        }
        let p1 = f.params();
        assert_eq!(p1.m, f.min_m, "should have scaled back down to min");
    }

    #[test]
    fn starts_at_min_m_on_zero_loss() {
        let mut f = AdaptiveFec::default_for_vpn();
        f.observe(0.0);
        assert_eq!(f.params().m, f.min_m);
    }

    #[test]
    fn starts_at_initial_m_not_floor() {
        // The whole point of the fix: the tunnel must start at `initial_m` (2)
        // so the first packets carry burst protection, and only relax to the
        // floor (min_m = 1) after sustained zero-loss samples. A controller
        // that snapped straight to the floor on startup would defeat the burst
        // protection and re-introduce the permanent 200% overhead tax.
        let f = AdaptiveFec::default_for_vpn();
        assert_eq!(f.current_m, 2, "default starts at initial_m = 2");
        // params() at construction (what the tunnel uses) must reflect that.
        assert_eq!(
            f.params().m,
            2,
            "initial params must be initial_m, not floor"
        );
        assert_eq!(f.min_m, 1, "floor is 1 (clean link relaxes to single twin)");

        // After enough zero-loss samples, it should relax down to the floor.
        let mut g = AdaptiveFec::default_for_vpn();
        for _ in 0..80 {
            g.observe(0.0);
        }
        assert_eq!(g.params().m, 1, "sustained clean link relaxes to min_m = 1");
    }

    #[test]
    fn k_is_one_by_default() {
        let f = AdaptiveFec::default_for_vpn();
        assert_eq!(f.k, 1, "k=1 eliminates partial groups");
    }

    #[test]
    fn moderate_loss_ramps_quickly() {
        let mut f = AdaptiveFec::default_for_vpn();
        for _ in 0..20 {
            f.observe(1.0);
        }
        let p = f.params();
        assert!(
            p.m == f.max_m,
            "sustained total loss should ramp m to the ceiling: got {}",
            p.m
        );
    }

    #[test]
    fn observe_unrecoverable_feeds_loss() {
        let mut f = AdaptiveFec::default_for_vpn();
        f.observe(0.0);
        assert_eq!(f.params().m, f.min_m);
        f.observe_unrecoverable(1, 1);
        assert!(
            f.params().m > f.min_m,
            "unrecoverable loss should increase m"
        );
    }

    #[test]
    fn observe_unrecoverable_zero_total_is_noop() {
        let mut f = AdaptiveFec::default_for_vpn();
        f.observe(0.0);
        let before = f.params();
        f.observe_unrecoverable(5, 0);
        assert_eq!(f.params(), before, "zero total should not change params");
    }

    #[test]
    fn with_params_generates_valid_thresholds() {
        let f = AdaptiveFec::with_params(2, 1, 10, 3, 0.25);
        assert_eq!(f.k, 2);
        assert_eq!(f.max_m, 10);
        assert_eq!(f.up.len(), 10, "should have max_m threshold bands");
        // First threshold should be low, last near 0.89.
        assert!(f.up[0] < 0.1, "first threshold should be low: {}", f.up[0]);
        assert!(
            f.up[9] > 0.8,
            "last threshold should be near 0.89: {}",
            f.up[9]
        );
    }
}
