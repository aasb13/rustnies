//! Live statistics counters shared with the CLI over IPC.

use std::time::Instant;

use serde::{Deserialize, Serialize};

/// Which daemon role produced this snapshot. Drives conditional display in
/// `format_stats`: server-only fields (clients, handshakes) are hidden on the
/// client and client-only fields (kill switch, dns leak, reconnecting) are
/// hidden on the server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaemonMode {
    #[default]
    Unknown,
    Client,
    Server,
}

/// A snapshot of tunnel state at a point in time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Stats {
    /// The daemon role that produced this snapshot (see [`DaemonMode`]).
    pub side: DaemonMode,
    pub connected: bool,
    pub uptime_secs: f64,
    pub loss_rate: f64,
    pub rtt_ms: f64,
    pub fec_k: u8,
    pub fec_m: u8,
    pub fec_overhead: f64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub fec_recovered: u64,
    pub congestion_window: f64,
    pub in_flight: u64,
    /// Number of currently connected client tunnels (server). Always 0 on the
    /// client side. Aggregated across all tunnels sharing these counters.
    pub clients: u64,
    /// True while the client daemon is in its reconnection backoff loop: a
    /// handshake failed or an established session tore down and it is waiting
    /// to retry. Always `false` on the server. Necessarily `false` when
    /// `connected` is true.
    pub reconnecting: bool,
    /// Number of the current reconnection attempt (1-based) in the active
    /// cycle. Resets to 0 once a session is established. 0 while connected.
    pub reconnect_attempts: u32,
    /// Short human-readable description of the most recent failure that drove
    /// the daemon into the reconnection loop (e.g. "session timeout",
    /// "handshake did not complete in time"). `None` while connected or before
    /// any failure.
    pub last_error: Option<String>,
    /// Whether the client kill switch is engaged (blocking non-tunnel traffic,
    /// fail closed). Always `false` on the server. Reflects the configured
    /// intent, not necessarily a successful install — see the daemon logs.
    pub kill_switch: bool,
    /// Whether DNS leak prevention is active (DNS forced through the tunnel
    /// while route-all is on). Always `false` on the server.
    pub dns_leak_protection: bool,
    /// Lifecycle counters (server-side aggregated). On the client these
    /// mirror the single-tunnel lifecycle.
    pub handshakes_accepted: u64,
    pub handshakes_rejected: u64,
    pub handshake_errors: u64,
    pub sessions_timed_out: u64,
    pub sessions_peer_closed: u64,
    pub sessions_evicted: u64,
    pub sessions_roamed: u64,
    /// Number of times the server dispatcher applied backpressure when a
    /// per-client TUN-forward channel was full — blocking the send rather
    /// than dropping a packet the client is waiting to receive. Server-only;
    /// always zero on the client.
    pub dispatch_backpressure: u64,
    /// Best-effort data packets dropped by the sender because the congestion
    /// window had no budget (backpressure drop, not wire loss). A sustained
    /// non-zero rate here means the app is offering more than the path can
    /// take; the tunnel drops rather than queueing so latency stays bounded.
    pub tx_dropped_congestion: u64,
    /// Data packets the sender held back for the pacer (rate limiter), as
    /// opposed to dropping. These are *not* lost: they are re-queued behind
    /// newer packet arrivals on the next send readiness. A high count simply
    /// means the sender is pacing aggressively.
    pub tx_paced: u64,
    /// Delivered packets whose RTT sample was fed to the congestion
    /// controller. Non-zero means the window is being driven by real data
    /// feedback rather than only by the ping probe.
    pub rtt_samples: u64,
    /// Current pacing rate in bytes/second derived from `cwnd / srtt`.
    pub pacing_rate: f64,
}

/// Mutable counters owned by the tunnel; [`Stats::snapshot`] produces a
/// transportable [`Stats`]. Cheap to clone into an `Arc<Mutex>`.
#[derive(Debug)]
pub struct Counters {
    pub start: Instant,
    pub connected: bool,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub fec_recovered: u64,
    pub loss_rate: f64,
    pub rtt_ms: f64,
    pub fec_k: u8,
    pub fec_m: u8,
    pub congestion_window: f64,
    pub in_flight: u64,
    /// Number of currently connected client tunnels (server). 0 on the client.
    pub clients: u64,
    /// See [`Stats::reconnecting`].
    pub reconnecting: bool,
    /// See [`Stats::reconnect_attempts`].
    pub reconnect_attempts: u32,
    /// See [`Stats::last_error`].
    pub last_error: Option<String>,
    /// See [`Stats::kill_switch`].
    pub kill_switch: bool,
    /// See [`Stats::dns_leak_protection`].
    pub dns_leak_protection: bool,
    /// Lifecycle counters (server-side: aggregated across all tunnels;
    /// client-side: single tunnel).
    pub handshakes_accepted: u64,
    pub handshakes_rejected: u64,
    pub handshake_errors: u64,
    pub sessions_timed_out: u64,
    pub sessions_peer_closed: u64,
    pub sessions_evicted: u64,
    pub sessions_roamed: u64,
    pub dispatch_backpressure: u64,
    pub tx_dropped_congestion: u64,
    pub tx_paced: u64,
    pub rtt_samples: u64,
    pub pacing_rate: f64,
    /// See [`Stats::side`].
    pub side: DaemonMode,
}

impl Default for Counters {
    fn default() -> Self {
        Self::new()
    }
}

impl Counters {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            connected: false,
            tx_packets: 0,
            rx_packets: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            fec_recovered: 0,
            loss_rate: 0.0,
            rtt_ms: 0.0,
            fec_k: 0,
            fec_m: 0,
            congestion_window: 0.0,
            in_flight: 0,
            clients: 0,
            reconnecting: false,
            reconnect_attempts: 0,
            last_error: None,
            kill_switch: false,
            dns_leak_protection: false,
            handshakes_accepted: 0,
            handshakes_rejected: 0,
            handshake_errors: 0,
            sessions_timed_out: 0,
            sessions_peer_closed: 0,
            sessions_evicted: 0,
            sessions_roamed: 0,
            dispatch_backpressure: 0,
            tx_dropped_congestion: 0,
            tx_paced: 0,
            rtt_samples: 0,
            pacing_rate: 0.0,
            side: DaemonMode::Unknown,
        }
    }

    pub fn snapshot(&self) -> Stats {
        Stats {
            connected: self.connected,
            uptime_secs: self.start.elapsed().as_secs_f64(),
            loss_rate: self.loss_rate,
            rtt_ms: self.rtt_ms,
            fec_k: self.fec_k,
            fec_m: self.fec_m,
            fec_overhead: if self.fec_k == 0 {
                0.0
            } else {
                self.fec_m as f64 / self.fec_k as f64
            },
            tx_packets: self.tx_packets,
            rx_packets: self.rx_packets,
            tx_bytes: self.tx_bytes,
            rx_bytes: self.rx_bytes,
            fec_recovered: self.fec_recovered,
            congestion_window: self.congestion_window,
            in_flight: self.in_flight,
            clients: self.clients,
            reconnecting: self.reconnecting,
            reconnect_attempts: self.reconnect_attempts,
            last_error: self.last_error.clone(),
            kill_switch: self.kill_switch,
            dns_leak_protection: self.dns_leak_protection,
            handshakes_accepted: self.handshakes_accepted,
            handshakes_rejected: self.handshakes_rejected,
            handshake_errors: self.handshake_errors,
            sessions_timed_out: self.sessions_timed_out,
            sessions_peer_closed: self.sessions_peer_closed,
            sessions_evicted: self.sessions_evicted,
            sessions_roamed: self.sessions_roamed,
            dispatch_backpressure: self.dispatch_backpressure,
            tx_dropped_congestion: self.tx_dropped_congestion,
            tx_paced: self.tx_paced,
            rtt_samples: self.rtt_samples,
            pacing_rate: self.pacing_rate,
            side: self.side,
        }
    }
}
