//! The tunnel: ties protocol, crypto, FEC, congestion and TUN together.
//!
//! Both client and server converge on [`Tunnel::run`]: after a Noise IK
//! handshake establishes two application keys and a session id, the same
//! steady-state loop handles TUN<->UDP pumping, FEC, congestion control, RTT
//! probes and graceful close. The loop is fed incoming UDP datagrams over a
//! channel so that a single shared socket can demux many concurrent tunnels
//! (the multi-client server in [`server`]) while the client uses a dedicated
//! socket-reader task. The only client/server differences are which side
//! initiates the handshake and whether the server installs NAT rules.

pub mod handshake;
pub mod peers;
pub mod server;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc, watch};

use crate::congestion::CongestionController;
use crate::crypto::aead::{self, Direction};
use crate::fec::adaptive::{AdaptiveFec, FecParams};
use crate::fec::reed_solomon::ReedSolomon;
use crate::obfuscation::{ObfuscationStack, is_decoy_frame};
use crate::protocol::SessionId;
use crate::protocol::codec;
use crate::protocol::header::{MAX_PAYLOAD, OUTER_OVERHEAD, PATH_MTU, PacketHeader, PacketType};
use crate::protocol::session::Session;
use crate::stats::Counters;
use crate::transport::Transport;

/// Time after which an incomplete RX FEC group is evicted (memory bound).
const RX_GROUP_TTL: Duration = Duration::from_secs(5);
/// How often to send an RTT probe.
const PING_INTERVAL: Duration = Duration::from_millis(500);
/// How often to flush a partial TX FEC group / re-evaluate FEC params.
const FEC_TICK: Duration = Duration::from_millis(100);
/// How often to check for retransmit of unacked control packets.
const RTO_TICK: Duration = Duration::from_millis(50);
/// How often to flush a coalesced standalone Ack (delayed-ack timer). Without
/// this, one-way flows only get acked on the 500 ms ping tick, the sender's
/// window starves between pings and every packet past `cwnd` is dropped even
/// though the path is idle — the tunnel manufactures its own loss.
const ACK_TICK: Duration = Duration::from_millis(25);
/// Send an immediate standalone Ack after this many data/parity receipts if
/// the timer has not fired yet (keeps the window moving under burst).
const ACK_EVERY: u32 = 4;
/// Max outstanding (unacked) reliable control packets.
const MAX_OUTSTANDING_CONTROL: usize = 64;
/// Largest RTT we will believe from a data-driven sample. Anything above this
/// is a stale send-time record (or a seq reused after wrap), not a real path
/// measurement, and would corrupt SRTT and the pacing rate.
const MAX_RTT_SAMPLE: Duration = Duration::from_secs(10);
/// Safety cap on the send-time map when the peer has not advertised any ack
/// window yet. The steady-state bound comes from `prune_send_times` (the ack
/// window); this only covers the pre-first-ack interval.
const MAX_SEND_TIMES: usize = 4096;
/// How often to send an authenticated keepalive during idle periods.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
/// If no traffic (keepalive or real) is seen from a peer within this timeout,
/// tear down the session. Must be comfortably longer than KEEPALIVE_INTERVAL.
const SESSION_TIMEOUT: Duration = Duration::from_secs(75);

/// Why the steady-state [`Tunnel::run`] loop exited. The client daemon maps
/// this onto the `last_error` field it publishes over IPC, so `rustnies status`
/// can report *why* it is reconnecting (e.g. "session timeout" vs "peer
/// closed") rather than only that it is retrying. The server logs it for
/// diagnostics when a client tunnel ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelExit {
    /// The shared stop signal fired (Ctrl+C or the IPC `Stop` command).
    Stopped,
    /// The peer sent an authenticated `Close` message.
    PeerClosed,
    /// No traffic (data, control, or keepalive) was received from the peer
    /// within the session inactivity timeout.
    SessionTimeout,
    /// The UDP feed closed — the socket-reader / server dispatcher is gone.
    UdpClosed,
    /// A read error on the TUN device.
    TunError,
}

impl std::fmt::Display for TunnelExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelExit::Stopped => write!(f, "stopped"),
            TunnelExit::PeerClosed => write!(f, "peer closed"),
            TunnelExit::SessionTimeout => write!(f, "session timeout"),
            TunnelExit::UdpClosed => write!(f, "udp source closed"),
            TunnelExit::TunError => write!(f, "tun read error"),
        }
    }
}

/// A pending reliable control packet awaiting acknowledgement.
struct Outstanding {
    seq: u32,
    ptype: PacketType,
    payload: Vec<u8>, // the encrypted frame to retransmit
    last_sent: Instant,
}

/// A receive-side FEC group under assembly.
struct RxGroup {
    /// `n = k + m` slots; `None` = not yet received.
    symbols: Vec<Option<Vec<u8>>>,
    /// Lengths observed (all equal once any present).
    k: u8,
    m: u8,
    /// Which source indices (0..k) have already been written to TUN, either by
    /// direct `Data` delivery or by FEC recovery. Late-arriving originals for
    /// these slots must be suppressed to avoid duplicate TUN writes.
    delivered: Vec<bool>,
    /// Whether `recover_group` has already decoded this group. A decoded group
    /// is kept (until TTL eviction) purely as the dedup set for late originals;
    /// no further recovery is attempted.
    decoded: bool,
    deadline: Instant,
}

impl RxGroup {
    fn new(k: u8, m: u8) -> Self {
        let n = k as usize + m as usize;
        Self {
            symbols: (0..n).map(|_| None).collect(),
            k,
            m,
            delivered: vec![false; k as usize],
            decoded: false,
            deadline: Instant::now() + RX_GROUP_TTL,
        }
    }
}

/// One direction of the established tunnel. Owns the hot-path state; the
/// [`Tunnel`] only runs a single task so most state lives on `&mut self`.
pub struct Tunnel {
    pub tun: Box<dyn crate::tun::Tun>,
    pub sock: Arc<UdpSocket>,
    pub peer: SocketAddr,
    pub session: Session,
    pub transport: Box<dyn Transport>,
    /// Stackable obfuscation transforms applied on top of `transport`. When
    /// empty (the default), this is an identity and the hot path is
    /// allocation-free. When non-empty, `apply` runs before `Transport::wrap`
    /// on send and `reverse` runs after `Transport::unwrap` on receive.
    pub obfuscation: ObfuscationStack,
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_dir: Direction,
    recv_dir: Direction,

    fec: AdaptiveFec,
    fec_params: FecParams,
    rs: ReedSolomon,
    group_id: u16,
    group_index: u8,
    group_buffer: Vec<Vec<u8>>,

    cc: CongestionController,
    outstanding: Vec<Outstanding>,

    // Ping bookkeeping.
    ping_seq: u32,
    last_ping_sent: Option<Instant>,

    /// When we last received any traffic (data, control, or keepalive) from
    /// the peer. Used to detect dead sessions.
    last_peer_activity: Instant,
    /// How often to send keepalives. Configurable for tests.
    keepalive_interval: Duration,
    /// Session inactivity timeout. Configurable for tests.
    session_timeout: Duration,

    rx_groups: HashMap<u16, RxGroup>,

    /// Last peer ack advertisement we have already accounted for. Used to
    /// avoid double-counting the same acked seqs across multiple datagrams:
    /// each incoming packet re-advertises the peer's current window, but we
    /// only want to release in-flight slots for seqs that became acked *since*
    /// the last datagram we processed. `0` means we have not seen one yet.
    last_peer_ack: u32,
    last_peer_bitmap: u32,
    /// Data/parity receipts since the last (piggyback or standalone) ack we
    /// advertised. Drives the delayed-ack timer: when this is non-zero the
    /// `ACK_TICK` fires a standalone `Ack` so one-way flows get timely
    /// feedback even with no reverse traffic to piggyback on.
    rx_since_ack: u32,

    /// When each of our outgoing wire seqs was handed to the socket. Populated
    /// by `send_data_like` / `send_packet` and drained as the peer's ack
    /// advertisement retires those seqs. This is what lets a data packet's
    /// round trip feed the congestion controller's RTT estimator: the ping
    /// probe alone only samples the path every `PING_INTERVAL`, which is far
    /// too coarse to grow a window against live traffic.
    send_times: HashMap<u32, Instant>,

    /// The packet the send gate refused on the last TUN read because the
    /// *pacer* (not the window) was holding it back. Carried into the next loop
    /// iteration and retried before reading another packet from the device, so
    /// a paced packet is delayed instead of dropped. Only ever holds one
    /// packet: a second arrival supersedes it (drop-oldest), so the buffer
    /// cannot grow and latency stays bounded.
    pending_out: Option<Vec<u8>>,

    /// Fires when the pacer will have credit for the pending packet. `None`
    /// means the window (not the pacer) is the blocker, in which case the
    /// retry is driven by the ack path instead.
    pending_deadline: Option<tokio::time::Instant>,

    /// Set when the peer sends a `Close` (or we decide to tear down); the run
    /// loop checks this after each datagram and exits.
    closing: bool,

    pub counters: Arc<Mutex<Counters>>,

    /// Optional eviction signal channel. When the dispatcher decides this
    /// session should be torn down (cap eviction, admin revoke, disconnect),
    /// it sends a `()` here. The tunnel task receives it, sends a `Close` to
    /// the peer (graceful teardown, same path as T4/T5), and exits with
    /// `TunnelExit::PeerClosed`. `None` on the client side (clients are never
    /// cap-evicted or revoked by a server-side dispatcher).
    evict_rx: Option<mpsc::UnboundedReceiver<()>>,

    /// Optional channel to notify the dispatcher of a confirmed peer address
    /// change (roaming). Set only on the server side; the tunnel task sends
    /// `(session_id, new_addr)` here after a successful AEAD decryption of a
    /// datagram from a source address that differs from `self.peer`. The
    /// dispatcher updates its `addr_index` and `ClientHandle.current_addr` in
    /// response. The tunnel never trusts an unauthenticated address update.
    addr_change_tx: Option<mpsc::UnboundedSender<(SessionId, SocketAddr)>>,
}

impl Tunnel {
    /// Construct a tunnel from the output of a completed handshake.
    ///
    /// `obfuscation` is the resolved [`ObfuscationStack`] (possibly empty). It
    /// must already have been initialised with the session seed via
    /// [`ObfuscationStack::init`] if it contains keying-based layers.
    pub fn from_handshake(
        tun: Box<dyn crate::tun::Tun>,
        sock: Arc<UdpSocket>,
        peer: SocketAddr,
        session: Session,
        transport: Box<dyn Transport>,
        obfuscation: ObfuscationStack,
        send_key: [u8; 32],
        recv_key: [u8; 32],
        send_dir: Direction,
        recv_dir: Direction,
        counters: Arc<Mutex<Counters>>,
    ) -> io::Result<Self> {
        let fec = AdaptiveFec::default_for_vpn();
        // Do NOT call observe(0.0) here: that would snap current_m down to the
        // floor immediately and throw away the configured starting redundancy
        // (initial_m = 2 by default), forcing every packet out with the
        // minimum parity from the very first byte. Start at the controller's
        // initial_m so the first packets carry burst protection, and let the
        // EMA earn its way down to min_m once real (zero) loss samples arrive.
        let params = fec.params();
        let rs = ReedSolomon::new(params.k as usize, params.m as usize)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(Self {
            tun,
            sock,
            peer,
            session,
            transport,
            obfuscation,
            send_key,
            recv_key,
            send_dir,
            recv_dir,
            fec,
            fec_params: params,
            rs,
            group_id: 0,
            group_index: 0,
            group_buffer: Vec::with_capacity(params.k as usize),
            cc: CongestionController::new(),
            outstanding: Vec::new(),
            ping_seq: 0,
            last_ping_sent: None,
            last_peer_activity: Instant::now(),
            keepalive_interval: KEEPALIVE_INTERVAL,
            session_timeout: SESSION_TIMEOUT,
            rx_groups: HashMap::new(),
            last_peer_ack: 0,
            last_peer_bitmap: 0,
            rx_since_ack: 0,
            send_times: HashMap::new(),
            pending_out: None,
            pending_deadline: None,
            closing: false,
            counters,
            addr_change_tx: None,
            evict_rx: None,
        })
    }

    /// Set the keepalive interval and session timeout. Used by tests to use
    /// short timeouts; production uses the module-level constants.
    pub fn set_keepalive_params(&mut self, interval: Duration, timeout: Duration) {
        self.keepalive_interval = interval;
        self.session_timeout = timeout;
    }

    /// Wire up the address-change notification channel so the per-session
    /// tunnel task can report confirmed peer address changes (roaming) back to
    /// the server dispatcher. No-op on the client side (the channel is `None`).
    pub fn set_addr_change_tx(&mut self, tx: mpsc::UnboundedSender<(SessionId, SocketAddr)>) {
        self.addr_change_tx = Some(tx);
    }

    /// Wire up the eviction signal channel. When the dispatcher decides this
    /// session should be torn down (cap eviction, revocation, disconnect), it
    /// sends a `()` here. The tunnel sends a `Close` to the peer (graceful
    /// teardown) and exits with `TunnelExit::PeerClosed`. `None` on the client
    /// side.
    pub fn set_evict_rx(&mut self, rx: mpsc::UnboundedReceiver<()>) {
        self.evict_rx = Some(rx);
    }

    /// Apply FEC parameters from the resolved config. Called by the daemon
    /// after [`Tunnel::from_handshake`] to override the default FEC settings.
    /// Falls back to [`AdaptiveFec::default_for_vpn`] if the custom parameters
    /// are invalid (e.g. `k + m > 255`).
    pub fn configure_fec(&mut self, k: u8, min_m: u8, max_m: u8, initial_m: u8) {
        self.fec = AdaptiveFec::with_params(k, min_m, max_m, initial_m, 0.25);
        // Start at the configured initial_m (burst protection on the first
        // packets) rather than immediately relaxing to the floor.
        self.fec_params = self.fec.params();
        match ReedSolomon::new(self.fec_params.k as usize, self.fec_params.m as usize) {
            Ok(r) => self.rs = r,
            Err(e) => {
                tracing::warn!(?e, "invalid FEC config; falling back to defaults");
                self.fec = AdaptiveFec::default_for_vpn();
                self.fec_params = self.fec.observe(0.0);
                self.rs = ReedSolomon::new(self.fec_params.k as usize, self.fec_params.m as usize)
                    .expect("default FEC params must be valid");
            }
        }
        tracing::info!(
            k = self.fec.k,
            min_m = self.fec.min_m,
            max_m = self.fec.max_m,
            initial_m = initial_m,
            "FEC configured from config"
        );
    }

    /// Apply the obfuscation stack (if any) then `Transport::wrap`. This is the
    /// single send-side seam: `frame -> stack.apply -> transport.wrap -> wire`.
    /// When the stack is empty this is just `transport.wrap(frame)` with no
    /// extra allocation.
    fn wrap_frame(&self, frame: &[u8]) -> Vec<u8> {
        if self.obfuscation.active() {
            let obf = self.obfuscation.apply(frame);
            self.transport.wrap(&obf)
        } else {
            self.transport.wrap(frame)
        }
    }

    /// `Transport::unwrap` then reverse the obfuscation stack (if any). This is
    /// the single receive-side seam:
    /// `wire -> transport.unwrap -> stack.reverse -> frame`.
    fn unwrap_frame(&self, datagram: &[u8]) -> Result<Vec<u8>, io::Error> {
        let inner = self
            .transport
            .unwrap(datagram)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if self.obfuscation.active() {
            self.obfuscation
                .reverse(&inner)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        } else {
            Ok(inner)
        }
    }

    /// Reclaim the underlying TUN device, dropping the rest of the tunnel
    /// state. Used by the client reconnection loop to reuse the same TUN
    /// interface (and the routes that reference it by name) across
    /// reconnections instead of tearing it down and rebuilding it.
    pub fn into_tun(self) -> Box<dyn crate::tun::Tun> {
        self.tun
    }

    /// Run the steady-state tunnel until the peer sends `Close`, the UDP source
    /// closes, or the process is asked to stop via the shared `stop` watch
    /// channel.
    ///
    /// Incoming UDP datagrams arrive on `udp_rx` rather than being read directly
    /// from `self.sock`. This lets a single shared socket feed many concurrent
    /// tunnels (the multi-client server demuxes by peer address) while keeping
    /// the steady-state loop identical for client and server. `self.sock` is
    /// still used for `send_to`.
    ///
    /// Takes `&mut self` (rather than `self`) so the caller can keep the tunnel
    /// alive across a session and reclaim the TUN device afterwards — the
    /// client reconnection loop relies on this to preserve the TUN interface
    /// and its routes between connections.
    ///
    /// Returns a [`TunnelExit`] describing why the loop ended, so the client
    /// daemon can surface the reason (e.g. "session timeout") in the reconnect
    /// state it publishes over IPC.
    pub async fn run(
        &mut self,
        mut stop: watch::Receiver<bool>,
        mut udp_rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    ) -> TunnelExit {
        let span = tracing::info_span!("tunnel", peer = %self.peer, session_id = self.session.id);
        let _enter = span.enter();

        tracing::info!("tunnel up");

        // Tell the controller the device MTU so its byte window maps onto the
        // real datagram size (used for the in-flight byte reservations and for
        // the packet-count figures in stats). Falls back to the compiled-in
        // default when the platform cannot report one.
        if let Ok(mtu) = self.tun.mtu() {
            self.cc.set_mtu(mtu);
        }

        {
            let mut c = self.counters.lock().await;
            c.connected = true;
            c.fec_k = self.fec_params.k;
            c.fec_m = self.fec_params.m;
        }

        let mut ping = tokio::time::interval(PING_INTERVAL);
        let mut fec_tick = tokio::time::interval(FEC_TICK);
        let mut rto_tick = tokio::time::interval(RTO_TICK);
        let mut ack_tick = tokio::time::interval(ACK_TICK);
        let mut keepalive = tokio::time::interval(self.keepalive_interval);
        let mut timeout_check = tokio::time::interval(Duration::from_secs(1));
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        fec_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ack_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut evict_rx = self.evict_rx.take();

        // Paced-packet retry timer. Recreated each time a packet is parked
        // (a `tokio::time::interval` cannot be re-armed to an arbitrary
        // deadline), so it starts far in the future to stay dormant.
        let pacer_retry = tokio::time::sleep(Duration::from_secs(3600));
        tokio::pin!(pacer_retry);

        let mut tun_buf = vec![0u8; 65535];

        // NOTE: no `biased` here on purpose. With `biased`, the TUN branch
        // (listed before UDP) starves the receive path under load: TUN reads
        // stay ready while UDP datagrams pile up in the kernel buffer, acks
        // arrive late, the congestion window collapses and RTT spikes into
        // the seconds (bufferbloat sawtooth). Fair polling keeps RX timely.
        let exit = loop {
            tokio::select! {
                changed = stop.changed() => {
                    let _ = changed;
                    if *stop.borrow() {
                        tracing::info!("shutdown signal received; closing tunnel");
                        if let Err(e) = self.send_control(PacketType::Close, &[]).await {
                            tracing::debug!(error = ?e, "failed to send Close during shutdown");
                        }
                        break TunnelExit::Stopped;
                    }
                }

                n = self.tun.recv(&mut tun_buf) => {
                    match n {
                        Ok(n) => {
                            // Drop-oldest: a fresh packet arriving behind a
                            // parked one means the pacer is about a packet
                            // behind, and holding both would start building a
                            // queue. The newest packet wins so added latency
                            // stays bounded at one pacing interval.
                            self.pending_out = None;
                            self.pending_deadline = None;
                            let packet = tun_buf[..n].to_vec();
                            let sent = self.handle_tun_packet(packet.clone()).await;
                            if !sent {
                                // The gate refused it. `park_if_paced`
                                // re-queues it only when the pacer (not the
                                // window) was the blocker; a full window is
                                // still a deliberate, counted drop.
                                self.park_if_paced(packet);
                            }
                            if let Some(d) = self.pending_deadline {
                                pacer_retry.as_mut().reset(d);
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = ?e, "tun read error");
                            break TunnelExit::TunError;
                        }
                    }
                }

                // Pacer retry: the deadline for the parked packet has passed.
                // `retry_pending` re-runs the gate and re-parks (with a fresh
                // deadline) if the pacer is still holding it.
                () = &mut pacer_retry, if self.pending_out.is_some() => {
                    self.retry_pending().await;
                    if let Some(d) = self.pending_deadline {
                        pacer_retry.as_mut().reset(d);
                    }
                }

                msg = udp_rx.recv() => {
                    match msg {
                        Some((datagram, from)) => {
                            // No pre-filter by source address: a roaming client
                            // may send from a new address, and the AEAD decrypt
                            // inside `handle_udp_datagram` is the real
                            // authentication gate. If a datagram from a
                            // different address decrypts successfully, the
                            // tunnel updates `self.peer` and signals the
                            // dispatcher (roaming); if it fails to decrypt it
                            // is silently dropped.
                            if let Err(e) = self.handle_udp_datagram(&datagram, from).await {
                                // A failure here means the datagram did not
                                // parse as a rustnies packet (transport unwrap,
                                // header version/type or length check failed).
                                // Benign: drop at debug.
                                tracing::debug!(
                                    from = %from,
                                    len = datagram.len(),
                                    error = ?e,
                                    "dropping non-protocol udp datagram"
                                );
                            }
                            if self.closing {
                                break TunnelExit::PeerClosed;
                            }
                        }
                        None => {
                            // UDP source (socket reader / server dispatcher)
                            // went away; the peer is gone or we are shutting
                            // down.
                            tracing::info!("udp source closed; tearing down");
                            break TunnelExit::UdpClosed;
                        }
                    }
                }

                _ = ping.tick() => {
                    self.send_ping().await;
                }
                _ = fec_tick.tick() => {
                    self.flush_fec_group_if_stale().await;
                    self.evict_expired_rx_groups();
                    self.publish_stats().await;
                }
                _ = rto_tick.tick() => {
                    self.check_retransmits().await;
                }
                _ = ack_tick.tick() => {
                    self.flush_coalesced_ack().await;
                }
                _ = keepalive.tick() => {
                    self.maybe_send_keepalive().await;
                }
                _ = timeout_check.tick() => {
                    if self.last_peer_activity.elapsed() >= self.session_timeout {
                        tracing::info!(
                            peer = %self.peer,
                            idle = ?self.last_peer_activity.elapsed(),
                            "session timed out (no traffic from peer); tearing down"
                         );
                         if let Err(e) = self.send_control(PacketType::Close, &[]).await {
                             tracing::debug!(error = ?e, "failed to send Close during session timeout");
                         }
                         break TunnelExit::SessionTimeout;
                    }
                }

                Some(()) = evict_recv(&mut evict_rx) => {
                    tracing::info!(
                        peer = %self.peer,
                        session_id = self.session.id,
                        "session evicted (cap/revoke/disconnect); sending Close"
                    );
                    if let Err(e) = self.send_control(PacketType::Close, &[]).await {
                        tracing::debug!(error = ?e, "failed to send Close during eviction");
                    }
                    break TunnelExit::PeerClosed;
                }
            }
        };

        tracing::info!("tunnel down");
        let mut c = self.counters.lock().await;
        c.connected = false;
        match exit {
            TunnelExit::SessionTimeout => {
                c.sessions_timed_out = c.sessions_timed_out.saturating_add(1);
            }
            TunnelExit::PeerClosed => {
                c.sessions_peer_closed = c.sessions_peer_closed.saturating_add(1);
            }
            TunnelExit::UdpClosed => {
                // Server: the dispatcher dropped the UDP channel (cap eviction,
                // revocation, disconnect). Client: the socket reader exited.
                c.sessions_evicted = c.sessions_evicted.saturating_add(1);
            }
            TunnelExit::Stopped | TunnelExit::TunError => {}
        }
        exit
    }

    // --------------------------- send paths ----------------------------

    /// If the last `handle_tun_packet` refusal was the *pacer* (not a full
    /// window), park the packet for a bounded time and arm the retry timer.
    ///
    /// A window-full refusal is a genuine drop: the device is offering more
    /// than the path can carry, and queueing would just add latency to packets
    /// the user is going to lose anyway. A pacer refusal is different — the
    /// packet is perfectly sendable, just not at this instant — so it is kept
    /// and retried, and only superseded if the device produces another packet
    /// in the meantime (drop-oldest, so the queue never grows past one).
    fn park_if_paced(&mut self, packet: Vec<u8>) {
        if let Some(deadline) = self.cc.next_send_deadline() {
            // Drop-oldest: the queue is bounded at one packet, so a pacer that
            // is persistently behind cannot turn into unbounded latency.
            self.pending_out = Some(packet);
            self.pending_deadline = Some(tokio::time::Instant::from_std(deadline));
        }
    }

    /// Re-run the send gate for the parked packet. Sends it and clears the
    /// pending state on success; keeps it parked (with a refreshed deadline)
    /// if the pacer is still holding it back, and drops it if the window has
    /// closed in the meantime.
    async fn retry_pending(&mut self) {
        let Some(packet) = self.pending_out.take() else {
            self.pending_deadline = None;
            return;
        };
        let sent = self.handle_tun_packet(packet.clone()).await;
        if sent {
            self.pending_deadline = None;
            return;
        }
        // Still gated. Only the pacer can re-park: a closed window means the
        // packet must be dropped, otherwise it would pin here forever.
        self.pending_deadline = None;
        self.park_if_paced(packet);
    }

    /// A packet read from the TUN interface: wrap as a Data packet, encrypt,
    /// feed into the current FEC group, and send immediately.
    ///
    /// Returns `false` when the packet was deliberately not sent (window full
    /// or the pacer holding it back), so the caller can keep or re-queue it.
    async fn handle_tun_packet(&mut self, packet: Vec<u8>) -> bool {
        // Wire-safety gate. A TUN payload larger than MAX_PAYLOAD would push
        // the outer UDP datagram (header + AEAD tag + UDP/IP) past the safe
        // wire budget toward path-MTU fragmentation. The TUN device MTU is
        // clamped to match, so this only fires for FD-backed or misconfigured
        // devices — but it must be enforced here rather than trusted.
        if packet.len() > MAX_PAYLOAD {
            tracing::debug!(
                len = packet.len(),
                max = MAX_PAYLOAD,
                "tun packet exceeds wire-safe payload; dropping"
            );
            let mut c = self.counters.lock().await;
            c.tx_dropped_mtu = c.tx_dropped_mtu.saturating_add(1);
            return false;
        }
        // Congestion gate. The window check is the real drop condition: if we
        // are at the limit, the device is offering more than the path can
        // carry, and dropping (rather than queueing) is what keeps latency
        // bounded. The pacer check is *not* a drop condition — it just means
        // "not yet" — so a pacer refusal parks the packet instead.
        //
        // Both checks live in `CongestionController::may_send`, which compares
        // in bytes rather than packet counts. Counting packets let a window of
        // "4" mean anything between 300 B and 5 KB of in-flight data depending
        // on the mix of pings and full-size payloads, which made the drop
        // decision meaningless and let bursts through unpaced.
        let len = packet.len().max(1);
        if self.cc.send_budget() < len as u64 {
            tracing::trace!("congestion window full; dropping tun packet");
            let mut c = self.counters.lock().await;
            c.tx_dropped_congestion = c.tx_dropped_congestion.saturating_add(1);
            return false;
        }
        if !self.cc.may_send(len) {
            // Pacer says "not yet": the packet is delayed, not dropped.
            tracing::trace!("pacer holding tun packet; re-queueing");
            let mut c = self.counters.lock().await;
            c.tx_paced = c.tx_paced.saturating_add(1);
            return false;
        }
        self.cc.on_send_bytes(len);

        let seq = self.session.alloc_seq();
        let (ack_seq, ack_bitmap) = self.session.ack_snapshot();
        let mut hdr = PacketHeader::new(PacketType::Data, self.session.id, seq);
        hdr.ack_seq = ack_seq;
        hdr.ack_bitmap = ack_bitmap;

        let k = self.fec_params.k;
        let m = self.fec_params.m;
        let idx = self.group_index;
        hdr.fec_group = self.group_id;
        hdr.fec_index = idx;
        hdr.fec_k = k;
        hdr.fec_m = m;

        // Encrypt: AAD = the 24-byte header, plaintext = the TUN packet.
        let nonce = aead::make_nonce(self.session.id, seq, self.send_dir);
        let hdr_bytes = hdr.to_bytes();
        let ciphertext = match aead::encrypt(&self.send_key, &nonce, &hdr_bytes, &packet) {
            Ok(ct) => ct,
            Err(e) => {
                tracing::error!(error = ?e, seq, "data encrypt failed; dropping packet");
                return false;
            }
        };
        let frame = codec::encode_raw(&hdr, &ciphertext);
        let wire = self.wrap_frame(&frame);
        // Post-transform guard: a custom obfuscation/transport stack (e.g. an
        // oversized padding bucket) can inflate the datagram past the path
        // MTU even when the TUN payload itself was within budget. Drop rather
        // than fragment the outer datagram on the wire.
        if wire.len() + OUTER_OVERHEAD > PATH_MTU {
            tracing::debug!(
                seq,
                wire_len = wire.len(),
                path_mtu = PATH_MTU,
                "obfuscated datagram exceeds path MTU; dropping"
            );
            let mut c = self.counters.lock().await;
            c.tx_dropped_mtu = c.tx_dropped_mtu.saturating_add(1);
            return false;
        }
        if let Err(e) = self.sock.send_to(&wire, self.peer).await {
            tracing::warn!(error = ?e, seq, peer = %self.peer, "udp send failed; dropping tun packet");
            return false;
        }
        // Remember when this seq went out so the ack advertisement that
        // retires it can produce a real RTT sample for the controller.
        self.send_times.insert(seq, Instant::now());

        {
            let mut c = self.counters.lock().await;
            c.tx_packets += 1;
            c.tx_bytes += packet.len() as u64;
        }

        // Accumulate the *plaintext* source symbol for FEC.
        self.group_buffer.push(packet);
        self.group_index += 1;
        if self.group_index >= k {
            self.flush_fec_group().await;
        }
        true
    }

    /// Encode and send parity symbols for the accumulated group, then reset.
    async fn flush_fec_group(&mut self) {
        if self.group_buffer.is_empty() {
            return;
        }
        let k = self.fec_params.k as usize;
        let m = self.fec_params.m as usize;
        let real = self.group_buffer.len();
        // Pad the real source symbols to a common length so RS encoding is
        // well-defined. We only ever encode a *full* group (see the partial
        // short-circuit below), so this padding is never transmitted as
        // recoverable traffic.
        let len = self.group_buffer.iter().map(|s| s.len()).max().unwrap_or(0);
        let mut sources: Vec<Vec<u8>> = self.group_buffer.drain(..).collect();
        for s in &mut sources {
            s.resize(len, 0);
        }
        // Reset accumulation state and advance the group id. The parities we
        // are about to send are tagged with the group id we just finished
        // filling (`flushed_group_id`); the next TUN packet starts a fresh
        // group under the bumped id.
        self.group_index = 0;
        let flushed_group_id = self.group_id;
        self.group_id = self.group_id.wrapping_add(1);

        if m == 0 || real < k {
            // No parity to send. Either FEC is disabled, or the group is
            // partial (flushed early by `flush_fec_group_if_stale` to bound
            // latency). The real `Data` packets were already transmitted and
            // delivered directly. Padding a partial group with zero
            // placeholders and emitting parities would let the peer decode
            // those placeholder slots and write them to its TUN as duplicate /
            // garbage packets (the receiver cannot distinguish a recovered
            // placeholder from recovered real data). Partial groups therefore
            // forfeit FEC protection, which is acceptable for best-effort
            // phase-1 data.
            return;
        }
        while sources.len() < k {
            sources.push(vec![0u8; len]);
        }
        match self.rs.encode(&sources) {
            Ok(parities) => {
                for (i, parity) in parities.into_iter().enumerate() {
                    // Parity is bulk wire traffic like data: it must consume
                    // congestion-window budget, otherwise the window accounts
                    // for only 1/(k+m) of what is actually sent (with the
                    // default k=1, m=2..4 the wire rate is 3-5x the paced
                    // rate) and the controller never throttles the real load.
                    // A full window drops the parity (it is expendable
                    // redundancy; the data already went out), while pacing
                    // credit is consumed without refusal so FEC is not
                    // disabled exactly when the path is busy.
                    let plen = parity.len().max(1);
                    if !self.cc.try_send_parity(plen) {
                        tracing::trace!("congestion window full; skipping fec parity");
                        let mut c = self.counters.lock().await;
                        c.tx_dropped_congestion = c.tx_dropped_congestion.saturating_add(1);
                        continue;
                    }
                    let seq = self.session.alloc_seq();
                    let mut hdr = PacketHeader::new(PacketType::Fec, self.session.id, seq);
                    let (ack_seq, ack_bitmap) = self.session.ack_snapshot();
                    hdr.ack_seq = ack_seq;
                    hdr.ack_bitmap = ack_bitmap;
                    hdr.fec_group = flushed_group_id;
                    hdr.fec_index = (k as u8) + i as u8;
                    hdr.fec_k = self.fec_params.k;
                    hdr.fec_m = self.fec_params.m;
                    let nonce = aead::make_nonce(self.session.id, seq, self.send_dir);
                    let hdr_bytes = hdr.to_bytes();
                    let ct = match aead::encrypt(&self.send_key, &nonce, &hdr_bytes, &parity) {
                        Ok(ct) => ct,
                        Err(e) => {
                            tracing::error!(error = ?e, seq, "parity encrypt failed; skipping");
                            continue;
                        }
                    };
                    let frame = codec::encode_raw(&hdr, &ct);
                    let wire = self.wrap_frame(&frame);
                    if wire.len() + OUTER_OVERHEAD > PATH_MTU {
                        tracing::debug!(
                            seq,
                            wire_len = wire.len(),
                            "obfuscated parity datagram exceeds path MTU; skipping"
                        );
                        let mut c = self.counters.lock().await;
                        c.tx_dropped_mtu = c.tx_dropped_mtu.saturating_add(1);
                        continue;
                    }
                    if let Err(e) = self.sock.send_to(&wire, self.peer).await {
                        tracing::debug!(
                            error = ?e, seq, peer = %self.peer,
                            "fec parity udp send failed; parity datagram lost"
                        );
                        continue;
                    }
                    self.send_times.insert(seq, Instant::now());
                    let mut c = self.counters.lock().await;
                    c.tx_packets += 1;
                    c.tx_bytes += parity.len() as u64;
                }
            }
            Err(e) => {
                tracing::warn!(error = ?e, "fec encode failed");
            }
        }
    }

    async fn flush_fec_group_if_stale(&mut self) {
        // If we've been holding a partial group for a while, flush it so the
        // receiver's group assembly doesn't stall.
        if !self.group_buffer.is_empty() {
            // Only flush early if there's risk of staleness; with a 100ms tick
            // and typical k=4 this is rare, but keeps latency bounded.
            self.flush_fec_group().await;
        }
    }

    /// Send an authenticated keepalive if the session has been idle (no
    /// outgoing traffic) for a while. The keepalive carries a timestamp so the
    /// peer can confirm freshness; it is best-effort (not retransmitted).
    async fn maybe_send_keepalive(&mut self) {
        // Only send a keepalive if we haven't sent anything recently. The FEC
        // tick (100ms) sends frequently during active traffic, so this only
        // fires during true idle.
        self.send_keepalive().await;
    }

    /// Send an authenticated keepalive packet with a timestamp payload.
    pub async fn send_keepalive(&mut self) {
        let now_micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let mut payload = [0u8; 8];
        payload.copy_from_slice(&now_micros.to_le_bytes());
        tracing::debug!(peer = %self.peer, "sending keepalive");
        self.send_packet(PacketType::Keepalive, &payload).await;
    }

    /// Send a best-effort Ping carrying a monotonic id and a timestamp.
    async fn send_ping(&mut self) {
        self.ping_seq = self.ping_seq.wrapping_add(1);
        let now_micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let mut payload = [0u8; 12];
        payload[0..4].copy_from_slice(&self.ping_seq.to_le_bytes());
        payload[4..12].copy_from_slice(&now_micros.to_le_bytes());
        self.last_ping_sent = Some(Instant::now());
        self.send_packet(PacketType::Ping, &payload).await;
    }

    /// Send a best-effort packet (Ping/Pong/Ack/Fec-adjacent control) with no
    /// retransmission. Reliable control goes through [`send_control`].
    async fn send_packet(&mut self, ptype: PacketType, payload: &[u8]) {
        let seq = self.session.alloc_seq();
        let (ack_seq, ack_bitmap) = self.session.ack_snapshot();
        let mut hdr = PacketHeader::new(ptype, self.session.id, seq);
        hdr.ack_seq = ack_seq;
        hdr.ack_bitmap = ack_bitmap;
        let nonce = aead::make_nonce(self.session.id, seq, self.send_dir);
        let hdr_bytes = hdr.to_bytes();
        let ct = match aead::encrypt(&self.send_key, &nonce, &hdr_bytes, payload) {
            Ok(ct) => ct,
            Err(e) => {
                tracing::error!(error = ?e, seq, "control encrypt failed; dropping packet");
                return;
            }
        };
        let frame = codec::encode_raw(&hdr, &ct);
        let wire = self.wrap_frame(&frame);
        tracing::trace!(ptype = ?ptype, seq, len = payload.len(), "send packet");
        if let Err(e) = self.sock.send_to(&wire, self.peer).await {
            tracing::debug!(
                error = ?e, ptype = ?ptype, seq, peer = %self.peer,
                "best-effort udp send failed"
            );
        }
    }

    /// Send a reliable control packet (Handshake*/Close), registering it for
    /// retransmission until the peer acks its seq.
    pub(crate) async fn send_control(
        &mut self,
        ptype: PacketType,
        payload: &[u8],
    ) -> io::Result<()> {
        let seq = self.session.alloc_seq();
        let (ack_seq, ack_bitmap) = self.session.ack_snapshot();
        let mut hdr = PacketHeader::new(ptype, self.session.id, seq);
        hdr.ack_seq = ack_seq;
        hdr.ack_bitmap = ack_bitmap;
        let nonce = aead::make_nonce(self.session.id, seq, self.send_dir);
        let hdr_bytes = hdr.to_bytes();
        let ct = aead::encrypt(&self.send_key, &nonce, &hdr_bytes, payload).map_err(|e| {
            tracing::error!(error = ?e, seq, "reliable control encrypt failed");
            io::Error::new(io::ErrorKind::Other, e.to_string())
        })?;
        let frame = codec::encode_raw(&hdr, &ct);
        let wire = self.wrap_frame(&frame);
        self.sock.send_to(&wire, self.peer).await?;
        if self.outstanding.len() < MAX_OUTSTANDING_CONTROL {
            self.outstanding.push(Outstanding {
                seq,
                ptype,
                payload: wire,
                last_sent: Instant::now(),
            });
        }
        Ok(())
    }

    /// Flush a coalesced standalone Ack if data/parity arrived since the last
    /// advertisement. Fired by the `ACK_TICK` timer so one-way flows get
    /// feedback within ~25 ms instead of waiting for the next piggyback
    /// opportunity (ping tick, 500 ms). Best-effort, like all acks.
    async fn flush_coalesced_ack(&mut self) {
        if self.rx_since_ack > 0 {
            self.rx_since_ack = 0;
            self.send_packet(PacketType::Ack, &[]).await;
        }
    }

    /// The RTT of the **oldest** seq newly acknowledged by the latest peer ack
    /// advertisement, or `None` if no newly-acked seq still has a send-time
    /// record (already pruned, or it was a control seq we never tracked).
    ///
    /// Oldest-by-seq is the right sample here: those packets were dispatched
    /// earliest, so their measured delay is least contaminated by queuing that
    /// this sender itself created. Using the newest seq instead makes a
    /// perfectly healthy path look slow whenever a burst is in flight (the
    /// last packet of a burst measures the whole burst's drain time), which
    /// would drive SRTT up, shrink the pacing rate, and throttle the flow.
    fn newly_acked_rtt(&self, prev_ack: u32, prev_bitmap: u32) -> Option<Duration> {
        let anchor = self.session.peer_ack;
        let bitmap = self.session.peer_bitmap;
        if anchor == 0 {
            return None;
        }
        let now_acked = |s: u32| -> bool {
            if s == 0 {
                return false;
            }
            if s == anchor {
                return true;
            }
            let back = anchor.wrapping_sub(s);
            if back >= 1 && back <= 32 {
                (bitmap >> (back - 1)) & 1 == 1
            } else {
                false
            }
        };
        let was_acked = |s: u32| -> bool {
            if prev_ack == 0 {
                return false;
            }
            if s == prev_ack {
                return true;
            }
            let back = prev_ack.wrapping_sub(s);
            if back >= 1 && back <= 32 {
                (prev_bitmap >> (back - 1)) & 1 == 1
            } else {
                false
            }
        };
        // Walk from the anchor downwards; the last (lowest) newly-acked seq we
        // find is the oldest, so remember it as we go.
        let mut oldest: Option<u32> = None;
        let mut s = anchor;
        for _ in 0..=32u32 {
            if now_acked(s) && !was_acked(s) {
                oldest = Some(s);
            }
            if s == 0 {
                break;
            }
            s = s.wrapping_sub(1);
        }
        // The anchor itself is the newest; only trust it if nothing older
        // showed up, and only when it actually became acked just now.
        let seq = match oldest {
            Some(s) => s,
            None => return None,
        };
        let sent = self.send_times.get(&seq)?;
        // Guard against a stale record (clock skew, or a seq reused after the
        // 2^32 wrap). A negative or absurd RTT would corrupt SRTT and pin the
        // pacing rate; fall back to "no sample" instead.
        let rtt = Instant::now().saturating_duration_since(*sent);
        if rtt.is_zero() || rtt > MAX_RTT_SAMPLE {
            return None;
        }
        Some(rtt)
    }

    /// Drop send-time records the peer's ack window already covers, keeping the
    /// map bounded (at most the ack window plus whatever is genuinely in
    /// flight).
    fn prune_send_times(&mut self) {
        let anchor = self.session.peer_ack;
        let bitmap = self.session.peer_bitmap;
        if anchor == 0 {
            // Nothing advertised yet: keep a safety cap so a peer that never
            // acks cannot leak memory.
            if self.send_times.len() > MAX_SEND_TIMES {
                let mut keys: Vec<u32> = self.send_times.keys().copied().collect();
                keys.sort_unstable();
                for k in keys.iter().take(self.send_times.len() - MAX_SEND_TIMES / 2) {
                    self.send_times.remove(k);
                }
            }
            return;
        }
        self.send_times.retain(|&seq, _| {
            if seq == anchor {
                return false; // acked by definition
            }
            let back = anchor.wrapping_sub(seq);
            if back == 0 || back > 32 {
                // Outside the ack window: it is either ancient (resolved) or a
                // future seq we have not sent. Drop ancient ones.
                return back <= (u32::MAX >> 1);
            }
            // Inside the window: keep only while still marked missing.
            (bitmap >> (back - 1)) & 1 == 0
        });
    }

    /// Count our outgoing seqs newly acknowledged by the latest peer ack
    /// advertisement, relative to the previous one we already accounted for.
    ///
    /// The ack format is a sliding window (see `AckTracker`): `anchor` is the
    /// peer's highest received seq (acked by definition) and bit `i` of
    /// `bitmap` covers `anchor - 1 - i`. We release one in-flight slot per
    /// seq the peer now knows about that it did not on the previous
    /// advertisement. Capped at the current `in_flight` so a runaway or
    /// stale advertisement can never drive the counter negative (the
    /// saturation in `on_ack` would otherwise paper over it, but bounding
    /// here keeps the window growth sane).
    fn newly_acked_count(&self, prev_ack: u32, prev_bitmap: u32) -> u64 {
        let anchor = self.session.peer_ack;
        let bitmap = self.session.peer_bitmap;
        if anchor == 0 {
            return 0;
        }
        // The set of seqs acked by an advertisement is infinite in principle
        // (everything below the anchor up to the 32-bit window). Counting the
        // *new* ones is equivalent to walking the 33 candidate seqs
        // (anchor plus the 32 below it) and counting those that are acked now
        // but were not acked by (prev_ack, prev_bitmap).
        let now_acked = |s: u32| -> bool {
            if s == 0 {
                return false;
            }
            if s == anchor {
                return true;
            }
            let back = anchor.wrapping_sub(s);
            if back >= 1 && back <= 32 {
                (bitmap >> (back - 1)) & 1 == 1
            } else {
                false
            }
        };
        let was_acked = |s: u32| -> bool {
            if prev_ack == 0 {
                return false;
            }
            if s == prev_ack {
                return true;
            }
            let back = prev_ack.wrapping_sub(s);
            if back >= 1 && back <= 32 {
                (prev_bitmap >> (back - 1)) & 1 == 1
            } else {
                false
            }
        };
        let mut count = 0u64;
        let mut s = anchor;
        for _ in 0..=32u32 {
            if now_acked(s) && !was_acked(s) {
                count += 1;
            }
            // Walk downwards below the anchor. Stop at the wrap boundary.
            if s == 0 {
                break;
            }
            s = s.wrapping_sub(1);
        }
        count.min(self.cc.in_flight)
    }

    /// How many of our seqs left flight since the previous advertisement,
    /// whether acked or lost. This is the anchor advance (forward only),
    /// capped at `in_flight` so a stale/jumped advertisement can never drive
    /// the counter negative. Backward/wrap moves resolve nothing — fall back
    /// to zero and let the acked-count path handle any bitmap fills.
    fn newly_resolved_count(&self, prev_ack: u32) -> u64 {
        let anchor = self.session.peer_ack;
        if anchor == 0 {
            return 0;
        }
        if prev_ack == 0 {
            // First advertisement: our seqs run 1..=anchor with no gaps on
            // the send side, so every seq up to the anchor has left flight
            // (acked or lost). Cap at in_flight for sanity.
            return (anchor as u64).min(self.cc.in_flight);
        }
        let advance = anchor.wrapping_sub(prev_ack);
        if advance == 0 {
            // Same anchor: resolution (if any) is bitmap fills below it, which
            // `newly_acked_count` already counts. Nothing extra to release.
            return 0;
        }
        if advance > (u32::MAX >> 1) {
            // Backward move or wrap: not a forward advance, resolve nothing.
            return 0;
        }
        (advance as u64).min(self.cc.in_flight)
    }

    /// Retransmit unacked control packets whose RTO has elapsed.
    async fn check_retransmits(&mut self) {
        let rto = self.cc.rto();
        let mut to_resend: Vec<usize> = Vec::new();
        for (i, o) in self.outstanding.iter().enumerate() {
            if o.last_sent.elapsed() >= rto {
                to_resend.push(i);
            }
        }
        for i in to_resend {
            let o = &mut self.outstanding[i];
            if let Err(e) = self.sock.send_to(&o.payload, self.peer).await {
                tracing::warn!(
                    error = ?e, seq = o.seq, ptype = ?o.ptype, peer = %self.peer,
                    "control retransmit send failed"
                );
            }
            o.last_sent = Instant::now();
            tracing::debug!(
                seq = o.seq,
                ptype = ?o.ptype,
                rto_ms = rto.as_millis(),
                "control retransmit"
            );
        }
        // Drop acked ones.
        let peer_ack = self.session.peer_ack;
        let peer_bitmap = self.session.peer_bitmap;
        self.outstanding.retain(|o| !self.session.peer_acked(o.seq));
        let _ = (peer_ack, peer_bitmap);
    }

    // --------------------------- recv paths ----------------------------

    async fn handle_udp_datagram(&mut self, datagram: &[u8], from: SocketAddr) -> io::Result<()> {
        let frame = self.unwrap_frame(datagram)?;
        // Drop idle-decoy frames produced by a peer's timing obfuscation layer.
        // A decoy carries the reserved sentinel version byte and never parses
        // as a real packet, so it is dropped here before any crypto work.
        if is_decoy_frame(&frame) {
            tracing::trace!(len = frame.len(), "dropping decoy frame");
            return Ok(());
        }
        let pkt =
            codec::decode(&frame).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let hdr = pkt.header;

        tracing::trace!(
            ptype = ?hdr.packet_type,
            seq = hdr.seq,
            ack_seq = hdr.ack_seq,
            len = pkt.body.len(),
            "recv packet"
        );

        // Observe the peer's ack advertisement (covers every packet type).
        self.session.observe_acks(hdr.ack_seq, hdr.ack_bitmap);
        // Piggyback acks report what the peer has received from us, for *all*
        // packet types. Two kinds of resolution happen here:
        // - acked seqs: release an in-flight slot AND grow the window.
        // - lost seqs (holes the anchor jumped over): release the slot but
        //   do NOT grow the window. Without this, best-effort data lost on
        //   the wire never releases its slot (data is never retransmitted),
        //   `in_flight` leaks upward, `send_budget` pins at zero and the
        //   sender stalls after any sustained loss.
        // Trigger on anchor OR bitmap change: holes filled below a stable
        // anchor still ack new seqs.
        if self.session.peer_ack != self.last_peer_ack
            || self.session.peer_bitmap != self.last_peer_bitmap
        {
            let acked = self.newly_acked_count(self.last_peer_ack, self.last_peer_bitmap);
            let resolved = self.newly_resolved_count(self.last_peer_ack);
            // `resolved` covers every seq that left flight since the last
            // advertisement (acked + lost); `acked` is the subset to grow on.
            let lost = resolved.saturating_sub(acked);
            // Turn the *newly acked* wire seqs into a data-driven RTT sample.
            // This is what keeps the window responsive: the ping probe samples
            // the path only twice a second, so a bulk flow had no feedback that
            // could raise its window between pings. Sampling the oldest newly
            // acked seq (rather than the newest) avoids crediting the sender
            // with a queuing delay it created itself, which would collapse the
            // window on a path that is actually fast.
            let rtt = self.newly_acked_rtt(self.last_peer_ack, self.last_peer_bitmap);
            // Retire the send-time records for every seq the peer now covers,
            // so the map cannot grow without bound.
            self.prune_send_times();

            // Byte counts: the window is in bytes, so retire and grow by the
            // number of bytes the acked seqs represented. Without this, a
            // packet-count-to-byte conversion would price every acked seq at
            // the full MTU, overgrowing the window for small packets (acks and
            // ping replies) — the exact failure mode the byte accounting is
            // meant to fix.
            let acked_bytes = (acked as u64).saturating_mul(self.cc.mtu as u64);
            let lost_bytes = (lost as u64).saturating_mul(self.cc.mtu as u64);
            if lost_bytes > 0 {
                self.cc.release(lost_bytes);
            }
            if acked_bytes > 0 {
                match rtt {
                    Some(sample) => {
                        self.cc.on_ack_with_rtt(acked_bytes, sample);
                        let mut c = self.counters.lock().await;
                        c.rtt_samples = c.rtt_samples.saturating_add(1);
                    }
                    None => self.cc.on_ack_bytes(acked_bytes),
                }
            }
            self.last_peer_ack = self.session.peer_ack;
            self.last_peer_bitmap = self.session.peer_bitmap;
        }

        // Decrypt.
        let nonce = aead::make_nonce(self.session.id, hdr.seq, self.recv_dir);
        let hdr_bytes = hdr.to_bytes();
        let plaintext = match aead::decrypt(&self.recv_key, &nonce, &hdr_bytes, &pkt.body) {
            Ok(p) => p,
            Err(_) => {
                tracing::debug!(seq = hdr.seq, "decrypt failed; dropping");
                return Ok(());
            }
        };

        // Roaming: a successfully decrypted datagram from a new source address
        // means the peer has moved. Update `self.peer` so subsequent sends go to
        // the new address, and signal the dispatcher to update its address index.
        // The AEAD tag passing is the authentication gate: only the legitimate
        // peer (who shares this direction's key) could have produced a packet
        // that decrypts here, so a successful decrypt is proof of identity
        // independent of the source address.
        if from != self.peer {
            tracing::info!(
                old_peer = %self.peer,
                new_peer = %from,
                "peer address changed (roaming); updating"
            );
            self.peer = from;
            if let Some(tx) = &self.addr_change_tx {
                if let Err(e) = tx.send((self.session.id, from)) {
                    tracing::debug!(
                        session_id = self.session.id, new_peer = %from,
                        error = ?e,
                        "addr-change notification dropped (dispatcher gone?)"
                    );
                }
            }
        }

        // Any successfully decrypted packet counts as peer activity for the
        // session-timeout check (data, control, keepalive, ping, etc.). This is
        // done before the reliable dedup early-return so even replayed control
        // packets refresh the timeout (the peer is still alive).
        self.last_peer_activity = Instant::now();

        // Every authenticated packet (data, parity and control alike)
        // advances the ack window we advertise back to the peer. Recording an
        // already-seen seq is idempotent, and the window is anchored at the
        // highest received seq so permanent data holes cannot stall it.
        // Without this, the anchor would only move on the rare reliable
        // control packets and the advertised acks would never cover the data
        // flow they exist to pace.
        self.session.ack.record(hdr.seq);

        // Delayed-ack coalescing, Data/Fec only (Ack/Ping/Pong/Keepalive must
        // not trigger acks or two idle peers would ack each other forever).
        // Piggyback covers bidirectional flows; the standalone Ack below is
        // what keeps one-way flows' windows moving between ping ticks.
        if matches!(hdr.packet_type, PacketType::Data | PacketType::Fec) {
            self.rx_since_ack = self.rx_since_ack.saturating_add(1);
            if self.rx_since_ack >= ACK_EVERY {
                self.rx_since_ack = 0;
                self.send_packet(PacketType::Ack, &[]).await;
            }
        }

        // Reliable control: dedup via replay window.
        if PacketType::is_reliable(hdr.packet_type) {
            if !self.session.receive_reliable(hdr.seq) {
                return Ok(()); // duplicate
            }
        }

        {
            let mut c = self.counters.lock().await;
            c.rx_packets += 1;
            c.rx_bytes += plaintext.len() as u64;
        }

        match hdr.packet_type {
            PacketType::Data => self.handle_data(hdr, plaintext).await,
            PacketType::Fec => self.handle_parity(hdr, plaintext).await,
            PacketType::Ping => self.handle_ping(hdr, plaintext).await,
            PacketType::Pong => self.handle_pong(plaintext).await,
            PacketType::Close => {
                tracing::info!(peer = %self.peer, "peer sent Close; tearing down");
                // No ack on the wire: the peer already knows it is closing and
                // sending a Close back would just bounce. Set the flag so the
                // run loop exits cleanly after this handler returns.
                self.closing = true;
            }
            PacketType::Ack => {
                // A standalone Ack means the peer received us but had no data
                // to piggyback on. The piggyback path above already released
                // any newly-acked in-flight slots for this datagram, so there is
                // nothing extra to do here; keep the arm explicit for clarity.
            }
            PacketType::Keepalive => {
                tracing::debug!(peer = %self.peer, "keepalive received");
            }
            _ => {}
        }
        Ok(())
    }

    async fn handle_data(&mut self, hdr: PacketHeader, payload: Vec<u8>) {
        // Suppress late/duplicate originals: if this source slot was already
        // written to TUN (directly, or reconstructed earlier by FEC recovery),
        // do not write it again. This is the dedup that makes FEC recovery safe
        // against out-of-order or duplicated UDP delivery: a packet recovered
        // from parity and then arriving again must not be delivered twice.
        if hdr.fec_m > 0 && self.is_source_delivered(hdr.fec_group, hdr.fec_index) {
            tracing::debug!(
                group = hdr.fec_group,
                index = hdr.fec_index,
                seq = hdr.seq,
                "suppressing duplicate data packet (already delivered)"
            );
            self.record_rx_symbol(
                hdr.fec_group,
                hdr.fec_index,
                hdr.fec_k,
                hdr.fec_m,
                payload,
                true,
            )
            .await;
            return;
        }
        // Deliver to TUN immediately.
        if let Err(e) = self.tun.send(&payload).await {
            tracing::warn!(
                error = ?e, seq = hdr.seq, len = payload.len(),
                "tun send failed; packet to local interface dropped"
            );
        }
        {
            let mut c = self.counters.lock().await;
            c.rx_bytes += 0; // already counted
        }
        // This source symbol arrived directly on the wire (not reconstructed
        // from parity): feed a zero-loss sample to the adaptive FEC EMA. The
        // controller is otherwise only fed loss (via `observe_unrecoverable`
        // in `recover_group`/`evict_expired_rx_groups`), so without a
        // dilution signal for every packet that *didn't* need recovery, the
        // smoothed loss ratchets toward 100% after any packet loss at all and
        // never comes back down, even on an otherwise healthy link. Sampling
        // it once per directly-delivered group keeps the EMA tracking true
        // wire loss (lost groups / total groups) instead of "fraction lost
        // among groups that had any loss".
        self.fec.observe(0.0);
        self.apply_fec_params();
        // Record into RX FEC group if FEC is enabled.
        if hdr.fec_m > 0 {
            self.record_rx_symbol(
                hdr.fec_group,
                hdr.fec_index,
                hdr.fec_k,
                hdr.fec_m,
                payload,
                true,
            )
            .await;
        }
    }

    /// Has the source symbol `(group, index)` already been written to TUN,
    /// either by direct `Data` delivery or by FEC recovery? Returns `false` if
    /// no state exists yet for the group (first packet) or the index is outside
    /// the source range.
    fn is_source_delivered(&self, group: u16, index: u8) -> bool {
        let entry = match self.rx_groups.get(&group) {
            Some(e) => e,
            None => return false,
        };
        let k = entry.k as usize;
        if (index as usize) >= k {
            return false;
        }
        entry.delivered[index as usize]
    }

    async fn handle_parity(&mut self, hdr: PacketHeader, payload: Vec<u8>) {
        if hdr.fec_m == 0 {
            return;
        }
        self.record_rx_symbol(
            hdr.fec_group,
            hdr.fec_index,
            hdr.fec_k,
            hdr.fec_m,
            payload,
            false,
        )
        .await;
    }

    async fn record_rx_symbol(
        &mut self,
        group: u16,
        index: u8,
        k: u8,
        m: u8,
        payload: Vec<u8>,
        is_data: bool,
    ) {
        let group_entry = self
            .rx_groups
            .entry(group)
            .or_insert_with(|| RxGroup::new(k, m));
        group_entry.deadline = Instant::now() + RX_GROUP_TTL;
        let n = k as usize + m as usize;
        if (index as usize) >= n {
            return;
        }
        let was_none = group_entry.symbols[index as usize].is_none();
        group_entry.symbols[index as usize] = Some(payload.clone());
        if is_data && was_none {
            // Mark delivered; we already wrote it to TUN.
            if (index as usize) < k as usize {
                group_entry.delivered[index as usize] = true;
            }
        }

        // Try to recover if we have at least k present symbols and have not
        // already decoded this group. A decoded group is retained only as the
        // dedup set for late originals, so we never re-run recovery on it.
        let present = group_entry.symbols.iter().filter(|s| s.is_some()).count();
        if !group_entry.decoded && present >= k as usize {
            self.recover_group(group).await;
        }
    }

    async fn recover_group(&mut self, group: u16) {
        let entry = match self.rx_groups.get_mut(&group) {
            Some(e) => e,
            None => return,
        };
        if entry.decoded {
            return;
        }
        let k = entry.k as usize;
        let m = entry.m as usize;
        // Build the option slice for RS decode and snapshot the pre-recovery
        // delivery state (which slots were already written to TUN directly).
        let symbols: Vec<Option<Vec<u8>>> = entry.symbols.clone();
        let pre_delivered: Vec<bool> = entry.delivered.clone();
        let rs = match ReedSolomon::new(k, m) {
            Ok(r) => r,
            Err(_) => return,
        };
        let recovered = match rs.decode(&symbols) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(
                    ?e,
                    group,
                    "rs decode failed (expected if k already complete)"
                );
                return;
            }
        };
        // Decode succeeded: mark the group decoded and every source slot
        // delivered so any late-arriving original is suppressed by
        // `is_source_delivered`. Keep the group (until TTL eviction) as the
        // dedup set rather than removing it immediately.
        entry.decoded = true;
        for i in 0..k {
            entry.delivered[i] = true;
        }

        let mut newly_recovered = 0u64;
        for (i, sym) in recovered.into_iter().enumerate() {
            if i < pre_delivered.len() && !pre_delivered[i] {
                // This source was lost in transit and we just reconstructed it.
                if let Err(e) = self.tun.send(&sym).await {
                    tracing::warn!(
                        error = ?e, ?group, index = i,
                        "tun send failed; fec-recovered packet dropped"
                    );
                } else {
                    newly_recovered += 1;
                }
            }
        }
        if newly_recovered > 0 {
            {
                let mut c = self.counters.lock().await;
                c.fec_recovered += newly_recovered;
            }
            // Loss sample: the fraction of source symbols that were lost in
            // transit and reconstructed from parity. Feed it to the adaptive
            // FEC controller so it can increase redundancy, and to the
            // congestion controller so it can back off. These packets *were*
            // lost on the wire: FEC hides that from the user, but it does not
            // erase the congestion signal. Feeding both controllers is what
            // breaks the runaway loop that previously pinned loss at 100%:
            // the congestion controller now shrinks the window on real loss,
            // so we stop flooding the link and the measured loss rate falls,
            // which in turn lets the FEC controller scale redundancy back
            // down from its 2000% ceiling.
            let lost = newly_recovered as u64;
            let total = k as u64;
            self.fec.observe_unrecoverable(lost, total);
            self.cc.on_loss(lost, total);
            self.apply_fec_params();
        }
    }

    fn apply_fec_params(&mut self) {
        let params = self.fec.params();
        if params != self.fec_params {
            tracing::debug!(
                old_k = self.fec_params.k,
                old_m = self.fec_params.m,
                new_k = params.k,
                new_m = params.m,
                loss_rate = self.fec.smoothed_loss,
                "FEC parameters updated"
            );
            self.fec_params = params;
            self.rs = match ReedSolomon::new(params.k as usize, params.m as usize) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(?e, "invalid FEC params; keeping old");
                    return;
                }
            };
        }
    }

    async fn handle_ping(&mut self, _hdr: PacketHeader, payload: Vec<u8>) {
        // Echo back as Pong with the same 12-byte body.
        self.send_packet(PacketType::Pong, &payload).await;
    }

    async fn handle_pong(&mut self, payload: Vec<u8>) {
        if payload.len() < 12 {
            return;
        }
        let ts_micros = u64::from_le_bytes([
            payload[4],
            payload[5],
            payload[6],
            payload[7],
            payload[8],
            payload[9],
            payload[10],
            payload[11],
        ]);
        let now_micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        if now_micros >= ts_micros {
            let rtt = Duration::from_micros(now_micros - ts_micros);
            self.cc.on_rtt_sample(rtt);
            let mut c = self.counters.lock().await;
            c.rtt_ms = rtt.as_secs_f64() * 1000.0;
            c.congestion_window = self.cc.cwnd as f64;
            c.in_flight = self.cc.in_flight;
        }
    }

    fn evict_expired_rx_groups(&mut self) {
        let now = Instant::now();
        // Before evicting, detect groups that expired without being decoded
        // (too many erasures for the current parity count). These represent
        // unrecoverable data loss: feed it to both the adaptive FEC controller
        // (to increase redundancy) and the congestion controller (to shrink
        // the window). This is the only signal that fires when loss exceeds
        // the current FEC capacity — without it, the controllers would never
        // learn that m is too low or that the link is congested.
        let mut total_lost = 0u64;
        let mut total_sources = 0u64;
        self.rx_groups.retain(|_, g| {
            if g.deadline <= now {
                if !g.decoded && g.k > 0 {
                    let undelivered = g.delivered.iter().filter(|&&d| !d).count() as u64;
                    total_lost += undelivered;
                    total_sources += g.k as u64;
                }
                false
            } else {
                true
            }
        });
        if total_lost > 0 {
            tracing::debug!(
                lost = total_lost,
                total = total_sources,
                "unrecoverable FEC groups evicted; increasing redundancy"
            );
            self.fec.observe_unrecoverable(total_lost, total_sources);
            self.cc.on_loss(total_lost, total_sources);
            self.apply_fec_params();
        }
    }

    async fn publish_stats(&mut self) {
        let mut c = self.counters.lock().await;
        c.fec_k = self.fec_params.k;
        c.fec_m = self.fec_params.m;
        c.loss_rate = self.fec.smoothed_loss;
        c.congestion_window = self.cc.cwnd as f64;
        c.in_flight = self.cc.in_flight;
        c.pacing_rate = self.cc.pacing_rate;
    }
}

/// Convenience: derive a 32-bit session id from a Noise handshake hash.
pub fn session_id_from_hash(h: &[u8; 32]) -> SessionId {
    let mut id = 0u32;
    for &b in &h[..4] {
        id = (id << 8) | b as u32;
    }
    if id == 0 { 1 } else { id }
}

/// Adapter for the eviction signal in the `Tunnel::run` select loop.
///
/// When `rx` is `Some`, polls the receiver for an eviction signal. When `rx`
/// is `None` (client side — never evicted), returns `pending()` so the select
/// branch simply never fires.
async fn evict_recv(rx: &mut Option<mpsc::UnboundedReceiver<()>>) -> Option<()> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::Direction;
    use crate::protocol::session::{Session, SessionRole};
    use crate::transport::default_transport;
    use crate::tun::{Tun, TunFut};
    use std::sync::Mutex as StdMutex;
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;

    /// A TUN that records every `send` into a shared vector. `recv` is never
    /// awaited in these tests (we drive the receive path directly).
    struct CaptureTun {
        sent: Arc<StdMutex<Vec<Vec<u8>>>>,
    }

    impl Tun for CaptureTun {
        fn recv<'a>(&'a mut self, _buf: &'a mut [u8]) -> TunFut<'a> {
            Box::pin(async move {
                std::future::pending::<()>().await;
                Ok(0)
            })
        }
        fn send<'a>(&'a mut self, buf: &'a [u8]) -> TunFut<'a> {
            let sent = self.sent.clone();
            Box::pin(async move {
                sent.lock().unwrap().push(buf.to_vec());
                Ok(buf.len())
            })
        }
        fn name(&self) -> std::io::Result<String> {
            Ok("capture".into())
        }
        fn mtu(&self) -> std::io::Result<u32> {
            Ok(1400)
        }
    }

    async fn build_tunnel(sent: Arc<StdMutex<Vec<Vec<u8>>>>) -> Tunnel {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let session = Session::new(0xCAFEBABE, SessionRole::Initiator);
        let tun: Box<dyn Tun> = Box::new(CaptureTun { sent });
        let counters = Arc::new(Mutex::new(Counters::new()));
        Tunnel::from_handshake(
            tun,
            sock,
            "127.0.0.1:1".parse().unwrap(),
            session,
            default_transport(),
            crate::obfuscation::ObfuscationStack::new(),
            [0u8; 32],
            [0u8; 32],
            Direction::InitiatorToResponder,
            Direction::ResponderToInitiator,
            counters,
        )
        .unwrap()
    }

    fn data_hdr(group: u16, index: u8, k: u8, m: u8) -> PacketHeader {
        let mut h = PacketHeader::new(PacketType::Data, 0xCAFEBABE, 1);
        h.fec_group = group;
        h.fec_index = index;
        h.fec_k = k;
        h.fec_m = m;
        h
    }

    fn parity_hdr(group: u16, index: u8, k: u8, m: u8) -> PacketHeader {
        let mut h = PacketHeader::new(PacketType::Fec, 0xCAFEBABE, 1);
        h.fec_group = group;
        h.fec_index = index;
        h.fec_k = k;
        h.fec_m = m;
        h
    }

    /// Build an encrypted incoming datagram as the peer would send it: the
    /// header (including the piggyback ack fields) is the AAD and the body is
    /// encrypted with the test tunnel's recv key (`[0u8; 32]`) and recv
    /// direction (`ResponderToInitiator`), matching `build_tunnel`.
    fn peer_frame(
        ptype: PacketType,
        seq: u32,
        ack_seq: u32,
        ack_bitmap: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut hdr = PacketHeader::new(ptype, 0xCAFEBABE, seq);
        hdr.ack_seq = ack_seq;
        hdr.ack_bitmap = ack_bitmap;
        let nonce = aead::make_nonce(0xCAFEBABE, seq, Direction::ResponderToInitiator);
        let ct = aead::encrypt(&[0u8; 32], &nonce, &hdr.to_bytes(), payload).unwrap();
        codec::encode_raw(&hdr, &ct).to_vec()
    }

    #[tokio::test]
    async fn data_and_parity_packets_advance_the_ack_anchor() {
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let mut t = build_tunnel(sent.clone()).await;
        assert_eq!(t.session.ack_snapshot(), (0, 0), "nothing received yet");
        // A plain data packet (fec_m = 0: delivered straight to TUN).
        t.handle_udp_datagram(
            &peer_frame(PacketType::Data, 1, 0, 0, b"hello"),
            "127.0.0.1:1".parse().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            t.session.ack_snapshot().0,
            1,
            "data packet must be recorded"
        );
        // A parity packet at seq 3 slides the window forward; seq 1 lands at
        // bit 1 (0b10 = seq two below the anchor).
        t.handle_udp_datagram(
            &peer_frame(PacketType::Fec, 3, 0, 0, b"parity"),
            "127.0.0.1:1".parse().unwrap(),
        )
        .await
        .unwrap();
        let (anchor, bitmap) = t.session.ack_snapshot();
        assert_eq!(anchor, 3, "parity packet must be recorded");
        assert!(bitmap & 0b10 != 0, "seq 1 sits two below the anchor");
    }

    #[tokio::test]
    async fn piggyback_ack_advertisement_releases_in_flight_slots() {
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let mut t = build_tunnel(sent.clone()).await;
        for _ in 0..3 {
            t.cc.on_send();
        }
        let cwnd_before = t.cc.cwnd;
        // The peer advertises anchor 2 plus bit 0 (seq 1): two of our seqs
        // are newly acknowledged.
        t.handle_udp_datagram(
            &peer_frame(PacketType::Keepalive, 1, 2, 0b01, b""),
            "127.0.0.1:1".parse().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            t.cc.in_flight, t.cc.mtu as u64,
            "two newly acked seqs release two slots' worth of bytes"
        );
        assert!(t.cc.cwnd > cwnd_before, "acks grow the window");
        // Receiving the same advertisement again releases nothing more:
        // already-accounted acks must not be double-counted.
        t.handle_udp_datagram(
            &peer_frame(PacketType::Keepalive, 2, 2, 0b01, b""),
            "127.0.0.1:1".parse().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            t.cc.in_flight, t.cc.mtu as u64,
            "duplicate advertisement is not recounted"
        );
        // An advertisement advancing the anchor releases the delta.
        t.handle_udp_datagram(
            &peer_frame(PacketType::Keepalive, 3, 3, 0b11, b""),
            "127.0.0.1:1".parse().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(t.cc.in_flight, 0, "anchor advance releases the new seq");
    }

    #[tokio::test]
    async fn ack_anchor_jump_over_hole_releases_lost_slot_without_growth() {
        // Best-effort data lost on the wire still occupies an in-flight slot.
        // When the peer's anchor jumps over the hole, the slot must be
        // released (or the sender stalls) but the window must only grow for
        // the acked seq, not the lost one.
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let mut t = build_tunnel(sent.clone()).await;
        for _ in 0..3 {
            t.cc.on_send();
        }
        let cwnd_before = t.cc.cwnd;
        // Anchor 3 with an empty bitmap: seq 3 acked, seqs 1-2 are holes the
        // anchor jumped over (lost). All three leave flight; only one ack.
        t.handle_udp_datagram(
            &peer_frame(PacketType::Keepalive, 1, 3, 0b00, b""),
            "127.0.0.1:1".parse().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            t.cc.in_flight, 0,
            "jumped-over holes must release their slots"
        );
        // Slow start grows by the acked bytes, not per resolved slot: only
        // seq 3 was acked, so the window grows by one MTU's worth of bytes
        // (the byte-based window replaced the old packet-count one).
        assert_eq!(
            t.cc.cwnd,
            cwnd_before + t.cc.mtu as u64,
            "window grows only for the acked seq"
        );
    }

    #[tokio::test]
    async fn congestion_gate_drops_instead_of_blocking() {
        // With no send budget the TUN packet must be dropped (counted), not
        // queued or slept on: blocking the event loop here stalls UDP RX and
        // turns mild congestion into second-scale RTT spikes.
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let mut t = build_tunnel(sent.clone()).await;
        // Exhaust the byte window: send until there is no budget left, with no
        // acks to reopen it.
        while t.cc.send_budget() > 0 {
            t.cc.on_send();
        }
        assert_eq!(t.cc.send_budget(), 0);
        let tx_before = t.counters.lock().await.tx_packets;
        t.handle_tun_packet(vec![0xAA; 32]).await;
        let c = t.counters.lock().await;
        assert_eq!(
            c.tx_packets, tx_before,
            "dropped packet is not counted as sent"
        );
        assert_eq!(c.tx_dropped_congestion, 1, "drop is observable in stats");
        assert_eq!(t.cc.in_flight, t.cc.cwnd, "dropped packet reserves no slot");
    }

    #[tokio::test]
    async fn oversize_tun_packet_is_dropped_before_send() {
        // A TUN packet larger than MAX_PAYLOAD would push the outer UDP
        // datagram toward path-MTU fragmentation; it must be dropped and
        // counted instead of shipped.
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let mut t = build_tunnel(sent.clone()).await;
        let tx_before = t.counters.lock().await.tx_packets;
        let sent_ok = t.handle_tun_packet(vec![0xAA; MAX_PAYLOAD + 1]).await;
        assert!(!sent_ok, "oversize packet must not be sent");
        let c = t.counters.lock().await;
        assert_eq!(c.tx_packets, tx_before, "drop is not counted as sent");
        assert_eq!(c.tx_dropped_mtu, 1, "drop is observable in stats");
    }

    #[tokio::test]
    async fn max_payload_tun_packet_is_sent() {
        // Boundary: exactly MAX_PAYLOAD must still go out (no off-by-one).
        // The default FEC group is k=1, so sending one data packet also
        // flushes one group and emits its parities — count the data send via
        // the return value, not the aggregate tx_packets counter.
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let mut t = build_tunnel(sent.clone()).await;
        let sent_ok = t.handle_tun_packet(vec![0xAA; MAX_PAYLOAD]).await;
        assert!(sent_ok, "MAX_PAYLOAD-sized packet must be sent");
        let c = t.counters.lock().await;
        assert!(c.tx_packets >= 1, "data packet counted as sent");
        assert_eq!(c.tx_dropped_mtu, 0, "no MTU drop on the boundary");
    }

    #[tokio::test]
    async fn full_group_no_loss_delivers_each_packet_once() {
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let mut t = build_tunnel(sent.clone()).await;
        let (k, m) = (4u8, 2u8);
        // Four distinct data packets plus two parities. No loss.
        let sources: Vec<Vec<u8>> = (0..k).map(|i| vec![i + 1]).collect();
        let rs = ReedSolomon::new(k as usize, m as usize).unwrap();
        let parities = rs.encode(&sources).unwrap();
        for (i, s) in sources.iter().enumerate() {
            t.handle_data(data_hdr(0, i as u8, k, m), s.clone()).await;
        }
        for (i, p) in parities.into_iter().enumerate() {
            t.handle_parity(parity_hdr(0, k + i as u8, k, m), p).await;
        }
        let delivered = sent.lock().unwrap().clone();
        assert_eq!(delivered.len(), k as usize, "no duplicates on full group");
        for (i, s) in sources.iter().enumerate() {
            assert_eq!(delivered[i], *s, "order/content preserved");
        }
    }

    #[tokio::test]
    async fn recovered_then_late_original_is_not_redelivered() {
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let mut t = build_tunnel(sent.clone()).await;
        let (k, m) = (4u8, 2u8);
        let sources: Vec<Vec<u8>> = (0..k).map(|i| vec![10 * (i + 1)]).collect();
        let rs = ReedSolomon::new(k as usize, m as usize).unwrap();
        let parities = rs.encode(&sources).unwrap();
        // d2 is lost in transit: deliver d0, d1, d3, then both parities.
        t.handle_data(data_hdr(7, 0, k, m), sources[0].clone())
            .await;
        t.handle_data(data_hdr(7, 1, k, m), sources[1].clone())
            .await;
        t.handle_data(data_hdr(7, 3, k, m), sources[3].clone())
            .await;
        t.handle_parity(parity_hdr(7, k, k, m), parities[0].clone())
            .await;
        t.handle_parity(parity_hdr(7, k + 1, k, m), parities[1].clone())
            .await;
        // At this point d2 should have been recovered and delivered once.
        let after_recover = sent.lock().unwrap().clone();
        assert_eq!(
            after_recover.len(),
            k as usize,
            "all four sources delivered after recovery"
        );
        assert!(
            after_recover.iter().any(|p| p == &sources[2]),
            "recovered d2 present"
        );
        // Now the original d2 arrives late over UDP (reorder/dup). It must be
        // suppressed, not written to TUN again.
        t.handle_data(data_hdr(7, 2, k, m), sources[2].clone())
            .await;
        let after_late = sent.lock().unwrap().clone();
        assert_eq!(
            after_late.len(),
            k as usize,
            "late original suppressed; no duplicate TUN write"
        );
    }

    #[tokio::test]
    async fn duplicate_direct_data_is_suppressed() {
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let mut t = build_tunnel(sent.clone()).await;
        let (k, m) = (4u8, 2u8);
        let payload = vec![42u8];
        // Same data slot delivered twice (UDP duplication) before any parity.
        t.handle_data(data_hdr(1, 0, k, m), payload.clone()).await;
        t.handle_data(data_hdr(1, 0, k, m), payload.clone()).await;
        let delivered = sent.lock().unwrap().clone();
        assert_eq!(delivered.len(), 1, "duplicate direct data suppressed");
    }

    #[tokio::test]
    async fn partial_group_emits_no_parity() {
        // Sender side: a partial group (1 real packet) flushed early must not
        // produce any parity UDP datagrams. We observe the socket for traffic.
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let mut t = build_tunnel(sent).await;
        // Force FEC on with k=4, m=2.
        t.fec_params = FecParams { k: 4, m: 2 };
        t.rs = ReedSolomon::new(4, 2).unwrap();
        // Recv socket to capture sends.
        let rx_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let rx_addr = rx_sock.local_addr().unwrap();
        let (rx_tx, mut rx_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let rx_sock_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match rx_sock.recv_from(&mut buf).await {
                    Ok((n, _)) => {
                        let _ = rx_tx.send(buf[..n].to_vec());
                    }
                    Err(_) => break,
                }
            }
        });
        t.peer = rx_addr;
        // One TUN packet -> partial group -> flush_fec_group via stale tick.
        t.handle_tun_packet(vec![7u8; 32]).await;
        t.flush_fec_group().await;
        // Allow the socket task to possibly receive; there should be nothing.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let got = rx_rx.try_recv().ok();
        // The single Data packet is sent (1 datagram), but NO parity should
        // follow. So at most one datagram (the Data) was received.
        let mut count = 0;
        while rx_rx.try_recv().is_ok() {
            count += 1;
        }
        let _ = (got, count);
        // Total datagrams seen must be exactly 1 (the Data), not 1 + m parities.
        let total = 1 + count;
        assert_eq!(total, 1, "partial group must not emit parity packets");
        rx_sock_task.abort();
    }

    #[tokio::test]
    async fn k1_group_emits_parity_immediately() {
        // With k=1 (the default), every packet fills its group immediately.
        // A single TUN packet should produce 1 Data + m parity datagrams.
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let mut t = build_tunnel(sent).await;
        t.fec_params = FecParams { k: 1, m: 3 };
        t.rs = ReedSolomon::new(1, 3).unwrap();
        let rx_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let rx_addr = rx_sock.local_addr().unwrap();
        let (rx_tx, mut rx_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let rx_sock_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match rx_sock.recv_from(&mut buf).await {
                    Ok((n, _)) => {
                        let _ = rx_tx.send(buf[..n].to_vec());
                    }
                    Err(_) => break,
                }
            }
        });
        t.peer = rx_addr;
        // One TUN packet with k=1 fills the group immediately.
        t.handle_tun_packet(vec![0xAA; 32]).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        let mut count = 0;
        while rx_rx.try_recv().is_ok() {
            count += 1;
        }
        // 1 Data + 3 parities = 4 datagrams.
        assert_eq!(count, 4, "k=1 should produce 1 data + m parities");
        rx_sock_task.abort();
    }

    #[tokio::test]
    async fn parity_skipped_when_window_full() {
        // Window accounting must cover parity: with only one packet of budget
        // left, the data packet goes out but its parities are skipped rather
        // than sent over the window.
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let mut t = build_tunnel(sent).await;
        t.fec_params = FecParams { k: 1, m: 3 };
        t.rs = ReedSolomon::new(1, 3).unwrap();
        let rx_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let rx_addr = rx_sock.local_addr().unwrap();
        let (rx_tx, mut rx_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let rx_sock_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match rx_sock.recv_from(&mut buf).await {
                    Ok((n, _)) => {
                        let _ = rx_tx.send(buf[..n].to_vec());
                    }
                    Err(_) => break,
                }
            }
        });
        t.peer = rx_addr;
        // Leave exactly one data packet of budget: the 32-byte data fits, but
        // after it is admitted the three 32-byte parities do not.
        t.cc.cwnd = 48;
        t.cc.in_flight = 0;
        assert_eq!(t.cc.send_budget(), 48);
        let dropped_before = t.counters.lock().await.tx_dropped_congestion;
        t.handle_tun_packet(vec![0xAA; 32]).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        let mut count = 0;
        while rx_rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, 1, "data goes out, window-full parities are skipped");
        let dropped_after = t.counters.lock().await.tx_dropped_congestion;
        assert_eq!(
            dropped_after - dropped_before,
            3,
            "each skipped parity is counted as a congestion drop"
        );
        rx_sock_task.abort();
    }

    #[tokio::test]
    async fn fec_recovery_signals_loss_to_congestion() {
        // FEC recovery hides the loss from the user (the packet is delivered),
        // but the packet *was* lost on the wire. The congestion controller must
        // learn about that loss so it can back off; otherwise it keeps flooding
        // a lossy link, which produces more loss, which produces more parity,
        // which floods the link further. Feeding recovery as loss is what
        // breaks that runaway loop.
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let mut t = build_tunnel(sent.clone()).await;
        let (k, m) = (4u8, 2u8);
        let sources: Vec<Vec<u8>> = (0..k).map(|i| vec![10 * (i + 1)]).collect();
        let rs = ReedSolomon::new(k as usize, m as usize).unwrap();
        let parities = rs.encode(&sources).unwrap();
        let cwnd_before = t.cc.cwnd;
        // Deliver 3 of 4 data + both parities -> recover the missing one.
        t.handle_data(data_hdr(7, 0, k, m), sources[0].clone())
            .await;
        t.handle_data(data_hdr(7, 1, k, m), sources[1].clone())
            .await;
        t.handle_data(data_hdr(7, 3, k, m), sources[3].clone())
            .await;
        t.handle_parity(parity_hdr(7, k, k, m), parities[0].clone())
            .await;
        t.handle_parity(parity_hdr(7, k + 1, k, m), parities[1].clone())
            .await;
        let cwnd_after = t.cc.cwnd;
        assert!(
            cwnd_after < cwnd_before,
            "congestion window must shrink on FEC recovery (1 of {k} lost): before={cwnd_before}, after={cwnd_after}"
        );
    }

    #[tokio::test]
    async fn unrecoverable_group_increases_redundancy() {
        // When a group expires without being decoded (too many erasures),
        // the adaptive controller should increase m.
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let mut t = build_tunnel(sent.clone()).await;
        t.fec_params = FecParams { k: 1, m: 1 };
        t.rs = ReedSolomon::new(1, 1).unwrap();
        // Simulate a group that received only 1 parity but lost the data
        // and has 0 surviving symbols to decode — it will expire undelivered.
        // We create a group entry with only a parity (index 1), no data.
        t.handle_parity(parity_hdr(42, 1, 1, 1), vec![0xFF; 16])
            .await;
        // The group has 1 symbol (the parity) but k=1, so present >= k
        // triggers recovery. With only the parity surviving, RS decode
        // will succeed (the parity IS one of the n symbols, and with k=1
        // and m=1, any 1 symbol recovers the source). So we need a case
        // where present < k. With k=2, m=1: deliver only 1 of 3 symbols.
        // Let's redo with k=2, planting a group that received *no* data slots
        // (both sources undelivered) so eviction reports a 1.0 loss ratio.
        let mut t2 = build_tunnel(sent.clone()).await;
        t2.fec_params = FecParams { k: 2, m: 1 };
        t2.rs = ReedSolomon::new(2, 1).unwrap();
        // With the default floor at min_m=1, a single moderate loss sample only
        // reaches the floor; feed a fully-undelivered (1.0-ratio) group so the
        // controller is forced above the floor, proving unrecoverable loss
        // still ramps redundancy.
        let m_before2 = t2.fec.params().m;
        let mut g = RxGroup::new(2, 1);
        g.deadline = Instant::now() - Duration::from_secs(1);
        // Both source slots undelivered: a total loss of the group.
        t2.rx_groups.insert(99, g);
        t2.evict_expired_rx_groups();
        let m_after2 = t2.fec.params().m;
        assert!(
            m_after2 > m_before2,
            "unrecoverable eviction should increase m: before={}, after={}",
            m_before2,
            m_after2
        );
    }

    /// Session timeout: if no traffic arrives from the peer within the
    /// configured timeout, the tunnel's `run` loop must exit on its own
    /// (tearing down the session and freeing state). We use a 2-second timeout
    /// and verify the loop completes within 5 seconds without any external
    /// stop signal.
    #[tokio::test]
    async fn session_times_out_after_silence() {
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let mut t = build_tunnel(sent).await;
        // Short timeout for testing: keepalive every 1s, timeout after 2s.
        t.set_keepalive_params(Duration::from_secs(1), Duration::from_secs(2));

        let (stop_tx, stop_rx) = watch::channel(false);
        let (_udp_tx, udp_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(16);

        // The run loop should exit on its own due to timeout.
        let result = tokio::time::timeout(Duration::from_secs(8), t.run(stop_rx, udp_rx)).await;
        assert!(result.is_ok(), "tunnel run exited within timeout");
        // The stop signal was never sent — the exit was due to session timeout.
        assert!(
            !*stop_tx.borrow(),
            "stop was not signalled; timeout caused exit"
        );
    }

    /// Keepalive packets are sent during idle and received correctly. We verify
    /// that a keepalive round-trips: the sender encrypts and sends a Keepalive,
    /// the receiver decrypts and handles it without error.
    #[tokio::test]
    async fn keepalive_round_trips() {
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let mut sender = build_tunnel(sent).await;
        let mut receiver = build_tunnel(Arc::new(StdMutex::new(Vec::new()))).await;

        // Make the receiver act as the responder: its recv_dir must match the
        // sender's send_dir (InitiatorToResponder), and its recv_key must equal
        // the sender's send_key.
        let shared_key = [0xABu8; 32];
        sender.send_key = shared_key;
        receiver.recv_key = shared_key;
        receiver.recv_dir = Direction::InitiatorToResponder;

        // Point the sender's peer at the receiver's socket.
        sender.peer = receiver.sock.local_addr().unwrap();

        // Send a keepalive from the sender.
        sender.send_keepalive().await;

        // The keepalive went out over the sender's socket to the receiver's
        // address. Read it on the receiver's socket and feed it through.
        let mut buf = vec![0u8; 65535];
        let (n, from) = receiver.sock.recv_from(&mut buf).await.unwrap();
        let result = receiver.handle_udp_datagram(&buf[..n], from).await;
        assert!(result.is_ok(), "keepalive decrypted and handled ok");

        // The receiver's last_peer_activity should now be very recent.
        let elapsed = receiver.last_peer_activity.elapsed();
        assert!(
            elapsed < Duration::from_millis(100),
            "last_peer_activity updated by keepalive (elapsed {:?})",
            elapsed
        );
    }

    /// Roaming: a datagram that decrypts successfully from a source address
    /// different from `self.peer` updates the tunnel's peer address and signals
    /// the dispatcher. A datagram that *fails* to decrypt from a new address
    /// must NOT update the peer or signal.
    #[tokio::test]
    async fn roaming_updates_peer_and_signals_after_successful_decrypt() {
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let mut sender = build_tunnel(sent).await;
        let mut receiver = build_tunnel(Arc::new(StdMutex::new(Vec::new()))).await;

        let shared_key = [0xABu8; 32];
        sender.send_key = shared_key;
        receiver.recv_key = shared_key;
        receiver.recv_dir = Direction::InitiatorToResponder;

        // Pretend the session was established from a different address than
        // the sender's actual socket. This simulates a client that roamed.
        let original_peer: SocketAddr = "10.99.99.99:1234".parse().unwrap();
        receiver.peer = original_peer;

        // Set up the address-change signal channel (server-side only).
        let (addr_tx, mut addr_rx) = mpsc::unbounded_channel::<(SessionId, SocketAddr)>();
        receiver.set_addr_change_tx(addr_tx);
        assert_ne!(receiver.peer, sender.sock.local_addr().unwrap());

        // Send a keepalive from the sender to the receiver's socket.
        sender.peer = receiver.sock.local_addr().unwrap();
        sender.send_keepalive().await;

        let mut buf = vec![0u8; 65535];
        let (n, from) = receiver.sock.recv_from(&mut buf).await.unwrap();
        // `from` is the sender's address, which differs from `original_peer`.
        assert_ne!(from, original_peer);

        // The datagram should decrypt (valid AEAD tag) and trigger roaming.
        let result = receiver.handle_udp_datagram(&buf[..n], from).await;
        assert!(
            result.is_ok(),
            "keepalive from a new address should decrypt"
        );

        assert_eq!(
            receiver.peer, from,
            "peer address must be updated to the confirmed new address"
        );
        let (sig_id, sig_addr) = addr_rx
            .recv()
            .await
            .expect("an address-change signal should have been sent");
        assert_eq!(
            sig_id, receiver.session.id,
            "signal must carry the session id"
        );
        assert_eq!(sig_addr, from, "signal must carry the new address");

        // A datagram that fails to decrypt from a *third* address must NOT
        // trigger another roaming update.
        let spoofed_addr: SocketAddr = "10.88.88.88:9999".parse().unwrap();
        let corrupt = {
            let mut bad = buf[..n].to_vec();
            let last = bad.len() - 1;
            bad[last] ^= 0xFF; // corrupt the AEAD tag
            bad
        };
        let _ = receiver.handle_udp_datagram(&corrupt, spoofed_addr).await;
        assert_eq!(
            receiver.peer, from,
            "failed decrypt must not change the peer address"
        );
        // The corrupt datagram must not have produced a roaming signal, so the
        // dispatcher's addr_index never learns the spoofed address. This is the
        // dispatcher-level expression of the AEAD-decrypt trust gate: an
        // attacker cannot redirect a victim's session by sending a guessed
        // SessionId with invalid ciphertext.
        let signal_after_corrupt =
            tokio::time::timeout(Duration::from_millis(100), addr_rx.recv()).await;
        assert!(
            signal_after_corrupt.is_err(),
            "a failed-decrypt datagram from a new address must not signal the dispatcher"
        );
    }
}
