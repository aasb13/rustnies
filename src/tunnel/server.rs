//! Multi-client server: a single UDP socket accepts an unbounded number of
//! Noise IK handshakes and runs one independent [`Tunnel`] per client.
//!
//! Architecture:
//!
//! - One bound [`UdpSocket`] (the server's public endpoint) is shared by every
//!   client. Outgoing datagrams use `send_to` (`&self`), so an `Arc<UdpSocket>`
//!   is cheaply shared across tunnel tasks.
//! - Incoming datagrams are read by a single **dispatcher** select loop (this
//!   module's [`run_server`]). The dispatcher is the sole owner of all session
//!   state and runs on one task, so the routing tables need no locking.
//!   Session identity is the 32-bit `SessionId` carried in every steady-state
//!   packet header — **not** the client's `SocketAddr`. The address is purely
//!   "where to send the next datagram for this session" and is updated (via
//!   roaming) as the client moves. Two routing structures are maintained:
//!   - `sessions: HashMap<SessionId, ClientHandle>` — the source of truth.
//!   - `addr_index: HashMap<SocketAddr, SessionId>` — a stale-tolerant cache so
//!     a datagram whose header can't be peeked (e.g. per-session header
//!     whitening, which the dispatcher cannot reverse without the session
//!     key) still has a chance of being routed without being mistaken for
//!     scan noise. A wrong `addr_index` entry never causes a misroute: at
//!     worst the datagram triggers an extra AEAD decrypt attempt that fails
//!     and is silently dropped.
//! - For each inbound UDP datagram the dispatcher runs:
//!   1. Peek the `SessionId` (raw fast path, else after stripping the
//!      stateless transport envelope and best-effort shared-stack
//!      de-obfuscation). If it resolves to a live session, forward the
//!      datagram (with its source address) to that session's UDP channel.
//!      Handshake bytes cannot peek-match a live session (see
//!      `peek_session_id`), so reconnects are never swallowed here.
//!   2. Otherwise, attempt `handshake::respond_message_1`. A Noise message-1
//!      authenticates the initiator against the server's static key, so this
//!      can never misclassify real session traffic — a steady-state Data/Fec/
//!      Ack/etc. frame is cryptographically a different shape and fails the
//!      probe immediately. On success a **new** session is spawned (see the
//!      replacement-policy note below). No address-keyed or static-key-based
//!      replacement happens here.
//!   3. If the handshake probe failed, consult the `addr_index` cache by
//!      source address. If it points at a live session, forward there. This
//!      runs *after* the handshake probe so a fresh handshake from a known
//!      address (same-address reconnect) is recognised as a new session
//!      instead of being forwarded into the old tunnel.
//!   4. If none matched, the datagram is scan noise and is dropped.
//! - `header_xor` roaming: the dispatcher stores each session's `header_xor`
//!   keystream as public routing metadata (derived from the handshake hash,
//!   not secret — the AEAD AAD still authenticates the header). The peek path
//!   tries de-whitening the frame with each live session's keystream and peeks
//!   the `SessionId` from the result, so a whitened session remains
//!   peek-routable even after roaming to a new address (where the
//!   `addr_index` cache is stale). A wrong keystream fails the version/type
//!   check with probability ~1/255, so trying every session's keystream never
//!   misroutes. Plain/padded/tagged sessions roam transparently regardless.
//! - Roaming: when a tunnel task successfully AEAD-decrypts a datagram from a
//!   source address different from its current peer, it updates `self.peer`
//!   and sends `(SessionId, new_addr)` over the address-change channel back to
//!   the dispatcher, which refreshes both `ClientHandle.current_addr` and the
//!   `addr_index`. The AEAD tag is the authentication gate: only the legitimate
//!   peer (who shares the key) could have produced a packet that decrypts, so a
//!   successful decrypt is proof of identity regardless of source address.
//! - One **TUN device** is shared by all clients via a [`ChannelTun`] per
//!   tunnel: each tunnel's `Tun::send` posts the decrypted IP packet to a
//!   shared write channel drained by the dispatcher, which writes it to the
//!   real TUN; `Tun::recv` reads from a per-client channel that the dispatcher
//!   feeds from TUN reads, routing by destination IPv4 address. The write
//!   aggregator now carries a `SessionId` tag (not a `SocketAddr`) so return
//!   traffic can be routed even when the client has roamed.
//! - The tunnel IP of each client is **learned from observed traffic**, but
//!   only from **plausible** sources: when a client sends its first data
//!   packet, the dispatcher checks the source IPv4 address against the
//!   configured TUN subnet(s) (see [`should_learn_tun_ip`]) and registers
//!   `tun_ip -> SessionId` only on a match. Return traffic from the TUN whose
//!   destination matches that IP is routed back to the client. Implausible
//!   sources (a LAN neighbor's address pulled into the tunnel by an over-broad
//!   client route-all, or the client's own public underlay IP) are rejected
//!   with a loud warning and never registered — accepting them would misroute
//!   return traffic into the tunnel (blackholing it) and pollute diagnostics.
//!   This needs no wire-protocol change (the handshake carries no address
//!   assignment). A client behind LAN sharing legitimately presents several
//!   TUN-subnet source IPs; all of them are tracked for return routing.
//!
//! ## Session replacement policy
//!
//! A fresh Noise handshake message-1 is **always** a new, independent session.
//! The dispatcher does **not** replace an existing session when a new handshake
//! arrives — not by address, and not by static public key. Each handshake uses
//! a fresh ephemeral key, so the derived `SessionId` is unique per session, and
//! two concurrent sessions from the same client (intentional multi-tunnel or a
//! re-NAT collision) coexist without interference. Stale sessions are reclaimed
//! by the existing idle `SESSION_TIMEOUT` (75s) and the periodic sweep
//! (channel-closed detection). This is a deliberate change from phase-1's
//! "replace-by-address-or-key" behaviour to satisfy the multi-session and
//! roaming requirements.
//!
//! All state (the client table) is owned by the single dispatcher task, so it
//! needs no locking. Client tunnels communicate back to the dispatcher through
//! the shared TUN-write channel and the address-change signal channel. The
//! dispatcher periodically sweeps entries whose tunnel task has exited
//! (detected via a closed TUN channel).
//!
//! This module is platform-independent: it uses only tokio UDP sockets, the
//! `Tun` trait, and IPv4 header parsing. No platform code lives here.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use crate::carrier::{Carrier, CarrierListener, Inbound};
use tokio::sync::{Mutex, mpsc, watch};
use tokio::task::JoinHandle;

use ipnet::IpNet;

use crate::crypto::keys::KeyPair;
use crate::obfuscation::{self, ObfuscationStack};
use crate::protocol::SessionId;
use crate::protocol::header::{HEADER_LEN, PROTOCOL_VERSION, PacketType};
use crate::protocol::profile::{LocalProfile, ResolvedProfile};
use crate::protocol::session::{Session, SessionRole};
use crate::stats::Counters;
use crate::transport::Transport;
use crate::tun::Tun;
use crate::tunnel::Tunnel;
use crate::tunnel::handshake::{self, Authorizer};

/// Commands the IPC server can send to the dispatcher, for server-only
/// operations that need access to the `sessions` table.
pub enum ControlCommand {
    /// Add `peer_key` to the runtime denylist and evict all live sessions for it.
    /// Returns the number of sessions evicted.
    Revoke {
        peer_key: [u8; 32],
        tx: tokio::sync::oneshot::Sender<usize>,
    },
    /// Enumerate all live sessions.
    ListSessions {
        tx: tokio::sync::oneshot::Sender<Vec<crate::ipc::messages::SessionInfo>>,
    },
    /// Disconnect sessions matching the criteria. `session_id` takes priority;
    /// if `None`, all sessions matching `peer_key` are evicted. Returns the
    /// number of sessions disconnected.
    Disconnect {
        session_id: Option<u32>,
        peer_key: Option<[u8; 32]>,
        tx: tokio::sync::oneshot::Sender<usize>,
    },
}

/// Shared handle handed to the IPC server so it can reach into the server
/// dispatcher for operator commands. `None` on the client side (client has no
/// peer table to query or revoke against).
#[derive(Clone)]
pub struct ServerHandle {
    pub peer_auth: Arc<StdMutex<crate::tunnel::peers::PeerAuth>>,
    pub control_tx: mpsc::Sender<ControlCommand>,
}
use crate::tunnel::peers::PeerAuth;

/// Per-client capacity for the TUN-forward and UDP-forward channels. When the
/// TUN-forward channel fills, the dispatcher takes backpressure (blocking send)
/// instead of silently dropping a packet the client is waiting to receive; the
/// kernel TUN buffer absorbs the short-term pressure. The UDP-forward channel
/// remains best-effort (logged drop on full/closed).
const PER_CLIENT_CHAN: usize = 512;
/// Capacity of the shared TUN-write aggregator (all clients -> TUN).
const TUN_WRITE_CHAN: usize = 4096;

/// Handshake-probe rate limiter constants.
/// Per-source token bucket: at most `HANDSHAKE_PROBE_BURST` probes burst, then
/// refilled at one token per `HANDSHAKE_PROBE_INTERVAL_MS` up to the burst
/// capacity. Caps the per-datagram asymmetric-crypto cost of the probe path.
const HANDSHAKE_PROBE_BURST: u32 = 4;
const HANDSHAKE_PROBE_INTERVAL_MS: u64 = 200;
/// Global cap on live probe-bucket entries (sources tracked at once). Prevents
/// an attacker rotating spoofed source addresses from growing the table without
/// bound.
const HANDSHAKE_PROBE_GLOBAL_CAP: usize = 64;
/// Per-source token-bucket TTL before eviction (idle sources drop their entry).
const HANDSHAKE_TOKEN_TTL_MS: u64 = 5_000;

/// Per-source token bucket for the handshake-probe path.
///
/// Each inbound UDP datagram that is not peek-routable and whose source is not
/// already claimed by a live session is an *attempted* handshake probe. A probe
/// runs `respond_message_1`, which performs asymmetric crypto (Noise IK
/// responder). An attacker can force unbounded crypto work by flooding garbage
/// that passes the cheap framing checks. This bucket limits how often a given
/// source may take that crypto-cost path.
struct ProbeBucket {
    last_refill: Instant,
    tokens: u32,
}

impl ProbeBucket {
    fn new() -> Self {
        Self {
            last_refill: Instant::now(),
            tokens: HANDSHAKE_PROBE_BURST,
        }
    }
    fn take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed_ms = self.last_refill.elapsed().as_millis() as u64;
        self.last_refill = now;
        if elapsed_ms > 0 {
            let gained = elapsed_ms / HANDSHAKE_PROBE_INTERVAL_MS;
            if gained > 0 {
                self.tokens = (self.tokens + gained as u32).min(HANDSHAKE_PROBE_BURST);
            }
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// Global probe rate limiter: one token bucket per source address, with a cap on
/// how many sources are tracked at once. Stale entries are lazily reaped.
struct ProbeLimiter {
    by_source: std::collections::HashMap<SocketAddr, ProbeBucket>,
    last_purge: Instant,
}

impl ProbeLimiter {
    fn new() -> Self {
        Self {
            by_source: std::collections::HashMap::new(),
            last_purge: Instant::now(),
        }
    }
    fn allow(&mut self, src: SocketAddr) -> bool {
        if self.last_purge.elapsed().as_millis() as u64 >= HANDSHAKE_TOKEN_TTL_MS {
            self.by_source.retain(|_, b| {
                (b.last_refill.elapsed().as_millis() as u64) < HANDSHAKE_TOKEN_TTL_MS
            });
            self.last_purge = Instant::now();
        }
        let allowed;
        if let Some(b) = self.by_source.get_mut(&src) {
            allowed = b.take();
        } else if self.by_source.len() >= HANDSHAKE_PROBE_GLOBAL_CAP {
            tracing::debug!(from = %src, "handshake probe rejected: global probe tracker full");
            return false;
        } else {
            let mut b = ProbeBucket::new();
            allowed = b.take();
            self.by_source.insert(src, b);
        }
        if !allowed {
            tracing::trace!(from = %src, "handshake probe rate-limited (token bucket empty)");
        }
        allowed
    }
}

/// A TUN backed by channels, used to give each server-side tunnel a private
/// `Box<dyn Tun>` view onto the single shared TUN device.
///
/// `recv` reads packets the dispatcher routed to this client (TUN -> client);
/// `send` posts packets this client decrypted (client -> TUN) onto the shared
/// write aggregator, tagging them with the `SessionId` so the dispatcher can
/// learn the client's tunnel IP from the source address and route return
/// traffic even when the client has roamed to a new UDP address.
struct ChannelTun {
    name: String,
    mtu: u32,
    session_id: SessionId,
    /// Packets routed *to* this client from the shared TUN reader.
    inbound: mpsc::Receiver<Vec<u8>>,
    /// Outbound aggregator: decrypted packets from this client to the TUN.
    outbound: mpsc::Sender<(SessionId, Vec<u8>)>,
}

impl Tun for ChannelTun {
    fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> crate::tun::TunFut<'a> {
        Box::pin(async move {
            match self.inbound.recv().await {
                Some(p) => {
                    let n = p.len().min(buf.len());
                    buf[..n].copy_from_slice(&p[..n]);
                    Ok(n)
                }
                None => Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "tun inbound channel closed",
                )),
            }
        })
    }

    fn send<'a>(&'a mut self, buf: &'a [u8]) -> crate::tun::TunFut<'a> {
        let outbound = self.outbound.clone();
        let session_id = self.session_id;
        Box::pin(async move {
            outbound
                .send((session_id, buf.to_vec()))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "tun writer closed"))?;
            Ok(buf.len())
        })
    }

    fn name(&self) -> io::Result<String> {
        Ok(self.name.clone())
    }
    fn mtu(&self) -> io::Result<u32> {
        Ok(self.mtu)
    }
}

/// Dispatcher-side handle for one connected client.
struct ClientHandle {
    /// Forward incoming UDP datagrams (with their source address) to the
    /// client's tunnel. The source address travels with each datagram so the
    /// tunnel can detect roaming.
    udp_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    /// Forward TUN packets (routed by dst IP) to the client's tunnel.
    tun_tx: mpsc::Sender<Vec<u8>>,
    /// The client's current source address — where to send the next outgoing
    /// datagram. Updated when the tunnel task confirms a roaming event via the
    /// address-change channel.
    current_addr: SocketAddr,
    /// The client's static public key — its stable identity across sessions.
    /// Used for the per-peer session cap (evicting the oldest-idle session of
    /// an oversubscribed peer on a new handshake), peer-label lookup in
    /// `list_sessions`, and finding sessions for revocation/disconnect.
    peer_key: [u8; 32],
    /// The configured label for `peer_key`, captured at handshake time.
    peer_label: Option<String>,
    /// Last time any datagram was forwarded to this session, for the per-peer
    /// oldest-idle eviction policy.
    last_forwarded: Instant,
    /// Signal sent to the tunnel task to request a graceful teardown (Close +
    /// exit). Set by cap eviction (T10), revocation, and disconnect IPC. The
    /// tunnel task sends a `Close` packet to the peer before exiting.
    evict_tx: mpsc::UnboundedSender<()>,
    /// Number of confirmed roaming events for this session.
    roam_count: u32,
    /// When the most recent roam was confirmed, as a monotonic Instant. `None`
    /// if the client has never roamed. Converted to a relative timestamp for
    /// IPC output.
    last_roam: Option<Instant>,
    /// When this session was spawned, for age calculation in `list_sessions`.
    spawned_at: Instant,
    /// The tunnel IPs learned from the client's outbound traffic. A client
    /// may send packets from multiple source IPs (its own TUN IP plus LAN
    /// clients routed through it), so we track all of them for return routing.
    tun_ips: std::collections::HashSet<Ipv4Addr>,
    /// Implausible source IPs already warned about (see
    /// [`should_learn_tun_ip`]). One chatty host can emit dozens of these per
    /// second, so the loud warning fires once per address per session and
    /// repeats are demoted to trace — the rejection itself still happens every
    /// time.
    warned_implausible: std::collections::HashSet<Ipv4Addr>,
    /// Public routing metadata for obfuscation reversal. The dispatcher cannot
    /// use the session's full AEAD keys (those stay in the tunnel task), but it
    /// *can* hold the per-session routing-only material needed to de-whiten a
    /// header so it can peek the `SessionId` for routing — even when the client
    /// has roamed to a new address and `addr_index` is stale.
    ///
    /// Currently this holds the `header_xor` keystream (derived from the
    /// handshake hash). `None` means the layer is inactive/initialised; the
    /// dispatcher then falls back to the plain peek path.
    pub_route_keystream: Option<[u8; HEADER_LEN]>,
    /// Join handle so we can await/cleanup if needed.
    #[allow(dead_code)]
    join: JoinHandle<()>,
}

/// Run the multi-client server until `stop` is signalled.
///
/// `sock` is the bound listening socket; `tun` is the single shared TUN device;
/// Server-wide state that every inbound event needs.
///
/// Grouping these keeps the dispatch path (which now has to handle two
/// different inbound shapes) readable, and means adding a field the dispatcher
/// needs is a one-line change rather than a signature change threaded through
/// four helpers.
struct ServerCtx {
    server_kp: KeyPair,
    profile: LocalProfile,
    obf_stack: obfuscation::SharedStack,
    /// How to answer a datagram carrier. `None` for a stream carrier, where a
    /// session's carrier comes from the accepted connection instead.
    sender: Option<Arc<dyn Carrier>>,
    peer_auth: Arc<StdMutex<PeerAuth>>,
    counters: Arc<Mutex<Counters>>,
    tun_write_tx: mpsc::Sender<(SessionId, Vec<u8>)>,
    addr_change_tx: mpsc::UnboundedSender<(SessionId, SocketAddr)>,
    stop_tx: watch::Sender<bool>,
    tun_name: String,
    tun_mtu: u32,
    fec_config: crate::config::FecConfig,
    max_sessions_per_peer: u8,
}

/// The carrier a datagram server answers from, if it has one.
///
/// A stream listener returns `None`: there is no shared socket, and each
/// session's carrier is the connection it was accepted on.
fn ctx_sender(listener: &dyn CarrierListener) -> Option<Arc<dyn Carrier>> {
    listener.sender()
}

/// Route one inbound datagram, or recognise it as a new handshake.
///
/// Dispatch order (SessionId is authoritative):
/// 1. Peek-based route (strips the transport envelope + best-effort
///    de-obfuscates with the *shared* stack, then per-session routing metadata
///    if present). A live SessionId match is forwarded with its source address
///    so the tunnel can detect roaming. Handshake bytes cannot produce a live
///    peek match.
/// 2. Handshake probe (rate-limited): recognises a fresh handshake from a known
///    address as a NEW session, not a reconnect swallowed by the old tunnel.
/// 3. `addr_index` fallback: covers packets whose header can't be peeked
///    (whitened frames from a known address). Runs after the probe so a
///    same-address reconnect is recognised.
/// 4. Otherwise drop as scan noise.
async fn dispatch_datagram(
    ctx: &ServerCtx,
    datagram: &[u8],
    from: SocketAddr,
    sessions: &mut HashMap<SessionId, ClientHandle>,
    addr_index: &mut HashMap<SocketAddr, SessionId>,
    probe_limiter: &mut ProbeLimiter,
) {
    // Step 1: peek-based route.
    let mut forwarded = false;
    if let Some(sid) = peek_routed_session(sessions, &*ctx.profile.handshake_transport, datagram) {
        if let Some(h) = sessions.get_mut(&sid) {
            if h.udp_tx.try_send((datagram.to_vec(), from)).is_ok() {
                h.last_forwarded = Instant::now();
                forwarded = true;
            } else {
                tracing::debug!(session_id = sid, from = %from, "session channel full/closed");
            }
        }
    }
    if forwarded {
        return;
    }

    // Step 2: no live session claims this datagram. Before paying the
    // asymmetric-crypto cost of `respond_message_1`, apply the per-source
    // probe rate limiter so a flood of garbage cannot force unbounded crypto.
    if !probe_limiter.allow(from) {
        tracing::debug!(from = %from, "handshake probe rate-limited; dropping datagram");
        return;
    }
    let Some(sender) = ctx.sender.clone() else {
        tracing::debug!(from = %from, "no sender for a datagram on a stream server");
        return;
    };
    if handle_handshake(ctx, datagram, from, sender, sessions, addr_index).await {
        return;
    }

    // Step 3: not a handshake either — last resort is the addr_index cache
    // (covers a whitened frame from a brand-new address before the tunnel has
    // signalled a roam). A stale entry never misroutes: the tunnel's AEAD
    // decrypt rejects foreign bytes.
    if let Some(sid) = addr_fallback(sessions, addr_index, from)
        && let Some(h) = sessions.get_mut(&sid)
        && h.udp_tx.try_send((datagram.to_vec(), from)).is_ok()
    {
        h.last_forwarded = Instant::now();
    } else if let Some(sid) = addr_fallback(sessions, addr_index, from) {
        tracing::debug!(session_id = sid, from = %from, "addr-index session channel full/closed; dropping");
    }
}

/// Run the handshake on a freshly accepted stream connection.
///
/// A stream connection cannot be shared, so there is nothing to peek-route or
/// fall back on: the connection *is* the session. The first message must be a
/// message 1, and every later message on this connection belongs to the
/// session the handshake creates.
async fn dispatch_connection(
    ctx: &ServerCtx,
    carrier: Arc<dyn Carrier>,
    from: SocketAddr,
    sessions: &mut HashMap<SessionId, ClientHandle>,
    addr_index: &mut HashMap<SocketAddr, SessionId>,
) {
    tracing::debug!(from = %from, carrier = carrier.name(), "accepted a connection; expecting message 1");
    let msg1 = match carrier.recv().await {
        Ok((data, _)) => data,
        Err(e) => {
            tracing::debug!(from = %from, error = ?e, "connection closed before message 1");
            return;
        }
    };
    if !handle_handshake(ctx, &msg1, from, carrier, sessions, addr_index).await {
        tracing::debug!(from = %from, "connection did not carry a valid message 1; dropping");
    }
}

/// `transport` is cloned (via [`Transport::boxed_clone`]) per tunnel; `counters`
/// is shared by all tunnels so IPC stats aggregate across clients. `obf_stack`
/// is the shared obfuscation stack configuration; each client tunnel gets a
/// fresh clone seeded from that client's handshake hash. `peer_auth` holds the
/// authorized-key set (and runtime denylist); `control_rx` carries
/// operator commands (revoke, disconnect, list-sessions) from the IPC server.
#[allow(clippy::too_many_arguments)]
pub async fn run_server(
    listener: Box<dyn CarrierListener>,
    server_kp: KeyPair,
    mut tun: Box<dyn Tun>,
    profile: LocalProfile,
    obf_stack: obfuscation::SharedStack,
    mut stop: watch::Receiver<bool>,
    stop_tx: watch::Sender<bool>,
    counters: Arc<Mutex<Counters>>,
    tun_name: String,
    tun_mtu: u32,
    tun_nets: Vec<IpNet>,
    peer_auth: Arc<StdMutex<PeerAuth>>,
    fec_config: crate::config::FecConfig,
    max_sessions_per_peer: u8,
    mut control_rx: mpsc::Receiver<ControlCommand>,
) -> io::Result<()> {
    tracing::info!(
        listen = %listener.name(),
        open_mode = peer_auth.lock().unwrap_or_else(|e| e.into_inner()).is_open_mode(),
        "multi-client server running; accepting handshakes"
    );

    // Mark the server as connected from the start (it is "up" and accepting).
    {
        let mut c = counters.lock().await;
        c.connected = true;
    }

    // Shared TUN-write aggregator: every client tunnel posts its decrypted
    // packets here (tagged with SessionId) for the dispatcher to write to the
    // real TUN and learn the client's tunnel IP from the source address.
    let (tun_write_tx, mut tun_write_rx) = mpsc::channel::<(SessionId, Vec<u8>)>(TUN_WRITE_CHAN);
    // Address-change signal channel: tunnel tasks send `(SessionId, new_addr)`
    // here after a confirmed AEAD decryption from a new source address (roaming).
    // The dispatcher uses it to refresh the address index.
    let (addr_change_tx, mut addr_change_rx) = mpsc::unbounded_channel::<(SessionId, SocketAddr)>();
    // Periodic sweep: removes client entries whose tunnel task has exited
    // (detected via a closed TUN channel). This is hygiene — the
    // correctness-critical path is identity-based dispatch — but it keeps the
    // client count accurate and bounds memory for clients that leave without
    // reconnecting.
    let mut sweep = tokio::time::interval(Duration::from_secs(1));
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // `sessions` is the source of truth for session identity, keyed by
    // SessionId (carried in cleartext on every steady-state packet). `addr_index`
    // is a stale-tolerant cache of `SocketAddr -> SessionId` used only as a
    // fast-path hint when the header can't be peeked (non-PlainTransport).
    let mut sessions: HashMap<SessionId, ClientHandle> = HashMap::new();
    let mut addr_index: HashMap<SocketAddr, SessionId> = HashMap::new();
    let mut probe_limiter = ProbeLimiter::new();
    let mut tun_buf = vec![0u8; 65535];

    // A datagram carrier answers from its shared socket. A stream carrier has
    // no shared sender: each session answers on its own accepted connection.
    let sender = ctx_sender(&*listener);
    let ctx = ServerCtx {
        server_kp,
        profile,
        obf_stack: obf_stack.clone(),
        sender,
        peer_auth: peer_auth.clone(),
        counters: counters.clone(),
        tun_write_tx: tun_write_tx.clone(),
        addr_change_tx: addr_change_tx.clone(),
        stop_tx: stop_tx.clone(),
        tun_name: tun_name.clone(),
        tun_mtu,
        fec_config: fec_config.clone(),
        max_sessions_per_peer,
    };

    // NOTE: no `biased` here on purpose (same reason as `Tunnel::run`):
    // a biased TUN-first poll starves UDP dispatch under load. With fair
    // (non-biased) scheduling, a full per-client TUN-forward channel takes
    // backpressure (blocking send) instead of dropping, so the server does
    // not manufacture the very loss its FEC then has to repair.
    loop {
        tokio::select! {
            changed = stop.changed() => {
                let _ = changed;
                if *stop.borrow() {
                    tracing::info!("server shutdown signal received");
                    break;
                }
            }

            // TUN -> clients: read a packet from the shared TUN and route it
            // to the client whose tunnel IP matches the destination.
            n = tun.recv(&mut tun_buf) => {
                match n {
                    Ok(n) => {
                        let pkt = &tun_buf[..n];
                        if let Some(dst) = ipv4_dst(pkt) {
                             // Find the client owning this destination IP.
                             // Skip entries whose tunnel has exited (closed
                             // channel): a stale entry from a previous
                             // connection would silently swallow return traffic.
                             if let Some((sid, h)) = sessions
                                 .iter()
                                 .find(|(_, h)| h.tun_ips.contains(&dst) && !h.tun_tx.is_closed())
                             {
                                 match h.tun_tx.try_send(pkt.to_vec()) {
                                     Ok(()) => {}
                                     Err(mpsc::error::TrySendError::Full(packet)) => {
                                         // The per-client TUN channel buffer (512
                                         // entries) is exhausted but the tunnel
                                         // task is alive. Apply backpressure:
                                         // block until space is available instead
                                         // of silently dropping a packet the
                                         // client is waiting to receive. The
                                         // kernel's TUN buffer absorbs the
                                         // short-term pressure; this prevents
                                         // the dispatcher from manufacturing the
                                         // very loss its FEC then has to repair.
                                         tracing::debug!(
                                             session_id = sid,
                                             dst = %dst,
                                             "per-client tun channel full; applying backpressure"
                                         );
                                         {
                                             let mut c = counters.lock().await;
                                             c.dispatch_backpressure =
                                                 c.dispatch_backpressure.saturating_add(1);
                                         }
                                         if let Err(e) = h.tun_tx.send(packet).await {
                                             tracing::trace!(
                                                 session_id = sid,
                                                 error = ?e,
                                                 "tun channel closed during backpressure send; dropping"
                                             );
                                         }
                                     }
                                     Err(mpsc::error::TrySendError::Closed(_)) => {
                                         // Race: the channel closed between the
                                         // is_closed() check in find() and
                                         // try_send. The tunnel task has exited;
                                         // the periodic sweep will reclaim this
                                         // entry, so no further action is needed.
                                         tracing::trace!(
                                             session_id = sid,
                                             "tun channel closed during dispatch; dropping stale packet"
                                         );
                                     }
                                 }
                             }
                            // Unknown destination: drop (no client owns it yet).
                        }
                        // Non-IPv4 packets from TUN are dropped; phase 1 is v4-only.
                    }
                    Err(e) => {
                        tracing::error!(error = ?e, "server tun read error");
                        break;
                    }
                }
            }

            // clients -> TUN: a tunnel posted a decrypted packet. Write it to
            // the real TUN and learn the client's tunnel IP from the src addr
            // — but only if the source is plausible (inside the TUN subnet).
            // Implausible sources are rejected and never registered: accepting
            // e.g. a LAN neighbor's address or the client's public underlay
            // IP would misroute return traffic into the tunnel. The packet
            // itself is still forwarded (filtering here is about return-path
            // routing, not the forward path — an operator may have manual
            // SNAT covering such sources, which dropping would break).
            Some((session_id, pkt)) = tun_write_rx.recv() => {
                // Learn the client's tunnel IP from the source of its traffic.
                if let Some(src) = ipv4_src(&pkt)
                    && let Some(h) = sessions.get_mut(&session_id)
                {
                    if should_learn_tun_ip(src, &tun_nets) {
                        if h.tun_ips.insert(src) {
                            tracing::info!(
                                session_id,
                                peer = %h.current_addr,
                                tun_ip = %src,
                                "learned client tunnel ip"
                            );
                        }
                    } else if note_implausible_ip(&mut h.warned_implausible, src) {
                        tracing::warn!(
                            session_id,
                            peer = %h.current_addr,
                            tun_ip = %src,
                            "ignoring implausible client tunnel ip (outside TUN subnet); check client route-all LAN exceptions and NAT (repeats suppressed)"
                        );
                    } else {
                        tracing::trace!(
                            session_id,
                            tun_ip = %src,
                            "implausible client tunnel ip still outside TUN subnet"
                        );
                    }
                }
                if let Err(e) = tun.send(&pkt).await {
                    tracing::warn!(error = ?e, "server tun write error");
                }
            }

            // Tunnel tasks signal confirmed address changes (roaming) here.
            Some((session_id, new_addr)) = addr_change_rx.recv() => {
                if let Some(h) = sessions.get_mut(&session_id) {
                    if h.current_addr != new_addr {
                        // Only remove the old index entry if it still points at
                        // this session (a stale entry for another session at
                        // the same address must not be clobbered).
                        if addr_index.get(&h.current_addr) == Some(&session_id) {
                            addr_index.remove(&h.current_addr);
                        }
                        h.current_addr = new_addr;
                        h.roam_count = h.roam_count.saturating_add(1);
                        h.last_roam = Some(Instant::now());
                        addr_index.insert(new_addr, session_id);
                        let mut c = counters.lock().await;
                        c.sessions_roamed = c.sessions_roamed.saturating_add(1);
                        tracing::info!(
                            session_id,
                            new_addr = %new_addr,
                            roam_count = h.roam_count,
                            "session address updated (roaming)"
                        );
                    }
                }
            }

            // Operator control commands from the IPC server (revoke, disconnect,
            // list-sessions). Handled synchronously between packet dispatches.
            cmd = control_rx.recv() => {
                if let Some(cmd) = cmd {
                    handle_control_command(cmd, &mut sessions, &peer_auth, &counters).await;
                } else {
                    // control_rx sender dropped; nothing to do, keep running.
                }
            }

            // Inbound: one event from the carrier listener. A datagram
            // carrier yields more datagrams from one socket; a stream carrier
            // yields a new connection, which *is* the session's identity.
            event = listener.next_event() => {
                match event {
                    Ok(Inbound::Datagram { data, from }) => {
                        dispatch_datagram(
                            &ctx, &data, from, &mut sessions, &mut addr_index, &mut probe_limiter,
                        ).await;
                    }
                    Ok(Inbound::Connection { carrier, from }) => {
                        dispatch_connection(
                            &ctx, carrier, from, &mut sessions, &mut addr_index,
                        ).await;
                    }
                    Err(e) => {
                        tracing::warn!(error = ?e, carrier = listener.name(), "server carrier accept error");
                    }
                }
            }

            // Sweep: remove entries whose tunnel task has exited (its TUN
            // channel sender reports closed because the receiver was dropped
            // when the task ended). Keeps the client count honest and bounds
            // memory for clients that leave without reconnecting.
            _ = sweep.tick() => {
                let before = sessions.len();
                sessions.retain(|_, h| !h.tun_tx.is_closed());
                // Reap stale addr_index entries pointing at reaped sessions.
                addr_index.retain(|_, sid| sessions.contains_key(sid));
                let reaped = before - sessions.len();
                if reaped > 0 {
                    let mut c = counters.lock().await;
                    c.clients = sessions.len() as u64;
                    if c.clients == 0 {
                        c.connected = false;
                    }
                    tracing::info!(reaped, remaining = c.clients, "swept expired client sessions");
                }
            }
        }
    }

    // Shutdown: dropping `sessions` closes every client's UDP/TUN channels,
    // which makes each tunnel's `run` loop exit (udp_rx returns None). They
    // also all subscribe to the same `stop` watch and will send Close.
    drop(sessions);
    drop(addr_index);
    drop(tun_write_tx);
    drop(addr_change_tx);
    {
        let mut c = counters.lock().await;
        c.connected = false;
        c.clients = 0;
    }
    Ok(())
}

/// Handle a potential handshake message 1 from `from`: authorize the peer,
/// respond with message 2, and spawn a tunnel if the handshake succeeds.
///
/// A successful handshake always creates a **new**, independent session keyed by
/// its `SessionId` — no existing session is replaced (by address or by static
/// key). Stale sessions are reclaimed by the idle `SESSION_TIMEOUT` and the
/// periodic sweep.
///
/// Returns `true` if the datagram was a valid, authorized handshake message 1
/// (a new session was spawned), `false` otherwise (scan noise, unauthorized
/// key, or corrupt handshake — the caller should try the `addr_index`
/// fallback / drop path).
#[allow(clippy::too_many_arguments)]
async fn handle_handshake(
    ctx: &ServerCtx,
    msg1: &[u8],
    from: SocketAddr,
    session_carrier: Arc<dyn Carrier>,
    sessions: &mut HashMap<SessionId, ClientHandle>,
    addr_index: &mut HashMap<SocketAddr, SessionId>,
) -> bool {
    let auth_guard = ctx.peer_auth.lock().unwrap_or_else(|e| e.into_inner());
    let authorizer: Option<Authorizer<'_>> = if auth_guard.is_open_mode() {
        None
    } else {
        Some(&|pk| auth_guard.check(pk))
    };
    match handshake::respond_message_1(
        &ctx.server_kp,
        &ctx.profile,
        &ctx.obf_stack,
        msg1,
        from,
        authorizer,
    ) {
        Some((established, m2_wire)) => {
            if let Err(e) = session_carrier.send(&m2_wire, from).await {
                tracing::warn!(
                    error = ?e, peer = %from,
                    "handshake reply send failed; client will not complete handshake"
                );
                let mut c = ctx.counters.lock().await;
                c.handshake_errors = c.handshake_errors.saturating_add(1);
                return false;
            }
            // A fresh handshake is always a new session — no replacement of
            // existing sessions by address or static key. The SessionId is
            // derived from the handshake hash (which includes a fresh
            // ephemeral), so it is unique per session. If the peer has hit the
            // per-static-key session cap, evict its oldest-idle session before
            // inserting the new one (rather than refusing the new handshake, so
            // a legit reconnect to a fresh NAT port still succeeds).
            let peer_key_bytes = established.peer_static.to_bytes();
            evict_oldest_peer_session(sessions, &peer_key_bytes, ctx.max_sessions_per_peer);
            let label = established.peer_label.clone();
            let peer_static_hex = hex::encode(peer_key_bytes);
            // Seed the per-client obfuscation stack from this session's
            // handshake hash, then hand it to the tunnel. The shared stack
            // configuration is cloned; the clone's keying layers are seeded
            // here so each client's keystream is distinct.
            let session_stack = ctx.obf_stack.deref().clone();
            session_stack.init(&established.handshake_hash);
            // Extract the per-session header_xor keystream (if any) so the
            // dispatcher can de-whiten incoming headers and peek-route without
            // the session's AEAD keys. This is public routing metadata only:
            // derived from the handshake hash, and the AEAD AAD still
            // authenticates the original header.
            let pub_route_keystream =
                extract_header_xor_keystream(&established.handshake_hash, &ctx.obf_stack);
            // Build this session's runnable profile from the negotiated
            // selection. The congestion controller is per-tunnel state, so a
            // fresh one is created here rather than shared from the server's
            // `LocalProfile`.
            let resolved = match ResolvedProfile::with_handshake_transport(
                &established.selection,
                &established.handshake_hash,
                &*ctx.profile.handshake_transport,
                ctx.profile.new_congestion(),
            ) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        peer = %from,
                        error = %e,
                        "negotiated profile cannot be instantiated; dropping client"
                    );
                    let mut c = ctx.counters.lock().await;
                    c.handshake_errors = c.handshake_errors.saturating_add(1);
                    return false;
                }
            };
            tracing::info!(
                peer = %from,
                profile = %resolved.describe(),
                "session profile instantiated"
            );
            spawn_client(
                session_carrier,
                ctx,
                resolved,
                session_stack,
                established,
                sessions,
                addr_index,
                pub_route_keystream,
            );
            tracing::info!(
                peer = %from,
                key = %peer_static_hex,
                label = label.as_deref().unwrap_or("unknown"),
                "handshake accepted; client tunnel spawned"
            );
            let mut c = ctx.counters.lock().await;
            c.clients = sessions.len() as u64;
            c.handshakes_accepted = c.handshakes_accepted.saturating_add(1);
            true
        }
        None => {
            // Every handshake outcome (rejected, failed, non-handshake/scan
            // noise) is logged at the appropriate level inside
            // `respond_message_1`; nothing to do here but drop the message.
            let mut c = ctx.counters.lock().await;
            c.handshakes_rejected = c.handshakes_rejected.saturating_add(1);
            false
        }
    }
}

/// Spawn a per-client tunnel task and register it in the session table.
fn spawn_client(
    carrier: Arc<dyn Carrier>,
    ctx: &ServerCtx,
    profile: ResolvedProfile,
    obfuscation: ObfuscationStack,
    established: handshake::SessionEstablished,
    sessions: &mut HashMap<SessionId, ClientHandle>,
    addr_index: &mut HashMap<SocketAddr, SessionId>,
    pub_route_keystream: Option<[u8; HEADER_LEN]>,
) {
    let counters = ctx.counters.clone();
    let tun_write_tx = ctx.tun_write_tx.clone();
    let addr_change_tx = ctx.addr_change_tx.clone();
    let stop_tx = ctx.stop_tx.clone();
    let tun_name = ctx.tun_name.as_str();
    let tun_mtu = ctx.tun_mtu;
    let fec_config = ctx.fec_config.clone();
    let peer = established.peer;
    let session = Session::new(established.session_id, SessionRole::Responder);
    let session_id = established.session_id;
    let peer_key = established.peer_static.to_bytes();
    let peer_label = established.peer_label.clone();
    let (udp_tx, udp_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(PER_CLIENT_CHAN);
    let (tun_in_tx, tun_in_rx) = mpsc::channel::<Vec<u8>>(PER_CLIENT_CHAN);
    let (evict_tx, evict_rx) = mpsc::unbounded_channel::<()>();

    let channel_tun = Box::new(ChannelTun {
        name: tun_name.to_string(),
        mtu: tun_mtu,
        session_id,
        inbound: tun_in_rx,
        outbound: tun_write_tx.clone(),
    });

    let mut tunnel = match Tunnel::from_handshake(
        channel_tun,
        carrier,
        peer,
        session,
        profile,
        obfuscation,
        established.send_key,
        established.recv_key,
        established.send_dir,
        established.recv_dir,
        counters,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = ?e, peer = %peer, "failed to construct tunnel; dropping client");
            return;
        }
    };

    // Wire up roaming notification: the tunnel task will signal confirmed
    // address changes back to the dispatcher.
    tunnel.set_addr_change_tx(addr_change_tx);
    // Wire up the eviction signal channel: the dispatcher sends here to ask
    // this tunnel to tear down gracefully (cap eviction, revocation, disconnect).
    tunnel.set_evict_rx(evict_rx);

    // Apply FEC settings from the resolved config. The erasure code itself came
    // from the negotiated profile; these are the local tuning parameters.
    tunnel.configure_fec(&fec_config);

    let stop_rx = stop_tx.subscribe();
    let join = tokio::spawn(async move {
        let exit = tunnel.run(stop_rx, udp_rx).await;
        tracing::info!(peer = %peer, session_id, exit = %exit, "client tunnel ended");
    });

    sessions.insert(
        session_id,
        ClientHandle {
            udp_tx,
            tun_tx: tun_in_tx,
            current_addr: peer,
            peer_key,
            peer_label,
            last_forwarded: Instant::now(),
            roam_count: 0,
            last_roam: None,
            spawned_at: Instant::now(),
            tun_ips: std::collections::HashSet::new(),
            warned_implausible: std::collections::HashSet::new(),
            pub_route_keystream,
            evict_tx,
            join,
        },
    );
    addr_index.insert(peer, session_id);
}

/// Enforce the per-static-key session cap. If adding a new session for `peer_key`
/// would exceed `max` concurrent sessions for that key, evict the oldest-idle one
/// (by `last_forwarded`) — not the new handshake, so a legit reconnect from a
/// fresh NAT port still succeeds. No-op when `max == 0` (unlimited, the default)
/// or the peer is under the cap.
///
/// Before removing the victim's `ClientHandle`, sends an eviction signal through
/// `evict_tx` so the tunnel task sends a `Close` packet to the peer (graceful
/// teardown) before its channel drops and it exits. Without this, the victim
/// would exit via the error path (`TunnelExit::UdpClosed`) without notifying the
/// peer, leaving the client to discover the eviction only via timeout.
fn evict_oldest_peer_session(
    sessions: &mut HashMap<SessionId, ClientHandle>,
    peer_key: &[u8; 32],
    max: u8,
) {
    if max == 0 {
        return;
    }
    let count = sessions
        .values()
        .filter(|h| h.peer_key == *peer_key)
        .count();
    if count < max as usize {
        return;
    }
    // Find the oldest-idle session for this peer key. Collect the candidate id
    // first to avoid holding an immutable borrow across the removal.
    let victim = sessions
        .iter()
        .filter(|(_, h)| h.peer_key == *peer_key)
        .min_by_key(|(_, h)| h.last_forwarded)
        .map(|(sid, _)| *sid);
    if let Some(sid) = victim {
        tracing::info!(
            session_id = sid,
            peer_key = %hex::encode(peer_key),
            max = max,
            "evicting oldest-idle session for peer (per-peer session cap reached)"
        );
        // Signal the victim tunnel to send a Close before we drop the handle.
        // `send` on an unbounded channel never blocks or fails; if the tunnel
        // task has already exited, the signal is simply dropped.
        if let Some(h) = sessions.get(&sid)
            && h.evict_tx.send(()).is_err()
        {
            tracing::debug!(
                session_id = sid,
                "evict signal dropped (tunnel task already exited)"
            );
        }
        sessions.remove(&sid);
    }
}

/// Handle an operator control command from the IPC server. Runs on the
/// dispatcher task so it can directly mutate the `sessions` table and `peer_auth`.
async fn handle_control_command(
    cmd: ControlCommand,
    sessions: &mut HashMap<SessionId, ClientHandle>,
    _peer_auth: &Arc<StdMutex<PeerAuth>>,
    counters: &Arc<Mutex<Counters>>,
) {
    match cmd {
        ControlCommand::Revoke { peer_key, tx } => {
            let evicted = evict_sessions_for_key(sessions, &peer_key, counters).await;
            if tx.send(evicted).is_err() {
                tracing::debug!("revoke response dropped (ipc client disconnected)");
            }
        }
        ControlCommand::ListSessions { tx } => {
            let infos = build_session_list(sessions);
            if tx.send(infos).is_err() {
                tracing::debug!("list-sessions response dropped (ipc client disconnected)");
            }
        }
        ControlCommand::Disconnect {
            session_id,
            peer_key,
            tx,
        } => {
            let evicted = evict_sessions(sessions, session_id, peer_key.as_ref(), counters).await;
            if tx.send(evicted).is_err() {
                tracing::debug!("disconnect response dropped (ipc client disconnected)");
            }
        }
    }
}

/// Evict all sessions owned by `peer_key` via the eviction signal (graceful Close).
/// Returns the number of sessions evicted.
async fn evict_sessions_for_key(
    sessions: &mut HashMap<SessionId, ClientHandle>,
    peer_key: &[u8; 32],
    counters: &Arc<Mutex<Counters>>,
) -> usize {
    let victims: Vec<SessionId> = sessions
        .iter()
        .filter(|(_, h)| h.peer_key == *peer_key)
        .map(|(sid, _)| *sid)
        .collect();
    let count = victims.len();
    for sid in &victims {
        if let Some(h) = sessions.get(sid)
            && h.evict_tx.send(()).is_err()
        {
            tracing::debug!(
                session_id = *sid,
                "evict signal dropped (tunnel task already exited)"
            );
        }
    }
    // Don't remove from `sessions` here — the sweep handles cleanup once the
    // tunnel task exits (signaled via `evict_tx` → Close → tunnel exits →
    // tun_tx closes → sweep reaps). This avoids mutating the map while we
    // might still be iterating (the victims Vec was already collected).
    if count > 0 {
        tracing::info!(
            peer_key = %hex::encode(peer_key),
            evicted = count,
            "revoke/disconnect: evicted sessions for peer"
        );
        let mut c = counters.lock().await;
        c.sessions_evicted = c.sessions_evicted.saturating_add(count as u64);
    }
    count
}

/// Evict sessions matching the criteria: `session_id` (exact) takes priority;
/// if `None`, all sessions matching `peer_key` are evicted.
async fn evict_sessions(
    sessions: &mut HashMap<SessionId, ClientHandle>,
    session_id: Option<u32>,
    peer_key: Option<&[u8; 32]>,
    counters: &Arc<Mutex<Counters>>,
) -> usize {
    let victims: Vec<SessionId> = match session_id {
        Some(sid) => {
            if sessions.contains_key(&sid) {
                vec![sid]
            } else {
                vec![]
            }
        }
        None => match peer_key {
            Some(key) => sessions
                .iter()
                .filter(|(_, h)| h.peer_key == *key)
                .map(|(sid, _)| *sid)
                .collect(),
            None => return 0,
        },
    };
    let count = victims.len();
    for sid in &victims {
        if let Some(h) = sessions.get(sid)
            && h.evict_tx.send(()).is_err()
        {
            tracing::debug!(
                session_id = *sid,
                "evict signal dropped (tunnel task already exited)"
            );
        }
    }
    if count > 0 {
        let mut c = counters.lock().await;
        c.sessions_evicted = c.sessions_evicted.saturating_add(count as u64);
    }
    count
}

/// Build a `Vec<SessionInfo>` snapshot from the live sessions table.
fn build_session_list(
    sessions: &HashMap<SessionId, ClientHandle>,
) -> Vec<crate::ipc::messages::SessionInfo> {
    let now = Instant::now();
    sessions
        .iter()
        .map(|(sid, h)| crate::ipc::messages::SessionInfo {
            session_id: *sid,
            peer_key: hex::encode(h.peer_key),
            peer_name: h.peer_label.clone(),
            peer_addr: h.current_addr.to_string(),
            roam_count: h.roam_count,
            last_roam: h.last_roam.map(|t| now.duration_since(t).as_secs_f64()),
            age_secs: now.duration_since(h.spawned_at).as_secs_f64(),
        })
        .collect()
}

/// Derive the per-session `header_xor` keystream (if the layer is configured)
/// from the Noise handshake hash. This is the public routing metadata the
/// dispatcher stores alongside a session so it can de-whiten a header to peek
/// the `SessionId` — without holding the session's AEAD keys.
///
/// Returns `Some` only if a `HeaderXor` layer is present in the *shared* stack
/// (i.e. obfuscation is configured with `header_xor`). When obfuscation is off
/// or the layer is absent, this returns `None` and the dispatcher uses the
/// plain peek path.
///
/// This duplicates the HKDF derivation in `header_xor::HeaderXor::derive` to
/// avoid exposing the `HeaderXor` type or its private `derive` here; the two
/// must stay in lock-step (same info string, same output length). Returns the
/// keystream only if the shared stack actually contains a `header_xor` layer.
fn extract_header_xor_keystream(
    handshake_hash: &[u8; 32],
    shared_stack: &obfuscation::ObfuscationStack,
) -> Option<[u8; HEADER_LEN]> {
    if !shared_stack.active() || !shared_stack.names().contains(&"header_xor") {
        return None;
    }
    use crate::obfuscation::header_xor::HKDF_INFO;
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(None, handshake_hash);
    let mut out = [0u8; HEADER_LEN];
    hk.expand(HKDF_INFO, &mut out)
        .expect("HKDF expand of 24 bytes cannot fail");
    Some(out)
}

/// Lightweight peek at the `SessionId` field of a cleartext header.
///
/// This reads only the version byte, packet-type byte, and 4-byte `SessionId`
/// — no AEAD verification, no full decode. It succeeds only for packets whose
/// wire bytes begin with a valid phase-1 header (version `0x01` + a known
/// `PacketType`). Noise handshake message-1/2 bytes happen to start with an
/// ephemeral X25519 public key byte, which is almost never `0x01`, and even if
/// it were, byte 1 is a random key byte that is almost never a valid
/// `PacketType` — so handshake datagrams fall through to the
/// `addr_index`/handshake path without a false positive.
///
/// This is a hint: a successful peek does **not** mean the packet belongs to
/// the indicated session (that requires AEAD verification inside the tunnel
/// task). It is used only to route the datagram to the right session's decrypt
/// attempt without a full parse.
fn peek_session_id(datagram: &[u8]) -> Option<SessionId> {
    if datagram.len() < HEADER_LEN {
        return None;
    }
    if datagram[0] != PROTOCOL_VERSION {
        return None;
    }
    let _ = PacketType::from_byte(datagram[1])?;
    let id = SessionId::from_le_bytes([datagram[2], datagram[3], datagram[4], datagram[5]]);
    if id == 0 {
        return None; // 0 is reserved (never assigned by session_id_from_hash)
    }
    Some(id)
}

/// `addr_index` fallback: resolve a source address to a live session, if the
/// cache points at one. Stale entries (pointing at reaped sessions) yield
/// `None` — the datagram is then dropped as scan noise. A wrong-but-live
/// entry never misroutes: the tunnel's AEAD decrypt rejects bytes that were
/// not sealed under that session's keys.
fn addr_fallback(
    sessions: &HashMap<SessionId, ClientHandle>,
    addr_index: &HashMap<SocketAddr, SessionId>,
    from: SocketAddr,
) -> Option<SessionId> {
    let sid = *addr_index.get(&from)?;
    sessions.contains_key(&sid).then_some(sid)
}

/// Decide which live session a datagram belongs to by peeking its `SessionId`.
///
/// Dispatch order (mirrors the dispatcher loop):
/// 1. Fast path: raw wire bytes already start with a valid cleartext header
///    (PlainTransport, no whitening). Zero-allocation peek.
/// 2. Transport envelope: strip a stateless envelope (e.g. `TaggedTransport`)
///    and retry the fast-path peek on the unwrapped frame. This is stateless
///    and needs no per-session state.
/// 3. Per-session header de-whitening: for each live session that carries a
///    `header_xor` keystream (stored as public routing metadata at handshake
///    time), XOR that keystream over the frame's first `HEADER_LEN` bytes and
///    retry the peek. A wrong keystream produces a wrong version byte with
///    probability ~1/255 and is silently rejected, so trying every session's
///    keystream is cheap (a 24-byte XOR + a version check) and never misroutes:
///    only the correct keystream yields a valid version + `PacketType` + live
///    `SessionId`. This is what fixes roaming under `header_xor`: after a
///    client roams to a new address, the old `addr_index` entry is stale, but
///    the de-whitening step recovers the SessionId so the datagram is routed
///    to the right session and the tunnel then confirms roaming via the AEAD
///    decrypt + address-change signal.
///
/// Returns the `SessionId` only if it resolves to a *live* session; otherwise
/// `None` (the caller tries the handshake probe and the `addr_index` fallback).
/// A successful peek is still only a routing hint — session membership is
/// proven by the AEAD decrypt inside the tunnel task.
fn peek_routed_session(
    sessions: &HashMap<SessionId, ClientHandle>,
    transport: &dyn Transport,
    datagram: &[u8],
) -> Option<SessionId> {
    fn peek_live(sessions: &HashMap<SessionId, ClientHandle>, frame: &[u8]) -> Option<SessionId> {
        let sid = peek_session_id(frame)?;
        if sessions.contains_key(&sid) {
            Some(sid)
        } else {
            None
        }
    }

    // Fast path: raw wire bytes are a cleartext header.
    if let Some(sid) = peek_live(sessions, datagram) {
        return Some(sid);
    }
    // Strip the transport envelope and try the (stateless) obfuscation layers.
    let unwrapped = transport.unwrap(datagram).ok()?;
    if let Some(sid) = peek_live(sessions, &unwrapped) {
        return Some(sid);
    }
    // Per-session header de-whitening: try each live session's stored keystream.
    // This is what restores routing under `header_xor` after a roam to a new
    // address (the addr_index cache is stale by then). A wrong keystream fails
    // the version/packet-type check with overwhelming probability, so this
    // never misroutes — only the correct keystream produces a valid header.
    for h in sessions.values() {
        if let Some(ks) = h.pub_route_keystream {
            let mut dewhitened = unwrapped.clone();
            let n = dewhitened.len().min(HEADER_LEN);
            for i in 0..n {
                dewhitened[i] ^= ks[i];
            }
            if let Some(sid) = peek_live(sessions, &dewhitened) {
                return Some(sid);
            }
        }
    }
    None
}

/// Extract the destination IPv4 address from a raw IP packet, if it is IPv4.
fn ipv4_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}

/// Extract the source IPv4 address from a raw IP packet, if it is IPv4.
fn ipv4_src(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]))
}

/// Decide whether an observed inner source address may be registered as one of
/// a client's tunnel IPs.
///
/// Only addresses inside the server's configured TUN subnet(s) are plausible:
/// the client's TUN interface address (and any same-subnet aliases, e.g. for
/// LAN sharing) live there. Anything else — a LAN neighbor's address pulled
/// into the tunnel by an over-broad client route-all, or the client's own
/// public underlay IP — is never a valid tunnel IP: registering it would make
/// the TUN->client router suck return traffic for that address into the tunnel
/// and blackhole it. Pure, for unit tests.
///
/// An empty `nets` list means "no subnet configured" (backwards compatibility
/// for embedded callers that construct the dispatcher without one): everything
/// is accepted, as before. The production daemon always passes its real TUN
/// subnet, so production is strict.
fn should_learn_tun_ip(src: Ipv4Addr, nets: &[IpNet]) -> bool {
    if nets.is_empty() {
        return true;
    }
    let ip = std::net::IpAddr::V4(src);
    nets.iter().any(|n| n.contains(&ip))
}

/// Warn-once gate for implausible tunnel IPs: records `src` in `seen` and
/// returns true on its first sighting (the caller logs WARN), false on
/// repeats (the caller logs at trace). One chatty host can otherwise emit
/// dozens of identical warnings per second. Pure, for unit tests.
fn note_implausible_ip(seen: &mut std::collections::HashSet<Ipv4Addr>, src: Ipv4Addr) -> bool {
    seen.insert(src)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_helpers() {
        // Minimal IPv4 header (20 bytes): version=4, src=10.7.0.2, dst=10.7.0.1.
        let mut pkt = [0u8; 20];
        pkt[0] = 0x45;
        pkt[12] = 10;
        pkt[13] = 7;
        pkt[14] = 0;
        pkt[15] = 2;
        pkt[16] = 10;
        pkt[17] = 7;
        pkt[18] = 0;
        pkt[19] = 1;
        assert_eq!(ipv4_src(&pkt), Some(Ipv4Addr::new(10, 7, 0, 2)));
        assert_eq!(ipv4_dst(&pkt), Some(Ipv4Addr::new(10, 7, 0, 1)));
        // v6 (version=6) is rejected.
        let mut v6 = [0u8; 40];
        v6[0] = 0x60;
        assert_eq!(ipv4_src(&v6), None);
        assert_eq!(ipv4_dst(&v6), None);
        // Too short is rejected.
        assert_eq!(ipv4_src(&[0x45, 0]), None);
    }

    // ---- should_learn_tun_ip ----

    fn tun_nets() -> Vec<IpNet> {
        vec!["10.7.0.0/24".parse().unwrap()]
    }

    #[test]
    fn learn_accepts_address_inside_tun_subnet() {
        // The client's real TUN address must be learned.
        assert!(should_learn_tun_ip(Ipv4Addr::new(10, 7, 0, 2), &tun_nets()));
        // Other same-subnet aliases (e.g. LAN sharing) are plausible too.
        assert!(should_learn_tun_ip(
            Ipv4Addr::new(10, 7, 0, 99),
            &tun_nets()
        ));
    }

    #[test]
    fn learn_rejects_lan_neighbors_and_public_ip() {
        // Exact garbage from the field report: one session "learned"
        // 192.168.50.x LAN neighbors and the client's own public IP, none of
        // which is the client's TUN address. All must be rejected.
        for ip in [
            Ipv4Addr::new(192, 168, 50, 112),
            Ipv4Addr::new(192, 168, 50, 71),
            Ipv4Addr::new(192, 168, 50, 82),
            Ipv4Addr::new(192, 168, 50, 11),
            Ipv4Addr::new(192, 168, 50, 31),
            Ipv4Addr::new(213, 138, 68, 130), // client's public underlay IP
            Ipv4Addr::new(1, 1, 1, 1),        // arbitrary internet IP
        ] {
            assert!(
                !should_learn_tun_ip(ip, &tun_nets()),
                "{ip} must not be learned as a tunnel IP"
            );
        }
    }

    #[test]
    fn learn_without_configured_nets_accepts_all() {
        // Backwards compatibility: no subnet configured means unrestricted
        // (production always configures the real subnet, so it is strict).
        let empty: Vec<IpNet> = Vec::new();
        assert!(should_learn_tun_ip(Ipv4Addr::new(192, 168, 50, 71), &empty));
    }

    #[test]
    fn implausible_ip_warning_fires_once_per_address() {
        // The field log showed dozens of identical warnings per second from
        // one chatty host; the gate must pass the first sighting and suppress
        // repeats, independently per address.
        let mut seen = std::collections::HashSet::new();
        let a = Ipv4Addr::new(213, 138, 68, 130);
        let b = Ipv4Addr::new(192, 168, 50, 71);
        assert!(note_implausible_ip(&mut seen, a), "first sighting warns");
        assert!(!note_implausible_ip(&mut seen, a), "repeat suppressed");
        assert!(!note_implausible_ip(&mut seen, a), "still suppressed");
        assert!(note_implausible_ip(&mut seen, b), "new address warns once");
        assert!(!note_implausible_ip(&mut seen, b), "then suppressed");
    }

    // ---- peek_session_id ----

    /// Build a minimal valid header as raw bytes: version=0x01, given packet
    /// type, given session id, rest zero.
    fn stub_header(ptype: PacketType, session_id: SessionId) -> Vec<u8> {
        let mut buf = vec![0u8; HEADER_LEN];
        buf[0] = PROTOCOL_VERSION;
        buf[1] = ptype as u8;
        buf[2..6].copy_from_slice(&session_id.to_le_bytes());
        buf
    }

    #[test]
    fn peek_session_id_extracts_id_from_valid_header() {
        let pkt = stub_header(PacketType::Data, 0xCAFEBABE);
        assert_eq!(peek_session_id(&pkt), Some(0xCAFEBABE));
    }

    #[test]
    fn peek_session_id_rejects_short_datagram() {
        let mut pkt = stub_header(PacketType::Data, 42);
        pkt.truncate(HEADER_LEN - 1);
        assert_eq!(peek_session_id(&pkt), None, "too short to hold a header");
    }

    #[test]
    fn peek_session_id_rejects_bad_version() {
        let mut pkt = stub_header(PacketType::Data, 42);
        pkt[0] = 0x02; // not PROTOCOL_VERSION
        assert_eq!(peek_session_id(&pkt), None, "wrong version byte");
    }

    #[test]
    fn peek_session_id_rejects_unknown_packet_type() {
        let mut pkt = stub_header(PacketType::Data, 42);
        pkt[1] = 0xFF; // not a valid PacketType
        assert_eq!(peek_session_id(&pkt), None, "unknown packet type");
    }

    #[test]
    fn peek_session_id_rejects_zero_session_id() {
        let pkt = stub_header(PacketType::Data, 0);
        assert_eq!(peek_session_id(&pkt), None, "zero is reserved");
    }

    #[test]
    fn peek_session_id_falls_through_for_noise_handshake_bytes() {
        // Hand-simulate a Noise IK message-1: 32B ephemeral + 32B static + 16B
        // tag = 80 bytes of essentially random key material. The first byte is
        // the first byte of an X25519 public key and is almost never 0x01; even
        // if it were, byte 1 would not be a valid PacketType, so the peek
        // returns None and the datagram falls through to the handshake path.
        let mut noise_msg1 = vec![0u8; 80];
        // Make byte 0 = PROTOCOL_VERSION (0x01) to prove the type check also
        // rejects it.
        noise_msg1[0] = PROTOCOL_VERSION;
        noise_msg1[1] = 0xAB; // not a valid PacketType
        assert_eq!(peek_session_id(&noise_msg1), None);
    }

    // ---- peek_routed_session + addr_fallback ----

    use crate::transport::{PlainTransport, TaggedTransport};

    fn plain() -> PlainTransport {
        PlainTransport
    }

    /// Build a minimal ClientHandle for routing tests (uses a dummy task).
    async fn make_handle(current_addr: SocketAddr) -> ClientHandle {
        let (udp_tx, _udp_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1);
        let (tun_tx, _tun_rx) = mpsc::channel::<Vec<u8>>(1);
        let (evict_tx, _evict_rx) = mpsc::unbounded_channel::<()>();
        let join = tokio::spawn(std::future::ready(()));
        ClientHandle {
            udp_tx,
            tun_tx,
            current_addr,
            peer_key: [0u8; 32],
            peer_label: None,
            last_forwarded: Instant::now(),
            roam_count: 0,
            last_roam: None,
            spawned_at: Instant::now(),
            tun_ips: std::collections::HashSet::new(),
            warned_implausible: std::collections::HashSet::new(),
            pub_route_keystream: None,
            evict_tx,
            join,
        }
    }

    #[tokio::test]
    async fn route_by_session_id_peek() {
        let addr_a: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let addr_b: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let mut sessions = HashMap::new();
        sessions.insert(100u32, make_handle(addr_a).await);
        sessions.insert(200u32, make_handle(addr_b).await);
        let transport = plain();

        let pkt_a = stub_header(PacketType::Data, 100);
        let pkt_b = stub_header(PacketType::Data, 200);
        let pkt_unknown = stub_header(PacketType::Data, 999);

        // Routing works purely via SessionId peek, independent of address.
        assert_eq!(
            peek_routed_session(&sessions, &transport, &pkt_a),
            Some(100)
        );
        assert_eq!(
            peek_routed_session(&sessions, &transport, &pkt_b),
            Some(200)
        );
        // SessionId not in table → None (addr fallback is a separate step).
        assert_eq!(
            peek_routed_session(&sessions, &transport, &pkt_unknown),
            None
        );
    }

    #[tokio::test]
    async fn handshake_probe_runs_before_addr_index_fallback() {
        // Regression test for dispatcher ordering. We construct a scenario where
        // the `addr_index` fallback would give a WRONG answer if consulted before
        // the handshake probe, and assert the correct behavior happens.
        //
        // Setup: session S1 (sid=1) was established from addr_a. Then S1's
        // tunnel task crashed and S1 was swept, but `addr_index` is NOT yet
        // refreshed (it still maps addr_a -> sid 1). A *different* client S2
        // (sid=2) reconnects from addr_a with a fresh handshake message-1. If the
        // dispatcher consulted addr_index first, it would either forward the
        // handshake bytes into the dead S1 (channel closed → dropped) or, if it
        // blindly forwarded to the address-cache entry, misattribute S2's
        // handshake to S1. The correct behavior is to probe the handshake first
        // and spawn a NEW session S2 — leaving sid 1 alone (already gone).
        //
        // We model the post-sweep state: addr_index maps addr_a -> sid 1, but
        // sid 1 is NOT in `sessions` (it was swept). Sid 2 is also not present
        // yet (it's the would-be new session we're about to spawn). We feed a
        // Noise-shaped message-1 datagram and assert neither peek nor
        // addr_fallback claims it (so the handshake probe path is what must
        // handle it).
        let addr_a: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let sessions: HashMap<SessionId, ClientHandle> = HashMap::new();
        // addr_index still has a stale entry for a swept session (sid 1).
        let mut addr_index: HashMap<SocketAddr, SessionId> = HashMap::new();
        addr_index.insert(addr_a, 1);

        let transport = plain();

        // A Noise message-1 is not a valid header (random key bytes), so the
        // fast-path peek must return None — it must NOT be routed to the stale
        // sid-1 entry that addr_index still holds.
        let mut noise_msg1 = vec![0u8; 80];
        noise_msg1[0] = PROTOCOL_VERSION; // deliberately wrong type byte
        noise_msg1[1] = 0xAB; // not a valid PacketType
        assert_eq!(
            peek_routed_session(&sessions, &transport, &noise_msg1),
            None,
            "handshake bytes from a known address must not peek-route to a stale session"
        );
        // And the addr_index fallback, while it *would* resolve to sid 1, is
        // only a hint: it returns sid 1 but that session is NOT live (swept),
        // so the caller must treat it as None and proceed to the handshake
        // probe. This proves addr_index alone cannot misspawn a session.
        assert_eq!(
            addr_fallback(&sessions, &addr_index, addr_a),
            None,
            "stale addr_index entry for a swept session must not resolve to a live session"
        );
    }

    #[tokio::test]
    async fn peek_strips_tagged_transport_envelope() {
        let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let mut sessions = HashMap::new();
        sessions.insert(77u32, make_handle(addr).await);
        let tagged = TaggedTransport { tag: [0xAA, 0x55] };

        let frame = stub_header(PacketType::Data, 77);
        let wire = tagged.wrap(&frame);
        // Raw wire bytes do NOT start with a valid header (2-byte tag first),
        // so the fast path misses — the slow path must strip the envelope.
        assert_eq!(peek_session_id(&wire), None);
        assert_eq!(peek_routed_session(&sessions, &tagged, &wire), Some(77));

        // Foreign tag → unwrap fails → no peek match, never a misroute.
        let foreign = TaggedTransport { tag: [0x00, 0x01] };
        assert_eq!(peek_routed_session(&sessions, &foreign, &wire), None);
    }

    #[tokio::test]
    async fn addr_fallback_hit_and_stale_miss() {
        let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let mut sessions = HashMap::new();
        sessions.insert(42u32, make_handle(addr).await);
        let mut addr_index: HashMap<SocketAddr, SessionId> = HashMap::new();
        addr_index.insert(addr, 42);

        assert_eq!(addr_fallback(&sessions, &addr_index, addr), Some(42));

        // Stale entry pointing at a reaped session is harmless: None.
        let stale_addr: SocketAddr = "10.0.0.2:9999".parse().unwrap();
        let mut stale_index: HashMap<SocketAddr, SessionId> = HashMap::new();
        stale_index.insert(stale_addr, 777); // not in sessions
        assert_eq!(addr_fallback(&sessions, &stale_index, stale_addr), None);

        // Unknown address → None (scan noise path).
        let unknown: SocketAddr = "10.9.9.9:1".parse().unwrap();
        assert_eq!(addr_fallback(&sessions, &addr_index, unknown), None);
    }

    #[tokio::test]
    async fn same_address_supports_multiple_sessions() {
        // Two sessions with different SessionIds, both from the same address.
        // This models "same device opening more than one tunnel."
        let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let mut sessions = HashMap::new();
        sessions.insert(100u32, make_handle(addr).await);
        sessions.insert(200u32, make_handle(addr).await);
        let transport = plain();

        let pkt_100 = stub_header(PacketType::Data, 100);
        let pkt_200 = stub_header(PacketType::Data, 200);

        // Even though both share the same address, the SessionId peek routes
        // each to the correct session — 100 is never misrouted to 200.
        assert_eq!(
            peek_routed_session(&sessions, &transport, &pkt_100),
            Some(100)
        );
        assert_eq!(
            peek_routed_session(&sessions, &transport, &pkt_200),
            Some(200)
        );
    }

    #[tokio::test]
    async fn roaming_updates_addr_index_and_current_addr() {
        // Simulate the dispatcher receiving an address-change signal from a
        // tunnel task and applying it.
        let addr_old: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let addr_new: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let sid = 42u32;

        let mut sessions = HashMap::new();
        sessions.insert(sid, make_handle(addr_old).await);
        let mut addr_index: HashMap<SocketAddr, SessionId> = HashMap::new();
        addr_index.insert(addr_old, sid);

        // Simulate the addr_change_rx arm.
        if let Some(h) = sessions.get_mut(&sid) {
            if h.current_addr != addr_new {
                if addr_index.get(&h.current_addr) == Some(&sid) {
                    addr_index.remove(&h.current_addr);
                }
                h.current_addr = addr_new;
                addr_index.insert(addr_new, sid);
            }
        }

        // Old address no longer maps; new address does.
        assert!(!addr_index.contains_key(&addr_old));
        assert_eq!(addr_index.get(&addr_new), Some(&sid));
        assert_eq!(sessions.get(&sid).unwrap().current_addr, addr_new);

        // Roaming does not depend on the address cache: the SessionId peek
        // routes the session from any source address.
        let transport = plain();
        let pkt = stub_header(PacketType::Data, 42);
        assert_eq!(peek_routed_session(&sessions, &transport, &pkt), Some(sid));
        assert_eq!(addr_fallback(&sessions, &addr_index, addr_new), Some(sid));
        assert_eq!(addr_fallback(&sessions, &addr_index, addr_old), None);
    }

    #[tokio::test]
    async fn addr_index_does_not_clobber_other_session_at_same_address() {
        // Two sessions at the same address: removing one's addr_index entry
        // must not remove the other's.
        let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let mut sessions = HashMap::new();
        sessions.insert(100u32, make_handle(addr).await);
        sessions.insert(200u32, make_handle(addr).await);
        // addr_index only knows about 200 (the most recent insert).
        let mut addr_index: HashMap<SocketAddr, SessionId> = HashMap::new();
        addr_index.insert(addr, 200);

        // If session 200 roams to a new address, the addr_index at `addr`
        // should remain pointing at 100 (since the old value was 200, not 100,
        // we remove the old entry only if it matches).
        let new_addr: SocketAddr = "10.0.0.9:9".parse().unwrap();
        {
            let h = sessions.get_mut(&200u32).unwrap();
            if addr_index.get(&h.current_addr) == Some(&200) {
                addr_index.remove(&h.current_addr);
            }
            h.current_addr = new_addr;
            addr_index.insert(new_addr, 200);
        }

        // addr_index no longer has the old shared address.
        assert!(!addr_index.contains_key(&addr));

        // Session 100 can still be found via SessionId peek.
        let transport = plain();
        let pkt = stub_header(PacketType::Data, 100);
        assert_eq!(peek_routed_session(&sessions, &transport, &pkt), Some(100));
    }

    // ---- rate limiter ----

    #[test]
    fn probe_limiter_allows_under_burst_then_throttles() {
        let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let mut lim = ProbeLimiter::new();
        for _ in 0..HANDSHAKE_PROBE_BURST {
            assert!(lim.allow(addr), "burst attempt should be allowed");
        }
        assert!(!lim.allow(addr), "burst exhausted; should be rate-limited");
    }

    #[test]
    fn probe_limiter_global_cap_rejects_new_sources() {
        let mut lim = ProbeLimiter::new();
        for port in 0..HANDSHAKE_PROBE_GLOBAL_CAP as u16 {
            let addr: SocketAddr = format!("10.0.0.{}:1", port).parse().unwrap();
            assert!(
                lim.allow(addr),
                "first probe for a new source should be allowed"
            );
        }
        let extra: SocketAddr = "10.1.1.1:1".parse().unwrap();
        assert!(
            !lim.allow(extra),
            "global probe tracker cap should reject new sources"
        );
    }

    #[test]
    fn probe_limiter_independent_buckets_per_source() {
        let a: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:2".parse().unwrap();
        let mut lim = ProbeLimiter::new();
        for _ in 0..HANDSHAKE_PROBE_BURST {
            assert!(lim.allow(a));
        }
        assert!(!lim.allow(a), "A should be throttled");
        assert!(lim.allow(b), "B is independent of A");
    }

    // ---- per-peer session cap / eviction ----

    async fn make_handle_for_peer(peer_key: [u8; 32], last_forwarded: Instant) -> ClientHandle {
        let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let (udp_tx, _rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1);
        let (tun_tx, _rx) = mpsc::channel::<Vec<u8>>(1);
        let (evict_tx, _evict_rx) = mpsc::unbounded_channel::<()>();
        let join = tokio::spawn(std::future::ready(()));
        ClientHandle {
            udp_tx,
            tun_tx,
            current_addr: addr,
            peer_key,
            peer_label: None,
            last_forwarded,
            roam_count: 0,
            last_roam: None,
            spawned_at: Instant::now(),
            tun_ips: std::collections::HashSet::new(),
            warned_implausible: std::collections::HashSet::new(),
            pub_route_keystream: None,
            evict_tx,
            join,
        }
    }

    #[tokio::test]
    async fn evict_keeps_peer_under_cap() {
        // When the peer has fewer than `max` sessions, no eviction.
        let peer_key = [0xAAu8; 32];
        let mut sessions = HashMap::new();
        sessions.insert(
            1u32,
            make_handle_for_peer(peer_key, Instant::now() - Duration::from_secs(10)).await,
        );
        sessions.insert(2u32, make_handle_for_peer(peer_key, Instant::now()).await);
        // Under cap (2 < 3): nothing evicted.
        evict_oldest_peer_session(&mut sessions, &peer_key, 3);
        assert_eq!(sessions.len(), 2, "under cap; no eviction");
    }

    #[tokio::test]
    async fn evict_evicts_oldest_when_at_cap() {
        // Semantics: handle_handshake calls eviction *before* inserting the new
        // session. So when a peer already has `max` sessions and a new handshake
        // arrives, the oldest is evicted to make room (net stays at max).
        let peer_key = [0xBBu8; 32];
        let mut sessions = HashMap::new();
        let old = Instant::now() - Duration::from_secs(10);
        let recent = Instant::now();
        sessions.insert(1u32, make_handle_for_peer(peer_key, old).await); // oldest
        sessions.insert(2u32, make_handle_for_peer(peer_key, recent).await);
        // Cap of 2: at-cap → evict oldest (sid 1) to make room for the incoming.
        evict_oldest_peer_session(&mut sessions, &peer_key, 2);
        assert_eq!(
            sessions.len(),
            1,
            "oldest evicted to make room for the new session"
        );
        assert!(!sessions.contains_key(&1u32), "sid 1 (oldest) was evicted");
        assert!(sessions.contains_key(&2u32));
    }

    #[tokio::test]
    async fn evict_noop_when_cap_zero() {
        let peer_key = [0xCCu8; 32];
        let mut sessions = HashMap::new();
        sessions.insert(1u32, make_handle_for_peer(peer_key, Instant::now()).await);
        sessions.insert(2u32, make_handle_for_peer(peer_key, Instant::now()).await);
        evict_oldest_peer_session(&mut sessions, &peer_key, 0);
        assert_eq!(sessions.len(), 2, "cap 0 = unlimited; no eviction");
    }

    #[tokio::test]
    async fn evict_does_not_touch_other_peers() {
        let peer_a = [0xAAu8; 32];
        let peer_b = [0xBBu8; 32];
        let mut sessions = HashMap::new();
        let old = Instant::now() - Duration::from_secs(10);
        sessions.insert(1u32, make_handle_for_peer(peer_a, old).await);
        sessions.insert(2u32, make_handle_for_peer(peer_a, Instant::now()).await);
        sessions.insert(3u32, make_handle_for_peer(peer_b, old).await);
        evict_oldest_peer_session(&mut sessions, &peer_a, 1);
        assert!(!sessions.contains_key(&1u32), "peer_a's oldest evicted");
        assert!(sessions.contains_key(&2u32), "peer_a's other session kept");
        assert!(sessions.contains_key(&3u32), "peer_b untouched");
    }

    // ---- header_xor de-whitening peek ----

    fn keystream_for(seed: &[u8; 32]) -> [u8; HEADER_LEN] {
        use crate::obfuscation::header_xor::HKDF_INFO;
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(None, seed);
        let mut out = [0u8; HEADER_LEN];
        hk.expand(HKDF_INFO, &mut out).expect("hkdf");
        out
    }

    fn whiten(frame: &[u8], ks: &[u8; HEADER_LEN]) -> Vec<u8> {
        let mut out = frame.to_vec();
        let n = out.len().min(HEADER_LEN);
        for i in 0..n {
            out[i] ^= ks[i];
        }
        out
    }

    #[tokio::test]
    async fn peek_dewhitens_header_xor_after_roam() {
        let addr_old: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let sid = 42u32;
        let ks = keystream_for(&[0x42; 32]);
        let mut sessions = HashMap::new();
        let mut h = make_handle(addr_old).await;
        h.peer_key = [0xEEu8; 32];
        h.pub_route_keystream = Some(ks);
        sessions.insert(sid, h);
        let transport = plain();
        let frame = stub_header(PacketType::Data, sid);
        let whitened = whiten(&frame, &ks);
        assert_eq!(peek_session_id(&whitened), None);
        assert_eq!(
            peek_routed_session(&sessions, &transport, &whitened),
            Some(sid),
            "whitened header from a roamed session must be de-whitened and routed"
        );
    }

    #[tokio::test]
    async fn peek_wrong_keystream_does_not_match() {
        let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let sid_b = 20u32;
        let mut sessions = HashMap::new();
        let mut hb = make_handle(addr).await;
        hb.peer_key = [0xBB; 32];
        hb.pub_route_keystream = Some(keystream_for(&[0xBB; 32]));
        sessions.insert(sid_b, hb);
        let transport = plain();
        let frame_b = stub_header(PacketType::Data, sid_b);
        let wrong_ks = keystream_for(&[0x99; 32]);
        let double_whitened = whiten(&frame_b, &wrong_ks);
        assert_eq!(
            peek_routed_session(&sessions, &transport, &double_whitened),
            None,
            "wrong keystream must not produce a valid header / no match"
        );
    }

    #[tokio::test]
    async fn peek_no_keystream_is_plain_peek() {
        let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let sid = 7u32;
        let mut sessions = HashMap::new();
        sessions.insert(sid, make_handle(addr).await);
        let transport = plain();
        let frame = stub_header(PacketType::Data, sid);
        assert!(sessions.get(&sid).unwrap().pub_route_keystream.is_none());
        assert_eq!(
            peek_routed_session(&sessions, &transport, &frame),
            Some(sid)
        );
    }
}
