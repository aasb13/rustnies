//! Integration test: full client<->server pipeline over loopback UDP with
//! in-memory TUN stubs (no root, no real TUN device).
//!
//! This validates that the Noise IK handshake establishes, that TUN packets
//! flow both directions through the encrypted/FEC'd protocol stack, and that
//! adaptive FEC recovers an injected erasure.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustnies::carrier::{Carrier, TcpCarrier, UdpCarrier, UdpListener};
use rustnies::crypto::aead::Direction;
use rustnies::crypto::keys::KeyPair;
use rustnies::crypto::noise::{HandshakeRole, NoiseHandshake};
use rustnies::obfuscation::ObfuscationStack;
use rustnies::platform::LinuxTunFactory;
use rustnies::platform::linux::{Decision, KillSwitch, RecordedBackend, evaluate_packet};
use rustnies::protocol::profile::{LocalProfile, ResolvedProfile};
use rustnies::protocol::session::session_id_from_hash;
use rustnies::protocol::session::{Session, SessionRole};
use rustnies::stats::Counters;
use rustnies::transport::default_transport;
use rustnies::tun::{Tun, TunFactory, TunFut};
use rustnies::tunnel::{Tunnel, TunnelExit, handshake};

use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc, watch};

/// Wrap a raw test socket as a UDP carrier.
///
/// The tests drive real sockets (relays, loss injectors) rather than mock
/// carriers, so they adapt at the seam boundary instead of re-plumbing every
/// call site.
fn udp_carrier(sock: &Arc<UdpSocket>, peer: SocketAddr) -> Arc<dyn Carrier> {
    Arc::new(UdpCarrier::new(sock.clone(), peer))
}
/// An in-memory TUN that captures written packets into a channel and feeds
/// canned packets back. Implements [`rustnies::tun::Tun`].
#[allow(dead_code)]
struct MemTun {
    name: String,
    mtu: u32,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
}

impl Tun for MemTun {
    fn recv<'a>(&'a mut self, _buf: &'a mut [u8]) -> TunFut<'a> {
        Box::pin(async move {
            // Wait for a canned packet; copy into buf.
            let mut rx = self.rx.lock().await;
            match rx.recv().await {
                Some(p) => {
                    let n = p.len().min(_buf.len());
                    _buf[..n].copy_from_slice(&p[..n]);
                    Ok(n)
                }
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "tun closed",
                )),
            }
        })
    }
    fn send<'a>(&'a mut self, buf: &'a [u8]) -> TunFut<'a> {
        Box::pin(async move {
            self.tx.send(buf.to_vec()).expect("tun channel open");
            Ok(buf.len())
        })
    }
    fn name(&self) -> std::io::Result<String> {
        Ok(self.name.clone())
    }
    fn mtu(&self) -> std::io::Result<u32> {
        Ok(self.mtu)
    }
}

impl MemTun {
    /// Build a MemTun plus the two ends the test drives it with.
    ///
    /// Returns `(tun, inject, rx)`: `inject` feeds packets *into* the tunnel
    /// (as if they arrived from the OS), and `rx` receives packets the tunnel
    /// wrote *out* to the OS.
    fn pair(
        name: &str,
        mtu: u32,
    ) -> (
        Box<dyn Tun>,
        mpsc::UnboundedSender<Vec<u8>>,
        mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        let (outbound, rx) = mpsc::unbounded_channel(); // tunnel -> OS
        let (inject, inbound) = mpsc::unbounded_channel(); // OS -> tunnel
        (
            Box::new(MemTun {
                name: name.to_string(),
                mtu,
                tx: outbound,
                rx: Mutex::new(inbound),
            }),
            inject,
            rx,
        )
    }
}

/// Feed a tunnel from a carrier, exactly as the daemon's reader task does.
///
/// The daemon's client-side reader is `socket_reader` over a [`Carrier`], so
/// this is the same shape for every carrier. The source address travels with
/// each message because the tunnel's roaming logic consumes it.
async fn carrier_reader(carrier: Arc<dyn Carrier>, tx: mpsc::Sender<(Vec<u8>, SocketAddr)>) {
    loop {
        match carrier.recv().await {
            Ok((data, from)) => {
                if tx.send((data.to_vec(), from)).await.is_err() {
                    break; // tunnel gone
                }
            }
            Err(e) => {
                eprintln!("carrier_reader exiting: {e:?}");
                break;
            }
        }
    }
}

/// A TunFactory that hands out MemTun instances (ignores name/addr).
#[allow(dead_code)]
struct MemTunFactory;

impl TunFactory for MemTunFactory {
    fn build(
        &self,
        name: &str,
        _ipv4: &str,
        _prefix: u8,
        _ipv6: Option<(&str, u8)>,
        mtu: u32,
    ) -> std::io::Result<Box<dyn Tun>> {
        let (tx, _rx_capture) = mpsc::unbounded_channel();
        let (_tx_feed, rx) = mpsc::unbounded_channel();
        Ok(Box::new(MemTun {
            name: name.to_string(),
            mtu,
            tx,
            rx: Mutex::new(rx),
        }))
    }
    fn from_fd(&self, _fd: std::os::fd::RawFd) -> std::io::Result<Box<dyn Tun>> {
        unreachable!("mem tun has no fd")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_to_end_handshake_and_data() {
    // Two UDP sockets on loopback.
    let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr: SocketAddr = server_sock.local_addr().unwrap();
    let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let server_kp = KeyPair::generate();
    let client_kp = KeyPair::generate();

    // Run server handshake in a task.
    let server_kp_clone = clone_keypair(&server_kp);
    let server_handle = tokio::spawn(async move {
        handshake::server(
            udp_carrier(&server_sock, server_addr),
            server_kp_clone,
            default_profile(),
            &ObfuscationStack::new(),
        )
        .await
        .unwrap()
    });

    // Client handshake.
    let established_client = tokio::time::timeout(
        Duration::from_secs(5),
        handshake::client(
            udp_carrier(&client_sock, server_addr),
            server_addr,
            &client_kp,
            server_kp.public,
            &default_profile(),
            &ObfuscationStack::new(),
        ),
    )
    .await
    .expect("client handshake timed out")
    .expect("client handshake failed");

    let established_server = tokio::time::timeout(Duration::from_secs(5), server_handle)
        .await
        .expect("server join timed out")
        .expect("server task panicked");

    // Both sides should have matching keys.
    assert_eq!(
        established_client.send_key, established_server.recv_key,
        "client send key == server recv key"
    );
    assert_eq!(
        established_client.recv_key, established_server.send_key,
        "client recv key == server send key"
    );
    assert_eq!(
        established_client.session_id, established_server.session_id,
        "session ids match"
    );

    // Smoke-test the static TUN factory is reachable (proves the platform
    // abstraction compiles and links). We don't actually open a TUN here
    // (needs root); just confirm the factory exists.
    let _factory = LinuxTunFactory;
}

/// Direct Noise handshake unit test mirroring the crypto module's own test, but
/// routed through the tunnel's handshake helpers' underlying types.
#[tokio::test]
async fn noise_handshake_keys_match() {
    // The transport-key HKDF context production supplies from the negotiated
    // suite. Both peers must use the same one, or the derived keys diverge.
    const SCHEDULE: &[u8] = b"rustnies/aead/chacha20poly1305";

    let server = KeyPair::generate();
    let client = KeyPair::generate();

    let mut init = NoiseHandshake::new(
        HandshakeRole::Initiator,
        clone_keypair(&client),
        Some(server.public),
    );
    let mut resp = NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server), None);

    let m1 = init.write_message_1(&[]).unwrap();
    let _ = resp.read_message_1(&m1).unwrap();
    let (m2, sr) = resp.write_message_2(b"hi", SCHEDULE).unwrap();
    let (payload, cr) = init.read_message_2(&m2, |_| SCHEDULE.to_vec()).unwrap();

    assert_eq!(payload, b"hi");
    assert_eq!(cr.key_i2r, sr.key_i2r);
    assert_eq!(cr.key_r2i, sr.key_r2i);
    assert_eq!(cr.handshake_hash, sr.handshake_hash);

    // session id derived from the handshake hash should be non-zero.
    let id = session_id_from_hash(&cr.handshake_hash);
    assert_ne!(id, 0);
    // And a Session can be constructed for either role.
    let _s = Session::new(id, SessionRole::Initiator);
    let _s = Session::new(id, SessionRole::Responder);
    // Direction enum is usable.
    let _d = Direction::InitiatorToResponder;
}

/// The rustnies default profile, built through the same
/// `LocalProfile::from_role_config` path the daemon uses with an empty config.
/// Tests that want a non-default profile build one explicitly.
fn default_profile() -> LocalProfile {
    LocalProfile::from_role_config(
        &Default::default(),
        &Default::default(),
        &Default::default(),
        &Default::default(),
        &Default::default(),
        &Default::default(),
    )
    .expect("the default config must resolve to a usable profile")
}

/// Instantiate the profile both peers agreed on, exactly as the daemon does
/// after a handshake.
fn resolved_profile(
    local: &LocalProfile,
    established: &handshake::SessionEstablished,
) -> ResolvedProfile {
    ResolvedProfile::with_handshake_transport(
        &established.selection,
        &established.handshake_hash,
        &*local.handshake_transport,
        local.new_congestion(),
    )
    .expect("the negotiated selection must be instantiable on both ends")
}

fn clone_keypair(kp: &KeyPair) -> KeyPair {
    let bytes = kp.secret.to_bytes();
    let secret = rustnies::crypto::keys::StaticSecret::from(bytes);
    let public = rustnies::crypto::keys::PublicKey::from(&secret);
    KeyPair { secret, public }
}

/// Peer authorization: a handshake from a client whose static key is NOT in
/// the server's authorized list must be rejected — `respond_message_1` returns
/// `None` and no session is created. A handshake from an authorized key
/// succeeds.
#[tokio::test]
async fn handshake_rejected_for_unauthorized_key() {
    let server_kp = KeyPair::generate();
    let authorized_client = KeyPair::generate();
    let rogue_client = KeyPair::generate();

    // The server only authorizes `authorized_client`.
    let auth_fn: Box<dyn Fn(&rustnies::crypto::keys::PublicKey) -> (bool, Option<String>)> =
        Box::new({
            let allowed = authorized_client.public_bytes();
            move |pk| {
                if pk.to_bytes() == allowed {
                    (true, Some("authorized_client".to_string()))
                } else {
                    (false, None)
                }
            }
        });

    // Build a message 1 from the rogue (unauthorized) client.
    let mut rogue_hs = NoiseHandshake::new(
        HandshakeRole::Initiator,
        clone_keypair(&rogue_client),
        Some(server_kp.public),
    );
    let rogue_m1 = rogue_hs.write_message_1(&[]).unwrap();
    let rogue_wire = default_transport().wrap(&rogue_m1);

    // The server should reject it.
    let result = handshake::respond_message_1(
        &server_kp,
        &default_profile(),
        &ObfuscationStack::new(),
        &rogue_wire,
        "127.0.0.1:9999".parse().unwrap(),
        Some(&*auth_fn),
    );
    assert!(
        result.is_none(),
        "unauthorized client handshake must be rejected"
    );

    // Build a message 1 from the authorized client.
    let mut good_hs = NoiseHandshake::new(
        HandshakeRole::Initiator,
        clone_keypair(&authorized_client),
        Some(server_kp.public),
    );
    let good_m1 = good_hs.write_message_1(&[]).unwrap();
    let good_wire = default_transport().wrap(&good_m1);

    // The server should accept it and produce message 2.
    let result = handshake::respond_message_1(
        &server_kp,
        &default_profile(),
        &ObfuscationStack::new(),
        &good_wire,
        "127.0.0.1:8888".parse().unwrap(),
        Some(&*auth_fn),
    );
    assert!(
        result.is_some(),
        "authorized client handshake must be accepted"
    );
    let (established, _m2) = result.unwrap();
    assert_eq!(
        established.peer_static.to_bytes(),
        authorized_client.public_bytes(),
        "server learned the correct client static key"
    );
    assert_eq!(
        established.peer_label.as_deref(),
        Some("authorized_client"),
        "established session carries the matched peer label"
    );
}

/// Without an authorizer (open mode), every handshake is accepted.
#[tokio::test]
async fn handshake_open_mode_accepts_all() {
    let server_kp = KeyPair::generate();
    let client_kp = KeyPair::generate();

    let mut hs = NoiseHandshake::new(
        HandshakeRole::Initiator,
        clone_keypair(&client_kp),
        Some(server_kp.public),
    );
    let m1 = hs.write_message_1(&[]).unwrap();
    let wire = default_transport().wrap(&m1);

    let result = handshake::respond_message_1(
        &server_kp,
        &default_profile(),
        &ObfuscationStack::new(),
        &wire,
        "127.0.0.1:7777".parse().unwrap(),
        None,
    );
    assert!(result.is_some(), "open mode accepts any peer");
}

// ---------------------------------------------------------------------------
// Kill switch + DNS leak prevention integration tests.
//
// These exercise the firewall policy against a *real* loopback Noise IK
// session: the handshake runs over actual UDP sockets, a Tunnel::run loop is
// driven, and the server is killed mid-session to confirm the client's kill
// switch keeps blocking direct internet (fail closed) until a graceful
// shutdown. A recorded (in-memory) firewall backend stands in for iptables
// so no root is required; the policy is verified with `evaluate_packet`.
// ---------------------------------------------------------------------------

/// A TUN stub whose `recv` never resolves, so the steady-state loop's TUN
/// branch never fires and the session-timeout/UDP branches drive the tunnel
/// (a real TUN would block on the FD the same way when no packets arrive).
struct PendingTun {
    name: String,
    mtu: u32,
}

impl Tun for PendingTun {
    fn recv<'a>(&'a mut self, _buf: &'a mut [u8]) -> TunFut<'a> {
        Box::pin(async move { std::future::pending::<std::io::Result<usize>>().await })
    }
    fn send<'a>(&'a mut self, buf: &'a [u8]) -> TunFut<'a> {
        Box::pin(async move { Ok(buf.len()) })
    }
    fn name(&self) -> std::io::Result<String> {
        Ok(self.name.clone())
    }
    fn mtu(&self) -> std::io::Result<u32> {
        Ok(self.mtu)
    }
}

/// Read UDP datagrams from `sock` and forward them onto `tx` until the socket
/// closes or all receivers are dropped (mirrors the daemon's client
/// socket-reader).
async fn socket_reader(sock: Arc<UdpSocket>, tx: mpsc::Sender<(Vec<u8>, SocketAddr)>) {
    let mut buf = vec![0u8; 65535];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((n, from)) => {
                if tx.send((buf[..n].to_vec(), from)).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

/// The headline kill-switch test: establish a real tunnel, kill the server
/// mid-session, and confirm the client still has no direct internet access
/// (fail closed) until a graceful shutdown removes the rules.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kill_switch_fail_closed_on_real_tunnel_drop() {
    // Two UDP sockets on loopback.
    let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr: SocketAddr = server_sock.local_addr().unwrap();
    let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let server_kp = KeyPair::generate();
    let client_kp = KeyPair::generate();

    // Run the Noise IK handshake over the real sockets.
    let server_kp_clone = clone_keypair(&server_kp);
    let server_handle = tokio::spawn({
        let carrier = udp_carrier(&server_sock, server_addr);
        async move {
            handshake::server(
                carrier,
                server_kp_clone,
                default_profile(),
                &ObfuscationStack::new(),
            )
            .await
            .unwrap()
        }
    });
    let established_client = tokio::time::timeout(
        Duration::from_secs(5),
        handshake::client(
            udp_carrier(&client_sock, server_addr),
            server_addr,
            &client_kp,
            server_kp.public,
            &default_profile(),
            &ObfuscationStack::new(),
        ),
    )
    .await
    .expect("client handshake timed out")
    .expect("client handshake failed");
    let _established_server = tokio::time::timeout(Duration::from_secs(5), server_handle)
        .await
        .expect("server join timed out")
        .expect("server task panicked");

    // The kill switch is installed before the tunnel runs (the daemon installs
    // it at startup). Use a recorded backend so we can inspect the policy
    // without root.
    let backend = Arc::new(RecordedBackend::new());
    let mut ks = KillSwitch::new(server_addr, "rustnies0", backend.clone());
    ks.install().unwrap();
    assert!(ks.is_active(), "kill switch engaged at startup");

    // Client tunnel with a short session timeout so the drop is detected fast.
    let client_tun = Box::new(PendingTun {
        name: "rustnies0".into(),
        mtu: 1400,
    });
    let mut client_tunnel = Tunnel::from_handshake(
        client_tun,
        udp_carrier(&client_sock, server_addr),
        established_client.peer,
        Session::new(established_client.session_id, SessionRole::Initiator),
        resolved_profile(&default_profile(), &established_client),
        ObfuscationStack::new(),
        established_client.send_key,
        established_client.recv_key,
        established_client.send_dir,
        established_client.recv_dir,
        Arc::new(Mutex::new(Counters::new())),
    )
    .unwrap();
    // keepalive every 100ms; declare the session dead after 400ms of silence.
    client_tunnel.set_keepalive_params(Duration::from_millis(100), Duration::from_millis(400));

    // Feed the client tunnel from its socket (mirrors the daemon wiring).
    let (udp_tx, udp_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
    tokio::spawn(socket_reader(client_sock.clone(), udp_tx));
    let (_stop_tx, stop_rx) = watch::channel(false);

    // Kill the server mid-session: drop the server socket so the client gets
    // no replies to its keepalives. (The server tunnel is never run — the
    // server vanished right after the handshake established the session.)
    drop(server_sock);

    let exit = tokio::time::timeout(Duration::from_secs(6), client_tunnel.run(stop_rx, udp_rx))
        .await
        .expect("client tunnel did not detect the drop in time");
    // The client must have detected the drop on its own (not been stopped).
    assert_ne!(
        exit,
        TunnelExit::Stopped,
        "client should detect the drop, not exit via stop signal"
    );
    assert!(
        matches!(exit, TunnelExit::SessionTimeout | TunnelExit::UdpClosed),
        "expected the drop to surface as a session timeout or udp-closed, got {exit:?}"
    );

    // FAIL CLOSED: after the drop, the kill switch is still engaged and direct
    // internet is still blocked — the client has NOT fallen back to the real
    // connection.
    assert!(
        ks.is_active(),
        "kill switch must stay engaged after a drop (fail closed)"
    );
    let ops = backend.ops();
    assert_eq!(
        evaluate_packet(&ops, "tcp", "93.184.216.34", 443, "eth0"),
        Decision::Reject,
        "direct internet must stay blocked after the tunnel drops (fail closed)"
    );
    // The server must remain reachable so the client can reconnect.
    let server_ip = server_addr.ip().to_string();
    assert_eq!(
        evaluate_packet(&ops, "udp", &server_ip, server_addr.port(), "eth0"),
        Decision::Accept,
        "server must stay reachable so the tunnel can be re-established"
    );
    // TUN traffic is still allowed.
    assert_eq!(
        evaluate_packet(&ops, "tcp", "8.8.8.8", 443, "rustnies0"),
        Decision::Accept
    );

    // Graceful shutdown: removing the kill switch restores direct internet.
    ks.remove().unwrap();
    assert!(!ks.is_active(), "kill switch disengaged on shutdown");
    let ops = backend.ops();
    assert_eq!(
        evaluate_packet(&ops, "tcp", "93.184.216.34", 443, "eth0"),
        Decision::Pass,
        "direct internet restored after graceful shutdown"
    );
}

/// DNS leak prevention + kill switch compose correctly during a real session:
/// DNS can only leave via the tunnel, everything else non-tunnel is blocked,
/// and the server stays reachable. Verifies the policy the daemon installs
/// (DNS chain before the kill switch chain) using the recorded backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_leak_prevention_with_kill_switch_compose() {
    let server: SocketAddr = "1.2.3.4:51820".parse().unwrap();
    let backend = Arc::new(RecordedBackend::new());

    // Install in the same order the daemon does: DNS leak first, then kill switch.
    let mut dns = rustnies::platform::linux::DnsLeakGuard::new("rustnies0", backend.clone());
    dns.install().unwrap();
    let mut ks = KillSwitch::new(server, "rustnies0", backend.clone());
    ks.install().unwrap();
    let ops = backend.ops();

    // DNS only reaches a resolver via the tunnel.
    assert_eq!(
        evaluate_packet(&ops, "udp", "8.8.8.8", 53, "rustnies0"),
        Decision::Accept,
        "DNS via the tunnel is allowed"
    );
    assert_eq!(
        evaluate_packet(&ops, "tcp", "8.8.8.8", 53, "rustnies0"),
        Decision::Accept
    );
    assert_eq!(
        evaluate_packet(&ops, "udp", "192.168.1.1", 53, "eth0"),
        Decision::Reject,
        "DNS via the real interface is blocked (no leak)"
    );
    assert_eq!(
        evaluate_packet(&ops, "tcp", "192.168.1.1", 53, "eth0"),
        Decision::Reject
    );

    // Non-DNS direct internet is blocked by the kill switch.
    assert_eq!(
        evaluate_packet(&ops, "tcp", "93.184.216.34", 443, "eth0"),
        Decision::Reject
    );
    // Non-DNS via the tunnel is allowed.
    assert_eq!(
        evaluate_packet(&ops, "tcp", "93.184.216.34", 443, "rustnies0"),
        Decision::Accept
    );
    // The server stays reachable for the encrypted tunnel UDP.
    let server_ip = server.ip().to_string();
    assert_eq!(
        evaluate_packet(&ops, "udp", &server_ip, server.port(), "eth0"),
        Decision::Accept
    );

    // Teardown clears both chains (graceful shutdown restores connectivity).
    ks.remove().unwrap();
    dns.remove().unwrap();
    let ops = backend.ops();
    assert_eq!(
        evaluate_packet(&ops, "tcp", "93.184.216.34", 443, "eth0"),
        Decision::Pass
    );
    assert_eq!(
        evaluate_packet(&ops, "udp", "192.168.1.1", 53, "eth0"),
        Decision::Pass,
        "DNS block removed on shutdown"
    );
}

// ---------------------------------------------------------------------------
// Bidirectional data flow: two real tunnels over loopback UDP with pipe TUNs.
// Verifies that a TUN packet injected on one side emerges from the TUN on the
// other side, in both directions — the core data path the status command
// claims is "connected" but the ping in the field report showed was broken.
// ---------------------------------------------------------------------------

/// A TUN that feeds injected packets into `recv` and captures `send` output,
/// so a test can simulate the kernel writing to and reading from the TUN
/// without a real device.  `inject_rx` is what `recv` drains (the test writes
/// here to simulate the kernel handing the tunnel an outbound packet);
/// `capture_tx` is where `send` posts (the test reads here to see what the
/// tunnel wrote back to the "kernel").
struct PipeTun {
    name: String,
    mtu: u32,
    inject_rx: Arc<Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
    capture_tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl Tun for PipeTun {
    fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> TunFut<'a> {
        let inject_rx = self.inject_rx.clone();
        Box::pin(async move {
            let mut rx = inject_rx.lock().await;
            match rx.recv().await {
                Some(p) => {
                    let n = p.len().min(buf.len());
                    buf[..n].copy_from_slice(&p[..n]);
                    Ok(n)
                }
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "tun inject channel closed",
                )),
            }
        })
    }
    fn send<'a>(&'a mut self, buf: &'a [u8]) -> TunFut<'a> {
        let capture_tx = self.capture_tx.clone();
        Box::pin(async move {
            let _ = capture_tx.send(buf.to_vec());
            Ok(buf.len())
        })
    }
    fn name(&self) -> std::io::Result<String> {
        Ok(self.name.clone())
    }
    fn mtu(&self) -> std::io::Result<u32> {
        Ok(self.mtu)
    }
}

/// Build a minimal 20-byte IPv4 packet (version 4, IHL 5) with the given
/// source and destination addresses. The tunnel treats TUN packets as opaque
/// bytes, so the IP header is sufficient — no ICMP/TCP payload is needed.
fn ipv4_packet(src: &str, dst: &str) -> Vec<u8> {
    let mut pkt = vec![0u8; 20];
    pkt[0] = 0x45; // version 4, IHL 5
    let src: std::net::Ipv4Addr = src.parse().unwrap();
    let dst: std::net::Ipv4Addr = dst.parse().unwrap();
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt
}

/// Two real tunnels (client + server) over loopback UDP with pipe TUNs.
/// Inject a packet on the client TUN, confirm it emerges from the server TUN;
/// inject a reply on the server TUN, confirm it emerges from the client TUN.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bidirectional_data_through_two_tunnels() {
    let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr: SocketAddr = server_sock.local_addr().unwrap();
    let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let server_kp = KeyPair::generate();
    let client_kp = KeyPair::generate();

    // Noise IK handshake over the real sockets.
    let server_kp_clone = clone_keypair(&server_kp);
    let server_sock_for_hs = server_sock.clone();
    let server_handle = tokio::spawn(async move {
        handshake::server(
            udp_carrier(&server_sock_for_hs, server_addr),
            server_kp_clone,
            default_profile(),
            &ObfuscationStack::new(),
        )
        .await
        .unwrap()
    });
    let established_client = tokio::time::timeout(
        Duration::from_secs(5),
        handshake::client(
            udp_carrier(&client_sock, server_addr),
            server_addr,
            &client_kp,
            server_kp.public,
            &default_profile(),
            &ObfuscationStack::new(),
        ),
    )
    .await
    .expect("client handshake timed out")
    .expect("client handshake failed");
    let established_server = tokio::time::timeout(Duration::from_secs(5), server_handle)
        .await
        .expect("server join timed out")
        .expect("server task panicked");

    // Pipe TUNs: the test holds the inject sender and capture receiver.
    let (client_inject_tx, client_inject_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (client_capture_tx, mut client_capture_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (server_inject_tx, server_inject_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (server_capture_tx, mut server_capture_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let client_tun = Box::new(PipeTun {
        name: "rustnies0".into(),
        mtu: 1400,
        inject_rx: Arc::new(Mutex::new(client_inject_rx)),
        capture_tx: client_capture_tx,
    });
    let server_tun = Box::new(PipeTun {
        name: "rustnies".into(),
        mtu: 1400,
        inject_rx: Arc::new(Mutex::new(server_inject_rx)),
        capture_tx: server_capture_tx,
    });

    let mut client_tunnel = Tunnel::from_handshake(
        client_tun,
        udp_carrier(&client_sock, server_addr),
        established_client.peer,
        Session::new(established_client.session_id, SessionRole::Initiator),
        resolved_profile(&default_profile(), &established_client),
        ObfuscationStack::new(),
        established_client.send_key,
        established_client.recv_key,
        established_client.send_dir,
        established_client.recv_dir,
        Arc::new(Mutex::new(Counters::new())),
    )
    .unwrap();
    let mut server_tunnel = Tunnel::from_handshake(
        server_tun,
        udp_carrier(&server_sock, server_addr),
        established_server.peer,
        Session::new(established_server.session_id, SessionRole::Responder),
        resolved_profile(&default_profile(), &established_server),
        ObfuscationStack::new(),
        established_server.send_key,
        established_server.recv_key,
        established_server.send_dir,
        established_server.recv_dir,
        Arc::new(Mutex::new(Counters::new())),
    )
    .unwrap();

    // Feed each tunnel from its socket (mirrors the daemon wiring).
    let (client_udp_tx, client_udp_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
    tokio::spawn(socket_reader(client_sock.clone(), client_udp_tx));
    let (server_udp_tx, server_udp_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
    tokio::spawn(socket_reader(server_sock.clone(), server_udp_tx));

    let (client_stop_tx, client_stop_rx) = watch::channel(false);
    let (server_stop_tx, server_stop_rx) = watch::channel(false);

    let client_task =
        tokio::spawn(async move { client_tunnel.run(client_stop_rx, client_udp_rx).await });
    let server_task =
        tokio::spawn(async move { server_tunnel.run(server_stop_rx, server_udp_rx).await });

    // Let the tunnels exchange a few pings so the session is warmed up.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- client -> server ---
    let ping = ipv4_packet("10.7.0.2", "10.7.0.1");
    client_inject_tx
        .send(ping.clone())
        .expect("inject client packet");
    let got = tokio::time::timeout(Duration::from_secs(3), server_capture_rx.recv())
        .await
        .expect("server did not receive the client's data packet in time")
        .expect("server capture channel closed");
    assert_eq!(
        got, ping,
        "server TUN should receive the client's packet intact"
    );

    // --- server -> client (the reply path that was broken in the field) ---
    let reply = ipv4_packet("10.7.0.1", "10.7.0.2");
    server_inject_tx
        .send(reply.clone())
        .expect("inject server reply");
    let got_reply = tokio::time::timeout(Duration::from_secs(3), client_capture_rx.recv())
        .await
        .expect("client did not receive the server's reply in time")
        .expect("client capture channel closed");
    assert_eq!(
        got_reply, reply,
        "client TUN should receive the server's reply intact"
    );

    // Shut down.
    let _ = client_stop_tx.send(true);
    let _ = server_stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), client_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;
}

/// Full server-dispatcher integration: a real `run_server` with a pipe TUN
/// accepts a client handshake, the client sends a data packet, it emerges from
/// the server's TUN, a reply injected into the server TUN is routed back to
/// the client, and it emerges from the client's TUN.  This exercises the
/// dispatcher's tunnel-IP learning and per-client TUN routing — the layer
/// between the real TUN and the per-client tunnel that the direct two-tunnel
/// test does not cover.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_flows_through_server_dispatcher() {
    use rustnies::config::FecConfig;
    use rustnies::tunnel::peers::PeerAuth;
    use rustnies::tunnel::server::run_server;

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let server_addr: SocketAddr = server_sock.local_addr().unwrap();
            let server_kp = KeyPair::generate();
            let server_pub = server_kp.public;
            // writes client data here.
            let (server_inject_tx, server_inject_rx) = mpsc::unbounded_channel::<Vec<u8>>();
            let (server_capture_tx, mut server_capture_rx) = mpsc::unbounded_channel::<Vec<u8>>();
            let server_tun = Box::new(PipeTun {
                name: "rustnies".into(),
                mtu: 1400,
                inject_rx: Arc::new(Mutex::new(server_inject_rx)),
                capture_tx: server_capture_tx,
            });

            let (stop_tx, stop_rx) = watch::channel(false);
            let peer_auth = Arc::new(std::sync::Mutex::new(PeerAuth::open_mode()));
            let server_counters = Arc::new(Mutex::new(Counters::new()));
            let server_stop = stop_tx.clone();

            let server_task = tokio::task::spawn_local(async move {
                run_server(
                    Box::new(UdpListener::new(server_sock.clone(), server_addr)),
                    server_kp,
                    server_tun,
                    default_profile(),
                    rustnies::obfuscation::build_shared_stack(None),
                    stop_rx,
                    stop_tx,
                    server_counters,
                    "rustnies".into(),
                    1400,
                    vec!["10.7.0.0/24".parse().unwrap()],
                    peer_auth,
                    FecConfig::default(),
                    0,
                    tokio::sync::mpsc::channel::<rustnies::tunnel::server::ControlCommand>(16).1,
                )
                .await
                .unwrap()
            });

            // Client handshake.
            let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let client_kp = KeyPair::generate();
            let established = tokio::time::timeout(
                Duration::from_secs(5),
                handshake::client(
                    udp_carrier(&client_sock, server_addr),
                    server_addr,
                    &client_kp,
                    server_pub,
                    &default_profile(),
                    &ObfuscationStack::new(),
                ),
            )
            .await
            .expect("client handshake timed out")
            .expect("client handshake failed");

            // Client pipe TUN.
            let (client_inject_tx, client_inject_rx) = mpsc::unbounded_channel::<Vec<u8>>();
            let (client_capture_tx, mut client_capture_rx) = mpsc::unbounded_channel::<Vec<u8>>();
            let client_tun = Box::new(PipeTun {
                name: "rustnies0".into(),
                mtu: 1400,
                inject_rx: Arc::new(Mutex::new(client_inject_rx)),
                capture_tx: client_capture_tx,
            });

            let mut client_tunnel = Tunnel::from_handshake(
                client_tun,
                udp_carrier(&client_sock, server_addr),
                established.peer,
                Session::new(established.session_id, SessionRole::Initiator),
                resolved_profile(&default_profile(), &established),
                ObfuscationStack::new(),
                established.send_key,
                established.recv_key,
                established.send_dir,
                established.recv_dir,
                Arc::new(Mutex::new(Counters::new())),
            )
            .unwrap();

            let (client_udp_tx, client_udp_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
            tokio::spawn(socket_reader(client_sock.clone(), client_udp_tx));
            let (client_stop_tx, client_stop_rx) = watch::channel(false);
            let client_task =
                tokio::spawn(async move { client_tunnel.run(client_stop_rx, client_udp_rx).await });

            // Let the tunnels warm up (pings, keepalives).
            tokio::time::sleep(Duration::from_millis(300)).await;

            // --- client -> server (through the dispatcher) ---
            let ping = ipv4_packet("10.7.0.2", "10.7.0.1");
            client_inject_tx
                .send(ping.clone())
                .expect("inject client packet");
            let got = tokio::time::timeout(Duration::from_secs(3), server_capture_rx.recv())
                .await
                .expect("server TUN did not receive client data through the dispatcher")
                .expect("server capture channel closed");
            assert_eq!(
                got, ping,
                "server TUN should receive the client's packet via the dispatcher"
            );

            // --- server -> client (the reply path that was broken in the field) ---
            let reply = ipv4_packet("10.7.0.1", "10.7.0.2");
            server_inject_tx
                .send(reply.clone())
                .expect("inject server reply");
            let got_reply = tokio::time::timeout(Duration::from_secs(3), client_capture_rx.recv())
                .await
                .expect("client TUN did not receive the server's reply through the dispatcher")
                .expect("client capture channel closed");
            assert_eq!(
                got_reply, reply,
                "client TUN should receive the server's reply via the dispatcher"
            );

            // Shut down.
            let _ = client_stop_tx.send(true);
            let _ = server_stop.send(true);
            let _ = tokio::time::timeout(Duration::from_secs(2), client_task).await;
            let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;
        })
        .await;
}

// ---------------------------------------------------------------------------
// Bad-connection simulation: a lossy, latency-adding UDP relay sits between
// the client and server so the tunnel's FEC recovery, congestion control and
// keepalive-driven session liveness can be exercised against realistic (and
// pathological) network conditions without a real flaky link.
//
// The relay is a single UDP socket both sides send to. It distinguishes the
// two peers by source address (the server's address is preconfigured; anyone
// else is treated as the client and learned on first contact). Each forwarded
// datagram is independently dropped with probability `loss_rate` and delayed
// by `delay` otherwise. A small xorshift PRNG seeded per test makes the loss
// pattern deterministic so failures are reproducible.
// ---------------------------------------------------------------------------

/// A tiny deterministic xorshift64 PRNG so the loss pattern is reproducible
/// without pulling `rand` into the test's public surface.
struct LossPrng {
    state: u64,
}
impl LossPrng {
    fn new(seed: u64) -> Self {
        Self {
            state: seed | 1, // must be non-zero
        }
    }
    fn next_f64(&mut self) -> f64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        // Map the high 53 bits to [0,1) for a uniform double.
        (x >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Number of leading packets the relay forwards losslessly so the Noise
/// handshake (msg1 + msg2) and the first RTT ping always complete, even when
/// the configured `loss_rate` is extreme. After the warmup the full loss rate
/// applies, stressing exactly the steady-state data and liveness paths.
const RELAY_WARMUP: u32 = 4;

/// Spawn a lossy UDP relay that forwards between a client and a known server.
/// Returns the relay's address: both sides should send to it. The relay learns
/// the client's address from the first packet it receives that is not from
/// `server_addr`, and forwards everything the server sends back to that client.
async fn spawn_lossy_link(
    server_addr: SocketAddr,
    loss_rate: f64,
    delay: Duration,
    seed: u64,
) -> SocketAddr {
    // The relay socket is created here so its address is known before the
    // handshake starts; the forwarding loop runs in a background task.
    let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay_addr = relay.local_addr().expect("relay has a local addr");
    let relay_for_task = relay.clone();
    tokio::spawn(async move {
        let mut rng = LossPrng::new(seed);
        let mut buf = vec![0u8; 65535];
        let mut client_addr: Option<SocketAddr> = None;
        let mut warmup = RELAY_WARMUP;
        loop {
            let (n, from) = match relay_for_task.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            // Decide where this datagram is going.
            let dst = if from == server_addr {
                // Server -> client (client must already be known; if not, drop).
                match client_addr {
                    Some(a) => a,
                    None => continue,
                }
            } else {
                // Client -> server; learn the client's address on first sight.
                client_addr = Some(from);
                server_addr
            };
            // The first few packets (the handshake + first ping) always get
            // through; only afterwards does the configured loss apply.
            if warmup > 0 {
                warmup -= 1;
            } else if rng.next_f64() < loss_rate {
                continue;
            }
            // Simulated latency on the surviving packets. This MUST NOT block
            // this receive loop: the sender emits `1 + m` datagrams per packet
            // (FEC copies), so a serial `sleep(delay)` here would cap the relay
            // at one datagram per `delay` and overflow its socket buffer,
            // making the *relay* the packet dropper. That models a broken
            // relay, not a high-RTT path, and it silently corrupts any test
            // that asserts zero loss over a delayed link. Hand each packet to
            // its own timer instead so latency does not consume receive
            // capacity.
            if delay.is_zero() {
                let _ = relay_for_task.send_to(&buf[..n], dst).await;
            } else {
                let payload = buf[..n].to_vec();
                let sock = relay_for_task.clone();
                let delay = delay;
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = sock.send_to(&payload, &dst).await;
                });
            }
        }
    });
    relay_addr
}

/// Everything a bad-connection test needs to drive two real tunnels through a
/// lossy relay and then tear them down.
struct LossyLinkTunnels {
    client_inject: mpsc::UnboundedSender<Vec<u8>>,
    server_capture: mpsc::UnboundedReceiver<Vec<u8>>,
    server_inject: mpsc::UnboundedSender<Vec<u8>>,
    client_capture: mpsc::UnboundedReceiver<Vec<u8>>,
    client_stop: watch::Sender<bool>,
    server_stop: watch::Sender<bool>,
    client_task: tokio::task::JoinHandle<TunnelExit>,
    server_task: tokio::task::JoinHandle<TunnelExit>,
}

impl LossyLinkTunnels {
    /// Signal both tunnels to stop and await their exit (bounded).
    async fn shutdown(self) {
        let _ = self.client_stop.send(true);
        let _ = self.server_stop.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(3), self.client_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(3), self.server_task).await;
    }
}

/// Build two real `Tunnel::run` loops (client + server) that talk to each other
/// through a lossy relay with the given `loss_rate`, per-packet `delay` and PRNG
/// `seed`. `keepalive` and `session_timeout` configure the tunnel liveness
/// timers so a test can probe session survival under stress on a short budget.
///
/// `fec_m` fixes the FEC parity count on both tunnels (k=1, min_m = max_m =
/// initial_m = `fec_m`) so every packet gets exactly `1 + fec_m` copies on the
/// wire from the very first packet. With k=1 each packet is its own complete
/// FEC group, so recovery is immediate and the adaptive controller never
/// changes `m`. Choosing `fec_m` high enough for the configured `loss_rate`
/// makes the probability of losing *all* copies of any single packet
/// vanishingly small (P = loss_rate^(1+fec_m)), so the test can assert
/// **zero** application-level loss.
async fn build_lossy_two_tunnels(
    loss_rate: f64,
    delay: Duration,
    seed: u64,
    keepalive: Duration,
    session_timeout: Duration,
    fec_m: u8,
) -> LossyLinkTunnels {
    // The server's socket is bound first so the relay knows where to forward
    // server-bound traffic.
    let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server_sock.local_addr().unwrap();
    let relay_addr = spawn_lossy_link(server_addr, loss_rate, delay, seed).await;

    let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let server_kp = KeyPair::generate();
    let server_pub = server_kp.public;
    let client_kp = KeyPair::generate();

    // Noise IK handshake: the server listens on its socket; the client
    // connects through the relay. The relay's warmup window forwards the
    // handshake (msg1 + msg2) losslessly, so it always completes.
    let server_kp_clone = clone_keypair(&server_kp);
    let server_sock_for_hs = server_sock.clone();
    let server_handle = tokio::spawn(async move {
        handshake::server(
            udp_carrier(&server_sock_for_hs, server_addr),
            server_kp_clone,
            default_profile(),
            &ObfuscationStack::new(),
        )
        .await
        .unwrap()
    });
    let established_client = tokio::time::timeout(
        Duration::from_secs(15),
        handshake::client(
            udp_carrier(&client_sock, server_addr),
            relay_addr,
            &client_kp,
            server_pub,
            &default_profile(),
            &ObfuscationStack::new(),
        ),
    )
    .await
    .expect("handshake timed out (relay too lossy to complete a round trip)")
    .expect("client handshake failed");
    let established_server = tokio::time::timeout(Duration::from_secs(15), server_handle)
        .await
        .expect("server handshake join timed out")
        .expect("server task panicked");

    // Pipe TUNs: inject outbound packets, capture inbound packets.
    let (client_inject_tx, client_inject_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (client_capture_tx, client_capture_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (server_inject_tx, server_inject_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (server_capture_tx, server_capture_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let client_tun = Box::new(PipeTun {
        name: "rustnies0".into(),
        mtu: 1400,
        inject_rx: Arc::new(Mutex::new(client_inject_rx)),
        capture_tx: client_capture_tx,
    });
    let server_tun = Box::new(PipeTun {
        name: "rustnies".into(),
        mtu: 1400,
        inject_rx: Arc::new(Mutex::new(server_inject_rx)),
        capture_tx: server_capture_tx,
    });

    let mut client_tunnel = Tunnel::from_handshake(
        client_tun,
        udp_carrier(&client_sock, server_addr),
        established_client.peer,
        Session::new(established_client.session_id, SessionRole::Initiator),
        resolved_profile(&default_profile(), &established_server),
        ObfuscationStack::new(),
        established_client.send_key,
        established_client.recv_key,
        established_client.send_dir,
        established_client.recv_dir,
        Arc::new(Mutex::new(Counters::new())),
    )
    .unwrap();
    let mut server_tunnel = Tunnel::from_handshake(
        server_tun,
        udp_carrier(&server_sock, server_addr),
        established_server.peer,
        Session::new(established_server.session_id, SessionRole::Responder),
        resolved_profile(&default_profile(), &established_server),
        ObfuscationStack::new(),
        established_server.send_key,
        established_server.recv_key,
        established_server.send_dir,
        established_server.recv_dir,
        Arc::new(Mutex::new(Counters::new())),
    )
    .unwrap();
    // Fix FEC parity at `fec_m` for both tunnels (k=1, min_m = max_m = fec_m).
    // With k=1 every packet is its own complete FEC group, so each packet gets
    // 1 + fec_m copies on the wire and FEC recovers from any single survivor.
    client_tunnel.configure_fec(&rustnies::config::FecConfig {
        scheme: vec![rustnies::fec::DEFAULT_FEC_SCHEME.to_string()],
        k: 1,
        min_m: fec_m,
        max_m: fec_m,
        initial_m: fec_m,
    });
    server_tunnel.configure_fec(&rustnies::config::FecConfig {
        scheme: vec![rustnies::fec::DEFAULT_FEC_SCHEME.to_string()],
        k: 1,
        min_m: fec_m,
        max_m: fec_m,
        initial_m: fec_m,
    });
    client_tunnel.set_keepalive_params(keepalive, session_timeout);
    server_tunnel.set_keepalive_params(keepalive, session_timeout);

    // Feed each tunnel from its own socket (mirrors the daemon wiring). Both
    // sockets receive from the relay, which matches each tunnel's `peer`.
    let (client_udp_tx, client_udp_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
    tokio::spawn(socket_reader(client_sock.clone(), client_udp_tx));
    let (server_udp_tx, server_udp_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
    tokio::spawn(socket_reader(server_sock.clone(), server_udp_tx));

    let (client_stop_tx, client_stop_rx) = watch::channel(false);
    let (server_stop_tx, server_stop_rx) = watch::channel(false);

    let client_task =
        tokio::spawn(async move { client_tunnel.run(client_stop_rx, client_udp_rx).await });
    let server_task =
        tokio::spawn(async move { server_tunnel.run(server_stop_rx, server_udp_rx).await });

    // Let the tunnels exchange a few pings/keepalives so the session is warm.
    tokio::time::sleep(Duration::from_millis(300)).await;

    LossyLinkTunnels {
        client_inject: client_inject_tx,
        server_capture: server_capture_rx,
        server_inject: server_inject_tx,
        client_capture: client_capture_rx,
        client_stop: client_stop_tx,
        server_stop: server_stop_tx,
        client_task,
        server_task,
    }
}

/// Collect exactly `want` packets from `capture`, or return however many
/// arrived within `max` if the channel goes quiet for `quiet`. Used to verify
/// that every sent packet was delivered (zero loss) over a lossy link where
/// FEC-recovered arrivals may be spread out in time.
async fn collect_packets(
    capture: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    want: usize,
    quiet: Duration,
    max: Duration,
) -> Vec<Vec<u8>> {
    let mut pkts = Vec::with_capacity(want);
    let start = tokio::time::Instant::now();
    while pkts.len() < want {
        let remaining = max.checked_sub(start.elapsed()).unwrap_or_default();
        if remaining.is_zero() {
            break;
        }
        let wait = quiet.min(remaining);
        match tokio::time::timeout(wait, capture.recv()).await {
            Ok(Some(p)) => pkts.push(p),
            _ => break,
        }
    }
    pkts
}

/// Under 10% packet loss with the default FEC ceiling (m=4, five copies per
/// packet), the probability of losing all five copies is 0.1^5 = 1e-5. Over 20
/// packets the expected unrecoverable loss is 0.0002 — effectively zero. The
/// tunnel must deliver every single packet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_loss_under_light_packet_loss() {
    let mut env = build_lossy_two_tunnels(
        0.10,
        Duration::ZERO,
        0xA1_u64,
        Duration::from_secs(2),
        Duration::from_secs(8),
        4,
    )
    .await;

    const N: usize = 20;
    let pkt = ipv4_packet("10.7.0.2", "10.7.0.1");
    for _ in 0..N {
        env.client_inject.send(pkt.clone()).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let got = collect_packets(
        &mut env.server_capture,
        N,
        Duration::from_millis(500),
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(
        got.len(),
        N,
        "zero loss expected at 10% loss with m=4: delivered {}/{N}",
        got.len()
    );
    assert!(
        !env.client_task.is_finished() && !env.server_task.is_finished(),
        "tunnels must stay up"
    );
    env.shutdown().await;
}

/// Under 30% packet loss with m=8 (nine copies per packet), P(all nine lost) =
/// 0.3^9 ≈ 2e-5. Over 20 packets the expected unrecoverable loss is 0.0004 —
/// effectively zero. The tunnel must deliver every single packet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_loss_under_moderate_packet_loss() {
    let mut env = build_lossy_two_tunnels(
        0.30,
        Duration::ZERO,
        0xB2_u64,
        Duration::from_secs(2),
        Duration::from_secs(8),
        8,
    )
    .await;

    const N: usize = 20;
    let pkt = ipv4_packet("10.7.0.2", "10.7.0.1");
    for _ in 0..N {
        env.client_inject.send(pkt.clone()).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let got = collect_packets(
        &mut env.server_capture,
        N,
        Duration::from_millis(500),
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(
        got.len(),
        N,
        "zero loss expected at 30% loss with m=8: delivered {}/{N}",
        got.len()
    );
    assert!(
        !env.client_task.is_finished() && !env.server_task.is_finished(),
        "tunnels must stay up under moderate loss"
    );
    env.shutdown().await;
}

/// Under 50% packet loss with m=15 (sixteen copies per packet), P(all sixteen
/// lost) = 0.5^16 ≈ 1.5e-5. Over 10 packets the expected unrecoverable loss
/// is 0.00015 — effectively zero. The tunnel must deliver every packet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_loss_under_heavy_packet_loss() {
    let mut env = build_lossy_two_tunnels(
        0.50,
        Duration::ZERO,
        0xC3_u64,
        Duration::from_millis(200),
        Duration::from_secs(4),
        15,
    )
    .await;

    const N: usize = 10;
    let pkt = ipv4_packet("10.7.0.2", "10.7.0.1");
    for _ in 0..N {
        env.client_inject.send(pkt.clone()).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let got = collect_packets(
        &mut env.server_capture,
        N,
        Duration::from_millis(500),
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(
        got.len(),
        N,
        "zero loss expected at 50% loss with m=15: delivered {}/{N}",
        got.len()
    );
    assert!(
        !env.client_task.is_finished() && !env.server_task.is_finished(),
        "tunnels must stay up under heavy loss"
    );
    env.shutdown().await;
}

/// Under 80% packet loss with m=40 (forty-one copies per packet), P(all
/// forty-one lost) = 0.8^41 ≈ 3.6e-5. Over 5 packets the expected unrecoverable
/// loss is 0.00018 — effectively zero. Even at extreme loss the FEC must
/// deliver every packet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_loss_under_extreme_packet_loss() {
    let mut env = build_lossy_two_tunnels(
        0.80,
        Duration::ZERO,
        0xD4_u64,
        Duration::from_millis(100),
        Duration::from_secs(3),
        40,
    )
    .await;

    const N: usize = 5;
    let pkt = ipv4_packet("10.7.0.2", "10.7.0.1");
    for _ in 0..N {
        env.client_inject.send(pkt.clone()).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let got = collect_packets(
        &mut env.server_capture,
        N,
        Duration::from_millis(800),
        Duration::from_secs(10),
    )
    .await;
    assert_eq!(
        got.len(),
        N,
        "zero loss expected at 80% loss with m=40: delivered {}/{N}",
        got.len()
    );
    assert!(
        !env.client_task.is_finished(),
        "tunnel must stay up under extreme loss"
    );
    env.shutdown().await;
}

/// Under severe (60%) loss the session must not time out: keepalives and RTT
/// pings are control traffic that gets through often enough (within the
/// configured timeout) to keep both sides believing the peer is alive. This
/// exercises the liveness path that a flaky real link would stress.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tunnel_stays_connected_under_severe_loss() {
    let env = build_lossy_two_tunnels(
        0.60,
        Duration::ZERO,
        0xE5_u64,
        Duration::from_millis(100),
        Duration::from_secs(2),
        10,
    )
    .await;
    // Run under loss for a while; keepalives (100ms) + pings (500ms) must keep
    // the session alive past the 2s inactivity timeout. With ~20 keepalive
    // chances in 2s the probability of all being lost at 60% is ~0.6^20, i.e.
    // negligible.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !env.client_task.is_finished(),
        "client must not time out under 60% loss (keepalives should survive)"
    );
    assert!(
        !env.server_task.is_finished(),
        "server must not time out under 60% loss"
    );
    env.shutdown().await;
}

/// Added latency must not break the data path: the tunnel tolerates a 40ms
/// per-hop delay (the relay delays each forwarded datagram), so a packet
/// should still arrive intact, just slower.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_survives_added_latency() {
    let mut env = build_lossy_two_tunnels(
        0.0,
        Duration::from_millis(40),
        0xF6_u64,
        Duration::from_secs(2),
        Duration::from_secs(8),
        1,
    )
    .await;
    let pkt = ipv4_packet("10.7.0.2", "10.7.0.1");
    env.client_inject.send(pkt.clone()).unwrap();
    let got = tokio::time::timeout(Duration::from_secs(3), env.server_capture.recv())
        .await
        .expect("packet did not arrive through the delayed link")
        .expect("capture channel closed");
    assert_eq!(
        got, pkt,
        "packet should arrive intact despite added latency"
    );
    env.shutdown().await;
}

/// Bidirectional zero loss: both the forward (client -> server) and reverse
/// (server -> client) directions must deliver every packet with zero loss at
/// 30% link loss. With m=8 (nine copies per packet) the probability of losing
/// all copies in either direction is negligible.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_loss_bidirectional_under_packet_loss() {
    let mut env = build_lossy_two_tunnels(
        0.30,
        Duration::ZERO,
        0x77_u64,
        Duration::from_secs(2),
        Duration::from_secs(8),
        8,
    )
    .await;

    const N: usize = 10;
    let ping = ipv4_packet("10.7.0.2", "10.7.0.1");
    let reply = ipv4_packet("10.7.0.1", "10.7.0.2");

    // Forward: client -> server.
    for _ in 0..N {
        env.client_inject.send(ping.clone()).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let fwd = collect_packets(
        &mut env.server_capture,
        N,
        Duration::from_millis(500),
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(
        fwd.len(),
        N,
        "zero forward loss expected at 30% with m=8: delivered {}/{N}",
        fwd.len()
    );

    // Reverse: server -> client.
    for _ in 0..N {
        env.server_inject.send(reply.clone()).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let rev = collect_packets(
        &mut env.client_capture,
        N,
        Duration::from_millis(500),
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(
        rev.len(),
        N,
        "zero reverse loss expected at 30% with m=8: delivered {}/{N}",
        rev.len()
    );

    assert!(
        !env.client_task.is_finished() && !env.server_task.is_finished(),
        "tunnels must stay up"
    );
    env.shutdown().await;
}

/// Reproduction of the reported symptom: a low-rate (10 pps) ICMP-like flow
/// across a realistic last-mile path (~98 ms RTT) with only 0.5% ambient wire
/// loss, using the shipped default FEC ceiling (m=4).
///
/// The reported failure is `ping -i 0.1` losing ~9% of packets while the RTT
/// stays rock-steady at ~98 ms. Stable latency with loss at trivial load is
/// not a congestion signature: 10 packets/second of ~124-byte wire packets
/// keeps at most one packet in flight, so a byte window of >= 2 KB and any
/// sane pacer are both far from binding. This test pins that reasoning down —
/// if the tunnel is dropping these packets itself, it fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn low_rate_flow_over_high_rtt_link_loses_nothing() {
    // 0.5% wire loss, ~49 ms each way (~98 ms RTT), default FEC ceiling.
    let mut env = build_lossy_two_tunnels(
        0.005,
        Duration::from_millis(49),
        0xB7_u64,
        Duration::from_secs(2),
        Duration::from_secs(8),
        4,
    )
    .await;

    const N: usize = 30;
    let pkt = ipv4_packet("10.7.0.2", "10.7.0.1");
    for _ in 0..N {
        env.client_inject.send(pkt.clone()).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let got = collect_packets(
        &mut env.server_capture,
        N,
        Duration::from_millis(400),
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(
        got.len(),
        N,
        "10 pps over a ~98 ms RTT link with 0.5% wire loss must deliver every packet: delivered {}/{N}",
        got.len()
    );
    assert!(
        !env.client_task.is_finished() && !env.server_task.is_finished(),
        "tunnels must stay up for the whole run"
    );
    env.shutdown().await;
}

// ---------------------------------------------------------------------------
// Non-default protocol profiles, end to end
// ---------------------------------------------------------------------------

/// Build a client/server profile pair from the four config sections, exactly as
/// the daemon does. `local_profile()` above is the same call with empty
/// sections.
fn profile_from(
    handshake: rustnies::config::HandshakeConfig,
    crypto: rustnies::config::CryptoConfig,
    transport: rustnies::config::TransportConfig,
    fec: rustnies::config::FecConfig,
    congestion: rustnies::config::CongestionConfig,
) -> LocalProfile {
    LocalProfile::from_role_config(
        &handshake,
        &crypto,
        &transport,
        &fec,
        &congestion,
        &Default::default(),
    )
    .expect("test profile must resolve")
}

/// A full loopback session over a deliberately non-default profile: FEC off,
/// congestion control off, a `tagged` steady-state envelope, and a proposing
/// client so the negotiation actually runs in both directions.
///
/// This is the test that would fail if any layer kept reaching for a hard-wired
/// implementation: the cipher, the envelope and the erasure code all come from
/// the negotiated selection, and the tunnel still has to deliver data.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_flows_over_a_non_default_negotiated_profile() {
    let client_profile = profile_from(
        rustnies::config::HandshakeConfig {
            kex: "noise-ik".into(),
            // Propose, so the server's preference order is actually exercised
            // against a client that advertises its own capabilities.
            propose: true,
        },
        rustnies::config::CryptoConfig::default(),
        rustnies::config::TransportConfig {
            handshake: "plain".into(),
            // Ask for the tagged envelope for steady-state frames.
            data: vec!["tagged".into()],
            tag_hex: None,
        },
        rustnies::config::FecConfig {
            scheme: vec!["none".into()],
            k: 1,
            min_m: 0,
            max_m: 4,
            initial_m: 2,
        },
        rustnies::config::CongestionConfig {
            algorithm: "none".into(),
        },
    );
    // The server prefers the tagged envelope and agrees to turn FEC off. Built
    // by a function because the responder and the post-handshake profile
    // instantiation each need their own copy.
    fn server_profile() -> LocalProfile {
        profile_from(
            rustnies::config::HandshakeConfig {
                kex: "noise-ik".into(),
                propose: false,
            },
            rustnies::config::CryptoConfig::default(),
            rustnies::config::TransportConfig {
                handshake: "plain".into(),
                data: vec!["tagged".into(), "same-as-handshake".into()],
                tag_hex: Some("beef".into()),
            },
            rustnies::config::FecConfig {
                scheme: vec!["none".into()],
                ..Default::default()
            },
            rustnies::config::CongestionConfig {
                algorithm: "none".into(),
            },
        )
    }

    /// Wrap a raw test socket as a UDP carrier.
    ///
    /// The tests drive real sockets (relays, loss injectors) rather than mock
    /// carriers, so they adapt at the boundary instead of re-plumbing every site.
    fn udp_carrier(sock: &Arc<UdpSocket>, peer: SocketAddr) -> Arc<dyn Carrier> {
        Arc::new(UdpCarrier::new(sock.clone(), peer))
    }

    // --- handshake over loopback UDP ---
    let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server_sock.local_addr().unwrap();
    let server_kp = KeyPair::generate();
    let client_kp = KeyPair::generate();
    let server_pub = server_kp.public;

    let obf = ObfuscationStack::new();
    let server_task = {
        let obf = ObfuscationStack::new();
        let carrier = udp_carrier(&server_sock, server_addr);
        let kp = clone_keypair(&server_kp);
        tokio::spawn(async move {
            handshake::server(carrier, kp, server_profile(), &obf)
                .await
                .expect("server handshake failed")
        })
    };
    let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let established_client = tokio::time::timeout(
        Duration::from_secs(10),
        handshake::client(
            udp_carrier(&client_sock, server_addr),
            server_addr,
            &client_kp,
            server_pub,
            &client_profile,
            &obf,
        ),
    )
    .await
    .expect("client handshake timed out")
    .expect("client handshake failed");
    let established_server = tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .expect("server task join timed out")
        .expect("server task panicked");

    // --- the negotiation produced the profile we asked for ---
    let sel = established_client.selection;
    assert_eq!(sel, established_server.selection, "both ends agreed");
    assert_eq!(
        sel.fec,
        rustnies::fec::FEC_NONE_ID,
        "FEC was negotiated off"
    );
    assert_eq!(sel.transport, rustnies::transport::TRANSPORT_TAGGED);
    assert_eq!(
        sel.transport_tag,
        [0xBE, 0xEF],
        "the server's tag_hex was carried in the selection, not configured on the client"
    );
    assert_eq!(sel.cipher, rustnies::crypto::suite::CIPHER_CHACHA20POLY1305);
    assert_eq!(established_client.session_id, established_server.session_id);
    assert_eq!(established_client.send_key, established_server.recv_key);

    // --- both ends instantiate an identical runnable profile ---
    let client_resolved = resolved_profile(&client_profile, &established_client);
    let server_resolved = resolved_profile(&server_profile(), &established_server);
    assert_eq!(client_resolved.describe(), server_resolved.describe());
    assert_eq!(client_resolved.transport.name(), "tagged");
    assert!(
        !client_resolved.fec.active(),
        "FEC is inactive on both ends"
    );
    assert_eq!(client_resolved.congestion.name(), "none");
    assert_eq!(
        client_resolved.cipher.key_schedule(),
        server_resolved.cipher.key_schedule()
    );

    // --- data flows through the tagged envelope with FEC and CC disabled ---
    let (client_inject_tx, client_inject_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (client_capture_tx, client_capture_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (server_inject_tx, server_inject_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (server_capture_tx, server_capture_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let client_tun = Box::new(PipeTun {
        name: "rustnies0".into(),
        mtu: 1400,
        inject_rx: Arc::new(Mutex::new(client_inject_rx)),
        capture_tx: client_capture_tx,
    });
    let server_tun = Box::new(PipeTun {
        name: "rustnies".into(),
        mtu: 1400,
        inject_rx: Arc::new(Mutex::new(server_inject_rx)),
        capture_tx: server_capture_tx,
    });

    let mut client_tunnel = Tunnel::from_handshake(
        client_tun,
        udp_carrier(&client_sock, server_addr),
        established_client.peer,
        Session::new(established_client.session_id, SessionRole::Initiator),
        client_resolved,
        ObfuscationStack::new(),
        established_client.send_key,
        established_client.recv_key,
        established_client.send_dir,
        established_client.recv_dir,
        Arc::new(Mutex::new(Counters::new())),
    )
    .unwrap();
    let mut server_tunnel = Tunnel::from_handshake(
        server_tun,
        udp_carrier(&server_sock, server_addr),
        established_server.peer,
        Session::new(established_server.session_id, SessionRole::Responder),
        server_resolved,
        ObfuscationStack::new(),
        established_server.send_key,
        established_server.recv_key,
        established_server.send_dir,
        established_server.recv_dir,
        Arc::new(Mutex::new(Counters::new())),
    )
    .unwrap();

    // `max_m = 4` in the config, but the negotiated scheme is inactive, so the
    // tunnel must collapse the parity budget to zero rather than emit parities
    // the peer's decoder was not built for.
    client_tunnel.configure_fec(&rustnies::config::FecConfig {
        scheme: vec!["none".into()],
        k: 1,
        min_m: 0,
        max_m: 4,
        initial_m: 2,
    });
    server_tunnel.configure_fec(&rustnies::config::FecConfig {
        scheme: vec!["none".into()],
        ..Default::default()
    });

    client_tunnel.set_keepalive_params(Duration::from_secs(2), Duration::from_secs(20));
    server_tunnel.set_keepalive_params(Duration::from_secs(2), Duration::from_secs(20));

    let (client_udp_tx, client_udp_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
    tokio::spawn(socket_reader(client_sock.clone(), client_udp_tx));
    let (server_udp_tx, server_udp_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
    tokio::spawn(socket_reader(server_sock.clone(), server_udp_tx));

    let (client_stop_tx, client_stop_rx) = watch::channel(false);
    let (server_stop_tx, server_stop_rx) = watch::channel(false);
    let client_task =
        tokio::spawn(async move { client_tunnel.run(client_stop_rx, client_udp_rx).await });
    let server_task =
        tokio::spawn(async move { server_tunnel.run(server_stop_rx, server_udp_rx).await });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Client -> server.
    let want: Vec<Vec<u8>> = (0..5u8)
        .map(|i| {
            let mut p = vec![0xC0; 64];
            p[0] = 0x45;
            p[20] = i;
            p
        })
        .collect();
    for p in &want {
        client_inject_tx.send(p.clone()).unwrap();
    }
    let mut got_rx = server_capture_rx;
    let got = collect_packets(
        &mut got_rx,
        want.len(),
        Duration::from_millis(500),
        Duration::from_secs(10),
    )
    .await;
    assert_eq!(
        got, want,
        "every packet survives the tagged envelope with FEC off"
    );

    // Server -> client, so the other direction is covered too.
    let back: Vec<Vec<u8>> = (0..5u8)
        .map(|i| {
            let mut p = vec![0xB0; 96];
            p[0] = 0x45;
            p[20] = 0x80 + i;
            p
        })
        .collect();
    for p in &back {
        server_inject_tx.send(p.clone()).unwrap();
    }
    let mut got_rx = client_capture_rx;
    let got = collect_packets(
        &mut got_rx,
        back.len(),
        Duration::from_millis(500),
        Duration::from_secs(10),
    )
    .await;
    assert_eq!(got, back, "the reverse direction works too");

    let _ = client_stop_tx.send(true);
    let _ = server_stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), client_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
}

// ---------------------------------------------------------------------------
// Carrier: a full session over TCP rather than UDP
// ---------------------------------------------------------------------------

/// An accepted loopback TCP connection, as `(server_side, client_side)`.
///
/// Done through `std` and converted to tokio, so the connection is fully
/// established before any await point. The listener is dropped: these tests
/// exercise the steady-state carrier, not `accept`.
fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let client = std::net::TcpStream::connect(addr).unwrap();
    let (server, _) = listener.accept().unwrap();
    client.set_nonblocking(true).unwrap();
    server.set_nonblocking(true).unwrap();
    (
        TcpStream::from_std(server).unwrap(),
        TcpStream::from_std(client).unwrap(),
    )
}

/// The handshake must complete over a length-delimited stream, not just a
/// datagram socket. This is the test that would fail if the carrier seam leaked
/// a datagram assumption into the handshake path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_completes_over_a_tcp_carrier() {
    let (server_stream, client_stream) = tcp_pair();
    let server_addr = server_stream.local_addr().unwrap();
    let client_addr = client_stream.local_addr().unwrap();

    let server_carrier: Arc<dyn Carrier> =
        Arc::new(TcpCarrier::new(server_stream, client_addr).unwrap());
    let client_carrier: Arc<dyn Carrier> =
        Arc::new(TcpCarrier::new(client_stream, server_addr).unwrap());

    let server_kp = KeyPair::generate();
    let client_kp = KeyPair::generate();

    let server_handle = {
        let kp = clone_keypair(&server_kp);
        let carrier = server_carrier.clone();
        tokio::spawn(async move {
            handshake::server(carrier, kp, default_profile(), &ObfuscationStack::new())
                .await
                .expect("server handshake failed over tcp")
        })
    };

    let established_client = tokio::time::timeout(
        Duration::from_secs(5),
        handshake::client(
            client_carrier.clone(),
            server_addr,
            &client_kp,
            server_kp.public,
            &default_profile(),
            &ObfuscationStack::new(),
        ),
    )
    .await
    .expect("client handshake timed out over tcp")
    .expect("client handshake failed over tcp");

    let established_server = tokio::time::timeout(Duration::from_secs(5), server_handle)
        .await
        .expect("server join timed out")
        .expect("server task panicked");

    assert_eq!(
        established_client.send_key, established_server.recv_key,
        "client send key == server recv key over tcp"
    );
    assert_eq!(
        established_client.recv_key, established_server.send_key,
        "client recv key == server send key over tcp"
    );
    assert_eq!(
        established_client.session_id, established_server.session_id,
        "session ids match over tcp"
    );
}

/// A steady-state tunnel over TCP: real handshake, real tunnels, data both ways.
///
/// The tunnels are driven directly (not via `run_server`) so the test isolates
/// the carrier: everything except the byte pipe is the production code path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_flows_in_both_directions_over_a_tcp_carrier() {
    let (server_stream, client_stream) = tcp_pair();
    let server_addr = server_stream.local_addr().unwrap();
    let client_addr = client_stream.local_addr().unwrap();

    let server_carrier: Arc<dyn Carrier> =
        Arc::new(TcpCarrier::new(server_stream, client_addr).unwrap());
    let client_carrier: Arc<dyn Carrier> =
        Arc::new(TcpCarrier::new(client_stream, server_addr).unwrap());

    let server_kp = KeyPair::generate();
    let client_kp = KeyPair::generate();

    // --- handshake -------------------------------------------------------
    let server_handle = {
        let kp = clone_keypair(&server_kp);
        let carrier = server_carrier.clone();
        tokio::spawn(async move {
            handshake::server(carrier, kp, default_profile(), &ObfuscationStack::new())
                .await
                .expect("server handshake failed over tcp")
        })
    };
    let established_client = tokio::time::timeout(
        Duration::from_secs(5),
        handshake::client(
            client_carrier.clone(),
            server_addr,
            &client_kp,
            server_kp.public,
            &default_profile(),
            &ObfuscationStack::new(),
        ),
    )
    .await
    .expect("client handshake timed out")
    .expect("client handshake failed");
    let established_server = tokio::time::timeout(Duration::from_secs(5), server_handle)
        .await
        .expect("server join timed out")
        .expect("server task panicked");

    // --- tunnels ---------------------------------------------------------
    // Each side gets a MemTun plus a reader task pulling whole messages off
    // the carrier, exactly as the daemon wires a UDP client.
    let (client_tun, client_inject, mut client_rx) = MemTun::pair("rustnies0", 1400);
    let (server_tun, server_inject, mut server_rx) = MemTun::pair("rustnies", 1400);

    let mut client_tunnel = Tunnel::from_handshake(
        client_tun,
        client_carrier.clone(),
        established_client.peer,
        Session::new(established_client.session_id, SessionRole::Initiator),
        resolved_profile(&default_profile(), &established_client),
        ObfuscationStack::new(),
        established_client.send_key,
        established_client.recv_key,
        established_client.send_dir,
        established_client.recv_dir,
        Arc::new(Mutex::new(Counters::new())),
    )
    .unwrap();
    let mut server_tunnel = Tunnel::from_handshake(
        server_tun,
        server_carrier.clone(),
        established_server.peer,
        Session::new(established_server.session_id, SessionRole::Responder),
        resolved_profile(&default_profile(), &established_server),
        ObfuscationStack::new(),
        established_server.send_key,
        established_server.recv_key,
        established_server.send_dir,
        established_server.recv_dir,
        Arc::new(Mutex::new(Counters::new())),
    )
    .unwrap();

    let (c_tx, c_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
    let (s_tx, s_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
    let c_reader = tokio::spawn(carrier_reader(client_carrier.clone(), c_tx));
    let s_reader = tokio::spawn(carrier_reader(server_carrier.clone(), s_tx));
    let (_c_stop_tx, c_stop_rx) = watch::channel(false);
    let (_s_stop_tx, s_stop_rx) = watch::channel(false);

    let c_run = tokio::spawn(async move { client_tunnel.run(c_stop_rx, c_rx).await });
    let s_run = tokio::spawn(async move { server_tunnel.run(s_stop_rx, s_rx).await });

    // --- client -> server ------------------------------------------------
    client_inject
        .send(vec![
            0x45, 0, 0, 20, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 40, 1, 10, 7, 0, 2,
        ])
        .unwrap();
    let to_server = tokio::time::timeout(Duration::from_secs(5), server_rx.recv())
        .await
        .expect("server did not receive the client packet over tcp")
        .expect("server tun channel closed");
    assert_eq!(
        to_server[0], 0x45,
        "server saw the client's inner IP packet"
    );
    assert_eq!(to_server.len(), 20);

    // --- server -> client ------------------------------------------------
    server_inject
        .send(vec![
            0x45, 0, 0, 20, 9, 9, 9, 9, 9, 9, 9, 9, 0, 0, 40, 1, 10, 7, 0, 3,
        ])
        .unwrap();
    let to_client = tokio::time::timeout(Duration::from_secs(5), client_rx.recv())
        .await
        .expect("client did not receive the server packet over tcp")
        .expect("client tun channel closed");
    assert_eq!(
        to_client[0], 0x45,
        "client saw the server's inner IP packet"
    );
    assert_eq!(to_client.len(), 20);

    c_run.abort();
    s_run.abort();
    c_reader.abort();
    s_reader.abort();
}

/// A full-MTU packet must survive TCP's stream framing. This is the case a
/// datagram carrier gets for free and a stream carrier must reassemble: the
/// payload spans several reads, and the 2-byte length prefix is the only thing
/// delimiting it.
///
/// Runs both tunnels, because the point is that a large frame crosses a real
/// stream in both directions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_mtu_packet_survives_tcp_stream_framing() {
    let (server_stream, client_stream) = tcp_pair();
    let server_addr = server_stream.local_addr().unwrap();
    let client_addr = client_stream.local_addr().unwrap();

    let server_carrier: Arc<dyn Carrier> =
        Arc::new(TcpCarrier::new(server_stream, client_addr).unwrap());
    let client_carrier: Arc<dyn Carrier> =
        Arc::new(TcpCarrier::new(client_stream, server_addr).unwrap());

    let server_kp = KeyPair::generate();
    let client_kp = KeyPair::generate();
    let server_handle = {
        let kp = clone_keypair(&server_kp);
        let carrier = server_carrier.clone();
        tokio::spawn(async move {
            handshake::server(carrier, kp, default_profile(), &ObfuscationStack::new())
                .await
                .expect("server handshake failed")
        })
    };
    let established_client = tokio::time::timeout(
        Duration::from_secs(5),
        handshake::client(
            client_carrier.clone(),
            server_addr,
            &client_kp,
            server_kp.public,
            &default_profile(),
            &ObfuscationStack::new(),
        ),
    )
    .await
    .expect("timed out")
    .expect("client handshake failed");
    let established_server = tokio::time::timeout(Duration::from_secs(5), server_handle)
        .await
        .expect("server join timed out")
        .expect("server task panicked");

    // FEC off, so the frame on the wire is exactly one packet plus its
    // header/tag: no parity symbols to confuse the byte count.
    let profile = |e: &handshake::SessionEstablished| {
        let mut p = resolved_profile(&default_profile(), e);
        p.fec = Box::new(rustnies::fec::NoFec);
        p
    };

    let (client_tun, client_inject, _client_rx) = MemTun::pair("rustnies0", 1400);
    let (server_tun, _server_inject, mut server_rx) = MemTun::pair("rustnies", 1400);

    let mut client_tunnel = Tunnel::from_handshake(
        client_tun,
        client_carrier.clone(),
        established_client.peer,
        Session::new(established_client.session_id, SessionRole::Initiator),
        profile(&established_client),
        ObfuscationStack::new(),
        established_client.send_key,
        established_client.recv_key,
        established_client.send_dir,
        established_client.recv_dir,
        Arc::new(Mutex::new(Counters::new())),
    )
    .unwrap();
    let mut server_tunnel = Tunnel::from_handshake(
        server_tun,
        server_carrier.clone(),
        established_server.peer,
        Session::new(established_server.session_id, SessionRole::Responder),
        profile(&established_server),
        ObfuscationStack::new(),
        established_server.send_key,
        established_server.recv_key,
        established_server.send_dir,
        established_server.recv_dir,
        Arc::new(Mutex::new(Counters::new())),
    )
    .unwrap();

    let (c_tx, c_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
    let (s_tx, s_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
    let c_reader = tokio::spawn(carrier_reader(client_carrier.clone(), c_tx));
    let s_reader = tokio::spawn(carrier_reader(server_carrier.clone(), s_tx));
    let (_c_stop, c_stop_rx) = watch::channel(false);
    let (_s_stop, s_stop_rx) = watch::channel(false);
    let c_run = tokio::spawn(async move { client_tunnel.run(c_stop_rx, c_rx).await });
    let s_run = tokio::spawn(async move { server_tunnel.run(s_stop_rx, s_rx).await });

    // The largest inner packet the protocol carries: MAX_PAYLOAD is
    // 1400 - HEADER_LEN(24) - AEAD_TAG_LEN(16) = 1360, and the tunnel drops
    // anything above it. So this is exactly at the limit, which is the
    // interesting case: one byte more and the tunnel refuses to send it.
    let mut big = vec![0u8; 1360];
    big[0] = 0x45;
    let total = u16::from_be_bytes([0x05, 0x50]); // 1360
    big[2..4].copy_from_slice(&total.to_be_bytes());
    for (i, b) in big.iter_mut().enumerate().skip(20) {
        *b = (i % 251) as u8; // a non-uniform pattern, so a misframed byte shows
    }
    client_inject.send(big.clone()).unwrap();

    let got = tokio::time::timeout(Duration::from_secs(5), server_rx.recv())
        .await
        .expect("full-MTU packet never arrived over tcp")
        .expect("tun channel closed");
    assert_eq!(
        got.len(),
        big.len(),
        "packet length preserved across stream framing"
    );
    assert_eq!(got, big, "packet bytes preserved across stream framing");

    c_run.abort();
    s_run.abort();
    c_reader.abort();
    s_reader.abort();
}
