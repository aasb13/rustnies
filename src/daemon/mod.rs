//! The persistent daemon process: owns the tunnel task(s) and the IPC server.
//!
//! `rustnies client` / `rustnies server` run a daemon in the foreground. The
//! CLI then talks to it over IPC for live stats and control — it never
//! relaunches the whole VPN.
//!
//! Both sides install a Ctrl+C (SIGINT) handler wired to the same shared
//! `tokio::sync::watch` stop channel as the IPC `Stop` command, so either
//! trigger produces a graceful shutdown (the tunnel sends a `Close` to the
//! peer before exiting).
//!
//! The **server** is fully async and multi-client: a single UDP socket accepts
//! an unbounded number of Noise IK handshakes and runs one independent tunnel
//! per client ([`crate::tunnel::server`]). The **client** runs one tunnel
//! against a single server endpoint.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use crate::carrier::{Carrier, bind_carrier_listener, connect_carrier};
use tokio::sync::{Mutex, mpsc, watch};

use crate::config::{ClientConfig, ServerConfig, ServerFileConfig};
use crate::crypto::keys::KeyPair;
use crate::obfuscation;
use crate::platform;
use crate::protocol::profile::{LocalProfile, ResolvedProfile};
use crate::protocol::session::{Session, SessionRole};
use crate::stats::Counters;
use crate::tun::TunFactory;
use crate::tunnel::Tunnel;
use crate::tunnel::TunnelExit;
use crate::tunnel::handshake;
use crate::tunnel::peers::PeerAuth;
use crate::tunnel::server;

/// Initial delay between client reconnection attempts (after a handshake
/// failure or a session teardown). Doubled after each failure, up to
/// [`RECONNECT_MAX_BACKOFF`].
const RECONNECT_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
/// Upper bound for the client reconnection backoff.
const RECONNECT_MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Clamp a configured TUN MTU to the largest value whose full-size inner
/// packets still fit the wire-safe payload budget without outer fragmentation.
///
/// The device MTU is the inner IP packet size the OS may hand us; the tunnel
/// adds `HEADER_LEN + AEAD_TAG_LEN` per datagram. Values at or below
/// `MAX_PAYLOAD` pass through unchanged; larger ones (including the legacy
/// 1400 default) are clamped to `MAX_PAYLOAD` so the kernel fragments the
/// *inner* packet (which the peer reassembles losslessly) instead of us
/// emitting an *outer* UDP datagram the path must fragment or drop.
pub fn effective_tun_mtu(configured: u32) -> u32 {
    let cap = crate::protocol::header::MAX_PAYLOAD as u32;
    configured.min(cap).max(576)
}

/// Run the client daemon. The TUN device and route rules are brought up once
/// and kept alive for the lifetime of the daemon; only the UDP session is
/// re-established on disconnect. With `reconnect` enabled (the default), a
/// handshake failure or session teardown triggers a new connection attempt
/// after a backoff delay instead of exiting the process, so the client keeps
/// trying until the server is reachable again or the user stops it. Returns
/// when the stop signal fires (Ctrl+C or the IPC `Stop` command), or — with
/// `reconnect` disabled — after the first session ends.
pub async fn run_client(mut cfg: ClientConfig) -> std::io::Result<()> {
    tracing::info!(
        server = %cfg.server,
        reconnect = cfg.reconnect,
        "rustnies client daemon starting"
    );

    if cfg.key_path.as_os_str().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no key file specified: set `key_path` in the config file or pass `--key`",
        ));
    }

    // The kill switch is only meaningful when all traffic is routed through
    // the tunnel: without route-all, normal traffic leaves via the real
    // interface and the kill switch would block it even while the tunnel is
    // up. Enabling the kill switch therefore forces route-all on.
    if cfg.kill_switch && !cfg.route_all {
        tracing::info!("kill switch enabled; forcing route-all on");
        cfg.route_all = true;
    }

    // Load the client static keypair and the server's expected public key.
    // Both are fixed for the daemon's lifetime and reused across reconnections.
    let client_kp = KeyPair::load_or_create(&cfg.key_path)?;
    let server_pub = parse_pubkey(&cfg.server_pubkey_hex).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad server pubkey")
    })?;

    // Shared stop signal: fired by IPC `Stop` and Ctrl+C. The reconnection
    // loop consults `stop_rx` between attempts and aborts its backoff sleeps
    // when it fires, so a stop request takes effect promptly.
    let (stop_tx, mut stop_rx) = watch::channel(false);
    spawn_ctrl_c(stop_tx.clone());

    // IPC counters (the client has one tunnel; the same Arc is shared with it).
    let counters = Arc::new(Mutex::new(Counters::new()));
    {
        let mut c = counters.lock().await;
        c.kill_switch = cfg.kill_switch;
        c.dns_leak_protection = cfg.route_all && cfg.dns_leak_protection;
        c.side = crate::stats::DaemonMode::Client;
    }

    tokio::spawn(crate::ipc::serve(
        cfg.ipc_path.clone(),
        counters.clone(),
        stop_tx.clone(),
        None,
    ));

    // Bring up the TUN once. It is kept up for the whole daemon lifetime —
    // tearing it down on every reconnect would flap the interface and break
    // the route-all / route-file rules that reference it by name. Each tunnel
    // session borrows it; the reconnection loop reclaims it with
    // [`Tunnel::into_tun`] when a session ends.
    let factory = platform_factory()?;
    let tun_v6 = cfg
        .tun_addr6
        .as_ref()
        .map(|addr| (addr.as_str(), cfg.tun_prefix6.unwrap_or(64)));
    // Clamp the device MTU to the wire-safe payload budget so the OS never
    // hands us an inner packet that would fragment the outer UDP datagram.
    let device_mtu = effective_tun_mtu(cfg.tun_mtu);
    if device_mtu != cfg.tun_mtu {
        tracing::info!(
            configured = cfg.tun_mtu,
            effective = device_mtu,
            "clamping TUN MTU to wire-safe payload budget"
        );
    }
    let mut tun = factory.build(
        &cfg.tun_name,
        &cfg.tun_addr,
        cfg.tun_prefix,
        tun_v6,
        device_mtu,
    )?;
    tracing::info!(tun = ?tun.name(), "TUN up (client)");

    // Route-all: if requested, install a host route to the VPN server's real IP
    // via the original default gateway, then replace the default route to point
    // through the TUN. The server-host route is installed *first* so UDP
    // tunnel traffic does not loop back into the tunnel itself.
    let mut route_guard: Option<RouteGuardBox> = None;
    if cfg.route_all {
        match install_route_all(&cfg.server, &cfg.tun_name) {
            Ok(rg) => {
                tracing::info!(server = %cfg.server, tun = %cfg.tun_name, "route-all enabled: default route -> TUN, server host route via original gateway");
                route_guard = Some(rg);
            }
            Err(e) => {
                tracing::warn!(error = ?e, "failed to install route-all rules; tunnel will run in subnet-only mode");
            }
        }
    }

    // Route-file: if a path is configured, install explicit routes for every
    // destination listed in it through the TUN device. This is independent of
    // route-all and uses netlink directly (no per-entry `ip` spawn), so large
    // route files are practical.
    let mut route_file_guard: Option<RouteFileGuardBox> = None;
    if let Some(rp) = cfg.route_path.as_ref() {
        match install_route_file(&cfg.tun_name, rp).await {
            Ok(g) => {
                tracing::info!(route_file = %rp.display(), tun = %cfg.tun_name, "route-file routes installed");
                route_file_guard = Some(g);
            }
            Err(e) => {
                tracing::warn!(error = ?e, route_file = %rp.display(), "failed to install route-file routes; continuing without them");
            }
        }
    }

    // DNS leak prevention: when route-all is active, block DNS (port 53) from
    // leaving via any interface other than the TUN and (unless `dns` is an
    // explicit empty list) rewrite /etc/resolv.conf to a resolver reachable
    // through the tunnel, so name resolution actually goes through the tunnel
    // instead of the system's normal resolver. Installed before the kill
    // switch so the DNS chain is jumped from OUTPUT first (its per-rule
    // counters stay meaningful for `rustnies dns-check`). Held for the
    // daemon lifetime; removed on shutdown.
    let mut dns_guard: Option<DnsLeakGuardBox> = None;
    let mut resolv_guard: Option<ResolvConfGuardBox> = None;
    if cfg.route_all && cfg.dns_leak_protection {
        let dns_servers: Vec<String> = cfg
            .dns
            .clone()
            .unwrap_or_else(|| vec!["1.1.1.1".to_string()]);
        #[cfg(target_os = "linux")]
        {
            let backend = std::sync::Arc::new(crate::platform::linux::IptablesBackend);
            let mut g = crate::platform::linux::DnsLeakGuard::new(&cfg.tun_name, backend);
            match g.install() {
                Ok(()) => {
                    tracing::info!(tun = %cfg.tun_name, "DNS leak prevention installed");
                    dns_guard = Some(DnsLeakGuardBox::new(g));
                }
                Err(e) => {
                    tracing::warn!(error = ?e, "failed to install DNS leak prevention; DNS may leak via the real interface")
                }
            }
            if !dns_servers.is_empty() {
                let mut rg = crate::platform::linux::ResolvConfGuard::new(
                    "/etc/resolv.conf",
                    "/etc/resolv.conf.rustnies.bak",
                );
                match rg.install(&dns_servers) {
                    Ok(()) => {
                        tracing::info!(servers = ?dns_servers, "resolv.conf rewritten to tunnel DNS");
                        resolv_guard = Some(ResolvConfGuardBox::new(rg));
                    }
                    Err(e) => {
                        tracing::warn!(error = ?e, "failed to rewrite /etc/resolv.conf; DNS may leak to the local resolver")
                    }
                }
            } else {
                tracing::info!(
                    "dns is an empty list; skipping resolv.conf rewrite (firewall block only)"
                );
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = &dns_servers;
            tracing::warn!("DNS leak prevention is not implemented on this platform");
        }
    }

    // Kill switch: block all non-tunnel outbound traffic except the encrypted
    // tunnel UDP to the server and loopback. The rules are held for the
    // daemon's lifetime (across reconnects) and only removed on a graceful
    // shutdown, so if the tunnel drops the client cannot fall back to the real
    // internet (fail closed). Installed after DNS leak prevention so its
    // chain follows the DNS chain in OUTPUT. A failed install is fatal: the
    // user asked for protection, so we refuse to run unprotected.
    let mut kill_switch_guard: Option<KillSwitchBox> = None;
    if cfg.kill_switch {
        #[cfg(target_os = "linux")]
        {
            let backend = std::sync::Arc::new(crate::platform::linux::IptablesBackend);
            let mut ks =
                crate::platform::linux::KillSwitch::new(cfg.server, &cfg.tun_name, backend);
            match ks.install() {
                Ok(()) => {
                    tracing::info!(server = %cfg.server, tun = %cfg.tun_name, "kill switch engaged");
                    kill_switch_guard = Some(KillSwitchBox::new(ks));
                }
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "failed to install kill switch: {e}; refusing to start unprotected \
                             (disable the kill switch — drop --kill-switch / set \
                             kill_switch = false — to start without it)"
                        ),
                    ));
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            tracing::warn!("kill switch is not implemented on this platform");
        }
    }

    // Client-side NAT (LAN sharing): masquerade forwarded traffic leaving via
    // the TUN so a LAN behind this client can share the tunnel — the server
    // only knows the client's TUN IP, not the LAN behind it, so without this
    // the server would route replies back to the client's TUN IP and the LAN
    // hosts would never see them. On by default; disable with `--no-nat` /
    // `[nat] enabled = false`. Best-effort: a failure (not root, no iptables)
    // is logged and the tunnel still comes up for the client itself — only
    // LAN sharing would not work. Held for the daemon lifetime (it references
    // the TUN name, which stays up across reconnects) and removed on shutdown.
    let mut nat_guard: Option<NatRulesBox> = None;
    if cfg.enable_nat {
        #[cfg(target_os = "linux")]
        {
            let mut rules = crate::platform::linux::NatRules::new_client(
                cfg.nat_source_cidr.clone(),
                cfg.tun_name.clone(),
            );
            match rules.install() {
                Ok(()) => {
                    tracing::info!(
                        tun = %cfg.tun_name,
                        source = ?cfg.nat_source_cidr,
                        "client NAT (LAN sharing) installed",
                    );
                    nat_guard = Some(NatRulesBox::new(rules));
                }
                Err(e) => {
                    tracing::warn!(error = ?e, "failed to install client NAT rules (are we root?)");
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            tracing::warn!("client NAT is not implemented on this platform");
        }
    }

    // Build the obfuscation stack once from the config. It is rebuilt (re-seeded)
    // per session from the handshake hash, but the layer configuration is fixed
    // for the daemon lifetime. An empty stack (the default) is an identity.
    let obfuscation_cfg = cfg.obfuscation.as_ref();
    let obf_stack = obfuscation::build_shared_stack(obfuscation_cfg);

    // Resolve this side's protocol profile from config. Every configured part
    // name is validated here, once, so a typo fails at startup with the
    // offending string in the message rather than as a handshake timeout later.
    let local_profile = match LocalProfile::from_role_config(
        &cfg.handshake,
        &cfg.crypto,
        &cfg.transport,
        &cfg.fec,
        &cfg.congestion,
    ) {
        Ok(p) => p,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid [protocol] configuration: {e}"),
            ));
        }
    };
    tracing::info!(
        profile = ?local_profile,
        "client protocol profile resolved from config"
    );

    // Reconnection loop. Each iteration opens a fresh carrier,
    // runs the Noise IK handshake, drives one tunnel session to completion,
    // then — if reconnection is enabled — starts again. A failed handshake
    // or a torn-down session is retried after an exponentially growing backoff
    // (capped) that is reset to the initial value once a session is
    // established. The backoff sleep is abortable by the stop signal.
    let mut backoff = RECONNECT_INITIAL_BACKOFF;

    loop {
        if *stop_rx.borrow() {
            break;
        }

        // A fresh carrier for this connection attempt. For a datagram carrier
        // that is a new ephemeral port each time (as before); for a stream
        // carrier it is a fresh connection.
        let carrier: Arc<dyn Carrier> = match connect_carrier(&cfg.carrier.name, cfg.server).await {
            Ok(c) => Arc::from(c),
            Err(e) => {
                tracing::error!(error = ?e, carrier = %cfg.carrier.name, "failed to open client carrier");
                {
                    let mut c = counters.lock().await;
                    c.reconnecting = true;
                    c.reconnect_attempts = c.reconnect_attempts.saturating_add(1);
                    c.last_error = Some(format!("bind failed: {e}"));
                }
                if !cfg.reconnect {
                    return Err(e);
                }
                if !sleep_or_stop(backoff, &mut stop_rx).await {
                    break;
                }
                backoff = (backoff * 2).min(RECONNECT_MAX_BACKOFF);
                continue;
            }
        };

        // Noise IK handshake. Stoppable: if the user hits Ctrl+C / IPC Stop
        // mid-handshake, bail out immediately rather than waiting for the
        // handshake's own internal retry budget to drain.
        let established = tokio::select! {
            biased;
            _ = stop_rx.changed() => {
                // Stopped mid-handshake: don't report ourselves as reconnecting.
                let mut c = counters.lock().await;
                c.reconnecting = false;
                break;
            }
            res = handshake::client(
                carrier.clone(),
                cfg.server,
                &client_kp,
                server_pub,
                &local_profile,
                &obf_stack,
            ) => match res {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        server = %cfg.server,
                        "client handshake failed"
                    );
                    {
                        let mut c = counters.lock().await;
                        c.reconnecting = true;
                        c.reconnect_attempts = c.reconnect_attempts.saturating_add(1);
                        c.last_error = Some(format!("{e}"));
                    }
                    if !cfg.reconnect {
                        return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
                    }
                    tracing::info!(backoff = ?backoff, "reconnecting after handshake failure");
                    if !sleep_or_stop(backoff, &mut stop_rx).await {
                        break;
                    }
                    backoff = (backoff * 2).min(RECONNECT_MAX_BACKOFF);
                    continue;
                }
            },
        };

        // Session established: reset the backoff and the published reconnect
        // state for the next disconnect.
        backoff = RECONNECT_INITIAL_BACKOFF;
        {
            let mut c = counters.lock().await;
            c.reconnecting = false;
            c.reconnect_attempts = 0;
            c.last_error = None;
        }

        // `from_handshake` only fails on an internal FEC invariant (a
        // Reed-Solomon generator that cannot be built for the default FEC
        // parameters); it does not depend on the network, so retrying is
        // pointless. Abort rather than spin.
        //
        // Initialise the obfuscation stack's per-session keying material from
        // the handshake hash. Both peers derive the same seed from the same
        // handshake hash, so keying-based layers (e.g. header_xor) activate
        // identically on both sides. A fresh clone of the stack is used per
        // session so the init does not leak across reconnects.
        let session_stack = (*obf_stack).clone();
        session_stack.init(&established.handshake_hash);

        // Instantiate the profile the server selected. The client validates the
        // selection during `client_finalize`, so a server running something this
        // build cannot do already failed the handshake; reaching here means the
        // two ends agree and can build identical profiles.
        let resolved = match ResolvedProfile::with_handshake_transport(
            &established.selection,
            &established.handshake_hash,
            &*local_profile.handshake_transport,
            local_profile.new_congestion(),
        ) {
            Ok(p) => p,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("server selected an unusable protocol profile: {e}"),
                ));
            }
        };
        tracing::info!(profile = %resolved.describe(), "client session profile negotiated");

        let session = Session::new(established.session_id, SessionRole::Initiator);
        let mut tunnel = Tunnel::from_handshake(
            tun,
            carrier.clone(),
            established.peer,
            session,
            resolved,
            session_stack,
            established.send_key,
            established.recv_key,
            established.send_dir,
            established.recv_dir,
            counters.clone(),
        )?;

        // Apply FEC tuning from the resolved config. The erasure code itself came
        // from the negotiated profile.
        tunnel.configure_fec(&cfg.fec);

        // Feed the tunnel from a dedicated socket-reader task so the
        // steady-state loop can be identical to the server's channel-fed
        // form. The task self-terminates when the tunnel's UDP receiver is
        // dropped at session end.
        let (udp_tx, udp_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
        tokio::spawn(socket_reader(carrier.clone(), udp_tx));

        let exit = tunnel.run(stop_tx.subscribe(), udp_rx).await;

        // Reclaim the TUN device so the next iteration reuses the same
        // interface (and the same routes). The rest of the tunnel state is
        // dropped here.
        tun = tunnel.into_tun();

        // Publish why the session ended so `rustnies status` can report it
        // (e.g. "session timeout", "peer closed") while we reconnect. A
        // user-initiated stop clears the reconnect state instead of marking
        // us reconnecting.
        {
            let mut c = counters.lock().await;
            c.connected = false;
            if exit == TunnelExit::Stopped || *stop_rx.borrow() {
                c.reconnecting = false;
                c.last_error = None;
            } else {
                c.reconnecting = true;
                c.reconnect_attempts = c.reconnect_attempts.saturating_add(1);
                c.last_error = Some(exit.to_string());
            }
        }

        if *stop_rx.borrow() {
            break;
        }
        if !cfg.reconnect {
            // Original fail-fast behaviour: a single session, then exit.
            break;
        }
        tracing::info!(exit = %exit, "tunnel down; reconnecting");
        if !sleep_or_stop(RECONNECT_INITIAL_BACKOFF, &mut stop_rx).await {
            break;
        }
    }

    drop(resolv_guard); // restores /etc/resolv.conf
    drop(dns_guard); // removes DNS leak firewall rules
    drop(kill_switch_guard); // unblocks direct internet
    drop(nat_guard); // removes client-side LAN-sharing MASQUERADE rules
    drop(route_guard); // removes route-all rules via Drop
    drop(route_file_guard); // removes route-file routes via Drop
    Ok(())
}

/// Sleep for `dur`, but return early if the stop signal fires. Returns
/// `false` if the stop signal was observed (the caller should break its
/// loop), `true` if the full duration elapsed without a stop.
async fn sleep_or_stop(dur: Duration, stop: &mut watch::Receiver<bool>) -> bool {
    if *stop.borrow() {
        return false;
    }
    tokio::select! {
        biased;
        _ = stop.changed() => !*stop.borrow(),
        _ = tokio::time::sleep(dur) => true,
    }
}

/// Run the server daemon (multi-client, async, unbounded handshakes).
pub async fn run_server(cfg: ServerConfig) -> std::io::Result<()> {
    tracing::info!(listen = %cfg.listen, "rustnies server daemon starting");

    if cfg.key_path.as_os_str().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no key file specified: set `key_path` in the config file or pass `--key`",
        ));
    }

    let listener = bind_carrier_listener(&cfg.carrier.name, cfg.listen).await?;

    let server_kp = KeyPair::load_or_create(&cfg.key_path)?;
    tracing::info!(
        pubkey = hex::encode(server_kp.public_bytes()),
        "server static public key"
    );

    // Peer authorization: the authorized set comes from the `[[peers]]`
    // array in the TOML config. `None` (no `[[peers]]` section) means open
    // mode (accept every peer, phase-1 compatibility); `Some(vec)` restricts
    // to the listed keys — including an explicit empty list, which rejects
    // everyone. Held behind an Arc<std Mutex> so the handshake responder
    // (sync) can consult it and SIGHUP can reload it.
    let peer_auth = match &cfg.peers {
        Some(entries) => {
            if entries.is_empty() {
                tracing::info!("configured with an empty [[peers]] list; rejecting all handshakes");
            } else {
                tracing::info!(
                    peers = entries.len(),
                    "using authorized peer list from config [[peers]]"
                );
            }
            Arc::new(StdMutex::new(PeerAuth::from_entries(entries)))
        }
        None => {
            tracing::info!(
                "no [[peers]] section in config; running in open mode (all peers accepted)"
            );
            Arc::new(StdMutex::new(PeerAuth::open_mode()))
        }
    };
    spawn_sighup(peer_auth.clone(), cfg.config_path.clone());

    // Shared stop signal: fired by IPC `Stop` and Ctrl+C.
    let (stop_tx, stop_rx) = watch::channel(false);
    spawn_ctrl_c(stop_tx.clone());

    // One shared counters set aggregated across all client tunnels.
    let counters = Arc::new(Mutex::new(Counters::new()));
    {
        let mut c = counters.lock().await;
        c.side = crate::stats::DaemonMode::Server;
    }

    // Control channel: lets the IPC server send operator commands (revoke,
    // disconnect, list-sessions) to the dispatcher task. Created before the
    // IPC server so the handle can be passed in.
    let (control_tx, control_rx) = mpsc::channel::<crate::tunnel::server::ControlCommand>(16);
    let server_handle = crate::tunnel::server::ServerHandle {
        peer_auth: peer_auth.clone(),
        control_tx,
    };

    tokio::spawn(crate::ipc::serve(
        cfg.ipc_path.clone(),
        counters.clone(),
        stop_tx.clone(),
        Some(server_handle),
    ));

    // Bring up the single shared TUN before NAT so the interface exists.
    let factory = platform_factory()?;
    let tun_v6 = cfg
        .tun_addr6
        .as_ref()
        .map(|addr| (addr.as_str(), cfg.tun_prefix6.unwrap_or(64)));
    let device_mtu = effective_tun_mtu(cfg.tun_mtu);
    if device_mtu != cfg.tun_mtu {
        tracing::info!(
            configured = cfg.tun_mtu,
            effective = device_mtu,
            "clamping TUN MTU to wire-safe payload budget"
        );
    }
    let tun = factory.build(
        &cfg.tun_name,
        &cfg.tun_addr,
        cfg.tun_prefix,
        tun_v6,
        device_mtu,
    )?;
    tracing::info!(tun = ?tun.name(), "TUN up (server, shared by all clients)");

    // NAT.
    let mut nat = None;
    if cfg.enable_nat {
        let tun_cidr = format!(
            "{}/{}",
            cidr_base(&cfg.tun_addr, cfg.tun_prefix),
            cfg.tun_prefix
        );
        let mut rules = crate::platform::linux::NatRules::new(
            tun_cidr,
            cfg.tun_name.clone(),
            cfg.nat_out_iface.clone(),
        );
        // Add IPv6 NAT if a dual-stack TUN is configured.
        if let Some(addr6) = &cfg.tun_addr6 {
            let prefix6 = cfg.tun_prefix6.unwrap_or(64);
            let cidr6 = format!("{}/{}", cidr_base_v6(addr6, prefix6), prefix6);
            rules = rules.with_v6_cidr(cidr6);
        }
        match rules.install() {
            Ok(()) => {
                tracing::info!("NAT rules installed");
                nat = Some(rules);
            }
            Err(e) => {
                tracing::warn!(error = ?e, "failed to install NAT rules (are we root?)");
            }
        }
    }

    // Build the obfuscation stack from the config. The server uses one shared
    // stack configuration; each client tunnel gets a fresh clone that is
    // seeded from that client's handshake hash (see `server::handle_handshake`).
    let obf_stack = obfuscation::build_shared_stack(cfg.obfuscation.as_ref());

    // Resolve the server's protocol profile from config. The server is
    // authoritative: this ordering is what the selection in the handshake
    // message-2 payload walks when a client proposes alternatives.
    let local_profile = match LocalProfile::from_role_config(
        &cfg.handshake,
        &cfg.crypto,
        &cfg.transport,
        &cfg.fec,
        &cfg.congestion,
    ) {
        Ok(p) => p,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid [protocol] configuration: {e}"),
            ));
        }
    };
    tracing::info!(
        profile = ?local_profile,
        "server protocol profile resolved from config"
    );

    // The TUN subnet(s) the dispatcher trusts for tunnel-IP learning: only
    // inner source addresses inside these nets are registered as client
    // tunnel IPs (implausible sources are rejected with a warning instead of
    // silently polluting return-path routing).
    let mut tun_nets: Vec<ipnet::IpNet> = Vec::new();
    if let Ok(net) = format!(
        "{}/{}",
        cidr_base(&cfg.tun_addr, cfg.tun_prefix),
        cfg.tun_prefix
    )
    .parse::<ipnet::IpNet>()
    {
        tun_nets.push(net);
    }
    if let Some(addr6) = &cfg.tun_addr6 {
        let prefix6 = cfg.tun_prefix6.unwrap_or(64);
        if let Ok(net) =
            format!("{}/{}", cidr_base_v6(addr6, prefix6), prefix6).parse::<ipnet::IpNet>()
        {
            tun_nets.push(net);
        }
    }

    // Run the multi-client accept/dispatch loop until stopped.
    server::run_server(
        listener,
        server_kp,
        tun,
        local_profile,
        obf_stack,
        stop_rx,
        stop_tx,
        counters,
        cfg.tun_name,
        cfg.tun_mtu,
        tun_nets,
        peer_auth,
        cfg.fec.clone(),
        cfg.max_sessions_per_peer,
        control_rx,
    )
    .await?;

    drop(nat); // drops rules via Drop
    Ok(())
}

/// Spawn a task that waits for Ctrl+C (SIGINT) and signals the shared stop
/// channel. This makes Ctrl+C produce a graceful shutdown (the tunnel sends a
/// `Close` to its peer) instead of killing the process mid-stream.
fn spawn_ctrl_c(stop: watch::Sender<bool>) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!("ctrl-c received; initiating graceful shutdown");
            if stop.send(true).is_err() {
                tracing::debug!("stop signal dropped (no receiver)");
            }
        }
    });
}

/// Spawn a task that waits for SIGHUP and reloads the authorized-peers set
/// live, without restarting the daemon. The `[[peers]]` array is re-read from
/// the same TOML config file the daemon started from: a present `[[peers]]`
/// section (even empty) switches to restrict mode, while a removed section
/// (file.peers == `None`) switches back to open mode. A no-op when no config
/// file was loaded (pure-CLI startup) — there is nothing to re-read.
#[cfg(unix)]
fn spawn_sighup(peer_auth: Arc<StdMutex<PeerAuth>>, config_path: Option<std::path::PathBuf>) {
    use tokio::signal::unix::{SignalKind, signal};
    let path = match config_path {
        Some(p) => p,
        None => {
            tracing::info!(
                "no config file loaded; SIGHUP peer reload disabled (restart to change peers)"
            );
            return;
        }
    };
    tokio::spawn(async move {
        let mut stream = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = ?e, "failed to install SIGHUP handler; live peer reload disabled");
                return;
            }
        };
        loop {
            stream.recv().await;
            tracing::info!("SIGHUP received; reloading authorized peers from config");
            match ServerFileConfig::load_or_empty(&path) {
                Ok(file) => {
                    let mut guard = peer_auth.lock().unwrap_or_else(|e| {
                        tracing::error!("peer auth mutex poisoned; recovering");
                        e.into_inner()
                    });
                    match file.peers {
                        Some(entries) => {
                            guard.set_peers(&entries);
                            let n = guard.len();
                            tracing::info!(peers = n, "authorized peers reloaded (restrict mode)");
                        }
                        None => {
                            guard.set_open();
                            tracing::info!(
                                "authorized peers reloaded: no [[peers]] section, open mode"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = ?e, "failed to reload config; keeping previous peer list");
                }
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_sighup(_peer_auth: Arc<StdMutex<PeerAuth>>, _config_path: Option<std::path::PathBuf>) {
    // SIGHUP is Unix-only; non-Unix hosts restart to reload peers.
}

/// Read whole messages from `carrier` and forward them onto `tx` until the
/// carrier errors or all receivers are dropped. Used by the client so its
/// tunnel can receive via the same channel form the server uses.
async fn socket_reader(carrier: Arc<dyn Carrier>, tx: mpsc::Sender<(Vec<u8>, SocketAddr)>) {
    loop {
        // The carrier yields one whole message per recv, so there is no
        // datagram-vs-stream distinction to handle here.
        match carrier.recv().await {
            Ok((data, from)) => {
                if tx.send((data.to_vec(), from)).await.is_err() {
                    break; // tunnel gone
                }
            }
            Err(e) => {
                tracing::warn!(error = ?e, carrier = carrier.name(), "client carrier recv error; reader exiting");
                break;
            }
        }
    }
}

/// Select the platform TUN factory. Currently only Linux has an implementation;
/// other targets fail at runtime so mobile hosts can plug their own in later.
fn platform_factory() -> std::io::Result<Box<dyn TunFactory>> {
    #[cfg(target_os = "linux")]
    {
        return Ok(Box::new(platform::LinuxTunFactory));
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "no platform TUN factory for this target; plug one in via the `platform` module",
        ))
    }
}

/// Type-erased route-all guard. On Linux this wraps the real `RouteGuard`; on
/// other platforms it is a no-op (route-all is Linux-only for now).
pub struct RouteGuardBox {
    #[cfg(target_os = "linux")]
    inner: Option<crate::platform::linux::RouteGuard>,
}

impl RouteGuardBox {
    #[cfg(target_os = "linux")]
    fn new(g: crate::platform::linux::RouteGuard) -> Self {
        Self { inner: Some(g) }
    }
    #[cfg(not(target_os = "linux"))]
    fn new() -> Self {
        Self {}
    }
}

impl Drop for RouteGuardBox {
    fn drop(&mut self) {
        // The inner guard's Drop does the real cleanup on Linux.
        #[cfg(target_os = "linux")]
        {
            self.inner.take();
        }
    }
}

/// Install route-all rules for the platform. On Linux this delegates to the
/// `ip route` orchestration; other platforms return an error.
fn install_route_all(
    server: &std::net::SocketAddr,
    tun_name: &str,
) -> std::io::Result<RouteGuardBox> {
    #[cfg(target_os = "linux")]
    {
        let g = crate::platform::linux::install_route_all(server, tun_name)?;
        Ok(RouteGuardBox::new(g))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (server, tun_name);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "route-all is not implemented on this platform",
        ))
    }
}

/// Type-erased route-file guard. On Linux this wraps the real
/// [`crate::platform::linux::RouteFileGuard`]; on other platforms it is a
/// no-op (route-file is Linux-only for now).
pub struct RouteFileGuardBox {
    #[cfg(target_os = "linux")]
    inner: Option<crate::platform::linux::RouteFileGuard>,
}

impl RouteFileGuardBox {
    #[cfg(target_os = "linux")]
    fn new(g: crate::platform::linux::RouteFileGuard) -> Self {
        Self { inner: Some(g) }
    }
    #[cfg(not(target_os = "linux"))]
    fn new() -> Self {
        Self {}
    }
}

impl Drop for RouteFileGuardBox {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.inner.take();
        }
    }
}

/// Install route-file routes for the platform. On Linux this reads the file
/// and adds each destination over netlink; other platforms return an error.
async fn install_route_file(
    tun_name: &str,
    path: &std::path::Path,
) -> std::io::Result<RouteFileGuardBox> {
    #[cfg(target_os = "linux")]
    {
        let g = crate::platform::linux::install_route_file(tun_name, path).await?;
        Ok(RouteFileGuardBox::new(g))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (tun_name, path);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "route-file is not implemented on this platform",
        ))
    }
}

/// Type-erased kill switch guard. On Linux wraps the real
/// [`crate::platform::linux::KillSwitch`]; on other platforms a no-op.
pub struct KillSwitchBox {
    #[cfg(target_os = "linux")]
    inner: Option<crate::platform::linux::KillSwitch>,
}

impl KillSwitchBox {
    #[cfg(target_os = "linux")]
    fn new(g: crate::platform::linux::KillSwitch) -> Self {
        Self { inner: Some(g) }
    }
    #[cfg(not(target_os = "linux"))]
    fn new() -> Self {
        Self {}
    }
}

impl Drop for KillSwitchBox {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.inner.take();
        }
    }
}

/// Type-erased client-side NAT guard. On Linux wraps the real
/// [`crate::platform::linux::NatRules`] (LAN-sharing MASQUERADE); on other
/// platforms a no-op.
pub struct NatRulesBox {
    #[cfg(target_os = "linux")]
    inner: Option<crate::platform::linux::NatRules>,
}

impl NatRulesBox {
    #[cfg(target_os = "linux")]
    fn new(g: crate::platform::linux::NatRules) -> Self {
        Self { inner: Some(g) }
    }
    #[cfg(not(target_os = "linux"))]
    fn new() -> Self {
        Self {}
    }
}

impl Drop for NatRulesBox {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.inner.take();
        }
    }
}

/// Type-erased DNS leak firewall guard. On Linux wraps the real
/// [`crate::platform::linux::DnsLeakGuard`]; on other platforms a no-op.
pub struct DnsLeakGuardBox {
    #[cfg(target_os = "linux")]
    inner: Option<crate::platform::linux::DnsLeakGuard>,
}

impl DnsLeakGuardBox {
    #[cfg(target_os = "linux")]
    fn new(g: crate::platform::linux::DnsLeakGuard) -> Self {
        Self { inner: Some(g) }
    }
    #[cfg(not(target_os = "linux"))]
    fn new() -> Self {
        Self {}
    }
}

impl Drop for DnsLeakGuardBox {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.inner.take();
        }
    }
}

/// Type-erased resolv.conf guard. On Linux wraps the real
/// [`crate::platform::linux::ResolvConfGuard`]; on other platforms a no-op.
pub struct ResolvConfGuardBox {
    #[cfg(target_os = "linux")]
    inner: Option<crate::platform::linux::ResolvConfGuard>,
}

impl ResolvConfGuardBox {
    #[cfg(target_os = "linux")]
    fn new(g: crate::platform::linux::ResolvConfGuard) -> Self {
        Self { inner: Some(g) }
    }
    #[cfg(not(target_os = "linux"))]
    fn new() -> Self {
        Self {}
    }
}

impl Drop for ResolvConfGuardBox {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.inner.take();
        }
    }
}

fn parse_pubkey(hex_str: &str) -> Option<crate::crypto::keys::PublicKey> {
    let bytes = hex::decode(hex_str.trim()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let arr: [u8; 32] = bytes[..32].try_into().ok()?;
    Some(crate::crypto::keys::PublicKey::from(arr))
}

/// Compute the network base address for a given addr/prefix, e.g.
/// `cidr_base("10.7.0.1", 24) == "10.7.0.0"`. Uses proper subnet masking so
/// non-/24 prefixes (and host bits set anywhere in the address) produce the
/// correct network — the MASQUERADE rule built from this must cover exactly
/// the TUN subnet, otherwise client traffic escapes un-NATed (replies can
/// never return) or unrelated subnets get NATed. Falls back to the address
/// itself when it does not parse as IPv4.
fn cidr_base(addr: &str, prefix: u8) -> String {
    if let Ok(ip) = addr.parse::<std::net::Ipv4Addr>() {
        if let Ok(net) = ipnet::IpNet::new(std::net::IpAddr::V4(ip), prefix) {
            return net.network().to_string();
        }
    }
    addr.to_string()
}

/// Compute the base network address from an IPv6 address and prefix length.
/// Zeroes out the host bits to derive the network prefix CIDR for NAT.
fn cidr_base_v6(addr: &str, prefix: u8) -> String {
    if let Ok(ip) = addr.parse::<std::net::Ipv6Addr>() {
        let segs = ip.segments();
        // For /64 and above, zero out the interface-ID portion (groups beyond
        // the prefix boundary). For smaller prefixes, fall through to the full
        // address (the caller handles /48 etc. in the config).
        if prefix >= 64 {
            let network_groups = (prefix as usize) / 16;
            let mut masked = segs;
            for seg in masked.iter_mut().skip(network_groups) {
                *seg = 0;
            }
            return std::net::Ipv6Addr::from(masked).to_string();
        }
    }
    addr.to_string()
}

// Keep the unused SocketAddr import used in some builds honest.
#[allow(unused_imports)]
use SocketAddr as _SocketAddr;

#[cfg(test)]
mod tests {
    use super::cidr_base;
    use super::cidr_base_v6;
    use super::sleep_or_stop;
    use std::time::Duration;

    #[test]
    fn cidr_base_computes_network_for_default_slash24() {
        // The default server config (10.7.0.1/24) must NAT exactly 10.7.0.0/24.
        assert_eq!(cidr_base("10.7.0.1", 24), "10.7.0.0");
    }

    #[test]
    fn cidr_base_masks_host_bits_for_non_24_prefixes() {
        // The old string-splitting implementation returned garbage (or an
        // over-broad network) for anything but /24; the MASQUERADE scope
        // depends on this being exact.
        assert_eq!(cidr_base("10.7.0.200", 25), "10.7.0.128");
        assert_eq!(cidr_base("10.8.3.5", 16), "10.8.0.0");
        assert_eq!(cidr_base("10.7.0.1", 32), "10.7.0.1");
    }

    #[test]
    fn cidr_base_falls_back_to_input_when_unparseable() {
        assert_eq!(cidr_base("not-an-ip", 24), "not-an-ip");
    }

    use tokio::sync::watch;

    /// If the stop signal is already set when the sleep begins, the helper
    /// must return `false` immediately without actually sleeping.
    #[tokio::test]
    async fn sleep_or_stop_returns_false_if_already_stopped() {
        let (tx, mut rx) = watch::channel(false);
        tx.send(true).unwrap();
        let ok = sleep_or_stop(Duration::from_secs(60), &mut rx).await;
        assert!(!ok, "already-stopped sleep should return false immediately");
    }

    /// With no stop signal, the helper sleeps the full duration and returns
    /// `true`.
    #[tokio::test]
    async fn sleep_or_stop_sleeps_full_when_not_stopped() {
        let (_tx, mut rx) = watch::channel(false);
        let ok = sleep_or_stop(Duration::from_millis(25), &mut rx).await;
        assert!(ok, "uninterrupted sleep should return true");
    }

    /// If the stop signal fires during the sleep, the helper must abort
    /// promptly and return `false` rather than waiting out the full duration.
    #[tokio::test]
    async fn sleep_or_stop_aborts_when_stop_fires_during_sleep() {
        let (tx, mut rx) = watch::channel(false);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(25)).await;
            tx.send(true).unwrap();
        });
        let started = std::time::Instant::now();
        let ok = sleep_or_stop(Duration::from_secs(30), &mut rx).await;
        let elapsed = started.elapsed();
        assert!(!ok, "stop during sleep should return false");
        assert!(
            elapsed < Duration::from_secs(5),
            "sleep should abort promptly after stop, not wait 30s (elapsed {elapsed:?})"
        );
    }

    #[test]
    fn cidr_base_v6_extracts_network_prefix() {
        assert_eq!(cidr_base_v6("fd00::1", 64), "fd00::");
        assert_eq!(cidr_base_v6("2001:db8::42", 64), "2001:db8::");
    }

    #[test]
    fn cidr_base_v6_short_prefix_keeps_full_address() {
        assert_eq!(cidr_base_v6("2001:db8::42", 48), "2001:db8::42");
    }

    #[test]
    fn cidr_base_v6_full_address_no_compression() {
        // An address with explicit groups before the :: — the network prefix
        // is extracted by trimming the interface-ID portion.
        assert_eq!(
            cidr_base_v6("2001:db8:1234:5678::1", 64),
            "2001:db8:1234:5678::"
        );
    }

    #[test]
    fn effective_tun_mtu_clamps_to_wire_safe_payload() {
        use crate::protocol::header::MAX_PAYLOAD;
        // The legacy 1400 default exceeds the payload budget and must clamp.
        assert_eq!(super::effective_tun_mtu(1400), MAX_PAYLOAD as u32);
        // Larger values clamp the same way; smaller ones pass through.
        assert_eq!(super::effective_tun_mtu(9000), MAX_PAYLOAD as u32);
        assert_eq!(super::effective_tun_mtu(1280), 1280);
        assert_eq!(
            super::effective_tun_mtu(MAX_PAYLOAD as u32),
            MAX_PAYLOAD as u32
        );
        // Degenerate tiny values floor at the minimum IP MTU instead of zero.
        assert_eq!(super::effective_tun_mtu(0), 576);
    }
}
