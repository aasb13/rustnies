//! Daemon <-> CLI IPC over a Unix domain socket.
//!
//! Protocol: newline-delimited JSON. The CLI opens the socket, sends one
//! [`Request`], reads one [`Response`], and exits. The daemon multiplexes
//! requests and owns the tunnel task handle that commands act on.

pub mod messages;

use std::io;
use std::path::PathBuf;

use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tokio::sync::watch;

use crate::stats::Stats;
use crate::tunnel::server::{ControlCommand, ServerHandle};

use messages::{Request, Response};

/// Run the IPC server until the process exits. `stats` is shared live counters
/// the daemon publishes; `stop` is signalled by `Request::Stop` (and also by
/// Ctrl+C from the daemon), using a shared `watch` channel so multiple sources
/// can request shutdown. `server_handle` gives the IPC server access to
/// server-only operations (revoke, list_sessions, disconnect); pass `None` on
/// the client side.
pub async fn serve(
    path: PathBuf,
    stats: std::sync::Arc<Mutex<crate::stats::Counters>>,
    stop: watch::Sender<bool>,
    server_handle: Option<ServerHandle>,
) -> io::Result<()> {
    // Ensure the socket's parent directory exists. A stock install relies on
    // systemd's `RuntimeDirectory=rustnies`, but a manual foreground run (no
    // systemd, no install script) would otherwise fail to bind with `ENOENT`.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755));
            }
        }
    }
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o660);
        std::fs::set_permissions(&path, perms)?;
    }
    tracing::info!(path = %path.display(), "IPC socket listening");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let stats = stats.clone();
                let stop = stop.clone();
                let handle = server_handle.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, stats, stop, handle).await {
                        tracing::warn!(error = ?e, "ipc client error");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = ?e, "ipc accept error");
                continue;
            }
        }
    }
}

async fn handle_client(
    stream: UnixStream,
    stats: std::sync::Arc<Mutex<crate::stats::Counters>>,
    stop: watch::Sender<bool>,
    server_handle: Option<ServerHandle>,
) -> io::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::Error(format!("bad request: {e}"));
                writer
                    .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
                    .await?;
                continue;
            }
        };
        let resp = match req {
            Request::Status => {
                let s = stats.lock().await;
                Response::Status(s.snapshot())
            }
            Request::Stop => {
                if stop.send(true).is_err() {
                    tracing::debug!("stop signal dropped (no tunnel task listening)");
                }
                Response::Ack("stopping".into())
            }
            Request::Ping => Response::Ack("pong".into()),
            Request::Revoke { public_key } => handle_revoke(&public_key, &server_handle).await,
            Request::ListSessions => handle_list_sessions(&server_handle).await,
            Request::Disconnect {
                session_id,
                peer_key,
            } => handle_disconnect(session_id, peer_key.as_deref(), &server_handle).await,
        };
        writer
            .write_all((serde_json::to_string(&resp)? + "\n").as_bytes())
            .await?;
    }
    Ok(())
}

async fn handle_revoke(public_key: &str, server_handle: &Option<ServerHandle>) -> Response {
    let handle = match server_handle {
        Some(h) => h,
        None => return Response::Error("revoke is only available on the server daemon".into()),
    };
    let bytes = match hex::decode(public_key.trim()) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return Response::Error("invalid public key: must be 32-byte hex".into()),
    };
    // Add to the runtime denylist (persistent across SIGHUP reloads).
    {
        let mut guard = handle.peer_auth.lock().unwrap_or_else(|e| e.into_inner());
        let pk = crate::crypto::keys::PublicKey::from(bytes);
        if guard.is_revoked(&pk) {
            return Response::Ack(format!("peer key {} already revoked", public_key));
        }
        guard.revoke(&bytes);
        let label = guard.check(&pk).1.unwrap_or_else(|| "unknown".to_string());
        tracing::info!(peer_key = %public_key, label = %label, "peer key revoked at runtime");
    }
    // Evict live sessions via the control channel.
    let (tx, rx) = tokio::sync::oneshot::channel();
    if handle
        .control_tx
        .send(ControlCommand::Revoke {
            peer_key: bytes,
            tx,
        })
        .await
        .is_err()
    {
        return Response::Error("dispatcher is not running".into());
    }
    match rx.await {
        Ok(n) => Response::Ack(format!("revoked; {} active session(s) evicted", n)),
        Err(_) => Response::Error("dispatcher dropped the response (shutdown in progress?)".into()),
    }
}

async fn handle_list_sessions(server_handle: &Option<ServerHandle>) -> Response {
    let handle = match server_handle {
        Some(h) => h,
        None => {
            return Response::Error("list_sessions is only available on the server daemon".into());
        }
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    if handle
        .control_tx
        .send(ControlCommand::ListSessions { tx })
        .await
        .is_err()
    {
        return Response::Error("dispatcher is not running".into());
    }
    match rx.await {
        Ok(sessions) => Response::Sessions(sessions),
        Err(_) => Response::Error("dispatcher dropped the response (shutdown in progress?)".into()),
    }
}

async fn handle_disconnect(
    session_id: Option<u32>,
    peer_key: Option<&str>,
    server_handle: &Option<ServerHandle>,
) -> Response {
    let handle = match server_handle {
        Some(h) => h,
        None => return Response::Error("disconnect is only available on the server daemon".into()),
    };
    let pk_bytes = match peer_key {
        Some(hex_str) => match hex::decode(hex_str.trim()) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                Some(arr)
            }
            _ => return Response::Error("invalid peer key: must be 32-byte hex".into()),
        },
        None => None,
    };
    if session_id.is_none() && pk_bytes.is_none() {
        return Response::Error("disconnect requires --session or --peer-key".into());
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    if handle
        .control_tx
        .send(ControlCommand::Disconnect {
            session_id,
            peer_key: pk_bytes,
            tx,
        })
        .await
        .is_err()
    {
        return Response::Error("dispatcher is not running".into());
    }
    match rx.await {
        Ok(n) => Response::Ack(format!("{} session(s) disconnected", n)),
        Err(_) => Response::Error("dispatcher dropped the response (shutdown in progress?)".into()),
    }
}

/// Send a single request to the daemon at `path` and return its response.
pub async fn request(path: &std::path::Path, req: Request) -> io::Result<Response> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let stream = UnixStream::connect(path)
        .await
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => io::Error::new(
                e.kind(),
                format!(
                    "no daemon listening at {} (is the rustnies daemon running?)",
                    path.display()
                ),
            ),
            _ => e,
        })?;
    let (reader, mut writer) = stream.into_split();
    let body = serde_json::to_string(&req)? + "\n";
    writer.write_all(body.as_bytes()).await?;
    let mut line = String::new();
    let mut reader = BufReader::new(reader);
    reader.read_line(&mut line).await?;
    let resp: Response = serde_json::from_str(line.trim())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(resp)
}

/// Pretty-print a [`Stats`] for the CLI `status` command.
///
/// Side-specific fields are suppressed so the output is never misleading:
/// `clients` and `handshakes` only appear on the server; `kill switch` and
/// `dns leak` only appear on the client (and the `reconnecting` reconnect loop
/// state is only reflected when the daemon is a client).
pub fn format_stats(s: &Stats) -> String {
    use crate::stats::DaemonMode;
    use std::fmt::Write;

    // Reflect the reconnect loop when the tunnel is down but the daemon is
    // still alive and retrying, so `status` reports *why* and *how many times*
    // it has failed instead of just "no". Only meaningful on the client; the
    // server never reconnects.
    let connected = if s.connected {
        "yes".to_string()
    } else if s.side == DaemonMode::Client && s.reconnecting {
        format!(
            "reconnecting (attempt {}, last error: {})",
            s.reconnect_attempts,
            s.last_error.as_deref().unwrap_or("unknown"),
        )
    } else {
        "no".to_string()
    };

    let mut out = String::new();
    let _ = writeln!(out, "connected: {}", connected);

    // Server-only: aggregate client tunnel count.
    if s.side == DaemonMode::Server {
        let _ = writeln!(out, "clients:   {}", s.clients);
    }

    let _ = writeln!(out, "uptime:    {:.1} s", s.uptime_secs);
    let _ = writeln!(out, "loss rate: {:.2}%", s.loss_rate * 100.0);
    let _ = writeln!(out, "rtt:       {:.1} ms", s.rtt_ms);
    let _ = writeln!(
        out,
        "fec:       k={} m={} ({:.0}% overhead)",
        s.fec_k,
        s.fec_m,
        s.fec_overhead * 100.0
    );
    let _ = writeln!(
        out,
        "tx:        {} pkts / {} bytes",
        s.tx_packets, s.tx_bytes
    );
    let _ = writeln!(
        out,
        "rx:        {} pkts / {} bytes",
        s.rx_packets, s.rx_bytes
    );
    let _ = writeln!(out, "fec recovered: {}", s.fec_recovered);
    // Byte window rendered against the 1400-byte MTU the tunnel defaults to,
    // so the number stays comparable with the old packet-count window.
    let _ = writeln!(
        out,
        "cwnd:      {:.1} pkts (in-flight {:.1} pkts)",
        s.congestion_window / 1400.0,
        s.in_flight as f64 / 1400.0
    );
    let _ = writeln!(
        out,
        "pacing:    {:.0} kbit/s ({} paced, {} dropped-congestion)",
        s.pacing_rate * 8.0 / 1000.0,
        s.tx_paced,
        s.tx_dropped_congestion
    );
    let _ = writeln!(out, "rtt samples:  {}", s.rtt_samples);

    // Server-only: handshake accept/reject counters.
    if s.side == DaemonMode::Server {
        let _ = writeln!(
            out,
            "handshakes:  accepted={} rejected={}",
            s.handshakes_accepted, s.handshakes_rejected
        );
    }

    // Shared across both sides: lifecycle counters (client tracks the single
    // tunnel's lifecycle; server aggregates across all tunnels).
    let _ = writeln!(
        out,
        "sessions:    timed_out={} peer_closed={} evicted={}",
        s.sessions_timed_out, s.sessions_peer_closed, s.sessions_evicted
    );

    // Server-only: dispatcher backpressure metric.
    if s.side == DaemonMode::Server {
        let _ = writeln!(out, "dispatch:    backpressure={}", s.dispatch_backpressure);
    }

    // Client-only: firewall / routing configuration.
    if s.side == DaemonMode::Client {
        let _ = writeln!(
            out,
            "kill switch:  {}",
            if s.kill_switch {
                "on (fail closed)"
            } else {
                "off"
            }
        );
        let _ = writeln!(
            out,
            "dns leak:     {}",
            if s.dns_leak_protection {
                "on (via tunnel)"
            } else {
                "off"
            }
        );
    }

    out
}
