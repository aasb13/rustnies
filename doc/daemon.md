# Daemon and IPC

rustnies runs the VPN as a **persistent background process** (the daemon). A
lightweight CLI communicates with the running daemon over local IPC (a Unix
domain socket) to query live stats or issue commands, without relaunching the
whole VPN or disrupting the tunnel session.

## Daemon

`src/daemon/mod.rs` owns the tunnel task and the IPC server.

### `run_client(cfg: ClientConfig)`

1. Initialise tracing (`tracing-subscriber` with `EnvFilter`; default
   level `info`, override via `RUST_LOG` or `log_level` in config / `--log-level`.
   Optional `log_file` / `--log-file` adds a file layer (append mode) alongside
   stdout.
2. Bind a UDP socket to `0.0.0.0:0` (ephemeral local port).
3. Load (or generate and persist) the client static keypair from
   `cfg.key_path`.
4. Parse the server's static public key from `cfg.server_pubkey_hex`.
5. Create the shared `Counters` (held in `Arc<Mutex<Counters>>`).
6. Spawn the IPC server on `cfg.ipc_path`.
7. Build the TUN via the platform factory. When `cfg.tun_addr6` is set, the TUN is
   configured dual-stack (IPv4 + IPv6); otherwise it is IPv4-only. See
   [doc/ipv6.md](ipv6.md) for the dual-stack implementation notes. Route-all,
   the kill switch, DNS leak prevention, and NAT all operate on both stacks when
   IPv6 is enabled.
8. Run the Noise IK handshake (client side), retried until success.
9. Construct a `Tunnel` from the handshake result and run the steady-state
   loop until shutdown.

### `run_server(cfg: ServerConfig)`

1. Initialise tracing (same as client branch: `RUST_LOG` > `log_level` config
   > `info` default; optional `log_file` / `--log-file` for file output).
2. Bind a UDP socket to `cfg.listen`.
3. Load (or generate and persist) the server static keypair; log the public key
   as hex (this is the value the client needs via `--server-key`).
4. Create shared `Counters` + shutdown channel.
5. Spawn the IPC server on `cfg.ipc_path`.
6. Build the TUN via the platform factory.
7. If `cfg.enable_nat`, install NAT rules via `NatRules` (auto-detecting the
   egress interface if `cfg.nat_out_iface` is `None`). When a dual-stack TUN is
   configured (`tun_addr6` set), the server also installs `ip6tables`
   MASQUERADE for the IPv6 TUN CIDR and `sysctl net.ipv6.conf.all.forwarding=1`;
   IPv6 rules are best-effort (skipped if `ip6tables` is absent). See
   [doc/ipv6.md](ipv6.md).
8. Run the multi-client dispatch loop (`tunnel::server::run_server`) until stopped.
   The loop owns the session tables keyed by `SessionId`; each inbound datagram
   is (1) peek-routed by `SessionId`, (2) rate-limited handshake-probe, or
   (3) addressed-index fallback. A per-static-key cap
   (`cfg.max_sessions_per_peer`, default 0 = unlimited) evicts the oldest-idle
   session of an oversubscribed peer on a new handshake instead of refusing it.
9. On exit, drop the NAT rules (via `Drop`).

### Shutdown

The tunnel's `run` loop selects on a `oneshot::Receiver<()>`. The IPC server
holds the `oneshot::Sender` inside an `Arc<Mutex<Option<Sender>>>`; when a
`Stop` request arrives, it takes the sender and fires it, causing the tunnel
loop to send a `Close` packet to the peer and exit. Receiving `Close` from the
peer also tears down the loop.

## IPC

`src/ipc/mod.rs` + `src/ipc/messages.rs`.

### Transport

- Unix domain socket at `cfg.ipc_path` (default
  `/run/rustnies/{client,server}.sock` — a fixed path, not `$TMPDIR`, so the
  daemon and the CLI agree on it across sudo / systemd `PrivateTmp`).
- The daemon creates the socket's parent directory if it is missing.
- Permissions `0o660` on Unix.
- Framing: **newline-delimited JSON**. The CLI sends one `Request` per line;
  the daemon responds with one `Response` per line.
- The daemon accepts multiple concurrent clients; each is handled in its own
  task. A client sends one request, reads one response, and exits.

### Messages

`Request` (tagged enum, `snake_case`):

| Variant | Meaning |
|---------|---------|
| `status` | Request a live stats snapshot. |
| `stop`   | Tell the daemon to tear down the tunnel and exit. |
| `ping`   | Round-trip a liveness probe. |

`Response` (tagged enum, `snake_case`):

| Variant | Meaning |
|---------|---------|
| `status(Stats)` | A live stats snapshot. |
| `ack(String)`   | A simple acknowledgement (e.g. `pong`, `stopping`). |
| `error(String)` | An error message. |

### Stats

`src/stats.rs` defines `Counters` (mutable, owned by the tunnel) and `Stats`
(a serialisable snapshot). The tunnel updates `Counters` on every send/receive,
FEC recovery, RTT sample, and FEC parameter change. A `status` IPC request
calls `Counters::snapshot()` and returns the resulting `Stats`.

`Stats` fields:

| Field | Type | Meaning |
|-------|------|---------|
| `side` | DaemonMode | Which daemon role produced this snapshot (`Client` / `Server`). |
| `connected` | bool | Is the tunnel up? |
| `uptime_secs` | f64 | Seconds since the tunnel started. |
| `loss_rate` | f64 | Smoothed packet loss ratio (0..1). |
| `rtt_ms` | f64 | Smoothed round-trip time in milliseconds. |
| `fec_k` | u8 | Current FEC group source count. |
| `fec_m` | u8 | Current FEC group parity count. |
| `fec_overhead` | f64 | `m / k`, the current redundancy ratio. |
| `tx_packets` | u64 | Packets sent. |
| `rx_packets` | u64 | Packets received. |
| `tx_bytes` | u64 | Bytes sent. |
| `rx_bytes` | u64 | Bytes received. |
| `fec_recovered` | u64 | Source symbols recovered by FEC. |
| `congestion_window` | f64 | Current congestion window in packets (`cwnd / mtu`). |
| `in_flight` | u64 | Outstanding unacked bytes. |
| `pacing_rate` | f64 | Current pacing rate in bytes/second (`cwnd / srtt`, clamped). |
| `clients` | u64 | Connected client tunnels (server; 0 on client). |
| `reconnecting` | bool | Client is in the reconnection backoff loop. |
| `reconnect_attempts` | u32 | Current reconnection attempt (1-based). |
| `last_error` | Option&lt;String&gt; | Most recent failure that drove reconnection. |
| `kill_switch` | bool | Kill switch engaged (fail-closed). Client only. |
| `dns_leak_protection` | bool | DNS leak prevention active. Client only. |
| `handshakes_accepted` | u64 | Handshake requests accepted. |
| `handshakes_rejected` | u64 | Handshake requests rejected (bad key, etc.). |
| `handshake_errors` | u64 | Malformed/error handshakes. |
| `sessions_timed_out` | u64 | Sessions closed on idle timeout. |
| `sessions_peer_closed` | u64 | Sessions closed by peer. |
| `sessions_evicted` | u64 | Sessions evicted by the session cap. |
| `sessions_roamed` | u64 | Sessions rebound to a new client address. |
| `tx_dropped_congestion` | u64 | Packets dropped because the window was full. |
| `tx_paced` | u64 | Packets held by the pacer (rate-limited, not dropped). |
| `rtt_samples` | u64 | Delivered packets whose RTT was fed to the controller. |

### `ipc::serve(path, counters, shutdown_tx)`

Binds the socket, removes any stale socket file first, sets `0o660` perms, and
loops accepting connections. Each connection reads requests line-by-line and
writes one response per request. `Stop` takes the shutdown sender and fires it.

### `ipc::request(path, req)`

Client-side helper: connects to the socket, sends one JSON request, reads one
JSON response, returns it. Used by the `status` / `stop` / `ping` CLI
subcommands.

### `ipc::format_stats(Stats)`

Pretty-prints a `Stats` snapshot for the `status` command output.

## Why not relaunch the VPN for control

Relaunching the whole VPN to query stats would either (a) tear down the
existing session, or (b) require a separate "stats mode" that duplicates
state-ownership logic. The daemon + IPC split keeps the tunnel state in one
long-lived process and makes the CLI a thin, unprivileged client. This also
matches how a mobile app would integrate: the app process hosts the daemon, and
UI screens query it over the same IPC surface.
