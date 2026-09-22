# CLI usage

The `rustnies` binary has eleven subcommands. `server` and `client` run the VPN
daemon in the foreground (they need root on Linux for TUN + NAT); `status`,
`stop`, `ping`, `revoke`, `list-sessions`, and `disconnect` are IPC clients
that talk to a running daemon (`revoke`, `list-sessions`, and `disconnect` are
server-only; the rest also work against the client daemon); `dns-check` verifies
DNS leak prevention from the firewall state (needs root); `keygen` provisions a
static keypair; `pubkey` re-derives the public half of an existing private key.

```
rustnies VPN — phase 1 modular UDP tunnel

Usage: rustnies <COMMAND>

Commands:
  server        Run the server side of the tunnel
  client        Run the client side of the tunnel
  status        Show live tunnel stats from a running daemon
  stop          Tell a running daemon to stop
  ping          Round-trip an IPC ping to a running daemon
  revoke        Revoke a peer's static key at runtime (server only). Rejects future handshakes from this key and evicts all live sessions for it. Runtime-only — resets on daemon restart (remove the key from the config and SIGHUP for permanent exclusion)
  list-sessions List all live sessions on a server daemon (server only)
  disconnect    Disconnect a session or all sessions for a peer (server only)
  dns-check     Verify DNS leak prevention: show whether DNS queries can only reach a resolver via the tunnel and not the real interface. Reports the active `/etc/resolv.conf` nameserver, the firewall packet counters (DNS via tunnel vs. DNS blocked on the real interface), and optionally performs a live resolution to demonstrate the path. Needs root (reads iptables)
  keygen        Generate a fresh static keypair, persist it, write the public key to <key>.pub, and print the public key
  pubkey        Derive and print the public key from an existing private key file. Also (re)writes <key>.pub alongside it
  help          Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## `server` — run the server daemon

```
rustnies server [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config <path>` | `/etc/rustnies/server.toml` | TOML config file. A missing default path is ignored; a missing `--config` path is an error. See [Config files](#config-files). |
| `--listen <addr>` | `0.0.0.0:46722` | UDP address to listen on. Override of `listen`. |
| `--tun <name>` | `rustnies` | TUN interface name to create. Override of `[tun] name`. |
| `--tun-addr <ip>` | `10.7.0.1` | TUN IPv4 address. Override of `[tun] addr`. |
| `--tun-prefix <n>` | `24` | TUN IPv4 prefix length. Override of `[tun] prefix`. |
| `--tun-addr6 <ip>` | _(none)_ | TUN IPv6 address for dual-stack (e.g. `fd00::1`). When set, an IPv6 address is configured on the TUN alongside IPv4. Omit for an IPv4-only tunnel. Override of `[tun] addr6`. |
| `--tun-prefix6 <n>` | `64` | TUN IPv6 prefix length. Used only when `--tun-addr6` is set; defaults to `64` when omitted. Override of `[tun] prefix6`. |
| `--tun-mtu <n>` | `1400` | TUN MTU. Override of `[tun] mtu`. |
| `--key <path>` | _(required)_ | Server static key file (created if absent). Override of `key_path`. |
| `--nat <bool>` | `true` | Install iptables NAT rules to forward tunneled traffic out. Override of `[nat] enabled`; pass `--nat false` to disable. |
| `--nat-iface <name>` | auto-detect | Egress interface for NAT. Override of `[nat] out_iface`. |
| `--socket <path>` | `/run/rustnies/rustnies.sock` | IPC socket path. Override of `ipc_path`. |
| `--log-level <filter>` | `info` | `RUST_LOG`-style filter (e.g. `debug`, `warn`, `error`, `trace`, or `rustnies::tunnel=trace`). Override of `log_level`. |
| `--verbose` | off | Enable debug logging (equivalent to `--log-level debug`). Overrides `log_level` from the config file. |
| `--log-file <path>` | _(none)_ | Write log lines to this file in addition to stdout (append mode). The parent directory is created if it does not exist. If the file cannot be opened, logging falls back to stdout-only. Override of `log_file`. |
| `--max-sessions-per-peer <n>` | `0` | Max concurrent sessions from one static peer key. `0` = unlimited; `2`–`4` caps a single misbehaving client. The oldest-idle session is evicted when exceeded. Override of `max_sessions_per_peer`. |

On startup the server logs its static public key (64 hex chars). That is the
value the client needs via `--server-key`.

Needs root (for TUN creation and NAT).

## `client` — run the client daemon

```
rustnies client [OPTIONS]
```

`--server-key` (or the config file's `server_key`) is required: the client
refuses to start without a server public key.

| Flag | Default | Description |
|------|---------|-------------|
| `--config <path>` | `/etc/rustnies/client.toml` | TOML config file. A missing default path is ignored; a missing `--config` path is an error. See [Config files](#config-files). |
| `--server <addr>` | `127.0.0.1:46722` | Server UDP endpoint. Override of `server`. |
| `--server-key <hex>` | (required) | The server's 32-byte static public key as 64 hex chars. Override of `server_key`. |
| `--tun <name>` | `rustnies0` | TUN interface name to create. Override of `[tun] name`. |
| `--tun-addr <ip>` | `10.7.0.2` | TUN IPv4 address. Override of `[tun] addr`. |
| `--tun-prefix <n>` | `24` | TUN IPv4 prefix length. Override of `[tun] prefix`. |
| `--tun-addr6 <ip>` | _(none)_ | TUN IPv6 address for dual-stack (e.g. `fd00::2`). When set, an IPv6 address is configured on the TUN alongside IPv4; route-all, NAT, kill switch, and DNS leak prevention then apply to both IPv4 and IPv6. Omit for an IPv4-only tunnel. Override of `[tun] addr6`. |
| `--tun-prefix6 <n>` | `64` | TUN IPv6 prefix length. Used only when `--tun-addr6` is set; defaults to `64` when omitted. Override of `[tun] prefix6`. |
| `--tun-mtu <n>` | `1400` | TUN MTU. Override of `[tun] mtu`. |
| `--key <path>` | _(required)_ | Client static key file (created if absent). Override of `key_path`. |
| `--socket <path>` | `/run/rustnies/rustnies.sock` | IPC socket path. Override of `ipc_path`. |
| `--no-route` | off | Disable route-all. By default the client routes all traffic (not just the TUN subnet) through the tunnel. Adds a host route to the VPN server via the original gateway before replacing the default route. When the server address is IPv6, the IPv6 host route and IPv6 default route are also installed. Override of `route_all`. |
| `--no-reconnect` | off | Disable automatic reconnection. By default the client keeps trying to re-establish the tunnel after a handshake failure or session teardown (with exponential backoff) instead of exiting, and keeps the TUN device and its routes up across reconnects. Pass this to restore the original fail-fast behaviour: exit on the first disconnect. Override of `reconnect`. |
| `--route-path <path>` | _(none)_ | Path to a plain-text file listing extra destinations (IPs or CIDRs, one per line) to route through the TUN device. Blank lines and lines starting with `#` are ignored. Routes are added directly over netlink (no per-entry `ip` process spawn), so files with tens of thousands of entries are practical. Independent of `--no-route`. Override of `route_path`. |
| `--no-dns-leak-protection` | off | Disable DNS leak prevention. By default, when route-all is active, the client blocks DNS (port 53) from leaving via any interface other than the TUN and rewrites `/etc/resolv.conf` to a resolver reachable through the tunnel, so name resolution cannot leak out the real interface. Override of `dns_leak_protection`. |
| `--dns <ip>[,<ip>...]` | `1.1.1.1` | Comma-separated resolver IPs written to `/etc/resolv.conf` while DNS leak prevention is active. The resolvers must be reachable through the tunnel (public resolvers work with route-all). Pass `--dns ""` to skip the `resolv.conf` rewrite and install only the firewall block. Override of `dns`. |
| `--kill-switch` | off | Enable the kill switch: block all outbound traffic except via the TUN, to the VPN server (the encrypted tunnel UDP), and on loopback. If the tunnel drops, the client cannot fall back to the real internet — the rules are kept across reconnects and only removed on a graceful shutdown (fail closed). Enabling this forces route-all on. Override of `kill_switch`. |
| `--no-nat` | off | Disable client-side NAT masquerade. By default the client installs an iptables MASQUERADE rule so a LAN behind this client can share the tunnel: forwarded traffic leaving via the TUN is rewritten to the client's tunnel address (the server only knows the client's TUN IP, not the LAN behind it). Pass this to leave forwarding untouched. Override of `enable_nat` (sets it to `false`). |
| `--nat-source-cidr <cidr>` | _(none)_ | Source CIDR for the client-side MASQUERADE (e.g. `192.168.50.0/24`). By default all traffic leaving via the TUN is masqueraded; set this to scope the rule to one LAN. Override of `[nat] source_cidr`. |
| `--log-level <filter>` | `info` | `RUST_LOG`-style filter (e.g. `debug`, `warn`, `error`, `trace`). Override of `log_level`. |
| `--verbose` | off | Enable debug logging (equivalent to `--log-level debug`). Overrides `log_level` from the config file. |
| `--log-file <path>` | _(none)_ | Write log lines to this file in addition to stdout (append mode). The parent directory is created if it does not exist. If the file cannot be opened, logging falls back to stdout-only. Override of `log_file`. |

Needs root (for TUN creation). The kill switch and DNS leak prevention also
need root (for `iptables`/`ip6tables` and to rewrite `/etc/resolv.conf`); the
kill switch refuses to start if it cannot be installed, so the client never
runs unprotected when you ask for it. When dual-stack TUN is configured
(`--tun-addr6`), these features apply to both IPv4 and IPv6 stacks.

## `status` — query live stats

```
rustnies status [--socket <path>]
```

Sends a `status` IPC request to the running daemon and prints a human-readable
stats block:

```
connected: yes
uptime:    12.4 s
loss rate: 1.20%
rtt:       53.2 ms
fec:       k=4 m=3 (75% overhead)
tx:        1024 pkts / 1048576 bytes
rx:        998 pkts / 1023984 bytes
fec recovered: 12
cwnd:      8.0 (in-flight 3)
```

Defaults to the client daemon's socket; pass `--socket` to target the server
daemon's socket instead.

Does not need root.

## `stop` — tear down the tunnel

```
rustnies stop [--socket <path>]
```

Sends a `stop` IPC request. The daemon sends a `Close` packet to the peer,
exits the tunnel loop, and (on the server) removes the NAT rules. Prints the
daemon's acknowledgement.

Does not need root.

## `ping` — IPC liveness probe

```
rustnies ping [--socket <path>]
```

Sends a `ping` IPC request; the daemon replies with `ack: "pong"`. Useful for
checking that a daemon is running and the IPC socket is reachable.

Does not need root.

## `dns-check` — verify DNS goes through the tunnel

```
rustnies dns-check [--resolv <path>] [--tun <name>] [--host <host>]
```

Verifies DNS leak prevention: confirms that DNS queries can only reach a
resolver via the tunnel, not the real interface. It prints the active
`/etc/resolv.conf` nameserver, snapshots the firewall packet counters (DNS
accepted via the TUN vs. DNS rejected on the real interface), performs a live
resolution of `--host` (default `example.com`) through the system resolver,
then snapshots the counters again and reports the deltas. A clean run shows
the lookup succeeded with `via tunnel +N pkts, blocked +0 pkts` and the verdict
"no DNS leak detected"; a leak attempt shows up as packets rejected on the
real interface.

Reads the live `iptables` counters, so it needs root — run it with `sudo`
while the client daemon is up. The counter parsing is unit-tested, so the
report is reliable across `iptables` versions.

Does not talk to the daemon (it inspects the firewall and resolver state
directly).

## `keygen` — provision a static keypair

```
rustnies keygen --key <path>
```

- If `<path>` does not exist: generates a fresh X25519 static keypair, writes
  the 32 secret bytes to `<path>` with `0600` permissions (Unix), writes the
  32-byte public key as 64 hex characters to `<path>.pub` with `0644`
  permissions, and prints the public key to stdout.
- If `<path>` exists: reads the existing 32-byte secret, (re)writes
  `<path>.pub`, and prints the corresponding public key.

The `.pub` sidecar is plaintext hex and is not sensitive; it exists so the
public key does not live only in terminal scrollback. The client needs this
value via `--server-key`.

Does not need root (as long as the key path is writable by the caller).

## `pubkey` — re-derive the public key from a private key

```
rustnies pubkey --key <path>
```

Reads the existing 32-byte private key at `<path>`, (re)writes `<path>.pub`
with the derived 64-char hex public key (0644 permissions), and prints the
public key to stdout. Use this to recheck a key's public half without
regenerating it. It is an error if `<path>` does not exist (use `keygen` to
create a new keypair).

Does not need root.

## Examples

### Loopback test on one host

```sh
# 1. Provision keys (public key is printed and written to <key>.pub)
sudo ./target/release/rustnies keygen --key /var/lib/rustnies/server.key
# prints: <server_pubkey>  (also in /var/lib/rustnies/server.key.pub)
sudo ./target/release/rustnies keygen --key /var/lib/rustnies/client.key

# 2. Start the server (foreground, root)
sudo ./target/release/rustnies server --key /var/lib/rustnies/server.key

# 3. In another shell, start the client
sudo ./target/release/rustnies client \
    --server 127.0.0.1:46722 \
    --server-key <server_pubkey> \
    --key /var/lib/rustnies/client.key

# 4. In a third shell, query the client daemon
./target/release/rustnies status

# 5. Stop the client daemon
./target/release/rustnies stop

# Lost the pubkey? Re-derive it without regenerating:
sudo ./target/release/rustnies pubkey --key /var/lib/rustnies/server.key
```

### Two-host deployment

On the server (public IP `1.2.3.4`):

```sh
sudo ./target/release/rustnies keygen --key /var/lib/rustnies/server.key
sudo ./target/release/rustnies server \
    --listen 0.0.0.0:46722 \
    --key /var/lib/rustnies/server.key
# pubkey is in /var/lib/rustnies/server.key.pub
```

On the client:

```sh
sudo ./target/release/rustnies keygen --key /var/lib/rustnies/client.key
sudo ./target/release/rustnies client \
    --server 1.2.3.4:46722 \
    --server-key <server_pubkey> \
    --key /var/lib/rustnies/client.key
```

### Logging

The daemon honours `RUST_LOG`:

```sh
sudo RUST_LOG=debug ./target/release/rustnies client ...
sudo RUST_LOG=warn  ./target/release/rustnies server ...
```

Default level is `info`. `--verbose` and the config file's `log_level` are
ignored when `RUST_LOG` is set in the environment.

To also persist logs to a file, use `log_file` in the config file or
`--log-file <path>` on the command line. Log lines are written to both stdout
and the file (append mode). The parent directory is created if it does not
exist. If the file cannot be opened (e.g. permission denied), a warning is
printed to stderr and logging continues to stdout only — the daemon always
starts.

## Config files

`server` and `client` read a TOML config file before applying CLI flags. This
is the convenient form for repeated deployments; every setting below can also
be set (and overridden) via a CLI flag.

Default paths (overridable with `--config <path>`):

- server: `/etc/rustnies/server.toml`
- client: `/etc/rustnies/client.toml`

A missing **default** path is silently ignored (the pure-CLI path still works
out of the box). A missing **`--config`** path is a hard error — the user
asked for that file specifically.

### Precedence

Built-in defaults  <  config file  <  CLI flags

A CLI flag only takes effect when actually passed, so an omitted flag does
**not** clobber a value set in the file. For boolean flags, `--no-route` and
`--verbose` are presence-based (set-true); `--nat` takes an explicit
`true`/`false` value.

### Unknown keys

Unknown keys at any level (top-level sections, `[tun]` / `[nat]` /
`[obfuscation]` sub-tables, or `[[peers]]` entries) produce a `WARN` log line
but do **not** prevent the daemon from starting. This means a typo never
locks you out of your own config. Check the daemon logs at startup for
`unknown config key; ignored` warnings if a setting seems to have no effect.

### Server config (`server.toml`)

```toml
listen    = "0.0.0.0:46722"
key_path  = "/var/lib/rustnies/server.key"  # required — no default; use `keygen` to create it
ipc_path  = "/run/rustnies/rustnies.sock"   # default; the daemon creates the dir if missing
log_level = "info"
log_file  = "/var/log/rustnies/server.log"  # optional: also write logs to this file (append mode)

# Authorized client public keys, inline as an array of tables. Each entry
# needs a `public_key` (64 hex chars / 32 bytes); `name` is an optional
# human-readable label shown in handshake/acceptance logs.
[[peers]]
public_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
name       = "alice"

[[peers]]
public_key = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
name       = "site-b"

[tun]
name   = "rustnies"
addr   = "10.7.0.1"
prefix = 24
addr6  = "fd00::1"  # optional: IPv6 address for dual-stack (prefix6 defaults to 64)
prefix6 = 64
mtu    = 1400

[nat]
enabled   = true
out_iface = "eth0"   # optional; auto-detected when unset
```

The `[[peers]]` array lives in the main config file. Send SIGHUP to reload it
live: the daemon re-reads the same TOML file and swaps in the new peer set
without restarting. A present but empty list (`peers = []`) rejects everyone;
omitting the `[[peers]]` section entirely runs the server in **open mode**
(accepts any peer) for phase-1 compatibility. The optional `name` field is
purely for log readability — handshake rejections/acceptances reference it,
falling back to `"unknown"` when the key is not in the list.

### Client config (`client.toml`)

```toml
server     = "198.51.100.7:46722"
server_key = "<64-hex-char server public key>"
key_path   = "/var/lib/rustnies/client.key"  # required — no default; use `keygen` to create it
ipc_path   = "/run/rustnies/rustnies.sock"   # default; the daemon creates the dir if missing
route_all  = true              # default; set false to keep the default route
route_path = "/etc/rustnies/routes.txt"  # optional: file of extra IPs/CIDRs to route via TUN
dns_leak_protection = true     # default; block DNS leaks + rewrite resolv.conf when route_all is on
dns        = ["1.1.1.1"]       # resolvers for /etc/resolv.conf via the tunnel (default 1.1.1.1); [] = block only
kill_switch = false           # opt-in; forces route_all on; fail closed across reconnects
log_level  = "info"
log_file   = "/var/log/rustnies/client.log"  # optional: also write logs to this file

[tun]
name   = "rustnies0"
addr   = "10.7.0.2"
prefix = 24
addr6  = "fd00::2"  # optional: IPv6 address for dual-stack (prefix6 defaults to 64)
prefix6 = 64
mtu    = 1400
```

`server_key` is required (via config or `--server-key`); the client refuses
to start without it.

### Generating an example config

The file configs are plain TOML; the tables above are valid as starting
points. Only the fields you want to override from the built-in defaults need
be present — everything else falls back to the defaults shown in the flag
tables above.
