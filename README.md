# rustnies

![CI](https://github.com/aasb13/rustnies/actions/workflows/ci.yml/badge.svg)
![Release](https://github.com/aasb13/rustnies/actions/workflows/release.yml/badge.svg)

A custom VPN written in Rust. Phase 1 is a working, reliable encrypted UDP
tunnel with adaptive forward error correction and basic congestion control.
It also ships an optional, stackable traffic-obfuscation layer (padding,
timing, header whitening) that is off by default and opt-in via the
`[obfuscation]` config section (see [doc/obfuscation.md](doc/obfuscation.md)); the
`Transport` trait remains the seam for future full protocol mimicry (e.g.
TLS/JA3 impersonation).

The `doc/` directory documents the design and operation of rustnies. Start with
[doc/architecture.md](doc/architecture.md) for the big picture, then drill into the
per-subsystem documents.

## Documents

| Document | Topic |
|----------|-------|
| [doc/architecture.md](doc/architecture.md) | End-to-end architecture, data flow, module map, key decisions |
| [doc/protocol.md](doc/protocol.md) | Wire format, packet header, packet types, sequencing, acks, replay protection |
| [doc/crypto.md](doc/crypto.md) | Noise IK handshake, AEAD, nonce construction, key management |
| [doc/fec.md](doc/fec.md) | Reed-Solomon over GF(256), adaptive controller, group lifecycle |
| [doc/congestion.md](doc/congestion.md) | RTT estimation, congestion window, loss response |
| [doc/transport.md](doc/transport.md) | The swappable wrap/unwrap envelope abstraction |
| [doc/obfuscation.md](doc/obfuscation.md) | Stackable, composable obfuscation transforms (off by default) |
| [doc/platform.md](doc/platform.md) | TUN abstraction, Linux platform layer, NAT, mobile readiness |
| [doc/daemon.md](doc/daemon.md) | Daemon process, IPC protocol, runtime control (revoke/list-sessions/disconnect), stats, CLI |
| [doc/cli.md](doc/cli.md) | Command-line usage and all 11 subcommands |
| [doc/testing.md](doc/testing.md) | Test suite layout and what is covered |
| [doc/ipv6.md](doc/ipv6.md) | IPv6 dual-stack audit and implementation notes |
| [doc/session-lifecycle.md](doc/session-lifecycle.md) | Session and peer lifecycle spec (multi-client dispatch, roaming, eviction, revocation) |

## Quick start

```sh
# Build
cargo build --release

# Generate a server static keypair (prints the 32-byte hex public key)
sudo ./target/release/rustnies keygen --key /var/lib/rustnies/server.key
# -> <server_pubkey_hex>

# Start the server (foreground; needs root for TUN + NAT)
sudo ./target/release/rustnies server --key /var/lib/rustnies/server.key

# On the client: generate a client key, then connect
sudo ./target/release/rustnies keygen --key /var/lib/rustnies/client.key
sudo ./target/release/rustnies client \
    --server <server_ip>:46722 \
    --server-key <server_pubkey_hex> \
    --key /var/lib/rustnies/client.key

# Query the running client daemon for live stats
./target/release/rustnies status

# Tell the running daemon to tear down the tunnel
./target/release/rustnies stop
```

The `client` and `server` subcommands run the daemon in the foreground. They
create a Unix-domain IPC socket (default `/run/rustnies/rustnies.sock`)
that the `status` / `stop` / `ping` subcommands talk to, so you never relaunch
the whole VPN to query or control it. The default is a fixed path (not
`$TMPDIR`) so the daemon and the CLI always agree on it regardless of how
either was invoked (sudo, systemd, etc.); pass `--socket <path>` to override.

## Installation

Two installers live under `scripts/`. Both build the release binary first
(`cargo build --release`); pass `--skip-build` to use an existing build.

**Full install** — binary, config / state / runtime directories, static
keypairs, and systemd services:

```sh
# Server box (skips the client service and client key):
sudo ./scripts/install.sh --server-only

# Client box:
sudo ./scripts/install.sh --client-only

# Both on one host (single-host loopback testing / relay only — a host
# normally runs either the server or the client, never both):
sudo ./scripts/install.sh --both

# Enable (and with --start, also start) the services now:
sudo ./scripts/install.sh --server-only --enable
sudo ./scripts/install.sh --server-only --start

# Custom install prefix (binary -> <prefix>/bin/rustnies; units rendered to
# match):
sudo ./scripts/install.sh --server-only --prefix /opt/rustnies
```

What it creates:

| Path | Contents |
|------|----------|
| `<prefix>/bin/rustnies` | The daemon / CLI binary. |
| `/etc/rustnies/server.toml`, `client.toml` | Live config (written only if absent; edits are never clobbered). Stock copies are refreshed to `*.toml.dist`. |
| `/var/lib/rustnies/{server,client}.key` | Static X25519 keypairs (mode 0600), created by `keygen`. |
| `/run/rustnies/rustnies.sock` | IPC socket (config sets `ipc_path` here). |
| `/etc/systemd/system/rustnies-{server,client}.service` | systemd units (graceful SIGINT shutdown, capability-bounded, filesystem-sandboxed). |

The client config ships with a placeholder `server_key`; edit
`/etc/rustnies/client.toml` to set `server` and `server_key` (the value the
server prints / writes to `server.key.pub`) before starting the client.
Because the daemon runs as root under systemd, control commands need root to
reach the `/run/rustnies` socket. The default `--socket` path already points
there, so the bare commands work; `--socket` only needs to be passed when
targeting a non-default location:

```sh
sudo rustnies status                         # default: /run/rustnies/rustnies.sock
sudo rustnies stop
```

**Binary-only install** — just the binary, no systemd / config / keys:

```sh
./scripts/install-bin.sh                      # -> /usr/local/bin (auto-sudos)
./scripts/install-bin.sh --prefix ~/.local    # user-local, no root needed
```

**Uninstall**:

```sh
sudo ./scripts/uninstall.sh            # removes units + binary, keeps config/keys
sudo ./scripts/uninstall.sh --purge    # also deletes /etc/rustnies and keys
```

Run `./scripts/install.sh --help` (or `install-bin.sh` / `uninstall.sh`) for
the full flag list.

## Continuous integration and releases

CI and releases run on GitHub Actions (workflows live in
[`.github/workflows/`](.github/workflows/)). The pinned toolchain is in
[`rust-toolchain.toml`](rust-toolchain.toml) (stable, with `rustfmt` and
`clippy`).

**CI** (`.github/workflows/ci.yml`) runs on every push to `master` and on
pull requests:

- `cargo fmt --all -- --check` — formatting is enforced (hard gate).
- `cargo build --all-targets --locked` with `RUSTFLAGS="-D warnings"` — the
  build must be warning-free (hard gate, per the project rule).
- `cargo test --locked --all` — the full unit + integration suite.
- `cargo clippy --all-targets -- -D warnings` — advisory only
  (`continue-on-error`); reports lint debt without blocking. Tighten to a
  hard gate once the existing lints (mostly in the Reed-Solomon GF(256) math
  and the platform layer) are cleaned up.

**Releases** (`.github/workflows/release.yml`) trigger on a pushed `v*` tag.
It runs the tests, builds the release binary (`cargo build --release`, with
`lto = "thin"` from `Cargo.toml`), strips it, and publishes a
`rustnies-<tag>-x86_64-unknown-linux-gnu.tar.gz` + `.sha256` checksum to the
GitHub Release for that tag.

```sh
# Cut a release:
git tag v0.1.0
git push origin v0.1.0      # triggers the Release workflow
```

The release step uses the auto-provided `GITHUB_TOKEN` (`contents: write`);
no extra secrets are needed.

## What phase 1 delivers

- Client and server in one binary, selected by a mode flag.
- Custom protocol over **UDP** (not TCP, not QUIC).
- Compact 24-byte packet header with session id, sequencing, piggybacked acks,
  and FEC group/index metadata.
- Encryption with **ChaCha20-Poly1305** and a **Noise IK** handshake
  (X25519 + HKDF-SHA256). No invented cryptography.
- Reliable delivery for control/handshake messages; tunneled data is
  best-effort.
- **Adaptive forward error correction**: redundancy rises with measured loss
  and falls as the link improves, with hysteresis to avoid flapping.
- **Congestion/rate control** driven by live RTT and loss, with pacer-based
  rate limiting (`cwnd / srtt`) to avoid burst flooding a lossy link.
- **Multi-client server dispatch**: a single server process serves many
  concurrent clients via SessionId-routed dispatch with per-static-key session
  caps and oldest-idle eviction (`src/tunnel/server.rs`).
- **Daemon architecture** with lightweight CLI over local IPC for live stats
  and runtime control (status, stop, ping, revoke, list-sessions, disconnect).
- **IPv6 dual-stack support** across TUN, route-all, kill switch, DNS leak
  prevention, and NAT (`ip6tables` when applicable; IPv6 TUN address and prefix
  via `tun_addr6` / `tun_prefix6`).
- **Client-side NAT**: optional iptables MASQUERADE lets a LAN behind the
  client share the tunnel (disable with `--no-nat`).
- **Cross-platform groundwork**: the core tunnel/protocol/crypto/FEC/congestion
  logic is a platform-independent library; Linux-specific TUN and NAT live
  behind traits so the core can be linked into Android/iOS without rewriting.
- **Swappable Transport abstraction** for the raw packet wrap/unwrap envelope,
  plus an optional, stackable **obfuscation layer** (padding, timing, header
  whitening) applied on top of it and opt-in via `[obfuscation]` (off by
  default). The `Transport` / `ObfuscationLayer` seams keep both envelope
  shape and future full protocol mimicry (e.g. TLS/JA3) pluggable without
  touching protocol/crypto/FEC/congestion/TUN.
