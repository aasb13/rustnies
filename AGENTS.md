# AGENTS.md

A brief orientation for agents (and humans) landing in this repository.

## What this is

README.md is in the root of the repo, not doc/.

`rustnies` is a custom VPN written in Rust. Phase 1 (the current state of this
repo) is a working, reliable encrypted UDP tunnel with adaptive forward error
correction and basic congestion control. It also ships an optional, stackable
traffic-obfuscation layer (padding, timing, header whitening) that is off by
default and opt-in via the `[obfuscation]` config section; see
`doc/obfuscation.md`. Full protocol mimicry (e.g. TLS/JA3 impersonation) is
still future work.

## Non-goals for phase 1

- No full protocol mimicry (e.g. TLS/JA3 impersonation). Basic obfuscation
  transforms — padding, timing, header whitening — ARE implemented in
  `src/obfuscation/` (off by default, opt-in via `[obfuscation]`); the
  `ObfuscationLayer` trait is the seam for heavier mimicry.
- No BBR-style congestion control (a simple TCP-inspired controller is in
  `src/congestion/`).
- No key rotation mid-session.

If a task seems to require any of the above, confirm scope before extending.

## Repository layout

```
src/
  lib.rs              crate root, re-exports public API
  main.rs             binary entrypoint -> cli::run()
  cli.rs             clap CLI: server / client / status / stop / ping / revoke / list-sessions / disconnect / dns-check / keygen / pubkey
  config.rs           ServerConfig / ClientConfig + TOML file configs & merge
  stats.rs            Counters + Stats snapshot (sent over IPC)
  daemon/mod.rs       persistent daemon: owns tunnel task + IPC server
  ipc/                Unix-socket IPC (newline-delimited JSON)
  tunnel/             steady-state tunnel + Noise IK handshake + peer auth + keepalives
  protocol/           wire format: 24-byte header, codec, session/replay/acks
  crypto/             Noise IK handshake, ChaCha20-Poly1305 AEAD, X25519 keys
  transport/          swappable wrap/unwrap trait (PlainTransport / TaggedTransport)
  obfuscation/        stackable, composable obfuscation transforms (padding / timing /
                      header_xor) applied on top of Transport, off by default
  fec/                Reed-Solomon over GF(256) + adaptive controller
  congestion/         SRTT/RTTVAR + slow start + multiplicative decrease
  tun/                platform-independent Tun / TunFactory traits
  platform/linux.rs   Linux TUN (tun_rs) + iptables NAT + route-all + route-file (netlink)
                      + DNS leak prevention (DnsLeakGuard / ResolvConfGuard) + kill switch
                      (KillSwitch), all behind a swappable FirewallBackend for testability
tests/
  end_to_end.rs       loopback handshake + key-matching + kill-switch fail-closed drop tests
doc/                  full design docs (start at doc/architecture.md)
.github/workflows/    GitHub Actions: ci.yml (fmt/build/test + advisory clippy),
                      release.yml (tag-driven release artifact published to GitHub Releases)
rust-toolchain.toml   pins the Rust toolchain (stable + rustfmt + clippy) for CI and local dev
```

## Key architectural rules (do not break these)

- **The core is platform-independent.** `protocol`, `crypto`, `fec`,
  `congestion`, `transport`, `tun`, and `tunnel` must not import
  platform-specific code. All Linux specifics (tun_rs, iptables, FD handling
  for a named device) live in `src/platform/linux.rs` behind the `Tun` /
  `TunFactory` traits. The core must stay linkable into Android/iOS without
  rewriting.
- **The core never opens a TUN device directly.** It receives a `Box<dyn Tun>`
  from a `TunFactory`, including an already-open FD path (`from_fd`) for mobile
  hosts that get the FD from the OS.
- **The `Transport` trait is the envelope seam; `ObfuscationLayer` is the
  stackable transform seam.** Raw packets go through `Transport::wrap`/`unwrap`
  (the envelope). On top of that, an optional `ObfuscationStack`
  (`src/obfuscation/`) applies ordered, composable transforms (padding, timing,
  header whitening) before `Transport::wrap` on send and reverses them after
  `Transport::unwrap` on receive. New obfuscation strategies implement
  `ObfuscationLayer` and slot into the stack from config without touching
  protocol/crypto/FEC/TUN. The stack is **off by default** and enabled only via
  the `[obfuscation]` TOML section. See `doc/obfuscation.md`.
- **No invented cryptography.** Use Noise IK (already implemented), X25519,
  HKDF-SHA256, ChaCha20-Poly1305. Do not roll custom crypto.
- **Data is best-effort; only control/handshake messages are reliable.**
  Reliability for data is the FEC layer's job, not a retransmission loop.
- **Daemon owns state; CLI is a thin IPC client.** Never relaunch the VPN to
  query or control it. Stats and `stop` go over the Unix socket in
  `src/ipc/`.

## Build / test / run

```sh
cargo build                      # debug build
cargo build --release            # release build
cargo test                       # all tests (418 passing)
cargo test --lib                 # unit tests only
cargo test --test end_to_end     # integration tests only

# Daemon subcommands (need root on Linux for TUN + NAT):
sudo ./target/release/rustnies keygen --key /var/lib/rustnies/server.key
sudo ./target/release/rustnies server --key /var/lib/rustnies/server.key
sudo ./target/release/rustnies client --server <ip>:46722 \
    --server-key <pubkey_hex> --key /var/lib/rustnies/client.key

# With the kill switch (blocks all non-tunnel traffic; fail closed on drop):
sudo ./target/release/rustnies client --server <ip>:46722 \
    --server-key <pubkey_hex> --key /var/lib/rustnies/client.key --kill-switch

# Or via TOML config files (defaults: /etc/rustnies/{server,client}.toml;
# override with --config <path>). CLI flags still override config values.
# `key_path` is required — there is no default; use `keygen` first:
sudo ./target/release/rustnies server --config /etc/rustnies/server.toml
sudo ./target/release/rustnies client --config /etc/rustnies/client.toml

# Unprivileged IPC clients (talk to a running daemon):
./target/release/rustnies status
./target/release/rustnies stop
./target/release/rustnies ping

# Verify DNS leak prevention (needs root to read iptables; run while the
# client daemon is up):
sudo ./target/release/rustnies dns-check
```

Logging goes through `tracing` and respects `RUST_LOG` (default `info`),
then `log_level` from config/`--log-level`, then `--verbose` (forces `debug`).

## CI / CD

CI and releases run on GitHub Actions via the workflows in
`.github/workflows/`:

- `ci.yml` — on push to `master` and on PRs. Hard gates: `cargo fmt --all
  -- --check`, `cargo build --all-targets --locked` with
  `RUSTFLAGS="-D warnings"`, and `cargo test --locked --all`. `cargo clippy
  --all-targets -- -D warnings` is advisory (`continue-on-error`) until the
  existing lint debt is paid down.
- `release.yml` — on a pushed `v*` tag. Builds the release binary, strips it,
  and uploads `rustnies-<tag>-x86_64-unknown-linux-gnu.tar.gz` + `.sha256` to
  the GitHub Release via `softprops/action-gh-release`. Uses the auto
  `GITHUB_TOKEN` (`contents: write`); no extra secrets needed.

Locally mirror the CI gates before pushing:

```sh
cargo fmt --all -- --check
RUSTFLAGS="-D warnings" cargo build --all-targets --locked
cargo test --locked --all
```

## Crate / dependency choices

- `tokio` (async runtime, full features), `tokio-stream`
- `tun-rs` (Linux TUN, `async_tokio` feature) — platform layer only
- `chacha20poly1305`, `x25519-dalek`, `hkdf`, `sha2`, `rand`, `zeroize` — crypto
- `bytes` (frame buffers), `serde` + `serde_json` (IPC + config), `toml` (config files)
- `clap` (CLI), `tracing` + `tracing-subscriber` (logging)
- `rtnetlink` + `netlink-packet-route` + `netlink-sys` (netlink route
  installation for the client route-file feature; platform layer only),
  `ipnet` (CIDR parsing), `futures` (streams)
- `bitflags`, `thiserror`, `hex`

Edition is `2024`. The crate is both a library (`src/lib.rs`) and a binary
(`src/main.rs`) so the core can be linked into mobile apps.

## Before you start working

1. Read `doc/architecture.md` for the big picture.
2. Read the doc for the subsystem you are touching (e.g. `doc/fec.md`).
3. Re-read the relevant source before editing; match existing style
   (module-level `//!` docs, `thiserror` error enums, hand-rolled wire
   serialisation in `protocol/`).
4. Keep the build warning-free (`cargo build` should emit no warnings); CI
   enforces this with `RUSTFLAGS="-D warnings"`.
5. Keep code `rustfmt`-clean (`cargo fmt --all`); CI enforces
   `cargo fmt --all -- --check`.
6. Add or update tests for behavioural changes; run `cargo test` before
   finishing.
7. Update the relevant `doc/` file if a design decision or wire format changes.

## Committing changes

Always commit your changes at the end of a task. After finishing the work and
verifying the build and tests pass, stage the relevant files and create a
commit with a concise, descriptive message that matches the repo style. Do not
amend, force-push, or commit unrelated changes.

## Common gotchas

- `x25519-dalek`'s `EphemeralSecret::diffie_hellman` consumes `self`, so it
  can only do one DH. The Noise IK handshake needs two DHs from one ephemeral,
  so `src/crypto/noise.rs` uses `StaticSecret` for the ephemeral (freshly
  generated per handshake, zeroised on drop) and calls `diffie_hellman(&self)`.
  Do not "fix" this by switching back to `EphemeralSecret`.
- The Reed-Solomon generator must be built as `G = V * V_top^{-1}` (systematic).
  Do not try to row-reduce the Vandermonde parity rows against the identity
  block; that zeroes them.
- The AEAD nonce is `session_id || seq || direction || 0x00 0x00 0x00`. The
  `direction` bit is required so the two directions can reuse seq numbers
  without a (key, nonce) collision.
- `tun_rs`'s tokio `AsyncDevice::recv`/`send` take `&self`, not `&mut self`.
  `from_fd` is `unsafe`.
- The server logs its static public key on startup; the client needs that exact
  hex string via `--server-key`.
- The kill switch and DNS leak prevention install iptables into dedicated
  chains (`RUSTNIES_KS`, `RUSTNIES_DNS`) jumped from `OUTPUT`. DNS leak is
  installed before the kill switch so its chain is jumped first (its per-rule
  counters stay meaningful for `dns-check`). Both build their rules as pure
  `FirewallOp` data and apply them through a `FirewallBackend` — production
  uses `IptablesBackend`, tests use `RecordedBackend` + `evaluate_packet`. Do
  not add iptables rules directly; add a `FirewallRuleSpec` and let the guard
  own the chain lifecycle (install is idempotent via a best-effort teardown;
  a failed kill-switch install is fatal so the client never runs unprotected).
- The kill switch fails closed: its guard is held for the daemon's lifetime
  (across reconnects) and only dropped on graceful shutdown. Do not move it
  inside the reconnection loop or it will be torn down on every drop.
- `ResolvConfGuard` swaps `/etc/resolv.conf` and restores it on drop. A stale
  `.rustnies.bak` from a crashed run is preserved (never overwritten) so the
  real original is never lost.
