# Platform layer and TUN abstraction

The core tunnel logic never touches a TUN device directly. It talks to a
platform-independent `Tun` trait, and a platform host provides the
implementation. This keeps the core free of desktop-only assumptions and lets
the same core be linked into Android and iOS apps later.

## The `Tun` trait

`src/tun/mod.rs`:

```rust
pub trait Tun: Send + 'static {
    fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> TunFut<'a>;
    fn send<'a>(&'a mut self, buf: &'a [u8]) -> TunFut<'a>;
    fn name(&self) -> io::Result<String>;
    fn mtu(&self) -> io::Result<u32>;
}
```

`recv` / `send` operate on **whole packets** (datagram semantics), not byte
streams. `TunFut` is a boxed, sendable future (`Pin<Box<dyn Future<Output =
io::Result<usize>> + Send + 'a>>`), so the trait is object-safe and usable from
async tasks.

The two halves are intentionally not split into separate read/write traits:
a TUN interface is a single file descriptor that both reads and writes, and
modeling it as one object matches reality while still being mockable (the
integration test in `tests/end_to_end.rs` provides an in-memory `MemTun`).

## The `TunFactory` trait

```rust
pub trait TunFactory: Send + Sync + 'static {
    fn build(&self, name: &str, ipv4: &str, prefix: u8,
             ipv6: Option<(&str, u8)>, mtu: u32)
        -> io::Result<Box<dyn Tun>>;
    fn from_fd(&self, fd: std::os::fd::RawFd) -> io::Result<Box<dyn Tun>>;
}
```

Two construction modes:

- `build` -> create a named TUN device with a given address/prefix/MTU. This
  is the desktop path (`tun0`, `rustnies0`, ...). The `ipv6` parameter, when
  `Some(addr, prefix)`, configures an IPv6 address on the TUN for dual-stack
  operation (see [ipv6.md](ipv6.md)). When `None`, only IPv4 is configured and
  the interface is IPv4-only.
- `from_fd` -> wrap an **already-open** file descriptor handed to the core by
  the host. This is the mobile path: on Android (`VpnService`) and iOS
  (`NEPacketTunnelProvider`) the OS grants the FD; the app does not create a
  named device. The core takes over the FD.

The core receives a `Box<dyn Tun>` from the factory and never knows which path
was used.

## Linux platform layer

`src/platform/linux.rs` provides `LinuxTunFactory` and `LinuxTun`:

- `LinuxTun` wraps `tun_rs::AsyncDevice` (tokio). `recv`/`send` delegate to the
  async device's `recv`/`send` (which take `&self`, matching the tun_rs API).
- `build` uses `tun_rs::DeviceBuilder` to create and configure the interface
  (name, IPv4 address/prefix, MTU). When `ipv6` is `Some`, `.ipv6(addr, prefix)`
  is also called for dual-stack operation.
- `from_fd` uses `unsafe { AsyncDevice::from_fd(fd) }` (the fd must be a valid
  open TUN file descriptor; safety is the host's responsibility).

`platform/mod.rs` selects the Linux factory at build time
(`#[cfg(target_os = "linux")]`). Other targets currently panic with a message
directing the integrator to plug in their own factory via the `platform`
module, rather than silently failing.

## NAT orchestration (server)

`NatRules` in `src/platform/linux.rs` brings up source NAT so traffic leaving
the default interface for the tunnel's address range is masqueraded to the
host. It lives in the platform layer so the core never touches `iptables`.

`NatRules` supports both IPv4 (`iptables`) and IPv6 (`ip6tables`). When a
dual-stack TUN is configured (`tun_addr6` set), the server daemon computes the
IPv6 TUN CIDR and calls `with_v6_cidr()` so `ip6tables` MASQUERADE and FORWARD
rules are installed for the IPv6 subnet alongside the IPv4 ones. IPv6 NAT rules
are best-effort (skipped if `ip6tables` is absent). See [ipv6.md](ipv6.md).

### Construction

```rust
pub struct NatRules {
    tun_cidr: String,        // e.g. "10.7.0.0/24"
    out_iface: Option<String>,
    installed: Vec<String>,
}
```

`NatRules::new(tun_cidr, out_iface)` -> `out_iface` of `None` means
auto-detect the default route interface.

### `install()`

1. `sysctl -w net.ipv4.ip_forward=1` (enable forwarding).
2. `sysctl -w net.ipv6.conf.all.forwarding=1`, but only when the kernel has
   IPv6 support (`/proc/sys/net/ipv6` exists); on IPv6-less hosts the sysctl
   and all `ip6tables` calls are skipped entirely and the summary log reports
   "IPv4 only" instead of claiming "IPv4+IPv6".
3. Auto-detect the egress interface via `ip -o -4 route show default` if
   needed.
4. Install three iptables rules (idempotent: any pre-existing identical rule
   is deleted first):
   - `nat POSTROUTING -s <tun_cidr> -o <iface> -j MASQUERADE`
   - `filter FORWARD -i rustnies -j ACCEPT`
   - `filter FORWARD -o rustnies -j ACCEPT`
   (Client LAN-sharing mode with no source CIDR installs the MASQUERADE rule
   *without* `-s`, so any LAN behind the client is masqueraded as it enters
   the tunnel. Without this, LAN-sourced packets would reach the server with
   private source addresses outside its TUN-subnet MASQUERADE scope — replies
   could never return, and the server would mis-learn those LAN addresses as
   tunnel IPs.)
5. When an IPv6 TUN CIDR is configured (`with_v6_cidr`) *and* IPv6 is
   available:
   - `ip6tables` equivalents of the FORWARD accept rules (always installed).
   - `ip6tables nat POSTROUTING -s <tun_cidr6> -o <iface> -j MASQUERADE`
   (best-effort: skipped if `ip6tables` is absent; only successfully installed
   rules are recorded for teardown, and the summary log reflects what actually
   went in).
6. Record the installed rules so `remove()` can tear them down.

All subprocess calls capture (never inherit) child output, so best-effort
cleanup of absent rules/chains stays silent instead of printing raw
`iptables: Bad rule ...` / `RTNETLINK answers: ...` noise; failures carry the
child's stderr in the returned error for `tracing`.

### `remove()` and `Drop`

`remove()` deletes the recorded rules (best-effort). `Drop` calls `remove()`,
so dropping the `NatRules` (which happens when the server tunnel closes) cleans
up the firewall state automatically.

### Failure modes

`install()` requires root. If it fails (not root, no `iptables`, no default
route), the daemon logs a warning and continues without NAT, so the tunnel
still comes up for testing (traffic just won't reach the internet).

## Route-all (client)

`install_route_all(server, tun_name)` installs routes in four steps and
returns a `RouteGuard` that removes them on drop:

1. A host route to the VPN server's real IP via the original default gateway
   (so encrypted UDP to the server does not loop back through the tunnel).
2. Explicit exception routes for the client's directly-attached local
   subnet(s) (from `ip -o -4 addr show dev <orig_iface>`) via the original
   gateway, so LAN traffic stays off the tunnel. Without this, route-all pulls
   LAN traffic into the tunnel and the server observes (and used to "learn")
   private LAN source addresses it cannot NAT or route back. Exceptions are
   warn-and-continue: losing one degrades to the old behaviour for that subnet
   rather than failing route-all. The ordered plan (server route, exceptions,
   default) is computed by the pure `route_all_plan` helper, unit-tested
   without touching real interfaces.
3. A new default route via the TUN interface with a low metric (wins over the
   original default).
4. A policy-routing bypass so inbound connections to the box itself keep
   working: reply packets sourced from the box's own addresses (`from`
   -rules at priority 20000 into table 100, which routes via the original
   gateway). Without this, the tunnel default captures replies — they leave
   via the tunnel, get NATed to the server's egress IP, and the far end drops
   them, so SSH/HTTP and every other listening service on the WAN address
   goes dark. Only the box's own addresses get rules, so new outbound traffic
   (sourced from the tunnel address) still uses the tunnel. Entries are
   installed best-effort with a pre-delete for idempotency across
   crash-restarts; the plan is computed by the pure `bypass_plan` helper.

All are added with `ip route add` / `ip rule add`. The guard's `Drop` deletes
them (bypass entries first, then the tunnel default, LAN exceptions, and
server host routes), restoring the original routing; cleanup is silent
(child output captured). If a required step (server route, tunnel default)
fails, the already-installed main-table entries are rolled back instead of
leaking. Requires root.

## Route-file (client)

`install_route_file(tun_name, path)` reads a plain-text file of destinations
(one per line; `#` comments and blank lines ignored) and installs a route for
each through the TUN device. It is wired to the `route_path` config setting /
`--route-path` flag and is independent of route-all.

Each line is parsed by `parse_route_line` and accepts:

- a bare IP (`8.8.8.8`) -> host route (`/32` IPv4, `/128` IPv6)
- a CIDR (`10.0.0.0/8`)
- the legacy `ip netmask` form (`178.66.83.0 255.255.255.0`) -> converted to a
  prefix length via `netmask_to_prefix`

Routes are added **directly over netlink** (`rtnetlink` / `netlink-packet-route`)
rather than by spawning an `ip` process per entry. This is the whole point of
the feature: a config with tens of thousands of route entries (the brownies
`routes.txt` case) cannot be installed by spawning `ip` 80k times, but netlink
handles it in well under a second. Each add uses `NLM_F_REPLACE | NLM_F_CREATE`
so re-adding an existing route is a no-op rather than an error (matching the
`suppress_route_errors` semantics of legacy configs); a route the kernel refuses
is logged and skipped, never fatal.

`RouteFileGuard`'s `Drop` removes every installed route synchronously over a raw
`netlink_sys::Socket` (so cleanup works during shutdown, outside a tokio
context).

## DNS leak prevention (client)

Even with route-all on, DNS queries can leak out the real interface: the
system resolver is often on the local LAN, and the kernel's connected route
for the local subnet is more specific than the default route via the TUN, so
queries to `192.168.1.1` bypass the tunnel entirely. DNS leak prevention closes
that gap whenever route-all is active (`dns_leak_protection = true`, the
default). It has two halves:

1. **Firewall block** (`DnsLeakGuard`): a dedicated iptables chain
   `RUSTNIES_DNS` jumped from `OUTPUT` that accepts DNS (port 53 UDP/TCP) out
   the TUN and rejects DNS out any other interface. DNS can only leave via the
   tunnel.
2. **Resolver swap** (`ResolvConfGuard`): rewrites `/etc/resolv.conf` to point
   at resolver IPs reachable through the tunnel (`dns`, default `1.1.1.1`), so
   name resolution actually works through the tunnel instead of the system's
   normal resolver. The original is backed up to
   `/etc/resolv.conf.rustnies.bak` and restored on shutdown. A stale backup
   from a crashed run is preserved (never overwritten), so the real original is
   never lost; the next install just rewrites `resolv.conf`.

Setting `dns = []` (an explicit empty list) skips the `resolv.conf` swap and
installs only the firewall block — for users who manage DNS themselves.

Packaging note: the client systemd unit allows writes to these paths via
`ReadWritePaths=/etc/resolv.conf -/etc/resolv.conf.rustnies.bak`. The `-`
prefix on the backup is required — the sidecar only exists while the swap is
active, and systemd fails namespace setup (`226/NAMESPACE`) if a listed path
is missing. Never pre-create the backup to satisfy the sandbox: an existing
backup is treated as a stale original from a crashed run and preserved.

### Verifying it: `rustnies dns-check`

`rustnies dns-check` is a standalone command (needs root to read iptables)
that verifies DNS only reaches a resolver via the tunnel. It:

- prints the active `/etc/resolv.conf` nameserver,
- snapshots the `RUSTNIES_DNS` chain's live counters (DNS accepted via the
  TUN vs. DNS rejected on the real interface), falling back to the
  `RUSTNIES_KS` chain if only the kill switch is active,
- performs a real resolution via the system resolver (which now points at the
  tunnel DNS),
- snapshots the counters again and reports the deltas — a clean run shows
  `via tunnel +N pkts, blocked +0 pkts` and the verdict "no DNS leak detected".

The counter parsing (`parse_iptables_chain`) is unit-tested with sample
`iptables -L` output so it does not depend on a live firewall.

## Kill switch (client)

The opt-in kill switch (`--kill-switch` / `kill_switch = true`, off by default)
blocks *all* outbound traffic except via the TUN, to the VPN server (the
encrypted tunnel UDP), and on loopback, so if the tunnel drops unexpectedly the
client cannot silently fall back to the real internet. It is the hard firewall
guarantee that complements route-all's routing change.

`KillSwitch` installs a dedicated chain `RUSTNIES_KS` jumped from `OUTPUT`:

1. `ACCEPT` loopback (`-o lo`),
2. `ACCEPT` the TUN (`-o <tun>`),
3. `ACCEPT` the encrypted tunnel UDP to the server
   (`-d <server_ip> -p udp --dport <server_port>`), so the tunnel can be
   (re)established,
4. `REJECT` everything else (the catch-all — fail closed).

### Fail-closed lifetime

The kill switch rules are held for the daemon's lifetime, *across reconnects*:
when a tunnel session drops, the daemon keeps trying to re-establish it, and
the kill switch stays engaged the whole time — direct internet remains blocked
until the user stops the daemon. Only a graceful shutdown (Ctrl+C or the IPC
`Stop` command) drops the guard, which removes the chain and restores direct
connectivity. A failed install is fatal: the user asked for protection, so the
daemon refuses to start unprotected rather than running with a false sense of
security.

Because the kill switch is only meaningful when all traffic is routed through
the tunnel, enabling it forces `route_all` on.

### Swappable backend + testability

Both `DnsLeakGuard` and `KillSwitch` build their rules as pure `FirewallOp`
data and apply them through a `FirewallBackend` trait. Production uses
`IptablesBackend` (shells out to `iptables`); tests inject a `RecordedBackend`
that records the operations and feeds them to `evaluate_packet`, an in-process
iptables-traversal simulator. This lets the test suite prove the rules block
what they should — and keep blocking after a tunnel drop (fail closed) —
without root or a real `iptables`. The chains are installed with a best-effort
teardown first, so re-installing (e.g. after a crash/restart) is idempotent and
never leaves duplicate jumps.

## Mobile readiness

The groundwork for Android/iOS is in place from day one:

- All core modules (`protocol`, `crypto`, `fec`, `transport`, `congestion`,
  `tunnel`) compile and unit-test independently of Linux.
- The `Tun` / `TunFactory` traits accept an open FD, which is how mobile
  platforms provide the TUN interface.
- No desktop-only assumptions (no direct `tun_rs` calls, no `iptables`, no
  device-name creation) leak into the core.
- A future `platform/android.rs` and `platform/ios.rs` would implement
  `TunFactory` (wrapping the OS-granted FD) and the core would work unchanged.

## Permissions

Running the daemon (`client` or `server`) requires root on Linux because:

- Creating a TUN device (`/dev/net/tun`) needs `CAP_NET_ADMIN`.
- Setting an interface address/MTU needs `CAP_NET_ADMIN`.
- `iptables`/`sysctl` NAT setup needs root.

The `keygen`, `status`, `stop`, and `ping` subcommands do **not** need root
(keygen only writes a key file the caller owns; the IPC subcommands just open a
Unix socket).
