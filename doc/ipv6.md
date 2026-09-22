# IPv6 Completeness Audit & Implementation Notes

This document records the IPv6 audit performed during the session-lifecycle
implementation step, identifying gaps in the original codebase and the fixes
applied.

## Status summary

| Area | Before | After |
|------|--------|-------|
| TUN device | IPv4 only (`.ipv4()` in `tun_rs`) | Dual-stack: configurable `.ipv4()` + optional `.ipv6()` |
| Route-all (client) | IPv4 host route + default route only | Both IPv4 and IPv6 (when server + default GW are IPv6) |
| Kill switch | `iptables` only (IPv4) | `iptables` + `ip6tables` (dual-stack, fail-closed on both) |
| DNS leak prevention | `iptables` only (IPv4) | `iptables` + `ip6tables` (dual-stack) |
| NAT (server) | `iptables` IPv4 only | IPv4 + IPv6 (`ip6tables`, best-effort) |
| Route file | Already IPv4+IPv6 (netlink) | Unchanged (already correct) |
| ResolvConfGuard | IP-agnostic (writes `nameserver` lines) | Unchanged (already correct) |
| Config | `tun_addr: String` (IPv4) | Added `tun_addr6: Option<String>` + `tun_prefix6: Option<u8>` |
| TUN factory trait | `build(name, ipv4, prefix, mtu)` | `build(name, ipv4, prefix, ipv6: Option<(&str,u8)>, mtu)` |

## Gaps found and fixes

### 1. TUN device — IPv4-only construction

**Before:** `LinuxTunFactory::build` only called `tun_rs::DeviceBuilder::new().ipv4(...)`.
The `TunFactory` trait signature did not accept an IPv6 address.

**Fix:** Extended `TunFactory::build` to accept `ipv6: Option<(&str, u8)>`.
`LinuxTunFactory::build` calls `.ipv6(addr, prefix)` when the IPv6 parameter
is `Some`. `ClientConfig`/`ServerConfig` gained `tun_addr6`/`tun_prefix6`
fields (default `None` — IPv4-only behaviour unchanged).

### 2. Route-all — IPv4-only host + default routes

**Before:** `install_route_all` (in `src/platform/linux.rs`) installed:
- `ip route add <server_ip> via <orig_gw>` (IPv4 host route)
- `ip route add default dev <tun> metric 1` (IPv4 default route)

No IPv6 equivalent was installed. A client with an IPv6-capable ISP would leak
IPv6 traffic outside the tunnel when `route_all` was active.

**Fix:** Added `install_route_all_v6()` which, when the server address is IPv6
and an IPv6 default gateway exists, installs:
- `ip -6 route add <server_ip6> via <gw6>` (IPv6 host route)
- `ip -6 route add default dev <tun> metric 1` (IPv6 default route)

`RouteGuard` now tracks both IPv4 and IPv6 server addresses / gateways and
removes both families' routes on drop.

### 3. `default_gateway` / `default_route_iface` — hardcoded `-4`

**Before:** `default_gateway()` and `default_route_iface()` both ran
`ip -o -4 route show default` (IPv4 only).

**Fix:** Added `default_gateway_v6()` / `parse_default_gateway_v6()` for the
IPv6 equivalent. `install_route_all_v6` uses it to find the IPv6 default
gateway. If no IPv6 default route exists (common on IPv4-only hosts), the
function returns `None` and IPv6 routes are skipped gracefully.

### 4. Kill switch — IPv4-only `iptables`

**Before:** `ks_rules()` generated rules using `iptables`-style `FirewallRuleSpec`
entries with no family distinction. The `IptablesBackend` only called `iptables`.

**Fix:**
- Added `FirewallFamily { Ipv4, Ipv6 }` enum to `FirewallRuleSpec`.
- `IptablesBackend::exec` now dispatches `Append`/`Delete` ops to `iptables`
  or `ip6tables` based on `rule.family`. Chain-level ops (`CreateChain`,
  `FlushChain`, `DeleteChain`, `Jump`, `Unjump`) are applied to **both**
  binaries so chains exist in both families.
- `ks_rules()` now generates rules for **both** families: the common rules
  (allow lo, allow TUN, REJECT catch-all) go in both; the server-allow rule
  is family-specific (only for the family matching the server's address, since
  `iptables` rejects IPv6 `-d` values and vice versa).

### 5. DNS leak prevention — IPv4-only `iptables`

**Before:** `dns_rules()` generated four IPv4-only rules (UDP+TCP DNS via TUN
allowed, via real interface rejected).

**Fix:** `dns_rules()` now iterates both `FirewallFamily::Ipv4` and
`FirewallFamily::Ipv6`, producing eight rules total. The `evaluate_packet`
test harness was extended with a family check: it parses the `dst` address and
only evaluates rules matching that address's family, preventing the IPv4
catch-all REJECT from incorrectly blocking IPv6 traffic (and vice versa).

### 6. NAT — IPv4-only iptables rules

**Before:** `NatRules::install()` only called `iptables` with IPv4 rules:
- `sysctl net.ipv4.ip_forward=1`
- `iptables -t nat -A POSTROUTING ...` (MASQUERADE)
- `iptables -A FORWARD -i/-o <tun> -j ACCEPT`

**Fix:**
- Added `sysctl net.ipv6.conf.all.forwarding=1` (best-effort).
- Added `ip6tables` equivalents for the FORWARD accept rules (always
  installed if `ip6tables` is available).
- Added ip6tables MASQUERADE when an IPv6 TUN CIDR is configured.
- `NatRules` gained a `source_cidr_v6` field; `NatRules::new()` classifies the
  CIDR as IPv4 or IPv6 via `ipnet::IpNet`. Added `with_v6_cidr()` builder
  method for dual-stack TUNs.
- `NatRules::remove()` now tries both `iptables` and `ip6tables` for teardown.
- The server daemon (`src/daemon/mod.rs`) computes the IPv6 TUN CIDR and calls
  `with_v6_cidr()` when `tun_addr6` is configured.

### 7. `evaluate_packet` — family-agnostic test harness

**Before:** The `evaluate_packet` function reconstructed chain state from all
`FirewallOp`s and matched against any family. With both IPv4 and IPv6 rules
installed, the IPv4 catch-all REJECT would match IPv6 test packets (and vice
versa), causing test failures.

**Fix:** Added a family filter at the top of `rule_matches()`: it parses the
test packet's `dst` as an `IpAddr` and skips rules whose `family` doesn't
match. Rules with `dst: None` (like catch-all REJECT) are still family-scoped,
so IPv6 traffic only hits IPv6 REJECT rules — exactly what we want for
dual-stack fail-closed behavior.

## What was already correct

- **Route file parsing** (`parse_route_line`): Already handled IPv6 via
  `ipnet::IpNet` parsing and bare `IpAddr::V6` with `/128` prefix. The
  `add_route` function already checked `AddressFamily::Inet6` and pushed
  `RouteAddress::Inet6(v6)`. No changes needed.
- **ResolvConfGuard**: Writes `nameserver <addr>` lines, which work for both
  IPv4 and IPv6 resolvers. No changes needed.
- **Protocol layer**: The 24-byte wire header has no IP-version dependency;
  the Noise IK handshake and AEAD keys are IP-agnostic. No changes needed.
- **Tunnel data path**: Reads/writes whole datagrams to/from the TUN device;
  `tun_rs` handles both IPv4 and IPv6 frames transparently. No changes needed.

## Tests added

- `kill_switch_blocks_ipv6_traffic` — verifies IPv6 non-TUN/non-lo traffic is
  REJECTed when the kill switch is active (server is IPv4).
- `kill_switch_ipv6_server_allows_v6_server_traffic` — verifies the server-allow
  rule is family-correct when the server address is IPv6.
- `dns_leak_rules_block_ipv6_dns` — verifies IPv6 DNS is allowed via TUN and
  blocked via real interface.
- `ks_rules_generates_both_ipv4_and_ipv6_families` — structural test that
  `ks_rules` produces rules for both families.
- `ks_rules_ipv6_server_generates_v6_server_rule` — verifies the server-allow
  rule is only in the matching family.
- `parse_default_gateway_v6_with_via` / `parse_default_gateway_v6_onlink` —
  unit tests for the IPv6 gateway parser.
- `cidr_base_v6_extracts_network_prefix` / `cidr_base_v6_short_prefix_keeps_full_address`
  / `cidr_base_v6_full_address_no_compression` — unit tests for IPv6 CIDR.
