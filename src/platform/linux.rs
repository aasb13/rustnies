//! Linux TUN device via [`tun_rs`] and server-side NAT orchestration.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use futures::StreamExt;
use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    route::{
        RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope,
        RouteType,
    },
};
use netlink_sys::{
    Socket as NetlinkSocket, SocketAddr as NetlinkSocketAddr, protocols::NETLINK_ROUTE,
};
use rtnetlink::Handle;
use tun_rs::AsyncDevice;

use crate::tun::{Tun, TunFactory, TunFut};

/// A TUN device backed by tun_rs's tokio async device.
pub struct LinuxTun {
    dev: AsyncDevice,
    name: String,
    mtu: u32,
}

impl Tun for LinuxTun {
    fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> TunFut<'a> {
        Box::pin(async move { self.dev.recv(buf).await })
    }

    fn send<'a>(&'a mut self, buf: &'a [u8]) -> TunFut<'a> {
        Box::pin(async move { self.dev.send(buf).await })
    }

    fn name(&self) -> io::Result<String> {
        Ok(self.name.clone())
    }

    fn mtu(&self) -> io::Result<u32> {
        Ok(self.mtu)
    }
}

/// Linux TUN factory.
#[derive(Debug, Default, Clone)]
pub struct LinuxTunFactory;

impl TunFactory for LinuxTunFactory {
    fn build(
        &self,
        name: &str,
        ipv4: &str,
        prefix: u8,
        ipv6: Option<(&str, u8)>,
        mtu: u32,
    ) -> io::Result<Box<dyn Tun>> {
        let mut builder = tun_rs::DeviceBuilder::new()
            .name(name)
            .ipv4(ipv4, prefix, None)
            .mtu(mtu as u16);
        if let Some((addr, p)) = ipv6 {
            builder = builder.ipv6(addr, p);
        }
        let dev = builder
            .build_async()
            .map_err(|e| {
                tracing::error!(error = ?e, tun = name, addr = ipv4, prefix, mtu, "failed to create TUN device");
                io::Error::new(io::ErrorKind::Other, e)
            })?;
        Ok(Box::new(LinuxTun {
            dev,
            name: name.to_string(),
            mtu,
        }))
    }

    fn from_fd(&self, fd: std::os::fd::RawFd) -> io::Result<Box<dyn Tun>> {
        // Construct an AsyncDevice from an already-open TUN fd. tun_rs exposes
        // `from_fd` (unsafe because the fd must be a valid TUN file descriptor).
        // Used by mobile hosts where the OS grants the FD.
        let dev = unsafe { AsyncDevice::from_fd(fd)? };
        Ok(Box::new(LinuxTun {
            dev,
            name: format!("fd:{fd}"),
            mtu: 1400,
        }))
    }
}

pub struct NatRules {
    /// IPv4 source CIDR for the MASQUERADE rule (`-s`). `None` masquerades all
    /// traffic leaving via the out interface (no `-s` filter) — used by the
    /// client-side LAN-sharing path to cover any LAN without configuration.
    source_cidr: Option<String>,
    /// Optional IPv6 source CIDR for the ip6tables MASQUERADE rule.
    source_cidr_v6: Option<String>,
    /// TUN interface name, used for the FORWARD accept rules (`-i`/`-o`).
    tun_name: String,
    /// Out interface for the MASQUERADE rule (`-o`). `None` auto-detects the
    /// default route interface (server-side use); the client-side path sets
    /// this to the TUN name itself so forwarded LAN traffic is masqueraded as
    /// it enters the tunnel.
    out_iface: Option<String>,
    /// Client LAN-sharing mode with no `-s` filter: masquerade *all* traffic
    /// leaving via the TUN (set by [`NatRules::new_client`] when no source
    /// CIDR is given). Without this, LAN hosts behind the client would arrive
    /// at the server with their un-NATed private source addresses — outside
    /// the server's TUN-subnet MASQUERADE scope, so replies could never return
    /// (and the server would "learn" those LAN addresses as tunnel IPs).
    masq_all: bool,
    installed: Vec<(String, Vec<String>)>,
}

/// Build a POSTROUTING MASQUERADE spec (the argv after the table flag):
/// `POSTROUTING [-s <source>] -o <iface> -j MASQUERADE`. Pure, for tests.
fn masq_spec(source: Option<&str>, iface: &str) -> Vec<String> {
    let mut masq = vec!["POSTROUTING".to_string()];
    if let Some(s) = source {
        masq.push("-s".into());
        masq.push(s.to_string());
    }
    masq.push("-o".into());
    masq.push(iface.to_string());
    masq.push("-j".into());
    masq.push("MASQUERADE".into());
    masq
}

impl NatRules {
    /// Server-side NAT: masquerade the TUN's subnet out the default (or given)
    /// egress interface so tunneled clients reach the internet.
    pub fn new(
        tun_cidr: impl Into<String>,
        tun_name: impl Into<String>,
        out_iface: Option<String>,
    ) -> Self {
        let cidr = tun_cidr.into();
        // If the CIDR is IPv6, store it in source_cidr_v6; otherwise IPv4.
        let (source_cidr, source_cidr_v6) = match cidr.parse::<ipnet::IpNet>() {
            Ok(ipnet::IpNet::V6(_)) => (None, Some(cidr)),
            _ => (Some(cidr), None),
        };
        Self {
            source_cidr,
            source_cidr_v6,
            tun_name: tun_name.into(),
            out_iface,
            masq_all: false,
            installed: Vec::new(),
        }
    }

    /// Set the IPv6 source CIDR for ip6tables MASQUERADE. Returns self for
    /// chaining. Called by the server daemon when a dual-stack TUN is configured.
    pub fn with_v6_cidr(mut self, cidr6: impl Into<String>) -> Self {
        let cidr = cidr6.into();
        match cidr.parse::<ipnet::IpNet>() {
            Ok(ipnet::IpNet::V6(_)) => {
                self.source_cidr_v6 = Some(cidr);
            }
            _ => {
                tracing::warn!("ignoring non-IPv6 CIDR for v6 NAT: {cidr}");
            }
        }
        self
    }

    /// Client-side NAT (LAN sharing): masquerade a LAN behind this client out
    /// the TUN so forwarded LAN traffic appears to come from the client's
    /// tunnel address — the server only knows the client's TUN IP, not the
    /// LAN behind it, so without this the server would drop reply traffic to
    /// the LAN hosts. A `source_cidr` of `None` masquerades all traffic leaving
    /// via the TUN (no `-s` filter): the broadest setting, which makes any LAN
    /// behind the client share the tunnel with no per-LAN configuration.
    /// `Some("192.168.50.0/24")` scopes the rule to one LAN.
    pub fn new_client(source_cidr: Option<impl Into<String>>, tun_name: impl Into<String>) -> Self {
        let tun = tun_name.into();
        // Classify the source CIDR as IPv4 or IPv6.
        let (source_cidr, source_cidr_v6) = match source_cidr {
            Some(s) => {
                let s = s.into();
                match s.parse::<ipnet::IpNet>() {
                    Ok(ipnet::IpNet::V6(_)) => (None, Some(s)),
                    _ => (Some(s), None),
                }
            }
            None => (None, None),
        };
        let masq_all = source_cidr.is_none() && source_cidr_v6.is_none();
        Self {
            source_cidr,
            source_cidr_v6,
            tun_name: tun.clone(),
            out_iface: Some(tun),
            // No source CIDR means "masquerade everything leaving via the
            // TUN" (no `-s` filter); a scoped CIDR keeps the `-s` filter.
            masq_all,
            installed: Vec::new(),
        }
    }

    /// Build the IPv4 rule specs without executing them (pure, for tests).
    /// Returns `(table, spec)` pairs where `spec` is the argv after the table
    /// flag (chain + match + target). The MASQUERADE entry is present when a
    /// source CIDR scopes it, or — in client LAN-sharing mode with no source
    /// CIDR — without a `-s` filter so all traffic leaving via the TUN is
    /// masqueraded.
    fn planned_v4(&self, iface: &str) -> Vec<(&'static str, Vec<String>)> {
        let tun = &self.tun_name;
        let mut rules: Vec<(&str, Vec<String>)> = Vec::new();
        // Scoped MASQUERADE (`-s <cidr>`), or — in client LAN-sharing mode
        // with no source CIDR — an unscoped one (no `-s` filter, so any LAN
        // behind the client is masqueraded as it enters the tunnel).
        if self.source_cidr.is_some() || self.masq_all {
            rules.push(("nat", masq_spec(self.source_cidr.as_deref(), iface)));
        }
        rules.push((
            "filter",
            vec![
                "FORWARD".into(),
                "-i".into(),
                tun.clone(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        ));
        rules.push((
            "filter",
            vec![
                "FORWARD".into(),
                "-o".into(),
                tun.clone(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        ));
        rules
    }

    /// Build the IPv6 MASQUERADE spec without executing it (pure, for tests).
    /// `None` when no IPv6 masquerade applies.
    fn planned_v6_masq(&self, iface: &str) -> Option<Vec<String>> {
        match self.source_cidr_v6.as_deref() {
            Some(s) => Some(masq_spec(Some(s), iface)),
            None if self.masq_all => Some(masq_spec(None, iface)),
            None => None,
        }
    }

    /// Install the rules. Requires root. Idempotent: failures due to
    /// pre-existing rules are tolerated.
    ///
    /// Installs IPv4 (`iptables`) rules always, and IPv6 (`ip6tables`) rules
    /// only when the kernel actually has IPv6 support (see
    /// [`ipv6_available`]): on IPv6-less hosts the sysctl/ip6tables calls are
    /// skipped entirely and the summary log says so, instead of attempting
    /// them, failing, and still claiming "IPv4+IPv6".
    pub fn install(&mut self) -> io::Result<()> {
        let iface = match &self.out_iface {
            Some(i) => i.clone(),
            None => default_route_iface()?,
        };
        let v6 = ipv6_available();
        // Enable forwarding for IPv4 always; for IPv6 only when supported.
        let _ = run("sysctl", &["-w", "net.ipv4.ip_forward=1"]);
        if v6 {
            let _ = run("sysctl", &["-w", "net.ipv6.conf.all.forwarding=1"]);
        } else {
            tracing::debug!("IPv6 unavailable; skipping IPv6 forwarding sysctl");
        }

        // IPv4: optional MASQUERADE + FORWARD accept rules (required).
        let rules_v4 = self.planned_v4(&iface);
        for (table, spec) in &rules_v4 {
            // idempotency: delete any existing identical rule first. Each
            // flag/value must be its own argv entry; joining them into one
            // string makes iptables treat the whole blob as the chain name
            // ("chain name too long").
            let mut del: Vec<&str> = vec!["-t", *table, "-D"];
            del.extend(spec.iter().map(|s| s.as_str()));
            let _ = iptables(&del);

            let mut add: Vec<&str> = vec!["-t", *table, "-A"];
            add.extend(spec.iter().map(|s| s.as_str()));
            iptables(&add)?;
            self.installed.push(((*table).to_string(), spec.clone()));
        }

        // IPv6: optional MASQUERADE + FORWARD accept rules. Best-effort —
        // ip6tables may not be installed on minimal hosts — and skipped
        // entirely when the kernel has no IPv6 support.
        let mut v6_ok = false;
        if v6 {
            if let Some(spec) = self.planned_v6_masq(&iface) {
                let mut cmd: Vec<&str> = vec!["-t", "nat", "-A"];
                cmd.extend(spec.iter().map(|s| s.as_str()));
                if ip6tables(&cmd).is_ok() {
                    v6_ok = true;
                    self.installed.push(("nat".to_string(), spec));
                } else {
                    tracing::debug!("ip6tables MASQUERADE failed (best-effort, ignored)");
                }
            }
            for direction in ["-i", "-o"] {
                let spec: Vec<String> = vec![
                    "FORWARD".into(),
                    direction.into(),
                    self.tun_name.clone(),
                    "-j".into(),
                    "ACCEPT".into(),
                ];
                let mut cmd = vec!["-t", "filter", "-A"];
                cmd.extend(spec.iter().map(|s| s.as_str()));
                if ip6tables(&cmd).is_ok() {
                    v6_ok = true;
                    self.installed.push(("filter".to_string(), spec));
                } else {
                    tracing::debug!(
                        direction,
                        "ip6tables FORWARD rule failed (best-effort, ignored)"
                    );
                }
            }
        }

        if v6 && v6_ok {
            tracing::info!(installed = ?self.installed, "installed NAT rules (IPv4+IPv6)");
        } else {
            tracing::info!(installed = ?self.installed, "installed NAT rules (IPv4 only; IPv6 unavailable or not configured)");
        }
        Ok(())
    }

    /// Remove the rules previously installed. Best-effort: tries both iptables
    /// and ip6tables for each recorded rule.
    pub fn remove(&mut self) -> io::Result<()> {
        for (table, spec) in &self.installed {
            let mut del: Vec<&str> = vec!["-t", table, "-D"];
            del.extend(spec.iter().map(|s| s.as_str()));
            let _ = iptables(&del);
            let _ = ip6tables(&del);
        }
        self.installed.clear();
        Ok(())
    }
}

impl Drop for NatRules {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

/// Shell out to `ip6tables` with the given arguments.
fn ip6tables(args: &[&str]) -> io::Result<()> {
    run("ip6tables", args)
}

fn iptables(args: &[&str]) -> io::Result<()> {
    run("iptables", args)
}

fn run(cmd: &str, args: &[&str]) -> io::Result<()> {
    // Capture (don't inherit) child output: best-effort cleanup paths call
    // this for rules/chains that may not exist, and inheriting stderr would
    // print raw `iptables: Bad rule ...` / `RTNETLINK answers: ...` noise to
    // the terminal on every start/stop. Failures carry the child's stderr in
    // the returned error instead, so required callers still see it via
    // `tracing` and best-effort callers stay silent (debug-logged).
    let out = Command::new(cmd).args(args).output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let msg = if stderr.is_empty() {
            format!("{cmd} {args:?} exited {}", out.status)
        } else {
            format!("{cmd} {args:?} exited {}: {stderr}", out.status)
        };
        return Err(io::Error::new(io::ErrorKind::Other, msg));
    }
    Ok(())
}

/// Whether the kernel has IPv6 support at all. When IPv6 is disabled (e.g.
/// `ipv6.disable=1`, minimal containers), `/proc/sys/net/ipv6` is absent and
/// every `sysctl net.ipv6...` / `ip6tables` call fails — those calls must be
/// skipped (not attempted and logged as success). Split into a
/// path-parameterised helper so tests can stub the "IPv6 unavailable"
/// condition without touching `/proc`.
fn ipv6_available_at(proc_net_ipv6: &Path) -> bool {
    proc_net_ipv6.exists()
}

/// Production IPv6 availability probe (see [`ipv6_available_at`]).
fn ipv6_available() -> bool {
    ipv6_available_at(Path::new("/proc/sys/net/ipv6"))
}

/// Best-effort detection of the default egress interface via `ip route`.
fn default_route_iface() -> io::Result<String> {
    let out = Command::new("ip")
        .args(["-o", "-4", "route", "show", "default"])
        .output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "ip route show default failed",
        ));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    parse_default_route_iface(&s)
}

/// Parse the `dev` field from `ip -o -4 route show default` output.
/// Extracted for unit testing the parsing without running a subprocess.
fn parse_default_route_iface(output: &str) -> io::Result<String> {
    // e.g. "default via 192.168.1.1 dev eth0 proto static"
    output
        .split_whitespace()
        .skip_while(|w| *w != "dev")
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no default route dev"))
        .map(|s| s.to_string())
}

/// Best-effort: the default gateway IP address (the `via` field of the default
/// route).
fn default_gateway() -> io::Result<String> {
    let out = Command::new("ip")
        .args(["-o", "-4", "route", "show", "default"])
        .output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "ip route show default failed",
        ));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    parse_default_gateway(&s)
}

/// Parse the `via` field from `ip -o -4 route show default` output.
/// Extracted for unit testing the parsing without running a subprocess.
fn parse_default_gateway(output: &str) -> io::Result<String> {
    output
        .split_whitespace()
        .skip_while(|w| *w != "via")
        .nth(1)
        .map(|gw| gw.to_string())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no default gateway"))
}

/// Best-effort: the IPv6 default gateway address (the `via` / `src` field of
/// the default route, or the link-local next-hop on `dev`).
fn default_gateway_v6() -> io::Result<String> {
    let out = Command::new("ip")
        .args(["-o", "-6", "route", "show", "default"])
        .output()?;
    if !out.status.success() || out.stdout.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no IPv6 default route found",
        ));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    parse_default_gateway_v6(&s)
}

/// Parse the IPv6 default route. Returns the next-hop gateway (either the `via`
/// address or the `src` address if the route is on-link with no `via`).
fn parse_default_gateway_v6(output: &str) -> io::Result<String> {
    // e.g. "default via fe80::1 dev eth0 proto ra metric 100"
    // or "default dev eth0 proto ra metric 100" (no via, on-link)
    for (i, w) in output.split_whitespace().enumerate() {
        if w == "via" {
            if let Some(gw) = output.split_whitespace().nth(i + 1) {
                return Ok(gw.to_string());
            }
        }
    }
    // No `via`: fall back to `src` if present.
    for (i, w) in output.split_whitespace().enumerate() {
        if w == "src" {
            if let Some(addr) = output.split_whitespace().nth(i + 1) {
                return Ok(addr.to_string());
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no IPv6 default gateway in route output",
    ))
}

/// Route-all orchestration for the client. Installs:
///
/// 1. A host route to the VPN server's real IP via the original default
///    gateway, so encrypted UDP traffic to the server does not itself go
///    through the tunnel (which would loop).
/// 2. Explicit routes for the client's directly-attached local subnet(s) via
///    the original gateway, so LAN traffic (printers, NAS, other hosts on the
///    local network) stays off the tunnel. Without this, route-all pulls LAN
///    traffic into the tunnel: the server then sees packets with private LAN
///    source addresses it cannot NAT or route back (and "learns" those LAN
///    addresses as client tunnel IPs). Real VPN clients keep local-subnet
///    traffic on the local gateway by default; only internet-bound traffic
///    goes through the tunnel.
/// 3. A new default route via the TUN interface, with a higher-priority
///    (lower) metric so all remaining traffic is pulled into the tunnel.
/// 4. A policy-routing bypass so *inbound* connections to the box itself keep
///    working: reply packets sourced from the box's own WAN address(es) are
///    looked up in a dedicated table that routes via the original gateway,
///    instead of following the tunnel default (which would NAT them to the
///    server's egress IP and break SSH, HTTP, and any other listening
///    service). See [`BYPASS_TABLE`].
///
/// The [`RouteGuard`] returned removes all four on drop, restoring the
/// original routing. Requires root.
pub struct RouteGuard {
    server_ip: String,
    orig_gw: String,
    tun_name: String,
    /// Local-subnet exceptions installed in step 2, as `(cidr, gateway)`
    /// pairs, removed on drop.
    lan_routes: Vec<(String, String)>,
    /// IPv6 equivalents (populated when the server address is IPv6 or the host
    /// has a default IPv6 route). Empty strings mean "no IPv6 route installed".
    server_ip6: String,
    orig_gw6: String,
    /// Original egress interface for the bypass table (step 4). Empty when no
    /// bypass routes were installed.
    orig_iface: String,
    /// Subnet routes installed in the bypass table, removed on drop.
    bypass_cidrs: Vec<String>,
    /// Local addresses with `from`-rules pointing at the bypass table,
    /// removed on drop.
    bypass_addrs: Vec<String>,
    /// IPv6 bypass-table equivalents. Empty when no IPv6 bypass was installed.
    orig_iface6: String,
    bypass_cidrs6: Vec<String>,
    bypass_addrs6: Vec<String>,
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        // Remove the bypass-table policy routing first (both families), so no
        // reply packet can outlive the tunnel default it was installed with.
        // Best-effort and silent: `run` captures child output.
        remove_bypass(self, false);
        remove_bypass(self, true);
        // Remove the default-via-TUN routes (both families). These are
        // best-effort and silent: `run` captures child output, so a missing
        // route no longer prints raw `RTNETLINK answers: ...` noise.
        let _ = run("ip", &["route", "del", "default", "dev", &self.tun_name]);
        if !self.server_ip6.is_empty() {
            let _ = run(
                "ip",
                &["-6", "route", "del", "default", "dev", &self.tun_name],
            );
        }
        // Remove the local-subnet exceptions.
        for (cidr, gw) in &self.lan_routes {
            let _ = run("ip", &["route", "del", cidr, "via", gw]);
        }
        // Remove the server host routes (both families, if installed).
        if !self.server_ip.is_empty() {
            let _ = run(
                "ip",
                &["route", "del", &self.server_ip, "via", &self.orig_gw],
            );
        }
        if !self.server_ip6.is_empty() {
            let _ = run(
                "ip",
                &[
                    "-6",
                    "route",
                    "del",
                    &self.server_ip6,
                    "via",
                    &self.orig_gw6,
                ],
            );
        }
        tracing::info!("route-all rules removed");
    }
}

/// Compute the ordered route-all installation plan as `ip` argv (each entry is
/// the argv after the leading `ip`). Pure, for unit testing the route
/// computation in isolation without touching real interfaces:
/// server host route first (so tunnel UDP never loops), then local-subnet
/// exceptions, then the default-via-TUN last (so it cannot swallow the
/// exceptions' traffic during installation).
fn route_all_plan(
    server_ip: &str,
    orig_gw: &str,
    lan_cidrs: &[String],
    tun_name: &str,
) -> Vec<Vec<String>> {
    let mut plan = Vec::new();
    plan.push(vec![
        "route".into(),
        "add".into(),
        server_ip.into(),
        "via".into(),
        orig_gw.into(),
    ]);
    for cidr in lan_cidrs {
        plan.push(vec![
            "route".into(),
            "add".into(),
            cidr.clone(),
            "via".into(),
            orig_gw.into(),
        ]);
    }
    plan.push(vec![
        "route".into(),
        "add".into(),
        "default".into(),
        "dev".into(),
        tun_name.into(),
        "metric".into(),
        "1".into(),
    ]);
    plan
}

/// Policy-routing table consulted for reply traffic to inbound connections
/// while route-all is active. Replies sourced from the box's own WAN
/// address(es) match `from`-rules into this table and leave via the original
/// gateway, instead of following the tunnel default (which would NAT them to
/// the server's egress IP and break every listening service). `100` avoids the
/// kernel-reserved tables (`local` 255, `main` 254, `default` 253).
const BYPASS_TABLE: &str = "100";
/// Priority of the bypass `from`-rules: before `main` (32766) so reply
/// traffic never consults the tunnel default, after `local` (0) so
/// interface-local delivery is untouched.
const BYPASS_RULE_PRIO: &str = "20000";

/// Compute the bypass-table installation plan as `ip` argv (each entry is the
/// argv after the leading `ip`). Pure, for tests: connected-subnet routes in
/// the bypass table first (so the `from`-rules never point at an empty
/// table), then the bypass default via the original gateway, then one
/// `from <addr>` rule per local address. `ip6` prefixes every step with `-6`
/// for the IPv6 half.
fn bypass_plan(
    orig_gw: &str,
    orig_iface: &str,
    lan_cidrs: &[String],
    local_addrs: &[String],
    ip6: bool,
) -> Vec<Vec<String>> {
    let mut plan = Vec::new();
    let prefix: &[String] = if ip6 { &["-6".into()] } else { &[] };
    for cidr in lan_cidrs {
        let mut step: Vec<String> = prefix.to_vec();
        step.extend([
            "route".into(),
            "add".into(),
            cidr.clone(),
            "dev".into(),
            orig_iface.into(),
            "table".into(),
            BYPASS_TABLE.into(),
        ]);
        plan.push(step);
    }
    let mut def: Vec<String> = prefix.to_vec();
    def.extend([
        "route".into(),
        "add".into(),
        "default".into(),
        "via".into(),
        orig_gw.into(),
        "dev".into(),
        orig_iface.into(),
        "table".into(),
        BYPASS_TABLE.into(),
    ]);
    plan.push(def);
    for addr in local_addrs {
        let mut rule: Vec<String> = prefix.to_vec();
        rule.extend([
            "rule".into(),
            "add".into(),
            "from".into(),
            addr.clone(),
            "table".into(),
            BYPASS_TABLE.into(),
            "priority".into(),
            BYPASS_RULE_PRIO.into(),
        ]);
        plan.push(rule);
    }
    plan
}

/// Remove one installed bypass family. Reconstructs the exact `del` argv for
/// every recorded entry; missing entries are normal (a failed install records
/// nothing) and ignored.
fn remove_bypass(guard: &RouteGuard, ip6: bool) {
    let (iface, cidrs, addrs): (&str, &[String], &[String]) = if ip6 {
        (
            guard.orig_iface6.as_str(),
            &guard.bypass_cidrs6,
            &guard.bypass_addrs6,
        )
    } else {
        (
            guard.orig_iface.as_str(),
            &guard.bypass_cidrs,
            &guard.bypass_addrs,
        )
    };
    if iface.is_empty() {
        return;
    }
    let prefix: &[&str] = if ip6 { &["-6"] } else { &[] };
    for addr in addrs {
        let mut del: Vec<&str> = prefix.to_vec();
        del.extend([
            "rule",
            "del",
            "from",
            addr,
            "table",
            BYPASS_TABLE,
            "priority",
            BYPASS_RULE_PRIO,
        ]);
        let _ = run("ip", &del);
    }
    for cidr in cidrs {
        let mut del: Vec<&str> = prefix.to_vec();
        del.extend(["route", "del", cidr, "dev", iface, "table", BYPASS_TABLE]);
        let _ = run("ip", &del);
    }
    {
        let mut del: Vec<&str> = prefix.to_vec();
        del.extend(["route", "del", "default", "table", BYPASS_TABLE]);
        let _ = run("ip", &del);
    }
}

/// Parse the host addresses of `ip -o addr show dev <iface>` output: every
/// `inet <addr>/<prefix>` token contributes its address. For `ip6`, every
/// `inet6` token except link-local (`fe80::/10`) — link-local sources never
/// arrive from the WAN, so no `from`-rule is needed for them. Duplicates are
/// removed. Pure, for tests.
fn parse_local_addrs(output: &str, ip6: bool) -> Vec<String> {
    let token = if ip6 { "inet6" } else { "inet" };
    let mut addrs = Vec::new();
    for line in output.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        for (i, w) in words.iter().enumerate() {
            if *w != token {
                continue;
            }
            if let Some(cidr) = words.get(i + 1) {
                let addr = cidr.split('/').next().unwrap_or(cidr);
                if ip6 {
                    let is_link_local = addr
                        .split(':')
                        .next()
                        .and_then(|h| u16::from_str_radix(h, 16).ok())
                        .is_some_and(|h| (h & 0xffc0) == 0xfe80);
                    if is_link_local || addr == "::1" {
                        continue;
                    }
                }
                if !addr.is_empty() && !addrs.contains(&addr.to_string()) {
                    addrs.push(addr.to_string());
                }
            }
        }
    }
    addrs
}

/// Parse the *network* CIDRs of `ip -o -6 addr show dev <iface>` output, the
/// IPv6 counterpart of [`parse_local_cidrs`]: every global `inet6` token
/// becomes its masked network. Link-local (`fe80::/10`) and host (`/128`)
/// assignments are skipped. Pure, for tests.
fn parse_local_cidrs_v6(output: &str) -> Vec<String> {
    let mut cidrs = Vec::new();
    for line in output.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        for (i, w) in words.iter().enumerate() {
            if *w != "inet6" {
                continue;
            }
            if let Some(cidr) = words.get(i + 1)
                && let Ok(ipnet::IpNet::V6(net)) = cidr.parse::<ipnet::IpNet>()
            {
                let addr = net.addr();
                if addr.is_unicast_link_local() || net.prefix_len() == 128 {
                    continue;
                }
                let masked = ipnet::IpNet::V6(net.trunc()).to_string();
                if !cidrs.contains(&masked) {
                    cidrs.push(masked);
                }
            }
        }
    }
    cidrs
}

/// Parse the *network* CIDRs of `ip -o -4 addr show dev <iface>` output: every
/// `inet <addr>/<prefix>` token becomes its masked network
/// (`213.138.68.130/24` -> `213.138.68.0/24`), because `ip route add` rejects
/// host-bits-set prefixes outright ("Invalid prefix for given prefix
/// length"). Host (/32, /128) assignments are skipped (the kernel's local
/// table already handles the interface's own address; routing it via the
/// gateway would be wrong). Duplicates are removed so each subnet is added
/// once. Pure, for tests.
fn parse_local_cidrs(output: &str) -> Vec<String> {
    let mut cidrs = Vec::new();
    for line in output.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        for (i, w) in words.iter().enumerate() {
            if *w != "inet" {
                continue;
            }
            if let Some(cidr) = words.get(i + 1) {
                if let Ok(net) = cidr.parse::<ipnet::IpNet>() {
                    let max = match net {
                        ipnet::IpNet::V4(_) => 32,
                        ipnet::IpNet::V6(_) => 128,
                    };
                    if net.prefix_len() == max {
                        continue;
                    }
                    let masked = net.trunc().to_string();
                    if !cidrs.contains(&masked) {
                        cidrs.push(masked);
                    }
                }
            }
        }
    }
    cidrs
}

/// Best-effort: the IPv4 CIDRs assigned to `iface` (the client's local
/// subnet(s)), via `ip -o -4 addr show`. Returns an empty vec when the
/// interface has no addresses or `ip` fails — the caller then installs no
/// exceptions (previous behaviour) rather than failing route-all entirely.
fn local_cidrs_for(iface: &str) -> Vec<String> {
    let out = match Command::new("ip")
        .args(["-o", "-4", "addr", "show", "dev", iface])
        .output()
    {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            tracing::debug!(
                iface,
                status = %o.status,
                "could not list addresses for route-all LAN exception; continuing without it"
            );
            return Vec::new();
        }
        Err(e) => {
            tracing::debug!(error = ?e, iface, "could not list addresses for route-all LAN exception; continuing without it");
            return Vec::new();
        }
    };
    parse_local_cidrs(&String::from_utf8_lossy(&out.stdout))
}

/// Best-effort: the IPv4 host addresses assigned to `iface`, via
/// `ip -o -4 addr show`. Used for the bypass-table `from`-rules so reply
/// traffic to inbound connections keeps leaving via the original gateway.
/// Empty when the interface has no addresses or `ip` fails.
fn local_addrs_for(iface: &str) -> Vec<String> {
    let out = match Command::new("ip")
        .args(["-o", "-4", "addr", "show", "dev", iface])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => {
            tracing::debug!(
                iface,
                "could not list addresses for bypass from-rules; inbound replies may use the tunnel"
            );
            return Vec::new();
        }
    };
    parse_local_addrs(&String::from_utf8_lossy(&out.stdout), false)
}

/// Best-effort: the global IPv6 host addresses assigned to `iface`, via
/// `ip -o -6 addr show`. IPv6 half of [`local_addrs_for`].
fn local_addrs_for_v6(iface: &str) -> Vec<String> {
    let out = match Command::new("ip")
        .args(["-o", "-6", "addr", "show", "dev", iface])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => {
            tracing::debug!(
                iface,
                "could not list IPv6 addresses for bypass from-rules; inbound IPv6 replies may use the tunnel"
            );
            return Vec::new();
        }
    };
    parse_local_addrs(&String::from_utf8_lossy(&out.stdout), true)
}

/// Best-effort: the global IPv6 networks assigned to `iface`, via
/// `ip -o -6 addr show`. IPv6 half of [`local_cidrs_for`].
fn local_cidrs_for_v6(iface: &str) -> Vec<String> {
    let out = match Command::new("ip")
        .args(["-o", "-6", "addr", "show", "dev", iface])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    parse_local_cidrs_v6(&String::from_utf8_lossy(&out.stdout))
}

/// Best-effort: the egress interface of the IPv6 default route, via
/// `ip -o -6 route show default`. IPv6 half of [`default_route_iface`].
fn default_route_iface_v6() -> io::Result<String> {
    let out = Command::new("ip")
        .args(["-o", "-6", "route", "show", "default"])
        .output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "ip -6 route show default failed",
        ));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    parse_default_route_iface(&s)
}

/// Install one bypass-table plan best-effort: each step is pre-cleaned (the
/// matching `del` runs first and is ignored) so a restart after a crash does
/// not accumulate duplicates, then added; failures warn and continue. Returns
/// the `(cidrs, addrs)` actually installed, for guard cleanup.
fn install_bypass_plan(plan: &[Vec<String>]) -> (Vec<String>, Vec<String>) {
    let mut cidrs = Vec::new();
    let mut addrs = Vec::new();
    for step in plan {
        let refs: Vec<&str> = step.iter().map(|s| s.as_str()).collect();
        // Position of the `add` verb: shifted by one when the step carries
        // the `-6` family prefix.
        let op_idx = if step.first().is_some_and(|s| s == "-6") {
            2
        } else {
            1
        };
        // Pre-clean: `del` the identical entry first (ignored), so reinstalls
        // are idempotent.
        let mut del = refs.clone();
        if let Some(op) = del.get_mut(op_idx) {
            *op = "del";
        }
        let _ = run("ip", &del);
        match run("ip", &refs) {
            Ok(()) => {
                let kind = step.get(op_idx + 1).map(|s| s.as_str()).unwrap_or("");
                if kind == "rule" {
                    if let Some(addr) = step.iter().skip_while(|s| *s != "from").nth(1) {
                        addrs.push(addr.clone());
                    }
                } else if kind == "route"
                    && let Some(dst) = step.get(op_idx + 2)
                    && *dst != "default"
                {
                    cidrs.push(dst.to_string());
                }
            }
            Err(e) => {
                tracing::warn!(error = ?e, step = ?step, "failed to install bypass-table entry; replies to inbound connections on this address may use the tunnel");
            }
        }
    }
    (cidrs, addrs)
}

/// Install route-all rules and return a guard that removes them on drop.
///
/// Installs host routes to the server and default routes via the TUN for
/// **both** IPv4 and IPv6 (when the server address and default routes are
/// available for each family).
pub fn install_route_all(server: &std::net::SocketAddr, tun_name: &str) -> io::Result<RouteGuard> {
    let server_ip = server.ip().to_string();
    let orig_gw = default_gateway()?;
    let orig_iface = default_route_iface()?;

    tracing::debug!(
        server_ip = %server_ip,
        orig_gw = %orig_gw,
        orig_iface = %orig_iface,
        tun = %tun_name,
        "installing route-all rules"
    );

    // Install the plan: server host route (required, first so tunnel UDP
    // never loops), then local-subnet exceptions (warn-and-continue: losing
    // one exception degrades to the previous behaviour for that subnet rather
    // than failing route-all entirely), then the default via TUN (required).
    let lan_cidrs = local_cidrs_for(&orig_iface);
    let local_addrs = local_addrs_for(&orig_iface);
    let plan = route_all_plan(&server_ip, &orig_gw, &lan_cidrs, tun_name);
    let mut lan_routes: Vec<(String, String)> = Vec::new();
    // Main-table routes added so far, for rollback if a required step fails
    // (otherwise a half-installed state leaks, e.g. the server host route
    // without the tunnel default).
    let mut added_main: Vec<Vec<String>> = Vec::new();
    for step in &plan {
        let refs: Vec<&str> = step.iter().map(|s| s.as_str()).collect();
        let is_lan_exception =
            step.len() >= 4 && step[0] == "route" && step[2] != "default" && step[2] != server_ip;
        match run("ip", &refs) {
            Ok(()) => {
                added_main.push(step.clone());
                if is_lan_exception {
                    lan_routes.push((step[2].clone(), orig_gw.clone()));
                }
            }
            Err(e) if is_lan_exception => {
                if e.to_string().contains("File exists") {
                    tracing::debug!(cidr = %step[2], "LAN subnet already has a kernel route; no exception needed");
                } else {
                    tracing::warn!(error = ?e, cidr = %step[2], "failed to install LAN exception route; that subnet's traffic will use the tunnel");
                }
            }
            Err(e) => {
                for done in added_main.iter().rev() {
                    let mut del: Vec<&str> = done.iter().map(|s| s.as_str()).collect();
                    if let Some(op) = del.get_mut(1) {
                        *op = "del";
                    }
                    let _ = run("ip", &del);
                }
                return Err(e);
            }
        }
    }
    tracing::debug!(server_ip = %server_ip, via = %orig_gw, "installed server host route (IPv4)");
    for (cidr, _) in &lan_routes {
        tracing::debug!(cidr = %cidr, via = %orig_gw, "installed LAN exception route (IPv4)");
    }
    tracing::debug!(tun = %tun_name, "installed default route via TUN (IPv4)");

    // Bypass table: reply traffic sourced from the box's own addresses leaves
    // via the original gateway, so inbound connections (SSH, HTTP, ...) keep
    // working under route-all. Best-effort: a failed entry only affects
    // replies for that address.
    let bypass = bypass_plan(&orig_gw, &orig_iface, &lan_cidrs, &local_addrs, false);
    let (bypass_cidrs, bypass_addrs) = install_bypass_plan(&bypass);
    tracing::debug!(addrs = ?bypass_addrs, "installed bypass-table from-rules (IPv4)");

    // IPv6: host route to server + default via TUN (if the server is reachable
    // over IPv6 and an IPv6 default gateway exists).
    let v6 = install_route_all_v6(server, tun_name).unwrap_or_default();

    tracing::info!(
        server_ip = %server_ip,
        "route-all active: all traffic -> TUN, server reachable via {}",
        orig_iface
    );

    Ok(RouteGuard {
        server_ip,
        orig_gw,
        tun_name: tun_name.to_string(),
        lan_routes,
        server_ip6: v6.server_ip6,
        orig_gw6: v6.orig_gw6,
        orig_iface,
        bypass_cidrs,
        bypass_addrs,
        orig_iface6: v6.orig_iface6,
        bypass_cidrs6: v6.bypass_cidrs6,
        bypass_addrs6: v6.bypass_addrs6,
    })
}

/// IPv6 route-all state handed back to the [`RouteGuard`] for cleanup.
/// `Default` is "no IPv6 route installed".
#[derive(Debug, Default)]
struct V6RouteAll {
    server_ip6: String,
    orig_gw6: String,
    orig_iface6: String,
    bypass_cidrs6: Vec<String>,
    bypass_addrs6: Vec<String>,
}

/// Install IPv6 equivalents of the route-all host route + default route, plus
/// the bypass-table entries for inbound IPv6 replies. Returns the state the
/// [`RouteGuard`] needs for cleanup, or `None` when IPv6 routing is not
/// available (no default IPv6 route, or the server address is IPv4).
fn install_route_all_v6(server: &std::net::SocketAddr, tun_name: &str) -> Option<V6RouteAll> {
    // Only install IPv6 routes if the server has an IPv6 address.
    let server_v6 = match server.ip() {
        std::net::IpAddr::V6(v6) => v6,
        std::net::IpAddr::V4(_) => return None,
    };
    let server_ip6 = server_v6.to_string();

    // Find the IPv6 default gateway and outgoing interface.
    let gw6 = match default_gateway_v6() {
        Ok(gw) => gw,
        Err(e) => {
            tracing::debug!(error = ?e, "no IPv6 default gateway; skipping IPv6 route-all");
            return None;
        }
    };
    let iface6 = match default_route_iface_v6() {
        Ok(iface) => iface,
        Err(e) => {
            tracing::debug!(error = ?e, "no IPv6 egress interface; skipping IPv6 route-all");
            return None;
        }
    };

    // Host route to the server via the original gateway.
    run("ip", &["-6", "route", "add", &server_ip6, "via", &gw6]).ok()?;
    tracing::debug!(server_ip = %server_ip6, via = %gw6, "installed server host route (IPv6)");

    // Default route through the TUN. On failure roll back the host route so
    // no half-installed state leaks.
    if run(
        "ip",
        &[
            "-6", "route", "add", "default", "dev", tun_name, "metric", "1",
        ],
    )
    .is_err()
    {
        let _ = run("ip", &["-6", "route", "del", &server_ip6, "via", &gw6]);
        return None;
    }
    tracing::debug!(tun = %tun_name, "installed default route via TUN (IPv6)");

    let lan_cidrs6 = local_cidrs_for_v6(&iface6);
    let local_addrs6 = local_addrs_for_v6(&iface6);
    let bypass6 = bypass_plan(&gw6, &iface6, &lan_cidrs6, &local_addrs6, true);
    let (bypass_cidrs6, bypass_addrs6) = install_bypass_plan(&bypass6);

    Some(V6RouteAll {
        server_ip6,
        orig_gw6: gw6,
        orig_iface6: iface6,
        bypass_cidrs6,
        bypass_addrs6,
    })
}

// ---------------------------------------------------------------------------
// Route-file: add a list of destinations (IPs/CIDRs) through the TUN device.
//
// The destinations are read from a plain text file (one per line; `#` comments
// and blank lines ignored). Routes are installed directly over netlink rather
// than by spawning an `ip` process per entry, so files with tens of thousands
// of routes are practical. Each route uses `NLM_F_REPLACE` so re-adding an
// existing route is a no-op rather than an error (matching the
// `suppress_route_errors` behaviour of legacy configs). The guard removes all
// installed routes on drop, restoring the original routing table.
// ---------------------------------------------------------------------------

/// A parsed route destination from the route file: an address and prefix
/// length. A bare IP becomes a host route (`/32` for IPv4, `/128` for IPv6).
#[derive(Debug, Clone, Copy)]
struct RouteDest {
    addr: std::net::IpAddr,
    prefix: u8,
}

/// Parse a single non-comment, non-blank line into a [`RouteDest`].
///
/// Accepts `a.b.c.d`, `a.b.c.d/p`, `a.b.c.d p.q.r.s` (the legacy
/// `route <ip> <mask>` form — the mask is converted to a prefix length), and
/// the IPv6 equivalents. Returns `None` for unparseable lines.
fn parse_route_line(line: &str) -> Option<RouteDest> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    // Legacy "ip mask" form: two whitespace-separated tokens where the second
    // is a dotted-quad netmask. Convert the netmask to a prefix length.
    let mut parts = line.split_whitespace();
    let first = parts.next()?;
    if let Some(second) = parts.next() {
        if let (Ok(ip), Ok(mask)) = (
            first.parse::<std::net::Ipv4Addr>(),
            second.parse::<std::net::Ipv4Addr>(),
        ) {
            if let Some(prefix) = netmask_to_prefix(mask) {
                return Some(RouteDest {
                    addr: std::net::IpAddr::V4(ip),
                    prefix,
                });
            }
        }
    }
    // CIDR or bare IP.
    if let Ok(cidr) = first.parse::<ipnet::IpNet>() {
        return Some(RouteDest {
            addr: cidr.addr(),
            prefix: cidr.prefix_len(),
        });
    }
    // Bare IP -> host route.
    if let Ok(ip) = first.parse::<std::net::IpAddr>() {
        let prefix = match ip {
            std::net::IpAddr::V4(_) => 32,
            std::net::IpAddr::V6(_) => 128,
        };
        return Some(RouteDest { addr: ip, prefix });
    }
    None
}

/// Convert an IPv4 netmask to a prefix length, or `None` if it is not a
/// contiguous mask (leading 1s then trailing 0s).
fn netmask_to_prefix(mask: std::net::Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    // all zeros -> /0
    if bits == 0 {
        return Some(0);
    }
    // The number of trailing zero bits is the host portion.
    let zeros = bits.trailing_zeros();
    // A contiguous mask is exactly `u32::MAX << zeros` (all-ones shifted up).
    if bits == u32::MAX << zeros {
        Some((32 - zeros) as u8)
    } else {
        None
    }
}

/// Guard that removes all routes installed from the route file on drop.
/// Deletion is done synchronously over a raw netlink socket so it works even
/// outside a tokio context (e.g. during shutdown).
pub struct RouteFileGuard {
    routes: Vec<RouteMessage>,
}

impl Drop for RouteFileGuard {
    fn drop(&mut self) {
        if self.routes.is_empty() {
            return;
        }
        let mut sock = match NetlinkSocket::new(NETLINK_ROUTE) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = ?e, "route-file cleanup: failed to open netlink socket");
                return;
            }
        };
        if let Err(e) = sock.bind_auto() {
            tracing::warn!(error = ?e, "route-file cleanup: failed to bind netlink socket");
            return;
        }
        let kernel = NetlinkSocketAddr::new(0, 0);
        let _ = sock.connect(&kernel);

        let mut removed = 0usize;
        for msg in self.routes.drain(..) {
            let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelRoute(msg));
            req.header.flags = NLM_F_REQUEST | NLM_F_ACK;
            let mut buf = vec![0u8; req.buffer_len()];
            req.serialize(&mut buf);
            if sock.send(&buf, 0).is_err() {
                continue;
            }
            // Read the ack/error. We ignore the result: a missing route is
            // expected if it was already removed, and we cannot retry in drop.
            let mut ack = bytes::BytesMut::with_capacity(4096);
            let _ = sock.recv(&mut ack, 0);
            removed += 1;
        }
        tracing::info!(removed, "route-file routes removed on shutdown");
    }
}

/// Read `path` and install a route through `tun_name` for every destination
/// listed in it. Returns a guard that removes all installed routes on drop.
///
/// Errors for individual lines or individual route additions are logged and
/// skipped (the `suppress_route_errors` semantics): a malformed line does not
/// abort the whole file, and a route that cannot be added (e.g. it already
/// exists with different attributes and the kernel refuses the replace) is
/// skipped rather than fatal. The function only returns `Err` if the file
/// itself cannot be read or the TUN interface cannot be resolved.
pub async fn install_route_file(tun_name: &str, path: &Path) -> io::Result<RouteFileGuard> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to read route file {}: {e}", path.display()),
        )
    })?;

    let dests: Vec<RouteDest> = contents.lines().filter_map(parse_route_line).collect();
    let total = dests.len();
    tracing::info!(route_file = %path.display(), entries = total, tun = tun_name, "loading route file");

    // Set up the rtnetlink connection and resolve the TUN interface index.
    let (connection, mut handle, _) = rtnetlink::new_connection().map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("netlink connection failed: {e}"),
        )
    })?;
    tokio::spawn(connection);

    let oif = link_index(&handle, tun_name).await?;

    let mut installed: Vec<RouteMessage> = Vec::with_capacity(dests.len());
    let mut ok = 0usize;
    let mut skipped = 0usize;
    for dest in dests {
        match add_route(&mut handle, oif, dest).await {
            Some(msg) => {
                installed.push(msg);
                ok += 1;
            }
            None => {
                skipped += 1;
            }
        }
    }
    tracing::info!(
        added = ok,
        skipped,
        total,
        tun = tun_name,
        "route file installed"
    );
    Ok(RouteFileGuard { routes: installed })
}

/// Resolve the kernel link index for `name` via netlink.
async fn link_index(handle: &Handle, name: &str) -> io::Result<u32> {
    use futures::TryStreamExt;
    let mut stream = handle.link().get().match_name(name.to_string()).execute();
    match stream.try_next().await {
        Ok(Some(msg)) => Ok(msg.header.index),
        Ok(None) => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("TUN interface {name} not found via netlink"),
        )),
        Err(e) => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("netlink error resolving interface {name}: {e}"),
        )),
    }
}

/// Add a single route via `oif` over netlink. On success returns the
/// `RouteMessage` (so the caller can later delete it); on failure logs and
/// returns `None`.
async fn add_route(handle: &mut Handle, oif: u32, dest: RouteDest) -> Option<RouteMessage> {
    let mut message = RouteMessage::default();
    message.header.table = RouteHeader::RT_TABLE_MAIN;
    message.header.protocol = RouteProtocol::Static;
    message.header.scope = RouteScope::Universe;
    message.header.kind = RouteType::Unicast;
    message.header.destination_prefix_length = dest.prefix;
    match dest.addr {
        std::net::IpAddr::V4(v4) => {
            message.header.address_family = AddressFamily::Inet;
            message
                .attributes
                .push(RouteAttribute::Destination(RouteAddress::Inet(v4)));
        }
        std::net::IpAddr::V6(v6) => {
            message.header.address_family = AddressFamily::Inet6;
            message
                .attributes
                .push(RouteAttribute::Destination(RouteAddress::Inet6(v6)));
        }
    }
    message.attributes.push(RouteAttribute::Oif(oif));

    let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(message.clone()));
    req.header.flags = NLM_F_REQUEST
        | NLM_F_ACK
        | netlink_packet_core::NLM_F_REPLACE
        | netlink_packet_core::NLM_F_CREATE;
    let mut response = match handle.request(req) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = ?e, dest = ?dest, "route-file: failed to send add request");
            return None;
        }
    };
    while let Some(msg) = response.next().await {
        if let NetlinkPayload::Error(e) = msg.payload {
            tracing::warn!(error = %e, dest = ?dest, "route-file: kernel rejected route (skipped)");
            return None;
        }
    }
    Some(message)
}

// ===========================================================================
// Firewall layer: DNS leak prevention + kill switch.
//
// Both features install iptables rules into dedicated chains jumped from
// OUTPUT, so they can be added/removed atomically and inspected in isolation
// (the `dns-check` command reads their live counters). The rule *logic* is
// built as pure [`FirewallOp`] data and applied through a swappable
// [`FirewallBackend`] — production shells out to `iptables`, tests inject an
// in-memory recorder and evaluate the policy with [`evaluate_packet`] without
// root.
// ===========================================================================

/// Firewall address family. Used to dispatch rule appends/deletes to
/// `iptables` (IPv4) or `ip6tables` (IPv6). Chain-level operations
/// (create/flush/delete/jump) are applied to both families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FirewallFamily {
    Ipv4,
    Ipv6,
}

impl Default for FirewallFamily {
    fn default() -> Self {
        FirewallFamily::Ipv4
    }
}

/// One match/target specification for a single iptables rule (the arguments
/// after the chain name). Kept as structured data so tests can build and
/// evaluate the exact policy without parsing argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallRuleSpec {
    /// Which address family this rule targets. `Default` is `Ipv4` for backward
    /// compatibility with existing `RecordedBackend` tests.
    pub family: FirewallFamily,
    /// `-p <proto>` (e.g. "udp", "tcp"). `None` matches any protocol.
    pub proto: Option<String>,
    /// `--dport <port>`. `None` matches any port.
    pub dport: Option<String>,
    /// `-o <iface>` (or `! -o <iface>` when [`Self::neg_out_iface`] is true).
    pub out_iface: Option<String>,
    /// If true, the [`Self::out_iface`] match is negated (`! -o <iface>`).
    pub neg_out_iface: bool,
    /// `-d <ip>`. `None` matches any destination.
    pub dst: Option<String>,
    /// `-j <target>` (e.g. "ACCEPT", "REJECT").
    pub target: String,
}

/// A structured firewall operation (one `iptables` command). Guards build a
/// sequence of these at construction time and apply them through a
/// [`FirewallBackend`]. Being pure data, they can be recorded and replayed by
/// a test backend and fed to [`evaluate_packet`] to verify the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallOp {
    /// `iptables -N <chain>`.
    CreateChain { chain: String },
    /// `iptables -F <chain>`.
    FlushChain { chain: String },
    /// `iptables -X <chain>`.
    DeleteChain { chain: String },
    /// `iptables -A <chain> <spec>`.
    Append {
        chain: String,
        rule: FirewallRuleSpec,
    },
    /// `iptables -D <chain> <spec>`.
    Delete {
        chain: String,
        rule: FirewallRuleSpec,
    },
    /// `iptables -A <from> -j <to>` (jump from one chain into another).
    Jump { from: String, to: String },
    /// `iptables -D <from> -j <to>` (remove a jump).
    Unjump { from: String, to: String },
}

impl FirewallOp {
    /// Render the operation as the argv that follows `iptables` (without the
    /// leading `iptables` itself).
    fn to_argv(&self) -> Vec<String> {
        let mut a = Vec::new();
        match self {
            FirewallOp::CreateChain { chain } => {
                a.push("-N".into());
                a.push(chain.clone());
            }
            FirewallOp::FlushChain { chain } => {
                a.push("-F".into());
                a.push(chain.clone());
            }
            FirewallOp::DeleteChain { chain } => {
                a.push("-X".into());
                a.push(chain.clone());
            }
            FirewallOp::Append { chain, rule } => {
                a.push("-A".into());
                a.push(chain.clone());
                a.extend(spec_argv(rule));
            }
            FirewallOp::Delete { chain, rule } => {
                a.push("-D".into());
                a.push(chain.clone());
                a.extend(spec_argv(rule));
            }
            FirewallOp::Jump { from, to } => {
                a.push("-A".into());
                a.push(from.clone());
                a.push("-j".into());
                a.push(to.clone());
            }
            FirewallOp::Unjump { from, to } => {
                a.push("-D".into());
                a.push(from.clone());
                a.push("-j".into());
                a.push(to.clone());
            }
        }
        a
    }
}

/// Render a [`FirewallRuleSpec`] as the argv appended after the chain name.
fn spec_argv(rule: &FirewallRuleSpec) -> Vec<String> {
    let mut a = Vec::new();
    if let Some(p) = &rule.proto {
        a.push("-p".into());
        a.push(p.clone());
    }
    if let Some(d) = &rule.dport {
        a.push("--dport".into());
        a.push(d.clone());
    }
    if let Some(o) = &rule.out_iface {
        if rule.neg_out_iface {
            a.push("!".into());
        }
        a.push("-o".into());
        a.push(o.clone());
    }
    if let Some(d) = &rule.dst {
        a.push("-d".into());
        a.push(d.clone());
    }
    a.push("-j".into());
    a.push(rule.target.clone());
    a
}

/// Swappable executor for [`FirewallOp`]s. Production uses [`IptablesBackend`];
/// tests inject [`RecordedBackend`] so the policy can be verified without root.
pub trait FirewallBackend: Send + Sync {
    /// Apply one operation. Best-effort callers ignore errors; required
    /// callers (chain creation, rule append, jump) propagate them.
    fn exec(&self, op: &FirewallOp) -> io::Result<()>;
}

/// Production backend: shells out to `iptables` and `ip6tables`. Chain-level
/// operations (create/flush/delete/jump/unjump) are applied to **both** families
/// so chains exist in both tables. Rule appends/deletes are routed to the binary
/// matching `rule.family`.
pub struct IptablesBackend;

impl FirewallBackend for IptablesBackend {
    fn exec(&self, op: &FirewallOp) -> io::Result<()> {
        let argv = op.to_argv();
        let refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        match op {
            // Chain management: apply to both IPv4 and IPv6 so chains exist
            // in both tables for jump rules and rule appends.
            FirewallOp::CreateChain { .. }
            | FirewallOp::FlushChain { .. }
            | FirewallOp::DeleteChain { .. }
            | FirewallOp::Jump { .. }
            | FirewallOp::Unjump { .. } => {
                run("iptables", &refs)?;
                run("ip6tables", &refs)
            }
            FirewallOp::Append { rule, .. } | FirewallOp::Delete { rule, .. } => {
                let bin = match rule.family {
                    FirewallFamily::Ipv4 => "iptables",
                    FirewallFamily::Ipv6 => "ip6tables",
                };
                run(bin, &refs)
            }
        }
    }
}

/// Test backend: records every applied operation in order and never fails.
/// The recorded sequence can be fed to [`evaluate_packet`] to verify the
/// effective policy (and to confirm fail-closed behaviour: a sequence with no
/// teardown ops leaves the blocking rules in place).
pub struct RecordedBackend {
    ops: std::sync::Mutex<Vec<FirewallOp>>,
}

impl RecordedBackend {
    /// Create an empty recorder.
    pub fn new() -> Self {
        Self {
            ops: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// All operations applied so far, in order.
    pub fn ops(&self) -> Vec<FirewallOp> {
        self.ops
            .lock()
            .expect("recorded backend mutex poisoned")
            .clone()
    }
}

impl Default for RecordedBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallBackend for RecordedBackend {
    fn exec(&self, op: &FirewallOp) -> io::Result<()> {
        self.ops
            .lock()
            .expect("recorded backend mutex poisoned")
            .push(op.clone());
        Ok(())
    }
}

/// The decision a modelled firewall rule returns for a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// A rule matched with `-j ACCEPT`.
    Accept,
    /// A rule matched with `-j REJECT` (or DROP).
    Reject,
    /// No rustnies rule matched (fell off the end of the modelled chains).
    Pass,
}

/// Simulate iptables traversal of the rules installed via `ops` for a packet
/// with the given attributes, starting at the OUTPUT chain. Only the chains
/// and jumps created by rustnies are modelled; the kernel's default policy and
/// any pre-existing rules are not (a `Pass` means "no rustnies rule matched").
///
/// This lets tests prove the kill switch and DNS leak prevention actually
/// block what they should — and keep blocking after a tunnel drop (fail
/// closed) — without root or a real `iptables`.
pub fn evaluate_packet(
    ops: &[FirewallOp],
    proto: &str,
    dst: &str,
    dport: u16,
    out_iface: &str,
) -> Decision {
    // Rebuild chain state: per-chain ordered entries (rules and jumps).
    let mut chains: HashMap<String, Vec<Entry>> = HashMap::new();
    for op in ops {
        match op {
            FirewallOp::CreateChain { chain } => {
                chains.entry(chain.clone()).or_default();
            }
            FirewallOp::FlushChain { chain } => {
                if let Some(e) = chains.get_mut(chain) {
                    e.clear();
                }
            }
            FirewallOp::DeleteChain { chain } => {
                chains.remove(chain);
            }
            FirewallOp::Append { chain, rule } => {
                chains
                    .entry(chain.clone())
                    .or_default()
                    .push(Entry::Rule(rule.clone()));
            }
            FirewallOp::Delete { chain, rule } => {
                if let Some(e) = chains.get_mut(chain) {
                    if let Some(pos) = e
                        .iter()
                        .position(|x| matches!(x, Entry::Rule(r) if r == rule))
                    {
                        e.remove(pos);
                    }
                }
            }
            FirewallOp::Jump { from, to } => {
                chains
                    .entry(from.clone())
                    .or_default()
                    .push(Entry::Jump(to.clone()));
            }
            FirewallOp::Unjump { from, to } => {
                if let Some(e) = chains.get_mut(from) {
                    if let Some(pos) = e
                        .iter()
                        .position(|x| matches!(x, Entry::Jump(t) if t == to))
                    {
                        e.remove(pos);
                    }
                }
            }
        }
    }
    let mut visited: Vec<String> = Vec::new();
    traverse(
        "OUTPUT",
        &chains,
        proto,
        dst,
        dport,
        out_iface,
        &mut visited,
    )
}

#[derive(Debug, Clone)]
enum Entry {
    Rule(FirewallRuleSpec),
    Jump(String),
}

fn traverse(
    chain: &str,
    chains: &HashMap<String, Vec<Entry>>,
    proto: &str,
    dst: &str,
    dport: u16,
    out_iface: &str,
    visited: &mut Vec<String>,
) -> Decision {
    if visited.iter().any(|c| c == chain) {
        return Decision::Pass;
    }
    visited.push(chain.to_string());
    let Some(entries) = chains.get(chain) else {
        return Decision::Pass;
    };
    for entry in entries {
        match entry {
            Entry::Rule(rule) => {
                if rule_matches(rule, proto, dst, dport, out_iface) {
                    return match rule.target.as_str() {
                        "ACCEPT" => Decision::Accept,
                        "REJECT" | "DROP" => Decision::Reject,
                        _ => Decision::Pass,
                    };
                }
            }
            Entry::Jump(target) => {
                let d = traverse(target, chains, proto, dst, dport, out_iface, visited);
                if d != Decision::Pass {
                    return d;
                }
            }
        }
    }
    Decision::Pass
}

fn rule_matches(
    rule: &FirewallRuleSpec,
    proto: &str,
    dst: &str,
    dport: u16,
    out_iface: &str,
) -> bool {
    // Family check: only evaluate rules matching the packet's address family.
    // This prevents the IPv4 catch-all REJECT from blocking IPv6 traffic (and
    // vice versa) in the dual-stack ruleset.
    let test_family = dst.parse::<std::net::IpAddr>().ok().map(|ip| match ip {
        std::net::IpAddr::V4(_) => FirewallFamily::Ipv4,
        std::net::IpAddr::V6(_) => FirewallFamily::Ipv6,
    });
    if let Some(f) = test_family {
        if rule.family != f {
            return false;
        }
    }
    if let Some(p) = &rule.proto {
        if p != proto {
            return false;
        }
    }
    if let Some(d) = &rule.dport {
        if d != &dport.to_string() {
            return false;
        }
    }
    if let Some(d) = &rule.dst {
        if d != dst {
            return false;
        }
    }
    if let Some(o) = &rule.out_iface {
        let eq = o == out_iface;
        if rule.neg_out_iface {
            if eq {
                return false;
            }
        } else if !eq {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Kill switch
// ---------------------------------------------------------------------------

/// The iptables chain the kill switch owns.
const KS_CHAIN: &str = "RUSTNIES_KS";

/// Opt-in kill switch: blocks *all* outbound traffic except via the TUN, to
/// the VPN server (the encrypted tunnel UDP), and on loopback. The rules are
/// held for the daemon's lifetime and only removed on a graceful shutdown —
/// so if the tunnel drops, the client cannot fall back to the real internet
/// (fail closed). Construction builds the rule set as pure data; [`install`]
/// applies it through the backend.
pub struct KillSwitch {
    backend: Arc<dyn FirewallBackend>,
    ops: Vec<FirewallOp>,
    active: bool,
}

impl KillSwitch {
    /// Build the kill switch rule set for a given server endpoint and TUN
    /// interface. The rules are not applied until [`Self::install`].
    pub fn new(server: SocketAddr, tun_name: &str, backend: Arc<dyn FirewallBackend>) -> Self {
        let rules = ks_rules(&server, tun_name);
        let ops = install_ops(KS_CHAIN, &rules);
        Self {
            backend,
            ops,
            active: false,
        }
    }

    /// Apply the rules. Idempotent: any pre-existing chain is torn down and
    /// rebuilt. Requires root (via the backend). On failure, any partially
    /// applied rules are cleaned up so no half-installed chain is left behind.
    pub fn install(&mut self) -> io::Result<()> {
        match apply_required(&self.backend, &self.ops) {
            Ok(()) => {
                self.active = true;
                tracing::info!(
                    chain = KS_CHAIN,
                    "kill switch engaged (non-tunnel traffic blocked, fail closed)"
                );
                Ok(())
            }
            Err(e) => {
                apply_best_effort(&self.backend, &remove_ops(KS_CHAIN));
                Err(e)
            }
        }
    }

    /// Remove the rules. Best-effort.
    pub fn remove(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        apply_best_effort(&self.backend, &remove_ops(KS_CHAIN));
        self.active = false;
        tracing::info!(chain = KS_CHAIN, "kill switch disengaged");
        Ok(())
    }

    /// Whether the blocking rules are currently applied.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// The operations that [`install`] applies (for inspection/tests).
    pub fn ops(&self) -> &[FirewallOp] {
        &self.ops
    }
}

impl Drop for KillSwitch {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

/// Build the ordered kill switch rules: allow loopback, allow the TUN, allow
/// the encrypted tunnel UDP to the server, then reject everything else.
///
/// The common rules (allow lo, allow TUN, reject all) are generated for **both**
/// IPv4 and IPv6 — the kill switch must fail closed on both stacks. The server
/// allow rule is family-specific (its `-d` is the server's IP), so it is only
/// generated for the family matching `server.ip()`.
fn ks_rules(server: &SocketAddr, tun_name: &str) -> Vec<FirewallRuleSpec> {
    let server_family = match server.ip() {
        std::net::IpAddr::V4(_) => FirewallFamily::Ipv4,
        std::net::IpAddr::V6(_) => FirewallFamily::Ipv6,
    };
    let mut rules = Vec::new();
    for family in [FirewallFamily::Ipv4, FirewallFamily::Ipv6] {
        rules.push(FirewallRuleSpec {
            family,
            proto: None,
            dport: None,
            out_iface: Some("lo".into()),
            neg_out_iface: false,
            dst: None,
            target: "ACCEPT".into(),
        });
        rules.push(FirewallRuleSpec {
            family,
            proto: None,
            dport: None,
            out_iface: Some(tun_name.into()),
            neg_out_iface: false,
            dst: None,
            target: "ACCEPT".into(),
        });
        // The server-allow rule only makes sense for the family matching the
        // server's address — iptables cannot parse an IPv6 -d and vice versa.
        if family == server_family {
            rules.push(FirewallRuleSpec {
                family,
                proto: Some("udp".into()),
                dport: Some(server.port().to_string()),
                out_iface: None,
                neg_out_iface: false,
                dst: Some(server.ip().to_string()),
                target: "ACCEPT".into(),
            });
        }
        // Catch-all: reject everything else (fail closed).
        rules.push(FirewallRuleSpec {
            family,
            proto: None,
            dport: None,
            out_iface: None,
            neg_out_iface: false,
            dst: None,
            target: "REJECT".into(),
        });
    }
    rules
}

// ---------------------------------------------------------------------------
// DNS leak prevention (firewall half)
// ---------------------------------------------------------------------------

/// The iptables chain DNS leak prevention owns.
const DNS_CHAIN: &str = "RUSTNIES_DNS";

/// Firewall rules that block DNS (port 53 UDP/TCP) from leaving via any
/// interface other than the TUN, while allowing DNS via the TUN. Active when
/// route-all is on (the TUN carries the default route, so public resolvers are
/// reachable through the tunnel). The companion [`ResolvConfGuard`] points
/// `/etc/resolv.conf` at a tunnel-reachable resolver so name resolution
/// actually works through the tunnel.
pub struct DnsLeakGuard {
    backend: Arc<dyn FirewallBackend>,
    ops: Vec<FirewallOp>,
    active: bool,
}

impl DnsLeakGuard {
    /// Build the DNS leak block rules for a given TUN interface.
    pub fn new(tun_name: &str, backend: Arc<dyn FirewallBackend>) -> Self {
        let rules = dns_rules(tun_name);
        let ops = install_ops(DNS_CHAIN, &rules);
        Self {
            backend,
            ops,
            active: false,
        }
    }

    /// Apply the rules (idempotent). Requires root (via the backend). On failure,
    /// any partially applied rules are cleaned up.
    pub fn install(&mut self) -> io::Result<()> {
        match apply_required(&self.backend, &self.ops) {
            Ok(()) => {
                self.active = true;
                tracing::info!(
                    chain = DNS_CHAIN,
                    "DNS leak prevention engaged (port 53 blocked except via TUN)"
                );
                Ok(())
            }
            Err(e) => {
                apply_best_effort(&self.backend, &remove_ops(DNS_CHAIN));
                Err(e)
            }
        }
    }

    /// Remove the rules. Best-effort.
    pub fn remove(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        apply_best_effort(&self.backend, &remove_ops(DNS_CHAIN));
        self.active = false;
        tracing::info!(chain = DNS_CHAIN, "DNS leak prevention disengaged");
        Ok(())
    }

    /// Whether the blocking rules are currently applied.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Drop for DnsLeakGuard {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

/// Build the ordered DNS leak rules: allow DNS via the TUN (UDP+TCP), then
/// reject DNS via any non-TUN interface (UDP+TCP).
///
/// Rules are generated for **both** IPv4 and IPv6 since DNS resolution can
/// target either stack and must not leak outside the tunnel.
fn dns_rules(tun_name: &str) -> Vec<FirewallRuleSpec> {
    let mut rules = Vec::new();
    for family in [FirewallFamily::Ipv4, FirewallFamily::Ipv6] {
        rules.push(FirewallRuleSpec {
            family,
            proto: Some("udp".into()),
            dport: Some("53".into()),
            out_iface: Some(tun_name.into()),
            neg_out_iface: false,
            dst: None,
            target: "ACCEPT".into(),
        });
        rules.push(FirewallRuleSpec {
            family,
            proto: Some("tcp".into()),
            dport: Some("53".into()),
            out_iface: Some(tun_name.into()),
            neg_out_iface: false,
            dst: None,
            target: "ACCEPT".into(),
        });
        rules.push(FirewallRuleSpec {
            family,
            proto: Some("udp".into()),
            dport: Some("53".into()),
            out_iface: Some(tun_name.into()),
            neg_out_iface: true,
            dst: None,
            target: "REJECT".into(),
        });
        rules.push(FirewallRuleSpec {
            family,
            proto: Some("tcp".into()),
            dport: Some("53".into()),
            out_iface: Some(tun_name.into()),
            neg_out_iface: true,
            dst: None,
            target: "REJECT".into(),
        });
    }
    rules
}

// ---------------------------------------------------------------------------
// Guard install/remove op sequences (shared by kill switch + DNS leak guard)
// ---------------------------------------------------------------------------

/// Build the idempotent install sequence for a chain: tear down any stale
/// chain (best-effort), recreate it, append the rules, then jump from OUTPUT.
fn install_ops(chain: &str, rules: &[FirewallRuleSpec]) -> Vec<FirewallOp> {
    let mut ops = Vec::new();
    // Best-effort cleanup of a stale chain from a previous/crashed run.
    ops.push(FirewallOp::Unjump {
        from: "OUTPUT".into(),
        to: chain.into(),
    });
    ops.push(FirewallOp::FlushChain {
        chain: chain.into(),
    });
    ops.push(FirewallOp::DeleteChain {
        chain: chain.into(),
    });
    // Fresh chain + rules + jump.
    ops.push(FirewallOp::CreateChain {
        chain: chain.into(),
    });
    for rule in rules {
        ops.push(FirewallOp::Append {
            chain: chain.into(),
            rule: rule.clone(),
        });
    }
    ops.push(FirewallOp::Jump {
        from: "OUTPUT".into(),
        to: chain.into(),
    });
    ops
}

/// Build the teardown sequence for a chain: remove the OUTPUT jump, flush, and
/// delete the chain.
fn remove_ops(chain: &str) -> Vec<FirewallOp> {
    vec![
        FirewallOp::Unjump {
            from: "OUTPUT".into(),
            to: chain.into(),
        },
        FirewallOp::FlushChain {
            chain: chain.into(),
        },
        FirewallOp::DeleteChain {
            chain: chain.into(),
        },
    ]
}

/// Apply a sequence of ops, tolerating the best-effort cleanup ops at the
/// start (the first three: unjump/flush/delete) but propagating errors from
/// the required ops (create/append/jump).
fn apply_required(backend: &Arc<dyn FirewallBackend>, ops: &[FirewallOp]) -> io::Result<()> {
    for (i, op) in ops.iter().enumerate() {
        // The first three ops (unjump, flush, delete) are best-effort: a
        // missing chain is normal on a fresh install.
        if i < 3 {
            if let Err(e) = backend.exec(op) {
                tracing::debug!(error = ?e, op = ?op, "firewall best-effort op failed (ignored)");
            }
        } else {
            backend.exec(op)?;
        }
    }
    Ok(())
}

/// Apply a sequence of ops, ignoring all errors (teardown is best-effort).
fn apply_best_effort(backend: &Arc<dyn FirewallBackend>, ops: &[FirewallOp]) {
    for op in ops {
        if let Err(e) = backend.exec(op) {
            tracing::debug!(error = ?e, op = ?op, "firewall teardown op failed (ignored)");
        }
    }
}

// ---------------------------------------------------------------------------
// resolv.conf swap (DNS leak prevention, resolver half)
// ---------------------------------------------------------------------------

/// Swaps `/etc/resolv.conf` to point at resolver IPs reachable through the
/// tunnel while DNS leak prevention is active, and restores the original on
/// drop. Robust to crashes: the original is backed up to a sidecar file; if a
/// stale backup already exists on install (a previous run crashed before
/// restoring), it is preserved (not overwritten) so the real original is never
/// lost. Paths are parameterised so the swap can be exercised in tests with
/// temp files and no root.
pub struct ResolvConfGuard {
    resolv_path: PathBuf,
    backup_path: PathBuf,
    installed: bool,
}

impl ResolvConfGuard {
    /// Create the guard for `resolv_path` (default `/etc/resolv.conf`) with
    /// the original backed up to `backup_path` (default
    /// `/etc/resolv.conf.rustnies.bak`). The swap is not applied until
    /// [`Self::install`].
    pub fn new(resolv_path: impl Into<PathBuf>, backup_path: impl Into<PathBuf>) -> Self {
        Self {
            resolv_path: resolv_path.into(),
            backup_path: backup_path.into(),
            installed: false,
        }
    }

    /// Back up the current `resolv.conf` (unless a stale backup already
    /// exists) and rewrite it to list `dns_servers`. `dns_servers` must be
    /// non-empty; the caller resolves the built-in default before
    /// constructing the guard.
    pub fn install(&mut self, dns_servers: &[String]) -> io::Result<()> {
        if dns_servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one DNS server is required for the resolv.conf swap",
            ));
        }
        // If a backup already exists, a previous run crashed before restoring:
        // keep it (it holds the real original) and just rewrite resolv.conf.
        if !self.backup_path.exists() {
            // Back up the current resolv.conf. If it is absent, back up an
            // empty file so the restore writes back an empty resolv.conf
            // (rather than failing to read).
            let current = std::fs::read(&self.resolv_path).unwrap_or_default();
            std::fs::write(&self.backup_path, &current)?;
            tracing::info!(
                resolv = %self.resolv_path.display(),
                backup = %self.backup_path.display(),
                "backed up original resolv.conf",
            );
        } else {
            tracing::warn!(
                backup = %self.backup_path.display(),
                "stale resolv.conf backup found; keeping it (previous run did not restore)",
            );
        }

        let mut body = String::from(
            "# Managed by rustnies VPN — DNS routed through the tunnel.\n\
             # Original backed up at the .rustnies.bak sidecar; restored on shutdown.\n",
        );
        for ns in dns_servers {
            body.push_str("nameserver ");
            body.push_str(ns);
            body.push('\n');
        }
        std::fs::write(&self.resolv_path, body)?;
        self.installed = true;
        tracing::info!(resolv = %self.resolv_path.display(), servers = ?dns_servers, "resolv.conf rewritten to tunnel DNS");
        Ok(())
    }

    /// Restore the original `resolv.conf` from the backup (if any).
    pub fn remove(&mut self) -> io::Result<()> {
        if !self.installed {
            return Ok(());
        }
        if self.backup_path.exists() {
            // Restore by copy so it works across same-filesystem paths and
            // leaves the backup removal explicit.
            let original = std::fs::read(&self.backup_path)?;
            std::fs::write(&self.resolv_path, original)?;
            let _ = std::fs::remove_file(&self.backup_path);
            tracing::info!(resolv = %self.resolv_path.display(), "restored original resolv.conf");
        } else {
            tracing::warn!(resolv = %self.resolv_path.display(), "no resolv.conf backup to restore; leaving current");
        }
        self.installed = false;
        Ok(())
    }
}

impl Drop for ResolvConfGuard {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

// ---------------------------------------------------------------------------
// dns-check: verify DNS only reaches a resolver via the tunnel
// ---------------------------------------------------------------------------

/// One parsed rule row from `iptables -L <chain> -v -n -x`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleCount {
    pkts: u64,
    target: String,
    out_iface: String,
    dport: Option<u16>,
}

/// Verify DNS leak prevention by inspecting the live firewall counters and,
/// optionally, performing a real resolution to show it goes through the
/// tunnel. Prints a human-readable report and returns Ok on success (even if
/// the lookup fails — a failed lookup is reported, not a hard error, so the
/// command is useful when the tunnel is down).
pub async fn dns_check(resolv_path: &Path, tun_name: &str, host: &str) -> io::Result<()> {
    println!("rustnies DNS leak check");
    println!("------------------------");

    // Active resolv.conf nameservers.
    match std::fs::read_to_string(resolv_path) {
        Ok(content) => {
            let ns: Vec<&str> = content
                .lines()
                .filter_map(|l| {
                    let l = l.trim();
                    l.strip_prefix("nameserver ").map(str::trim)
                })
                .collect();
            println!(
                "resolv.conf: {}",
                if ns.is_empty() {
                    "(none)".into()
                } else {
                    ns.join(", ")
                }
            );
        }
        Err(e) => println!("resolv.conf: unreadable ({e})"),
    }

    // Snapshot the firewall counters.
    let before = snapshot_dns_counters(tun_name);
    print_counters("before lookup", &before, tun_name);

    // Live lookup via the system resolver (uses the rewritten resolv.conf).
    let lookup_ok = match tokio::net::lookup_host((host, 0)).await {
        Ok(addrs) => {
            let first = addrs.into_iter().next();
            println!(
                "lookup: {} -> {}",
                host,
                first
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "no answer".into())
            );
            true
        }
        Err(e) => {
            println!("lookup: {} failed ({e})", host);
            false
        }
    };

    let after = snapshot_dns_counters(tun_name);
    print_counters("after lookup", &after, tun_name);

    let via_tunnel_delta = after.via_tunnel.saturating_sub(before.via_tunnel);
    let blocked_delta = after.blocked.saturating_sub(before.blocked);
    println!("delta: via tunnel +{via_tunnel_delta} pkts, blocked +{blocked_delta} pkts");

    if lookup_ok && blocked_delta == 0 {
        println!("verdict: no DNS leak detected (queries reached a resolver only via the tunnel)");
    } else if blocked_delta > 0 {
        println!(
            "verdict: DNS leak attempt blocked {blocked_delta} time(s) — queries were kept off the real interface"
        );
    } else {
        println!(
            "verdict: lookup did not complete; check that the tunnel is up and the resolver is reachable through it"
        );
    }
    Ok(())
}

/// Aggregated DNS-relevant firewall counters.
#[derive(Debug, Default, Clone, Copy)]
struct DnsCounters {
    /// DNS packets allowed via the TUN (or, under a kill switch, packets
    /// accepted out the TUN interface).
    via_tunnel: u64,
    /// DNS packets blocked on a non-TUN interface (or, under a kill switch,
    /// non-tunnel packets rejected).
    blocked: u64,
}

/// Read the live counters from the DNS leak chain (if present) and fall back
/// to the kill switch chain. Returns zeros if neither chain exists (e.g. the
/// daemon is not running or these features are off).
fn snapshot_dns_counters(tun_name: &str) -> DnsCounters {
    // Prefer the dedicated DNS chain: it separates DNS via tunnel from DNS
    // blocked with per-rule counters.
    if let Some(rows) = list_chain(DNS_CHAIN) {
        let mut c = DnsCounters::default();
        for r in &rows {
            let is_dns = r.dport == Some(53);
            if is_dns && r.target == "ACCEPT" {
                c.via_tunnel = c.via_tunnel.saturating_add(r.pkts);
            } else if is_dns && (r.target == "REJECT" || r.target == "DROP") {
                c.blocked = c.blocked.saturating_add(r.pkts);
            }
        }
        return c;
    }
    // Fall back to the kill switch chain: DNS is not separable, so report
    // TUN-accepted vs. rejected totals.
    if let Some(rows) = list_chain(KS_CHAIN) {
        let mut c = DnsCounters::default();
        for r in &rows {
            if r.target == "ACCEPT" && r.out_iface == tun_name {
                c.via_tunnel = c.via_tunnel.saturating_add(r.pkts);
            } else if r.target == "REJECT" || r.target == "DROP" {
                c.blocked = c.blocked.saturating_add(r.pkts);
            }
        }
        return c;
    }
    DnsCounters::default()
}

fn print_counters(label: &str, c: &DnsCounters, _tun: &str) {
    println!(
        "{label}: via tunnel {} pkts, blocked {} pkts",
        c.via_tunnel, c.blocked
    );
}

/// Run `iptables -L <chain> -v -n -x` and parse the rule rows. Returns `None`
/// if the chain does not exist (iptables exits non-zero).
fn list_chain(chain: &str) -> Option<Vec<RuleCount>> {
    let out = Command::new("iptables")
        .args(["-L", chain, "-v", "-n", "-x"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Some(parse_iptables_chain(&text))
}

/// Parse the output of `iptables -L <chain> -v -n -x` into rule rows.
/// Extracted for unit testing the parsing without running iptables.
fn parse_iptables_chain(output: &str) -> Vec<RuleCount> {
    let mut rows = Vec::new();
    for line in output.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 {
            continue;
        }
        // Rule lines start with a numeric packet count; header/chain lines do not.
        let Ok(pkts) = f[0].parse::<u64>() else {
            continue;
        };
        let target = f[2];
        // Columns: pkts bytes target prot opt in out source destination ...
        let out_iface = if f.len() > 6 { f[6] } else { "*" };
        let dport = extract_dport(line);
        rows.push(RuleCount {
            pkts,
            target: target.to_string(),
            out_iface: out_iface.to_string(),
            dport,
        });
    }
    rows
}

/// Extract the destination port from a rule line containing `dpt:N`.
fn extract_dport(line: &str) -> Option<u16> {
    let key = "dpt:";
    let idx = line.find(key)?;
    let rest = &line[idx + key.len()..];
    let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse::<u16>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_route_iface_extracts_dev() {
        let output = "default via 192.168.1.1 dev eth0 proto static\n";
        assert_eq!(parse_default_route_iface(output).unwrap(), "eth0");
    }

    #[test]
    fn parse_default_route_iface_handles_extra_fields() {
        let output = "default via 10.0.0.1 dev wlan0 metric 100 proto dhcp\n";
        assert_eq!(parse_default_route_iface(output).unwrap(), "wlan0");
    }

    #[test]
    fn parse_default_route_iface_errors_when_no_dev() {
        let output = "default via 192.168.1.1\n";
        assert!(parse_default_route_iface(output).is_err());
    }

    #[test]
    fn parse_default_gateway_extracts_via() {
        let output = "default via 192.168.1.1 dev eth0 proto static\n";
        assert_eq!(parse_default_gateway(output).unwrap(), "192.168.1.1");
    }

    #[test]
    fn parse_default_gateway_handles_extra_fields() {
        let output = "default via 10.0.0.1 dev wlan0 metric 100\n";
        assert_eq!(parse_default_gateway(output).unwrap(), "10.0.0.1");
    }

    #[test]
    fn parse_default_gateway_errors_when_no_via() {
        let output = "default dev eth0\n";
        assert!(parse_default_gateway(output).is_err());
    }

    /// Verify that install_route_all fails gracefully when not running as root.
    /// On a typical test host we don't have permission to add routes, so this
    /// confirms the error is propagated rather than panicking. If we *are*
    /// root (CI with privileges), the routes are installed and the guard
    /// cleans them up on drop — either outcome is acceptable.
    #[test]
    fn install_route_all_handles_lack_of_permissions() {
        let server: std::net::SocketAddr = "1.2.3.4:51820".parse().unwrap();
        // This will fail at default_gateway/default_route_iface if there's no
        // default route, or at the `ip route add` if not root. Either way it
        // should return an Err, not panic.
        match install_route_all(&server, "rustnies_test") {
            Ok(_guard) => {
                // We're root and routes were installed; the guard cleans up
                // on drop. Nothing more to assert.
            }
            Err(e) => {
                // Expected when not root: the error is propagated cleanly.
                assert!(!e.to_string().is_empty(), "error should have a message");
            }
        }
    }

    #[test]
    fn parse_route_line_bare_ipv4() {
        let d = parse_route_line("8.8.8.8").unwrap();
        assert_eq!(d.addr, std::net::IpAddr::V4("8.8.8.8".parse().unwrap()));
        assert_eq!(d.prefix, 32);
    }

    #[test]
    fn parse_route_line_ipv4_cidr() {
        let d = parse_route_line("10.0.0.0/8").unwrap();
        assert_eq!(d.addr, std::net::IpAddr::V4("10.0.0.0".parse().unwrap()));
        assert_eq!(d.prefix, 8);
    }

    #[test]
    fn parse_route_line_trims_trailing_whitespace() {
        // The brownies config has entries like "route 66.111.48.0/22 " with
        // trailing spaces; after stripping the "route " prefix the remainder
        // still needs trimming.
        let d = parse_route_line("66.111.48.0/22 ").unwrap();
        assert_eq!(d.prefix, 22);
    }

    #[test]
    fn parse_route_line_legacy_ip_mask_form() {
        // Legacy "178.66.83.0 255.255.255.0" form (seen commented out in the
        // brownies config) is converted to a /24.
        let d = parse_route_line("178.66.83.0 255.255.255.0").unwrap();
        assert_eq!(d.addr, std::net::IpAddr::V4("178.66.83.0".parse().unwrap()));
        assert_eq!(d.prefix, 24);
    }

    #[test]
    fn parse_route_line_ipv6() {
        let d = parse_route_line("2001:db8::/32").unwrap();
        assert_eq!(d.addr, std::net::IpAddr::V6("2001:db8::".parse().unwrap()));
        assert_eq!(d.prefix, 32);
    }

    #[test]
    fn parse_default_gateway_v6_with_via() {
        let out = "default via fe80::1 dev eth0 proto ra metric 100\n";
        assert_eq!(parse_default_gateway_v6(out).unwrap(), "fe80::1");
    }

    #[test]
    fn parse_default_gateway_v6_onlink() {
        let out = "default dev eth0 proto ra metric 100\n";
        // On-link default with no `via`: falls back to `src` if present.
        let out_with_src = "default dev eth0 proto ra metric 100 src 2001:db8::42\n";
        assert_eq!(
            parse_default_gateway_v6(out_with_src).unwrap(),
            "2001:db8::42"
        );
        // No src either — should error.
        assert!(parse_default_gateway_v6(out).is_err());
    }

    #[test]
    fn parse_route_line_ignores_comments_and_blanks() {
        assert!(parse_route_line("# a comment").is_none());
        assert!(parse_route_line("").is_none());
        assert!(parse_route_line("   ").is_none());
    }

    #[test]
    fn parse_route_line_rejects_garbage() {
        assert!(parse_route_line("not an ip").is_none());
    }

    #[test]
    fn netmask_to_prefix_contiguous() {
        assert_eq!(
            netmask_to_prefix("255.255.255.0".parse().unwrap()),
            Some(24)
        );
        assert_eq!(netmask_to_prefix("255.255.0.0".parse().unwrap()), Some(16));
        assert_eq!(netmask_to_prefix("255.0.0.0".parse().unwrap()), Some(8));
        assert_eq!(netmask_to_prefix("0.0.0.0".parse().unwrap()), Some(0));
        assert_eq!(
            netmask_to_prefix("255.255.255.255".parse().unwrap()),
            Some(32)
        );
    }

    #[test]
    fn netmask_to_prefix_rejects_non_contiguous() {
        // 255.0.255.0 is not a valid contiguous netmask.
        assert_eq!(netmask_to_prefix("255.0.255.0".parse().unwrap()), None);
    }

    /// `install_route_file` should fail cleanly (not panic) when the path does
    /// not exist, regardless of privileges.
    #[tokio::test]
    async fn install_route_file_missing_path_errors() {
        let path = std::path::PathBuf::from("/nonexistent/rustnies-route-file-test.txt");
        match install_route_file("rustnies_test", &path).await {
            Ok(_guard) => {
                // Should not happen for a missing path, but if we are root and
                // somehow the file exists, nothing to assert.
            }
            Err(e) => {
                assert!(!e.to_string().is_empty(), "error should have a message");
            }
        }
    }

    // ----------------------- firewall layer tests -----------------------

    #[test]
    fn kill_switch_rules_block_all_except_tunnel_server_lo() {
        let server: SocketAddr = "1.2.3.4:51820".parse().unwrap();
        let backend = Arc::new(RecordedBackend::new());
        let mut ks = KillSwitch::new(server, "rustnies0", backend.clone());
        ks.install().unwrap();

        let ops = backend.ops();
        // Loopback always allowed.
        assert_eq!(
            evaluate_packet(&ops, "tcp", "127.0.0.1", 0, "lo"),
            Decision::Accept
        );
        // TUN traffic always allowed (any port/proto).
        assert_eq!(
            evaluate_packet(&ops, "tcp", "93.184.216.34", 443, "rustnies0"),
            Decision::Accept
        );
        assert_eq!(
            evaluate_packet(&ops, "udp", "8.8.8.8", 53, "rustnies0"),
            Decision::Accept
        );
        // Encrypted tunnel UDP to the server is allowed via the real interface.
        assert_eq!(
            evaluate_packet(&ops, "udp", "1.2.3.4", 51820, "eth0"),
            Decision::Accept
        );
        // Direct internet via the real interface is blocked (the whole point).
        assert_eq!(
            evaluate_packet(&ops, "tcp", "93.184.216.34", 443, "eth0"),
            Decision::Reject
        );
        // DNS via the real interface is also blocked by the catch-all.
        assert_eq!(
            evaluate_packet(&ops, "udp", "192.168.1.1", 53, "eth0"),
            Decision::Reject
        );
        // Non-tunnel UDP to the server's *port* but wrong dest is blocked.
        assert_eq!(
            evaluate_packet(&ops, "udp", "5.6.7.8", 51820, "eth0"),
            Decision::Reject
        );
    }

    #[test]
    fn kill_switch_fail_closed_stays_active_without_remove() {
        // Simulate a tunnel drop: the guard is installed, then the session
        // dies but the guard is NOT removed (fail closed). The blocking rules
        // must remain in place.
        let server: SocketAddr = "10.0.0.1:51820".parse().unwrap();
        let backend = Arc::new(RecordedBackend::new());
        let mut ks = KillSwitch::new(server, "tun0", backend.clone());
        ks.install().unwrap();
        assert!(ks.is_active());

        // "tunnel drops" — do nothing to the kill switch.
        let ops = backend.ops();
        assert_eq!(
            evaluate_packet(&ops, "tcp", "1.1.1.1", 443, "eth0"),
            Decision::Reject,
            "direct internet must stay blocked after a drop (fail closed)"
        );
        assert_eq!(
            evaluate_packet(&ops, "udp", "10.0.0.1", 51820, "eth0"),
            Decision::Accept,
            "server must stay reachable so the tunnel can be re-established"
        );

        // Graceful shutdown: remove restores direct internet.
        ks.remove().unwrap();
        assert!(!ks.is_active());
        let ops = backend.ops();
        assert_eq!(
            evaluate_packet(&ops, "tcp", "1.1.1.1", 443, "eth0"),
            Decision::Pass,
            "after shutdown, no rustnies rule matches (direct internet restored)"
        );
    }

    #[test]
    fn dns_leak_rules_allow_tun_block_real() {
        let backend = Arc::new(RecordedBackend::new());
        let mut g = DnsLeakGuard::new("rustnies0", backend.clone());
        g.install().unwrap();
        let ops = backend.ops();

        // DNS via the TUN is allowed (UDP and TCP).
        assert_eq!(
            evaluate_packet(&ops, "udp", "8.8.8.8", 53, "rustnies0"),
            Decision::Accept
        );
        assert_eq!(
            evaluate_packet(&ops, "tcp", "8.8.8.8", 53, "rustnies0"),
            Decision::Accept
        );
        // DNS via the real interface is blocked (the leak prevention).
        assert_eq!(
            evaluate_packet(&ops, "udp", "192.168.1.1", 53, "eth0"),
            Decision::Reject
        );
        assert_eq!(
            evaluate_packet(&ops, "tcp", "192.168.1.1", 53, "eth0"),
            Decision::Reject
        );
        // Non-DNS traffic is not touched by the DNS chain (passes through).
        assert_eq!(
            evaluate_packet(&ops, "tcp", "93.184.216.34", 443, "eth0"),
            Decision::Pass
        );
        assert_eq!(
            evaluate_packet(&ops, "udp", "1.2.3.4", 51820, "eth0"),
            Decision::Pass
        );
        // Non-53 traffic via the TUN also passes (the DNS chain only matches dpt:53).
        assert_eq!(
            evaluate_packet(&ops, "tcp", "9.9.9.9", 443, "rustnies0"),
            Decision::Pass
        );
    }

    #[test]
    fn dns_and_kill_switch_chains_compose_in_order() {
        // DNS leak prevention is installed before the kill switch, so the DNS
        // chain is jumped from OUTPUT first: DNS is handled by RUSTNIES_DNS
        // (per-DNS counters), everything else by RUSTNIES_KS.
        let server: SocketAddr = "1.2.3.4:51820".parse().unwrap();
        let backend = Arc::new(RecordedBackend::new());
        let mut dns = DnsLeakGuard::new("rustnies0", backend.clone());
        dns.install().unwrap();
        let mut ks = KillSwitch::new(server, "rustnies0", backend.clone());
        ks.install().unwrap();
        let ops = backend.ops();

        // DNS via TUN -> accepted by the DNS chain (not the kill switch).
        assert_eq!(
            evaluate_packet(&ops, "udp", "8.8.8.8", 53, "rustnies0"),
            Decision::Accept
        );
        // DNS via real -> rejected by the DNS chain.
        assert_eq!(
            evaluate_packet(&ops, "udp", "192.168.1.1", 53, "eth0"),
            Decision::Reject
        );
        // Non-DNS via TUN -> passes DNS chain, accepted by kill switch.
        assert_eq!(
            evaluate_packet(&ops, "tcp", "93.184.216.34", 443, "rustnies0"),
            Decision::Accept
        );
        // Non-DNS via real -> passes DNS chain, rejected by kill switch.
        assert_eq!(
            evaluate_packet(&ops, "tcp", "93.184.216.34", 443, "eth0"),
            Decision::Reject
        );
        // Server UDP -> passes DNS chain, accepted by kill switch.
        assert_eq!(
            evaluate_packet(&ops, "udp", "1.2.3.4", 51820, "eth0"),
            Decision::Accept
        );
    }

    #[test]
    fn kill_switch_install_is_idempotent() {
        // Installing twice without removing (e.g. after a crash/restart) must
        // not leave duplicate jumps/rules: the cleanup ops tear down the stale
        // chain first. Prove this by installing twice, then removing once — a
        // single remove must fully clear the chain (if a duplicate jump had
        // survived, one remove would leave the other behind, still blocking).
        let server: SocketAddr = "1.2.3.4:51820".parse().unwrap();
        let backend = Arc::new(RecordedBackend::new());
        let mut ks = KillSwitch::new(server, "tun0", backend.clone());
        ks.install().unwrap();
        ks.install().unwrap();
        let ops = backend.ops();
        assert_eq!(
            evaluate_packet(&ops, "tcp", "1.1.1.1", 443, "eth0"),
            Decision::Reject,
            "still blocking after double install"
        );
        ks.remove().unwrap();
        let ops = backend.ops();
        assert_eq!(
            evaluate_packet(&ops, "tcp", "1.1.1.1", 443, "eth0"),
            Decision::Pass,
            "a single remove must clear all (no duplicate jumps survived)"
        );
    }

    #[test]
    fn kill_switch_blocks_ipv6_traffic() {
        // When the server is IPv4, IPv6 kill-switch rules should still reject
        // all non-TUN, non-loopback IPv6 traffic.
        let server: SocketAddr = "1.2.3.4:51820".parse().unwrap();
        let backend = Arc::new(RecordedBackend::new());
        let mut ks = KillSwitch::new(server, "tun0", backend.clone());
        ks.install().unwrap();
        let ops = backend.ops();

        // IPv6 loopback always allowed.
        assert_eq!(
            evaluate_packet(&ops, "tcp", "::1", 443, "lo"),
            Decision::Accept,
        );
        // IPv6 traffic via the TUN is allowed.
        assert_eq!(
            evaluate_packet(&ops, "tcp", "2001:db8::1", 443, "tun0"),
            Decision::Accept,
        );
        // IPv6 direct internet is blocked (fail closed on IPv6 too).
        assert_eq!(
            evaluate_packet(&ops, "tcp", "2606:4700:4700::1111", 443, "eth0"),
            Decision::Reject,
        );
        // IPv6 DNS via real interface is also blocked.
        assert_eq!(
            evaluate_packet(&ops, "udp", "2001:4860:4860::8888", 53, "eth0"),
            Decision::Reject,
        );
    }

    #[test]
    fn kill_switch_ipv6_server_allows_v6_server_traffic() {
        // When the server is IPv6, the server-allow rule must be in the IPv6
        // ruleset and accept UDP to that server.
        let server: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
        let backend = Arc::new(RecordedBackend::new());
        let mut ks = KillSwitch::new(server, "tun0", backend.clone());
        ks.install().unwrap();
        let ops = backend.ops();

        // Encrypted UDP tunnel to the IPv6 server is allowed via the real iface.
        assert_eq!(
            evaluate_packet(&ops, "udp", "2001:db8::1", 51820, "eth0"),
            Decision::Accept,
        );
        // IPv6 direct internet is still blocked.
        assert_eq!(
            evaluate_packet(&ops, "tcp", "2606:4700:4700::1111", 443, "eth0"),
            Decision::Reject,
        );
    }

    #[test]
    fn dns_leak_rules_block_ipv6_dns() {
        let backend = Arc::new(RecordedBackend::new());
        let mut g = DnsLeakGuard::new("tun0", backend.clone());
        g.install().unwrap();
        let ops = backend.ops();

        // IPv6 DNS via TUN is allowed.
        assert_eq!(
            evaluate_packet(&ops, "udp", "2001:4860:4860::8888", 53, "tun0"),
            Decision::Accept,
        );
        assert_eq!(
            evaluate_packet(&ops, "tcp", "2001:4860:4860::8888", 53, "tun0"),
            Decision::Accept,
        );
        // IPv6 DNS via real interface is blocked.
        assert_eq!(
            evaluate_packet(&ops, "udp", "2001:4860:4860::8888", 53, "eth0"),
            Decision::Reject,
        );
        assert_eq!(
            evaluate_packet(&ops, "tcp", "2001:4860:4860::8888", 53, "eth0"),
            Decision::Reject,
        );
        // IPv6 non-DNS traffic passes the DNS chain.
        assert_eq!(
            evaluate_packet(&ops, "tcp", "2001:db8::1", 443, "eth0"),
            Decision::Pass,
        );
    }

    #[test]
    fn ks_rules_generates_both_ipv4_and_ipv6_families() {
        let server: SocketAddr = "1.2.3.4:51820".parse().unwrap();
        let rules = ks_rules(&server, "tun0");
        let v4_count = rules
            .iter()
            .filter(|r| r.family == FirewallFamily::Ipv4)
            .count();
        let v6_count = rules
            .iter()
            .filter(|r| r.family == FirewallFamily::Ipv6)
            .count();
        assert!(v4_count > 0, "should have IPv4 rules");
        assert!(v6_count > 0, "should have IPv6 rules");
        // The server-allow rule should appear exactly once (IPv4 only, since
        // the server address is IPv4).
        let server_allow = rules
            .iter()
            .filter(|r| r.proto == Some("udp".into()) && r.dport == Some("51820".to_string()));
        assert_eq!(server_allow.count(), 1);
    }

    #[test]
    fn ks_rules_ipv6_server_generates_v6_server_rule() {
        let server: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
        let rules = ks_rules(&server, "tun0");
        // The server-allow rule should appear only in IPv6.
        let server_allow_v4 = rules.iter().filter(|r| {
            r.family == FirewallFamily::Ipv4
                && r.proto == Some("udp".into())
                && r.dport == Some("51820".to_string())
        });
        assert_eq!(server_allow_v4.count(), 0);
        let server_allow_v6 = rules.iter().filter(|r| {
            r.family == FirewallFamily::Ipv6
                && r.proto == Some("udp".into())
                && r.dport == Some("51820".to_string())
        });
        assert_eq!(server_allow_v6.count(), 1);
    }

    #[test]
    fn resolv_conf_swap_backs_up_and_restores() {
        let dir = std::env::temp_dir().join(format!("rustnies-resolv-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let resolv = dir.join("resolv.conf");
        let backup = dir.join("resolv.conf.bak");
        std::fs::write(&resolv, "nameserver 192.168.1.1\n").unwrap();

        let mut g = ResolvConfGuard::new(&resolv, &backup);
        g.install(&["1.1.1.1".to_string(), "8.8.8.8".to_string()])
            .unwrap();
        let active = std::fs::read_to_string(&resolv).unwrap();
        assert!(active.contains("nameserver 1.1.1.1"));
        assert!(active.contains("nameserver 8.8.8.8"));
        assert!(
            !active.contains("192.168.1.1"),
            "local resolver must be replaced"
        );
        assert!(backup.exists(), "original must be backed up");

        // remove restores the original.
        g.remove().unwrap();
        assert_eq!(
            std::fs::read_to_string(&resolv).unwrap(),
            "nameserver 192.168.1.1\n"
        );
        assert!(!backup.exists(), "backup is consumed on restore");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolv_conf_drop_restores() {
        let dir = std::env::temp_dir().join(format!("rustnies-resolv-drop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let resolv = dir.join("resolv.conf");
        let backup = dir.join("resolv.conf.bak");
        std::fs::write(&resolv, "nameserver 10.0.0.1\n").unwrap();

        {
            let mut g = ResolvConfGuard::new(&resolv, &backup);
            g.install(&["1.1.1.1".to_string()]).unwrap();
        } // dropped here
        assert_eq!(
            std::fs::read_to_string(&resolv).unwrap(),
            "nameserver 10.0.0.1\n",
            "Drop must restore the original resolv.conf"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolv_conf_stale_backup_is_preserved() {
        // Simulate a crashed previous run: a backup already exists. The new
        // install must keep it (the real original) rather than overwriting it
        // with the rustnies-managed content.
        let dir =
            std::env::temp_dir().join(format!("rustnies-resolv-stale-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let resolv = dir.join("resolv.conf");
        let backup = dir.join("resolv.conf.bak");
        // The crashed run left a backup of the REAL original, and resolv.conf
        // is currently the rustnies one.
        std::fs::write(&backup, "nameserver 9.9.9.9\n").unwrap();
        std::fs::write(&resolv, "nameserver 1.1.1.1\n").unwrap();

        let mut g = ResolvConfGuard::new(&resolv, &backup);
        g.install(&["8.8.8.8".to_string()]).unwrap();
        // The backup must still hold the real original, not be overwritten.
        assert_eq!(
            std::fs::read_to_string(&backup).unwrap(),
            "nameserver 9.9.9.9\n"
        );
        // resolv.conf now points at the new tunnel DNS.
        assert!(
            std::fs::read_to_string(&resolv)
                .unwrap()
                .contains("nameserver 8.8.8.8")
        );

        // remove restores the preserved original.
        g.remove().unwrap();
        assert_eq!(
            std::fs::read_to_string(&resolv).unwrap(),
            "nameserver 9.9.9.9\n"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolv_conf_empty_dns_rejected() {
        let g = ResolvConfGuard::new("/dev/null", "/dev/null");
        let mut g = g;
        let err = g.install(&[]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn parse_iptables_chain_counts_dns_rules() {
        let output = "\
Chain RUSTNIES_DNS (1 references)
    pkts      bytes target     prot opt in     out     source               destination
      42      2520 ACCEPT     udp  --  *      rustnies0  0.0.0.0/0            0.0.0.0/0            udp dpt:53
       0         0 ACCEPT     tcp  --  *      rustnies0  0.0.0.0/0            0.0.0.0/0            tcp dpt:53
       7       420 REJECT     udp  --  *      *      0.0.0.0/0            0.0.0.0/0            udp dpt:53
       0         0 REJECT     tcp  --  *      *      0.0.0.0/0            0.0.0.0/0            tcp dpt:53
";
        let rows = parse_iptables_chain(output);
        assert_eq!(rows.len(), 4);
        // UDP-accept: 42 pkts, dpt:53, out rustnies0.
        assert_eq!(rows[0].pkts, 42);
        assert_eq!(rows[0].target, "ACCEPT");
        assert_eq!(rows[0].out_iface, "rustnies0");
        assert_eq!(rows[0].dport, Some(53));
        // UDP-reject: 7 pkts (a leak attempt was blocked).
        assert_eq!(rows[2].pkts, 7);
        assert_eq!(rows[2].target, "REJECT");
        assert_eq!(rows[2].dport, Some(53));
    }

    #[test]
    fn parse_iptables_chain_handles_kill_switch() {
        let output = "\
Chain RUSTNIES_KS (1 references)
    pkts      bytes target     prot opt in     out     source               destination
     100      6000 ACCEPT     all  --  *      lo      0.0.0.0/0            0.0.0.0/0
     220     13200 ACCEPT     all  --  *      rustnies0  0.0.0.0/0          0.0.0.0/0
      12       720 ACCEPT     udp  --  *      *       0.0.0.0/0            1.2.3.4              udp dpt:51820
       3       180 REJECT     all  --  *      *       0.0.0.0/0            0.0.0.0/0
";
        let rows = parse_iptables_chain(output);
        assert_eq!(rows.len(), 4);
        // TUN-accept out rustnies0.
        let tun_accept = rows
            .iter()
            .find(|r| r.target == "ACCEPT" && r.out_iface == "rustnies0")
            .unwrap();
        assert_eq!(tun_accept.pkts, 220);
        // Catch-all reject.
        let reject = rows.iter().find(|r| r.target == "REJECT").unwrap();
        assert_eq!(reject.pkts, 3);
        // Server accept has a dport.
        let srv = rows.iter().find(|r| r.dport == Some(51820)).unwrap();
        assert_eq!(srv.target, "ACCEPT");
    }

    #[test]
    fn extract_dport_finds_port() {
        assert_eq!(extract_dport("0.0.0.0/0 udp dpt:53"), Some(53));
        assert_eq!(extract_dport("udp dpt:51820 flags 0x17"), Some(51820));
        assert_eq!(extract_dport("no port here"), None);
    }

    // ----------------------- subprocess noise -----------------------

    #[test]
    fn run_captures_stderr_into_error_instead_of_printing() {
        // A failing command's stderr must come back in the error (for
        // tracing), not be inherited to the terminal.
        let err = run("sh", &["-c", "echo oops >&2; exit 1"]).unwrap_err();
        assert!(
            err.to_string().contains("oops"),
            "child stderr should be captured in the error, got: {err}"
        );
        // Success stays silent and Ok.
        assert!(run("true", &[]).is_ok());
    }

    #[test]
    fn ipv6_available_probes_the_given_path() {
        let dir = std::env::temp_dir().join(format!("rustnies-ipv6-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let present = dir.join("ipv6");
        std::fs::create_dir_all(&present).unwrap();
        assert!(ipv6_available_at(&present));
        assert!(!ipv6_available_at(&dir.join("missing")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ----------------------- NAT planning -----------------------

    #[test]
    fn server_nat_plans_scoped_masquerade() {
        let n = NatRules::new("10.7.0.0/24", "rustnies", Some("ens1".into()));
        let rules = n.planned_v4("ens1");
        let masq = rules
            .iter()
            .find(|(t, _)| *t == "nat")
            .expect("server NAT must include a MASQUERADE rule");
        assert_eq!(
            masq.1,
            vec![
                "POSTROUTING",
                "-s",
                "10.7.0.0/24",
                "-o",
                "ens1",
                "-j",
                "MASQUERADE"
            ]
        );
    }

    #[test]
    fn client_nat_without_source_masquerades_all_via_tun() {
        // Regression test: `new_client(None)` documents "masquerades all
        // traffic leaving via the TUN (no `-s` filter)", and the server
        // depends on it — un-NATed LAN sources would arrive at the server
        // outside its TUN-subnet MASQUERADE scope (replies unroutable) and
        // pollute tunnel-IP learning.
        let n: NatRules = NatRules::new_client(None::<String>, "rustnies0");
        let rules = n.planned_v4("rustnies0");
        let masq = rules
            .iter()
            .find(|(t, _)| *t == "nat")
            .expect("client NAT with no source must still masquerade");
        assert_eq!(
            masq.1,
            vec!["POSTROUTING", "-o", "rustnies0", "-j", "MASQUERADE"],
            "no `-s` filter: covers any LAN behind the client"
        );
        // Same for the IPv6 half.
        let v6 = n
            .planned_v6_masq("rustnies0")
            .expect("client NAT with no source must masquerade v6 too");
        assert_eq!(
            v6,
            vec!["POSTROUTING", "-o", "rustnies0", "-j", "MASQUERADE"]
        );
    }

    #[test]
    fn client_nat_with_source_scopes_masquerade() {
        let n: NatRules = NatRules::new_client(Some("192.168.50.0/24"), "rustnies0");
        let rules = n.planned_v4("rustnies0");
        let masq = rules
            .iter()
            .find(|(t, _)| *t == "nat")
            .expect("scoped client NAT must masquerade");
        assert!(masq.1.contains(&"-s".to_string()));
        assert!(masq.1.contains(&"192.168.50.0/24".to_string()));
        assert!(n.planned_v6_masq("rustnies0").is_none());
    }

    // ----------------------- DNS regression (field report) -----------------------

    #[test]
    fn dns_rules_allow_tunnel_resolver_block_physical() {
        // Exact field-report scenario: resolv.conf points at 1.1.1.1, TUN is
        // rustnies0. DNS to the tunnel resolver via the TUN must be accepted
        // (UDP and TCP, both families); the same query via the physical
        // interface must be rejected — and must never be confused with
        // TUN-bound traffic.
        let backend = Arc::new(RecordedBackend::new());
        let mut g = DnsLeakGuard::new("rustnies0", backend.clone());
        g.install().unwrap();
        let ops = backend.ops();

        for proto in ["udp", "tcp"] {
            assert_eq!(
                evaluate_packet(&ops, proto, "1.1.1.1", 53, "rustnies0"),
                Decision::Accept,
                "{proto} DNS to the tunnel resolver via the TUN must be allowed"
            );
            assert_eq!(
                evaluate_packet(&ops, proto, "1.1.1.1", 53, "end0"),
                Decision::Reject,
                "{proto} DNS to the same resolver via the physical iface must be blocked"
            );
        }
        // TUN-sourced is keyed on the interface, not the destination: any
        // resolver via the TUN is fine.
        assert_eq!(
            evaluate_packet(&ops, "udp", "8.8.8.8", 53, "rustnies0"),
            Decision::Accept
        );
    }

    // ----------------------- route-all LAN exceptions -----------------------

    #[test]
    fn parse_local_cidrs_extracts_inet_cidrs() {
        let output = "2: end0    inet 192.168.50.71/24 brd 192.168.50.255 scope global dynamic noprefixroute end0\n   valid_lft 1595sec preferred_lft 1595sec\n";
        assert_eq!(parse_local_cidrs(output), vec!["192.168.50.0/24"]);
    }

    #[test]
    fn parse_local_cidrs_masks_host_bits() {
        // Exact field failure: `ip addr` reports the interface *address*
        // (213.138.68.130/24), but `ip route add` rejects host-bits-set
        // prefixes ("Invalid prefix for given prefix length") — the parser
        // must emit the masked network.
        let output = "2: end0    inet 213.138.68.130/24 brd 213.138.68.255 scope global end0\n   valid_lft forever preferred_lft forever\n";
        assert_eq!(parse_local_cidrs(output), vec!["213.138.68.0/24"]);
    }

    #[test]
    fn parse_local_cidrs_dedupes_overlapping_assignments() {
        let output = "2: end0    inet 192.168.50.71/24 scope global end0\n3: end0    inet 192.168.50.72/24 scope global secondary end0\n";
        assert_eq!(parse_local_cidrs(output), vec!["192.168.50.0/24"]);
    }

    #[test]
    fn parse_local_cidrs_skips_host_routes_and_garbage() {
        let output = "1: lo    inet 127.0.0.1/8 scope host lo\n2: end0    inet 192.168.50.71/24 brd 192.168.50.255 scope global end0\n3: tun0    inet 10.9.0.5/32 scope global tun0\nnot an addr line\n";
        let cidrs = parse_local_cidrs(output);
        assert!(cidrs.contains(&"127.0.0.0/8".to_string()));
        assert!(cidrs.contains(&"192.168.50.0/24".to_string()));
        assert!(
            !cidrs.iter().any(|c| c.ends_with("/32")),
            "host routes must be skipped, got: {cidrs:?}"
        );
    }

    #[test]
    fn parse_local_cidrs_empty_when_no_inet() {
        assert!(parse_local_cidrs("").is_empty());
        assert!(parse_local_cidrs("2: end0    inet6 fe80::1/64 scope link\n").is_empty());
    }

    #[test]
    fn route_all_plan_orders_server_lan_then_default() {
        // The plan for the field-report host: server 82.22.53.28 via the
        // original gateway, local LAN 192.168.50.0/24 kept on the gateway,
        // everything else via the TUN.
        let plan = route_all_plan(
            "82.22.53.28",
            "192.168.50.1",
            &["192.168.50.0/24".to_string()],
            "rustnies0",
        );
        assert_eq!(plan.len(), 3);
        assert_eq!(
            plan[0],
            vec!["route", "add", "82.22.53.28", "via", "192.168.50.1"]
        );
        assert_eq!(
            plan[1],
            vec!["route", "add", "192.168.50.0/24", "via", "192.168.50.1"]
        );
        assert_eq!(
            plan[2],
            vec!["route", "add", "default", "dev", "rustnies0", "metric", "1"]
        );
    }

    #[test]
    fn route_all_plan_without_lan_is_server_then_default() {
        let plan = route_all_plan("1.2.3.4", "10.0.0.1", &[], "tun0");
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0][2], "1.2.3.4");
        assert_eq!(plan[1][2], "default");
    }

    // ----------------------- bypass-table policy routing -----------------------

    #[test]
    fn parse_local_addrs_extracts_v4_and_dedupes() {
        let output = "2: end0    inet 213.138.68.130/24 brd 213.138.68.255 scope global end0\n3: end0    inet 213.138.68.131/24 scope global secondary end0\n";
        assert_eq!(
            parse_local_addrs(output, false),
            vec!["213.138.68.130", "213.138.68.131"]
        );
    }

    #[test]
    fn parse_local_addrs_ignores_v6_tokens_in_v4_mode() {
        let output = "2: end0    inet 192.168.50.71/24 scope global end0\n2: end0    inet6 fe80::1/64 scope link\n";
        assert_eq!(parse_local_addrs(output, false), vec!["192.168.50.71"]);
    }

    #[test]
    fn parse_local_addrs_v6_skips_link_local() {
        let output = "2: end0    inet6 2001:db8::42/64 scope global\n2: end0    inet6 fe80::1/64 scope link\n";
        assert_eq!(parse_local_addrs(output, true), vec!["2001:db8::42"]);
    }

    #[test]
    fn parse_local_cidrs_v6_masks_and_skips_link_local() {
        let output = "2: end0    inet6 2001:db8::42/64 scope global\n2: end0    inet6 fe80::1/64 scope link\n3: tun0    inet6 ::1/128 scope host\n";
        assert_eq!(parse_local_cidrs_v6(output), vec!["2001:db8::/64"]);
    }

    #[test]
    fn bypass_plan_orders_table_routes_then_from_rules() {
        let plan = bypass_plan(
            "213.138.68.129",
            "end0",
            &["213.138.68.0/24".to_string()],
            &["213.138.68.130".to_string()],
            false,
        );
        assert_eq!(plan.len(), 3);
        assert_eq!(
            plan[0],
            vec![
                "route",
                "add",
                "213.138.68.0/24",
                "dev",
                "end0",
                "table",
                "100"
            ]
        );
        assert_eq!(
            plan[1],
            vec![
                "route",
                "add",
                "default",
                "via",
                "213.138.68.129",
                "dev",
                "end0",
                "table",
                "100"
            ]
        );
        assert_eq!(
            plan[2],
            vec![
                "rule",
                "add",
                "from",
                "213.138.68.130",
                "table",
                "100",
                "priority",
                "20000"
            ]
        );
    }

    #[test]
    fn bypass_plan_v6_prefixes_family_flag() {
        let plan = bypass_plan(
            "fe80::1",
            "end0",
            &["2001:db8::/64".to_string()],
            &["2001:db8::42".to_string()],
            true,
        );
        assert_eq!(plan.len(), 3);
        assert!(plan.iter().all(|s| s[0] == "-6"));
        assert_eq!(
            plan[2],
            vec![
                "-6",
                "rule",
                "add",
                "from",
                "2001:db8::42",
                "table",
                "100",
                "priority",
                "20000"
            ]
        );
    }

    #[test]
    fn bypass_plan_without_addrs_is_routes_only() {
        let plan = bypass_plan("10.0.0.1", "eth0", &[], &[], false);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0][2], "default");
    }
}
