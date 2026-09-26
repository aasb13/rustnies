//! Configuration types for the daemon and CLI.
//!
//! There are two layers of configuration:
//!
//! 1. **Runtime config** ([`ServerConfig`] / [`ClientConfig`]) — the fully
//!    resolved, non-optional values the daemon consumes. Every field has a
//!    value; there are no holes.
//! 2. **File config** ([`ServerFileConfig`] / [`ClientFileConfig`]) — the
//!    TOML-parsed, all-`Option` shape read from disk. Any subset of fields may
//!    be present; missing fields are `None` and mean "leave the default".
//!
//! Resolution order (lowest to highest precedence):
//!   `*Config::default()`  →  file config  →  CLI flags
//!
//! CLI flags therefore override the config file only when actually passed;
//! an omitted flag does not clobber a value set in the file. This keeps the
//! pure-CLI path working exactly as before while making a TOML file the
//! convenient default for repeated use.
//!
//! Default config file paths:
//!   - server: `/etc/rustnies/server.toml`
//!   - client: `/etc/rustnies/client.toml`
//!
//! Both can be overridden with `--config <path>`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Peer entries (shared by runtime and file configs)
// ---------------------------------------------------------------------------

/// One authorized peer in the server's `[[peers]]` array.
///
/// `public_key` is the hex-encoded 32-byte X25519 static public key the
/// client presents in the Noise IK handshake. `name` is an optional
/// human-readable label used purely for log readability (e.g. "alice",
/// "site-b") — it has no effect on authorization.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerEntry {
    /// Hex-encoded 32-byte X25519 static public key.
    pub public_key: String,
    /// Optional label shown in handshake/acceptance log lines.
    pub name: Option<String>,
}

// ---------------------------------------------------------------------------
// Obfuscation (shared by runtime and file configs)
// ---------------------------------------------------------------------------

/// The resolved `[obfuscation]` section: an ordered list of layer names plus
/// per-layer parameters.
///
/// This struct is shared by the runtime and file configs (it is not
/// all-`Option`, because every field has a sensible default that means "no
/// override"). The presence of the section itself is tracked by the
/// `Option<ObfuscationConfig>` on the runtime/file config structs: `None`
/// means no `[obfuscation]` section was present and obfuscation is fully off;
/// `Some` with an empty `layers` list is also off.
///
/// ```toml
/// [obfuscation]
/// layers = ["padding", "header_xor"]   # ordered; applied in order on send
/// padding_buckets = [64, 128, 256, 512, 1024, 1400]
/// padding_max = 1400
/// timing_max_jitter_us = 2000
/// timing_decoy_interval_ms = 200
/// timing_decoy_max_len = 256
/// ```
///
/// Buckets are measured in bytes at the padded output (incl. the 2-byte length
/// prefix). Keep the top bucket wire-safe: bucket + UDP/IPv4 envelope (28 B)
/// must fit the 1500-byte path MTU, so 1400 is the default ceiling — a 1500
/// bucket would emit 1528-byte outer datagrams that fragment on Ethernet.
///
/// Unknown layer names in `layers` are logged at `warn` and skipped, so a typo
/// never prevents the tunnel from coming up. The recognised layer names are:
/// - `"padding"`    — [`crate::obfuscation::padding::SizePadding`]
/// - `"timing"`     — [`crate::obfuscation::timing::TimingJitter`]
/// - `"header_xor"` — [`crate::obfuscation::header_xor::HeaderXor`]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObfuscationConfig {
    /// Ordered list of obfuscation layer names, applied in order on the send
    /// path and in reverse on the receive path. Empty (the default) means no
    /// obfuscation.
    #[serde(default)]
    pub layers: Vec<String>,
    /// `[padding]` bucket sizes (bytes, inclusive of the 2-byte length prefix).
    /// A frame is padded into the smallest bucket that fits. Empty (the
    /// default) means the layer's built-in defaults.
    #[serde(default)]
    pub padding_buckets: Vec<usize>,
    /// Hard cap on padding output size. `0` (the default) means the layer's
    /// built-in default.
    #[serde(default)]
    pub padding_max: usize,
    /// `[timing]` maximum random send jitter, in microseconds. `0` (the
    /// default) means the layer's built-in default.
    #[serde(default)]
    pub timing_max_jitter_us: u64,
    /// `[timing]` idle decoy-packet interval, in milliseconds. `0` (the
    /// default) means the layer's built-in default.
    #[serde(default)]
    pub timing_decoy_interval_ms: u64,
    /// `[timing]` maximum decoy payload length, in bytes. `0` (the default)
    /// means the layer's built-in default.
    #[serde(default)]
    pub timing_decoy_max_len: usize,
}

// ---------------------------------------------------------------------------
// Protocol profile (shared by runtime and file configs)
// ---------------------------------------------------------------------------
//
// These four sections select which implementation of each swappable protocol
// part a session runs. See `doc/profiles.md` for the full model.
//
// Three are *negotiated* in the handshake (`[crypto]`, `[transport] data`,
// `[fec] scheme`): the server picks, from its own ordered preference, the first
// candidate the client also supports, and its answer travels in the Noise
// message-2 payload.
//
// One is purely *local* (`[congestion]`): a congestion window is invisible to
// the peer, so there is nothing to agree on and each side uses its own.
//
// Two settings are *config-pinned on both peers* because they are needed before
// any negotiation channel exists: `[handshake] kex` and
// `[transport] handshake`. A mismatch there is detected and reported at
// handshake time, not negotiated away.

/// The `[handshake]` section: key exchange and profile negotiation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandshakeConfig {
    /// Key-exchange algorithm. Must be named identically in the server's and
    /// the client's config: the KEX is what carries the profile negotiation, so
    /// it cannot itself be negotiated. `"noise-ik"` is the only phase-1 value.
    ///
    /// An unknown name is a **hard error** on both sides (not a warn-and-skip as
    /// for an obfuscation layer): a fallback would leave the peers running
    /// different algorithms and every handshake would time out with no useful
    /// diagnostic.
    #[serde(default = "default_kex")]
    pub kex: String,
    /// Whether the client appends its ordered capability offer to message 1, so
    /// the server can pick something both sides support. `false` (the default)
    /// means the server simply picks its own first preference and the client
    /// validates the answer.
    ///
    /// Off by default because appending a payload to message 1 is a wire change
    /// a peer that predates it cannot parse. Turning it on requires *both* peers
    /// to be new; the message-2 answer is additive and needs no such opt-in.
    #[serde(default)]
    pub propose: bool,
}

fn default_kex() -> String {
    crate::protocol::handshake::DEFAULT_HANDSHAKE.to_string()
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        Self {
            kex: default_kex(),
            propose: false,
        }
    }
}

/// The `[crypto]` section: the per-packet AEAD suite.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CryptoConfig {
    /// Ordered preference list of AEAD cipher names. The first entry is the
    /// default; the rest are fallbacks. Empty (the default) means
    /// `["chacha20poly1305"]`.
    ///
    /// **Negotiated.** The chosen suite is also folded into the Noise
    /// transport-key HKDF, so peers that disagree derive different keys and the
    /// mismatch surfaces as an authentication failure on the first data packet
    /// rather than as a session that appears to connect and then misbehaves.
    #[serde(default)]
    pub aead: Vec<String>,
}

/// The `[transport]` section: the datagram envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportConfig {
    /// Envelope for the Noise handshake messages. A single name, not a list,
    /// because it cannot be negotiated — it is what carries the negotiation.
    /// Must match on both peers. `"plain"` (the default) is the identity.
    ///
    /// A keyed transport cannot be used here: its key material is derived from
    /// the handshake hash, which does not exist until the handshake completes.
    #[serde(default = "default_transport_name")]
    pub handshake: String,
    /// Ordered preference list of envelopes for steady-state frames. The first
    /// entry is the default; the rest are fallbacks. Empty (the default) means
    /// `["same-as-handshake"]`, which reuses the handshake envelope and needs no
    /// negotiation at all.
    ///
    /// **Negotiated.** The first supported entry wins; see
    /// [`crate::protocol::profile`].
    #[serde(default = "default_data_transports")]
    pub data: Vec<String>,
    /// Two-byte framing tag for the `"tagged"` data envelope, as 4 hex digits.
    ///
    /// **Server-side only.** The tag travels inside the server's negotiation
    /// answer, so a client never has to configure one. It does not affect the
    /// handshake transport, which always uses the compiled-in default tag on
    /// both peers. Empty (the default) uses that same default.
    #[serde(default)]
    pub tag_hex: Option<String>,
}

fn default_transport_name() -> String {
    crate::transport::DEFAULT_TRANSPORT.to_string()
}

fn default_data_transports() -> Vec<String> {
    vec![crate::transport::TRANSPORT_SAME_AS_HANDSHAKE.to_string()]
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            handshake: default_transport_name(),
            data: default_data_transports(),
            tag_hex: None,
        }
    }
}

/// The `[congestion]` section: the sender's rate limiter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CongestionConfig {
    /// Congestion-control algorithm. A single name, not a list: the setting is
    /// **purely local** (a congestion window is invisible to the peer, so there
    /// is nothing to negotiate) and a preference list would have no meaning.
    /// Empty (the default) means `"tcp-reno"`.
    #[serde(default = "default_congestion_name")]
    pub algorithm: String,
}

fn default_congestion_name() -> String {
    crate::congestion::DEFAULT_CONGESTION.to_string()
}

impl Default for CongestionConfig {
    fn default() -> Self {
        Self {
            algorithm: default_congestion_name(),
        }
    }
}

// ---------------------------------------------------------------------------
// Runtime configs (fully resolved, consumed by the daemon)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// UDP address to listen on (e.g. "0.0.0.0:46722").
    pub listen: SocketAddr,
    /// TUN interface name to create.
    pub tun_name: String,
    /// TUN IPv4 address, e.g. "10.7.0.1".
    pub tun_addr: String,
    pub tun_prefix: u8,
    /// TUN IPv6 address + prefix, e.g. ("fd00::1", 64). `None` for IPv4-only.
    pub tun_addr6: Option<String>,
    pub tun_prefix6: Option<u8>,
    pub tun_mtu: u32,
    /// Path to the server's long-term static key file.
    pub key_path: PathBuf,
    /// If true, install iptables NAT rules to forward tunneled traffic out.
    pub enable_nat: bool,
    /// Override the egress interface for NAT (auto-detected if None).
    pub nat_out_iface: Option<String>,
    /// Path to the IPC socket the daemon listens on.
    pub ipc_path: PathBuf,
    /// Authorized client peers, inline in the TOML config as a `[[peers]]`
    /// array of tables. `None` means no `[[peers]]` section was present and
    /// the server runs in open mode (accepts every peer, phase-1
    /// compatibility). `Some(vec)` restricts handshakes to the listed keys —
    /// including an explicit empty list, which rejects everyone.
    pub peers: Option<Vec<PeerEntry>>,
    /// Resolved path of the TOML config file the daemon loaded from (the
    /// `--config` path or the `/etc/rustnies/server.toml` default). Kept so a
    /// SIGHUP can re-read the `[[peers]]` array live without restarting.
    pub config_path: Option<PathBuf>,
    /// Optional `RUST_LOG`-style filter applied at startup when `--verbose`
    /// is not passed and `RUST_LOG` is not already set in the environment.
    pub log_level: Option<String>,
    /// Optional path to a log file. When set, log lines are written to both
    /// stdout and the file (append mode). `None` (the default) means
    /// stdout-only logging.
    pub log_file: Option<PathBuf>,
    /// Resolved obfuscation configuration. `None` (the default) means no
    /// `[obfuscation]` section was present and obfuscation is disabled. An
    /// `Some` value with an empty `layers` list also disables obfuscation.
    pub obfuscation: Option<ObfuscationConfig>,
    /// Resolved FEC (forward error correction) configuration.
    pub fec: FecConfig,
    /// Resolved `[handshake]` configuration (KEX name + whether to propose).
    pub handshake: HandshakeConfig,
    /// Resolved `[crypto]` configuration (AEAD suite preference).
    pub crypto: CryptoConfig,
    /// Resolved `[transport]` configuration (envelope selection).
    pub transport: TransportConfig,
    /// Resolved `[congestion]` configuration (local rate limiter).
    pub congestion: CongestionConfig,
    /// Maximum concurrent sessions accepted from a single static peer key. A
    /// misbehaving or malicious client can otherwise open sessions until the
    /// server exhausts memory/fds. When a new handshake from an already-saturated
    /// peer would exceed this cap, the oldest-idle session for that key is
    /// evicted (not the new one refused) so a legit reconnect to a fresh NAT
    /// port still succeeds. `0` (the default) means "no cap" (phase-1
    /// compatibility for single-client deployments).
    pub max_sessions_per_peer: u8,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: std::net::SocketAddr::from(([0, 0, 0, 0], 46722)),
            tun_name: "rustnies".into(),
            tun_addr: "10.7.0.1".into(),
            tun_prefix: 24,
            tun_addr6: None,
            tun_prefix6: None,
            tun_mtu: 1400,
            key_path: PathBuf::new(),
            enable_nat: true,
            nat_out_iface: None,
            ipc_path: default_ipc_path(),
            peers: None,
            config_path: None,
            log_level: None,
            log_file: None,
            obfuscation: None,
            fec: FecConfig::default(),
            handshake: HandshakeConfig::default(),
            crypto: CryptoConfig::default(),
            transport: TransportConfig::default(),
            congestion: CongestionConfig::default(),
            max_sessions_per_peer: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Server UDP endpoint.
    pub server: SocketAddr,
    /// The server's static public key (32 bytes, hex-encoded).
    pub server_pubkey_hex: String,
    pub tun_name: String,
    /// TUN IPv4 address, e.g. "10.7.0.2".
    pub tun_addr: String,
    pub tun_prefix: u8,
    /// TUN IPv6 address + prefix, e.g. "fd00::2". `None` for IPv4-only.
    pub tun_addr6: Option<String>,
    pub tun_prefix6: Option<u8>,
    pub tun_mtu: u32,
    pub key_path: PathBuf,
    pub ipc_path: PathBuf,
    /// When true (the default), route all client traffic (not just the TUN
    /// subnet) through the tunnel by replacing the default route. Disable with
    /// `--no-route` or `route_all = false` in the config file.
    pub route_all: bool,
    /// Optional path to a file listing extra destinations (IPs or CIDRs, one
    /// per line) to route through the TUN device. Lines beginning with `#` and
    /// blank lines are ignored. This is independent of `route_all`: when set,
    /// each listed destination gets a host/network route via the TUN interface
    /// regardless of whether the default route is also replaced. Routes are
    /// added directly over netlink (no per-entry `ip` process spawn) so tens
    /// of thousands of entries are practical, and are removed on shutdown.
    pub route_path: Option<PathBuf>,
    /// When true (the default), automatically re-establish the tunnel after a
    /// handshake failure or session teardown instead of exiting the process.
    /// The client retries with an exponentially growing backoff (capped) and
    /// keeps the TUN device and its routes up across reconnects. Disable with
    /// `--no-reconnect` or `reconnect = false` in the config file to keep the
    /// original fail-fast behaviour (exit on the first disconnect).
    pub reconnect: bool,
    /// DNS leak prevention. When `route_all` is active and this is true (the
    /// default), the client installs firewall rules that block DNS (port 53
    /// UDP/TCP) from leaving via any interface other than the TUN, and
    /// rewrites `/etc/resolv.conf` to point at [`ClientConfig::dns`] (resolver
    /// IPs reachable through the tunnel) so name resolution actually goes
    /// through the tunnel instead of the system's normal resolver. Disable
    /// with `--no-dns-leak-protection` or `dns_leak_protection = false`.
    pub dns_leak_protection: bool,
    /// Resolver IPs written to `/etc/resolv.conf` while DNS leak prevention is
    /// active. `None` means use the built-in default (`1.1.1.1`). `Some(vec)`
    /// uses the listed servers; `Some([])` (an explicit empty list) skips the
    /// `resolv.conf` rewrite and only installs the firewall block.
    pub dns: Option<Vec<String>>,
    /// Opt-in kill switch. When true, the client installs firewall rules that
    /// block *all* outbound traffic except via the TUN, to the VPN server
    /// (the encrypted tunnel UDP), and on loopback — so if the tunnel drops
    /// unexpectedly the client cannot silently fall back to the real internet.
    /// The rules are held for the daemon's lifetime (across reconnects) and
    /// only removed on a graceful shutdown: the switch fails closed. Enabling
    /// this also forces `route_all` on (the kill switch is only meaningful when
    /// all traffic is routed through the tunnel).
    pub kill_switch: bool,
    /// Client-side NAT (LAN sharing). When true (the default), the client
    /// installs an iptables MASQUERADE rule so a LAN behind this client can
    /// share the tunnel: forwarded traffic leaving via the TUN is rewritten to
    /// the client's tunnel address, since the server only knows the client's
    /// TUN IP, not the LAN behind it. Disable with `--no-nat` or
    /// `[nat] enabled = false` in the config file.
    pub enable_nat: bool,
    /// Source CIDR for the client-side MASQUERADE rule. `None` (the default)
    /// masquerades all traffic leaving via the TUN (no `-s` filter), which
    /// makes any LAN behind the client share the tunnel with no per-LAN
    /// configuration; `Some("192.168.50.0/24")` scopes the rule to that LAN.
    /// See [`ClientConfig::enable_nat`].
    pub nat_source_cidr: Option<String>,
    /// Optional `RUST_LOG`-style filter applied at startup when `--verbose`
    /// is not passed and `RUST_LOG` is not already set in the environment.
    pub log_level: Option<String>,
    /// Optional path to a log file. When set, log lines are written to both
    /// stdout and the file (append mode). `None` (the default) means
    /// stdout-only logging.
    pub log_file: Option<PathBuf>,
    /// Resolved obfuscation configuration. `None` (the default) means no
    /// `[obfuscation]` section was present and obfuscation is disabled. An
    /// `Some` value with an empty `layers` list also disables obfuscation.
    pub obfuscation: Option<ObfuscationConfig>,
    /// Resolved FEC (forward error correction) configuration.
    pub fec: FecConfig,
    /// Resolved `[handshake]` configuration (KEX name + whether to propose).
    pub handshake: HandshakeConfig,
    /// Resolved `[crypto]` configuration (AEAD suite preference).
    pub crypto: CryptoConfig,
    /// Resolved `[transport]` configuration (envelope selection).
    pub transport: TransportConfig,
    /// Resolved `[congestion]` configuration (local rate limiter).
    pub congestion: CongestionConfig,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server: std::net::SocketAddr::from(([127, 0, 0, 1], 46722)),
            server_pubkey_hex: String::new(),
            tun_name: "rustnies0".into(),
            tun_addr: "10.7.0.2".into(),
            tun_prefix: 24,
            tun_addr6: None,
            tun_prefix6: None,
            tun_mtu: 1400,
            key_path: PathBuf::new(),
            ipc_path: default_ipc_path(),
            route_all: true,
            route_path: None,
            reconnect: true,
            dns_leak_protection: true,
            dns: None,
            kill_switch: false,
            enable_nat: true,
            nat_source_cidr: None,
            log_level: None,
            log_file: None,
            obfuscation: None,
            fec: FecConfig::default(),
            handshake: HandshakeConfig::default(),
            crypto: CryptoConfig::default(),
            transport: TransportConfig::default(),
            congestion: CongestionConfig::default(),
        }
    }
}

/// Default IPC socket path for the daemon.
///
/// This is a **fixed, well-known location** — `/run/rustnies/rustnies.sock` —
/// shared by both the server and the client so the daemon and the CLI always
/// agree on where to meet regardless of `TMPDIR` or the privilege boundary
/// either process was invoked across. A host runs either the server or the
/// client, never both; if you ever need both on one machine, override
/// `ipc_path` (config file) or `--socket` (CLI) for one of them.
///
/// Deriving this from `std::env::temp_dir()` was unstable: `TMPDIR`, sudo's
/// env reset, and systemd's `PrivateTmp=true` all made the daemon and the CLI
/// resolve *different* paths, so `status` / `stop` / `ping` failed with
/// `ENOENT` ("No such file or directory") even while the tunnel was up. The
/// installed config templates (`scripts/dist/*.toml`) and the systemd unit's
/// `RuntimeDirectory=rustnies` both use this exact path, so the default now
/// matches a stock install with no extra flags. The daemon creates the parent
/// directory if it is missing (see [`crate::ipc::serve`]).
pub fn default_ipc_path() -> PathBuf {
    PathBuf::from("/run/rustnies/rustnies.sock")
}

/// Default on-disk config path for a given role (`server` or `client`).
///
/// `/etc/rustnies/<role>.toml`. The path is only used when it exists; a
/// missing default path is silently ignored so the pure-CLI path still works
/// out of the box.
pub fn default_config_path(role: &str) -> PathBuf {
    PathBuf::from("/etc/rustnies").join(format!("{role}.toml"))
}

// ---------------------------------------------------------------------------
// Unknown-key warnings
// ---------------------------------------------------------------------------
//
// File configs do NOT use `#[serde(deny_unknown_fields)]`: a single typo
// should not prevent the daemon from starting. Instead, the TOML is parsed
// into a generic `toml::Value` first and walked against a static schema of
// known keys. Any key not in the schema produces a `tracing::warn!` so the
// user sees it in the logs without the config being rejected. This covers
// every level: top-level sections, `[tun]` / `[nat]` / `[obfuscation]`
// sub-tables, and individual `[[peers]]` entries.

/// Schema describing the known keys at one level of a TOML config file.
struct SectionSchema {
    /// Known scalar (non-table) key names at this level.
    scalars: &'static [&'static str],
    /// Known sub-tables: `(name, sub_schema)`. The value is a single TOML
    /// table (written as `[name]` or `name = { ... }`).
    tables: &'static [(&'static str, &'static SectionSchema)],
    /// Known arrays-of-tables: `(name, element_schema)`. The value is a TOML
    /// array whose elements are tables (written as `[[name]]` or
    /// `name = [{ ... }]`).
    array_tables: &'static [(&'static str, &'static SectionSchema)],
}

const TUN_SCHEMA: SectionSchema = SectionSchema {
    scalars: &["name", "addr", "prefix", "mtu"],
    tables: &[],
    array_tables: &[],
};

const NAT_SCHEMA: SectionSchema = SectionSchema {
    scalars: &["enabled", "out_iface"],
    tables: &[],
    array_tables: &[],
};

const CLIENT_NAT_SCHEMA: SectionSchema = SectionSchema {
    scalars: &["enabled", "source_cidr"],
    tables: &[],
    array_tables: &[],
};

const OBFUSCATION_SCHEMA: SectionSchema = SectionSchema {
    scalars: &[
        "layers",
        "padding_buckets",
        "padding_max",
        "timing_max_jitter_us",
        "timing_decoy_interval_ms",
        "timing_decoy_max_len",
    ],
    tables: &[],
    array_tables: &[],
};

const PEER_SCHEMA: SectionSchema = SectionSchema {
    scalars: &["public_key", "name"],
    tables: &[],
    array_tables: &[],
};

const FEC_SCHEMA: SectionSchema = SectionSchema {
    scalars: &["scheme", "k", "min_m", "max_m", "initial_m"],
    tables: &[],
    array_tables: &[],
};

const HANDSHAKE_SCHEMA: SectionSchema = SectionSchema {
    scalars: &["kex", "propose"],
    tables: &[],
    array_tables: &[],
};

const CRYPTO_SCHEMA: SectionSchema = SectionSchema {
    scalars: &["aead"],
    tables: &[],
    array_tables: &[],
};

const TRANSPORT_SCHEMA: SectionSchema = SectionSchema {
    scalars: &["handshake", "data", "tag_hex"],
    tables: &[],
    array_tables: &[],
};

const CONGESTION_SCHEMA: SectionSchema = SectionSchema {
    scalars: &["algorithm"],
    tables: &[],
    array_tables: &[],
};

const SERVER_SCHEMA: SectionSchema = SectionSchema {
    scalars: &[
        "listen",
        "key_path",
        "ipc_path",
        "log_level",
        "log_file",
        "max_sessions_per_peer",
    ],
    tables: &[
        ("tun", &TUN_SCHEMA),
        ("nat", &NAT_SCHEMA),
        ("obfuscation", &OBFUSCATION_SCHEMA),
        ("fec", &FEC_SCHEMA),
        ("handshake", &HANDSHAKE_SCHEMA),
        ("crypto", &CRYPTO_SCHEMA),
        ("transport", &TRANSPORT_SCHEMA),
        ("congestion", &CONGESTION_SCHEMA),
    ],
    array_tables: &[("peers", &PEER_SCHEMA)],
};

const CLIENT_SCHEMA: SectionSchema = SectionSchema {
    scalars: &[
        "server",
        "server_key",
        "key_path",
        "ipc_path",
        "route_all",
        "route_path",
        "reconnect",
        "dns_leak_protection",
        "dns",
        "kill_switch",
        "log_level",
        "log_file",
    ],
    tables: &[
        ("tun", &TUN_SCHEMA),
        ("nat", &CLIENT_NAT_SCHEMA),
        ("obfuscation", &OBFUSCATION_SCHEMA),
        ("fec", &FEC_SCHEMA),
        ("handshake", &HANDSHAKE_SCHEMA),
        ("crypto", &CRYPTO_SCHEMA),
        ("transport", &TRANSPORT_SCHEMA),
        ("congestion", &CONGESTION_SCHEMA),
    ],
    array_tables: &[],
};

/// Walk a parsed TOML value and emit `tracing::warn!` for every key that is
/// not in `schema`, recursing into known sub-tables and arrays-of-tables.
///
/// `path` is the dotted path to the current table (e.g. `""` for the root,
/// `"tun"` for the `[tun]` section). Unknown keys are warned with their full
/// path so the user can find the typo.
fn warn_unknown_keys(value: &toml::Value, path: &str, schema: &SectionSchema) {
    let Some(table) = value.as_table() else {
        return;
    };
    for (key, val) in table.iter() {
        let full_path = if path.is_empty() {
            key.clone()
        } else {
            format!("{path}.{key}")
        };

        if schema.scalars.contains(&key.as_str()) {
            continue;
        }
        if let Some(&(_, sub_schema)) = schema.tables.iter().find(|(n, _)| *n == key.as_str()) {
            warn_unknown_keys(val, &full_path, sub_schema);
            continue;
        }
        if let Some(&(_, elem_schema)) =
            schema.array_tables.iter().find(|(n, _)| *n == key.as_str())
        {
            if let Some(arr) = val.as_array() {
                for (i, elem) in arr.iter().enumerate() {
                    let p = format!("{full_path}[{i}]");
                    warn_unknown_keys(elem, &p, elem_schema);
                }
            }
            continue;
        }
        tracing::warn!(key = %key, path = %full_path, "unknown config key; ignored");
    }
}

// ---------------------------------------------------------------------------
// File configs (TOML, all-optional)
// ---------------------------------------------------------------------------
//
// These mirror the runtime configs but with every field optional and the TUN
// / NAT settings grouped under `[tun]` / `[nat]` sections for readability.
// Any field left out of the file stays `None` and does not override the
// runtime default or a CLI flag.

// ---------------------------------------------------------------------------
// FEC (shared by runtime and file configs)
// ---------------------------------------------------------------------------

/// `[fec]` section: forward-error-correction tuning.
///
/// All fields have sensible defaults; specifying an empty `[fec]` section
/// is equivalent to omitting it.
///
/// ```toml
/// [fec]
/// scheme = ["reed-solomon"]  # ordered preference; "none" disables parity entirely
/// k = 1          # source symbols per group (1 = every packet is its own group)
/// min_m = 0      # minimum parity symbols (clean links can disable FEC)
/// max_m = 4      # maximum parity symbols (higher = more loss tolerance)
/// initial_m = 2  # starting parity count before adaptation (burst protection)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FecConfig {
    /// Ordered preference list of FEC erasure codes. The first entry is the
    /// default; the rest are fallbacks so a mixed-version deployment connects
    /// either way. Empty (the default) means `["reed-solomon"]`.
    ///
    /// This is *negotiated* in the handshake, because a mismatched code would
    /// corrupt groups rather than fail cleanly. The server's order wins; see
    /// `doc/profiles.md`.
    #[serde(default)]
    pub scheme: Vec<String>,
    /// Source symbols per FEC group. `k = 1` (the default) means every
    /// packet is its own group, eliminating partial-group vulnerability for
    /// sparse traffic.
    #[serde(default = "default_fec_k")]
    pub k: u8,
    /// Minimum parity symbols per group. Defaults to zero so a consistently
    /// clean link pays no FEC overhead after the controller has measured enough
    /// source outcomes. The tunnel starts at `initial_m` for burst protection,
    /// then sender-side ACK loss feedback raises or lowers `m` for later groups.
    #[serde(default = "default_fec_min_m")]
    pub min_m: u8,
    /// Maximum parity symbols per group. Higher values handle more loss at
    /// the cost of more bandwidth. Capped at 4 by default: with `k = 1` that
    /// is 400% overhead (any 1 of 5 copies surviving ~80% loss). The old
    /// default of 20 could amplify modest real loss into 2000% overhead,
    /// saturating the link and producing *more* loss (congestive collapse
    /// with bufferbloat RTT spikes and burst drops).
    #[serde(default = "default_fec_max_m")]
    pub max_m: u8,
    /// Initial parity count before the adaptive controller adjusts.
    #[serde(default = "default_fec_initial_m")]
    pub initial_m: u8,
}

fn default_fec_k() -> u8 {
    1
}
fn default_fec_min_m() -> u8 {
    0
}
fn default_fec_max_m() -> u8 {
    4
}
fn default_fec_initial_m() -> u8 {
    2
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            scheme: default_fec_scheme(),
            k: default_fec_k(),
            min_m: default_fec_min_m(),
            max_m: default_fec_max_m(),
            initial_m: default_fec_initial_m(),
        }
    }
}

fn default_fec_scheme() -> Vec<String> {
    vec![crate::fec::DEFAULT_FEC_SCHEME.to_string()]
}

/// `[fec]` section for file configs (all `Option`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FecSection {
    pub scheme: Option<Vec<String>>,
    pub k: Option<u8>,
    pub min_m: Option<u8>,
    pub max_m: Option<u8>,
    pub initial_m: Option<u8>,
}

/// `[tun]` section shared by server and client file configs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunSection {
    pub name: Option<String>,
    pub addr: Option<String>,
    pub prefix: Option<u8>,
    /// Optional IPv6 address for dual-stack TUN (e.g. `fd00::1`).
    pub addr6: Option<String>,
    /// IPv6 prefix length (e.g. 64). Required when `addr6` is set.
    pub prefix6: Option<u8>,
    pub mtu: Option<u32>,
}

/// `[nat]` section for the server file config.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NatSection {
    /// Enable iptables NAT masquerading for tunneled traffic.
    pub enabled: Option<bool>,
    /// Override the egress interface (auto-detected when unset).
    pub out_iface: Option<String>,
}

/// `[nat]` section for the client file config (LAN-sharing masquerade).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientNatSection {
    /// Enable client-side MASQUERADE so a LAN behind this client can share the
    /// tunnel (default true).
    pub enabled: Option<bool>,
    /// Source CIDR to masquerade into the TUN. `None` (the default) masquerades
    /// all traffic leaving via the TUN; a CIDR (e.g. `192.168.50.0/24`) scopes
    /// it to that LAN.
    pub source_cidr: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerFileConfig {
    pub listen: Option<SocketAddr>,
    pub key_path: Option<PathBuf>,
    pub ipc_path: Option<PathBuf>,
    /// Authorized client peers as a `[[peers]]` array of tables, each with a
    /// `public_key` (hex) and optional `name`. `None` (no `[[peers]]` section)
    /// means open mode; `Some(vec)` restricts — including an explicit empty
    /// list, which rejects everyone.
    pub peers: Option<Vec<PeerEntry>>,
    pub log_level: Option<String>,
    /// Path to a log file. When set, log lines are written to both stdout and
    /// the file (append mode). See [`ServerConfig::log_file`].
    pub log_file: Option<PathBuf>,
    #[serde(default)]
    pub tun: TunSection,
    #[serde(default)]
    pub nat: NatSection,
    /// `[obfuscation]` section. `None` (no section) leaves obfuscation off.
    #[serde(default)]
    pub obfuscation: Option<ObfuscationConfig>,
    /// `[fec]` section. `None` (no section) leaves FEC at defaults.
    #[serde(default)]
    pub fec: Option<FecSection>,
    /// `[handshake]` section. `None` leaves the KEX and negotiation at defaults.
    #[serde(default)]
    pub handshake: Option<HandshakeConfig>,
    /// `[crypto]` section. `None` leaves the AEAD suite at its default.
    #[serde(default)]
    pub crypto: Option<CryptoConfig>,
    /// `[transport]` section. `None` leaves the envelope at its default.
    #[serde(default)]
    pub transport: Option<TransportConfig>,
    /// `[congestion]` section. `None` leaves the algorithm at its default.
    #[serde(default)]
    pub congestion: Option<CongestionConfig>,
    /// Max concurrent sessions from one static peer key. `None` (no field)
    /// leaves the runtime default. See `ServerConfig::max_sessions_per_peer`.
    #[serde(default)]
    pub max_sessions_per_peer: Option<u8>,
}

impl ServerFileConfig {
    /// Parse a server config from a TOML string.
    ///
    /// Unknown keys at any level produce `tracing::warn!` messages but do
    /// not cause an error, so a typo does not prevent the daemon from
    /// starting.
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        let value: toml::Value = toml::from_str(s)?;
        warn_unknown_keys(&value, "", &SERVER_SCHEMA);
        toml::from_str(s)
    }

    /// Load a server config from `path`. Returns an empty (all-`None`) config
    /// if `path` does not exist, so callers can use the default path without
    /// caring whether the file is present.
    pub fn load_or_empty(path: &Path) -> std::io::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => Self::from_toml(&s).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid server config {}: {e}", path.display()),
                )
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientFileConfig {
    pub server: Option<SocketAddr>,
    /// The server's static public key (32 bytes, hex-encoded).
    pub server_key: Option<String>,
    pub key_path: Option<PathBuf>,
    pub ipc_path: Option<PathBuf>,
    pub route_all: Option<bool>,
    /// Optional path to a file of extra route destinations (IPs/CIDRs, one per
    /// line). See [`ClientConfig::route_path`].
    pub route_path: Option<PathBuf>,
    /// Enable automatic reconnection. See [`ClientConfig::reconnect`].
    pub reconnect: Option<bool>,
    /// Enable DNS leak prevention. See [`ClientConfig::dns_leak_protection`].
    pub dns_leak_protection: Option<bool>,
    /// Resolver IPs for `/etc/resolv.conf` during DNS leak prevention. See
    /// [`ClientConfig::dns`].
    pub dns: Option<Vec<String>>,
    /// Enable the kill switch. See [`ClientConfig::kill_switch`].
    pub kill_switch: Option<bool>,
    pub log_level: Option<String>,
    /// Path to a log file. When set, log lines are written to both stdout and
    /// the file (append mode). See [`ClientConfig::log_file`].
    pub log_file: Option<PathBuf>,
    #[serde(default)]
    pub tun: TunSection,
    /// `[nat]` section for client-side LAN-sharing masquerade.
    #[serde(default)]
    pub nat: ClientNatSection,
    /// `[obfuscation]` section. `None` (no section) leaves obfuscation off.
    #[serde(default)]
    pub obfuscation: Option<ObfuscationConfig>,
    /// `[fec]` section. `None` (no section) leaves FEC at defaults.
    #[serde(default)]
    pub fec: Option<FecSection>,
    /// `[handshake]` section. `None` leaves the KEX and negotiation at defaults.
    #[serde(default)]
    pub handshake: Option<HandshakeConfig>,
    /// `[crypto]` section. `None` leaves the AEAD suite at its default.
    #[serde(default)]
    pub crypto: Option<CryptoConfig>,
    /// `[transport]` section. `None` leaves the envelope at its default.
    #[serde(default)]
    pub transport: Option<TransportConfig>,
    /// `[congestion]` section. `None` leaves the algorithm at its default.
    #[serde(default)]
    pub congestion: Option<CongestionConfig>,
}

impl ClientFileConfig {
    /// Parse a client config from a TOML string.
    ///
    /// Unknown keys at any level produce `tracing::warn!` messages but do
    /// not cause an error, so a typo does not prevent the daemon from
    /// starting.
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        let value: toml::Value = toml::from_str(s)?;
        warn_unknown_keys(&value, "", &CLIENT_SCHEMA);
        toml::from_str(s)
    }

    /// Load a client config from `path`, or return an empty config if the path
    /// does not exist. See [`ServerFileConfig::load_or_empty`].
    pub fn load_or_empty(path: &Path) -> std::io::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => Self::from_toml(&s).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid client config {}: {e}", path.display()),
                )
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Merge: default  →  file  →  CLI overrides
// ---------------------------------------------------------------------------

/// Helper: return `cli` if `Some`, else `file` if `Some`, else `def`.
#[inline]
#[allow(dead_code)]
fn pick<T>(cli: Option<T>, file: Option<T>, def: T) -> T {
    cli.or(file).unwrap_or(def)
}

/// Merge server defaults, file config, and CLI overrides (CLI wins).
///
/// `cli` is a [`ServerCliOverrides`] captured from the parsed command line.
pub fn merge_server_config(
    mut base: ServerConfig,
    file: ServerFileConfig,
    cli: &ServerCliOverrides,
) -> ServerConfig {
    if let Some(v) = file.listen {
        base.listen = v;
    }
    if let Some(v) = file.key_path {
        base.key_path = v;
    }
    if let Some(v) = file.ipc_path {
        base.ipc_path = v;
    }
    if let Some(v) = file.peers {
        base.peers = Some(v);
    }
    if let Some(v) = file.log_level {
        base.log_level = Some(v);
    }
    if let Some(v) = file.log_file {
        base.log_file = Some(v);
    }
    if let Some(v) = file.tun.name {
        base.tun_name = v;
    }
    if let Some(v) = file.tun.addr {
        base.tun_addr = v;
    }
    if let Some(v) = file.tun.prefix {
        base.tun_prefix = v;
    }
    if let Some(v) = file.tun.addr6 {
        base.tun_addr6 = Some(v);
    }
    if let Some(v) = file.tun.prefix6 {
        base.tun_prefix6 = Some(v);
    }
    if let Some(v) = file.tun.mtu {
        base.tun_mtu = v;
    }
    if let Some(v) = file.nat.enabled {
        base.enable_nat = v;
    }
    if let Some(v) = file.nat.out_iface {
        base.nat_out_iface = Some(v);
    }
    if let Some(v) = file.obfuscation {
        base.obfuscation = Some(v);
    }
    if let Some(v) = file.fec {
        if let Some(x) = v.scheme {
            base.fec.scheme = x;
        }
        if let Some(x) = v.k {
            base.fec.k = x;
        }
        if let Some(x) = v.min_m {
            base.fec.min_m = x;
        }
        if let Some(x) = v.max_m {
            base.fec.max_m = x;
        }
        if let Some(x) = v.initial_m {
            base.fec.initial_m = x;
        }
    }
    if let Some(v) = file.handshake {
        base.handshake = v;
    }
    if let Some(v) = file.crypto {
        base.crypto = v;
    }
    if let Some(v) = file.transport {
        base.transport = v;
    }
    if let Some(v) = file.congestion {
        base.congestion = v;
    }
    if let Some(v) = file.max_sessions_per_peer {
        base.max_sessions_per_peer = v;
    }

    // CLI overrides (only when explicitly passed -> Some).
    if let Some(v) = cli.listen.clone() {
        base.listen = v.parse().unwrap_or(base.listen);
    }
    if let Some(v) = cli.key.clone() {
        base.key_path = v;
    }
    if let Some(v) = cli.socket.clone() {
        base.ipc_path = v;
    }
    if let Some(v) = cli.log_file.clone() {
        base.log_file = Some(v);
    }
    if let Some(v) = cli.tun.clone() {
        base.tun_name = v;
    }
    if let Some(v) = cli.tun_addr.clone() {
        base.tun_addr = v;
    }
    if let Some(v) = cli.tun_prefix {
        base.tun_prefix = v;
    }
    if let Some(v) = cli.tun_addr6.clone() {
        base.tun_addr6 = Some(v);
    }
    if let Some(v) = cli.tun_prefix6 {
        base.tun_prefix6 = Some(v);
    }
    if let Some(v) = cli.tun_mtu {
        base.tun_mtu = v;
    }
    if let Some(v) = cli.nat {
        base.enable_nat = v;
    }
    if let Some(v) = cli.nat_iface.clone() {
        base.nat_out_iface = Some(v);
    }
    if let Some(v) = cli.max_sessions_per_peer {
        base.max_sessions_per_peer = v;
    }
    if cli.verbose {
        base.log_level = Some("debug".to_string());
    } else if let Some(v) = cli.log_level.clone() {
        base.log_level = Some(v);
    }
    base
}

/// Merge client defaults, file config, and CLI overrides (CLI wins).
pub fn merge_client_config(
    mut base: ClientConfig,
    file: ClientFileConfig,
    cli: &ClientCliOverrides,
) -> ClientConfig {
    if let Some(v) = file.server {
        base.server = v;
    }
    if let Some(v) = file.server_key {
        base.server_pubkey_hex = v;
    }
    if let Some(v) = file.key_path {
        base.key_path = v;
    }
    if let Some(v) = file.ipc_path {
        base.ipc_path = v;
    }
    if let Some(v) = file.route_all {
        base.route_all = v;
    }
    if let Some(v) = file.route_path {
        base.route_path = Some(v);
    }
    if let Some(v) = file.reconnect {
        base.reconnect = v;
    }
    if let Some(v) = file.dns_leak_protection {
        base.dns_leak_protection = v;
    }
    if let Some(v) = file.dns {
        base.dns = Some(v.into_iter().filter(|s| !s.is_empty()).collect());
    }
    if let Some(v) = file.kill_switch {
        base.kill_switch = v;
    }
    if let Some(v) = file.nat.enabled {
        base.enable_nat = v;
    }
    if let Some(v) = file.nat.source_cidr {
        base.nat_source_cidr = Some(v);
    }
    if let Some(v) = file.log_level {
        base.log_level = Some(v);
    }
    if let Some(v) = file.log_file {
        base.log_file = Some(v);
    }
    if let Some(v) = file.tun.name {
        base.tun_name = v;
    }
    if let Some(v) = file.tun.addr {
        base.tun_addr = v;
    }
    if let Some(v) = file.tun.prefix {
        base.tun_prefix = v;
    }
    if let Some(v) = file.tun.addr6 {
        base.tun_addr6 = Some(v);
    }
    if let Some(v) = file.tun.prefix6 {
        base.tun_prefix6 = Some(v);
    }
    if let Some(v) = file.tun.mtu {
        base.tun_mtu = v;
    }
    if let Some(v) = file.obfuscation {
        base.obfuscation = Some(v);
    }
    if let Some(v) = file.fec {
        if let Some(x) = v.scheme {
            base.fec.scheme = x;
        }
        if let Some(x) = v.k {
            base.fec.k = x;
        }
        if let Some(x) = v.min_m {
            base.fec.min_m = x;
        }
        if let Some(x) = v.max_m {
            base.fec.max_m = x;
        }
        if let Some(x) = v.initial_m {
            base.fec.initial_m = x;
        }
    }
    if let Some(v) = file.handshake {
        base.handshake = v;
    }
    if let Some(v) = file.crypto {
        base.crypto = v;
    }
    if let Some(v) = file.transport {
        base.transport = v;
    }
    if let Some(v) = file.congestion {
        base.congestion = v;
    }

    // CLI overrides.
    if let Some(v) = cli.server.clone() {
        base.server = v.parse().unwrap_or(base.server);
    }
    if let Some(v) = cli.server_key.clone() {
        base.server_pubkey_hex = v;
    }
    if let Some(v) = cli.key.clone() {
        base.key_path = v;
    }
    if let Some(v) = cli.socket.clone() {
        base.ipc_path = v;
    }
    if let Some(v) = cli.route_all {
        base.route_all = v;
    }
    if let Some(v) = cli.route_path.clone() {
        base.route_path = Some(v);
    }
    if let Some(v) = cli.reconnect {
        base.reconnect = v;
    }
    if let Some(v) = cli.dns_leak_protection {
        base.dns_leak_protection = v;
    }
    if let Some(v) = cli.dns.clone() {
        base.dns = Some(v.into_iter().filter(|s| !s.is_empty()).collect());
    }
    if let Some(v) = cli.kill_switch {
        base.kill_switch = v;
    }
    if let Some(v) = cli.enable_nat {
        base.enable_nat = v;
    }
    if let Some(v) = cli.nat_source_cidr.clone() {
        base.nat_source_cidr = Some(v);
    }
    if let Some(v) = cli.tun.clone() {
        base.tun_name = v;
    }
    if let Some(v) = cli.tun_addr.clone() {
        base.tun_addr = v;
    }
    if let Some(v) = cli.tun_prefix {
        base.tun_prefix = v;
    }
    if let Some(v) = cli.tun_addr6.clone() {
        base.tun_addr6 = Some(v);
    }
    if let Some(v) = cli.tun_prefix6 {
        base.tun_prefix6 = Some(v);
    }
    if let Some(v) = cli.tun_mtu {
        base.tun_mtu = v;
    }
    if let Some(v) = cli.log_file.clone() {
        base.log_file = Some(v);
    }
    if cli.verbose {
        base.log_level = Some("debug".to_string());
    } else if let Some(v) = cli.log_level.clone() {
        base.log_level = Some(v);
    }
    base
}

// ---------------------------------------------------------------------------
// CLI override bundles
// ---------------------------------------------------------------------------
//
// These are filled in by the CLI layer from the parsed `clap` subcommand
// variants. A field is `Some` only when the user actually passed that flag,
// so the merge functions can apply the "CLI wins, but only if present" rule.
// They live here (not in `cli.rs`) so the merge logic and the override shape
// stay in one place.

#[derive(Debug, Default, Clone)]
pub struct ServerCliOverrides {
    pub listen: Option<String>,
    pub tun: Option<String>,
    pub tun_addr: Option<String>,
    pub tun_prefix: Option<u8>,
    pub tun_addr6: Option<String>,
    pub tun_prefix6: Option<u8>,
    pub tun_mtu: Option<u32>,
    pub key: Option<PathBuf>,
    pub nat: Option<bool>,
    pub nat_iface: Option<String>,
    pub socket: Option<PathBuf>,
    pub log_level: Option<String>,
    pub verbose: bool,
    pub log_file: Option<PathBuf>,
    pub max_sessions_per_peer: Option<u8>,
}

#[derive(Debug, Default, Clone)]
pub struct ClientCliOverrides {
    pub server: Option<String>,
    pub server_key: Option<String>,
    pub tun: Option<String>,
    pub tun_addr: Option<String>,
    pub tun_prefix: Option<u8>,
    pub tun_addr6: Option<String>,
    pub tun_prefix6: Option<u8>,
    pub tun_mtu: Option<u32>,
    pub key: Option<PathBuf>,
    pub socket: Option<PathBuf>,
    pub route_all: Option<bool>,
    pub route_path: Option<PathBuf>,
    pub reconnect: Option<bool>,
    pub dns_leak_protection: Option<bool>,
    pub dns: Option<Vec<String>>,
    pub kill_switch: Option<bool>,
    pub enable_nat: Option<bool>,
    pub nat_source_cidr: Option<String>,
    pub log_level: Option<String>,
    pub verbose: bool,
    pub log_file: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_file_partial_overrides_defaults() {
        let toml = r#"
key_path = "/tmp/k.key"
log_level = "debug"

[tun]
addr = "10.9.0.1"
mtu = 1280

[nat]
enabled = false
"#;
        let file = ServerFileConfig::from_toml(toml).unwrap();
        let merged = merge_server_config(
            ServerConfig::default(),
            file,
            &ServerCliOverrides::default(),
        );
        assert_eq!(merged.key_path, PathBuf::from("/tmp/k.key"));
        assert_eq!(merged.log_level.as_deref(), Some("debug"));
        assert_eq!(merged.tun_addr, "10.9.0.1");
        assert_eq!(merged.tun_mtu, 1280);
        // Untouched fields keep defaults.
        assert_eq!(merged.tun_name, "rustnies");
        assert_eq!(merged.tun_prefix, 24);
        assert_eq!(merged.enable_nat, false);
        assert_eq!(merged.listen, "0.0.0.0:46722".parse().unwrap());
    }

    #[test]
    fn cli_overrides_file_overrides_default() {
        let toml = r#"
listen = "1.2.3.4:9000"
[tun]
name = "fromfile"
mtu = 1000
"#;
        let file = ServerFileConfig::from_toml(toml).unwrap();
        let cli = ServerCliOverrides {
            tun: Some("fromcli".to_string()),
            ..Default::default()
        };
        let merged = merge_server_config(ServerConfig::default(), file, &cli);
        // CLI tun name wins over file; file listen wins over default.
        assert_eq!(merged.tun_name, "fromcli");
        assert_eq!(merged.listen, "1.2.3.4:9000".parse().unwrap());
        // File mtu untouched by CLI.
        assert_eq!(merged.tun_mtu, 1000);
    }

    #[test]
    fn cli_verbose_forces_debug() {
        let toml = r#"log_level = "error""#;
        let file = ServerFileConfig::from_toml(toml).unwrap();
        let cli = ServerCliOverrides {
            verbose: true,
            ..Default::default()
        };
        let merged = merge_server_config(ServerConfig::default(), file, &cli);
        assert_eq!(merged.log_level.as_deref(), Some("debug"));
    }

    #[test]
    fn cli_log_level_overrides_file_log_level() {
        let toml = r#"log_level = "error""#;
        let file = ServerFileConfig::from_toml(toml).unwrap();
        let cli = ServerCliOverrides {
            log_level: Some("trace".to_string()),
            ..Default::default()
        };
        let merged = merge_server_config(ServerConfig::default(), file, &cli);
        assert_eq!(merged.log_level.as_deref(), Some("trace"));
    }

    #[test]
    fn missing_default_path_is_empty() {
        let path = PathBuf::from("/nonexistent/rustnies-test-12345.toml");
        let f = ServerFileConfig::load_or_empty(&path).unwrap();
        assert!(f.listen.is_none());
        assert!(f.key_path.is_none());
    }

    #[test]
    fn client_file_partial_overrides_defaults() {
        let toml = r#"
server = "10.0.0.5:51820"
server_key = "deadbeef"
route_all = true

[tun]
name = "vpn0"
"#;
        let file = ClientFileConfig::from_toml(toml).unwrap();
        let merged = merge_client_config(
            ClientConfig::default(),
            file,
            &ClientCliOverrides::default(),
        );
        assert_eq!(merged.server, "10.0.0.5:51820".parse().unwrap());
        assert_eq!(merged.server_pubkey_hex, "deadbeef");
        assert!(merged.route_all);
        assert_eq!(merged.tun_name, "vpn0");
        // Defaults preserved.
        assert_eq!(merged.tun_mtu, 1400);
    }

    #[test]
    fn client_cli_overrides_file() {
        let toml = r#"
server = "10.0.0.5:51820"
server_key = "fromfile"
"#;
        let file = ClientFileConfig::from_toml(toml).unwrap();
        let cli = ClientCliOverrides {
            server_key: Some("fromcli".to_string()),
            ..Default::default()
        };
        let merged = merge_client_config(ClientConfig::default(), file, &cli);
        assert_eq!(merged.server_pubkey_hex, "fromcli");
    }

    #[test]
    fn client_route_path_from_file() {
        let toml = r#"
server = "10.0.0.5:51820"
server_key = "deadbeef"
route_path = "/etc/rustnies/routes.txt"
"#;
        let file = ClientFileConfig::from_toml(toml).unwrap();
        let merged = merge_client_config(
            ClientConfig::default(),
            file,
            &ClientCliOverrides::default(),
        );
        assert_eq!(
            merged.route_path.as_deref(),
            Some(std::path::Path::new("/etc/rustnies/routes.txt"))
        );
    }

    #[test]
    fn client_route_path_cli_overrides_file() {
        let toml = r#"route_path = "/from/file""#;
        let file = ClientFileConfig::from_toml(toml).unwrap();
        let cli = ClientCliOverrides {
            route_path: Some(std::path::PathBuf::from("/from/cli")),
            ..Default::default()
        };
        let merged = merge_client_config(ClientConfig::default(), file, &cli);
        assert_eq!(
            merged.route_path.as_deref(),
            Some(std::path::Path::new("/from/cli"))
        );
    }

    #[test]
    fn client_route_path_default_none() {
        let merged = merge_client_config(
            ClientConfig::default(),
            ClientFileConfig::default(),
            &ClientCliOverrides::default(),
        );
        assert!(merged.route_path.is_none());
    }

    #[test]
    fn client_dns_and_kill_switch_defaults() {
        let d = ClientConfig::default();
        assert!(d.dns_leak_protection, "DNS leak protection defaults on");
        assert!(d.dns.is_none(), "dns defaults to None (built-in 1.1.1.1)");
        assert!(!d.kill_switch, "kill switch defaults off (opt-in)");
    }

    #[test]
    fn client_dns_and_kill_switch_from_file() {
        let toml = r#"
server = "10.0.0.5:51820"
server_key = "deadbeef"
dns_leak_protection = false
dns = ["1.1.1.1", "8.8.8.8"]
kill_switch = true
"#;
        let file = ClientFileConfig::from_toml(toml).unwrap();
        let merged = merge_client_config(
            ClientConfig::default(),
            file,
            &ClientCliOverrides::default(),
        );
        assert!(!merged.dns_leak_protection);
        assert_eq!(
            merged.dns.as_deref(),
            Some(&["1.1.1.1".to_string(), "8.8.8.8".to_string()][..])
        );
        assert!(merged.kill_switch);
    }

    #[test]
    fn client_dns_and_kill_switch_cli_overrides_file() {
        let toml = r#"
dns = ["8.8.8.8"]
kill_switch = false
"#;
        let file = ClientFileConfig::from_toml(toml).unwrap();
        let cli = ClientCliOverrides {
            dns: Some(vec!["1.1.1.1".to_string()]),
            kill_switch: Some(true),
            dns_leak_protection: Some(false),
            ..Default::default()
        };
        let merged = merge_client_config(ClientConfig::default(), file, &cli);
        assert_eq!(merged.dns.as_deref(), Some(&["1.1.1.1".to_string()][..]));
        assert!(merged.kill_switch, "CLI --kill-switch overrides file");
        assert!(
            !merged.dns_leak_protection,
            "CLI --no-dns-leak-protection overrides default"
        );
    }

    #[test]
    fn client_nat_defaults_to_enabled_with_no_source() {
        let merged = merge_client_config(
            ClientConfig::default(),
            ClientFileConfig::default(),
            &ClientCliOverrides::default(),
        );
        assert!(merged.enable_nat, "client NAT defaults on (opt-out)");
        assert!(
            merged.nat_source_cidr.is_none(),
            "source CIDR defaults to None (all)"
        );
    }

    #[test]
    fn client_nat_section_overrides_file() {
        let toml = r#"
[nat]
enabled = false
source_cidr = "192.168.50.0/24"
"#;
        let file = ClientFileConfig::from_toml(toml).unwrap();
        let merged = merge_client_config(
            ClientConfig::default(),
            file,
            &ClientCliOverrides::default(),
        );
        assert!(!merged.enable_nat);
        assert_eq!(merged.nat_source_cidr.as_deref(), Some("192.168.50.0/24"));
    }

    #[test]
    fn client_nat_cli_overrides_file() {
        let toml = r#"
[nat]
enabled = false
"#;
        let file = ClientFileConfig::from_toml(toml).unwrap();
        let cli = ClientCliOverrides {
            enable_nat: Some(true),
            nat_source_cidr: Some("10.0.0.0/8".to_string()),
            ..Default::default()
        };
        let merged = merge_client_config(ClientConfig::default(), file, &cli);
        assert!(
            merged.enable_nat,
            "CLI enable_nat=true overrides file enabled=false"
        );
        assert_eq!(merged.nat_source_cidr.as_deref(), Some("10.0.0.0/8"));
    }

    #[test]
    fn client_empty_dns_list_skips_resolv_rewrite() {
        let toml = r#"dns = []"#;
        let file = ClientFileConfig::from_toml(toml).unwrap();
        let merged = merge_client_config(
            ClientConfig::default(),
            file,
            &ClientCliOverrides::default(),
        );
        assert_eq!(merged.dns.as_deref(), Some(&[][..]));
    }

    #[test]
    fn server_inline_peers_parsed() {
        let toml = r#"
[[peers]]
public_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
name = "alice"
"#;
        let file = ServerFileConfig::from_toml(toml).unwrap();
        let peers = file.peers.as_ref().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(
            peers[0].public_key,
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        );
        assert_eq!(peers[0].name.as_deref(), Some("alice"));
        let merged = merge_server_config(
            ServerConfig::default(),
            file,
            &ServerCliOverrides::default(),
        );
        assert!(merged.peers.is_some());
        assert_eq!(merged.peers.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn server_peers_section_optional_means_open_mode() {
        // No [[peers]] section at all → None → open mode.
        let toml = r#"
listen = "0.0.0.0:51820"
"#;
        let file = ServerFileConfig::from_toml(toml).unwrap();
        assert!(file.peers.is_none());
        let merged = merge_server_config(
            ServerConfig::default(),
            file,
            &ServerCliOverrides::default(),
        );
        assert!(merged.peers.is_none());
    }

    #[test]
    fn server_empty_peers_array_rejects_all() {
        // An explicit empty peers = [] → Some([]) → reject all (not open mode).
        let toml = r#"peers = []"#;
        let file = ServerFileConfig::from_toml(toml).unwrap();
        let merged = merge_server_config(
            ServerConfig::default(),
            file,
            &ServerCliOverrides::default(),
        );
        let peers = merged.peers.as_ref().unwrap();
        assert!(peers.is_empty());
    }

    #[test]
    fn empty_toml_keeps_defaults() {
        let file = ServerFileConfig::from_toml("").unwrap();
        let merged = merge_server_config(
            ServerConfig::default(),
            file,
            &ServerCliOverrides::default(),
        );
        let d = ServerConfig::default();
        assert_eq!(merged.listen, d.listen);
        assert_eq!(merged.tun_mtu, d.tun_mtu);
        assert_eq!(merged.enable_nat, d.enable_nat);
    }

    #[test]
    fn server_unknown_top_level_key_is_warned_not_rejected() {
        // Unknown top-level keys should be warned about (via tracing) but not
        // cause a hard error, so a typo does not prevent the daemon from
        // starting.
        let toml = r#"key = "server.key""#;
        let result = ServerFileConfig::from_toml(toml);
        assert!(
            result.is_ok(),
            "unknown field should be warned, not rejected"
        );
    }

    #[test]
    fn client_unknown_top_level_key_is_warned_not_rejected() {
        let toml = r#"
server = "10.0.0.5:51820"
key = "client.key"
"#;
        let result = ClientFileConfig::from_toml(toml);
        assert!(
            result.is_ok(),
            "unknown field should be warned, not rejected"
        );
    }

    #[test]
    fn server_unknown_section_is_warned_not_rejected() {
        let toml = r#"
key_path = "/tmp/k.key"
[nonexistent_section]
whatever = "hello"
"#;
        let result = ServerFileConfig::from_toml(toml);
        assert!(
            result.is_ok(),
            "unknown section should be warned, not rejected"
        );
    }

    #[test]
    fn client_unknown_section_is_warned_not_rejected() {
        let toml = r#"
server = "10.0.0.5:51820"
server_key = "deadbeef"
[invalid_section]
xyz = "abc"
"#;
        let result = ClientFileConfig::from_toml(toml);
        assert!(
            result.is_ok(),
            "unknown section should be warned, not rejected"
        );
    }

    #[test]
    fn server_unknown_nested_tun_field_is_warned_not_rejected() {
        let toml = r#"
[tun]
addr = "10.9.0.1"
bogus_field = true
"#;
        let file = ServerFileConfig::from_toml(toml).unwrap();
        assert_eq!(file.tun.addr.as_deref(), Some("10.9.0.1"));
    }

    #[test]
    fn server_unknown_nested_nat_field_is_warned_not_rejected() {
        let toml = r#"
[nat]
enabled = true
fake_nat_setting = 42
"#;
        let file = ServerFileConfig::from_toml(toml).unwrap();
        assert_eq!(file.nat.enabled, Some(true));
    }

    #[test]
    fn server_unknown_nested_obfuscation_field_is_warned_not_rejected() {
        let toml = r#"
[obfuscation]
layers = ["padding"]
fake_obf_setting = 99
"#;
        let file = ServerFileConfig::from_toml(toml).unwrap();
        let obf = file.obfuscation.as_ref().unwrap();
        assert_eq!(obf.layers, vec!["padding"]);
    }

    #[test]
    fn server_unknown_nested_peer_field_is_warned_not_rejected() {
        let toml = r#"
[[peers]]
public_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
name = "alice"
bogus_peer_field = true
"#;
        let file = ServerFileConfig::from_toml(toml).unwrap();
        let peers = file.peers.as_ref().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name.as_deref(), Some("alice"));
    }

    #[test]
    fn client_unknown_nested_tun_field_is_warned_not_rejected() {
        let toml = r#"
server = "10.0.0.5:51820"
server_key = "deadbeef"
[tun]
name = "vpn0"
bogus_tun = true
"#;
        let file = ClientFileConfig::from_toml(toml).unwrap();
        assert_eq!(file.tun.name.as_deref(), Some("vpn0"));
    }

    #[test]
    fn client_unknown_nested_obfuscation_field_is_warned_not_rejected() {
        let toml = r#"
server = "10.0.0.5:51820"
server_key = "deadbeef"
[obfuscation]
layers = ["timing"]
bogus_obf = 42
"#;
        let file = ClientFileConfig::from_toml(toml).unwrap();
        let obf = file.obfuscation.as_ref().unwrap();
        assert_eq!(obf.layers, vec!["timing"]);
    }

    #[test]
    fn server_default_key_path_is_empty() {
        assert!(ServerConfig::default().key_path.as_os_str().is_empty());
    }

    #[test]
    fn client_default_key_path_is_empty() {
        assert!(ClientConfig::default().key_path.as_os_str().is_empty());
    }

    #[test]
    fn pick_helper_order() {
        assert_eq!(pick(Some(1), Some(2), 3), 1);
        assert_eq!(pick(None, Some(2), 3), 2);
        assert_eq!(pick(None, None, 3), 3);
    }

    // ---- obfuscation config tests ----

    #[test]
    fn obfuscation_defaults_to_none() {
        let d = ServerConfig::default();
        assert!(d.obfuscation.is_none(), "server obfuscation defaults off");
        let d = ClientConfig::default();
        assert!(d.obfuscation.is_none(), "client obfuscation defaults off");
    }

    #[test]
    fn server_obfuscation_section_parsed() {
        let toml = r#"
[obfuscation]
layers = ["padding", "header_xor"]
padding_buckets = [100, 200, 400]
padding_max = 500
"#;
        let file = ServerFileConfig::from_toml(toml).unwrap();
        let obf = file.obfuscation.as_ref().unwrap();
        assert_eq!(obf.layers, vec!["padding", "header_xor"]);
        assert_eq!(obf.padding_buckets, vec![100, 200, 400]);
        assert_eq!(obf.padding_max, 500);
        let merged = merge_server_config(
            ServerConfig::default(),
            file,
            &ServerCliOverrides::default(),
        );
        let obf = merged.obfuscation.unwrap();
        assert_eq!(obf.layers, vec!["padding", "header_xor"]);
    }

    #[test]
    fn client_obfuscation_section_parsed() {
        let toml = r#"
server = "10.0.0.5:51820"
server_key = "deadbeef"

[obfuscation]
layers = ["timing"]
timing_max_jitter_us = 5000
timing_decoy_interval_ms = 100
timing_decoy_max_len = 128
"#;
        let file = ClientFileConfig::from_toml(toml).unwrap();
        let obf = file.obfuscation.as_ref().unwrap();
        assert_eq!(obf.layers, vec!["timing"]);
        assert_eq!(obf.timing_max_jitter_us, 5000);
        assert_eq!(obf.timing_decoy_interval_ms, 100);
        assert_eq!(obf.timing_decoy_max_len, 128);
        let merged = merge_client_config(
            ClientConfig::default(),
            file,
            &ClientCliOverrides::default(),
        );
        let obf = merged.obfuscation.unwrap();
        assert_eq!(obf.layers, vec!["timing"]);
        assert_eq!(obf.timing_max_jitter_us, 5000);
    }

    #[test]
    fn empty_obfuscation_layers_is_off() {
        let toml = r#"
[obfuscation]
layers = []
"#;
        let file = ServerFileConfig::from_toml(toml).unwrap();
        let obf = file.obfuscation.as_ref().unwrap();
        assert!(obf.layers.is_empty());
        let merged = merge_server_config(
            ServerConfig::default(),
            file,
            &ServerCliOverrides::default(),
        );
        let obf = merged.obfuscation.unwrap();
        assert!(
            obf.layers.is_empty(),
            "empty layers = off but section present"
        );
    }

    #[test]
    fn no_obfuscation_section_means_none() {
        let toml = r#"listen = "0.0.0.0:51820""#;
        let file = ServerFileConfig::from_toml(toml).unwrap();
        assert!(
            file.obfuscation.is_none(),
            "no [obfuscation] section -> None"
        );
    }

    #[test]
    fn obfuscation_config_default_is_empty() {
        let c = ObfuscationConfig::default();
        assert!(c.layers.is_empty());
        assert!(c.padding_buckets.is_empty());
        assert_eq!(c.padding_max, 0);
        assert_eq!(c.timing_max_jitter_us, 0);
        assert_eq!(c.timing_decoy_interval_ms, 0);
        assert_eq!(c.timing_decoy_max_len, 0);
    }

    /// The default IPC socket path is a fixed, well-known location (not
    /// derived from `TMPDIR`/`temp_dir()`) so the daemon and the CLI agree on
    /// where to meet across privilege boundaries. Both roles resolve to the
    /// same path under `/run/rustnies/`, matching the install templates and the
    /// systemd `RuntimeDirectory=rustnies` unit.
    #[test]
    fn default_ipc_path_is_fixed_run_location() {
        assert_eq!(
            default_ipc_path(),
            PathBuf::from("/run/rustnies/rustnies.sock")
        );
        // The runtime defaults must agree with the helper.
        assert_eq!(ServerConfig::default().ipc_path, default_ipc_path());
        assert_eq!(ClientConfig::default().ipc_path, default_ipc_path());
    }

    // ---- log_file tests ----

    #[test]
    fn server_log_file_defaults_to_none() {
        assert!(
            ServerConfig::default().log_file.is_none(),
            "log_file defaults to None (stdout only)"
        );
    }

    #[test]
    fn client_log_file_defaults_to_none() {
        assert!(
            ClientConfig::default().log_file.is_none(),
            "log_file defaults to None (stdout only)"
        );
    }

    #[test]
    fn server_log_file_from_file_config() {
        let toml = r#"key_path = "/tmp/k.key"
log_file = "/var/log/rustnies/server.log"
"#;
        let file = ServerFileConfig::from_toml(toml).unwrap();
        assert_eq!(
            file.log_file.as_deref(),
            Some(std::path::Path::new("/var/log/rustnies/server.log"))
        );
        let merged = merge_server_config(
            ServerConfig::default(),
            file,
            &ServerCliOverrides::default(),
        );
        assert_eq!(
            merged.log_file.as_deref(),
            Some(std::path::Path::new("/var/log/rustnies/server.log"))
        );
    }

    #[test]
    fn server_log_file_cli_overrides_file() {
        let toml = r#"log_file = "/from/file""#;
        let file = ServerFileConfig::from_toml(toml).unwrap();
        let cli = ServerCliOverrides {
            log_file: Some(std::path::PathBuf::from("/from/cli")),
            ..Default::default()
        };
        let merged = merge_server_config(ServerConfig::default(), file, &cli);
        assert_eq!(
            merged.log_file.as_deref(),
            Some(std::path::Path::new("/from/cli"))
        );
    }

    #[test]
    fn client_log_file_from_file_config() {
        let toml = r#"
server = "10.0.0.5:51820"
server_key = "deadbeef"
log_file = "/var/log/rustnies/client.log"
"#;
        let file = ClientFileConfig::from_toml(toml).unwrap();
        let merged = merge_client_config(
            ClientConfig::default(),
            file,
            &ClientCliOverrides::default(),
        );
        assert_eq!(
            merged.log_file.as_deref(),
            Some(std::path::Path::new("/var/log/rustnies/client.log"))
        );
    }

    #[test]
    fn client_log_file_cli_overrides_file() {
        let toml = r#"
server = "10.0.0.5:51820"
server_key = "deadbeef"
log_file = "/from/file"
"#;
        let file = ClientFileConfig::from_toml(toml).unwrap();
        let cli = ClientCliOverrides {
            log_file: Some(std::path::PathBuf::from("/from/cli")),
            ..Default::default()
        };
        let merged = merge_client_config(ClientConfig::default(), file, &cli);
        assert_eq!(
            merged.log_file.as_deref(),
            Some(std::path::Path::new("/from/cli"))
        );
    }

    #[test]
    fn log_file_not_in_file_kills_unknown_key_warning() {
        // `log_file` must be a known key so it does not trigger a warning.
        // We verify this indirectly: the field is present in both schemas and
        // the file parses without error.
        let server_toml = r#"key_path = "/tmp/k.key"
log_file = "/var/log/rustnies/s.log"
"#;
        let client_toml = r#"
server = "10.0.0.5:51820"
server_key = "deadbeef"
log_file = "/var/log/rustnies/c.log"
"#;
        assert!(ServerFileConfig::from_toml(server_toml).is_ok());
        assert!(ClientFileConfig::from_toml(client_toml).is_ok());
    }

    // ---- Protocol profile sections -------------------------------------
    //
    // The four sections that select which implementation of each swappable
    // protocol part a session runs. See `doc/profiles.md`. These tests cover
    // parsing, the merge into the runtime config, and the defaults, because a
    // mistake in any of those silently changes what a deployment negotiates.

    const FULL_PROFILE_TOML: &str = r#"
[handshake]
kex = "noise-ik"
propose = true

[crypto]
aead = ["chacha20poly1305"]

[transport]
handshake = "plain"
data = ["tagged", "same-as-handshake"]
tag_hex = "abcd"

[fec]
scheme = ["reed-solomon"]
k = 2
min_m = 1
max_m = 6
initial_m = 3

[congestion]
algorithm = "none"
"#;

    #[test]
    fn profile_sections_parse_on_the_server_side() {
        let file = ServerFileConfig::from_toml(FULL_PROFILE_TOML).unwrap();
        let h = file.handshake.unwrap();
        assert_eq!(h.kex, "noise-ik");
        assert!(h.propose);
        assert_eq!(file.crypto.unwrap().aead, ["chacha20poly1305"]);
        let t = file.transport.unwrap();
        assert_eq!(t.handshake, "plain");
        assert_eq!(t.data, ["tagged", "same-as-handshake"]);
        assert_eq!(t.tag_hex.as_deref(), Some("abcd"));
        let f = file.fec.unwrap();
        assert_eq!(f.scheme.as_deref(), Some(&["reed-solomon".to_string()][..]));
        assert_eq!(f.k, Some(2));
        assert_eq!(file.congestion.unwrap().algorithm, "none");
    }

    #[test]
    fn profile_sections_parse_on_the_client_side() {
        // The client config has the same four sections; a key that only existed
        // on the server would be silently ignored here.
        let file = ClientFileConfig::from_toml(FULL_PROFILE_TOML).unwrap();
        assert!(file.handshake.unwrap().propose);
        assert_eq!(file.crypto.unwrap().aead, ["chacha20poly1305"]);
        assert_eq!(file.transport.unwrap().data.len(), 2);
        assert_eq!(file.fec.unwrap().k, Some(2));
        assert_eq!(file.congestion.unwrap().algorithm, "none");
    }

    #[test]
    fn profile_sections_merge_into_the_server_runtime_config() {
        let file = ServerFileConfig::from_toml(FULL_PROFILE_TOML).unwrap();
        let merged = merge_server_config(
            ServerConfig::default(),
            file,
            &ServerCliOverrides::default(),
        );
        assert_eq!(merged.handshake.kex, "noise-ik");
        assert!(merged.handshake.propose);
        assert_eq!(merged.crypto.aead, ["chacha20poly1305"]);
        assert_eq!(merged.transport.handshake, "plain");
        assert_eq!(merged.transport.data, ["tagged", "same-as-handshake"]);
        assert_eq!(merged.transport.tag_hex.as_deref(), Some("abcd"));
        assert_eq!(merged.fec.scheme, ["reed-solomon"]);
        assert_eq!(merged.fec.k, 2);
        assert_eq!(merged.fec.max_m, 6);
        assert_eq!(merged.congestion.algorithm, "none");
    }

    #[test]
    fn profile_sections_merge_into_the_client_runtime_config() {
        let file = ClientFileConfig::from_toml(FULL_PROFILE_TOML).unwrap();
        let merged = merge_client_config(
            ClientConfig::default(),
            file,
            &ClientCliOverrides::default(),
        );
        assert!(merged.handshake.propose);
        assert_eq!(merged.crypto.aead, ["chacha20poly1305"]);
        assert_eq!(merged.transport.data, ["tagged", "same-as-handshake"]);
        assert_eq!(merged.fec.scheme, ["reed-solomon"]);
        assert_eq!(merged.congestion.algorithm, "none");
    }

    #[test]
    fn absent_profile_sections_leave_the_defaults() {
        // An empty config file must resolve to the rustnies defaults, which is
        // what keeps an unconfigured deployment on the pre-negotiation protocol.
        let file = ServerFileConfig::from_toml("").unwrap();
        let merged = merge_server_config(
            ServerConfig::default(),
            file,
            &ServerCliOverrides::default(),
        );
        let d = ServerConfig::default();
        assert_eq!(merged.handshake, d.handshake);
        assert_eq!(merged.crypto, d.crypto);
        assert_eq!(merged.transport, d.transport);
        assert_eq!(merged.congestion, d.congestion);
        assert_eq!(merged.fec.scheme, d.fec.scheme);
        assert!(!merged.handshake.propose, "proposing is opt-in");
    }

    #[test]
    fn an_empty_profile_section_keeps_the_defaults() {
        let file =
            ServerFileConfig::from_toml("[handshake]\n[crypto]\n[transport]\n[congestion]\n")
                .unwrap();
        let merged = merge_server_config(
            ServerConfig::default(),
            file,
            &ServerCliOverrides::default(),
        );
        let d = ServerConfig::default();
        assert_eq!(merged.handshake, d.handshake);
        assert_eq!(merged.crypto, d.crypto);
        assert_eq!(merged.transport, d.transport);
        assert_eq!(merged.congestion, d.congestion);
    }

    #[test]
    fn a_partial_fec_section_leaves_the_other_scalars_alone() {
        // `FecSection` is all-`Option`, so naming one key must not reset the rest
        // to a serde default.
        let file = ServerFileConfig::from_toml("[fec]\nmax_m = 7\n").unwrap();
        let merged = merge_server_config(
            ServerConfig::default(),
            file,
            &ServerCliOverrides::default(),
        );
        assert_eq!(merged.fec.max_m, 7);
        assert_eq!(merged.fec.k, FecConfig::default().k);
        assert_eq!(merged.fec.min_m, FecConfig::default().min_m);
        assert_eq!(merged.fec.initial_m, FecConfig::default().initial_m);
    }

    /// `warn_unknown_keys` walks a static schema rather than rejecting, so a key
    /// missing from a `SectionSchema` is *silently dropped with a warning*. That
    /// makes the schema a real correctness dependency: forget a key there and a
    /// valid config setting quietly does nothing.
    ///
    /// These tests assert every key of every profile section survives a
    /// round-trip, which is what would break if the schema and the struct ever
    /// drifted apart.
    #[test]
    fn every_profile_section_key_round_trips() {
        let server = ServerFileConfig::from_toml(FULL_PROFILE_TOML).unwrap();
        assert!(server.handshake.is_some());
        assert!(server.crypto.is_some());
        assert!(server.transport.is_some());
        assert!(server.fec.is_some());
        assert!(server.congestion.is_some());

        let client = ClientFileConfig::from_toml(FULL_PROFILE_TOML).unwrap();
        assert!(client.handshake.is_some());
        assert!(client.crypto.is_some());
        assert!(client.transport.is_some());
        assert!(client.fec.is_some());
        assert!(client.congestion.is_some());

        // The schemas must list the same key names the structs declare, at the
        // right nesting level. Assert them literally so adding a field without
        // updating the schema fails here.
        for schema in [
            &HANDSHAKE_SCHEMA,
            &CRYPTO_SCHEMA,
            &TRANSPORT_SCHEMA,
            &FEC_SCHEMA,
            &CONGESTION_SCHEMA,
        ] {
            assert!(
                schema.scalars.iter().all(|k| !k.is_empty()),
                "schema keys must be non-empty"
            );
        }
        assert_eq!(HANDSHAKE_SCHEMA.scalars, ["kex", "propose"]);
        assert_eq!(CRYPTO_SCHEMA.scalars, ["aead"]);
        assert_eq!(TRANSPORT_SCHEMA.scalars, ["handshake", "data", "tag_hex"]);
        assert_eq!(
            FEC_SCHEMA.scalars,
            ["scheme", "k", "min_m", "max_m", "initial_m"]
        );
        assert_eq!(CONGESTION_SCHEMA.scalars, ["algorithm"]);

        // And the sections must be reachable from the top level of both roles.
        for tables in [&SERVER_SCHEMA.tables, &CLIENT_SCHEMA.tables] {
            for name in ["handshake", "crypto", "transport", "fec", "congestion"] {
                assert!(
                    tables.iter().any(|(n, _)| *n == name),
                    "[{name}] must be in the top-level schema tables"
                );
            }
        }
    }

    #[test]
    fn the_default_profile_config_resolves_to_a_usable_local_profile() {
        // End-to-end through the real resolution path: a default config must
        // produce a profile the daemon can actually run.
        let defaults = ServerConfig::default();
        let profile = crate::protocol::profile::LocalProfile::from_role_config(
            &defaults.handshake,
            &defaults.crypto,
            &defaults.transport,
            &defaults.fec,
            &defaults.congestion,
        )
        .expect("the default config must resolve to a usable profile");
        assert_eq!(
            profile.kex_name,
            crate::protocol::handshake::DEFAULT_HANDSHAKE
        );
        assert!(!profile.propose);
        assert!(profile.offer().is_none());
        assert_eq!(
            profile.congestion_name,
            crate::congestion::DEFAULT_CONGESTION
        );
    }

    #[test]
    fn a_config_file_profile_resolves_to_a_usable_local_profile() {
        let file = ServerFileConfig::from_toml(FULL_PROFILE_TOML).unwrap();
        let merged = merge_server_config(
            ServerConfig::default(),
            file,
            &ServerCliOverrides::default(),
        );
        let profile = crate::protocol::profile::LocalProfile::from_role_config(
            &merged.handshake,
            &merged.crypto,
            &merged.transport,
            &merged.fec,
            &merged.congestion,
        )
        .expect("a well-formed profile config must resolve");
        assert!(profile.propose);
        assert_eq!(profile.data_tag, [0xAB, 0xCD]);
        assert_eq!(profile.congestion_name, "none");
        let offer = profile.offer().unwrap();
        assert_eq!(
            offer.cipher_ids,
            [crate::crypto::suite::CIPHER_CHACHA20POLY1305]
        );
        assert_eq!(offer.transport_ids, [crate::transport::TRANSPORT_TAGGED]);
    }

    #[test]
    fn a_bad_part_name_fails_profile_resolution_not_just_parsing() {
        // Parsing succeeds (the name is a string) but resolution must refuse it,
        // with the offending string in the message.
        let file = ServerFileConfig::from_toml("[crypto]\naead = [\"aes-gcm\"]\n").unwrap();
        let merged = merge_server_config(
            ServerConfig::default(),
            file,
            &ServerCliOverrides::default(),
        );
        let err = crate::protocol::profile::LocalProfile::from_role_config(
            &merged.handshake,
            &merged.crypto,
            &merged.transport,
            &merged.fec,
            &merged.congestion,
        )
        .unwrap_err();
        assert!(err.to_string().contains("aes-gcm"), "got {err}");
    }
}

#[cfg(test)]
mod dist_template_tests {
    //! The shipped `scripts/dist/*.toml` are the first config a new deployment
    //! sees. If they fail to parse, or name a part that does not resolve, a
    //! stock install breaks — so they are covered here rather than only by
    //! inspection.

    use super::*;

    fn resolve(merged: &ServerConfig) {
        crate::protocol::profile::LocalProfile::from_role_config(
            &merged.handshake,
            &merged.crypto,
            &merged.transport,
            &merged.fec,
            &merged.congestion,
        )
        .unwrap_or_else(|e| panic!("shipped server.toml must resolve a usable profile: {e}"));
    }

    #[test]
    fn the_shipped_server_template_resolves() {
        let path = "scripts/dist/server.toml";
        let file = match ServerFileConfig::load_or_empty(Path::new(path)) {
            Ok(f) => f,
            Err(e) => panic!("{path} must parse: {e}"),
        };
        let merged = merge_server_config(
            ServerConfig::default(),
            file,
            &ServerCliOverrides::default(),
        );
        // The template documents the defaults explicitly, so it must agree with
        // them — a stock install must not silently change behaviour.
        assert_eq!(merged.handshake.kex, "noise-ik");
        assert!(!merged.handshake.propose, "proposing stays opt-in");
        assert_eq!(merged.crypto.aead, ["chacha20poly1305"]);
        assert_eq!(merged.transport.handshake, "plain");
        assert_eq!(merged.transport.data, ["same-as-handshake"]);
        assert_eq!(merged.fec.scheme, ["reed-solomon"]);
        assert_eq!(merged.congestion.algorithm, "tcp-reno");
        resolve(&merged);
    }

    #[test]
    fn the_shipped_client_template_resolves() {
        let path = "scripts/dist/client.toml";
        let file = match ClientFileConfig::load_or_empty(Path::new(path)) {
            Ok(f) => f,
            Err(e) => panic!("{path} must parse: {e}"),
        };
        let merged = merge_client_config(
            ClientConfig::default(),
            file,
            &ClientCliOverrides::default(),
        );
        assert_eq!(merged.handshake.kex, "noise-ik");
        assert!(!merged.handshake.propose);
        assert_eq!(merged.crypto.aead, ["chacha20poly1305"]);
        assert_eq!(merged.transport.handshake, "plain");
        assert_eq!(merged.transport.data, ["same-as-handshake"]);
        assert_eq!(merged.fec.scheme, ["reed-solomon"]);
        assert_eq!(merged.congestion.algorithm, "tcp-reno");
        crate::protocol::profile::LocalProfile::from_role_config(
            &merged.handshake,
            &merged.crypto,
            &merged.transport,
            &merged.fec,
            &merged.congestion,
        )
        .unwrap_or_else(|e| panic!("shipped client.toml must resolve a usable profile: {e}"));
    }

    #[test]
    fn both_templates_agree_on_the_config_pinned_parts() {
        // The KEX and the handshake envelope must be named identically on both
        // sides; nothing negotiates them, so a mismatch is a silent outage.
        let s = merge_server_config(
            ServerConfig::default(),
            ServerFileConfig::load_or_empty(Path::new("scripts/dist/server.toml")).unwrap(),
            &ServerCliOverrides::default(),
        );
        let c = merge_client_config(
            ClientConfig::default(),
            ClientFileConfig::load_or_empty(Path::new("scripts/dist/client.toml")).unwrap(),
            &ClientCliOverrides::default(),
        );
        assert_eq!(s.handshake.kex, c.handshake.kex);
        assert_eq!(s.transport.handshake, c.transport.handshake);
    }
}
