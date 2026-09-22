//! Command-line interface.
//!
//! Subcommands:
//! - `server` — run the server daemon in the foreground.
//! - `client` — run the client daemon in the foreground.
//! - `status` — query a running daemon's live stats over IPC.
//! - `stop`  — tell a running daemon to tear down the tunnel.
//! - `ping`  — round-trip an IPC ping.
//! - `keygen` — generate a static keypair, persist it, write the public key
//!   to `<key>.pub`, and print the public key (hex).
//! - `pubkey` — derive and print the public key from an existing private key
//!   file (and refresh `<key>.pub`).
//!
//! `client` and `server` accept flags mirroring [`crate::config`]; `status` /
//! `stop` / `ping` target a specific IPC socket (`--socket`).
//!
//! ## Config files
//!
//! `server` and `client` also read a TOML config file. The default paths are
//! `/etc/rustnies/server.toml` and `/etc/rustnies/client.toml`; override with
//! `--config <path>`. A missing *default* path is silently ignored (the
//! pure-CLI path still works); a missing `--config` path is an error.
//!
//! Every flag here is an **override**: it only takes effect when actually
//! passed, so an omitted flag does not clobber a value set in the config file.
//! Precedence is: built-in defaults  <  config file  <  CLI flags.

use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand};

use crate::config::{
    ClientCliOverrides, ClientConfig, ClientFileConfig, ServerCliOverrides, ServerConfig,
    ServerFileConfig, default_config_path, merge_client_config, merge_server_config,
};
use crate::ipc::messages::Request;

#[derive(Debug, Parser)]
#[command(
    name = "rustnies",
    version,
    about = "rustnies VPN — phase 1 modular UDP tunnel"
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Run the server side of the tunnel.
    Server {
        /// Path to a TOML config file. Defaults to /etc/rustnies/server.toml.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Override `listen` from the config file.
        #[arg(long)]
        listen: Option<String>,
        /// Override `[tun] name`.
        #[arg(long)]
        tun: Option<String>,
        /// Override `[tun] addr`.
        #[arg(long)]
        tun_addr: Option<String>,
        /// Override `[tun] prefix`.
        #[arg(long)]
        tun_prefix: Option<u8>,
        /// Override `[tun] addr6` (IPv6 address, e.g. `fd00::1`).
        #[arg(long)]
        tun_addr6: Option<String>,
        /// Override `[tun] prefix6` (IPv6 prefix length, e.g. `64`).
        #[arg(long)]
        tun_prefix6: Option<u8>,
        /// Override `[tun] mtu`.
        #[arg(long)]
        tun_mtu: Option<u32>,
        /// Override `key_path`.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Override `[nat] enabled` (pass `true` or `false`).
        #[arg(long, action = ArgAction::Set)]
        nat: Option<bool>,
        /// Override `[nat] out_iface`.
        #[arg(long)]
        nat_iface: Option<String>,
        /// Override `ipc_path` (the daemon's IPC socket).
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Override `log_level` (a `RUST_LOG`-style filter, e.g. `info`,
        /// `debug`, `warn`, `error`, `trace`, or `rustnies::tunnel=trace`).
        #[arg(long)]
        log_level: Option<String>,
        /// Enable debug logging (equivalent to `--log-level debug`). Overrides
        /// `log_level` from the config file.
        #[arg(long, action = ArgAction::SetTrue)]
        verbose: bool,
        /// Write log lines to this file in addition to stdout (append mode).
        /// The parent directory is created if it does not exist. Override of
        /// `log_file`.
        #[arg(long)]
        log_file: Option<PathBuf>,
        /// Override the per-peer concurrent-session cap. 0 = unlimited (the
        /// default). Values like 2-4 limit how many sessions a single static
        /// peer key may have simultaneously; the oldest-idle is evicted when
        /// exceeded. Override of `max_sessions_per_peer` in the config file.
        #[arg(long)]
        max_sessions_per_peer: Option<u8>,
    },
    /// Run the client side of the tunnel.
    Client {
        /// Path to a TOML config file. Defaults to /etc/rustnies/client.toml.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Override `server` (the server UDP endpoint).
        #[arg(long)]
        server: Option<String>,
        /// Override `server_key` (the server's static public key, 32 bytes hex).
        #[arg(long)]
        server_key: Option<String>,
        /// Override `[tun] name`.
        #[arg(long)]
        tun: Option<String>,
        /// Override `[tun] addr`.
        #[arg(long)]
        tun_addr: Option<String>,
        /// Override `[tun] prefix`.
        #[arg(long)]
        tun_prefix: Option<u8>,
        /// Override `[tun] addr6` (IPv6 address, e.g. `fd00::2`).
        #[arg(long)]
        tun_addr6: Option<String>,
        /// Override `[tun] prefix6` (IPv6 prefix length, e.g. `64`).
        #[arg(long)]
        tun_prefix6: Option<u8>,
        /// Override `[tun] mtu`.
        #[arg(long)]
        tun_mtu: Option<u32>,
        /// Override `key_path`.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Override `ipc_path` (the daemon's IPC socket).
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Disable route-all. By default the client routes all traffic (not
        /// just the TUN subnet) through the tunnel by replacing the default
        /// route, after first adding a host route to the VPN server via the
        /// original gateway so tunnel traffic does not loop. Pass this to keep
        /// the default route unchanged and only route the TUN subnet.
        #[arg(long, action = ArgAction::SetTrue)]
        no_route: bool,
        /// Disable automatic reconnection. By default the client keeps trying
        /// to re-establish the tunnel after a handshake failure or session
        /// teardown (with exponential backoff) instead of exiting, and keeps
        /// the TUN device and its routes up across reconnects. Pass this to
        /// restore the original fail-fast behaviour: exit on the first
        /// disconnect.
        #[arg(long, action = ArgAction::SetTrue)]
        no_reconnect: bool,
        /// Path to a file listing extra destinations (IPs or CIDRs, one per
        /// line) to route through the TUN device. Blank lines and lines
        /// starting with `#` are ignored. Routes are added over netlink (no
        /// per-entry process spawn, so large files are fine) and removed on
        /// shutdown. Independent of `--no-route`.
        #[arg(long)]
        route_path: Option<PathBuf>,
        /// Disable DNS leak prevention. By default, when route-all is active,
        /// the client blocks DNS (port 53) from leaving via any interface other
        /// than the TUN and rewrites `/etc/resolv.conf` to point at a resolver
        /// reachable through the tunnel, so name resolution cannot leak out the
        /// real interface. Pass this to leave DNS untouched.
        #[arg(long, action = ArgAction::SetTrue)]
        no_dns_leak_protection: bool,
        /// Comma-separated resolver IPs written to `/etc/resolv.conf` while DNS
        /// leak prevention is active (default `1.1.1.1`). The resolvers must be
        /// reachable through the tunnel (public resolvers work with route-all).
        /// Pass an empty string (`--dns ""`) to skip the `resolv.conf` rewrite
        /// and only install the firewall block. Override of `dns`.
        #[arg(long, value_delimiter = ',')]
        dns: Option<Vec<String>>,
        /// Enable the kill switch: block all outbound traffic except via the
        /// TUN, to the VPN server (the encrypted tunnel UDP), and on loopback.
        /// If the tunnel drops, the client cannot fall back to the real
        /// internet — the rules are kept across reconnects and only removed on
        /// a graceful shutdown (fail closed). Enabling this forces route-all on.
        #[arg(long, action = ArgAction::SetTrue)]
        kill_switch: bool,
        /// Disable client-side NAT masquerade. By default the client installs an
        /// iptables MASQUERADE rule so a LAN behind this client can share the
        /// tunnel: forwarded traffic leaving via the TUN is rewritten to the
        /// client's tunnel address (the server only knows the client's TUN IP,
        /// not the LAN behind it). Pass this to leave forwarding untouched.
        #[arg(long, action = ArgAction::SetTrue)]
        no_nat: bool,
        /// Source CIDR for the client-side MASQUERADE (e.g.
        /// `192.168.50.0/24`). By default all traffic leaving via the TUN is
        /// masqueraded; set this to scope the rule to one LAN. Override of
        /// `[nat] source_cidr`.
        #[arg(long)]
        nat_source_cidr: Option<String>,
        /// Override `log_level` (a `RUST_LOG`-style filter, e.g. `info`,
        /// `debug`, `warn`, `error`, `trace`, or `rustnies::tunnel=trace`).
        #[arg(long)]
        log_level: Option<String>,
        /// Enable debug logging (equivalent to `--log-level debug`). Overrides
        /// `log_level` from the config file.
        #[arg(long, action = ArgAction::SetTrue)]
        verbose: bool,
        /// Write log lines to this file in addition to stdout (append mode).
        /// The parent directory is created if it does not exist. Override of
        /// `log_file`.
        #[arg(long)]
        log_file: Option<PathBuf>,
    },
    /// Show live tunnel stats from a running daemon.
    Status {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Tell a running daemon to stop.
    Stop {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Round-trip an IPC ping to a running daemon.
    Ping {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Revoke a peer's static key at runtime (server only). Rejects future
    /// handshakes from this key and evicts all live sessions for it.
    /// Runtime-only — resets on daemon restart (remove the key from the
    /// config and SIGHUP for permanent exclusion).
    Revoke {
        /// Hex-encoded 32-byte X25519 public key to revoke.
        #[arg(long)]
        peer_key: String,
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// List all live sessions on a server daemon (server only).
    ListSessions {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Disconnect a session or all sessions for a peer (server only).
    Disconnect {
        /// Disconnect a specific session by ID.
        #[arg(long)]
        session: Option<u32>,
        /// Disconnect all sessions for this peer key (hex-encoded 32 bytes).
        #[arg(long)]
        peer_key: Option<String>,
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Verify DNS leak prevention: show whether DNS queries can only reach a
    /// resolver via the tunnel and not the real interface. Reports the active
    /// `/etc/resolv.conf` nameserver, the firewall packet counters (DNS via
    /// tunnel vs. DNS blocked on the real interface), and optionally performs a
    /// live resolution to demonstrate the path. Needs root (reads iptables).
    DnsCheck {
        /// Override the `/etc/resolv.conf` path to inspect (defaults to
        /// `/etc/resolv.conf`).
        #[arg(long)]
        resolv: Option<PathBuf>,
        /// Override the TUN interface name (defaults to `rustnies0`).
        #[arg(long)]
        tun: Option<String>,
        /// Host name to resolve for the live-lookup probe (defaults to
        /// `example.com`).
        #[arg(long)]
        host: Option<String>,
    },
    /// Generate a fresh static keypair, persist it, write the public key to
    /// `<key>.pub`, and print the public key.
    Keygen {
        #[arg(long)]
        key: PathBuf,
    },
    /// Derive and print the public key from an existing private key file.
    /// Also (re)writes `<key>.pub` alongside it.
    Pubkey {
        #[arg(long)]
        key: PathBuf,
    },
}

/// Entry point used by `main.rs`.
pub async fn run() -> std::io::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Server {
            config,
            listen,
            tun,
            tun_addr,
            tun_prefix,
            tun_addr6,
            tun_prefix6,
            tun_mtu,
            key,
            nat,
            nat_iface,
            socket,
            log_level,
            verbose,
            log_file,
            max_sessions_per_peer,
        } => {
            let (file, config_path) = load_server_config(config.as_deref())?;
            let cli_overrides = ServerCliOverrides {
                listen,
                tun,
                tun_addr,
                tun_prefix,
                tun_addr6,
                tun_prefix6,
                tun_mtu,
                key,
                nat,
                nat_iface,
                socket,
                log_level,
                verbose,
                log_file,
                max_sessions_per_peer,
            };
            let mut cfg = merge_server_config(ServerConfig::default(), file, &cli_overrides);
            cfg.config_path = Some(config_path);
            crate::logging::init_tracing(cfg.log_level.as_deref(), cfg.log_file.as_deref());
            crate::daemon::run_server(cfg).await
        }
        Cmd::Client {
            config,
            server,
            server_key,
            tun,
            tun_addr,
            tun_prefix,
            tun_addr6,
            tun_prefix6,
            tun_mtu,
            key,
            socket,
            no_route,
            no_reconnect,
            route_path,
            no_dns_leak_protection,
            dns,
            kill_switch,
            no_nat,
            nat_source_cidr,
            log_level,
            verbose,
            log_file,
        } => {
            let file = load_client_config(config.as_deref())?;
            let cli_overrides = ClientCliOverrides {
                server,
                server_key,
                tun,
                tun_addr,
                tun_prefix,
                tun_addr6,
                tun_prefix6,
                tun_mtu,
                key,
                socket,
                route_all: no_route.then_some(false),
                reconnect: no_reconnect.then_some(false),
                route_path,
                dns_leak_protection: no_dns_leak_protection.then_some(false),
                dns,
                kill_switch: kill_switch.then_some(true),
                enable_nat: no_nat.then_some(false),
                nat_source_cidr,
                log_level,
                verbose,
                log_file,
            };
            let cfg = merge_client_config(ClientConfig::default(), file, &cli_overrides);
            if cfg.server_pubkey_hex.trim().is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "server public key is required: pass --server-key or set \
                     `server_key` in the client config file",
                ));
            }
            crate::logging::init_tracing(cfg.log_level.as_deref(), cfg.log_file.as_deref());
            crate::daemon::run_client(cfg).await
        }
        Cmd::Status { socket } => {
            let path = resolve_socket(socket);
            let resp = crate::ipc::request(&path, Request::Status).await?;
            match resp {
                crate::ipc::messages::Response::Status(s) => {
                    print!("{}", crate::ipc::format_stats(&s));
                    Ok(())
                }
                crate::ipc::messages::Response::Ack(m) => {
                    eprintln!("ack: {m}");
                    Ok(())
                }
                crate::ipc::messages::Response::Error(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
                other => {
                    eprintln!("unexpected response: {other:?}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::Stop { socket } => {
            let path = resolve_socket(socket);
            match crate::ipc::request(&path, Request::Stop).await? {
                crate::ipc::messages::Response::Ack(m) => {
                    println!("{m}");
                    Ok(())
                }
                other => {
                    println!("{other:?}");
                    Ok(())
                }
            }
        }
        Cmd::Ping { socket } => {
            let path = resolve_socket(socket);
            match crate::ipc::request(&path, Request::Ping).await? {
                crate::ipc::messages::Response::Ack(m) => {
                    println!("{m}");
                    Ok(())
                }
                other => {
                    println!("{other:?}");
                    Ok(())
                }
            }
        }
        Cmd::Revoke { peer_key, socket } => {
            let path = resolve_socket(socket);
            match crate::ipc::request(
                &path,
                Request::Revoke {
                    public_key: peer_key,
                },
            )
            .await?
            {
                crate::ipc::messages::Response::Ack(m) => {
                    println!("{m}");
                    Ok(())
                }
                crate::ipc::messages::Response::Error(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
                other => {
                    eprintln!("unexpected response: {other:?}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::ListSessions { socket } => {
            let path = resolve_socket(socket);
            match crate::ipc::request(&path, Request::ListSessions).await? {
                crate::ipc::messages::Response::Sessions(sessions) => {
                    if sessions.is_empty() {
                        println!("no active sessions");
                    } else {
                        for s in &sessions {
                            println!(
                                "session_id={} peer_key={} name={} addr={} roams={} age={:.1}s",
                                s.session_id,
                                s.peer_key,
                                s.peer_name.as_deref().unwrap_or("-"),
                                s.peer_addr,
                                s.roam_count,
                                s.age_secs,
                            );
                        }
                    }
                    Ok(())
                }
                crate::ipc::messages::Response::Error(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
                other => {
                    eprintln!("unexpected response: {other:?}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::Disconnect {
            session,
            peer_key,
            socket,
        } => {
            let path = resolve_socket(socket);
            match crate::ipc::request(
                &path,
                Request::Disconnect {
                    session_id: session,
                    peer_key,
                },
            )
            .await?
            {
                crate::ipc::messages::Response::Ack(m) => {
                    println!("{m}");
                    Ok(())
                }
                crate::ipc::messages::Response::Error(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
                other => {
                    eprintln!("unexpected response: {other:?}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::DnsCheck { resolv, tun, host } => {
            let resolv_path = resolv.unwrap_or_else(|| PathBuf::from("/etc/resolv.conf"));
            let tun_name = tun.unwrap_or_else(|| "rustnies0".to_string());
            let host = host.unwrap_or_else(|| "example.com".to_string());
            crate::platform::dns_check(&resolv_path, &tun_name, &host).await
        }
        Cmd::Keygen { key } => {
            let kp = crate::crypto::keys::KeyPair::load_or_create(&key)?;
            let pubkey_hex = hex::encode(kp.public_bytes());
            write_pubkey_file(&key, &pubkey_hex)?;
            println!("{pubkey_hex}");
            Ok(())
        }
        Cmd::Pubkey { key } => {
            if !key.exists() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!(
                        "private key file not found: {} (use `keygen --key` to \
                         create one)",
                        key.display()
                    ),
                ));
            }
            let kp = crate::crypto::keys::KeyPair::load_or_create(&key)?;
            let pubkey_hex = hex::encode(kp.public_bytes());
            write_pubkey_file(&key, &pubkey_hex)?;
            println!("{pubkey_hex}");
            Ok(())
        }
    }
}

/// Write the 64-char hex public key to `<key>.pub` with 0644 permissions
/// (Unix). The public key is not sensitive.
fn write_pubkey_file(key: &std::path::Path, pubkey_hex: &str) -> std::io::Result<()> {
    let pub_path = {
        let mut p = key.to_path_buf();
        let mut name = p
            .file_name()
            .map(std::ffi::OsStr::to_os_string)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "key path has no file name component",
                )
            })?;
        name.push(".pub");
        p.set_file_name(name);
        p
    };
    std::fs::write(&pub_path, pubkey_hex)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o644);
        std::fs::set_permissions(&pub_path, perms)?;
    }
    Ok(())
}

/// Load the server file config and return it along with the resolved path of
/// the file that was read (the `--config` path if given, otherwise the
/// `/etc/rustnies/server.toml` default). The path is kept on the runtime
/// config so a SIGHUP can re-read the `[[peers]]` array from the same file.
///
/// If `explicit` is given (`--config <path>`), that path is read and a missing
/// file is an error. Otherwise the default path is used and a missing file
/// yields an empty config (path is still returned so reload can pick up a file
/// created later).
fn load_server_config(
    explicit: Option<&std::path::Path>,
) -> std::io::Result<(ServerFileConfig, PathBuf)> {
    match explicit {
        Some(p) => ServerFileConfig::load_or_empty(p).and_then(|f| {
            // For an explicit --config path, a missing file should be a hard
            // error rather than silently behaving like no config.
            if !p.exists() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("config file not found: {}", p.display()),
                ));
            }
            Ok((f, p.to_path_buf()))
        }),
        None => {
            let default = default_config_path("server");
            ServerFileConfig::load_or_empty(&default).map(|f| (f, default))
        }
    }
}

/// Load the client file config. See [`load_server_config`].
fn load_client_config(explicit: Option<&std::path::Path>) -> std::io::Result<ClientFileConfig> {
    match explicit {
        Some(p) => ClientFileConfig::load_or_empty(p).and_then(|f| {
            if !p.exists() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("config file not found: {}", p.display()),
                ));
            }
            Ok(f)
        }),
        None => {
            let default = default_config_path("client");
            ClientFileConfig::load_or_empty(&default)
        }
    }
}

fn resolve_socket(socket: Option<PathBuf>) -> PathBuf {
    socket.unwrap_or_else(crate::config::default_ipc_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_pubkey_file_writes_hex_with_0644() {
        let dir = std::env::temp_dir().join(format!("rustnies-cli-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("server.key");

        let kp = crate::crypto::keys::KeyPair::generate();
        let pubkey_hex = hex::encode(kp.public_bytes());
        std::fs::write(&key_path, kp.secret.to_bytes()).unwrap();
        write_pubkey_file(&key_path, &pubkey_hex).unwrap();

        let pub_path = dir.join("server.key.pub");
        let written = std::fs::read_to_string(&pub_path).unwrap();
        assert_eq!(written, pubkey_hex);
        assert_eq!(written.len(), 64);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&pub_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o644);
        }

        // Re-deriving from the private key file matches the written pub file.
        let reloaded = crate::crypto::keys::KeyPair::load_or_create(&key_path).unwrap();
        assert_eq!(reloaded.public_bytes(), kp.public_bytes());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--dns` with comma-separated values parses into a list; an empty
    /// `--dns ""` is filtered by the merge into an empty list (so the daemon
    /// skips the resolv.conf rewrite and installs only the firewall block, as
    /// documented).
    #[test]
    fn dns_flag_parsing_and_merge() {
        use crate::config::{
            ClientCliOverrides, ClientConfig, ClientFileConfig, merge_client_config,
        };

        // Comma-separated -> list.
        let cli = Cli::parse_from(["rustnies", "client", "--dns", "1.1.1.1,8.8.8.8"]);
        let dns = match cli.cmd {
            Cmd::Client { dns, .. } => dns,
            _ => panic!("expected Client"),
        };
        assert_eq!(
            dns.as_deref(),
            Some(&["1.1.1.1".to_string(), "8.8.8.8".to_string()][..])
        );
        let merged = merge_client_config(
            ClientConfig::default(),
            ClientFileConfig::default(),
            &ClientCliOverrides {
                dns,
                ..Default::default()
            },
        );
        assert_eq!(
            merged.dns.as_deref(),
            Some(&["1.1.1.1".to_string(), "8.8.8.8".to_string()][..])
        );

        // Empty --dns "" -> raw clap keeps an empty token, but the merge filters
        // empties to Some([]), which the daemon treats as "skip resolv.conf
        // rewrite (firewall block only)".
        let cli = Cli::parse_from(["rustnies", "client", "--dns", ""]);
        let dns = match cli.cmd {
            Cmd::Client { dns, .. } => dns,
            _ => panic!("expected Client"),
        };
        assert_eq!(dns.as_deref(), Some(&["".to_string()][..]));
        let merged = merge_client_config(
            ClientConfig::default(),
            ClientFileConfig::default(),
            &ClientCliOverrides {
                dns,
                ..Default::default()
            },
        );
        assert!(merged.dns.is_some(), "--dns was passed -> Some");
        assert!(
            merged.dns.as_deref().unwrap().is_empty(),
            "empty --dns filters to [] (skip resolv rewrite)"
        );

        // Omitted --dns -> None (the daemon applies the built-in default).
        let cli = Cli::parse_from(["rustnies", "client"]);
        match cli.cmd {
            Cmd::Client { dns, .. } => assert!(dns.is_none()),
            _ => panic!("expected Client"),
        }
    }

    /// `--kill-switch` and `--no-dns-leak-protection` are presence flags that
    /// map to the override bundle.
    #[test]
    fn kill_switch_and_no_dns_flags_parse() {
        let cli = Cli::parse_from([
            "rustnies",
            "client",
            "--kill-switch",
            "--no-dns-leak-protection",
        ]);
        match cli.cmd {
            Cmd::Client {
                kill_switch,
                no_dns_leak_protection,
                ..
            } => {
                assert!(kill_switch);
                assert!(no_dns_leak_protection);
            }
            _ => panic!("expected Client"),
        }
    }

    #[test]
    fn server_log_file_flag_parsed() {
        let cli = Cli::parse_from(["rustnies", "server", "--log-file", "/var/log/rustnies.log"]);
        match cli.cmd {
            Cmd::Server { log_file, .. } => {
                assert_eq!(log_file, Some(PathBuf::from("/var/log/rustnies.log")));
            }
            _ => panic!("expected Server"),
        }
    }

    #[test]
    fn client_log_file_flag_parsed() {
        let cli = Cli::parse_from([
            "rustnies",
            "client",
            "--server-key",
            "deadbeef",
            "--log-file",
            "/var/log/rustnies.log",
        ]);
        match cli.cmd {
            Cmd::Client { log_file, .. } => {
                assert_eq!(log_file, Some(PathBuf::from("/var/log/rustnies.log")));
            }
            _ => panic!("expected Client"),
        }
    }

    #[test]
    fn log_file_flag_defaults_to_none() {
        let cli = Cli::parse_from(["rustnies", "server"]);
        match cli.cmd {
            Cmd::Server { log_file, .. } => assert!(log_file.is_none()),
            _ => panic!("expected Server"),
        }
    }
}
