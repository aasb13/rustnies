//! Platform-specific glue.
//!
//! `linux` provides the Linux TUN factory (via [`tun_rs`]), NAT orchestration
//! for the server, and the client-side firewall layer (DNS leak prevention +
//! kill switch). The core never imports this module — it receives a
//! [`crate::tun::Tun`] trait object from here. Other platforms (Android, iOS)
//! will live in sibling modules and implement the same trait.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub use linux::LinuxTunFactory;

use std::io;
use std::path::Path;

/// Verify DNS leak prevention by inspecting the live firewall counters and
/// performing a real resolution. On Linux this delegates to the iptables-based
/// implementation; other platforms are unsupported. Delegates to
/// [`linux::dns_check`] when on Linux.
pub async fn dns_check(resolv: &Path, tun: &str, host: &str) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        return linux::dns_check(resolv, tun, host).await;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (resolv, tun, host);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "dns-check is not implemented on this platform",
        ))
    }
}
