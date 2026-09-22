//! Platform-independent TUN abstraction.
//!
//! The core tunnel logic talks to a [`Tun`] trait object; it never constructs
//! a TUN device directly. A platform host (the Linux daemon, or a future
//! Android/iOS app) provides the [`Tun`] implementation and, if appropriate,
//! hands the core an already-open file descriptor rather than a device name.
//! This keeps the core free of desktop-only assumptions.

use std::future::Future;
use std::io;
use std::pin::Pin;

/// A boxed, sendable future returned by [`Tun`] methods.
pub type TunFut<'a> = Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>>;

/// A read/write view of a TUN interface owned by the core.
///
/// `recv`/`send` operate on whole packets (datagram semantics). Implementations
/// are free to wrap an OS-owned FD handed to the core by a mobile host.
pub trait Tun: Send + 'static {
    /// Read one packet into `buf`, returning the number of bytes read.
    fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> TunFut<'a>;

    /// Write one packet from `buf`, returning the number of bytes written.
    fn send<'a>(&'a mut self, buf: &'a [u8]) -> TunFut<'a>;

    /// A human-readable name for logging (e.g. "tun0").
    fn name(&self) -> io::Result<String>;

    /// The configured MTU.
    fn mtu(&self) -> io::Result<u32>;
}

/// Factory that builds a [`Tun`] for a given platform.
///
/// Implementations live in [`crate::platform`].
pub trait TunFactory: Send + Sync + 'static {
    /// Build a new TUN device from a name and address spec.
    ///
    /// `ipv4` / `prefix` configure the IPv4 address and subnet on the TUN
    /// interface. `ipv6` / `prefix6` optionally configure an IPv6 address and
    /// subnet for dual-stack operation. If `ipv6` is `None`, only IPv4 is
    /// configured and the interface is IPv4-only.
    fn build(
        &self,
        name: &str,
        ipv4: &str,
        prefix: u8,
        ipv6: Option<(&str, u8)>,
        mtu: u32,
    ) -> io::Result<Box<dyn Tun>>;

    /// Build a TUN around an already-open file descriptor. The host owns the
    /// FD and passes it in; the core takes it over. Used by mobile hosts where
    /// the OS grants the FD (e.g. Android VpnService).
    fn from_fd(&self, fd: std::os::fd::RawFd) -> io::Result<Box<dyn Tun>>;
}
