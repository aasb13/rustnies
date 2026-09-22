//! rustnies — a modular UDP VPN tunnel.
//!
//! Phase 1 provides a working encrypted tunnel with adaptive FEC and basic
//! congestion control. The crate is organised so the protocol, crypto, FEC,
//! congestion and transport layers are platform-independent and reusable from
//! mobile (Android/iOS) hosts without rewriting the core.
//!
//! Layout:
//! - [`protocol`]   — wire format, framing, session state, replay protection
//! - [`crypto`]     — Noise IK handshake + ChaCha20Poly1305 AEAD
//! - [`transport`]  — swappable packet wrap/unwrap envelope
//! - [`obfuscation`] — stackable, composable traffic-obfuscation transforms
//! - [`fec`]        — adaptive forward error correction
//! - [`congestion`] — RTT/loss-driven rate control
//! - [`tun`]        — platform-independent TUN trait
//! - [`tunnel`]     — ties the above into a client/server tunnel loop
//! - [`platform`]   — Linux-specific TUN + NAT orchestration
//! - [`ipc`]        — daemon <-> CLI IPC
//! - [`daemon`]     — persistent process orchestration
//! - [`cli`]        — CLI subcommands
//! - [`config`]     — configuration types
//! - [`stats`]      — live statistics

pub mod cli;
pub mod config;
pub mod congestion;
pub mod crypto;
pub mod daemon;
pub mod fec;
pub mod ipc;
pub mod logging;
pub mod obfuscation;
pub mod platform;
pub mod protocol;
pub mod stats;
pub mod transport;
pub mod tun;
pub mod tunnel;

pub use protocol::codec::Packet;
pub use protocol::header::{PacketHeader, PacketType, SessionId};
