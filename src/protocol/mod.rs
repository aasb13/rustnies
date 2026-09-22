//! Protocol wire format and session state.
//!
//! The on-the-wire packet is:
//! ```text
//!   [ cleartext header (24 bytes) ][ encrypted payload ]
//! ```
//! The header is *authenticated* (passed as AEAD associated data) but not
//! encrypted, so a receiver can route, replay-filter and sequence packets
//! before decrypting. Encryption/authentication is performed by [`crate::crypto`].

pub mod codec;
pub mod handshake;
pub mod header;
pub mod session;

pub use handshake::{
    DEFAULT_HANDSHAKE, Handshake, HandshakeKind, SessionEstablished, select_handshake,
};
pub use header::{HEADER_LEN, PacketHeader, PacketType, SessionId};
pub use session::{Session, SessionRole};
