//! Protocol wire format, session state, and protocol profiles.
//!
//! The on-the-wire packet is:
//! ```text
//!   [ cleartext header (24 bytes) ][ encrypted payload ]
//! ```
//! The header is *authenticated* (passed as AEAD associated data) but not
//! encrypted, so a receiver can route, replay-filter and sequence packets
//! before decrypting. Encryption/authentication is performed by [`crate::crypto`].
//!
//! The *parts* of the protocol that are not the wire format are selected per
//! session from config and negotiated in the handshake; see [`profile`].

pub mod codec;
pub mod handshake;
pub mod header;
pub mod profile;
pub mod session;

pub use handshake::{
    DEFAULT_HANDSHAKE, Handshake, HandshakeError, HandshakeKind, SessionEstablished,
    select_handshake,
};
pub use header::{HEADER_LEN, PacketHeader, PacketType, SessionId};
pub use profile::{
    ClientOffer, LocalProfile, ProfileError, ProfilePrefs, ResolvedProfile, Selection,
};
pub use session::{Session, SessionRole};
