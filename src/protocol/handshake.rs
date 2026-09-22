//! Protocol-level handshake abstraction.
//!
//! [`Handshake`] is the seam behind the Noise IK key exchange: it isolates the
//! tunnel layer from the concrete KEX so a different algorithm could be slotted
//! in without touching protocol/crypto/FEC/congestion/TUN. [`SessionEstablished`]
//! is the *product* of a completed handshake — the per-direction AEAD keys, the
//! session id, the peer's static key and the Noise handshake hash. The live
//! [`crate::protocol::session::Session`] is built by the tunnel layer from
//! `session_id` and is deliberately NOT part of this contract (it is runtime
//! state, not a handshake product).
//!
//! Only one implementation exists in phase 1: Noise IK
//! ([`crate::crypto::noise::NoiseHandshake`]), selected by
//! [`select_handshake`] under the name `"noise-ik"`.

use std::net::SocketAddr;

use bytes::Bytes;

use crate::crypto::aead::Direction;
use crate::crypto::keys::PublicKey;
use crate::crypto::noise::NoiseError;
use crate::protocol::SessionId;

/// Resolved session material handed to the tunnel layer to construct a
/// [`crate::tunnel::Tunnel`].
///
/// Replaces the ad-hoc `tunnel::handshake::Established`. It carries the same
/// semantic fields; the only omission is the live `Session`, which the tunnel
/// layer constructs from `session_id`. [`SessionId`] is carried directly so a
/// handshake implementation never needs to build a tunnel-level `Session`, and
/// `peer_label` is retained (server-matched `[[peers]]` name) — neither is
/// dropped.
#[derive(Debug)]
pub struct SessionEstablished {
    /// The peer's transport address, supplied by the tunnel layer from the UDP
    /// source/destination.
    pub peer: SocketAddr,
    /// Session id derived from the Noise handshake hash
    /// ([`crate::tunnel::session_id_from_hash`]); non-zero.
    pub session_id: SessionId,
    /// Initiator->responder AEAD key.
    pub send_key: [u8; 32],
    /// Responder->initiator AEAD key.
    pub recv_key: [u8; 32],
    pub send_dir: Direction,
    pub recv_dir: Direction,
    /// The peer's long-term static public key, learned during the handshake.
    /// The server uses this to authorize the client; the client already knew
    /// the server's key but keeps it here for logging/diagnostics.
    pub peer_static: PublicKey,
    /// Authorized peer label, if the server matched the initiator's static key
    /// against a named `[[peers]]` entry. `None` on the client side and in open
    /// mode; used by the dispatcher for readable acceptance logs.
    pub peer_label: Option<String>,
    /// Final Noise handshake hash (transcript binding). Used to seed the
    /// per-session obfuscation stack (e.g. the header-XOR keystream) so both
    /// peers derive the same keying material independently.
    pub handshake_hash: [u8; 32],
}

/// A key-exchange handshake machine (phase 1: Noise IK).
///
/// An instance is bound to a single role (initiator/client or
/// responder/server). The responder produces message 2 via
/// [`Handshake::server_message_1`]; the initiator finalizes via
/// [`Handshake::client_finalize`]. Both operate on raw Noise message bytes —
/// transport wrapping, obfuscation and authorization are tunnel-layer policy
/// handled by the orchestrators ([`crate::tunnel::handshake::respond_message_1`]
/// and [`crate::tunnel::handshake::client`]).
pub trait Handshake {
    /// Responder: consume the initiator's raw Noise message 1 and return the raw
    /// message 2 bytes to send back. The derived session material is retained
    /// internally so [`session_id`](Handshake::session_id) works afterward.
    ///
    /// Returns [`NoiseError::WrongRole`] if this instance is the initiator.
    fn server_message_1(&mut self, msg1: &[u8]) -> Result<Bytes, NoiseError>;

    /// Initiator: consume the raw message 2 received from the responder and
    /// return the established session material. `peer` is the responder's
    /// transport address (supplied by the tunnel layer; the Noise exchange
    /// itself does not carry it).
    ///
    /// Returns [`NoiseError::WrongRole`] if this instance is the responder.
    fn client_finalize(
        &mut self,
        msg2: &[u8],
        peer: SocketAddr,
    ) -> Result<SessionEstablished, NoiseError>;

    /// Session id derived from the Noise handshake hash. Returns the reserved
    /// `0` before the handshake has produced a hash.
    fn session_id(&self) -> SessionId;
}

/// Supported key-exchange implementations selectable via [`select_handshake`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeKind {
    /// Noise IK (`Noise_IK_25519_ChaChaPoly_SHA256`) — the rustnies default.
    NoiseIk,
}

/// Default handshake name used by the rustnies entry points ("noise-ik").
pub const DEFAULT_HANDSHAKE: &str = "noise-ik";

/// Resolve a handshake implementation by name.
///
/// Phase 1 recognises only the default rustnies Noise IK path (`""`,
/// `"noise-ik"`, `"rustnies"`); any other name is a hard error rather than a
/// silent fallback, so a misconfiguration fails loudly instead of degrading to
/// an unknown algorithm. Unknown names return
/// [`NoiseError::UnsupportedHandshake`].
pub fn select_handshake(name: &str) -> Result<HandshakeKind, NoiseError> {
    match name {
        "" | "noise-ik" | "rustnies" => Ok(HandshakeKind::NoiseIk),
        _ => Err(NoiseError::UnsupportedHandshake),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_handshake_recognises_default_and_noise_ik() {
        assert_eq!(
            select_handshake(DEFAULT_HANDSHAKE).unwrap(),
            HandshakeKind::NoiseIk
        );
        assert_eq!(select_handshake("").unwrap(), HandshakeKind::NoiseIk);
        assert_eq!(
            select_handshake("rustnies").unwrap(),
            HandshakeKind::NoiseIk
        );
        assert_eq!(
            select_handshake("noise-ik").unwrap(),
            HandshakeKind::NoiseIk
        );
    }

    #[test]
    fn select_handshake_errors_on_unknown_name() {
        // Must be Err, never a panic, for an unknown selector.
        assert_eq!(
            select_handshake("bogus").unwrap_err(),
            NoiseError::UnsupportedHandshake
        );
        assert_eq!(
            select_handshake("Noise_IK").unwrap_err(),
            NoiseError::UnsupportedHandshake
        );
    }
}
