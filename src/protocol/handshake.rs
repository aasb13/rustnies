//! Protocol-level handshake abstraction.
//!
//! [`Handshake`] is the seam behind the key exchange: it isolates the tunnel
//! layer from the concrete KEX so a different algorithm could be slotted in
//! without touching protocol/crypto/FEC/congestion/TUN. [`SessionEstablished`]
//! is the *product* of a completed handshake — the per-direction AEAD keys, the
//! session id, the peer's static key, the negotiated [`Selection`] and the Noise
//! handshake hash. The live [`crate::protocol::session::Session`] is built by the
//! tunnel layer from `session_id` and is deliberately NOT part of this contract
//! (it is runtime state, not a handshake product).
//!
//! Only one implementation exists in phase 1: Noise IK
//! ([`crate::crypto::noise::NoiseHandshake`]), selected by
//! [`select_handshake`] under the name `"noise-ik"` and instantiated through
//! [`build_handshake`].
//!
//! # The KEX is the one part that cannot be negotiated
//!
//! Everything else in the profile ([`crate::protocol::profile`]) is agreed in
//! the message-2 payload, which is itself carried by the KEX. The KEX therefore
//! has to be named identically in both configs. [`HandshakeError::IncompatibleKex`]
//! turns a mismatch into a readable startup failure rather than a handshake
//! timeout.

use std::net::SocketAddr;

use bytes::Bytes;

use crate::crypto::aead::Direction;
use crate::crypto::keys::{KeyPair, PublicKey};
use crate::crypto::noise::NoiseError;
use crate::protocol::SessionId;
use crate::protocol::profile::Selection;

/// Errors a handshake can fail with.
///
/// This exists so a second KEX is not forced to reuse [`NoiseError`] as its
/// error channel. The tunnel layer wraps all of these into its own
/// `HandshakeError` (which adds `Timeout` and `Io`), so the split is:
/// protocol-level cause here, transport-level policy there.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandshakeError {
    /// The KEX itself failed (bad message, wrong peer key, corrupted packet).
    #[error("handshake failed: {0}")]
    Kex(#[from] NoiseError),
    /// The configured KEX name is not implemented by this build.
    #[error("unsupported handshake algorithm {0:?}")]
    UnsupportedKex(String),
    /// The peer is running a different KEX, so the two can never complete a
    /// handshake. Detected because neither side's message could be parsed.
    #[error("handshake algorithm mismatch: this peer uses {0:?}")]
    IncompatibleKex(String),
    /// The responder selected a protocol profile this peer cannot run.
    #[error("incompatible protocol profile: {0}")]
    IncompatibleProfile(crate::protocol::profile::ProfileError),
}

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
    /// the server's key but keeps this here for logging/diagnostics.
    pub peer_static: PublicKey,
    /// Authorized peer label, if the server matched the initiator's static key
    /// against a named `[[peers]]` entry. `None` on the client side and in open
    /// mode; used by the dispatcher for readable acceptance logs.
    pub peer_label: Option<String>,
    /// Final Noise handshake hash (transcript binding). Used to seed the
    /// per-session obfuscation stack and any keyed transport, so both peers
    /// derive the same keying material independently.
    pub handshake_hash: [u8; 32],
    /// The protocol profile both peers agreed on for this session.
    ///
    /// The initiator fills this in from the responder's message-2 payload; the
    /// responder fills it in from the selection it sent. Both then build an
    /// identical [`crate::protocol::profile::ResolvedProfile`], which is what
    /// makes the two ends agree byte-for-byte on which cipher and envelope
    /// every frame uses.
    pub selection: Selection,
}

/// What a responder learns from message 1, before it commits to anything.
///
/// Produced by [`Handshake::responder_read_message_1`] and consumed by
/// [`Handshake::responder_message_2`]. It is owned rather than borrowed so the
/// authorization gate (and the profile negotiation) can run in between without
/// holding a borrow on the handshake machine.
#[derive(Debug, Clone)]
pub struct InitiatorHello {
    /// The initiator's long-term static public key, freshly decrypted. This is
    /// what the server authorizes against.
    pub peer_static: PublicKey,
    /// The raw, authenticated offer payload the initiator appended to message 1.
    /// Empty when the initiator did not propose anything. Kept as bytes rather
    /// than a decoded [`crate::protocol::profile::ClientOffer`] so the bytes
    /// that were actually authenticated are the bytes the responder acts on.
    pub offer: Vec<u8>,
}

/// A key-exchange handshake machine (phase 1: Noise IK).
///
/// An instance is bound to a single side ([`HandshakeSide`]) and runs a strict
/// four-step lifecycle:
///
/// 1. [`initiator_message_1`](Handshake::initiator_message_1) — initiator only.
/// 2. [`responder_read_message_1`](Handshake::responder_read_message_1) —
///    responder only; returns the initiator's key so the caller can authorize it.
/// 3. [`responder_message_2`](Handshake::responder_message_2) — responder only;
///    puts the caller's chosen [`Selection`] into the message-2 payload, which is
///    the only profile-negotiation channel there is.
/// 4. [`client_finalize`](Handshake::client_finalize) — initiator only; reads the
///    selection back out of that payload and produces the session.
///
/// The trait is the *mechanism*; the *policy* (what we offer, what we pick, what
/// a session ends up running) lives in [`crate::protocol::profile`]. Splitting
/// them this way is what lets a new KEX slot in without having to re-decide how
/// profiles are negotiated, and it is why steps 2 and 3 are separate: the
/// authorization gate must be able to reject a peer *before* any reply is
/// produced.
///
/// Implementations operate on raw handshake message bytes; transport wrapping,
/// obfuscation and the retry loop are tunnel-layer policy.
pub trait Handshake: Send {
    /// Initiator: build message 1. `offer` is the encoded
    /// [`crate::protocol::profile::ClientOffer`] to append, or an empty slice to
    /// append nothing.
    ///
    /// Implementations must treat an empty `offer` as "produce the pre-negotiation
    /// message", so a non-proposing client stays wire-compatible with a peer that
    /// predates negotiation.
    fn initiator_message_1(&mut self, offer: &[u8]) -> Result<Bytes, HandshakeError>;

    /// Responder: consume message 1 and report the initiator's static key plus
    /// any offer it appended. Performs no authorization and sends nothing: the
    /// caller decides whether to proceed to
    /// [`responder_message_2`](Handshake::responder_message_2).
    fn responder_read_message_1(&mut self, msg1: &[u8]) -> Result<InitiatorHello, HandshakeError>;

    /// Responder: build message 2, carrying `selection` in the message-2
    /// payload, and return it alongside the responder's own view of the
    /// established session.
    ///
    /// `selection` must be the profile this responder chose; because it is bound
    /// into the transport-key derivation, the initiator — which reads the same
    /// bytes back — derives identical keys.
    fn responder_message_2(
        &mut self,
        hello: &InitiatorHello,
        selection: &Selection,
        peer: SocketAddr,
        peer_label: Option<String>,
    ) -> Result<(Bytes, SessionEstablished), HandshakeError>;

    /// Initiator: consume the raw message 2 and return the established session,
    /// including the profile selection the responder chose.
    ///
    /// Returns [`HandshakeError::IncompatibleProfile`] if the selection names an
    /// implementation this build does not have, so the tunnel is never built on
    /// keys the peer cannot reproduce.
    fn client_finalize(
        &mut self,
        msg2: &[u8],
        peer: SocketAddr,
    ) -> Result<SessionEstablished, HandshakeError>;
}

/// Supported key-exchange implementations selectable via [`select_handshake`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeKind {
    /// Noise IK (`Noise_IK_25519_ChaChaPoly_SHA256`) — the rustnies default.
    NoiseIk,
}

impl HandshakeKind {
    /// The name this kind is selected by (and reports in errors).
    pub fn name(self) -> &'static str {
        match self {
            HandshakeKind::NoiseIk => DEFAULT_HANDSHAKE,
        }
    }
}

/// Default handshake name used by the rustnies entry points ("noise-ik").
pub const DEFAULT_HANDSHAKE: &str = "noise-ik";

/// Resolve a handshake implementation by name.
///
/// Phase 1 recognises only the default rustnies Noise IK path (`""`,
/// `"noise-ik"`, `"rustnies"`); any other name is a hard error rather than a
/// silent fallback, so a misconfiguration fails loudly instead of degrading to
/// an unknown algorithm. Unknown names return
/// [`HandshakeError::UnsupportedKex`].
///
/// Note the asymmetry with the other part selectors: a typo here is fatal (it is
/// checked in both peer configs, and the alternative is a handshake that can
/// never complete), whereas a typo in a layer name is only a warning.
pub fn select_handshake(name: &str) -> Result<HandshakeKind, HandshakeError> {
    match name.trim() {
        "" | DEFAULT_HANDSHAKE | "rustnies" => Ok(HandshakeKind::NoiseIk),
        other => Err(HandshakeError::UnsupportedKex(other.to_string())),
    }
}

/// Which side of the handshake an instance plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeSide {
    /// The client: knows the responder's static key up front, sends message 1.
    Initiator,
    /// The server: learns the initiator's static key from message 1, replies
    /// with message 2.
    Responder,
}

impl HandshakeSide {
    /// The role name the Noise implementation uses.
    pub fn noise_role(self) -> crate::crypto::noise::HandshakeRole {
        match self {
            HandshakeSide::Initiator => crate::crypto::noise::HandshakeRole::Initiator,
            HandshakeSide::Responder => crate::crypto::noise::HandshakeRole::Responder,
        }
    }
}

/// Construct a boxed handshake machine for `kind`.
///
/// This is the registry entry point for the KEX: adding a second algorithm means
/// adding a variant here, a `Handshake` impl, and a wire id — no changes in the
/// tunnel, the daemon, or the config plumbing, all of which go through
/// `build_handshake`.
///
/// `peer_static` is the responder's known static key, and is required for
/// [`HandshakeSide::Initiator`] and must be `None` for
/// [`HandshakeSide::Responder`].
pub fn build_handshake(
    kind: HandshakeKind,
    side: HandshakeSide,
    local: KeyPair,
    peer_static: Option<PublicKey>,
) -> Result<Box<dyn Handshake>, HandshakeError> {
    match kind {
        HandshakeKind::NoiseIk => Ok(Box::new(crate::crypto::noise::NoiseHandshake::new(
            side.noise_role(),
            local,
            peer_static,
        ))),
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
        // Surrounding whitespace is a config-file artefact, not a typo.
        assert_eq!(
            select_handshake("  noise-ik  ").unwrap(),
            HandshakeKind::NoiseIk
        );
    }

    #[test]
    fn select_handshake_errors_on_unknown_name() {
        // Must be Err, never a panic, for an unknown selector.
        assert_eq!(
            select_handshake("bogus").unwrap_err(),
            HandshakeError::UnsupportedKex("bogus".into())
        );
        assert_eq!(
            select_handshake("Noise_IK").unwrap_err(),
            HandshakeError::UnsupportedKex("Noise_IK".into())
        );
    }

    #[test]
    fn kind_name_roundtrips_through_select() {
        for kind in [HandshakeKind::NoiseIk] {
            assert_eq!(select_handshake(kind.name()).unwrap(), kind);
        }
    }

    #[test]
    fn build_handshake_produces_a_usable_machine() {
        let kp = crate::crypto::keys::KeyPair::generate();
        let mut hs =
            build_handshake(HandshakeKind::NoiseIk, HandshakeSide::Responder, kp, None).unwrap();
        // A responder asked for message 1 must fail rather than misbehave.
        let err = hs.initiator_message_1(b"").unwrap_err();
        assert!(matches!(err, HandshakeError::Kex(NoiseError::WrongRole)));
    }

    #[test]
    fn build_handshake_reports_a_kex_mismatch_rather_than_panicking() {
        // An initiator built without the responder's known key cannot proceed.
        let kp = crate::crypto::keys::KeyPair::generate();
        let mut hs =
            build_handshake(HandshakeKind::NoiseIk, HandshakeSide::Initiator, kp, None).unwrap();
        let err = hs.initiator_message_1(b"").unwrap_err();
        assert!(matches!(
            err,
            HandshakeError::Kex(NoiseError::MissingPeerStatic)
        ));
    }
}
