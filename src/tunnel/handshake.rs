//! Noise IK handshake driver over UDP.
//!
//! The handshake is the only reliable phase of the protocol; afterwards data is
//! best-effort. We make it robust to packet loss by having the client retry the
//! full handshake (a fresh ephemeral each attempt) until it receives a valid
//! message 2, and the server respond to each valid message 1.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::crypto::aead::Direction;
use crate::crypto::keys::{KeyPair, PublicKey};
use crate::crypto::noise::{HandshakeRole, NoiseError, NoiseHandshake};
use crate::obfuscation::ObfuscationStack;
use crate::protocol::SessionId;
use crate::transport::Transport;

pub use crate::protocol::handshake::{
    DEFAULT_HANDSHAKE, Handshake, HandshakeKind, SessionEstablished, select_handshake,
};

const HANDSHAKE_RTO: Duration = Duration::from_millis(500);
const HANDSHAKE_MAX_ATTEMPTS: u32 = 10;
/// Minimum message-1 length (32B ephemeral + 32B static + 16B tag).
const MSG1_MIN: usize = 32 + 32 + 16;
/// Minimum message-2 length (32B ephemeral + 0B payload + 16B tag).
const MSG2_MIN: usize = 32 + 16;

/// Authorization callback used by [`respond_message_1`]: given the
/// initiator's freshly-decrypted static public key, returns
/// `(allowed, matched_label)`. `matched_label` is the configured `name` of
/// the matched `[[peers]]` entry (if any); `None` when the key was not matched
/// or the server is in open mode.
pub type Authorizer<'a> = &'a dyn Fn(&PublicKey) -> (bool, Option<String>);

/// Run the initiator side of the handshake. `sock` should already be bound to
/// an ephemeral local address.
///
/// `obfuscation` is the resolved stack (possibly empty). It is applied to
/// handshake messages on send and reversed on receive, so padding/whitening
/// layers are consistent across the handshake and steady state. Keying-based
/// layers (e.g. `header_xor`) are no-ops during the handshake because their
/// keystream is not derived until [`super::Tunnel::from_handshake`] calls
/// `init` with the handshake hash.
pub async fn client(
    sock: Arc<UdpSocket>,
    server: SocketAddr,
    client_kp: &KeyPair,
    server_pub: PublicKey,
    transport: Box<dyn Transport>,
    obfuscation: &ObfuscationStack,
) -> Result<SessionEstablished, HandshakeError> {
    select_handshake(DEFAULT_HANDSHAKE)?;
    for attempt in 1..=HANDSHAKE_MAX_ATTEMPTS {
        tracing::debug!(attempt, server = %server, "client handshake attempt");
        let mut hs = NoiseHandshake::new(
            HandshakeRole::Initiator,
            clone_keypair(client_kp),
            Some(server_pub),
        );
        let m1 = hs.write_message_1()?;
        let obf = obfuscation.apply(&m1);
        let wire = transport.wrap(&obf);
        tracing::trace!(attempt, len = wire.len(), "sending msg1");
        sock.send_to(&wire, server).await?;

        // Wait for message 2.
        let mut buf = vec![0u8; 65535];
        match timeout(HANDSHAKE_RTO, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => {
                if from != server {
                    tracing::trace!(from = %from, "ignoring msg2 from wrong address");
                    continue;
                }
                let unwrapped = match transport.unwrap(&buf[..n]) {
                    Ok(u) => u,
                    Err(_) => {
                        tracing::trace!(attempt, "transport unwrap failed for msg2; retrying");
                        continue;
                    }
                };
                let unwrapped = match obfuscation.reverse(&unwrapped) {
                    Ok(u) => u,
                    Err(_) => {
                        tracing::trace!(attempt, "obfuscation reverse failed for msg2; retrying");
                        continue;
                    }
                };
                if unwrapped.len() < MSG2_MIN {
                    tracing::trace!(attempt, len = unwrapped.len(), "msg2 too short; retrying");
                    continue;
                }
                match hs.read_message_2(&unwrapped) {
                    Ok((_payload, result)) => {
                        let session_id = super::session_id_from_hash(&result.handshake_hash);
                        tracing::debug!(attempt, server = %server, "client handshake accepted");
                        return Ok(SessionEstablished {
                            peer: server,
                            session_id,
                            send_key: result.key_i2r,
                            recv_key: result.key_r2i,
                            send_dir: Direction::InitiatorToResponder,
                            recv_dir: Direction::ResponderToInitiator,
                            peer_static: server_pub,
                            peer_label: None,
                            handshake_hash: result.handshake_hash,
                        });
                    }
                    Err(e) => {
                        tracing::debug!(attempt, error = ?e, "bad m2; retrying");
                    }
                }
            }
            Ok(Err(e)) => {
                tracing::warn!(error = ?e, "udp recv error during handshake");
            }
            Err(_) => {
                tracing::debug!("handshake attempt timed out");
            }
        }
    }
    Err(HandshakeError::Timeout)
}

/// Process a single message 1 from a peer: validate it, run the Noise
/// responder, and produce the message 2 to send back plus the established
/// session material. Returns `None` if the datagram is not a valid message 1
/// (transport unwrap failed, too short, Noise rejected it) or if `authorizer`
/// rejects the initiator's static public key.
///
/// `authorizer` is consulted after the initiator's static key is decrypted but
/// *before* message 2 is built, so an unauthorized peer never receives a reply
/// and no session state is created. Pass `None` for open (phase-1) mode. It
/// returns `(allowed, matched_label)`: the label is the configured `name` of
/// the matched `[[peers]]` entry (if any), carried through to the `Established`
/// result and used in acceptance logs (falling back to `"unknown"` when the
/// key was not matched).
///
/// Logging policy (so every connection attempt is visible by default):
///   - A datagram with valid framing and a plausible message-1 length logs an
///     `info` "incoming handshake attempt" line (source + size) before any
///     crypto work.
///   - A datagram the transport rejects, or that is too short to be a message
///     1, is treated as non-handshake / scan noise and logged at `debug`.
///   - An authorized handshake logs `info` "handshake accepted" via the caller
///     (which has the spawn context); an unauthorized key logs `info`
///     "handshake rejected" with the offending key; any other Noise failure
///     logs `info` "handshake failed" with the specific reason.
///
/// This is the per-datagram handshake primitive used by the multi-client
/// server dispatcher ([`super::server`]). It does no I/O: the caller sends
/// `m2_wire` to `peer` over the shared socket.
pub fn respond_message_1(
    server_kp: &KeyPair,
    transport: &dyn Transport,
    obfuscation: &ObfuscationStack,
    msg1_wire: &[u8],
    peer: SocketAddr,
    authorizer: Option<Authorizer<'_>>,
) -> Option<(SessionEstablished, Vec<u8>)> {
    // Transport framing check. A datagram the transport rejects is not a
    // handshake attempt at all (internet background scan / foreign traffic).
    // Keep this at debug so scan spam never pollutes the default info log; it
    // is still visible with --verbose / RUST_LOG=debug.
    let unwrapped = match transport.unwrap(msg1_wire) {
        Ok(u) => u,
        Err(_) => {
            tracing::debug!(
                from = %peer,
                len = msg1_wire.len(),
                "non-handshake datagram: transport rejected it; ignoring"
            );
            return None;
        }
    };
    let unwrapped = match obfuscation.reverse(&unwrapped) {
        Ok(u) => u,
        Err(_) => {
            tracing::debug!(
                from = %peer,
                len = msg1_wire.len(),
                "non-handshake datagram: obfuscation rejected it; ignoring"
            );
            return None;
        }
    };
    if unwrapped.len() < MSG1_MIN {
        tracing::debug!(
            from = %peer,
            len = unwrapped.len(),
            "non-handshake datagram: too short for a message 1; ignoring"
        );
        return None;
    }
    // The datagram has valid framing and a plausible message-1 length, so it
    // looks like a real connection attempt. Log it at info so every attempt is
    // visible by default regardless of outcome.
    tracing::info!(from = %peer, len = msg1_wire.len(), "incoming handshake attempt");
    let mut hs = NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(server_kp), None);
    let initiator_pub = match hs.read_message_1(&unwrapped) {
        Ok(pk) => pk,
        Err(e) => {
            tracing::info!(
                from = %peer,
                error = %e,
                "handshake failed: could not read message 1 (wrong server key, corrupted or malformed packet)"
            );
            return None;
        }
    };
    // Authorization gate: check the freshly-learned initiator static key
    // against the server's peer list before committing to the handshake.
    let peer_label = if let Some(auth) = authorizer {
        let (allowed, matched_name) = auth(&initiator_pub);
        if !allowed {
            tracing::info!(
                from = %peer,
                key = %hex::encode(initiator_pub.to_bytes()),
                "handshake rejected: client static key not in authorized peers list"
            );
            return None;
        }
        matched_name
    } else {
        None
    };
    let (m2, result) = match hs.write_message_2(&[]) {
        Ok(v) => v,
        Err(e) => {
            tracing::info!(
                from = %peer,
                error = %e,
                "handshake failed: could not build message 2"
            );
            return None;
        }
    };
    let obf = obfuscation.apply(&m2);
    let wire = transport.wrap(&obf);
    let session_id = super::session_id_from_hash(&result.handshake_hash);
    Some((
        SessionEstablished {
            peer,
            session_id,
            send_key: result.key_r2i,
            recv_key: result.key_i2r,
            send_dir: Direction::ResponderToInitiator,
            recv_dir: Direction::InitiatorToResponder,
            peer_static: initiator_pub,
            peer_label,
            handshake_hash: result.handshake_hash,
        },
        wire,
    ))
}

/// Run the responder side: wait for a valid message 1 and reply with message 2.
/// Returns the peer address plus the established session material.
///
/// This is the single-peer, blocking-accept form kept for tests and any
/// single-client host. The live multi-client server uses
/// [`super::server::run_server`] which calls [`respond_message_1`] per
/// datagram instead.
pub async fn server(
    sock: Arc<UdpSocket>,
    server_kp: KeyPair,
    transport: Box<dyn Transport>,
    obfuscation: &ObfuscationStack,
) -> Result<SessionEstablished, HandshakeError> {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, from) = sock.recv_from(&mut buf).await?;
        if let Some((established, m2_wire)) =
            respond_message_1(&server_kp, &*transport, obfuscation, &buf[..n], from, None)
        {
            sock.send_to(&m2_wire, from).await?;
            return Ok(established);
        }
    }
}

impl Handshake for NoiseHandshake {
    fn server_message_1(&mut self, msg1: &[u8]) -> Result<Bytes, NoiseError> {
        let _initiator_pub = self.read_message_1(msg1)?;
        let (m2, _result) = self.write_message_2(b"")?;
        Ok(Bytes::from(m2))
    }

    fn client_finalize(
        &mut self,
        msg2: &[u8],
        peer: SocketAddr,
    ) -> Result<SessionEstablished, NoiseError> {
        let (_payload, result) = self.read_message_2(msg2)?;
        let session_id = super::session_id_from_hash(&result.handshake_hash);
        let peer_static = self
            .peer_static_key()
            .ok_or(NoiseError::MissingPeerStatic)?;
        Ok(SessionEstablished {
            peer,
            session_id,
            send_key: result.key_i2r,
            recv_key: result.key_r2i,
            send_dir: Direction::InitiatorToResponder,
            recv_dir: Direction::ResponderToInitiator,
            peer_static,
            peer_label: None,
            handshake_hash: result.handshake_hash,
        })
    }

    fn session_id(&self) -> SessionId {
        super::session_id_from_hash(&self.handshake_hash())
    }
}

/// Copy the secret/public of a [`KeyPair`] (x25519-dalek types are Clone-able
/// for the public; the secret must be re-derived from its bytes).
fn clone_keypair(kp: &KeyPair) -> KeyPair {
    let secret_bytes = kp.secret.to_bytes();
    let secret = crate::crypto::keys::StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret);
    KeyPair { secret, public }
}

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("handshake did not complete in time")]
    Timeout,
    #[error("noise handshake error: {0}")]
    Noise(#[from] crate::crypto::noise::NoiseError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{KeyPair, PublicKey, StaticSecret};
    use crate::crypto::noise::{HandshakeRole, NoiseError, NoiseHandshake};
    use crate::protocol::SessionId;
    use serde::Serialize;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Test-only deterministic key material (never secret).
    const CLIENT_STATIC: [u8; 32] = [0x11; 32];
    const SERVER_STATIC: [u8; 32] = [0x22; 32];
    const CLIENT_EPH: [u8; 32] = [0x33; 32];
    const SERVER_EPH: [u8; 32] = [0x44; 32];

    #[derive(Serialize, PartialEq, Debug)]
    struct Baseline {
        client_static_pub: String,
        server_static_pub: String,
        initiator_ephemeral_pub: String,
        responder_ephemeral_pub: String,
        msg1: String,
        msg2: String,
        send_key: String,
        recv_key: String,
        handshake_hash: String,
        session_id: SessionId,
        initiator_static_pub_from_server: String,
    }

    fn fixed_kp(secret: [u8; 32]) -> KeyPair {
        let s = StaticSecret::from(secret);
        let public = PublicKey::from(&s);
        KeyPair { secret: s, public }
    }

    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    fn atomic_write(path: &str, data: &[u8]) {
        let tmp = format!("{path}.tmp.{}", TMP_SEQ.fetch_add(1, Ordering::Relaxed));
        std::fs::write(&tmp, data).unwrap();
        std::fs::rename(&tmp, path).unwrap();
    }

    fn current_path_baseline() -> Baseline {
        let client_kp = fixed_kp(CLIENT_STATIC);
        let server_kp = fixed_kp(SERVER_STATIC);

        let mut init = NoiseHandshake::new(
            HandshakeRole::Initiator,
            clone_keypair(&client_kp),
            Some(server_kp.public),
        );
        init.set_test_ephemeral(CLIENT_EPH);
        let m1 = init.write_message_1().unwrap();

        let mut resp =
            NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server_kp), None);
        resp.set_test_ephemeral(SERVER_EPH);
        let initiator_pub = resp.read_message_1(&m1).unwrap();
        let (m2, result) = resp.write_message_2(b"").unwrap();
        let (_payload, client_result) = init.read_message_2(&m2).unwrap();

        assert_eq!(result.key_i2r, client_result.key_i2r);
        assert_eq!(result.key_r2i, client_result.key_r2i);
        assert_eq!(result.handshake_hash, client_result.handshake_hash);
        let session_id = crate::tunnel::session_id_from_hash(&result.handshake_hash);
        assert_eq!(
            crate::tunnel::session_id_from_hash(&client_result.handshake_hash),
            session_id
        );

        Baseline {
            client_static_pub: hex::encode(client_kp.public.to_bytes()),
            server_static_pub: hex::encode(server_kp.public.to_bytes()),
            initiator_ephemeral_pub: hex::encode(&m1[..32]),
            responder_ephemeral_pub: hex::encode(&m2[..32]),
            msg1: hex::encode(&m1),
            msg2: hex::encode(&m2),
            send_key: hex::encode(&client_result.key_i2r),
            recv_key: hex::encode(&client_result.key_r2i),
            handshake_hash: hex::encode(&client_result.handshake_hash),
            session_id,
            initiator_static_pub_from_server: hex::encode(initiator_pub.to_bytes()),
        }
    }

    // Pins the current Noise IK wire format and derived keys to a golden file.
    // Independent of the `Handshake` trait, so it is green even before the
    // abstraction lands (regression guard for non-regression of message bytes).
    #[test]
    fn handshake_baseline() {
        let baseline = current_path_baseline();
        let dir = ".omo/evidence/1-baseline";
        std::fs::create_dir_all(dir).unwrap();
        atomic_write(
            &format!("{dir}/baseline.json"),
            serde_json::to_string_pretty(&baseline).unwrap().as_bytes(),
        );
    }

    // The `Handshake` trait must be byte-for-byte equivalent to the baseline
    // produced by the inherent Noise IK path: same msg1/msg2 bytes, same keys,
    // same session id, same peer-static extraction.
    #[test]
    fn handshake_trait_matches_baseline() {
        let baseline = current_path_baseline();
        let dir = ".omo/evidence/1-baseline";
        std::fs::create_dir_all(dir).unwrap();
        atomic_write(
            &format!("{dir}/baseline.json"),
            serde_json::to_string_pretty(&baseline).unwrap().as_bytes(),
        );
        let written = std::fs::read_to_string(format!("{dir}/baseline.json")).unwrap();
        assert_eq!(
            serde_json::to_string_pretty(&baseline).unwrap(),
            written,
            "baseline.json round-trips"
        );

        let client_kp = fixed_kp(CLIENT_STATIC);
        let server_kp = fixed_kp(SERVER_STATIC);

        let mut init = NoiseHandshake::new(
            HandshakeRole::Initiator,
            clone_keypair(&client_kp),
            Some(server_kp.public),
        );
        init.set_test_ephemeral(CLIENT_EPH);
        let m1 = Handshake::server_message_1(&mut init, &[]).unwrap_err();
        // Initiator must not be asked to produce message 1:
        assert_eq!(m1, NoiseError::WrongRole);

        // Build msg1 via the real initiator method (trait has no msg1 method).
        let m1 = init.write_message_1().unwrap();
        assert_eq!(hex::encode(&m1), baseline.msg1);

        let mut resp =
            NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server_kp), None);
        resp.set_test_ephemeral(SERVER_EPH);
        let m2 = Handshake::server_message_1(&mut resp, &m1).unwrap();
        assert_eq!(hex::encode(&m2), baseline.msg2);
        assert_eq!(
            Handshake::session_id(&resp),
            baseline.session_id,
            "responder session_id matches baseline"
        );

        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let est = Handshake::client_finalize(&mut init, &m2, peer).unwrap();
        let send_key: [u8; 32] = hex::decode(&baseline.send_key).unwrap().try_into().unwrap();
        let recv_key: [u8; 32] = hex::decode(&baseline.recv_key).unwrap().try_into().unwrap();
        let h_hash: [u8; 32] = hex::decode(&baseline.handshake_hash)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(est.send_key, send_key);
        assert_eq!(est.recv_key, recv_key);
        assert_eq!(est.handshake_hash, h_hash);
        assert_eq!(est.session_id, baseline.session_id);
        assert_eq!(est.peer, peer);
        assert_eq!(est.peer_static, server_kp.public);
        assert!(est.peer_label.is_none());
        assert_eq!(est.send_dir, Direction::InitiatorToResponder);
        assert_eq!(est.recv_dir, Direction::ResponderToInitiator);

        // Wrong role: a responder asked to finalize must error, not panic.
        assert_eq!(
            Handshake::client_finalize(&mut resp, &m2, peer).unwrap_err(),
            NoiseError::WrongRole
        );
    }
}
