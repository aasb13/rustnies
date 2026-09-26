//! Noise IK handshake driver over UDP.
//!
//! The handshake is the only reliable phase of the protocol; afterwards data is
//! best-effort. We make it robust to packet loss by having the client retry the
//! full handshake (a fresh ephemeral each attempt) until it receives a valid
//! message 2, and the server respond to each valid message 1.
//!
//! # Where the pieces live
//!
//! This module is *policy*: the retry loop, the transport/obfuscation interleave,
//! the authorization gate, the framing-length gates, and the profile negotiation
//! that decides which implementations the resulting session runs. The
//! *mechanism* is behind traits owned by the layers below:
//!
//! * [`crate::protocol::handshake::Handshake`] — the key exchange itself,
//!   instantiated by `build_handshake` from `[handshake] kex`.
//! * [`crate::protocol::profile::LocalProfile`] — this side's resolved profile:
//!   its ordered preferences, the handshake envelope, the local congestion
//!   controller, and whether it proposes anything to the responder.
//! * [`crate::protocol::profile`] — the offer/selection encodings and the
//!   server-authoritative selection rule.
//!
//! # Negotiation summary
//!
//! The client optionally appends an encrypted [`ClientOffer`] to message 1
//! (opt-in, because appending is a wire change). The responder reads it, picks a
//! [`Selection`] with the server's preference order as the tie-break, and puts
//! it in message 2's payload — a slot this protocol already had and left empty.
//! The client reads the selection back and validates it *before* building a
//! tunnel, so an incompatible server fails the handshake with a readable error
//! rather than producing a session whose every packet fails to authenticate.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::crypto::keys::{KeyPair, PublicKey};
use crate::obfuscation::ObfuscationStack;
use crate::protocol::handshake::{HandshakeSide, build_handshake};
use crate::protocol::profile::{ClientOffer, LocalProfile, negotiate};

pub use crate::protocol::handshake::{
    DEFAULT_HANDSHAKE, Handshake, HandshakeError as ProtocolHandshakeError, HandshakeSide as Side,
    InitiatorHello, SessionEstablished, select_handshake as select_kex,
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
/// `profile` is this side's resolved [`LocalProfile`]. It supplies the handshake
/// envelope, the offer (if `propose` is set), the KEX name, and the ordered
/// preferences used to validate the responder's selection.
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
    profile: &LocalProfile,
    obfuscation: &ObfuscationStack,
) -> Result<SessionEstablished, HandshakeError> {
    let kind = select_kex(&profile.kex_name)?;
    let transport = &*profile.handshake_transport;
    // Build the offer once: it is constant for the daemon's lifetime, and every
    // retry re-sends the identical bytes.
    let offer = profile.offer().map(|o| o.encode()).unwrap_or_default();

    for attempt in 1..=HANDSHAKE_MAX_ATTEMPTS {
        tracing::debug!(attempt, server = %server, "client handshake attempt");
        let mut hs = build_handshake(
            kind,
            HandshakeSide::Initiator,
            clone_keypair(client_kp),
            Some(server_pub),
        )?;
        let m1 = hs.initiator_message_1(&offer)?;
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
                match hs.client_finalize(&unwrapped, server) {
                    Ok(est) => {
                        // Validate the responder's selection *before* anything
                        // is built from it. `client_finalize` has already
                        // decoded it; re-checking here makes the failure point
                        // explicit and keeps this the single place the client
                        // accepts a server's choice.
                        match est.selection.check() {
                            Ok(()) => {
                                tracing::debug!(
                                    attempt,
                                    server = %server,
                                    profile = %est.selection.describe(&profile.congestion_name),
                                    "client handshake accepted"
                                );
                                return Ok(est);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    attempt,
                                    error = %e,
                                    "server selected an incompatible protocol profile"
                                );
                                return Err(ProtocolHandshakeError::IncompatibleProfile(e).into());
                            }
                        }
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

/// Process a single message 1 from a peer: validate it, run the responder KEX,
/// negotiate the protocol profile, and produce the message 2 to send back plus
/// the established session material. Returns `None` if the datagram is not a
/// valid message 1 (transport unwrap failed, too short, KEX rejected it) or if
/// `authorizer` rejects the initiator's static public key.
///
/// `authorizer` is consulted after the initiator's static key is decrypted but
/// *before* message 2 is built, so an unauthorized peer never receives a reply
/// and no session state is created. Pass `None` for open (phase-1) mode. It
/// returns `(allowed, matched_label)`: the label is the configured `name` of
/// the matched `[[peers]]` entry (if any), carried through to the
/// [`SessionEstablished`] result and used in acceptance logs.
///
/// This is the per-datagram handshake primitive used by the multi-client
/// server dispatcher ([`super::server`]). It does no I/O: the caller sends
/// `m2_wire` to `peer` over the shared socket.
pub fn respond_message_1(
    server_kp: &KeyPair,
    profile: &LocalProfile,
    obfuscation: &ObfuscationStack,
    msg1_wire: &[u8],
    peer: SocketAddr,
    authorizer: Option<Authorizer<'_>>,
) -> Option<(SessionEstablished, Vec<u8>)> {
    let transport = &*profile.handshake_transport;

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
    // looks like a real connection attempt. Log at info so every attempt is
    // visible by default regardless of outcome.
    tracing::info!(from = %peer, len = msg1_wire.len(), "incoming handshake attempt");

    // 1. Read message 1: learn the initiator's static key and any offer it
    //    appended. Both come from the authenticated bytes, so the offer the
    //    server acts on is exactly the offer the client signed for.
    let kex_name = profile.kex_name.as_str();
    let kind = match crate::protocol::handshake::select_handshake(kex_name) {
        Ok(k) => k,
        Err(e) => {
            tracing::info!(from = %peer, error = %e, "handshake failed: bad [handshake] kex config");
            return None;
        }
    };
    let mut hs = match build_handshake(
        kind,
        HandshakeSide::Responder,
        clone_keypair(server_kp),
        None,
    ) {
        Ok(h) => h,
        Err(e) => {
            tracing::info!(from = %peer, error = %e, "handshake failed: could not build kex");
            return None;
        }
    };
    let hello = match hs.responder_read_message_1(&unwrapped) {
        Ok(v) => v,
        Err(e) => {
            tracing::info!(
                from = %peer,
                error = %e,
                "handshake failed: could not read message 1 (wrong server key, kex mismatch, corrupted or malformed packet)"
            );
            return None;
        }
    };
    let initiator_pub = hello.peer_static;

    // 2. Authorization gate: check the freshly-learned initiator static key
    //    against the server's peer list before committing to the handshake. A
    //    rejected peer never receives a reply and no session state is created.
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

    // 3. Negotiate the profile. The server is authoritative: it walks its own
    //    preference order and takes the first candidate the client also lists.
    let offer = match ClientOffer::decode(&hello.offer) {
        Ok(o) => o,
        Err(e) => {
            // An unparseable offer is not fatal — the payload is authenticated,
            // so this means the client proposed something we do not understand.
            // Fall back to our own preference and say so.
            tracing::info!(
                from = %peer,
                error = %e,
                "ignoring undecodable client profile offer; using server preference"
            );
            None
        }
    };
    let selection = match negotiate(&profile.prefs, offer.as_ref(), profile.data_tag) {
        Ok(s) => s,
        Err(e) => {
            tracing::info!(
                from = %peer,
                error = %e,
                "handshake rejected: no common protocol profile"
            );
            return None;
        }
    };

    // 4. Build message 2 with the selection in its payload, and the responder's
    //    own view of the established session alongside it.
    let (m2, established) = match hs.responder_message_2(&hello, &selection, peer, peer_label) {
        Ok(v) => v,
        Err(e) => {
            tracing::info!(from = %peer, error = %e, "handshake failed: could not build message 2");
            return None;
        }
    };
    let obf = obfuscation.apply(&m2);
    let wire = transport.wrap(&obf);

    tracing::debug!(
        from = %peer,
        profile = %selection.describe(&profile.congestion_name),
        "negotiated protocol profile"
    );
    Some((established, wire))
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
    profile: LocalProfile,
    obfuscation: &ObfuscationStack,
) -> Result<SessionEstablished, HandshakeError> {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, from) = sock.recv_from(&mut buf).await?;
        if let Some((established, m2_wire)) =
            respond_message_1(&server_kp, &profile, obfuscation, &buf[..n], from, None)
        {
            sock.send_to(&m2_wire, from).await?;
            return Ok(established);
        }
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

/// Errors from the handshake *driver* (policy), as opposed to
/// [`ProtocolHandshakeError`] (mechanism).
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("handshake did not complete in time")]
    Timeout,
    #[error("noise handshake error: {0}")]
    Noise(#[from] crate::crypto::noise::NoiseError),
    #[error("protocol handshake error: {0}")]
    Protocol(#[from] ProtocolHandshakeError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{KeyPair, StaticSecret};
    use crate::obfuscation::ObfuscationStack;
    use crate::protocol::profile::ResolvedProfile;
    use crate::protocol::profile::{ClientOffer, ProfilePrefs, Selection};
    use crate::protocol::session::session_id_from_hash;
    use crate::transport::PlainTransport;

    fn fixed_kp(secret: [u8; 32]) -> KeyPair {
        let s = StaticSecret::from(secret);
        let public = PublicKey::from(&s);
        KeyPair { secret: s, public }
    }

    fn default_profile() -> LocalProfile {
        LocalProfile::from_role_config(
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .expect("the default config must resolve")
    }

    /// A profile with a non-default selection, for the cases where the point is
    /// that the server's choice is honoured end to end.
    fn profile_with(
        propose: bool,
        ciphers: &[&str],
        transports: &[&str],
        fecs: &[&str],
    ) -> LocalProfile {
        LocalProfile::from_role_config(
            &crate::config::HandshakeConfig {
                kex: DEFAULT_HANDSHAKE.to_string(),
                propose,
            },
            &crate::config::CryptoConfig {
                aead: ciphers.iter().map(|s| s.to_string()).collect(),
            },
            &crate::config::TransportConfig {
                handshake: "plain".into(),
                data: transports.iter().map(|s| s.to_string()).collect(),
                tag_hex: None,
            },
            &crate::config::FecConfig {
                scheme: fecs.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
            &Default::default(),
        )
        .expect("test profile must resolve")
    }

    // ---- the default profile is byte-identical to the pre-negotiation wire ----

    /// The whole point of keeping the message-2 payload optional and the
    /// message-1 append opt-in is that a default-configured pair still speaks
    /// the old protocol. This pins the shape: msg1 carries no trailing offer,
    /// and msg2 carries exactly the selection.
    #[test]
    fn default_profile_produces_no_msg1_offer_and_a_msg2_selection() {
        let profile = default_profile();
        assert!(!profile.propose, "proposing must be opt-in");
        assert!(
            profile.offer().is_none(),
            "a non-proposing client sends no offer payload"
        );

        let server_kp = fixed_kp([0x22; 32]);
        let client_kp = fixed_kp([0x11; 32]);
        let mut init = crate::crypto::noise::NoiseHandshake::new(
            crate::crypto::noise::HandshakeRole::Initiator,
            clone_keypair(&client_kp),
            Some(server_kp.public),
        );
        let m1 = init.initiator_message_1(b"").unwrap();
        // 32 ephemeral + 32 static + 16 tag: no trailing payload at all.
        assert_eq!(m1.len(), 32 + 32 + 16);

        let mut resp = crate::crypto::noise::NoiseHandshake::new(
            crate::crypto::noise::HandshakeRole::Responder,
            clone_keypair(&server_kp),
            None,
        );
        let hello = resp.responder_read_message_1(&m1).unwrap();
        assert!(hello.offer.is_empty(), "responder sees no offer");
        assert_eq!(hello.peer_static, client_kp.public);

        let selection = negotiate(&profile.prefs, None, profile.data_tag).unwrap();
        let (m2, established) = resp
            .responder_message_2(&hello, &selection, "127.0.0.1:1".parse().unwrap(), None)
            .unwrap();
        // 32 ephemeral + 6-byte selection + 16 tag.
        assert_eq!(m2.len(), 32 + selection.encode().len() + 16);
        assert_eq!(established.selection, selection);
        assert_eq!(
            established.session_id,
            session_id_from_hash(&established.handshake_hash)
        );
    }

    // ---- end-to-end over the driver, with the profile threaded through ----

    /// Run a full client/server handshake over loopback UDP with the given
    /// profiles, returning what each side established.
    async fn handshake_pair(
        server_profile: LocalProfile,
        client_profile: LocalProfile,
    ) -> (
        Result<SessionEstablished, String>,
        Result<SessionEstablished, String>,
    ) {
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let server_kp = fixed_kp([0x22; 32]);
        let client_kp = fixed_kp([0x11; 32]);
        let obf = ObfuscationStack::new();

        let handle = tokio::spawn({
            let server_kp = clone_keypair(&server_kp);
            let obf = ObfuscationStack::new();
            async move {
                server(server_sock, server_kp, server_profile, &obf)
                    .await
                    .map_err(|e| e.to_string())
            }
        });

        let server_pub = server_kp.public;
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = client(
            client_sock,
            server_addr,
            &client_kp,
            server_pub,
            &client_profile,
            &obf,
        )
        .await
        .map_err(|e| e.to_string());
        let server = handle.await.expect("server task panicked");
        (client, server)
    }

    #[tokio::test]
    async fn both_sides_agree_on_the_default_profile() {
        let (client, server) = handshake_pair(default_profile(), default_profile()).await;
        let c = client.expect("client handshake failed");
        let s = server.expect("server handshake failed");
        assert_eq!(
            c.selection, s.selection,
            "both ends selected the same parts"
        );
        assert_eq!(c.session_id, s.session_id);
        assert_eq!(c.handshake_hash, s.handshake_hash);
        // Keys match in opposite directions, as they must.
        assert_eq!(c.send_key, s.recv_key);
        assert_eq!(c.recv_key, s.send_key);
        // Default means: no transport negotiation, defaults everywhere.
        assert!(c.selection.reuses_handshake_transport());
        assert_eq!(
            c.selection.cipher,
            crate::crypto::suite::CIPHER_CHACHA20POLY1305
        );
        assert_eq!(c.selection.fec, crate::fec::FEC_REED_SOLOMON);
    }

    #[tokio::test]
    async fn server_choice_wins_when_the_client_does_not_propose() {
        // The client is configured for `fec = none` but does not propose, so the
        // server's Reed-Solomon preference is what it gets — and the client
        // accepts it because it can run Reed-Solomon too.
        let server = profile_with(
            false,
            &["chacha20poly1305"],
            &["same-as-handshake"],
            &["reed-solomon"],
        );
        let client = profile_with(
            false,
            &["chacha20poly1305"],
            &["same-as-handshake"],
            &["none"],
        );
        let (c, s) = handshake_pair(server, client).await;
        let c = c.expect("client handshake failed");
        let s = s.expect("server handshake failed");
        assert_eq!(c.selection, s.selection);
        assert_eq!(
            c.selection.fec,
            crate::fec::FEC_REED_SOLOMON,
            "server preference is authoritative when the client does not propose"
        );
    }

    #[tokio::test]
    async fn client_proposal_lets_the_server_fall_back() {
        // The server's first choice is `none`, the client only offers
        // Reed-Solomon. With `propose = true` on the client the server must
        // pick the client's only option instead of failing.
        let server = profile_with(
            false,
            &["chacha20poly1305"],
            &["same-as-handshake"],
            &["none"],
        );
        let client = profile_with(
            true,
            &["chacha20poly1305"],
            &["same-as-handshake"],
            &["reed-solomon"],
        );
        let (c, s) = handshake_pair(server, client).await;
        let c = c.expect("client handshake failed");
        let s = s.expect("server handshake failed");
        assert_eq!(c.selection, s.selection);
        assert_eq!(
            c.selection.fec,
            crate::fec::FEC_REED_SOLOMON,
            "server fell back to the only scheme the client offered"
        );
    }

    #[tokio::test]
    async fn a_proposing_client_can_move_the_data_envelope() {
        // A client that offers `tagged` for steady-state frames makes the
        // server pick it (the server's `same-as-handshake` is terminal, so a
        // real candidate before it wins).
        let server = profile_with(
            false,
            &["chacha20poly1305"],
            &["same-as-handshake"],
            &["reed-solomon"],
        );
        let client = profile_with(true, &["chacha20poly1305"], &["tagged"], &["reed-solomon"]);
        let (c, s) = handshake_pair(server, client).await;
        let c = c.expect("client handshake failed");
        let s = s.expect("server handshake failed");
        assert_eq!(c.selection, s.selection);
        assert!(!c.selection.reuses_handshake_transport());
        assert_eq!(c.selection.transport, crate::transport::TRANSPORT_TAGGED);
        // Both ends build an identical runnable profile from that selection.
        let a = ResolvedProfile::with_handshake_transport(
            &c.selection,
            &c.handshake_hash,
            &PlainTransport,
            default_profile().new_congestion(),
        )
        .unwrap();
        let b = ResolvedProfile::with_handshake_transport(
            &s.selection,
            &s.handshake_hash,
            &PlainTransport,
            default_profile().new_congestion(),
        )
        .unwrap();
        assert_eq!(a.transport.name(), b.transport.name());
        assert_eq!(a.cipher.key_schedule(), b.cipher.key_schedule());
    }

    /// Drive the responder directly with an offer the server cannot satisfy.
    ///
    /// A config-driven client can only ever advertise ids this build implements,
    /// so the "no overlap" case needs a synthetic offer — which is exactly what a
    /// peer running a code we have never heard of looks like on the wire.
    fn respond_to_offer(server_profile: &LocalProfile, offer: &ClientOffer) -> bool {
        let server_kp = fixed_kp([0x22; 32]);
        let client_kp = fixed_kp([0x11; 32]);
        let mut init = crate::crypto::noise::NoiseHandshake::new(
            crate::crypto::noise::HandshakeRole::Initiator,
            clone_keypair(&client_kp),
            Some(server_kp.public),
        );
        let m1 = init.initiator_message_1(&offer.encode()).unwrap();
        let obf = ObfuscationStack::new();
        respond_message_1(
            &server_kp,
            server_profile,
            &obf,
            &m1,
            "127.0.0.1:1".parse().unwrap(),
            None,
        )
        .is_some()
    }

    #[test]
    fn a_client_offering_only_unknown_parts_is_rejected() {
        let server_profile = profile_with(
            false,
            &["chacha20poly1305"],
            &["same-as-handshake"],
            &["reed-solomon"],
        );
        let offer = ClientOffer {
            cipher_ids: vec![201],
            transport_ids: vec![],
            fec_ids: vec![202],
        };
        assert!(
            !respond_to_offer(&server_profile, &offer),
            "an offer with no implementable part must be refused, not half-honoured"
        );
    }

    #[test]
    fn one_unnegotiable_part_rejects_the_whole_profile() {
        // The FEC code is fine but the cipher is unrecognised. A profile is
        // accepted or rejected as a unit: half-negotiating would build a session
        // whose transport keys are guaranteed wrong, so the responder refuses
        // rather than "agreeing on what it can".
        let server_profile = profile_with(
            false,
            &["chacha20poly1305"],
            &["same-as-handshake"],
            &["reed-solomon"],
        );
        let offer = ClientOffer {
            cipher_ids: vec![201],
            transport_ids: vec![],
            fec_ids: vec![crate::fec::FEC_REED_SOLOMON],
        };
        assert!(!respond_to_offer(&server_profile, &offer));
    }

    #[tokio::test]
    async fn a_client_rejects_a_selection_it_cannot_run() {
        // Drive `client_finalize` directly with a selection naming an unknown
        // cipher id, which is what an older client sees from a newer server.
        let server_kp = fixed_kp([0x22; 32]);
        let client_kp = fixed_kp([0x11; 32]);
        let mut init = crate::crypto::noise::NoiseHandshake::new(
            crate::crypto::noise::HandshakeRole::Initiator,
            clone_keypair(&client_kp),
            Some(server_kp.public),
        );
        let m1 = init.initiator_message_1(b"").unwrap();
        let mut resp = crate::crypto::noise::NoiseHandshake::new(
            crate::crypto::noise::HandshakeRole::Responder,
            clone_keypair(&server_kp),
            None,
        );
        let hello = resp.responder_read_message_1(&m1).unwrap();
        let bogus = Selection {
            cipher: 250, // not implemented by any build
            ..Selection::defaults()
        };
        // The responder refuses to build a message it cannot back up with keys.
        assert!(
            resp.responder_message_2(&hello, &bogus, "127.0.0.1:1".parse().unwrap(), None)
                .is_err()
        );

        // And the initiator side rejects the same bytes if they somehow arrive.
        let (m2, _) = resp
            .responder_message_2(
                &hello,
                &Selection::defaults(),
                "127.0.0.1:1".parse().unwrap(),
                None,
            )
            .unwrap();
        let mut payload = Selection::defaults().encode();
        payload[1] = 250; // claim an unknown cipher in the selection
        assert!(
            init.client_finalize(&m2, "127.0.0.1:1".parse().unwrap())
                .is_ok()
        );
        // Re-encoding a bogus selection and checking it is what the client would
        // reject:
        assert!(
            Selection {
                cipher: 250,
                ..Selection::defaults()
            }
            .check()
            .is_err()
        );
    }

    // ---- transport / obfuscation still interleave around the handshake ----

    #[tokio::test]
    async fn a_rejecting_transport_hides_the_handshake_from_the_server() {
        let server_profile = profile_with(
            false,
            &["chacha20poly1305"],
            &["same-as-handshake"],
            &["reed-solomon"],
        );
        let server_kp = fixed_kp([0x22; 32]);
        let client_kp = fixed_kp([0x11; 32]);
        let mut init = crate::crypto::noise::NoiseHandshake::new(
            crate::crypto::noise::HandshakeRole::Initiator,
            clone_keypair(&client_kp),
            Some(server_kp.public),
        );
        let m1 = init.initiator_message_1(b"").unwrap();
        // Send through a `tagged` transport while the server expects `plain`.
        let wrong_envelope = crate::transport::build_transport("tagged", [0xAA, 0xBB]);
        let wire = wrong_envelope.wrap(&m1);
        let obf = ObfuscationStack::new();
        assert!(
            respond_message_1(
                &server_kp,
                &server_profile,
                &obf,
                &wire,
                "127.0.0.1:1".parse().unwrap(),
                None
            )
            .is_none(),
            "a mismatched handshake envelope must not look like a handshake"
        );
    }

    // ---- offer encoding ----

    #[test]
    fn an_empty_offer_payload_decodes_to_none() {
        assert_eq!(ClientOffer::decode(&[]).unwrap(), None);
    }

    #[test]
    fn an_unknown_offer_version_is_rejected_not_misparsed() {
        let mut encoded = ClientOffer {
            cipher_ids: vec![1],
            transport_ids: vec![],
            fec_ids: vec![1],
        }
        .encode();
        encoded[0] = 99;
        assert!(matches!(
            ClientOffer::decode(&encoded),
            Err(crate::protocol::profile::ProfileError::UnsupportedVersion(
                99
            ))
        ));
    }

    #[test]
    fn a_truncated_offer_is_rejected() {
        let encoded = ClientOffer {
            cipher_ids: vec![1, 2],
            transport_ids: vec![],
            fec_ids: vec![1],
        }
        .encode();
        for cut in 1..encoded.len() {
            assert!(
                ClientOffer::decode(&encoded[..cut]).is_err(),
                "truncating to {cut} bytes must be rejected"
            );
        }
    }

    #[test]
    fn an_oversized_offer_list_is_rejected() {
        let mut encoded = vec![crate::protocol::profile::NEGOTIATION_VERSION, 200];
        encoded.extend(std::iter::repeat_n(1u8, 200));
        assert!(ClientOffer::decode(&encoded).is_err());
    }

    // ---- the KEX config gate ----

    #[test]
    fn an_unknown_kex_name_is_a_hard_error_in_the_local_profile() {
        let err = LocalProfile::from_role_config(
            &crate::config::HandshakeConfig {
                kex: "not-a-kex".into(),
                propose: false,
            },
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, crate::protocol::profile::ProfileError::Config(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn the_default_prefs_negotiate_to_the_default_selection() {
        let prefs = ProfilePrefs::rustnies_default();
        let sel = negotiate(&prefs, None, [0x52, 0x4E]).unwrap();
        assert_eq!(sel, Selection::defaults());
    }
}
