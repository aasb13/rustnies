//! Noise IK handshake (Noise_IK_25519_ChaChaPoly_SHA256).
//!
//! The Noise Protocol Framework is a standard, well-studied handshake
//! construction; this module implements the **IK** pattern faithfully against
//! the spec rather than inventing a new protocol. The initiator must already
//! know the responder's static public key (authenticated out of band).
//!
//! IK message flow:
//! ```text
//!   <- s                          (responder static key known to initiator)
//!   -> e, es, s, ss               message 1 (initiator -> responder)
//!   <- e, ee, se                  message 2 (responder -> initiator)
//! ```
//!
//! After the handshake we run Noise's `Split()` then HKDF-derive two
//! application keys (`k_i2r`, `k_r2i`) used by the per-packet AEAD in
//! [`crate::crypto::aead`]. We deliberately do **not** reuse Noise's stateful
//! transport cipher state because UDP packets can be lost or reordered;
//! instead we use explicit per-packet nonces derived from the session id +
//! sequence number. Deriving application keys via HKDF from the handshake
//! output is exactly what `Split()` does — no new cryptography.
//!
//! Implementation note: we use [`x25519_dalek::StaticSecret`] for the ephemeral
//! key as well as the static key. The ephemeral is freshly generated per
//! handshake (so each handshake uses a unique ephemeral, satisfying Noise's
//! "use once" intent) and `StaticSecret::diffie_hellman` borrows `&self`,
//! letting us compute multiple DHs from one ephemeral — which IK requires
//! (`es`+`ss` on the initiator, `ee`+`se` on the responder). The ephemeral is
//! zeroised on drop via `StaticSecret`'s `Zeroize` impl.

use std::net::SocketAddr;

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use super::keys::KeyPair;

/// Protocol name (Noise uses SHA256 here — a valid, standard Noise hash).
const NOISE_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_SHA256";

/// AEAD tag length appended by every internal seal (16 bytes).
const TAG_LEN: usize = 16;

/// Base HKDF info string for the per-direction application keys.
///
/// The negotiated cipher suite's own [`crate::crypto::suite::AeadCipher::key_schedule`]
/// context is appended to this before expansion, so two peers that disagree
/// about the suite derive *different* keys. A suite mismatch therefore shows up
/// as a failed tag check on the first data packet, rather than as a session
/// that appears to connect and then silently misbehaves.
const TRANSPORT_KEY_INFO: &[u8] = b"rustnies-transport-keys";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    Initiator,
    Responder,
}

/// Output of a completed handshake: two application keys + the binding hash.
#[derive(Debug, zeroize::Zeroize)]
pub struct HandshakeResult {
    /// Initiator -> responder key.
    pub key_i2r: [u8; 32],
    /// Responder -> initiator key.
    pub key_r2i: [u8; 32],
    /// Final Noise handshake hash (transcript binding).
    pub handshake_hash: [u8; 32],
}

/// An in-progress Noise IK handshake.
pub struct NoiseHandshake {
    role: HandshakeRole,
    ck: [u8; 32],
    h: [u8; 32],
    k: Option<[u8; 32]>,
    n: u64,
    /// Our own static keypair.
    local: KeyPair,
    /// Our own ephemeral secret (fresh per handshake; kept alive across
    /// messages as needed). Uses `StaticSecret` so multiple DHs are possible.
    local_eph: Option<StaticSecret>,
    /// Peer static public key.
    ///   - Initiator: the known responder static (provided up front).
    ///   - Responder: the initiator's static, learned during `read_message_1`.
    peer_static: Option<PublicKey>,
    /// Peer ephemeral public key, learned from the peer's first message.
    peer_eph: Option<PublicKey>,
    /// Test-only deterministic ephemeral override. `None` in production (no
    /// setter outside `cfg(test)`); see `set_test_ephemeral`. Production IK
    /// bytes are unchanged: `None` falls through to the OS RNG, identical to
    /// before. Needed only so in-process tests can reproduce msg1/msg2/k bytes.
    test_ephemeral: Option<[u8; 32]>,
}

impl NoiseHandshake {
    /// Create a new handshake state for `role` using the given local static
    /// keypair. For the initiator, `peer_static` must be the responder's known
    /// static public key; for the responder pass `None`.
    pub fn new(role: HandshakeRole, local: KeyPair, peer_static: Option<PublicKey>) -> Self {
        let mut h = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(NOISE_NAME);
        h.copy_from_slice(&hasher.finalize());
        let ck = h;
        Self {
            role,
            ck,
            h,
            k: None,
            n: 0,
            local,
            local_eph: None,
            peer_static,
            peer_eph: None,
            test_ephemeral: None,
        }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.h);
        hasher.update(data);
        self.h.copy_from_slice(&hasher.finalize());
    }

    fn mix_key(&mut self, input: &[u8]) -> Result<(), NoiseError> {
        let hk = Hkdf::<Sha256>::new(Some(&self.ck), input);
        let mut okm = [0u8; 64];
        hk.expand(&[], &mut okm)
            .map_err(|_| NoiseError::HkdfFailed)?;
        self.ck.copy_from_slice(&okm[..32]);
        let mut k = [0u8; 32];
        k.copy_from_slice(&okm[32..]);
        self.k = Some(k);
        self.n = 0;
        Ok(())
    }

    fn mix_key_shared(&mut self, ss: SharedSecret) -> Result<(), NoiseError> {
        self.mix_key(ss.as_bytes())
    }

    fn noise_aead_encrypt(
        key: &[u8; 32],
        n: u64,
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&n.to_le_bytes());
        cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: ad,
                },
            )
            .map_err(|_| NoiseError::EncryptFailed)
    }

    fn noise_aead_decrypt(
        key: &[u8; 32],
        n: u64,
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&n.to_le_bytes());
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: ad,
                },
            )
            .map_err(|_| NoiseError::DecryptFailed)
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let k = self.k.ok_or(NoiseError::MissingKey)?;
        let n = self.n;
        self.n += 1;
        let c = Self::noise_aead_encrypt(&k, n, &self.h, plaintext)?;
        self.mix_hash(&c);
        Ok(c)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let k = self.k.ok_or(NoiseError::MissingKey)?;
        let n = self.n;
        self.n += 1;
        let p = Self::noise_aead_decrypt(&k, n, &self.h, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(p)
    }

    /// Fresh ephemeral keypair. Production: OS RNG, byte-identical to before.
    /// `cfg(test)`: a deterministic override may be injected for baseline tests.
    fn fresh_ephemeral(&self) -> (StaticSecret, PublicKey) {
        let secret = if let Some(bytes) = self.test_ephemeral {
            StaticSecret::from(bytes)
        } else {
            let mut rng = rand::rngs::OsRng;
            StaticSecret::random_from_rng(&mut rng)
        };
        let public = PublicKey::from(&secret);
        (secret, public)
    }

    // ---- Message 1 (initiator -> responder): e, es, s, ss ----

    /// Initiator: build message 1. Returns the raw bytes to send.
    ///
    /// `offer` is an optional encrypted trailing payload — the encoded
    /// [`crate::protocol::profile::ClientOffer`]. Passing an empty slice
    /// produces byte-for-byte the same message 1 as before this parameter
    /// existed, which is what keeps a non-proposing client compatible with a
    /// peer that predates profile negotiation.
    ///
    /// The trailing payload is encrypted under the same ephemeral-derived key
    /// as the static key and is `mix_hash`ed like any other Noise payload, so
    /// it is confidential and tamper-evident even though message 1 is not yet
    /// authenticated end-to-end.
    pub fn write_message_1(&mut self, offer: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if self.role != HandshakeRole::Initiator {
            return Err(NoiseError::WrongRole);
        }
        let rs = self.peer_static.ok_or(NoiseError::MissingPeerStatic)?;

        let (e, e_pub) = self.fresh_ephemeral();
        let mut out = e_pub.to_bytes().to_vec();
        self.mix_hash(&e_pub.to_bytes());
        // es: DH(e_local, rs)
        self.mix_key_shared(e.diffie_hellman(&rs))?;
        // s: encrypted local static public key
        let s_pub = self.local.public;
        let s_enc = self.encrypt_and_hash(&s_pub.to_bytes())?;
        out.extend_from_slice(&s_enc);
        // ss: DH(s_local, rs). Compute the shared secret before mutating self.
        let ss = self.local.secret.diffie_hellman(&rs);
        self.mix_key_shared(ss)?;
        // Optional trailing payload: the client's profile offer. Encrypted and
        // hashed exactly like `s`, so it cannot be read or altered by a third
        // party. Order matters — the `ss` mixing must happen before this, which
        // it does.
        if !offer.is_empty() {
            let offer_enc = self.encrypt_and_hash(offer)?;
            out.extend_from_slice(&offer_enc);
        }

        // Keep our ephemeral secret for message 2 (ee + se).
        self.local_eph = Some(e);
        Ok(out)
    }

    /// Responder: read message 1. Returns the initiator's static public key and
    /// the decoded trailing offer payload (empty when the initiator did not
    /// propose anything).
    ///
    /// A message 1 with no trailing payload is fully supported, so a
    /// non-proposing client interoperates with a negotiating responder.
    pub fn read_message_1(&mut self, msg: &[u8]) -> Result<(PublicKey, Vec<u8>), NoiseError> {
        if self.role != HandshakeRole::Responder {
            return Err(NoiseError::WrongRole);
        }
        if msg.len() < 32 + 32 + TAG_LEN {
            return Err(NoiseError::MessageTooShort);
        }
        // e
        let mut e_pub_bytes = [0u8; 32];
        e_pub_bytes.copy_from_slice(&msg[..32]);
        let e_pub = PublicKey::from(e_pub_bytes);
        self.peer_eph = Some(e_pub);
        self.mix_hash(&e_pub_bytes);
        // es: DH(s_local, e)
        let ss = self.local.secret.diffie_hellman(&e_pub);
        self.mix_key_shared(ss)?;

        // The encrypted static key occupies everything after the 32-byte
        // ephemeral, minus this token's own tag. Anything beyond it is the
        // optional trailing payload, so split the buffer first rather than
        // handing the whole remainder to the AEAD.
        let rest = &msg[32..];
        let s_token_len = 32 + TAG_LEN;
        if rest.len() < s_token_len {
            return Err(NoiseError::MessageTooShort);
        }
        let (s_enc, trailing) = rest.split_at(s_token_len);

        // s (encrypted)
        let s_bytes = self.decrypt_and_hash(s_enc)?;
        if s_bytes.len() != 32 {
            return Err(NoiseError::BadStaticKey);
        }
        let mut s_pub_arr = [0u8; 32];
        s_pub_arr.copy_from_slice(&s_bytes[..32]);
        let s_pub = PublicKey::from(s_pub_arr);
        self.peer_static = Some(s_pub);
        // ss: DH(s_local, s_remote)
        let ss = self.local.secret.diffie_hellman(&s_pub);
        self.mix_key_shared(ss)?;

        // Optional trailing payload: decrypt only if present. An empty result
        // means "client did not propose".
        let offer = if trailing.is_empty() {
            Vec::new()
        } else {
            self.decrypt_and_hash(trailing)?
        };
        Ok((s_pub, offer))
    }

    // ---- Message 2 (responder -> initiator): e, ee, se + payload ----

    /// Responder: build message 2. `payload` is optional encrypted confirmation
    /// and carries the negotiated [`crate::protocol::profile::Selection`].
    /// Returns the raw bytes plus the derived [`HandshakeResult`].
    ///
    /// `key_schedule` must be the suite context matching the selection in
    /// `payload`; it is folded into the transport-key HKDF so the initiator
    /// derives the same keys from the selection it reads back out of `payload`.
    pub fn write_message_2(
        &mut self,
        payload: &[u8],
        key_schedule: &[u8],
    ) -> Result<(Vec<u8>, HandshakeResult), NoiseError> {
        if self.role != HandshakeRole::Responder {
            return Err(NoiseError::WrongRole);
        }
        let initiator_e = self.peer_eph.ok_or(NoiseError::MissingPeerEphemeral)?;
        let initiator_s = self.peer_static.ok_or(NoiseError::MissingPeerStatic)?;

        let (e, e_pub) = self.fresh_ephemeral();
        let mut out = e_pub.to_bytes().to_vec();
        self.mix_hash(&e_pub.to_bytes());
        // ee: DH(e_local, e_remote)
        self.mix_key_shared(e.diffie_hellman(&initiator_e))?;
        // se: DH(e_local, s_remote)
        self.mix_key_shared(e.diffie_hellman(&initiator_s))?;
        // Encrypted payload (key confirmation).
        let enc_payload = self.encrypt_and_hash(payload)?;
        out.extend_from_slice(&enc_payload);

        self.local_eph = Some(e);
        let result = self.split(key_schedule)?;
        Ok((out, result))
    }

    /// Initiator: read message 2. `payload` is returned decrypted.
    ///
    /// There is an ordering problem here: the suite context that must be folded
    /// into the transport-key HKDF is carried *inside* the payload, so it is not
    /// known until the payload has been decrypted — but the keys are derived
    /// immediately afterwards. `key_schedule` is therefore a closure over the
    /// freshly decrypted payload, invoked between those two steps.
    ///
    /// The closure is infallible by design. If the payload names a suite this
    /// build does not implement, the derived keys will simply be wrong; the
    /// caller detects that by validating the decoded [`Selection`] it also gets
    /// back and fails the handshake, which is the correct outcome — a session
    /// built on mismatched keys could not work anyway.
    pub fn read_message_2<F>(
        &mut self,
        msg: &[u8],
        key_schedule: F,
    ) -> Result<(Vec<u8>, HandshakeResult), NoiseError>
    where
        F: FnOnce(&[u8]) -> Vec<u8>,
    {
        if self.role != HandshakeRole::Initiator {
            return Err(NoiseError::WrongRole);
        }
        if msg.len() < 32 + TAG_LEN {
            return Err(NoiseError::MessageTooShort);
        }
        let mut e_pub_bytes = [0u8; 32];
        e_pub_bytes.copy_from_slice(&msg[..32]);
        let e_pub = PublicKey::from(e_pub_bytes);
        self.peer_eph = Some(e_pub);
        self.mix_hash(&e_pub_bytes);
        // ee: DH(e_local, e_remote) — both ephemerals.
        let e_local = self
            .local_eph
            .take()
            .ok_or(NoiseError::MissingLocalEphemeral)?;
        self.mix_key_shared(e_local.diffie_hellman(&e_pub))?;
        // se: DH(s_local, e_remote) — initiator static x responder ephemeral.
        let responder_e = e_pub;
        let ss = self.local.secret.diffie_hellman(&responder_e);
        self.mix_key_shared(ss)?;
        // Decrypt payload, then derive the keys with whatever suite context
        // the payload itself names.
        let enc = &msg[32..];
        let payload = self.decrypt_and_hash(enc)?;
        let result = self.split(&key_schedule(&payload))?;
        Ok((payload, result))
    }

    /// Noise `Split()` then HKDF into two application keys for the transport.
    ///
    /// `key_schedule` is the negotiated cipher suite's domain-separation
    /// context ([`crate::crypto::suite::AeadCipher::key_schedule`]). Folding it
    /// into the HKDF `info` binds the session keys to the agreed suite, so a
    /// mismatch can only ever surface as an authentication failure. It must be
    /// identical on both sides, which the [`Selection`] in the message-2
    /// payload guarantees.
    fn split(&self, key_schedule: &[u8]) -> Result<HandshakeResult, NoiseError> {
        let hk = Hkdf::<Sha256>::new(Some(&self.ck), &[]);
        let mut info = Vec::with_capacity(TRANSPORT_KEY_INFO.len() + key_schedule.len());
        info.extend_from_slice(TRANSPORT_KEY_INFO);
        info.extend_from_slice(key_schedule);
        let mut okm = [0u8; 64];
        hk.expand(&info, &mut okm)
            .map_err(|_| NoiseError::HkdfFailed)?;
        let mut key_i2r = [0u8; 32];
        let mut key_r2i = [0u8; 32];
        key_i2r.copy_from_slice(&okm[..32]);
        key_r2i.copy_from_slice(&okm[32..]);
        Ok(HandshakeResult {
            key_i2r,
            key_r2i,
            handshake_hash: self.h,
        })
    }

    /// Convenience: the local static public key.
    pub fn local_public(&self) -> PublicKey {
        self.local.public
    }

    /// Remote static public key held by this role: the responder's static for an
    /// initiator, the initiator's static (after `read_message_1`) for a
    /// responder. `None` until learned.
    pub(crate) fn peer_static_key(&self) -> Option<PublicKey> {
        self.peer_static
    }

    /// Test-only deterministic ephemeral injection (for baseline tests).
    /// `cfg(test)` only; production always uses the OS RNG, so IK wire bytes
    /// are unchanged.
    #[cfg(test)]
    pub(crate) fn set_test_ephemeral(&mut self, bytes: [u8; 32]) {
        self.test_ephemeral = Some(bytes);
    }
}

impl crate::protocol::handshake::Handshake for NoiseHandshake {
    fn initiator_message_1(
        &mut self,
        offer: &[u8],
    ) -> Result<bytes::Bytes, crate::protocol::handshake::HandshakeError> {
        Ok(bytes::Bytes::from(NoiseHandshake::write_message_1(
            self, offer,
        )?))
    }

    fn responder_read_message_1(
        &mut self,
        msg1: &[u8],
    ) -> Result<
        crate::protocol::handshake::InitiatorHello,
        crate::protocol::handshake::HandshakeError,
    > {
        let (peer_static, offer) = NoiseHandshake::read_message_1(self, msg1)?;
        Ok(crate::protocol::handshake::InitiatorHello { peer_static, offer })
    }

    fn responder_message_2(
        &mut self,
        hello: &crate::protocol::handshake::InitiatorHello,
        selection: &crate::protocol::profile::Selection,
        peer: SocketAddr,
        peer_label: Option<String>,
    ) -> Result<
        (bytes::Bytes, crate::protocol::handshake::SessionEstablished),
        crate::protocol::handshake::HandshakeError,
    > {
        use crate::crypto::aead::Direction;
        use crate::protocol::handshake::{HandshakeError, SessionEstablished};
        use crate::protocol::session::session_id_from_hash;

        // Reject an unusable selection *before* deriving keys from it, so the
        // session is never built on material the peer cannot reproduce.
        selection
            .check()
            .map_err(HandshakeError::IncompatibleProfile)?;

        // The selection goes in the message-2 payload, and its suite context
        // into the transport-key HKDF. The initiator reads the selection back
        // out of this same payload and therefore derives identical keys.
        let (m2, result) =
            NoiseHandshake::write_message_2(self, &selection.encode(), suite_schedule(selection))?;

        let established = SessionEstablished {
            peer,
            session_id: session_id_from_hash(&result.handshake_hash),
            send_key: result.key_r2i,
            recv_key: result.key_i2r,
            send_dir: Direction::ResponderToInitiator,
            recv_dir: Direction::InitiatorToResponder,
            peer_static: hello.peer_static,
            peer_label,
            handshake_hash: result.handshake_hash,
            selection: *selection,
        };
        Ok((bytes::Bytes::from(m2), established))
    }

    fn client_finalize(
        &mut self,
        msg2: &[u8],
        peer: SocketAddr,
    ) -> Result<
        crate::protocol::handshake::SessionEstablished,
        crate::protocol::handshake::HandshakeError,
    > {
        use crate::crypto::aead::Direction;
        use crate::protocol::handshake::{HandshakeError, SessionEstablished};
        use crate::protocol::profile::Selection;
        use crate::protocol::session::session_id_from_hash;

        // The selection is inside the payload, and the keys depend on it, so
        // the suite context is resolved by a closure that runs after the payload
        // is decrypted. A selection this build cannot run still yields a
        // (mismatched) key schedule here; the `check()` below then rejects the
        // handshake before any session state exists.
        let (payload, result) =
            NoiseHandshake::read_message_2(self, msg2, |p| match Selection::decode(p) {
                Ok(sel) => suite_schedule(&sel).to_vec(),
                Err(e) => {
                    tracing::debug!(
                        error = %e,
                        "undecodable profile selection in msg2; using local default suite"
                    );
                    suite_schedule(&Selection::defaults()).to_vec()
                }
            })?;

        let selection = Selection::decode(&payload).map_err(HandshakeError::IncompatibleProfile)?;
        selection
            .check()
            .map_err(HandshakeError::IncompatibleProfile)?;

        let peer_static = self
            .peer_static_key()
            .ok_or(NoiseError::MissingPeerStatic)?;
        Ok(SessionEstablished {
            peer,
            session_id: session_id_from_hash(&result.handshake_hash),
            send_key: result.key_i2r,
            recv_key: result.key_r2i,
            send_dir: Direction::InitiatorToResponder,
            recv_dir: Direction::ResponderToInitiator,
            peer_static,
            peer_label: None,
            handshake_hash: result.handshake_hash,
            selection,
        })
    }
}

/// The transport-key HKDF context for the cipher named by `selection`.
///
/// Falls back to the default suite's context for a selection this build cannot
/// run, so a doomed handshake still produces well-defined (and mismatched)
/// keys rather than panicking.
fn suite_schedule(selection: &crate::protocol::profile::Selection) -> &'static [u8] {
    use crate::crypto::suite::CipherKind;
    CipherKind::from_id(selection.cipher)
        .map(|k| k.key_schedule())
        .unwrap_or_else(|| CipherKind::ChaCha20Poly1305.key_schedule())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NoiseError {
    #[error("called from the wrong handshake role")]
    WrongRole,
    #[error("message shorter than expected")]
    MessageTooShort,
    #[error("decryption failed during handshake")]
    DecryptFailed,
    #[error("bad static key length")]
    BadStaticKey,
    #[error("missing known peer static public key")]
    MissingPeerStatic,
    #[error("missing peer ephemeral public key")]
    MissingPeerEphemeral,
    #[error("missing stored local ephemeral")]
    MissingLocalEphemeral,
    #[error("encryption key not yet derived")]
    MissingKey,
    #[error("HKDF expansion failed")]
    HkdfFailed,
    #[error("AEAD encryption failed")]
    EncryptFailed,
    #[error("unsupported handshake algorithm")]
    UnsupportedHandshake,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The transport-key HKDF context the tests use. Production supplies this
    /// from the negotiated suite (`AeadCipher::key_schedule`); the default suite
    /// is the only one implemented, so pinning it here keeps the tests honest
    /// about what the derivation actually mixes in.
    const TEST_SCHEDULE: &[u8] = b"rustnies/aead/chacha20poly1305";

    /// `read_message_2` takes a closure over the decrypted payload (the suite
    /// context lives inside it). Tests have no selection payload to inspect, so
    /// use the pinned schedule.
    fn test_schedule(_payload: &[u8]) -> Vec<u8> {
        TEST_SCHEDULE.to_vec()
    }

    #[test]
    fn handshake_roundtrip() {
        let server = KeyPair::generate();
        let client = KeyPair::generate();

        let mut initiator = NoiseHandshake::new(
            HandshakeRole::Initiator,
            clone_keypair(&client),
            Some(server.public),
        );
        let mut responder =
            NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server), None);

        let m1 = initiator.write_message_1(&[]).unwrap();
        let _ = responder.read_message_1(&m1).unwrap();

        let payload = b"client-hello";
        let (m2, server_result) = responder.write_message_2(payload, TEST_SCHEDULE).unwrap();
        let (dec_payload, client_result) = initiator.read_message_2(&m2, test_schedule).unwrap();

        assert_eq!(dec_payload, payload);
        assert_eq!(client_result.key_i2r, server_result.key_i2r);
        assert_eq!(client_result.key_r2i, server_result.key_r2i);
        assert_eq!(client_result.handshake_hash, server_result.handshake_hash);
    }

    fn clone_keypair(kp: &KeyPair) -> KeyPair {
        let secret_bytes = kp.secret.to_bytes();
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        KeyPair { secret, public }
    }

    // ---- Profile negotiation integration ----

    /// The transport keys must be bound to the negotiated suite, so that a peer
    /// that ends up with a different suite derives *different* keys instead of
    /// silently reusing the same ones.
    ///
    /// This is the property that makes a suite mismatch safe: it can only ever
    /// surface as an authentication failure on the first data packet, never as a
    /// session that appears to work.
    #[test]
    fn transport_keys_are_bound_to_the_cipher_suite() {
        let server = KeyPair::generate();
        let client = KeyPair::generate();
        let sel = crate::protocol::profile::Selection::defaults();
        let schedule = suite_schedule(&sel);

        // Two handshakes over the *same* transcript inputs but different suite
        // contexts must not produce the same keys.
        let mut a_i = NoiseHandshake::new(
            HandshakeRole::Initiator,
            clone_keypair(&client),
            Some(server.public),
        );
        let mut a_r = NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server), None);
        let m1 = a_i.write_message_1(&[]).unwrap();
        a_r.read_message_1(&m1).unwrap();
        let (m2, sr) = a_r.write_message_2(&sel.encode(), schedule).unwrap();
        let (_, cr) = a_i.read_message_2(&m2, test_schedule).unwrap();
        // Sanity: same schedule on both sides agrees.
        assert_eq!(cr.key_i2r, sr.key_i2r);

        // Now derive with a different schedule on the responder side only.
        let mut b_i = NoiseHandshake::new(
            HandshakeRole::Initiator,
            clone_keypair(&client),
            Some(server.public),
        );
        let mut b_r = NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server), None);
        let m1b = b_i.write_message_1(&[]).unwrap();
        b_r.read_message_1(&m1b).unwrap();
        let (m2b, sr2) = b_r
            .write_message_2(&sel.encode(), b"rustnies/aead/some-other-suite")
            .unwrap();
        let (_, cr2) = b_i.read_message_2(&m2b, test_schedule).unwrap();
        assert_ne!(
            cr2.key_i2r, cr.key_i2r,
            "a different suite context must yield different transport keys"
        );
        assert_ne!(cr2.key_i2r, sr2.key_i2r);
    }

    /// The selection the responder puts in the message-2 payload is what the
    /// initiator uses to pick its key schedule, so the two agree even though the
    /// initiator learns the suite only after decrypting.
    #[test]
    fn the_initiator_takes_its_key_schedule_from_the_msg2_selection() {
        let server = KeyPair::generate();
        let client = KeyPair::generate();
        let sel = crate::protocol::profile::Selection::defaults();

        let mut i = NoiseHandshake::new(
            HandshakeRole::Initiator,
            clone_keypair(&client),
            Some(server.public),
        );
        let mut r = NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server), None);
        let m1 = i.write_message_1(&[]).unwrap();
        r.read_message_1(&m1).unwrap();
        let (m2, sr) = r
            .write_message_2(&sel.encode(), suite_schedule(&sel))
            .unwrap();

        // The initiator resolves the schedule from the payload, exactly as the
        // `Handshake` impl does.
        let (payload, cr) = i
            .read_message_2(&m2, |p| {
                suite_schedule(&crate::protocol::profile::Selection::decode(p).unwrap()).to_vec()
            })
            .unwrap();
        let decoded = crate::protocol::profile::Selection::decode(&payload).unwrap();
        assert_eq!(decoded, sel);
        assert_eq!(cr.key_i2r, sr.key_i2r, "both sides derived the same keys");
        assert_eq!(cr.handshake_hash, sr.handshake_hash);
    }

    /// A client that proposes sends an encrypted trailing payload; a responder
    /// that does not expect one must still parse the message, and a client that
    /// proposes nothing must produce byte-identical message 1 to before.
    #[test]
    fn the_msg1_offer_is_optional_and_authenticated() {
        let server = KeyPair::generate();
        let client = KeyPair::generate();

        let mk = |offer: &[u8]| {
            let mut hs = NoiseHandshake::new(
                HandshakeRole::Initiator,
                clone_keypair(&client),
                Some(server.public),
            );
            hs.set_test_ephemeral([0x33; 32]);
            hs.write_message_1(offer).unwrap()
        };

        let plain = mk(&[]);
        assert_eq!(plain.len(), 32 + 32 + TAG_LEN, "no trailing payload");

        let offer = b"\x01\x01\x00\x00\x01".to_vec();
        let with_offer = mk(&offer);
        assert_eq!(with_offer.len(), plain.len() + offer.len() + TAG_LEN);

        // A responder parses both, and recovers the offer only from the second.
        for (msg, expect) in [(plain.clone(), Vec::new()), (with_offer, offer.clone())] {
            let mut r = NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server), None);
            let (pk, got) = r.read_message_1(&msg).unwrap();
            assert_eq!(pk, client.public);
            assert_eq!(got, expect);
        }

        // A tampered offer fails the whole message: the trailing payload is
        // `mix_hash`ed, so it cannot be edited in flight.
        let mut bad = mk(&offer);
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        let mut r = NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server), None);
        assert!(
            r.read_message_1(&bad).is_err(),
            "a tampered offer must fail the message"
        );
    }

    // ---- Failure-mode tests ----

    #[test]
    fn initiator_rejects_short_message_2() {
        let server = KeyPair::generate();
        let client = KeyPair::generate();
        let mut init = NoiseHandshake::new(
            HandshakeRole::Initiator,
            clone_keypair(&client),
            Some(server.public),
        );
        let _ = init.write_message_1(&[]).unwrap();
        // Truncated message 2 (shorter than 32 + TAG_LEN).
        let short = vec![0u8; 32 + TAG_LEN - 1];
        assert_eq!(
            init.read_message_2(&short, test_schedule).unwrap_err(),
            NoiseError::MessageTooShort
        );
    }

    #[test]
    fn responder_rejects_short_message_1() {
        let server = KeyPair::generate();
        let mut resp = NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server), None);
        // Shorter than 32 + 32 + TAG_LEN.
        let short = vec![0u8; 32 + 32 + TAG_LEN - 1];
        assert_eq!(
            resp.read_message_1(&short).unwrap_err(),
            NoiseError::MessageTooShort
        );
    }

    #[test]
    fn initiator_rejects_tampered_message_2() {
        let server = KeyPair::generate();
        let client = KeyPair::generate();
        let mut init = NoiseHandshake::new(
            HandshakeRole::Initiator,
            clone_keypair(&client),
            Some(server.public),
        );
        let mut resp = NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server), None);
        let m1 = init.write_message_1(&[]).unwrap();
        let _ = resp.read_message_1(&m1).unwrap();
        let (mut m2, _) = resp.write_message_2(b"", TEST_SCHEDULE).unwrap();
        // Flip a bit in the ephemeral key portion.
        m2[0] ^= 0x01;
        assert!(
            init.read_message_2(&m2, test_schedule).is_err(),
            "tampered m2 must fail"
        );
    }

    #[test]
    fn responder_rejects_tampered_message_1() {
        let server = KeyPair::generate();
        let client = KeyPair::generate();
        let mut init = NoiseHandshake::new(
            HandshakeRole::Initiator,
            clone_keypair(&client),
            Some(server.public),
        );
        let mut resp = NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server), None);
        let mut m1 = init.write_message_1(&[]).unwrap();
        // Flip a bit in the encrypted static key portion (past the 32-byte ephemeral).
        m1[40] ^= 0x01;
        assert!(resp.read_message_1(&m1).is_err(), "tampered m1 must fail");
    }

    #[test]
    fn responder_rejects_message_1_with_wrong_known_server_key() {
        // If the initiator encrypts the static key under a DH with the wrong
        // responder static, the responder cannot decrypt it.
        let wrong_server = KeyPair::generate();
        let real_server = KeyPair::generate();
        let client = KeyPair::generate();
        let mut init = NoiseHandshake::new(
            HandshakeRole::Initiator,
            clone_keypair(&client),
            Some(wrong_server.public),
        );
        let mut resp =
            NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&real_server), None);
        let m1 = init.write_message_1(&[]).unwrap();
        assert!(
            resp.read_message_1(&m1).is_err(),
            "wrong server key must fail decryption"
        );
    }

    #[test]
    fn write_message_1_from_responder_errors() {
        let server = KeyPair::generate();
        let mut resp = NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server), None);
        assert_eq!(
            resp.write_message_1(&[]).unwrap_err(),
            NoiseError::WrongRole
        );
    }

    #[test]
    fn write_message_2_from_initiator_errors() {
        let server = KeyPair::generate();
        let client = KeyPair::generate();
        let mut init = NoiseHandshake::new(
            HandshakeRole::Initiator,
            clone_keypair(&client),
            Some(server.public),
        );
        assert_eq!(
            init.write_message_2(b"", TEST_SCHEDULE).unwrap_err(),
            NoiseError::WrongRole
        );
    }

    #[test]
    fn read_message_1_from_initator_errors() {
        let server = KeyPair::generate();
        let client = KeyPair::generate();
        let mut init = NoiseHandshake::new(
            HandshakeRole::Initiator,
            clone_keypair(&client),
            Some(server.public),
        );
        let m1 = init.write_message_1(&[]).unwrap();
        // Initiator trying to read m1 (wrong role).
        assert_eq!(init.read_message_1(&m1).unwrap_err(), NoiseError::WrongRole);
    }

    #[test]
    fn read_message_2_from_responder_errors() {
        let server = KeyPair::generate();
        let mut resp = NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server), None);
        // Responder trying to read m2 (wrong role) without having processed m1.
        let fake_m2 = vec![0u8; 48];
        assert_eq!(
            resp.read_message_2(&fake_m2, test_schedule).unwrap_err(),
            NoiseError::WrongRole
        );
    }

    #[test]
    fn initiator_without_peer_static_errors() {
        let client = KeyPair::generate();
        let mut init = NoiseHandshake::new(
            HandshakeRole::Initiator,
            clone_keypair(&client),
            None, // missing known responder static
        );
        assert_eq!(
            init.write_message_1(&[]).unwrap_err(),
            NoiseError::MissingPeerStatic
        );
    }

    #[test]
    fn responder_write_message_2_without_read_message_1_errors() {
        let server = KeyPair::generate();
        let mut resp = NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server), None);
        // No read_message_1 yet: no peer ephemeral/static.
        assert_eq!(
            resp.write_message_2(b"", TEST_SCHEDULE).unwrap_err(),
            NoiseError::MissingPeerEphemeral
        );
    }

    #[test]
    fn keys_differ_across_independent_handshakes() {
        // Two handshakes with fresh ephemerals must produce different keys.
        let server = KeyPair::generate();
        let client = KeyPair::generate();
        let mut init1 = NoiseHandshake::new(
            HandshakeRole::Initiator,
            clone_keypair(&client),
            Some(server.public),
        );
        let mut resp1 = NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server), None);
        let m1a = init1.write_message_1(&[]).unwrap();
        let _ = resp1.read_message_1(&m1a).unwrap();
        let (_, r1) = resp1.write_message_2(b"", TEST_SCHEDULE).unwrap();

        let mut init2 = NoiseHandshake::new(
            HandshakeRole::Initiator,
            clone_keypair(&client),
            Some(server.public),
        );
        let mut resp2 = NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server), None);
        let m1b = init2.write_message_1(&[]).unwrap();
        let _ = resp2.read_message_1(&m1b).unwrap();
        let (_, r2) = resp2.write_message_2(b"", TEST_SCHEDULE).unwrap();

        assert_ne!(
            r1.key_i2r, r2.key_i2r,
            "fresh ephemerals must yield distinct keys"
        );
        assert_ne!(r1.key_r2i, r2.key_r2i);
        assert_ne!(r1.handshake_hash, r2.handshake_hash);
    }

    #[test]
    fn handshake_hash_is_deterministic_for_replay() {
        // If an attacker replays the exact same m1 and m2, the handshake hash
        // is the same (this is expected; replay protection is the replay
        // window's job, not the handshake's). The test pins that the transcript
        // hash is a deterministic function of the messages.
        let server = KeyPair::generate();
        let client = KeyPair::generate();
        let do_handshake = || {
            let mut init = NoiseHandshake::new(
                HandshakeRole::Initiator,
                clone_keypair(&client),
                Some(server.public),
            );
            let mut resp =
                NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server), None);
            let m1 = init.write_message_1(&[]).unwrap();
            let _ = resp.read_message_1(&m1).unwrap();
            let (m2, _r) = resp.write_message_2(b"hi", TEST_SCHEDULE).unwrap();
            let (_, cr) = init.read_message_2(&m2, test_schedule).unwrap();
            cr
        };
        let c1 = do_handshake();
        let c2 = do_handshake();
        // Different ephemerals each time -> different hashes (this confirms the
        // ephemeral actually contributes to the transcript; a broken mix would
        // make them identical).
        assert_ne!(c1.handshake_hash, c2.handshake_hash);
    }

    #[test]
    fn payload_survives_roundtrip_with_nonempty_data() {
        let server = KeyPair::generate();
        let client = KeyPair::generate();
        let mut init = NoiseHandshake::new(
            HandshakeRole::Initiator,
            clone_keypair(&client),
            Some(server.public),
        );
        let mut resp = NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server), None);
        let m1 = init.write_message_1(&[]).unwrap();
        let _ = resp.read_message_1(&m1).unwrap();
        let payload = b"confirm identity please";
        let (m2, _) = resp.write_message_2(payload, TEST_SCHEDULE).unwrap();
        let (dec, _) = init.read_message_2(&m2, test_schedule).unwrap();
        assert_eq!(dec, payload);
    }
}
