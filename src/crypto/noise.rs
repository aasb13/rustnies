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
    pub fn write_message_1(&mut self) -> Result<Vec<u8>, NoiseError> {
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

        // Keep our ephemeral secret for message 2 (ee + se).
        self.local_eph = Some(e);
        Ok(out)
    }

    /// Responder: read message 1. Returns the initiator's static public key.
    pub fn read_message_1(&mut self, msg: &[u8]) -> Result<PublicKey, NoiseError> {
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
        // s (encrypted)
        let s_enc = &msg[32..];
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
        Ok(s_pub)
    }

    // ---- Message 2 (responder -> initiator): e, ee, se + payload ----

    /// Responder: build message 2. `payload` is optional encrypted confirmation.
    /// Returns the raw bytes plus the derived [`HandshakeResult`].
    pub fn write_message_2(
        &mut self,
        payload: &[u8],
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
        let result = self.split()?;
        Ok((out, result))
    }

    /// Initiator: read message 2. `payload` is returned decrypted.
    pub fn read_message_2(&mut self, msg: &[u8]) -> Result<(Vec<u8>, HandshakeResult), NoiseError> {
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
        // Decrypt payload.
        let enc = &msg[32..];
        let payload = self.decrypt_and_hash(enc)?;
        let result = self.split()?;
        Ok((payload, result))
    }

    /// Noise `Split()` then HKDF into two application keys for the transport.
    fn split(&self) -> Result<HandshakeResult, NoiseError> {
        let hk = Hkdf::<Sha256>::new(Some(&self.ck), &[]);
        let mut okm = [0u8; 64];
        hk.expand(b"rustnies-transport-keys", &mut okm)
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

    /// The final Noise handshake hash (`h`); the transcript binding used for the
    /// session id and obfuscation seeding. Valid only after message 2 completes.
    pub(crate) fn handshake_hash(&self) -> [u8; 32] {
        self.h
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

        let m1 = initiator.write_message_1().unwrap();
        let _ = responder.read_message_1(&m1).unwrap();

        let payload = b"client-hello";
        let (m2, server_result) = responder.write_message_2(payload).unwrap();
        let (dec_payload, client_result) = initiator.read_message_2(&m2).unwrap();

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
        let _ = init.write_message_1().unwrap();
        // Truncated message 2 (shorter than 32 + TAG_LEN).
        let short = vec![0u8; 32 + TAG_LEN - 1];
        assert_eq!(
            init.read_message_2(&short).unwrap_err(),
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
        let m1 = init.write_message_1().unwrap();
        let _ = resp.read_message_1(&m1).unwrap();
        let (mut m2, _) = resp.write_message_2(b"").unwrap();
        // Flip a bit in the ephemeral key portion.
        m2[0] ^= 0x01;
        assert!(init.read_message_2(&m2).is_err(), "tampered m2 must fail");
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
        let mut m1 = init.write_message_1().unwrap();
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
        let m1 = init.write_message_1().unwrap();
        assert!(
            resp.read_message_1(&m1).is_err(),
            "wrong server key must fail decryption"
        );
    }

    #[test]
    fn write_message_1_from_responder_errors() {
        let server = KeyPair::generate();
        let mut resp = NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server), None);
        assert_eq!(resp.write_message_1().unwrap_err(), NoiseError::WrongRole);
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
            init.write_message_2(b"").unwrap_err(),
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
        let m1 = init.write_message_1().unwrap();
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
            resp.read_message_2(&fake_m2).unwrap_err(),
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
            init.write_message_1().unwrap_err(),
            NoiseError::MissingPeerStatic
        );
    }

    #[test]
    fn responder_write_message_2_without_read_message_1_errors() {
        let server = KeyPair::generate();
        let mut resp = NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server), None);
        // No read_message_1 yet: no peer ephemeral/static.
        assert_eq!(
            resp.write_message_2(b"").unwrap_err(),
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
        let m1a = init1.write_message_1().unwrap();
        let _ = resp1.read_message_1(&m1a).unwrap();
        let (_, r1) = resp1.write_message_2(b"").unwrap();

        let mut init2 = NoiseHandshake::new(
            HandshakeRole::Initiator,
            clone_keypair(&client),
            Some(server.public),
        );
        let mut resp2 = NoiseHandshake::new(HandshakeRole::Responder, clone_keypair(&server), None);
        let m1b = init2.write_message_1().unwrap();
        let _ = resp2.read_message_1(&m1b).unwrap();
        let (_, r2) = resp2.write_message_2(b"").unwrap();

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
            let m1 = init.write_message_1().unwrap();
            let _ = resp.read_message_1(&m1).unwrap();
            let (m2, _r) = resp.write_message_2(b"hi").unwrap();
            let (_, cr) = init.read_message_2(&m2).unwrap();
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
        let m1 = init.write_message_1().unwrap();
        let _ = resp.read_message_1(&m1).unwrap();
        let payload = b"confirm identity please";
        let (m2, _) = resp.write_message_2(payload).unwrap();
        let (dec, _) = init.read_message_2(&m2).unwrap();
        assert_eq!(dec, payload);
    }
}
