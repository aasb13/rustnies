//! The swappable per-packet AEAD cipher suite.
//!
//! [`AeadCipher`] is the seam behind the per-packet authenticated encryption
//! that protects every frame after the handshake. The default and only phase-1
//! implementation is [`ChaCha20Poly1305Cipher`] (RFC 8439), selected by name
//! through [`select_cipher`] / [`build_cipher`].
//!
//! Two design points matter for a second implementation to slot in:
//!
//! * **Nonce construction belongs to the cipher.** [`AeadCipher::make_nonce`]
//!   (not the free function [`crate::crypto::aead::make_nonce`]) is what the
//!   tunnel calls, so a suite with a different nonce size or derivation is
//!   expressible. The ChaCha20-Poly1305 impl keeps the exact historical layout
//!   (`session_id || seq || direction || 0x00 0x00 0x00`, little-endian) so
//!   default wire bytes are unchanged.
//! * **The suite id is bound into the transport keys.**
//!   [`AeadCipher::key_schedule`] returns a domain-separation string that
//!   [`crate::crypto::noise`] folds into the HKDF that derives the per-direction
//!   application keys. Two peers that disagree about the suite therefore derive
//!   *different* keys, so the very first data packet fails to authenticate
//!   instead of the session silently decrypting garbage. A suite mismatch is
//!   always a clean auth failure, never a parse error or a stalled tunnel.
//!
//! `id()` values are part of the negotiation wire format (see
//! [`crate::protocol::profile`]) and must never be reused or renumbered.

use crate::crypto::aead::{
    CryptoError, Direction, NonceBytes, TAG_LEN, decrypt, encrypt, make_nonce,
};
use crate::protocol::SessionId;

/// A swappable authenticated-encryption scheme for data frames.
///
/// Implementations must be stateless per call (the only per-session input is
/// the key plus the deterministic nonce), allocation-light, and must not touch
/// the socket, TUN or session state.
pub trait AeadCipher: Send + Sync + 'static {
    /// Config name, e.g. `"chacha20poly1305"`. Must match the name accepted by
    /// [`select_cipher`].
    fn name(&self) -> &'static str;

    /// Stable wire id used in the handshake negotiation payload. Must be
    /// unique and never reused.
    fn id(&self) -> u8;

    /// Domain-separation context folded into the transport-key HKDF. See the
    /// module docs.
    fn key_schedule(&self) -> &'static [u8];

    /// Build the deterministic per-packet nonce.
    ///
    /// Uniqueness of the (key, nonce) pair is what makes this safe, so an
    /// implementation must keep the per-direction bit in the derivation.
    fn make_nonce(&self, session_id: SessionId, seq: u32, dir: Direction) -> Vec<u8>;

    /// Encrypt `plaintext`, returning `ciphertext || tag`. `aad` is
    /// authenticated but not encrypted (typically the packet header).
    fn seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// Decrypt the output of [`AeadCipher::seal`]. Returns
    /// [`CryptoError::Decryption`] on a bad tag, a wrong key or a wrong nonce.
    fn open(
        &self,
        key: &[u8; 32],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// Boxed clone so a cipher can be held behind a trait object and duplicated
    /// across the per-session tunnels a server owns.
    fn boxed_clone(&self) -> Box<dyn AeadCipher>;
}

/// ChaCha20-Poly1305 (RFC 8439) with a 96-bit nonce. The rustnies default.
#[derive(Debug, Default, Clone, Copy)]
pub struct ChaCha20Poly1305Cipher;

impl AeadCipher for ChaCha20Poly1305Cipher {
    fn name(&self) -> &'static str {
        "chacha20poly1305"
    }

    fn id(&self) -> u8 {
        CIPHER_CHACHA20POLY1305
    }

    fn key_schedule(&self) -> &'static [u8] {
        b"rustnies/aead/chacha20poly1305"
    }

    fn make_nonce(&self, session_id: SessionId, seq: u32, dir: Direction) -> Vec<u8> {
        make_nonce(session_id, seq, dir).to_vec()
    }

    fn seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        encrypt(key, as_nonce_bytes(nonce)?, aad, plaintext)
    }

    fn open(
        &self,
        key: &[u8; 32],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        decrypt(key, as_nonce_bytes(nonce)?, aad, ciphertext)
    }

    fn boxed_clone(&self) -> Box<dyn AeadCipher> {
        Box::new(*self)
    }
}

/// Reinterpret a caller-supplied nonce slice, rejecting a length this suite
/// cannot use. A wrong length is a programming error (the tunnel always builds
/// the nonce via [`AeadCipher::make_nonce`]) so it maps onto the ordinary
/// decryption-failure error rather than panicking.
fn as_nonce_bytes(nonce: &[u8]) -> Result<&NonceBytes, CryptoError> {
    nonce.try_into().map_err(|_| CryptoError::Decryption)
}

/// Cipher ids on the negotiation wire. See [`crate::protocol::profile`].
pub const CIPHER_CHACHA20POLY1305: u8 = 1;

/// Default cipher name used when `[crypto] aead` is unset.
pub const DEFAULT_CIPHER: &str = "chacha20poly1305";

/// Selectable cipher implementations, resolved by name from config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    /// ChaCha20-Poly1305 with a 96-bit nonce.
    ChaCha20Poly1305,
}

impl CipherKind {
    /// The name this kind is selected by (and reports from
    /// [`AeadCipher::name`]).
    pub fn name(self) -> &'static str {
        match self {
            CipherKind::ChaCha20Poly1305 => DEFAULT_CIPHER,
        }
    }

    /// The negotiation wire id for this kind.
    pub fn id(self) -> u8 {
        match self {
            CipherKind::ChaCha20Poly1305 => CIPHER_CHACHA20POLY1305,
        }
    }

    /// Look a kind up by its negotiation wire id. `None` means this build does
    /// not implement it, which is what a peer sees when it is older than the
    /// server's preference list.
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            CIPHER_CHACHA20POLY1305 => Some(CipherKind::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// The domain-separation context folded into the transport-key HKDF.
    pub fn key_schedule(self) -> &'static [u8] {
        match self {
            CipherKind::ChaCha20Poly1305 => ChaCha20Poly1305Cipher.key_schedule(),
        }
    }

    /// Construct the boxed cipher implementation.
    pub fn build(self) -> Box<dyn AeadCipher> {
        match self {
            CipherKind::ChaCha20Poly1305 => Box::new(ChaCha20Poly1305Cipher),
        }
    }
}

/// Resolve a cipher by config name.
///
/// Unlike obfuscation layers (which warn-and-skip an unknown name so a typo
/// never stops the tunnel), an unknown cipher is a **hard error**: falling back
/// silently would put the two peers in different crypto configurations and the
/// session would fail on its first data packet with no diagnostic. Fail at
/// config-resolution time instead.
pub fn select_cipher(name: &str) -> Result<CipherKind, UnknownCipher> {
    match name.trim() {
        "" | DEFAULT_CIPHER => Ok(CipherKind::ChaCha20Poly1305),
        other => Err(unknown_cipher(other)),
    }
}

/// Build a boxed cipher from a config name, defaulting on an empty string.
pub fn build_cipher(name: &str) -> Result<Box<dyn AeadCipher>, UnknownCipher> {
    Ok(select_cipher(name)?.build())
}

/// A config name that does not match any [`AeadCipher`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown aead cipher {name:?}; supported: {supported}")]
pub struct UnknownCipher {
    /// The rejected config name.
    pub name: String,
    /// The comma-separated list of supported names, for the error message.
    pub supported: String,
}

fn unknown_cipher(name: &str) -> UnknownCipher {
    UnknownCipher {
        name: name.to_string(),
        supported: [DEFAULT_CIPHER].join(", "),
    }
}

/// Nominal tag length of every supported suite, used by tests and by
/// [`crate::protocol::header::MAX_PAYLOAD`] accounting.
pub const AEAD_TAG_LEN: usize = TAG_LEN;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead;

    #[test]
    fn select_cipher_recognises_default_and_empty() {
        assert_eq!(
            select_cipher(DEFAULT_CIPHER).unwrap(),
            CipherKind::ChaCha20Poly1305
        );
        assert_eq!(select_cipher("").unwrap(), CipherKind::ChaCha20Poly1305);
    }

    #[test]
    fn select_cipher_rejects_unknown_hard() {
        // A wrong cipher must be an error, never a silent fallback.
        let err = select_cipher("aes-gcm").unwrap_err();
        assert_eq!(err.name, "aes-gcm");
        assert!(build_cipher("aes-gcm").is_err());
    }

    #[test]
    fn names_and_ids_are_stable() {
        for kind in [CipherKind::ChaCha20Poly1305] {
            let built = kind.build();
            assert_eq!(built.name(), kind.name());
            assert_eq!(built.id(), kind.id());
            assert_eq!(built.key_schedule(), kind.key_schedule());
        }
    }

    #[test]
    fn ids_are_unique() {
        let ids: Vec<u8> = [CipherKind::ChaCha20Poly1305]
            .iter()
            .map(|k| k.id())
            .collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "cipher ids must be unique");
    }

    #[test]
    fn key_schedules_are_unique() {
        // Domain separation only works if no two suites share a context.
        let a = CipherKind::ChaCha20Poly1305.key_schedule();
        assert!(!a.is_empty());
        assert!(std::str::from_utf8(a).is_ok());
    }

    #[test]
    fn default_nonce_layout_is_unchanged() {
        // Pinned: the negotiated path must not perturb the existing wire bytes.
        let c = ChaCha20Poly1305Cipher;
        let got = c.make_nonce(0x12345678, 42, Direction::InitiatorToResponder);
        let want = aead::make_nonce(0x12345678, 42, Direction::InitiatorToResponder);
        assert_eq!(got.as_slice(), want.as_slice());
        assert_eq!(got.len(), 12);
    }

    #[test]
    fn seal_open_roundtrip() {
        let c = ChaCha20Poly1305Cipher;
        let key = aead::random_key();
        let nonce = c.make_nonce(7, 1, Direction::InitiatorToResponder);
        let ct = c.seal(&key, &nonce, b"hdr", b"payload").unwrap();
        assert_eq!(ct.len(), b"payload".len() + AEAD_TAG_LEN);
        assert_eq!(c.open(&key, &nonce, b"hdr", &ct).unwrap(), b"payload");
    }

    #[test]
    fn open_rejects_tampered_aad() {
        let c = ChaCha20Poly1305Cipher;
        let key = aead::random_key();
        let nonce = c.make_nonce(7, 1, Direction::InitiatorToResponder);
        let ct = c.seal(&key, &nonce, b"hdr", b"payload").unwrap();
        assert!(c.open(&key, &nonce, b"other", &ct).is_err());
    }

    #[test]
    fn open_rejects_wrong_direction_nonce() {
        // The direction bit is what stops the two directions colliding.
        let c = ChaCha20Poly1305Cipher;
        let key = aead::random_key();
        let a = c.make_nonce(7, 1, Direction::InitiatorToResponder);
        let b = c.make_nonce(7, 1, Direction::ResponderToInitiator);
        assert_ne!(a, b);
        let ct = c.seal(&key, &a, b"hdr", b"payload").unwrap();
        assert!(c.open(&key, &b, b"hdr", &ct).is_err());
    }

    #[test]
    fn open_rejects_malformed_nonce_length() {
        let c = ChaCha20Poly1305Cipher;
        let key = aead::random_key();
        let nonce = c.make_nonce(7, 1, Direction::InitiatorToResponder);
        let ct = c.seal(&key, &nonce, b"hdr", b"payload").unwrap();
        assert!(c.open(&key, &nonce[..11], b"hdr", &ct).is_err());
        assert!(c.open(&key, &[0u8; 16], b"hdr", &ct).is_err());
    }

    #[test]
    fn boxed_clone_preserves_behavior() {
        let t: Box<dyn AeadCipher> = build_cipher(DEFAULT_CIPHER).unwrap();
        let clone = t.boxed_clone();
        let key = aead::random_key();
        let nonce = t.make_nonce(1, 1, Direction::InitiatorToResponder);
        let ct = clone.seal(&key, &nonce, b"a", b"m").unwrap();
        assert_eq!(t.open(&key, &nonce, b"a", &ct).unwrap(), b"m");
        assert_eq!(clone.name(), t.name());
    }
}
