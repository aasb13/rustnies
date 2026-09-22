//! Per-packet AEAD: ChaCha20-Poly1305 with explicit 96-bit nonces.
//!
//! ChaCha20-Poly1305 (RFC 8439) is an audited AEAD construction. We use a
//! deterministic per-packet nonce derived from the session id and the packet
//! sequence number so each (key, nonce) pair is used exactly once without
//! maintaining send-side state beyond the sequence counter.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::RngCore;

use crate::protocol::SessionId;

/// 12-byte AEAD nonce.
pub type NonceBytes = [u8; 12];

/// Tag length appended by ChaCha20-Poly1305.
pub const TAG_LEN: usize = 16;

/// Direction bit folded into the nonce so initiator->responder and
/// responder->initiator traffic can reuse seq numbers without colliding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    InitiatorToResponder = 0,
    ResponderToInitiator = 1,
}

/// Build a deterministic 96-bit nonce for a packet.
///
/// Layout (little-endian): `session_id[0..4] || seq[0..4] || dir || 0 0 0`.
pub fn make_nonce(session_id: SessionId, seq: u32, dir: Direction) -> NonceBytes {
    let mut n = [0u8; 12];
    n[0..4].copy_from_slice(&session_id.to_le_bytes());
    n[4..8].copy_from_slice(&seq.to_le_bytes());
    n[8] = dir as u8;
    n
}

/// Encrypt `plaintext` with the given 32-byte key. `aad` is authenticated but
/// not encrypted (typically the packet header). Returns
/// `ciphertext || tag` (28 bytes overhead for empty input).
pub fn encrypt(
    key: &[u8; 32],
    nonce: &NonceBytes,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encryption)
}

/// Decrypt the AEAD output produced by [`encrypt`].
pub fn decrypt(
    key: &[u8; 32],
    nonce: &NonceBytes,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decryption)
}

/// Generate a random 32-byte key, e.g. for one-off testing.
pub fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    k
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    Encryption,
    #[error("decryption failed (bad tag or wrong key)")]
    Decryption,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn encrypt_then_decrypt_roundtrips() {
        let k = key();
        let nonce = make_nonce(0x12345678, 42, Direction::InitiatorToResponder);
        let aad = b"associated data";
        let pt = b"plaintext payload";
        let ct = encrypt(&k, &nonce, aad, pt).unwrap();
        assert_eq!(ct.len(), pt.len() + TAG_LEN);
        let pt2 = decrypt(&k, &nonce, aad, &ct).unwrap();
        assert_eq!(pt2, pt);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let k = key();
        let wrong = {
            let mut w = key();
            w[0] ^= 0xFF;
            w
        };
        let nonce = make_nonce(1, 1, Direction::InitiatorToResponder);
        let ct = encrypt(&k, &nonce, b"aad", b"secret").unwrap();
        assert!(decrypt(&wrong, &nonce, b"aad", &ct).is_err());
    }

    #[test]
    fn decrypt_with_wrong_nonce_fails() {
        let k = key();
        let nonce = make_nonce(1, 1, Direction::InitiatorToResponder);
        let other = make_nonce(1, 2, Direction::InitiatorToResponder);
        let ct = encrypt(&k, &nonce, b"aad", b"secret").unwrap();
        assert!(decrypt(&k, &other, b"aad", &ct).is_err());
    }

    #[test]
    fn decrypt_with_tampered_aad_fails() {
        let k = key();
        let nonce = make_nonce(1, 1, Direction::InitiatorToResponder);
        let ct = encrypt(&k, &nonce, b"original aad", b"secret").unwrap();
        assert!(decrypt(&k, &nonce, b"tampered aad", &ct).is_err());
    }

    #[test]
    fn decrypt_with_tampered_ciphertext_fails() {
        let k = key();
        let nonce = make_nonce(1, 1, Direction::InitiatorToResponder);
        let mut ct = encrypt(&k, &nonce, b"aad", b"secret").unwrap();
        ct[0] ^= 0x01; // flip a bit in the ciphertext
        assert!(decrypt(&k, &nonce, b"aad", &ct).is_err());
    }

    #[test]
    fn decrypt_with_tampered_tag_fails() {
        let k = key();
        let nonce = make_nonce(1, 1, Direction::InitiatorToResponder);
        let mut ct = encrypt(&k, &nonce, b"aad", b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01; // flip a bit in the Poly1305 tag
        assert!(decrypt(&k, &nonce, b"aad", &ct).is_err());
    }

    #[test]
    fn decrypt_truncated_ciphertext_fails() {
        let k = key();
        let nonce = make_nonce(1, 1, Direction::InitiatorToResponder);
        let ct = encrypt(&k, &nonce, b"aad", b"secret").unwrap();
        let truncated = &ct[..ct.len() - 4];
        assert!(decrypt(&k, &nonce, b"aad", truncated).is_err());
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let k = key();
        let nonce = make_nonce(1, 1, Direction::InitiatorToResponder);
        let ct = encrypt(&k, &nonce, b"aad", b"").unwrap();
        assert_eq!(ct.len(), TAG_LEN, "empty plaintext -> tag only");
        let pt = decrypt(&k, &nonce, b"aad", &ct).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn empty_aad_roundtrips() {
        let k = key();
        let nonce = make_nonce(1, 1, Direction::InitiatorToResponder);
        let ct = encrypt(&k, &nonce, b"", b"data").unwrap();
        let pt = decrypt(&k, &nonce, b"", &ct).unwrap();
        assert_eq!(pt, b"data");
    }

    #[test]
    fn same_key_seq_different_direction_do_not_collide() {
        // The direction bit exists so the two directions can reuse seq numbers
        // without a (key, nonce) collision. Encrypting the same plaintext with
        // the same seq but different directions must produce different
        // ciphertexts and each must decrypt only with its own direction.
        let k = key();
        let n_i2r = make_nonce(1, 5, Direction::InitiatorToResponder);
        let n_r2i = make_nonce(1, 5, Direction::ResponderToInitiator);
        assert_ne!(n_i2r, n_r2i, "nonce must differ by direction");
        let ct_i2r = encrypt(&k, &n_i2r, b"aad", b"payload").unwrap();
        let ct_r2i = encrypt(&k, &n_r2i, b"aad", b"payload").unwrap();
        assert_ne!(ct_i2r, ct_r2i, "ciphertext must differ by direction");
        // Cross-direction decrypt must fail.
        assert!(decrypt(&k, &n_r2i, b"aad", &ct_i2r).is_err());
        assert!(decrypt(&k, &n_i2r, b"aad", &ct_r2i).is_err());
    }

    #[test]
    fn nonce_layout_is_session_seq_dir_padding() {
        let n = make_nonce(0xDEADBEEF, 0x12345678, Direction::ResponderToInitiator);
        assert_eq!(&n[0..4], &0xDEADBEEF_u32.to_le_bytes());
        assert_eq!(&n[4..8], &0x12345678_u32.to_le_bytes());
        assert_eq!(n[8], Direction::ResponderToInitiator as u8);
        assert_eq!(&n[9..12], &[0, 0, 0], "trailing bytes must be zero");
    }

    #[test]
    fn different_sessions_same_seq_produce_different_ciphertext() {
        let k = key();
        let n1 = make_nonce(0x11111111, 1, Direction::InitiatorToResponder);
        let n2 = make_nonce(0x22222222, 1, Direction::InitiatorToResponder);
        let ct1 = encrypt(&k, &n1, b"aad", b"payload").unwrap();
        let ct2 = encrypt(&k, &n2, b"aad", b"payload").unwrap();
        assert_ne!(ct1, ct2, "different sessions must not collide");
    }

    #[test]
    fn random_key_is_32_bytes_and_nonzero() {
        let k = random_key();
        assert_eq!(k.len(), 32);
        assert!(
            k.iter().any(|&b| b != 0),
            "random key should not be all-zero (overwhelmingly)"
        );
    }

    #[test]
    fn large_payload_roundtrips() {
        let k = key();
        let nonce = make_nonce(1, 1, Direction::InitiatorToResponder);
        let pt = vec![0xABu8; 1300];
        let ct = encrypt(&k, &nonce, b"aad", &pt).unwrap();
        let pt2 = decrypt(&k, &nonce, b"aad", &ct).unwrap();
        assert_eq!(pt2, pt);
    }
}
