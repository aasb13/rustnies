//! Cryptography.
//!
//! Uses standard, audited primitives only:
//! - X25519 ephemeral-static Diffie-Hellman ([`x25519_dalek`])
//! - HKDF-SHA256 for key derivation ([`hkdf`], [`sha2`])
//! - ChaCha20-Poly1305 AEAD ([`chacha20poly1305`])
//!
//! The handshake follows the Noise **IK** pattern (Noise_IK_25519_ChaChaPoly_
//! BLAKE2s) adapted to our explicit-nonce UDP transport. We implement the
//! pattern faithfully against the Noise Protocol Framework spec; we do **not**
//! invent a new protocol. See [`noise`] for details.
//!
//! Per-packet encryption uses ChaCha20Poly1305 with a 96-bit nonce composed of
//! `session_id (32 bits) || seq (32 bits) || direction (8 bits) || zero (24)`,
//! giving each packet a unique, deterministic nonce without maintaining state.

pub mod aead;
pub mod keys;
pub mod noise;
pub mod suite;

pub use aead::{NonceBytes, decrypt, encrypt};
pub use keys::{KeyPair, PublicKey, StaticSecret};
pub use noise::{HandshakeResult, HandshakeRole, NoiseHandshake};
pub use suite::{AeadCipher, CipherKind, DEFAULT_CIPHER, build_cipher, select_cipher};
