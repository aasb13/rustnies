//! Header-XOR keystream obfuscation layer.
//!
//! The rustnies protocol header has several bytes that are **constant across
//! every packet of every session** at a fixed offset: `version` (0x01) at
//! offset 0, and a small set of `packet_type` discriminant bytes at offset 1.
//! An observer who can see the on-wire bytes (even through an encrypted
//! transport) can fingerprint the protocol by these constant offsets. The
//! AEAD ciphertext body is already indistinguishable from random, but the
//! header is in the clear (it is used as AEAD AAD).
//!
//! This layer XORs a *per-session-derived keystream* over the first
//! `HEADER_LEN` (24) bytes of every frame, so there is no constant byte
//! pattern at a fixed offset across sessions. The keystream is derived once
//! per session from the Noise handshake hash via HKDF-SHA256, so both peers
//! derive the same keystream independently and a passive observer who did not
//! participate in the handshake cannot recover it.
//!
//! The keystream is a single 24-byte block: we do not need the cryptographic
//! properties of a stream cipher here because the underlying AEAD already
//! provides confidentiality and integrity for the whole frame. This layer's
//! only goal is to **whiten the fixed header bytes** so they are not a
//! fingerprint. XORing a 24-byte block with a 24-byte pad is sufficient for
//! that: the header bytes become indistinguishable from random to an observer
//! without the keystream.
//!
//! ## Why this is safe
//!
//! - The keystream is derived from the handshake hash, which is secret to the
//!   two peers and never sent on the wire.
//! - XOR is its own inverse, so `reverse` is exactly `apply` (symmetric).
//! - The AEAD tag still authenticates the original header (as AAD), so a
//!   tampered whitened header that survives XOR produces an invalid AAD on
//!   decrypt and is rejected by the crypto layer. This layer does not weaken
//!   integrity.
//! - We do not use the keystream as a nonce or key for the AEAD; it is purely
//!   a whitening mask over the header bytes.
//!
//! ## Handshake frames
//!
//! Handshake message 1 and message 2 are *not* `header || ciphertext` frames
//! — they are raw Noise handshake bytes. This layer must therefore not
//! transform a frame shorter than `HEADER_LEN` (it would corrupt a handshake
//! message). `apply`/`reverse` leave frames shorter than `HEADER_LEN`
//! untouched, so handshake bytes pass through unchanged. Once the handshake
//! completes, `init` is called with the session seed and the keystream is
//! active for all steady-state frames (which are always >= `HEADER_LEN`).
//!
//! ## Configuration
//!
//! From the `[obfuscation]` TOML section:
//!
//! ```toml
//! [obfuscation]
//! layers = ["header_xor"]
//! ```
//!
//! The layer takes no per-layer parameters; the keystream is derived from the
//! session seed at `init` time. A layer constructed without `init` (e.g. in a
//! unit test) uses a zero keystream, which makes `apply`/`reverse` identities
//! — safe and reversible.

use std::sync::Mutex;

use hkdf::Hkdf;
use sha2::Sha256;

use crate::protocol::header::HEADER_LEN;

use super::{ObfuscationError, ObfuscationLayer};

/// HKDF info string for deriving the header-whitening keystream.
pub(crate) const HKDF_INFO: &[u8] = b"rustnies-obfuscation-header-xor";

/// A header-XOR keystream obfuscation layer.
///
/// XORs a per-session-derived 24-byte keystream over the first `HEADER_LEN`
/// bytes of every frame of length >= `HEADER_LEN`. Frames shorter than
/// `HEADER_LEN` (handshake messages) are passed through unchanged.
#[derive(Debug)]
pub struct HeaderXor {
    keystream: Mutex<Option<[u8; HEADER_LEN]>>,
}

impl Default for HeaderXor {
    fn default() -> Self {
        Self {
            keystream: Mutex::new(None),
        }
    }
}

impl HeaderXor {
    /// Construct an uninitialised layer. The keystream is all-zero until
    /// `init` is called, making `apply`/`reverse` identities.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the layer from the resolved `[obfuscation]` config section. The
    /// layer takes no parameters; the keystream is derived at `init`.
    pub fn from_config(_cfg: &crate::config::ObfuscationConfig) -> Self {
        Self::new()
    }

    /// Derive the 24-byte keystream from a session seed via HKDF-SHA256.
    fn derive(seed: &[u8; 32]) -> [u8; HEADER_LEN] {
        let hk = Hkdf::<Sha256>::new(None, seed);
        let mut out = [0u8; HEADER_LEN];
        // HEADER_LEN (24) is well within HKDF-SHA256's max output (255 * 32).
        hk.expand(HKDF_INFO, &mut out)
            .expect("HKDF expand of 24 bytes cannot fail");
        out
    }

    /// XOR `keystream` over the first `HEADER_LEN` bytes of `buf`, returning
    /// a new Vec. Frames shorter than `HEADER_LEN` are returned unchanged.
    fn xor_header(&self, buf: &[u8]) -> Vec<u8> {
        let guard = self.keystream.lock().expect("header_xor lock");
        let ks = match guard.as_ref() {
            Some(ks) => ks,
            None => return buf.to_vec(), // uninitialised -> identity
        };
        if buf.len() < HEADER_LEN {
            return buf.to_vec(); // handshake frames are not header-framed
        }
        let mut out = buf.to_vec();
        for (i, b) in out[..HEADER_LEN].iter_mut().enumerate() {
            *b ^= ks[i];
        }
        out
    }
}

impl Clone for HeaderXor {
    fn clone(&self) -> Self {
        let guard = self.keystream.lock().expect("header_xor lock");
        Self {
            keystream: Mutex::new(*guard),
        }
    }
}

impl ObfuscationLayer for HeaderXor {
    fn name(&self) -> &'static str {
        "header_xor"
    }

    fn apply(&self, frame: &[u8]) -> Vec<u8> {
        self.xor_header(frame)
    }

    fn reverse(&self, buf: &[u8]) -> Result<Vec<u8>, ObfuscationError> {
        // XOR is symmetric: reverse is identical to apply.
        Ok(self.xor_header(buf))
    }

    fn init(&self, session_seed: &[u8; 32]) {
        let mut guard = self.keystream.lock().expect("header_xor lock");
        *guard = Some(Self::derive(session_seed));
    }

    fn boxed_clone(&self) -> Box<dyn ObfuscationLayer> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ObfuscationConfig;

    #[test]
    fn uninitialised_layer_is_identity() {
        let l = HeaderXor::new();
        let frame = vec![0x01u8; HEADER_LEN + 10];
        assert_eq!(l.apply(&frame), frame);
        assert_eq!(l.reverse(&frame).unwrap(), frame);
    }

    #[test]
    fn roundtrips_full_frame_after_init() {
        let l = HeaderXor::new();
        l.init(&[0xAB; 32]);
        let frame: Vec<u8> = (0..HEADER_LEN + 40).map(|i| i as u8).collect();
        let applied = l.apply(&frame);
        // Header bytes must change (whitened).
        assert_ne!(&applied[..HEADER_LEN], &frame[..HEADER_LEN]);
        // Body bytes must be unchanged.
        assert_eq!(&applied[HEADER_LEN..], &frame[HEADER_LEN..]);
        // Reverse recovers the original.
        let rev = l.reverse(&applied).unwrap();
        assert_eq!(rev, frame);
    }

    #[test]
    fn short_frames_pass_through_unchanged() {
        let l = HeaderXor::new();
        l.init(&[0x99; 32]);
        // A handshake message (shorter than HEADER_LEN) must not be XORed.
        let frame = vec![0x42u8; 10];
        let applied = l.apply(&frame);
        assert_eq!(applied, frame, "short frames must not be whitened");
        let rev = l.reverse(&frame).unwrap();
        assert_eq!(rev, frame);
    }

    #[test]
    fn exactly_header_len_roundtrips() {
        let l = HeaderXor::new();
        l.init(&[0x01; 32]);
        let frame: Vec<u8> = (0..HEADER_LEN).map(|i| i as u8).collect();
        let applied = l.apply(&frame);
        assert_ne!(applied, frame);
        assert_eq!(l.reverse(&applied).unwrap(), frame);
    }

    #[test]
    fn different_seeds_produce_different_keystreams() {
        let a = HeaderXor::new();
        a.init(&[0x11; 32]);
        let b = HeaderXor::new();
        b.init(&[0x22; 32]);
        let frame = vec![0u8; HEADER_LEN];
        let oa = a.apply(&frame);
        let ob = b.apply(&frame);
        // Different seeds -> different whitened output (with high probability
        // for any non-degenerate frame; here the all-zero frame makes the
        // output exactly the keystream, which must differ).
        assert_ne!(oa, ob, "different seeds must produce different keystreams");
    }

    #[test]
    fn same_seed_produces_same_keystream() {
        let a = HeaderXor::new();
        a.init(&[0xDE; 32]);
        let b = HeaderXor::new();
        b.init(&[0xDE; 32]);
        let frame = vec![0u8; HEADER_LEN];
        assert_eq!(a.apply(&frame), b.apply(&frame));
    }

    #[test]
    fn header_bytes_are_whitened_no_constant_offset_across_sessions() {
        // The constant version byte 0x01 at offset 0 must become different
        // across sessions with different seeds.
        let mut frame = vec![0u8; HEADER_LEN + 5];
        frame[0] = 0x01; // PROTOCOL_VERSION
        let a = HeaderXor::new();
        a.init(&[0x01; 32]);
        let b = HeaderXor::new();
        b.init(&[0x02; 32]);
        let oa = a.apply(&frame);
        let ob = b.apply(&frame);
        assert_ne!(oa[0], ob[0], "version byte must differ across sessions");
        assert_ne!(oa[0], 0x01, "version byte must be whitened");
    }

    #[test]
    fn from_config_is_identity_until_init() {
        let cfg = ObfuscationConfig::default();
        let l = HeaderXor::from_config(&cfg);
        let frame = vec![0x55; HEADER_LEN];
        assert_eq!(l.apply(&frame), frame);
        l.init(&[0xFF; 32]);
        assert_ne!(l.apply(&frame), frame);
        assert_eq!(l.reverse(&l.apply(&frame)).unwrap(), frame);
    }

    #[test]
    fn clone_preserves_initialised_keystream() {
        let l = HeaderXor::new();
        l.init(&[0x77; 32]);
        let c = l.clone();
        let frame = vec![0u8; HEADER_LEN];
        assert_eq!(l.apply(&frame), c.apply(&frame));
    }
}
