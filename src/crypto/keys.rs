//! Static long-term key handling.
//!
//! A rustnies peer has a long-term X25519 static keypair, identified by a
//! fingerprint (the public key). The static key authenticates the peer across
//! sessions; the Noise IK handshake proves possession of it.

use std::path::Path;

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

/// A long-term static secret key. Zeroised on drop.
pub type StaticSecret = X25519StaticSecret;

/// A 32-byte X25519 public key.
pub type PublicKey = X25519PublicKey;

/// A generated or loaded static keypair.
pub struct KeyPair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &hex::encode(self.public.to_bytes()))
            .finish()
    }
}

impl KeyPair {
    /// Generate a fresh static keypair using the OS RNG.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let secret = StaticSecret::random_from_rng(&mut rng);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Encode the public key as 32 bytes.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Load a keypair from `path`, generating and persisting one if the file is
    /// absent. The file is stored as 32 raw secret bytes with 0600 permissions
    /// (on Unix).
    pub fn load_or_create(path: &Path) -> std::io::Result<Self> {
        if path.exists() {
            let bytes = std::fs::read(path)?;
            if bytes.len() != 32 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "static key file must be exactly 32 bytes",
                ));
            }
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&bytes);
            // Reconstruct via try_from on a cloned array (x25519-dalek takes
            // ownership; we keep a copy for the public derivation).
            let secret = StaticSecret::from(secret);
            let public = X25519PublicKey::from(&secret);
            Ok(Self { secret, public })
        } else {
            let kp = Self::generate();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, kp.secret.to_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o600);
                std::fs::set_permissions(path, perms)?;
            }
            Ok(kp)
        }
    }
}
