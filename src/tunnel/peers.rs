//! Server-side peer authorization: the list of client static public keys a
//! server will accept handshakes from.
//!
//! The authorized peer set is configured inline in the server's TOML config as
//! a `[[peers]]` array of tables, each carrying a `public_key` (hex-encoded
//! 32-byte X25519 key) and an optional `name` label used purely for log
//! readability. When no `[[peers]]` section is present the server runs in open
//! mode (every peer accepted) for phase-1 compatibility; an explicit but empty
//! list rejects everyone.
//!
//! The set is held behind an `Arc<Mutex<PeerAuth>>` so a SIGHUP handler in the
//! daemon can re-read the config file's `[[peers]]` array and swap it in live
//! via [`PeerAuth::set_peers`] / [`PeerAuth::set_open`] without restarting.

use std::collections::{HashMap, HashSet};

use crate::config::PeerEntry;
use crate::crypto::keys::PublicKey;

/// The authorized-peer set. Pure data + authorization logic; the daemon layer
/// owns the on-disk reload (it re-parses the TOML and calls the setters).
pub struct PeerAuth {
    /// Authorized static public keys (raw 32-byte form) mapped to an optional
    /// human-readable label. Empty does *not* by itself mean open mode — see
    /// [`PeerAuth::open`].
    keys: HashMap<[u8; 32], Option<String>>,
    /// Runtime-only denylist. A key in this set is rejected for handshakes
    /// regardless of whether it appears in `keys` or whether the server is in
    /// open mode. This is populated by the IPC `Revoke` command (runtime-only;
    /// resets on daemon restart). It exists to tear down *live* sessions for a
    /// compromised key — the `[[peers]]` allowlist controls new handshakes.
    denylist: HashSet<[u8; 32]>,
    /// Open (accept-all) mode. True when no `[[peers]]` section was configured.
    /// When false, only keys present in `keys` are authorized (an empty map
    /// rejects everyone).
    open: bool,
}

impl PeerAuth {
    /// Open mode: accept every peer. Used when no `[[peers]]` section is
    /// present in the config.
    pub fn open_mode() -> Self {
        Self {
            keys: HashMap::new(),
            denylist: HashSet::new(),
            open: true,
        }
    }

    /// Build an authorized set from an inline `[[peers]]` list. Malformed or
    /// wrong-length entries are skipped (with a warning). The resulting set is
    /// *not* open mode even if every entry was invalid or the list is empty —
    /// an explicit `[[peers]]` section means "restrict", so an empty result
    /// rejects everyone (unlike open mode).
    pub fn from_entries(peers: &[PeerEntry]) -> Self {
        let mut keys = HashMap::new();
        for (idx, entry) in peers.iter().enumerate() {
            let line = entry.public_key.trim();
            if line.is_empty() {
                continue;
            }
            let bytes = match hex::decode(line) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        idx,
                        error = ?e,
                        "peers: skipping malformed hex public_key entry"
                    );
                    continue;
                }
            };
            if bytes.len() != 32 {
                tracing::warn!(
                    idx,
                    len = bytes.len(),
                    "peers: skipping public_key that is not 32 bytes"
                );
                continue;
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes[..32]);
            keys.insert(arr, entry.name.clone().filter(|s| !s.trim().is_empty()));
        }
        tracing::info!(
            peers = keys.len(),
            "loaded authorized peer keys from config"
        );
        Self {
            keys,
            denylist: HashSet::new(),
            open: false,
        }
    }

    /// Whether `key` is authorized to connect. In open mode (no `[[peers]]`
    /// section) every key is accepted, unless the key has been revoked at
    /// runtime (denylist).
    pub fn authorized(&self, key: &PublicKey) -> bool {
        !self.is_revoked(key) && (self.open || self.keys.contains_key(&key.to_bytes()))
    }

    /// Check a key and return `(allowed, matched_name)`. `matched_name` is the
    /// configured label when the key was found in the peer list (regardless of
    /// whether it has a name); it is `None` when the key was not found or the
    /// server is in open mode (no per-key labels in open mode).
    ///
    /// A revoked (denylisted) key is always rejected, even in open mode or if it
    /// is also in the allowlist.
    ///
    /// Used by the handshake path so rejection/acceptance logs can reference
    /// the peer's label, falling back to `"unknown"` when not matched.
    pub fn check(&self, key: &PublicKey) -> (bool, Option<String>) {
        if self.is_revoked(key) {
            return (false, Some("revoked".to_string()));
        }
        if self.open {
            return (true, None);
        }
        match self.keys.get(&key.to_bytes()) {
            Some(name) => (true, name.clone()),
            None => (false, None),
        }
    }

    /// Add `key` to the runtime denylist. Future handshakes from this key are
    /// rejected (T2) regardless of allowlist or open-mode status. This does
    /// **not** tear down already-live sessions — callers (the IPC `Revoke`
    /// handler) must separately evict live sessions for this key.
    ///
    /// This is runtime-only: the denylist is not persisted and resets when the
    /// daemon restarts. To permanently exclude a key, remove it from the
    /// `[[peers]]` config and SIGHUP.
    pub fn revoke(&mut self, key: &[u8; 32]) {
        self.denylist.insert(*key);
    }

    /// Whether `key` has been administratively revoked (denylisted) at runtime.
    pub fn is_revoked(&self, key: &PublicKey) -> bool {
        self.denylist.contains(&key.to_bytes())
    }

    /// Number of keys in the runtime denylist.
    pub fn deny_count(&self) -> usize {
        self.denylist.len()
    }

    /// Remove a key from the denylist (re-authorize a previously revoked peer).
    /// This does **not** re-establish any session — the peer must re-handshake.
    pub fn unrevoke(&mut self, key: &[u8; 32]) {
        self.denylist.remove(key);
    }

    /// Swap in a new authorized set parsed from a re-read config file's
    /// `[[peers]]` array. Leaves restrict mode (even if `peers` is empty,
    /// which rejects everyone). Used by the SIGHUP reload path.
    pub fn set_peers(&mut self, peers: &[PeerEntry]) {
        let fresh = Self::from_entries(peers);
        self.keys = fresh.keys;
        self.open = false;
    }

    /// Switch to open (accept-all) mode, dropping the key set. Used by the
    /// SIGHUP reload path when the `[[peers]]` section was removed from the
    /// config file.
    pub fn set_open(&mut self) {
        self.keys.clear();
        self.open = true;
    }

    /// Number of authorized peers (0 in open mode does *not* mean "reject
    /// all"; see [`authorized`]).
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the server is in open (accept-all) mode.
    pub fn is_open_mode(&self) -> bool {
        self.open
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyPair;

    fn entry(pubkey: &[u8; 32], name: Option<&str>) -> PeerEntry {
        PeerEntry {
            public_key: hex::encode(pubkey),
            name: name.map(str::to_string),
        }
    }

    #[test]
    fn open_mode_accepts_everyone() {
        let auth = PeerAuth::open_mode();
        assert!(auth.is_open_mode());
        let kp = KeyPair::generate();
        assert!(auth.authorized(&kp.public));
        let (allowed, name) = auth.check(&kp.public);
        assert!(allowed);
        assert!(name.is_none(), "open mode has no per-key labels");
    }

    #[test]
    fn entries_authorize_only_listed_keys() {
        let allowed = KeyPair::generate();
        let blocked = KeyPair::generate();
        let auth = PeerAuth::from_entries(&[entry(&allowed.public_bytes(), Some("alice"))]);
        assert!(!auth.is_open_mode());
        assert!(auth.authorized(&allowed.public), "listed key accepted");
        assert!(!auth.authorized(&blocked.public), "unlisted key rejected");
        let (ok, name) = auth.check(&allowed.public);
        assert!(ok);
        assert_eq!(name.as_deref(), Some("alice"));
        let (ok, name) = auth.check(&blocked.public);
        assert!(!ok);
        assert!(name.is_none(), "unmatched key has no name");
    }

    #[test]
    fn empty_entries_list_rejects_all_and_is_not_open() {
        let auth = PeerAuth::from_entries(&[]);
        assert!(!auth.is_open_mode());
        let kp = KeyPair::generate();
        assert!(!auth.authorized(&kp.public), "empty list rejects all");
    }

    #[test]
    fn malformed_entries_are_skipped() {
        let good = KeyPair::generate();
        let peers = vec![
            PeerEntry {
                public_key: "not-hex".into(),
                name: None,
            },
            PeerEntry {
                public_key: "deadbeef".into(),
                name: None,
            },
            entry(&good.public_bytes(), None),
        ];
        let auth = PeerAuth::from_entries(&peers);
        assert_eq!(auth.len(), 1, "only the one valid key loaded");
        assert!(auth.authorized(&good.public));
    }

    #[test]
    fn blank_name_is_treated_as_absent() {
        let kp = KeyPair::generate();
        let auth = PeerAuth::from_entries(&[PeerEntry {
            public_key: hex::encode(kp.public_bytes()),
            name: Some("   ".into()),
        }]);
        let (_, name) = auth.check(&kp.public);
        assert!(name.is_none(), "whitespace-only name is dropped");
    }

    #[test]
    fn set_peers_replaces_list_live() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let mut auth = PeerAuth::from_entries(&[entry(&a.public_bytes(), None)]);
        assert!(auth.authorized(&a.public));
        assert!(!auth.authorized(&b.public));
        // Reload: drop a, add b.
        auth.set_peers(&[entry(&b.public_bytes(), Some("bob"))]);
        assert!(!auth.authorized(&a.public), "old key gone after reload");
        assert!(auth.authorized(&b.public), "new key present after reload");
        assert!(!auth.is_open_mode());
        let (_, name) = auth.check(&b.public);
        assert_eq!(name.as_deref(), Some("bob"));
    }

    #[test]
    fn set_open_switches_to_accept_all() {
        let a = KeyPair::generate();
        let mut auth = PeerAuth::from_entries(&[entry(&a.public_bytes(), None)]);
        assert!(!auth.is_open_mode());
        auth.set_open();
        assert!(auth.is_open_mode());
        let b = KeyPair::generate();
        assert!(auth.authorized(&b.public), "open mode accepts everyone");
    }

    #[test]
    fn set_peers_with_empty_rejects_all() {
        let a = KeyPair::generate();
        let mut auth = PeerAuth::from_entries(&[entry(&a.public_bytes(), None)]);
        auth.set_peers(&[]);
        assert!(!auth.is_open_mode());
        assert!(!auth.authorized(&a.public), "empty reload rejects all");
    }
}
