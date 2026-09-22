//! IPC request/response messages.

use serde::{Deserialize, Serialize};

use crate::stats::Stats;

/// Information about a single live session, returned by `list_sessions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// The 32-bit session ID carried in cleartext on every packet.
    pub session_id: u32,
    /// Hex-encoded static public key of the peer.
    pub peer_key: String,
    /// Human-readable label if configured, else `null`.
    pub peer_name: Option<String>,
    /// Current source address of the peer (changes on roaming).
    pub peer_addr: String,
    /// Number of confirmed roaming events for this session.
    pub roam_count: u32,
    /// Unix timestamp of the last roam, if any.
    pub last_roam: Option<f64>,
    /// Seconds since the session was spawned.
    pub age_secs: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum Request {
    Status,
    Stop,
    Ping,
    /// Revoke a static public key at runtime. Adds the key to the server's
    /// denylist (rejects future handshakes) and immediately evicts any live
    /// session(s) for that peer. Runtime-only — resets on daemon restart.
    /// The `public_key` field is the hex-encoded 32-byte X25519 key.
    Revoke {
        public_key: String,
    },
    /// List all live sessions on the server. On the client, returns an empty
    /// array (clients have one session).
    ListSessions,
    /// Disconnect a specific session (by `session_id`) or all sessions for a
    /// peer (by `peer_key` hex). Sends a graceful Close to the victim(s).
    Disconnect {
        session_id: Option<u32>,
        peer_key: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum Response {
    Status(Stats),
    /// `list_sessions` result. Empty on the client.
    Sessions(Vec<SessionInfo>),
    Ack(String),
    Error(String),
}
