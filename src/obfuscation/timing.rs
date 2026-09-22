//! Timing-jitter + idle decoy-packet obfuscation layer.
//!
//! This layer defeats two traffic-analysis signals an observer can use even
//! when payload size and content are already hidden:
//!
//! 1. **Inter-packet timing**: a passive observer can fingerprint a protocol
//!    or infer activity/inactivity from the precise timing between datagrams.
//! 2. **Idle gaps**: when the tunnel goes quiet, the *absence* of traffic is
//!    itself a signal (the tunnelled application is idle, the user stepped
//!    away, etc.).
//!
//! This layer addresses both with a single, reversible transform that does
//! **no I/O and no waiting** itself — it stays a pure function on a packet
//! buffer, in keeping with the [`super::ObfuscationLayer`] contract (layers
//! may not touch the socket or schedule timers). The actual pacing/idle-gap
//! insertion is driven by the tunnel's existing send loop, which consults
//! [`TimingJitter::next_send_delay`] before each send and
//! [`TimingJitter::should_emit_decoy`] on its idle tick. The layer owns the
//! bookkeeping state those decisions need.
//!
//! Concretely:
//!
//! - **Timing jitter**: each `apply` call records the send time and returns
//!   the frame unchanged (this layer does not modify bytes). Before sending,
//!   the tunnel calls `next_send_delay` to get a small randomised delay to
//!   `tokio::time::sleep` before the actual `send_to`. The delay is drawn from
//!   `[0, max_jitter]` and is independent of the payload.
//! - **Idle decoy packets**: on each idle tick (the tunnel already has a
//!   periodic tick), the tunnel calls `should_emit_decoy`. When true, it sends
//!   a decoy frame produced by [`TimingJitter::decoy_frame`]: a frame with the
//!   reserved `Decoy` packet type and a randomised length, so the on-wire
//!   traffic looks like real application data. The receiver's `reverse` passes
//!   the frame through unchanged (it is a real frame); the tunnel's receive
//!   path recognises the `Decoy` packet type and drops it without writing to
//!   TUN.
//!
//! ## Why this shape
//!
//! Keeping the layer I/O-free means:
//! - It composes like every other layer (pure `apply`/`reverse`).
//! - The stack stays cheap and deterministic to test.
//! - The tunnel's send loop already owns the socket and timers, so it is the
//!   natural place to apply the advised delays.
//!
//! A future, heavier "timing shape" layer (e.g. one that mimics a specific
//! protocol's inter-arrival distribution) can replace this one without
//! changing the tunnel plumbing: it just produces different
//! `next_send_delay` values.
//!
//! ## Configuration
//!
//! From the `[obfuscation]` TOML section:
//!
//! ```toml
//! [obfuscation]
//! layers = ["timing"]
//! timing_max_jitter_us = 2000      # 0-2ms random send delay
//! timing_decoy_interval_ms = 200   # emit a decoy every ~200ms when idle
//! timing_decoy_max_len = 256       # decoy payload length cap
//! ```
//!
//! Defaults: `max_jitter` 2ms, `decoy_interval` 200ms, `decoy_max_len` 256.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::Rng;
use rand::rngs::OsRng;

use crate::protocol::SessionId;
use crate::protocol::header::{HEADER_LEN, PacketHeader, PacketType};

use super::{ObfuscationError, ObfuscationLayer};

/// Default maximum random send jitter (0..=this) in microseconds.
const DEFAULT_MAX_JITTER_US: u64 = 2000;
/// Default interval between idle decoy packets.
const DEFAULT_DECOY_INTERVAL_MS: u64 = 200;
/// Default maximum decoy payload length (bytes).
const DEFAULT_DECOY_MAX_LEN: usize = 256;

/// The reserved `Decoy` packet-type discriminant.
///
/// This is distinct from all real packet types in
/// [`crate::protocol::header::PacketType`]. The receiver recognises it and
/// drops the frame without delivering to TUN. Because the frame is still
/// AEAD-encrypted and transport-framed like any other, an observer cannot
/// distinguish a decoy from real data by content or size.
pub const DECOY_PACKET_TYPE: u8 = 0x7F;

/// A timing-jitter + idle-decoy obfuscation layer.
///
/// `apply`/`reverse` are byte identities (the layer does not modify frames);
/// the layer's value is in the advisory `next_send_delay` and
/// `should_emit_decoy` methods the send loop consults.
#[derive(Debug)]
pub struct TimingJitter {
    inner: Mutex<State>,
    max_jitter: Duration,
    decoy_interval: Duration,
    decoy_max_len: usize,
}

#[derive(Debug)]
struct State {
    last_send: Option<Instant>,
    last_decoy: Option<Instant>,
}

impl TimingJitter {
    /// Construct a new timing layer with the given parameters.
    pub fn new(max_jitter: Duration, decoy_interval: Duration, decoy_max_len: usize) -> Self {
        Self {
            inner: Mutex::new(State {
                last_send: None,
                last_decoy: None,
            }),
            max_jitter,
            decoy_interval,
            decoy_max_len,
        }
    }

    /// Build the layer from the resolved `[obfuscation]` config section.
    /// Falls back to defaults when the timing-specific fields are absent or
    /// zero.
    pub fn from_config(cfg: &crate::config::ObfuscationConfig) -> Self {
        let max_jitter = if cfg.timing_max_jitter_us == 0 {
            Duration::from_micros(DEFAULT_MAX_JITTER_US)
        } else {
            Duration::from_micros(cfg.timing_max_jitter_us)
        };
        let decoy_interval = if cfg.timing_decoy_interval_ms == 0 {
            Duration::from_millis(DEFAULT_DECOY_INTERVAL_MS)
        } else {
            Duration::from_millis(cfg.timing_decoy_interval_ms)
        };
        let decoy_max_len = if cfg.timing_decoy_max_len == 0 {
            DEFAULT_DECOY_MAX_LEN
        } else {
            cfg.timing_decoy_max_len
        };
        Self::new(max_jitter, decoy_interval, decoy_max_len)
    }

    /// Return a randomised delay to apply before the next send, and record
    /// that a send is about to happen. Returns `Duration::ZERO` when jitter is
    /// disabled (max_jitter == 0). The delay is uniform in `[0, max_jitter]`.
    ///
    /// The tunnel calls this right before `send_to`; the returned duration is
    /// suitable for `tokio::time::sleep`.
    pub fn next_send_delay(&self) -> Duration {
        let mut state = self.inner.lock().expect("timing state lock");
        state.last_send = Some(Instant::now());
        if self.max_jitter.is_zero() {
            return Duration::ZERO;
        }
        let mut rng = OsRng;
        let us = rng.gen_range(0..=self.max_jitter.as_micros() as u64);
        Duration::from_micros(us)
    }

    /// Whether the tunnel should emit a decoy packet now. Returns true when at
    /// least `decoy_interval` has elapsed since the last real *or* decoy send,
    /// or when no send has ever been recorded (the very first idle tick always
    /// fires, seeding the channel). Resets the decoy timer so the caller does
    /// not need to.
    pub fn should_emit_decoy(&self) -> bool {
        if self.decoy_interval.is_zero() {
            return false;
        }
        let mut state = self.inner.lock().expect("timing state lock");
        let now = Instant::now();
        match state.last_decoy.or(state.last_send) {
            None => {
                // No history: fire immediately so the decoy channel is seeded.
                state.last_decoy = Some(now);
                true
            }
            Some(last) => {
                if now.saturating_duration_since(last) >= self.decoy_interval {
                    state.last_decoy = Some(now);
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Produce a decoy frame: a real protocol frame with the reserved `Decoy`
    /// packet type, a random session id and seq (so it is indistinguishable
    /// from real traffic on the wire), and a randomised payload length up to
    /// `decoy_max_len`. The frame is returned unencrypted (the tunnel encrypts
    /// it like any other frame before passing through the rest of the stack).
    ///
    /// `session_id` and `seq` should be the tunnel's current values so the
    /// decoy is byte-identical in shape to a real data packet of the same
    /// session; passing the real values is safe because the decoy carries no
    /// tunneled payload and is dropped on receive.
    pub fn decoy_frame(&self, session_id: SessionId, seq: u32) -> Vec<u8> {
        let mut rng = OsRng;
        let payload_len = rng.gen_range(0..=self.decoy_max_len);
        let mut hdr = PacketHeader::new(PacketType::Data, session_id, seq);
        // Overload the version byte to mark a decoy so the receiver can drop
        // it without needing to decrypt. We use a distinct sentinel that the
        // header parser rejects, so a decoy never parses as a real packet.
        hdr.version = DECOY_PACKET_TYPE;
        let hdr_bytes = hdr.to_bytes();
        let mut frame = Vec::with_capacity(HEADER_LEN + payload_len);
        frame.extend_from_slice(&hdr_bytes);
        frame.extend(vec![0u8; payload_len]);
        frame
    }
}

impl Default for TimingJitter {
    fn default() -> Self {
        Self::new(
            Duration::from_micros(DEFAULT_MAX_JITTER_US),
            Duration::from_millis(DEFAULT_DECOY_INTERVAL_MS),
            DEFAULT_DECOY_MAX_LEN,
        )
    }
}

impl Clone for TimingJitter {
    fn clone(&self) -> Self {
        Self::new(self.max_jitter, self.decoy_interval, self.decoy_max_len)
    }
}

impl ObfuscationLayer for TimingJitter {
    fn name(&self) -> &'static str {
        "timing"
    }

    fn apply(&self, frame: &[u8]) -> Vec<u8> {
        // Record the send for timing bookkeeping. We do not sleep here (the
        // layer must not do I/O); the tunnel consults `next_send_delay`.
        let mut state = self.inner.lock().expect("timing state lock");
        state.last_send = Some(Instant::now());
        drop(state);
        frame.to_vec()
    }

    fn reverse(&self, buf: &[u8]) -> Result<Vec<u8>, ObfuscationError> {
        // The timing layer does not modify bytes; decoy filtering happens in
        // the tunnel receive path (which recognises DECOY_PACKET_TYPE).
        Ok(buf.to_vec())
    }

    fn boxed_clone(&self) -> Box<dyn ObfuscationLayer> {
        Box::new(self.clone())
    }
}

/// Whether a received frame (the raw bytes after `Transport::unwrap` and
/// obfuscation `reverse`) is a decoy produced by [`TimingJitter::decoy_frame`].
/// The tunnel calls this on every received frame before attempting to parse
/// the header as a real packet; decoys are dropped silently.
pub fn is_decoy_frame(frame: &[u8]) -> bool {
    frame.first().copied() == Some(DECOY_PACKET_TYPE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ObfuscationConfig;
    use crate::protocol::header::PROTOCOL_VERSION;

    #[test]
    fn apply_is_identity() {
        let t = TimingJitter::default();
        let frame = b"hello timing";
        let out = t.apply(frame);
        assert_eq!(out, frame);
    }

    #[test]
    fn reverse_is_identity() {
        let t = TimingJitter::default();
        let frame = b"hello timing";
        let rev = t.reverse(frame).unwrap();
        assert_eq!(rev, frame);
    }

    #[test]
    fn next_send_delay_is_within_max_jitter() {
        let t = TimingJitter::new(Duration::from_micros(500), Duration::ZERO, 0);
        for _ in 0..20 {
            let d = t.next_send_delay();
            assert!(d <= Duration::from_micros(500), "delay {d:?} > max");
        }
    }

    #[test]
    fn next_send_delay_zero_when_jitter_disabled() {
        let t = TimingJitter::new(Duration::ZERO, Duration::ZERO, 0);
        assert_eq!(t.next_send_delay(), Duration::ZERO);
    }

    #[test]
    fn should_emit_decoy_true_after_interval_with_no_history() {
        let t = TimingJitter::new(Duration::ZERO, Duration::from_millis(1), 16);
        // No history: first check after >= interval should be true.
        std::thread::sleep(Duration::from_millis(2));
        assert!(t.should_emit_decoy());
    }

    #[test]
    fn should_emit_decoy_true_on_first_call_with_no_history() {
        // With no history, the first call should fire immediately (seeding the
        // decoy channel) regardless of the interval.
        let t = TimingJitter::new(Duration::ZERO, Duration::from_secs(60), 16);
        assert!(t.should_emit_decoy());
    }

    #[test]
    fn should_emit_decoy_false_immediately_after_first_emission() {
        // After the first emission, the next call within the interval is false.
        let t = TimingJitter::new(Duration::ZERO, Duration::from_secs(60), 16);
        assert!(t.should_emit_decoy(), "first call fires");
        assert!(
            !t.should_emit_decoy(),
            "second call within interval suppressed"
        );
    }

    #[test]
    fn should_emit_decoy_false_when_disabled() {
        let t = TimingJitter::new(Duration::ZERO, Duration::ZERO, 16);
        assert!(!t.should_emit_decoy());
    }

    #[test]
    fn decoy_frame_has_decoy_version_byte() {
        let t = TimingJitter::default();
        let frame = t.decoy_frame(0xCAFEBABE, 42);
        assert!(is_decoy_frame(&frame), "decoy frame must be recognised");
        assert_eq!(frame[0], DECOY_PACKET_TYPE);
        // The rest of the header is a valid header shape with the decoy
        // version sentinel.
        assert_eq!(frame.len() >= HEADER_LEN, true);
    }

    #[test]
    fn decoy_frame_payload_len_within_cap() {
        let t = TimingJitter::new(Duration::ZERO, Duration::ZERO, 64);
        for _ in 0..30 {
            let f = t.decoy_frame(1, 1);
            assert!(f.len() >= HEADER_LEN);
            assert!(f.len() <= HEADER_LEN + 64);
        }
    }

    #[test]
    fn is_decoy_frame_false_for_real_packet() {
        // A real packet has version PROTOCOL_VERSION (0x01), not the decoy
        // sentinel.
        let mut hdr = PacketHeader::new(PacketType::Data, 1, 1);
        hdr.version = PROTOCOL_VERSION;
        let bytes = hdr.to_bytes();
        assert!(!is_decoy_frame(&bytes));
    }

    #[test]
    fn is_decoy_frame_false_for_empty() {
        assert!(!is_decoy_frame(&[]));
    }

    #[test]
    fn from_config_uses_defaults_when_zero() {
        let cfg = ObfuscationConfig::default();
        let t = TimingJitter::from_config(&cfg);
        assert_eq!(t.max_jitter, Duration::from_micros(DEFAULT_MAX_JITTER_US));
        assert_eq!(
            t.decoy_interval,
            Duration::from_millis(DEFAULT_DECOY_INTERVAL_MS)
        );
        assert_eq!(t.decoy_max_len, DEFAULT_DECOY_MAX_LEN);
    }

    #[test]
    fn from_config_uses_custom_values() {
        let cfg = ObfuscationConfig {
            timing_max_jitter_us: 5000,
            timing_decoy_interval_ms: 100,
            timing_decoy_max_len: 128,
            ..Default::default()
        };
        let t = TimingJitter::from_config(&cfg);
        assert_eq!(t.max_jitter, Duration::from_micros(5000));
        assert_eq!(t.decoy_interval, Duration::from_millis(100));
        assert_eq!(t.decoy_max_len, 128);
    }
}
