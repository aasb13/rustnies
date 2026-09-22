//! Per-connection session state: sequencing, replay protection and ack
//! tracking.
//!
//! This is pure bookkeeping; it has no I/O so it can be unit-tested and reused
//! from any platform host.

use super::{PacketType, SessionId};

/// Which side of the handshake this session plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// The side that initiated the Noise handshake.
    Initiator,
    /// The side that responded.
    Responder,
}

/// A sliding-window replay filter, like IPsec AH: a `highest` watermark plus
/// a bitmap of the `WINDOW` most recent sequence numbers below `highest`.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// Highest sequence number seen so far (0 = none seen yet).
    highest: u32,
    bits: u64,
}

const WINDOW: u32 = 64;

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            highest: 0,
            bits: 0,
        }
    }

    /// Returns `true` if `seq` is fresh (not seen) and records it.
    /// Sequence numbers are accepted monotonically; old/duplicate/replay
    /// packets below the window are rejected.
    pub fn check_and_record(&mut self, seq: u32) -> bool {
        if seq == 0 {
            // 0 is reserved as "no sequence"; never accept.
            return false;
        }
        if seq > self.highest {
            let shift = seq - self.highest;
            if shift >= WINDOW {
                self.bits = 0;
            } else {
                self.bits <<= shift;
            }
            self.bits |= 1;
            self.highest = seq;
            true
        } else {
            let back = self.highest - seq;
            if back >= WINDOW {
                false
            } else {
                let mask = 1u64 << back;
                if self.bits & mask != 0 {
                    false
                } else {
                    self.bits |= mask;
                    true
                }
            }
        }
    }

    pub fn next_expected(&self) -> u32 {
        self.highest.wrapping_add(1)
    }
}

/// Track which peer seqs we have received so we can advertise selective acks
/// piggybacked on outgoing packets. Every authenticated packet (data, parity
/// and control) is recorded, not only reliable ones.
///
/// The advertisement is a *sliding* window anchored at the highest received
/// seq, not a cumulative-ack watermark: data is best-effort and holes are
/// permanent, so a contiguous watermark would stall forever at the first lost
/// data packet, after which the peer could never learn about later packets.
///
/// Wire semantics of the advertised `(ack_seq, ack_bitmap)` pair: `ack_seq`
/// (the anchor) is the highest received seq and is acked by definition; bit
/// `i` of `ack_bitmap` (i in 0..32) is set iff seq `ack_seq - 1 - i` has been
/// received, covering the 32 seqs immediately *below* the anchor.
#[derive(Debug, Clone, Default)]
pub struct AckTracker {
    /// Highest received seq (0 = nothing received yet).
    anchor: u32,
    /// Bit `i` set iff `anchor - 1 - i` was received.
    bitmap: u32,
}

impl AckTracker {
    pub fn record(&mut self, seq: u32) {
        if seq == 0 {
            // 0 is reserved as "no sequence"; never record it.
            return;
        }
        if self.anchor == 0 {
            self.anchor = seq;
            return;
        }
        let advance = seq.wrapping_sub(self.anchor);
        if advance == 0 {
            return; // duplicate of the anchor
        }
        if advance <= (u32::MAX >> 1) {
            // Seq moved forward (tolerating u32 wrap): slide the window. The
            // old anchor, received by definition, lands at bit `advance - 1`.
            let mut b = if advance >= 32 {
                0u32
            } else {
                self.bitmap << advance
            };
            if advance <= 32 {
                b |= 1u32 << (advance - 1);
            }
            self.bitmap = b;
            self.anchor = seq;
        } else {
            // Seq is below the anchor: set its bit if it is still in range.
            let back = self.anchor.wrapping_sub(seq);
            if back >= 1 && back <= 32 {
                self.bitmap |= 1u32 << (back - 1);
            }
        }
    }

    /// Produce the (ack_seq, bitmap) pair to advertise in an outgoing header:
    /// `ack_seq` is the highest received seq (the anchor, acked by
    /// definition), and bit `i` of `ack_bitmap` covers `ack_seq - 1 - i`.
    pub fn snapshot(&self) -> (u32, u32) {
        (self.anchor, self.bitmap)
    }
}

/// State held per session, independent of the cipher (which lives in
/// [`crate::crypto`]). The session owns sequence number generation and replay
/// filtering for one direction of the tunnel.
#[derive(Debug)]
pub struct Session {
    pub id: SessionId,
    pub role: SessionRole,
    /// Next outgoing sequence number.
    pub next_seq: u32,
    /// Replay filter for incoming packets.
    pub replay: ReplayWindow,
    /// Ack tracker: records the seq of every authenticated incoming packet so
    /// the advertised sliding window covers the whole flow, not only the rare
    /// reliable control packets.
    pub ack: AckTracker,
    /// Peer's last advertised ack anchor (its highest received seq).
    pub peer_ack: u32,
    /// Peer's last advertised bitmap (bit i = seq `peer_ack - 1 - i` seen).
    pub peer_bitmap: u32,
}

impl Session {
    pub fn new(id: SessionId, role: SessionRole) -> Self {
        Self {
            id,
            role,
            next_seq: 1,
            replay: ReplayWindow::new(),
            ack: AckTracker::default(),
            peer_ack: 0,
            peer_bitmap: 0,
        }
    }

    /// Allocate the next outgoing sequence number.
    pub fn alloc_seq(&mut self) -> u32 {
        let s = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        s
    }

    /// Record an incoming packet's ack advertisement (peer telling us what it
    /// has received from us). The pair uses the sliding-window format produced
    /// by [`AckTracker::snapshot`]. Used by the reliable-sender to discard
    /// acked outstanding packets and by the congestion controller to release
    /// in-flight slots.
    pub fn observe_acks(&mut self, ack_seq: u32, ack_bitmap: u32) {
        self.peer_ack = ack_seq;
        self.peer_bitmap = ack_bitmap;
    }

    /// Decide whether the peer has acknowledged our outgoing seq `s`, based on
    /// the most recently observed ack advertisement (sliding-window format):
    /// the anchor is acked by definition, seqs within 32 below it are acked
    /// iff their bitmap bit is set, and anything else (above the anchor, or
    /// fallen out of the window) is reported as not acked.
    pub fn peer_acked(&self, s: u32) -> bool {
        if s == 0 || self.peer_ack == 0 {
            return false;
        }
        if s == self.peer_ack {
            return true;
        }
        let back = self.peer_ack.wrapping_sub(s);
        if back >= 1 && back <= 32 {
            (self.peer_bitmap >> (back - 1)) & 1 == 1
        } else {
            false
        }
    }

    /// Record an incoming reliable packet and update ack state.
    pub fn receive_reliable(&mut self, seq: u32) -> bool {
        let fresh = self.replay.check_and_record(seq);
        if fresh {
            self.ack.record(seq);
        }
        fresh
    }

    /// Produce the (ack_seq, bitmap) snapshot for outgoing headers.
    pub fn ack_snapshot(&self) -> (u32, u32) {
        self.ack.snapshot()
    }

    /// Whether a given incoming packet type should be processed through the
    /// reliable channel.
    pub fn is_reliable_in(ptype: PacketType) -> bool {
        ptype.is_reliable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_basic() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_record(1));
        assert!(w.check_and_record(2));
        assert!(!w.check_and_record(1), "duplicate rejected");
        assert!(w.check_and_record(5));
        // older, inside window
        assert!(w.check_and_record(4));
        assert!(!w.check_and_record(4), "duplicate rejected after reorder");
        // far future jumps window
        assert!(w.check_and_record(200));
        assert!(!w.check_and_record(5), "below window rejected");
    }

    #[test]
    fn ack_tracker_snapshot() {
        let mut a = AckTracker::default();
        a.record(1);
        a.record(2);
        a.record(3);
        // Anchor sits at the highest received seq; seqs 2 and 1 land below it.
        let (w, b) = a.snapshot();
        assert_eq!(w, 3);
        assert_eq!(b, 0b11, "seqs 2 and 1 covered by bits 0 and 1");
        a.record(6);
        a.record(8);
        let (w, b) = a.snapshot();
        assert_eq!(w, 8);
        // Below the anchor: 6 (back 2 -> bit 1), 3 (back 5 -> bit 4),
        // 2 (back 6 -> bit 5), 1 (back 7 -> bit 6). 4, 5 and 7 never arrived.
        assert!(b & (1 << 1) != 0, "seq 6 bit set");
        assert!(b & (1 << 4) != 0, "seq 3 bit set");
        assert!(b & (1 << 5) != 0, "seq 2 bit set");
        assert!(b & (1 << 6) != 0, "seq 1 bit set");
        assert_eq!(b & 0b11, 0b10, "seq 7 unseen, seq 6 seen");
    }

    #[test]
    fn session_peer_acked() {
        let mut s = Session::new(0x1234, SessionRole::Initiator);
        // Anchor at 12 (acked by definition); bits 0 and 2 set -> seqs 11, 9.
        s.observe_acks(12, 0b0101);
        assert!(s.peer_acked(12));
        assert!(s.peer_acked(11));
        assert!(!s.peer_acked(10));
        assert!(s.peer_acked(9));
        assert!(!s.peer_acked(8));
        assert!(!s.peer_acked(13), "above the anchor is never acked");
        assert!(!s.peer_acked(45), "above the anchor is never acked");
    }

    // ---- ReplayWindow property tests ----

    #[test]
    fn replay_window_rejects_seq_zero() {
        let mut w = ReplayWindow::new();
        assert!(!w.check_and_record(0), "seq 0 is reserved");
        // A fresh window must still accept the first real seq afterwards.
        assert!(w.check_and_record(1));
    }

    #[test]
    fn replay_window_rejects_duplicate_at_high_watermark() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_record(10));
        assert!(!w.check_and_record(10), "highest seen again is a dup");
        assert!(!w.check_and_record(10), "still a dup on third attempt");
    }

    #[test]
    fn replay_window_accepts_full_in_order_sequence() {
        let mut w = ReplayWindow::new();
        for s in 1..=1000u32 {
            assert!(w.check_and_record(s), "in-order seq {s} must be fresh");
        }
    }

    #[test]
    fn replay_window_rejects_old_below_window_after_jump() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_record(1));
        // Jump far ahead so seq 1 falls outside the 64-wide window.
        assert!(w.check_and_record(1 + WINDOW + 10));
        assert!(!w.check_and_record(1), "seq 1 now below window");
        // A seq just inside the window on the low side is still acceptable
        // if not seen before.
        let inside = w.highest - WINDOW + 1;
        assert!(inside > 0, "test setup must keep inside > 0");
        assert!(
            w.check_and_record(inside),
            "fresh seq inside window accepted"
        );
    }

    #[test]
    fn replay_window_handles_exact_window_edge() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_record(100));
        // exactly WINDOW behind is rejected (>= WINDOW comparison).
        assert!(
            !w.check_and_record(100 - WINDOW),
            "exact window edge rejected"
        );
        // WINDOW-1 behind is the last acceptable slot.
        assert!(
            w.check_and_record(100 - (WINDOW - 1)),
            "just inside accepted"
        );
        assert!(
            !w.check_and_record(100 - (WINDOW - 1)),
            "duplicate rejected"
        );
    }

    #[test]
    fn replay_window_far_future_resets_all_old_bits() {
        let mut w = ReplayWindow::new();
        // Record a cluster, then jump far beyond the window.
        for s in 1..=5u32 {
            assert!(w.check_and_record(s));
        }
        assert!(w.check_and_record(1000));
        // Old cluster is now below the window and must all be rejected, even
        // the ones we never recorded before (no residual bits after a reset).
        assert!(!w.check_and_record(3));
        assert!(!w.check_and_record(4));
    }

    #[test]
    fn replay_window_next_expected_is_one_past_highest() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.next_expected(), 1, "empty window expects seq 1");
        w.check_and_record(42);
        assert_eq!(w.next_expected(), 43);
    }

    // ---- AckTracker property tests ----

    #[test]
    fn ack_tracker_initial_anchor_is_zero() {
        let a = AckTracker::default();
        let (w, b) = a.snapshot();
        assert_eq!(w, 0, "fresh tracker advertises anchor 0");
        assert_eq!(b, 0);
    }

    #[test]
    fn ack_tracker_record_zero_is_ignored() {
        let mut a = AckTracker::default();
        a.record(0); // reserved; must not move the anchor
        let (w, b) = a.snapshot();
        assert_eq!((w, b), (0, 0), "seq 0 must never be advertised as acked");
    }

    #[test]
    fn ack_tracker_anchor_follows_highest_seq() {
        let mut a = AckTracker::default();
        for s in 1..=10u32 {
            a.record(s);
        }
        let (w, b) = a.snapshot();
        assert_eq!(w, 10, "anchor is the highest received seq");
        // Seqs 1..=9 sit at bits 8..0 below the anchor: all set.
        assert_eq!(b, 0x1FF, "nine seqs below the anchor covered");
    }

    #[test]
    fn ack_tracker_gap_is_a_permanent_hole() {
        let mut a = AckTracker::default();
        a.record(1);
        a.record(2);
        a.record(5); // 3,4 lost for good: anchor must not stall on them
        let (w, b) = a.snapshot();
        assert_eq!(w, 5, "anchor jumps over permanent holes");
        // seq 2 (back 3 -> bit 2), seq 1 (back 4 -> bit 3); 3,4 unseen.
        assert_eq!(b, 0b1100);
        // A retransmitted/filler pair still gets recorded below the anchor.
        a.record(3);
        a.record(4);
        let (w, b) = a.snapshot();
        assert_eq!(w, 5, "anchor unchanged by late arrivals");
        assert_eq!(b, 0b1111, "late arrivals set their bits");
    }

    #[test]
    fn ack_tracker_seq_beyond_window_is_forgotten() {
        let mut a = AckTracker::default();
        a.record(1);
        // A jump of 34 slides seq 1 out of the 32-wide bitmap entirely.
        a.record(1 + 34);
        let (w, b) = a.snapshot();
        assert_eq!(w, 35);
        assert_eq!(b, 0, "seq 34 below the anchor is out of range");
    }

    #[test]
    fn ack_tracker_duplicate_record_is_idempotent() {
        let mut a = AckTracker::default();
        a.record(5);
        a.record(5);
        a.record(5);
        let (w, b) = a.snapshot();
        assert_eq!((w, b), (5, 0), "duplicate of the anchor is a no-op");
    }

    // ---- Session integration tests ----

    #[test]
    fn session_alloc_seq_starts_at_one_and_increments() {
        let mut s = Session::new(0x1, SessionRole::Initiator);
        assert_eq!(s.alloc_seq(), 1);
        assert_eq!(s.alloc_seq(), 2);
        assert_eq!(s.alloc_seq(), 3);
    }

    #[test]
    fn session_alloc_seq_wraps_at_u32_max() {
        let mut s = Session::new(0x1, SessionRole::Initiator);
        s.next_seq = u32::MAX;
        assert_eq!(s.alloc_seq(), u32::MAX);
        // Wraps to 0 then to 1? Implementation uses wrapping_add, so 0.
        assert_eq!(s.alloc_seq(), 0, "wrapping_add wraps to 0");
    }

    #[test]
    fn session_receive_reliable_records_and_acks() {
        let mut s = Session::new(0x1, SessionRole::Responder);
        assert!(s.receive_reliable(1));
        assert!(s.receive_reliable(2));
        assert!(!s.receive_reliable(1), "duplicate reliable rejected");
        let (w, b) = s.ack_snapshot();
        assert_eq!(w, 2, "anchor at the highest received seq");
        assert_eq!(b, 0b1, "seq 1 acked via bit 0 below the anchor");
    }

    #[test]
    fn session_receive_reliable_duplicate_does_not_re_record_ack() {
        let mut s = Session::new(0x1, SessionRole::Responder);
        assert!(s.receive_reliable(5));
        let (w1, _) = s.ack_snapshot();
        assert!(!s.receive_reliable(5), "duplicate rejected");
        let (w2, _) = s.ack_snapshot();
        assert_eq!(w1, w2, "ack watermark unchanged on duplicate");
    }

    #[test]
    fn session_peer_acked_below_anchor_needs_a_bitmap_bit() {
        let mut s = Session::new(0x1, SessionRole::Initiator);
        s.observe_acks(100, 0);
        // Anchor is acked; with an empty bitmap nothing below it is. There
        // is no cumulative-ack floor: holes below the anchor stay unacked.
        assert!(s.peer_acked(100));
        assert!(!s.peer_acked(99));
        assert!(!s.peer_acked(1));
        assert!(!s.peer_acked(200), "above the anchor is never acked");
    }

    #[test]
    fn session_peer_acked_all_32_bitmap_bits() {
        let mut s = Session::new(0x1, SessionRole::Initiator);
        // All 32 bits set: seqs ack_seq-1 ..= ack_seq-32 are all acked.
        s.observe_acks(40, 0xFFFF_FFFF);
        for back in 1..=32u32 {
            assert!(s.peer_acked(40 - back), "seq {} should be acked", 40 - back);
        }
        assert!(
            !s.peer_acked(40 - 33),
            "33 below the anchor is out of range"
        );
    }

    #[test]
    fn session_peer_acked_specific_bit_pattern() {
        let mut s = Session::new(0x1, SessionRole::Initiator);
        // bit i set => ack_seq - 1 - i acked. Set bits 0 and 3 -> seqs 49, 46.
        s.observe_acks(50, 0b1001);
        assert!(s.peer_acked(49), "bit 0 -> seq 49");
        assert!(!s.peer_acked(48), "bit 1 clear -> seq 48");
        assert!(!s.peer_acked(47), "bit 2 clear -> seq 47");
        assert!(s.peer_acked(46), "bit 3 -> seq 46");
    }

    #[test]
    fn session_observe_acks_overwrites_previous() {
        let mut s = Session::new(0x1, SessionRole::Initiator);
        s.observe_acks(10, 0b1);
        assert!(s.peer_acked(9), "bit 0 -> seq 9 under anchor 10");
        s.observe_acks(20, 0);
        // New advertisement overwrites the old one entirely: seq 9 is no
        // longer covered (empty bitmap under anchor 20), and 21 is above it.
        assert!(!s.peer_acked(9));
        assert!(s.peer_acked(20));
        assert!(!s.peer_acked(21));
    }

    #[test]
    fn session_is_reliable_in_matches_is_reliable() {
        for p in [
            PacketType::Handshake1,
            PacketType::Handshake2,
            PacketType::Data,
            PacketType::Ack,
            PacketType::Fec,
            PacketType::Ping,
            PacketType::Pong,
            PacketType::Close,
        ] {
            assert_eq!(
                Session::is_reliable_in(p),
                p.is_reliable(),
                "is_reliable_in must agree with is_reliable for {p:?}"
            );
        }
    }

    // ---- ReplayWindow edge cases ----

    #[test]
    fn replay_window_dense_reverse_order_all_accepted() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_record(100));
        // Walk backwards through the window; every seq is fresh and must be
        // accepted even though they arrive out of order.
        for s in (60..100).rev() {
            assert!(w.check_and_record(s), "reverse-order seq {s} fresh");
        }
        // Replaying any already-recorded seq must now be rejected.
        assert!(!w.check_and_record(80), "already-recorded seq rejected");
        assert!(!w.check_and_record(100), "highest replayed rejected");
    }

    #[test]
    fn replay_window_jump_by_window_clears_old_state() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_record(10));
        // A jump of exactly WINDOW hits the `shift >= WINDOW` path and clears
        // all old bits.
        assert!(w.check_and_record(10 + WINDOW));
        // seq 10 is now exactly WINDOW behind the new highest: rejected by the
        // `back >= WINDOW` comparison.
        assert!(!w.check_and_record(10), "old seq below window after jump");
        // A fresh seq just inside the new window is still accepted.
        assert!(
            w.check_and_record(10 + WINDOW - 1),
            "fresh seq just inside window"
        );
    }

    #[test]
    fn replay_window_repeated_far_jumps_each_reset_state() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_record(1));
        let step = WINDOW + 50;
        let mut hi = 1;
        for _ in 0..3 {
            hi += step;
            assert!(w.check_and_record(hi), "far jump to {hi} accepted");
        }
        // The very first cluster's seq is far below the window and rejected.
        assert!(
            !w.check_and_record(1),
            "first-cluster seq below window after jumps"
        );
    }

    #[test]
    fn replay_window_does_not_wrap_around_u32_max() {
        // Characterisation of a known limitation: the IPsec-style window uses
        // unsigned subtraction, so it does not handle a wrap from u32::MAX back
        // to the low sequence numbers. After seeing u32::MAX, the wrapped seq 1
        // is treated as far "below" the window and rejected. This pins the
        // boundary behaviour so a future wraparound-safe change is detected.
        let mut w = ReplayWindow::new();
        assert!(w.check_and_record(u32::MAX), "u32::MAX is fresh");
        assert!(
            !w.check_and_record(1),
            "wrap-around seq 1 rejected (known limitation)"
        );
        // A genuinely-higher (pre-wrap) seq would still be accepted, but there
        // is none above u32::MAX; only the wrapped range exists, which is the
        // gap documented here.
    }

    #[test]
    fn replay_window_just_inside_window_after_large_jump_accepted() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_record(1000));
        // The lowest seq still inside the window (WINDOW-1 behind) is fresh
        // and must be accepted exactly once.
        let inside = 1000 - (WINDOW - 1);
        assert!(w.check_and_record(inside), "fresh seq just inside window");
        assert!(!w.check_and_record(inside), "second copy is a duplicate");
    }

    // ---- AckTracker edge cases ----

    #[test]
    fn ack_tracker_all_32_bitmap_bits_set() {
        // The bitmap covers exactly the 32 seqs below the anchor; filling all
        // of them sets every bit without overflow.
        let mut a = AckTracker::default();
        for s in 1..=33u32 {
            a.record(s);
        }
        let (w, b) = a.snapshot();
        assert_eq!(w, 33);
        assert_eq!(b, 0xFFFF_FFFF, "all 32 bitmap bits set");
        // One more advance slides the window: seq 1 falls out of range and
        // the old anchor takes bit 0; the window stays full.
        a.record(34);
        let (w, b) = a.snapshot();
        assert_eq!(w, 34);
        assert_eq!(b, 0xFFFF_FFFF, "seqs 2..=33 still fill the window");
    }

    #[test]
    fn ack_tracker_order_independent() {
        // Recording the same set in a scrambled order must produce the same
        // anchor and bitmap as an in-order recording.
        let mut a = AckTracker::default();
        for &s in &[5, 1, 3, 2, 4, 6] {
            a.record(s);
        }
        let (w, b) = a.snapshot();
        assert_eq!(w, 6, "anchor is the highest recorded seq");
        assert_eq!(b, 0b1_1111, "seqs 1..=5 all covered below the anchor");
    }

    #[test]
    fn ack_tracker_large_jump_still_tracks_recent_window() {
        let mut a = AckTracker::default();
        a.record(1);
        a.record(1000); // advance of 999: seq 1 falls far out of the window
        let (w, b) = a.snapshot();
        assert_eq!((w, b), (1000, 0));
        // Fill the entire gap; the 32 seqs below the anchor become acked.
        for s in 2..=999u32 {
            a.record(s);
        }
        let (w, b) = a.snapshot();
        assert_eq!(w, 1000);
        assert_eq!(b, 0xFFFF_FFFF, "all 32 seqs below the anchor received");
    }

    #[test]
    fn ack_tracker_snapshot_is_stable_until_new_record() {
        let mut a = AckTracker::default();
        a.record(1);
        a.record(5);
        let (w1, b1) = a.snapshot();
        let (w2, b2) = a.snapshot();
        assert_eq!((w1, b1), (w2, b2), "snapshot is pure until a new record");
        a.record(2); // sets a bit below the anchor
        let (w3, b3) = a.snapshot();
        assert_ne!((w3, b3), (w1, b1), "snapshot changes after a record");
    }

    // ---- Session edge cases ----

    #[test]
    fn session_peer_acked_default_state_acks_nothing() {
        // A fresh session has observed no acks; nothing must be considered
        // acknowledged (the sender must not drop unacked packets prematurely).
        let s = Session::new(0x1, SessionRole::Initiator);
        assert!(!s.peer_acked(1));
        assert!(!s.peer_acked(100));
        assert!(!s.peer_acked(u32::MAX));
    }

    #[test]
    fn session_receive_reliable_rejects_seq_zero() {
        let mut s = Session::new(0x1, SessionRole::Responder);
        // seq 0 is reserved and must be rejected by the replay filter without
        // touching the ack tracker.
        assert!(!s.receive_reliable(0), "seq 0 reserved");
        let (w, b) = s.ack_snapshot();
        assert_eq!(w, 0, "no ack recorded for rejected seq 0");
        assert_eq!(b, 0);
        // A real seq immediately afterwards still works.
        assert!(s.receive_reliable(1));
        let (w, _) = s.ack_snapshot();
        assert_eq!(w, 1, "anchor at the received seq");
    }

    #[test]
    fn session_alloc_seq_strictly_monotonic_until_wrap() {
        let mut s = Session::new(0x1, SessionRole::Initiator);
        s.next_seq = u32::MAX - 3;
        assert_eq!(s.alloc_seq(), u32::MAX - 3);
        assert_eq!(s.alloc_seq(), u32::MAX - 2);
        assert_eq!(s.alloc_seq(), u32::MAX - 1);
        assert_eq!(s.alloc_seq(), u32::MAX);
        // wrapping_add wraps to 0, which is the reserved seq (see test below).
        assert_eq!(s.alloc_seq(), 0);
        assert_eq!(s.alloc_seq(), 1);
    }

    #[test]
    fn session_alloc_seq_wrap_to_zero_is_rejected_by_peer() {
        // Integration characterisation: when the sender's seq wraps past
        // u32::MAX it allocates the reserved seq 0, which a fresh peer rejects.
        // This pins the known wraparound consequence for the reliable channel.
        let mut sender = Session::new(0x1, SessionRole::Initiator);
        sender.next_seq = u32::MAX;
        assert_eq!(sender.alloc_seq(), u32::MAX);
        let wrapped = sender.alloc_seq();
        assert_eq!(wrapped, 0, "seq wraps to reserved 0");

        let mut receiver = Session::new(0x1, SessionRole::Responder);
        assert!(
            !receiver.receive_reliable(wrapped),
            "peer rejects wrapped seq 0"
        );
        // The peer still accepts a real seq afterwards.
        assert!(receiver.receive_reliable(1));
    }

    #[test]
    fn session_receive_reliable_long_in_order_run_advances_anchor() {
        let mut s = Session::new(0x1, SessionRole::Responder);
        for seq in 1..=500u32 {
            assert!(s.receive_reliable(seq), "in-order seq {seq} fresh");
        }
        let (w, b) = s.ack_snapshot();
        assert_eq!(w, 500, "anchor is the highest received seq");
        assert_eq!(b, 0xFFFF_FFFF, "32 seqs below the anchor all received");
        // A late duplicate of an early seq is below the replay window now.
        assert!(!s.receive_reliable(1), "old seq below replay window");
    }

    #[test]
    fn session_observe_acks_zero_anchor_acks_nothing() {
        let mut s = Session::new(0x1, SessionRole::Initiator);
        s.observe_acks(0, 0xFFFF_FFFF);
        // anchor 0 = "peer has received nothing": the bitmap is meaningless
        // and nothing, not even seq 1, may be considered acknowledged.
        for seq in 0..=33u32 {
            assert!(!s.peer_acked(seq), "seq {seq} must not be acked");
        }
    }
}
