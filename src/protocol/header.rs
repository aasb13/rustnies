//! Compact packet header.
//!
//! Layout (24 bytes, little-endian, packed):
//!
//! | offset | field        | size | notes                                  |
//! |--------|--------------|------|----------------------------------------|
//! | 0      | version      | 1    | protocol version (currently 0x01)      |
//! | 1      | packet_type  | 1    | see [`PacketType`]                     |
//! | 2      | session_id   | 4    | connection/session id                  |
//! | 6      | seq         | 4    | monotonic sequence number              |
//! | 10     | ack_seq     | 4    | cumulative ack (highest received)      |
//! | 14     | ack_bitmap  | 4    | bitmap of the 32 seqs after ack_seq    |
//! | 18     | fec_group   | 2    | FEC group id                           |
//! | 20     | fec_index   | 1    | index within the group (0..k+m)       |
//! | 21     | fec_k       | 1    | number of source symbols in the group  |
//! | 22     | fec_m       | 1    | number of parity symbols in the group  |
//! | 23     | flags       | 1    | reserved                               |
//!
//! `seq` is the authoritative nonce component; `ack_seq`/`ack_bitmap` carry
//! reverse-direction ack information piggybacked onto every packet.

use serde::{Deserialize, Serialize};

/// Protocol version.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Total header length in bytes.
pub const HEADER_LEN: usize = 24;

/// Length of the ChaCha20-Poly1305 authentication tag appended to every
/// encrypted payload.
pub const AEAD_TAG_LEN: usize = 16;

/// Outer UDP header carried on the wire for every datagram.
pub const UDP_HEADER_LEN: usize = 8;
/// Outer IPv4 header carried on the wire for every datagram (IPv6 paths add
/// a further 20 bytes; see the margin discussion on [`MAX_PAYLOAD`]).
pub const IPV4_HEADER_LEN: usize = 20;
/// Outer L3/L4 envelope: UDP + IPv4. An IPv6 outer path costs 48 bytes
/// instead of 28; the [`MAX_PAYLOAD`] margin below still covers that.
pub const OUTER_OVERHEAD: usize = UDP_HEADER_LEN + IPV4_HEADER_LEN;
/// Assumed path MTU for the encrypted UDP datagrams. Standard Ethernet is
/// 1500; PPPoE (-8), carrier encapsulation, or a second VPN hop shrink it,
/// which is why [`MAX_PAYLOAD`] keeps a ~70-byte margin under this budget.
pub const PATH_MTU: usize = 1500;

/// Maximum TUN payload (inner IP packet) carried in a single Data datagram.
///
/// Wire budget for a full-size payload with the default 1400-byte TUN MTU:
///
/// ```text
///   1360 (payload) + 24 (header) + 16 (AEAD tag) + 8 (UDP) + 20 (IPv4) = 1428
/// ```
///
/// That stays under the 1500-byte [`PATH_MTU`] with ~70 bytes of margin for
/// PPPoE, carrier encapsulation, an IPv6 outer (extra 20), or a small
/// transport tag. It does NOT cover a 1500-byte padding bucket, which is why
/// the padding layer's default top bucket must stay at or below the frame
/// size for a full payload (see `obfuscation::padding`).
///
/// The TUN device itself is configured with a matching MTU (see the daemon's
/// effective-MTU clamp) so the OS never hands us an inner packet larger than
/// this; [`crate::tunnel`] additionally drops anything larger as a safety
/// net for FD-backed / misconfigured devices.
pub const MAX_PAYLOAD: usize = 1400 - HEADER_LEN - AEAD_TAG_LEN;

/// 4-byte opaque session identifier.
pub type SessionId = u32;

bitflags::bitflags! {
    /// Reserved header flag bits. All bits are currently unassigned; a receiver
    /// silently drops unknown bits (`from_bits_truncate`), so a future flag is
    /// backwards compatible.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct HeaderFlags: u8 {
        const NONE = 0;
    }
}

/// Packet type discriminator.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketType {
    /// Noise IK handshake message 1 (client -> server).
    Handshake1 = 1,
    /// Noise IK handshake message 2 (server -> client).
    Handshake2 = 2,
    /// Application data tunneled from the TUN interface.
    Data = 3,
    /// Acknowledgement of reliable control delivery (piggybacked normally).
    Ack = 4,
    /// Forward error correction parity symbol.
    Fec = 5,
    /// RTT probe (carries a timestamp).
    Ping = 6,
    /// RTT response (echoes the timestamp back).
    Pong = 7,
    /// Graceful session teardown.
    Close = 8,
    /// Authenticated keepalive: sent during idle periods to keep NAT mappings
    /// alive and prove the peer is still responsive. Carries a timestamp.
    Keepalive = 9,
}

impl PacketType {
    /// Convert a raw byte to a [`PacketType`]; `None` if unknown.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Handshake1),
            2 => Some(Self::Handshake2),
            3 => Some(Self::Data),
            4 => Some(Self::Ack),
            5 => Some(Self::Fec),
            6 => Some(Self::Ping),
            7 => Some(Self::Pong),
            8 => Some(Self::Close),
            9 => Some(Self::Keepalive),
            _ => None,
        }
    }

    /// Whether this packet type uses the reliable-delivery channel
    /// (sequenced, retransmitted, acked).
    pub fn is_reliable(self) -> bool {
        matches!(self, Self::Handshake1 | Self::Handshake2 | Self::Close)
    }
}

/// The 24-byte compact header.
///
/// Fields are stored little-endian. Serialisation is hand-rolled (no serde on
/// the wire) so the format is byte-stable and dependency-free on the hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    pub version: u8,
    pub packet_type: PacketType,
    pub session_id: SessionId,
    pub seq: u32,
    pub ack_seq: u32,
    pub ack_bitmap: u32,
    pub fec_group: u16,
    pub fec_index: u8,
    pub fec_k: u8,
    pub fec_m: u8,
    pub flags: HeaderFlags,
}

impl PacketHeader {
    /// Construct a header with sensible defaults and a given type/session.
    pub fn new(packet_type: PacketType, session_id: SessionId, seq: u32) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            packet_type,
            session_id,
            seq,
            ack_seq: 0,
            ack_bitmap: 0,
            fec_group: 0,
            fec_index: 0,
            fec_k: 0,
            fec_m: 0,
            flags: HeaderFlags::NONE,
        }
    }

    /// Serialise into exactly [`HEADER_LEN`] bytes at the start of `buf`.
    /// Returns `()` on success or an error if the buffer is too small.
    pub fn write_to(&self, buf: &mut [u8]) -> Result<(), HeaderError> {
        if buf.len() < HEADER_LEN {
            return Err(HeaderError::BufferTooSmall);
        }
        buf[0] = self.version;
        buf[1] = self.packet_type as u8;
        buf[2..6].copy_from_slice(&self.session_id.to_le_bytes());
        buf[6..10].copy_from_slice(&self.seq.to_le_bytes());
        buf[10..14].copy_from_slice(&self.ack_seq.to_le_bytes());
        buf[14..18].copy_from_slice(&self.ack_bitmap.to_le_bytes());
        buf[18..20].copy_from_slice(&self.fec_group.to_le_bytes());
        buf[20] = self.fec_index;
        buf[21] = self.fec_k;
        buf[22] = self.fec_m;
        buf[23] = self.flags.bits();
        Ok(())
    }

    /// Serialise into a fixed-size array. Infallible: the buffer is always
    /// exactly [`HEADER_LEN`] bytes.
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        let _ = self.write_to(&mut buf);
        buf
    }

    /// Parse a header from the first [`HEADER_LEN`] bytes of `buf`.
    pub fn read_from(buf: &[u8]) -> Result<Self, HeaderError> {
        if buf.len() < HEADER_LEN {
            return Err(HeaderError::BufferTooSmall);
        }
        let version = buf[0];
        if version != PROTOCOL_VERSION {
            return Err(HeaderError::BadVersion(version));
        }
        let packet_type = PacketType::from_byte(buf[1]).ok_or(HeaderError::BadType(buf[1]))?;
        let session_id = SessionId::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]);
        let seq = u32::from_le_bytes([buf[6], buf[7], buf[8], buf[9]]);
        let ack_seq = u32::from_le_bytes([buf[10], buf[11], buf[12], buf[13]]);
        let ack_bitmap = u32::from_le_bytes([buf[14], buf[15], buf[16], buf[17]]);
        let fec_group = u16::from_le_bytes([buf[18], buf[19]]);
        let fec_index = buf[20];
        let fec_k = buf[21];
        let fec_m = buf[22];
        let flags = HeaderFlags::from_bits_truncate(buf[23]);
        Ok(Self {
            version,
            packet_type,
            session_id,
            seq,
            ack_seq,
            ack_bitmap,
            fec_group,
            fec_index,
            fec_k,
            fec_m,
            flags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    #[error("header buffer too small")]
    BufferTooSmall,
    #[error("unsupported protocol version {0}")]
    BadVersion(u8),
    #[error("unknown packet type {0}")]
    BadType(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> PacketHeader {
        let mut h = PacketHeader::new(PacketType::Data, 0xDEADBEEF, 0x12345678);
        h.ack_seq = 0x11223344;
        h.ack_bitmap = 0xAABBCCDD;
        h.fec_group = 0xBABE;
        h.fec_index = 3;
        h.fec_k = 4;
        h.fec_m = 2;
        h.flags = HeaderFlags::NONE;
        h
    }

    #[test]
    fn write_then_read_roundtrips_every_field() {
        let h = sample_header();
        let mut buf = [0u8; HEADER_LEN];
        h.write_to(&mut buf).unwrap();
        let h2 = PacketHeader::read_from(&buf).unwrap();
        assert_eq!(h, h2, "every header field must survive a write/read cycle");
    }

    #[test]
    fn write_into_oversized_buffer_only_uses_first_24_bytes() {
        let h = sample_header();
        let mut buf = [0xFFu8; HEADER_LEN + 16];
        h.write_to(&mut buf).unwrap();
        // First HEADER_LEN bytes hold the header; the rest must be untouched.
        assert_eq!(
            buf[HEADER_LEN], 0xFF,
            "write must not spill past HEADER_LEN"
        );
        let h2 = PacketHeader::read_from(&buf[..HEADER_LEN]).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn write_rejects_buffer_smaller_than_header_len() {
        let h = sample_header();
        let mut buf = [0u8; HEADER_LEN - 1];
        assert_eq!(
            h.write_to(&mut buf).unwrap_err(),
            HeaderError::BufferTooSmall
        );
    }

    #[test]
    fn read_rejects_buffer_smaller_than_header_len() {
        let buf = [0u8; HEADER_LEN - 1];
        assert_eq!(
            PacketHeader::read_from(&buf).unwrap_err(),
            HeaderError::BufferTooSmall
        );
    }

    #[test]
    fn read_rejects_empty_buffer() {
        let buf: [u8; 0] = [];
        assert_eq!(
            PacketHeader::read_from(&buf).unwrap_err(),
            HeaderError::BufferTooSmall
        );
    }

    #[test]
    fn read_rejects_bad_version() {
        let h = sample_header();
        let mut buf = [0u8; HEADER_LEN];
        h.write_to(&mut buf).unwrap();
        buf[0] = 0x02; // unsupported version
        assert_eq!(
            PacketHeader::read_from(&buf).unwrap_err(),
            HeaderError::BadVersion(0x02)
        );
    }

    #[test]
    fn read_rejects_unknown_packet_type() {
        let h = sample_header();
        let mut buf = [0u8; HEADER_LEN];
        h.write_to(&mut buf).unwrap();
        buf[1] = 0xFE; // not a valid PacketType discriminant
        assert_eq!(
            PacketHeader::read_from(&buf).unwrap_err(),
            HeaderError::BadType(0xFE)
        );
    }

    #[test]
    fn all_packet_types_roundtrip_through_from_byte() {
        let all = [
            PacketType::Handshake1,
            PacketType::Handshake2,
            PacketType::Data,
            PacketType::Ack,
            PacketType::Fec,
            PacketType::Ping,
            PacketType::Pong,
            PacketType::Close,
        ];
        for p in all {
            let b = p as u8;
            assert_eq!(PacketType::from_byte(b), Some(p), "type {p:?} byte {b:#x}");
        }
    }

    #[test]
    fn from_byte_rejects_unused_discriminants() {
        for b in [0u8, 10u8, 100u8, 0xFFu8] {
            assert_eq!(
                PacketType::from_byte(b),
                None,
                "byte {b:#x} must be unknown"
            );
        }
    }

    #[test]
    fn only_handshake1_2_and_close_are_reliable() {
        assert!(PacketType::Handshake1.is_reliable());
        assert!(PacketType::Handshake2.is_reliable());
        assert!(PacketType::Close.is_reliable());
        // Everything else is best-effort.
        for p in [
            PacketType::Data,
            PacketType::Ack,
            PacketType::Fec,
            PacketType::Ping,
            PacketType::Pong,
            PacketType::Keepalive,
        ] {
            assert!(!p.is_reliable(), "{p:?} should not be reliable");
        }
    }

    #[test]
    fn header_flags_roundtrip_via_from_bits_truncate() {
        // No flag bits are assigned yet, so a written header reads back empty.
        let h = sample_header();
        let mut buf = [0u8; HEADER_LEN];
        h.write_to(&mut buf).unwrap();
        let h2 = PacketHeader::read_from(&buf).unwrap();
        assert_eq!(h2.flags, HeaderFlags::NONE);
        // Unknown flag bits are silently dropped rather than rejected
        // (from_bits_truncate), which is what makes a future flag backwards
        // compatible with an older receiver.
        buf[23] = 0xFF;
        let h3 = PacketHeader::read_from(&buf).unwrap();
        assert_eq!(h3.flags, HeaderFlags::NONE, "unknown bits dropped");
    }

    #[test]
    fn all_packet_types_have_distinct_byte_values() {
        let all = [
            PacketType::Handshake1,
            PacketType::Handshake2,
            PacketType::Data,
            PacketType::Ack,
            PacketType::Fec,
            PacketType::Ping,
            PacketType::Pong,
            PacketType::Close,
        ];
        let bytes: Vec<u8> = all.iter().map(|p| *p as u8).collect();
        let mut unique = bytes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(bytes.len(), unique.len(), "discriminants must be unique");
    }

    #[test]
    fn wire_layout_is_byte_stable_across_endian() {
        // The spec is little-endian; pin the exact on-wire bytes for the
        // sample header so an accidental big-endian regression is caught.
        let h = sample_header();
        let mut buf = [0u8; HEADER_LEN];
        h.write_to(&mut buf).unwrap();
        assert_eq!(buf[0], PROTOCOL_VERSION);
        assert_eq!(buf[1], PacketType::Data as u8);
        // session_id little-endian
        assert_eq!(&buf[2..6], &0xDEADBEEF_u32.to_le_bytes());
        // seq little-endian
        assert_eq!(&buf[6..10], &0x12345678_u32.to_le_bytes());
        // ack_seq
        assert_eq!(&buf[10..14], &0x11223344_u32.to_le_bytes());
        // ack_bitmap
        assert_eq!(&buf[14..18], &0xAABBCCDD_u32.to_le_bytes());
        // fec_group
        assert_eq!(&buf[18..20], &0xBABE_u16.to_le_bytes());
        // fec_index/k/m
        assert_eq!(buf[20], 3);
        assert_eq!(buf[21], 4);
        assert_eq!(buf[22], 2);
        // flags (no bits are assigned yet)
        assert_eq!(buf[23], HeaderFlags::NONE.bits());
    }

    #[test]
    fn zero_session_id_roundtrips() {
        // session id 0 is unusual but the codec must not special-case it.
        let h = PacketHeader::new(PacketType::Ping, 0, 1);
        let mut buf = [0u8; HEADER_LEN];
        h.write_to(&mut buf).unwrap();
        let h2 = PacketHeader::read_from(&buf).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn max_seq_and_session_id_roundtrip() {
        let h = PacketHeader::new(PacketType::Close, u32::MAX, u32::MAX);
        let mut buf = [0u8; HEADER_LEN];
        h.write_to(&mut buf).unwrap();
        let h2 = PacketHeader::read_from(&buf).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn to_bytes_then_read_from_roundtrips() {
        // The infallible to_bytes() path must agree with write_to().
        let h = sample_header();
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), HEADER_LEN);
        let h2 = PacketHeader::read_from(&bytes).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn new_initialises_all_non_seq_fields_to_zero() {
        let h = PacketHeader::new(PacketType::Data, 0x42, 7);
        assert_eq!(h.version, PROTOCOL_VERSION);
        assert_eq!(h.packet_type, PacketType::Data);
        assert_eq!(h.session_id, 0x42);
        assert_eq!(h.seq, 7);
        // Everything else must default to zero/empty.
        assert_eq!(h.ack_seq, 0);
        assert_eq!(h.ack_bitmap, 0);
        assert_eq!(h.fec_group, 0);
        assert_eq!(h.fec_index, 0);
        assert_eq!(h.fec_k, 0);
        assert_eq!(h.fec_m, 0);
        assert_eq!(h.flags, HeaderFlags::NONE);
    }

    #[test]
    fn read_from_ignores_bytes_beyond_header_len() {
        // A larger buffer (e.g. a full frame) must parse only the first 24 bytes;
        // trailing payload bytes must not corrupt the header.
        let h = sample_header();
        let mut buf = vec![0u8; HEADER_LEN + 64];
        h.write_to(&mut buf).unwrap();
        // Fill the trailing payload region with junk.
        for b in &mut buf[HEADER_LEN..] {
            *b = 0xEE;
        }
        let h2 = PacketHeader::read_from(&buf).unwrap();
        assert_eq!(h, h2, "trailing bytes must not affect header parse");
    }

    #[test]
    fn flags_none_serialises_as_zero_byte() {
        let mut h = sample_header();
        h.flags = HeaderFlags::NONE;
        let mut buf = [0u8; HEADER_LEN];
        h.write_to(&mut buf).unwrap();
        assert_eq!(buf[23], 0, "NONE flags must be byte 0");
        let h2 = PacketHeader::read_from(&buf).unwrap();
        assert_eq!(h2.flags, HeaderFlags::NONE);
    }

    #[test]
    fn read_reports_actual_bad_version_byte() {
        let h = sample_header();
        let mut buf = [0u8; HEADER_LEN];
        h.write_to(&mut buf).unwrap();
        buf[0] = 0x07;
        // The error must carry the offending byte for diagnostics.
        assert_eq!(
            PacketHeader::read_from(&buf).unwrap_err(),
            HeaderError::BadVersion(0x07)
        );
    }

    #[test]
    fn read_reports_actual_bad_type_byte() {
        let h = sample_header();
        let mut buf = [0u8; HEADER_LEN];
        h.write_to(&mut buf).unwrap();
        buf[1] = 0xCD;
        assert_eq!(
            PacketHeader::read_from(&buf).unwrap_err(),
            HeaderError::BadType(0xCD)
        );
    }

    #[test]
    fn version_zero_is_rejected() {
        // 0x00 is not a valid version even though it is a common "default".
        let h = sample_header();
        let mut buf = [0u8; HEADER_LEN];
        h.write_to(&mut buf).unwrap();
        buf[0] = 0x00;
        assert_eq!(
            PacketHeader::read_from(&buf).unwrap_err(),
            HeaderError::BadVersion(0x00)
        );
    }

    #[test]
    fn keepalive_roundtrips_and_is_not_reliable() {
        // Keepalive (9) was the newest added type; pin its byte, roundtrip and
        // reliability classification explicitly.
        assert_eq!(PacketType::Keepalive as u8, 9);
        assert_eq!(PacketType::from_byte(9), Some(PacketType::Keepalive));
        assert!(!PacketType::Keepalive.is_reliable());

        let h = PacketHeader::new(PacketType::Keepalive, 0x1234, 99);
        let mut buf = [0u8; HEADER_LEN];
        h.write_to(&mut buf).unwrap();
        let h2 = PacketHeader::read_from(&buf).unwrap();
        assert_eq!(h, h2);
        assert_eq!(h2.packet_type, PacketType::Keepalive);
    }

    #[test]
    fn write_to_exactly_header_len_buffer_succeeds() {
        // Boundary: a buffer of exactly HEADER_LEN bytes is the minimum legal
        // target and must succeed without error.
        let h = sample_header();
        let mut buf = [0u8; HEADER_LEN];
        assert!(h.write_to(&mut buf).is_ok());
        assert_eq!(PacketHeader::read_from(&buf).unwrap(), h);
    }

    #[test]
    fn fec_fields_at_max_values_roundtrip() {
        let mut h = PacketHeader::new(PacketType::Fec, u32::MAX, u32::MAX);
        h.fec_group = u16::MAX;
        h.fec_index = u8::MAX;
        h.fec_k = u8::MAX;
        h.fec_m = u8::MAX;
        let mut buf = [0u8; HEADER_LEN];
        h.write_to(&mut buf).unwrap();
        let h2 = PacketHeader::read_from(&buf).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn header_byte_offsets_are_pinned() {
        // Pin the exact byte offsets of every field so an accidental re-layout
        // of the packed header is caught immediately.
        let h = sample_header();
        let buf = h.to_bytes();
        assert_eq!(buf[0], h.version, "version at offset 0");
        assert_eq!(buf[1], h.packet_type as u8, "packet_type at offset 1");
        assert_eq!(
            &buf[2..6],
            &h.session_id.to_le_bytes(),
            "session_id at 2..6"
        );
        assert_eq!(&buf[6..10], &h.seq.to_le_bytes(), "seq at 6..10");
        assert_eq!(&buf[10..14], &h.ack_seq.to_le_bytes(), "ack_seq at 10..14");
        assert_eq!(
            &buf[14..18],
            &h.ack_bitmap.to_le_bytes(),
            "ack_bitmap at 14..18"
        );
        assert_eq!(
            &buf[18..20],
            &h.fec_group.to_le_bytes(),
            "fec_group at 18..20"
        );
        assert_eq!(buf[20], h.fec_index, "fec_index at offset 20");
        assert_eq!(buf[21], h.fec_k, "fec_k at offset 21");
        assert_eq!(buf[22], h.fec_m, "fec_m at offset 22");
        assert_eq!(buf[23], h.flags.bits(), "flags at offset 23");
    }
}
