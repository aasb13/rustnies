//! Packet encode/decode.
//!
//! Encoding is split into two stages so the [`crate::transport::Transport`]
//! layer can interpose on the bytes that actually go on the wire:
//!
//! 1. [`encode`] produces the *plaintext* on-the-wire frame:
//!    `header || ciphertext`, where `ciphertext` is the AEAD-sealed payload.
//! 2. The optional `ObfuscationStack` may transform that frame, then the
//!    [`Transport`] layer wraps it, producing the final UDP datagram.
//!
//! Decoding is the inverse: [`Transport::unwrap`] yields a plaintext frame,
//! then [`decode`] splits header from ciphertext for the session to decrypt.

use bytes::{Buf, BufMut, BytesMut};

use super::PacketType;
use super::header::{HEADER_LEN, HeaderError, PacketHeader};

/// A decoded packet: header plus the still-encrypted ciphertext body.
///
/// Decryption is intentionally left to [`crate::crypto`]; the codec is purely
/// structural so it stays independent of the cipher.
#[derive(Debug, Clone)]
pub struct Packet {
    pub header: PacketHeader,
    /// AEAD ciphertext (payload + 16-byte tag). Empty for control packets
    /// that carry no payload.
    pub body: bytes::Bytes,
}

impl Packet {
    /// Build a packet header-only frame (no payload).
    pub fn empty(ptype: PacketType, session_id: super::SessionId, seq: u32) -> Self {
        Self {
            header: PacketHeader::new(ptype, session_id, seq),
            body: bytes::Bytes::new(),
        }
    }

    /// Encode the plaintext frame `header || body` into a fresh `BytesMut`.
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(HEADER_LEN + self.body.len());
        buf.put_slice(&self.header.to_bytes());
        buf.put_slice(&self.body);
        buf
    }
}

/// Encode a header plus a pre-encrypted body into a fresh `BytesMut`.
pub fn encode_raw(header: &PacketHeader, ciphertext: &[u8]) -> BytesMut {
    let mut buf = BytesMut::with_capacity(HEADER_LEN + ciphertext.len());
    buf.put_slice(&header.to_bytes());
    buf.put_slice(ciphertext);
    buf
}

/// Decode a plaintext frame into [`Packet`].
///
/// `buf` is the *unwrapped* output of [`crate::transport::Transport::unwrap`];
/// i.e. the bytes after any transport-layer wrapping have been removed.
pub fn decode(buf: &[u8]) -> Result<Packet, HeaderError> {
    let header = PacketHeader::read_from(buf)?;
    let body = bytes::Bytes::copy_from_slice(&buf[HEADER_LEN..]);
    Ok(Packet { header, body })
}

/// Convenience: split a BytesMut frame at the header boundary without copying
/// the header. Used by hot-path decoders that want a header borrow + body owned.
pub fn split(buf: &mut BytesMut) -> Result<(PacketHeader, bytes::Bytes), HeaderError> {
    if buf.remaining() < HEADER_LEN {
        return Err(HeaderError::BufferTooSmall);
    }
    let header = PacketHeader::read_from(buf.chunk())?;
    buf.advance(HEADER_LEN);
    let body = buf.split().freeze();
    Ok((header, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::header::{HEADER_LEN, PacketHeader, PacketType};

    fn sample_packet(payload: &[u8]) -> Packet {
        let mut h = PacketHeader::new(PacketType::Data, 0xCAFEBABE, 7);
        h.ack_seq = 9;
        h.ack_bitmap = 0x1234;
        h.fec_group = 0xBEEF;
        h.fec_index = 2;
        h.fec_k = 4;
        h.fec_m = 2;
        Packet {
            header: h,
            body: bytes::Bytes::copy_from_slice(payload),
        }
    }

    #[test]
    fn encode_then_decode_preserves_header_and_body() {
        let payload = b"hello world";
        let p = sample_packet(payload);
        let buf = p.encode();
        // Frame layout: header || body.
        assert_eq!(buf.len(), HEADER_LEN + payload.len());
        let p2 = decode(&buf).unwrap();
        assert_eq!(p2.header, p.header);
        assert_eq!(p2.body.as_ref(), payload);
    }

    #[test]
    fn encode_raw_matches_encode() {
        let payload = b"abc";
        let p = sample_packet(payload);
        let via_packet = p.encode();
        let via_raw = encode_raw(&p.header, &p.body);
        assert_eq!(via_packet.as_ref(), via_raw.as_ref());
    }

    #[test]
    fn empty_body_roundtrips() {
        let p = Packet::empty(PacketType::Ack, 0x1, 5);
        let buf = p.encode();
        assert_eq!(buf.len(), HEADER_LEN, "header-only frame has no body");
        let p2 = decode(&buf).unwrap();
        assert_eq!(p2.header, p.header);
        assert!(p2.body.is_empty());
    }

    #[test]
    fn decode_rejects_short_buffer() {
        let buf = vec![0u8; HEADER_LEN - 1];
        assert_eq!(decode(&buf).unwrap_err(), HeaderError::BufferTooSmall);
    }

    #[test]
    fn decode_rejects_empty_buffer() {
        let buf: Vec<u8> = Vec::new();
        assert_eq!(decode(&buf).unwrap_err(), HeaderError::BufferTooSmall);
    }

    #[test]
    fn decode_propagates_bad_version() {
        let p = sample_packet(b"x");
        let mut buf = p.encode();
        buf[0] = 0x09; // bad version
        assert_eq!(decode(&buf).unwrap_err(), HeaderError::BadVersion(0x09));
    }

    #[test]
    fn decode_propagates_bad_packet_type() {
        let p = sample_packet(b"x");
        let mut buf = p.encode();
        buf[1] = 0xAB; // unknown type
        assert_eq!(decode(&buf).unwrap_err(), HeaderError::BadType(0xAB));
    }

    #[test]
    fn decode_preserves_large_body_intact() {
        // A body larger than the MTU is still structurally fine for the codec.
        let payload = vec![0x5Au8; 4000];
        let p = sample_packet(&payload);
        let buf = p.encode();
        let p2 = decode(&buf).unwrap();
        assert_eq!(p2.body.len(), payload.len());
        assert_eq!(p2.body.as_ref(), payload.as_slice());
    }

    #[test]
    fn split_returns_header_and_body_consistent_with_decode() {
        let payload = b"split me";
        let p = sample_packet(payload);
        let mut buf = p.encode();
        let (hdr, body) = split(&mut buf).unwrap();
        assert_eq!(hdr, p.header);
        assert_eq!(body.as_ref(), payload);
        // After split, the BytesMut should be empty.
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn split_rejects_short_buffer() {
        let mut buf = BytesMut::from(&[0u8; 5][..]);
        assert_eq!(split(&mut buf).unwrap_err(), HeaderError::BufferTooSmall);
    }

    #[test]
    fn split_propagates_header_decode_errors() {
        let p = sample_packet(b"x");
        let mut buf = p.encode();
        buf[1] = 0xFE; // bad type
        assert_eq!(split(&mut buf).unwrap_err(), HeaderError::BadType(0xFE));
    }

    #[test]
    fn empty_packet_helper_has_no_body() {
        let p = Packet::empty(PacketType::Ping, 0xABCDEF, 42);
        assert!(p.body.is_empty());
        assert_eq!(p.header.packet_type, PacketType::Ping);
        assert_eq!(p.header.session_id, 0xABCDEF);
        assert_eq!(p.header.seq, 42);
    }

    #[test]
    fn encode_raw_empty_ciphertext_yields_header_only_frame() {
        let h = PacketHeader::new(PacketType::Ack, 0x1, 1);
        let buf = encode_raw(&h, &[]);
        assert_eq!(buf.len(), HEADER_LEN, "no body -> header-only frame");
        let p = decode(&buf).unwrap();
        assert_eq!(p.header, h);
        assert!(p.body.is_empty());
    }

    #[test]
    fn roundtrip_every_packet_type() {
        // Every defined PacketType must survive an encode/decode cycle.
        let all = [
            PacketType::Handshake1,
            PacketType::Handshake2,
            PacketType::Data,
            PacketType::Ack,
            PacketType::Fec,
            PacketType::Ping,
            PacketType::Pong,
            PacketType::Close,
            PacketType::Keepalive,
        ];
        for ptype in all {
            let p = Packet::empty(ptype, 0x55AA, 3);
            let buf = p.encode();
            let p2 = decode(&buf).unwrap();
            assert_eq!(
                p2.header.packet_type, ptype,
                "type {ptype:?} lost in roundtrip"
            );
            assert_eq!(p2.header, p.header);
            assert!(p2.body.is_empty());
        }
    }

    #[test]
    fn body_with_zero_bytes_roundtrips() {
        // A body full of 0x00 must not be confused with "empty"; length is
        // authoritative.
        let payload = vec![0u8; 32];
        let p = sample_packet(&payload);
        let buf = p.encode();
        assert_eq!(buf.len(), HEADER_LEN + 32);
        let p2 = decode(&buf).unwrap();
        assert_eq!(p2.body.len(), 32);
        assert_eq!(p2.body.as_ref(), payload.as_slice());
    }

    #[test]
    fn body_with_all_0xff_roundtrips() {
        let payload = vec![0xFFu8; 17];
        let p = sample_packet(&payload);
        let buf = p.encode();
        let p2 = decode(&buf).unwrap();
        assert_eq!(p2.body.as_ref(), payload.as_slice());
    }

    #[test]
    fn split_header_only_frame_yields_empty_body() {
        let p = Packet::empty(PacketType::Close, 0x2, 8);
        let mut buf = p.encode();
        assert_eq!(buf.len(), HEADER_LEN);
        let (hdr, body) = split(&mut buf).unwrap();
        assert_eq!(hdr, p.header);
        assert!(body.is_empty());
        assert_eq!(buf.remaining(), 0, "nothing left after consuming header");
    }

    #[test]
    fn split_consumes_header_and_body_leaving_empty() {
        let payload = b"payload bytes here";
        let p = sample_packet(payload);
        let mut buf = p.encode();
        let (hdr, body) = split(&mut buf).unwrap();
        assert_eq!(hdr, p.header);
        assert_eq!(body.as_ref(), payload);
        // After split, the whole frame (header + body) must be consumed.
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn decode_with_exactly_header_len_yields_empty_body() {
        // Boundary: a frame of exactly HEADER_LEN bytes is a header-only packet.
        let h = PacketHeader::new(PacketType::Pong, 0x9, 1);
        let mut buf = vec![0u8; HEADER_LEN];
        h.write_to(&mut buf).unwrap();
        let p = decode(&buf).unwrap();
        assert_eq!(p.header, h);
        assert!(p.body.is_empty());
    }

    #[test]
    fn decode_body_bytes_do_not_affect_header_parse() {
        // Body bytes that look like a bad version/type must not corrupt the
        // already-parsed header; the codec treats the body as opaque.
        let p = sample_packet(b"abc");
        let mut buf = p.encode();
        // Clobber the first body byte (offset HEADER_LEN) with a bad version.
        buf[HEADER_LEN] = 0x09;
        let p2 = decode(&buf).unwrap();
        assert_eq!(p2.header, p.header, "header parse unaffected by body");
        assert_eq!(p2.body[0], 0x09);
    }

    #[test]
    fn encode_and_encode_raw_match_for_empty_body() {
        let h = PacketHeader::new(PacketType::Ping, 0x1, 1);
        let via_packet = Packet {
            header: h,
            body: bytes::Bytes::new(),
        }
        .encode();
        let via_raw = encode_raw(&h, &[]);
        assert_eq!(via_packet.as_ref(), via_raw.as_ref());
        assert_eq!(via_packet.len(), HEADER_LEN);
    }
}
