//! The framing seam: how a [`PacketHeader`] becomes bytes on the wire.
//!
//! # Why this seam exists
//!
//! The tunnel's behaviour is a *closed set* of things a VPN does — carry a
//! data packet, emit a parity symbol, probe RTT, ack reliable delivery, tear
//! down. That set is deliberately **not** configurable: [`PacketType`] stays a
//! closed `#[repr(u8)]` enum and the receive path's `match` on it stays
//! exhaustive, so adding a packet type is a compile error until every site
//! handles it. Turning the taxonomy into a runtime-configurable blob would buy
//! nothing and cost that safety property.
//!
//! What *is* swappable is the **encoding**: how those same semantic fields are
//! laid out in bytes. Two codecs over the same [`PacketHeader`] produce two
//! genuinely different wire protocols, and the tunnel does not change. That
//! also means a future header extension is a new codec rather than a
//! re-layout of this one, and a peer running either can still be served.
//!
//! # What a codec is responsible for
//!
//! - Serialising a [`PacketHeader`] to bytes and back.
//! - Telling a receiver how many bytes it must have before it can route a
//!   message ([`FrameCodec::route_prefix_len`]) — this is what lets a server
//!   demux many sessions off one socket without decrypting anything.
//! - Bounding its own header size ([`FrameCodec::max_header_len`]) so the MTU
//! and routing-whitening budgets can be computed without knowing which codec
//! is in use.
//!
//! # What a codec is *not* responsible for
//!
//! Message boundaries. Whether the bytes arrive as discrete datagrams or
//! concatenated on a stream is a property of the
//! [`crate::carrier::Carrier`], not of the protocol. A stream carrier
//! length-delimits frames itself; a codec never sees the delimiter.

use std::sync::Arc;

use bytes::{BufMut, BytesMut};

use super::PacketType;
use super::header::{HEADER_LEN, HeaderError, PROTOCOL_VERSION, PacketHeader, SessionId};

/// A swappable header encoding.
///
/// Implementors must be cheap to clone-by-hand (`box_clone`) and must be
/// `Send + Sync`: the server shares one codec across every session.
pub trait FrameCodec: Send + Sync + 'static {
    /// Config name, e.g. `"v1-fixed"`. Stable; appears in the config file and
    /// in the negotiation offer.
    fn name(&self) -> &'static str;

    /// Stable wire id used in the negotiation answer. Never reuse an id.
    fn wire_id(&self) -> u8;

    /// Bytes a receiver needs before it can route a message by `SessionId`
    /// without decrypting it.
    ///
    /// A server holds one socket shared by every session, so the only thing it
    /// can do with an inbound message is peek far enough to find a session id
    /// and forward it. This bounds how far it must read.
    fn route_prefix_len(&self) -> usize;

    /// Upper bound on this codec's header size.
    ///
    /// Used for the MTU budget (the TUN MTU clamp) and for the server's
    /// routing-whitening keystream. A variable-length codec returns its
    /// maximum, not its typical size, so the budget stays an upper bound.
    fn max_header_len(&self) -> usize;

    /// Append this header's encoding to `out`.
    fn write_header(&self, header: &PacketHeader, out: &mut BytesMut) -> Result<(), FrameError>;

    /// Parse a header from the first `max_header_len()` bytes of `buf`.
    ///
    /// For a variable-length codec, `buf` must be the *whole frame* (the codec
    /// finds its own boundary) — this is why the signature takes a slice with
    /// no length argument rather than a fixed-size array.
    fn read_header(&self, buf: &[u8]) -> Result<PacketHeader, FrameError>;

    /// Cheap routing check: does `buf` look like a message of *this* codec?
    ///
    /// Must not allocate, decrypt, or trust any length. Used to reject scan
    /// noise before paying for a handshake.
    fn looks_like_frame(&self, buf: &[u8]) -> bool;

    /// The session id to route by, or `None` if this message cannot be routed.
    ///
    /// `None` is the normal answer for a handshake message (no session yet)
    /// and for a frame too short to route. A wrong-but-plausible id is
    /// harmless: the forwarded frame is authenticated and a mismatch is
    /// dropped, so this is a hint, never an authority.
    fn peek_session_id(&self, buf: &[u8]) -> Option<SessionId>;

    /// Where `frame`'s header ends and its body begins.
    ///
    /// This is the reason the trait takes a whole frame rather than a
    /// fixed-size header array: a variable-length codec finds its own boundary
    /// and this reports it. For a fixed-layout codec it is always
    /// [`FrameCodec::max_header_len`].
    ///
    /// `frame` must be a frame this codec has already accepted — call
    /// [`FrameCodec::read_header`] first, so a malformed frame is rejected
    /// rather than silently yielding a bogus offset.
    fn body_offset(&self, frame: &[u8]) -> usize;

    /// The header's encoding as a standalone buffer.
    ///
    /// Used for AEAD associated data, which must be byte-identical to the
    /// header the sender authenticated. Infinible by construction: the buffer
    /// is sized from [`FrameCodec::max_header_len`].
    fn encode_header(&self, header: &PacketHeader) -> bytes::Bytes {
        let mut out = BytesMut::with_capacity(self.max_header_len());
        self.write_header(header, &mut out)
            .expect("buffer sized from max_header_len cannot be too small");
        out.freeze()
    }

    /// Encode `header || ciphertext` — the full plaintext frame, pre-envelope.
    fn encode_frame(&self, header: &PacketHeader, ciphertext: &[u8]) -> BytesMut {
        let mut out = BytesMut::with_capacity(self.max_header_len() + ciphertext.len());
        // Capacity is sized off `max_header_len`, so a variable-length codec
        // may still reallocate here; that is fine, it happens once per send.
        self.write_header(header, &mut out)
            .expect("frame buffer sized from max_header_len cannot be too small");
        out.put_slice(ciphertext);
        out
    }

    /// Hand-roll a clone. Object safety precludes `Clone`.
    fn box_clone(&self) -> Box<dyn FrameCodec>;
}

impl Clone for Box<dyn FrameCodec> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

/// Errors from header serialisation. Deliberately a superset of
/// [`HeaderError`] so a codec can report its own failures in the same enum.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("header buffer too small")]
    BufferTooSmall,
    #[error("unsupported protocol version {0}")]
    BadVersion(u8),
    #[error("unknown packet type {0}")]
    BadType(u8),
    #[error("malformed frame: {0}")]
    Malformed(&'static str),
    #[error("unknown frame codec {0:?}")]
    UnknownCodec(String),
    #[error("unknown frame codec wire id {0}")]
    UnknownCodecId(u8),
}

impl From<HeaderError> for FrameError {
    fn from(e: HeaderError) -> Self {
        match e {
            HeaderError::BufferTooSmall => Self::BufferTooSmall,
            HeaderError::BadVersion(v) => Self::BadVersion(v),
            HeaderError::BadType(b) => Self::BadType(b),
        }
    }
}

// ---------------------------------------------------------------------------
// v1-fixed: the original packed 24-byte header.
// ---------------------------------------------------------------------------

/// The original fixed 24-byte packed header, byte-for-byte.
///
/// This is a thin seam over [`PacketHeader`]'s own `write_to`/`read_from`, so
/// the default wire format is unchanged by the existence of the trait. That
/// matters: it is what lets a default-configured build stay interoperable with
/// a pre-seam one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct V1FixedCodec;

impl V1FixedCodec {
    /// Construct the codec.
    pub const fn new() -> Self {
        Self
    }
}

impl FrameCodec for V1FixedCodec {
    fn name(&self) -> &'static str {
        "v1-fixed"
    }

    fn wire_id(&self) -> u8 {
        FRAME_V1_FIXED
    }

    fn route_prefix_len(&self) -> usize {
        // version, packet_type, session_id.
        V1_ROUTE_PREFIX_LEN
    }

    fn max_header_len(&self) -> usize {
        HEADER_LEN
    }

    fn write_header(&self, header: &PacketHeader, out: &mut BytesMut) -> Result<(), FrameError> {
        let start = out.len();
        out.resize(start + HEADER_LEN, 0);
        header.write_to(&mut out[start..])?;
        Ok(())
    }

    fn read_header(&self, buf: &[u8]) -> Result<PacketHeader, FrameError> {
        Ok(PacketHeader::read_from(buf)?)
    }

    fn looks_like_frame(&self, buf: &[u8]) -> bool {
        buf.len() >= V1_ROUTE_PREFIX_LEN
            && buf[0] == PROTOCOL_VERSION
            && PacketType::from_byte(buf[1]).is_some()
    }

    fn peek_session_id(&self, buf: &[u8]) -> Option<SessionId> {
        if !self.looks_like_frame(buf) {
            return None;
        }
        Some(SessionId::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]))
    }

    fn body_offset(&self, frame: &[u8]) -> usize {
        // Fixed layout: always exactly HEADER_LEN. `min` guards a frame that
        // was truncated after `read_header` accepted it, which cannot happen
        // but keeps this total rather than panicking.
        HEADER_LEN.min(frame.len())
    }

    fn box_clone(&self) -> Box<dyn FrameCodec> {
        Box::new(*self)
    }
}

/// Wire id for [`V1FixedCodec`].
pub const FRAME_V1_FIXED: u8 = 1;

/// The default codec's config name.
///
/// Also the codec a pre-seam peer is assumed to run: it is the only one that
/// existed, so a 6-byte `Selection` and a three-list offer both decode to it.
pub const DEFAULT_FRAME_CODEC: &str = "v1-fixed";

/// Bytes of a v1-fixed message needed to recover the `SessionId`:
/// version (1) + packet_type (1) + session_id (4).
pub const V1_ROUTE_PREFIX_LEN: usize = 6;

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Every codec in this build, for the codec-agnostic peek.
///
/// A datagram server has to route a frame *before* it knows which session it
/// belongs to, and therefore before it knows that session's negotiated codec.
/// So the routing peek cannot ask one codec — it has to try them all.
///
/// This is unambiguous because each codec's `looks_like_frame` requires a
/// distinct wire discriminator (the version byte for v1-fixed, the TLV magic
/// for v2-tlv), so at most one can accept a given buffer. Adding a codec is one
/// entry here; the ordering is irrelevant.
pub const ALL_CODECS: &[fn() -> Box<dyn FrameCodec>] = &[|| Box::new(V1FixedCodec::new())];

/// Route a frame to a session without knowing its codec.
///
/// Returns `None` if no codec claims the buffer — which is the normal answer
/// for a handshake message and for scan noise. As with a single codec's peek,
/// this is a *hint*: a match routes the frame to one session's decrypt attempt,
/// and the AEAD tag is what actually decides.
pub fn peek_any_session_id(buf: &[u8]) -> Option<SessionId> {
    ALL_CODECS
        .iter()
        .find_map(|make| make().peek_session_id(buf))
}

/// Whether any codec claims `buf`.
pub fn any_codec_claims(buf: &[u8]) -> bool {
    ALL_CODECS.iter().any(|make| make().looks_like_frame(buf))
}

/// Registry of known frame codecs, keyed by config name.
///
/// A name that is not here is a hard error, never a fallback: a silent
/// fallback would leave the two peers encoding headers differently, and the
/// symptom (a session that connects then drops every packet) is very hard to
/// trace back to a config typo.
pub fn build_frame_codec(name: &str) -> Result<Arc<dyn FrameCodec>, FrameError> {
    match name {
        "v1-fixed" => Ok(Arc::new(V1FixedCodec::new())),
        other => Err(FrameError::UnknownCodec(other.to_string())),
    }
}

/// Registry lookup by wire id, for the receiving side of a negotiation.
///
/// An id this build cannot run is a hard error: it means the peer selected
/// something we do not implement, and continuing would misparse every frame.
pub fn frame_codec_by_id(id: u8) -> Result<Arc<dyn FrameCodec>, FrameError> {
    match id {
        FRAME_V1_FIXED => Ok(Arc::new(V1FixedCodec::new())),
        other => Err(FrameError::UnknownCodecId(other)),
    }
}

impl FrameError {
    /// Error for an unknown config name.
    pub fn unknown_codec(name: impl Into<String>) -> Self {
        Self::UnknownCodec(name.into())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PacketHeader {
        let mut h = PacketHeader::new(PacketType::Data, 0xDEADBEEF, 0x12345678);
        h.ack_seq = 0x11223344;
        h.ack_bitmap = 0xAABBCCDD;
        h.fec_group = 0xBABE;
        h.fec_index = 3;
        h.fec_k = 4;
        h.fec_m = 2;
        h
    }

    /// The whole point of the seam is that `V1FixedCodec` is a no-op
    /// re-expression of the original header. Pin the exact bytes so a refactor
    /// that quietly changes the default wire format fails here.
    #[test]
    fn v1_fixed_produces_exactly_the_original_header_bytes() {
        let c = V1FixedCodec::new();
        let h = sample();
        let frame = c.encode_frame(&h, b"payload");
        assert_eq!(
            &frame[..HEADER_LEN],
            &h.to_bytes(),
            "seam must be byte-identical to PacketHeader::to_bytes"
        );
        assert_eq!(&frame[HEADER_LEN..], b"payload");
    }

    #[test]
    fn v1_fixed_header_len_is_still_24() {
        assert_eq!(V1FixedCodec::new().max_header_len(), 24);
        assert_eq!(V1FixedCodec::new().route_prefix_len(), 6);
    }

    #[test]
    fn v1_fixed_roundtrips_a_header() {
        let c = V1FixedCodec::new();
        let h = sample();
        let buf = c.encode_frame(&h, b"");
        assert_eq!(c.read_header(&buf).unwrap(), h);
    }

    #[test]
    fn v1_fixed_rejects_a_bad_version() {
        let c = V1FixedCodec::new();
        let mut buf = c.encode_frame(&sample(), b"").to_vec();
        buf[0] = 0x02;
        assert_eq!(
            c.read_header(&buf).unwrap_err(),
            FrameError::BadVersion(0x02)
        );
        assert!(!c.looks_like_frame(&buf));
    }

    #[test]
    fn v1_fixed_rejects_an_unknown_type() {
        let c = V1FixedCodec::new();
        let mut buf = c.encode_frame(&sample(), b"").to_vec();
        buf[1] = 0xFE;
        assert_eq!(c.read_header(&buf).unwrap_err(), FrameError::BadType(0xFE));
        assert!(!c.looks_like_frame(&buf));
    }

    #[test]
    fn v1_fixed_read_rejects_a_short_buffer() {
        let c = V1FixedCodec::new();
        assert_eq!(
            c.read_header(&[0u8; 3]).unwrap_err(),
            FrameError::BufferTooSmall
        );
    }

    #[test]
    fn v1_fixed_peek_recovers_the_session_id() {
        let c = V1FixedCodec::new();
        let buf = c.encode_frame(&sample(), b"body");
        assert_eq!(c.peek_session_id(&buf), Some(0xDEADBEEF));
    }

    #[test]
    fn v1_fixed_peek_needs_only_its_prefix_len() {
        let c = V1FixedCodec::new();
        let full = c.encode_frame(&sample(), b"body");
        // Truncating to exactly the route prefix must still route.
        let prefix = &full[..c.route_prefix_len()];
        assert_eq!(prefix.len(), 6);
        assert_eq!(c.peek_session_id(prefix), Some(0xDEADBEEF));
    }

    #[test]
    fn v1_fixed_peek_rejects_short_and_non_v1_buffers() {
        let c = V1FixedCodec::new();
        assert_eq!(c.peek_session_id(&[PROTOCOL_VERSION, 3]), None);
        assert_eq!(c.peek_session_id(&[]), None);
        // Right length, wrong version.
        assert_eq!(c.peek_session_id(&[0x09, 3, 0, 0, 0, 1]), None);
    }

    #[test]
    fn write_header_appends_rather_than_overwrites() {
        // `encode_frame` and `write_header` are used interchangeably by the
        // handshake driver, which pre-fills the buffer in some paths.
        let c = V1FixedCodec::new();
        let mut out = BytesMut::from(&b"pre"[..]);
        c.write_header(&sample(), &mut out).unwrap();
        assert_eq!(&out[..3], b"pre");
        assert_eq!(&out[3..3 + HEADER_LEN], &sample().to_bytes());
    }

    #[test]
    fn encode_header_matches_the_header_prefix_of_encode_frame() {
        // The AEAD AAD is `encode_header`, and the frame's header must be the
        // same bytes or every decrypt fails. Pin that they agree.
        let c = V1FixedCodec::new();
        let h = sample();
        let aad = c.encode_header(&h);
        let frame = c.encode_frame(&h, b"body");
        assert_eq!(&aad[..], &frame[..HEADER_LEN]);
    }

    #[test]
    fn body_offset_splits_frame_from_body() {
        let c = V1FixedCodec::new();
        let h = sample();
        let frame = c.encode_frame(&h, b"the body");
        let off = c.body_offset(&frame);
        assert_eq!(off, HEADER_LEN);
        assert_eq!(&frame[off..], b"the body");
    }

    #[test]
    fn body_offset_of_a_header_only_frame_is_the_header_len() {
        let c = V1FixedCodec::new();
        let frame = c.encode_frame(&sample(), b"");
        assert_eq!(c.body_offset(&frame), HEADER_LEN);
        assert!(frame[c.body_offset(&frame)..].is_empty());
    }

    #[test]
    fn encode_then_decode_then_encode_is_stable() {
        // AAD is re-encoded on the receive path from the *decoded* header, so a
        // codec whose round-trip is not exact would authenticate a different
        // byte string than the sender used and fail every packet. This is the
        // property the whole design depends on.
        let c = V1FixedCodec::new();
        let h = sample();
        let once = c.encode_header(&h);
        let decoded = c.read_header(&once).unwrap();
        let twice = c.encode_header(&decoded);
        assert_eq!(once, twice, "header encoding must be round-trip stable");
    }

    #[test]
    fn every_sample_header_survives_the_full_seam() {
        // Sweep the extremes rather than one happy-path header.
        let c = V1FixedCodec::new();
        for (sid, seq, ptype) in [
            (0u32, 0u32, PacketType::Data),
            (u32::MAX, u32::MAX, PacketType::Close),
            (0xCAFEBABE, 7, PacketType::Fec),
            (1, 1, PacketType::Keepalive),
        ] {
            let mut h = PacketHeader::new(ptype, sid, seq);
            h.ack_seq = seq.wrapping_mul(3);
            h.ack_bitmap = seq.rotate_left(13);
            h.fec_group = seq as u16;
            h.fec_index = (seq % 251) as u8;
            h.fec_k = 4;
            h.fec_m = 2;
            let frame = c.encode_frame(&h, b"payload");
            let back = c.read_header(&frame).unwrap();
            assert_eq!(back, h, "header must survive the seam");
            assert_eq!(&frame[c.body_offset(&frame)..], b"payload");
            assert_eq!(c.encode_header(&back), c.encode_header(&h));
            assert_eq!(c.peek_session_id(&frame), Some(sid));
        }
    }

    #[test]
    fn box_clone_is_a_deep_enough_copy() {
        let a: Box<dyn FrameCodec> = Box::new(V1FixedCodec::new());
        let b = a.box_clone();
        assert_eq!(a.name(), b.name());
        assert_eq!(a.wire_id(), b.wire_id());
    }

    #[test]
    fn the_codec_agnostic_peek_agrees_with_the_single_codec_peek() {
        let c = V1FixedCodec::new();
        let buf = c.encode_frame(&sample(), b"body");
        assert_eq!(peek_any_session_id(&buf), c.peek_session_id(&buf));
        assert!(any_codec_claims(&buf));
    }

    #[test]
    fn the_codec_agnostic_peek_rejects_noise() {
        assert_eq!(peek_any_session_id(&[]), None);
        assert_eq!(
            peek_any_session_id(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            None
        );
        assert!(!any_codec_claims(&[0xFF; 32]));
    }

    /// The routing peek must be unambiguous: a frame one codec produced must
    /// not be claimed by a *different* one, or the server would route it to the
    /// wrong session. Pinned by requiring distinct discriminators.
    #[test]
    fn every_codec_has_a_distinct_wire_discriminator() {
        let mut seen = std::collections::HashMap::new();
        for make in ALL_CODECS {
            let c = make();
            let probe = c.encode_frame(&sample(), b"");
            // The first two bytes are each codec's discriminator.
            let key = (&probe[..c.route_prefix_len().min(2)]).to_vec();
            if let Some(prev) = seen.insert(key.clone(), c.name()) {
                panic!(
                    "{} and {} share a wire prefix {key:?}; a routing peek could \
                     not tell them apart",
                    prev,
                    c.name()
                );
            }
            // And a frame from one codec must not be claimed by another.
            for other in ALL_CODECS {
                let o = other();
                if o.name() == c.name() {
                    continue;
                }
                assert!(
                    !o.looks_like_frame(&probe)
                        || o.peek_session_id(&probe) == c.peek_session_id(&probe),
                    "{} claims a frame produced by {}",
                    o.name(),
                    c.name()
                );
            }
        }
    }

    #[test]
    fn registry_resolves_the_default_by_name_and_id() {
        let by_name = build_frame_codec("v1-fixed").unwrap();
        assert_eq!(by_name.name(), "v1-fixed");
        assert_eq!(by_name.wire_id(), FRAME_V1_FIXED);
        let by_id = frame_codec_by_id(FRAME_V1_FIXED).unwrap();
        assert_eq!(by_id.name(), "v1-fixed");
    }

    #[test]
    fn registry_rejects_an_unknown_name_and_id() {
        assert!(matches!(
            build_frame_codec("tlv"),
            Err(FrameError::UnknownCodec(_))
        ));
        assert!(matches!(
            frame_codec_by_id(200),
            Err(FrameError::UnknownCodecId(200))
        ));
    }
}
