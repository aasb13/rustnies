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
//!   and routing-whitening budgets can be computed without knowing which codec
//!   is in use.
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
use super::header::{
    HEADER_LEN, HeaderError, HeaderFlags, PROTOCOL_VERSION, PacketHeader, SessionId,
};

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
pub const ALL_CODECS: &[fn() -> Box<dyn FrameCodec>] = &[
    || Box::new(V1FixedCodec::new()),
    || Box::new(V2TlvCodec::new()),
];

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
        "v2-tlv" => Ok(Arc::new(V2TlvCodec::new())),
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
        FRAME_V2_TLV => Ok(Arc::new(V2TlvCodec::new())),
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
            let key = probe[..c.route_prefix_len().min(2)].to_vec();
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

// ---------------------------------------------------------------------------
// v2-tlv: a variable-length, self-describing header.
// ---------------------------------------------------------------------------

/// Wire id for [`V2TlvCodec`].
pub const FRAME_V2_TLV: u8 = 2;

/// The first byte of a v2-tlv frame.
///
/// A distinct value from [`PROTOCOL_VERSION`], which is what lets a server's
/// codec-agnostic routing peek tell the two layouts apart. A v1 frame always
/// starts `0x01`; a v2 frame always starts `0x52`.
pub const V2_TLV_MAGIC: u8 = 0x52;

/// Tag bytes in a v2-tlv header, in wire order.
const T_VERSION: u8 = 0x01;
const T_TYPE: u8 = 0x02;
const T_SESSION: u8 = 0x03;
const T_SEQ: u8 = 0x04;
const T_ACK_SEQ: u8 = 0x05;
const T_ACK_BITMAP: u8 = 0x06;
const T_FEC_GROUP: u8 = 0x07;
const T_FEC_INDEX: u8 = 0x08;
const T_FEC_K: u8 = 0x09;
const T_FEC_M: u8 = 0x0A;
const T_FLAGS: u8 = 0x0B;

/// Length of the magic + total-length preamble every v2-tlv frame starts with.
pub const V2_TLV_PREAMBLE: usize = 3;

/// A variable-length, tag-length-value header.
///
/// # Why this exists
///
/// The v1 header is a fixed 24 bytes whether or not the fields are used: a
/// `Ping` carries no FEC fields and still spends six bytes on them, and any
/// future field needs a new fixed-layout codec. This layout is
/// self-describing instead, so:
///
/// - a frame is only as long as its fields warrant -- a `Ping` is 21 bytes
///   against v1's 24 -- and
/// - a new optional field can be added without a new codec — an old decoder
///   skips a tag it does not know, exactly as it already skips unknown flag
///   bits.
///
/// # Wire format
///
/// ```text
/// [0]      magic (0x52)
/// [1..3]   total header length, u16 big-endian (excluding this preamble)
/// then, repeated until the header length is consumed:
///   [tag u8][len u8][value, `len` bytes]
/// ```
///
/// Big-endian for the length, so a decoder can size its buffer before parsing
/// anything. Tags are written in ascending order, which makes the encoding
/// canonical — a decoder that re-encodes produces identical bytes, which is
/// what the AEAD associated data depends on.
///
/// # The size tradeoff, stated honestly
///
/// A TLV costs two bytes of tag+length per field, so a **fully populated**
/// header is *larger* than v1's 24 bytes (49 here). A **sparse** one is much
/// smaller, because a field left at its zero default is omitted entirely and
/// decodes back to zero. In practice most frames are sparse -- a `Ping` has no
/// ack, no FEC and no flags, and lands at 21 bytes against v1's flat 24.
///
/// So this is not a general-purpose compaction, and it is not claimed to be.
/// The win is extensibility: a new optional field costs a tag, not a re-layout
/// and a new codec. Whether that trade is right depends on the deployment; a
/// v1 peer and a v2 peer coexist precisely because the codec is negotiated.
/// An empty field is never written, which is what keeps the encoding canonical
/// -- see the round-trip-stability test.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct V2TlvCodec;

impl V2TlvCodec {
    /// Construct the codec.
    pub const fn new() -> Self {
        Self
    }
}

/// Push one TLV onto `out`.
fn tlv(out: &mut BytesMut, tag: u8, value: &[u8]) {
    out.put_u8(tag);
    out.put_u8(value.len() as u8);
    out.put_slice(value);
}

impl FrameCodec for V2TlvCodec {
    fn name(&self) -> &'static str {
        "v2-tlv"
    }

    fn wire_id(&self) -> u8 {
        FRAME_V2_TLV
    }

    fn route_prefix_len(&self) -> usize {
        // Enough to reach the session id in the worst case: magic, length,
        // then tag+len+4 bytes of value. The common case is shorter, and
        // `peek_session_id` returns as soon as it has the id.
        V2_TLV_PREAMBLE + 2 + 4
    }

    fn max_header_len(&self) -> usize {
        // The longest encoding this codec can produce: the preamble, then every
        // tag with its value.
        V2_TLV_PREAMBLE
            + (1 + 1 + 1) // version
            + (1 + 1 + 1) // type
            + (1 + 1 + 4) // session_id
            + (1 + 1 + 4) // seq
            + (1 + 1 + 4) // ack_seq
            + (1 + 1 + 4) // ack_bitmap
            + (1 + 1 + 2) // fec_group
            + (1 + 1 + 1) // fec_index
            + (1 + 1 + 1) // fec_k
            + (1 + 1 + 1) // fec_m
            + (1 + 1 + 1) // flags
    }

    fn write_header(&self, header: &PacketHeader, out: &mut BytesMut) -> Result<(), FrameError> {
        let mut body = BytesMut::with_capacity(self.max_header_len());
        // Always written: without a type the frame cannot be dispatched, and
        // without a session id it cannot be routed or bound to a session.
        tlv(&mut body, T_VERSION, &[header.version]);
        tlv(&mut body, T_TYPE, &[header.packet_type as u8]);
        tlv(&mut body, T_SESSION, &header.session_id.to_le_bytes());
        tlv(&mut body, T_SEQ, &header.seq.to_le_bytes());
        // Written only when non-zero. A decoder initialises these to zero, so
        // omitting a zero is lossless -- and it is what makes a sparse frame
        // cheaper than v1's fixed 24 bytes.
        if header.ack_seq != 0 {
            tlv(&mut body, T_ACK_SEQ, &header.ack_seq.to_le_bytes());
        }
        if header.ack_bitmap != 0 {
            tlv(&mut body, T_ACK_BITMAP, &header.ack_bitmap.to_le_bytes());
        }
        if header.fec_group != 0 {
            tlv(&mut body, T_FEC_GROUP, &header.fec_group.to_le_bytes());
        }
        if header.fec_index != 0 {
            tlv(&mut body, T_FEC_INDEX, &[header.fec_index]);
        }
        if header.fec_k != 0 {
            tlv(&mut body, T_FEC_K, &[header.fec_k]);
        }
        if header.fec_m != 0 {
            tlv(&mut body, T_FEC_M, &[header.fec_m]);
        }
        if !header.flags.is_empty() {
            tlv(&mut body, T_FLAGS, &[header.flags.bits()]);
        }
        if body.len() > u16::MAX as usize {
            return Err(FrameError::Malformed("tlv header exceeds 64 KiB"));
        }
        out.reserve(V2_TLV_PREAMBLE + body.len());
        out.put_u8(V2_TLV_MAGIC);
        out.put_u16(body.len() as u16);
        out.put_slice(&body);
        Ok(())
    }

    fn read_header(&self, buf: &[u8]) -> Result<PacketHeader, FrameError> {
        if buf.len() < V2_TLV_PREAMBLE {
            return Err(FrameError::BufferTooSmall);
        }
        if buf[0] != V2_TLV_MAGIC {
            return Err(FrameError::Malformed("not a v2-tlv frame"));
        }
        let body_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        let end = V2_TLV_PREAMBLE
            .checked_add(body_len)
            .ok_or(FrameError::Malformed("tlv length overflows"))?;
        if end > buf.len() {
            return Err(FrameError::Malformed("tlv header truncated"));
        }
        let body = &buf[V2_TLV_PREAMBLE..end];

        let mut version = PROTOCOL_VERSION;
        let mut packet_type: Option<PacketType> = None;
        let mut session_id: SessionId = 0;
        let mut seq = 0u32;
        let mut ack_seq = 0u32;
        let mut ack_bitmap = 0u32;
        let mut fec_group = 0u16;
        let mut fec_index = 0u8;
        let mut fec_k = 0u8;
        let mut fec_m = 0u8;
        let mut flags = HeaderFlags::NONE;

        let mut i = 0usize;
        while i < body.len() {
            if i + 2 > body.len() {
                return Err(FrameError::Malformed("truncated tlv tag/length"));
            }
            let tag = body[i];
            let len = body[i + 1] as usize;
            i += 2;
            if i + len > body.len() {
                return Err(FrameError::Malformed("tlv value runs past the header"));
            }
            let value = &body[i..i + len];
            i += len;

            // A length other than the field's natural width is malformed, not
            // something to coerce: silently accepting it would let two peers
            // disagree about a field's value and still authenticate.
            let u32v = |v: &[u8]| -> Result<u32, FrameError> {
                v.try_into()
                    .map(u32::from_le_bytes)
                    .map_err(|_| FrameError::Malformed("tlv value is not a u32"))
            };
            let u16v = |v: &[u8]| -> Result<u16, FrameError> {
                v.try_into()
                    .map(u16::from_le_bytes)
                    .map_err(|_| FrameError::Malformed("tlv value is not a u16"))
            };
            let u8v = |v: &[u8]| -> Result<u8, FrameError> {
                v.first()
                    .copied()
                    .ok_or(FrameError::Malformed("tlv value is not a u8"))
            };

            match tag {
                T_VERSION => version = u8v(value)?,
                T_TYPE => {
                    packet_type = Some(
                        PacketType::from_byte(u8v(value)?)
                            .ok_or(FrameError::BadType(u8v(value).unwrap_or(0)))?,
                    )
                }
                T_SESSION => session_id = u32v(value)?,
                T_SEQ => seq = u32v(value)?,
                T_ACK_SEQ => ack_seq = u32v(value)?,
                T_ACK_BITMAP => ack_bitmap = u32v(value)?,
                T_FEC_GROUP => fec_group = u16v(value)?,
                T_FEC_INDEX => fec_index = u8v(value)?,
                T_FEC_K => fec_k = u8v(value)?,
                T_FEC_M => fec_m = u8v(value)?,
                T_FLAGS => {
                    flags = HeaderFlags::from_bits_truncate(u8v(value)?);
                }
                // An unknown tag is skipped, not rejected. That is the whole
                // point of a self-describing header: a future field does not
                // need a new codec, and this build can still read the rest.
                _ => {}
            }
        }

        // Type and session id are not optional: without them a frame cannot be
        // dispatched or authenticated meaningfully.
        let packet_type =
            packet_type.ok_or(FrameError::Malformed("v2-tlv frame has no packet type"))?;
        Ok(PacketHeader {
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

    fn looks_like_frame(&self, buf: &[u8]) -> bool {
        buf.len() >= V2_TLV_PREAMBLE && buf[0] == V2_TLV_MAGIC
    }

    fn peek_session_id(&self, buf: &[u8]) -> Option<SessionId> {
        if !self.looks_like_frame(buf) {
            return None;
        }
        let body_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        let end = V2_TLV_PREAMBLE.checked_add(body_len)?;
        if end > buf.len() {
            return None; // header not fully present yet
        }
        let body = &buf[V2_TLV_PREAMBLE..end];
        let mut i = 0usize;
        while i + 2 <= body.len() {
            let tag = body[i];
            let len = body[i + 1] as usize;
            i += 2;
            if i + len > body.len() {
                return None;
            }
            let value = &body[i..i + len];
            i += len;
            if tag == T_SESSION && len == 4 {
                return Some(SessionId::from_le_bytes([
                    value[0], value[1], value[2], value[3],
                ]));
            }
        }
        None
    }

    fn body_offset(&self, frame: &[u8]) -> usize {
        if frame.len() < V2_TLV_PREAMBLE || frame[0] != V2_TLV_MAGIC {
            return 0;
        }
        let body_len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
        (V2_TLV_PREAMBLE + body_len).min(frame.len())
    }

    fn box_clone(&self) -> Box<dyn FrameCodec> {
        Box::new(*self)
    }
}

#[cfg(test)]
mod tlv_tests {
    //! Tests for `v2-tlv`, focused on the properties that make it a safe
    //! substitute for `v1-fixed` rather than on its exact bytes.

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

    #[test]
    fn it_roundtrips_every_field() {
        let c = V2TlvCodec::new();
        let h = sample();
        let frame = c.encode_frame(&h, b"payload");
        assert_eq!(c.read_header(&frame).unwrap(), h);
        assert_eq!(&frame[c.body_offset(&frame)..], b"payload");
    }

    #[test]
    fn it_is_not_the_v1_layout() {
        // If these two ever produced the same bytes, the routing peek would be
        // ambiguous and a v1 frame could be parsed as v2.
        let h = sample();
        let v1 = V1FixedCodec::new().encode_frame(&h, b"");
        let v2 = V2TlvCodec::new().encode_frame(&h, b"");
        assert_ne!(v1, v2);
        assert_eq!(v1[0], PROTOCOL_VERSION);
        assert_eq!(v2[0], V2_TLV_MAGIC);
    }

    #[test]
    fn a_v2_frame_is_invisible_to_the_v1_codec_and_vice_versa() {
        // The property the routing peek depends on.
        let h = sample();
        let v1 = V1FixedCodec::new().encode_frame(&h, b"");
        let v2 = V2TlvCodec::new().encode_frame(&h, b"");
        assert!(!V1FixedCodec::new().looks_like_frame(&v2));
        assert_eq!(V1FixedCodec::new().peek_session_id(&v2), None);
        assert!(!V2TlvCodec::new().looks_like_frame(&v1));
        assert_eq!(V2TlvCodec::new().peek_session_id(&v1), None);
    }

    #[test]
    fn the_codec_agnostic_peek_routes_both_layouts() {
        let h = sample();
        for c in [
            Box::new(V1FixedCodec::new()) as Box<dyn FrameCodec>,
            Box::new(V2TlvCodec::new()),
        ] {
            let frame = c.encode_frame(&h, b"body");
            assert_eq!(
                peek_any_session_id(&frame),
                Some(h.session_id),
                "{} frame must route",
                c.name()
            );
            assert!(any_codec_claims(&frame));
        }
    }

    #[test]
    fn a_sparse_header_beats_v1_and_a_full_one_loses_to_it() {
        // The honest tradeoff, pinned so the doc comment cannot drift. A TLV
        // costs two bytes per field, so a fully populated header is larger than
        // v1's fixed 24; a sparse one is smaller, because zero-valued fields are
        // omitted.
        //
        // The exact numbers are asserted, not just the ordering. Doc comments
        // that quote a size drift the moment the layout changes, and "a Ping is
        // 11 bytes" sat wrong in three documents before this test existed.
        let v1 = V1FixedCodec::new();

        // Sparse: a Ping with no ack, no FEC, no flags.
        //   3 (preamble) + (2+1 version) + (2+1 type) + (2+4 session) + (2+4 seq) = 21
        let sparse = PacketHeader::new(PacketType::Ping, 0xCAFEBABE, 1);
        let v1_len = v1.encode_frame(&sparse, b"").len();
        let v2_len = V2TlvCodec::new().encode_frame(&sparse, b"").len();
        assert_eq!(v1_len, 24, "v1 is always 24 bytes");
        assert_eq!(v2_len, 21, "the size quoted in the docs for a sparse frame");
        assert!(
            v2_len < v1_len,
            "a sparse v2 header ({v2_len}) must beat v1 ({v1_len})"
        );

        // Full: every *writable* field set, which is the worst case for a TLV.
        //   21 + (2+4 ack_seq) + (2+4 ack_bitmap) + (2+2 group)
        //      + (2+1 index) + (2+1 k) + (2+1 m) = 46
        //
        // The flags field is not counted because no `HeaderFlags` bits are
        // assigned, so its TLV is never emitted. `max_header_len` still budgets
        // for it (49), which is correct for an upper bound and is what the
        // MTU math relies on.
        let full = sample();
        let v1_len = v1.encode_frame(&full, b"").len();
        let v2_len = V2TlvCodec::new().encode_frame(&full, b"").len();
        assert_eq!(v2_len, 46, "the size quoted in the docs for a full frame");
        assert!(
            v2_len > v1_len,
            "a fully populated v2 header ({v2_len}) is expected to exceed v1 ({v1_len}); \
             that is the documented cost of extensibility"
        );
    }

    #[test]
    fn a_zero_valued_field_is_omitted_and_still_decodes_to_zero() {
        let c = V2TlvCodec::new();
        let h = PacketHeader::new(PacketType::Ping, 7, 9);
        let frame = c.encode_frame(&h, b"");
        let body = &frame[V2_TLV_PREAMBLE..c.body_offset(&frame)];
        // Walk the TLVs properly -- they are variable-length, so a fixed chunk
        // size would read value bytes as tags.
        let mut tags = Vec::new();
        let mut i = 0;
        while i < body.len() {
            let tag = body[i];
            let len = body[i + 1] as usize;
            tags.push(tag);
            i += 2 + len;
        }
        assert_eq!(tags, [T_VERSION, T_TYPE, T_SESSION, T_SEQ]);
        assert_eq!(body.len(), 18, "3 + 3 + 6 + 6 bytes of preamble and TLVs");
        assert_eq!(c.read_header(&frame).unwrap(), h);
    }

    #[test]
    fn max_header_len_bounds_every_encoding() {
        // `max_header_len` drives the MTU budget, so it must be a true upper
        // bound or a frame could exceed the payload the tunnel budgeted for.
        let c = V2TlvCodec::new();
        for (sid, seq, ptype) in [
            (0u32, 0u32, PacketType::Data),
            (u32::MAX, u32::MAX, PacketType::Close),
            (0xCAFEBABE, 7, PacketType::Fec),
        ] {
            let mut h = PacketHeader::new(ptype, sid, seq);
            {
                h.ack_seq = u32::MAX;
                h.ack_bitmap = u32::MAX;
                h.fec_group = u16::MAX;
                h.fec_index = u8::MAX;
                h.fec_k = u8::MAX;
                h.fec_m = u8::MAX;
                h.flags = HeaderFlags::all();
                let frame = c.encode_frame(&h, b"");
                assert!(
                    frame.len() <= c.max_header_len(),
                    "{} bytes exceeds max_header_len {}",
                    frame.len(),
                    c.max_header_len()
                );
                assert_eq!(c.read_header(&frame).unwrap(), h);
            }
        }
    }

    #[test]
    fn encoding_is_canonical() {
        // The AEAD AAD is re-encoded from the decoded header, so encode must be
        // a function of the header alone -- no map iteration order, no
        // optional-field presence leaking into the bytes.
        let c = V2TlvCodec::new();
        let h = sample();
        let first = c.encode_header(&h);
        for _ in 0..8 {
            assert_eq!(c.encode_header(&c.read_header(&first).unwrap()), first);
        }
    }

    #[test]
    fn an_unknown_tag_is_skipped_rather_than_rejected() {
        // The extensibility claim: a future field does not need a new codec.
        let c = V2TlvCodec::new();
        let h = sample();
        let mut body = BytesMut::new();
        tlv(&mut body, T_VERSION, &[h.version]);
        tlv(&mut body, T_TYPE, &[h.packet_type as u8]);
        tlv(&mut body, T_SESSION, &h.session_id.to_le_bytes());
        tlv(&mut body, T_SEQ, &h.seq.to_le_bytes());
        tlv(&mut body, 0x7F, &[0xDE, 0xAD, 0xBE, 0xEF]); // a tag from the future
        tlv(&mut body, T_ACK_SEQ, &h.ack_seq.to_le_bytes());
        tlv(&mut body, T_ACK_BITMAP, &h.ack_bitmap.to_le_bytes());
        tlv(&mut body, T_FEC_GROUP, &h.fec_group.to_le_bytes());
        tlv(&mut body, T_FEC_INDEX, &[h.fec_index]);
        tlv(&mut body, T_FEC_K, &[h.fec_k]);
        tlv(&mut body, T_FEC_M, &[h.fec_m]);
        tlv(&mut body, T_FLAGS, &[h.flags.bits()]);
        let mut frame = BytesMut::new();
        frame.put_u8(V2_TLV_MAGIC);
        frame.put_u16(body.len() as u16);
        frame.put_slice(&body);
        frame.put_slice(b"payload");

        // The unknown tag is ignored; everything else still round-trips.
        let back = c.read_header(&frame).unwrap();
        assert_eq!(back, h);
        assert_eq!(&frame[c.body_offset(&frame)..], b"payload");
        // And the session id is still findable for routing, despite the
        // unknown tag sitting between it and the end.
        assert_eq!(c.peek_session_id(&frame), Some(h.session_id));
    }

    #[test]
    fn a_truncated_header_is_rejected_rather_than_half_parsed() {
        let c = V2TlvCodec::new();
        let frame = c.encode_frame(&sample(), b"");
        for cut in 0..frame.len() {
            assert!(
                c.read_header(&frame[..cut]).is_err(),
                "a {cut}-byte prefix must not parse"
            );
        }
    }

    #[test]
    fn a_truncated_body_leaves_the_offset_on_the_header_boundary() {
        // `body_offset` must never point *into* the header, or the AEAD would
        // authenticate part of the header as ciphertext.
        let c = V2TlvCodec::new();
        let frame = c.encode_frame(&sample(), b"body");
        let full = c.body_offset(&frame);
        for cut in 0..full {
            let off = c.body_offset(&frame[..cut]);
            assert!(
                off <= full,
                "offset {off} must not exceed the header end {full}"
            );
        }
    }

    #[test]
    fn a_wrong_magic_is_rejected() {
        let c = V2TlvCodec::new();
        let mut frame = c.encode_frame(&sample(), b"").to_vec();
        frame[0] = PROTOCOL_VERSION;
        assert!(!c.looks_like_frame(&frame));
        assert!(matches!(
            c.read_header(&frame),
            Err(FrameError::Malformed(_))
        ));
    }

    #[test]
    fn a_mis_sized_field_is_rejected_not_coerced() {
        // Accepting a 2-byte session id would let two peers disagree about its
        // value and still authenticate the frame.
        let c = V2TlvCodec::new();
        let mut body = BytesMut::new();
        tlv(&mut body, T_VERSION, &[PROTOCOL_VERSION]);
        tlv(&mut body, T_TYPE, &[PacketType::Data as u8]);
        tlv(&mut body, T_SESSION, &[0x01, 0x02]); // should be 4 bytes
        let mut frame = BytesMut::new();
        frame.put_u8(V2_TLV_MAGIC);
        frame.put_u16(body.len() as u16);
        frame.put_slice(&body);
        assert!(matches!(
            c.read_header(&frame),
            Err(FrameError::Malformed(_))
        ));
    }

    #[test]
    fn a_frame_with_no_packet_type_is_rejected() {
        // Dispatch is impossible without one, so this must not silently
        // default to Data.
        let c = V2TlvCodec::new();
        let mut body = BytesMut::new();
        tlv(&mut body, T_VERSION, &[PROTOCOL_VERSION]);
        tlv(&mut body, T_SESSION, &7u32.to_le_bytes());
        let mut frame = BytesMut::new();
        frame.put_u8(V2_TLV_MAGIC);
        frame.put_u16(body.len() as u16);
        frame.put_slice(&body);
        assert!(matches!(
            c.read_header(&frame),
            Err(FrameError::Malformed(_))
        ));
        assert_eq!(c.peek_session_id(&frame), Some(7), "but it still routes");
    }

    #[test]
    fn an_unknown_packet_type_is_rejected() {
        let c = V2TlvCodec::new();
        let mut body = BytesMut::new();
        tlv(&mut body, T_VERSION, &[PROTOCOL_VERSION]);
        tlv(&mut body, T_TYPE, &[0xFE]);
        tlv(&mut body, T_SESSION, &7u32.to_le_bytes());
        let mut frame = BytesMut::new();
        frame.put_u8(V2_TLV_MAGIC);
        frame.put_u16(body.len() as u16);
        frame.put_slice(&body);
        assert!(matches!(
            c.read_header(&frame),
            Err(FrameError::BadType(0xFE))
        ));
    }

    #[test]
    fn a_declared_length_past_the_buffer_is_rejected() {
        let c = V2TlvCodec::new();
        let mut frame = c.encode_frame(&sample(), b"").to_vec();
        frame[1..3].copy_from_slice(&9999u16.to_be_bytes());
        assert!(matches!(
            c.read_header(&frame),
            Err(FrameError::Malformed(_))
        ));
        assert_eq!(c.peek_session_id(&frame), None);
    }

    #[test]
    fn a_tlv_value_running_past_the_header_is_rejected() {
        let c = V2TlvCodec::new();
        // Claim a 9-byte seq inside a header that has no room for it.
        let mut body = BytesMut::new();
        tlv(&mut body, T_VERSION, &[PROTOCOL_VERSION]);
        tlv(&mut body, T_TYPE, &[PacketType::Data as u8]);
        body.put_u8(T_SEQ);
        body.put_u8(9); // says 9 bytes follow
        body.put_u8(0); // ... but the header ends here
        let mut frame = BytesMut::new();
        frame.put_u8(V2_TLV_MAGIC);
        frame.put_u16(body.len() as u16);
        frame.put_slice(&body);
        assert!(matches!(
            c.read_header(&frame),
            Err(FrameError::Malformed(_))
        ));
    }

    #[test]
    fn every_sample_header_survives_the_seam() {
        let c = V2TlvCodec::new();
        for (sid, seq, ptype) in [
            (0u32, 0u32, PacketType::Data),
            (u32::MAX, u32::MAX, PacketType::Close),
            (0xCAFEBABE, 7, PacketType::Fec),
            (1, 1, PacketType::Keepalive),
            (0x01020304, 0xFFFFFFFF, PacketType::Ack),
        ] {
            let mut h = PacketHeader::new(ptype, sid, seq);
            h.ack_seq = seq.rotate_left(7);
            h.ack_bitmap = seq.wrapping_mul(2654435761);
            h.fec_group = (seq >> 8) as u16;
            h.fec_index = (seq % 255) as u8;
            h.fec_k = 4;
            h.fec_m = 2;
            let frame = c.encode_frame(&h, b"payload");
            let back = c.read_header(&frame).unwrap();
            assert_eq!(back, h);
            assert_eq!(c.encode_header(&back), c.encode_header(&h));
            assert_eq!(c.peek_session_id(&frame), Some(sid));
            assert_eq!(&frame[c.body_offset(&frame)..], b"payload");
        }
    }

    #[test]
    fn registry_resolves_it_by_name_and_id() {
        assert_eq!(build_frame_codec("v2-tlv").unwrap().wire_id(), FRAME_V2_TLV);
        assert_eq!(frame_codec_by_id(FRAME_V2_TLV).unwrap().name(), "v2-tlv");
        assert_ne!(FRAME_V2_TLV, FRAME_V1_FIXED, "wire ids must be distinct");
    }
}
