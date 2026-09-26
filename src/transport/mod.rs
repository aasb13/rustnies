//! The swappable Transport abstraction.
//!
//! The raw packet (header || AEAD ciphertext) is never sent directly on UDP.
//! It passes through a [`Transport`] which `wrap`s it into the bytes that go
//! on the wire and `unwrap`s incoming bytes back into the plaintext frame.
//!
//! The default [`PlainTransport`] is a no-op identity transform. Stackable
//! obfuscation transforms (padding, timing, header whitening) are NOT
//! transports — they sit on top via the [`crate::obfuscation`] `ObfuscationLayer`
//! stack (off by default). This trait is reserved for envelope-level / full
//! protocol mimicry (e.g. TLS-fronting), still future work, which slots in
//! without touching the protocol, crypto, FEC or TUN layers.
//!
//! Transport implementations are *stateless transforms on individual
//! messages* by design; any stateful shaping (reordering, coalescing) lives in
//! a higher layer. This keeps the trait trivial to implement and reason about.
//!
//! Note the layering: this trait shapes the bytes of one protocol message, while
//! the [`crate::carrier`] seam below it decides what a message *is* — a
//! datagram, or a length-delimited frame on a stream. A transport never sees
//! the carrier, and the carrier never sees the transport's shape.

/// The error a transport may return. Wrapping is expected to be infallible for
/// well-formed inputs, but unwrapping may fail if the incoming bytes don't
/// match the expected shape (e.g. an obfuscation transform rejecting foreign
/// traffic).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    #[error("transport unwrap rejected the input")]
    UnwrapFailed,
    #[error("transport output was too large ({0} bytes)")]
    TooLarge(usize),
}

/// A swappable packet wrap/unwrap step.
///
/// `wrap` converts a *plaintext frame* (`header || ciphertext`) into the
/// bytes to send on the UDP socket. `unwrap` is the inverse.
///
/// Implementations must be cheap, allocation-light, and self-contained — they
/// may not touch the socket, TUN, or session state.
pub trait Transport: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    /// `frame` is the plaintext packet produced by the negotiated
    /// [`crate::protocol::frame::FrameCodec`]. Returns the bytes to transmit as
    /// one protocol message.
    fn wrap(&self, frame: &[u8]) -> Vec<u8>;

    /// `message` is the raw bytes of one whole message from the
    /// [`crate::carrier::Carrier`]. Returns the plaintext frame for the codec to
    /// split.
    fn unwrap(&self, message: &[u8]) -> Result<Vec<u8>, TransportError>;

    /// Derive per-session keying material from the handshake hash. Called once
    /// per session, after the handshake completes and before the first
    /// steady-state frame, mirroring
    /// [`crate::obfuscation::ObfuscationLayer::init`]. A transport that needs
    /// session-derived keys (e.g. to mask a marker) overrides this; a stateless
    /// transport leaves the default no-op in place.
    ///
    /// Note this is **not** called for the handshake transport: it wraps
    /// message 1 and message 2, which must be encoded before any session hash
    /// exists. Handshake transports are therefore required to be unkeyed.
    fn init(&self, _session_seed: &[u8; 32]) {}

    /// Boxed clone so a transport can be held behind a trait object and
    /// duplicated across tasks.
    fn boxed_clone(&self) -> Box<dyn Transport>;
}

/// Identity transport: writes the frame verbatim. This is the phase-1 default
/// and the reference for any future transport.
#[derive(Debug, Default, Clone)]
pub struct PlainTransport;

impl Transport for PlainTransport {
    fn name(&self) -> &'static str {
        "plain"
    }

    fn wrap(&self, frame: &[u8]) -> Vec<u8> {
        frame.to_vec()
    }

    fn unwrap(&self, message: &[u8]) -> Result<Vec<u8>, TransportError> {
        Ok(message.to_vec())
    }

    fn boxed_clone(&self) -> Box<dyn Transport> {
        Box::new(self.clone())
    }
}

/// A transport that prepends a small framing tag. Included as a second impl to
/// prove the abstraction is real (and as a skeleton for obfuscation work).
#[derive(Debug, Default, Clone)]
pub struct TaggedTransport {
    /// A fixed 2-byte tag placed before every wrapped message.
    pub tag: [u8; 2],
}

impl Transport for TaggedTransport {
    fn name(&self) -> &'static str {
        "tagged"
    }

    fn wrap(&self, frame: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.tag.len() + frame.len());
        out.extend_from_slice(&self.tag);
        out.extend_from_slice(frame);
        out
    }

    fn unwrap(&self, message: &[u8]) -> Result<Vec<u8>, TransportError> {
        if message.len() < self.tag.len() {
            return Err(TransportError::UnwrapFailed);
        }
        if &message[..self.tag.len()] != &self.tag {
            return Err(TransportError::UnwrapFailed);
        }
        Ok(message[self.tag.len()..].to_vec())
    }

    fn boxed_clone(&self) -> Box<dyn Transport> {
        Box::new(self.clone())
    }
}

/// Convenience: produce the default plain transport.
pub fn default_transport() -> Box<dyn Transport> {
    Box::new(PlainTransport)
}

// ---------------------------------------------------------------------------
// Config-driven selection
// ---------------------------------------------------------------------------
//
// A transport is chosen by name from the `[transport]` config section, using the
// same name-to-type registry shape as `obfuscation::build_stack`: a plain
// `match` over `&str`, a warn-and-skip for an unknown name (a bad transport
// name degrades to plain rather than preventing the tunnel from coming up),
// and a `boxed_clone` so each session gets its own copy.
//
// Unlike `[obfuscation]`, `[transport]` has two entries because the handshake
// and steady-state messages can legitimately use different envelopes:
//   * `handshake` wraps message 1 / message 2, which are encoded *before* any
//     session key material exists, so it is config-only and must match on both
//     peers. There is nothing to negotiate it against.
//   * `data` wraps steady-state frames and *is* negotiated, because by then the
//     session exists and the server's pick can be echoed in message 2.

/// Default transport name, also the fallback for an empty config value.
pub const DEFAULT_TRANSPORT: &str = "plain";

/// The `data` preference entry that means "reuse the handshake transport".
///
/// With this selected (and no other `data` entry) there is nothing to
/// negotiate: both peers already agree because the handshake envelope is
/// config-pinned. See [`crate::protocol::profile`].
pub const TRANSPORT_SAME_AS_HANDSHAKE: &str = "same-as-handshake";

/// Resolve a transport config name to a boxed implementation.
///
/// `tag` supplies the framing marker for `"tagged"`; it is ignored by every
/// other implementation. An unknown name is logged at `warn` and falls back to
/// [`PlainTransport`], so a typo degrades the envelope rather than breaking
/// connectivity — the same warn-and-skip policy the obfuscation registry uses.
pub fn build_transport(name: &str, tag: [u8; 2]) -> Box<dyn Transport> {
    match name.trim() {
        "" | DEFAULT_TRANSPORT => Box::new(PlainTransport),
        "tagged" => Box::new(TaggedTransport { tag }),
        other => {
            tracing::warn!(
                transport = other,
                "unknown transport name in [transport]; falling back to plain"
            );
            Box::new(PlainTransport)
        }
    }
}

/// Build a transport from config and seed it with the per-session hash, for a
/// steady-state (post-handshake) envelope.
pub fn build_session_transport(
    name: &str,
    tag: [u8; 2],
    session_seed: &[u8; 32],
) -> Box<dyn Transport> {
    let t = build_transport(name, tag);
    t.init(session_seed);
    t
}

/// Marker bytes used by [`TaggedTransport`] when `[transport] tag_hex` is unset.
pub const DEFAULT_TAG: [u8; 2] = [0x52, 0x4E]; // "RN"

/// Transport ids on the negotiation wire. See [`crate::protocol::profile`].
pub const TRANSPORT_PLAIN: u8 = 1;
pub const TRANSPORT_TAGGED: u8 = 2;

/// Map a transport config name to its negotiation wire id. `None` means this
/// build does not implement it. An empty name resolves to plain.
pub fn transport_id(name: &str) -> Option<u8> {
    match name.trim() {
        "" | DEFAULT_TRANSPORT => Some(TRANSPORT_PLAIN),
        "tagged" => Some(TRANSPORT_TAGGED),
        _ => None,
    }
}

/// The config name for a negotiation wire id, or `None` if unimplemented.
pub fn transport_name(id: u8) -> Option<&'static str> {
    match id {
        TRANSPORT_PLAIN => Some(DEFAULT_TRANSPORT),
        TRANSPORT_TAGGED => Some("tagged"),
        _ => None,
    }
}

/// Build a transport from a negotiation wire id, for the receiving side.
///
/// Returns `None` for an id this build does not implement, which the caller
/// turns into a `ProfileError::UnsupportedPart`. `tag` is only consumed by
/// `"tagged"`.
pub fn build_transport_id(id: u8, tag: [u8; 2]) -> Option<Box<dyn Transport>> {
    match id {
        TRANSPORT_PLAIN => Some(Box::new(PlainTransport)),
        TRANSPORT_TAGGED => Some(Box::new(TaggedTransport { tag })),
        _ => None,
    }
}

/// Parse an optional `tag_hex` config value into a 2-byte framing tag.
///
/// An absent or empty value yields [`DEFAULT_TAG`]. Anything else must be
/// exactly 4 hex digits. This is a **server-side** setting: the tag travels in
/// the server's [`crate::protocol::Selection`], so a client never has to
/// configure one. It does not affect the handshake transport, which is
/// config-pinned and uses [`DEFAULT_TAG`] on both peers.
pub fn parse_tag(hex_str: Option<&str>) -> Result<[u8; 2], TransportError> {
    let Some(s) = hex_str.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(DEFAULT_TAG);
    };
    let bytes = hex::decode(s).map_err(|_| TransportError::UnwrapFailed)?;
    bytes.try_into().map_err(|_| TransportError::UnwrapFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- PlainTransport ----

    #[test]
    fn plain_wrap_then_unwrap_is_identity() {
        let t = PlainTransport;
        let frame = b"hello wire world";
        let wire = t.wrap(frame);
        assert_eq!(wire, frame);
        assert_eq!(t.unwrap(&wire).unwrap(), frame);
    }

    #[test]
    fn plain_wrap_empty_frame() {
        let t = PlainTransport;
        let wire = t.wrap(b"");
        assert!(wire.is_empty());
        assert_eq!(t.unwrap(&wire).unwrap(), b"");
    }

    #[test]
    fn plain_wrap_preserves_exact_bytes() {
        let t = PlainTransport;
        let frame: Vec<u8> = (0..=255u8).collect();
        let wire = t.wrap(&frame);
        assert_eq!(wire, frame);
        assert_eq!(t.unwrap(&wire).unwrap(), frame);
    }

    #[test]
    fn plain_unwrap_accepts_arbitrary_garbage() {
        // Plain transport never rejects; it is the identity transform.
        let t = PlainTransport;
        let garbage = vec![0xFFu8; 100];
        assert_eq!(t.unwrap(&garbage).unwrap(), garbage);
    }

    // ---- TaggedTransport ----

    #[test]
    fn tagged_wrap_then_unwrap_roundtrips() {
        let t = TaggedTransport { tag: [0xAB, 0xCD] };
        let frame = b"payload";
        let wire = t.wrap(frame);
        assert_eq!(&wire[..2], &[0xAB, 0xCD]);
        assert_eq!(&wire[2..], frame);
        assert_eq!(t.unwrap(&wire).unwrap(), frame);
    }

    #[test]
    fn tagged_unwrap_rejects_short_input() {
        let t = TaggedTransport { tag: [0xAB, 0xCD] };
        // 1-byte input is shorter than the 2-byte tag.
        assert_eq!(t.unwrap(&[0xAB]).unwrap_err(), TransportError::UnwrapFailed);
        // Empty input.
        assert_eq!(t.unwrap(&[]).unwrap_err(), TransportError::UnwrapFailed);
    }

    #[test]
    fn tagged_unwrap_rejects_wrong_tag() {
        let t = TaggedTransport { tag: [0xAB, 0xCD] };
        let mut wire = t.wrap(b"data");
        wire[0] = 0x00; // wrong tag byte 0
        assert_eq!(t.unwrap(&wire).unwrap_err(), TransportError::UnwrapFailed);
        let mut wire = t.wrap(b"data");
        wire[1] = 0x00; // wrong tag byte 1
        assert_eq!(t.unwrap(&wire).unwrap_err(), TransportError::UnwrapFailed);
    }

    #[test]
    fn tagged_wrap_empty_frame_still_has_tag() {
        let t = TaggedTransport { tag: [0x01, 0x02] };
        let wire = t.wrap(b"");
        assert_eq!(wire, vec![0x01, 0x02]);
        assert_eq!(t.unwrap(&wire).unwrap(), b"");
    }

    #[test]
    fn tagged_unwrap_exact_tag_only_no_payload() {
        let t = TaggedTransport { tag: [0x01, 0x02] };
        // Just the tag, no payload: should unwrap to empty.
        assert_eq!(t.unwrap(&[0x01, 0x02]).unwrap(), b"");
    }

    // ---- Trait object / boxed_clone ----

    #[test]
    fn boxed_clone_preserves_behavior() {
        let t: Box<dyn Transport> = Box::new(TaggedTransport { tag: [0xCA, 0xFE] });
        let clone = t.boxed_clone();
        let frame = b"clone me";
        let wire = t.wrap(frame);
        assert_eq!(clone.unwrap(&wire).unwrap(), frame);
        assert_eq!(clone.name(), t.name());
    }

    #[test]
    fn boxed_clone_for_plain() {
        let t: Box<dyn Transport> = Box::new(PlainTransport);
        let clone = t.boxed_clone();
        let frame = b"plain";
        assert_eq!(clone.unwrap(&t.wrap(frame)).unwrap(), frame);
    }

    #[test]
    fn default_transport_is_plain() {
        let t = default_transport();
        assert_eq!(t.name(), "plain");
        let frame = b"default";
        assert_eq!(t.unwrap(&t.wrap(frame)).unwrap(), frame);
    }

    #[test]
    fn transport_names_are_distinct() {
        let plain = PlainTransport;
        let tagged = TaggedTransport { tag: [0, 0] };
        assert_ne!(plain.name(), tagged.name());
    }

    // ---- Config-driven selection ----

    #[test]
    fn build_transport_resolves_known_names() {
        assert_eq!(
            build_transport(DEFAULT_TRANSPORT, DEFAULT_TAG).name(),
            "plain"
        );
        assert_eq!(build_transport("", DEFAULT_TAG).name(), "plain");
        assert_eq!(build_transport("tagged", [0xAA, 0xBB]).name(), "tagged");
    }

    #[test]
    fn build_transport_falls_back_on_unknown_name() {
        // Warn-and-skip: a typo must not prevent the tunnel coming up.
        assert_eq!(build_transport("tls-front", DEFAULT_TAG).name(), "plain");
    }

    #[test]
    fn build_transport_honours_tag() {
        let t = build_transport("tagged", [0xAA, 0xBB]);
        let wire = t.wrap(b"x");
        assert_eq!(&wire[..2], &[0xAA, 0xBB]);
        assert_eq!(t.unwrap(&wire).unwrap(), b"x");
    }

    #[test]
    fn build_transport_id_roundtrips_names() {
        for id in [TRANSPORT_PLAIN, TRANSPORT_TAGGED] {
            let name = transport_name(id).unwrap();
            assert_eq!(transport_id(name), Some(id));
            assert_eq!(build_transport_id(id, DEFAULT_TAG).unwrap().name(), name);
        }
        assert_eq!(transport_id(""), Some(TRANSPORT_PLAIN));
        assert_eq!(transport_id("tls-front"), None);
    }

    #[test]
    fn build_transport_id_rejects_unknown_id() {
        assert!(build_transport_id(0, DEFAULT_TAG).is_none());
        assert!(build_transport_id(200, DEFAULT_TAG).is_none());
        assert_eq!(transport_name(200), None);
    }

    #[test]
    fn build_transport_id_honours_negotiated_tag() {
        let t = build_transport_id(TRANSPORT_TAGGED, [0x99, 0x88]).unwrap();
        let wire = t.wrap(b"z");
        assert_eq!(&wire[..2], &[0x99, 0x88]);
        assert_eq!(t.unwrap(&wire).unwrap(), b"z");
    }

    #[test]
    fn parse_tag_defaults_and_validates() {
        assert_eq!(parse_tag(None).unwrap(), DEFAULT_TAG);
        assert_eq!(parse_tag(Some("")).unwrap(), DEFAULT_TAG);
        assert_eq!(parse_tag(Some("  ")).unwrap(), DEFAULT_TAG);
        assert_eq!(parse_tag(Some("abcd")).unwrap(), [0xAB, 0xCD]);
        // Must be exactly two bytes of hex.
        assert!(parse_tag(Some("ab")).is_err());
        assert!(parse_tag(Some("abcde")).is_err());
        assert!(parse_tag(Some("zzzz")).is_err());
    }

    #[test]
    fn build_session_transport_seeds_via_init() {
        // PlainTransport ignores the seed; the call must still be a no-op that
        // returns a working transport.
        let t = build_session_transport(DEFAULT_TRANSPORT, DEFAULT_TAG, &[7u8; 32]);
        assert_eq!(t.name(), "plain");
        assert_eq!(t.unwrap(&t.wrap(b"ok")).unwrap(), b"ok");
    }

    #[test]
    fn plain_transport_init_is_a_noop() {
        let t = PlainTransport;
        t.init(&[0u8; 32]);
        assert_eq!(t.wrap(b"a"), b"a");
    }
}
