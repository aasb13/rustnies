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
//! datagrams* by design; any stateful shaping (reordering, coalescing) lives in
//! a higher layer. This keeps the trait trivial to implement and reason about.

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

    /// `frame` is the plaintext packet produced by [`crate::protocol::codec`].
    /// Returns the bytes to actually transmit.
    fn wrap(&self, frame: &[u8]) -> Vec<u8>;

    /// `datagram` is the raw bytes received from the UDP socket. Returns the
    /// plaintext frame for [`crate::protocol::codec::decode`].
    fn unwrap(&self, datagram: &[u8]) -> Result<Vec<u8>, TransportError>;

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

    fn unwrap(&self, datagram: &[u8]) -> Result<Vec<u8>, TransportError> {
        Ok(datagram.to_vec())
    }

    fn boxed_clone(&self) -> Box<dyn Transport> {
        Box::new(self.clone())
    }
}

/// A transport that prepends a small framing tag. Included as a second impl to
/// prove the abstraction is real (and as a skeleton for obfuscation work).
#[derive(Debug, Default, Clone)]
pub struct TaggedTransport {
    /// A fixed 2-byte tag placed before every wrapped datagram.
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

    fn unwrap(&self, datagram: &[u8]) -> Result<Vec<u8>, TransportError> {
        if datagram.len() < self.tag.len() {
            return Err(TransportError::UnwrapFailed);
        }
        if &datagram[..self.tag.len()] != &self.tag {
            return Err(TransportError::UnwrapFailed);
        }
        Ok(datagram[self.tag.len()..].to_vec())
    }

    fn boxed_clone(&self) -> Box<dyn Transport> {
        Box::new(self.clone())
    }
}

/// Convenience: produce the default plain transport.
pub fn default_transport() -> Box<dyn Transport> {
    Box::new(PlainTransport)
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
}
