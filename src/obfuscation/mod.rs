//! Stackable, composable traffic-obfuscation transforms applied on top of the
//! [`crate::transport::Transport`] layer.
//!
//! ## Where this fits
//!
//! The [`crate::transport::Transport`] trait handles **wrap/unwrap semantics** —
//! the low-level framing that turns a plaintext protocol frame into the bytes
//! that go on the UDP socket (and back). That layer is intentionally narrow
//! and stateless: it is the single seam reserved for the *envelope* shape.
//!
//! [`ObfuscationLayer`] is a **separate, optional, stackable** abstraction that
//! sits *on top of* a `Transport`. Each layer is a pure transform on a packet
//! buffer: [`ObfuscationLayer::apply`] turns an outgoing frame into the bytes
//! to feed to `Transport::wrap`, and [`ObfuscationLayer::reverse`] is the
//! exact inverse on the receive path. Layers are composed in an ordered
//! [`ObfuscationStack`]: on the send path layers are applied in order, and on
//! the receive path they are reversed in **reverse** order, so the stack is a
//! symmetric pipeline.
//!
//! ```text
//!   send:    frame -> [L1.apply -> L2.apply -> ... -> Ln.apply] -> Transport::wrap -> wire
//!   recv:    wire  -> Transport::unwrap -> [Ln.reverse -> ... -> L2.reverse -> L1.reverse] -> frame
//! ```
//!
//! ## Why a separate trait
//!
//! The `Transport` trait is a single object with `wrap`/`unwrap`; it is not
//! composable by itself. A real obfuscation deployment wants to mix and match
//! independent transforms (size padding, timing shaping, header whitening, and
//! eventually full protocol mimicry) without each one having to re-implement
//! the envelope. By keeping `ObfuscationLayer` as a distinct, stackable,
//! ordered transform, deployments compose a pipeline from config without code
//! changes, and a future heavy mimicry layer (TLS/JA3 impersonation) can be
//! implemented as *one* `ObfuscationLayer` that produces a byte stream the
//! `Transport` then frames — without touching the protocol, crypto, FEC, or
//! TUN layers.
//!
//! ## Off by default
//!
//! No layer is active unless explicitly configured in the `[obfuscation]`
//! section of the TOML config. With no `[obfuscation]` section (or an empty
//! `layers = []`), the stack is empty and the pipeline is identical to
//! phase 1: `Transport::wrap`/`unwrap` directly on the plaintext frame.

pub mod header_xor;
pub mod padding;
pub mod timing;

use std::sync::Arc;

use crate::config::ObfuscationConfig;

pub use timing::is_decoy_frame;

/// Error returned by an obfuscation layer's `reverse` when the input does not
/// match the expected shape (e.g. a padding layer sees a length marker that
/// does not correspond to a configured bucket, or a header-XOR layer sees a
/// buffer too short for the header).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ObfuscationError {
    /// The incoming bytes were rejected by the layer (malformed, wrong length,
    /// or foreign traffic).
    #[error("obfuscation layer rejected the input")]
    Rejected,
    /// The layer produced output larger than the configured maximum.
    #[error("obfuscation layer output was too large ({0} bytes)")]
    TooLarge(usize),
}

/// A single stackable obfuscation transform.
///
/// `apply` is the send-side transform: it takes a *frame* (the plaintext
/// `header || ciphertext` produced by [`crate::protocol::codec`]) and returns
/// the bytes that will be passed to [`crate::transport::Transport::wrap`].
/// `reverse` is the exact inverse on the receive path: it takes the output of
/// [`crate::transport::Transport::unwrap`] and returns the original frame.
///
/// Layers must be **deterministic inverses**: for any frame `f`,
/// `layer.reverse(layer.apply(f)) == Ok(f)`. This is tested in the layer's
/// unit tests.
///
/// Layers MAY be stateful (e.g. a timing layer that tracks the last send
/// time, or a header-XOR layer keyed on session material), but the state must
/// be self-contained — a layer may not touch the socket, TUN, or session
/// state. Stateful layers are `Send + Sync` so the stack can be shared across
/// tasks.
///
/// Layers that need per-session keying material receive it via
/// [`ObfuscationLayer::init`], called once after the Noise handshake completes
/// with the derived session seed (see [`ObfuscationStack::init`]). Layers that
/// do not need keying material use the default no-op impl.
pub trait ObfuscationLayer: Send + Sync + 'static {
    /// Human-readable name (for logging / config diagnostics).
    fn name(&self) -> &'static str;

    /// Send-side transform. Infallible for well-formed inputs.
    fn apply(&self, frame: &[u8]) -> Vec<u8>;

    /// Receive-side inverse. Returns `Err` if the input is not a valid output
    /// of this layer (foreign / corrupted traffic).
    fn reverse(&self, buf: &[u8]) -> Result<Vec<u8>, ObfuscationError>;

    /// Initialize the layer with per-session keying material derived from the
    /// Noise handshake hash. Called once after the handshake completes, before
    /// any `apply`/`reverse`. The default implementation is a no-op for layers
    /// that do not need per-session keying.
    fn init(&self, _session_seed: &[u8; 32]) {}

    /// Boxed clone so a layer can be held behind a trait object and duplicated
    /// across tasks (the handshake and tunnel each need their own stack).
    fn boxed_clone(&self) -> Box<dyn ObfuscationLayer>;
}

/// An ordered, composable stack of [`ObfuscationLayer`]s.
///
/// On the send path, layers are applied in order (first to last). On the
/// receive path, layers are reversed in reverse order (last to first). This
/// makes the stack a symmetric pipeline:
///
/// ```text
///   send:    frame -> L0.apply -> L1.apply -> ... -> Ln.apply -> Transport::wrap
///   recv:    Transport::unwrap -> Ln.reverse -> ... -> L1.reverse -> L0.reverse -> frame
/// ```
///
/// An empty stack is the identity transform: `apply` and `reverse` return the
/// input unchanged. This is the default when no `[obfuscation]` section is
/// present in the config.
#[derive(Default)]
pub struct ObfuscationStack {
    layers: Vec<Box<dyn ObfuscationLayer>>,
    /// Cached flag: true when `layers` is non-empty. Lets the hot path skip
    /// the allocation and iteration entirely when obfuscation is off.
    active: bool,
}

impl Clone for ObfuscationStack {
    fn clone(&self) -> Self {
        Self {
            layers: self.layers.iter().map(|l| l.boxed_clone()).collect(),
            active: self.active,
        }
    }
}

impl std::fmt::Debug for ObfuscationStack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObfuscationStack")
            .field("active", &self.active)
            .field("layers", &self.names())
            .finish()
    }
}

impl ObfuscationStack {
    /// Construct an empty (identity) stack.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a stack from an ordered list of layers.
    pub fn from_layers(layers: Vec<Box<dyn ObfuscationLayer>>) -> Self {
        let active = !layers.is_empty();
        Self { layers, active }
    }

    /// Whether any layer is active. When false, `apply`/`reverse` are
    /// allocation-free identities.
    pub fn active(&self) -> bool {
        self.active
    }

    /// Push a layer onto the end of the stack (applied last on send, reversed
    /// first on receive).
    pub fn push(&mut self, layer: Box<dyn ObfuscationLayer>) {
        self.layers.push(layer);
        self.active = true;
    }

    /// Initialize every layer with per-session keying material. Called once
    /// after the Noise handshake completes. Idempotent for layers that guard
    /// re-init.
    pub fn init(&self, session_seed: &[u8; 32]) {
        for layer in &self.layers {
            layer.init(session_seed);
        }
    }

    /// Send-side transform: apply every layer in order. When the stack is
    /// empty, returns the input verbatim with no allocation.
    pub fn apply(&self, frame: &[u8]) -> Vec<u8> {
        if !self.active {
            return frame.to_vec();
        }
        let mut buf = frame.to_vec();
        for layer in &self.layers {
            buf = layer.apply(&buf);
        }
        buf
    }

    /// Receive-side transform: reverse every layer in reverse order. When the
    /// stack is empty, returns the input verbatim with no allocation.
    pub fn reverse(&self, buf: &[u8]) -> Result<Vec<u8>, ObfuscationError> {
        if !self.active {
            return Ok(buf.to_vec());
        }
        let mut cur = buf.to_vec();
        for layer in self.layers.iter().rev() {
            cur = layer.reverse(&cur)?;
        }
        Ok(cur)
    }

    /// The number of layers in the stack.
    pub fn len(&self) -> usize {
        self.layers.len()
    }

    /// Whether the stack is empty.
    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    /// The names of the layers in order, for logging.
    pub fn names(&self) -> Vec<&'static str> {
        self.layers.iter().map(|l| l.name()).collect()
    }
}

/// Build an [`ObfuscationStack`] from a resolved [`ObfuscationConfig`].
///
/// The config is the *file* config section (`[obfuscation]`), which is an
/// ordered list of layer names plus per-layer parameters. Unknown names and
/// malformed parameters are logged at `warn` and skipped, so a typo never
/// prevents the tunnel from coming up — the offending layer is just omitted.
///
/// Returns an empty (identity) stack when:
///   - the config is `None` (no `[obfuscation]` section), or
///   - `layers` is empty, or
///   - every named layer failed to construct.
pub fn build_stack(cfg: Option<&ObfuscationConfig>) -> ObfuscationStack {
    let Some(cfg) = cfg else {
        return ObfuscationStack::new();
    };
    if cfg.layers.is_empty() {
        return ObfuscationStack::new();
    }
    let mut stack = ObfuscationStack::new();
    for name in &cfg.layers {
        match name.as_str() {
            "padding" => stack.push(Box::new(padding::SizePadding::from_config(cfg))),
            "timing" => stack.push(Box::new(timing::TimingJitter::from_config(cfg))),
            "header_xor" => stack.push(Box::new(header_xor::HeaderXor::from_config(cfg))),
            other => {
                tracing::warn!(
                    layer = other,
                    "unknown obfuscation layer name in [obfuscation] layers; skipping"
                );
            }
        }
    }
    if stack.active() {
        tracing::info!(
            layers = ?stack.names(),
            "obfuscation stack active"
        );
    }
    stack
}

/// A shared, cloneable handle to an [`ObfuscationStack`].
///
/// The stack itself is already `Clone`, but the layers are behind `Box<dyn>`,
/// so cloning copies the boxes. For the common case of sharing the *same*
/// stack across the handshake and tunnel tasks, this `Arc` wrapper avoids the
/// clone and lets both tasks call `init` on the same layer state. The `apply`
/// and `reverse` methods take `&self`, so sharing is safe.
pub type SharedStack = Arc<ObfuscationStack>;

/// Convenience: build a shared stack from config.
pub fn build_shared_stack(cfg: Option<&ObfuscationConfig>) -> SharedStack {
    Arc::new(build_stack(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A no-op layer that uppercases bytes on apply and lowercases on reverse,
    /// used to verify stack ordering and composition.
    struct Upper;
    impl ObfuscationLayer for Upper {
        fn name(&self) -> &'static str {
            "upper"
        }
        fn apply(&self, frame: &[u8]) -> Vec<u8> {
            frame.iter().map(|b| b.to_ascii_uppercase()).collect()
        }
        fn reverse(&self, buf: &[u8]) -> Result<Vec<u8>, ObfuscationError> {
            Ok(buf.iter().map(|b| b.to_ascii_lowercase()).collect())
        }
        fn boxed_clone(&self) -> Box<dyn ObfuscationLayer> {
            Box::new(Upper)
        }
    }

    /// A layer that XORs every byte with 0x01 on apply and reverse (symmetric).
    struct XorOne;
    impl ObfuscationLayer for XorOne {
        fn name(&self) -> &'static str {
            "xorone"
        }
        fn apply(&self, frame: &[u8]) -> Vec<u8> {
            frame.iter().map(|b| b ^ 0x01).collect()
        }
        fn reverse(&self, buf: &[u8]) -> Result<Vec<u8>, ObfuscationError> {
            Ok(buf.iter().map(|b| b ^ 0x01).collect())
        }
        fn boxed_clone(&self) -> Box<dyn ObfuscationLayer> {
            Box::new(XorOne)
        }
    }

    #[test]
    fn empty_stack_is_identity() {
        let s = ObfuscationStack::new();
        assert!(!s.active());
        let frame = b"hello world";
        assert_eq!(s.apply(frame), frame);
        assert_eq!(s.reverse(frame).unwrap(), frame);
    }

    #[test]
    fn single_layer_roundtrips() {
        let mut s = ObfuscationStack::new();
        s.push(Box::new(Upper));
        let frame = b"Hello World";
        let applied = s.apply(frame);
        assert_eq!(applied, b"HELLO WORLD");
        let reversed = s.reverse(&applied).unwrap();
        assert_eq!(reversed, b"hello world");
    }

    #[test]
    fn multi_layer_roundtrips_and_ordering() {
        // Stack: [Upper, XorOne]
        // send:  Upper.apply -> XorOne.apply
        // recv:  XorOne.reverse -> Upper.reverse
        let mut s = ObfuscationStack::new();
        s.push(Box::new(Upper));
        s.push(Box::new(XorOne));
        let frame = b"AbC";
        // Upper: ABC, then XorOne: ABC ^ 01 = @BC (A^1=@, B^1=C, C^1=B)
        let applied = s.apply(frame);
        let expected: Vec<u8> = b"ABC".iter().map(|b| b ^ 0x01).collect();
        assert_eq!(applied, expected);
        // reverse: XorOne.reverse -> ABC, Upper.reverse -> abc
        let reversed = s.reverse(&applied).unwrap();
        assert_eq!(reversed, b"abc");
    }

    #[test]
    fn names_preserve_order() {
        let mut s = ObfuscationStack::new();
        s.push(Box::new(Upper));
        s.push(Box::new(XorOne));
        assert_eq!(s.names(), vec!["upper", "xorone"]);
    }

    #[test]
    fn init_calls_each_layer() {
        // init is a no-op for these layers; just verify it doesn't panic and
        // the default impl is used.
        let mut s = ObfuscationStack::new();
        s.push(Box::new(Upper));
        s.push(Box::new(XorOne));
        s.init(&[0u8; 32]);
        assert!(s.active());
    }

    #[test]
    fn build_stack_empty_config_is_identity() {
        let s = build_stack(None);
        assert!(!s.active());
        let s2 = build_stack(Some(&ObfuscationConfig::default()));
        assert!(!s2.active());
    }

    #[test]
    fn build_stack_unknown_layer_skipped() {
        let cfg = ObfuscationConfig {
            layers: vec!["nonexistent".to_string()],
            ..Default::default()
        };
        let s = build_stack(Some(&cfg));
        assert!(!s.active(), "unknown layers are skipped, stack stays empty");
    }
}
