//! Forward error correction.
//!
//! Two layers:
//! - [`reed_solomon`] — a standard systematic Reed-Solomon erasure code over
//!   GF(256). This is the same family of codes used in QR codes, CDs and
//!   distributed storage; it recovers *any* `m` erasures out of an `n = k+m`
//!   group provided the surviving symbols are sufficient and the erasure
//!   positions are known (which they are here: each packet carries its index).
//! - [`adaptive`] — an [`AdaptiveFec`] controller that watches measured packet
//!   loss and adjusts the redundancy ratio `m/k` up as loss rises and down as
//!   it improves, with hysteresis to avoid oscillation.
//!
//! FEC operates purely on `Vec<Vec<u8>>` symbol groups and is decoupled from the
//! protocol, crypto and transport layers. The tunnel decides how to feed
//! packets into groups; FEC only knows about symbols and indices.
//!
//! # Swapping the code
//!
//! [`FecScheme`] is the seam behind the erasure code itself, selected by name
//! from `[fec] scheme` via [`build_fec_scheme`]. It is deliberately separate
//! from [`AdaptiveFec`]: the controller only ever *picks* `k` and `m`, and
//! knows nothing about how symbols are turned into parity. That split is what
//! lets a deployment turn FEC off entirely ([`NoFec`]) or move to a different
//! code without touching the loss-feedback loop, and it is why the `k`/`m`
//! choice is negotiable per session (both ends read them off every packet
//! header) while the *code* is negotiated once, in the handshake.

pub mod adaptive;
pub mod gf256;
pub mod reed_solomon;

pub use adaptive::{AdaptiveFec, FecParams};
pub use reed_solomon::{FecError, ReedSolomon};

use std::sync::Arc;

/// A swappable erasure code for a FEC group.
///
/// `k` and `m` are passed per call rather than held as state so one
/// implementation can serve every group size the [`AdaptiveFec`] controller
/// selects (it varies `m` as loss rises and falls).
pub trait FecScheme: Send + Sync + 'static {
    /// Config name, e.g. `"reed-solomon"`. Must match the name accepted by
    /// [`select_fec_scheme`].
    fn name(&self) -> &'static str;

    /// Stable wire id used in the handshake negotiation payload. Must be
    /// unique and never reused. See [`crate::protocol::profile`].
    fn id(&self) -> u8;

    /// Whether this scheme can produce parity at all. A scheme reporting
    /// `false` pins the adaptive controller's `max_m` to zero, so the tunnel
    /// never allocates a parity budget and never emits a `Fec` packet.
    fn active(&self) -> bool {
        true
    }

    /// Produce `m` parity symbols for `k` equal-length `sources`.
    fn encode(&self, k: usize, m: usize, sources: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, FecError>;

    /// Recover the `k` source symbols from `k + m` slots, any of which may be
    /// erased (`None`). Erasure positions must be known, which the packet
    /// header guarantees.
    fn decode(
        &self,
        k: usize,
        m: usize,
        symbols: &[Option<Vec<u8>>],
    ) -> Result<Vec<Vec<u8>>, FecError>;

    /// Boxed clone so a scheme can be held behind a trait object and shared
    /// across the per-session tunnels a server owns.
    fn boxed_clone(&self) -> Box<dyn FecScheme>;
}

/// The default scheme: systematic Reed-Solomon over GF(256).
#[derive(Debug, Default, Clone, Copy)]
pub struct ReedSolomonScheme;

impl FecScheme for ReedSolomonScheme {
    fn name(&self) -> &'static str {
        DEFAULT_FEC_SCHEME
    }

    fn id(&self) -> u8 {
        FEC_REED_SOLOMON
    }

    fn encode(&self, k: usize, m: usize, sources: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, FecError> {
        ReedSolomon::new(k, m)?.encode(sources)
    }

    fn decode(
        &self,
        k: usize,
        m: usize,
        symbols: &[Option<Vec<u8>>],
    ) -> Result<Vec<Vec<u8>>, FecError> {
        ReedSolomon::new(k, m)?.decode(symbols)
    }

    fn boxed_clone(&self) -> Box<dyn FecScheme> {
        Box::new(*self)
    }
}

/// FEC turned off. Reports [`FecScheme::active`] as `false`, which pins the
/// adaptive controller's `max_m` to zero so the tunnel skips the parity path
/// entirely — no parity is encoded, sent, buffered or decoded. `Data` packets
/// are still delivered directly; the cost of turning FEC off is purely that
/// lossy groups are unrecoverable.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoFec;

impl FecScheme for NoFec {
    fn name(&self) -> &'static str {
        FEC_NONE
    }

    fn id(&self) -> u8 {
        FEC_NONE_ID
    }

    fn active(&self) -> bool {
        false
    }

    fn encode(&self, _k: usize, _m: usize, _sources: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, FecError> {
        // Unreachable in practice: an inactive scheme pins max_m to 0, so the
        // tunnel returns before calling encode. Erroring (rather than
        // returning empty parities) keeps a future caller from silently
        // believing it got protection it did not.
        Err(FecError::Inactive)
    }

    fn decode(
        &self,
        _k: usize,
        _m: usize,
        _symbols: &[Option<Vec<u8>>],
    ) -> Result<Vec<Vec<u8>>, FecError> {
        Err(FecError::Inactive)
    }

    fn boxed_clone(&self) -> Box<dyn FecScheme> {
        Box::new(*self)
    }
}

/// Shared handle for a resolved scheme, mirroring
/// [`crate::obfuscation::SharedStack`].
pub type SharedFec = Arc<dyn FecScheme>;

/// FEC scheme ids on the negotiation wire. See [`crate::protocol::profile`].
pub const FEC_REED_SOLOMON: u8 = 1;
pub const FEC_NONE_ID: u8 = 2;

/// Default scheme name, used when `[fec] scheme` is unset.
pub const DEFAULT_FEC_SCHEME: &str = "reed-solomon";
/// Config name that disables FEC.
pub const FEC_NONE: &str = "none";

/// Selectable FEC schemes, resolved by name from config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FecSchemeKind {
    /// Systematic Reed-Solomon over GF(256).
    ReedSolomon,
    /// No parity at all.
    None,
}

impl FecSchemeKind {
    /// The name this kind is selected by (and reports from
    /// [`FecScheme::name`]).
    pub fn name(self) -> &'static str {
        match self {
            FecSchemeKind::ReedSolomon => DEFAULT_FEC_SCHEME,
            FecSchemeKind::None => FEC_NONE,
        }
    }

    /// The negotiation wire id for this kind.
    pub fn id(self) -> u8 {
        match self {
            FecSchemeKind::ReedSolomon => FEC_REED_SOLOMON,
            FecSchemeKind::None => FEC_NONE_ID,
        }
    }

    /// Look a kind up by its negotiation wire id. `None` means this build does
    /// not implement it, which is what a peer sees when it is older than the
    /// server's preference list.
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            FEC_REED_SOLOMON => Some(FecSchemeKind::ReedSolomon),
            FEC_NONE_ID => Some(FecSchemeKind::None),
            _ => None,
        }
    }

    /// Construct the boxed scheme implementation.
    pub fn build(self) -> Box<dyn FecScheme> {
        match self {
            FecSchemeKind::ReedSolomon => Box::new(ReedSolomonScheme),
            FecSchemeKind::None => Box::new(NoFec),
        }
    }
}

/// Resolve a FEC scheme by config name.
///
/// An unknown name is a hard error, not a silent fallback: a mismatched FEC
/// scheme between peers corrupts groups rather than failing cleanly, so it is
/// better to refuse to start than to fall back to something the peer is not
/// using.
pub fn select_fec_scheme(name: &str) -> Result<FecSchemeKind, UnknownFecScheme> {
    match name.trim() {
        "" | DEFAULT_FEC_SCHEME => Ok(FecSchemeKind::ReedSolomon),
        FEC_NONE | "off" | "disabled" => Ok(FecSchemeKind::None),
        other => Err(UnknownFecScheme {
            name: other.to_string(),
            supported: [DEFAULT_FEC_SCHEME, FEC_NONE].join(", "),
        }),
    }
}

/// Build a boxed FEC scheme from a config name, defaulting on an empty string.
pub fn build_fec_scheme(name: &str) -> Result<Box<dyn FecScheme>, UnknownFecScheme> {
    Ok(select_fec_scheme(name)?.build())
}

/// A config name that does not match any [`FecScheme`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown fec scheme {name:?}; supported: {supported}")]
pub struct UnknownFecScheme {
    /// The rejected config name.
    pub name: String,
    /// The comma-separated list of supported names, for the error message.
    pub supported: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syms(n: usize, len: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| (0..len).map(|j| (i * 7 + j) as u8).collect())
            .collect()
    }

    #[test]
    fn select_fec_scheme_recognises_names() {
        assert_eq!(
            select_fec_scheme(DEFAULT_FEC_SCHEME).unwrap(),
            FecSchemeKind::ReedSolomon
        );
        assert_eq!(select_fec_scheme("").unwrap(), FecSchemeKind::ReedSolomon);
        assert_eq!(select_fec_scheme(FEC_NONE).unwrap(), FecSchemeKind::None);
        assert_eq!(select_fec_scheme("off").unwrap(), FecSchemeKind::None);
    }

    #[test]
    fn select_fec_scheme_rejects_unknown_hard() {
        let err = select_fec_scheme("ldpc").unwrap_err();
        assert_eq!(err.name, "ldpc");
        assert!(err.supported.contains(DEFAULT_FEC_SCHEME));
        assert!(build_fec_scheme("ldpc").is_err());
    }

    #[test]
    fn names_and_ids_are_stable() {
        for kind in [FecSchemeKind::ReedSolomon, FecSchemeKind::None] {
            let s = kind.build();
            assert_eq!(s.name(), kind.name());
            assert_eq!(s.id(), kind.id());
        }
    }

    #[test]
    fn ids_are_unique() {
        let ids: Vec<u8> = [FecSchemeKind::ReedSolomon, FecSchemeKind::None]
            .iter()
            .map(|k| k.id())
            .collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len());
    }

    #[test]
    fn only_none_is_inactive() {
        assert!(FecSchemeKind::ReedSolomon.build().active());
        assert!(!FecSchemeKind::None.build().active());
    }

    #[test]
    fn reed_solomon_scheme_roundtrips() {
        let s = ReedSolomonScheme;
        let src = syms(2, 64);
        let par = s.encode(2, 2, &src).unwrap();
        assert_eq!(par.len(), 2);
        // Erase the first source; the rest must still recover it.
        let mut slots: Vec<Option<Vec<u8>>> = vec![None, Some(src[1].clone())];
        slots.extend(par.into_iter().map(Some));
        let got = s.decode(2, 2, &slots).unwrap();
        assert_eq!(got, src);
    }

    #[test]
    fn no_fec_reports_failure_rather_than_empty_parity() {
        let s = NoFec;
        assert!(matches!(
            s.encode(1, 2, &syms(1, 8)),
            Err(FecError::Inactive)
        ));
        assert!(matches!(
            s.decode(1, 2, &[None, None]),
            Err(FecError::Inactive)
        ));
    }

    #[test]
    fn boxed_clone_preserves_behavior() {
        let t: Box<dyn FecScheme> = build_fec_scheme(DEFAULT_FEC_SCHEME).unwrap();
        let clone = t.boxed_clone();
        let src = syms(1, 16);
        let par = clone.encode(1, 1, &src).unwrap();
        assert_eq!(clone.name(), t.name());
        assert_eq!(clone.id(), t.id());
        assert_eq!(par.len(), 1);
    }
}
