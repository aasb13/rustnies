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
//! FEC operates purely on `Vec<Vec<u8>>` symbol groups and is decoupled from
//! the protocol, crypto and transport layers. The tunnel decides how to feed
//! packets into groups; FEC only knows about symbols and indices.

pub mod adaptive;
pub mod gf256;
pub mod reed_solomon;

pub use adaptive::{AdaptiveFec, FecParams};
pub use reed_solomon::ReedSolomon;
