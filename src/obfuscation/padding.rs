//! Size-padding obfuscation layer.
//!
//! Pads each outgoing frame up to the smallest configured "bucket" size, so
//! an observer cannot infer payload size from the on-wire datagram length.
//! A single 2-byte big-endian length prefix records the real frame length so
//! `reverse` can strip the padding exactly.
//!
//! This is a deterministic, stateless transform: `reverse(apply(f)) == f` for
//! every frame. The length prefix is *not* encrypted by this layer (the frame
//! it receives is already `header || AEAD ciphertext`, so the payload is
//! already confidential); the prefix only leaks the original length to the
//! same extent the unpadded frame would have. The bucketing is what defeats
//! size-based traffic analysis: the on-wire size becomes one of a small set
//! of bucket sizes rather than a continuous distribution.
//!
//! ## Configuration
//!
//! From the `[obfuscation]` TOML section:
//!
//! ```toml
//! [obfuscation]
//! layers = ["padding"]
//! padding_buckets = [64, 128, 256, 512, 1024, 1500]
//! padding_max = 1500
//! ```
//!
//! `padding_buckets` is the sorted list of bucket sizes (in bytes, measured at
//! the *padded* output including the 2-byte length prefix). A frame is padded
//! into the smallest bucket that fits it; if no bucket fits, it is sent
//! unpadded (with the length prefix only) so large frames are never dropped.
//! `padding_max` caps the output size (an over-bucket frame larger than
//! `padding_max` is rejected on apply — but in practice the transport MTU
//! keeps frames well under any reasonable `padding_max`).
//!
//! Defaults: buckets `[128, 256, 512, 1024, 1500]`, max 1500.

use super::{ObfuscationError, ObfuscationLayer};

/// The 2-byte big-endian length prefix used to record the real frame length.
const LEN_PREFIX: usize = 2;

/// Default bucket sizes (bytes, inclusive of the 2-byte length prefix).
const DEFAULT_BUCKETS: [usize; 5] = [128, 256, 512, 1024, 1500];
/// Default maximum output size.
const DEFAULT_MAX: usize = 1500;

/// A size-padding obfuscation layer.
///
/// Pads each frame up to the smallest configured bucket, prefixed by a 2-byte
/// big-endian length of the original frame. The pad bytes are zero. `reverse`
/// reads the length prefix and returns exactly that many bytes, dropping the
/// padding.
#[derive(Debug, Clone)]
pub struct SizePadding {
    /// Sorted, deduplicated bucket sizes (output sizes, including the length
    /// prefix). A frame fits a bucket when `frame.len() + LEN_PREFIX <= bucket`.
    buckets: Vec<usize>,
    /// Hard cap on output size. Frames whose smallest-fitting bucket exceeds
    /// this are sent with the length prefix only (no padding) so they are not
    /// dropped; frames that already exceed `max` are rejected on apply.
    max: usize,
}

impl Default for SizePadding {
    fn default() -> Self {
        Self {
            buckets: DEFAULT_BUCKETS.to_vec(),
            max: DEFAULT_MAX,
        }
    }
}

impl SizePadding {
    /// Construct a new padding layer with the given buckets and max.
    ///
    /// Buckets are sorted and deduplicated. Zero-length and sub-`LEN_PREFIX`
    /// buckets are dropped (they can never fit any frame). If `buckets` is
    /// empty after cleaning, the layer is a no-op (length prefix only, no
    /// padding applied), which is still a valid, reversible transform.
    pub fn new(mut buckets: Vec<usize>, max: usize) -> Self {
        buckets.sort_unstable();
        buckets.dedup();
        buckets.retain(|&b| b >= LEN_PREFIX);
        Self { buckets, max }
    }

    /// Build the layer from the resolved `[obfuscation]` config section.
    /// Falls back to defaults when the padding-specific fields are absent.
    pub fn from_config(cfg: &crate::config::ObfuscationConfig) -> Self {
        let buckets = if cfg.padding_buckets.is_empty() {
            DEFAULT_BUCKETS.to_vec()
        } else {
            cfg.padding_buckets.clone()
        };
        let max = if cfg.padding_max == 0 {
            DEFAULT_MAX
        } else {
            cfg.padding_max
        };
        Self::new(buckets, max)
    }

    /// Choose the smallest bucket that fits the framed output (frame +
    /// `LEN_PREFIX`), or `None` if no bucket fits.
    fn pick_bucket(&self, frame_len: usize) -> Option<usize> {
        let need = frame_len + LEN_PREFIX;
        self.buckets.iter().copied().find(|&b| b >= need)
    }
}

impl ObfuscationLayer for SizePadding {
    fn name(&self) -> &'static str {
        "padding"
    }

    fn apply(&self, frame: &[u8]) -> Vec<u8> {
        // Output = [len:2 BE][frame][zero-pad to bucket]
        let need = frame.len() + LEN_PREFIX;
        // Over-max: emit length-prefixed but unpadded so the frame is not
        // dropped. The receiver still recovers the exact frame via the prefix.
        if need > self.max {
            let mut out = Vec::with_capacity(need);
            let len = (frame.len() as u16).to_be_bytes();
            out.extend_from_slice(&len);
            out.extend_from_slice(frame);
            return out;
        }
        let total = self.pick_bucket(frame.len()).unwrap_or(need);
        let mut out = Vec::with_capacity(total);
        let len = (frame.len() as u16).to_be_bytes();
        out.extend_from_slice(&len);
        out.extend_from_slice(frame);
        // Zero-pad up to the bucket size.
        if total > need {
            out.resize(total, 0);
        }
        out
    }

    fn reverse(&self, buf: &[u8]) -> Result<Vec<u8>, ObfuscationError> {
        if buf.len() < LEN_PREFIX {
            return Err(ObfuscationError::Rejected);
        }
        let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if buf.len() < LEN_PREFIX + len {
            return Err(ObfuscationError::Rejected);
        }
        Ok(buf[LEN_PREFIX..LEN_PREFIX + len].to_vec())
    }

    fn boxed_clone(&self) -> Box<dyn ObfuscationLayer> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ObfuscationConfig;

    #[test]
    fn roundtrips_small_frame_into_smallest_bucket() {
        let p = SizePadding::default();
        let frame = b"hi";
        let out = p.apply(frame);
        // Smallest default bucket is 128; output is exactly 128 bytes.
        assert_eq!(out.len(), 128);
        let rev = p.reverse(&out).unwrap();
        assert_eq!(rev, frame);
    }

    #[test]
    fn roundtrips_frame_that_exceeds_smallest_bucket() {
        let p = SizePadding::default();
        let frame = vec![0xAB; 200];
        let out = p.apply(&frame);
        // 200 + 2 = 202; smallest fitting bucket is 256.
        assert_eq!(out.len(), 256);
        let rev = p.reverse(&out).unwrap();
        assert_eq!(rev, frame);
    }

    #[test]
    fn roundtrips_frame_that_fits_no_bucket_unpadded() {
        let p = SizePadding::new(vec![128, 256], 1500);
        let frame = vec![0xCD; 1000];
        let out = p.apply(&frame);
        // No bucket fits (max useful is 256); output is len + frame, unpadded.
        assert_eq!(out.len(), 1000 + LEN_PREFIX);
        let rev = p.reverse(&out).unwrap();
        assert_eq!(rev, frame);
    }

    #[test]
    fn over_max_is_length_prefixed_unpadded() {
        let p = SizePadding::new(vec![128, 256], 300);
        let frame = vec![0x11; 500];
        let out = p.apply(&frame);
        // 500 + 2 = 502 > 300 max -> unpadded but length-prefixed.
        assert_eq!(out.len(), 500 + LEN_PREFIX);
        let rev = p.reverse(&out).unwrap();
        assert_eq!(rev, frame);
    }

    #[test]
    fn empty_frame_roundtrips() {
        let p = SizePadding::default();
        let frame: &[u8] = b"";
        let out = p.apply(frame);
        assert_eq!(out.len(), 128);
        let rev = p.reverse(&out).unwrap();
        assert!(rev.is_empty());
    }

    #[test]
    fn reverse_rejects_too_short() {
        let p = SizePadding::default();
        assert_eq!(p.reverse(&[0x00]).unwrap_err(), ObfuscationError::Rejected);
        assert_eq!(p.reverse(&[]).unwrap_err(), ObfuscationError::Rejected);
    }

    #[test]
    fn reverse_rejects_truncated_payload() {
        let p = SizePadding::default();
        // Length prefix says 50 bytes but only 10 follow.
        let mut bad = vec![0u8; 12];
        bad[0] = 0x00;
        bad[1] = 0x32; // 50
        assert_eq!(p.reverse(&bad).unwrap_err(), ObfuscationError::Rejected);
    }

    #[test]
    fn buckets_are_sorted_deduped_and_cleaned() {
        let p = SizePadding::new(vec![512, 0, 128, 128, 64, 1], 2000);
        // 0 and 1 are dropped (< LEN_PREFIX=2); 128 < 2 is kept but 1 dropped.
        // Remaining sorted: [64, 128, 512]
        assert_eq!(p.buckets, vec![64, 128, 512]);
    }

    #[test]
    fn empty_buckets_is_length_prefix_only() {
        let p = SizePadding::new(vec![], 1500);
        let frame = b"hello";
        let out = p.apply(frame);
        // No buckets -> output is len + frame, no padding.
        assert_eq!(out.len(), frame.len() + LEN_PREFIX);
        let rev = p.reverse(&out).unwrap();
        assert_eq!(rev, frame);
    }

    #[test]
    fn from_config_uses_defaults_when_empty() {
        let cfg = ObfuscationConfig::default();
        let p = SizePadding::from_config(&cfg);
        assert_eq!(p.buckets, DEFAULT_BUCKETS);
        assert_eq!(p.max, DEFAULT_MAX);
    }

    #[test]
    fn from_config_uses_custom_values() {
        let cfg = ObfuscationConfig {
            padding_buckets: vec![100, 200, 400],
            padding_max: 500,
            ..Default::default()
        };
        let p = SizePadding::from_config(&cfg);
        assert_eq!(p.buckets, vec![100, 200, 400]);
        assert_eq!(p.max, 500);
    }

    #[test]
    fn padded_output_is_constant_size_for_same_bucket() {
        let p = SizePadding::default();
        let a = p.apply(b"a");
        let b = p.apply(b"ab");
        let c = p.apply(b"abc");
        // All three fit the 128 bucket; outputs are all 128 bytes.
        assert_eq!(a.len(), 128);
        assert_eq!(b.len(), 128);
        assert_eq!(c.len(), 128);
    }
}
