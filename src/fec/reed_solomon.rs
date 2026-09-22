//! Systematic Reed-Solomon erasure code over GF(256).
//!
//! Given `k` source symbols of equal length, [`ReedSolomon`] produces `m`
//! parity symbols. Any `k` surviving symbols out of the `n = k + m` total
//! suffice to recover the sources — the defining MDS property of Reed-Solomon.
//! Erasure positions are known (each packet carries its group index), so we
//! decode by solving a linear system over GF(256) rather than running a
//! Berlekamp-Massey error-and-erasure solver.
//!
//! Limits: `k + m <= 255` (GF(256) symbol alphabet). Symbols within a group
//! must be padded to a common length; the caller is responsible for trimming
//! recovered symbols to the true IP packet length.

use super::gf256::{self, solve_system};

#[derive(Debug, thiserror::Error)]
pub enum FecError {
    #[error("invalid parameters: k={k} m={m} (need 1<=k, 0<=m, k+m<=255)")]
    InvalidParams { k: usize, m: usize },
    #[error("expected {expected} source symbols, got {got}")]
    WrongSourceCount { expected: usize, got: usize },
    #[error("symbols must be equal length (first={first}, this={this})")]
    UnequalLengths { first: usize, this: usize },
    #[error("expected {n} symbols, got {got}")]
    WrongTotal { n: usize, got: usize },
    #[error("not enough surviving symbols to decode (have {have}, need {need})")]
    Insufficient { have: usize, need: usize },
    #[error("decode linear system was singular")]
    Singular,
}

/// A Reed-Solomon (k, m) configuration plus its systematic generator matrix.
#[derive(Debug, Clone)]
pub struct ReedSolomon {
    pub k: usize,
    pub m: usize,
    /// Systematic generator: `n` rows of `k` columns. Rows `0..k` are the
    /// identity; rows `k..n` are the parity rows.
    pub g: Vec<Vec<u8>>,
}

impl ReedSolomon {
    /// Build a (`k`, `m`) code. `k >= 1`, `m >= 0`, `k + m <= 255`.
    pub fn new(k: usize, m: usize) -> Result<Self, FecError> {
        if k == 0 || k + m > 255 {
            return Err(FecError::InvalidParams { k, m });
        }
        let n = k + m;
        // Vandermonde V[i][j] = alpha^(i*j), alpha = 2. This is a full-rank
        // n x k matrix over GF(256) (Vandermonde with distinct evaluation
        // points alpha^0..alpha^(n-1) is MDS).
        let mut v = vec![vec![0u8; k]; n];
        for i in 0..n {
            for j in 0..k {
                v[i][j] = exp2((i * j) as u32 % 255);
            }
        }
        // Systematic generator: G = V * V_top^{-1}, where V_top is the top k x k
        // block of V. Then G[0..k] = I and G[k..n] is the parity generator.
        // We compute V_top^{-1} by solving V_top * X = I column-by-column.
        let v_top_inv = invert_matrix(&v[0..k], k)?;
        let mut g = vec![vec![0u8; k]; n];
        for i in 0..n {
            for j in 0..k {
                let mut acc = 0u8;
                for t in 0..k {
                    acc ^= gf256::mul(v[i][t], v_top_inv[t][j]);
                }
                g[i][j] = acc;
            }
        }
        // Sanity: top k rows should now be identity.
        for i in 0..k {
            for j in 0..k {
                let want = if i == j { 1 } else { 0 };
                debug_assert_eq!(g[i][j], want, "systematic block not identity");
            }
        }
        Ok(Self { k, m, g })
    }

    /// Encode `sources` (length `k`, equal lengths) into `m` parity symbols.
    pub fn encode(&self, sources: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, FecError> {
        if sources.len() != self.k {
            return Err(FecError::WrongSourceCount {
                expected: self.k,
                got: sources.len(),
            });
        }
        let len = sources[0].len();
        for s in sources {
            if s.len() != len {
                return Err(FecError::UnequalLengths {
                    first: len,
                    this: s.len(),
                });
            }
        }
        let n = self.k + self.m;
        let mut parity = Vec::with_capacity(self.m);
        for i in self.k..n {
            let mut p = vec![0u8; len];
            let row = &self.g[i];
            for (j, sym) in sources.iter().enumerate() {
                let coef = row[j];
                if coef == 0 {
                    continue;
                }
                for (b, &x) in sym.iter().enumerate() {
                    p[b] ^= gf256::mul(coef, x);
                }
            }
            parity.push(p);
        }
        Ok(parity)
    }

    /// Recover the `k` source symbols from a full set of `n` slots, some of
    /// which may be `None` (erased). Returned symbols are padded to the common
    /// symbol length; the caller trims to the real IP packet length.
    pub fn decode(&self, symbols: &[Option<Vec<u8>>]) -> Result<Vec<Vec<u8>>, FecError> {
        let n = self.k + self.m;
        if symbols.len() != n {
            return Err(FecError::WrongTotal {
                n,
                got: symbols.len(),
            });
        }
        // Determine common symbol length from any surviving symbol.
        let len = symbols
            .iter()
            .find_map(|s| s.as_ref().map(|s| s.len()))
            .ok_or(FecError::Insufficient {
                have: 0,
                need: self.k,
            })?;

        // Validate that every present symbol shares the common length. A
        // mismatched data slot would otherwise silently produce garbage or
        // panic during the byte-wise solve.
        for (i, s) in symbols.iter().enumerate() {
            if let Some(sym) = s {
                if sym.len() != len {
                    return Err(FecError::UnequalLengths {
                        first: len,
                        this: sym.len(),
                    });
                }
            }
            let _ = i;
        }

        // Surviving data (systematic positions 0..k) are known sources.
        let recovered: Vec<Option<Vec<u8>>> = (0..self.k).map(|i| symbols[i].clone()).collect();
        let erased: Vec<usize> = (0..self.k).filter(|i| recovered[*i].is_none()).collect();
        if erased.is_empty() {
            return Ok(recovered.into_iter().map(|o| o.unwrap()).collect());
        }
        // Gather equations from surviving parity rows.
        let mut eq_rows = Vec::new();
        for i in self.k..n {
            if let Some(sym) = &symbols[i] {
                if sym.len() != len {
                    return Err(FecError::UnequalLengths {
                        first: len,
                        this: sym.len(),
                    });
                }
                let row = &self.g[i];
                // RHS starts at the parity value, with known-data contributions removed.
                let mut rhs = sym.clone();
                for (j, rec) in recovered.iter().enumerate() {
                    if let Some(known) = rec {
                        let coef = row[j];
                        if coef == 0 {
                            continue;
                        }
                        for (b, &x) in known.iter().enumerate() {
                            rhs[b] ^= gf256::mul(coef, x);
                        }
                    }
                }
                // Coefficients for the erased unknowns.
                let coefs: Vec<u8> = erased.iter().map(|&j| row[j]).collect();
                eq_rows.push((coefs, rhs));
            }
        }
        if eq_rows.len() < erased.len() {
            return Err(FecError::Insufficient {
                have: eq_rows.len(),
                need: erased.len(),
            });
        }
        // Solve byte-by-byte. The coefficient matrix is identical across all
        // bytes, so we solve once per byte position using the corresponding RHS.
        let u = erased.len();
        let mut mat: Vec<Vec<u8>> = eq_rows
            .iter()
            .take(u)
            .map(|(coefs, _)| {
                let mut row = coefs.clone();
                row.push(0); // RHS placeholder
                row
            })
            .collect();
        // Fill known sources as zero-padded for the contribution step.
        let known: Vec<Vec<u8>> = (0..self.k)
            .map(|j| recovered[j].clone().unwrap_or_else(|| vec![0u8; len]))
            .collect();
        let _ = known; // (contributions already folded into RHS above)
        let mut out = vec![vec![0u8; len]; self.k];
        // Place known sources.
        for j in 0..self.k {
            if let Some(s) = &recovered[j] {
                out[j] = s.clone();
            }
        }
        for b in 0..len {
            for (r, (coefs, rhs)) in eq_rows.iter().take(u).enumerate() {
                mat[r][..u].copy_from_slice(coefs);
                mat[r][u] = rhs[b];
            }
            let sol = solve_system(&mut mat, u).map_err(|_| FecError::Singular)?;
            for (idx, &data_pos) in erased.iter().enumerate() {
                out[data_pos][b] = sol[idx];
            }
        }
        Ok(out)
    }
}

/// alpha^(e) in GF(256), alpha = 2.
fn exp2(e: u32) -> u8 {
    // 2^e via the log/exp tables: 2 = alpha, so 2^e = exp[log[2] + e] = exp[e]
    // for e in [0,254]. We compute by repeated multiplication for clarity and
    // to avoid ordering issues with the static-table accessor in const context.
    let mut r = 1u8;
    for _ in 0..e {
        r = gf256::mul(r, 2);
    }
    r
}

/// Invert a k x k matrix over GF(256) by solving `M * X = I` column-by-column.
/// Returns the inverse or an error if `M` is singular.
fn invert_matrix(m: &[Vec<u8>], k: usize) -> Result<Vec<Vec<u8>>, FecError> {
    let mut inv = vec![vec![0u8; k]; k];
    for col in 0..k {
        // Build augmented rows = [M | e_col].
        let mut rows: Vec<Vec<u8>> = m
            .iter()
            .map(|r| {
                let mut row = r.clone();
                row.push(0);
                row
            })
            .collect();
        for r in 0..k {
            rows[r][k] = if r == col { 1 } else { 0 };
        }
        let sol = gf256::solve_system(&mut rows, k).map_err(|_| FecError::Singular)?;
        for r in 0..k {
            inv[r][col] = sol[r];
        }
    }
    Ok(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng_data(count: usize, len: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|i| (0..len).map(|j| ((i * 31 + j * 7) & 0xff) as u8).collect())
            .collect()
    }

    #[test]
    fn encode_then_decode_all_present() {
        let rs = ReedSolomon::new(4, 2).unwrap();
        let src = rng_data(4, 16);
        let parity = rs.encode(&src).unwrap();
        let mut all: Vec<Option<Vec<u8>>> = src.clone().into_iter().map(Some).collect();
        for p in parity {
            all.push(Some(p));
        }
        let out = rs.decode(&all).unwrap();
        assert_eq!(out, src);
    }

    #[test]
    fn recover_m_erased_data() {
        let rs = ReedSolomon::new(4, 3).unwrap();
        let src = rng_data(4, 32);
        let parity = rs.encode(&src).unwrap();
        let mut all: Vec<Option<Vec<u8>>> = src.clone().into_iter().map(Some).collect();
        for p in parity {
            all.push(Some(p));
        }
        // erase two data symbols and one parity; parity count (3) >= erased data (2).
        all[1] = None;
        all[3] = None;
        all[6] = None; // a parity
        let out = rs.decode(&all).unwrap();
        assert_eq!(out[0], src[0]);
        assert_eq!(out[1], src[1]);
        assert_eq!(out[2], src[2]);
        assert_eq!(out[3], src[3]);
    }

    #[test]
    fn recover_only_parities_survive() {
        let rs = ReedSolomon::new(3, 3).unwrap();
        let src = rng_data(3, 8);
        let parity = rs.encode(&src).unwrap();
        let mut all: Vec<Option<Vec<u8>>> = vec![None; 6];
        for (i, p) in parity.into_iter().enumerate() {
            all[3 + i] = Some(p);
        }
        let out = rs.decode(&all).unwrap();
        assert_eq!(out, src);
    }

    #[test]
    fn systematic_block_is_identity() {
        // The top k rows of the generator must be the identity matrix; this is
        // the invariant that makes the code systematic (sources appear verbatim
        // in the codeword). A regression here would corrupt every encode.
        for (k, m) in [(1u8, 0u8), (2, 1), (4, 2), (4, 4), (8, 8), (16, 4), (1, 10)] {
            let rs = ReedSolomon::new(k as usize, m as usize).unwrap();
            for i in 0..k as usize {
                for j in 0..k as usize {
                    let want = if i == j { 1 } else { 0 };
                    assert_eq!(
                        rs.g[i][j], want,
                        "systematic block not identity for k={k} m={m} at ({i},{j})"
                    );
                }
            }
        }
    }

    #[test]
    fn parity_rows_are_nonzero_and_distinct() {
        // If two parity rows were identical, the code would lose rank and fail
        // to correct the erasures it claims to. Vandermonde construction must
        // prevent this.
        let rs = ReedSolomon::new(4, 4).unwrap();
        let mut seen = std::collections::HashSet::new();
        for i in 4..8 {
            let row = &rs.g[i];
            assert!(row.iter().any(|&b| b != 0), "parity row {i} is all zero");
            assert!(
                seen.insert(row.clone()),
                "parity row {i} duplicates another"
            );
        }
    }

    #[test]
    fn recover_all_data_lost_one_parity_lost() {
        // k=4, m=3: lose 2 data + 1 parity. 3 surviving parities - 1 lost = 2
        // usable equations, exactly enough for 2 erased unknowns.
        let rs = ReedSolomon::new(4, 3).unwrap();
        let src = rng_data(4, 64);
        let parity = rs.encode(&src).unwrap();
        let mut all: Vec<Option<Vec<u8>>> = src.clone().into_iter().map(Some).collect();
        for p in parity {
            all.push(Some(p));
        }
        all[0] = None; // data 0 lost
        all[2] = None; // data 2 lost
        all[6] = None; // parity 2 lost
        let out = rs.decode(&all).unwrap();
        assert_eq!(out, src);
    }

    #[test]
    fn recover_max_erasures_m_equals_lost() {
        // MDS boundary: erase exactly m data symbols; the m parities suffice.
        let (k, m) = (4u8, 3u8);
        let rs = ReedSolomon::new(k as usize, m as usize).unwrap();
        let src = rng_data(k as usize, 48);
        let parity = rs.encode(&src).unwrap();
        let mut all: Vec<Option<Vec<u8>>> = src.clone().into_iter().map(Some).collect();
        for p in parity {
            all.push(Some(p));
        }
        // Erase 3 data symbols (== m).
        all[0] = None;
        all[1] = None;
        all[3] = None;
        let out = rs.decode(&all).unwrap();
        assert_eq!(out, src);
    }

    #[test]
    fn recover_more_than_m_erasures_fails() {
        // MDS bound: erasing m+1 symbols must be unrecoverable.
        let (k, m) = (4u8, 2u8);
        let rs = ReedSolomon::new(k as usize, m as usize).unwrap();
        let src = rng_data(k as usize, 32);
        let parity = rs.encode(&src).unwrap();
        let mut all: Vec<Option<Vec<u8>>> = src.clone().into_iter().map(Some).collect();
        for p in parity {
            all.push(Some(p));
        }
        // Erase 3 data symbols (m+1).
        all[0] = None;
        all[1] = None;
        all[2] = None;
        assert!(
            rs.decode(&all).is_err(),
            "erasing m+1 must be unrecoverable"
        );
    }

    #[test]
    fn recover_zero_data_lost_returns_directly() {
        // No erasures: decode short-circuits and returns the sources verbatim.
        let rs = ReedSolomon::new(4, 2).unwrap();
        let src = rng_data(4, 16);
        let parity = rs.encode(&src).unwrap();
        let mut all: Vec<Option<Vec<u8>>> = src.clone().into_iter().map(Some).collect();
        for p in parity {
            all.push(Some(p));
        }
        let out = rs.decode(&all).unwrap();
        assert_eq!(out, src);
    }

    #[test]
    fn decode_rejects_wrong_slot_count() {
        let rs = ReedSolomon::new(4, 2).unwrap();
        let too_few: Vec<Option<Vec<u8>>> = vec![None; 5];
        assert!(rs.decode(&too_few).is_err(), "5 slots for n=6 must error");
        let too_many: Vec<Option<Vec<u8>>> = vec![None; 7];
        assert!(rs.decode(&too_many).is_err(), "7 slots for n=6 must error");
    }

    #[test]
    fn decode_all_none_reports_insufficient() {
        let rs = ReedSolomon::new(4, 2).unwrap();
        let all: Vec<Option<Vec<u8>>> = vec![None; 6];
        assert!(rs.decode(&all).is_err(), "no symbols must be insufficient");
    }

    #[test]
    fn decode_rejects_unequal_symbol_lengths() {
        let rs = ReedSolomon::new(2, 1).unwrap();
        let mut all: Vec<Option<Vec<u8>>> = vec![Some(vec![1, 2, 3]), Some(vec![4, 5])];
        all.push(Some(vec![6, 7, 8]));
        assert!(rs.decode(&all).is_err(), "unequal lengths must error");
    }

    #[test]
    fn encode_then_decode_random_erasure_patterns() {
        // For a (4,2) code, exhaustively try a few random erasure patterns
        // within the MDS bound (<=2 erasures) and confirm recovery.
        let (k, m) = (4u8, 2u8);
        let rs = ReedSolomon::new(k as usize, m as usize).unwrap();
        let src = rng_data(k as usize, 40);
        let parity = rs.encode(&src).unwrap();
        let n = (k + m) as usize;
        let mut all: Vec<Option<Vec<u8>>> = src.clone().into_iter().map(Some).collect();
        for p in parity {
            all.push(Some(p));
        }
        // Try erasing each single slot.
        for e in 0..n {
            let mut trial = all.clone();
            trial[e] = None;
            let out = rs.decode(&trial).unwrap();
            assert_eq!(out, src, "single erasure at {e} must recover");
        }
        // Try a couple of double erasures within bound.
        for (a, b) in [(0, 5), (1, 4), (2, 3), (0, 1)] {
            let mut trial = all.clone();
            trial[a] = None;
            trial[b] = None;
            let out = rs.decode(&trial).unwrap();
            assert_eq!(out, src, "double erasure ({a},{b}) must recover");
        }
    }

    #[test]
    fn encode_rejects_wrong_source_count() {
        let rs = ReedSolomon::new(4, 2).unwrap();
        assert!(rs.encode(&rng_data(3, 8)).is_err(), "3 sources for k=4");
        assert!(rs.encode(&rng_data(5, 8)).is_err(), "5 sources for k=4");
    }

    #[test]
    fn encode_rejects_unequal_lengths() {
        let rs = ReedSolomon::new(2, 1).unwrap();
        let sources = vec![vec![1, 2, 3], vec![4, 5]];
        assert!(rs.encode(&sources).is_err());
    }

    #[test]
    fn one_byte_symbols_roundtrip() {
        // Edge: minimum symbol length.
        let rs = ReedSolomon::new(4, 2).unwrap();
        let src: Vec<Vec<u8>> = vec![vec![0xAB], vec![0xCD], vec![0x12], vec![0x34]];
        let parity = rs.encode(&src).unwrap();
        let mut all: Vec<Option<Vec<u8>>> = src.clone().into_iter().map(Some).collect();
        for p in parity {
            all.push(Some(p));
        }
        all[1] = None;
        all[2] = None;
        let out = rs.decode(&all).unwrap();
        assert_eq!(out, src);
    }

    #[test]
    fn large_symbol_roundtrip() {
        // Edge: symbols near the MTU size.
        let rs = ReedSolomon::new(4, 2).unwrap();
        let src: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8; 1300]).collect();
        let parity = rs.encode(&src).unwrap();
        let mut all: Vec<Option<Vec<u8>>> = src.clone().into_iter().map(Some).collect();
        for p in parity {
            all.push(Some(p));
        }
        all[0] = None;
        all[3] = None;
        let out = rs.decode(&all).unwrap();
        assert_eq!(out, src);
    }

    #[test]
    fn k1_m0_is_valid_no_op() {
        // Smallest valid code: k=1, m=0.
        let rs = ReedSolomon::new(1, 0).unwrap();
        let src = vec![vec![1, 2, 3]];
        let parity = rs.encode(&src).unwrap();
        assert!(parity.is_empty(), "m=0 produces no parities");
        let all: Vec<Option<Vec<u8>>> = vec![Some(vec![1, 2, 3])];
        let out = rs.decode(&all).unwrap();
        assert_eq!(out, src);
    }

    #[test]
    fn invalid_params_rejected() {
        assert!(ReedSolomon::new(0, 0).is_err(), "k=0 invalid");
        assert!(ReedSolomon::new(0, 4).is_err(), "k=0 invalid even with m");
        assert!(ReedSolomon::new(252, 4).is_err(), "k+m > 255 invalid");
        assert!(ReedSolomon::new(255, 1).is_err(), "k+m = 256 invalid");
        assert!(ReedSolomon::new(255, 0).is_ok(), "k+m = 255 valid boundary");
        assert!(ReedSolomon::new(1, 254).is_ok(), "k+m = 255 valid boundary");
    }

    // -------------------------------------------------------------------
    // High-loss / extreme-scenario tests (the new default k=1 regime)
    // -------------------------------------------------------------------

    #[test]
    fn k1_high_m_recovers_from_any_single_survivor() {
        // k=1, m=20 (n=21): any 1 surviving symbol out of 21 suffices.
        // This is the extreme-loss regime: up to 20 out of 21 erased.
        let rs = ReedSolomon::new(1, 20).unwrap();
        let src = vec![vec![0x5Au8; 64]];
        let parity = rs.encode(&src).unwrap();
        assert_eq!(parity.len(), 20);

        // For every possible single survivor, decode must succeed.
        let mut all: Vec<Option<Vec<u8>>> = src.clone().into_iter().map(Some).collect();
        for p in &parity {
            all.push(Some(p.clone()));
        }
        let n = all.len();
        for survivor in 0..n {
            let mut trial = vec![None; n];
            trial[survivor] = all[survivor].clone();
            let out = rs.decode(&trial).unwrap();
            assert_eq!(
                out, src,
                "decode must recover from any single survivor (index {survivor}/{n})"
            );
        }
    }

    #[test]
    fn k1_high_m_fails_when_all_erased() {
        // k=1, m=20, all 21 erased: unrecoverable.
        let rs = ReedSolomon::new(1, 20).unwrap();
        let all: Vec<Option<Vec<u8>>> = vec![None; 21];
        assert!(rs.decode(&all).is_err(), "all-erased must be unrecoverable");
    }

    #[test]
    fn k1_high_m_recovers_with_m_erasures() {
        // k=1, m=10: erase exactly m=10 of 11. Any 1 survivor suffices.
        let rs = ReedSolomon::new(1, 10).unwrap();
        let src = vec![vec![0xBBu8; 32]];
        let parity = rs.encode(&src).unwrap();
        let mut all: Vec<Option<Vec<u8>>> = src.clone().into_iter().map(Some).collect();
        for p in &parity {
            all.push(Some(p.clone()));
        }
        // Erase data + first 9 parities = 10 erased out of 11. One parity left.
        all[0] = None;
        for i in 1..10 {
            all[i] = None;
        }
        let out = rs.decode(&all).unwrap();
        assert_eq!(out, src, "single surviving parity must recover the source");
    }

    #[test]
    fn k1_simulated_90_percent_loss() {
        // Simulate 90% packet loss over many trials with a seeded PRNG.
        // With k=1, m=20: 21 symbols per group, 90% loss means ~2.1 survive.
        // All loss events are independent, so the residual loss per trial
        // should be much less than 90%.
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        let mut rng = StdRng::seed_from_u64(42);
        let rs = ReedSolomon::new(1, 20).unwrap();
        let trials = 500;
        let mut recovered = 0;
        let mut unrecoverable = 0;

        for _ in 0..trials {
            let src = vec![vec![rng.r#gen(); 16]];
            let parity = rs.encode(&src).unwrap();
            let mut all: Vec<Option<Vec<u8>>> = src.clone().into_iter().map(Some).collect();
            for p in &parity {
                all.push(Some(p.clone()));
            }
            // Each of the 21 symbols independently has a 90% chance of being erased.
            for slot in &mut all {
                if rng.r#gen::<f64>() < 0.90 {
                    *slot = None;
                }
            }
            match rs.decode(&all) {
                Ok(out) if out == src => recovered += 1,
                Ok(_) => panic!("decode produced wrong data"),
                Err(_) => unrecoverable += 1,
            }
        }

        // P(all 21 lost) = 0.9^21 ≈ 11%. Over 500 trials, expect ~55 failures.
        let recovery_rate = recovered as f64 / trials as f64;
        eprintln!(
            "90% loss, k=1 m=20: {recovered}/{trials} recovered ({:.1}%), {unrecoverable} unrecoverable",
            recovery_rate * 100.0
        );
        assert!(
            recovery_rate > 0.85,
            "expected >85% recovery at 90% loss with m=20, got {:.1}%",
            recovery_rate * 100.0
        );
    }

    #[test]
    fn k1_simulated_95_percent_loss_with_max_m() {
        // 95% loss with m=20: P(all lost) = 0.95^21 ≈ 34%. Still too high.
        // This validates that even max_m=20 cannot fully eliminate loss at
        // 95% — the adaptive controller will need more copies via TCP-style
        // retransmission (which this VPN doesn't do for data). But we verify
        // the recovery rate is much better than raw 95%.
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        let mut rng = StdRng::seed_from_u64(99);
        let rs = ReedSolomon::new(1, 20).unwrap();
        let trials = 500;
        let mut recovered = 0;

        for _ in 0..trials {
            let src = vec![vec![rng.r#gen(); 16]];
            let parity = rs.encode(&src).unwrap();
            let mut all: Vec<Option<Vec<u8>>> = src.clone().into_iter().map(Some).collect();
            for p in &parity {
                all.push(Some(p.clone()));
            }
            for slot in &mut all {
                if rng.r#gen::<f64>() < 0.95 {
                    *slot = None;
                }
            }
            if rs.decode(&all).is_ok() {
                recovered += 1;
            }
        }
        let rate = recovered as f64 / trials as f64;
        eprintln!(
            "95% loss, k=1 m=20: recovered {recovered}/{trials} ({:.1}%)",
            rate * 100.0
        );
        // Even at 95% loss, FEC with m=20 should recover substantially
        // more than 5%.
        assert!(rate > 0.10, "expected >10% recovery at 95% loss");
    }

    #[test]
    fn k1_high_m_random_erasure_patterns() {
        // Exhaustive random-pattern coverage for k=1, various m values.
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        let mut rng = StdRng::seed_from_u64(7);
        for m in [1, 2, 5, 10, 20, 40] {
            let rs = ReedSolomon::new(1, m).unwrap();
            let src = vec![vec![rng.r#gen(); 24]];
            let parity = rs.encode(&src).unwrap();
            // Run 200 random erasure patterns (anything up to n erasures).
            for _ in 0..200 {
                let mut all: Vec<Option<Vec<u8>>> = src.clone().into_iter().map(Some).collect();
                for p in &parity {
                    all.push(Some(p.clone()));
                }
                // Randomly erase each symbol with 50% probability.
                let mut present = 0;
                for slot in &mut all {
                    if rng.r#gen::<bool>() {
                        *slot = None;
                    } else {
                        present += 1;
                    }
                }
                // With k=1, decode succeeds iff at least 1 symbol is present.
                if present >= 1 {
                    let out = rs.decode(&all).unwrap();
                    assert_eq!(out, src, "k=1 m={m}: decode failed with {present} present");
                } else {
                    assert!(rs.decode(&all).is_err(), "k=1 m={m}: all erased must fail");
                }
            }
        }
    }

    #[test]
    fn k1_high_m_residual_loss_matches_theory() {
        // For k=1, the residual loss after FEC is p^(1+m).
        // With p=0.50 and m=3: residual = 0.0625 (6.25%).
        // With p=0.50 and m=20: residual = 0.0000009537 (negligible).
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        let mut rng = StdRng::seed_from_u64(13);
        let loss_rate = 0.50;

        // m=3
        let rs = ReedSolomon::new(1, 3).unwrap();
        let mut lost = 0;
        let trials = 2000;
        for _ in 0..trials {
            let src = vec![vec![rng.r#gen(); 8]];
            let parity = rs.encode(&src).unwrap();
            let mut all: Vec<Option<Vec<u8>>> = src.clone().into_iter().map(Some).collect();
            for p in &parity {
                all.push(Some(p.clone()));
            }
            for slot in &mut all {
                if rng.r#gen::<f64>() < loss_rate {
                    *slot = None;
                }
            }
            if rs.decode(&all).is_err() {
                lost += 1;
            }
        }
        let observed = lost as f64 / trials as f64;
        assert!(
            (observed - loss_rate.powi(4)).abs() < 0.05,
            "m=3 residual should be ~{:.4}, got {observed:.4}",
            loss_rate.powi(4)
        );

        // m=20
        let rs = ReedSolomon::new(1, 20).unwrap();
        let mut lost = 0;
        for _ in 0..trials {
            let src = vec![vec![rng.r#gen(); 8]];
            let parity = rs.encode(&src).unwrap();
            let mut all: Vec<Option<Vec<u8>>> = src.clone().into_iter().map(Some).collect();
            for p in &parity {
                all.push(Some(p.clone()));
            }
            for slot in &mut all {
                if rng.r#gen::<f64>() < loss_rate {
                    *slot = None;
                }
            }
            if rs.decode(&all).is_err() {
                lost += 1;
            }
        }
        let observed = lost as f64 / trials as f64;
        assert!(
            observed < 0.001,
            "m=20 residual at 50% loss should be ~0, got {observed:.4}"
        );
    }

    #[test]
    fn k4_m8_recovers_up_to_8_erasures() {
        // Verify the old default (k=4, m=8) still works correctly.
        // k+m=12, any 8 erasures recoverable.
        let rs = ReedSolomon::new(4, 8).unwrap();
        let src = vec![
            vec![0x11; 16],
            vec![0x22; 16],
            vec![0x33; 16],
            vec![0x44; 16],
        ];
        let parity = rs.encode(&src).unwrap();
        assert_eq!(parity.len(), 8);
        // Erase all 8 parities -> still recoverable (all data present).
        let mut all: Vec<Option<Vec<u8>>> = src.clone().into_iter().map(Some).collect();
        for _ in 0..8 {
            all.push(None);
        }
        let out = rs.decode(&all).unwrap();
        assert_eq!(out, src, "all parities lost, all data present");
        // Erase 4 data and 4 parities -> need 4 parities, have 4. OK.
        let mut all2: Vec<Option<Vec<u8>>> = src.clone().into_iter().map(Some).collect();
        for p in &parity {
            all2.push(Some(p.clone()));
        }
        for i in 0..4 {
            all2[i] = None; // erase data 0..4
        }
        for i in 5..9 {
            all2[i] = None; // erase parities 1..5 (keep 0)
        }
        // Present: data 1,2,3 (3 data) + parity 0 (1 parity) = 4 = k. OK.
        let out = rs.decode(&all2).unwrap();
        assert_eq!(out, src);
    }

    #[test]
    fn k1_m1_minimum_redundancy_recovers_one_loss() {
        // k=1, m=1: 2 symbols, any 1 survives. Exactly 50% loss tolerance.
        let rs = ReedSolomon::new(1, 1).unwrap();
        let src = vec![vec![0xCD]];
        let parity = rs.encode(&src).unwrap();
        // Data lost, parity survives.
        let all = vec![None, Some(parity[0].clone())];
        let out = rs.decode(&all).unwrap();
        assert_eq!(out, src);
        // Data survives, parity lost.
        let all = vec![Some(src[0].clone()), None];
        let out = rs.decode(&all).unwrap();
        assert_eq!(out, src);
        // Both lost: unrecoverable.
        let all = vec![None, None];
        assert!(rs.decode(&all).is_err());
    }

    #[test]
    fn k1_m2_recovers_two_consecutive_losses() {
        // k=1, m=2: with m=1 a data+parity pair that's both dropped (consecutive
        // burst) is unrecoverable; the extra twin here must survive such a burst.
        let rs = ReedSolomon::new(1, 2).unwrap();
        let src = vec![vec![0xAB; 8]];
        let parity = rs.encode(&src).unwrap();
        assert_eq!(parity.len(), 2, "k=1 m=2 emits two parity symbols");

        // 2-burst: data + parity1 lost, only parity2 survives -> recovered.
        let all = vec![None, None, Some(parity[1].clone())];
        let out = rs.decode(&all).unwrap();
        assert_eq!(out, src, "k=1 m=2 must survive a 2-datagram burst");

        // 1-burst: data + parity2 lost, parity1 survives -> recovered.
        let all = vec![None, Some(parity[0].clone()), None];
        let out = rs.decode(&all).unwrap();
        assert_eq!(out, src);

        // data + both parity lost -> unrecoverable (3-burst, beyond m=2).
        let all: Vec<Option<Vec<u8>>> = vec![None, None, None];
        assert!(
            rs.decode(&all).is_err(),
            "all three lost must remain unrecoverable"
        );

        // Full group present: recovered (and unchanged).
        let all = vec![
            Some(src[0].clone()),
            Some(parity[0].clone()),
            Some(parity[1].clone()),
        ];
        let out = rs.decode(&all).unwrap();
        assert_eq!(out, src);
    }
}
