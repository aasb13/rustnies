//! GF(256) arithmetic with the standard irreducible polynomial 0x11d
//! (x^8 + x^4 + x^3 + x^2 + 1), generator 2. This is the textbook field used
//! by Reed-Solomon implementations everywhere (e.g. the QR-code reference).

/// The field-reduction polynomial.
const POLY: u16 = 0x11d;

/// Log and exponent tables, plus a multiply helper. Tables are built once.
struct Gf256 {
    exp: [u8; 512],
    log: [u8; 256],
}

static GF: Gf256 = Gf256::new();

impl Gf256 {
    const fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x = 1u8;
        let mut i = 0;
        while i < 255 {
            exp[i] = x;
            log[x as usize] = i as u8;
            // x = x * 2 with reduction mod the irreducible polynomial.
            let hi = x & 0x80 != 0;
            x <<= 1;
            if hi {
                x ^= (POLY & 0xff) as u8;
            }
            i += 1;
        }
        // exp[i+255] = exp[i] so we can index without masking on the hot path.
        let mut i = 255;
        while i < 512 {
            exp[i] = exp[i - 255];
            i += 1;
        }
        // log[0] is undefined; leave 0.
        Self { exp, log }
    }

    #[inline]
    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp[self.log[a as usize] as usize + self.log[b as usize] as usize]
        }
    }

    #[inline]
    fn div(&self, a: u8, b: u8) -> u8 {
        if a == 0 {
            0
        } else if b == 0 {
            panic!("gf256 division by zero");
        } else {
            // exp[i+255] == exp[i] (the table is 512 entries), so indexing with
            // (255 + log[a] - log[b]) in [1, 509] yields the correct quotient
            // without any mod-256 masking. The previous `& 0xff` here was a
            // bug: it wrapped at 256 but the exponent cycles at 255, so e.g.
            // div(2, 1) returned 1 instead of 2.
            self.exp[255 + self.log[a as usize] as usize - self.log[b as usize] as usize]
        }
    }

    #[inline]
    fn inv(&self, a: u8) -> u8 {
        if a == 0 {
            panic!("gf256 inverse of zero");
        }
        self.exp[(255 - self.log[a as usize] as usize) & 0xff]
    }
}

#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    GF.mul(a, b)
}

#[inline]
pub fn div(a: u8, b: u8) -> u8 {
    GF.div(a, b)
}

#[inline]
pub fn inv(a: u8) -> u8 {
    GF.inv(a)
}

/// In-place Gaussian elimination over GF(256) for a square matrix `a` of size
/// `n`, with the right-hand side appended as an extra column (so `a` is `n x
/// (n+1)` stored row-major). Solves for `x` and writes it into `out` (length n).
/// Returns `Err` if singular.
pub fn solve_system(rows: &mut [Vec<u8>], n: usize) -> Result<Vec<u8>, &'static str> {
    if rows.len() != n {
        return Err("row count mismatch");
    }
    for r in 0..n {
        if rows[r].len() != n + 1 {
            return Err("column count mismatch");
        }
    }
    // Forward elimination with partial pivot.
    for col in 0..n {
        // find pivot
        let mut piv = None;
        for r in col..n {
            if rows[r][col] != 0 {
                piv = Some(r);
                break;
            }
        }
        let piv = piv.ok_or("singular matrix")?;
        if piv != col {
            rows.swap(col, piv);
        }
        let inv_p = inv(rows[col][col]);
        for j in col..=n {
            rows[col][j] = mul(rows[col][j], inv_p);
        }
        for r in 0..n {
            if r == col {
                continue;
            }
            let factor = rows[r][col];
            if factor == 0 {
                continue;
            }
            for j in col..=n {
                let v = mul(factor, rows[col][j]);
                rows[r][j] ^= v;
            }
        }
    }
    let mut out = Vec::with_capacity(n);
    for r in 0..n {
        out.push(rows[r][n]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_is_zero_if_either_operand_is_zero() {
        for a in 0..=255u8 {
            assert_eq!(mul(a, 0), 0, "a={a} * 0 == 0");
            assert_eq!(mul(0, a), 0, "0 * a={a} == 0");
        }
    }

    #[test]
    fn mul_one_is_identity() {
        for a in 0..=255u8 {
            assert_eq!(mul(a, 1), a, "a={a} * 1 == a");
            assert_eq!(mul(1, a), a, "1 * a={a} == a");
        }
    }

    #[test]
    fn mul_is_commutative() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(mul(a, b), mul(b, a), "mul({a},{b}) == mul({b},{a})");
            }
        }
    }

    #[test]
    fn mul_is_associative() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                for c in 0..=255u8 {
                    assert_eq!(
                        mul(mul(a, b), c),
                        mul(a, mul(b, c)),
                        "associativity a={a} b={b} c={c}"
                    );
                }
            }
        }
    }

    #[test]
    fn mul_is_distributive_over_xor() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                for c in 0..=255u8 {
                    assert_eq!(
                        mul(a, b ^ c),
                        mul(a, b) ^ mul(a, c),
                        "distributivity a={a} b={b} c={c}"
                    );
                }
            }
        }
    }

    #[test]
    fn inv_is_inverse_of_mul() {
        for a in 1..=255u8 {
            assert_eq!(mul(a, inv(a)), 1, "a * inv(a) == 1 for a={a}");
            assert_eq!(mul(inv(a), a), 1, "inv(a) * a == 1 for a={a}");
        }
    }

    #[test]
    fn div_is_mul_by_inverse() {
        for a in 1..=255u8 {
            assert_eq!(div(a, a), 1, "a / a == 1 for a={a}");
            assert_eq!(div(a, 1), a, "a / 1 == a for a={a}");
        }
    }

    #[test]
    #[should_panic(expected = "gf256 division by zero")]
    fn div_by_zero_panics() {
        let _ = div(1, 0);
    }

    #[test]
    #[should_panic(expected = "gf256 inverse of zero")]
    fn inv_of_zero_panics() {
        let _ = inv(0);
    }

    #[test]
    fn solve_system_identity_returns_rhs() {
        // 3x3 identity with rhs [10, 20, 30].
        let mut rows = vec![vec![1, 0, 0, 10], vec![0, 1, 0, 20], vec![0, 0, 1, 30]];
        let sol = solve_system(&mut rows, 3).unwrap();
        assert_eq!(sol, vec![10, 20, 30]);
    }

    #[test]
    fn solve_system_singular_returns_err() {
        // Two identical rows => singular.
        let mut rows = vec![vec![1, 2, 5], vec![1, 2, 5]];
        assert!(solve_system(&mut rows, 2).is_err());
    }

    #[test]
    fn solve_system_requires_pivot() {
        // First column has a zero in the diagonal position; partial pivot must
        // swap in a non-zero row. Matrix: [[0,1,3],[1,1,5]] -> x=[2,3].
        let mut rows = vec![vec![0, 1, 3], vec![1, 1, 5]];
        let sol = solve_system(&mut rows, 2).unwrap();
        // Verify by back-substitution: 0*2 + 1*3 = 3; 1*2 + 1*3 = 5. Correct.
        assert_eq!(mul(0, sol[0]) ^ mul(1, sol[1]), 3);
        assert_eq!(mul(1, sol[0]) ^ mul(1, sol[1]), 5);
    }

    #[test]
    fn solve_system_rejects_wrong_dimensions() {
        let mut rows = vec![vec![1, 2, 3], vec![4, 5, 6]];
        assert!(solve_system(&mut rows, 3).is_err(), "row count mismatch");
        let mut rows = vec![vec![1, 2], vec![4, 5]];
        assert!(solve_system(&mut rows, 2).is_err(), "column count mismatch");
    }
}
