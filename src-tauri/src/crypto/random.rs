//! All randomness in the application funnels through this module.
//!
//! It draws straight from the OS CSPRNG via `getrandom` — there is no userspace
//! PRNG state to seed, fork, or leak. `Math.random()` and any non-cryptographic
//! generator are forbidden project-wide (see AGENTS.md).

use crate::error::Result;

/// Fill `buf` with cryptographically secure random bytes.
pub fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf)?;
    Ok(())
}

/// A fixed-size array of cryptographically secure random bytes.
pub fn bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

/// A uniformly distributed integer in `[0, n)`.
///
/// Uses rejection sampling rather than the naive `rand % n`, which is biased
/// toward small values whenever `n` does not divide 2^32. For password
/// generation that bias is a real entropy loss, so it is worth the loop.
pub fn uniform_below(n: u32) -> Result<u32> {
    assert!(n > 0, "uniform_below(0) is undefined");

    // `rem` = 2^32 mod n, computed without overflowing u32.
    let rem = ((u32::MAX % n) + 1) % n;
    // Reject the top `rem` values so the accepted range is an exact multiple of
    // `n`. When `rem == 0` this accepts everything, which is correct.
    let max_accept = u32::MAX - rem;

    loop {
        let v = u32::from_le_bytes(bytes::<4>()?);
        if v <= max_accept {
            return Ok(v % n);
        }
    }
}

/// Pick a uniformly random element of `slice`.
pub fn choose<T: Copy>(slice: &[T]) -> Result<T> {
    debug_assert!(!slice.is_empty());
    let idx = uniform_below(slice.len() as u32)? as usize;
    Ok(slice[idx])
}

/// Fisher-Yates shuffle driven by the OS CSPRNG.
pub fn shuffle<T>(slice: &mut [T]) -> Result<()> {
    for i in (1..slice.len()).rev() {
        let j = uniform_below((i + 1) as u32)? as usize;
        slice.swap(i, j);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_below_stays_in_range() {
        for n in [1u32, 2, 3, 7, 26, 64, 95, 7776] {
            for _ in 0..500 {
                assert!(uniform_below(n).unwrap() < n);
            }
        }
    }

    #[test]
    fn uniform_below_one_is_always_zero() {
        for _ in 0..50 {
            assert_eq!(uniform_below(1).unwrap(), 0);
        }
    }

    /// A crude uniformity smoke test: over 60k draws into 6 buckets, every
    /// bucket should land within ±25% of the 10k expectation. This would catch
    /// a modulo-bias regression or an off-by-one in the rejection bound.
    #[test]
    fn uniform_below_is_roughly_flat() {
        let mut counts = [0u32; 6];
        for _ in 0..60_000 {
            counts[uniform_below(6).unwrap() as usize] += 1;
        }
        for c in counts {
            assert!(
                (7_500..=12_500).contains(&c),
                "bucket distribution looks biased: {counts:?}"
            );
        }
    }

    #[test]
    fn shuffle_is_a_permutation() {
        let mut v: Vec<u32> = (0..256).collect();
        shuffle(&mut v).unwrap();
        let mut sorted = v.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..256).collect::<Vec<_>>());
    }

    #[test]
    fn shuffle_handles_degenerate_lengths() {
        shuffle::<u8>(&mut []).unwrap();
        shuffle(&mut [1]).unwrap();
    }

    #[test]
    fn random_bytes_are_not_constant() {
        // Not a statistical test — just catches a stubbed-out RNG.
        let a = bytes::<32>().unwrap();
        let b = bytes::<32>().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
