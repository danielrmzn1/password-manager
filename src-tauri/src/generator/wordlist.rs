//! The EFF "large" diceware wordlist, embedded at compile time.
//!
//! Source: <https://www.eff.org/dice> (`eff_large_wordlist.txt`, 7776 words —
//! 5 dice rolls, log2(7776) ≈ 12.925 bits per word). The dice-roll column has
//! been stripped; only the words are stored, one per line.
//!
//! This list was chosen over the "short" lists because 12.9 bits/word means a
//! 6-word passphrase already clears 77 bits, and the words are filtered to avoid
//! profanity, homophones and confusable spellings.

use std::sync::OnceLock;

const RAW: &str = include_str!("eff_large_wordlist.txt");

/// Expected size of the EFF large wordlist: 6^5.
pub const EXPECTED_LEN: usize = 7776;

/// The wordlist, parsed once on first use.
pub fn words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        RAW.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect()
    })
}

/// Bits of entropy contributed by one uniformly chosen word.
pub fn bits_per_word() -> f64 {
    (words().len() as f64).log2()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_has_the_expected_size() {
        assert_eq!(words().len(), EXPECTED_LEN);
    }

    #[test]
    fn wordlist_has_no_duplicates() {
        let unique: std::collections::HashSet<_> = words().iter().collect();
        assert_eq!(unique.len(), words().len());
    }

    #[test]
    fn words_are_clean_and_usable() {
        for w in words() {
            assert!(w.len() >= 3, "suspiciously short word: {w:?}");
            assert!(
                w.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "unexpected characters in {w:?}"
            );
            assert!(!w.starts_with('-') && !w.ends_with('-'));
        }
    }

    #[test]
    fn entropy_per_word_matches_five_dice() {
        assert!((bits_per_word() - 12.925).abs() < 0.001);
    }

    /// Spot-check the endpoints against the published list, which catches a
    /// truncated or reordered asset.
    #[test]
    fn known_endpoints_are_present() {
        assert_eq!(words()[0], "abacus");
        assert_eq!(words()[EXPECTED_LEN - 1], "zoom");
    }
}
