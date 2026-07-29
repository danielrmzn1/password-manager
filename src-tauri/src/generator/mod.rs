//! Password and passphrase generation.
//!
//! Every random choice comes from [`crate::crypto::random`], which draws from the
//! OS CSPRNG and samples uniformly by rejection (no modulo bias). Generation
//! happens in Rust, never in the webview.

pub mod wordlist;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::random;
use crate::error::{AppError, Result};

/// A sensible default special-character set: broadly accepted by websites,
/// avoiding quotes/backslashes that tend to break naive input handling.
pub const DEFAULT_SYMBOLS: &str = "!@#$%^&*()-_=+[]{}?";

/// Every ASCII punctuation character, offered to the UI so the user can pick
/// exactly which specials to allow.
pub const ALL_SYMBOLS: &str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

/// Characters that are easily confused with one another in common fonts.
pub const AMBIGUOUS: &str = "0O1lI";

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";

pub const MIN_LENGTH: usize = 4;
pub const MAX_LENGTH: usize = 256;
pub const MIN_WORDS: usize = 3;
pub const MAX_WORDS: usize = 24;
pub const MAX_SEPARATOR_LEN: usize = 8;

/// Minimum master password length. A master password is the single thing
/// standing between an attacker with the vault file and every secret in it, so
/// the floor here is higher than for an ordinary account password.
pub const MIN_MASTER_PASSWORD_LEN: usize = 12;
/// Minimum acceptable zxcvbn score (0-4) for a master password.
pub const MIN_MASTER_PASSWORD_SCORE: u8 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum GeneratorOptions {
    Characters(CharacterOptions),
    Passphrase(PassphraseOptions),
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self::Characters(CharacterOptions::default())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharacterOptions {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Exactly which special characters are allowed. Ignored when `symbols` is
    /// false. Duplicates are collapsed so they cannot skew the distribution.
    pub symbol_set: String,
    /// Drop `0O1lI` from every pool.
    pub exclude_ambiguous: bool,
    /// Guarantee at least one character from each enabled class.
    pub require_each_class: bool,
}

impl Default for CharacterOptions {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            symbol_set: DEFAULT_SYMBOLS.to_string(),
            exclude_ambiguous: false,
            require_each_class: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Capitalization {
    #[default]
    Lowercase,
    /// First letter of each word capitalized.
    Titlecase,
    Uppercase,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassphraseOptions {
    pub word_count: usize,
    pub separator: String,
    pub capitalization: Capitalization,
    /// Append a random digit to one randomly chosen word.
    pub include_number: bool,
    /// Append a random special character to one randomly chosen word.
    pub include_symbol: bool,
    pub symbol_set: String,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            word_count: 6,
            separator: "-".to_string(),
            capitalization: Capitalization::Lowercase,
            include_number: false,
            include_symbol: false,
            symbol_set: DEFAULT_SYMBOLS.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Strength {
    VeryWeak,
    Weak,
    Fair,
    Strong,
    VeryStrong,
}

/// Map bits of entropy onto a coarse label.
///
/// Thresholds follow the usual guidance: ~60 bits resists a determined online
/// attacker, ~80 bits resists sustained offline cracking of a well-hashed
/// credential.
pub fn strength_from_bits(bits: f64) -> Strength {
    if bits < 28.0 {
        Strength::VeryWeak
    } else if bits < 36.0 {
        Strength::Weak
    } else if bits < 60.0 {
        Strength::Fair
    } else if bits < 80.0 {
        Strength::Strong
    } else {
        Strength::VeryStrong
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratedSecret {
    pub value: String,
    pub entropy_bits: f64,
    pub strength: Strength,
    /// Size of the alphabet actually used (character mode) or of the wordlist
    /// (passphrase mode). Shown in the UI to explain the entropy figure.
    pub pool_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratorPreset {
    pub id: Uuid,
    pub name: String,
    pub options: GeneratorOptions,
    #[serde(default)]
    pub created_at: i64,
}

/// Deduplicate while preserving order, and optionally drop ambiguous glyphs.
fn build_pool(source: &str, exclude_ambiguous: bool) -> Vec<char> {
    let mut seen = std::collections::HashSet::new();
    source
        .chars()
        .filter(|c| !exclude_ambiguous || !AMBIGUOUS.contains(*c))
        .filter(|c| seen.insert(*c))
        .collect()
}

pub fn generate(options: &GeneratorOptions) -> Result<GeneratedSecret> {
    match options {
        GeneratorOptions::Characters(o) => generate_characters(o),
        GeneratorOptions::Passphrase(o) => generate_passphrase(o),
    }
}

pub fn generate_characters(options: &CharacterOptions) -> Result<GeneratedSecret> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&options.length) {
        return Err(AppError::InvalidOptions(format!(
            "length must be between {MIN_LENGTH} and {MAX_LENGTH}"
        )));
    }

    // Each enabled class contributes a pool. Classes whose pool is emptied by
    // the ambiguous filter are an error rather than a silent no-op, so the user
    // is never quietly given a weaker alphabet than they asked for.
    let mut pools: Vec<Vec<char>> = Vec::new();
    for (enabled, source, name) in [
        (options.lowercase, LOWERCASE, "lowercase"),
        (options.uppercase, UPPERCASE, "uppercase"),
        (options.digits, DIGITS, "digits"),
        (options.symbols, options.symbol_set.as_str(), "symbols"),
    ] {
        if !enabled {
            continue;
        }
        let pool = build_pool(source, options.exclude_ambiguous);
        if pool.is_empty() {
            return Err(AppError::InvalidOptions(format!(
                "the {name} character set is empty after applying your exclusions"
            )));
        }
        pools.push(pool);
    }

    if pools.is_empty() {
        return Err(AppError::InvalidOptions(
            "enable at least one character type".into(),
        ));
    }

    // Union of all enabled pools, deduplicated so a symbol set that overlaps
    // another class cannot distort the entropy figure.
    let combined = {
        let mut seen = std::collections::HashSet::new();
        let mut v = Vec::new();
        for c in pools.iter().flatten().copied() {
            if seen.insert(c) {
                v.push(c);
            }
        }
        v
    };

    if options.require_each_class && options.length < pools.len() {
        return Err(AppError::InvalidOptions(format!(
            "length must be at least {} to include one of each selected type",
            pools.len()
        )));
    }

    let mut chars: Vec<char> = Vec::with_capacity(options.length);
    if options.require_each_class {
        for pool in &pools {
            chars.push(random::choose(pool)?);
        }
    }
    while chars.len() < options.length {
        chars.push(random::choose(&combined)?);
    }
    // Without this, the guaranteed one-per-class characters would always sit at
    // the front in a fixed class order.
    random::shuffle(&mut chars)?;

    // Entropy for a uniform draw over the combined alphabet. With
    // `require_each_class` the true figure is marginally lower, because
    // strings missing a class are excluded; the difference is well under a bit
    // at realistic lengths, and reporting the unconstrained value is the
    // conventional choice.
    let entropy_bits = options.length as f64 * (combined.len() as f64).log2();

    Ok(GeneratedSecret {
        value: chars.into_iter().collect(),
        entropy_bits,
        strength: strength_from_bits(entropy_bits),
        pool_size: combined.len(),
    })
}

pub fn generate_passphrase(options: &PassphraseOptions) -> Result<GeneratedSecret> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&options.word_count) {
        return Err(AppError::InvalidOptions(format!(
            "word count must be between {MIN_WORDS} and {MAX_WORDS}"
        )));
    }
    if options.separator.chars().count() > MAX_SEPARATOR_LEN {
        return Err(AppError::InvalidOptions(format!(
            "separator must be at most {MAX_SEPARATOR_LEN} characters"
        )));
    }

    let words = wordlist::words();
    let mut chosen: Vec<String> = Vec::with_capacity(options.word_count);
    for _ in 0..options.word_count {
        // Sampling *with* replacement. Excluding already-used words would
        // reduce entropy, not increase it.
        let idx = random::uniform_below(words.len() as u32)? as usize;
        chosen.push(apply_capitalization(words[idx], options.capitalization));
    }

    let mut entropy_bits = options.word_count as f64 * wordlist::bits_per_word();

    if options.include_number {
        let digit = random::uniform_below(10)?;
        let target = random::uniform_below(options.word_count as u32)? as usize;
        chosen[target].push_str(&digit.to_string());
        // Only the digit's own entropy is counted. The position is random too,
        // but an attacker knows the scheme, so counting it would be optimistic.
        entropy_bits += 10f64.log2();
    }

    if options.include_symbol {
        let pool = build_pool(&options.symbol_set, false);
        if pool.is_empty() {
            return Err(AppError::InvalidOptions(
                "choose at least one special character".into(),
            ));
        }
        let symbol = random::choose(&pool)?;
        let target = random::uniform_below(options.word_count as u32)? as usize;
        chosen[target].push(symbol);
        entropy_bits += (pool.len() as f64).log2();
    }

    Ok(GeneratedSecret {
        value: chosen.join(&options.separator),
        entropy_bits,
        strength: strength_from_bits(entropy_bits),
        pool_size: words.len(),
    })
}

fn apply_capitalization(word: &str, mode: Capitalization) -> String {
    match mode {
        Capitalization::Lowercase => word.to_string(),
        Capitalization::Uppercase => word.to_uppercase(),
        Capitalization::Titlecase => {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        }
    }
}

/// Character sets and limits, handed to the UI so it does not hard-code them.
#[derive(Debug, Clone, Serialize)]
pub struct GeneratorCapabilities {
    pub all_symbols: String,
    pub default_symbols: String,
    pub ambiguous: String,
    pub min_length: usize,
    pub max_length: usize,
    pub min_words: usize,
    pub max_words: usize,
    pub wordlist_size: usize,
    pub bits_per_word: f64,
    pub min_master_password_length: usize,
}

pub fn capabilities() -> GeneratorCapabilities {
    GeneratorCapabilities {
        all_symbols: ALL_SYMBOLS.to_string(),
        default_symbols: DEFAULT_SYMBOLS.to_string(),
        ambiguous: AMBIGUOUS.to_string(),
        min_length: MIN_LENGTH,
        max_length: MAX_LENGTH,
        min_words: MIN_WORDS,
        max_words: MAX_WORDS,
        wordlist_size: wordlist::words().len(),
        bits_per_word: wordlist::bits_per_word(),
        min_master_password_length: MIN_MASTER_PASSWORD_LEN,
    }
}

// ---------------------------------------------------------------------------
// Master password strength assessment
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct PasswordAssessment {
    /// zxcvbn score, 0 (worst) to 4 (best).
    pub score: u8,
    pub entropy_bits: f64,
    pub strength: Strength,
    /// Whether this password clears the minimum policy for a master password.
    pub acceptable: bool,
    /// Why it was rejected, when `acceptable` is false.
    pub problems: Vec<String>,
    /// zxcvbn's canned advice. These are fixed strings from the library and
    /// never contain the password itself.
    pub warning: Option<String>,
    pub suggestions: Vec<String>,
}

/// Assess a candidate master password.
///
/// Runs entirely in-process — nothing is hashed, logged or transmitted. The
/// password is not retained past this call.
pub fn assess_master_password(password: &str) -> PasswordAssessment {
    let estimate = zxcvbn::zxcvbn(password, &[]);
    let score: u8 = u8::from(estimate.score());

    // zxcvbn reports guesses; convert to bits for a single consistent scale
    // across generated and user-chosen passwords.
    let entropy_bits = estimate.guesses_log10() * std::f64::consts::LOG2_10;

    let mut problems = Vec::new();
    let char_count = password.chars().count();
    if char_count < MIN_MASTER_PASSWORD_LEN {
        problems.push(format!(
            "Use at least {MIN_MASTER_PASSWORD_LEN} characters (currently {char_count})."
        ));
    }
    if score < MIN_MASTER_PASSWORD_SCORE {
        problems.push("Too easy to guess — avoid common words, names and patterns.".to_string());
    }

    let feedback = estimate.feedback();
    let warning = feedback.and_then(|f| f.warning()).map(|w| w.to_string());
    let suggestions = feedback
        .map(|f| f.suggestions().iter().map(|s| s.to_string()).collect())
        .unwrap_or_default();

    PasswordAssessment {
        score,
        entropy_bits,
        strength: strength_from_bits(entropy_bits),
        acceptable: problems.is_empty(),
        problems,
        warning,
        suggestions,
    }
}

/// Enforce the master password policy, for use at the point of setting one.
pub fn enforce_master_password_policy(password: &str) -> Result<()> {
    let assessment = assess_master_password(password);
    if assessment.acceptable {
        return Ok(());
    }
    Err(AppError::WeakMasterPassword(assessment.problems.join(" ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- character mode ----------------------------------------------------

    #[test]
    fn respects_length_and_alphabet() {
        let opts = CharacterOptions {
            length: 32,
            ..Default::default()
        };
        let out = generate_characters(&opts).unwrap();
        assert_eq!(out.value.chars().count(), 32);
        for c in out.value.chars() {
            assert!(
                c.is_ascii_alphanumeric() || DEFAULT_SYMBOLS.contains(c),
                "unexpected character {c:?}"
            );
        }
    }

    #[test]
    fn only_uses_enabled_classes() {
        let opts = CharacterOptions {
            length: 64,
            uppercase: false,
            lowercase: true,
            digits: false,
            symbols: false,
            require_each_class: true,
            ..Default::default()
        };
        let out = generate_characters(&opts).unwrap();
        assert!(out.value.chars().all(|c| c.is_ascii_lowercase()));
        assert_eq!(out.pool_size, 26);
    }

    #[test]
    fn honours_a_custom_symbol_set() {
        let opts = CharacterOptions {
            length: 40,
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: true,
            symbol_set: "#%&".into(),
            ..Default::default()
        };
        let out = generate_characters(&opts).unwrap();
        assert!(out.value.chars().all(|c| "#%&".contains(c)));
        assert_eq!(out.pool_size, 3);
    }

    #[test]
    fn excludes_ambiguous_characters_when_asked() {
        let opts = CharacterOptions {
            length: 200,
            exclude_ambiguous: true,
            symbols: false,
            ..Default::default()
        };
        let out = generate_characters(&opts).unwrap();
        for c in out.value.chars() {
            assert!(!AMBIGUOUS.contains(c), "ambiguous character {c:?} leaked");
        }
        // 26 + 26 + 10 minus the five ambiguous glyphs.
        assert_eq!(out.pool_size, 57);
    }

    #[test]
    fn require_each_class_covers_every_class() {
        let opts = CharacterOptions {
            length: 4,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            symbol_set: "!".into(),
            require_each_class: true,
            exclude_ambiguous: false,
        };
        // At length == class count, every class must appear exactly once.
        for _ in 0..100 {
            let v = generate_characters(&opts).unwrap().value;
            assert!(v.chars().any(|c| c.is_ascii_lowercase()), "{v}");
            assert!(v.chars().any(|c| c.is_ascii_uppercase()), "{v}");
            assert!(v.chars().any(|c| c.is_ascii_digit()), "{v}");
            assert!(v.contains('!'), "{v}");
        }
    }

    #[test]
    fn guaranteed_characters_are_not_left_in_class_order() {
        // Without the shuffle, position 0 would always be lowercase.
        let opts = CharacterOptions {
            length: 4,
            symbol_set: "!".into(),
            require_each_class: true,
            ..Default::default()
        };
        let mut first_chars = std::collections::HashSet::new();
        for _ in 0..200 {
            let v = generate_characters(&opts).unwrap().value;
            first_chars.insert(v.chars().next().unwrap().is_ascii_lowercase());
        }
        assert_eq!(first_chars.len(), 2, "output does not look shuffled");
    }

    #[test]
    fn rejects_impossible_configurations() {
        let no_classes = CharacterOptions {
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        assert!(generate_characters(&no_classes).is_err());

        let empty_symbols = CharacterOptions {
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: true,
            symbol_set: String::new(),
            ..Default::default()
        };
        assert!(generate_characters(&empty_symbols).is_err());

        let too_short = CharacterOptions {
            length: 1,
            ..Default::default()
        };
        assert!(generate_characters(&too_short).is_err());

        let too_long = CharacterOptions {
            length: MAX_LENGTH + 1,
            ..Default::default()
        };
        assert!(generate_characters(&too_long).is_err());

        // Four classes requested but only three slots.
        let cannot_cover = CharacterOptions {
            length: 3,
            require_each_class: true,
            symbol_set: "!".into(),
            ..Default::default()
        };
        assert!(generate_characters(&cannot_cover).is_err());

        // Digits enabled but every digit is ambiguous-excluded... only 0 and 1
        // are, so this must still succeed; the empty-pool error is reachable
        // through a symbol set made entirely of ambiguous characters.
        let emptied = CharacterOptions {
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: true,
            symbol_set: "0O1lI".into(),
            exclude_ambiguous: true,
            ..Default::default()
        };
        assert!(generate_characters(&emptied).is_err());
    }

    #[test]
    fn duplicate_symbols_do_not_inflate_the_pool() {
        let opts = CharacterOptions {
            length: 10,
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: true,
            symbol_set: "!!!@@@".into(),
            ..Default::default()
        };
        assert_eq!(generate_characters(&opts).unwrap().pool_size, 2);
    }

    #[test]
    fn overlapping_symbol_set_does_not_double_count() {
        // 'a' appears in both the lowercase pool and the symbol set.
        let opts = CharacterOptions {
            length: 10,
            lowercase: true,
            uppercase: false,
            digits: false,
            symbols: true,
            symbol_set: "a!".into(),
            ..Default::default()
        };
        // 26 lowercase + '!' only.
        assert_eq!(generate_characters(&opts).unwrap().pool_size, 27);
    }

    #[test]
    fn entropy_matches_the_alphabet_size() {
        let opts = CharacterOptions {
            length: 10,
            lowercase: true,
            uppercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        let out = generate_characters(&opts).unwrap();
        assert!((out.entropy_bits - 10.0 * 26f64.log2()).abs() < 1e-9);
    }

    #[test]
    fn generated_values_differ() {
        let opts = CharacterOptions::default();
        let a = generate_characters(&opts).unwrap().value;
        let b = generate_characters(&opts).unwrap().value;
        assert_ne!(a, b);
    }

    // -- passphrase mode ---------------------------------------------------

    #[test]
    fn passphrase_has_the_requested_shape() {
        let opts = PassphraseOptions {
            word_count: 5,
            separator: "-".into(),
            ..Default::default()
        };
        let out = generate_passphrase(&opts).unwrap();
        assert_eq!(out.value.split('-').count(), 5);
        assert!((out.entropy_bits - 5.0 * 12.925).abs() < 0.01);
    }

    #[test]
    fn passphrase_capitalization_modes() {
        let title = generate_passphrase(&PassphraseOptions {
            capitalization: Capitalization::Titlecase,
            separator: " ".into(),
            ..Default::default()
        })
        .unwrap()
        .value;
        for word in title.split(' ') {
            assert!(word.chars().next().unwrap().is_ascii_uppercase(), "{title}");
        }

        let upper = generate_passphrase(&PassphraseOptions {
            capitalization: Capitalization::Uppercase,
            ..Default::default()
        })
        .unwrap()
        .value;
        assert_eq!(upper, upper.to_uppercase());

        let lower = generate_passphrase(&PassphraseOptions {
            capitalization: Capitalization::Lowercase,
            ..Default::default()
        })
        .unwrap()
        .value;
        assert_eq!(lower, lower.to_lowercase());
    }

    #[test]
    fn passphrase_injections_are_applied_and_counted() {
        let opts = PassphraseOptions {
            word_count: 4,
            separator: "-".into(),
            include_number: true,
            include_symbol: true,
            symbol_set: "!".into(),
            ..Default::default()
        };
        let out = generate_passphrase(&opts).unwrap();
        assert!(
            out.value.chars().any(|c| c.is_ascii_digit()),
            "{}",
            out.value
        );
        assert!(out.value.contains('!'), "{}", out.value);

        let expected = 4.0 * 12.925 + 10f64.log2() + 1f64.log2();
        assert!((out.entropy_bits - expected).abs() < 0.01);
    }

    #[test]
    fn multi_character_separator_is_supported() {
        let out = generate_passphrase(&PassphraseOptions {
            word_count: 3,
            separator: " :: ".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(out.value.matches(" :: ").count(), 2);
    }

    #[test]
    fn empty_separator_is_allowed() {
        let out = generate_passphrase(&PassphraseOptions {
            word_count: 4,
            separator: String::new(),
            capitalization: Capitalization::Titlecase,
            ..Default::default()
        })
        .unwrap();
        assert!(!out.value.contains('-'));
        assert!(!out.value.is_empty());
    }

    #[test]
    fn rejects_bad_passphrase_options() {
        assert!(generate_passphrase(&PassphraseOptions {
            word_count: 1,
            ..Default::default()
        })
        .is_err());

        assert!(generate_passphrase(&PassphraseOptions {
            word_count: MAX_WORDS + 1,
            ..Default::default()
        })
        .is_err());

        assert!(generate_passphrase(&PassphraseOptions {
            separator: "x".repeat(MAX_SEPARATOR_LEN + 1),
            ..Default::default()
        })
        .is_err());

        assert!(generate_passphrase(&PassphraseOptions {
            include_symbol: true,
            symbol_set: String::new(),
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn passphrases_differ_between_calls() {
        let opts = PassphraseOptions::default();
        let a = generate_passphrase(&opts).unwrap().value;
        let b = generate_passphrase(&opts).unwrap().value;
        assert_ne!(a, b);
    }

    #[test]
    fn dispatch_through_the_enum_works() {
        assert!(generate(&GeneratorOptions::default()).unwrap().value.len() >= MIN_LENGTH);
        assert!(
            !generate(&GeneratorOptions::Passphrase(PassphraseOptions::default()))
                .unwrap()
                .value
                .is_empty()
        );
    }

    #[test]
    fn options_survive_a_json_round_trip() {
        // Presets are persisted in the vault payload, so this must be stable.
        for opts in [
            GeneratorOptions::Characters(CharacterOptions::default()),
            GeneratorOptions::Passphrase(PassphraseOptions::default()),
        ] {
            let json = serde_json::to_string(&opts).unwrap();
            let back: GeneratorOptions = serde_json::from_str(&json).unwrap();
            assert_eq!(
                serde_json::to_string(&back).unwrap(),
                json,
                "round trip changed the options"
            );
        }
        assert!(serde_json::to_string(&GeneratorOptions::default())
            .unwrap()
            .contains("\"mode\":\"characters\""));
    }

    // -- strength ----------------------------------------------------------

    #[test]
    fn strength_thresholds() {
        assert_eq!(strength_from_bits(10.0), Strength::VeryWeak);
        assert_eq!(strength_from_bits(30.0), Strength::Weak);
        assert_eq!(strength_from_bits(45.0), Strength::Fair);
        assert_eq!(strength_from_bits(70.0), Strength::Strong);
        assert_eq!(strength_from_bits(128.0), Strength::VeryStrong);
    }

    #[test]
    fn master_password_policy_rejects_weak_choices() {
        for weak in ["short", "password", "123456789012", "aaaaaaaaaaaa"] {
            let a = assess_master_password(weak);
            assert!(!a.acceptable, "{weak:?} should be rejected: {a:?}");
            assert!(enforce_master_password_policy(weak).is_err());
        }
    }

    #[test]
    fn master_password_policy_accepts_a_strong_passphrase() {
        let strong = generate_passphrase(&PassphraseOptions {
            word_count: 6,
            ..Default::default()
        })
        .unwrap()
        .value;
        let a = assess_master_password(&strong);
        assert!(a.acceptable, "{strong:?} rejected: {a:?}");
        assert!(a.entropy_bits > 40.0);
        assert!(enforce_master_password_policy(&strong).is_ok());
    }

    #[test]
    fn assessment_never_echoes_the_password() {
        let password = "correct-horse-battery-staple";
        let a = assess_master_password(password);
        let json = serde_json::to_string(&a).unwrap();
        assert!(
            !json.contains(password),
            "assessment leaked the password: {json}"
        );
    }

    #[test]
    fn long_password_does_not_blow_up() {
        // zxcvbn is superlinear in input length; make sure a paste of nonsense
        // cannot wedge the UI thread.
        let a = assess_master_password(&"a1!Bc".repeat(40));
        assert!(a.entropy_bits >= 0.0);
    }

    #[test]
    fn capabilities_are_self_consistent() {
        let c = capabilities();
        assert_eq!(c.wordlist_size, wordlist::EXPECTED_LEN);
        assert!(c
            .default_symbols
            .chars()
            .all(|ch| c.all_symbols.contains(ch)));
        assert!(c.min_length < c.max_length);
    }
}
