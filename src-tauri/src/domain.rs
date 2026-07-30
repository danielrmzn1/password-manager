//! Host extraction and matching for the browser extension.
//!
//! This decides which stored credentials get offered to a page, so a loose match
//! here is a credential-disclosure bug. The rules are intentionally strict:
//! matching happens on whole DNS labels, never on raw substrings, so
//! `notexample.com` can never match an entry saved for `example.com`.

/// Extract the lowercase host from a URL or a bare hostname.
///
/// Handles missing schemes, userinfo, ports, IPv6 literals and trailing dots.
/// Returns `None` when no plausible host is present.
pub fn host_of(input: &str) -> Option<String> {
    let mut rest = input.trim();
    if rest.is_empty() {
        return None;
    }

    // Strip the scheme, if any.
    //
    // `://` is only a scheme separator when it appears *before* the first path
    // separator. Searching the whole string would misread
    // `example.com/redirect?to=https://elsewhere.test` as having host
    // `elsewhere.test`.
    let scheme_end = rest.find("://").filter(|idx| {
        rest[..*idx]
            .find(['/', '?', '#'])
            .is_none_or(|sep| sep > *idx)
    });
    if let Some(idx) = scheme_end {
        rest = &rest[idx + 3..];
    } else if let Some(stripped) = rest.strip_prefix("//") {
        rest = stripped;
    }

    // Cut off path, query and fragment.
    rest = rest.split(['/', '?', '#']).next().unwrap_or_default();

    // Strip userinfo. `rfind` because a password may itself contain '@'.
    if let Some(idx) = rest.rfind('@') {
        rest = &rest[idx + 1..];
    }

    if rest.is_empty() {
        return None;
    }

    // An IPv6 literal is bracketed; the colons inside it are not a port.
    let host = if let Some(end) = rest.find(']') {
        if rest.starts_with('[') {
            &rest[..=end]
        } else {
            return None;
        }
    } else {
        // Strip a port.
        rest.split(':').next().unwrap_or_default()
    };

    // A trailing dot is a legal fully-qualified form; normalize it away so
    // `example.com.` and `example.com` compare equal.
    let host = host.trim_end_matches('.').to_ascii_lowercase();

    if host.is_empty() || host.contains(' ') {
        return None;
    }
    Some(host)
}

/// Whether a host looks like an IP literal, which must only ever match exactly.
fn is_ip_literal(host: &str) -> bool {
    if host.starts_with('[') {
        return true;
    }
    // IPv4: four numeric labels. Anything all-numeric-and-dots is treated as an
    // IP for matching purposes, which is the conservative choice.
    !host.is_empty() && host.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Whether a credential stored against `entry_url` should be offered for a page
/// on `target_host`.
///
/// True when the entry's host equals the target host, or is a parent domain of
/// it at a label boundary (`example.com` matches `login.example.com`).
pub fn matches_host(entry_url: &str, target_host: &str) -> bool {
    let Some(entry_host) = host_of(entry_url) else {
        return false;
    };
    let Some(target) = host_of(target_host) else {
        return false;
    };

    if entry_host == target {
        return true;
    }

    // IP addresses and `localhost` have no domain hierarchy to walk.
    if is_ip_literal(&entry_host) || is_ip_literal(&target) || entry_host == "localhost" {
        return false;
    }

    // A single-label entry host (`com`, `internal`) would match far too much, so
    // it only ever matches exactly.
    //
    // Note: without a Public Suffix List this cannot tell `co.uk` from
    // `example.com`, so an entry saved against a bare public suffix such as
    // `co.uk` would match any host under it. Entry URLs come from the user's own
    // vault, so this is a usability edge case rather than an attack surface —
    // the attacker-controlled side is `target_host`, which is fully guarded by
    // the label-boundary check below.
    if !entry_host.contains('.') {
        return false;
    }

    // The label boundary is what makes this safe: requiring the '.' means
    // `notexample.com` does not end with `.example.com`.
    target.ends_with(&format!(".{entry_host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_hosts_from_realistic_urls() {
        let cases = [
            ("https://example.com", "example.com"),
            ("https://example.com/", "example.com"),
            ("http://example.com/login?next=/a#f", "example.com"),
            ("https://login.example.co.uk/path", "login.example.co.uk"),
            ("example.com", "example.com"),
            ("example.com/login", "example.com"),
            ("//example.com/x", "example.com"),
            ("https://EXAMPLE.COM", "example.com"),
            ("https://example.com.", "example.com"),
            ("https://example.com:8443/x", "example.com"),
            ("https://user:pass@example.com/x", "example.com"),
            ("https://user:p@ss@example.com/x", "example.com"),
            ("https://127.0.0.1:9000", "127.0.0.1"),
            ("http://[::1]:9000/x", "[::1]"),
            ("  https://example.com  ", "example.com"),
        ];
        for (input, expected) in cases {
            assert_eq!(host_of(input).as_deref(), Some(expected), "input: {input}");
        }
    }

    /// A `://` inside a path or query must not be mistaken for the scheme
    /// separator — otherwise a stored URL with a redirect parameter resolves to
    /// the redirect target's host.
    #[test]
    fn scheme_separator_inside_a_path_or_query_is_ignored() {
        assert_eq!(
            host_of("example.com/redirect?to=https://elsewhere.test").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            host_of("https://example.com/r?to=https://elsewhere.test").as_deref(),
            Some("example.com")
        );
        assert_eq!(host_of("example.com/a://b").as_deref(), Some("example.com"));
        // And the credential must not be offered for the redirect target.
        assert!(!matches_host(
            "example.com/redirect?to=https://elsewhere.test",
            "elsewhere.test"
        ));
        assert!(matches_host(
            "example.com/redirect?to=https://elsewhere.test",
            "example.com"
        ));
    }

    #[test]
    fn rejects_inputs_with_no_host() {
        for input in ["", "   ", "https://", "//", "https:///path", "http://:8080"] {
            assert_eq!(host_of(input), None, "input: {input:?}");
        }
    }

    #[test]
    fn exact_host_matches() {
        assert!(matches_host("https://example.com", "example.com"));
        assert!(matches_host("https://example.com/login", "example.com"));
        assert!(matches_host("example.com", "EXAMPLE.COM"));
    }

    #[test]
    fn subdomains_of_a_saved_domain_match() {
        assert!(matches_host("https://example.com", "login.example.com"));
        assert!(matches_host("https://example.com", "a.b.example.com"));
        assert!(matches_host("https://example.co.uk", "shop.example.co.uk"));
    }

    /// The core anti-phishing property.
    #[test]
    fn lookalike_hosts_never_match() {
        assert!(!matches_host("https://example.com", "notexample.com"));
        assert!(!matches_host("https://example.com", "example.com.evil.com"));
        assert!(!matches_host("https://example.com", "examplecom"));
        assert!(!matches_host("https://example.com", "example.co"));
        assert!(!matches_host("https://example.com", "myexample.com"));
        assert!(!matches_host("https://bank.com", "bank.com.attacker.net"));
    }

    #[test]
    fn a_more_specific_entry_does_not_match_a_broader_host() {
        // A credential saved for the login subdomain should not be offered on
        // the apex domain.
        assert!(!matches_host("https://login.example.com", "example.com"));
    }

    #[test]
    fn single_label_entries_only_match_exactly() {
        assert!(!matches_host("https://com", "example.com"));
        assert!(!matches_host("http://internal", "host.internal"));
        assert!(matches_host("http://internal", "internal"));
    }

    #[test]
    fn localhost_and_ip_literals_match_exactly_only() {
        assert!(matches_host("http://localhost:3000", "localhost"));
        assert!(!matches_host("http://localhost", "app.localhost"));

        assert!(matches_host("http://127.0.0.1:9000", "127.0.0.1"));
        assert!(!matches_host("http://127.0.0.1", "1.127.0.0.1"));
        assert!(!matches_host("http://10.0.0.1", "10.0.0.10"));

        assert!(matches_host("http://[::1]:9000", "[::1]"));
        assert!(!matches_host("http://[::1]", "a.[::1]"));
    }

    #[test]
    fn empty_and_malformed_inputs_never_match() {
        assert!(!matches_host("", "example.com"));
        assert!(!matches_host("https://example.com", ""));
        assert!(!matches_host("not a url", "example.com"));
        assert!(!matches_host("https://", "example.com"));
    }

    #[test]
    fn port_and_scheme_differences_do_not_prevent_a_match() {
        // Matching is host-based; a credential is not scoped to a port.
        assert!(matches_host("http://example.com:8080", "example.com"));
        assert!(matches_host("https://example.com", "example.com"));
    }
}
