//! Exhaustive unit tests for `ws_core::profile_match::san_is_permitted`
//! (the SAN pattern matcher).
//!
//! The matcher is pure and total over `(patterns, san)` — no database, no
//! I/O — so this suite needs no Postgres and is not `#[ignore]`-gated. It
//! pins every rule the matcher must implement:
//!
//! - a DNS pattern matches exactly that name (case-insensitively), never a
//!   subdomain;
//! - a `*.` pattern matches one or more additional labels, but not the
//!   bare suffix domain;
//! - an IP-literal pattern matches exactly that address;
//! - a CIDR pattern matches any IP in the range (version-matched);
//! - a bare `*` matches any DNS name but never an IP literal;
//! - an unparsable pattern is a typed [`CoreError::Config`], never a
//!   silent non-match.

use ws_core::error::CoreError;
use ws_core::profile_match::san_is_permitted;

/// Convenience wrapper: string slices in, bool out (unwrapping the
/// `Ok`/panic on error — errors are asserted separately).
fn perm(patterns: &[&str], san: &str) -> bool {
    let owned: Vec<String> = patterns.iter().map(|p| (*p).to_string()).collect();
    san_is_permitted(&owned, san).expect("pattern list should be well-formed")
}

/// A DNS pattern matches exactly that name and never a subdomain.
#[test]
fn dns_pattern_matches_exactly() {
    assert!(perm(&["example.com"], "example.com"));
    assert!(!perm(&["example.com"], "sub.example.com"));
    assert!(!perm(&["example.com"], "a.b.example.com"));
    assert!(!perm(&["example.com"], "example.org"));
    assert!(!perm(&["example.com"], "com"));
}

/// `*.example.com` matches one or more additional labels — `a.example.com`
/// and `a.b.example.com` both match — but not `example.com` itself.
#[test]
fn wildcard_matches_one_or_more_labels() {
    assert!(perm(&["*.example.com"], "a.example.com"));
    assert!(perm(&["*.example.com"], "a.b.example.com"));
    assert!(perm(&["*.example.com"], "deep.a.b.example.com"));
    assert!(!perm(&["*.example.com"], "example.com"));
    assert!(!perm(&["*.example.com"], "b.example.org"));
    assert!(!perm(&["*.example.com"], "xexample.com"));
}

/// Matching is case-insensitive in both directions.
#[test]
fn dns_matching_is_case_insensitive() {
    assert!(perm(&["EXAMPLE.com"], "example.com"));
    assert!(perm(&["example.com"], "EXAMPLE.com"));
    assert!(perm(&["*.Example.com"], "a.EXAMPLE.com"));
    assert!(perm(&["MiXeD.Example.COM"], "mixed.example.com"));
}

/// A CIDR pattern matches any IP in its range, version-matched: an IPv4
/// CIDR never covers an IPv6 address.
#[test]
fn cidr_matches_range() {
    assert!(perm(&["10.0.0.0/8"], "10.1.2.3"));
    assert!(perm(&["10.0.0.0/8"], "10.255.255.255"));
    assert!(!perm(&["10.0.0.0/8"], "11.0.0.1"));
    assert!(
        !perm(&["10.0.0.0/8"], "2001:db8::1"),
        "an IPv4 CIDR never covers IPv6"
    );
    assert!(perm(&["2001:db8::/32"], "2001:db8::1"));
    assert!(!perm(&["2001:db8::/32"], "2001:db9::1"));
    assert!(perm(&["0.0.0.0/0"], "1.2.3.4"));
    assert!(perm(&["0.0.0.0/0"], "255.255.255.255"));
    assert!(
        !perm(&["0.0.0.0/0"], "2001:db8::1"),
        "0.0.0.0/0 is IPv4-only"
    );
}

/// An IP-literal pattern matches exactly that address.
#[test]
fn ip_literal_matches_exactly() {
    assert!(perm(&["10.0.0.5"], "10.0.0.5"));
    assert!(!perm(&["10.0.0.5"], "10.0.0.6"));
    assert!(!perm(&["10.0.0.5"], "10.0.0.5.example.com"));
    assert!(perm(&["2001:db8::5"], "2001:db8::5"));
    assert!(!perm(&["2001:db8::5"], "2001:db8::6"));
    assert!(!perm(&["10.0.0.5"], "example.com"));
}

/// A bare `*` matches any DNS name but never an IP literal: an IP needs an
/// explicit IP or CIDR pattern (or `0.0.0.0/0`).
#[test]
fn bare_star_matches_dns_only() {
    assert!(perm(&["*"], "anything.example"));
    assert!(perm(&["*"], "a.b.c.test"));
    assert!(perm(&["*"], "example.com"));
    assert!(!perm(&["*"], "192.0.2.1"));
    assert!(!perm(&["*"], "2001:db8::5"));
}

/// Patterns accumulate: permission holds if any pattern matches. Combined
/// with the version rule, a profile that lists a domain, its wildcard, and
/// its CIDRs covers exactly its names and addresses.
#[test]
fn any_matching_pattern_permits() {
    let patterns = ["example.com", "*.example.com", "10.0.0.0/8"];
    assert!(perm(&patterns, "example.com"));
    assert!(perm(&patterns, "a.example.com"));
    assert!(perm(&patterns, "10.9.9.9"));
    assert!(!perm(&patterns, "other.org"));
    assert!(!perm(&patterns, "11.0.0.1"));
}

/// A `*.` pattern — the `*.` wildcard prefix with an EMPTY suffix — is a
/// typed error, not a wildcard over "any DNS name containing a dot": the
/// profile that stores it is data damage, and the matcher must fail
/// closed on the issuance hot path (the Task 10 deferred fix, from Task
/// 5's review R-a). Built-in default profiles never store `*.`.
#[test]
fn star_dot_empty_suffix_fails_closed() {
    let err = san_is_permitted(&["*.".to_string()], "foo.other.com")
        .expect_err("`*.` (empty suffix) must fail closed, never match");
    assert!(
        matches!(err, CoreError::Config(_)),
        "unexpected error: {err:?}"
    );

    // The empty-suffix pattern fails closed even against a name the broken
    // wildcard "should" have covered.
    let err = san_is_permitted(&["*.".to_string()], "example.com")
        .expect_err("`*.` must fail closed for every name");
    assert!(matches!(err, CoreError::Config(_)));
}

/// An unparsable pattern is a typed error rather than a silent non-match:
/// a broken stored pattern is data damage and must not read as "no match".
#[test]
fn unparsable_pattern_is_a_typed_error() {
    let patterns = ["example.com/".to_string(), "sub.example.com".to_string()];
    let err = san_is_permitted(&patterns, "sub.example.com").expect_err("broken pattern");
    assert!(
        matches!(err, CoreError::Config(_)),
        "unexpected error: {err:?}"
    );

    // Even when an earlier pattern would have matched, a later broken one
    // fails closed with the error.
    let patterns = ["*.example.com".to_string(), "10.0.0.0/33".to_string()];
    let err = san_is_permitted(&patterns, "a.example.com").expect_err("broken CIDR");
    assert!(
        matches!(err, CoreError::Config(_)),
        "unexpected error: {err:?}"
    );

    // An unparsable san literal is an error too, not a silent non-match.
    let patterns = ["example.com".to_string()];
    let err =
        san_is_permitted(&patterns, "10.0.0.0/8").expect_err("a san literal may not be a CIDR");
    assert!(
        matches!(err, CoreError::Config(_)),
        "unexpected error: {err:?}"
    );
    let err = san_is_permitted(&patterns, "").expect_err("an empty san is damage");
    assert!(
        matches!(err, CoreError::Config(_)),
        "unexpected error: {err:?}"
    );
}
