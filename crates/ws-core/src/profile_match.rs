//! SAN permission matching: the ONE place SAN-permission logic lives.
//!
//! A profile revision stores `san_patterns`; [`san_is_permitted`] decides
//! whether a requested subject-alternative name (a DNS name or an IP
//! literal) is covered. The function is pure and total over `(patterns,
//! san)` — no database, no I/O — so this rule set is exhaustively unit
//! tested in `tests/profile_match_test.rs`.
//!
//! Rules:
//!
//! - a pattern that parses as an IP literal is an IP pattern; a pattern
//!   containing `/` is a CIDR pattern; anything else is a DNS name
//!   pattern;
//! - a DNS pattern matches exactly that name, case-insensitively —
//!   `example.com` does not cover `sub.example.com`;
//! - a `*.` pattern matches ONE OR MORE additional labels under the
//!   suffix — `a.example.com` and `a.b.example.com` both match
//!   `*.example.com`, but `example.com` does not;
//! - a CIDR pattern matches any IP in the range, version-matched (an
//!   IPv4 CIDR never covers an IPv6 address and vice versa);
//! - a bare `*` matches any DNS name but NEVER an IP literal — an IP
//!   needs an explicit IP or CIDR pattern (or `0.0.0.0/0`);
//! - an unparsable pattern is [`CoreError::Config`]: a broken stored
//!   pattern is data damage and must fail closed, not read as a silent
//!   non-match. The same failure mode covers a malformed `san` (empty,
//!   or a CIDR literal where a name belongs).

use std::net::IpAddr;

use sqlx::types::ipnet::{Ipv4Net, Ipv6Net};

use crate::error::CoreError;

/// One classified pattern from a profile's `san_patterns` list.
#[derive(Debug, Clone, PartialEq)]
enum Pattern {
    /// An exact IP literal (`10.0.0.5`, `2001:db8::5`).
    Ip(IpAddr),
    /// An IPv4 CIDR (`10.0.0.0/8`) — matches IPv4 addresses only.
    Ipv4Cidr(Ipv4Net),
    /// An IPv6 CIDR (`2001:db8::/32`) — matches IPv6 addresses only.
    Ipv6Cidr(Ipv6Net),
    /// A single DNS name, matched exactly (case-insensitively).
    Dns(String),
    /// A `*.` wildcard whose suffix every extra label hangs under.
    Wildcard(String),
    /// The bare `*`: any DNS name, never an IP literal.
    AnyDns,
}

/// Classify one stored pattern. Every failure mode of THIS function (not
/// only its "unparsable" arm) is a caller-data error surfaced as
/// [`CoreError::Config`] — the wildcard arm rejects `*` elsewhere in the
/// pattern for the same fail-closed reason: its matching semantics are not
/// defined here, and a silent literal-match of `*` would be wider than
/// anyone intended.
fn parse_pattern(pattern: &str) -> Result<Pattern, CoreError> {
    if pattern.is_empty() {
        return Err(CoreError::Config(
            "empty san pattern in profile".to_string(),
        ));
    }
    if let Ok(ip) = pattern.parse::<IpAddr>() {
        return Ok(Pattern::Ip(ip));
    }
    if pattern.contains('/') {
        if let Ok(net) = pattern.parse::<Ipv4Net>() {
            return Ok(Pattern::Ipv4Cidr(net));
        }
        if let Ok(net) = pattern.parse::<Ipv6Net>() {
            return Ok(Pattern::Ipv6Cidr(net));
        }
        return Err(CoreError::Config(format!(
            "unparsable CIDR san pattern in profile: {pattern:?}"
        )));
    }
    if pattern == "*" {
        return Ok(Pattern::AnyDns);
    }
    if pattern.contains('*') {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            // `*.` (an EMPTY suffix) would otherwise mint a wildcard over
            // "any DNS name containing a dot" — an open-ended grant nobody
            // profile meant to publish. Fail closed (the Task 10 deferred
            // fix, from Task 5's review R-a); the built-in default
            // profiles never store `*.`.
            if suffix.is_empty() {
                return Err(CoreError::Config(format!(
                    "wildcard san pattern in profile is not exactly `*` or `*.<labels>`: {pattern:?} \
                     (\u{60}*\u{60} with an empty suffix is refused)"
                )));
            }
            if !suffix.contains('*') {
                return Ok(Pattern::Wildcard(suffix.to_lowercase()));
            }
        }
        return Err(CoreError::Config(format!(
            "wildcard san pattern in profile is not exactly `*` or `*.<labels>`: {pattern:?}"
        )));
    }
    Ok(Pattern::Dns(pattern.to_lowercase()))
}

/// Whether `san` — a DNS name or an IP literal, as issued in a leaf — is
/// permitted by `patterns` (a profile revision's stored list).
///
/// Every pattern is classified BEFORE any match runs: one broken pattern
/// makes the whole decision a [`CoreError::Config`], even when an earlier
/// pattern would have matched. Permission is then true when any pattern
/// matches.
pub fn san_is_permitted(patterns: &[String], san: &str) -> Result<bool, CoreError> {
    if san.is_empty() || san.contains('/') {
        return Err(CoreError::Config(format!(
            "malformed san literal {san:?}: expected a DNS name or an IP address"
        )));
    }
    let classified: Vec<Pattern> = patterns
        .iter()
        .map(|p| parse_pattern(p))
        .collect::<Result<Vec<_>, _>>()?;

    // An IP literal SAN is matched by IP/CIDR patterns only; a DNS SAN by
    // DNS patterns only. The two families never cross.
    if let Ok(ip) = san.parse::<IpAddr>() {
        let matched = classified.iter().any(|p| match (p, ip) {
            (Pattern::Ip(pattern_ip), san_ip) => *pattern_ip == san_ip,
            (Pattern::Ipv4Cidr(net), IpAddr::V4(v4)) => net.contains(&v4),
            (Pattern::Ipv6Cidr(net), IpAddr::V6(v6)) => net.contains(&v6),
            _ => false,
        });
        return Ok(matched);
    }

    let san = san.to_lowercase();
    let matched = classified.iter().any(|p| match p {
        Pattern::Dns(name) => *name == san,
        // One or more labels under the wildcard suffix: the SAN must END
        // with `.suffix` and carry at least one label before it. The one
        // or more rule covers `a.b.example.com` under `*.example.com` in
        // the same comparison.
        Pattern::Wildcard(suffix) => san
            .rsplit_once(&format!(".{suffix}"))
            .is_some_and(|(head, _)| !head.is_empty()),
        Pattern::AnyDns => true,
        _ => false,
    });
    Ok(matched)
}
