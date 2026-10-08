//! Path selection from a verified registry (SECURITY_MODEL §5.3).
//!
//! The client picks its own path, which is what keeps the authority from
//! learning which subscriber uses which relays. Every rule is computed from the
//! signed document alone: no network query, and no name resolved anywhere, so a
//! resolver cannot learn a path by watching lookups.
//!
//! Selection counts the valid triples and then walks to a uniformly chosen
//! index. Two passes cost nothing at these sizes and buy two properties worth
//! having. The distribution is exactly uniform over valid paths rather than over
//! sampling attempts, and nothing allocates in proportion to the number of
//! triples, which is cubic in the relay count.

use std::net::IpAddr;

use quiethop_crypto::noise::STATIC_KEY_LEN;
use quiethop_crypto::registry::{Document, RelayEntry};
use rand::rngs::OsRng;
use rand::Rng;

use crate::error::ClientError;

/// Largest registry this selector will enumerate.
///
/// Enumeration is cubic in the relay count, so a registry far larger than any
/// planned deployment is a configuration or publication fault rather than
/// something to grind through. Above this the selector fails loudly, because a
/// silent multi-second pause inside a circuit build reads as a hang.
pub const MAX_RELAYS: usize = 256;

/// Why no path could be built.
///
/// These values reach logs and the SOCKS failure surface, so they carry no
/// relay identity by construction. A reason naming the relays considered would
/// write path material where a local reader or a crash report could collect it,
/// which is the same information this step exists to stop producing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoPathReason {
    /// Outside the document's validity window, in either direction.
    RegistryUnusable,
    /// More relays than `MAX_RELAYS`.
    RegistryTooLarge,
    /// An entry the publisher should never have signed.
    InvalidRegistryEntry,
    /// A role has no eligible relay at all.
    InsufficientRelays,
    /// Relays exist for every role, but no combination satisfies the rules.
    DiversityUnsatisfiable,
}

impl std::fmt::Display for NoPathReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::RegistryUnusable => "the registry is outside its validity window",
            Self::RegistryTooLarge => {
                "the registry lists more relays than this client will enumerate"
            }
            Self::InvalidRegistryEntry => "the registry carries a malformed entry",
            Self::InsufficientRelays => "a hop role has no eligible relay",
            Self::DiversityUnsatisfiable => "no combination of relays satisfies the path rules",
        };
        f.write_str(s)
    }
}

/// Which rules are enforced.
///
/// `require_operator_diversity` is client configuration and never a registry
/// field. The rule exists to constrain the authority, so the party being checked
/// must not be able to switch it off (docs/DECISIONS.md entry 5).
#[derive(Debug, Clone, Copy)]
pub struct PathRules {
    pub require_operator_diversity: bool,
}

impl Default for PathRules {
    /// False, because during the single operator stage every relay carries one
    /// `operator_id` and no path could satisfy the rule (SECURITY_MODEL §5.3).
    fn default() -> Self {
        Self {
            require_operator_diversity: false,
        }
    }
}

/// Three relays and the guarantee the path carries.
#[derive(Debug, Clone)]
pub struct SelectedPath {
    pub guard: RelayEntry,
    pub middle: RelayEntry,
    pub exit: RelayEntry,
    /// Distinct `operator_id` values spanned, a count and never the values.
    ///
    /// SECURITY_MODEL §5.3 requires this for every circuit whatever
    /// `require_operator_diversity` is set to, so a path across one operator
    /// cannot be mistaken for a path across three.
    pub operator_span: usize,
}

/// A registry entry that passed well-formedness, with its address parsed once.
struct Candidate<'a> {
    entry: &'a RelayEntry,
    ip: IpAddr,
}

/// Select a path using the OS RNG.
pub fn select(
    doc: &Document,
    rules: PathRules,
    now_unix: i64,
) -> Result<SelectedPath, ClientError> {
    select_with(doc, rules, now_unix, &mut OsRng)
}

/// Select a path using a caller-supplied RNG.
///
/// Production goes through [`select`] and the OS RNG. This entry point exists so
/// the uniformity test can run against a seeded generator and be deterministic,
/// because a statistical assertion driven by the OS RNG would be a flaky gate
/// step rather than a check.
pub fn select_with<R: Rng>(
    doc: &Document,
    rules: PathRules,
    now_unix: i64,
    rng: &mut R,
) -> Result<SelectedPath, ClientError> {
    if !doc.is_usable_at(now_unix)? {
        return Err(no_path(NoPathReason::RegistryUnusable));
    }
    if doc.relays.len() > MAX_RELAYS {
        return Err(no_path(NoPathReason::RegistryTooLarge));
    }

    let candidates = candidates(doc)?;
    let guards = by_role(&candidates, "guard");
    let middles = by_role(&candidates, "middle");
    let exits = by_role(&candidates, "exit");
    if guards.is_empty() || middles.is_empty() || exits.is_empty() {
        return Err(no_path(NoPathReason::InsufficientRelays));
    }

    let total = count_valid(&guards, &middles, &exits, rules);
    if total == 0 {
        return Err(no_path(NoPathReason::DiversityUnsatisfiable));
    }

    // gen_range rejects out-of-range draws rather than taking a remainder, so
    // the pick is unbiased. A modulo would skew toward the low indices.
    let wanted = rng.gen_range(0..total);
    let mut seen = 0usize;
    for g in &guards {
        for m in &middles {
            for e in &exits {
                if !triple_is_valid(g, m, e, rules) {
                    continue;
                }
                if seen == wanted {
                    return Ok(SelectedPath {
                        guard: g.entry.clone(),
                        middle: m.entry.clone(),
                        exit: e.entry.clone(),
                        operator_span: operator_span(g, m, e),
                    });
                }
                seen += 1;
            }
        }
    }
    // count_valid and this walk apply the same predicate to the same slices, so
    // reaching here would mean they disagreed.
    unreachable!("counted {total} valid triples and then found {seen}")
}

fn no_path(reason: NoPathReason) -> ClientError {
    ClientError::NoPath(reason)
}

/// Validate every entry, rejecting the whole document if any is malformed.
///
/// Dropping a bad entry instead would let a publication fault quietly shrink the
/// set a path is drawn from, and a signed document carrying a malformed entry is
/// a bug at the authority rather than a condition to work around.
fn candidates(doc: &Document) -> Result<Vec<Candidate<'_>>, ClientError> {
    let mut out = Vec::with_capacity(doc.relays.len());
    for entry in &doc.relays {
        if entry.id.is_empty()
            || entry.operator_id.is_empty()
            || entry.host_id.is_empty()
            || entry.tls_name.is_empty()
            || entry.port == 0
            || entry.static_pubkey.len() != STATIC_KEY_LEN * 2
            || !entry.static_pubkey.bytes().all(|b| b.is_ascii_hexdigit())
            || !matches!(entry.role.as_str(), "guard" | "middle" | "exit")
        {
            return Err(no_path(NoPathReason::InvalidRegistryEntry));
        }
        // Parsed as a literal and never resolved. An entry holding a name fails
        // here rather than reaching a resolver (SECURITY_MODEL §5.3).
        let Ok(ip) = entry.ip.parse::<IpAddr>() else {
            return Err(no_path(NoPathReason::InvalidRegistryEntry));
        };
        out.push(Candidate { entry, ip });
    }
    Ok(out)
}

fn by_role<'a>(all: &'a [Candidate<'a>], role: &str) -> Vec<&'a Candidate<'a>> {
    all.iter().filter(|c| c.entry.role == role).collect()
}

fn count_valid(
    guards: &[&Candidate],
    middles: &[&Candidate],
    exits: &[&Candidate],
    rules: PathRules,
) -> usize {
    let mut n = 0;
    for g in guards {
        for m in middles {
            for e in exits {
                if triple_is_valid(g, m, e, rules) {
                    n += 1;
                }
            }
        }
    }
    n
}

/// The rules of SECURITY_MODEL §5.3, in the order that section states them.
fn triple_is_valid(g: &Candidate, m: &Candidate, e: &Candidate, rules: PathRules) -> bool {
    // Three distinct relays. The role split usually gives this, but one id
    // appearing under two roles is a document the client should refuse to build
    // a path from rather than one it relies on being impossible.
    if g.entry.id == m.entry.id || g.entry.id == e.entry.id || m.entry.id == e.entry.id {
        return false;
    }
    // Rule a, enforced only when operator diversity is required.
    if rules.require_operator_diversity
        && (g.entry.operator_id == m.entry.operator_id
            || g.entry.operator_id == e.entry.operator_id
            || m.entry.operator_id == e.entry.operator_id)
    {
        return false;
    }
    // Rule b, always.
    if g.entry.host_id == m.entry.host_id
        || g.entry.host_id == e.entry.host_id
        || m.entry.host_id == e.entry.host_id
    {
        return false;
    }
    // Rule c, always.
    !(same_prefix(g.ip, m.ip) || same_prefix(g.ip, e.ip) || same_prefix(m.ip, e.ip))
}

/// Whether two addresses fall in the same IPv4 /16 or IPv6 /32.
///
/// The prefix lengths follow Tor's universal path constraints. A v4 and a v6
/// address share no prefix, so the rule applies within a family only.
fn same_prefix(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a.octets()[..2] == b.octets()[..2],
        (IpAddr::V6(a), IpAddr::V6(b)) => a.octets()[..4] == b.octets()[..4],
        _ => false,
    }
}

fn operator_span(g: &Candidate, m: &Candidate, e: &Candidate) -> usize {
    let mut ids = [
        g.entry.operator_id.as_str(),
        m.entry.operator_id.as_str(),
        e.entry.operator_id.as_str(),
    ];
    ids.sort_unstable();
    1 + ids.windows(2).filter(|w| w[0] != w[1]).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    // 2026-10-08T14:00:00Z. valid_after must be on an exact hour and version must
    // be that hour, which the authority's CHECK constraints also enforce.
    const AFTER: i64 = 1_791_468_000;
    const AFTER_STR: &str = "2026-10-08T14:00:00Z";
    const FRESH_STR: &str = "2026-10-08T15:00:00Z";
    const UNTIL: i64 = 1_791_489_600;
    const UNTIL_STR: &str = "2026-10-08T20:00:00Z";
    const NOW: i64 = AFTER + 60;

    fn entry(id: &str, op: &str, host: &str, role: &str, ip: &str) -> RelayEntry {
        RelayEntry {
            id: id.to_string(),
            operator_id: op.to_string(),
            host_id: host.to_string(),
            role: role.to_string(),
            ip: ip.to_string(),
            port: 443,
            tls_name: format!("{id}.example"),
            static_pubkey: "ab".repeat(STATIC_KEY_LEN),
        }
    }

    fn doc(relays: Vec<RelayEntry>) -> Document {
        Document {
            version: AFTER / 3600,
            valid_after: AFTER_STR.to_string(),
            fresh_until: FRESH_STR.to_string(),
            valid_until: UNTIL_STR.to_string(),
            relays,
        }
    }

    /// Three relays that satisfy every rule, as the baseline each case varies
    /// from by exactly one fact.
    fn clean() -> Vec<RelayEntry> {
        vec![
            entry("g1", "op-a", "host-1", "guard", "10.1.0.1"),
            entry("m1", "op-b", "host-2", "middle", "10.2.0.1"),
            entry("e1", "op-c", "host-3", "exit", "10.3.0.1"),
        ]
    }

    fn strict() -> PathRules {
        PathRules {
            require_operator_diversity: true,
        }
    }

    fn reason(e: ClientError) -> NoPathReason {
        match e {
            ClientError::NoPath(r) => r,
            other => panic!("expected NoPath, got {other:?}"),
        }
    }

    fn pick(relays: Vec<RelayEntry>, rules: PathRules) -> Result<SelectedPath, ClientError> {
        select(&doc(relays), rules, NOW)
    }

    #[test]
    fn a_valid_path_is_found_and_reports_its_operator_span() {
        let p = pick(clean(), PathRules::default()).expect("a clean registry yields a path");
        assert_eq!(
            (
                p.guard.id.as_str(),
                p.middle.id.as_str(),
                p.exit.id.as_str()
            ),
            ("g1", "m1", "e1")
        );
        assert_eq!(p.guard.role, "guard");
        assert_eq!(p.middle.role, "middle");
        assert_eq!(p.exit.role, "exit");
        assert_eq!(
            p.operator_span, 3,
            "three distinct operators must report as three"
        );
    }

    /// The span is a count of distinct operators, so a single operator path must
    /// report 1 rather than 3. A constant would pass the clean case alone.
    #[test]
    fn operator_span_counts_distinct_operators_not_hops() {
        let mut r = clean();
        for e in r.iter_mut() {
            e.operator_id = "op-only".to_string();
        }
        let p = pick(r, PathRules::default()).expect("one operator is allowed when not required");
        assert_eq!(p.operator_span, 1);

        let mut r = clean();
        r[1].operator_id = "op-a".to_string();
        let p = pick(r, PathRules::default()).expect("path exists");
        assert_eq!(
            p.operator_span, 2,
            "two distinct operators across three hops"
        );
    }

    #[test]
    fn same_operator_is_rejected_when_diversity_is_required() {
        let mut r = clean();
        r[1].operator_id = "op-a".to_string();
        assert_eq!(
            reason(pick(r.clone(), strict()).unwrap_err()),
            NoPathReason::DiversityUnsatisfiable
        );
        // Control: the only changed fact is the rule, so the rejection above is
        // attributable to rule a and not to anything else in the fixture.
        assert!(
            pick(r, PathRules::default()).is_ok(),
            "the same registry must yield a path when diversity is not required"
        );
    }

    #[test]
    fn same_host_is_always_rejected() {
        let mut r = clean();
        r[2].host_id = "host-1".to_string();
        assert_eq!(
            reason(pick(r.clone(), PathRules::default()).unwrap_err()),
            NoPathReason::DiversityUnsatisfiable,
            "host distinctness holds even with operator diversity off"
        );
        // Control: restoring only host_id must produce a path.
        r[2].host_id = "host-3".to_string();
        assert!(pick(r, PathRules::default()).is_ok());
    }

    #[test]
    fn same_ipv4_slash_16_is_rejected_and_a_different_one_is_not() {
        let mut r = clean();
        r[2].ip = "10.1.255.254".to_string();
        assert_eq!(
            reason(pick(r.clone(), PathRules::default()).unwrap_err()),
            NoPathReason::DiversityUnsatisfiable,
            "10.1.0.1 and 10.1.255.254 share a /16"
        );
        // Accept side, which a too-wide mask would break.
        r[2].ip = "10.4.0.1".to_string();
        assert!(
            pick(r, PathRules::default()).is_ok(),
            "10.1/16 and 10.4/16 differ"
        );
    }

    #[test]
    fn same_ipv6_slash_32_is_rejected_and_a_different_one_is_not() {
        let mut r = clean();
        r[0].ip = "2001:db8::1".to_string();
        r[1].ip = "2001:db8:ffff::1".to_string();
        r[2].ip = "2001:dba::1".to_string();
        assert_eq!(
            reason(pick(r.clone(), PathRules::default()).unwrap_err()),
            NoPathReason::DiversityUnsatisfiable,
            "2001:db8:: and 2001:db8:ffff:: share a /32"
        );
        r[1].ip = "2001:db9::1".to_string();
        assert!(
            pick(r, PathRules::default()).is_ok(),
            "2001:db8/32 and 2001:db9/32 differ"
        );
    }

    /// A v4 and a v6 address share no prefix, so the mask must not be compared
    /// across families. Octet-slice comparison on mismatched families would
    /// otherwise reject a legitimate mixed path.
    #[test]
    fn addresses_in_different_families_are_never_in_the_same_prefix() {
        let mut r = clean();
        r[0].ip = "10.1.0.1".to_string();
        r[1].ip = "2001:db8::1".to_string();
        r[2].ip = "2001:db9::1".to_string();
        assert!(pick(r, PathRules::default()).is_ok());
    }

    #[test]
    fn a_role_with_no_relay_fails_closed() {
        let mut r = clean();
        r.retain(|e| e.role != "exit");
        assert_eq!(
            reason(pick(r, PathRules::default()).unwrap_err()),
            NoPathReason::InsufficientRelays
        );
    }

    #[test]
    fn too_few_relays_fails_closed() {
        let r = vec![
            entry("g1", "op-a", "host-1", "guard", "10.1.0.1"),
            entry("m1", "op-b", "host-2", "middle", "10.2.0.1"),
        ];
        assert_eq!(
            reason(pick(r, PathRules::default()).unwrap_err()),
            NoPathReason::InsufficientRelays
        );
        assert_eq!(
            reason(pick(vec![], PathRules::default()).unwrap_err()),
            NoPathReason::InsufficientRelays,
            "an empty registry has no eligible relay for any role"
        );
    }

    #[test]
    fn every_relay_on_one_host_fails_closed() {
        let mut r = clean();
        for e in r.iter_mut() {
            e.host_id = "host-1".to_string();
        }
        assert_eq!(
            reason(pick(r, PathRules::default()).unwrap_err()),
            NoPathReason::DiversityUnsatisfiable,
            "relays exist for every role, so this is not InsufficientRelays"
        );
    }

    #[test]
    fn a_registry_outside_its_window_is_unusable() {
        let d = doc(clean());
        assert_eq!(
            reason(select(&d, PathRules::default(), UNTIL).unwrap_err()),
            NoPathReason::RegistryUnusable,
            "valid_until has no grace period"
        );
        assert!(
            select(&d, PathRules::default(), UNTIL - 1).is_ok(),
            "one second before valid_until is still usable"
        );
        assert_eq!(
            reason(select(&d, PathRules::default(), AFTER - 61).unwrap_err()),
            NoPathReason::RegistryUnusable,
            "beyond the skew allowance before valid_after"
        );
        assert!(
            select(&d, PathRules::default(), AFTER - 60).is_ok(),
            "the 60 second skew allowance applies to valid_after"
        );
    }

    #[test]
    fn an_oversized_registry_fails_loudly() {
        let mut r = clean();
        while r.len() <= MAX_RELAYS {
            let n = r.len();
            r.push(entry(
                &format!("x{n}"),
                "op-x",
                &format!("h{n}"),
                "middle",
                "10.9.0.1",
            ));
        }
        assert_eq!(
            reason(pick(r, PathRules::default()).unwrap_err()),
            NoPathReason::RegistryTooLarge
        );
    }

    /// One malformed field, applied to the exit entry of an otherwise clean
    /// registry, so each case differs from the baseline by exactly one fact.
    fn with_malformed_exit(case: &str) -> Vec<RelayEntry> {
        let mut r = clean();
        let e = &mut r[2];
        match case {
            "empty id" => e.id.clear(),
            "empty operator_id" => e.operator_id.clear(),
            "empty host_id" => e.host_id.clear(),
            "empty tls_name" => e.tls_name.clear(),
            "zero port" => e.port = 0,
            "unknown role" => e.role = "bridge".to_string(),
            "short pubkey" => e.static_pubkey.truncate(10),
            "non-hex pubkey" => e.static_pubkey = "zz".repeat(STATIC_KEY_LEN),
            "prefixed ip" => e.ip = "10.3.0.1/32".to_string(),
            other => panic!("unknown case {other}"),
        }
        r
    }

    #[test]
    fn a_malformed_entry_rejects_the_whole_document() {
        for case in [
            "empty id",
            "empty operator_id",
            "empty host_id",
            "empty tls_name",
            "zero port",
            "unknown role",
            "short pubkey",
            "non-hex pubkey",
            "prefixed ip",
        ] {
            assert_eq!(
                reason(pick(with_malformed_exit(case), PathRules::default()).unwrap_err()),
                NoPathReason::InvalidRegistryEntry,
                "{case} must reject the document"
            );
        }
        // Control: the baseline the cases are built from must itself be accepted,
        // so a rejection above cannot come from the fixture.
        assert!(pick(clean(), PathRules::default()).is_ok());
    }

    /// The guarantee is that no name is resolved. An entry whose ip field holds
    /// a hostname must fail, never fall back to a lookup.
    #[test]
    fn a_hostname_in_the_ip_field_is_refused_rather_than_resolved() {
        for name in ["relay.example", "localhost", "", "10.3.0.1:443"] {
            let mut r = clean();
            r[2].ip = name.to_string();
            assert_eq!(
                reason(pick(r, PathRules::default()).unwrap_err()),
                NoPathReason::InvalidRegistryEntry,
                "{name:?} was accepted as an address"
            );
        }
    }

    /// Five relays per role, all mutually compatible, so every one of the 125
    /// triples is valid and each guard should appear in a fifth of draws.
    fn uniform_fixture() -> Vec<RelayEntry> {
        let mut r = Vec::new();
        for (role, block) in [("guard", 1u8), ("middle", 2), ("exit", 3)] {
            for i in 0..5u8 {
                r.push(entry(
                    &format!("{role}-{i}"),
                    &format!("op-{role}-{i}"),
                    &format!("host-{role}-{i}"),
                    role,
                    &format!("{}.{}.0.1", 10 + block, 100 + i),
                ));
            }
        }
        r
    }

    /// Selection must be uniform over valid paths, in particular not biased
    /// toward the first relay in the list.
    ///
    /// Chi-square goodness of fit on the guard position, 5 categories and so 4
    /// degrees of freedom, against the uniform expectation. N is 20,000, giving
    /// an expected 4,000 per guard. The critical value at alpha 0.001 is 18.467,
    /// chosen over the usual 0.05 so a correct implementation fails about one run
    /// in a thousand rather than one in twenty: this runs in the gate.
    ///
    /// Power: a five point absolute bias on one guard, 5,000 against 4,000
    /// expected, contributes 250 to the statistic on its own, far past the
    /// threshold, so this N detects bias well short of the always-first case.
    ///
    /// What it cannot detect: modulo bias. Drawing a 5 way choice from a 32 bit
    /// value with a remainder skews the low indices by about one part in a
    /// billion, which no feasible sample size sees. That is guarded by using an
    /// unbiased range method in the first place, not by this test.
    #[test]
    fn selection_is_uniform_across_valid_paths() {
        const N: usize = 20_000;
        const EXPECTED: f64 = N as f64 / 5.0;
        const CRITICAL: f64 = 18.467;

        let d = doc(uniform_fixture());
        let mut rng = StdRng::seed_from_u64(0x5151_2026_1008);
        let mut counts = [0usize; 5];
        for _ in 0..N {
            let p = select_with(&d, PathRules::default(), NOW, &mut rng).expect("path exists");
            let idx: usize = p
                .guard
                .id
                .rsplit('-')
                .next()
                .and_then(|s| s.parse().ok())
                .expect("guard id ends in its index");
            counts[idx] += 1;
        }
        let chi: f64 = counts
            .iter()
            .map(|&c| {
                let d = c as f64 - EXPECTED;
                d * d / EXPECTED
            })
            .sum();
        assert!(
            chi < CRITICAL,
            "guard selection is not uniform: counts {counts:?}, chi-square {chi:.3} \
             against a critical value of {CRITICAL} at alpha 0.001"
        );
        assert_eq!(counts.iter().sum::<usize>(), N);
    }

    /// Production goes through the OS RNG, so repeated calls must not keep
    /// returning one path. This catches a fixed seed wired into `select`.
    ///
    /// It does not prove the generator is cryptographically secure; that rests on
    /// OsRng itself and on the gate step that greps for a seeded generator in
    /// non-test code.
    #[test]
    fn select_does_not_return_a_fixed_path() {
        let d = doc(uniform_fixture());
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..200 {
            let p = select(&d, PathRules::default(), NOW).expect("path exists");
            seen.insert((p.guard.id, p.middle.id, p.exit.id));
        }
        assert!(
            seen.len() > 1,
            "200 selections returned one path, so production is not drawing randomly"
        );
    }
}
