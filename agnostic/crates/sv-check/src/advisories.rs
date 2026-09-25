//! Matching the bill of materials against known vulnerabilities.
//!
//! # `sv` does not fetch anything
//!
//! This reads a local OSV database the owner points it at, and never opens a network connection. That is
//! a deliberate decision rather than an unfinished one, for three reasons:
//!
//! * **Checking code is not a reason to phone home.** The list of packages an app depends on is
//!   business-confidential, and sending it to a service to be checked is a disclosure the owner did not
//!   ask for. v1 fences generated code to loopback for the same reason.
//! * **A fetch is a dependency on somebody else's uptime.** A check that silently degrades when a
//!   service is slow is a check that reports a clean result on a bad day.
//! * **`sv` runs where there may be no network at all** — an air-gapped review, a CI runner with egress
//!   rules, somebody's laptop on a train.
//!
//! Getting the data is therefore the owner's step, done deliberately and visible in their shell history:
//! OSV publishes per-ecosystem zip exports, and `sv audit --advisories <dir>` reads what they unpacked.
//!
//! # No data is not a clean result
//!
//! The rule this module exists under. With no advisory directory, `audit` reports **not assessed** and
//! says what to do about it. It never prints "no known vulnerabilities", because that sentence would be
//! true of an empty directory, a stale one, and a healthy app alike, and only one of those is good news.
//! The same applies per-ecosystem: advisories for npm say nothing about the Python packages beside them.

use crate::finding::{Confidence, Finding, Location, Severity};
use crate::sbom::{Component, Sbom};
use crate::verified::Verified;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;

/// One OSV record, cut down to the fields a match needs.
#[derive(Debug, Deserialize)]
pub struct Advisory {
    pub id: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub affected: Vec<Affected>,
    #[serde(default)]
    pub severity: Vec<SeverityEntry>,
    #[serde(default)]
    pub withdrawn: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SeverityEntry {
    #[serde(default)]
    pub score: String,
}

#[derive(Debug, Deserialize)]
pub struct Affected {
    #[serde(default)]
    pub package: Package,
    #[serde(default)]
    pub ranges: Vec<Range>,
    /// Explicit list of affected versions, when the record carries one.
    #[serde(default)]
    pub versions: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Package {
    #[serde(default)]
    pub ecosystem: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct Range {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub events: Vec<Event>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Event {
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
}

/// What the database covers, so silence can be read correctly.
#[derive(Debug, Default)]
pub struct AuditResult {
    pub findings: Vec<Finding>,
    /// What the comparison may claim to have examined and found nothing wrong in.
    ///
    /// Empty unless every condition below holds, because each one is a way a clean result would be
    /// a lie: no advisory database, no components, an ecosystem the database says nothing about,
    /// a version that could not be compared, or a component list known to be partial.
    pub verified: Vec<Verified>,
    /// Ecosystems in the app for which the database held no records at all.
    pub uncovered: BTreeSet<String>,
    /// Components whose version could not be compared, so nothing can be said about them.
    pub uncomparable: Vec<(String, String)>,
    pub advisories_read: usize,
    pub components_checked: usize,
}

/// Loads every OSV JSON record under `dir`, recursively.
pub fn load_database(dir: &Path) -> std::io::Result<Vec<Advisory>> {
    let mut out = Vec::new();
    load_into(dir, &mut out)?;
    Ok(out)
}

fn load_into(dir: &Path, out: &mut Vec<Advisory>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            load_into(&path, out)?;
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        // A record this version of `sv` cannot parse is skipped rather than fatal: an OSV export
        // carries records with fields added since, and refusing the whole database over one of them
        // would trade a partial answer for none.
        if let Ok(advisory) = serde_json::from_str::<Advisory>(&text) {
            out.push(advisory);
        }
    }
    Ok(())
}

/// The OSV ecosystem name for one of `sv`'s.
fn osv_ecosystem(ours: &str) -> Option<&'static str> {
    Some(match ours {
        "npm" => "npm",
        "Python" => "PyPI",
        "Rust" => "crates.io",
        "Ruby" => "RubyGems",
        "PHP" => "Packagist",
        "Go" => "Go",
        _ => return None,
    })
}

/// Compares two versions the way a package manager would, as far as it can.
///
/// Returns `None` when the strings are not comparable — a git hash, a date, a build tag. That is not a
/// failure to be smoothed over: an uncomparable version is one nothing can be said about, and saying
/// nothing loudly is the point.
pub fn compare(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    use std::cmp::Ordering;

    /// The numeric core, and whether a pre-release followed it.
    fn parse(v: &str) -> Option<(Vec<u64>, Option<String>)> {
        let v = v.trim().trim_start_matches('v');
        // Build metadata after `+` is not part of precedence.
        let v = v.split('+').next()?;
        let (core, pre) = match v.split_once('-') {
            Some((core, pre)) => (core, Some(pre.to_owned())),
            None => (v, None),
        };
        let nums: Vec<u64> = core
            .split('.')
            .map(str::parse::<u64>)
            .collect::<Result<_, _>>()
            .ok()?;
        (!nums.is_empty()).then_some((nums, pre))
    }

    let (mut x, xpre) = parse(a)?;
    let (mut y, ypre) = parse(b)?;
    let len = x.len().max(y.len());
    x.resize(len, 0);
    y.resize(len, 0);
    match x.cmp(&y) {
        Ordering::Equal => {}
        other => return Some(other),
    }

    // Same numbers: a pre-release comes before the release it leads to. Getting this backwards says a
    // vulnerable 1.2.3-beta is fixed because the fix landed in 1.2.3, which is a false negative and the
    // worst kind of mistake this file can make.
    Some(match (xpre, ypre) {
        (None, None) => Ordering::Equal,
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (Some(p), Some(q)) => compare_prerelease(&p, &q),
    })
}

/// Pre-release identifiers, compared dot-part by dot-part: numbers numerically, anything else as text,
/// and a numeric part ranks below a non-numeric one, as semver says.
fn compare_prerelease(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (mut xs, mut ys) = (a.split('.'), b.split('.'));
    loop {
        return match (xs.next(), ys.next()) {
            (None, None) => Ordering::Equal,
            // Fewer identifiers ranks lower when all the preceding ones are equal.
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(x), Some(y)) => {
                let ordering = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(m), Ok(n)) => m.cmp(&n),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => x.cmp(y),
                };
                if ordering == Ordering::Equal {
                    continue;
                }
                ordering
            }
        };
    }
}

/// Whether `version` falls inside an affected range.
fn in_range(version: &str, range: &Range) -> Option<bool> {
    // Only semantic and ecosystem ranges are ordered in a way this can reason about.
    if range.kind == "GIT" {
        return None;
    }
    let mut affected = false;
    for event in &range.events {
        if let Some(introduced) = &event.introduced {
            // OSV writes "0" for "every version from the beginning", which is not a version and would
            // not parse as one.
            let from_the_start = introduced == "0";
            if from_the_start || compare(version, introduced)? != std::cmp::Ordering::Less {
                affected = true;
            }
        }
        if let Some(fixed) = &event.fixed
            && compare(version, fixed)? != std::cmp::Ordering::Less
        {
            affected = false;
        }
    }
    Some(affected)
}

fn matches(component: &Component, affected: &Affected) -> Option<bool> {
    let Some(expected) = osv_ecosystem(&component.ecosystem) else {
        return Some(false);
    };
    if affected.package.ecosystem != expected
        || !affected.package.name.eq_ignore_ascii_case(&component.name)
    {
        return Some(false);
    }
    if affected.versions.iter().any(|v| v == &component.version) {
        return Some(true);
    }
    // No explicit list, or the version is not in it: fall back to the ranges.
    let mut any_comparable = affected.ranges.is_empty();
    for range in &affected.ranges {
        match in_range(&component.version, range) {
            Some(true) => return Some(true),
            Some(false) => any_comparable = true,
            None => {}
        }
    }
    if any_comparable { Some(false) } else { None }
}

/// Matches every component against the database.
pub fn audit(sbom: &Sbom, database: &[Advisory]) -> AuditResult {
    let mut result = AuditResult {
        advisories_read: database.len(),
        components_checked: sbom.components.len(),
        ..Default::default()
    };

    // Which ecosystems the database says anything about at all.
    let covered: BTreeSet<&str> = database
        .iter()
        .flat_map(|a| a.affected.iter())
        .map(|a| a.package.ecosystem.as_str())
        .collect();
    for component in &sbom.components {
        match osv_ecosystem(&component.ecosystem) {
            Some(osv) if covered.contains(osv) => {}
            _ => {
                result.uncovered.insert(component.ecosystem.clone());
            }
        }
    }

    for component in &sbom.components {
        let mut undecided = false;
        for advisory in database {
            if advisory.withdrawn.is_some() {
                continue;
            }
            for affected in &advisory.affected {
                match matches(component, affected) {
                    Some(true) => {
                        result.findings.push(finding_for(component, advisory));
                        undecided = false;
                        break;
                    }
                    None => undecided = true,
                    Some(false) => {}
                }
            }
        }
        if undecided {
            result
                .uncomparable
                .push((component.name.clone(), component.version.clone()));
        }
    }
    result
        .findings
        .dedup_by(|a, b| a.rule_id == b.rule_id && a.title == b.title);

    // What this comparison may say it looked at. A finding is a claim about something that is
    // there; this is the mirror, and it is only worth the coverage behind it — so every way the
    // coverage could be short switches it off entirely rather than qualifying it.
    //
    // Each condition below is a real way a clean result would mislead. An empty database compares
    // every component against nothing. No components is nothing examined. An ecosystem the database
    // says nothing about means the packages in it were never really checked. A version that could
    // not be compared is a component whose status is unknown, not clear. And a component list known
    // to be incomplete is a clean answer about the wrong question: nobody asked whether the
    // packages `sv` could see are safe, they asked whether the app ships anything vulnerable.
    // `advisories_read > 0` below cannot currently be the condition that blocks a claim on its own:
    // an empty database covers no ecosystem, so `uncovered` is already non-empty and stops it first.
    // Breaking it produces no failing test, which is exactly what a condition carrying no weight
    // looks like. It is kept as the statement of intent — the claim is about what was compared
    // against, and that must never be nothing — and labelled rather than left to look load-bearing.
    // The test asserts the behaviour, not which condition produced it.
    let complete_enough = sbom.unread.is_empty();
    if result.findings.is_empty()
        && result.advisories_read > 0
        && result.components_checked > 0
        && result.uncovered.is_empty()
        && result.uncomparable.is_empty()
        && complete_enough
    {
        result.verified.push(Verified::new(
            "advisories",
            &["V15.2.1"],
            format!(
                "all {} package{} in the bill of materials, compared against {} advisor{}",
                result.components_checked,
                if result.components_checked == 1 {
                    ""
                } else {
                    "s"
                },
                result.advisories_read,
                if result.advisories_read == 1 {
                    "y"
                } else {
                    "ies"
                }
            ),
        ));
    }
    result
}

fn finding_for(component: &Component, advisory: &Advisory) -> Finding {
    // The advisory's own rating, computed from its CVSS vector rather than guessed from the words in
    // it. Where there is no vector this can score, the seriousness shown is a placeholder and the
    // finding says so — a placeholder reading "medium" is believed by anyone sorting the list.
    let rated = crate::cvss::severity_of(advisory.severity.iter().map(|s| s.score.as_str()));
    let (severity, rating) = match rated {
        Some((severity, score)) => (
            severity,
            format!(
                "The advisory rates this {score} out of 10, which is {}.",
                severity.name()
            ),
        ),
        None => (
            Severity::Medium,
            "This advisory carries no CVSS vector `sv` can read, so the seriousness shown here is a \
             placeholder rather than the advisory's own rating — read the advisory before deciding \
             how urgent it is."
                .to_owned(),
        ),
    };
    let names = if advisory.aliases.is_empty() {
        advisory.id.clone()
    } else {
        format!("{} ({})", advisory.id, advisory.aliases.join(", "))
    };
    Finding {
        rule_id: format!("advisory.{}", advisory.id),
        title: format!(
            "{} {} has a known vulnerability: {names}",
            component.name, component.version
        ),
        severity,
        confidence: if component.source == crate::sbom::VersionSource::Locked {
            Confidence::High
        } else {
            // The version came from a manifest, so it is what was asked for, not what is installed.
            Confidence::Medium
        },
        location: Location {
            file: "sbom.cdx.json".into(),
            line: 1,
        },
        secret: None,
        // V15.2.1 asks that the application only contains components which have not breached
        // the documented update and remediation time frames. A component with a published
        // advisory against the version being shipped is the evidence that bears on it. This cited
        // V1.3.5 — user-supplied template content — until 24 September 2026.
        requirement_ids: vec!["V15.2.1".into()],
        cwe: vec![],
        description: if advisory.summary.is_empty() {
            format!(
                "{names} affects {} {}. {rating}",
                component.name, component.version
            )
        } else {
            format!("{} {rating}", advisory.summary)
        },
        impact:
            "A known vulnerability in something this app ships is a problem somebody has already \
                 written down, which means it is also written down for anyone looking for a way in."
                .into(),
        fix: format!(
            "Upgrade {} past the affected range, then reinstall from the lockfile so the fix is what \
             actually ships.",
            component.name
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom::VersionSource;

    fn component(name: &str, version: &str, eco: &str) -> Component {
        Component {
            name: name.into(),
            version: version.into(),
            ecosystem: eco.into(),
            source: VersionSource::Locked,
        }
    }

    fn sbom_of(components: Vec<Component>) -> Sbom {
        Sbom {
            components,
            unread: Vec::new(),
        }
    }

    fn advisory(json: &str) -> Advisory {
        serde_json::from_str(json).expect("advisory parses")
    }

    const LODASH: &str = r#"{
      "id": "GHSA-test-lodash",
      "summary": "Prototype pollution in lodash",
      "aliases": ["CVE-2020-8203"],
      "affected": [{
        "package": {"ecosystem": "npm", "name": "lodash"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.20"}]}]
      }]
    }"#;

    #[test]
    fn a_version_inside_the_range_is_reported() {
        let result = audit(
            &sbom_of(vec![component("lodash", "4.17.15", "npm")]),
            &[advisory(LODASH)],
        );
        assert_eq!(result.findings.len(), 1, "{result:?}");
        assert!(result.findings[0].title.contains("CVE-2020-8203"));
    }

    #[test]
    fn the_advisorys_own_rating_decides_the_severity() {
        // Not the words in the record: the vector it publishes, scored.
        let critical = advisory(
            r#"{"id":"GHSA-crit","summary":"Remote code execution.",
                "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
                "affected":[{"package":{"ecosystem":"npm","name":"lodash"},
                "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.17.20"}]}]}]}"#,
        );
        let result = audit(
            &sbom_of(vec![component("lodash", "4.17.15", "npm")]),
            &[critical],
        );
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert!(
            result.findings[0].description.contains("10 out of 10"),
            "{}",
            result.findings[0].description
        );
    }

    #[test]
    fn a_low_rated_advisory_is_not_promoted_to_medium() {
        // The old code called everything it could not recognise medium, so a genuinely minor advisory
        // and an unrated one looked identical. They are different facts.
        let low = advisory(
            r#"{"id":"GHSA-low","summary":"Minor information leak.",
                "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"}],
                "affected":[{"package":{"ecosystem":"npm","name":"lodash"},
                "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.17.20"}]}]}]}"#,
        );
        let result = audit(
            &sbom_of(vec![component("lodash", "4.17.15", "npm")]),
            &[low],
        );
        assert_eq!(
            result.findings[0].severity,
            Severity::Low,
            "{:?}",
            result.findings[0]
        );
    }

    #[test]
    fn an_advisory_with_no_readable_rating_says_the_severity_is_a_placeholder() {
        // A v4 vector, which this cannot score. Showing "medium" without saying so would be believed
        // by anybody sorting the list by seriousness.
        let unrated = advisory(
            r#"{"id":"GHSA-v4","summary":"Something bad.",
                "severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
                "affected":[{"package":{"ecosystem":"npm","name":"lodash"},
                "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.17.20"}]}]}]}"#,
        );
        let result = audit(
            &sbom_of(vec![component("lodash", "4.17.15", "npm")]),
            &[unrated],
        );
        assert_eq!(result.findings[0].severity, Severity::Medium);
        assert!(
            result.findings[0].description.contains("placeholder"),
            "an unreadable rating must say so: {}",
            result.findings[0].description
        );
    }

    #[test]
    fn the_fixed_version_is_not_affected() {
        // Off-by-one here reports every upgraded app as vulnerable, which is the fastest way to teach
        // somebody to ignore this check.
        let result = audit(
            &sbom_of(vec![component("lodash", "4.17.20", "npm")]),
            &[advisory(LODASH)],
        );
        assert!(result.findings.is_empty(), "{result:?}");
    }

    #[test]
    fn a_pre_release_of_the_fixed_version_is_still_affected() {
        // 4.17.20-beta comes before 4.17.20, so the fix is not in it. Treating a pre-release as equal
        // to its release makes this report clean — a false negative on a genuinely vulnerable install,
        // and the worst mistake this file can make. The unit test on `compare` catches the same bug one
        // level down; this one catches it where it would actually be believed.
        let result = audit(
            &sbom_of(vec![component("lodash", "4.17.20-beta.1", "npm")]),
            &[advisory(LODASH)],
        );
        assert_eq!(
            result.findings.len(),
            1,
            "a pre-release of the fix is not the fix: {result:?}"
        );
    }

    #[test]
    fn a_later_version_is_not_affected() {
        let result = audit(
            &sbom_of(vec![component("lodash", "4.17.21", "npm")]),
            &[advisory(LODASH)],
        );
        assert!(result.findings.is_empty(), "{result:?}");
    }

    #[test]
    fn a_package_of_the_same_name_in_another_ecosystem_is_not_it() {
        // `lodash` on PyPI is not `lodash` on npm. Matching on the name alone invents vulnerabilities.
        let result = audit(
            &sbom_of(vec![component("lodash", "4.17.15", "Python")]),
            &[advisory(LODASH)],
        );
        assert!(result.findings.is_empty(), "{result:?}");
    }

    #[test]
    fn a_withdrawn_advisory_is_ignored() {
        let withdrawn = advisory(
            r#"{"id":"GHSA-gone","withdrawn":"2024-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}"#,
        );
        let result = audit(
            &sbom_of(vec![component("lodash", "4.17.15", "npm")]),
            &[withdrawn],
        );
        assert!(
            result.findings.is_empty(),
            "a withdrawn record is not a finding: {result:?}"
        );
    }

    #[test]
    fn an_ecosystem_the_database_says_nothing_about_is_named() {
        // The database covers npm. The Python packages beside it are not clean — they are unchecked,
        // and a result that does not say so is the "no news is good news" mistake.
        let sbom = sbom_of(vec![
            component("lodash", "4.17.21", "npm"),
            component("flask", "3.0.0", "Python"),
        ]);
        let result = audit(&sbom, &[advisory(LODASH)]);
        assert!(result.findings.is_empty());
        assert!(result.uncovered.contains("Python"), "{result:?}");
        assert!(!result.uncovered.contains("npm"), "{result:?}");
    }

    #[test]
    fn a_version_that_cannot_be_compared_is_admitted_to_rather_than_passed() {
        let git_version = advisory(
            r#"{"id":"GHSA-git","affected":[{"package":{"ecosystem":"Go","name":"example.com/m"},"ranges":[{"type":"GIT","events":[{"introduced":"0"}]}]}]}"#,
        );
        let sbom = sbom_of(vec![component(
            "example.com/m",
            "v0.0.0-20240101120000-abcdef123456",
            "Go",
        )]);
        let result = audit(&sbom, &[git_version]);
        assert!(result.findings.is_empty());
        assert_eq!(result.uncomparable.len(), 1, "{result:?}");
    }

    #[test]
    fn a_declared_version_is_reported_with_less_confidence_than_a_locked_one() {
        // The version came from a manifest, so it is what was asked for. The finding is still worth
        // making; pretending to be as sure about it as about a lockfile is not.
        let mut declared = component("lodash", "4.17.15", "npm");
        declared.source = VersionSource::Declared;
        let result = audit(&sbom_of(vec![declared]), &[advisory(LODASH)]);
        assert_eq!(result.findings[0].confidence, Confidence::Medium);

        let locked = audit(
            &sbom_of(vec![component("lodash", "4.17.15", "npm")]),
            &[advisory(LODASH)],
        );
        assert_eq!(locked.findings[0].confidence, Confidence::High);
    }

    #[test]
    fn versions_compare_the_way_a_package_manager_would() {
        use std::cmp::Ordering;
        assert_eq!(compare("1.2.3", "1.2.10"), Some(Ordering::Less));
        assert_eq!(compare("1.10.0", "1.9.9"), Some(Ordering::Greater));
        assert_eq!(compare("v1.2.3", "1.2.3"), Some(Ordering::Equal));
        assert_eq!(compare("1.2", "1.2.0"), Some(Ordering::Equal));
        // A pre-release comes before the release it leads to. The other way round says a vulnerable
        // 1.2.3-beta is fixed because the fix landed in 1.2.3.
        assert_eq!(compare("1.2.3-beta", "1.2.3"), Some(Ordering::Less));
        assert_eq!(compare("1.2.3-alpha", "1.2.3-beta"), Some(Ordering::Less));
        assert_eq!(compare("1.2.3-rc.2", "1.2.3-rc.10"), Some(Ordering::Less));
        assert_eq!(
            compare("1.2.3+build9", "1.2.3+build1"),
            Some(Ordering::Equal)
        );
        // A Go pseudo-version is ordered, and Go's own module system relies on it being so.
        assert_eq!(
            compare("v0.0.0-20240101120000-abcdef", "1.0.0"),
            Some(Ordering::Less)
        );
        // Genuinely not comparable, and saying so beats guessing.
        assert_eq!(compare("latest", "1.0.0"), None);
        assert_eq!(compare("", "1.0.0"), None);
    }
}
