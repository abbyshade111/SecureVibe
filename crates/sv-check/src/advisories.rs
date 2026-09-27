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
use sv_manifest::FixWithinDays;

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
    /// When the record was published, as RFC 3339. The vulnerability may have been known before
    /// that, never after, so an age counted from here is the shortest it can be.
    #[serde(default)]
    pub published: Option<String>,
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
    /// For each finding's rule id, how it stands against the owner's time frame.
    pub due: std::collections::BTreeMap<String, Due>,
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

/// The requirement a clean comparison is evidence about: the app contains only components that have
/// not breached the documented remediation time frames. Named once, so `sv coverage` cannot drift.
pub const COMPONENTS_REQUIREMENT: &str = "V15.2.1";

/// Matches every component against the database, with no time frames to judge the findings by.
pub fn audit(sbom: &Sbom, database: &[Advisory]) -> AuditResult {
    audit_against(sbom, database, None, None)
}

/// Matches every component against the database, and holds each finding to the owner's time frame.
///
/// `today` is `None` when the clock could not be read, and then nothing is judged against a time
/// frame at all: a wrong "today" could only ever make something overdue look as though it were not.
pub fn audit_against(
    sbom: &Sbom,
    database: &[Advisory],
    time_frames: Option<&FixWithinDays>,
    today: Option<Day>,
) -> AuditResult {
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
                        let due = due_for(advisory, time_frames, today);
                        result.findings.push(finding_for(component, advisory, &due));
                        result.due.insert(format!("advisory.{}", advisory.id), due);
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
    // against, and that must never be nothing — and labeled rather than left to look load-bearing.
    // The test asserts the behavior, not which condition produced it.
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
            &[COMPONENTS_REQUIREMENT],
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

fn finding_for(component: &Component, advisory: &Advisory, due: &Due) -> Finding {
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
        //
        // Inside the owner's time frame it is still a known vulnerability, and still a finding,
        // but it is not a breach of the time frame, which is what V15.2.1 asks about. Anything
        // that cannot be shown to be inside it — no time frame, no date — is counted as a breach,
        // because that is what this said before there were time frames to compare with.
        requirement_ids: if due.is_within() {
            Vec::new()
        } else {
            vec![COMPONENTS_REQUIREMENT.into()]
        },
        cwe: vec![],
        description: {
            let what = if advisory.summary.is_empty() {
                format!(
                    "{names} affects {} {}. {rating}",
                    component.name, component.version
                )
            } else {
                format!("{} {rating}", advisory.summary)
            };
            format!("{what} {}", due.sentence())
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

/// A calendar day, counted from 1 January 1970. Enough date arithmetic for a deadline and no more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Day(pub i64);

impl Day {
    /// The date at the start of an RFC 3339 timestamp, `YYYY-MM-DD`. Anything else is `None`, and
    /// a finding with no date it can read is judged against no time frame.
    pub fn parse(text: &str) -> Option<Day> {
        let date = text.get(..10)?;
        let b = date.as_bytes();
        let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
        if b[4] != b'-' || b[7] != b'-' || !digits(0..4) || !digits(5..7) || !digits(8..10) {
            return None;
        }
        let year: i64 = date[..4].parse().ok()?;
        let month: i64 = date[5..7].parse().ok()?;
        let day: i64 = date[8..10].parse().ok()?;
        if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
            return None;
        }
        Some(Day(days_from_civil(year, month, day)))
    }

    /// Today, by this computer's clock. `None` if the clock reads before 1970, which is a clock
    /// that is wrong rather than a date to judge anything by.
    pub fn today() -> Option<Day> {
        let since = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        Some(Day(i64::try_from(since.as_secs() / 86_400).ok()?))
    }

    pub fn plus(self, days: u32) -> Day {
        Day(self.0 + i64::from(days))
    }

    /// `YYYY-MM-DD`, which reads the same everywhere.
    pub fn show(self) -> String {
        let (y, m, d) = civil_from_days(self.0);
        format!("{y:04}-{m:02}-{d:02}")
    }
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// Howard Hinnant's algorithms for converting between a civil date and a day count.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// How one known vulnerability stands against the owner's time frame for fixing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Due {
    /// Past the time frame. This is the breach V15.2.1 asks about.
    Overdue {
        published: Day,
        allowed: u32,
        /// No rating could be read, so `allowed` is the shortest time frame stated.
        unrated: bool,
        by: Day,
        days_over: i64,
    },
    /// Inside it. Still a known vulnerability, and still a finding; not yet a breach.
    Within {
        published: Day,
        allowed: u32,
        unrated: bool,
        by: Day,
    },
    /// Nothing to judge it by, so it counts against V15.2.1 as it always did. Says why.
    Unjudged(String),
}

impl Due {
    pub fn is_within(&self) -> bool {
        matches!(self, Due::Within { .. })
    }

    /// The sentence the finding carries about its deadline, or about why it has none.
    pub fn sentence(&self) -> String {
        match self {
            Due::Overdue {
                published,
                allowed,
                unrated,
                by,
                days_over,
            } => format!(
                "Published on {}, and {}, so it was due by {} and is {days_over} day{} past it.",
                published.show(),
                time_frame_words(*allowed, *unrated),
                by.show(),
                plural(*days_over)
            ),
            Due::Within {
                published,
                allowed,
                unrated,
                by,
            } => format!(
                "Published on {}, and {}, so it is due by {}. It may have been known before it \
                 was published, never after.",
                published.show(),
                time_frame_words(*allowed, *unrated),
                by.show()
            ),
            // Said in the finding itself, so every place that shows it — `sv audit`, the report,
            // SARIF — carries the reason rather than only the terminal.
            Due::Unjudged(why) => {
                format!("It is treated as past your time frame for fixing it, because {why}.")
            }
        }
    }
}

/// Which time frame applied, and why, when it was not simply the one for the advisory's rating.
fn time_frame_words(allowed: u32, unrated: bool) -> String {
    let days = format!("{allowed} day{}", plural(i64::from(allowed)));
    if unrated {
        format!(
            "with no rating to go by it is held to the shortest time frame you set, which is {days}"
        )
    } else {
        format!("your time frame for this is {days}")
    }
}

fn plural(n: i64) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// The time frame that applies to one advisory, and where it puts the advisory today.
fn due_for(advisory: &Advisory, time_frames: Option<&FixWithinDays>, today: Option<Day>) -> Due {
    let Some(frames) = time_frames else {
        return Due::Unjudged("securevibe.toml states no time frames".to_owned());
    };
    let Some(today) = today else {
        return Due::Unjudged("this computer's clock could not be read".to_owned());
    };
    let rated = crate::cvss::severity_of(advisory.severity.iter().map(|s| s.score.as_str()));
    let unrated = rated.is_none();
    let allowed = match rated {
        Some((severity, _)) => {
            let stated = match severity {
                Severity::Critical => frames.critical,
                Severity::High => frames.high,
                Severity::Medium => frames.medium,
                Severity::Low | Severity::Info => frames.low,
            };
            let Some(days) = stated else {
                return Due::Unjudged(format!(
                    "securevibe.toml states no time frame for {} vulnerabilities",
                    severity.name()
                ));
            };
            days
        }
        // No rating it can read, so the severity is unknown. The shortest time frame stated is
        // the one that cannot hide a breach: any longer one could call something inside its
        // deadline that the real rating would put past it.
        None => {
            let shortest = [frames.critical, frames.high, frames.medium, frames.low]
                .into_iter()
                .flatten()
                .min();
            let Some(days) = shortest else {
                return Due::Unjudged("securevibe.toml states no time frames".to_owned());
            };
            days
        }
    };
    let Some(published) = advisory.published.as_deref().and_then(Day::parse) else {
        return Due::Unjudged(
            "the advisory carries no publication date that can be read".to_owned(),
        );
    };
    let by = published.plus(allowed);
    if today > by {
        Due::Overdue {
            published,
            allowed,
            unrated,
            by,
            days_over: today.0 - by.0,
        }
    } else {
        Due::Within {
            published,
            allowed,
            unrated,
            by,
        }
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
        // The old code called everything it could not recognize medium, so a genuinely minor advisory
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

#[cfg(test)]
mod deadline_tests {
    use super::*;
    use crate::sbom::VersionSource;

    fn day(text: &str) -> Day {
        Day::parse(text).expect("a real date")
    }

    fn lodash() -> Sbom {
        Sbom {
            components: vec![Component {
                name: "lodash".into(),
                version: "4.17.15".into(),
                ecosystem: "npm".into(),
                source: VersionSource::Locked,
            }],
            unread: Vec::new(),
        }
    }

    /// An advisory against lodash 4.17.15, rated high (7.5) unless `vector` says otherwise.
    fn advisory(published: Option<&str>, vector: Option<&str>) -> Advisory {
        let severity = match vector {
            Some(v) => format!(r#","severity":[{{"type":"CVSS_V3","score":"{v}"}}]"#),
            None => String::new(),
        };
        let published = match published {
            Some(p) => format!(r#","published":"{p}""#),
            None => String::new(),
        };
        serde_json::from_str(&format!(
            r#"{{"id":"GHSA-due","summary":"Prototype pollution."{severity}{published},
                "affected":[{{"package":{{"ecosystem":"npm","name":"lodash"}},
                "ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"4.17.20"}}]}}]}}]}}"#
        ))
        .expect("advisory parses")
    }

    const HIGH: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";
    const CRITICAL: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";

    fn frames(critical: Option<u32>, high: Option<u32>, low: Option<u32>) -> FixWithinDays {
        FixWithinDays {
            critical,
            high,
            medium: None,
            low,
        }
    }

    fn run(advisory: Advisory, frames: Option<&FixWithinDays>, today: Option<&str>) -> AuditResult {
        audit_against(&lodash(), &[advisory], frames, today.map(day))
    }

    #[test]
    fn dates_are_read_and_written_the_same_way() {
        assert_eq!(day("1970-01-01"), Day(0));
        assert_eq!(day("2020-07-15T19:15:00Z").show(), "2020-07-15");
        assert_eq!(day("2024-02-29").show(), "2024-02-29");
        assert_eq!(day("2023-12-31").plus(1).show(), "2024-01-01");
        assert_eq!(day("2024-02-28").plus(2).show(), "2024-03-01");
        for bad in [
            "2023-02-29",
            "2020-13-01",
            "2020/07/15",
            "20-07-15",
            "+020-07-15",
            "",
            "soon",
        ] {
            assert_eq!(Day::parse(bad), None, "{bad:?} is not a date");
        }
    }

    #[test]
    fn past_the_time_frame_is_a_breach_of_v15_2_1() {
        let result = run(
            advisory(Some("2020-01-01T00:00:00Z"), Some(HIGH)),
            Some(&frames(None, Some(30), None)),
            Some("2020-03-01"),
        );
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].requirement_ids, ["V15.2.1"]);
        assert!(
            matches!(
                result.due["advisory.GHSA-due"],
                Due::Overdue { days_over: 30, .. }
            ),
            "{:?}",
            result.due
        );
        assert!(
            result.findings[0].description.contains("due by 2020-01-31"),
            "{}",
            result.findings[0].description
        );
    }

    #[test]
    fn inside_the_time_frame_is_still_a_finding_and_not_a_breach() {
        let result = run(
            advisory(Some("2020-01-01T00:00:00Z"), Some(HIGH)),
            Some(&frames(None, Some(30), None)),
            Some("2020-01-10"),
        );
        assert_eq!(
            result.findings.len(),
            1,
            "a known vulnerability is never dropped"
        );
        assert!(
            result.findings[0].requirement_ids.is_empty(),
            "inside the time frame is not a breach of it: {:?}",
            result.findings[0].requirement_ids
        );
        assert!(result.due["advisory.GHSA-due"].is_within());
        assert!(
            result.findings[0].description.contains("due by 2020-01-31"),
            "{}",
            result.findings[0].description
        );
    }

    #[test]
    fn a_vulnerability_inside_its_time_frame_still_stops_the_clean_claim() {
        // The mistake this change invites. With nothing citing V15.2.1 any more, "no finding about
        // V15.2.1" and "nothing found" are different sentences, and only the second is a clean
        // comparison. A package with a known vulnerability is not clean because it is not late yet.
        let result = run(
            advisory(Some("2020-01-01T00:00:00Z"), Some(HIGH)),
            Some(&frames(None, Some(30), None)),
            Some("2020-01-10"),
        );
        assert!(result.due["advisory.GHSA-due"].is_within(), "the setup");
        assert!(
            result.verified.is_empty(),
            "credited V15.2.1 with a known vulnerability in the app: {:?}",
            result.verified
        );
    }

    #[test]
    fn the_last_day_is_inside_and_the_day_after_is_not() {
        let frames = frames(None, Some(30), None);
        let on = run(
            advisory(Some("2020-01-01"), Some(HIGH)),
            Some(&frames),
            Some("2020-01-31"),
        );
        assert!(on.due["advisory.GHSA-due"].is_within(), "{:?}", on.due);
        let after = run(
            advisory(Some("2020-01-01"), Some(HIGH)),
            Some(&frames),
            Some("2020-02-01"),
        );
        assert!(
            matches!(
                after.due["advisory.GHSA-due"],
                Due::Overdue { days_over: 1, .. }
            ),
            "{:?}",
            after.due
        );
    }

    #[test]
    fn nothing_to_judge_by_counts_against_v15_2_1_as_it_always_did() {
        // Every way the comparison could be missing a piece. Each must leave the finding citing
        // V15.2.1, because "not shown to be late" is not "shown to be on time".
        let cases: [(&str, Advisory, Option<FixWithinDays>, Option<&str>); 5] = [
            (
                "no time frames",
                advisory(Some("2020-01-01"), Some(HIGH)),
                None,
                Some("2020-01-10"),
            ),
            (
                "none for this severity",
                advisory(Some("2020-01-01"), Some(CRITICAL)),
                Some(frames(None, Some(30), None)),
                Some("2020-01-10"),
            ),
            (
                "no publication date",
                advisory(None, Some(HIGH)),
                Some(frames(None, Some(30), None)),
                Some("2020-01-10"),
            ),
            (
                "a date that is not one",
                advisory(Some("last Tuesday"), Some(HIGH)),
                Some(frames(None, Some(30), None)),
                Some("2020-01-10"),
            ),
            (
                "no clock",
                advisory(Some("2020-01-01"), Some(HIGH)),
                Some(frames(None, Some(30), None)),
                None,
            ),
        ];
        for (why, advisory, frames, today) in cases {
            let result = run(advisory, frames.as_ref(), today);
            assert_eq!(result.findings.len(), 1, "{why}");
            assert_eq!(result.findings[0].requirement_ids, ["V15.2.1"], "{why}");
            assert!(
                matches!(result.due["advisory.GHSA-due"], Due::Unjudged(_)),
                "{why}: {:?}",
                result.due
            );
        }
    }

    #[test]
    fn an_unrated_advisory_is_held_to_the_shortest_time_frame() {
        // Its real severity is unknown, and any time frame longer than the shortest could call
        // something on time that its real rating would make late.
        let result = run(
            advisory(Some("2020-01-01"), None),
            Some(&frames(Some(7), None, Some(180))),
            Some("2020-01-20"),
        );
        assert!(
            matches!(
                result.due["advisory.GHSA-due"],
                Due::Overdue { allowed: 7, .. }
            ),
            "{:?}",
            result.due
        );
        assert_eq!(result.findings[0].requirement_ids, ["V15.2.1"]);
        assert!(
            result.findings[0]
                .description
                .contains("shortest time frame you set"),
            "the reader is not told why the critical number applies: {}",
            result.findings[0].description
        );
    }
}
