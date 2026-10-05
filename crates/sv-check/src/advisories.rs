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
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::LazyLock;
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
    /// The last version affected, for a range with no fixed release yet: the version named is
    /// affected, and the ones after it are not.
    #[serde(default)]
    pub last_affected: Option<String>,
    /// Every other key, kept so a range carrying one is known to say something this does not read.
    /// Until 29 September 2026 serde dropped them without a word, and a range ending in
    /// `last_affected` read as never ending: paramiko 5.0.0 was reported under an advisory whose
    /// last affected version is 4.0.0.
    #[serde(flatten)]
    pub other: std::collections::BTreeMap<String, serde_json::Value>,
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
    Ok(read_database(dir)?.records)
}

/// The records of an advisory database, and the JSON files in it that could not be read as one.
#[derive(Debug, Default)]
pub struct Database {
    pub records: Vec<Advisory>,
    /// Each file that could not be read as a record, from the database's folder, with why.
    pub unread: Vec<(String, String)>,
}

/// As `load_database`, and the files that could not be read. A record this version of `sv` cannot parse is
/// skipped rather than fatal, since an OSV export carries records with fields added since, and refusing the
/// whole database over one would trade a partial answer for none; but it is counted and named, since a
/// vulnerability in a file nobody read is not one the app is clear of (the deep review's improvement 4).
pub fn read_database(dir: &Path) -> std::io::Result<Database> {
    let mut out = Database::default();
    load_into(dir, dir, &mut out)?;
    out.unread.sort();
    Ok(out)
}

fn load_into(root: &Path, dir: &Path, out: &mut Database) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            load_into(root, &path, out)?;
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) => {
                out.unread
                    .push((name, format!("it could not be read ({e})")));
                continue;
            }
        };
        match serde_json::from_str::<Advisory>(&text) {
            Ok(advisory) => out.records.push(advisory),
            Err(e) => out
                .unread
                .push((name, format!("it is not an OSV record `sv` can read ({e})"))),
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

/// `compare`, in the way the ecosystem's own installer orders versions: PEP 440 for PyPI, which writes a
/// pre-release with no separator (`2.0.0rc1`), and semver for the rest.
fn compare_in(ecosystem: &str, a: &str, b: &str) -> Option<std::cmp::Ordering> {
    match ecosystem {
        "PyPI" => Some(pep440_key(a)?.cmp(&pep440_key(b)?)),
        "RubyGems" => compare_gem(a, b),
        _ => compare(a, b),
    }
}

/// One part of a RubyGems version: a number, or letters, which mark a pre-release.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GemSegment {
    Number(u64),
    Letters(String),
}

/// Compares two versions the way RubyGems does (`Gem::Version#<=>`), not as semver: `1.0.0.rc1` is a
/// pre-release of `1.0.0`, `1.0` equals `1.0.0`, and a `-` is read as `.pre.`. `None` for a string
/// that is not a RubyGems version, such as one still carrying a platform (`1.15.4-x86_64-linux`
/// would read as a pre-release); the lockfile reader takes the platform off first.
fn compare_gem(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    use std::cmp::Ordering;
    static GEM_VERSION: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[0-9]+(?:\.[0-9a-zA-Z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")
            .expect("the RubyGems pattern is valid")
    });
    static SEGMENT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new("[0-9]+|[a-zA-Z]+").expect("the segment pattern is valid"));
    // `Gem::Version#canonical_segments`: the numbers before the first letters and the parts from
    // there on, each without its trailing zeros.
    fn segments(version: &str) -> Option<Vec<GemSegment>> {
        let version = version.trim();
        if !GEM_VERSION.is_match(version) {
            return None;
        }
        let version = version.replace('-', ".pre.");
        let all: Vec<GemSegment> = SEGMENT
            .find_iter(&version)
            .map(|m| match m.as_str().parse::<u64>() {
                Ok(n) => Some(GemSegment::Number(n)),
                Err(_) if m.as_str().bytes().all(|b| b.is_ascii_digit()) => None,
                Err(_) => Some(GemSegment::Letters(m.as_str().to_owned())),
            })
            .collect::<Option<_>>()?;
        let split = all
            .iter()
            .position(|s| matches!(s, GemSegment::Letters(_)))
            .unwrap_or(all.len());
        let trim = |part: &[GemSegment]| {
            let mut part = part.to_vec();
            while part.last() == Some(&GemSegment::Number(0)) {
                part.pop();
            }
            part
        };
        let mut out = trim(&all[..split]);
        out.extend(trim(&all[split..]));
        Some(out)
    }
    let (x, y) = (segments(a)?, segments(b)?);
    for i in 0..x.len().max(y.len()) {
        let zero = GemSegment::Number(0);
        let (l, r) = (x.get(i).unwrap_or(&zero), y.get(i).unwrap_or(&zero));
        let order = match (l, r) {
            (GemSegment::Number(p), GemSegment::Number(q)) => p.cmp(q),
            (GemSegment::Letters(p), GemSegment::Letters(q)) => p.cmp(q),
            (GemSegment::Letters(_), GemSegment::Number(_)) => Ordering::Less,
            (GemSegment::Number(_), GemSegment::Letters(_)) => Ordering::Greater,
        };
        if order != Ordering::Equal {
            return Some(order);
        }
    }
    Some(Ordering::Equal)
}

/// The parts a PEP 440 version sorts by: epoch, release, pre-release, post-release, development.
type Pep440Key = (u64, Vec<u64>, (u8, u8, u64), (u8, u64), (u8, u64));

/// What a PEP 440 version sorts by, in the order pip and Python's `packaging` sort it: epoch, then
/// the release numbers (trailing zeros ignored), then pre-release, post-release, and development
/// release. The local label after `+` is ignored, where `packaging` would sort `2.1.0+cu118` after
/// `2.1.0`: a local build is built from that release's source, so an advisory whose last affected
/// version is `2.1.0` has to reach it too. So
/// `1.0.dev0 < 1.0a1 < 1.0b1 < 1.0rc1 < 1.0 < 1.0.post1`, and `1!1.0` is after every version with
/// no epoch. `None` for a string that is not a PEP 440 version.
fn pep440_key(version: &str) -> Option<Pep440Key> {
    static PEP440: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?ix)^v?
              (?:(?P<epoch>[0-9]+)!)?
              (?P<release>[0-9]+(?:\.[0-9]+)*)
              (?:[-_.]?(?P<pre_l>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<pre_n>[0-9]+)?)?
              (?:-(?P<post_n1>[0-9]+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?)?
              (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
              (?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$",
        )
        .expect("the PEP 440 pattern is valid")
    });
    let c = PEP440.captures(version.trim())?;
    let number =
        |name: &str| -> Option<u64> { c.name(name).map_or(Some(0), |m| m.as_str().parse().ok()) };
    let epoch = number("epoch")?;
    let mut release: Vec<u64> = c["release"]
        .split('.')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    while release.len() > 1 && release.last() == Some(&0) {
        release.pop();
    }
    let has_post = c.name("post_n1").is_some() || c.name("post_l").is_some();
    let has_dev = c.name("dev_l").is_some();
    // A development release with nothing before it comes before every pre-release of that version;
    // a final release comes after them all.
    let pre = match c.name("pre_l").map(|m| m.as_str().to_ascii_lowercase()) {
        Some(letter) => {
            let rank = match letter.as_str() {
                "a" | "alpha" => 0,
                "b" | "beta" => 1,
                _ => 2,
            };
            (1, rank, number("pre_n")?)
        }
        None if has_dev && !has_post => (0, 0, 0),
        None => (2, 0, 0),
    };
    let post = if has_post {
        let n = match c.name("post_n1") {
            Some(m) => m.as_str().parse().ok()?,
            None => number("post_n2")?,
        };
        (1, n)
    } else {
        (0, 0)
    };
    let dev = if has_dev {
        (0, number("dev_n")?)
    } else {
        (1, 0)
    };
    Some((epoch, release, pre, post, dev))
}

/// Whether `version` falls inside an affected range, compared as `ecosystem` orders its versions.
fn in_range(ecosystem: &str, version: &str, range: &Range) -> Option<bool> {
    // Only semantic and ecosystem ranges are ordered in a way this can reason about.
    if range.kind == "GIT" {
        return None;
    }
    // An event this does not read (OSV's `limit` belongs to GIT ranges, and a field added later
    // would land here too) could end the range anywhere, so the range is not compared rather than
    // read without it: a gap in the report, not a finding made up.
    if range.events.iter().any(|e| !e.other.is_empty()) {
        return None;
    }
    // OSV asks for the events to be read in version order, not the order they are written in:
    // 86 real ranges list a later `introduced` before an earlier `fixed`, and read in file order
    // they end the range too soon. Two events at the same version could be read either way, so a
    // range with any is not compared.
    let mut events: Vec<(EventKind, &str)> = Vec::new();
    for event in &range.events {
        for (kind, at) in [
            (EventKind::Introduced, &event.introduced),
            (EventKind::Fixed, &event.fixed),
            (EventKind::LastAffected, &event.last_affected),
        ] {
            if let Some(at) = at {
                events.push((kind, at.as_str()));
            }
        }
    }
    let order = |a: &str, b: &str| -> Option<std::cmp::Ordering> {
        // OSV writes "0" for "every version from the beginning", which is not a version and would
        // not parse as one.
        match (a == "0", b == "0") {
            (true, true) => Some(std::cmp::Ordering::Equal),
            (true, false) => Some(std::cmp::Ordering::Less),
            (false, true) => Some(std::cmp::Ordering::Greater),
            (false, false) => compare_in(ecosystem, a, b),
        }
    };
    // An insertion sort, since a comparison can fail and the ranges are short.
    let mut sorted: Vec<(EventKind, &str)> = Vec::with_capacity(events.len());
    for (kind, at) in events {
        let mut place = sorted.len();
        for (i, (_, other)) in sorted.iter().enumerate() {
            match order(at, other)? {
                std::cmp::Ordering::Equal => return None,
                std::cmp::Ordering::Less => {
                    place = i;
                    break;
                }
                std::cmp::Ordering::Greater => {}
            }
        }
        sorted.insert(place, (kind, at));
    }
    let mut affected = false;
    for (kind, at) in sorted {
        let here = order(version, at)?;
        match kind {
            EventKind::Introduced if here != std::cmp::Ordering::Less => affected = true,
            EventKind::Fixed if here != std::cmp::Ordering::Less => affected = false,
            // `last_affected` is the last version still affected, where `fixed` is the first that
            // is not: past it, not affected; at it, still affected.
            EventKind::LastAffected if here == std::cmp::Ordering::Greater => affected = false,
            _ => {}
        }
    }
    Some(affected)
}

/// The three kinds of event a range is read from.
#[derive(Debug, Clone, Copy)]
enum EventKind {
    Introduced,
    Fixed,
    LastAffected,
}

fn matches(component: &Component, affected: &Affected) -> Option<bool> {
    let Some(expected) = osv_ecosystem(&component.ecosystem) else {
        return Some(false);
    };
    if affected.package.ecosystem != expected
        || !same_package(expected, &affected.package.name, &component.name)
    {
        return Some(false);
    }
    if affected.versions.iter().any(|v| v == &component.version) {
        return Some(true);
    }
    // No explicit list, or the version is not in it: fall back to the ranges.
    let mut any_comparable = affected.ranges.is_empty();
    for range in &affected.ranges {
        match in_range(expected, &component.version, range) {
            Some(true) => return Some(true),
            Some(false) => any_comparable = true,
            None => {}
        }
    }
    if any_comparable { Some(false) } else { None }
}

/// Whether an advisory's package name and a component's name are the same package.
///
/// PyPI treats `jupyter_server`, `Jupyter-Server` and `jupyter.server` as one name (PEP 503: case
/// folded, and every run of `-`, `_` and `.` read as one `-`). A lockfile and an advisory may each
/// spell it either way, so comparing the spellings would quietly miss the advisory.
fn same_package(ecosystem: &str, advisory: &str, ours: &str) -> bool {
    if ecosystem == "PyPI" {
        crate::manifest_lock::python_name(advisory) == crate::manifest_lock::python_name(ours)
    } else {
        advisory.eq_ignore_ascii_case(ours)
    }
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

    // Which ecosystems the database is about: those with a record about that ecosystem and no other.
    // A record that names several is in several exports, so a mention alone says nothing about which
    // was loaded: OSV's crates.io export holds records that also name PyPI packages, and counting a
    // mention would call a Python app compared against a database with nothing else about Python in it.
    let covered: BTreeSet<&str> = database
        .iter()
        .filter_map(|a| {
            let first = a.affected.first()?.package.ecosystem.as_str();
            a.affected
                .iter()
                .all(|x| x.package.ecosystem == first)
                .then_some(first)
        })
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
        let mut matched: Vec<&Advisory> = Vec::new();
        for advisory in database {
            if advisory.withdrawn.is_some() {
                continue;
            }
            // Undecided is per advisory: one that matches settles itself, and says nothing about
            // another that could not be compared, which stays a gap in the report.
            let mut this_one_undecided = false;
            let mut hit = false;
            for affected in &advisory.affected {
                match matches(component, affected) {
                    Some(true) => {
                        hit = true;
                        break;
                    }
                    None => this_one_undecided = true,
                    Some(false) => {}
                }
            }
            if hit {
                matched.push(advisory);
            } else if this_one_undecided {
                undecided = true;
            }
        }
        // One vulnerability, once: records that name each other (a GitHub advisory and the PyPI one
        // for the same flaw, each listing the other as an alias) are one finding, from the record
        // rated most serious, since two ratings of one flaw that disagree are settled toward care.
        for twins in same_vulnerability(&matched) {
            let advisory = twins
                .iter()
                .copied()
                .min_by_key(|a| (seriousness(a), a.id.clone()))
                .expect("a group is never empty");
            let due = due_for(advisory, time_frames, today);
            let mut finding = finding_for(component, advisory, &due);
            let others: Vec<&str> = twins
                .iter()
                .filter(|a| a.id != advisory.id)
                .map(|a| a.id.as_str())
                .filter(|id| !advisory.aliases.iter().any(|x| x == id))
                .collect();
            if !others.is_empty() {
                finding.title = format!("{} (also {})", finding.title, others.join(", "));
            }
            result.findings.push(finding);
            result.due.insert(format!("advisory.{}", advisory.id), due);
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
    //
    // A second lockfile nobody read is the same wrong question from the other side: every package
    // in the list was compared, and the list may not be what the app is installed from.
    //
    // A manifest that asks for other versions than its lockfile has is the same again: the list
    // describes the lockfile, and whoever installs from the manifest runs something else.
    // A package listed only by what the manifest asks for is not known to be what is installed, so
    // a clean comparison of it is a clean comparison of the request, not of the app.
    let complete_enough = sbom.is_complete()
        && sbom.passed_over.is_empty()
        && !sbom
            .disagreements
            .iter()
            .any(crate::sbom::Disagreement::differs);
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
            clean_scope(sbom, result.advisories_read),
        ));
    }
    result
}

/// What a clean comparison says it covered (deep review, improvement 2): how many packages of each
/// ecosystem, the lockfiles they were read from, that a lockfile's list holds the packages the
/// others need and its development packages, and what no lockfile lists.
fn clean_scope(sbom: &Sbom, advisories: usize) -> String {
    format!(
        "all {} in the bill of materials ({}), compared against {} advisor{}. That is everything each \
         lockfile lists: the packages the app asks for, the packages those need in turn, and the \
         development packages a lockfile keeps beside them. Not in it: anything installed another \
         way, such as the system's own packages, a container image's, or a script loaded from \
         another site",
        crate::sbom::count(sbom.components.len(), "package", "packages"),
        sbom.what_was_read(),
        advisories,
        if advisories == 1 { "y" } else { "ies" },
    )
}

/// The records in `matched` grouped by the vulnerability they describe: two are the same when one's
/// id or aliases name the other's id or aliases, directly or through a third.
fn same_vulnerability<'a>(matched: &[&'a Advisory]) -> Vec<Vec<&'a Advisory>> {
    let names = |a: &Advisory| -> BTreeSet<String> {
        std::iter::once(a.id.clone())
            .chain(a.aliases.iter().cloned())
            .collect()
    };
    let mut groups: Vec<(BTreeSet<String>, Vec<&'a Advisory>)> = Vec::new();
    for advisory in matched {
        let mine = names(advisory);
        let (mut joined, rest): (Vec<_>, Vec<_>) = groups
            .into_iter()
            .partition(|(known, _)| !known.is_disjoint(&mine));
        let mut merged = (mine, vec![*advisory]);
        for (known, members) in joined.drain(..) {
            merged.0.extend(known);
            merged.1.extend(members);
        }
        groups = rest;
        groups.push(merged);
    }
    groups.into_iter().map(|(_, members)| members).collect()
}

/// How serious a record says its flaw is, for choosing between records of one flaw: its own CVSS
/// rating, most serious first, and a record with no rating `sv` can read after every rated one.
fn seriousness(advisory: &Advisory) -> (u8, Severity) {
    match crate::cvss::severity_of(advisory.severity.iter().map(|s| s.score.as_str())) {
        Some((severity, _)) => (0, severity),
        None => (1, Severity::Medium),
    }
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
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
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
/// The time of day in an RFC 3339 timestamp, after its `T`: `HH:MM:SS`, a fraction of a second if
/// any, and `Z` or an offset `+HH:MM`.
fn is_time(text: &str) -> bool {
    let b = text.as_bytes();
    let digits =
        |r: std::ops::Range<usize>| b.get(r).is_some_and(|d| d.iter().all(u8::is_ascii_digit));
    if b.len() < 9
        || !digits(0..2)
        || b[2] != b':'
        || !digits(3..5)
        || b[5] != b':'
        || !digits(6..8)
    {
        return false;
    }
    let mut rest = &text[8..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let n = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 {
            return false;
        }
        rest = &fraction[n..];
    }
    let o = rest.as_bytes();
    matches!(rest, "Z" | "z")
        || (o.len() == 6
            && matches!(o[0], b'+' | b'-')
            && o[1..3].iter().all(u8::is_ascii_digit)
            && o[3] == b':'
            && o[4..6].iter().all(u8::is_ascii_digit))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Day(pub i64);

impl Day {
    /// A date, `YYYY-MM-DD`, alone or at the start of an RFC 3339 timestamp. Anything else is
    /// `None`, and a finding with no date it can read is judged against no time frame. Text after
    /// the date that is not a whole time of day is refused, where it was once read past: an entry
    /// dated `2026-09-27 or so` counted as dated that day (the deep review's improvement 6).
    pub fn parse(text: &str) -> Option<Day> {
        let date = text.get(..10)?;
        if !(text.len() == 10 || text[10..].strip_prefix(['T', 't']).is_some_and(is_time)) {
            return None;
        }
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
        Day::of(std::time::SystemTime::now())
    }

    /// The day a moment falls on, such as a file's modification time. `None` before 1970.
    pub fn of(time: std::time::SystemTime) -> Option<Day> {
        let since = time.duration_since(std::time::UNIX_EPOCH).ok()?;
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
            passed_over: Vec::new(),
            disagreements: Vec::new(),
            lockfiles: Vec::new(),
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

    /// The record the cato-pipeline session reported, cut down: no fixed release, only the last
    /// affected one, and no list of versions that would decide it first.
    const LAST_AFFECTED: &str = r#"{
      "id": "GHSA-r374-rxx8-8654",
      "aliases": ["PYSEC-2026-2858"],
      "summary": "An issue in paramiko",
      "affected": [{
        "package": {"ecosystem": "PyPI", "name": "paramiko"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "4.0.0"}]}]
      }]
    }"#;

    #[test]
    fn a_version_after_the_last_affected_one_is_not_reported() {
        for (version, affected) in [
            ("3.5.1", true),
            ("4.0.0", true),
            ("4.0.1", false),
            ("5.0.0", false),
        ] {
            let result = audit(
                &sbom_of(vec![component("paramiko", version, "Python")]),
                &[advisory(LAST_AFFECTED)],
            );
            assert_eq!(
                result.findings.len(),
                usize::from(affected),
                "{version}: {result:?}"
            );
            assert!(result.uncomparable.is_empty(), "{version}: {result:?}");
        }
    }

    #[test]
    fn python_versions_are_ordered_by_pep_440() {
        use std::cmp::Ordering::{Equal, Greater, Less};
        let py = |a: &str, b: &str| compare_in("PyPI", a, b);
        // The cases the cato-pipeline session reported from family-hub.
        for (a, b, expected) in [
            ("3.1.9", "2.0.0rc1", Greater),
            ("2.0.0rc1", "2.0.0", Less),
            ("1.0a1", "1.0b1", Less),
            ("1.0.post1", "1.0", Greater),
            ("1.0.dev0", "1.0a1", Less),
            ("1!1.0", "2.0", Greater),
        ] {
            assert_eq!(py(a, b), Some(expected), "{a} against {b}");
            assert_eq!(py(b, a), Some(expected.reverse()), "{b} against {a}");
        }
        // The whole order, each one before the next: development, the pre-releases, the release,
        // and its post-releases, with a development release of a post-release between them.
        let chain = [
            "1.0.dev0",
            "1.0.dev1",
            "1.0a1.dev0",
            "1.0a1",
            "1.0a2",
            "1.0b1",
            "1.0rc1",
            "1.0rc2",
            "1.0",
            "1.0.post1.dev0",
            "1.0.post1",
            "1.0.post2",
            "1.0.1",
            "1.1.dev0",
            "2.0",
        ];
        for pair in chain.windows(2) {
            assert_eq!(
                py(pair[0], pair[1]),
                Some(Less),
                "{} before {}",
                pair[0],
                pair[1]
            );
        }
        // Other spellings of the same version, and what is ignored.
        for (a, b) in [
            ("1.0", "1.0.0"),
            ("1.0alpha1", "1.0a1"),
            ("1.0-beta.2", "1.0b2"),
            ("1.0c1", "1.0rc1"),
            ("1.0.preview1", "1.0rc1"),
            ("1.0RC1", "1.0rc1"),
            ("1.0-1", "1.0.post1"),
            ("1.0.rev1", "1.0.post1"),
            ("1.0+local.7", "1.0"),
            ("v2.0", "2.0"),
            ("1.0a", "1.0a0"),
        ] {
            assert_eq!(py(a, b), Some(Equal), "{a} and {b}");
        }
        for not_a_version in ["latest", "", "1.0-garbage", "abc123", "1.0.0.0.x"] {
            assert_eq!(py(not_a_version, "1.0"), None, "{not_a_version}");
        }
        // The other ecosystems keep semver: a PEP 440 pre-release is not a semver version.
        assert_eq!(compare_in("npm", "2.0.0rc1", "2.0.0"), None);
        assert_eq!(compare_in("npm", "1.2.3-beta", "1.2.3"), Some(Less));
    }

    #[test]
    fn a_local_build_of_an_affected_release_is_affected() {
        // `packaging` puts 2.1.0+cu118 after 2.1.0, which would read it as past the last affected
        // release. It is that release, built locally.
        let record = LAST_AFFECTED
            .replace("paramiko", "torch")
            .replace("4.0.0", "2.1.0");
        let result = audit(
            &sbom_of(vec![component("torch", "2.1.0+cu118", "Python")]),
            &[advisory(&record)],
        );
        assert_eq!(result.findings.len(), 1, "{result:?}");
    }

    /// The shape of the werkzeug records family-hub could not be compared against: one range that
    /// begins at a pre-release.
    const WERKZEUG: &str = r#"{
      "id": "GHSA-q34m-jh98-gwm2",
      "summary": "An issue in werkzeug",
      "affected": [{
        "package": {"ecosystem": "PyPI", "name": "werkzeug"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0rc1"}, {"fixed": "3.0.6"}]}]
      }]
    }"#;

    #[test]
    fn a_python_range_that_begins_at_a_pre_release_is_compared() {
        for (version, affected) in [
            ("3.1.9", false),
            ("1.0.1", false),
            ("2.0.0b9", false),
            ("2.0.0rc1", true),
            ("2.0.0", true),
            ("3.0.6rc1", true),
            ("3.0.6", false),
        ] {
            let result = audit(
                &sbom_of(vec![component("werkzeug", version, "Python")]),
                &[advisory(WERKZEUG)],
            );
            assert_eq!(
                result.findings.len(),
                usize::from(affected),
                "{version}: {result:?}"
            );
            assert!(result.uncomparable.is_empty(), "{version}: {result:?}");
        }
    }

    #[test]
    fn a_range_with_an_event_this_does_not_read_is_not_compared_rather_than_reported() {
        let unknown = LAST_AFFECTED.replace("\"last_affected\"", "\"ends_somewhere\"");
        let result = audit(
            &sbom_of(vec![component("paramiko", "5.0.0", "Python")]),
            &[advisory(&unknown)],
        );
        assert!(result.findings.is_empty(), "{result:?}");
        assert_eq!(result.uncomparable.len(), 1, "{result:?}");
        assert!(
            result.verified.is_empty(),
            "a range not read is not a clean result"
        );
        // The control: the same record with the event this reads decides it.
        let known = audit(
            &sbom_of(vec![component("paramiko", "5.0.0", "Python")]),
            &[advisory(LAST_AFFECTED)],
        );
        assert!(
            known.findings.is_empty() && known.uncomparable.is_empty(),
            "{known:?}"
        );
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
        // A v2 vector, which this cannot score. Showing "medium" without saying so would be believed
        // by anybody sorting the list by seriousness.
        let unrated = advisory(
            r#"{"id":"GHSA-v2","summary":"Something bad.",
                "severity":[{"type":"CVSS_V2","score":"AV:N/AC:L/Au:N/C:P/I:P/A:P"}],
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
    fn an_advisory_with_only_a_v4_vector_is_rated_by_it() {
        // The deep review's improvement 4: 2,340 OSV records carry only a v4 vector, and each was shown
        // as a placeholder medium. Scored with FIRST's own tables (ADR-033).
        let v4 = advisory(
            r#"{"id":"GHSA-v4","summary":"Something bad.",
                "severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
                "affected":[{"package":{"ecosystem":"npm","name":"lodash"},
                "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.17.20"}]}]}]}"#,
        );
        let result = audit(&sbom_of(vec![component("lodash", "4.17.15", "npm")]), &[v4]);
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert!(
            result.findings[0].description.contains("9.3 out of 10"),
            "{}",
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

    const JUPYTER_SERVER: &str = r#"{
      "id": "GHSA-test-jupyter",
      "summary": "An issue in jupyter-server",
      "affected": [{
        "package": {"ecosystem": "PyPI", "name": "jupyter-server"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]
      }]
    }"#;

    #[test]
    fn a_python_name_spelled_another_way_is_the_same_package() {
        // PyPI reads `jupyter_server`, `Jupyter.Server` and `jupyter--server` as `jupyter-server`.
        for spelled in [
            "jupyter-server",
            "jupyter_server",
            "Jupyter.Server",
            "jupyter__server",
            "jupyter-_.server",
        ] {
            let result = audit(
                &sbom_of(vec![component(spelled, "1.0.0", "Python")]),
                &[advisory(JUPYTER_SERVER)],
            );
            assert_eq!(result.findings.len(), 1, "{spelled}: {result:?}");
        }
        // The other way round: an advisory spelled with an underscore finds a hyphenated lockfile.
        let underscored = JUPYTER_SERVER.replace("\"jupyter-server\"}", "\"jupyter_server\"}");
        assert_ne!(underscored, JUPYTER_SERVER, "the advisory was respelled");
        let result = audit(
            &sbom_of(vec![component("jupyter-server", "1.0.0", "Python")]),
            &[advisory(&underscored)],
        );
        assert_eq!(result.findings.len(), 1, "{result:?}");
        // Normalizing joins separators; it does not drop them or merge different names.
        for different in ["jupyterserver", "jupyter-server-x", "jupyter"] {
            let result = audit(
                &sbom_of(vec![component(different, "1.0.0", "Python")]),
                &[advisory(JUPYTER_SERVER)],
            );
            assert!(result.findings.is_empty(), "{different}: {result:?}");
        }
    }

    #[test]
    fn only_python_names_are_normalized() {
        // npm names `lodash_x` and `lodash-x` are two packages; reading them as one invents findings.
        let other = LODASH.replace("\"lodash\"}", "\"lodash-x\"}");
        assert_ne!(other, LODASH, "the advisory was renamed");
        let result = audit(
            &sbom_of(vec![component("lodash_x", "4.17.15", "npm")]),
            &[advisory(&other)],
        );
        assert!(result.findings.is_empty(), "{result:?}");
        let control = audit(
            &sbom_of(vec![component("lodash-x", "4.17.15", "npm")]),
            &[advisory(&other)],
        );
        assert_eq!(control.findings.len(), 1, "the control: {control:?}");
    }

    #[test]
    fn a_clean_comparison_names_its_ecosystems_its_lockfiles_and_what_is_not_in_it() {
        // Deep review, improvement 2. A real folder: npm with a development package and a package
        // another needs, and Pipenv with a development section. The claim says what it covered, and
        // the list really holds what the claim says it does.
        let dir =
            std::env::temp_dir().join(format!("sv-advisories-clean-claim-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            r#"{"name":"app","dependencies":{"express":"4.18.2"},"devDependencies":{"jest":"29.7.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},
                "node_modules/express":{"version":"4.18.2"},
                "node_modules/debug":{"version":"2.6.9"},
                "node_modules/jest":{"version":"29.7.0","dev":true}}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("Pipfile"),
            "[packages]\nflask = \"==3.0.0\"\n\n[dev-packages]\npytest = \"==8.0.0\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("Pipfile.lock"),
            r#"{"_meta":{},"default":{"flask":{"version":"==3.0.0"}},"develop":{"pytest":{"version":"==8.0.0"}}}"#,
        )
        .unwrap();
        let sbom = crate::sbom::build(&dir);
        std::fs::remove_dir_all(&dir).ok();
        let mut names: Vec<&str> = sbom.components.iter().map(|c| c.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            ["debug", "express", "flask", "jest", "pytest"],
            "{sbom:?}"
        );
        let python = LODASH
            .replace(
                "\"npm\", \"name\": \"lodash\"",
                "\"PyPI\", \"name\": \"jinja2\"",
            )
            .replace("GHSA-test-lodash", "GHSA-test-jinja2");
        assert_ne!(python, LODASH, "the second advisory was made");
        let result = audit(&sbom, &[advisory(LODASH), advisory(&python)]);
        assert_eq!(result.verified.len(), 1, "{result:?}");
        assert_eq!(
            result.verified[0].scope,
            "all 5 packages in the bill of materials (3 npm packages and 2 Python packages, read \
             from `package-lock.json` and `Pipfile.lock`), compared against 2 advisories. That is \
             everything each lockfile lists: the packages the app asks for, the packages those need \
             in turn, and the development packages a lockfile keeps beside them. Not in it: anything \
             installed another way, such as the system's own packages, a container image's, or a \
             script loaded from another site"
        );
        // The inventory's own claim names the same.
        let inventory = crate::sbom::completeness_verified(&sbom).expect("the list is complete");
        assert_eq!(
            inventory.scope,
            "an inventory of 5 third-party libraries, each at the version actually installed, from \
             every ecosystem found in the app (3 npm packages and 2 Python packages, read from \
             `package-lock.json` and `Pipfile.lock`), with the packages those need and the \
             development packages each lockfile keeps"
        );
    }

    #[test]
    fn a_package_known_only_from_its_manifest_stops_the_clean_claim() {
        // lodash 4.17.21 is past the fix. Read from a lockfile, that is what is installed and the
        // comparison can be credited. Read from a manifest asking for exactly 4.17.21, it is only
        // what was asked for: nothing says that is what the app runs.
        let locked = audit(
            &sbom_of(vec![component("lodash", "4.17.21", "npm")]),
            &[advisory(LODASH)],
        );
        assert_eq!(locked.verified.len(), 1, "the control: {locked:?}");

        let mut declared = component("left-pad", "1.3.0", "npm");
        declared.source = VersionSource::Declared;
        let result = audit(
            &sbom_of(vec![component("lodash", "4.17.21", "npm"), declared]),
            &[advisory(LODASH)],
        );
        assert!(result.findings.is_empty(), "{result:?}");
        assert!(result.uncomparable.is_empty(), "{result:?}");
        assert!(
            result.verified.is_empty(),
            "no clean claim while a package is only declared: {result:?}"
        );
    }

    /// A record whose two ranges are written out of version order: affected from the start until
    /// 1.0.0, and again from 1.2.0 until 1.2.2, with the second `introduced` before the first `fixed`.
    const OUT_OF_ORDER: &str = r#"{
      "id": "GHSA-test-order",
      "affected": [{
        "package": {"ecosystem": "npm", "name": "left-pad"},
        "ranges": [{"type": "SEMVER", "events": [
          {"introduced": "0"}, {"introduced": "1.2.0"}, {"fixed": "1.0.0"}, {"fixed": "1.2.2"}
        ]}]
      }]
    }"#;

    #[test]
    fn range_events_are_read_in_version_order_not_file_order() {
        for (version, affected) in [
            ("0.9.0", true),
            ("1.0.0", false),
            ("1.1.5", false),
            ("1.2.0", true),
            ("1.2.1", true),
            ("1.2.2", false),
            ("2.0.0", false),
        ] {
            let result = audit(
                &sbom_of(vec![component("left-pad", version, "npm")]),
                &[advisory(OUT_OF_ORDER)],
            );
            assert_eq!(
                result.findings.len(),
                usize::from(affected),
                "{version}: {result:?}"
            );
            assert!(result.uncomparable.is_empty(), "{version}: {result:?}");
        }
    }

    #[test]
    fn two_events_at_one_version_are_not_compared() {
        // Introduced and fixed at 1.0.0: read one way it is affected, read the other it is not.
        let tie = OUT_OF_ORDER.replace(r#"{"introduced": "1.2.0"}"#, r#"{"introduced": "1.0.0"}"#);
        assert_ne!(tie, OUT_OF_ORDER, "the record was changed");
        let result = audit(
            &sbom_of(vec![component("left-pad", "1.0.0", "npm")]),
            &[advisory(&tie)],
        );
        assert!(result.findings.is_empty(), "{result:?}");
        assert_eq!(result.uncomparable.len(), 1, "{result:?}");
        assert!(result.verified.is_empty(), "{result:?}");
    }

    #[test]
    fn a_match_leaves_another_advisorys_could_not_compare_standing() {
        // The first record's range cannot be compared with this version; the second matches. The
        // second is a finding, and the first is still a gap, whichever comes first.
        let unreadable = OUT_OF_ORDER
            .replace("GHSA-test-order", "GHSA-test-unreadable")
            .replace(r#""1.2.2""#, r#""not-a-version""#);
        let matching = LODASH.replace(r#""name": "lodash""#, r#""name": "left-pad""#);
        assert_ne!(matching, LODASH, "the record was renamed");
        for database in [
            vec![advisory(&unreadable), advisory(&matching)],
            vec![advisory(&matching), advisory(&unreadable)],
        ] {
            let result = audit(
                &sbom_of(vec![component("left-pad", "1.2.1", "npm")]),
                &database,
            );
            assert_eq!(result.findings.len(), 1, "{result:?}");
            assert_eq!(result.uncomparable.len(), 1, "{result:?}");
        }
    }

    #[test]
    fn rubygems_versions_compare_the_way_rubygems_does() {
        use std::cmp::Ordering::{Equal, Greater, Less};
        for (a, b, want) in [
            ("1.0.0.rc1", "1.0.0", Some(Less)),
            ("1.0.0.pre", "1.0.0.rc1", Some(Less)),
            ("1.0", "1.0.0", Some(Equal)),
            // Zeros before the letters do not count: RubyGems holds these to be one version.
            ("2.0.0.rc1", "2.0.rc1", Some(Equal)),
            ("1.0.0.a", "1.a", Some(Equal)),
            ("1.15.4", "1.15.10", Some(Less)),
            ("2.0.0.beta2", "2.0.0.beta10", Some(Less)),
            ("1.0.0-1", "1.0.0", Some(Less)),
            ("1.13.10", "1.13.9", Some(Greater)),
            // A platform is not part of the version; still on it, nothing is said.
            ("1.15.4-x86_64-linux", "1.15.4", None),
            ("abc", "1.0", None),
        ] {
            assert_eq!(compare_gem(a, b), want, "{a} against {b}");
        }
    }

    #[test]
    fn a_gem_pre_release_is_held_to_an_advisory_by_rubygems_rules() {
        // `2.0.0.rc1` is not a semver version at all: compared as one, it could not be compared,
        // and a pre-release of the fixed release would go unreported.
        let fixed_in = r#"{
          "id": "GHSA-test-rails",
          "affected": [{
            "package": {"ecosystem": "RubyGems", "name": "rails"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]
          }]
        }"#;
        for (version, affected) in [
            ("2.0.0.rc1", true),
            ("2.0.0.beta3", true),
            ("1.9", true),
            ("2.0.0", false),
            ("2.0", false),
            ("2.0.1", false),
        ] {
            let result = audit(
                &sbom_of(vec![component("rails", version, "Ruby")]),
                &[advisory(fixed_in)],
            );
            assert!(result.uncomparable.is_empty(), "{version}: {result:?}");
            assert_eq!(
                result.findings.len(),
                usize::from(affected),
                "{version}: {result:?}"
            );
        }
    }

    #[test]
    fn a_gem_built_for_a_platform_is_compared_by_its_version() {
        let dir = std::env::temp_dir().join(format!("sv-advisories-gem-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Gemfile"), "gem 'nokogiri'\n").unwrap();
        let fixed_in = r#"{
          "id": "GHSA-test-nokogiri",
          "affected": [{
            "package": {"ecosystem": "RubyGems", "name": "nokogiri"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.15.4"}]}]
          }]
        }"#;
        let mut findings = Vec::new();
        for version in ["1.15.4-x86_64-linux", "1.15.3-x86_64-linux", "1.15.4"] {
            std::fs::write(
                dir.join("Gemfile.lock"),
                format!(
                    "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri ({version})\n\n\
                     PLATFORMS\n  x86_64-linux\n\nDEPENDENCIES\n  nokogiri\n"
                ),
            )
            .unwrap();
            let sbom = crate::sbom::build(&dir);
            assert_eq!(sbom.components.len(), 1, "{version}: {sbom:?}");
            assert_eq!(sbom.components[0].ecosystem, "Ruby", "{version}: {sbom:?}");
            let result = audit(&sbom, &[advisory(fixed_in)]);
            assert!(result.uncomparable.is_empty(), "{version}: {result:?}");
            findings.push(result.findings.len());
        }
        std::fs::remove_dir_all(&dir).ok();
        // The fixed release on a platform is fixed; the one before it is not; the plain fixed
        // release is the control.
        assert_eq!(findings, vec![0, 1, 0]);
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
    fn a_second_lockfile_nothing_read_stops_the_clean_claim() {
        // lodash 4.17.21 is past the fix, so the comparison finds nothing. With only
        // `package-lock.json` there, that is a clean claim; with a `yarn.lock` beside it that was
        // never read, nothing says the app is installed from the file that was compared.
        let mut sbom = sbom_of(vec![component("lodash", "4.17.21", "npm")]);
        let one = audit(&sbom, &[advisory(LODASH)]);
        assert_eq!(one.verified.len(), 1, "the control: {one:?}");

        sbom.passed_over.push(crate::sbom::PassedOver {
            project: "npm".into(),
            read: "package-lock.json".into(),
            not_read: vec!["yarn.lock".into()],
        });
        let two = audit(&sbom, &[advisory(LODASH)]);
        assert!(two.findings.is_empty(), "{two:?}");
        assert!(
            two.verified.is_empty(),
            "no clean claim with a lockfile unread: {two:?}"
        );
    }

    #[test]
    fn a_manifest_that_disagrees_with_its_lockfile_stops_the_clean_claim() {
        // The comparison read `package-lock.json` and found nothing. When `package.json` asks for
        // another lodash, nothing says the app is installed from the file that was compared; when
        // all that is known is that one entry could not be compared, the list is still the lock's.
        let mut sbom = sbom_of(vec![component("lodash", "4.17.21", "npm")]);
        let disagreement = |differs: Vec<crate::manifest_lock::Differs>,
                            not_compared: Vec<String>| {
            crate::sbom::Disagreement {
                project: "npm".into(),
                manifest: "package.json".into(),
                lockfile: "package-lock.json".into(),
                comparison: crate::manifest_lock::Comparison {
                    differs,
                    not_compared,
                },
            }
        };
        sbom.disagreements
            .push(disagreement(Vec::new(), vec!["lodash latest".into()]));
        let unknown = audit(&sbom, &[advisory(LODASH)]);
        assert_eq!(unknown.verified.len(), 1, "the control: {unknown:?}");

        sbom.disagreements.push(disagreement(
            vec![crate::manifest_lock::Differs {
                asked: "lodash 4.17.15".into(),
                locked: vec!["4.17.21".into()],
            }],
            Vec::new(),
        ));
        let differing = audit(&sbom, &[advisory(LODASH)]);
        assert!(differing.findings.is_empty(), "{differing:?}");
        assert!(
            differing.verified.is_empty(),
            "no clean claim while the manifest asks for something else: {differing:?}"
        );
    }

    #[test]
    fn an_ecosystem_named_only_beside_another_is_not_covered() {
        // As in OSV's crates.io export: a record about a crate that is also published to PyPI names
        // both. Loaded alone, it says nothing about the rest of PyPI.
        let both = || {
            advisory(
                r#"{"id":"GHSA-both","affected":[
                {"package":{"ecosystem":"crates.io","name":"pyo3"},
                 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0.1"}]}]},
                {"package":{"ecosystem":"PyPI","name":"pyo3-pack"},
                 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0.1"}]}]}]}"#,
            )
        };
        let sbom = sbom_of(vec![
            component("lodash", "4.17.21", "npm"),
            component("flask", "3.0.0", "Python"),
        ]);
        let result = audit(&sbom, &[advisory(LODASH), both()]);
        assert!(result.uncovered.contains("Python"), "{result:?}");
        assert!(!result.uncovered.contains("npm"), "{result:?}");
        assert!(
            result.verified.is_empty(),
            "no clean claim with Python unchecked"
        );

        // The control: a record about PyPI alone, as the PyPI export holds, does cover it.
        let pypi = advisory(
            r#"{"id":"PYSEC-only","affected":[
                {"package":{"ecosystem":"PyPI","name":"django"},
                 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0"}]}]}]}"#,
        );
        let result = audit(&sbom, &[advisory(LODASH), both(), pypi]);
        assert!(result.uncovered.is_empty(), "{result:?}");
    }

    /// A record about lodash below 4.17.20, with its own id, aliases, and CVSS vector.
    fn lodash_record(id: &str, aliases: &[&str], vector: Option<&str>) -> Advisory {
        let severity = vector
            .map(|v| format!(r#","severity":[{{"type":"CVSS_V3","score":"{v}"}}]"#))
            .unwrap_or_default();
        let aliases: Vec<String> = aliases.iter().map(|a| format!("\"{a}\"")).collect();
        advisory(&format!(
            r#"{{"id":"{id}","aliases":[{}]{severity},"affected":[{{
                "package":{{"ecosystem":"npm","name":"lodash"}},
                "ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"4.17.20"}}]}}]}}]}}"#,
            aliases.join(",")
        ))
    }

    const HIGH_VECTOR: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";
    const LOW_VECTOR: &str = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N";

    #[test]
    fn one_vulnerability_under_two_names_is_one_finding_rated_the_more_serious() {
        let sbom = sbom_of(vec![component("lodash", "4.17.15", "npm")]);
        let result = audit(
            &sbom,
            &[
                // The more serious record sorts last by id, so choosing it is not an accident of order.
                lodash_record("GHSA-1", &["CVE-1", "PYSEC-1"], Some(LOW_VECTOR)),
                lodash_record("PYSEC-1", &["CVE-1", "GHSA-1"], Some(HIGH_VECTOR)),
            ],
        );
        assert_eq!(result.findings.len(), 1, "{result:?}");
        assert_eq!(result.findings[0].rule_id, "advisory.PYSEC-1");
        assert_eq!(result.findings[0].severity, Severity::High);
        assert!(result.findings[0].title.contains("GHSA-1"));
        assert_eq!(result.due.len(), 1);

        // The control: two vulnerabilities that share no name stay two.
        let result = audit(
            &sbom,
            &[
                lodash_record("GHSA-1", &["CVE-1"], Some(HIGH_VECTOR)),
                lodash_record("GHSA-2", &["CVE-2"], Some(HIGH_VECTOR)),
            ],
        );
        assert_eq!(result.findings.len(), 2, "{result:?}");
    }

    #[test]
    fn names_join_through_a_third_record_and_one_sided_aliases_still_join() {
        let sbom = sbom_of(vec![component("lodash", "4.17.15", "npm")]);
        // A names B, C names B; A and C never name each other, and all three are one flaw.
        let result = audit(
            &sbom,
            &[
                lodash_record("A-1", &["B-1"], None),
                lodash_record("C-1", &["B-1"], None),
                lodash_record("B-1", &[], Some(HIGH_VECTOR)),
            ],
        );
        assert_eq!(result.findings.len(), 1, "{result:?}");
        // The one record with a rating `sv` can read is the one kept.
        assert_eq!(result.findings[0].rule_id, "advisory.B-1");
        let title = &result.findings[0].title;
        assert!(
            title.contains("B-1") && title.contains("A-1") && title.contains("C-1"),
            "every name it goes by is in the finding: {title}"
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
            passed_over: Vec::new(),
            disagreements: Vec::new(),
            lockfiles: Vec::new(),
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
        assert_eq!(day("2020-07-15T19:15:00.123456+02:00").show(), "2020-07-15");
        for bad in [
            // Text after the date that is not a time of day (the deep review's improvement 6).
            "2026-09-27 or so",
            "2026-09-27x",
            "2026-09-27T",
            "2026-09-27T19:15",
            "2026-09-27T19:15:00",
            "2026-09-27T19:15:00Zjunk",
            "2026-09-27T19:15:00.Z",
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
