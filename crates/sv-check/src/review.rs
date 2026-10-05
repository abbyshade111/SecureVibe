//! A person's record that a finding is a false alarm, or a risk they accept for now.
//!
//! The owner's decisions, 27 September 2026 (BACKLOG, "False alarms, part 2"). Two verdicts:
//! *false alarm*, the code is fine; *accepted risk*, a real problem lived with for now. Only a
//! person's word counts: the AI coding tool rewrites code until a warning stops, and a switch that
//! makes a warning stop is the easiest rewrite of all, so an entry the tool wrote is shown as its
//! proposal and the finding still counts. Since 4 October 2026 (deep review R1) that means an entry
//! recorded through `sv review`, which seals it (`crate::seal`): `by = "owner"` written into the file
//! by anyone else is a proposal too. A false alarm lapses when the flagged line changes, because
//! the fingerprint it names stops matching; an accepted risk lapses after 90 days; a finding that has
//! no line of code (a running-app probe, a settings check) has nothing to watch, so a false alarm
//! about one lapses after 90 days as well. An entry that does not count is listed with its reason,
//! never dropped quietly.
//!
//! A false alarm leaves the list of things to fix. An accepted risk stays on it, labeled. Neither
//! credits anything: the report sends a requirement whose finding was set aside back to what else is
//! known about it, and never to *checked*.

use crate::advisories::Day;
use crate::finding::Finding;
use crate::seal::{Checker, Sealed};
use std::path::Path;
use sv_manifest::FindingReview;

/// Who an entry says made the decision, as a sentence reads it: "the owner" for `owner`, otherwise
/// the name as written. Only what securevibe.toml says: `sv` cannot tell who wrote the entry
/// (deep review R1), so every report puts it as "securevibe.toml says".
pub fn who_said(by: &str) -> String {
    if by.trim().eq_ignore_ascii_case("owner") {
        "the owner".to_owned()
    } else {
        by.trim().to_owned()
    }
}

/// How long a verdict holds when nothing else ends it.
pub const CURRENT_FOR_DAYS: u32 = 90;
/// The shortest reason that can say what was looked at and what it showed.
pub const LEAST_WHY_CHARS: usize = 40;
/// The shortest for a key or password found in the code: saying why it is not a real one takes more.
pub const LEAST_WHY_CHARS_SECRET: usize = 80;

pub const FALSE_ALARM: &str = "false-alarm";
pub const ACCEPTED_RISK: &str = "accepted-risk";

/// A finding a person set aside, with what they decided.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SetAside {
    pub finding: Finding,
    pub verdict: String,
    pub why: String,
    pub by: String,
    pub on: String,
    /// Where its seal was checked: on this computer, or nowhere, this computer having no key.
    pub sealed: Sealed,
}

/// What the entries came to.
#[derive(Debug, Default)]
pub struct Outcome {
    /// Every finding that still counts, accepted risks among them.
    pub findings: Vec<Finding>,
    /// Every entry that counts: false alarms, which left `findings`, and accepted risks, which did not.
    pub set_aside: Vec<SetAside>,
    /// Entries that do not count, each with its reason, for the report to list.
    pub not_counted: Vec<String>,
}

/// What a fingerprint made since 5 October 2026 starts with (deep review A2). A fingerprint of
/// sixteen hex characters and nothing else is the earlier form, which named a line by its text
/// alone; entries written with it still count where it names one finding (`apply`).
pub const FINGERPRINT_V2: &str = "v2-";

/// The most lines above a flagged line that are kept for one name it uses: the assignment that
/// sets it, and the ones that add to it after.
const MOST_ASSIGNMENTS: usize = 8;

/// The name a review gives a finding.
///
/// For a finding on a line of code: its rule, its file, the text of that line with its spaces
/// trimmed, the lines above it that set a name the line uses (for each name, the nearest line that
/// assigns it, and any that add to it after), and which of the lines with all of that the same it
/// is, counted from the top of the file. So moving the line keeps the name; changing it, or
/// changing a line that sets a value it uses, does not; and two identical lines each have their
/// own (deep review A2). A finding with no line of code is named by its title instead, as before.
/// Only a hash of these is kept, sixteen hex characters of SHA-256 after `v2-`, so the line a key
/// was found on is never copied anywhere.
pub fn fingerprint(app_dir: &Path, f: &Finding) -> String {
    Texts::new(app_dir).fingerprint(f, &f.rule_id)
}

/// The earlier fingerprint of what a finding names, from its rule, its file, and its trimmed line
/// (or its title, for a finding with no line of code): sixteen hex characters. Still the
/// fingerprint of a finding with no line of code; for a line of code, only read back from entries
/// written before 5 October 2026.
pub fn named(rule: &str, file: &str, what: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("{rule}\n{file}\n{what}").as_bytes());
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// Whether a fingerprint is in the form used before 5 October 2026: sixteen hex characters.
pub fn is_earlier_form(fingerprint: &str) -> bool {
    fingerprint.len() == 16 && fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The fingerprint of line `index` (from 0) of `lines`, under `rule` in `file`.
fn line_fingerprint(rule: &str, file: &str, lines: &[String], index: usize) -> String {
    use sha2::{Digest, Sha256};
    let what = lines[index].trim();
    let reaching = reaching(lines, index);
    let occurrence = (0..index)
        .filter(|&j| lines[j].trim() == what && reaching_eq(lines, j, &reaching))
        .count();
    let digest = Sha256::digest(
        format!(
            "v2\n{rule}\n{file}\n{what}\n{}\n{}\n{occurrence}",
            reaching.len(),
            reaching.join("\n")
        )
        .as_bytes(),
    );
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("{FINGERPRINT_V2}{hex}")
}

fn reaching_eq(lines: &[String], index: usize, reaching_of_other: &[String]) -> bool {
    reaching(lines, index) == reaching_of_other
}

/// The lines above line `index` that set a name it uses, each as `name: trimmed line`: for each
/// name, in the order the line first uses it, the nearest line above that assigns it with `=`,
/// `:=`, or a declaration, and any line between that adds to it (`+=`, `.=`, `||=`, ...).
///
/// Read as text, the same in every language: a line that assigns the name inside a string, or
/// passes it as a keyword argument, counts too. That only ever adds a line to watch, so a false
/// alarm comes back for looking at again more often, never less.
fn reaching(lines: &[String], index: usize) -> Vec<String> {
    let line = &lines[index];
    let mut names: Vec<&str> = Vec::new();
    let mut start = None;
    for (i, c) in line
        .char_indices()
        .chain(std::iter::once((line.len(), ' ')))
    {
        let word = c.is_ascii_alphanumeric() || c == '_' || c == '$';
        match (start, word) {
            (None, true) if !c.is_ascii_digit() => start = Some(i),
            (Some(s), false) => {
                let name = &line[s..i];
                if !names.contains(&name) {
                    names.push(name);
                }
                start = None;
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    for name in names {
        let Some(re) = assignment(name) else {
            continue;
        };
        let mut kept = 0;
        for above in lines[..index].iter().rev() {
            if !above.contains(name) {
                continue;
            }
            let Some(m) = re.captures(above) else {
                continue;
            };
            out.push(format!("{name}: {}", above.trim()));
            kept += 1;
            let adds_to = m.get(1).is_some();
            if !adds_to || kept == MOST_ASSIGNMENTS {
                break;
            }
        }
    }
    out
}

/// A pattern for a line that assigns `name`: the name as a whole word, an optional type after a
/// colon, and `=` (not `==`, `=>`, or `=~`), with the operator of an assignment that adds to it in
/// the first group.
fn assignment(name: &str) -> Option<regex::Regex> {
    regex::Regex::new(&format!(
        r"(?:^|[^A-Za-z0-9_$]){}\s*(?::[^=;(){{}}]*?)?\s*(\+|-|\*\*|\*|//|/|%|\.|\|\||&&|\?\?|\||&|\^|<<|>>)?:?=(?:[^=>~]|$)",
        regex::escape(name)
    ))
    .ok()
}

/// The app's files as a review reads them, each read once.
struct Texts<'a> {
    app_dir: &'a Path,
    read: std::collections::HashMap<String, Option<Vec<String>>>,
}

impl<'a> Texts<'a> {
    fn new(app_dir: &'a Path) -> Self {
        Texts {
            app_dir,
            read: std::collections::HashMap::new(),
        }
    }

    /// The lines of `file`, or `None` when it is outside the app folder or cannot be read.
    fn lines(&mut self, file: &str) -> Option<&[String]> {
        let app_dir = self.app_dir;
        self.read
            .entry(file.to_owned())
            .or_insert_with(|| {
                let inside = Path::new(file)
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_)));
                if !inside {
                    return None;
                }
                std::fs::read_to_string(app_dir.join(file))
                    .ok()
                    .map(|t| t.lines().map(str::to_owned).collect())
            })
            .as_deref()
    }

    /// `f`'s fingerprint as if `rule` had reported it.
    fn fingerprint(&mut self, f: &Finding, rule: &str) -> String {
        if !crate::finding::reads_code(f) {
            return named(rule, &f.location.file, &f.title);
        }
        let n = f.location.line;
        match self.lines(&f.location.file) {
            Some(lines) if n >= 1 && n <= lines.len() => {
                line_fingerprint(rule, &f.location.file, lines, n - 1)
            }
            _ => named(rule, &f.location.file, &format!("line {n}")),
        }
    }

    /// `f`'s fingerprint in the form used before 5 October 2026, as if `rule` had reported it.
    fn earlier_fingerprint(&mut self, f: &Finding, rule: &str) -> String {
        if !crate::finding::reads_code(f) {
            return named(rule, &f.location.file, &f.title);
        }
        let n = f.location.line;
        let what = self
            .lines(&f.location.file)
            .and_then(|lines| lines.get(n.saturating_sub(1)))
            .map(|l| l.trim().to_owned())
            .unwrap_or_else(|| format!("line {n}"));
        named(rule, &f.location.file, &what)
    }
}

/// The lines of `file` an entry's fingerprint names, as their numbers and their text with spaces
/// trimmed, for `sv review` to show the person what they are deciding about. At most one, except
/// for a fingerprint in the earlier form on lines that read the same, which names them all (and so
/// counts for none of them). Empty when no line matches (the line changed, or the finding is not
/// about a line), and for a file outside the app folder, whose lines are never read.
pub fn lines_with_fingerprint(
    app_dir: &Path,
    rule: &str,
    file: &str,
    fingerprint: &str,
) -> Vec<(usize, String)> {
    let mut texts = Texts::new(app_dir);
    let Some(lines) = texts.lines(file) else {
        return Vec::new();
    };
    let earlier = is_earlier_form(fingerprint);
    if !earlier && !fingerprint.starts_with(FINGERPRINT_V2) {
        return Vec::new();
    }
    let mut found = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        let matches = if earlier {
            named(rule, file, l.trim()) == fingerprint
        } else {
            line_fingerprint(rule, file, lines, i) == fingerprint
        };
        if matches {
            found.push((i + 1, l.trim().to_owned()));
            if !earlier {
                break;
            }
        }
    }
    found
}

/// The fingerprint, in today's form, of the one line an entry's earlier-form fingerprint names, for
/// `sv review` to write in its place when a person records the entry. `None` when the fingerprint
/// is already in today's form, or names no line or more than one.
pub fn todays_form(app_dir: &Path, rule: &str, file: &str, fingerprint: &str) -> Option<String> {
    if !is_earlier_form(fingerprint) {
        return None;
    }
    let found = lines_with_fingerprint(app_dir, rule, file, fingerprint);
    let [(n, _)] = found.as_slice() else {
        return None;
    };
    let mut texts = Texts::new(app_dir);
    let lines = texts.lines(file)?;
    Some(line_fingerprint(rule, file, lines, n - 1))
}

/// Fills in every finding's fingerprint.
pub fn fill_fingerprints(app_dir: &Path, findings: &mut [Finding]) {
    let mut texts = Texts::new(app_dir);
    for f in findings {
        let fingerprint = texts.fingerprint(f, &f.rule_id);
        let earlier = texts.earlier_fingerprint(f, &f.rule_id);
        f.earlier_fingerprints = if earlier == fingerprint {
            Vec::new()
        } else {
            vec![earlier]
        };
        f.fingerprint = fingerprint;
    }
}

/// Whether this run looked for what an entry's rule reports, in the entry's file: what tells an
/// entry whose finding is gone from one whose finding nobody looked for this time (deep review R3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Looked {
    /// The check that reports the rule ran over the file, so a finding missing from it is gone.
    Ran,
    /// The rule is one this version has, and it did not look at the file this time, for this
    /// reason: it needs `--run` or `--tools`, the file's language was not read, the file was not
    /// opened, and so on.
    NotThisTime(String),
    /// This version of `sv` has no such rule, so nothing in it could report one.
    Unknown,
}

/// Applies the entries to the findings, which must already have their fingerprints. `looked` says,
/// for an entry that matches no finding, whether its rule looked at its file this time.
///
/// An entry may name a rule that was merged into a finding rather than the one kept (see
/// `merge_same_place`): the rule kept on a line can change when a tool is added or `sv`'s choice
/// of words changes, and a person's review of that line should not be lost with it. Such an entry
/// counts when its fingerprint is the one the finding would have had under the rule it names
/// (its line read from `app_dir`).
///
/// One entry matches one finding. An entry with a fingerprint in the earlier form, which named a
/// line by its text alone, matches the finding it always did when only one finding is on a line
/// with that text; when several are, it matches none of them, and says so, rather than one picked
/// for it or all of them.
pub fn apply(
    app_dir: &Path,
    entries: &[FindingReview],
    findings: Vec<Finding>,
    today: Day,
    seals: &Checker,
    looked: &dyn Fn(&str, &str) -> Looked,
) -> Outcome {
    let mut texts = Texts::new(app_dir);
    // The findings a false alarm has taken off the list so far.
    let mut taken = vec![false; findings.len()];
    let mut out = Outcome::default();
    for entry in entries {
        let named = format!("`{}` in {} ({})", entry.rule, entry.file, entry.fingerprint);
        let earlier = is_earlier_form(&entry.fingerprint);
        let candidates: Vec<usize> = findings
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                if f.location.file != entry.file {
                    return false;
                }
                let kept = f.rule_id == entry.rule;
                let merged = f.also_reported_by.contains(&entry.rule);
                if !kept && !merged {
                    return false;
                }
                let own = if earlier {
                    texts.earlier_fingerprint(f, &f.rule_id)
                } else {
                    f.fingerprint.clone()
                };
                own == entry.fingerprint
                    || (merged
                        && (if earlier {
                            texts.earlier_fingerprint(f, &entry.rule)
                        } else {
                            texts.fingerprint(f, &entry.rule)
                        }) == entry.fingerprint)
            })
            .map(|(i, _)| i)
            .collect();
        let places: std::collections::BTreeSet<usize> = candidates
            .iter()
            .map(|&i| findings[i].location.line)
            .collect();
        if places.len() > 1 {
            let lines: Vec<String> = places.iter().map(usize::to_string).collect();
            let lines = and_list(&lines);
            out.not_counted.push(format!(
                "{named}: {}, so which one it means cannot be told, and it applies to none of them. \
                 Write the entry again with the fingerprint the report now prints beside the one \
                 you mean, record it through `sv review`, and remove this one.",
                if earlier {
                    format!(
                        "its fingerprint is in the form `sv` used before 5 October 2026, which \
                         named a line by its text alone, and {} findings are on lines that read \
                         the same (lines {lines})",
                        places.len()
                    )
                } else {
                    format!("{} findings, on lines {lines}, match it", places.len())
                }
            ));
            continue;
        }
        let Some(&i) = candidates.iter().find(|&&i| !taken[i]) else {
            out.not_counted.push(if candidates.is_empty() {
                unmatched(&named, entry, looked(&entry.rule, &entry.file))
            } else {
                format!(
                    "{named}: an entry above it already set this finding aside as a false alarm, \
                     so this one is not applied."
                )
            });
            continue;
        };
        match judge(entry, &findings[i], today, seals) {
            Err(why) => out.not_counted.push(format!("{named}: {why}")),
            Ok(sealed) => {
                if entry.verdict == FALSE_ALARM {
                    taken[i] = true;
                }
                out.set_aside.push(SetAside {
                    finding: findings[i].clone(),
                    verdict: entry.verdict.clone(),
                    why: entry.why.trim().to_owned(),
                    by: entry.by.clone().unwrap_or_default(),
                    on: entry.on.clone().unwrap_or_default(),
                    sealed,
                });
            }
        }
    }
    out.findings = findings
        .into_iter()
        .zip(taken)
        .filter(|(_, taken)| !taken)
        .map(|(f, _)| f)
        .collect();
    out
}

/// What the report says of an entry that matches no finding: one of three things, because they
/// ask different things of the owner, and only the last is a sign the finding may be fixed.
fn unmatched(named: &str, entry: &FindingReview, looked: Looked) -> String {
    match looked {
        Looked::Ran => format!(
            "{named}: no finding matches it any more, and the check that reports it looked at this \
             file. The flagged line changed, or a line above it that sets a value it uses, so the \
             finding has a new fingerprint and needs looking at again; or the finding is gone and \
             the entry can be removed."
        ),
        Looked::NotThisTime(why) => format!(
            "{named}: not looked for this time ({why}), so whether the finding is still there is \
             not known. This is not a sign the finding was fixed: keep the entry, and it applies \
             again on a run that looks for it."
        ),
        Looked::Unknown => format!(
            "{named}: this version of `sv` ({}) has no rule `{}`, so nothing in it could find this. \
             The entry may come from another version of `sv`, or the rule's name may be misspelled. \
             This is not a sign the finding was fixed: the entry applies to nothing until a version \
             with that rule reads it.",
            env!("CARGO_PKG_VERSION"),
            entry.rule
        ),
    }
}

/// "3", "3 and 9", "3, 9, and 12".
fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [a, b] => format!("{a} and {b}"),
        [rest @ .., last] => format!("{}, and {last}", rest.join(", ")),
    }
}

/// Whether an entry counts, and why not when it does not.
fn judge(
    entry: &FindingReview,
    finding: &Finding,
    today: Day,
    seals: &Checker,
) -> Result<Sealed, String> {
    let secret = finding.rule_id.starts_with("secrets.")
        || finding
            .also_reported_by
            .iter()
            .any(|r| r.starts_with("secrets."));
    match entry.verdict.as_str() {
        FALSE_ALARM => {}
        ACCEPTED_RISK if secret => {
            return Err(
                "a key or password found in the code cannot be an accepted risk: a real one is \
                 replaced and taken out of the code, and one that is not real is a false alarm, \
                 with a reason that says why."
                    .to_owned(),
            );
        }
        ACCEPTED_RISK => {}
        other => {
            return Err(format!(
                "`verdict = \"{other}\"` is not one of the two: `false-alarm` or `accepted-risk`."
            ));
        }
    }
    let by = entry.by.as_deref().map(str::trim).unwrap_or("");
    if by.is_empty()
        || by.eq_ignore_ascii_case(crate::design::AI_TOOL)
        || by.eq_ignore_ascii_case("AI coding tool")
    {
        return Err(format!(
            "the AI coding tool's proposal, not a person's decision, so the finding still counts. \
             It says: \"{}\". {AGREE}",
            entry.why.trim()
        ));
    }
    let fields = crate::seal::finding_review_fields(entry);
    let sealed = seals
        .check(entry.seal.as_deref(), &crate::seal::as_strs(&fields))
        .map_err(|why| format!("{why}. It says: \"{}\". {AGREE}", entry.why.trim()))?;
    let Some(on) = entry.on.as_deref().and_then(Day::parse) else {
        return Err("it has no date in `on` (YYYY-MM-DD), so how old it is cannot be told.".into());
    };
    if on > today {
        return Err(format!(
            "it is dated {}, which has not come yet.",
            entry.on.as_deref().unwrap_or("")
        ));
    }
    let least = if secret {
        LEAST_WHY_CHARS_SECRET
    } else {
        LEAST_WHY_CHARS
    };
    if entry.why.trim().chars().count() < least {
        return Err(if secret {
            format!(
                "for a key or password, the reason has to say why it is not a real one (a test \
                 value, a published example, one already revoked), in at least {least} characters."
            )
        } else {
            format!(
                "the reason is shorter than {least} characters; say what was looked at and what it \
                 showed."
            )
        });
    }
    let watches_a_line = crate::finding::reads_code(finding);
    if (entry.verdict == ACCEPTED_RISK || !watches_a_line) && on.plus(CURRENT_FOR_DAYS) < today {
        return Err(format!(
            "it was decided on {} and has lapsed after {CURRENT_FOR_DAYS} days{}; look again and \
             date it anew if it still holds.",
            on.show(),
            if watches_a_line {
                ""
            } else {
                ", since this finding has no line of code whose change would end it"
            }
        ));
    }
    Ok(sealed)
}

/// What the owner does to make a proposal count.
pub const AGREE: &str = "If you agree after reading the code, run `sv review` in your own terminal \
    to record it as your decision.";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Confidence, Location, Severity};

    fn finding(rule: &str, file: &str, line: usize) -> Finding {
        Finding {
            rule_id: rule.into(),
            title: format!("found by {rule}"),
            severity: Severity::High,
            confidence: Confidence::Medium,
            location: Location {
                file: file.into(),
                line,
            },
            secret: None,
            requirement_ids: Vec::new(),
            cwe: Vec::new(),
            description: String::new(),
            impact: String::new(),
            fix: String::new(),
            also_reported_by: Vec::new(),
            fingerprint: format!("fp-{rule}"),
            earlier_fingerprints: Vec::new(),
            marked_test_code: false,
        }
    }

    const WHY: &str = "The next= value is checked against our own paths on the line above.";
    const SECRET_WHY: &str =
        "This is the AWS documentation's published example key, used only by the test suite here.";

    fn entry(rule: &str, verdict: &str, by: Option<&str>, on: &str, why: &str) -> FindingReview {
        FindingReview {
            rule: rule.into(),
            file: "app.py".into(),
            fingerprint: format!("fp-{rule}"),
            verdict: verdict.into(),
            why: why.into(),
            by: by.map(str::to_owned),
            on: Some(on.into()),
            seal: Some(RESEAL.into()),
        }
    }

    /// Stands for the seal `sv review` would write over the entry as it is when applied, so a test
    /// can change a field after making the entry.
    const RESEAL: &str = "reseal";

    /// This computer's key in these tests, from the system's randomness.
    fn key() -> crate::seal::Key {
        static KEY: std::sync::OnceLock<crate::seal::Key> = std::sync::OnceLock::new();
        KEY.get_or_init(|| crate::seal::Key::random().unwrap())
            .clone()
    }

    /// `apply` as on the computer whose key sealed the entries.
    fn apply(entries: &[FindingReview], findings: Vec<Finding>, today: Day) -> Outcome {
        apply_in(Path::new("/no/app/folder"), entries, findings, today)
    }

    /// `apply`, with the app's lines read from `app_dir`.
    fn apply_in(
        app_dir: &Path,
        entries: &[FindingReview],
        findings: Vec<Finding>,
        today: Day,
    ) -> Outcome {
        let sealed: Vec<FindingReview> = entries
            .iter()
            .map(|e| {
                let mut e = e.clone();
                if e.seal.as_deref() == Some(RESEAL) {
                    let fields = crate::seal::finding_review_fields(&e);
                    e.seal = Some(key().seal(&crate::seal::as_strs(&fields)));
                }
                e
            })
            .collect();
        super::apply(
            app_dir,
            &sealed,
            findings,
            today,
            &Checker::Key(key()),
            &|_, _| Looked::Ran,
        )
    }

    fn today() -> Day {
        Day::parse("2026-09-27").unwrap()
    }

    #[test]
    fn a_false_alarm_leaves_the_list_and_an_accepted_risk_stays_on_it() {
        let out = apply(
            &[
                entry("ast.a", FALSE_ALARM, Some("owner"), "2026-09-27", WHY),
                entry("ast.b", ACCEPTED_RISK, Some("Sam Lee"), "2026-09-20", WHY),
            ],
            vec![finding("ast.a", "app.py", 5), finding("ast.b", "app.py", 9)],
            today(),
        );
        assert!(out.not_counted.is_empty(), "{:?}", out.not_counted);
        let still: Vec<&str> = out.findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(still, vec!["ast.b"]);
        assert_eq!(out.set_aside.len(), 2);
        assert_eq!(out.set_aside[1].by, "Sam Lee");
    }

    #[test]
    fn a_rule_merged_into_another_finding_can_still_be_named() {
        let mut f = finding("semgrep.sqli", "app.py", 5);
        f.also_reported_by = vec!["ast.sql".into()];
        f.fingerprint = "fp-ast.sql".into();
        let out = apply(
            &[entry(
                "ast.sql",
                FALSE_ALARM,
                Some("owner"),
                "2026-09-27",
                WHY,
            )],
            vec![f],
            today(),
        );
        assert!(out.findings.is_empty(), "{:?}", out.not_counted);
    }

    #[test]
    fn a_review_of_the_rule_that_used_to_be_kept_still_counts_when_another_is_kept() {
        // Bandit's B105 was kept on the family-hub line until 4 October 2026, and `sv`'s own rule
        // is now; a review written against Bandit's fingerprint must still find its line.
        let dir = std::env::temp_dir().join(format!("sv-review-merged-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("app.py"),
            "WRONG_PASSWORD = \"Your current password isn't right.\"\nOTHER = 1\n",
        )
        .unwrap();
        let kept = || {
            let mut f = finding("secrets.credential-assignment", "app.py", 1);
            f.also_reported_by = vec!["bandit.B105".into()];
            f.fingerprint = fingerprint(&dir, &f);
            f
        };
        let reviewed = |rule: &str, line: &str| {
            let mut e = entry(rule, FALSE_ALARM, Some("owner"), "2026-09-27", SECRET_WHY);
            e.fingerprint = named(rule, "app.py", line);
            e
        };
        let line = "WRONG_PASSWORD = \"Your current password isn't right.\"";
        // The setup: the kept finding's own fingerprint is not the one the entry holds.
        assert_ne!(kept().fingerprint, named("bandit.B105", "app.py", line));
        let out = apply_in(
            &dir,
            &[reviewed("bandit.B105", line)],
            vec![kept()],
            today(),
        );
        assert!(out.findings.is_empty(), "{:?}", out.not_counted);
        // The controls: another line under the same rule, and a rule not merged into this finding.
        for e in [
            reviewed("bandit.B105", "OTHER = 1"),
            reviewed("semgrep.hardcoded-password", line),
        ] {
            let out = apply_in(&dir, &[e], vec![kept()], today());
            assert_eq!(
                out.findings.len(),
                1,
                "an entry for another finding counted"
            );
            assert_eq!(out.not_counted.len(), 1);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_entry_counts_only_as_sv_review_sealed_it() {
        let finding = || vec![finding("ast.a", "app.py", 5)];
        let sealed =
            |e: &FindingReview| {
                let mut e = e.clone();
                e.seal = Some(key().seal(&crate::seal::as_strs(
                    &crate::seal::finding_review_fields(&e),
                )));
                e
            };
        let good = sealed(&entry(
            "ast.a",
            FALSE_ALARM,
            Some("owner"),
            "2026-09-27",
            WHY,
        ));
        let here = super::apply(
            Path::new("/no/app/folder"),
            std::slice::from_ref(&good),
            finding(),
            today(),
            &Checker::Key(key()),
            &|_, _| Looked::Ran,
        );
        assert!(here.findings.is_empty(), "{:?}", here.not_counted);
        assert_eq!(here.set_aside[0].sealed, Sealed::Here);

        // `by = "owner"` with no seal, as the AI coding tool would write it: a proposal.
        let unsealed = FindingReview {
            seal: None,
            ..good.clone()
        };
        // The reason changed after it was sealed.
        let changed = FindingReview {
            why: format!("{WHY} Also fine."),
            ..good.clone()
        };
        // Sealed with another computer's key.
        let other = crate::seal::Key::random().unwrap();
        let elsewhere = sealed(&FindingReview {
            seal: None,
            ..good.clone()
        });
        let elsewhere = FindingReview {
            seal: Some(
                other.seal(&crate::seal::as_strs(&crate::seal::finding_review_fields(
                    &elsewhere,
                ))),
            ),
            ..elsewhere
        };
        for (e, says) in [
            (&unsealed, "not recorded through `sv review`"),
            (&changed, "does not match"),
            (&elsewhere, "not this computer's"),
        ] {
            let out = super::apply(
                Path::new("/no/app/folder"),
                std::slice::from_ref(e),
                finding(),
                today(),
                &Checker::Key(key()),
                &|_, _| Looked::Ran,
            );
            assert_eq!(out.findings.len(), 1, "{says}");
            assert!(out.set_aside.is_empty(), "{says}");
            assert!(
                out.not_counted[0].contains(says)
                    && out.not_counted[0].contains("sv review")
                    && out.not_counted[0].contains(WHY),
                "{says}: {:?}",
                out.not_counted
            );
        }

        // Where there is no key to check with, a sealed entry counts and says so; an unsealed one
        // is still a proposal.
        let no_key = super::apply(
            Path::new("/no/app/folder"),
            std::slice::from_ref(&elsewhere),
            finding(),
            today(),
            &Checker::NoKey,
            &|_, _| Looked::Ran,
        );
        assert!(no_key.findings.is_empty(), "{:?}", no_key.not_counted);
        assert_eq!(
            no_key.set_aside[0].sealed,
            Sealed::Unchecked { key: other.id() }
        );
        let no_key = super::apply(
            Path::new("/no/app/folder"),
            &[unsealed],
            finding(),
            today(),
            &Checker::NoKey,
            &|_, _| Looked::Ran,
        );
        assert_eq!(no_key.findings.len(), 1);
    }

    #[test]
    fn only_a_persons_word_counts() {
        for by in [None, Some("ai-tool"), Some("AI coding tool"), Some("  ")] {
            let out = apply(
                &[entry("ast.a", FALSE_ALARM, by, "2026-09-27", WHY)],
                vec![finding("ast.a", "app.py", 5)],
                today(),
            );
            assert_eq!(out.findings.len(), 1, "{by:?} set a finding aside");
            assert!(out.set_aside.is_empty());
            assert!(
                out.not_counted[0].contains("proposal") && out.not_counted[0].contains(WHY),
                "the proposal is shown, with what the tool said: {:?}",
                out.not_counted
            );
        }
    }

    #[test]
    fn an_entry_that_does_not_count_says_why_and_the_finding_stays() {
        for (e, reason) in [
            (
                entry("ast.a", "wontfix", Some("owner"), "2026-09-27", WHY),
                "not one of the two",
            ),
            (
                entry("ast.a", FALSE_ALARM, Some("owner"), "2026-09-27", "fine"),
                "shorter than 40",
            ),
            (
                entry("ast.a", FALSE_ALARM, Some("owner"), "2026-10-02", WHY),
                "has not come yet",
            ),
            (
                entry("ast.a", FALSE_ALARM, Some("owner"), "someday", WHY),
                "no date",
            ),
            (
                entry("ast.a", ACCEPTED_RISK, Some("owner"), "2026-06-28", WHY),
                "lapsed after 90 days",
            ),
            (
                FindingReview {
                    fingerprint: "fp-changed".into(),
                    ..entry("ast.a", FALSE_ALARM, Some("owner"), "2026-09-27", WHY)
                },
                "no finding matches it any more",
            ),
        ] {
            let out = apply(&[e], vec![finding("ast.a", "app.py", 5)], today());
            assert_eq!(out.findings.len(), 1, "{reason}");
            assert!(out.set_aside.is_empty(), "{reason}");
            assert!(
                out.not_counted.len() == 1 && out.not_counted[0].contains(reason),
                "{reason}: {:?}",
                out.not_counted
            );
        }
    }

    #[test]
    fn a_false_alarm_on_a_line_of_code_holds_until_the_line_changes_but_one_without_a_line_lapses()
    {
        // Old, and still matching: the line has not changed, so it holds.
        let out = apply(
            &[entry(
                "ast.a",
                FALSE_ALARM,
                Some("owner"),
                "2025-01-01",
                WHY,
            )],
            vec![finding("ast.a", "app.py", 5)],
            today(),
        );
        assert!(out.findings.is_empty(), "{:?}", out.not_counted);
        // A probe of the running app has no line to watch.
        let mut probe = finding("probe.a", "the running app", 1);
        probe.fingerprint = "fp-probe.a".into();
        let mut e = entry("probe.a", FALSE_ALARM, Some("owner"), "2025-01-01", WHY);
        e.file = "the running app".into();
        let out = apply(&[e.clone()], vec![probe.clone()], today());
        assert_eq!(out.findings.len(), 1);
        assert!(
            out.not_counted[0].contains("no line of code"),
            "{:?}",
            out.not_counted
        );
        e.on = Some("2026-09-01".into());
        assert!(apply(&[e], vec![probe], today()).findings.is_empty());
    }

    #[test]
    fn a_key_or_password_needs_a_longer_reason_and_cannot_be_an_accepted_risk() {
        let key = || finding("secrets.aws-access-key", "app.py", 3);
        let out = apply(
            &[entry(
                "secrets.aws-access-key",
                FALSE_ALARM,
                Some("owner"),
                "2026-09-27",
                WHY,
            )],
            vec![key()],
            today(),
        );
        assert_eq!(out.findings.len(), 1, "a 40-character reason is not enough");
        assert!(out.not_counted[0].contains("not a real one"));
        let out = apply(
            &[entry(
                "secrets.aws-access-key",
                FALSE_ALARM,
                Some("owner"),
                "2026-09-27",
                SECRET_WHY,
            )],
            vec![key()],
            today(),
        );
        assert!(out.findings.is_empty(), "{:?}", out.not_counted);
        let out = apply(
            &[entry(
                "secrets.aws-access-key",
                ACCEPTED_RISK,
                Some("owner"),
                "2026-09-27",
                SECRET_WHY,
            )],
            vec![key()],
            today(),
        );
        assert_eq!(out.findings.len(), 1);
        assert!(out.not_counted[0].contains("cannot be an accepted risk"));
    }

    #[test]
    fn a_finding_says_what_it_was_called_before_its_fingerprint_changed_form() {
        // For a tracker that keys findings by fingerprint across runs (cato-pipeline's POA&M):
        // the earlier name is given when it differs, and only then.
        let dir = std::env::temp_dir().join(format!("sv-review-earlier-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let line = "    cur.execute(\"SELECT * FROM t WHERE id = \" + user_id)";
        std::fs::write(dir.join("app.py"), format!("import x\n{line}\n")).unwrap();
        let mut findings = vec![finding("ast.sql", "app.py", 2)];
        fill_fingerprints(&dir, &mut findings);
        let f = &findings[0];
        assert!(
            f.fingerprint.starts_with(FINGERPRINT_V2),
            "the setup: today's form"
        );
        assert_eq!(
            f.earlier_fingerprints,
            vec![named("ast.sql", "app.py", line.trim())],
            "the earlier form, by the line's text"
        );
        let json = serde_json::to_value(f).unwrap();
        assert_eq!(
            json["earlier_fingerprints"][0],
            f.earlier_fingerprints[0].as_str()
        );
        // A finding about no line of code is named as before, so nothing earlier is given.
        let mut about_the_app = finding("config.security-contact", "", 0);
        about_the_app.location.file = String::new();
        let mut findings = vec![about_the_app];
        fill_fingerprints(&dir, &mut findings);
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            findings[0].earlier_fingerprints.is_empty(),
            "{:?}",
            findings[0].fingerprint
        );
        assert!(
            serde_json::to_value(&findings[0])
                .unwrap()
                .get("earlier_fingerprints")
                .is_none()
        );
    }

    #[test]
    fn the_fingerprint_follows_the_lines_text_not_its_number_and_never_holds_it() {
        let dir = std::env::temp_dir().join(format!("sv-review-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let line = "    cur.execute(\"SELECT * FROM t WHERE id = \" + user_id)";
        std::fs::write(dir.join("app.py"), format!("import x\n{line}\n")).unwrap();
        let mut f = finding("ast.sql", "app.py", 2);
        let first = fingerprint(&dir, &f);
        // Two lines added above: the finding moves, and keeps its name.
        std::fs::write(dir.join("app.py"), format!("import x\n\n\n{line}\n")).unwrap();
        f.location.line = 4;
        assert_eq!(fingerprint(&dir, &f), first);
        // The line itself changes: a new name, so a false alarm about the old line lapses.
        std::fs::write(dir.join("app.py"), format!("import x\n{line} # changed\n")).unwrap();
        f.location.line = 2;
        assert_ne!(fingerprint(&dir, &f), first);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(first.len(), 19);
        assert!(first.starts_with(FINGERPRINT_V2));
        assert!(first[3..].chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!first.contains("SELECT"));
    }

    /// A scratch app folder holding `app.py`, removed when dropped.
    struct App(std::path::PathBuf);

    impl App {
        fn new(name: &str, text: &str) -> App {
            let dir = std::env::temp_dir().join(format!("sv-review-{name}-{}", std::process::id()));
            std::fs::remove_dir_all(&dir).ok();
            std::fs::create_dir_all(&dir).unwrap();
            let app = App(dir);
            app.write(text);
            app
        }

        fn write(&self, text: &str) {
            std::fs::write(self.0.join("app.py"), text).unwrap();
        }

        /// The findings of `rule` on these lines, with the fingerprints the report gives them.
        fn findings(&self, rule: &str, lines: &[usize]) -> Vec<Finding> {
            let mut found: Vec<Finding> =
                lines.iter().map(|&n| finding(rule, "app.py", n)).collect();
            fill_fingerprints(&self.0, &mut found);
            found
        }
    }

    impl Drop for App {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    fn reviewed(rule: &str, fingerprint: &str) -> FindingReview {
        FindingReview {
            fingerprint: fingerprint.to_owned(),
            ..entry(rule, FALSE_ALARM, Some("owner"), "2026-09-27", WHY)
        }
    }

    /// `apply` with what `looked` says of an entry that matches nothing.
    fn apply_looked(
        app: &App,
        entries: &[FindingReview],
        findings: Vec<Finding>,
        looked: Looked,
    ) -> Outcome {
        let sealed: Vec<FindingReview> = entries
            .iter()
            .map(|e| {
                let mut e = e.clone();
                let fields = crate::seal::finding_review_fields(&e);
                e.seal = Some(key().seal(&crate::seal::as_strs(&fields)));
                e
            })
            .collect();
        super::apply(
            &app.0,
            &sealed,
            findings,
            today(),
            &Checker::Key(key()),
            &move |_, _| looked.clone(),
        )
    }

    const TWO_QUERIES: &str = "def mine(cur, uid):\n    sql = \"SELECT * FROM notes WHERE owner = ?\"\n    cur.execute(sql, (uid,))\n\ndef theirs(cur, uid):\n    sql = \"SELECT * FROM notes WHERE owner = ?\"\n    cur.execute(sql, (uid,))\n";

    #[test]
    fn identical_lines_each_need_their_own_review() {
        let app = App::new("identical", TWO_QUERIES);
        let found = app.findings("ast.sql", &[3, 7]);
        // The setup: the two lines read the same, and the earlier fingerprint could not tell them
        // apart.
        assert_eq!(
            Texts::new(&app.0).earlier_fingerprint(&found[0], "ast.sql"),
            Texts::new(&app.0).earlier_fingerprint(&found[1], "ast.sql")
        );
        assert_ne!(found[0].fingerprint, found[1].fingerprint);
        // A review of the second sets aside the second and nothing else, and the other way round.
        for (reviewed_one, still) in [(1, 3), (0, 7)] {
            let out = apply_looked(
                &app,
                &[reviewed("ast.sql", &found[reviewed_one].fingerprint)],
                found.clone(),
                Looked::Ran,
            );
            assert!(out.not_counted.is_empty(), "{:?}", out.not_counted);
            assert_eq!(out.set_aside.len(), 1);
            let lines: Vec<usize> = out.findings.iter().map(|f| f.location.line).collect();
            assert_eq!(lines, vec![still]);
        }
        // Each needs its own: both reviewed, both set aside.
        let out = apply_looked(
            &app,
            &[
                reviewed("ast.sql", &found[0].fingerprint),
                reviewed("ast.sql", &found[1].fingerprint),
            ],
            found.clone(),
            Looked::Ran,
        );
        assert!(out.findings.is_empty(), "{:?}", out.not_counted);
        // `sv review` shows the one line each names.
        for f in &found {
            let lines = lines_with_fingerprint(&app.0, "ast.sql", "app.py", &f.fingerprint);
            assert_eq!(lines.len(), 1);
            assert_eq!(lines[0].0, f.location.line);
        }
    }

    #[test]
    fn a_change_to_the_line_that_sets_its_value_ends_the_review_and_others_do_not() {
        let safe = "def find(cur, uid):\n    sql = \"SELECT * FROM notes WHERE owner = ?\"\n    cur.execute(sql, (uid,))\n";
        let app = App::new("reaching", safe);
        let before = app.findings("ast.sql", &[3])[0].fingerprint.clone();
        let entry = reviewed("ast.sql", &before);
        // The setup: it counts while nothing has changed.
        let out = apply_looked(
            &app,
            std::slice::from_ref(&entry),
            app.findings("ast.sql", &[3]),
            Looked::Ran,
        );
        assert!(out.findings.is_empty(), "{:?}", out.not_counted);

        // Changes that leave what reaches the line alone keep its name: a line added above, a
        // comment, another function.
        for (text, line) in [
            (format!("import os\n\n{safe}"), 5),
            (format!("{safe}\ndef other():\n    return 1\n"), 3),
            (
                safe.replace(
                    "def find(cur, uid):\n",
                    "def find(cur, uid):\n    # the owner's notes\n",
                ),
                4,
            ),
        ] {
            app.write(&text);
            assert_eq!(
                app.findings("ast.sql", &[line])[0].fingerprint,
                before,
                "{text}"
            );
        }

        // Changes to what the flagged line uses: the value built from input, or added to after.
        for (text, line) in [
            (safe.replace("= ?\"", "= \" + uid"), 3),
            (
                safe.replace("    cur.execute", "    sql += \" OR 1=1\"\n    cur.execute"),
                4,
            ),
            (
                safe.replace(
                    "    cur.execute",
                    "    cur = other_db.cursor()\n    cur.execute",
                ),
                4,
            ),
        ] {
            app.write(&text);
            let now = app.findings("ast.sql", &[line]);
            assert_ne!(now[0].fingerprint, before, "{text}");
            let out = apply_looked(&app, std::slice::from_ref(&entry), now, Looked::Ran);
            assert_eq!(out.findings.len(), 1, "{text}");
            assert!(
                out.not_counted[0].contains("no finding matches it any more")
                    && out.not_counted[0].contains("a line above it that sets a value it uses"),
                "{:?}",
                out.not_counted
            );
        }
    }

    #[test]
    fn a_value_built_over_several_lines_is_watched_back_to_where_it_is_set() {
        // `sql +=` adds to what `sql =` set, so the line that sets it is watched too, not only the
        // nearest.
        let safe = "def find(cur, uid):\n    sql = \"SELECT * FROM notes WHERE owner = ?\"\n    sql += \" ORDER BY id\"\n    cur.execute(sql, (uid,))\n";
        let app = App::new("chain", safe);
        let before = app.findings("ast.sql", &[4])[0].fingerprint.clone();
        app.write(&safe.replace("= ?\"", "= \" + uid"));
        assert_ne!(app.findings("ast.sql", &[4])[0].fingerprint, before);
        // The setup: with the first line as it was, the fingerprint is as it was.
        app.write(safe);
        assert_eq!(app.findings("ast.sql", &[4])[0].fingerprint, before);
    }

    #[test]
    fn an_entry_with_the_earlier_fingerprint_matches_its_one_finding_and_says_when_it_cannot_tell()
    {
        // As family-hub's 25 entries were written: sixteen hex characters over the rule, the file,
        // and the trimmed line.
        let app = App::new(
            "earlier",
            &format!(
                "{TWO_QUERIES}\ndef one(cur, name):\n    cur.execute(\"SELECT 1 WHERE a = \" + name)\n"
            ),
        );
        let found = app.findings("ast.sql", &[3, 7, 10]);
        let unique = named(
            "ast.sql",
            "app.py",
            "cur.execute(\"SELECT 1 WHERE a = \" + name)",
        );
        let twice = named("ast.sql", "app.py", "cur.execute(sql, (uid,))");
        assert!(is_earlier_form(&unique) && is_earlier_form(&twice));
        assert!(
            found
                .iter()
                .all(|f| f.fingerprint.starts_with(FINGERPRINT_V2))
        );

        // Where one finding is on a line with that text: it matches that finding, as it did, and
        // the seal `sv review` made over it still holds.
        let out = apply_looked(
            &app,
            &[reviewed("ast.sql", &unique)],
            found.clone(),
            Looked::Ran,
        );
        assert!(out.not_counted.is_empty(), "{:?}", out.not_counted);
        assert_eq!(out.set_aside[0].finding.location.line, 10);
        assert_eq!(out.set_aside[0].sealed, Sealed::Here);
        assert_eq!(out.findings.len(), 2);

        // Where two are on lines that read the same: neither, and it says why and what to do.
        let out = apply_looked(
            &app,
            &[reviewed("ast.sql", &twice)],
            found.clone(),
            Looked::Ran,
        );
        assert_eq!(out.findings.len(), 3);
        assert!(out.set_aside.is_empty());
        assert!(
            out.not_counted[0].contains("before 5 October 2026")
                && out.not_counted[0].contains("lines 3 and 7")
                && out.not_counted[0].contains("applies to none of them")
                && out.not_counted[0].contains("record it through `sv review`"),
            "{:?}",
            out.not_counted
        );
        // `sv review` sees both lines, and has no one line to write today's fingerprint for.
        assert_eq!(
            lines_with_fingerprint(&app.0, "ast.sql", "app.py", &twice).len(),
            2
        );
        assert_eq!(todays_form(&app.0, "ast.sql", "app.py", &twice), None);
        // For the one line, today's fingerprint is the one the report gives its finding.
        assert_eq!(
            todays_form(&app.0, "ast.sql", "app.py", &unique).as_deref(),
            Some(found[2].fingerprint.as_str())
        );
    }

    #[test]
    fn an_entry_that_matches_nothing_says_whether_it_was_looked_for() {
        let app = App::new("looked", "x = 1\n");
        let entry = reviewed(
            "tests.name-does-not-match-requirement",
            "v2-0123456789abcdef",
        );
        let said = |looked: Looked| {
            let out = apply_looked(&app, std::slice::from_ref(&entry), Vec::new(), looked);
            assert!(out.set_aside.is_empty());
            assert_eq!(out.not_counted.len(), 1);
            out.not_counted[0].clone()
        };
        let gone = said(Looked::Ran);
        let not_looked = said(Looked::NotThisTime(
            "the app's own tests run only with --run".to_owned(),
        ));
        let unknown = said(Looked::Unknown);
        assert!(gone.contains("no finding matches it any more") && gone.contains("can be removed"));
        for not_gone in [&not_looked, &unknown] {
            assert!(
                !not_gone.contains("no finding matches it any more")
                    && !not_gone.contains("can be removed")
                    && not_gone.contains("not a sign the finding was fixed"),
                "{not_gone}"
            );
        }
        assert!(
            not_looked
                .contains("not looked for this time (the app's own tests run only with --run)")
                && not_looked.contains("keep the entry"),
            "{not_looked}"
        );
        assert!(
            unknown.contains("has no rule `tests.name-does-not-match-requirement`"),
            "{unknown}"
        );
    }

    #[test]
    fn a_second_entry_for_a_finding_already_set_aside_is_not_called_gone() {
        // Two entries for one finding is the open item R11; one entry matching one finding does
        // not change which is applied, and the second is not told its finding is gone.
        let app = App::new("twice", TWO_QUERIES);
        let found = app.findings("ast.sql", &[3, 7]);
        let e = reviewed("ast.sql", &found[0].fingerprint);
        let out = apply_looked(&app, &[e.clone(), e], found, Looked::Ran);
        assert_eq!(out.set_aside.len(), 1);
        assert_eq!(out.findings.len(), 1);
        assert!(
            out.not_counted[0].contains("an entry above it already set this finding aside")
                && !out.not_counted[0].contains("no finding matches"),
            "{:?}",
            out.not_counted
        );
    }
}
