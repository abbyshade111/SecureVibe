//! A person's record that a finding is a false alarm, or a risk they accept for now.
//!
//! The owner's decisions, 27 September 2026 (BACKLOG, "False alarms, part 2"). Two verdicts:
//! *false alarm*, the code is fine; *accepted risk*, a real problem lived with for now. Only a
//! person's word counts: the AI coding tool rewrites code until a warning stops, and a switch that
//! makes a warning stop is the easiest rewrite of all, so an entry the tool wrote is shown as its
//! proposal and the finding still counts. A false alarm lapses when the flagged line changes, because
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
use std::path::Path;
use sv_manifest::FindingReview;

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

/// The name a review gives a finding: its rule, its file, and, for a finding on a line of code, the
/// text of that line with its spaces trimmed, so moving the line keeps the name and changing it does
/// not. A finding with no line of code is named by its title instead. Only a hash of these is kept,
/// sixteen hex characters of SHA-256, so the line a key was found on is never copied anywhere.
pub fn fingerprint(app_dir: &Path, f: &Finding) -> String {
    use sha2::{Digest, Sha256};
    let what = if crate::finding::reads_code(f) {
        std::fs::read_to_string(app_dir.join(&f.location.file))
            .ok()
            .and_then(|text| {
                text.lines()
                    .nth(f.location.line.saturating_sub(1))
                    .map(|l| l.trim().to_owned())
            })
            .unwrap_or_else(|| format!("line {}", f.location.line))
    } else {
        f.title.clone()
    };
    let digest = Sha256::digest(format!("{}\n{}\n{what}", f.rule_id, f.location.file).as_bytes());
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// Fills in every finding's fingerprint.
pub fn fill_fingerprints(app_dir: &Path, findings: &mut [Finding]) {
    for f in findings {
        f.fingerprint = fingerprint(app_dir, f);
    }
}

/// Applies the entries to the findings, which must already have their fingerprints.
pub fn apply(entries: &[FindingReview], findings: Vec<Finding>, today: Day) -> Outcome {
    let mut out = Outcome {
        findings,
        ..Outcome::default()
    };
    for entry in entries {
        let named = format!("`{}` in {} ({})", entry.rule, entry.file, entry.fingerprint);
        let Some(i) = out.findings.iter().position(|f| {
            f.fingerprint == entry.fingerprint
                && f.location.file == entry.file
                && (f.rule_id == entry.rule || f.also_reported_by.contains(&entry.rule))
        }) else {
            out.not_counted.push(format!(
                "{named}: no finding matches it any more. The flagged line changed, so the \
                 finding has a new fingerprint and needs looking at again, or the finding is gone \
                 and the entry can be removed."
            ));
            continue;
        };
        match judge(entry, &out.findings[i], today) {
            Err(why) => out.not_counted.push(format!("{named}: {why}")),
            Ok(()) => {
                let finding = if entry.verdict == FALSE_ALARM {
                    out.findings.remove(i)
                } else {
                    out.findings[i].clone()
                };
                out.set_aside.push(SetAside {
                    finding,
                    verdict: entry.verdict.clone(),
                    why: entry.why.trim().to_owned(),
                    by: entry.by.clone().unwrap_or_default(),
                    on: entry.on.clone().unwrap_or_default(),
                });
            }
        }
    }
    out
}

/// Whether an entry counts, and why not when it does not.
fn judge(entry: &FindingReview, finding: &Finding, today: Day) -> Result<(), String> {
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
             It says: \"{}\". If you agree after reading the code, put your name (or `owner`) in \
             `by` and today's date in `on`.",
            entry.why.trim()
        ));
    }
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
    Ok(())
}

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
            in_test_module: false,
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
        }
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
        assert_eq!(first.len(), 16);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!first.contains("SELECT"));
    }
}
