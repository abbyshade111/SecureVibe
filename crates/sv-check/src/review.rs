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

/// The name a review gives a finding: its rule, its file, and, for a finding on a line of code, the
/// text of that line with its spaces trimmed, so moving the line keeps the name and changing it does
/// not. A finding with no line of code is named by its title instead. Only a hash of these is kept,
/// sixteen hex characters of SHA-256, so the line a key was found on is never copied anywhere.
pub fn fingerprint(app_dir: &Path, f: &Finding) -> String {
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
    named(&f.rule_id, &f.location.file, &what)
}

/// The fingerprint of what a finding names, from its rule, its file, and its trimmed line (or its
/// title, for a finding with no line of code).
pub fn named(rule: &str, file: &str, what: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("{rule}\n{file}\n{what}").as_bytes());
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// The line of `file` an entry's fingerprint names, as its number and its text with spaces
/// trimmed, for `sv review` to show the person what they are deciding about. `None` when no line
/// matches (the line changed, or the finding is not about a line), and for a file outside the app
/// folder, whose lines are never read.
pub fn line_with_fingerprint(
    app_dir: &Path,
    rule: &str,
    file: &str,
    fingerprint: &str,
) -> Option<(usize, String)> {
    let inside = Path::new(file)
        .components()
        .all(|c| matches!(c, std::path::Component::Normal(_)));
    if !inside {
        return None;
    }
    let text = std::fs::read_to_string(app_dir.join(file)).ok()?;
    text.lines()
        .enumerate()
        .find(|(_, l)| named(rule, file, l.trim()) == fingerprint)
        .map(|(i, l)| (i + 1, l.trim().to_owned()))
}

/// Fills in every finding's fingerprint.
pub fn fill_fingerprints(app_dir: &Path, findings: &mut [Finding]) {
    for f in findings {
        f.fingerprint = fingerprint(app_dir, f);
    }
}

/// Applies the entries to the findings, which must already have their fingerprints.
///
/// An entry may name a rule that was merged into a finding rather than the one kept (see
/// `merge_same_place`): the rule kept on a line can change when a tool is added or `sv`'s choice
/// of words changes, and a person's review of that line should not be lost with it. Such an entry
/// counts when its fingerprint is the one the finding would have had under the rule it names
/// (its line read from `app_dir`).
///
/// One entry answers for one finding. Each entry that counts takes the first finding it matches
/// that no earlier entry has taken, so two identical lines with an entry each are both answered.
/// An entry that counts and finds every finding it matches already taken says the same thing again,
/// or says the opposite: the first adds nothing, and the second leaves the finding to be decided,
/// so neither entry counts. Until 5 October 2026 both were applied, a conflicting pair as a false
/// alarm and an accepted risk at once (R11 of the deep review).
pub fn apply(
    app_dir: &Path,
    entries: &[FindingReview],
    findings: Vec<Finding>,
    today: Day,
    seals: &Checker,
) -> Outcome {
    let matches = |entry: &FindingReview, f: &Finding| {
        f.location.file == entry.file
            && ((f.fingerprint == entry.fingerprint
                && (f.rule_id == entry.rule || f.also_reported_by.contains(&entry.rule)))
                || (f.also_reported_by.contains(&entry.rule)
                    && fingerprint(
                        app_dir,
                        &Finding {
                            rule_id: entry.rule.clone(),
                            ..f.clone()
                        },
                    ) == entry.fingerprint))
    };
    let named = |entry: &FindingReview| {
        format!("`{}` in {} ({})", entry.rule, entry.file, entry.fingerprint)
    };
    let mut not_counted = Vec::new();
    // Which entry has taken each finding, and what each counting entry decided.
    let mut taken: Vec<Option<usize>> = vec![None; findings.len()];
    let mut counting: Vec<(usize, usize, Sealed)> = Vec::new();
    let mut voided: Vec<bool> = vec![false; entries.len()];
    for (k, entry) in entries.iter().enumerate() {
        let candidates: Vec<usize> = (0..findings.len())
            .filter(|i| matches(entry, &findings[*i]))
            .collect();
        let Some(&first) = candidates.first() else {
            not_counted.push(format!(
                "{}: no finding matches it any more. The flagged line changed, so the finding has \
                 a new fingerprint and needs looking at again, or the finding is gone and the entry \
                 can be removed.",
                named(entry)
            ));
            continue;
        };
        let sealed = match judge(entry, &findings[first], today, seals) {
            Err(why) => {
                not_counted.push(format!("{}: {why}", named(entry)));
                continue;
            }
            Ok(sealed) => sealed,
        };
        if let Some(&free) = candidates.iter().find(|i| taken[**i].is_none()) {
            taken[free] = Some(k);
            counting.push((k, free, sealed));
            continue;
        }
        // Every finding it matches is answered already: by an entry saying the same, or the opposite.
        let earlier = taken[first].expect("taken");
        if entries[earlier].verdict == entry.verdict {
            not_counted.push(format!(
                "{}: an earlier entry already answers for this finding in the same way, so this one \
                 adds nothing and can be removed.",
                named(entry)
            ));
        } else {
            voided[earlier] = true;
            voided[k] = true;
            not_counted.push(format!(
                "{}: it says {} and an earlier entry for the same finding says {}, so neither \
                 counts and the finding stands until one of them is removed.",
                named(entry),
                entry.verdict,
                entries[earlier].verdict
            ));
        }
    }
    let mut set_aside = Vec::new();
    let mut gone = Vec::new();
    for (k, i, sealed) in counting {
        let entry = &entries[k];
        if voided[k] {
            continue;
        }
        if entry.verdict == FALSE_ALARM {
            gone.push(i);
        }
        set_aside.push(SetAside {
            finding: findings[i].clone(),
            verdict: entry.verdict.clone(),
            why: entry.why.trim().to_owned(),
            by: entry.by.clone().unwrap_or_default(),
            on: entry.on.clone().unwrap_or_default(),
            sealed,
        });
    }
    let findings = findings
        .into_iter()
        .enumerate()
        .filter(|(i, _)| !gone.contains(i))
        .map(|(_, f)| f)
        .collect();
    Outcome {
        findings,
        set_aside,
        not_counted,
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
        super::apply(app_dir, &sealed, findings, today, &Checker::Key(key()))
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
    fn one_entry_answers_for_one_finding_and_a_pair_that_disagree_leaves_it_standing() {
        // R11 of the deep review: duplicate and conflicting entries were each applied.
        let a = || finding("ast.a", "app.py", 5);
        let fa = |by: &str| entry("ast.a", FALSE_ALARM, Some(by), "2026-09-27", WHY);
        let ar = |by: &str| entry("ast.a", ACCEPTED_RISK, Some(by), "2026-09-27", WHY);

        // The same answer twice: the first counts, the second adds nothing and says so.
        let out = apply(&[ar("owner"), ar("Sam Lee")], vec![a()], today());
        assert_eq!(out.set_aside.len(), 1, "{:?}", out.set_aside);
        assert_eq!(out.set_aside[0].by, "owner");
        assert_eq!(out.findings.len(), 1, "an accepted risk stays on the list");
        assert!(
            out.not_counted[0].contains("adds nothing"),
            "{:?}",
            out.not_counted
        );

        // Opposite answers: neither counts, and the finding stands, in either order.
        for pair in [[fa("owner"), ar("owner")], [ar("owner"), fa("owner")]] {
            let out = apply(&pair, vec![a()], today());
            assert!(out.set_aside.is_empty(), "{:?}", out.set_aside);
            assert_eq!(out.findings.len(), 1, "the finding stands");
            assert!(
                out.not_counted.iter().any(|n| n.contains("neither")),
                "{:?}",
                out.not_counted
            );
        }

        // Two identical lines, an entry for each: both are answered, as before.
        let out = apply(
            &[fa("owner"), fa("owner")],
            vec![a(), finding("ast.a", "app.py", 9)],
            today(),
        );
        assert!(out.not_counted.is_empty(), "{:?}", out.not_counted);
        assert_eq!(out.set_aside.len(), 2);
        assert!(out.findings.is_empty());

        // An entry that does not count takes nothing: the one after it still answers.
        let mut unsealed = fa("owner");
        unsealed.seal = None;
        let out = apply(&[unsealed, fa("owner")], vec![a()], today());
        assert_eq!(out.set_aside.len(), 1, "{:?}", out.not_counted);
        assert!(out.findings.is_empty());
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
