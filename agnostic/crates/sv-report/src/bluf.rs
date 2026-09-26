//! The short version: what this app's report says, before any of the explaining.
//!
//! The report used to open by explaining its own epistemology — what *checked* means, what it does
//! not mean, why nothing here is a pass — and only then, several hundred words later, get to what
//! was actually found. That order is right for a careful reader and wrong for everybody else. The
//! owner's question is "what should I do about my app", and the answer was on the third screen.
//!
//! # This is the most dangerous section in the report
//!
//! It is also the only one most people will read, which is exactly why it needs the most care. Every
//! honesty rule this project has is easiest to break here, in a summary, where a number sits without
//! the sentence that qualifies it. Three rules hold it:
//!
//! - **No total that reads as a score.** "32 of 218" invites the reader to compute 15% and call it a
//!   grade. The counts are given as a list of what was *done* — something looked, nothing looked —
//!   not as a fraction of an ideal.
//! - **The unexamined majority is stated first among the counts**, because on nearly every real app
//!   it is the largest number and the most important fact. A summary that leads with what was
//!   checked buries it.
//! - **Never the word pass, and never a claim about the app's security.** The report says what was
//!   found and what nobody looked at. `the_short_version_never_says_the_app_is_secure` pins it.
//!
//! # What it is for
//!
//! Three things, in the order somebody would do them: fix what was found, answer what only a person
//! can answer, write tests for the rest. Each names where in the report to go.

use crate::{Report, Status};
use sv_check::Severity;

/// How many findings the short version names one by one before it starts counting.
const NAMED_FINDINGS: usize = 5;

/// One thing to do, in the order a person would do it.
pub struct NextStep {
    /// The imperative, in the owner's language.
    pub what: String,
    /// Where in the report it is set out.
    pub where_to_look: String,
}

/// The findings worth naming at the top, worst first, and how many were left out.
pub fn worst_findings(report: &Report) -> (Vec<&sv_check::Finding>, usize) {
    let mut findings: Vec<&sv_check::Finding> = report.findings.iter().collect();
    findings.sort_by_key(|f| severity_rank(f.severity));
    let shown = findings.len().min(NAMED_FINDINGS);
    let rest = findings.len() - shown;
    (findings.into_iter().take(shown).collect(), rest)
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

/// The one-sentence headline: what was found, or that nothing was.
///
/// The "nothing was found" wording is the careful one. An app with no findings has not passed
/// anything, and the sentence has to carry that without the reader having to read on.
pub fn headline(report: &Report) -> String {
    // Counted over the findings, not over `needs_attention`, because the bullets under this line
    // are findings and the two numbers legitimately differ: a finding can name a requirement this
    // app is not being assessed against, which is reported and does not make a requirement need
    // attention. The first version of this line said "1 requirement needs attention" above a list
    // of two, which is the kind of small contradiction a reader notices and cannot resolve.
    let n = report.findings.len();
    if n == 0 {
        return format!(
            "Nothing here found a problem. That is not the same as this app being sound: {} of \
             the {} requirements that apply have had nothing look at them at all.",
            report.counts.not_verified, report.counts.applicable
        );
    }
    format!(
        "{n} thing{} {} found, worst first.",
        if n == 1 { "" } else { "s" },
        if n == 1 { "was" } else { "were" }
    )
}

/// What was done, as a list of activities rather than a score.
///
/// Deliberately not a fraction. "32 of 218" is read as a grade, and there is no grade here.
///
/// Ordered strongest evidence first — a problem was found, then a check ran, then the owner's own
/// word, then nothing at all — at the owner's request, and it reads as the severity order somebody
/// expects. The earlier order put the unexamined majority first so it could not be buried, and that
/// job now belongs entirely to the headline above, which names the number in a sentence rather than
/// a row: `a_clean_run_is_never_reported_as_the_app_being_sound` is what holds it there.
pub fn counted(report: &Report) -> Vec<(String, usize)> {
    let c = &report.counts;
    let mut rows = vec![
        ("something found a problem".to_owned(), c.needs_attention),
        (
            "an automated check looked and found nothing wrong".to_owned(),
            c.checked,
        ),
    ];
    if c.documented > 0 {
        rows.push((
            "you answered the question in the security notes".to_owned(),
            c.documented,
        ));
    }
    if c.attested > 0 {
        rows.push((
            "you answered yes about how the app is built".to_owned(),
            c.attested,
        ));
    }
    rows.push((
        "nothing has looked at these at all".to_owned(),
        c.not_verified,
    ));
    rows
}

/// How many applicable requirements no check can ever settle, so only a person can.
pub fn only_a_person_can(report: &Report) -> usize {
    only_a_person_can_counts(report).0
}

/// The same, and how many of them are at ASVS level 1 — the part worth starting on.
pub fn only_a_person_can_counts(report: &Report) -> (usize, usize) {
    let a_test_could: std::collections::BTreeSet<&str> = report
        .tests_to_write
        .iter()
        .map(|t| t.id.as_str())
        .collect();
    let theirs: Vec<&crate::RequirementLine> = report
        .requirements
        .iter()
        .filter(|r| r.status == Status::NotVerified && !a_test_could.contains(r.id.as_str()))
        .collect();
    let level_one = theirs.iter().filter(|r| r.level == 1).count();
    (theirs.len(), level_one)
}

/// What to do, in the order a person would do it. Only steps there is actually work for.
pub fn next_steps(report: &Report) -> Vec<NextStep> {
    let mut steps = Vec::new();
    let c = &report.counts;
    if c.needs_attention > 0 {
        steps.push(NextStep {
            what: format!(
                "Fix the {} {}.",
                c.needs_attention,
                if c.needs_attention == 1 {
                    "thing that needs attention"
                } else {
                    "things that need attention"
                }
            ),
            where_to_look: "security.md lists each one with what to do".to_owned(),
        });
    }
    let (person, person_level_one) = only_a_person_can_counts(report);
    if person > 0 {
        // The level-1 subset leads, because the whole number is daunting and most of it is the
        // Secure by Design checklist, which is design review rather than anything to go and do
        // this afternoon. "98 things" stops a reader; "7 to start with" does not.
        steps.push(NextStep {
            what: if person_level_one > 0 {
                format!(
                    "Answer the {person_level_one} question{} at level 1 that no tool can settle — \
                     what your rules are, who may do what, how the app is built. {person} in all, \
                     most of them design review at higher levels.",
                    if person_level_one == 1 { "" } else { "s" }
                )
            } else {
                format!(
                    "Answer the {person} requirement{} no tool can settle — what your rules are, \
                     who may do what, how the app is built.",
                    if person == 1 { "" } else { "s" }
                )
            },
            where_to_look:
                "`sv notes` writes the questions out; the rest are the [design] section \
                            of securevibe.toml"
                    .to_owned(),
        });
    }
    if !report.tests_to_write.is_empty() {
        let level_one = report
            .tests_to_write
            .iter()
            .filter(|t| t.level == 1)
            .count();
        steps.push(NextStep {
            what: format!(
                "Write tests for the {} requirement{} a test could settle{}.",
                report.tests_to_write.len(),
                if report.tests_to_write.len() == 1 {
                    ""
                } else {
                    "s"
                },
                if level_one > 0 {
                    format!(", starting with the {level_one} at level 1")
                } else {
                    String::new()
                }
            ),
            where_to_look: "\"Tests to write\", lowest level first".to_owned(),
        });
    }
    if c.not_assessed > 0 {
        steps.push(NextStep {
            what: format!(
                "Answer the questions in securevibe.toml that would place {} more requirements, \
                 which are neither excluded nor passed today.",
                c.not_assessed
            ),
            where_to_look: "\"Requirements nobody has placed\" names the question for each"
                .to_owned(),
        });
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Counts;

    fn report(counts: Counts) -> Report {
        Report {
            app_name: "Test".into(),
            target_level: 1,
            generated: None,
            run_note: None,
            run_steps: Vec::new(),
            counts,
            requirements: Vec::new(),
            excluded: Vec::new(),
            undecided: Vec::new(),
            claims: Vec::new(),
            findings: Vec::new(),
            out_of_scope: Vec::new(),
            satisfied_elsewhere: Vec::new(),
            checklist_above_level: Vec::new(),
            tests_to_write: Vec::new(),
            only_you_can_check: Vec::new(),
            no_instructions_yet: 0,
            named_not_credited: Vec::new(),
            not_for_tests: 0,
            threats: Vec::new(),
            threat_parts: Vec::new(),
            gaps: Vec::new(),
        }
    }

    #[test]
    fn a_clean_run_is_never_reported_as_the_app_being_sound() {
        // The sentence somebody will screenshot. An app that nothing found a problem with has not
        // passed anything, and the headline has to carry that without being read on from.
        let r = report(Counts {
            applicable: 200,
            not_verified: 190,
            checked: 10,
            ..Counts::default()
        });
        let line = headline(&r);
        assert!(
            line.contains("190"),
            "the unexamined count must be in it: {line}"
        );
        let lowered = line.to_lowercase();
        for word in ["pass", "secure", "compliant", "safe"] {
            assert!(!lowered.contains(word), "{word:?} must not appear: {line}");
        }
    }

    fn a_finding(rule: &str) -> sv_check::Finding {
        sv_check::Finding {
            rule_id: rule.into(),
            title: "Something".into(),
            severity: Severity::High,
            confidence: sv_check::Confidence::High,
            location: sv_check::Location {
                file: "app.py".into(),
                line: 1,
            },
            secret: None,
            requirement_ids: vec!["V6.3.1".into()],
            cwe: Vec::new(),
            description: String::new(),
            impact: String::new(),
            fix: String::new(),
        }
    }

    #[test]
    fn the_headline_counts_the_findings_listed_under_it() {
        // The bug this pins: the headline counted `needs_attention`, which is requirements, while
        // the bullets under it are findings. A finding naming a requirement this app is not being
        // assessed against is reported and moves no requirement, so the real report said
        // "1 requirement needs attention" above a list of two. The reader cannot resolve that.
        let mut r = report(Counts {
            applicable: 200,
            needs_attention: 1,
            not_verified: 190,
            ..Counts::default()
        });
        r.findings = vec![a_finding("probe.one"), a_finding("config.two")];
        let line = headline(&r);
        assert!(line.starts_with("2 things were found"), "got {line}");
        assert_eq!(worst_findings(&r).0.len(), 2, "and both are listed");
    }

    #[test]
    fn the_worst_finding_comes_first_and_the_rest_are_counted() {
        let mut r = report(Counts {
            applicable: 10,
            not_verified: 10,
            ..Counts::default()
        });
        // Three, in an order that is neither sorted nor the reverse of sorted. Two findings
        // given worst-last cannot tell a sort from a `reverse()`: both put the worst first, and
        // replacing the sort with a reverse was caught by nothing until this fixture had three.
        let mut medium = a_finding("medium.one");
        medium.severity = Severity::Medium;
        let mut critical = a_finding("critical.one");
        critical.severity = Severity::Critical;
        let mut low = a_finding("low.one");
        low.severity = Severity::Low;
        r.findings = vec![medium, critical, low];
        let (shown, rest) = worst_findings(&r);
        let order: Vec<&str> = shown.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(
            order,
            ["critical.one", "medium.one", "low.one"],
            "worst first"
        );
        assert_eq!(rest, 0);

        r.findings = (0..9).map(|i| a_finding(&format!("r{i}"))).collect();
        let (shown, rest) = worst_findings(&r);
        assert_eq!(shown.len(), NAMED_FINDINGS, "the top of the list is named");
        assert_eq!(
            rest,
            9 - NAMED_FINDINGS,
            "and the rest are counted, not dropped"
        );
    }

    #[test]
    fn the_person_step_leads_with_the_level_one_subset() {
        // "98 things" stops a reader. Most of that number is the Secure by Design checklist, which
        // is design review rather than work to start this afternoon.
        let mut r = report(Counts {
            applicable: 100,
            not_verified: 100,
            ..Counts::default()
        });
        let mut high = unverified("SBD-AC-01");
        high.level = 0;
        r.requirements = vec![unverified("V2.1.1"), high];
        let step = next_steps(&r)
            .into_iter()
            .find(|s| s.what.contains("no tool can settle"))
            .expect("the step exists");
        assert!(
            step.what.starts_with("Answer the 1 question at level 1"),
            "got {}",
            step.what
        );
        assert!(step.what.contains("2 in all"), "got {}", step.what);
    }

    #[test]
    fn the_counts_run_from_strongest_evidence_to_none() {
        // The owner's order: a problem found, then a check that ran, then their own word, then
        // nothing. It reads as the severity order somebody expects.
        let r = report(Counts {
            applicable: 200,
            checked: 10,
            not_verified: 189,
            needs_attention: 1,
            ..Counts::default()
        });
        let rows = counted(&r);
        let labels: Vec<&str> = rows.iter().map(|(l, _)| l.as_str()).collect();
        assert!(labels[0].contains("found a problem"), "{labels:?}");
        assert!(labels[1].contains("automated check"), "{labels:?}");
        assert!(
            labels
                .last()
                .is_some_and(|l| l.contains("nothing has looked")),
            "{labels:?}"
        );
    }

    #[test]
    fn the_unexamined_majority_is_still_impossible_to_miss() {
        // It used to be the first row, so that a reader skimming the tally met it first. It is now
        // the last one, which is the whole risk of the owner's order — so the headline has to carry
        // it, and this is the test that says the headline is now the only thing that does.
        let r = report(Counts {
            applicable: 200,
            checked: 10,
            not_verified: 189,
            needs_attention: 1,
            ..Counts::default()
        });
        let rows = counted(&r);
        assert!(
            rows.last()
                .is_some_and(|(l, _)| l.contains("nothing has looked")),
            "the premise of this test has changed: {rows:?}"
        );
        // With a finding present the headline is about findings, so the clean-run headline is the
        // one that must name the number. Both are checked, because either can be what a reader sees.
        let clean = report(Counts {
            applicable: 200,
            checked: 10,
            not_verified: 190,
            ..Counts::default()
        });
        assert!(
            headline(&clean).contains("190"),
            "a clean run must name the unexamined count in the headline: {}",
            headline(&clean)
        );
    }

    #[test]
    fn the_owner_tiers_are_shown_only_when_there_are_any() {
        let none = counted(&report(Counts {
            applicable: 10,
            not_verified: 10,
            ..Counts::default()
        }));
        assert!(!none.iter().any(|(label, _)| label.contains("you answered")));
        let some = counted(&report(Counts {
            applicable: 10,
            not_verified: 8,
            documented: 1,
            attested: 1,
            ..Counts::default()
        }));
        assert_eq!(
            some.iter()
                .filter(|(label, _)| label.contains("you answered"))
                .count(),
            2
        );
    }

    #[test]
    fn nothing_to_do_produces_no_steps_rather_than_an_empty_instruction() {
        let r = report(Counts {
            applicable: 10,
            checked: 10,
            ..Counts::default()
        });
        assert!(next_steps(&r).is_empty(), "{:?}", next_steps(&r).len());
    }

    /// A requirement line nothing has looked at, which is what `only_a_person_can` counts.
    fn unverified(id: &str) -> crate::RequirementLine {
        crate::RequirementLine {
            id: id.into(),
            description: String::new(),
            chapter: String::new(),
            level: 1,
            status: Status::NotVerified,
            findings: Vec::new(),
            checked_by: Vec::new(),
            supported_by: Vec::new(),
            documented_by: Vec::new(),
            attested_by: Vec::new(),
        }
    }

    #[test]
    fn only_a_person_can_counts_what_no_test_would_settle() {
        let mut r = report(Counts {
            applicable: 2,
            not_verified: 2,
            ..Counts::default()
        });
        r.requirements = vec![unverified("V2.1.1"), unverified("V1.2.4")];
        r.tests_to_write = vec![crate::TestToWrite {
            id: "V1.2.4".into(),
            level: 1,
            description: String::new(),
        }];
        assert_eq!(
            only_a_person_can(&r),
            1,
            "only the one no test could settle counts"
        );
    }

    #[test]
    fn the_steps_are_in_the_order_somebody_would_do_them() {
        let mut r = report(Counts {
            applicable: 200,
            needs_attention: 2,
            not_verified: 190,
            not_assessed: 40,
            ..Counts::default()
        });
        r.requirements = vec![unverified("V2.1.1"), unverified("V1.2.4")];
        r.tests_to_write = vec![crate::TestToWrite {
            id: "V1.2.4".into(),
            level: 1,
            description: String::new(),
        }];
        let steps: Vec<String> = next_steps(&r).into_iter().map(|s| s.what).collect();
        assert!(steps[0].starts_with("Fix the 2"), "{steps:?}");
        assert!(steps[1].contains("no tool can settle"), "{steps:?}");
        assert!(steps[2].contains("Write tests"), "{steps:?}");
        assert!(steps[3].contains("securevibe.toml"), "{steps:?}");
    }

    #[test]
    fn every_step_says_where_to_go() {
        // A next step with nowhere to go is a reproach, not an instruction.
        let mut r = report(Counts {
            applicable: 200,
            needs_attention: 2,
            not_verified: 190,
            not_assessed: 40,
            ..Counts::default()
        });
        r.requirements = vec![unverified("V2.1.1")];
        r.tests_to_write = vec![crate::TestToWrite {
            id: "V1.2.4".into(),
            level: 1,
            description: String::new(),
        }];
        for step in next_steps(&r) {
            assert!(
                step.where_to_look.len() > 10,
                "{:?} says nowhere to look",
                step.what
            );
        }
    }
}
