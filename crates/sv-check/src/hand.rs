//! The checks made by hand: a person looked at the app, and says what they saw.
//!
//! Twenty ASVS requirements are left over once the security notes and the design questions have had
//! theirs (`human-checks.json`): the certificate on the live site, whether being away signs you out,
//! whether two people can book the same slot. No check here can make them, so the AI coding tool
//! walks the owner through them (`sv questions`). Until 26 September 2026 what the owner saw was then
//! lost. It is now recorded in the `[checked-by-hand]` section of securevibe.toml, as the owner agreed
//! the same day:
//!
//! ```toml
//! [checked-by-hand]
//! "V12.2.2" = { result = "done", on = "2026-09-26", by = "owner",
//!               how = "Opened the live site; the padlock shows a trusted certificate." }
//! ```
//!
//! # What an answer is worth
//!
//! - **`done` by the owner** is *checked by hand by the owner*: its own tier, just above *attested*,
//!   because the owner watched the app behave rather than describing how it is built, and never
//!   *checked*, which means an automated check looked. It is still the owner's word, which `sv` cannot
//!   repeat, so it stays a test to write where a test could show it and settles no threat.
//! - **`done` by the AI coding tool**, or by nobody named, is *stated by the AI coding tool*, as for
//!   the design questions.
//! - **`problem`** is a finding, from either. Reporting a failure never overstates the app.
//! - **`not-yet`** adds nothing, like `not-sure`.
//!
//! # What keeps it honest
//!
//! - **`how` is required.** One sentence of what was done and seen is the whole of the evidence, and
//!   the report prints it; a bare `done` is reported as unreadable, not counted.
//! - **`on` is required, and a check goes out of date** after [`CURRENT_FOR_DAYS`]. Certificates
//!   expire and apps change; a check older than that is reported as needing to be made again and
//!   counts for nothing. A date in the future is unreadable.
//! - **Only the checks in the list are read.** An id that is not a check by hand is named as
//!   unreadable rather than quietly ignored or quietly credited.

use crate::advisories::Day;
use crate::human::HumanChecks;
use crate::{Confidence, Finding, Location, Severity, Verified};
use std::collections::BTreeMap;

pub const DONE: &str = "done";
pub const PROBLEM: &str = "problem";
pub const NOT_YET: &str = "not-yet";
pub const RESULTS: [&str; 3] = [DONE, PROBLEM, NOT_YET];

/// How long a check made by hand counts for. One number for all of them, at the owner's choice.
pub const CURRENT_FOR_DAYS: u32 = 90;

/// One check, as securevibe.toml gives it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Answer {
    pub result: String,
    pub on: Option<String>,
    pub by: Option<String>,
    pub how: Option<String>,
}

/// What the checks came to.
#[derive(Debug, Default)]
pub struct Outcome {
    /// The owner's `done`, current, with what they saw.
    pub by_owner: Vec<Verified>,
    /// The AI coding tool's `done`, or one nobody said was the owner's.
    pub stated: Vec<Verified>,
    /// `problem`, from anyone.
    pub findings: Vec<Finding>,
    /// A `done` older than [`CURRENT_FOR_DAYS`]: the id and the day it was made.
    pub out_of_date: Vec<(String, String)>,
    /// Answers that cannot be read, each with why: a word that is not one of the three, a missing
    /// `how` or `on`, a date that is not one or is in the future, a `by` that is neither word, or an
    /// id that is not a check by hand.
    pub unreadable: Vec<(String, String)>,
}

/// Reads the checks against the list, for the requirements that apply, as of `today`.
pub fn evaluate(
    checks: &HumanChecks,
    answers: &BTreeMap<String, Answer>,
    applicable: &dyn Fn(&str) -> bool,
    today: Day,
) -> Outcome {
    let mut out = Outcome::default();
    for (id, answer) in answers {
        let Some(check) = checks.checks.iter().find(|c| &c.id == id) else {
            out.unreadable.push((
                id.clone(),
                "it is not one of the checks made by hand, so there is nothing to record it \
                 against"
                    .to_owned(),
            ));
            continue;
        };
        if !applicable(id) {
            continue;
        }
        let by_owner = match answer.by.as_deref() {
            None | Some(crate::design::AI_TOOL) => false,
            Some(crate::design::OWNER) => true,
            Some(other) => {
                out.unreadable.push((
                    id.clone(),
                    format!("`by` is \"{other}\", not owner or ai-tool"),
                ));
                continue;
            }
        };
        match answer.result.as_str() {
            NOT_YET => continue,
            DONE | PROBLEM => {}
            other => {
                out.unreadable.push((
                    id.clone(),
                    format!("`result` is \"{other}\", not done, problem, or not-yet"),
                ));
                continue;
            }
        }
        let Some(how) = answer
            .how
            .as_deref()
            .map(str::trim)
            .filter(|h| !h.is_empty())
        else {
            out.unreadable.push((
                id.clone(),
                "it has no `how`: what was done and what was seen is the evidence".to_owned(),
            ));
            continue;
        };
        let Some(on) = answer
            .on
            .as_deref()
            .filter(|d| d.len() == 10)
            .and_then(Day::parse)
        else {
            out.unreadable.push((
                id.clone(),
                "it has no `on` date written as YYYY-MM-DD".to_owned(),
            ));
            continue;
        };
        if on > today {
            out.unreadable.push((
                id.clone(),
                format!("`on` is {}, which has not happened yet", on.show()),
            ));
            continue;
        }
        let who = if by_owner {
            "you"
        } else if answer.by.is_some() {
            "your AI coding tool"
        } else {
            "somebody who is not named, so it counts as your AI coding tool"
        };
        if answer.result == PROBLEM {
            out.findings.push(problem(check, how, on, who));
            continue;
        }
        if on.plus(CURRENT_FOR_DAYS) < today {
            out.out_of_date.push((id.clone(), on.show()));
            continue;
        }
        let scope = format!(
            "securevibe.toml: checked by hand by {who} on {}: \"{how}\" Nothing here repeated it.",
            on.show()
        );
        if by_owner {
            out.by_owner
                .push(Verified::new("hand.checked", &[id.as_str()], scope));
        } else {
            out.stated
                .push(Verified::new("hand.stated-by-ai", &[id.as_str()], scope));
        }
    }
    out
}

/// Somebody checked and it failed. A failure reported never overstates the app, whoever saw it.
fn problem(check: &crate::human::HumanCheck, how: &str, on: Day, who: &str) -> Finding {
    Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        rule_id: "hand.problem".to_owned(),
        title: format!(
            "Checked by hand, and it failed: {}",
            check.title.to_lowercase()
        ),
        severity: Severity::Medium,
        confidence: Confidence::High,
        location: Location {
            file: "securevibe.toml".to_owned(),
            line: 1,
        },
        secret: None,
        requirement_ids: vec![check.id.clone()],
        cwe: Vec::new(),
        description: format!(
            "Checked by hand by {who} on {}, and recorded as a problem: \"{how}\"",
            on.show()
        ),
        impact: format!(
            "{} is one of the requirements this app is being checked against, and the check made \
             by hand found it does not hold.",
            check.id
        ),
        fix: format!(
            "Fix what the check found, make the check again, and record it as done with what you \
             saw. How to check: {}",
            check.how.split_whitespace().collect::<Vec<_>>().join(" ")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::human::HumanCheck;

    fn checks() -> HumanChecks {
        HumanChecks {
            checks: vec![HumanCheck {
                id: "V12.2.2".into(),
                title: "The certificate on the live site is one browsers trust".into(),
                how: "Open the live site and click the padlock.".into(),
            }],
        }
    }

    fn today() -> Day {
        Day::parse("2026-09-26").unwrap()
    }

    fn answer(result: &str, on: Option<&str>, by: Option<&str>, how: Option<&str>) -> Answer {
        Answer {
            result: result.into(),
            on: on.map(Into::into),
            by: by.map(Into::into),
            how: how.map(Into::into),
        }
    }

    fn run(a: Answer) -> Outcome {
        evaluate(
            &checks(),
            &BTreeMap::from([("V12.2.2".to_owned(), a)]),
            &|_| true,
            today(),
        )
    }

    const SAW: &str = "Padlock shows Let's Encrypt, valid to December, name matches.";

    #[test]
    fn the_owners_done_is_recorded_with_what_they_saw() {
        let out = run(answer(DONE, Some("2026-09-20"), Some("owner"), Some(SAW)));
        assert_eq!(out.by_owner.len(), 1, "{out:?}");
        assert!(out.stated.is_empty() && out.findings.is_empty());
        let scope = &out.by_owner[0].scope;
        assert!(
            scope.contains(SAW) && scope.contains("2026-09-20"),
            "{scope}"
        );
        assert!(scope.contains("Nothing here repeated it"), "{scope}");
    }

    #[test]
    fn the_tools_done_or_nobodys_is_the_weaker_tier() {
        for by in [Some("ai-tool"), None] {
            let out = run(answer(DONE, Some("2026-09-20"), by, Some(SAW)));
            assert!(out.by_owner.is_empty(), "{by:?} is not the owner");
            assert_eq!(out.stated.len(), 1, "{by:?}: {out:?}");
            assert_eq!(out.stated[0].check_id, "hand.stated-by-ai");
        }
    }

    #[test]
    fn a_problem_is_a_finding_whoever_saw_it() {
        for by in [Some("owner"), Some("ai-tool"), None] {
            let out = run(answer(
                PROBLEM,
                Some("2026-09-20"),
                by,
                Some("Browser warns."),
            ));
            assert_eq!(out.findings.len(), 1, "{by:?}");
            assert_eq!(out.findings[0].rule_id, "hand.problem");
            assert!(out.by_owner.is_empty() && out.stated.is_empty());
        }
    }

    #[test]
    fn a_done_without_how_is_unreadable_not_counted() {
        for how in [None, Some("  ")] {
            let out = run(answer(DONE, Some("2026-09-20"), Some("owner"), how));
            assert!(out.by_owner.is_empty(), "a bare done must not count");
            assert_eq!(out.unreadable.len(), 1, "{how:?}: {out:?}");
        }
    }

    #[test]
    fn a_done_without_a_readable_date_is_unreadable() {
        for on in [
            None,
            Some("last week"),
            Some("2026-9-20"),
            Some("2026-09-20T10:00"),
        ] {
            let out = run(answer(DONE, on, Some("owner"), Some(SAW)));
            assert!(out.by_owner.is_empty(), "{on:?} counted");
            assert_eq!(out.unreadable.len(), 1, "{on:?}");
        }
    }

    #[test]
    fn a_date_in_the_future_is_unreadable() {
        let out = run(answer(DONE, Some("2026-10-01"), Some("owner"), Some(SAW)));
        assert!(out.by_owner.is_empty());
        assert_eq!(out.unreadable.len(), 1);
    }

    #[test]
    fn a_check_goes_out_of_date_after_ninety_days_and_not_before() {
        // 2026-06-28 is exactly 90 days before 2026-09-26: still current. One day earlier is not.
        let current = run(answer(DONE, Some("2026-06-28"), Some("owner"), Some(SAW)));
        assert_eq!(current.by_owner.len(), 1, "{current:?}");
        let stale = run(answer(DONE, Some("2026-06-27"), Some("owner"), Some(SAW)));
        assert!(stale.by_owner.is_empty(), "an old check must not count");
        assert_eq!(
            stale.out_of_date,
            vec![("V12.2.2".to_owned(), "2026-06-27".to_owned())]
        );
    }

    #[test]
    fn not_yet_adds_nothing() {
        let out = run(answer(NOT_YET, None, None, None));
        assert!(out.by_owner.is_empty() && out.stated.is_empty() && out.findings.is_empty());
        assert!(out.unreadable.is_empty() && out.out_of_date.is_empty());
    }

    #[test]
    fn a_word_that_is_not_a_result_or_a_who_is_named() {
        let out = run(answer("yes", Some("2026-09-20"), Some("owner"), Some(SAW)));
        assert_eq!(out.unreadable.len(), 1);
        let out = run(answer(DONE, Some("2026-09-20"), Some("me"), Some(SAW)));
        assert_eq!(out.unreadable.len(), 1);
        assert!(out.by_owner.is_empty() && out.stated.is_empty());
    }

    #[test]
    fn an_id_that_is_not_a_check_by_hand_is_named_not_credited() {
        let out = evaluate(
            &checks(),
            &BTreeMap::from([(
                "V8.3.1".to_owned(),
                answer(DONE, Some("2026-09-20"), Some("owner"), Some(SAW)),
            )]),
            &|_| true,
            today(),
        );
        assert!(out.by_owner.is_empty());
        assert_eq!(out.unreadable.len(), 1);
        assert_eq!(out.unreadable[0].0, "V8.3.1");
    }

    #[test]
    fn a_check_whose_requirement_does_not_apply_is_not_read() {
        let out = evaluate(
            &checks(),
            &BTreeMap::from([(
                "V12.2.2".to_owned(),
                answer(PROBLEM, Some("2026-09-20"), Some("owner"), Some(SAW)),
            )]),
            &|_| false,
            today(),
        );
        assert!(out.findings.is_empty() && out.unreadable.is_empty());
    }
}
