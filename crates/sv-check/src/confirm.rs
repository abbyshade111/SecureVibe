//! A person confirming what the AI coding tool said, so it counts for as much as their own word.
//!
//! Asked for by the owner on 27 September 2026, after the interview in VS Code: when the owner does
//! not know an answer, the tool answers from the code and the report calls it *stated by the AI
//! coding tool*, the weakest tier that counts for anything. The owner's only way up was to write
//! `by = "owner"`, which would say something untrue: they did not give the answer, they checked
//! somebody else's. So there was nowhere honest to record a careful owner who looked.
//!
//! A confirmation sits beside the tool's answer, so the report still says who said it first:
//!
//! ```toml
//! "V8.3.1" = { answer = "yes", where = "src/app.js", by = "ai-tool",
//!              confirmed = { by = "owner", on = "2026-09-27", answer = "yes", where = "src/app.js",
//!                            how = "Sent a POST to the site and got 405; only GET and HEAD work." } }
//! ```
//!
//! # What it is worth (the owner's decisions, 27 September 2026)
//!
//! - **Level with the owner's own record of the same kind**: a confirmed design answer ranks with
//!   *attested by the owner*, a confirmed check made by hand with *checked by hand by the owner*.
//!   Once a person has looked and put their name to it, it is their word, and a sentence of what
//!   they saw is at least as good as a bare yes. It is shown as confirmed, never as theirs.
//! - **The owner or anyone named may confirm**, at the same rank, the name printed. `sv` cannot
//!   tell who anyone is, so a named reviewer does not outrank the owner; the reader judges.
//! - **Never *checked***: it stays on the tests to write and settles no threat, as the tiers it
//!   joins do.
//!
//! # What keeps it honest
//!
//! A confirmation that fails any of these does not count, and the report says which and why; the
//! tool's answer is then worth what it was before, *stated by the AI coding tool*.
//!
//! - **`how` is required**: what the person looked at or tried, and saw. A bare confirmation is
//!   rubber-stamping, and the report prints the sentence so a reader can judge it.
//! - **`on` is required, and it lasts 90 days**, like a check made by hand.
//! - **It names the answer it confirmed** (`answer` and `where` for a design answer, `result` for a
//!   check made by hand), so an answer changed afterwards is not carried by a confirmation of the
//!   old one.
//! - **The file it points at must not have changed since.** A design answer's `where` file modified
//!   after the day of the confirmation ends it: the person confirmed that code, not whatever it says
//!   now. Judged by the file's modification date, so a fresh copy of the project, whose files all
//!   look new, asks again, which is the safe direction.
//! - **The AI coding tool cannot confirm its own answer.**
//!
//! Disagreeing needs nothing new: the owner answers the question themselves (`by = "owner"`, `no`),
//! or records the check made by hand as a `problem`, and either is a finding.

use crate::Verified;
use crate::advisories::Day;
use crate::seal::{Checker, Sealed};

/// How long a confirmation counts, the same as a check made by hand.
pub const CURRENT_FOR_DAYS: u32 = crate::hand::CURRENT_FOR_DAYS;

/// The check ids a confirmation is credited under, one per tier it joins.
pub const DESIGN_CONFIRMED: &str = "design.confirmed";
pub const HAND_CONFIRMED: &str = "hand.confirmed";

/// A confirmation, as securevibe.toml gives it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Confirmation {
    pub by: Option<String>,
    pub on: Option<String>,
    pub how: Option<String>,
    /// The design answer confirmed: `yes`, `no`, `not-sure`, or `planned`.
    pub answer: Option<String>,
    /// The design answer's `where`, as it was when confirmed.
    pub location: Option<String>,
    /// The check made by hand's `result` confirmed.
    pub result: Option<String>,
    /// What `sv review` wrote when a person recorded it (`crate::seal`).
    pub seal: Option<String>,
}

impl Confirmation {
    /// The fields its seal is made over, for the requirement it is about, under `check_id`.
    pub fn sealed_fields(&self, check_id: &str, requirement: &str) -> Vec<String> {
        crate::seal::confirmation_fields(
            section_of(check_id),
            requirement,
            [
                self.by.as_deref(),
                self.on.as_deref(),
                self.how.as_deref(),
                self.answer.as_deref(),
                self.location.as_deref(),
                self.result.as_deref(),
            ],
        )
    }
}

/// The part of securevibe.toml a confirmation credited under `check_id` sits in.
pub fn section_of(check_id: &str) -> &'static str {
    if check_id == HAND_CONFIRMED {
        "checked-by-hand"
    } else {
        "design"
    }
}

/// What the confirmation is of, as the manifest says it now.
pub enum Current<'a> {
    Design {
        answer: &'a str,
        location: Option<&'a str>,
        /// The day `location` was last changed, if it names a file that could be read.
        modified: Option<Day>,
    },
    Hand {
        result: &'a str,
    },
}

/// A confirmation that holds, and what the report says about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holds {
    /// "you" for the owner, otherwise the name as written.
    pub who: String,
    pub on: Day,
    pub how: String,
}

/// Judges one confirmation. `Err` says, in words for the owner, why it does not count.
pub fn judge(confirmation: &Confirmation, current: &Current, today: Day) -> Result<Holds, String> {
    let by = confirmation
        .by
        .as_deref()
        .map(str::trim)
        .filter(|b| !b.is_empty())
        .ok_or("it does not say who confirmed it (`by`)")?;
    if by.eq_ignore_ascii_case(crate::design::AI_TOOL) || by.eq_ignore_ascii_case("AI coding tool")
    {
        return Err("the AI coding tool cannot confirm its own answer".to_owned());
    }
    let how = confirmation
        .how
        .as_deref()
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .ok_or("it has no `how`: what was looked at and seen is the whole of the evidence")?;
    let on = confirmation
        .on
        .as_deref()
        .filter(|d| d.len() == 10)
        .and_then(Day::parse)
        .ok_or("it has no `on` date written as YYYY-MM-DD")?;
    if on > today {
        return Err(format!("`on` is {}, which has not happened yet", on.show()));
    }
    match current {
        Current::Design {
            answer,
            location,
            modified,
        } => {
            let confirmed = confirmation
                .answer
                .as_deref()
                .ok_or("it does not say which answer it confirms (`answer`)")?;
            if confirmed != *answer {
                return Err(format!(
                    "it confirms the answer {confirmed}, and the answer is now {answer}"
                ));
            }
            if confirmation.location.as_deref() != *location {
                return Err(format!(
                    "it confirms {}, and the answer now points at {}",
                    confirmation.location.as_deref().unwrap_or("no file"),
                    location.unwrap_or("no file")
                ));
            }
            if let (Some(path), Some(changed)) = (location, modified)
                && *changed > on
            {
                return Err(format!(
                    "{path} changed on {}, after it was confirmed on {}",
                    changed.show(),
                    on.show()
                ));
            }
        }
        Current::Hand { result } => {
            let confirmed = confirmation
                .result
                .as_deref()
                .ok_or("it does not say which result it confirms (`result`)")?;
            if confirmed != *result {
                return Err(format!(
                    "it confirms the result {confirmed}, and the result is now {result}"
                ));
            }
        }
    }
    if on.plus(CURRENT_FOR_DAYS) < today {
        return Err(format!(
            "it was confirmed on {}, more than {CURRENT_FOR_DAYS} days ago",
            on.show()
        ));
    }
    let who = if by.eq_ignore_ascii_case(crate::design::OWNER) {
        "you".to_owned()
    } else {
        by.to_owned()
    };
    Ok(Holds {
        who,
        on,
        how: how.to_owned(),
    })
}

/// The confirmed version of a piece of *stated* evidence: the tool's words, then the person's, and
/// whether `sv review`'s seal on it was checked here.
pub fn credit(stated: &Verified, check_id: &str, holds: &Holds, sealed: &Sealed) -> Verified {
    Verified::new(
        check_id,
        &stated
            .requirement_ids
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        match sealed {
            Sealed::Here => format!(
                "{} Recorded through `sv review` on this computer: {} confirmed it on {}, having \
                 looked: \"{}\"",
                stated.scope.trim_end(),
                holds.who,
                holds.on.show(),
                holds.how
            ),
            Sealed::Signed { key, from } => format!(
                "{} Recorded through `sv review` and signed with key {key}, which {} trusts for \
                 this app: {} confirmed it on {}, having looked: \"{}\"",
                stated.scope.trim_end(),
                from.named(),
                holds.who,
                holds.on.show(),
                holds.how
            ),
        },
    )
}

/// What confirming came to, for one kind of record.
#[derive(Debug, Default)]
pub struct Outcome {
    /// Evidence moved up a tier, under `DESIGN_CONFIRMED` or `HAND_CONFIRMED`.
    pub confirmed: Vec<Verified>,
    /// Requirement id and, in words, why its confirmation does not count.
    pub not_counted: Vec<(String, String)>,
}

/// Goes through the *stated* evidence and moves each item whose confirmation holds up a tier.
///
/// `confirmation_of` gives, for a requirement, its confirmation and what it is of now; items it
/// says nothing about stay as they are. What is moved leaves `stated`, so nothing is counted twice.
pub fn apply<'a>(
    stated: &mut Vec<Verified>,
    check_id: &str,
    confirmation_of: &dyn Fn(&str) -> Option<(&'a Confirmation, Current<'a>)>,
    today: Day,
    seals: &Checker,
) -> Outcome {
    let mut out = Outcome::default();
    stated.retain(|item| {
        let Some(id) = item.requirement_ids.first() else {
            return true;
        };
        let Some((confirmation, current)) = confirmation_of(id) else {
            return true;
        };
        let fields = confirmation.sealed_fields(check_id, id);
        match judge(confirmation, &current, today).and_then(|holds| {
            let sealed = seals
                .check(confirmation.seal.as_deref(), &crate::seal::as_strs(&fields))
                .map_err(|why| {
                    format!(
                        "{why}. If you have looked for yourself, run `sv review` in your own \
                         terminal to record it as yours"
                    )
                })?;
            Ok((holds, sealed))
        }) {
            Ok((holds, sealed)) => {
                out.confirmed.push(credit(item, check_id, &holds, &sealed));
                false
            }
            Err(why) => {
                out.not_counted.push((id.clone(), why));
                true
            }
        }
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(text: &str) -> Day {
        Day::parse(text).unwrap()
    }

    fn confirmed(by: &str, on: &str, how: &str) -> Confirmation {
        Confirmation {
            by: Some(by.into()),
            on: Some(on.into()),
            how: Some(how.into()),
            answer: Some("yes".into()),
            location: Some("src/app.js".into()),
            result: None,
            seal: None,
        }
    }

    /// This computer's key in these tests, from the system's randomness.
    /// This computer's key in the test, sealing for the app the test reads.
    fn key() -> crate::seal::AppKey {
        computer_key().for_app(&crate::seal::App::named_for_tests("app"))
    }

    fn computer_key() -> crate::seal::Key {
        static KEY: std::sync::OnceLock<crate::seal::Key> = std::sync::OnceLock::new();
        KEY.get_or_init(|| crate::seal::Key::random().unwrap())
            .clone()
    }

    /// The confirmation as `sv review` would have sealed it on the computer `key` belongs to.
    fn sealed(mut c: Confirmation, check_id: &str, requirement: &str) -> Confirmation {
        let fields = c.sealed_fields(check_id, requirement);
        c.seal = Some(key().seal(&crate::seal::as_strs(&fields)));
        c
    }

    fn design(modified: Option<&str>) -> Current<'static> {
        Current::Design {
            answer: "yes",
            location: Some("src/app.js"),
            modified: modified.map(day),
        }
    }

    const HOW: &str = "Sent a POST to the site and got 405; only GET and HEAD work.";
    const TODAY: &str = "2026-09-27";

    #[test]
    fn a_confirmation_with_what_was_seen_holds() {
        let holds = judge(
            &confirmed("owner", "2026-09-27", HOW),
            &design(Some("2026-09-20")),
            day(TODAY),
        )
        .unwrap();
        assert_eq!(holds.who, "you");
        assert_eq!(holds.how, HOW);
    }

    #[test]
    fn a_named_reviewer_is_named() {
        let holds = judge(
            &confirmed("Sam Lee, security consultant", "2026-09-27", HOW),
            &design(None),
            day(TODAY),
        )
        .unwrap();
        assert_eq!(holds.who, "Sam Lee, security consultant");
    }

    #[test]
    fn each_thing_that_makes_it_not_count_is_said() {
        let base = confirmed("owner", "2026-09-27", HOW);
        let cases: Vec<(Confirmation, Current, &str)> = vec![
            (
                Confirmation {
                    by: None,
                    ..base.clone()
                },
                design(None),
                "who confirmed",
            ),
            (
                Confirmation {
                    by: Some("ai-tool".into()),
                    ..base.clone()
                },
                design(None),
                "cannot confirm its own",
            ),
            (
                Confirmation {
                    by: Some("AI coding tool".into()),
                    ..base.clone()
                },
                design(None),
                "cannot confirm its own",
            ),
            (
                Confirmation {
                    how: Some("  ".into()),
                    ..base.clone()
                },
                design(None),
                "no `how`",
            ),
            (
                Confirmation {
                    on: Some("27 Sep".into()),
                    ..base.clone()
                },
                design(None),
                "YYYY-MM-DD",
            ),
            (
                Confirmation {
                    on: Some("2026-10-01".into()),
                    ..base.clone()
                },
                design(None),
                "has not happened yet",
            ),
            (
                Confirmation {
                    answer: None,
                    ..base.clone()
                },
                design(None),
                "which answer",
            ),
            (
                Confirmation {
                    answer: Some("not-sure".into()),
                    ..base.clone()
                },
                design(None),
                "the answer is now yes",
            ),
            (
                Confirmation {
                    location: Some("src/old.js".into()),
                    ..base.clone()
                },
                design(None),
                "now points at src/app.js",
            ),
            (base.clone(), design(Some("2026-09-28")), "changed on"),
            (
                Confirmation {
                    on: Some("2026-06-01".into()),
                    ..base.clone()
                },
                design(None),
                "more than 90 days ago",
            ),
            (
                base.clone(),
                Current::Hand { result: "done" },
                "which result",
            ),
            (
                Confirmation {
                    result: Some("problem".into()),
                    ..base.clone()
                },
                Current::Hand { result: "done" },
                "the result is now done",
            ),
        ];
        for (confirmation, current, says) in cases {
            let why = judge(&confirmation, &current, day("2026-09-30")).unwrap_err();
            assert!(why.contains(says), "{confirmation:?}: {why}");
        }
    }

    #[test]
    fn a_file_changed_the_same_day_or_before_is_the_code_that_was_confirmed() {
        for modified in ["2026-09-27", "2026-01-01"] {
            assert!(
                judge(
                    &confirmed("owner", "2026-09-27", HOW),
                    &design(Some(modified)),
                    day(TODAY),
                )
                .is_ok(),
                "{modified}"
            );
        }
    }

    #[test]
    fn apply_moves_what_holds_and_leaves_the_rest_stated() {
        let mut stated =
            vec![
            Verified::new(
                "design.stated-by-ai",
                &["V8.3.1"],
                "securevibe.toml: your AI coding tool answered yes. This is the word of the tool."
                    .to_owned(),
            ),
            Verified::new("design.stated-by-ai", &["V2.2.2"], "the tool's word".to_owned()),
            Verified::new("design.stated-by-ai", &["V1.1.1"], "the tool's word".to_owned()),
        ];
        let good = sealed(
            confirmed("owner", "2026-09-27", HOW),
            DESIGN_CONFIRMED,
            "V8.3.1",
        );
        let stale = sealed(
            Confirmation {
                answer: Some("no".into()),
                ..confirmed("owner", "2026-09-27", HOW)
            },
            DESIGN_CONFIRMED,
            "V2.2.2",
        );
        // Sealed for V8.3.1, then copied to V1.1.1: the seal names the requirement, so it fails.
        let moved = good.clone();
        let out = apply(
            &mut stated,
            DESIGN_CONFIRMED,
            &|id| match id {
                "V8.3.1" => Some((&good, design(None))),
                "V2.2.2" => Some((&stale, design(None))),
                "V1.1.1" => Some((&moved, design(None))),
                _ => None,
            },
            day(TODAY),
            &Checker::key(key()),
        );
        assert_eq!(out.confirmed.len(), 1);
        assert_eq!(out.confirmed[0].check_id, DESIGN_CONFIRMED);
        assert_eq!(out.confirmed[0].requirement_ids, vec!["V8.3.1".to_owned()]);
        assert!(
            out.confirmed[0]
                .scope
                .contains("your AI coding tool answered yes")
                && out.confirmed[0].scope.contains(
                    "Recorded through `sv review` on this computer: you confirmed it on 2026-09-27"
                )
                && out.confirmed[0].scope.contains(HOW),
            "the tool's word first, then the person's: {}",
            out.confirmed[0].scope
        );
        let left: Vec<&str> = stated
            .iter()
            .map(|v| v.requirement_ids[0].as_str())
            .collect();
        assert_eq!(
            left,
            ["V2.2.2", "V1.1.1"],
            "what moved is not counted twice"
        );
        assert_eq!(out.not_counted.len(), 2);
        assert_eq!(out.not_counted[0].0, "V2.2.2");
        assert_eq!(out.not_counted[1].0, "V1.1.1");
        assert!(
            out.not_counted[1].1.contains("does not match"),
            "{:?}",
            out.not_counted
        );
    }

    #[test]
    fn a_confirmation_counts_only_as_sv_review_sealed_it() {
        let stated = || {
            vec![Verified::new(
                "design.stated-by-ai",
                &["V8.3.1"],
                "the tool's word".to_owned(),
            )]
        };
        let run = |c: &Confirmation, seals: &Checker| {
            let mut s = stated();
            apply(
                &mut s,
                DESIGN_CONFIRMED,
                &|_| Some((c, design(None))),
                day(TODAY),
                seals,
            )
        };
        let plain = confirmed("owner", "2026-09-27", HOW);
        let good = sealed(plain.clone(), DESIGN_CONFIRMED, "V8.3.1");
        // Sealed as a check made by hand, then moved under [design]: it fails.
        let other_section = sealed(plain.clone(), HAND_CONFIRMED, "V8.3.1");
        let here = Checker::key(key());
        assert_eq!(run(&good, &here).confirmed.len(), 1);
        for (c, says) in [
            (&plain, "not recorded through `sv review`"),
            (&other_section, "does not match"),
        ] {
            let out = run(c, &here);
            assert!(out.confirmed.is_empty(), "{says}");
            assert!(out.not_counted[0].1.contains(says), "{:?}", out.not_counted);
        }
        let app = crate::seal::App::named_for_tests("app");
        let elsewhere = run(
            &good,
            &Checker::key(crate::seal::Key::random().unwrap().for_app(&app)),
        );
        assert!(elsewhere.confirmed.is_empty());
        // No key here: it does not count, and says why and what to do (item 8 of the review of 1
        // to 4 October).
        let unchecked = run(&good, &Checker::no_key());
        assert!(unchecked.confirmed.is_empty());
        assert!(
            unchecked.not_counted[0].1.contains("cannot check"),
            "{:?}",
            unchecked.not_counted
        );
        // Nor in another app on this computer (item 11).
        let shop = crate::seal::App::named_for_tests("shop");
        let copied = run(&good, &Checker::key(computer_key().for_app(&shop)));
        assert!(copied.confirmed.is_empty());
        assert!(
            copied.not_counted[0].1.contains("another folder"),
            "{:?}",
            copied.not_counted
        );
        assert!(run(&plain, &Checker::no_key()).confirmed.is_empty());
    }
}
