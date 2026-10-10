//! The design questions: how the app is built, answered by the only person who knows.
//!
//! Sixteen requirements at level 1 and 2 ask for a property of the design rather than a fact in the
//! code — is validation enforced on the server, are the app's own services authenticated to each
//! other, can a load balancer's headers be faked by a browser. A scanner can sometimes see a
//! fragment of one and never the whole, so they sat in the report as *not verified* beside the
//! requirements nobody had looked at.
//!
//! The owner answers them in stackvet.toml, as `yes`, `no`, `not-sure`, or `planned`, with `where`
//! naming the file that does it.
//!
//! # Why this tier is weaker than the notes, and how much weaker
//!
//! The security notes credit requirements that ask for a *document*: writing the document is the
//! thing ASVS asks for, so writing it partly satisfies the requirement. Nothing of the kind is true
//! here. V8.3.1 asks that authorization be enforced at a trusted service layer; an owner writing
//! "yes" has not enforced anything. The answer is worth recording — it is a decision, and `where`
//! points somebody at the code — but it is **the owner's word about the app, not the app**.
//!
//! So *attested by the owner* ranks below *documented by the owner*, and two things follow that the
//! tier would be dishonest without:
//!
//! - **An attested requirement is still a test to write.** Every other tier that is not *checked*
//!   stays on that list, and this one must too: an attestation is precisely the claim a test would
//!   settle. Dropping it off the list would let an attestation quietly retire the work of proving it.
//! - **An attestation settles no threat**, for the same reason a document does not, only more so.
//!
//! # The answers that are findings
//!
//! Two of them, and they are what make this worth building rather than a way to feel better about a
//! report:
//!
//! - **`no`** — the owner has said the control is not there. That is the requirement failing, on the
//!   best authority available, and it belongs in the report as *needs attention* rather than as a
//!   silent nothing.
//! - **A `where` that names a file the app does not have** — a pointer that has gone stale, which is
//!   worse than no pointer: it reads as evidence and leads nowhere. The attestation is withheld and
//!   the staleness is reported.
//!
//! # `planned`: decided before there is code, then held to
//!
//! Since 5 October 2026 (backlog item 5 of the design-time list, the owner's decision): a decision
//! made before the code is written has no file to point to yet, and `yes` would be a claim about
//! code that does not exist. So `planned`, with `where` naming the file it will be in. It credits
//! nothing, ever; what it is worth depends on whether the app has code yet:
//!
//! - **No code yet** (the scan read no source file and no dependency manifest): it is listed as
//!   planned, not built yet. That is the honest state of a brief, and not a gap in the app.
//! - **Code, and the named file is not there**: a finding, *decided, never built*. Low, like the
//!   stale pointer it resembles, and less certain, because the work may be in another file.
//! - **Code, and the named file is there**: still nothing credited. The decision may be built now,
//!   and the answer should say so: `yes` if it is, `no` if it is not.
//! - **Code, and no `where`**: nothing to look for, so `sv` says it cannot tell whether it was built.
//!
//! # The AI coding tool's answers, one tier lower
//!
//! The tool that wrote the app knows its code better than a non-programmer owner does, so it is
//! asked these questions too (`sv mcp`). Its `yes` is the author grading its own work, so it gets
//! its own tier, *stated by the AI coding tool*, below the owner's word, with everything above
//! holding for it as well: still a test to write, no threat settled, and `no` still a finding. An
//! answer that does not say who gave it is counted as the tool's: the file is usually written by the
//! tool, and crediting the owner on nobody's say-so is the direction that overstates.
//!
//! # The owner's answers are the ones recorded through `sv review`
//!
//! Since 4 October 2026 (deep review R1, the owner's decision): `by = "owner"` is one line the AI
//! coding tool can write as easily as the owner, so an answer counts as the owner's only when
//! `sv review` recorded it and sealed it (`crate::seal`). Any other `by = "owner"` counts as the
//! tool's word, one tier down, and the report says why and how to make it the owner's.

use crate::verified::Tier;
use crate::{Confidence, Finding, Location, Severity, Verified};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

pub const YES: &str = "yes";
pub const NO: &str = "no";
pub const NOT_SURE: &str = "not-sure";
pub const PLANNED: &str = "planned";

/// The four answers, and nothing else. A typo must not read as an answer.
pub const ANSWERS: [&str; 4] = [YES, NO, NOT_SURE, PLANNED];

/// Who gave an answer, as `by` says it.
pub const OWNER: &str = "owner";
pub const AI_TOOL: &str = "ai-tool";
pub const WHO: [&str; 2] = [OWNER, AI_TOOL];

#[derive(Debug, Clone, Deserialize)]
pub struct Question {
    pub id: String,
    pub title: String,
    /// The question, in the words of somebody who is not a programmer.
    pub asks: String,
    /// What `where` should name for this question, said in the file `sv` writes.
    #[serde(rename = "whereMeans")]
    pub where_means: String,
    /// Where to go and look to answer it, for the checklist of what only a person can check.
    #[serde(rename = "howToFindOut", default)]
    pub how_to_find_out: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Questions {
    pub questions: Vec<Question>,
}

impl Questions {
    pub fn load(path: &Path) -> Result<Questions> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let questions: Questions = serde_json::from_str(&text)
            .with_context(|| sv_frameworks::data::not_understood(path))?;
        for q in &questions.questions {
            if q.asks.trim().is_empty() {
                anyhow::bail!("{}: the question for {} asks nothing", path.display(), q.id);
            }
        }
        Ok(questions)
    }

    pub fn get(&self, id: &str) -> Option<&Question> {
        self.questions.iter().find(|q| q.id == id)
    }
}

/// One answer, as stackvet.toml gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub answer: String,
    pub location: Option<String>,
    /// `owner`, `ai-tool`, or nothing, which counts as `ai-tool`.
    pub by: Option<String>,
    /// For an answer `by = "owner"`: whether `sv review` recorded it, as its seal is checked where
    /// this runs, or why not. Not read for anyone else's answer.
    pub recorded: Result<crate::seal::Sealed, String>,
}

/// What the answers came to.
#[derive(Debug, Default)]
pub struct Outcome {
    /// The owner's `yes`, with a pointer that resolves if one was given.
    pub attested: Vec<Verified>,
    /// The AI coding tool's `yes`, or one nobody said was the owner's. One tier below `attested`.
    pub stated: Vec<Verified>,
    /// `no`, and pointers that lead nowhere.
    pub findings: Vec<Finding>,
    /// Questions that apply and nobody has answered, or answered `not-sure`.
    pub unanswered: Vec<String>,
    /// Questions answered `planned` that are not a finding: none of them credits anything.
    pub planned: Vec<Planned>,
    /// An answer that is not one of the three words, or a `by` that is neither `owner` nor
    /// `ai-tool`, named so a typo cannot pass for silence or for somebody else's word.
    pub unreadable: Vec<String>,
}

/// A `planned` answer that is not a finding, and why it is not one yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    pub id: String,
    /// The file it will be in, as `where` names it.
    pub location: Option<String>,
    pub state: PlannedState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlannedState {
    /// The app has no code yet: planned, not built yet.
    NoCodeYet,
    /// The app has code and the named file is there: the answer is due to become `yes` or `no`.
    FileIsThere,
    /// The app has code and the answer names no file, so there is nothing to look for.
    NothingToLookFor,
}

/// Reads the answers against the questions that apply, and says what each one is worth.
///
/// `file_exists` is passed in rather than touching the disk here, so the judgment is testable
/// without a temporary directory, the same split the probes use. `has_code` is whether the scan
/// read any source file or dependency manifest, which decides whether a `planned` answer is still
/// a plan or a decision the code should by now hold to.
pub fn evaluate(
    questions: &Questions,
    answers: &BTreeMap<String, Answer>,
    applicable: &dyn Fn(&str) -> bool,
    file_exists: &dyn Fn(&str) -> bool,
    has_code: bool,
) -> Outcome {
    let mut out = Outcome::default();
    for question in &questions.questions {
        if !applicable(&question.id) {
            continue;
        }
        let Some(answer) = answers.get(&question.id) else {
            out.unanswered.push(question.id.clone());
            continue;
        };
        let who = match answer.by.as_deref() {
            None | Some(AI_TOOL) => Who::AiTool,
            Some(OWNER) => match &answer.recorded {
                Ok(sealed) => Who::Owner(sealed.clone()),
                Err(_) => Who::OwnerUnrecorded,
            },
            Some(_) => {
                out.unreadable.push(question.id.clone());
                continue;
            }
        };
        match answer.answer.as_str() {
            NOT_SURE => out.unanswered.push(question.id.clone()),
            NO => out.findings.push(said_no(question, &who)),
            PLANNED => {
                let state = match &answer.location {
                    _ if !has_code => PlannedState::NoCodeYet,
                    Some(path) if !file_exists(path) => {
                        out.findings.push(never_built(question, path, &who));
                        continue;
                    }
                    Some(_) => PlannedState::FileIsThere,
                    None => PlannedState::NothingToLookFor,
                };
                out.planned.push(Planned {
                    id: question.id.clone(),
                    location: answer.location.clone(),
                    state,
                });
            }
            YES => match &answer.location {
                Some(path) if !file_exists(path) => {
                    out.findings.push(stale_pointer(question, path, &who));
                }
                location => {
                    let named = match location {
                        Some(path) => format!("named {path}"),
                        None => "did not say where".to_owned(),
                    };
                    let id = [question.id.as_str()];
                    match &who {
                        Who::Owner(sealed) => out.attested.push(
                            Verified::new(
                                "design.attested",
                                &id,
                                format!(
                                    "stackvet.toml: you answered yes, and {named}{}. This is \
                                     your word about the app, not a check of it.",
                                    crate::seal::recorded_where(sealed)
                                ),
                            )
                            .resting_on(Tier::Attested),
                        ),
                        Who::OwnerUnrecorded => out.stated.push(Verified::new(
                            "design.stated-by-ai",
                            &id,
                            format!(
                                "stackvet.toml says you answered yes, and {named}, but {}, so it \
                                 counts as your AI coding tool's word, not a check of the code. If \
                                 it is your answer, run `sv review` in your own terminal to record \
                                 it as yours.",
                                answer.recorded.as_ref().err().map_or("", String::as_str)
                            ),
                        ).resting_on(Tier::Stated)),
                        Who::AiTool => out.stated.push(Verified::new(
                            "design.stated-by-ai",
                            &id,
                            format!(
                                "stackvet.toml: {} yes, and {named}. This is the word of the \
                                 tool that wrote the code, not a check of it.",
                                if answer.by.is_some() {
                                    "your AI coding tool answered"
                                } else {
                                    "the answer does not say who gave it, so it counts as your AI \
                                     coding tool's. It answered"
                                }
                            ),
                        ).resting_on(Tier::Stated)),
                    }
                }
            },
            _ => out.unreadable.push(question.id.clone()),
        }
    }
    out
}

#[derive(Clone)]
enum Who {
    /// The owner's answer, recorded through `sv review`.
    Owner(crate::seal::Sealed),
    /// `by = "owner"`, not recorded through `sv review`: counted as the tool's.
    OwnerUnrecorded,
    AiTool,
}

impl Who {
    /// The start of a sentence about the answer.
    fn answered(&self) -> &'static str {
        match self {
            Who::Owner(_) => "You answered",
            Who::OwnerUnrecorded => "stackvet.toml says you answered",
            Who::AiTool => "Your AI coding tool answered",
        }
    }
}

/// The owner, or the tool that wrote the code, says the control is not there. For a missing control
/// either is the best authority there is: nobody overstates an app by saying it lacks something.
#[track_caller]
fn said_no(question: &Question, who: &Who) -> Finding {
    crate::finding::found(Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        bundled_library: None,
        outranked: None,
        also_on_this_line: Vec::new(),
        rule_id: "design.answered-no".to_owned(),
        title: format!("{} no: {}", who.answered(), question.title.to_lowercase()),
        // The owner reporting a missing control is as certain as this gets; how bad it is depends
        // on the requirement, so the severity is the same for all of them and the requirement's own
        // words say what is at stake.
        severity: Severity::Medium,
        confidence: Confidence::High,
        location: Location {
            file: "stackvet.toml".to_owned(),
            line: 1,
        },
        secret: None,
        requirement_ids: vec![question.id.clone()],
        cwe: Vec::new(),
        description: format!(
            "In stackvet.toml {} no to this question: {}",
            match who {
                Who::OwnerUnrecorded => "the answer, given as yours, is",
                Who::Owner(_) => "you answered",
                Who::AiTool => "your AI coding tool answered",
            },
            question.asks
        ),
        impact: format!(
            "{} is one of the requirements this app is being checked against, and {} said the \
             control it asks for is not there.",
            question.id,
            match who {
                Who::Owner(_) => "you have",
                Who::OwnerUnrecorded => "stackvet.toml says you have",
                Who::AiTool => "your AI coding tool has",
            }
        ),
        fix: format!(
            "Either build the control and change the answer to yes, naming {}, or leave the answer \
             as no so the report keeps saying this is outstanding.",
            question.where_means
        ),
    })
}

/// A pointer that leads nowhere reads as evidence and is not, which is worse than none.
#[track_caller]
fn stale_pointer(question: &Question, path: &str, who: &Who) -> Finding {
    crate::finding::found(Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        bundled_library: None,
        outranked: None,
        also_on_this_line: Vec::new(),
        rule_id: "design.where-is-not-there".to_owned(),
        title: format!("`{path}` is not in this app"),
        severity: Severity::Low,
        confidence: Confidence::High,
        location: Location {
            file: "stackvet.toml".to_owned(),
            line: 1,
        },
        secret: None,
        requirement_ids: vec![question.id.clone()],
        cwe: Vec::new(),
        description: format!(
            "{} yes for {} and said the work is in `{path}`, and there is no such file in this \
             app. It may have been renamed or moved.",
            who.answered(),
            question.id
        ),
        impact: "A pointer that leads nowhere reads as evidence and is not, so this answer is not \
                 counted until it names something real."
            .to_owned(),
        fix: format!(
            "Point `where` at {}, or remove it and leave the answer as yes on its own.",
            question.where_means
        ),
    })
}

/// A decision made before the code, and the code has come without the file it was to be in.
#[track_caller]
fn never_built(question: &Question, path: &str, who: &Who) -> Finding {
    crate::finding::found(Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        bundled_library: None,
        outranked: None,
        also_on_this_line: Vec::new(),
        rule_id: "design.planned-never-built".to_owned(),
        title: format!("Decided, never built: {}", question.title.to_lowercase()),
        severity: Severity::Low,
        // The file named is not there, which is certain; that the decision was not built anywhere
        // else is not, so this is less sure than a stale pointer.
        confidence: Confidence::Medium,
        location: Location {
            file: "stackvet.toml".to_owned(),
            line: 1,
        },
        secret: None,
        requirement_ids: vec![question.id.clone()],
        cwe: Vec::new(),
        description: format!(
            "{} planned for {} and said it would be in `{path}`. The app has code now, and there is \
             no such file in it, so the decision may never have been built. The question was: {}",
            who.answered(),
            question.id,
            question.asks
        ),
        impact: format!(
            "{} is one of the requirements this app is being checked against. A decision written \
             down and never built reads as a plan being followed when it is not.",
            question.id
        ),
        fix: format!(
            "If it was built somewhere else, point `where` at {} and change the answer to yes. If \
             it was not, build it, or change the answer to no so the report keeps saying it is \
             outstanding.",
            question.where_means
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn questions() -> Questions {
        Questions {
            questions: vec![
                Question {
                    id: "V8.3.1".into(),
                    title: "Who may do what is enforced on the server".into(),
                    asks: "Are the authorization rules enforced on the server?".into(),
                    where_means: "the file where authorization is enforced".into(),
                    how_to_find_out: None,
                },
                Question {
                    id: "V2.2.2".into(),
                    title: "Input is validated on the server".into(),
                    asks: "Does the app validate input on the server as well as in the browser?"
                        .into(),
                    where_means: "the file where input validation happens".into(),
                    how_to_find_out: None,
                },
            ],
        }
    }

    fn answers(pairs: &[(&str, &str, Option<&str>)]) -> BTreeMap<String, Answer> {
        pairs
            .iter()
            .map(|(id, answer, location)| {
                (
                    (*id).to_owned(),
                    Answer {
                        answer: (*answer).to_owned(),
                        location: location.map(|l| l.to_owned()),
                        by: Some(OWNER.to_owned()),
                        recorded: Ok(crate::seal::Sealed::Here),
                    },
                )
            })
            .collect()
    }

    fn all_apply(_: &str) -> bool {
        true
    }

    fn everything_exists(_: &str) -> bool {
        true
    }

    fn nothing_exists(_: &str) -> bool {
        false
    }

    #[test]
    fn yes_is_attested_and_says_it_is_only_the_owners_word() {
        let out = evaluate(
            &questions(),
            &answers(&[("V8.3.1", YES, Some("auth.py"))]),
            &all_apply,
            &everything_exists,
            true,
        );
        assert_eq!(out.attested.len(), 1);
        assert_eq!(out.attested[0].requirement_ids, vec!["V8.3.1".to_owned()]);
        assert!(
            out.attested[0].scope.contains("your word about the app"),
            "the scope is printed beside the claim and must not read as a check: {:?}",
            out.attested[0].scope
        );
        assert!(out.findings.is_empty());
    }

    #[test]
    fn no_is_a_finding_because_the_owner_has_said_the_control_is_missing() {
        let out = evaluate(
            &questions(),
            &answers(&[("V8.3.1", NO, None)]),
            &all_apply,
            &everything_exists,
            true,
        );
        assert!(out.attested.is_empty(), "no is never evidence for it");
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule_id, "design.answered-no");
        assert_eq!(out.findings[0].requirement_ids, vec!["V8.3.1".to_owned()]);
    }

    #[test]
    fn a_pointer_to_a_file_that_is_not_there_withholds_the_attestation() {
        // The failure this catches is a rename. The answer stays yes, the file moves, and the
        // report would otherwise keep crediting a pointer that leads nowhere.
        let out = evaluate(
            &questions(),
            &answers(&[("V8.3.1", YES, Some("old/auth.py"))]),
            &all_apply,
            &nothing_exists,
            true,
        );
        assert!(
            out.attested.is_empty(),
            "a stale pointer must not be credited"
        );
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule_id, "design.where-is-not-there");
    }

    #[test]
    fn not_sure_adds_nothing_at_all() {
        // The third answer exists so that a question the owner cannot answer is not rounded down to
        // no, which would be a false finding, or up to yes, which would be a false claim.
        let out = evaluate(
            &questions(),
            &answers(&[("V8.3.1", NOT_SURE, None)]),
            &all_apply,
            &everything_exists,
            true,
        );
        assert!(out.attested.is_empty());
        assert!(out.findings.is_empty());
        // V2.2.2 is unanswered in this fixture and belongs on the list too; what matters here is
        // that an explicit "not sure" lands in the same place as saying nothing.
        assert!(out.unanswered.contains(&"V8.3.1".to_owned()), "{out:?}");
    }

    #[test]
    fn silence_and_not_sure_come_to_the_same_thing() {
        let out = evaluate(
            &questions(),
            &BTreeMap::new(),
            &all_apply,
            &everything_exists,
            true,
        );
        assert_eq!(
            out.unanswered,
            vec!["V8.3.1".to_owned(), "V2.2.2".to_owned()]
        );
        assert!(out.attested.is_empty() && out.findings.is_empty());
    }

    #[test]
    fn a_word_that_is_not_one_of_the_three_is_named_rather_than_ignored() {
        // "true", "y", "Yes " — a typo silently read as silence is a question the owner believes
        // they have answered and the report has dropped.
        let out = evaluate(
            &questions(),
            &answers(&[("V8.3.1", "true", None)]),
            &all_apply,
            &everything_exists,
            true,
        );
        assert_eq!(out.unreadable, vec!["V8.3.1".to_owned()]);
        assert!(out.attested.is_empty() && out.findings.is_empty());
        assert!(
            !out.unanswered.contains(&"V8.3.1".to_owned()),
            "an unreadable answer is its own problem, not silence"
        );
    }

    #[test]
    fn a_question_whose_requirement_does_not_apply_is_not_asked() {
        let out = evaluate(
            &questions(),
            &answers(&[("V8.3.1", YES, None), ("V2.2.2", NO, None)]),
            &|id| id == "V8.3.1",
            &everything_exists,
            true,
        );
        assert_eq!(out.attested.len(), 1);
        assert!(
            out.findings.is_empty(),
            "V2.2.2 does not apply, so answering no about it reports nothing"
        );
        assert!(out.unanswered.is_empty());
    }

    fn by(who: Option<&str>) -> BTreeMap<String, Answer> {
        let mut a = answers(&[("V8.3.1", YES, Some("auth.py"))]);
        a.get_mut("V8.3.1").unwrap().by = who.map(|w| w.to_owned());
        a
    }

    #[test]
    fn the_ai_tools_yes_is_its_own_tier_and_says_whose_word_it_is() {
        let out = evaluate(
            &questions(),
            &by(Some(AI_TOOL)),
            &all_apply,
            &everything_exists,
            true,
        );
        assert!(
            out.attested.is_empty(),
            "the tool's word is not the owner's"
        );
        assert_eq!(out.stated.len(), 1);
        assert_eq!(out.stated[0].check_id, "design.stated-by-ai");
        assert!(
            out.stated[0]
                .scope
                .contains("your AI coding tool answered yes")
                && out.stated[0].scope.contains("not a check of it"),
            "{:?}",
            out.stated[0].scope
        );
    }

    #[test]
    fn an_answer_that_does_not_say_who_gave_it_counts_as_the_ai_tools() {
        // The file is usually written by the tool. Crediting the owner on nobody's say-so is the
        // direction that overstates, so silence about who answered takes the weaker tier.
        let out = evaluate(
            &questions(),
            &by(None),
            &all_apply,
            &everything_exists,
            true,
        );
        assert!(out.attested.is_empty());
        assert_eq!(out.stated.len(), 1);
        assert!(
            out.stated[0].scope.contains("does not say who gave it"),
            "{:?}",
            out.stated[0].scope
        );
    }

    #[test]
    fn a_by_that_is_neither_owner_nor_ai_tool_is_named_rather_than_guessed() {
        let out = evaluate(
            &questions(),
            &by(Some("me")),
            &all_apply,
            &everything_exists,
            true,
        );
        assert_eq!(out.unreadable, vec!["V8.3.1".to_owned()]);
        assert!(out.attested.is_empty() && out.stated.is_empty() && out.findings.is_empty());
    }

    #[test]
    fn the_ai_tools_no_is_still_a_finding_and_says_who_said_it() {
        let mut a = answers(&[("V8.3.1", NO, None)]);
        a.get_mut("V8.3.1").unwrap().by = Some(AI_TOOL.to_owned());
        let out = evaluate(&questions(), &a, &all_apply, &everything_exists, true);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule_id, "design.answered-no");
        assert!(
            out.findings[0]
                .title
                .starts_with("Your AI coding tool answered no"),
            "{}",
            out.findings[0].title
        );
    }

    #[test]
    fn the_ai_tools_stale_pointer_is_withheld_like_the_owners() {
        let out = evaluate(
            &questions(),
            &by(Some(AI_TOOL)),
            &all_apply,
            &nothing_exists,
            true,
        );
        assert!(out.stated.is_empty() && out.attested.is_empty());
        assert_eq!(out.findings[0].rule_id, "design.where-is-not-there");
    }

    #[test]
    fn planned_before_there_is_code_is_listed_and_credits_nothing() {
        // Nothing exists, and that is right for a brief: no file is due yet.
        let out = evaluate(
            &questions(),
            &answers(&[
                ("V8.3.1", PLANNED, Some("server/auth.py")),
                ("V2.2.2", PLANNED, None),
            ]),
            &all_apply,
            &nothing_exists,
            false,
        );
        assert!(out.attested.is_empty() && out.stated.is_empty(), "{out:?}");
        assert!(
            out.findings.is_empty(),
            "no code yet is not a failure: {out:?}"
        );
        assert!(
            out.unanswered.is_empty() && out.unreadable.is_empty(),
            "{out:?}"
        );
        assert_eq!(
            out.planned,
            vec![
                Planned {
                    id: "V8.3.1".into(),
                    location: Some("server/auth.py".into()),
                    state: PlannedState::NoCodeYet,
                },
                Planned {
                    id: "V2.2.2".into(),
                    location: None,
                    state: PlannedState::NoCodeYet,
                },
            ]
        );
    }

    #[test]
    fn planned_once_there_is_code_and_no_such_file_is_decided_never_built() {
        for who in [Some(OWNER), Some(AI_TOOL), None] {
            let mut a = answers(&[("V8.3.1", PLANNED, Some("server/auth.py"))]);
            a.get_mut("V8.3.1").unwrap().by = who.map(str::to_owned);
            let out = evaluate(&questions(), &a, &all_apply, &nothing_exists, true);
            assert_eq!(out.findings.len(), 1, "{who:?}: {out:?}");
            let f = &out.findings[0];
            assert_eq!(f.rule_id, "design.planned-never-built");
            assert_eq!(f.requirement_ids, vec!["V8.3.1".to_owned()]);
            assert_eq!(f.severity, Severity::Low);
            assert!(f.title.starts_with("Decided, never built"), "{}", f.title);
            assert!(
                f.description.contains("`server/auth.py`"),
                "{}",
                f.description
            );
            assert!(out.planned.is_empty() && out.attested.is_empty() && out.stated.is_empty());
        }
    }

    #[test]
    fn planned_once_the_file_is_there_still_credits_nothing_and_asks_for_the_answer() {
        let out = evaluate(
            &questions(),
            &answers(&[("V8.3.1", PLANNED, Some("server/auth.py"))]),
            &all_apply,
            &everything_exists,
            true,
        );
        assert!(out.attested.is_empty() && out.stated.is_empty(), "{out:?}");
        assert!(out.findings.is_empty(), "{out:?}");
        assert_eq!(out.planned.len(), 1);
        assert_eq!(out.planned[0].state, PlannedState::FileIsThere);
    }

    #[test]
    fn planned_with_code_and_no_where_has_nothing_to_look_for() {
        let out = evaluate(
            &questions(),
            &answers(&[("V8.3.1", PLANNED, None)]),
            &all_apply,
            &nothing_exists,
            true,
        );
        assert!(
            out.findings.is_empty() && out.attested.is_empty(),
            "{out:?}"
        );
        assert_eq!(out.planned.len(), 1);
        assert_eq!(out.planned[0].state, PlannedState::NothingToLookFor);
    }

    #[test]
    fn planned_for_a_question_that_does_not_apply_says_nothing() {
        let out = evaluate(
            &questions(),
            &answers(&[("V2.2.2", PLANNED, Some("gone.py"))]),
            &|id| id == "V8.3.1",
            &nothing_exists,
            true,
        );
        assert!(out.findings.is_empty() && out.planned.is_empty(), "{out:?}");
    }

    #[test]
    fn the_answers_are_exactly_four_words() {
        assert_eq!(ANSWERS, [YES, NO, NOT_SURE, PLANNED]);
    }

    #[test]
    fn the_owners_answer_counts_as_theirs_only_when_sv_review_recorded_it() {
        let mut a = answers(&[("V8.3.1", YES, Some("auth.py")), ("V2.2.2", NO, None)]);
        for answer in a.values_mut() {
            answer.recorded = Err("it was not recorded through `sv review`".into());
        }
        let out = evaluate(&questions(), &a, &all_apply, &everything_exists, true);
        assert!(out.attested.is_empty(), "{out:?}");
        assert_eq!(out.stated.len(), 1);
        assert!(
            out.stated[0]
                .scope
                .contains("stackvet.toml says you answered yes")
                && out.stated[0]
                    .scope
                    .contains("not recorded through `sv review`")
                && out.stated[0].scope.contains("run `sv review`"),
            "{}",
            out.stated[0].scope
        );
        // A no is still a finding, and says whose word it rests on.
        assert_eq!(out.findings.len(), 1);
        assert!(
            out.findings[0]
                .title
                .starts_with("stackvet.toml says you answered no")
        );
    }
}
