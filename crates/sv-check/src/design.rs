//! The design questions: how the app is built, answered by the only person who knows.
//!
//! Sixteen requirements at level 1 and 2 ask for a property of the design rather than a fact in the
//! code — is validation enforced on the server, are the app's own services authenticated to each
//! other, can a load balancer's headers be faked by a browser. A scanner can sometimes see a
//! fragment of one and never the whole, so they sat in the report as *not verified* beside the
//! requirements nobody had looked at.
//!
//! The owner answers them in securevibe.toml, as `yes`, `no`, or `not-sure`, with `where` naming the
//! file that does it.
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
//! # The AI coding tool's answers, one tier lower
//!
//! The tool that wrote the app knows its code better than a non-programmer owner does, so it is
//! asked these questions too (`sv mcp`). Its `yes` is the author grading its own work, so it gets
//! its own tier, *stated by the AI coding tool*, below the owner's word, with everything above
//! holding for it as well: still a test to write, no threat settled, and `no` still a finding. An
//! answer that does not say who gave it is counted as the tool's: the file is usually written by the
//! tool, and crediting the owner on nobody's say-so is the direction that overstates.

use crate::{Confidence, Finding, Location, Severity, Verified};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

pub const YES: &str = "yes";
pub const NO: &str = "no";
pub const NOT_SURE: &str = "not-sure";

/// The three answers, and nothing else. A typo must not read as an answer.
pub const ANSWERS: [&str; 3] = [YES, NO, NOT_SURE];

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
        let questions: Questions =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
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

/// One answer, as securevibe.toml gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub answer: String,
    pub location: Option<String>,
    /// `owner`, `ai-tool`, or nothing, which counts as `ai-tool`.
    pub by: Option<String>,
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
    /// An answer that is not one of the three words, or a `by` that is neither `owner` nor
    /// `ai-tool`, named so a typo cannot pass for silence or for somebody else's word.
    pub unreadable: Vec<String>,
}

/// Reads the answers against the questions that apply, and says what each one is worth.
///
/// `file_exists` is passed in rather than touching the disk here, so the judgment is testable
/// without a temporary directory, the same split the probes use.
pub fn evaluate(
    questions: &Questions,
    answers: &BTreeMap<String, Answer>,
    applicable: &dyn Fn(&str) -> bool,
    file_exists: &dyn Fn(&str) -> bool,
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
            Some(OWNER) => Who::Owner,
            Some(_) => {
                out.unreadable.push(question.id.clone());
                continue;
            }
        };
        match answer.answer.as_str() {
            NOT_SURE => out.unanswered.push(question.id.clone()),
            NO => out.findings.push(said_no(question, who)),
            YES => match &answer.location {
                Some(path) if !file_exists(path) => {
                    out.findings.push(stale_pointer(question, path, who));
                }
                location => {
                    let named = match location {
                        Some(path) => format!("named {path}"),
                        None => "did not say where".to_owned(),
                    };
                    let id = [question.id.as_str()];
                    match who {
                        Who::Owner => out.attested.push(Verified::new(
                            "design.attested",
                            &id,
                            format!(
                                "securevibe.toml: you answered yes, and {named}. This is your word \
                                 about the app, not a check of it."
                            ),
                        )),
                        Who::AiTool => out.stated.push(Verified::new(
                            "design.stated-by-ai",
                            &id,
                            format!(
                                "securevibe.toml: {} yes, and {named}. This is the word of the \
                                 tool that wrote the code, not a check of it.",
                                if answer.by.is_some() {
                                    "your AI coding tool answered"
                                } else {
                                    "the answer does not say who gave it, so it counts as your AI \
                                     coding tool's. It answered"
                                }
                            ),
                        )),
                    }
                }
            },
            _ => out.unreadable.push(question.id.clone()),
        }
    }
    out
}

#[derive(Clone, Copy)]
enum Who {
    Owner,
    AiTool,
}

impl Who {
    /// The start of a sentence about the answer.
    fn answered(self) -> &'static str {
        match self {
            Who::Owner => "You answered",
            Who::AiTool => "Your AI coding tool answered",
        }
    }
}

/// The owner, or the tool that wrote the code, says the control is not there. For a missing control
/// either is the best authority there is: nobody overstates an app by saying it lacks something.
fn said_no(question: &Question, who: Who) -> Finding {
    Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        in_test_module: false,
        rule_id: "design.answered-no".to_owned(),
        title: format!("{} no: {}", who.answered(), question.title.to_lowercase()),
        // The owner reporting a missing control is as certain as this gets; how bad it is depends
        // on the requirement, so the severity is the same for all of them and the requirement's own
        // words say what is at stake.
        severity: Severity::Medium,
        confidence: Confidence::High,
        location: Location {
            file: "securevibe.toml".to_owned(),
            line: 1,
        },
        secret: None,
        requirement_ids: vec![question.id.clone()],
        cwe: Vec::new(),
        description: format!(
            "In securevibe.toml {} no to this question: {}",
            who.answered().to_lowercase(),
            question.asks
        ),
        impact: format!(
            "{} is one of the requirements this app is being checked against, and {} said the \
             control it asks for is not there.",
            question.id,
            match who {
                Who::Owner => "you have",
                Who::AiTool => "your AI coding tool has",
            }
        ),
        fix: format!(
            "Either build the control and change the answer to yes, naming {}, or leave the answer \
             as no so the report keeps saying this is outstanding.",
            question.where_means
        ),
    }
}

/// A pointer that leads nowhere reads as evidence and is not, which is worse than none.
fn stale_pointer(question: &Question, path: &str, who: Who) -> Finding {
    Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        in_test_module: false,
        rule_id: "design.where-is-not-there".to_owned(),
        title: format!("`{path}` is not in this app"),
        severity: Severity::Low,
        confidence: Confidence::High,
        location: Location {
            file: "securevibe.toml".to_owned(),
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
    }
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
        let out = evaluate(&questions(), &by(None), &all_apply, &everything_exists);
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
        );
        assert_eq!(out.unreadable, vec!["V8.3.1".to_owned()]);
        assert!(out.attested.is_empty() && out.stated.is_empty() && out.findings.is_empty());
    }

    #[test]
    fn the_ai_tools_no_is_still_a_finding_and_says_who_said_it() {
        let mut a = answers(&[("V8.3.1", NO, None)]);
        a.get_mut("V8.3.1").unwrap().by = Some(AI_TOOL.to_owned());
        let out = evaluate(&questions(), &a, &all_apply, &everything_exists);
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
        );
        assert!(out.stated.is_empty() && out.attested.is_empty());
        assert_eq!(out.findings[0].rule_id, "design.where-is-not-there");
    }

    #[test]
    fn the_answers_are_exactly_three_words() {
        assert_eq!(ANSWERS, [YES, NO, NOT_SURE]);
    }
}
