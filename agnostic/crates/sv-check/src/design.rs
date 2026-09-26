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
}

/// What the answers came to.
#[derive(Debug, Default)]
pub struct Outcome {
    /// `yes`, with a pointer that resolves if one was given.
    pub attested: Vec<Verified>,
    /// `no`, and pointers that lead nowhere.
    pub findings: Vec<Finding>,
    /// Questions that apply and nobody has answered, or answered `not-sure`.
    pub unanswered: Vec<String>,
    /// An answer that is not one of the three words, named so a typo cannot pass for silence.
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
        match answer.answer.as_str() {
            NOT_SURE => out.unanswered.push(question.id.clone()),
            NO => out.findings.push(said_no(question)),
            YES => match &answer.location {
                Some(path) if !file_exists(path) => {
                    out.findings.push(stale_pointer(question, path));
                }
                Some(path) => out.attested.push(Verified::new(
                    "design.attested",
                    &[question.id.as_str()],
                    format!(
                        "securevibe.toml: you answered yes, and named {path}. This is your word \
                         about the app, not a check of it."
                    ),
                )),
                None => out.attested.push(Verified::new(
                    "design.attested",
                    &[question.id.as_str()],
                    "securevibe.toml: you answered yes, without saying where. This is your word \
                     about the app, not a check of it."
                        .to_owned(),
                )),
            },
            _ => out.unreadable.push(question.id.clone()),
        }
    }
    out
}

/// The owner says the control is not there. Their word is the best authority there is for that.
fn said_no(question: &Question) -> Finding {
    Finding {
        rule_id: "design.answered-no".to_owned(),
        title: format!("You answered no: {}", question.title.to_lowercase()),
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
            "In securevibe.toml you answered no to this question: {}",
            question.asks
        ),
        impact: format!(
            "{} is one of the requirements this app is being checked against, and you have said \
             the control it asks for is not there.",
            question.id
        ),
        fix: format!(
            "Either build the control and change the answer to yes, naming {}, or leave the answer \
             as no so the report keeps saying this is outstanding.",
            question.where_means
        ),
    }
}

/// A pointer that leads nowhere reads as evidence and is not, which is worse than none.
fn stale_pointer(question: &Question, path: &str) -> Finding {
    Finding {
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
            "You answered yes for {} and said the work is in `{path}`, and there is no such file \
             in this app. It may have been renamed or moved.",
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

    #[test]
    fn the_answers_are_exactly_three_words() {
        assert_eq!(ANSWERS, [YES, NO, NOT_SURE]);
    }
}
