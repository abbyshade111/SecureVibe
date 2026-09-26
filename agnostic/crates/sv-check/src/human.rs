//! What only a person can check, and how to check it.
//!
//! On a real app, 98 of the applicable requirements can be settled by nobody but the owner. They sat
//! in the report as *not verified*, indistinguishable from the ones nothing had got around to, with
//! no hint of what doing something about them would even involve.
//!
//! The instructions come from three places, because two of them already existed:
//!
//! - **The security notes** (`security-notes.json`) — 19 requirements that ask for a written
//!   decision. The question is the instruction: write the thing down.
//! - **The design questions** (`design-questions.json`) — 16 that ask how the app is built. The
//!   question is the instruction: answer it, and say where in the code.
//! - **`human-checks.json`** — the 20 ASVS requirements left over, each with a line saying what to
//!   go and look at and what would count as the wrong answer.
//!
//! One requirement never appears twice: `crates/sv-check/tests/human_checks.rs` refuses an entry in
//! `human-checks.json` that another catalog already asks about, because the two would give different
//! advice about the same thing and the reader has no way to tell which is meant.
//!
//! # It credits nothing
//!
//! Every requirement here is still *not verified*, and stays that way until the owner does something
//! that produces evidence — writes the notes section, answers the design question, or writes a test.
//! The instruction sits beside the requirement; it is not a substitute for having followed it. This
//! is the one thing the section could get wrong, and `nothing_here_credits_a_requirement` holds it.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct HumanCheck {
    pub id: String,
    pub title: String,
    /// What to go and do, in the words of somebody who is not a programmer.
    pub how: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HumanChecks {
    pub checks: Vec<HumanCheck>,
}

impl HumanChecks {
    pub fn load(path: &Path) -> Result<HumanChecks> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let checks: HumanChecks =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        for c in &checks.checks {
            if c.how.trim().is_empty() {
                anyhow::bail!("{}: the check for {} says nothing", path.display(), c.id);
            }
        }
        Ok(checks)
    }
}

/// One line of the checklist: a requirement, and what doing something about it involves.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Item {
    pub id: String,
    pub title: String,
    pub how: String,
    /// Where to go and look, when the question alone does not say. Absent for a `human-checks.json`
    /// entry, whose `how` is already the instruction.
    pub where_to_look: Option<String>,
    /// Where the instruction came from, so the reader knows what kind of answer is wanted.
    pub route: Route,
}

/// What kind of thing would settle this requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Route {
    /// Write it down in security-notes.md.
    WriteItDown,
    /// Answer it in the [design] section of securevibe.toml.
    AnswerInTheManifest,
    /// Go and look at the running app, or at how it is deployed.
    GoAndLook,
}

impl Route {
    pub fn what_to_do(self) -> &'static str {
        match self {
            Route::WriteItDown => "write your answer in security-notes.md (`sv notes` makes it)",
            Route::AnswerInTheManifest => "answer it in the [design] section of securevibe.toml",
            Route::GoAndLook => "check it by hand; nothing here can",
        }
    }
}

/// The checklist for one app, in the order the work should be done.
///
/// `applicable` decides membership, so a requirement this app is not being assessed against never
/// appears — the instruction would be busywork. Requirements that already have evidence are the
/// caller's to exclude.
pub fn checklist(
    notes: &crate::notes::Catalog,
    design: &crate::design::Questions,
    human: &HumanChecks,
    wanted: &BTreeSet<String>,
) -> Vec<Item> {
    let mut out: Vec<Item> = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for section in &notes.sections {
        if wanted.contains(&section.id) && seen.insert(&section.id) {
            out.push(Item {
                id: section.id.clone(),
                title: section.title.clone(),
                how: section.asks.clone(),
                where_to_look: section.how_to_find_out.clone(),
                route: Route::WriteItDown,
            });
        }
    }
    for question in &design.questions {
        if wanted.contains(&question.id) && seen.insert(&question.id) {
            out.push(Item {
                id: question.id.clone(),
                title: question.title.clone(),
                how: question.asks.clone(),
                where_to_look: question.how_to_find_out.clone(),
                route: Route::AnswerInTheManifest,
            });
        }
    }
    for check in &human.checks {
        if wanted.contains(&check.id) && seen.insert(&check.id) {
            out.push(Item {
                id: check.id.clone(),
                title: check.title.clone(),
                how: check.how.clone(),
                where_to_look: None,
                route: Route::GoAndLook,
            });
        }
    }
    out
}

/// The requirements in `wanted` that no catalog says anything about.
///
/// Counted rather than listed by the report: on a real app these are the Secure by Design and AISVS
/// controls, which are design review from standards that are themselves checklists, and 58 more rows
/// of "read the standard" is the wall this work exists to remove.
pub fn without_instructions(
    notes: &crate::notes::Catalog,
    design: &crate::design::Questions,
    human: &HumanChecks,
    wanted: &BTreeSet<String>,
) -> Vec<String> {
    let known: BTreeSet<&str> = notes
        .sections
        .iter()
        .map(|s| s.id.as_str())
        .chain(design.questions.iter().map(|q| q.id.as_str()))
        .chain(human.checks.iter().map(|c| c.id.as_str()))
        .collect();
    wanted
        .iter()
        .filter(|id| !known.contains(id.as_str()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notes() -> crate::notes::Catalog {
        crate::notes::Catalog {
            file: "security-notes.md".into(),
            sections: vec![crate::notes::Section {
                id: "V6.1.1".into(),
                title: "How sign-in is protected".into(),
                asks: "How the app defends against guessing.".into(),
                facts: Vec::new(),
                how_to_find_out: None,
            }],
            elsewhere: Vec::new(),
        }
    }

    fn design() -> crate::design::Questions {
        crate::design::Questions {
            questions: vec![crate::design::Question {
                id: "V8.3.1".into(),
                title: "Authorization on the server".into(),
                asks: "Is authorization enforced on the server?".into(),
                where_means: "the file where it happens".into(),
                how_to_find_out: None,
            }],
        }
    }

    fn human() -> HumanChecks {
        HumanChecks {
            checks: vec![HumanCheck {
                id: "V12.2.2".into(),
                title: "The certificate is one browsers trust".into(),
                how: "Click the padlock.".into(),
            }],
        }
    }

    fn want(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn every_source_contributes_and_each_says_what_kind_of_answer_it_wants() {
        let list = checklist(
            &notes(),
            &design(),
            &human(),
            &want(&["V6.1.1", "V8.3.1", "V12.2.2"]),
        );
        let routes: Vec<Route> = list.iter().map(|i| i.route).collect();
        assert_eq!(
            routes,
            [
                Route::WriteItDown,
                Route::AnswerInTheManifest,
                Route::GoAndLook
            ]
        );
        for item in &list {
            assert!(!item.how.trim().is_empty(), "{} says nothing", item.id);
        }
    }

    #[test]
    fn a_where_to_look_line_reaches_the_row() {
        // The data guard in tests/human_checks.rs says the catalogs carry a `howToFindOut`. It says
        // nothing about whether that text ever reaches the reader, and dropping it on the way into
        // the row was caught by nothing: a guard on the input is not a guard on the output.
        let mut n = notes();
        n.sections[0].how_to_find_out = Some("Look in your sign-in code.".to_owned());
        let list = checklist(&n, &design(), &human(), &want(&["V6.1.1"]));
        assert_eq!(
            list[0].where_to_look.as_deref(),
            Some("Look in your sign-in code."),
            "the line is in the catalog and not in the row"
        );

        let mut d = design();
        d.questions[0].how_to_find_out =
            Some("Find the code that runs on every request.".to_owned());
        let list = checklist(&notes(), &d, &human(), &want(&["V8.3.1"]));
        assert_eq!(
            list[0].where_to_look.as_deref(),
            Some("Find the code that runs on every request.")
        );
    }

    #[test]
    fn a_requirement_that_does_not_apply_is_not_on_the_list() {
        // The instruction would be busywork, and a checklist that asks for work nobody needs is one
        // people stop reading.
        let list = checklist(&notes(), &design(), &human(), &want(&["V6.1.1"]));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "V6.1.1");
    }

    #[test]
    fn a_requirement_in_two_catalogs_appears_once() {
        // They would give different advice about the same thing, and the reader cannot tell which
        // is meant. The data guard refuses this; this is the belt to its braces.
        let mut h = human();
        h.checks.push(HumanCheck {
            id: "V6.1.1".into(),
            title: "Also this".into(),
            how: "Do something else.".into(),
        });
        let list = checklist(&notes(), &design(), &h, &want(&["V6.1.1"]));
        assert_eq!(list.len(), 1, "{list:?}");
        assert_eq!(
            list[0].route,
            Route::WriteItDown,
            "the notes come first, so their wording wins"
        );
    }

    #[test]
    fn what_no_catalog_covers_is_reported_rather_than_dropped() {
        // On a real app this is the 58 Secure by Design and AISVS controls. Silently omitting them
        // would make the checklist look complete when it covers 40 of 98.
        let rest = without_instructions(
            &notes(),
            &design(),
            &human(),
            &want(&["V6.1.1", "SBD-AC-01", "C1.1.1"]),
        );
        assert_eq!(rest, ["C1.1.1".to_owned(), "SBD-AC-01".to_owned()]);
    }

    #[test]
    fn the_list_is_empty_when_there_is_nothing_to_do() {
        assert!(checklist(&notes(), &design(), &human(), &want(&[])).is_empty());
        assert!(without_instructions(&notes(), &design(), &human(), &want(&[])).is_empty());
    }
}
