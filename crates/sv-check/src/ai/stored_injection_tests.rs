//! A prompt injection saved in a note (the gap analysis of 7 October 2026, finding 13(e)): found
//! when the app's search hands the note to the model with the injection in it, and only once the
//! second user's plain note has been shown to reach the model the same way.

use super::tests::{Flaws, credited, found, notes_run, signed_run};
use super::*;

/// The fake app with its search handing notes over as they were saved.
fn unscreened() -> Flaws {
    let mut flaws = Flaws::default();
    flaws.notes_unscreened = true;
    flaws
}

fn asked_about_planted(o: &Outcome) -> Option<&String> {
    o.steps
        .iter()
        .find(|s| s.contains("about their note carrying a prompt injection"))
}

#[test]
fn an_injection_in_a_saved_note_that_reaches_the_model_is_found() {
    let o = notes_run(unscreened());
    let f = o
        .findings
        .iter()
        .find(|f| f.rule_id == STORED_INJECTION.rule_id)
        .unwrap_or_else(|| panic!("{:?}", o.steps));
    assert_eq!(f.requirement_ids, ["C2.1.3"]);
    assert_eq!(
        f.title,
        "A prompt injection saved in a note reaches the model"
    );
    let step = asked_about_planted(&o).unwrap_or_else(|| panic!("{:?}", o.steps));
    assert!(
        step.ends_with("the note reached the model with the injection in it"),
        "{step}"
    );
    // The injection typed in is still screened: this is the stored path alone.
    assert!(!found(&o).contains(&UNSCREENED.rule_id), "{:?}", o.findings);
}

#[test]
fn a_saved_injection_screened_out_is_said_and_not_credited() {
    let o = notes_run(Flaws::default());
    assert!(
        !found(&o).contains(&STORED_INJECTION.rule_id),
        "{:?}",
        o.findings
    );
    assert!(!credited(&o).contains(&STORED_INJECTION.rule_id));
    // The setup: the note was saved, and it did reach the model, only without the injection.
    assert!(
        o.steps
            .iter()
            .any(|s| s.starts_with("saved a note carrying a textbook prompt injection")),
        "{:?}",
        o.steps
    );
    let step = asked_about_planted(&o).unwrap_or_else(|| panic!("{:?}", o.steps));
    assert!(
        step.ends_with("the note reached the model without the injection's words"),
        "{step}"
    );
}

#[test]
fn without_the_plain_note_reaching_the_model_the_planted_one_is_not_asked() {
    // Said to read notes, and it does not: the control fails, and the planted note is never asked
    // about, so a search that finds nothing cannot read as a screen.
    let o = signed_run(unscreened(), false, true);
    assert!(!found(&o).contains(&STORED_INJECTION.rule_id));
    assert!(asked_about_planted(&o).is_none(), "{:?}", o.steps);
}
