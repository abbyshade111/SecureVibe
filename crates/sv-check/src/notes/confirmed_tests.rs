//! A security notes section the AI coding tool wrote, confirmed by a person through `sv review`
//! (the gap analysis of 7 October 2026, finding 22(c); ADR-022, Later): documented, shown as
//! confirmed, and never the owner's own, however its `Written by:` line is changed afterwards.

use super::*;

fn key() -> crate::seal::AppKey {
    static KEY: std::sync::OnceLock<crate::seal::Key> = std::sync::OnceLock::new();
    KEY.get_or_init(|| crate::seal::Key::random().unwrap())
        .clone()
        .for_app(&crate::seal::App::named_for_tests("app"))
}

fn catalog() -> Catalog {
    Catalog {
        file: "security-notes.md".into(),
        sections: vec![Section {
            id: "V8.1.1".into(),
            title: "Who may do what".into(),
            asks: "Who may do what in the app.".into(),
            facts: vec![],
            how_to_find_out: None,
            heading: None,
            not_covered: None,
        }],
        ..Default::default()
    }
}

const ANSWER: &str = "Administrators may open every page; everyone else only their own records.";

/// A section by `writer`, sealed over `fields` when given.
fn section(writer: &str, fields: Option<Vec<String>>) -> Answers {
    let mut body = format!("{WRITTEN_BY} {writer}\n\n{ANSWER}");
    if let Some(fields) = fields {
        body.push_str(&format!(
            "\n\n{SEALED_BY} {}",
            key().seal(&crate::seal::as_strs(&fields))
        ));
    }
    Answers {
        sections: vec![("V8.1.1".into(), body)],
        ..Default::default()
    }
}

fn evidence_of(answers: &Answers) -> Evidence {
    super::evidence(
        &catalog(),
        answers,
        "security-notes.md",
        &crate::seal::Checker::key(key()),
    )
}

#[test]
fn a_tool_section_a_person_confirmed_is_documented_as_confirmed() {
    let fields = crate::seal::notes_confirmed_fields("V8.1.1", ANSWER);
    let out = evidence_of(&section(BY_AI_TOOL, Some(fields)));
    assert_eq!(out.documented.len(), 1, "{:?}", out.stated);
    assert!(out.stated.is_empty());
    let v = &out.documented[0];
    assert_eq!(v.check_id, CONFIRMED);
    assert_eq!(v.requirement_ids, ["V8.1.1"]);
    assert!(
        v.scope
            .contains("written by your AI coding tool and confirmed by a person"),
        "{}",
        v.scope
    );
}

#[test]
fn unconfirmed_it_is_the_tools_word_and_says_to_confirm_it() {
    let out = evidence_of(&section(BY_AI_TOOL, None));
    assert!(out.documented.is_empty());
    assert!(
        out.stated[0].scope.contains("run `sv review`")
            && out.stated[0].scope.contains("to confirm it"),
        "{}",
        out.stated[0].scope
    );
}

#[test]
fn a_confirmed_section_marked_the_owners_afterwards_is_nobodys_documentation() {
    // The tool, or anyone, changes the line to `owner` and keeps the seal: the owner's fields are
    // checked, the confirmed seal does not hold for them, and the draft is the tool's word again.
    let fields = crate::seal::notes_confirmed_fields("V8.1.1", ANSWER);
    let out = evidence_of(&section(BY_OWNER, Some(fields)));
    assert!(out.documented.is_empty(), "{:?}", out.documented);
    assert_eq!(out.stated.len(), 1);
}

#[test]
fn an_owners_seal_on_a_section_the_tool_wrote_confirms_nothing() {
    // The other way about: an owner's seal moved onto a section marked as the tool's.
    let fields = crate::seal::notes_fields("V8.1.1", ANSWER);
    let out = evidence_of(&section(BY_AI_TOOL, Some(fields)));
    assert!(out.documented.is_empty(), "{:?}", out.documented);
    assert_eq!(out.stated.len(), 1);
}

#[test]
fn a_confirmed_section_whose_answer_changed_is_the_tools_word_again() {
    let fields = crate::seal::notes_confirmed_fields("V8.1.1", "Everyone may open every page.");
    let out = evidence_of(&section(BY_AI_TOOL, Some(fields)));
    assert!(out.documented.is_empty(), "{:?}", out.documented);
    assert_eq!(out.stated.len(), 1);
}
