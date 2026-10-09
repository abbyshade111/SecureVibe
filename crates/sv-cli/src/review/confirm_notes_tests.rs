//! `sv review` confirming a security notes section the AI coding tool wrote (the gap analysis of 7
//! October 2026, finding 22(c); ADR-022, Later): by a person's name, never the tool's, sealed so
//! the section still says the tool wrote it.

use super::tests::{HEAD, Scratch, with_app};

const NOTES: &str = "# Security notes\n\n## V8.1.1 — Who may do what\n\nWritten by: AI coding \
                     tool\n\nAdministrators may open every page; everyone else only their own.\n";

fn answers(s: &Scratch) -> (String, sv_check::notes::Answers) {
    let after = std::fs::read_to_string(s.app().join("security-notes.md")).unwrap();
    let catalog = sv_check::notes::Catalog::load(&crate::notes_path()).unwrap();
    let answers = sv_check::notes::read_answers(&catalog, &after);
    (after, answers)
}

#[test]
fn a_person_confirms_the_tools_section_and_it_still_says_the_tool_wrote_it() {
    let s = Scratch::new("confirm-notes");
    with_app(&s, HEAD);
    std::fs::write(s.app().join("security-notes.md"), NOTES).unwrap();
    // The tool's own name is refused, and the person's is taken.
    let (result, out) = s.run("AI coding tool\nSam Lee\n");
    result.unwrap();
    assert!(
        out.contains("The AI coding tool cannot confirm its own answer"),
        "{out}"
    );
    assert!(out.contains("Recorded as confirmed by Sam Lee."), "{out}");
    let (after, answers) = answers(&s);
    assert!(answers.confirmed("V8.1.1", &s.checker()).is_ok(), "{after}");
    // Still the tool's section, and not the owner's: the owner's seal does not hold for it.
    assert_eq!(
        answers.writer("V8.1.1"),
        Some(sv_check::notes::Writer::AiTool)
    );
    assert!(answers.recorded("V8.1.1", &s.checker()).is_err());
    // Only the seal line was added.
    let added: Vec<&str> = after
        .lines()
        .filter(|l| !NOTES.lines().any(|n| n == *l))
        .collect();
    assert_eq!(added.len(), 1, "{after}");
    assert!(added[0].starts_with(sv_check::notes::SEALED_BY));
    // Nothing waits the second time.
    let (result, out) = s.run("");
    result.unwrap();
    assert!(out.contains("Nothing in"), "{out}");
}

#[test]
fn left_as_it_is_the_section_is_not_sealed() {
    let s = Scratch::new("confirm-notes-left");
    with_app(&s, HEAD);
    std::fs::write(s.app().join("security-notes.md"), NOTES).unwrap();
    let (result, out) = s.run("\n");
    result.unwrap();
    assert!(out.contains("Left as the tool's word."), "{out}");
    let (after, answers) = answers(&s);
    assert_eq!(after, NOTES);
    assert!(answers.confirmed("V8.1.1", &s.checker()).is_err());
}
