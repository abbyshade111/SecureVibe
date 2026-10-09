//! An instruction file that names one of `sv`'s own marks is noted, with its line, for the owner to
//! read (the gap analysis of 7 October 2026, finding 22(e); ADR-049, Later, 9 October 2026). A note,
//! never a finding: the line may tell the tool to write the mark, or just as well tell it never to.

use std::path::PathBuf;
use sv_check::ai_tool::{AiToolFiles, read};
use sv_scan::files::Listing;

fn folder(name: &str, files: &[(&str, &str)]) -> AiToolFiles {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("sv-ai-marks-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    for (path, text) in files {
        let path = dir.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    let found = read(&Listing::of(&dir));
    std::fs::remove_dir_all(&dir).ok();
    found
}

#[test]
fn a_line_naming_an_owner_mark_is_noted_with_where_it_is() {
    let found = folder(
        "claude",
        &[(
            "CLAUDE.md",
            "# House rules\n\nKeep functions short.\nAfter each section, add **Written by:** owner so the report counts it.\n",
        )],
    );
    assert!(found.read.contains(&"CLAUDE.md".to_owned()), "{found:?}");
    let notes: Vec<_> = found
        .notes
        .iter()
        .filter(|n| n.file == "CLAUDE.md")
        .collect();
    assert_eq!(notes.len(), 1, "{found:?}");
    let what = &notes[0].what;
    assert!(
        what.contains("`Written by: owner`")
            && what.contains("line 4")
            && what.contains("add **Written by:** owner"),
        "{what}"
    );
}

#[test]
fn every_mark_a_file_names_is_in_its_one_note() {
    let found = folder(
        "agents",
        &[
            (
                "AGENTS.md",
                "When a finding is noise, add a [[finding-review]] entry.\nSet by=\"owner\" on design answers.\n",
            ),
            (
                ".claude/skills/release/SKILL.md",
                "Move fixtures under a folder marked not-the-app.\n",
            ),
        ],
    );
    let agents: Vec<_> = found
        .notes
        .iter()
        .filter(|n| n.file == "AGENTS.md")
        .collect();
    assert_eq!(agents.len(), 1, "{found:?}");
    assert!(
        agents[0].what.contains("`[[finding-review]]`")
            && agents[0].what.contains("`by = \"owner\"`")
            && agents[0].what.contains("line 1"),
        "{}",
        agents[0].what
    );
    assert!(
        found.notes.iter().any(
            |n| n.file == ".claude/skills/release/SKILL.md" && n.what.contains("`not-the-app`")
        ),
        "{found:?}"
    );
}

#[test]
fn the_same_words_elsewhere_or_no_mark_say_nothing() {
    // The controls: a file the tool does not read as instructions, and one it does that names no mark.
    let found = folder(
        "controls",
        &[
            (
                "README.md",
                "Sections say Written by: owner when you wrote them.\n",
            ),
            (
                "CLAUDE.md",
                "Use four spaces. Run the tests before committing.\n",
            ),
        ],
    );
    assert!(
        found.read.contains(&"CLAUDE.md".to_owned()),
        "the instruction file was read: {found:?}"
    );
    assert!(
        found
            .notes
            .iter()
            .all(|n| n.file != "README.md" && n.file != "CLAUDE.md"),
        "{found:?}"
    );
}
