//! A heading of the owner's own in security-notes.md, end to end.
//!
//! Found on 4 October 2026 writing the design-time prompts (BACKLOG, "A heading of the owner's own in
//! `security-notes.md` is read as part of the answer above it"): the reader ends a section only at a
//! heading that starts with a requirement id, so a heading of anyone else's, and what follows it, could
//! become the answer to the section above. This holds what the report says about a section nobody
//! answered when such a heading sits under it.

use std::path::{Path, PathBuf};
use std::process::Command;

const PLACEHOLDER: &str = "_Nobody has written this yet._";
const PROSE: &str =
    "Each of these is decided and written down here, with enough words to be an answer.";

fn sv(args: &[&str], dir: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sv"))
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .args(args)
        .arg(dir)
        .output()
        .expect("sv runs")
}

/// The ids of the sections `sv notes` wrote, in order.
fn section_ids(notes: &str) -> Vec<String> {
    notes
        .lines()
        .filter_map(|line| line.strip_prefix("## "))
        .filter_map(|rest| rest.split(" — ").next())
        .map(str::to_owned)
        .collect()
}

/// The status column of the requirement's row in compliance.md.
fn status_of(compliance: &str, id: &str) -> String {
    let row = compliance
        .lines()
        .find(|line| line.starts_with(&format!("| {id} |")))
        .unwrap_or_else(|| panic!("no row for {id} in the report"));
    row.split('|').nth(2).unwrap_or("").trim().to_owned()
}

/// A fresh app with the notes `sv notes` writes, and those notes.
fn app(name: &str) -> (PathBuf, String) {
    let dir = std::env::temp_dir().join(format!("sv-notes-headings-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("app.py"), "def home():\n    return 'hi'\n").unwrap();
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/tested-notes/securevibe.toml");
    std::fs::copy(manifest, dir.join("securevibe.toml")).unwrap();
    let made = sv(&["notes"], &dir);
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    let notes = std::fs::read_to_string(dir.join("security-notes.md")).unwrap();
    (dir, notes)
}

/// The report's compliance.md for the app with these notes.
fn compliance(dir: &Path, notes: &str) -> String {
    std::fs::write(dir.join("security-notes.md"), notes).unwrap();
    let out_dir = dir.join("report");
    std::fs::remove_dir_all(&out_dir).ok();
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .arg("report")
        .arg(dir)
        .arg("--out")
        .arg(&out_dir)
        .output()
        .expect("sv runs");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read_to_string(out_dir.join("compliance.md")).unwrap()
}

/// The notes with `extra` placed just before the second section's heading, so it sits under the first.
fn under_first(notes: &str, ids: &[String], extra: &str) -> String {
    let second = notes
        .lines()
        .find(|l| l.starts_with(&format!("## {} — ", ids[1])))
        .unwrap()
        .to_owned();
    notes.replacen(&second, &format!("{extra}\n\n{second}"), 1)
}

#[test]
fn a_heading_of_the_owners_own_does_not_answer_the_section_above_it() {
    let (dir, notes) = app("stray");
    let ids = section_ids(&notes);
    assert!(ids.len() >= 2, "too few sections to test with: {ids:?}");

    // The control: unanswered, the first section is not verified, and answered by the tool it is
    // stated by the tool. So the report does read this section, and an answer here would show.
    let untouched = compliance(&dir, &notes);
    assert!(
        status_of(&untouched, &ids[0]).starts_with("not verified"),
        "{untouched}"
    );
    let answered = notes.replacen(
        PLACEHOLDER,
        &format!("Written by: AI coding tool\n\n{PROSE}"),
        1,
    );
    let answered = compliance(&dir, &answered);
    assert!(
        status_of(&answered, &ids[0]).starts_with("stated by the AI coding tool"),
        "the setup: an answer here is counted"
    );

    let mut counted = Vec::new();
    // A note of the owner's own, under a heading of their own, below the first section, which nobody
    // answered: it is not an answer to that section, with or without a line saying who wrote it.
    for note in [
        format!("## A note from me\n\n{PROSE}"),
        format!("## A note from me\n\nWritten by: AI coding tool\n\n{PROSE}"),
        format!("### Things to do later\n\nWritten by: AI coding tool\n\n{PROSE}"),
    ] {
        let report = compliance(&dir, &under_first(&notes, &ids, &note));
        let status = status_of(&report, &ids[0]);
        if !status.starts_with("not verified") {
            counted.push(format!("{note:?}\n    made it: {status}"));
        }
    }
    // The report says what it did not read, naming the heading and where it was.
    let note = format!("## A note from me\n\n{PROSE}");
    let report = compliance(&dir, &under_first(&notes, &ids, &note));
    assert!(
        report.contains("heading of your own in security-notes.md")
            && report.contains(&format!("\"A note from me\", after {}", ids[0])),
        "{report}"
    );
    // `sv notes` writes the file again and keeps the note, once.
    std::fs::write(
        dir.join("security-notes.md"),
        under_first(&notes, &ids, &note),
    )
    .unwrap();
    let again = sv(&["notes"], &dir);
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    let rewritten = std::fs::read_to_string(dir.join("security-notes.md")).unwrap();
    assert_eq!(rewritten.matches(note.as_str()).count(), 1, "{rewritten}");
    // Kept word for word in the section of text that is not under a question, which the report
    // does not read, and not in the section it followed.
    let pos = |what: &str| rewritten.find(what).unwrap();
    assert!(
        pos("## Kept as you wrote it") < pos(&note)
            && pos(&note) < pos(&format!("## {} — ", ids[0])),
        "{rewritten}"
    );
    let reread = compliance(&dir, &rewritten);
    assert!(
        status_of(&reread, &ids[0]).starts_with("not verified"),
        "{reread}"
    );
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        counted.is_empty(),
        "{} was never answered, and a heading of the owner's own under it was counted as its answer:\n  {}",
        ids[0],
        counted.join("\n  ")
    );
}
