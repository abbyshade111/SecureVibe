//! A security notes section the AI coding tool wrote, confirmed by a person through `sv review`, as
//! the report shows it (the gap analysis of 7 October 2026, finding 22(c); ADR-022, Later): answered
//! in the notes, and said to be the tool's words a person confirmed, never the owner's own. Its
//! `Written by:` line changed to `owner` afterwards, the seal no longer holds and it is the tool's
//! word again.

use std::path::{Path, PathBuf};
use std::process::Command;

const PLACEHOLDER: &str = "_Nobody has written this yet._";

fn sv(args: &[&str], dir: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sv"))
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .args(args)
        .arg(dir)
        .output()
        .expect("sv runs")
}

fn section_ids(notes: &str) -> Vec<String> {
    notes
        .lines()
        .filter_map(|line| line.strip_prefix("## "))
        .filter_map(|rest| rest.split(" — ").next())
        .map(str::to_owned)
        .collect()
}

fn status_of<'a>(compliance: &'a str, id: &str) -> &'a str {
    let row = compliance
        .lines()
        .find(|line| line.starts_with(&format!("| {id} |")))
        .unwrap_or_else(|| panic!("no row for {id} in the report"));
    row.split('|').nth(2).unwrap_or("").trim()
}

#[test]
fn a_confirmed_section_is_shown_as_the_tools_words_a_person_confirmed() {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("sv-notes-confirmed-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("app.py"), "def home():\n    return 'hi'\n").unwrap();
    let manifest =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/tested-notes/stackvet.toml");
    std::fs::copy(manifest, dir.join("stackvet.toml")).unwrap();
    let made = sv(&["notes"], &dir);
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    let template = std::fs::read_to_string(dir.join("security-notes.md")).unwrap();
    let ids = section_ids(&template);
    assert!(ids.len() >= 2, "too few sections to test with: {ids:?}");

    let prose =
        "Each of these is decided and written down here, with enough words to be an answer.";
    let (key, _) = sv_check::seal::Key::load_or_make_in(
        &dir.join("config").join(sv_frameworks::names::CONFIG_DIR),
    )
    .unwrap();
    let key = key.for_app(&sv_check::seal::App::of(&dir).unwrap());
    let confirmed = |id: &str| {
        key.seal(&sv_check::seal::as_strs(
            &sv_check::seal::notes_confirmed_fields(id, prose),
        ))
    };
    let sealed_by = sv_check::notes::SEALED_BY;
    let answers = [
        // Confirmed as `sv review` writes it.
        format!(
            "Written by: AI coding tool\n{sealed_by} {}\n\n{prose}",
            confirmed(&ids[0])
        ),
        // The same confirmation, with the line changed to the owner's afterwards.
        format!(
            "Written by: owner\n{sealed_by} {}\n\n{prose}",
            confirmed(&ids[1])
        ),
    ];
    let mut written = template.clone();
    for answer in &answers {
        written = written.replacen(PLACEHOLDER, answer, 1);
    }
    std::fs::write(dir.join("security-notes.md"), &written).unwrap();

    let out_dir = dir.join("report");
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .arg("report")
        .arg(&dir)
        .arg("--out")
        .arg(&out_dir)
        .output()
        .expect("sv runs");
    let compliance = std::fs::read_to_string(out_dir.join("compliance.md")).unwrap_or_default();
    let html = std::fs::read_to_string(out_dir.join("report.html")).unwrap_or_default();
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!compliance.is_empty(), "the report was not written");

    let shown = status_of(&compliance, &ids[0]);
    assert!(
        shown.starts_with("written by the AI coding tool, confirmed through sv review"),
        "{}: {shown}",
        ids[0]
    );
    assert!(
        shown.contains("your AI coding tool wrote this, and a person confirmed it"),
        "{}: {shown}",
        ids[0]
    );
    assert!(!shown.contains("documented by the owner"), "{shown}");
    assert!(
        html.contains("written by the AI coding tool, confirmed through sv review"),
        "the page says it too"
    );
    let flipped = status_of(&compliance, &ids[1]);
    assert!(
        flipped.starts_with("stated by the AI coding tool"),
        "{}: {flipped}",
        ids[1]
    );
}
