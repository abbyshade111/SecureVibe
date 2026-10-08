//! Who wrote a section of security-notes.md decides what it is worth in the report, end to end.
//!
//! Found in the owner's first run in VS Code, 27 September 2026: the AI coding tool wrote nine
//! sections from the code, and the report called every one *documented by the owner*. The unit
//! tests beside the reader hold the rules; this holds what the report says, which is what the owner
//! reads.

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
fn status_of<'a>(compliance: &'a str, id: &str) -> &'a str {
    let row = compliance
        .lines()
        .find(|line| line.starts_with(&format!("| {id} |")))
        .unwrap_or_else(|| panic!("no row for {id} in the report"));
    row.split('|').nth(2).unwrap_or("").trim()
}

#[test]
fn the_report_credits_only_what_the_owner_wrote_to_the_owner() {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("sv-notes-authorship-{}", std::process::id()));
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
    let template = std::fs::read_to_string(dir.join("security-notes.md")).unwrap();
    let ids = section_ids(&template);
    // Four sections, so each kind of writer has one: the setup must really have them to fill.
    assert!(ids.len() >= 4, "too few sections to test with: {ids:?}");

    let prose =
        "Each of these is decided and written down here, with enough words to be an answer.";
    // The owner's, recorded through `sv review`, as it counts as theirs only then.
    let (key, _) = sv_check::seal::Key::load_or_make_in(
        &dir.join("config").join(sv_frameworks::names::CONFIG_DIR),
    )
    .unwrap();
    // Sealed for this app, as `sv review` run in it seals.
    let key = key.for_app(&sv_check::seal::App::of(&dir).unwrap());
    let seal = key.seal(&sv_check::seal::as_strs(&sv_check::seal::notes_fields(
        &ids[0], prose,
    )));
    let answers = [
        format!(
            "Written by: owner\n{} {seal}\n\n{prose}",
            sv_check::notes::SEALED_BY
        ),
        format!(
            "*Written by the AI coding tool from the code; review before relying on it.*\n\n{prose}"
        ),
        format!("Written by: AI coding tool\n\n{prose}"),
        format!("Written by: Sam\n\n{prose}"),
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
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!compliance.is_empty(), "the report was not written");

    let owner = status_of(&compliance, &ids[0]);
    assert!(
        owner.starts_with("documented by the owner"),
        "{}: {owner}",
        ids[0]
    );
    for id in &ids[1..3] {
        let status = status_of(&compliance, id);
        assert!(
            status.starts_with("stated by the AI coding tool"),
            "{id} was written by the tool: {status}"
        );
    }
    let unreadable = status_of(&compliance, &ids[3]);
    assert!(
        unreadable.starts_with("not verified"),
        "{}: {unreadable}",
        ids[3]
    );
    assert!(
        compliance.contains(&format!(
            "names somebody else or says both, so nothing was made of it: {}",
            ids[3]
        )),
        "the unreadable line must be named: {compliance}"
    );
}
