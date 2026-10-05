//! `sv notes` keeps everything in security-notes.md that `sv` did not write (deep review R7).
//!
//! Until 4 October 2026 it rewrote the file from the answers alone: a preface the owner wrote above
//! the first question, a quote in an answer, a bullet added to `sv`'s facts, and a file that was not
//! UTF-8 (all of it) were gone after the next `sv notes`. The unit tests beside the reader hold the
//! rules; this holds the command the owner runs, and that a refusal writes nothing.

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

fn app(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-notes-keep-{tag}-{}", std::process::id()));
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
    dir
}

/// Each of `lines` is a whole line of `text`, in this order.
fn in_order(text: &str, lines: &[&str]) {
    let all: Vec<&str> = text.split('\n').collect();
    let mut from = 0;
    for line in lines {
        let at = all[from..]
            .iter()
            .position(|l| l == line)
            .unwrap_or_else(|| panic!("{line:?} is gone, or out of order:\n{text}"));
        from += at + 1;
    }
}

#[test]
fn sv_notes_keeps_the_owners_text_before_between_and_after_its_sections() {
    let dir = app("order");
    let notes = dir.join("security-notes.md");
    let made = std::fs::read_to_string(&notes).unwrap();
    assert!(
        made.matches("\n## V").count() >= 2 && made.contains(PLACEHOLDER),
        "the setup needs two questions to write between:\n{made}"
    );
    let owner = [
        "BEFORE: reviewed with Sam on 1 October.",
        "Written by: owner",
        "ANSWER: names are 1 to 80 characters, and emails are checked by a link.",
        "> QUOTE: our lawyer said to keep it simple.",
        "BETWEEN: written after the first answer.",
        "AFTER: the very end of the file.",
    ];
    let second_heading = made.match_indices("\n## V").nth(1).unwrap().0;
    let edited = format!(
        "{}\n{}\n{}",
        &made[..second_heading],
        owner[4],
        &made[second_heading..]
    )
    .replacen(
        "# Security notes\n\n",
        &format!("# Security notes\n\n{}\n\n", owner[0]),
        1,
    )
    .replacen(
        PLACEHOLDER,
        &format!("{}\n\n{}\n\n{}", owner[1], owner[2], owner[3]),
        1,
    ) + &format!("\n{}\n", owner[5]);
    in_order(&edited, &owner);
    // A heading given the owner's own words, and an answer with Windows line endings and an
    // indented first line, kept byte for byte.
    let heading = made.lines().find(|l| l.starts_with("## V")).unwrap();
    let retitled = format!("{heading} (our own words)");
    let crlf = "    Indented first line.\r\nWritten by: owner\r\nOur decision, with Windows line endings.\r";
    let edited = edited
        .replacen(heading, &retitled, 1)
        .replacen(PLACEHOLDER, crlf, 1);
    assert!(
        edited.contains(crlf) && edited.contains(&retitled),
        "the setup failed"
    );
    std::fs::write(&notes, &edited).unwrap();

    let again = sv(&["notes"], &dir);
    let said = String::from_utf8_lossy(&again.stdout).into_owned();
    assert!(again.status.success(), "{said}");
    let written = std::fs::read_to_string(&notes).unwrap();
    in_order(&written, &owner);
    assert!(written.contains(&format!("\n{crlf}\n")), "{written}");
    assert!(written.contains(&format!("\n{retitled}\n")), "{written}");
    assert!(said.contains("Kept as you wrote it"), "{said}");
    // And once more, byte for byte.
    assert!(sv(&["notes"], &dir).status.success());
    assert_eq!(std::fs::read_to_string(&notes).unwrap(), written);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn sv_notes_refuses_what_it_cannot_keep_and_writes_nothing() {
    let dir = app("refuse");
    let notes = dir.join("security-notes.md");
    let made = std::fs::read_to_string(&notes).unwrap();
    let first_heading = made
        .lines()
        .find(|l| l.starts_with("## V"))
        .unwrap()
        .to_owned();

    // Not UTF-8: before R7, read as no file at all and written over with a new one.
    let mut latin1 = made
        .clone()
        .replacen(PLACEHOLDER, "Our caf", 1)
        .into_bytes();
    let at = latin1.windows(7).position(|w| w == b"Our caf").unwrap() + 7;
    latin1.insert(at, 0xE9);
    // Two sections for one question.
    let twice = format!("{made}{first_heading}\n\nA second answer, written further down.\n");
    for (what, bytes, says) in [
        ("not UTF-8", latin1, "UTF-8"),
        ("two sections", twice.into_bytes(), "two sections"),
    ] {
        std::fs::write(&notes, &bytes).unwrap();
        let out = sv(&["notes"], &dir);
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(!out.status.success(), "{what}: accepted");
        assert!(
            err.contains(says) && err.contains("written nothing"),
            "{what}: {err}"
        );
        assert_eq!(
            std::fs::read(&notes).unwrap(),
            bytes,
            "{what}: the file changed"
        );
        let strays: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".sv-"))
            .collect();
        assert!(strays.is_empty(), "{what}: a half-written file was left");
    }
    std::fs::remove_dir_all(&dir).ok();
}
