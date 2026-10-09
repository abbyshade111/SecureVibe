//! What the report says when stackvet.toml does not say what the app holds about people.
//!
//! Level 1 is a claim that nothing sensitive is held; a list nobody filled in makes no claim, so the
//! app is held to level 2 and the report says why. `categories = []` is an answer, and gets level 1.

use std::path::PathBuf;
use std::process::Command;

/// Runs `sv report` on a one-file app with this `[data]` section, and returns compliance.md.
fn compliance_with(name: &str, data: &str) -> String {
    let dir: PathBuf = std::env::temp_dir().join(format!("sv-data-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("app.py"), "def home():\n    return 'hi'\n").unwrap();
    std::fs::write(
        dir.join("stackvet.toml"),
        format!(
            "manifest-version = 1\n\n[app]\nname = \"Notes\"\naudience = \"just-me\"\n\
             deployment = \"local-only\"\n\n[stack]\nlanguages = [\"python\"]\n{data}"
        ),
    )
    .unwrap();
    let out_dir = dir.join("report");
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
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
    compliance
}

const WHY: &str = "does not say what information the app holds about people";

#[test]
fn an_unanswered_data_list_is_held_to_level_2_and_says_why() {
    let silent = compliance_with("silent", "");
    assert!(
        silent.contains("ASVS level 2."),
        "no answer must not buy level 1:\n{silent}"
    );
    assert!(silent.contains(WHY), "the report must say why:\n{silent}");

    // The control: the same app, answering "nothing about people", is level 1 and nothing is said.
    let none = compliance_with("none", "\n[data]\ncategories = []\n");
    assert!(none.contains("ASVS level 1."), "{none}");
    assert!(!none.contains(WHY), "{none}");
}
