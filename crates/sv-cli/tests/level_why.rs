//! Every report says why the app is held to its level and on whose word, and at level 1 what
//! level 2 would bring (the gap analysis of 7 October 2026, finding 17; ADR-024, Later, 9 October
//! 2026), end to end through the binary.

use std::path::{Path, PathBuf};
use std::process::Command;

fn app(name: &str, audience: &str, data: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-level-why-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("stackvet.toml"),
        format!(
            "manifest-version = 1\n\n[app]\nname = \"Notes\"\ndescription = \"Notes.\"\n\
             audience = \"{audience}\"\ndeployment = \"internet\"\n\n[stack]\nlanguages = [\"python\"]\n\n{data}"
        ),
    )
    .unwrap();
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    dir
}

/// The report's JSON, and its compliance page.
fn report(dir: &Path) -> (serde_json::Value, String) {
    let out = dir.join("report");
    let ran = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args([
            "report",
            dir.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .expect("sv runs");
    assert!(
        ran.status.success(),
        "{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    let json =
        serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap()).unwrap();
    let page = std::fs::read_to_string(out.join("compliance.md")).unwrap();
    std::fs::remove_dir_all(dir).ok();
    (json, page)
}

#[test]
fn level_one_says_what_it_rests_on_and_what_level_two_would_add() {
    let (json, page) = report(&app("one", "just-me", "[data]\ncategories = []\n"));
    assert_eq!(json["target_level"], 1);
    let more = json["level_why"]["level_two_more"]
        .as_u64()
        .expect("a count");
    // The setup: level 2 must add something, or "would add" says nothing.
    assert!(more > 0, "{json}");
    // Level 2's own requirements only, not level 3's too: everything above level 1 is more.
    let above = json["counts"]["out_of_level"]
        .as_u64()
        .expect("a count above the level");
    assert!(
        more < above,
        "level 2 adds {more}, and {above} are above level 1 in all: {json}"
    );
    assert!(
        page.contains("Level 1 because stackvet.toml says only you use it, and that the app holds nothing sensitive about people")
            && page.contains("nobody has confirmed")
            && page.contains(&format!("At level 2, {more} more requirements would apply.")),
        "{page}"
    );
}

#[test]
fn level_two_says_which_answer_made_it_so() {
    let (json, page) = report(&app("two", "customers", "[data]\ncategories = []\n"));
    assert_eq!(json["target_level"], 2);
    assert!(
        page.contains("Level 2 because stackvet.toml says customers use it:"),
        "{page}"
    );
    // The control: nothing above level 2 is offered as "what level 2 would add".
    assert!(!page.contains("At level 2,"), "{page}");
    let (_, page) = report(&app("unanswered", "just-me", ""));
    assert!(
        page.contains(
            "Level 2 because it does not say what information the app holds about people"
        ),
        "{page}"
    );
}
