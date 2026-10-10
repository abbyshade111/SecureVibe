//! Every gap in `report.json` says why in one word a program can read, and names the requirements
//! it speaks of when it names any (backlog 226, part 2, item 20). The words are the eight of
//! `sv_report::GapReason` and two more; none may be missing.

use serde_json::Value;
use std::path::Path;
use std::process::Command;

const REASONS: [&str; 10] = [
    "not-asked",
    "not-installed",
    "could-not-read",
    "no-reader",
    "stopped",
    "person-only",
    "planned",
    "partial",
    "left-out",
    "outdated",
];

fn gaps_of(app: &str, args: &[&str]) -> Vec<Value> {
    let app = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(app);
    let out = std::env::temp_dir().join(format!(
        "sv-gap-reasons-{}-{}",
        app.file_name().unwrap().to_string_lossy(),
        std::process::id()
    ));
    std::fs::remove_dir_all(&out).ok();
    let ran = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(&app)
        .args(args)
        .arg("--out")
        .arg(&out)
        .env("PATH", "")
        .output()
        .unwrap();
    let text = std::fs::read_to_string(out.join("report.json"))
        .unwrap_or_else(|_| panic!("no report.json: {}", String::from_utf8_lossy(&ran.stderr)));
    std::fs::remove_dir_all(&out).ok();
    let json: Value = serde_json::from_str(&text).unwrap();
    json["gaps"].as_array().expect("gaps").clone()
}

#[test]
fn every_gap_says_why_in_a_word_a_program_reads() {
    let gaps = gaps_of("flask-booking", &["--tools"]);
    // The setup: a report with gaps of several kinds to read.
    assert!(gaps.len() >= 3, "{gaps:?}");
    for gap in &gaps {
        let reason = gap["reason"]
            .as_str()
            .unwrap_or_else(|| panic!("no reason: {gap}"));
        assert!(REASONS.contains(&reason), "{reason}: {gap}");
    }
    let said = |what: &str| {
        gaps.iter()
            .find(|g| g["what"] == what)
            .unwrap_or_else(|| panic!("no gap {what:?}: {gaps:?}"))["reason"]
            .clone()
    };
    // Not started: --run was not given.
    assert_eq!(said("the running app"), "not-asked");
    // With nothing on the PATH, the outside tools are not there.
    let tool = gaps
        .iter()
        .find(|g| {
            g["what"]
                .as_str()
                .is_some_and(|w| w.starts_with("what `bandit` would have found"))
        })
        .unwrap_or_else(|| panic!("no gap for bandit: {gaps:?}"));
    assert_eq!(tool["reason"], "not-installed", "{tool}");
}
