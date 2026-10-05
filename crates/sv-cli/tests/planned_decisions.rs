//! Decisions as planned, then held to (backlog item 5 of the design-time list), end to end: a
//! `[design]` answer of `planned` credits nothing, is a plan while the app has no code, and once it
//! has code is a finding when the file it named is not there.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The status column of the requirement's row in compliance.md.
fn status_of<'a>(compliance: &'a str, id: &str) -> &'a str {
    let row = compliance
        .lines()
        .find(|line| line.starts_with(&format!("| {id} |")))
        .unwrap_or_else(|| panic!("no row for {id} in the report:\n{compliance}"));
    row.split('|').nth(2).unwrap_or("").trim()
}

/// Writes the tested-notes example's securevibe.toml with `design` as its [design] section, runs
/// `sv report`, and gives back compliance.md and report.json.
fn report(dir: &Path, design: &str) -> (String, String) {
    let example = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/tested-notes/securevibe.toml");
    let mut manifest = std::fs::read_to_string(example).unwrap();
    assert_eq!(
        manifest.matches("[design]").count(),
        0,
        "the example grew answers of its own; this test would be adding to them"
    );
    manifest.push_str(&format!("\n[design]\n{design}"));
    std::fs::write(dir.join("securevibe.toml"), &manifest).unwrap();
    let out_dir = dir.join("report");
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
    (
        std::fs::read_to_string(out_dir.join("compliance.md")).unwrap(),
        std::fs::read_to_string(out_dir.join("report.json")).unwrap(),
    )
}

fn fresh(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-planned-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const ANSWERS: &str = r#""V8.3.1" = { answer = "planned", where = "server/auth.py", by = "ai-tool" }
"V2.2.2" = { answer = "planned", where = "app.py", by = "ai-tool" }
"V15.3.1" = { answer = "planned", by = "ai-tool" }
"#;

/// Neither credited nor counted as a failure in the table: the owner's plan is not the app.
fn assert_not_credited(compliance: &str) {
    for id in ["V8.3.1", "V2.2.2", "V15.3.1"] {
        let status = status_of(compliance, id);
        assert!(
            !status.starts_with("attested") && !status.starts_with("stated"),
            "{id}: a plan was credited: {status}"
        );
    }
}

#[test]
fn before_there_is_code_a_planned_decision_is_a_plan() {
    let dir = fresh("no-code");
    // A brief and nothing else: no source file, no dependency manifest.
    std::fs::write(dir.join("README.md"), "A notes app, to be built.\n").unwrap();
    let (compliance, json) = report(&dir, ANSWERS);
    std::fs::remove_dir_all(&dir).ok();

    assert_not_credited(&compliance);
    assert!(
        !json.contains("design.planned-never-built"),
        "no code yet is not a decision broken"
    );
    assert!(
        json.contains("3 design decisions planned, not built yet"),
        "the plans are listed as plans: {json}"
    );
    for absent in ["the file is there now", "with no file named"] {
        assert!(!json.contains(absent), "{absent}");
    }
}

#[test]
fn once_there_is_code_a_planned_file_that_is_not_there_is_decided_never_built() {
    let dir = fresh("code");
    std::fs::write(dir.join("app.py"), "def home():\n    return 'hi'\n").unwrap();
    let (compliance, json) = report(&dir, ANSWERS);
    std::fs::remove_dir_all(&dir).ok();

    assert_not_credited(&compliance);
    // V8.3.1 named server/auth.py, which the app does not have.
    let report: serde_json::Value = serde_json::from_str(&json).expect("report.json");
    let never_built: Vec<&serde_json::Value> = report["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter(|f| f["rule_id"] == "design.planned-never-built")
        .collect();
    assert_eq!(never_built.len(), 1, "{json}");
    assert_eq!(
        never_built[0]["requirement_ids"],
        serde_json::json!(["V8.3.1"])
    );
    assert!(
        never_built[0]["description"]
            .as_str()
            .is_some_and(|d| d.contains("`server/auth.py`")),
        "{}",
        never_built[0]
    );
    // V2.2.2 named app.py, which is there: due an answer, still not credited.
    assert!(
        json.contains("1 design decision planned, and the file is there now")
            && json.contains("V2.2.2 (in `app.py`)"),
        "{json}"
    );
    // V15.3.1 named nothing, so there is nothing to look for.
    assert!(
        json.contains("1 design decision planned, with no file named"),
        "{json}"
    );
    assert!(!json.contains("planned, not built yet"), "{json}");
}

#[test]
fn a_dependency_list_with_no_source_read_is_code_too() {
    // The same test the technology answers use: a dependency manifest is the app begun, even in a
    // language `sv` cannot read the source of, so a plan is held to from then on.
    let dir = fresh("manifest-only");
    std::fs::write(
        dir.join("package.json"),
        r#"{ "name": "notes", "version": "1.0.0", "dependencies": { "express": "4.19.2" } }"#,
    )
    .unwrap();
    let (compliance, json) = report(&dir, ANSWERS);
    std::fs::remove_dir_all(&dir).ok();

    assert_not_credited(&compliance);
    assert!(json.contains("\"design.planned-never-built\""), "{json}");
    assert!(!json.contains("planned, not built yet"), "{json}");
}
