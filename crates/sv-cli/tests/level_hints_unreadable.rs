//! A hints file `sv` cannot read is a gap in the report, where the AI coding tool reading it through
//! MCP sees it, not a line on stderr nobody does (backlog 226, part 1, item 6).

use std::path::{Path, PathBuf};
use std::process::Command;

fn copy(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            copy(&path, &to.join(entry.file_name()));
        } else {
            std::fs::copy(&path, to.join(entry.file_name())).unwrap();
        }
    }
}

fn level_one_app(root: &Path) -> PathBuf {
    let app = root.join("app");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(
        app.join("stackvet.toml"),
        "manifest-version = 1\n\n[app]\nname = \"Tracker\"\ndescription = \"Tracker.\"\n\
         audience = \"just-me\"\ndeployment = \"internet\"\n\n[stack]\nlanguages = [\"python\"]\n\n\
         [data]\ncategories = []\n",
    )
    .unwrap();
    std::fs::write(app.join("app.py"), "print('hello')\n").unwrap();
    app
}

#[test]
fn a_hints_file_that_cannot_be_read_is_a_gap_in_the_report() {
    let root = std::env::temp_dir().join(format!("sv-hints-unreadable-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let data = root.join("data");
    copy(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data"),
        &data,
    );
    std::fs::write(data.join("level-hints.json"), "not json").unwrap();
    let app = level_one_app(&root);
    let out = root.join("report");
    let ran = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args([
            "report",
            app.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .env("SV_DATA_DIR", &data)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&ran.stderr).into_owned();
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap()).unwrap();
    std::fs::remove_dir_all(&root).ok();
    assert_eq!(json["target_level"], 1, "the setup: held to level 1");
    let gaps = json["gaps"].as_array().expect("gaps");
    let gap = gaps
        .iter()
        .find(|g| {
            g["what"]
                .as_str()
                .is_some_and(|w| w.contains("answers that set the level"))
        })
        .unwrap_or_else(|| panic!("no gap for the hints file: {gaps:?}\n{stderr}"));
    assert!(
        gap["why"].as_str().unwrap().contains("level-hints.json"),
        "{gap}"
    );
}
