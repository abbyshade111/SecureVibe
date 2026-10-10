//! A run kept in history holds each requirement's status, and the report's statuses are exactly
//! those (ADR-083, part 1), through the real `sv`, with a home of its own.

use serde_json::Value;
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

#[test]
fn a_kept_run_holds_each_requirements_status_as_the_report_gave_it() {
    let root = std::env::temp_dir().join(format!("sv-history-statuses-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let app = root.join("app");
    copy(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/flask-booking"),
        &app,
    );
    std::fs::remove_dir_all(app.join(sv_scan::ecosystems::DEFAULT_REPORT_DIR)).ok();
    let sv = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_sv"))
            .args(args)
            .env("HOME", &home)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_DATA_HOME")
            .output()
            .unwrap()
    };
    assert!(sv(&["history", "on"]).status.success());
    let run = sv(&["report", app.to_str().unwrap()]);
    assert!(
        matches!(run.status.code(), Some(0..=2)),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let report: Value = serde_json::from_str(
        &std::fs::read_to_string(app.join("stackvet-report/report.json")).unwrap(),
    )
    .unwrap();
    // The one run kept, wherever history put it under this home.
    let kept: Vec<PathBuf> = walk(&home.join(".local/share/stackvet/history"))
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "json") && !p.ends_with("app.json"))
        .collect();
    assert_eq!(kept.len(), 1, "{kept:?}");
    let kept: Value = serde_json::from_str(&std::fs::read_to_string(&kept[0]).unwrap()).unwrap();
    std::fs::remove_dir_all(&root).ok();

    assert_eq!(kept["format"], 4);
    let in_report: Vec<(String, String)> = report["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["id"].as_str().unwrap().to_owned(),
                r["status"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let in_history: Vec<(String, String)> = kept["requirements"]
        .as_array()
        .expect("statuses kept")
        .iter()
        .map(|r| {
            (
                r["id"].as_str().unwrap().to_owned(),
                r["status"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    // The setup: the report has requirements, more than one kind of status among them.
    assert!(in_report.len() > 20, "{}", in_report.len());
    assert_eq!(in_history, in_report);
    // Only the id and the status: nothing of the requirement's text or the app's.
    for r in kept["requirements"].as_array().unwrap() {
        let keys: Vec<&String> = r.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["id", "status"], "{r}");
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}
