//! What else a run read that can move a requirement is kept with it (ADR-083, part 3), through the
//! real `sv`, with a home of its own: two runs with the security notes changed between them are
//! not compared, and the page says that is why.

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

#[test]
fn a_change_to_the_security_notes_is_kept_and_named_as_why_two_runs_are_not_compared() {
    let root = std::env::temp_dir().join(format!("sv-history-inputs-{}", std::process::id()));
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
    let report = |notes: &str| {
        std::fs::write(app.join("security-notes.md"), notes).unwrap();
        let run = sv(&["report", app.to_str().unwrap()]);
        assert!(
            matches!(run.status.code(), Some(0..=2)),
            "{}",
            String::from_utf8_lossy(&run.stderr)
        );
        serde_json::from_str::<Value>(
            &std::fs::read_to_string(app.join("stackvet-report/report.json")).unwrap(),
        )
        .unwrap()
    };
    assert!(sv(&["history", "on"]).status.success());
    let first = report("# Security notes\n\nA first draft.\n");
    let second_notes = "# Security notes\n\nA second draft.\n";
    let decisions = "# Design decisions\n\nNone yet.\n";
    std::fs::write(app.join("design-decisions.md"), decisions).unwrap();
    let second = report(second_notes);

    // The report's own record holds each input's hash: the notes and the decisions as read (none
    // the first time), and the data folder this `sv` read, the same one this test finds.
    let inputs = &second["run_record"]["inputs"];
    assert_eq!(
        inputs["security_notes_sha256"],
        sv_cli::bundle::sha256(second_notes.as_bytes()),
        "{inputs}"
    );
    assert_eq!(
        inputs["design_decisions_sha256"],
        sv_cli::bundle::sha256(decisions.as_bytes()),
        "{inputs}"
    );
    assert_eq!(
        first["run_record"]["inputs"]["design_decisions_sha256"],
        Value::Null
    );
    let data = sv_cli::report_lock::data_sha256().expect("this test finds sv's data");
    assert_eq!(inputs["sv_data_sha256"], data, "{inputs}");
    assert_ne!(
        first["run_record"]["inputs"]["security_notes_sha256"],
        inputs["security_notes_sha256"]
    );

    // Each kept run holds the same.
    let kept: Vec<Value> = walk(&home.join(".local/share/stackvet/history"))
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "json") && !p.ends_with("app.json"))
        .map(|p| serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap())
        .collect();
    assert_eq!(kept.len(), 2);
    for run in &kept {
        assert_eq!(run["format"], 3);
        assert_eq!(run["inputs"]["sv_data_sha256"], data, "{run}");
    }

    // The page says why the second is not set against the first.
    let page = root.join("page.html");
    let made = sv(&[
        "dashboard",
        app.to_str().unwrap(),
        "--out",
        page.to_str().unwrap(),
    ]);
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    let pages: String = walk(&root)
        .into_iter()
        .filter(|p| !p.starts_with(&app) && p.extension().is_some_and(|e| e == "html"))
        .map(|p| std::fs::read_to_string(p).unwrap())
        .collect();
    std::fs::remove_dir_all(&root).ok();
    assert!(
        pages.contains("Not compared with the run before it: your security notes changed"),
        "{pages}"
    );
}

#[test]
fn the_data_hash_changes_with_a_files_content_or_name_and_not_otherwise() {
    let root = std::env::temp_dir().join(format!("sv-data-hash-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    std::fs::create_dir_all(root.join("frameworks")).unwrap();
    std::fs::write(root.join("frameworks/a.json"), "{}").unwrap();
    std::fs::write(root.join("b.json"), "[]").unwrap();
    let hash = || sv_cli::report_lock::folder_sha256(&root).unwrap();
    let before = hash();
    assert_eq!(hash(), before, "the same folder hashes the same");
    std::fs::write(root.join("b.json"), "[1]").unwrap();
    let changed = hash();
    assert_ne!(changed, before, "a file's content");
    std::fs::rename(root.join("b.json"), root.join("c.json")).unwrap();
    assert_ne!(hash(), changed, "a file's name");
    std::fs::remove_dir_all(&root).ok();
}
