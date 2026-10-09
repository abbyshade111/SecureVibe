//! History is kept under the app's real place, however the folder was named on the command line
//! (backlog 0120). Until 9 October 2026 `sv report .` kept every app's runs under one `.`, where
//! `sv history forget` and the dashboard, which ask by the real place, never found them.

use std::path::{Path, PathBuf};
use std::process::Command;
use sv_frameworks::paths::Canonical;

fn sv(root: &Path, here: &Path, args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .current_dir(here)
        .args(args)
        .env("HOME", root.join("home"))
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("RUST_BACKTRACE")
        .output()
        .unwrap();
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// A copy of the example app, under `name`.
fn app(root: &Path, name: &str) -> PathBuf {
    let from = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/notes-with-users");
    let dir = root.join("apps").join(name);
    copy(&from, &dir);
    std::fs::remove_dir_all(dir.join(sv_scan::ecosystems::DEFAULT_REPORT_DIR)).ok();
    dir.canonical().unwrap()
}

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

/// The app folders history holds, by the place each was kept for.
fn kept(root: &Path) -> Vec<String> {
    let history = root.join("home/.local/share/stackvet/history");
    let Ok(entries) = std::fs::read_dir(history) else {
        return Vec::new();
    };
    let mut places: Vec<String> = entries
        .flatten()
        .filter_map(|e| std::fs::read_to_string(e.path().join("app.json")).ok())
        .map(|t| {
            let v: serde_json::Value = serde_json::from_str(&t).unwrap();
            v["folder"].as_str().unwrap().to_owned()
        })
        .collect();
    places.sort();
    places
}

#[test]
fn two_apps_checked_from_inside_each_keep_their_own_history_and_forget_finds_it() {
    let root = std::env::temp_dir().join(format!("sv-history-where-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    std::fs::create_dir_all(root.join("home")).unwrap();
    let one = app(&root, "one");
    let two = app(&root, "two");

    let (on, said) = sv(&root, &root, &["history", "on"]);
    assert_eq!(on, Some(0), "{said}");
    for dir in [&one, &two] {
        let (_, said) = sv(&root, dir, &["report", "."]);
        assert!(
            dir.join(sv_scan::ecosystems::DEFAULT_REPORT_DIR)
                .join("report.json")
                .is_file(),
            "the setup: a report was written: {said}"
        );
    }
    let mut both = vec![one.display().to_string(), two.display().to_string()];
    both.sort();
    assert_eq!(kept(&root), both, "each app under its own real place");

    // Asked by its full path from elsewhere, and by a relative one, the history is found.
    let (code, said) = sv(&root, &root, &["history", "forget", one.to_str().unwrap()]);
    assert_eq!(code, Some(0), "{said}");
    assert!(said.contains("Deleted the history kept for"), "{said}");
    assert_eq!(kept(&root), [two.display().to_string()]);
    let (_, said) = sv(&root, &root, &["history", "forget", "apps/two"]);
    assert!(said.contains("Deleted the history kept for"), "{said}");
    assert!(kept(&root).is_empty());
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn an_app_named_by_a_relative_path_is_kept_under_its_full_one() {
    let root = std::env::temp_dir().join(format!("sv-history-relative-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    std::fs::create_dir_all(root.join("home")).unwrap();
    let one = app(&root, "one");
    sv(&root, &root, &["history", "on"]);
    let (_, said) = sv(&root, &root, &["report", "apps/./one"]);
    assert!(
        one.join(sv_scan::ecosystems::DEFAULT_REPORT_DIR)
            .join("report.json")
            .is_file(),
        "the setup: a report was written: {said}"
    );
    assert_eq!(kept(&root), [one.display().to_string()]);
    let (_, said) = sv(&root, &one, &["history", "forget", "."]);
    assert!(said.contains("Deleted the history kept for"), "{said}");
    assert!(kept(&root).is_empty());
    std::fs::remove_dir_all(&root).ok();
}
