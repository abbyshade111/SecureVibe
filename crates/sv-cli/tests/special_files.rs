//! A named pipe in the app is named and never opened: `sv check`, `sv report`, and `sv bundle` each
//! finish, and say it was not read (deep review S12). Before, the first check to read it waited forever.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Runs `sv` with `args`, and fails the test if it is still running after a minute: the fault this
/// guards is a hang, which would otherwise hang the test with it.
fn sv_within_a_minute(args: &[&str]) -> (bool, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sv runs");
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(60) {
            child.kill().ok();
            panic!("sv {} was still running after a minute", args.join(" "));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// The Flask example, copied, with a named pipe beside its code.
fn app_with_a_pipe(tag: &str) -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("sv-special-{tag}-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let app = root.join("app");
    std::fs::create_dir_all(&app).unwrap();
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/flask-booking");
    for entry in std::fs::read_dir(example).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), app.join(entry.file_name())).unwrap();
        }
    }
    let made = Command::new("mkfifo")
        .arg(app.join("events.pipe"))
        .status()
        .expect("mkfifo runs");
    assert!(made.success());
    let kind = std::fs::symlink_metadata(app.join("events.pipe"))
        .unwrap()
        .file_type();
    assert!(!kind.is_file() && !kind.is_symlink(), "the plant is a pipe");
    (root, app)
}

#[test]
fn sv_check_finishes_and_names_the_pipe() {
    let (root, app) = app_with_a_pipe("check");
    let (_, said) = sv_within_a_minute(&["check", app.to_str().unwrap()]);
    std::fs::remove_dir_all(&root).ok();
    assert!(said.contains("not an ordinary file"), "{said}");
    assert!(said.contains("events.pipe"), "{said}");
}

#[test]
fn sv_report_finishes_and_lists_the_pipe_as_a_gap() {
    let (root, app) = app_with_a_pipe("report");
    let out = root.join("report");
    let (ok, said) = sv_within_a_minute(&[
        "report",
        app.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok, "{said}");
    let json = std::fs::read_to_string(out.join("report.json")).unwrap();
    std::fs::remove_dir_all(&root).ok();
    let report: serde_json::Value = serde_json::from_str(&json).unwrap();
    let gaps = report["gaps"].as_array().unwrap();
    assert!(
        gaps.iter().any(|g| {
            g["what"].as_str().unwrap().contains("not an ordinary file")
                && g["why"].as_str().unwrap().contains("events.pipe")
        }),
        "{gaps:?}"
    );
    // And the checks that read the app's files say they read only part of it.
    assert!(
        json.contains("not ordinary files were not opened"),
        "no check said it read only part of the app"
    );
}

#[test]
fn sv_bundle_finishes_and_leaves_the_pipe_out_saying_why() {
    let (root, app) = app_with_a_pipe("bundle");
    let zip = root.join("out.zip");
    let (ok, said) = sv_within_a_minute(&[
        "bundle",
        app.to_str().unwrap(),
        "--out",
        zip.to_str().unwrap(),
    ]);
    std::fs::remove_dir_all(&root).ok();
    assert!(ok, "{said}");
    assert!(said.contains("events.pipe"), "{said}");
    assert!(said.contains("not an ordinary file"), "{said}");
}
