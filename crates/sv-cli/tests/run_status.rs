//! `sv report` says whether it started the app, in its first line after the files it wrote.
//!
//! Item 9 of the owner's first build from scratch: the AI coding tool had to infer from the counts
//! whether `--run` had started the app. Neither case here needs a container: without `--run`
//! nothing is started, and with it a manifest that says nothing about how to run the app cannot
//! be started, which is said rather than left to be noticed.

use serde_json::Value;
use std::process::Command;

fn report(name: &str, run: bool) -> (String, Value) {
    report_with(name, run, "")
}

fn report_with(name: &str, run: bool, manifest_extra: &str) -> (String, Value) {
    let dir = std::env::temp_dir().join(format!("sv-run-status-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("stackvet.toml"),
        format!("manifest-version = 1\n[app]\nname = \"x\"\n{manifest_extra}"),
    )
    .unwrap();
    std::fs::write(dir.join("app.py"), "print('hi')\n").unwrap();
    let out = dir.join("report");
    let mut args = vec![
        "report",
        dir.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ];
    if run {
        args.push("--run");
    }
    let done = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(&args)
        .output()
        .expect("sv runs");
    // With --run and an app that cannot be started, 2: the checks of the running app were asked for and
    // none ran (DESIGN, "Exit codes for CI"). Without --run, 0.
    assert_eq!(
        done.status.code(),
        Some(if run { 2 } else { 0 }),
        "{}",
        String::from_utf8_lossy(&done.stderr)
    );
    let stdout = String::from_utf8(done.stdout).unwrap();
    let json: Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap()).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    (stdout, json)
}

/// The line after the list of files written, which is where a reader looks first.
fn first_line_after_the_files(stdout: &str) -> &str {
    stdout
        .split("\n\n")
        .nth(1)
        .map(|p| p.lines().next().unwrap_or(""))
        .unwrap_or("")
}

#[test]
fn without_run_it_says_the_app_was_not_started_and_how_to_start_it() {
    let (stdout, json) = report("not-asked", false);
    assert_eq!(
        first_line_after_the_files(&stdout),
        "The app was not started. `sv report` does not start the app unless you pass --run.",
        "{stdout}"
    );
    assert_eq!(
        json["run_status"]["state"], "not-asked",
        "{}",
        json["run_status"]
    );
}

#[test]
fn with_run_and_nothing_to_run_it_says_it_could_not_start_and_why() {
    let (stdout, json) = report("could-not-start", true);
    let line = first_line_after_the_files(&stdout);
    assert!(
        line.starts_with("--run was given, and the app could not be started. "),
        "{stdout}"
    );
    assert!(
        line.len() > "--run was given, and the app could not be started. ".len() + 10,
        "{line}"
    );
    assert_eq!(json["run_status"]["state"], "could-not-start");
    assert!(
        json["run_status"]["why"]
            .as_str()
            .is_some_and(|w| !w.is_empty()),
        "{}",
        json["run_status"]
    );
}

#[test]
fn a_run_section_that_is_not_enough_to_start_the_app_is_said_too() {
    // An image and no start command: asked for, and not startable.
    let (stdout, json) = report_with(
        "half-run",
        true,
        "[stack.run]\nimage = \"python:3.12-slim\"\n",
    );
    assert!(
        first_line_after_the_files(&stdout)
            .starts_with("--run was given, and the app could not be started. "),
        "{stdout}"
    );
    assert_eq!(json["run_status"]["state"], "could-not-start");
}
