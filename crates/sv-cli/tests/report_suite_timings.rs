//! `sv report --run` times each suite of questions to the running app, and the app's own tests,
//! in `report.json`'s `timings` (backlog 226, part 2, item 13). Real containers and the real
//! binary. With no container backend, the app is not run and no suite is timed; where CI says one
//! must be here (`SV_REQUIRE_BACKEND=1`), its absence is a failure.

use serde_json::Value;
use std::path::Path;
use std::process::Command;

#[test]
fn each_suite_and_the_app_s_own_tests_are_timed_in_the_report() {
    let app = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/tested-notes");
    let out = std::env::temp_dir().join(format!("sv-suite-timings-{}", std::process::id()));
    std::fs::remove_dir_all(&out).ok();
    let ran = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args([
            "report",
            app.to_str().unwrap(),
            "--run",
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let json: Value = serde_json::from_str(
        &std::fs::read_to_string(out.join("report.json")).expect("report.json is written"),
    )
    .unwrap();
    std::fs::remove_dir_all(&out).ok();
    let suites: Vec<&str> = json["timings"]
        .as_array()
        .expect("timings")
        .iter()
        .filter_map(|t| t["what"].as_str())
        .filter_map(|what| what.strip_prefix(sv_report::SUITE_TIMING))
        .collect();
    if sv_run::detect().is_err() {
        assert_ne!(
            std::env::var("SV_REQUIRE_BACKEND").as_deref(),
            Ok("1"),
            "SV_REQUIRE_BACKEND=1 and there is no container backend here"
        );
        println!("no container backend here; checking that no suite is said to be timed");
        assert!(suites.is_empty(), "{suites:?}");
        return;
    }
    // The setup: the app was started, so the times stand for a real run.
    assert_eq!(
        json["run_status"]["state"],
        "started",
        "the app was not started: {}\n{}",
        json["run_status"],
        String::from_utf8_lossy(&ran.stderr)
    );
    assert_eq!(
        suites,
        [
            "the questions asked as somebody not signed in",
            "the app's own tests"
        ],
        "{}",
        json["timings"]
    );
}
