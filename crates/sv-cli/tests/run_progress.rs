//! A run of the app says each suite of questions, and the app's own tests, on stderr as each
//! begins (backlog 226, part 2, item 15). Real containers and the real binary. With no container
//! backend, nothing is started and nothing is said to be; where CI says one must be here
//! (`SV_REQUIRE_BACKEND=1`), its absence is a failure.

use std::path::Path;
use std::process::Command;

#[test]
fn a_run_says_each_suite_and_the_app_s_own_tests_as_each_begins() {
    let app = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/tested-notes");
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("run")
        .arg(&app)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let steps: Vec<&str> = stderr
        .lines()
        .filter(|l| l.starts_with("  now: "))
        .collect();
    if sv_run::detect().is_err() {
        assert_ne!(
            std::env::var("SV_REQUIRE_BACKEND").as_deref(),
            Ok("1"),
            "SV_REQUIRE_BACKEND=1 and there is no container backend here"
        );
        println!("no container backend here; checking that nothing is said to begin");
        assert!(steps.is_empty(), "{stderr}");
        return;
    }
    // The setup: the app was started and asked, so the lines stand for a real run.
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert_eq!(
        steps,
        [
            "  now: the questions asked as somebody not signed in",
            "  now: the app's own tests",
        ],
        "{stderr}"
    );
    assert!(
        !stdout.contains("  now: "),
        "progress went to stdout: {stdout}"
    );
}
