//! What `sv report --tools` says on screen when the tools it was asked to run are not there.
//!
//! Gap analysis 5.3: with no outside tool installed it said nothing on screen and exited 0, so a
//! run where none of them ran read as one where they had. By default that still exits 0 (ADR-029);
//! the screen now says which did not run and how to install each, once, whatever the status.

use std::path::{Path, PathBuf};
use std::process::Command;

const SV: &str = env!("CARGO_BIN_EXE_sv");

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-tools-screen-{tag}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    dir
}

/// `sv report --tools` on the Flask example with nothing on the PATH, so no tool can be found.
fn report(dir: &Path, extra: &[&str]) -> (Option<i32>, String) {
    let app = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/flask-booking");
    let out = Command::new(SV)
        .arg("report")
        .arg(&app)
        .arg("--tools")
        .arg("--out")
        .arg(dir.join("report"))
        .args(extra)
        .env("PATH", dir.join("bin"))
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn tools_that_did_not_run_are_named_on_screen_with_how_to_install_them() {
    let dir = scratch("default");
    let (code, said) = report(&dir, &[]);
    let (strict, strict_said) = report(&dir, &["--fail-on", "not-assessed"]);
    std::fs::remove_dir_all(&dir).ok();

    assert_eq!(
        code,
        Some(0),
        "not running a tool is not a failure by default: {said}"
    );
    assert!(said.contains("Asked for, and not all of it ran"), "{said}");
    for tool in ["bandit", "semgrep", "codeql-python"] {
        assert!(
            said.contains(&format!("{tool} did not run")),
            "{tool}: {said}"
        );
    }
    // The hint for this kind of computer: `pip install` is refused on many (data/adapters.json,
    // `install_on`).
    let semgrep_hint = if cfg!(target_os = "macos") {
        "run `brew install semgrep`"
    } else if cfg!(target_os = "linux") {
        "run `pipx install semgrep`"
    } else {
        "run `pip install semgrep`"
    };
    assert!(
        said.contains(&format!("To install it, {semgrep_hint}")),
        "{said}"
    );
    // CodeQL's install is steps in words, not a command to quote.
    assert!(
        said.contains("To install it, download the CodeQL bundle"),
        "{said}"
    );
    assert!(!said.contains("`download"), "{said}");

    // When the status already lists them, they are said once.
    assert_eq!(strict, Some(2), "{strict_said}");
    assert_eq!(
        strict_said.matches("semgrep did not run").count(),
        1,
        "{strict_said}"
    );
}
