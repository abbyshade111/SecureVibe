//! Within the outside tools' stage, `sv report --tools` says each tool on stderr as it begins, so
//! the longest stage is not one line and then minutes of silence (backlog 226, part 2, item 15).
//! The suites of questions to a running app say themselves the same way, through the same line
//! (`sv_check::script`'s own tests, and `sv_run::RunPlan::on_step`).

use std::path::Path;
use std::process::Command;

#[test]
fn each_outside_tool_is_said_under_its_stage_on_stderr() {
    let app = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/flask-booking");
    let dir = std::env::temp_dir().join(format!("sv-report-steps-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    // Nothing on the PATH, so no tool is found and the run is quick; each is still begun on, and
    // said, before `sv` finds it missing.
    let ran = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(&app)
        .arg("--tools")
        .arg("--out")
        .arg(dir.join("report"))
        .env("PATH", dir.join("bin"))
        .output()
        .unwrap();
    std::fs::remove_dir_all(&dir).ok();
    let stderr = String::from_utf8_lossy(&ran.stderr);
    let stdout = String::from_utf8_lossy(&ran.stdout);
    let lines: Vec<&str> = stderr.lines().collect();
    let at = |stage: usize| {
        let prefix = format!("sv report: {stage} of ");
        lines
            .iter()
            .position(|l| l.starts_with(&prefix))
            .unwrap_or_else(|| panic!("no stage {stage}: {stderr}"))
    };
    let (tools, after) = (at(8), at(9));
    let steps: Vec<&str> = lines[tools + 1..after]
        .iter()
        .filter(|l| l.starts_with("  now: "))
        .copied()
        .collect();
    assert_eq!(
        steps,
        ["  now: Bandit", "  now: Semgrep", "  now: CodeQL (Python)"],
        "{stderr}"
    );
    assert!(
        !stdout.contains("  now: "),
        "progress went to stdout: {stdout}"
    );
}
