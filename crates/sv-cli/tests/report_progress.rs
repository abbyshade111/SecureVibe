//! `sv report` says each stage on stderr as it starts, so a run of minutes is seen to be moving,
//! and leaves stdout as it was (backlog 226, part 2, item 15).

use std::path::Path;
use std::process::Command;

#[test]
fn each_stage_is_said_on_stderr_in_order() {
    let app = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/tested-notes");
    let out = std::env::temp_dir().join(format!("sv-report-progress-{}", std::process::id()));
    std::fs::remove_dir_all(&out).ok();
    let ran = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args([
            "report",
            app.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    std::fs::remove_dir_all(&out).ok();
    let stderr = String::from_utf8_lossy(&ran.stderr);
    let stdout = String::from_utf8_lossy(&ran.stdout);
    let said: Vec<&str> = stderr
        .lines()
        .filter(|l| l.starts_with("sv report: "))
        .collect();
    let stages = sv_cli::REPORT_STAGES;
    assert_eq!(said.len(), stages.len(), "{stderr}");
    for (n, (line, name)) in said.iter().zip(stages).enumerate() {
        assert_eq!(
            *line,
            format!("sv report: {} of {}, {name}", n + 1, stages.len())
        );
    }
    assert!(
        !stdout.contains("sv report: "),
        "progress went to stdout: {stdout}"
    );
}
