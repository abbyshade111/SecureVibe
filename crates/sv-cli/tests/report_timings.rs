//! A report says how long each stage of its run took, and names the slowest on its pages (backlog
//! 226, part 2, item 13).

use std::path::Path;
use std::process::Command;

#[test]
fn each_stage_is_timed_and_the_slowest_are_named() {
    let app = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/tested-notes");
    let out = std::env::temp_dir().join(format!("sv-report-timings-{}", std::process::id()));
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
    assert!(ran.status.code().is_some_and(|c| c < 3), "{ran:?}");
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap()).unwrap();
    let page = std::fs::read_to_string(out.join("report.html")).unwrap();
    let compliance = std::fs::read_to_string(out.join("compliance.md")).unwrap();
    std::fs::remove_dir_all(&out).ok();
    let timings = json["timings"].as_array().expect("timings in report.json");
    let stages: Vec<&str> = timings
        .iter()
        .map(|t| t["what"].as_str().unwrap())
        .take(sv_cli::REPORT_STAGES.len())
        .collect();
    assert_eq!(stages, sv_cli::REPORT_STAGES, "each stage, in order");
    assert!(timings.iter().all(|t| t["took_ms"].is_u64()), "{timings:?}");
    for (name, text) in [("report.html", &page), ("compliance.md", &compliance)] {
        assert!(
            text.contains("The slowest parts:"),
            "{name} does not name the slowest parts"
        );
    }
}
