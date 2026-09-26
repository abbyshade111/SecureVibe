//! The MITRE ATLAS references reach the report through the binary, for an app that uses AI.
//!
//! The references are compiled into `sv` and attached to the threat rules where `sv report` loads
//! them; a test of the report library alone would pass with that step left out.

use serde_json::Value;
use std::process::Command;

#[test]
fn an_app_that_uses_ai_gets_the_reviewer_s_atlas_table() {
    let dir = std::env::temp_dir().join(format!("sv-atlas-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("securevibe.toml"),
        "manifest-version = 1\n[app]\nname = \"x\"\n[capabilities.ai]\nenabled = true\n",
    )
    .unwrap();
    std::fs::write(dir.join("app.py"), "print('hi')\n").unwrap();
    let out = dir.join("report");
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args([
            "report",
            dir.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .expect("sv runs");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap()).unwrap();
    let injection = report["threats"]
        .as_array()
        .expect("threats")
        .iter()
        .find(|t| t["id"] == "T-07")
        .expect("prompt injection applies to an app that uses AI");
    assert_eq!(injection["atlas"][0]["id"], "AML.T0051", "{injection}");
    assert_eq!(report["threat_atlas_release"], "2026.09");
    let md = std::fs::read_to_string(out.join("compliance.md")).unwrap();
    assert!(
        md.contains("For a security reviewer: these threats in MITRE ATLAS"),
        "{md}"
    );
    std::fs::remove_dir_all(&dir).ok();
}
