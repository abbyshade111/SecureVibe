//! Appendix C apart from the app's own requirements, through the binary: the numbers at the top
//! leave out what nothing reached, and the section says which rules the tool was given.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn the_flask_example_counts_appendix_c_apart_and_names_the_rules_given() {
    let app = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/flask-booking");
    let out = std::env::temp_dir().join(format!("sv-appendix-c-{}", std::process::id()));
    std::fs::remove_dir_all(&out).ok();
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args([
            "report",
            app.to_str().unwrap(),
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
    let said = String::from_utf8(run.stdout).unwrap();
    assert!(said.contains("are counted apart"), "{said}");

    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap()).unwrap();
    let requirements = report["requirements"].as_array().unwrap();
    assert!(
        !requirements
            .iter()
            .any(|r| r["id"].as_str().unwrap().starts_with("AC.") && r["status"] == "not-verified"),
        "no unreached Appendix C requirement is left in the app's own list"
    );
    let lines = report["ai_process"]["lines"].as_array().unwrap();
    assert!(!lines.is_empty());
    assert_eq!(
        report["counts"]["ai_process"].as_u64().unwrap() as usize,
        lines.len()
    );
    let route = |id: &str| {
        lines
            .iter()
            .find(|l| l["id"] == id)
            .unwrap_or_else(|| panic!("{id} is not in the section"))["route"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    // The keys rule cites AC.3.1; the Flask example says it has CI, so the workflow rules are given
    // and their AC.12 requirements are theirs.
    assert_eq!(route("AC.3.1"), "rules-given");
    assert_eq!(route("AC.12.1"), "rules-given");
    // A rule cites AC.4.1 too, and it is among the owner's questions, which is what settles it.
    assert_eq!(route("AC.4.1"), "your-decision");
    // Every one is still listed in compliance.md and report.html, and each headline says where.
    let compliance = std::fs::read_to_string(out.join("compliance.md")).unwrap();
    let html = std::fs::read_to_string(out.join("report.html")).unwrap();
    for page in [&compliance, &html] {
        assert!(page.contains("How the app is built with AI (OWASP AISVS Appendix C)"));
        assert!(page.contains("are counted apart"));
    }
    for l in lines {
        assert!(compliance.contains(l["id"].as_str().unwrap()));
    }
    std::fs::remove_dir_all(&out).ok();
}

#[test]
fn a_problem_recorded_by_hand_keeps_an_appendix_c_requirement_in_the_counts() {
    // The owner looked, and it is not done: that is a finding, and a finding is never set aside.
    let example = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/flask-booking");
    let app = std::env::temp_dir().join(format!("sv-appendix-c-hand-{}", std::process::id()));
    std::fs::remove_dir_all(&app).ok();
    std::fs::create_dir_all(&app).unwrap();
    for entry in std::fs::read_dir(&example).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), app.join(entry.file_name())).unwrap();
        }
    }
    let manifest = std::fs::read_to_string(app.join("stackvet.toml")).unwrap();
    let on = "2026-09-27";
    let entry = format!(
        "\"AC.4.1\" = {{ result = \"problem\", on = \"{on}\", by = \"owner\", how = \"Nobody but the AI tool has looked at the sign-in code.\" }}\n"
    );
    let manifest = if manifest.contains("[checked-by-hand]") {
        manifest.replace(
            "[checked-by-hand]\n",
            &format!("[checked-by-hand]\n{entry}"),
        )
    } else {
        format!("{manifest}\n[checked-by-hand]\n{entry}")
    };
    std::fs::write(app.join("stackvet.toml"), manifest).unwrap();
    let out = app.join("report-out");
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args([
            "report",
            app.to_str().unwrap(),
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
    let line = report["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "AC.4.1")
        .expect("a finding keeps AC.4.1 among the app's requirements");
    assert_eq!(line["status"], "needs-attention", "{line}");
    assert!(
        !report["ai_process"]["lines"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l["id"] == "AC.4.1")
    );
    std::fs::remove_dir_all(&app).ok();
}
