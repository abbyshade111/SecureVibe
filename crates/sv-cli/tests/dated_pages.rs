//! Every page of a report, and its SARIF, says when its run started and which run it was, matching
//! `report.json` (backlog 226, part 2, item 12): pages read apart can be told to be of one run.

use std::path::Path;
use std::process::Command;

fn report(out: &Path) {
    let app = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/tested-notes");
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
}

#[test]
fn every_page_and_the_sarif_name_the_run_and_its_start() {
    let root = std::env::temp_dir().join(format!("sv-dated-pages-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let (one, two) = (root.join("one"), root.join("two"));
    report(&one);
    report(&two);
    let record = |out: &Path| {
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap())
                .unwrap();
        json["run_record"].clone()
    };
    let (first, second) = (record(&one), record(&two));
    let id = first["run_id"].as_str().expect("a run id").to_owned();
    let started = first["started"].as_str().unwrap().to_owned();
    assert_eq!(id.len(), 12, "{id}");
    assert_ne!(
        Some(id.as_str()),
        second["run_id"].as_str(),
        "two runs, one id"
    );
    for page in ["report.html", "compliance.md", "security.md"] {
        let text = std::fs::read_to_string(one.join(page)).unwrap();
        assert!(
            text.contains(&format!("{started}, run {id}")),
            "{page} does not say which run it is of"
        );
    }
    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(one.join("findings.sarif")).unwrap())
            .unwrap();
    let invocation = &sarif["runs"][0]["invocations"][0];
    assert_eq!(invocation["startTimeUtc"], started.as_str());
    assert_eq!(invocation["properties"]["runId"], id.as_str());
    std::fs::remove_dir_all(&root).ok();
}
