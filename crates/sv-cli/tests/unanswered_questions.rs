//! A question the manifest asks, left unanswered, excludes nothing — end to end through the binary.
//!
//! Found on 26 September 2026 reviewing the manifest questions: with `ci-cd` and `iac` unanswered,
//! a scan that found no CI or infrastructure file answered "no" for the owner, and `sv report`
//! marked twelve requirements not applicable. An uploaded copy of an app often leaves those files
//! out, and a pipeline can be configured on a server, so not finding the file is not finding the
//! pipeline absent. The requirements belong in "not assessed", and the report has to say why.

use serde_json::Value;
use std::process::Command;

/// The twelve a manifest holding nothing but a name used to lose.
const TWELVE: [&str; 12] = [
    "AC.12.1",
    "AC.12.2",
    "AC.12.3",
    "AC.12.4",
    "AC.12.5",
    "AC.12.6",
    "AC.12.7",
    "AC.12.8",
    "AC.7.3",
    "AC.7.4",
    "AC.9.1",
    "SBD-AC-07",
];

fn ids(list: &Value) -> Vec<String> {
    list.as_array()
        .expect("a list")
        .iter()
        .filter_map(|x| x["id"].as_str().map(str::to_owned))
        .collect()
}

#[test]
fn a_bare_manifest_leaves_the_pipeline_requirements_not_assessed() {
    let dir = std::env::temp_dir().join(format!("sv-unanswered-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("securevibe.toml"),
        "manifest-version = 1\n[app]\nname = \"x\"\n",
    )
    .unwrap();
    // Something to read, so the scan is complete and really does find no CI file: the case where
    // the old code answered for the owner. An empty folder would have been "not assessed" anyway.
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

    let excluded = ids(&report["excluded"]);
    let undecided = ids(&report["undecided"]);
    for id in TWELVE {
        assert!(
            !excluded.contains(&id.to_owned()),
            "{id} excluded on silence"
        );
        assert!(
            undecided.contains(&id.to_owned()),
            "{id} is not among the not assessed"
        );
    }

    for name in ["ci-cd", "iac"] {
        let claim = report["claims"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("{name} is not among the claims"));
        assert_eq!(claim["state"], "unanswered", "{name}: {claim}");
        assert_eq!(
            claim["found_in_code"], false,
            "{name}: the setup, a scan that looked and found nothing"
        );
    }
}
