//! A corpus of known verdicts: what `sv report` concludes about each example app, requirement by requirement, held
//! to a snapshot beside this test (`tests/verdicts/<app>.json`). The honesty rule turned into a measurement
//! (BACKLOG, "From the end-of-day write-up of 8 October 2026: ideas for `sv` itself", item 2): a change that credits
//! more or finds less has to say why, by updating the snapshot in the same pull request.
//!
//! When a verdict changes on purpose, rerun with `SV_UPDATE_VERDICTS=1`, which rewrites the snapshots, and commit
//! them with the change. A new example app needs a snapshot the same way; the test fails until it has one.
//! Only the static report is held here (no run, no outside tools, no attestations), so the statuses that appear
//! are the ones a reading of the code can reach.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn verdicts_of(app: &Path) -> BTreeMap<String, String> {
    let out = std::env::temp_dir().join(format!(
        "sv-verdicts-{}-{}",
        app.file_name().unwrap().to_string_lossy(),
        std::process::id()
    ));
    std::fs::remove_dir_all(&out).ok();
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(app)
        .arg("--out")
        .arg(&out)
        .output()
        .expect("sv runs");
    let report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(out.join("report.json")).unwrap_or_else(|e| {
            panic!(
                "no report.json for {}: {e}\n{}{}",
                app.display(),
                String::from_utf8_lossy(&run.stdout),
                String::from_utf8_lossy(&run.stderr)
            )
        }),
    )
    .expect("report.json is JSON");
    std::fs::remove_dir_all(&out).ok();
    let requirements = report["requirements"]
        .as_array()
        .expect("report.json lists the requirements");
    assert!(
        requirements.len() > 100,
        "{} requirements read for {}; the setup did not work",
        requirements.len(),
        app.display()
    );
    requirements
        .iter()
        .map(|r| {
            (
                r["id"].as_str().unwrap().to_string(),
                r["status"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn every_example_app_gets_the_verdicts_its_snapshot_holds() {
    let examples = repo().join("examples");
    let snapshots = repo().join("crates/sv-cli/tests/verdicts");
    let update = std::env::var_os("SV_UPDATE_VERDICTS").is_some();
    let mut apps: Vec<PathBuf> = std::fs::read_dir(&examples)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    apps.sort();
    assert!(
        apps.len() >= 3,
        "the example apps are where this test expects them"
    );
    let mut problems = Vec::new();
    for app in &apps {
        let name = app.file_name().unwrap().to_string_lossy().to_string();
        let got = verdicts_of(app);
        let snapshot = snapshots.join(format!("{name}.json"));
        if update {
            std::fs::write(
                &snapshot,
                serde_json::to_string_pretty(&got).unwrap() + "\n",
            )
            .unwrap();
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&snapshot) else {
            problems.push(format!(
                "{name}: no snapshot at {}; run with SV_UPDATE_VERDICTS=1 to write one",
                snapshot.display()
            ));
            continue;
        };
        let expected: BTreeMap<String, String> = serde_json::from_str(&text).unwrap();
        let ids: std::collections::BTreeSet<&String> = expected.keys().chain(got.keys()).collect();
        for id in ids {
            match (expected.get(id), got.get(id)) {
                (Some(e), Some(g)) if e == g => {}
                (e, g) => problems.push(format!(
                    "{name}: {id} was {} and is now {}",
                    e.map(String::as_str).unwrap_or("absent"),
                    g.map(String::as_str).unwrap_or("absent")
                )),
            }
        }
    }
    assert!(
        problems.is_empty(),
        "{} verdict(s) differ from the snapshots. If the change is meant, rerun with SV_UPDATE_VERDICTS=1 and \
         commit the snapshots with it, saying why in the pull request:\n{}",
        problems.len(),
        problems.join("\n")
    );
}
