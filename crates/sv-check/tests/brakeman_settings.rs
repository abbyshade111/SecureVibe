//! Brakeman is given an empty settings file of `sv`'s own, so the app's `config/brakeman.yml` is
//! never read (the review of 8 October 2026, item 2). Brakeman reads the first settings *file* it
//! finds, `-c`'s before the app's, which is why `-c /dev/null` (not a file) never helped.
//!
//! Needs the real Brakeman: without it on `PATH` this says so and checks nothing. Run here on 8
//! October 2026 with Brakeman 8.1.0, where the control run without `-c` honored the planted
//! `skip_checks` and the run through `sv` did not.

mod scratch;

use scratch::Scratch;
use std::path::PathBuf;
use std::process::Command;
use sv_check::adapters::{self, Adapters};

fn fixture_app() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/brakeman/app")
}

fn real_adapters() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json")
}

fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// The rule ids in a SARIF file Brakeman wrote.
fn reported(sarif: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(sarif).unwrap();
    let mut ids: Vec<String> = v["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["ruleId"].as_str().unwrap().to_owned())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

#[test]
fn the_apps_own_settings_file_is_not_read_when_brakeman_really_runs() {
    let adapters = Adapters::load(&real_adapters()).unwrap();
    let brakeman = adapters
        .all()
        .iter()
        .find(|a| a.id == "brakeman")
        .unwrap()
        .clone();
    if !adapters::is_installed(&brakeman) {
        println!("brakeman is not installed here; the real run is skipped");
        return;
    }
    let dir = Scratch::new("brakeman-settings");
    let app = dir.join("app");
    copy_tree(&fixture_app(), &app);
    // The plant: the app's settings file turns the SQL injection check off.
    std::fs::write(
        app.join("config/brakeman.yml"),
        "---\n:skip_checks:\n- CheckSQL\n",
    )
    .unwrap();

    // The control: Brakeman run as the entry ran it before, without `-c`, reads the file and
    // reports no SQL injection in an app that has one.
    let bare = dir.join("bare.sarif");
    let out = Command::new("brakeman")
        .args(["--format", "sarif", "--output"])
        .arg(&bare)
        .args(["--no-progress", "--quiet"])
        .arg(&app)
        .output()
        .expect("brakeman runs");
    assert!(
        out.status.code() == Some(3),
        "the control run warns of something: {:?}",
        out.status
    );
    let control = reported(&std::fs::read_to_string(&bare).unwrap());
    assert!(
        !control.contains(&"BRAKE0000".to_owned()),
        "the setup: the planted skip_checks hid the SQL injection from a bare run: {control:?}"
    );
    assert!(
        control.len() > 5,
        "the control run still reported the rest: {control:?}"
    );

    // Through `sv`: the same app, the same Brakeman, and the SQL injection is reported, because
    // Brakeman read `sv`'s empty settings file and not the app's.
    let run = adapters::run_all(
        &adapters,
        &app,
        &["ruby".to_owned()],
        &Default::default(),
        &dir,
        &sv_check::secrets::SecretRules::load(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/secret-rules.json"),
        )
        .unwrap(),
    );
    // Every tool for Ruby runs; only Brakeman's outcome is this test's.
    let brakeman_not_run: Vec<_> = run
        .not_run
        .iter()
        .filter(|(id, _)| id == "brakeman")
        .collect();
    assert!(brakeman_not_run.is_empty(), "{brakeman_not_run:?}");
    assert!(run.ran.contains(&"brakeman".to_owned()), "{:?}", run.ran);
    let sql: Vec<_> = run
        .findings
        .iter()
        .filter(|f| f.rule_id == "brakeman.BRAKE0000")
        .collect();
    assert!(
        !sql.is_empty(),
        "the SQL injection the app's settings file would hide is reported: {:?}",
        run.findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}
