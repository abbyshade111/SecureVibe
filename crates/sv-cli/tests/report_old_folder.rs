//! An app reported on before the rename (ADR-062) has a `securevibe-report` folder with the old
//! marker. `sv report` writes into that folder, under the new marker, rather than leaving it behind
//! and making a second one; an app with neither folder gets the new name.

use std::path::{Path, PathBuf};
use sv_frameworks::names;
use sv_scan::ecosystems::{DEFAULT_REPORT_DIR, REPORT_MARKER};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-old-folder-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn copy(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            copy(&path, &to.join(entry.file_name()));
        } else {
            std::fs::copy(&path, to.join(entry.file_name())).unwrap();
        }
    }
}

/// A copy of the example app `partly-passing`, with no report folder of either name.
fn app_in(root: &Path) -> PathBuf {
    let from = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/partly-passing");
    let app = root.join("app");
    copy(&from, &app);
    std::fs::remove_dir_all(app.join(DEFAULT_REPORT_DIR)).ok();
    std::fs::remove_dir_all(app.join(names::OLD_REPORT_DIR)).ok();
    app
}

fn report(app: &Path) -> String {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(app)
        .output()
        .unwrap();
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.code().is_some_and(|c| c < 2),
        "the setup: sv report did not finish: {said}"
    );
    said
}

#[test]
fn a_folder_from_before_the_rename_is_written_over_under_the_new_marker() {
    let root = scratch("old");
    let app = app_in(&root);
    let old = app.join(names::OLD_REPORT_DIR);
    std::fs::create_dir_all(&old).unwrap();
    std::fs::write(old.join(names::OLD_REPORT_MARKER), "sv\n").unwrap();
    std::fs::write(old.join("report.json"), "{}\n").unwrap();
    assert!(old.join("report.json").is_file(), "the setup");
    let said = report(&app);
    assert!(
        old.join("report.json").is_file()
            && std::fs::read_to_string(old.join("report.json")).unwrap() != "{}\n",
        "the old folder was not written over: {said}"
    );
    assert!(
        !app.join(DEFAULT_REPORT_DIR).exists(),
        "a second folder was made beside the old one: {said}"
    );
    assert!(
        old.join(REPORT_MARKER).is_file(),
        "the marker was not rewritten under the new name"
    );
    assert!(
        !old.join(names::OLD_REPORT_MARKER).exists(),
        "the old marker was left beside the new one"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn an_app_with_no_report_folder_gets_the_new_name() {
    let root = scratch("fresh");
    let app = app_in(&root);
    let said = report(&app);
    assert!(
        app.join(DEFAULT_REPORT_DIR).join("report.json").is_file(),
        "{said}"
    );
    assert!(
        !app.join(names::OLD_REPORT_DIR).exists(),
        "the old name was written for a new app: {said}"
    );
    std::fs::remove_dir_all(&root).ok();
}
