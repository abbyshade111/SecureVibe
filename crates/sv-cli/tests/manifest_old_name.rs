//! An app whose manifest is still `securevibe.toml` is read as it was (ADR-062): `sv report` runs,
//! and the report and the terminal say once that the old name was read. A folder with both names
//! is refused with its reason, and an app with the new name alone gets no such note.

use std::path::{Path, PathBuf};
use sv_frameworks::names::{MANIFEST, OLD_MANIFEST};
use sv_scan::ecosystems::DEFAULT_REPORT_DIR;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-old-manifest-{name}-{}", std::process::id()));
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

/// A copy of the example app `partly-passing`, its manifest under `name`, with no report folder.
fn app_named(root: &Path, name: &str) -> PathBuf {
    let from = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/partly-passing");
    let app = root.join("app");
    copy(&from, &app);
    std::fs::remove_dir_all(app.join(DEFAULT_REPORT_DIR)).ok();
    std::fs::rename(app.join(MANIFEST), app.join(name)).unwrap();
    app
}

fn report(app: &Path) -> (Option<i32>, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(app)
        .output()
        .unwrap();
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn the_old_name_is_read_and_said_once_in_the_report_and_at_the_terminal() {
    let root = scratch("old");
    let app = app_named(&root, OLD_MANIFEST);
    assert!(
        app.join(OLD_MANIFEST).is_file() && !app.join(MANIFEST).exists(),
        "the setup"
    );
    let (code, said) = report(&app);
    assert!(code.is_some_and(|c| c < 2), "{said}");
    let json = std::fs::read_to_string(app.join(DEFAULT_REPORT_DIR).join("report.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        value["manifest_file"], OLD_MANIFEST,
        "the report names the file it read"
    );
    let gaps = value["gaps"].as_array().unwrap();
    let about_the_name: Vec<&serde_json::Value> = gaps
        .iter()
        .filter(|g| {
            g["why"]
                .as_str()
                .is_some_and(|w| w.contains("read under its old name"))
        })
        .collect();
    assert_eq!(about_the_name.len(), 1, "said once in the report: {gaps:?}");
    assert!(
        about_the_name[0]["why"]
            .as_str()
            .unwrap()
            .contains(MANIFEST),
        "the gap names the new name to rename to"
    );
    assert_eq!(
        said.matches("read under its old name").count(),
        1,
        "said once at the terminal: {said}"
    );
    // A finding the manifest's answers made points at the file by the name it has.
    let findings = value["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .all(|f| f["location"]["file"].as_str() != Some(MANIFEST)),
        "no finding points at a file this app does not have: {findings:?}"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn both_names_at_once_are_refused_with_the_reason() {
    let root = scratch("both");
    let app = app_named(&root, OLD_MANIFEST);
    std::fs::copy(app.join(OLD_MANIFEST), app.join(MANIFEST)).unwrap();
    let (code, said) = report(&app);
    assert_eq!(code, Some(3), "sv itself refuses: {said}");
    assert!(
        said.contains("two manifests are two answers"),
        "the reason is given: {said}"
    );
    assert!(
        !app.join(DEFAULT_REPORT_DIR).exists(),
        "nothing was written"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn the_new_name_alone_gets_no_note() {
    let root = scratch("new");
    let app = app_named(&root, MANIFEST);
    let (code, said) = report(&app);
    assert!(code.is_some_and(|c| c < 2), "{said}");
    assert!(!said.contains("read under its old name"), "{said}");
    let json = std::fs::read_to_string(app.join(DEFAULT_REPORT_DIR).join("report.json")).unwrap();
    assert!(
        !json.contains("read under its old name"),
        "no note in the report"
    );
    assert!(
        json.contains(&format!("\"manifest_file\": \"{MANIFEST}\"")),
        "{json}"
    );
    std::fs::remove_dir_all(&root).ok();
}
