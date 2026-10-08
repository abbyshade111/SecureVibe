//! A report folder from before the rename (ADR-062) is still `sv`'s own: its old marker, its old
//! lock, and its old default name are read as the new ones are.

use std::path::PathBuf;
use sv_frameworks::names;
use sv_scan::ecosystems::{
    DEFAULT_REPORT_DIR, REPORT_MARKER, has_report_marker, is_sv_output, marker_refused,
};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-old-names-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_folder_with_the_old_marker_and_only_report_files_is_svs_own() {
    let root = scratch("old-marker");
    let old = root.join("reports");
    std::fs::create_dir_all(&old).unwrap();
    std::fs::write(old.join(names::OLD_REPORT_MARKER), "sv\n").unwrap();
    std::fs::write(old.join(names::OLD_REPORT_LOCK), "").unwrap();
    std::fs::write(old.join("report.json"), "{}\n").unwrap();
    assert!(has_report_marker(&old));
    assert!(
        is_sv_output(&old),
        "the old marker and lock are names `sv` wrote"
    );
    assert!(!marker_refused(&old));
    // The control: the same folder under the new marker, and one holding a file of the app's.
    let new = root.join("new");
    std::fs::create_dir_all(&new).unwrap();
    std::fs::write(new.join(REPORT_MARKER), "sv\n").unwrap();
    std::fs::write(new.join("report.json"), "{}\n").unwrap();
    assert!(is_sv_output(&new));
    std::fs::write(old.join("notes.py"), "print(1)\n").unwrap();
    assert!(
        marker_refused(&old),
        "a file `sv` did not write is still refused under the old marker"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn the_old_default_folder_name_is_still_a_report_folder() {
    let root = scratch("old-dir");
    for name in [names::OLD_REPORT_DIR, DEFAULT_REPORT_DIR] {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("report.html"), "<html>\n").unwrap();
        assert!(is_sv_output(&dir), "{name}");
        std::fs::write(dir.join("app.py"), "print(1)\n").unwrap();
        assert!(marker_refused(&dir), "{name}");
    }
    assert_eq!(DEFAULT_REPORT_DIR, names::REPORT_DIR);
    assert_eq!(REPORT_MARKER, names::REPORT_MARKER);
    std::fs::remove_dir_all(&root).ok();
}
