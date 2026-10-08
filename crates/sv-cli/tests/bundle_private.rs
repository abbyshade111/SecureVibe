//! `sv bundle` writes the report on its way into the zip into a private folder of the run's own,
//! and leaves nothing in the system's temporary folder (the review of 8 October 2026, item 6;
//! ADR-017, Later). The temporary folder is pointed at an empty folder of this test's own through
//! `TMPDIR`, so what the bundle leaves there is all that is there.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn the_bundle_leaves_nothing_in_the_temporary_folder_and_makes_its_zip() {
    let app = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/partly-passing");
    let root = std::env::temp_dir().join(format!("sv-bundle-private-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let temp = root.join("tmp");
    let out = root.join("out");
    std::fs::create_dir_all(&temp).unwrap();
    std::fs::create_dir_all(&out).unwrap();
    let zip = out.join("app.zip");
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .env("TMPDIR", &temp)
        .arg("bundle")
        .arg(&app)
        .arg("--out")
        .arg(&zip)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(zip.is_file(), "the zip was written");
    let left: Vec<String> = std::fs::read_dir(&temp)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(left.is_empty(), "left in the temporary folder: {left:?}");
    std::fs::remove_dir_all(&root).ok();
}
