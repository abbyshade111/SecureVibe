//! A data file `sv` ships that does not parse says it most likely belongs to another `sv`, what to
//! do, and that nothing about the app was checked (backlog 226, part 2, item 16).

use std::path::Path;
use std::process::Command;

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

#[test]
fn a_data_file_that_does_not_parse_says_what_it_means_and_what_to_do() {
    let root = std::env::temp_dir().join(format!("sv-data-not-understood-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let data = root.join("data");
    copy(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data"),
        &data,
    );
    std::fs::write(data.join("secret-rules.json"), "{ \"rules\": [ ").unwrap();
    let app = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/tested-notes");
    let out = root.join("report");
    let ran = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args([
            "report",
            app.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .env("SV_DATA_DIR", &data)
        .output()
        .unwrap();
    std::fs::remove_dir_all(&root).ok();
    let said = String::from_utf8_lossy(&ran.stderr);
    assert!(!ran.status.success(), "{said}");
    for words in [
        "secret-rules.json is one of the data files `sv` ships",
        "belongs to another version of `sv`",
        "SV_DATA_DIR",
        "Nothing about the app was checked.",
    ] {
        assert!(said.contains(words), "missing {words:?} in:\n{said}");
    }
}
