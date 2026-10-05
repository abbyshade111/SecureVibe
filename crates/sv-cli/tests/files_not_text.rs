//! A file that holds no text, and a file that is not text, each said for what it is (deep review
//! H22). Before, one `.DS_Store` left the credential scan partial for good, and the report said only
//! "1 file not read while looking for credentials", so an AI tool went searching for which.

use std::path::{Path, PathBuf};
use std::process::Command;

fn sv(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(args)
        .output()
        .expect("sv runs");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The Flask example, copied, with what `plant` adds beside its code.
fn app_with(tag: &str, plant: &[(&str, &[u8])]) -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("sv-not-text-{tag}-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let app = root.join("app");
    std::fs::create_dir_all(&app).unwrap();
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/flask-booking");
    for entry in std::fs::read_dir(example).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), app.join(entry.file_name())).unwrap();
        }
    }
    for (name, bytes) in plant {
        std::fs::write(app.join(name), bytes).unwrap();
    }
    (root, app)
}

const DS_STORE: &[u8] = b"\x00\x00\x00\x01Bud1\x00\x00\x10\x00";
const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
const BINARY: &[u8] = b"\x7fELF\x02\x01\x01\x00\x00\xff\x80\x9c";

fn credential_gap(report: &serde_json::Value) -> Option<String> {
    report["gaps"].as_array().unwrap().iter().find_map(|g| {
        g["what"]
            .as_str()
            .filter(|w| w.contains("not read while looking for credentials"))
            .map(|w| format!("{w}: {}", g["why"].as_str().unwrap_or("")))
    })
}

#[test]
fn an_image_and_a_ds_store_are_named_and_leave_no_gap() {
    let (root, app) = app_with("named", &[(".DS_Store", DS_STORE), ("logo.png", PNG)]);
    let check = sv(&["check", app.to_str().unwrap()]);
    let out = root.join("report");
    sv(&[
        "report",
        app.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    let json = std::fs::read_to_string(out.join("report.json")).unwrap();
    std::fs::remove_dir_all(&root).ok();
    // `sv check` names both, and what each is.
    assert!(
        check.contains(".DS_Store — a macOS Finder settings file"),
        "{check}"
    );
    assert!(check.contains("logo.png — a PNG image"), "{check}");
    assert!(
        !check.contains("not read, so nothing is claimed"),
        "{check}"
    );
    // The report keeps no credential gap for them.
    let report: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(credential_gap(&report), None);
}

#[test]
fn a_file_that_is_not_text_is_named_in_the_report_with_why() {
    let (root, app) = app_with("gap", &[(".DS_Store", DS_STORE), ("data.bin", BINARY)]);
    let out = root.join("report");
    sv(&[
        "report",
        app.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    let json = std::fs::read_to_string(out.join("report.json")).unwrap();
    std::fs::remove_dir_all(&root).ok();
    let report: serde_json::Value = serde_json::from_str(&json).unwrap();
    let gap = credential_gap(&report).expect("the binary file is a gap");
    assert!(gap.starts_with("1 file not read"), "{gap}");
    assert!(gap.contains("`data.bin` (not a text file)"), "{gap}");
    assert!(!gap.contains(".DS_Store"), "{gap}");
}
