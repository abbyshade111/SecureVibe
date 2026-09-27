//! One walk of the app, end to end through the binary: a link is not followed and is named, and a
//! file too large to read is named rather than parsed or passed over.
//!
//! The fixture that found the first fault (review of 27 September 2026, item 1): `vendor-link` points
//! at a folder outside the app and `src/loop` at `..`. Before, `sv check` read the outside folder's
//! file and reported its finding at every level of the loop, about thirty times, under paths four
//! hundred characters long, and stopped only because the operating system refuses a link chain past
//! thirty-two.

use std::path::{Path, PathBuf};
use std::process::Command;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-one-walk-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn check(app: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("check")
        .arg(app)
        .output()
        .expect("sv runs");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn report(app: &Path) -> serde_json::Value {
    let out_dir = app.join("report");
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["report", app.to_str().unwrap(), "--out", out_dir.to_str().unwrap()])
        .output()
        .expect("sv runs");
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    serde_json::from_str(&std::fs::read_to_string(out_dir.join("report.json")).unwrap()).unwrap()
}

#[cfg(unix)]
#[test]
fn a_link_out_of_the_app_and_a_loop_are_named_once_and_never_read() {
    let root = scratch("links");
    let app = root.join("app");
    let outside = root.join("outside");
    std::fs::create_dir_all(app.join("src")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(app.join("src/app.py"), "print('hi')\n").unwrap();
    std::fs::write(
        app.join("securevibe.toml"),
        "manifest-version = 1\n[app]\nname = \"Links\"\n",
    )
    .unwrap();
    // A finding the code rules would raise, and a name the credential scan would flag, both outside.
    std::fs::write(
        outside.join("settings.py"),
        "import os\neval(os.environ['X'])\nOUTSIDE_MARKER = 'sv-outside-8f3a1c9d2e7b4f60'\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(&outside, app.join("vendor-link")).unwrap();
    std::os::unix::fs::symlink("..", app.join("src/loop")).unwrap();

    let said = check(&app);
    let json = report(&app);
    std::fs::remove_dir_all(&root).ok();

    // The setup: the app's own file was read, so an absence below is not the scan having read nothing.
    assert!(said.contains("Read 2 file"), "{said}");
    assert!(
        !said.contains("settings.py") && !said.contains("sv-outside"),
        "the file outside the app was read:\n{said}"
    );
    assert!(!said.contains("loop/src/loop"), "the loop was followed:\n{said}");
    assert!(
        said.contains("2 symbolic links were not followed")
            && said.contains("  src/loop")
            && said.contains("  vendor-link"),
        "{said}"
    );
    let gaps = json["gaps"].as_array().unwrap();
    let link_gap = gaps
        .iter()
        .find(|g| g["what"].as_str().unwrap_or("").contains("symbolic link"))
        .unwrap_or_else(|| panic!("no gap names the links: {gaps:?}"));
    assert!(link_gap["why"].as_str().unwrap().contains("vendor-link"));
    let findings = json["findings"].as_array().unwrap();
    assert!(
        findings.iter().all(|f| !f["location"]["file"]
            .as_str()
            .unwrap_or("")
            .contains("vendor-link")),
        "{findings:?}"
    );
}

#[test]
fn a_file_too_large_to_read_is_named_and_keeps_the_rules_from_claiming_a_clean_result() {
    let root = scratch("large");
    std::fs::write(
        root.join("securevibe.toml"),
        "manifest-version = 1\n[app]\nname = \"Large\"\n",
    )
    .unwrap();
    std::fs::write(root.join("app.py"), "print('hi')\n").unwrap();
    // Over the 2 MB limit, in a language the rules read: generated code, as a bundle is.
    let big = "x = 1\n".repeat(400_000);
    assert!(big.len() as u64 > sv_scan::files::MAX_FILE_BYTES);
    std::fs::write(root.join("bundle.py"), big).unwrap();

    let said = check(&root);
    let json = report(&root);
    std::fs::remove_dir_all(&root).ok();

    assert!(
        said.contains("bundle.py — larger than 2 MB"),
        "the credential scan names it:\n{said}"
    );
    assert!(
        said.contains("Not read") && said.contains("bundle.py"),
        "the code rules name it:\n{said}"
    );
    // No code rule is credited while a file it should have read was not.
    let credited: Vec<&str> = json["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|r| r["checked_by"].as_array().into_iter().flatten())
        .filter_map(|c| c["check_id"].as_str())
        .collect();
    assert!(
        credited.iter().all(|c| !c.starts_with("ast.")),
        "a code rule was credited beside an unread file: {credited:?}"
    );
    let gaps = json["gaps"].as_array().unwrap();
    assert!(
        gaps.iter().any(|g| g["what"]
            .as_str()
            .unwrap_or("")
            .contains("in a language the rules read, not opened")),
        "{gaps:?}"
    );
}
