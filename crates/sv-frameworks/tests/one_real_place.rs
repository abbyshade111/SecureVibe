//! Every real place `sv` works out comes from `sv_frameworks::paths::canonical`, so on Windows none
//! reaches Docker, a report, or a settings file in the `\\?\` form Docker refuses (backlog 0120).

use std::path::{Path, PathBuf};

fn sources(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, found);
        } else if path.extension().is_some_and(|e| e == "rs") {
            found.push(path);
        }
    }
}

#[test]
fn nothing_but_the_helper_asks_the_standard_library_for_a_real_place() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    sources(&crates, &mut files);
    let helper = Path::new("sv-frameworks").join("src").join("paths.rs");
    let mut callers = 0;
    let mut raw = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        if file.ends_with(&helper) {
            assert!(
                text.contains("std::fs::canonicalize(path)"),
                "the helper itself"
            );
            continue;
        }
        // The helper's own tests hold it to the standard library, and this file names the call.
        if file.ends_with(Path::new("paths").join("tests.rs"))
            || file.ends_with("one_real_place.rs")
        {
            continue;
        }
        callers += text.matches("canonical(").count();
        for (n, line) in text.lines().enumerate() {
            if line.contains("canonicalize(") {
                raw.push(format!("{}:{}: {}", file.display(), n + 1, line.trim()));
            }
        }
    }
    // The walk really reached the code: the crates, and the callers already moved to the helper.
    assert!(files.len() > 200, "only {} source files", files.len());
    assert!(callers >= 30, "only {callers} calls of the helper found");
    assert!(
        raw.is_empty(),
        "use sv_frameworks::paths::canonical (or `.canonical()`) instead:\n{}",
        raw.join("\n")
    );
}
