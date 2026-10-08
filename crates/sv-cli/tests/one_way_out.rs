//! `sv` ends through `exit::exit_with`, which lets what was printed out first, and nowhere else
//! calls `std::process::exit` directly. Two places ended a Ctrl-C run that way (the review of
//! 8 October 2026, item 6); a test cannot watch a flush that was skipped, so this reads the source.

use std::path::Path;

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn sv_ends_only_through_exit_with() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    // Setup: the walk found the program, and the one place allowed to end it.
    assert!(files.iter().any(|f| f.ends_with("main.rs")), "{files:?}");
    assert!(
        std::fs::read_to_string(src.join("exit.rs"))
            .unwrap()
            .contains("std::process::exit(code)"),
        "exit_with no longer ends the process: this test needs updating"
    );
    let mut direct = Vec::new();
    for file in &files {
        if file.ends_with("exit.rs") {
            continue;
        }
        let text = std::fs::read_to_string(file).unwrap();
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or_default();
            if code.contains("process::exit(") {
                direct.push(format!("{}:{}: {}", file.display(), n + 1, line.trim()));
            }
        }
    }
    assert!(
        direct.is_empty(),
        "ends without the flush; use exit::exit_with: {direct:#?}"
    );
}
