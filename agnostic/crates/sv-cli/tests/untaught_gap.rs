//! An app whose every language every rule was taught gets no "not looked for" account at all.
//!
//! The wording itself is tested beside the functions that write it (`untaught_lines`,
//! `untaught_gaps`); every real rule is now taught every language `sv` reads, so an app cannot
//! produce the account through the real rules. What an app can show is its absence, and that is
//! worth pinning: an empty section, or a gap row for nothing, would read as a hole where there is
//! none.

use std::process::Command;

fn app(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-untaught-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("app.py"), "def home():\n    return 'hi'\n").unwrap();
    std::fs::write(dir.join("worker.rs"), "fn main() { println!(\"hi\"); }\n").unwrap();
    std::fs::write(dir.join("cgi.c"), "int main(void) { return 0; }\n").unwrap();
    dir
}

#[test]
fn the_terminal_has_no_such_section() {
    let dir = app("check");
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("check")
        .arg(&dir)
        .output()
        .expect("sv runs");
    std::fs::remove_dir_all(&dir).ok();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!stdout.contains("Not looked for"), "{stdout}");
}

#[test]
fn the_report_has_no_such_gap() {
    let dir = app("report");
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/tested-notes/securevibe.toml");
    std::fs::copy(manifest, dir.join("securevibe.toml")).unwrap();
    let out_dir = dir.join("report");
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(&dir)
        .arg("--out")
        .arg(&out_dir)
        .output()
        .expect("sv runs");
    let compliance = std::fs::read_to_string(out_dir.join("compliance.md")).unwrap_or_default();
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!compliance.is_empty(), "the report was not written");
    assert!(!compliance.contains("has not been taught"), "{compliance}");
}
