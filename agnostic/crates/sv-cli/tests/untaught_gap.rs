//! A rule that met a language it was never taught says so, in the terminal and in the report.
//!
//! Withholding the claim is half of it. The other half is the owner being told why a rule that
//! read their Python has nothing to say, rather than finding the line simply missing.

use std::process::Command;

fn app(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-untaught-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("app.py"), "def home():\n    return 'hi'\n").unwrap();
    std::fs::write(dir.join("worker.rs"), "fn main() { println!(\"hi\"); }\n").unwrap();
    dir
}

#[test]
fn the_terminal_names_the_rule_and_the_language() {
    let dir = app("check");
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("check")
        .arg(&dir)
        .output()
        .expect("sv runs");
    std::fs::remove_dir_all(&dir).ok();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Not looked for"), "{stdout}");
    assert!(
        stdout.contains("(ast.shell-command) — not in rust"),
        "{stdout}"
    );
    // A rule taught both languages is not on the list.
    assert!(
        !stdout.contains("(ast.sql-built-by-hand) — not in"),
        "{stdout}"
    );
}

#[test]
fn the_report_lists_it_as_a_gap() {
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
    assert!(
        compliance.contains("(ast.shell-command), in rust"),
        "{compliance}"
    );
    assert!(compliance.contains("has not been taught what to look for in rust"));
}
