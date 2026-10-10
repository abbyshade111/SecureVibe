//! `--keep-tool-output` keeps what the outside tools wrote, so without `--tools` there is nothing
//! for it to keep, and `sv report` says so rather than writing a report that looks as if it kept
//! something (backlog 0229, part 4).

use std::process::Command;

#[test]
fn keep_tool_output_without_tools_is_refused_and_says_what_it_needs() {
    let dir = std::env::temp_dir().join(format!("sv-keep-tool-output-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["report", "--keep-tool-output"])
        .arg(&dir)
        .output()
        .expect("sv runs");
    let said = String::from_utf8_lossy(&out.stderr).into_owned();
    let wrote = dir.join(sv_scan::ecosystems::DEFAULT_REPORT_DIR).exists();
    std::fs::remove_dir_all(&dir).ok();
    assert!(!out.status.success(), "{said}");
    assert!(said.contains("needs --tools as well"), "{said}");
    assert!(!wrote, "a report was written: {said}");
}

#[test]
fn the_help_names_the_option_under_report() {
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["report", "--help"])
        .output()
        .expect("sv runs");
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(said.contains("--keep-tool-output"), "{said}");
}
