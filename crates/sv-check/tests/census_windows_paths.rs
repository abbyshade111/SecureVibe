//! A credit logged on Windows names its place in the code with `\`, as Rust's own `file!()` writes it
//! there, and `tools/coverage.py --credits` reads it as the same place written with `/` (backlog
//! 0120). Until 9 October 2026 no place written with `\` matched a file, and on Windows every log read
//! as holding no credit.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// What `--credits` says for a log whose only credit names its place as `place`.
fn said(tag: &str, place: &str) -> String {
    let dir = std::env::temp_dir().join(format!("sv-census-place-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("credits.log");
    std::fs::write(
        &log,
        format!("probe.admin-action-ordinary-user\tV8.2.1,V8.3.1\t{place}:1\n"),
    )
    .unwrap();
    std::fs::write(dir.join("credits.log.withheld"), "").unwrap();
    let out = Command::new("python3")
        .arg("-I")
        .arg(repo().join("tools/coverage.py"))
        .arg("--credits")
        .arg(&log)
        .output()
        .expect("python3 runs");
    std::fs::remove_dir_all(&dir).ok();
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_place_written_with_backslashes_is_the_same_place() {
    // The setup: the file is one that ships, so a credit placed in it counts.
    assert!(repo().join("crates/sv-check/src/probes.rs").is_file());
    let unix = said("unix", "crates/sv-check/src/probes.rs");
    assert!(!unix.contains("holds no credit"), "the control: {unix}");
    let windows = said("windows", r"crates\sv-check\src\probes.rs");
    assert!(!windows.contains("holds no credit"), "{windows}");
    // The same verdict either way: only the separators differ.
    assert_eq!(
        windows.replace(r"crates\sv-check", "crates/sv-check"),
        unix,
        "the two logs read differently"
    );
}

/// What `--withheld` counts, for a log whose credit and finding name their place as `place`.
fn withheld(tag: &str, place: &str) -> String {
    let dir = std::env::temp_dir().join(format!("sv-withheld-place-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("credits.log");
    let check = "probe.admin-action-ordinary-user";
    std::fs::write(&log, format!("{check}\tV8.2.1\t{place}:1\n")).unwrap();
    std::fs::write(
        dir.join("credits.log.withheld"),
        format!("{check}\t{place}:1\n"),
    )
    .unwrap();
    let out = Command::new("python3")
        .arg("-I")
        .arg(repo().join("tools/coverage.py"))
        .arg("--withheld")
        .arg(&log)
        .output()
        .expect("python3 runs");
    std::fs::remove_dir_all(&dir).ok();
    String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
}

#[test]
fn the_withheld_count_reads_backslashes_as_the_same_place() {
    let unix = withheld("unix", "crates/sv-check/src/probes.rs");
    assert!(
        unix.contains("1 checks were seen giving credit; 1 of them were also seen withholding"),
        "the control: {unix}"
    );
    assert_eq!(withheld("windows", r"crates\sv-check\src\probes.rs"), unix);
}
