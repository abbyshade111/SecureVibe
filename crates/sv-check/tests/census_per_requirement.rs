//! The credit census holds each requirement a check cites, not only each check (the review of
//! 8 October 2026, item 5): a check citing two requirements whose tests only ever credited one
//! passed `tools/coverage.py --credits`, with the other cited on no evidence the suite had seen.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// What `--credits` says about `check` given a log whose only credits are `credits` for it, from the
/// code that ships.
fn said(tag: &str, check: &str, credits: &str) -> String {
    let dir = std::env::temp_dir().join(format!("sv-census-ids-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("credits.log");
    std::fs::write(
        &log,
        format!("{check}\t{credits}\tcrates/sv-check/src/probes.rs:1\n"),
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
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter(|l| l.contains(check))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn a_requirement_a_check_cites_and_was_never_seen_crediting_is_a_fault() {
    // The setup: this check cites both requirements, and gives credit (it is not findings-only).
    let check = "probe.admin-action-ordinary-user";
    let source = std::fs::read_to_string(repo().join("crates/sv-check/src/signed_in/rules.rs"))
        .unwrap_or_default()
        + &std::fs::read_to_string(repo().join("crates/sv-check/src/probes.rs")).unwrap();
    assert!(
        source.contains(check),
        "the setup: {check} is a check of sv's"
    );

    let one = said("one", check, "V8.2.1");
    assert!(
        one.contains(&format!(
            "{check} cites V8.3.1 and the suite never saw it credit that"
        )),
        "{one}"
    );
    // The control: both credited, and nothing is said of the requirements.
    let both = said("both", check, "V8.2.1,V8.3.1");
    assert!(!both.contains("never saw it credit"), "{both}");
}
