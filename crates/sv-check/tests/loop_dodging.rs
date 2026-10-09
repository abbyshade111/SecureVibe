//! The loop trials' measures of how each finding went away, and of edits that seek credit
//! (`docs/prompts/loop-pilot/loop_dodging.py`; the gap analysis of 7 October 2026, finding 21). The
//! script is run on the trials' transcripts by hand; this holds its rules to its self-test, which
//! has a written-out build for each class and each count.

use std::process::Command;

#[test]
fn the_loop_dodging_measures_pass_their_self_test() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = Command::new("python3")
        .arg(root.join("docs/prompts/loop-pilot/loop_dodging.py"))
        .arg("--self-test")
        .output()
        .expect("python3 is needed to test the loop trials' measures");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{said}");
    // The setup: the self-test ran to its end, not merely started.
    assert!(said.contains("self-test passed"), "{said}");
}
