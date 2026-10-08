//! `tools/merge_main.py` brings `main` into a branch and settles the one conflict every session used to resolve by
//! hand: both sides added to `docs/BACKLOG.md` at the same place. Its self-test builds a repository with that
//! conflict and with two it must leave alone; this runs it, so a change to the script that settles too much, or
//! too little, fails here and not on somebody's branch.

use std::process::Command;

#[test]
fn the_merge_script_settles_only_what_both_sides_added() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = Command::new("python3")
        .arg("-I")
        .arg(root.join("tools/merge_main.py"))
        .arg("--self-test")
        .output()
        .expect("python3 runs");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{said}");
    assert!(said.contains("merge_main self-test: ok"), "{said}");
}
