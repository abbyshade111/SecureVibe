//! `tools/backlog.py` prints which backlog items are open, claimed, done, or partly done, read from the items' own
//! markers (BACKLOG, "Backlog management"). Its self-test holds the reading to a sample of every kind; the second
//! test runs it on the real file, so a change to how items are written that the reader cannot follow fails here
//! rather than in the owner's hands.

use std::process::Command;

fn run(args: &[&str]) -> (bool, String) {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = Command::new("python3")
        .arg("-I")
        .arg(root.join("tools/backlog.py"))
        .args(args)
        .output()
        .expect("python3 runs");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), said)
}

#[test]
fn the_board_reads_every_kind_of_marker() {
    let (ok, said) = run(&["--self-test"]);
    assert!(ok, "{said}");
    assert!(said.contains("backlog self-test: ok"), "{said}");
}

#[test]
fn the_board_reads_the_real_backlog() {
    let (ok, said) = run(&["summary"]);
    assert!(ok, "{said}");
    assert!(said.contains("items in Next:"), "{said}");
    let count: usize = said
        .split(" items in Next")
        .next()
        .and_then(|s| s.trim().parse().ok())
        .expect("a count before 'items in Next'");
    assert!(
        count > 100,
        "the real backlog has over a hundred items, read {count}: {said}"
    );
}
