//! The backlog is one file per item under `docs/backlog/` (`docs/adr/ADR-061.md`), each with a status line, because
//! every session adding to the end of one file made any two open pull requests conflict there, and what was done was a
//! reading of prose. `tools/backlog.py` reads and writes the status lines; this runs its self-test, its check on the
//! real folder (a misnamed file, a missing title or status, two files with one title, or an item left in
//! `docs/BACKLOG.md` fails it), and its summary, so a layout drift fails here and not in the owner's hands.

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
fn the_tool_passes_its_own_checks() {
    let (ok, said) = run(&["--self-test"]);
    assert!(ok, "{said}");
    assert!(said.contains("backlog self-test: ok"), "{said}");
}

#[test]
fn the_items_are_files_with_a_title_and_a_status_and_the_guide_holds_none() {
    let (ok, said) = run(&["--check"]);
    assert!(ok, "the layout check failed:\n{said}");
}

#[test]
fn the_board_reads_the_real_items() {
    let (ok, said) = run(&["summary"]);
    assert!(ok, "{said}");
    let count: usize = said
        .split(" items:")
        .next()
        .and_then(|s| s.trim().parse().ok())
        .expect("a count before 'items:'");
    assert!(
        count > 100,
        "the backlog has over a hundred items, read {count}: {said}"
    );
}
