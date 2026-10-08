//! The design record is one file per entry under `docs/design/` (`docs/adr/ADR-060.md`), because every session
//! adding a section to the end of one file made any two open pull requests conflict there. Sessions used to that file
//! will keep adding to it; this fails when one does, and when an entry is misnamed, has no title, or shares a title
//! with another, since the code and the documents cite entries by title.

use std::process::Command;

fn run(arg: &str) -> std::process::Output {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    Command::new("python3")
        .arg(root.join("tools/design_entry.py"))
        .arg(arg)
        .output()
        .expect("python3 is needed to check docs/design/; install it, or run the script by hand")
}

#[test]
fn the_design_record_is_one_file_per_entry() {
    let out = run("--check");
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The checks above are only as good as the script's reading of a section and a title; its self-test breaks each.
#[test]
fn the_design_entry_script_passes_its_self_test() {
    let out = run("--self-test");
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
