//! `docs/COVERAGE.md` is generated from the checks' own citations, and is only worth reading while
//! it matches them. A change to a rule, an adapter's map, or a hard-coded citation that is not
//! followed by `python3 tools/coverage.py` fails here, rather than leaving the document to claim
//! coverage the checks no longer have, or to miss coverage they gained.

use std::process::Command;

#[test]
fn the_coverage_document_matches_the_checks() {
    let agnostic = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = Command::new("python3")
        .arg(agnostic.join("tools/coverage.py"))
        .arg("--check")
        .output()
        .expect(
            "python3 is needed to check docs/COVERAGE.md; install it, or run the script by hand",
        );
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
