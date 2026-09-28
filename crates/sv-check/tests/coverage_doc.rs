//! `docs/COVERAGE.md` is generated from the checks' own citations, and is only worth reading while
//! it matches them. A change to a rule, an adapter's map, or a hard-coded citation that is not
//! followed by `python3 tools/coverage.py` fails here, rather than leaving the document to claim
//! coverage the checks no longer have, or to miss coverage they gained.

use std::process::Command;

#[test]
fn the_coverage_document_matches_the_checks() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = Command::new("python3")
        .arg(root.join("tools/coverage.py"))
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

/// `docs/REQUIREMENTS.md`, written by the same script, is checked for staleness above. This holds what
/// it must contain: every ASVS and AISVS requirement in the data, once each, so a change to the script
/// that quietly drops a family or a level cannot pass by regenerating the file.
#[test]
fn the_requirements_list_names_every_requirement_once() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let list = std::fs::read_to_string(root.join("docs/REQUIREMENTS.md")).unwrap();
    let mut listed: Vec<&str> = list
        .lines()
        .filter_map(|l| l.strip_prefix("| **"))
        .filter_map(|l| l.split("**").next())
        .collect();
    let mut expected = Vec::new();
    for file in ["asvs-5.0.0.json", "aisvs-1.0.json"] {
        let data: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(root.join("data/frameworks").join(file)).unwrap(),
        )
        .unwrap();
        for chapter in data["chapters"].as_array().unwrap() {
            for section in chapter["sections"].as_array().unwrap() {
                for r in section["requirements"].as_array().unwrap() {
                    expected.push(r["id"].as_str().unwrap().to_owned());
                }
            }
        }
    }
    // The control: the data really holds both frameworks, not an empty list compared with another.
    assert!(
        expected.len() > 500,
        "only {} requirements read",
        expected.len()
    );
    let total = listed.len();
    listed.sort_unstable();
    listed.dedup();
    assert_eq!(total, listed.len(), "a requirement is listed twice");
    expected.sort_unstable();
    assert_eq!(
        listed,
        expected.iter().map(String::as_str).collect::<Vec<_>>()
    );
}
