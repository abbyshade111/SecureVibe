//! A report names the `sv` that made it, in each of its forms: reported from the owner's family-hub on 3 October
//! 2026, where a report could not say which build made it, so a review naming a rule the reader's `sv` lacked could
//! not be explained.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn every_form_of_the_report_names_the_version_and_commit_sv_version_names() {
    let sv = env!("CARGO_BIN_EXE_sv");
    let version = Command::new(sv).arg("--version").output().expect("sv runs");
    let line = String::from_utf8(version.stdout).unwrap();
    // `sv 0.1.0 (commit 9573c0d...)`
    let commit = line
        .split("(commit ")
        .nth(1)
        .and_then(|rest| rest.split(')').next())
        .expect("--version names a commit")
        .to_owned();
    assert!(!commit.is_empty(), "{line}");

    let app = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/flask-booking");
    let out = std::env::temp_dir().join(format!("sv-made-by-{}", std::process::id()));
    std::fs::remove_dir_all(&out).ok();
    let run = Command::new(sv)
        .args([
            "report",
            app.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .expect("sv runs");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let read = |name: &str| std::fs::read_to_string(out.join(name)).unwrap();

    let json: Value = serde_json::from_str(&read("report.json")).unwrap();
    assert_eq!(
        json["sv"]["version"],
        env!("CARGO_PKG_VERSION"),
        "{}",
        json["sv"]
    );
    assert_eq!(json["sv"]["commit"], commit.as_str(), "{}", json["sv"]);

    let sarif: Value = serde_json::from_str(&read("findings.sarif")).unwrap();
    let driver = &sarif["runs"][0]["tool"]["driver"];
    assert_eq!(driver["version"], env!("CARGO_PKG_VERSION"), "{driver}");
    assert_eq!(driver["properties"]["commit"], commit.as_str(), "{driver}");

    // The page and the Markdown give the commit cut short, as a person reads it.
    let short: String = commit.chars().take(12).collect();
    let html = read("report.html");
    assert!(html.contains(&short) && html.contains(env!("CARGO_PKG_VERSION")));
    let markdown = std::fs::read_dir(&out)
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "md"))
        .map(|e| std::fs::read_to_string(e.path()).unwrap())
        .collect::<Vec<_>>();
    assert!(!markdown.is_empty(), "the report writes Markdown");
    for text in &markdown {
        assert!(
            text.contains(&format!("(commit {short}")),
            "{}",
            &text[..200.min(text.len())]
        );
    }
    std::fs::remove_dir_all(&out).ok();
}
