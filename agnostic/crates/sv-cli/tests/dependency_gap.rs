//! What `sv report` says about dependencies it could not read, end to end through the binary.
//!
//! The fault these pin: for an ecosystem whose manifest versions `sv` cannot read — npm with no
//! lockfile — the report said the list of dependencies was "what was asked for rather than what is
//! there", when the list held nothing at all. `sv sbom` said it correctly on the same app. The
//! report now asks the bill of materials instead of reasoning from the scan, so the two agree.
//!
//! Three apps, because one sentence covering every ecosystem is what went wrong in the first place
//! and a test against one ecosystem would not have caught it.

use std::path::{Path, PathBuf};
use std::process::Command;

fn app(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-depgap-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/tested-notes/securevibe.toml");
    std::fs::copy(manifest, dir.join("securevibe.toml")).unwrap();
    for (name, contents) in files {
        std::fs::write(dir.join(name), contents).unwrap();
    }
    dir
}

/// The report's gap rows, and the bill of materials as `sv sbom` writes it, for the same app.
fn report_gaps_and_sbom(dir: &Path) -> (Vec<(String, String)>, String) {
    let out_dir = dir.join("report");
    let report = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args([
            "report",
            dir.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
        ])
        .output()
        .expect("sv runs");
    assert!(
        report.status.success(),
        "sv report failed: {}",
        String::from_utf8_lossy(&report.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out_dir.join("report.json")).unwrap())
            .unwrap();
    let gaps = json["gaps"]
        .as_array()
        .expect("the report has gaps")
        .iter()
        .map(|g| {
            (
                g["what"].as_str().unwrap_or_default().to_owned(),
                g["why"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();

    let sbom = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["sbom", dir.to_str().unwrap()])
        .output()
        .expect("sv runs");
    assert!(sbom.status.success());
    let sbom = String::from_utf8_lossy(&sbom.stdout).into_owned();
    (gaps, sbom)
}

const PACKAGE_JSON: &str = "{ \"name\": \"shop\", \"dependencies\": { \"react\": \"18.0.0\", \"express\": \"^4.19.2\" } }\n";
const SERVER_JS: &str = "const express = require('express');\nexpress().listen(3000);\n";

#[test]
fn npm_with_no_lockfile_is_an_empty_list_not_an_approximate_one() {
    let dir = app(
        "npm",
        &[("package.json", PACKAGE_JSON), ("server.js", SERVER_JS)],
    );
    let (gaps, sbom) = report_gaps_and_sbom(&dir);
    std::fs::remove_dir_all(&dir).ok();

    // Assert the setup really is the case under test before asserting anything about the wording:
    // an app whose package.json the scanner never noticed would pass the rest for the wrong reason.
    assert!(
        sbom.contains("securevibe:unread:npm"),
        "the fixture is not the unreadable-npm case at all: {sbom}"
    );

    let npm: Vec<&(String, String)> = gaps
        .iter()
        .filter(|(what, why)| what.contains("npm") || why.contains("npm"))
        .collect();
    assert!(
        !npm.is_empty(),
        "the report said nothing about npm: {gaps:?}"
    );

    let why: String = npm.iter().map(|(_, why)| why.as_str()).collect();
    assert!(
        why.contains("none of its packages are listed") || why.contains("empty one"),
        "the report does not say the npm list is empty: {why}"
    );
    // The exact sentence the backlog entry named. An empty list is not "what was asked for".
    assert!(
        !why.contains("the list of dependencies is what was asked for"),
        "the report still calls an empty npm list the versions that were asked for: {why}"
    );
}

#[test]
fn a_pinned_requirements_file_is_what_was_asked_for_and_says_so() {
    let dir = app(
        "pip",
        &[
            ("requirements.txt", "flask==3.0.0\nrequests==2.32.3\n"),
            ("app.py", "from flask import Flask\napp = Flask(__name__)\n"),
        ],
    );
    let (gaps, sbom) = report_gaps_and_sbom(&dir);
    std::fs::remove_dir_all(&dir).ok();

    // The other half of the fix, and the one a reworded sentence would have broken: these versions
    // were read, so the list is real. Confirm the packages are genuinely in the document first.
    assert!(
        sbom.contains("flask") && !sbom.contains("securevibe:unread:Python"),
        "the fixture's requirements.txt was not read, so it proves nothing: {sbom}"
    );

    let why: String = gaps
        .iter()
        .filter(|(what, why)| what.contains("Python") || why.contains("Python"))
        .map(|(_, why)| why.as_str())
        .collect();
    assert!(
        why.contains("what was asked for"),
        "a manifest-declared list should still be called what was asked for: {why}"
    );
    assert!(
        !why.contains("empty one"),
        "the Python list is not empty and must not be described as one: {why}"
    );
    // The old sentence said this file pinned no versions. Every line of it pins one.
    assert!(
        !why.contains("pins no versions"),
        "requirements.txt pins every version it names: {why}"
    );
}

#[test]
fn an_app_with_a_lockfile_gets_no_dependency_gap_at_all() {
    // The guard against a gap row for nothing. Over-reporting reads as a hole where there is none,
    // and it is what a fix that simply always printed something would produce.
    let dir = app(
        "locked",
        &[
            ("package.json", PACKAGE_JSON),
            ("server.js", SERVER_JS),
            (
                "package-lock.json",
                "{ \"name\": \"shop\", \"lockfileVersion\": 3, \"packages\": {\
                 \"\": { \"name\": \"shop\" },\
                 \"node_modules/react\": { \"version\": \"18.0.0\" },\
                 \"node_modules/express\": { \"version\": \"4.19.2\" } } }\n",
            ),
        ],
    );
    let (gaps, sbom) = report_gaps_and_sbom(&dir);
    std::fs::remove_dir_all(&dir).ok();

    assert!(
        sbom.contains("pkg:npm/react@18.0.0"),
        "the lockfile was not read, so this is not the locked case: {sbom}"
    );
    let dependency: Vec<&(String, String)> = gaps
        .iter()
        .filter(|(what, _)| what.contains("installs") || what.contains("versions are really"))
        .collect();
    assert!(
        dependency.is_empty(),
        "a fully locked app should have no dependency gap: {dependency:?}"
    );
}
