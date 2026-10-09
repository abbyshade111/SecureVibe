//! Configuration files found wherever an app keeps them (gap analysis of 7 October 2026, finding
//! 16; ADR-015, Later, 9 October 2026).
//!
//! The fault this pins: `iac` and `ci-cd` are the two claims whose absence is an answer, and
//! `Dockerfile` was looked for only at the root. An app with its Dockerfile in `deploy/` was answered
//! "nothing found", which agrees with an owner who said "no infrastructure configuration" when the
//! repository holds some. A file pattern `**/name` matches the name at any depth; the tests below
//! also hold the names added beside it, and that a folder the scan does not enter still counts for
//! nothing.

use std::path::PathBuf;
use sv_frameworks::Condition;
use sv_scan::{Evidence, ScanReport, Signatures, scan};

fn data(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data")
        .join(file)
}

/// A scan of an app made of `files`, with both signature sets as the CLI loads them.
fn scan_files(name: &str, files: &[(&str, &str)]) -> ScanReport {
    let dir = std::env::temp_dir().join(format!("sv-any-depth-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    for (path, contents) in files {
        let path = dir.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    let sigs = Signatures::load_all(&[
        &data("tech-signatures.json"),
        &data("claim-corroborators.json"),
    ])
    .expect("signatures load");
    let report = scan(&dir, &sigs).expect("scan");
    std::fs::remove_dir_all(&dir).ok();
    report
}

/// The answer to `condition`: true with the file found, or false with nothing found.
fn found(report: &ScanReport, condition: Condition) -> Option<String> {
    let answer = report
        .answers
        .iter()
        .find(|a| a.condition == condition)
        .expect("condition answered");
    match (&answer.value, &answer.evidence) {
        (Some(true), Evidence::File { path }) => Some(path.clone()),
        (Some(false), Evidence::NothingFound { .. }) => None,
        other => panic!("{} answered {other:?}", condition.name()),
    }
}

const APP: (&str, &str) = (
    "server.js",
    "require('http').createServer((q, s) => s.end('ok')).listen(3000);\n",
);

#[test]
fn a_dockerfile_one_folder_down_is_infrastructure_configuration() {
    let report = scan_files(
        "deploy-dockerfile",
        &[APP, ("deploy/Dockerfile", "FROM node:22\nCOPY . .\n")],
    );
    // The file has to be in what the scan listed, or the answer below tests nothing.
    assert!(report.all_paths.contains("deploy/Dockerfile"));
    assert_eq!(
        found(&report, Condition::Iac).as_deref(),
        Some("deploy/Dockerfile")
    );
}

#[test]
fn compose_and_chart_files_count_at_any_depth() {
    for (name, path) in [
        ("compose-root", "compose.yaml"),
        ("compose-nested", "docker/compose.yml"),
        ("containerfile", "build/Containerfile"),
        ("chart", "charts/app/Chart.yaml"),
        ("cdk", "cdk.json"),
    ] {
        let report = scan_files(name, &[APP, (path, "services: {}\n")]);
        assert!(report.all_paths.contains(path), "{path} was not listed");
        assert_eq!(
            found(&report, Condition::Iac).as_deref(),
            Some(path),
            "{path} is infrastructure configuration"
        );
    }
}

#[test]
fn travis_cloud_build_and_buildkite_are_ci_configuration() {
    for (name, path) in [
        ("travis", ".travis.yml"),
        ("cloudbuild", "cloudbuild.yaml"),
        ("buildkite", ".buildkite/pipeline.yml"),
    ] {
        let report = scan_files(name, &[APP, (path, "steps: []\n")]);
        assert!(report.all_paths.contains(path), "{path} was not listed");
        assert!(
            found(&report, Condition::CiCd).is_some(),
            "{path} is CI configuration"
        );
    }
}

#[test]
fn a_name_inside_another_name_is_not_a_match() {
    // `**/Dockerfile` matches a file or folder of that name, not one that merely ends in it.
    let report = scan_files(
        "lookalike",
        &[
            APP,
            ("docs/MyDockerfile", "notes\n"),
            ("old-compose.yaml.txt", "notes\n"),
        ],
    );
    assert_eq!(found(&report, Condition::Iac), None);
}

#[test]
fn an_app_with_none_of_them_is_still_answered_nothing_found() {
    // The control: without it, answering "yes" for every app would pass the tests above.
    let report = scan_files("none", &[APP]);
    assert_eq!(found(&report, Condition::Iac), None);
    assert_eq!(found(&report, Condition::CiCd), None);
}

#[test]
fn a_dockerfile_inside_an_installed_package_does_not_count() {
    // A package's own Dockerfile under `node_modules` says nothing about the app's infrastructure.
    let report = scan_files(
        "node-modules",
        &[
            APP,
            ("node_modules/some-pkg/Dockerfile", "FROM alpine\n"),
            ("node_modules/some-pkg/index.js", "module.exports = 1;\n"),
        ],
    );
    assert_eq!(found(&report, Condition::Iac), None);
}
