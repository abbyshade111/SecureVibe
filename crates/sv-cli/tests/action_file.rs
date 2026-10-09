//! The GitHub Action (`action.yml`, ADR-081) held to what the owner decided for it on 9 October 2026: the image the
//! publish job pushes, checked against its signature (ADR-080) before it runs; no network, the repository read-only,
//! never `--run` or `--tools`; every action it uses pinned to a commit, as the workflows' are. Each is one line of a
//! file nobody runs on their own computer, so a test is the only thing that reads them before an app's workflow does.

use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Read with `\n` line endings, as a Windows checkout gives `\r\n`.
fn read(path: &str) -> String {
    std::fs::read_to_string(repo().join(path))
        .unwrap_or_else(|e| panic!("{path}: {e}"))
        .replace("\r\n", "\n")
}

/// The image the publishing job pushes, from its `IMAGE:` setting.
fn published_image() -> String {
    let workflow = read(".github/workflows/rust.yml");
    let publish = workflow
        .split("\n  publish:\n")
        .nth(1)
        .expect("the workflow has a publish job");
    publish
        .lines()
        .find_map(|l| l.trim().strip_prefix("IMAGE: "))
        .expect("the publish job names its image")
        .trim()
        .to_owned()
}

/// The `docker run` command of the step that runs `sv`, joined across its continued lines.
fn docker_run(action: &str) -> String {
    let start = action
        .find("docker run ")
        .expect("the Action runs the image");
    let mut command = String::new();
    for line in action[start..].lines() {
        let line = line.trim();
        command.push_str(line.trim_end_matches('\\'));
        command.push(' ');
        if !line.ends_with('\\') {
            break;
        }
    }
    command
}

#[test]
fn the_action_runs_the_published_image_and_checks_its_signature_first() {
    let action = read("action.yml");
    let image = published_image();
    assert_eq!(image, "ghcr.io/abbyshade111/stackvet-sv", "the setup");
    assert!(
        action.contains(&format!("default: {image}:latest")),
        "the Action's default image is not the one the publish job pushes ({image})"
    );
    let verify = action
        .find("gh attestation verify")
        .expect("the Action checks the image's signature");
    let run = action
        .find("docker run ")
        .expect("the Action runs the image");
    assert!(
        verify < run,
        "the signature is checked after the image has run"
    );
    assert!(
        action.contains("--signer-workflow abbyshade111/StackVet/.github/workflows/rust.yml"),
        "the signature check does not require this repository's own workflow to have signed it"
    );
}

#[test]
fn the_image_runs_without_a_network_or_write_access_to_the_code() {
    let action = read("action.yml");
    let command = docker_run(&action);
    assert!(command.contains("docker run"), "the setup: {command}");
    assert!(
        command.contains("--network none"),
        "no --network none: {command}"
    );
    assert!(
        command.contains("\"$GITHUB_WORKSPACE:$GITHUB_WORKSPACE:ro\""),
        "the repository is not mounted read-only: {command}"
    );
    assert!(
        command.contains("--user \"$(id -u):$(id -g)\""),
        "the image runs as root, not as the runner's user: {command}"
    );
}

#[test]
fn the_action_never_starts_the_app_or_runs_other_tools() {
    let action = read("action.yml");
    // Only the lines that run something; the comments say why these are left out.
    let code: String = action
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        code.contains("args=(report "),
        "the setup: the Action builds sv's arguments"
    );
    for flag in ["--run", "--tools", "--slow"] {
        assert!(!code.contains(flag), "the Action passes {flag}");
    }
}

#[test]
fn every_action_it_uses_is_pinned_to_a_commit() {
    let action = read("action.yml");
    let uses: Vec<&str> = action
        .lines()
        .filter_map(|l| l.trim().strip_prefix("uses: "))
        .collect();
    assert!(
        uses.len() >= 2,
        "the setup: only {} uses: lines found",
        uses.len()
    );
    for line in uses {
        let reference = line.split_whitespace().next().unwrap_or("");
        let commit = reference.rsplit_once('@').map_or("", |(_, c)| c);
        assert!(
            commit.len() == 40 && commit.chars().all(|c| c.is_ascii_hexdigit()),
            "not pinned to a commit: {line}"
        );
    }
}

#[test]
fn the_readme_uses_the_action_from_main_not_the_archived_v1_branch() {
    // `v1` is the branch SecureVibe v1 is archived on: `@v1` would load the old app, which has no Action (ADR-081).
    let readme = read("README.md");
    let uses: Vec<&str> = readme
        .lines()
        .filter_map(|l| l.trim().strip_prefix("- uses: abbyshade111/StackVet@"))
        .collect();
    assert!(
        !uses.is_empty(),
        "the setup: the README shows no workflow using the Action"
    );
    for reference in uses {
        assert_eq!(
            reference.trim(),
            "main",
            "the README uses the Action at @{reference}"
        );
    }
}
