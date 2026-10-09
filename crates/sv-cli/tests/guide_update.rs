//! The guide's "Keeping StackVet up to date" (`docs/GAP-ANALYSIS.md`, 5.3), held to the workflow that
//! publishes the image and to what `sv --version` prints: a guide that names an image nobody publishes,
//! or a tag that does not exist, sends the owner to an update that never comes.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    std::fs::read_to_string(repo().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The image the publishing job pushes, from its `IMAGE:` setting.
fn published_image(workflow: &str) -> String {
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

/// The guide's section on updating, up to the next section.
fn update_section(guide: &str) -> String {
    let start = guide
        .find("\n## Keeping StackVet up to date\n")
        .expect("the guide has a section on keeping StackVet up to date");
    let rest = &guide[start + 1..];
    let end = rest[3..].find("\n## ").map_or(rest.len(), |e| e + 3);
    rest[..end].to_owned()
}

#[test]
fn the_guide_updates_the_image_the_workflow_publishes() {
    let workflow = read(".github/workflows/rust.yml");
    let image = published_image(&workflow);
    assert_eq!(image, "ghcr.io/abbyshade111/stackvet-sv", "the setup");
    let guide = read("docs/GETTING-STARTED.md");
    let section = update_section(&guide);

    assert!(
        section.contains(&format!("docker pull {image}\n")),
        "{section}"
    );
    assert!(
        section.contains(&format!("docker run --rm {image} --version\n")),
        "{section}"
    );
    // The copy built on this computer is updated as the installing section says.
    assert!(
        section.contains("`git pull`, then `sh tools/install.sh`"),
        "{section}"
    );
    assert!(guide.contains("then `git pull`, then `sh tools/install.sh` again"));
    // A new version is picked up only when the tool starts the server again.
    assert!(section.contains("restart your AI tool"), "{section}");

    // Every image the guide names is the one published, so a rename cannot leave the guide behind.
    let named = guide.matches("ghcr.io/").count();
    assert!(
        named >= 8,
        "the setup: the guide names the image throughout"
    );
    assert_eq!(
        guide
            .matches(&format!("ghcr.io/{}", &image["ghcr.io/".len()..]))
            .count(),
        named,
        "the guide names an image the workflow does not publish"
    );
}

#[test]
fn a_version_can_be_held_to_by_its_commit() {
    // The guide says every image is published under the commit `--version` prints. Both come from the
    // same `github.sha` in the publishing job, or the pinned name would be one nobody pushed.
    let workflow = read(".github/workflows/rust.yml");
    let publish = workflow.split("\n  publish:\n").nth(1).unwrap();
    assert!(
        publish.contains("--build-arg SV_GIT_COMMIT=${{ github.sha }}"),
        "the image's --version names another commit than its tag"
    );
    assert!(
        publish.contains("docker push \"$IMAGE:${{ github.sha }}\""),
        "no image is published under its commit"
    );
    assert!(
        publish.contains("docker push \"$IMAGE:latest\""),
        "the newest is not published as latest"
    );
    let guide = read("docs/GETTING-STARTED.md");
    assert!(
        update_section(&guide).contains("followed by the whole commit that `--version` prints")
    );

    // And `--version` prints the whole commit, as the guide says: 40 letters and digits.
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("--version")
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&out.stdout);
    let first = said.lines().next().unwrap_or_default();
    let commit = first
        .strip_prefix(&format!("sv {} (commit ", env!("CARGO_PKG_VERSION")))
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or_else(|| panic!("not the line the guide shows: {first}"));
    assert!(
        commit == "unknown"
            || (commit.len() == 40 && commit.chars().all(|c| c.is_ascii_hexdigit())),
        "{commit}"
    );
}
