//! Records the commit `sv` was built from, so a bundle and a report can say which `sv` made them. The Docker image's
//! build context has no `.git`, so the image is built with the commit given as `SV_GIT_COMMIT` (a build argument the
//! workflows pass). Given neither, it says `unknown` rather than guessing.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// A commit given from outside: hexadecimal, and long enough to be one. Anything else (empty, a word, a
/// branch name) is not taken for a commit.
fn given_commit() -> Option<String> {
    let given = std::env::var("SV_GIT_COMMIT").ok()?;
    let given = given.trim();
    (given.len() >= 7 && given.len() <= 64 && given.chars().all(|c| c.is_ascii_hexdigit()))
        .then(|| given.to_ascii_lowercase())
}

fn main() {
    println!("cargo:rerun-if-env-changed=SV_GIT_COMMIT");
    let commit = given_commit()
        .or_else(|| git(&["rev-parse", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=SV_GIT_COMMIT={commit}");
    // Run again when the checkout moves: the HEAD file changes on a switch, and the branch's own file on a commit.
    if let Some(head) = git(&["rev-parse", "--git-path", "HEAD"]) {
        println!("cargo:rerun-if-changed={head}");
    }
    if let Some(branch) = git(&["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git(&["rev-parse", "--git-path", &branch])
    {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
