//! `sv preflight`, end to end: the run settings read against the code, with nothing run, nothing
//! written, and nothing credited (ADR-035).

use std::path::{Path, PathBuf};
use std::process::Command;

fn sv(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(args)
        .output()
        .expect("sv runs")
}

fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name)
}

/// Every file under `dir`, with its contents.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push((path.clone(), std::fs::read(&path).unwrap()));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn the_example_built_to_be_signed_in_to_has_nothing_to_look_at_and_is_left_as_it_was() {
    let dir = example("notes-with-users");
    let before = snapshot(&dir);
    let out = sv(&["preflight", dir.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("Nothing was run."), "{text}");
    assert!(text.contains("nothing is credited"), "{text}");
    assert!(text.contains("\n0 to look at, 0 could not tell,"), "{text}");
    // The seed, the tables, and the sign-in path were each looked at, not skipped.
    for topic in ["(accounts)", "(tables)", "(path): The sign-in path"] {
        assert!(
            text.contains(&format!("**looks right** {topic}")),
            "{topic}: {text}"
        );
    }
    assert_eq!(
        snapshot(&dir),
        before,
        "the preflight wrote into the app's folder"
    );
}

#[test]
fn an_app_started_on_loopback_is_said_before_it_is_run() {
    // flask-booking's start command binds 127.0.0.1, where `sv run` cannot reach it.
    let out = sv(&["preflight", example("flask-booking").to_str().unwrap()]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("**look at this** (listen)"), "{text}");
    assert!(text.contains("\n1 to look at,"), "{text}");
}

#[test]
fn a_folder_with_no_manifest_says_to_write_one() {
    let dir = std::env::temp_dir().join(format!("sv-preflight-empty-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    let out = sv(&["preflight", dir.to_str().unwrap()]);
    std::fs::remove_dir_all(&dir).ok();
    assert!(!out.status.success());
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("no securevibe.toml"), "{said}");
}
