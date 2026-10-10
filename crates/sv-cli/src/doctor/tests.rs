//! `sv doctor`'s answers, each set up and then asked (backlog 0217, part 3).

use super::*;
use std::path::{Path, PathBuf};
use std::process::Command;

const READS: &str = "manifest-version = 1\n[app]\nname = \"x\"\n";
const RUNS: &str = "manifest-version = 1\n[app]\nname = \"x\"\n[stack.run]\nimage = \"python:3.12-slim\"\nstart = \"python app.py\"\n";

fn folder(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-doctor-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn git_init(dir: &Path) {
    let done = Command::new("git")
        .args(["init", "-q"])
        .current_dir(dir)
        .status()
        .expect("git runs");
    assert!(done.success());
    // The setup worked: the folder really is in git now.
    assert!(dir.join(".git").is_dir());
}

fn ask(dir: &Path, in_container: bool, backend: &dyn Fn() -> Result<(), CannotRun>) -> Vec<Line> {
    answers(
        dir,
        &Asked {
            version: "sv 0.1.0 (commit test)",
            data: Ok(PathBuf::from("/data")),
            in_container,
            backend,
        },
    )
}

fn state(lines: &[Line], topic: &str) -> (State, String) {
    let l = lines
        .iter()
        .find(|l| l.topic == topic)
        .unwrap_or_else(|| panic!("no answer about {topic}: {lines:?}"));
    (l.state, l.said.clone())
}

fn docker_ok() -> Result<(), CannotRun> {
    Ok(())
}

fn no_docker() -> Result<(), CannotRun> {
    Err(CannotRun::NoBackend {
        checked: "`docker` could not be started: not found".to_owned(),
    })
}

#[test]
fn a_folder_set_up_all_the_way_is_ready_on_every_line_and_nothing_more_is_claimed() {
    let dir = folder("ready");
    git_init(&dir);
    std::fs::write(dir.join("stackvet.toml"), RUNS).unwrap();
    let lines = ask(&dir, false, &docker_ok);
    std::fs::remove_dir_all(&dir).ok();
    for topic in [
        "sv",
        "git",
        "stackvet.toml",
        "how to start the app",
        "Docker",
    ] {
        assert_eq!(state(&lines, topic).0, State::Ready, "{topic}: {lines:?}");
    }
    let said = text(Path::new("app"), &lines);
    assert!(said.contains("Nothing above is missing"), "{said}");
    assert!(
        said.contains("says nothing about whether the app is secure"),
        "{said}"
    );
    assert!(said.contains("no network connection"), "{said}");
}

#[test]
fn an_empty_folder_is_not_ready_and_says_what_to_do_for_each() {
    let dir = folder("empty");
    let lines = ask(&dir, false, &no_docker);
    let left = std::fs::read_dir(&dir).unwrap().count();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(left, 0, "doctor wrote something into the folder");
    let (git, said) = state(&lines, "git");
    assert_eq!(git, State::NotReady);
    assert!(said.contains("git init"), "{said}");
    let (toml, said) = state(&lines, "stackvet.toml");
    assert_eq!(toml, State::NotReady);
    assert!(said.contains("sv init"), "{said}");
    // Not asked of a manifest that is not there: can't tell, not "not ready".
    assert_eq!(state(&lines, "how to start the app").0, State::CannotTell);
    let (docker, said) = state(&lines, "Docker");
    assert_eq!(docker, State::NotReady);
    assert!(
        said.contains("not found"),
        "Docker's own reason is kept: {said}"
    );
    assert!(text(&dir, &lines).contains("3 things above are not ready yet"));
}

#[test]
fn a_stackvet_toml_that_does_not_read_says_why() {
    let dir = folder("unreadable");
    std::fs::write(dir.join("stackvet.toml"), "[app\nname = \n").unwrap();
    let lines = ask(&dir, false, &docker_ok);
    std::fs::remove_dir_all(&dir).ok();
    let (toml, said) = state(&lines, "stackvet.toml");
    assert_eq!(toml, State::NotReady);
    assert!(said.contains("does not read"), "{said}");
    assert_eq!(state(&lines, "how to start the app").0, State::CannotTell);
}

#[test]
fn a_stackvet_toml_without_a_start_command_names_what_is_missing() {
    let dir = folder("no-run");
    std::fs::write(dir.join("stackvet.toml"), READS).unwrap();
    let lines = ask(&dir, false, &docker_ok);
    std::fs::remove_dir_all(&dir).ok();
    // The setup: the file itself reads.
    assert_eq!(state(&lines, "stackvet.toml").0, State::Ready);
    let (start, said) = state(&lines, "how to start the app");
    assert_eq!(start, State::NotReady);
    assert!(said.contains("image, start"), "{said}");
}

#[test]
fn inside_the_container_docker_is_not_asked_and_says_why() {
    let dir = folder("container");
    let never =
        || -> Result<(), CannotRun> { panic!("docker was asked from inside the container") };
    let lines = ask(&dir, true, &never);
    std::fs::remove_dir_all(&dir).ok();
    let (docker, said) = state(&lines, "Docker");
    assert_eq!(docker, State::CannotTell);
    assert!(said.contains("installed on the computer"), "{said}");
}

#[test]
fn the_old_name_reads_and_is_said() {
    let dir = folder("old-name");
    std::fs::write(dir.join(sv_frameworks::names::OLD_MANIFEST), RUNS).unwrap();
    let lines = ask(&dir, false, &docker_ok);
    std::fs::remove_dir_all(&dir).ok();
    let (toml, said) = state(&lines, "stackvet.toml");
    assert_eq!(toml, State::Ready);
    assert!(said.contains(sv_frameworks::names::OLD_MANIFEST), "{said}");
    assert_eq!(state(&lines, "how to start the app").0, State::Ready);
}

#[test]
fn no_data_is_not_ready() {
    let dir = folder("no-data");
    let lines = answers(
        &dir,
        &Asked {
            version: "sv 0.1.0 (commit test)",
            data: Err("no data folder beside the program".to_owned()),
            in_container: true,
            backend: &docker_ok,
        },
    );
    std::fs::remove_dir_all(&dir).ok();
    let (sv, said) = state(&lines, "sv");
    assert_eq!(sv, State::NotReady);
    assert!(said.contains("no data folder beside the program"), "{said}");
}
