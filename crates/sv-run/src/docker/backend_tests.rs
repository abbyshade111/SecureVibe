//! Whether Docker is a backend `sv` can use: one that runs Linux containers (backend 0120).

use super::*;

#[test]
fn docker_that_runs_linux_containers_is_a_backend() {
    assert!(linux_containers(0, "linux\n").is_ok());
    assert!(linux_containers(0, "  linux  ").is_ok());
}

#[test]
fn docker_that_runs_windows_containers_is_not_and_says_what_to_change() {
    let Err(absent) = linux_containers(0, "windows\r\n") else {
        panic!("Windows containers were taken for a backend");
    };
    assert!(matches!(absent, CannotRun::NoBackend { .. }));
    let said = absent.explain();
    for part in [
        "Windows containers",
        "Switch to Linux containers",
        "not assessed",
    ] {
        assert!(said.contains(part), "{part} in {said}");
    }
}

#[test]
fn an_answer_that_is_neither_or_a_failure_is_no_backend_with_what_docker_said() {
    for (code, answer, part) in [
        (0, "", "did not say it runs Linux containers"),
        (0, "plan9\nmore", "`plan9`"),
        (
            1,
            "Cannot connect to the Docker daemon\n",
            "Cannot connect to the Docker daemon",
        ),
        (1, "", "no detail"),
    ] {
        let Err(absent) = linux_containers(code, answer) else {
            panic!("{answer:?} was taken for a backend");
        };
        let said = absent.explain();
        assert!(said.contains(part), "{part} in {said}");
        assert!(said.contains("not assessed"), "{said}");
    }
}
