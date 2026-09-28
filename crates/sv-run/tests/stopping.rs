//! A run that takes too long is stopped, and a run that was stopped leaves nothing behind.
//!
//! Real containers, as in `fence.rs`, and the same rule: with no container backend the tests check
//! the honest-absence path and say which branch they took, rather than passing on nothing.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};
use sv_manifest::Manifest;
use sv_run::{Backend, CannotRun, RunPlan, cleanup, docker::DockerBackend};

fn plan() -> RunPlan {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/static-app");
    let manifest = Manifest::load(&dir.join("securevibe.toml")).expect("fixture manifest");
    RunPlan::from_manifest(&manifest, &dir).expect("fixture declares how to run")
}

/// The backend, or `None` after checking that its absence is reported as not assessed.
fn backend() -> Option<DockerBackend> {
    let backend = DockerBackend::new();
    match backend.available() {
        Ok(()) => {
            println!("container backend present; running for real");
            Some(backend)
        }
        Err(absent) => {
            println!("no container backend here; checking the honest-absence path instead");
            assert!(matches!(absent, CannotRun::NoBackend { .. }));
            assert!(
                absent.explain().contains("not assessed"),
                "{}",
                absent.explain()
            );
            None
        }
    }
}

#[test]
fn a_suite_still_running_at_its_limit_is_stopped_and_one_that_finishes_is_not() {
    let Some(backend) = backend() else { return };

    // The control: a suite that finishes inside the same limit is read as it always was.
    let mut quick = plan();
    quick.test = Some("echo all good".to_owned());
    quick.test_limit = Duration::from_secs(20);
    let tests = backend
        .run(&quick, &[])
        .expect("the fixture runs")
        .tests
        .expect("tests ran");
    assert_eq!((tests.exit_code, tests.stopped_after), (0, None));
    assert!(tests.output.contains("all good"), "{:?}", tests.output);

    let mut slow = plan();
    slow.test = Some("echo started; sleep 120".to_owned());
    slow.test_limit = Duration::from_secs(3);
    let started = Instant::now();
    let tests = backend
        .run(&slow, &[])
        .expect("the fixture runs")
        .tests
        .expect("tests ran");
    assert!(
        started.elapsed() < Duration::from_secs(100),
        "the run waited for the suite instead of stopping it: {:?}",
        started.elapsed()
    );
    assert_eq!(tests.stopped_after, Some(Duration::from_secs(3)));
    assert_ne!(
        tests.exit_code, 0,
        "a stopped suite must never read as passing"
    );
    assert_eq!(tests.report, None, "nothing a stopped suite wrote is read");
    assert!(
        tests.output.contains("started"),
        "what it printed is kept: {:?}",
        tests.output
    );
    assert!(
        tests
            .report_note
            .as_deref()
            .unwrap_or("")
            .contains("3 seconds"),
        "{:?}",
        tests.report_note
    );
}

fn docker(args: &[&str]) -> (bool, String) {
    let out = Command::new("docker")
        .args(args)
        .output()
        .expect("docker runs");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).trim().to_owned(),
    )
}

fn exists(name: &str) -> bool {
    docker(&["container", "inspect", name]).0
}

/// The id of a process that has ended.
fn ended_pid() -> u32 {
    let mut child = Command::new("true").spawn().expect("true runs");
    let pid = child.id();
    child.wait().expect("it ends");
    pid
}

#[test]
fn a_run_first_removes_what_a_stopped_run_left_on_this_machine_and_nothing_else() {
    let Some(backend) = backend() else { return };
    let machine = cleanup::owner()
        .rsplit_once(':')
        .map(|(m, _)| m.to_owned())
        .expect("owner is machine:pid");
    let dead = ended_pid();
    let me = std::process::id();
    let name = |what: &str| format!("sv-leftover-test-{me}-{what}");
    let start = |what: &str, owner: &str| {
        let label = format!("{}={owner}", cleanup::OWNER_LABEL);
        let (ok, out) = docker(&[
            "run",
            "-d",
            "--label",
            &label,
            "--name",
            &name(what),
            "busybox:1.36",
            "sleep",
            "300",
        ]);
        assert!(ok, "could not start the {what} container: {out}");
    };
    start("left", &format!("{machine}:{dead}"));
    start("elsewhere", &format!("another-machine:{dead}"));
    start("running", &format!("{machine}:{me}"));
    let (ok, _) = docker(&[
        "network",
        "create",
        "--label",
        &format!("{}={machine}:{dead}", cleanup::OWNER_LABEL),
        &name("net"),
    ]);
    assert!(ok, "could not create the left-over network");
    // Everything the test looks for is really there before the run.
    for what in ["left", "elsewhere", "running"] {
        assert!(exists(&name(what)), "{what} was not started");
    }

    let outcome = backend.run(&plan(), &[]).expect("the fixture runs");
    let removed = outcome.left_over_removed.clone();
    let cleanup_after = || {
        for what in ["left", "elsewhere", "running"] {
            let _ = docker(&["rm", "-f", &name(what)]);
        }
        let _ = docker(&["network", "rm", &name("net")]);
    };
    let result = std::panic::catch_unwind(|| {
        assert!(removed.contains(&name("left")), "{removed:?}");
        assert!(removed.contains(&name("net")), "{removed:?}");
        assert!(!exists(&name("left")), "the leftover is gone");
        assert!(
            exists(&name("elsewhere")),
            "another machine's is left alone"
        );
        assert!(
            exists(&name("running")),
            "a running process's is left alone"
        );
        let said = cleanup::removed_sentence(&removed).expect("something was removed");
        assert!(said.contains(&name("left")), "{said}");
    });
    cleanup_after();
    result.unwrap();
}
