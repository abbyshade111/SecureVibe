//! A run has an end: the app's own tests are stopped when they take too long, and a run cut short
//! still removes what it started. Run for real when there is a container backend, and said so when
//! there is not.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};
use sv_manifest::Manifest;
use sv_run::{Backend, RunPlan, docker::DockerBackend};

fn plan(test: &str) -> RunPlan {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/static-app");
    let manifest = Manifest::load(&dir.join("stackvet.toml")).expect("fixture manifest");
    let mut plan = RunPlan::from_manifest(&manifest, &dir).expect("fixture declares how to run");
    plan.test = Some(test.to_owned());
    plan.test_limit = Duration::from_secs(4);
    plan
}

/// Containers and networks this process's runs made, by the name every run gives them.
fn left_behind() -> Vec<String> {
    let prefix = format!("sv-{}-", std::process::id());
    let mut names = Vec::new();
    for args in [
        &["ps", "-a", "--format", "{{.Names}}"][..],
        &["network", "ls", "--format", "{{.Name}}"][..],
    ] {
        let out = Command::new("docker").args(args).output().expect("docker");
        names.extend(
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|n| n.starts_with(&prefix))
                .map(str::to_owned),
        );
    }
    names
}

#[test]
fn a_suite_that_hangs_is_stopped_at_the_limit_and_the_run_still_cleans_up() {
    let backend = DockerBackend::new();
    if backend.available().is_err() {
        println!("no container backend here; the limit on the app's tests cannot be exercised");
        return;
    }
    // The control: the same app, a suite that finishes, is not stopped.
    let quick = backend
        .run(&plan("echo all good"), &[])
        .expect("the fixture app should come up");
    let tests = quick.tests.expect("a test command was declared");
    assert_eq!(tests.stopped_after, None, "{tests:?}");
    assert_eq!(tests.exit_code, 0, "{tests:?}");

    let started = Instant::now();
    let hung = backend
        .run(&plan("echo started the suite; sleep 600"), &[])
        .expect("the fixture app should come up");
    let took = started.elapsed();
    let tests = hung.tests.expect("a test command was declared");
    assert_eq!(
        tests.stopped_after,
        Some(Duration::from_secs(4)),
        "{tests:?}"
    );
    assert_ne!(
        tests.exit_code, 0,
        "a stopped suite must not read as passed"
    );
    assert_eq!(tests.report, None, "nothing is read from a suite cut short");
    assert!(
        tests.output.contains("started the suite"),
        "what it printed before it was stopped is kept: {tests:?}"
    );
    assert!(took < Duration::from_secs(120), "the run took {took:?}");
    assert_eq!(left_behind(), Vec::<String>::new());
}
