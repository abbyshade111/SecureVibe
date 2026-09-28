//! Ctrl-C in the middle of a run: the run returns, and its teardown removes the containers and the
//! network. A test binary of its own, because Ctrl-C here is sent to this very process, and what it
//! sets is process-wide.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};
use sv_manifest::Manifest;
use sv_run::{Backend, RunPlan, docker::DockerBackend};

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
fn ctrl_c_ends_the_run_and_the_teardown_still_runs() {
    let backend = DockerBackend::new();
    if backend.available().is_err() {
        println!("no container backend here; there is no run to interrupt");
        return;
    }
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/static-app");
    let manifest = Manifest::load(&dir.join("securevibe.toml")).expect("fixture manifest");
    let mut plan = RunPlan::from_manifest(&manifest, &dir).expect("fixture declares how to run");
    plan.test = Some("sleep 600".to_owned());

    let me = std::process::id().to_string();
    let signal = std::thread::spawn(move || {
        // The setup worked: containers are really there before the interrupt is sent.
        let deadline = Instant::now() + Duration::from_secs(180);
        while left_behind().len() < 2 {
            assert!(Instant::now() < deadline, "the run never started");
            std::thread::sleep(Duration::from_millis(500));
        }
        std::thread::sleep(Duration::from_secs(3));
        let there = left_behind();
        let sent = Command::new("kill").args(["-INT", &me]).status().unwrap();
        assert!(sent.success());
        there
    });
    let started = Instant::now();
    let outcome = backend.run(&plan, &[]);
    let there = signal.join().expect("the interrupt was sent");
    let after = left_behind();
    for name in &after {
        let _ = Command::new("docker").args(["rm", "-f", name]).output();
        let _ = Command::new("docker")
            .args(["network", "rm", name])
            .output();
    }

    assert!(sv_run::interrupted());
    assert!(
        started.elapsed() < Duration::from_secs(300),
        "the run waited out its test command"
    );
    // Whatever the run hands back, nothing it got to counts: the tests credit nothing.
    if let Ok(o) = &outcome {
        assert!(o.tests.as_ref().is_none_or(|t| t.exit_code != 0), "{o:?}");
    }
    assert!(
        after.is_empty(),
        "left behind: {after:?} (there were {there:?})"
    );
}
