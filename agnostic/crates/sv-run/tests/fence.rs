//! Runs a real app in a real container, and checks the fence actually held.
//!
//! These tests never skip quietly. A test whose setup can fail without saying so is worse than no
//! test: it passes whatever the code does. When there is no container backend, the assertions
//! switch to the honest-absence path — `sv` must report *not assessed* — so something real is
//! always being checked, and the run prints which branch it took.

use std::path::PathBuf;
use std::process::Command;
use sv_manifest::Manifest;
use sv_run::{Backend, CannotRun, Fence, RunPlan, docker::DockerBackend};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/static-app")
}

fn plan() -> RunPlan {
    let dir = fixture();
    let manifest = Manifest::load(&dir.join("securevibe.toml")).expect("fixture manifest");
    RunPlan::from_manifest(&manifest, &dir).expect("fixture declares how to run")
}

#[test]
fn an_app_runs_inside_the_fence_or_sv_says_it_was_not_assessed() {
    let backend = DockerBackend::new();
    match backend.available() {
        Err(absent) => {
            // No backend. The thing to verify is that `sv` says so honestly rather than reporting
            // the app as failing — which is the case most people running `sv` will be in.
            println!("no container backend here; checking the honest-absence path instead");
            assert!(matches!(absent, CannotRun::NoBackend { .. }));
            assert!(
                absent.explain().contains("not assessed"),
                "absence must be reported as not assessed: {}",
                absent.explain()
            );
        }
        Ok(()) => {
            println!("container backend present; running the fixture app for real");
            let outcome = backend
                .run(&plan(), &[])
                .expect("the fixture app should come up");
            assert!(outcome.healthy, "the app answered its health path");
            assert_eq!(outcome.fence, Fence::DockerInternalNetwork);
            assert_eq!(outcome.tests, None, "the fixture declares no test command");
        }
    }
}

#[test]
fn an_app_that_never_starts_is_not_assessed_rather_than_failed() {
    let backend = DockerBackend::new();
    if backend.available().is_err() {
        println!("no container backend here; nothing to run");
        return;
    }
    // A start command that exits immediately. An app that will not run under `sv` has not been
    // shown to be insecure, and must never be reported as though it had failed a check.
    let mut p = plan();
    p.start = "false".to_owned();
    let err = backend.run(&p, &[]).unwrap_err();
    match &err {
        CannotRun::NeverReady { .. } => {}
        other => panic!("expected NeverReady, got {other:?}"),
    }
    assert!(
        err.explain().contains("not been shown"),
        "{}",
        err.explain()
    );
}

#[test]
fn the_fence_really_blocks_outbound_traffic() {
    // The security property the whole runner rests on, checked by breaking out rather than by
    // trusting the flag. `--internal` was measured to block outbound and DNS; this asserts the
    // runner actually uses it, so that a future edit swapping it for a bridge fails here.
    let backend = DockerBackend::new();
    if backend.available().is_err() {
        println!("no container backend here; the fence cannot be exercised");
        return;
    }

    // First: confirm this machine can reach the outside at all. Without it, "blocked" below
    // would prove nothing — which is exactly how an earlier attempt at this measurement went
    // wrong, reporting a fence where there was only a dead address.
    let host_reaches = Command::new("nc")
        .args(["-z", "-w", "4", "1.1.1.1", "53"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(
        host_reaches,
        "this machine cannot reach 1.1.1.1:53, so a blocked container proves nothing"
    );

    let network = "sv-fence-assert-net";
    let container = "sv-fence-assert-app";
    let _ = Command::new("docker")
        .args(["rm", "-f", container])
        .output();
    let _ = Command::new("docker")
        .args(["network", "rm", network])
        .output();

    let created = Command::new("docker")
        .args(["network", "create", "--internal", network])
        .output()
        .expect("docker network create");
    assert!(
        created.status.success(),
        "could not create the fenced network"
    );

    let started = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            container,
            "--network",
            network,
            "busybox:1.36",
            "sh",
            "-c",
            "sleep 30",
        ])
        .output()
        .expect("docker run");
    assert!(started.status.success(), "could not start the container");

    let escaped = Command::new("docker")
        .args(["exec", container, "nc", "-z", "-w", "4", "1.1.1.1", "53"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let _ = Command::new("docker")
        .args(["rm", "-f", container])
        .output();
    let _ = Command::new("docker")
        .args(["network", "rm", network])
        .output();

    assert!(
        !escaped,
        "a container on an --internal network reached the internet: the fence is not holding"
    );
}

#[test]
fn the_runner_refuses_to_run_anything_on_an_unfenced_network() {
    // The test above proves Docker fences an --internal network. It does not prove `sv` uses one:
    // it would pass unchanged if the runner switched to a bridge. This checks the runner's own
    // verification, which is what actually stands between untrusted code and the internet.
    let backend = DockerBackend::new();
    if backend.available().is_err() {
        println!("no container backend here; the fence check cannot be exercised");
        return;
    }
    let network = "sv-unfenced-assert-net";
    let _ = Command::new("docker")
        .args(["network", "rm", network])
        .output();

    // A perfectly ordinary bridge network — what you get if `--internal` is ever dropped.
    let created = Command::new("docker")
        .args(["network", "create", network])
        .output()
        .expect("docker network create");
    assert!(
        created.status.success(),
        "could not create the bridge network"
    );

    let verdict = backend.verify_fenced(network);
    let _ = Command::new("docker")
        .args(["network", "rm", network])
        .output();

    match verdict {
        Err(CannotRun::BackendFailed { detail }) => assert!(
            detail.contains("not internal"),
            "the refusal must say why: {detail}"
        ),
        other => panic!("an unfenced network must be refused, got {other:?}"),
    }
}

#[test]
fn the_fence_the_runner_creates_is_the_fenced_kind() {
    // And the other direction: the network the runner actually makes must pass its own check.
    let backend = DockerBackend::new();
    if backend.available().is_err() {
        println!("no container backend here; nothing to verify");
        return;
    }
    let network = "sv-fenced-assert-net";
    let _ = Command::new("docker")
        .args(["network", "rm", network])
        .output();
    let created = Command::new("docker")
        .args(["network", "create", "--internal", network])
        .output()
        .expect("docker network create");
    assert!(created.status.success());
    let verdict = backend.verify_fenced(network);
    let _ = Command::new("docker")
        .args(["network", "rm", network])
        .output();
    assert!(
        verdict.is_ok(),
        "an --internal network must pass: {verdict:?}"
    );
}

fn probe_plan() -> RunPlan {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/probe-app");
    let manifest = Manifest::load(&dir.join("securevibe.toml")).expect("probe fixture manifest");
    RunPlan::from_manifest(&manifest, &dir).expect("probe fixture declares how to run")
}

#[test]
fn the_probes_reach_the_app_through_the_fence_or_sv_says_it_was_not_assessed() {
    // The one test that exercises the transport: a real container, a real socket, a real response
    // read back. Everything else about the probes is judged against recorded answers, which cannot
    // tell whether a single byte ever left.
    let backend = DockerBackend::new();
    let plan = probe_plan();
    let requests = sv_check::probes::requests(&plan.health_path);

    if let Err(absent) = backend.available() {
        println!("no container backend here; checking the honest-absence path instead");
        assert!(matches!(absent, CannotRun::NoBackend { .. }));
        assert!(
            absent.explain().contains("not assessed"),
            "{}",
            absent.explain()
        );
        return;
    }

    println!("container backend present; probing the fixture app for real");
    let outcome = backend
        .run(&plan, &requests)
        .expect("the fixture app should come up");
    assert!(outcome.healthy);
    assert_eq!(outcome.fence, Fence::DockerInternalNetwork);

    let answer = |id: &str| {
        outcome
            .probe_responses
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("no answer to `{id}`: {:?}", outcome.probe_responses))
    };

    // First, that the setup worked. A probe suite whose requests silently went nowhere would pass
    // every assertion below by finding nothing, which is the failure this whole file exists to
    // prevent.
    let home = answer("home");
    assert_eq!(home.status, 200, "{home:?}");
    assert!(
        home.body.contains("probe fixture"),
        "the body came back: {home:?}"
    );
    assert!(
        home.header("set-cookie")
            .is_some_and(|c| c.contains("session=abc")),
        "the fixture's cookie came back: {home:?}"
    );

    // The proof that the request carried what it was asked to carry: the fixture only sends this
    // header when it received an Origin, and it sends back the value it was given.
    let sent_origin = requests
        .iter()
        .find(|r| r.id == "cors")
        .and_then(|r| r.headers.iter().find(|(k, _)| k == "Origin"))
        .map(|(_, v)| v.clone())
        .expect("the suite asks with an Origin");
    let cors = answer("cors");
    assert_eq!(
        cors.header("access-control-allow-origin"),
        Some(sent_origin.as_str()),
        "the Origin this probe sent came back, so the header really travelled: {cors:?}"
    );

    // And that a body is read for a status a client library would have thrown away. This is the
    // reason the probes speak HTTP over a socket rather than through `wget`, which returns no body
    // at all for a 404 — so the thing to check here is that one arrived, whatever it says. Whether
    // a body *looks like* a stack trace is judged offline, against recorded answers; busybox's
    // error page is its own, and this build ignores the `E404:` directive that would replace it.
    let missing = answer("missing");
    assert_eq!(missing.status, 404, "{missing:?}");
    assert!(
        missing.body.contains("404 Not Found"),
        "a body came back with an error status: {missing:?}"
    );

    let findings = sv_check::probes::evaluate(&outcome.probe_responses);
    let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    for expected in [
        "probe.security-headers",
        "probe.cookie-attributes",
        "probe.cors-any-origin",
    ] {
        assert!(ids.contains(&expected), "expected {expected} in {ids:?}");
    }
    // The two this fixture cannot provoke must stay silent rather than guess: busybox's own error
    // page carries no stack trace, and busybox does not echo a TRACE. Both are exercised against
    // recorded answers in `sv-check`; what is verified here is the transport underneath them.
    assert!(!ids.contains(&"probe.error-detail-leak"), "{ids:?}");
    assert!(!ids.contains(&"probe.trace-enabled"), "{ids:?}");
}

#[test]
fn two_runs_in_one_process_do_not_collide() {
    // The names were the process id alone, so the second run asked the daemon for a network that
    // already existed and failed. Deliberate rather than accidental: without this, the only thing
    // catching it is running the other tests in this file on more than one thread, which is a
    // property of how they happen to be invoked.
    let backend = DockerBackend::new();
    if let Err(absent) = backend.available() {
        println!("no container backend here; checking the honest-absence path instead");
        assert!(matches!(absent, CannotRun::NoBackend { .. }));
        assert!(
            absent.explain().contains("not assessed"),
            "{}",
            absent.explain()
        );
        return;
    }
    println!("container backend present; running the same app twice in this process");
    for attempt in 1..=2 {
        let outcome = backend
            .run(&plan(), &[])
            .unwrap_or_else(|e| panic!("run {attempt} of 2 should come up: {e:?}"));
        assert!(outcome.healthy, "run {attempt} of 2 answered");
    }
}
