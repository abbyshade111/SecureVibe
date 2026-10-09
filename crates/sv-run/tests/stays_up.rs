//! V16.5.4: whether the app was still running after the questions, read from a real container.
//!
//! The judgment is tested against recorded states in `sv_check::running`; this is the part that
//! cannot be: that the run really reads the container after the questions, and that an app a
//! request stopped reads as stopped. Without a container backend it says so and checks the
//! honest-absence path, as the fence tests do.

use std::path::PathBuf;
use sv_check::probes::ProbeRequest;
use sv_manifest::Manifest;
use sv_run::{Backend, CannotRun, RunPlan, docker::DockerBackend};

fn plan() -> RunPlan {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/stops-app");
    let manifest = Manifest::load(&dir.join("stackvet.toml")).expect("stops fixture manifest");
    RunPlan::from_manifest(&manifest, &dir).expect("stops fixture declares how to run")
}

fn get(id: &str, path: &str) -> ProbeRequest {
    ProbeRequest {
        id: id.into(),
        method: "GET".into(),
        path: path.into(),
        headers: Vec::new(),
        body: None,
    }
}

#[test]
fn an_app_a_request_stopped_is_found_stopped_and_one_left_alone_is_not() {
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
    println!("container backend present; running the fixture app for real");
    let plan = plan();

    // The control: asked only for its home page, it is still up and answering afterwards.
    let left_alone = backend
        .run(&plan, &[get("home", "/cgi-bin/home.sh")])
        .expect("the fixture app should come up");
    assert!(left_alone.healthy);
    assert!(
        left_alone
            .probe_responses
            .iter()
            .any(|r| r.id == "home" && r.body.contains("stops fixture")),
        "the request reached it: {:?}",
        left_alone.probe_responses
    );
    assert_eq!(left_alone.liveness.len(), 1, "{:?}", left_alone.liveness);
    let l = &left_alone.liveness[0];
    assert_eq!(
        (l.status.as_str(), l.answered, l.restarts),
        ("running", true, 0),
        "{l:?}"
    );
    let fine = sv_check::running::evaluate(&[], &[], &[], &left_alone.liveness);
    assert!(fine.findings.is_empty(), "{:?}", fine.findings);

    // Asked for the page that stops it, it is gone afterwards, and that is a finding.
    let stopped = backend
        .run(&plan, &[get("stop", "/cgi-bin/stop.sh")])
        .expect("the fixture app should come up");
    assert!(stopped.healthy, "it was up before the questions");
    let l = &stopped.liveness[0];
    assert!(l.status != "running" || !l.answered, "{l:?}");
    assert!(!l.out_of_memory, "{l:?}");
    let found = sv_check::running::evaluate(&[], &[], &[], &stopped.liveness);
    assert_eq!(
        found
            .findings
            .iter()
            .map(|f| f.rule_id.as_str())
            .collect::<Vec<_>>(),
        [sv_check::running::STAYED_UP],
        "{:?}",
        stopped.liveness
    );
}
