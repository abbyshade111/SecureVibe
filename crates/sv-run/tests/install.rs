//! The install step (ADR-052), against a real container backend: an app that needs a package starts
//! only because `sv` installed it first, the package reached the app, and a second run with the same
//! files reuses the first one's download. The install container's mounts and options are tested
//! without a backend in `sv_run::install`; this is the part that cannot be: that the packages really
//! arrive, read-only, in an app that still has no network. Without a container backend it says so
//! and checks the honest-absence path, as the fence tests do.

use std::path::PathBuf;
use sv_check::probes::ProbeRequest;
use sv_manifest::Manifest;
use sv_run::{Backend, CannotRun, RunPlan, docker::DockerBackend, install::Ecosystem};

fn plan() -> RunPlan {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/install-app");
    let manifest = Manifest::load(&dir.join("securevibe.toml")).expect("install fixture manifest");
    RunPlan::from_manifest(&manifest, &dir).expect("install fixture declares how to run")
}

fn home() -> ProbeRequest {
    ProbeRequest {
        id: "home".into(),
        method: "GET".into(),
        path: "/".into(),
        headers: Vec::new(),
        body: None,
    }
}

#[test]
fn an_app_that_needs_a_package_starts_with_it_installed_and_a_second_run_reuses_the_download() {
    let plan = plan();
    assert!(plan.install, "the fixture asks for the install step");
    let backend = DockerBackend::new();
    if let Err(absent) = backend.available() {
        println!("no container backend here; checking the honest-absence path instead");
        assert!(matches!(absent, CannotRun::NoBackend { .. }));
        return;
    }
    println!("container backend present; installing and running the fixture app for real");

    let first = backend.run(&plan, &[home()]).expect("the fixture app should come up");
    assert!(first.healthy);
    assert_eq!(first.installed.len(), 1, "{:?}", first.installed);
    assert_eq!(first.installed[0].0, Ecosystem::Python);
    let page = first
        .probe_responses
        .iter()
        .find(|r| r.id == "home")
        .expect("the home page answered");
    assert!(
        page.body.contains("install fixture: six 1.16.0"),
        "the installed package reached the app: {}",
        page.body
    );
    // The app itself is still fenced.
    assert_eq!(first.fence, sv_run::Fence::DockerInternalNetwork);

    let second = backend.run(&plan, &[home()]).expect("the fixture app should come up again");
    assert_eq!(
        second.installed,
        vec![(Ecosystem::Python, true)],
        "the same files in the same image reuse the first download"
    );
}

#[test]
fn without_install_the_same_app_cannot_start_because_its_package_is_missing() {
    let mut plan = plan();
    plan.install = false;
    let backend = DockerBackend::new();
    if backend.available().is_err() {
        println!("no container backend here; nothing to compare");
        return;
    }
    match backend.run(&plan, &[home()]).map_err(|failed| failed.reason) {
        Err(CannotRun::NeverReady { detail, .. }) => {
            assert!(detail.contains("six"), "{detail}")
        }
        other => panic!("without the install step the app must not start: {other:?}"),
    }
}
