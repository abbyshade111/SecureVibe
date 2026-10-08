//! `image` under `[stack.run]` is held to Docker's grammar before the plan is made (the review of
//! 8 October 2026, item 6): a value Docker would read as an option never reaches its command line.

use super::{CannotRun, RunPlan};
use std::path::Path;
use sv_manifest::Manifest;

fn plan_for(image: &str) -> Result<RunPlan, CannotRun> {
    let mut m = Manifest::default();
    m.stack.run.image = Some(image.to_owned());
    m.stack.run.start = Some("gunicorn app:app".to_owned());
    RunPlan::from_manifest(&m, Path::new("/tmp/app"))
}

#[test]
fn an_image_docker_would_read_as_an_option_is_refused_before_the_run() {
    for image in [
        "--privileged",
        "-v",
        "python:3.12 --privileged",
        "Python:3.12",
    ] {
        let err = plan_for(image).unwrap_err();
        let CannotRun::BadImage { image: named, why } = &err else {
            panic!("{image:?}: {err:?}");
        };
        assert_eq!(named, image);
        assert!(!why.is_empty());
        let said = err.explain();
        assert!(
            said.contains("not a name Docker reads as one") && said.contains("not assessed"),
            "{said}"
        );
    }
}

#[test]
fn the_names_apps_really_use_make_a_plan() {
    for image in [
        "python:3.12-slim",
        "node:22",
        "ghcr.io/abbyshade111/securevibe-sv:latest",
        "localhost:5000/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ] {
        let plan = plan_for(image).unwrap_or_else(|e| panic!("{image}: {e:?}"));
        assert_eq!(plan.image, image);
    }
}
