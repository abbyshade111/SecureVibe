//! What happened to the containers, said where it was silent or wrong (backlog 226, part 2, item 18).

use super::*;
use crate::{ContainerRecord, Exited};

/// A backend whose `docker` is `script`, written to a scratch folder.
fn backend_running(test: &str, script: &str) -> DockerBackend {
    use std::os::unix::fs::PermissionsExt;
    let dir =
        std::env::temp_dir().join(format!("sv-container-record-{test}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let docker = dir.join("docker");
    std::fs::write(&docker, script).unwrap();
    std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755)).unwrap();
    DockerBackend {
        binary: docker.to_string_lossy().into_owned(),
        owner: crate::cleanup::owner(),
        cpus: OnceLock::new(),
        run: std::sync::Mutex::new(None),
        clock_offset: OnceLock::new(),
        sidecar_lost: std::sync::Mutex::new(None),
        left_behind: std::sync::Mutex::new(Vec::new()),
        request_times: std::sync::Mutex::new(Vec::new()),
    }
}

#[test]
fn a_teardown_names_what_it_could_not_remove_and_not_what_was_already_gone() {
    // Until 10 October 2026 each removal's answer was dropped (`let _`).
    let backend = backend_running(
        "teardown",
        "#!/bin/sh\n\
         case \"$1 $2\" in\n\
         \"ps -aq\") echo app1; echo gone1 ;;\n\
         \"network ls\") echo net1 ;;\n\
         \"rm -f\") if [ \"$3\" = gone1 ]; then echo \"Error: No such container: gone1\" >&2; exit 1; fi;\n\
           echo \"Error response from daemon: container $3 is busy\" >&2; exit 1 ;;\n\
         esac\n\
         exit 0\n",
    );
    let guard = Teardown {
        backend: &backend,
        run: "sv-1-1-test".to_owned(),
        network: "sv-1-1-test-net".to_owned(),
        containers: vec!["sv-1-1-test-app".to_owned()],
        done: false,
    };
    assert_eq!(
        guard.finish(),
        ["container app1 (Error response from daemon: container app1 is busy)"]
    );
}

#[test]
fn how_a_container_ended_is_read_from_docker_inspect() {
    assert_eq!(
        exited_from("exited 137 true\n"),
        Some(Exited {
            code: 137,
            out_of_memory: true
        })
    );
    assert_eq!(
        exited_from("exited 3 false"),
        Some(Exited {
            code: 3,
            out_of_memory: false
        })
    );
    assert_eq!(exited_from("running 0 false"), None);
    assert_eq!(exited_from(""), None);
}

#[test]
fn an_app_that_exited_at_once_is_not_said_to_have_been_waited_for_a_minute() {
    let said = |exited| {
        CannotRun::NeverReady {
            waited_seconds: 2,
            detail: "Its last words: boom.".to_owned(),
            loopback: None,
            crashed: true,
            exited,
        }
        .explain()
    };
    let stopped = said(Some(Exited {
        code: 3,
        out_of_memory: false,
    }));
    assert!(
        stopped.starts_with("The app stopped 2s after it started, with exit code 3"),
        "{stopped}"
    );
    assert!(!stopped.contains("within"), "{stopped}");
    let killed = said(Some(Exited {
        code: 137,
        out_of_memory: true,
    }));
    assert!(
        killed.contains("killed for using more memory than the container was given"),
        "{killed}"
    );
    assert!(said(None).contains("never answered on its health path within 2s"));
}

#[test]
fn the_record_says_the_wait_the_fence_what_was_left_and_the_kept_volume() {
    assert_eq!(ContainerRecord::default().sentences(), None);
    let said = ContainerRecord {
        ready_after_seconds: Some(4),
        network_made: Some(
            "with `com.docker.network.bridge.gateway_mode_ipv4=isolated`".to_owned(),
        ),
        not_removed: vec!["network n1 (busy)".to_owned()],
        volumes_kept: vec!["sv-deps-py-abc".to_owned()],
    }
    .sentences()
    .unwrap();
    for words in [
        "answered on its health path 4s after it started",
        "Its fenced network was made with `com.docker.network.bridge.gateway_mode_ipv4=isolated`.",
        "these could not be removed: network n1 (busy)",
        "`docker volume rm sv-deps-py-abc` removes it",
        "label=stackvet.deps",
    ] {
        assert!(said.contains(words), "missing {words:?} in {said}");
    }
}

#[test]
fn a_run_that_fails_says_what_its_teardown_could_not_remove() {
    // The network cannot be made, so the run fails before the app starts; its teardown then finds
    // the run's container and cannot remove it. Until 10 October 2026 that answer was dropped with
    // the guard, and only a run that finished said what it left (backlog 226, part 2, item 18).
    use crate::Backend;
    let backend = backend_running(
        "failed-run",
        "#!/bin/sh\n\
         case \"$1 $2\" in\n\
         \"network create\") echo \"Error response from daemon: no networks left\" >&2; exit 1 ;;\n\
         \"ps -aq\") case \"$*\" in *org.stackvet.run=*) echo app1 ;; esac ;;\n\
         \"rm -f\") echo \"Error response from daemon: container $3 is busy\" >&2; exit 1 ;;\n\
         esac\n\
         exit 0\n",
    );
    let mut manifest = sv_manifest::Manifest::default();
    manifest.stack.run.image = Some("python:3.12".to_owned());
    manifest.stack.run.start = Some("gunicorn app:app".to_owned());
    let plan = crate::RunPlan::from_manifest(&manifest, std::path::Path::new("/tmp/app")).unwrap();
    let failed = backend.run(&plan, &[]).unwrap_err();
    assert!(
        matches!(failed.reason, CannotRun::BackendFailed { .. }),
        "the run is meant to fail on the network: {:?}",
        failed.reason
    );
    assert_eq!(
        failed.not_removed,
        ["container app1 (Error response from daemon: container app1 is busy)"]
    );
    let said = failed.explain();
    assert!(
        said.contains("When the run ended, these could not be removed: container app1")
            && said.contains("`docker rm -f <name>`"),
        "{said}"
    );
    // A run after it starts afresh: what the last one left is not said again.
    assert!(backend.left_behind.lock().unwrap().is_empty());
}

#[test]
fn each_request_is_timed_where_it_is_sent_even_one_that_fails() {
    // Backlog 226, part 2, item 13: a time on each request inside a suite, taken in `probe`, so no
    // suite has to time itself.
    let backend = backend_running("request-times", "#!/bin/sh\nsleep 0.05\nexit 1\n");
    let request = sv_check::probes::ProbeRequest {
        id: "probe-1".to_owned(),
        method: "GET".to_owned(),
        path: "/".to_owned(),
        headers: Vec::new(),
        body: None,
    };
    assert!(
        backend
            .probe(&Via::Sidecar("sv-1-probe"), "app", 8000, &request)
            .is_none()
    );
    let times = backend.take_request_times();
    assert_eq!(times.len(), 1, "{times:?}");
    assert_eq!(times[0].0, "probe-1");
    assert!(times[0].1 >= 40, "{times:?}");
    assert!(backend.take_request_times().is_empty(), "taken once");
}
