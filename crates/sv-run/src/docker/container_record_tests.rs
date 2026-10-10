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
