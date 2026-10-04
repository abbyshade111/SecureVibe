//! Ctrl-C during `sv run` removes what the run started. A signal ends a Rust process without
//! unwinding, so before this the app's containers and network stayed behind after every interrupted
//! run, under names nobody would recognize.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Containers and networks a run by process `pid` made, by the name every run gives them.
fn made_by(pid: u32) -> Vec<String> {
    let prefix = format!("sv-{pid}-");
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
fn ctrl_c_during_a_run_removes_its_containers_and_network() {
    interrupt(&["run"]);
}

#[test]
fn ctrl_c_during_report_run_writes_no_report_and_removes_the_run() {
    interrupt(&["report", "--run", "--out", "REPORT"]);
}

/// Starts `sv <command> <app>`, sends Ctrl-C once the run's containers are up, and checks what is
/// left. `REPORT` in `command` is the report folder, which must not be written.
fn interrupt(command: &[&str]) {
    let docker_up = Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !docker_up {
        println!("no container backend here; there is no run to interrupt");
        return;
    }
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "sv-interrupt-{}-{}",
        std::process::id(),
        command[0]
    ));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("index.html"), "<p>hello</p>\n").unwrap();
    // A suite that would hold the run for ten minutes, so the run is certainly still going when
    // it is interrupted.
    std::fs::write(
        dir.join("securevibe.toml"),
        "manifest-version = 1\n[app]\nname = \"Interrupted\"\naudience = \"just-me\"\n\
         deployment = \"local-only\"\n[stack]\nlanguages = []\n[stack.run]\n\
         image = \"busybox:1.36\"\nstart = \"httpd -f -h /app -p $PORT\"\n\
         health = \"/index.html\"\ntest = \"sleep 600\"\n",
    )
    .unwrap();

    let report = dir.join("report");
    let report_arg = report.to_string_lossy().into_owned();
    let args: Vec<&str> = command
        .iter()
        .map(|a| {
            if *a == "REPORT" {
                report_arg.as_str()
            } else {
                a
            }
        })
        .collect();
    let mut sv = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(&args[..1])
        .arg(&dir)
        .args(&args[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sv starts");
    let pid = sv.id();

    // The setup worked: the run has really started containers, and is still going.
    let deadline = Instant::now() + Duration::from_secs(180);
    while made_by(pid).len() < 2 {
        if sv.try_wait().unwrap().is_some() {
            // Say why: without what sv said, a run refused for a reason of its own read the same as
            // a test that went wrong.
            let out = sv.wait_with_output().unwrap();
            panic!(
                "sv ended before starting anything: {}",
                String::from_utf8_lossy(&out.stderr).replace('\n', " / ")
            );
        }
        assert!(
            Instant::now() < deadline,
            "the run never started its containers"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    std::thread::sleep(Duration::from_secs(3));
    let before = made_by(pid);
    assert!(sv.try_wait().unwrap().is_none(), "sv ended by itself");

    let sent = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .unwrap();
    assert!(sent.success());
    let out = sv.wait_with_output().unwrap();
    let after = made_by(pid);
    let wrote = report.exists();
    std::fs::remove_dir_all(&dir).ok();
    // Removed by hand if the run did not, so a failure here does not leave them for the next.
    for name in &after {
        let _ = Command::new("docker").args(["rm", "-f", name]).output();
        let _ = Command::new("docker")
            .args(["network", "rm", name])
            .output();
    }

    let said = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(130), "{said}");
    assert!(said.contains("Stopped with Ctrl-C"), "{said}");
    assert!(!wrote, "a report was written for a run stopped with Ctrl-C");
    assert!(
        after.is_empty(),
        "left behind after Ctrl-C: {after:?} (there were {before:?})"
    );
}
