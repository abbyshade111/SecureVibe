//! `sv run` killed outright cannot remove what it started, so the next run does, and says so. (Ctrl-C
//! is `interrupt.rs`'s: the run removes its own before it exits.)
//!
//! Real containers and the real binary. With no container backend, `sv run` must say the app was
//! not assessed, and that is what is checked instead.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// In Cargo's own scratch folder beside the build, not the system's temporary folder: on a Mac that
/// is under `/var/folders`, which Colima does not share with its machine, so the app's folder
/// arrived empty, `httpd` had no page to serve, and the quick run never answered its health path.
/// The build folder is inside the checkout, which every Mac backend shares.
fn app(name: &str, test: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("sv-stop-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("index.html"), "<p>hello</p>\n").unwrap();
    std::fs::write(
        dir.join("securevibe.toml"),
        format!(
            "manifest-version = 1\n[app]\nname = \"Stop\"\n[stack]\nlanguages = []\n\
             [stack.run]\nimage = \"busybox:1.36\"\nstart = \"httpd -f -h /app -p $PORT\"\n\
             health = \"/index.html\"\n{test}\n"
        ),
    )
    .unwrap();
    dir
}

fn docker_ok() -> bool {
    Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn start_run(app: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("run")
        .arg(app)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sv starts")
}

/// The containers and networks labeled as started by process `pid` on this machine.
fn started_by(pid: u32) -> Vec<String> {
    let machine = sv_run::cleanup::owner()
        .rsplit_once(':')
        .map(|(m, _)| m.to_owned())
        .unwrap();
    let filter = format!("label={}={machine}:{pid}", sv_run::cleanup::OWNER_LABEL);
    let mut names = Vec::new();
    for args in [
        vec!["ps", "-a", "--filter", &filter, "--format", "{{.Names}}"],
        vec![
            "network",
            "ls",
            "--filter",
            &filter,
            "--format",
            "{{.Name}}",
        ],
    ] {
        let out = Command::new("docker")
            .args(&args)
            .output()
            .expect("docker runs");
        names.extend(
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_owned),
        );
    }
    names
}

/// Waits until the run has started its app container, which is when there is something to leave.
fn wait_for_app(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        if started_by(pid).iter().any(|n| n.ends_with("-app")) {
            // The app is up and the suite is sleeping; give it a moment to be well into it.
            std::thread::sleep(Duration::from_secs(3));
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("the run never started its app: {:?}", started_by(pid));
}

fn signal(pid: u32, which: &str) {
    let ok = Command::new("kill")
        .args([which, &pid.to_string()])
        .status()
        .expect("kill runs")
        .success();
    assert!(ok, "kill {which} {pid} failed");
}

fn wait_for_exit(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("wait") {
            return status;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = child.kill();
    panic!("sv did not exit after the signal");
}

/// Waits until no removal the killed run started is still going. Killing `sv` does not kill its
/// `docker` calls: a `docker rm -f` of the sidecar in flight at the kill finishes on its own, and when
/// it did so after the listing below, the list named a container the next run found already gone
/// (seen once on CI). Only removals are waited for: a `docker exec` of the suite, also left going,
/// runs for minutes and removes nothing.
fn wait_for_its_removals(pid: u32) {
    let removals = format!("(rm -f|network rm) sv-{pid}-");
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        let still = Command::new("pgrep")
            .args(["-f", &removals])
            .output()
            .expect("pgrep runs");
        // 1 is pgrep's "nothing matched"; anything else but 0 means it could not look.
        match still.status.code() {
            Some(1) => return,
            Some(0) => std::thread::sleep(Duration::from_millis(200)),
            other => panic!("pgrep could not look for the killed run's removals: {other:?}"),
        }
    }
    panic!("the killed run's removals were still going after two minutes");
}

/// Starts a run with a long suite, kills it outright, and returns what it left behind.
fn leave_a_run_behind(name: &str) -> Vec<String> {
    let dir = app(name, "test = \"sleep 300\"");
    let mut run = start_run(&dir);
    let pid = run.id();
    wait_for_app(pid);
    // `kill -9` runs nothing at all in the process, so this is what used to happen on Ctrl-C too.
    signal(pid, "-KILL");
    wait_for_exit(&mut run);
    wait_for_its_removals(pid);
    let left = started_by(pid);
    assert!(
        left.iter().any(|n| n.ends_with("-app")) && left.iter().any(|n| n.ends_with("-net")),
        "the control: a killed run leaves its app and its network: {left:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
    left
}

fn nothing_left(left: &[String]) -> bool {
    let (containers, networks) = (
        Command::new("docker")
            .args(["ps", "-a", "--format", "{{.Names}}"])
            .output()
            .unwrap(),
        Command::new("docker")
            .args(["network", "ls", "--format", "{{.Name}}"])
            .output()
            .unwrap(),
    );
    let there = format!(
        "{}\n{}",
        String::from_utf8_lossy(&containers.stdout),
        String::from_utf8_lossy(&networks.stdout)
    );
    !left.iter().any(|n| there.lines().any(|l| l.trim() == n))
}

#[test]
fn a_run_killed_outright_is_cleaned_up_by_the_next_one_and_said_to_be() {
    if !docker_ok() {
        println!("no container backend here; nothing to leave behind");
        return;
    }
    let quick = app("next", "");

    // Followed by `sv run`, which says so on the terminal.
    let left = leave_a_run_behind("killed-run");
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("run")
        .arg(&quick)
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(said.contains("Before starting, `sv` removed"), "{said}");
    for name in &left {
        assert!(said.contains(name.as_str()), "{name} named: {said}");
    }
    assert!(nothing_left(&left), "the next run removed all of it");

    // Followed by `sv report --run`, which says so in the report.
    let left = leave_a_run_behind("killed-report");
    let out_dir = quick.join("report");
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(&quick)
        .args(["--run", "--out"])
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let compliance = std::fs::read_to_string(out_dir.join("compliance.md")).unwrap();
    assert!(
        compliance.contains("Before starting, `sv` removed"),
        "{compliance}"
    );
    for name in &left {
        assert!(compliance.contains(name.as_str()), "{name} named");
    }
    assert!(nothing_left(&left));
    std::fs::remove_dir_all(&quick).ok();
}
