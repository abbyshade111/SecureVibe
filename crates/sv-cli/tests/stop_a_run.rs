//! `sv run` stopped part way: by Ctrl-C, it removes what it started before it exits; killed
//! outright, it cannot, and the next run removes what it left and says so.
//!
//! Real containers and the real binary. With no container backend, `sv run` must say the app was
//! not assessed, and that is what is checked instead.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// One at a time: every run removes what an ended run left, so a run in one test could remove the
/// leftovers the other is about to look for.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn app(name: &str, test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-stop-{name}-{}", std::process::id()));
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

#[test]
fn ctrl_c_removes_what_the_run_started_before_sv_exits() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let dir = app("ctrl-c", "test = \"sleep 300\"");
    if !docker_ok() {
        println!("no container backend here; checking the honest-absence path instead");
        let out = Command::new(env!("CARGO_BIN_EXE_sv"))
            .arg("run")
            .arg(&dir)
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).contains("Not assessed"));
        return;
    }
    let mut run = start_run(&dir);
    let pid = run.id();
    wait_for_app(pid);
    assert!(!started_by(pid).is_empty(), "there is something to remove");

    signal(pid, "-INT");
    let status = wait_for_exit(&mut run);
    assert_eq!(
        status.code(),
        Some(130),
        "the usual status for a process stopped by Ctrl-C"
    );
    assert_eq!(
        started_by(pid),
        Vec::<String>::new(),
        "everything it started is gone"
    );
    let mut err = String::new();
    std::io::Read::read_to_string(&mut run.stderr.take().unwrap(), &mut err).unwrap();
    assert!(err.contains("was stopped"), "{err}");
    std::fs::remove_dir_all(&dir).ok();
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
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
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

#[test]
fn a_suite_stopped_at_its_time_limit_is_named_in_the_report_and_credits_nothing() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    // The suite names a requirement, so a suite read as passing would credit it.
    let dir = app(
        "limit",
        "test = \"echo V1.2.1 checked; sleep 120\"\ntest-time-limit = 3",
    );
    std::fs::create_dir_all(dir.join("tests")).unwrap();
    std::fs::write(
        dir.join("tests/test_app.sh"),
        "# V1.2.1 the page escapes what it shows\n",
    )
    .unwrap();
    let out_dir = dir.join("report");
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["report"])
        .arg(&dir)
        .args(["--run", "--out"])
        .arg(&out_dir)
        .output()
        .expect("sv runs");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let compliance = std::fs::read_to_string(out_dir.join("compliance.md")).unwrap();
    if !docker_ok() {
        println!("no container backend here; checking the honest-absence path instead");
        assert!(compliance.contains("not assessed") || compliance.contains("Not assessed"));
        return;
    }
    assert!(
        compliance.contains("the suite was still running after 3 seconds, so `sv` stopped it. A"),
        "{compliance}"
    );
    assert!(
        compliance.contains("set `test-time-limit` (in seconds)"),
        "the report says how to allow longer: {compliance}"
    );
    assert!(
        !compliance.contains("they failed (exit"),
        "a stopped suite is not called a failed one: {compliance}"
    );
    assert!(
        compliance.contains("were still running after 3 seconds, so `sv` stopped them"),
        "the output's heading says so too: {compliance}"
    );
    // What the suite's named tests were weighed as: a `tests.` check or finding appears only when
    // the suite's tests were counted at all.
    let weighed = |report: &Path| {
        std::fs::read_to_string(report.join("report.json"))
            .unwrap()
            .matches("\"tests.")
            .count()
    };
    assert_eq!(
        weighed(&out_dir),
        0,
        "a stopped suite credits nothing, and is held to nothing"
    );

    // The control: the same suite, finishing in time, is weighed, so the zero above is not a
    // report that never looks.
    std::fs::write(
        dir.join("securevibe.toml"),
        std::fs::read_to_string(dir.join("securevibe.toml"))
            .unwrap()
            .replace("; sleep 120", ""),
    )
    .unwrap();
    let control = dir.join("control");
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["report"])
        .arg(&dir)
        .args(["--run", "--out"])
        .arg(&control)
        .output()
        .expect("sv runs");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(weighed(&control) > 0, "the control's suite was weighed");
    std::fs::remove_dir_all(&dir).ok();
}
