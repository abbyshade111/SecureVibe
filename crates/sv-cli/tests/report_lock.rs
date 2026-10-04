//! Two runs at once in one report folder: the second is refused and told which run holds it, a run
//! killed outright does not leave the folder blocked, and a report from a run that started later is
//! not replaced by an older one (BACKLOG, "What the owner hit building family-hub", item 2).
//!
//! Real processes of the real binary. The first run is made to take a while by starting the app with
//! `--run` and a test command that sleeps, which needs a container backend; with none, the two-run
//! tests say so and check nothing. The older-report test needs no container.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const LOCK: &str = ".securevibe-report.lock";

/// In Cargo's scratch folder beside the build, which every Mac container backend shares (see
/// `killed_run.rs`).
fn app(name: &str, test: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("sv-lock-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("index.html"), "<p>hello</p>\n").unwrap();
    std::fs::write(
        dir.join("securevibe.toml"),
        format!(
            "manifest-version = 1\n[app]\nname = \"Lock\"\n[stack]\nlanguages = []\n\
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

fn sv(args: &[&str], app: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(app)
        .args(args)
        .output()
        .expect("sv starts")
}

fn start(args: &[&str], app: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(app)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sv starts")
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Waits until the lock in `folder` names process `pid`: the run holds the folder.
fn wait_for_lock(folder: &Path, pid: u32, run: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(folder.join(LOCK))
            && text.contains(&format!("\"process\": {pid}"))
        {
            return;
        }
        if let Some(status) = run.try_wait().unwrap() {
            panic!("the first run ended before it took the folder: {status}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("the first run never took the folder");
}

/// Waits until the run has started its app container, by which time it has read securevibe.toml.
fn wait_for_app(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        let out = Command::new("docker")
            .args([
                "ps",
                "--filter",
                &format!("name=sv-{pid}-"),
                "--format",
                "{{.Names}}",
            ])
            .output()
            .unwrap();
        if String::from_utf8_lossy(&out.stdout)
            .lines()
            .any(|n| n.trim().ends_with("-app"))
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    panic!("the run never started its app");
}

fn wait_for_exit(child: &mut Child, within: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("wait") {
            return status;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = child.kill();
    panic!("sv did not finish in {within:?}");
}

fn sha256_of(path: &Path) -> String {
    for (tool, args) in [("shasum", vec!["-a", "256"]), ("sha256sum", vec![])] {
        if let Ok(out) = Command::new(tool).args(&args).arg(path).output()
            && out.status.success()
        {
            return String::from_utf8_lossy(&out.stdout)
                .split_whitespace()
                .next()
                .unwrap()
                .to_owned();
        }
    }
    panic!("neither shasum nor sha256sum is here");
}

fn report_json(folder: &Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(folder.join("report.json")).unwrap()).unwrap()
}

/// Removes what a killed run left in the container backend, labeled with its process number.
fn remove_left_by(pid: u32) {
    let out = Command::new("docker")
        .args(["ps", "-aq", "--filter", &format!("name=sv-{pid}-")])
        .output()
        .unwrap();
    for id in String::from_utf8_lossy(&out.stdout).split_whitespace() {
        let _ = Command::new("docker").args(["rm", "-f", id]).output();
    }
    let out = Command::new("docker")
        .args([
            "network",
            "ls",
            "-q",
            "--filter",
            &format!("name=sv-{pid}-"),
        ])
        .output()
        .unwrap();
    for id in String::from_utf8_lossy(&out.stdout).split_whitespace() {
        let _ = Command::new("docker").args(["network", "rm", id]).output();
    }
}

#[test]
fn a_second_run_is_refused_while_the_first_holds_the_folder_and_the_first_finishes() {
    if !docker_ok() {
        println!("no container backend here, so no run lasts long enough to overlap; not checked");
        return;
    }
    let dir = app("two", "test = \"sleep 20\"");
    let folder = dir.join("securevibe-report");
    let toml_before = sha256_of(&dir.join("securevibe.toml"));

    let mut first = start(&["--run"], &dir);
    let pid = first.id();
    wait_for_lock(&folder, pid, &mut first);

    // The second, at the same time: refused at once, naming the first.
    let began = Instant::now();
    let second = sv(&[], &dir);
    let words = said(&second);
    assert!(
        !second.status.success(),
        "the second run was refused: {words}"
    );
    assert!(
        began.elapsed() < Duration::from_secs(20),
        "refused at once, not after its own run: {:?}",
        began.elapsed()
    );
    assert!(
        words.contains("Another sv run is writing its report"),
        "{words}"
    );
    assert!(words.contains(&format!("(process {pid})")), "{words}");
    assert!(words.contains("`sv report "), "{words}");
    assert!(words.contains(" --run`"), "{words}");
    assert!(words.contains("--out"), "{words}");
    assert!(
        !folder.join("report.json").exists(),
        "the refused run wrote nothing, and the first has not written yet"
    );
    assert!(
        first.try_wait().unwrap().is_none(),
        "the first was still running when the second was refused, so they overlapped"
    );

    // The owner's start-command change, while the first run goes on (family-hub's item 1). Made once
    // its app is up, so the run has read the file before the change: a change before it read the file
    // is a change it checks.
    wait_for_app(pid);
    let mut toml = std::fs::read_to_string(dir.join("securevibe.toml")).unwrap();
    toml.push_str("# changed while the run went on\n");
    std::fs::write(dir.join("securevibe.toml"), &toml).unwrap();

    let status = wait_for_exit(&mut first, Duration::from_secs(300));
    let mut out = String::new();
    std::io::Read::read_to_string(first.stderr.as_mut().unwrap(), &mut out).unwrap();
    assert!(status.success(), "the first run finished: {out}");
    assert!(
        out.contains("Note: securevibe.toml changed while this check ran"),
        "{out}"
    );
    assert!(!folder.join(LOCK).exists(), "the first let the folder go");

    let report = report_json(&folder);
    let record = &report["run_record"];
    assert_eq!(record["securevibe_toml_sha256"], toml_before, "{record}");
    assert!(record["started_unix_ms"].as_u64().unwrap() > 1_700_000_000_000);
    assert!(
        record["started"].as_str().unwrap().ends_with('Z'),
        "{record}"
    );
    assert!(
        report["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["what"] == "securevibe.toml as it is now"),
        "the report says the file changed under it: {}",
        report["gaps"]
    );

    // And with the folder free, the next run writes, and records the file as it is now.
    let third = sv(&[], &dir);
    assert!(third.status.success(), "{}", said(&third));
    assert_eq!(
        report_json(&folder)["run_record"]["securevibe_toml_sha256"],
        sha256_of(&dir.join("securevibe.toml"))
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_run_killed_outright_does_not_block_the_folder_and_the_next_says_so() {
    if !docker_ok() {
        println!("no container backend here, so no run lasts long enough to kill; not checked");
        return;
    }
    let dir = app("killed", "test = \"sleep 300\"");
    let folder = dir.join("securevibe-report");
    let mut first = start(&["--run"], &dir);
    let pid = first.id();
    wait_for_lock(&folder, pid, &mut first);
    // `kill -9`: nothing runs in the process, so it cannot remove its lock.
    let killed = Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    wait_for_exit(&mut first, Duration::from_secs(60));
    assert!(
        std::fs::read_to_string(folder.join(LOCK))
            .unwrap()
            .contains(&format!("\"process\": {pid}")),
        "the control: the killed run left its lock behind"
    );

    let next = sv(&[], &dir);
    let words = said(&next);
    assert!(next.status.success(), "not blocked: {words}");
    assert!(words.contains("stopped before it finished"), "{words}");
    assert!(words.contains(&format!("(process {pid})")), "{words}");
    assert!(folder.join("report.json").is_file());
    assert!(!folder.join(LOCK).exists(), "and let go again");
    remove_left_by(pid);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_report_from_a_run_that_started_later_is_not_replaced() {
    let dir = app("older", "");
    let folder = dir.join("securevibe-report");
    let first = sv(&[], &dir);
    assert!(first.status.success(), "{}", said(&first));
    let mut there = report_json(&folder);
    assert!(
        there["run_record"]["started_unix_ms"].as_u64().is_some(),
        "the setup: a report records when its run started: {}",
        there["run_record"]
    );

    // The control: a report from an earlier run is replaced, as always.
    let again = sv(&[], &dir);
    assert!(again.status.success(), "{}", said(&again));

    // A report from a run that started a day from now, and read a different file: one that finished
    // while the lock could not hold (a disk without locks, or an `sv` from before the lock).
    let later = there["run_record"]["started_unix_ms"].as_u64().unwrap() + 86_400_000;
    there["run_record"]["started_unix_ms"] = later.into();
    there["run_record"]["started"] = "2099-01-01T00:00:00Z".into();
    there["run_record"]["securevibe_toml_sha256"] = "0".repeat(64).into();
    let newer = serde_json::to_string_pretty(&there).unwrap();
    std::fs::write(folder.join("report.json"), &newer).unwrap();
    let html_before = std::fs::read(folder.join("report.html")).unwrap();

    let older = sv(&[], &dir);
    let words = said(&older);
    assert!(!older.status.success(), "{words}");
    assert!(words.contains("2099-01-01T00:00:00Z"), "{words}");
    assert!(words.contains("kept the newer one"), "{words}");
    assert!(
        words.contains("different versions of securevibe.toml"),
        "{words}"
    );
    assert_eq!(
        std::fs::read_to_string(folder.join("report.json")).unwrap(),
        newer,
        "the newer report.json is still there"
    );
    assert_eq!(
        std::fs::read(folder.join("report.html")).unwrap(),
        html_before,
        "and nothing beside it was replaced"
    );
    assert!(!folder.join(LOCK).exists(), "let go after refusing");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_run_that_writes_no_report_leaves_the_folder_as_it_found_it() {
    // A securevibe.toml that does not read: the run takes the folder, then fails.
    let dir = app("failed", "");
    let folder = dir.join("securevibe-report");
    std::fs::write(dir.join("securevibe.toml"), "manifest-version = [\n").unwrap();
    let failed = sv(&[], &dir);
    assert!(!failed.status.success(), "the setup: the run fails");
    assert!(
        said(&failed).contains("securevibe.toml"),
        "and fails reading the file: {}",
        said(&failed)
    );
    assert!(!folder.exists(), "the folder it made is gone");

    // A folder already there, with a report in it, keeps everything it had and loses the lock.
    let good = app("failed-kept", "");
    let kept = good.join("securevibe-report");
    assert!(sv(&[], &good).status.success());
    let before = std::fs::read(kept.join("report.json")).unwrap();
    std::fs::write(good.join("securevibe.toml"), "manifest-version = [\n").unwrap();
    assert!(!sv(&[], &good).status.success());
    assert_eq!(std::fs::read(kept.join("report.json")).unwrap(), before);
    assert!(kept.join(".securevibe-report").is_file(), "still marked");
    assert!(!kept.join(LOCK).exists(), "let go");
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&good).ok();
}
