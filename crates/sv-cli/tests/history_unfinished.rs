//! A run that did not finish leaves a record of its own when history is on (ADR-083, part 2), so
//! the dashboard does not show the last report as today's: one that failed, and, on Unix, one
//! stopped with Ctrl-C. Through the real `sv`, with a home of its own.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn copy(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            copy(&path, &to.join(entry.file_name()));
        } else {
            std::fs::copy(&path, to.join(entry.file_name())).unwrap();
        }
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// The runs history kept under `home`, oldest first, and its record of the app.
fn kept(home: &Path) -> (Vec<Value>, Value) {
    let files = walk(&home.join(".local/share/stackvet/history"));
    let read = |p: &PathBuf| -> Value {
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    };
    let mut runs: Vec<Value> = files
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "json") && !p.ends_with("app.json"))
        .map(read)
        .collect();
    runs.sort_by_key(|r| r["started_unix_ms"].as_u64());
    let app = files
        .iter()
        .find(|p| p.ends_with("app.json"))
        .map(read)
        .unwrap_or(Value::Null);
    (runs, app)
}

#[test]
fn a_run_that_failed_is_kept_as_failed_and_the_page_says_the_report_is_older() {
    let root = std::env::temp_dir().join(format!("sv-history-failed-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let app = root.join("app");
    copy(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/flask-booking"),
        &app,
    );
    std::fs::remove_dir_all(app.join(sv_scan::ecosystems::DEFAULT_REPORT_DIR)).ok();
    let sv = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_sv"))
            .args(args)
            .env("HOME", &home)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_DATA_HOME")
            .output()
            .unwrap()
    };
    assert!(sv(&["history", "on"]).status.success());
    let first = sv(&["report", app.to_str().unwrap()]);
    let first_code = first.status.code().unwrap();
    assert!(
        (0..=2).contains(&first_code),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    // A stackvet.toml that does not read: `sv` stops with an error and writes no report.
    let broken = "this is [[ not what sv reads";
    std::fs::write(app.join("stackvet.toml"), broken).unwrap();
    let second = sv(&["report", app.to_str().unwrap()]);
    assert_eq!(
        second.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );

    let (runs, app_record) = kept(&home);
    assert_eq!(runs.len(), 2, "{runs:?}");
    // The finished run keeps what it ended with; the failed one says it failed, and how it ended.
    assert_eq!(runs[0]["outcome"], "finished");
    assert_eq!(runs[0]["exit_code"], first_code);
    assert_eq!(runs[1]["outcome"], "failed", "{}", runs[1]);
    assert_eq!(runs[1]["exit_code"], 3);
    assert_eq!(runs[1]["format"], 4);
    // Nothing of what the app's files said, and the app's name kept from the run that read it.
    assert!(
        !runs[1].to_string().contains("not what sv reads"),
        "{}",
        runs[1]
    );
    assert_eq!(runs[1]["requirements"], Value::Array(Vec::new()));
    assert_eq!(app_record["app_name"], runs[0]["app_name"], "{app_record}");
    assert_ne!(app_record["app_name"], "");

    let page = root.join("page.html");
    let made = sv(&[
        "dashboard",
        app.to_str().unwrap(),
        "--out",
        page.to_str().unwrap(),
    ]);
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    let page = std::fs::read_to_string(&page).unwrap();
    std::fs::remove_dir_all(&root).ok();
    // Both views say so: each app's own, and the one of every app.
    assert_eq!(
        page.matches("did not finish.</strong> The report shown is from the last run that did")
            .count(),
        2,
        "{page}"
    );
    assert!(
        page.contains("Did not finish: sv stopped with an error"),
        "{page}"
    );
    assert!(page.contains("(it ended with 3)"), "{page}");
}

/// Ctrl-C during `sv report --tools`, as `tools_interrupt.rs` sends it, with history on.
#[cfg(unix)]
#[test]
fn a_run_stopped_with_ctrl_c_is_kept_as_stopped() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let dir = std::env::temp_dir().join(format!("sv-history-stopped-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let (bin, tmp, home) = (dir.join("bin"), dir.join("tmp"), dir.join("home"));
    for d in [&bin, &tmp, &home] {
        std::fs::create_dir_all(d).unwrap();
    }
    let started = dir.join("started");
    // Bandit answers its version, then holds the run until it is stopped.
    std::fs::write(
        bin.join("bandit"),
        format!(
            "#!/bin/sh\nPATH=/bin:/usr/bin\n[ \"$1\" = --version ] && {{ echo 'bandit 1.7.9'; exit 0; }}\n\
             : > '{}'\nsleep 300 &\nwait\n",
            started.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(bin.join("bandit"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let kill = ["/bin/kill", "/usr/bin/kill"]
        .into_iter()
        .find(|k| Path::new(k).exists())
        .expect("no kill on this computer");
    std::os::unix::fs::symlink(kill, bin.join("kill")).unwrap();

    let on = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["history", "on"])
        .env("HOME", &home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .output()
        .unwrap();
    assert!(on.status.success());
    let app = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/flask-booking");
    let mut sv = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(&app)
        .arg("--tools")
        .arg("--out")
        .arg(dir.join("report"))
        .env("PATH", &bin)
        .env("TMPDIR", &tmp)
        .env("HOME", &home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Setup: the tool is running, so the run is mid-way when it is stopped.
    let deadline = Instant::now() + Duration::from_secs(180);
    while !started.exists() {
        if let Some(status) = sv.try_wait().unwrap() {
            let out = sv.wait_with_output().unwrap();
            panic!(
                "sv ended ({status}) before the tool started: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        assert!(Instant::now() < deadline, "the tool never started");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        Command::new("kill")
            .args(["-INT", &sv.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    while sv.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            sv.kill().ok();
            panic!("sv did not end within a minute of Ctrl-C");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = sv.wait_with_output().unwrap();
    let (runs, _) = kept(&home);
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(
        out.status.code(),
        Some(130),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(runs.len(), 1, "{runs:?}");
    assert_eq!(runs[0]["outcome"], "stopped", "{}", runs[0]);
    assert_eq!(runs[0]["exit_code"], 130);
}
