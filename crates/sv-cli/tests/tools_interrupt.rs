//! Ctrl-C during `sv report --tools` stops the tool that is running and everything it started,
//! starts no other, removes the tools' private folder, lets go of the report folder, and writes
//! nothing. Before this, nothing caught Ctrl-C on that path: it ended `sv` alone, and the tool, in
//! a process group of its own so the limit can stop all of it, ran on with no limit at all (the
//! review of 8 October 2026, item 1).
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Writes an executable shell script.
fn script(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, format!("#!/bin/sh\nPATH=/bin:/usr/bin\n{body}")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Whether process `pid` is gone: not there, or ended and waiting only to be collected.
fn gone(pid: &str) -> bool {
    let out = Command::new("ps")
        .args(["-o", "stat=", "-p", pid])
        .output()
        .expect("ps");
    let stat = String::from_utf8_lossy(&out.stdout);
    stat.trim().is_empty() || stat.trim_start().starts_with('Z')
}

/// The tools' private folders in `tmp`.
fn private_folders(tmp: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(tmp)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with("sv-tools-"))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn ctrl_c_while_a_tool_runs_stops_it_and_writes_nothing() {
    let dir = std::env::temp_dir().join(format!("sv-tools-interrupt-cli-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let (bin, tmp) = (dir.join("bin"), dir.join("tmp"));
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&tmp).unwrap();
    let sleeping = dir.join("sleeping");
    let semgrep_ran = dir.join("semgrep-ran");
    // Bandit, which comes first for a Python app: it answers its version, then starts a program
    // that would hold the run for five minutes, as Semgrep's real work is done by a second
    // program, and waits for it.
    script(
        &bin.join("bandit"),
        &format!(
            "[ \"$1\" = --version ] && {{ echo 'bandit 1.7.9'; exit 0; }}\n\
             sleep 300 &\necho $! > '{0}.part' && mv '{0}.part' '{0}'\nwait\n",
            sleeping.display()
        ),
    );
    // `sv` stops a tool's process group with the computer's `kill`, found on the PATH it is given,
    // which here holds only these tools.
    let kill = ["/bin/kill", "/usr/bin/kill"]
        .into_iter()
        .find(|k| Path::new(k).exists())
        .expect("no kill on this computer");
    std::os::unix::fs::symlink(kill, bin.join("kill")).unwrap();
    // Semgrep, which comes after it, says whether it was ever asked to read the app.
    script(
        &bin.join("semgrep"),
        &format!(
            "[ \"$1\" = --version ] && {{ echo 1.80.0; exit 0; }}\n: > '{}'\nexit 2\n",
            semgrep_ran.display()
        ),
    );

    let app = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/flask-booking");
    let report = dir.join("report");
    let mut sv = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(&app)
        .arg("--tools")
        .arg("--out")
        .arg(&report)
        .env("PATH", &bin)
        .env("TMPDIR", &tmp)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Setup: Bandit is running, with the program it started, inside the run's private folder.
    let deadline = Instant::now() + Duration::from_secs(180);
    while !sleeping.exists() {
        if let Some(status) = sv.try_wait().unwrap() {
            let out = sv.wait_with_output().unwrap();
            panic!(
                "sv ended ({status}) before the tool started: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        assert!(Instant::now() < deadline, "the tool never started");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        private_folders(&tmp).len(),
        1,
        "no private folder to see removed"
    );
    let pid = std::fs::read_to_string(&sleeping).unwrap();
    let pid = pid.trim().to_owned();
    assert!(
        !gone(&pid),
        "the tool's program is not running to be stopped"
    );

    // Ctrl-C, as the terminal sends it: to `sv`, since the tool leads a process group of its own.
    let sent = Command::new("kill")
        .args(["-INT", &sv.id().to_string()])
        .status()
        .unwrap();
    assert!(sent.success());
    let deadline = Instant::now() + Duration::from_secs(60);
    while sv.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            sv.kill().ok();
            panic!("sv did not end within a minute of Ctrl-C");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = sv.wait_with_output().unwrap();
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stopped_in_time = (0..200).any(|_| {
        let done = gone(&pid);
        if !done {
            std::thread::sleep(Duration::from_millis(50));
        }
        done
    });
    let left_in_tmp = private_folders(&tmp);
    let report_files: Vec<PathBuf> = std::fs::read_dir(&report)
        .map(|entries| entries.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    let semgrep_asked = semgrep_ran.exists();
    if stopped_in_time {
        std::fs::remove_dir_all(&dir).ok();
    } else {
        Command::new("kill").args(["-KILL", &pid]).status().ok();
    }

    assert_eq!(out.status.code(), Some(130), "{said}");
    assert!(said.contains("Stopped with Ctrl-C"), "{said}");
    assert!(
        stopped_in_time,
        "process {pid}, which the tool started, still runs"
    );
    assert!(!semgrep_asked, "a tool was started after Ctrl-C");
    assert!(left_in_tmp.is_empty(), "left behind: {left_in_tmp:?}");
    assert!(
        report_files.is_empty(),
        "written or left in the report folder: {report_files:?}"
    );
}
