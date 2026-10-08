//! Ctrl-C while an outside tool runs stops the tool and everything it started (the review of
//! 8 October 2026, item 1). The whole path, from the key press to `sv` ending with nothing written,
//! is `crates/sv-cli/tests/tools_interrupt.rs`; this is the runner's own part of it.

use super::*;
use std::process::Stdio;
use std::time::{Duration, Instant};

/// Whether process `pid` is gone: not there, or ended and waiting only to be collected.
fn gone(pid: &str) -> bool {
    let out = Command::new("ps")
        .args(["-o", "stat=", "-p", pid])
        .output()
        .expect("ps");
    let stat = String::from_utf8_lossy(&out.stdout);
    stat.trim().is_empty() || stat.trim_start().starts_with('Z')
}

#[test]
fn being_asked_to_stop_ends_a_tool_and_what_it_started() {
    let dir = std::env::temp_dir().join(format!("sv-tools-interrupt-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    let pid_file = dir.join("started");
    // A tool whose work is done by a second program it starts, as Semgrep's is, and which would
    // hold the run for five minutes.
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(format!(
            "sleep 300 & echo $! > '{}.part' && mv '{0}.part' '{0}'; wait",
            pid_file.display()
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    std::os::unix::process::CommandExt::process_group(&mut command, 0);

    // Asked to stop once the second program is certainly running, as a person presses Ctrl-C
    // part of the way through.
    let asked = || pid_file.exists();
    let started = Instant::now();
    let ran = finish_unless(&mut command, 600, &asked).unwrap();
    let pid = std::fs::read_to_string(&pid_file).unwrap();
    std::fs::remove_dir_all(&dir).ok();

    assert!(ran.interrupted, "not stopped for being asked to");
    assert!(!ran.timed_out);
    assert_eq!(ran.code, None, "a stopped tool has no exit code of its own");
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "it waited for the tool: {:?}",
        started.elapsed()
    );
    // The program the tool started is stopped with it, not left running with no limit.
    let pid = pid.trim();
    assert!(pid.parse::<u32>().is_ok(), "no process id: {pid:?}");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !gone(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        gone(pid),
        "process {pid}, which the tool started, is still running"
    );
}

#[test]
fn a_tool_nobody_asks_to_stop_runs_to_its_end() {
    let mut command = Command::new("sh");
    command
        .args(["-c", "sleep 1; exit 3"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let ran = finish_unless(&mut command, 600, &|| false).unwrap();
    assert!(!ran.interrupted && !ran.timed_out);
    assert_eq!(ran.code, Some(3));
}

#[test]
fn nothing_is_started_once_somebody_has_asked_to_stop() {
    // A program that is not there: starting it fails, so whether it was tried shows in the
    // answer, where a program that did start would be stopped before it could leave a mark.
    let missing = std::env::temp_dir().join(format!("sv-no-such-tool-{}", std::process::id()));
    let mut command = Command::new(&missing);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // Setup: not asked to stop, it is tried, and fails to start.
    assert!(finish_unless(&mut command, 600, &|| false).is_err());

    let ran =
        finish_unless(&mut command, 600, &|| true).expect("a program was started after Ctrl-C");
    assert!(ran.interrupted && ran.code.is_none());
}
