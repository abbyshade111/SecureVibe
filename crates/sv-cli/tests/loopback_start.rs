//! An app told to listen on 127.0.0.1 cannot be reached by `sv`, which asks it from a second
//! container (family-hub, 3 October 2026). `sv run` warns before it waits, and when the wait ends,
//! names the address as the likely cause. A control app listening on 0.0.0.0 answers, unwarned.
//!
//! Real containers and the real binary. With no container backend, `sv run` must say the app was
//! not assessed, and that is what is checked instead.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;

/// Printed by the loopback app once it has answered itself on 127.0.0.1, so the test knows the app
/// really was up and listening there, and that `sv` not reaching it is the address, not a dead app.
const ANSWERED_ITSELF: &str = "loopback-app-answered-itself";

/// In Cargo's scratch folder beside the build, which every Mac backend shares (see `killed_run.rs`).
fn app(name: &str, start: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("sv-loopback-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("index.html"), "<p>hello</p>\n").unwrap();
    std::fs::write(
        dir.join("securevibe.toml"),
        format!(
            "manifest-version = 1\n[app]\nname = \"Loopback\"\n[stack]\nlanguages = []\n\
             [stack.run]\nimage = \"busybox:1.36\"\nstart = \"{start}\"\n\
             health = \"/index.html\"\n"
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

/// `sv run` on the app, to the end: what it printed to standard output and to standard error, and
/// its exit status.
fn sv_run(app: &PathBuf) -> (String, String, Option<i32>) {
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("run")
        .arg(app)
        .output()
        .expect("sv runs");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}

#[test]
fn an_app_listening_on_loopback_is_warned_about_and_named_as_the_likely_cause() {
    let loopback = app(
        "named",
        &format!(
            "httpd -f -h /app -p 127.0.0.1:$PORT & sleep 1; \
             wget -q -O /dev/null http://127.0.0.1:$PORT/index.html && echo {ANSWERED_ITSELF}; wait"
        ),
    );
    let (stdout, stderr, code) = sv_run(&loopback);
    // Not assessed exits 2 (ADR-029, as the owner decided for `sv run` on 6 October 2026), with a
    // backend or without one.
    assert_eq!(code, Some(2), "{stdout}\n{stderr}");
    if !docker_ok() {
        println!("no container backend here; checking the honest-absence path instead");
        assert!(stdout.contains("Not assessed"), "{stdout}\n{stderr}");
        return;
    }
    println!("container backend present; running the loopback app for real");
    // Before the wait: the warning, which does not stop the run.
    assert!(
        stderr.contains("Warning: the start command in securevibe.toml names 127.0.0.1"),
        "{stderr}"
    );
    assert!(stderr.contains("Starting it anyway"), "{stderr}");
    // The setup worked: the app was up and answered itself on 127.0.0.1, inside its container.
    assert!(
        stdout.contains(ANSWERED_ITSELF),
        "the app never showed it was listening, so its silence proves nothing: {stdout}\n{stderr}"
    );
    // After the wait: not assessed, and the address named as the likely cause.
    assert!(
        stdout.contains("never answered on its health path"),
        "{stdout}"
    );
    assert!(
        stdout.contains("Its start command names 127.0.0.1, which is the likely cause"),
        "{stdout}"
    );
    assert!(stdout.contains("listen on 0.0.0.0"), "{stdout}");
    std::fs::remove_dir_all(&loopback).ok();
}

#[test]
fn the_same_app_listening_on_every_address_answers_and_is_not_warned_about() {
    // No self-check here: its own `127.0.0.1` would be warned about, rightly, since the warning
    // reads only the command line.
    let open = app("open", "httpd -f -h /app -p 0.0.0.0:$PORT");
    let (stdout, stderr, code) = sv_run(&open);
    if !docker_ok() {
        println!("no container backend here; checking the honest-absence path instead");
        assert!(stdout.contains("Not assessed"), "{stdout}\n{stderr}");
        assert_eq!(code, Some(2), "{stdout}\n{stderr}");
        return;
    }
    println!("container backend present; running the control app for real");
    assert!(
        stdout.contains("The app started and answered on /index.html"),
        "the control must answer, or the loopback test's silence proves nothing: {stdout}\n{stderr}"
    );
    assert!(!stderr.contains("Warning: the start command"), "{stderr}");
    // The control for the exit code: an app that ran exits 0, findings or not.
    assert_eq!(code, Some(0), "{stdout}\n{stderr}");
    std::fs::remove_dir_all(&open).ok();
}
