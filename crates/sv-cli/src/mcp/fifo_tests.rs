//! A pipe named `securevibe.toml` (the review of 8 October 2026, item 6): reading it waits for a
//! writer that never comes, and with it the server's one thread for answering. It is refused, with
//! the reason, before it is read.
#![cfg(unix)]
use super::tests::{call, scratch_app, text};
use super::*;

#[test]
fn a_pipe_under_a_name_the_server_reads_is_refused_rather_than_waited_on() {
    let root = scratch_app("fifo-manifest", "flask-booking");
    let manifest = root.join("app/securevibe.toml");
    std::fs::remove_file(&manifest).ok();
    let made = std::process::Command::new("mkfifo")
        .arg(&manifest)
        .status()
        .expect("mkfifo runs");
    // The setup: a pipe is really there, under the name the server reads.
    assert!(made.success());
    let kind = std::fs::symlink_metadata(&manifest).unwrap().file_type();
    assert!(
        std::os::unix::fs::FileTypeExt::is_fifo(&kind),
        "the setup: not a pipe"
    );
    let server = Server::new(&root).unwrap();
    let (sent, answered) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = call(&server, "securevibe_check", json!({ "path": "app" }));
        let _ = sent.send(result);
    });
    let result = answered.recv_timeout(std::time::Duration::from_secs(30));
    std::fs::remove_dir_all(&root).ok();
    let result = result.expect("the server was still reading the pipe after 30 seconds");
    assert_eq!(result["isError"], true, "{}", text(&result));
    assert!(
        text(&result).contains("securevibe.toml in app is not an ordinary file"),
        "{}",
        text(&result)
    );
}
