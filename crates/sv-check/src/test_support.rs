//! What the tests of this crate share.

use std::path::Path;
#[cfg(unix)]
use std::process::{Command, Stdio};

/// Writes `text` to `path` as a program, and makes it one that can be run, from a child process
/// rather than this one.
///
/// Written here, the file is open for writing for a moment, and any other test that starts a
/// program in that moment hands the open file to its child until the child's own program begins.
/// Running the script then fails with "text file busy", which `presence` reads as a tool that is
/// not installed. CI met it on 9 October 2026 (`a_tool_that_does_not_say_its_version_is_broken_
/// not_waited_for` read "Missing"); eight threads writing and running a script 150 times each met
/// it 45 times in 1,200 written here, and never written by a child.
#[cfg(unix)]
pub fn executable(path: &Path, text: &str) {
    use std::io::Write;
    let mut child = Command::new("sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .expect("sh writes the script");
    child
        .stdin
        .take()
        .expect("its input")
        .write_all(text.as_bytes())
        .expect("the script is handed over");
    assert!(
        child.wait().expect("sh finishes").success(),
        "the script was not written: {}",
        path.display()
    );
}

/// Elsewhere a file runs by what it is named and what runs it, not by a permission, and the race is
/// a Unix one (a child keeps what its parent had open until its own program begins), so the file is
/// written here, as the tests did before this helper.
#[cfg(not(unix))]
pub fn executable(path: &Path, text: &str) {
    std::fs::write(path, text).expect("the script is written");
}

#[cfg(test)]
mod tests;
