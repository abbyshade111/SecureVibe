//! `sv init > stackvet.toml` writes a file `sv` can read (gap analysis 5.3).
//!
//! `sv init` prints the starter file and then the instructions for the AI coding tool, which are
//! prose. Redirected into `stackvet.toml`, that made a file every later command refused. Into a
//! file it now prints only the starter; through a pipe, as an AI coding tool reads it, everything.

use std::process::{Command, Stdio};

const SV: &str = env!("CARGO_BIN_EXE_sv");

#[test]
fn redirected_into_a_file_it_writes_only_what_sv_can_read() {
    let dir = std::env::temp_dir().join(format!("sv-init-redirect-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    let file = std::fs::File::create(dir.join("stackvet.toml")).unwrap();
    let into_file = Command::new(SV)
        .arg("init")
        .stdout(Stdio::from(file))
        .output()
        .unwrap();
    let written = std::fs::read_to_string(dir.join("stackvet.toml")).unwrap();
    let scope = Command::new(SV).arg("scope").arg(&dir).output().unwrap();
    let piped = Command::new(SV).arg("init").output().unwrap();
    std::fs::remove_dir_all(&dir).ok();

    let said = String::from_utf8_lossy(&into_file.stderr);
    assert_eq!(into_file.status.code(), Some(0), "{said}");
    assert!(
        written.contains("manifest-version = 1"),
        "the setup: the starter was written: {written}"
    );
    assert!(!written.contains("\n### "), "prose in the file: {written}");
    assert!(
        said.contains("The instructions for your AI coding tool were left out"),
        "{said}"
    );
    assert_eq!(
        scope.status.code(),
        Some(0),
        "sv cannot read what sv init wrote: {}",
        String::from_utf8_lossy(&scope.stderr)
    );

    // Through a pipe, which is how an AI coding tool reads it, the instructions are all there.
    let all = String::from_utf8_lossy(&piped.stdout);
    assert!(all.starts_with(&written), "the starter comes first");
    assert!(all.len() > written.len(), "{} bytes", all.len());
    assert!(all.contains("\n### "), "no instructions through a pipe");
}
