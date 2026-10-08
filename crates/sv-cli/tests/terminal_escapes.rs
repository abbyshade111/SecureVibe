//! What `sv` prints never carries a control character from the app to the terminal (the deep review's
//! improvement 5). A file name is the app's to choose, and on Linux and macOS it can hold an escape
//! character: printed as it is, it can rewrite what is on screen or retitle the window.

#[cfg(unix)]
#[test]
fn a_file_name_with_an_escape_in_it_is_printed_with_the_escape_written_out() {
    use std::process::Command;
    let dir = std::env::temp_dir().join(format!("sv-terminal-escape-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    // A link `sv` does not follow, so its name is listed: an escape that would set the window's title.
    let name = "notes\u{1b}]0;all clear\u{7}.py";
    std::os::unix::fs::symlink("app.py", dir.join(name)).unwrap();
    assert!(
        std::fs::symlink_metadata(dir.join(name)).is_ok(),
        "the link with the escape in its name was made"
    );

    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["check"])
        .arg(&dir)
        .output()
        .expect("sv runs");
    std::fs::remove_dir_all(&dir).ok();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The name is there, so the line that would have carried the escape was printed.
    assert!(
        stdout.contains("notes\\u{001b}]0;all clear\\u{0007}.py"),
        "{stdout}{stderr}"
    );
    for (what, text) in [("stdout", &stdout), ("stderr", &stderr)] {
        assert!(
            !text
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t'),
            "{what} carries a control character: {text:?}"
        );
    }
}

/// `sv review` runs only in a terminal, so this gives it one with `script`, on Linux, where its flags are
/// known. What it shows is in the app's own words: here a reason the AI coding tool wrote into
/// stackvet.toml, with an escape that would retitle the window.
#[cfg(target_os = "linux")]
#[test]
fn the_review_shows_an_escape_in_a_proposal_rather_than_sending_it() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    if Command::new("script").arg("--version").output().is_err() {
        println!("no `script` here to give sv review a terminal; this needs it");
        return;
    }
    let root = std::env::temp_dir().join(format!("sv-terminal-review-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let (app, home) = (root.join("app"), root.join("home"));
    std::fs::create_dir_all(&app).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(app.join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(
        app.join("stackvet.toml"),
        "manifest-version = 1\n[app]\nname = \"Reviewed\"\n[stack]\nlanguages = [\"python\"]\n\n\
         [[finding-review]]\nrule = \"ast.open-redirect\"\nfile = \"app.py\"\nfingerprint = \"abc\"\n\
         verdict = \"false-alarm\"\nwhy = \"Safe: \\u001b]0;all clear\\u0007 the redirect is fixed\"\n",
    )
    .unwrap();
    let command = format!("'{}' review '{}'", env!("CARGO_BIN_EXE_sv"), app.display());
    let mut child = Command::new("script")
        .args(["-qec", &command, "/dev/null"])
        .env("HOME", &home)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("script runs");
    // Enter: leave the proposal as it is.
    child.stdin.take().unwrap().write_all(b"\n").unwrap();
    let out = child.wait_with_output().unwrap();
    std::fs::remove_dir_all(&root).ok();
    let shown = String::from_utf8_lossy(&out.stdout);
    // The proposal was shown, so the line that would have carried the escape was written.
    assert!(
        shown.contains("Safe: \\u{001b}]0;all clear\\u{0007} the redirect is fixed"),
        "{shown:?}"
    );
    assert!(
        !shown.contains('\u{1b}') && !shown.contains('\u{7}'),
        "{shown:?}"
    );
}
