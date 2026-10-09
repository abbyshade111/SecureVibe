//! `sv review` says once, before anything else, when the key folder in use is the old one,
//! `~/.config/securevibe` (ADR-062), and names the move; it says nothing of it otherwise.

use std::path::{Path, PathBuf};
use std::process::Command;
use sv_frameworks::names::{CONFIG_DIR, OLD_CONFIG_DIR};

/// Runs `sv` with stdin, stdout and stderr on a pseudo-terminal, typing `typed`.
const PTY: &str = r#"
import os, pty, select, subprocess, sys
typed = sys.argv[1]
main, child = pty.openpty()
p = subprocess.Popen(sys.argv[2:], stdin=child, stdout=child, stderr=child, close_fds=True)
os.close(child)
os.write(main, typed.encode())
out = b""
while True:
    ready, _, _ = select.select([main], [], [], 20)
    if not ready:
        break
    try:
        data = os.read(main, 4096)
    except OSError:
        break
    if not data:
        break
    out += data
p.wait()
sys.stdout.buffer.write(out)
sys.exit(p.returncode)
"#;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-review-old-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(dir.join("app")).unwrap();
    std::fs::write(
        dir.join("app/stackvet.toml"),
        "manifest-version = 1\n[app]\nname = \"Reviewed\"\n[stack]\nlanguages = [\"python\"]\n",
    )
    .unwrap();
    std::fs::write(dir.join("app/app.py"), "print(1)\n").unwrap();
    dir
}

fn review(dir: &Path) -> String {
    let run = Command::new("python3")
        .arg("-c")
        .arg(PTY)
        .arg("\n")
        .arg(env!("CARGO_BIN_EXE_sv"))
        .arg("review")
        .arg(dir.join("app"))
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env_remove(sv_check::signed::TRUSTED_VARIABLE)
        .output()
        .expect("python3 runs");
    String::from_utf8_lossy(&run.stdout).into_owned()
}

#[test]
fn the_old_key_folder_in_use_is_said_once_with_the_move() {
    let dir = scratch("old");
    let old = dir.join("config").join(OLD_CONFIG_DIR);
    let new = dir.join("config").join(CONFIG_DIR);
    std::fs::create_dir_all(&old).unwrap();
    let said = review(&dir);
    assert_eq!(
        said.matches("read under its old name").count(),
        1,
        "said once: {said}"
    );
    assert!(
        said.contains(&format!("mv {} {}", old.display(), new.display())),
        "the move is named: {said}"
    );
    assert!(
        !new.exists(),
        "nothing was moved or made under the new name"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_computer_with_no_old_folder_hears_nothing_of_it() {
    let dir = scratch("new");
    let said = review(&dir);
    assert!(!said.contains("read under its old name"), "{said}");
    std::fs::remove_dir_all(&dir).ok();
}
