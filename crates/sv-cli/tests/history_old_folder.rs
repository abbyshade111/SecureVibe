//! History kept before the rename, in `~/.local/share/securevibe/history`, is still the folder
//! `sv history` uses while only it exists (ADR-062); a computer with neither gets the new name.

use std::path::{Path, PathBuf};
use sv_frameworks::names::{CONFIG_DIR, OLD_CONFIG_DIR};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-history-old-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(dir.join("home")).unwrap();
    dir
}

fn status(home: &Path) -> String {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["history", "status"])
        .env("HOME", home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn the_old_history_folder_is_used_while_only_it_exists() {
    let root = scratch("old");
    let home = root.join("home");
    let old = home
        .join(".local/share")
        .join(OLD_CONFIG_DIR)
        .join("history");
    let new = home.join(".local/share").join(CONFIG_DIR).join("history");
    // Neither: the new name.
    let said = status(&home);
    assert!(said.contains(&format!(", in {}", new.display())), "{said}");
    // Only the old, with a run kept in it: that folder, and its runs.
    std::fs::create_dir_all(old.join("0123456789abcdef")).unwrap();
    std::fs::write(
        old.join("0123456789abcdef/app.json"),
        r#"{"folder": "/somewhere/app", "app_name": "App"}"#,
    )
    .unwrap();
    let said = status(&home);
    assert!(said.contains(&format!(", in {}", old.display())), "{said}");
    assert!(
        said.contains("/somewhere/app"),
        "the kept app is listed: {said}"
    );
    // Both: the new one.
    std::fs::create_dir_all(&new).unwrap();
    let said = status(&home);
    assert!(said.contains(&format!(", in {}", new.display())), "{said}");
    std::fs::remove_dir_all(&root).ok();
}
