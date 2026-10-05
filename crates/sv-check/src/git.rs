//! Git, run in the folder of the app being checked (ADR-032).
//!
//! Git reads the repository's own `.git/config`, and the app's author wrote that file. Some of its
//! settings are programs git runs: `core.fsmonitor` is one, and plain `git ls-files` runs it.
//! Reproduced on 5 October 2026, so an app handed to the owner to check could run anything on the
//! owner's computer, outside the fence, during `sv check`. A setting given on git's command line
//! wins over the repository's, so the setting that names a program for these commands is given
//! there, set to nothing.

use std::path::Path;
use std::process::Command;

/// The setting given on git's command line, over the repository's own: no file-system monitor,
/// which is a program git runs to learn which files changed. Hooks were tried as well
/// (`post-index-change` and `reference-transaction` under a planted `core.hooksPath`), and
/// `ls-files` runs none, so nothing is given for them; a command added here should be tried the
/// same way.
const OVERRIDES: [&str; 2] = ["-c", "core.fsmonitor=false"];

/// `git` with the overrides, run in `app_dir`.
fn git(app_dir: &Path) -> Command {
    let mut command = Command::new("git");
    command.args(OVERRIDES).arg("-C").arg(app_dir);
    command
}

/// The files git tracks under `app_dir`, named from it: `None` when git could not say.
pub fn ls_files(app_dir: &Path) -> Option<Vec<String>> {
    let out = git(app_dir).arg("ls-files").output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_owned)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A repository with one file committed, and a program its own config names as the file-system
    /// monitor, which leaves a mark when it runs.
    fn planted(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("sv-git-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        let mark = dir.join("ran");
        let run = |args: &[&str]| {
            let ok = Command::new("git")
                .arg("-C")
                .arg(&dir)
                .args(args)
                .output()
                .is_ok_and(|o| o.status.success());
            assert!(ok, "git {args:?} failed in the test's setup");
        };
        run(&["init", "-q"]);
        std::fs::write(dir.join("app.py"), "print(1)\n").unwrap();
        run(&["add", "app.py"]);
        run(&[
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-qm",
            "one",
        ]);
        // Set after the commit, so the setup itself never runs it.
        let program = format!("touch '{}'; false", mark.display());
        run(&["config", "core.fsmonitor", &program]);
        (dir, mark)
    }

    #[test]
    fn a_program_the_app_s_repository_names_is_not_run() {
        if Command::new("git").arg("--version").output().is_err() {
            println!("no git here; this needs it");
            return;
        }
        // The control: plain git runs the planted program, so the setup is the attack.
        let (dir, mark) = planted("control");
        let plain = Command::new("git")
            .arg("-C")
            .arg(&dir)
            .arg("ls-files")
            .output()
            .unwrap();
        assert!(plain.status.success());
        assert!(
            mark.exists(),
            "plain git did not run the planted program, so this proves nothing"
        );
        std::fs::remove_dir_all(&dir).ok();

        let (dir, mark) = planted("guarded");
        assert_eq!(ls_files(&dir), Some(vec!["app.py".to_owned()]));
        assert!(
            !mark.exists(),
            "git ran the program the app's repository named"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
