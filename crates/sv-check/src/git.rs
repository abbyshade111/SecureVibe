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

/// The same override, as the environment of a program `sv` starts that may run `git` itself: the
/// outside tools (`adapters::prepared`). Git reads settings given this way after the repository's own,
/// so they win, as `-c` does, from git 2.31; an older git ignores them. Semgrep and Opengrep run
/// `git ls-files` in a folder they are given and CodeQL may run git too, so without this they would
/// keep to ADR-032 only by being handed files rather than folders (6 October 2026).
pub(crate) const ENV_OVERRIDES: [(&str, &str); 3] = [
    ("GIT_CONFIG_COUNT", "1"),
    ("GIT_CONFIG_KEY_0", "core.fsmonitor"),
    ("GIT_CONFIG_VALUE_0", "false"),
];

/// `git` with the overrides, run in `app_dir`.
fn git(app_dir: &Path) -> Command {
    let mut command = Command::new("git");
    command.args(OVERRIDES).arg("-C").arg(app_dir);
    command
}

/// The files git tracks under `app_dir`, named from it: `None` when git could not say.
///
/// Each name ends in a zero byte (`-z`), and is given as it is. Without `-z`, git puts a name holding
/// an accented letter, a quote, or a backslash in quotes with escapes (`"donn\303\251es/.env"`), so
/// the name read was not the file's, and a committed secrets file in such a folder was not seen (the
/// review of 6 October, item 11).
pub fn ls_files(app_dir: &Path) -> Option<Vec<String>> {
    let out = git(app_dir).args(["ls-files", "-z"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        out.stdout
            .split(|b| *b == 0)
            .filter(|name| !name.is_empty())
            .map(|name| String::from_utf8_lossy(name).into_owned())
            .collect(),
    )
}

/// Settings given on `git log`'s command line, over the repository's own, besides `OVERRIDES`. With
/// `log.showSignature` on, `git log` checks each signed commit's signature by running `gpg.program`,
/// which the repository can name; `diff.external` and a `textconv` driver are programs too, though
/// `--name-only` shows no diff. Each is switched off here, and `log_runs_nothing_the_repository_names`
/// plants all three and the file-system monitor and watches for their mark.
const LOG_OVERRIDES: [&str; 4] = ["-c", "log.showSignature=false", "-c", "gpg.program=false"];

/// Every file ever added to the repository in any commit on any branch, under `app_dir` and named
/// from it, as `ls_files` names them: `None` when git could not say. A file committed once and
/// untracked since is in this list, and in no `ls_files` list after.
pub fn ever_added(app_dir: &Path) -> Option<Vec<String>> {
    let out = git(app_dir)
        .args(LOG_OVERRIDES)
        .args([
            "log",
            "--all",
            "--no-show-signature",
            "--no-ext-diff",
            "--no-textconv",
            "--diff-filter=A",
            "--name-only",
            "--format=",
            "--relative",
            "-z",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let mut names: Vec<String> = out
        .stdout
        .split(|b| *b == 0 || *b == b'\n')
        .filter(|name| !name.is_empty())
        .map(|name| String::from_utf8_lossy(name).into_owned())
        .collect();
    names.sort();
    names.dedup();
    Some(names)
}

/// Whether the repository holds only its most recent commits (a shallow copy), so the history
/// `ever_added` reads is not all of it: `None` when git could not say.
pub fn is_shallow(app_dir: &Path) -> Option<bool> {
    let out = git(app_dir)
        .args(["rev-parse", "--is-shallow-repository"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    match String::from_utf8_lossy(&out.stdout).trim() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
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

    /// A repository whose history holds a `.env` committed and then untracked, a commit with a
    /// signature on it, and a config naming a program three ways `git log` can run one: as the
    /// signature checker, with signatures shown by default, and as the external diff.
    fn planted_for_log(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let (dir, mark) = planted(name);
        let git_ok = |args: &[&str]| -> String {
            let out = Command::new("git")
                .args(["-c", "user.email=t@t", "-c", "user.name=t"])
                .arg("-C")
                .arg(&dir)
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?} failed in the test's setup"
            );
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        };
        // The fsmonitor `planted` set would run during these setup commands; take it off first.
        git_ok(&["config", "--unset", "core.fsmonitor"]);
        std::fs::write(dir.join(".env"), "PORT=1\n").unwrap();
        git_ok(&["add", ".env"]);
        git_ok(&["commit", "-qm", "two"]);
        git_ok(&["rm", "-q", "--cached", ".env"]);
        git_ok(&["commit", "-qm", "three"]);
        // A commit carrying a signature and adding a file, so a `git log` that lists added files
        // shows it, and one that shows signatures runs the checker. A signed commit adding nothing
        // is not shown by `--diff-filter=A`, and proved nothing: the first version of this test.
        std::fs::write(dir.join("signed.txt"), "x\n").unwrap();
        git_ok(&["add", "signed.txt"]);
        let tree = git_ok(&["write-tree"]);
        git_ok(&["rm", "-q", "--cached", "signed.txt"]);
        std::fs::remove_file(dir.join("signed.txt")).ok();
        let parent = git_ok(&["rev-parse", "HEAD"]);
        let body = format!(
            "tree {tree}\nparent {parent}\nauthor t <t@t> 1700000000 +0000\n\
             committer t <t@t> 1700000000 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n \
             iQEzBAABCAAdFiEE\n -----END PGP SIGNATURE-----\n\nsigned\n"
        );
        let object =
            std::env::temp_dir().join(format!("sv-git-commit-{name}-{}", std::process::id()));
        std::fs::write(&object, body).unwrap();
        let signed = git_ok(&[
            "hash-object",
            "-t",
            "commit",
            "-w",
            object.to_str().unwrap(),
        ]);
        std::fs::remove_file(&object).ok();
        git_ok(&["update-ref", "refs/heads/signed", &signed]);
        // The program, as a script, since `gpg.program` is run without a shell.
        let script = dir.join("leave-a-mark.sh");
        crate::test_support::executable(
            &script,
            &format!("#!/bin/sh\ntouch '{}'\nexit 1\n", mark.display()),
        );
        let program = script.display().to_string();
        git_ok(&["config", "log.showSignature", "true"]);
        git_ok(&["config", "gpg.program", &program]);
        git_ok(&["config", "diff.external", &program]);
        git_ok(&["config", "core.fsmonitor", &program]);
        std::fs::remove_file(&mark).ok();
        (dir, mark)
    }

    #[test]
    fn log_runs_nothing_the_repository_names_and_finds_a_file_untracked_since() {
        if Command::new("git").arg("--version").output().is_err() {
            println!("no git here; this needs it");
            return;
        }
        // The control: the same `git log` `ever_added` runs, without its overrides, runs the planted
        // program, so the setup is the attack and the overrides are what stop it.
        let (dir, mark) = planted_for_log("log-control");
        let plain = Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args([
                "log",
                "--all",
                "--diff-filter=A",
                "--name-only",
                "--format=",
                "--relative",
                "-z",
            ])
            .output()
            .unwrap();
        assert!(plain.status.success());
        assert!(
            mark.exists(),
            "plain git log did not run the planted program, so this proves nothing"
        );
        std::fs::remove_dir_all(&dir).ok();

        let (dir, mark) = planted_for_log("log-guarded");
        let added = ever_added(&dir).expect("git answers");
        let tracked = ls_files(&dir).expect("git answers");
        let shallow = is_shallow(&dir);
        let ran = mark.exists();
        std::fs::remove_dir_all(&dir).ok();
        assert!(!ran, "git log ran the program the app's repository named");
        assert!(added.iter().any(|n| n == ".env"), "{added:?}");
        assert!(added.iter().any(|n| n == "app.py"), "{added:?}");
        // The point of reading history: the file is no longer tracked, and is still found.
        assert!(!tracked.iter().any(|n| n == ".env"), "{tracked:?}");
        assert_eq!(shallow, Some(false));
    }

    #[test]
    fn a_name_git_would_quote_is_given_as_it_is() {
        let (dir, _) = planted("quoted");
        // Git quotes a name with letters beyond English, a quote, or a backslash. Windows refuses
        // the last two in a file name (a backslash is its folder separator), so there the names
        // are the ones it allows (backlog 0120).
        let mut names = vec!["données/secrets.json", "clé 🔑 privée.pem"];
        if cfg!(unix) {
            names.extend(["a \"quoted\" name.txt", "back\\slash.txt"]);
        }
        for name in names.iter().copied() {
            let path = dir.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "x\n").unwrap();
        }
        let added = Command::new("git")
            .args(OVERRIDES)
            .arg("-C")
            .arg(&dir)
            .args(["add", "."])
            .output()
            .is_ok_and(|o| o.status.success());
        assert!(added, "git add failed in the test's setup");
        let listed = ls_files(&dir).expect("git answers");
        std::fs::remove_dir_all(&dir).ok();
        for name in names {
            assert!(listed.iter().any(|l| l == name), "{name} not in {listed:?}");
        }
        assert!(listed.iter().any(|l| l == "app.py"), "{listed:?}");
    }
}
