//! Configuration checks: the things that are wrong about an app's setup rather than its code.
//!
//! These are the checks that survive being language-agnostic. v1 has nineteen, and most are about its own
//! template — whether `package.json` was modified, whether the session policy matches the profile, whether
//! `trust proxy` is set to the right number of hops. Those mean nothing for an app somebody else wrote.
//! What is left is small and universal, and one of it matters more than everything in `secrets.rs`:
//!
//! **A credential in a file is a problem. A credential in version control is a different problem**, because
//! history keeps it after the file is fixed, and every clone, fork and backup has a copy. `sv check` can
//! find a key in `.env`; only git can say whether `.env` was committed.
//!
//! Every check here reports one of three things, never two. It passed, it failed, or **it could not be
//! run** — and the third is a first-class answer with a reason attached, because a check that did not run
//! is not a check that passed. Asking git about a folder that is not a repository is the ordinary case for
//! an app somebody uploaded, not an error.

use crate::finding::{Confidence, Finding, Location, Severity};
use std::path::Path;
use std::process::Command;

/// What a configuration check concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Passed,
    Failed(Box<Finding>),
    /// The check could not run. The string says why, in words an owner can act on.
    NotAssessed(String),
}

#[derive(Debug, Default)]
pub struct ConfigReport {
    pub findings: Vec<Finding>,
    pub passed: Vec<String>,
    /// Check id and why it could not run. Never folded into "passed".
    pub not_assessed: Vec<(String, String)>,
}

impl ConfigReport {
    fn record(&mut self, id: &str, outcome: Outcome) {
        match outcome {
            Outcome::Passed => self.passed.push(id.to_owned()),
            Outcome::Failed(f) => self.findings.push(*f),
            Outcome::NotAssessed(why) => self.not_assessed.push((id.to_owned(), why)),
        }
    }
}

/// Runs every configuration check over the app folder.
pub fn check_dir(app_dir: &Path) -> ConfigReport {
    let mut report = ConfigReport::default();
    report.record(
        "config.secrets-file-committed",
        secrets_file_committed(app_dir),
    );
    report.record("config.gitignore-covers-env", gitignore_covers_env(app_dir));
    report.record("config.security-contact", security_contact(app_dir));
    report
}

/// Files whose whole job is to hold credentials.
const SECRET_FILES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "secrets.json",
    "credentials.json",
    "service-account.json",
    "id_rsa",
    "id_ed25519",
    ".npmrc",
    ".pypirc",
    ".netrc",
];

/// Names that are meant to be committed: a template showing which settings exist, with no values in it.
fn is_example_file(name: &str) -> bool {
    name.ends_with(".example") || name.ends_with(".sample") || name.ends_with(".template")
}

/// Asks git which files it is tracking. `None` when git cannot answer — not a repository, not installed.
fn tracked_files(app_dir: &Path) -> Option<Vec<String>> {
    if !app_dir.join(".git").exists() {
        return None;
    }
    let out = Command::new("git")
        .args(["-C", app_dir.to_str()?, "ls-files"])
        .output()
        .ok()?;
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

/// The check that matters most: a file whose job is holding credentials, committed to version control.
fn secrets_file_committed(app_dir: &Path) -> Outcome {
    let Some(tracked) = tracked_files(app_dir) else {
        return Outcome::NotAssessed(
            "This folder is not a git repository that `sv` could read, so it cannot say whether a \
             secrets file was ever committed. If the app is kept in version control somewhere else, \
             that question is still open."
                .to_owned(),
        );
    };

    let committed: Vec<&String> = tracked
        .iter()
        .filter(|path| {
            let name = path.rsplit('/').next().unwrap_or(path);
            !is_example_file(name) && (SECRET_FILES.contains(&name) || name.starts_with(".env."))
        })
        .collect();

    match committed.first() {
        None => Outcome::Passed,
        Some(first) => Outcome::Failed(Box::new(Finding {
            rule_id: "config.secrets-file-committed".into(),
            title: format!("A file that holds credentials is in version control (`{first}`)"),
            severity: Severity::Critical,
            confidence: Confidence::High,
            location: Location { file: (*first).clone(), line: 1 },
            secret: None,
            requirement_ids: vec!["V13.3.1".into(), "AC-05".into()],
            cwe: vec!["CWE-540".into(), "CWE-538".into()],
            description: if committed.len() == 1 {
                format!("`{first}` is tracked by git, and files with that name hold credentials.")
            } else {
                format!(
                    "`{first}` and {} other file(s) that hold credentials are tracked by git.",
                    committed.len() - 1
                )
            },
            impact: "Deleting the file does not help: version control keeps its history, and every \
                     clone, fork and backup already has a copy. Treat every credential in it as known \
                     to anyone who has ever had access to the repository."
                .into(),
            fix: "Change every credential in the file first — that is the part that actually protects \
                  you. Then stop tracking it (`git rm --cached`), add it to .gitignore, and keep a \
                  .env.example with the names and no values."
                .into(),
        })),
    }
}

/// Whether `.gitignore` excludes the environment file, so the next person does not commit it.
fn gitignore_covers_env(app_dir: &Path) -> Outcome {
    let path = app_dir.join(".gitignore");
    let Ok(text) = std::fs::read_to_string(&path) else {
        // No .gitignore is only a problem if this is a repository at all.
        if app_dir.join(".git").exists() {
            return Outcome::Failed(Box::new(env_not_ignored_finding(
                ".gitignore",
                "This app is in version control and has no .gitignore, so nothing stops `.env` being \
                 committed."
                    .to_owned(),
            )));
        }
        return Outcome::NotAssessed(
            "There is no .gitignore and this folder is not a git repository, so there is nothing for \
             this check to read."
                .to_owned(),
        );
    };

    let covered = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .any(|l| matches!(l, ".env" | ".env*" | ".env.*" | "*.env" | "**/.env"));

    if covered {
        Outcome::Passed
    } else {
        Outcome::Failed(Box::new(env_not_ignored_finding(
            ".gitignore",
            "The .gitignore file does not list `.env`, so nothing stops it being committed."
                .to_owned(),
        )))
    }
}

fn env_not_ignored_finding(file: &str, description: String) -> Finding {
    Finding {
        rule_id: "config.gitignore-covers-env".into(),
        title: "Nothing stops the environment file being committed".into(),
        severity: Severity::High,
        confidence: Confidence::High,
        location: Location { file: file.to_owned(), line: 1 },
        secret: None,
        requirement_ids: vec!["V13.3.1".into(), "AC-05".into()],
        cwe: vec!["CWE-540".into()],
        description,
        impact: "Once a credential reaches a repository it is effectively known to everyone with \
                 access to it, including any host or backup, and deleting it later does not undo that."
            .into(),
        fix: "Add `.env` and `.env.*` to .gitignore, with an exception for `.env.example`.".into(),
    }
}

/// Whether there is a way to report a security problem. Not a vulnerability; an absence.
fn security_contact(app_dir: &Path) -> Outcome {
    const PLACES: &[&str] = &[
        "SECURITY.md",
        "security.md",
        ".github/SECURITY.md",
        "docs/SECURITY.md",
    ];
    if PLACES.iter().any(|p| app_dir.join(p).exists()) {
        return Outcome::Passed;
    }
    Outcome::Failed(Box::new(Finding {
        rule_id: "config.security-contact".into(),
        title: "There is no way to report a security problem".into(),
        severity: Severity::Low,
        confidence: Confidence::High,
        location: Location {
            file: "SECURITY.md".into(),
            line: 1,
        },
        secret: None,
        requirement_ids: vec!["AC-13".into()],
        cwe: vec![],
        description: "No SECURITY.md was found, so somebody who finds a problem in this app has \
                      nowhere obvious to say so."
            .into(),
        impact: "Problems found by outsiders get reported publicly, or not at all.".into(),
        fix: "Add a SECURITY.md saying where to send a report and how long a reply should take."
            .into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sv-config-{name}-{}", std::process::id()));
        fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn git_repo(name: &str) -> Option<std::path::PathBuf> {
        let dir = scratch(name);
        let ok = Command::new("git")
            .args(["-C", dir.to_str().unwrap(), "init", "-q"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            return None;
        }
        for (k, v) in [("user.email", "t@example.com"), ("user.name", "t")] {
            let _ = Command::new("git")
                .args(["-C", dir.to_str().unwrap(), "config", k, v])
                .status();
        }
        Some(dir)
    }

    fn commit_all(dir: &Path) {
        let d = dir.to_str().unwrap();
        let _ = Command::new("git").args(["-C", d, "add", "-A"]).status();
        let _ = Command::new("git")
            .args(["-C", d, "commit", "-q", "-m", "t"])
            .status();
    }

    #[test]
    fn a_committed_env_file_is_critical() {
        let Some(dir) = git_repo("committed") else {
            // Never a silent skip: if git is missing the test says so and checks nothing else.
            println!("git is not available here, so this cannot be exercised");
            return;
        };
        fs::write(dir.join(".env"), "SESSION_SECRET=Xk7mQ92vLpR4sTz\n").unwrap();
        commit_all(&dir);
        let report = check_dir(&dir);
        let found = report
            .findings
            .iter()
            .find(|f| f.rule_id == "config.secrets-file-committed")
            .unwrap_or_else(|| panic!("no finding; report was {report:?}"));
        assert_eq!(found.severity, Severity::Critical);
        // The fix has to lead with changing the credential, because that is the part that helps.
        assert!(
            found.fix.starts_with("Change every credential"),
            "{}",
            found.fix
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_example_file_is_meant_to_be_committed() {
        let Some(dir) = git_repo("example") else {
            println!("git is not available here, so this cannot be exercised");
            return;
        };
        fs::write(dir.join(".env.example"), "SESSION_SECRET=\n").unwrap();
        fs::write(dir.join(".gitignore"), ".env\n").unwrap();
        commit_all(&dir);
        let report = check_dir(&dir);
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule_id == "config.secrets-file-committed"),
            "a .env.example was reported as a committed secrets file: {report:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_folder_that_is_not_a_repository_is_not_assessed_rather_than_passed() {
        // The ordinary case for an app somebody uploaded. Saying "no committed secrets" here would be
        // a claim `sv` cannot support: it has not seen the history, only a copy of the files.
        let dir = scratch("norepo");
        fs::write(dir.join(".env"), "SESSION_SECRET=x\n").unwrap();
        let report = check_dir(&dir);
        assert!(
            !report
                .passed
                .contains(&"config.secrets-file-committed".to_string()),
            "a folder with no git history must not pass this check"
        );
        let (_, why) = report
            .not_assessed
            .iter()
            .find(|(id, _)| id == "config.secrets-file-committed")
            .expect("must be recorded as not assessed");
        assert!(why.contains("not a git repository"), "{why}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_repository_git_cannot_read_is_not_assessed_either() {
        // The other way the question goes unanswered, and a different code path from a missing .git:
        // the marker is there but git refuses — a broken worktree pointer, a corrupt repository, git not
        // installed. The tempting answer is "no tracked secrets found", and it would be a claim made
        // about history nobody read.
        let dir = scratch("brokenrepo");
        fs::write(dir.join(".git"), "gitdir: /nowhere/that/exists\n").unwrap();
        fs::write(dir.join(".env"), "SESSION_SECRET=x\n").unwrap();
        let report = check_dir(&dir);
        assert!(
            !report
                .passed
                .contains(&"config.secrets-file-committed".to_string()),
            "a repository git cannot read must not pass: {report:?}"
        );
        assert!(
            report
                .not_assessed
                .iter()
                .any(|(id, _)| id == "config.secrets-file-committed"),
            "it must be recorded as not assessed: {report:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn gitignore_that_covers_env_passes_and_one_that_does_not_fails() {
        let dir = scratch("ignore");
        fs::write(dir.join(".gitignore"), "node_modules\n.env\n").unwrap();
        assert!(
            check_dir(&dir)
                .passed
                .contains(&"config.gitignore-covers-env".to_string())
        );

        fs::write(dir.join(".gitignore"), "node_modules\ndist\n").unwrap();
        let report = check_dir(&dir);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id == "config.gitignore-covers-env"),
            "{report:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_wildcard_env_entry_counts() {
        let dir = scratch("wildcard");
        for pattern in [".env*", ".env.*", "*.env", "**/.env"] {
            fs::write(dir.join(".gitignore"), format!("{pattern}\n")).unwrap();
            assert!(
                check_dir(&dir)
                    .passed
                    .contains(&"config.gitignore-covers-env".to_string()),
                "{pattern} should count as covering .env"
            );
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_security_file_is_low_and_a_present_one_passes() {
        let dir = scratch("security");
        let report = check_dir(&dir);
        let f = report
            .findings
            .iter()
            .find(|f| f.rule_id == "config.security-contact")
            .unwrap();
        assert_eq!(f.severity, Severity::Low);

        fs::create_dir_all(dir.join(".github")).unwrap();
        fs::write(
            dir.join(".github/SECURITY.md"),
            "mail security@example.com\n",
        )
        .unwrap();
        assert!(
            check_dir(&dir)
                .passed
                .contains(&"config.security-contact".to_string())
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn nothing_is_both_passed_and_found() {
        let dir = scratch("disjoint");
        fs::write(dir.join(".gitignore"), ".env\n").unwrap();
        let report = check_dir(&dir);
        for id in &report.passed {
            assert!(
                !report.findings.iter().any(|f| &f.rule_id == id),
                "{id} is reported as both passed and failed"
            );
            assert!(
                !report.not_assessed.iter().any(|(n, _)| n == id),
                "{id} is reported as both passed and not assessed"
            );
        }
        fs::remove_dir_all(&dir).ok();
    }
}
