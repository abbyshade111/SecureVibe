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
use crate::verified::Verified;
use std::path::Path;
use std::process::Command;
use sv_scan::ecosystems::Pinning;

/// What a configuration check concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Passed, and the requirements this check is evidence about.
    ///
    /// The list is not decoration. A check that names its requirements when it fails and drops them
    /// when it passes can only ever subtract: the report can say a requirement needs attention but
    /// never that anything looked at it and was satisfied, so every requirement reads as unchecked
    /// however many checks ran. The failing side of each check below already knew these ids.
    Passed(&'static [&'static str]),
    Failed(Box<Finding>),
    /// The check could not run. The string says why, in words an owner can act on.
    NotAssessed(String),
}

#[derive(Debug, Default)]
pub struct ConfigReport {
    pub findings: Vec<Finding>,
    pub passed: Vec<Verified>,
    /// Check id and why it could not run. Never folded into "passed".
    pub not_assessed: Vec<(String, String)>,
}

impl ConfigReport {
    fn record(&mut self, id: &str, outcome: Outcome) {
        match outcome {
            Outcome::Passed(requirement_ids) => self.passed.push(Verified::new(
                id,
                requirement_ids,
                "the files this check reads".to_owned(),
            )),
            Outcome::Failed(f) => self.findings.push(*f),
            Outcome::NotAssessed(why) => self.not_assessed.push((id.to_owned(), why)),
        }
    }
}

/// Runs every configuration check over the app folder.
pub fn check_dir(app_dir: &Path) -> ConfigReport {
    let listing = sv_scan::files::Listing::of(app_dir);
    let bill_of_materials = crate::sbom::build_in(&listing);
    check_dir_in(&listing, &bill_of_materials)
}

/// `check_dir`, with the app's files and its bill of materials already made, so `sv report` walks
/// the folder once and builds the bill once.
pub fn check_dir_in(
    listing: &sv_scan::files::Listing,
    bill_of_materials: &crate::sbom::Sbom,
) -> ConfigReport {
    let app_dir = listing.root.as_path();
    let mut report = ConfigReport::default();
    report.record(
        "config.secrets-file-committed",
        secrets_file_committed(app_dir),
    );
    report.record("config.gitignore-covers-env", gitignore_covers_env(app_dir));
    report.record("config.security-contact", security_contact(app_dir));
    report.record(
        "config.versions-pinned",
        versions_pinned(listing, bill_of_materials),
    );
    crate::launch::check(listing, &mut report);
    crate::rich_text::check(listing, bill_of_materials, &mut report);
    crate::grants::check(listing, bill_of_materials, &mut report);
    crate::model_files::check(listing, &mut report);
    let workflows = crate::workflows::check(app_dir);
    report.findings.extend(workflows.findings);
    report.passed.extend(workflows.passed);
    report.not_assessed.extend(workflows.not_assessed);
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

/// Why git could not say which files it tracks.
enum NoHistory {
    /// There is no `.git` here at all: the app was never put in git.
    NotARepository,
    /// There is one, and git could not read it: not installed, a broken link, a refused owner.
    Unreadable,
}

/// The folder holding the git repository the app is in: the app folder itself, or one above it
/// when the app is a subfolder of a larger repository. Until 29 September 2026 only the app folder
/// was looked at, so `sv report repo/app` said "not a git repository" of an app in one.
fn repository_root(app_dir: &Path) -> Option<std::path::PathBuf> {
    let full = std::fs::canonicalize(app_dir).unwrap_or_else(|_| app_dir.to_path_buf());
    full.ancestors()
        .find(|folder| folder.join(".git").exists())
        .map(Path::to_path_buf)
}

/// Asks git which files it is tracking under the app folder. Run from inside the folder, git lists
/// only the files under it, named from it, so a file elsewhere in a larger repository is not the
/// app's and is not reported.
fn tracked_files(app_dir: &Path) -> Result<Vec<String>, NoHistory> {
    if repository_root(app_dir).is_none() {
        return Err(NoHistory::NotARepository);
    }
    read_tracked(app_dir).ok_or(NoHistory::Unreadable)
}

fn read_tracked(app_dir: &Path) -> Option<Vec<String>> {
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
    let tracked = match tracked_files(app_dir) {
        Ok(tracked) => tracked,
        // Found in the owner's first build (27 September 2026): a beginner's app usually starts
        // outside git, and nothing said to put it there, so this check never ran. The order in the
        // advice matters: `git add` before a `.gitignore` commits the very file this looks for.
        Err(NoHistory::NotARepository) => {
            return Outcome::NotAssessed(
                "This folder is not a git repository, so `sv` cannot say whether a secrets file \
                 was ever committed. Putting the app in git (version control, which keeps every \
                 saved version) makes this check run, and is worth doing anyway. Ask your AI coding \
                 tool to do it, and to add a .gitignore that leaves out .env and other secret files \
                 before the first commit, so that commit does not save them. If the app is already \
                 kept in version control somewhere else, that copy's history is still unchecked."
                    .to_owned(),
            );
        }
        Err(NoHistory::Unreadable) => {
            return Outcome::NotAssessed(
                "This folder has a git repository that git could not read (git may not be \
                 installed, or the repository is damaged or belongs to another user), so `sv` \
                 cannot say whether a secrets file was ever committed."
                    .to_owned(),
            );
        }
    };

    let committed: Vec<&String> = tracked
        .iter()
        .filter(|path| {
            let name = path.rsplit('/').next().unwrap_or(path);
            !is_example_file(name) && (SECRET_FILES.contains(&name) || name.starts_with(".env."))
        })
        .collect();

    match committed.first() {
        None => Outcome::Passed(&["V13.3.1"]),
        Some(first) => Outcome::Failed(Box::new(Finding {
            also_reported_by: Vec::new(),
            fingerprint: String::new(),
            earlier_fingerprints: Vec::new(),
            marked_test_code: false,
            rule_id: "config.secrets-file-committed".into(),
            title: format!("A file that holds credentials is in version control (`{first}`)"),
            severity: Severity::Critical,
            confidence: Confidence::High,
            location: Location { file: (*first).clone(), line: 1 },
            secret: None,
            requirement_ids: vec!["V13.3.1".into()],
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
        let root = repository_root(app_dir);
        let full = std::fs::canonicalize(app_dir).unwrap_or_else(|_| app_dir.to_path_buf());
        if root.as_deref() == Some(full.as_path()) {
            return Outcome::Failed(Box::new(env_not_ignored_finding(
                ".gitignore",
                "This app is in version control and has no .gitignore, so nothing stops `.env` being \
                 committed."
                    .to_owned(),
            )));
        }
        // A subfolder of a larger repository: the .gitignore that matters may be in a folder
        // above, which is outside what `sv` was pointed at.
        if root.is_some() {
            return Outcome::NotAssessed(
                "This app is a folder inside a larger git repository and has no .gitignore of its \
                 own. A .gitignore in a folder above it may leave out .env, but `sv` reads only the \
                 app's folder, so this check did not run."
                    .to_owned(),
            );
        }
        return Outcome::NotAssessed(
            "There is no .gitignore and this folder is not a git repository, so there is nothing for \
             this check to read."
                .to_owned(),
        );
    };

    let covered = gitignore_ignores(&text, ".env");

    if covered {
        Outcome::Passed(&["V13.3.1"])
    } else {
        Outcome::Failed(Box::new(env_not_ignored_finding(
            ".gitignore",
            "The .gitignore file does not list `.env`, so nothing stops it being committed."
                .to_owned(),
        )))
    }
}

/// Whether a `.gitignore` at the app's root leaves out the file at `path` (a file at the root, such
/// as `.env`), read the way git reads it: blank lines and `#` comments skipped, the last pattern
/// that matches decides, `!` brings a file back, and a pattern with a `/` in it is anchored to the
/// root (one ending in `/` names only folders, and so never matches a file's path). Until 5 October
/// 2026 only a few whole lines were recognized, so `/.env` failed, `.env` followed by `!.env`
/// passed, and `.env.*` alone, which git does not apply to `.env`, passed too (H23 of the deep
/// review).
fn gitignore_ignores(text: &str, path: &str) -> bool {
    let mut ignored = false;
    for raw in text.lines() {
        let line = raw.trim_end_matches(['\r', '\n']);
        // Trailing spaces are dropped unless the last is escaped.
        let line = if line.ends_with("\\ ") {
            line
        } else {
            line.trim_end_matches(' ')
        };
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (negate, pattern) = match line.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, line.strip_prefix('\\').unwrap_or(line)),
        };
        let anchored = pattern.contains('/');
        let pattern = pattern.strip_prefix('/').unwrap_or(pattern);
        let matches = if anchored {
            glob_matches(pattern, path)
        } else {
            glob_matches(pattern, path.rsplit('/').next().unwrap_or(path))
        };
        if matches {
            ignored = !negate;
        }
    }
    ignored
}

/// Git's wildcards: `*` and `?` within one part of a path, `**` across parts, `[...]` a set of
/// characters (with `!` or `^` for its opposite), and `\` taking the next character as it is.
fn glob_matches(pattern: &str, text: &str) -> bool {
    fn go(p: &[char], t: &[char]) -> bool {
        match p.split_first() {
            None => t.is_empty(),
            Some(('*', rest)) if rest.first() == Some(&'*') => {
                let rest = &rest[1..];
                let rest = rest.strip_prefix(&['/']).unwrap_or(rest);
                (0..=t.len()).any(|i| go(rest, &t[i..]))
            }
            Some(('*', rest)) => (0..=t.len())
                .take_while(|i| *i == 0 || t[i - 1] != '/')
                .any(|i| go(rest, &t[i..])),
            Some(('?', rest)) => t.first().is_some_and(|c| *c != '/') && go(rest, &t[1..]),
            Some(('[', rest)) => {
                let Some(close) = rest.iter().skip(1).position(|c| *c == ']').map(|i| i + 1) else {
                    return t.first() == Some(&'[') && go(rest, &t[1..]);
                };
                let (set, after) = (&rest[..close], &rest[close + 1..]);
                let (negated, set) = match set.first() {
                    Some('!' | '^') => (true, &set[1..]),
                    _ => (false, set),
                };
                let Some(c) = t.first() else { return false };
                let mut inside = false;
                let mut i = 0;
                while i < set.len() {
                    if i + 2 < set.len() && set[i + 1] == '-' {
                        inside |= set[i] <= *c && *c <= set[i + 2];
                        i += 3;
                    } else {
                        inside |= set[i] == *c;
                        i += 1;
                    }
                }
                inside != negated && *c != '/' && go(after, &t[1..])
            }
            Some(('\\', rest)) if !rest.is_empty() => {
                t.first() == Some(&rest[0]) && go(&rest[1..], &t[1..])
            }
            Some((c, rest)) => t.first() == Some(c) && go(rest, &t[1..]),
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    go(&p, &t)
}

fn env_not_ignored_finding(file: &str, description: String) -> Finding {
    Finding {
        also_reported_by: Vec::new(),
            fingerprint: String::new(),
            earlier_fingerprints: Vec::new(),
            marked_test_code: false,
        rule_id: "config.gitignore-covers-env".into(),
        title: "Nothing stops the environment file being committed".into(),
        severity: Severity::High,
        confidence: Confidence::High,
        location: Location { file: file.to_owned(), line: 1 },
        secret: None,
        requirement_ids: vec!["V13.3.1".into()],
        cwe: vec!["CWE-540".into()],
        description,
        impact: "Once a credential reaches a repository it is effectively known to everyone with \
                 access to it, including any host or backup, and deleting it later does not undo that."
            .into(),
        fix: "Add `.env` and `.env.*` to .gitignore, with an exception for `.env.example`.".into(),
    }
}

/// Whether the app pins what it installs.
///
/// An ecosystem in use with no lockfile means nobody can say what is actually installed — not the
/// developer, not a reviewer, and not `sv`. The same build on a different day is a different app.
///
/// The trap here is worth naming, because it was one function call away. `pom.xml` has no lockfile to
/// look for: Maven pins in the manifest itself, and Gradle's lockfile is something a project turns on.
/// A check that asked "is there a lockfile?" would report every Maven project as pinning nothing — not
/// a coverage gap but a wrong statement in a report, which is exactly what v1's ADR-012 is about — and did
/// report every Gradle project without one. So for both the versions are read (`sv_scan::jvm`): all
/// exact passes, one that floats is a finding at its line, and one `sv` cannot work out leaves the
/// question open with the reason.
fn versions_pinned(
    listing: &sv_scan::files::Listing,
    bill_of_materials: &crate::sbom::Sbom,
) -> Outcome {
    let app_dir = listing.root.as_path();
    let detected = sv_scan::ecosystems::detect_in(listing);
    if detected.is_empty() {
        return Outcome::NotAssessed(
            "No package manifest was found, so there is nothing whose versions could be pinned. If this \
             app installs dependencies some other way, that is not something `sv` can see."
                .to_owned(),
        );
    }

    let judged: Vec<(sv_scan::ecosystems::DetectedEcosystem, Pinning)> = detected
        .into_iter()
        .map(|e| {
            let p = sv_scan::ecosystems::pinning(app_dir, &e);
            (e, p)
        })
        .collect();

    let unpinned: Vec<&(sv_scan::ecosystems::DetectedEcosystem, Pinning)> =
        judged.iter().filter(|(_, p)| p.is_unpinned()).collect();
    if let Some((first, how)) = unpinned.first() {
        let names: Vec<String> = unpinned.iter().map(|(e, _)| e.label()).collect();
        let (location, description, fix) = match how {
            Pinning::Floating(versions) => (
                Location {
                    file: versions[0].manifest.clone(),
                    line: versions[0].line,
                },
                format!(
                    "`{}` asks for {}, so the versions installed today and the versions installed \
                     tomorrow can differ.",
                    first.manifest,
                    listed(versions)
                ),
                "Write an exact version for each of these (`1.2.3`, not a range, `+`, `LATEST`, or a \
                 snapshot). A Gradle project can instead turn on dependency locking and commit the \
                 `gradle.lockfile` it writes.",
            ),
            _ => (
                Location {
                    file: first.manifest.clone(),
                    line: 1,
                },
                format!(
                    "`{}` is in use and there is no lockfile beside it, so the versions installed \
                     today and the versions installed tomorrow can differ.",
                    first.manifest
                ),
                "Install once and commit the lockfile that produces, then install from it from then on.",
            ),
        };
        return Outcome::Failed(Box::new(Finding {
            also_reported_by: Vec::new(),
            fingerprint: String::new(),
            earlier_fingerprints: Vec::new(),
            marked_test_code: false,
            rule_id: "config.versions-pinned".into(),
            title: if names.len() == 1 {
                format!("{} does not pin the versions it installs", names[0])
            } else {
                format!("{} do not pin the versions they install", names.join(" and "))
            },
            severity: Severity::Medium,
            confidence: Confidence::High,
            location,
            secret: None,
            // V15.1.2 asks that an inventory catalog of third-party libraries is maintained.
            // A lockfile is what makes that inventory the versions actually installed rather than
            // the versions asked for. This cited V1.3.5 — sanitizing user-supplied template and
            // stylesheet content — until 24 September 2026, and that citation was also attached to
            // the *passing* outcome below, so a lockfile put a green line against template
            // sanitization.
            requirement_ids: vec!["V15.1.2".into()],
            cwe: vec!["CWE-1104".into()],
            description,
            impact: "The inventory of third-party libraries this app ships is then a list of what was \
                     asked for rather than what is installed, so nobody can say whether a known \
                     vulnerability applies to it — and a component that is compromised upstream arrives \
                     on the next install without anything changing here."
                .into(),
            fix: fix.into(),
        }));
    }

    let open: Vec<String> = judged
        .iter()
        .filter_map(|(e, p)| match p {
            Pinning::Unsettled(versions) => Some(format!(
                "{} (`{}`): {}",
                e.label(),
                e.manifest,
                listed(versions)
            )),
            _ => None,
        })
        .collect();
    if !open.is_empty() {
        return Outcome::NotAssessed(format!(
            "`sv` read the versions this app asks for and could not settle every one. {}. Whether \
             this app pins what it installs is still an open question, not a passed check.",
            open.join("; ")
        ));
    }

    // A lockfile `sv` could take nothing from is a lockfile nobody here has seen pin anything: a
    // format it cannot read, or one that parsed and held no packages. Counting its presence as a
    // pass credited V15.1.2, an inventory of what is installed, for an app whose inventory the
    // same run reported as empty (found 27 September 2026, with a `poetry.lock` holding no packages).
    // The bill of materials is what read it, so it is what is asked.
    let mut unread: Vec<&str> = judged
        .iter()
        .filter(|(e, _)| e.lockfile.is_some())
        .flat_map(|(e, _)| {
            bill_of_materials
                .unread
                .iter()
                .filter(move |(name, _)| *name == e.name)
                .map(|(_, why)| why.as_str())
        })
        .collect();
    unread.dedup();
    if !unread.is_empty() {
        return Outcome::NotAssessed(format!(
            "A lockfile is there, and `sv` could not read the versions from it: {}. Whether this app \
             pins what it installs is still an open question, not a passed check.",
            unread.join("; ")
        ));
    }

    Outcome::Passed(&["V15.1.2"])
}

/// Up to three versions in words, with how many more there are: "`g:a` at `[1.0,2.0)` (line 12, a
/// range, …)".
fn listed(versions: &[sv_scan::jvm::VersionAt]) -> String {
    let mut parts: Vec<String> = versions
        .iter()
        .take(3)
        .map(|v| {
            let at = if v.version.is_empty() {
                String::new()
            } else {
                format!(" at `{}`", v.version)
            };
            format!("`{}`{at} (line {}: {})", v.dependency, v.line, v.why)
        })
        .collect();
    if versions.len() > 3 {
        parts.push(format!("and {} more", versions.len() - 3));
    }
    parts.join(", ")
}

/// Whether the app says how to report a security problem: a `SECURITY` file (`.md`, `.txt`, `.rst`,
/// `.adoc`, or none) at its root, in `.github/`, or in `docs/`, or a `security.txt` where a site
/// serves it from (RFC 9116: `.well-known/`, also under `public/` or `static/`, and at the root).
/// Any capitalization. Until 5 October 2026 only four exact paths counted (H23 of the deep review).
fn has_security_contact(app_dir: &Path) -> bool {
    const FOLDERS: &[&str] = &[
        "",
        ".github",
        "docs",
        ".well-known",
        "public/.well-known",
        "static/.well-known",
        "public",
        "static",
    ];
    const NAMES: &[&str] = &[
        "security.md",
        "security.txt",
        "security.rst",
        "security.adoc",
        "security",
    ];
    FOLDERS.iter().any(|folder| {
        let Ok(entries) = std::fs::read_dir(app_dir.join(folder)) else {
            return false;
        };
        entries.flatten().any(|e| {
            let name = e.file_name().to_string_lossy().to_lowercase();
            NAMES.contains(&name.as_str()) && e.file_type().is_ok_and(|k| k.is_file())
        })
    })
}

/// Whether there is a way to report a security problem. Not a vulnerability; an absence.
fn security_contact(app_dir: &Path) -> Outcome {
    if has_security_contact(app_dir) {
        // Deliberately empty. Nothing in ASVS, AISVS or Appendix C requires a way to report a
        // vulnerability; it is an organizational control rather than an application one. This check
        // is worth running and is evidence about no requirement in particular, which the reports
        // show rather than hide.
        return Outcome::Passed(&[]);
    }
    Outcome::Failed(Box::new(Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        rule_id: "config.security-contact".into(),
        title: "There is no way to report a security problem".into(),
        severity: Severity::Low,
        confidence: Confidence::High,
        location: Location {
            file: "SECURITY.md".into(),
            line: 1,
        },
        secret: None,
        requirement_ids: vec![],
        cwe: vec![],
        description:
            "No SECURITY.md or security.txt was found, so somebody who finds a problem in \
                      this app has nowhere obvious to say so."
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

    #[test]
    fn a_lockfile_nothing_could_be_read_from_is_not_a_pass() {
        // A lockfile being there is not the same as its versions being known: with nothing taken
        // from it, a pass credited an inventory the same run reported as empty.
        let dir = scratch("garbled-lock");
        fs::write(
            dir.join("pyproject.toml"),
            "[tool.poetry]\nname = \"x\"\n[tool.poetry.dependencies]\nflask = \"^3.0\"\n",
        )
        .unwrap();
        fs::write(dir.join("poetry.lock"), "this is not a lockfile\n").unwrap();
        let pinned = |dir: &std::path::Path| {
            let listing = sv_scan::files::Listing::of(dir);
            versions_pinned(&listing, &crate::sbom::build_in(&listing))
        };
        let outcome = pinned(&dir);

        // And the control, in the same folder: a lockfile the bill of materials can read passes.
        fs::write(
            dir.join("poetry.lock"),
            "[[package]]\nname = \"flask\"\nversion = \"3.0.0\"\n",
        )
        .unwrap();
        let readable = pinned(&dir);
        fs::remove_dir_all(&dir).ok();

        match outcome {
            Outcome::NotAssessed(why) => assert!(why.contains("could not read"), "{why}"),
            other => panic!("expected not assessed, got {other:?}"),
        }
        assert_eq!(readable, Outcome::Passed(&["V15.1.2"]));
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
    fn an_app_in_a_subfolder_of_a_repository_is_checked_against_its_history() {
        // Found in the owner's comparison study (29 September 2026): `sv report repo/app` said
        // "not a git repository" of an app in one, because only `app/.git` was looked for.
        let Some(repo) = git_repo("subfolder") else {
            println!("git is not available here, so this cannot be exercised");
            return;
        };
        let app = repo.join("app");
        fs::create_dir_all(&app).unwrap();
        fs::create_dir_all(repo.join("other")).unwrap();
        fs::write(app.join(".env"), "SESSION_SECRET=x\n").unwrap();
        fs::write(repo.join("other").join(".env"), "SESSION_SECRET=x\n").unwrap();
        commit_all(&repo);
        // The setup worked: both files really are in the repository's history.
        let listed = read_tracked(&repo).expect("git lists the repository");
        assert!(
            listed.iter().any(|f| f == "app/.env") && listed.iter().any(|f| f == "other/.env"),
            "{listed:?}"
        );

        let report = check_dir(&app);
        let found = report
            .findings
            .iter()
            .find(|f| f.rule_id == "config.secrets-file-committed")
            .unwrap_or_else(|| panic!("no finding; report was {report:?}"));
        // Named from the app's folder, as every other finding is.
        assert_eq!(found.location.file, ".env");
        // It has no .gitignore of its own, and the repository's may be above it: not a failure.
        let (_, why) = report
            .not_assessed
            .iter()
            .find(|(id, _)| id == "config.gitignore-covers-env")
            .unwrap_or_else(|| panic!("not recorded as not assessed: {report:?}"));
        assert!(why.contains("inside a larger git repository"), "{why}");

        // The control: a sibling folder whose only neighbor committed a secrets file. That file is
        // not the app's, and the app's own history is clean.
        let clean = repo.join("clean");
        fs::create_dir_all(&clean).unwrap();
        fs::write(clean.join("main.py"), "print(1)\n").unwrap();
        commit_all(&repo);
        assert!(
            check_dir(&clean)
                .passed
                .iter()
                .any(|p| p.check_id == "config.secrets-file-committed"),
            "a file elsewhere in the repository must not be reported against this app"
        );
        fs::remove_dir_all(&repo).ok();
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
                .iter()
                .any(|p| p.check_id == "config.secrets-file-committed"),
            "a folder with no git history must not pass this check"
        );
        let (_, why) = report
            .not_assessed
            .iter()
            .find(|(id, _)| id == "config.secrets-file-committed")
            .expect("must be recorded as not assessed");
        assert!(why.contains("not a git repository"), "{why}");
        // And it says how to fix that safely: a .gitignore before the first commit, or the first
        // commit saves the very file this check looks for.
        assert!(
            why.contains("Putting the app in git") && why.contains("before the first commit"),
            "{why}"
        );
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
                .iter()
                .any(|p| p.check_id == "config.secrets-file-committed"),
            "a repository git cannot read must not pass: {report:?}"
        );
        let (_, why) = report
            .not_assessed
            .iter()
            .find(|(id, _)| id == "config.secrets-file-committed")
            .expect("it must be recorded as not assessed");
        // It is in git already, so the advice for an app outside git would be wrong here.
        assert!(
            why.contains("could not read") && !why.contains("Putting the app in git"),
            "{why}"
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
                .iter()
                .any(|p| p.check_id == "config.gitignore-covers-env")
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
    fn a_gitignore_is_read_the_way_git_reads_it() {
        // H23: `/.env` failed, and `.env` followed by `!.env` passed. Each case is what git itself
        // does with the file at the root called `.env`.
        for (text, ignored) in [
            ("/.env\n", true),
            (".env\n!.env\n", false),
            (".env*\n!.env.example\n", true),
            ("!.env\n.env\n", true),
            ("*\n!.gitignore\n", true),
            ("*\n!*.env\n", false),
            ("**/.env\n", true),
            (".en?\n", true),
            (".[e]nv\n", true),
            (".[!e]nv\n", false),
            ("*.env\n", true),
            (".env/\n", false),
            ("config/.env\n", false),
            ("/config/.env\n", false),
            ("# .env\n", false),
            ("\\#.env\n", false),
            (".env   \n", true),
            ("node_modules\ndist\n", false),
            (".envrc\n", false),
            ("", false),
        ] {
            assert_eq!(gitignore_ignores(text, ".env"), ignored, "{text:?}");
        }
        // And through the check itself, both ways.
        let dir = scratch("gitignore-git");
        fs::write(dir.join(".gitignore"), "/.env\n").unwrap();
        assert!(
            check_dir(&dir)
                .passed
                .iter()
                .any(|p| p.check_id == "config.gitignore-covers-env")
        );
        fs::write(dir.join(".gitignore"), ".env\n!.env\n").unwrap();
        assert!(
            check_dir(&dir)
                .findings
                .iter()
                .any(|f| f.rule_id == "config.gitignore-covers-env")
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_security_contact_is_found_however_it_is_spelled_and_wherever_a_site_serves_it() {
        // H23: `.well-known/security.txt` and other spellings were not recognized.
        for place in [
            "SECURITY.md",
            "Security.md",
            "SECURITY.txt",
            "SECURITY",
            "SECURITY.rst",
            ".github/security.md",
            "docs/Security.md",
            ".well-known/security.txt",
            "public/.well-known/security.txt",
            "static/.well-known/security.txt",
            "security.txt",
        ] {
            let dir = scratch("security-places");
            let path = dir.join(place);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, "Contact: mailto:security@example.com\n").unwrap();
            assert!(
                check_dir(&dir)
                    .passed
                    .iter()
                    .any(|p| p.check_id == "config.security-contact"),
                "{place}"
            );
            fs::remove_dir_all(&dir).ok();
        }
        // A folder by that name, or the name somewhere it is not served from, is not one.
        for place in ["SECURITY/notes.txt", "src/security.txt", "security.py"] {
            let dir = scratch("security-not");
            let path = dir.join(place);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, "x").unwrap();
            assert!(
                check_dir(&dir)
                    .findings
                    .iter()
                    .any(|f| f.rule_id == "config.security-contact"),
                "{place}"
            );
            fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn a_wildcard_env_entry_counts() {
        let dir = scratch("wildcard");
        for pattern in [".env*", "*.env", "**/.env", "/.env", ".env\n.env.*"] {
            fs::write(dir.join(".gitignore"), format!("{pattern}\n")).unwrap();
            assert!(
                check_dir(&dir)
                    .passed
                    .iter()
                    .any(|p| p.check_id == "config.gitignore-covers-env"),
                "{pattern} should count as covering .env"
            );
        }
        // `.env.*` alone needs a dot after `env`, so git still commits the file called `.env`.
        // Until 5 October 2026 this was counted as covering it.
        fs::write(dir.join(".gitignore"), ".env.*\n").unwrap();
        assert!(
            check_dir(&dir)
                .findings
                .iter()
                .any(|f| f.rule_id == "config.gitignore-covers-env")
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_ecosystem_with_no_lockfile_is_reported() {
        let dir = scratch("nolock");
        fs::write(dir.join("package.json"), "{\"name\":\"x\"}").unwrap();
        let report = check_dir(&dir);
        let f = report
            .findings
            .iter()
            .find(|f| f.rule_id == "config.versions-pinned")
            .unwrap_or_else(|| panic!("{report:?}"));
        assert_eq!(f.severity, Severity::Medium);
        assert!(f.title.contains("npm"), "{}", f.title);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_ecosystem_with_a_lockfile_passes() {
        // A lockfile with a package in it. This used `{}`, which is the case a lockfile nobody can
        // read anything from, and which now leaves the question open instead of passing it.
        let dir = scratch("locked");
        fs::write(dir.join("package.json"), "{\"name\":\"x\"}").unwrap();
        fs::write(
            dir.join("package-lock.json"),
            r#"{"packages":{"":{"name":"x"},"node_modules/express":{"version":"4.19.2"}}}"#,
        )
        .unwrap();
        assert!(
            check_dir(&dir)
                .passed
                .iter()
                .any(|p| p.check_id == "config.versions-pinned")
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn maven_is_not_reported_as_pinning_nothing() {
        // The trap. Maven has no lockfile to be missing — versions are in pom.xml — so asking "is there
        // a lockfile?" reports every Maven project as unpinned. That is a wrong statement in a report,
        // not a coverage gap, and it is what v1's ADR-012 is about.
        let dir = scratch("maven");
        fs::write(
            dir.join("pom.xml"),
            "<project><artifactId>x</artifactId></project>",
        )
        .unwrap();
        let report = check_dir(&dir);
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule_id == "config.versions-pinned"),
            "Maven was reported as unpinned: {report:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn maven_is_an_open_question_when_a_version_cannot_be_worked_out() {
        // The other half, and a different assertion: not reporting it must not mean approving it. A
        // version held in a property from a parent outside the folder is one `sv` cannot see.
        let dir = scratch("maven2");
        fs::write(
            dir.join("pom.xml"),
            "<project><parent><groupId>com.acme</groupId><artifactId>base</artifactId>\
             <version>3</version><relativePath/></parent><artifactId>x</artifactId><dependencies>\
             <dependency><groupId>org.x</groupId><artifactId>y</artifactId>\
             <version>${y.version}</version></dependency></dependencies></project>",
        )
        .unwrap();
        let report = check_dir(&dir);
        assert!(
            !report
                .passed
                .iter()
                .any(|p| p.check_id == "config.versions-pinned"),
            "Maven must not pass a check nothing performed: {report:?}"
        );
        let (_, why) = report
            .not_assessed
            .iter()
            .find(|(id, _)| id == "config.versions-pinned")
            .unwrap_or_else(|| panic!("{report:?}"));
        assert!(
            why.contains("${y.version}") && why.contains("org.x:y"),
            "{why}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    fn pinned_outcome(dir: &std::path::Path) -> (bool, Option<Finding>, Option<String>) {
        let report = check_dir(dir);
        (
            report
                .passed
                .iter()
                .any(|p| p.check_id == "config.versions-pinned"),
            report
                .findings
                .into_iter()
                .find(|f| f.rule_id == "config.versions-pinned"),
            report
                .not_assessed
                .into_iter()
                .find(|(id, _)| id == "config.versions-pinned")
                .map(|(_, why)| why),
        )
    }

    #[test]
    fn maven_with_exact_versions_passes() {
        // A Spring Boot app as Spring Initializr writes it: the parent is exact, the starters take
        // their versions from it, and one library's version is a property set in the same file.
        let dir = scratch("maven-exact");
        fs::write(
            dir.join("pom.xml"),
            "<project>\n<parent><groupId>org.springframework.boot</groupId>\
             <artifactId>spring-boot-starter-parent</artifactId><version>3.3.4</version></parent>\n\
             <properties><jjwt.version>0.12.6</jjwt.version></properties>\n<dependencies>\n\
             <dependency><groupId>org.springframework.boot</groupId>\
             <artifactId>spring-boot-starter-web</artifactId></dependency>\n\
             <dependency><groupId>io.jsonwebtoken</groupId><artifactId>jjwt-api</artifactId>\
             <version>${jjwt.version}</version></dependency>\n</dependencies></project>",
        )
        .unwrap();
        let (passed, finding, open) = pinned_outcome(&dir);
        assert!(
            passed && finding.is_none() && open.is_none(),
            "{finding:?} {open:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_maven_range_is_a_finding_at_its_line() {
        let dir = scratch("maven-range");
        fs::write(
            dir.join("pom.xml"),
            "<project>\n<artifactId>x</artifactId>\n<dependencies>\n<dependency>\n\
             <groupId>org.x</groupId><artifactId>y</artifactId>\n<version>[1.0,2.0)</version>\n\
             </dependency>\n</dependencies></project>",
        )
        .unwrap();
        let (passed, finding, _) = pinned_outcome(&dir);
        let f = finding.expect("a range floats");
        assert!(!passed);
        assert_eq!((f.location.file.as_str(), f.location.line), ("pom.xml", 6));
        assert!(f.title.contains("Maven"), "{}", f.title);
        assert!(
            f.description.contains("org.x:y") && f.description.contains("[1.0,2.0)"),
            "{}",
            f.description
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_snapshot_is_a_finding() {
        // A snapshot is republished under the same version number, so it floats like a range.
        let dir = scratch("maven-snapshot");
        fs::write(
            dir.join("pom.xml"),
            "<project><artifactId>x</artifactId><dependencies><dependency><groupId>org.x</groupId>\
             <artifactId>y</artifactId><version>2.1-SNAPSHOT</version></dependency></dependencies>\
             </project>",
        )
        .unwrap();
        let (passed, finding, _) = pinned_outcome(&dir);
        let f = finding.expect("a snapshot floats");
        assert!(!passed);
        assert!(f.description.contains("snapshot"), "{}", f.description);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn gradle_without_a_lockfile_is_not_reported_when_every_version_is_exact() {
        // The wrong statement this replaced: Gradle's lockfile is optional, and a build that names
        // exact versions installs the same thing every time without one.
        let dir = scratch("gradle-exact");
        fs::write(
            dir.join("build.gradle"),
            "plugins { id 'java' }\ndependencies {\n    implementation 'com.google.guava:guava:33.3.1-jre'\n    testImplementation(\"org.junit.jupiter:junit-jupiter:5.11.2\")\n}\n",
        )
        .unwrap();
        let (passed, finding, open) = pinned_outcome(&dir);
        assert!(
            passed && finding.is_none() && open.is_none(),
            "{finding:?} {open:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_gradle_dynamic_version_is_a_finding_unless_a_lockfile_pins_it() {
        let dir = scratch("gradle-plus");
        fs::write(
            dir.join("build.gradle.kts"),
            "dependencies {\n    implementation(\"com.google.guava:guava:33.+\")\n}\n",
        )
        .unwrap();
        let (_, finding, _) = pinned_outcome(&dir);
        let f = finding.expect("a `+` floats");
        assert_eq!(
            (f.location.file.as_str(), f.location.line),
            ("build.gradle.kts", 2)
        );
        assert!(f.fix.contains("gradle.lockfile"), "{}", f.fix);

        fs::write(
            dir.join("gradle.lockfile"),
            "com.google.guava:guava:33.3.1-jre=compileClasspath\n",
        )
        .unwrap();
        let (passed, finding, _) = pinned_outcome(&dir);
        assert!(passed && finding.is_none(), "{finding:?}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_folder_with_no_manifest_is_not_assessed() {
        let dir = scratch("nomanifest");
        fs::write(dir.join("README.md"), "hello\n").unwrap();
        let report = check_dir(&dir);
        assert!(
            !report
                .passed
                .iter()
                .any(|p| p.check_id == "config.versions-pinned")
        );
        assert!(
            report
                .not_assessed
                .iter()
                .any(|(id, _)| id == "config.versions-pinned")
        );
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
                .iter()
                .any(|p| p.check_id == "config.security-contact")
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn nothing_is_both_passed_and_found() {
        let dir = scratch("disjoint");
        fs::write(dir.join(".gitignore"), ".env\n").unwrap();
        let report = check_dir(&dir);
        for passed in &report.passed {
            let id = &passed.check_id;
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

#[cfg(test)]
mod passed_evidence_tests {
    use super::*;

    #[test]
    fn a_check_that_names_requirements_when_it_fails_names_them_when_it_passes_too() {
        // The asymmetry this guards against is invisible from either side on its own: the failing
        // branch cites V13.3.1, the passing branch cited nothing, and a report built from that can
        // only ever say a requirement needs attention — never that anything looked and was
        // satisfied. Every requirement then reads as unchecked however many checks ran.
        let dir = tempdir("passed-cites");
        std::fs::write(dir.join(".gitignore"), ".env\n").unwrap();
        std::fs::write(dir.join("SECURITY.md"), "mail security@example.test\n").unwrap();
        let report = check_dir(&dir);
        std::fs::remove_dir_all(&dir).ok();

        assert!(!report.passed.is_empty(), "nothing passed: {report:?}");

        // A check may honestly be evidence about no requirement in any loaded framework, and one
        // is: nothing in ASVS, AISVS or Appendix C asks for a way to report a vulnerability. That
        // has to be a decision somebody wrote down, not a forgotten field, so it is listed here
        // and every other check has to say what it is evidence about. The five after it can only
        // ever show their requirement failing (a start command the files do not show, a pinned
        // version that is not a cryptographic check, a sanitizer that may clean another field, a
        // grant switched on in a database rather than a file, a model downloaded when the app
        // runs), so a clean reading of them is evidence about nothing, on purpose.
        const CITES_NOTHING_ON_PURPOSE: &[&str] = &[
            "config.security-contact",
            crate::launch::DEV_SERVER,
            crate::launch::MCP_UNPINNED,
            crate::rich_text::RICH_TEXT,
            crate::grants::RETIRED_GRANT,
            crate::model_files::PICKLE_MODEL,
        ];
        let silent: Vec<&str> = report
            .passed
            .iter()
            .filter(|p| p.requirement_ids.is_empty())
            .map(|p| p.check_id.as_str())
            .filter(|id| !CITES_NOTHING_ON_PURPOSE.contains(id))
            .collect();
        assert!(
            silent.is_empty(),
            "these checks pass without saying what they are evidence about: {silent:?}"
        );
    }

    #[test]
    fn the_ids_a_check_cites_are_the_same_whichever_way_it_goes() {
        // Second witness, of a different shape: not that the passing side says *something*, but
        // that it says the *same* thing. A pass citing a requirement its failure does not would
        // credit a requirement nothing actually examined.
        let clean = tempdir("same-ids-clean");
        std::fs::write(clean.join(".gitignore"), ".env\n").unwrap();
        let passed = check_dir(&clean);
        std::fs::remove_dir_all(&clean).ok();

        let dirty = tempdir("same-ids-dirty");
        std::fs::write(dirty.join(".gitignore"), "node_modules\n").unwrap();
        let failed = check_dir(&dirty);
        std::fs::remove_dir_all(&dirty).ok();

        let on_pass: Vec<String> = passed
            .passed
            .iter()
            .find(|p| p.check_id == "config.gitignore-covers-env")
            .map(|p| p.requirement_ids.clone())
            .expect("the clean app passes this check");
        let on_fail: Vec<String> = failed
            .findings
            .iter()
            .find(|f| f.rule_id == "config.gitignore-covers-env")
            .map(|f| f.requirement_ids.clone())
            .expect("the dirty app fails this check");
        assert_eq!(on_pass, on_fail);
    }

    fn tempdir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sv-config-cites-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
