//! Which package ecosystems and languages an application actually uses.
//!
//! A port of v1's `server/src/scanners/ecosystems.ts`, whose header says the thing worth keeping:
//! SecureVibe once told a Flask app it was missing a `package-lock.json` and marked it down for not
//! setting `ignore-scripts` in an `.npmrc` it had no reason to own. Those were not coverage gaps,
//! which are honest and visible — they were wrong statements in a report, and an owner acting on
//! them would have added npm configuration to a Python application.

use std::collections::BTreeSet;
use std::path::Path;

pub struct EcosystemDef {
    /// What a person calls it.
    pub name: &'static str,
    /// The file whose presence says this ecosystem is in use.
    pub manifest: &'static str,
    /// Files that pin exact versions. An ecosystem in use with none of these present means nobody
    /// can say what is actually installed — worth reporting in its own right, in any language. A
    /// `*` stands for a part of the name that varies (`pylock.*.toml`), and is never empty.
    pub lockfiles: &'static [&'static str],
}

pub const ECOSYSTEMS: &[EcosystemDef] = &[
    EcosystemDef {
        name: "npm",
        manifest: "package.json",
        lockfiles: &[
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            // Bun's lockfile: text since Bun 1.2, binary (`bun.lockb`) before it. Both pin; left out,
            // every Bun app was told it had no lockfile, which was untrue.
            "bun.lock",
            "bun.lockb",
        ],
    },
    EcosystemDef {
        name: "Python",
        manifest: "requirements.txt",
        // `pylock.toml` is PEP 751's lockfile, which pip writes (`pip lock`); a project may name one
        // per environment, `pylock.<name>.toml`. A `requirements.txt` with every package pinned and
        // hashed is a lock in its own right; `detect_in` says so when nothing here is present.
        lockfiles: &[
            "poetry.lock",
            "Pipfile.lock",
            "pylock.toml",
            "pylock.*.toml",
            "requirements.lock",
        ],
    },
    EcosystemDef {
        name: "Python",
        manifest: "pyproject.toml",
        // `requirements.lock` is what `uv pip compile pyproject.toml -o requirements.lock` writes, and
        // the name Rye uses. Left out, such a project was told it had no lockfile and listed no
        // packages. It comes last: when a tool's own lockfile is there too, that one is read.
        lockfiles: &[
            "poetry.lock",
            "pdm.lock",
            "uv.lock",
            "pylock.toml",
            "pylock.*.toml",
            "requirements.lock",
        ],
    },
    EcosystemDef {
        name: "Go",
        manifest: "go.mod",
        lockfiles: &["go.sum"],
    },
    EcosystemDef {
        name: "Rust",
        manifest: "Cargo.toml",
        lockfiles: &["Cargo.lock"],
    },
    EcosystemDef {
        name: "Ruby",
        manifest: "Gemfile",
        lockfiles: &["Gemfile.lock"],
    },
    EcosystemDef {
        name: "PHP",
        manifest: "composer.json",
        lockfiles: &["composer.lock"],
    },
    EcosystemDef {
        name: "Java (Maven)",
        manifest: "pom.xml",
        lockfiles: &[],
    },
    EcosystemDef {
        name: "Java (Gradle)",
        manifest: "build.gradle",
        lockfiles: &["gradle.lockfile"],
    },
    // The Kotlin DSL, which is what `gradle init` and Spring Initializr write for a Kotlin project.
    // Not listing it left every such app with no dependencies read at all.
    EcosystemDef {
        name: "Java (Gradle)",
        manifest: "build.gradle.kts",
        lockfiles: &["gradle.lockfile"],
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedEcosystem {
    pub name: String,
    /// The manifest's path from the app folder, with `/` separators: `package.json`, or
    /// `server/package.json` for a project that is not at the top.
    pub manifest: String,
    /// The lockfile found, when one was, as a path from the app folder. It sits beside the manifest,
    /// or at the root of a workspace the manifest belongs to.
    pub lockfile: Option<String>,
    /// Other lockfiles of the same kind in the folder `lockfile` came from, which were not read.
    ///
    /// `package-lock.json` beside a `yarn.lock`, or `uv.lock` beside a `requirements.lock`: one is
    /// read, in the order the ecosystem lists them, and the rest are named here, because two
    /// lockfiles can disagree and a report that described one of them without saying so would
    /// leave the owner no way to tell which versions it was about.
    pub passed_over: Vec<String>,
    /// Whether this ecosystem pins versions with a lockfile at all.
    ///
    /// Maven does not: versions live in `pom.xml` and there is no lockfile to look for. Without this
    /// flag `unpinned` reported every Maven project as pinning nothing, which is not a coverage gap
    /// but a wrong statement in a report — the thing v1's ADR-012 exists to stop. A caller that wants to
    /// say "this app pins nothing" asks `pinning`, which reads Maven's versions instead.
    pub pins_with_lockfile: bool,
}

impl DetectedEcosystem {
    /// How to name this project to a person: `npm`, or `npm in server/` when it is not at the top.
    /// Two projects of the same kind otherwise read as "npm and npm".
    pub fn label(&self) -> String {
        match self.manifest.rsplit_once('/') {
            Some((dir, _)) => format!("{} in {dir}/", self.name),
            None => self.name.clone(),
        }
    }
}

/// The file name at the end of a path from `detect`, which is what decides how it is read.
pub fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Every project in the app folder, wherever it sits, root first.
///
/// Walks the whole tree rather than looking at the top only. An app written as `client/` and
/// `server/` — the usual shape of a full-stack app from an AI builder — has no manifest at the top,
/// and looking only there read none of its dependencies: every technology condition fell back to
/// source patterns, and the pinning check said there was nothing to pin. Installed dependencies and
/// build output are skipped (`SKIP_DIRS`), because a `package.json` inside `node_modules` belongs to
/// somebody else's project.
pub fn detect(app_dir: &Path) -> Vec<DetectedEcosystem> {
    detect_in(&crate::files::Listing::of(app_dir))
}

/// `detect`, from a listing already made. The bill of materials, the dependency reader, and the
/// pinning check all come through here, and each used to walk the folder again for it.
pub fn detect_in(listing: &crate::files::Listing) -> Vec<DetectedEcosystem> {
    let app_dir = listing.root.as_path();
    let mut dirs: Vec<String> = ECOSYSTEMS
        .iter()
        .flat_map(|e| listing.dirs_holding(e.manifest))
        .collect();
    dirs.sort();
    dirs.dedup();
    // Root first, then by depth and path, so "the first manifest" in a message is the one a reader
    // would look at first.
    dirs.sort_by(|a, b| {
        a.matches('/')
            .count()
            .cmp(&b.matches('/').count())
            .then_with(|| a.is_empty().cmp(&b.is_empty()).reverse())
            .then_with(|| a.cmp(b))
    });
    let mut out = Vec::new();
    for rel_dir in &dirs {
        let dir = if rel_dir.is_empty() {
            app_dir.to_path_buf()
        } else {
            app_dir.join(rel_dir)
        };
        for eco in ECOSYSTEMS {
            if !dir.join(eco.manifest).exists() {
                continue;
            }
            let lockfile = find_lockfile(app_dir, rel_dir, eco.lockfiles).or_else(|| {
                // A requirements.txt that pins and hashes every package lists everything pip will
                // install: under `--require-hashes` it refuses anything else.
                (eco.manifest == "requirements.txt"
                    && std::fs::read_to_string(dir.join(eco.manifest))
                        .is_ok_and(|text| fully_hash_pinned(&text)))
                .then(|| join(rel_dir, eco.manifest))
            });
            let passed_over = lockfile
                .as_deref()
                .map(|found| others_beside(app_dir, found, eco.lockfiles))
                .unwrap_or_default();
            out.push(DetectedEcosystem {
                name: eco.name.to_owned(),
                manifest: join(rel_dir, eco.manifest),
                lockfile,
                passed_over,
                pins_with_lockfile: !eco.lockfiles.is_empty(),
            });
        }
    }
    out
}

fn join(rel_dir: &str, name: &str) -> String {
    if rel_dir.is_empty() {
        name.to_owned()
    } else {
        format!("{rel_dir}/{name}")
    }
}

/// The lockfile that pins a project: beside its manifest, or at the root of a workspace that lists it.
///
/// A lockfile further up only counts when that folder is a workspace root *and* its member list
/// covers this project. npm, pnpm, Yarn, Cargo and uv keep one lockfile at the workspace root for
/// every member — and a lockfile at the top of a repository pins nothing in a project the workspace
/// does not list, or in an unrelated `server/` beside a plain root project. Calling either pinned
/// would be a wrong statement in a report, in the direction that hides something, so a member list
/// that cannot be read counts as not listing it.
fn find_lockfile(app_dir: &Path, rel_dir: &str, lockfiles: &[&str]) -> Option<String> {
    let beside = lockfiles
        .iter()
        .find_map(|f| present(&app_dir.join(rel_dir), f).into_iter().next())
        .map(|f| join(rel_dir, &f));
    if beside.is_some() {
        return beside;
    }
    let mut rel = rel_dir.to_owned();
    while !rel.is_empty() {
        let parent = rel
            .rsplit_once('/')
            .map_or(String::new(), |(head, _)| head.to_owned());
        let root = if parent.is_empty() {
            app_dir.to_path_buf()
        } else {
            app_dir.join(&parent)
        };
        let below = rel_dir
            .strip_prefix(&parent)
            .unwrap_or(rel_dir)
            .trim_start_matches('/');
        if workspace_members(&root)
            .is_some_and(|members| members.iter().any(|m| glob_matches(m, below)))
            && let Some(found) = lockfiles
                .iter()
                .find_map(|f| present(&root, f).into_iter().next())
        {
            return Some(join(&parent, &found));
        }
        rel = parent;
    }
    None
}

/// The lockfiles of the same kind that sit in the same folder as `found` and were not read.
fn others_beside(app_dir: &Path, found: &str, lockfiles: &[&str]) -> Vec<String> {
    let dir = found.rsplit_once('/').map_or("", |(head, _)| head);
    let mut out: Vec<String> = lockfiles
        .iter()
        .flat_map(|f| present(&app_dir.join(dir), f))
        .map(|f| join(dir, &f))
        .filter(|path| path != found)
        .collect();
    out.dedup();
    out
}

/// The files in `dir` a lockfile name stands for, sorted: the name itself when it is there, or,
/// for a name with a `*`, every file it matches, with something in the place of the `*`.
fn present(dir: &Path, name: &str) -> Vec<String> {
    let Some((before, after)) = name.split_once('*') else {
        return if dir.join(name).is_file() {
            vec![name.to_owned()]
        } else {
            Vec::new()
        };
    };
    let mut found: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|f| {
            f.len() > before.len() + after.len() && f.starts_with(before) && f.ends_with(after)
        })
        .collect();
    found.sort();
    found
}

/// Whether a requirements file pins and hashes every package it installs, so it can stand as a
/// lockfile: every requirement `name==version` (no wildcard) with at least one `--hash`, at least
/// one requirement, and nothing that installs from elsewhere (`-r`, `-e`, a path, or an address).
/// Lines that only set where pip looks, or that ask for hashes, are allowed beside them.
pub fn fully_hash_pinned(text: &str) -> bool {
    const SETTINGS: &[&str] = &[
        "--require-hashes",
        "--index-url",
        "--extra-index-url",
        "-i",
        "--trusted-host",
        "--find-links",
        "-f",
        "--no-index",
        "--prefer-binary",
        "--only-binary",
        "--no-binary",
        "--pre",
    ];
    // One requirement per logical line: a `\` at the end joins the next one on.
    let mut logical = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        let line = line.split_once(" #").map_or(line, |(code, _)| code);
        let line = if line.trim_start().starts_with('#') {
            ""
        } else {
            line
        };
        match line.trim_end().strip_suffix('\\') {
            Some(head) => {
                current.push_str(head);
                current.push(' ');
            }
            None => {
                current.push_str(line);
                logical.push(std::mem::take(&mut current));
            }
        }
    }
    logical.push(current);
    let mut requirements = 0;
    for line in logical.iter().map(|l| l.trim()).filter(|l| !l.is_empty()) {
        if line.starts_with('-') {
            let option = line.split([' ', '=']).next().unwrap_or(line);
            if SETTINGS.contains(&option) {
                continue;
            }
            return false;
        }
        let (requirement, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        let requirement = requirement.split(';').next().unwrap_or(requirement);
        let Some((name, version)) = requirement.split_once("==") else {
            return false;
        };
        let version = version.trim_start_matches('=');
        let name_ok = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-[],".contains(c));
        let version_ok = !version.is_empty() && !version.contains('*');
        let hashed = rest
            .split_whitespace()
            .any(|t| t.starts_with("--hash=") || t == "--hash");
        if !(name_ok && version_ok && hashed) {
            return false;
        }
        requirements += 1;
    }
    requirements > 0
}

/// The member patterns a workspace root declares, when the folder is one.
fn workspace_members(dir: &Path) -> Option<Vec<String>> {
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).ok();
    // npm and Yarn: `"workspaces": [...]` or `"workspaces": {"packages": [...]}`.
    if let Some(text) = read("package.json")
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&text)
        && let Some(w) = v.get("workspaces")
    {
        let list = w
            .as_array()
            .or_else(|| w.get("packages").and_then(|p| p.as_array()));
        return list.map(|l| {
            l.iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect()
        });
    }
    // pnpm: `packages:` followed by `- pattern` lines.
    if let Some(text) = read("pnpm-workspace.yaml") {
        return Some(
            text.lines()
                .map(str::trim)
                .filter_map(|l| l.strip_prefix("- "))
                .map(|p| p.trim().trim_matches(['"', '\'']).to_owned())
                .filter(|p| !p.starts_with('!'))
                .collect(),
        );
    }
    // Cargo `[workspace]` and uv `[tool.uv.workspace]`: a `members = [...]` array in that table.
    for (file, table) in [
        ("Cargo.toml", "workspace"),
        ("pyproject.toml", "tool.uv.workspace"),
    ] {
        if let Some(text) = read(file)
            && let Ok(v) = text.parse::<toml::Table>()
        {
            let mut node = Some(&v);
            for key in table.split('.') {
                node = node.and_then(|n| n.get(key)).and_then(|n| n.as_table());
            }
            if let Some(ws) = node {
                return Some(
                    ws.get("members")
                        .and_then(|m| m.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(str::to_owned))
                                .collect()
                        })
                        .unwrap_or_default(),
                );
            }
        }
    }
    None
}

/// A workspace member pattern against a path below the workspace root: `*` is one folder name,
/// `**` any number of them. That is all the workspace formats use.
fn glob_matches(pattern: &str, path: &str) -> bool {
    fn go(p: &[&str], s: &[&str]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(&"**"), _) => go(&p[1..], s) || (!s.is_empty() && go(p, &s[1..])),
            (Some(pp), Some(ss)) => segment(pp, ss) && go(&p[1..], &s[1..]),
            _ => false,
        }
    }
    fn segment(p: &str, s: &str) -> bool {
        match p.split_once('*') {
            None => p == s,
            Some((pre, post)) => {
                s.len() >= pre.len() + post.len() && s.starts_with(pre) && s.ends_with(post)
            }
        }
    }
    let pattern = pattern.trim_start_matches("./").trim_end_matches('/');
    let p: Vec<&str> = pattern.split('/').filter(|x| !x.is_empty()).collect();
    let s: Vec<&str> = path.split('/').filter(|x| !x.is_empty()).collect();
    go(&p, &s)
}

/// Whether one project pins what it installs, and how `sv` knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pinning {
    /// A lockfile pins it: the lockfile's path from the app folder.
    Lockfile(String),
    /// No lockfile, and every version the build names is exact, or given by something that is.
    /// Maven always, and Gradle without `gradle.lockfile`; see `jvm`.
    Exact,
    /// An ecosystem that pins with a lockfile, without one.
    NoLockfile,
    /// Versions that move: the build takes whatever is newest when it runs.
    Floating(Vec<crate::jvm::VersionAt>),
    /// Versions `sv` could not settle from the files, and nothing floating beside them.
    Unsettled(Vec<crate::jvm::VersionAt>),
}

impl Pinning {
    /// Whether this is a statement that the project does not pin what it installs.
    pub fn is_unpinned(&self) -> bool {
        matches!(self, Pinning::NoLockfile | Pinning::Floating(_))
    }
}

/// How one detected project pins what it installs.
///
/// A lockfile settles it. Without one, Maven and Gradle are read for their versions, because
/// neither needs a lockfile to install the same thing every time; every other ecosystem without
/// its lockfile pins nothing.
pub fn pinning(app_dir: &Path, eco: &DetectedEcosystem) -> Pinning {
    if let Some(lockfile) = &eco.lockfile {
        return Pinning::Lockfile(lockfile.clone());
    }
    let reading = match file_name(&eco.manifest) {
        "pom.xml" => crate::jvm::read_pom(app_dir, &eco.manifest),
        "build.gradle" | "build.gradle.kts" => crate::jvm::read_gradle(app_dir, &eco.manifest),
        _ if eco.pins_with_lockfile => return Pinning::NoLockfile,
        _ => None,
    };
    match reading {
        None => Pinning::Unsettled(vec![crate::jvm::VersionAt {
            manifest: eco.manifest.clone(),
            line: 1,
            dependency: eco.manifest.clone(),
            version: String::new(),
            why: "the file could not be read".to_owned(),
        }]),
        Some(r) if !r.floating.is_empty() => Pinning::Floating(r.floating),
        Some(r) if !r.unsettled.is_empty() => Pinning::Unsettled(r.unsettled),
        Some(_) => Pinning::Exact,
    }
}

/// Ecosystems in use that do not pin what they install, so what is actually installed cannot be
/// known: a lockfile missing where one is used, or a Maven or Gradle version that floats.
///
/// Maven has no lockfile to be missing and Gradle's is optional, so for both the versions are read
/// instead; reporting either for the missing file alone would be a wrong statement, not a finding.
pub fn unpinned(app_dir: &Path) -> Vec<DetectedEcosystem> {
    unpinned_in(&crate::files::Listing::of(app_dir))
}

/// `unpinned`, from a listing already made.
pub fn unpinned_in(listing: &crate::files::Listing) -> Vec<DetectedEcosystem> {
    detect_in(listing)
        .into_iter()
        .filter(|e| pinning(&listing.root, e).is_unpinned())
        .collect()
}

/// Ecosystems in use whose pinning `sv` could not settle: a Maven or Gradle version it could not
/// work out, with nothing floating beside it.
pub fn pinning_unknown(app_dir: &Path) -> Vec<DetectedEcosystem> {
    detect(app_dir)
        .into_iter()
        .filter(|e| matches!(pinning(app_dir, e), Pinning::Unsettled(_)))
        .collect()
}

/// The languages `sv` can read, keyed by file extension. A language absent from this table is one
/// whose files are counted as unread, which is what keeps the coverage rule honest.
pub fn language_of(extension: &str) -> Option<&'static str> {
    Some(match extension {
        "js" | "jsx" | "mjs" | "cjs" => "javascript",
        "ts" | "tsx" | "mts" | "cts" => "typescript",
        "py" | "pyi" => "python",
        "java" => "java",
        "kt" | "kts" => "kotlin",
        "go" => "go",
        "rs" => "rust",
        "rb" => "ruby",
        "php" => "php",
        "cs" => "csharp",
        "c" | "h" => "c",
        "dart" => "dart",
        "swift" => "swift",
        "sh" | "bash" => "shell",
        "cc" | "cpp" | "cxx" | "hpp" | "hh" => "cpp",
        // Recognized so an app written in it is not silently skipped, and deliberately left without a
        // grammar in ast.rs: the language sv-check's own tests use to prove that combination still
        // behaves. Whoever gives it a grammar moves those tests to the next one without.
        "m" | "mm" => "objc",
        "html" | "htm" | "vue" | "svelte" => "html",
        _ => return None,
    })
}

/// Languages the code rules read that the technology scan does not: none of their dependency files
/// (`pubspec.yaml`, `Package.swift`) is read, and no signature has a source pattern for them. Their
/// files count as not looked in, so a technology is never called absent on their account.
///
/// Shell is read by the code rules and deliberately not listed. Before it had a grammar a `.sh` file
/// was invisible to this scan, which drew its conclusions without it; listing it would take every
/// "this app does not use X" answer away from any app with one deploy script, to cover a technology
/// written only in shell, which is rare. The price is stated in DESIGN rather than paid silently.
pub const NO_TECHNOLOGY_READER: &[&str] = &["dart", "swift"];

/// Directories never worth walking: installed dependencies, build output, version control. Their
/// contents belong to the dependency scan, not to the app's own source.
pub const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "out",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".nuxt",
    ".tox",
    "site-packages",
    ".gradle",
    ".mypy_cache",
    ".pytest_cache",
    "coverage",
    ".idea",
    ".vscode",
    // Where `sv report` writes by default. Any other folder it writes to carries REPORT_MARKER.
    "securevibe-report",
];

/// Editor settings, in `SKIP_DIRS` for every walk of the app's code, and not for the credential scan:
/// a `.vscode/settings.json` can hold a token as easily as any other file.
pub const EDITOR_DIRS: &[&str] = &[".idea", ".vscode"];

/// Written by `sv report` into every folder it writes a report to, so no walk of the app reads the
/// report as the app's own code. Found in the owner's first build (26 September 2026): the report was
/// read back as part of the app, and while a page no code rule could fully read was there, nothing was
/// claimed, so the requirements checked fell from 9 to 1. A folder name alone does not do it, since
/// `--out` takes any name.
pub const REPORT_MARKER: &str = ".securevibe-report";

/// Whether a walk of the app should leave this folder out: installed dependencies, build output,
/// version control, editor settings, or a report `sv` wrote.
pub fn skip_dir(dir: &Path) -> bool {
    let name = dir
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    SKIP_DIRS.contains(&name.as_ref()) || is_sv_output(dir)
}

/// A folder `sv report` wrote.
pub fn is_sv_output(dir: &Path) -> bool {
    dir.join(REPORT_MARKER).is_file()
}

/// Every language whose files appear in the app, from the extensions actually seen.
pub fn languages_present(files: &[(String, String)]) -> BTreeSet<String> {
    files.iter().map(|(lang, _)| lang.clone()).collect()
}
