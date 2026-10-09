//! Which package ecosystems and languages an application actually uses.
//!
//! A port of v1's `server/src/scanners/ecosystems.ts`, whose header says the thing worth keeping:
//! StackVet once told a Flask app it was missing a `package-lock.json` and marked it down for not
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
    // Pipenv's own pair. Left out, an app with only `Pipfile` and `Pipfile.lock` had no Python at
    // all as far as `sv` could tell: its packages were never compared with an advisory, and the
    // comparison of everything else was credited as covering the app (deep review H9).
    EcosystemDef {
        name: "Python",
        manifest: "Pipfile",
        lockfiles: &["Pipfile.lock"],
    },
    // A `Pipfile.lock` with no `Pipfile` beside it, which `pipenv sync` and `pipenv install
    // --ignore-pipfile` install from alone. It stands as its own manifest, and only where nothing
    // in its folder above already reads it as a lockfile (`detect_in`): beside a `requirements.txt`
    // or a `Pipfile` it is theirs. Left out, an app shipped with the lockfile alone had no Python
    // as far as `sv` could tell (deep review H9, the part left open on 5 October 2026).
    EcosystemDef {
        name: "Python",
        manifest: "Pipfile.lock",
        lockfiles: &["Pipfile.lock"],
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

/// An ecosystem whose dependency files `sv` does not read (gap analysis, item 2): found, so that its
/// packages are named as unread rather than absent.
pub struct UnreadEcosystemDef {
    /// What a person calls it.
    pub name: &'static str,
    /// The files that declare its dependencies. A `*` stands for a part of the name that varies
    /// (`*.csproj`), and is never empty.
    pub manifests: &'static [&'static str],
    /// Its own lockfiles, named in the message when one is beside a manifest.
    pub lockfiles: &'static [&'static str],
}

/// Before these were found, a .NET app was told "No package manifest was found", and a mixed app had
/// V15.2.1 credited on its npm half while an old Newtonsoft.Json sat pinned in its `.csproj`.
pub const UNREAD_ECOSYSTEMS: &[UnreadEcosystemDef] = &[
    UnreadEcosystemDef {
        name: ".NET (NuGet)",
        manifests: &[
            "*.csproj",
            "*.fsproj",
            "*.vbproj",
            "packages.config",
            "Directory.Packages.props",
        ],
        lockfiles: &["packages.lock.json"],
    },
    UnreadEcosystemDef {
        name: "Dart (pub)",
        manifests: &["pubspec.yaml"],
        lockfiles: &["pubspec.lock"],
    },
    UnreadEcosystemDef {
        name: "Swift (Swift Package Manager)",
        manifests: &["Package.swift"],
        lockfiles: &["Package.resolved"],
    },
    UnreadEcosystemDef {
        name: "Elixir (Mix)",
        manifests: &["mix.exs"],
        lockfiles: &["mix.lock"],
    },
    UnreadEcosystemDef {
        name: "Deno",
        manifests: &["deno.json", "deno.jsonc"],
        lockfiles: &["deno.lock"],
    },
];

/// One file declaring dependencies `sv` does not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadDeclaration {
    /// The ecosystem's name, as `UNREAD_ECOSYSTEMS` gives it.
    pub name: &'static str,
    /// The file, as a path from the app folder.
    pub path: String,
    /// Its ecosystem's lockfile beside it, when there is one.
    pub lockfile: Option<String>,
}

/// Whether a file name matches a pattern with at most one `*`, which stands for at least one
/// character.
fn name_matches(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((head, tail)) => {
            name.len() > head.len() + tail.len() && name.starts_with(head) && name.ends_with(tail)
        }
    }
}

/// Every file in the app that declares dependencies in an ecosystem `sv` does not read, in path
/// order.
pub fn unread_declarations_in(listing: &crate::files::Listing) -> Vec<UnreadDeclaration> {
    let names: BTreeSet<&str> = listing.app_files().map(|f| f.relative.as_str()).collect();
    let mut out = Vec::new();
    for file in listing.app_files() {
        let name = file.file_name();
        let Some(eco) = UNREAD_ECOSYSTEMS
            .iter()
            .find(|e| e.manifests.iter().any(|m| name_matches(m, name)))
        else {
            continue;
        };
        let dir = file.relative.rsplit_once('/').map_or("", |(dir, _)| dir);
        let lockfile = eco
            .lockfiles
            .iter()
            .map(|l| join(dir, l))
            .find(|l| names.contains(l.as_str()));
        out.push(UnreadDeclaration {
            name: eco.name,
            path: file.relative.clone(),
            lockfile,
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

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
            if !dir.join(eco.manifest).exists() || read_as_lockfile_beside(&dir, eco) {
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

/// Whether `eco` is a lockfile standing as its own manifest (`Pipfile.lock` alone) and another
/// manifest of the same kind in `dir` already lists it as a lockfile, so that project reads it.
/// Counted twice, the same packages would be listed under two projects, and one of them named a
/// manifest that is not there.
fn read_as_lockfile_beside(dir: &Path, eco: &EcosystemDef) -> bool {
    eco.lockfiles.contains(&eco.manifest)
        && ECOSYSTEMS.iter().any(|other| {
            other.name == eco.name
                && other.manifest != eco.manifest
                && other.lockfiles.contains(&eco.manifest)
                && dir.join(other.manifest).exists()
        })
}

/// A file beside the manifests above that says which Python packages an app installs, in a form
/// the bill of materials does not read as a manifest: `setup.py`, `setup.cfg`, a requirements file
/// under another name (`requirements-dev.txt`, `requirements/prod.txt`), or a Conda
/// `environment.yml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonDeclaration {
    /// The file's path from the app folder, with `/` separators.
    pub path: String,
    /// What kind of file it is, which decides how the bill of materials treats it.
    pub kind: DeclarationKind,
    /// Whether a Python lockfile in the same folder was found by `detect_in`, which then stands
    /// for what this file asks for.
    pub beside_lockfile: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclarationKind {
    /// `setup.py` or `setup.cfg` that names packages to install (`install_requires`,
    /// `extras_require`).
    Setup,
    /// A requirements file with another name than `requirements.txt`.
    Requirements,
    /// A Conda environment file, whose packages come from Conda's channels rather than PyPI.
    Conda,
}

/// Every Python dependency declaration in the app that is not one of `ECOSYSTEMS`' manifests.
///
/// Found so that the bill of materials can say they were not read, rather than leave a list that
/// looks whole (deep review H9). A `setup.cfg` that only configures tools, and a `setup.py` that
/// names no packages, declare nothing and are not listed. `requirements.in` is not either: it is
/// the input `pip-compile` turns into the requirements file beside it, which is what is installed.
pub fn python_declarations_in(listing: &crate::files::Listing) -> Vec<PythonDeclaration> {
    let locked_dirs: BTreeSet<String> = detect_in(listing)
        .into_iter()
        .filter(|e| e.name == "Python" && e.lockfile.is_some())
        .map(|e| {
            e.manifest
                .rsplit_once('/')
                .map_or(String::new(), |(dir, _)| dir.to_owned())
        })
        .collect();
    let mut out = Vec::new();
    for file in listing.app_files() {
        let name = file.file_name();
        let dir = file
            .relative
            .rsplit_once('/')
            .map_or("", |(dir, _)| dir)
            .to_owned();
        let in_requirements_dir = dir == "requirements" || dir.ends_with("/requirements");
        // A file that could not be read is listed: whether it names packages is not known, and
        // leaving it out would be deciding that it does not.
        let mentions_packages = || {
            file.read_text().map_or(true, |text| {
                text.contains("install_requires") || text.contains("extras_require")
            })
        };
        let kind = match name {
            "requirements.txt" => continue,
            "setup.py" | "setup.cfg" if mentions_packages() => DeclarationKind::Setup,
            "environment.yml" | "environment.yaml"
                if file.read_text().map_or(true, |text| {
                    text.lines().any(|l| l.starts_with("dependencies:"))
                }) =>
            {
                DeclarationKind::Conda
            }
            _ if name.ends_with(".txt")
                && (name.starts_with("requirements")
                    || name.ends_with("-requirements.txt")
                    || name.ends_with("_requirements.txt")
                    || in_requirements_dir) =>
            {
                DeclarationKind::Requirements
            }
            _ => continue,
        };
        out.push(PythonDeclaration {
            path: file.relative.clone(),
            kind,
            beside_lockfile: locked_dirs.contains(&dir),
        });
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
        .chain(declared_elsewhere_in(listing))
        .filter(|e| pinning(&listing.root, e).is_unpinned())
        .collect()
}

/// Python projects declared in a file that is not one of `ECOSYSTEMS`' manifests, each as a
/// project for the pinning check to judge:
///
/// - a `setup.py` or `setup.cfg` that names packages, with no Python lockfile in the same folder,
///   pins with a lockfile and has none. `pip install .` resolves what `install_requires` asks for
///   afresh each time, as `pip install -r requirements.txt` does without a lockfile.
/// - a requirements file under another name (`requirements-dev.txt`, `requirements/prod.txt`) is its
///   own lockfile when it pins and hashes every package (`fully_hash_pinned`), as `requirements.txt`
///   is, and otherwise pins nothing, whatever lockfile is beside it: `requirements-dev.txt` is
///   usually the very list a lockfile beside it leaves out, and the bill of materials names it as
///   unread for the same reason.
/// - a Conda `environment.yml` is not judged: Conda's own pins are a question no reader here
///   answers, so it is left to the bill of materials, which names it as unread.
///
/// Deep review H9: such a file is not a manifest `detect_in` finds, so an app whose Python was
/// declared there alone was told it had no package manifest, and one with an npm app beside it had
/// its pinning credited on npm's lockfile alone. Not added to `detect_in`, whose callers read each
/// manifest as a list of packages, which these files are not.
pub fn declared_elsewhere_in(listing: &crate::files::Listing) -> Vec<DetectedEcosystem> {
    python_declarations_in(listing)
        .into_iter()
        .filter_map(|d| {
            let lockfile = match d.kind {
                DeclarationKind::Setup if d.beside_lockfile => return None,
                DeclarationKind::Setup => None,
                DeclarationKind::Requirements => {
                    std::fs::read_to_string(listing.root.join(&d.path))
                        .is_ok_and(|text| fully_hash_pinned(&text))
                        .then(|| d.path.clone())
                }
                DeclarationKind::Conda => return None,
            };
            Some(DetectedEcosystem {
                name: "Python".to_owned(),
                manifest: d.path,
                lockfile,
                passed_over: Vec::new(),
                pins_with_lockfile: true,
            })
        })
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
        // Pages, and templates whose own syntax cannot run code: the scripts in them are read as
        // JavaScript, and nothing else in them can call what the code rules look for (ADR-054).
        "html" | "htm" | "vue" | "svelte" | "hbs" | "handlebars" | "mustache" | "liquid"
        | "twig" | "j2" | "jinja" | "jinja2" | "njk" => "html",
        // Templates whose code ast.rs takes out and reads with the page's scripts: Astro's `---`
        // header and `{…}` as TypeScript, and EJS's `<% %>` blocks as JavaScript (ADR-054, Later).
        "astro" | "ejs" => "html",
        // Jupyter notebooks: their code cells are read as Python (ADR-054).
        "ipynb" => "notebook",
        // Templates that hold a general-purpose language, by the name of their kind. None has a
        // grammar in ast.rs yet, so while one is present the code rules claim nothing (ADR-054).
        "pug" => "pug",
        "erb" => "erb",
        "jsp" => "jsp",
        "cshtml" | "razor" => "razor",
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

/// The templates `language_of` names that hold a general-purpose language, which no grammar in
/// `sv` reads yet (ADR-054).
pub const CODE_TEMPLATES: &[&str] = &["pug", "erb", "jsp", "razor"];

/// Whether the technology scan passes over files of this kind, as it did before they had names
/// (ADR-054): notebooks, and templates that hold code. No signature has a pattern for them, and
/// counting them as not looked in would take a "this app does not use X" answer away from every app
/// with one template.
pub fn not_for_technology(language: &str) -> bool {
    language == "notebook" || CODE_TEMPLATES.contains(&language)
}

/// Folders never walked, wherever they are: version control, installed dependencies, virtual
/// environments, caches, and editor settings. Nobody keeps an app's own code under these names. Their
/// contents belong to the dependency scan, not to the app's own source.
pub const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
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
    ".idea",
    ".vscode",
];

/// Folders with ordinary names that hold installed or built code only where an ecosystem puts it
/// there: each name, with the manifests beside which that folder is that ecosystem's output.
///
/// H6 of the deep review: `build`, `out`, `dist`, `vendor`, `coverage`, and `target` were skipped at
/// any depth, so an app keeping code in `src/build/` or `tools/out/` had it read by no check, and
/// nothing said so. Each is now skipped only beside a manifest that explains it (`target` beside
/// `Cargo.toml`, `dist` beside `package.json`), read as the app's own code anywhere else, and every
/// skip is recorded with its reason (`files::Listing::skipped`).
pub const OUTPUT_DIRS: &[(&str, &[&str])] = &[
    ("target", &["Cargo.toml", "pom.xml"]),
    (
        "vendor",
        &[
            "go.mod",
            "composer.json",
            "Gemfile",
            "requirements.txt",
            "pyproject.toml",
            "package.json",
        ],
    ),
    (
        "dist",
        &["package.json", "pyproject.toml", "setup.py", "setup.cfg"],
    ),
    (
        "build",
        &[
            "package.json",
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "build.gradle",
            "build.gradle.kts",
            "pubspec.yaml",
            "CMakeLists.txt",
        ],
    ),
    ("out", &["package.json", "tsconfig.json", "build.gradle"]),
    (
        "coverage",
        &[
            "package.json",
            "pyproject.toml",
            "setup.cfg",
            "jest.config.js",
        ],
    ),
];

/// Where `sv report` writes when not told otherwise. Like any folder carrying `REPORT_MARKER`, it is
/// left out only while it holds nothing but what `sv` writes (`is_sv_output`). The name, and the
/// marker's and the lock's, are the product's (`sv_frameworks::names`, ADR-062); a folder carrying
/// the old names is still `sv`'s own.
pub const DEFAULT_REPORT_DIR: &str = sv_frameworks::names::REPORT_DIR;

/// The lock `sv report` holds on the folder while it writes (`sv-cli`'s `report_lock`). A dot name,
/// beside the marker, so a listing hides it.
pub const REPORT_LOCK: &str = sv_frameworks::names::REPORT_LOCK;

/// The five files a report is written as, in the order they are written and sealed. The one list
/// the names of a report folder derive from: `REPORT_FOLDER_NAMES` here, and in `sv-cli` the table
/// that says how each is rendered and what kind of file it is (`report_files`), which the compiler
/// holds to this one, the seal (`report_seal::SEALED`), and the MCP server's resources.
pub const REPORT_FILES: [&str; 5] = [
    "report.html",
    "compliance.md",
    "security.md",
    "findings.sarif",
    "report.json",
];

/// The record of the build loop (ADR-076): one line for each call the AI coding tool made to `sv`'s
/// MCP server for the app, kept in its report folder beside the reports and read when one is written.
/// Not a report file and not sealed: it grows between reports, and the report carries what it read.
pub const BUILD_LOOP_RECORD: &str = "build-loop.jsonl";

/// Every name `sv` writes in a report folder: the marker, the lock, their old forms (a report folder
/// from before the rename holds those), the record of the build loop, and the five reports.
pub const REPORT_FOLDER_NAMES: &[&str] = &{
    let mut names = [""; 5 + REPORT_FILES.len()];
    names[0] = REPORT_MARKER;
    names[1] = REPORT_LOCK;
    names[2] = sv_frameworks::names::OLD_REPORT_MARKER;
    names[3] = sv_frameworks::names::OLD_REPORT_LOCK;
    names[4] = BUILD_LOOP_RECORD;
    let mut i = 0;
    while i < REPORT_FILES.len() {
        names[5 + i] = REPORT_FILES[i];
        i += 1;
    }
    names
};

/// Why a walk leaves a folder out, for the report to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// One of `SKIP_DIRS`: not recorded, since every app has some and none holds the app's code.
    Always,
    /// An ordinary name beside the manifest of the ecosystem whose output it is.
    Output { beside: &'static str },
    /// A report `sv` wrote.
    Report,
}

/// A folder carrying `sv`'s marker, or named as `sv`'s default report folder, that holds something
/// `sv` does not write. It is read as the app's own, and the report says so: the marker can be put
/// anywhere, by anyone, and an AI tool could once put it there through `stackvet_write_report`.
pub fn marker_refused(dir: &Path) -> bool {
    claims_to_be_report(dir) && !holds_only_report_files(dir)
}

fn claims_to_be_report(dir: &Path) -> bool {
    has_report_marker(dir)
        || dir.file_name().is_some_and(|n| {
            let name = n.to_string_lossy();
            name == DEFAULT_REPORT_DIR || name == sv_frameworks::names::OLD_REPORT_DIR
        })
}

/// Whether the folder carries `sv`'s marker, under its name or the name it had before the rename
/// (ADR-062): both are `sv`'s own writing.
pub fn has_report_marker(dir: &Path) -> bool {
    report_marker_in(dir).is_some()
}

/// The marker file in `dir`, under its name or its old one (the new first when both are there),
/// as a path; `None` when the folder carries neither. A link where the marker would be is not one.
pub fn report_marker_in(dir: &Path) -> Option<std::path::PathBuf> {
    [REPORT_MARKER, sv_frameworks::names::OLD_REPORT_MARKER]
        .iter()
        .map(|name| dir.join(name))
        .find(|path| std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file()))
}

/// The app's default report folder: the new name when it exists or when neither does, the old name
/// while only it exists (ADR-062), so a report written before the rename is still found and still
/// written over, and a new app gets the new name.
pub fn default_report_dir_in(app_dir: &Path) -> std::path::PathBuf {
    let new = app_dir.join(DEFAULT_REPORT_DIR);
    let old = app_dir.join(sv_frameworks::names::OLD_REPORT_DIR);
    if !new.exists() && old.is_dir() {
        return old;
    }
    new
}

/// Every entry is one of the names `sv` writes, compared without regard to capitals, and each is a
/// plain file. An empty folder holds nothing to hide.
fn holds_only_report_files(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().all(|entry| {
        let name = entry.file_name().to_string_lossy().to_lowercase();
        REPORT_FOLDER_NAMES.iter().any(|n| n.to_lowercase() == name)
            && entry.file_type().is_ok_and(|k| k.is_file())
    })
}

/// Why a walk of the app should leave this folder out, if it should.
pub fn skip_reason(dir: &Path) -> Option<Skip> {
    let name = dir.file_name()?.to_string_lossy();
    if SKIP_DIRS.contains(&name.as_ref()) {
        return Some(Skip::Always);
    }
    if is_sv_output(dir) {
        return Some(Skip::Report);
    }
    let (_, manifests) = OUTPUT_DIRS.iter().find(|(n, _)| *n == name)?;
    let parent = dir.parent()?;
    manifests
        .iter()
        .find(|m| parent.join(m).is_file())
        .map(|m| Skip::Output { beside: m })
}

/// Editor settings, in `SKIP_DIRS` for every walk of the app's code, and not for the credential scan:
/// a `.vscode/settings.json` can hold a token as easily as any other file.
pub const EDITOR_DIRS: &[&str] = &[".idea", ".vscode"];

/// Written by `sv report` into every folder it writes a report to, so no walk of the app reads the
/// report as the app's own code. Found in the owner's first build (26 September 2026): the report was
/// read back as part of the app, and while a page no code rule could fully read was there, nothing was
/// claimed, so the requirements checked fell from 9 to 1. A folder name alone does not do it, since
/// `--out` takes any name.
pub const REPORT_MARKER: &str = sv_frameworks::names::REPORT_MARKER;

/// Whether a walk of the app should leave this folder out: installed dependencies, build output
/// beside the manifest that explains it, version control, editor settings, or a report `sv` wrote.
pub fn skip_dir(dir: &Path) -> bool {
    skip_reason(dir).is_some()
}

/// A folder `sv report` wrote: it carries the marker, or has the default name, and holds nothing but
/// what `sv` writes.
pub fn is_sv_output(dir: &Path) -> bool {
    claims_to_be_report(dir) && holds_only_report_files(dir)
}

/// Every language whose files appear in the app, from the extensions actually seen.
pub fn languages_present(files: &[(String, String)]) -> BTreeSet<String> {
    files.iter().map(|(lang, _)| lang.clone()).collect()
}
