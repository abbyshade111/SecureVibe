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
    /// can say what is actually installed — worth reporting in its own right, in any language.
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
        ],
    },
    EcosystemDef {
        name: "Python",
        manifest: "requirements.txt",
        lockfiles: &["poetry.lock", "Pipfile.lock", "requirements.lock"],
    },
    EcosystemDef {
        name: "Python",
        manifest: "pyproject.toml",
        lockfiles: &["poetry.lock", "pdm.lock", "uv.lock"],
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
    /// Whether this ecosystem pins versions with a lockfile at all.
    ///
    /// Maven does not: versions live in `pom.xml` and there is no lockfile to look for. Without this
    /// flag `unpinned` reports every Maven project as pinning nothing, which is not a coverage gap but
    /// a wrong statement in a report — the thing ADR-012 exists to stop. A caller that wants to say
    /// "this app pins nothing" has to check this first.
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
    let mut dirs = Vec::new();
    project_dirs(app_dir, app_dir, &mut dirs);
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
            out.push(DetectedEcosystem {
                name: eco.name.to_owned(),
                manifest: join(rel_dir, eco.manifest),
                lockfile: find_lockfile(app_dir, rel_dir, eco.lockfiles),
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

/// Every folder, relative to the app folder, that holds a manifest `sv` knows.
fn project_dirs(root: &Path, dir: &Path, out: &mut Vec<String>) {
    if ECOSYSTEMS.iter().any(|e| dir.join(e.manifest).exists()) {
        let rel = dir
            .strip_prefix(root)
            .unwrap_or(dir)
            .to_string_lossy()
            .replace('\\', "/");
        out.push(rel);
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        // `file_type` rather than `is_dir`, so a symlinked folder is not followed into a loop.
        if entry.file_type().is_ok_and(|t| t.is_dir()) && !SKIP_DIRS.contains(&name.as_str()) {
            project_dirs(root, &path, out);
        }
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
        .find(|f| app_dir.join(rel_dir).join(f).exists())
        .map(|f| join(rel_dir, f));
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
            && let Some(found) = lockfiles.iter().find(|f| root.join(f).exists())
        {
            return Some(join(&parent, found));
        }
        rel = parent;
    }
    None
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

/// Ecosystems in use that pin nothing, so what is actually installed cannot be known.
///
/// Only ecosystems that pin with a lockfile can be missing one. Maven is in use here and has no lockfile
/// to be missing; reporting it would be a wrong statement rather than a finding.
pub fn unpinned(app_dir: &Path) -> Vec<DetectedEcosystem> {
    detect(app_dir)
        .into_iter()
        .filter(|e| e.pins_with_lockfile && e.lockfile.is_none())
        .collect()
}

/// Ecosystems in use whose pinning `sv` cannot judge, because they do not use a lockfile at all.
pub fn pinning_unknown(app_dir: &Path) -> Vec<DetectedEcosystem> {
    detect(app_dir)
        .into_iter()
        .filter(|e| !e.pins_with_lockfile)
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
];

/// Every language whose files appear in the app, from the extensions actually seen.
pub fn languages_present(files: &[(String, String)]) -> BTreeSet<String> {
    files.iter().map(|(lang, _)| lang.clone()).collect()
}
