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
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedEcosystem {
    pub name: String,
    pub manifest: String,
    /// The lockfile found, when one was.
    pub lockfile: Option<String>,
}

/// Every ecosystem whose manifest is in the app folder, in the order listed above.
pub fn detect(app_dir: &Path) -> Vec<DetectedEcosystem> {
    ECOSYSTEMS
        .iter()
        .filter(|eco| app_dir.join(eco.manifest).exists())
        .map(|eco| DetectedEcosystem {
            name: eco.name.to_owned(),
            manifest: eco.manifest.to_owned(),
            lockfile: eco
                .lockfiles
                .iter()
                .find(|f| app_dir.join(f).exists())
                .map(|f| (*f).to_owned()),
        })
        .collect()
}

/// Ecosystems in use that pin nothing, so what is actually installed cannot be known.
pub fn unpinned(app_dir: &Path) -> Vec<DetectedEcosystem> {
    detect(app_dir)
        .into_iter()
        .filter(|e| e.lockfile.is_none())
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
        "cc" | "cpp" | "cxx" | "hpp" | "hh" => "cpp",
        "html" | "htm" | "vue" | "svelte" => "html",
        _ => return None,
    })
}

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
