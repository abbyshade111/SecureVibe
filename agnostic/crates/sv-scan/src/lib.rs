//! The dependency and source scanner: it answers the `derived` conditions, the ones nobody should
//! have to be believed about.
//!
//! The rule that makes an answer here honest is in `evaluate`. A signature match means the
//! condition holds. **No match only means the condition does not hold when every file that could
//! have carried it was actually read.** Several of these technologies are reachable from a standard
//! library with no dependency at all — Python's `xml.etree`, Java's JAXB — so a dependency-only
//! scan answering "no XML parser is used" would be the same class of wrong statement as the
//! inherited v1 reasons this work replaced.
//!
//! Matching is case-insensitive substring. It over-matches rather than under-matches, and an
//! over-match makes a condition *true*, which only ever adds requirements — the same safe direction
//! the manifest claims run in.

pub mod deps;
pub mod ecosystems;

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use sv_frameworks::Condition;

#[derive(Debug, Deserialize)]
// `deny_unknown_fields` is not fussiness. Without it, `absenceIsEvidence` in the data file did not
// bind to `absence_is_evidence` here, every corroborator silently took the default — the dangerous
// value, true — and the only symptom was requirements quietly switching off. A typo in this file
// should stop the run, not change the answer.
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Signature {
    pub condition: String,
    /// Why this signature is shaped the way it is. Carried into the report.
    #[serde(default)]
    pub note: String,
    /// Languages whose mere presence settles the condition (C for unmanaged code, and so on).
    #[serde(default)]
    pub languages: Vec<String>,
    /// Dependency names, by ecosystem.
    #[serde(default)]
    pub packages: BTreeMap<String, Vec<String>>,
    /// Source patterns, by language.
    #[serde(default)]
    pub source: BTreeMap<String, Vec<String>>,
    /// Paths whose presence settles the condition: an exact relative path, or `*.ext`.
    #[serde(default)]
    pub files: Vec<String>,
    /// Set when no check is possible at all, rather than merely inconclusive.
    ///
    /// A claim about how the app is *deployed* — what else answers on its hostname — is not written
    /// down anywhere in the app's own code, so there is nothing to look for and no amount of
    /// scanning would change the answer. Saying that in as many words is a better answer than a
    /// signature that pretends to look. Such a signature carries a `note` and no patterns.
    #[serde(default)]
    pub no_corroborator: bool,
    /// Whether finding nothing is itself an answer.
    ///
    /// True for a technology that always leaves a trace, and for configuration that has to be a
    /// file in the repository. False wherever the capability can be hand-rolled: sign-in built
    /// from a hash function and a database table leaves no library behind, and calling it absent
    /// because no library appears is the over-confident exclusion this project exists to avoid.
    #[serde(default = "yes")]
    pub absence_is_evidence: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signatures {
    /// Present in the data files as documentation; ignored here but named so it is not "unknown".
    #[serde(rename = "_comment", default)]
    pub comment: String,
    pub signatures: Vec<Signature>,
}

impl Signatures {
    /// Loads several signature files into one set. The technology signatures answer the `derived`
    /// conditions and the corroborators check the manifest's claims; they do not overlap.
    pub fn load_all(paths: &[&Path]) -> Result<Self> {
        let mut all = Signatures {
            comment: String::new(),
            signatures: Vec::new(),
        };
        for path in paths {
            all.signatures.extend(Self::load(path)?.signatures);
        }
        Ok(all)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }
}

/// Why a condition was answered the way it was. A report that cannot say this is asking to be
/// believed, which is the thing `sv` does not do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evidence {
    /// A dependency the app declares.
    Dependency { name: String, manifest: String },
    /// A pattern in the app's own source.
    Source { pattern: String, file: String },
    /// The language is present at all.
    Language { language: String },
    /// A file in the repository.
    File { path: String },
    /// Nothing was found, and for this condition that does not mean it is absent.
    NotFoundButNotDecisive { note: String },
    /// Nothing matched, and every file that could have carried it was read.
    NothingFound { files_read: usize },
    /// Nothing matched, but files that could have carried it were not read.
    Incomplete { reason: String },
    /// No check for this claim is possible, and this is why. Distinct from `NothingFound`, which
    /// means `sv` looked: this one means there was never anywhere to look.
    NoCheckExists { reason: String },
}

#[derive(Debug, Clone)]
pub struct Answer {
    pub condition: Condition,
    /// `None` when the scan could not cover what it would have to.
    pub value: Option<bool>,
    pub evidence: Evidence,
}

#[derive(Debug, Default)]
pub struct ScanReport {
    pub ecosystems: Vec<ecosystems::DetectedEcosystem>,
    /// Ecosystems in use that pin nothing, so what is installed cannot be known.
    pub unpinned: Vec<ecosystems::DetectedEcosystem>,
    pub declared: Vec<deps::Declared>,
    pub languages: BTreeSet<String>,
    /// Every path in the app, whatever its type, so a configuration file can be looked for.
    pub all_paths: BTreeSet<String>,
    pub files_read: usize,
    /// Files that look like source but whose language `sv` cannot read, with their extensions.
    pub unread_extensions: BTreeSet<String>,
    pub answers: Vec<Answer>,
}

impl ScanReport {
    /// The scanner as a corroborator, in the shape `sv_manifest::resolve` expects.
    pub fn as_corroborator(&self) -> impl Fn(Condition) -> Option<bool> + '_ {
        move |c| self.answers.iter().find(|a| a.condition == c)?.value
    }
}

/// Reads the app's manifests and source, and answers every signature it can.
pub fn scan(app_dir: &Path, signatures: &Signatures) -> Result<ScanReport> {
    let mut report = ScanReport {
        ecosystems: ecosystems::detect(app_dir),
        unpinned: ecosystems::unpinned(app_dir),
        declared: deps::read(app_dir),
        ..Default::default()
    };

    let mut files: Vec<(String, String, String)> = Vec::new(); // (language, path, contents)
    walk(app_dir, app_dir, &mut files, &mut report)?;
    report.files_read = files.len();
    report.languages = files.iter().map(|(l, _, _)| l.clone()).collect();

    for sig in &signatures.signatures {
        if let Some(condition) = Condition::from_name(&sig.condition) {
            report
                .answers
                .push(evaluate(condition, sig, &report, &files));
        }
    }
    Ok(report)
}

fn evaluate(
    condition: Condition,
    sig: &Signature,
    report: &ScanReport,
    files: &[(String, String, String)],
) -> Answer {
    // 0. Some claims cannot be checked from the code at all. Answering "not found" for those would
    // be a kind of lie by omission: it reads as a search that came up empty rather than as a
    // question nobody here can answer.
    if sig.no_corroborator {
        return Answer {
            condition,
            value: None,
            evidence: Evidence::NoCheckExists {
                reason: sig.note.clone(),
            },
        };
    }

    // 1. The language being present at all settles some of these outright.
    for lang in &sig.languages {
        if report.languages.contains(lang) {
            return Answer {
                condition,
                value: Some(true),
                evidence: Evidence::Language {
                    language: lang.clone(),
                },
            };
        }
    }

    // 2. A file in the repository. Configuration is the clearest kind of evidence there is: it
    // either exists or it does not.
    for pattern in &sig.files {
        if let Some(hit) = matching_path(&report.all_paths, pattern) {
            return Answer {
                condition,
                value: Some(true),
                evidence: Evidence::File { path: hit },
            };
        }
    }

    // 3. A declared dependency.
    for declared in &report.declared {
        if let Some(names) = sig.packages.get(&declared.ecosystem)
            && names.iter().any(|n| eq_ignore_case(n, &declared.name))
        {
            {
                return Answer {
                    condition,
                    value: Some(true),
                    evidence: Evidence::Dependency {
                        name: declared.name.clone(),
                        manifest: declared.manifest.clone(),
                    },
                };
            }
        }
    }

    // 4. A pattern in the app's own source — how a standard-library use is caught.
    for (language, path, contents) in files {
        let Some(patterns) = sig.source.get(language) else {
            continue;
        };
        let haystack = contents.to_lowercase();
        for pattern in patterns {
            if haystack.contains(&pattern.to_lowercase()) {
                return Answer {
                    condition,
                    value: Some(true),
                    evidence: Evidence::Source {
                        pattern: pattern.clone(),
                        file: path.clone(),
                    },
                };
            }
        }
    }

    // 5. Nothing matched.
    //
    // For most claims that is where it stops. A capability that can be written by hand leaves
    // nothing to find, so "no library appears" is not "the app does not do this" — it is `sv`
    // having no opinion, which `resolve` records as the claim being unverified rather than
    // contradicted.
    if !sig.absence_is_evidence {
        return Answer {
            condition,
            value: None,
            evidence: Evidence::NotFoundButNotDecisive {
                note: sig.note.clone(),
            },
        };
    }

    // Whether the rest is an answer depends entirely on what was read.
    //
    // Reading nothing is the clearest case: a scan that did not run is not a clean result. An
    // empty folder, a repository of files `sv` skipped, an app whose source lives somewhere else —
    // all of them would otherwise come back as "none of these technologies are used", which reads
    // exactly like a thorough scan that found nothing.
    if report.files_read == 0 && report.declared.is_empty() {
        return Answer {
            condition,
            value: None,
            evidence: Evidence::Incomplete {
                reason: "no source files and no dependency manifests were read".to_owned(),
            },
        };
    }

    //
    // A signature can only hide in a language it has patterns for. If the app contains files in a
    // language `sv` cannot read, it cannot say the signature is absent — it can only say it did
    // not find it, which is not the same and must not be reported as one.
    if !report.unread_extensions.is_empty() {
        let mut exts: Vec<&str> = report
            .unread_extensions
            .iter()
            .map(String::as_str)
            .collect();
        exts.sort_unstable();
        return Answer {
            condition,
            value: None,
            evidence: Evidence::Incomplete {
                reason: format!(
                    "files `sv` cannot read are present ({}), so it cannot say this is absent",
                    exts.join(", ")
                ),
            },
        };
    }

    // An ecosystem that pins nothing is a second way of not knowing: the declared names are not
    // what is installed, so an absent dependency is not evidence of an absent technology.
    if !report.unpinned.is_empty() && !sig.packages.is_empty() {
        let names: Vec<&str> = report.unpinned.iter().map(|e| e.name.as_str()).collect();
        return Answer {
            condition,
            value: None,
            evidence: Evidence::Incomplete {
                reason: format!(
                    "{} pins no versions, so what is actually installed cannot be known",
                    names.join(", ")
                ),
            },
        };
    }

    Answer {
        condition,
        value: Some(false),
        evidence: Evidence::NothingFound {
            files_read: report.files_read,
        },
    }
}

/// A path pattern: either an exact relative path, or `*.ext` matched against every path.
fn matching_path(paths: &BTreeSet<String>, pattern: &str) -> Option<String> {
    if let Some(ext) = pattern.strip_prefix("*.") {
        let suffix = format!(".{}", ext.to_lowercase());
        return paths
            .iter()
            .find(|p| p.to_lowercase().ends_with(&suffix))
            .cloned();
    }
    let wanted = pattern.replace('\\', "/").to_lowercase();
    paths
        .iter()
        .find(|p| {
            let p = p.replace('\\', "/").to_lowercase();
            p == wanted || p.starts_with(&format!("{wanted}/"))
        })
        .cloned()
}

fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.to_lowercase() == b.to_lowercase()
}

fn walk(
    root: &Path,
    dir: &Path,
    files: &mut Vec<(String, String, String)>,
    report: &mut ScanReport,
) -> Result<()> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            // Only the genuinely uninteresting directories are skipped. `.github` is a dot-directory
            // and is exactly where a CI pipeline lives, so a blanket dot-skip would answer "no
            // CI/CD" for every repository that has one.
            if ecosystems::SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            report.all_paths.insert(relative);
            walk(root, &path, files, report)?;
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        // Recorded before anything is decided about reading it. A file with no extension — a
        // `Dockerfile`, a `Jenkinsfile`, a `CODEOWNERS` — used to be skipped here, before its path
        // was ever written down, so signatures that name those files could not match. For `iac`,
        // which rules itself out by absence, that turned "I did not look" into "there is no
        // infrastructure configuration", on an app whose Dockerfile was sitting next to the source.
        report.all_paths.insert(relative.clone());
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        match ecosystems::language_of(&ext.to_lowercase()) {
            Some(language) => match std::fs::read_to_string(&path) {
                Ok(contents) => files.push((language.to_owned(), relative, contents)),
                // A source file that cannot be read is a hole in the coverage, not an empty file.
                Err(_) => {
                    report.unread_extensions.insert(ext.to_lowercase());
                }
            },
            None => {
                if looks_like_source(ext) {
                    report.unread_extensions.insert(ext.to_lowercase());
                }
            }
        }
    }
    Ok(())
}

/// Extensions that are probably code `sv` has no reader for. Deliberately narrow: counting every
/// unknown extension as unread source would make the scanner permanently unable to answer anything,
/// and a check that can never conclude is no more useful than one that always does.
fn looks_like_source(ext: &str) -> bool {
    matches!(
        ext.to_lowercase().as_str(),
        "swift"
            | "scala"
            | "clj"
            | "ex"
            | "exs"
            | "erl"
            | "hs"
            | "ml"
            | "dart"
            | "lua"
            | "pl"
            | "r"
            | "jl"
            | "groovy"
            | "m"
            | "mm"
            | "f90"
            | "pas"
            | "vb"
            | "asm"
            | "zig"
            | "nim"
    )
}
