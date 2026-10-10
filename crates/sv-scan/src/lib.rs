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
pub mod files;
pub mod jvm;
mod not_the_app;
pub use not_the_app::not_the_app_in;

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
    /// The condition this answers. A name the data file misspells stops the load, as an unknown
    /// condition does everywhere else, rather than leaving this signature silently unread (the
    /// architecture assessment of 8 October 2026, item 12).
    pub condition: Condition,
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
        serde_json::from_str(&text).with_context(|| sv_frameworks::data::not_understood(path))
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
    /// The package lists found and not read (backlog 0226, part 1, item 11): what they name is not in
    /// `declared`, which the report says beside the technology answers.
    pub unread_manifests: Vec<deps::Unread>,
    pub languages: BTreeSet<String>,
    /// Every path in the app, whatever its type, so a configuration file can be looked for.
    pub all_paths: BTreeSet<String>,
    pub files_read: usize,
    /// Extensions of source files the technology scan did not look in: a language `sv` cannot read
    /// at all, or one only the code rules read (`ecosystems::NO_TECHNOLOGY_READER`).
    pub unread_extensions: BTreeSet<String>,
    pub answers: Vec<Answer>,
    /// The folders the manifest says are not the app (`[repository] not-the-app`), as used: empty when
    /// the list was not used (`not_the_app_refused`).
    pub not_the_app: Vec<String>,
    /// Why the list was not used, when it would have set apart every code file the app has.
    pub not_the_app_refused: Option<String>,
    /// How many of the app's code files the list set apart, and how many the app has.
    pub code_set_apart: (usize, usize),
    /// The folders in the app that one of those matched, and so were not looked in for evidence.
    pub set_apart: BTreeSet<String>,
    /// Conditions found only inside those folders, each with the file or manifest that showed it
    /// (gap analysis, item 19). Not read as a "no": whether the app itself does it is a question,
    /// so `as_corroborator` answers nothing for them.
    pub found_only_apart: Vec<(Condition, String)>,
}

impl ScanReport {
    /// The scanner as a corroborator, in the shape `sv_manifest::resolve` expects.
    pub fn as_corroborator(&self) -> impl Fn(Condition) -> Option<bool> + '_ {
        move |c| {
            if self.found_only_apart.iter().any(|(found, _)| *found == c) {
                return None;
            }
            self.answers.iter().find(|a| a.condition == c)?.value
        }
    }
}

/// Reads the app's manifests and source, and answers every signature it can.
pub fn scan(app_dir: &Path, signatures: &Signatures) -> Result<ScanReport> {
    scan_listing(&files::Listing::of(app_dir), signatures)
}

/// `scan`, over a listing already made.
///
/// The source is read in one pass: each file is read once and lowercased once, and every signature's
/// patterns for its language are tried against it there, the first match in path order being the
/// evidence. Before, every file was held in memory for the whole run and lowercased again for each
/// of about thirty signatures.
pub fn scan_listing(listing: &files::Listing, signatures: &Signatures) -> Result<ScanReport> {
    scan_listing_app(listing, signatures, &[])
}

/// As `scan_listing`, leaving out the folders the manifest says are not the app: a fixture's
/// `authlib` is not evidence that the app signs people in. Only the answers change. The code rules,
/// the credentials scan, and every other check still read those folders.
pub fn scan_listing_app(
    listing: &files::Listing,
    signatures: &Signatures,
    not_the_app: &[String],
) -> Result<ScanReport> {
    let app_dir = listing.root.as_path();
    let (not_the_app, not_the_app_refused, code_set_apart) = not_the_app_in(listing, not_the_app);
    let not_the_app = not_the_app.as_slice();
    let ours = |path: &str| !under_any(path, not_the_app);
    let mut report = ScanReport {
        ecosystems: ecosystems::detect_in(listing)
            .into_iter()
            .filter(|e| ours(&e.manifest))
            .collect(),
        unpinned: ecosystems::unpinned_in(listing)
            .into_iter()
            .filter(|e| ours(&e.manifest))
            .collect(),
        declared: deps::read_in(listing)
            .into_iter()
            .filter(|d| ours(&d.manifest))
            .collect(),
        unread_manifests: deps::unread_in(listing)
            .into_iter()
            .filter(|u| ours(&u.manifest))
            .collect(),
        all_paths: listing
            .all_paths()
            .into_iter()
            .filter(|p| ours(p))
            .collect(),
        not_the_app: not_the_app.to_vec(),
        not_the_app_refused,
        code_set_apart,
        // The outermost folder each entry matched, so the report can name what it set apart.
        set_apart: listing
            .dirs
            .iter()
            .filter(|d| !ours(d) && d.rsplit_once('/').is_none_or(|(parent, _)| ours(parent)))
            .cloned()
            .collect(),
        ..Default::default()
    };

    // Each signature's source patterns, lowercased once, by language.
    let lowered: Vec<BTreeMap<&str, Vec<String>>> = signatures
        .signatures
        .iter()
        .map(|sig| {
            sig.source
                .iter()
                .map(|(language, patterns)| {
                    (
                        language.as_str(),
                        patterns.iter().map(|p| p.to_lowercase()).collect(),
                    )
                })
                .collect()
        })
        .collect();
    // The first file each signature's patterns matched: (the pattern as written, the file).
    let mut source_hits: Vec<Option<(String, String)>> = vec![None; signatures.signatures.len()];

    for entry in listing.app_files().filter(|e| ours(&e.relative)) {
        let Some(ext) = &entry.extension else {
            continue;
        };
        let Some(language) = entry.language else {
            if looks_like_source(ext) {
                report.unread_extensions.insert(ext.clone());
            }
            continue;
        };
        if ecosystems::not_for_technology(language) {
            continue;
        }
        let contents = match entry.read_text() {
            Ok(contents) => contents,
            // A source file that cannot be read — or is over the size limit — is a hole in the
            // coverage, not an empty file.
            Err(_) => {
                report.unread_extensions.insert(ext.clone());
                continue;
            }
        };
        // Read by the code rules, and present as a language, but not looked in for technologies:
        // no dependency file of theirs is read and no signature has a pattern for them, so a Dart
        // app's GraphQL would go unseen and be called absent.
        if ecosystems::NO_TECHNOLOGY_READER.contains(&language) {
            report.unread_extensions.insert(ext.clone());
        }
        report.files_read += 1;
        report.languages.insert(language.to_owned());
        let haystack = contents.to_lowercase();
        for (i, sig) in signatures.signatures.iter().enumerate() {
            if source_hits[i].is_some() {
                continue;
            }
            let Some(patterns) = lowered[i].get(language) else {
                continue;
            };
            if let Some(at) = patterns.iter().position(|p| haystack.contains(p.as_str())) {
                source_hits[i] = Some((sig.source[language][at].clone(), entry.relative.clone()));
            }
        }
    }

    for (i, sig) in signatures.signatures.iter().enumerate() {
        report.answers.push(evaluate(
            sig.condition,
            sig,
            &report,
            source_hits[i].as_ref(),
        ));
    }

    // A compose file that builds two or more services from this repository's own code is the
    // strongest evidence there is of several services. One `build:` beside a database image is the
    // commonest single app of all, so it takes two. Read as lines rather than YAML: a service's
    // `build:` is always indented under it, and a miss here only leaves the answer as it was.
    if let Some(file) = compose_with_two_builds(app_dir, &report.all_paths)
        && let Some(answer) = report
            .answers
            .iter_mut()
            .find(|a| a.condition == Condition::MultipleServices)
        && answer.value != Some(true)
    {
        answer.value = Some(true);
        answer.evidence = Evidence::Source {
            pattern: "two or more services with their own `build:`".to_owned(),
            file,
        };
    }

    // What the app shows only inside the folders set apart (gap analysis, item 19). Listing the one
    // folder that holds the app's AI client turned the AI requirements to "does not apply"; now each
    // such condition is named, and not read as a "no".
    if !not_the_app.is_empty() {
        let whole = scan_listing_app(listing, signatures, &[])?;
        for found in whole.answers.iter().filter(|a| a.value == Some(true)) {
            let here = report
                .answers
                .iter()
                .find(|a| a.condition == found.condition)
                .and_then(|a| a.value);
            if here == Some(true) {
                continue;
            }
            let shown_by = match &found.evidence {
                Evidence::Source { file, .. } => file.clone(),
                Evidence::Dependency { name, manifest } => format!("{name}, in {manifest}"),
                Evidence::File { path } => path.clone(),
                Evidence::Language { language } => format!("code in {language}"),
                _ => continue,
            };
            report.found_only_apart.push((found.condition, shown_by));
        }
    }
    Ok(report)
}

/// The names Docker Compose reads a project from.
const COMPOSE_FILES: &[&str] = &[
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
];

/// The first compose file in the app that builds at least two services from its own code.
fn compose_with_two_builds(app_dir: &Path, paths: &BTreeSet<String>) -> Option<String> {
    paths
        .iter()
        .filter(|p| {
            let name = p.rsplit(['/', '\\']).next().unwrap_or(p);
            COMPOSE_FILES.contains(&name.to_lowercase().as_str())
        })
        .find(|p| {
            std::fs::read_to_string(app_dir.join(p)).is_ok_and(|text| {
                text.lines()
                    .filter(|line| {
                        line.starts_with([' ', '\t'])
                            && line
                                .trim_start()
                                .strip_prefix("build")
                                .is_some_and(|rest| rest.trim_start().starts_with(':'))
                    })
                    .count()
                    >= 2
            })
        })
        .cloned()
}

fn evaluate(
    condition: Condition,
    sig: &Signature,
    report: &ScanReport,
    source_hit: Option<&(String, String)>,
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
            && names
                .iter()
                .any(|n| package_matches(&declared.ecosystem, n, &declared.name))
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

    // 4. A pattern in the app's own source — how a standard-library use is caught. Found in the
    //    one pass over the files in `scan_listing`.
    if let Some((pattern, file)) = source_hit {
        return Answer {
            condition,
            value: Some(true),
            evidence: Evidence::Source {
                pattern: pattern.clone(),
                file: file.clone(),
            },
        };
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

    // An ecosystem that does not pin what it installs is a second way of not knowing: the declared names are not
    // what is installed, so an absent dependency is not evidence of an absent technology.
    if !report.unpinned.is_empty() && !sig.packages.is_empty() {
        let names: Vec<&str> = report.unpinned.iter().map(|e| e.name.as_str()).collect();
        return Answer {
            condition,
            value: None,
            evidence: Evidence::Incomplete {
                reason: format!(
                    "{} does not pin every version it installs, so what is actually installed \
                     cannot be known",
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

/// A path pattern: an exact relative path (or a folder at the root), `*.ext` matched against
/// every path, or `**/name` matched against a file or folder of that name at any depth.
///
/// `**/` is for names that are as often in a subfolder as at the root: a `Dockerfile` under
/// `deploy/`, a `compose.yaml` under `docker/`, a `Chart.yaml` under `charts/app/`. A bare
/// `Dockerfile` matched only at the root, so an app whose Dockerfile sat one folder down was
/// answered "no infrastructure configuration" when its owner had said nothing (gap analysis of
/// 7 October 2026, finding 16).
fn matching_path(paths: &BTreeSet<String>, pattern: &str) -> Option<String> {
    if let Some(name) = pattern.strip_prefix("**/") {
        let name = name.replace('\\', "/").to_lowercase();
        return paths
            .iter()
            .find(|p| {
                let p = p.replace('\\', "/").to_lowercase();
                p == name
                    || p.starts_with(&format!("{name}/"))
                    || p.ends_with(&format!("/{name}"))
                    || p.contains(&format!("/{name}/"))
            })
            .cloned();
    }
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

/// Whether a declared dependency is the package a signature names.
///
/// Exact everywhere except Go, where `go.mod` declares a full module path —
/// `github.com/gorilla/websocket`, `github.com/golang-jwt/jwt/v5` — and a signature names the part
/// people say, `gorilla/websocket`. Compared exactly, no Go signature had ever matched, and a Go app
/// using a WebSocket library had the WebSocket requirements excluded because "no WebSocket library
/// is used". So a Go signature matches the whole path, or its tail on a `/` boundary, with a major
/// version suffix (`/v5`) set aside first. Matching on a boundary keeps `ws` from matching
/// `gobwas/ws`'s neighbors; over-matching here would add requirements, never remove them.
fn package_matches(ecosystem: &str, signature: &str, declared: &str) -> bool {
    if eq_ignore_case(signature, declared) {
        return true;
    }
    if ecosystem != "Go" {
        return false;
    }
    let declared = declared.to_lowercase();
    let path = match declared.rsplit_once('/') {
        Some((head, tail))
            if tail.len() > 1
                && tail.starts_with('v')
                && tail[1..].chars().all(|c| c.is_ascii_digit()) =>
        {
            head
        }
        _ => declared.as_str(),
    };
    let signature = signature.to_lowercase();
    path == signature || path.ends_with(&format!("/{signature}"))
}

fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.to_lowercase() == b.to_lowercase()
}

/// Whether a path from the app folder is inside one of `folders`, where `*` stands for one whole
/// folder name. `examples` holds `examples/shop/app.py`, and not `examples.md` or `my-examples/`.
pub fn under_any(path: &str, folders: &[String]) -> bool {
    let parts: Vec<&str> = path.split(['/', '\\']).filter(|p| !p.is_empty()).collect();
    folders.iter().any(|folder| {
        let pattern: Vec<&str> = folder.split('/').collect();
        pattern.len() <= parts.len()
            && pattern
                .iter()
                .zip(&parts)
                .all(|(want, got)| *want == "*" || want == got)
    })
}

/// Extensions that are probably code `sv` has no reader for. Deliberately narrow: counting every
/// unknown extension as unread source would make the scanner permanently unable to answer anything,
/// and a check that can never conclude is no more useful than one that always does.
fn looks_like_source(ext: &str) -> bool {
    matches!(
        ext.to_lowercase().as_str(),
        "scala"
            | "clj"
            | "ex"
            | "exs"
            | "erl"
            | "hs"
            | "ml"
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
