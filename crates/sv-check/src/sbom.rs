//! The software bill of materials: what this app actually ships.
//!
//! An SBOM is only worth the completeness of the list. A partial one is more dangerous than none,
//! because the whole point of handing it to somebody is that they can ask "is the compromised version of
//! that library in here?" and trust the answer. So two things are recorded on every component and on the
//! document itself.
//!
//! **Where the version came from.** A lockfile says what is installed. A manifest says what was asked
//! for, and `^4.18.0` is not a version — the thing installed under it changes over time and differs
//! between machines. Components built from a manifest are marked `declared`, and the document says how
//! many of them there are, because "we ship express 4.18.2" and "we asked for some express 4" are
//! different sentences.
//!
//! **What was not read.** An ecosystem whose lockfile format `sv` cannot parse yet is named in the
//! document rather than silently omitted. An SBOM that quietly drops a whole ecosystem reads exactly like
//! one that had nothing to drop.

use crate::finding::{Confidence, Finding, Location, Severity};
use serde::Serialize;
use std::path::Path;
use sv_scan::ecosystems::DetectedEcosystem;

/// Whether a version is what is installed, or only what was requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VersionSource {
    /// Read from a lockfile: this is what is installed.
    Locked,
    /// Read from a manifest: this is what was asked for, and may be a range.
    Declared,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub source: VersionSource,
}

impl Component {
    /// A package URL, the identifier an SBOM reader matches advisories against.
    pub fn purl(&self) -> String {
        let kind = match self.ecosystem.as_str() {
            "npm" => "npm",
            "Python" => "pypi",
            "Rust" => "cargo",
            "Ruby" => "gem",
            "PHP" => "composer",
            "Go" => "golang",
            _ => "generic",
        };
        format!("pkg:{kind}/{}@{}", self.name, self.version)
    }
}

#[derive(Debug, Default)]
pub struct Sbom {
    pub components: Vec<Component>,
    /// Ecosystems that are present and whose contents `sv` could not read, with the reason.
    pub unread: Vec<(String, String)>,
    /// Projects with more than one lockfile of their kind. The list is still a full reading of the
    /// lockfile it came from, so this does not make it incomplete; it says which lockfile the
    /// versions are from, and which were not read.
    pub passed_over: Vec<PassedOver>,
    /// Projects whose manifest and lockfile were compared and did not wholly agree, or could not
    /// all be compared. The list is still the lockfile's; this says the manifest asks for something
    /// else, so whoever installs from the manifest runs versions the list does not name.
    pub disagreements: Vec<Disagreement>,
    /// The lockfiles the listed packages were read from, so a clean comparison can say where its
    /// list came from (deep review, improvement 2).
    pub lockfiles: Vec<String>,
}

/// A project whose manifest asks for something other than what its lockfile has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disagreement {
    /// The project, as `DetectedEcosystem::label` names it.
    pub project: String,
    pub manifest: String,
    pub lockfile: String,
    pub comparison: crate::manifest_lock::Comparison,
}

impl Disagreement {
    /// The packages that differ, each as "`asked` (the lockfile has 2.8.0)": at most five, then a count.
    fn differing(&self) -> String {
        let shown: Vec<String> = self
            .comparison
            .differs
            .iter()
            .take(5)
            .map(|d| {
                if d.locked.is_empty() {
                    format!("`{}` (not in the lockfile)", d.asked)
                } else {
                    format!("`{}` (the lockfile has {})", d.asked, d.locked.join(", "))
                }
            })
            .collect();
        let more = self.comparison.differs.len().saturating_sub(shown.len());
        if more == 0 {
            shown.join("; ")
        } else {
            format!("{}; and {more} more", shown.join("; "))
        }
    }

    /// The sentence a person reads about the packages that differ.
    pub fn explain(&self) -> String {
        let n = self.comparison.differs.len();
        format!(
            "`{}` and `{}` disagree about {n} package{}: {}. The versions listed here are the \
             lockfile's, so if the app is installed from `{}`, they are not the ones installed",
            self.manifest,
            self.lockfile,
            if n == 1 { "" } else { "s" },
            self.differing(),
            self.manifest,
        )
    }

    /// The sentence a person reads about the packages that could not be compared.
    pub fn explain_not_compared(&self) -> String {
        let n = self.comparison.not_compared.len();
        let shown: Vec<String> = self
            .comparison
            .not_compared
            .iter()
            .take(5)
            .map(|p| format!("`{p}`"))
            .collect();
        format!(
            "{n} package{} in `{}` could not be held to `{}` ({}{}): a pre-release, a link instead \
             of a version, a platform condition, or a range written in a form `sv` does not read, so \
             whether they agree is not known",
            if n == 1 { "" } else { "s" },
            self.manifest,
            self.lockfile,
            shown.join(", "),
            if n > 5 { ", …" } else { "" },
        )
    }

    /// Whether any package was found to differ, as opposed to only some not compared.
    pub fn differs(&self) -> bool {
        !self.comparison.differs.is_empty()
    }
}

/// One project's lockfiles when it has more than one: the one read, and the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassedOver {
    /// The project, as `DetectedEcosystem::label` names it: `npm`, or `npm in server/`.
    pub project: String,
    pub read: String,
    pub not_read: Vec<String>,
}

impl PassedOver {
    /// The files that were not read, each in backticks: "`yarn.lock`", or "`a` and `b`".
    pub fn not_read_list(&self) -> String {
        self.not_read
            .iter()
            .map(|f| format!("`{f}`"))
            .collect::<Vec<_>>()
            .join(" and ")
    }

    /// The sentence a person reads.
    pub fn explain(&self) -> String {
        let one = self.not_read.len() == 1;
        format!(
            "`{}` was read; {} {} there too and {} not read, so if the app is installed from {}, \
             the versions listed here may not be the ones installed",
            self.read,
            self.not_read_list(),
            if one { "is" } else { "are" },
            if one { "was" } else { "were" },
            if one { "it" } else { "one of them" },
        )
    }
}

impl Sbom {
    /// How many components are only as good as the range that was asked for.
    pub fn declared_count(&self) -> usize {
        self.components
            .iter()
            .filter(|c| c.source == VersionSource::Declared)
            .count()
    }

    /// Whether this document can be relied on as a complete list.
    pub fn is_complete(&self) -> bool {
        self.unread.is_empty() && self.declared_count() == 0
    }

    /// What the list holds and where it came from, for a claim to name its limits (deep review,
    /// improvement 2): "3 npm packages and 2 Python packages, read from `package-lock.json` and
    /// `Pipfile.lock`". The ecosystems in alphabetical order, whatever case each is written in; the
    /// lockfiles in the order they were read.
    pub fn what_was_read(&self) -> String {
        let mut by_ecosystem: Vec<(&str, usize)> = Vec::new();
        for component in &self.components {
            match by_ecosystem
                .iter_mut()
                .find(|(e, _)| *e == component.ecosystem)
            {
                Some((_, n)) => *n += 1,
                None => by_ecosystem.push((component.ecosystem.as_str(), 1)),
            }
        }
        by_ecosystem.sort_by_key(|(e, _)| e.to_lowercase());
        let ecosystems: Vec<String> = by_ecosystem
            .iter()
            .map(|(e, n)| count(*n, &format!("{e} package"), &format!("{e} packages")))
            .collect();
        let lockfiles: Vec<String> = self.lockfiles.iter().map(|l| format!("`{l}`")).collect();
        let ecosystems = crate::ast::and_list(&ecosystems);
        if lockfiles.is_empty() {
            ecosystems
        } else {
            format!(
                "{ecosystems}, read from {}",
                crate::ast::and_list(&lockfiles)
            )
        }
    }
}

/// Builds the bill of materials for an app folder.
pub fn build(app_dir: &Path) -> Sbom {
    build_in(&sv_scan::files::Listing::of(app_dir))
}

/// `build`, from a listing already made. `sv report` builds one bill of materials and hands it to
/// the lockfile check and the report; it used to build it twice, and `sv check` three times.
pub fn build_in(listing: &sv_scan::files::Listing) -> Sbom {
    let app_dir = listing.root.as_path();
    let mut sbom = Sbom::default();
    for eco in sv_scan::ecosystems::detect_in(listing) {
        read_ecosystem(app_dir, &eco, &mut sbom);
    }
    for declaration in sv_scan::ecosystems::python_declarations_in(listing) {
        read_declaration(app_dir, &declaration, &mut sbom);
    }
    sbom.components.sort_by(|a, b| {
        a.ecosystem
            .cmp(&b.ecosystem)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.version.cmp(&b.version))
    });
    sbom.components.dedup();
    sbom
}

fn read_ecosystem(app_dir: &Path, eco: &DetectedEcosystem, sbom: &mut Sbom) {
    // The file names below decide how each is read; the paths are where they really are, which for a
    // project in `server/` or a workspace member is not the top of the app folder.
    let lockfile_path = eco.lockfile.clone().unwrap_or_default();
    if !eco.passed_over.is_empty() {
        sbom.passed_over.push(PassedOver {
            project: eco.label(),
            read: lockfile_path.clone(),
            not_read: eco.passed_over.clone(),
        });
    }
    let read = |name: &str| {
        let path = if sv_scan::ecosystems::file_name(&lockfile_path) == name {
            lockfile_path.as_str()
        } else if sv_scan::ecosystems::file_name(&eco.manifest) == name {
            eco.manifest.as_str()
        } else {
            name
        };
        std::fs::read_to_string(app_dir.join(path)).ok()
    };

    let locked: Option<Vec<(String, String)>> = match eco
        .lockfile
        .as_deref()
        .map(sv_scan::ecosystems::file_name)
    {
        Some("package-lock.json") => read("package-lock.json").as_deref().map(from_package_lock),
        // npm-shrinkwrap.json is package-lock.json under another name.
        Some("npm-shrinkwrap.json") => read("npm-shrinkwrap.json")
            .as_deref()
            .map(from_package_lock),
        Some("Cargo.lock") => read("Cargo.lock").as_deref().map(from_package_table_toml),
        Some("poetry.lock") => read("poetry.lock").as_deref().map(from_package_table_toml),
        Some("pdm.lock") => read("pdm.lock").as_deref().map(from_package_table_toml),
        Some("uv.lock") => read("uv.lock").as_deref().map(from_package_table_toml),
        Some("Pipfile.lock") => {
            let text = read("Pipfile.lock");
            let (pairs, unversioned) = text.as_deref().map(from_pipfile_lock).unwrap_or_default();
            if !unversioned.is_empty() {
                // A package Pipenv installs from a repository or a folder is locked by its commit or
                // its path, with no version. It is installed all the same, so the list is not the
                // whole of what is, and dropping it without a word would read as if it were.
                sbom.unread.push((
                    eco.name.clone(),
                    format!(
                        "{} package(s) in `{lockfile_path}` give no version, because they are \
                         installed from a repository, a folder, or an address ({}), so they are \
                         not listed; the rest are",
                        unversioned.len(),
                        unversioned.join(", ")
                    ),
                ));
                if pairs.is_empty() {
                    return;
                }
            }
            text.map(|_| pairs)
        }
        Some("yarn.lock") => {
            let text = read("yarn.lock");
            let (pairs, unversioned) = text.as_deref().map(from_yarn_lock).unwrap_or_default();
            if note_unversioned(sbom, &eco.name, &lockfile_path, &unversioned) && pairs.is_empty() {
                return;
            }
            text.map(|_| pairs)
        }
        Some("bun.lock") => read("bun.lock").as_deref().map(from_bun_lock),
        Some("bun.lockb") => {
            sbom.unread.push((
                eco.name.clone(),
                format!(
                    "`bun.lockb` is Bun's binary lockfile, which `sv` cannot read, so nothing from {} is \
                     listed. Bun 1.2 and later write a text `bun.lock` instead (`bun install \
                     --save-text-lockfile` makes one), and `sv` reads that",
                    eco.name
                ),
            ));
            return;
        }
        Some("gradle.lockfile") => read("gradle.lockfile").as_deref().map(from_gradle_lockfile),
        Some("composer.lock") => read("composer.lock").as_deref().map(from_composer_lock),
        Some("Gemfile.lock") => read("Gemfile.lock").as_deref().map(from_gemfile_lock),
        Some("pnpm-lock.yaml") => {
            let text = read("pnpm-lock.yaml");
            let (pairs, unversioned) = text.as_deref().map(from_pnpm_lock).unwrap_or_default();
            if note_unversioned(sbom, &eco.name, &lockfile_path, &unversioned) && pairs.is_empty() {
                return;
            }
            text.map(|_| pairs)
        }
        Some("go.sum") => {
            let sum = read("go.sum");
            let modules = match read("go.mod") {
                Some(go_mod) => from_go_mod(&go_mod, sum.as_deref()),
                // No go.mod to say which version is used: every version go.sum holds, as before.
                None => GoModules {
                    pairs: sum.as_deref().map(from_go_sum).unwrap_or_default(),
                    local: Vec::new(),
                },
            };
            if !modules.local.is_empty() {
                sbom.unread.push((
                    eco.name.clone(),
                    format!(
                        "{} module(s) in go.mod are replaced by a folder on this computer ({}), so \
                         they have no published version and are not listed; the rest are",
                        modules.local.len(),
                        modules.local.join(", ")
                    ),
                ));
            }
            sum.map(|_| modules.pairs)
        }
        Some("requirements.lock") => read("requirements.lock")
            .as_deref()
            .map(from_pinned_requirements),
        // A requirements.txt that pins and hashes every package is its own lockfile (`detect_in`).
        Some("requirements.txt") => read("requirements.txt")
            .as_deref()
            .map(from_pinned_requirements),
        Some(name) if name.starts_with("pylock.") && name.ends_with(".toml") => {
            let text = std::fs::read_to_string(app_dir.join(&lockfile_path)).ok();
            let (pairs, unversioned) = text.as_deref().map(from_pylock).unwrap_or_default();
            if !unversioned.is_empty() {
                // PEP 751 lets a package installed from a folder, a repository, or an archive go
                // without a version. It is installed all the same, so the list is not the whole of
                // what is.
                sbom.unread.push((
                    eco.name.clone(),
                    format!(
                        "{} package(s) in `{lockfile_path}` give no version, because they are \
                         installed from a folder, a repository, or an archive ({}), so they are not \
                         listed; the rest are",
                        unversioned.len(),
                        unversioned.join(", ")
                    ),
                ));
            }
            text.map(|_| pairs)
        }
        Some(other) => {
            sbom.unread.push((
                eco.name.clone(),
                format!("`{other}` is a lockfile format `sv` cannot read yet, so nothing from {} is listed", eco.name),
            ));
            return;
        }
        None => None,
    };

    if let Some(pairs) = locked {
        if pairs.is_empty() {
            // The file was read and nothing came out of it: a format that changed under us, or one this
            // reader does not understand as well as it thinks. Either way the ecosystem is present, and
            // saying nothing about it reads exactly like having nothing to say.
            sbom.unread.push((
                eco.name.clone(),
                format!(
                    "`{}` was read and no packages could be taken from it, so nothing from {} is listed",
                    eco.lockfile.as_deref().unwrap_or("the lockfile"),
                    eco.name
                ),
            ));
            return;
        }
        // The list is the lockfile's. Whether the manifest beside it asks for the same thing is said
        // beside it (DESIGN, "When a manifest and its lockfile disagree").
        // A requirements.txt that is its own lockfile has nothing else to be compared with.
        let manifest_name = sv_scan::ecosystems::file_name(&eco.manifest);
        if lockfile_path != eco.manifest
            && let Some(manifest) = read(manifest_name)
            && let Some(comparison) =
                crate::manifest_lock::compare(manifest_name, &manifest, &pairs)
            && comparison != crate::manifest_lock::Comparison::default()
        {
            sbom.disagreements.push(Disagreement {
                project: eco.label(),
                manifest: eco.manifest.clone(),
                lockfile: lockfile_path.clone(),
                comparison,
            });
        }
        sbom.lockfiles.push(lockfile_path.clone());
        sbom.components
            .extend(pairs.into_iter().map(|(name, version)| Component {
                name,
                version,
                ecosystem: eco.name.clone(),
                source: VersionSource::Locked,
            }));
        return;
    }

    // No lockfile, or one that produced nothing. Fall back to the manifest and say what that means.
    let declared = match sv_scan::ecosystems::file_name(&eco.manifest) {
        "requirements.txt" => read("requirements.txt")
            .as_deref()
            .map(from_pinned_requirements),
        "Pipfile" => {
            let pipfile = read("Pipfile").as_deref().and_then(from_pipfile);
            if let Some((_, unpinned)) = &pipfile
                && !unpinned.is_empty()
            {
                // `"*"` and `">=2"` say which versions would do, not which one is there: such a
                // package is named here rather than listed at a version nobody installed.
                sbom.unread.push((
                    eco.name.clone(),
                    format!(
                        "`{}` has no `Pipfile.lock` beside it, and {} of its packages ask for a \
                         range or any version rather than one version ({}), so they are not listed; \
                         `pipenv lock` writes the lockfile `sv` reads",
                        eco.manifest,
                        unpinned.len(),
                        unpinned.join(", ")
                    ),
                ));
                if pipfile
                    .as_ref()
                    .is_some_and(|(pinned, _)| pinned.is_empty())
                {
                    return;
                }
            }
            pipfile.map(|(pinned, _)| pinned)
        }
        _ => None,
    };
    match declared {
        Some(pairs) if !pairs.is_empty() => {
            sbom.components.extend(pairs.into_iter().map(|(name, version)| Component {
                name,
                version,
                ecosystem: eco.name.clone(),
                source: VersionSource::Declared,
            }));
        }
        _ => sbom.unread.push((
            eco.name.clone(),
            format!(
                "{} is in use but nothing readable says which versions are installed, so none of its \
                 packages are listed",
                eco.name
            ),
        )),
    }
}

/// A Python dependency declaration that is not one of the manifests above (deep review H9).
///
/// Before these were looked for, an app whose packages were named only in `setup.py` or
/// `requirements-dev.txt` had a list that looked whole without them, and a comparison of that list
/// with advisories was credited as covering the app. Each is now read where it can be and named
/// where it cannot:
///
/// - A requirements file under another name that pins and hashes every package is a lockfile in
///   its own right, as `requirements.txt` is (`fully_hash_pinned`), and is read as one. Any other
///   is named: what it installs is not known, and a lockfile beside it says nothing about it,
///   since `requirements-dev.txt` is usually the very list a lockfile beside it leaves out.
/// - `setup.py` and `setup.cfg` are named unless a Python lockfile in the same folder was read: a
///   lockfile is made from what the project asks for, `setup.py` included (`pipenv install -e .`,
///   `pip-compile setup.py`), so it stands for the file. Their own contents are code or
///   configuration `sv` does not evaluate.
/// - A Conda `environment.yml` is always named: its packages come from Conda's channels, which no
///   reader here understands and PyPI's advisories do not describe.
fn read_declaration(
    app_dir: &Path,
    declaration: &sv_scan::ecosystems::PythonDeclaration,
    sbom: &mut Sbom,
) {
    use sv_scan::ecosystems::DeclarationKind;
    let path = &declaration.path;
    let why = match declaration.kind {
        DeclarationKind::Requirements => {
            let text = std::fs::read_to_string(app_dir.join(path)).ok();
            if let Some(text) = text.as_deref()
                && sv_scan::ecosystems::fully_hash_pinned(text)
            {
                sbom.lockfiles.push(path.clone());
                sbom.components
                    .extend(
                        from_pinned_requirements(text)
                            .into_iter()
                            .map(|(name, version)| Component {
                                name,
                                version,
                                ecosystem: "Python".into(),
                                source: VersionSource::Locked,
                            }),
                    );
                return;
            }
            format!(
                "`{path}` lists Python packages to install and does not pin and hash every one of \
                 them, so what it installs is not known and none of it is listed; `pip-compile \
                 --generate-hashes` writes one that `sv` reads"
            )
        }
        DeclarationKind::Setup if declaration.beside_lockfile => return,
        DeclarationKind::Setup => format!(
            "`{path}` names Python packages to install, which `sv` does not read, and no Python \
             lockfile beside it says which versions are installed, so they are not listed; a \
             lockfile made from it (`pip-compile --generate-hashes {path}`, `pipenv lock`, or \
             `uv lock`) is read"
        ),
        DeclarationKind::Conda => format!(
            "`{path}` is a Conda environment, whose packages come from Conda's channels; `sv` \
             does not read it, so none of them is listed"
        ),
    };
    sbom.unread.push(("Python".into(), why));
}

/// Names the packages a lockfile lists with no version, as not listed. They are installed all the
/// same, from a folder, a link, a repository, or an address, so the list is not the whole of what
/// is, and dropping them without a word would read as if it were. `true` when there were any.
fn note_unversioned(sbom: &mut Sbom, ecosystem: &str, lockfile: &str, names: &[String]) -> bool {
    if names.is_empty() {
        return false;
    }
    sbom.unread.push((
        ecosystem.to_owned(),
        format!(
            "{} package(s) in `{lockfile}` give no version, because they are installed from a \
             folder, a link, a repository, or an address ({}), so they are not listed; the rest are",
            names.len(),
            names.join(", ")
        ),
    ));
    true
}

// ---------------------------------------------------------------------------------------------
// Lockfile readers. Each returns (name, version) pairs; none guesses.

fn from_package_lock(text: &str) -> Vec<(String, String)> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    // Lockfile v2/v3: a "packages" map keyed by path, where "" is the app itself.
    if let Some(map) = v.get("packages").and_then(|p| p.as_object()) {
        for (path, entry) in map {
            if path.is_empty() {
                continue;
            }
            let name = entry
                .get("name")
                .and_then(|n| n.as_str())
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    path.rsplit("node_modules/")
                        .next()
                        .unwrap_or(path)
                        .to_owned()
                });
            if let Some(version) = entry.get("version").and_then(|x| x.as_str()) {
                out.push((name, version.to_owned()));
            }
        }
    }
    // Lockfile v1: a nested "dependencies" map.
    if out.is_empty()
        && let Some(map) = v.get("dependencies").and_then(|p| p.as_object())
    {
        package_lock_v1(map, &mut out);
    }
    out
}

/// Lockfile v1 nests a package's own copy of another under that package's `dependencies`, when it
/// needs a version the top level does not have. Those copies are installed too, so each is listed.
fn package_lock_v1(
    map: &serde_json::Map<String, serde_json::Value>,
    out: &mut Vec<(String, String)>,
) {
    for (name, entry) in map {
        if let Some(version) = entry.get("version").and_then(|x| x.as_str()) {
            out.push((name.clone(), version.to_owned()));
        }
        if let Some(nested) = entry.get("dependencies").and_then(|d| d.as_object()) {
            package_lock_v1(nested, out);
        }
    }
}

/// TOML lockfiles built from `[[package]]` tables: Cargo, Poetry, PDM and uv all use this shape.
fn from_package_table_toml(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let (mut name, mut version) = (None, None);
    for line in text.lines().map(str::trim) {
        if line == "[[package]]" {
            name = None;
            version = None;
            continue;
        }
        if let Some(rest) = line.strip_prefix("name = ") {
            name = Some(rest.trim_matches('"').to_owned());
        } else if let Some(rest) = line.strip_prefix("version = ") {
            version = Some(rest.trim_matches('"').to_owned());
        }
        if let (Some(n), Some(v)) = (&name, &version) {
            out.push((n.clone(), v.clone()));
            name = None;
            version = None;
        }
    }
    out
}

/// `Pipfile.lock` is JSON, and its versions carry the `==` with them.
///
/// Every section is read: `default`, `develop` (development packages are listed, as every other
/// ecosystem's are), and any other package category the `Pipfile` adds; `_meta` is the only key
/// that is not packages. Gives the pairs, and the names of the packages with no version: those
/// installed from a repository, a folder, or an address, which Pipenv locks by commit or path.
/// The app's own folder (`"path": "."`, what `pipenv install -e .` writes) is the app, not a
/// package it depends on, and is left out of both.
fn from_pipfile_lock(text: &str) -> (Vec<(String, String)>, Vec<String>) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return (Vec::new(), Vec::new());
    };
    let (mut pairs, mut unversioned) = (Vec::new(), Vec::new());
    for (section, packages) in v.as_object().into_iter().flatten() {
        if section == "_meta" {
            continue;
        }
        for (name, entry) in packages.as_object().into_iter().flatten() {
            match entry.get("version").and_then(|x| x.as_str()) {
                // "==3.0.0" is a pin written as a specifier; the version is what follows it.
                Some(version) => {
                    pairs.push((name.clone(), version.trim_start_matches("==").to_owned()))
                }
                None if entry.get("path").and_then(|p| p.as_str()) == Some(".") => {}
                None => unversioned.push(name.clone()),
            }
        }
    }
    unversioned.sort();
    unversioned.dedup();
    (pairs, unversioned)
}

/// The packages a manifest pins to one version, and the names of the rest.
type Pinned = (Vec<(String, String)>, Vec<String>);

/// A `Pipfile` read as a manifest, for when there is no `Pipfile.lock`: the packages pinned to one
/// version (`"==2.2.0"`, or a table whose `version` is that), and the names of the rest, which
/// ask for a range, for any version (`"*"`), or for a repository or a folder. `None` when it is
/// not TOML.
fn from_pipfile(text: &str) -> Option<Pinned> {
    let doc: toml::Table = text.parse().ok()?;
    let (mut pinned, mut rest) = (Vec::new(), Vec::new());
    for (category, packages) in &doc {
        if sv_scan::deps::PIPFILE_NOT_PACKAGES.contains(&category.as_str()) {
            continue;
        }
        for (name, value) in packages.as_table().into_iter().flatten() {
            let asked = match value {
                toml::Value::String(v) => Some(v.as_str()),
                toml::Value::Table(t) => t.get("version").and_then(|v| v.as_str()),
                _ => None,
            };
            let exact = asked
                .map(str::trim)
                .and_then(|v| v.strip_prefix("===").or_else(|| v.strip_prefix("==")))
                .map(str::trim)
                .filter(|v| !v.is_empty() && !v.contains([',', '*', ' ', ';']));
            match exact {
                Some(version) => pinned.push((name.clone(), version.to_owned())),
                None => rest.push(name.clone()),
            }
        }
    }
    rest.sort();
    rest.dedup();
    Some((pinned, rest))
}

/// Yarn's lockfile, classic or Berry: a header line naming one or more ranges, then an indented
/// version.
///
/// The header is the *range* that was asked for, which is not the package name — `lodash@^4.17.0` and
/// `lodash@~4.17.20` are two headers for one package. Classic Yarn (v1) writes `version "4.17.21"`,
/// and the name is everything before the last `@`, so a scoped package like `@babel/core@^7` keeps its
/// scope. Yarn 2 and later ("Berry", which starts the file with `__metadata:`) write `version: 4.17.21`
/// and put a protocol in each range, `lodash@npm:^4.17.0`, so there the name ends at the first `@`
/// after any scope, and only packages from the registry are listed: the app itself
/// (`@workspace:`), and anything linked from a folder, are not packages anyone publishes advisories
/// about.
/// Yarn's `yarn.lock`, classic (v1) or Berry (v2 and later). Gives the pairs, and the names of the
/// packages it lists with no version from a registry: in Berry, those from a folder, a link, or a
/// repository (`file:`, `link:`, `portal:`, `git`, `https:`, ...); in classic, an entry with no
/// `version` line. The app's own workspaces (`workspace:`) are its own code and are left out.
fn from_yarn_lock(text: &str) -> (Vec<(String, String)>, Vec<String>) {
    let berry = text.lines().any(|l| l.trim_end() == "__metadata:");
    let mut out: Vec<(String, String)> = Vec::new();
    let mut unversioned: Vec<String> = Vec::new();
    let mut pending: Option<String> = None;
    for line in text.lines() {
        if line.trim_start().starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            // A classic entry that never said its version.
            if let Some(name) = pending.take()
                && !berry
            {
                unversioned.push(name);
            }
            // A header may list several ranges separated by commas; they are all the same package.
            let first = line.trim_end_matches(':').split(',').next().unwrap_or(line);
            let spec = first.trim().trim_matches('"');
            if spec == "__metadata" {
                continue;
            }
            pending = if berry {
                let at = spec
                    .char_indices()
                    .skip(1)
                    .find(|(_, c)| *c == '@')
                    .map(|(i, _)| i);
                match at {
                    Some(i) => {
                        let protocol = &spec[i + 1..];
                        if protocol.starts_with("npm:") || protocol.starts_with("patch:") {
                            Some(spec[..i].to_owned())
                        } else {
                            if !protocol.starts_with("workspace:") {
                                unversioned.push(spec[..i].to_owned());
                            }
                            None
                        }
                    }
                    None => None,
                }
            } else {
                spec.rfind('@')
                    .filter(|i| *i > 0)
                    .map(|i| spec[..i].to_owned())
            };
            continue;
        }
        let version = if berry {
            line.trim().strip_prefix("version:")
        } else {
            line.trim().strip_prefix("version ")
        };
        if let Some(rest) = version
            && let Some(name) = pending.take()
        {
            out.push((name, rest.trim().trim_matches('"').to_owned()));
        }
    }
    if let Some(name) = pending
        && !berry
    {
        unversioned.push(name);
    }
    out.sort();
    out.dedup();
    unversioned.sort();
    unversioned.dedup();
    (out, unversioned)
}

/// Bun's text lockfile (Bun 1.2 and later): JSON that allows a comma before a closing bracket.
/// `packages` maps each install path to an array whose first entry is `name@version`. An entry
/// whose version names a protocol (`workspace:`, `file:`, `github:`, and the like) is not a package
/// from the registry, and is left out as Yarn's are.
fn from_bun_lock(text: &str) -> Vec<(String, String)> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&without_trailing_commas(text)) else {
        return Vec::new();
    };
    let mut out: Vec<(String, String)> = v
        .get("packages")
        .and_then(|p| p.as_object())
        .into_iter()
        .flat_map(|p| p.values())
        .filter_map(|entry| entry.get(0)?.as_str())
        .filter_map(|spec| {
            let at = spec.rfind('@').filter(|i| *i > 0)?;
            let (name, version) = (&spec[..at], &spec[at + 1..]);
            (!name.is_empty() && !version.is_empty() && !version.contains(':'))
                .then(|| (name.to_owned(), version.to_owned()))
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// JSON with every comma that stands just before a `}` or `]` removed, outside strings.
fn without_trailing_commas(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let (mut in_string, mut escaped) = (false, false);
    for (i, &c) in chars.iter().enumerate() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        if c == '"' {
            in_string = true;
        } else if c == ','
            && chars[i + 1..]
                .iter()
                .find(|n| !n.is_whitespace())
                .is_some_and(|n| *n == '}' || *n == ']')
        {
            continue;
        }
        out.push(c);
    }
    out
}

/// Gradle's lockfile: `group:artifact:version=configuration,configuration`.
fn from_gradle_lockfile(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split('=').next())
        .filter_map(|coord| {
            // `group:artifact:version`; the version follows the last colon. A line with no colon at
            // all is Gradle's `empty=configuration` marker, which is not a package.
            let (name, version) = coord.rsplit_once(':')?;
            (!version.is_empty() && !name.is_empty()).then(|| (name.to_owned(), version.to_owned()))
        })
        .collect()
}

fn from_composer_lock(text: &str) -> Vec<(String, String)> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for key in ["packages", "packages-dev"] {
        if let Some(list) = v.get(key).and_then(|p| p.as_array()) {
            for entry in list {
                if let (Some(n), Some(ver)) = (
                    entry.get("name").and_then(|x| x.as_str()),
                    entry.get("version").and_then(|x| x.as_str()),
                ) {
                    out.push((n.to_owned(), ver.to_owned()));
                }
            }
        }
    }
    out
}

/// pnpm's lockfile, read without a YAML parser.
///
/// Deliberate. The only YAML needed here is the set of keys directly under `packages:`, and the
/// established serde YAML crate has been archived since 2024 — putting an unmaintained parser into a tool
/// whose subject is supply-chain hygiene is a poor trade for one file format. So this reads the one block
/// it needs and refuses to guess at anything else.
///
/// Returns an empty list when the file does not look like a pnpm lockfile it understands. The caller
/// turns that into "read, and no packages could be taken from it", which is the honest thing to tell
/// somebody and is checked one place rather than two — an inner guard here duplicated it and could be
/// deleted without any test noticing.
///
/// Two key shapes, and peer suffixes on either:
///   v9:  `express@4.18.2:` and `@babel/core@7.23.0:`, sometimes `vite@5.0.0(terser@5.0.0):`
///   v6:  `/express@4.18.2:` and `/@babel/core@7.23.0:`, with peer variants in brackets as in v9
///   v5:  `/express/4.18.2:` and `/@babel/core/7.23.0:`, sometimes `/foo/1.0.0_bar@2.0.0:`
fn from_pnpm_lock(text: &str) -> (Vec<(String, String)>, Vec<String>) {
    let mut out = Vec::new();
    let mut unversioned = Vec::new();
    let mut in_packages = false;
    // Lockfile 5.x writes `/name/version`, with a peer variant after `_`; 6.0 and later write
    // `/name@version` and `name@version`, with a peer variant in brackets. Without the version
    // line, the `@` shape is tried first and the slash shape after it.
    let slash_shape = text
        .lines()
        .find_map(|l| l.strip_prefix("lockfileVersion:"))
        .map(|v| v.trim().trim_matches(|c| c == '\'' || c == '"'))
        .and_then(|v| v.split('.').next()?.parse::<u32>().ok())
        .is_some_and(|major| major <= 5);

    for line in text.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        // A key at column zero ends whatever block we were in.
        if !line.starts_with(' ') {
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        if !in_packages {
            continue;
        }
        // Only the block's own keys, which are indented one level; anything deeper describes a package.
        let indent = line.len() - line.trim_start().len();
        if indent != 2 {
            continue;
        }
        let key = line.trim();
        let Some(key) = key.strip_suffix(':') else {
            continue;
        };
        let key = key.trim_matches(|c| c == '\'' || c == '"');
        // `vite@5.0.0(terser@5.0.0)` is one package with a peer variant, not two.
        let key = key.split('(').next().unwrap_or(key);
        let rest = key.strip_prefix('/').unwrap_or(key);

        let by_at = || {
            // name@version, where a scoped name contains its own @.
            rest.rsplit_once('@')
                .filter(|(name, _)| !name.is_empty())
                .map(|(name, version)| (name.to_owned(), version.to_owned()))
        };
        let by_slash = || {
            // name/version, where a scoped name contains a slash of its own, and the version may
            // carry a peer variant after `_`.
            rest.rsplit_once('/').map(|(name, version)| {
                let version = version.split('_').next().unwrap_or(version);
                (name.to_owned(), version.to_owned())
            })
        };
        let parsed = if slash_shape {
            by_slash()
        } else {
            by_at().or_else(by_slash)
        };
        // A version starts with a digit. A key whose version is an address (`file:`, `https:`,
        // `link:`) is a package installed from somewhere else, named as such; a key that fits
        // neither shape is not invented into a package.
        match parsed {
            Some((name, version)) if version.starts_with(|c: char| c.is_ascii_digit()) => {
                out.push((name, version));
            }
            Some((name, version)) if version.contains(':') => unversioned.push(name),
            _ => {}
        }
    }

    out.sort();
    out.dedup();
    unversioned.sort();
    unversioned.dedup();
    (out, unversioned)
}

fn from_gemfile_lock(text: &str) -> Vec<(String, String)> {
    // Specs are indented four spaces under `specs:`; their dependencies are indented six and are not
    // separate packages.
    let mut out = Vec::new();
    let mut in_specs = false;
    for line in text.lines() {
        let trimmed = line.trim_end();
        if trimmed.trim() == "specs:" {
            in_specs = true;
            continue;
        }
        if in_specs && !trimmed.starts_with("    ") {
            in_specs = false;
        }
        if !in_specs || trimmed.starts_with("      ") {
            continue;
        }
        let entry = trimmed.trim();
        // `nokogiri (1.15.4-x86_64-linux)`: Bundler writes a gem built for one platform with the
        // platform after the first `-`, and reads it back the same way, so the version is what
        // comes before it. Kept, the platform would read as a pre-release of 1.15.4.
        if let Some((name, rest)) = entry.split_once(" (")
            && let Some(version) = rest.strip_suffix(')')
        {
            let version = version.split('-').next().unwrap_or(version);
            out.push((name.to_owned(), version.to_owned()));
        }
    }
    out
}

/// What go.mod says is built: one version of each module, and the modules swapped for a folder.
#[derive(Debug, Default)]
struct GoModules {
    pairs: Vec<(String, String)>,
    local: Vec<String>,
}

/// The modules a Go app is built from, and the one version of each, from go.mod: its `require`
/// lines, with its `replace` lines applied. go.sum keeps a checksum for every version Go has looked
/// at, older ones included, so reading it as the versions in use reported versions the app no
/// longer builds with (A3 of the deep review).
///
/// From Go 1.17 on, go.mod lists every module in the build, indirect ones too. Before it, or with no
/// `go` line, which Go reads as 1.16, it may not, and a module named only in go.sum is given the
/// highest version there: the one Go would choose whenever go.sum holds the version it chose.
fn from_go_mod(go_mod: &str, go_sum: Option<&str>) -> GoModules {
    let words = |line: &str| -> Vec<String> {
        let line = line.split("//").next().unwrap_or("");
        line.split_whitespace()
            .map(|w| w.trim_matches('"').to_owned())
            .collect()
    };
    let (mut required, mut replaces) = (Vec::<(String, String)>::new(), Vec::new());
    let mut go_version: Option<String> = None;
    let mut block: Option<String> = None;
    for raw in go_mod.lines() {
        let w = words(raw);
        if w.is_empty() {
            continue;
        }
        if block.is_some() && w[0] == ")" {
            block = None;
            continue;
        }
        if block.is_none() && w.get(1).is_some_and(|x| x == "(") {
            block = Some(w[0].clone());
            continue;
        }
        let (verb, rest): (&str, &[String]) = match &block {
            Some(verb) => (verb.as_str(), &w[..]),
            None => (w[0].as_str(), &w[1..]),
        };
        match verb {
            "go" => go_version = rest.first().cloned(),
            "require" if rest.len() >= 2 => required.push((rest[0].clone(), rest[1].clone())),
            "replace" => {
                if let Some(arrow) = rest.iter().position(|x| x == "=>") {
                    let old = &rest[..arrow];
                    let new = &rest[arrow + 1..];
                    if let (Some(old_path), Some(new_path)) = (old.first(), new.first()) {
                        replaces.push((
                            old_path.clone(),
                            old.get(1).cloned(),
                            new_path.clone(),
                            new.get(1).cloned(),
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    // Before 1.17, go.mod may leave out the indirect modules; go.sum names them.
    let lists_everything = go_version.as_deref().is_some_and(|v| {
        crate::advisories::compare(v, "1.17").is_some_and(|o| o != std::cmp::Ordering::Less)
    });
    if !lists_everything && let Some(sum) = go_sum {
        let mut highest: Vec<(String, String)> = Vec::new();
        for (name, version) in from_go_sum(sum) {
            if required.iter().any(|(r, _)| *r == name) {
                continue;
            }
            match highest.iter_mut().find(|(n, _)| *n == name) {
                Some((_, kept)) => {
                    if crate::advisories::compare(&version, kept)
                        == Some(std::cmp::Ordering::Greater)
                    {
                        *kept = version;
                    }
                }
                None => highest.push((name, version)),
            }
        }
        required.extend(highest);
    }
    let mut out = GoModules::default();
    for (name, version) in required {
        let replaced = replaces
            .iter()
            .find(|(old, old_version, _, _)| {
                *old == name && old_version.as_ref().is_none_or(|v| *v == version)
            })
            .map(|(_, _, new, new_version)| (new.clone(), new_version.clone()));
        match replaced {
            None => out.pairs.push((name, version)),
            Some((new, Some(new_version))) => out.pairs.push((new, new_version)),
            Some((_, None)) => out.local.push(name),
        }
    }
    out
}

fn from_go_sum(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(version)) = (parts.next(), parts.next()) else {
            continue;
        };
        // `module v1.2.3/go.mod h1:…` repeats the module; keep the one naming the module itself.
        if version.ends_with("/go.mod") {
            continue;
        }
        out.push((name.to_owned(), version.to_owned()));
    }
    out
}

/// Exact pins only. `flask>=2` says which versions are acceptable, not which one is there.
/// A line may end in an environment marker, `colorama==0.4.6 ; sys_platform == 'win32'`, with or
/// without the space before the `;`. The marker is not read: the package is listed wherever it would
/// be installed, which for the comparison with advisories is the safe side, and makes the list say
/// slightly more than one computer installs.
/// PEP 751's `pylock.toml`: a `[[packages]]` entry for everything installed, transitive
/// dependencies included, each with its `name` and, when it comes from an index, its `version`. A
/// TOML reading rather than a line one: each package's `[[packages.wheels]]` carry a `name` too,
/// which is a file name. Gives the pairs, and the names of the packages with no version.
fn from_pylock(text: &str) -> (Vec<(String, String)>, Vec<String>) {
    let Ok(table) = text.parse::<toml::Table>() else {
        return (Vec::new(), Vec::new());
    };
    let (mut pairs, mut unversioned) = (Vec::new(), Vec::new());
    for package in table
        .get("packages")
        .and_then(|p| p.as_array())
        .into_iter()
        .flatten()
    {
        let Some(name) = package.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        match package.get("version").and_then(|v| v.as_str()) {
            Some(version) => pairs.push((name.to_owned(), version.to_owned())),
            None => unversioned.push(name.to_owned()),
        }
    }
    (pairs, unversioned)
}

fn from_pinned_requirements(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(|l| {
            l.split_once(';')
                .map_or(l, |(requirement, _marker)| requirement)
        })
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('-'))
        .filter_map(|l| l.split_once("=="))
        .map(|(name, version)| {
            // `name[extra]==1.0` installs `name`.
            let name = name.split('[').next().unwrap_or(name);
            (
                name.trim().to_owned(),
                version
                    .trim_start_matches('=')
                    .split_whitespace()
                    .next()
                    .unwrap_or(version)
                    .trim()
                    .to_owned(),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// CycloneDX

#[derive(Serialize)]
struct CycloneComponent {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    version: String,
    purl: String,
    properties: Vec<Property>,
}

#[derive(Serialize)]
struct Property {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct Metadata {
    tools: Vec<Tool>,
    properties: Vec<Property>,
}

#[derive(Serialize)]
struct Tool {
    vendor: &'static str,
    name: &'static str,
}

#[derive(Serialize)]
pub struct CycloneDx {
    #[serde(rename = "bomFormat")]
    bom_format: &'static str,
    #[serde(rename = "specVersion")]
    spec_version: &'static str,
    version: u32,
    metadata: Metadata,
    components: Vec<CycloneComponent>,
}

/// Renders the bill of materials as CycloneDX 1.5 JSON.
///
/// The completeness caveats go in `metadata.properties` rather than only in the terminal, because the
/// document is the thing that gets sent to somebody else, and a caveat that stays behind is not a caveat.
pub fn to_cyclonedx(sbom: &Sbom) -> CycloneDx {
    let mut properties = vec![Property {
        name: "securevibe:complete".into(),
        value: sbom.is_complete().to_string(),
    }];
    if sbom.declared_count() > 0 {
        properties.push(Property {
            name: "securevibe:declared-versions".into(),
            value: format!(
                "{} component(s) carry the version that was asked for, not the version installed",
                sbom.declared_count()
            ),
        });
    }
    for (eco, why) in &sbom.unread {
        properties.push(Property {
            name: format!("securevibe:unread:{eco}"),
            value: why.clone(),
        });
    }
    for passed in &sbom.passed_over {
        properties.push(Property {
            name: format!("securevibe:lockfile-passed-over:{}", passed.project),
            value: passed.explain(),
        });
    }
    for disagreement in &sbom.disagreements {
        if disagreement.differs() {
            properties.push(Property {
                name: format!("securevibe:manifest-disagrees:{}", disagreement.project),
                value: disagreement.explain(),
            });
        }
        if !disagreement.comparison.not_compared.is_empty() {
            properties.push(Property {
                name: format!("securevibe:manifest-not-compared:{}", disagreement.project),
                value: disagreement.explain_not_compared(),
            });
        }
    }

    CycloneDx {
        bom_format: "CycloneDX",
        spec_version: "1.5",
        version: 1,
        metadata: Metadata {
            tools: vec![Tool {
                vendor: "SecureVibe",
                name: "sv",
            }],
            properties,
        },
        components: sbom
            .components
            .iter()
            .map(|c| CycloneComponent {
                kind: "library",
                bom_ref: c.purl(),
                name: c.name.clone(),
                version: c.version.clone(),
                purl: c.purl(),
                properties: vec![Property {
                    name: "securevibe:version-source".into(),
                    value: match c.source {
                        VersionSource::Locked => "locked: this is what is installed".into(),
                        VersionSource::Declared => {
                            "declared: this is what was asked for, and may be a range".to_string()
                        }
                    },
                }],
            })
            .collect(),
    }
}

/// A finding when the bill of materials cannot be trusted as a complete list.
/// The requirement a complete bill of materials is evidence about: an inventory catalog of every
/// third-party library in use. Named once so the check and `sv coverage` cannot disagree.
pub const INVENTORY_REQUIREMENT: &str = "V15.1.2";

/// What the bill of materials may claim to be, when it is complete enough to claim anything.
///
/// The mirror of `incompleteness_finding`: exactly one of the two speaks, and which one is decided
/// by `is_complete`, so a document cannot be reported as both incomplete and a good inventory. An
/// empty list is not a complete inventory either — an app with no dependencies `sv` could find is
/// far more often an app whose manifests were not read than an app with no dependencies.
/// "1 package", "2 packages".
pub(crate) fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

pub fn completeness_verified(sbom: &Sbom) -> Option<crate::verified::Verified> {
    if !sbom.is_complete() || sbom.components.is_empty() {
        return None;
    }
    Some(crate::verified::Verified::new(
        "sbom",
        &[INVENTORY_REQUIREMENT],
        format!(
            "an inventory of {} third-party librar{}, each at the version actually installed, from \
             every ecosystem found in the app ({}), with the packages those need and the development \
             packages each lockfile keeps",
            sbom.components.len(),
            if sbom.components.len() == 1 {
                "y"
            } else {
                "ies"
            },
            sbom.what_was_read()
        ),
    ))
}

pub fn incompleteness_finding(sbom: &Sbom) -> Option<Finding> {
    if sbom.is_complete() {
        return None;
    }
    let mut reasons: Vec<String> = sbom.unread.iter().map(|(_, why)| why.clone()).collect();
    if sbom.declared_count() > 0 {
        reasons.push(format!(
            "{} package(s) are listed at the version asked for rather than the version installed",
            sbom.declared_count()
        ));
    }
    Some(Finding {
            also_reported_by: Vec::new(),
            fingerprint: String::new(),
            earlier_fingerprints: Vec::new(),
            marked_test_code: false,
        rule_id: "sbom.incomplete".into(),
        title: "The list of what this app ships is not complete".into(),
        severity: Severity::Medium,
        confidence: Confidence::High,
        location: Location { file: "sbom.cdx.json".into(), line: 1 },
        secret: None,
        // V15.1.2 asks that an inventory catalog — a software bill of materials — is
        // maintained of every third-party library in use. This finding says that catalog is not
        // complete, which is the thing that requirement is about. It cited V1.3.5 until 24
        // September 2026, which is about sanitizing user-supplied template and stylesheet content
        // and has nothing whatever to do with dependencies.
        requirement_ids: vec!["V15.1.2".into()],
        cwe: vec!["CWE-1104".into()],
        description: reasons.join("; "),
        impact: "A bill of materials is worth the completeness of its list. Asked whether a compromised \
                 version of some library is in this app, nobody could answer from this document."
            .into(),
        fix: "Commit a lockfile for every ecosystem in use, and install from it.".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sv-sbom-{name}-{}", std::process::id()));
        fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_locked_npm_app_lists_what_is_installed() {
        let dir = scratch("npm");
        fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
        fs::write(
            dir.join("package-lock.json"),
            r#"{"packages":{"":{"name":"app"},"node_modules/express":{"version":"4.18.2"}}}"#,
        )
        .unwrap();
        let sbom = build(&dir);
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].name, "express");
        assert_eq!(sbom.components[0].version, "4.18.2");
        assert_eq!(sbom.components[0].source, VersionSource::Locked);
        assert_eq!(sbom.components[0].purl(), "pkg:npm/express@4.18.2");
        assert!(sbom.is_complete());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_npm_v1_lockfile_lists_the_copies_installed_under_other_packages() {
        // Lockfile v1 keeps a second version of a package under the one that needs it. That copy is
        // installed, and an advisory against it is about this app, so it is listed by its own name.
        let dir = scratch("npm-v1");
        fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
        fs::write(
            dir.join("package-lock.json"),
            r#"{"name":"app","lockfileVersion":1,"dependencies":{
                "express":{"version":"4.18.2","dependencies":{
                    "debug":{"version":"2.6.9","dependencies":{
                        "ms":{"version":"2.0.0"}}}}},
                "debug":{"version":"4.3.4"},
                "ms":{"version":"2.1.2"}}}"#,
        )
        .unwrap();
        let sbom = build(&dir);
        fs::remove_dir_all(&dir).ok();
        let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
        assert_eq!(
            purls,
            vec![
                "pkg:npm/debug@2.6.9",
                "pkg:npm/debug@4.3.4",
                "pkg:npm/express@4.18.2",
                "pkg:npm/ms@2.0.0",
                "pkg:npm/ms@2.1.2",
            ],
            "{sbom:?}"
        );
        assert!(sbom.is_complete(), "{sbom:?}");
    }

    #[test]
    fn a_range_is_not_a_version_and_the_document_says_so() {
        // requirements.txt with no lockfile: `flask>=2` tells nobody what is installed. Listing it as
        // though it were a version is the failure this whole module is arranged around.
        let dir = scratch("ranges");
        fs::write(dir.join("requirements.txt"), "flask>=2.0\ngunicorn\n").unwrap();
        let sbom = build(&dir);
        assert!(
            sbom.components.is_empty(),
            "a range must not become a component: {sbom:?}"
        );
        assert!(!sbom.is_complete());
        assert!(!sbom.unread.is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn exact_pins_are_read_and_marked_as_declared() {
        let dir = scratch("pins");
        fs::write(
            dir.join("requirements.txt"),
            "flask==3.0.0\nstripe==7.8.0\n",
        )
        .unwrap();
        let sbom = build(&dir);
        assert_eq!(sbom.components.len(), 2);
        assert!(
            sbom.components
                .iter()
                .all(|c| c.source == VersionSource::Declared)
        );
        // Declared is not complete: nothing has confirmed that is what is installed.
        assert!(!sbom.is_complete());
        assert_eq!(sbom.declared_count(), 2);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_caveats_travel_with_the_document() {
        // The terminal is not where an SBOM ends up. Someone receives this file and asks it a question.
        let dir = scratch("caveats");
        fs::write(dir.join("requirements.txt"), "flask==3.0.0\n").unwrap();
        let sbom = build(&dir);
        let json = serde_json::to_string(&to_cyclonedx(&sbom)).unwrap();
        assert!(json.contains("securevibe:complete"), "{json}");
        assert!(json.contains("\"value\":\"false\""), "{json}");
        assert!(json.contains("asked for"), "{json}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_complete_document_does_not_carry_a_warning_it_has_not_earned() {
        let dir = scratch("clean");
        fs::write(dir.join("Cargo.toml"), "[package]\nname='x'\n").unwrap();
        fs::write(
            dir.join("Cargo.lock"),
            "[[package]]\nname = \"serde\"\nversion = \"1.0.229\"\n",
        )
        .unwrap();
        let sbom = build(&dir);
        assert!(sbom.is_complete(), "{sbom:?}");
        assert!(incompleteness_finding(&sbom).is_none());
        assert_eq!(sbom.components[0].purl(), "pkg:cargo/serde@1.0.229");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn poetry_pdm_and_uv_share_cargos_shape() {
        for (manifest, lock) in [
            ("pyproject.toml", "poetry.lock"),
            ("pyproject.toml", "pdm.lock"),
            ("pyproject.toml", "uv.lock"),
        ] {
            let dir = scratch(&format!("toml-{lock}"));
            fs::write(dir.join(manifest), "[project]\nname='x'\n").unwrap();
            fs::write(
                dir.join(lock),
                "[[package]]\nname = \"flask\"\nversion = \"3.0.0\"\ndescription = \"web\"\n",
            )
            .unwrap();
            let sbom = build(&dir);
            assert_eq!(sbom.components.len(), 1, "{lock}: {sbom:?}");
            assert_eq!(sbom.components[0].purl(), "pkg:pypi/flask@3.0.0", "{lock}");
            assert!(sbom.is_complete(), "{lock} should be a complete read");
            fs::remove_dir_all(&dir).ok();
        }
    }

    /// A `pylock.toml` as pip writes it, cut down: each package's wheels carry a `name` that is a
    /// file name, which must not be read as a package.
    const PYLOCK: &str = r#"lock-version = "1.0"
created-by = "pip"
requires-python = ">=3.12"

[[packages]]
name = "flask"
version = "3.1.3"

[[packages.wheels]]
name = "flask-3.1.3-py3-none-any.whl"
url = "https://files.pythonhosted.org/flask-3.1.3-py3-none-any.whl"
hashes = { sha256 = "0000" }

[[packages]]
name = "werkzeug"
version = "3.1.9"

[[packages.wheels]]
name = "werkzeug-3.1.9-py3-none-any.whl"
hashes = { sha256 = "0000" }
"#;

    #[test]
    fn a_pylock_file_is_read_as_the_list_of_what_is_installed() {
        let dir = scratch("pylock-read");
        fs::write(dir.join("requirements.txt"), "flask>=3\n").unwrap();
        fs::write(dir.join("pylock.toml"), PYLOCK).unwrap();
        let sbom = build(&dir);
        fs::remove_dir_all(&dir).ok();
        let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
        assert_eq!(
            purls,
            vec!["pkg:pypi/flask@3.1.3", "pkg:pypi/werkzeug@3.1.9"],
            "{sbom:?}"
        );
        assert!(
            sbom.components
                .iter()
                .all(|c| c.source == VersionSource::Locked)
        );
        assert!(sbom.is_complete(), "{sbom:?}");
    }

    #[test]
    fn a_pylock_package_with_no_version_leaves_the_list_incomplete_and_says_so() {
        let dir = scratch("pylock-unversioned");
        fs::write(dir.join("pyproject.toml"), "[project]\nname = \"demo\"\n").unwrap();
        fs::write(
            dir.join("pylock.toml"),
            format!(
                "{PYLOCK}\n[[packages]]\nname = \"local-tools\"\n\n[packages.directory]\npath = \"./tools\"\n"
            ),
        )
        .unwrap();
        let sbom = build(&dir);
        fs::remove_dir_all(&dir).ok();
        assert_eq!(sbom.components.len(), 2, "{sbom:?}");
        assert!(!sbom.is_complete());
        assert!(
            sbom.unread
                .iter()
                .any(|(_, why)| why.contains("local-tools") && why.contains("the rest are")),
            "{:?}",
            sbom.unread
        );
    }

    #[test]
    fn a_requirements_file_that_pins_and_hashes_everything_is_listed_as_installed() {
        // family-hub, reported on 3 October 2026: listed "at the version asked for rather than the
        // version installed", though pip installs exactly these.
        let dir = scratch("requirements-hashed-sbom");
        let hash = "ab".repeat(32);
        fs::write(
            dir.join("requirements.txt"),
            format!(
                "blinker==1.9.0 \\\n    --hash=sha256:{hash}\nflask[async]==3.1.3 \\\n    --hash=sha256:{hash}\n"
            ),
        )
        .unwrap();
        let sbom = build(&dir);
        fs::remove_dir_all(&dir).ok();
        let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
        assert_eq!(
            purls,
            vec!["pkg:pypi/blinker@1.9.0", "pkg:pypi/flask@3.1.3"],
            "{sbom:?}"
        );
        assert!(sbom.is_complete(), "{sbom:?}");
        assert!(incompleteness_finding(&sbom).is_none());
        assert!(sbom.disagreements.is_empty(), "{:?}", sbom.disagreements);
    }

    #[test]
    fn a_requirements_lock_beside_pyproject_is_read_hashes_and_markers_included() {
        // What `uv pip compile pyproject.toml --universal --generate-hashes -o requirements.lock`
        // writes: a continuation backslash, `--hash` lines, `# via` comments, and a marker line, here
        // written both with and without the space before its `;`.
        let dir = scratch("pyproject-requirements-lock");
        fs::write(
            dir.join("pyproject.toml"),
            "[project]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\"PyYAML>=6.0\"]\n",
        )
        .unwrap();
        fs::write(
            dir.join("requirements.lock"),
            "# This file was autogenerated by uv via the following command:\n\
             #    uv pip compile pyproject.toml --universal --generate-hashes -o requirements.lock\n\
             colorama==0.4.6 ; sys_platform == 'win32' \\\n    \
             --hash=sha256:08695f5cb7ed6e0531a20572697297273c47b8cae5a63ffc6d6ed5c201be6e44\n    \
             # via demo\n\
             pywin32==306;sys_platform=='win32'\n\
             pyyaml==6.0.2 \\\n    \
             --hash=sha256:0a9a2848a5b7feac301353437eb7d5957887edbf81d56e903999a75a3d743086\n    \
             # via demo\n",
        )
        .unwrap();
        let sbom = build(&dir);
        let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
        assert_eq!(
            purls,
            [
                "pkg:pypi/colorama@0.4.6",
                "pkg:pypi/pywin32@306",
                "pkg:pypi/pyyaml@6.0.2"
            ],
            "{sbom:?}"
        );
        assert!(sbom.is_complete(), "{sbom:?}");
        assert!(
            sbom.components
                .iter()
                .all(|c| c.source == VersionSource::Locked),
            "{sbom:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_manifest_that_disagrees_with_its_lockfile_is_named_in_the_document() {
        let dir = scratch("manifest-disagrees");
        fs::write(
            dir.join("requirements.txt"),
            "flask==3.0.0\npyjwt==2.13.0\n",
        )
        .unwrap();
        fs::write(
            dir.join("requirements.lock"),
            "flask==3.0.0\npyjwt==2.8.0\n",
        )
        .unwrap();
        fs::create_dir_all(dir.join("server")).unwrap();
        fs::write(
            dir.join("server/package.json"),
            r#"{"name":"web","dependencies":{"lodash":"^4.17.21","left-pad":"1.3.0"}}"#,
        )
        .unwrap();
        fs::write(
            dir.join("server/package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}"#,
        )
        .unwrap();
        let sbom = build(&dir);
        // The list is still the lockfiles', and still complete.
        assert!(sbom.is_complete(), "{sbom:?}");
        assert!(
            sbom.components
                .iter()
                .any(|c| c.name == "pyjwt" && c.version == "2.8.0"),
            "{sbom:?}"
        );
        let said: Vec<(&str, &str, &str)> = sbom
            .disagreements
            .iter()
            .map(|d| (d.project.as_str(), d.manifest.as_str(), d.lockfile.as_str()))
            .collect();
        assert_eq!(
            said,
            vec![
                ("Python", "requirements.txt", "requirements.lock"),
                (
                    "npm in server/",
                    "server/package.json",
                    "server/package-lock.json"
                ),
            ]
        );
        let doc = serde_json::to_value(to_cyclonedx(&sbom)).unwrap();
        let property = |name: &str| {
            doc["metadata"]["properties"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["name"] == name)
                .and_then(|p| p["value"].as_str())
                .map(str::to_owned)
        };
        let python = property("securevibe:manifest-disagrees:Python")
            .unwrap_or_else(|| panic!("the document names it: {doc}"));
        assert!(
            python.contains("`pyjwt==2.13.0` (the lockfile has 2.8.0)")
                && python.contains("about 1 package:"),
            "{python}"
        );
        let npm = property("securevibe:manifest-disagrees:npm in server/").unwrap();
        assert!(
            npm.contains("`left-pad 1.3.0` (not in the lockfile)"),
            "{npm}"
        );

        // In step, nothing is said.
        fs::write(
            dir.join("requirements.lock"),
            "flask==3.0.0\npyjwt==2.13.0\n",
        )
        .unwrap();
        fs::write(
            dir.join("server/package.json"),
            r#"{"name":"web","dependencies":{"lodash":"^4.17.21"}}"#,
        )
        .unwrap();
        let in_step = build(&dir);
        assert!(
            in_step.disagreements.is_empty(),
            "{:?}",
            in_step.disagreements
        );
        let doc = serde_json::to_string(&to_cyclonedx(&in_step)).unwrap();
        assert!(!doc.contains("manifest-"), "{doc}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_other_manifests_are_held_to_their_lockfiles_too() {
        let dir = scratch("other-manifests");
        fs::write(dir.join("Gemfile"), "gem \"rails\", \"~> 7.1.0\"\n").unwrap();
        fs::write(
            dir.join("Gemfile.lock"),
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.2.0)\n\nDEPENDENCIES\n  rails (~> 7.1.0)\n",
        )
        .unwrap();
        fs::create_dir_all(dir.join("svc")).unwrap();
        fs::write(
            dir.join("svc/Cargo.toml"),
            "[package]\nname = \"svc\"\n[dependencies]\nserde = \"1.0\"\n",
        )
        .unwrap();
        fs::write(
            dir.join("svc/Cargo.lock"),
            "[[package]]\nname = \"serde\"\nversion = \"1.0.228\"\n",
        )
        .unwrap();
        let sbom = build(&dir);
        let said: Vec<(&str, Vec<String>)> = sbom
            .disagreements
            .iter()
            .map(|d| {
                (
                    d.project.as_str(),
                    d.comparison
                        .differs
                        .iter()
                        .map(|x| x.asked.clone())
                        .collect(),
                )
            })
            .collect();
        // The Gemfile asks for 7.1 and the lock has 7.2; Cargo's two agree, and say nothing.
        assert_eq!(said, vec![("Ruby", vec!["rails ~> 7.1.0".to_owned()])]);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_lockfile_passed_over_is_named_in_the_document_and_leaves_it_complete() {
        let dir = scratch("passed-over");
        fs::write(dir.join("Cargo.toml"), "[package]\nname='x'\n").unwrap();
        fs::write(
            dir.join("Cargo.lock"),
            "[[package]]\nname = \"serde\"\nversion = \"1.0.229\"\n",
        )
        .unwrap();
        fs::write(dir.join("package.json"), "{\"name\":\"web\"}").unwrap();
        fs::write(
            dir.join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}"#,
        )
        .unwrap();
        fs::write(dir.join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
        let sbom = build(&dir);
        assert_eq!(
            sbom.passed_over,
            vec![PassedOver {
                project: "npm".into(),
                read: "package-lock.json".into(),
                not_read: vec!["yarn.lock".into()],
            }]
        );
        assert!(
            sbom.is_complete(),
            "a full reading of one lockfile: {sbom:?}"
        );
        let doc = serde_json::to_value(to_cyclonedx(&sbom)).unwrap();
        let said = doc["metadata"]["properties"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "securevibe:lockfile-passed-over:npm")
            .unwrap_or_else(|| panic!("the document names it: {doc}"));
        let said = said["value"].as_str().unwrap();
        assert!(
            said.contains("`package-lock.json` was read")
                && said.contains("`yarn.lock` is there too"),
            "{said}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pipfile_lock_strips_the_pin_from_the_version() {
        // Pipfile.lock writes "==3.0.0": the specifier travels with the value, and a purl carrying
        // `@==3.0.0` matches no advisory anywhere.
        let dir = scratch("pipfile");
        fs::write(dir.join("requirements.txt"), "flask\n").unwrap();
        fs::write(
            dir.join("Pipfile.lock"),
            r#"{"default":{"flask":{"version":"==3.0.0"}},"develop":{"pytest":{"version":"==8.0.0"}}}"#,
        )
        .unwrap();
        let sbom = build(&dir);
        let flask = sbom
            .components
            .iter()
            .find(|c| c.name == "flask")
            .expect("flask");
        assert_eq!(
            flask.version, "3.0.0",
            "the == must not survive into the version"
        );
        assert_eq!(flask.purl(), "pkg:pypi/flask@3.0.0");
        assert_eq!(
            sbom.components.len(),
            2,
            "development packages ship too: {sbom:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    /// A `Pipfile.lock` as `pipenv lock` writes it, cut down: `_meta`, then each category.
    const PIPFILE_LOCK: &str = r#"{
        "_meta": {"hash": {"sha256": "x"}, "pipfile-spec": 6, "requires": {"python_version": "3.11"},
                  "sources": [{"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": true}]},
        "default": {
            "django": {"hashes": ["sha256:y"], "index": "pypi", "version": "==2.2.0"},
            "sqlparse": {"hashes": ["sha256:z"], "markers": "python_version >= '3.5'", "version": "==0.4.4"}
        },
        "develop": {"pytest": {"hashes": ["sha256:w"], "version": "==8.0.0"}},
        "docs": {"sphinx": {"version": "==7.2.6"}}
    }"#;

    #[test]
    fn a_pipenv_app_alone_is_read_from_its_lockfile() {
        // Deep review H9: with only `Pipfile` and `Pipfile.lock`, nothing at all was listed.
        let dir = scratch("pipenv-alone");
        fs::write(
            dir.join("Pipfile"),
            "[[source]]\nurl = \"https://pypi.org/simple\"\nname = \"pypi\"\n\n\
             [packages]\ndjango = \"==2.2.0\"\n\n[dev-packages]\npytest = \"*\"\n\n\
             [docs]\nsphinx = \"*\"\n\n[requires]\npython_version = \"3.11\"\n",
        )
        .unwrap();
        fs::write(dir.join("Pipfile.lock"), PIPFILE_LOCK).unwrap();
        let sbom = build(&dir);
        fs::remove_dir_all(&dir).ok();

        let listed: Vec<String> = sbom
            .components
            .iter()
            .map(|c| format!("{} {} {:?}", c.name, c.version, c.source))
            .collect();
        assert_eq!(
            listed,
            [
                "django 2.2.0 Locked",
                "pytest 8.0.0 Locked",
                "sphinx 7.2.6 Locked",
                "sqlparse 0.4.4 Locked",
            ],
            "every section is read, development packages and other categories too"
        );
        assert!(sbom.is_complete(), "{sbom:?}");
        assert!(
            sbom.disagreements.is_empty(),
            "the Pipfile agrees with its lockfile: {:?}",
            sbom.disagreements
        );
    }

    #[test]
    fn a_pipfile_that_asks_for_another_version_than_its_lockfile_is_named() {
        let dir = scratch("pipenv-disagrees");
        fs::write(dir.join("Pipfile"), "[packages]\ndjango = \"==2.2.28\"\n").unwrap();
        fs::write(dir.join("Pipfile.lock"), PIPFILE_LOCK).unwrap();
        let sbom = build(&dir);
        fs::remove_dir_all(&dir).ok();
        let disagreement = sbom.disagreements.first().expect("named");
        assert!(disagreement.differs(), "{disagreement:?}");
        assert!(
            disagreement
                .explain()
                .contains("`django ==2.2.28` (the lockfile has 2.2.0)"),
            "{}",
            disagreement.explain()
        );
    }

    #[test]
    fn a_pipfile_lock_package_with_no_version_is_named_not_dropped() {
        // Pipenv locks a package from a repository by its commit, and one from a folder by its
        // path: no version. Installed all the same, so the list is not the whole of what is
        // (deep review H21, for this reader). The app's own folder is the app, not a package.
        let dir = scratch("pipenv-unversioned");
        fs::write(dir.join("Pipfile"), "[packages]\ndjango = \"*\"\n").unwrap();
        fs::write(
            dir.join("Pipfile.lock"),
            r#"{"_meta": {},
                "default": {
                    "django": {"version": "==4.2.11"},
                    "myapp": {"editable": true, "path": "."},
                    "toolkit": {"git": "https://example.com/toolkit.git", "ref": "abc123"},
                    "shared": {"editable": true, "path": "./libs/shared"}
                },
                "develop": {}}"#,
        )
        .unwrap();
        let sbom = build(&dir);
        fs::remove_dir_all(&dir).ok();

        assert_eq!(sbom.components.len(), 1, "{sbom:?}");
        assert_eq!(sbom.unread.len(), 1, "{:?}", sbom.unread);
        let (eco, why) = &sbom.unread[0];
        assert_eq!(eco, "Python");
        assert!(
            why.contains("2 package(s) in `Pipfile.lock` give no version")
                && why.contains("shared, toolkit"),
            "{why}"
        );
        assert!(
            !why.contains("myapp"),
            "the app itself is not a package: {why}"
        );
        assert!(!sbom.is_complete());
    }

    #[test]
    fn a_pipfile_without_its_lockfile_lists_only_its_pins_and_names_the_rest() {
        let dir = scratch("pipfile-alone");
        fs::write(
            dir.join("Pipfile"),
            "[packages]\ndjango = \"==2.2.0\"\nrequests = \"*\"\n\
             flask = {version = \"==3.0.0\", extras = [\"async\"]}\n\
             toolkit = {git = \"https://example.com/toolkit.git\"}\n\n\
             [dev-packages]\npytest = \">=8\"\n",
        )
        .unwrap();
        let sbom = build(&dir);
        fs::write(dir.join("Pipfile"), "[packages]\nrequests = \"*\"\n").unwrap();
        let none_pinned = build(&dir);
        fs::remove_dir_all(&dir).ok();

        let listed: Vec<String> = sbom
            .components
            .iter()
            .map(|c| format!("{} {} {:?}", c.name, c.version, c.source))
            .collect();
        assert_eq!(listed, ["django 2.2.0 Declared", "flask 3.0.0 Declared"]);
        assert_eq!(sbom.unread.len(), 1, "{:?}", sbom.unread);
        assert!(
            sbom.unread[0].1.contains("3 of its packages")
                && sbom.unread[0].1.contains("pytest, requests, toolkit"),
            "{:?}",
            sbom.unread
        );
        assert!(!sbom.is_complete());

        assert!(none_pinned.components.is_empty());
        assert_eq!(
            none_pinned.unread.len(),
            1,
            "one reason, not that one and the general one too: {:?}",
            none_pinned.unread
        );
        assert!(none_pinned.unread[0].1.contains("requests"));
    }

    #[test]
    fn python_declarations_sv_does_not_read_leave_the_list_incomplete_and_say_which() {
        // Beside a locked npm app, so the list is not empty and a clean comparison of it would
        // otherwise have been credited (deep review H9).
        let dir = scratch("python-declarations");
        fs::write(dir.join("package.json"), r#"{"name":"web"}"#).unwrap();
        fs::write(
            dir.join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}"#,
        )
        .unwrap();
        let control = build(&dir);
        assert!(control.is_complete(), "the control: {control:?}");

        let cases: &[(&str, &str, &str)] = &[
            (
                "worker/setup.py",
                "from setuptools import setup\nsetup(name='w', install_requires=['celery'])\n",
                "`worker/setup.py` names Python packages",
            ),
            (
                "worker/setup.cfg",
                "[options]\ninstall_requires =\n    celery\n",
                "`worker/setup.cfg` names Python packages",
            ),
            (
                "requirements-dev.txt",
                "pytest==8.0.0\n",
                "`requirements-dev.txt` lists Python packages",
            ),
            (
                "requirements/prod.txt",
                "gunicorn>=22\n",
                "`requirements/prod.txt` lists Python packages",
            ),
            (
                "environment.yml",
                "name: lab\ndependencies:\n  - numpy\n",
                "`environment.yml` is a Conda environment",
            ),
        ];
        for (path, text, said) in cases {
            let file = dir.join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(&file, text).unwrap();
            let sbom = build(&dir);
            fs::remove_file(&file).ok();
            assert!(!sbom.is_complete(), "{path}: {sbom:?}");
            assert!(
                sbom.unread
                    .iter()
                    .any(|(eco, why)| eco == "Python" && why.contains(said)),
                "{path}: {:?}",
                sbom.unread
            );
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_setup_py_beside_a_python_lockfile_is_stood_for_by_it() {
        let dir = scratch("setup-beside-lock");
        fs::write(
            dir.join("setup.py"),
            "from setuptools import setup\nsetup(install_requires=['django'])\n",
        )
        .unwrap();
        let alone = build(&dir);
        fs::write(
            dir.join("Pipfile"),
            "[packages]\nmyapp = {path = \".\", editable = true}\n",
        )
        .unwrap();
        fs::write(dir.join("Pipfile.lock"), PIPFILE_LOCK).unwrap();
        let locked = build(&dir);
        fs::remove_dir_all(&dir).ok();

        assert!(
            alone
                .unread
                .iter()
                .any(|(_, why)| why.contains("`setup.py`")),
            "the control: {alone:?}"
        );
        assert!(locked.is_complete(), "{locked:?}");
    }

    #[test]
    fn a_requirements_file_under_another_name_that_pins_and_hashes_is_read() {
        let dir = scratch("requirements-dev-hashed");
        let hash = format!("sha256:{}", "a".repeat(64));
        fs::write(
            dir.join("requirements-dev.txt"),
            format!("pytest==8.0.0 \\\n    --hash={hash}\n"),
        )
        .unwrap();
        let sbom = build(&dir);
        fs::remove_dir_all(&dir).ok();
        assert!(sbom.unread.is_empty(), "{:?}", sbom.unread);
        assert_eq!(
            sbom.components,
            [Component {
                name: "pytest".into(),
                version: "8.0.0".into(),
                ecosystem: "Python".into(),
                source: VersionSource::Locked,
            }]
        );
        // It is named as where the list came from.
        assert_eq!(
            sbom.what_was_read(),
            "1 Python package, read from `requirements-dev.txt`"
        );
    }

    #[test]
    fn yarn_lock_reads_one_package_from_several_ranges() {
        // The header is the range that was asked for, not the name, and one package can have several
        // headers. Treating each header as a package would invent packages and double the list.
        let dir = scratch("yarn");
        fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
        fs::write(
            dir.join("yarn.lock"),
            "# yarn lockfile v1\n\nlodash@^4.17.0, lodash@~4.17.20:\n  version \"4.17.21\"\n  resolved \"https://x\"\n\n\"@babel/core@^7.0.0\":\n  version \"7.23.0\"\n",
        )
        .unwrap();
        let sbom = build(&dir);
        let names: Vec<&str> = sbom.components.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["@babel/core", "lodash"], "{sbom:?}");
        // A scoped package keeps its scope: the name is everything before the LAST @.
        assert!(
            sbom.components
                .iter()
                .any(|c| c.purl() == "pkg:npm/@babel/core@7.23.0")
        );
        fs::remove_dir_all(&dir).ok();
    }

    const YARN_BERRY: &str = r#"# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 8
  cacheKey: 10c0

"@babel/core@npm:^7.0.0":
  version: 7.23.0
  resolution: "@babel/core@npm:7.23.0"
  dependencies:
    "@babel/code-frame": "npm:^7.22.13"
  checksum: 10c0/0a1b2c
  languageName: node
  linkType: hard

"lodash@npm:^4.17.0, lodash@npm:~4.17.20":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: 10c0/3d4e5f
  languageName: node
  linkType: hard

"my-app@workspace:.":
  version: 0.0.0-use.local
  resolution: "my-app@workspace:."
  dependencies:
    lodash: "npm:^4.17.0"
  languageName: unknown
  linkType: soft

"local-lib@file:../lib::locator=my-app%40workspace%3A.":
  version: 1.0.0
  resolution: "local-lib@file:../lib#../lib::hash=1a2b3c&locator=my-app%40workspace%3A."
  languageName: node
  linkType: hard

"resolve@patch:resolve@npm%3A^1.22.0#optional!builtin<compat/resolve>":
  version: 1.22.8
  resolution: "resolve@patch:resolve@npm%3A1.22.8#optional!builtin<compat/resolve>::version=1.22.8&hash=c3c19d"
  languageName: node
  linkType: hard
"#;

    #[test]
    fn a_yarn_berry_lockfile_lists_what_came_from_the_registry_and_nothing_else() {
        let dir = scratch("yarn-berry");
        fs::write(dir.join("package.json"), r#"{"name":"my-app"}"#).unwrap();
        fs::write(dir.join("yarn.lock"), YARN_BERRY).unwrap();
        let sbom = build(&dir);
        fs::remove_dir_all(&dir).ok();
        let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
        // Not the app itself, not `__metadata`'s own version, and the patched `resolve` once, by
        // its own name. The folder it links is installed too, from outside the registry, so it is
        // named as not listed rather than dropped without a word; the app's own workspace is not.
        assert_eq!(
            purls,
            vec![
                "pkg:npm/@babel/core@7.23.0",
                "pkg:npm/lodash@4.17.21",
                "pkg:npm/resolve@1.22.8",
            ],
            "{sbom:?}"
        );
        assert_eq!(sbom.unread.len(), 1, "{:?}", sbom.unread);
        assert!(
            sbom.unread[0].1.contains("(local-lib)"),
            "{:?}",
            sbom.unread
        );
        assert!(!sbom.is_complete());
    }

    const BUN_LOCK: &str = r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "my-app",
      "dependencies": {
        "@babel/core": "^7.0.0",
        "lodash": "^4.17.0",
      },
    },
    "packages/ui": {
      "name": "ui",
    },
  },
  "packages": {
    "@babel/core": ["@babel/core@7.23.0", "", { "dependencies": { "debug": "^4.1.0" } }, "sha512-AAAA=="],
    "lodash": ["lodash@4.17.21", "", {}, "sha512-BBBB=="],
    "ui": ["ui@workspace:packages/ui"],
    "some-git": ["some-git@github:owner/repo#1a2b3c", {}],
    "debug/ms": ["ms@2.1.2", "", {}, "sha512-CCCC=="],
  },
}
"#;

    #[test]
    fn a_bun_lockfile_is_read_with_its_trailing_commas() {
        let dir = scratch("bun");
        fs::write(dir.join("package.json"), r#"{"name":"my-app"}"#).unwrap();
        fs::write(dir.join("bun.lock"), BUN_LOCK).unwrap();
        let eco = sv_scan::ecosystems::detect(&dir);
        let pinning = eco.first().map(|e| sv_scan::ecosystems::pinning(&dir, e));
        let sbom = build(&dir);
        fs::remove_dir_all(&dir).ok();
        // Bun's lockfile pins: a Bun app is not told it has none.
        assert_eq!(
            pinning,
            Some(sv_scan::ecosystems::Pinning::Lockfile("bun.lock".into()))
        );
        let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
        // A package installed under another one is listed by its own name; a workspace member and a
        // GitHub dependency are not registry packages.
        assert_eq!(
            purls,
            vec![
                "pkg:npm/@babel/core@7.23.0",
                "pkg:npm/lodash@4.17.21",
                "pkg:npm/ms@2.1.2",
            ],
            "{sbom:?}"
        );
        assert!(sbom.unread.is_empty(), "{:?}", sbom.unread);
    }

    #[test]
    fn bun_s_binary_lockfile_pins_and_says_it_cannot_be_read() {
        let dir = scratch("bun-binary");
        fs::write(dir.join("package.json"), r#"{"name":"my-app"}"#).unwrap();
        fs::write(dir.join("bun.lockb"), [0x23, 0x21, 0x2f, 0x00, 0xff, 0x01]).unwrap();
        let eco = sv_scan::ecosystems::detect(&dir);
        let pinning = eco.first().map(|e| sv_scan::ecosystems::pinning(&dir, e));
        let sbom = build(&dir);
        fs::remove_dir_all(&dir).ok();
        assert_eq!(
            pinning,
            Some(sv_scan::ecosystems::Pinning::Lockfile("bun.lockb".into()))
        );
        assert!(sbom.components.is_empty());
        assert!(
            sbom.unread.iter().any(|(eco, why)| eco == "npm"
                && why.contains("binary")
                && why.contains("bun.lock")),
            "{:?}",
            sbom.unread
        );
    }

    #[test]
    fn only_a_comma_before_a_closing_bracket_and_outside_a_string_is_dropped() {
        assert_eq!(
            without_trailing_commas(r#"{"a": [1, 2,], "b": "x,}", "c": "q\",]",}"#),
            r#"{"a": [1, 2], "b": "x,}", "c": "q\",]"}"#
        );
        assert_eq!(without_trailing_commas("[1 ,\n ]"), "[1 \n ]");
    }

    #[test]
    fn a_project_below_the_top_has_its_lockfile_read() {
        // A `server/` project's packages were missing from the bill of materials, because only the
        // top of the app folder was looked at.
        let dir = scratch("nested");
        fs::create_dir_all(dir.join("server")).unwrap();
        fs::write(dir.join("server/package.json"), r#"{"name":"server"}"#).unwrap();
        fs::write(
            dir.join("server/package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"":{"name":"server"},"node_modules/express":{"version":"4.19.2"}}}"#,
        )
        .unwrap();
        let sbom = build(&dir);
        fs::remove_dir_all(&dir).ok();
        assert!(
            sbom.components
                .iter()
                .any(|c| c.purl() == "pkg:npm/express@4.19.2"),
            "{sbom:?}"
        );
    }

    #[test]
    fn a_nested_rust_project_has_its_lockfile_read() {
        // Second witness, another ecosystem and another reader.
        let dir = scratch("nested-cargo");
        fs::create_dir_all(dir.join("worker")).unwrap();
        fs::write(
            dir.join("worker/Cargo.toml"),
            "[package]\nname = \"worker\"\n",
        )
        .unwrap();
        fs::write(
            dir.join("worker/Cargo.lock"),
            "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.210\"\n",
        )
        .unwrap();
        let sbom = build(&dir);
        fs::remove_dir_all(&dir).ok();
        assert!(
            sbom.components
                .iter()
                .any(|c| c.name == "serde" && c.version == "1.0.210"),
            "{sbom:?}"
        );
    }

    #[test]
    fn gradle_lockfile_skips_its_empty_configuration_line() {
        // A real gradle.lockfile ends with `empty=someConfiguration` for configurations that resolved
        // nothing. Reading it as a coordinate would put a package called "empty" in the document.
        let dir = scratch("gradle");
        fs::write(dir.join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            dir.join("gradle.lockfile"),
            "# This is a Gradle generated file for dependency locking.\norg.springframework:spring-core:6.1.0=compileClasspath,runtimeClasspath\nempty=annotationProcessor\n",
        )
        .unwrap();
        let sbom = build(&dir);
        assert_eq!(sbom.components.len(), 1, "{sbom:?}");
        assert_eq!(sbom.components[0].name, "org.springframework:spring-core");
        assert_eq!(sbom.components[0].version, "6.1.0");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pnpm_lock_v9_is_read_including_scopes_and_peer_variants() {
        let dir = scratch("pnpm9");
        fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
        fs::write(
            dir.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n\npackages:\n\n  express@4.18.2:\n    resolution: {integrity: sha512-x}\n    engines: {node: '>= 0.10.0'}\n\n  '@babel/core@7.23.0':\n    resolution: {integrity: sha512-y}\n\n  vite@5.0.0(terser@5.0.0):\n    resolution: {integrity: sha512-z}\n\nsnapshots:\n\n  express@4.18.2:\n    dependencies:\n      body-parser: 1.20.1\n",
        )
        .unwrap();
        let sbom = build(&dir);
        let names: Vec<&str> = sbom.components.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["@babel/core", "express", "vite"], "{sbom:?}");
        // A peer variant is one package, and the peer is not a second one.
        assert!(
            sbom.components.iter().all(|c| c.name != "terser"),
            "{sbom:?}"
        );
        assert!(
            sbom.components
                .iter()
                .any(|c| c.purl() == "pkg:npm/@babel/core@7.23.0")
        );
        // `snapshots:` repeats the same keys; reading both blocks would double the list.
        assert_eq!(sbom.components.len(), 3, "{sbom:?}");
        assert!(sbom.is_complete(), "{sbom:?}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pnpm_lock_v6_uses_a_slash_and_an_at_and_is_read_too() {
        // pnpm 8's lockfile 6.0: `/name@version`, with peer variants in brackets as in v9.
        let dir = scratch("pnpm6");
        fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
        fs::write(
            dir.join("pnpm-lock.yaml"),
            "lockfileVersion: '6.0'\n\npackages:\n\n  /express@4.18.2:\n    resolution: {integrity: sha512-x}\n\n  /@babel/core@7.23.0:\n    resolution: {integrity: sha512-y}\n\n  /vite@5.0.0(terser@5.0.0):\n    resolution: {integrity: sha512-z}\n",
        )
        .unwrap();
        let sbom = build(&dir);
        fs::remove_dir_all(&dir).ok();
        let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
        assert_eq!(
            purls,
            vec![
                "pkg:npm/@babel/core@7.23.0",
                "pkg:npm/express@4.18.2",
                "pkg:npm/vite@5.0.0",
            ],
            "{sbom:?}"
        );
        assert!(sbom.is_complete(), "{sbom:?}");
    }

    #[test]
    fn pnpm_lock_v5_uses_slashes_and_its_peer_suffix_is_not_the_version() {
        let dir = scratch("pnpm5");
        fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
        fs::write(
            dir.join("pnpm-lock.yaml"),
            "lockfileVersion: 5.4\n\npackages:\n\n  /express/4.18.2:\n    resolution: {integrity: sha512-x}\n\n  /@babel/core/7.23.0:\n    resolution: {integrity: sha512-y}\n\n  /react-dom/18.2.0_react@18.2.0:\n    resolution: {integrity: sha512-z}\n",
        )
        .unwrap();
        let sbom = build(&dir);
        fs::remove_dir_all(&dir).ok();
        let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
        assert_eq!(
            purls,
            vec![
                "pkg:npm/@babel/core@7.23.0",
                "pkg:npm/express@4.18.2",
                "pkg:npm/react-dom@18.2.0",
            ],
            "{sbom:?}"
        );
        assert!(sbom.is_complete(), "{sbom:?}");
    }

    #[test]
    fn a_pnpm_package_with_no_version_is_named_not_dropped() {
        // pnpm 9 lists a package installed from a folder or an address by that, not by a version.
        // It is installed, so the list is not complete, and says which.
        let dir = scratch("pnpm9-file");
        fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
        fs::write(
            dir.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n\npackages:\n\n  express@4.18.2:\n    resolution: {integrity: sha512-x}\n\n  my-lib@file:../lib:\n    resolution: {directory: ../lib, type: directory}\n\n  left-pad@https://codeload.github.com/x/left-pad/tar.gz/abc:\n    resolution: {tarball: https://codeload.github.com/x/left-pad/tar.gz/abc}\n",
        )
        .unwrap();
        let sbom = build(&dir);
        fs::remove_dir_all(&dir).ok();
        let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
        assert_eq!(purls, vec!["pkg:npm/express@4.18.2"], "{sbom:?}");
        assert!(!sbom.is_complete(), "{sbom:?}");
        assert!(
            sbom.unread.iter().any(|(eco, why)| eco == "npm"
                && why.contains("2 package(s)")
                && why.contains("left-pad")
                && why.contains("my-lib")),
            "{sbom:?}"
        );
    }

    #[test]
    fn a_yarn_package_with_no_registry_version_is_named_not_dropped() {
        // Berry: a folder, a link, and a repository are named; the app's own workspace is not.
        let dir = scratch("yarn-unversioned");
        fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
        fs::write(
            dir.join("yarn.lock"),
            "__metadata:\n  version: 8\n\n\"lodash@npm:^4.17.0\":\n  version: 4.17.21\n  resolution: \"lodash@npm:4.17.21\"\n\n\"my-lib@file:../lib::locator=app%40workspace%3A.\":\n  version: 0.0.0-use.local\n\n\"shared@link:../shared::locator=app%40workspace%3A.\":\n  version: 0.0.0-use.local\n\n\"left-pad@https://github.com/x/left-pad.git#commit=abc\":\n  version: 1.3.0\n\n\"app@workspace:.\":\n  version: 0.0.0-use.local\n",
        )
        .unwrap();
        let sbom = build(&dir);
        let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
        assert_eq!(purls, vec!["pkg:npm/lodash@4.17.21"], "{sbom:?}");
        assert!(!sbom.is_complete(), "{sbom:?}");
        let said = sbom
            .unread
            .iter()
            .find(|(eco, _)| eco == "npm")
            .map(|(_, why)| why.clone())
            .unwrap_or_default();
        assert!(said.contains("3 package(s)"), "{said}");
        for name in ["my-lib", "shared", "left-pad"] {
            assert!(said.contains(name), "{name}: {said}");
        }
        assert!(!said.contains("app,") && !said.contains("app)"), "{said}");

        // Classic: an entry that never says its version is named too.
        fs::write(
            dir.join("yarn.lock"),
            "# yarn lockfile v1\n\nlodash@^4.17.0:\n  version \"4.17.21\"\n  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz\"\n\n\"my-lib@file:../lib\":\n  resolved \"file:../lib\"\n\nzod@^3.22.0:\n  version \"3.22.4\"\n\n\"tail-lib@file:../tail\":\n  resolved \"file:../tail\"\n",
        )
        .unwrap();
        let sbom = build(&dir);
        fs::remove_dir_all(&dir).ok();
        let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
        // One without a version between two with, and one at the very end.
        assert_eq!(
            purls,
            vec!["pkg:npm/lodash@4.17.21", "pkg:npm/zod@3.22.4"],
            "{sbom:?}"
        );
        for name in ["my-lib", "tail-lib"] {
            assert!(
                sbom.unread
                    .iter()
                    .any(|(eco, why)| eco == "npm" && why.contains(name)),
                "{name}: {sbom:?}"
            );
        }
    }

    #[test]
    fn a_pnpm_file_this_reader_does_not_understand_is_named_not_emptied() {
        // The guard that makes hand-parsing acceptable. A future lockfile version, or a file that is
        // not really a pnpm lock, must come back as "not read" — an empty list is indistinguishable
        // from an app with no dependencies, which is the one wrong answer available here.
        let dir = scratch("pnpmfuture");
        fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
        fs::write(
            dir.join("pnpm-lock.yaml"),
            "lockfileVersion: '99.0'\n\nmodules:\n  something: else\n",
        )
        .unwrap();
        let sbom = build(&dir);
        assert!(sbom.components.is_empty());
        assert!(
            sbom.unread
                .iter()
                .any(|(eco, why)| eco == "npm" && why.contains("no packages could be taken")),
            "an unrecognized pnpm lockfile must be named, and say why: {sbom:?}"
        );
        assert!(!sbom.is_complete());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_lockfile_that_parses_to_nothing_is_named_rather_than_silently_empty() {
        // Not pnpm-specific: any reader that returns an empty list leaves the ecosystem present and
        // the document silent about it, which reads exactly like having nothing to say.
        let dir = scratch("emptylock");
        fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
        fs::write(dir.join("package-lock.json"), r#"{"lockfileVersion":3}"#).unwrap();
        let sbom = build(&dir);
        assert!(sbom.components.is_empty());
        assert!(
            sbom.unread
                .iter()
                .any(|(eco, why)| eco == "npm" && why.contains("no packages")),
            "{sbom:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_ecosystem_is_never_silently_nothing() {
        // The invariant behind every "named rather than dropped" test, stated once: if an ecosystem is
        // in use, the document either lists something from it or says why it does not. Silence about an
        // ecosystem that is present is the one outcome that reads like an answer and is not.
        let cases: &[(&str, &str, &str)] = &[
            (
                "package.json",
                "pnpm-lock.yaml",
                "lockfileVersion: '99.0'\nmodules:\n  x: y\n",
            ),
            (
                "package.json",
                "package-lock.json",
                r#"{"packages":{"node_modules/x":{"version":"1.0.0"}}}"#,
            ),
            (
                "Gemfile",
                "Gemfile.lock",
                "GEM\n  specs:\n    rake (13.0.6)\n",
            ),
            ("requirements.txt", "", "flask>=2\n"),
            ("Pipfile", "", "[packages]\nflask = \"*\"\n"),
            (
                "Pipfile",
                "Pipfile.lock",
                r#"{"default":{"flask":{"git":"https://example.com/flask.git"}}}"#,
            ),
            ("go.mod", "go.sum", "example.com/m v1.0.0 h1:x=\n"),
        ];
        for (manifest, lock, contents) in cases {
            let dir = scratch(&format!("invariant-{manifest}-{lock}"));
            if lock.is_empty() {
                fs::write(dir.join(manifest), contents).unwrap();
            } else {
                fs::write(dir.join(manifest), "placeholder\n").unwrap();
                fs::write(dir.join(lock), contents).unwrap();
            }
            let detected = sv_scan::ecosystems::detect(&dir);
            assert!(!detected.is_empty(), "{manifest} should be detected");
            let sbom = build(&dir);
            assert!(
                !sbom.components.is_empty() || !sbom.unread.is_empty(),
                "{manifest}/{lock}: an ecosystem was present and the document says nothing about it: {sbom:?}"
            );
            fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn go_mod_names_the_version_built_and_go_sum_s_older_ones_are_not_listed() {
        // A3: go.sum keeps checksums for versions Go has since moved past. Only go.mod's own
        // `require` lines say which one the app is built with.
        let go_mod = "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/gorilla/websocket v1.5.1\n\tgolang.org/x/net v0.23.0 // indirect\n)\n\nrequire github.com/google/uuid v1.6.0\n";
        let go_sum = "github.com/gorilla/websocket v1.4.2 h1:a=\ngithub.com/gorilla/websocket v1.4.2/go.mod h1:b=\ngithub.com/gorilla/websocket v1.5.1 h1:c=\ngolang.org/x/net v0.17.0/go.mod h1:d=\ngolang.org/x/net v0.23.0 h1:e=\ngithub.com/google/uuid v1.6.0 h1:f=\nexample.com/dropped v1.0.0 h1:g=\n";
        let got = from_go_mod(go_mod, Some(go_sum));
        let mut pairs = got.pairs.clone();
        pairs.sort();
        assert_eq!(
            pairs,
            [
                ("github.com/google/uuid".to_owned(), "v1.6.0".to_owned()),
                (
                    "github.com/gorilla/websocket".to_owned(),
                    "v1.5.1".to_owned()
                ),
                ("golang.org/x/net".to_owned(), "v0.23.0".to_owned()),
            ]
        );
        assert!(got.local.is_empty());

        // `replace` decides what is built: another module at a version, or a folder of the app's own.
        let replaced = "module x\ngo 1.22\nrequire (\n  a.example/one v1.0.0\n  b.example/two v1.0.0\n  c.example/three v2.0.0\n)\nreplace (\n  a.example/one => a.example/fork v1.0.5\n  b.example/two v1.0.0 => ../two\n  c.example/three v9.9.9 => ../never\n)\n";
        let got = from_go_mod(replaced, None);
        assert!(
            got.pairs
                .contains(&("a.example/fork".to_owned(), "v1.0.5".to_owned())),
            "{got:?}"
        );
        assert!(
            got.pairs
                .contains(&("c.example/three".to_owned(), "v2.0.0".to_owned())),
            "a replace for another version leaves this one: {got:?}"
        );
        assert_eq!(got.local, ["b.example/two"]);

        // Before Go 1.17 go.mod may leave the indirect modules out, so go.sum names them, at the
        // highest version it holds.
        let old = "module x\ngo 1.16\nrequire github.com/a/direct v1.2.0\n";
        let sum = "github.com/a/direct v1.1.0 h1:x=\ngithub.com/a/direct v1.2.0 h1:x=\ngithub.com/b/indirect v0.9.0 h1:x=\ngithub.com/b/indirect v0.10.0 h1:x=\ngithub.com/b/indirect v0.11.0/go.mod h1:x=\n";
        let mut got = from_go_mod(old, Some(sum)).pairs;
        got.sort();
        assert_eq!(
            got,
            [
                ("github.com/a/direct".to_owned(), "v1.2.0".to_owned()),
                ("github.com/b/indirect".to_owned(), "v0.10.0".to_owned()),
            ]
        );
    }

    #[test]
    fn a_go_app_is_listed_from_go_mod_and_says_what_a_folder_replaced() {
        let dir = scratch("go-mod");
        fs::write(
            dir.join("go.mod"),
            "module x\ngo 1.21\nrequire (\n  github.com/gorilla/websocket v1.5.1\n  example.com/local v0.1.0\n)\nreplace example.com/local => ./local\n",
        )
        .unwrap();
        fs::write(
            dir.join("go.sum"),
            "github.com/gorilla/websocket v1.4.2 h1:a=\ngithub.com/gorilla/websocket v1.5.1 h1:b=\n",
        )
        .unwrap();
        let sbom = build(&dir);
        let versions: Vec<&str> = sbom.components.iter().map(|c| c.version.as_str()).collect();
        assert_eq!(versions, ["v1.5.1"], "{sbom:?}");
        assert!(
            sbom.unread
                .iter()
                .any(|(_, why)| why.contains("example.com/local")),
            "{:?}",
            sbom.unread
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn go_sum_lists_each_module_once() {
        let dir = scratch("go");
        fs::write(dir.join("go.mod"), "module x\n").unwrap();
        fs::write(
            dir.join("go.sum"),
            "github.com/gorilla/websocket v1.5.0 h1:abc=\ngithub.com/gorilla/websocket v1.5.0/go.mod h1:def=\n",
        )
        .unwrap();
        let sbom = build(&dir);
        assert_eq!(sbom.components.len(), 1, "{sbom:?}");
        assert_eq!(sbom.components[0].version, "v1.5.0");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn gemfile_lock_reads_specs_and_not_their_dependencies() {
        let dir = scratch("gem");
        fs::write(dir.join("Gemfile"), "source 'x'\n").unwrap();
        fs::write(
            dir.join("Gemfile.lock"),
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.0)\n      actionpack (= 7.1.0)\n    rake (13.0.6)\n",
        )
        .unwrap();
        let sbom = build(&dir);
        let names: Vec<&str> = sbom.components.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["rails", "rake"],
            "nested dependencies are not separate packages"
        );
        fs::remove_dir_all(&dir).ok();
    }
}
