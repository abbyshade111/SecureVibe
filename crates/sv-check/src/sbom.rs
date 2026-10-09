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
        if let Some(why) = &self.comparison.whole {
            return format!(
                "{why}, so whether it asks for the versions `{}` has was not compared, and is not known",
                self.lockfile
            );
        }
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
    // Dependencies in an ecosystem `sv` does not read (gap analysis, item 2): named, so the list is
    // not taken for complete and V15.2.1 is not credited on the rest.
    for unread in sv_scan::ecosystems::unread_declarations_in(listing) {
        sbom.unread
            .push((unread.name.to_owned(), unread_reason(&unread)));
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

    // What the manifest is compared with, when that is not the list itself. Go's list comes from
    // go.mod (A3), so comparing go.mod with it would compare the file with itself.
    let mut compared_with: Option<Vec<(String, String)>> = None;
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
            compared_with = sum.as_deref().map(from_go_sum);
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
        // A manifest that cannot be read, or one of a kind compared here that cannot be understood, is
        // a comparison not made, and said so: left out, it read as the two agreeing.
        let not_made = |why: String| crate::manifest_lock::Comparison {
            whole: Some(why),
            ..Default::default()
        };
        let comparison = if lockfile_path == eco.manifest {
            None
        } else {
            match read(manifest_name) {
                None => Some(not_made(format!("`{}` could not be read", eco.manifest))),
                Some(manifest) => match crate::manifest_lock::compare(
                    manifest_name,
                    &manifest,
                    compared_with.as_deref().unwrap_or(&pairs),
                ) {
                    Some(comparison) => Some(comparison),
                    None if crate::manifest_lock::compares(manifest_name) => {
                        Some(not_made(format!(
                            "`{}` could not be understood (it is not written as `sv` reads one)",
                            eco.manifest
                        )))
                    }
                    None => None,
                },
            }
        };
        if let Some(comparison) = comparison
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
        "requirements.txt" => {
            let requirements = read("requirements.txt").as_deref().map(from_requirements);
            if let Some((pinned, rest)) = &requirements
                && !rest.is_empty()
            {
                // Deep review H9: `flask>=2` beside `stripe==7.8.0` was left out of the list and
                // not named, so the list looked like everything the file asks for.
                sbom.unread.push((
                    eco.name.clone(),
                    format!(
                        "`{}` has no lockfile beside it, and {} of what it installs is asked for \
                         as a range, as any version, from an address or a folder, or from another \
                         file ({}), so it is not listed; a lockfile, such as one from \
                         `pip-compile --generate-hashes` or `uv pip compile`, is what `sv` reads",
                        eco.manifest,
                        rest.len(),
                        rest.join(", ")
                    ),
                ));
                if pinned.is_empty() {
                    return;
                }
            }
            requirements.map(|(pinned, _)| pinned)
        }
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

/// Why an ecosystem `sv` does not read is not in the list, in the words the report uses.
pub fn unread_reason(unread: &sv_scan::ecosystems::UnreadDeclaration) -> String {
    let lockfile = match &unread.lockfile {
        Some(lockfile) => format!(", nor its lockfile `{lockfile}`"),
        None => String::new(),
    };
    format!(
        "`{}` declares {} dependencies, and `sv` does not read that file{lockfile}, so none of \
         its packages is listed or compared with known vulnerabilities",
        unread.path, unread.name
    )
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
    from_requirements(text).0
}

/// A requirements file read line by line: the packages pinned to one version (`name==1.0`), and
/// what else it installs, by name: a package asking for a range or for any version (`flask>=2`,
/// `gunicorn`), one installed from an address or a folder, and another requirements file it pulls
/// in (`-r base.txt`). Deep review H9: before, all of those were left out without a word, so a
/// `requirements.txt` with no lockfile had a list that looked like everything it asked for.
///
/// `-e .` is the app itself, as in `Pipfile.lock`, and is not named. A constraints file (`-c`) and
/// the lines that only say where pip looks install nothing.
fn from_requirements(text: &str) -> Pinned {
    let (mut pinned, mut rest) = (Vec::new(), Vec::new());
    // A line ending in `\` goes on on the next one, as pip reads it.
    let joined = text.replace("\\\r\n", " ").replace("\\\n", " ");
    for line in joined.lines() {
        // A comment starts at a `#` at the start of a line or after a space.
        let line = match line.find(" #") {
            Some(i) => &line[..i],
            None => line,
        };
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('-') {
            let (option, value) = line
                .split_once(['=', ' ', '\t'])
                .map_or((line, ""), |(o, v)| (o, v.trim()));
            match option {
                "-r" | "--requirement" => rest.push(format!("`{value}`, which it pulls in")),
                "-e" | "--editable" if !matches!(value, "." | "./") && !value.starts_with(".[") => {
                    rest.push(requirement_name(value))
                }
                _ => {}
            }
            continue;
        }
        let requirement = line.split_once(';').map_or(line, |(r, _marker)| r).trim();
        let exact = requirement
            .split_once("==")
            .filter(|(name, _)| !name.contains(['<', '>', '!', '~', '@']))
            .map(|(name, version)| {
                (
                    name,
                    version
                        .trim_start_matches('=')
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .trim(),
                )
            })
            .filter(|(_, version)| !version.is_empty() && !version.contains(['*', ',']));
        match exact {
            // `name[extra]==1.0` installs `name`.
            Some((name, version)) => pinned.push((
                name.split('[').next().unwrap_or(name).trim().to_owned(),
                version.to_owned(),
            )),
            None => rest.push(requirement_name(requirement)),
        }
    }
    rest.sort();
    rest.dedup();
    (pinned, rest)
}

/// The package a requirement names: the name at its start, the `#egg=` of an address, or, when
/// neither is there, the requirement itself.
fn requirement_name(requirement: &str) -> String {
    let name: String = requirement
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .collect();
    // `git+https://…` and `https://…` start with their scheme, not a name; `pkg @ https://…` does not.
    let after = &requirement[name.len()..];
    let address =
        after.starts_with("://") || after.starts_with('+') || requirement.starts_with(['.', '/']);
    if !name.is_empty() && !address {
        return name;
    }
    match requirement.split_once("#egg=") {
        Some((_, egg)) => egg.split('&').next().unwrap_or(egg).to_owned(),
        None => requirement.chars().take(60).collect(),
    }
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
        if disagreement.comparison.not_all_compared() {
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
                vendor: "StackVet",
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
    Some(crate::finding::found(Finding {
            also_reported_by: Vec::new(),
            fingerprint: String::new(),
            earlier_fingerprints: Vec::new(),
            marked_test_code: false,
            bundled_library: None,
            outranked: None,
            also_on_this_line: Vec::new(),
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
    }))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod not_compared_tests;
