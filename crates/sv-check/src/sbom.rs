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

mod cyclonedx;
mod lockfiles;
pub use cyclonedx::*;
use lockfiles::*;

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

/// Every lockfile reader on the same text, the way a check reads a lockfile an app hands `sv`: for
/// the fuzzing targets (ADR-077), which call each reader by its one public door rather than widening
/// the readers themselves. It returns nothing worth keeping; what matters is that it returns.
#[doc(hidden)]
pub fn read_as_every_lockfile(text: &str) {
    let _ = from_package_lock(text);
    let _ = from_package_table_toml(text);
    let _ = from_pipfile_lock(text);
    let _ = from_pipfile(text);
    let _ = from_yarn_lock(text);
    let _ = from_bun_lock(text);
    let _ = from_gradle_lockfile(text);
    let _ = from_composer_lock(text);
    let _ = from_pnpm_lock(text);
    let _ = from_gemfile_lock(text);
    let _ = from_go_mod(text, Some(text));
    let _ = from_go_mod(text, None);
    let _ = from_go_sum(text);
    let _ = from_pylock(text);
    let _ = from_pinned_requirements(text);
    let _ = from_requirements(text);
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod not_compared_tests;
