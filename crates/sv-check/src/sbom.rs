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
use sv_scan::ecosystems::{DetectedEcosystem, detect};

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
}

/// Builds the bill of materials for an app folder.
pub fn build(app_dir: &Path) -> Sbom {
    let mut sbom = Sbom::default();
    for eco in detect(app_dir) {
        read_ecosystem(app_dir, &eco, &mut sbom);
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
        Some("Pipfile.lock") => read("Pipfile.lock").as_deref().map(from_pipfile_lock),
        Some("yarn.lock") => read("yarn.lock").as_deref().map(from_yarn_lock),
        Some("gradle.lockfile") => read("gradle.lockfile").as_deref().map(from_gradle_lockfile),
        Some("composer.lock") => read("composer.lock").as_deref().map(from_composer_lock),
        Some("Gemfile.lock") => read("Gemfile.lock").as_deref().map(from_gemfile_lock),
        Some("pnpm-lock.yaml") => read("pnpm-lock.yaml").as_deref().map(from_pnpm_lock),
        Some("go.sum") => read("go.sum").as_deref().map(from_go_sum),
        Some("requirements.lock") => read("requirements.lock")
            .as_deref()
            .map(from_pinned_requirements),
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
        for (name, entry) in map {
            if let Some(version) = entry.get("version").and_then(|x| x.as_str()) {
                out.push((name.clone(), version.to_owned()));
            }
        }
    }
    out
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
fn from_pipfile_lock(text: &str) -> Vec<(String, String)> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for section in ["default", "develop"] {
        if let Some(map) = v.get(section).and_then(|p| p.as_object()) {
            for (name, entry) in map {
                if let Some(version) = entry.get("version").and_then(|x| x.as_str()) {
                    // "==3.0.0" is a pin written as a specifier; the version is what follows it.
                    out.push((name.clone(), version.trim_start_matches("==").to_owned()));
                }
            }
        }
    }
    out
}

/// Yarn's classic lockfile: a header line naming one or more ranges, then an indented `version "x"`.
///
/// The header is the *range* that was asked for, which is not the package name — `lodash@^4.17.0` and
/// `lodash@~4.17.20` are two headers for one package. The name is everything before the last `@`, so a
/// scoped package like `@babel/core@^7` keeps its scope.
fn from_yarn_lock(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut pending: Option<String> = None;
    for line in text.lines() {
        if line.trim_start().starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            // A header may list several ranges separated by commas; they are all the same package.
            let first = line.trim_end_matches(':').split(',').next().unwrap_or(line);
            let spec = first.trim().trim_matches('"');
            pending = spec
                .rfind('@')
                .filter(|i| *i > 0)
                .map(|i| spec[..i].to_owned());
            continue;
        }
        if let Some(rest) = line.trim().strip_prefix("version ")
            && let Some(name) = pending.take()
        {
            out.push((name, rest.trim().trim_matches('"').to_owned()));
        }
    }
    out.sort();
    out.dedup();
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
///   v6:  `/express/4.18.2:` and `/@babel/core/7.23.0:`
fn from_pnpm_lock(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut in_packages = false;

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

        let parsed = if let Some(rest) = key.strip_prefix('/') {
            // v6: /name/version, where the name may itself contain a slash when scoped.
            rest.rsplit_once('/')
                .map(|(name, version)| (name.to_owned(), version.to_owned()))
        } else {
            // v9: name@version, where a scoped name contains its own @.
            key.rsplit_once('@')
                .filter(|(name, _)| !name.is_empty())
                .map(|(name, version)| (name.to_owned(), version.to_owned()))
        };
        // A version starts with a digit. Anything else means this is not the key shape expected, and
        // inventing a package out of it would be worse than admitting the file was not understood.
        if let Some((name, version)) = parsed
            && version.starts_with(|c: char| c.is_ascii_digit())
        {
            out.push((name, version));
        }
    }

    out.sort();
    out.dedup();
    out
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
        if let Some((name, rest)) = entry.split_once(" (")
            && let Some(version) = rest.strip_suffix(')')
        {
            out.push((name.to_owned(), version.to_owned()));
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
fn from_pinned_requirements(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('-'))
        .filter_map(|l| l.split_once("=="))
        .map(|(name, version)| {
            (
                name.trim().to_owned(),
                version
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
pub fn completeness_verified(sbom: &Sbom) -> Option<crate::verified::Verified> {
    if !sbom.is_complete() || sbom.components.is_empty() {
        return None;
    }
    Some(crate::verified::Verified::new(
        "sbom",
        &[INVENTORY_REQUIREMENT],
        format!(
            "an inventory of {} third-party librar{}, each at the version actually installed, from \
             every ecosystem found in the app",
            sbom.components.len(),
            if sbom.components.len() == 1 {
                "y"
            } else {
                "ies"
            }
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
    fn pnpm_lock_v6_uses_slashes_and_is_read_too() {
        let dir = scratch("pnpm6");
        fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
        fs::write(
            dir.join("pnpm-lock.yaml"),
            "lockfileVersion: 6.0\n\npackages:\n\n  /express/4.18.2:\n    resolution: {integrity: sha512-x}\n\n  /@babel/core/7.23.0:\n    resolution: {integrity: sha512-y}\n",
        )
        .unwrap();
        let sbom = build(&dir);
        let names: Vec<&str> = sbom.components.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["@babel/core", "express"], "{sbom:?}");
        fs::remove_dir_all(&dir).ok();
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
