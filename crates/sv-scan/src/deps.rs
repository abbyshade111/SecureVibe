//! Dependency names, pulled out of whatever manifests the app has.
//!
//! Deliberately shallow. This is not a resolver and must never be mistaken for one: it collects the
//! names an app declares, so a signature can be matched against them. What is actually installed is
//! a different question, and an ecosystem that pins nothing cannot answer it at all — which is why
//! `ecosystems::unpinned` exists and is reported separately.

use std::collections::BTreeSet;
use std::path::Path;

/// A dependency name, and the manifest that declared it, so a finding can point at a real file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Declared {
    pub ecosystem: String,
    pub manifest: String,
    pub name: String,
}

pub fn read(app_dir: &Path) -> Vec<Declared> {
    let mut out = BTreeSet::new();
    for eco in super::ecosystems::detect(app_dir) {
        let path = app_dir.join(&eco.manifest);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let names = match super::ecosystems::file_name(&eco.manifest) {
            "package.json" => from_package_json(&text),
            "requirements.txt" => from_requirements(&text),
            "pyproject.toml" | "Cargo.toml" => from_toml_manifest(&text),
            "go.mod" => from_go_mod(&text),
            "Gemfile" => from_gemfile(&text),
            "composer.json" => from_composer(&text),
            "pom.xml" => from_pom(&text),
            "build.gradle" | "build.gradle.kts" => from_gradle(&text),
            _ => Vec::new(),
        };
        for name in names {
            out.insert(Declared {
                ecosystem: eco.name.clone(),
                manifest: eco.manifest.clone(),
                name,
            });
        }
    }
    out.into_iter().collect()
}

fn from_package_json(text: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ]
    .iter()
    .filter_map(|k| v.get(*k))
    .filter_map(|d| d.as_object())
    .flat_map(|o| o.keys().cloned())
    .collect()
}

fn from_requirements(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('-'))
        // Strip the version specifier: "lxml>=4.9" is the lxml dependency.
        .map(|l| {
            l.split(|c: char| "=<>!~[; ".contains(c))
                .next()
                .unwrap_or(l)
                .trim()
                .to_owned()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

/// `pyproject.toml` and `Cargo.toml` both keep dependencies as table keys or PEP 508 strings.
/// Matching is by name, so reading the keys is enough without a full TOML parse of every dialect.
fn from_toml_manifest(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_deps = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_deps = line.contains("dependencies");
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if in_deps && let Some((name, _)) = line.split_once('=') {
            let name = name.trim().trim_matches('"').trim();
            if !name.is_empty() {
                out.push(name.to_owned());
            }
        }
        // PEP 621 style: dependencies = ["lxml>=4.9", "flask"]
        if line.starts_with('"') || line.starts_with('\'') {
            let inner = line.trim_matches(|c| c == '"' || c == '\'' || c == ',' || c == ' ');
            let name = inner
                .split(|c: char| "=<>!~[; ".contains(c))
                .next()
                .unwrap_or(inner);
            if !name.is_empty() {
                out.push(name.to_owned());
            }
        }
    }
    out
}

fn from_go_mod(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("//"))
        .filter_map(|l| {
            let l = l.strip_prefix("require ").unwrap_or(l);
            if l.starts_with("module ") || l.starts_with("go ") || l == "require (" || l == ")" {
                return None;
            }
            l.split_whitespace().next().map(str::to_owned)
        })
        .collect()
}

fn from_gemfile(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix("gem "))
        .map(|l| l.trim_start_matches(['"', '\'']))
        .filter_map(|l| l.split(['"', '\'']).next())
        .map(str::to_owned)
        .collect()
}

fn from_composer(text: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    ["require", "require-dev"]
        .iter()
        .filter_map(|k| v.get(*k))
        .filter_map(|d| d.as_object())
        .flat_map(|o| o.keys().cloned())
        .collect()
}

/// Maven and Gradle are read as text on purpose: an artifact id is all a signature needs, and
/// parsing the whole build file would be a resolver, which this is not.
fn from_pom(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("<artifactId>") {
        rest = &rest[start + "<artifactId>".len()..];
        if let Some(end) = rest.find("</artifactId>") {
            out.push(rest[..end].trim().to_owned());
            rest = &rest[end..];
        } else {
            break;
        }
    }
    out
}

fn from_gradle(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| {
            [
                "implementation",
                "api",
                "compile",
                "testImplementation",
                "runtimeOnly",
            ]
            .iter()
            .any(|k| l.starts_with(k))
        })
        .filter_map(|l| {
            let quoted = l.split(['"', '\'']).nth(1)?;
            // "group:artifact:version" — the artifact id is what a signature names.
            Some(quoted.split(':').nth(1).unwrap_or(quoted).to_owned())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_version_specifiers_from_requirements() {
        let got =
            from_requirements("lxml>=4.9.0\n# a comment\nflask==3.0.0\n-r other.txt\n\nldap3\n");
        assert_eq!(got, vec!["lxml", "flask", "ldap3"]);
    }

    #[test]
    fn reads_every_dependency_block_of_a_package_json() {
        let got =
            from_package_json(r#"{"dependencies":{"ws":"^8"},"devDependencies":{"vitest":"^1"}}"#);
        assert!(got.contains(&"ws".to_owned()) && got.contains(&"vitest".to_owned()));
    }

    #[test]
    fn reads_both_toml_dependency_styles() {
        let got = from_toml_manifest(
            "[project]\ndependencies = [\n  \"lxml>=4.9\",\n]\n\n[tool.poetry.dependencies]\nflask = \"^3.0\"\n",
        );
        assert!(
            got.contains(&"lxml".to_owned()),
            "PEP 621 list style: {got:?}"
        );
        assert!(
            got.contains(&"flask".to_owned()),
            "poetry table style: {got:?}"
        );
    }

    #[test]
    fn reads_maven_artifact_ids() {
        let got = from_pom(
            "<dependency><groupId>org.dom4j</groupId><artifactId>dom4j</artifactId></dependency>",
        );
        assert_eq!(got, vec!["dom4j"]);
    }

    #[test]
    fn reads_the_artifact_from_a_gradle_coordinate() {
        let got = from_gradle("    implementation 'org.dom4j:dom4j:2.1.3'\n");
        assert_eq!(got, vec!["dom4j"]);
    }
}
