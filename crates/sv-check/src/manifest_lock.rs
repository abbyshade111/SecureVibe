//! Whether a manifest and the lockfile beside it describe the same app.
//!
//! `sv` reads the lockfile when there is one, because it says what is installed. A manifest can
//! move on without it: on 23 September 2026 a dependency bot raised `pyjwt` in
//! `examples/flask-booking/requirements.txt` and left `requirements.lock` alone, so for ten days
//! GitHub, which reads the manifest, and `sv`, which reads the lock, described two different apps.
//! Whoever installs from the other file runs versions the report never looked at.
//!
//! Each package the manifest asks for is held to the versions the lockfile has for it. A package
//! the lockfile does not have at all disagrees too. What cannot be compared (a pre-release, a git
//! URL, a range written in a form not read here) is listed as not compared, never as agreeing.
//!
//! Nine manifests are read: `requirements.txt`, `pyproject.toml` (its own list and Poetry's),
//! `package.json`, `Cargo.toml`, `composer.json`, `Gemfile`, `go.mod`, and Gradle's `build.gradle`
//! and `build.gradle.kts`, each with the range rules its package manager documents.

/// What the manifest asks for, in a form a version can be held to.
#[derive(Debug, Clone)]
enum Spec {
    /// Python's comma-joined clauses, all of which must hold.
    Python(Vec<(PyOp, String)>),
    /// npm's `||`-joined sets of comparators; a version must meet every comparator of one set.
    /// Cargo's and Composer's requirements are read into the same form.
    Npm(Vec<Comparators>),
    /// One version, written out: Go's `require` names exactly the version it builds with.
    Exact(String),
    /// Gradle's: clauses on the release number, for a version whose words after it (`-jre`,
    /// `.Final`) are these. A version with other words cannot be put in order against them.
    Qualified(String, Vec<(PyOp, String)>),
    /// Written in a form not read here.
    Unread,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PyOp {
    Exact,
    Equal,
    NotEqual,
    Compatible,
    AtLeast,
    AtMost,
    Above,
    Below,
}

/// One set of npm comparators, all of which a version must meet: `>=1.2.3 <2.0.0`.
type Comparators = Vec<(NpmOp, [u64; 3])>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NpmOp {
    AtLeast,
    AtMost,
    Above,
    Below,
    Equal,
}

/// One package the manifest asks for.
#[derive(Debug, Clone)]
struct Wanted {
    /// The name the lockfile is searched for, normalized as its ecosystem compares names.
    key: String,
    /// The package as the manifest writes it, for a person to find it there.
    asked: String,
    spec: Spec,
    /// The package may rightly be missing from the lockfile: a line with a platform condition, an
    /// optional dependency, an extra, or a group. Missing, it is not compared; present, it still is.
    conditional: bool,
}

/// A package where the manifest and the lockfile say different things.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Differs {
    /// As the manifest writes it: `pyjwt==2.13.0`, or `express ^4.18.0`.
    pub asked: String,
    /// Every version the lockfile has for it; empty when it has none.
    pub locked: Vec<String>,
}

/// What comparing one manifest with its lockfile found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Comparison {
    pub differs: Vec<Differs>,
    /// Packages the manifest asks for that could not be held to the lockfile, as it writes them.
    pub not_compared: Vec<String>,
}

/// Compares a manifest with what its lockfile has, when the manifest is one read here. `None` for a
/// manifest of another kind, or one that could not be read.
pub fn compare(
    manifest_name: &str,
    manifest: &str,
    locked: &[(String, String)],
) -> Option<Comparison> {
    type Read = (Vec<Wanted>, fn(&str) -> String, fn(&str) -> String);
    let (wanted, key, version_of): Read = match manifest_name {
        "requirements.txt" => (python_wants(manifest), python_name, str::to_owned),
        "pyproject.toml" => (pyproject_wants(manifest)?, python_name, str::to_owned),
        "Pipfile" => (pipfile_wants(manifest)?, python_name, str::to_owned),
        "package.json" => (npm_wants(manifest)?, str::to_owned, str::to_owned),
        "Cargo.toml" => (cargo_wants(manifest)?, cargo_name, str::to_owned),
        "composer.json" => (composer_wants(manifest)?, str::to_lowercase, str::to_owned),
        "Gemfile" => (gem_wants(manifest), str::to_owned, gem_version),
        "go.mod" => (go_wants(manifest), str::to_owned, str::to_owned),
        "build.gradle" | "build.gradle.kts" => {
            (gradle_wants(manifest), str::to_owned, str::to_owned)
        }
        _ => return None,
    };
    let mut out = Comparison::default();
    for want in wanted {
        let versions: Vec<String> = locked
            .iter()
            .filter(|(name, _)| key(name) == want.key)
            .map(|(_, version)| version_of(version))
            .collect();
        if versions.is_empty() {
            if want.conditional {
                out.not_compared.push(want.asked);
            } else {
                out.differs.push(Differs {
                    asked: want.asked,
                    locked: Vec::new(),
                });
            }
            continue;
        }
        let verdicts: Vec<Option<bool>> = versions.iter().map(|v| allows(&want.spec, v)).collect();
        if verdicts.contains(&Some(true)) {
            continue;
        }
        if verdicts.contains(&None) {
            out.not_compared.push(want.asked);
            continue;
        }
        let mut locked = versions;
        locked.sort();
        locked.dedup();
        out.differs.push(Differs {
            asked: want.asked,
            locked,
        });
    }
    Some(out)
}

/// The packages a manifest asks for, each named as its ecosystem compares names, when the manifest
/// is one read here; `None` for a manifest of another kind, or one that could not be read.
///
/// For a check that needs to know *which* packages an app uses and not which versions, such as
/// whether it has a rich-text editor, when there is no lockfile to read them from.
pub fn declared_names(manifest_name: &str, manifest: &str) -> Option<Vec<String>> {
    let wanted = match manifest_name {
        "requirements.txt" => python_wants(manifest),
        "pyproject.toml" => pyproject_wants(manifest)?,
        "Pipfile" => pipfile_wants(manifest)?,
        "package.json" => npm_wants(manifest)?,
        "Cargo.toml" => cargo_wants(manifest)?,
        "composer.json" => composer_wants(manifest)?,
        "Gemfile" => gem_wants(manifest),
        "go.mod" => go_wants(manifest),
        "build.gradle" | "build.gradle.kts" => gradle_wants(manifest),
        _ => return None,
    };
    Some(wanted.into_iter().map(|w| w.key).collect())
}

/// Whether `version` is one the spec allows; `None` when that cannot be told.
fn allows(spec: &Spec, version: &str) -> Option<bool> {
    match spec {
        Spec::Unread => None,
        Spec::Exact(wanted) => Some(wanted == version),
        Spec::Qualified(qualifier, clauses) => {
            let (release, words) = gradle_split(version);
            if &words != qualifier {
                return None;
            }
            allows(&Spec::Python(clauses.clone()), &release)
        }
        Spec::Python(clauses) => {
            let mut all = Some(true);
            for (op, wanted) in clauses {
                match python_allows(*op, wanted, version) {
                    Some(true) => {}
                    Some(false) => return Some(false),
                    None => all = None,
                }
            }
            all
        }
        Spec::Npm(sets) => {
            let have = npm_version(version)?;
            Some(sets.iter().any(|set| {
                set.iter().all(|(op, bound)| match op {
                    NpmOp::AtLeast => have >= *bound,
                    NpmOp::AtMost => have <= *bound,
                    NpmOp::Above => have > *bound,
                    NpmOp::Below => have < *bound,
                    NpmOp::Equal => have == *bound,
                })
            }))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Python: `requirements.txt` (PEP 508 lines) and PEP 440 versions, as far as plain release numbers go.

/// A Python package name as the index compares it (PEP 503): lower case, with runs of `-`, `_`,
/// and `.` read as one `-`.
pub(crate) fn python_name(name: &str) -> String {
    let mut out = String::new();
    let mut gap = false;
    for c in name.trim().chars() {
        if matches!(c, '-' | '_' | '.') {
            gap = true;
        } else {
            if gap && !out.is_empty() {
                out.push('-');
            }
            gap = false;
            out.extend(c.to_lowercase());
        }
    }
    out
}

fn python_wants(text: &str) -> Vec<Wanted> {
    let mut out = Vec::new();
    for line in text.lines() {
        // A comment starts at `#` at the start of a line or after white space.
        let line = match line.find(" #").or_else(|| line.find("\t#")) {
            Some(at) => &line[..at],
            None => line,
        };
        // A `\\` at the end carries the requirement on to the next line, where its `--hash`
        // options are; it is not part of the version.
        let line = line.trim().trim_end_matches('\\').trim();
        // Options (`-r`, `-e`, `--hash` on its own line) and comments are not packages.
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        let (requirement, marker) = match line.split_once(';') {
            Some((r, m)) => (r.trim(), !m.trim().is_empty()),
            None => (line, false),
        };
        // Options on the same line (`--hash=...`) are not part of the requirement.
        let requirement = requirement
            .split(" --")
            .next()
            .unwrap_or(requirement)
            .trim();
        let name_end = requirement
            .find(|c: char| "[<>=!~ (@".contains(c))
            .unwrap_or(requirement.len());
        let name = &requirement[..name_end];
        if name.is_empty() {
            continue;
        }
        let mut rest = requirement[name_end..].trim();
        if let Some(after) = rest.strip_prefix('[') {
            rest = after.split_once(']').map_or("", |(_, r)| r).trim();
        }
        let rest = rest.trim_start_matches('(').trim_end_matches(')').trim();
        let spec = if rest.starts_with('@') {
            // A direct URL: no version to hold it to.
            Spec::Unread
        } else if rest.is_empty() {
            Spec::Python(Vec::new())
        } else {
            python_spec(rest).map_or(Spec::Unread, Spec::Python)
        };
        out.push(Wanted {
            key: python_name(name),
            asked: requirement.split_whitespace().collect::<Vec<_>>().join(""),
            // A direct URL (`pkg @ git+https://…`) is installed without a version, and a
            // lockfile reader may leave it out of the list: missing, it is not compared.
            conditional: marker || rest.starts_with('@'),
            spec,
        });
    }
    out
}

fn python_spec(text: &str) -> Option<Vec<(PyOp, String)>> {
    let mut clauses = Vec::new();
    for clause in text.split(',') {
        let clause = clause.trim();
        let (op, version) = [
            ("===", PyOp::Exact),
            ("==", PyOp::Equal),
            ("!=", PyOp::NotEqual),
            ("~=", PyOp::Compatible),
            (">=", PyOp::AtLeast),
            ("<=", PyOp::AtMost),
            (">", PyOp::Above),
            ("<", PyOp::Below),
        ]
        .iter()
        .find_map(|(sign, op)| clause.strip_prefix(sign).map(|v| (*op, v.trim())))?;
        if version.is_empty() {
            return None;
        }
        clauses.push((op, version.to_owned()));
    }
    Some(clauses)
}

/// A plain release number, `2.8.0`: its parts, or `None` for anything more (a pre-release, a
/// post-release, a local version), which is not compared here.
fn python_release(version: &str) -> Option<Vec<u64>> {
    let version = version.trim().strip_prefix('v').unwrap_or(version.trim());
    version.split('.').map(|part| part.parse().ok()).collect()
}

/// Two releases compared as PEP 440 compares them: `2.8` and `2.8.0` are the same.
fn release_cmp(a: &[u64], b: &[u64]) -> std::cmp::Ordering {
    let len = a.len().max(b.len());
    let at = |v: &[u64], i: usize| v.get(i).copied().unwrap_or(0);
    (0..len)
        .map(|i| at(a, i).cmp(&at(b, i)))
        .find(|o| o.is_ne())
        .unwrap_or(std::cmp::Ordering::Equal)
}

fn python_allows(op: PyOp, wanted: &str, have: &str) -> Option<bool> {
    if op == PyOp::Exact {
        return Some(wanted.trim() == have.trim());
    }
    // `==1.2.*` and `!=1.2.*`: a prefix of the release.
    if let Some(prefix) = wanted.strip_suffix(".*") {
        let prefix = python_release(prefix)?;
        let have = python_release(have)?;
        let matches = have.len() >= prefix.len() && have[..prefix.len()] == prefix[..];
        return match op {
            PyOp::Equal => Some(matches),
            PyOp::NotEqual => Some(!matches),
            _ => None,
        };
    }
    // The same text is the same version, whatever it holds.
    if op == PyOp::Equal && wanted.trim() == have.trim() {
        return Some(true);
    }
    let w = python_release(wanted)?;
    let h = python_release(have)?;
    let order = release_cmp(&h, &w);
    use std::cmp::Ordering::*;
    Some(match op {
        PyOp::Equal => order == Equal,
        PyOp::NotEqual => order != Equal,
        PyOp::AtLeast => order != Less,
        PyOp::AtMost => order != Greater,
        PyOp::Above => order == Greater,
        PyOp::Below => order == Less,
        // `~=2.2.1` is `>=2.2.1, ==2.2.*`; it needs two parts at least.
        PyOp::Compatible => {
            if w.len() < 2 {
                return None;
            }
            let prefix = &w[..w.len() - 1];
            order != Less && h.len() >= prefix.len() && h[..prefix.len()] == prefix[..]
        }
        PyOp::Exact => unreachable!("handled above"),
    })
}

// ---------------------------------------------------------------------------------------------
// npm: `package.json` and the range forms npm documents, for versions without a pre-release.

fn npm_wants(text: &str) -> Option<Vec<Wanted>> {
    let json: serde_json::Value = serde_json::from_str(text).ok()?;
    let mut out = Vec::new();
    // Peer dependencies are the host's to install, and may rightly be missing.
    for field in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(map) = json.get(field).and_then(|d| d.as_object()) else {
            continue;
        };
        for (name, range) in map {
            let range = range.as_str().unwrap_or_default();
            let elsewhere = npm_elsewhere(range);
            out.push(Wanted {
                key: name.clone(),
                asked: format!("{name} {range}"),
                spec: if elsewhere {
                    Spec::Unread
                } else {
                    npm_spec(range).map_or(Spec::Unread, Spec::Npm)
                },
                // An optional dependency that failed to build is left out of nothing: npm still
                // locks it. Only one from somewhere other than the registry may be missing from
                // the list read from the lockfile, which names packages by what they are.
                conditional: elsewhere,
            });
        }
    }
    Some(out)
}

/// Whether a dependency comes from somewhere other than the registry under its own name: another
/// package of the same workspace (`workspace:*`), a folder (`file:../lib`, `link:`, `./lib`),
/// a repository (`git+https://…`, `github:user/repo`, `user/repo`), an archive's address, or the
/// registry under another name (`npm:other@1.2.3`). The lockfile readers list it, if at all, by
/// what it is, so its absence under this name says nothing.
fn npm_elsewhere(range: &str) -> bool {
    let range = range.trim();
    const PREFIXES: &[&str] = &[
        "workspace:",
        "file:",
        "link:",
        "portal:",
        "patch:",
        "npm:",
        "git+",
        "git:",
        "github:",
        "gitlab:",
        "bitbucket:",
        "http:",
        "https:",
        "./",
        "../",
        "~/",
        "/",
    ];
    PREFIXES.iter().any(|p| range.starts_with(p)) || (range.contains('/') && !range.contains(' '))
}

/// `1.2.3` as three numbers; `None` for a pre-release or anything else.
fn npm_version(text: &str) -> Option<[u64; 3]> {
    let text = text.trim().trim_start_matches(['v', '=']);
    let text = text.split('+').next()?;
    if text.contains('-') {
        return None;
    }
    let parts: Vec<u64> = text
        .split('.')
        .map(|p| p.parse().ok())
        .collect::<Option<_>>()?;
    match parts[..] {
        [a, b, c] => Some([a, b, c]),
        _ => None,
    }
}

/// A partial version, `1`, `1.2`, `1.x`, `*`: the parts given, the rest left open.
fn npm_partial(text: &str) -> Option<Vec<u64>> {
    let text = text.trim().trim_start_matches(['v', '=']);
    if text.contains('-') || text.contains('+') {
        return None;
    }
    let mut parts = Vec::new();
    for part in text.split('.') {
        if matches!(part, "x" | "X" | "*") {
            break;
        }
        parts.push(part.parse().ok()?);
    }
    (parts.len() <= 3 && !text.is_empty()).then_some(parts)
}

/// The first version above every version the partial covers: `1.2` gives `1.3.0`, `1` gives `2.0.0`.
fn npm_next(parts: &[u64]) -> [u64; 3] {
    match parts {
        [a] => [a + 1, 0, 0],
        [a, b] => [*a, b + 1, 0],
        [a, b, c] => [*a, *b, c + 1],
        _ => [u64::MAX, 0, 0],
    }
}

fn npm_floor(parts: &[u64]) -> [u64; 3] {
    let at = |i: usize| parts.get(i).copied().unwrap_or(0);
    [at(0), at(1), at(2)]
}

fn npm_spec(text: &str) -> Option<Vec<Comparators>> {
    let text = text.trim();
    // Tags, paths, URLs, workspaces, and aliases name no version range.
    if text.contains(':')
        || text.contains('/')
        || text
            .chars()
            .any(|c| c.is_ascii_alphabetic() && !matches!(c, 'x' | 'X' | 'v'))
    {
        return None;
    }
    let mut sets = Vec::new();
    for set in text.split("||") {
        let set = set.trim();
        let mut comparators = Vec::new();
        if let Some((low, high)) = set.split_once(" - ") {
            let low = npm_partial(low)?;
            let high = npm_partial(high)?;
            comparators.push((NpmOp::AtLeast, npm_floor(&low)));
            if high.len() == 3 {
                comparators.push((NpmOp::AtMost, npm_floor(&high)));
            } else if !high.is_empty() {
                comparators.push((NpmOp::Below, npm_next(&high)));
            }
            sets.push(comparators);
            continue;
        }
        // `>= 1.2.3` may be written with a space after the operator.
        let joined = set
            .replace(">= ", ">=")
            .replace("<= ", "<=")
            .replace("> ", ">")
            .replace("< ", "<")
            .replace("= ", "=");
        for word in joined.split_whitespace() {
            comparators.extend(npm_comparator(word)?);
        }
        sets.push(comparators);
    }
    Some(sets)
}

/// One comparator, as the bounds it stands for.
fn npm_comparator(word: &str) -> Option<Comparators> {
    let (op, rest) = [">=", "<=", ">", "<", "=", "^", "~"]
        .iter()
        .find_map(|op| word.strip_prefix(op).map(|r| (*op, r)))
        .unwrap_or(("", word));
    let parts = npm_partial(rest)?;
    let floor = npm_floor(&parts);
    Some(match op {
        ">=" => vec![(NpmOp::AtLeast, floor)],
        ">" if parts.len() == 3 => vec![(NpmOp::Above, floor)],
        ">" if parts.is_empty() => vec![(NpmOp::Below, [0, 0, 0])],
        ">" => vec![(NpmOp::AtLeast, npm_next(&parts))],
        "<" => vec![(NpmOp::Below, floor)],
        "<=" if parts.len() == 3 => vec![(NpmOp::AtMost, floor)],
        "<=" if parts.is_empty() => vec![],
        "<=" => vec![(NpmOp::Below, npm_next(&parts))],
        "^" => {
            // Up to the next change in the first part that is not zero, among those given.
            let upper = match parts[..] {
                [] => return Some(vec![]),
                [0] => [1, 0, 0],
                [0, 0] => [0, 1, 0],
                [0, 0, c] => [0, 0, c + 1],
                [0, b, ..] => [0, b + 1, 0],
                [a, ..] => [a + 1, 0, 0],
            };
            vec![(NpmOp::AtLeast, floor), (NpmOp::Below, upper)]
        }
        "~" => {
            let upper = match parts[..] {
                [] => return Some(vec![]),
                [a] => [a + 1, 0, 0],
                [a, b, ..] => [a, b + 1, 0],
            };
            vec![(NpmOp::AtLeast, floor), (NpmOp::Below, upper)]
        }
        // `1.2.3`, `=1.2.3`, `1.2`, `1.x`, `*`.
        _ => match parts.len() {
            0 => vec![],
            3 => vec![(NpmOp::Equal, floor)],
            _ => vec![(NpmOp::AtLeast, floor), (NpmOp::Below, npm_next(&parts))],
        },
    })
}

// ---------------------------------------------------------------------------------------------
// `pyproject.toml`: the project's own list (PEP 621), its extras and groups, and Poetry's tables.

fn pyproject_wants(text: &str) -> Option<Vec<Wanted>> {
    let doc: toml::Table = toml::from_str(text).ok()?;
    let mut out = Vec::new();
    let lines = |value: Option<&toml::Value>| -> String {
        value
            .and_then(toml::Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(toml::Value::as_str)
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default()
    };
    let project = doc.get("project");
    out.extend(python_wants(&lines(
        project.and_then(|p| p.get("dependencies")),
    )));
    // Extras and groups are installed only when asked for, so each may be missing from a lock.
    let mut optional = Vec::new();
    if let Some(extras) = project
        .and_then(|p| p.get("optional-dependencies"))
        .and_then(toml::Value::as_table)
    {
        optional.extend(extras.values().map(|v| lines(Some(v))));
    }
    if let Some(groups) = doc.get("dependency-groups").and_then(toml::Value::as_table) {
        optional.extend(groups.values().map(|v| lines(Some(v))));
    }
    for list in optional {
        out.extend(python_wants(&list).into_iter().map(|mut w| {
            w.conditional = true;
            w
        }));
    }
    // Poetry's own tables.
    let poetry = doc.get("tool").and_then(|t| t.get("poetry"));
    let mut tables: Vec<(&toml::Table, bool)> = Vec::new();
    if let Some(t) = poetry
        .and_then(|p| p.get("dependencies"))
        .and_then(toml::Value::as_table)
    {
        tables.push((t, false));
    }
    if let Some(t) = poetry
        .and_then(|p| p.get("dev-dependencies"))
        .and_then(toml::Value::as_table)
    {
        tables.push((t, true));
    }
    if let Some(groups) = poetry
        .and_then(|p| p.get("group"))
        .and_then(toml::Value::as_table)
    {
        for group in groups.values() {
            if let Some(t) = group.get("dependencies").and_then(toml::Value::as_table) {
                tables.push((t, true));
            }
        }
    }
    for (table, in_group) in tables {
        for (name, value) in table {
            // The Python the project runs on, not a package.
            if name == "python" {
                continue;
            }
            let (constraint, conditional) = match value {
                toml::Value::String(c) => (Some(c.as_str()), false),
                toml::Value::Table(t) => {
                    let elsewhere = ["git", "path", "url"].iter().any(|k| t.contains_key(*k));
                    let conditional =
                        ["optional", "markers", "python", "platform"]
                            .iter()
                            .any(|k| {
                                t.contains_key(*k)
                                    && t.get(*k) != Some(&toml::Value::Boolean(false))
                            });
                    (
                        if elsewhere {
                            None
                        } else {
                            t.get("version").and_then(toml::Value::as_str)
                        },
                        conditional,
                    )
                }
                // A list of constraints, one per platform or Python: not read.
                _ => (None, true),
            };
            out.push(Wanted {
                key: python_name(name),
                asked: format!("{name} {}", constraint.unwrap_or("(not a version)")),
                spec: constraint
                    .and_then(poetry_spec)
                    .map_or(Spec::Unread, Spec::Python),
                conditional: conditional || in_group,
            });
        }
    }
    Some(out)
}

/// Pipenv's `Pipfile`: each package category (`[packages]`, `[dev-packages]`, and any other a
/// project adds) maps a name to `"*"`, PEP 440 clauses, or a table with a `version` among other
/// keys. `pipenv lock` locks every category, so none is optional; a platform condition makes a
/// package one that may rightly be missing, and one installed from a repository, a folder, or an
/// address has no version to hold it to.
fn pipfile_wants(text: &str) -> Option<Vec<Wanted>> {
    let doc: toml::Table = toml::from_str(text).ok()?;
    let mut out = Vec::new();
    for (category, packages) in &doc {
        if sv_scan::deps::PIPFILE_NOT_PACKAGES.contains(&category.as_str()) {
            continue;
        }
        let Some(packages) = packages.as_table() else {
            continue;
        };
        for (name, value) in packages {
            let (constraint, conditional) = match value {
                toml::Value::String(c) => (Some(c.as_str()), false),
                toml::Value::Table(t) => {
                    let elsewhere = ["git", "path", "file", "url", "hg", "svn", "bzr"]
                        .iter()
                        .any(|k| t.contains_key(*k));
                    let conditional = t.keys().any(|k| {
                        k == "markers"
                            || k == "sys_platform"
                            || k == "os_name"
                            || k == "python_version"
                            || k.starts_with("platform_")
                    });
                    let version = t.get("version").and_then(toml::Value::as_str);
                    // One from a repository or a folder is locked with no version, or is the app
                    // itself, so it is not in the lockfile's list to be held to.
                    (
                        if elsewhere {
                            None
                        } else {
                            Some(version.unwrap_or("*"))
                        },
                        conditional || elsewhere,
                    )
                }
                _ => (None, false),
            };
            let spec = match constraint.map(str::trim) {
                None => Spec::Unread,
                Some("*") | Some("") => Spec::Python(Vec::new()),
                Some(c) => python_spec(c).map_or(Spec::Unread, Spec::Python),
            };
            out.push(Wanted {
                key: python_name(name),
                asked: format!("{name} {}", constraint.unwrap_or("(not a version)")),
                spec,
                conditional,
            });
        }
    }
    Some(out)
}

/// Poetry's constraint (`^1.2`, `~1.2.3`, `1.2.*`, `1.2.3`, or PEP 440 clauses), as PEP 440 clauses.
fn poetry_spec(text: &str) -> Option<Vec<(PyOp, String)>> {
    let text = text.trim();
    if text.contains('|') {
        return None;
    }
    let mut clauses = Vec::new();
    for word in text.split(',').map(str::trim) {
        if word.is_empty() || word == "*" {
            continue;
        }
        let bounded = |rest: &str, bump: fn(&[u64]) -> usize| -> Option<Vec<(PyOp, String)>> {
            let parts = python_release(rest)?;
            Some(vec![
                (PyOp::AtLeast, rest.trim().to_owned()),
                (PyOp::Below, release_text(&bumped(&parts, bump(&parts)))),
            ])
        };
        if let Some(rest) = word.strip_prefix('^') {
            clauses.extend(bounded(rest, caret_place)?);
        } else if let Some(rest) = word.strip_prefix('~').filter(|r| !r.starts_with('=')) {
            clauses.extend(bounded(rest, |p| 1.min(p.len() - 1))?);
        } else if word.starts_with(|c: char| c.is_ascii_digit()) {
            // `1.2.3` is exactly that version, and `1.2.*` its prefix.
            clauses.push((PyOp::Equal, word.to_owned()));
        } else {
            clauses.extend(python_spec(word)?);
        }
    }
    Some(clauses)
}

/// Where `^` raises a version for its upper bound: the first part that is not zero, or the last.
fn caret_place(parts: &[u64]) -> usize {
    parts
        .iter()
        .position(|&p| p != 0)
        .unwrap_or(parts.len() - 1)
}

/// The version with the part at `at` raised by one and everything after it dropped.
fn bumped(parts: &[u64], at: usize) -> Vec<u64> {
    let mut out = parts[..=at].to_vec();
    out[at] += 1;
    out
}

fn release_text(parts: &[u64]) -> String {
    parts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

// ---------------------------------------------------------------------------------------------
// Cargo: `Cargo.toml`, whose bare requirement `1.2` means `^1.2`.

/// Cargo's index treats `-` and `_` in a crate's name alike.
fn cargo_name(name: &str) -> String {
    name.replace('_', "-")
}

fn cargo_wants(text: &str) -> Option<Vec<Wanted>> {
    let doc: toml::Table = toml::from_str(text).ok()?;
    let mut tables: Vec<(&toml::Table, bool)> = Vec::new();
    for kind in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(t) = doc.get(kind).and_then(toml::Value::as_table) {
            tables.push((t, false));
        }
        // A workspace's shared requirements, which its members name with `workspace = true`.
        if let Some(t) = doc
            .get("workspace")
            .and_then(|w| w.get(kind))
            .and_then(toml::Value::as_table)
        {
            tables.push((t, false));
        }
    }
    // Dependencies for one platform only may rightly be missing from a lock made elsewhere.
    if let Some(targets) = doc.get("target").and_then(toml::Value::as_table) {
        for target in targets.values() {
            for kind in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(t) = target.get(kind).and_then(toml::Value::as_table) {
                    tables.push((t, true));
                }
            }
        }
    }
    let mut out = Vec::new();
    for (table, for_a_platform) in tables {
        for (key, value) in table {
            let (requirement, package, optional) = match value {
                toml::Value::String(r) => (Some(r.as_str()), key.as_str(), false),
                toml::Value::Table(t) => {
                    // `workspace = true` takes its requirement from the workspace, which is compared
                    // where it is written; `path` and `git` are not from the registry.
                    if ["workspace", "path", "git"]
                        .iter()
                        .any(|k| t.contains_key(*k))
                    {
                        continue;
                    }
                    (
                        t.get("version").and_then(toml::Value::as_str),
                        t.get("package")
                            .and_then(toml::Value::as_str)
                            .unwrap_or(key),
                        t.get("optional") == Some(&toml::Value::Boolean(true)),
                    )
                }
                _ => (None, key.as_str(), false),
            };
            out.push(Wanted {
                key: cargo_name(package),
                asked: format!("{package} {}", requirement.unwrap_or("(not a version)")),
                spec: requirement
                    .and_then(cargo_spec)
                    .map_or(Spec::Unread, |set| Spec::Npm(vec![set])),
                conditional: for_a_platform || optional,
            });
        }
    }
    Some(out)
}

/// Cargo's comma-joined comparators, all of which must hold.
fn cargo_spec(text: &str) -> Option<Comparators> {
    let mut set = Vec::new();
    for word in text.split(',').map(str::trim) {
        let word = word
            .replace(">= ", ">=")
            .replace("<= ", "<=")
            .replace("> ", ">")
            .replace("< ", "<")
            .replace("= ", "=");
        // A bare requirement is a caret requirement in Cargo, not an exact one as in npm.
        let word = if word.starts_with(|c: char| c.is_ascii_digit()) && !word.contains('*') {
            format!("^{word}")
        } else {
            word
        };
        set.extend(npm_comparator(&word)?);
    }
    Some(set)
}

// ---------------------------------------------------------------------------------------------
// Composer: `composer.json`, whose `~1.2` means `>=1.2 <2.0`, not npm's `<1.3`.

fn composer_wants(text: &str) -> Option<Vec<Wanted>> {
    let json: serde_json::Value = serde_json::from_str(text).ok()?;
    let mut out = Vec::new();
    for field in ["require", "require-dev"] {
        let Some(map) = json.get(field).and_then(|d| d.as_object()) else {
            continue;
        };
        for (name, constraint) in map {
            // PHP itself, its extensions, and Composer's own interfaces are not packages.
            if !name.contains('/') {
                continue;
            }
            let constraint = constraint.as_str().unwrap_or_default();
            out.push(Wanted {
                key: name.to_lowercase(),
                asked: format!("{name} {constraint}"),
                spec: composer_spec(constraint).map_or(Spec::Unread, Spec::Npm),
                conditional: false,
            });
        }
    }
    Some(out)
}

fn composer_spec(text: &str) -> Option<Vec<Comparators>> {
    // Stability flags (`@beta`), branches (`dev-main`), and aliases (`1.0 as 2.0`) name no plain
    // range; each has a word no version reader below takes, so the whole constraint is not read.
    let mut sets = Vec::new();
    for set in text.trim().replace("||", "|").split('|').map(str::trim) {
        if set.contains(" - ") {
            sets.extend(npm_spec(set)?);
            continue;
        }
        let joined = set
            .replace(',', " ")
            .replace(">= ", ">=")
            .replace("<= ", "<=")
            .replace("> ", ">")
            .replace("< ", "<")
            .replace("!= ", "!=")
            .replace("= ", "=");
        let mut comparators = Vec::new();
        for word in joined.split_whitespace() {
            if word.starts_with("!=") {
                return None;
            }
            if let Some(rest) = word.strip_prefix('~') {
                let parts = npm_partial(rest)?;
                if parts.is_empty() {
                    return None;
                }
                let upper = npm_next(&parts[..(parts.len() - 1).max(1)]);
                comparators.push((NpmOp::AtLeast, npm_floor(&parts)));
                comparators.push((NpmOp::Below, upper));
            } else if word.starts_with(|c: char| c.is_ascii_digit() || c == 'v')
                && !word.contains(['*', 'x', 'X'])
            {
                // An exact version: `1.2` is `1.2.0`, not every `1.2.x`.
                comparators.push((NpmOp::Equal, npm_floor(&npm_partial(word)?)));
            } else {
                comparators.extend(npm_comparator(word)?);
            }
        }
        sets.push(comparators);
    }
    Some(sets)
}

// ---------------------------------------------------------------------------------------------
// Bundler: the `gem` lines of a `Gemfile`, whose `~> 1.2` means `>= 1.2, < 2`.

fn gem_wants(text: &str) -> Vec<Wanted> {
    let mut out = Vec::new();
    // Blocks for a platform or an `install_if` hold gems another computer may rightly not install.
    let mut blocks: Vec<bool> = Vec::new();
    for line in text.lines() {
        let line = line.split(" #").next().unwrap_or(line).trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line.ends_with(" do") || line.contains(" do |") {
            // `platform` and `platforms` both.
            blocks.push(line.starts_with("platform") || line.starts_with("install_if"));
            continue;
        }
        if line == "end" {
            blocks.pop();
            continue;
        }
        let Some(rest) = line
            .strip_prefix("gem ")
            .or_else(|| line.strip_prefix("gem("))
        else {
            continue;
        };
        let quoted = quoted_strings(rest);
        let Some((name, after_name)) = quoted.first() else {
            continue;
        };
        // The version constraints are the quoted strings straight after the name, before any option.
        let mut constraints = Vec::new();
        let mut at = *after_name;
        for (text, end) in quoted.iter().skip(1) {
            let between = rest[at..].split(text.as_str()).next().unwrap_or("");
            if between.contains(':') || between.contains("=>") {
                break;
            }
            constraints.push(text.clone());
            at = *end;
        }
        let options = &rest[at..];
        let elsewhere = [
            "git:",
            "github:",
            "path:",
            "gist:",
            "bitbucket:",
            ":git",
            ":github",
            ":path",
        ]
        .iter()
        .any(|o| options.contains(o));
        let conditional = blocks.iter().any(|b| *b)
            || [
                "platforms:",
                "platform:",
                "install_if:",
                ":platforms",
                ":platform",
            ]
            .iter()
            .any(|o| options.contains(o));
        let spec = if elsewhere {
            Spec::Unread
        } else {
            constraints
                .iter()
                .map(|c| gem_clauses(c))
                .collect::<Option<Vec<_>>>()
                .map_or(Spec::Unread, |c| Spec::Python(c.concat()))
        };
        out.push(Wanted {
            key: name.clone(),
            asked: if constraints.is_empty() {
                name.clone()
            } else {
                format!("{name} {}", constraints.join(", "))
            },
            spec,
            conditional,
        });
    }
    out
}

/// The strings in single or double quotes in `text`, each with the position just after it.
fn quoted_strings(text: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    let mut chars = text.char_indices();
    while let Some((_, c)) = chars.next() {
        if c != '"' && c != '\'' {
            continue;
        }
        let mut inner = String::new();
        for (j, d) in chars.by_ref() {
            if d == c {
                out.push((inner, j + 1));
                break;
            }
            inner.push(d);
        }
    }
    out
}

/// One RubyGems requirement, `~> 7.1`, `>= 2.0`, or a bare version, as PEP 440 clauses: RubyGems
/// compares plain release numbers the same way, `1.2` and `1.2.0` alike.
fn gem_clauses(text: &str) -> Option<Vec<(PyOp, String)>> {
    let text = text.trim();
    let (op, version) = ["~>", ">=", "<=", "!=", ">", "<", "="]
        .iter()
        .find_map(|op| text.strip_prefix(op).map(|v| (*op, v.trim())))
        .unwrap_or(("=", text));
    let parts = python_release(version)?;
    Some(match op {
        "~>" => {
            let at = parts.len().saturating_sub(2);
            vec![
                (PyOp::AtLeast, version.to_owned()),
                (PyOp::Below, release_text(&bumped(&parts, at))),
            ]
        }
        ">=" => vec![(PyOp::AtLeast, version.to_owned())],
        "<=" => vec![(PyOp::AtMost, version.to_owned())],
        "!=" => vec![(PyOp::NotEqual, version.to_owned())],
        ">" => vec![(PyOp::Above, version.to_owned())],
        "<" => vec![(PyOp::Below, version.to_owned())],
        _ => vec![(PyOp::Equal, version.to_owned())],
    })
}

/// A gem's version as `Gemfile.lock` writes it, without the platform some gems carry
/// (`1.16.0-x86_64-linux`).
fn gem_version(version: &str) -> String {
    match version.split_once('-') {
        Some((release, platform)) if platform.starts_with(|c: char| c.is_ascii_alphabetic()) => {
            release.to_owned()
        }
        _ => version.to_owned(),
    }
}

// ---------------------------------------------------------------------------------------------
// Go: `go.mod`, whose `require` names the exact version the module builds with.

fn go_wants(text: &str) -> Vec<Wanted> {
    let mut replaced = std::collections::BTreeSet::new();
    let mut required: Vec<(String, String)> = Vec::new();
    let mut block: Option<&str> = None;
    for line in text.lines() {
        let line = line.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line == ")" {
            block = None;
            continue;
        }
        let (directive, rest) = match block {
            Some(d) => (d, line),
            None => match line.split_once(char::is_whitespace) {
                Some((d, r)) => (d, r.trim()),
                None => continue,
            },
        };
        if rest == "(" {
            block = Some(match directive {
                "require" => "require",
                "replace" => "replace",
                _ => "other",
            });
            continue;
        }
        let words: Vec<&str> = rest.split_whitespace().collect();
        match directive {
            "require" if words.len() >= 2 => {
                required.push((words[0].to_owned(), words[1].to_owned()));
            }
            "replace" if !words.is_empty() => {
                replaced.insert(words[0].to_owned());
            }
            _ => {}
        }
    }
    required
        .into_iter()
        .map(|(module, version)| Wanted {
            asked: format!("{module} {version}"),
            // A module replaced by another, or by a folder, is not what `go.sum` lists under its name.
            spec: if replaced.contains(&module) {
                Spec::Unread
            } else {
                Spec::Exact(version)
            },
            key: module,
            // `go.sum` may hold only the hash of a module's `go.mod`, which the bill of materials does
            // not list, for a module nothing imports; missing, it is not compared.
            conditional: true,
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Gradle: `build.gradle` and `build.gradle.kts`, whose plain version is the least Gradle will use.

/// The coordinates a build file asks for, in either notation, with their version as written.
fn gradle_wants(text: &str) -> Vec<Wanted> {
    static STRING: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r#"\b[A-Za-z]\w*\s*\(?\s*["']([^"'\s:]+):([^"'\s:]+):([^"'\s:@]+)(?::[^"'\s]*)?(?:@\w+)?["']"#)
            .expect("the pattern is valid")
    });
    static MAP: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r#"group\s*[:=]\s*["']([^"']+)["']\s*,\s*name\s*[:=]\s*["']([^"']+)["']\s*,\s*version\s*[:=]\s*["']([^"']+)["']"#,
        )
        .expect("the pattern is valid")
    });
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split("//").next().unwrap_or("");
        for caps in STRING.captures_iter(line).chain(MAP.captures_iter(line)) {
            let (group, artifact, version) = (&caps[1], &caps[2], &caps[3]);
            out.push(Wanted {
                key: format!("{group}:{artifact}"),
                asked: format!("{group}:{artifact}:{version}"),
                spec: gradle_spec(version),
                // Which configurations are locked is the project's choice, and a dependency in one
                // that is not has nothing in the lockfile: missing, it is not compared.
                conditional: true,
            });
        }
    }
    out
}

/// A Gradle version as written: `1.2.3` (at least that), `1.2.3!!` (exactly that), `1.2.+` (that
/// prefix), or a range in brackets.
fn gradle_spec(text: &str) -> Spec {
    // A version from a variable (`$v`) or a word (`latest.release`) has no number to read, and is
    // not read below.
    let text = text.trim();
    // A prefix or a range says nothing of words after the number, so it is held to versions without.
    if let Some(prefix) = text.strip_suffix(".+") {
        return Spec::Qualified(String::new(), vec![(PyOp::Equal, format!("{prefix}.*"))]);
    }
    if text.starts_with(['[', '(', ']']) {
        return gradle_range(text).map_or(Spec::Unread, |c| Spec::Qualified(String::new(), c));
    }
    let strict = text.strip_suffix("!!");
    let (release, qualifier) = gradle_split(strict.unwrap_or(text));
    if python_release(&release).is_none() {
        return Spec::Unread;
    }
    let op = if strict.is_some() {
        PyOp::Equal
    } else {
        PyOp::AtLeast
    };
    Spec::Qualified(qualifier, vec![(op, release)])
}

/// `[1.0,2.0)`, `[1.0,)`, `(,2.0]`: Maven's ranges, which Gradle reads, as clauses.
fn gradle_range(text: &str) -> Option<Vec<(PyOp, String)>> {
    // By character, not by byte: `[` alone, or a range ending in a letter outside ASCII, is not a
    // range, and slicing it by byte would panic (`implementation 'g:a:['`).
    let open = text.chars().next()?;
    let close = text
        .chars()
        .last()
        .filter(|c| [']', ')', '['].contains(c))?;
    let inner = text.strip_prefix(open)?.strip_suffix(close)?;
    let (low, high) = inner.split_once(',')?;
    let mut clauses = Vec::new();
    if !low.trim().is_empty() {
        python_release(low)?;
        clauses.push((
            if open == '[' {
                PyOp::AtLeast
            } else {
                PyOp::Above
            },
            low.trim().to_owned(),
        ));
    }
    if !high.trim().is_empty() {
        python_release(high)?;
        clauses.push((
            if close == ']' {
                PyOp::AtMost
            } else {
                PyOp::Below
            },
            high.trim().to_owned(),
        ));
    }
    Some(clauses)
}

/// A Gradle version's release number and what follows it, lower case: `33.0.0-jre` is `33.0.0` and
/// `jre`, `5.3.2.Final` is `5.3.2` and `final`, and `2.1.0` is `2.1.0` and nothing.
fn gradle_split(version: &str) -> (String, String) {
    let mut release = Vec::new();
    let mut rest = version;
    loop {
        let end = rest.find(['.', '-']).unwrap_or(rest.len());
        let part = &rest[..end];
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            break;
        }
        release.push(part);
        rest = &rest[end..];
        match rest.strip_prefix(['.', '-']) {
            Some(after) if after.starts_with(|c: char| c.is_ascii_digit()) => rest = after,
            Some(after) => {
                rest = after;
                break;
            }
            None => break,
        }
    }
    (release.join("."), rest.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locked(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect()
    }

    /// Whether `version` satisfies `range`, as npm documents ranges.
    fn npm(range: &str, version: &str) -> Option<bool> {
        allows(&npm_spec(range).map_or(Spec::Unread, Spec::Npm), version)
    }

    /// Whether `version` satisfies the Python requirement `spec` (`>=1,<2`).
    fn py(spec: &str, version: &str) -> Option<bool> {
        allows(
            &python_spec(spec).map_or(Spec::Unread, Spec::Python),
            version,
        )
    }

    #[test]
    fn a_pipfile_is_held_to_its_lockfile() {
        let manifest = "[packages]\ndjango = \"==2.2.0\"\nrequests = \"*\"\n\
                        flask = {version = \">=3,<4\", extras = [\"async\"]}\n\
                        colorama = {version = \"*\", sys_platform = \"== 'win32'\"}\n\
                        myapp = {path = \".\", editable = true}\n\n\
                        [dev-packages]\nPyTest = \">=8\"\n\n[requires]\npython_version = \"3.11\"\n";
        let lock = locked(&[
            ("django", "2.2.0"),
            ("requests", "2.31.0"),
            ("flask", "3.0.0"),
            ("pytest", "8.0.0"),
        ]);
        let agree = compare("Pipfile", manifest, &lock).unwrap();
        assert!(agree.differs.is_empty(), "{agree:?}");
        let mut not_compared = agree.not_compared.clone();
        not_compared.sort();
        assert_eq!(
            not_compared,
            ["colorama *", "myapp (not a version)"],
            "a platform condition, and the app's own folder, may rightly be missing"
        );

        let older = locked(&[
            ("django", "2.2.0"),
            ("requests", "2.31.0"),
            ("flask", "2.3.0"),
        ]);
        let found = compare("Pipfile", manifest, &older).unwrap();
        let mut asked: Vec<&str> = found.differs.iter().map(|d| d.asked.as_str()).collect();
        asked.sort();
        assert_eq!(asked, ["PyTest >=8", "flask >=3,<4"]);
        let mut names = declared_names("Pipfile", manifest).unwrap();
        names.sort();
        assert_eq!(
            names,
            ["colorama", "django", "flask", "myapp", "pytest", "requests"]
        );
        assert_eq!(compare("Pipfile", "not = [toml", &[]), None);
    }

    #[test]
    fn a_hashed_requirement_is_read_without_its_continuation() {
        // `name==version \` with its `--hash` on the next line, as pip-compile writes it: the
        // backslash was read as part of the version, and nothing matched the lockfile.
        let manifest = "blinker==1.9.0 \\\n    --hash=sha256:00\nflask[async]==3.1.3 \\\n    --hash=sha256:00\n";
        let lock = locked(&[("blinker", "1.9.0"), ("flask", "3.1.3")]);
        let found = compare("requirements.txt", manifest, &lock).unwrap();
        assert_eq!(found, Comparison::default(), "{found:?}");
    }

    #[test]
    fn the_case_that_was_found_is_found() {
        // examples/flask-booking between 23 September and 3 October 2026.
        let manifest = "flask==3.0.0\ngunicorn==21.2.0\nauthlib==1.3.0\npyjwt==2.13.0\n";
        let lock = locked(&[
            ("flask", "3.0.0"),
            ("gunicorn", "21.2.0"),
            ("authlib", "1.3.0"),
            ("pyjwt", "2.8.0"),
        ]);
        let found = compare("requirements.txt", manifest, &lock).unwrap();
        assert_eq!(
            found.differs,
            vec![Differs {
                asked: "pyjwt==2.13.0".to_owned(),
                locked: vec!["2.8.0".to_owned()],
            }]
        );
        assert!(found.not_compared.is_empty(), "{found:?}");
    }

    #[test]
    fn either_file_can_be_the_older_one() {
        // The manifest moved on: it asks for more than the lock has.
        let older_lock = compare(
            "requirements.txt",
            "pyjwt>=2.10\n",
            &locked(&[("pyjwt", "2.8.0")]),
        )
        .unwrap();
        assert_eq!(older_lock.differs.len(), 1, "{older_lock:?}");
        // The lock moved on: it has more than the manifest allows.
        let older_manifest = compare(
            "requirements.txt",
            "pyjwt<2.9\n",
            &locked(&[("pyjwt", "2.13.0")]),
        )
        .unwrap();
        assert_eq!(older_manifest.differs.len(), 1, "{older_manifest:?}");
        // A range the lock satisfies is quiet.
        let within = compare(
            "requirements.txt",
            "pyjwt>=2,<3\n",
            &locked(&[("pyjwt", "2.13.0")]),
        )
        .unwrap();
        assert_eq!(within, Comparison::default());
        // And the same for npm.
        let pkg = r#"{"dependencies": {"express": "^4.18.0", "jsonwebtoken": "9.0.0"}}"#;
        let npm_found = compare(
            "package.json",
            pkg,
            &locked(&[("express", "4.21.2"), ("jsonwebtoken", "8.5.1")]),
        )
        .unwrap();
        assert_eq!(
            npm_found.differs,
            vec![Differs {
                asked: "jsonwebtoken 9.0.0".to_owned(),
                locked: vec!["8.5.1".to_owned()],
            }]
        );
    }

    #[test]
    fn a_package_the_lock_does_not_have_disagrees_unless_it_is_for_another_platform() {
        let found = compare(
            "requirements.txt",
            "flask==3.0.0\nstripe==7.8.0\npywin32==306 ; sys_platform == \"win32\"\n",
            &locked(&[("flask", "3.0.0")]),
        )
        .unwrap();
        assert_eq!(
            found.differs,
            vec![Differs {
                asked: "stripe==7.8.0".to_owned(),
                locked: Vec::new(),
            }]
        );
        assert_eq!(found.not_compared, vec!["pywin32==306".to_owned()]);
    }

    #[test]
    fn names_are_compared_as_the_index_compares_them() {
        let found = compare(
            "requirements.txt",
            "Flask_Login==0.6.3\nzope.interface==6.0\nrequests[security]==2.32.3\n",
            &locked(&[
                ("flask-login", "0.6.3"),
                ("zope-interface", "6.0"),
                ("Requests", "2.32.3"),
            ]),
        )
        .unwrap();
        assert_eq!(found, Comparison::default());
        assert_eq!(python_name("Zope.._-Interface"), "zope-interface");
    }

    #[test]
    fn what_cannot_be_compared_is_said_and_never_agrees() {
        let found = compare(
            "requirements.txt",
            "# a comment\n-r base.txt\n--index-url https://example.invalid\n\
             mylib @ git+https://example.invalid/mylib.git\nrc==1.0.0\nweird>=1.0.0b1\n\
             plain\n",
            &locked(&[
                ("mylib", "0.1.0"),
                ("rc", "1.0.0rc1"),
                ("weird", "1.0.0"),
                ("plain", "4.0"),
            ]),
        )
        .unwrap();
        assert!(found.differs.is_empty(), "{found:?}");
        assert_eq!(
            found.not_compared,
            vec![
                "mylib@git+https://example.invalid/mylib.git",
                "rc==1.0.0",
                "weird>=1.0.0b1"
            ]
        );
        let pkg = r#"{"dependencies": {"a": "latest", "b": "file:../b", "c": "github:o/c", "d": "^1.0.0-beta.1", "e": "npm:other@1"},
                      "devDependencies": {"f": "^2.0.0"}}"#;
        let found = compare(
            "package.json",
            pkg,
            &locked(&[
                ("a", "1.0.0"),
                ("b", "1.0.0"),
                ("c", "1.0.0"),
                ("d", "1.0.0"),
                ("e", "1.0.0"),
                ("f", "2.0.0-rc.1"),
            ]),
        )
        .unwrap();
        assert!(found.differs.is_empty(), "{found:?}");
        assert_eq!(found.not_compared.len(), 6, "{found:?}");
        // A manifest of another kind is not compared at all, rather than found to agree.
        assert_eq!(compare("pom.xml", "<project/>\n", &[]), None);
        assert_eq!(compare("package.json", "{not json", &[]), None);
    }

    #[test]
    fn any_version_the_lock_has_that_is_allowed_is_enough() {
        // npm can install two copies; the manifest is met when one of them meets it.
        let found = compare(
            "package.json",
            r#"{"dependencies": {"debug": "^4.0.0"}}"#,
            &locked(&[("debug", "2.6.9"), ("debug", "4.3.4")]),
        )
        .unwrap();
        assert_eq!(found, Comparison::default());
        let found = compare(
            "package.json",
            r#"{"dependencies": {"debug": "^4.0.0"}}"#,
            &locked(&[("debug", "2.6.9"), ("debug", "3.2.7"), ("debug", "2.6.9")]),
        )
        .unwrap();
        assert_eq!(found.differs[0].locked, vec!["2.6.9", "3.2.7"]);
    }

    #[test]
    fn python_versions_are_compared_as_pep_440_compares_releases() {
        for (spec, version, expected) in [
            ("==2.8", "2.8.0", Some(true)),
            ("==2.8.0", "2.8", Some(true)),
            ("==2.8.0", "2.8.1", Some(false)),
            ("!=2.8.0", "2.8.1", Some(true)),
            ("!=2.8.0", "2.8", Some(false)),
            (">=2.10", "2.9.0", Some(false)),
            (">=2.10", "2.10", Some(true)),
            (">2.10", "2.10.0", Some(false)),
            ("<=2.10", "2.10.0", Some(true)),
            ("<2.10", "2.9.99", Some(true)),
            ("==2.*", "2.13.0", Some(true)),
            ("==2.8.*", "2.9.0", Some(false)),
            ("!=2.8.*", "2.9.0", Some(true)),
            ("~=2.2", "2.9", Some(true)),
            ("~=2.2", "3.0", Some(false)),
            ("~=2.2.1", "2.2.9", Some(true)),
            ("~=2.2.1", "2.3.0", Some(false)),
            ("~=2.2.1", "2.2.0", Some(false)),
            ("~=2", "2.0", None),
            ("===1.0+local", "1.0+local", Some(true)),
            ("===1.0", "1.0.0", Some(false)),
            (">=1,<2", "1.5", Some(true)),
            (">=1,<2", "2.0", Some(false)),
            (">=1,!=1.5", "1.5", Some(false)),
            (">=1.0", "1.0rc1", None),
            ("==1.0rc1", "1.0rc1", Some(true)),
            ("=>1.0", "1.0", None),
        ] {
            assert_eq!(py(spec, version), expected, "{spec} against {version}");
        }
    }

    #[test]
    fn npm_ranges_are_read_as_npm_documents_them() {
        for (range, version, expected) in [
            ("1.2.3", "1.2.3", Some(true)),
            ("=1.2.3", "1.2.4", Some(false)),
            ("v1.2.3", "1.2.3", Some(true)),
            ("^1.2.3", "1.9.0", Some(true)),
            ("^1.2.3", "2.0.0", Some(false)),
            ("^1.2.3", "1.2.2", Some(false)),
            ("^0.2.3", "0.2.9", Some(true)),
            ("^0.2.3", "0.3.0", Some(false)),
            ("^0.0.3", "0.0.4", Some(false)),
            ("^0.0.3", "0.0.3", Some(true)),
            ("^1.x", "1.9.9", Some(true)),
            ("^0.x", "0.9.0", Some(true)),
            ("^0.x", "1.0.0", Some(false)),
            ("^0.0", "0.0.9", Some(true)),
            ("^0.0", "0.1.0", Some(false)),
            ("~1.2.3", "1.2.9", Some(true)),
            ("~1.2.3", "1.3.0", Some(false)),
            ("~1.2", "1.2.0", Some(true)),
            ("~1", "1.9.0", Some(true)),
            ("~1", "2.0.0", Some(false)),
            ("1.x", "1.4.0", Some(true)),
            ("1.2.x", "1.3.0", Some(false)),
            ("1", "1.0.1", Some(true)),
            ("*", "9.9.9", Some(true)),
            ("", "9.9.9", Some(true)),
            (">=1.2.3 <2", "1.9.9", Some(true)),
            (">=1.2.3 <2", "2.0.0", Some(false)),
            (">= 1.2.3 < 2", "2.0.0", Some(false)),
            (">1.2", "1.2.9", Some(false)),
            (">1.2", "1.3.0", Some(true)),
            (">1.2.3", "1.2.3", Some(false)),
            ("<=1.2", "1.2.9", Some(true)),
            ("<=1.2", "1.3.0", Some(false)),
            ("<1.2", "1.1.9", Some(true)),
            ("<1.2", "1.2.0", Some(false)),
            ("1.2.3 - 2.3.4", "2.3.4", Some(true)),
            ("1.2.3 - 2.3.4", "2.3.5", Some(false)),
            ("1.2 - 2.3", "2.3.9", Some(true)),
            ("1.2 - 2.3", "2.4.0", Some(false)),
            ("1.2 - 2.3", "1.1.9", Some(false)),
            ("^1.0.0 || ^3.0.0", "3.1.0", Some(true)),
            ("^1.0.0 || ^3.0.0", "2.1.0", Some(false)),
            ("^1.0.0", "1.1.0-beta.1", None),
            ("^1.0.0", "1.1.0+build.5", Some(true)),
            ("latest", "1.0.0", None),
            ("^1.0.0-rc.1", "1.0.0", None),
        ] {
            assert_eq!(npm(range, version), expected, "{range:?} against {version}");
        }
    }

    /// The packages that differ, as the manifest writes them, and those not compared.
    fn found(manifest: &str, text: &str, lock: &[(&str, &str)]) -> (Vec<String>, Vec<String>) {
        let c = compare(manifest, text, &locked(lock)).unwrap();
        (
            c.differs.into_iter().map(|d| d.asked).collect(),
            c.not_compared,
        )
    }

    #[test]
    fn a_dependency_from_somewhere_other_than_the_registry_is_not_said_to_disagree() {
        // Found in the review of 1 to 4 October (item 20): a workspace package, a folder, a
        // repository, or an alias is not in the list read from the lockfile under its own name,
        // and each was reported as the lockfile not having it.
        let manifest = r#"{"dependencies": {
            "@app/shared": "workspace:*", "lib": "file:../lib", "linked": "link:../linked",
            "forked": "github:someone/forked", "short": "someone/short",
            "repo": "git+https://example.com/repo.git", "tarball": "https://example.com/t.tgz",
            "aliased": "npm:other@^1.2.0", "express": "^4.18.0", "missing": "^1.0.0"
        }}"#;
        let (differs, not_compared) = found("package.json", manifest, &[("express", "4.19.2")]);
        // The control: a registry package missing from the lockfile still disagrees.
        assert_eq!(differs, ["missing ^1.0.0"]);
        assert_eq!(not_compared.len(), 8, "{not_compared:?}");
        let (differs, not_compared) = found(
            "requirements.txt",
            "flask==3.0.0\nmylib @ git+https://example.com/mylib.git\nother==1.0\n",
            &[("flask", "3.0.0")],
        );
        assert_eq!(differs, ["other==1.0"]);
        assert_eq!(not_compared, ["mylib@git+https://example.com/mylib.git"]);
    }

    #[test]
    fn pyproject_lists_and_poetry_tables_are_compared() {
        let manifest = r#"
[project]
name = "app"
dependencies = ["flask>=3,<4", "PyJWT==2.13.0", "gunicorn"]
[project.optional-dependencies]
docs = ["sphinx>=7"]
[dependency-groups]
dev = ["pytest==8.0.0"]
"#;
        let (differs, not_compared) = found(
            "pyproject.toml",
            manifest,
            &[
                ("flask", "3.0.3"),
                ("pyjwt", "2.8.0"),
                ("gunicorn", "22.0.0"),
                ("pytest", "7.4.0"),
            ],
        );
        // An extra that is not installed may be missing; a group that is, at the wrong version, is not.
        assert_eq!(differs, vec!["PyJWT==2.13.0", "pytest==8.0.0"]);
        assert_eq!(not_compared, vec!["sphinx>=7"]);

        let poetry = r#"
[tool.poetry.dependencies]
python = "^3.11"
django = "^4.2"
requests = { version = "~2.31", extras = ["socks"] }
mylib = { git = "https://example.invalid/mylib.git" }
vendored = { path = "../vendored", version = "9.9" }
win = { version = "1.0", markers = "sys_platform == 'win32'" }
[tool.poetry.group.dev.dependencies]
black = "24.1.0"
"#;
        let (differs, not_compared) = found(
            "pyproject.toml",
            poetry,
            &[
                ("Django", "5.0.1"),
                ("requests", "2.31.9"),
                ("mylib", "0.1.0"),
                ("vendored", "0.1.0"),
                ("black", "24.1.0"),
            ],
        );
        assert_eq!(differs, vec!["django ^4.2"]);
        // A folder's version is the folder's, whatever the table says.
        assert_eq!(
            not_compared,
            vec![
                "mylib (not a version)",
                "vendored (not a version)",
                "win 1.0"
            ]
        );
        assert_eq!(compare("pyproject.toml", "not = [toml", &[]), None);
    }

    #[test]
    fn poetry_constraints_are_read_as_poetry_documents_them() {
        let poetry =
            |c: &str, v: &str| allows(&poetry_spec(c).map_or(Spec::Unread, Spec::Python), v);
        for (constraint, version, expected) in [
            ("^1.2.3", "1.9.0", Some(true)),
            ("^1.2.3", "2.0.0", Some(false)),
            ("^0.2.3", "0.3.0", Some(false)),
            ("^0.0.3", "0.0.4", Some(false)),
            ("^0", "0.9", Some(true)),
            ("^0", "1.0", Some(false)),
            ("~1.2.3", "1.2.9", Some(true)),
            ("~1.2.3", "1.3.0", Some(false)),
            ("~1.2", "1.3.0", Some(false)),
            ("~1", "1.9", Some(true)),
            ("~1", "2.0", Some(false)),
            ("~=1.2", "1.9", Some(true)),
            ("1.2.3", "1.2.3", Some(true)),
            ("1.2.3", "1.2.4", Some(false)),
            ("1.2.*", "1.2.9", Some(true)),
            ("1.2.*", "1.3.0", Some(false)),
            ("*", "9.9", Some(true)),
            (">=1.2,<2", "1.5", Some(true)),
            (">=1.2,<2", "2.0", Some(false)),
            ("^1.2 || ^2.0", "2.1", None),
            ("^1.0", "1.1.0rc1", None),
        ] {
            assert_eq!(
                poetry(constraint, version),
                expected,
                "{constraint} against {version}"
            );
        }
    }

    #[test]
    fn cargo_requirements_are_read_as_cargo_documents_them() {
        let manifest = r#"
[package]
name = "app"
[dependencies]
serde = "1.0"
tokio = { version = "1.38", features = ["full"] }
rand = "0.7"
local = { path = "../local" }
shared.workspace = true
renamed = { package = "real_name", version = "2" }
extra = { version = "3", optional = true }
[dev-dependencies]
proptest = "=1.4.0"
[target.'cfg(windows)'.dependencies]
winapi = "0.3"
"#;
        let (differs, not_compared) = found(
            "Cargo.toml",
            manifest,
            &[
                ("serde", "1.0.228"),
                ("tokio", "1.47.1"),
                ("rand", "0.8.5"),
                ("real-name", "2.1.0"),
                ("proptest", "1.5.0"),
                ("local", "0.1.0"),
            ],
        );
        // `0.7` is `^0.7`, which 0.8 does not meet; `=1.4.0` is exact.
        assert_eq!(differs, vec!["rand 0.7", "proptest =1.4.0"]);
        // An optional crate and one for another platform may be missing; a path and the workspace's
        // own requirement are not compared here at all.
        assert_eq!(not_compared, vec!["extra 3", "winapi 0.3"]);

        let workspace = "[workspace]\nmembers = [\"a\"]\n[workspace.dependencies]\nserde = \"2\"\n";
        let (differs, _) = found("Cargo.toml", workspace, &[("serde", "1.0.228")]);
        assert_eq!(differs, vec!["serde 2"]);

        let cargo = |c: &str, v: &str| {
            allows(
                &cargo_spec(c).map_or(Spec::Unread, |s| Spec::Npm(vec![s])),
                v,
            )
        };
        for (requirement, version, expected) in [
            ("1.2.3", "1.9.0", Some(true)),
            ("1.2.3", "2.0.0", Some(false)),
            ("0.2", "0.2.9", Some(true)),
            ("0.2", "0.3.0", Some(false)),
            ("0.0.3", "0.0.4", Some(false)),
            ("=1.2.3", "1.2.4", Some(false)),
            ("~1.2", "1.2.9", Some(true)),
            ("~1.2", "1.3.0", Some(false)),
            ("1.*", "1.9.0", Some(true)),
            ("1.*", "2.0.0", Some(false)),
            ("*", "9.0.0", Some(true)),
            (">=1.2, <1.5", "1.4.9", Some(true)),
            (">= 1.2, < 1.5", "1.5.0", Some(false)),
            ("1.2.3", "1.3.0-alpha.1", None),
        ] {
            assert_eq!(
                cargo(requirement, version),
                expected,
                "{requirement} against {version}"
            );
        }
    }

    #[test]
    fn composer_constraints_are_read_as_composer_documents_them() {
        let manifest = r#"{"require": {"php": ">=8.1", "ext-json": "*", "monolog/monolog": "^3.0",
            "symfony/console": "~6.4", "Guzzlehttp/Guzzle": "7.8.1", "laravel/framework": "dev-master"},
            "require-dev": {"phpunit/phpunit": "^10.5"}}"#;
        let (differs, not_compared) = found(
            "composer.json",
            manifest,
            &[
                ("monolog/monolog", "3.5.0"),
                ("symfony/console", "v7.0.1"),
                ("guzzlehttp/guzzle", "7.8.1"),
                ("laravel/framework", "dev-master"),
            ],
        );
        // PHP and its extensions are not packages; `~6.4` stops below 7.0.
        assert_eq!(
            differs,
            vec!["symfony/console ~6.4", "phpunit/phpunit ^10.5"]
        );
        assert_eq!(not_compared, vec!["laravel/framework dev-master"]);

        let composer =
            |c: &str, v: &str| allows(&composer_spec(c).map_or(Spec::Unread, Spec::Npm), v);
        for (constraint, version, expected) in [
            ("~1.2", "1.9.0", Some(true)),
            ("~1.2", "2.0.0", Some(false)),
            ("~1.2.3", "1.2.9", Some(true)),
            ("~1.2.3", "1.3.0", Some(false)),
            ("~1", "1.9.0", Some(true)),
            ("~1", "2.0.0", Some(false)),
            ("^1.2", "1.9.0", Some(true)),
            ("^0.3", "0.4.0", Some(false)),
            ("1.2", "1.2.0", Some(true)),
            ("1.2", "1.2.1", Some(false)),
            ("1.2.*", "1.2.7", Some(true)),
            (">=1.0 <2.0", "1.5.0", Some(true)),
            (">=1.0,<2.0", "2.0.0", Some(false)),
            ("^1.0 || ^2.0", "2.3.0", Some(true)),
            ("^1.0 | ^2.0", "3.0.0", Some(false)),
            ("1.0 - 2.0", "2.0.0", Some(true)),
            ("^1.0", "v1.4.0", Some(true)),
            ("^1.0@beta", "1.0.0", None),
            ("1.0.0@dev", "1.0.0", None),
            ("dev-main#abc123", "1.0.0", None),
            ("1.0 as 2.0", "2.0.0", None),
            ("!=1.2.0", "1.3.0", None),
        ] {
            assert_eq!(
                composer(constraint, version),
                expected,
                "{constraint} against {version}"
            );
        }
    }

    #[test]
    fn gemfile_lines_are_read_as_bundler_reads_them() {
        let manifest = r#"
source "https://rubygems.org"
gem "rails", "~> 7.1.0"
gem 'pg', '>= 1.1', '< 2.0'
gem "puma", ">= 5.0", require: false
gem "nokogiri", "1.16.0"
gem "devise" # no version
gem "mylib", git: "https://example.invalid/mylib.git"
gem "tzinfo-data", platforms: %i[ windows jruby ]
group :development, :test do
  gem "rspec-rails", "~> 6"
end
platforms :jruby do
  gem "jdbc", "~> 1.0"
end
install_if -> { RUBY_PLATFORM =~ /darwin/ } do
  gem "terminal-notifier", "~> 2.0"
end
"#;
        let (differs, not_compared) = found(
            "Gemfile",
            manifest,
            &[
                ("rails", "7.2.0"),
                ("pg", "1.5.4"),
                ("puma", "6.4.2"),
                ("nokogiri", "1.16.0-x86_64-linux"),
                ("devise", "4.9.3"),
                ("mylib", "0.1.0"),
                ("rspec-rails", "7.0.0"),
            ],
        );
        assert_eq!(differs, vec!["rails ~> 7.1.0", "rspec-rails ~> 6"]);
        assert_eq!(
            not_compared,
            vec![
                "mylib",
                "tzinfo-data",
                "jdbc ~> 1.0",
                "terminal-notifier ~> 2.0"
            ]
        );

        let gem = |c: &str, v: &str| {
            allows(
                &gem_clauses(c).map_or(Spec::Unread, Spec::Python),
                &gem_version(v),
            )
        };
        for (requirement, version, expected) in [
            ("~> 7.1", "7.9", Some(true)),
            ("~> 7.1", "8.0", Some(false)),
            ("~> 7.1.0", "7.1.5", Some(true)),
            ("~> 7.1.0", "7.2.0", Some(false)),
            ("~> 6", "6.9", Some(true)),
            ("~> 6", "7.0", Some(false)),
            ("1.2", "1.2.0", Some(true)),
            ("= 1.2.0", "1.2.1", Some(false)),
            ("!= 1.2.0", "1.2.1", Some(true)),
            ("> 1.2", "1.2.0", Some(false)),
            ("1.16.0", "1.16.0-arm64-darwin", Some(true)),
            ("~> 1.0", "1.1.0.rc1", None),
        ] {
            assert_eq!(
                gem(requirement, version),
                expected,
                "{requirement} against {version}"
            );
        }
    }

    #[test]
    fn go_requires_are_held_to_go_sum_exactly() {
        let manifest = "module example.com/app\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.10.0\n\
            require (\n\tgolang.org/x/crypto v0.25.0 // indirect\n\tgithub.com/old/thing v1.0.0\n\
            \texample.com/forked v1.2.0\n\texample.com/unused v0.1.0 // indirect\n\
            \t// example.com/dropped v3.0.0\n)\n\
            replace example.com/forked => ../forked\n";
        let (differs, not_compared) = found(
            "go.mod",
            manifest,
            &[
                ("github.com/gin-gonic/gin", "v1.10.0"),
                ("golang.org/x/crypto", "v0.24.0"),
                ("golang.org/x/crypto", "v0.25.0"),
                ("github.com/old/thing", "v0.9.0"),
                ("example.com/forked", "v1.1.0"),
            ],
        );
        assert_eq!(differs, vec!["github.com/old/thing v1.0.0"]);
        // Replaced, and a module go.sum may hold only the go.mod hash of.
        assert_eq!(
            not_compared,
            vec!["example.com/forked v1.2.0", "example.com/unused v0.1.0"]
        );
    }

    #[test]
    fn gradle_build_files_are_held_to_gradle_lockfile() {
        let groovy = r#"
plugins {
    id 'org.springframework.boot' version '3.2.0'
}
dependencies {
    implementation 'com.google.guava:guava:32.1.0-jre'
    implementation "org.slf4j:slf4j-api:2.0.9"
    implementation 'com.fasterxml.jackson.core:jackson-databind:2.17.0!!'
    runtimeOnly group: 'org.postgresql', name: 'postgresql', version: '42.7.1'
    testImplementation 'junit:junit:4.+'
    implementation "org.example:fromvar:$exampleVersion"
    implementation project(':shared')
    implementation libs.okhttp
    // implementation 'com.example:commented:1.0.0'
    compileOnly 'org.projectlombok:lombok:1.18.30'
}
"#;
        let lock = [
            ("com.google.guava:guava", "33.0.0-jre"),
            ("org.slf4j:slf4j-api", "1.7.36"),
            ("com.fasterxml.jackson.core:jackson-databind", "2.17.1"),
            ("org.postgresql:postgresql", "42.7.1"),
            ("junit:junit", "4.13.2"),
            ("org.example:fromvar", "1.0.0"),
        ];
        let (differs, not_compared) = found("build.gradle", groovy, &lock);
        // A newer guava is what Gradle picks when something else asks for more; an older slf4j is not.
        assert_eq!(
            differs,
            vec![
                "org.slf4j:slf4j-api:2.0.9",
                "com.fasterxml.jackson.core:jackson-databind:2.17.0!!",
            ]
        );
        // A version from a variable, and a configuration the lockfile may not lock.
        assert_eq!(
            not_compared,
            vec![
                "org.example:fromvar:$exampleVersion",
                "org.projectlombok:lombok:1.18.30",
            ]
        );

        let kotlin = r#"
dependencies {
    implementation("io.ktor:ktor-server-core:2.3.7")
    implementation(group = "org.jetbrains.exposed", name = "exposed-core", version = "0.45.0")
    testImplementation("io.kotest:kotest-runner-junit5:[5.0,6.0)")
}
"#;
        let (differs, not_compared) = found(
            "build.gradle.kts",
            kotlin,
            &[
                ("io.ktor:ktor-server-core", "2.3.7"),
                ("org.jetbrains.exposed:exposed-core", "0.44.1"),
                ("io.kotest:kotest-runner-junit5", "6.0.0"),
            ],
        );
        assert_eq!(
            differs,
            vec![
                "org.jetbrains.exposed:exposed-core:0.45.0",
                "io.kotest:kotest-runner-junit5:[5.0,6.0)",
            ]
        );
        assert!(not_compared.is_empty(), "{not_compared:?}");
    }

    #[test]
    fn gradle_versions_are_read_as_gradle_resolves_them() {
        let gradle = |v: &str, have: &str| allows(&gradle_spec(v), have);
        for (version, have, expected) in [
            ("1.2.3", "1.2.3", Some(true)),
            ("1.2.3", "1.3.0", Some(true)),
            ("1.2.3", "1.2.2", Some(false)),
            ("1.2.3!!", "1.2.4", Some(false)),
            ("1.2.3!!", "1.2.3", Some(true)),
            ("1.2.+", "1.2.9", Some(true)),
            ("1.2.+", "1.3.0", Some(false)),
            ("[1.0,2.0)", "1.9.9", Some(true)),
            ("[1.0,2.0)", "2.0", Some(false)),
            ("(1.0,2.0]", "1.0", Some(false)),
            ("[1.0,)", "9.0", Some(true)),
            ("(,2.0]", "2.0", Some(true)),
            ("32.1.0-jre", "33.0.0-jre", Some(true)),
            ("32.1.0-jre", "31.0.0-jre", Some(false)),
            ("32.1.0-jre", "33.0.0-android", None),
            ("5.3.2.Final", "5.3.3.Final", Some(true)),
            ("5.3.2.Final", "5.3.2.final", Some(true)),
            ("2.0.0", "2.1.0-rc1", None),
            ("latest.release", "1.0", None),
            ("$v", "1.0", None),
            // Found in the review of 1 to 4 October (item 21): these panicked, or read a range
            // that was not closed.
            ("[", "1.0", None),
            ("(", "1.0", None),
            ("[1.0,2é", "1.0", None),
            ("[1.0,2.0", "1.0", None),
            ("]1.0,2.0[", "1.5", Some(true)),
        ] {
            assert_eq!(gradle(version, have), expected, "{version} against {have}");
        }
        assert_eq!(
            gradle_split("33.0.0-jre"),
            ("33.0.0".to_owned(), "jre".to_owned())
        );
        assert_eq!(
            gradle_split("5.3.2.Final"),
            ("5.3.2".to_owned(), "final".to_owned())
        );
        assert_eq!(gradle_split("2.1.0"), ("2.1.0".to_owned(), String::new()));
    }
}
