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
//! Two manifests are read: `requirements.txt` and `package.json`. The rest are not compared yet.

/// What the manifest asks for, in a form a version can be held to.
#[derive(Debug, Clone)]
enum Spec {
    /// Python's comma-joined clauses, all of which must hold.
    Python(Vec<(PyOp, String)>),
    /// npm's `||`-joined sets of comparators; a version must meet every comparator of one set.
    Npm(Vec<Comparators>),
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
    /// Python only: the line has an environment marker, so the package may rightly be missing
    /// from a lock made for another platform or Python.
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
    let (wanted, key): (Vec<Wanted>, fn(&str) -> String) = match manifest_name {
        "requirements.txt" => (python_wants(manifest), python_name),
        "package.json" => (npm_wants(manifest)?, str::to_owned),
        _ => return None,
    };
    let mut out = Comparison::default();
    for want in wanted {
        let versions: Vec<&str> = locked
            .iter()
            .filter(|(name, _)| key(name) == want.key)
            .map(|(_, version)| version.as_str())
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
        let mut locked: Vec<String> = versions.iter().map(|v| (*v).to_owned()).collect();
        locked.sort();
        locked.dedup();
        out.differs.push(Differs {
            asked: want.asked,
            locked,
        });
    }
    Some(out)
}

/// Whether `version` is one the spec allows; `None` when that cannot be told.
fn allows(spec: &Spec, version: &str) -> Option<bool> {
    match spec {
        Spec::Unread => None,
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
fn python_name(name: &str) -> String {
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
        let line = line.trim();
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
            spec,
            conditional: marker,
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
            out.push(Wanted {
                key: name.clone(),
                asked: format!("{name} {range}"),
                spec: npm_spec(range).map_or(Spec::Unread, Spec::Npm),
                // An optional dependency that failed to build is left out of nothing: npm still
                // locks it. Nothing here is conditional.
                conditional: false,
            });
        }
    }
    Some(out)
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
        assert_eq!(compare("Cargo.toml", "[dependencies]\n", &[]), None);
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
}
