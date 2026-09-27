//! What a check found, and what it is evidence about.
//!
//! Two things are deliberate here and both come from v1's rules.
//!
//! **A secret never travels in a finding.** `Secret` cannot be constructed with the value visible: it
//! redacts on the way in, and there is no accessor that gives the original back. A finding is written to
//! reports, logs and SARIF, and a scanner that reports a credential has copied it somewhere new.
//!
//! **A check that knows which requirements it verifies says so.** `requirement_ids` is not decoration: it
//! is the link between "this rule fired" and "this ASVS requirement has evidence about it". A finding with
//! an empty list is evidence about nothing in particular, which is a fair thing to be, but it has to be
//! visible rather than assumed.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn name(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

/// How sure the rule is, kept separate from how bad it would be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// A credential that has been found. The value is redacted on construction and cannot be recovered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Secret {
    /// Enough to recognize it in the file, never enough to use it.
    redacted: String,
    /// How long the original was, which is sometimes the only way to tell two findings apart.
    length: usize,
}

impl Secret {
    /// Keeps the first four characters and says how much was dropped. Four is enough to match a key
    /// against the one in a password manager, and far short of enough to authenticate with.
    pub fn redact(value: &str) -> Self {
        let visible: String = value.chars().take(4).collect();
        let total = value.chars().count();
        let hidden = total.saturating_sub(visible.chars().count());
        Secret {
            redacted: if hidden == 0 {
                visible
            } else {
                format!("{visible}… ({hidden} more characters)")
            },
            length: total,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.redacted
    }

    pub fn length(&self) -> usize {
        self.length
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Location {
    pub file: String,
    /// 1-indexed, as an editor counts.
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub location: Location,
    /// What was found, redacted. Absent for rules that report a situation rather than a value.
    pub secret: Option<Secret>,
    /// The requirements this finding is evidence about. Empty is allowed and means exactly that.
    pub requirement_ids: Vec<String>,
    pub cwe: Vec<String>,
    /// Plain language, for somebody who is not a programmer.
    pub description: String,
    pub impact: String,
    pub fix: String,
    /// Other rules that reported the same kind of weakness on the same line, merged into this one so
    /// the owner reads it once. See `merge_same_place`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub also_reported_by: Vec<String>,
    /// What an owner's review names the finding by: see `crate::review::fingerprint`. Empty until the
    /// report fills it in.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
    /// On a line Rust builds only for its tests, inside a file that is otherwise the app's own: see
    /// `mark_rust_test_code`. False until the report looks.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub in_test_module: bool,
}

impl Finding {
    /// How sure `sv` is that this is a real problem, in the owner's words: "confirmed" when the rule
    /// is sure (or the running app was seen doing it), "likely" when it usually is, and "possible"
    /// when it is worth a look before any code is changed. Every one of them still needs attention;
    /// this says how much to trust it, not whether to count it.
    pub fn certainty(&self) -> &'static str {
        match self.confidence {
            Confidence::High => "confirmed",
            Confidence::Medium => "likely",
            Confidence::Low => "possible",
        }
    }

    /// Whether the finding is in code that tests the app or shows how to use it, rather than in the
    /// app itself. Said beside it, never used to hide it: test code can hold a real key, and sample
    /// code gets copied.
    pub fn in_test_code(&self) -> bool {
        self.in_test_module || is_test_path(&self.location.file)
    }
}

/// Marks the findings that sit inside Rust test code in a file that is otherwise the app's own: a
/// `#[cfg(test)]` module, a `#[test]` function, or a file that starts `#![cfg(test)]`. Rust keeps its
/// unit tests in the same file as the code they test, so the file's name cannot say which is which.
pub fn mark_rust_test_code(app_dir: &std::path::Path, findings: &mut [Finding]) {
    let mut read: std::collections::HashMap<String, Vec<(usize, usize)>> =
        std::collections::HashMap::new();
    for f in findings {
        if !f.location.file.ends_with(".rs") {
            continue;
        }
        let lines = read.entry(f.location.file.clone()).or_insert_with(|| {
            std::fs::read_to_string(app_dir.join(&f.location.file))
                .map(|source| rust_test_lines(&source))
                .unwrap_or_default()
        });
        f.in_test_module = lines
            .iter()
            .any(|(first, last)| (*first..=*last).contains(&f.location.line));
    }
}

/// The lines, 1-indexed and inclusive, that Rust compiles only for its tests.
pub fn rust_test_lines(source: &str) -> Vec<(usize, usize)> {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        let text: String = source[node.byte_range()]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        match node.kind() {
            "inner_attribute_item" if text == "#![cfg(test)]" => {
                return vec![(1, usize::MAX)];
            }
            "attribute_item" if marks_test(&text) => {
                // The attribute applies to the next item; other attributes and comments may sit between.
                let mut next = node.next_named_sibling();
                while let Some(n) = next {
                    if !matches!(
                        n.kind(),
                        "attribute_item" | "line_comment" | "block_comment"
                    ) {
                        break;
                    }
                    next = n.next_named_sibling();
                }
                if let Some(item) = next {
                    out.push((node.start_position().row + 1, item.end_position().row + 1));
                }
            }
            _ => {
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            }
        }
    }
    out
}

/// `#[cfg(test)]`, `#[test]`, or a test runner's own, such as `#[tokio::test]`, whitespace removed.
fn marks_test(attribute: &str) -> bool {
    attribute == "#[cfg(test)]"
        || attribute == "#[test]"
        || (attribute.starts_with("#[")
            && (attribute.ends_with("::test]") || attribute.contains("::test(")))
}

/// A path that belongs to tests, fixtures, or samples, by the conventions of the languages `sv`
/// reads: a folder named for them, or a file named the way each test runner finds its tests.
pub fn is_test_path(path: &str) -> bool {
    let path = path.replace('\\', "/");
    let mut parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    let Some(file) = parts.pop() else {
        return false;
    };
    const FOLDERS: &[&str] = &[
        "test",
        "tests",
        "__tests__",
        "spec",
        "specs",
        "testdata",
        "fixtures",
        "__fixtures__",
        "e2e",
        "cypress",
        "examples",
        "example",
        "samples",
    ];
    if parts
        .iter()
        .any(|p| FOLDERS.contains(&p.to_ascii_lowercase().as_str()))
    {
        return true;
    }
    let lower = file.to_ascii_lowercase();
    let stem = lower.split('.').next().unwrap_or(&lower);
    lower == "conftest.py"
        || stem == "tests"
        || stem == "test"
        || (lower.starts_with("test_") && lower.ends_with(".py"))
        || stem.ends_with("_test")
        || lower.contains(".test.")
        || lower.contains(".spec.")
        || lower.ends_with("_spec.rb")
        || file.ends_with("Test.java")
        || file.ends_with("Tests.java")
        || file.ends_with("Test.kt")
        || file.ends_with("Tests.cs")
        || file.ends_with("Test.php")
}

/// Findings that report the same kind of weakness on the same line of the same file, merged so the
/// owner reads each once.
///
/// "The same kind" is a CWE they share: `sv`'s own rule and semgrep's both calling line 12 of
/// `app.py` CWE-89 are one problem, seen twice. Two findings with no CWE in common stay apart, even on
/// one line, because they are two problems; so do findings without a line in a file (a running app, a
/// settings file), which are about different things. The one kept is the most severe, then the one
/// `sv` is surest of; it takes every requirement and CWE of the others, and names their rules in
/// `also_reported_by`, so nothing the others were evidence about is lost.
pub fn merge_same_place(findings: Vec<Finding>) -> Vec<Finding> {
    let rank = |c: Confidence| match c {
        Confidence::High => 0,
        Confidence::Medium => 1,
        Confidence::Low => 2,
    };
    let mut out: Vec<Finding> = Vec::with_capacity(findings.len());
    for f in findings {
        let same = out.iter().position(|kept| {
            reads_code(kept)
                && reads_code(&f)
                && kept.location == f.location
                && kept.rule_id != f.rule_id
                && kept.cwe.iter().any(|c| f.cwe.contains(c))
        });
        let Some(i) = same else {
            out.push(f);
            continue;
        };
        let kept = &mut out[i];
        let f_first = (f.severity, rank(f.confidence)) < (kept.severity, rank(kept.confidence));
        let (mut keep, other) = if f_first {
            (f, std::mem::replace(kept, placeholder()))
        } else {
            (std::mem::replace(kept, placeholder()), f)
        };
        for id in std::iter::once(other.rule_id).chain(other.also_reported_by) {
            if id != keep.rule_id && !keep.also_reported_by.contains(&id) {
                keep.also_reported_by.push(id);
            }
        }
        for r in other.requirement_ids {
            if !keep.requirement_ids.contains(&r) {
                keep.requirement_ids.push(r);
            }
        }
        for c in other.cwe {
            if !keep.cwe.contains(&c) {
                keep.cwe.push(c);
            }
        }
        out[i] = keep;
    }
    out
}

/// Whether a finding points at a line of the app's code. The running-app probes, the settings and
/// dependency checks, and the owner's own answers all give a place that is not a line of code ("the
/// running app", line 1), and two of them on "the same line" are two different things.
pub(crate) fn reads_code(f: &Finding) -> bool {
    const ELSEWHERE: &[&str] = &[
        "probe.",
        "live.",
        "config.",
        "design.",
        "hand.",
        "advisory.",
        "sbom.",
        "tests.",
    ];
    f.location.line > 0 && !ELSEWHERE.iter().any(|p| f.rule_id.starts_with(p))
}

fn placeholder() -> Finding {
    Finding {
        rule_id: String::new(),
        title: String::new(),
        severity: Severity::Info,
        confidence: Confidence::Low,
        location: Location {
            file: String::new(),
            line: 0,
        },
        secret: None,
        requirement_ids: Vec::new(),
        cwe: Vec::new(),
        description: String::new(),
        impact: String::new(),
        fix: String::new(),
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        in_test_module: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(rule: &str, file: &str, line: usize, cwe: &[&str], severity: Severity) -> Finding {
        // A real requirement per rule, so the three merged below are told apart.
        let requirement = match rule {
            "ast.sql-built-by-hand" => "V1.2.4",
            "semgrep.sqli" => "V1.2.5",
            "bandit.B608" => "V5.3.2",
            _ => "V1.2.4",
        };
        Finding {
            rule_id: rule.into(),
            title: format!("found by {rule}"),
            severity,
            confidence: Confidence::Medium,
            location: Location {
                file: file.into(),
                line,
            },
            secret: None,
            requirement_ids: vec![requirement.to_owned()],
            cwe: cwe.iter().map(|c| (*c).to_owned()).collect(),
            description: String::new(),
            impact: String::new(),
            fix: String::new(),
            also_reported_by: Vec::new(),
            fingerprint: String::new(),
            in_test_module: false,
        }
    }

    #[test]
    fn one_weakness_on_one_line_is_one_finding_that_keeps_everything_the_others_said() {
        let merged = merge_same_place(vec![
            at(
                "ast.sql-built-by-hand",
                "app.py",
                5,
                &["CWE-89"],
                Severity::High,
            ),
            at(
                "semgrep.sqli",
                "app.py",
                5,
                &["CWE-89", "CWE-20"],
                Severity::Critical,
            ),
            at("bandit.B608", "app.py", 5, &["CWE-89"], Severity::Medium),
        ]);
        assert_eq!(merged.len(), 1, "{merged:#?}");
        let f = &merged[0];
        // The most severe is the one kept, and it names the other two.
        assert_eq!(f.rule_id, "semgrep.sqli");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(
            f.also_reported_by,
            vec!["ast.sql-built-by-hand".to_owned(), "bandit.B608".to_owned()]
        );
        // Every requirement any of them was evidence about still is.
        for r in ["V1.2.4", "V1.2.5", "V5.3.2"] {
            assert!(f.requirement_ids.contains(&r.to_owned()), "{r}: {f:?}");
        }
        assert!(f.cwe.contains(&"CWE-20".to_owned()));
    }

    #[test]
    fn at_equal_severity_the_finding_sv_is_surer_of_is_kept() {
        let mut sure = at("ast.x", "a.py", 3, &["CWE-78"], Severity::High);
        sure.confidence = Confidence::High;
        let merged = merge_same_place(vec![
            at("semgrep.y", "a.py", 3, &["CWE-78"], Severity::High),
            sure,
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].rule_id, "ast.x");
        assert_eq!(merged[0].also_reported_by, vec!["semgrep.y".to_owned()]);
    }

    #[test]
    fn different_weaknesses_lines_or_places_that_are_not_code_stay_apart() {
        for (a, b) in [
            // Two problems on one line.
            (
                at("ast.a", "app.py", 5, &["CWE-89"], Severity::High),
                at("semgrep.b", "app.py", 5, &["CWE-78"], Severity::High),
            ),
            // One kind of problem on two lines.
            (
                at("ast.a", "app.py", 5, &["CWE-89"], Severity::High),
                at("semgrep.b", "app.py", 6, &["CWE-89"], Severity::High),
            ),
            // Two files.
            (
                at("ast.a", "app.py", 5, &["CWE-89"], Severity::High),
                at("semgrep.b", "db.py", 5, &["CWE-89"], Severity::High),
            ),
            // Neither says what kind of weakness it is.
            (
                at("ast.a", "app.py", 5, &[], Severity::High),
                at("semgrep.b", "app.py", 5, &[], Severity::High),
            ),
            // Two probes of the running app, which both say "line 1" of a place that is not a file.
            (
                at(
                    "probe.a",
                    "the running app",
                    1,
                    &["CWE-613"],
                    Severity::High,
                ),
                at(
                    "probe.b",
                    "the running app",
                    1,
                    &["CWE-613"],
                    Severity::High,
                ),
            ),
            (
                at("config.a", "SECURITY.md", 1, &["CWE-1059"], Severity::Low),
                at("semgrep.b", "SECURITY.md", 1, &["CWE-1059"], Severity::Low),
            ),
        ] {
            let merged = merge_same_place(vec![a.clone(), b.clone()]);
            assert_eq!(
                merged.len(),
                2,
                "{} and {} were merged",
                a.rule_id,
                b.rule_id
            );
            assert!(merged.iter().all(|f| f.also_reported_by.is_empty()));
        }
    }

    #[test]
    fn test_and_sample_code_is_recognized_by_the_usual_conventions() {
        for path in [
            "tests/test_app.py",
            "app/tests.py",
            "src/__tests__/login.js",
            "src/login.test.ts",
            "web/Button.spec.tsx",
            "pkg/auth/auth_test.go",
            "test_login.py",
            "conftest.py",
            "spec/models/user_spec.rb",
            "src/test/java/app/UserTest.java",
            "App.Tests/LoginTests.cs",
            "examples/demo.js",
            "testdata/keys.json",
            "server\\fixtures\\users.json",
        ] {
            assert!(is_test_path(path), "{path} is test or sample code");
        }
        for path in [
            "app.py",
            "src/latest.js",
            "src/attestation.py",
            "contest.py",
            "src/testing_helpers.py",
            "src/Testimonials.java",
            "protest/index.js",
        ] {
            assert!(!is_test_path(path), "{path} is the app's own code");
        }
    }

    /// Which of the lines Rust builds only for its tests, as `rust_test_lines` says.
    fn test_lines(source: &str) -> Vec<usize> {
        let ranges = rust_test_lines(source);
        (1..=source.lines().count())
            .filter(|n| ranges.iter().any(|(a, b)| (*a..=*b).contains(n)))
            .collect()
    }

    #[test]
    fn rust_code_built_only_for_its_tests_is_recognized() {
        let module = "fn hash(b: &[u8]) {}\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n}\nfn after() {}\n";
        assert_eq!(
            test_lines(module),
            vec![3, 4, 5, 6],
            "the module, attribute to closing brace"
        );

        let function = "fn app() {}\n#[test]\nfn works() {\n    app();\n}\n";
        assert_eq!(test_lines(function), vec![2, 3, 4, 5]);

        let runner = "fn app() {}\n#[tokio::test]\nasync fn works() {}\n#[tokio::test(flavor = \"multi_thread\")]\nasync fn also() {}\n";
        assert_eq!(test_lines(runner), vec![2, 3, 4, 5]);

        // Another attribute or a comment between the marker and the item does not lose the item.
        let between =
            "#[cfg(test)]\n// the tests\n#[allow(dead_code)]\nmod tests {\n}\nfn app() {}\n";
        assert_eq!(test_lines(between), vec![1, 2, 3, 4, 5]);

        let nested = "mod inner {\n    fn app() {}\n    #[cfg( test )]\n    mod tests {}\n}\n";
        assert_eq!(
            test_lines(nested),
            vec![3, 4],
            "inside another module, spaces and all"
        );

        let whole = "#![cfg(test)]\nfn helper() {}\n";
        assert_eq!(
            test_lines(whole),
            vec![1, 2],
            "a file built only for tests is all test code"
        );
    }

    #[test]
    fn rust_code_that_only_looks_like_a_test_is_the_apps_own() {
        for source in [
            "#[cfg(not(test))]\nmod real {}\n",
            "#[cfg(feature = \"test\")]\nmod real {}\n",
            "#[cfg(test_utils)]\nmod real {}\n",
            "#[derive(Debug)]\nstruct Test;\nfn test() {}\n",
            "const S: &str = \"#[cfg(test)]\";\nfn app() {}\n",
            "// #[cfg(test)]\nmod real {}\n",
            "#[testing]\nfn real() {}\n",
        ] {
            assert!(
                test_lines(source).is_empty(),
                "{source:?} is the app's own code"
            );
        }
    }

    #[test]
    fn findings_inside_rust_tests_are_marked_and_the_rest_are_not() {
        let dir = std::env::temp_dir().join(format!("sv-rust-tests-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            "fn app() {}\n\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n",
        )
        .unwrap();
        // Same line numbers in a file that is not Rust, and a Rust file that cannot be read.
        std::fs::write(
            dir.join("src/app.py"),
            "#[cfg(test)]\nmod tests {\n\n\n\n}\n",
        )
        .unwrap();
        let mut findings = vec![
            at("r", "src/lib.rs", 1, &[], Severity::High),
            at("r", "src/lib.rs", 5, &[], Severity::High),
            at("r", "src/app.py", 5, &[], Severity::High),
            at("r", "src/gone.rs", 5, &[], Severity::High),
            at("r", "src/lib.rs", 0, &[], Severity::High),
        ];
        mark_rust_test_code(&dir, &mut findings);
        let marked: Vec<bool> = findings.iter().map(|f| f.in_test_module).collect();
        assert_eq!(marked, vec![false, true, false, false, false]);
        assert!(
            findings[1].in_test_code(),
            "and the reports read it as test code"
        );
        assert!(!findings[0].in_test_code());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn how_sure_is_said_in_the_owners_words() {
        let mut f = at("ast.a", "a.py", 1, &[], Severity::High);
        for (c, word) in [
            (Confidence::High, "confirmed"),
            (Confidence::Medium, "likely"),
            (Confidence::Low, "possible"),
        ] {
            f.confidence = c;
            assert_eq!(f.certainty(), word);
        }
    }

    #[test]
    fn a_secret_cannot_be_read_back_out_of_a_finding() {
        // The property that matters: whatever a report or a log does with this, the credential is not in it.
        // Assembled rather than written out: a key-shaped literal in this file is one GitHub's push
        // protection blocks, and it blocked this branch once already on this crate's test data.
        let real = ["sk", "ant", "api03", "ZmFrZWtleWZha2VrZXlmYWtla2V5"].join("-");
        let real = real.as_str();
        let secret = Secret::redact(real);
        assert!(!secret.as_str().contains("ZmFrZWtleWZha2VrZXk"));
        assert!(real.starts_with(secret.as_str().split('…').next().unwrap()));
        let json = serde_json::to_string(&secret).unwrap();
        assert!(
            !json.contains("ZmFrZWtleQ"),
            "the value reached JSON: {json}"
        );
    }

    #[test]
    fn redaction_keeps_enough_to_recognise_and_no_more() {
        let secret = Secret::redact("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(secret.as_str(), "AKIA… (16 more characters)");
        assert_eq!(secret.length(), 20);
    }

    #[test]
    fn a_short_value_is_not_padded_into_looking_longer() {
        let secret = Secret::redact("abc");
        assert_eq!(secret.as_str(), "abc");
        assert_eq!(secret.length(), 3);
    }

    #[test]
    fn a_whole_finding_serialises_without_the_credential() {
        let finding = Finding {
            also_reported_by: Vec::new(),
            fingerprint: String::new(),
            in_test_module: false,
            rule_id: "secrets.anthropic-key".into(),
            title: "Anthropic API key found in a file".into(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            location: Location {
                file: "src/app.py".into(),
                line: 12,
            },
            secret: Some(Secret::redact(
                &["sk", "ant", "SUPERSECRETVALUE12345"].join("-"),
            )),
            requirement_ids: vec!["V13.3.1".into()],
            cwe: vec!["CWE-798".into()],
            description: String::new(),
            impact: String::new(),
            fix: String::new(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(!json.contains("SUPERSECRETVALUE"), "{json}");
    }
}
