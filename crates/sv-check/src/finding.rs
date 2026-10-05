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

/// The rules whose findings are shown beside a requirement's credit rather than over it, and whose
/// review as a false alarm leaves that credit standing. Each says so in its own text; a rule goes on
/// this list only when it does, so the report never contradicts the finding it shows.
pub const INFORMATION_ONLY: &[&str] = &[crate::suite::NAME_MISMATCH];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Location {
    pub file: String,
    /// 1-indexed, as an editor counts.
    pub line: usize,
}

impl Location {
    /// The place given for a finding about the running app, which has no file and no line.
    pub const RUNNING_APP: &'static str = "the running app";
    /// The place given for a finding in what the running app printed.
    pub const RUNNING_APP_OUTPUT: &'static str = "the running app's output";

    /// A finding about the running app. Line 1, because every report shows a line; it means none.
    pub fn running_app() -> Self {
        Location {
            file: Self::RUNNING_APP.to_owned(),
            line: 1,
        }
    }

    /// A finding in the running app's output.
    pub fn running_app_output() -> Self {
        Location {
            file: Self::RUNNING_APP_OUTPUT.to_owned(),
            line: 1,
        }
    }

    /// Whether this names a file of the app, rather than the running app or its output. A tool
    /// that wants a file address (SARIF's) must not be handed one of these as if it were a path.
    pub fn is_file(&self) -> bool {
        !matches!(
            self.file.as_str(),
            Self::RUNNING_APP | Self::RUNNING_APP_OUTPUT
        )
    }
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
    /// What the same finding was named before its fingerprint changed form (deep review A2): the
    /// earlier form, when it differs from `fingerprint`. For a tool that tracks findings by
    /// fingerprint across runs (cato-pipeline's POA&M), so it can carry an item over rather than
    /// close it and open another. Identical lines shared one earlier fingerprint, so it can name
    /// several findings; a tracker should give it to the first and treat the rest as new.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub earlier_fingerprints: Vec<String>,
    /// Known to be test or sample code from more than its file's name: on a line Rust builds only for
    /// its tests (`mark_rust_test_code`), or in a folder the manifest says is not the app
    /// (`mark_not_the_app`). False until the report looks.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub marked_test_code: bool,
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

    /// Whether this finding keeps a requirement it names from being *checked*: true for every finding
    /// but the few that say, in their own text, that they leave the credit alone.
    ///
    /// Those are listed by name in `INFORMATION_ONLY`, and must also be `Severity::Info`, so raising
    /// one's severity makes it count again rather than quietly staying beside the credit. A finding
    /// another rule was merged into counts whatever its own rule is. Every other finding counts,
    /// including a tool's at `info`: a tool's lowest level is still the tool saying something is
    /// wrong, and nothing in its text says otherwise. (BACKLOG, family-hub item 6, 4 October 2026.)
    pub fn withholds_credit(&self) -> bool {
        !(self.severity == Severity::Info
            && self.also_reported_by.is_empty()
            && INFORMATION_ONLY.contains(&self.rule_id.as_str()))
    }

    /// Whether the finding is in code that tests the app or shows how to use it, rather than in the
    /// app itself. Said beside it, never used to hide it: test code can hold a real key, and sample
    /// code gets copied.
    pub fn in_test_code(&self) -> bool {
        self.marked_test_code || is_test_path(&self.location.file)
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
        f.marked_test_code |= lines
            .iter()
            .any(|(first, last)| (*first..=*last).contains(&f.location.line));
    }
}

/// Marks the findings in a folder the manifest says is not the app (`[repository] not-the-app`), so
/// the reports list them with test and sample code. They still count.
pub fn mark_not_the_app(folders: &[String], findings: &mut [Finding]) {
    for f in findings {
        f.marked_test_code |= sv_scan::under_any(&f.location.file, folders);
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
/// settings file), which are about different things.
///
/// The one kept, whose words the owner reads, is the most severe, so a merge never lowers a
/// finding. At the same severity it is `sv`'s own rule's rather than an outside tool's: `sv`'s words
/// carry its own qualifications (such as "this reads like a sentence"), where a tool's are its
/// rule's general text, and every tool finding is given medium confidence because `sv` did not judge
/// it, so "surer" between the two would compare a judgment with a placeholder. Only then is it the
/// one `sv` is surest of. The kept finding keeps its own confidence: two reports of one line do not
/// make either more certain. It takes every requirement and CWE of the others, names their rules in
/// `also_reported_by`, carries the redacted value if it had none, and says, in one line each, how
/// `sv`'s own rules among the others rated the line, so nothing the others were evidence about and
/// no reason for `sv`'s own rating is lost. A tool's text is not copied over: it can quote the value
/// it found (S8), and it is named instead. (BACKLOG, family-hub item 7, 4 October 2026.)
pub fn merge_same_place(findings: Vec<Finding>) -> Vec<Finding> {
    let rank = |c: Confidence| match c {
        Confidence::High => 0,
        Confidence::Medium => 1,
        Confidence::Low => 2,
    };
    // Lower comes first: more severe, then `sv`'s own, then surer.
    let order = |f: &Finding| (f.severity, !is_svs_own(&f.rule_id), rank(f.confidence));
    // Each group is the findings of one place, and which of them is kept so far.
    let mut groups: Vec<(Vec<Finding>, usize, Vec<String>)> = Vec::with_capacity(findings.len());
    for f in findings {
        let same = groups.iter().position(|(members, kept, cwe)| {
            let kept = &members[*kept];
            reads_code(kept)
                && reads_code(&f)
                && kept.location == f.location
                && kept.rule_id != f.rule_id
                && cwe.iter().any(|c| f.cwe.contains(c))
        });
        match same {
            None => {
                let cwe = f.cwe.clone();
                groups.push((vec![f], 0, cwe));
            }
            Some(i) => {
                let (members, kept, cwe) = &mut groups[i];
                for c in &f.cwe {
                    if !cwe.contains(c) {
                        cwe.push(c.clone());
                    }
                }
                if order(&f) < order(&members[*kept]) {
                    *kept = members.len();
                }
                members.push(f);
            }
        }
    }
    groups
        .into_iter()
        .map(|(mut members, kept, _)| {
            let mut keep = members.remove(kept);
            for other in members {
                if !other.rule_id.is_empty()
                    && other.rule_id != keep.rule_id
                    && is_svs_own(&other.rule_id)
                {
                    let said = format!(
                        "`sv`'s own rule `{}` reported this line too, as {} and {}: {}",
                        other.rule_id,
                        other.severity.name(),
                        other.certainty(),
                        other.title
                    );
                    keep.description = if keep.description.is_empty() {
                        said
                    } else {
                        format!("{}\n\n{said}", keep.description)
                    };
                }
                if keep.secret.is_none() {
                    keep.secret = other.secret;
                }
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
            }
            keep
        })
        .collect()
}

/// Whether a rule is `sv`'s own rather than an outside tool's, by the start of its name. A list of
/// `sv`'s own, not of the tools, so a tool added to `data/adapters.json` and missed here is treated
/// as a tool: its words are not preferred over `sv`'s, which is the safe way to be wrong.
pub fn is_svs_own(rule_id: &str) -> bool {
    const OWN: &[&str] = &[
        "secrets.",
        "ast.",
        "config.",
        "probe.",
        "live.",
        "design.",
        "hand.",
        "decisions.",
        "advisory.",
        "sbom.",
        "tests.",
    ];
    OWN.iter().any(|p| rule_id.starts_with(p))
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
        "decisions.",
        "advisory.",
        "sbom.",
        "tests.",
    ];
    f.location.line > 0 && !ELSEWHERE.iter().any(|p| f.rule_id.starts_with(p))
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
            earlier_fingerprints: Vec::new(),
            marked_test_code: false,
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

    /// `sv`'s finding on the family-hub line: low, possible, with its sentence note and the value
    /// redacted.
    fn svs_sentence() -> Finding {
        let mut f = at(
            "secrets.credential-assignment",
            "account.py",
            1,
            &["CWE-798", "CWE-259"],
            Severity::Low,
        );
        f.confidence = Confidence::Low;
        f.title = "A value written under a credential's name is in the code, but it reads like a \
                   sentence (`WRONG_PASSWORD`)"
            .into();
        f.fix = "This reads like a sentence, so read the line first.".into();
        f.secret = Some(Secret::redact("Your current password isn't right."));
        f
    }

    /// Bandit's on the same line, as the adapter makes it: medium confidence because `sv` did not
    /// judge it, its rule's text, and a message quoting the value.
    fn bandits_b105(severity: Severity) -> Finding {
        let mut f = at("bandit.B105", "account.py", 1, &["CWE-259"], severity);
        f.title = "Bandit reported B105".into();
        f.description = "Possible hardcoded password: 'Your current password isn't right.'".into();
        f.requirement_ids = vec!["V13.3.1".into()];
        f
    }

    #[test]
    fn at_the_same_severity_svs_own_words_are_kept_and_the_tool_is_named() {
        for findings in [
            vec![svs_sentence(), bandits_b105(Severity::Low)],
            vec![bandits_b105(Severity::Low), svs_sentence()],
        ] {
            let merged = merge_same_place(findings);
            assert_eq!(merged.len(), 1, "{merged:#?}");
            let f = &merged[0];
            assert_eq!(f.rule_id, "secrets.credential-assignment");
            assert_eq!(f.also_reported_by, vec!["bandit.B105".to_owned()]);
            assert!(f.title.contains("reads like a sentence"));
            assert!(f.fix.contains("reads like a sentence"));
            // Its own certainty, not raised by the tool's placeholder "medium".
            assert_eq!(f.severity, Severity::Low);
            assert_eq!(f.certainty(), "possible");
            // The tool's evidence: its requirement and CWE, and its name above.
            assert!(f.requirement_ids.contains(&"V13.3.1".to_owned()));
            assert!(f.cwe.contains(&"CWE-259".to_owned()));
            // Its message quotes the value; nothing of it is copied over (S8).
            assert!(
                !f.description.contains("current password isn"),
                "the kept description quotes the value (rule {})",
                f.rule_id
            );
            assert!(f.secret.is_some());
        }
    }

    #[test]
    fn a_more_severe_tool_finding_is_kept_and_says_how_svs_own_rule_rated_the_line() {
        for findings in [
            vec![svs_sentence(), bandits_b105(Severity::High)],
            vec![bandits_b105(Severity::High), svs_sentence()],
        ] {
            let merged = merge_same_place(findings);
            assert_eq!(merged.len(), 1, "{merged:#?}");
            let f = &merged[0];
            // Never lowered by the merge: the tool rated it high, and its words say why.
            assert_eq!(f.rule_id, "bandit.B105");
            assert_eq!(f.severity, Severity::High);
            assert_eq!(f.certainty(), "likely");
            assert_eq!(
                f.also_reported_by,
                vec!["secrets.credential-assignment".to_owned()]
            );
            // `sv`'s own reason for its lower rating is said, once, and its redacted value kept.
            assert_eq!(
                f.description
                    .matches(
                        "`sv`'s own rule `secrets.credential-assignment` reported this line too, \
                         as low and possible: A value written under a credential's name is in the \
                         code, but it reads like a sentence"
                    )
                    .count(),
                1,
                "{}",
                f.description
            );
            assert_eq!(
                f.secret.as_ref().map(Secret::as_str),
                Some("Your… (30 more characters)")
            );
        }
    }

    #[test]
    fn at_the_same_severity_svs_own_rule_is_kept_even_when_it_is_less_sure() {
        // Changed on 4 October 2026: the tool's "medium" is a placeholder, not a judgment, and
        // `sv`'s rule says how sure it is and why. Its "possible" stays: the merge raises nothing.
        let mut unsure = at("ast.x", "a.py", 3, &["CWE-601"], Severity::Medium);
        unsure.confidence = Confidence::Low;
        let merged = merge_same_place(vec![
            at("semgrep.y", "a.py", 3, &["CWE-601"], Severity::Medium),
            unsure,
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].rule_id, "ast.x");
        assert_eq!(merged[0].confidence, Confidence::Low);
        assert_eq!(merged[0].also_reported_by, vec!["semgrep.y".to_owned()]);
        // A tool merged into `sv`'s finding adds no words of its own.
        assert!(
            merged[0].description.is_empty(),
            "{}",
            merged[0].description
        );
    }

    #[test]
    fn svs_own_rules_are_told_from_every_outside_tools() {
        let data = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data");
        let read = |name: &str| -> serde_json::Value {
            serde_json::from_str(&std::fs::read_to_string(data.join(name)).unwrap()).unwrap()
        };
        let adapters = read("adapters.json");
        let tools: Vec<&str> = adapters["adapters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["id"].as_str().unwrap())
            .collect();
        assert!(
            tools.contains(&"bandit") && tools.contains(&"semgrep"),
            "{tools:?}"
        );
        for tool in &tools {
            assert!(!is_svs_own(&format!("{tool}.B105")), "{tool}");
        }
        let mut own = 0;
        for file in ["ast-rules.json", "secret-rules.json"] {
            for rule in read(file)["rules"].as_array().unwrap() {
                let id = rule["id"].as_str().unwrap();
                assert!(is_svs_own(id), "{id}");
                own += 1;
            }
        }
        assert!(own > 20, "only {own} of sv's own rules were read");
        for id in [
            "secrets.credential-assignment",
            crate::suite::NAME_MISMATCH,
            "config.debug-mode",
            "probe.x",
            "advisory.GHSA-x",
        ] {
            assert!(is_svs_own(id), "{id}");
        }
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
        let marked: Vec<bool> = findings.iter().map(|f| f.marked_test_code).collect();
        assert_eq!(marked, vec![false, true, false, false, false]);
        assert!(
            findings[1].in_test_code(),
            "and the reports read it as test code"
        );
        assert!(!findings[0].in_test_code());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn findings_in_a_folder_that_is_not_the_app_are_listed_with_test_code() {
        let folders = vec!["demo".to_owned()];
        let mut findings = vec![
            at("r", "demo/shop/app.py", 3, &[], Severity::High),
            at("r", "demo/lib.rs", 1, &[], Severity::High),
            at("r", "demos/app.py", 3, &[], Severity::High),
            at("r", "src/app.py", 3, &[], Severity::High),
        ];
        mark_not_the_app(&folders, &mut findings);
        // Reading a Rust file afterwards finds no test there, and must not undo what the folder said.
        mark_rust_test_code(std::path::Path::new("/nonexistent"), &mut findings);
        let marked: Vec<bool> = findings.iter().map(|f| f.in_test_code()).collect();
        assert_eq!(marked, vec![true, true, false, false]);
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
            earlier_fingerprints: Vec::new(),
            marked_test_code: false,
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
