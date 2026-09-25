//! What the app's own tests are evidence about.
//!
//! The largest untapped source of positive evidence here, and the easiest place in the whole
//! workspace to overclaim — so the rule is narrow and stated once: **a test counts only for a
//! requirement it names, and only when the suite it belongs to actually passed.**
//!
//! Everything else that suggests itself is guessing. A test called `test_login` might be about
//! authentication requirements, or session requirements, or neither; matching it to a requirement by
//! its words would credit a requirement on the strength of a name somebody chose for other reasons.
//! `sv init` therefore asks the app's author to write the requirement id into the test, and this
//! reads that back. A test that names nothing is not evidence about anything in particular, which is
//! a fair thing for a test to be.
//!
//! Three things have to hold before a single requirement is credited:
//!
//! 1. **The suite ran and passed.** A failing suite says nothing about any requirement in it — not
//!    even the tests that passed, because `sv` sees one exit code and not which tests it came from.
//! 2. **The id is a real requirement.** An id that resolves to nothing is a typo, and crediting it
//!    would put a green line against a requirement that does not exist.
//! 3. **The id appears in a test file.** A requirement named in a comment in the application code is
//!    somebody's note, not a test.
//!
//! The one thing this cannot check is whether the test actually tests what it names. v1 compares the
//! test's wording with the requirement's and reports where they share nothing; about a third of those
//! flags are honest tests phrased differently, so it reports and never withholds credit. The same
//! choice is made here, for the same reason: a check that withholds credit on a third of honest work
//! is a check people turn off.

use crate::finding::{Confidence, Finding, Location, Severity};
use crate::verified::Verified;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// A line in a test file that names one or more requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedTest {
    pub requirement_ids: Vec<String>,
    /// The line as written, for a reader who wants to go and look at it.
    pub text: String,
    pub file: String,
    pub line: usize,
}

/// Whether a path is somewhere tests live.
///
/// Deliberately generous about the shapes different languages use — `tests/`, `spec/`, `__tests__/`,
/// `*_test.go`, `*.spec.ts`, `test_*.py` — and deliberately narrow about where it looks, because a
/// requirement id in the application code is a note somebody wrote, not a test that ran.
pub fn looks_like_a_test_path(relative: &str) -> bool {
    let lower = relative.to_lowercase();
    let parts: Vec<&str> = lower.split(['/', '\\']).collect();
    let (file, directories) = match parts.split_last() {
        Some((file, rest)) => (*file, rest),
        None => return false,
    };
    if directories.iter().any(|d| {
        matches!(
            *d,
            "test" | "tests" | "spec" | "specs" | "__tests__" | "testing"
        )
    }) {
        return true;
    }
    let stem = file.split('.').next().unwrap_or(file);
    // The separator is not optional. Without it `latest.go` is a test file and `codespec.rb` is a
    // spec, and a walk that reads the application code is a walk that credits requirements named
    // in somebody's comments.
    matches!(stem, "test" | "tests" | "spec" | "specs")
        || stem.starts_with("test_")
        || stem.starts_with("test-")
        || stem.ends_with("_test")
        || stem.ends_with("-test")
        || stem.ends_with("_spec")
        || stem.ends_with("-spec")
        || file.contains(".test.")
        || file.contains(".spec.")
}

/// Pulls every requirement id out of the test files under an app.
///
/// `known` is the set of ids that really exist. An id outside it is dropped rather than credited:
/// a typo that resolves to nothing would otherwise put a green line against a requirement nobody
/// has, and the id is reported as unknown by the caller instead.
pub fn tests_naming_requirements(app_dir: &Path, known: &BTreeSet<&str>) -> Vec<NamedTest> {
    let mut out = Vec::new();
    walk(app_dir, app_dir, known, &mut out);
    out.sort_by(|a, b| a.file.cmp(&b.file).then_with(|| a.line.cmp(&b.line)));
    out
}

fn walk(root: &Path, dir: &Path, known: &BTreeSet<&str>, out: &mut Vec<NamedTest>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if sv_scan::ecosystems::SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            walk(root, &path, known, out);
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        if !looks_like_a_test_path(&relative) {
            continue;
        }
        let Ok(source) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (index, line) in source.lines().enumerate() {
            let ids: Vec<String> = requirement_ids_in(line)
                .into_iter()
                .filter(|id| known.contains(id.as_str()))
                .collect();
            if ids.is_empty() {
                continue;
            }
            out.push(NamedTest {
                requirement_ids: ids,
                text: line.trim().chars().take(160).collect(),
                file: relative.clone(),
                line: index + 1,
            });
        }
    }
}

/// Every requirement-id-shaped token in a line.
///
/// Reads the three shapes the loaded frameworks use — `V1.2.1`, `AC.1.1` and `C9.5.4` — and accepts
/// an underscore where a dot belongs, because `def test_V1.2.1_x` is not a function name in most
/// languages and the spec asks people to write these into test names. A hyphen is **not** accepted:
/// the checkers themselves once cited `AC-05` for a family written `AC.5`, and a reader that quietly
/// took both spellings would have hidden that.
pub fn requirement_ids_in(line: &str) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        // A candidate starts at a word boundary, so `SV1.2.1` is not read as `V1.2.1`. An
        // underscore *is* a boundary, and has to be: `def test_V1_2_1_x` is the shape the spec asks
        // people to write, and rejecting it would have made this read nothing at all.
        //
        // One word is allowed to run straight into it, and only because Go requires it: `go test`
        // only runs a function called `TestXxx`, so `TestV1_2_1` is how a Go test names a
        // requirement. Rejecting that would have meant reading nothing in any Go suite while
        // looking like it worked.
        if i > 0 && chars[i - 1].is_ascii_alphanumeric() && !preceded_by_the_word_test(&chars, i) {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < chars.len() && chars[j].is_ascii_uppercase() {
            j += 1;
        }
        let letters: String = chars[i..j].iter().collect();
        if !matches!(letters.as_str(), "V" | "C" | "AC") {
            i += 1;
            continue;
        }
        // Then digits, separated by dots or underscores. A separator only counts when a digit
        // follows it, which is what stops `V1_2_1_search_is_bound` swallowing the words after it.
        let mut token = letters;
        // Appendix C writes a separator between the letters and the first number — `AC.1.1` — where
        // ASVS runs them together as `V1.2.1`. Both are real ids in the loaded data.
        if j < chars.len()
            && (chars[j] == '.' || chars[j] == '_')
            && j + 1 < chars.len()
            && chars[j + 1].is_ascii_digit()
        {
            token.push('.');
            j += 1;
        }
        let mut groups = 0;
        loop {
            let digits_start = j;
            while j < chars.len() && chars[j].is_ascii_digit() {
                j += 1;
            }
            if j == digits_start {
                break;
            }
            groups += 1;
            token.extend(chars[digits_start..j].iter());
            let separator = j < chars.len() && (chars[j] == '.' || chars[j] == '_');
            let digit_after = separator && j + 1 < chars.len() && chars[j + 1].is_ascii_digit();
            if !digit_after {
                break;
            }
            token.push('.');
            j += 1;
        }
        // At least two groups, so a chapter like `V1` is not read as a requirement.
        if groups >= 2 {
            out.push(token);
            i = j;
        } else {
            i += 1;
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Whether the identifier running into this position is exactly the word `test`.
fn preceded_by_the_word_test(chars: &[char], at: usize) -> bool {
    let mut start = at;
    while start > 0 && chars[start - 1].is_ascii_alphanumeric() {
        start -= 1;
    }
    let word: String = chars[start..at].iter().collect();
    word.eq_ignore_ascii_case("test")
}

/// Whether a line reads as the place a test is declared, rather than a mention of one.
///
/// Only used to choose between lines that name the same requirement in the same file. It does not
/// decide whether anything counts: a requirement named only in a comment above a test is exactly
/// what the spec asks for, and still counts.
fn looks_like_a_test_declaration(line: &str) -> bool {
    let text = line.trim_start();
    if text.starts_with('#') || text.starts_with("//") || text.starts_with('*') {
        return false;
    }
    let lower = text.to_lowercase();
    [
        "def ",
        "func ",
        "fn ",
        "sub ",
        "it(",
        "it (",
        "test(",
        "describe(",
        "class ",
    ]
    .iter()
    .any(|k| lower.starts_with(k))
        || lower.contains("@test")
        || lower.contains("[fact]")
        || lower.contains("[theory]")
        || lower.contains("void test")
        || lower.contains("function test")
}

/// The name a test runner would report this declaration under, if one can be read off it.
///
/// Only used to line a source line up with a case in the runner's own report, and only ever to
/// *add* credit. A line whose name cannot be read, or which the runner named differently, is simply
/// not matched and not credited — which is where things stood before the report was read at all.
pub fn declared_test_name(line: &str) -> Option<String> {
    let text = line.trim();
    // `def test_x(`, `func TestX(`, `fn test_x(`, `public void testX(`, `sub test_x {`.
    for keyword in ["def ", "func ", "fn ", "sub ", "void "] {
        if let Some(at) = text.find(keyword) {
            let rest = &text[at + keyword.len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    // `it('…')`, `test("…")`, `describe('…')`: the runner reports the string, not an identifier.
    for keyword in ["it(", "test(", "describe("] {
        if let Some(at) = text.find(keyword) {
            let rest = &text[at + keyword.len()..];
            let quote = rest.chars().next()?;
            if quote == '\'' || quote == '"' || quote == '`' {
                let name: String = rest[1..].chars().take_while(|c| *c != quote).collect();
                if !name.is_empty() {
                    return Some(name);
                }
            }
        }
    }
    None
}

/// What the run said about the suite as a whole.
#[derive(Debug, Clone, Copy)]
pub enum SuiteOutcome<'a> {
    /// Every test passed. One exit code is enough to credit everything that named a requirement.
    Passed,
    /// It did not pass. `passed` is the set of case names the runner's own report said came through,
    /// when there was a report and it could be read; `None` when there was not.
    Failed {
        passed: Option<&'a BTreeSet<String>>,
    },
}

/// Turns passing tests into evidence, and says where a test and its requirement share no words.
///
/// The outcome is not a courtesy parameter. A failing suite used to credit nothing at all, because
/// one exit code does not say which tests it came from. A runner's own report does say, so a suite
/// that mostly passed is now worth what it really established — but only ever *more* than before,
/// never less: when the suite passed outright the report is not consulted, and when it failed a
/// test is credited only if the report names it and says it passed. Anything unmatched stays
/// uncredited, which is exactly where it stood before any of this.
///
/// A requirement is credited **once per file**, however many lines in that file name it. A test that
/// says `V1.2.1` in its name and again in its docstring is one test, and counting the lines would
/// have reported it twice and then complained that the docstring's words do not match the
/// requirement. Where a file names a requirement more than once, the line that reads as the test's
/// declaration is the one reported, because that is the line a reader wants to be sent to.
pub fn credit(
    tests: &[NamedTest],
    outcome: SuiteOutcome<'_>,
    describe: &dyn Fn(&str) -> Option<String>,
) -> (Vec<Verified>, Vec<Finding>) {
    let tests: Vec<&NamedTest> = match outcome {
        SuiteOutcome::Passed => tests.iter().collect(),
        SuiteOutcome::Failed { passed: None } => return (Vec::new(), Vec::new()),
        SuiteOutcome::Failed {
            passed: Some(names),
        } => tests
            .iter()
            .filter(|t| declared_test_name(&t.text).is_some_and(|name| names.contains(&name)))
            .collect(),
    };
    if tests.is_empty() {
        return (Vec::new(), Vec::new());
    }
    // (file, requirement) -> the one line that stands for it.
    let mut chosen: BTreeMap<(String, String), &NamedTest> = BTreeMap::new();
    for test in tests.iter().copied() {
        for id in &test.requirement_ids {
            let key = (test.file.clone(), id.clone());
            match chosen.get(&key) {
                Some(existing) if !beats(test, existing) => {}
                _ => {
                    chosen.insert(key, test);
                }
            }
        }
    }

    // Back together, so one line naming two requirements is one claim about both.
    let mut per_line: BTreeMap<(String, usize), (&NamedTest, Vec<String>)> = BTreeMap::new();
    for ((_, id), test) in &chosen {
        per_line
            .entry((test.file.clone(), test.line))
            .or_insert_with(|| (test, Vec::new()))
            .1
            .push(id.clone());
    }

    let mut verified = Vec::new();
    let mut findings = Vec::new();
    for (test, ids) in per_line.into_values() {
        let borrowed: Vec<&str> = ids.iter().map(String::as_str).collect();
        verified.push(Verified::new(
            "app-tests",
            &borrowed,
            match outcome {
                SuiteOutcome::Passed => format!(
                    "the app's own test at {}:{}, in a suite that passed",
                    test.file, test.line
                ),
                // The distinction matters to a reader: the suite did not pass, and this particular
                // test is credited because the runner's own report named it and said it did.
                SuiteOutcome::Failed { .. } => format!(
                    "the app's own test at {}:{}, which the test runner reported as passing in a \
                     suite that did not",
                    test.file, test.line
                ),
            },
        ));
        for id in &ids {
            let Some(description) = describe(id) else {
                continue;
            };
            if shares_no_words(&test.text, &description) {
                findings.push(mismatch(test, id, &description));
            }
        }
    }
    (verified, findings)
}

/// Which of two lines naming the same requirement in the same file should be the one reported.
fn beats(candidate: &NamedTest, incumbent: &NamedTest) -> bool {
    let rank = |test: &NamedTest| -> u8 {
        let text = test.text.trim_start();
        if looks_like_a_test_declaration(text) {
            2
        } else if text.starts_with('#') || text.starts_with("//") || text.starts_with('*') {
            // A comment carries the id but not the test's own words, so it is the weakest line to
            // send a reader to — and the one most likely to look like a mismatch when it is not.
            0
        } else {
            1
        }
    };
    let (mine, theirs) = (rank(candidate), rank(incumbent));
    // Same rank: the earlier line, which for a comment above its declaration is the comment.
    mine > theirs || (mine == theirs && candidate.line < incumbent.line)
}

fn mismatch(test: &NamedTest, requirement_id: &str, description: &str) -> Finding {
    Finding {
        rule_id: "tests.name-does-not-match-requirement".into(),
        title: format!("A test named for {requirement_id} shares no words with it"),
        severity: Severity::Info,
        // Low on purpose, and the description says why. Roughly a third of these are honest tests
        // phrased differently, which is exactly why this reports rather than withholds credit.
        confidence: Confidence::Low,
        location: Location {
            file: test.file.clone(),
            line: test.line,
        },
        secret: None,
        requirement_ids: vec![requirement_id.to_owned()],
        cwe: vec![],
        description: format!(
            "`{}` says it is about {requirement_id}, which asks: {}",
            test.text,
            first_sentence(description)
        ),
        impact: "The credit for this requirement rests on the test being about what it says it is \
                 about. Nothing here can check that, and a test pointed at the wrong requirement \
                 leaves that requirement looking examined when nothing examined it."
            .into(),
        fix:
            "Read the test and the requirement side by side. If they do match, nothing needs doing \
              — about a third of these are honest tests written in different words, which is why \
              this does not take the credit away."
                .into(),
    }
}

fn first_sentence(text: &str) -> String {
    let trimmed = text.trim();
    match trimmed.find(". ") {
        Some(at) => trimmed[..=at].to_owned(),
        None => trimmed.chars().take(200).collect(),
    }
}

/// Words that say nothing about what a test is for.
const NOISE: &[&str] = &[
    "test",
    "tests",
    "testing",
    "it",
    "should",
    "when",
    "then",
    "given",
    "def",
    "fn",
    "func",
    "function",
    "public",
    "void",
    "async",
    "await",
    "assert",
    "asserts",
    "expect",
    "describe",
    "spec",
    "case",
    "the",
    "a",
    "an",
    "and",
    "or",
    "of",
    "to",
    "in",
    "is",
    "are",
    "for",
    "that",
    "this",
    "with",
    "from",
    "not",
    "verify",
    "verifies",
    "verified",
    "check",
    "checks",
    "self",
    "app",
    "application",
    "must",
    "can",
    "does",
    "do",
    "be",
    "by",
    "on",
    "at",
    "as",
    "its",
    "it's",
    // The words the spec itself asks people to write next to an id. `# covers V1.2.1` is the
    // recommended form, and reading "covers" as the test's subject would report every one of them.
    "cover",
    "covers",
    "covering",
    "requirement",
    "requirements",
    "asvs",
    "aisvs",
];

/// Whether two pieces of prose have no substantive word in common.
///
/// Public because the citation guard (`tests/citations.rs`) compares a rule's description with the
/// requirement it cites using exactly this test. Two comparisons that are meant to be the same and
/// are written twice are two comparisons that drift.
pub fn shares_no_words(test_text: &str, requirement: &str) -> bool {
    let words = |text: &str| -> BTreeSet<String> {
        text.split(|c: char| !c.is_ascii_alphanumeric())
            .map(|w| w.to_lowercase())
            .filter(|w| w.len() >= 4 && !NOISE.contains(&w.as_str()))
            // A word that is only a requirement id is the thing being matched, not evidence of it.
            .filter(|w| !w.chars().next().is_some_and(|c| c.is_ascii_digit()))
            .map(|w| stem(&w))
            .collect()
    };
    let in_test = words(test_text);
    if in_test.is_empty() {
        // A test with nothing to compare cannot be said to disagree with anything.
        return false;
    }
    in_test.is_disjoint(&words(requirement))
}

/// Enough of a stem that `passwords` and `password` are the same word, and no more.
fn stem(word: &str) -> String {
    for suffix in ["ing", "ies", "es", "ed", "s"] {
        if word.len() > suffix.len() + 3 && word.ends_with(suffix) {
            let base = &word[..word.len() - suffix.len()];
            return if suffix == "ies" {
                format!("{base}y")
            } else {
                base.to_owned()
            };
        }
    }
    word.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shapes_a_requirement_id_is_written_in() {
        // The underscore forms are the important ones: `def test_V1.2.1_x` is not a function name in
        // most languages, so a reader that only took dots would find nothing in a real test suite.
        for (line, expected) in [
            (
                "def test_V1_2_1_search_uses_bound_parameters():",
                vec!["V1.2.1"],
            ),
            ("# covers V1.2.1", vec!["V1.2.1"]),
            (
                "it('V1.2.1 and V13.3.1', () => {",
                vec!["V1.2.1", "V13.3.1"],
            ),
            ("func TestV1_2_1(t *testing.T) {", vec!["V1.2.1"]),
            ("// AC.1.1 and C9.5.4", vec!["AC.1.1", "C9.5.4"]),
        ] {
            assert_eq!(
                requirement_ids_in(line),
                expected.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                "{line}"
            );
        }
    }

    #[test]
    fn what_is_not_a_requirement_id() {
        for line in [
            // A chapter is not a requirement, and neither is a section on its own.
            "# about V1",
            // Not at a word boundary: this is somebody's own identifier.
            "let SV1.2.1 = 1",
            "const xV1_2_1 = 1",
            // The hyphen spelling the checkers themselves once got wrong. Taking it quietly here
            // would have hidden exactly that mistake.
            "# covers AC-05",
            "// nothing here",
            "assert response.status == 200",
        ] {
            assert!(
                requirement_ids_in(line).is_empty(),
                "{line} -> {:?}",
                requirement_ids_in(line)
            );
        }
    }

    #[test]
    fn an_id_stops_where_the_digits_do() {
        // The separator only counts when a digit follows, which is what keeps the rest of a test's
        // name out of the id.
        assert_eq!(
            requirement_ids_in("def test_V1_2_1_search_is_bound():"),
            vec!["V1.2.1".to_string()]
        );
        assert_eq!(
            requirement_ids_in("V1.2.1. The sentence ends here."),
            vec!["V1.2.1".to_string()]
        );
    }

    #[test]
    fn where_tests_live() {
        for path in [
            "tests/test_login.py",
            "spec/login_spec.rb",
            "src/__tests__/login.js",
            "internal/login_test.go",
            "src/login.test.ts",
            "src/login.spec.ts",
            "test/Login.java",
        ] {
            assert!(looks_like_a_test_path(path), "{path}");
        }
        for path in [
            "src/login.py",
            "app/models/user.rb",
            "src/latest.go",
            "lib/contest.js",
        ] {
            assert!(!looks_like_a_test_path(path), "{path}");
        }
    }

    #[test]
    fn a_failing_suite_credits_nothing_at_all() {
        // Not even the tests in it that passed: `sv` sees one exit code and cannot say which tests
        // it came from. This is the guard that stops a suite with one broken test handing out
        // credit for the other forty.
        let tests = vec![NamedTest {
            requirement_ids: vec!["V1.2.1".into()],
            text: "def test_V1_2_1_search_uses_bound_parameters():".into(),
            file: "tests/test_search.py".into(),
            line: 12,
        }];
        let describe =
            |_: &str| Some("Verify that the application uses parameterised queries".to_owned());
        let (verified, findings) = credit(&tests, SuiteOutcome::Failed { passed: None }, &describe);
        assert!(verified.is_empty() && findings.is_empty());

        let (verified, _) = credit(&tests, SuiteOutcome::Passed, &describe);
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].requirement_ids, vec!["V1.2.1".to_string()]);
        assert!(
            verified[0].scope.contains("tests/test_search.py:12"),
            "the scope has to say where to look: {}",
            verified[0].scope
        );
    }

    #[test]
    fn a_test_that_shares_no_words_with_its_requirement_is_reported_and_still_credited() {
        // About a third of these are honest tests phrased differently, which is exactly why this
        // reports rather than withholds. A check that takes credit away from a third of real work
        // is a check people turn off.
        let tests = vec![NamedTest {
            requirement_ids: vec!["V1.2.1".into()],
            text: "def test_the_homepage_renders():".into(),
            file: "tests/test_pages.py".into(),
            line: 3,
        }];
        let describe = |_: &str| {
            Some("Verify that the application uses parameterised database queries".to_owned())
        };
        let (verified, findings) = credit(&tests, SuiteOutcome::Passed, &describe);
        assert_eq!(verified.len(), 1, "the credit stands");
        assert_eq!(findings.len(), 1, "and the mismatch is reported");
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].confidence, Confidence::Low);
        assert!(
            findings[0].fix.contains("about a third"),
            "the fix has to say how often this is nothing: {}",
            findings[0].fix
        );
    }

    #[test]
    fn a_test_that_does_share_words_is_not_reported() {
        let tests = vec![NamedTest {
            requirement_ids: vec!["V1.2.1".into()],
            text: "def test_V1_2_1_search_uses_parameterised_queries():".into(),
            file: "tests/test_search.py".into(),
            line: 9,
        }];
        let describe = |_: &str| {
            Some("Verify that the application uses parameterised database queries".to_owned())
        };
        let (_, findings) = credit(&tests, SuiteOutcome::Passed, &describe);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn a_requirement_named_twice_in_one_file_is_credited_once() {
        // The docstring under a test repeats the id — that is one test, not two, and counting the
        // lines reported it twice and then complained that the docstring did not match the
        // requirement. The declaration is the line a reader wants to be sent to.
        let tests = vec![
            NamedTest {
                requirement_ids: vec!["V1.2.1".into()],
                text: "def test_V1_2_1_search_uses_parameterised_queries(self):".into(),
                file: "tests/test_search.py".into(),
                line: 12,
            },
            NamedTest {
                requirement_ids: vec!["V1.2.1".into()],
                text:
                    "\"\"\"The id in the name is what lets `sv` credit this test to V1.2.1.\"\"\""
                        .into(),
                file: "tests/test_search.py".into(),
                line: 13,
            },
        ];
        let describe = |_: &str| {
            Some("Verify that the application uses parameterised database queries".to_owned())
        };
        let (verified, findings) = credit(&tests, SuiteOutcome::Passed, &describe);
        assert_eq!(verified.len(), 1, "{verified:?}");
        assert!(
            verified[0].scope.contains("tests/test_search.py:12"),
            "{}",
            verified[0].scope
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn the_same_requirement_in_two_files_is_two_claims() {
        // Collapsing per file, not per requirement: two suites that both cover something are two
        // places to go and look, and reporting one of them hides the other.
        let tests = vec![
            NamedTest {
                requirement_ids: vec!["V1.2.1".into()],
                text: "def test_V1_2_1_search(self):".into(),
                file: "tests/test_search.py".into(),
                line: 4,
            },
            NamedTest {
                requirement_ids: vec!["V1.2.1".into()],
                text: "def test_V1_2_1_search(self):".into(),
                file: "tests/test_reports.py".into(),
                line: 9,
            },
        ];
        let describe = |_: &str| None;
        let (verified, _) = credit(&tests, SuiteOutcome::Passed, &describe);
        assert_eq!(verified.len(), 2, "{verified:?}");
    }

    #[test]
    fn the_form_the_spec_recommends_is_not_reported_as_a_mismatch() {
        // `# covers V1.2.1` above a test is what `sv init` asks for. It carries the id and none of
        // the test's own words, so reading "covers" as the test's subject would have flagged every
        // single one of them.
        let tests = vec![NamedTest {
            requirement_ids: vec!["V1.2.1".into()],
            text: "# covers V1.2.1".into(),
            file: "tests/test_search.py".into(),
            line: 11,
        }];
        let describe = |_: &str| {
            Some("Verify that the application uses parameterised database queries".to_owned())
        };
        let (verified, findings) = credit(&tests, SuiteOutcome::Passed, &describe);
        assert_eq!(verified.len(), 1);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn plurals_count_as_the_same_word() {
        // `passwords` and `password` are the same word to a reader, and a check that disagrees
        // would report honest tests for no reason — which is how this one gets ignored.
        let tests = vec![NamedTest {
            requirement_ids: vec!["V1.2.1".into()],
            text: "def test_passwords_are_hashed():".into(),
            file: "tests/test_auth.py".into(),
            line: 4,
        }];
        let describe = |_: &str| Some("Verify that each password is hashed".to_owned());
        let (_, findings) = credit(&tests, SuiteOutcome::Passed, &describe);
        assert!(findings.is_empty(), "{findings:?}");
    }
}
