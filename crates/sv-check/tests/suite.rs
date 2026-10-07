//! Reading requirement ids back out of a real folder of tests.
//!
//! The unit tests in `sv_check::suite` work on `NamedTest` values that were handed to them. These
//! build the folder instead, because the two mistakes that matter here are both about where the
//! walk goes: an id in the application code being read as a test, and a whole language's test files
//! being skipped while everything still looks like it worked.

mod scratch;

use scratch::Scratch;
use std::collections::BTreeSet;
use std::path::Path;
use sv_check::junit::TestCase;
use sv_check::suite::{SuiteOutcome, credit, declared_test_name, tests_naming_requirements};

fn scratch(name: &str) -> Scratch {
    Scratch::new(&format!("suite-{name}"))
}

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

fn known() -> BTreeSet<&'static str> {
    ["V1.2.1", "V1.2.2", "V1.2.4", "V13.3.1", "AC.1.1"]
        .into_iter()
        .collect()
}

#[test]
fn a_requirement_named_in_the_application_code_is_not_a_test() {
    // The distinction the whole thing rests on. `# covers V1.2.1` in `app.py` is somebody's note
    // about an intention; the same line in `tests/test_search.py` is a test that ran.
    let root = scratch("app-code");
    write(
        &root,
        "app.py",
        "# covers V1.2.1 — the search is bound\ndef search(q):\n    pass\n",
    );
    write(
        &root,
        "tests/test_search.py",
        "def test_V1_2_2_no_shell_is_spawned():\n    pass\n",
    );

    let found = tests_naming_requirements(&root, &known());
    let ids: Vec<&str> = found
        .iter()
        .flat_map(|t| t.requirement_ids.iter().map(String::as_str))
        .collect();
    assert_eq!(ids, vec!["V1.2.2"], "{found:?}");
    assert_eq!(found[0].file, "tests/test_search.py");
    assert_eq!(found[0].line, 1);
}

#[test]
fn a_note_or_a_text_file_among_the_tests_is_not_a_test() {
    // ADR-050: only code is read. A Markdown note under `tests/` that lists the requirements the
    // tests are meant to cover, or a text file of them, ran nothing. The control beside them, a
    // test in Python naming another id, is read, so the walk reached the folder.
    let root = scratch("notes");
    write(
        &root,
        "tests/README.md",
        "These tests cover V1.2.1 and V13.3.1.\n",
    );
    write(&root, "tests/covered.txt", "V1.2.4\n");
    write(
        &root,
        "tests/test_search.py",
        "def test_V1_2_2_no_shell_is_spawned():\n    pass\n",
    );
    let found = tests_naming_requirements(&root, &known());
    let ids: Vec<&str> = found
        .iter()
        .flat_map(|t| t.requirement_ids.iter().map(String::as_str))
        .collect();
    assert_eq!(ids, vec!["V1.2.2"], "{found:?}");
}

#[test]
fn every_language_the_spec_tells_people_to_use_is_actually_read() {
    // Written as one test on purpose. Each of these is a naming convention some ecosystem insists
    // on, and a walk that misses one reads nothing in that language while reporting nothing wrong.
    let root = scratch("languages");
    write(
        &root,
        "tests/test_python.py",
        "def test_V1_2_1_x():\n    pass\n",
    );
    write(
        &root,
        "internal/search_test.go",
        "func TestV1_2_2(t *testing.T) {}\n",
    );
    write(
        &root,
        "spec/search_spec.rb",
        "it 'V13.3.1 keeps no literal secret' do\nend\n",
    );
    write(
        &root,
        "src/__tests__/search.js",
        "// covers AC.1.1\ntest('x', () => {});\n",
    );
    write(
        &root,
        "web/search.test.ts",
        "it('V1.2.1 binds', () => {});\n",
    );

    let found = tests_naming_requirements(&root, &known());
    let mut ids: Vec<&str> = found
        .iter()
        .flat_map(|t| t.requirement_ids.iter().map(String::as_str))
        .collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(
        ids,
        vec!["AC.1.1", "V1.2.1", "V1.2.2", "V13.3.1"],
        "{found:?}"
    );
    assert_eq!(found.len(), 5, "one line each, from five files: {found:?}");
}

#[test]
fn an_id_that_resolves_to_nothing_is_not_credited() {
    // A typo has to come out as no credit rather than a green line against a requirement nobody
    // has. `V1.2.9` is the shape of a real id and is not one of the ids that exist here.
    let root = scratch("unknown-id");
    write(
        &root,
        "tests/test_typo.py",
        "def test_V1_2_9_something():\n    pass\n",
    );

    assert!(tests_naming_requirements(&root, &known()).is_empty());
}

#[test]
fn an_unknown_id_beside_a_known_one_drops_only_itself() {
    // The other half of the filter. A guard that throws the file away on one typo would lose the
    // real test sitting next to it, and the report would read the same either way.
    let root = scratch("unknown-beside-known");
    write(
        &root,
        "tests/test_mixed.py",
        "def test_V1_2_9_typo():\n    pass\n\ndef test_V1_2_1_search_is_bound():\n    pass\n",
    );

    let found = tests_naming_requirements(&root, &known());
    let ids: Vec<&str> = found
        .iter()
        .flat_map(|t| t.requirement_ids.iter().map(String::as_str))
        .collect();
    assert_eq!(ids, vec!["V1.2.1"], "{found:?}");
    assert_eq!(found[0].line, 4);
}

#[test]
fn only_the_test_that_disagrees_is_reported() {
    // Not "does it report" but "does it report the right one". A check that flags everything and a
    // check that flags nothing both pass a test that only counts findings on a single test.
    let root = scratch("one-mismatch");
    write(
        &root,
        "tests/test_pages.py",
        "def test_V1_2_1_search_uses_parameterised_queries():\n    pass\n\ndef test_V1_2_2_the_homepage_renders():\n    pass\n",
    );

    let found = tests_naming_requirements(&root, &known());
    let describe = |id: &str| match id {
        "V1.2.1" => {
            Some("Verify that the application uses parameterised database queries".to_owned())
        }
        "V1.2.2" => Some(
            "Verify that the application never passes input to an operating system shell"
                .to_owned(),
        ),
        _ => None,
    };
    let (verified, findings) = credit(&found, SuiteOutcome::Passed, &describe);
    assert_eq!(verified.len(), 2, "both are still credited: {verified:?}");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].requirement_ids, vec!["V1.2.2".to_string()]);
    assert_eq!(findings[0].location.line, 4);
}

#[test]
fn a_failing_suite_credits_nothing_however_many_tests_name_a_requirement() {
    // The unit test for this hands `credit` one test. The fear is a suite of forty where one
    // broke, so the witness has to be a folder with several.
    let root = scratch("failing-suite");
    write(
        &root,
        "tests/test_a.py",
        "def test_V1_2_1_search_is_bound():\n    pass\n",
    );
    write(
        &root,
        "tests/test_b.py",
        "def test_V1_2_2_no_shell():\n    pass\n",
    );
    write(
        &root,
        "tests/test_c.py",
        "def test_V13_3_1_no_literal_secret():\n    pass\n",
    );

    let found = tests_naming_requirements(&root, &known());
    assert_eq!(found.len(), 3, "{found:?}");

    let describe = |_: &str| Some("Verify something".to_owned());
    let (verified, findings) = credit(&found, SuiteOutcome::Failed { cases: None }, &describe);
    assert!(
        verified.is_empty() && findings.is_empty(),
        "one exit code does not say which of the three it came from: {verified:?} {findings:?}"
    );
}

#[test]
fn a_docstring_repeating_the_id_does_not_credit_the_test_twice() {
    // The shape the example app is written in, end to end through the walk rather than through
    // hand-built values: two lines name V1.2.1, and the report has to say one test, at line 1.
    let root = scratch("docstring");
    write(
        &root,
        "tests/test_search.py",
        "def test_V1_2_1_search_uses_parameterised_queries(self):\n    \"\"\"Naming V1.2.1 here is what credits it.\"\"\"\n    pass\n",
    );

    let found = tests_naming_requirements(&root, &known());
    assert_eq!(found.len(), 2, "both lines really do name it: {found:?}");

    let describe = |_: &str| {
        Some("Verify that the application uses parameterised database queries".to_owned())
    };
    let (verified, findings) = credit(&found, SuiteOutcome::Passed, &describe);
    assert_eq!(verified.len(), 1, "{verified:?}");
    assert!(
        verified[0].scope.contains("tests/test_search.py:1"),
        "the declaration is the line to send a reader to: {}",
        verified[0].scope
    );
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_failing_suite_credits_the_tests_its_runner_says_passed() {
    // The point of reading the runner's report. One broken test used to cost the credit of every
    // other test in the suite, because `sv` saw one exit code and could not say which.
    let root = scratch("partly-passing");
    write(
        &root,
        "tests/test_mixed.py",
        "def test_V1_2_4_search_is_bound():\n    pass\n\ndef test_V1_2_2_broken():\n    assert False\n",
    );
    let found = tests_naming_requirements(&root, &known());
    assert_eq!(found.len(), 2, "{found:?}");
    let describe = |_: &str| None;

    // Without a report, a failing suite still credits nothing at all.
    let (none, _) = credit(&found, SuiteOutcome::Failed { cases: None }, &describe);
    assert!(none.is_empty(), "{none:?}");

    // With one, the test the runner named as passing is credited and the other is not.
    let passed = cases(&["test_V1_2_4_search_is_bound"], &[]);
    let (verified, _) = credit(
        &found,
        SuiteOutcome::Failed {
            cases: Some(&passed),
        },
        &describe,
    );
    assert_eq!(verified.len(), 1, "{verified:?}");
    assert_eq!(verified[0].requirement_ids, vec!["V1.2.4".to_string()]);
    assert!(
        verified[0].scope.contains("did not"),
        "the scope has to say the suite failed and this test did not: {}",
        verified[0].scope
    );
}

#[test]
fn reading_the_report_can_only_ever_add_credit() {
    // The property the whole design rests on. Whatever the report says, a suite that passed credits
    // exactly what it credited before — the report is not even consulted — so this can never take
    // away a claim that used to be made.
    let root = scratch("monotone");
    write(
        &root,
        "tests/test_a.py",
        "def test_V1_2_4_one():\n    pass\n\ndef test_V1_2_2_two():\n    pass\n",
    );
    let found = tests_naming_requirements(&root, &known());
    let describe = |_: &str| None;

    let (whole_suite, _) = credit(&found, SuiteOutcome::Passed, &describe);
    let nothing_passed = cases(&[], &[]);
    let (with_empty_report, _) = credit(
        &found,
        SuiteOutcome::Failed {
            cases: Some(&nothing_passed),
        },
        &describe,
    );
    assert_eq!(whole_suite.len(), 2);
    assert!(
        with_empty_report.is_empty(),
        "a report naming nothing credits nothing, and the passing case is untouched"
    );
}

#[test]
fn a_test_is_found_under_the_names_runners_give_it() {
    // Until 6 October 2026 matching was exact, so a test whose runner reports it inside a longer
    // name was never credited from a failing suite: jest and Mocha put the `describe` titles first,
    // Vitest joins them with ` > `, pytest adds a parameter, and Go a subtest.
    let root = scratch("runner-names");
    write(
        &root,
        "tests/search.test.ts",
        "describe('search', () => {\n  it('V1.2.4 binds its parameters', () => {});\n});\n",
    );
    write(
        &root,
        "tests/test_auth.py",
        "def test_V13_3_1_no_literal_secret(value):\n    pass\n",
    );
    write(
        &root,
        "app/auth_test.go",
        "func TestV1_2_2Escapes(t *testing.T) {}\n",
    );
    let found = tests_naming_requirements(&root, &known());
    assert_eq!(found.len(), 3, "{found:?}");
    let credited = |reported: &[TestCase]| {
        let (verified, _) = credit(
            &found,
            SuiteOutcome::Failed {
                cases: Some(reported),
            },
            &describe_nothing(),
        );
        let mut ids: Vec<String> = verified
            .into_iter()
            .flat_map(|v| v.requirement_ids)
            .collect();
        ids.sort();
        ids
    };
    for (runner, title) in [
        ("jest and Mocha", "search V1.2.4 binds its parameters"),
        ("Vitest", "search > V1.2.4 binds its parameters"),
        ("exact", "V1.2.4 binds its parameters"),
    ] {
        assert_eq!(
            credited(&cases(
                &[
                    title,
                    "test_V13_3_1_no_literal_secret[empty]",
                    "TestV1_2_2Escapes/quotes"
                ],
                &["the homepage renders"]
            )),
            ["V1.2.2", "V1.2.4", "V13.3.1"],
            "{runner}"
        );
    }
    // A name that holds the title only inside a word, or another test's name, is not it.
    assert!(
        credited(&cases(
            &[
                "searchV1.2.4 binds its parameters",
                "test_V13_3_1_no_literal_secrets",
                "TestV1_2_2EscapesAll"
            ],
            &["the homepage renders"]
        ))
        .is_empty()
    );
}

#[test]
fn a_failing_case_that_could_be_the_same_test_credits_nothing() {
    // Until 6 October 2026 a passing case was enough, whatever else of the same name failed: two
    // classes each with `test_V1_2_4_bound`, one failing, credited V1.2.4. Every case that could be
    // the test has to have passed, so a wider match can only ever take credit away.
    let root = scratch("same-name");
    write(
        &root,
        "tests/test_search.py",
        "class TestA:\n    def test_V1_2_4_bound(self):\n        pass\n",
    );
    write(
        &root,
        "tests/search.test.js",
        "it('V1.2.2 escapes its output', () => {});\n",
    );
    let found = tests_naming_requirements(&root, &known());
    assert_eq!(found.len(), 2, "{found:?}");
    for reported in [
        cases(
            &["test_V1_2_4_bound", "V1.2.2 escapes its output"],
            &["test_V1_2_4_bound", "admin V1.2.2 escapes its output"],
        ),
        cases(
            &["test_V1_2_4_bound[a]", "a > V1.2.2 escapes its output"],
            &["test_V1_2_4_bound[b]", "b > V1.2.2 escapes its output"],
        ),
    ] {
        let (verified, _) = credit(
            &found,
            SuiteOutcome::Failed {
                cases: Some(&reported),
            },
            &describe_nothing(),
        );
        assert!(verified.is_empty(), "{reported:?}: {verified:?}");
    }
    // The control: with the failing ones gone, both are credited.
    let reported = cases(&["test_V1_2_4_bound", "V1.2.2 escapes its output"], &[]);
    let (verified, _) = credit(
        &found,
        SuiteOutcome::Failed {
            cases: Some(&reported),
        },
        &describe_nothing(),
    );
    assert_eq!(verified.len(), 2, "{verified:?}");
}

/// A runner's report: these cases passed, and these did not.
fn cases(passed: &[&str], failed: &[&str]) -> Vec<TestCase> {
    let case = |name: &&str, passed: bool| TestCase {
        name: (*name).to_owned(),
        classname: "c".to_owned(),
        passed,
    };
    passed
        .iter()
        .map(|n| case(n, true))
        .chain(failed.iter().map(|n| case(n, false)))
        .collect()
}

#[test]
fn a_test_the_runner_skipped_is_not_credited() {
    // A skipped test did not run, so it established nothing — and crediting one is the dangerous
    // direction: a requirement would go green on the strength of a test nobody executed. The
    // parser decides this, so this asserts it again from the crediting side, end to end.
    let root = scratch("skipped");
    write(
        &root,
        "tests/test_skip.py",
        "def test_V1_2_4_needs_a_database():\n    pass\n",
    );
    let found = tests_naming_requirements(&root, &known());
    assert_eq!(found.len(), 1);

    let report = r#"<testsuite>
  <testcase classname="c" name="test_V1_2_4_needs_a_database"><skipped message="no database"/></testcase>
</testsuite>"#;
    let cases = sv_check::junit::parse(report).expect("the report reads");
    assert!(
        cases.iter().all(|c| !c.passed),
        "a skipped case is not a passing one: {cases:?}"
    );

    let (verified, _) = credit(
        &found,
        SuiteOutcome::Failed {
            cases: Some(&cases),
        },
        &describe_nothing(),
    );
    assert!(
        verified.is_empty(),
        "a test that never ran must not credit anything: {verified:?}"
    );
}

#[test]
fn tests_reported_in_tap_go_json_and_jest_json_are_credited_as_junit_ones_are() {
    // The same suite of three tests, each naming a requirement, one failing and one skipped, read
    // from each form `test_report` reads. Only the one that passed is credited, from every form.
    let root = scratch("report-forms");
    write(
        &root,
        "test/notes.test.js",
        "describe('notes', () => {\n  it('are private V13.3.1', () => {});\n  \
         it('escape output V1.2.1', () => {});\n  it.skip('bind queries V1.2.4', () => {});\n});\n",
    );
    write(
        &root,
        "notes_test.go",
        "func TestPrivate_V13_3_1(t *testing.T) {}\nfunc TestEscape_V1_2_1(t *testing.T) {}\n\
         func TestBound_V1_2_4(t *testing.T) {}\n",
    );
    let found = tests_naming_requirements(&root, &known());
    let js: Vec<_> = found
        .iter()
        .filter(|t| t.file.ends_with(".js"))
        .cloned()
        .collect();
    let go: Vec<_> = found
        .iter()
        .filter(|t| t.file.ends_with(".go"))
        .cloned()
        .collect();
    assert_eq!((js.len(), go.len()), (3, 3), "{found:?}");

    let tap = "TAP version 13\n# Subtest: notes\n    ok 1 - are private V13.3.1\n    \
               not ok 2 - escape output V1.2.1\n    ok 3 - bind queries V1.2.4 # SKIP\n    1..3\n\
               not ok 1 - notes\n1..1\n";
    let jest = r#"{"testResults":[{"name":"test/notes.test.js","assertionResults":[
        {"fullName":"notes are private V13.3.1","status":"passed"},
        {"fullName":"notes escape output V1.2.1","status":"failed"},
        {"fullName":"notes bind queries V1.2.4","status":"pending"}]}]}"#;
    let go_json = [
        ("TestPrivate_V13_3_1", "pass"),
        ("TestEscape_V1_2_1", "fail"),
        ("TestBound_V1_2_4", "skip"),
    ]
    .iter()
    .map(|(t, a)| format!("{{\"Action\":\"{a}\",\"Package\":\"app\",\"Test\":\"{t}\"}}\n"))
    .collect::<String>();

    for (form, report, tests) in [
        ("TAP", tap, &js),
        ("jest JSON", jest, &js),
        ("go test -json", go_json.as_str(), &go),
    ] {
        // Through the function `sv report` reads a failed suite's report with.
        let cases = sv_check::suite::reported_cases(Some(report))
            .expect("a report was given")
            .unwrap_or_else(|e| panic!("{form} was refused: {}", e.why));
        let (verified, _) = credit(
            tests,
            SuiteOutcome::Failed {
                cases: Some(&cases),
            },
            &describe_nothing(),
        );
        let ids: Vec<&str> = verified
            .iter()
            .flat_map(|v| v.requirement_ids.iter().map(String::as_str))
            .collect();
        assert_eq!(ids, ["V13.3.1"], "{form}: {verified:?}");
    }
}

fn describe_nothing() -> impl Fn(&str) -> Option<String> {
    |_: &str| None
}

#[test]
fn the_names_a_runner_would_report() {
    for (line, expected) in [
        ("def test_V1_2_4_search(self):", Some("test_V1_2_4_search")),
        ("func TestV1_2_4(t *testing.T) {", Some("TestV1_2_4")),
        ("    fn test_v1_2_4() {", Some("test_v1_2_4")),
        (
            "public void testSearchIsBound() {",
            Some("testSearchIsBound"),
        ),
        (
            "it('binds its parameters', () => {",
            Some("binds its parameters"),
        ),
        ("test(\"binds\", async () => {", Some("binds")),
        ("# covers V1.2.4", None),
        ("assert response.status == 200", None),
    ] {
        assert_eq!(declared_test_name(line).as_deref(), expected, "{line}");
    }
}
