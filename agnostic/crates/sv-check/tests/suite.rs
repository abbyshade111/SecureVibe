//! Reading requirement ids back out of a real folder of tests.
//!
//! The unit tests in `sv_check::suite` work on `NamedTest` values that were handed to them. These
//! build the folder instead, because the two mistakes that matter here are both about where the
//! walk goes: an id in the application code being read as a test, and a whole language's test files
//! being skipped while everything still looks like it worked.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use sv_check::suite::{credit, tests_naming_requirements};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-suite-{name}"));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

fn known() -> BTreeSet<&'static str> {
    ["V1.2.1", "V1.2.2", "V13.3.1", "AC.1.1"]
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
    let (verified, findings) = credit(&found, true, &describe);
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
    let (verified, findings) = credit(&found, false, &describe);
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
    let (verified, findings) = credit(&found, true, &describe);
    assert_eq!(verified.len(), 1, "{verified:?}");
    assert!(
        verified[0].scope.contains("tests/test_search.py:1"),
        "the declaration is the line to send a reader to: {}",
        verified[0].scope
    );
    assert!(findings.is_empty(), "{findings:?}");
}
