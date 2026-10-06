//! A test runner's own report in whichever of the forms `sv` reads: JUnit XML (`junit.rs`), TAP,
//! the JSON lines `go test -json` writes, and the JSON jest and Vitest write.
//!
//! Every reader here holds to `junit.rs`'s design: **it fails closed**. Reading a failed case as
//! passed credits a requirement nothing established, so anything a reader was not written for (a
//! line it does not know, a result word it has never seen, a count that does not add up) refuses the
//! whole report rather than returning what it understood. A refused report falls back to the exit
//! code, which credits nothing from a failed suite.
//!
//! Which form a file is in is decided from how it opens, never guessed from its name: `<` is XML, a
//! `TAP version` line (or a TAP plan or result line) is TAP, a JSON object holding `testResults` is
//! jest's or Vitest's, and JSON objects one to a line holding `Action` are Go's. A file that opens
//! some other way is refused, and the refusal names the forms that are read.

use crate::junit::{TestCase, Unreadable};

fn refuse(why: impl Into<String>) -> Unreadable {
    Unreadable { why: why.into() }
}

/// Every case in a test report, whichever readable form it is in, or a refusal naming what stopped it.
pub fn parse(text: &str) -> Result<Vec<TestCase>, Unreadable> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let start = text.trim_start();
    if start.starts_with('<') {
        return crate::junit::parse(text);
    }
    if start.starts_with('{') {
        // One object for the whole run is jest's or Vitest's; one object a line is Go's.
        return match serde_json::from_str::<serde_json::Value>(start) {
            // One event alone parses whole too.
            Ok(whole) if whole.get("Action").is_some() => go_test_json(start),
            Ok(whole) => jest(&whole),
            Err(_) => go_test_json(start),
        };
    }
    let first = start.lines().next().unwrap_or_default().trim_end();
    if first.starts_with("TAP version ")
        || first.starts_with("1..")
        || first.starts_with("ok ")
        || first == "ok"
        || first.starts_with("not ok")
    {
        return tap(start);
    }
    Err(refuse(
        "the report is in none of the forms `sv` reads (JUnit XML, TAP, `go test -json`, or the \
         JSON jest and Vitest write)",
    ))
}

/// TAP, versions 13 and 14, as `node --test`, `bats`, and any TAP producer write it.
///
/// A result line is `ok` or `not ok`, a number, and a description, with an optional `# SKIP` or
/// `# TODO` directive; neither directive is a pass, since a skipped test did not run and a TODO test
/// is not yet expected to work. A subtest is indented four spaces under the test it belongs to
/// (TAP 14, and `node --test`), and is read as a case of its own. A YAML block after a result (`---`
/// to `...`) is skipped whole, as are comments and pragmas.
///
/// Refused: a `Bail out!`, which means the run stopped early; a top level with no plan, or a plan
/// whose count differs from the results at its level, which means the report is not the whole run;
/// a version other than 13 or 14; and any line that is none of these.
fn tap(text: &str) -> Result<Vec<TestCase>, Unreadable> {
    let mut out = Vec::new();
    // For each indentation level in use: the plan's count, if one was seen, and the results so far.
    let mut levels: Vec<(usize, Option<usize>, usize)> = Vec::new();
    let mut in_yaml: Option<usize> = None;
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim_end();
        let indent = line.len() - line.trim_start().len();
        let body = line.trim_start();
        if let Some(yaml_indent) = in_yaml {
            if body == "..." && indent == yaml_indent {
                in_yaml = None;
            } else if !body.is_empty() && indent < yaml_indent {
                return Err(refuse(format!(
                    "line {} ends a YAML block that was never closed",
                    n + 1
                )));
            }
            continue;
        }
        if body.is_empty() || body.starts_with('#') || body.starts_with("pragma ") {
            continue;
        }
        // A YAML block sits two spaces in from the result it belongs to.
        if body == "---" {
            in_yaml = Some(indent);
            continue;
        }
        if indent % 4 != 0 {
            return Err(refuse(format!(
                "line {} is indented {indent} spaces, which is no subtest level",
                n + 1
            )));
        }
        let level = indent / 4;
        if let Some(version) = body.strip_prefix("TAP version ") {
            if n != 0 && level == 0 {
                return Err(refuse("a `TAP version` line is not the first line"));
            }
            if version != "13" && version != "14" {
                return Err(refuse(format!(
                    "TAP version {version} is not one `sv` reads"
                )));
            }
            continue;
        }
        if body.starts_with("Bail out!") {
            return Err(refuse(
                "the run bailed out, so the report is not the whole of it",
            ));
        }
        while levels.len() <= level {
            levels.push((levels.len(), None, 0));
        }
        if let Some(plan) = body.strip_prefix("1..") {
            let count = plan
                .split(|c: char| c.is_whitespace() || c == '#')
                .next()
                .and_then(|c| c.parse::<usize>().ok())
                .ok_or_else(|| refuse(format!("line {} is a plan with no count", n + 1)))?;
            if levels[level].1.replace(count).is_some() {
                return Err(refuse(format!(
                    "line {} is a second plan at its level",
                    n + 1
                )));
            }
            continue;
        }
        let (passed, rest) = if let Some(rest) = body.strip_prefix("not ok") {
            (false, rest)
        } else if let Some(rest) = body.strip_prefix("ok") {
            (true, rest)
        } else {
            return Err(refuse(format!(
                "line {} is not a line of TAP this reader knows",
                n + 1
            )));
        };
        if !(rest.is_empty() || rest.starts_with(' ')) {
            return Err(refuse(format!(
                "line {} is not a line of TAP this reader knows",
                n + 1
            )));
        }
        // A deeper level ends when its parent's result arrives; its plan must have been met.
        close_deeper(&mut levels, level)?;
        levels[level].2 += 1;
        let rest = rest.trim_start();
        let rest = rest
            .trim_start_matches(|c: char| c.is_ascii_digit())
            .trim_start();
        let rest = rest.strip_prefix("- ").unwrap_or(rest);
        let (description, directive) = split_directive(rest);
        let directed = directive
            .map(|d| {
                let d = d.to_ascii_uppercase();
                d.starts_with("SKIP") || d.starts_with("TODO")
            })
            .unwrap_or(false);
        out.push(TestCase {
            name: description,
            classname: String::new(),
            passed: passed && !directed,
        });
    }
    if in_yaml.is_some() {
        return Err(refuse("the report ends inside a YAML block"));
    }
    close_deeper(&mut levels, 0)?;
    match levels.first() {
        None => return Err(refuse("the report names no test cases at all")),
        Some((_, None, _)) => {
            return Err(refuse(
                "the report has no plan (`1..N`), so whether it is the whole run is not known",
            ));
        }
        Some((_, Some(planned), seen)) if planned != seen => {
            return Err(refuse(format!(
                "the plan says {planned} tests and the report gives {seen}"
            )));
        }
        _ => {}
    }
    if out.is_empty() {
        return Err(refuse("the report names no test cases at all"));
    }
    Ok(out)
}

/// Checks and forgets every level deeper than `level`: a planned subtest level must have as many
/// results as its plan says.
fn close_deeper(
    levels: &mut Vec<(usize, Option<usize>, usize)>,
    level: usize,
) -> Result<(), Unreadable> {
    while levels.len() > level + 1 {
        let (depth, plan, seen) = levels.pop().expect("longer than level + 1");
        if let Some(planned) = plan
            && planned != seen
        {
            return Err(refuse(format!(
                "a subtest at level {depth} plans {planned} tests and gives {seen}"
            )));
        }
    }
    Ok(())
}

/// A TAP description and its directive: `name # SKIP why` is `("name", Some("SKIP why"))`. A `\#`
/// is a `#` in the name, and `\\` a backslash.
fn split_directive(text: &str) -> (String, Option<String>) {
    let mut name = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if matches!(chars.peek(), Some('#') | Some('\\')) => {
                name.push(chars.next().expect("peeked"));
            }
            '#' => {
                let directive: String = chars.collect();
                return (
                    name.trim_end().to_owned(),
                    Some(directive.trim().to_owned()),
                );
            }
            _ => name.push(c),
        }
    }
    (name.trim_end().to_owned(), None)
}

/// The JSON `go test -json` writes: one event a line. A test's last word is `pass`, `fail`, or
/// `skip`; only `pass` is passed. A test that started and never got a last word (a panic, a time-out)
/// is a case that did not pass, so it can never be credited by a same-named case that did. A line
/// that is not a JSON object, or an action Go does not write, refuses the report.
fn go_test_json(text: &str) -> Result<Vec<TestCase>, Unreadable> {
    const ACTIONS: &[&str] = &[
        "start",
        "run",
        "pause",
        "cont",
        "pass",
        "bench",
        "fail",
        "output",
        "skip",
        "build-output",
        "build-fail",
    ];
    // In the order first seen: (package, test) and the last word so far.
    let mut tests: Vec<((String, String), Option<bool>)> = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event: serde_json::Value = serde_json::from_str(line).map_err(|_| {
            refuse(format!(
                "line {} is not one of the JSON events `go test -json` writes",
                n + 1
            ))
        })?;
        let action = event
            .get("Action")
            .and_then(|a| a.as_str())
            .ok_or_else(|| refuse(format!("line {} has no Action", n + 1)))?;
        if !ACTIONS.contains(&action) {
            return Err(refuse(format!(
                "line {} has the action \"{action}\", which this reader does not know",
                n + 1
            )));
        }
        // Package-level events say how the package went, which the exit code already does.
        let Some(test) = event.get("Test").and_then(|t| t.as_str()) else {
            continue;
        };
        let package = event
            .get("Package")
            .and_then(|p| p.as_str())
            .unwrap_or_default();
        let key = (package.to_owned(), test.to_owned());
        let at = match tests.iter().position(|(k, _)| *k == key) {
            Some(at) => at,
            None => {
                tests.push((key, None));
                tests.len() - 1
            }
        };
        match action {
            "pass" => tests[at].1 = Some(true),
            "fail" | "skip" => tests[at].1 = Some(false),
            _ => {}
        }
    }
    if tests.is_empty() {
        return Err(refuse("the report names no test cases at all"));
    }
    Ok(tests
        .into_iter()
        .map(|((package, test), word)| TestCase {
            name: test,
            classname: package,
            passed: word == Some(true),
        })
        .collect())
}

/// The JSON jest writes with `--json`, and Vitest with `--reporter=json`, which follows jest's shape:
/// `testResults`, one per file, each with `assertionResults`, one per test, each with a `status`.
/// A test's name is its `fullName`, the `describe` titles and its own, as the runner reports it.
/// Only `passed` is passed; `failed`, `pending`, `skipped`, `todo`, `disabled`, and `focused` are
/// not; any other status refuses the report. A file that could not run has no results and adds no
/// case, so nothing in it is credited.
fn jest(whole: &serde_json::Value) -> Result<Vec<TestCase>, Unreadable> {
    const NOT_PASSED: &[&str] = &[
        "failed", "pending", "skipped", "todo", "disabled", "focused",
    ];
    let files = whole
        .get("testResults")
        .and_then(|r| r.as_array())
        .ok_or_else(|| {
            refuse("the JSON report has no `testResults`, so it is not jest's or Vitest's")
        })?;
    let mut out = Vec::new();
    for file in files {
        let path = file
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or_default();
        let results = file
            .get("assertionResults")
            .and_then(|r| r.as_array())
            .ok_or_else(|| refuse(format!("`{path}` in the report has no `assertionResults`")))?;
        for result in results {
            let name = result
                .get("fullName")
                .or_else(|| result.get("title"))
                .and_then(|n| n.as_str())
                .ok_or_else(|| refuse(format!("a test in `{path}` has no name")))?;
            let status = result
                .get("status")
                .and_then(|s| s.as_str())
                .ok_or_else(|| refuse(format!("the test \"{name}\" has no status")))?;
            let passed = match status {
                "passed" => true,
                s if NOT_PASSED.contains(&s) => false,
                other => {
                    return Err(refuse(format!(
                        "the test \"{name}\" has the status \"{other}\", which this reader does not know"
                    )));
                }
            };
            out.push(TestCase {
                name: name.to_owned(),
                classname: path.to_owned(),
                passed,
            });
        }
    }
    if out.is_empty() {
        return Err(refuse("the report names no test cases at all"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cases(text: &str) -> Vec<(String, bool)> {
        parse(text)
            .unwrap_or_else(|e| panic!("refused: {}", e.why))
            .into_iter()
            .map(|c| (c.name, c.passed))
            .collect()
    }

    fn refused(text: &str) -> String {
        match parse(text) {
            Ok(c) => panic!("read when it should be refused: {c:?}"),
            Err(e) => e.why,
        }
    }

    fn case(name: &str, passed: bool) -> (String, bool) {
        (name.to_owned(), passed)
    }

    /// What `node --test` 22 writes with `--test-reporter=tap`: subtests indented under their
    /// `describe`, YAML after every result, and comments at the end.
    const NODE_TAP: &str = "TAP version 13
# Subtest: search
    # Subtest: binds its parameters V1.2.4
    ok 1 - binds its parameters V1.2.4
      ---
      duration_ms: 1.2
      ...
    # Subtest: refuses another user's notes V8.2.2
    not ok 2 - refuses another user's notes V8.2.2
      ---
      duration_ms: 0.8
      failureType: 'testCodeFailure'
      error: 'Expected values to be strictly equal'
      ...
    1..2
not ok 1 - search
  ---
  duration_ms: 3.1
  ...
# Subtest: skipped one V2.1.1
ok 2 - skipped one V2.1.1 # SKIP not ready
  ---
  duration_ms: 0.1
  ...
1..2
# tests 3
# pass 1
# fail 1
";

    #[test]
    fn node_s_tap_is_read_with_its_subtests_and_directives() {
        assert_eq!(
            cases(NODE_TAP),
            [
                case("binds its parameters V1.2.4", true),
                case("refuses another user's notes V8.2.2", false),
                case("search", false),
                case("skipped one V2.1.1", false),
            ]
        );
    }

    #[test]
    fn bats_tap_is_read() {
        // What `bats --formatter tap` writes: the plan first, no version line.
        let bats = "1..3\nok 1 sign-in refuses a wrong password V6.3.1\nnot ok 2 reset expires\n\
                    # (in test file test.bats, line 9)\nok 3 todo one # TODO later\n";
        assert_eq!(
            cases(bats),
            [
                case("sign-in refuses a wrong password V6.3.1", true),
                case("reset expires", false),
                case("todo one", false),
            ]
        );
    }

    #[test]
    fn an_escaped_hash_is_part_of_a_tap_name() {
        assert_eq!(
            cases("1..1\nok 1 - issue \\#12 is fixed\n"),
            [case("issue #12 is fixed", true)]
        );
    }

    #[test]
    fn tap_that_is_not_the_whole_run_is_refused() {
        assert!(refused("TAP version 13\nok 1 - a\n").contains("no plan"));
        assert!(refused("1..3\nok 1 - a\nok 2 - b\n").contains("says 3 tests"));
        assert!(refused("1..2\nok 1 - a\nBail out! database gone\n").contains("bailed out"));
        // A subtest level that gives fewer results than it plans.
        let short = "TAP version 14\n    1..2\n    ok 1 - inner\nok 1 - outer\n1..1\n";
        assert!(refused(short).contains("plans 2"), "{}", refused(short));
    }

    #[test]
    fn tap_this_reader_does_not_know_is_refused() {
        assert!(refused("TAP version 12\n1..1\nok 1 - a\n").contains("version 12"));
        assert!(refused("1..1\nok 1 - a\nPASSED somewhere\n").contains("line 3"));
        assert!(refused("1..1\n  ok 1 - a\n").contains("indented 2"));
        assert!(refused("1..1\nok 1 - a\n  ---\n  x: 1\n").contains("YAML"));
        assert!(refused("1..1\nokay 1 - a\n").contains("line 2"));
    }

    /// `go test -json ./...` for a package with one passing test, one failing subtest, one skipped
    /// test, and one that started and never finished.
    const GO_JSON: &str = r#"{"Time":"2026-10-06T10:00:00Z","Action":"start","Package":"example.com/app"}
{"Time":"2026-10-06T10:00:00Z","Action":"run","Package":"example.com/app","Test":"TestQueryIsBound_V1_2_4"}
{"Time":"2026-10-06T10:00:00Z","Action":"output","Package":"example.com/app","Test":"TestQueryIsBound_V1_2_4","Output":"=== RUN   TestQueryIsBound_V1_2_4\n"}
{"Time":"2026-10-06T10:00:00Z","Action":"pass","Package":"example.com/app","Test":"TestQueryIsBound_V1_2_4","Elapsed":0}
{"Time":"2026-10-06T10:00:00Z","Action":"run","Package":"example.com/app","Test":"TestOwner_V8_2_2"}
{"Time":"2026-10-06T10:00:00Z","Action":"run","Package":"example.com/app","Test":"TestOwner_V8_2_2/other_user"}
{"Time":"2026-10-06T10:00:00Z","Action":"fail","Package":"example.com/app","Test":"TestOwner_V8_2_2/other_user","Elapsed":0}
{"Time":"2026-10-06T10:00:00Z","Action":"fail","Package":"example.com/app","Test":"TestOwner_V8_2_2","Elapsed":0}
{"Time":"2026-10-06T10:00:00Z","Action":"run","Package":"example.com/app","Test":"TestLater"}
{"Time":"2026-10-06T10:00:00Z","Action":"skip","Package":"example.com/app","Test":"TestLater","Elapsed":0}
{"Time":"2026-10-06T10:00:00Z","Action":"run","Package":"example.com/app","Test":"TestHangs"}
{"Time":"2026-10-06T10:00:00Z","Action":"fail","Package":"example.com/app","Elapsed":0.01}
"#;

    #[test]
    fn go_test_json_is_read_with_its_subtests() {
        let read = parse(GO_JSON).unwrap_or_else(|e| panic!("{}", e.why));
        assert!(read.iter().all(|c| c.classname == "example.com/app"));
        assert_eq!(
            cases(GO_JSON),
            [
                case("TestQueryIsBound_V1_2_4", true),
                case("TestOwner_V8_2_2", false),
                case("TestOwner_V8_2_2/other_user", false),
                case("TestLater", false),
                case("TestHangs", false),
            ]
        );
    }

    #[test]
    fn go_test_json_this_reader_does_not_know_is_refused() {
        let mut odd = GO_JSON.to_owned();
        odd.push_str("{\"Action\":\"teleport\",\"Package\":\"p\",\"Test\":\"T\"}\n");
        assert!(refused(&odd).contains("teleport"));
        let mut noise = GO_JSON.to_owned();
        noise.push_str("ok  \texample.com/app\t0.01s\n");
        assert!(refused(&noise).contains("line 13"));
        assert!(refused("{\"Action\":\"start\",\"Package\":\"p\"}\n{\"Action\":\"pass\",\"Package\":\"p\"}\n")
            .contains("no test cases"));
    }

    /// What `jest --json` writes, trimmed to what is read: one file that ran and one that could not.
    const JEST_JSON: &str = r#"{
  "numTotalTests": 4, "success": false,
  "testResults": [
    {"name": "/app/test/notes.test.js", "status": "failed",
     "assertionResults": [
       {"ancestorTitles": ["notes"], "title": "are private V8.2.2", "fullName": "notes are private V8.2.2", "status": "passed"},
       {"ancestorTitles": ["notes"], "title": "escape output V1.2.1", "fullName": "notes escape output V1.2.1", "status": "failed"},
       {"ancestorTitles": [], "title": "later", "fullName": "later", "status": "todo"},
       {"ancestorTitles": [], "title": "off", "fullName": "off", "status": "pending"}
     ]},
    {"name": "/app/test/broken.test.js", "status": "failed", "message": "Cannot find module", "assertionResults": []}
  ]
}"#;

    #[test]
    fn jest_and_vitest_json_are_read() {
        assert_eq!(
            cases(JEST_JSON),
            [
                case("notes are private V8.2.2", true),
                case("notes escape output V1.2.1", false),
                case("later", false),
                case("off", false),
            ]
        );
        // Vitest's `--reporter=json` has the same shape; its names are its own.
        let vitest = r#"{"testResults":[{"name":"/app/a.test.ts","assertionResults":[
            {"fullName":"auth > locks after five tries V6.3.1","title":"locks after five tries V6.3.1","status":"passed"},
            {"fullName":"auth > skipped","title":"skipped","status":"skipped"}]}]}"#;
        assert_eq!(
            cases(vitest),
            [
                case("auth > locks after five tries V6.3.1", true),
                case("auth > skipped", false),
            ]
        );
    }

    #[test]
    fn json_this_reader_does_not_know_is_refused() {
        assert!(refused(r#"{"results": []}"#).contains("testResults"));
        assert!(
            refused(r#"{"testResults":[{"name":"a","assertionResults":[{"fullName":"x","status":"flaky"}]}]}"#)
                .contains("flaky")
        );
        assert!(
            refused(r#"{"testResults":[{"name":"a","assertionResults":[{"fullName":"x"}]}]}"#)
                .contains("no status")
        );
        assert!(refused(r#"{"testResults":[{"name":"a"}]}"#).contains("assertionResults"));
        assert!(refused(r#"{"testResults":[]}"#).contains("no test cases"));
    }

    #[test]
    fn junit_still_goes_to_its_own_reader_and_anything_else_is_refused() {
        let junit = r#"<testsuite><testcase name="a" classname="k"/></testsuite>"#;
        assert_eq!(cases(junit), [case("a", true)]);
        assert_eq!(cases(&format!("\u{feff}  {junit}")), [case("a", true)]);
        assert!(refused("PASS test/a.test.js\n").contains("none of the forms"));
        assert!(refused("").contains("none of the forms"));
    }
}
