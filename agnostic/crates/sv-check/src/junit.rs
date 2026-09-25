//! Reading a test runner's own report, so a suite that mostly passed is worth something.
//!
//! `suite.rs` credits a requirement only when the whole suite passed, because `sv run` sees one exit
//! code and cannot tell which tests it came from. One failing test anywhere therefore credits
//! nothing, however many of the other forty named a requirement and passed. Every runner in the
//! languages the manifest knows can write JUnit XML, and that names each case and says how it went.
//!
//! **This parser fails closed, and that is the whole design.** Hand-written XML is error-prone, and
//! the way it would be wrong here is the way that matters: reading a failed case as passed credits a
//! requirement nothing established. So anything surprising — an unclosed tag, an entity it does not
//! know, a construct it was not written for — refuses the entire report rather than returning what
//! it managed to understand. A refused report falls back to the exit code, which is where this
//! started. That turns every weakness of the parser into lost coverage instead of a false claim.
//!
//! The reader is also deliberately small. It understands `testsuites`, `testsuite` and `testcase`,
//! the `name` and `classname` attributes, and the `failure`, `error` and `skipped` children. It does
//! not understand `properties`, `system-out`, or anything else with content worth interpreting — it
//! skips those by name, and refuses any element it has never heard of.

use std::collections::BTreeSet;

/// One case as the runner reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestCase {
    pub name: String,
    pub classname: String,
    /// A skipped test did not run, so it is not passed. It is not evidence about anything.
    pub passed: bool,
}

/// Why a report could not be used. Always reported to the owner: a report that cannot be read and a
/// report saying everything passed must never reach them as the same thing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable {
    pub why: String,
}

fn refuse(why: impl Into<String>) -> Unreadable {
    Unreadable { why: why.into() }
}

/// Elements whose contents are of no interest and may hold anything at all.
const SKIPPED_WHOLE: &[&str] = &["properties", "system-out", "system-err"];
/// Elements this reader understands.
const KNOWN: &[&str] = &[
    "testsuites",
    "testsuite",
    "testcase",
    "failure",
    "error",
    "skipped",
    "property",
    "properties",
    "system-out",
    "system-err",
    "rerunFailure",
    "flakyFailure",
];

/// Every case in a JUnit XML report, or a refusal naming what stopped it.
pub fn parse(xml: &str) -> Result<Vec<TestCase>, Unreadable> {
    let chars: Vec<char> = xml.chars().collect();
    let mut i = 0;
    let mut out: Vec<TestCase> = Vec::new();
    // The case currently open, and whether anything has said it did not pass.
    let mut open_case: Option<TestCase> = None;
    let mut depth_of_open_case = 0usize;
    let mut depth = 0usize;

    while i < chars.len() {
        if chars[i] != '<' {
            i += 1;
            continue;
        }
        // Comments, CDATA, declarations and doctypes: skipped whole, never interpreted.
        if starts_with(&chars, i, "<!--") {
            i = find(&chars, i, "-->").ok_or_else(|| refuse("a comment is never closed"))? + 3;
            continue;
        }
        if starts_with(&chars, i, "<![CDATA[") {
            i = find(&chars, i, "]]>").ok_or_else(|| refuse("a CDATA section is never closed"))?
                + 3;
            continue;
        }
        if starts_with(&chars, i, "<?") {
            i = find(&chars, i, "?>")
                .ok_or_else(|| refuse("a processing instruction is never closed"))?
                + 2;
            continue;
        }
        if starts_with(&chars, i, "<!") {
            i = find(&chars, i, ">").ok_or_else(|| refuse("a declaration is never closed"))? + 1;
            continue;
        }

        let end = find(&chars, i, ">").ok_or_else(|| refuse("a tag is never closed"))?;
        let raw: String = chars[i + 1..end].iter().collect();
        i = end + 1;

        let closing = raw.starts_with('/');
        let self_closing = raw.ends_with('/');
        let body = raw.trim_start_matches('/').trim_end_matches('/').trim();
        let name = body
            .split_whitespace()
            .next()
            .ok_or_else(|| refuse("a tag has no name"))?
            .to_owned();

        if !KNOWN.contains(&name.as_str()) {
            return Err(refuse(format!(
                "the report holds a <{name}> element this reader does not understand"
            )));
        }

        if closing {
            depth = depth.checked_sub(1).ok_or_else(|| {
                refuse(format!("</{name}> closes an element that was never opened"))
            })?;
            if name == "testcase" {
                let case = open_case
                    .take()
                    .ok_or_else(|| refuse("</testcase> closes a case that was never opened"))?;
                out.push(case);
            }
            continue;
        }

        // An element whose contents may be anything: skip to its matching close.
        if SKIPPED_WHOLE.contains(&name.as_str()) && !self_closing {
            i = skip_element(&chars, i, &name)?;
            continue;
        }

        match name.as_str() {
            "testcase" => {
                if open_case.is_some() {
                    return Err(refuse("a <testcase> opens inside another <testcase>"));
                }
                let attributes = attributes(body)?;
                let case_name = attributes
                    .iter()
                    .find(|(k, _)| k == "name")
                    .map(|(_, v)| v.clone())
                    .ok_or_else(|| refuse("a <testcase> has no name"))?;
                let classname = attributes
                    .iter()
                    .find(|(k, _)| k == "classname")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                let case = TestCase {
                    name: case_name,
                    classname,
                    // Passed until something inside it says otherwise.
                    passed: true,
                };
                if self_closing {
                    out.push(case);
                } else {
                    open_case = Some(case);
                    depth_of_open_case = depth;
                }
            }
            "failure" | "error" | "skipped" => {
                // Only meaningful inside a case; a runner that puts one elsewhere is one this
                // reader was not written for.
                let case = open_case
                    .as_mut()
                    .ok_or_else(|| refuse(format!("a <{name}> appears outside any <testcase>")))?;
                case.passed = false;
                if !self_closing {
                    i = skip_element(&chars, i, &name)?;
                    continue;
                }
            }
            _ => {}
        }

        if !self_closing {
            depth += 1;
        }
    }

    if let Some(case) = open_case {
        let _ = depth_of_open_case;
        return Err(refuse(format!(
            "the report ends with <testcase name=\"{}\"> still open",
            case.name
        )));
    }
    if depth != 0 {
        return Err(refuse("the report ends with elements still open"));
    }
    if out.is_empty() {
        return Err(refuse("the report names no test cases at all"));
    }
    Ok(out)
}

/// The names of every case that passed.
pub fn passed_names(cases: &[TestCase]) -> BTreeSet<String> {
    cases
        .iter()
        .filter(|c| c.passed)
        .map(|c| c.name.clone())
        .collect()
}

fn starts_with(chars: &[char], at: usize, text: &str) -> bool {
    text.chars()
        .enumerate()
        .all(|(offset, c)| chars.get(at + offset) == Some(&c))
}

fn find(chars: &[char], from: usize, text: &str) -> Option<usize> {
    (from..chars.len()).find(|&i| starts_with(chars, i, text))
}

/// Past the matching close tag of an element that is already open, counting nesting.
fn skip_element(chars: &[char], from: usize, name: &str) -> Result<usize, Unreadable> {
    let open = format!("<{name}");
    let close = format!("</{name}");
    let mut depth = 1usize;
    let mut i = from;
    while i < chars.len() {
        if starts_with(chars, i, "<!--") {
            i = find(chars, i, "-->").ok_or_else(|| refuse("a comment is never closed"))? + 3;
            continue;
        }
        if starts_with(chars, i, "<![CDATA[") {
            i = find(chars, i, "]]>").ok_or_else(|| refuse("a CDATA section is never closed"))? + 3;
            continue;
        }
        if starts_with(chars, i, &close) {
            depth -= 1;
            let end = find(chars, i, ">").ok_or_else(|| refuse("a tag is never closed"))?;
            i = end + 1;
            if depth == 0 {
                return Ok(i);
            }
            continue;
        }
        if starts_with(chars, i, &open) {
            let end = find(chars, i, ">").ok_or_else(|| refuse("a tag is never closed"))?;
            let raw: String = chars[i + 1..end].iter().collect();
            if !raw.trim_end().ends_with('/') {
                depth += 1;
            }
            i = end + 1;
            continue;
        }
        i += 1;
    }
    Err(refuse(format!("<{name}> is never closed")))
}

/// `name="value"` pairs, with the five XML entities put back.
///
/// Refuses an unquoted value and an entity it does not know, rather than guessing: a mangled test
/// name silently fails to match the test it came from, which reads as that test not existing.
fn attributes(body: &str) -> Result<Vec<(String, String)>, Unreadable> {
    let chars: Vec<char> = body.chars().collect();
    let mut out = Vec::new();
    // Past the element name.
    let mut i = 0;
    while i < chars.len() && !chars[i].is_whitespace() {
        i += 1;
    }
    while i < chars.len() {
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        let key_start = i;
        while i < chars.len() && chars[i] != '=' && !chars[i].is_whitespace() {
            i += 1;
        }
        let key: String = chars[key_start..i].iter().collect();
        if key.is_empty() {
            break;
        }
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() || chars[i] != '=' {
            return Err(refuse(format!("the attribute `{key}` has no value")));
        }
        i += 1;
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        let quote = *chars
            .get(i)
            .ok_or_else(|| refuse(format!("the attribute `{key}` ends the tag")))?;
        if quote != '"' && quote != '\'' {
            return Err(refuse(format!("the attribute `{key}` is not quoted")));
        }
        i += 1;
        let value_start = i;
        while i < chars.len() && chars[i] != quote {
            i += 1;
        }
        if i >= chars.len() {
            return Err(refuse(format!("the attribute `{key}` is never closed")));
        }
        let raw: String = chars[value_start..i].iter().collect();
        i += 1;
        out.push((key, unescape(&raw)?));
    }
    Ok(out)
}

fn unescape(text: &str) -> Result<String, Unreadable> {
    let mut out = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '&' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let end = (i..chars.len())
            .take(12)
            .find(|&j| chars[j] == ';')
            .ok_or_else(|| refuse("an entity in an attribute is never closed"))?;
        let entity: String = chars[i + 1..end].iter().collect();
        let replacement = match entity.as_str() {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            other => {
                let code = other
                    .strip_prefix("#x")
                    .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                    .or_else(|| other.strip_prefix('#').and_then(|d| d.parse().ok()))
                    .ok_or_else(|| {
                        refuse(format!(
                            "the entity `&{other};` is not one this reader knows"
                        ))
                    })?;
                char::from_u32(code)
                    .ok_or_else(|| refuse(format!("the entity `&{other};` is not a character")))?
            }
        };
        out.push(replacement);
        i = end + 1;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shapes_the_real_runners_write() {
        // pytest --junitxml, jest-junit, surefire and gotestsum all land in this family. A failure
        // is a child element, not an attribute, which is the whole reason this is not a regex.
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<testsuites>
  <testsuite name="pytest" tests="4" failures="1" skipped="1">
    <testcase classname="tests.test_search" name="test_V1_2_4_search_is_bound" time="0.01"/>
    <testcase classname="tests.test_search" name="test_the_homepage_renders" time="0.01">
      <failure message="assert 1 == 2">Traceback...</failure>
    </testcase>
    <testcase classname="tests.test_auth" name="test_V13_3_1_no_literal_secret" time="0.02"></testcase>
    <testcase classname="tests.test_slow" name="test_skipped_one">
      <skipped message="needs a database"/>
    </testcase>
  </testsuite>
</testsuites>"#;
        let cases = parse(xml).expect("this is the ordinary shape");
        assert_eq!(cases.len(), 4);
        assert!(cases[0].passed);
        assert!(!cases[1].passed, "a <failure> child means it failed");
        assert!(cases[2].passed, "an empty element pair is a pass");
        assert!(
            !cases[3].passed,
            "a skipped test did not run, so it is not evidence"
        );
        assert_eq!(
            passed_names(&cases),
            [
                "test_V1_2_4_search_is_bound",
                "test_V13_3_1_no_literal_secret"
            ]
            .iter()
            .map(|s| s.to_string())
            .collect()
        );
    }

    #[test]
    fn content_that_could_be_mistaken_for_markup_is_skipped_whole() {
        // The case that breaks a naive reader: captured output holding what looks like a tag, and
        // a CDATA section holding one. Reading either as markup invents or hides a result.
        let xml = r#"<testsuite>
  <testcase classname="c" name="test_one">
    <system-out>&lt;failure&gt; printed by the app, and a real one: <failure/></system-out>
  </testcase>
  <testcase classname="c" name="test_two">
    <failure message="no"><![CDATA[ </testcase><testcase name="invented"/> ]]></failure>
  </testcase>
</testsuite>"#;
        let cases = parse(xml).expect("both are legal");
        assert_eq!(cases.len(), 2, "CDATA must not invent a case: {cases:?}");
        assert!(
            cases[0].passed,
            "a <failure> inside system-out is not a result"
        );
        assert!(!cases[1].passed);
    }

    #[test]
    fn attribute_entities_are_put_back() {
        let xml = r#"<testsuite><testcase classname="c" name="test_&lt;a&gt;_&amp;_&quot;b&quot;"/></testsuite>"#;
        let cases = parse(xml).unwrap();
        assert_eq!(cases[0].name, r#"test_<a>_&_"b""#);
    }

    #[test]
    fn anything_it_does_not_understand_refuses_the_whole_report() {
        // The design, in one test. Every one of these would otherwise return a shorter list that
        // looks exactly like a smaller test suite, and credit would be handed out on the strength
        // of it. A refusal falls back to the exit code, which claims nothing.
        for (xml, expect) in [
            (r#"<testsuite><testcase name="a"><failure>"#, "never closed"),
            (r#"<testsuite><testcase name="a"/>"#, "still open"),
            (
                r#"<testsuite><banana/><testcase name="a"/></testsuite>"#,
                "does not understand",
            ),
            (
                r#"<testsuite><testcase classname="c"/></testsuite>"#,
                "no name",
            ),
            (
                r#"<testsuite><testcase name=a /></testsuite>"#,
                "not quoted",
            ),
            (
                r#"<testsuite><testcase name="a&nbsp;b"/></testsuite>"#,
                "not one this reader knows",
            ),
            (r#"<testsuite></testsuite>"#, "names no test cases"),
            (
                r#"<testsuite><failure/><testcase name="a"/></testsuite>"#,
                "outside any <testcase>",
            ),
            (
                r#"<testsuite><testcase name="a"><testcase name="b"/></testcase></testsuite>"#,
                "inside another",
            ),
            (r#"<testsuite><!-- unterminated"#, "comment is never closed"),
        ] {
            let refusal = parse(xml).expect_err(&format!("should refuse: {xml}"));
            assert!(
                refusal.why.contains(expect),
                "wrong reason for {xml}: {}",
                refusal.why
            );
        }
    }

    #[test]
    fn a_report_from_a_runner_that_nests_suites() {
        // surefire and gotestsum both nest. Depth is counted, so the close tags have to line up.
        let xml = r#"<testsuites>
  <testsuite name="outer">
    <testsuite name="inner">
      <testcase classname="c" name="test_deep"/>
    </testsuite>
    <testcase classname="c" name="test_shallow"><error message="boom"/></testcase>
  </testsuite>
</testsuites>"#;
        let cases = parse(xml).unwrap();
        assert_eq!(cases.len(), 2);
        assert!(cases[0].passed);
        assert!(!cases[1].passed, "an <error> is a failure too");
    }
}
