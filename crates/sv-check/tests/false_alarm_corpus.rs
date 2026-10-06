//! The Semgrep false-alarm measurement of 4 October 2026 (`docs/SEMGREP-FALSE-ALARMS.md`), read back
//! against `sv`'s own rule for what is test code. Its file, `docs/semgrep-false-alarms.csv`, holds one
//! row per finding with the reader's verdict and whether the finding was in a test file; no value
//! and no code. Follow-up 2 asked that the secret rules' findings in test code be listed apart with
//! the rest: `Finding::in_test_code` decides that from the path for every rule alike, and this holds
//! it to the corpus.

use std::path::PathBuf;
use sv_check::finding::is_test_path;

struct Row {
    app: String,
    rule: String,
    file: String,
    verdict: String,
    test_file: bool,
}

/// The fields of one line of the file: comma-separated, a field in double quotes when it holds a
/// comma, and `""` for a quote inside one.
fn fields(line: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                chars.next();
                out.last_mut().unwrap().push('"');
            }
            ('"', _) => quoted = !quoted,
            (',', false) => out.push(String::new()),
            (c, _) => out.last_mut().unwrap().push(c),
        }
    }
    out
}

fn rows() -> Vec<Row> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/semgrep-false-alarms.csv");
    let text = std::fs::read_to_string(&path).expect("the measurement's file is there");
    let mut lines = text.lines();
    let header = fields(lines.next().unwrap());
    let at = |name: &str| header.iter().position(|h| h == name).unwrap();
    let (app, rule, file, verdict, test_file) = (
        at("app"),
        at("rule"),
        at("file"),
        at("verdict"),
        at("test_file"),
    );
    lines
        .map(|line| {
            let f = fields(line);
            assert_eq!(f.len(), header.len(), "{line}");
            Row {
                app: f[app].clone(),
                rule: f[rule].clone(),
                file: f[file].clone(),
                verdict: f[verdict].clone(),
                test_file: f[test_file] == "True",
            }
        })
        .collect()
}

/// Semgrep's secret rules, as the adapter's map names them.
fn secret_rule(rule: &str) -> bool {
    rule.starts_with("generic.secrets.")
}

#[test]
fn the_secret_rules_findings_in_test_code_are_listed_apart_with_the_rest() {
    let rows = rows();
    // The setup: the whole file was read, and it holds what the measurement says it does.
    assert_eq!(rows.len(), 868);
    assert_eq!(rows.iter().filter(|r| r.test_file).count(), 112);

    // Every secret-rule finding the measurement found in test code is test code to `sv`.
    let secret_in_tests: Vec<&Row> = rows
        .iter()
        .filter(|r| secret_rule(&r.rule) && r.test_file)
        .collect();
    assert_eq!(secret_in_tests.len(), 92);
    for r in &secret_in_tests {
        assert!(is_test_path(&r.file), "{} {} {}", r.app, r.rule, r.file);
    }

    // And every other one, but one: `run_tests.py`, the script that runs an example's tests, is
    // named for no test runner's convention.
    let missed: Vec<String> = rows
        .iter()
        .filter(|r| r.test_file && !is_test_path(&r.file))
        .map(|r| format!("{} {}", r.app, r.file))
        .collect();
    assert_eq!(missed, ["ex-partly-passing run_tests.py"]);

    // Listing test code apart moves no true finding, and no unsure one: the measurement's "loses no
    // true finding", held to `sv`'s rule rather than the reader's.
    let moved: Vec<String> = rows
        .iter()
        .filter(|r| r.verdict != "false" && is_test_path(&r.file))
        .map(|r| format!("{} {} {}", r.app, r.rule, r.file))
        .collect();
    assert!(moved.is_empty(), "{moved:?}");
    // The setup for that: the true findings are there to be moved.
    assert_eq!(rows.iter().filter(|r| r.verdict == "true").count(), 301);
}

#[test]
fn the_rules_only_worth_a_look_were_wrong_279_times_in_280() {
    // Semgrep follow-up 5 (the owner's decision, 6 October 2026), held to the measurement it rests
    // on: every finding of the five rules in the corpus is named by `WORTH_A_LOOK`, and their
    // verdicts are 279 false alarms and one real finding, as the owner was told.
    use sv_check::finding::WORTH_A_LOOK;
    let five = [
        "unsafe-dynamic-method",
        "detect-non-literal-regexp",
        "prohibit-jquery-html",
        "plaintext-http-link",
        "var-in-href",
    ];
    let rows = rows();
    let theirs: Vec<&Row> = rows
        .iter()
        .filter(|r| five.contains(&r.rule.rsplit('.').next().unwrap_or("")))
        .collect();
    for r in &theirs {
        assert!(
            WORTH_A_LOOK.contains(&format!("semgrep.{}", r.rule).as_str()),
            "{} is not named, as `sv` names it",
            r.rule
        );
    }
    let verdict = |v: &str| theirs.iter().filter(|r| r.verdict == v).count();
    assert_eq!(
        (verdict("false"), verdict("true"), verdict("unsure")),
        (279, 1, 0)
    );
    // The control: no other rule in the corpus is named.
    assert!(
        rows.iter()
            .filter(|r| !five.contains(&r.rule.rsplit('.').next().unwrap_or("")))
            .all(|r| !WORTH_A_LOOK.contains(&format!("semgrep.{}", r.rule).as_str()))
    );
    // And each named rule is one the Semgrep adapter maps, so a misspelled entry fails here.
    let adapters: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let semgrep = adapters["adapters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == "semgrep")
        .unwrap();
    for id in WORTH_A_LOOK {
        let rule = id.strip_prefix("semgrep.").unwrap();
        assert!(semgrep["rules"].get(rule).is_some(), "{id} is not mapped");
    }
    // Every rule of one of the five names the adapter maps is named, in each language it comes in.
    for rule in semgrep["rules"].as_object().unwrap().keys() {
        if five.contains(&rule.rsplit('.').next().unwrap_or("")) {
            assert!(
                WORTH_A_LOOK.contains(&format!("semgrep.{rule}").as_str()),
                "{rule} is mapped and not named"
            );
        }
    }
}
