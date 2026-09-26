//! CodeQL, the one tool here that follows a value from where it enters the app to where it is used.
//!
//! It works in two steps — build a database of the code, then analyze it — so its entry in
//! `adapters.json` has a `prepare` step as well as a `run`, and a `{database}` folder that passes
//! between them. CodeQL is not installed where these run, so a stand-in plays it: a few lines of
//! Python that make the database folder on `prepare`, refuse to analyze one that is not there, and
//! write a report copied from a real CodeQL 2.27.1 run (`fixtures/codeql`, trimmed of help text).
//! What is exercised is the adapter code and the real entries' rules and arguments.
//!
//! The one test that runs the real tool is skipped when `codeql` is not on the PATH, and says so.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use sv_check::adapters::{self, Adapters};
use sv_check::finding::Severity;

fn real_adapters() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json")
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/codeql")
        .join(name)
}

fn real(id: &str) -> adapters::Adapter {
    Adapters::load(&real_adapters())
        .unwrap()
        .all()
        .iter()
        .find(|a| a.id == id)
        .unwrap()
        .clone()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-codeql-{name}"));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Plays `codeql database create` and `codeql database analyze`. The database is a folder holding
/// the source root it was made from; analyzing one that is missing, or made from somewhere else,
/// fails the way CodeQL would. The report is copied from `SV_FAKE_SARIF`, with the lines-of-code
/// metric set to `SV_FAKE_LINES` when that is given.
const FAKE: &str = r#"
import json, os, sys
args = sys.argv[1:]
if args[:2] == ["database", "create"]:
    if os.environ.get("SV_FAKE_PREPARE_FAIL"):
        sys.stderr.write("A fatal error occurred: no JavaScript code was found\n")
        sys.exit(32)
    db = args[2]
    root = args[args.index("--source-root") + 1]
    if os.environ.get("SV_FAKE_PREPARE_NOOP"):
        # Succeeds without building anything, as a tool that reuses a database it finds would.
        sys.exit(0)
    os.makedirs(db, exist_ok=True)
    open(os.path.join(db, "source-root"), "w").write(root)
    sys.exit(0)
if args[:2] == ["database", "analyze"]:
    db = args[2]
    if not os.path.exists(os.path.join(db, "source-root")):
        sys.stderr.write("A fatal error occurred: not a database\n")
        sys.exit(2)
    if open(os.path.join(db, "source-root")).read() == "/somewhere/else":
        # A database of some other code: its report is not this app's.
        os.environ["SV_FAKE_SARIF"] = os.environ.get("SV_FAKE_OTHER_SARIF", os.environ["SV_FAKE_SARIF"])
    out = args[args.index("--output") + 1]
    report = json.load(open(os.environ["SV_FAKE_SARIF"]))
    only = os.environ.get("SV_FAKE_ONLY_RULES")
    if only:
        keep = only.split(",")
        driver = report["runs"][0]["tool"]["driver"]
        driver["rules"] = [r for r in driver["rules"] if r["id"] in keep]
    lines = os.environ.get("SV_FAKE_LINES")
    if lines is not None:
        for m in report["runs"][0]["properties"]["metricResults"]:
            m["value"] = int(lines)
    json.dump(report, open(out, "w"))
    sys.exit(0)
sys.exit(1)
"#;

/// The real entry, its rules and its arguments, with `codeql` swapped for the stand-in.
fn stand_in(dir: &Path, id: &str, env: &[(&str, &str)]) -> Adapters {
    let mut file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(real_adapters()).unwrap()).unwrap();
    let mut entry = file["adapters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == id)
        .unwrap()
        .clone();
    let script = dir.join("fake.py");
    let mut prelude = String::from("import os\n");
    for (k, v) in env {
        prelude.push_str(&format!("os.environ[{k:?}] = {v:?}\n"));
    }
    std::fs::write(&script, format!("{prelude}{FAKE}")).unwrap();
    for step in ["prepare", "run"] {
        assert_eq!(entry[step]["command"], "codeql", "{id} {step}");
        let mut args = vec![serde_json::json!(script.to_string_lossy())];
        args.extend(entry[step]["args"].as_array().unwrap().iter().cloned());
        entry[step] = serde_json::json!({ "command": "python3", "args": args });
    }
    entry["version"] = serde_json::json!({ "command": "true" });
    file["adapters"] = serde_json::json!([entry]);
    let path = dir.join("adapters.json");
    std::fs::write(&path, file.to_string()).unwrap();
    Adapters::load(&path).expect("the stand-in loads")
}

fn app(dir: &Path) -> PathBuf {
    let app = dir.join("app");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(app.join("server.js"), "require('express')\n").unwrap();
    app
}

fn run(name: &str, id: &str, languages: &[&str], env: &[(&str, &str)]) -> adapters::AdapterRun {
    run_with_leftover(name, id, languages, env, false)
}

/// The same, optionally with a database left in the scratch folder by an earlier run, made from a
/// different app, where this run's will go.
fn run_with_leftover(
    name: &str,
    id: &str,
    languages: &[&str],
    env: &[(&str, &str)],
    leftover: bool,
) -> adapters::AdapterRun {
    let dir = scratch(name);
    let app = app(&dir);
    if leftover {
        let stale = dir.join(format!("sv-{id}.db"));
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::write(stale.join("source-root"), "/somewhere/else").unwrap();
    }
    let adapters = stand_in(&dir, id, env);
    let languages: Vec<String> = languages.iter().map(|l| (*l).to_owned()).collect();
    let outcome = adapters::run_all(&adapters, &app, &languages, &dir);
    // Its working state goes when it is done: a database left behind would be the next run's.
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".db"))
        .collect();
    assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
    std::fs::remove_dir_all(&dir).ok();
    outcome
}

fn sarif(name: &str) -> String {
    fixture(name).to_string_lossy().to_string()
}

#[test]
fn a_real_report_becomes_findings_with_the_rules_own_severity_and_weakness() {
    let out = run(
        "findings",
        "codeql-javascript",
        &["javascript"],
        &[("SV_FAKE_SARIF", &sarif("javascript-findings.sarif"))],
    );
    assert!(out.not_run.is_empty(), "{:?}", out.not_run);
    assert!(
        out.verified.is_empty(),
        "a run with findings credits nothing"
    );
    let xss = out
        .findings
        .iter()
        .find(|f| f.rule_id == "codeql-javascript.js/reflected-xss")
        .expect("the cross-site scripting result");
    assert_eq!(xss.location.file, "server.js");
    assert_eq!(xss.location.line, 8);
    assert_eq!(xss.requirement_ids, vec!["V1.2.1".to_owned()]);
    // CodeQL puts both on the rule, not the result: 7.8 is high, and the tag is `cwe-079`.
    assert_eq!(xss.severity, Severity::High);
    assert!(xss.cwe.contains(&"CWE-79".to_owned()), "{:?}", xss.cwe);
    let command = out
        .findings
        .iter()
        .find(|f| f.rule_id == "codeql-javascript.js/command-line-injection")
        .unwrap();
    assert_eq!(command.severity, Severity::Critical, "9.8");
    assert_eq!(command.requirement_ids, vec!["V1.2.5".to_owned()]);
    // A rule the map does not know is still shown, carrying no requirement.
    let unmapped = out
        .findings
        .iter()
        .find(|f| f.rule_id == "codeql-javascript.js/missing-rate-limiting")
        .unwrap();
    assert!(unmapped.requirement_ids.is_empty());
}

#[test]
fn the_python_entry_reads_its_own_report_the_same_way() {
    let out = run(
        "python",
        "codeql-python",
        &["python"],
        &[("SV_FAKE_SARIF", &sarif("python-findings.sarif"))],
    );
    assert!(out.not_run.is_empty(), "{:?}", out.not_run);
    let found: BTreeSet<&str> = out.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert_eq!(
        found,
        BTreeSet::from([
            "codeql-python.py/command-line-injection",
            "codeql-python.py/sql-injection",
            "codeql-python.py/url-redirection",
        ])
    );
    let sql = out
        .findings
        .iter()
        .find(|f| f.rule_id == "codeql-python.py/sql-injection")
        .unwrap();
    assert_eq!(sql.requirement_ids, vec!["V1.2.4".to_owned()]);
}

#[test]
fn a_clean_run_is_credited_only_with_the_rules_its_suite_ran() {
    let out = run(
        "clean",
        "codeql-javascript",
        &["javascript"],
        &[("SV_FAKE_SARIF", &sarif("javascript-clean.sarif"))],
    );
    assert!(out.findings.is_empty());
    assert_eq!(out.verified.len(), 1, "{:?}", out.not_run);
    let credited: BTreeSet<&str> = out.verified[0]
        .requirement_ids
        .iter()
        .map(String::as_str)
        .collect();
    for id in [
        "V1.2.1", "V1.2.4", "V1.2.9", "V15.3.5", "V15.3.6", "V16.4.1",
    ] {
        assert!(credited.contains(id), "{id} not credited: {credited:?}");
    }
    // Only ever findings: an incomplete scheme check found missing says nothing about URL
    // encoding, and no user input reaching a system prompt is not an instruction hierarchy.
    assert!(!credited.contains("V1.2.2"), "{credited:?}");
    assert!(!credited.contains("C2.1.6"), "{credited:?}");
}

#[test]
fn a_rule_the_map_knows_and_the_suite_did_not_run_is_not_credited() {
    let codeql = real("codeql-javascript");
    let loaded: BTreeSet<String> = ["js/sql-injection".to_owned()].into();
    let evidence = adapters::clean_run_evidence(&codeql, &loaded, &["javascript".to_owned()]);
    assert_eq!(evidence, vec!["V1.2.4".to_owned()]);
    let nothing =
        adapters::clean_run_evidence(&codeql, &BTreeSet::new(), &["javascript".to_owned()]);
    assert!(nothing.is_empty(), "{nothing:?}");
}

#[test]
fn a_run_that_extracted_no_code_is_not_a_clean_result() {
    let out = run(
        "no-code",
        "codeql-javascript",
        &["javascript"],
        &[
            ("SV_FAKE_SARIF", &sarif("javascript-clean.sarif")),
            ("SV_FAKE_LINES", "0"),
        ],
    );
    assert!(out.verified.is_empty(), "{:?}", out.verified);
    assert_eq!(out.not_run.len(), 1);
    assert!(
        out.not_run[0].1.contains("found no code"),
        "{:?}",
        out.not_run
    );
}

#[test]
fn a_database_that_could_not_be_built_means_it_did_not_run() {
    let out = run(
        "prepare-fails",
        "codeql-javascript",
        &["javascript"],
        &[
            ("SV_FAKE_SARIF", &sarif("javascript-clean.sarif")),
            ("SV_FAKE_PREPARE_FAIL", "1"),
        ],
    );
    assert!(out.verified.is_empty() && out.findings.is_empty());
    assert_eq!(out.not_run.len(), 1);
    let why = &out.not_run[0].1;
    assert!(
        why.contains("could not prepare") && why.contains("no JavaScript code was found"),
        "{why}"
    );
}

#[test]
fn the_javascript_entry_reads_an_app_written_only_in_typescript() {
    let out = run(
        "typescript",
        "codeql-javascript",
        &["typescript"],
        &[("SV_FAKE_SARIF", &sarif("javascript-clean.sarif"))],
    );
    assert_eq!(out.verified.len(), 1, "{:?}", out.not_run);
    let out = run(
        "go-only",
        "codeql-javascript",
        &["go"],
        &[("SV_FAKE_SARIF", &sarif("javascript-clean.sarif"))],
    );
    assert!(
        out.verified.is_empty() && out.not_run.is_empty(),
        "not asked at all for an app with none"
    );
}

#[test]
fn the_real_codeql_finds_the_same_things_when_it_is_installed() {
    let codeql = real("codeql-javascript");
    if !adapters::is_installed(&codeql) {
        println!("codeql is not installed here; the real run is skipped");
        return;
    }
    let dir = scratch("real");
    let app = dir.join("app");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(
        app.join("server.js"),
        "const express = require('express');\nconst app = express();\n\
         app.get('/hello', (req, res) => res.send('<p>Hello ' + req.query.name + '</p>'));\n\
         app.listen(8080);\n",
    )
    .unwrap();
    let adapters = Adapters::load(&real_adapters()).unwrap();
    let out = adapters::run_all(&adapters, &app, &["javascript".to_owned()], &dir);
    std::fs::remove_dir_all(&dir).ok();
    let not_run: Vec<_> = out
        .not_run
        .iter()
        .filter(|(id, _)| id.starts_with("codeql"))
        .collect();
    assert!(not_run.is_empty(), "{not_run:?}");
    assert!(
        out.findings
            .iter()
            .any(|f| f.rule_id == "codeql-javascript.js/reflected-xss"),
        "{:?}",
        out.findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn the_python_findings_carry_the_rules_severity_and_weakness_too() {
    let out = run(
        "python-severity",
        "codeql-python",
        &["python"],
        &[("SV_FAKE_SARIF", &sarif("python-findings.sarif"))],
    );
    let sql = out
        .findings
        .iter()
        .find(|f| f.rule_id == "codeql-python.py/sql-injection")
        .unwrap();
    assert_eq!(sql.severity, Severity::High, "8.8");
    // 9.8 on the rule, where the rule's default level alone would say only `error`, high.
    let command = out
        .findings
        .iter()
        .find(|f| f.rule_id == "codeql-python.py/command-line-injection")
        .unwrap();
    assert_eq!(command.severity, Severity::Critical);
    assert!(sql.cwe.contains(&"CWE-89".to_owned()), "{:?}", sql.cwe);
}

#[test]
fn a_report_listing_fewer_rules_is_credited_with_fewer_requirements() {
    let out = run(
        "fewer-rules",
        "codeql-javascript",
        &["javascript"],
        &[
            ("SV_FAKE_SARIF", &sarif("javascript-clean.sarif")),
            ("SV_FAKE_ONLY_RULES", "js/sql-injection,js/log-injection"),
        ],
    );
    assert_eq!(out.verified.len(), 1, "{:?}", out.not_run);
    let mut credited = out.verified[0].requirement_ids.clone();
    credited.sort();
    assert_eq!(credited, vec!["V1.2.4".to_owned(), "V16.4.1".to_owned()]);
}

#[test]
fn a_python_database_that_could_not_be_built_means_it_did_not_run() {
    let out = run(
        "python-prepare-fails",
        "codeql-python",
        &["python"],
        &[
            ("SV_FAKE_SARIF", &sarif("python-findings.sarif")),
            ("SV_FAKE_PREPARE_FAIL", "1"),
        ],
    );
    assert!(out.findings.is_empty(), "{:?}", out.findings);
    assert!(
        out.not_run[0].1.contains("could not prepare"),
        "{:?}",
        out.not_run
    );
}

#[test]
fn a_python_run_that_extracted_no_code_is_not_a_clean_result() {
    let out = run(
        "python-no-code",
        "codeql-python",
        &["python"],
        &[
            ("SV_FAKE_SARIF", &sarif("python-findings.sarif")),
            ("SV_FAKE_LINES", "0"),
        ],
    );
    // Findings are still findings; it is the empty report that must not read as clean. So this one
    // is checked on the reason recorded beside a clean report.
    let out_clean = run(
        "python-no-code-clean",
        "codeql-javascript",
        &["javascript"],
        &[
            ("SV_FAKE_SARIF", &sarif("javascript-clean.sarif")),
            ("SV_FAKE_LINES", "0"),
            ("SV_FAKE_ONLY_RULES", "js/sql-injection"),
        ],
    );
    assert!(!out.findings.is_empty());
    assert!(out_clean.verified.is_empty(), "{:?}", out_clean.verified);
}

/// A tool whose `prepare` succeeds and builds nothing, beside a database left by an earlier run of
/// some other code: the old one must not be what is analyzed.
fn leftover_is_not_read(id: &str, language: &str, report: &str) {
    let out = run_with_leftover(
        &format!("leftover-{id}"),
        id,
        &[language],
        &[
            ("SV_FAKE_SARIF", &sarif(report)),
            ("SV_FAKE_PREPARE_NOOP", "1"),
        ],
        true,
    );
    assert!(
        out.verified.is_empty() && out.findings.is_empty(),
        "{id}: the old database was read"
    );
    assert!(
        out.not_run[0].1.contains("wrote no report"),
        "{id}: {:?}",
        out.not_run
    );
}

#[test]
fn a_database_left_by_an_earlier_run_is_never_analyzed_in_place_of_this_one() {
    leftover_is_not_read("codeql-javascript", "javascript", "javascript-clean.sarif");
}

#[test]
fn nor_is_a_python_one() {
    leftover_is_not_read("codeql-python", "python", "python-findings.sarif");
}

#[test]
fn an_entry_reading_several_languages_is_offered_for_each_of_them() {
    let adapters = Adapters::load(&real_adapters()).unwrap();
    let ids = |langs: &[&str]| -> BTreeSet<String> {
        let langs: Vec<String> = langs.iter().map(|l| (*l).to_owned()).collect();
        adapters
            .for_languages(&langs)
            .iter()
            .map(|a| a.id.clone())
            .filter(|id| id.starts_with("codeql"))
            .collect()
    };
    assert_eq!(
        ids(&["typescript"]),
        BTreeSet::from(["codeql-javascript".to_owned()])
    );
    assert_eq!(
        ids(&["javascript"]),
        BTreeSet::from(["codeql-javascript".to_owned()])
    );
    assert_eq!(
        ids(&["python"]),
        BTreeSet::from(["codeql-python".to_owned()])
    );
    assert!(ids(&["go", "ruby"]).is_empty());
}
