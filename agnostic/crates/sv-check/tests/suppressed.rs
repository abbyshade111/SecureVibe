//! A tool that was told to look away must not be credited with having looked.
//!
//! `# nosec` on a line makes bandit report nothing about it. Before this, `sv` saw the empty list of
//! results, called the run clean, and credited V1.2.4 to an app whose `search()` joined user input
//! into SQL on exactly that line. The reports kept here are what the tools really wrote, over the
//! small apps beside them (see `fixtures/suppressed/README.md`).

use std::path::{Path, PathBuf};
use sv_check::adapters::{self, Adapters};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/suppressed")
}

fn real_adapters() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-suppressed-{name}"));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The real entry for one tool, with its rules and settings, made to "run" by copying a kept report
/// into place. `cp` is a plain program name, as the loader requires, and `true` answers the question
/// of whether the tool is here — so what is exercised is `run_all`, not a copy of its logic.
fn replaying(id: &str, report: &Path, dir: &Path) -> Adapters {
    let mut file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(real_adapters()).unwrap()).unwrap();
    let mut entry = file["adapters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == id)
        .unwrap_or_else(|| panic!("{id} is listed"))
        .clone();
    entry["version"] = serde_json::json!({ "command": "true" });
    entry["run"] = serde_json::json!({
        "command": "cp",
        "args": [report.to_string_lossy(), "{output}"]
    });
    entry.as_object_mut().unwrap().remove("working_directory");
    file["adapters"] = serde_json::json!([entry]);
    let path = dir.join("adapters.json");
    std::fs::write(&path, file.to_string()).unwrap();
    Adapters::load(&path).expect("the replaying adapter loads")
}

fn run(id: &str, language: &str, report: &Path, app: &Path) -> adapters::AdapterRun {
    // Named after the report as well, since the tests run side by side.
    let name = report.file_stem().unwrap().to_string_lossy();
    let scratch = scratch(&format!("{id}-work-{name}"));
    let adapters = replaying(id, report, &scratch);
    let outcome = adapters::run_all(&adapters, app, &[language.to_owned()], &scratch);
    std::fs::remove_dir_all(&scratch).ok();
    outcome
}

/// A bandit report that found nothing, with the two counts of what it was told to skip set as given.
fn bandit_report(nosec: u64, skipped_tests: u64, dir: &Path) -> PathBuf {
    let mut report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixtures().join("bandit-1.9.4-nosec.sarif")).unwrap(),
    )
    .unwrap();
    let totals = &mut report["runs"][0]["properties"]["metrics"]["_totals"];
    totals["nosec"] = nosec.into();
    totals["skipped_tests"] = skipped_tests.into();
    let path = dir.join(format!("bandit-{nosec}-{skipped_tests}.sarif"));
    std::fs::write(&path, report.to_string()).unwrap();
    path
}

#[test]
fn the_kept_bandit_report_really_is_empty_and_really_counts_the_skips() {
    // The setup the tests below stand on. If a newer bandit ever reports the nosec line as a result,
    // or stops counting, this says so rather than letting the others pass for the wrong reason.
    let report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixtures().join("bandit-1.9.4-nosec.sarif")).unwrap(),
    )
    .unwrap();
    let run = &report["runs"][0];
    assert_eq!(run["results"].as_array().unwrap().len(), 0);
    assert_eq!(run["properties"]["metrics"]["_totals"]["nosec"], 1);
    assert_eq!(run["properties"]["metrics"]["_totals"]["skipped_tests"], 1);
}

#[test]
fn a_clean_bandit_run_with_nothing_skipped_is_credited() {
    // The control. Without it, the two tests after this would pass just as well if a clean bandit
    // run were never credited at all.
    let dir = scratch("control");
    let outcome = run("bandit", "python", &bandit_report(0, 0, &dir), &dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(outcome.not_run.is_empty(), "{:?}", outcome.not_run);
    assert_eq!(outcome.verified.len(), 1);
    assert!(
        outcome.verified[0]
            .requirement_ids
            .contains(&"V1.2.4".to_owned())
    );
}

#[test]
fn a_line_marked_nosec_withholds_the_clean_run() {
    let dir = scratch("blanket");
    let outcome = run("bandit", "python", &bandit_report(1, 0, &dir), &dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(outcome.verified.is_empty(), "{:?}", outcome.verified);
    let (id, why) = &outcome.not_run[0];
    assert_eq!(id, "bandit");
    assert!(why.contains("1 line is marked `# nosec`"), "{why}");
    assert!(why.contains("not counted"), "{why}");
}

#[test]
fn a_check_switched_off_on_one_line_withholds_it_too() {
    // `# nosec B608` is counted apart from a bare `# nosec`, and hides just as much.
    let dir = scratch("targeted");
    let outcome = run("bandit", "python", &bandit_report(0, 2, &dir), &dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(outcome.verified.is_empty(), "{:?}", outcome.verified);
    assert!(
        outcome.not_run[0]
            .1
            .contains("2 of its checks were switched off"),
        "{:?}",
        outcome.not_run
    );
}

#[test]
fn the_real_report_is_withheld_for_both_reasons() {
    let outcome = run(
        "bandit",
        "python",
        &fixtures().join("bandit-1.9.4-nosec.sarif"),
        &fixtures().join("bandit-app"),
    );
    assert!(outcome.verified.is_empty(), "{:?}", outcome.verified);
    let why = &outcome.not_run[0].1;
    // Each reason by its own words: "`# nosec`" alone would be matched by the second as well.
    assert!(why.contains("1 line is marked `# nosec`"), "{why}");
    assert!(why.contains("1 of its checks was switched off"), "{why}");
}

#[test]
fn bandit_is_asked_to_report_what_it_was_told_to_skip() {
    // The better half of the fix: rather than only withholding credit, bandit is run so that it
    // looks anyway and says where. The kept report of that run, over the same two files, has both
    // injections in it.
    let bandit = Adapters::load(&real_adapters()).unwrap();
    let bandit = bandit.all().iter().find(|a| a.id == "bandit").unwrap();
    let args = bandit.run.args.join(" ");
    assert!(args.contains("--ignore-nosec"), "{args}");
    let findings = adapters::parse_sarif(
        bandit,
        &std::fs::read_to_string(fixtures().join("bandit-1.9.4-ignore-nosec.sarif")).unwrap(),
    )
    .unwrap();
    let files: Vec<&str> = findings
        .iter()
        .filter(|f| f.rule_id == "bandit.B608")
        .map(|f| f.location.file.as_str())
        .collect();
    assert_eq!(files, ["blanket.py", "targeted.py"]);
}

#[test]
fn an_app_s_own_bandit_settings_are_not_read() {
    // A `.bandit` file in the app can skip checks and folders, and bandit's report then says nothing
    // at all about it: not a count, not a rule list. Measured with bandit 1.9.4, which prints "Found
    // project level .bandit file" and reports an injection only when given `--ini /dev/null`.
    let bandit = Adapters::load(&real_adapters()).unwrap();
    let bandit = bandit.all().iter().find(|a| a.id == "bandit").unwrap();
    let args = &bandit.run.args;
    let at = args
        .iter()
        .position(|a| a == "--ini")
        .expect("--ini is passed");
    assert_eq!(args[at + 1], "/dev/null");
}

#[test]
fn gosec_is_asked_to_keep_what_it_was_told_to_skip() {
    // Without `-track-suppressions`, gosec 2.29.0 leaves a `#nosec` line out of its SARIF and says
    // nothing. With it, the issue is there and marked. The kept run has three marked and one not.
    let all = Adapters::load(&real_adapters()).unwrap();
    let gosec = all.all().iter().find(|a| a.id == "gosec").unwrap();
    assert!(gosec.run.args.iter().any(|a| a == "-track-suppressions"));
    let findings = adapters::parse_sarif(
        gosec,
        &std::fs::read_to_string(fixtures().join("gosec-2.29.0-tracked.sarif")).unwrap(),
    )
    .unwrap();
    let marked = findings
        .iter()
        .filter(|f| f.description.contains("marked to be ignored"))
        .count();
    assert_eq!((findings.len(), marked), (4, 3));
    let injection = findings
        .iter()
        .find(|f| f.rule_id == "gosec.G202")
        .expect("the #nosec injection is reported");
    assert!(
        injection.description.contains("by a comment on the line"),
        "{}",
        injection.description
    );
}

#[test]
fn a_semgrep_finding_hidden_by_nosemgrep_is_shown_and_says_so() {
    let all = Adapters::load(&real_adapters()).unwrap();
    let semgrep = all.all().iter().find(|a| a.id == "semgrep").unwrap();
    let findings = adapters::parse_sarif(
        semgrep,
        &std::fs::read_to_string(fixtures().join("semgrep-1.178.0-nosemgrep.sarif")).unwrap(),
    )
    .unwrap();
    assert_eq!(findings.len(), 2);
    assert!(
        findings
            .iter()
            .all(|f| f.description.contains("by a comment on the line")),
        "{findings:?}"
    );
}

#[test]
fn a_brakeman_warning_in_its_ignore_file_is_shown_and_names_the_file() {
    let all = Adapters::load(&real_adapters()).unwrap();
    let brakeman = all.all().iter().find(|a| a.id == "brakeman").unwrap();
    let findings = adapters::parse_sarif(
        brakeman,
        &std::fs::read_to_string(fixtures().join("brakeman-8.0.6-ignored.sarif")).unwrap(),
    )
    .unwrap();
    let sql = findings
        .iter()
        .find(|f| f.rule_id == "brakeman.BRAKE0000")
        .expect("the ignored injection is reported");
    assert!(
        sql.description.contains("`config/brakeman.ignore`"),
        "{}",
        sql.description
    );
    let csrf = findings
        .iter()
        .find(|f| f.rule_id == "brakeman.BRAKE0007")
        .unwrap();
    assert!(
        !csrf.description.contains("marked to be ignored"),
        "a warning nobody suppressed must not say it was: {}",
        csrf.description
    );
}

/// A Brakeman report with no warnings in it, over an app folder built for the test.
fn brakeman_clean(with_settings: bool) -> adapters::AdapterRun {
    let dir = scratch(&format!("brakeman-{with_settings}"));
    let report = dir.join(format!("clean-{with_settings}.sarif"));
    let mut sarif: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixtures().join("brakeman-8.0.6-ignored.sarif")).unwrap(),
    )
    .unwrap();
    sarif["runs"][0]["results"] = serde_json::json!([]);
    std::fs::write(&report, sarif.to_string()).unwrap();
    let app = dir.join("app");
    std::fs::create_dir_all(app.join("config")).unwrap();
    if with_settings {
        std::fs::write(
            app.join("config/brakeman.yml"),
            "---\n:skip_checks:\n- CheckSQL\n",
        )
        .unwrap();
    }
    let outcome = run("brakeman", "ruby", &report, &app);
    std::fs::remove_dir_all(&dir).ok();
    outcome
}

#[test]
fn a_clean_brakeman_run_with_no_settings_file_is_credited() {
    let outcome = brakeman_clean(false);
    assert!(outcome.not_run.is_empty(), "{:?}", outcome.not_run);
    assert_eq!(outcome.verified.len(), 1);
}

#[test]
fn brakeman_settings_that_can_skip_checks_withhold_the_clean_run() {
    // Brakeman 8.0.6 reads `config/brakeman.yml` on its own, `skip_checks` there hides an injection
    // with no trace in the report, and `--config-file /dev/null` does not stop it reading the file.
    let outcome = brakeman_clean(true);
    assert!(outcome.verified.is_empty(), "{:?}", outcome.verified);
    assert!(
        outcome.not_run[0].1.contains("`config/brakeman.yml`"),
        "{:?}",
        outcome.not_run
    );
}

#[test]
fn a_run_that_found_something_is_not_turned_into_not_run() {
    // Withholding is about crediting a clean run. A run with findings is reported as it is, and the
    // reason it looked away from other lines must not hide the findings it did make.
    let dir = scratch("findings");
    let mut report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixtures().join("bandit-1.9.4-ignore-nosec.sarif")).unwrap(),
    )
    .unwrap();
    report["runs"][0]["properties"]["metrics"]["_totals"]["nosec"] = 3.into();
    let path = dir.join("found.sarif");
    std::fs::write(&path, report.to_string()).unwrap();
    let outcome = run("bandit", "python", &path, &fixtures().join("bandit-app"));
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(outcome.findings.len(), 2);
    assert!(outcome.verified.is_empty());
    assert!(outcome.not_run.is_empty(), "{:?}", outcome.not_run);
}

#[test]
fn the_settings_file_is_named_in_what_was_looked_away_from() {
    // Second witness for the settings file, asked directly rather than through a run: present, it
    // is named; absent, nothing is said.
    let all = Adapters::load(&real_adapters()).unwrap();
    let brakeman = all.all().iter().find(|a| a.id == "brakeman").unwrap();
    let dir = scratch("settings-named");
    std::fs::create_dir_all(dir.join("config")).unwrap();
    let before = adapters::looked_away(brakeman, "{}", &dir);
    std::fs::write(dir.join("config/brakeman.yml"), "---\n").unwrap();
    let after = adapters::looked_away(brakeman, "{}", &dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(before.is_empty(), "{before:?}");
    assert_eq!(after.len(), 1);
    assert!(after[0].contains("`config/brakeman.yml`"), "{after:?}");
}

#[test]
fn each_way_of_suppressing_is_described_as_what_it_is() {
    let all = Adapters::load(&real_adapters()).unwrap();
    let semgrep = all.all().iter().find(|a| a.id == "semgrep").unwrap();
    let result = |suppressions: serde_json::Value| {
        serde_json::json!({
            "ruleId": "r",
            "level": "warning",
            "message": { "text": "Something." },
            "locations": [{ "physicalLocation": {
                "artifactLocation": { "uri": "app.py" }, "region": { "startLine": 1 } } }],
            "suppressions": suppressions
        })
    };
    let report = serde_json::json!({ "version": "2.1.0", "runs": [{
        "tool": { "driver": { "name": "Semgrep", "rules": [] } },
        "results": [
            result(serde_json::json!([{ "kind": "inSource" }])),
            result(serde_json::json!([{ "kind": "external", "location": { "physicalLocation": {
                "artifactLocation": { "uri": "security/allow.json" } } } }])),
            result(serde_json::json!([{ "kind": "external" }])),
            result(serde_json::json!([])),
        ]
    }]});
    let findings = adapters::parse_sarif(semgrep, &report.to_string()).unwrap();
    let said: Vec<&str> = findings.iter().map(|f| f.description.as_str()).collect();
    assert!(said[0].contains("by a comment on the line"), "{}", said[0]);
    assert!(said[1].contains("in `security/allow.json`"), "{}", said[1]);
    assert!(said[2].contains("outside the code"), "{}", said[2]);
    assert_eq!(said[3], "Something.", "an empty list is not a suppression");
}
