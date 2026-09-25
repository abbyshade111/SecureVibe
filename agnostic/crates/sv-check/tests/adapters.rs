//! What the adapters must never do.
//!
//! These tools are the only part of `sv` whose results come from somebody else's code, and they are
//! the only part that can be absent. Both are ways of arriving at a report that looks like a clean
//! scan and is not one.

use std::path::PathBuf;
use sv_check::adapters::{self, Adapters, Outcome};

fn data() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json")
}

fn adapters() -> Adapters {
    Adapters::load(&data()).expect("the adapter file loads")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-adapters-{name}"));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_tool_that_is_not_installed_is_not_run_rather_than_clean() {
    // The reason this is a data file with a gap attached rather than a shell script. A script that
    // skips a missing binary produces a report identical to one where the tool ran and found
    // nothing, and the second is the one everybody assumes.
    let dir = scratch("absent");
    let file = std::fs::read_to_string(data()).unwrap();
    let doctored = file.replace(
        "\"command\": \"bandit\"",
        "\"command\": \"sv-no-such-tool-9f2a\"",
    );
    let path = dir.join("adapters.json");
    std::fs::write(&path, doctored).unwrap();
    let adapters = Adapters::load(&path).expect("still valid");
    let bandit = adapters
        .all()
        .iter()
        .find(|a| a.id == "bandit")
        .expect("bandit is listed");

    let outcome = adapters::run_one(bandit, &dir, &dir.join("out.sarif"));
    std::fs::remove_dir_all(&dir).ok();

    match outcome {
        Outcome::NotRun { why } => {
            assert!(
                why.contains("not installed"),
                "it must say the tool is missing: {why}"
            );
            assert!(
                why.contains("pip install bandit"),
                "and how to get it: {why}"
            );
        }
        Outcome::Ran { findings, .. } => {
            panic!("a missing tool reported as having run, with {findings:?}")
        }
    }
}

#[test]
fn a_tool_that_writes_no_report_is_not_run_either() {
    // Second witness, of a different shape: the binary is there and does nothing useful. `true`
    // exists on every machine this runs on, exits zero, and writes no report — which is exactly the
    // shape of brakeman meeting a Ruby app that is not Rails. A zero exit is not a result.
    let dir = scratch("silent");
    let file = std::fs::read_to_string(data()).unwrap();
    let doctored = file
        .replace("\"command\": \"bandit\"", "\"command\": \"true\"")
        .replace("\"command\": \"gosec\"", "\"command\": \"true\"");
    let path = dir.join("adapters.json");
    std::fs::write(&path, doctored).unwrap();
    let adapters = Adapters::load(&path).unwrap();
    let bandit = adapters.all().iter().find(|a| a.id == "bandit").unwrap();

    let outcome = adapters::run_one(bandit, &dir, &dir.join("out.sarif"));
    std::fs::remove_dir_all(&dir).ok();

    match outcome {
        Outcome::NotRun { why } => assert!(
            why.contains("no report"),
            "the reason must say the report is missing: {why}"
        ),
        Outcome::Ran { findings, .. } => {
            panic!("a tool that wrote nothing reported as having run, with {findings:?}")
        }
    }
}

#[test]
fn a_rule_the_map_does_not_name_carries_no_requirement() {
    // Crediting every requirement a tool knows about to every one of its findings would make one
    // bandit hit look like evidence about injection, secrets and weak hashing at once.
    let adapters = adapters();
    let bandit = adapters.all().iter().find(|a| a.id == "bandit").unwrap();
    let report = sarif(
        "Bandit",
        &[("B608", "error", "Possible SQL injection", "app.py", 12)],
    );
    let mapped = adapters::parse_sarif(bandit, &report).unwrap();
    // V1.2.4 is parameterized database queries. This test asserted V1.2.1 — output encoding for an
    // HTTP response — for as long as the map said so, which is how a wrong citation survives: the
    // test is written from the map rather than from the requirement.
    assert_eq!(mapped[0].requirement_ids, vec!["V1.2.4".to_owned()]);

    let report = sarif("Bandit", &[("B999", "error", "Something new", "app.py", 3)]);
    let unmapped = adapters::parse_sarif(bandit, &report).unwrap();
    assert!(
        unmapped[0].requirement_ids.is_empty(),
        "an unmapped rule must claim nothing: {:?}",
        unmapped[0].requirement_ids
    );
    // It still has to be reported. A finding nobody has mapped is still a finding.
    assert_eq!(unmapped.len(), 1);
    assert!(unmapped[0].rule_id.contains("B999"));
}

#[test]
fn the_findings_carry_where_they_came_from() {
    // A reader has to be able to tell `sv`'s own rules from somebody else's, because they are worth
    // different amounts and are fixed by reading different documentation.
    let adapters = adapters();
    let bandit = adapters.all().iter().find(|a| a.id == "bandit").unwrap();
    let report = sarif(
        "Bandit",
        &[("B608", "error", "Possible SQL injection", "src/db.py", 42)],
    );
    let findings = adapters::parse_sarif(bandit, &report).unwrap();
    let f = &findings[0];
    assert_eq!(f.rule_id, "bandit.B608");
    assert_eq!(f.location.file, "src/db.py");
    assert_eq!(f.location.line, 42);
    assert!(f.impact.contains("Bandit"), "{}", f.impact);
    assert_eq!(
        f.confidence,
        sv_check::Confidence::Medium,
        "somebody else's rule fired; `sv` did not judge it right"
    );
}

#[test]
fn an_adapter_naming_something_other_than_a_program_is_refused_at_load() {
    // The commands come from this repository rather than from the app, so this is not the last line
    // of defence. A security tool that can be made to run something else by an edit to a data file
    // would still be a poor advertisement.
    let dir = scratch("injection");
    for bad in [
        "bandit; rm -rf /",
        "../../../bin/sh",
        "bandit && curl example.test",
        "bandit $(whoami)",
    ] {
        let file = std::fs::read_to_string(data()).unwrap();
        let doctored = file.replace(
            "\"command\": \"bandit\"",
            &format!("\"command\": \"{bad}\""),
        );
        let path = dir.join("adapters.json");
        std::fs::write(&path, doctored).unwrap();
        assert!(
            Adapters::load(&path).is_err(),
            "loading accepted a command of {bad:?}"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn an_unknown_placeholder_is_refused_rather_than_passed_through() {
    // `{dir}` and `{output}` are the two this code fills. Anything else would reach the tool as a
    // literal brace, which is a silently wrong argument rather than an error.
    let dir = scratch("placeholder");
    let file = std::fs::read_to_string(data()).unwrap();
    // Targets the placeholder itself rather than its neighbours: the JSON has been reformatted
    // once already, and a test that matches on surrounding whitespace stops doctoring anything
    // while still passing.
    let doctored = file.replace("\"{dir}\"", "\"{app_folder}\"");
    assert_ne!(doctored, file, "the doctoring matched nothing");
    let path = dir.join("adapters.json");
    std::fs::write(&path, doctored).unwrap();
    let err = Adapters::load(&path).unwrap_err().to_string();
    std::fs::remove_dir_all(&dir).ok();
    assert!(err.contains("{app_folder}"), "{err}");
}

#[test]
fn every_adapter_names_a_language_and_a_way_to_install_it() {
    for adapter in adapters().all() {
        assert!(
            !adapter.install.is_empty(),
            "{} has no install line",
            adapter.id
        );
        assert!(
            !adapter.language.is_empty(),
            "{} names no language",
            adapter.id
        );
        assert!(
            adapter.run.args.iter().any(|a| a.contains("{output}")),
            "{} never asks for a report file, so nothing could be read back",
            adapter.id
        );
        assert!(
            adapter
                .run
                .args
                .iter()
                .any(|a| a.contains("sarif") || a.contains("{output}")),
            "{} is not asked for SARIF",
            adapter.id
        );
    }
}

#[test]
fn every_requirement_an_adapter_maps_to_is_one_that_exists() {
    // The same guard the reports put on `sv`'s own checks, applied to the mapping table. A tool's
    // rule pointing at a requirement that does not exist does nothing, silently.
    let frameworks = sv_frameworks::Frameworks::load(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../data/frameworks"),
    )
    .expect("the OWASP data loads");
    let adapters = adapters();
    let mut unknown = Vec::new();
    let mut mapped = 0;
    for adapter in adapters.all() {
        for (rule, mapped_rule) in &adapter.rules {
            for id in &mapped_rule.requirements {
                mapped += 1;
                if !frameworks.requirements.contains_key(id) {
                    unknown.push(format!("{}:{rule} -> {id}", adapter.id));
                }
            }
        }
    }
    assert!(
        mapped > 20,
        "the table is too small to be checking anything"
    );
    assert!(
        unknown.is_empty(),
        "adapter rules point at requirements that are in no loaded framework: {unknown:?}"
    );
}

#[test]
fn a_tool_that_reaches_the_network_says_so() {
    // `sv` itself opens no connection. One of these does, the first time it runs, and somebody who
    // chose this tool for an air-gapped review should not find that out from a firewall log.
    let adapters = adapters();
    let semgrep = adapters.all().iter().find(|a| a.id == "semgrep");
    if let Some(semgrep) = semgrep {
        assert!(semgrep.network, "semgrep fetches its rules and must say so");
        assert!(
            semgrep.note.contains("network"),
            "and the note must explain it: {}",
            semgrep.note
        );
    }
    for adapter in adapters.all().iter().filter(|a| !a.network) {
        assert!(
            !adapter.run.args.iter().any(|a| a.starts_with("http")),
            "{} does not declare network use but names a URL",
            adapter.id
        );
    }
}

/// A minimal SARIF 2.1.0 document, in the shape these tools really emit.
fn sarif(tool: &str, results: &[(&str, &str, &str, &str, u64)]) -> String {
    let rules: Vec<serde_json::Value> = results
        .iter()
        .map(|(id, _, text, _, _)| {
            serde_json::json!({
                "id": id,
                "shortDescription": { "text": text },
                "fullDescription": { "text": format!("More about {id}.") }
            })
        })
        .collect();
    let items: Vec<serde_json::Value> = results
        .iter()
        .map(|(id, level, text, file, line)| {
            serde_json::json!({
                "ruleId": id,
                "level": level,
                "message": { "text": text },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": file },
                        "region": { "startLine": line }
                    }
                }]
            })
        })
        .collect();
    serde_json::json!({
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": tool, "rules": rules } },
            "results": items
        }]
    })
    .to_string()
}

#[test]
fn a_tool_that_is_there_and_will_not_start_is_told_apart_from_a_missing_one() {
    // Found by running this rather than by reasoning about it: semgrep is installed on the machine
    // that wrote this and cannot start under the sandbox, and the first version reported it as
    // missing and told the owner to install a tool they already had. `false` is on every machine
    // this runs on and exits non-zero, which is the same shape.
    let dir = scratch("broken");
    let file = std::fs::read_to_string(data()).unwrap();
    let doctored = file.replace("\"command\": \"bandit\"", "\"command\": \"false\"");
    let path = dir.join("adapters.json");
    std::fs::write(&path, doctored).unwrap();
    let adapters = Adapters::load(&path).unwrap();
    let bandit = adapters.all().iter().find(|a| a.id == "bandit").unwrap();

    assert_eq!(
        adapters::presence(bandit),
        adapters::Presence::Broken {
            detail: "it exited with an error and said nothing".to_owned()
        }
    );
    let outcome = adapters::run_one(bandit, &dir, &dir.join("out.sarif"));
    std::fs::remove_dir_all(&dir).ok();
    match outcome {
        Outcome::NotRun { why } => {
            assert!(why.contains("would not start"), "{why}");
            assert!(
                !why.contains("pip install"),
                "telling somebody to install a tool they have is worse than saying nothing: {why}"
            );
        }
        Outcome::Ran { .. } => panic!("a tool that will not start reported as having run"),
    }
}

#[test]
fn a_tool_reporting_an_absolute_path_has_it_made_relative() {
    // Tools report where they looked, which is absolute when they were given an absolute path.
    // `sv`'s own findings are relative, and a report is something an owner may send on: the layout
    // of their home directory is not part of what they meant to share.
    let adapters = adapters();
    let bandit = adapters.all().iter().find(|a| a.id == "bandit").unwrap();
    let report = sarif(
        "Bandit",
        &[(
            "B608",
            "error",
            "Possible SQL injection",
            "/Users/somebody/projects/notes/app.py",
            12,
        )],
    );
    let findings = adapters::parse_sarif_relative_to(
        bandit,
        &report,
        std::path::Path::new("/Users/somebody/projects/notes"),
    )
    .unwrap();
    assert_eq!(findings[0].location.file, "app.py");
    assert!(
        !findings[0].location.file.contains("somebody"),
        "the owner's directory layout must not survive into the report"
    );
}

#[test]
fn a_path_that_is_not_under_the_app_folder_is_left_alone() {
    // Second witness of a different shape: stripping a prefix that is not there must not mangle the
    // path. A tool that reports a file outside the folder is telling us something, and a truncated
    // path would be worse than a long one.
    let adapters = adapters();
    let bandit = adapters.all().iter().find(|a| a.id == "bandit").unwrap();
    let report = sarif("Bandit", &[("B608", "error", "x", "/elsewhere/lib.py", 1)]);
    let findings = adapters::parse_sarif_relative_to(
        bandit,
        &report,
        std::path::Path::new("/Users/somebody/notes"),
    )
    .unwrap();
    assert_eq!(findings[0].location.file, "/elsewhere/lib.py");
}

// ---- Brakeman, against its own output ----

/// A real SARIF report from Brakeman 8.0.6, run over `tests/fixtures/brakeman/app` — a small Rails
/// app with one of each kind of fault in it — and kept beside the app, so what is checked here is what
/// the tool really writes rather than what its documentation was read to say.
fn brakeman_real_run() -> Vec<sv_check::Finding> {
    let sarif = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/brakeman/brakeman-8.0.6.sarif"),
    )
    .unwrap();
    let adapters = adapters();
    let brakeman = adapters
        .all()
        .iter()
        .find(|a| a.id == "brakeman")
        .expect("brakeman is listed");
    adapters::parse_sarif(brakeman, &sarif).expect("the real report parses")
}

#[test]
fn every_rule_brakeman_really_reported_is_mapped() {
    // The mapping was written from documented warning codes and never seen in a real run, and it
    // was mostly wrong. An unmapped id is not wrong, only uninformative — but every id in a real run
    // over faults that all have a requirement should land on one.
    let findings = brakeman_real_run();
    assert!(findings.len() >= 15, "only {} findings", findings.len());
    let unmapped: Vec<&str> = findings
        .iter()
        .filter(|f| f.requirement_ids.is_empty())
        .map(|f| f.rule_id.as_str())
        .collect();
    assert!(unmapped.is_empty(), "reported and not mapped: {unmapped:?}");
}

#[test]
fn each_brakeman_finding_lands_on_the_requirement_it_is_about() {
    // Each of these was a line of the fixture written to produce exactly that fault. The first three
    // were each mapped to the wrong requirement until the real run: 0002 as SQL, 0013 as OS command
    // injection, 0016 as SQL.
    let findings = brakeman_real_run();
    let first = |rule: &str| {
        findings
            .iter()
            .find(|f| f.rule_id == format!("brakeman.{rule}"))
            .unwrap_or_else(|| panic!("{rule} is in the real run"))
    };
    for (rule, requirement) in [
        ("BRAKE0002", "V1.2.1"),
        ("BRAKE0013", "V1.3.2"),
        ("BRAKE0016", "V5.3.2"),
        ("BRAKE0000", "V1.2.4"),
        ("BRAKE0014", "V1.2.5"),
        ("BRAKE0025", "V1.5.2"),
        ("BRAKE0070", "V15.3.3"),
        ("BRAKE0071", "V12.3.2"),
        ("BRAKE0084", "V1.3.7"),
        ("BRAKE0126", "V11.3.1"),
    ] {
        let found = first(rule);
        assert_eq!(
            found.requirement_ids,
            vec![requirement.to_owned()],
            "{rule}"
        );
    }
    // And the location is where the fault was written, not somewhere near it.
    let sql = first("BRAKE0000");
    assert_eq!(sql.location.file, "app/controllers/users_controller.rb");
    assert_eq!(sql.location.line, 5, "the find_by_sql line");
}

// ---- Semgrep, against its own output ----

/// A real SARIF report from Semgrep 1.178.0, run over `tests/fixtures/semgrep/app` — a Flask app and a
/// Go program with one of each kind of fault in them. How the run was made, and why its rule ids have
/// the registry's form, is in the fixture's README.
fn semgrep_real_run() -> Vec<sv_check::Finding> {
    let sarif = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/semgrep/semgrep-1.178.0.sarif"),
    )
    .unwrap();
    let adapters = adapters();
    let semgrep = adapters
        .all()
        .iter()
        .find(|a| a.id == "semgrep")
        .expect("semgrep is listed");
    adapters::parse_sarif(semgrep, &sarif).expect("the real report parses")
}

#[test]
fn every_security_rule_semgrep_really_reported_is_mapped() {
    // Before this map, every semgrep finding carried no requirement at all. Semgrep's own
    // best-practice and correctness rules fire here too, and stay unmapped: a missing timeout is not
    // a security requirement.
    let findings = semgrep_real_run();
    assert!(findings.len() >= 30, "only {} findings", findings.len());
    let (security, other): (Vec<_>, Vec<_>) = findings
        .iter()
        .partition(|f| f.rule_id.contains(".security."));
    assert!(
        security.len() >= 25,
        "only {} security findings",
        security.len()
    );
    let unmapped: Vec<&str> = security
        .iter()
        .filter(|f| f.requirement_ids.is_empty())
        .map(|f| f.rule_id.as_str())
        .collect();
    assert!(unmapped.is_empty(), "reported and not mapped: {unmapped:?}");
    assert!(!other.is_empty(), "the fixture is meant to include some");
    for f in other {
        assert!(f.requirement_ids.is_empty(), "{} is mapped", f.rule_id);
    }
}

#[test]
fn each_semgrep_finding_lands_on_the_requirement_it_is_about() {
    // Each is a line of the fixture written to produce exactly that fault. The two tainted-SQL rules
    // are the ones semgrep itself tags with the wrong CWE (type conversion, and mass assignment), so
    // the map's two keys refused them and a reviewed override put them back.
    let findings = semgrep_real_run();
    let first = |rule: &str| {
        findings
            .iter()
            .find(|f| f.rule_id == format!("semgrep.{rule}"))
            .unwrap_or_else(|| panic!("{rule} is in the real run"))
    };
    for (rule, requirement) in [
        (
            "python.lang.security.audit.eval-detected.eval-detected",
            "V1.3.2",
        ),
        (
            "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
            "V1.2.4",
        ),
        (
            "python.flask.security.injection.tainted-sql-string.tainted-sql-string",
            "V1.2.4",
        ),
        (
            "python.django.security.injection.tainted-sql-string.tainted-sql-string",
            "V1.2.4",
        ),
        (
            "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
            "V1.2.5",
        ),
        (
            "python.lang.security.deserialization.pickle.avoid-pickle",
            "V1.5.2",
        ),
        (
            "python.flask.security.open-redirect.open-redirect",
            "V3.7.2",
        ),
        (
            "python.flask.security.injection.ssrf-requests.ssrf-requests",
            "V1.3.6",
        ),
        (
            "python.flask.security.injection.path-traversal-open.path-traversal-open",
            "V5.3.2",
        ),
        (
            "python.requests.security.disabled-cert-validation.disabled-cert-validation",
            "V12.3.2",
        ),
        (
            "python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5",
            "V11.4.1",
        ),
        (
            "go.lang.security.audit.crypto.use_of_weak_crypto.use-of-DES",
            "V11.3.2",
        ),
        (
            "go.lang.security.audit.crypto.use_of_weak_crypto.use-of-md5",
            "V11.4.1",
        ),
        (
            "go.lang.security.audit.crypto.math_random.math-random-used",
            "V11.5.1",
        ),
        (
            "go.lang.security.audit.crypto.missing-ssl-minversion.missing-ssl-minversion",
            "V12.1.1",
        ),
        (
            "go.lang.security.audit.database.string-formatted-query.string-formatted-query",
            "V1.2.4",
        ),
    ] {
        assert_eq!(
            first(rule).requirement_ids,
            vec![requirement.to_owned()],
            "{rule}"
        );
    }
    // And the location is where the fault was written.
    let eval = first("python.lang.security.audit.eval-detected.eval-detected");
    assert_eq!(eval.location.file, "app/app.py");
    assert_eq!(eval.location.line, 16, "the eval line");
}

/// The rules the kept semgrep run says it loaded, and the requirements a clean run over an app in
/// these languages would be credited with.
fn semgrep_clean_run_evidence(languages: &[&str]) -> Vec<String> {
    let sarif = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/semgrep/semgrep-1.178.0.sarif"),
    )
    .unwrap();
    let adapters = adapters();
    let semgrep = adapters.all().iter().find(|a| a.id == "semgrep").unwrap();
    let languages: Vec<String> = languages.iter().map(|l| (*l).to_owned()).collect();
    adapters::clean_run_evidence(semgrep, &adapters::loaded_rules(&sarif), &languages)
}

#[test]
fn a_clean_semgrep_run_credits_only_rules_it_ran_for_the_app_s_languages() {
    // With the map filled, crediting every mapped requirement on a clean run would have marked 39
    // requirements checked for any app at all, including zip slip, whose only rule is Go's, on an
    // app with no Go in it. The same loaded rules, read against the app's languages:
    assert_eq!(
        semgrep_clean_run_evidence(&["python"]),
        [
            "V1.2.4", "V1.2.5", "V1.3.2", "V1.3.6", "V1.5.2", "V11.4.1", "V12.3.2", "V3.7.2",
            "V5.3.2"
        ]
    );
    assert_eq!(
        semgrep_clean_run_evidence(&["go"]),
        ["V1.2.4", "V11.3.2", "V11.4.1", "V11.5.1", "V12.1.1"]
    );
}

#[test]
fn rules_that_ran_for_none_of_the_app_s_languages_credit_nothing() {
    // The kept run loaded Python and Go rules. A Ruby app it ran over has been examined by none.
    let evidence = semgrep_clean_run_evidence(&["ruby"]);
    assert!(evidence.is_empty(), "{evidence:?}");
}

#[test]
fn a_semgrep_report_that_lists_no_rules_credits_nothing() {
    // A run whose report does not say what it loaded has not shown it looked for anything.
    let adapters = adapters();
    let semgrep = adapters.all().iter().find(|a| a.id == "semgrep").unwrap();
    let evidence = adapters::clean_run_evidence(
        semgrep,
        &std::collections::BTreeSet::new(),
        &["python".to_owned()],
    );
    assert!(evidence.is_empty(), "{evidence:?}");
}

#[test]
fn a_one_language_tool_is_still_credited_with_everything_it_maps() {
    // Bandit runs every one of its checks over Python whatever its report lists, so the narrowing
    // is for the tool that covers many languages and runs a pack.
    one_language_tools_keep_their_whole_map(&["bandit"]);
}

#[test]
fn so_are_gosec_and_brakeman() {
    one_language_tools_keep_their_whole_map(&["gosec", "brakeman"]);
}

fn one_language_tools_keep_their_whole_map(ids: &[&str]) {
    let adapters = adapters();
    for id in ids {
        let tool = adapters.all().iter().find(|a| a.id == *id).unwrap();
        let evidence = adapters::clean_run_evidence(
            tool,
            &std::collections::BTreeSet::new(),
            std::slice::from_ref(&tool.language),
        );
        let mut mapped: Vec<String> = tool
            .rules
            .values()
            .flat_map(|r| r.requirements.iter().cloned())
            .collect();
        mapped.sort();
        mapped.dedup();
        assert!(!mapped.is_empty(), "{id}");
        assert_eq!(evidence, mapped, "{id}");
    }
}

// ---- a tool that was told to look away ----

#[test]
fn a_run_with_a_suppression_in_it_is_not_a_clean_run() {
    // Verified against real bandit output before this was written: `# nosec` on a line holding a
    // SQL injection makes bandit report `"results": []` and `"nosec": 1` in the same document. The
    // empty results array is indistinguishable from a file with nothing wrong in it, and crediting
    // it is the missing-tool mistake one layer in — worse, because the report says a check looked.
    let adapters = adapters();
    let bandit = adapters.all().iter().find(|a| a.id == "bandit").unwrap();
    let report = serde_json::json!({
        "runs": [{
            "tool": { "driver": { "name": "Bandit", "rules": [] } },
            "results": [],
            "properties": { "metrics": { "_totals": { "nosec": 1, "skipped_tests": 0, "loc": 3 } } }
        }]
    })
    .to_string();

    let dir = std::env::temp_dir().join("sv-suppressions-none");
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    let said = adapters::suppressions(bandit, &report, &dir);
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said[0].contains("1 line(s) marked to be skipped"),
        "{}",
        said[0]
    );

    // And a report that says nothing was skipped, over a folder with no markers, stays silent.
    let clean = serde_json::json!({
        "runs": [{
            "tool": { "driver": { "name": "Bandit", "rules": [] } },
            "results": [],
            "properties": { "metrics": { "_totals": { "nosec": 0, "skipped_tests": 0 } } }
        }]
    })
    .to_string();
    assert!(adapters::suppressions(bandit, &clean, &dir).is_empty());
}

#[test]
fn a_marker_in_the_code_counts_when_the_tool_does_not_say() {
    // gosec and semgrep could not be checked here — gosec is not installed and semgrep cannot start
    // in this sandbox — so for a report that says nothing about suppressions the markers in the
    // files are counted instead. Blunter, and blunt in the safe direction: it withholds a claim.
    let adapters = adapters();
    let gosec = adapters.all().iter().find(|a| a.id == "gosec").unwrap();
    let dir = std::env::temp_dir().join("sv-suppressions-marker");
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("main.go"),
        "cmd := exec.Command(\"sh\", \"-c\", userInput) // #nosec G204\n",
    )
    .unwrap();
    let report =
        serde_json::json!({"runs":[{"tool":{"driver":{"name":"gosec","rules":[]}},"results":[]}]})
            .to_string();
    let said = adapters::suppressions(gosec, &report, &dir);
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said[0].contains("main.go"),
        "it has to name the file: {}",
        said[0]
    );

    // Another tool's marker is not counted against this one.
    let brakeman = adapters.all().iter().find(|a| a.id == "brakeman").unwrap();
    assert!(adapters::suppressions(brakeman, &report, &dir).is_empty());
}

#[test]
fn a_suppression_stops_the_clean_run_claim_itself() {
    // The decision the whole suppression fix turns on, tested directly. It lived inside a match arm
    // and breaking it turned no test red: `suppressions()` was covered and the thing that consults
    // it was not. Both halves are asserted here, because a claim that can never be made is not a
    // guard, it is a disabled check.
    use std::collections::BTreeSet;
    let adapters = adapters();
    let bandit = adapters.all().iter().find(|a| a.id == "bandit").unwrap();
    let languages = vec!["python".to_owned()];
    let loaded = BTreeSet::new();

    let clean = adapters::clean_run_claim(bandit, &loaded, &languages, &[], &[])
        .expect("a run with nothing found and nothing suppressed may say so");
    assert!(
        clean.requirement_ids.contains(&"V1.2.4".to_owned()),
        "{:?}",
        clean.requirement_ids
    );

    assert!(
        adapters::clean_run_claim(
            bandit,
            &loaded,
            &languages,
            &[],
            &["Bandit reports 1 line(s) marked to be skipped".to_owned()],
        )
        .is_none(),
        "a run that was told to look away has not found nothing"
    );
}
