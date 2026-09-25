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
        Outcome::Ran { findings } => {
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
        Outcome::Ran { findings } => {
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
