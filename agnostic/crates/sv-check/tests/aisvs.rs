//! Semgrep's rules about applications that call a model, read for AISVS.
//!
//! These rules can show an AISVS control missing and cannot show it present: finding no user input
//! in a system prompt is not an enforced instruction hierarchy. So the map names each AISVS
//! requirement in `findings_against`, carried by a finding and never credited by a clean run, and
//! these tests hold both halves against a real run (`fixtures/semgrep-aisvs`).

use std::collections::BTreeMap;
use std::path::PathBuf;
use sv_check::adapters::{self, Adapter, Adapters};

fn adapters() -> Adapters {
    Adapters::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json"))
        .expect("the adapter file loads")
}

fn semgrep(all: &Adapters) -> &Adapter {
    all.all().iter().find(|a| a.id == "semgrep").unwrap()
}

fn real_run() -> Vec<sv_check::Finding> {
    let sarif = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/semgrep-aisvs/semgrep-1.178.0.sarif"),
    )
    .unwrap();
    let all = adapters();
    adapters::parse_sarif(semgrep(&all), &sarif).expect("the real report parses")
}

fn is_aisvs(id: &str) -> bool {
    id.starts_with('C') && id[1..].starts_with(|c: char| c.is_ascii_digit())
}

#[test]
fn each_ai_finding_lands_on_the_aisvs_requirement_it_is_about() {
    // Rule, by the last part of its id, and line in `assistant.py` or `.js` → what it carries.
    let findings = real_run();
    let mut seen: BTreeMap<(String, usize), Vec<String>> = BTreeMap::new();
    for f in &findings {
        assert!(f.location.file.starts_with("app/assistant."), "{f:?}");
        let short = f.rule_id.rsplit('.').next().unwrap().to_owned();
        seen.insert((short, f.location.line), f.requirement_ids.clone());
    }
    let expect = |rule: &str, line: usize, ids: &[&str]| {
        let got = seen
            .get(&(rule.to_owned(), line))
            .unwrap_or_else(|| panic!("{rule} at line {line} was not in the run: {seen:?}"));
        assert_eq!(
            got,
            &ids.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
            "{rule}"
        );
    };
    expect("openai-user-input-in-system-prompt-python", 21, &["C2.1.6"]);
    expect("openai-missing-max-tokens-python", 18, &["C7.1.2"]);
    expect("openai-missing-moderation", 18, &["C2.2.1"]);
    expect("openai-missing-moderation", 30, &["C2.2.1"]);
    expect("agent-unbounded-loop-python", 30, &["C9.1.2"]);
    // Already mapped to ASVS for running code; the AISVS requirement is carried beside it.
    expect("langchain-dangerous-exec-python", 38, &["V1.3.2", "C9.3.1"]);
    expect("mcp-credential-in-response-python", 43, &["C9.5.4"]);
    expect("mcp-unsanitized-return-python", 49, &["C10.4.2"]);
    // The JavaScript rules, which are separate rules and not the Python ones read twice.
    expect("openai-user-input-in-system-prompt-js", 17, &["C2.1.6"]);
    expect("anthropic-missing-max-tokens-javascript", 25, &["C7.1.2"]);
    expect("anthropic-user-input-in-system-prompt-js", 27, &["C2.1.6"]);
    expect("cohere-safety-mode-off-javascript", 34, &["C7.3.1"]);
    assert_eq!(findings.len(), 12);
}

#[test]
fn a_clean_run_of_every_ai_rule_credits_no_aisvs_requirement() {
    // Every rule in the map counted as loaded, over an app in every language: the widest clean run
    // there could be. Not one AISVS requirement may come out of it.
    let all = adapters();
    let semgrep = semgrep(&all);
    let loaded = semgrep.rules.keys().cloned().collect();
    let languages: Vec<String> = ["python", "javascript", "typescript", "go", "java", "ruby"]
        .iter()
        .map(|l| (*l).to_owned())
        .collect();
    let evidence = adapters::clean_run_evidence(semgrep, &loaded, &languages);
    let aisvs: Vec<&String> = evidence.iter().filter(|id| is_aisvs(id)).collect();
    assert!(aisvs.is_empty(), "{aisvs:?}");
    // And the ASVS half is still credited, so the line above is not passing on an empty list.
    assert!(evidence.iter().any(|id| id == "V1.3.2"), "{evidence:?}");
}

#[test]
fn every_aisvs_citation_is_one_a_finding_carries_and_a_clean_run_does_not() {
    // AISVS appears only in `findings_against`, and every rule with one has a `what` for the
    // citation guard to read it against.
    let all = adapters();
    let semgrep = semgrep(&all);
    let mut against = 0;
    for (id, rule) in &semgrep.rules {
        assert!(
            !rule.requirements.iter().any(|r| is_aisvs(r)),
            "{id} credits an AISVS requirement on a clean run: {:?}",
            rule.requirements
        );
        if rule.findings_against.iter().any(|r| is_aisvs(r)) {
            against += 1;
            assert!(id.starts_with("ai."), "{id}");
            assert!(!rule.what.is_empty(), "{id}");
        }
    }
    assert_eq!(
        against, 24,
        "the families in tools/semgrep_rule_map.py's AISVS table"
    );
}

#[test]
fn the_careful_version_raises_nothing() {
    // The same calls with moderation checked, max_tokens set, and user input in the user message.
    assert!(
        !real_run()
            .iter()
            .any(|f| f.location.file == "app/careful.py"),
    );
}

#[test]
fn a_requirement_both_credited_and_only_ever_a_finding_is_refused() {
    let dir = std::env::temp_dir().join("sv-aisvs-both");
    std::fs::create_dir_all(&dir).unwrap();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json");
    let mut file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let rule = file["adapters"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|a| a["id"] == "semgrep")
        .unwrap()["rules"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .find(|r| r["requirements"].as_array().is_some_and(|a| !a.is_empty()))
        .unwrap();
    rule["findings_against"] = rule["requirements"].clone();
    let doctored = dir.join("adapters.json");
    std::fs::write(&doctored, file.to_string()).unwrap();
    let loaded = Adapters::load(&doctored);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        loaded
            .unwrap_err()
            .to_string()
            .contains("only ever a finding")
    );
}

#[test]
fn the_asvs_requirements_only_a_finding_can_speak_to_are_carried_and_never_credited() {
    // From the Level 1 pass: text written into a page as HTML against V3.2.2 (a safe rendering
    // function), and C# token validation with expiry turned off against V9.2.1.
    let all = adapters();
    let semgrep = semgrep(&all);
    let against = |requirement: &str| -> Vec<&str> {
        semgrep
            .rules
            .iter()
            .filter(|(_, r)| r.findings_against.iter().any(|q| q == requirement))
            .map(|(id, _)| id.rsplit('.').next().unwrap())
            .collect()
    };
    assert_eq!(
        against("V3.2.2"),
        [
            "insecure-document-method",
            "insecure-document-method",
            "insecure-innerhtml",
            "avoid-v-html",
            "react-dangerouslysetinnerhtml"
        ]
    );
    assert_eq!(
        against("V9.2.1"),
        ["jwt-tokenvalidationparameters-no-expiry-validation"]
    );
    assert_eq!(against("V4.4.1"), ["detect-insecure-websocket"]);
    let loaded = semgrep.rules.keys().cloned().collect();
    let languages: Vec<String> = ["javascript", "typescript", "csharp", "html"]
        .iter()
        .map(|l| (*l).to_owned())
        .collect();
    let evidence = adapters::clean_run_evidence(semgrep, &loaded, &languages);
    assert!(
        !evidence
            .iter()
            .any(|id| id == "V3.2.2" || id == "V9.2.1" || id == "V4.4.1"),
        "{evidence:?}"
    );
    assert!(
        evidence.iter().any(|id| id == "V1.2.1"),
        "the ASVS credit beside it stays"
    );
}

#[test]
fn a_real_innerhtml_finding_carries_both_requirements() {
    // From the kept semgrep run over a Flask app and a Go program, which has no browser code; so
    // the finding is written the way semgrep writes one, with the id the map is keyed on.
    let all = adapters();
    let semgrep = semgrep(&all);
    let id = "javascript.browser.security.insecure-innerhtml.insecure-innerhtml";
    let report = serde_json::json!({"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Semgrep", "rules": [{"id": id}]}},
        "results": [{"ruleId": id, "level": "warning", "message": {"text": "innerHTML"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "static/app.js"},
                "region": {"startLine": 4}}}]}]}]});
    let findings = adapters::parse_sarif(semgrep, &report.to_string()).unwrap();
    assert_eq!(findings[0].requirement_ids, ["V1.2.1", "V3.2.2"]);
}
