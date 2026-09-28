//! Outside-tool rules that were already running and counted for nothing, mapped on 28 September 2026
//! (see `docs/PARTIAL-CHECKS.md`). Each requirement asks for a control, so each rule can show it
//! missing and never present: a finding carries the requirement, and a clean run credits nothing.

use std::path::PathBuf;
use sv_check::adapters::{self, Adapter, Adapters};

/// Rule id, the tool that runs it, and the requirement a finding from it must carry.
const MAPPED: &[(&str, &str, &str)] = &[
    (
        "html.security.audit.missing-integrity.missing-integrity",
        "semgrep",
        "V3.6.1",
    ),
    (
        "c.lang.security.insecure-use-gets-fn.insecure-use-gets-fn",
        "semgrep",
        "V1.4.1",
    ),
    (
        "c.lang.security.insecure-use-string-copy-fn.insecure-use-string-copy-fn",
        "semgrep",
        "V1.4.1",
    ),
    (
        "c.lang.security.insecure-use-strcat-fn.insecure-use-strcat-fn",
        "semgrep",
        "V1.4.1",
    ),
    (
        "c.lang.security.use-after-free.use-after-free",
        "semgrep",
        "V1.4.3",
    ),
    (
        "c.lang.security.double-free.double-free",
        "semgrep",
        "V1.4.3",
    ),
    (
        "go.lang.security.decompression_bomb.potential-dos-via-decompression-bomb",
        "semgrep",
        "V5.2.3",
    ),
    (
        "java.lang.security.audit.crypto.gcm-nonce-reuse.gcm-nonce-reuse",
        "semgrep",
        "V11.3.4",
    ),
    (
        "php.lang.security.openssl-cbc-static-iv.openssl-cbc-static-iv",
        "semgrep",
        "V11.3.4",
    ),
    (
        "go.grpc.security.grpc-client-insecure-connection.grpc-client-insecure-connection",
        "semgrep",
        "V12.3.3",
    ),
    (
        "go.grpc.security.grpc-server-insecure-connection.grpc-server-insecure-connection",
        "semgrep",
        "V12.3.3",
    ),
    (
        "javascript.grpc.security.grpc-nodejs-insecure-connection.grpc-nodejs-insecure-connection",
        "semgrep",
        "V12.3.3",
    ),
    (
        "trailofbits.go.missing-unlock-before-return.missing-unlock-before-return",
        "semgrep",
        "V15.4.3",
    ),
    ("B306", "bandit", "V15.4.2"),
    ("G407", "gosec", "V11.3.4"),
];

fn adapters() -> Adapters {
    Adapters::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json"))
        .expect("the adapter file loads")
}

fn tool<'a>(all: &'a Adapters, id: &str) -> &'a Adapter {
    all.all().iter().find(|a| a.id == id).unwrap()
}

/// A report of one result for `rule`, written the way SARIF carries one.
fn one_finding(adapter: &Adapter, rule: &str) -> Vec<sv_check::Finding> {
    let report = serde_json::json!({"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": adapter.id, "rules": [{"id": rule}]}},
        "results": [{"ruleId": rule, "level": "warning", "message": {"text": "found"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/app.c"},
                "region": {"startLine": 3}}}]}]}]});
    adapters::parse_sarif(adapter, &report.to_string()).expect("the report parses")
}

#[test]
fn a_finding_from_each_rule_carries_its_requirement() {
    let all = adapters();
    // The control: a rule mapped before, whose finding is known to carry V1.2.4.
    let control = one_finding(tool(&all, "bandit"), "B608");
    assert_eq!(control.len(), 1);
    assert!(control[0].requirement_ids.iter().any(|q| q == "V1.2.4"));
    for (rule, tool_id, requirement) in MAPPED {
        let findings = one_finding(tool(&all, tool_id), rule);
        assert_eq!(findings.len(), 1, "{rule}");
        assert!(
            findings[0].requirement_ids.iter().any(|q| q == requirement),
            "{rule} carries {:?}, not {requirement}",
            findings[0].requirement_ids
        );
    }
}

#[test]
fn a_clean_run_credits_none_of_them() {
    let all = adapters();
    let languages: Vec<String> = [
        "c",
        "go",
        "html",
        "java",
        "javascript",
        "php",
        "python",
        "typescript",
    ]
    .iter()
    .map(|l| (*l).to_owned())
    .collect();
    let mut credited = Vec::new();
    for tool_id in ["semgrep", "bandit", "gosec"] {
        let adapter = tool(&all, tool_id);
        let loaded = adapter.rules.keys().cloned().collect();
        credited.extend(adapters::clean_run_evidence(adapter, &loaded, &languages));
    }
    // The control: the same clean runs do credit what the map says they may.
    assert!(credited.iter().any(|q| q == "V1.2.4"), "{credited:?}");
    for (rule, _, requirement) in MAPPED {
        assert!(
            !credited.iter().any(|q| q == requirement),
            "a clean run credits {requirement}, which {rule} can only ever find failing"
        );
    }
}
