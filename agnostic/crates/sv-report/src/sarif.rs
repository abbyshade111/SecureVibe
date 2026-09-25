//! Findings as SARIF 2.1.0, for editors and CI tools that read it.
//!
//! SARIF has no way to say "this was not examined", and nothing here pretends otherwise: the file
//! carries the findings and only the findings. The gaps live in the reports a person reads, and the
//! `invocation` below records that this run was partial whenever `sv` knows it was, because a tool
//! that reports zero results from a scan that never ran looks exactly like a clean one.

use crate::Report;
use serde_json::{Value, json};

pub fn render(report: &Report) -> String {
    let rules: Vec<Value> = {
        let mut seen: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
        seen.sort_unstable();
        seen.dedup();
        seen.into_iter()
            .map(|id| {
                let example = report
                    .findings
                    .iter()
                    .find(|f| f.rule_id == id)
                    .expect("the id came from the findings");
                json!({
                    "id": id,
                    "name": id,
                    "shortDescription": { "text": example.title },
                    "fullDescription": { "text": example.impact },
                    "help": { "text": example.fix },
                    "properties": {
                        "tags": example.cwe,
                        "requirements": example.requirement_ids,
                    }
                })
            })
            .collect()
    };

    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.rule_id,
                "level": match f.severity {
                    sv_check::Severity::Critical | sv_check::Severity::High => "error",
                    sv_check::Severity::Medium => "warning",
                    _ => "note",
                },
                "message": { "text": format!("{} {}", f.title, f.description) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.location.file },
                        "region": { "startLine": f.location.line.max(1) }
                    }
                }]
            })
        })
        .collect();

    // Said plainly rather than left to be inferred from an empty `results` array.
    let notifications: Vec<Value> = report
        .gaps
        .iter()
        .map(|gap| {
            json!({
                "level": "warning",
                "message": { "text": format!("Not examined: {} — {}", gap.what, gap.why) },
                "descriptor": { "id": "sv.not-examined" }
            })
        })
        .collect();

    let document = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "sv",
                "informationUri": "https://github.com/abbyshade111/SecureVibe",
                "rules": rules,
            }},
            "invocations": [{
                "executionSuccessful": true,
                "toolExecutionNotifications": notifications,
            }],
            "results": results,
        }]
    });
    serde_json::to_string_pretty(&document).expect("a JSON value serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Counts, Report};

    fn empty_report(gaps: Vec<crate::Gap>) -> Report {
        Report {
            app_name: "test".into(),
            target_level: 1,
            generated: None,
            run_note: None,
            counts: Counts::default(),
            requirements: vec![],
            excluded: vec![],
            undecided: vec![],
            claims: vec![],
            findings: vec![],
            out_of_scope: vec![],
            checklist_above_level: vec![],
            tests_to_write: vec![],
            named_not_credited: vec![],
            not_for_tests: 0,
            threats: Vec::new(),
            threat_parts: Vec::new(),
            satisfied_elsewhere: vec![],
            gaps,
        }
    }

    #[test]
    fn a_scan_that_examined_nothing_does_not_look_like_a_clean_one() {
        // Zero results and zero notifications is a tool saying "I looked everywhere and it is
        // fine". Zero results with the gaps attached is a tool saying what it did.
        let report = empty_report(vec![crate::Gap {
            what: "the running app".into(),
            why: "no container backend is available".into(),
        }]);
        let value: serde_json::Value = serde_json::from_str(&render(&report)).unwrap();
        let notifications = &value["runs"][0]["invocations"][0]["toolExecutionNotifications"];
        assert_eq!(notifications.as_array().map(Vec::len), Some(1));
        assert!(
            notifications[0]["message"]["text"]
                .as_str()
                .unwrap()
                .contains("no container backend"),
            "{notifications}"
        );
    }

    #[test]
    fn the_document_is_valid_sarif_shaped_json() {
        let value: serde_json::Value =
            serde_json::from_str(&render(&empty_report(vec![]))).unwrap();
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["runs"][0]["tool"]["driver"]["name"], "sv");
        assert!(value["runs"][0]["results"].is_array());
    }
}
