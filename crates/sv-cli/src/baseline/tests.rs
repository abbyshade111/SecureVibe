//! A finding held by its fingerprint, or by an earlier form of it, and nothing held by an empty one.

use super::Baseline;
use sv_check::{Confidence, Finding, Location, Severity};

fn finding(fingerprint: &str, earlier: &[&str]) -> Finding {
    Finding {
        also_reported_by: Vec::new(),
        fingerprint: fingerprint.to_owned(),
        earlier_fingerprints: earlier.iter().map(|s| (*s).to_owned()).collect(),
        marked_test_code: false,
        bundled_library: None,
        outranked: None,
        also_on_this_line: Vec::new(),
        rule_id: "ast.eval".into(),
        title: "t".into(),
        severity: Severity::High,
        confidence: Confidence::High,
        location: Location {
            file: "app.py".into(),
            line: 1,
        },
        secret: None,
        requirement_ids: Vec::new(),
        cwe: Vec::new(),
        description: String::new(),
        impact: String::new(),
        fix: String::new(),
    }
}

/// A baseline folder whose report.json holds `findings`, as `(fingerprint, earlier)` pairs.
fn baseline(tag: &str, findings: &[(&str, &[&str])]) -> Baseline {
    let dir = std::env::temp_dir().join(format!("sv-baseline-unit-{tag}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    let list: Vec<serde_json::Value> = findings
        .iter()
        .map(
            |(fp, earlier)| serde_json::json!({"fingerprint": fp, "earlier_fingerprints": earlier}),
        )
        .collect();
    std::fs::write(
        dir.join("report.json"),
        serde_json::json!({"app_name": "A", "findings": list}).to_string(),
    )
    .unwrap();
    let b = Baseline::load(&dir).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    b
}

#[test]
fn a_finding_is_held_by_its_fingerprint_or_an_earlier_form_either_way() {
    let b = baseline("forms", &[("today", &["yesterday"])]);
    assert!(b.holds(&finding("today", &[])));
    // The baseline was made by an older `sv`: today's finding carries its old form.
    assert!(b.holds(&finding("newer", &["today"])));
    // The baseline's own earlier form matches this run's fingerprint.
    assert!(b.holds(&finding("yesterday", &[])));
    assert!(!b.holds(&finding("other", &["another"])));
}

#[test]
fn an_empty_fingerprint_holds_nothing() {
    let b = baseline("empty", &[("", &[""])]);
    assert!(!b.holds(&finding("", &[])));
    assert!(!b.holds(&finding("x", &[""])));
}

#[test]
fn any_of_several_earlier_forms_will_do() {
    let b = baseline("several", &[("second", &[])]);
    assert!(b.holds(&finding("third", &["first", "second"])));
}

#[test]
fn a_finding_with_no_fingerprint_at_all_is_new() {
    let b = baseline("none", &[("real", &[])]);
    assert!(!b.holds(&finding("", &[])));
}
