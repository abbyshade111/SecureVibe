//! `sv compare` on reports made here, field by field.

use super::*;
use serde_json::json;

fn report(level: u8, requirements: Value, findings: Value) -> Value {
    json!({
        "app_name": "Booking",
        "target_level": level,
        "sv": {"version": "0.1.0", "commit": "abcdef0123456789"},
        "run_record": {"started": "2026-10-10T10:00:00Z", "started_unix_ms": 1,
                       "securevibe_toml_sha256": "t",
                       "inputs": {"security_notes_sha256": null, "design_decisions_sha256": null,
                                  "sv_data_sha256": "d"}},
        "not_run_this_time": {"kinds": ["the running app"]},
        "counts": {},
        "findings": findings,
        "requirements": requirements,
    })
}

fn side(json: Value) -> Side {
    Side {
        folder: PathBuf::from("/reports/one"),
        json,
        sealed: Ok(()),
    }
}

fn finding(fingerprint: &str, title: &str) -> Value {
    json!({"fingerprint": fingerprint, "severity": "high", "rule_id": "r", "title": title})
}

#[test]
fn a_requirement_that_moved_is_named_with_what_it_gained_and_lost() {
    let older = report(
        1,
        json!([
            {"id": "V1.1.1", "status": "documented",
             "documented_by": [{"file": "security-notes.md", "scope": "an answer"}]},
            {"id": "V2.2.2", "status": "checked", "checked_by": [{"check_id": "a.rule", "scope": "s"}]},
        ]),
        json!([]),
    );
    let newer = report(
        1,
        json!([
            {"id": "V1.1.1", "status": "checked",
             "checked_by": [{"check_id": "ast.new-rule", "scope": "s"}]},
            {"id": "V2.2.2", "status": "checked", "checked_by": [{"check_id": "a.rule", "scope": "s"}]},
        ]),
        json!([]),
    );
    let said = text(&side(older), &side(newer));
    assert!(said.contains("1 requirement changed status:"), "{said}");
    assert!(
        said.contains("  V1.1.1: documented by the owner then, checked now"),
        "{said}"
    );
    assert!(said.contains("gained: checked by ast.new-rule"), "{said}");
    assert!(
        said.contains("lost: answered in your notes security-notes.md"),
        "{said}"
    );
    // The one that did not move is not listed.
    assert!(!said.contains("V2.2.2"), "{said}");
    assert!(said.contains("Nothing was written."), "{said}");
}

#[test]
fn a_requirement_in_only_one_report_did_not_apply_in_the_other() {
    let older = report(
        1,
        json!([{"id": "V1.1.1", "status": "not-verified"}]),
        json!([]),
    );
    let newer = report(
        1,
        json!([{"id": "V1.1.1", "status": "not-verified"},
               {"id": "V2.1.1", "status": "needs-attention", "findings": ["f1"]}]),
        json!([]),
    );
    let said = text(&side(older), &side(newer));
    assert!(
        said.contains("  V2.1.1: did not apply then, needs attention now"),
        "{said}"
    );
    assert!(said.contains("gained: finding f1"), "{said}");
}

#[test]
fn findings_that_came_and_went_are_listed() {
    let older = report(
        1,
        json!([{"id": "V1.1.1", "status": "checked"}]),
        json!([finding("a", "Old one")]),
    );
    let newer = report(
        1,
        json!([{"id": "V1.1.1", "status": "checked"}]),
        json!([finding("b", "New one")]),
    );
    let said = text(&side(older), &side(newer));
    assert!(said.contains("No requirement's status changed."), "{said}");
    assert!(said.contains("New finding (high): New one"), "{said}");
    assert!(said.contains("No longer found (high): Old one"), "{said}");
}

#[test]
fn a_report_sv_cannot_show_it_wrote_is_said_first() {
    let r = report(1, json!([{"id": "V1.1.1", "status": "checked"}]), json!([]));
    let mut older = side(r.clone());
    older.sealed = Err("its marker holds no seal".to_owned());
    let said = text(&older, &side(r));
    let warned = said
        .find("sv cannot show it wrote the older report: its marker holds no seal.")
        .expect(&said);
    assert!(
        warned < said.find("No requirement's status changed.").unwrap(),
        "{said}"
    );
    assert!(!said.contains("newer report:"), "{said}");
}

#[test]
fn two_runs_that_were_not_alike_are_said_to_differ_before_what_moved() {
    let older = report(1, json!([{"id": "V1.1.1", "status": "checked"}]), json!([]));
    let newer = report(
        2,
        json!([{"id": "V1.1.1", "status": "not-verified"}]),
        json!([]),
    );
    let said = text(&side(older.clone()), &side(newer));
    assert!(
        said.contains("These two runs were not alike: held to a different level."),
        "{said}"
    );
    // Alike: nothing said.
    let same = text(&side(older.clone()), &side(older));
    assert!(!same.contains("not alike"), "{same}");
    assert!(!same.contains("is not known"), "{same}");
}

#[test]
fn a_report_from_an_older_sv_says_what_cannot_be_said() {
    let mut older = report(1, json!([]), json!([]));
    older["run_record"]["inputs"] = Value::Null;
    let newer = report(1, json!([{"id": "V1.1.1", "status": "checked"}]), json!([]));
    let said = text(&side(older), &side(newer));
    assert!(
        said.contains("Which requirements moved cannot be said"),
        "{said}"
    );
    assert!(said.contains("did not record them"), "{said}");
}
