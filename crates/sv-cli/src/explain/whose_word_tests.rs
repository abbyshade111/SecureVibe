//! `sv explain` says whose word a status rests on as the report does (backlog 0226, part 1, item 2).
//! Until 9 October 2026 it told the owner "answered by you" for an answer only the AI coding tool
//! gave, which the owner had confirmed through `sv review`, while the report said the tool's.

use super::*;
use serde_json::json;

/// A report with one requirement, at `status`, credited by `ids` in the list `key`.
fn report(status: &str, key: &str, ids: &[&str]) -> Value {
    let credits: Vec<Value> = ids
        .iter()
        .map(|id| json!({"check_id": id, "scope": "a scope"}))
        .collect();
    json!({
        "app_name": "an app",
        "requirements": [{"id": "V1.1.1", "status": status, key: credits}],
    })
}

fn said(report: &Value) -> String {
    from_report(report, "last report", "V1.1.1", &[])
}

#[test]
fn the_tools_answer_that_somebody_confirmed_is_never_called_the_owners() {
    for (status, key, id, label) in [
        (
            "attested",
            "attested_by",
            "design.stated-by-ai",
            "stated by the AI coding tool, confirmed through sv review",
        ),
        (
            "by-hand",
            "by_hand",
            sv_check::confirm::HAND_CONFIRMED,
            "checked by the AI coding tool, confirmed through sv review",
        ),
        (
            "documented",
            "documented_by",
            sv_check::notes::CONFIRMED,
            "written by the AI coding tool, confirmed through sv review",
        ),
    ] {
        let text = said(&report(status, key, &[id]));
        assert!(text.contains(label), "{status}: {text}");
        assert!(!text.contains("by you"), "{status}: {text}");
        // And it is the report's own label, read by the report's own rule.
        let status: sv_report::Status = serde_json::from_value(json!(status)).unwrap();
        assert!(sv_report::confirmed_only_by(
            status,
            &[id.to_owned()],
            &[id.to_owned()],
            &[id.to_owned()],
        ));
        assert!(text.contains(status.shown(true)), "{text}");
    }
}

#[test]
fn the_owners_own_answer_is_still_called_theirs() {
    let text = said(&report("attested", "attested_by", &["design.attested"]));
    assert!(text.contains("answered by you in stackvet.toml"), "{text}");
    assert!(!text.contains("AI coding tool"), "{text}");
    // An owner's record beside the confirmed one is the owner's, as the report reads it.
    let text = said(&report(
        "by-hand",
        "by_hand",
        &[sv_check::confirm::HAND_CONFIRMED, "hand.recorded"],
    ));
    assert!(text.contains("checked by hand, by you"), "{text}");
}
