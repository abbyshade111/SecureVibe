//! A probe finding names the answers it was read from, and no others (ADR-082, backlog 0229,
//! part 1): what a person checks it against, and what `seen.json` holds those answers under.

use super::*;

fn answer(id: &str, status: u16, headers: &[(&str, &str)], body: &str) -> ProbeResponse {
    ProbeResponse {
        id: id.to_owned(),
        status,
        headers: headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        body: body.to_owned(),
    }
}

#[test]
fn a_content_type_finding_names_the_answer_without_a_charset_and_no_other() {
    // The setup: `home` is text with no charset, and `missing` is text with one.
    let home = answer("home", 200, &[("content-type", "text/plain")], "hi");
    let missing = answer(
        "missing",
        404,
        &[("content-type", "text/html; charset=utf-8")],
        "no",
    );
    let found = evaluate(&[home, missing]);
    let finding = found
        .iter()
        .find(|f| f.rule_id == CONTENT_TYPE.rule_id)
        .expect("the setup should produce a content-type finding");
    assert_eq!(finding.evidence, ["home"], "{finding:?}");
}

#[test]
fn a_trace_finding_names_the_trace_answer() {
    let trace = answer(
        "trace",
        200,
        &[("content-type", "message/http; charset=utf-8")],
        "TRACE / HTTP/1.1\r\nsv-probe-echo-value: yes",
    );
    let found = evaluate(&[trace]);
    let finding = found
        .iter()
        .find(|f| f.rule_id == TRACE_ENABLED.rule_id)
        .expect("the setup should produce a trace finding");
    assert_eq!(finding.evidence, ["trace"], "{finding:?}");
}

#[test]
fn an_answer_with_no_problem_is_not_named_by_the_check_it_passes() {
    // `home` has a charset, so the content-type check does not name it. Other checks may still
    // read it (it lacks security headers, for one), and name it for their own reasons.
    let fine = answer(
        "home",
        200,
        &[("content-type", "text/html; charset=utf-8")],
        "ok",
    );
    let found = evaluate(&[fine]);
    assert!(
        found.iter().all(|f| {
            f.rule_id != CONTENT_TYPE.rule_id || !f.evidence.contains(&"home".to_owned())
        }),
        "{found:#?}"
    );
}
