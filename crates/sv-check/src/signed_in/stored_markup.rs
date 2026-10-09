//! A saved record written back into a page unencoded: stored cross-site scripting, asked without a
//! browser (the gap analysis of 7 October 2026, finding 13(b), the stored record's half).
//!
//! The first user saves a second `owned` record whose text carries `<"'` between the marks the
//! reflection probes use, then opens the record and the pages that list it. An HTML page with the
//! `<` as it is between the marks is the finding. The marks are the reflection probes' own so the
//! runner keeps the text around them however long the page is.

use super::*;
use crate::probes::{REFLECTION_END, REFLECTION_MARK, echoes};

/// What the record's text is: the reflection marks around a `<`, a `"`, and a `'`.
pub(super) fn stored_value() -> String {
    format!("{REFLECTION_MARK}<\"'{REFLECTION_END}")
}

/// What one page did with the saved text: wrote the `<` as it is, wrote the text escaped, or did not
/// show it as HTML at all (not there, not a success, or not said to be HTML).
#[derive(Debug, PartialEq)]
pub(super) enum Shown {
    Raw,
    Escaped,
    NotJudged,
}

pub(super) fn judged(response: &Option<ProbeResponse>) -> Shown {
    let Some(r) = response.as_ref().filter(|_| ok(response)) else {
        return Shown::NotJudged;
    };
    let html = r
        .header("content-type")
        .is_some_and(|t| t.to_lowercase().contains("html"));
    let echoed = echoes(&r.body);
    if !html || echoed.is_empty() {
        Shown::NotJudged
    } else if echoed.iter().any(|e| e.contains('<')) {
        Shown::Raw
    } else {
        Shown::Escaped
    }
}

/// Runs as the first user, once their own record has been read back.
pub(super) fn stored_markup_check(
    http: &mut dyn Http,
    users: &UsersSection,
    owned: &sv_manifest::OwnedSection,
    a: &Session,
    out: &mut Outcome,
) {
    let value = stored_value();
    let mut session = a.clone();
    let (created, _) = send_template(
        http,
        "stored-markup-create",
        &owned.create,
        &Values {
            marker: &value,
            ..Default::default()
        },
        &mut session,
        &users.private,
    );
    let what = "a record whose text holds `<\"'`";
    if !accepted(&created) {
        // An app that refuses the characters has not shown how it writes them out.
        out.steps.push(format!(
            "A saved {what}: refused ({}), so how a page writes it was not seen",
            status(&created)
        ));
        return;
    }
    let mut places: Vec<String> = Vec::new();
    if let Some(path) = created.as_ref().and_then(|r| record_path(owned, r)) {
        places.push(path);
    }
    for page in owned.list.iter().chain(&users.private) {
        if !places.contains(page) {
            places.push(page.clone());
        }
    }
    let mut raw = Vec::new();
    let mut escaped = Vec::new();
    for (i, place) in places.iter().enumerate() {
        let seen = http.send(&get(&format!("stored-markup-{i}"), place, &session));
        match judged(&seen) {
            Shown::Raw => raw.push(place.clone()),
            Shown::Escaped => escaped.push(place.clone()),
            Shown::NotJudged => {}
        }
    }
    out.steps.push(format!(
        "A saved {what}; {}",
        match (raw.is_empty(), escaped.is_empty()) {
            (false, _) => format!("the `<` came back as it is on {}", raw.join(", ")),
            (true, false) => format!("it came back escaped on {}", escaped.join(", ")),
            (true, true) => "no page showed it as HTML (a JSON answer is not judged)".to_owned(),
        }
    ));
    if !raw.is_empty() {
        out.findings.push(finding(
            &STORED_HTML,
            "Saved text is written into the page unencoded",
            Severity::High,
            format!(
                "The first test user saved a record holding `<\"'`, and {} wrote the `<` back into \
                 the page as it is, where a browser reads it as the start of a tag.",
                raw.join(" and ")
            ),
        ));
    }
}
