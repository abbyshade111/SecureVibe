//! A saved record written back into a page unencoded (the gap analysis of 7 October 2026, finding
//! 13(b), the stored record's half): found on the pages that write the `<` as it is, and on no other,
//! and never judged from an answer that is not said to be HTML.

use super::fake_app::*;
use super::*;

fn stored_finding(o: &Outcome) -> Option<&Finding> {
    o.findings.iter().find(|f| f.rule_id == STORED_HTML.rule_id)
}

#[test]
fn saved_text_written_into_the_page_as_it_is_is_found() {
    let o = run_against(
        Flaws {
            notes_unescaped: true,
            ..Default::default()
        },
        &users(),
    );
    let f = stored_finding(&o).unwrap_or_else(|| panic!("{:?}", o.steps));
    assert_eq!(f.title, "Saved text is written into the page unencoded");
    assert_eq!(f.requirement_ids, ["V1.2.1"]);
    // The record's own page, written by the flaw.
    assert!(
        f.description.contains("/notes/2 wrote the `<` back"),
        "{}",
        f.description
    );
}

#[test]
fn saved_text_escaped_is_not_reported_and_credits_nothing() {
    let o = run_against(Flaws::default(), &users());
    assert!(stored_finding(&o).is_none());
    assert!(!verified_ids(&o).contains(&STORED_HTML.rule_id));
    // The setup: the text was saved and found on the pages, escaped, so the check did look.
    assert!(
        o.steps.iter().any(|s| s
            == "A saved a record whose text holds `<\"'`; it came back escaped on \
                /notes/2"),
        "{:?}",
        o.steps
    );
}

fn page(content_type: Option<&str>, body: &str) -> Option<ProbeResponse> {
    Some(ProbeResponse {
        id: "p".into(),
        status: 200,
        headers: content_type
            .map(|t| vec![("content-type".to_owned(), t.to_owned())])
            .unwrap_or_default(),
        body: body.into(),
    })
}

#[test]
fn only_an_html_page_with_the_text_in_it_is_judged() {
    let raw = format!("<li>{}</li>", stored_value());
    let escaped = raw.replace("<\"'", "&lt;&quot;&#39;");
    assert_eq!(judged(&page(Some("text/html"), &raw)), Shown::Raw);
    assert_eq!(judged(&page(Some("text/html"), &escaped)), Shown::Escaped);
    // JSON carries a `<` as it is, rightly: the page that shows it is what decides.
    assert_eq!(
        judged(&page(Some("application/json"), &raw)),
        Shown::NotJudged
    );
    // A page that does not say what it is, and one without the text, say nothing.
    assert_eq!(judged(&page(None, &raw)), Shown::NotJudged);
    assert_eq!(
        judged(&page(Some("text/html"), "<p>nothing here</p>")),
        Shown::NotJudged
    );
    let mut refused = page(Some("text/html"), &raw);
    refused.as_mut().unwrap().status = 403;
    assert_eq!(judged(&refused), Shown::NotJudged);
}

#[test]
fn every_page_that_writes_it_as_it_is_is_named_and_none_that_escapes_it() {
    // With the list of notes named, both the record's page and the list are looked at.
    let o = run_against(
        Flaws {
            notes_unescaped: true,
            ..Default::default()
        },
        &users_full(),
    );
    let f = stored_finding(&o).unwrap_or_else(|| panic!("{:?}", o.steps));
    assert!(
        f.description.contains(" and /my-notes wrote the `<` back"),
        "{}",
        f.description
    );
    let clean = run_against(Flaws::default(), &users_full());
    assert!(stored_finding(&clean).is_none());
    assert!(
        clean
            .steps
            .iter()
            .any(|s| s.starts_with("A saved a record whose text holds")
                && s.ends_with(", /my-notes")),
        "{:?}",
        clean.steps
    );
}
