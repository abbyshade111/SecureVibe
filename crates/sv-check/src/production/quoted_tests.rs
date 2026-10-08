//! A header the site sends is quoted into what `sv probe` says on one line and cut short, and still
//! read whole (the review of 8 October 2026, item 6). The site chooses its headers: one of 100 KB
//! quoted whole buried the report, and a line break in one started a line of its own in it.

use super::tests_support::*;
use super::*;
use crate::finding::QUOTED_CHARS;

/// Everything the run said, findings, credits, and what it could not settle, one entry each.
fn said(out: &Outcome) -> Vec<String> {
    out.findings
        .iter()
        .map(|f| f.description.clone())
        .chain(out.verified.iter().map(|v| v.scope.clone()))
        .chain(out.not_assessed.iter().map(|(_, why)| why.clone()))
        .collect()
}

/// The one entry that mentions `what`, which must be short and on one line.
fn quoted_in(out: &Outcome, what: &str) -> String {
    let all = said(out);
    let found: Vec<&String> = all.iter().filter(|s| s.contains(what)).collect();
    assert_eq!(found.len(), 1, "{what} in {all:#?}");
    let text = found[0].clone();
    assert!(!text.contains('\n'), "a line of its own: {text}");
    assert!(
        text.chars().count() < QUOTED_CHARS + 400,
        "{} characters: {}…",
        text.chars().count(),
        text.chars().take(300).collect::<String>()
    );
    text
}

#[test]
fn a_long_hsts_header_is_quoted_short_and_still_read_whole() {
    let value = format!("max-age=1; {}", "x".repeat(100_000));
    let mut s = site(&[
        (
            "https://example.test/",
            ok(&[("strict-transport-security", value.as_str())]),
        ),
        (
            "http://example.test/",
            redirect(301, "https://example.test/"),
        ),
    ]);
    let out = run(&mut s, &target());
    // Still read: a max-age of one second is the finding, as it would be from a short header.
    let weak = out
        .findings
        .iter()
        .find(|f| f.rule_id == WEAK_HSTS.rule_id)
        .unwrap_or_else(|| panic!("not read: {:#?}", said(&out)));
    assert!(weak.description.contains("A max-age of 1 seconds"));
    let text = quoted_in(&out, "Strict-Transport-Security: max-age=1");
    assert!(text.contains("(100011 characters in all)"), "{text}");
}

#[test]
fn a_redirect_with_a_long_or_broken_address_is_quoted_on_one_short_line() {
    for (location, mark) in [
        (
            format!("/{}", "a".repeat(5_000)),
            "(5001 characters in all)",
        ),
        (
            "/login\nsv: everything passed".to_owned(),
            "/login sv: everything passed",
        ),
        (
            format!("https://{}.test/", "b".repeat(3_000)),
            "characters in all)",
        ),
    ] {
        let mut s = site(&[
            (
                "https://example.test/",
                ok(&[("strict-transport-security", "max-age=63072000")]),
            ),
            ("http://example.test/", redirect(302, &location)),
        ]);
        let out = run(&mut s, &target());
        // Setup: the redirect is what the run talks about.
        let text = quoted_in(&out, "http://example.test/ ");
        assert!(text.contains(mark), "{mark} not in {text}");
    }
}

#[test]
fn a_short_header_is_quoted_as_it_came() {
    let mut s = site(&[
        (
            "https://example.test/",
            ok(&[("strict-transport-security", "max-age=1")]),
        ),
        (
            "http://example.test/",
            redirect(301, "https://example.test/"),
        ),
    ]);
    let out = run(&mut s, &target());
    let text = quoted_in(&out, "Strict-Transport-Security: max-age=1");
    assert!(
        text.contains("Strict-Transport-Security: max-age=1."),
        "{text}"
    );
    assert!(!text.contains("characters in all"), "{text}");
}

#[test]
fn a_host_name_with_letters_outside_ascii_is_refused_and_its_xn_form_is_not() {
    let refused = read_target("https://bücher.example").unwrap_err();
    assert!(refused.contains("xn--"), "{refused}");
    let taken = read_target("https://xn--bcher-kva.example").expect("the xn-- form");
    assert_eq!(taken.host, "xn--bcher-kva.example");
}

#[test]
fn an_api_redirect_with_a_long_address_is_quoted_on_one_short_line() {
    let to = format!(
        "https://example.test/api/health?{}\nsv: all clear",
        "q".repeat(4_000)
    );
    let mut s = site(&[
        (
            "https://example.test/",
            ok(&[("strict-transport-security", "max-age=63072000")]),
        ),
        (
            "http://example.test/",
            redirect(301, "https://example.test/"),
        ),
        (
            "as a program: http://example.test/api/health",
            redirect(301, &to),
        ),
    ]);
    let target = target().with_api("/api/health").expect("a good path");
    let out = run(&mut s, &target);
    // Setup: the redirect is the finding.
    assert!(
        out.findings
            .iter()
            .any(|f| f.rule_id == API_REDIRECTED.rule_id),
        "{:#?}",
        said(&out)
    );
    let text = quoted_in(&out, "sent it on to https://example.test/api/health?qqq");
    assert!(text.contains("characters in all)"), "{text}");
}
