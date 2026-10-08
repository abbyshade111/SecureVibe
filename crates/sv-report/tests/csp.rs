//! Both pages carry a Content-Security-Policy `meta` tag (the review of 8 October 2026, item 6): a
//! file opened from disk has no server to send a header, and a report is a file somebody hands on.

use sv_report::dashboard;
use sv_report::html::CSP_META;

#[test]
fn the_policy_lets_nothing_load_and_no_script_run() {
    assert!(CSP_META.starts_with("<meta http-equiv=\"Content-Security-Policy\""));
    for directive in [
        "default-src 'none'",
        "style-src 'unsafe-inline'",
        "base-uri 'none'",
        "form-action 'none'",
    ] {
        assert!(CSP_META.contains(directive), "{CSP_META}");
    }
    assert!(
        !CSP_META.contains("script-src"),
        "no script is allowed by default-src 'none'"
    );
}

#[test]
fn the_dashboard_carries_the_policy_in_its_head() {
    let page = dashboard::page(&[], "2026-10-08");
    let head = page.split("</head>").next().unwrap();
    assert!(head.contains(CSP_META.trim_end()), "{head}");
    assert!(!page.contains("<script"));
}
