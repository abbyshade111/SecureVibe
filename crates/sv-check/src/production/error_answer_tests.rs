//! The tests of `production.rs` that were `mod error_answer_tests` inside it until 8 October 2026, moved out so
//! two sessions adding a test do not meet in one file (the architecture assessment of that day, item 11).

use super::tests_support::*;
use super::*;

#[test]
fn an_error_answer_settles_nothing_about_the_headers_it_did_not_send() {
    // Found by running this against a real site through a proxy that answered 400. The site
    // certainly sends HSTS; the 400 did not, and the check reported the site as missing it.
    // An error page's headers are not the ones a visitor gets.
    let mut s = site(&[
        (
            "https://example.test/",
            Answer {
                revocation: None,
                status: 400,
                headers: Vec::new(),
                failure: None,
            },
        ),
        (
            "http://example.test/",
            redirect(301, "https://example.test/"),
        ),
    ]);
    let out = run(&mut s, &target());
    let found: Vec<&str> = out.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        !found.contains(&"probe.no-hsts"),
        "a 400 that sent no HSTS is not the site failing to send it: {found:?}"
    );
    assert!(
        out.not_assessed
            .iter()
            .any(|(ids, why)| ids.contains("V3.4.1") && why.contains("400")),
        "and it says why: {:?}",
        out.not_assessed
    );
    // The handshake still answers V12.2.2, because that is about the certificate and not the
    // page, and it still reads plain HTTP, because that is a different request.
    assert!(
        out.verified
            .iter()
            .any(|v| v.check_id == "probe.certificate-not-trusted"),
        "the certificate question is answered by the handshake whatever the status"
    );
}

#[test]
fn an_ordinary_answer_is_still_judged() {
    // The other half: without this, making errors settle nothing would be indistinguishable
    // from the check never running.
    let mut s = site(&[
        ("https://example.test/", ok(&[])),
        (
            "http://example.test/",
            redirect(301, "https://example.test/"),
        ),
    ]);
    let out = run(&mut s, &target());
    assert!(
        out.findings.iter().any(|f| f.rule_id == "probe.no-hsts"),
        "a 200 with no HSTS is the site failing to send it"
    );
}

#[test]
fn a_proxys_connect_line_is_not_read_as_the_sites_answer() {
    // A proxy answers CONNECT with its own status line first. Counting it would clear the
    // site's headers when they arrive after, or take its 200 for the site's.
    let answer = parse_head(
        "HTTP/1.1 200 Connection Established\r\n\r\n\
             HTTP/2 200 \r\nStrict-Transport-Security: max-age=1\r\n\r\n",
    );
    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.header("strict-transport-security"),
        Some("max-age=1"),
        "the site's headers must survive the tunnel's own status line"
    );
}
