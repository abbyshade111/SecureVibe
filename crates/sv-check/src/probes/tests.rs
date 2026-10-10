//! The tests of `probes.rs` that were `mod tests` inside it until 8 October 2026, moved out so
//! two sessions adding a test do not meet in one file (the architecture assessment of that day, item 11).

use super::*;

/// A response as a real app sends it: with a Content-Type, unless the test names its own, and
/// without one when the test gives it as empty.
fn response(id: &str, status: u16, headers: &[(&str, &str)], body: &str) -> ProbeResponse {
    let mut headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), (*v).to_owned()))
        .collect();
    if !headers.iter().any(|(k, _)| k == "content-type") {
        headers.push(("content-type".into(), "text/html; charset=utf-8".into()));
    }
    // And isolated from other windows, as a careful app's pages are, unless the test says not.
    if !headers
        .iter()
        .any(|(k, _)| k == "cross-origin-opener-policy")
    {
        headers.push(("cross-origin-opener-policy".into(), "same-origin".into()));
    }
    headers.retain(|(k, v)| {
        !((k == "content-type" || k == "cross-origin-opener-policy") && v.is_empty())
    });
    ProbeResponse {
        id: id.into(),
        status,
        headers,
        body: body.into(),
    }
}

fn ids(findings: &[Finding]) -> Vec<&str> {
    findings.iter().map(|f| f.rule_id.as_str()).collect()
}

/// Everything a careful app would send.
fn good_home() -> ProbeResponse {
    response(
        "home",
        200,
        &[
            (
                "Content-Security-Policy",
                "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; report-uri /csp-reports",
            ),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            (
                "Set-Cookie",
                "session=abc; HttpOnly; SameSite=Strict; Secure; Path=/",
            ),
        ],
        "<html>hello</html>",
    )
}

#[test]
fn an_app_that_sends_the_right_headers_gets_no_findings() {
    // The most important test here. A probe suite that cannot come back clean is one nobody will
    // act on, because every app looks equally bad.
    let findings = evaluate(&[good_home()]);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_policy_short_of_what_v3_4_3_names_is_found_for_what_it_lacks() {
    // V3.4.3's minimum: `object-src 'none'`, `base-uri 'none'`, and an allowlist (ADR-047).
    let with = |policy: &str| {
        let mut home = good_home();
        home.headers.retain(|(k, _)| k != "content-security-policy");
        home.headers
            .push(("content-security-policy".into(), policy.into()));
        evaluate(&[home])
            .into_iter()
            .find(|f| f.rule_id == SECURITY_HEADERS.rule_id)
            .map(|f| f.description)
    };
    // The setup: the full policy passes, so each case below differs by what it leaves out.
    let full = "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; report-uri /r";
    assert_eq!(with(full), None);
    for (policy, lacks) in [
        (
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; report-uri /r",
            "`object-src 'none'`",
        ),
        (
            "default-src 'self'; object-src 'self'; base-uri 'none'; frame-ancestors 'none'; report-uri /r",
            "`object-src 'none'`",
        ),
        (
            "default-src 'self'; object-src 'none' 'self'; base-uri 'none'; frame-ancestors 'none'; report-uri /r",
            "`object-src 'none'`",
        ),
        (
            "default-src 'self'; object-src 'none'; frame-ancestors 'none'; report-uri /r",
            "`base-uri 'none'`",
        ),
        (
            "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; report-uri /r",
            "`base-uri 'none'`",
        ),
        (
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; report-uri /r",
            "`default-src` or `script-src`",
        ),
    ] {
        let said = with(policy).unwrap_or_else(|| panic!("{policy} was not found"));
        assert!(said.contains(lacks), "{policy}: {said}");
    }
    // `default-src 'none'` is what a browser falls back to for `object-src`, and `script-src`
    // is an allowlist as `default-src` is; capitals are read as a browser reads them.
    for fine in [
        "default-src 'none'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'; report-uri /r",
        "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; report-uri /r",
        "DEFAULT-SRC 'self'; Object-Src 'NONE'; base-uri 'none'; frame-ancestors 'none'; report-uri /r",
    ] {
        assert_eq!(with(fine), None, "{fine}");
    }
}

#[test]
fn missing_headers_are_named_individually() {
    let findings = evaluate(&[response("home", 200, &[], "hi")]);
    assert_eq!(ids(&findings), vec!["probe.security-headers"]);
    let description = &findings[0].description;
    for expected in [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ] {
        assert!(description.contains(expected), "{description}");
    }
}

#[test]
fn frame_ancestors_counts_instead_of_x_frame_options() {
    // Both are correct answers to the same question, and demanding the older one would report a
    // modern app for doing it the current way.
    let with_csp = response(
        "home",
        200,
        &[
            (
                "Content-Security-Policy",
                "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; report-to csp",
            ),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
        ],
        "hi",
    );
    assert!(evaluate(&[with_csp]).is_empty());
}

#[test]
fn one_missing_header_is_reported_on_its_own() {
    // A second witness, of a different shape to the one above: an app that has nearly all of it.
    // Breaking the check has to fail on the app that is almost right, not only on the bare one,
    // or the guard is only known to work where everything is wrong.
    let findings = evaluate(&[response(
        "home",
        200,
        &[
            (
                "Content-Security-Policy",
                "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; report-to csp",
            ),
            ("X-Content-Type-Options", "nosniff"),
        ],
        "hi",
    )]);
    assert_eq!(ids(&findings), vec!["probe.security-headers"]);
    let description = &findings[0].description;
    assert!(description.contains("Referrer-Policy"), "{description}");
    // And it must not name the ones that were there.
    assert!(
        !description.contains("X-Content-Type-Options"),
        "{description}"
    );
}

#[test]
fn a_cookie_without_httponly_is_high_not_medium() {
    let findings = evaluate(&[response(
        "home",
        200,
        &[
            (
                "Content-Security-Policy",
                "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            ),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Set-Cookie", "session=abc; Path=/"),
        ],
        "hi",
    )]);
    let cookie = findings
        .iter()
        .find(|f| f.rule_id == "probe.cookie-attributes")
        .unwrap_or_else(|| panic!("{findings:?}"));
    assert_eq!(cookie.severity, Severity::High);
    assert!(
        cookie.description.contains("HttpOnly"),
        "{}",
        cookie.description
    );
    assert!(
        cookie.description.contains("SameSite"),
        "{}",
        cookie.description
    );
}

#[test]
fn the_cookie_that_is_wrong_is_the_one_named() {
    // Second witness of a different shape: two cookies, one of them correct. An app usually sets
    // more than one, and a check that only fires when every cookie is wrong would miss the real
    // case, where the session cookie is the careless one.
    let findings = evaluate(&[response(
        "home",
        200,
        &[
            (
                "Content-Security-Policy",
                "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            ),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Set-Cookie", "theme=dark; HttpOnly; SameSite=Lax; Path=/"),
            ("Set-Cookie", "session=abc; SameSite=Lax; Path=/"),
        ],
        "hi",
    )]);
    let cookie = findings
        .iter()
        .find(|f| f.rule_id == "probe.cookie-attributes")
        .unwrap_or_else(|| panic!("{findings:?}"));
    assert!(
        cookie.description.contains("`session`"),
        "{}",
        cookie.description
    );
    assert!(
        !cookie.description.contains("`theme`"),
        "{}",
        cookie.description
    );
}

#[test]
fn no_cookie_at_all_is_not_a_cookie_problem() {
    let findings = evaluate(&[good_home()]);
    assert!(
        !ids(&findings).contains(&"probe.cookie-attributes"),
        "{findings:?}"
    );
}

#[test]
fn an_origin_echoed_back_is_reported() {
    // The app was asked with an origin that does not exist. Answering with it means nothing is
    // being checked.
    let findings = evaluate(&[response(
        "cors",
        200,
        &[("Access-Control-Allow-Origin", STRANGER)],
        "",
    )]);
    assert_eq!(ids(&findings), vec!["probe.cors-any-origin"]);
    assert_eq!(findings[0].severity, Severity::Medium);
}

#[test]
fn echoing_the_origin_and_allowing_credentials_is_worse() {
    // This is the combination that actually hands data over, and it should not read the same as
    // the one that does not.
    let findings = evaluate(&[response(
        "cors",
        200,
        &[
            ("Access-Control-Allow-Origin", STRANGER),
            ("Access-Control-Allow-Credentials", "true"),
        ],
        "",
    )]);
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn a_fixed_allowed_origin_is_not_a_finding() {
    // An app that names one origin is doing it correctly, whatever that origin is.
    let findings = evaluate(&[response(
        "cors",
        200,
        &[("Access-Control-Allow-Origin", "https://app.example.com")],
        "",
    )]);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_stack_trace_on_a_missing_page_is_reported() {
    let findings = evaluate(&[response(
        "missing",
        500,
        &[],
        "Traceback (most recent call last):\n  File \"/app/main.py\", line 42",
    )]);
    assert_eq!(ids(&findings), vec!["probe.error-detail-leak"]);
    assert!(
        findings[0].description.contains("Traceback"),
        "{}",
        findings[0].description
    );
}

#[test]
fn django_s_debug_404_is_a_leak_though_it_prints_no_trace() {
    let findings = evaluate(&[response(
        "missing",
        404,
        &[],
        "<h1>Page not found <span>(404)</span></h1>\n<p>Using the URLconf defined in \
             <code>shop.urls</code>, Django tried these URL patterns</p>\n<footer id=\"explanation\">\
             <p>You\u{2019}re seeing this error because you have <code>DEBUG = True</code> in\n\
             your Django settings file.</p></footer>",
    )]);
    assert_eq!(ids(&findings), vec!["probe.error-detail-leak"]);
    // And a page that only mentions the setting is not the debug page.
    let findings = evaluate(&[response(
        "missing",
        404,
        &[],
        "<p>Not found. Set DEBUG = True to see more.</p>",
    )]);
    assert!(ids(&findings).is_empty());
}

#[test]
fn a_go_panic_is_a_leak_too() {
    // Second witness of a different shape: the marker list exists because apps are not all
    // written in Python, and a check exercised by one language is a check for one language.
    let findings = evaluate(&[response(
        "missing",
        500,
        &[],
        "panic: runtime error: index out of range\n\ngoroutine 1 [running]:",
    )]);
    assert_eq!(ids(&findings), vec!["probe.error-detail-leak"]);
    assert!(
        findings[0].description.contains("panic:"),
        "{}",
        findings[0].description
    );
}

#[test]
fn an_ordinary_not_found_page_is_not_a_leak() {
    let findings = evaluate(&[response("missing", 404, &[], "<h1>Not found</h1>")]);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn trace_is_only_reported_when_the_server_really_echoed() {
    // A 200 alone is not evidence: plenty of apps answer TRACE with their normal page. The
    // header this probe invented coming back in the body is what shows the echo happened.
    let echoed = response(
        "trace",
        200,
        &[],
        "TRACE / HTTP/1.0\r\nX-Probe-Echo: sv-probe-echo-value\r\n",
    );
    assert_eq!(ids(&evaluate(&[echoed])), vec!["probe.trace-enabled"]);

    let refused = response("trace", 405, &[], "Method Not Allowed");
    assert!(evaluate(&[refused]).is_empty());

    let ordinary_page = response("trace", 200, &[], "<html>the usual home page</html>");
    assert!(
        evaluate(&[ordinary_page]).is_empty(),
        "a 200 alone is not an echo"
    );
}

#[test]
fn a_trace_refused_or_not_echoed_is_credited_and_one_echoed_is_not() {
    // Until 6 October 2026 only the tests that run an app in Docker reached this credit, so
    // the census of credits (`tools/coverage.py --credits`) failed wherever Docker was not.
    let credited =
        |r: ProbeResponse| verified_ids(&[r]).contains(&TRACE_ENABLED.rule_id.to_owned());
    assert!(credited(response("trace", 405, &[], "Method Not Allowed")));
    assert!(credited(response(
        "trace",
        200,
        &[],
        "<html>the usual home page</html>"
    )));
    assert!(!credited(response(
        "trace",
        200,
        &[],
        "TRACE / HTTP/1.0\r\nX-Probe-Echo: sv-probe-echo-value\r\n",
    )));
}

#[test]
fn a_trace_that_answers_normally_among_other_answers_is_not_reported() {
    // Second witness for the echo requirement, of a different shape: the whole suite, where the
    // app is careless about everything else and correct about TRACE. Loosening the echo check
    // makes this app read as though it echoed, and nothing else here would notice.
    let findings = evaluate(&[
        response("home", 200, &[], "hi"),
        response(
            "trace",
            200,
            &[],
            "<html>the usual home page, served for any method</html>",
        ),
    ]);
    assert!(
        !ids(&findings).contains(&"probe.trace-enabled"),
        "a 200 with no echo of our own header is not TRACE: {findings:?}"
    );
    assert!(
        ids(&findings).contains(&"probe.security-headers"),
        "{findings:?}"
    );
}

#[test]
fn a_whole_set_of_answers_reports_every_one_of_them() {
    // A second witness for each check, of a different shape again: a real run hands `evaluate`
    // four answers at once, not one. A check that only fires when its own response is the sole
    // one there — or that reads the wrong answer because two came back — is caught here and
    // nowhere above.
    let findings = evaluate(&[
        response(
            "home",
            200,
            &[("Set-Cookie", "session=abc; Path=/")],
            "<html>hi</html>",
        ),
        response(
            "cors",
            200,
            &[("Access-Control-Allow-Origin", STRANGER)],
            "",
        ),
        response("missing", 500, &[], "Traceback (most recent call last):"),
        response("trace", 200, &[], "X-Probe-Echo: sv-probe-echo-value"),
    ]);
    let mut found = ids(&findings);
    found.sort_unstable();
    assert_eq!(
        found,
        vec![
            "probe.cookie-attributes",
            "probe.cors-any-origin",
            "probe.error-detail-leak",
            "probe.security-headers",
            "probe.trace-enabled",
        ]
    );
    // Worst first, so the list is read in the order it should be acted on.
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn what_these_probes_cannot_reach_is_stated() {
    // The suite signs in as nobody. Saying nothing about authorization would read exactly like
    // finding nothing wrong with it.
    let unassessed = unassessed_requirements(false);
    assert!(!unassessed.is_empty());
    assert!(
        unassessed.iter().any(|(ids, _)| ids.contains("V8")),
        "authorization must be named: {unassessed:?}"
    );
    assert!(
        unassessed.iter().any(|(_, why)| why.contains("signed-in")),
        "the reason authorization is unreachable must be named: {unassessed:?}"
    );
    assert!(
        unassessed.iter().any(|(ids, _)| *ids == "V3.5.1"),
        "request forgery is V3.5.1 in ASVS 5.0: {unassessed:?}"
    );
    // When the signed-in probes ran they speak for authorization themselves, and what input
    // handling needs is still out of reach either way.
    let with_users = unassessed_requirements(true);
    assert!(
        !with_users.iter().any(|(ids, _)| ids.contains("V8")),
        "{with_users:?}"
    );
    assert!(
        with_users.iter().any(|(ids, _)| ids.contains("V5")),
        "{with_users:?}"
    );
}

/// The healthy home answer's headers, on the root page instead.
fn good_root() -> ProbeResponse {
    let mut root = good_home();
    root.id = "root".into();
    root
}

#[test]
fn a_root_page_without_the_headers_is_named_and_withholds_the_credit() {
    // The health path is fine and the root page, the one people see, is not.
    let mut root = good_root();
    root.headers.retain(|(k, _)| k != "referrer-policy");
    let answers = [good_home(), root];
    let findings = evaluate(&answers);
    let found = findings
        .iter()
        .find(|f| f.rule_id == SECURITY_HEADERS.rule_id)
        .unwrap_or_else(|| panic!("{findings:?}"));
    assert!(
        found
            .description
            .starts_with("The root page came back without Referrer-Policy"),
        "{}",
        found.description
    );
    assert!(
        !found.description.contains("health path"),
        "{}",
        found.description
    );
    assert!(
        !verified(&answers)
            .iter()
            .any(|v| v.check_id == SECURITY_HEADERS.rule_id),
        "one page short of the headers is no credit for either"
    );
}

#[test]
fn both_pages_with_the_headers_are_credited_and_named() {
    let answers = [good_home(), good_root()];
    assert!(!ids(&evaluate(&answers)).contains(&SECURITY_HEADERS.rule_id));
    let credit = verified(&answers)
        .into_iter()
        .find(|v| v.check_id == SECURITY_HEADERS.rule_id)
        .expect("credited");
    assert!(
        credit.scope.contains("the health path and the root page"),
        "{}",
        credit.scope
    );
    let cookies = verified(&answers)
        .into_iter()
        .find(|v| v.check_id == COOKIE_ATTRIBUTES.rule_id)
        .expect("cookies credited");
    assert!(cookies.scope.contains("the root page"), "{}", cookies.scope);
    // Two pages a stranger sees are one sample of the app's responses (ADR-053, Later).
    assert!(credit.in_part && cookies.in_part, "{credit:?} {cookies:?}");
}

#[test]
fn an_app_that_names_its_own_origin_is_credited_and_one_that_says_nothing_is_not() {
    // Until 6 October 2026 no test reached this credit: the census of what the suite credits
    // (`tools/coverage.py --credits`) found it.
    let fixed = response(
        "cors",
        200,
        &[("Access-Control-Allow-Origin", "https://app.example")],
        "",
    );
    assert!(!ids(&evaluate(std::slice::from_ref(&fixed))).contains(&CORS_ANY_ORIGIN.rule_id));
    assert!(credited_in_part(
        std::slice::from_ref(&fixed),
        CORS_ANY_ORIGIN.rule_id
    ));
    assert!(verified_ids(&[fixed]).contains(&CORS_ANY_ORIGIN.rule_id.to_owned()));
    // An app that sends no Access-Control-Allow-Origin was not asked the question.
    let silent = response("cors", 200, &[], "");
    assert!(!verified_ids(&[silent]).contains(&CORS_ANY_ORIGIN.rule_id.to_owned()));
    let echoed = response(
        "cors",
        200,
        &[("Access-Control-Allow-Origin", STRANGER)],
        "",
    );
    assert!(!verified_ids(&[echoed]).contains(&CORS_ANY_ORIGIN.rule_id.to_owned()));
}

#[test]
fn a_root_that_is_not_there_is_not_judged() {
    // An app that serves only an API answers its root with a 404: nothing there is a page.
    let mut root = good_root();
    root.status = 404;
    root.headers.clear();
    let answers = [good_home(), root];
    assert!(!ids(&evaluate(&answers)).contains(&SECURITY_HEADERS.rule_id));
    let credit = verified(&answers)
        .into_iter()
        .find(|v| v.check_id == SECURITY_HEADERS.rule_id)
        .expect("the health path alone is still credited");
    assert!(!credit.scope.contains("root"), "{}", credit.scope);
}

#[test]
fn a_cookie_the_root_page_sets_without_protection_is_found_there() {
    let mut root = good_root();
    root.headers
        .push(("set-cookie".into(), "prefs=dark; Path=/".into()));
    let answers = [good_home(), root];
    let found = evaluate(&answers)
        .into_iter()
        .find(|f| f.rule_id == COOKIE_ATTRIBUTES.rule_id)
        .expect("the root page's cookie is judged");
    assert!(
        found.description.contains("`prefs`, set by the root page"),
        "{}",
        found.description
    );
    assert!(
        !verified(&answers)
            .iter()
            .any(|v| v.check_id == COOKIE_ATTRIBUTES.rule_id)
    );
}

#[test]
fn an_error_answer_is_credited_only_when_the_app_was_made_to_give_one() {
    // ADR-056 (gap analysis 1.6). A missing page with no trace credited V13.4.2 and V16.5.1 in
    // 177 of about 190 trial builds; frameworks show their traces when code fails, not on a 404.
    let answer = |id: &str, status: u16, body: &str| ProbeResponse {
        id: id.to_owned(),
        status,
        headers: Vec::new(),
        body: body.to_owned(),
    };
    let credited = |answers: &[ProbeResponse]| -> Vec<String> {
        verified(answers)
            .into_iter()
            .filter(|v| v.check_id == ERROR_DETAIL_LEAK.rule_id)
            .flat_map(|v| v.requirement_ids)
            .collect()
    };
    let missing = answer("missing", 404, "<h1>Not Found</h1>");
    let to = |status: u16, body: &str| answer("bad-body POST /login", status, body);

    // The missing page alone, clean, credits nothing, and says why.
    assert!(credited(std::slice::from_ref(&missing)).is_empty());
    // Bodies refused as a method or a page it does not have are not errors either.
    for status in [404, 405, 501, 200, 302] {
        let answers = [missing.clone(), to(status, "nope")];
        assert!(credited(&answers).is_empty(), "{status}");
        let (ids, why) = error_answer_gap(&answers).expect("the gap is named");
        assert_eq!(ids, "V16.5.1, V13.4.2", "{status}");
        assert!(why.contains("`POST /login`"), "{why}");
    }
    // A clean "bad request" credits the generic error message, and not debug mode.
    for status in [400, 422] {
        let answers = [missing.clone(), to(status, r#"{"error":"bad request"}"#)];
        assert_eq!(credited(&answers), ["V16.5.1"], "{status}");
        assert_eq!(error_answer_gap(&answers).map(|g| g.0), Some("V13.4.2"));
    }
    // A clean failure credits both.
    let answers = [missing.clone(), to(500, "<h1>Something went wrong</h1>")];
    assert_eq!(credited(&answers), ["V13.4.2", "V16.5.1"]);
    assert_eq!(error_answer_gap(&answers), None);
    let scope = verified(&answers)
        .into_iter()
        .find(|v| v.check_id == ERROR_DETAIL_LEAK.rule_id)
        .unwrap()
        .scope;
    assert!(scope.contains("`POST /login` (500)"), "{scope}");
    assert!(credited_in_part(&answers, ERROR_DETAIL_LEAK.rule_id));

    // A trace in the error answer is a finding, and credits nothing.
    let leaking = [
        missing.clone(),
        to(
            400,
            "SyntaxError: Unexpected end of JSON input\n    at JSON.parse (<anonymous>)",
        ),
    ];
    assert!(credited(&leaking).is_empty());
    let found = evaluate(&leaking)
        .into_iter()
        .find(|f| f.rule_id == ERROR_DETAIL_LEAK.rule_id)
        .expect("the trace is found");
    assert!(
        found.description.contains("at `POST /login`"),
        "{}",
        found.description
    );
    // Nor does a clean error beside a missing page that leaks.
    let answers = [
        answer("missing", 404, "Traceback (most recent call last)"),
        to(500, "error"),
    ];
    assert!(credited(&answers).is_empty());
    // No answer to a bad body at all: nothing credited, and no gap claimed for a question
    // nobody asked.
    assert!(credited(std::slice::from_ref(&missing)).is_empty());
    assert_eq!(error_answer_gap(&[missing]), None);
}

#[test]
fn a_bad_body_goes_to_each_route_that_reads_one_once() {
    let routes = [
        ("POST".to_owned(), "/login".to_owned()),
        ("post".to_owned(), "/login".to_owned()),
        ("POST".to_owned(), "/api/notes".to_owned()),
        ("PUT".to_owned(), "/api/notes/{id}".to_owned()),
        ("POST".to_owned(), "/healthz".to_owned()),
        ("POST".to_owned(), "/".to_owned()),
        ("POST".to_owned(), "relative".to_owned()),
    ];
    let ids: Vec<String> = error_requests("/healthz", &routes)
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(ids, ["bad-body POST /login", "bad-body POST /api/notes"]);
}

#[test]
fn the_suite_asks_what_it_says_it_asks() {
    let requests = requests("/healthz");
    assert_eq!(
        requests.len(),
        6 + LISTING_PATHS.len()
            + UNUSED_METHODS.len()
            + 1
            + LOG_PATHS.len()
            + EXPOSED_PATHS.len()
            + 1
            + CONSOLES.len()
            + 3
            + 2
    );
    // A body that does not parse, to the health path and the root (ADR-056), signed out.
    for path in ["/healthz", "/"] {
        let request = requests
            .iter()
            .find(|r| r.id == format!("bad-body POST {path}"))
            .unwrap_or_else(|| panic!("no bad body sent to {path}"));
        assert_eq!(
            (request.method.as_str(), request.path.as_str()),
            ("POST", path)
        );
        assert_eq!(request.body.as_deref(), Some(BAD_BODY));
        assert!(serde_json::from_slice::<serde_json::Value>(BAD_BODY).is_err());
    }
    assert_eq!(
        super::requests("/")
            .iter()
            .filter(|r| r.id.starts_with(BAD_BODY_ID))
            .count(),
        1
    );
    // The root is asked as well as the health path, and only once when they are the same.
    assert!(requests.iter().any(|r| r.id == "root" && r.path == "/"));
    assert!(!super::requests("/").iter().any(|r| r.id == "root"));
    for path in EXPOSED_PATHS {
        let request = requests
            .iter()
            .find(|r| r.path == **path)
            .unwrap_or_else(|| panic!("{path} is never asked for"));
        assert_eq!(request.id, exposed_id(path), "{path}");
    }
    for method in UNUSED_METHODS {
        assert!(
            requests
                .iter()
                .any(|r| r.method == *method && r.id == method_id(method)),
            "{method}"
        );
    }
    assert!(
        requests
            .iter()
            .any(|r| r.id == "jsonp" && r.path == "/healthz?callback=svProbeJsonp")
    );
    assert!(requests.iter().any(|r| r.path == "/.git/HEAD"));
    // Every listing path is asked for, and each response can be found again by its id: the
    // check reads `id`, not `path`, so a request whose id it cannot rebuild is a dead probe.
    for path in LISTING_PATHS {
        let request = requests
            .iter()
            .find(|r| r.path == **path)
            .unwrap_or_else(|| panic!("{path} is never asked for"));
        assert_eq!(request.id, listing_id(path), "{path}");
    }
    assert!(requests.iter().any(|r| r.path == "/.git/config"));
    assert!(
        requests
            .iter()
            .any(|r| r.path == "/healthz" && r.headers.is_empty())
    );
    assert!(
        requests
            .iter()
            .any(|r| r.headers.iter().any(|(k, _)| k == "Origin"))
    );
    assert!(requests.iter().any(|r| r.path.contains("does-not-exist")));
    assert!(requests.iter().any(|r| r.method == "TRACE"), "{requests:?}");
}

// ---- Content-Type (V4.1.1) and a served .git folder (V13.4.1)

fn not_found() -> ProbeResponse {
    response("missing", 404, &[], "<p>No such page.</p>")
}

#[test]
fn a_response_with_no_content_type_is_found() {
    let bare = response("home", 200, &[("Content-Type", "")], "hello");
    let found = evaluate(&[bare.clone(), not_found()]);
    assert!(ids(&found).contains(&"probe.content-type"), "{found:?}");
    assert!(
        !verified(&[bare, not_found()])
            .iter()
            .any(|v| v.check_id == "probe.content-type")
    );
}

#[test]
fn a_text_type_with_no_charset_is_found() {
    let no_charset = response(
        "missing",
        404,
        &[("Content-Type", "text/html")],
        "<p>no</p>",
    );
    let found = evaluate(&[good_home(), no_charset]);
    assert_eq!(ids(&found), vec!["probe.content-type"], "{found:?}");
    assert!(found[0].description.contains("no charset"));
}

#[test]
fn json_needs_no_charset_and_an_empty_body_needs_no_type() {
    let json = response("home", 200, &[("Content-Type", "application/json")], "{}");
    let empty = response("missing", 404, &[("Content-Type", "")], "");
    assert!(!ids(&evaluate(&[json, empty])).contains(&"probe.content-type"));
}

#[test]
fn content_types_are_credited_only_when_both_answers_had_one() {
    let credited = |responses: &[ProbeResponse]| {
        verified(responses)
            .iter()
            .any(|v| v.check_id == "probe.content-type")
    };
    assert!(credited(&[good_home(), not_found()]));
    assert!(credited_in_part(
        &[good_home(), not_found()],
        "probe.content-type"
    ));
    // One answer judged is not the app's responses judged.
    assert!(!credited(&[good_home()]));
}

#[test]
fn a_served_git_folder_is_found_from_either_file() {
    let head = response(
        "git-head",
        200,
        &[("Content-Type", "text/plain; charset=utf-8")],
        "ref: refs/heads/main\n",
    );
    let config = response(
        "git-config",
        200,
        &[("Content-Type", "text/plain; charset=utf-8")],
        "[core]\n\trepositoryformatversion = 0\n",
    );
    let refused = |id: &str| response(id, 404, &[], "<p>No such page.</p>");
    for answers in [
        vec![head.clone(), refused("git-config")],
        vec![refused("git-head"), config.clone()],
    ] {
        let found = evaluate(&answers);
        assert_eq!(
            ids(&found),
            vec!["probe.source-control-exposed"],
            "{found:?}"
        );
        assert!(
            !verified(&answers)
                .iter()
                .any(|v| v.check_id == "probe.source-control-exposed")
        );
    }
}

#[test]
fn an_app_that_answers_everything_with_its_page_is_not_serving_git() {
    // A single-page app answers every path with 200 and its own page. That is not a .git folder.
    let page = |id: &str| response(id, 200, &[], "<html><div id=app></div></html>");
    let answers = [page("git-head"), page("git-config")];
    assert!(!ids(&evaluate(&answers)).contains(&"probe.source-control-exposed"));
    assert!(
        verified(&answers)
            .iter()
            .any(|v| v.check_id == "probe.source-control-exposed")
    );
    // And with one of the two unanswered, nothing is credited.
    assert!(
        !verified(&answers[..1])
            .iter()
            .any(|v| v.check_id == "probe.source-control-exposed")
    );
}

#[test]
fn the_error_page_is_held_to_the_same_rule() {
    let plain = response(
        "missing",
        404,
        &[("Content-Type", "text/plain")],
        "Not found",
    );
    let found = evaluate(&[good_home(), plain.clone()]);
    assert_eq!(ids(&found), vec!["probe.content-type"], "{found:?}");
    let untyped = response("missing", 404, &[("Content-Type", "")], "Not found");
    let found = evaluate(&[good_home(), untyped.clone()]);
    assert_eq!(ids(&found), vec!["probe.content-type"], "{found:?}");
    assert!(found[0].description.contains("no Content-Type"));
    for answers in [[good_home(), plain], [good_home(), untyped]] {
        assert!(
            !verified(&answers)
                .iter()
                .any(|v| v.check_id == "probe.content-type")
        );
    }
    // And the error page alone, however correct, is one answer.
    assert!(
        !verified(&[not_found()])
            .iter()
            .any(|v| v.check_id == "probe.content-type")
    );
}

#[test]
fn each_git_file_is_recognized_by_its_own_contents() {
    let text = [("Content-Type", "text/plain; charset=utf-8")];
    let refused = |id: &str| response(id, 404, &[], "<p>No such page.</p>");
    let head = response("git-head", 200, &text, "ref: refs/heads/trunk");
    let config = response("git-config", 200, &text, "[core]\n\tbare = false\n");
    assert!(
        ids(&evaluate(&[head, refused("git-config")])).contains(&"probe.source-control-exposed")
    );
    assert!(
        ids(&evaluate(&[refused("git-head"), config])).contains(&"probe.source-control-exposed")
    );
    // A sign-in page answered at those paths is not git, whatever its status.
    let login = |id: &str| response(id, 200, &[], "<form><input name=password></form>");
    let answers = [login("git-head"), login("git-config")];
    assert!(!ids(&evaluate(&answers)).contains(&"probe.source-control-exposed"));
}

// ---- Directory listings (V13.4.3)

#[test]
fn a_server_default_directory_listing_is_found() {
    // The three servers that actually do this, in the words each writes. Apache and nginx both
    // head the page "Index of /x"; Python's http.server writes "Directory listing for /x".
    for (server, body) in [
        (
            "nginx",
            "<html><head><title>Index of /static/</title></head><body><h1>Index of /static/</h1><hr><pre><a href=\"../\">../</a>\n<a href=\"backup.sql\">backup.sql</a>\n</pre></body></html>",
        ),
        (
            "Apache",
            "<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1><table><tr><td><a href=\"invoice.pdf\">invoice.pdf</a></td></tr></table></body></html>",
        ),
        (
            "python",
            "<!DOCTYPE HTML><html><head><title>Directory listing for /files/</title></head><body><h1>Directory listing for /files/</h1><ul><li><a href=\"keys.txt\">keys.txt</a></li></ul></body></html>",
        ),
    ] {
        let path = if body.contains("/static") {
            "/static/"
        } else if body.contains("/uploads") {
            "/uploads/"
        } else {
            "/files/"
        };
        let finding = directory_listing(&[response(&listing_id(path), 200, &[], body)])
            .unwrap_or_else(|| panic!("{server}'s listing of {path} was not found"));
        assert_eq!(finding.rule_id, "probe.directory-listing");
        assert!(
            finding.description.contains(path),
            "{}",
            finding.description
        );
        assert!(finding.requirement_ids.iter().any(|r| r == "V13.4.3"));
    }
}

#[test]
fn an_ordinary_page_full_of_links_is_not_a_directory_listing() {
    // Why this matches the servers' own words rather than "a page with several links in it":
    // every real page is a page with several links in it, and a finding on each one would make
    // the check worthless. A 404 page and a redirect must not count either.
    let pages = [
        response(
            &listing_id("/static/"),
            200,
            &[],
            "<h1>Our files</h1><a href='/a'>A</a><a href='/b'>B</a><a href='/c'>C</a>",
        ),
        response(
            &listing_id("/assets/"),
            404,
            &[],
            "<h1>Index of /assets/</h1>",
        ),
        response(&listing_id("/uploads/"), 301, &[], ""),
        response(&listing_id("/public/"), 403, &[], "Forbidden"),
    ];
    assert!(directory_listing(&pages).is_none());
}

#[test]
fn every_listing_path_is_actually_asked_for() {
    // The dead-probe guard, in the other direction from the suite test: a body that lists is
    // only found if a request for that path was made and its response can be found by id.
    for path in LISTING_PATHS {
        let body = format!("<h1>Index of {path}</h1>");
        assert!(
            directory_listing(&[response(&listing_id(path), 200, &[], &body)]).is_some(),
            "{path} is in the list but its response is never matched"
        );
    }
}

#[test]
fn a_listing_is_found_through_the_real_request_list() {
    // Closes the loop between what the suite asks for and what the check looks for. Both sides
    // compute the probe id, and if they ever compute it differently the probe is dead: the
    // request still goes out, the response still comes back, and nothing reads it. Nothing
    // fails, which is the whole danger — so this builds its responses from `requests()` itself
    // rather than from ids typed into the test.
    let requests = requests("/healthz");
    let responses: Vec<ProbeResponse> = requests
        .iter()
        .map(|r| {
            let body = if r.path == "/uploads/" {
                "<h1>Index of /uploads/</h1><pre><a href='tax-return.pdf'>tax-return.pdf</a></pre>"
            } else {
                "nothing here"
            };
            response(
                &r.id,
                if r.path == "/uploads/" { 200 } else { 404 },
                &[],
                body,
            )
        })
        .collect();
    let findings = evaluate(&responses);
    let listing = findings
        .iter()
        .find(|f| f.rule_id == "probe.directory-listing")
        .expect("the listing the suite asked for was never read back");
    assert!(
        listing.description.contains("/uploads/"),
        "{}",
        listing.description
    );
}

#[test]
fn finding_no_listing_credits_nothing() {
    // Six guesses and three signatures. Finding nothing is not evidence that nothing lists, so
    // V13.4.3 must never appear among the confirmed checks.
    let clean: Vec<ProbeResponse> = LISTING_PATHS
        .iter()
        .map(|p| response(&listing_id(p), 404, &[], "not found"))
        .collect();
    assert!(directory_listing(&clean).is_none());
    let credited = verified(&clean);
    assert!(
        !credited
            .iter()
            .any(|v| v.requirement_ids.iter().any(|r| r == "V13.4.3")),
        "a clean sweep of six guesses credited V13.4.3: {credited:?}"
    );
}

// ---- GraphQL and WebSocket

fn gql(id: &str, status: u16, body: &str) -> ProbeResponse {
    response(id, status, &[("Content-Type", "application/json")], body)
}

const PLAIN_OK: &str = r#"{"data":{"__typename":"Query"}}"#;

#[test]
fn graphql_questions_are_asked_only_of_a_path_that_answers_graphql() {
    let (f, v, na) = evaluate_api(
        &[
            gql("graphql-plain", 404, "not found"),
            gql("graphql-introspection", 404, "not found"),
            gql("graphql-aliases", 404, "not found"),
        ],
        Some(false),
    );
    assert!(f.is_empty() && v.is_empty(), "{f:?} {v:?}");
    assert!(
        na.iter()
            .any(|(id, _)| id.contains("V4.3.1") && id.contains("V4.3.2"))
    );
}

#[test]
fn introspection_is_judged_against_whether_the_api_is_meant_for_others() {
    let open = [
        gql("graphql-plain", 200, PLAIN_OK),
        gql(
            "graphql-introspection",
            200,
            r#"{"data":{"__schema":{"queryType":{"name":"Query"}}}}"#,
        ),
    ];
    let (f, _, _) = evaluate_api(&open, Some(false));
    assert!(
        f.iter().any(|x| x.rule_id == "probe.graphql-introspection"),
        "{f:?}"
    );
    let (f, v, _) = evaluate_api(&open, Some(true));
    assert!(
        f.is_empty(),
        "an API meant for others may be introspected: {f:?}"
    );
    assert!(
        v.iter()
            .any(|x| x.check_id == "probe.graphql-introspection")
    );
    let (f, v, na) = evaluate_api(&open, None);
    assert!(
        f.is_empty()
            && !v
                .iter()
                .any(|x| x.check_id == "probe.graphql-introspection")
    );
    assert!(
        na.iter()
            .any(|(id, why)| id == "V4.3.2" && why.contains("public-api")),
        "{na:?}"
    );

    // Refused introspection is credited whatever the API is for.
    let closed = [
        gql("graphql-plain", 200, PLAIN_OK),
        gql(
            "graphql-introspection",
            200,
            r#"{"errors":[{"message":"introspection is disabled"}]}"#,
        ),
    ];
    let (f, v, _) = evaluate_api(&closed, Some(false));
    assert!(f.is_empty());
    assert!(
        v.iter()
            .any(|x| x.check_id == "probe.graphql-introspection")
    );
}

#[test]
fn a_thousand_aliases_run_is_a_finding_and_read_from_the_start_of_the_answer() {
    // Bodies are kept to their first few thousand characters, so the answer to a thousand
    // aliases is cut off long before `a999`. The check must not need the end of it.
    let mut body = String::from(r#"{"data":{"#);
    for i in 0..1000 {
        body.push_str(&format!(r#""a{i}":"Query","#));
    }
    let cut: String = body.chars().take(4000).collect();
    assert!(
        !cut.contains("a999"),
        "the fixture is not cut the way real bodies are"
    );
    let (f, v, _) = evaluate_api(
        &[
            gql("graphql-plain", 200, PLAIN_OK),
            gql("graphql-aliases", 200, &cut),
        ],
        Some(false),
    );
    assert!(
        f.iter()
            .any(|x| x.rule_id == "probe.graphql-no-amount-limit"),
        "{f:?}"
    );
    assert!(
        !v.iter()
            .any(|x| x.check_id == "probe.graphql-no-amount-limit")
    );
}

#[test]
fn a_refused_alias_flood_is_credited_only_beside_a_working_plain_query() {
    let refused = gql(
        "graphql-aliases",
        400,
        r#"{"errors":[{"message":"query has too many aliases"}]}"#,
    );
    let (f, v, _) = evaluate_api(
        &[gql("graphql-plain", 200, PLAIN_OK), refused.clone()],
        Some(false),
    );
    assert!(f.is_empty());
    assert!(
        v.iter()
            .any(|x| x.check_id == "probe.graphql-no-amount-limit")
    );
    // Without the plain query working, the refusal proves nothing.
    let (_, v, _) = evaluate_api(&[gql("graphql-plain", 500, "boom"), refused], Some(false));
    assert!(
        !v.iter()
            .any(|x| x.check_id == "probe.graphql-no-amount-limit")
    );
}

#[test]
fn a_websocket_is_judged_only_when_a_plain_handshake_upgrades() {
    let upgraded = |id: &str| response(id, 101, &[("Upgrade", "websocket")], "");
    let (f, _, _) = evaluate_api(
        &[upgraded("ws-no-origin"), upgraded("ws-foreign-origin")],
        None,
    );
    assert!(
        f.iter()
            .any(|x| x.rule_id == "probe.websocket-origin-unchecked"),
        "{f:?}"
    );

    let (f, v, _) = evaluate_api(
        &[
            upgraded("ws-no-origin"),
            response("ws-foreign-origin", 403, &[], ""),
        ],
        None,
    );
    assert!(f.is_empty());
    assert!(
        v.iter()
            .any(|x| x.check_id == "probe.websocket-origin-unchecked")
    );
    // One handshake on one path (ADR-053, Later).
    assert!(
        v.iter()
            .all(|x| x.check_id != "probe.websocket-origin-unchecked" || x.in_part)
    );

    // An endpoint that upgrades nothing: a refused foreign handshake means nothing.
    let (f, v, na) = evaluate_api(
        &[
            response("ws-no-origin", 404, &[], ""),
            response("ws-foreign-origin", 404, &[], ""),
        ],
        None,
    );
    assert!(f.is_empty() && v.is_empty());
    assert!(na.iter().any(|(id, _)| id == "V4.4.2"), "{na:?}");
}

#[test]
fn a_partial_answer_with_errors_is_a_limit_not_a_run() {
    // A cost limiter that stops partway answers with some data *and* an error. That is the
    // limit working, and the second witness for reading `errors` at all.
    let partial = gql(
        "graphql-aliases",
        200,
        r#"{"data":{"a0":"Query","a1":"Query"},"errors":[{"message":"query cost limit reached"}]}"#,
    );
    let (f, v, _) = evaluate_api(&[gql("graphql-plain", 200, PLAIN_OK), partial], Some(false));
    assert!(
        !f.iter()
            .any(|x| x.rule_id == "probe.graphql-no-amount-limit"),
        "{f:?}"
    );
    assert!(
        v.iter()
            .any(|x| x.check_id == "probe.graphql-no-amount-limit")
    );
}

#[test]
fn an_empty_schema_beside_an_error_is_introspection_refused() {
    // The same shape for introspection, and the second witness for reading `errors`: a
    // `__schema` key that came back empty, beside the error saying why, is a refusal.
    let refused = gql(
        "graphql-introspection",
        200,
        r#"{"data":{"__schema":null},"errors":[{"message":"introspection is disabled"}]}"#,
    );
    let (f, _, _) = evaluate_api(&[gql("graphql-plain", 200, PLAIN_OK), refused], Some(false));
    assert!(
        !f.iter().any(|x| x.rule_id == "probe.graphql-introspection"),
        "{f:?}"
    );
}

#[test]
fn an_api_meant_for_others_may_be_introspected() {
    // The second witness for the `public-api` claim, on its own: an open schema is not a fault
    // for an API other programs are meant to use, and must never be reported as one.
    let (f, _, _) = evaluate_api(
        &[
            gql("graphql-plain", 200, PLAIN_OK),
            gql(
                "graphql-introspection",
                200,
                r#"{"data":{"__schema":{"queryType":{"name":"Query"}}}}"#,
            ),
        ],
        Some(true),
    );
    assert!(f.is_empty(), "{f:?}");
}

#[test]
fn a_websocket_that_refuses_every_handshake_is_not_credited() {
    // The second witness for the WebSocket setup proof: an endpoint refusing the plain
    // handshake and the foreign one alike is not checking origins, it is not working, and the
    // foreign refusal must not be read as the control.
    let (f, v, na) = evaluate_api(
        &[
            response("ws-no-origin", 403, &[], ""),
            response("ws-foreign-origin", 403, &[], ""),
        ],
        None,
    );
    assert!(f.is_empty());
    assert!(
        !v.iter()
            .any(|x| x.check_id == "probe.websocket-origin-unchecked"),
        "{v:?}"
    );
    assert!(na.iter().any(|(id, _)| id == "V4.4.2"));
}

#[test]
fn a_websocket_accepting_any_origin_is_found() {
    let up = |id: &str| response(id, 101, &[("Upgrade", "websocket")], "");
    let (f, v, _) = evaluate_api(&[up("ws-no-origin"), up("ws-foreign-origin")], Some(true));
    assert!(
        f.iter()
            .any(|x| x.rule_id == "probe.websocket-origin-unchecked"),
        "{f:?}"
    );
    assert!(
        !v.iter()
            .any(|x| x.check_id == "probe.websocket-origin-unchecked")
    );
}

#[test]
fn the_api_requests_are_only_made_for_what_the_app_has() {
    assert!(api_requests(None, None).is_empty());
    let only_ws = api_requests(None, Some("/ws"));
    assert!(only_ws.iter().all(|r| r.id.starts_with("ws-")));
    let gql_reqs = api_requests(Some("/graphql"), None);
    let aliases = gql_reqs.iter().find(|r| r.id == "graphql-aliases").unwrap();
    assert!(aliases.body_text().contains("a999:__typename"));
    // And every id the evaluation reads is one a request really carries.
    let all = api_requests(Some("/graphql"), Some("/ws"));
    for id in [
        "graphql-plain",
        "graphql-introspection",
        "graphql-aliases",
        "ws-no-origin",
        "ws-foreign-origin",
    ] {
        assert!(
            all.iter().any(|r| r.id == id),
            "{id} is read but never asked"
        );
    }
}

// --------------------------------------------------------------------------------------------
// Methods, JSONP, documentation and monitoring pages, version numbers, and two browser headers

fn verified_ids(responses: &[ProbeResponse]) -> Vec<String> {
    verified(responses)
        .into_iter()
        .map(|v| v.check_id)
        .collect()
}

/// Whether `rule_id` was credited, and every credit it gave is in part (ADR-053, Later).
fn credited_in_part(responses: &[ProbeResponse], rule_id: &str) -> bool {
    let credits: Vec<crate::Verified> = verified(responses)
        .into_iter()
        .filter(|v| v.check_id == rule_id)
        .collect();
    !credits.is_empty() && credits.iter().all(|v| v.in_part)
}

/// The start of Werkzeug 3.1.9's console page, as `render_console_html` writes it, with its
/// per-process secret replaced.
const WERKZEUG_CONSOLE: &str = "<!doctype html>\n<html lang=en>\n  <head>\n    <title>Console // Werkzeug Debugger</title>\n    <link rel=\"stylesheet\" href=\"?__debugger__=yes&amp;cmd=resource&amp;f=style.css\">\n    <script>\n      var CONSOLE_MODE = true,\n          EVALEX = true,\n          EVALEX_TRUSTED = false,\n          SECRET = \"sv-test\";\n    </script>\n  </head>\n  <body style=\"background-color: #fff\">\n    <div class=\"debugger\">\n<h1>Interactive Console</h1>\n<div class=\"explanation\">\nIn this console you can execute Python expressions in the context of the\napplication.";

/// Rails 8.1.4's properties page, as `Rails::Info.to_html` writes the table inside it.
const RAILS_PROPERTIES: &str = "<h1>Properties</h1><table><tr><td class=\"name\">Rails version</td><td class=\"value\">8.1.4</td></tr><tr><td class=\"name\">Ruby version</td><td class=\"value\">3.3.6</td></tr><tr><td class=\"name\">Environment</td><td class=\"value\">development</td></tr></table>";

/// The start of Go's pprof index, as `indexTmplExecute` writes it.
const PPROF_INDEX: &str = "<html>\n<head>\n<title>/debug/pprof/</title>\n<style>\n.profile-name{\n\tdisplay:inline-block;\n\twidth:6rem;\n}\n</style>\n</head>\n<body>\n/debug/pprof/\n<br>\n<p>Set debug=1 as a query parameter to export in legacy text format</p>\n<br>\nTypes of profiles available:\n<table>";

/// Ignition's health check, as Laravel writes the array `HealthCheckController` returns.
const IGNITION_HEALTH: &str = "{\"can_execute_commands\":true}";

/// Symfony's profiler search results: the title from `base.html.twig`, the heading from
/// `results.html.twig`.
const SYMFONY_RESULTS: &str = "<!DOCTYPE html>\n<html>\n    <head>\n        <meta charset=\"UTF-8\" />\n        <meta name=\"robots\" content=\"noindex,nofollow\" />\n        <title>Symfony Profiler</title>\n    </head>\n    <body>\n        <h2>Profile Search</h2>\n        <h2>10 results found</h2>";

/// Phoenix LiveDashboard's layout, from `dash.html.heex`, as its home page renders it.
const LIVE_DASHBOARD: &str = "<!DOCTYPE html>\n<html lang=\"en\" phx-socket=\"/live\">\n  <head>\n    <script>\n      window.LiveDashboard = {\n        customHooks: {},\n      }\n    </script>\n    <title>Home · Phoenix LiveDashboard</title>\n  </head>\n  <body>\n      <footer class=\"flex-shrink-0\">\n        Phoenix LiveDashboard was made with love by\n        <a href=\"https://dashbit.co/\" target=\"_blank\" class=\"footer-dashbit\">";

#[test]
fn a_development_console_that_answers_is_found_by_its_own_words() {
    let bodies = [
        WERKZEUG_CONSOLE,
        RAILS_PROPERTIES,
        PPROF_INDEX,
        IGNITION_HEALTH,
        SYMFONY_RESULTS,
        LIVE_DASHBOARD,
    ];
    assert_eq!(
        CONSOLES.len(),
        bodies.len(),
        "a console with no page to test"
    );
    // Each path as its tool's source serves it: a path written wrong asks where nothing is.
    assert_eq!(
        CONSOLES.iter().map(|c| c.path).collect::<Vec<_>>(),
        [
            "/console",
            "/rails/info/properties",
            "/debug/pprof/",
            "/_ignition/health-check",
            "/_profiler/empty/search/results?limit=10",
            "/dev/dashboard/home",
        ]
    );
    for (console, body) in CONSOLES.iter().zip(bodies) {
        let findings = evaluate(&[
            good_home(),
            response(&console_id(console.path), 200, &[], body),
        ]);
        assert_eq!(
            ids(&findings),
            vec!["probe.development-console-open"],
            "{}",
            console.path
        );
        assert!(
            findings[0].description.contains(console.path),
            "{}",
            findings[0].description
        );
        assert_eq!(findings[0].requirement_ids, vec!["V15.2.3", "V13.4.2"]);
        // Refused, the same page is nothing: a status alone is never read as the console.
        let refused = evaluate(&[
            good_home(),
            response(&console_id(console.path), 404, &[], body),
        ]);
        assert!(ids(&refused).is_empty(), "{}", console.path);
    }
    // Every console is asked for.
    let asked = requests("/");
    for console in CONSOLES {
        assert!(
            asked
                .iter()
                .any(|r| r.id == console_id(console.path) && r.path == console.path)
        );
    }
}

#[test]
fn a_page_that_is_not_a_console_is_not_read_as_one() {
    // An app that answers every path with its home page, and one of Werkzeug's traceback pages,
    // which shares the title's second half but is not the console, and a page that talks about
    // Rails without being its information page.
    for (path, body) in [
        (
            "/console",
            "<html><title>Shop</title><h1>Welcome</h1></html>",
        ),
        (
            "/console",
            "<title>ZeroDivisionError // Werkzeug Debugger</title><h1>ZeroDivisionError</h1>",
        ),
        (
            "/rails/info/properties",
            "<p>Rails version 8.1 is out. Environment matters.</p>",
        ),
        // A blog post about pprof, Ignition switched off (Laravel's 404 page), Symfony's
        // profiler refused by the app's own page, and a dashboard of the app's own.
        (
            "/debug/pprof/",
            "<title>Profiling Go with /debug/pprof/</title><p>Types of profiles available: heap, cpu</p>",
        ),
        (
            "/_ignition/health-check",
            "<html><title>Not Found</title><div>404 | Not Found</div></html>",
        ),
        (
            "/_profiler/empty/search/results?limit=10",
            "<title>Symfony Profiler</title><p>The profiler is disabled.</p>",
        ),
        (
            "/dev/dashboard/home",
            "<html><title>Dashboard</title><h1>Your dashboard</h1><footer>Made with love</footer></html>",
        ),
        // A page about LiveDashboard showing its script, without its footer.
        (
            "/dev/dashboard/home",
            "<h1>Custom hooks</h1><pre>window.LiveDashboard.registerCustomHooks({})</pre>",
        ),
    ] {
        let findings = evaluate(&[good_home(), response(&console_id(path), 200, &[], body)]);
        assert!(ids(&findings).is_empty(), "{path}: {body}");
    }
}

#[test]
fn a_page_that_answers_an_unused_method_is_found_for_each_method() {
    for method in UNUSED_METHODS {
        let findings = evaluate(&[
            good_home(),
            response(&method_id(method), 200, &[], "<html>hello</html>"),
        ]);
        assert_eq!(
            ids(&findings),
            vec!["probe.unused-method-accepted"],
            "{method}"
        );
        assert!(findings[0].description.contains(method));
    }
    // WebDAV's own success answer counts too.
    let findings = evaluate(&[good_home(), response("method-propfind", 207, &[], "<d/>")]);
    assert_eq!(ids(&findings), vec!["probe.unused-method-accepted"]);
}

#[test]
fn refused_methods_are_not_found_and_not_credited() {
    let answers = [
        good_home(),
        response("method-delete", 405, &[], "method not allowed"),
        response("method-propfind", 404, &[], "not found"),
    ];
    assert!(evaluate(&answers).is_empty(), "{:?}", evaluate(&answers));
    assert!(!verified_ids(&answers).contains(&UNUSED_METHOD.rule_id.to_owned()));
}

/// What came back of the value, written into a body the way each kind of app writes it.
fn echoed(between: &str) -> String {
    format!("{REFLECTION_MARK}{between}{REFLECTION_END}")
}

fn reflected_ids(id: &str, content_type: &str, body: &str) -> Vec<String> {
    evaluate(&[
        good_home(),
        response(id, 200, &[("Content-Type", content_type)], body),
    ])
    .into_iter()
    .filter(|f| f.rule_id.starts_with("probe.reflected"))
    .map(|f| f.rule_id)
    .collect()
}

#[test]
fn the_value_is_sent_to_three_pages_encoded_as_a_browser_sends_it() {
    let asked = requests("/healthz");
    let path = |id: &str| {
        asked
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("{id} is never asked"))
            .path
            .clone()
    };
    let value = format!("{REFLECTION_MARK}%3C%22%27{REFLECTION_END}");
    assert_eq!(path(REFLECT_HOME), format!("/healthz?q={value}"));
    assert_eq!(path(REFLECT_ROOT), format!("/?q={value}"));
    assert_eq!(path(REFLECT_MISSING), format!("{MISSING_PATH}-{value}"));
    // Nothing in a request line may be a raw quote, angle bracket, or space.
    for r in asked.iter().filter(|r| r.id.starts_with("reflect-")) {
        assert!(!r.path.contains(['<', '"', '\'', ' ']), "{}", r.path);
        assert_eq!(r.method, "GET");
        assert!(r.body.is_none() && r.headers.is_empty());
    }
    // The root is the health path when they are the same, and asked once.
    let at_root = requests("/");
    assert!(!at_root.iter().any(|r| r.id == REFLECT_ROOT));
    assert!(
        at_root
            .iter()
            .any(|r| r.id == REFLECT_HOME && r.path == format!("/?q={value}"))
    );
    // A health path with its own query gets the value after `&`.
    assert!(
        requests("/health?full=1")
            .iter()
            .any(|r| r.id == REFLECT_HOME && r.path == format!("/health?full=1&q={value}"))
    );
}

#[test]
fn a_page_that_writes_the_value_back_unencoded_is_found() {
    for (id, body) in [
        (
            REFLECT_HOME,
            format!("<p>You searched for {}</p>", echoed("<\"'")),
        ),
        (
            REFLECT_ROOT,
            format!("<h1>Results: {}</h1>", echoed("<\"'")),
        ),
        // An error page repeating the path it was asked for.
        (
            REFLECT_MISSING,
            format!(
                "<p>No page at /sv-probe-does-not-exist-9f2a-{}</p>",
                echoed("<\"'")
            ),
        ),
        // An app that stopped writing at the `<`, so the end never came back.
        (REFLECT_HOME, format!("<p>{REFLECTION_MARK}<\"'</p>")),
    ] {
        assert_eq!(
            reflected_ids(id, "text/html; charset=utf-8", &body),
            ["probe.reflected-unencoded"],
            "{body}"
        );
    }
    let findings = evaluate(&[
        good_home(),
        response(
            REFLECT_MISSING,
            404,
            &[("Content-Type", "text/html")],
            &echoed("<\"'"),
        ),
    ]);
    let f = findings
        .iter()
        .find(|f| f.rule_id == "probe.reflected-unencoded")
        .unwrap();
    assert_eq!(f.requirement_ids, ["V1.2.1"]);
    assert!(
        f.description.contains("a page that does not exist"),
        "{}",
        f.description
    );
}

#[test]
fn a_page_that_encodes_the_value_or_does_not_repeat_it_is_not_found() {
    for body in [
        format!("<p>You searched for {}</p>", echoed("&lt;&quot;&#39;")),
        format!("<p>You searched for {}</p>", echoed("&lt;&#34;&#x27;")),
        // Written back as it was sent, still percent-encoded, in a link.
        format!("<a href=\"/?q={}\">again</a>", echoed("%3C%22%27")),
        // Taken out altogether.
        format!("<p>You searched for {}</p>", echoed("")),
        // The quotes as they are and the `<` encoded: harmless in text, harmful in an
        // attribute, and which it is is not read, so not judged.
        format!("<p>You searched for {}</p>", echoed("&lt;\"'")),
        "<p>No results.</p>".to_owned(),
    ] {
        assert!(
            reflected_ids(REFLECT_HOME, "text/html", &body).is_empty(),
            "{body}"
        );
    }
}

#[test]
fn json_with_the_quote_unescaped_is_found_and_escaped_json_is_not() {
    let raw = format!("{{\"query\": \"{}\"}}", echoed("<\"'"));
    assert_eq!(
        reflected_ids(REFLECT_HOME, "application/json", &raw),
        ["probe.reflected-json-unescaped"]
    );
    for body in [
        format!("{{\"query\": \"{}\"}}", echoed("<\\\"'")),
        format!("{{\"query\": \"{}\"}}", echoed("\\u003c\\u0022\\u0027")),
    ] {
        assert!(
            reflected_ids(REFLECT_HOME, "application/json", &body).is_empty(),
            "{body}"
        );
    }
    let findings = evaluate(&[
        good_home(),
        response(
            REFLECT_HOME,
            200,
            &[("Content-Type", "application/json")],
            &raw,
        ),
    ]);
    let f = findings
        .iter()
        .find(|f| f.rule_id == "probe.reflected-json-unescaped")
        .unwrap();
    assert_eq!(f.requirement_ids, ["V1.2.3"]);
}

#[test]
fn an_answer_that_is_neither_a_page_nor_json_is_not_judged() {
    let body = echoed("<\"'");
    assert!(reflected_ids(REFLECT_HOME, "text/plain", &body).is_empty());
    assert!(
        reflected_ids(REFLECT_HOME, "", &body).is_empty(),
        "no type said"
    );
    // Only the three reflection answers are read for it: the same text in another answer is
    // that answer's business.
    assert!(reflected_ids("home", "text/html", &body).is_empty());
}

#[test]
fn writing_the_value_back_encoded_is_never_credit() {
    let encoded = response(
        REFLECT_HOME,
        200,
        &[("Content-Type", "text/html")],
        &echoed("&lt;&quot;&#39;"),
    );
    for v in verified(&[good_home(), encoded]) {
        assert!(
            !v.requirement_ids.iter().any(|r| r.starts_with("V1.2.")),
            "{v:?}"
        );
    }
    assert!(
        unassessed_requirements(false)
            .iter()
            .any(|(ids, why)| ids.contains("V1.2") && why.contains("credits nothing")),
    );
}

#[test]
fn jsonp_is_found_however_the_framework_wraps_it() {
    for (content_type, body) in [
        (
            "text/javascript; charset=utf-8",
            "/**/ typeof svProbeJsonp === 'function' && svProbeJsonp({\"ok\":true});",
        ),
        (
            "application/javascript; charset=utf-8",
            "svProbeJsonp({\"ok\":true})",
        ),
    ] {
        let findings = evaluate(&[
            good_home(),
            response("jsonp", 200, &[("Content-Type", content_type)], body),
        ]);
        assert_eq!(ids(&findings), vec!["probe.jsonp-enabled"], "{body}");
    }
}

#[test]
fn a_callback_ignored_or_only_echoed_in_a_page_is_not_jsonp() {
    for (content_type, body) in [
        ("application/json; charset=utf-8", "{\"ok\":true}"),
        // An HTML page that writes the address it was asked for back into itself.
        (
            "text/html; charset=utf-8",
            "<a href=\"/?callback=svProbeJsonp(\">again</a>",
        ),
    ] {
        let findings = evaluate(&[
            good_home(),
            response("jsonp", 200, &[("Content-Type", content_type)], body),
        ]);
        assert!(findings.is_empty(), "{body}: {findings:?}");
    }
}

#[test]
fn documentation_and_monitoring_pages_are_found_by_what_they_say() {
    let docs = evaluate(&[
        good_home(),
        response(
            &exposed_id("/openapi.json"),
            200,
            &[("Content-Type", "application/json")],
            "{\"openapi\":\"3.1.0\",\"info\":{},\"paths\":{\"/api/notes\":{}}}",
        ),
    ]);
    assert_eq!(ids(&docs), vec!["probe.docs-or-monitoring-exposed"]);
    assert_eq!(docs[0].severity, Severity::Low);
    assert!(docs[0].description.contains("/openapi.json"));

    let metrics = evaluate(&[
        good_home(),
        response(
            &exposed_id("/metrics"),
            200,
            &[("Content-Type", "text/plain; charset=utf-8")],
            "# HELP process_cpu_seconds_total Total CPU.\n# TYPE process_cpu_seconds_total counter\nprocess_cpu_seconds_total 1.5\n",
        ),
        response(
            &exposed_id("/swagger-ui.html"),
            200,
            &[],
            "<div id=\"swagger-ui\"></div>",
        ),
    ]);
    assert_eq!(ids(&metrics), vec!["probe.docs-or-monitoring-exposed"]);
    assert_eq!(metrics[0].severity, Severity::Medium);
    assert!(metrics[0].description.contains("Prometheus"));
    assert!(metrics[0].description.contains("/swagger-ui.html"));
}

#[test]
fn a_front_page_served_for_every_path_is_not_documentation() {
    let answers: Vec<ProbeResponse> = std::iter::once(good_home())
        .chain(EXPOSED_PATHS.iter().map(|path| {
            response(
                &exposed_id(path),
                200,
                &[],
                "<html><div id=root></div><script src=/app.js></script></html>",
            )
        }))
        .collect();
    assert!(evaluate(&answers).is_empty(), "{:?}", evaluate(&answers));
    // And a page that is really there, refused, is not open.
    let refused = [
        good_home(),
        response(
            &exposed_id("/actuator"),
            401,
            &[("Content-Type", "application/json")],
            "{\"_links\":{\"self\":{\"href\":\"/actuator\"}}}",
        ),
    ];
    assert!(evaluate(&refused).is_empty());
}

#[test]
fn version_numbers_are_found_in_headers_and_on_error_pages() {
    for extra in [
        response("missing", 404, &[("Server", "nginx/1.25.3")], "not found"),
        response(
            "missing",
            404,
            &[("X-Powered-By", "PHP/8.3.0")],
            "not found",
        ),
        response(
            "missing",
            404,
            &[],
            "<address>Apache/2.4.58 (Debian) Server at app Port 8080</address>",
        ),
    ] {
        let findings = evaluate(&[good_home(), extra.clone()]);
        assert_eq!(ids(&findings), vec!["probe.version-disclosed"], "{extra:?}");
    }
}

#[test]
fn a_product_named_without_its_version_is_not_found() {
    for extra in [
        response("missing", 404, &[("Server", "nginx")], "not found"),
        response("missing", 404, &[("X-Powered-By", "Express")], "not found"),
        // A version on a page that worked is the app's own content, not an error page.
        response("method-delete", 405, &[], "Method not allowed"),
    ] {
        let findings = evaluate(&[good_home(), extra.clone()]);
        assert!(findings.is_empty(), "{extra:?}: {findings:?}");
    }
    let page = response(
        "home",
        200,
        &[],
        "<p>Built with Django 5.0 and nginx/1.25</p>",
    );
    let mut home = good_home();
    home.body = page.body;
    assert!(evaluate(&[home]).is_empty());
}

#[test]
fn a_page_without_an_opener_policy_is_found_and_one_with_it_credited() {
    for value in ["", "unsafe-none"] {
        let mut home = good_home();
        home.headers
            .retain(|(k, _)| k != "cross-origin-opener-policy");
        if !value.is_empty() {
            home.headers
                .push(("cross-origin-opener-policy".into(), value.into()));
        }
        let findings = evaluate(&[home.clone()]);
        assert_eq!(
            ids(&findings),
            vec!["probe.opener-policy-missing"],
            "{value:?}"
        );
        assert!(!verified_ids(&[home]).contains(&OPENER_POLICY.rule_id.to_owned()));
    }
    // The error page is a document too.
    let missing = response(
        "missing",
        404,
        &[("Cross-Origin-Opener-Policy", "")],
        "<html>not here</html>",
    );
    assert_eq!(
        ids(&evaluate(&[good_home(), missing])),
        vec!["probe.opener-policy-missing"]
    );
    let mut popups = good_home();
    popups
        .headers
        .retain(|(k, _)| k != "cross-origin-opener-policy");
    popups.headers.push((
        "cross-origin-opener-policy".into(),
        "same-origin-allow-popups".into(),
    ));
    assert!(evaluate(&[popups.clone()]).is_empty());
    assert!(credited_in_part(
        std::slice::from_ref(&popups),
        OPENER_POLICY.rule_id
    ));
    assert!(verified_ids(&[popups]).contains(&OPENER_POLICY.rule_id.to_owned()));
}

#[test]
fn an_answer_that_is_not_a_page_needs_no_opener_policy_and_earns_no_credit() {
    let json = response(
        "home",
        200,
        &[
            ("Content-Type", "application/json"),
            ("Cross-Origin-Opener-Policy", ""),
        ],
        "{\"ok\":true}",
    );
    assert!(!ids(&evaluate(std::slice::from_ref(&json))).contains(&"probe.opener-policy-missing"));
    assert!(!verified_ids(&[json]).contains(&OPENER_POLICY.rule_id.to_owned()));
}

#[test]
fn a_policy_that_reports_nowhere_is_found_and_one_that_reports_credited() {
    for policy in [
        "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    ] {
        let mut home = good_home();
        home.headers.retain(|(k, _)| k != "content-security-policy");
        home.headers
            .push(("content-security-policy".into(), policy.into()));
        assert_eq!(
            ids(&evaluate(&[home.clone()])),
            vec!["probe.csp-no-report"],
            "{policy}"
        );
        assert!(!verified_ids(&[home]).contains(&CSP_REPORTING.rule_id.to_owned()));
    }
    assert!(verified_ids(&[good_home()]).contains(&CSP_REPORTING.rule_id.to_owned()));
    assert!(credited_in_part(&[good_home()], CSP_REPORTING.rule_id));
}

#[test]
fn with_no_policy_at_all_reporting_is_neither_found_nor_credited() {
    let mut home = good_home();
    home.headers.retain(|(k, _)| k != "content-security-policy");
    let found = ids(&evaluate(&[home.clone()]))
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert!(found.contains(&"probe.security-headers".to_owned()));
    assert!(!found.contains(&"probe.csp-no-report".to_owned()));
    assert!(!verified_ids(&[home]).contains(&CSP_REPORTING.rule_id.to_owned()));
}

// Second witnesses, each of a different shape from the first, so that no guard above is known
// to work from one test alone.

#[test]
fn a_search_page_that_repeats_the_callback_is_not_jsonp() {
    let page = response("jsonp", 200, &[], "<p>No results for svProbeJsonp(</p>");
    assert!(evaluate(&[good_home(), page]).is_empty());
}

#[test]
fn a_script_that_never_calls_the_callback_is_not_jsonp() {
    let script = response(
        "jsonp",
        200,
        &[("Content-Type", "text/javascript; charset=utf-8")],
        "window.ready = true;",
    );
    assert!(evaluate(&[good_home(), script]).is_empty());
}

#[test]
fn documentation_behind_a_sign_in_is_not_open() {
    let answers = [
        good_home(),
        response(
            &exposed_id("/v3/api-docs"),
            403,
            &[("Content-Type", "application/json")],
            "{\"openapi\":\"3.0.1\",\"paths\":{}}",
        ),
    ];
    assert!(evaluate(&answers).is_empty());
}

#[test]
fn a_health_answer_on_a_monitoring_path_is_not_monitoring() {
    let answers = [
        good_home(),
        response(
            &exposed_id("/metrics"),
            200,
            &[("Content-Type", "text/plain; charset=utf-8")],
            "ok",
        ),
    ];
    assert!(evaluate(&answers).is_empty());
}

#[test]
fn a_product_header_with_a_dot_and_no_number_is_not_a_version() {
    for (name, value) in [
        ("X-Powered-By", "Next.js"),
        ("X-Generator", "Drupal (https://www.drupal.org)"),
    ] {
        let findings = evaluate(&[
            good_home(),
            response("missing", 404, &[(name, value)], "not found"),
        ]);
        assert!(findings.is_empty(), "{value}: {findings:?}");
    }
}

#[test]
fn a_version_in_what_the_app_shows_is_not_a_version_leak() {
    let mut home = good_home();
    home.body = "<footer>Powered by nginx/1.25 and PHP/8.3</footer>".into();
    assert!(evaluate(&[home]).is_empty());
}

#[test]
fn a_plain_text_error_needs_no_opener_policy() {
    let missing = response(
        "missing",
        404,
        &[
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Cross-Origin-Opener-Policy", ""),
        ],
        "not found",
    );
    assert!(evaluate(&[good_home(), missing]).is_empty());
}

#[test]
fn an_opener_policy_that_isolates_nothing_is_found_on_the_error_page() {
    let missing = response(
        "missing",
        404,
        &[("Cross-Origin-Opener-Policy", "unsafe-none")],
        "<html>not here</html>",
    );
    assert_eq!(
        ids(&evaluate(&[good_home(), missing])),
        vec!["probe.opener-policy-missing"]
    );
}

#[test]
fn a_policy_with_frame_ancestors_and_no_report_is_still_found() {
    let home = response(
        "home",
        200,
        &[
            (
                "Content-Security-Policy",
                "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'",
            ),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
        ],
        "<html>hi</html>",
    );
    assert_eq!(ids(&evaluate(&[home])), vec!["probe.csp-no-report"]);
}

#[test]
fn a_bare_page_earns_neither_header_credit() {
    let bare = [response("home", 200, &[], "hi")];
    let credited = verified_ids(&bare);
    assert!(
        !credited.contains(&CSP_REPORTING.rule_id.to_owned()),
        "{credited:?}"
    );
    // With no page that is a document at all, there is nothing to credit the opener policy on.
    let json_only = [
        response("home", 200, &[("Content-Type", "application/json")], "{}"),
        response(
            "missing",
            404,
            &[("Content-Type", "application/json")],
            "{}",
        ),
    ];
    assert!(!verified_ids(&json_only).contains(&OPENER_POLICY.rule_id.to_owned()));
}

#[test]
fn iis_naming_its_framework_is_not_a_version() {
    let missing = response("missing", 404, &[("X-Powered-By", "ASP.NET")], "not found");
    assert!(evaluate(&[good_home(), missing]).is_empty());
}

fn component(name: &str, ecosystem: &str) -> crate::sbom::Component {
    crate::sbom::Component {
        name: name.to_owned(),
        version: "1.0.0".to_owned(),
        ecosystem: ecosystem.to_owned(),
        source: crate::sbom::VersionSource::Locked,
    }
}

#[test]
fn a_hosted_backend_in_the_packages_is_named_as_out_of_reach() {
    for (name, ecosystem, service) in [
        ("@supabase/supabase-js", "npm", "Supabase"),
        ("@supabase/ssr", "npm", "Supabase"),
        ("supabase", "PyPI", "Supabase"),
        ("firebase", "npm", "Firebase"),
        ("@react-native-firebase/auth", "npm", "Firebase"),
        ("firebase-admin", "PyPI", "Firebase"),
    ] {
        let packages = [component("react", "npm"), component(name, ecosystem)];
        let (ids, why) = hosted_backend_gap(&packages).expect(name);
        assert_eq!(ids, "V8, V6", "{name}");
        assert!(why.contains(&format!("uses {service} (`{name}`)")), "{why}");
        let rules = if service == "Firebase" {
            "firestore.rules"
        } else {
            "supabase/migrations/"
        };
        assert!(why.contains(rules), "{why}");
    }
    // Packages that only share a word with them, and an app with none, name no gap.
    for name in ["supabase-mock", "firebase-tools-lite", "flask", "express"] {
        assert_eq!(
            hosted_backend_gap(&[component(name, "npm")]),
            None,
            "{name}"
        );
    }
    assert_eq!(hosted_backend_gap(&[]), None);
    // The list `sv run` and the report both print carries it, after the others.
    let gaps = running_app_gaps(false, &[], &[component("@supabase/supabase-js", "npm")]);
    assert_eq!(gaps.last().map(|g| g.0), Some("V8, V6"), "{gaps:?}");
    assert_eq!(gaps.len(), unassessed_requirements(false).len() + 1);
    assert_eq!(
        running_app_gaps(true, &[], &[]).len(),
        unassessed_requirements(true).len()
    );
}

#[test]
fn a_log_file_served_to_anybody_is_found_by_its_lines() {
    // ADR-072, V16.4.2. Each common shape of log line, at three addresses.
    for (path, body) in [
        (
            "/storage/logs/laravel.log",
            "[2026-10-09 12:00:01] production.ERROR: Undefined index: email\n[2026-10-09 12:00:02] production.INFO: Signed in a@example.test\n[2026-10-09 12:00:03] production.WARNING: Slow query\n",
        ),
        (
            "/logs/app.log",
            "{\"level\":\"info\",\"time\":\"2026-10-09T12:00:01Z\",\"msg\":\"request\"}\n{\"level\":\"error\",\"time\":\"2026-10-09T12:00:02Z\",\"msg\":\"db\"}\n{\"level\":\"info\",\"time\":\"2026-10-09T12:00:03Z\",\"msg\":\"request\"}\n",
        ),
        (
            "/error.log",
            "Oct  9 12:00:01 app node[1]: started\nOct  9 12:00:02 app node[1]: token=abc\nOct  9 12:00:03 app node[1]: stopped\n",
        ),
        (
            "/npm-debug.log",
            "10.0.0.1 - - [09/Oct/2026:12:00:01 +0000] \"GET / HTTP/1.1\" 200\n10.0.0.1 - - [09/Oct/2026:12:00:02 +0000] \"GET /a HTTP/1.1\" 200\n10.0.0.1 - - [09/Oct/2026:12:00:03 +0000] \"GET /b HTTP/1.1\" 404\n",
        ),
    ] {
        let found = evaluate(&[
            good_home(),
            response(&log_id(path), 200, &[("Content-Type", "text/plain")], body),
        ]);
        let f = found
            .iter()
            .find(|f| f.rule_id == "probe.log-file-served")
            .unwrap_or_else(|| panic!("{path}: {found:?}"));
        assert_eq!(f.severity, Severity::High);
        assert!(f.description.contains(path), "{}", f.description);
        assert_eq!(f.requirement_ids, ["V16.4.2"]);
    }
}

#[test]
fn a_page_that_is_not_a_log_is_never_taken_for_one() {
    let three_lines = "[2026-10-09 12:00:01] a\n[2026-10-09 12:00:02] b\n[2026-10-09 12:00:03] c\n";
    for (path, status, body) in [
        // The app's own page, answered at every address.
        (
            "/logs/app.log",
            200,
            "<!doctype html><html><body>Welcome</body></html>",
        ),
        // The app's own page again, with a list whose rows carry a date and a word a log also
        // uses: HTML, so never a log.
        (
            "/log/production.log",
            200,
            "<!doctype html><html><body><ul>\n<li>2026-10-09 12:00 Opening hours: more info</li>\n<li>2026-10-08 09:30 New menu: more info</li>\n<li>2026-10-07 18:15 Events: more info</li>\n</ul></body></html>",
        ),
        // A listing of a logs folder, whose rows carry dates: the listing check's to find.
        (
            "/logs/",
            200,
            "<html><body><a href=\"app.log\">app.log</a> 2026-10-09 12:00  4K\n<a href=\"b.log\">b.log</a> 2026-10-09 12:01  4K\n<a href=\"c.log\">c.log</a> 2026-10-09 12:02  4K\n</body></html>",
        ),
        // Two lines are not enough.
        (
            "/error.log",
            200,
            "[2026-10-09 12:00:01] a\n[2026-10-09 12:00:02] b\n",
        ),
        // Not served.
        ("/debug.log", 404, three_lines),
        ("/log/", 403, three_lines),
    ] {
        let found = evaluate(&[good_home(), response(&log_id(path), status, &[], body)]);
        assert!(
            !ids(&found).contains(&"probe.log-file-served"),
            "{path} {status}: {found:?}"
        );
    }
}
