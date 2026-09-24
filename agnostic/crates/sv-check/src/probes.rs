//! What to ask a running app, and what its answers mean.
//!
//! Deliberately split from the thing that makes the requests. This file decides what to ask and how to
//! read the reply; `sv-run` knows about containers and networks. That way the judgement is testable
//! against recorded responses without Docker, which is most of it.
//!
//! # These probes sign in as nobody
//!
//! Every request here is made by somebody who has not logged in, because `sv` does not know how to log
//! in to an app it did not write. v1 seeds users and probes as them; doing that for an arbitrary app
//! means the manifest saying how, which is its own piece of work.
//!
//! The consequence is stated rather than hidden: authorisation, session handling and anything behind a
//! login are **not assessed**, and `unassessed_requirements` names them. A probe suite that quietly
//! covers only the front door, and reports nothing, reads exactly like one that found nothing wrong.

use crate::finding::{Confidence, Finding, Location, Severity};

/// One request to make against the running app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeRequest {
    /// Ties the answer back to the question.
    pub id: String,
    /// The HTTP method. Anything is allowed: the requests are spoken directly over a socket rather
    /// than made with a client that has opinions about which verbs exist.
    pub method: String,
    /// Path on the app, beginning with `/`.
    pub path: String,
    /// Extra request headers, as name and value.
    pub headers: Vec<(String, String)>,
}

/// What came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResponse {
    pub id: String,
    pub status: u16,
    /// Response headers, names lowercased.
    pub headers: Vec<(String, String)>,
    /// The start of the body — enough to recognise a stack trace, not enough to copy a page.
    pub body: String,
}

impl ProbeResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A path that will not exist, to see what the app says when something goes wrong.
const MISSING_PATH: &str = "/sv-probe-does-not-exist-9f2a";
/// An origin the app has certainly never heard of.
const STRANGER: &str = "https://sv-probe-stranger.invalid";

/// The requests this suite needs.
pub fn requests(health_path: &str) -> Vec<ProbeRequest> {
    vec![
        ProbeRequest {
            id: "home".into(),
            method: "GET".into(),
            path: health_path.to_owned(),
            headers: Vec::new(),
        },
        ProbeRequest {
            id: "cors".into(),
            method: "GET".into(),
            path: health_path.to_owned(),
            headers: vec![("Origin".into(), STRANGER.into())],
        },
        ProbeRequest {
            id: "missing".into(),
            method: "GET".into(),
            path: MISSING_PATH.into(),
            headers: Vec::new(),
        },
        ProbeRequest {
            id: "trace".into(),
            method: "TRACE".into(),
            path: health_path.to_owned(),
            headers: vec![("X-Probe-Echo".into(), "sv-probe-echo-value".into())],
        },
    ]
}

/// Requirements this suite cannot speak to, and why. Never folded into a pass.
pub fn unassessed_requirements() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "V8, V7",
            "Authorisation and session handling need a signed-in user, and `sv` does not know how to \
             sign in to an app it did not write.",
        ),
        (
            "V4.2",
            "Cross-site request forgery is about what a logged-in browser can be made to do, so it \
             needs a session too.",
        ),
        (
            "V5, V1.2",
            "Whether input is validated or escaped needs requests that send data and a way to see \
             where it comes back out, which means knowing the app's forms and routes.",
        ),
    ]
}

/// What is fixed about a check: everything except the words describing this particular answer.
///
/// Grouped rather than passed one by one, so adding a field to a finding does not add a parameter to
/// every call site.
struct Rule {
    rule_id: &'static str,
    confidence: Confidence,
    requirement_ids: &'static [&'static str],
    cwe: &'static [&'static str],
    impact: &'static str,
    fix: &'static str,
}

fn finding(about: &Rule, title: &str, severity: Severity, description: String) -> Finding {
    Finding {
        rule_id: about.rule_id.to_owned(),
        title: title.to_owned(),
        severity,
        confidence: about.confidence,
        location: Location {
            file: "the running app".into(),
            line: 1,
        },
        secret: None,
        requirement_ids: about
            .requirement_ids
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        cwe: about.cwe.iter().map(|s| (*s).to_owned()).collect(),
        description,
        impact: about.impact.to_owned(),
        fix: about.fix.to_owned(),
    }
}

/// Reads the answers.
pub fn evaluate(responses: &[ProbeResponse]) -> Vec<Finding> {
    let mut out = Vec::new();
    let find = |id: &str| responses.iter().find(|r| r.id == id);

    if let Some(home) = find("home") {
        out.extend(security_headers(home));
        out.extend(cookie_attributes(home));
    }
    if let Some(cors) = find("cors") {
        out.extend(reflected_origin(cors));
    }
    if let Some(missing) = find("missing") {
        out.extend(error_page_leak(missing));
    }
    if let Some(trace) = find("trace") {
        out.extend(trace_enabled(trace));
    }
    out.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    out
}

const SECURITY_HEADERS: Rule = Rule {
    rule_id: "probe.security-headers",
    confidence: Confidence::High,
    // One id per header this rule looks for, and no others. It used to cite V3.4.1 (Strict-
    // Transport-Security) and V14.4.1 (which is not a requirement at all): invented rather than
    // looked up, and invisible until the report tried to resolve them.
    requirement_ids: &["V3.4.3", "V3.4.4", "V3.4.5", "V3.4.6"],
    cwe: &["CWE-693", "CWE-1021"],
    impact: "These are the instructions a browser follows to protect the person using the app. \
             Without them the browser does what a page tells it, including a page somebody else wrote.",
    fix: "Set them once, in whatever sits in front of every response, rather than per route.",
};

/// Headers a browser needs in order to protect the people using the app.
fn security_headers(response: &ProbeResponse) -> Option<Finding> {
    let mut missing = Vec::new();
    if response.header("content-security-policy").is_none() {
        missing.push("Content-Security-Policy, which limits what a page may load and run");
    }
    if response.header("x-content-type-options").is_none() {
        missing.push("X-Content-Type-Options, which stops a browser guessing a file's type");
    }
    let framing_denied = response.header("x-frame-options").is_some_and(|v| {
        v.to_lowercase().contains("deny") || v.to_lowercase().contains("sameorigin")
    }) || response
        .header("content-security-policy")
        .is_some_and(|v| v.to_lowercase().contains("frame-ancestors"));
    if !framing_denied {
        missing.push("a rule against being shown inside somebody else's page");
    }
    if response.header("referrer-policy").is_none() {
        missing.push("Referrer-Policy, which stops addresses leaking to other sites");
    }
    if missing.is_empty() {
        return None;
    }
    Some(finding(
        &SECURITY_HEADERS,
        "The app is missing headers a browser relies on",
        Severity::Medium,
        format!("The page came back without {}.", missing.join("; without ")),
    ))
}

const COOKIE_ATTRIBUTES: Rule = Rule {
    rule_id: "probe.cookie-attributes",
    confidence: Confidence::High,
    // V3.3.4 is HttpOnly, V3.3.2 is SameSite. It used to cite the CORS and CSP requirements.
    requirement_ids: &["V3.3.2", "V3.3.4"],
    cwe: &["CWE-1004", "CWE-1275"],
    impact: "A cookie a script can read is a session that any injected script can take. One with no \
             SameSite is a session another site can use on the owner's behalf.",
    fix: "Set HttpOnly and SameSite on every cookie the app issues, and Secure once it is served \
          over HTTPS.",
};

/// A cookie that a script can read, or that travels to another site, is a session waiting to be taken.
fn cookie_attributes(response: &ProbeResponse) -> Option<Finding> {
    let cookies: Vec<&str> = response
        .headers
        .iter()
        .filter(|(k, _)| k == "set-cookie")
        .map(|(_, v)| v.as_str())
        .collect();
    if cookies.is_empty() {
        return None;
    }
    let mut problems = Vec::new();
    for cookie in &cookies {
        let lower = cookie.to_lowercase();
        let name = cookie.split('=').next().unwrap_or("a cookie").trim();
        if !lower.contains("httponly") {
            problems.push(format!(
                "`{name}` can be read by any script on the page (no HttpOnly)"
            ));
        }
        if !lower.contains("samesite") {
            problems.push(format!(
                "`{name}` does not say when it may travel to other sites (no SameSite)"
            ));
        }
    }
    if problems.is_empty() {
        return None;
    }
    Some(finding(
        &COOKIE_ATTRIBUTES,
        "A cookie is set without the attributes that protect it",
        Severity::High,
        problems.join("; "),
    ))
}

const CORS_ANY_ORIGIN: Rule = Rule {
    rule_id: "probe.cors-any-origin",
    confidence: Confidence::High,
    // V3.4.2 is the one: Access-Control-Allow-Origin must be a fixed value, or the Origin
    // header must be checked against an allow-list. Exactly what this probe tests.
    requirement_ids: &["V3.4.2"],
    cwe: &["CWE-942"],
    impact: "A site the owner has never heard of can make the browser fetch this app's pages as the \
             person using it, and read what comes back.",
    fix: "List the origins allowed to call this app and compare against that list, rather than \
          echoing back whatever arrives.",
};

/// An app that echoes back whatever Origin it is given is not enforcing one.
fn reflected_origin(response: &ProbeResponse) -> Option<Finding> {
    let allowed = response.header("access-control-allow-origin")?;
    let reflects = allowed == STRANGER;
    let wildcard = allowed.trim() == "*";
    if !reflects && !wildcard {
        return None;
    }
    let credentials = response
        .header("access-control-allow-credentials")
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));
    // Reflecting an origin *and* allowing credentials is the combination that actually hands data over.
    let severity = if credentials {
        Severity::High
    } else {
        Severity::Medium
    };
    Some(finding(
        &CORS_ANY_ORIGIN,
        if reflects {
            "The app accepts whatever site asks it to"
        } else {
            "The app allows any site to read its responses"
        },
        severity,
        if reflects {
            format!(
                "Asked with an Origin of {STRANGER}, which does not exist, the app answered \
                 `Access-Control-Allow-Origin: {allowed}`{}.",
                if credentials {
                    " and allowed credentials with it"
                } else {
                    ""
                }
            )
        } else {
            "The app answers `Access-Control-Allow-Origin: *`, so any site may read its responses."
                .to_owned()
        },
    ))
}

/// Traces that a language or framework prints when something goes wrong.
const TRACE_MARKERS: &[&str] = &[
    "Traceback (most recent call last)",
    "    at ",
    "stack trace",
    "Werkzeug Debugger",
    "django.core.exceptions",
    "org.springframework",
    "java.lang.",
    "goroutine ",
    "panic:",
    "ActionController::",
    "Fatal error:",
    "Warning: mysqli",
];

const ERROR_DETAIL_LEAK: Rule = Rule {
    rule_id: "probe.error-detail-leak",
    confidence: Confidence::High,
    // V16.5.1 is the generic error message, V13.4.2 is debug mode left on in production. It used
    // to cite sensitive data in URLs and session termination, neither of which this looks at.
    requirement_ids: &["V13.4.2", "V16.5.1"],
    cwe: &["CWE-209", "CWE-497"],
    impact: "A stack trace names the framework, its version, the file layout and often the query \
             that failed. It is the first thing somebody looking for a way in would like to read.",
    fix: "Turn off debug mode wherever the app is reachable by anyone else, and return a plain error \
          page with the detail kept in the log.",
};

/// What the app says when asked for something that is not there.
fn error_page_leak(response: &ProbeResponse) -> Option<Finding> {
    let found: Vec<&str> = TRACE_MARKERS
        .iter()
        .copied()
        .filter(|marker| response.body.contains(marker))
        .collect();
    if found.is_empty() {
        return None;
    }
    Some(finding(
        &ERROR_DETAIL_LEAK,
        "An error page shows how the app is built",
        Severity::Medium,
        format!(
            "Asking for a page that does not exist produced a response containing {}.",
            found
                .iter()
                .map(|m| format!("`{}`", m.trim()))
                .collect::<Vec<_>>()
                .join(" and ")
        ),
    ))
}

const TRACE_ENABLED: Rule = Rule {
    rule_id: "probe.trace-enabled",
    confidence: Confidence::High,
    // V13.4.4 is TRACE by name.
    requirement_ids: &["V13.4.4"],
    cwe: &["CWE-16"],
    impact: "Anything the browser attaches to a request — cookies, authorisation headers — comes \
             back in a readable body, which turns a scripting flaw elsewhere into a way of reading \
             them.",
    fix: "Turn TRACE off. Almost nothing needs it, and the web server in front of the app can refuse \
          it in one line.",
};

/// TRACE asks the server to echo the request back, headers and all.
fn trace_enabled(response: &ProbeResponse) -> Option<Finding> {
    // Only a server that actually performed the trace echoes the header back in its body.
    let echoed = response.body.contains("sv-probe-echo-value");
    if !(200..300).contains(&response.status) || !echoed {
        return None;
    }
    Some(finding(
        &TRACE_ENABLED,
        "The app echoes requests back with TRACE",
        Severity::Medium,
        "A TRACE request came back with its own headers in the body, including one this probe \
         invented."
            .to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(id: &str, status: u16, headers: &[(&str, &str)], body: &str) -> ProbeResponse {
        ProbeResponse {
            id: id.into(),
            status,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_lowercase(), (*v).to_owned()))
                .collect(),
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
                    "default-src 'self'; frame-ancestors 'none'",
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
                ("Content-Security-Policy", "frame-ancestors 'none'"),
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
                    "default-src 'self'; frame-ancestors 'none'",
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
                    "default-src 'self'; frame-ancestors 'none'",
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
                    "default-src 'self'; frame-ancestors 'none'",
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
        // The suite signs in as nobody. Saying nothing about authorisation would read exactly like
        // finding nothing wrong with it.
        let unassessed = unassessed_requirements();
        assert!(!unassessed.is_empty());
        assert!(
            unassessed.iter().any(|(ids, _)| ids.contains("V8")),
            "authorisation must be named: {unassessed:?}"
        );
        assert!(
            unassessed.iter().any(|(_, why)| why.contains("sign in")),
            "the reason authorisation is unreachable must be named: {unassessed:?}"
        );
    }

    #[test]
    fn the_suite_asks_what_it_says_it_asks() {
        let requests = requests("/healthz");
        assert_eq!(requests.len(), 4);
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
}
