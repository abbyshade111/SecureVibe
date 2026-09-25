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
    /// A body, sent with its `Content-Length`. Only the signed-in probes send one: signing in, and
    /// creating the thing another user must not be able to read.
    pub body: Option<String>,
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
            body: None,
        },
        ProbeRequest {
            id: "cors".into(),
            method: "GET".into(),
            path: health_path.to_owned(),
            headers: vec![("Origin".into(), STRANGER.into())],
            body: None,
        },
        ProbeRequest {
            id: "missing".into(),
            method: "GET".into(),
            path: MISSING_PATH.into(),
            headers: Vec::new(),
            body: None,
        },
        ProbeRequest {
            id: "trace".into(),
            method: "TRACE".into(),
            path: health_path.to_owned(),
            headers: vec![("X-Probe-Echo".into(), "sv-probe-echo-value".into())],
            body: None,
        },
        ProbeRequest {
            id: "git-head".into(),
            method: "GET".into(),
            path: "/.git/HEAD".into(),
            headers: Vec::new(),
            body: None,
        },
        ProbeRequest {
            id: "git-config".into(),
            method: "GET".into(),
            path: "/.git/config".into(),
            headers: Vec::new(),
            body: None,
        },
    ]
}

/// Requirements this suite cannot speak to, and why. Never folded into a pass.
///
/// `signed_in_ran` is whether the signed-in probes (`signed_in.rs`) asked too. When they did, they
/// say for themselves what they reached and what they could not, so authorization, sessions and
/// forgery are not repeated here as untouched.
pub fn unassessed_requirements(signed_in_ran: bool) -> Vec<(&'static str, &'static str)> {
    let mut out = Vec::new();
    if !signed_in_ran {
        out.push((
            "V8, V7",
            "Authorization and session handling need a signed-in user. `sv` signs in only when \
             securevibe.toml says how, under [stack.run.users], and this one does not.",
        ));
        // V3.5.1 is the request forgery requirement in ASVS 5.0. This line cited V4.2 until
        // 25 September 2026, which is HTTP message structure validation — a different subject.
        out.push((
            "V3.5.1",
            "Cross-site request forgery is about what a signed-in browser can be made to do, so it \
             needs a session too.",
        ));
    }
    out.push((
        "V5, V1.2",
        "Whether input is validated or escaped needs requests that send data and a way to see \
         where it comes back out, which means knowing the app's forms and routes.",
    ));
    out
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
    out.extend(content_type(&with_bodies(responses)));
    out.extend(source_control_exposed(responses));
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

/// What the answers show the app is doing right.
///
/// The strongest positive evidence anything here produces, and the only kind that is direct: a
/// header that came back really did come back. The rest of the workspace can say a rule did not
/// fire over the code it read; this can say the app, running, answered correctly.
///
/// Fail closed on a missing answer. A probe that got no reply establishes nothing about the app,
/// and a rule whose response is absent is skipped rather than credited — which is why each arm
/// looks up its own response instead of assuming the suite ran.
pub fn verified(responses: &[ProbeResponse]) -> Vec<crate::Verified> {
    let mut out = Vec::new();
    let find = |id: &str| responses.iter().find(|r| r.id == id);

    if let Some(home) = find("home") {
        if security_headers(home).is_none() {
            out.push(crate::Verified::new(
                SECURITY_HEADERS.rule_id,
                SECURITY_HEADERS.requirement_ids,
                "the app's answer on its health path, as somebody not signed in".to_owned(),
            ));
        }
        // Only when there was a cookie to judge. No cookie is not a correct cookie.
        let sets_a_cookie = home.headers.iter().any(|(k, _)| k == "set-cookie");
        if sets_a_cookie && cookie_attributes(home).is_none() {
            out.push(crate::Verified::new(
                COOKIE_ATTRIBUTES.rule_id,
                COOKIE_ATTRIBUTES.requirement_ids,
                "every cookie the app set on that answer".to_owned(),
            ));
        }
    }
    if let Some(cors) = find("cors") {
        // And only when the app answered the CORS question at all. An app that sends no
        // Access-Control-Allow-Origin has not been shown to check origins; it has been shown not to
        // be asked. Those read the same in a report unless this line is here.
        if cors.header("access-control-allow-origin").is_some() && reflected_origin(cors).is_none()
        {
            out.push(crate::Verified::new(
                CORS_ANY_ORIGIN.rule_id,
                CORS_ANY_ORIGIN.requirement_ids,
                "an Origin the app has never heard of".to_owned(),
            ));
        }
    }
    if let Some(missing) = find("missing")
        && error_page_leak(missing).is_none()
    {
        out.push(crate::Verified::new(
            ERROR_DETAIL_LEAK.rule_id,
            ERROR_DETAIL_LEAK.requirement_ids,
            "what the app says when asked for a page that is not there".to_owned(),
        ));
    }
    if let Some(trace) = find("trace")
        && trace_enabled(trace).is_none()
    {
        out.push(crate::Verified::new(
            TRACE_ENABLED.rule_id,
            TRACE_ENABLED.requirement_ids,
            "a TRACE request carrying a header this probe invented".to_owned(),
        ));
    }
    // Only over the page and the error, both of which have to have answered with a body: one
    // answer judged is not the app's responses judged.
    let judged: Vec<&ProbeResponse> = with_bodies(responses)
        .into_iter()
        .filter(|r| r.id == "home" || r.id == "missing")
        .collect();
    if judged.len() == 2 && content_type(&judged).is_none() {
        out.push(crate::Verified::new(
            CONTENT_TYPE.rule_id,
            CONTENT_TYPE.requirement_ids,
            "the app's page and its answer for a page that is not there".to_owned(),
        ));
    }
    // Both asked and both answered, or nothing is shown about the folder.
    if find("git-head").is_some()
        && find("git-config").is_some()
        && source_control_exposed(responses).is_none()
    {
        out.push(crate::Verified::new(
            SOURCE_CONTROL.rule_id,
            SOURCE_CONTROL.requirement_ids,
            "requests for /.git/HEAD and /.git/config".to_owned(),
        ));
    }
    out
}

/// The responses that carried a body, which are the ones a Content-Type is owed for.
fn with_bodies(responses: &[ProbeResponse]) -> Vec<&ProbeResponse> {
    responses
        .iter()
        .filter(|r| !r.body.trim().is_empty())
        .collect()
}

const CONTENT_TYPE: Rule = Rule {
    rule_id: "probe.content-type",
    confidence: Confidence::High,
    // V4.1.1 is a Content-Type on every response with a body, with the charset.
    requirement_ids: &["V4.1.1"],
    cwe: &["CWE-436"],
    impact: "A browser left to guess what a response is can guess wrong, and treat text an attacker \
             wrote as a page to run.",
    fix: "Send a Content-Type on every response with a body, with `; charset=utf-8` on text types.",
};

/// Every response with a body names its type, and a text type names its character set.
fn content_type(responses: &[&ProbeResponse]) -> Option<Finding> {
    let mut problems = Vec::new();
    for r in responses {
        match r.header("content-type") {
            None => problems.push(format!("the answer for `{}` had no Content-Type", r.id)),
            Some(t) => {
                let lower = t.to_lowercase();
                if lower.starts_with("text/") && !lower.contains("charset=") {
                    problems.push(format!(
                        "the answer for `{}` was `{t}`, with no charset",
                        r.id
                    ));
                }
            }
        }
    }
    if problems.is_empty() {
        return None;
    }
    Some(finding(
        &CONTENT_TYPE,
        "A response does not say what it is",
        Severity::Low,
        format!("{}.", problems.join("; ")),
    ))
}

const SOURCE_CONTROL: Rule = Rule {
    rule_id: "probe.source-control-exposed",
    confidence: Confidence::High,
    // V13.4.1 is source control metadata left where it can be fetched.
    requirement_ids: &["V13.4.1"],
    cwe: &["CWE-527"],
    impact: "The `.git` folder holds the whole history of the code, including anything ever \
             committed and later deleted, such as a password.",
    fix: "Deploy a build rather than the repository, or refuse every path under `/.git/` in the \
          web server.",
};

/// A `.git` folder served over the web answers with what only git writes.
fn source_control_exposed(responses: &[ProbeResponse]) -> Option<Finding> {
    let served = |id: &str, looks: &dyn Fn(&str) -> bool| {
        responses
            .iter()
            .find(|r| r.id == id)
            .is_some_and(|r| (200..300).contains(&r.status) && looks(&r.body))
    };
    let head = served("git-head", &|b: &str| {
        b.trim_start().starts_with("ref: refs/")
    });
    let config = served("git-config", &|b: &str| b.contains("[core]"));
    if !head && !config {
        return None;
    }
    let what: Vec<&str> = [(head, "/.git/HEAD"), (config, "/.git/config")]
        .iter()
        .filter(|(f, _)| *f)
        .map(|(_, p)| *p)
        .collect();
    Some(finding(
        &SOURCE_CONTROL,
        "The app serves its source control folder",
        Severity::High,
        format!(
            "The app answered {} with git's own contents.",
            what.join(" and ")
        ),
    ))
}

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
        headers.retain(|(k, v)| !(k == "content-type" && v.is_empty()));
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
        // The suite signs in as nobody. Saying nothing about authorization would read exactly like
        // finding nothing wrong with it.
        let unassessed = unassessed_requirements(false);
        assert!(!unassessed.is_empty());
        assert!(
            unassessed.iter().any(|(ids, _)| ids.contains("V8")),
            "authorisation must be named: {unassessed:?}"
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

    #[test]
    fn the_suite_asks_what_it_says_it_asks() {
        let requests = requests("/healthz");
        assert_eq!(requests.len(), 6);
        assert!(requests.iter().any(|r| r.path == "/.git/HEAD"));
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
            ids(&evaluate(&[head, refused("git-config")]))
                .contains(&"probe.source-control-exposed")
        );
        assert!(
            ids(&evaluate(&[refused("git-head"), config]))
                .contains(&"probe.source-control-exposed")
        );
        // A sign-in page answered at those paths is not git, whatever its status.
        let login = |id: &str| response(id, 200, &[], "<form><input name=password></form>");
        let answers = [login("git-head"), login("git-config")];
        assert!(!ids(&evaluate(&answers)).contains(&"probe.source-control-exposed"));
    }
}
