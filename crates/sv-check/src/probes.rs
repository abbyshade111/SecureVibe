//! What to ask a running app, and what its answers mean.
//!
//! Deliberately split from the thing that makes the requests. This file decides what to ask and how to
//! read the reply; `sv-run` knows about containers and networks. That way the judgment is testable
//! against recorded responses without Docker, which is most of it.
//!
//! # These probes sign in as nobody
//!
//! Every request here is made by somebody who has not logged in, because `sv` does not know how to log
//! in to an app it did not write. v1 seeds users and probes as them; doing that for an arbitrary app
//! means the manifest saying how, which is its own piece of work.
//!
//! The consequence is stated rather than hidden: authorization, session handling and anything behind a
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
    /// creating the thing another user must not be able to read. Bytes rather than text, so a file
    /// that is not text (an archive) can be uploaded as it is.
    pub body: Option<Vec<u8>>,
}

impl ProbeRequest {
    /// The body read as text, for the checks and the test apps that read a form or JSON. Bytes that
    /// are not text come back replaced, so this is never used to send anything.
    pub fn body_text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(self.body.as_deref().unwrap_or_default())
    }
}

/// How much of an answer's body the run keeps: enough to recognize a stack trace, not enough to copy
/// a page out of somebody's app. The running app's answers are cut to this in `sv-run`.
pub const KEPT_CHARS: usize = 4000;

/// What came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResponse {
    pub id: String,
    pub status: u16,
    /// Response headers, names lowercased.
    pub headers: Vec<(String, String)>,
    /// The start of the body — enough to recognize a stack trace, not enough to copy a page.
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
pub(crate) const STRANGER: &str = "https://sv-probe-stranger.invalid";
/// A body that is not JSON, sent as JSON, to make the app's code fail where it reads one (ADR-056).
/// A body that does not parse cannot create anything.
const BAD_BODY: &[u8] = b"{\"sv-probe\": ";
/// The start of the id of each request that sends it, followed by its method and path.
const BAD_BODY_ID: &str = "bad-body";

/// A request sending `BAD_BODY`, signed out, with an id that says where it went.
fn bad_body_request(method: &str, path: &str) -> ProbeRequest {
    ProbeRequest {
        id: format!("{BAD_BODY_ID} {method} {path}"),
        method: method.to_owned(),
        path: path.to_owned(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: Some(BAD_BODY.to_vec()),
    }
}

/// `BAD_BODY` sent to the routes stackvet.toml names that read a body (sign-in, sign-up, the
/// record `owned` creates), each as `(method, path)`, beyond the health path and the root, which
/// `requests` sends it to. A path with a placeholder in it (`{id}`) is left out, as is one already
/// asked.
pub fn error_requests(health_path: &str, routes: &[(String, String)]) -> Vec<ProbeRequest> {
    let mut out: Vec<ProbeRequest> = Vec::new();
    for (method, path) in routes {
        let asked_already =
            method.eq_ignore_ascii_case("POST") && (path == health_path || path == "/");
        if !path.starts_with('/') || path.contains('{') || asked_already {
            continue;
        }
        let request = bad_body_request(&method.to_ascii_uppercase(), path);
        if !out.iter().any(|r| r.id == request.id) {
            out.push(request);
        }
    }
    out
}

/// Whether an answer is an error the app produced: a request it could not use (400, 422), or its
/// own failure (500 to 599). 501 is a method it does not have, which says nothing about its errors.
fn is_error_answer(status: u16) -> bool {
    matches!(status, 400 | 422) || is_server_error(status)
}

fn is_server_error(status: u16) -> bool {
    (500..600).contains(&status) && status != 501
}

/// The answers to `BAD_BODY`.
fn bad_body_answers(responses: &[ProbeResponse]) -> Vec<&ProbeResponse> {
    responses
        .iter()
        .filter(|r| r.id.starts_with(BAD_BODY_ID))
        .collect()
}

/// What the report says when no request drew an error, so V16.5.1 and V13.4.2 were not credited
/// (ADR-056). `None` when one did, or when no request sending `BAD_BODY` was answered at all.
pub fn error_answer_gap(responses: &[ProbeResponse]) -> Option<(&'static str, String)> {
    let answers = bad_body_answers(responses);
    if answers.is_empty() {
        return None;
    }
    let drew_error = answers.iter().any(|r| is_error_answer(r.status));
    let drew_server_error = answers.iter().any(|r| is_server_error(r.status));
    let asked = answers
        .iter()
        .map(|r| format!("`{}`", r.id.trim_start_matches(BAD_BODY_ID).trim()))
        .collect::<Vec<_>>()
        .join(", ");
    if !drew_error {
        Some((
            "V16.5.1, V13.4.2",
            format!(
                "Whether an error is answered with a generic message, and debug mode is off, show \
                 only in an error answer. The app was asked for a page that does not exist, and sent \
                 a body that is not JSON at {asked}, and answered without an error."
            ),
        ))
    } else if !drew_server_error {
        Some((
            "V13.4.2",
            format!(
                "Debug mode shows when the app's code fails. Sent a body that is not JSON at \
                 {asked}, the app refused it, and none of them failed, so whether a failure would \
                 show a debug page is not known."
            ),
        ))
    } else {
        None
    }
}

/// The requests this suite needs.
pub fn requests(health_path: &str) -> Vec<ProbeRequest> {
    // The root as well as the health path, when they differ: a health path is often a small JSON
    // status reply nobody sees, and the root is the page people land on.
    let root = (health_path != "/").then(|| ProbeRequest {
        id: "root".into(),
        method: "GET".into(),
        path: "/".into(),
        headers: Vec::new(),
        body: None,
    });
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
    .into_iter()
    .chain(LISTING_PATHS.iter().map(|path| ProbeRequest {
        id: listing_id(path),
        method: "GET".into(),
        path: (*path).to_owned(),
        headers: Vec::new(),
        body: None,
    }))
    .chain(UNUSED_METHODS.iter().map(|method| ProbeRequest {
        id: method_id(method),
        method: (*method).to_owned(),
        path: health_path.to_owned(),
        headers: Vec::new(),
        body: None,
    }))
    .chain(std::iter::once(ProbeRequest {
        id: "jsonp".into(),
        method: "GET".into(),
        path: format!(
            "{health_path}{}callback={JSONP_CALLBACK}",
            if health_path.contains('?') { '&' } else { '?' }
        ),
        headers: Vec::new(),
        body: None,
    }))
    .chain(LOG_PATHS.iter().map(|path| ProbeRequest {
        id: log_id(path),
        method: "GET".into(),
        path: (*path).to_owned(),
        headers: Vec::new(),
        body: None,
    }))
    .chain(EXPOSED_PATHS.iter().map(|path| ProbeRequest {
        id: exposed_id(path),
        method: "GET".into(),
        path: (*path).to_owned(),
        headers: Vec::new(),
        body: None,
    }))
    .chain(root)
    .chain(CONSOLES.iter().map(|console| ProbeRequest {
        id: console_id(console.path),
        method: "GET".into(),
        path: console.path.to_owned(),
        headers: Vec::new(),
        body: None,
    }))
    .chain(reflection_requests(health_path))
    .chain(std::iter::once(bad_body_request("POST", health_path)))
    .chain((health_path != "/").then(|| bad_body_request("POST", "/")))
    .collect()
}

/// Folders a web server is most often left serving, asked for with the trailing slash that makes a
/// server offer a listing rather than a file.
///
/// Six guesses are six guesses. Finding none is not evidence that nothing lists, which is why the
/// check below is a finding and never a pass.
const LISTING_PATHS: &[&str] = &[
    "/static/",
    "/assets/",
    "/uploads/",
    "/public/",
    "/images/",
    "/files/",
];

/// The probe id for one of those paths. A response carries its id and not its path, so the request
/// and the check have to agree on this, and they agree by both calling it.
fn listing_id(path: &str) -> String {
    format!("listing-{}", path.trim_matches('/'))
}

/// Requirements this suite cannot speak to, and why. Never folded into a pass.
///
/// `signed_in_ran` is whether the signed-in probes (`signed_in/`) asked too. When they did, they
/// say for themselves what they reached and what they could not, so authorization, sessions and
/// forgery are not repeated here as untouched.
pub fn unassessed_requirements(signed_in_ran: bool) -> Vec<(&'static str, &'static str)> {
    let mut out = Vec::new();
    if !signed_in_ran {
        out.push((
            "V8, V7",
            "Authorization and session handling need a signed-in user. `sv` signs in only when \
             stackvet.toml says how, under [stack.run.users], and this one does not.",
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
         where it comes back out, which means knowing the app's forms and routes. One value, with \
         `<`, `\"` and `'` in it, is sent in the address of the health path, the root page and a \
         page that does not exist, and coming back unencoded is a finding; coming back encoded \
         credits nothing, since every other place the app writes out what it was sent is untried.",
    ));
    out
}

/// The hosted backend an app's packages show, when it has one: Firebase or Supabase, named with the
/// first package that shows it (gap analysis, item 10, its fourth part).
///
/// An app built with Lovable, Bolt, and the like often signs people in and keeps their data with one
/// of these, reached from the browser. Behind the network fence the app cannot reach it, so asking
/// the running app says nothing about who can read or change that data, however much else it says.
pub fn hosted_backend(components: &[crate::sbom::Component]) -> Option<(&'static str, String)> {
    components.iter().find_map(|c| {
        let name = c.name.to_ascii_lowercase();
        let service = if name == "firebase"
            || name == "firebase-admin"
            || name == "pyrebase4"
            || name.starts_with("@firebase/")
            || name.starts_with("@react-native-firebase/")
            || name.starts_with("firebase_")
        {
            "Firebase"
        } else if name == "supabase"
            || name.starts_with("@supabase/")
            || name.starts_with("supabase_")
        {
            "Supabase"
        } else {
            return None;
        };
        Some((service, c.name.clone()))
    })
}

/// What asking the running app could not reach when the app's sign-in and data are hosted, or `None`
/// when its packages show no hosted backend.
pub fn hosted_backend_gap(components: &[crate::sbom::Component]) -> Option<(&'static str, String)> {
    let (service, package) = hosted_backend(components)?;
    let rules = if service == "Firebase" {
        "its rules files (`firestore.rules`, `storage.rules`, `database.rules.json`)"
    } else {
        "the policies in `supabase/migrations/`"
    };
    Some((
        "V8, V6",
        format!(
            "The app uses {service} (`{package}`), and the network fence keeps the running app from \
             reaching it, so nothing here signed in through {service} or read or changed the data it \
             holds. Who can reach which records there is decided by {service} itself: `sv check` \
             reads {rules} for rules left open, and nothing tested them running."
        ),
    ))
}

/// Everything asking the running app could not reach, as requirement ids and why, in the order
/// `sv run` prints them and the report lists them: one list, so the two cannot say different things.
pub fn running_app_gaps(
    signed_in_ran: bool,
    responses: &[ProbeResponse],
    components: &[crate::sbom::Component],
) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = unassessed_requirements(signed_in_ran)
        .into_iter()
        .map(|(ids, why)| (ids, why.to_owned()))
        .collect();
    out.extend(error_answer_gap(responses));
    out.extend(hosted_backend_gap(components));
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

#[track_caller]
fn finding(about: &Rule, title: &str, severity: Severity, description: String) -> Finding {
    crate::finding::found(Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        bundled_library: None,
        outranked: None,
        also_on_this_line: Vec::new(),
        rule_id: about.rule_id.to_owned(),
        title: title.to_owned(),
        severity,
        confidence: about.confidence,
        location: Location::running_app(),
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
    })
}

/// Reads the answers.
pub fn evaluate(responses: &[ProbeResponse]) -> Vec<Finding> {
    let mut out = Vec::new();
    let find = |id: &str| responses.iter().find(|r| r.id == id);

    let judged = pages(responses);
    out.extend(security_headers(&judged));
    out.extend(cookie_attributes(&judged));
    if let Some(cors) = find("cors") {
        out.extend(reflected_origin(cors));
    }
    if let Some(missing) = find("missing") {
        out.extend(error_page_leak(missing));
    }
    out.extend(error_answer_leak(&bad_body_answers(responses)));
    if let Some(trace) = find("trace") {
        out.extend(trace_enabled(trace));
    }
    out.extend(content_type(&with_bodies(responses)));
    out.extend(source_control_exposed(responses));
    out.extend(directory_listing(responses));
    out.extend(unused_methods(responses));
    out.extend(jsonp(responses));
    out.extend(reflected(responses));
    out.extend(exposed_endpoints(responses));
    out.extend(served_logs(responses));
    out.extend(development_console(responses));
    out.extend(version_disclosed(responses));
    out.extend(opener_policy(responses));
    if let Some(home) = find("home") {
        out.extend(csp_reporting(home));
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

    // Every judged page has to pass for the credit, which names them.
    let judged = pages(responses);
    let names = judged
        .iter()
        .map(|p| page_name(p))
        .collect::<Vec<_>>()
        .join(" and ");
    if !judged.is_empty() && security_headers(&judged).is_none() {
        out.push(crate::Verified::new(
            SECURITY_HEADERS.rule_id,
            SECURITY_HEADERS.requirement_ids,
            format!("the app's answers on {names}, as somebody not signed in"),
        ));
    }
    // Only when there was a cookie to judge. No cookie is not a correct cookie.
    let sets_a_cookie = judged
        .iter()
        .any(|p| p.headers.iter().any(|(k, _)| k == "set-cookie"));
    if sets_a_cookie && cookie_attributes(&judged).is_none() {
        out.push(crate::Verified::new(
            COOKIE_ATTRIBUTES.rule_id,
            COOKIE_ATTRIBUTES.requirement_ids,
            format!("every cookie the app set on {names}"),
        ));
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
    // ADR-056: a clean missing page is not a clean error. Credit needs an error the app was made to
    // give, and no answer asked for it, the missing page included, carrying a trace.
    let provoked = bad_body_answers(responses);
    let clean = find("missing").is_none_or(|m| error_page_leak(m).is_none())
        && provoked.iter().all(|r| error_page_leak(r).is_none());
    if clean {
        let errors: Vec<&&ProbeResponse> = provoked
            .iter()
            .filter(|r| is_error_answer(r.status))
            .collect();
        let server_error = errors.iter().any(|r| is_server_error(r.status));
        if !errors.is_empty() {
            let shown = errors
                .iter()
                .map(|r| {
                    format!(
                        "`{}` ({})",
                        r.id.trim_start_matches(BAD_BODY_ID).trim(),
                        r.status
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            out.push(crate::Verified::new(
                ERROR_DETAIL_LEAK.rule_id,
                if server_error {
                    &["V13.4.2", "V16.5.1"]
                } else {
                    &["V16.5.1"]
                },
                format!("the app's error answers to a body that is not JSON, at {shown}"),
            ));
        }
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
        .filter(|r| r.id == "home" || r.id == "missing" || r.id == "root")
        .collect();
    if judged.iter().any(|r| r.id == "home")
        && judged.iter().any(|r| r.id == "missing")
        && content_type(&judged).is_none()
    {
        out.push(crate::Verified::new(
            CONTENT_TYPE.rule_id,
            CONTENT_TYPE.requirement_ids,
            "the app's page and its answer for a page that is not there".to_owned(),
        ));
    }
    // Only over pages that start a document, and only when there was one.
    let documents = html_documents(responses);
    if !documents.is_empty() && opener_policy(responses).is_none() {
        out.push(crate::Verified::new(
            OPENER_POLICY.rule_id,
            OPENER_POLICY.requirement_ids,
            format!(
                "{} page{} the app answered with, as somebody not signed in",
                documents.len(),
                if documents.len() == 1 { "" } else { "s" }
            ),
        ));
    }
    // Only when there was a policy to read. No policy is the security-headers finding, not this.
    if let Some(home) = find("home")
        && home.header("content-security-policy").is_some()
        && csp_reporting(home).is_none()
    {
        out.push(crate::Verified::new(
            CSP_REPORTING.rule_id,
            CSP_REPORTING.requirement_ids,
            "the Content-Security-Policy on the app's answer on its health path".to_owned(),
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

const DIRECTORY_LISTING: Rule = Rule {
    rule_id: "probe.directory-listing",
    confidence: Confidence::High,
    requirement_ids: &["V13.4.3"],
    cwe: &["CWE-548"],
    impact: "A folder that lists its contents shows everything in it, including files nobody \
             linked to and nobody meant to publish — a backup, an export, a key.",
    fix: "Turn the listing off in the web server (`autoindex off` in nginx, `Options -Indexes` in \
          Apache) and serve a real page or a 404 instead.",
};

/// A folder that answers with its own contents.
///
/// Matched on what the three servers that do this actually write — Apache and nginx both head the
/// page "Index of /x", Python's `http.server` writes "Directory listing for /x" — rather than on
/// "a page with several links in it", which every real page is.
///
/// That precision is also the limit: a listing a framework renders itself, in its own words, is not
/// found here. Between guessing six paths and reading only three signatures, finding nothing means
/// nothing was found, not that nothing lists, so this is only ever a finding and never credits
/// V13.4.3.
fn directory_listing(responses: &[ProbeResponse]) -> Option<Finding> {
    let listed: Vec<&str> = LISTING_PATHS
        .iter()
        .filter(|path| {
            responses
                .iter()
                .find(|r| r.id == listing_id(path))
                .is_some_and(|r| {
                    (200..300).contains(&r.status)
                        && (r.body.contains("Index of /")
                            || r.body.contains("Directory listing for"))
                })
        })
        .copied()
        .collect();
    if listed.is_empty() {
        return None;
    }
    Some(finding(
        &DIRECTORY_LISTING,
        "A folder on the app's address lists its contents",
        Severity::Medium,
        format!(
            "The app answered {} with a listing of what is in {}.",
            listed.join(", "),
            if listed.len() == 1 { "it" } else { "them" }
        ),
    ))
}

// ------------------------------------------------------------------------------------------------
// GraphQL and WebSocket, when stackvet.toml names where they are.

/// How many aliases the amount probe asks for. Large enough that no app means to allow it for one
/// request, small enough that answering it costs a server nothing worth worrying about: each one is
/// `__typename`, which every GraphQL server answers without touching any data.
const ALIASES: usize = 1000;

/// A key for the WebSocket handshake. Any 16 bytes, base64; the server only echoes a hash of it.
const WS_KEY: &str = "c3YtcHJvYmUtd3Mta2V5LTE2Yg==";

fn graphql_request(id: &str, path: &str, query: &str) -> ProbeRequest {
    ProbeRequest {
        id: id.to_owned(),
        method: "POST".into(),
        path: path.to_owned(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: Some(serde_json::json!({ "query": query }).to_string().into()),
    }
}

fn ws_request(id: &str, path: &str, origin: Option<&str>) -> ProbeRequest {
    let mut headers = vec![
        ("Upgrade".into(), "websocket".into()),
        ("Connection".into(), "Upgrade".into()),
        ("Sec-WebSocket-Key".into(), WS_KEY.into()),
        ("Sec-WebSocket-Version".into(), "13".into()),
    ];
    if let Some(origin) = origin {
        headers.push(("Origin".into(), origin.to_owned()));
    }
    ProbeRequest {
        id: id.to_owned(),
        method: "GET".into(),
        path: path.to_owned(),
        headers,
        body: None,
    }
}

/// The requests for the GraphQL and WebSocket questions, for whichever of the two the app has.
pub fn api_requests(graphql: Option<&str>, websocket: Option<&str>) -> Vec<ProbeRequest> {
    let mut out = Vec::new();
    if let Some(path) = graphql {
        out.push(graphql_request("graphql-plain", path, "{__typename}"));
        out.push(graphql_request(
            "graphql-introspection",
            path,
            "{__schema{queryType{name}}}",
        ));
        let aliases: Vec<String> = (0..ALIASES).map(|i| format!("a{i}:__typename")).collect();
        out.push(graphql_request(
            "graphql-aliases",
            path,
            &format!("{{{}}}", aliases.join(" ")),
        ));
    }
    if let Some(path) = websocket {
        out.push(ws_request("ws-no-origin", path, None));
        out.push(ws_request("ws-foreign-origin", path, Some(STRANGER)));
    }
    out
}

/// A GraphQL answer that carries data and no errors: the query was accepted and run.
fn graphql_ran(r: &ProbeResponse, key: &str) -> bool {
    (200..300).contains(&r.status)
        && r.body.contains("\"data\"")
        && r.body.contains(&format!("\"{key}\""))
        && !r.body.contains("\"errors\"")
}

/// What the GraphQL and WebSocket answers show.
///
/// Everything here establishes its setup first. A GraphQL question is only asked of an endpoint
/// that answered `{__typename}`, the one query every server accepts; a WebSocket one only of an
/// endpoint that upgraded a handshake with no `Origin`, which is how a non-browser client connects
/// and how nearly every server accepts one. Without that, a refusal says only that the path is not
/// what stackvet.toml says.
pub fn evaluate_api(
    responses: &[ProbeResponse],
    public_api: Option<bool>,
) -> (Vec<Finding>, Vec<crate::Verified>, Vec<(String, String)>) {
    let mut findings = Vec::new();
    let mut verified = Vec::new();
    let mut not_assessed = Vec::new();
    let find = |id: &str| responses.iter().find(|r| r.id == id);

    // ---- GraphQL
    if let Some(plain) = find("graphql-plain") {
        if !graphql_ran(plain, "__typename") {
            not_assessed.push((
                "V4.3.1, V4.3.2".to_owned(),
                format!(
                    "The GraphQL path answered `{{__typename}}` with {} and no data, so it is not \
                     answering GraphQL as stackvet.toml says, and nothing else could be asked.",
                    plain.status
                ),
            ));
        } else {
            // V4.3.2: introspection, allowed only for an API meant for other programs.
            if let Some(intro) = find("graphql-introspection") {
                let open = graphql_ran(intro, "__schema");
                match (open, public_api) {
                    (false, _) => verified.push(crate::Verified::new(
                        GRAPHQL_INTROSPECTION.rule_id,
                        GRAPHQL_INTROSPECTION.requirement_ids,
                        "an introspection query for the schema, refused where a plain GraphQL query \
                         was answered"
                            .to_owned(),
                    )),
                    (true, Some(false)) => findings.push(finding(
                        &GRAPHQL_INTROSPECTION,
                        "The GraphQL schema is handed to anybody who asks",
                        Severity::Medium,
                        "An introspection query was answered with the schema, and stackvet.toml \
                         says no other programs are meant to use this API."
                            .to_owned(),
                    )),
                    (true, Some(true)) => verified.push(crate::Verified::new(
                        GRAPHQL_INTROSPECTION.rule_id,
                        GRAPHQL_INTROSPECTION.requirement_ids,
                        "introspection answered, which V4.3.2 allows for an API meant for other \
                         programs, as stackvet.toml says this one is"
                            .to_owned(),
                    )),
                    (true, None) => not_assessed.push((
                        "V4.3.2".to_owned(),
                        "Introspection is on. That is right for an API other programs are meant to \
                         use and wrong otherwise, and stackvet.toml does not say which this is \
                         (`public-api` under [capabilities])."
                            .to_owned(),
                    )),
                }
            }
            // V4.3.1: a thousand aliases in one request. Read from the start of the answer, not
            // the end: bodies are kept to their first few thousand characters, and a server
            // applies amount and cost limits before it runs anything, so `a0` coming back with no
            // errors means the whole request was allowed.
            if let Some(many) = find("graphql-aliases") {
                if graphql_ran(many, "a0") {
                    findings.push(finding(
                        &GRAPHQL_AMOUNT,
                        "One GraphQL request can ask for a thousand things at once",
                        Severity::Medium,
                        format!(
                            "A single request of {ALIASES} aliases was accepted and run. Nothing \
                             limits how much one request may ask for."
                        ),
                    ));
                } else {
                    verified.push(crate::Verified::new(
                        GRAPHQL_AMOUNT.rule_id,
                        GRAPHQL_AMOUNT.requirement_ids,
                        format!(
                            "a request of {ALIASES} aliases {} where a plain query was answered",
                            if (200..300).contains(&many.status) {
                                "answered with an error instead of being run".to_owned()
                            } else {
                                format!("refused ({})", many.status)
                            }
                        ),
                    ));
                }
            }
        }
    }

    // ---- WebSocket
    if let (Some(plain), Some(foreign)) = (find("ws-no-origin"), find("ws-foreign-origin")) {
        if plain.status != 101 {
            not_assessed.push((
                "V4.4.2".to_owned(),
                format!(
                    "The WebSocket path answered a plain handshake with {} rather than switching \
                     protocols, so either it is not where stackvet.toml says or it refuses every \
                     handshake; either way a refusal of a foreign one would prove nothing.",
                    plain.status
                ),
            ));
        } else if foreign.status == 101 {
            findings.push(finding(
                &WS_ORIGIN,
                "A WebSocket connection is accepted from any website",
                Severity::Medium,
                format!(
                    "A handshake carrying `Origin: {STRANGER}` was accepted (101). A page on any \
                     site can open this connection with the visitor's cookies."
                ),
            ));
        } else {
            verified.push(crate::Verified::new(
                WS_ORIGIN.rule_id,
                WS_ORIGIN.requirement_ids,
                format!(
                    "a WebSocket handshake from a site the app has never heard of, refused ({}) \
                     where one with no Origin was accepted",
                    foreign.status
                ),
            ));
        }
    }
    (findings, verified, not_assessed)
}

const GRAPHQL_INTROSPECTION: Rule = Rule {
    rule_id: "probe.graphql-introspection",
    confidence: Confidence::High,
    requirement_ids: &["V4.3.2"],
    cwe: &["CWE-200"],
    impact: "The schema is a map of every query and field the API has, including the ones no page \
             uses, handed to whoever asks.",
    fix: "Turn introspection off in production; every GraphQL server has a setting for it.",
};

const GRAPHQL_AMOUNT: Rule = Rule {
    rule_id: "probe.graphql-no-amount-limit",
    confidence: Confidence::High,
    requirement_ids: &["V4.3.1"],
    cwe: &["CWE-770"],
    impact: "One request can make the server do a thousand times the work of an ordinary one, which \
             is the cheapest way there is to slow an API down for everybody.",
    fix: "Limit aliases, depth, or query cost per request, or accept only queries from an allowlist.",
};

const WS_ORIGIN: Rule = Rule {
    rule_id: "probe.websocket-origin-unchecked",
    confidence: Confidence::High,
    requirement_ids: &["V4.4.2"],
    cwe: &["CWE-1385"],
    impact: "Browsers do not stop cross-site WebSocket connections the way they stop other \
             cross-site requests, so another site can open one as the visitor and read what comes \
             back.",
    fix: "Compare the handshake's `Origin` with the app's own origins and refuse the rest.",
};

/// Headers a browser needs in order to protect the people using the app.
/// The answers the page checks judge: the health path's always, and the root's when it answered
/// with a page of its own. Each is named in what the checks say, so a credit says which pages it
/// covers and a finding which page fell short.
fn pages(responses: &[ProbeResponse]) -> Vec<&ProbeResponse> {
    responses
        .iter()
        .filter(|r| r.id == "home" || (r.id == "root" && (200..300).contains(&r.status)))
        .collect()
}

/// Which page a judged answer was, for saying so.
fn page_name(response: &ProbeResponse) -> &'static str {
    if response.id == "root" {
        "the root page"
    } else {
        "the health path"
    }
}

/// What a Content-Security-Policy lacks of the minimum V3.4.3 names: `object-src 'none'`,
/// `base-uri 'none'`, and an allowlist (ADR-047). `object-src` left out falls back to
/// `default-src`, so `default-src 'none'` stands in for it; nothing stands in for `base-uri`.
fn policy_short_of_v3_4_3(policy: &str) -> Vec<&'static str> {
    let directives: Vec<(String, Vec<String>)> = policy
        .split(';')
        .filter_map(|d| {
            let mut words = d.split_whitespace().map(str::to_lowercase);
            Some((words.next()?, words.collect()))
        })
        .collect();
    let values = |name: &str| {
        directives
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
    };
    let only_none = |v: Option<&[String]>| v.is_some_and(|v| v == ["'none'"]);
    let mut short = Vec::new();
    let object_none = match values("object-src") {
        Some(v) => only_none(Some(v)),
        None => only_none(values("default-src")),
    };
    if !object_none {
        short.push(
            "`object-src 'none'` in its Content-Security-Policy, which stops plug-in content \
             running",
        );
    }
    if !only_none(values("base-uri")) {
        short.push(
            "`base-uri 'none'` in its Content-Security-Policy, which stops an injected `<base>` \
             tag moving where the page's scripts load from",
        );
    }
    if values("default-src").is_none() && values("script-src").is_none() {
        short.push(
            "a `default-src` or `script-src` in its Content-Security-Policy, the list of where \
             scripts may come from",
        );
    }
    short
}

/// The headers one answer lacks.
pub(crate) fn missing_headers(response: &ProbeResponse) -> Vec<&'static str> {
    let mut missing = Vec::new();
    match response.header("content-security-policy") {
        None => missing.push("Content-Security-Policy, which limits what a page may load and run"),
        Some(policy) => missing.extend(policy_short_of_v3_4_3(policy)),
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
    missing
}

/// Every judged page carries the headers; a finding names each page that does not, and what it
/// lacks.
fn security_headers(pages: &[&ProbeResponse]) -> Option<Finding> {
    let short: Vec<String> = pages
        .iter()
        .filter_map(|page| {
            let missing = missing_headers(page);
            (!missing.is_empty()).then(|| {
                format!(
                    "{} came back without {}",
                    page_name(page),
                    missing.join("; without ")
                )
            })
        })
        .collect();
    if short.is_empty() {
        return None;
    }
    Some(finding(
        &SECURITY_HEADERS,
        "The app is missing headers a browser relies on",
        Severity::Medium,
        format!("{}.", capitalized(&short.join(". "))),
    ))
}

fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
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
fn cookie_attributes(pages: &[&ProbeResponse]) -> Option<Finding> {
    let mut problems = Vec::new();
    for page in pages {
        for (k, cookie) in &page.headers {
            if k != "set-cookie" {
                continue;
            }
            let lower = cookie.to_lowercase();
            let name = cookie.split('=').next().unwrap_or("a cookie").trim();
            if !lower.contains("httponly") {
                problems.push(format!(
                    "`{name}`, set by {}, can be read by any script on the page (no HttpOnly)",
                    page_name(page)
                ));
            }
            if !lower.contains("samesite") {
                problems.push(format!(
                    "`{name}`, set by {}, does not say when it may travel to other sites (no \
                     SameSite)",
                    page_name(page)
                ));
            }
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
pub(crate) fn reflected_origin(response: &ProbeResponse) -> Option<Finding> {
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

/// Traces that a language or framework prints when something goes wrong. Public so the runner can
/// look for them in the whole of an answer before it keeps only the start (H17 of the deep review).
pub const TRACE_MARKERS: &[&str] = &[
    "Traceback (most recent call last)",
    "    at ",
    "stack trace",
    "Werkzeug Debugger",
    "django.core.exceptions",
    // Django's own 404 and 500 pages with debug on (`views/templates/technical_404.html`, read in
    // Django 5.2.17), which name the routes rather than print a trace.
    "because you have <code>DEBUG = True</code>",
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

/// The trace markers a body carries, for the checks elsewhere that read an error answer.
pub(crate) fn trace_markers_in(body: &str) -> Vec<&'static str> {
    TRACE_MARKERS
        .iter()
        .copied()
        .filter(|marker| body.contains(marker))
        .collect()
}

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

/// What the app says when sent a body it cannot read (ADR-056): one finding naming every request
/// whose answer carried a trace.
fn error_answer_leak(answers: &[&ProbeResponse]) -> Option<Finding> {
    let leaking: Vec<(String, Vec<&str>)> = answers
        .iter()
        .map(|r| {
            (
                r.id.trim_start_matches(BAD_BODY_ID).trim().to_owned(),
                trace_markers_in(&r.body),
            )
        })
        .filter(|(_, found)| !found.is_empty())
        .collect();
    if leaking.is_empty() {
        return None;
    }
    Some(finding(
        &ERROR_DETAIL_LEAK,
        "An error answer shows how the app is built",
        Severity::Medium,
        format!(
            "Sent a body that is not JSON, marked as JSON, the app answered with {}.",
            leaking
                .iter()
                .map(|(asked, found)| format!(
                    "{} at `{asked}`",
                    found
                        .iter()
                        .map(|m| format!("`{}`", m.trim()))
                        .collect::<Vec<_>>()
                        .join(" and ")
                ))
                .collect::<Vec<_>>()
                .join("; ")
        ),
    ))
}

const TRACE_ENABLED: Rule = Rule {
    rule_id: "probe.trace-enabled",
    confidence: Confidence::High,
    // V13.4.4 is TRACE by name.
    requirement_ids: &["V13.4.4"],
    cwe: &["CWE-16"],
    impact: "Anything the browser attaches to a request — cookies, authorization headers — comes \
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

// ------------------------------------------------------------------------------------------------
// Methods, JSONP, documentation and monitoring pages, version numbers, and two browser headers.

/// Methods a page that is only ever read has no use for. `DELETE` is an ordinary method an app can
/// route by accident (`app.all`, a catch-all handler); `PROPFIND` is WebDAV's, which a web server
/// can have switched on without the app knowing.
const UNUSED_METHODS: &[&str] = &["DELETE", "PROPFIND"];

fn method_id(method: &str) -> String {
    format!("method-{}", method.to_lowercase())
}

const UNUSED_METHOD: Rule = Rule {
    rule_id: "probe.unused-method-accepted",
    confidence: Confidence::Medium,
    // V4.1.4 is only the methods the app supports, and the rest blocked.
    requirement_ids: &["V4.1.4"],
    cwe: &["CWE-650"],
    impact: "A route that answers every method does whatever its code does for methods nobody \
             thought about, and rules written for GET and POST — checks against forged requests, \
             caching, logging — may not cover them.",
    fix: "Route each path for the methods it uses, and answer the rest with 405 Method Not \
          Allowed; switch off WebDAV in the web server if nothing needs it.",
};

/// The page the health path serves, asked for with methods it has no use for, answered as success.
///
/// Only a finding: two methods on one path are not the app's methods, so an app that refuses both
/// has shown nothing about the rest of its routes.
fn unused_methods(responses: &[ProbeResponse]) -> Option<Finding> {
    let accepted: Vec<&str> = UNUSED_METHODS
        .iter()
        .filter(|m| {
            responses
                .iter()
                .find(|r| r.id == method_id(m))
                .is_some_and(|r| (200..300).contains(&r.status))
        })
        .copied()
        .collect();
    if accepted.is_empty() {
        return None;
    }
    Some(finding(
        &UNUSED_METHOD,
        "The app answers methods its page has no use for",
        Severity::Low,
        format!(
            "Its health path, a page that is only read, answered {} as a success.",
            accepted.join(" and ")
        ),
    ))
}

/// A function name nothing but this probe would ask for.
const JSONP_CALLBACK: &str = "svProbeJsonp";

const JSONP: Rule = Rule {
    rule_id: "probe.jsonp-enabled",
    confidence: Confidence::High,
    requirement_ids: &["V3.5.6"],
    cwe: &["CWE-346"],
    impact: "JSONP wraps data in a call to a function the asker names, which any other site can load \
             with a script tag — and with the visitor's cookies, so it reads what they can read.",
    fix: "Drop JSONP (`res.jsonp`, a `callback` parameter) and serve plain JSON, with CORS for the \
          origins that need it.",
};

/// The health path, asked with `callback=`, answering with a call to that function.
///
/// Only a finding: one path asked is not every path.
fn jsonp(responses: &[ProbeResponse]) -> Option<Finding> {
    let r = responses.iter().find(|r| r.id == "jsonp")?;
    let html = r
        .header("content-type")
        .is_some_and(|t| t.to_lowercase().contains("html"));
    if !(200..300).contains(&r.status) || html || !r.body.contains(&format!("{JSONP_CALLBACK}(")) {
        return None;
    }
    Some(finding(
        &JSONP,
        "The app answers with JSONP",
        Severity::Medium,
        format!(
            "Asked for its health path with `callback={JSONP_CALLBACK}`, the app answered with a \
             call to `{JSONP_CALLBACK}(…)`."
        ),
    ))
}

/// The start of the value the reflection probes send. Nothing but `sv` would send it, so finding it
/// in an answer means the answer is repeating what it was sent. The runner keeps the text around it
/// when it comes back past the part of a page it otherwise keeps (`sv_run`'s `parse_response`).
pub const REFLECTION_MARK: &str = "svEcho4b7e";
/// The end of that value, so what came back between the two can be read.
pub(crate) const REFLECTION_END: &str = "e7b4ohcEvs";

/// The value, as it is written into an address: `<`, `"` and `'` percent-encoded, as a browser
/// sends them. An app that decodes its address and writes it into a page unencoded writes them as
/// they are.
fn reflection_value() -> String {
    format!("{REFLECTION_MARK}%3C%22%27{REFLECTION_END}")
}

/// The pages the value is sent to, by probe id: the health path and the root with it as `q`, the
/// parameter a search reads, and a page that does not exist with it in the path, which an error
/// page often repeats.
fn reflection_requests(health_path: &str) -> Vec<ProbeRequest> {
    let value = reflection_value();
    let query = |path: &str| {
        format!(
            "{path}{}q={value}",
            if path.contains('?') { '&' } else { '?' }
        )
    };
    let mut asked = vec![(REFLECT_HOME, query(health_path))];
    if health_path != "/" {
        asked.push((REFLECT_ROOT, query("/")));
    }
    asked.push((REFLECT_MISSING, format!("{MISSING_PATH}-{value}")));
    asked
        .into_iter()
        .map(|(id, path)| ProbeRequest {
            id: id.into(),
            method: "GET".into(),
            path,
            headers: Vec::new(),
            body: None,
        })
        .collect()
}

const REFLECT_HOME: &str = "reflect-home";
const REFLECT_ROOT: &str = "reflect-root";
const REFLECT_MISSING: &str = "reflect-missing";

fn reflected_page_name(id: &str) -> &'static str {
    match id {
        REFLECT_HOME => "the health path",
        REFLECT_ROOT => "the root page",
        _ => "a page that does not exist",
    }
}

const REFLECTED_HTML: Rule = Rule {
    rule_id: "probe.reflected-unencoded",
    confidence: Confidence::High,
    requirement_ids: &["V1.2.1"],
    cwe: &["CWE-79"],
    impact: "Whatever is in the address comes back as part of the page. Somebody can send a link whose \
             address carries a script, and it runs in the app as the person who clicks it, with \
             their session: this is reflected cross-site scripting.",
    fix: "Write values into pages through the template engine's escaping (Jinja2, React, and most \
          others do it unless told not to: look for `|safe`, `Markup`, `dangerouslySetInnerHTML`, \
          `innerHTML`, or a page built by joining strings), and never into a page by hand.",
};

const REFLECTED_JSON: Rule = Rule {
    rule_id: "probe.reflected-json-unescaped",
    confidence: Confidence::High,
    requirement_ids: &["V1.2.3"],
    cwe: &["CWE-116"],
    impact: "A `\"` sent in the address comes back in JSON as it is, so it ends the string it was put in \
             and whatever follows is read as more of the JSON: the sender decides part of its shape.",
    fix: "Build JSON with the language's JSON encoder (`json.dumps`, `JSON.stringify`, `jsonify`) \
          rather than by joining strings.",
};

/// What came back of the value in one answer: the text between its start and its end, or up to 40
/// characters when the end did not come back, for each time it appears.
pub(crate) fn echoes(body: &str) -> Vec<&str> {
    body.match_indices(REFLECTION_MARK)
        .map(|(at, _)| {
            let rest = &body[at + REFLECTION_MARK.len()..];
            match rest.find(REFLECTION_END) {
                Some(end) if end <= 40 => &rest[..end],
                _ => {
                    let cut = rest.char_indices().nth(40).map_or(rest.len(), |(i, _)| i);
                    &rest[..cut]
                }
            }
        })
        .collect()
}

/// The value sent in an address, coming back in a page with `<` as it is, or in JSON with `"`
/// unescaped. Only ever a finding: one value on three pages is not every place the app writes out
/// what it was sent, and V1.2.1 asks about all of them.
///
/// In a page, only a raw `<` is a finding: a quote as it is is harmless in text and harmful in an
/// attribute, and which one it landed in is not read here. In JSON, a `"` with no backslash before
/// it is. An answer that is neither, or whose type is not said, is not judged.
fn reflected(responses: &[ProbeResponse]) -> Vec<Finding> {
    let mut html = Vec::new();
    let mut json = Vec::new();
    for r in responses
        .iter()
        .filter(|r| [REFLECT_HOME, REFLECT_ROOT, REFLECT_MISSING].contains(&r.id.as_str()))
    {
        let kind = r.header("content-type").unwrap_or("").to_lowercase();
        let echoed = echoes(&r.body);
        if kind.contains("html") && echoed.iter().any(|e| e.contains('<')) {
            html.push(reflected_page_name(&r.id));
        } else if kind.contains("json")
            && echoed
                .iter()
                .any(|e| e.match_indices('"').any(|(i, _)| !e[..i].ends_with('\\')))
        {
            json.push(reflected_page_name(&r.id));
        }
    }
    let mut out = Vec::new();
    if !html.is_empty() {
        out.push(finding(
            &REFLECTED_HTML,
            "Text from the address is written into the page unencoded",
            Severity::High,
            format!(
                "Sent `<\"'` in the address of {}, the app wrote the `<` back into the page as it is, \
                 where a browser reads it as the start of a tag.",
                html.join(" and ")
            ),
        ));
    }
    if !json.is_empty() {
        out.push(finding(
            &REFLECTED_JSON,
            "Text from the address is written into JSON unescaped",
            Severity::Medium,
            format!(
                "Sent `<\"'` in the address of {}, the app wrote the `\"` back into its JSON with no \
                 backslash before it.",
                json.join(" and ")
            ),
        ));
    }
    out
}

/// Where documentation and monitoring pages are most often left. Each is judged by what comes back,
/// not by answering at all: many apps answer every path with their own front page.
const EXPOSED_PATHS: &[&str] = &[
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/swagger-ui.html",
    "/docs",
    "/redoc",
    "/actuator",
    "/metrics",
    "/debug/vars",
    "/debug/pprof/",
    "/server-status",
    "/nginx_status",
    "/phpinfo.php",
];

/// Where frameworks and servers commonly leave the app's log files, asked for by somebody not signed
/// in (V16.4.2, ADR-072).
const LOG_PATHS: &[&str] = &[
    "/logs/",
    "/log/",
    "/logs/app.log",
    "/log/production.log",
    "/storage/logs/laravel.log",
    "/error.log",
    "/debug.log",
    "/npm-debug.log",
    "/var/log/app.log",
];

fn log_id(path: &str) -> String {
    format!("log-{}", path.trim_matches('/').replace(['/', '.'], "-"))
}

/// A line that starts the way log lines do: an ISO date and time (`2026-10-09 12:00`,
/// `[2026-10-09T12:00`), or syslog's `Oct  9 12:00:01`.
static LOG_LINE_START: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(
        r"^\[?(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}|[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2})",
    )
    .expect("a fixed pattern")
});

/// The common log format's time, which follows the client's address:
/// `10.0.0.1 - - [09/Oct/2026:12:00:01 +0000]`.
static ACCESS_LOG_TIME: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"\[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}").expect("a fixed pattern")
});

/// A level word beside a date anywhere on the line: `level=error ts=2026-10-09…`, `{"level":"info",
/// "time":"2026-10-09…"}`.
static LEVEL_WITH_DATE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"(?i)\b(?:info|warn|warning|error|debug|fatal|trace)\b.*\d{4}-\d{2}-\d{2}|\d{4}-\d{2}-\d{2}.*\b(?:INFO|WARN|WARNING|ERROR|DEBUG|FATAL|TRACE)\b")
        .expect("a fixed pattern")
});

/// Whether an answer reads as a log: at least three lines that each start as a log line does, carry
/// the common log format's time, or carry a level word beside a date. A page of HTML never does, a
/// listing of a logs folder included, whose rows carry dates and which `probe.directory-listing`
/// finds itself.
fn reads_as_log(body: &str) -> bool {
    let start = body.trim_start().to_ascii_lowercase();
    if start.starts_with('<') || start.contains("<html") || start.contains("<a href") {
        return false;
    }
    body.lines()
        .filter(|l| {
            LOG_LINE_START.is_match(l.trim_start())
                || ACCESS_LOG_TIME.is_match(l)
                || LEVEL_WITH_DATE.is_match(l)
        })
        .count()
        >= 3
}

const LOG_SERVED: Rule = Rule {
    rule_id: "probe.log-file-served",
    confidence: Confidence::High,
    requirement_ids: &["V16.4.2"],
    cwe: &["CWE-538"],
    impact: "The app's log is handed to anybody who asks for it, with whatever it holds: sessions \
             and tokens, email addresses, the errors that show how the app is built.",
    fix: "Write logs outside every folder the web server serves, or to a logging service, and \
          make sure no route answers with a log file. Remove any log already left where it is \
          served.",
};

/// Log files answered to somebody not signed in (V16.4.2). Only a finding: nine guesses are nine
/// guesses.
fn served_logs(responses: &[ProbeResponse]) -> Option<Finding> {
    let found: Vec<&str> = LOG_PATHS
        .iter()
        .filter(|path| {
            responses
                .iter()
                .find(|r| r.id == log_id(path))
                .is_some_and(|r| (200..300).contains(&r.status) && reads_as_log(&r.body))
        })
        .copied()
        .collect();
    if found.is_empty() {
        return None;
    }
    Some(finding(
        &LOG_SERVED,
        "The app's log file is served to anybody who asks",
        Severity::High,
        format!(
            "Asked as somebody not signed in, the app answered {} with lines that read as a log.",
            found.join(", ")
        ),
    ))
}

fn exposed_id(path: &str) -> String {
    format!(
        "exposed-{}",
        path.trim_matches('/').replace(['/', '.'], "-")
    )
}

const EXPOSED: Rule = Rule {
    rule_id: "probe.docs-or-monitoring-exposed",
    confidence: Confidence::High,
    requirement_ids: &["V13.4.5"],
    cwe: &["CWE-200"],
    impact: "Documentation lists every route and what it takes, internal ones included; a \
             monitoring page shows how the app is built and what it is doing, sometimes with its \
             settings. Either saves an attacker the work of finding out.",
    fix: "Serve documentation and monitoring only where they are meant to be read — behind a \
          sign-in, on an internal port, or not in production at all. If one is meant to be public, \
          say so in security-notes.md.",
};

/// What a documentation or monitoring page says about itself, and whether it is monitoring.
fn exposed_kind(body: &str) -> Option<(&'static str, bool)> {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{')
        && (body.contains("\"openapi\"") || body.contains("\"swagger\""))
        && body.contains("\"paths\"")
    {
        return Some(("an OpenAPI description of its routes", false));
    }
    if body.contains("swagger-ui") || body.contains("<redoc") || body.contains("redoc.standalone") {
        return Some(("a page documenting its API", false));
    }
    if body.contains("\"_links\"") && body.contains("actuator") {
        return Some(("Spring Boot's actuator", true));
    }
    if body.lines().any(|l| l.starts_with("# HELP "))
        && body.lines().any(|l| l.starts_with("# TYPE "))
    {
        return Some(("metrics in Prometheus's format", true));
    }
    if body.contains("\"memstats\"") && body.contains("\"cmdline\"") {
        return Some((
            "Go's expvar, with the command line it was started with",
            true,
        ));
    }
    if body.contains("Types of profiles available") {
        return Some(("Go's profiler", true));
    }
    if body.contains("Apache Server Status") {
        return Some(("Apache's server status", true));
    }
    if body.contains("Active connections:") && body.contains("server accepts handled requests") {
        return Some(("nginx's status", true));
    }
    if body.contains("phpinfo()") || (body.contains("PHP Version") && body.contains("PHP License"))
    {
        return Some(("PHP's configuration page", true));
    }
    None
}

/// Documentation and monitoring pages answered to somebody not signed in.
///
/// Only a finding: fourteen guesses are fourteen guesses, and V13.4.5 allows what is "explicitly
/// intended", which only the owner can say.
fn exposed_endpoints(responses: &[ProbeResponse]) -> Option<Finding> {
    let found: Vec<(&str, &str, bool)> = EXPOSED_PATHS
        .iter()
        .filter_map(|path| {
            let r = responses.iter().find(|r| r.id == exposed_id(path))?;
            if !(200..300).contains(&r.status) {
                return None;
            }
            exposed_kind(&r.body).map(|(what, monitoring)| (*path, what, monitoring))
        })
        .collect();
    if found.is_empty() {
        return None;
    }
    Some(finding(
        &EXPOSED,
        "Documentation or monitoring pages are open to anybody",
        if found.iter().any(|(_, _, monitoring)| *monitoring) {
            Severity::Medium
        } else {
            Severity::Low
        },
        format!(
            "Asked as somebody not signed in, the app served {}.",
            found
                .iter()
                .map(|(path, what, _)| format!("{what} at {path}"))
                .collect::<Vec<_>>()
                .join("; ")
        ),
    ))
}

/// A development tool's own page, and the words only that page carries, read from each tool's
/// source on 29 September 2026: Werkzeug 3.1.9 (`debug/tbtools.py`, served at `/console` only when
/// the debugger may run code) and Rails 8.1.4 (`application/finisher.rb`, which adds the info pages
/// only in development, and `info.rb`, which writes each property's name in its own cell).
///
/// And on 6 October 2026, from each project's main branch:
/// - Go's `net/http/pprof` (`pprof.go`), whose `init` puts its index on the default router for any
///   program that imports the package, and whose index page is written in `indexTmplExecute`;
/// - Laravel Ignition (`ignition-routes.php`, `RunnableSolutionsGuard.php`,
///   `HealthCheckController.php`), whose routes under `_ignition` answer only with `app.debug` on,
///   in a local or development environment (or with runnable solutions switched on), beside the
///   `execute-solution` route that runs commands;
/// - Symfony's WebProfilerBundle 7.3 (`config/routing/profiler.php`, `ProfilerController.php`,
///   `Profiler/base.html.twig`, `Profiler/results.html.twig`), mounted at `/_profiler` by the
///   recipe only in the dev environment; its home page only redirects, so the search results it
///   redirects to are asked for;
/// - Phoenix LiveDashboard (`router.ex`, `layouts/dash.html.heex`), which the Phoenix generator
///   mounts at `/dev/dashboard` only with `dev_routes` on, and whose layout carries its footer.
struct Console {
    path: &'static str,
    what: &'static str,
    marks: &'static [&'static str],
}

const CONSOLES: &[Console] = &[
    Console {
        path: "/console",
        what: "Werkzeug's interactive console, which runs Python typed into the page",
        marks: &[
            "// Werkzeug Debugger</title>",
            "<h1>Interactive Console</h1>",
        ],
    },
    Console {
        path: "/rails/info/properties",
        what: "Rails' development information page",
        marks: &[
            "<td class=\"name\">Rails version</td>",
            "<td class=\"name\">Environment</td>",
        ],
    },
    Console {
        path: "/debug/pprof/",
        what: "Go's profiler (`net/http/pprof`), which hands anybody the program's memory, \
               goroutines, and command line",
        marks: &[
            "<title>/debug/pprof/</title>",
            "Types of profiles available:",
        ],
    },
    Console {
        path: "/_ignition/health-check",
        what: "Laravel Ignition's endpoints, which answer only with debug mode on, beside the one \
               that runs commands",
        marks: &["\"can_execute_commands\""],
    },
    Console {
        path: "/_profiler/empty/search/results?limit=10",
        what: "Symfony's profiler, which shows every request the app has served, with its \
               settings and `phpinfo()`",
        marks: &["<title>Symfony Profiler</title>", "<h2>Profile Search</h2>"],
    },
    Console {
        path: "/dev/dashboard/home",
        what: "Phoenix LiveDashboard, which shows the running system and can kill its processes",
        marks: &[
            "window.LiveDashboard",
            "Phoenix LiveDashboard was made with love by",
        ],
    },
];

fn console_id(path: &str) -> String {
    format!("console-{}", path.trim_matches('/').replace('/', "-"))
}

const CONSOLE: Rule = Rule {
    rule_id: "probe.development-console-open",
    confidence: Confidence::High,
    // V15.2.3 is development functionality left in production; V13.4.2 is debug modes turned off
    // there. Each page answers only with its tool's debug or development mode on.
    requirement_ids: &["V15.2.3", "V13.4.2"],
    cwe: &["CWE-489", "CWE-215"],
    impact: "A development console is built for the person writing the app, on their own computer. \
             On an address others can reach it shows how the app is set up, and some do more: \
             Werkzeug's runs code on the server for anybody who gets past its PIN, Laravel \
             Ignition's has run commands for anybody at all (CVE-2021-3129), and Go's profiler \
             hands out the program's memory.",
    fix: "Start the app the way it is meant to run for others: debug mode off (`debug=False`, no \
          `FLASK_DEBUG`; `APP_DEBUG=false` in Laravel), Rails and Symfony in the production \
          environment (`RAILS_ENV=production`, `APP_ENV=prod`), Phoenix without `dev_routes`, and \
          no `import _ \"net/http/pprof\"` in a Go program that serves the default router.",
};

/// A development console that answered, judged by the page's own words and never by its status
/// alone: an app that answers every path with its home page is not a console.
///
/// Only ever a finding. Two consoles are two guesses, and one that is not found may be on
/// another path or behind a tool this does not know.
fn development_console(responses: &[ProbeResponse]) -> Option<Finding> {
    let found: Vec<&Console> = CONSOLES
        .iter()
        .filter(|console| {
            responses
                .iter()
                .find(|r| r.id == console_id(console.path))
                .is_some_and(|r| {
                    (200..300).contains(&r.status)
                        && console.marks.iter().all(|m| r.body.contains(m))
                })
        })
        .collect();
    if found.is_empty() {
        return None;
    }
    Some(finding(
        &CONSOLE,
        "A development console answers on the running app",
        Severity::High,
        format!(
            "Asked as somebody not signed in, the app served {}.",
            found
                .iter()
                .map(|c| format!("{} at {}", c.what, c.path))
                .collect::<Vec<_>>()
                .join("; ")
        ),
    ))
}

const VERSION: Rule = Rule {
    rule_id: "probe.version-disclosed",
    confidence: Confidence::High,
    requirement_ids: &["V13.4.6"],
    cwe: &["CWE-200"],
    impact: "A version number tells an attacker which published weaknesses to try first, without \
             having to guess.",
    fix: "Leave the version out: `server_tokens off` in nginx, `ServerTokens Prod` in Apache, \
          `app.disable('x-powered-by')` in Express, and the equivalent for the framework's own \
          headers and error pages.",
};

/// The headers that name what a response came from.
const PRODUCT_HEADERS: &[&str] = &[
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
];

/// A product and its version, as servers write them on error pages: `nginx/1.25.3`,
/// `Apache/2.4.58`, `Werkzeug/3.0.1`, `PHP/8.3.0`.
fn product_version(text: &str) -> Option<String> {
    static PATTERN: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)\b(apache|nginx|openresty|werkzeug|gunicorn|uvicorn|jetty|tomcat|express|php|iis|microsoft-iis|caddy|lighttpd|kestrel|jboss|wildfly|puma|django|rails|node(?:\.js)?)[/ ]v?\d+\.\d+(?:\.\d+)?",
        )
        .expect("a fixed pattern")
    });
    PATTERN.find(text).map(|m| m.as_str().to_owned())
}

/// Version numbers in the headers of every answer, or on the pages the app shows for errors.
///
/// Only a finding: the headers and error pages seen are not every place a version can be shown.
fn version_disclosed(responses: &[ProbeResponse]) -> Option<Finding> {
    let mut seen: Vec<String> = Vec::new();
    for r in responses {
        for name in PRODUCT_HEADERS {
            if let Some(value) = r.header(name)
                && value.chars().any(|c| c.is_ascii_digit())
                && value.contains('.')
            {
                let said = format!("{name}: {}", crate::finding::quoted(value));
                if !seen.contains(&said) {
                    seen.push(said);
                }
            }
        }
        if !(200..300).contains(&r.status)
            && let Some(version) = product_version(&r.body)
        {
            let said = format!("`{version}` on the page for `{}`", r.id);
            if !seen.iter().any(|s| s.contains(&version)) {
                seen.push(said);
            }
        }
    }
    if seen.is_empty() {
        return None;
    }
    Some(finding(
        &VERSION,
        "The app says which versions it runs",
        Severity::Low,
        format!("The app's answers carried {}.", seen.join("; ")),
    ))
}

const OPENER_POLICY: Rule = Rule {
    rule_id: "probe.opener-policy-missing",
    confidence: Confidence::High,
    requirement_ids: &["V3.4.8"],
    cwe: &["CWE-1021"],
    impact: "Without it, a page the app's page opens — or one that opened it — keeps a handle to its \
             window, which cross-window attacks use to steer it or to learn about it.",
    fix: "Send `Cross-Origin-Opener-Policy: same-origin` on every HTML page (or \
          `same-origin-allow-popups` where the app opens sign-in pop-ups).",
};

/// The answers that are HTML pages a browser would open as a document.
fn html_documents(responses: &[ProbeResponse]) -> Vec<&ProbeResponse> {
    responses
        .iter()
        .filter(|r| r.id == "home" || r.id == "missing" || r.id == "root")
        .filter(|r| {
            r.header("content-type")
                .is_some_and(|t| t.to_lowercase().starts_with("text/html"))
        })
        .collect()
}

/// Every HTML page seen carries `Cross-Origin-Opener-Policy: same-origin` or
/// `same-origin-allow-popups`.
fn opener_policy(responses: &[ProbeResponse]) -> Option<Finding> {
    let without: Vec<&str> = html_documents(responses)
        .into_iter()
        .filter(|r| {
            !r.header("cross-origin-opener-policy")
                .is_some_and(|v| v.trim().to_lowercase().starts_with("same-origin"))
        })
        .map(|r| r.id.as_str())
        .collect();
    if without.is_empty() {
        return None;
    }
    Some(finding(
        &OPENER_POLICY,
        "A page does not isolate its window from others",
        Severity::Low,
        format!(
            "The HTML answer for {} came back without Cross-Origin-Opener-Policy set to \
             same-origin or same-origin-allow-popups.",
            without
                .iter()
                .map(|id| format!("`{id}`"))
                .collect::<Vec<_>>()
                .join(" and ")
        ),
    ))
}

const CSP_REPORTING: Rule = Rule {
    rule_id: "probe.csp-no-report",
    confidence: Confidence::High,
    requirement_ids: &["V3.4.7"],
    cwe: &["CWE-778"],
    impact: "A Content-Security-Policy with nowhere to report blocks an attack silently: nobody \
             learns it was tried, or that the policy is breaking a real page.",
    fix: "Add `report-to` (with a `Reporting-Endpoints` header) or `report-uri` to the policy, \
          pointing at somewhere the reports are read.",
};

/// A Content-Security-Policy that names where to report what it blocks. Nothing is said when there
/// is no policy at all: that is the security-headers finding.
fn csp_reporting(home: &ProbeResponse) -> Option<Finding> {
    let policy = home.header("content-security-policy")?.to_lowercase();
    if policy.contains("report-to") || policy.contains("report-uri") {
        return None;
    }
    Some(finding(
        &CSP_REPORTING,
        "The Content-Security-Policy reports nowhere",
        Severity::Low,
        "The app's Content-Security-Policy has neither `report-to` nor `report-uri`.".to_owned(),
    ))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod quoted_tests;
