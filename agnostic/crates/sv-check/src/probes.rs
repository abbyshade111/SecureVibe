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
    .chain(EXPOSED_PATHS.iter().map(|path| ProbeRequest {
        id: exposed_id(path),
        method: "GET".into(),
        path: (*path).to_owned(),
        headers: Vec::new(),
        body: None,
    }))
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
    out.extend(directory_listing(responses));
    out.extend(unused_methods(responses));
    out.extend(jsonp(responses));
    out.extend(exposed_endpoints(responses));
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
// GraphQL and WebSocket, when securevibe.toml names where they are.

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
        body: Some(serde_json::json!({ "query": query }).to_string()),
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
/// what securevibe.toml says.
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
                     answering GraphQL as securevibe.toml says, and nothing else could be asked.",
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
                        "An introspection query was answered with the schema, and securevibe.toml \
                         says no other programs are meant to use this API."
                            .to_owned(),
                    )),
                    (true, Some(true)) => verified.push(crate::Verified::new(
                        GRAPHQL_INTROSPECTION.rule_id,
                        GRAPHQL_INTROSPECTION.requirement_ids,
                        "introspection answered, which V4.3.2 allows for an API meant for other \
                         programs, as securevibe.toml says this one is"
                            .to_owned(),
                    )),
                    (true, None) => not_assessed.push((
                        "V4.3.2".to_owned(),
                        "Introspection is on. That is right for an API other programs are meant to \
                         use and wrong otherwise, and securevibe.toml does not say which this is \
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
                     protocols, so either it is not where securevibe.toml says or it refuses every \
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
                let said = format!("{name}: {value}");
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
        .filter(|r| r.id == "home" || r.id == "missing")
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
                    "default-src 'self'; frame-ancestors 'none'; report-uri /csp-reports",
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
                (
                    "Content-Security-Policy",
                    "frame-ancestors 'none'; report-to csp",
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
                    "default-src 'self'; frame-ancestors 'none'; report-to csp",
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

    #[test]
    fn the_suite_asks_what_it_says_it_asks() {
        let requests = requests("/healthz");
        assert_eq!(
            requests.len(),
            6 + LISTING_PATHS.len() + UNUSED_METHODS.len() + 1 + EXPOSED_PATHS.len()
        );
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
                response(&r.id, if r.path == "/uploads/" { 200 } else { 404 }, &[], body)
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
        assert!(aliases.body.as_deref().unwrap().contains("a999:__typename"));
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
        assert!(
            !ids(&evaluate(std::slice::from_ref(&json))).contains(&"probe.opener-policy-missing")
        );
        assert!(!verified_ids(&[json]).contains(&OPENER_POLICY.rule_id.to_owned()));
    }

    #[test]
    fn a_policy_that_reports_nowhere_is_found_and_one_that_reports_credited() {
        for policy in [
            "default-src 'self'; frame-ancestors 'none'",
            "frame-ancestors 'none'",
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
                    "script-src 'self'; frame-ancestors 'self'",
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
}
