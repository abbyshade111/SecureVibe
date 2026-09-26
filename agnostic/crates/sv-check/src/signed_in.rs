//! What a signed-in user can do, asked of the running app.
//!
//! The probes in `probes.rs` sign in as nobody, so authorization, sessions and request forgery were
//! always *not assessed*. This asks as two ordinary users, A and B — and an admin, when the app's
//! `seed` command makes one — using what `[stack.run.users]` in securevibe.toml says about how to sign
//! up, sign in and out, and which pages and records belong to whom.
//!
//! # Every check establishes its own setup first
//!
//! A test whose setup can fail quietly is worse than no test: B being refused A's note proves nothing
//! if A could not read it either, and "logout ended the session" proves nothing if the session never
//! worked. So each check first shows the thing it relies on — A's session reaches a private page, A
//! can read what A created, the admin can open the admin page — and when it cannot, the check reports
//! *not assessed* with the reason, never a pass.
//!
//! # Judgment here, requests elsewhere
//!
//! Like `probes.rs`, this decides what to ask and how to read the answers; it talks to the app only
//! through [`Http`]. `sv-run` supplies one that speaks from inside the network fence, and the tests
//! supply a scripted app with each flaw switchable, which is how every rule here is shown to fire.

use crate::finding::{Confidence, Finding, Location, Severity};
use crate::probes::{ProbeRequest, ProbeResponse};
use std::collections::BTreeMap;
use sv_manifest::{RequestTemplate, UploadSection, UsersSection};

/// Something that can put a request to the running app and bring back its answer.
pub trait Http {
    fn send(&mut self, request: &ProbeRequest) -> Option<ProbeResponse>;

    /// The emails the app has sent to this address during the run, oldest first, as text: `None`
    /// when the run has no mail sink to read them from. Waits a little for there to be at least
    /// `at_least` of them, since an app may send its mail after it has answered.
    fn mail(&mut self, _to: &str, _at_least: usize) -> Option<Vec<String>> {
        None
    }

    /// Now, in seconds since 1970, by the clock the app is also reading. A test's fake app keeps
    /// its own, so a check that has to wait for the next time step does not really wait.
    fn now(&mut self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    /// Waits this many seconds, by that same clock.
    fn wait(&mut self, seconds: u64) {
        std::thread::sleep(std::time::Duration::from_secs(seconds));
    }

    /// Sends a request to the run's test OpenID Connect provider rather than to the app: `None`
    /// when the run has no provider. The path is the provider's own, query included.
    fn provider(&mut self, _request: &ProbeRequest) -> Option<ProbeResponse> {
        None
    }

    /// Has the run's headless browser do what `job` says, and gives back one answer per action:
    /// `None` when the run has no browser, or it did not finish. See `browser.rs`.
    fn browser(&mut self, _job: &crate::browser::Job) -> Option<Vec<serde_json::Value>> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub user: String,
    pub password: String,
}

/// The accounts the run made: two ordinary users, and an admin when `seed` was asked for one.
#[derive(Debug, Clone)]
pub struct Accounts {
    pub a: Account,
    pub b: Account,
    pub admin: Option<Account>,
    /// Random hex, at least 32 characters, for the passwords the password checks sign up with.
    /// Made with the accounts so every run's are different and none can be guessed from the code.
    pub spare: String,
    /// A third account with two-factor sign-in, when securevibe.toml has a `totp` entry and a
    /// `seed` to enroll it. Never A or B: they have to keep signing in with a password alone.
    pub totp: Option<TotpAccount>,
}

/// An account `seed` enrolled in two-factor sign-in with a secret this run made.
#[derive(Debug, Clone)]
pub struct TotpAccount {
    pub account: Account,
    /// The raw secret. `seed` is given it in base32 as `SV_TOTP_SECRET`.
    pub secret: Vec<u8>,
}

/// What asking as a signed-in user showed.
#[derive(Debug, Default, Clone)]
pub struct Outcome {
    pub findings: Vec<Finding>,
    pub verified: Vec<crate::Verified>,
    /// What could not be asked, and why, in the words the report uses: requirement ids, reason.
    pub not_assessed: Vec<(String, String)>,
    /// What happened, in order, for the run note: "signed in as A", "B was refused A's record".
    pub steps: Vec<String>,
    /// The strings the probes planted for the log check to look for afterwards. See `logs.rs`.
    pub log_markers: crate::logs::Markers,
}

/// The most this check will ever send in one upload.
///
/// A limit stated far above this is not tested: the point is to find an app that takes anything,
/// not to become a denial-of-service attempt against somebody's own app.
const MOST_UPLOAD_BYTES: u64 = 8 * 1024 * 1024;

/// An origin the app has certainly never heard of, for the forgery check.
const STRANGER: &str = "https://sv-probe-stranger.invalid";

// ------------------------------------------------------------------------------------------------
// Sessions

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cookie {
    name: String,
    value: String,
    http_only: bool,
    same_site: Option<String>,
}

fn parse_set_cookie(header: &str) -> Option<Cookie> {
    let mut parts = header.split(';');
    let (name, value) = parts.next()?.split_once('=')?;
    let mut cookie = Cookie {
        name: name.trim().to_owned(),
        value: value.trim().to_owned(),
        http_only: false,
        same_site: None,
    };
    for attribute in parts {
        let attribute = attribute.trim();
        let (key, val) = attribute.split_once('=').unwrap_or((attribute, ""));
        match key.to_lowercase().as_str() {
            "httponly" => cookie.http_only = true,
            "samesite" => cookie.same_site = Some(val.trim().to_lowercase()),
            _ => {}
        }
    }
    Some(cookie)
}

fn set_cookies(response: &ProbeResponse) -> Vec<Cookie> {
    response
        .headers
        .iter()
        .filter(|(k, _)| k == "set-cookie")
        .filter_map(|(_, v)| parse_set_cookie(v))
        .collect()
}

/// What a browser would send back: cookies by name, and a bearer token when sign-in gave one.
#[derive(Debug, Clone, Default)]
pub(crate) struct Session {
    cookies: Vec<(String, String)>,
    bearer: Option<String>,
}

impl Session {
    pub(crate) fn cookies(&self) -> &[(String, String)] {
        &self.cookies
    }

    pub(crate) fn absorb(&mut self, response: &ProbeResponse) {
        for cookie in set_cookies(response) {
            self.cookies.retain(|(n, _)| *n != cookie.name);
            // An emptied cookie is how most frameworks delete one.
            if !cookie.value.is_empty() {
                self.cookies.push((cookie.name, cookie.value));
            }
        }
    }

    fn headers(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        if !self.cookies.is_empty() {
            let line: Vec<String> = self
                .cookies
                .iter()
                .map(|(n, v)| format!("{n}={v}"))
                .collect();
            out.push(("Cookie".to_owned(), line.join("; ")));
        }
        if let Some(token) = &self.bearer {
            out.push(("Authorization".to_owned(), format!("Bearer {token}")));
        }
        out
    }
}

// ------------------------------------------------------------------------------------------------
// Anti-forgery tokens

/// The field and cookie names frameworks put their anti-forgery token under.
const CSRF_FIELDS: &[&str] = &[
    "csrf_token",
    "csrfmiddlewaretoken",
    "authenticity_token",
    "_csrf",
    "_token",
    "csrf",
    "__requestverificationtoken",
];
const CSRF_COOKIES: &[&str] = &["csrftoken", "xsrf-token", "_csrf", "csrf_token", "csrf"];

/// The token a page offers, from a hidden field, a `<meta>` tag, or a cookie.
fn csrf_token(page: &ProbeResponse, session: &Session) -> Option<String> {
    for tag in tags(&page.body, "input") {
        let is_token = attribute(&tag, "name")
            .is_some_and(|n| CSRF_FIELDS.contains(&n.to_lowercase().as_str()));
        if is_token && let Some(value) = attribute(&tag, "value") {
            return Some(value);
        }
    }
    for tag in tags(&page.body, "meta") {
        let names_csrf = attribute(&tag, "name").is_some_and(|n| n.to_lowercase().contains("csrf"));
        if names_csrf && let Some(value) = attribute(&tag, "content") {
            return Some(value);
        }
    }
    session
        .cookies
        .iter()
        .find(|(n, _)| CSRF_COOKIES.contains(&n.to_lowercase().as_str()))
        .map(|(_, v)| v.clone())
}

/// Every `<name ...>` tag in a page, as its text.
fn tags(body: &str, name: &str) -> Vec<String> {
    let lower = body.to_lowercase();
    let open = format!("<{name}");
    lower
        .match_indices(&open)
        .filter(|(i, _)| {
            // `<input` but not `<inputs`: the next character ends the tag name.
            lower[i + open.len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_whitespace() || c == '>' || c == '/')
        })
        .map(|(i, _)| {
            let end = lower[i..].find('>').map_or(body.len(), |e| i + e);
            body[i..end].to_owned()
        })
        .collect()
}

/// An attribute's value from inside one tag, quoted with `"`, with `'`, or not at all — all three
/// are valid HTML, and a page written with unquoted attributes was the first real app this met.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let pattern = regex::Regex::new(&format!(
        r#"(?i)(?:^|\s){}\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))"#,
        regex::escape(name)
    ))
    .ok()?;
    let captures = pattern.captures(tag)?;
    (1..=3)
        .find_map(|i| captures.get(i))
        .map(|m| m.as_str().to_owned())
}

// ------------------------------------------------------------------------------------------------
// Requests from templates

/// The values a template's placeholders stand for in one request.
#[derive(Default, Clone)]
struct Values<'a> {
    user: &'a str,
    password: &'a str,
    csrf: Option<String>,
    marker: &'a str,
    id: &'a str,
    new_password: &'a str,
    code: &'a str,
}

fn fill(text: &str, v: &Values) -> String {
    text.replace("{user}", v.user)
        .replace("{new_password}", v.new_password)
        .replace("{password}", v.password)
        .replace("{csrf}", v.csrf.as_deref().unwrap_or(""))
        .replace("{marker}", v.marker)
        .replace("{id}", v.id)
        .replace("{code}", v.code)
}

fn uses_csrf(t: &RequestTemplate) -> bool {
    t.form
        .values()
        .chain(t.json.values())
        .any(|v| v.contains("{csrf}"))
}

fn form_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn request(id: &str, t: &RequestTemplate, v: &Values, session: &Session) -> ProbeRequest {
    let mut headers = session.headers();
    let body = if !t.json.is_empty() {
        headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
        let map: serde_json::Map<String, serde_json::Value> = t
            .json
            .iter()
            .map(|(k, val)| (k.clone(), serde_json::Value::String(fill(val, v))))
            .collect();
        Some(serde_json::Value::Object(map).to_string())
    } else if !t.form.is_empty() {
        headers.push((
            "Content-Type".to_owned(),
            "application/x-www-form-urlencoded".to_owned(),
        ));
        let pairs: Vec<String> = t
            .form
            .iter()
            .map(|(k, val)| format!("{}={}", form_encode(k), form_encode(&fill(val, v))))
            .collect();
        Some(pairs.join("&"))
    } else {
        Some(String::new())
    };
    if let Some(token) = &v.csrf
        && !token.is_empty()
    {
        // The header most frameworks accept for a token that did not come in a form field.
        headers.push(("X-CSRF-Token".to_owned(), token.clone()));
        headers.push(("X-CSRFToken".to_owned(), token.clone()));
        headers.push(("X-XSRF-TOKEN".to_owned(), token.clone()));
    }
    ProbeRequest {
        id: id.to_owned(),
        method: t.method.to_uppercase(),
        path: fill(&t.path, v),
        headers,
        body,
    }
}

pub(crate) fn get(id: &str, path: &str, session: &Session) -> ProbeRequest {
    ProbeRequest {
        id: id.to_owned(),
        method: "GET".to_owned(),
        path: path.to_owned(),
        headers: session.headers(),
        body: None,
    }
}

pub(crate) fn ok(response: &Option<ProbeResponse>) -> bool {
    response
        .as_ref()
        .is_some_and(|r| (200..300).contains(&r.status))
}

/// Accepted: done, or done and sent elsewhere. A refusal is 4xx; a crash is 5xx.
fn accepted(response: &Option<ProbeResponse>) -> bool {
    response
        .as_ref()
        .is_some_and(|r| (200..400).contains(&r.status))
}

pub(crate) fn status(response: &Option<ProbeResponse>) -> String {
    response
        .as_ref()
        .map_or("no answer".to_owned(), |r| r.status.to_string())
}

/// Sends a templated request, fetching a page for its token first when the template needs one.
///
/// The template's own path is tried first — a form usually posts back to the page that shows it —
/// then `pages`, in order: a sign-out button, for one, lives on every page but its own address
/// often shows nothing at all.
fn send_template(
    http: &mut dyn Http,
    id: &str,
    t: &RequestTemplate,
    values: &Values,
    session: &mut Session,
    pages: &[String],
) -> (Option<ProbeResponse>, Vec<Cookie>) {
    let mut v = values.clone();
    if uses_csrf(t) && v.csrf.is_none() {
        let own = fill(&t.path, &v);
        for path in std::iter::once(&own).chain(pages.iter()) {
            let page = http.send(&get(&format!("{id}-page"), path, session));
            if let Some(page) = &page {
                session.absorb(page);
                v.csrf = csrf_token(page, session);
            }
            if v.csrf.is_some() {
                break;
            }
        }
    }
    let response = http.send(&request(id, t, &v, session));
    let cookies = response.as_ref().map(set_cookies).unwrap_or_default();
    if let Some(r) = &response {
        session.absorb(r);
    }
    (response, cookies)
}

// ------------------------------------------------------------------------------------------------
// Findings

pub(crate) struct Rule {
    pub(crate) rule_id: &'static str,
    pub(crate) requirement_ids: &'static [&'static str],
    pub(crate) cwe: &'static [&'static str],
    pub(crate) impact: &'static str,
    pub(crate) fix: &'static str,
}

pub(crate) fn finding(
    rule: &Rule,
    title: &str,
    severity: Severity,
    description: String,
) -> Finding {
    Finding {
        rule_id: rule.rule_id.to_owned(),
        title: title.to_owned(),
        severity,
        confidence: Confidence::High,
        location: Location {
            file: "the running app".into(),
            line: 1,
        },
        secret: None,
        requirement_ids: rule
            .requirement_ids
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        cwe: rule.cwe.iter().map(|s| (*s).to_owned()).collect(),
        description,
        impact: rule.impact.to_owned(),
        fix: rule.fix.to_owned(),
    }
}

const PRIVATE_PAGE: Rule = Rule {
    rule_id: "probe.private-page-anonymous",
    requirement_ids: &["V8.2.1"],
    cwe: &["CWE-862"],
    impact: "Anybody can open a page meant only for people who have signed in, without signing in.",
    fix: "Require a signed-in session on the server for every page that shows a user's own things, \
          and send anyone without one to the sign-in page.",
};

const ADMIN_PAGE: Rule = Rule {
    rule_id: "probe.admin-page-ordinary-user",
    requirement_ids: &["V8.2.1"],
    cwe: &["CWE-285"],
    impact: "An ordinary account can open a page meant only for administrators, so anyone who signs \
             up can do what an administrator does there.",
    fix: "Check the signed-in user's role on the server before serving an admin page or acting on \
          an admin request; hiding the link is not a check.",
};

const OTHER_USERS_DATA: Rule = Rule {
    rule_id: "probe.other-users-data",
    requirement_ids: &["V8.2.2"],
    cwe: &["CWE-639"],
    impact: "Changing a number in the address is enough to read what another person saved, which is \
             how most data leaks from web apps happen.",
    fix: "Look records up by their owner as well as their id — `where id = ? and owner = ?` — so a \
          record that is not yours is simply not found.",
};

const PRIVATE_PAGE_CACHING: Rule = Rule {
    rule_id: "probe.private-page-cached",
    requirement_ids: &["V14.3.2"],
    cwe: &["CWE-525"],
    impact: "A private page a browser is allowed to store stays on the machine after the person \
             signs out, where the next person to press Back can read it — which is what shared and \
             public computers make ordinary.",
    fix: "Send `Cache-Control: no-store` on every response that shows somebody's own data. \
          `no-cache` is not the same thing: it allows the copy to be kept and asks for it to be \
          revalidated.",
};

const SIGN_OUT_LINK: Rule = Rule {
    rule_id: "probe.no-sign-out-link",
    requirement_ids: &["V7.4.4"],
    cwe: &["CWE-613"],
    impact: "Somebody who cannot find how to sign out stays signed in, and a session left open on \
             a shared machine is the next person's session.",
    fix: "Put a visible sign-out control on every page that needs signing in — a link to the \
          sign-out address, or a small form that posts to it.",
};

const OVERSIZED_FILE: Rule = Rule {
    rule_id: "probe.oversized-file-accepted",
    requirement_ids: &["V5.2.1"],
    cwe: &["CWE-400"],
    impact: "A file larger than the app says it accepts was taken anyway, so anybody can fill the \
             disk or tie the app up processing something enormous.",
    fix: "Refuse a request whose body is larger than the limit before reading it \
          \u{2014} in the web server or the framework, not after the file is already in memory.",
};

const CONTENT_MISMATCH: Rule = Rule {
    rule_id: "probe.file-contents-unchecked",
    requirement_ids: &["V5.2.2"],
    cwe: &["CWE-434"],
    impact: "A file is trusted on the strength of its name. Something that is not an image at all \
             can be stored, and later served, as though it were one.",
    fix: "Read the first bytes of the file and check they are what the extension promises, with a \
          library for the type rather than by hand.",
};

const UPLOAD_EXECUTED: Rule = Rule {
    rule_id: "probe.uploaded-file-executed",
    requirement_ids: &["V5.3.1"],
    cwe: &["CWE-434"],
    impact: "Code somebody uploaded runs on the server when the file is fetched. This is the whole \
             app, and usually the machine: it is the most serious thing an upload can do wrong.",
    fix: "Keep uploads outside the folder the web server serves, hand them back through code that \
          reads and sends the bytes, and never let the server execute anything in that folder.",
};

const UPLOAD_RENDERED: Rule = Rule {
    rule_id: "probe.uploaded-file-rendered",
    requirement_ids: &["V3.2.1"],
    cwe: &["CWE-79"],
    impact: "A page somebody uploaded is shown by the browser as part of this app, so a script in \
             it runs with the app's cookies and can do whatever the signed-in person can.",
    fix: "Serve uploads with `Content-Disposition: attachment`, or with a \
          `Content-Security-Policy: sandbox` header, or from a different hostname \
          \u{2014} any one stops the browser treating the file as a page of this app.",
};

const DOWNLOAD_UNNAMED: Rule = Rule {
    rule_id: "probe.download-unnamed",
    requirement_ids: &["V5.4.1"],
    cwe: &["CWE-116"],
    impact: "The browser names the file from the address instead, which is whatever the person who \
             uploaded it chose, and a name somebody else chose is the start of most download tricks.",
    fix: "Send `Content-Disposition: attachment; filename=\"...\"` with a name the app made or \
          cleaned, not the one that came in with the upload.",
};

const DOWNLOAD_NAME_INJECTED: Rule = Rule {
    rule_id: "probe.download-name-injected",
    requirement_ids: &["V5.4.2"],
    cwe: &["CWE-113"],
    impact: "Whoever names the file writes part of the response header, and can change how the \
             browser handles the download, or what it thinks the file is.",
    fix: "Quote the name and escape what is inside it (RFC 6266), or better, send \
          `filename*=UTF-8''` with the name percent-encoded; most frameworks have a helper for \
          exactly this.",
};

const CLIENT_SIDE_VALIDATION: Rule = Rule {
    rule_id: "probe.validation-only-in-the-browser",
    requirement_ids: &["V2.2.2"],
    cwe: &["CWE-602"],
    impact: "The rule the form shows a person is not applied on the server, so anybody sending the \
             request directly \u{2014} which takes no special tools \u{2014} can put in whatever \
             they like.",
    fix: "Apply every rule the form states again on the server, and refuse the request when it \
          does not hold. The form's own attributes are a good list of what to check.",
};

const SESSION_TOKEN_UNVERIFIED: Rule = Rule {
    rule_id: "probe.session-token-unverified",
    requirement_ids: &["V7.2.1"],
    cwe: &["CWE-290"],
    impact: "A session value this check invented opened a private page, so the app is believing \
             the cookie rather than checking it. Anybody can make one up.",
    fix: "Look the session up on the server on every request \u{2014} in the session store, or by \
          verifying the token's signature \u{2014} and refuse it when it is not found.",
};

const RECORD_LEAKS_FIELDS: Rule = Rule {
    rule_id: "probe.record-returns-secret-fields",
    requirement_ids: &["V15.3.1"],
    cwe: &["CWE-213"],
    impact: "A record handed back to the browser carries fields nobody outside the server should \
             ever see. Whatever is in them has already left.",
    fix: "Return only the fields the page needs, named one by one, rather than handing back the \
          whole row as it came out of the database.",
};

const SESSION_COOKIE: Rule = Rule {
    rule_id: "probe.session-cookie-attributes",
    requirement_ids: &["V3.3.2", "V3.3.4"],
    cwe: &["CWE-1004", "CWE-1275"],
    impact: "A session cookie a script can read is a session any injected script can take; one with \
             no SameSite travels with requests another site makes.",
    fix: "Set HttpOnly and SameSite (Lax or Strict) on the session cookie, and Secure once the app is \
          served over HTTPS.",
};

const SESSION_RENEWAL: Rule = Rule {
    rule_id: "probe.session-not-renewed",
    requirement_ids: &["V7.2.4"],
    cwe: &["CWE-384"],
    impact: "The session id a visitor had before signing in keeps working after, so somebody who \
             planted that id in their browser is signed in as them too.",
    fix: "Issue a new session id at sign-in and discard the old one; most frameworks have a single \
          call for this (regenerate, rotate or cycle the session).",
};

const LOGOUT: Rule = Rule {
    rule_id: "probe.logout-keeps-session",
    requirement_ids: &["V7.4.1"],
    cwe: &["CWE-613"],
    impact: "Signing out does not end the session: a copied cookie, or a shared computer, still has \
             the account after the person has left.",
    fix: "End the session on the server at logout — delete it from the session store, or record the \
          token as revoked — rather than only clearing the cookie in the browser.",
};

const FORGERY: Rule = Rule {
    rule_id: "probe.cross-site-request-accepted",
    requirement_ids: &["V3.5.1"],
    cwe: &["CWE-352"],
    impact: "Another website can make a signed-in person's browser send this request, and the app \
             carries it out as them.",
    fix: "Require an anti-forgery token on every request that changes something, or check the \
          Origin header against the app's own address, and set SameSite on the session cookie.",
};

const SHORT_PASSWORD: Rule = Rule {
    rule_id: "probe.short-password-accepted",
    requirement_ids: &["V6.2.1"],
    cwe: &["CWE-521"],
    impact: "A password of seven characters can be tried exhaustively, and people will choose one if \
             the app lets them.",
    fix: "Refuse passwords shorter than 8 characters at sign-up and at password change; 15 is the \
          recommended minimum.",
};

const COMMON_PASSWORD: Rule = Rule {
    rule_id: "probe.common-password-accepted",
    requirement_ids: &["V6.2.4"],
    cwe: &["CWE-521"],
    impact: "The passwords everybody uses are the first ones anybody trying to get in will try.",
    fix: "Check new passwords against a list of the most common ones (at least the top 3000 that \
          meet the app's length rule) and refuse a match.",
};

const BREACHED_PASSWORD: Rule = Rule {
    rule_id: "probe.breached-password-accepted",
    requirement_ids: &["V6.2.12"],
    cwe: &["CWE-521"],
    impact: "A password other people have already used, and lost, is on the lists anybody trying to \
             get in works through first — long after the top few thousand.",
    fix: "Check new passwords against a large set of breached passwords, not only the most common \
          few thousand: a downloaded copy of the Pwned Passwords list, or its range API, which is \
          sent only the first five characters of the password's SHA-1 hash.",
};

const CONTEXT_WORD_PASSWORD: Rule = Rule {
    rule_id: "probe.context-word-password-accepted",
    requirement_ids: &["V6.2.11"],
    cwe: &["CWE-521"],
    impact: "A password built from the app's own name, or the organization's, is one of the first \
             things somebody who knows where they are will try.",
    fix: "Refuse a new password that contains any word from your list of context-specific words, \
          compared without regard to case.",
};

const STEP_SKIPPED: Rule = Rule {
    rule_id: "probe.flow-step-skipped",
    requirement_ids: &["V2.3.1"],
    cwe: &["CWE-841"],
    impact: "A step that can be skipped is a check that can be skipped: the payment before the order, \
             the confirmation before the change, the approval before the release.",
    fix: "Keep where each person is in the flow on the server, and have every step refuse unless the \
          step before it was completed by the same person in the same flow.",
};

const TOTP_REUSED: Rule = Rule {
    rule_id: "probe.totp-reused",
    requirement_ids: &["V6.5.1"],
    cwe: &["CWE-294"],
    impact: "A code that works twice works for whoever sees it the first time: over a shoulder, in \
             a screenshot, or captured on its way to the app.",
    fix: "Record the last time step each account's code was accepted for, and refuse a code for \
          that step or an earlier one.",
};

const TOTP_OLD_CODE: Rule = Rule {
    rule_id: "probe.totp-old-code-accepted",
    requirement_ids: &["V6.5.5"],
    cwe: &["CWE-613"],
    impact: "A code that still works minutes after it was shown gives anybody who saw it minutes \
             to use it.",
    fix: "Accept the code for the current 30-second step, and at most one step either side for a \
          clock that has drifted.",
};

const FORWARDED_TRUSTED: Rule = Rule {
    rule_id: "probe.forwarded-for-trusted",
    requirement_ids: &["V15.3.4"],
    cwe: &["CWE-348"],
    impact: "Anybody can step around the limit on guessing passwords by claiming a different \
             address in each request, which costs them nothing.",
    fix: "Take the client's address from X-Forwarded-For only when the request came through a \
          proxy you run, and only the entry that proxy added: set the framework's trusted-proxy \
          setting to your proxy rather than reading the header yourself.",
};

const COMPOSITION_RULES: Rule = Rule {
    rule_id: "probe.password-composition-rules",
    requirement_ids: &["V6.2.5"],
    cwe: &["CWE-521"],
    impact: "Rules like \"must contain a digit\" push people towards predictable passwords such as \
             Password1, and refuse long passphrases that are stronger.",
    fix: "Drop the rules about which kinds of character a password must contain; require length, \
          and check against common passwords instead.",
};

const DEFAULT_ACCOUNT: Rule = Rule {
    rule_id: "probe.default-account",
    requirement_ids: &["V6.3.2"],
    cwe: &["CWE-1392"],
    impact: "An account with a name and password everybody knows is an account anybody can sign in \
             to.",
    fix: "Remove the default account, or disable it, and create administrators with passwords chosen \
          when they are set up.",
};

const PASSWORD_IN_URL: Rule = Rule {
    rule_id: "probe.password-in-url",
    requirement_ids: &["V14.2.1"],
    cwe: &["CWE-598"],
    impact: "A password in the address ends up in browser history, server logs, and any proxy in \
             between, where it can be read long after.",
    fix: "Accept sign-in only as a POST with the password in the body, and refuse it in the query \
          string.",
};

const WEAK_SESSION_ID: Rule = Rule {
    rule_id: "probe.session-id-weak",
    requirement_ids: &["V7.2.3"],
    cwe: &["CWE-330"],
    impact: "A session id short enough, or repeated, can be guessed, and a guessed session id is a \
             signed-in session.",
    fix: "Use the framework's own session store, which makes ids of at least 128 random bits from a \
          cryptographically secure generator, rather than making them by hand.",
};

const ALTERED_PASSWORD: Rule = Rule {
    rule_id: "probe.password-altered",
    requirement_ids: &["V6.2.8"],
    cwe: &["CWE-521"],
    impact: "A password that still works when its capitals are changed, or when everything past a \
             certain length is left off, is a much smaller thing to guess than the one the person \
             chose.",
    fix: "Compare the password exactly as it was typed: no changing its case, no cutting it short. \
          If the hashing function has a length limit (bcrypt stops at 72 bytes), hash a digest of the \
          password, or use one without the limit, such as Argon2id.",
};

const LONG_PASSWORD: Rule = Rule {
    rule_id: "probe.long-password-refused",
    requirement_ids: &["V6.2.9"],
    cwe: &["CWE-521"],
    impact: "People who use a password manager or a long passphrase are told to choose something \
             shorter, which is weaker.",
    fix: "Allow passwords of at least 64 characters; there is no need for a maximum below 128.",
};

const UNMASKED_PASSWORD: Rule = Rule {
    rule_id: "probe.password-field-unmasked",
    requirement_ids: &["V6.2.6"],
    cwe: &["CWE-549"],
    impact: "A password typed into an ordinary text field is shown on the screen for anybody nearby \
             to read, and may be remembered by the browser as ordinary text.",
    fix: "Use `<input type=\"password\">` for every password field. A button that lets the person \
          show what they typed is fine; showing it by default is not.",
};

const PASTE_BLOCKED: Rule = Rule {
    rule_id: "probe.password-paste-blocked",
    requirement_ids: &["V6.2.7"],
    cwe: &["CWE-521"],
    impact: "Stopping people pasting a password stops them using a password manager, which pushes \
             them towards short passwords they can type from memory.",
    fix: "Remove the handler that blocks pasting into the password field.",
};

const CHANGE_PASSWORD: Rule = Rule {
    rule_id: "probe.password-change",
    requirement_ids: &["V6.2.2"],
    cwe: &["CWE-620"],
    impact: "A password that cannot really be changed cannot be changed after it leaks: the old one \
             keeps working.",
    fix: "Replace the stored password hash when the password is changed, so only the new password \
          signs in afterwards.",
};

const CHANGE_WITHOUT_CURRENT: Rule = Rule {
    rule_id: "probe.password-change-without-current",
    requirement_ids: &["V6.2.3"],
    cwe: &["CWE-620"],
    impact: "Anybody who gets hold of a signed-in session for a moment, on a shared computer or \
             through a stolen cookie, can change the password and keep the account.",
    fix: "Ask for the current password when the password is changed, check it against the stored \
          hash, and refuse the change when it does not match.",
};

const RESET_REUSABLE: Rule = Rule {
    rule_id: "probe.reset-reusable",
    requirement_ids: &["V6.4.3"],
    cwe: &["CWE-640"],
    impact: "A reset link that works more than once works for whoever finds it next — in a mailbox, \
             a browser history, or a forwarded email — long after the owner used it.",
    fix: "Mark the reset code as used, or delete it, in the same step that sets the new password, \
          and refuse a code that has been used.",
};

const RESET_KEEPS_OLD: Rule = Rule {
    rule_id: "probe.reset-keeps-old-password",
    requirement_ids: &["V6.4.3"],
    cwe: &["CWE-640"],
    impact: "Somebody who resets a password because it leaked is still locked in with whoever has the \
             old one.",
    fix: "Replace the stored password hash when the password is reset, so only the new password \
          signs in afterwards.",
};

const RESET_CODE_GUESSABLE: Rule = Rule {
    rule_id: "probe.reset-code-guessable",
    requirement_ids: &["V6.4.3"],
    cwe: &["CWE-640", "CWE-330"],
    impact: "A reset code that can be guessed lets anybody who knows an email address take the \
             account, without ever seeing the email.",
    fix: "Make each reset code from a secure random generator, long enough that guessing is hopeless \
          (16 random bytes is a common choice), and never reuse or count up from an earlier one.",
};

const RESET_REVEALS_ACCOUNT: Rule = Rule {
    rule_id: "probe.reset-reveals-account",
    requirement_ids: &["V6.3.8"],
    cwe: &["CWE-204"],
    impact: "Anybody can find out whether an email address has an account, which is where guessing \
             passwords and targeted phishing begin.",
    fix: "Answer a reset request the same way whether or not the address has an account — the same \
          status and the same words, such as \"if that address has an account, we have sent it a \
          link\" — and send the email, or not, afterwards.",
};

const EMAIL_CODE_REUSABLE: Rule = Rule {
    rule_id: "probe.email-code-reusable",
    requirement_ids: &["V6.5.1"],
    cwe: &["CWE-294"],
    impact: "A sign-in code or link that works more than once signs in whoever finds it next — in a \
             mailbox, a browser history, or a forwarded email.",
    fix: "Mark the code as used, or delete it, in the same step that signs the user in, and refuse a \
          code that has been used.",
};

const EMAIL_CODE_UNBOUND: Rule = Rule {
    rule_id: "probe.email-code-unbound",
    requirement_ids: &["V6.6.2"],
    cwe: &["CWE-294"],
    impact: "A code that completes a sign-in other than the one it was sent for can be used by \
             somebody who started their own sign-in and then got hold of the code — a phishing page \
             that asks for it is enough.",
    fix: "Tie each code to the sign-in request that asked for it, for instance by storing the \
          session it was asked from, and refuse it anywhere else.",
};

const EMAIL_CODE_SHORT: Rule = Rule {
    rule_id: "probe.email-code-short",
    requirement_ids: &["V6.5.4"],
    cwe: &["CWE-330"],
    impact: "A sign-in code short enough to guess lets anybody who knows an email address sign in \
             as its owner without ever seeing the email.",
    fix: "Make each code from a secure random generator, with at least six random digits (20 bits), \
          and more for a code in a link.",
};

const EMAIL_CODE_GUESSING: Rule = Rule {
    rule_id: "probe.email-code-guessing-unlimited",
    requirement_ids: &["V6.6.3"],
    cwe: &["CWE-307"],
    impact: "Codes can be tried until one works: at six digits, a million tries sign anybody in.",
    fix: "Count wrong codes for each sign-in request and each account, and after a few, refuse more \
          attempts or cancel the code and ask for a new one.",
};

const NO_IDLE_TIMEOUT: Rule = Rule {
    rule_id: "probe.session-idle-timeout",
    requirement_ids: &["V7.3.1"],
    cwe: &["CWE-613"],
    impact: "A session left open on a shared or stolen computer stays signed in long after its owner \
             walked away.",
    fix: "End a session that has not been used for the time you stated, on the server: record when \
          it was last used, and refuse it once that is longer ago than the timeout.",
};

const NO_SESSION_LIFETIME: Rule = Rule {
    rule_id: "probe.session-lifetime",
    requirement_ids: &["V7.3.2"],
    cwe: &["CWE-613"],
    impact: "A session kept busy — by its owner, or by whoever stole it — never has to sign in again.",
    fix: "Record when each session began, and ask for the password again once it is older than the \
          lifetime you stated, however recently it was used.",
};

const SESSIONS_SURVIVE_DELETION: Rule = Rule {
    rule_id: "probe.sessions-survive-deletion",
    requirement_ids: &["V7.4.2"],
    cwe: &["CWE-613"],
    impact: "An account that has been deleted can still be used from any browser that was signed in \
             to it, so deleting a compromised or departed person's account does not lock them out.",
    fix: "When an account is deleted or disabled, delete every session belonging to it from the \
          session store, or check on each request that the session's account still exists.",
};

const PASSWORD_HINTS: Rule = Rule {
    rule_id: "probe.password-hints",
    requirement_ids: &["V6.4.2"],
    cwe: &["CWE-640"],
    impact: "A password hint or a secret question is a second, weaker password: the answer to \
             \"your first pet\" is often on a social media profile.",
    fix: "Remove password hints and secret questions; recover accounts through a link sent to the \
          email address or phone the person registered.",
};

const NO_BRUTE_FORCE_LIMIT: Rule = Rule {
    rule_id: "probe.failed-sign-ins-unlimited",
    requirement_ids: &["V6.3.1"],
    cwe: &["CWE-307"],
    impact: "Someone can try passwords as fast as the network allows, so a weak or leaked password              is found in minutes rather than never. This is how most accounts are actually taken.",
    fix: "Count failed sign-ins per account and per address, and once the number you stated is           reached, slow the next attempt down or refuse it for a while. Refusing for a while beats           locking the account outright, which lets somebody lock a real person out on purpose.",
};

const SIGN_OUT_ON_GET: Rule = Rule {
    rule_id: "probe.sign-out-on-get",
    requirement_ids: &["V3.5.3"],
    cwe: &["CWE-352"],
    impact: "Signing out by visiting an address means any page, image, or link can sign a person out \
             without their asking, and it is a sign that other actions may be reachable the same \
             way.",
    fix: "Accept sign-out, and anything else that changes something, only as a POST (or PUT, PATCH, \
          DELETE), and answer a GET to it with an error or a page asking to confirm.",
};

/// A password from the top 3000 most common that meets an 8-character rule: line 1,238 of
/// `data/knowledge/common-passwords.txt`.
const COMMON: &str = "123qweasdzxc";

/// A password far down the common list, at line 12,393 of `data/knowledge/common-passwords.txt`:
/// well past the top 3000 that V6.2.4 asks about, so an app that checks only those accepts it, and
/// 16 characters, so a length rule of up to 16 does not refuse it first. That it is breached is
/// not taken from the list, whose source is recorded nowhere: it is Have I Been Pwned's count, in
/// `data/breached-password-evidence.json`, and `BREACHED_SEEN` below says it in the finding. A test
/// holds the two to that file, so neither can change without new evidence.
const BREACHED: &str = "1qaz2wsx3edc4rfv";

/// How often Pwned Passwords has seen `BREACHED`, and when that was checked.
const BREACHED_SEEN: &str = "133,732 times, as of 26 September 2026";

/// A password with the same shape as `template` — each lowercase letter, capital, and digit
/// replaced by a random one of the same kind, everything else kept — made from `spare`, the random
/// material every run has. The control that says a refusal was about *these* characters and not
/// about their length or kinds.
fn random_like(template: &str, spare: &str) -> String {
    let nibbles: Vec<u8> = spare
        .chars()
        .filter_map(|c| c.to_digit(16))
        .map(|d| d as u8)
        .collect();
    template
        .chars()
        .enumerate()
        .map(|(i, c)| {
            let n = nibbles[i % nibbles.len()];
            match c {
                'a'..='z' => (b'a' + n) as char,
                'A'..='Z' => (b'A' + n) as char,
                '0'..='9' => (b'0' + n % 10) as char,
                other => other,
            }
        })
        .collect()
}

/// The password tried for V6.2.11: the first word of at least four letters or digits in the
/// owner's list, lowercased and repeated to at least 16 characters, so no length rule refuses it
/// first. `None` when no word on the list is long enough to mean anything.
fn context_password(words: &[String]) -> Option<(String, String)> {
    let word = words.iter().find_map(|w| {
        let kept: String = w
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>()
            .to_ascii_lowercase();
        (4..=32).contains(&kept.len()).then_some((w.clone(), kept))
    })?;
    let (named, kept) = word;
    let mut password = kept.clone();
    while password.len() < 16 {
        password.push_str(&kept);
    }
    Some((named, password))
}

/// Accounts somebody might leave in place, tried with their name as the password and with
/// `password`.
const DEFAULT_ACCOUNTS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("administrator", "administrator"),
];

// ------------------------------------------------------------------------------------------------
// The suite

/// A user signed in, with what the sign-in showed.
struct SignedIn {
    session: Session,
    /// Cookies set by the sign-in response itself: the session cookies.
    set_at_login: Vec<Cookie>,
    /// Cookies the app had given before sign-in.
    before_login: Vec<(String, String)>,
}

fn sign_in(
    http: &mut dyn Http,
    users: &UsersSection,
    who: &str,
    account: &Account,
    steps: &mut Vec<String>,
) -> Option<SignedIn> {
    let login = users.login.as_ref()?;
    let mut session = Session::default();
    // The sign-in page first, as a browser would: this is where a token and a pre-login session
    // cookie come from.
    let mut csrf = None;
    if let Some(page) = http.send(&get(&format!("login-page-{who}"), &login.path, &session)) {
        session.absorb(&page);
        csrf = csrf_token(&page, &session);
    }
    let before_login = session.cookies.clone();
    let values = Values {
        user: &account.user,
        password: &account.password,
        csrf,
        ..Default::default()
    };
    let (response, set_at_login) = send_template(
        http,
        &format!("login-{who}"),
        login,
        &values,
        &mut session,
        &[],
    );
    let response = response?;
    steps.push(format!(
        "signed in as {} ({}{})",
        who.to_uppercase(),
        response.status,
        if values.csrf.is_some() {
            ", with the page's anti-forgery token"
        } else {
            ""
        }
    ));
    if let Some(field) = &users.token_field {
        session.bearer = serde_json::from_str::<serde_json::Value>(&response.body)
            .ok()
            .and_then(|v| v.get(field).and_then(|t| t.as_str()).map(str::to_owned));
    }
    Some(SignedIn {
        session,
        set_at_login,
        before_login,
    })
}

/// Everything the signed-in probes can ask, given what securevibe.toml says.
///
/// `seeded` says whether `seed` already made the accounts; when it did not, they are made through the
/// app's own sign-up.
pub fn run(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    seeded: bool,
    policy: &sv_manifest::PolicySection,
) -> Outcome {
    run_with(http, users, accounts, seeded, policy, false)
}

/// `run`, and with `slow` also the checks that have to wait: the session timeouts the owner states,
/// waited out (`sv run --slow`).
pub fn run_with(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    seeded: bool,
    policy: &sv_manifest::PolicySection,
    slow: bool,
) -> Outcome {
    let mut out = Outcome::default();
    let problems = users.problems();
    if !problems.is_empty() {
        out.not_assessed.push((
            "V8.2.1, V8.2.2, V7.2.4, V7.4.1, V3.5.1, V14.3.2, V7.4.4".to_owned(),
            format!(
                "[stack.run.users] in securevibe.toml cannot be used: {}.",
                problems.join("; ")
            ),
        ));
        return out;
    }
    // The Secure attribute cannot be judged here at all, and saying so beats a finding every app
    // would get: inside the fence the app is reached over plain HTTP.
    out.not_assessed.push((
        "V3.3.1".to_owned(),
        "Whether cookies carry Secure: the app was reached over plain HTTP inside the fence, where \
         many apps rightly leave it off. Check the production settings."
            .to_owned(),
    ));

    if !seeded && let Some(signup) = &users.signup {
        for (who, account) in [("a", &accounts.a), ("b", &accounts.b)] {
            let response = sign_up(http, signup, who, account);
            out.steps.push(format!(
                "signed up {} ({})",
                who.to_uppercase(),
                status(&response)
            ));
        }
    }

    // 1. Private pages, as nobody. This needs no account, so it runs whatever happens next.
    let anonymous = Session::default();
    let mut served_anonymously = Vec::new();
    for path in &users.private {
        let response = http.send(&get("private-anonymous", path, &anonymous));
        if ok(&response) {
            served_anonymously.push(path.clone());
        }
    }
    if !served_anonymously.is_empty() {
        out.findings.push(finding(
            &PRIVATE_PAGE,
            "A page meant for signed-in users opens without signing in",
            Severity::High,
            format!(
                "Asked as somebody who had not signed in, the app served {}.",
                served_anonymously.join(", ")
            ),
        ));
    }

    // 2. Signing in, and showing it worked. Without this every check below would be comparing
    //    refusals to refusals.
    let Some(a) = sign_in(http, users, "a", &accounts.a, &mut out.steps) else {
        out.not_assessed.push((
            "V8.2.1, V8.2.2, V7.2.4, V7.4.1, V3.5.1, V3.3.2, V3.3.4, V14.3.2, V7.4.4".to_owned(),
            "Signing in as the first test user got no answer from the app.".to_owned(),
        ));
        return out;
    };
    let confirm_path = users.private.first().cloned();
    let signed_in_works = match &confirm_path {
        Some(path) => {
            let response = http.send(&get("private-a", path, &a.session));
            let works = ok(&response) && !served_anonymously.contains(path);
            out.steps.push(format!(
                "signed in as A and opened {path} ({})",
                status(&response)
            ));
            works
        }
        None => false,
    };
    if confirm_path.is_some() && !signed_in_works && served_anonymously.is_empty() {
        out.not_assessed.push((
            "V8.2.1, V8.2.2, V7.2.4, V7.4.1, V3.5.1, V3.3.2, V3.3.4, V14.3.2, V7.4.4".to_owned(),
            format!(
                "Signing in as the first test user did not open {} — the sign-in request, the \
                 accounts, or the page is not what securevibe.toml says — so nothing here can say \
                 what a signed-in user can do.",
                confirm_path.as_deref().unwrap_or("")
            ),
        ));
        return out;
    }
    if signed_in_works && served_anonymously.is_empty() {
        out.verified.push(crate::Verified::new(
            PRIVATE_PAGE.rule_id,
            PRIVATE_PAGE.requirement_ids,
            format!(
                "{} private page{}, refused to somebody not signed in and opened by a signed-in user",
                users.private.len(),
                if users.private.len() == 1 { "" } else { "s" }
            ),
        ));
    }

    // 2b. The session timeouts, which mean waiting. Here, while A's password is still the one it
    //     was made with — later checks change it when there is no sign-up — and with sessions of
    //     its own, so nothing below is using them.
    session_timeout_checks(
        http,
        users,
        &accounts.a,
        confirm_path.as_deref().filter(|_| signed_in_works),
        policy,
        slow,
        &mut out,
    );

    // 3. A record A owns, read as B and as nobody; then the same request from another site. First
    //    among the signed-in checks because A reading back what A made is the second way to show
    //    the session works — the only way, when the private page turned out to be open to all.
    let owned_read = owned_checks(http, users, accounts, &a, &mut out);

    // 4. The session cookie, and whether signing in made a new one.
    session_checks(&a, signed_in_works || owned_read.is_some(), &mut out);

    // 4b. The markers the log check reads afterwards. Done here because the successful one has to
    //     be a sign-in that really worked, and the refused one a page that is really private.
    plant_log_markers(http, users, accounts, signed_in_works, &mut out);

    // 5. The private pages themselves, read with A's session: what they let a browser keep, and
    //    whether they show a way out. Before anything that signs another account in, so the
    //    session that opened them is the one step 2 showed working.
    private_page_checks(http, users, &a, &mut out);

    // 5b. The same pages drawn in a real browser, when securevibe.toml asks for one, with A's
    //     cookies: whether the way out can be seen, and whether text typed into a form comes back
    //     as text. Here for the same reason as step 5, and it signs nobody else in.
    crate::browser::checks(
        http,
        users,
        &a.session,
        signed_in_works,
        &crate::browser::token(&accounts.spare),
        &mut out,
    );

    // 6. Admin pages, as an ordinary user, confirmed against the admin.
    admin_checks(http, users, accounts, &a, &mut out);

    // 6a. Three more, each reading something the run already has or sending one more request:
    //     a session value this check invented, the rules the sign-up form states, and whether the
    //     record read back above carried fields that should not leave the server.
    invented_session_check(
        http,
        &a,
        confirm_path.clone().filter(|_| signed_in_works).as_deref(),
        &mut out,
    );
    client_side_validation_check(http, users, accounts, &mut out);

    // 6b. Uploads, with A's session, before anything below signs another account in. Placed here
    //     rather than at the end because it needs a working session and nothing it does disturbs
    //     one: it posts files and fetches them back.
    upload_checks(http, users, &a, &mut out);

    // 6c. A flow of several steps, gone through in order with A's session and then skipped as B,
    //     signed in afresh. Neither disturbs A's session.
    flow_checks(http, users, accounts, &a, &mut out);

    // 7. What sign-up and sign-in let through: passwords and default accounts. These sign in as
    //    other accounts, so A's session is untouched for the sign-out below.
    let confirm = confirm_path.clone().filter(|_| signed_in_works);
    password_checks(http, users, accounts, confirm.as_deref(), policy, &mut out);
    default_account_check(http, users, confirm.as_deref(), &mut out);
    password_field_checks(http, users, Some(&a.session), &mut out);

    // 8. Logging out, which ends A's session.
    logout_check(
        http,
        users,
        &a,
        confirm_path.filter(|_| signed_in_works).or(owned_read),
        &mut out,
    );

    // 9. Last, because each signs A in again, and an app that allows one session per user would
    //    end the one the checks above were using.
    password_in_url_check(http, users, &accounts.a, confirm.as_deref(), &mut out);
    session_id_check(http, users, accounts, &a, signed_in_works, &mut out);
    sign_out_on_get_check(http, users, &accounts.a, confirm.as_deref(), &mut out);

    // 10. Last of all, because it changes a password: with an account made for it when there is a
    //    sign-up, and with A's own when there is not.
    change_password_checks(http, users, accounts, confirm.as_deref(), &mut out);
    delete_account_check(http, users, accounts, confirm.as_deref(), &mut out);
    reset_checks(http, users, accounts, confirm.as_deref(), &mut out);
    email_code_checks(http, users, accounts, confirm.as_deref(), &mut out);
    totp_checks(http, users, accounts, confirm.as_deref(), &mut out);

    // 10. After everything else, without exception. This one deliberately provokes the app into
    //     refusing requests, and a limiter that counts by address rather than by account would then
    //     be refusing every check above too. Running it last means the worst it can cost is itself.
    brute_force_check(http, users, accounts, policy, &mut out);
    // And codes after passwords: both set out to be refused, and this one is the newer.
    email_code_guessing(http, users, accounts, confirm.as_deref(), policy, &mut out);

    out
}

/// One wrong sign-in attempt, carrying `extra` headers, in a fresh session; the status it got, 0 for
/// no answer.
fn guess_once(
    http: &mut dyn Http,
    login: &RequestTemplate,
    wrong: &Account,
    id: &str,
    extra: &[(&str, &str)],
) -> u16 {
    let mut session = Session::default();
    let mut csrf = None;
    if let Some(page) = http.send(&get(&format!("{id}-page"), &login.path, &session)) {
        session.absorb(&page);
        csrf = csrf_token(&page, &session);
    }
    let values = Values {
        user: &wrong.user,
        password: &wrong.password,
        csrf,
        ..Default::default()
    };
    let mut req = request(id, login, &values, &session);
    for (k, v) in extra {
        req.headers.push(((*k).to_owned(), (*v).to_owned()));
    }
    http.send(&req).map_or(0, |r| r.status)
}

/// Whether the limit on guessing believes an address the client made up (V15.3.4).
///
/// Called once the brute-force check has seen the app refuse. Two more wrong attempts, each
/// claiming a different new address from the range set aside for documentation, in every header an
/// app might take one from; then two more claiming nothing. Both claimed attempts answered as the
/// very first attempt was, while both plain ones are still refused, is a limiter that let a header
/// the client wrote lift it. The plain pair is the control: a limit that lifted by itself lifts for
/// them too.
///
/// Two of each, not one: a limiter that lets one attempt through for every one it refuses — a token
/// bucket, a sliding window, `nginx limit_req` — answers one claimed and one plain attempt in exactly
/// the pattern of a limit that believes the header, and reported a correct app for it. Found in
/// review with a fake limiter that leaks (`lockout_leaks`). Alternating the attempts does not help:
/// such a limiter produces exactly that alternation. The remaining blind spot is the other
/// direction — a leaky limiter can still hide an app that does trust the header — which is the safe
/// one, since this is only ever a finding.
///
/// Only ever a finding. An app whose limit counts by account is not moved by the header at all,
/// and that shows nothing about how it treats addresses.
fn forwarded_check(
    http: &mut dyn Http,
    login: &RequestTemplate,
    wrong: &Account,
    first_status: u16,
    out: &mut Outcome,
) {
    const ADDRESSES: [&str; 2] = ["203.0.113.77", "203.0.113.78"];
    let spoofed: Vec<u16> = ADDRESSES
        .iter()
        .enumerate()
        .map(|(n, address)| {
            let forwarded = format!("for={address}");
            guess_once(
                http,
                login,
                wrong,
                &format!("guess-forwarded-{n}"),
                &[
                    ("X-Forwarded-For", address),
                    ("X-Real-IP", address),
                    ("Forwarded", &forwarded),
                ],
            )
        })
        .collect();
    let plain: Vec<u16> = (0..2)
        .map(|n| {
            guess_once(
                http,
                login,
                wrong,
                &format!("guess-after-forwarded-{n}"),
                &[],
            )
        })
        .collect();
    let lifted = spoofed.iter().all(|s| *s == first_status);
    let still_refused = plain.iter().all(|p| *p != first_status);
    let said = |answers: &[u16]| {
        let all_first = answers.iter().all(|a| *a == first_status);
        let none_first = answers.iter().all(|a| *a != first_status);
        let list = answers
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        if all_first {
            format!("answered {list}, as the first attempt was")
        } else if none_first {
            format!("still refused ({list})")
        } else {
            format!("answered {list}, one as the first attempt was and one refused")
        }
    };
    out.steps.push(format!(
        "two more wrong attempts claiming to come from {} and {}: {}; two more claiming nothing: {}",
        ADDRESSES[0],
        ADDRESSES[1],
        said(&spoofed),
        said(&plain)
    ));
    if lifted && still_refused {
        out.findings.push(finding(
            &FORWARDED_TRUSTED,
            "The limit on guessing passwords can be lifted by claiming another address",
            Severity::Medium,
            format!(
                "After the app started refusing wrong passwords, two more attempts, carrying \
                 `X-Forwarded-For: {}` and then `{}`, were both answered as the very first attempt \
                 was, while the two after them, claiming nothing, were both still refused. Nothing \
                 sits in front of the app here, so the addresses came from the requests \
                 themselves.",
                ADDRESSES[0], ADDRESSES[1]
            ),
        ));
    }
}

/// The most `sv run --slow` waits, in all. A lifetime stated longer is not waited out.
const MOST_WAIT_MINUTES: u32 = 90;

/// Whether sessions end when the owner says they should (V7.3.1, V7.3.2), which means waiting.
///
/// Two sessions of A's, both shown open first. One is left alone; the other is kept busy, a request
/// every so often. After the idle timeout and a minute more, the idle one must be refused and the
/// busy one must still work — the busy one is what shows the idle one was refused for being idle,
/// rather than because every session died or the app stopped answering. After the lifetime and a
/// minute more, the busy one must be refused too, and a sign-in begun then must still work.
///
/// The numbers are the owner's (`idle-timeout-minutes`, `session-lifetime-minutes`), as
/// `failed-sign-ins` is: the requirements ask for timeouts "according to documented security
/// decisions", and a number can be held to where prose cannot. Only with `--slow`.
fn session_timeout_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    a: &Account,
    confirm: Option<&str>,
    policy: &sv_manifest::PolicySection,
    slow: bool,
    out: &mut Outcome,
) {
    let idle = policy.idle_timeout_minutes;
    let lifetime = policy.session_lifetime_minutes;
    let say = |id: &str, why: String, out: &mut Outcome| {
        out.not_assessed.push((id.to_owned(), why));
    };
    if idle.is_none() && lifetime.is_none() {
        say(
            "V7.3.1, V7.3.2",
            "Whether sessions time out: say after how long, as `idle-timeout-minutes` and \
             `session-lifetime-minutes` under [policy] in securevibe.toml, and run `sv run --slow`, \
             which waits that long and then asks."
                .to_owned(),
            out,
        );
        return;
    }
    if !slow {
        say(
            "V7.3.1, V7.3.2",
            "Whether sessions time out when securevibe.toml says they should: that means waiting, \
             so it is asked only by `sv run --slow`."
                .to_owned(),
            out,
        );
        return;
    }
    let Some(confirm) = confirm else {
        say(
            "V7.3.1, V7.3.2",
            "Whether sessions time out: telling needs a private page a signed-in user alone can \
             open, and none was shown."
                .to_owned(),
            out,
        );
        return;
    };
    // What will be waited out, within the most this waits.
    let lifetime = match lifetime {
        Some(0) | None => None,
        Some(l) if l > MOST_WAIT_MINUTES => {
            say(
                "V7.3.2",
                format!(
                    "A session lifetime of {l} minutes is longer than the {MOST_WAIT_MINUTES} this \
                     waits, so it was not waited out."
                ),
                out,
            );
            None
        }
        Some(l) => Some(l),
    };
    let idle = match idle {
        Some(0) | None => None,
        Some(i) if i + 1 > MOST_WAIT_MINUTES => {
            say(
                "V7.3.1",
                format!(
                    "An idle timeout of {i} minutes is longer than the {MOST_WAIT_MINUTES} this \
                     waits, so it was not waited out."
                ),
                out,
            );
            None
        }
        // A session that must end within the idle timeout anyway cannot show idleness is what
        // ended it: the busy one would end too.
        Some(i) if lifetime.is_some_and(|l| l <= i) => {
            say(
                "V7.3.1",
                format!(
                    "The idle timeout, {i} minutes, is no shorter than the session lifetime, so a \
                     session refused after it cannot be told to have ended for being idle."
                ),
                out,
            );
            None
        }
        Some(i) => Some(i),
    };
    if idle.is_none() && lifetime.is_none() {
        return;
    }

    let opens = |http: &mut dyn Http, session: &Session, label: &str| {
        ok(&http.send(&get(&format!("timeout-{label}"), confirm, session)))
    };
    let mut quiet = Vec::new();
    let (Some(left), Some(busy)) = (
        sign_in(http, users, "idle", a, &mut quiet),
        sign_in(http, users, "busy", a, &mut quiet),
    ) else {
        return;
    };
    let (left, busy) = (left.session, busy.session);
    if !(opens(http, &left, "idle-start") && opens(http, &busy, "busy-start")) {
        say(
            "V7.3.1, V7.3.2",
            "Whether sessions time out: two new sessions of the first test user did not both open \
             the private page to begin with."
                .to_owned(),
            out,
        );
        return;
    }
    let began = http.now();
    // Kept busy well inside the shortest timeout, and never idle for more than two minutes.
    let every = idle.map_or(120, |i| (u64::from(i) * 60 / 3).clamp(10, 120));
    let wait_until = |http: &mut dyn Http, until: u64| {
        while http.now() < until {
            let left = until - http.now();
            http.wait(every.min(left));
            ok(&http.send(&get("timeout-keep-busy", confirm, &busy)));
        }
    };

    if let Some(minutes) = idle {
        wait_until(http, began + u64::from(minutes) * 60 + 60);
        let left_open = opens(http, &left, "idle-after");
        let busy_open = opens(http, &busy, "busy-after-idle");
        out.steps.push(format!(
            "after {} minutes, a session left alone {} and one kept busy {}",
            minutes + 1,
            if left_open {
                "still opened the private page"
            } else {
                "was refused"
            },
            if busy_open {
                "still opened it"
            } else {
                "was refused"
            },
        ));
        if left_open {
            out.findings.push(finding(
                &NO_IDLE_TIMEOUT,
                "A session left unused does not time out",
                Severity::Medium,
                format!(
                    "securevibe.toml says a session should end after {} unused. A \
                     session left alone for {} minutes still opened {confirm}.",
                    minutes_text(minutes),
                    minutes + 1
                ),
            ));
        } else if busy_open {
            out.verified.push(crate::Verified::new(
                NO_IDLE_TIMEOUT.rule_id,
                NO_IDLE_TIMEOUT.requirement_ids,
                format!(
                    "a session left unused for {} minutes, refused, where one kept busy for the \
                     same time still opened the private page; the timeout you stated is {}",
                    minutes + 1,
                    minutes_text(minutes)
                ),
            ));
        } else {
            say(
                "V7.3.1",
                "A session left unused was refused, but so was one kept busy, so it cannot be \
                 said to have ended for being idle."
                    .to_owned(),
                out,
            );
        }
    }

    if let Some(minutes) = lifetime {
        wait_until(http, began + u64::from(minutes) * 60 + 60);
        let busy_open = opens(http, &busy, "busy-after-lifetime");
        let fresh = sign_in(http, users, "after-lifetime", a, &mut quiet)
            .is_some_and(|s| opens(http, &s.session, "fresh-after-lifetime"));
        out.steps.push(format!(
            "after {} minutes, the session kept busy {}, and a new sign-in {}",
            minutes + 1,
            if busy_open {
                "still opened the private page"
            } else {
                "was refused"
            },
            if fresh { "worked" } else { "did not" },
        ));
        if busy_open {
            out.findings.push(finding(
                &NO_SESSION_LIFETIME,
                "A session kept busy never has to sign in again",
                Severity::Medium,
                format!(
                    "securevibe.toml says a session should last at most {}. One \
                     used every {every} seconds still opened {confirm} after {} minutes.",
                    minutes_text(minutes),
                    minutes + 1
                ),
            ));
        } else if fresh {
            out.verified.push(crate::Verified::new(
                NO_SESSION_LIFETIME.rule_id,
                NO_SESSION_LIFETIME.requirement_ids,
                format!(
                    "a session used every {every} seconds, refused after {} minutes, where a new \
                     sign-in then worked; the lifetime you stated is {}",
                    minutes + 1,
                    minutes_text(minutes)
                ),
            ));
        } else {
            say(
                "V7.3.2",
                "The busy session was refused at the end of its lifetime, but a new sign-in then \
                 did not work either, so the refusal cannot be said to be the lifetime."
                    .to_owned(),
                out,
            );
        }
    }
}

/// "1 minute", "15 minutes".
fn minutes_text(n: u32) -> String {
    format!("{n} minute{}", if n == 1 { "" } else { "s" })
}

/// Whether the app pushes back after the number of wrong passwords the owner said it would (V6.3.1).
///
/// V6.3.1 asks that brute-force controls are implemented *according to the application's security
/// documentation*, which nothing can check against prose. A number can be checked: `failed-sign-ins`
/// in securevibe.toml is the owner stating the policy, and the probe holds the app to it by making
/// one more wrong attempt than that and watching what changes.
///
/// What counts as pushing back is deliberately broad — a different status, a refusal, a lockout or
/// an error page, or an attempt that takes markedly longer than the first. Narrowing it would make
/// the check report apps that defend themselves in a way this did not anticipate, and a check that
/// cries wolf is one people learn to skip.
///
/// Three things it does not do. It never uses A or B, whose sessions the checks above depend on,
/// and never the admin: it makes its own account through `signup`, or uses a name no account can
/// have. It does not test `within-minutes`, because every attempt here lands within a few seconds,
/// which is inside any window worth stating — the count is the testable half and the report says so.
/// And a clean result is *checked* rather than a pass: it shows the app pushed back at the stated
/// number on one run, not that the control is correct.
fn brute_force_check(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    policy: &sv_manifest::PolicySection,
    out: &mut Outcome,
) {
    let Some(login) = users.login.as_ref() else {
        return;
    };
    let Some(allowed) = policy.failed_sign_ins else {
        out.not_assessed.push((
            "V6.3.1".to_owned(),
            "Whether the app resists password guessing: say how many wrong passwords in a row it \
             should allow, as `failed-sign-ins` under [policy] in securevibe.toml, and this will \
             make one more attempt than that and watch what the app does."
                .to_owned(),
        ));
        return;
    };
    // Zero would mean the first attempt is already too many, which no app can implement and no
    // owner means. Said rather than silently treated as one.
    if allowed == 0 {
        out.not_assessed.push((
            "V6.3.1".to_owned(),
            "[policy] failed-sign-ins is 0, which would mean refusing the first attempt anybody \
             makes. Set it to the number of wrong passwords in a row the app should allow."
                .to_owned(),
        ));
        return;
    }
    // A cap, so a large number cannot turn one check into thousands of requests against somebody's
    // app. Above it the check says what it did rather than pretending to have tested the policy.
    const MOST_ATTEMPTS: u32 = 25;
    if allowed >= MOST_ATTEMPTS {
        out.not_assessed.push((
            "V6.3.1".to_owned(),
            format!(
                "[policy] failed-sign-ins is {allowed}. This check makes at most {MOST_ATTEMPTS} \
                 attempts, so it cannot reach that number; a limit that high is worth reconsidering \
                 on its own."
            ),
        ));
        return;
    }

    // An account whose password this check knows, so a wrong one is certainly wrong: its own,
    // through sign-up, and failing that a name no account can have. The second only exercises a
    // limiter that counts by address; the report says which was used.
    let target = match &users.signup {
        Some(signup) => {
            let account = Account {
                user: format!("guessed.{}", accounts.a.user),
                password: format!(
                    "Gx-{}-1aZ!",
                    accounts.b.password.chars().take(12).collect::<String>()
                ),
            };
            sign_up(http, signup, "guessed", &account);
            account
        }
        None => Account {
            user: format!("nobody.{}", accounts.a.user),
            password: "this-account-does-not-exist".to_owned(),
        },
    };
    let real_account = users.signup.is_some();

    let wrong = Account {
        user: target.user.clone(),
        password: "Wrong-Password-For-This-Probe-1!".to_owned(),
    };
    let attempts = allowed + 1;
    let mut answers: Vec<(u16, u128)> = Vec::new();
    for n in 0..attempts {
        let mut session = Session::default();
        let mut csrf = None;
        if let Some(page) = http.send(&get(&format!("guess-page-{n}"), &login.path, &session)) {
            session.absorb(&page);
            csrf = csrf_token(&page, &session);
        }
        let values = Values {
            user: &wrong.user,
            password: &wrong.password,
            csrf,
            ..Default::default()
        };
        let started = std::time::Instant::now();
        let (response, _) = send_template(
            http,
            &format!("guess-{n}"),
            login,
            &values,
            &mut session,
            &[],
        );
        let elapsed = started.elapsed().as_millis();
        match response {
            Some(r) => answers.push((r.status, elapsed)),
            // No answer at all is the app refusing to talk, which is pushing back.
            None => answers.push((0, elapsed)),
        }
    }

    let Some(&(first_status, first_ms)) = answers.first() else {
        return;
    };
    // The app was already pushing back before this check made its first attempt, so whatever it is
    // refusing, it is not refusing because of the number the owner stated. Found by session
    // securevibe-e9 reviewing this after it merged: the test below is the witness. Reachable
    // exactly where this check is most careful — it runs last *because* it provokes refusals, and
    // by then the suite has made dozens of sign-in attempts from one address, so a limiter counting
    // by address is already tripped. Crediting here would be a false *checked* on no evidence.
    if matches!(first_status, 0 | 423 | 429) {
        out.not_assessed.push((
            "V6.3.1".to_owned(),
            format!(
                "The app was already refusing sign-in attempts ({first_status}) before this check \
                 made its first one, so nothing here can say whether it pushes back at {allowed}. \
                 Something earlier in the run has most likely tripped a limit that counts by \
                 address rather than by account."
            ),
        ));
        return;
    }
    let last = answers.last().copied().unwrap_or((0, 0));
    // Pushing back is any of: a different status on the last attempt than the first, a status that
    // says refused outright, or an attempt that took markedly longer than the first.
    let status_changed = last.0 != first_status;
    let refused = matches!(last.0, 0 | 423 | 429) || (last.0 >= 400 && first_status < 400);
    // No `first_ms >= 1` guard: the `+ 900` floor already covers a zero measurement, and the guard
    // only stopped an app whose first answer came back inside a millisecond — realistic in a local
    // container — from ever being found to have slowed.
    let slowed = last.1 >= first_ms.saturating_mul(4).max(first_ms + 900);
    let pushed_back = status_changed || refused || slowed;

    let how = if refused {
        format!("refused it outright ({})", last.0)
    } else if status_changed {
        format!("answered {} where the first got {first_status}", last.0)
    } else {
        format!("took {}ms against {first_ms}ms for the first", last.1)
    };
    let against = if real_account {
        "an account this check made for it"
    } else {
        "a user name no account has, since securevibe.toml declares no sign-up"
    };

    out.steps.push(format!(
        "made {attempts} wrong sign-in attempts against {against}; the app {}",
        if pushed_back {
            "pushed back"
        } else {
            "did not push back"
        }
    ));

    // V15.3.4, only where the app pushed back with a different answer: a delay is too noisy to
    // tell apart from a delay the next attempt happens to get.
    if refused || status_changed {
        forwarded_check(http, login, &wrong, first_status, out);
    }

    if pushed_back {
        out.verified.push(crate::Verified::new(
            NO_BRUTE_FORCE_LIMIT.rule_id,
            NO_BRUTE_FORCE_LIMIT.requirement_ids,
            format!(
                "{attempts} wrong passwords in a row against {against}, the number you stated plus \
                 one: the app {how}. The count is what was tested; `within-minutes` was not, \
                 because every attempt landed within a few seconds"
            ),
        ));
    } else {
        out.findings.push(finding(
            &NO_BRUTE_FORCE_LIMIT,
            "Wrong passwords can be tried without limit",
            Severity::High,
            format!(
                "securevibe.toml says the app should allow {allowed} wrong passwords in a row. \
                 Asked {attempts} times in a row with a wrong password, against {against}, the app \
                 answered {} every time and the last attempt took {}ms against {first_ms}ms for \
                 the first: nothing about it changed.",
                first_status, last.1
            ),
        ));
    }
}

/// Does three things no other traffic could have done, each carrying a string nothing else
/// contains, so the container's log can be read for them afterwards (V16.3.1, V16.3.2).
///
/// None of this asserts anything on its own: `logs::evaluate` reads what the app wrote. The point
/// of planting rather than searching for ordinary words is that "the log mentions `admin`" says
/// nothing at all — every log mentions `admin`.
fn plant_log_markers(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    signed_in_works: bool,
    out: &mut Outcome,
) {
    // A unique run-scoped tag, taken from the account names the run already made unique.
    let tag: String = accounts
        .a
        .user
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(16)
        .collect();

    // 1. A sign-in for an account that does not exist. Its name can only reach the log because a
    //    failed authentication was written down.
    if let Some(login) = &users.login {
        let nobody = Account {
            user: format!("sv-log-nobody-{tag}@example.test"),
            password: "Sv-Log-Marker-Not-A-Real-Password-1!".to_owned(),
        };
        let mut session = Session::default();
        let mut csrf = None;
        if let Some(page) = http.send(&get("log-marker-page", &login.path, &session)) {
            session.absorb(&page);
            csrf = csrf_token(&page, &session);
        }
        let values = Values {
            user: &nobody.user,
            password: &nobody.password,
            csrf,
            ..Default::default()
        };
        send_template(http, "log-marker-failed", login, &values, &mut session, &[]);
        out.log_markers.failed_sign_in = Some(nobody.user);
    }

    // 2. A sign-in that works, by an account used for nothing else. Needs `signup`: A and B sign in
    //    and fail elsewhere in the run, so neither of their names could tell the two apart.
    if let Some(signup) = &users.signup {
        let only = Account {
            user: format!("sv-log-ok-{tag}@example.test"),
            password: format!("Sv-Log-{tag}-aZ9!"),
        };
        sign_up(http, signup, "log-marker", &only);
        if sign_in(http, users, "log-marker-ok", &only, &mut Vec::new()).is_some() {
            out.log_markers.successful_sign_in = Some(only.user);
        }
    }

    // 3. A private page asked for by nobody, with a marker in the address, which the app should
    //    refuse. Only planted once the page is known to be private at all.
    if signed_in_works && let Some(path) = users.private.first() {
        let marker = format!("sv-log-refused-{tag}");
        let joiner = if path.contains('?') { '&' } else { '?' };
        let asked = format!("{path}{joiner}{marker}=1");
        let response = http.send(&get("log-marker-refused", &asked, &Session::default()));
        // Only a marker the app actually refused is evidence about a refusal being recorded, and
        // the status it refused with travels with it: a redirect to the sign-in page is a refusal
        // too, and no fixed list of "refused" codes would have contained it.
        if let Some(status) = response.map(|r| r.status).filter(|s| *s >= 300) {
            out.log_markers.refused_request = Some((marker, status));
        }
    }
}

/// Signs an account up through the app's own form.
fn sign_up(
    http: &mut dyn Http,
    signup: &RequestTemplate,
    who: &str,
    account: &Account,
) -> Option<ProbeResponse> {
    let values = Values {
        user: &account.user,
        password: &account.password,
        ..Default::default()
    };
    let mut session = Session::default();
    send_template(
        http,
        &format!("signup-{who}"),
        signup,
        &values,
        &mut session,
        &[],
    )
    .0
}

/// Whether this account can sign in and open the private page: the only test of a password that
/// does not depend on how the app words its refusals.
fn account_works(
    http: &mut dyn Http,
    users: &UsersSection,
    who: &str,
    account: &Account,
    confirm: &str,
    steps: &mut Vec<String>,
) -> bool {
    let mut quiet = Vec::new();
    let Some(signed_in) = sign_in(http, users, who, account, &mut quiet) else {
        return false;
    };
    let works = ok(&http.send(&get(&format!("private-{who}"), confirm, &signed_in.session)));
    steps.push(format!(
        "signed in as {} with {}: {}",
        account.user,
        describe_password(&account.password),
        if works { "opened" } else { "refused" }
    ));
    works
}

fn describe_password(p: &str) -> String {
    if p == COMMON {
        return format!("the common password `{COMMON}`");
    }
    let kinds = [
        (p.chars().any(|c| c.is_ascii_lowercase()), "lowercase"),
        (p.chars().any(|c| c.is_ascii_uppercase()), "uppercase"),
        (p.chars().any(|c| c.is_ascii_digit()), "digits"),
        (p.chars().any(|c| !c.is_ascii_alphanumeric()), "symbols"),
    ];
    let kinds: Vec<&str> = kinds.iter().filter(|(k, _)| *k).map(|(_, n)| *n).collect();
    format!("a {}-character password of {}", p.len(), kinds.join(", "))
}

/// The password rules, asked through the app's own sign-up and answered by signing in.
///
/// A control goes first: an account signed up with an ordinary strong password, 32 characters of
/// every kind, which has to be able to sign in or nothing here can be told. Each password after it
/// differs from the control in one thing only, so a refusal is about that thing: seven characters;
/// lowercase letters alone; a common password, beside a random one of the same length and kinds of
/// character. The test users may have been made by `seed`; these never are.
fn password_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    policy: &sv_manifest::PolicySection,
    out: &mut Outcome,
) {
    const IDS: &str = "V6.2.1, V6.2.4, V6.2.5, V6.2.8, V6.2.9, V6.2.11, V6.2.12";
    let Some(signup) = &users.signup else {
        out.not_assessed.push((
            IDS.to_owned(),
            "The password rules are asked through the app's own sign-up, and securevibe.toml sets \
             no `signup` under [stack.run.users]."
                .to_owned(),
        ));
        return;
    };
    let Some(confirm) = confirm else {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether a password was accepted is told by signing in with it and opening a private \
             page, and no private page was shown to open for a signed-in user alone."
                .to_owned(),
        ));
        return;
    };
    let spare = &accounts.spare;
    if spare.len() < 32 || !spare.chars().all(|c| c.is_ascii_hexdigit()) {
        out.not_assessed.push((
            IDS.to_owned(),
            "There was no random material to make test passwords from.".to_owned(),
        ));
        return;
    }
    let account = |label: &str, password: String| Account {
        user: format!("{label}.{}", accounts.a.user),
        password,
    };
    let lowercase: String = spare
        .chars()
        .map(|c| (b'g' + c.to_digit(16).unwrap_or(0) as u8) as char)
        .collect();
    let control = account("control", format!("Sv-{}-aZ9!", &spare[8..32]));
    sign_up(http, signup, "control", &control);
    if !account_works(http, users, "control", &control, confirm, &mut out.steps) {
        out.not_assessed.push((
            IDS.to_owned(),
            "An account signed up with an ordinary strong password could not then sign in, so \
             nothing can be told from the passwords the app refuses."
                .to_owned(),
        ));
        return;
    }
    let tries = [
        ("short", account("short", format!("S{}aZ9!", &spare[..2]))),
        ("lower", account("lower", lowercase)),
        ("common", account("common", COMMON.to_owned())),
        (
            "like-common",
            account("like-common", spare[2..14].to_owned()),
        ),
        ("breached", account("breached", BREACHED.to_owned())),
        (
            "like-breached",
            account("like-breached", random_like(BREACHED, &spare[14..32])),
        ),
    ];
    let context = context_password(&policy.context_words);
    let context_tries: Vec<(&str, Account)> = match &context {
        Some((_, password)) => vec![
            ("context", account("context", password.clone())),
            (
                "like-context",
                account("like-context", random_like(password, &spare[4..28])),
            ),
        ],
        None => Vec::new(),
    };
    let tries: Vec<(&str, Account)> = tries.into_iter().chain(context_tries).collect();
    let mut works = std::collections::BTreeMap::new();
    for (label, try_account) in &tries {
        sign_up(http, signup, label, try_account);
        works.insert(
            *label,
            account_works(http, users, label, try_account, confirm, &mut out.steps),
        );
    }

    if works["short"] {
        out.findings.push(finding(
            &SHORT_PASSWORD,
            "A password shorter than 8 characters is accepted",
            Severity::Medium,
            format!(
                "The app let an account sign up with the 7-character password `{}` and sign in \
                 with it.",
                tries[0].1.password
            ),
        ));
    } else {
        out.verified.push(crate::Verified::new(
            SHORT_PASSWORD.rule_id,
            SHORT_PASSWORD.requirement_ids,
            "a 7-character password at sign-up, refused where a 32-character one of the same kinds \
             of character was accepted"
                .to_owned(),
        ));
    }

    if works["lower"] {
        out.verified.push(crate::Verified::new(
            COMPOSITION_RULES.rule_id,
            COMPOSITION_RULES.requirement_ids,
            "a 32-character password of lowercase letters alone, accepted at sign-up".to_owned(),
        ));
    } else {
        out.findings.push(finding(
            &COMPOSITION_RULES,
            "Passwords must contain certain kinds of character",
            Severity::Low,
            "The app refused a 32-character password of lowercase letters alone, where it \
             accepted one of the same length with capitals, digits and symbols."
                .to_owned(),
        ));
    }

    match (works["common"], works["like-common"]) {
        (true, _) => out.findings.push(finding(
            &COMMON_PASSWORD,
            "A common password is accepted",
            Severity::Medium,
            format!(
                "The app let an account sign up with `{COMMON}`, which is among the 3000 most \
                 common passwords, and sign in with it."
            ),
        )),
        (false, true) => out.verified.push(crate::Verified::new(
            COMMON_PASSWORD.rule_id,
            COMMON_PASSWORD.requirement_ids,
            format!(
                "`{COMMON}` at sign-up, refused where a random password of the same length and \
                 kinds of character was accepted"
            ),
        )),
        (false, false) => out.not_assessed.push((
            "V6.2.4".to_owned(),
            format!(
                "The app refused `{COMMON}`, and also a random password of the same length and \
                 kinds of character, so the refusal cannot be told apart from another rule."
            ),
        )),
    }

    // V6.2.12, in the same shape as V6.2.4: refused beside a random password of the same shape
    // that was accepted is evidence; refused beside a refused control is evidence of nothing.
    match (works["breached"], works["like-breached"]) {
        (true, _) => out.findings.push(finding(
            &BREACHED_PASSWORD,
            "A password known from data breaches is accepted",
            Severity::Low,
            format!(
                "The app let an account sign up with `{BREACHED}`, and sign in with it. Have I Been \
                 Pwned has seen that password in breaches {BREACHED_SEEN}, though it is not among \
                 the 3000 most common, so a check against a large set of breached passwords would \
                 have refused it."
            ),
        )),
        (false, true) => out.verified.push(crate::Verified::new(
            BREACHED_PASSWORD.rule_id,
            BREACHED_PASSWORD.requirement_ids,
            format!(
                "`{BREACHED}`, seen in breaches {BREACHED_SEEN} and not among the 3000 most \
                 common, refused at sign-up where a random password of the same shape was accepted"
            ),
        )),
        (false, false) => out.not_assessed.push((
            "V6.2.12".to_owned(),
            format!(
                "The app refused `{BREACHED}`, and also a random password of the same length and \
                 kinds of character, so the refusal cannot be told apart from another rule."
            ),
        )),
    }

    // V6.2.11 asks that the *documented* list is used, so without the owner's list there is
    // nothing to hold the app to, and guessing at words would be testing a list nobody wrote.
    match &context {
        None => out.not_assessed.push((
            "V6.2.11".to_owned(),
            if policy.context_words.is_empty() {
                "securevibe.toml lists no context-specific words. Add your app's and your \
                 organization's names under [policy] as `context-words`, and sign-up is asked to \
                 refuse a password made from one."
                    .to_owned()
            } else {
                "No word under `context-words` in securevibe.toml has between 4 and 32 letters or \
                 digits, so none could be made into a password worth trying."
                    .to_owned()
            },
        )),
        Some((word, password)) => match (works["context"], works["like-context"]) {
            (true, _) => out.findings.push(finding(
                &CONTEXT_WORD_PASSWORD,
                "A password made from one of your context-specific words is accepted",
                Severity::Low,
                format!(
                    "The app let an account sign up with `{password}`, which is \"{word}\" from \
                     `context-words` in securevibe.toml, repeated, and sign in with it."
                ),
            )),
            (false, true) => out.verified.push(crate::Verified::new(
                CONTEXT_WORD_PASSWORD.rule_id,
                CONTEXT_WORD_PASSWORD.requirement_ids,
                format!(
                    "a password made from \"{word}\", the first usable word in `context-words`, \
                     refused at sign-up where a random password of the same shape was accepted"
                ),
            )),
            (false, false) => out.not_assessed.push((
                "V6.2.11".to_owned(),
                format!(
                    "The app refused a password made from \"{word}\", and also a random password \
                     of the same length and kinds of character, so the refusal cannot be told \
                     apart from another rule."
                ),
            )),
        },
    }

    exact_password_checks(http, users, signup, &control, spare, confirm, out);
}

/// Whether the password is checked exactly as typed (V6.2.8), and whether a long one is allowed at
/// all (V6.2.9).
///
/// Two ways an app alters a password before comparing it, each asked against an account that is
/// shown to work with its real password first. Its capitals swapped, on the control account: an app
/// that lowercases passwords lets it in. And an 83-character password cut to its first 72: an app
/// that hashes with bcrypt, which stops reading at 72 bytes, lets that in too. Signing that account
/// up at all is the V6.2.9 question.
fn exact_password_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    signup: &RequestTemplate,
    control: &Account,
    spare: &str,
    confirm: &str,
    out: &mut Outcome,
) {
    let swapped = Account {
        user: control.user.clone(),
        password: control
            .password
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase() {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect(),
    };
    let case_works = account_works(http, users, "case", &swapped, confirm, &mut out.steps);

    let long = Account {
        user: format!("long.{}", control.user.trim_start_matches("control.")),
        password: format!("Lg-{0}{0}{1}-aZ9!", &spare[..32], &spare[..11]),
    };
    sign_up(http, signup, "long", &long);
    let long_works = account_works(http, users, "long", &long, confirm, &mut out.steps);
    let cut = Account {
        user: long.user.clone(),
        password: long.password.chars().take(72).collect(),
    };
    let cut_works = long_works && account_works(http, users, "cut", &cut, confirm, &mut out.steps);

    if long_works {
        out.verified.push(crate::Verified::new(
            LONG_PASSWORD.rule_id,
            LONG_PASSWORD.requirement_ids,
            format!(
                "a {}-character password, accepted at sign-up and signed in with",
                long.password.len()
            ),
        ));
    } else {
        out.findings.push(finding(
            &LONG_PASSWORD,
            "A long password is refused",
            Severity::Low,
            format!(
                "The app did not let an account sign up with a {}-character password and sign in \
                 with it, where it accepted one of 32 characters of the same kinds.",
                long.password.len()
            ),
        ));
    }

    let mut altered = Vec::new();
    if case_works {
        altered.push("with the capitals in the password swapped".to_owned());
    }
    if cut_works {
        altered.push(format!(
            "with only the first 72 of its {} characters",
            long.password.len()
        ));
    }
    if !altered.is_empty() {
        out.findings.push(finding(
            &ALTERED_PASSWORD,
            "The password is not checked exactly as typed",
            Severity::Medium,
            format!("Signing in worked {}.", altered.join(", and ")),
        ));
    } else if long_works {
        out.verified.push(crate::Verified::new(
            ALTERED_PASSWORD.rule_id,
            ALTERED_PASSWORD.requirement_ids,
            format!(
                "the password with its capitals swapped, and an {}-character one cut to 72, both \
                 refused where the exact passwords signed in",
                long.password.len()
            ),
        ));
    } else {
        out.not_assessed.push((
            "V6.2.8".to_owned(),
            "Whether a password is cut short before it is checked: the app would not take a long \
             password to begin with. A password with its capitals swapped was refused."
                .to_owned(),
        ));
    }
}

/// The password field on the sign-in and sign-up pages: masked (V6.2.6), and not refusing a paste
/// (V6.2.7).
///
/// Read from the page's HTML, which is what a browser is given. The field is the one securevibe.toml
/// sends `{password}` in, so what is looked at is the field the app reads, not any input that
/// happens to say "password". A page that builds its form with script has no such field in its HTML,
/// and says so rather than passing. Pasting blocked by a script attached after the page loads cannot
/// be seen here, so V6.2.7 is only ever a finding.
fn password_field_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    signed_in: Option<&Session>,
    out: &mut Outcome,
) {
    let anonymous = Session::default();
    // The password-change page is asked for as a signed-in user, since it is only shown to one.
    let forms: Vec<(&str, &RequestTemplate, &Session)> = [
        ("sign-in", &users.login, &anonymous),
        ("sign-up", &users.signup, &anonymous),
        (
            "password-change",
            &users.change_password,
            signed_in.unwrap_or(&anonymous),
        ),
    ]
    .into_iter()
    .filter_map(|(label, t, session)| t.as_ref().map(|t| (label, t, session)))
    .collect();
    let mut masked = Vec::new();
    let mut unmasked = Vec::new();
    let mut pasting = Vec::new();
    let mut missing = Vec::new();
    let mut hints = Vec::new();
    for (label, template, session) in forms {
        // Every field a password is sent in: the one of a sign-in, both of a password change.
        let fields: Vec<&String> = template
            .form
            .iter()
            .filter(|(_, v)| v.contains("{password}") || v.contains("{new_password}"))
            .map(|(k, _)| k)
            .collect();
        if fields.is_empty() {
            continue;
        }
        let page = http.send(&get(
            &format!("password-field-{label}"),
            &template.path,
            session,
        ));
        if let Some(what) = page
            .as_ref()
            .filter(|p| p.status == 200)
            .and_then(|p| password_hint(&p.body))
        {
            hints.push(format!("the {label} page {} ({what})", template.path));
        }
        let inputs: Vec<String> = page
            .as_ref()
            .filter(|p| p.status == 200)
            .map(|p| tags(&p.body, "input"))
            .unwrap_or_default()
            .into_iter()
            .filter(|tag| {
                attribute(tag, "name").is_some_and(|name| fields.iter().any(|f| **f == name))
            })
            .collect();
        if inputs.is_empty() {
            missing.push(format!("{} ({})", template.path, status(&page)));
            continue;
        }
        let where_ = format!("the {label} page {}", template.path);
        if inputs
            .iter()
            .all(|tag| attribute(tag, "type").is_some_and(|t| t.eq_ignore_ascii_case("password")))
        {
            masked.push(where_.clone());
        } else {
            unmasked.push(where_.clone());
        }
        if inputs.iter().any(|tag| attribute(tag, "onpaste").is_some()) {
            pasting.push(where_);
        }
    }
    if !unmasked.is_empty() {
        out.findings.push(finding(
            &UNMASKED_PASSWORD,
            "A password field shows what is typed",
            Severity::Medium,
            format!(
                "The password field on {} is not `type=\"password\"`.",
                unmasked.join(" and on ")
            ),
        ));
    } else if !masked.is_empty() {
        out.verified.push(crate::Verified::new(
            UNMASKED_PASSWORD.rule_id,
            UNMASKED_PASSWORD.requirement_ids,
            format!(
                "the password field securevibe.toml names, on {}, served as type=password",
                masked.join(" and ")
            ),
        ));
    }
    if !hints.is_empty() {
        out.findings.push(finding(
            &PASSWORD_HINTS,
            "A password hint or secret question is offered",
            Severity::Medium,
            format!("Found on {}.", hints.join(" and on ")),
        ));
    }
    if !pasting.is_empty() {
        out.findings.push(finding(
            &PASTE_BLOCKED,
            "Pasting into a password field is blocked",
            Severity::Low,
            format!(
                "The password field on {} has an `onpaste` handler.",
                pasting.join(" and on ")
            ),
        ));
    }
    if masked.is_empty() && unmasked.is_empty() {
        out.not_assessed.push((
            "V6.2.6".to_owned(),
            if missing.is_empty() {
                "Whether password fields are masked: securevibe.toml names no form with a \
                 `{password}` field."
                    .to_owned()
            } else {
                format!(
                    "Whether password fields are masked: the field securevibe.toml names was not in \
                     the HTML of {}. A page that builds its form with script cannot be read here.",
                    missing.join(" or ")
                )
            },
        ));
    }
}

/// Whether a password can be changed (V6.2.2), and whether changing it needs the current one
/// (V6.2.3), through `change-password`.
///
/// The wrong current password first, then the right one, each told by signing in afterwards. If the
/// change with a wrong current password takes, that is the finding, and it has also shown a
/// password can be changed. If it does not, the same change with the right current password has to
/// take, the new password signing in and the old one no longer, or the refusal before it cannot be
/// told apart from a change that never works.
fn change_password_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    const IDS: &str = "V6.2.2, V6.2.3";
    let Some(change) = &users.change_password else {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether a password can be changed, and whether that needs the current one: \
             securevibe.toml sets no `change-password` under [stack.run.users]."
                .to_owned(),
        ));
        return;
    };
    let Some(confirm) = confirm else {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether a password can be changed: telling needs a private page a signed-in user alone \
             can open, and none was shown."
                .to_owned(),
        ));
        return;
    };
    let spare = &accounts.spare;
    if spare.len() < 32 {
        return;
    }
    let account = match &users.signup {
        Some(signup) => {
            let account = Account {
                user: format!("change.{}", accounts.a.user),
                password: format!("Ch-{}-aZ9!", &spare[4..28]),
            };
            sign_up(http, signup, "change", &account);
            account
        }
        None => accounts.a.clone(),
    };
    if !account_works(http, users, "change", &account, confirm, &mut out.steps) {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "Whether a password can be changed: the account made for it, {}, could not sign in \
                 to begin with.",
                account.user
            ),
        ));
        return;
    }
    let wrong = format!("Wr-{}-aZ9!", &spare[6..30]);
    let first = format!("N1-{}-aZ9!", &spare[8..32]);
    let second = format!("N2-{}-aZ9!", &spare[2..26]);

    let changed = |http: &mut dyn Http, current: &str, new: &str, label: &str| {
        let mut quiet = Vec::new();
        let signed_in = sign_in(http, users, label, &account, &mut quiet)?;
        let mut session = signed_in.session;
        let values = Values {
            user: &account.user,
            password: current,
            new_password: new,
            ..Default::default()
        };
        // As for deletion: the form may be on the account page rather than at the address it posts
        // to.
        let pages: Vec<String> = users.private.clone();
        send_template(
            http,
            &format!("change-password-{label}"),
            change,
            &values,
            &mut session,
            &pages,
        )
        .0
    };
    let as_with = |password: &str| Account {
        user: account.user.clone(),
        password: password.to_owned(),
    };

    let answer = changed(http, &wrong, &first, "wrong-current");
    out.steps.push(format!(
        "asked to change the password giving a wrong current one ({})",
        status(&answer)
    ));
    if account_works(
        http,
        users,
        "changed",
        &as_with(&first),
        confirm,
        &mut out.steps,
    ) {
        out.findings.push(finding(
            &CHANGE_WITHOUT_CURRENT,
            "The password can be changed without the current one",
            Severity::High,
            format!(
                "A request to {} giving a wrong current password changed it: the new password then \
                 signed in.",
                change.path
            ),
        ));
        out.verified.push(crate::Verified::new(
            CHANGE_PASSWORD.rule_id,
            CHANGE_PASSWORD.requirement_ids,
            format!(
                "a password change through {}, after which the new password signed in",
                change.path
            ),
        ));
        return;
    }

    let answer = changed(http, &account.password, &second, "right-current");
    out.steps.push(format!(
        "asked to change the password giving the right current one ({})",
        status(&answer)
    ));
    let new_works = account_works(
        http,
        users,
        "changed",
        &as_with(&second),
        confirm,
        &mut out.steps,
    );
    if !new_works {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "A change of password through {} with the right current password did not take: \
                 the new password did not sign in. Check `change-password` in securevibe.toml. With \
                 no change that works, a refused one shows nothing.",
                change.path
            ),
        ));
        return;
    }
    let old_works = account_works(http, users, "old", &account, confirm, &mut out.steps);
    if old_works {
        out.findings.push(finding(
            &CHANGE_PASSWORD,
            "The old password still works after a change",
            Severity::High,
            format!(
                "After changing the password through {}, both the new password and the old one \
                 signed in.",
                change.path
            ),
        ));
    } else {
        out.verified.push(crate::Verified::new(
            CHANGE_PASSWORD.rule_id,
            CHANGE_PASSWORD.requirement_ids,
            format!(
                "a password change through {}, after which the new password signed in and the old \
                 one was refused",
                change.path
            ),
        ));
    }
    out.verified.push(crate::Verified::new(
        CHANGE_WITHOUT_CURRENT.rule_id,
        CHANGE_WITHOUT_CURRENT.requirement_ids,
        format!(
            "a change through {} giving a wrong current password, refused where the same change \
             with the right one took",
            change.path
        ),
    ));
}

/// A forgotten-password reset, followed through the email it sends (V6.4.3, V6.3.8).
///
/// The run gives the app a mail server that keeps what it is sent, and this reads it as the
/// account's owner would. The setup is shown to work before anything is judged: the email has to
/// arrive, a code has to be found in it, and using that code has to set a password that then signs
/// in. Only then is the same code tried again, the old password tried, and the code's length read.
///
/// Only ever findings. V6.4.3 also asks that a reset does not get round two-factor sign-in, and a
/// safe reset expires; neither is tried here, so a clean run credits nothing and says so.
fn reset_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    const IDS: &str = "V6.4.3, V6.3.8";
    let Some(reset) = &users.reset else {
        out.not_assessed.push((
            IDS.to_owned(),
            "How a forgotten password is reset: securevibe.toml sets no `reset` under \
             [stack.run.users]."
                .to_owned(),
        ));
        return;
    };
    let patterns = match code_patterns(reset.code_pattern.as_deref(), "reset") {
        Ok(p) => p,
        Err(e) => {
            out.not_assessed.push((
                IDS.to_owned(),
                format!("`reset.code-pattern` in securevibe.toml cannot be used: {e}."),
            ));
            return;
        }
    };
    let Some(confirm) = confirm else {
        out.not_assessed.push((
            IDS.to_owned(),
            "How a forgotten password is reset: telling whether a reset worked needs a private page \
             a signed-in user alone can open, and none was shown."
                .to_owned(),
        ));
        return;
    };
    let spare = &accounts.spare;
    if spare.len() < 32 {
        return;
    }
    // Never A, whose password the checks before this rely on. B when there is no sign-up: nothing
    // after this signs B in.
    let account = match &users.signup {
        Some(signup) => {
            let account = Account {
                user: format!("reset.{}", accounts.a.user),
                password: format!("Re-{}-aZ9!", &spare[5..29]),
            };
            sign_up(http, signup, "reset", &account);
            account
        }
        None => accounts.b.clone(),
    };
    let Some(before) = http.mail(&account.user, 0) else {
        out.not_assessed.push((
            IDS.to_owned(),
            "How a forgotten password is reset: the run had no mail server for the app to send to, \
             so there was no email to follow."
                .to_owned(),
        ));
        return;
    };
    if !account_works(http, users, "reset", &account, confirm, &mut out.steps) {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "How a forgotten password is reset: the account used for it, {}, could not sign in \
                 to begin with.",
                account.user
            ),
        ));
        return;
    }

    // Two requests for the account and one for an address nobody has: the pair shows what varies
    // between two identical requests, so that only a difference beyond it is held against the app.
    let ask = |http: &mut dyn Http, user: &str, label: &str| {
        let values = Values {
            user,
            ..Default::default()
        };
        let mut session = Session::default();
        send_template(
            http,
            &format!("reset-request-{label}"),
            &reset.request,
            &values,
            &mut session,
            &[],
        )
        .0
    };
    let first = ask(http, &account.user, "1");
    let second = ask(http, &account.user, "2");
    let nobody = format!("nobody-{}@example.test", &spare[..12]);
    let stranger = ask(http, &nobody, "nobody");
    out.steps.push(format!(
        "asked for a password reset for {} twice ({}, {}) and for an address with no account ({})",
        account.user,
        status(&first),
        status(&second),
        status(&stranger)
    ));
    reveals_account_check(
        [&first, &second, &stranger],
        &account.user,
        &nobody,
        &reset.request.path,
        out,
    );

    let mail = http
        .mail(&account.user, before.len() + 2)
        .unwrap_or_default();
    let arrived: Vec<&String> = mail.iter().skip(before.len()).collect();
    out.steps.push(format!(
        "{} email{} arrived for {}",
        arrived.len(),
        if arrived.len() == 1 { "" } else { "s" },
        account.user
    ));
    if arrived.is_empty() {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "Asked for a password reset, the app sent no email to {} at the run's mail server. \
                 The app is told where that is in SMTP_HOST and SMTP_PORT; check that it reads them, \
                 and check `reset.request` in securevibe.toml.",
                account.user
            ),
        ));
        return;
    }
    let codes: Vec<String> = arrived
        .iter()
        .filter_map(|m| reset_code(m, &patterns))
        .collect();
    // The newest: an app that cancels an earlier code when a new one is asked for is right to.
    let Some(code) = codes.last().cloned() else {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "The reset email arrived and no code was found in it{}. Set `reset.code-pattern` in \
                 securevibe.toml to a pattern whose first group is the code.",
                if reset.code_pattern.is_some() {
                    " with `reset.code-pattern`"
                } else {
                    " as a link's `token`, `code`, or `key`"
                }
            ),
        ));
        return;
    };
    reset_code_check(&codes, out);

    let set = |http: &mut dyn Http, new: &str, label: &str| {
        let values = Values {
            user: &account.user,
            code: &code,
            new_password: new,
            ..Default::default()
        };
        let mut session = Session::default();
        send_template(
            http,
            &format!("reset-use-{label}"),
            &reset.use_code,
            &values,
            &mut session,
            &[],
        )
        .0
    };
    let with = |password: &str| Account {
        user: account.user.clone(),
        password: password.to_owned(),
    };
    let first_new = format!("R1-{}-aZ9!", &spare[7..31]);
    let second_new = format!("R2-{}-aZ9!", &spare[1..25]);

    let answer = set(http, &first_new, "1");
    out.steps.push(format!(
        "used the code from the email to set a new password ({})",
        status(&answer)
    ));
    let reset_worked = account_works(
        http,
        users,
        "reset-new",
        &with(&first_new),
        confirm,
        &mut out.steps,
    );
    out.steps.push(format!(
        "the password the reset set {}",
        if reset_worked {
            "signed in"
        } else {
            "did not sign in"
        }
    ));
    if !reset_worked {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "Using the code from the reset email through {} did not change the password: the \
                 new password did not sign in. Check `reset.use` and `reset.code-pattern` in \
                 securevibe.toml. With no reset that works, a refused one shows nothing.",
                reset.use_code.path
            ),
        ));
        return;
    }
    let old_works = account_works(http, users, "reset-old", &account, confirm, &mut out.steps);
    out.steps.push(format!(
        "the password from before the reset {}",
        if old_works {
            "still signed in"
        } else {
            "was refused"
        }
    ));
    if old_works {
        out.findings.push(finding(
            &RESET_KEEPS_OLD,
            "The old password still works after a reset",
            Severity::High,
            format!(
                "After a reset through {}, both the new password and the old one signed in.",
                reset.use_code.path
            ),
        ));
    }
    let again = set(http, &second_new, "2");
    out.steps.push(format!(
        "used the same code from the email a second time ({})",
        status(&again)
    ));
    let reused = account_works(
        http,
        users,
        "reset-again",
        &with(&second_new),
        confirm,
        &mut out.steps,
    );
    out.steps.push(format!(
        "the password the used code tried to set {}",
        if reused { "signed in" } else { "was refused" }
    ));
    if reused {
        out.findings.push(finding(
            &RESET_REUSABLE,
            "A password reset link works more than once",
            Severity::High,
            format!(
                "The code from one reset email set the password twice through {}: after it had \
                 been used, it set another new password, which then signed in.",
                reset.use_code.path
            ),
        ));
    }
    out.not_assessed.push((
        "V6.4.3".to_owned(),
        "Two parts of a safe password reset were not tried: whether a reset code stops working \
         after a while, which would mean waiting, and whether a reset gets round two-factor \
         sign-in, which needs an account that has it."
            .to_owned(),
    ));
}

/// Signing in with a code the app emails, followed through the mail server (V6.5.1, V6.5.4,
/// V6.6.2). V6.6.3, guessing, is `email_code_guessing`, which runs last of all.
///
/// Every code is asked for and used in a session of its own, as a browser would, since a code tied
/// to the session that asked for it is exactly what V6.6.2 wants. The setup is shown to work first:
/// a code used where it was asked for signs in, which the private page confirms.
fn email_code_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    const IDS: &str = "V6.5.1, V6.5.4, V6.6.2, V6.6.3";
    let Some(flow) = EmailCode::start(http, users, accounts, confirm, IDS, out) else {
        return;
    };

    // 1. A code, used where it was asked for: the setup proof.
    let mut first = Session::default();
    let code = match flow.ask(http, &mut first, "1", out) {
        Ok(code) => code,
        Err(why) => {
            out.not_assessed.push((IDS.to_owned(), why));
            return;
        }
    };
    if !flow.signs_in(http, &code, &mut first, "1", out) {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "Using the emailed code through {} in the session that asked for it did not open \
                 {}: check `email-code` in securevibe.toml. With no code that works, a refused one \
                 shows nothing.",
                flow.entry.use_code.path, flow.confirm
            ),
        ));
        return;
    }
    let mut codes = vec![code.clone()];

    // 2. Two sessions each ask for a code; the first session's code is used in the second
    //    (V6.6.2). Then the second session's own code, so a refusal is known to be about the code.
    //    Before the second use of a code, because what a refused second use means depends on it.
    let mut asked_one = Session::default();
    let mut asked_two = Session::default();
    let (one, two) = match (
        flow.ask(http, &mut asked_one, "2", out),
        flow.ask(http, &mut asked_two, "3", out),
    ) {
        (Ok(one), Ok(two)) => (one, two),
        (Err(why), _) | (_, Err(why)) => {
            email_code_short_check(&codes, out);
            out.not_assessed.push(("V6.6.2, V6.5.1".to_owned(), why));
            return;
        }
    };
    codes.extend([one.clone(), two.clone()]);
    email_code_short_check(&codes, out);
    let crossed = flow.signs_in(http, &one, &mut asked_two, "crossed", out);
    let bound = if crossed {
        out.findings.push(finding(
            &EMAIL_CODE_UNBOUND,
            "An emailed sign-in code works for a sign-in it was not sent for",
            Severity::Medium,
            format!(
                "Two sign-ins were started in separate sessions. The code sent for the first, used \
                 through {} in the second, signed the second one in.",
                flow.entry.use_code.path
            ),
        ));
        Some(false)
    } else if flow.signs_in(http, &two, &mut asked_two, "own", out) {
        out.verified.push(crate::Verified::new(
            EMAIL_CODE_UNBOUND.rule_id,
            EMAIL_CODE_UNBOUND.requirement_ids,
            format!(
                "a code sent for one sign-in, refused through {} in another session, where that \
                 session's own code then signed in",
                flow.entry.use_code.path
            ),
        ));
        Some(true)
    } else {
        out.not_assessed.push((
            "V6.6.2".to_owned(),
            "A code used in a session that did not ask for it was refused, and so was that \
             session's own code afterwards, so the refusal cannot be said to be about the code."
                .to_owned(),
        ));
        None
    };

    // 3. The first code again, already used, from a new session (V6.5.1). Signing in is a finding
    //    whatever else is true. A refusal is credited only where codes were shown to work outside
    //    the session that asked: a code tied to its session would be refused in a new one used or
    //    not, and the session it belonged to is the one its first use signed in.
    let mut again = Session::default();
    if flow.signs_in(http, &code, &mut again, "again", out) {
        out.findings.push(finding(
            &EMAIL_CODE_REUSABLE,
            "An emailed sign-in code works more than once",
            Severity::High,
            format!(
                "The code from one sign-in email signed in twice through {}: once where it was \
                 asked for, and again in a new session after it had been used.",
                flow.entry.use_code.path
            ),
        ));
    } else if bound == Some(false) {
        out.verified.push(crate::Verified::new(
            EMAIL_CODE_REUSABLE.rule_id,
            EMAIL_CODE_REUSABLE.requirement_ids,
            format!(
                "an emailed sign-in code through {}, which signed in once and was refused the \
                 second time, where an unused code worked from any session",
                flow.entry.use_code.path
            ),
        ));
    } else {
        out.not_assessed.push((
            "V6.5.1".to_owned(),
            "Whether an emailed code works twice: a used code was refused in a new session, but \
             codes here are tied to the session that asked for them, so it would have been \
             refused there unused too, and the session it belonged to is already signed in."
                .to_owned(),
        ));
    }
}

/// Wrong emailed codes, one more than the owner says the app allows, then the right one (V6.6.3).
///
/// Run after everything else, the password guessing included, for the same reason: it sets out to
/// make the app refuse requests. The app is held to pushing back in any way — refusing the right
/// code afterwards, or answering the wrong ones differently or slowly — as the password check does.
fn email_code_guessing(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    policy: &sv_manifest::PolicySection,
    out: &mut Outcome,
) {
    const MOST_ATTEMPTS: u32 = 25;
    if users.email_code.is_none() {
        return;
    }
    let Some(allowed) = policy
        .failed_codes
        .filter(|n| (1..MOST_ATTEMPTS).contains(n))
    else {
        out.not_assessed.push((
            "V6.6.3".to_owned(),
            match policy.failed_codes {
                None => {
                    "Whether emailed sign-in codes can be guessed: say how many wrong codes in \
                         a row the app should allow, as `failed-codes` under [policy] in \
                         securevibe.toml, and this will make one more attempt than that."
                        .to_owned()
                }
                Some(n) => format!(
                    "[policy] failed-codes is {n}; this check makes between 2 and {MOST_ATTEMPTS} \
                     attempts, so it cannot hold the app to that number."
                ),
            },
        ));
        return;
    };
    // Quietly: the checks above already said why, if the flow cannot be started.
    let mut quiet = Outcome::default();
    let Some(flow) = EmailCode::start(http, users, accounts, confirm, "V6.6.3", &mut quiet) else {
        out.not_assessed.push((
            "V6.6.3".to_owned(),
            "Whether emailed sign-in codes can be guessed: the sign-in by emailed code could not \
             be started, as said above."
                .to_owned(),
        ));
        return;
    };
    // First, that a code works at all here, in a session of its own. Otherwise the right code
    // refused after the guesses — the strongest sign of pushing back — would be credited for an
    // app whose codes never sign anybody in. Found by the seeded fixture's witness.
    let mut proof = Session::default();
    let works = match flow.ask(http, &mut proof, "guess-proof", out) {
        Ok(code) => flow.signs_in(http, &code, &mut proof, "guess-proof", out),
        Err(_) => false,
    };
    if !works {
        out.not_assessed.push((
            "V6.6.3".to_owned(),
            "Whether emailed sign-in codes can be guessed: a code asked for and used in the same \
             session did not sign in, so a right code refused after wrong ones would show nothing."
                .to_owned(),
        ));
        return;
    }
    let mut session = Session::default();
    let code = match flow.ask(http, &mut session, "guessed", out) {
        Ok(code) => code,
        Err(why) => {
            out.not_assessed.push(("V6.6.3".to_owned(), why));
            return;
        }
    };
    let attempts = allowed + 1;
    let mut answers: Vec<(u16, u128)> = Vec::new();
    for n in 0..attempts {
        let wrong = wrong_code(&code, n);
        let started = std::time::Instant::now();
        let response = flow.send_use(http, &wrong, &mut session, &format!("guess-{n}"));
        let elapsed = started.elapsed().as_millis();
        answers.push((response.map_or(0, |r| r.status), elapsed));
    }
    let Some(&(first_status, first_ms)) = answers.first() else {
        return;
    };
    if matches!(first_status, 0 | 423 | 429) {
        out.not_assessed.push((
            "V6.6.3".to_owned(),
            format!(
                "The app was already refusing ({first_status}) before this check made its first \
                 wrong code, most likely because of a limit an earlier check tripped, so nothing \
                 here can say whether it pushes back at {allowed}."
            ),
        ));
        return;
    }
    let last = answers.last().copied().unwrap_or((0, 0));
    let right_still_works = flow.signs_in(http, &code, &mut session, "after-guesses", out);
    let status_changed = last.0 != first_status;
    let refused = matches!(last.0, 0 | 423 | 429);
    let slowed = last.1 >= first_ms.saturating_mul(4).max(first_ms + 900);
    let how = if !right_still_works {
        "then refused the right code".to_owned()
    } else if refused {
        format!("refused the last wrong code outright ({})", last.0)
    } else if status_changed {
        format!(
            "answered the last wrong code {} where the first got {first_status}",
            last.0
        )
    } else if slowed {
        format!(
            "took {}ms over the last wrong code against {first_ms}ms",
            last.1
        )
    } else {
        String::new()
    };
    out.steps.push(format!(
        "sent {attempts} wrong emailed codes in a row, then the right one; the app {}",
        if how.is_empty() {
            "did not push back"
        } else {
            &how
        }
    ));
    if how.is_empty() {
        out.findings.push(finding(
            &EMAIL_CODE_GUESSING,
            "Emailed sign-in codes can be guessed without limit",
            Severity::High,
            format!(
                "securevibe.toml says the app should allow {allowed} wrong codes in a row. After \
                 {attempts} wrong codes through {}, each answered {first_status}, the right code \
                 still signed in.",
                flow.entry.use_code.path
            ),
        ));
    } else {
        out.verified.push(crate::Verified::new(
            EMAIL_CODE_GUESSING.rule_id,
            EMAIL_CODE_GUESSING.requirement_ids,
            format!(
                "{attempts} wrong emailed codes in a row, the number you stated plus one: the app \
                 {how}"
            ),
        ));
    }
}

/// A code that is certainly wrong and looks like the real one: the same length and kind of
/// character, each position moved along by a different amount.
fn wrong_code(code: &str, n: u32) -> String {
    code.chars()
        .enumerate()
        .map(|(i, c)| {
            let step = (n as usize + i) % 8 + 1;
            if c.is_ascii_digit() {
                char::from(b'0' + ((c as u8 - b'0') as usize + step) as u8 % 10)
            } else if c.is_ascii_lowercase() {
                char::from(b'a' + ((c as u8 - b'a') as usize + step) as u8 % 26)
            } else if c.is_ascii_uppercase() {
                char::from(b'A' + ((c as u8 - b'A') as usize + step) as u8 % 26)
            } else {
                c
            }
        })
        .collect()
}

/// Whether an emailed sign-in code could be guessed: too short to hold 20 bits (V6.5.4).
///
/// Only ever a finding, by `most_bits`, an upper bound: a code this calls too short is too short
/// however it was made, and a long one may still be predictable.
fn email_code_short_check(codes: &[String], out: &mut Outcome) {
    let Some(shortest) = codes.iter().min_by_key(|c| c.chars().count()) else {
        return;
    };
    let bits = most_bits(shortest);
    if bits < 19.9 {
        out.findings.push(finding(
            &EMAIL_CODE_SHORT,
            "The emailed sign-in code is short enough to guess",
            Severity::High,
            format!(
                "The code in the sign-in email is {} characters long and can hold at most {bits:.0} \
                 bits, fewer than the 20 of six random digits that ASVS asks for.",
                shortest.chars().count()
            ),
        ));
    }
}

/// The pieces every emailed-code check needs, found once.
struct EmailCode<'a> {
    entry: &'a sv_manifest::ResetSection,
    patterns: Vec<regex::Regex>,
    account: Account,
    confirm: &'a str,
}

impl<'a> EmailCode<'a> {
    /// Everything up to the first code, or `None` having said why not.
    fn start(
        http: &mut dyn Http,
        users: &'a UsersSection,
        accounts: &Accounts,
        confirm: Option<&'a str>,
        ids: &str,
        out: &mut Outcome,
    ) -> Option<Self> {
        let Some(entry) = &users.email_code else {
            out.not_assessed.push((
                ids.to_owned(),
                "Signing in with an emailed code: securevibe.toml sets no `email-code` under \
                 [stack.run.users]."
                    .to_owned(),
            ));
            return None;
        };
        let patterns = match code_patterns(
            entry.code_pattern.as_deref(),
            "login|log-in|signin|sign-in|magic|verify|auth",
        ) {
            Ok(p) => p,
            Err(e) => {
                out.not_assessed.push((
                    ids.to_owned(),
                    format!("`email-code.code-pattern` in securevibe.toml cannot be used: {e}."),
                ));
                return None;
            }
        };
        let Some(confirm) = confirm else {
            out.not_assessed.push((
                ids.to_owned(),
                "Signing in with an emailed code: telling whether it worked needs a private page a \
                 signed-in user alone can open, and none was shown."
                    .to_owned(),
            ));
            return None;
        };
        // A sign-in by code changes nothing about an account, so A will do when there is no
        // sign-up; with one, an account of its own keeps its mail apart from everything else.
        let account = match &users.signup {
            Some(signup) => {
                let spare = &accounts.spare;
                let account = Account {
                    user: format!("code.{}", accounts.a.user),
                    password: format!(
                        "Co-{}-aZ9!",
                        spare.chars().skip(4).take(24).collect::<String>()
                    ),
                };
                sign_up(http, signup, "code", &account);
                account
            }
            None => accounts.a.clone(),
        };
        if http.mail(&account.user, 0).is_none() {
            out.not_assessed.push((
                ids.to_owned(),
                "Signing in with an emailed code: the run had no mail server for the app to send \
                 to, so there was no email to read."
                    .to_owned(),
            ));
            return None;
        }
        Some(EmailCode {
            entry,
            patterns,
            account,
            confirm,
        })
    }

    /// Asks for a code in this session and reads it from the newest email; or says why there is
    /// none, for the caller to report against the requirements it was needed for.
    fn ask(
        &self,
        http: &mut dyn Http,
        session: &mut Session,
        label: &str,
        out: &mut Outcome,
    ) -> Result<String, String> {
        let no_sink = || "The run's mail server stopped answering.".to_owned();
        let before = http.mail(&self.account.user, 0).ok_or_else(no_sink)?.len();
        self.open_form(http, &self.entry.request.path, session, label);
        let values = Values {
            user: &self.account.user,
            ..Default::default()
        };
        let (response, _) = send_template(
            http,
            &format!("email-code-request-{label}"),
            &self.entry.request,
            &values,
            session,
            &[],
        );
        let mail = http
            .mail(&self.account.user, before + 1)
            .ok_or_else(no_sink)?;
        let code = mail
            .get(before..)
            .and_then(|new| new.last())
            .and_then(|m| reset_code(m, &self.patterns));
        out.steps.push(format!(
            "asked for a sign-in code for {} ({}): {}",
            self.account.user,
            status(&response),
            match (&code, mail.len() > before) {
                (Some(_), _) => "the email arrived with a code in it",
                (None, true) => "the email arrived with no code found in it",
                (None, false) => "no email arrived",
            }
        ));
        match (code, mail.len() > before) {
            (Some(code), _) => Ok(code),
            (None, true) => Err(
                "The sign-in email arrived and no code was found in it. Set \
                                 `email-code.code-pattern` in securevibe.toml to a pattern whose \
                                 first group is the code."
                    .to_owned(),
            ),
            (None, false) => Err(format!(
                "Asked for a sign-in code, the app sent no email to {} at the run's mail server. \
                 The app is told where that is in SMTP_HOST and SMTP_PORT; check that it reads \
                 them, and check `email-code.request` in securevibe.toml.",
                self.account.user
            )),
        }
    }

    /// Opens the form's page first in a session that has nothing yet, as a browser would. A
    /// template with no `{csrf}` sends no page request of its own, and a code asked for with no
    /// session at all cannot be tied to one: that is how the first run against a real app reported
    /// a correct one for codes that work anywhere.
    fn open_form(&self, http: &mut dyn Http, path: &str, session: &mut Session, label: &str) {
        if session.cookies.is_empty()
            && session.bearer.is_none()
            && let Some(page) = http.send(&get(&format!("email-code-page-{label}"), path, session))
        {
            session.absorb(&page);
        }
    }

    fn send_use(
        &self,
        http: &mut dyn Http,
        code: &str,
        session: &mut Session,
        label: &str,
    ) -> Option<ProbeResponse> {
        let values = Values {
            user: &self.account.user,
            code,
            ..Default::default()
        };
        send_template(
            http,
            &format!("email-code-use-{label}"),
            &self.entry.use_code,
            &values,
            session,
            &[],
        )
        .0
    }

    /// Uses a code in this session and says whether the session then opens the private page.
    fn signs_in(
        &self,
        http: &mut dyn Http,
        code: &str,
        session: &mut Session,
        label: &str,
        out: &mut Outcome,
    ) -> bool {
        self.open_form(http, &self.entry.use_code.path, session, label);
        let answer = self.send_use(http, code, session, label);
        let opened = ok(&http.send(&get(
            &format!("email-code-private-{label}"),
            self.confirm,
            session,
        )));
        out.steps.push(format!(
            "used an emailed code ({label}, {}): {}",
            status(&answer),
            if opened { "signed in" } else { "not signed in" }
        ));
        opened
    }
}

/// Where a code is looked for in an email: the owner's pattern, or a link's usual places, with
/// `under` naming the words a link's path goes through (`reset`, or the sign-in words).
fn code_patterns(custom: Option<&str>, under: &str) -> Result<Vec<regex::Regex>, String> {
    if let Some(custom) = custom {
        let pattern = regex::Regex::new(custom).map_err(|e| e.to_string())?;
        if pattern.captures_len() < 2 {
            return Err("it has no group, `( … )`, to say which part is the code".to_owned());
        }
        return Ok(vec![pattern]);
    }
    // `;` as well as `&` before a parameter: in an HTML email a link's `&` is written `&amp;`.
    [
        r"(?i)[?&;](?:reset[_-]?|login[_-]?)?(?:token|code|key)=([A-Za-z0-9._~%-]+)".to_owned(),
        format!(
            r#"(?i)https?://[^\s"'<>]*(?:{under})[^\s"'<>?]*/([A-Za-z0-9._~-]{{8,}})(?:[\s"'<>?#]|$)"#
        ),
        // A code written out on its own: "your code is 482913", "Code: X7K2Q9".
        r"(?i)\bcode(?:\s+is)?\s*:?\s*([A-Za-z0-9]{4,12})\b".to_owned(),
    ]
    .iter()
    .map(|p| regex::Regex::new(p).map_err(|e| e.to_string()))
    .collect()
}

fn reset_code(mail: &str, patterns: &[regex::Regex]) -> Option<String> {
    let found = patterns
        .iter()
        .find_map(|p| p.captures(mail).and_then(|c| c.get(1)))?;
    let code = percent_decode(found.as_str());
    (!code.is_empty()).then_some(code)
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(b) = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether a reset code could be guessed: too short to hold 20 bits, or counting up.
///
/// The floor is the one ASVS sets for codes sent out of band (V6.5.4), which names six random
/// digits as enough; a code is compared against it by `most_bits`, an upper bound, so a code this
/// calls too short is too short however it was made. A long code is credited with nothing.
fn reset_code_check(codes: &[String], out: &mut Outcome) {
    let Some(shortest) = codes.iter().min_by_key(|c| c.chars().count()) else {
        return;
    };
    let bits = most_bits(shortest);
    if bits < 19.9 {
        out.findings.push(finding(
            &RESET_CODE_GUESSABLE,
            "The password reset code is short enough to guess",
            Severity::High,
            format!(
                "The code in the reset email is {} characters long and can hold at most {bits:.0} \
                 bits, fewer than the 20 of six random digits, the least ASVS accepts for a code \
                 sent by email.",
                shortest.chars().count()
            ),
        ));
        return;
    }
    let numbers: Vec<u128> = codes.iter().filter_map(|c| c.parse().ok()).collect();
    if numbers.len() == codes.len()
        && let [.., earlier, later] = numbers.as_slice()
        && (1..=1000).contains(&later.abs_diff(*earlier))
    {
        out.findings.push(finding(
            &RESET_CODE_GUESSABLE,
            "Password reset codes count up",
            Severity::High,
            format!(
                "Two reset emails asked for one after the other carried codes {} apart: whoever has \
                 one code can work out the next.",
                later.abs_diff(*earlier)
            ),
        ));
    }
}

/// Whether the answer to a reset request tells an address with an account from one without.
///
/// Two requests for the same account show what changes between identical requests — a token in
/// a hidden field, a time — and all of that is set aside first; the address itself is replaced
/// in each answer, since echoing it back is no leak. Only a difference left over after that is a
/// finding, and a pair that differs from itself leaves the wording unjudged, never faulted.
fn reveals_account_check(
    answers: [&Option<ProbeResponse>; 3],
    user: &str,
    nobody: &str,
    path: &str,
    out: &mut Outcome,
) {
    let [Some(first), Some(second), Some(stranger)] = answers else {
        return;
    };
    if first.status == second.status && stranger.status != first.status {
        out.findings.push(finding(
            &RESET_REVEALS_ACCOUNT,
            "Password reset tells anyone whether an address has an account",
            Severity::Medium,
            format!(
                "A reset request to {path} was answered {} for an address with an account and {} \
                 for one without.",
                first.status, stranger.status
            ),
        ));
        return;
    }
    let shape = |r: &ProbeResponse, address: &str| {
        let location = r
            .headers
            .iter()
            .find(|(k, _)| k == "location")
            .map_or("", |(_, v)| v.as_str());
        same_shape(&format!("{location}\n{}", r.body), address)
    };
    let (a, b, c) = (
        shape(first, user),
        shape(second, user),
        shape(stranger, nobody),
    );
    if a == b && c != a && first.status == stranger.status {
        out.findings.push(finding(
            &RESET_REVEALS_ACCOUNT,
            "Password reset tells anyone whether an address has an account",
            Severity::Medium,
            format!(
                "A reset request to {path} was answered in different words, or sent somewhere \
                 different, for an address with an account than for one without, where two \
                 requests for the same account were answered alike."
            ),
        ));
    }
}

/// An answer with what legitimately differs between requests taken out: the address it was about,
/// however it was written, the values of fields, and long random-looking runs.
fn same_shape(text: &str, address: &str) -> String {
    let mut text = text.to_owned();
    for written in [
        address.to_owned(),
        address.replace('@', "%40"),
        address.replace('@', "&#64;"),
        address.replace('@', "&#x40;"),
    ] {
        text = text.replace(&written, "{user}");
    }
    let values = regex::Regex::new(r#"(?i)value\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)"#)
        .expect("a fixed pattern");
    let long = regex::Regex::new(r"[A-Za-z0-9_-]{16,}").expect("a fixed pattern");
    let text = values.replace_all(&text, "value");
    long.replace_all(&text, "#").into_owned()
}

/// A password hint or a secret question on a page, in the page's words or a field's name.
///
/// Only ever a finding: a page with none of these words can still ask for one in a way no list of
/// phrases foresees, and the same page may be one step of several.
fn password_hint(body: &str) -> Option<String> {
    let words = regex::Regex::new(
        r"(?i)\b(security question|secret question|password hint|mother'?s maiden name|name of your first pet|first pet'?s name|what city were you born)\b",
    )
    .ok()?;
    if let Some(m) = words.find(body) {
        return Some(format!("\"{}\"", m.as_str()));
    }
    let names = regex::Regex::new(
        r"(?i)^(password_?hint|hint|security_?question|secret_?question|security_?answer|secret_?answer)$",
    )
    .ok()?;
    ["input", "select", "textarea"]
        .iter()
        .flat_map(|t| tags(body, t))
        .filter_map(|tag| attribute(&tag, "name"))
        .find(|name| names.is_match(name))
        .map(|name| format!("a field named `{name}`"))
}

/// Whether deleting an account ends every session it had (V7.4.2), through `delete-account`.
///
/// Only ever on an account made for it through `signup`; A and B are never deleted. It is signed in
/// twice, as two browsers would be, and both sessions are shown to open the private page. The
/// account is deleted from the first; then the second is asked for the private page again. The
/// deletion itself is shown first: the account's password must no longer sign in, or a surviving
/// session says nothing about deletion.
fn delete_account_check(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    const IDS: &str = "V7.4.2";
    let Some(delete) = &users.delete_account else {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether deleting an account ends its sessions: securevibe.toml sets no \
             `delete-account` under [stack.run.users]."
                .to_owned(),
        ));
        return;
    };
    let Some(signup) = &users.signup else {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether deleting an account ends its sessions: only an account made for the purpose is \
             ever deleted, and securevibe.toml sets no `signup` to make one."
                .to_owned(),
        ));
        return;
    };
    let Some(confirm) = confirm else {
        return;
    };
    let spare = &accounts.spare;
    if spare.len() < 32 {
        return;
    }
    let account = Account {
        user: format!("delete.{}", accounts.a.user),
        password: format!("De-{}-aZ9!", &spare[3..27]),
    };
    sign_up(http, signup, "delete", &account);
    let mut quiet = Vec::new();
    let (Some(first), Some(second)) = (
        sign_in(http, users, "delete-1", &account, &mut quiet),
        sign_in(http, users, "delete-2", &account, &mut quiet),
    ) else {
        return;
    };
    let opens = |http: &mut dyn Http, s: &Session, id: &str| ok(&http.send(&get(id, confirm, s)));
    if !(opens(http, &first.session, "delete-before-1")
        && opens(http, &second.session, "delete-before-2"))
    {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether deleting an account ends its sessions: the account made for it could not be \
             signed in twice to begin with."
                .to_owned(),
        ));
        return;
    }
    let mut session = first.session.clone();
    let values = Values {
        user: &account.user,
        password: &account.password,
        ..Default::default()
    };
    // The token is looked for where sign-out looks for it: the delete button is usually on a page
    // of its own account, not at the address it posts to.
    let pages: Vec<String> = users
        .private
        .iter()
        .cloned()
        .chain(users.owned.as_ref().map(|o| o.create.path.clone()))
        .collect();
    let (answer, _) = send_template(
        http,
        "delete-account",
        delete,
        &values,
        &mut session,
        &pages,
    );
    out.steps.push(format!(
        "deleted an account made for it, signed in twice ({})",
        status(&answer)
    ));
    if account_works(http, users, "deleted", &account, confirm, &mut out.steps) {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "Whether deleting an account ends its sessions: after the request to {}, the \
                 account still signed in, so it was not deleted. Check `delete-account` in \
                 securevibe.toml.",
                delete.path
            ),
        ));
        return;
    }
    if opens(http, &second.session, "delete-after") {
        out.findings.push(finding(
            &SESSIONS_SURVIVE_DELETION,
            "A deleted account's other sessions keep working",
            Severity::High,
            format!(
                "After the account was deleted through {}, a second session signed in to it earlier \
                 still opened {confirm}.",
                delete.path
            ),
        ));
    } else {
        out.verified.push(crate::Verified::new(
            SESSIONS_SURVIVE_DELETION.rule_id,
            SESSIONS_SURVIVE_DELETION.requirement_ids,
            format!(
                "an account signed in twice and deleted through {} from one session: the other was \
                 refused afterwards, and the account's password no longer signed in",
                delete.path
            ),
        ));
    }
}

// ------------------------------------------------------------------------------------------------
// Uploads

/// A GIF's magic bytes, which are ASCII and so survive a body that must be valid text.
///
/// The probe requests carry a `String` body, so a real PNG or JPEG header cannot be written into
/// one: `\x89PNG` is not valid UTF-8. GIF87a is, which is why the correct file here is a GIF. That
/// is a convenience of the harness rather than a claim about what apps accept, and it is why the
/// mismatched file below claims `.gif` too: both halves of the comparison are the same extension,
/// so a refusal can only be about the contents.
const GIF_MAGIC: &str = "GIF87a";

/// One file the probes send: its name, its contents, and what it is for.
struct Upload<'a> {
    id: &'a str,
    name: &'a str,
    contents: String,
}

/// Builds a multipart body by hand, because there is no HTTP client here to do it.
fn multipart(
    boundary: &str,
    field: &str,
    file: &Upload,
    form: &BTreeMap<String, String>,
) -> String {
    let mut body = String::new();
    for (name, value) in form {
        body.push_str(&format!("--{boundary}\r\n"));
        body.push_str(&format!(
            "Content-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!("--{boundary}\r\n"));
    body.push_str(&format!(
        "Content-Disposition: form-data; name=\"{field}\"; filename=\"{}\"\r\n",
        file.name
    ));
    body.push_str("Content-Type: application/octet-stream\r\n\r\n");
    body.push_str(&file.contents);
    body.push_str(&format!("\r\n--{boundary}--\r\n"));
    body
}

/// Sends one file and returns what the app answered.
fn send_upload(
    http: &mut dyn Http,
    upload: &UploadSection,
    file: &Upload,
    session: &Session,
    csrf: Option<&str>,
) -> Option<ProbeResponse> {
    const BOUNDARY: &str = "----sv-probe-boundary-6f21a9";
    let values = Values {
        user: "",
        password: "",
        csrf: csrf.map(str::to_owned),
        ..Default::default()
    };
    let form: BTreeMap<String, String> = upload
        .form
        .iter()
        .map(|(k, v)| (k.clone(), fill(v, &values)))
        .collect();
    let body = multipart(BOUNDARY, &upload.field, file, &form);
    let mut request = ProbeRequest {
        id: file.id.to_owned(),
        method: "POST".into(),
        path: upload.path.clone(),
        headers: vec![(
            "Content-Type".into(),
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )],
        body: Some(body),
    };
    for (name, value) in session.headers() {
        request.headers.push((name, value));
    }
    http.send(&request)
}

/// The three files an app ought to refuse, and what it serves back afterwards.
///
/// Every part of this establishes its own setup first. A refusal proves nothing unless an ordinary
/// file of the same shape was accepted, so an ordinary GIF goes first and each later answer is read
/// against it: if the app refuses everything, or the upload path is not what securevibe.toml says,
/// the questions are reported *not assessed* rather than passed.
/// What every two-factor sign-in attempt shares: where to send the code, as whom, and the private
/// page that says whether it worked.
struct TotpSignIn<'a> {
    users: &'a UsersSection,
    entry: &'a RequestTemplate,
    account: &'a Account,
    confirm: &'a str,
}

impl TotpSignIn<'_> {
    /// Signs in with the password, then gives `code`, and says whether the private page then
    /// opened. `gate` first asks the private page between the two steps, and answers `None` when it
    /// already opened there: then the code is not what let anybody in, and nothing about codes can
    /// be told.
    fn attempt(&self, http: &mut dyn Http, code: &str, who: &str, gate: bool) -> Option<bool> {
        let mut quiet = Vec::new();
        let mut session = sign_in(http, self.users, who, self.account, &mut quiet)?.session;
        if gate && ok(&http.send(&get(&format!("totp-gate-{who}"), self.confirm, &session))) {
            return None;
        }
        let values = Values {
            user: &self.account.user,
            password: &self.account.password,
            code,
            ..Default::default()
        };
        send_template(
            http,
            &format!("totp-{who}"),
            self.entry,
            &values,
            &mut session,
            &self.users.private,
        );
        Some(ok(&http.send(&get(
            &format!("totp-confirm-{who}"),
            self.confirm,
            &session,
        ))))
    }
}

/// Whether a two-factor code works once only (V6.5.1) and only while it is current (V6.5.5).
///
/// `seed` enrolled a third account with a secret this run made, so the codes an authenticator app
/// would show are computed here. The order is the substance:
///
/// 1. **The code from five steps ago, first**, two and a half minutes old, which no clock drift
///    explains — and before any code has been used. Many apps refuse a code for any step not later
///    than the last one used, which is how they stop a code being used twice; ask for an old code
///    after a current one and that rule refuses it whatever the app thinks of its age, and an app
///    that takes ten-minute-old codes would be credited. The private page has to stay shut between
///    the password and this code, or nothing about codes can be told.
/// 2. **The current code**, which has to sign in: the control.
/// 3. **The same code again**, in a new sign-in.
/// 4. **A fresh code**, once the next step has begun, which has to sign in too. Without it, two
///    refusals in a row could be the account locking rather than the codes being refused, and
///    neither is credited.
fn totp_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    const IDS: &str = "V6.5.1, V6.5.5";
    let Some(entry) = &users.totp else {
        return;
    };
    let Some(totp) = &accounts.totp else {
        out.not_assessed.push((
            IDS.to_owned(),
            "`totp` is set in securevibe.toml, but only `seed` can enroll an account in two-factor \
             sign-in, and there is no `seed`."
                .to_owned(),
        ));
        return;
    };
    let Some(confirm) = confirm else {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether a code signed in is told by opening a private page, and no private page was \
             shown to open for a signed-in user alone."
                .to_owned(),
        ));
        return;
    };
    let secret = &totp.secret;
    let signing = TotpSignIn {
        users,
        entry,
        account: &totp.account,
        confirm,
    };
    let step = http.now() / crate::totp::STEP;
    let current = crate::totp::code_at_step(secret, step);
    let old = crate::totp::code_at_step(secret, step.saturating_sub(5));

    // 1. The old code, before any code has been used.
    let Some(stale) = signing.attempt(http, &old, "1", true) else {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "The two-factor account opened {confirm} with its password alone, before any code \
                 was given, so what the app does with a code cannot be seen. Check that `seed` \
                 enrolled it with SV_TOTP_SECRET."
            ),
        ));
        return;
    };

    // 2. The control: the current code.
    if !signing.attempt(http, &current, "2", false).unwrap_or(false) {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "The current code for the secret `seed` was given did not sign the two-factor \
                 account in through {}, so a refused code shows nothing. Check `totp` in \
                 securevibe.toml, and that `seed` enrolled the account with SV_TOTP_SECRET.",
                entry.path
            ),
        ));
        return;
    }

    // 3. The same code again, in a new sign-in.
    let reused = signing.attempt(http, &current, "3", false) == Some(true);
    out.steps.push(format!(
        "the two-factor account's code from 2½ minutes ago: {}; the current code: opened; the \
         same code again: {}",
        if stale { "opened" } else { "refused" },
        if reused { "opened" } else { "refused" }
    ));

    // 4. A fresh code, once the next step has begun.
    let into_next = crate::totp::STEP - http.now() % crate::totp::STEP + 1;
    http.wait(into_next);
    let fresh = crate::totp::code_at_step(secret, http.now() / crate::totp::STEP);
    let works = signing.attempt(http, &fresh, "4", false) == Some(true);
    out.steps.push(format!(
        "waited {into_next}s for the next step; its code: {}",
        if works { "opened" } else { "refused" }
    ));

    for (worked, rule, id, title, severity, what) in [
        (
            reused,
            &TOTP_REUSED,
            "V6.5.1",
            "A two-factor code works more than once",
            Severity::Medium,
            "the code that had just signed the account in, used again in a new sign-in",
        ),
        (
            stale,
            &TOTP_OLD_CODE,
            "V6.5.5",
            "A two-factor code still works minutes after it was shown",
            Severity::Low,
            "the code from five 30-second steps earlier, two and a half minutes old, before any \
             code had been used",
        ),
    ] {
        if worked {
            out.findings.push(finding(
                rule,
                title,
                severity,
                format!("The app signed the two-factor account in with {what}."),
            ));
        } else if works {
            out.verified.push(crate::Verified::new(
                rule.rule_id,
                rule.requirement_ids,
                format!("{what}, refused, where a fresh code afterwards signed in"),
            ));
        } else {
            out.not_assessed.push((
                id.to_owned(),
                format!(
                    "The app refused {what}, but then refused a fresh code as well, so the refusal \
                     may be the account locking rather than the code."
                ),
            ));
        }
    }
}

/// Whether an answer says the flow finished: `completed` in its page, or in the address it sends
/// the browser on to. Only an answer the app accepted counts, so an error page that happens to
/// mention the words does not.
fn finished(response: &Option<ProbeResponse>, completed: &str) -> bool {
    response.as_ref().is_some_and(|r| {
        (200..400).contains(&r.status)
            && (r.body.contains(completed)
                || r.headers
                    .iter()
                    .any(|(k, v)| k.eq_ignore_ascii_case("location") && v.contains(completed)))
    })
}

/// Sends the steps given, in the order given, in one session; the last answer.
fn take_steps(
    http: &mut dyn Http,
    who: &str,
    steps: &[&RequestTemplate],
    values: &Values,
    session: &mut Session,
    pages: &[String],
) -> Option<ProbeResponse> {
    let mut last = None;
    for (i, step) in steps.iter().enumerate() {
        last = send_template(
            http,
            &format!("flow-{who}-{i}"),
            step,
            values,
            session,
            pages,
        )
        .0;
    }
    last
}

/// Whether a flow of several steps can be skipped through (V2.3.1).
///
/// A goes through every step in order first. That has to end in the owner's `completed`, or
/// nothing can be told: a skip refused by an app whose flow does not work as described is not a
/// skip refused. Then B, signed in afresh so nothing of A's carries over, goes straight to the last
/// step, and — when there is a middle to leave out — signs in afresh again and does the first step
/// and then the last. Either ending in `completed` is a finding. Both refused is support for V2.3.1
/// and no more: it is on the manual-only list, because two skips refused is not every order refused.
///
/// Doing a step twice, and doing steps out of order other than by leaving some out, are not tried.
fn flow_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    a: &SignedIn,
    out: &mut Outcome,
) {
    const ID: &str = "V2.3.1";
    let Some(flow) = &users.flow else {
        return;
    };
    if flow.steps.len() < 2 {
        out.not_assessed.push((
            ID.to_owned(),
            "The `flow` in securevibe.toml has fewer than two steps, so there is no step to skip."
                .to_owned(),
        ));
        return;
    }
    if flow.completed.trim().is_empty() {
        out.not_assessed.push((
            ID.to_owned(),
            "The `flow` in securevibe.toml does not say what the last step shows when the flow \
             finished (`completed`), so a skip that worked cannot be told from one that was refused."
                .to_owned(),
        ));
        return;
    }
    let steps: Vec<&RequestTemplate> = flow.steps.iter().collect();
    let last = steps[steps.len() - 1];
    let marker = format!("sv-flow-{}", accounts.spare.get(..8).unwrap_or("0"));
    fn values<'v>(account: &'v Account, marker: &'v str) -> Values<'v> {
        Values {
            user: &account.user,
            password: &account.password,
            marker,
            ..Default::default()
        }
    }

    // The control: every step, in order, as A.
    let mut session = a.session.clone();
    let done = take_steps(
        http,
        "a",
        &steps,
        &values(&accounts.a, &marker),
        &mut session,
        &users.private,
    );
    if !finished(&done, &flow.completed) {
        out.not_assessed.push((
            ID.to_owned(),
            format!(
                "Going through the {} steps in order as A ended in {}, without \"{}\", so the flow \
                 does not finish as securevibe.toml describes and nothing can be told from skipping \
                 a step.",
                steps.len(),
                status(&done),
                flow.completed
            ),
        ));
        return;
    }
    out.steps.push(format!(
        "went through the {} steps of the flow in order as A: finished",
        steps.len()
    ));

    let mut tries: Vec<(&str, Vec<&RequestTemplate>)> = vec![(
        "straight to the last step, with none of the steps before it",
        vec![last],
    )];
    if steps.len() >= 3 {
        tries.push((
            "the first step and then the last, leaving out the ones between",
            vec![steps[0], last],
        ));
    }
    let mut skipped = Vec::new();
    for (i, (how, these)) in tries.iter().enumerate() {
        let who = format!("flow-b{i}");
        let Some(b) = sign_in(http, users, &who, &accounts.b, &mut out.steps) else {
            out.not_assessed.push((
                ID.to_owned(),
                "B could not sign in again to try skipping a step in a fresh session.".to_owned(),
            ));
            return;
        };
        let mut session = b.session.clone();
        let answer = take_steps(
            http,
            &who,
            these,
            &values(&accounts.b, &marker),
            &mut session,
            &users.private,
        );
        let worked = finished(&answer, &flow.completed);
        out.steps.push(format!(
            "as B, {how}: {}",
            if worked { "finished" } else { "refused" }
        ));
        if worked {
            skipped.push(*how);
        }
    }

    if skipped.is_empty() {
        out.verified.push(crate::Verified::new(
            STEP_SKIPPED.rule_id,
            STEP_SKIPPED.requirement_ids,
            format!(
                "a {}-step flow skipped {} way{}, refused each time, where the steps in order \
                 finished",
                steps.len(),
                tries.len(),
                if tries.len() == 1 { "" } else { "s" }
            ),
        ));
    } else {
        out.findings.push(finding(
            &STEP_SKIPPED,
            "A step of the flow can be skipped",
            Severity::High,
            format!(
                "The flow ended in \"{}\" for B, going {}. Only going through every step in order \
                 should get there.",
                flow.completed,
                skipped.join(", and also ")
            ),
        ));
    }
}

fn upload_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    signed_in: &SignedIn,
    out: &mut Outcome,
) {
    let Some(upload) = &users.upload else {
        return;
    };
    let session = &signed_in.session;
    let csrf = |http: &mut dyn Http| {
        users.private.first().and_then(|path| {
            http.send(&get("upload-page", path, session))
                .and_then(|page| csrf_token(&page, session))
        })
    };
    let token = csrf(http);

    // 1. An ordinary file, to show the upload works at all. Without this every refusal below is
    //    a refusal of everything.
    let ordinary = Upload {
        id: "upload-ordinary",
        name: "sv-probe.gif",
        contents: format!("{GIF_MAGIC}sv-probe-ordinary-file"),
    };
    let accepted = send_upload(http, upload, &ordinary, session, token.as_deref());
    if accepted.as_ref().is_none_or(|r| r.status >= 400) {
        out.not_assessed.push((
            "V5.2.1, V5.2.2, V5.3.1, V3.2.1".to_owned(),
            format!(
                "An ordinary file was not accepted at {} ({}), so nothing here can tell a file \
                 refused for being wrong from one refused because the upload does not work as \
                 securevibe.toml describes.",
                upload.path,
                status(&accepted)
            ),
        ));
        return;
    }
    out.steps
        .push(format!("uploaded an ordinary GIF to {}", upload.path));

    // 2. V5.2.1: a file larger than the owner says the app accepts.
    match upload.max_bytes {
        None => out.not_assessed.push((
            "V5.2.1".to_owned(),
            "Whether the app refuses files that are too large: say the largest it should accept, \
             as `max-bytes` under the `upload` entry in securevibe.toml, and this will send one \
             larger than that."
                .to_owned(),
        )),
        // A cap, so one check cannot become a denial-of-service against somebody's own app. Above
        // it the check says what it did rather than pretending to have tested the policy.
        Some(most) if most > MOST_UPLOAD_BYTES => out.not_assessed.push((
            "V5.2.1".to_owned(),
            format!(
                "`max-bytes` is {most}. This check sends at most {MOST_UPLOAD_BYTES} bytes, so it \
                 cannot exceed that number without becoming a denial-of-service attempt against \
                 your own app."
            ),
        )),
        Some(most) => {
            let big = Upload {
                id: "upload-oversized",
                name: "sv-probe-big.gif",
                contents: format!("{GIF_MAGIC}{}", "A".repeat((most + 1024) as usize)),
            };
            let answer = send_upload(http, upload, &big, session, token.as_deref());
            let refused = answer.as_ref().is_none_or(|r| r.status >= 400);
            out.steps.push(format!(
                "sent a file of {} bytes where {most} is the stated limit: {}",
                most + 1024 + GIF_MAGIC.len() as u64,
                if refused { "refused" } else { "accepted" }
            ));
            if refused {
                out.verified.push(crate::Verified::new(
                    OVERSIZED_FILE.rule_id,
                    OVERSIZED_FILE.requirement_ids,
                    format!(
                        "a file about {} bytes larger than the {most} you stated, refused where an \
                         ordinary one was accepted",
                        1024 + GIF_MAGIC.len() as u64
                    ),
                ));
            } else {
                out.findings.push(finding(
                    &OVERSIZED_FILE,
                    "A file larger than the stated limit was accepted",
                    Severity::Medium,
                    format!(
                        "securevibe.toml says the app accepts at most {most} bytes. A file larger \
                         than that was accepted at {} ({}).",
                        upload.path,
                        status(&answer)
                    ),
                ));
            }
        }
    }

    // 3. V5.2.2: contents that are not what the extension promises. Same extension as the ordinary
    //    file above, so a refusal can only be about what is inside it.
    let mismatched = Upload {
        id: "upload-mismatched",
        name: "sv-probe-not-really.gif",
        contents: "<?php echo 'sv-probe'; ?>\nthis is not a GIF at all\n".to_owned(),
    };
    let answer = send_upload(http, upload, &mismatched, session, token.as_deref());
    let refused = answer.as_ref().is_none_or(|r| r.status >= 400);
    out.steps.push(format!(
        "sent a .gif whose contents are not a GIF: {}",
        if refused { "refused" } else { "accepted" }
    ));
    if refused {
        out.verified.push(crate::Verified::new(
            CONTENT_MISMATCH.rule_id,
            CONTENT_MISMATCH.requirement_ids,
            "a file named .gif whose contents are not a GIF, refused where a real GIF of the same \
             name and shape was accepted"
                .to_owned(),
        ));
    } else {
        out.findings.push(finding(
            &CONTENT_MISMATCH,
            "A file is accepted on the strength of its name",
            Severity::Medium,
            format!(
                "A file called `.gif` holding no GIF at all was accepted at {} ({}), where a real \
                 GIF was accepted too: nothing looked at the contents.",
                upload.path,
                status(&answer)
            ),
        ));
    }

    // 4. V5.3.1 and V3.2.1: what the app does with an upload when it is fetched back.
    let Some(serves_at) = &upload.serves_at else {
        out.not_assessed.push((
            "V5.3.1, V3.2.1".to_owned(),
            "The `upload` entry has no `serves-at`, so nothing here could fetch an uploaded file \
             back. An app that never serves uploads over the web has nothing to get wrong here, \
             which is the safest arrangement and not a failure."
                .to_owned(),
        ));
        return;
    };
    served_upload_checks(http, upload, serves_at, session, token.as_deref(), out);
    download_name_checks(http, upload, serves_at, session, token.as_deref(), out);
}

/// The parameters of a `Content-Disposition` value, split on `;` the way RFC 6266 means it:
/// never inside a quoted string, and with `\"` inside one taken as a quote rather than its end.
///
/// A naive split on `;` would itself be the bug V5.4.2 is about, so it cannot be how the check
/// reads the header.
fn disposition_params(header: &str) -> Vec<(String, String)> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for c in header.chars() {
        if escaped {
            current.push(c);
            escaped = false;
        } else if quoted && c == '\\' {
            current.push(c);
            escaped = true;
        } else if c == '"' {
            current.push(c);
            quoted = !quoted;
        } else if c == ';' && !quoted {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(c);
        }
    }
    parts.push(current);
    parts
        .iter()
        .filter_map(|p| {
            let (name, value) = p.split_once('=')?;
            Some((
                name.trim().to_lowercase(),
                value.trim().trim_matches('"').to_owned(),
            ))
        })
        .collect()
}

/// The name a file comes back under (V5.4.1), and whether a hostile name can break the header it
/// comes back in (V5.4.2).
///
/// V5.4.1 is read off the ordinary GIF the upload check already put in: an upload fetched back is
/// a download, and the requirement asks that it be served under a name.
///
/// V5.4.2 needs a name built to break things. `sv-probe;svinjected=1.gif` is a legal file name
/// whose `;` and `=` would start a new header parameter if the app wrote the name into
/// `Content-Disposition` unquoted, and nothing else on earth sets a parameter called `svinjected`.
/// So the question becomes exact: after the round trip, does the header have a parameter by that
/// name?
fn download_name_checks(
    http: &mut dyn Http,
    upload: &UploadSection,
    serves_at: &str,
    session: &Session,
    token: Option<&str>,
    out: &mut Outcome,
) {
    const HOSTILE: &str = "sv-probe;svinjected=1.gif";

    // ---- V5.4.1: the ordinary file, uploaded before any of this ran.
    let ordinary_path = serves_at.replace("{name}", "sv-probe.gif");
    match http.send(&get("download-ordinary", &ordinary_path, session)) {
        Some(r) if r.status < 400 => {
            let header = r
                .header("content-disposition")
                .unwrap_or_default()
                .to_owned();
            let named = disposition_params(&header)
                .iter()
                .any(|(k, v)| (k == "filename" || k == "filename*") && !v.is_empty());
            out.steps.push(format!(
                "fetched the ordinary upload back from {ordinary_path}: {}",
                if named {
                    "served under a name"
                } else {
                    "served with no file name"
                }
            ));
            if named {
                out.verified.push(crate::Verified::new(
                    "probe.download-unnamed",
                    &["V5.4.1"],
                    format!(
                        "an uploaded file fetched back from {ordinary_path} came with \
                         `Content-Disposition: {}`, naming the file",
                        header.trim()
                    ),
                ));
            } else {
                out.findings.push(finding(
                    &DOWNLOAD_UNNAMED,
                    "An uploaded file is served back without a file name",
                    Severity::Low,
                    format!(
                        "{ordinary_path} answered {} with {}, so nothing tells the browser what \
                         the file is called; it falls back to a name taken from the address.",
                        r.status,
                        if header.is_empty() {
                            "no `Content-Disposition` header".to_owned()
                        } else {
                            format!(
                                "`Content-Disposition: {}` and no file name in it",
                                header.trim()
                            )
                        }
                    ),
                ));
            }
        }
        answer => out.not_assessed.push((
            "V5.4.1".to_owned(),
            format!(
                "The ordinary upload could not be fetched back from {ordinary_path} ({}), so \
                 nothing here saw what name it is served under.",
                status(&answer)
            ),
        )),
    }

    // ---- V5.4.2: a name built to break the header.
    let hostile = Upload {
        id: "upload-hostile-name",
        name: HOSTILE,
        contents: format!("{GIF_MAGIC}sv-probe-hostile-name"),
    };
    let stored = send_upload(http, upload, &hostile, session, token);
    if stored.as_ref().is_none_or(|r| r.status >= 400) {
        out.not_assessed.push((
            "V5.4.2".to_owned(),
            format!(
                "The app refused a file named `{HOSTILE}` ({}), which is a sound thing to do with \
                 a name like that, but it means nothing here saw such a name served back.",
                status(&stored)
            ),
        ));
        return;
    }
    let path = serves_at.replace("{name}", HOSTILE);
    let fetched = http.send(&get("download-hostile", &path, session));
    let Some(fetched) = fetched.filter(|r| r.status < 400) else {
        out.not_assessed.push((
            "V5.4.2".to_owned(),
            format!(
                "A file named `{HOSTILE}` was accepted but could not be fetched back from {path}. \
                 The app may have stored it under a safer name, which would be right; either way \
                 nothing here saw the name served."
            ),
        ));
        return;
    };
    let header = fetched
        .header("content-disposition")
        .unwrap_or_default()
        .to_owned();
    let params = disposition_params(&header);
    let injected = params.iter().any(|(k, _)| k == "svinjected");
    let named = params
        .iter()
        .any(|(k, v)| (k == "filename" || k == "filename*") && !v.is_empty());
    out.steps.push(format!(
        "fetched a file named `{HOSTILE}` back: {}",
        if injected {
            "its name broke the header"
        } else if named {
            "its name was served intact"
        } else {
            "served with no file name"
        }
    ));
    if injected {
        out.findings.push(finding(
            &DOWNLOAD_NAME_INJECTED,
            "A file name is written into a response header unescaped",
            Severity::Medium,
            format!(
                "A file named `{HOSTILE}` came back from {path} with `Content-Disposition: {}`. The \
                 `;` in the name ended the file name and began a parameter of its own.",
                header.trim()
            ),
        ));
    } else if named {
        out.verified.push(crate::Verified::new(
            DOWNLOAD_NAME_INJECTED.rule_id,
            DOWNLOAD_NAME_INJECTED.requirement_ids,
            format!(
                "a file named `{HOSTILE}` fetched back from {path} with `Content-Disposition: {}`, \
                 its name kept inside the file name rather than starting a parameter",
                header.trim()
            ),
        ));
    } else {
        out.not_assessed.push((
            "V5.4.2".to_owned(),
            format!(
                "A file named `{HOSTILE}` came back from {path} with no file name in its \
                 headers, so there was no served name to judge."
            ),
        ));
    }
}

/// The two questions that need the file fetched back again.
fn served_upload_checks(
    http: &mut dyn Http,
    upload: &UploadSection,
    serves_at: &str,
    session: &Session,
    token: Option<&str>,
    out: &mut Outcome,
) {
    // Server-side code, and a page. One file answers both only if the app serves it, so each is
    // uploaded and fetched on its own.
    const MARKER: &str = "sv-probe-upload-marker-7c31";
    let code = Upload {
        id: "upload-code",
        name: "sv-probe.php",
        contents: format!("<?php echo \"{MARKER}\"; ?>"),
    };
    let page = Upload {
        id: "upload-page-file",
        name: "sv-probe.html",
        contents: format!("<html><body>{MARKER}<script>1</script></body></html>"),
    };

    for (file, rule) in [(&code, &UPLOAD_EXECUTED), (&page, &UPLOAD_RENDERED)] {
        let stored = send_upload(http, upload, file, session, token);
        if stored.as_ref().is_none_or(|r| r.status >= 400) {
            // Refusing the file outright is a perfectly good answer, and a better one than serving
            // it safely — but it is not evidence about how uploads are served, so it is not a pass.
            out.not_assessed.push((
                rule.requirement_ids.join(", "),
                format!(
                    "The app refused `{}` ({}), which is a sound thing to do, but it means nothing \
                     here saw how an uploaded file of that kind is served.",
                    file.name,
                    status(&stored)
                ),
            ));
            continue;
        }
        let path = serves_at.replace("{name}", file.name);
        let Some(fetched) = http.send(&get(&format!("{}-fetch", file.id), &path, session)) else {
            out.not_assessed.push((
                rule.requirement_ids.join(", "),
                format!("Fetching the uploaded file back from {path} got no answer."),
            ));
            continue;
        };
        if fetched.status >= 400 {
            out.not_assessed.push((
                rule.requirement_ids.join(", "),
                format!(
                    "The file was accepted but {path} answered {}, so `serves-at` is not where \
                     this app serves uploads and nothing here saw one served.",
                    fetched.status
                ),
            ));
            continue;
        }

        if std::ptr::eq(rule, &UPLOAD_EXECUTED) {
            // The source came back: not executed. Its output alone, without the source, is.
            let source_intact = fetched.body.contains("<?php");
            let ran = !source_intact && fetched.body.contains(MARKER);
            out.steps.push(format!(
                "fetched an uploaded .php back from {path}: {}",
                if ran {
                    "it had been run"
                } else {
                    "served as-is"
                }
            ));
            if ran {
                out.findings.push(finding(
                    &UPLOAD_EXECUTED,
                    "An uploaded file is executed as server-side code",
                    Severity::High,
                    format!(
                        "A `.php` file this check uploaded came back from {path} with its code \
                         gone and only its output left, so the server ran it."
                    ),
                ));
            } else {
                out.verified.push(crate::Verified::new(
                    UPLOAD_EXECUTED.rule_id,
                    UPLOAD_EXECUTED.requirement_ids,
                    format!(
                        "a `.php` file uploaded and fetched back from {path}, which came back as \
                         it was written rather than as its output"
                    ),
                ));
            }
        } else {
            // A page is safe when the browser is told not to render it as part of this app.
            let disposition = fetched
                .header("content-disposition")
                .unwrap_or_default()
                .to_lowercase();
            let content_type = fetched
                .header("content-type")
                .unwrap_or_default()
                .to_lowercase();
            let csp = fetched
                .header("content-security-policy")
                .unwrap_or_default()
                .to_lowercase();
            let attachment = disposition.contains("attachment");
            let sandboxed = csp.contains("sandbox");
            let not_html = !content_type.contains("text/html");
            let safe = attachment || sandboxed || not_html;
            let how = if attachment {
                "as an attachment"
            } else if sandboxed {
                "with a sandbox policy"
            } else {
                "as something other than a page"
            };
            out.steps.push(format!(
                "fetched an uploaded .html back from {path}: {}",
                if safe { how } else { "served as a page" }
            ));
            if safe {
                out.verified.push(crate::Verified::new(
                    UPLOAD_RENDERED.rule_id,
                    UPLOAD_RENDERED.requirement_ids,
                    format!("an uploaded HTML file, served back from {path} {how}"),
                ));
            } else {
                out.findings.push(finding(
                    &UPLOAD_RENDERED,
                    "An uploaded page is served for the browser to render",
                    Severity::High,
                    format!(
                        "An HTML file this check uploaded came back from {path} as \
                         `{content_type}` with no `Content-Disposition: attachment` and no sandbox \
                         policy, so a browser renders it as part of this app."
                    ),
                ));
            }
        }
    }
}

/// Whether the rules the form states are applied again on the server (V2.2.2).
///
/// The form's own HTML is the list of what the app says it wants: `maxlength`, `type=number`, and
/// `pattern`. Each of those is a rule a browser applies and anybody sending the request directly
/// does not have to. So the probe reads one off the sign-up page and sends a value that breaks it.
///
/// It establishes its setup first, as everything here does: a *correct* sign-up has to be accepted,
/// or "refused" means only that sign-up does not work. And it only ever produces a finding — an app
/// that refuses the broken value might be refusing it for some other reason, so refusing is not
/// proof that this rule in particular is applied.
fn client_side_validation_check(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    out: &mut Outcome,
) {
    let Some(signup) = &users.signup else {
        out.not_assessed.push((
            "V2.2.2".to_owned(),
            "Whether the server applies the rules its own form states: this needs `signup` in \
             [stack.run.users], so a value that breaks one of them can be sent."
                .to_owned(),
        ));
        return;
    };
    // Which field the password goes in, so the constraint found is not the password's own.
    let password_fields: Vec<&str> = signup
        .form
        .iter()
        .filter(|(_, v)| v.contains("{password}"))
        .map(|(k, _)| k.as_str())
        .collect();

    let Some(page) = http.send(&get("validation-form", &signup.path, &Session::default())) else {
        return;
    };
    let session = {
        let mut s = Session::default();
        s.absorb(&page);
        s
    };

    // The first constraint the form states that this can break by sending a longer or non-numeric
    // value. `required` is not usable: leaving a field out is refused by almost everything.
    let mut broken: Option<(String, String, String)> = None;
    for tag in tags(&page.body, "input") {
        let Some(name) = attribute(&tag, "name") else {
            continue;
        };
        if password_fields.contains(&name.as_str()) || !signup.form.contains_key(&name) {
            continue;
        }
        if let Some(max) = attribute(&tag, "maxlength").and_then(|m| m.trim().parse::<usize>().ok())
            && (1..=512).contains(&max)
        {
            broken = Some((name, format!("maxlength={max}"), "a".repeat(max + 10)));
            break;
        }
        if attribute(&tag, "type").is_some_and(|t| t.eq_ignore_ascii_case("number")) {
            broken = Some((name, "type=number".to_owned(), "not-a-number".to_owned()));
            break;
        }
    }
    let Some((field, constraint, value)) = broken else {
        out.not_assessed.push((
            "V2.2.2".to_owned(),
            format!(
                "The sign-up page at {} states no rule in its own HTML that this could break \
                 (`maxlength` or `type=number` on a field securevibe.toml fills in), so there was \
                 nothing to send against.",
                signup.path
            ),
        ));
        return;
    };

    // Setup: an ordinary sign-up has to work, or a refusal below says nothing.
    let control = Account {
        user: format!("valid.{}", accounts.a.user),
        password: format!("Sv-Valid-{}-aZ9!", accounts.b.password.len()),
    };
    if sign_up(http, signup, "validation-control", &control).is_none_or(|r| r.status >= 400) {
        out.not_assessed.push((
            "V2.2.2".to_owned(),
            "An ordinary sign-up was not accepted, so a refusal of the broken value would say \
             nothing about the rule being applied."
                .to_owned(),
        ));
        return;
    }

    let broken_account = Account {
        user: format!("broken.{}", accounts.a.user),
        password: control.password.clone(),
    };
    let values = Values {
        user: &broken_account.user,
        password: &broken_account.password,
        csrf: csrf_token(&page, &session),
        ..Default::default()
    };
    let mut session = session.clone();
    let mut template = signup.clone();
    template.form.insert(field.clone(), value);
    let (response, _) = send_template(
        http,
        "validation-broken",
        &template,
        &values,
        &mut session,
        &[],
    );
    let accepted = response.as_ref().is_some_and(|r| r.status < 400);
    out.steps.push(format!(
        "sent `{field}` breaking the form's own {constraint}: {}",
        if accepted { "accepted" } else { "refused" }
    ));
    if accepted {
        out.findings.push(finding(
            &CLIENT_SIDE_VALIDATION,
            "A rule the form states is not applied on the server",
            Severity::Medium,
            format!(
                "The sign-up page says `{field}` must satisfy {constraint}. Sent directly, without \
                 a browser, a value breaking that was accepted ({}).",
                status(&response)
            ),
        ));
    }
}

/// Whether a session value this check invented is refused (V7.2.1).
///
/// The app's own cookie says what a session looks like; this sends one of the same name and shape
/// that no session store could ever have issued. A private page that opens for it is an app taking
/// the cookie's word rather than checking it.
///
/// Different from V7.2.3, which asks whether a real session id could be *guessed*. This asks
/// whether anything is checked at all, which is the more basic failure and the cheaper one to make.
fn invented_session_check(
    http: &mut dyn Http,
    signed_in: &SignedIn,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    let (Some(confirm), Some(real)) = (confirm, signed_in.session.cookies.first()) else {
        return;
    };
    // The same name and the same length, so nothing is refused merely for being the wrong shape.
    let (name, real_value) = real;
    let invented: String = "sv0probe0invented0session0value0"
        .chars()
        .cycle()
        .take(real_value.chars().count().max(16))
        .collect();
    if invented == *real_value {
        return;
    }
    let mut session = Session::default();
    session.cookies.push((name.clone(), invented));
    let response = http.send(&get("invented-session", confirm, &session));
    let opened = ok(&response);
    out.steps.push(format!(
        "asked for {confirm} with a session value this check invented: {}",
        if opened { "opened" } else { "refused" }
    ));
    if opened {
        out.findings.push(finding(
            &SESSION_TOKEN_UNVERIFIED,
            "A made-up session value opens a private page",
            Severity::High,
            format!(
                "A cookie named `{}`, of the same length as a real one but with a value this check \
                 made up, opened {confirm}.",
                name
            ),
        ));
    } else {
        out.verified.push(crate::Verified::new(
            SESSION_TOKEN_UNVERIFIED.rule_id,
            SESSION_TOKEN_UNVERIFIED.requirement_ids,
            format!(
                "a cookie of the app's own session name and length, with an invented value, \
                 refused {confirm} where the real session opened it"
            ),
        ));
    }
}

/// Field names that should never leave the server, whatever the app calls its columns.
const SECRET_FIELD_NAMES: &[&str] = &[
    "password",
    "passwd",
    "password_hash",
    "pwhash",
    "hashed_password",
    "salt",
    "secret",
    "api_key",
    "apikey",
    "private_key",
    "session_token",
    "csrf_secret",
];

/// Whether a record handed back carries fields nobody outside the server should see (V15.3.1).
///
/// Only ever a finding. Not seeing these names proves nothing: this app may have no such column,
/// may call it something else, or may return the record somewhere this never looked.
fn record_fields_check(body: &str, path: &str, out: &mut Outcome) {
    let lower = body.to_lowercase();
    // A name has to appear as a field, not as a word in a sentence: `"password":` in JSON, or
    // `password=` / `password":` in whatever the app writes. Otherwise a page saying "change your
    // password" is a finding.
    let found: Vec<&str> = SECRET_FIELD_NAMES
        .iter()
        .filter(|name| {
            [
                format!("\"{name}\""),
                format!("'{name}'"),
                format!("{name}="),
            ]
            .iter()
            .any(|shape| lower.contains(shape.as_str()))
        })
        .copied()
        .collect();
    if found.is_empty() {
        return;
    }
    out.findings.push(finding(
        &RECORD_LEAKS_FIELDS,
        "A record is handed back with fields that should stay on the server",
        Severity::Medium,
        format!(
            "Reading back the record at {path} produced {}, named as {} field{}.",
            found.join(", "),
            if found.len() == 1 { "a" } else { "" },
            if found.len() == 1 { "" } else { "s" }
        ),
    ));
}

/// Whether signing out tells the browser to throw away what it kept (V14.3.1).
///
/// Credit on presence only, and this is the reason: `Clear-Site-Data` is one way to meet V14.3.1
/// and the requirement names it as something that "may be able to help". An app whose own script
/// clears storage when the session ends has met it without the header, so not finding one is not a
/// failure — it is simply not something this saw.
fn clear_site_data_check(response: Option<&ProbeResponse>, path: &str, out: &mut Outcome) {
    let Some(response) = response else {
        return;
    };
    let header = response
        .header("clear-site-data")
        .unwrap_or_default()
        .to_lowercase();
    // `"*"` covers everything; otherwise storage is the part that holds signed-in data. Cookies
    // alone are not it: the session ending already does that.
    let clears = header.contains('*') || header.contains("storage");
    out.steps.push(format!(
        "signing out sent Clear-Site-Data: {}",
        if clears {
            "yes"
        } else if header.is_empty() {
            "no"
        } else {
            "not covering storage"
        }
    ));
    if clears {
        out.verified.push(crate::Verified::new(
            "probe.clear-site-data",
            &["V14.3.1"],
            format!(
                "signing out at {path} answered with `Clear-Site-Data: {}`, telling the browser to \
                 throw away what it had kept",
                header.trim()
            ),
        ));
    } else {
        out.not_assessed.push((
            "V14.3.1".to_owned(),
            format!(
                "Whether data is cleared from the browser when the session ends: signing out sent \
                 {}. That is not a failure — an app whose own script clears storage has met this \
                 without the header — but nothing here saw it happen.",
                if header.is_empty() {
                    "no `Clear-Site-Data` header".to_owned()
                } else {
                    format!(
                        "`Clear-Site-Data: {}`, which does not cover storage",
                        header.trim()
                    )
                }
            ),
        ));
    }
}

/// Whether signing out also happens on a plain page visit (V3.5.3).
///
/// A fresh sign-in, shown to open the private page; a GET to the sign-out address; then the private
/// page again. Only ever a finding: one address refusing a GET says nothing about the others.
/// Two questions about the private pages themselves, asked with the session that opened them.
///
/// Both are read off the same responses, because both need the same thing shown first: that the
/// page really opened for a signed-in user. A page that answered 302 to the sign-in screen has no
/// caching headers worth reading and no sign-out link worth looking for, and counting it either way
/// would be judging the sign-in page instead.
fn private_page_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    signed_in: &SignedIn,
    out: &mut Outcome,
) {
    if users.private.is_empty() {
        out.not_assessed.push((
            "V14.3.2, V7.4.4".to_owned(),
            "[stack.run.users] lists no `private` pages, so there is no signed-in page to read \
             caching headers from or to look for a sign-out link on."
                .to_owned(),
        ));
        return;
    }
    let logout_path = users.logout.as_ref().map(|l| l.path.as_str());

    let mut opened = Vec::new();
    let mut not_stored = Vec::new();
    let mut stored = Vec::new();
    let mut with_link = Vec::new();
    let mut without_link = Vec::new();

    for path in &users.private {
        let Some(response) = http.send(&get("private-page-headers", path, &signed_in.session))
        else {
            continue;
        };
        if !(200..300).contains(&response.status) {
            continue;
        }
        opened.push(path.clone());

        // `no-store` is the only value that means "do not keep a copy". `no-cache` permits the copy
        // and asks for it to be revalidated, and `private` only says not to keep it in a shared
        // cache, so neither answers this requirement.
        let cache_control = response
            .header("cache-control")
            .unwrap_or_default()
            .to_lowercase();
        if cache_control
            .split(',')
            .any(|part| part.trim() == "no-store")
        {
            not_stored.push(path.clone());
        } else {
            stored.push(path.clone());
        }

        if logout_path.is_some_and(|logout| points_at(&response.body, logout)) {
            with_link.push(path.clone());
        } else {
            without_link.push(path.clone());
        }
    }

    if opened.is_empty() {
        out.not_assessed.push((
            "V14.3.2, V7.4.4".to_owned(),
            "No private page opened for the signed-in test user, so nothing here could read what \
             it sends or look for its sign-out link."
                .to_owned(),
        ));
        return;
    }

    // ---- V14.3.2: Cache-Control: no-store
    out.steps.push(format!(
        "{} of {} private page{} sent Cache-Control: no-store",
        not_stored.len(),
        opened.len(),
        if opened.len() == 1 { "" } else { "s" }
    ));
    if stored.is_empty() {
        out.verified.push(crate::Verified::new(
            PRIVATE_PAGE_CACHING.rule_id,
            PRIVATE_PAGE_CACHING.requirement_ids,
            format!(
                "{} private page{}, each sending Cache-Control: no-store to a signed-in user",
                opened.len(),
                if opened.len() == 1 { "" } else { "s" }
            ),
        ));
    } else {
        out.findings.push(finding(
            &PRIVATE_PAGE_CACHING,
            "A private page may be kept in the browser's cache",
            Severity::Medium,
            format!(
                "Opened by a signed-in user, {} came back without `Cache-Control: no-store`.",
                stored.join(", ")
            ),
        ));
    }

    // ---- V7.4.4: a visible way to sign out
    //
    // Only asked when securevibe.toml says where signing out happens. Without that there is no
    // address to look for, and "no sign-out link" would be a statement about the manifest.
    let Some(logout) = logout_path else {
        out.not_assessed.push((
            "V7.4.4".to_owned(),
            "[stack.run.users] has no `logout`, so there is no sign-out address to look for on the \
             private pages."
                .to_owned(),
        ));
        return;
    };
    out.steps.push(format!(
        "{} of {} private page{} showed a way to reach {logout}",
        with_link.len(),
        opened.len(),
        if opened.len() == 1 { "" } else { "s" }
    ));
    if without_link.is_empty() {
        out.verified.push(crate::Verified::new(
            SIGN_OUT_LINK.rule_id,
            SIGN_OUT_LINK.requirement_ids,
            format!(
                "{} private page{}, each carrying a link or form pointing at {logout}",
                opened.len(),
                if opened.len() == 1 { "" } else { "s" }
            ),
        ));
    } else {
        out.findings.push(finding(
            &SIGN_OUT_LINK,
            "A private page offers no visible way to sign out",
            Severity::Low,
            format!(
                "Opened by a signed-in user, {} carried no link or form pointing at {logout}.",
                without_link.join(", ")
            ),
        ));
    }
}

/// Whether a page offers a way to reach `target`: a link to it, or a form that posts to it.
///
/// Reads the `href` and `action` attributes rather than searching the whole page for the text, so a
/// sign-out address mentioned in a comment or a script string is not mistaken for a control the
/// person can see. What it cannot tell is whether the control is *visible* — a link inside a
/// collapsed menu counts here — which is why finding one is worth no more than this.
fn points_at(body: &str, target: &str) -> bool {
    let matches = |value: &str| {
        let value = value.trim();
        value == target
            || value.trim_end_matches('/') == target.trim_end_matches('/')
            || value.split('?').next().is_some_and(|v| v == target)
    };
    tags(body, "a")
        .iter()
        .filter_map(|t| attribute(t, "href"))
        .any(|href| matches(&href))
        || tags(body, "form")
            .iter()
            .filter_map(|t| attribute(t, "action"))
            .any(|action| matches(&action))
}

fn sign_out_on_get_check(
    http: &mut dyn Http,
    users: &UsersSection,
    account: &Account,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    let (Some(confirm), Some(logout)) = (confirm, &users.logout) else {
        return;
    };
    let mut quiet = Vec::new();
    let Some(signed_in) = sign_in(http, users, "get-logout", account, &mut quiet) else {
        return;
    };
    if !ok(&http.send(&get(
        "private-before-get-logout",
        confirm,
        &signed_in.session,
    ))) {
        return;
    }
    let mut session = signed_in.session.clone();
    if let Some(response) = http.send(&get("logout-by-get", &logout.path, &session)) {
        session.absorb(&response);
    }
    // The session as it was, so a cookie the answer cleared in the browser does not count as the
    // session ending on the server.
    let ended = !ok(&http.send(&get(
        "private-after-get-logout",
        confirm,
        &signed_in.session,
    )));
    out.steps.push(format!(
        "visited {} as a plain page: {}",
        logout.path,
        if ended {
            "signed out"
        } else {
            "still signed in"
        }
    ));
    if ended {
        out.findings.push(finding(
            &SIGN_OUT_ON_GET,
            "Signing out happens on a plain page visit",
            Severity::Low,
            format!(
                "A GET to {}, with no form and no token, ended the session: afterwards {confirm} \
                 was refused.",
                logout.path
            ),
        ));
    }
}

/// Signing in with a few names and passwords somebody might leave in place.
///
/// Only ever a finding. Four tries show four accounts are not there, which is not the same as there
/// being none, so nothing is credited when they all fail.
fn default_account_check(
    http: &mut dyn Http,
    users: &UsersSection,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    let Some(confirm) = confirm else {
        return;
    };
    let mut opened = Vec::new();
    for (user, password) in DEFAULT_ACCOUNTS {
        let account = Account {
            user: (*user).to_owned(),
            password: (*password).to_owned(),
        };
        let mut quiet = Vec::new();
        if let Some(signed_in) = sign_in(http, users, "default", &account, &mut quiet)
            && ok(&http.send(&get("private-default", confirm, &signed_in.session)))
        {
            opened.push(format!("{user} / {password}"));
        }
    }
    out.steps.push(format!(
        "tried {} default accounts: {}",
        DEFAULT_ACCOUNTS.len(),
        if opened.is_empty() {
            "none signed in".to_owned()
        } else {
            opened.join(", ")
        }
    ));
    if !opened.is_empty() {
        out.findings.push(finding(
            &DEFAULT_ACCOUNT,
            "A default account can sign in",
            Severity::Critical,
            format!(
                "Signing in as {} worked and opened {confirm}.",
                opened.join(" and as ")
            ),
        ));
    }
}

/// Signing in with the password in the address rather than the body.
///
/// Only ever a finding: an app that refuses this has shown one address refuses it.
fn password_in_url_check(
    http: &mut dyn Http,
    users: &UsersSection,
    account: &Account,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    let (Some(confirm), Some(login)) = (confirm, &users.login) else {
        return;
    };
    if login.form.is_empty() || !login.method.eq_ignore_ascii_case("POST") {
        return;
    }
    let mut session = Session::default();
    let mut csrf = None;
    if let Some(page) = http.send(&get("login-page-url", &login.path, &session)) {
        session.absorb(&page);
        csrf = csrf_token(&page, &session);
    }
    let values = Values {
        user: &account.user,
        password: &account.password,
        csrf,
        ..Default::default()
    };
    let query: Vec<String> = login
        .form
        .iter()
        .map(|(k, v)| format!("{}={}", form_encode(k), form_encode(&fill(v, &values))))
        .collect();
    let path = format!(
        "{}{}{}",
        fill(&login.path, &values),
        if login.path.contains('?') { "&" } else { "?" },
        query.join("&")
    );
    let mut request = get("login-in-url", &path, &session);
    request.headers = session.headers();
    if let Some(response) = http.send(&request) {
        session.absorb(&response);
    }
    let works = ok(&http.send(&get("private-url", confirm, &session)));
    out.steps.push(format!(
        "signed in with the password in the address: {}",
        if works { "opened" } else { "refused" }
    ));
    if works {
        out.findings.push(finding(
            &PASSWORD_IN_URL,
            "The app accepts a password in the address",
            Severity::Medium,
            format!(
                "Sending the sign-in fields as a GET to {} signed the user in, so a password can \
                 arrive in the query string.",
                login.path
            ),
        ));
    }
}

/// At most how many bits of randomness a value could hold, from its length and the kinds of
/// character in it.
///
/// An upper bound, and meant as one: hex counted as letters and digits is credited with more than
/// it has. It can show an id too short to be unguessable; it can never show one is random.
fn most_bits(value: &str) -> f64 {
    let kinds = [
        (value.chars().any(|c| c.is_ascii_digit()), 10.0),
        (value.chars().any(|c| c.is_ascii_lowercase()), 26.0),
        (value.chars().any(|c| c.is_ascii_uppercase()), 26.0),
        (value.chars().any(|c| !c.is_ascii_alphanumeric()), 4.0),
    ];
    let alphabet: f64 = kinds.iter().filter(|(k, _)| *k).map(|(_, n)| n).sum();
    if alphabet < 2.0 {
        return 0.0;
    }
    value.chars().count() as f64 * alphabet.log2()
}

/// Whether the session id could be guessed: too short to hold 128 bits, or the same twice.
///
/// Only ever a finding. Length is necessary and far from sufficient; whether an id came from a
/// secure generator is not something its value shows, so a long one is credited with nothing.
fn session_id_check(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    a: &SignedIn,
    signed_in_works: bool,
    out: &mut Outcome,
) {
    if !signed_in_works || a.set_at_login.is_empty() {
        return;
    }
    let mut quiet = Vec::new();
    let Some(again) = sign_in(http, users, "a-again", &accounts.a, &mut quiet) else {
        return;
    };
    let mut problems = Vec::new();
    for first in &a.set_at_login {
        let bits = most_bits(&first.value);
        if bits < 128.0 {
            problems.push(format!(
                "`{}` is {} characters, room for at most {bits:.0} bits",
                first.name,
                first.value.chars().count()
            ));
        }
        if again
            .set_at_login
            .iter()
            .any(|c| c.name == first.name && c.value == first.value)
        {
            problems.push(format!(
                "`{}` had the same value at two separate sign-ins",
                first.name
            ));
        }
    }
    out.steps.push(format!(
        "compared the session cookies of two sign-ins: {}",
        if problems.is_empty() {
            "long enough and different"
        } else {
            "too short or repeated"
        }
    ));
    if !problems.is_empty() {
        out.findings.push(finding(
            &WEAK_SESSION_ID,
            "The session id could be guessed",
            Severity::High,
            problems.join("; "),
        ));
    }
}

fn session_checks(a: &SignedIn, signed_in_works: bool, out: &mut Outcome) {
    if a.session.bearer.is_some() && a.set_at_login.is_empty() {
        out.not_assessed.push((
            "V3.3.2, V3.3.4, V7.2.4".to_owned(),
            "Sign-in answered with a token rather than a cookie, so there is no session cookie to \
             judge."
                .to_owned(),
        ));
        return;
    }
    if !signed_in_works {
        out.not_assessed.push((
            "V3.3.2, V3.3.4, V7.2.4".to_owned(),
            "Nothing showed the signed-in session working — no private page opened for the signed-in \
             user alone, and no record was created and read back — so which cookie is the session \
             cannot be told."
                .to_owned(),
        ));
        return;
    }
    if a.set_at_login.is_empty() {
        if a.before_login.is_empty() {
            out.not_assessed.push((
                "V3.3.2, V3.3.4, V7.2.4".to_owned(),
                "Signing in set no cookie and none was set before it, so the session is carried \
                 some way this probe does not see."
                    .to_owned(),
            ));
        } else {
            // The session works and sign-in issued nothing: the cookie from before sign-in is now
            // the signed-in session. That is session fixation, whatever else is true.
            let names: Vec<&str> = a.before_login.iter().map(|(n, _)| n.as_str()).collect();
            out.findings.push(finding(
                &SESSION_RENEWAL,
                "Signing in does not issue a new session",
                Severity::High,
                format!(
                    "The app set {} before sign-in and nothing new at sign-in, and the old value \
                     then opened a signed-in page.",
                    names.join(", ")
                ),
            ));
        }
        return;
    }

    let mut problems = Vec::new();
    for c in &a.set_at_login {
        if !c.http_only {
            problems.push(format!(
                "`{}` can be read by any script on the page (no HttpOnly)",
                c.name
            ));
        }
        if c.same_site.is_none() {
            problems.push(format!(
                "`{}` does not say when it may travel to other sites (no SameSite)",
                c.name
            ));
        }
    }
    if problems.is_empty() {
        out.verified.push(crate::Verified::new(
            SESSION_COOKIE.rule_id,
            SESSION_COOKIE.requirement_ids,
            "every cookie the app set when a test user signed in".to_owned(),
        ));
    } else {
        out.findings.push(finding(
            &SESSION_COOKIE,
            "The session cookie is set without the attributes that protect it",
            Severity::High,
            problems.join("; "),
        ));
    }

    let kept: Vec<&str> = a
        .set_at_login
        .iter()
        .filter(|c| {
            a.before_login
                .iter()
                .any(|(n, v)| *n == c.name && *v == c.value)
        })
        .map(|c| c.name.as_str())
        .collect();
    if kept.is_empty() {
        out.verified.push(crate::Verified::new(
            SESSION_RENEWAL.rule_id,
            SESSION_RENEWAL.requirement_ids,
            "a sign-in by a test user, compared with the cookies given before it".to_owned(),
        ));
    } else {
        out.findings.push(finding(
            &SESSION_RENEWAL,
            "Signing in does not issue a new session",
            Severity::High,
            format!(
                "Sign-in set {} to the same value it had before sign-in.",
                kept.join(", ")
            ),
        ));
    }
}

fn admin_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    a: &SignedIn,
    out: &mut Outcome,
) {
    if users.admin.is_empty() {
        out.not_assessed.push((
            "V8.2.1".to_owned(),
            "Admin pages: securevibe.toml lists none under [stack.run.users] admin.".to_owned(),
        ));
        return;
    }
    let admin = accounts
        .admin
        .as_ref()
        .and_then(|account| sign_in(http, users, "admin", account, &mut out.steps));
    let mut refused_and_confirmed = 0;
    let mut opened_by_ordinary = Vec::new();
    let mut unconfirmed = Vec::new();
    for path in &users.admin {
        let as_a = http.send(&get("admin-a", path, &a.session));
        let as_admin = admin
            .as_ref()
            .map(|admin| http.send(&get("admin-admin", path, &admin.session)));
        let admin_opens = as_admin.as_ref().is_some_and(ok);
        if ok(&as_a) {
            // A 2xx to an ordinary user is a finding whether or not the admin was confirmed.
            opened_by_ordinary.push(path.clone());
        } else if admin_opens {
            refused_and_confirmed += 1;
        } else {
            unconfirmed.push(path.clone());
        }
    }
    if !opened_by_ordinary.is_empty() {
        out.findings.push(finding(
            &ADMIN_PAGE,
            "An ordinary user can open an admin page",
            Severity::High,
            format!(
                "Signed in as an ordinary test user, the app served {}.",
                opened_by_ordinary.join(", ")
            ),
        ));
    }
    if !unconfirmed.is_empty() {
        out.not_assessed.push((
            "V8.2.1".to_owned(),
            format!(
                "The admin account did not open {} either, so the ordinary user being refused says \
                 nothing: the page may not be where securevibe.toml says.",
                unconfirmed.join(", ")
            ),
        ));
    }
    if refused_and_confirmed > 0 && opened_by_ordinary.is_empty() {
        out.verified.push(crate::Verified::new(
            ADMIN_PAGE.rule_id,
            ADMIN_PAGE.requirement_ids,
            format!(
                "{refused_and_confirmed} admin page{}, refused to an ordinary user and opened by the admin",
                if refused_and_confirmed == 1 { "" } else { "s" }
            ),
        ));
    }
}

/// Returns the path of A's record when A could read it, for the logout check to reuse.
fn owned_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    a: &SignedIn,
    out: &mut Outcome,
) -> Option<String> {
    let Some(owned) = &users.owned else {
        out.not_assessed.push((
            "V8.2.2, V3.5.1".to_owned(),
            "Another user's records, and requests from another site: securevibe.toml lists no \
             `owned` record under [stack.run.users]."
                .to_owned(),
        ));
        return None;
    };
    let marker = "sv-probe-private-4c7e";
    let mut session = a.session.clone();
    let values = Values {
        marker,
        ..Default::default()
    };
    let (created, _) = send_template(
        http,
        "owned-create",
        &owned.create,
        &values,
        &mut session,
        &users.private,
    );
    let read_path = created.as_ref().and_then(|r| record_path(owned, r));
    let Some(read_path) = read_path.filter(|_| accepted(&created)) else {
        out.not_assessed.push((
            "V8.2.2, V3.5.1".to_owned(),
            format!(
                "Creating a record as the first user did not work ({}), or did not say where it \
                 went, so there is nothing to ask another user to read.",
                status(&created)
            ),
        ));
        return None;
    };
    let holds_marker =
        |r: &Option<ProbeResponse>| ok(r) && r.as_ref().is_some_and(|r| r.body.contains(marker));
    let as_a = http.send(&get("owned-a", &read_path, &session));
    if !holds_marker(&as_a) {
        out.not_assessed.push((
            "V8.2.2, V3.5.1".to_owned(),
            format!(
                "The first user could not read back the record they created at {read_path} ({}), \
                 so another user being refused it would prove nothing.",
                status(&as_a)
            ),
        ));
        return None;
    }
    out.steps.push(format!(
        "A created a record at {read_path} and read it back"
    ));
    // The record the owner is entitled to read is exactly the place to look for fields nobody
    // should be handed at all (V15.3.1). Read from the response already in hand.
    if let Some(body) = as_a.as_ref().map(|r| r.body.as_str()) {
        record_fields_check(body, &read_path, out);
    }

    let b = sign_in(http, users, "b", &accounts.b, &mut out.steps);
    let as_b = b
        .as_ref()
        .map(|b| http.send(&get("owned-b", &read_path, &b.session)));
    let as_nobody = http.send(&get("owned-anonymous", &read_path, &Session::default()));
    let mut leaked_to = Vec::new();
    if as_b.as_ref().is_some_and(&holds_marker) {
        leaked_to.push("another signed-in user");
    }
    if holds_marker(&as_nobody) {
        leaked_to.push("somebody not signed in");
    }
    if !leaked_to.is_empty() {
        out.findings.push(finding(
            &OTHER_USERS_DATA,
            "One user can read another user's records",
            Severity::Critical,
            format!(
                "A record the first test user created at {read_path} was served, with its contents, \
                 to {}.",
                leaked_to.join(" and to ")
            ),
        ));
    } else if b.is_some() {
        out.verified.push(crate::Verified::new(
            OTHER_USERS_DATA.rule_id,
            OTHER_USERS_DATA.requirement_ids,
            format!(
                "a record one test user created at {read_path}, refused to a second test user and to \
                 somebody not signed in, and read back by its owner"
            ),
        ));
    } else {
        out.not_assessed.push((
            "V8.2.2".to_owned(),
            "The second test user could not sign in, so whether they can read the first user's \
             record is unknown."
                .to_owned(),
        ));
    }

    forgery_check(http, owned, &session, a, out);
    Some(read_path)
}

/// Where a created record can be read: the `read` path with its id, or the `Location` it was sent to.
fn record_path(owned: &sv_manifest::OwnedSection, created: &ProbeResponse) -> Option<String> {
    let location = created
        .header("location")
        .map(|l| strip_origin(l).to_owned());
    match &owned.read {
        Some(read) if read.contains("{id}") => {
            let field = owned.id_field.as_deref().unwrap_or("id");
            let from_json = serde_json::from_str::<serde_json::Value>(&created.body)
                .ok()
                .and_then(|v| match v.get(field)? {
                    serde_json::Value::String(s) => Some(s.clone()),
                    serde_json::Value::Number(n) => Some(n.to_string()),
                    _ => None,
                });
            // Or the last part of where the app sent the browser: `/notes/7` gives 7.
            let from_location = location
                .as_deref()
                .and_then(|l| l.trim_end_matches('/').rsplit('/').next())
                .map(str::to_owned);
            let id = from_json.or(from_location)?;
            Some(read.replace("{id}", &id))
        }
        Some(read) => Some(read.clone()),
        None => location,
    }
}

fn strip_origin(location: &str) -> &str {
    match location.find("://") {
        Some(i) => {
            let rest = &location[i + 3..];
            rest.find('/').map_or("/", |j| &rest[j..])
        }
        None => location,
    }
}

fn forgery_check(
    http: &mut dyn Http,
    owned: &sv_manifest::OwnedSection,
    session: &Session,
    a: &SignedIn,
    out: &mut Outcome,
) {
    // The same request A just made, as a page on another site would make it: A's cookies go with
    // it (that is what a browser does), the Origin is somebody else's, and there is no token,
    // because another site cannot read one.
    let values = Values {
        marker: "sv-probe-forged-9b21",
        csrf: Some(String::new()),
        ..Default::default()
    };
    let mut forged = request("forged-create", &owned.create, &values, session);
    forged
        .headers
        .retain(|(n, _)| !n.to_lowercase().contains("csrf") && !n.to_lowercase().contains("xsrf"));
    forged
        .headers
        .push(("Origin".to_owned(), STRANGER.to_owned()));
    forged
        .headers
        .push(("Referer".to_owned(), format!("{STRANGER}/")));
    let response = http.send(&forged);
    if accepted(&response) {
        // SameSite on the session cookie means a browser would not have sent it from another site,
        // which is a real defense — but not the check V3.5.1 asks for, so it lowers the severity
        // rather than removing the finding.
        let protected_by_same_site = !a.set_at_login.is_empty()
            && a.set_at_login
                .iter()
                .all(|c| matches!(c.same_site.as_deref(), Some("lax") | Some("strict")));
        out.findings.push(finding(
            &FORGERY,
            "A request from another site is accepted",
            if protected_by_same_site {
                Severity::Medium
            } else {
                Severity::High
            },
            format!(
                "Creating a record was accepted ({}) when sent with the signed-in user's cookies, an \
                 Origin of {STRANGER} and no anti-forgery token.{}",
                status(&response),
                if protected_by_same_site {
                    " The session cookie's SameSite would stop a browser sending it from another \
                     site, which is why this is not rated higher."
                } else {
                    ""
                }
            ),
        ));
    } else {
        out.verified.push(crate::Verified::new(
            FORGERY.rule_id,
            FORGERY.requirement_ids,
            "a request that creates a record, sent with a signed-in user's cookies from another \
             origin and without a token, and refused"
                .to_owned(),
        ));
    }
}

fn logout_check(
    http: &mut dyn Http,
    users: &UsersSection,
    a: &SignedIn,
    confirm: Option<String>,
    out: &mut Outcome,
) {
    let Some(logout) = &users.logout else {
        out.not_assessed.push((
            "V7.4.1".to_owned(),
            "Whether signing out ends the session: securevibe.toml lists no `logout`.".to_owned(),
        ));
        return;
    };
    let Some(path) = confirm else {
        out.not_assessed.push((
            "V7.4.1".to_owned(),
            "Whether signing out ends the session: nothing showed the session working in the first \
             place, so its ending would show nothing."
                .to_owned(),
        ));
        return;
    };
    let before = a.session.clone();
    let mut session = a.session.clone();
    let pages: Vec<String> = users
        .private
        .iter()
        .cloned()
        .chain(users.owned.as_ref().map(|o| o.create.path.clone()))
        .collect();
    let (response, _) = send_template(
        http,
        "logout",
        logout,
        &Values::default(),
        &mut session,
        &pages,
    );
    out.steps
        .push(format!("A signed out ({})", status(&response)));
    clear_site_data_check(response.as_ref(), &logout.path, out);
    // A sign-out the app refused has ended nothing, and the session still working afterwards would
    // then be blamed on the app. The same setup rule as everywhere else: show the thing happened.
    if !accepted(&response) {
        out.not_assessed.push((
            "V7.4.1".to_owned(),
            format!(
                "Whether signing out ends the session: the sign-out request itself was refused ({}), \
                 so there was no sign-out to test. Check `logout` in securevibe.toml.",
                status(&response)
            ),
        ));
        return;
    }
    // The copy kept from before logout, as somebody who had copied the cookie would use it.
    let replay = http.send(&get("after-logout", &path, &before));
    if ok(&replay) {
        out.findings.push(finding(
            &LOGOUT,
            "Signing out does not end the session",
            Severity::High,
            format!("After signing out, the old session still opened {path}."),
        ));
    } else {
        out.verified.push(crate::Verified::new(
            LOGOUT.rule_id,
            LOGOUT.requirement_ids,
            format!("the session from before sign-out, sent again to {path} and refused"),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A small app, run in memory, with every flaw this suite looks for switchable.
    ///
    /// Sessions are server-side and named by a random-looking counter; notes belong to whoever made
    /// them. Each flag turns one protection off, so each rule can be shown to fire when its thing is
    /// broken and to stay quiet when it is not.
    #[derive(Default)]
    struct FakeApp {
        flaws: Flaws,
        /// Seconds a signed-in session may go unused, when this app ends idle sessions at all.
        idle_limit: Option<u64>,
        /// Seconds a signed-in session may last, when this app limits that at all.
        lifetime_limit: Option<u64>,
        /// Per session: when it was first seen signed in, and when it was last used.
        session_times: BTreeMap<String, (u64, u64)>,
        /// Whether `window_rolls_over_at_first_claim` has rolled over.
        leaked_once: bool,
        /// From this moment on the clock, every sign-in is refused, as by an app that went down.
        sign_ins_refused_from: Option<u64>,
        /// Signing in ends every other session of the same user.
        one_session_per_user: bool,
        /// Two-factor secrets, by user.
        totp: BTreeMap<String, Vec<u8>>,
        /// Sessions past the password and waiting for a code: session id -> user.
        pending: BTreeMap<String, String>,
        /// The last time step each user's code was accepted for.
        totp_last: BTreeMap<String, u64>,
        /// Wrong codes given, by user, for `totp_locks`.
        totp_wrong: BTreeMap<String, u32>,
        /// The app's clock, in seconds since 1970. Waiting moves it on rather than sleeping.
        clock: u64,
        /// How far each user has got through the checkout.
        checkout: BTreeMap<String, u32>,
        users: BTreeMap<String, (String, bool)>, // user -> (password, is admin)
        sessions: BTreeMap<String, String>,      // session id -> user ("" = not signed in)
        notes: Vec<(String, String)>,            // (owner, text)
        next: u32,
        /// Old passwords a change left working, under `change_keeps_old`.
        kept: BTreeMap<String, String>,
        /// What `Clear-Site-Data` the sign-out sends, when `clears_site_data` is set. `None` is
        /// the correct value covering storage.
        clear_site_data_value: Option<String>,
        /// Files the app has taken, by name.
        uploads: BTreeMap<String, String>,
        /// The largest file body the app was sent, accepted or not. This is how the size cap's
        /// promise is made observable: the promise is about what is sent, and no finding says it.
        largest_upload: usize,
        /// Wrong passwords in a row per account, counted only when `locks_out_after` is set.
        failures: BTreeMap<String, u32>,
        /// Every account a wrong password was tried against, always recorded. This is how the
        /// brute-force check's promise not to guess at the test users is made observable: the
        /// promise is about which account it attacks, and no step or finding says which.
        guessed_at: Vec<String>,
        /// The exact `Cache-Control` a private page sends. `None` means the correct `no-store`,
        /// so a test can set a value that only looks right without a flaw flag for each one.
        cache_control: Option<String>,
        /// Every email the app has sent, as (to, text), oldest first.
        outbox: Vec<(String, String)>,
        /// Reset codes handed out: code -> (account, used).
        reset_codes: BTreeMap<String, (String, bool)>,
        /// Sign-in codes handed out: code -> (account, the session that asked, used).
        sign_in_codes: BTreeMap<String, (String, String, bool)>,
        /// Wrong sign-in codes per session.
        code_failures: BTreeMap<String, u32>,
    }

    /// The fake app's own context-specific word, as an owner would list it in `context-words`.
    const CONTEXT_WORD: &str = "acmenotes";

    #[derive(Default, Clone, Copy)]
    struct Flaws {
        private_open: bool,
        admin_open: bool,
        /// Any signed-in user can read any record.
        idor: bool,
        /// Anybody at all can read any record.
        records_public: bool,
        no_csrf_check: bool,
        keep_session_at_login: bool,
        logout_keeps_session: bool,
        no_httponly: bool,
        broken_login: bool,
        /// Sign-up takes a password shorter than 8 characters.
        short_password_ok: bool,
        /// Sign-up takes a password from the common list.
        common_password_ok: bool,
        /// Sign-up takes a password from far down the common list.
        breached_password_ok: bool,
        /// Any step of the checkout can be taken first.
        flow_unguarded: bool,
        /// The last step of the checkout needs the first, and not the one between.
        flow_checks_first_only: bool,
        /// A refused checkout step says "Order placed" in its refusal.
        flow_refusal_says_placed: bool,
        /// The checkout's last step never finishes, even in order.
        flow_broken: bool,
        /// A refused checkout step sends the browser back to the first step, as many apps do.
        flow_refusal_redirects: bool,
        /// A two-factor code can be used again.
        totp_reusable: bool,
        /// A two-factor code from any of the last ten steps is accepted.
        totp_any_age: bool,
        /// The password alone signs a two-factor account all the way in.
        totp_not_required: bool,
        /// A second wrong two-factor code locks the account's codes.
        totp_locks: bool,
        /// The first wrong two-factor code locks the account's codes.
        totp_locks_at_once: bool,
        /// No two-factor code is ever accepted.
        totp_broken: bool,
        /// Sign-up takes a password containing the app's context word.
        context_word_ok: bool,
        /// Sign-up wants a capital and a digit in every password.
        composition_rules: bool,
        /// `admin` / `admin` is an account.
        default_admin: bool,
        /// A GET to /login with the fields in the query string signs in.
        password_in_url: bool,
        /// Session ids are a short counter.
        short_session_ids: bool,
        /// Sign-up refuses everybody.
        signup_closed: bool,
        /// Each user gets the same long session id every time they sign in.
        same_session_id: bool,
        /// Sign-up wants at least 16 characters.
        long_minimum: bool,
        /// Sign-up answers as if it worked and makes no account.
        signup_does_nothing: bool,
        /// Passwords are compared with their case folded.
        case_folded: bool,
        /// Passwords are compared on their first 72 characters, as bcrypt does.
        cut_at_72: bool,
        /// Sign-up refuses a password longer than 64 characters.
        longest_64: bool,
        /// The password fields are ordinary text fields.
        password_shown: bool,
        /// The password fields refuse a paste.
        paste_blocked: bool,
        /// The pages carry no password field in their HTML: a form built by script.
        no_form_in_html: bool,
        /// A GET to /logout ends the session.
        logout_on_get: bool,
        /// A password change does not check the current password.
        change_without_current: bool,
        /// A password change adds the new password and leaves the old one working.
        change_keeps_old: bool,
        /// A password change answers as if it worked and changes nothing.
        change_does_nothing: bool,
        /// The new-password field of the change page alone is an ordinary text field.
        new_field_shown: bool,
        /// Deleting an account leaves its other sessions working.
        deletion_keeps_sessions: bool,
        /// Deleting an account answers as if it worked and deletes nothing.
        delete_does_nothing: bool,
        /// Sign-up asks for the answer to a secret question.
        secret_question: bool,
        /// Takes a file larger than the stated limit.
        oversized_upload_ok: bool,
        /// Takes a .gif whose contents are not a GIF.
        unchecked_contents_ok: bool,
        /// Runs an uploaded .php when it is fetched back, serving its output instead of its source.
        runs_uploaded_code: bool,
        /// Serves an uploaded .html as text/html with nothing telling the browser not to render it.
        renders_uploaded_pages: bool,
        /// Serves an uploaded file back with no file name in `Content-Disposition`.
        download_no_filename: bool,
        /// Writes the uploaded name into `Content-Disposition` as it came in, unquoted.
        download_name_raw: bool,
        /// Quotes the uploaded name but does not clean it. Not a fault: a `;` inside a quoted
        /// string is part of the name, and this is here so a check that split on it would be
        /// caught accusing a correct app.
        download_name_quoted_uncleaned: bool,
        /// Accepts a session cookie it never issued.
        session_not_verified: bool,
        /// The sign-up form states maxlength, and the server does not apply it.
        validation_only_in_browser: bool,
        /// A record is handed back with the owner's password hash in it.
        record_leaks_fields: bool,
        /// Signing out sends Clear-Site-Data.
        clears_site_data: bool,
        /// Refuses every upload, whatever it is. An app whose upload path does not work as
        /// securevibe.toml describes, which must read as *not assessed* and never as four passes.
        upload_broken: bool,
        /// Refuses sign-in with 429 once an account has this many failures in a row. `None` — the
        /// default, and what a naive app does — counts nothing and accepts guesses forever.
        locks_out_after: Option<u32>,
        /// `locks_out_after` counts wrong passwords by the client's address, not by account.
        limits_by_address: bool,
        /// The client's address is read from `X-Forwarded-For` when a request carries one.
        trusts_forwarded_for: bool,
        /// A lockout lasts for one refused attempt and then lifts by itself.
        lockout_forgets: bool,
        /// Each refusal lets the next attempt through: one attempt per refusal, as a token bucket, a
        /// sliding window, or `nginx limit_req` does, whatever it thinks about addresses.
        lockout_leaks: bool,
        /// The limit's window rolls over once, just as the first attempt claiming another address
        /// arrives: that attempt gets through whatever the header says, and nothing after it does.
        /// Timing a real limiter can produce by chance.
        window_rolls_over_at_first_claim: bool,
        /// Answers a wrong password with this status from the very first attempt, as an app whose
        /// address-based limiter an earlier check has already tripped would. Correct sign-ins
        /// still work, because the suite has to reach the brute-force check for this to be the
        /// case under test at all. A status rather than a flag: a guard written for 429 alone
        /// leaves 423 and a dropped connection crediting the requirement, and one witness cannot
        /// tell those apart.
        already_refusing: Option<u16>,
        /// Private pages come back without `Cache-Control: no-store`.
        private_page_cacheable: bool,
        /// Private pages carry no link or form pointing at the sign-out address — but do name it
        /// in a script, which is what a page built by JavaScript looks like and what a check
        /// searching the whole page for the text would wrongly credit.
        no_sign_out_link: bool,
        /// The run has no mail server, so there is no email to read.
        no_mail_sink: bool,
        /// A reset request answers but sends no email.
        reset_sends_nothing: bool,
        /// Using a reset code answers as if it worked and changes nothing.
        reset_does_nothing: bool,
        /// A reset code can be used again after it has been used.
        reset_reusable: bool,
        /// A reset adds the new password and leaves the old one working.
        reset_keeps_old: bool,
        /// Reset codes are four digits.
        reset_short_code: bool,
        /// Reset codes are six digits, one more than the last.
        reset_counting_codes: bool,
        /// A reset for an address with no account is answered 404.
        reset_reveals_by_status: bool,
        /// A reset for an address with no account is answered in different words.
        reset_reveals_by_words: bool,
        /// The reset email carries its code where the default patterns do not look.
        reset_code_elsewhere: bool,
        /// Every reset answer says how many have been asked for, so two identical requests are
        /// answered differently. Not a fault: it is here so a comparison that forgot to check the
        /// two alike answers first would accuse a correct app.
        reset_answer_counts: bool,
        /// A sign-in code can be used again after it has signed in.
        code_reusable: bool,
        /// A sign-in code works in any session, not only the one that asked for it.
        code_unbound: bool,
        /// Sign-in codes are four digits.
        code_short: bool,
        /// Wrong sign-in codes are never counted.
        code_guessing_unlimited: bool,
        /// A session is locked after its first wrong code, rather than its third.
        code_locks_after_one: bool,
        /// Using a sign-in code answers as if it worked and signs nobody in.
        code_does_nothing: bool,
        /// Asking for a sign-in code answers and sends no email.
        code_sends_nothing: bool,
        /// The sign-in-by-code forms carry no anti-forgery token, so nothing makes the probe open
        /// their pages. Not a fault.
        code_no_csrf: bool,
        /// Past the limit, wrong codes are answered as before and the code is quietly cancelled:
        /// the only sign of pushing back is that the right code no longer works. Not a fault.
        code_cancels_quietly: bool,
        /// Every wrong code is answered 429 from the first, as an app whose limiter an earlier
        /// check has tripped would.
        code_already_refusing: bool,
    }

    const CSRF: &str = "tok-123";
    /// The largest file this fake app takes, matching the max-bytes the tests state.
    const UPLOAD_LIMIT: usize = 4096;

    impl FakeApp {
        fn new(flaws: Flaws) -> Self {
            let mut app = FakeApp {
                flaws,
                clock: 1_700_000_010,
                ..Default::default()
            };
            if flaws.default_admin {
                app.users.insert("admin".into(), ("admin".into(), true));
            }
            app
        }

        fn new_id(&mut self) -> String {
            self.next += 1;
            if self.flaws.short_session_ids {
                return format!("s{:04}x{}", self.next * 7919, self.next);
            }
            let n = u64::from(self.next);
            format!(
                "{:016x}{:016x}",
                n.wrapping_mul(0x9E37_79B9_7F4A_7C15),
                n.wrapping_mul(0xC2B2_AE3D_27D4_EB4F)
            )
        }

        /// A new session for this user, answered the way POST /login answers.
        fn signed_in(&mut self, who: String) -> ProbeResponse {
            if self.one_session_per_user {
                self.sessions.retain(|_, u| *u != who);
            }
            let id = if self.flaws.same_session_id {
                let n = who.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
                    (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
                });
                format!("{n:016x}{:016x}", n.rotate_left(17))
            } else {
                self.new_id()
            };
            self.sessions.insert(id.clone(), who);
            let attrs = self.cookie_attrs();
            Self::respond(
                303,
                vec![
                    ("Location", "/account".into()),
                    ("Set-Cookie", format!("sid={id}; {attrs}")),
                ],
                "",
            )
        }

        fn totp_is_locked(&self, who: &str) -> bool {
            let wrong = self.totp_wrong.get(who).copied().unwrap_or(0);
            (self.flaws.totp_locks && wrong >= 2) || (self.flaws.totp_locks_at_once && wrong >= 1)
        }

        fn password_matches(&self, stored: &str, given: &str) -> bool {
            let fold = |p: &str| {
                let p: String = if self.flaws.cut_at_72 {
                    p.chars().take(72).collect()
                } else {
                    p.to_owned()
                };
                if self.flaws.case_folded {
                    p.to_lowercase()
                } else {
                    p
                }
            };
            fold(stored) == fold(given)
        }

        /// The password field as the sign-in and sign-up pages serve it.
        fn password_input(&self) -> String {
            self.password_input_named("password")
        }

        /// A password field of this name, with whatever flaws are switched on.
        fn password_input_named(&self, name: &str) -> String {
            if self.flaws.no_form_in_html {
                return String::new();
            }
            format!(
                "<input type=\"{}\" name=\"{name}\"{}>",
                if self.flaws.password_shown {
                    "text"
                } else {
                    "password"
                },
                if self.flaws.paste_blocked {
                    " onpaste=\"return false\""
                } else {
                    ""
                }
            )
        }

        fn password_allowed(&self, password: &str) -> bool {
            if self.flaws.longest_64 && password.chars().count() > 64 {
                return false;
            }
            if password.chars().count() < 8 && !self.flaws.short_password_ok {
                return false;
            }
            if self.flaws.long_minimum && password.chars().count() < 16 {
                return false;
            }
            if password == COMMON && !self.flaws.common_password_ok {
                return false;
            }
            if password == BREACHED && !self.flaws.breached_password_ok {
                return false;
            }
            if password.to_ascii_lowercase().contains(CONTEXT_WORD) && !self.flaws.context_word_ok {
                return false;
            }
            if self.flaws.composition_rules
                && !(password.chars().any(|c| c.is_ascii_uppercase())
                    && password.chars().any(|c| c.is_ascii_digit()))
            {
                return false;
            }
            true
        }

        fn cookie_attrs(&self) -> &'static str {
            if self.flaws.no_httponly {
                "Path=/; SameSite=Lax"
            } else {
                "Path=/; HttpOnly; SameSite=Lax"
            }
        }

        fn respond(status: u16, headers: Vec<(&str, String)>, body: &str) -> ProbeResponse {
            ProbeResponse {
                id: String::new(),
                status,
                headers: headers
                    .into_iter()
                    .map(|(k, v)| (k.to_lowercase(), v))
                    .collect(),
                body: body.to_owned(),
            }
        }
    }

    fn cookie_value(request: &ProbeRequest, name: &str) -> Option<String> {
        let line = request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))?
            .1
            .clone();
        line.split("; ").find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            (k == name).then(|| v.to_owned())
        })
    }

    fn decode(text: &str) -> String {
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'+' => out.push(b' '),
                b'%' if i + 2 < bytes.len() => {
                    let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                    match u8::from_str_radix(hex, 16) {
                        Ok(b) => {
                            out.push(b);
                            i += 2;
                        }
                        Err(_) => out.push(b'%'),
                    }
                }
                b => out.push(b),
            }
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn pairs(text: &str) -> BTreeMap<String, String> {
        text.split('&')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (decode(k), decode(v)))
            .collect()
    }

    fn form(request: &ProbeRequest) -> BTreeMap<String, String> {
        pairs(request.body.as_deref().unwrap_or(""))
    }

    impl Http for FakeApp {
        fn now(&mut self) -> u64 {
            self.clock
        }

        fn wait(&mut self, seconds: u64) {
            self.clock += seconds;
        }

        fn mail(&mut self, to: &str, _at_least: usize) -> Option<Vec<String>> {
            if self.flaws.no_mail_sink {
                return None;
            }
            Some(
                self.outbox
                    .iter()
                    .filter(|(who, _)| who == to)
                    .map(|(_, text)| text.clone())
                    .collect(),
            )
        }

        fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
            // A bearer token is a session id too, for the JSON sign-in below.
            let bearer = r
                .headers
                .iter()
                .find(|(k, _)| k == "Authorization")
                .and_then(|(_, v)| v.strip_prefix("Bearer "))
                .map(str::to_owned);
            let sid = bearer.or_else(|| cookie_value(r, "sid"));
            // The session timeouts, when this app keeps any: a signed-in session is ended here if
            // it has been unused, or alive, too long; otherwise its last use is now.
            if let Some(s) = sid.as_ref()
                && self.sessions.get(s).is_some_and(|u| !u.is_empty())
            {
                let now = self.clock;
                let (began, last) = *self.session_times.entry(s.clone()).or_insert((now, now));
                let idle_over = self.idle_limit.is_some_and(|limit| now - last > limit);
                let life_over = self.lifetime_limit.is_some_and(|limit| now - began > limit);
                if idle_over || life_over {
                    self.sessions.remove(s);
                    self.session_times.remove(s);
                } else if let Some(times) = self.session_times.get_mut(s) {
                    times.1 = now;
                }
            }
            let user = sid
                .as_ref()
                .and_then(|s| self.sessions.get(s))
                .filter(|u| !u.is_empty())
                .cloned()
                // A session id is normally looked up; under this flaw any non-empty one is
                // believed, which is what an app that never checks the cookie does.
                .or_else(|| {
                    (self.flaws.session_not_verified
                        && sid.as_deref().is_some_and(|s| !s.is_empty()))
                    .then(|| "believed@example.test".to_owned())
                });
            let foreign = r
                .headers
                .iter()
                .any(|(k, v)| k == "Origin" && v == STRANGER);
            let token_ok = form(r).get("csrf_token").map(String::as_str) == Some(CSRF);
            let is_admin = user
                .as_ref()
                .is_some_and(|u| self.users.get(u).is_some_and(|(_, admin)| *admin));
            let (path, query) = match r.path.split_once('?') {
                Some((p, q)) => (p.to_owned(), pairs(q)),
                None => (r.path.clone(), BTreeMap::new()),
            };
            if self.flaws.password_in_url
                && r.method == "GET"
                && path == "/login"
                && let (Some(email), Some(password)) = (query.get("email"), query.get("password"))
                && self.users.get(email).is_some_and(|(p, _)| p == password)
            {
                return Some(self.signed_in(email.clone()));
            }
            Some(match (r.method.as_str(), path.as_str()) {
                ("GET", "/login") => {
                    let id = self.new_id();
                    self.sessions.insert(id.clone(), String::new());
                    let attrs = self.cookie_attrs();
                    Self::respond(
                        200,
                        vec![("Set-Cookie", format!("sid={id}; {attrs}"))],
                        &format!(
                            "<form><input type=\"hidden\" name=\"csrf_token\" value=\"{CSRF}\">{}</form>",
                            self.password_input()
                        ),
                    )
                }
                ("POST", "/login") => {
                    let f = form(r);
                    let given = f.get("password")?;
                    let email = f.get("email")?;
                    let address = r
                        .headers
                        .iter()
                        .find(|(k, _)| {
                            self.flaws.trusts_forwarded_for
                                && k.eq_ignore_ascii_case("x-forwarded-for")
                        })
                        .map_or("127.0.0.1".to_owned(), |(_, v)| v.clone());
                    let key = if self.flaws.limits_by_address {
                        address
                    } else {
                        email.clone()
                    };
                    // The window rolling over lets exactly one more attempt in.
                    if self.flaws.window_rolls_over_at_first_claim
                        && !self.leaked_once
                        && r.headers
                            .iter()
                            .any(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-for"))
                        && let Some(limit) = self.flaws.locks_out_after
                        && let Some(count) = self.failures.get_mut(&key)
                    {
                        self.leaked_once = true;
                        *count = (*count).min(limit.saturating_sub(1));
                    }
                    if let Some(limit) = self.flaws.locks_out_after
                        && self.failures.get(&key).copied().unwrap_or(0) >= limit
                    {
                        if self.flaws.lockout_forgets {
                            self.failures.remove(&key);
                        }
                        if self.flaws.lockout_leaks
                            && let Some(count) = self.failures.get_mut(&key)
                        {
                            // One attempt through for every one refused, as a token bucket does.
                            *count -= 1;
                        }
                        return Some(Self::respond(429, vec![], "too many attempts"));
                    }
                    let good = !self.flaws.broken_login
                        && self
                            .sign_ins_refused_from
                            .is_none_or(|from| self.clock < from)
                        && (self
                            .users
                            .get(email)
                            .is_some_and(|(p, _)| self.password_matches(p, given))
                            || self.kept.get(email) == Some(given));
                    if !good || !token_ok {
                        self.guessed_at.push(email.clone());
                        if let Some(status) = self.flaws.already_refusing {
                            return Some(Self::respond(status, vec![], "too many attempts"));
                        }
                        if self.flaws.locks_out_after.is_some() {
                            *self.failures.entry(key).or_insert(0) += 1;
                        }
                        return Some(Self::respond(403, vec![], "no"));
                    }
                    self.failures.remove(&key);
                    let who = f.get("email")?.clone();
                    if self.totp.contains_key(&who) && !self.flaws.totp_not_required {
                        let id = self.new_id();
                        self.sessions.insert(id.clone(), String::new());
                        self.pending.insert(id.clone(), who);
                        let attrs = self.cookie_attrs();
                        return Some(Self::respond(
                            200,
                            vec![("Set-Cookie", format!("sid={id}; {attrs}"))],
                            "enter the code from your app",
                        ));
                    }
                    if self.flaws.keep_session_at_login {
                        self.sessions.insert(sid?, who);
                        return Some(Self::respond(
                            303,
                            vec![("Location", "/account".into())],
                            "",
                        ));
                    }
                    self.signed_in(who)
                }
                ("GET", "/signup") => Self::respond(
                    200,
                    vec![],
                    &format!(
                        "<input type=hidden name=csrf_token value={CSRF}><input name=email maxlength=40>{}{}",
                        self.password_input(),
                        if self.flaws.secret_question {
                            "<label>Favorite teacher <input name=security_answer></label>"
                        } else {
                            ""
                        }
                    ),
                ),
                ("GET", "/password") => match user {
                    Some(_) => Self::respond(
                        200,
                        vec![],
                        &format!(
                            "<input type=hidden name=csrf_token value={CSRF}>{}{}",
                            self.password_input_named("current"),
                            if self.flaws.new_field_shown {
                                "<input type=\"text\" name=\"new\">".to_owned()
                            } else {
                                self.password_input_named("new")
                            }
                        ),
                    ),
                    None => Self::respond(302, vec![("Location", "/login".into())], ""),
                },
                ("POST", "/password") => {
                    let Some(who) = user else {
                        return Some(Self::respond(302, vec![("Location", "/login".into())], ""));
                    };
                    if !token_ok {
                        return Some(Self::respond(403, vec![], "refused"));
                    }
                    let f = form(r);
                    let (current, new) = (f.get("current")?.clone(), f.get("new")?.clone());
                    let stored = self.users.get(&who)?.0.clone();
                    if !self.flaws.change_without_current
                        && !self.password_matches(&stored, &current)
                    {
                        return Some(Self::respond(403, vec![], "wrong password"));
                    }
                    if !self.flaws.change_does_nothing {
                        if self.flaws.change_keeps_old {
                            self.kept.insert(who.clone(), stored);
                        }
                        self.users.get_mut(&who)?.0 = new;
                    }
                    Self::respond(303, vec![("Location", "/account".into())], "")
                }
                ("GET", "/login/code" | "/login/verify") => {
                    // A session for the code to be tied to, unless the browser already has one.
                    let mut headers = vec![];
                    if !sid.as_ref().is_some_and(|s| self.sessions.contains_key(s)) {
                        let id = self.new_id();
                        self.sessions.insert(id.clone(), String::new());
                        let attrs = self.cookie_attrs();
                        headers.push(("Set-Cookie", format!("sid={id}; {attrs}")));
                    }
                    Self::respond(
                        200,
                        headers,
                        &format!("<input type=hidden name=csrf_token value={CSRF}>"),
                    )
                }
                ("POST", "/login/code") => {
                    if !token_ok && !self.flaws.code_no_csrf {
                        return Some(Self::respond(403, vec![], "refused"));
                    }
                    let email = form(r).get("email")?.clone();
                    if self.users.contains_key(&email) && !self.flaws.code_sends_nothing {
                        self.next += 1;
                        let n = u64::from(self.next).wrapping_mul(7_919 * 104_729);
                        let code = if self.flaws.code_short {
                            format!("{:04}", n % 10_000)
                        } else {
                            format!("{:06}", n % 1_000_000)
                        };
                        self.sign_in_codes.insert(
                            code.clone(),
                            (email.clone(), sid.clone().unwrap_or_default(), false),
                        );
                        self.outbox.push((
                            email,
                            format!("Your sign-in code is {code}. It works once, in this browser."),
                        ));
                    }
                    Self::respond(
                        200,
                        vec![],
                        "If that address has an account, we sent a code.",
                    )
                }
                ("POST", "/login/verify") => {
                    if !token_ok && !self.flaws.code_no_csrf {
                        return Some(Self::respond(403, vec![], "refused"));
                    }
                    let session = sid.clone().unwrap_or_default();
                    let limit = if self.flaws.code_locks_after_one {
                        1
                    } else {
                        3
                    };
                    let failures = self.code_failures.get(&session).copied().unwrap_or(0);
                    let code = form(r).get("code")?.clone();
                    if failures >= limit && !self.flaws.code_guessing_unlimited {
                        if self.flaws.code_cancels_quietly {
                            self.sign_in_codes
                                .retain(|_, (_, asked, _)| *asked != session);
                            *self.code_failures.entry(session).or_insert(0) += 1;
                            return Some(Self::respond(401, vec![], "that code does not work"));
                        }
                        return Some(Self::respond(429, vec![], "ask for a new code"));
                    }
                    if self.flaws.code_already_refusing && !self.sign_in_codes.contains_key(&code) {
                        return Some(Self::respond(429, vec![], "slow down"));
                    }
                    let good = self
                        .sign_in_codes
                        .get(&code)
                        .cloned()
                        .filter(|(_, asked, used)| {
                            (*asked == session || self.flaws.code_unbound)
                                && (!used || self.flaws.code_reusable)
                        });
                    let Some((who, asked, _)) = good else {
                        *self.code_failures.entry(session).or_insert(0) += 1;
                        return Some(Self::respond(401, vec![], "that code does not work"));
                    };
                    self.sign_in_codes.insert(code, (who.clone(), asked, true));
                    if !self.flaws.code_does_nothing && !session.is_empty() {
                        self.sessions.insert(session, who);
                    }
                    Self::respond(303, vec![("Location", "/account".into())], "")
                }
                ("GET", "/forgot" | "/reset") => Self::respond(
                    200,
                    vec![],
                    &format!("<input type=hidden name=csrf_token value={CSRF}>"),
                ),
                ("POST", "/forgot") => {
                    if !token_ok {
                        return Some(Self::respond(403, vec![], "refused"));
                    }
                    let email = form(r).get("email")?.clone();
                    let known = self.users.contains_key(&email);
                    if known && !self.flaws.reset_sends_nothing {
                        self.next += 1;
                        let code = if self.flaws.reset_short_code {
                            format!("{:04}", (self.next * 7919) % 10_000)
                        } else if self.flaws.reset_counting_codes {
                            format!("{}", 100_000 + self.next)
                        } else {
                            self.new_id()
                        };
                        self.reset_codes
                            .insert(code.clone(), (email.clone(), false));
                        let text = if self.flaws.reset_code_elsewhere {
                            format!("Your reset number is {code}. Type it on the reset page.")
                        } else {
                            format!(
                                "Hello,\r\nReset your password: http://app:8080/reset?token={code}\r\n"
                            )
                        };
                        self.outbox.push((email.clone(), text));
                    }
                    // A field that differs on every answer, as a real form's token does, so the
                    // comparison is shown to set it aside.
                    // Short, so it is the field's value being set aside that saves the comparison and
                    // not the rule for long random-looking runs.
                    self.next += 1;
                    let nonce = format!("{:08x}", self.next.wrapping_mul(2_654_435_761));
                    let hidden = format!("<input type=hidden name=nonce value={nonce}>");
                    if !known && self.flaws.reset_reveals_by_status {
                        return Some(Self::respond(404, vec![], "no such account"));
                    }
                    let words = if !known && self.flaws.reset_reveals_by_words {
                        format!("There is no account for {email}.")
                    } else if self.flaws.reset_reveals_by_words {
                        format!("We have sent a link to {email}.")
                    } else {
                        format!("If {email} has an account, we have sent it a link.")
                    };
                    let count = if self.flaws.reset_answer_counts {
                        format!("<p>Request {} today.</p>", self.next)
                    } else {
                        String::new()
                    };
                    Self::respond(200, vec![], &format!("{hidden}<p>{words}</p>{count}"))
                }
                ("POST", "/reset") => {
                    if !token_ok {
                        return Some(Self::respond(403, vec![], "refused"));
                    }
                    let f = form(r);
                    let (code, new) = (f.get("token")?.clone(), f.get("password")?.clone());
                    let Some((who, used)) = self.reset_codes.get(&code).cloned() else {
                        return Some(Self::respond(400, vec![], "unknown link"));
                    };
                    if used && !self.flaws.reset_reusable {
                        return Some(Self::respond(400, vec![], "this link has been used"));
                    }
                    self.reset_codes.insert(code, (who.clone(), true));
                    if !self.flaws.reset_does_nothing {
                        let stored = self.users.get(&who)?.0.clone();
                        if self.flaws.reset_keeps_old {
                            self.kept.insert(who.clone(), stored);
                        }
                        self.users.get_mut(&who)?.0 = new;
                    }
                    Self::respond(303, vec![("Location", "/login".into())], "")
                }
                ("POST", "/account/delete") => {
                    let Some(who) = user else {
                        return Some(Self::respond(302, vec![("Location", "/login".into())], ""));
                    };
                    let f = form(r);
                    let stored = self.users.get(&who)?.0.clone();
                    if !token_ok || !self.password_matches(&stored, f.get("password")?) {
                        return Some(Self::respond(403, vec![], "refused"));
                    }
                    if !self.flaws.delete_does_nothing {
                        self.users.remove(&who);
                        if self.flaws.deletion_keeps_sessions {
                            if let Some(s) = sid {
                                self.sessions.remove(&s);
                            }
                        } else {
                            self.sessions.retain(|_, u| *u != who);
                        }
                    }
                    Self::respond(303, vec![("Location", "/".into())], "")
                }
                ("GET", "/logout") if self.flaws.logout_on_get => {
                    if let Some(s) = sid {
                        self.sessions.remove(&s);
                    }
                    Self::respond(303, vec![("Location", "/".into())], "")
                }
                ("POST", "/signup") => {
                    if !token_ok {
                        return Some(Self::respond(403, vec![], "refused"));
                    }
                    let f = form(r);
                    let (email, password) = (f.get("email")?.clone(), f.get("password")?.clone());
                    // The form says maxlength=40. A correct app applies that again here.
                    if email.chars().count() > 40 && !self.flaws.validation_only_in_browser {
                        return Some(Self::respond(422, vec![], "too long"));
                    }
                    if self.flaws.signup_closed || !self.password_allowed(&password) {
                        return Some(Self::respond(422, vec![], "password refused"));
                    }
                    if !self.flaws.signup_does_nothing {
                        self.users.insert(email, (password, false));
                    }
                    Self::respond(303, vec![("Location", "/login".into())], "")
                }
                ("POST", "/api/login") => {
                    let body: serde_json::Value =
                        serde_json::from_str(r.body.as_deref().unwrap_or("")).ok()?;
                    let email = body.get("email")?.as_str()?.to_owned();
                    let password = body.get("password")?.as_str()?.to_owned();
                    let good = self.users.get(&email).is_some_and(|(p, _)| *p == password);
                    if !good {
                        return Some(Self::respond(401, vec![], "{}"));
                    }
                    let id = self.new_id();
                    self.sessions.insert(id.clone(), email);
                    Self::respond(200, vec![], &format!("{{\"token\": \"{id}\"}}"))
                }
                ("POST", "/logout") => {
                    // Like the real app this was first run against: sign-out needs the token, and
                    // `/logout` has no page of its own to find one on.
                    if !token_ok {
                        return Some(Self::respond(403, vec![], "refused"));
                    }
                    if !self.flaws.logout_keeps_session
                        && let Some(s) = sid
                    {
                        self.sessions.remove(&s);
                    }
                    let mut headers = vec![("Set-Cookie", "sid=; Max-Age=0".to_string())];
                    if self.flaws.clears_site_data {
                        let value = self
                            .clear_site_data_value
                            .clone()
                            .unwrap_or_else(|| "\"storage\", \"cookies\"".to_string());
                        headers.push(("Clear-Site-Data", value));
                    }
                    Self::respond(303, headers, "")
                }
                ("GET", "/account") => {
                    if user.is_some() || self.flaws.private_open {
                        // A correct private page: not to be kept by the browser, and carrying a
                        // visible way out. Each half is switched off by its own flaw, so a test
                        // that breaks one is not quietly relying on the other.
                        let headers = match (&self.cache_control, self.flaws.private_page_cacheable)
                        {
                            (_, true) => vec![],
                            (Some(value), _) => vec![("Cache-Control", value.clone())],
                            (None, _) => vec![("Cache-Control", "no-store".to_string())],
                        };
                        let body = if self.flaws.no_sign_out_link {
                            "your account<script>const OUT = '/logout';</script>".to_string()
                        } else {
                            format!(
                                "your account<form method='post' action='/logout'>\
                                 <input name='csrf_token' value='{CSRF}'>\
                                 <button>Sign out</button></form>"
                            )
                        };
                        Self::respond(200, headers, &body)
                    } else {
                        Self::respond(302, vec![("Location", "/login".into())], "")
                    }
                }
                ("GET", "/admin") => {
                    if is_admin || (user.is_some() && self.flaws.admin_open) {
                        Self::respond(200, vec![], "admin")
                    } else {
                        Self::respond(403, vec![], "no")
                    }
                }
                ("GET", "/notes") => Self::respond(
                    200,
                    vec![],
                    &format!("<input name='csrf_token' value='{CSRF}'>"),
                ),
                ("POST", "/upload") => {
                    if user.is_none() || self.flaws.upload_broken {
                        return Some(Self::respond(403, vec![], "no"));
                    }
                    let body = r.body.clone().unwrap_or_default();
                    let name = body
                        .split("filename=\"")
                        .nth(1)
                        .and_then(|rest: &str| rest.split('"').next())
                        .unwrap_or("")
                        .to_owned();
                    // The file's own bytes: everything after the blank line that ends its part.
                    let contents = body
                        .split("application/octet-stream\r\n\r\n")
                        .nth(1)
                        .and_then(|rest: &str| rest.rsplit_once("\r\n--"))
                        .map(|(file, _)| file.to_owned())
                        .unwrap_or_default();
                    self.largest_upload = self.largest_upload.max(contents.len());
                    if contents.len() > UPLOAD_LIMIT && !self.flaws.oversized_upload_ok {
                        return Some(Self::respond(413, vec![], "too large"));
                    }
                    let claims_gif = name.ends_with(".gif");
                    let is_gif = contents.starts_with("GIF87a") || contents.starts_with("GIF89a");
                    if claims_gif && !is_gif && !self.flaws.unchecked_contents_ok {
                        return Some(Self::respond(415, vec![], "not a gif"));
                    }
                    self.uploads.insert(name, contents);
                    Self::respond(201, vec![], "stored")
                }
                ("GET", path) if path.starts_with("/files/") => {
                    let name = path.trim_start_matches("/files/");
                    let Some(contents) = self.uploads.get(name) else {
                        return Some(Self::respond(404, vec![], "no such file"));
                    };
                    if name.ends_with(".php") {
                        if self.flaws.runs_uploaded_code {
                            // Only the output: the source is gone, which is what "it ran" means.
                            let shown = contents
                                .split_once("echo \"")
                                .and_then(|(_, rest)| rest.split_once('"'))
                                .map(|(out, _)| out.to_owned())
                                .unwrap_or_default();
                            return Some(Self::respond(200, vec![], &shown));
                        }
                        return Some(Self::respond(
                            200,
                            vec![("Content-Type", "text/plain".into())],
                            contents,
                        ));
                    }
                    if name.ends_with(".html") {
                        if self.flaws.renders_uploaded_pages {
                            return Some(Self::respond(
                                200,
                                vec![("Content-Type", "text/html; charset=utf-8".into())],
                                contents,
                            ));
                        }
                        return Some(Self::respond(
                            200,
                            vec![
                                ("Content-Type", "text/html; charset=utf-8".into()),
                                ("Content-Disposition", "attachment".into()),
                            ],
                            contents,
                        ));
                    }
                    // A correct download: a name the app cleaned, quoted. Each fault is its own
                    // switch, so a test that breaks one is not quietly relying on the other.
                    let disposition = if self.flaws.download_no_filename {
                        "attachment".to_owned()
                    } else if self.flaws.download_name_raw {
                        format!("attachment; filename={name}")
                    } else if self.flaws.download_name_quoted_uncleaned {
                        format!("attachment; filename=\"{name}\"")
                    } else {
                        let clean: String = name
                            .chars()
                            .map(|c| {
                                if c.is_ascii_alphanumeric() || ".-_".contains(c) {
                                    c
                                } else {
                                    '_'
                                }
                            })
                            .collect();
                        format!("attachment; filename=\"{clean}\"")
                    };
                    Self::respond(
                        200,
                        vec![
                            ("Content-Type", "image/gif".into()),
                            ("Content-Disposition", disposition),
                        ],
                        contents,
                    )
                }
                ("POST", "/notes") => {
                    let Some(owner) = user else {
                        return Some(Self::respond(302, vec![("Location", "/login".into())], ""));
                    };
                    if !self.flaws.no_csrf_check && (foreign || !token_ok) {
                        return Some(Self::respond(403, vec![], "forged"));
                    }
                    self.notes
                        .push((owner, form(r).get("text").cloned().unwrap_or_default()));
                    Self::respond(
                        303,
                        vec![(
                            "Location",
                            format!("http://app:8080/notes/{}", self.notes.len()),
                        )],
                        "",
                    )
                }
                ("GET", p) if p.starts_with("/notes/") => {
                    let n: usize = p["/notes/".len()..].parse().ok()?;
                    let Some((owner, text)) = self.notes.get(n.checked_sub(1)?) else {
                        return Some(Self::respond(404, vec![], "none"));
                    };
                    if user.as_ref() == Some(owner)
                        || (self.flaws.idor && user.is_some())
                        || self.flaws.records_public
                    {
                        let extra = if self.flaws.record_leaks_fields {
                            "<script>const row={\"id\":1,\"password_hash\":\"$2b$12$abc\"}</script>"
                        } else {
                            ""
                        };
                        // The prose is deliberate: a real record page often says something like
                        // this, and a check matching the bare word `password` would make a
                        // finding out of every app that has one. Keeping it here means the
                        // correct-app tests catch that mistake.
                        Self::respond(
                            200,
                            vec![],
                            &format!(
                                "<p>{text}</p><footer>Change your password in Account</footer>\
                                 {extra}"
                            ),
                        )
                    } else {
                        Self::respond(404, vec![], "none")
                    }
                }
                ("POST", "/login/2fa") => {
                    let id = sid.clone()?;
                    let Some(who) = self.pending.get(&id).cloned() else {
                        return Some(Self::respond(403, vec![], "sign in first"));
                    };
                    let given = form(r).get("code")?.clone();
                    let secret = self.totp.get(&who)?.clone();
                    let now = self.clock / crate::totp::STEP;
                    let oldest = if self.flaws.totp_any_age {
                        now.saturating_sub(10)
                    } else {
                        now.saturating_sub(1)
                    };
                    let matched = (oldest..=now + 1)
                        .find(|step| crate::totp::code_at_step(&secret, *step) == given);
                    let fresh = |step: u64| {
                        self.flaws.totp_reusable
                            || self.totp_last.get(&who).is_none_or(|last| step > *last)
                    };
                    match matched {
                        Some(step)
                            if fresh(step)
                                && !self.flaws.totp_broken
                                && !self.totp_is_locked(&who) =>
                        {
                            self.totp_last.insert(who.clone(), step);
                            self.pending.remove(&id);
                            self.sessions.insert(id, who);
                            Self::respond(303, vec![("Location", "/account".into())], "")
                        }
                        _ => {
                            *self.totp_wrong.entry(who).or_insert(0) += 1;
                            Self::respond(403, vec![], "wrong code")
                        }
                    }
                }
                ("POST", step) if step.starts_with("/checkout/") => {
                    let Some(who) = user.clone() else {
                        return Some(Self::respond(401, vec![], "sign in"));
                    };
                    let n: u32 = step["/checkout/".len()..].parse().ok()?;
                    let reached = self.checkout.get(&who).copied().unwrap_or(0);
                    let allowed = self.flaws.flow_unguarded
                        || reached + 1 == n
                        || (self.flaws.flow_checks_first_only && n == 3 && reached >= 1);
                    if (!allowed || !token_ok) && self.flaws.flow_refusal_redirects {
                        return Some(Self::respond(
                            303,
                            vec![("Location", "/checkout/1".into())],
                            "",
                        ));
                    }
                    if !allowed || !token_ok {
                        return Some(Self::respond(
                            409,
                            vec![],
                            if self.flaws.flow_refusal_says_placed {
                                "An order is placed only after the steps before it"
                            } else {
                                "finish the steps before this one"
                            },
                        ));
                    }
                    if n < 3 {
                        self.checkout.insert(who, n);
                        return Some(Self::respond(200, vec![], "next step"));
                    }
                    self.checkout.remove(&who);
                    if self.flaws.flow_broken {
                        return Some(Self::respond(200, vec![], "something went wrong"));
                    }
                    Self::respond(303, vec![("Location", "/orders/7".into())], "Order placed")
                }
                _ => Self::respond(404, vec![], "none"),
            })
        }
    }

    fn users() -> UsersSection {
        let t = |path: &str, fields: &[(&str, &str)]| RequestTemplate {
            method: "POST".into(),
            path: path.into(),
            form: fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            json: BTreeMap::new(),
        };
        UsersSection {
            seed: Some("seed".into()),
            signup: None,
            login: Some(t(
                "/login",
                &[
                    ("email", "{user}"),
                    ("password", "{password}"),
                    ("csrf_token", "{csrf}"),
                ],
            )),
            logout: Some(t("/logout", &[("csrf_token", "{csrf}")])),
            token_field: None,
            private: vec!["/account".into()],
            admin: vec!["/admin".into()],
            owned: Some(sv_manifest::OwnedSection {
                create: RequestTemplate {
                    method: "POST".into(),
                    path: "/notes".into(),
                    form: [("text", "{marker}"), ("csrf_token", "{csrf}")]
                        .iter()
                        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                        .collect(),
                    json: BTreeMap::new(),
                },
                read: None,
                id_field: None,
            }),
            change_password: Some(t(
                "/password",
                &[
                    ("current", "{password}"),
                    ("new", "{new_password}"),
                    ("csrf_token", "{csrf}"),
                ],
            )),
            delete_account: Some(t(
                "/account/delete",
                &[("password", "{password}"), ("csrf_token", "{csrf}")],
            )),
            upload: None,
            reset: Some(sv_manifest::ResetSection {
                request: t("/forgot", &[("email", "{user}"), ("csrf_token", "{csrf}")]),
                use_code: t(
                    "/reset",
                    &[
                        ("token", "{code}"),
                        ("password", "{new_password}"),
                        ("csrf_token", "{csrf}"),
                    ],
                ),
                code_pattern: None,
            }),
            email_code: Some(sv_manifest::ResetSection {
                request: t(
                    "/login/code",
                    &[("email", "{user}"), ("csrf_token", "{csrf}")],
                ),
                use_code: t(
                    "/login/verify",
                    &[("code", "{code}"), ("csrf_token", "{csrf}")],
                ),
                code_pattern: None,
            }),
            totp: Some(t("/login/2fa", &[("code", "{code}")])),
            flow: Some(sv_manifest::FlowSection {
                steps: (1..=3)
                    .map(|n| t(&format!("/checkout/{n}"), &[("csrf_token", "{csrf}")]))
                    .collect(),
                completed: "/orders/".into(),
            }),
            browser: None,
        }
    }

    fn accounts() -> Accounts {
        Accounts {
            a: Account {
                user: "a@example.test".into(),
                password: "Sv-0a1b2c3d4e5f60718293a4b5-aZ9!".into(),
            },
            b: Account {
                user: "b@example.test".into(),
                password: "Sv-b5a4938271605f4e3d2c1b0a-aZ9!".into(),
            },
            admin: Some(Account {
                user: "admin@example.test".into(),
                password: "Sv-00112233445566778899aabb-aZ9!".into(),
            }),
            spare: "3f9c0a7e5b1d2468ace13579bdf02468".into(),
            totp: Some(TotpAccount {
                account: Account {
                    user: "totp@example.test".into(),
                    password: "Sv-7a6b5c4d3e2f10293847a6b5-aZ9!".into(),
                },
                // RFC 6238's own SHA-1 test secret.
                secret: b"12345678901234567890".to_vec(),
            }),
        }
    }

    /// Runs the suite against the fake app, seeded the way `seed` would seed it.
    fn run_against(flaws: Flaws, users: &UsersSection) -> Outcome {
        let mut app = FakeApp::new(flaws);
        let acc = accounts();
        app.users
            .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
        app.users
            .insert(acc.b.user.clone(), (acc.b.password.clone(), false));
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        if let Some(totp) = &acc.totp {
            app.users.insert(
                totp.account.user.clone(),
                (totp.account.password.clone(), false),
            );
            app.totp
                .insert(totp.account.user.clone(), totp.secret.clone());
        }
        run(&mut app, users, &acc, true, &Default::default())
    }

    /// A run with no seeded admin, for the fixtures that sign up rather than being seeded.
    fn run_with_users(flaws: Flaws, users: &UsersSection) -> Outcome {
        let mut app = FakeApp::new(flaws);
        let mut acc = accounts();
        acc.admin = None;
        acc.totp = None;
        run(&mut app, users, &acc, false, &Default::default())
    }

    fn rule_ids(o: &Outcome) -> Vec<&str> {
        o.findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    fn verified_ids(o: &Outcome) -> Vec<&str> {
        o.verified.iter().map(|v| v.check_id.as_str()).collect()
    }

    #[test]
    fn a_correct_app_raises_nothing_and_every_check_says_what_it_confirmed() {
        let o = run_against(Flaws::default(), &users());
        assert!(o.findings.is_empty(), "{:#?}", o.findings);
        for id in [
            PRIVATE_PAGE.rule_id,
            SESSION_COOKIE.rule_id,
            SESSION_RENEWAL.rule_id,
            ADMIN_PAGE.rule_id,
            OTHER_USERS_DATA.rule_id,
            FORGERY.rule_id,
            LOGOUT.rule_id,
            PRIVATE_PAGE_CACHING.rule_id,
            SIGN_OUT_LINK.rule_id,
            SESSION_TOKEN_UNVERIFIED.rule_id,
        ] {
            assert!(
                verified_ids(&o).contains(&id),
                "{id} was not confirmed: {:?}\n{:?}",
                verified_ids(&o),
                o.not_assessed
            );
        }
    }

    #[test]
    fn a_rule_the_form_states_and_the_server_does_not_apply_is_found() {
        // Needs `signup`, so it is its own test rather than a row in the table below, which runs
        // against a fixture that has none.
        let flawed = run_with_users(
            Flaws {
                validation_only_in_browser: true,
                ..Default::default()
            },
            &with_signup(),
        );
        assert!(
            rule_ids(&flawed).contains(&CLIENT_SIDE_VALIDATION.rule_id),
            "{:?} / {:?}",
            rule_ids(&flawed),
            flawed.not_assessed
        );
        let correct = run_with_users(Flaws::default(), &with_signup());
        assert!(
            !rule_ids(&correct).contains(&CLIENT_SIDE_VALIDATION.rule_id),
            "an app that applies its own rule was accused: {:?}",
            rule_ids(&correct)
        );
        // Never credited: refusing the broken value might be a refusal for some other reason.
        assert!(!verified_ids(&correct).contains(&CLIENT_SIDE_VALIDATION.rule_id));
    }

    #[test]
    fn without_a_sign_up_the_form_rule_question_is_not_asked() {
        let o = run_against(Flaws::default(), &users());
        assert!(!rule_ids(&o).contains(&CLIENT_SIDE_VALIDATION.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(id, why)| id == "V2.2.2" && why.contains("signup")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn the_run_note_names_a_clear_site_data_that_falls_short() {
        // The second witness for the storage rule, on the run note rather than on the verdict.
        // "sent a header" and "sent a header that does the job" are different things, and the
        // note is where the owner can see which one happened.
        let mut app = FakeApp::new(Flaws {
            clears_site_data: true,
            ..Default::default()
        });
        app.clear_site_data_value = Some("\"cookies\"".to_string());
        let acc = accounts();
        app.users
            .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
        app.users
            .insert(acc.b.user.clone(), (acc.b.password.clone(), false));
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        let o = run(&mut app, &users(), &acc, true, &Default::default());
        let note = o.steps.join(" | ");
        assert!(
            note.contains("Clear-Site-Data: not covering storage"),
            "a cookies-only header was noted as if it did the job: {note}"
        );
    }

    #[test]
    fn a_secret_name_has_to_be_a_field_not_a_word() {
        // The failure this check would otherwise have: almost every app has a page saying "change
        // your password" or "forgot your password". Matching the bare word makes a finding out of
        // every one of them, and a check that cries wolf is one people learn to skip.
        for prose in [
            "<p>Change your password</p>",
            "Forgot your password? We never store your password in plain text.",
            "<label>Current password</label>",
            "<p>Your secret is safe with us</p>",
        ] {
            let mut out = Outcome::default();
            record_fields_check(prose, "/notes/1", &mut out);
            assert!(
                out.findings.is_empty(),
                "prose was read as a leaked field: {prose}"
            );
        }
        // And the shapes that really are fields, so this cannot pass by never finding anything.
        for record in [
            r#"{"id":1,"password_hash":"$2b$12$abc"}"#,
            "{'salt': 'xyz', 'id': 2}",
            "id=1&api_key=sk-live-abc",
        ] {
            let mut out = Outcome::default();
            record_fields_check(record, "/notes/1", &mut out);
            assert_eq!(
                out.findings.len(),
                1,
                "a field was not recognized: {record}"
            );
            assert!(
                out.findings[0]
                    .requirement_ids
                    .iter()
                    .any(|r| r == "V15.3.1")
            );
        }
    }

    #[test]
    fn the_run_note_says_what_each_of_these_asked_and_what_came_back() {
        // A second reading of three checks at once, on the surface the owner sees. A check that
        // quietly stopped asking would leave the findings list empty, which looks exactly like an
        // app with nothing wrong; the note is where the two are told apart.
        let correct = run_with_users(Flaws::default(), &with_signup());
        let note = correct.steps.join(" | ");
        assert!(note.contains("session value this check invented"), "{note}");
        assert!(note.contains("breaking the form's own"), "{note}");
        assert!(note.contains("Clear-Site-Data"), "{note}");

        let flawed = run_with_users(
            Flaws {
                session_not_verified: true,
                validation_only_in_browser: true,
                clears_site_data: true,
                ..Default::default()
            },
            &with_signup(),
        );
        let note = flawed.steps.join(" | ");
        assert!(note.contains("invented: opened"), "{note}");
        assert!(note.contains("maxlength=40: accepted"), "{note}");
        assert!(note.contains("Clear-Site-Data: yes"), "{note}");
    }

    #[test]
    fn clear_site_data_credits_on_presence_and_never_faults() {
        // The shape of this check, in one test. Sending the header is credited; not sending it is
        // *not assessed*, because an app whose own script clears storage has met V14.3.1 without
        // it. A finding here would be accusing apps of something this cannot see.
        let with = run_against(
            Flaws {
                clears_site_data: true,
                ..Default::default()
            },
            &users(),
        );
        assert!(
            verified_ids(&with).contains(&"probe.clear-site-data"),
            "{:?}",
            with.not_assessed
        );

        let without = run_against(Flaws::default(), &users());
        assert!(!verified_ids(&without).contains(&"probe.clear-site-data"));
        assert!(
            !rule_ids(&without).contains(&"probe.clear-site-data"),
            "not sending the header must never be a finding"
        );
        assert!(
            without
                .not_assessed
                .iter()
                .any(|(id, why)| id == "V14.3.1" && why.contains("not a failure")),
            "{:?}",
            without.not_assessed
        );
    }

    #[test]
    fn a_header_that_does_not_cover_storage_is_not_enough() {
        // `Clear-Site-Data: "cookies"` clears the cookie the session already ended with, and
        // leaves everything the page kept. Crediting it would be crediting the wrong thing.
        let mut app = FakeApp::new(Flaws {
            clears_site_data: true,
            ..Default::default()
        });
        app.clear_site_data_value = Some("\"cookies\"".to_string());
        let acc = accounts();
        app.users
            .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
        app.users
            .insert(acc.b.user.clone(), (acc.b.password.clone(), false));
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        let o = run(&mut app, &users(), &acc, true, &Default::default());
        assert!(!verified_ids(&o).contains(&"probe.clear-site-data"));
        assert!(
            o.not_assessed
                .iter()
                .any(|(id, why)| id == "V14.3.1" && why.contains("does not cover storage")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn an_app_that_believes_any_session_cookie_is_found() {
        // Deliberately not in the table below, and the reason is worth writing down: an app that
        // takes any session id at its word does not fail *one* check. Default accounts sign in,
        // sign-out does not end anything, a password change needs no current password — because
        // every one of those is asked with a cookie the app now believes. Putting it in a table
        // that asserts "this flaw and no other" would be asserting something untrue about it.
        let o = run_against(
            Flaws {
                session_not_verified: true,
                ..Default::default()
            },
            &users(),
        );
        assert!(
            rule_ids(&o).contains(&SESSION_TOKEN_UNVERIFIED.rule_id),
            "{:?}",
            rule_ids(&o)
        );
        assert!(!verified_ids(&o).contains(&SESSION_TOKEN_UNVERIFIED.rule_id));
        // And a correct app is not accused of it, which is the half that could quietly rot.
        let correct = run_against(Flaws::default(), &users());
        assert!(!rule_ids(&correct).contains(&SESSION_TOKEN_UNVERIFIED.rule_id));
        assert!(verified_ids(&correct).contains(&SESSION_TOKEN_UNVERIFIED.rule_id));
    }

    #[test]
    fn each_flaw_is_found_by_its_own_rule_and_by_no_other() {
        for (flaw, rule) in [
            (
                Flaws {
                    private_open: true,
                    ..Default::default()
                },
                PRIVATE_PAGE.rule_id,
            ),
            (
                Flaws {
                    admin_open: true,
                    ..Default::default()
                },
                ADMIN_PAGE.rule_id,
            ),
            (
                Flaws {
                    idor: true,
                    ..Default::default()
                },
                OTHER_USERS_DATA.rule_id,
            ),
            (
                Flaws {
                    records_public: true,
                    ..Default::default()
                },
                OTHER_USERS_DATA.rule_id,
            ),
            (
                Flaws {
                    no_csrf_check: true,
                    ..Default::default()
                },
                FORGERY.rule_id,
            ),
            (
                Flaws {
                    keep_session_at_login: true,
                    ..Default::default()
                },
                SESSION_RENEWAL.rule_id,
            ),
            (
                Flaws {
                    logout_keeps_session: true,
                    ..Default::default()
                },
                LOGOUT.rule_id,
            ),
            (
                Flaws {
                    no_httponly: true,
                    ..Default::default()
                },
                SESSION_COOKIE.rule_id,
            ),
            (
                Flaws {
                    default_admin: true,
                    ..Default::default()
                },
                DEFAULT_ACCOUNT.rule_id,
            ),
            (
                Flaws {
                    password_in_url: true,
                    ..Default::default()
                },
                PASSWORD_IN_URL.rule_id,
            ),
            (
                Flaws {
                    short_session_ids: true,
                    ..Default::default()
                },
                WEAK_SESSION_ID.rule_id,
            ),
            (
                Flaws {
                    same_session_id: true,
                    ..Default::default()
                },
                WEAK_SESSION_ID.rule_id,
            ),
            (
                Flaws {
                    password_shown: true,
                    ..Default::default()
                },
                UNMASKED_PASSWORD.rule_id,
            ),
            (
                Flaws {
                    paste_blocked: true,
                    ..Default::default()
                },
                PASTE_BLOCKED.rule_id,
            ),
            (
                Flaws {
                    logout_on_get: true,
                    ..Default::default()
                },
                SIGN_OUT_ON_GET.rule_id,
            ),
            (
                Flaws {
                    private_page_cacheable: true,
                    ..Default::default()
                },
                PRIVATE_PAGE_CACHING.rule_id,
            ),
            (
                Flaws {
                    record_leaks_fields: true,
                    ..Default::default()
                },
                RECORD_LEAKS_FIELDS.rule_id,
            ),
            (
                Flaws {
                    no_sign_out_link: true,
                    ..Default::default()
                },
                SIGN_OUT_LINK.rule_id,
            ),
        ] {
            let o = run_against(flaw, &users());
            let found = rule_ids(&o);
            assert!(
                found.contains(&rule),
                "{rule} not found: {found:?}\n{:?}",
                o.not_assessed
            );
            assert!(
                !verified_ids(&o).contains(&rule),
                "{rule} both found and confirmed"
            );
            let others: Vec<&&str> = found.iter().filter(|r| **r != rule).collect();
            // A private page open to anybody makes the signed-in session unprovable on that page,
            // which is its own not-assessed, not another finding.
            assert!(others.is_empty(), "{rule} also raised {others:?}");
        }
    }

    #[test]
    fn an_app_with_every_flaw_at_once_has_every_one_found() {
        // The second witness for each rule, and a check that no flaw hides another.
        let o = run_against(
            Flaws {
                admin_open: true,
                idor: true,
                no_csrf_check: true,
                logout_keeps_session: true,
                no_httponly: true,
                ..Default::default()
            },
            &users(),
        );
        let mut found = rule_ids(&o);
        found.sort_unstable();
        let mut expected = vec![
            ADMIN_PAGE.rule_id,
            OTHER_USERS_DATA.rule_id,
            FORGERY.rule_id,
            LOGOUT.rule_id,
            SESSION_COOKIE.rule_id,
        ];
        expected.sort_unstable();
        assert_eq!(found, expected, "{:?}", o.not_assessed);

        // The two that change what a session is, together: a page open to all and a session kept
        // across sign-in. Each has to be found beside the other.
        let o = run_against(
            Flaws {
                private_open: true,
                keep_session_at_login: true,
                ..Default::default()
            },
            &users(),
        );
        let found = rule_ids(&o);
        assert!(found.contains(&PRIVATE_PAGE.rule_id), "{found:?}");
        assert!(found.contains(&SESSION_RENEWAL.rule_id), "{found:?}");
    }

    #[test]
    fn a_leak_says_who_it_leaked_to_and_no_more() {
        // A record open to everybody is a worse leak than one open to other users, and the finding
        // has to say which, or the fix looks smaller than it is.
        let open = run_against(
            Flaws {
                records_public: true,
                ..Default::default()
            },
            &users(),
        );
        let leak = open
            .findings
            .iter()
            .find(|f| f.rule_id == OTHER_USERS_DATA.rule_id)
            .expect("the leak is found");
        assert!(
            leak.description.contains("somebody not signed in"),
            "{}",
            leak.description
        );

        let signed_in_only = run_against(
            Flaws {
                idor: true,
                ..Default::default()
            },
            &users(),
        );
        let leak = signed_in_only
            .findings
            .iter()
            .find(|f| f.rule_id == OTHER_USERS_DATA.rule_id)
            .expect("the leak is found");
        assert!(
            !leak.description.contains("not signed in"),
            "it did not leak to anonymous visitors: {}",
            leak.description
        );
    }

    #[test]
    fn accounts_that_were_never_made_are_not_assessed_either() {
        // Second shape of the sign-in setup check: the app is fine, the accounts are not there.
        let mut app = FakeApp::new(Flaws::default());
        let o = run(&mut app, &users(), &accounts(), true, &Default::default());
        assert!(o.findings.is_empty(), "{:?}", rule_ids(&o));
        assert!(o.verified.is_empty(), "{:?}", verified_ids(&o));
        assert!(
            o.not_assessed
                .iter()
                .any(|(_, why)| why.contains("did not open /account")),
            "the reason has to be the sign-in, not whatever check happened to stop next: {:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_record_without_the_marker_cannot_be_recognized_so_is_not_assessed() {
        // Second shape of the read-back check: the owner reads the record, but nothing in it says
        // it is the one created, so another user reading "a record" would prove nothing.
        let mut u = users();
        u.owned
            .as_mut()
            .unwrap()
            .create
            .form
            .insert("text".into(), "no marker here".into());
        let o = run_against(
            Flaws {
                idor: true,
                ..Default::default()
            },
            &u,
        );
        assert!(
            !rule_ids(&o).contains(&OTHER_USERS_DATA.rule_id),
            "{:?}",
            rule_ids(&o)
        );
        assert!(!verified_ids(&o).contains(&OTHER_USERS_DATA.rule_id));
    }

    #[test]
    fn a_refused_sign_out_is_not_blamed_on_the_app() {
        // Found against the first real app: the sign-out was refused for want of a token, the
        // session carried on, and the suite reported that signing out does not end sessions. A
        // sign-out that did not happen proves nothing, whatever the app does with real ones.
        let mut u = users();
        u.logout.as_mut().unwrap().form.clear(); // no token field, so the app refuses it
        for flaws in [
            Flaws::default(),
            Flaws {
                logout_keeps_session: true,
                ..Default::default()
            },
        ] {
            let o = run_against(flaws, &u);
            assert!(
                !rule_ids(&o).contains(&LOGOUT.rule_id),
                "{:?}",
                rule_ids(&o)
            );
            assert!(!verified_ids(&o).contains(&LOGOUT.rule_id));
            assert!(
                o.not_assessed
                    .iter()
                    .any(|(ids, why)| ids == "V7.4.1" && why.contains("refused")),
                "{:?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn a_sign_out_sent_to_the_wrong_address_is_not_blamed_on_the_app_either() {
        // The second shape: not a missing token but a path the app does not have. A 404 ended no
        // session, so the session carrying on says nothing about sign-out.
        let mut u = users();
        u.logout.as_mut().unwrap().path = "/sign-out".into();
        let o = run_against(Flaws::default(), &u);
        assert!(
            !rule_ids(&o).contains(&LOGOUT.rule_id),
            "{:?}",
            rule_ids(&o)
        );
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids == "V7.4.1" && why.contains("404")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn the_sign_out_token_is_found_on_another_page() {
        // `/logout` shows nothing; the token is on the note form, as a sign-out button's would be
        // on whatever page it sits. Without looking there, every correct app would fail to sign out.
        let o = run_against(Flaws::default(), &users());
        assert!(
            verified_ids(&o).contains(&LOGOUT.rule_id),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn accounts_can_be_made_through_the_apps_own_sign_up() {
        // No seed: both users sign up the way a visitor would, token and all, and then everything
        // that does not need an admin runs as it does for a seeded app.
        let mut u = users();
        u.seed = None;
        u.admin = Vec::new();
        u.signup = Some(RequestTemplate {
            method: "POST".into(),
            path: "/signup".into(),
            form: [
                ("email", "{user}"),
                ("password", "{password}"),
                ("csrf_token", "{csrf}"),
            ]
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
            json: BTreeMap::new(),
        });
        let mut app = FakeApp::new(Flaws {
            idor: true,
            ..Default::default()
        });
        let mut acc = accounts();
        acc.admin = None;
        acc.totp = None;
        let o = run(&mut app, &u, &acc, false, &Default::default());
        assert!(
            app.users.contains_key(&acc.a.user) && app.users.contains_key(&acc.b.user),
            "both users signed up"
        );
        assert!(
            o.steps.iter().any(|s| s.starts_with("signed up A")),
            "{:?}",
            o.steps
        );
        assert_eq!(
            rule_ids(&o),
            vec![OTHER_USERS_DATA.rule_id],
            "{:?}",
            o.not_assessed
        );
        assert!(verified_ids(&o).contains(&LOGOUT.rule_id));
    }

    #[test]
    fn a_json_sign_in_with_a_bearer_token_is_used_and_its_cookie_checks_are_not_claimed() {
        // An API that answers sign-in with a token in JSON. The signed-in checks run on the token;
        // the cookie checks have no cookie to look at, and say so rather than passing.
        let mut u = users();
        u.login = Some(RequestTemplate {
            method: "POST".into(),
            path: "/api/login".into(),
            form: BTreeMap::new(),
            json: [("email", "{user}"), ("password", "{password}")]
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        });
        u.token_field = Some("token".into());
        u.logout = None;
        u.owned = None;
        let o = run_against(
            Flaws {
                admin_open: true,
                ..Default::default()
            },
            &u,
        );
        assert!(
            verified_ids(&o).contains(&PRIVATE_PAGE.rule_id),
            "{:?}",
            o.not_assessed
        );
        assert_eq!(rule_ids(&o), vec![ADMIN_PAGE.rule_id]);
        assert!(!verified_ids(&o).contains(&SESSION_COOKIE.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(_, why)| why.contains("token rather than a cookie")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_sign_in_that_does_not_work_is_not_assessed_rather_than_passed() {
        // The setup check. Every refusal below would read as a pass if the session never worked.
        let o = run_against(
            Flaws {
                broken_login: true,
                ..Default::default()
            },
            &users(),
        );
        assert!(o.findings.is_empty(), "{:?}", rule_ids(&o));
        assert!(
            o.verified.is_empty(),
            "nothing can be confirmed: {:?}",
            verified_ids(&o)
        );
        assert!(
            o.not_assessed
                .iter()
                .any(|(_, why)| why.contains("did not open /account")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn an_owner_who_cannot_read_their_own_record_makes_the_other_user_check_not_assessed() {
        // B being refused A's record proves nothing if A was refused it too.
        let mut u = users();
        u.owned.as_mut().unwrap().read = Some("/notes/999".into());
        let o = run_against(
            Flaws {
                idor: true,
                ..Default::default()
            },
            &u,
        );
        assert!(!rule_ids(&o).contains(&OTHER_USERS_DATA.rule_id));
        assert!(!verified_ids(&o).contains(&OTHER_USERS_DATA.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids.contains("V8.2.2") && why.contains("could not read back")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn an_admin_page_the_admin_cannot_open_either_is_not_assessed() {
        let mut u = users();
        u.admin = vec!["/not-the-admin-page".into()];
        let o = run_against(Flaws::default(), &u);
        assert!(!verified_ids(&o).contains(&ADMIN_PAGE.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(_, why)| why.contains("/not-the-admin-page")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_manifest_that_cannot_be_used_says_why_and_asks_nothing() {
        let mut u = users();
        u.login = None;
        let mut app = FakeApp::new(Flaws::default());
        let o = run(&mut app, &u, &accounts(), true, &Default::default());
        assert!(o.findings.is_empty() && o.verified.is_empty());
        assert!(
            o.not_assessed[0].1.contains("`login` is not set"),
            "{:?}",
            o.not_assessed
        );
        assert_eq!(app.next, 0, "no request was made");
    }

    #[test]
    fn what_is_not_listed_is_named_as_not_assessed() {
        let mut u = users();
        u.logout = None;
        u.owned = None;
        u.admin = Vec::new();
        let o = run_against(Flaws::default(), &u);
        let said: Vec<&str> = o.not_assessed.iter().map(|(ids, _)| ids.as_str()).collect();
        for ids in ["V7.4.1", "V8.2.2, V3.5.1", "V8.2.1", "V3.3.1"] {
            assert!(said.contains(&ids), "{ids} not named: {said:?}");
        }
    }

    #[test]
    fn the_token_is_found_however_the_page_offers_it() {
        let page = |body: &str| ProbeResponse {
            id: String::new(),
            status: 200,
            headers: vec![],
            body: body.into(),
        };
        let none = Session::default();
        assert_eq!(
            csrf_token(
                &page("<input type=hidden name=\"csrf_token\" value=\"t1\">"),
                &none
            )
            .as_deref(),
            Some("t1")
        );
        assert_eq!(
            csrf_token(
                &page("<input value='t2' name='csrfmiddlewaretoken'>"),
                &none
            )
            .as_deref(),
            Some("t2")
        );
        assert_eq!(
            csrf_token(&page("<meta name=\"csrf-token\" content=\"t3\">"), &none).as_deref(),
            Some("t3")
        );
        let with_cookie = Session {
            cookies: vec![("XSRF-TOKEN".into(), "t4".into())],
            bearer: None,
        };
        assert_eq!(
            csrf_token(&page("<p>nothing</p>"), &with_cookie).as_deref(),
            Some("t4")
        );
        assert_eq!(
            csrf_token(&page("<input name=\"email\" value=\"x\">"), &none),
            None
        );
        // Unquoted, which is valid HTML and how the first real app this met wrote its form.
        assert_eq!(
            csrf_token(&page("<input type=hidden name=csrf_token value=t5>"), &none).as_deref(),
            Some("t5")
        );
        // A field whose name only contains the word is not the token.
        assert_eq!(
            csrf_token(&page("<input name=not_csrf_token value=x>"), &none),
            None
        );
    }

    #[test]
    fn a_created_record_is_found_from_a_location_or_a_json_id() {
        let created = |headers: Vec<(&str, &str)>, body: &str| ProbeResponse {
            id: String::new(),
            status: 201,
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
            body: body.into(),
        };
        let owned = |read: Option<&str>| sv_manifest::OwnedSection {
            create: RequestTemplate::default(),
            read: read.map(str::to_owned),
            id_field: None,
        };
        assert_eq!(
            record_path(
                &owned(None),
                &created(vec![("location", "http://app:8080/notes/7")], "")
            )
            .as_deref(),
            Some("/notes/7")
        );
        assert_eq!(
            record_path(
                &owned(Some("/api/notes/{id}")),
                &created(vec![], "{\"id\": 42}")
            )
            .as_deref(),
            Some("/api/notes/42")
        );
        assert_eq!(record_path(&owned(None), &created(vec![], "{}")), None);
    }

    /// The suite with no `seed`: every account, the test passwords' included, goes through sign-up.
    fn with_signup() -> UsersSection {
        let mut u = users();
        u.seed = None;
        u.admin = Vec::new();
        u.signup = Some(RequestTemplate {
            method: "POST".into(),
            path: "/signup".into(),
            form: [
                ("email", "{user}"),
                ("password", "{password}"),
                ("csrf_token", "{csrf}"),
            ]
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
            json: BTreeMap::new(),
        });
        u
    }

    fn run_signing_up(flaws: Flaws) -> Outcome {
        run_signing_up_with(flaws, &with_words(&["Acme Notes"]))
    }

    fn run_signing_up_with(flaws: Flaws, policy: &sv_manifest::PolicySection) -> Outcome {
        let mut app = FakeApp::new(flaws);
        let mut acc = accounts();
        acc.admin = None;
        acc.totp = None;
        run(&mut app, &with_signup(), &acc, false, policy)
    }

    /// A policy listing these context-specific words, as an owner would write them.
    fn with_words(words: &[&str]) -> sv_manifest::PolicySection {
        sv_manifest::PolicySection {
            context_words: words.iter().map(|w| (*w).to_owned()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn a_correct_sign_up_confirms_the_password_rules_and_raises_nothing() {
        let o = run_signing_up(Flaws::default());
        assert!(o.findings.is_empty(), "{:#?}\n{:?}", o.findings, o.steps);
        for id in [
            SHORT_PASSWORD.rule_id,
            COMMON_PASSWORD.rule_id,
            COMPOSITION_RULES.rule_id,
            ALTERED_PASSWORD.rule_id,
            LONG_PASSWORD.rule_id,
            UNMASKED_PASSWORD.rule_id,
            BREACHED_PASSWORD.rule_id,
            CONTEXT_WORD_PASSWORD.rule_id,
        ] {
            assert!(verified_ids(&o).contains(&id), "{id}: {:?}", o.steps);
        }
        // These can only ever find something; a clean answer is credited with nothing.
        for id in [
            DEFAULT_ACCOUNT.rule_id,
            PASSWORD_IN_URL.rule_id,
            WEAK_SESSION_ID.rule_id,
            PASTE_BLOCKED.rule_id,
            SIGN_OUT_ON_GET.rule_id,
        ] {
            assert!(!verified_ids(&o).contains(&id), "{id} was credited");
        }
        assert!(
            o.steps.iter().any(|s| s.contains("7-character password")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn each_password_flaw_is_found_by_its_own_rule_and_by_no_other() {
        for (flaw, rule) in [
            (
                Flaws {
                    short_password_ok: true,
                    ..Default::default()
                },
                SHORT_PASSWORD.rule_id,
            ),
            (
                Flaws {
                    common_password_ok: true,
                    ..Default::default()
                },
                COMMON_PASSWORD.rule_id,
            ),
            (
                Flaws {
                    composition_rules: true,
                    ..Default::default()
                },
                COMPOSITION_RULES.rule_id,
            ),
            (
                Flaws {
                    breached_password_ok: true,
                    ..Default::default()
                },
                BREACHED_PASSWORD.rule_id,
            ),
            (
                Flaws {
                    context_word_ok: true,
                    ..Default::default()
                },
                CONTEXT_WORD_PASSWORD.rule_id,
            ),
            (
                Flaws {
                    default_admin: true,
                    ..Default::default()
                },
                DEFAULT_ACCOUNT.rule_id,
            ),
            (
                Flaws {
                    password_in_url: true,
                    ..Default::default()
                },
                PASSWORD_IN_URL.rule_id,
            ),
            (
                Flaws {
                    short_session_ids: true,
                    ..Default::default()
                },
                WEAK_SESSION_ID.rule_id,
            ),
            (
                Flaws {
                    same_session_id: true,
                    ..Default::default()
                },
                WEAK_SESSION_ID.rule_id,
            ),
            (
                Flaws {
                    case_folded: true,
                    ..Default::default()
                },
                ALTERED_PASSWORD.rule_id,
            ),
            (
                Flaws {
                    cut_at_72: true,
                    ..Default::default()
                },
                ALTERED_PASSWORD.rule_id,
            ),
            (
                Flaws {
                    longest_64: true,
                    ..Default::default()
                },
                LONG_PASSWORD.rule_id,
            ),
            (
                Flaws {
                    password_shown: true,
                    ..Default::default()
                },
                UNMASKED_PASSWORD.rule_id,
            ),
            (
                Flaws {
                    paste_blocked: true,
                    ..Default::default()
                },
                PASTE_BLOCKED.rule_id,
            ),
            (
                Flaws {
                    logout_on_get: true,
                    ..Default::default()
                },
                SIGN_OUT_ON_GET.rule_id,
            ),
            (
                Flaws {
                    deletion_keeps_sessions: true,
                    ..Default::default()
                },
                SESSIONS_SURVIVE_DELETION.rule_id,
            ),
            (
                Flaws {
                    secret_question: true,
                    ..Default::default()
                },
                PASSWORD_HINTS.rule_id,
            ),
        ] {
            let o = run_signing_up(flaw);
            let found = rule_ids(&o);
            assert_eq!(found, vec![rule], "{:?}\n{:?}", o.steps, o.not_assessed);
            assert!(
                !verified_ids(&o).contains(&rule),
                "{rule} both found and confirmed"
            );
        }
    }

    #[test]
    fn a_correct_password_change_confirms_both_questions() {
        for (how, o) in [
            ("signing up", run_signing_up(Flaws::default())),
            ("seeded, with A", run_against(Flaws::default(), &users())),
        ] {
            assert!(o.findings.is_empty(), "{how}: {:#?}", o.findings);
            for id in [CHANGE_PASSWORD.rule_id, CHANGE_WITHOUT_CURRENT.rule_id] {
                assert!(verified_ids(&o).contains(&id), "{how}: {id}: {:?}", o.steps);
            }
        }
    }

    #[test]
    fn each_password_change_flaw_is_found_by_its_own_rule() {
        for (flaw, rule, credited) in [
            (
                Flaws {
                    change_without_current: true,
                    ..Default::default()
                },
                CHANGE_WITHOUT_CURRENT.rule_id,
                // A change that took has shown the password can be changed.
                Some(CHANGE_PASSWORD.rule_id),
            ),
            (
                Flaws {
                    change_keeps_old: true,
                    ..Default::default()
                },
                CHANGE_PASSWORD.rule_id,
                Some(CHANGE_WITHOUT_CURRENT.rule_id),
            ),
        ] {
            for o in [run_signing_up(flaw), run_against(flaw, &users())] {
                assert_eq!(rule_ids(&o), vec![rule], "{:?}", o.steps);
                assert!(
                    !verified_ids(&o).contains(&rule),
                    "{rule} both found and credited"
                );
                if let Some(other) = credited {
                    assert!(verified_ids(&o).contains(&other), "{other}: {:?}", o.steps);
                }
            }
        }
    }

    #[test]
    fn a_change_that_never_takes_answers_neither_question() {
        // Refusing the wrong current password means nothing if the right one is refused too.
        let o = run_signing_up(Flaws {
            change_does_nothing: true,
            ..Default::default()
        });
        assert!(o.findings.is_empty(), "{:?}", o.findings);
        for id in [CHANGE_PASSWORD.rule_id, CHANGE_WITHOUT_CURRENT.rule_id] {
            assert!(!verified_ids(&o).contains(&id), "{id} credited");
        }
        let (_, why) = o
            .not_assessed
            .iter()
            .find(|(ids, _)| ids == "V6.2.2, V6.2.3")
            .expect("both are named as not assessed");
        assert!(why.contains("did not take"), "{why}");
    }

    #[test]
    fn with_no_change_password_entry_both_are_not_assessed() {
        let mut u = with_signup();
        u.change_password = None;
        let mut app = FakeApp::new(Flaws::default());
        let mut acc = accounts();
        acc.admin = None;
        acc.totp = None;
        let o = run(&mut app, &u, &acc, false, &Default::default());
        let (_, why) = o
            .not_assessed
            .iter()
            .find(|(ids, _)| ids == "V6.2.2, V6.2.3")
            .expect("named as not assessed");
        assert!(why.contains("`change-password`"), "{why}");
    }

    #[test]
    fn the_password_change_page_is_read_signed_in_and_both_its_fields_are_judged() {
        // The change page sends anybody not signed in to /login; only a signed-in read sees it.
        let o = run_signing_up(Flaws {
            password_shown: true,
            ..Default::default()
        });
        let found = o
            .findings
            .iter()
            .find(|f| f.rule_id == UNMASKED_PASSWORD.rule_id)
            .expect("found");
        assert!(
            found.description.contains("password-change page /password"),
            "{}",
            found.description
        );
    }

    #[test]
    fn the_new_password_field_is_judged_as_well_as_the_current_one() {
        let o = run_signing_up(Flaws {
            new_field_shown: true,
            ..Default::default()
        });
        assert_eq!(
            rule_ids(&o),
            vec![UNMASKED_PASSWORD.rule_id],
            "{:?}",
            o.steps
        );
        assert!(o.findings[0].description.contains("/password"));
    }

    #[test]
    fn deleting_an_account_ends_its_other_sessions_and_says_so() {
        let o = run_signing_up(Flaws::default());
        assert!(
            verified_ids(&o).contains(&SESSIONS_SURVIVE_DELETION.rule_id),
            "{:?}\n{:?}",
            o.steps,
            o.not_assessed
        );
        let o = run_signing_up(Flaws {
            deletion_keeps_sessions: true,
            ..Default::default()
        });
        assert_eq!(
            rule_ids(&o),
            vec![SESSIONS_SURVIVE_DELETION.rule_id],
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_deletion_that_did_not_happen_answers_nothing() {
        // The account still signing in means nothing was deleted, and a live session afterwards
        // would otherwise be blamed on the sessions.
        let o = run_signing_up(Flaws {
            delete_does_nothing: true,
            ..Default::default()
        });
        assert!(o.findings.is_empty(), "{:?}", o.findings);
        assert!(!verified_ids(&o).contains(&SESSIONS_SURVIVE_DELETION.rule_id));
        let (_, why) = o
            .not_assessed
            .iter()
            .find(|(ids, _)| ids == "V7.4.2")
            .expect("named as not assessed");
        assert!(why.contains("was not deleted"), "{why}");
    }

    #[test]
    fn without_sign_up_no_account_is_ever_deleted() {
        // A and B are the accounts every other question stands on; deleting one is never done.
        let o = run_against(Flaws::default(), &users());
        assert!(!verified_ids(&o).contains(&SESSIONS_SURVIVE_DELETION.rule_id));
        let (_, why) = o
            .not_assessed
            .iter()
            .find(|(ids, _)| ids == "V7.4.2")
            .expect("named as not assessed");
        assert!(why.contains("`signup`"), "{why}");
        assert!(
            !o.steps.iter().any(|s| s.contains("deleted")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_secret_question_is_found_by_its_field_and_by_its_words() {
        let o = run_signing_up(Flaws {
            secret_question: true,
            ..Default::default()
        });
        assert_eq!(rule_ids(&o), vec![PASSWORD_HINTS.rule_id], "{:?}", o.steps);
        assert!(o.findings[0].description.contains("security_answer"));
        assert_eq!(
            password_hint("<p>Choose a security question.</p>").as_deref(),
            Some("\"security question\"")
        );
        assert_eq!(
            password_hint("<input name=hint>").as_deref(),
            Some("a field named `hint`")
        );
        // Ordinary words that are not a hint: "hints" in prose, a "question" field of a form.
        assert_eq!(
            password_hint("<p>Some hints for a strong password</p><input name=question>"),
            None
        );
    }

    #[test]
    fn a_password_both_case_folded_and_cut_short_is_one_finding_naming_both() {
        let o = run_signing_up(Flaws {
            case_folded: true,
            cut_at_72: true,
            ..Default::default()
        });
        let altered: Vec<&Finding> = o
            .findings
            .iter()
            .filter(|f| f.rule_id == ALTERED_PASSWORD.rule_id)
            .collect();
        assert_eq!(altered.len(), 1, "{:?}", o.findings);
        let said = &altered[0].description;
        assert!(
            said.contains("capitals") && said.contains("first 72"),
            "{said}"
        );
    }

    #[test]
    fn a_long_password_refused_leaves_the_cut_short_question_unanswered() {
        // Nothing can be cut short if nothing long was taken. The case question still ran.
        let o = run_signing_up(Flaws {
            longest_64: true,
            ..Default::default()
        });
        assert!(!verified_ids(&o).contains(&ALTERED_PASSWORD.rule_id));
        let (_, why) = o
            .not_assessed
            .iter()
            .find(|(ids, _)| ids == "V6.2.8")
            .expect("V6.2.8 is named as not assessed");
        assert!(why.contains("capitals swapped was refused"), "{why}");
    }

    #[test]
    fn a_form_built_by_script_is_not_assessed_rather_than_passed() {
        let o = run_signing_up(Flaws {
            no_form_in_html: true,
            ..Default::default()
        });
        assert!(!verified_ids(&o).contains(&UNMASKED_PASSWORD.rule_id));
        let (_, why) = o
            .not_assessed
            .iter()
            .find(|(ids, _)| ids == "V6.2.6")
            .expect("V6.2.6 is named as not assessed");
        assert!(why.contains("/login") && why.contains("/signup"), "{why}");
    }

    #[test]
    fn the_password_field_is_the_one_the_form_sends_not_any_input() {
        // A search box that happens to be a text field is not the password field: only the input
        // named by the template's `{password}` is judged.
        let mut app = FakeApp::new(Flaws::default());
        let mut out = Outcome::default();
        struct Page<'a>(&'a mut FakeApp);
        impl Http for Page<'_> {
            fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
                let mut response = self.0.send(r)?;
                if r.path == "/login" && r.method == "GET" {
                    response.body.push_str("<input type=\"text\" name=\"q\">");
                }
                Some(response)
            }
        }
        password_field_checks(&mut Page(&mut app), &with_signup(), None, &mut out);
        assert!(out.findings.is_empty(), "{:?}", out.findings);
        assert_eq!(verified_ids(&out), [UNMASKED_PASSWORD.rule_id]);
    }

    #[test]
    fn composition_rules_leave_the_common_password_check_unanswerable_rather_than_passed() {
        // The common password has no capital, so an app that wants one refuses it for that; the
        // random password of the same kinds is refused too, which is what shows it.
        let o = run_signing_up(Flaws {
            composition_rules: true,
            ..Default::default()
        });
        assert!(!verified_ids(&o).contains(&COMMON_PASSWORD.rule_id));
        assert!(
            o.not_assessed.iter().any(|(ids, _)| ids == "V6.2.4"),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn with_no_sign_up_the_password_rules_are_not_assessed() {
        let o = run_against(Flaws::default(), &users());
        let (_, why) = o
            .not_assessed
            .iter()
            .find(|(ids, _)| ids.contains("V6.2.1"))
            .expect("the password rules are named as not assessed");
        assert!(why.contains("`signup`"), "{why}");
        for id in [
            SHORT_PASSWORD.rule_id,
            COMMON_PASSWORD.rule_id,
            COMPOSITION_RULES.rule_id,
        ] {
            assert!(!verified_ids(&o).contains(&id));
        }
    }

    #[test]
    fn a_session_id_is_measured_by_its_length_and_kinds_of_character() {
        assert!(most_bits("s7919x1") < 128.0);
        assert!(most_bits("0123456789abcdef0123456789abcdef") >= 128.0);
        // Twenty-two base64 characters hold 128 bits and no more.
        assert!(most_bits("aB3dE5fG7hI9jK1lM3nO5p") >= 128.0);
        // An upper bound: a long run of one letter passes. It can only ever show an id too short.
        assert!(most_bits("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") >= 128.0);
        assert_eq!(most_bits(""), 0.0);
    }

    #[test]
    fn seed_and_sign_up_together_ask_both_the_admin_and_the_password_questions() {
        // `seed` makes the admin; `signup` is only used for the passwords, never for the test users.
        let mut u = with_signup();
        u.seed = Some("seed".into());
        u.admin = vec!["/admin".into()];
        let o = run_against(Flaws::default(), &u);
        assert!(o.findings.is_empty(), "{:#?}", o.findings);
        for id in [
            ADMIN_PAGE.rule_id,
            SHORT_PASSWORD.rule_id,
            COMMON_PASSWORD.rule_id,
        ] {
            assert!(verified_ids(&o).contains(&id), "{id}: {:?}", o.steps);
        }
    }

    #[test]
    fn a_sign_up_that_refuses_everybody_asks_no_password_question() {
        // The control is refused too, so no refusal can be put down to the password.
        let mut u = with_signup();
        u.seed = Some("seed".into());
        let o = run_against(
            Flaws {
                signup_closed: true,
                ..Default::default()
            },
            &u,
        );
        for id in [
            SHORT_PASSWORD.rule_id,
            COMMON_PASSWORD.rule_id,
            COMPOSITION_RULES.rule_id,
        ] {
            assert!(!verified_ids(&o).contains(&id), "{id} credited");
            assert!(!rule_ids(&o).contains(&id), "{id} found");
        }
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids.contains("V6.2.1") && why.contains("strong password")),
            "{:?}",
            o.not_assessed
        );
    }

    fn run_flow(flaws: Flaws, users: &UsersSection) -> Outcome {
        run_against(flaws, users)
    }

    fn flow_not_assessed(o: &Outcome) -> Option<&str> {
        o.not_assessed
            .iter()
            .find(|(ids, _)| ids == "V2.3.1")
            .map(|(_, why)| why.as_str())
    }

    #[test]
    fn a_flow_that_refuses_both_skips_is_supported_and_found_nothing() {
        let o = run_flow(Flaws::default(), &users());
        assert!(
            !rule_ids(&o).contains(&STEP_SKIPPED.rule_id),
            "{:?}",
            o.steps
        );
        assert!(
            verified_ids(&o).contains(&STEP_SKIPPED.rule_id),
            "{:?}\n{:?}",
            o.steps,
            o.not_assessed
        );
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("in order as A: finished")),
            "the control is not in the steps: {:?}",
            o.steps
        );
        assert_eq!(
            o.steps
                .iter()
                .filter(|s| s.starts_with("as B,") && s.ends_with("refused"))
                .count(),
            2,
            "both skips, straight to the end and past the middle: {:?}",
            o.steps
        );
    }

    #[test]
    fn a_step_that_can_be_skipped_is_found_whichever_way_it_is_skipped() {
        for (flaws, how) in [
            (
                Flaws {
                    flow_unguarded: true,
                    ..Default::default()
                },
                "straight to the last step",
            ),
            (
                Flaws {
                    flow_checks_first_only: true,
                    ..Default::default()
                },
                "the first step and then the last",
            ),
        ] {
            let o = run_flow(flaws, &users());
            let f = o
                .findings
                .iter()
                .find(|f| f.rule_id == STEP_SKIPPED.rule_id)
                .unwrap_or_else(|| panic!("{how}: not found: {:?}", o.steps));
            assert!(f.description.contains(how), "{how}: {}", f.description);
            assert!(
                !verified_ids(&o).contains(&STEP_SKIPPED.rule_id),
                "{how}: credited as well"
            );
        }
    }

    #[test]
    fn a_refusal_that_mentions_the_finishing_words_is_still_a_refusal() {
        // The owner's words can turn up on an error page ("an order is placed only after…"). An
        // answer counts as finished only when the app accepted it.
        let mut u = users();
        u.flow.as_mut().unwrap().completed = "placed".into();
        let o = run_flow(
            Flaws {
                flow_refusal_says_placed: true,
                ..Default::default()
            },
            &u,
        );
        assert!(
            !rule_ids(&o).contains(&STEP_SKIPPED.rule_id),
            "{:?}",
            o.steps
        );
        assert!(
            verified_ids(&o).contains(&STEP_SKIPPED.rule_id),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_refusal_that_sends_the_browser_back_to_the_start_is_a_refusal() {
        // 303 is an accepted status. Only the owner's words tell a redirect to the finished order
        // from a redirect back to step one.
        let o = run_flow(
            Flaws {
                flow_refusal_redirects: true,
                ..Default::default()
            },
            &users(),
        );
        assert!(
            !rule_ids(&o).contains(&STEP_SKIPPED.rule_id),
            "{:?}",
            o.steps
        );
        assert!(
            verified_ids(&o).contains(&STEP_SKIPPED.rule_id),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_flow_that_does_not_finish_in_order_says_so_and_credits_nothing() {
        // Every skip is refused by an app whose flow never finishes. That is not a guarded flow.
        let o = run_flow(
            Flaws {
                flow_broken: true,
                ..Default::default()
            },
            &users(),
        );
        assert!(
            !verified_ids(&o).contains(&STEP_SKIPPED.rule_id),
            "credited a broken flow"
        );
        assert!(!rule_ids(&o).contains(&STEP_SKIPPED.rule_id));
        let why = flow_not_assessed(&o).expect("V2.3.1 is named as not assessed");
        assert!(why.contains("in order as A"), "{why}");
    }

    #[test]
    fn a_two_step_flow_is_skipped_the_one_way_it_can_be() {
        let mut u = users();
        let flow = u.flow.as_mut().unwrap();
        flow.steps.remove(1);
        flow.steps[1].path = "/checkout/2".into();
        flow.completed = "next step".into();
        let o = run_flow(Flaws::default(), &u);
        let v = o
            .verified
            .iter()
            .find(|v| v.check_id == STEP_SKIPPED.rule_id)
            .unwrap_or_else(|| panic!("{:?}\n{:?}", o.steps, o.not_assessed));
        assert!(v.scope.contains("1 way,"), "{}", v.scope);
    }

    #[test]
    fn a_flow_described_too_thinly_to_try_is_not_assessed() {
        let mut one = users();
        one.flow.as_mut().unwrap().steps.truncate(1);
        let mut silent = users();
        silent.flow.as_mut().unwrap().completed = "  ".into();
        for (u, says) in [(one, "fewer than two"), (silent, "completed")] {
            let o = run_flow(Flaws::default(), &u);
            let why = flow_not_assessed(&o).unwrap_or_else(|| panic!("{says}: not named"));
            assert!(why.contains(says), "{why}");
            assert!(!verified_ids(&o).contains(&STEP_SKIPPED.rule_id));
        }
    }

    #[test]
    fn with_no_flow_nothing_is_said_about_v2_3_1() {
        let mut u = users();
        u.flow = None;
        let o = run_flow(Flaws::default(), &u);
        assert!(flow_not_assessed(&o).is_none());
        assert!(!verified_ids(&o).contains(&STEP_SKIPPED.rule_id));
        assert!(!rule_ids(&o).contains(&STEP_SKIPPED.rule_id));
    }

    /// Every reason given for not assessing `id`. V6.5.1 is also the emailed-code check's, whose
    /// reasons are not about two-factor codes, so a test looks through them all.
    fn totp_named(o: &Outcome, id: &str) -> Vec<String> {
        o.not_assessed
            .iter()
            .filter(|(ids, _)| ids.split(", ").any(|i| i == id))
            .map(|(_, why)| why.clone())
            .collect()
    }

    #[test]
    fn a_code_used_once_and_only_while_current_is_credited_for_both() {
        let o = run_against(Flaws::default(), &users());
        for rule in [&TOTP_REUSED, &TOTP_OLD_CODE] {
            assert!(!rule_ids(&o).contains(&rule.rule_id), "{:?}", o.steps);
            assert!(
                verified_ids(&o).contains(&rule.rule_id),
                "{} not credited: {:?}\n{:?}",
                rule.rule_id,
                o.steps,
                o.not_assessed
            );
        }
        assert!(
            o.steps
                .iter()
                .any(|s| s.starts_with("waited ") && s.ends_with("opened")),
            "the fresh code after the wait is the control, and it is not in the steps: {:?}",
            o.steps
        );
    }

    #[test]
    fn each_code_flaw_is_found_by_its_own_rule_and_the_other_is_still_credited() {
        for (flaws, found, credited) in [
            (
                Flaws {
                    totp_reusable: true,
                    ..Default::default()
                },
                &TOTP_REUSED,
                &TOTP_OLD_CODE,
            ),
            (
                Flaws {
                    totp_any_age: true,
                    ..Default::default()
                },
                &TOTP_OLD_CODE,
                &TOTP_REUSED,
            ),
        ] {
            let o = run_against(flaws, &users());
            assert!(
                rule_ids(&o).contains(&found.rule_id),
                "{}: {:?}",
                found.rule_id,
                o.steps
            );
            assert!(
                !verified_ids(&o).contains(&found.rule_id),
                "{} credited as well",
                found.rule_id
            );
            assert!(
                !rule_ids(&o).contains(&credited.rule_id),
                "{}",
                credited.rule_id
            );
            assert!(
                verified_ids(&o).contains(&credited.rule_id),
                "{}",
                credited.rule_id
            );
        }
    }

    #[test]
    fn nothing_about_codes_is_said_when_the_setup_does_not_hold() {
        // Three ways the control fails: the password alone lets the account in, no code ever
        // works, and the account locks after the first wrong code so the fresh one is refused.
        for (flaws, says) in [
            (
                Flaws {
                    totp_not_required: true,
                    ..Default::default()
                },
                "password alone",
            ),
            (
                Flaws {
                    totp_broken: true,
                    ..Default::default()
                },
                "did not sign the two-factor account in",
            ),
            (
                Flaws {
                    totp_locks: true,
                    ..Default::default()
                },
                "refused a fresh code as well",
            ),
            (
                Flaws {
                    totp_locks_at_once: true,
                    ..Default::default()
                },
                "did not sign the two-factor account in",
            ),
        ] {
            let o = run_against(flaws, &users());
            for (id, rule) in [("V6.5.1", &TOTP_REUSED), ("V6.5.5", &TOTP_OLD_CODE)] {
                assert!(
                    !verified_ids(&o).contains(&rule.rule_id),
                    "{says}: {id} credited"
                );
                assert!(!rule_ids(&o).contains(&rule.rule_id), "{says}: {id} found");
                let why = totp_named(&o, id);
                assert!(
                    why.iter().any(|w| w.contains(says)),
                    "{says}: {id}: {why:?}"
                );
            }
        }
    }

    #[test]
    fn without_seed_there_is_no_two_factor_account_and_it_says_so() {
        // Only `seed` can enroll an account, so a sign-up run has none, as the real runner does.
        let mut u = with_signup();
        u.totp = users().totp;
        let mut app = FakeApp::new(Flaws::default());
        let mut acc = accounts();
        acc.admin = None;
        acc.totp = None;
        let o = run(&mut app, &u, &acc, false, &Default::default());
        let why = totp_named(&o, "V6.5.5");
        assert!(why.iter().any(|w| w.contains("`seed`")), "{why:?}");
    }

    #[test]
    fn with_no_totp_entry_nothing_is_said_about_codes() {
        let mut u = users();
        u.totp = None;
        let o = run_against(Flaws::default(), &u);
        assert!(totp_named(&o, "V6.5.5").is_empty());
        for rule in [&TOTP_REUSED, &TOTP_OLD_CODE] {
            assert!(!verified_ids(&o).contains(&rule.rule_id));
            assert!(!rule_ids(&o).contains(&rule.rule_id));
        }
    }

    #[test]
    fn with_no_context_words_listed_v6_2_11_is_not_assessed_and_says_how_to_list_them() {
        // V6.2.11 asks that the *documented* list is used. Guessing at words would be testing a
        // list nobody wrote, so no list means nothing to hold the app to.
        let o = run_signing_up_with(
            Flaws {
                context_word_ok: true,
                ..Default::default()
            },
            &Default::default(),
        );
        assert!(
            !rule_ids(&o).contains(&CONTEXT_WORD_PASSWORD.rule_id),
            "found a fault against a list nobody wrote"
        );
        assert!(!verified_ids(&o).contains(&CONTEXT_WORD_PASSWORD.rule_id));
        let (_, why) = o
            .not_assessed
            .iter()
            .find(|(ids, _)| ids == "V6.2.11")
            .expect("V6.2.11 is named as not assessed");
        assert!(why.contains("context-words"), "{why}");
    }

    #[test]
    fn a_list_of_words_too_short_to_try_is_not_assessed_rather_than_padded() {
        let o = run_signing_up_with(Flaws::default(), &with_words(&["ab", "x!y"]));
        assert!(!verified_ids(&o).contains(&CONTEXT_WORD_PASSWORD.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids == "V6.2.11" && why.contains("between 4 and 32")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_refusal_that_also_refuses_the_control_credits_neither_new_rule() {
        // Composition rules refuse both the listed password and its random twin, since neither
        // has a capital. A refusal the control shares is about the shape, not the password.
        let o = run_signing_up(Flaws {
            composition_rules: true,
            ..Default::default()
        });
        for (id, rule) in [
            ("V6.2.12", BREACHED_PASSWORD.rule_id),
            ("V6.2.11", CONTEXT_WORD_PASSWORD.rule_id),
        ] {
            assert!(!verified_ids(&o).contains(&rule), "{rule} credited");
            assert!(!rule_ids(&o).contains(&rule), "{rule} found");
            assert!(
                o.not_assessed.iter().any(|(ids, _)| ids == id),
                "{id} not named: {:?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn the_breached_password_and_its_count_are_the_ones_the_evidence_records() {
        // The finding calls this password breached on the strength of one recorded check. Changing
        // the password, or the count the finding quotes, without new evidence must fail here.
        let evidence: serde_json::Value = serde_json::from_str(include_str!(
            "../../../data/breached-password-evidence.json"
        ))
        .expect("the evidence file parses");
        assert_eq!(
            evidence["password"], BREACHED,
            "a different password than the one checked"
        );
        let seen = evidence["seen"].as_u64().expect("a count");
        let sha1 = evidence["sha1"].as_str().expect("a hash");
        assert_eq!(
            evidence["line"].as_str(),
            Some(format!("{}:{seen}", &sha1[5..]).as_str()),
            "the recorded line is not the one for this hash"
        );
        let with_commas = seen
            .to_string()
            .as_bytes()
            .rchunks(3)
            .rev()
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            BREACHED_SEEN.starts_with(&format!("{with_commas} times")),
            "the finding says {BREACHED_SEEN:?}; the evidence says {seen}"
        );
    }

    #[test]
    fn the_control_has_the_same_shape_and_none_of_the_characters() {
        let spare = "0123456789abcdef0123456789abcdef";
        let twin = random_like(BREACHED, spare);
        assert_eq!(twin.len(), BREACHED.len());
        for (a, b) in BREACHED.chars().zip(twin.chars()) {
            assert_eq!(
                a.is_ascii_digit(),
                b.is_ascii_digit(),
                "{BREACHED} / {twin}"
            );
            assert_eq!(
                a.is_ascii_lowercase(),
                b.is_ascii_lowercase(),
                "{BREACHED} / {twin}"
            );
        }
        assert_ne!(twin, BREACHED);
        assert!(!twin.contains(CONTEXT_WORD));
    }

    #[test]
    fn the_context_password_is_the_word_repeated_past_any_length_rule() {
        let (word, password) = context_password(&["Hi".into(), "Acme Notes".into()]).unwrap();
        assert_eq!(word, "Acme Notes", "the first word long enough, as written");
        assert_eq!(password, "acmenotesacmenotes");
        assert!(password.len() >= 16);
        assert_eq!(context_password(&["ab".into()]), None);
        assert_eq!(context_password(&[]), None);
    }

    #[test]
    fn a_long_minimum_leaves_the_common_password_check_unanswerable_too() {
        // A second way the random password beside the common one is refused: it is shorter than
        // the app allows. The common one's refusal then says nothing about a list of passwords.
        let o = run_signing_up(Flaws {
            long_minimum: true,
            ..Default::default()
        });
        assert!(o.findings.is_empty(), "{:#?}", o.findings);
        assert!(!verified_ids(&o).contains(&COMMON_PASSWORD.rule_id));
        assert!(o.not_assessed.iter().any(|(ids, _)| ids == "V6.2.4"));
        // The rules it can answer, it still does.
        assert!(verified_ids(&o).contains(&SHORT_PASSWORD.rule_id));
    }

    #[test]
    fn a_sign_up_that_makes_no_account_asks_no_password_question_either() {
        // It answers as if it worked. Only signing in shows it did not.
        let mut u = with_signup();
        u.seed = Some("seed".into());
        let o = run_against(
            Flaws {
                signup_does_nothing: true,
                ..Default::default()
            },
            &u,
        );
        for id in [
            SHORT_PASSWORD.rule_id,
            COMMON_PASSWORD.rule_id,
            COMPOSITION_RULES.rule_id,
        ] {
            assert!(!verified_ids(&o).contains(&id), "{id} credited");
        }
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids.contains("V6.2.1") && why.contains("strong password"))
        );
    }

    #[test]
    fn beside_seed_a_common_password_accepted_is_found() {
        let mut u = with_signup();
        u.seed = Some("seed".into());
        let o = run_against(
            Flaws {
                common_password_ok: true,
                ..Default::default()
            },
            &u,
        );
        assert_eq!(rule_ids(&o), vec![COMMON_PASSWORD.rule_id], "{:?}", o.steps);
    }

    // -------------------------------------------------------------------------------------------
    // Holding the app to the number of wrong passwords the owner said it would allow (V6.3.1)
    // -------------------------------------------------------------------------------------------

    fn policy(failed: Option<u32>) -> sv_manifest::PolicySection {
        sv_manifest::PolicySection {
            failed_sign_ins: failed,
            within_minutes: Some(15),
            ..Default::default()
        }
    }

    fn run_with(flaws: Flaws, policy: &sv_manifest::PolicySection) -> Outcome {
        run_keeping_app(flaws, policy).0
    }

    /// The outcome and the app, for the assertions that are about what the app was *sent* rather
    /// than about what the report says.
    fn run_keeping_app(
        flaws: Flaws,
        policy: &sv_manifest::PolicySection,
    ) -> (Outcome, FakeApp, Accounts) {
        let mut app = FakeApp::new(flaws);
        let mut acc = accounts();
        acc.admin = None;
        acc.totp = None;
        let out = run(&mut app, &with_signup(), &acc, false, policy);
        (out, app, acc)
    }

    fn finding_ids(out: &Outcome) -> Vec<&str> {
        out.findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    #[test]
    fn an_app_that_never_pushes_back_is_a_finding() {
        let out = run_with(Flaws::default(), &policy(Some(3)));
        assert!(
            finding_ids(&out).contains(&"probe.failed-sign-ins-unlimited"),
            "got {:?}",
            finding_ids(&out)
        );
    }

    #[test]
    fn an_app_that_locks_out_at_the_stated_number_is_checked() {
        let flaws = Flaws {
            locks_out_after: Some(3),
            ..Flaws::default()
        };
        let out = run_with(flaws, &policy(Some(3)));
        assert!(
            !finding_ids(&out).contains(&"probe.failed-sign-ins-unlimited"),
            "an app that pushed back was reported anyway: {:?}",
            finding_ids(&out)
        );
        assert!(
            out.verified
                .iter()
                .any(|v| v.check_id == "probe.failed-sign-ins-unlimited"
                    && v.requirement_ids.iter().any(|r| r == "V6.3.1")),
            "and it must be credited: {:?}",
            out.verified
                .iter()
                .map(|v| v.check_id.as_str())
                .collect::<Vec<_>>()
        );
    }

    // The limits below are six, not three: a limit counting by address trips during the suite
    // itself, whose default-account check alone makes four wrong sign-ins in a row, and then the
    // brute-force check rightly finds the app already refusing and asks nothing, this included.
    fn forwarded_steps(out: &Outcome) -> Vec<&String> {
        out.steps
            .iter()
            .filter(|s| s.contains("claiming to come from"))
            .collect()
    }

    #[test]
    fn a_limit_that_believes_a_made_up_address_is_found() {
        let out = run_with(
            Flaws {
                locks_out_after: Some(6),
                limits_by_address: true,
                trusts_forwarded_for: true,
                ..Flaws::default()
            },
            &policy(Some(6)),
        );
        assert!(
            finding_ids(&out).contains(&FORWARDED_TRUSTED.rule_id),
            "{:?}\n{:?}",
            finding_ids(&out),
            out.steps
        );
        assert!(
            finding_ids(&out).len() == 1,
            "found only by its own rule: {:?}",
            finding_ids(&out)
        );
    }

    #[test]
    fn a_limit_that_ignores_the_header_is_not_found() {
        // By address and not trusting the header, and by account, which the header cannot touch.
        for flaws in [
            Flaws {
                locks_out_after: Some(6),
                limits_by_address: true,
                ..Flaws::default()
            },
            Flaws {
                locks_out_after: Some(6),
                trusts_forwarded_for: true,
                ..Flaws::default()
            },
        ] {
            let out = run_with(flaws, &policy(Some(6)));
            assert!(
                !finding_ids(&out).contains(&FORWARDED_TRUSTED.rule_id),
                "{:?}",
                out.steps
            );
            let steps = forwarded_steps(&out);
            assert_eq!(steps.len(), 1, "the attempt was made: {:?}", out.steps);
            assert!(steps[0].contains("still refused"), "{}", steps[0]);
        }
    }

    #[test]
    fn a_limit_that_lifts_by_itself_is_not_blamed_on_the_header() {
        // The control. The attempt claiming another address is answered normally, but so is the
        // one after it, claiming nothing: the limit lifted on its own. Counted by account, so the
        // suite's earlier wrong sign-ins cannot make it lift partway through the guessing.
        let out = run_with(
            Flaws {
                locks_out_after: Some(6),
                lockout_forgets: true,
                ..Flaws::default()
            },
            &policy(Some(6)),
        );
        assert!(
            !finding_ids(&out).contains(&FORWARDED_TRUSTED.rule_id),
            "{:?}",
            out.steps
        );
        let steps = forwarded_steps(&out);
        assert_eq!(steps.len(), 1, "{:?}", out.steps);
        assert!(
            steps[0].contains("claiming nothing: answered"),
            "the control must have run and lifted: {}",
            steps[0]
        );
    }

    #[test]
    fn with_no_limit_to_lift_no_address_is_claimed() {
        let out = run_with(Flaws::default(), &policy(Some(6)));
        assert!(forwarded_steps(&out).is_empty(), "{:?}", out.steps);
        assert!(!finding_ids(&out).contains(&FORWARDED_TRUSTED.rule_id));
    }

    #[test]
    fn an_app_that_pushes_back_too_late_is_still_a_finding() {
        // The number is the owner's claim, and the point of stating it is that the app is held to
        // it. An app that only gives way after twenty attempts has not implemented the policy that
        // says three, and a check that accepted any limiter at all would not be checking the claim.
        let flaws = Flaws {
            locks_out_after: Some(20),
            ..Flaws::default()
        };
        let out = run_with(flaws, &policy(Some(3)));
        assert!(
            finding_ids(&out).contains(&"probe.failed-sign-ins-unlimited"),
            "got {:?}",
            finding_ids(&out)
        );
    }

    #[test]
    fn without_a_stated_number_nothing_is_claimed_either_way() {
        // The honest default. An app nobody has stated a policy for is not thereby failing, and it
        // is certainly not passing: the report says which question would settle it.
        let out = run_with(Flaws::default(), &policy(None));
        assert!(!finding_ids(&out).contains(&"probe.failed-sign-ins-unlimited"));
        assert!(
            !out.verified
                .iter()
                .any(|v| v.check_id == "probe.failed-sign-ins-unlimited")
        );
        let said = out
            .not_assessed
            .iter()
            .find(|(ids, _)| ids.contains("V6.3.1"))
            .unwrap_or_else(|| {
                panic!(
                    "V6.3.1 must be named as not assessed: {:?}",
                    out.not_assessed
                )
            });
        assert!(
            said.1.contains("failed-sign-ins") && said.1.contains("[policy]"),
            "and it must say what to write: {}",
            said.1
        );
    }

    #[test]
    fn a_number_this_check_will_not_make_that_many_attempts_for_is_refused() {
        // A cap, so one check cannot turn into thousands of requests against somebody's app.
        let out = run_with(Flaws::default(), &policy(Some(500)));
        assert!(!finding_ids(&out).contains(&"probe.failed-sign-ins-unlimited"));
        assert!(
            out.not_assessed
                .iter()
                .any(|(ids, why)| ids.contains("V6.3.1") && why.contains("500")),
            "{:?}",
            out.not_assessed
        );
    }

    #[test]
    fn zero_is_refused_rather_than_read_as_one() {
        // Nobody means "refuse the first attempt anybody makes", and guessing that they meant one
        // would hold the app to a policy the owner did not state.
        let out = run_with(Flaws::default(), &policy(Some(0)));
        assert!(!finding_ids(&out).contains(&"probe.failed-sign-ins-unlimited"));
        assert!(
            out.not_assessed
                .iter()
                .any(|(ids, why)| ids.contains("V6.3.1") && why.contains("first attempt")),
            "{:?}",
            out.not_assessed
        );
    }

    #[test]
    fn an_app_already_refusing_before_the_first_attempt_is_not_credited() {
        // Found by session securevibe-e9 reviewing #104, after it had merged. `refused` read only
        // the last attempt, so an app answering 429 from the very first one satisfied it and
        // V6.3.1 was credited having tested nothing at all — a false *checked*, which is the one
        // outcome this report exists to prevent.
        //
        // Reachable exactly where the check is most careful: it runs last precisely because it
        // provokes refusals, and by then the suite has made dozens of sign-in attempts from one
        // address. A limiter counting by address is already tripped when this begins.
        //
        // Every refusal the guard names gets a case. With 429 alone, narrowing the guard to 429
        // was caught by nothing, and 423 and a dropped connection would have gone on being
        // credited.
        for status in [429, 423, 0] {
            let flaws = Flaws {
                already_refusing: Some(status),
                ..Flaws::default()
            };
            let out = run_with(flaws, &policy(Some(3)));
            assert!(
                !out.verified
                    .iter()
                    .any(|v| v.check_id == "probe.failed-sign-ins-unlimited"),
                "answering {status} from the first attempt proves nothing about the stated \
                 number, but it was credited"
            );
            assert!(
                !finding_ids(&out).contains(&"probe.failed-sign-ins-unlimited"),
                "and {status} is not a finding either: nothing was established"
            );
            let said = out
                .not_assessed
                .iter()
                .find(|(ids, _)| ids.contains("V6.3.1"))
                .unwrap_or_else(|| panic!("V6.3.1 must be named for {status}"));
            assert!(
                said.1.contains("already refusing"),
                "and the reason is worth telling the owner, because something earlier tripped a \
                 limiter: {}",
                said.1
            );
        }
    }

    #[test]
    fn the_guessing_never_touches_the_accounts_the_other_checks_need() {
        // The hazard this check has and no other does: it provokes the app into refusing requests.
        // If it guessed at A, an app that locks an account out would end the session every check
        // above depends on, and the run would start reporting faults of this check's own making.
        //
        // The first version of this test looped over `out.steps` looking for A's name — and no step
        // carries it, so the assertion could never fail. Deleting the safeguard was caught by
        // nothing. The promise is about which account is attacked, so the app records that.
        let flaws = Flaws {
            locks_out_after: Some(2),
            ..Flaws::default()
        };
        let (_out, app, acc) = run_keeping_app(flaws, &policy(Some(2)));
        assert!(
            !app.guessed_at.is_empty(),
            "no wrong password reached the app at all, so this proves nothing"
        );
        // Counted and labeled rather than printed. The accounts these come from carry generated
        // passwords, and a failure message is a log line like any other: nothing built from an
        // `Accounts` belongs in one, whatever the particular field happens to hold.
        for (label, who) in [("A", &acc.a.user), ("B", &acc.b.user)] {
            assert!(
                !app.guessed_at.contains(who),
                "the guessing attacked {label}, whose session the checks above depend on \
                 ({} accounts were guessed at)",
                app.guessed_at.len()
            );
        }
    }

    // ---- The private pages themselves: what they let a browser keep (V14.3.2), and whether they
    // show a way out (V7.4.4).

    #[test]
    fn no_cache_is_not_no_store() {
        // The distinction the whole check turns on, and the one an app is most likely to get
        // half-right. `no-cache` permits the browser to keep the copy and asks it to revalidate;
        // `private` only says not to keep it in a shared cache. Neither is what V14.3.2 asks for,
        // and a substring search for "no-store" inside "no-cache, private" would find nothing
        // anyway — what would pass wrongly is a looser reading of the header.
        for value in [
            "no-cache",
            "private",
            "max-age=0",
            "no-cache, private, max-age=0",
        ] {
            let mut app = FakeApp::new(Flaws::default());
            app.cache_control = Some(value.to_string());
            let acc = accounts();
            app.users
                .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
            app.users
                .insert(acc.b.user.clone(), (acc.b.password.clone(), false));
            let admin = acc.admin.clone().unwrap();
            app.users.insert(admin.user, (admin.password, true));
            let o = run(&mut app, &users(), &acc, true, &Default::default());
            assert!(
                rule_ids(&o).contains(&PRIVATE_PAGE_CACHING.rule_id),
                "`{value}` was accepted as no-store: {:?}",
                rule_ids(&o)
            );
            assert!(
                !verified_ids(&o).contains(&PRIVATE_PAGE_CACHING.rule_id),
                "`{value}` was credited as no-store"
            );
        }
    }

    #[test]
    fn the_run_note_counts_the_pages_that_answered_each_question() {
        // A second reading of the same two checks, on the surface the owner actually sees. The
        // findings list says something is wrong; this line says how much of the app was looked at,
        // and a check that silently examined nothing would still print a reassuring "0 of 0".
        let correct = run_against(Flaws::default(), &users());
        let steps = correct.steps.join(" | ");
        assert!(
            steps.contains("1 of 1 private page sent Cache-Control: no-store"),
            "{steps}"
        );
        assert!(
            steps.contains("1 of 1 private page showed a way to reach /logout"),
            "{steps}"
        );

        let mut app = FakeApp::new(Flaws::default());
        app.cache_control = Some("no-cache, private".to_string());
        let acc = accounts();
        app.users
            .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
        app.users
            .insert(acc.b.user.clone(), (acc.b.password.clone(), false));
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        let loose = run(&mut app, &users(), &acc, true, &Default::default());
        assert!(
            loose
                .steps
                .join(" | ")
                .contains("0 of 1 private page sent Cache-Control: no-store"),
            "`no-cache, private` was counted as no-store in the run note: {:?}",
            loose.steps
        );
    }

    #[test]
    fn no_store_among_other_directives_is_still_no_store() {
        // The other direction: a real app writes `no-store, max-age=0` or
        // `private, no-store, must-revalidate`, and refusing those would be a finding for every
        // app that gets this right.
        for value in [
            "no-store",
            "no-store, max-age=0",
            "private, no-store, must-revalidate",
            "No-Store",
        ] {
            let mut app = FakeApp::new(Flaws::default());
            app.cache_control = Some(value.to_string());
            let acc = accounts();
            app.users
                .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
            app.users
                .insert(acc.b.user.clone(), (acc.b.password.clone(), false));
            let admin = acc.admin.clone().unwrap();
            app.users.insert(admin.user, (admin.password, true));
            let o = run(&mut app, &users(), &acc, true, &Default::default());
            assert!(
                !rule_ids(&o).contains(&PRIVATE_PAGE_CACHING.rule_id),
                "`{value}` was refused as no-store"
            );
            assert!(
                verified_ids(&o).contains(&PRIVATE_PAGE_CACHING.rule_id),
                "`{value}` was not credited"
            );
        }
    }

    #[test]
    fn a_sign_out_address_only_mentioned_in_a_script_is_not_a_visible_way_out() {
        // `points_at` reads href and action attributes rather than searching the page for the
        // text. A page that names the sign-out address in a script string or a comment offers the
        // person nothing, and a substring search would have credited it.
        assert!(!points_at(
            "<script>const LOGOUT = '/logout';</script><!-- /logout -->",
            "/logout"
        ));
        assert!(!points_at("you can sign out at /logout one day", "/logout"));
        assert!(points_at("<a href='/logout'>Sign out</a>", "/logout"));
        assert!(points_at(
            "<form method='post' action='/logout'><button>out</button></form>",
            "/logout"
        ));
        // Spellings a real page uses, which must not cost an app the credit.
        assert!(points_at("<a href=\"/logout/\">out</a>", "/logout"));
        assert!(points_at("<a href=\"/logout?next=/\">out</a>", "/logout"));
        assert!(!points_at("<a href='/logout-help'>help</a>", "/logout"));
    }

    #[test]
    fn a_private_page_that_never_opened_answers_neither_question() {
        // The setup-first rule. If the signed-in session cannot open the private page, there are no
        // headers worth reading and no link worth looking for, and both requirements must come back
        // not assessed rather than as a pass or a finding.
        //
        // A page that never opens also stops the run before these checks are reached at all, so
        // what this really pins is that the bail-out names them: a requirement nothing asked about
        // has to be said out loud wherever the asking stopped.
        let mut broken = users();
        broken.private = vec!["/nowhere".into()];
        let o = run_against(Flaws::default(), &broken);
        assert!(
            !rule_ids(&o).contains(&PRIVATE_PAGE_CACHING.rule_id)
                && !rule_ids(&o).contains(&SIGN_OUT_LINK.rule_id),
            "a page that never opened produced a finding: {:?}",
            rule_ids(&o)
        );
        assert!(
            !verified_ids(&o).contains(&PRIVATE_PAGE_CACHING.rule_id)
                && !verified_ids(&o).contains(&SIGN_OUT_LINK.rule_id),
            "a page that never opened was credited"
        );
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, _)| ids.contains("V14.3.2") && ids.contains("V7.4.4")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn an_app_with_no_private_pages_listed_answers_neither_question() {
        // The other way to have nowhere to look. `private = []` reaches the checks rather than
        // bailing out before them, so this is the branch inside `private_page_checks` itself.
        let mut none = users();
        none.private = Vec::new();
        let o = run_against(Flaws::default(), &none);
        assert!(
            !rule_ids(&o).contains(&PRIVATE_PAGE_CACHING.rule_id)
                && !rule_ids(&o).contains(&SIGN_OUT_LINK.rule_id),
            "{:?}",
            rule_ids(&o)
        );
        assert!(
            !verified_ids(&o).contains(&PRIVATE_PAGE_CACHING.rule_id)
                && !verified_ids(&o).contains(&SIGN_OUT_LINK.rule_id),
            "nothing was read, so nothing may be credited"
        );
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, _)| ids.contains("V14.3.2") && ids.contains("V7.4.4")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn without_a_sign_out_address_the_link_question_is_not_asked() {
        // V7.4.4 needs somewhere to look for. With no `logout` in securevibe.toml, "no sign-out
        // link" would be a statement about the manifest rather than about the app — but the caching
        // question does not depend on it and must still be answered.
        let mut no_logout = users();
        no_logout.logout = None;
        let o = run_against(Flaws::default(), &no_logout);
        assert!(!rule_ids(&o).contains(&SIGN_OUT_LINK.rule_id));
        assert!(!verified_ids(&o).contains(&SIGN_OUT_LINK.rule_id));
        assert!(
            o.not_assessed.iter().any(|(ids, _)| ids.contains("V7.4.4")),
            "{:?}",
            o.not_assessed
        );
        assert!(
            verified_ids(&o).contains(&PRIVATE_PAGE_CACHING.rule_id),
            "the caching question does not depend on the sign-out address"
        );
    }

    // ---- Uploads (V5.2.1, V5.2.2, V5.3.1, V3.2.1)

    fn with_upload(serves_at: Option<&str>, max_bytes: Option<u64>) -> UsersSection {
        let mut u = users();
        u.upload = Some(sv_manifest::UploadSection {
            path: "/upload".into(),
            field: "file".into(),
            form: [("csrf_token".to_owned(), "{csrf}".to_owned())]
                .into_iter()
                .collect(),
            serves_at: serves_at.map(str::to_owned),
            max_bytes,
        });
        u
    }

    fn upload_run_keeping_app(flaws: Flaws, users: &UsersSection) -> (Outcome, FakeApp) {
        let mut app = FakeApp::new(flaws);
        let acc = accounts();
        app.users
            .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
        app.users
            .insert(acc.b.user.clone(), (acc.b.password.clone(), false));
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        let out = run(&mut app, users, &acc, true, &Default::default());
        (out, app)
    }

    #[test]
    fn the_cap_is_about_what_is_sent_not_only_about_what_is_reported() {
        // The second reading of the cap, on the thing it is actually for. Saying "not assessed" is
        // the report half; the half that matters to somebody's app is that no enormous body ever
        // left this process, and no finding or note can show that.
        let (_, app) = upload_run_keeping_app(
            Flaws::default(),
            &with_upload(Some("/files/{name}"), Some(64 * 1024 * 1024)),
        );
        assert!(
            (app.largest_upload as u64) <= MOST_UPLOAD_BYTES,
            "sent {} bytes, past the {MOST_UPLOAD_BYTES}-byte cap",
            app.largest_upload
        );
        // And it really did send something, so this cannot pass by never uploading at all.
        assert!(app.largest_upload > 0, "nothing was sent");
    }

    #[test]
    fn serving_the_source_and_serving_its_output_are_told_apart() {
        // V5.3.1 turns on one distinction: the file came back as written, or only what running it
        // produced. Both bodies contain the marker, so anything keyed on the marker alone cannot
        // tell them apart — which is exactly the wrong check to write here.
        let safe = run_against(
            Flaws::default(),
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        assert!(
            verified_ids(&safe).contains(&UPLOAD_EXECUTED.rule_id),
            "serving the source as-is should be credited: {:?}",
            safe.not_assessed
        );
        let unsafe_app = run_against(
            Flaws {
                runs_uploaded_code: true,
                ..Default::default()
            },
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        assert!(
            rule_ids(&unsafe_app).contains(&UPLOAD_EXECUTED.rule_id),
            "serving only the output should be a finding: {:?}",
            rule_ids(&unsafe_app)
        );
        assert!(!verified_ids(&unsafe_app).contains(&UPLOAD_EXECUTED.rule_id));
    }

    #[test]
    fn any_one_of_the_three_ways_to_stop_a_browser_rendering_counts() {
        // V3.2.1 asks that the browser not render the file as part of this app, and names several
        // ways. Insisting on one of them would report apps that chose another; accepting none of
        // them would credit every app. Both halves are asserted here.
        let served_safely = run_against(
            Flaws::default(),
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        assert!(verified_ids(&served_safely).contains(&UPLOAD_RENDERED.rule_id));
        let rendered = run_against(
            Flaws {
                renders_uploaded_pages: true,
                ..Default::default()
            },
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        assert!(
            rule_ids(&rendered).contains(&UPLOAD_RENDERED.rule_id),
            "an uploaded page served as text/html with nothing else is a finding: {:?}",
            rule_ids(&rendered)
        );
        assert!(!verified_ids(&rendered).contains(&UPLOAD_RENDERED.rule_id));
    }

    #[test]
    fn a_disposition_header_is_split_the_way_rfc_6266_means_it() {
        // A `;` inside a quoted name is part of the name; outside quotes it starts a parameter.
        // Splitting naively on `;` would be the very bug V5.4.2 is about.
        let quoted = disposition_params(r#"attachment; filename="sv-probe;svinjected=1.gif""#);
        assert!(!quoted.iter().any(|(k, _)| k == "svinjected"), "{quoted:?}");
        assert!(
            quoted
                .iter()
                .any(|(k, v)| k == "filename" && v == "sv-probe;svinjected=1.gif")
        );

        let raw = disposition_params("attachment; filename=sv-probe;svinjected=1.gif");
        assert!(raw.iter().any(|(k, _)| k == "svinjected"), "{raw:?}");

        // An escaped quote stays inside the quoted string rather than ending it.
        let escaped = disposition_params(r#"attachment; filename="a\"b;svinjected=1.gif""#);
        assert!(
            !escaped.iter().any(|(k, _)| k == "svinjected"),
            "{escaped:?}"
        );

        let star = disposition_params("attachment; filename*=UTF-8''sv-probe%3Bsvinjected%3D1.gif");
        assert!(star.iter().any(|(k, _)| k == "filename*"));
        assert!(!star.iter().any(|(k, _)| k == "svinjected"));
    }

    #[test]
    fn a_download_is_named_and_a_hostile_name_does_not_break_its_header() {
        let o = run_against(
            Flaws::default(),
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        for rule in [DOWNLOAD_UNNAMED.rule_id, DOWNLOAD_NAME_INJECTED.rule_id] {
            assert!(
                verified_ids(&o).contains(&rule),
                "{rule} was not confirmed: {:?}",
                o.not_assessed
            );
            assert!(
                !rule_ids(&o).contains(&rule),
                "{rule} also raised a finding"
            );
        }
    }

    #[test]
    fn each_download_fault_is_found_by_its_own_rule() {
        for (flaw, rule) in [
            (
                Flaws {
                    download_no_filename: true,
                    ..Default::default()
                },
                DOWNLOAD_UNNAMED.rule_id,
            ),
            (
                Flaws {
                    download_name_raw: true,
                    ..Default::default()
                },
                DOWNLOAD_NAME_INJECTED.rule_id,
            ),
        ] {
            let o = run_against(
                flaw,
                &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
            );
            let found = rule_ids(&o);
            assert!(found.contains(&rule), "{rule} did not fire: {found:?}");
            let other = if rule == DOWNLOAD_UNNAMED.rule_id {
                DOWNLOAD_NAME_INJECTED.rule_id
            } else {
                DOWNLOAD_UNNAMED.rule_id
            };
            assert!(
                !found.contains(&other),
                "{rule}'s fault also raised {other}"
            );
        }
    }

    #[test]
    fn a_quoted_name_with_a_semicolon_in_it_is_correct_and_credited() {
        // The second witness for reading the header properly, end to end. Quoting is enough under
        // RFC 6266 — the app does not have to clean the name as well — and a check that split on
        // every `;` would accuse this correct app of the exact fault it avoided.
        let o = run_against(
            Flaws {
                download_name_quoted_uncleaned: true,
                ..Default::default()
            },
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        assert!(
            !rule_ids(&o).contains(&DOWNLOAD_NAME_INJECTED.rule_id),
            "a correctly quoted name was reported as injected: {:?}",
            rule_ids(&o)
        );
        assert!(verified_ids(&o).contains(&DOWNLOAD_NAME_INJECTED.rule_id));
    }

    #[test]
    fn the_run_note_says_when_a_name_broke_the_header() {
        // Second witness for the injection finding, on the surface the owner reads.
        let o = run_against(
            Flaws {
                download_name_raw: true,
                ..Default::default()
            },
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        let note = o.steps.join(" | ");
        assert!(note.contains("its name broke the header"), "{note}");
        let fine = run_against(
            Flaws::default(),
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        assert!(
            fine.steps
                .join(" | ")
                .contains("its name was served intact")
        );
    }

    #[test]
    fn the_run_note_says_when_a_download_has_no_name() {
        // Second witness for V5.4.1, on the note rather than the verdict: "served under a name" and
        // "served with no file name" are what the owner reads, and a check that stopped telling
        // them apart would leave the findings list looking clean.
        let unnamed = run_against(
            Flaws {
                download_no_filename: true,
                ..Default::default()
            },
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        let note = unnamed.steps.join(" | ");
        assert!(note.contains("served with no file name"), "{note}");
        assert!(
            !note.contains("upload back from /files/sv-probe.gif: served under a name"),
            "{note}"
        );

        let named = run_against(
            Flaws::default(),
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        assert!(named.steps.join(" | ").contains("served under a name"));
    }

    #[test]
    fn with_no_file_name_served_the_hostile_name_has_nothing_to_break() {
        // V5.4.2 is about a name that is served. When none is, there is nothing to judge, and the
        // absence is V5.4.1's finding to make, not V5.4.2's.
        let o = run_against(
            Flaws {
                download_no_filename: true,
                ..Default::default()
            },
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        assert!(!rule_ids(&o).contains(&DOWNLOAD_NAME_INJECTED.rule_id));
        assert!(!verified_ids(&o).contains(&DOWNLOAD_NAME_INJECTED.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(id, why)| id == "V5.4.2" && why.contains("no file name")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_correct_app_confirms_all_four_upload_questions() {
        let o = run_against(
            Flaws::default(),
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        for rule in [
            OVERSIZED_FILE.rule_id,
            CONTENT_MISMATCH.rule_id,
            UPLOAD_EXECUTED.rule_id,
            UPLOAD_RENDERED.rule_id,
        ] {
            assert!(
                verified_ids(&o).contains(&rule),
                "{rule} was not confirmed: {:?} / {:?}",
                verified_ids(&o),
                o.not_assessed
            );
            assert!(
                !rule_ids(&o).contains(&rule),
                "{rule} also raised a finding"
            );
        }
    }

    #[test]
    fn each_upload_flaw_is_found_by_its_own_rule_and_by_no_other() {
        for (flaw, rule) in [
            (
                Flaws {
                    oversized_upload_ok: true,
                    ..Default::default()
                },
                OVERSIZED_FILE.rule_id,
            ),
            (
                Flaws {
                    unchecked_contents_ok: true,
                    ..Default::default()
                },
                CONTENT_MISMATCH.rule_id,
            ),
            (
                Flaws {
                    runs_uploaded_code: true,
                    ..Default::default()
                },
                UPLOAD_EXECUTED.rule_id,
            ),
            (
                Flaws {
                    renders_uploaded_pages: true,
                    ..Default::default()
                },
                UPLOAD_RENDERED.rule_id,
            ),
        ] {
            let o = run_against(
                flaw,
                &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
            );
            let found = rule_ids(&o);
            assert!(found.contains(&rule), "{rule} did not fire: {found:?}");
            let others: Vec<&str> = found
                .iter()
                .copied()
                .filter(|f| {
                    *f != rule
                        && [
                            OVERSIZED_FILE.rule_id,
                            CONTENT_MISMATCH.rule_id,
                            UPLOAD_EXECUTED.rule_id,
                            UPLOAD_RENDERED.rule_id,
                        ]
                        .contains(f)
                })
                .collect();
            assert!(others.is_empty(), "{rule}'s flaw also raised {others:?}");
        }
    }

    #[test]
    fn an_upload_that_refuses_everything_answers_nothing() {
        // The setup-first rule, and the one that matters most here: an app whose upload path is not
        // what securevibe.toml says refuses every file, and "refused" is what each of these checks
        // is looking for. Without the ordinary file first, a broken upload would read as four
        // passes — the most flattering possible result for the least working app.
        let o = run_against(
            Flaws {
                upload_broken: true,
                ..Default::default()
            },
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        for rule in [
            OVERSIZED_FILE.rule_id,
            CONTENT_MISMATCH.rule_id,
            UPLOAD_EXECUTED.rule_id,
            UPLOAD_RENDERED.rule_id,
        ] {
            assert!(!verified_ids(&o).contains(&rule), "{rule} was credited");
            assert!(!rule_ids(&o).contains(&rule), "{rule} raised a finding");
        }
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids.contains("V5.2.1")
                    && ids.contains("V3.2.1")
                    && why.contains("ordinary file")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn the_run_note_never_claims_an_upload_that_did_not_happen() {
        // The second reading of the setup proof, on the surface the owner sees. The findings list
        // can be empty for two very different reasons — nothing was wrong, or nothing was asked —
        // and the run note is where those are told apart. An app that refused every file must not
        // leave a line saying a file went in.
        let broken = run_against(
            Flaws {
                upload_broken: true,
                ..Default::default()
            },
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        let note = broken.steps.join(" | ");
        assert!(
            !note.contains("uploaded an ordinary"),
            "the note says a file was uploaded to an app that refused every one: {note}"
        );
        assert!(
            !note.contains("stated limit") && !note.contains("not a GIF"),
            "the note describes files that were never really tried: {note}"
        );

        // And the opposite, so this cannot pass by the note always being empty.
        let working = run_against(
            Flaws::default(),
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        let note = working.steps.join(" | ");
        assert!(note.contains("uploaded an ordinary"), "{note}");
        assert!(note.contains("stated limit"), "{note}");
    }

    #[test]
    fn without_a_stated_size_the_oversize_question_is_not_asked() {
        // V5.2.1 is a documented-policy requirement like V6.3.1: prose cannot be checked, a number
        // can. With no number there is nothing to hold the app to, and the other three still run.
        let o = run_against(Flaws::default(), &with_upload(Some("/files/{name}"), None));
        assert!(!verified_ids(&o).contains(&OVERSIZED_FILE.rule_id));
        assert!(!rule_ids(&o).contains(&OVERSIZED_FILE.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids.contains("V5.2.1") && why.contains("max-bytes")),
            "{:?}",
            o.not_assessed
        );
        assert!(
            verified_ids(&o).contains(&CONTENT_MISMATCH.rule_id),
            "the other questions do not depend on the stated size"
        );
    }

    #[test]
    fn a_size_beyond_the_cap_is_refused_rather_than_sent() {
        // One check must not become a denial-of-service attempt against somebody's own app.
        let o = run_against(
            Flaws::default(),
            &with_upload(Some("/files/{name}"), Some(64 * 1024 * 1024)),
        );
        assert!(!verified_ids(&o).contains(&OVERSIZED_FILE.rule_id));
        assert!(!rule_ids(&o).contains(&OVERSIZED_FILE.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids.contains("V5.2.1") && why.contains("denial-of-service")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn without_serves_at_nothing_is_claimed_about_what_is_served() {
        // An app that stores uploads where no URL reaches them is the safest arrangement there is.
        // Reporting it as a failure, or as a pass, would both be wrong.
        let o = run_against(
            Flaws::default(),
            &with_upload(None, Some(UPLOAD_LIMIT as u64)),
        );
        for rule in [UPLOAD_EXECUTED.rule_id, UPLOAD_RENDERED.rule_id] {
            assert!(!verified_ids(&o).contains(&rule), "{rule} was credited");
            assert!(!rule_ids(&o).contains(&rule), "{rule} raised a finding");
        }
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, _)| ids.contains("V5.3.1") && ids.contains("V3.2.1")),
            "{:?}",
            o.not_assessed
        );
        // The two that need no serving still ran.
        assert!(verified_ids(&o).contains(&OVERSIZED_FILE.rule_id));
        assert!(verified_ids(&o).contains(&CONTENT_MISMATCH.rule_id));
    }

    #[test]
    fn no_upload_entry_means_the_questions_are_never_raised() {
        // An app with no `upload` entry is not an app that failed these; it is one nobody asked.
        let o = run_against(Flaws::default(), &users());
        for rule in [
            OVERSIZED_FILE.rule_id,
            CONTENT_MISMATCH.rule_id,
            UPLOAD_EXECUTED.rule_id,
            UPLOAD_RENDERED.rule_id,
        ] {
            assert!(!verified_ids(&o).contains(&rule));
            assert!(!rule_ids(&o).contains(&rule));
        }
    }

    // --------------------------------------------------------------------------------------------
    // Password reset, through the mail sink

    const RESET_RULES: [&str; 4] = [
        RESET_REUSABLE.rule_id,
        RESET_KEEPS_OLD.rule_id,
        RESET_CODE_GUESSABLE.rule_id,
        RESET_REVEALS_ACCOUNT.rule_id,
    ];

    fn reset_findings(o: &Outcome) -> Vec<&str> {
        rule_ids(o)
            .into_iter()
            .filter(|id| RESET_RULES.contains(id))
            .collect()
    }

    fn reset_not_assessed(o: &Outcome) -> Vec<&str> {
        o.not_assessed
            .iter()
            .filter(|(ids, _)| ids.contains("V6.4.3"))
            .map(|(_, why)| why.as_str())
            .collect()
    }

    #[test]
    fn a_reset_that_works_once_is_followed_through_and_faults_nothing() {
        let o = run_against(Flaws::default(), &users());
        assert!(reset_findings(&o).is_empty(), "{:#?}", o.findings);
        // The setup was really shown to work: the email arrived, and its code set a password
        // that then signed in. Without these the quiet above would mean nothing.
        let steps = o.steps.join("\n");
        assert!(
            steps.contains("2 emails arrived for b@example.test"),
            "{steps}"
        );
        for step in [
            "the password the reset set signed in",
            "the password from before the reset was refused",
            "the password the used code tried to set was refused",
        ] {
            assert!(steps.contains(step), "{step}:\n{steps}");
        }
        // And it credits nothing, saying what it did not try.
        assert!(!verified_ids(&o).iter().any(|id| RESET_RULES.contains(id)));
        let why = reset_not_assessed(&o);
        assert_eq!(why.len(), 1, "{why:?}");
        assert!(why[0].contains("two-factor"), "{why:?}");
    }

    #[test]
    fn each_fault_in_a_reset_is_found_by_its_own_rule() {
        let cases: [(Flaws, &str); 6] = [
            (
                Flaws {
                    reset_reusable: true,
                    ..Default::default()
                },
                RESET_REUSABLE.rule_id,
            ),
            (
                Flaws {
                    reset_keeps_old: true,
                    ..Default::default()
                },
                RESET_KEEPS_OLD.rule_id,
            ),
            (
                Flaws {
                    reset_short_code: true,
                    ..Default::default()
                },
                RESET_CODE_GUESSABLE.rule_id,
            ),
            (
                Flaws {
                    reset_counting_codes: true,
                    ..Default::default()
                },
                RESET_CODE_GUESSABLE.rule_id,
            ),
            (
                Flaws {
                    reset_reveals_by_status: true,
                    ..Default::default()
                },
                RESET_REVEALS_ACCOUNT.rule_id,
            ),
            (
                Flaws {
                    reset_reveals_by_words: true,
                    ..Default::default()
                },
                RESET_REVEALS_ACCOUNT.rule_id,
            ),
        ];
        for (flaws, rule) in cases {
            let o = run_against(flaws, &users());
            assert_eq!(
                reset_findings(&o),
                vec![rule],
                "{rule}: {:#?}\n{:?}",
                o.findings,
                o.steps
            );
        }
    }

    #[test]
    fn a_reset_that_changes_nothing_is_not_assessed_however_else_it_is_broken() {
        // Reusable and keeping the old password, in an app whose reset does nothing at all: the
        // old password "still works" and a second use "does nothing new" for a reason that has
        // nothing to do with either, and neither may be reported off the back of it.
        let o = run_against(
            Flaws {
                reset_does_nothing: true,
                reset_reusable: true,
                reset_keeps_old: true,
                ..Default::default()
            },
            &users(),
        );
        assert!(reset_findings(&o).is_empty(), "{:#?}", o.findings);
        assert!(
            reset_not_assessed(&o)
                .iter()
                .any(|w| w.contains("did not change the password")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn with_no_email_to_read_a_reset_is_not_assessed_and_says_why() {
        for (flaws, why) in [
            (
                Flaws {
                    no_mail_sink: true,
                    reset_reusable: true,
                    ..Default::default()
                },
                "no mail server",
            ),
            (
                Flaws {
                    reset_sends_nothing: true,
                    reset_reusable: true,
                    ..Default::default()
                },
                "sent no email",
            ),
            (
                Flaws {
                    reset_code_elsewhere: true,
                    reset_reusable: true,
                    ..Default::default()
                },
                "no code was found",
            ),
        ] {
            let o = run_against(flaws, &users());
            assert!(
                !reset_findings(&o).contains(&RESET_REUSABLE.rule_id),
                "{why}: {:#?}",
                o.findings
            );
            assert!(
                reset_not_assessed(&o).iter().any(|w| w.contains(why)),
                "{why}: {:?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn a_code_pattern_finds_a_code_the_defaults_miss_and_a_broken_one_is_refused() {
        let mut u = users();
        u.reset.as_mut().unwrap().code_pattern = Some(r"reset number is ([0-9a-f]+)".into());
        let flaws = Flaws {
            reset_code_elsewhere: true,
            reset_reusable: true,
            ..Default::default()
        };
        let o = run_against(flaws, &u);
        assert_eq!(
            reset_findings(&o),
            vec![RESET_REUSABLE.rule_id],
            "{:?}",
            o.steps
        );

        u.reset.as_mut().unwrap().code_pattern = Some(r"reset number is [0-9a-f]+".into());
        let o = run_against(flaws, &u);
        assert!(reset_findings(&o).is_empty());
        assert!(
            reset_not_assessed(&o)
                .iter()
                .any(|w| w.contains("code-pattern") && w.contains("no group")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn with_a_sign_up_the_reset_uses_an_account_of_its_own() {
        let mut app = FakeApp::new(Flaws {
            reset_reusable: true,
            ..Default::default()
        });
        let mut acc = accounts();
        acc.admin = None;
        acc.totp = None;
        let o = run(&mut app, &with_signup(), &acc, false, &Default::default());
        assert_eq!(reset_findings(&o), vec![RESET_REUSABLE.rule_id]);
        assert!(
            app.outbox
                .iter()
                .filter(|(_, text)| text.contains("Reset"))
                .all(|(to, _)| to == "reset.a@example.test"),
            "only the account made for it is ever sent a reset: {:?}",
            app.outbox
        );
        // A and B keep the passwords they started with.
        assert_eq!(app.users[&acc.a.user].0, acc.a.password);
        assert_eq!(app.users[&acc.b.user].0, acc.b.password);
    }

    #[test]
    fn a_code_is_found_in_a_link_however_the_email_writes_it() {
        let p = code_patterns(None, "reset").unwrap();
        for (mail, code) in [
            ("Go to http://app/reset?token=abc123XYZ now", "abc123XYZ"),
            (
                "<a href=\"http://app/reset?uid=4&amp;token=k9%2Dz_Q\">Reset</a>",
                "k9-z_Q",
            ),
            (
                "https://app.test/password/reset/9f8e7d6c5b4a3210\r\n",
                "9f8e7d6c5b4a3210",
            ),
            ("http://app/forgot?reset_code=77aa99bb", "77aa99bb"),
        ] {
            assert_eq!(reset_code(mail, &p).as_deref(), Some(code), "{mail}");
        }
        assert_eq!(reset_code("Thanks for signing up. http://app/", &p), None);
    }

    #[test]
    fn six_random_digits_pass_and_fewer_or_counting_do_not() {
        let judged = |codes: &[&str]| {
            let mut out = Outcome::default();
            let codes: Vec<String> = codes.iter().map(|c| (*c).to_owned()).collect();
            reset_code_check(&codes, &mut out);
            out.findings.len()
        };
        assert_eq!(judged(&["482913", "117204"]), 0);
        assert_eq!(judged(&["9f86d081884c7d659a2feaa0c55ad015"]), 0);
        assert_eq!(judged(&["4829", "1172"]), 1);
        assert_eq!(judged(&["482913", "482914"]), 1);
        assert_eq!(judged(&["482913", "483913"]), 1);
        assert_eq!(judged(&["482913", "483914"]), 0);
    }

    #[test]
    fn two_answers_differing_only_in_what_every_answer_changes_are_the_same_shape() {
        let a = same_shape(
            "<input value=\"9f86d081884c7d659a2f\">If a@x.test has an account",
            "a@x.test",
        );
        let b = same_shape(
            "<input value='0c55ad0159f86d081884'>If nobody@x.test has an account",
            "nobody@x.test",
        );
        assert_eq!(a, b);
        let c = same_shape("There is no account for nobody%40x.test", "nobody@x.test");
        let d = same_shape("There is no account for a@x.test", "a@x.test");
        assert_eq!(c, d);
        assert_ne!(a, c);
    }

    #[test]
    fn the_same_faults_are_found_with_an_account_made_for_the_reset() {
        // The same rules through the other way of getting an account, so no rule rests on the
        // seeded fixture alone.
        for (flaws, rule) in [
            (
                Flaws {
                    reset_keeps_old: true,
                    ..Default::default()
                },
                RESET_KEEPS_OLD.rule_id,
            ),
            (
                Flaws {
                    reset_reveals_by_status: true,
                    ..Default::default()
                },
                RESET_REVEALS_ACCOUNT.rule_id,
            ),
            (
                Flaws {
                    reset_reveals_by_words: true,
                    ..Default::default()
                },
                RESET_REVEALS_ACCOUNT.rule_id,
            ),
        ] {
            let o = run_signing_up(flaws);
            assert_eq!(reset_findings(&o), vec![rule], "{rule}: {:?}", o.steps);
        }
        let o = run_signing_up(Flaws {
            no_mail_sink: true,
            reset_reusable: true,
            ..Default::default()
        });
        assert!(reset_findings(&o).is_empty());
        assert!(
            reset_not_assessed(&o)
                .iter()
                .any(|w| w.contains("no mail server")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn answers_that_differ_between_identical_requests_are_not_held_against_the_app() {
        for users in [users(), with_signup()] {
            let mut app = FakeApp::new(Flaws {
                reset_answer_counts: true,
                ..Default::default()
            });
            let mut acc = accounts();
            let seeded = users.seed.is_some();
            if seeded {
                for account in [&acc.a, &acc.b] {
                    app.users
                        .insert(account.user.clone(), (account.password.clone(), false));
                }
            }
            if !seeded {
                acc.admin = None;
                acc.totp = None;
                acc.totp = None;
            } else {
                let admin = acc.admin.clone().unwrap();
                app.users.insert(admin.user, (admin.password, true));
            }
            let o = run(&mut app, &users, &acc, seeded, &Default::default());
            assert!(reset_findings(&o).is_empty(), "{:#?}", o.findings);
            // And the comparison really ran: all three requests were answered.
            assert!(
                o.steps
                    .iter()
                    .any(|s| s.contains("twice (200, 200)") && s.contains("no account (200)")),
                "{:?}",
                o.steps
            );
        }
    }

    #[test]
    fn a_reset_that_changes_nothing_through_sign_up_is_not_assessed_either() {
        let o = run_signing_up(Flaws {
            reset_does_nothing: true,
            reset_reusable: true,
            reset_keeps_old: true,
            ..Default::default()
        });
        assert!(reset_findings(&o).is_empty(), "{:#?}", o.findings);
        assert!(
            reset_not_assessed(&o)
                .iter()
                .any(|w| w.contains("did not change the password")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn wording_is_judged_only_when_two_requests_for_the_same_account_agree() {
        let answer = |status: u16, body: &str| {
            Some(ProbeResponse {
                id: String::new(),
                status,
                headers: Vec::new(),
                body: body.to_owned(),
            })
        };
        let judged = |first: &Option<ProbeResponse>, second: &Option<ProbeResponse>| {
            let stranger = answer(200, "Sent. Ticket 9.");
            let mut out = Outcome::default();
            reveals_account_check(
                [first, second, &stranger],
                "a@x.test",
                "n@x.test",
                "/forgot",
                &mut out,
            );
            out.findings.len()
        };
        // The pair disagrees with itself, so a third answer that differs shows nothing.
        assert_eq!(
            judged(
                &answer(200, "Sent. Ticket 7."),
                &answer(200, "Sent. Ticket 8.")
            ),
            0
        );
        // The pair agrees, and the third answer does not.
        assert_eq!(
            judged(
                &answer(200, "Sent. Ticket 7."),
                &answer(200, "Sent. Ticket 7.")
            ),
            1
        );
    }

    // --------------------------------------------------------------------------------------------
    // Signing in with an emailed code

    const CODE_RULES: [&str; 4] = [
        EMAIL_CODE_REUSABLE.rule_id,
        EMAIL_CODE_UNBOUND.rule_id,
        EMAIL_CODE_SHORT.rule_id,
        EMAIL_CODE_GUESSING.rule_id,
    ];

    fn code_findings(o: &Outcome) -> Vec<&str> {
        rule_ids(o)
            .into_iter()
            .filter(|id| CODE_RULES.contains(id))
            .collect()
    }

    fn code_credits(o: &Outcome) -> Vec<&str> {
        verified_ids(o)
            .into_iter()
            .filter(|id| CODE_RULES.contains(id))
            .collect()
    }

    fn code_not_assessed(o: &Outcome) -> Vec<&str> {
        o.not_assessed
            .iter()
            .filter(|(ids, _)| ids.contains("V6.5.1") || ids.contains("V6.6."))
            .map(|(_, why)| why.as_str())
            .collect()
    }

    fn codes_policy(n: u32) -> sv_manifest::PolicySection {
        sv_manifest::PolicySection {
            failed_codes: Some(n),
            ..Default::default()
        }
    }

    #[test]
    fn a_code_that_works_once_where_it_was_asked_for_is_credited() {
        for o in [
            run_against(Flaws::default(), &users()),
            run_signing_up(Flaws::default()),
        ] {
            assert!(code_findings(&o).is_empty(), "{:#?}", o.findings);
            assert_eq!(
                code_credits(&o),
                vec![EMAIL_CODE_UNBOUND.rule_id],
                "{:?}",
                o.steps
            );
            // A code tied to its session cannot be tried twice from another, so single use is
            // not credited on a refusal there.
            assert!(
                o.not_assessed
                    .iter()
                    .any(|(ids, why)| ids == "V6.5.1" && why.contains("tied to the session")),
                "{:?}",
                o.not_assessed
            );
            // Guessing is held to a stated number, and none was stated.
            assert!(
                o.not_assessed
                    .iter()
                    .any(|(ids, why)| ids == "V6.6.3" && why.contains("failed-codes")),
                "{:?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn each_fault_in_a_sign_in_code_is_found_by_its_own_rule() {
        for (flaws, found) in [
            (
                Flaws {
                    code_reusable: true,
                    code_unbound: true,
                    ..Default::default()
                },
                vec![EMAIL_CODE_UNBOUND.rule_id, EMAIL_CODE_REUSABLE.rule_id],
            ),
            (
                Flaws {
                    code_unbound: true,
                    ..Default::default()
                },
                vec![EMAIL_CODE_UNBOUND.rule_id],
            ),
            (
                Flaws {
                    code_short: true,
                    ..Default::default()
                },
                vec![EMAIL_CODE_SHORT.rule_id],
            ),
        ] {
            for o in [run_against(flaws, &users()), run_signing_up(flaws)] {
                assert_eq!(code_findings(&o), found, "{found:?}: {:?}", o.steps);
                for rule in &found {
                    assert!(
                        !code_credits(&o).contains(rule),
                        "{rule} both found and credited"
                    );
                }
            }
        }
        // A code that works from any session but only once: the one case where a refused second
        // use is credited.
        let flaws = Flaws {
            code_unbound: true,
            ..Default::default()
        };
        for o in [run_against(flaws, &users()), run_signing_up(flaws)] {
            assert_eq!(
                code_credits(&o),
                vec![EMAIL_CODE_REUSABLE.rule_id],
                "{:?}",
                o.steps
            );
        }
    }

    #[test]
    fn guessing_is_held_to_the_stated_number_of_wrong_codes() {
        let o = run_with(Flaws::default(), &codes_policy(3));
        assert!(
            code_credits(&o).contains(&EMAIL_CODE_GUESSING.rule_id),
            "{:?}\n{:?}",
            o.steps,
            o.not_assessed
        );
        assert!(!code_findings(&o).contains(&EMAIL_CODE_GUESSING.rule_id));

        let o = run_with(
            Flaws {
                code_guessing_unlimited: true,
                ..Default::default()
            },
            &codes_policy(3),
        );
        assert_eq!(
            code_findings(&o),
            vec![EMAIL_CODE_GUESSING.rule_id],
            "{:?}",
            o.steps
        );
        // And through the seeded fixture, with A's own address.
        let mut app = FakeApp::new(Flaws {
            code_guessing_unlimited: true,
            ..Default::default()
        });
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        let o = run(&mut app, &users(), &acc, true, &codes_policy(3));
        assert_eq!(code_findings(&o), vec![EMAIL_CODE_GUESSING.rule_id]);
    }

    #[test]
    fn guessing_is_not_judged_on_a_number_it_cannot_reach() {
        for n in [0, 25, 400] {
            let o = run_with(
                Flaws {
                    code_guessing_unlimited: true,
                    ..Default::default()
                },
                &codes_policy(n),
            );
            assert!(
                !code_findings(&o).contains(&EMAIL_CODE_GUESSING.rule_id),
                "{n}"
            );
            assert!(
                !code_credits(&o).contains(&EMAIL_CODE_GUESSING.rule_id),
                "{n}"
            );
        }
    }

    #[test]
    fn a_sign_in_code_that_signs_nobody_in_is_not_assessed_however_else_it_is_broken() {
        let flaws = Flaws {
            code_does_nothing: true,
            code_reusable: true,
            code_unbound: true,
            ..Default::default()
        };
        for o in [run_against(flaws, &users()), run_signing_up(flaws)] {
            assert!(code_findings(&o).is_empty(), "{:#?}", o.findings);
            assert!(code_credits(&o).is_empty(), "{:?}", code_credits(&o));
            assert!(
                code_not_assessed(&o)
                    .iter()
                    .any(|w| w.contains("did not open")),
                "{:?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn with_no_sign_in_email_to_read_nothing_is_judged_and_it_says_why() {
        for (flaws, why) in [
            (
                Flaws {
                    no_mail_sink: true,
                    code_reusable: true,
                    ..Default::default()
                },
                "no mail server",
            ),
            (
                Flaws {
                    code_sends_nothing: true,
                    code_reusable: true,
                    ..Default::default()
                },
                "sent no email",
            ),
        ] {
            for o in [run_against(flaws, &users()), run_signing_up(flaws)] {
                assert!(code_findings(&o).is_empty(), "{why}: {:#?}", o.findings);
                assert!(code_credits(&o).is_empty(), "{why}");
                assert!(
                    code_not_assessed(&o).iter().any(|w| w.contains(why)),
                    "{why}: {:?}",
                    o.not_assessed
                );
            }
        }
    }

    #[test]
    fn a_refusal_is_credited_only_when_the_sessions_own_code_then_works() {
        // The session is locked by its first wrong code, so the code from elsewhere is refused and
        // so is its own afterwards: the refusal says nothing about where the code came from.
        let flaws = Flaws {
            code_locks_after_one: true,
            ..Default::default()
        };
        for o in [run_against(flaws, &users()), run_signing_up(flaws)] {
            // Nor is single use: with binding unknown, a refused second use shows nothing.
            assert!(!code_credits(&o).contains(&EMAIL_CODE_REUSABLE.rule_id));
            assert!(!code_credits(&o).contains(&EMAIL_CODE_UNBOUND.rule_id));
            assert!(!code_findings(&o).contains(&EMAIL_CODE_UNBOUND.rule_id));
            assert!(
                o.not_assessed
                    .iter()
                    .any(|(ids, why)| ids == "V6.6.2" && why.contains("own code")),
                "{:?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn a_wrong_code_is_wrong_everywhere_and_looks_like_the_right_one() {
        for code in ["482913", "X7k2Q9", "000000", "9f86d081884c7d659a2f"] {
            let guesses: Vec<String> = (0..25).map(|n| wrong_code(code, n)).collect();
            for g in &guesses {
                assert_eq!(g.len(), code.len());
                assert!(
                    g.chars().zip(code.chars()).all(|(a, b)| a != b
                        && a.is_ascii_digit() == b.is_ascii_digit()
                        && a.is_ascii_lowercase() == b.is_ascii_lowercase()),
                    "{code} -> {g}"
                );
            }
        }
    }

    #[test]
    fn pushing_back_by_cancelling_the_code_counts_and_refusing_from_the_start_is_not_judged() {
        // Wrong codes answered the same all the way through: the right code refused afterwards is
        // the only sign, and it is enough.
        let flaws = Flaws {
            code_cancels_quietly: true,
            ..Default::default()
        };
        let o = run_with(flaws, &codes_policy(3));
        assert!(
            code_credits(&o).contains(&EMAIL_CODE_GUESSING.rule_id),
            "{:?}",
            o.steps
        );
        assert!(!code_findings(&o).contains(&EMAIL_CODE_GUESSING.rule_id));

        let flaws = Flaws {
            code_already_refusing: true,
            code_guessing_unlimited: true,
            ..Default::default()
        };
        let o = run_with(flaws, &codes_policy(3));
        assert!(!code_findings(&o).contains(&EMAIL_CODE_GUESSING.rule_id));
        assert!(!code_credits(&o).contains(&EMAIL_CODE_GUESSING.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids == "V6.6.3" && why.contains("already refusing")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_short_code_that_works_anywhere_and_twice_is_three_findings_and_no_credit() {
        let flaws = Flaws {
            code_reusable: true,
            code_unbound: true,
            code_short: true,
            ..Default::default()
        };
        let o = run_with(flaws, &codes_policy(3));
        let mut found = code_findings(&o);
        found.sort_unstable();
        let mut want = vec![
            EMAIL_CODE_REUSABLE.rule_id,
            EMAIL_CODE_UNBOUND.rule_id,
            EMAIL_CODE_SHORT.rule_id,
        ];
        want.sort_unstable();
        assert_eq!(found, want, "{:?}", o.steps);
        assert_eq!(code_credits(&o), vec![EMAIL_CODE_GUESSING.rule_id]);
    }

    /// The seeded fixture, with a policy: the other way into every emailed-code check, so none of
    /// them rests on the sign-up fixture alone.
    fn seeded_with(flaws: Flaws, policy: &sv_manifest::PolicySection) -> Outcome {
        let mut app = FakeApp::new(flaws);
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        run(&mut app, &users(), &acc, true, policy)
    }

    #[test]
    fn seeded_a_locked_session_leaves_binding_unjudged() {
        let o = seeded_with(
            Flaws {
                code_locks_after_one: true,
                ..Default::default()
            },
            &Default::default(),
        );
        assert!(!code_credits(&o).contains(&EMAIL_CODE_UNBOUND.rule_id));
        assert!(!code_findings(&o).contains(&EMAIL_CODE_UNBOUND.rule_id));
    }

    #[test]
    fn seeded_guessing_is_credited_when_pushed_back_and_found_when_not() {
        let o = seeded_with(Flaws::default(), &codes_policy(3));
        assert!(code_credits(&o).contains(&EMAIL_CODE_GUESSING.rule_id));
        assert!(!code_findings(&o).contains(&EMAIL_CODE_GUESSING.rule_id));
        let o = seeded_with(
            Flaws {
                code_cancels_quietly: true,
                ..Default::default()
            },
            &codes_policy(3),
        );
        assert!(
            code_credits(&o).contains(&EMAIL_CODE_GUESSING.rule_id),
            "{:?}",
            o.steps
        );
        assert!(!code_findings(&o).contains(&EMAIL_CODE_GUESSING.rule_id));
    }

    #[test]
    fn seeded_guessing_without_limit_is_found() {
        let o = seeded_with(
            Flaws {
                code_guessing_unlimited: true,
                ..Default::default()
            },
            &codes_policy(5),
        );
        assert_eq!(
            code_findings(&o),
            vec![EMAIL_CODE_GUESSING.rule_id],
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn seeded_an_app_refusing_from_the_first_wrong_code_is_not_judged() {
        let o = seeded_with(
            Flaws {
                code_already_refusing: true,
                code_guessing_unlimited: true,
                ..Default::default()
            },
            &codes_policy(3),
        );
        assert!(!code_findings(&o).contains(&EMAIL_CODE_GUESSING.rule_id));
        assert!(!code_credits(&o).contains(&EMAIL_CODE_GUESSING.rule_id));
    }

    #[test]
    fn seeded_a_code_that_signs_nobody_in_is_not_assessed() {
        let o = seeded_with(
            Flaws {
                code_does_nothing: true,
                code_reusable: true,
                code_unbound: true,
                ..Default::default()
            },
            &codes_policy(3),
        );
        assert!(code_findings(&o).is_empty(), "{:#?}", o.findings);
        assert!(code_credits(&o).is_empty());
        assert!(
            code_not_assessed(&o)
                .iter()
                .any(|w| w.contains("did not open")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_code_that_signs_nobody_in_is_never_credited_for_resisting_guesses() {
        let o = run_with(
            Flaws {
                code_does_nothing: true,
                ..Default::default()
            },
            &codes_policy(3),
        );
        assert!(!code_credits(&o).contains(&EMAIL_CODE_GUESSING.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids == "V6.6.3" && why.contains("did not sign in")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn seeded_no_mail_server_is_said_as_such() {
        let o = seeded_with(
            Flaws {
                no_mail_sink: true,
                ..Default::default()
            },
            &Default::default(),
        );
        assert!(
            code_not_assessed(&o)
                .iter()
                .any(|w| w.contains("no mail server")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn seeded_a_number_too_large_to_reach_is_not_judged() {
        let o = seeded_with(
            Flaws {
                code_guessing_unlimited: true,
                ..Default::default()
            },
            &codes_policy(400),
        );
        assert!(!code_findings(&o).contains(&EMAIL_CODE_GUESSING.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids == "V6.6.3" && why.contains("400")),
            "{:?}",
            o.not_assessed
        );
    }

    /// The fixtures with the emailed-code forms carrying no `{csrf}`.
    fn without_code_csrf(mut u: UsersSection) -> UsersSection {
        let entry = u.email_code.as_mut().unwrap();
        for t in [&mut entry.request, &mut entry.use_code] {
            t.form.remove("csrf_token");
        }
        u
    }

    #[test]
    fn a_form_with_no_token_is_still_opened_first_so_the_code_has_a_session_to_belong_to() {
        let flaws = Flaws {
            code_no_csrf: true,
            ..Default::default()
        };
        let mut app = FakeApp::new(flaws);
        let mut acc = accounts();
        acc.admin = None;
        acc.totp = None;
        let o = run(
            &mut app,
            &without_code_csrf(with_signup()),
            &acc,
            false,
            &Default::default(),
        );
        assert!(
            code_findings(&o).is_empty(),
            "{:#?}\n{:?}",
            o.findings,
            o.steps
        );
        assert_eq!(code_credits(&o), vec![EMAIL_CODE_UNBOUND.rule_id]);
    }

    #[test]
    fn seeded_a_form_with_no_token_is_still_opened_first() {
        let mut app = FakeApp::new(Flaws {
            code_no_csrf: true,
            ..Default::default()
        });
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        let o = run(
            &mut app,
            &without_code_csrf(users()),
            &acc,
            true,
            &codes_policy(3),
        );
        assert!(code_findings(&o).is_empty(), "{:#?}", o.findings);
        assert!(code_credits(&o).contains(&EMAIL_CODE_UNBOUND.rule_id));
        assert!(code_credits(&o).contains(&EMAIL_CODE_GUESSING.rule_id));
    }

    // --------------------------------------------------------------------------------------------
    // Session timeouts, waited out with --slow

    const TIMEOUT_RULES: [&str; 2] = [NO_IDLE_TIMEOUT.rule_id, NO_SESSION_LIFETIME.rule_id];

    fn timeout_findings(o: &Outcome) -> Vec<&str> {
        rule_ids(o)
            .into_iter()
            .filter(|id| TIMEOUT_RULES.contains(id))
            .collect()
    }

    fn timeout_credits(o: &Outcome) -> Vec<&str> {
        verified_ids(o)
            .into_iter()
            .filter(|id| TIMEOUT_RULES.contains(id))
            .collect()
    }

    fn timeout_why(o: &Outcome, id: &str) -> Vec<String> {
        o.not_assessed
            .iter()
            .filter(|(ids, _)| ids.contains(id))
            .map(|(_, why)| why.clone())
            .collect()
    }

    fn timeouts(idle: Option<u32>, lifetime: Option<u32>) -> sv_manifest::PolicySection {
        sv_manifest::PolicySection {
            idle_timeout_minutes: idle,
            session_lifetime_minutes: lifetime,
            ..Default::default()
        }
    }

    /// The seeded fixture, with the app's own timeouts in minutes, the owner's stated ones, and
    /// `slow` on.
    fn slow_run(
        app_idle: Option<u64>,
        app_lifetime: Option<u64>,
        policy: &sv_manifest::PolicySection,
        tune: impl FnOnce(&mut FakeApp),
    ) -> Outcome {
        let mut app = FakeApp::new(Flaws::default());
        app.idle_limit = app_idle.map(|m| m * 60);
        app.lifetime_limit = app_lifetime.map(|m| m * 60);
        tune(&mut app);
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        super::run_with(&mut app, &users(), &acc, true, policy, true)
    }

    /// The same through sign-up rather than seeding.
    fn slow_signup_run(
        app_idle: Option<u64>,
        app_lifetime: Option<u64>,
        policy: &sv_manifest::PolicySection,
    ) -> Outcome {
        let mut app = FakeApp::new(Flaws::default());
        app.idle_limit = app_idle.map(|m| m * 60);
        app.lifetime_limit = app_lifetime.map(|m| m * 60);
        let mut acc = accounts();
        acc.admin = None;
        super::run_with(&mut app, &with_signup(), &acc, false, policy, true)
    }

    #[test]
    fn sessions_that_end_when_stated_are_credited_for_both() {
        let policy = timeouts(Some(15), Some(60));
        for o in [
            slow_run(Some(15), Some(60), &policy, |_| {}),
            slow_signup_run(Some(15), Some(60), &policy),
        ] {
            assert!(timeout_findings(&o).is_empty(), "{:#?}", o.findings);
            assert_eq!(
                timeout_credits(&o),
                vec![NO_IDLE_TIMEOUT.rule_id, NO_SESSION_LIFETIME.rule_id],
                "{:?}\n{:?}",
                o.steps,
                o.not_assessed
            );
        }
    }

    #[test]
    fn a_session_that_never_idles_out_is_found() {
        let policy = timeouts(Some(15), Some(60));
        for o in [
            slow_run(None, Some(60), &policy, |_| {}),
            slow_signup_run(None, Some(60), &policy),
        ] {
            assert_eq!(
                timeout_findings(&o),
                vec![NO_IDLE_TIMEOUT.rule_id],
                "{:?}",
                o.steps
            );
            assert_eq!(timeout_credits(&o), vec![NO_SESSION_LIFETIME.rule_id]);
        }
    }

    #[test]
    fn a_session_that_lasts_forever_when_busy_is_found() {
        let policy = timeouts(Some(15), Some(60));
        for o in [
            slow_run(Some(15), None, &policy, |_| {}),
            slow_signup_run(Some(15), None, &policy),
        ] {
            assert_eq!(
                timeout_findings(&o),
                vec![NO_SESSION_LIFETIME.rule_id],
                "{:?}",
                o.steps
            );
            assert_eq!(timeout_credits(&o), vec![NO_IDLE_TIMEOUT.rule_id]);
        }
    }

    #[test]
    fn a_timeout_longer_than_stated_is_found() {
        // Idle sessions do end, at 30 minutes: not at the 15 stated.
        let o = slow_run(Some(30), Some(60), &timeouts(Some(15), Some(60)), |_| {});
        assert_eq!(
            timeout_findings(&o),
            vec![NO_IDLE_TIMEOUT.rule_id],
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn an_idle_session_refused_beside_a_busy_one_refused_too_is_not_credited() {
        // Every session dies after ten minutes, busy or not: the idle one's refusal at sixteen
        // says nothing about idleness.
        for o in [
            slow_run(None, Some(10), &timeouts(Some(15), Some(60)), |_| {}),
            slow_signup_run(None, Some(10), &timeouts(Some(15), Some(60))),
        ] {
            assert!(!timeout_credits(&o).contains(&NO_IDLE_TIMEOUT.rule_id));
            assert!(!timeout_findings(&o).contains(&NO_IDLE_TIMEOUT.rule_id));
            assert!(
                timeout_why(&o, "V7.3.1")
                    .iter()
                    .any(|w| w.contains("kept busy")),
                "{:?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn a_busy_session_refused_when_no_sign_in_works_is_not_credited() {
        // The app refuses every sign-in from 40 minutes in: the busy session's refusal at the
        // lifetime cannot be told from the app no longer letting anyone in.
        let policy = timeouts(None, Some(60));
        let o = slow_run(Some(15), Some(60), &policy, |app| {
            app.sign_ins_refused_from = Some(app.clock + 40 * 60);
        });
        assert!(
            !timeout_credits(&o).contains(&NO_SESSION_LIFETIME.rule_id),
            "{:?}",
            o.steps
        );
        assert!(
            timeout_why(&o, "V7.3.2")
                .iter()
                .any(|w| w.contains("new sign-in")),
            "{:?}",
            o.not_assessed
        );
        let o = slow_run(None, Some(30), &timeouts(None, Some(45)), |app| {
            app.sign_ins_refused_from = Some(app.clock + 40 * 60);
        });
        assert!(
            !timeout_credits(&o).contains(&NO_SESSION_LIFETIME.rule_id),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn nothing_is_waited_for_without_slow_or_without_numbers() {
        let mut app = FakeApp::new(Flaws::default());
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let start = app.clock;
        let o = super::run_with(
            &mut app,
            &users(),
            &acc,
            true,
            &timeouts(Some(15), Some(60)),
            false,
        );
        assert!(timeout_credits(&o).is_empty() && timeout_findings(&o).is_empty());
        assert!(
            timeout_why(&o, "V7.3.1")
                .iter()
                .any(|w| w.contains("--slow"))
        );
        assert!(app.clock - start < 5 * 60, "it waited without --slow");

        let o = slow_run(None, None, &timeouts(None, None), |_| {});
        assert!(timeout_findings(&o).is_empty());
        assert!(
            timeout_why(&o, "V7.3.1")
                .iter()
                .any(|w| w.contains("idle-timeout-minutes")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn numbers_that_cannot_be_waited_out_or_told_apart_are_said_so() {
        // A day is not waited for; the idle timeout is still judged.
        let o = slow_run(Some(15), None, &timeouts(Some(15), Some(24 * 60)), |_| {});
        assert!(
            timeout_why(&o, "V7.3.2")
                .iter()
                .any(|w| w.contains("longer than"))
        );
        assert_eq!(timeout_credits(&o), vec![NO_IDLE_TIMEOUT.rule_id]);
        // An idle timeout no shorter than the lifetime cannot be told apart from it.
        let o = slow_run(Some(30), Some(30), &timeouts(Some(30), Some(30)), |_| {});
        assert!(
            timeout_why(&o, "V7.3.1")
                .iter()
                .any(|w| w.contains("no shorter")),
            "{:?}",
            o.not_assessed
        );
        assert_eq!(timeout_credits(&o), vec![NO_SESSION_LIFETIME.rule_id]);
    }

    #[test]
    fn two_sessions_that_do_not_both_open_are_not_judged() {
        // One session per user: signing the busy one in ends the idle one at once. Its refusal at
        // the end would otherwise read as an idle timeout.
        let o = slow_run(None, None, &timeouts(Some(15), None), |app| {
            app.one_session_per_user = true;
        });
        assert!(timeout_credits(&o).is_empty(), "{:?}", o.steps);
        assert!(
            timeout_why(&o, "V7.3.1")
                .iter()
                .any(|w| w.contains("did not both open")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn seeded_an_idle_refusal_with_the_busy_one_refused_too_is_not_credited() {
        let o = slow_run(Some(15), Some(10), &timeouts(Some(15), None), |_| {});
        assert!(
            !timeout_credits(&o).contains(&NO_IDLE_TIMEOUT.rule_id),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn through_sign_up_a_session_that_lasts_forever_is_found() {
        let o = slow_signup_run(None, None, &timeouts(None, Some(45)));
        assert_eq!(
            timeout_findings(&o),
            vec![NO_SESSION_LIFETIME.rule_id],
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_lifetime_refusal_when_sign_in_stopped_working_is_not_credited_through_a_short_lifetime() {
        let o = slow_run(None, Some(30), &timeouts(None, Some(45)), |app| {
            app.sign_ins_refused_from = Some(app.clock + 40 * 60);
        });
        assert!(
            !timeout_credits(&o).contains(&NO_SESSION_LIFETIME.rule_id),
            "{:?}",
            o.steps
        );
        assert!(
            timeout_why(&o, "V7.3.2")
                .iter()
                .any(|w| w.contains("new sign-in"))
        );
    }

    #[test]
    fn through_sign_up_nothing_is_waited_for_without_slow() {
        let mut app = FakeApp::new(Flaws::default());
        app.idle_limit = Some(15 * 60);
        let mut acc = accounts();
        acc.admin = None;
        let start = app.clock;
        let o = super::run_with(
            &mut app,
            &with_signup(),
            &acc,
            false,
            &timeouts(Some(15), None),
            false,
        );
        assert!(timeout_credits(&o).is_empty());
        assert!(app.clock - start < 5 * 60, "it waited without --slow");
    }

    #[test]
    fn through_sign_up_no_numbers_are_said_to_be_needed() {
        let o = slow_signup_run(Some(15), None, &timeouts(None, None));
        assert!(timeout_credits(&o).is_empty());
        assert!(
            timeout_why(&o, "V7.3.2")
                .iter()
                .any(|w| w.contains("session-lifetime-minutes"))
        );
    }

    #[test]
    fn a_lifetime_of_two_hours_is_not_waited_for() {
        let o = slow_run(None, None, &timeouts(None, Some(120)), |_| {});
        assert!(timeout_findings(&o).is_empty(), "{:?}", o.steps);
        assert!(
            timeout_why(&o, "V7.3.2")
                .iter()
                .any(|w| w.contains("longer than"))
        );
    }

    #[test]
    fn an_idle_timeout_longer_than_the_lifetime_is_not_judged() {
        let o = slow_run(None, Some(30), &timeouts(Some(45), Some(30)), |_| {});
        assert!(
            !timeout_findings(&o).contains(&NO_IDLE_TIMEOUT.rule_id),
            "{:?}",
            o.steps
        );
        assert!(
            timeout_why(&o, "V7.3.1")
                .iter()
                .any(|w| w.contains("no shorter"))
        );
    }

    /// The four rows found in review: steady and leaky limits by address, reading the header or not.
    fn forwarded_case(leaks: bool, trusts: bool) -> Outcome {
        run_with(
            Flaws {
                locks_out_after: Some(6),
                limits_by_address: true,
                trusts_forwarded_for: trusts,
                lockout_leaks: leaks,
                ..Flaws::default()
            },
            &policy(Some(6)),
        )
    }

    #[test]
    fn a_leaky_limit_that_ignores_the_header_is_not_accused_of_trusting_it() {
        // The false positive: the leak let exactly one claimed attempt through, which is what a
        // single claimed attempt beside a single plain one could not tell from a trusted header.
        let out = forwarded_case(true, false);
        assert!(
            !finding_ids(&out).contains(&FORWARDED_TRUSTED.rule_id),
            "{:?}",
            out.steps
        );
        let steps = forwarded_steps(&out);
        assert_eq!(steps.len(), 1, "the attempts were made: {:?}", out.steps);
        assert!(
            steps[0].contains("one as the first attempt was and one refused"),
            "{}",
            steps[0]
        );
    }

    #[test]
    fn the_four_rows_from_review_come_out_as_they_should() {
        for (leaks, trusts, found) in [
            (false, false, false),
            (false, true, true),
            (true, false, false),
            // A leaky limit still hides an app that trusts the header: the safe direction.
            (true, true, false),
        ] {
            let out = forwarded_case(leaks, trusts);
            assert_eq!(
                finding_ids(&out).contains(&FORWARDED_TRUSTED.rule_id),
                found,
                "leaks {leaks}, trusts {trusts}: {:?}",
                forwarded_steps(&out)
            );
        }
    }

    fn forwarded_once(trusts: bool) -> Outcome {
        run_with(
            Flaws {
                locks_out_after: Some(6),
                limits_by_address: true,
                trusts_forwarded_for: trusts,
                window_rolls_over_at_first_claim: true,
                ..Flaws::default()
            },
            &policy(Some(6)),
        )
    }

    #[test]
    fn a_limit_that_lets_one_attempt_through_once_is_not_accused() {
        // One claimed attempt gets through and everything after is refused: only the second
        // claimed attempt, from its own address, tells this apart from a trusted header.
        let out = forwarded_once(false);
        assert!(
            !finding_ids(&out).contains(&FORWARDED_TRUSTED.rule_id),
            "{:?}",
            forwarded_steps(&out)
        );
    }

    #[test]
    fn a_limit_that_leaked_once_and_trusts_the_header_is_still_found() {
        let out = forwarded_once(true);
        assert!(
            finding_ids(&out).contains(&FORWARDED_TRUSTED.rule_id),
            "{:?}",
            forwarded_steps(&out)
        );
    }

    #[test]
    fn a_leaky_limit_hides_a_trusted_header_rather_than_inventing_one() {
        let out = forwarded_case(true, true);
        assert!(
            !finding_ids(&out).contains(&FORWARDED_TRUSTED.rule_id),
            "{:?}",
            forwarded_steps(&out)
        );
    }

    #[test]
    fn seeded_a_limit_that_lets_one_attempt_through_once_is_not_accused() {
        let out = seeded_with(
            Flaws {
                locks_out_after: Some(6),
                limits_by_address: true,
                window_rolls_over_at_first_claim: true,
                ..Flaws::default()
            },
            &policy(Some(6)),
        );
        let steps = forwarded_steps(&out);
        assert_eq!(steps.len(), 1, "the attempts were made: {:?}", out.steps);
        assert!(
            !finding_ids(&out).contains(&FORWARDED_TRUSTED.rule_id),
            "{steps:?}"
        );
    }
}
