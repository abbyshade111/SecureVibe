//! What a signed-in user can do, asked of the running app.
//!
//! The probes in `probes.rs` sign in as nobody, so authorization, sessions and request forgery were
//! always *not assessed*. This asks as two ordinary users, A and B — and an admin, when the app's
//! `seed` command makes one — using what `[stack.run.users]` in stackvet.toml says about how to sign
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
//!
//! # Where each check lives
//!
//! This file holds what every check shares: sessions and cookies, anti-forgery tokens, requests
//! filled from stackvet.toml's templates, signing in and up, and `run_with`, which calls each
//! area's checks in turn. The rules each check can raise are in `rules.rs`. The checks themselves:
//!
//! - `signin.rs`: wrong-password limits (V6.3.1), `X-Forwarded-For`, default accounts, a password in
//!   an address, and signing out.
//! - `sessions.rs`: session cookies, ids, and timeouts, invented sessions, private pages and their
//!   caching, `Clear-Site-Data`, the fields a record gives back, and a private WebSocket's session
//!   and origin.
//! - `passwords.rs`: the password rules at sign-up (short, common, breached, context words, altered,
//!   long), the password field, changing a password, hints, and deleting an account.
//! - `reset.rs`: a forgotten-password reset, followed through the email it sends.
//! - `codes.rs`: signing in with an emailed code, and what the three email flows share for finding a
//!   code in an email.
//! - `activation.rs`: the activation code emailed at sign-up.
//! - `totp.rs`: two-factor codes from an authenticator app.
//! - `admin.rs`: the admin page and admin actions, a role given at sign-up, and records that belong
//!   to someone else.
//! - `forgery.rs`: cross-site request forgery, `Origin: null`, and forms another site can send
//!   without a preflight. The WebSocket origin check's tests are here too, beside the other origin
//!   tests; the check itself is in `sessions.rs`.
//! - `flows.rs`: steps of a multi-step flow taken out of order.
//! - `uploads.rs`: uploads and downloads.
//!
//! Each file's tests sit beside its checks. The tests here are the ones that exercise several areas
//! at once, and `fake_app.rs` is the scripted app they all drive.

use crate::finding::{Confidence, Finding, Location, Severity};
use crate::probes::{ProbeRequest, ProbeResponse};
use regex::Regex;
use std::collections::BTreeMap;
use std::sync::LazyLock;
use sv_manifest::{RequestTemplate, UploadSection, UsersSection};

mod activation;
mod admin;
mod archives;
mod burst;
mod codes;
mod cross_site;
mod email_role;
mod flows;
mod forgery;
mod once;
mod owner_field;
mod passwords;
mod redirects;
mod reset;
mod rules;
mod sessions;
mod signin;
mod sql;
mod stored_markup;
mod tokens;
mod totp;
mod uploads;
use activation::*;
use admin::*;
use burst::*;
use codes::*;
use email_role::*;
use flows::*;
use forgery::*;
use once::*;
use owner_field::*;
use passwords::*;
use redirects::*;
use reset::*;
use rules::*;
pub(crate) use rules::{Rule, finding};
use sessions::*;
use signin::*;
use sql::*;
use stored_markup::*;
use tokens::*;
use totp::*;
use uploads::*;

/// Something that can put a request to the running app and bring back its answer.
pub trait Http {
    fn send(&mut self, request: &ProbeRequest) -> Option<ProbeResponse>;

    /// Sends these requests at once, each over its own connection, all started together rather
    /// than one after another, and gives back each answer in the order given. A request may be
    /// given more than once, to send copies of it. `None` when this way of reaching the app cannot
    /// send at the same instant: requests sent one after another cannot show a race, so a check
    /// that needs one is then not assessed.
    fn send_together(&mut self, _requests: &[ProbeRequest]) -> Option<Vec<Option<ProbeResponse>>> {
        None
    }

    /// Sends these requests one after another, each waiting for its answer before the next starts,
    /// as `send` would, but handed to the app's side in one go, and gives back each answer in the
    /// order given. The app sees what it would see from `send` called for each in turn; the run
    /// pays for one way into the fence rather than one each. `None` when this way of reaching the
    /// app cannot, and the caller sends them one by one.
    fn send_in_turn(&mut self, _requests: &[ProbeRequest]) -> Option<Vec<Option<ProbeResponse>>> {
        None
    }

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

    /// Sends a request to the run's test model rather than to the app: `None` when the run has no
    /// test model. See `ai.rs`.
    fn model(&mut self, _request: &ProbeRequest) -> Option<ProbeResponse> {
        None
    }

    /// The test model's server as the app reaches it on the fenced network, such as
    /// `http://sv-1-model:9100`: `None` when the run has no test model that answered. A wrapper
    /// must pass this on, or the checks behind it read as having no test server.
    fn model_address(&mut self) -> Option<String> {
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
    /// A third account with two-factor sign-in, when stackvet.toml has a `totp` entry and a
    /// `seed` to enroll it. Never A or B: they have to keep signing in with a password alone.
    pub totp: Option<TotpAccount>,
    /// A secret for the admin's own two-factor sign-in, made with the accounts when there is an
    /// admin, a `totp` entry and a `seed`. `seed` is given it in base32 as `SV_ADMIN_TOTP_SECRET`
    /// and may enroll the admin with it; when the admin's sign-in then stops at the code step, the
    /// code is worked out from it. Held like the two-factor account's: never written anywhere but
    /// the app's container.
    pub admin_totp_secret: Option<Vec<u8>>,
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
    /// The lines of the app's output the log checks read, each with what for (ADR-082).
    pub log_lines: Vec<crate::logs::KeptLine>,
    /// The last lines of the app's output when the log was read, at most `crate::logs::TAIL`.
    pub log_tail: Vec<String>,
}

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
    secure: bool,
    path: Option<String>,
}

fn parse_set_cookie(header: &str) -> Option<Cookie> {
    let mut parts = header.split(';');
    let (name, value) = parts.next()?.split_once('=')?;
    let mut cookie = Cookie {
        name: name.trim().to_owned(),
        value: value.trim().to_owned(),
        http_only: false,
        same_site: None,
        secure: false,
        path: None,
    };
    for attribute in parts {
        let attribute = attribute.trim();
        let (key, val) = attribute.split_once('=').unwrap_or((attribute, ""));
        match key.to_lowercase().as_str() {
            "httponly" => cookie.http_only = true,
            "samesite" => cookie.same_site = Some(val.trim().to_lowercase()),
            "secure" => cookie.secure = true,
            // Only a path a browser would take: one that starts with `/`.
            "path" if val.trim().starts_with('/') => cookie.path = Some(val.trim().to_owned()),
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
    /// Each cookie's attributes as the app set them, by name, for handing them to a real browser:
    /// a browser keeps a `__Host-` cookie only when it is `Secure` (family-hub, 3 October 2026).
    attributes: Vec<crate::browser::BrowserCookie>,
}

impl Session {
    pub(crate) fn cookies(&self) -> &[(String, String)] {
        &self.cookies
    }

    /// The cookies with the attributes the app gave them, in the order `cookies` has them.
    pub(crate) fn browser_cookies(&self) -> Vec<crate::browser::BrowserCookie> {
        self.cookies
            .iter()
            .map(|(name, value)| {
                let set = self.attributes.iter().find(|c| c.name == *name);
                crate::browser::BrowserCookie {
                    name: name.clone(),
                    value: value.clone(),
                    ..set.cloned().unwrap_or_default()
                }
            })
            .collect()
    }

    pub(crate) fn absorb(&mut self, response: &ProbeResponse) {
        for cookie in set_cookies(response) {
            self.cookies.retain(|(n, _)| *n != cookie.name);
            self.attributes.retain(|c| c.name != cookie.name);
            // An emptied cookie is how most frameworks delete one.
            if !cookie.value.is_empty() {
                self.attributes.push(crate::browser::BrowserCookie {
                    name: cookie.name.clone(),
                    value: String::new(),
                    secure: cookie.secure,
                    http_only: cookie.http_only,
                    path: cookie.path,
                    same_site: cookie.same_site,
                });
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
    new_email: &'a str,
    code: &'a str,
}

fn fill(text: &str, v: &Values) -> String {
    text.replace("{user}", v.user)
        .replace("{new_password}", v.new_password)
        .replace("{new_email}", v.new_email)
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
        body: body.map(String::into_bytes),
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

/// Whether an answer is the app's page shell: a success with a body exactly the front page's, short
/// enough to have been kept whole. Matching a cut body would set aside a server-rendered page that
/// only begins as the front page does.
fn is_page_shell(response: &Option<ProbeResponse>, front: &Option<ProbeResponse>) -> bool {
    let (Some(page), Some(front)) = (response, front) else {
        return false;
    };
    (200..300).contains(&page.status)
        && (200..300).contains(&front.status)
        && !page.body.trim().is_empty()
        && page.body.chars().count() < crate::probes::KEPT_CHARS
        && page.body == front.body
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
    send_template_as(http, id, t, values, session, pages, |_| {})
}

/// A template's request, ready to send: its values filled in, and the page's anti-forgery token
/// fetched first when it asks for one.
fn prepared(
    http: &mut dyn Http,
    id: &str,
    t: &RequestTemplate,
    values: &Values,
    session: &mut Session,
    pages: &[String],
) -> ProbeRequest {
    let v = with_token(http, id, t, values, session, pages);
    request(id, t, &v, session)
}

/// `values`, with the anti-forgery token the request needs, when it needs one: fetched from the
/// request's own page or, failing that, the first of `pages` that has one.
fn with_token<'a>(
    http: &mut dyn Http,
    id: &str,
    t: &RequestTemplate,
    values: &Values<'a>,
    session: &mut Session,
    pages: &[String],
) -> Values<'a> {
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
    v
}

/// `send_template`, with the request changed by `adjust` after the token is in it and before it
/// goes: for a header a particular browser would send.
fn send_template_as(
    http: &mut dyn Http,
    id: &str,
    t: &RequestTemplate,
    values: &Values,
    session: &mut Session,
    pages: &[String],
    adjust: impl FnOnce(&mut ProbeRequest),
) -> (Option<ProbeResponse>, Vec<Cookie>) {
    let mut sent = prepared(http, id, t, values, session, pages);
    adjust(&mut sent);
    let response = http.send(&sent);
    let cookies = response.as_ref().map(set_cookies).unwrap_or_default();
    if let Some(r) = &response {
        session.absorb(r);
    }
    (response, cookies)
}

/// Sends a template whose own placeholders are already filled in, fetching the page's anti-forgery
/// token first when it asks for one, as `send_template` does for the checks here.
/// Creates the `owned` record as whoever `session` belongs to, with `marker` in it, and gives back
/// the app's answer and the id it gave the record. For the AI checks, which ask the app's own tools
/// for a record by its id (C9.5.3).
pub(crate) fn create_owned(
    http: &mut dyn Http,
    users: &UsersSection,
    session: &mut Session,
    marker: &str,
) -> (Option<ProbeResponse>, Option<String>) {
    let Some(owned) = &users.owned else {
        return (None, None);
    };
    let values = Values {
        marker,
        ..Default::default()
    };
    let (created, _) = send_template(
        http,
        "owned-create-ai",
        &owned.create,
        &values,
        session,
        &users.private,
    );
    let id = created.as_ref().and_then(|r| record_id(owned, r));
    (created, id)
}

pub(crate) fn send_filled(
    http: &mut dyn Http,
    id: &str,
    t: &RequestTemplate,
    session: &mut Session,
    pages: &[String],
) -> Option<ProbeResponse> {
    send_template(http, id, t, &Values::default(), session, pages).0
}

// ------------------------------------------------------------------------------------------------
// The suite

/// A user signed in, with what the sign-in showed.
pub(crate) struct SignedIn {
    pub(crate) session: Session,
    /// Cookies set by the sign-in response itself: the session cookies.
    set_at_login: Vec<Cookie>,
    /// Cookies the app had given before sign-in.
    before_login: Vec<(String, String)>,
    /// Where the sign-in answer left the browser, for a reason when the session turns out not to
    /// be signed in: "answered 200", or "sent the browser to /login/2fa".
    pub(crate) landed: String,
    /// Whether the sign-in was answered by the app's rate limiter, after the wait [`Patient`] gives
    /// it: the limit on sign-in attempts refused `sv`, so nothing about the session says anything
    /// about the app's checks or stackvet.toml.
    pub(crate) limited: bool,
}

pub(crate) fn sign_in(
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
    let landed = match response.header("location") {
        Some(to) if (300..400).contains(&response.status) => {
            // The path alone: what follows `?` may be a token of the app's own.
            let path = strip_origin(to);
            format!(
                "sent the browser to {}",
                path.split(['?', '#']).next().unwrap_or(path)
            )
        }
        _ => format!("answered {}", response.status),
    };
    Some(SignedIn {
        session,
        set_at_login,
        before_login,
        landed,
        limited: rate_limited(&response).is_some(),
    })
}

/// A signed in again after the session timeouts were waited out (`sv run --slow`), shown to open
/// `confirm` as the first sign-in did, when there is one to open. `None`, with the checks that
/// needed A's session left not assessed and why, when the app did not answer or the new session
/// did not open the page: the run goes no further, as when the first sign-in fails.
fn sign_in_again(
    http: &mut dyn Http,
    users: &UsersSection,
    a: &Account,
    confirm: Option<&str>,
    out: &mut Outcome,
) -> Option<SignedIn> {
    let refused = |out: &mut Outcome, what: String| {
        out.not_assessed.push((
            "V8.2.1, V8.2.2, V7.2.4, V7.4.1, V3.5.1, V3.3.2, V3.3.4, V14.3.2, V7.4.4".to_owned(),
            format!(
                "After waiting out the session timeouts, the first test user's earlier session had \
                 sat unused for the whole wait, so it was signed in again; {what}. The checks that \
                 needed a working session were not run, rather than run with one the app may have \
                 ended."
            ),
        ));
    };
    let Some(fresh) = sign_in(http, users, "a-after-wait", a, &mut out.steps) else {
        refused(out, "the app did not answer that sign-in".to_owned());
        return None;
    };
    if let Some(path) = confirm {
        let response = http.send(&get("private-a-after-wait", path, &fresh.session));
        out.steps.push(format!(
            "signed in as A again after the wait and opened {path} ({})",
            status(&response)
        ));
        if !ok(&response) {
            refused(
                out,
                format!(
                    "the new session did not open {path} ({})",
                    status(&response)
                ),
            );
            return None;
        }
    }
    Some(fresh)
}

/// How many times one run signs in, at most, before the password-guessing check's wrong passwords
/// at the very end: the number the spec gives a builder, so an app's own limit on sign-in attempts
/// can be set to allow it in the copy `sv` runs. The busiest of the scripted runs signs in 50 times
/// (`a_run_signs_in_no_more_often_than_the_spec_says`), which this leaves room above.
pub const SIGN_INS_IN_A_RUN: usize = 60;

/// The requirements whose checks need the first test user signed in.
const NEEDS_A_SESSION: &str =
    "V8.2.1, V8.2.2, V7.2.4, V7.4.1, V3.5.1, V3.3.2, V3.3.4, V14.3.2, V7.4.4";

/// What the report says when the app's limit on sign-in attempts refused `sv`'s own sign-ins
/// (`refused`, as request ids): the limit doing its job, not the app failing the checks it blocked,
/// and what to change so the next run gets through.
fn sign_in_limit_says(refused: &[String]) -> String {
    format!(
        "The app's limit on sign-in attempts refused `sv`'s own sign-in ({}) even after `sv` \
         waited as the app asked. That is the limit working, not the app failing these checks, and \
         not a mistake in stackvet.toml: the checks that needed that sign-in were not run, or \
         not credited. `sv` signs in up to {SIGN_INS_IN_A_RUN} times in one run, all from one \
         address, before the password-guessing check's wrong passwords at the end. Let the copy \
         of the app `sv` runs allow that many (for example, through a setting only the test copy \
         is started with), keep the real limit everywhere else, and run again.",
        refused.join(", ")
    )
}

/// What the sign-in limit's gap is listed under: the requirements whose credit was withheld, and the
/// first user's checks only when it was the first user's sign-in that was refused, since any other's
/// left those running on a session the limit let through (the review of 6 October, item 6). With no
/// requirement to name, it says so in words.
fn limit_gap_names(withheld: &[&str], refused: &[String]) -> String {
    let mut ids: Vec<&str> = withheld.to_vec();
    if refused.iter().any(|id| id == "login-a") {
        ids.extend(NEEDS_A_SESSION.split(", "));
    }
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        "The checks that needed that sign-in".to_owned()
    } else {
        ids.join(", ")
    }
}

/// Everything the signed-in probes can ask, given what stackvet.toml says.
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
///
/// Every request goes through [`Patient`], which waits out a rate limiter's answer once. When the
/// limiter was still answering after that, no refusal in the run can be told from the limiter's, so
/// nothing the run would have credited is: each credit becomes not assessed, naming the requests the
/// limiter kept answering. Findings stay, since hiding a real one is the worse fault, and the run
/// says which of them could rest on the limiter's refusal rather than the app's.
pub fn run_with(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    seeded: bool,
    policy: &sv_manifest::PolicySection,
    slow: bool,
) -> Outcome {
    run_within(
        http,
        users,
        accounts,
        seeded,
        policy,
        slow,
        &std::cell::Cell::new(0),
    )
}

/// The connection the checks are handed, counting what is asked of the app through it: requests,
/// requests sent together, and pages a browser opens. What a mock provider or the mailbox is asked
/// is not counted, since neither is the app.
struct Counted<'a> {
    inner: &'a mut dyn Http,
    asked: usize,
}

impl Http for Counted<'_> {
    fn send(&mut self, request: &ProbeRequest) -> Option<ProbeResponse> {
        self.asked += 1;
        self.inner.send(request)
    }

    fn send_together(&mut self, requests: &[ProbeRequest]) -> Option<Vec<Option<ProbeResponse>>> {
        self.asked += requests.len();
        self.inner.send_together(requests)
    }

    fn mail(&mut self, to: &str, at_least: usize) -> Option<Vec<String>> {
        self.inner.mail(to, at_least)
    }

    fn now(&mut self) -> u64 {
        self.inner.now()
    }

    fn wait(&mut self, seconds: u64) {
        self.inner.wait(seconds)
    }

    fn provider(&mut self, request: &ProbeRequest) -> Option<ProbeResponse> {
        self.inner.provider(request)
    }

    fn browser(&mut self, job: &crate::browser::Job) -> Option<Vec<serde_json::Value>> {
        self.asked += 1;
        self.inner.browser(job)
    }

    fn model(&mut self, request: &ProbeRequest) -> Option<ProbeResponse> {
        self.inner.model(request)
    }

    fn model_address(&mut self) -> Option<String> {
        self.inner.model_address()
    }
}

/// What `out` held before a check ran, and what had been asked of the app: where each list ended.
struct Said {
    asked: usize,
    findings: usize,
    verified: usize,
    not_assessed: usize,
}

impl Said {
    fn mark(out: &Outcome, asked: usize) -> Self {
        Said {
            asked,
            findings: out.findings.len(),
            verified: out.verified.len(),
            not_assessed: out.not_assessed.len(),
        }
    }

    /// The requirement ids the check named since `self`: found, credited, or not assessed.
    fn since(&self, out: &Outcome) -> std::collections::BTreeSet<String> {
        let mut ids = std::collections::BTreeSet::new();
        for f in &out.findings[self.findings..] {
            ids.extend(f.requirement_ids.iter().cloned());
        }
        for v in &out.verified[self.verified..] {
            ids.extend(v.requirement_ids.iter().cloned());
        }
        for (list, _) in &out.not_assessed[self.not_assessed..] {
            ids.extend(list.split(',').map(|id| id.trim().to_owned()));
        }
        ids.retain(|id| !id.is_empty());
        ids
    }

    /// Holds a check that speaks once it has asked: when it asked the app anything and named none
    /// of `speaks_to`, those are not assessed, "asked and never answered", rather than left out of
    /// the report; and sv-check's own tests stop there, so the check is fixed rather than
    /// covered for.
    fn held(&self, out: &mut Outcome, check: &str, speaks_to: &[&str], asked: usize) {
        if asked == self.asked {
            return;
        }
        let named = self.since(out);
        if speaks_to.iter().any(|id| named.contains(*id)) {
            return;
        }
        // sv-check's own tests stop here, against the fake app, where every check's every path is
        // known. Not any debug build: `sv` built for the workspace's tests runs real apps in
        // Docker, and there a silent check is said in the report rather than ending the run.
        if cfg!(test) {
            panic!(
                "`{check}` asked the app {} time(s) and returned without naming any of \
                 {speaks_to:?}: a finding, a credit, or a not-assessed entry with its reason",
                asked - self.asked
            );
        }
        out.not_assessed.push((
            speaks_to.join(", "),
            format!(
                "A check asked the app about this and returned without saying what it found \
                 (`{check}`), so nothing about it is known from this run."
            ),
        ));
    }
}

/// Runs one check of the suite that speaks once it has asked, and holds it to that
/// (`Said::held`): the architecture assessment of 8 October 2026, item 8, which found four checks
/// that returned without a word. `speaks_to` is every requirement the check names.
macro_rules! asked {
    ($out:ident, $http:ident, $check:literal, $speaks_to:expr, $call:expr) => {{
        let said = Said::mark(&$out, $http.asked);
        let answer = $call;
        said.held(&mut $out, $check, $speaks_to, $http.asked);
        answer
    }};
}

/// Runs one check that may ask and then say nothing, as its answer: its rules are findings only
/// (`tools/coverage.py`, the findings-only list), or it credits only what it can show, so saying
/// nothing means nothing was found and nothing shown. Marked, so every check in the suite is one
/// kind or the other (`check_guard_tests`).
macro_rules! quiet {
    ($call:expr) => {
        $call
    };
}

/// `run_with`, with the waiting for a limiter counted against `spent`, the run's one budget.
pub fn run_within(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    seeded: bool,
    policy: &sv_manifest::PolicySection,
    slow: bool,
    spent: &std::cell::Cell<u64>,
) -> Outcome {
    let mut patient = Patient::within(http, spent);
    patient.login_path = users
        .login
        .as_ref()
        .map(|login| login.path.split('?').next().unwrap_or_default().to_owned());
    let mut out = run_checks(&mut patient, users, accounts, seeded, policy, slow);
    patient.settle(&mut out);
    out
}

/// What a limiter that kept answering after the wait means for `out` (ADR-021): said once; the
/// sign-ins it refused named; every credit not assessed, since a refusal may have been the
/// limiter's; the findings kept, with a note.
fn settle_limited(patient: &mut Patient<'_>, out: &mut Outcome) {
    if patient.still_limited.is_empty() {
        return;
    }
    let limited = patient.still_limited.join(", ");
    out.steps.push(format!(
        "the app's rate limiter was still answering after waiting as it asked: {limited}"
    ));
    // The sign-ins the limit refused, said once and plainly, under every requirement whose check
    // they kept from running or from being credited.
    let refused_sign_ins = std::mem::take(&mut patient.limited_sign_ins);
    if !refused_sign_ins.is_empty() {
        let withheld: Vec<&str> = out
            .verified
            .iter()
            .flat_map(|v| v.requirement_ids.iter().map(String::as_str))
            .collect();
        out.not_assessed.push((
            limit_gap_names(&withheld, &refused_sign_ins),
            sign_in_limit_says(&refused_sign_ins),
        ));
    }
    for credit in std::mem::take(&mut out.verified) {
        out.not_assessed.push((
            credit.requirement_ids.join(", "),
            format!(
                "`{}` would have been credited ({}), but the app's rate limiter was still refusing \
                 requests after `sv` waited as it asked ({limited}), so a refusal here may be the \
                 limiter's rather than the app's own check. Run again with the limiter relaxed for \
                 the test run, or with a longer wait between requests.",
                credit.check_id, credit.scope
            ),
        ));
    }
    if !out.findings.is_empty() {
        let mut ids: Vec<&str> = out
            .findings
            .iter()
            .flat_map(|f| f.requirement_ids.iter().map(String::as_str))
            .collect();
        ids.sort_unstable();
        ids.dedup();
        out.not_assessed.push((
            ids.join(", "),
            format!(
                "The app's rate limiter was still refusing requests after `sv` waited as it asked \
                 ({limited}). The findings above are kept, but one that rests on the app refusing \
                 something may be the limiter's refusal: read each against its evidence."
            ),
        ));
    }
}

/// The passes the signed-in checks credit because the app refused something, and the requests
/// whose refusal earns each: an id, or the start of one when it ends in `-`. A server error (5xx),
/// or no answer at all, is read as "not 2xx" and so as refused wherever a refusal is read, which
/// credited a page that crashes for a stranger as refused to somebody not signed in. A crash is
/// not an answer to the question, so a pass here is withheld when any of its requests crashed.
///
/// `a_crash_never_turns_a_finding_into_a_pass` holds it: it runs the scripted app with its flaws
/// switched on, crashes each request a run sends, one at a time, and fails when a rule held back
/// without the crash is credited with it. It found requests this list first missed, of
/// five kinds. It can only try a rule some scenario holds back (finds at fault, or, for a rule
/// that is only ever credited, leaves open), and fails when
/// a rule listed here is not; a new check that credits a refusal needs its flaw added to a
/// scenario there.
const RESTS_ON_A_REFUSAL: &[(&str, &[&str])] = &[
    (PRIVATE_PAGE.rule_id, &["private-anonymous"]),
    (ADMIN_PAGE.rule_id, &["login-a", "admin-a"]),
    (ROLE_FIELD.rule_id, &["role-admin-"]),
    (
        EMAIL_ROLE_FIELD.rule_id,
        &["email-role-admin-", "email-role-change"],
    ),
    (
        OTHER_USERS_DATA.rule_id,
        &[
            "login-b",
            "owned-b",
            "owned-anonymous",
            // ADR-053: the lists the second user opens, the change and delete they send, and the
            // first user's read-back after each. A crashed change or delete is not one refused.
            "owned-b-list-",
            "owned-b-update",
            "owned-b-delete",
            "owned-a-after-",
            // ADR-053, Later: the first user's own request at a second record, which shows the
            // request reaches a route; a crashed control is not a control that worked.
            "owned-control-",
        ],
    ),
    (FORGERY.rule_id, &["forged-create"]),
    (STEP_SKIPPED.rule_id, &["flow-flow-b"]),
    (
        EMAIL_CODE_UNBOUND.rule_id,
        &["email-code-use-crossed", "email-code-private-crossed"],
    ),
    (
        EMAIL_CODE_REUSABLE.rule_id,
        &["email-code-use-again", "email-code-private-again"],
    ),
    (
        EMAIL_CODE_LONG_LIVED.rule_id,
        &["email-code-use-late", "email-code-private-late"],
    ),
    (
        EMAIL_CODE_GUESSING.rule_id,
        &[
            "email-code-use-guess-",
            "email-code-use-after-guesses",
            "email-code-private-after-guesses",
        ],
    ),
    (NO_BRUTE_FORCE_LIMIT.rule_id, &["guess-"]),
    (
        BREACHED_PASSWORD.rule_id,
        &["signup-breached", "login-breached", "private-breached"],
    ),
    (
        SHORT_PASSWORD.rule_id,
        &["signup-short", "login-short", "private-short"],
    ),
    (
        COMMON_PASSWORD.rule_id,
        &[
            "signup-common",
            "login-common",
            "private-common",
            // ADR-055: the two more common words.
            "signup-common-b",
            "login-common-b",
            "private-common-b",
            "signup-common-c",
            "login-common-c",
            "private-common-c",
        ],
    ),
    (
        CONTEXT_WORD_PASSWORD.rule_id,
        &["signup-context", "login-context", "private-context"],
    ),
    (
        ALTERED_PASSWORD.rule_id,
        &["login-case", "private-case", "login-cut", "private-cut"],
    ),
    (CHANGE_PASSWORD.rule_id, &["login-old", "private-old"]),
    (
        CHANGE_WITHOUT_CURRENT.rule_id,
        &[
            "change-password-wrong-current",
            "login-wrong-current",
            "private-wrong-current",
            "login-changed",
            "private-changed",
        ],
    ),
    (CHANGE_ENDS_SESSIONS.rule_id, &["bystander-after"]),
    (DONE_TWICE.rule_id, &["once"]),
    (CREATE_UNLIMITED.rule_id, &["burst-"]),
    (
        EMAIL_CHANGE_WITHOUT_PASSWORD.rule_id,
        &[
            "change-email-wrong-password",
            "login-email-wrong-password",
            "login-email-moved-wrong",
            "private-email-moved-wrong",
        ],
    ),
    (
        SESSIONS_SURVIVE_DELETION.rule_id,
        &["delete-after", "login-deleted", "private-deleted"],
    ),
    (NO_IDLE_TIMEOUT.rule_id, &["timeout-idle-after"]),
    (
        NO_SESSION_LIFETIME.rule_id,
        &["timeout-busy-after-lifetime"],
    ),
    (SESSION_TOKEN_UNVERIFIED.rule_id, &["invented-session"]),
    (APP_TOKEN_UNSIGNED.rule_id, &["token-altered"]),
    (APP_TOKEN_ALG_NONE.rule_id, &["token-alg-none"]),
    (APP_TOKEN_EXPIRED.rule_id, &["token-expired"]),
    (
        WS_WITHOUT_SESSION.rule_id,
        &["websocket-no-session", "websocket-invented-session"],
    ),
    (WS_FOREIGN_ORIGIN.rule_id, &["websocket-foreign-origin"]),
    (LOGOUT.rule_id, &["after-logout"]),
    (
        TOTP_OLD_CODE.rule_id,
        &["login-1", "totp-1", "totp-confirm-1"],
    ),
    (
        TOTP_REUSED.rule_id,
        &["login-3-", "totp-3-", "totp-confirm-3-"],
    ),
    (OVERSIZED_FILE.rule_id, &["upload-oversized"]),
    (CONTENT_MISMATCH.rule_id, &["upload-mismatched"]),
    (UPLOAD_SVG_SCRIPT.rule_id, &["upload-svg"]),
    (UPLOAD_PATH_TRAVERSAL.rule_id, &["upload-traversal"]),
    (UPLOAD_NOT_SCANNED.rule_id, &["upload-eicar"]),
    (ARCHIVE_UNCHECKED.rule_id, &["upload-archive-"]),
];

/// The findings the signed-in checks raise because the app refused something, or answered two
/// requests differently, and the requests whose answer raises each. A crash on one of them reads
/// as the app refusing: a page that fails after signing out by a plain link reads as the session
/// ended, a sign-up with a lowercase or a long password that fails reads as the password refused,
/// a reset for nobody that fails reads as answered differently from one for a real account, and a
/// guess that fails may never have been counted by the app's limit. So a finding here is moved to
/// not assessed when any of its requests crashed.
///
/// `a_crash_on_a_correct_app_raises_no_finding` holds it: it crashes each request of a correct
/// app, one at a time, and fails on any finding that appears, listed here or not.
const RAISED_ON_A_REFUSAL: &[(&str, &[&str])] = &[
    (SIGN_OUT_ON_GET.rule_id, &["private-after-get-logout"]),
    (
        COMPOSITION_RULES.rule_id,
        &["signup-lower", "login-lower", "private-lower"],
    ),
    (
        LONG_PASSWORD.rule_id,
        &["signup-long", "login-long", "private-long"],
    ),
    (RESET_REVEALS_ACCOUNT.rule_id, &["reset-request-"]),
    (SIGNIN_REVEALS_ACCOUNT.rule_id, &["reveal-"]),
    (SIGNUP_REVEALS_ACCOUNT.rule_id, &["signup-reveal-"]),
    (NO_BRUTE_FORCE_LIMIT.rule_id, &["guess-"]),
];

/// Whether `id` is one of `requests`: equal to one, or the page fetched for its form's token
/// first (`signup-short-page`), or starting with one that ends in `-`.
fn one_of(id: &str, requests: &[&str]) -> bool {
    let id = id.strip_suffix("-page").unwrap_or(id);
    requests
        .iter()
        .any(|r| id == *r || (r.ends_with('-') && id.starts_with(r)))
}

/// Moves each pass that rests on a refusal, and each finding raised from one, to not assessed when
/// one of its requests crashed.
fn withhold_what_rests_on_a_crash(crashed: &[(String, String)], out: &mut Outcome) {
    if crashed.is_empty() {
        return;
    }
    let mut kept = Vec::new();
    for credit in std::mem::take(&mut out.verified) {
        let rests_on = RESTS_ON_A_REFUSAL
            .iter()
            .find(|(rule, _)| *rule == credit.check_id)
            .map_or(&[][..], |(_, requests)| *requests);
        let answers: Vec<String> = crashed
            .iter()
            .filter(|(id, _)| one_of(id, rests_on))
            .map(|(id, status)| format!("{id} ({status})"))
            .collect();
        if answers.is_empty() {
            kept.push(credit);
            continue;
        }
        out.not_assessed.push((
            credit.requirement_ids.join(", "),
            format!(
                "`{}` would have been credited ({}) because the app did not let something \
                 through, but the app crashed or did not answer rather than refusing: {}. A crash \
                 is not an answer to whether it would have let it through, so this is not \
                 credited. Fix the error, and run it again.",
                credit.check_id,
                credit.scope,
                answers.join(", ")
            ),
        ));
    }
    out.verified = kept;

    let mut kept = Vec::new();
    for finding in std::mem::take(&mut out.findings) {
        let rests_on = RAISED_ON_A_REFUSAL
            .iter()
            .find(|(rule, _)| *rule == finding.rule_id)
            .map_or(&[][..], |(_, requests)| *requests);
        let answers: Vec<String> = crashed
            .iter()
            .filter(|(id, _)| one_of(id, rests_on))
            .map(|(id, status)| format!("{id} ({status})"))
            .collect();
        if answers.is_empty() {
            kept.push(finding);
            continue;
        }
        out.not_assessed.push((
            finding.requirement_ids.join(", "),
            format!(
                "`{}` (\"{}\") would have been reported because the app seemed to refuse \
                 something, but the app crashed or did not answer rather than refusing: {}. A \
                 crash is not an answer, so this is neither reported nor credited. Fix the error, \
                 and run it again.",
                finding.rule_id,
                finding.title,
                answers.join(", ")
            ),
        ));
    }
    out.findings = kept;
}

/// What came back to a question, before any check reads it (ADR-021): the app's own answer, or one
/// of the three things that are not one. Every check that reads whether the app answered reads it
/// through here (`answer_of`), so the rule is written once. Until 8 October 2026 it was written in
/// seven places with three definitions, one of them missing the limiter's 503 (the architecture
/// assessment of that day, item 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer<'a> {
    /// The app answered the question: a status below 500 that is not a limiter's.
    Answered(&'a ProbeResponse),
    /// Nothing came back, or nothing that was HTTP.
    Silent,
    /// A server error that is not the limiter's: the app failed, which says nothing about whether
    /// it would have let the request through.
    Crashed(u16),
    /// A rate limiter's: 429, or 503 with `Retry-After`. The request was stopped before it reached
    /// the check it was asking about. `retry_after` is what the app asks to wait, in seconds.
    Limited { status: u16, retry_after: u64 },
}

impl<'a> Answer<'a> {
    /// The app's own answer, when there is one.
    pub fn answered(self) -> Option<&'a ProbeResponse> {
        match self {
            Answer::Answered(r) => Some(r),
            _ => None,
        }
    }

    /// Whether a rate limiter answered in the app's place.
    pub fn is_limited(self) -> bool {
        matches!(self, Answer::Limited { .. })
    }

    /// Whether the app crashed or did not answer: not a refusal, and not the limiter's either.
    pub fn is_crash_or_silence(self) -> bool {
        matches!(self, Answer::Silent | Answer::Crashed(_))
    }
}

/// How a crash or a silence is written down for `RESTS_ON_A_REFUSAL`: the status, or "no answer".
fn crash_of(response: Option<&ProbeResponse>) -> Option<String> {
    match answer_of(response) {
        Answer::Silent => Some("no answer".to_owned()),
        Answer::Crashed(status) => Some(status.to_string()),
        Answer::Answered(_) | Answer::Limited { .. } => None,
    }
}

/// What `response` is, by the one rule (ADR-021).
pub fn answer_of(response: Option<&ProbeResponse>) -> Answer<'_> {
    let Some(r) = response else {
        return Answer::Silent;
    };
    if let Some(retry_after) = rate_limited(r) {
        return Answer::Limited {
            status: r.status,
            retry_after,
        };
    }
    if r.status == 0 {
        return Answer::Silent;
    }
    if r.status >= 500 {
        return Answer::Crashed(r.status);
    }
    Answer::Answered(r)
}

/// Seconds to wait before asking again, when `response` is a rate limiter's rather than an answer to
/// the question: 429, or 503 with `Retry-After`. The app's own `Retry-After` in seconds, at most a
/// minute; five seconds when it gives none, or gives a date.
pub(crate) fn rate_limited(response: &ProbeResponse) -> Option<u64> {
    let retry_after = response.header("retry-after");
    match response.status {
        429 => {}
        503 if retry_after.is_some() => {}
        _ => return None,
    }
    Some(
        retry_after
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(5)
            .min(60),
    )
}

/// The questions asked as somebody not signed in, each through the same wait as the signed-in
/// ones, and what came back.
///
/// An answer that is still the rate limiter's after the wait is left out, as a request that got no
/// answer is: the checks that read these (`probes::evaluate`, `probes::verified`,
/// `probes::evaluate_api`, `running::evaluate`) judge whatever they are given as the app's, so a
/// limiter's page on `/` would be a security-headers finding the app does not deserve, and a
/// limiter's 429 on `/.git/HEAD` would be credited as the folder not exposed. The requests left
/// out are returned, as "id (status)", for the run to say which they were.
pub fn ask_anonymously(
    http: &mut dyn Http,
    requests: &[ProbeRequest],
) -> (Vec<ProbeResponse>, Vec<String>) {
    ask_anonymously_within(http, requests, &std::cell::Cell::new(0))
}

/// `ask_anonymously`, with the waiting for a limiter counted against `spent`, the seconds already
/// waited in this run: one budget for the whole run (`MOST_WAITING`), not one per suite.
pub fn ask_anonymously_within(
    http: &mut dyn Http,
    requests: &[ProbeRequest],
    spent: &std::cell::Cell<u64>,
) -> (Vec<ProbeResponse>, Vec<String>) {
    let mut patient = Patient::within(http, spent);
    // In one go when the way to the app allows, up to the first answer that is a rate limiter's.
    // From there on, one at a time as before: that answer is waited out and the request asked
    // again, and so is each after it, so the waiting is what it was. Each of those was also asked
    // in the one go, which a limiter counts; it was already saying no.
    let in_turn = patient.inner.send_in_turn(requests).unwrap_or_default();
    let mut answers = Vec::new();
    let mut from = 0;
    for answer in in_turn.into_iter().take(requests.len()) {
        if answer.as_ref().is_some_and(|a| rate_limited(a).is_some()) {
            break;
        }
        answers.extend(answer);
        from += 1;
    }
    answers.extend(
        requests[from..]
            .iter()
            .filter_map(|request| patient.send(request))
            .filter(|answer| rate_limited(answer).is_none()),
    );
    (answers, patient.still_limited)
}

/// The app, with a rate limiter's answer waited out once.
///
/// A 429 from a limiter says nothing about the question asked: a private page refused with 429 was
/// never shown to the app's own sign-in check, and a check that reads "not 2xx" as "refused" would
/// credit a refusal nobody made (V8.2.1, and wherever else a refusal is read), or report one (a
/// sign-out that seemed to end a session). So a limited answer is waited out, as long as the app
/// asks and at most a minute, and the request sent once more. Not for a request whose id says it is
/// a guess, or part of a burst (`burst-`): those checks send requests on purpose to see the limiter
/// answer, and a wait would both change what they measure and send one more than they count.
pub struct Patient<'a> {
    inner: &'a mut dyn Http,
    /// Requests the limiter was still answering after the wait, as "id (status)".
    still_limited: Vec<String>,
    /// The path sign-ins are sent to (`[stack.run.users] login`), without its query.
    login_path: Option<String>,
    /// Of `still_limited`, the sign-ins: requests other than GET to `login_path`, by id.
    limited_sign_ins: Vec<String>,
    /// Seconds waited so far in this run, against `MOST_WAITING`: shared with the other suites of
    /// the run when made with `within`, so the run as a whole waits at most that long.
    waited: WaitedSoFar<'a>,
    /// Requests answered with a server error (5xx) or not answered at all: (request id, status or
    /// "no answer").
    crashed: Vec<(String, String)>,
}

/// All the waiting one run does for a rate limiter. Each wait is at most a minute, but a limiter
/// answering every request would otherwise hold a run up for a minute a request; past this, a
/// limited answer is recorded as the limiter's without waiting.
pub const MOST_WAITING: u64 = 300;

/// The seconds a run has spent waiting for a limiter: this suite's own count, or the run's, shared.
enum WaitedSoFar<'a> {
    Own(u64),
    Shared(&'a std::cell::Cell<u64>),
}

impl WaitedSoFar<'_> {
    fn get(&self) -> u64 {
        match self {
            WaitedSoFar::Own(n) => *n,
            WaitedSoFar::Shared(cell) => cell.get(),
        }
    }

    fn add(&mut self, seconds: u64) {
        match self {
            WaitedSoFar::Own(n) => *n += seconds,
            WaitedSoFar::Shared(cell) => cell.set(cell.get() + seconds),
        }
    }
}

impl<'a> Patient<'a> {
    pub fn new(inner: &'a mut dyn Http) -> Self {
        Patient {
            inner,
            still_limited: Vec::new(),
            login_path: None,
            limited_sign_ins: Vec::new(),
            waited: WaitedSoFar::Own(0),
            crashed: Vec::new(),
        }
    }

    /// As `new`, with the waiting counted against `spent`, shared by every suite of the run.
    pub fn within(inner: &'a mut dyn Http, spent: &'a std::cell::Cell<u64>) -> Self {
        let mut patient = Patient::new(inner);
        patient.waited = WaitedSoFar::Shared(spent);
        patient
    }

    /// What the limiter and the crashes left, said in `out` as every suite says it: the credits a
    /// limiter that kept answering puts in doubt become not assessed, the findings are kept with a
    /// note, and what rests on a request that crashed is withheld (ADR-021). Called once a suite is
    /// done asking.
    pub fn settle(&mut self, out: &mut Outcome) {
        withhold_what_rests_on_a_crash(&self.crashed, out);
        settle_limited(self, out);
    }
}

impl Patient<'_> {
    /// The app's answer, with a rate limiter's waited out once.
    fn answer(&mut self, request: &ProbeRequest) -> Option<ProbeResponse> {
        let first = self.inner.send(request);
        if request.id.contains("guess") || request.id.starts_with("burst-") {
            return first;
        }
        let Some(wait) = first.as_ref().and_then(rate_limited) else {
            return first;
        };
        if self.waited.get() + wait > MOST_WAITING {
            if let Some(r) = &first {
                self.still_limited.push(format!(
                    "{} ({}, not waited for: {MOST_WAITING} seconds already spent waiting)",
                    request.id, r.status
                ));
                self.note_sign_in(request);
            }
            return first;
        }
        self.waited.add(wait);
        self.inner.wait(wait);
        let second = self.inner.send(request);
        if let Some(r) = second.as_ref().filter(|r| rate_limited(r).is_some()) {
            self.still_limited
                .push(format!("{} ({})", request.id, r.status));
            self.note_sign_in(request);
        }
        second
    }

    /// Notes `request`, which the limiter is still answering, as a refused sign-in when it is one:
    /// sent to the sign-in path, and not the GET for the sign-in page.
    fn note_sign_in(&mut self, request: &ProbeRequest) {
        let path = request.path.split('?').next().unwrap_or_default();
        if request.method != "GET" && self.login_path.as_deref() == Some(path) {
            self.limited_sign_ins.push(request.id.clone());
        }
    }
}

impl Http for Patient<'_> {
    fn send(&mut self, request: &ProbeRequest) -> Option<ProbeResponse> {
        let answer = self.answer(request);
        // A crash, or no answer at all, is not the app refusing. Recorded for every request,
        // the guesses included, and read against `RESTS_ON_A_REFUSAL` once the run is over.
        if let Some(status) = crash_of(answer.as_ref()) {
            self.crashed.push((request.id.clone(), status));
        }
        answer
    }

    fn send_together(&mut self, requests: &[ProbeRequest]) -> Option<Vec<Option<ProbeResponse>>> {
        // Not waited out: a limiter's answer to a copy sent together is part of what was asked.
        let answers = self.inner.send_together(requests)?;
        for (request, answer) in requests.iter().zip(&answers) {
            if let Some(status) = crash_of(answer.as_ref()) {
                self.crashed.push((request.id.clone(), status));
            }
        }
        Some(answers)
    }

    fn mail(&mut self, to: &str, at_least: usize) -> Option<Vec<String>> {
        self.inner.mail(to, at_least)
    }

    fn now(&mut self) -> u64 {
        self.inner.now()
    }

    fn wait(&mut self, seconds: u64) {
        self.inner.wait(seconds);
    }

    fn provider(&mut self, request: &ProbeRequest) -> Option<ProbeResponse> {
        self.inner.provider(request)
    }

    fn browser(&mut self, job: &crate::browser::Job) -> Option<Vec<serde_json::Value>> {
        self.inner.browser(job)
    }

    fn model(&mut self, request: &ProbeRequest) -> Option<ProbeResponse> {
        self.inner.model(request)
    }

    fn model_address(&mut self) -> Option<String> {
        self.inner.model_address()
    }
}

/// The checks themselves, in order; `run_with` wraps them.
fn run_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    seeded: bool,
    policy: &sv_manifest::PolicySection,
    slow: bool,
) -> Outcome {
    let mut counted = Counted {
        inner: http,
        asked: 0,
    };
    let http = &mut counted;
    let mut out = Outcome::default();
    let problems = users.problems();
    if !problems.is_empty() {
        out.not_assessed.push((
            "V8.2.1, V8.2.2, V7.2.4, V7.4.1, V3.5.1, V14.3.2, V7.4.4".to_owned(),
            format!(
                "[stack.run.users] in stackvet.toml cannot be used: {}.",
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
            let response = sign_up(http, users, signup, who, account);
            out.steps.push(format!(
                "signed up {} ({})",
                who.to_uppercase(),
                status(&response)
            ));
        }
    }

    // 1. Private pages, as nobody. This needs no account, so it runs whatever happens next.
    //    A page that answers exactly as the front page does is the app's page shell: a single-page
    //    app sends everybody the same page and draws it in the browser from what it fetches after.
    //    That answer is neither the private page served nor refused, so the page is set aside here
    //    and every check after this one is given the private pages that are left.
    let anonymous = Session::default();
    let front = http.send(&get("front-anonymous", "/", &anonymous));
    let mut served_anonymously = Vec::new();
    let mut shells = Vec::new();
    for path in &users.private {
        let response = http.send(&get("private-anonymous", path, &anonymous));
        if is_page_shell(&response, &front) {
            shells.push(path.clone());
        } else if ok(&response) {
            served_anonymously.push(path.clone());
        }
    }
    let judged;
    let users = if shells.is_empty() {
        users
    } else {
        out.steps.push(
            format!(
                "{} answered exactly as the front page does, so not judged: {}",
                shells.join(", "),
                if shells.len() == 1 {
                    "it is"
                } else {
                    "they are"
                }
            ) + " the app's page shell",
        );
        judged = UsersSection {
            private: users
                .private
                .iter()
                .filter(|p| !shells.contains(p))
                .cloned()
                .collect(),
            ..users.clone()
        };
        &judged
    };
    if !shells.is_empty() && users.private.is_empty() {
        out.not_assessed.push((
            PRIVATE_PAGE.requirement_ids.join(", "),
            format!(
                "Every private page ({}) answered somebody not signed in exactly as the front page \
                 does: the app's page shell, which a single-page app sends everybody and fills in \
                 the browser. Whether the page is private is decided by what the browser fetches \
                 next. List those addresses (`/api/me`, for example) under `private` in \
                 stackvet.toml, and they are asked instead.",
                shells.join(", ")
            ),
        ));
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
        if a.limited {
            // Not the sign-in request, the accounts, or the page: the app's limit refused it, and
            // `run_with` says so, with what to change, once the run is over.
            out.steps.push(
                "signing in as A was refused by the app's limit on sign-in attempts".to_owned(),
            );
            return out;
        }
        out.not_assessed.push((
            NEEDS_A_SESSION.to_owned(),
            format!(
                "Signing in as the first test user did not open {} — the sign-in request, the \
                 accounts, or the page is not what stackvet.toml says — so nothing here can say \
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
                "{} private page{}, refused to somebody not signed in and opened by a signed-in user{}",
                users.private.len(),
                if users.private.len() == 1 { "" } else { "s" },
                if shells.is_empty() {
                    String::new()
                } else {
                    format!(
                        "; {} answered as the front page does and {} not judged",
                        shells.join(", "),
                        if shells.len() == 1 { "was" } else { "were" }
                    )
                }
            ),
        ));
    }

    // 2a. The same private pages, as nobody but naming A in a header a proxy would add. Here,
    //     because only now is it known that signing in opens them and a stranger does not.
    if signed_in_works {
        let refused: Vec<String> = users
            .private
            .iter()
            .filter(|p| !served_anonymously.contains(p))
            .cloned()
            .collect();
        quiet!(identity_header_check(
            http,
            &accounts.a.user,
            &refused,
            &mut out
        ));
    }

    // 2b. The session timeouts, which mean waiting. Here, while A's password is still the one it
    //     was made with — later checks change it when there is no sign-up — and with sessions of
    //     its own, so nothing below is using them.
    let waited = asked!(
        out,
        http,
        "session_timeout_checks",
        &["V7.3.1", "V7.3.2"],
        session_timeout_checks(
            http,
            users,
            &accounts.a,
            confirm_path.as_deref().filter(|_| signed_in_works),
            policy,
            slow,
            &mut out
        )
    );
    // 2c. A's session sat unused through that wait, and an app with an idle timeout has ended it:
    //     every check below would be asking with a session the app no longer knows, and reading
    //     its refusals as answers. So A signs in afresh, and is shown working again as in step 2.
    let a = if waited {
        match sign_in_again(
            http,
            users,
            &accounts.a,
            confirm_path.as_deref().filter(|_| signed_in_works),
            &mut out,
        ) {
            Some(fresh) => fresh,
            None => return out,
        }
    } else {
        a
    };

    // 3. A record A owns, read as B and as nobody; then the same request from another site. First
    //    among the signed-in checks because A reading back what A made is the second way to show
    //    the session works — the only way, when the private page turned out to be open to all.
    let owned_read = asked!(
        out,
        http,
        "owned_checks",
        &["V3.5.1", "V3.5.2", "V8.2.2", "V8.2.3", "V15.3.1"],
        owned_checks(http, users, accounts, &a, &mut out)
    );

    // 3½. Another site's Origin on the private pages, as A (ADR-055): the place a page that lets any
    //     site read it does harm, which the anonymous question to the health path never reaches.
    quiet!(cross_site::private_pages(http, users, &a, &mut out));

    // 4. The session cookie, and whether signing in made a new one, once it is shown which cookies
    //    carry the session.
    let carried = sign_in_cookies_carry_session(
        http,
        &a,
        confirm_path.as_deref().filter(|_| signed_in_works),
    );
    asked!(
        out,
        http,
        "session_checks",
        &["V3.3.2", "V3.3.4", "V7.2.4"],
        session_checks(
            &a,
            signed_in_works || owned_read.is_some(),
            carried,
            &mut out
        )
    );

    // 4b. The markers the log check reads afterwards. Done here because the successful one has to
    //     be a sign-in that really worked, and the refused one a page that is really private.
    quiet!(plant_log_markers(
        http,
        users,
        accounts,
        signed_in_works,
        &mut out
    ));

    // 5. The private pages themselves, read with A's session: what they let a browser keep, and
    //    whether they show a way out. Before anything that signs another account in, so the
    //    session that opened them is the one step 2 showed working.
    asked!(
        out,
        http,
        "private_page_checks",
        &[
            "V3.4.3", "V3.4.4", "V3.4.5", "V3.4.6", "V7.4.4", "V14.2.2", "V14.3.2", "V3.3.2",
            "V3.3.4"
        ],
        private_page_checks(http, users, &a, carried, &mut out)
    );

    // 5b. The same pages drawn in a real browser, when stackvet.toml asks for one, with A's
    //     cookies: whether the way out can be seen, and whether text typed into a form comes back
    //     as text. Here for the same reason as step 5, and it signs nobody else in.
    asked!(
        out,
        http,
        "checks",
        &["V7.4.4"],
        crate::browser::checks(
            http,
            users,
            &a.session,
            &accounts.a,
            signed_in_works,
            &crate::browser::token(&accounts.spare),
            &mut out
        )
    );

    // 6. Admin pages, as an ordinary user, confirmed against the admin.
    asked!(
        out,
        http,
        "admin_checks",
        &["V8.2.1", "V8.3.1"],
        admin_checks(http, users, accounts, &a, &mut out)
    );

    // 6a. Three more, each reading something the run already has or sending one more request:
    //     a session value this check invented, the rules the sign-up form states, and whether the
    //     record read back above carried fields that should not leave the server.
    asked!(
        out,
        http,
        "invented_session_check",
        &["V7.2.1"],
        invented_session_check(
            http,
            &a,
            confirm_path.clone().filter(|_| signed_in_works).as_deref(),
            carried,
            &mut out
        )
    );
    quiet!(client_side_validation_check(
        http, users, accounts, &mut out
    ));
    // 6a'. The app's own sign-in token, when it is a JWT, changed two ways and sent alone. With
    //      A's token, which nothing here changes.
    asked!(
        out,
        http,
        "app_token_checks",
        &["V9.1.1", "V9.1.2", "V9.1.3"],
        app_token_checks(
            http,
            &a,
            confirm_path.clone().filter(|_| signed_in_works).as_deref(),
            &mut out
        )
    );

    // 6b. Uploads, with A's session, before anything below signs another account in. Placed here
    //     rather than at the end because it needs a working session and nothing it does disturbs
    //     one: it posts files and fetches them back.
    asked!(
        out,
        http,
        "upload_checks",
        &[
            "V1.3.4", "V3.2.1", "V5.2.1", "V5.2.2", "V5.3.1", "V5.3.2", "V5.4.1", "V5.4.2",
            "V5.4.3"
        ],
        upload_checks(http, users, &a, &mut out)
    );

    // 6c. A flow of several steps, gone through in order with A's session and then skipped as B,
    //     signed in afresh. Neither disturbs A's session.
    asked!(
        out,
        http,
        "flow_checks",
        &["V2.3.1"],
        flow_checks(http, users, accounts, &a, &mut out)
    );

    // 6d. Database conditions added to values the app reads from an address, with A's session:
    //     requests that only read, which change nothing.
    quiet!(sql_injection_check(
        http,
        users,
        &a,
        owned_read.as_deref(),
        &mut out
    ));

    // 7. What sign-up and sign-in let through: passwords and default accounts. These sign in as
    //    other accounts, so A's session is untouched for the sign-out below.
    let confirm = confirm_path.clone().filter(|_| signed_in_works);
    asked!(
        out,
        http,
        "password_checks",
        &[
            "V6.2.1", "V6.2.4", "V6.2.5", "V6.2.8", "V6.2.9", "V6.2.11", "V6.2.12"
        ],
        password_checks(http, users, accounts, confirm.as_deref(), policy, &mut out)
    );
    quiet!(signup_reveals_account_check(
        http, users, accounts, &mut out
    ));
    quiet!(signup_replaces_account_check(
        http,
        users,
        accounts,
        confirm.as_deref(),
        &mut out
    ));
    quiet!(default_account_check(
        http,
        users,
        confirm.as_deref(),
        &mut out
    ));
    asked!(
        out,
        http,
        "password_field_checks",
        &["V6.2.6", "V6.2.7", "V6.4.2"],
        password_field_checks(http, users, Some(&a.session), &mut out)
    );

    // 8. Logging out, which ends A's session.
    asked!(
        out,
        http,
        "logout_check",
        &["V7.4.1", "V14.3.1"],
        logout_check(
            http,
            users,
            &a,
            confirm_path.filter(|_| signed_in_works).or(owned_read),
            &mut out
        )
    );

    // 9. Last, because each signs A in again, and an app that allows one session per user would
    //    end the one the checks above were using.
    quiet!(password_in_url_check(
        http,
        users,
        &accounts.a,
        confirm.as_deref(),
        &mut out
    ));
    asked!(
        out,
        http,
        "session_id_check",
        &["V7.2.2"],
        session_id_check(
            http,
            users,
            accounts,
            &a,
            confirm.as_deref(),
            signed_in_works,
            &mut out
        )
    );
    quiet!(sign_out_on_get_check(
        http,
        users,
        &accounts.a,
        confirm.as_deref(),
        &mut out
    ));
    // And signing out in a real browser, with a sign-in of its own: clicking the app's sign-out
    // ends that session, so it goes here, after the checks that needed A's.
    if users.browser.is_some() {
        let fresh = confirm
            .as_ref()
            .and_then(|_| sign_in(http, users, "a-browser", &accounts.a, &mut out.steps))
            .map(|s| s.session);
        asked!(
            out,
            http,
            "sign_out_check",
            &["V14.3.1"],
            crate::browser::sign_out_check(http, users, fresh.as_ref(), &mut out)
        );
    }
    // And what the app keeps in the browser after a sign-in through its own form: another sign-in,
    // so it goes here too.
    asked!(
        out,
        http,
        "storage_check",
        &["V10.1.1", "V14.3.3"],
        crate::browser_storage::storage_check(
            http,
            users,
            &accounts.a,
            confirm.is_some(),
            &mut out
        )
    );

    // 9b. A private WebSocket, with a sign-in of its own that it signs out at the end: after
    //     everything that needed A's first session.
    asked!(
        out,
        http,
        "websocket_session_checks",
        &["V4.4.2", "V4.4.3", "V4.4.4"],
        websocket_session_checks(http, users, &accounts.a, &mut out)
    );
    // 9b'. Where the sign-in and sign-out send the browser when given an address outside the app:
    //     sessions of their own, and nothing changed.
    quiet!(open_redirect_check(http, users, &accounts.a, &mut out));
    quiet!(page_redirect_check(http, users, &accounts.a, &mut out));
    // 9b''. The app's own sign-in token, waited out until it expires: a sign-in of its own, and
    //      before the password changes below, which can change A's.
    quiet!(app_token_expiry_check(
        http,
        users,
        &accounts.a,
        confirm.as_deref(),
        slow,
        &mut out
    ));

    // 9c. Admin actions, sent by A and then by the admin. Late, because an action changes what the
    //     app holds and the checks above have had what they needed; before the password changes
    //     below, one of which can change A's own password, and before the checks that set out to be
    //     refused and can leave the app refusing everybody, the admin included.
    asked!(
        out,
        http,
        "admin_action_checks",
        &["V8.2.1", "V8.3.1"],
        admin_action_checks(http, users, accounts, confirm.as_deref(), &mut out)
    );
    // 9d. A role written into the sign-up form, with two accounts made for it. Before the password
    //     changes for the same reason as the admin actions.
    quiet!(role_field_check(
        http,
        users,
        accounts,
        confirm.as_deref(),
        &mut out
    ));
    //     The same fields sent with an email change, by an account made for it (finding 13(a)).
    quiet!(email_role_check(
        http,
        users,
        accounts,
        confirm.as_deref(),
        &mut out
    ));
    // 9e. The action that should go through once, sent many times at the same instant by A.
    asked!(
        out,
        http,
        "once_check",
        &["V2.3.4"],
        once_check(http, users, accounts, &mut out)
    );
    // 9f. A burst of creations by B, held to the stated limit. Before the password changes, which can
    //     change B's password too (a reset); it sets out to be refused, so it waits the minute out
    //     afterwards before anything else is asked.
    asked!(
        out,
        http,
        "burst_check",
        &["V2.4.1"],
        burst_check(http, users, &accounts.b, policy, &mut out)
    );
    // 9g. Compressed files past the stated limits, with a sign-in of A's own: after every other
    //     upload, since an app that unpacks one may fall over; before the password changes below,
    //     which can change A's.
    asked!(
        out,
        http,
        "archive_checks",
        &["V5.2.3"],
        archives::archive_checks(http, users, accounts, confirm.as_deref(), &mut out)
    );

    // 10. Last of all, because it changes a password: with an account made for it when there is a
    //    sign-up, and with A's own when there is not.
    asked!(
        out,
        http,
        "change_password_checks",
        &["V6.2.2", "V6.2.3", "V6.3.7", "V7.4.3"],
        change_password_checks(http, users, accounts, confirm.as_deref(), &mut out)
    );
    asked!(
        out,
        http,
        "change_email_check",
        &["V7.5.1"],
        change_email_check(http, users, accounts, confirm.as_deref(), &mut out)
    );
    asked!(
        out,
        http,
        "delete_account_check",
        &["V7.4.2"],
        delete_account_check(http, users, accounts, confirm.as_deref(), &mut out)
    );
    asked!(
        out,
        http,
        "reset_checks",
        &["V6.3.8", "V6.4.3"],
        reset_checks(http, users, accounts, confirm.as_deref(), &mut out)
    );
    asked!(
        out,
        http,
        "activation_checks",
        &["V6.4.1"],
        activation_checks(http, users, accounts, confirm.as_deref(), &mut out)
    );
    asked!(
        out,
        http,
        "email_code_checks",
        &["V6.5.1", "V6.5.4", "V6.6.2", "V6.6.3"],
        email_code_checks(http, users, accounts, confirm.as_deref(), &mut out)
    );
    asked!(
        out,
        http,
        "email_code_lifetime",
        &["V6.5.5"],
        email_code_lifetime(http, users, accounts, confirm.as_deref(), slow, &mut out)
    );
    asked!(
        out,
        http,
        "totp_checks",
        &["V6.5.1", "V6.5.5"],
        totp_checks(http, users, accounts, confirm.as_deref(), &mut out)
    );

    // 10. After everything else, without exception. This one deliberately provokes the app into
    //     refusing requests, and a limiter that counts by address rather than by account would then
    //     be refusing every check above too. Running it last means the worst it can cost is itself.
    asked!(
        out,
        http,
        "brute_force_check",
        &["V6.3.1", "V15.3.4"],
        brute_force_check(http, users, accounts, policy, &mut out)
    );
    // And codes after passwords: both set out to be refused, and this one is the newer.
    asked!(
        out,
        http,
        "email_code_guessing",
        &["V6.6.3"],
        email_code_guessing(http, users, accounts, confirm.as_deref(), policy, &mut out)
    );
    // The only sign-ins after the guesses: three wrong passwords would use up part of a limit that
    // counts by address before the guessing check, and here a limit still refusing leaves them
    // uncompared rather than misread.
    quiet!(signin_reveals_account_check(
        http, users, accounts, &mut out
    ));

    out
}

/// Signs an account up through the app's own form.
/// Makes an account through `signup`, and — when the app activates accounts with an emailed code
/// (`activation`) — activates it, so every account a check signs up can sign in as that check
/// expects. Quietly: a check that needs to watch activation happen calls `sign_up_only`.
pub(crate) fn sign_up(
    http: &mut dyn Http,
    users: &UsersSection,
    signup: &RequestTemplate,
    who: &str,
    account: &Account,
) -> Option<ProbeResponse> {
    let Some(activation) = &users.activation else {
        return sign_up_only(http, signup, who, account);
    };
    let before = http.mail(&account.user, 0).map_or(0, |m| m.len());
    let answer = sign_up_only(http, signup, who, account);
    let code = code_patterns(
        activation.code_pattern.as_deref(),
        "activate|activation|verify|confirm|welcome",
    )
    .ok()
    .and_then(|patterns| {
        let mail = http.mail(&account.user, before + 1)?;
        mail.get(before..)?
            .last()
            .and_then(|m| reset_code(m, &patterns))
    });
    if let Some(code) = code {
        let values = Values {
            user: &account.user,
            code: &code,
            ..Default::default()
        };
        let mut session = Session::default();
        send_template(
            http,
            &format!("activate-{who}"),
            &activation.use_code,
            &values,
            &mut session,
            &[],
        );
    }
    answer
}

#[cfg(test)]
mod asked_tests;
#[cfg(test)]
mod check_guard_tests;
#[cfg(test)]
mod email_role_tests;
#[cfg(test)]
mod fake_app;
#[cfg(test)]
mod in_turn_tests;
#[cfg(test)]
mod owner_field_tests;
#[cfg(test)]
mod page_cookie_tests;
#[cfg(test)]
mod resignup_tests;
#[cfg(test)]
mod storage_check_tests;
#[cfg(test)]
mod stored_markup_tests;

#[cfg(test)]
mod tests {
    use super::fake_app::*;
    use super::*;

    #[test]
    fn one_rule_says_what_an_answer_is() {
        // ADR-021, in one place since 8 October 2026: the limiter's two shapes, a crash, silence,
        // and an answer. The 503 with `Retry-After` is the case one of the seven copies missed.
        let with = |status: u16, headers: &[(&str, &str)]| ProbeResponse {
            id: "q".to_owned(),
            status,
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            body: String::new(),
        };
        assert_eq!(answer_of(None), Answer::Silent);
        assert_eq!(answer_of(Some(&with(0, &[]))), Answer::Silent);
        assert_eq!(answer_of(Some(&with(500, &[]))), Answer::Crashed(500));
        assert_eq!(answer_of(Some(&with(503, &[]))), Answer::Crashed(503));
        assert_eq!(
            answer_of(Some(&with(503, &[("retry-after", "7")]))),
            Answer::Limited {
                status: 503,
                retry_after: 7
            }
        );
        assert_eq!(
            answer_of(Some(&with(429, &[]))),
            Answer::Limited {
                status: 429,
                retry_after: 5
            }
        );
        let ok = with(403, &[]);
        assert_eq!(answer_of(Some(&ok)), Answer::Answered(&ok));
        assert!(answer_of(Some(&with(429, &[]))).is_limited());
        assert!(answer_of(Some(&with(502, &[]))).is_crash_or_silence());
        assert!(!answer_of(Some(&with(429, &[]))).is_crash_or_silence());
        assert_eq!(crash_of(Some(&with(502, &[]))).as_deref(), Some("502"));
        assert_eq!(crash_of(None).as_deref(), Some("no answer"));
        assert_eq!(crash_of(Some(&with(429, &[]))), None);
    }
    use std::collections::BTreeMap;

    #[test]
    fn a_correct_app_raises_nothing_and_every_check_says_what_it_confirmed() {
        let o = run_against(Flaws::default(), &users());
        assert!(o.findings.is_empty(), "{:#?}", o.findings);
        for id in [
            PRIVATE_PAGE.rule_id,
            SESSION_COOKIE.rule_id,
            SESSION_RENEWAL.rule_id,
            ADMIN_PAGE.rule_id,
            ADMIN_ACTION.rule_id,
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
        assert!(note.contains("every other cookie kept: opened"), "{note}");
        assert!(note.contains("maxlength=40: accepted"), "{note}");
        assert!(note.contains("Clear-Site-Data: yes"), "{note}");
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
                    owner_from_request: true,
                    record_names_owner: true,
                    ..Default::default()
                },
                OWNER_FIELD.rule_id,
            ),
            (
                Flaws {
                    notes_unescaped: true,
                    ..Default::default()
                },
                STORED_HTML.rule_id,
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
            (
                Flaws {
                    no_referrer: true,
                    refuses_null_origin: true,
                    ..Default::default()
                },
                OWN_FORMS_REFUSED.rule_id,
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
                notes_unescaped: true,
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
            STORED_HTML.rule_id,
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
    fn a_cookie_set_at_sign_in_is_the_session_only_when_the_page_needs_it() {
        // The review of 1 to 4 October, item 13: an app that keeps its session from before sign-in
        // and sets an unrelated cookie at sign-in was found to take a made-up session (that cookie,
        // altered) and credited for renewing its session.
        let o = run_against(
            Flaws {
                keep_session_at_login: true,
                other_cookie_at_login: true,
                ..Default::default()
            },
            &users(),
        );
        let found = rule_ids(&o);
        assert!(found.contains(&SESSION_RENEWAL.rule_id), "{found:?}");
        assert!(
            !found.contains(&SESSION_TOKEN_UNVERIFIED.rule_id),
            "{found:?}"
        );
        assert!(!verified_ids(&o).contains(&SESSION_RENEWAL.rule_id));
        assert!(!verified_ids(&o).contains(&SESSION_COOKIE.rule_id));
        // The setup: sign-in really did set that cookie, and only it.
        assert!(
            o.steps.iter().any(|s| s.contains("signed in as A")),
            "{:?}",
            o.steps
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
    fn accounts_can_be_made_through_the_apps_own_sign_up() {
        // No seed: both users sign up the way a visitor would, token and all, and then everything
        // that does not need an admin runs as it does for a seeded app.
        let mut u = users();
        u.seed = None;
        u.admin = Vec::new();
        u.admin_actions = Vec::new();
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
        u.admin_actions = Vec::new();
        let o = run_against(Flaws::default(), &u);
        // Each id named in one of the lists, whatever else that list names beside it: since
        // 8 October 2026 the sign-out line names V14.3.1 with V7.4.1, and the owned line V3.5.2.
        let said: Vec<&str> = o
            .not_assessed
            .iter()
            .flat_map(|(ids, _)| ids.split(", "))
            .collect();
        for id in ["V7.4.1", "V8.2.2", "V3.5.1", "V8.2.1", "V3.3.1"] {
            assert!(said.contains(&id), "{id} not named: {said:?}");
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
            ..Default::default()
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

    /// The suite with no `seed`: every account, the test passwords' included, goes through sign-up.
    pub(super) fn with_signup() -> UsersSection {
        let mut u = users();
        u.seed = None;
        u.admin = Vec::new();
        u.admin_actions = Vec::new();
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

    pub(super) fn run_signing_up(flaws: Flaws) -> Outcome {
        run_signing_up_with(flaws, &with_words(&["Acme Notes"]))
    }

    pub(super) fn run_signing_up_with(
        flaws: Flaws,
        policy: &sv_manifest::PolicySection,
    ) -> Outcome {
        let mut app = FakeApp::new(flaws);
        let mut acc = accounts();
        acc.admin = None;
        acc.totp = None;
        run(&mut app, &with_signup(), &acc, false, policy)
    }

    /// A policy listing these context-specific words, as an owner would write them.
    pub(super) fn with_words(words: &[&str]) -> sv_manifest::PolicySection {
        sv_manifest::PolicySection {
            context_words: words.iter().map(|w| (*w).to_owned()).collect(),
            ..Default::default()
        }
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

    pub(super) fn run_with(flaws: Flaws, policy: &sv_manifest::PolicySection) -> Outcome {
        run_keeping_app(flaws, policy).0
    }

    /// The outcome and the app, for the assertions that are about what the app was *sent* rather
    /// than about what the report says.
    pub(super) fn run_keeping_app(
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

    /// The seeded fixture, with a policy: the other way into every emailed-code check, so none of
    /// them rests on the sign-up fixture alone.
    pub(super) fn seeded_with(flaws: Flaws, policy: &sv_manifest::PolicySection) -> Outcome {
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

    pub(super) fn timeouts(idle: Option<u32>, lifetime: Option<u32>) -> sv_manifest::PolicySection {
        sv_manifest::PolicySection {
            idle_timeout_minutes: idle,
            session_lifetime_minutes: lifetime,
            ..Default::default()
        }
    }

    // --------------------------------------------------------------------------------------------
    // A private WebSocket's own session

    const WS_RULES: [&str; 2] = [WS_WITHOUT_SESSION.rule_id, WS_AFTER_SIGN_OUT.rule_id];

    pub(super) fn ws_run(flaws: Flaws) -> Outcome {
        let mut u = users();
        u.private_websocket = Some("/ws".into());
        run_against(flaws, &u)
    }

    pub(super) fn ws_findings(o: &Outcome) -> Vec<&str> {
        rule_ids(o)
            .into_iter()
            .filter(|id| WS_RULES.contains(id))
            .collect()
    }

    pub(super) fn bearer_ws_users() -> UsersSection {
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
        u.private_websocket = Some("/ws".into());
        u
    }

    /// The fake app, with a browser that answers only the storage job: signed in through the form,
    /// and the password kept in `localStorage`.
    struct KeepsPassword {
        app: FakeApp,
        stored: String,
    }

    impl Http for KeepsPassword {
        fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
            self.app.send(r)
        }
        fn now(&mut self) -> u64 {
            self.app.now()
        }
        fn wait(&mut self, seconds: u64) {
            self.app.wait(seconds);
        }
        fn browser(&mut self, job: &crate::browser::Job) -> Option<Vec<serde_json::Value>> {
            use crate::browser::Action;
            use serde_json::json;
            let signs_in = job
                .actions
                .iter()
                .any(|a| matches!(a, Action::Act(e) if e.contains("input[type=password]")));
            if !signs_in {
                return None;
            }
            let store = |pairs: serde_json::Value| json!({ "value": { "local": pairs, "session": [], "indexeddb": [], "cookie": "" } });
            Some(vec![
                json!({ "status": 200, "path": "/login" }),
                store(json!([])),
                json!({ "found": true, "after": { "status": 200, "path": "/" } }),
                json!({ "status": 200, "path": "/account" }),
                store(json!([["pw", self.stored]])),
            ])
        }
    }

    #[test]
    fn the_suite_asks_the_browser_what_the_app_keeps_after_signing_in() {
        let mut u = users();
        u.browser = Some(Default::default());
        let acc = accounts();

        // No browser to start: said, never passed.
        let mut app = FakeApp::new(Flaws::default());
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let o = run(&mut app, &u, &acc, false, &Default::default());
        assert!(
            o.not_assessed.iter().any(|(ids, why)| ids == "V10.1.1, V14.3.3"
                && why.contains("could not be started")),
            "{:?}",
            o.not_assessed
        );

        // A browser that finds the password kept: the finding reaches the outcome.
        let mut app = FakeApp::new(Flaws::default());
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let mut http = KeepsPassword {
            app,
            stored: acc.a.password.clone(),
        };
        let o = run(&mut http, &u, &acc, false, &Default::default());
        assert!(
            rule_ids(&o).contains(&crate::browser_storage::PASSWORD_IN_STORAGE.rule_id),
            "{:?}",
            o.steps
        );
    }
}

/// A rate limiter's answer is not the app's answer to the question (V8.2.1 and wherever a refusal
/// is read). Found on 28 September 2026: the private-page check read anything but 2xx as "refused",
/// so a limiter's 429 was credited as the app refusing a stranger, and the sign-out check read one
/// as a GET having ended a session.
#[cfg(test)]
mod rate_limit_tests {
    use super::fake_app::*;
    use super::*;

    /// The fake app behind a limiter: the next `times` requests with id `id` are answered `status`,
    /// with `Retry-After: retry` when given, instead of reaching the app. Counts what it waited.
    struct Limited {
        app: FakeApp,
        id: &'static str,
        status: u16,
        retry: Option<&'static str>,
        times: u32,
        waited: u64,
        limited: u32,
    }

    impl Http for Limited {
        fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
            if (r.id == self.id || self.id == "*") && self.times > 0 {
                self.times -= 1;
                self.limited += 1;
                return Some(ProbeResponse {
                    id: r.id.clone(),
                    status: self.status,
                    headers: self
                        .retry
                        .map(|v| vec![("retry-after".to_owned(), v.to_owned())])
                        .unwrap_or_default(),
                    body: "slow down".into(),
                });
            }
            self.app.send(r)
        }
        fn mail(&mut self, to: &str, at_least: usize) -> Option<Vec<String>> {
            self.app.mail(to, at_least)
        }
        fn now(&mut self) -> u64 {
            self.app.now()
        }
        fn wait(&mut self, seconds: u64) {
            self.waited += seconds;
            self.app.wait(seconds);
        }
    }

    fn limited(id: &'static str, status: u16, retry: Option<&'static str>, times: u32) -> Limited {
        limited_with(Flaws::default(), id, status, retry, times)
    }

    fn limited_with(
        flaws: Flaws,
        id: &'static str,
        status: u16,
        retry: Option<&'static str>,
        times: u32,
    ) -> Limited {
        let mut app = FakeApp::new(flaws);
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        Limited {
            app,
            id,
            status,
            retry,
            times,
            waited: 0,
            limited: 0,
        }
    }

    fn run_limited(limiter: &mut Limited) -> Outcome {
        let mut acc = accounts();
        acc.totp = None;
        run(limiter, &users(), &acc, true, &Default::default())
    }

    fn credits_private_page(o: &Outcome) -> bool {
        verified_ids(o).contains(&PRIVATE_PAGE.rule_id)
    }

    /// The not-assessed entry that names the sign-ins the app's limit refused, if there is one.
    fn sign_in_limit_gap(o: &Outcome) -> Option<&(String, String)> {
        o.not_assessed
            .iter()
            .find(|(_, why)| why.contains("limit on sign-in attempts refused"))
    }

    #[test]
    fn a_sign_in_the_limit_refuses_is_named_and_not_blamed_on_the_app() {
        // Control: no limiter, no such entry, and the admin page check is credited.
        let mut control = limited("login-admin", 429, Some("5"), 0);
        let o = run_limited(&mut control);
        assert!(sign_in_limit_gap(&o).is_none(), "{:?}", o.not_assessed);
        assert!(verified_ids(&o).contains(&ADMIN_PAGE.rule_id));

        let mut limiter = limited("login-admin", 429, Some("5"), 99);
        let o = run_limited(&mut limiter);
        assert!(limiter.limited >= 2, "the setup: the limiter answered");
        let (ids, why) = sign_in_limit_gap(&o).expect("the refused sign-in is said");
        assert!(why.contains("(login-admin)"), "{why}");
        assert!(why.contains("not the app failing"), "{why}");
        assert!(
            why.contains(&format!("up to {SIGN_INS_IN_A_RUN} times")),
            "{why}"
        );
        // Listed under the requirements whose credit it held back, the admin page's among them.
        for id in ADMIN_PAGE.requirement_ids {
            assert!(ids.split(", ").any(|i| i == *id), "{id} missing from {ids}");
        }
        assert!(o.verified.is_empty(), "the credits are still withheld");
        // One entry, not one per sign-in page or per credit.
        assert_eq!(
            o.not_assessed
                .iter()
                .filter(|(_, why)| why.contains("limit on sign-in attempts"))
                .count(),
            1
        );
    }

    #[test]
    fn the_first_sign_in_refused_by_the_limit_is_not_called_a_mistake_in_securevibe_toml() {
        let mut limiter = limited("login-a", 429, Some("5"), 99);
        let o = run_limited(&mut limiter);
        assert!(limiter.limited >= 2, "the setup: the limiter answered");
        assert!(
            !o.not_assessed
                .iter()
                .any(|(_, why)| why.contains("not what stackvet.toml says")),
            "{:?}",
            o.not_assessed
        );
        let (ids, why) = sign_in_limit_gap(&o).expect("the refused sign-in is said");
        assert!(why.contains("(login-a)"), "{why}");
        let mut expected: Vec<&str> = NEEDS_A_SESSION.split(", ").collect();
        expected.sort_unstable();
        assert_eq!(
            ids,
            &expected.join(", "),
            "every check that needed A's session"
        );

        // The same sign-in refused for another reason is still the manifest's to look at.
        let mut refused = limited("login-a", 401, None, 99);
        let o = run_limited(&mut refused);
        assert!(sign_in_limit_gap(&o).is_none(), "{:?}", o.not_assessed);
        assert!(
            o.not_assessed
                .iter()
                .any(|(_, why)| why.contains("not what stackvet.toml says")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_refused_sign_in_names_only_the_checks_it_kept_from_counting() {
        // The review of 6 October, item 6: B's sign-in refused, nothing credited to withhold, and
        // A's checks named as not run, though they ran on a session the limit let through.
        let b = ["login-b".to_owned()];
        assert_eq!(
            limit_gap_names(&[], &b),
            "The checks that needed that sign-in"
        );
        assert_eq!(limit_gap_names(&["V2.3.4", "V2.3.4"], &b), "V2.3.4");
        // A's own sign-in refused: A's checks are named, with what was withheld.
        let a = ["login-a".to_owned()];
        let named = limit_gap_names(&["V2.3.4"], &a);
        for id in NEEDS_A_SESSION.split(", ").chain(["V2.3.4"]) {
            assert!(named.split(", ").any(|i| i == id), "{id} missing: {named}");
        }
    }

    #[test]
    fn a_limited_page_that_is_not_a_sign_in_is_not_called_one() {
        // The sign-in page itself (GET), a private page, and a record created (POST elsewhere):
        // limited, but not sign-ins.
        for id in ["login-page-a", "private-anonymous", "owned-create"] {
            let mut limiter = limited(id, 429, Some("5"), 99);
            let o = run_limited(&mut limiter);
            assert!(limiter.limited >= 2, "the setup: the limiter answered {id}");
            assert!(
                sign_in_limit_gap(&o).is_none(),
                "{id}: {:?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn a_limiter_that_answers_once_is_waited_out_and_the_refusal_is_the_apps() {
        let mut control = limited("private-anonymous", 429, Some("7"), 0);
        assert!(
            credits_private_page(&run_limited(&mut control)),
            "the setup: with no limiter the private page is credited"
        );
        let mut limiter = limited("private-anonymous", 429, Some("7"), 1);
        let o = run_limited(&mut limiter);
        assert_eq!(limiter.limited, 1, "the setup: the limiter answered");
        assert_eq!(limiter.waited, 7, "waited as long as the app asked");
        assert!(credits_private_page(&o), "{:?}", o.not_assessed);
        assert!(
            !o.not_assessed
                .iter()
                .any(|(_, why)| why.contains("rate limiter")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_limiter_that_keeps_answering_credits_nothing_in_the_run() {
        let mut limiter = limited("private-anonymous", 429, None, 99);
        let o = run_limited(&mut limiter);
        assert_eq!(
            limiter.limited, 2,
            "asked twice: once, and once after waiting"
        );
        assert_eq!(limiter.waited, 5, "no Retry-After: five seconds");
        assert!(!credits_private_page(&o), "a refusal nobody made, credited");
        assert!(o.verified.is_empty(), "{:?}", verified_ids(&o));
        let (ids, why) = o
            .not_assessed
            .iter()
            .find(|(_, why)| why.contains(PRIVATE_PAGE.rule_id))
            .expect("the withdrawn credit says why");
        assert!(ids.contains("V8.2.1"), "{ids}");
        assert!(why.contains("private-anonymous (429)"), "{why}");
    }

    #[test]
    fn a_503_is_a_limiter_only_when_it_says_when_to_come_back() {
        let mut with_retry = limited("private-anonymous", 503, Some("3"), 1);
        let o = run_limited(&mut with_retry);
        assert_eq!(with_retry.waited, 3);
        assert!(credits_private_page(&o));
        // Without Retry-After a 503 is the app failing, not a limiter, and is not waited out.
        let mut without = limited("private-anonymous", 503, None, 1);
        run_limited(&mut without);
        assert_eq!(without.waited, 0);
    }

    #[test]
    fn a_limiter_does_not_make_a_sign_out_out_of_a_plain_page_visit() {
        // The app keeps the session on a GET to /logout. A limiter answering the check's next look
        // at the private page made it read as signed out.
        let mut once = limited("private-after-get-logout", 429, Some("2"), 1);
        let o = run_limited(&mut once);
        assert_eq!(
            once.limited, 1,
            "the setup: the limiter answered that request"
        );
        assert!(
            !rule_ids(&o).contains(&SIGN_OUT_ON_GET.rule_id),
            "a limiter's 429 read as a sign-out"
        );
        // Still answering after the wait: the finding stands, and the run says what it may rest on.
        let mut always = limited("private-after-get-logout", 429, Some("2"), 99);
        let o = run_limited(&mut always);
        assert!(rule_ids(&o).contains(&SIGN_OUT_ON_GET.rule_id));
        assert!(o.verified.is_empty(), "credited: {:?}", verified_ids(&o));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids.contains("V3.5.3") && why.contains("may be the limiter's")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_limiter_asking_for_an_hour_is_waited_a_minute() {
        // An app may ask for a long wait; the run waits at most a minute, once, and then says what
        // it could not tell rather than stalling the whole report.
        let mut limiter = limited("private-anonymous", 429, Some("3600"), 1);
        let o = run_limited(&mut limiter);
        assert_eq!(limiter.waited, 60);
        assert!(credits_private_page(&o));
        let limited_for = |value: &str| {
            rate_limited(&ProbeResponse {
                id: String::new(),
                status: 429,
                headers: vec![("retry-after".into(), value.into())],
                body: String::new(),
            })
        };
        assert_eq!(limited_for("12"), Some(12));
        assert_eq!(
            limited_for("Wed, 21 Oct 2026 07:28:00 GMT"),
            Some(5),
            "a date: five seconds"
        );
    }

    #[test]
    fn a_real_finding_is_kept_through_a_persistent_limit_and_flagged() {
        // An app with a default admin account, behind a limiter that never lets the stranger's look
        // at the private page through. The default account is found by signing in, which the
        // limiter does not touch: the finding stays, and the run says it may rest on the limiter.
        let flaws = Flaws {
            default_admin: true,
            ..Default::default()
        };
        let mut limiter = limited_with(flaws, "private-anonymous", 429, Some("1"), 99);
        let o = run_limited(&mut limiter);
        assert!(
            rule_ids(&o).contains(&DEFAULT_ACCOUNT.rule_id),
            "{:?}",
            rule_ids(&o)
        );
        assert!(o.verified.is_empty(), "credited: {:?}", verified_ids(&o));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids.contains("V6.3.2") && why.contains("may be the limiter's")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn what_counts_as_a_limiter_and_how_long_it_is_waited() {
        let answer = |status: u16, retry: Option<&str>| {
            rate_limited(&ProbeResponse {
                id: String::new(),
                status,
                headers: retry
                    .map(|v| vec![("retry-after".to_owned(), v.to_owned())])
                    .unwrap_or_default(),
                body: String::new(),
            })
        };
        assert_eq!(answer(429, Some("12")), Some(12));
        assert_eq!(answer(429, Some("3600")), Some(60), "at most a minute");
        assert_eq!(answer(429, None), Some(5));
        assert_eq!(answer(503, Some("3")), Some(3));
        assert_eq!(
            answer(503, None),
            None,
            "a 503 that names no wait is the app failing"
        );
        assert_eq!(answer(500, Some("3")), None);
        assert_eq!(answer(401, Some("3")), None, "a refusal is an answer");
        assert_eq!(answer(200, None), None);
    }

    #[test]
    fn a_guess_is_never_waited_out() {
        // The guessing checks send wrong passwords and codes to see the limiter answer. Waiting
        // would change what they measure and send one guess more than they count.
        let mut inner = limited("guess-3", 429, Some("30"), 99);
        let mut patient = Patient::new(&mut inner);
        let request = get("guess-3", "/login", &Session::default());
        let answer = patient.send(&request).expect("an answer");
        assert_eq!(answer.status, 429);
        assert!(patient.still_limited.is_empty());
        drop(patient);
        assert_eq!((inner.limited, inner.waited), (1, 0));
    }

    #[test]
    fn a_limiter_answering_everything_is_waited_for_five_minutes_in_all() {
        // Ten requests, each answered by the limiter asking for a minute: five are waited for,
        // and the rest are recorded as the limiter's without waiting.
        let mut inner = limited("*", 429, Some("60"), 1000);
        let mut patient = Patient::new(&mut inner);
        for n in 0..10 {
            patient.send(&get(&format!("page-{n}"), "/", &Session::default()));
        }
        assert_eq!(
            patient.still_limited.len(),
            10,
            "{:?}",
            patient.still_limited
        );
        assert!(
            patient.still_limited[9].contains("not waited for"),
            "{:?}",
            patient.still_limited
        );
        drop(patient);
        assert_eq!(inner.waited, MOST_WAITING);
        assert_eq!(inner.limited, 15, "five asked twice, five once");
    }

    #[test]
    fn an_anonymous_answer_is_waited_for_and_one_still_limited_is_left_out() {
        let requests = crate::probes::requests("/");
        let home = requests
            .iter()
            .find(|r| r.id == "home")
            .expect("the probes ask for the home page");

        // The limiter says no once: waited out, and the app's own answer is what comes back.
        let mut once = limited("home", 429, Some("2"), 1);
        let (answers, left_out) = ask_anonymously(&mut once, std::slice::from_ref(home));
        assert!(left_out.is_empty(), "{left_out:?}");
        assert_eq!(answers.len(), 1);
        assert_ne!(answers[0].status, 429);
        assert_eq!(once.waited, 2);

        // The limiter never lets go: the answer is left out rather than judged as the app's.
        let mut always = limited("home", 429, Some("2"), 99);
        let (answers, left_out) = ask_anonymously(&mut always, &requests);
        assert!(
            answers.iter().all(|a| a.id != "home"),
            "the limiter's page was kept: {answers:?}"
        );
        assert_eq!(left_out, ["home (429)"]);
        // Every other question still got its answer.
        assert_eq!(answers.len(), requests.len() - 1);

        // Why the limiter's page is left out rather than judged: read as the app's, a 429 page
        // without headers is a security-headers finding, and two 429s on `/.git` are a credit for
        // the folder not being exposed.
        let page = |id: &str| ProbeResponse {
            id: id.to_owned(),
            status: 429,
            headers: vec![("retry-after".to_owned(), "2".to_owned())],
            body: "slow down".into(),
        };
        let judged = [page("home"), page("git-head"), page("git-config")];
        assert!(
            crate::probes::evaluate(&judged)
                .iter()
                .any(|f| f.rule_id == "probe.security-headers"),
            "the false alarm this prevents"
        );
        assert!(
            crate::probes::verified(&judged)
                .iter()
                .any(|v| v.check_id == "probe.source-control-exposed"),
            "the false pass this prevents"
        );
    }
}

#[cfg(test)]
mod crash_tests {
    use super::fake_app::*;
    use super::tests::with_signup;
    use super::*;
    use std::collections::BTreeSet;

    /// The fake app, answering 500 to every request whose id is `crash` (or nothing at all, with
    /// `silent`), and noting every id sent.
    struct Crashing {
        app: FakeApp,
        crash: Option<String>,
        silent: bool,
        sent: BTreeSet<String>,
        /// Every request sent, in order and with repeats, as (id, method, path).
        log: Vec<(String, String, String)>,
    }

    impl Http for Crashing {
        fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
            self.sent.insert(r.id.clone());
            self.log
                .push((r.id.clone(), r.method.clone(), r.path.clone()));
            if self.crash.as_deref() == Some(r.id.as_str()) {
                if self.silent {
                    return None;
                }
                return Some(ProbeResponse {
                    id: r.id.clone(),
                    status: 500,
                    headers: Vec::new(),
                    body: "Internal Server Error".into(),
                });
            }
            self.app.send(r)
        }
        fn send_together(&mut self, rs: &[ProbeRequest]) -> Option<Vec<Option<ProbeResponse>>> {
            for r in rs {
                self.sent.insert(r.id.clone());
                self.log
                    .push((r.id.clone(), r.method.clone(), r.path.clone()));
            }
            let mut answers = self.app.send_together(rs)?;
            // One copy of the same instant crashes, as one of a burst can.
            if let Some(i) = rs
                .iter()
                .position(|r| self.crash.as_deref() == Some(r.id.as_str()))
            {
                let r = &rs[i];
                answers[i] = (!self.silent).then(|| ProbeResponse {
                    id: r.id.clone(),
                    status: 500,
                    headers: Vec::new(),
                    body: "Internal Server Error".into(),
                });
            }
            Some(answers)
        }
        fn mail(&mut self, to: &str, at_least: usize) -> Option<Vec<String>> {
            self.app.mail(to, at_least)
        }
        fn now(&mut self) -> u64 {
            self.app.now()
        }
        fn wait(&mut self, seconds: u64) {
            self.app.wait(seconds);
        }
        fn model(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
            self.app.model(r)
        }
        fn model_address(&mut self) -> Option<String> {
            self.app.model_address()
        }
    }

    /// One fixture: the app's flaws, what stackvet.toml says, and how the run is made.
    struct Scenario {
        name: &'static str,
        flaws: Flaws,
        users: UsersSection,
        seeded: bool,
        policy: sv_manifest::PolicySection,
        slow: bool,
        /// Session limits for the fake app, in seconds: idle, lifetime.
        limits: (Option<u64>, Option<u64>),
        /// How long the fake app's tokens last, when it hands out tokens rather than session ids.
        jwt: Option<u64>,
    }

    impl Scenario {
        fn new(name: &'static str, flaws: Flaws, users: UsersSection, seeded: bool) -> Self {
            Scenario {
                name,
                flaws,
                users,
                seeded,
                policy: Default::default(),
                slow: false,
                limits: (None, None),
                jwt: None,
            }
        }

        /// One run, crashing on `crash`: the outcome and every request id sent.
        fn run(&self, crash: Option<&str>) -> (Outcome, BTreeSet<String>) {
            self.run_answering(crash, false)
        }

        /// `run`, with the crash answered by nothing at all when `silent`.
        fn run_answering(&self, crash: Option<&str>, silent: bool) -> (Outcome, BTreeSet<String>) {
            let (out, http) = self.run_logged(crash, silent);
            (out, http.sent)
        }

        /// `run_answering`, giving back the fake app as the run left it, with every request sent.
        fn run_logged(&self, crash: Option<&str>, silent: bool) -> (Outcome, Crashing) {
            let mut app = FakeApp::new(self.flaws);
            app.idle_limit = self.limits.0;
            app.lifetime_limit = self.limits.1;
            app.jwt_lifetime = self.jwt;
            // A run whose app hands out tokens has the test model's server to name in them.
            app.model_up = self.jwt.is_some();
            let mut acc = accounts();
            if self.seeded {
                for account in [&acc.a, &acc.b] {
                    app.users
                        .insert(account.user.clone(), (account.password.clone(), false));
                }
                let admin = acc.admin.clone().unwrap();
                app.users.insert(admin.user, (admin.password, true));
                let totp = acc.totp.clone().unwrap();
                app.users.insert(
                    totp.account.user.clone(),
                    (totp.account.password.clone(), false),
                );
                app.totp.insert(totp.account.user, totp.secret);
            } else {
                acc.admin = None;
                acc.totp = None;
            }
            let mut http = Crashing {
                app,
                crash: crash.map(str::to_owned),
                silent,
                sent: BTreeSet::new(),
                log: Vec::new(),
            };
            let out = run_with(
                &mut http,
                &self.users,
                &acc,
                self.seeded,
                &self.policy,
                self.slow,
            );
            (out, http)
        }

        /// Crashes each request the run sends, one at a time. Every rule the run without a crash
        /// held back and the run with one credited, with the request that crashed; and the rules
        /// held back, so the caller can see what the sweep reached. Held back is found at fault,
        /// or, for a rule in `ONLY_CREDITED`, left open: a rule whose check never ran without the crash may be rightly credited with one,
        /// once the crash hides a flaw that stood in its way.
        fn sweep(&self) -> (Vec<String>, BTreeSet<String>) {
            let (plain, sent) = self.run(None);
            let credited: BTreeSet<String> =
                plain.verified.iter().map(|v| v.check_id.clone()).collect();
            let mut found: BTreeSet<String> =
                plain.findings.iter().map(|f| f.rule_id.clone()).collect();
            found.extend(
                ONLY_CREDITED
                    .iter()
                    .filter(|rule| {
                        let ids = rule.requirement_ids.join(", ");
                        !credited.contains(rule.rule_id)
                            && plain.not_assessed.iter().any(|(i, _)| *i == ids)
                    })
                    .map(|rule| rule.rule_id.to_owned()),
            );
            let sent: Vec<&String> = sent.iter().collect();
            let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
            let turned = std::thread::scope(|scope| {
                let handles: Vec<_> = sent
                    .chunks(sent.len().div_ceil(threads).max(1))
                    .map(|ids| {
                        let found = &found;
                        scope.spawn(move || {
                            let mut turned = Vec::new();
                            for id in ids {
                                let (crashed, _) = self.run(Some(id));
                                for credit in &crashed.verified {
                                    if found.contains(&credit.check_id) {
                                        turned.push(format!(
                                            "{}: {} credited when {id} crashed",
                                            self.name, credit.check_id
                                        ));
                                    }
                                }
                            }
                            turned
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .flat_map(|h| h.join().unwrap())
                    .collect()
            });
            (turned, found)
        }
    }

    /// The rules that are never a finding, only credited or left open: for these, held back is
    /// left open (not assessed under the rule's own requirements alone) by the run without a
    /// crash. Listed here rather than read from `RESTS_ON_A_REFUSAL`, so a rule missing from that
    /// list is still tried.
    const ONLY_CREDITED: &[&Rule] = &[&CHANGE_ENDS_SESSIONS, &CHANGE_NOTIFIED];

    #[test]
    fn a_run_signs_in_no_more_often_than_the_spec_says() {
        // Every sign-in, by what it is sent to rather than its id: the ids vary (`log-marker-…`,
        // `redirect-login-…`), and a repeat under the same id is a second attempt to an app's limit.
        let mut most = 0;
        let mut guesses_seen = false;
        for scenario in scenarios() {
            let (_, http) = scenario.run_logged(None, false);
            let login = scenario
                .users
                .login
                .as_ref()
                .expect("signs in")
                .path
                .clone();
            let login = login.split('?').next().unwrap_or_default();
            let sign_ins: Vec<&str> = http
                .log
                .iter()
                .filter(|(_, method, path)| {
                    method != "GET" && path.split('?').next() == Some(login)
                })
                .map(|(id, _, _)| id.as_str())
                .collect();
            // The password-guessing check's wrong passwords are meant to meet the limit, and come
            // last of all the sign-ins, so a limit that stops them takes nothing else with it. The
            // one exception is the check on whether a failed sign-in tells accounts apart
            // (`reveal-`), whose three wrong passwords come after, and which leaves its answers
            // uncompared when a limit refuses them.
            let first_guess = sign_ins.iter().position(|id| id.starts_with("guess-"));
            if let Some(first) = first_guess {
                guesses_seen = true;
                let after: Vec<&&str> = sign_ins[first..]
                    .iter()
                    .skip_while(|id| id.starts_with("guess-"))
                    .collect();
                assert!(
                    after.iter().all(|id| id.starts_with("reveal-")),
                    "{}: a sign-in after the guesses: {sign_ins:?}",
                    scenario.name
                );
            }
            let counted = first_guess.unwrap_or(sign_ins.len());
            assert!(
                counted <= SIGN_INS_IN_A_RUN,
                "{}: {counted} sign-ins, more than the {SIGN_INS_IN_A_RUN} the spec states",
                scenario.name
            );
            most = most.max(counted);
        }
        // The setup: the sign-ins are really counted, and the guesses really set apart.
        assert!(
            most >= 40,
            "only {most} sign-ins counted in the busiest run"
        );
        assert!(guesses_seen, "no run made the guessing check's attempts");
        // The spec gives the builder the same number.
        assert!(
            sv_manifest::spec::STARTER_MANIFEST
                .contains(&format!("up to {SIGN_INS_IN_A_RUN} times")),
            "the spec does not state the number"
        );
    }

    fn scenarios() -> Vec<Scenario> {
        // Sign-up and seeding both: the password rules need the app's own sign-up, and the role
        // check needs a seeded admin to compare with.
        let mut signed_up = with_signup();
        signed_up.seed = Some("seed".into());
        signed_up.admin = vec!["/admin".into()];
        let mut sockets_and_files = users();
        sockets_and_files.private_websocket = Some("/ws".into());
        sockets_and_files.upload = Some(sv_manifest::UploadSection {
            path: "/upload".into(),
            field: "file".into(),
            form: [("csrf_token".to_owned(), "{csrf}".to_owned())].into(),
            serves_at: Some("/files/{name}".into()),
            max_bytes: Some(UPLOAD_LIMIT as u64),
            unpacks_archives: Some(vec![
                sv_manifest::ArchiveFormat::Zip,
                sv_manifest::ArchiveFormat::Gzip,
            ]),
            max_unpacked_bytes: Some(ARCHIVE_UNPACK_LIMIT),
            max_files: Some(ARCHIVE_FILE_LIMIT),
        });
        vec![
            // ADR-055: a list that holds the first common word and not the other two.
            Scenario::new(
                "a short common-password list",
                Flaws {
                    common_list_short: true,
                    ..Default::default()
                },
                {
                    let mut u = with_signup();
                    u.seed = Some("seed".into());
                    u
                },
                true,
            ),
            // Each of ADR-053's three on its own, so that crashing any one request is tried
            // against a run where that finding is the only one standing between it and a pass.
            Scenario::new(
                "another user's record listed",
                Flaws {
                    list_shows_others: true,
                    ..Default::default()
                },
                users_full(),
                true,
            ),
            Scenario::new(
                "another user's record changed",
                Flaws {
                    idor_update: true,
                    ..Default::default()
                },
                users_full(),
                true,
            ),
            Scenario::new(
                "another user's record deleted",
                Flaws {
                    idor_delete: true,
                    ..Default::default()
                },
                users_full(),
                true,
            ),
            Scenario::new(
                "seeded",
                Flaws {
                    private_open: true,
                    admin_open: true,
                    idor: true,
                    no_csrf_check: true,
                    logout_keeps_session: true,
                    flow_unguarded: true,
                    ..Default::default()
                },
                users(),
                true,
            ),
            Scenario::new(
                "two-factor codes twice",
                Flaws {
                    totp_reusable: true,
                    ..Default::default()
                },
                users(),
                true,
            ),
            Scenario {
                policy: sv_manifest::PolicySection {
                    context_words: vec!["Acme Notes".into()],
                    failed_sign_ins: Some(3),
                    within_minutes: Some(15),
                    failed_codes: Some(3),
                    requests_per_minute: Some(5),
                    ..Default::default()
                },
                ..Scenario::new(
                    "signed up",
                    Flaws {
                        short_password_ok: true,
                        common_password_ok: true,
                        breached_password_ok: true,
                        context_word_ok: true,
                        case_folded: true,
                        change_without_current: true,
                        email_change_without_password: true,
                        booking_races: true,
                        code_guessing_unlimited: true,
                        signup_trusts_role: true,
                        email_change_trusts_role: true,
                        ..Default::default()
                    },
                    signed_up,
                    true,
                )
            },
            Scenario::new(
                "signed up, emailed codes",
                Flaws {
                    code_reusable: true,
                    code_unbound: true,
                    change_keeps_old: true,
                    change_keeps_sessions: true,
                    change_sends_no_email: true,
                    deletion_keeps_sessions: true,
                    ..Default::default()
                },
                with_signup(),
                false,
            ),
            Scenario::new(
                "a private WebSocket, uploads, and any session cookie",
                Flaws {
                    ws_open: true,
                    oversized_upload_ok: true,
                    unchecked_contents_ok: true,
                    svg_scripts_kept: true,
                    no_malware_scan: true,
                    upload_path_traversal: true,
                    archive_size_unchecked: true,
                    archive_files_unchecked: true,
                    session_not_verified: true,
                    ..Default::default()
                },
                sockets_and_files,
                true,
            ),
            Scenario {
                jwt: Some(30),
                ..Scenario::new(
                    "the app's own tokens, neither signature nor expiry checked, and the key they \
                     name fetched",
                    Flaws {
                        jwt_signature_ignored: true,
                        jwt_expiry_ignored: true,
                        jwt_key_source_followed: true,
                        ..Default::default()
                    },
                    users(),
                    true,
                )
            },
            Scenario {
                policy: sv_manifest::PolicySection {
                    idle_timeout_minutes: Some(15),
                    session_lifetime_minutes: Some(60),
                    ..Default::default()
                },
                slow: true,
                ..Scenario::new(
                    "slow, sessions and codes that never end, and two-factor codes of any age",
                    Flaws {
                        totp_any_age: true,
                        code_long_lived: true,
                        ..Default::default()
                    },
                    users(),
                    true,
                )
            },
        ]
    }

    #[test]
    fn a_private_page_that_crashes_for_a_stranger_is_not_credited_as_refused() {
        // The control: the correct app credits the private page.
        let plain = Scenario::new("plain", Flaws::default(), users(), true);
        let (o, _) = plain.run(None);
        assert!(
            verified_ids(&o).contains(&PRIVATE_PAGE.rule_id),
            "{:?}",
            o.steps
        );

        // The same app crashing on that one request: not credited, and the owner is told why.
        let (o, _) = plain.run(Some("private-anonymous"));
        assert!(!verified_ids(&o).contains(&PRIVATE_PAGE.rule_id));
        let (ids, why) = o
            .not_assessed
            .iter()
            .find(|(_, why)| why.contains(PRIVATE_PAGE.rule_id))
            .unwrap_or_else(|| panic!("{:?}", o.not_assessed));
        assert!(ids.contains("V8.2.1"), "{ids}");
        assert!(why.contains("private-anonymous (500)"), "{why}");
        assert!(why.contains("crashed or did not answer"), "{why}");
        // Everything that did not rest on that request is still credited.
        assert!(
            verified_ids(&o).contains(&ADMIN_PAGE.rule_id),
            "{:?}",
            verified_ids(&o)
        );

        // No answer at all is not a refusal either.
        let (o, _) = plain.run_answering(Some("private-anonymous"), true);
        assert!(!verified_ids(&o).contains(&PRIVATE_PAGE.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(_, why)| why.contains("private-anonymous (no answer)")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_page_that_crashes_after_a_plain_sign_out_link_is_not_reported_as_signed_out() {
        let correct = Scenario::new("correct", Flaws::default(), users(), true);
        let (o, sent) = correct.run(Some("private-after-get-logout"));
        assert!(
            sent.contains("private-after-get-logout"),
            "the setup reaches the check"
        );
        assert!(!rule_ids(&o).contains(&SIGN_OUT_ON_GET.rule_id));
        let (_, why) = o
            .not_assessed
            .iter()
            .find(|(_, why)| why.contains(SIGN_OUT_ON_GET.rule_id))
            .unwrap_or_else(|| panic!("{:?}", o.not_assessed));
        assert!(why.contains("private-after-get-logout (500)"), "{why}");
        assert!(why.contains("neither reported nor credited"), "{why}");

        // The app that really does sign out on a plain link is still reported, crash or no crash
        // elsewhere.
        let flawed = Scenario::new(
            "signs out on a plain link",
            Flaws {
                logout_on_get: true,
                ..Default::default()
            },
            users(),
            true,
        );
        let (o, _) = flawed.run(Some("private-anonymous"));
        assert!(
            rule_ids(&o).contains(&SIGN_OUT_ON_GET.rule_id),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_crash_on_a_correct_app_raises_no_finding() {
        // The other direction: a correct app, each request crashed in turn. Any finding that
        // appears was raised by the crash, whether or not `RAISED_ON_A_REFUSAL` lists it.
        let mut signed_up = with_signup();
        signed_up.seed = Some("seed".into());
        signed_up.admin = vec!["/admin".into()];
        let mut sockets_and_files = users();
        sockets_and_files.private_websocket = Some("/ws".into());
        sockets_and_files.upload = Some(sv_manifest::UploadSection {
            path: "/upload".into(),
            field: "file".into(),
            form: [("csrf_token".to_owned(), "{csrf}".to_owned())].into(),
            serves_at: Some("/files/{name}".into()),
            max_bytes: Some(UPLOAD_LIMIT as u64),
            unpacks_archives: Some(vec![
                sv_manifest::ArchiveFormat::Zip,
                sv_manifest::ArchiveFormat::Gzip,
            ]),
            max_unpacked_bytes: Some(ARCHIVE_UNPACK_LIMIT),
            max_files: Some(ARCHIVE_FILE_LIMIT),
        });
        let scenarios = [
            Scenario {
                policy: sv_manifest::PolicySection {
                    context_words: vec!["Acme Notes".into()],
                    failed_sign_ins: Some(3),
                    within_minutes: Some(15),
                    failed_codes: Some(3),
                    ..Default::default()
                },
                ..Scenario::new(
                    "signed up, with a limit on wrong passwords",
                    Flaws {
                        locks_out_after: Some(3),
                        ..Default::default()
                    },
                    signed_up,
                    true,
                )
            },
            Scenario::new(
                "a private WebSocket and uploads",
                Flaws::default(),
                sockets_and_files,
                true,
            ),
            Scenario {
                policy: sv_manifest::PolicySection {
                    idle_timeout_minutes: Some(15),
                    session_lifetime_minutes: Some(60),
                    ..Default::default()
                },
                slow: true,
                limits: (Some(15 * 60), Some(60 * 60)),
                ..Scenario::new(
                    "slow, with sessions that end",
                    Flaws::default(),
                    users(),
                    true,
                )
            },
        ];
        let mut raised = Vec::new();
        for scenario in &scenarios {
            let (plain, sent) = scenario.run(None);
            // The setup is a correct app: nothing to find before anything crashes.
            assert!(
                plain.findings.is_empty(),
                "{}: {:?}",
                scenario.name,
                plain
                    .findings
                    .iter()
                    .map(|f| &f.rule_id)
                    .collect::<Vec<_>>()
            );
            let sent: Vec<&String> = sent.iter().collect();
            let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
            raised.extend(std::thread::scope(|scope| {
                let handles: Vec<_> = sent
                    .chunks(sent.len().div_ceil(threads).max(1))
                    .map(|ids| {
                        scope.spawn(move || {
                            let mut raised = Vec::new();
                            for id in ids {
                                let (crashed, _) = scenario.run(Some(id));
                                for f in &crashed.findings {
                                    raised.push(format!(
                                        "{}: {} raised when {id} crashed",
                                        scenario.name, f.rule_id
                                    ));
                                }
                            }
                            raised
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .flat_map(|h| h.join().unwrap())
                    .collect::<Vec<_>>()
            }));
        }
        assert!(raised.is_empty(), "{raised:#?}");
    }

    #[test]
    fn a_crash_never_turns_a_finding_into_a_pass() {
        let mut reached = BTreeSet::new();
        let mut turned = Vec::new();
        for scenario in scenarios() {
            let (t, found) = scenario.sweep();
            turned.extend(t);
            reached.extend(found);
        }
        assert!(turned.is_empty(), "{turned:#?}");
        // The sweep is only as good as the findings it starts from: a rule listed here that no
        // scenario found at fault was never tried, so it is named rather than passed quietly.
        let missed: Vec<&str> = RESTS_ON_A_REFUSAL
            .iter()
            .map(|(rule, _)| *rule)
            .filter(|rule| !reached.contains(*rule))
            .collect();
        assert!(
            missed.is_empty(),
            "no scenario found these at fault: {missed:?}"
        );
    }
}

/// A single-page app's page shell is not its private page (gap analysis 2.2). Such an app sends
/// everybody the same page for every address and draws it in the browser from what it fetches
/// next, so `/account` answering 200 to a stranger was reported as a private page served to anyone,
/// and every check that needs the signed-in control then read "not assessed".
#[cfg(test)]
mod page_shell_tests {
    use super::fake_app::*;
    use super::*;

    fn spa() -> Flaws {
        Flaws {
            page_shell: true,
            ..Default::default()
        }
    }

    fn with_private(private: &[&str]) -> UsersSection {
        UsersSection {
            private: private.iter().map(|p| (*p).to_owned()).collect(),
            ..users()
        }
    }

    fn answer(status: u16, body: &str) -> Option<ProbeResponse> {
        Some(ProbeResponse {
            id: String::new(),
            status,
            headers: Vec::new(),
            body: body.to_owned(),
        })
    }

    #[test]
    fn a_private_page_that_is_only_the_page_shell_is_not_judged_and_says_what_to_list() {
        let o = run_against(spa(), &with_private(&["/account"]));
        assert!(
            !rule_ids(&o).contains(&PRIVATE_PAGE.rule_id),
            "the page shell was taken for the private page: {:#?}",
            o.findings
        );
        assert!(
            !verified_ids(&o).contains(&PRIVATE_PAGE.rule_id),
            "nothing was judged, so nothing is credited"
        );
        let (_, why) = o
            .not_assessed
            .iter()
            .find(|(ids, _)| ids.contains("V8.2.1"))
            .expect("V8.2.1 says why it was not judged");
        assert!(why.contains("/account") && why.contains("/api/me"), "{why}");
        // The checks after it are given no shell to compare with either: a shell answered after
        // signing out is not a session that still works.
        assert!(o.findings.is_empty(), "{:#?}", o.findings);
    }

    #[test]
    fn the_address_the_page_fetches_is_judged_beside_the_shell() {
        let o = run_against(spa(), &with_private(&["/account", "/api/me"]));
        assert!(o.findings.is_empty(), "{:#?}", o.findings);
        let credit = o
            .verified
            .iter()
            .find(|v| v.check_id == PRIVATE_PAGE.rule_id)
            .expect("/api/me refused a stranger and opened for A");
        assert!(
            credit.scope.starts_with("1 private page,"),
            "{}",
            credit.scope
        );
        assert!(
            credit
                .scope
                .contains("/account answered as the front page does"),
            "{}",
            credit.scope
        );
        assert!(
            o.steps.iter().any(|s| s.contains("page shell")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn an_open_address_behind_the_shell_is_still_found() {
        let o = run_against(
            Flaws {
                private_open: true,
                ..spa()
            },
            &with_private(&["/account", "/api/me"]),
        );
        let found = o
            .findings
            .iter()
            .find(|f| f.rule_id == PRIVATE_PAGE.rule_id)
            .expect("/api/me opens for anybody");
        assert!(
            found.description.contains("/api/me"),
            "{}",
            found.description
        );
        assert!(
            !found.description.contains("/account"),
            "{}",
            found.description
        );
    }

    #[test]
    fn only_a_whole_answer_exactly_the_front_pages_is_a_shell() {
        let front = answer(200, PAGE_SHELL);
        assert!(is_page_shell(&answer(200, PAGE_SHELL), &front));
        // Another page, a refusal, an empty answer, or no front page to compare with.
        assert!(!is_page_shell(&answer(200, "your account"), &front));
        assert!(!is_page_shell(&answer(302, PAGE_SHELL), &front));
        assert!(!is_page_shell(
            &answer(200, PAGE_SHELL),
            &answer(404, PAGE_SHELL)
        ));
        assert!(!is_page_shell(&answer(200, ""), &answer(200, "")));
        assert!(!is_page_shell(&answer(200, PAGE_SHELL), &None));
        // A server-rendered page as long as the kept part may differ from the front page only
        // past the cut, so matching that far is not the same page.
        let long = "<div>layout</div>".repeat(crate::probes::KEPT_CHARS);
        let cut: String = long.chars().take(crate::probes::KEPT_CHARS).collect();
        assert!(!is_page_shell(&answer(200, &cut), &answer(200, &cut)));
    }
}
