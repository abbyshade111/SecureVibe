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
use regex::Regex;
use std::collections::BTreeMap;
use std::sync::LazyLock;
use sv_manifest::{RequestTemplate, UploadSection, UsersSection};

mod admin;
mod flows;
mod forgery;
mod passwords;
mod rules;
mod sessions;
mod uploads;
use admin::*;
use flows::*;
use forgery::*;
use passwords::*;
use rules::*;
pub(crate) use rules::{Rule, finding};
use sessions::*;
use uploads::*;

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

    /// Sends a request to the run's test model rather than to the app: `None` when the run has no
    /// test model. See `ai.rs`.
    fn model(&mut self, _request: &ProbeRequest) -> Option<ProbeResponse> {
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
    send_template_as(http, id, t, values, session, pages, |_| {})
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
    let mut sent = request(id, t, &v, session);
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
// Findings

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
pub(crate) struct SignedIn {
    pub(crate) session: Session,
    /// Cookies set by the sign-in response itself: the session cookies.
    set_at_login: Vec<Cookie>,
    /// Cookies the app had given before sign-in.
    before_login: Vec<(String, String)>,
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
            let response = sign_up(http, users, signup, who, account);
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
        &accounts.a,
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
    // And signing out in a real browser, with a sign-in of its own: clicking the app's sign-out
    // ends that session, so it goes here, after the checks that needed A's.
    if users.browser.is_some() {
        let fresh = confirm
            .as_ref()
            .and_then(|_| sign_in(http, users, "a-browser", &accounts.a, &mut out.steps))
            .map(|s| s.session);
        crate::browser::sign_out_check(http, users, fresh.as_ref(), &mut out);
    }

    // 9b. A private WebSocket, with a sign-in of its own that it signs out at the end: after
    //     everything that needed A's first session.
    websocket_session_checks(http, users, &accounts.a, &mut out);

    // 9c. Admin actions, sent by A and then by the admin. Late, because an action changes what the
    //     app holds and the checks above have had what they needed; before the password changes
    //     below, one of which can change A's own password, and before the checks that set out to be
    //     refused and can leave the app refusing everybody, the admin included.
    admin_action_checks(http, users, accounts, confirm.as_deref(), &mut out);
    // 9d. A role written into the sign-up form, with two accounts made for it. Before the password
    //     changes for the same reason as the admin actions.
    role_field_check(http, users, accounts, confirm.as_deref(), &mut out);

    // 10. Last of all, because it changes a password: with an account made for it when there is a
    //    sign-up, and with A's own when there is not.
    change_password_checks(http, users, accounts, confirm.as_deref(), &mut out);
    delete_account_check(http, users, accounts, confirm.as_deref(), &mut out);
    reset_checks(http, users, accounts, confirm.as_deref(), &mut out);
    activation_checks(http, users, accounts, confirm.as_deref(), &mut out);
    email_code_checks(http, users, accounts, confirm.as_deref(), &mut out);
    email_code_lifetime(http, users, accounts, confirm.as_deref(), slow, &mut out);
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
            sign_up(http, users, signup, "guessed", &account);
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
        sign_up(http, users, signup, "log-marker", &only);
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
            sign_up(http, users, signup, "reset", &account);
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

/// How long an emailed sign-in code lasts (V6.5.5): at most ten minutes. Only with `--slow`.
///
/// A code is asked for, and its session kept busy while ten minutes pass — a code tied to a session
/// that ended for being idle would be refused for that, not for its age. Then the code is used
/// there. Signing in is a finding. A refusal is credited only when a code asked for then, in a new
/// session, signs in at once: that is what shows the old one was refused for being old.
fn email_code_lifetime(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    slow: bool,
    out: &mut Outcome,
) {
    const ID: &str = "V6.5.5";
    /// Ten minutes, the most V6.5.5 allows, and a few seconds more.
    const LATE: u64 = 10 * 60 + 5;
    if users.email_code.is_none() {
        return;
    }
    if !slow {
        out.not_assessed.push((
            ID.to_owned(),
            "How long an emailed sign-in code keeps working: that means waiting ten minutes, so it \
             is asked only by `sv run --slow`."
                .to_owned(),
        ));
        return;
    }
    // Quietly: the checks above already said why, if the flow cannot be started.
    let mut quiet = Outcome::default();
    let Some(flow) = EmailCode::start(http, users, accounts, confirm, ID, &mut quiet) else {
        out.not_assessed.push((
            ID.to_owned(),
            "How long an emailed sign-in code keeps working: the sign-in by emailed code could not \
             be started, as said above."
                .to_owned(),
        ));
        return;
    };
    let mut asked = Session::default();
    let asked_at = http.now();
    let code = match flow.ask(http, &mut asked, "old", out) {
        Ok(code) => code,
        Err(why) => {
            out.not_assessed.push((ID.to_owned(), why));
            return;
        }
    };
    // Kept busy, a page request every two minutes, so the session outlives the wait.
    while http.now() < asked_at + LATE {
        let left = asked_at + LATE - http.now();
        http.wait(left.min(120));
        http.send(&get(
            "email-code-keep-busy",
            &flow.entry.use_code.path,
            &asked,
        ));
    }
    let late = flow.signs_in(http, &code, &mut asked, "late", out);
    let waited = http.now().saturating_sub(asked_at);
    let after = format!("{} minutes {} seconds", waited / 60, waited % 60);
    if late {
        out.findings.push(finding(
            &EMAIL_CODE_LONG_LIVED,
            "An emailed sign-in code still works after ten minutes",
            Severity::Medium,
            format!(
                "A code asked for through {} was used through {} {after} later, in the session \
                 that asked for it, and signed in.",
                flow.entry.request.path, flow.entry.use_code.path
            ),
        ));
        return;
    }
    let mut fresh = Session::default();
    let control = match flow.ask(http, &mut fresh, "fresh", out) {
        Ok(new) => flow.signs_in(http, &new, &mut fresh, "fresh", out),
        Err(_) => false,
    };
    out.steps.push(format!(
        "an emailed code used {after} after it was asked for: refused; a code asked for then {}",
        if control {
            "signed in"
        } else {
            "did not sign in either"
        }
    ));
    if control {
        out.verified.push(crate::Verified::new(
            EMAIL_CODE_LONG_LIVED.rule_id,
            EMAIL_CODE_LONG_LIVED.requirement_ids,
            format!(
                "an emailed sign-in code refused through {} {after} after it was asked for, in a \
                 session kept in use, where a code asked for then signed in",
                flow.entry.use_code.path
            ),
        ));
    } else {
        out.not_assessed.push((
            ID.to_owned(),
            format!(
                "How long an emailed sign-in code keeps working: a code used {after} after it was \
                 asked for was refused, and so was one asked for and used straight away then, so \
                 the refusal cannot be said to be about its age."
            ),
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
                sign_up(http, users, signup, "code", &account);
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

/// The activation code emailed at sign-up (V6.4.1), followed through the mail server.
///
/// Two accounts are made through `signup`, so there are two codes to compare. The setup is shown
/// to work first: the email arrives and a code is found in it; where the app refuses a sign-in
/// before activation, the code has to lift that. Then two findings are possible: a code short
/// enough to guess, or two that count up; and an activation link that signs the account in and
/// then does so again. Only ever findings: V6.4.1 also asks that a code expire after a while and
/// that an initial password never become the lasting one, which this does not try.
fn activation_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    const ID: &str = "V6.4.1";
    let Some(entry) = &users.activation else {
        return;
    };
    let say = |why: String, out: &mut Outcome| out.not_assessed.push((ID.to_owned(), why));
    let Some(signup) = &users.signup else {
        say(
            "The activation code emailed at sign-up: securevibe.toml sets `activation` and no \
             `signup`, so no account is made that would be sent one."
                .to_owned(),
            out,
        );
        return;
    };
    let Some(confirm) = confirm else {
        say(
            "The activation code emailed at sign-up: telling whether it worked needs a private \
             page a signed-in user alone can open, and none was shown."
                .to_owned(),
            out,
        );
        return;
    };
    let patterns = match code_patterns(
        entry.code_pattern.as_deref(),
        "activate|activation|verify|confirm|welcome",
    ) {
        Ok(p) => p,
        Err(e) => {
            say(
                format!("`activation.code-pattern` in securevibe.toml cannot be used: {e}."),
                out,
            );
            return;
        }
    };
    let spare = &accounts.spare;
    if spare.len() < 32 {
        return;
    }
    let made: Vec<Account> = (1..=2)
        .map(|n| Account {
            user: format!("activate{n}.{}", accounts.a.user),
            password: format!("Ac{n}-{}-aZ9!", &spare[n..n + 24]),
        })
        .collect();
    if http.mail(&made[0].user, 0).is_none() {
        say(
            "The activation code emailed at sign-up: the run had no mail server for the app to \
             send to, so there was no email to read."
                .to_owned(),
            out,
        );
        return;
    }

    // Each account: signed up, its email read. Whether it could sign in before activation is
    // asked of the first only; it decides what the code has to show.
    let mut codes = Vec::new();
    let mut gated = false;
    for (n, account) in made.iter().enumerate() {
        let before = http.mail(&account.user, 0).map_or(0, |m| m.len());
        let answer = sign_up_only(http, signup, &format!("activate-{n}"), account);
        let mail = http.mail(&account.user, before + 1).unwrap_or_default();
        let code = mail
            .get(before..)
            .and_then(|new| new.last())
            .and_then(|m| reset_code(m, &patterns));
        out.steps.push(format!(
            "signed up {} ({}): {}",
            account.user,
            status(&answer),
            match (&code, mail.len() > before) {
                (Some(_), _) => "an email arrived with an activation code in it",
                (None, true) => "an email arrived with no code found in it",
                (None, false) => "no email arrived",
            }
        ));
        let Some(code) = code else {
            say(
                if mail.len() > before {
                    "The sign-up email arrived and no activation code was found in it. Set \
                     `activation.code-pattern` in securevibe.toml to a pattern whose first group \
                     is the code."
                        .to_owned()
                } else {
                    format!(
                        "Signing up {} sent no email to the run's mail server. The app is told \
                         where that is in SMTP_HOST and SMTP_PORT; check that it reads them.",
                        account.user
                    )
                },
                out,
            );
            return;
        };
        if n == 0 {
            gated = !account_works(
                http,
                users,
                "activate-before",
                account,
                confirm,
                &mut out.steps,
            );
        }
        codes.push(code);
    }

    // The code, used once in a new session: whether it activated, and whether it signed in.
    let use_code = |http: &mut dyn Http, code: &str, label: &str, session: &mut Session| {
        let values = Values {
            user: &made[0].user,
            code,
            ..Default::default()
        };
        send_template(
            http,
            &format!("activation-{label}"),
            &entry.use_code,
            &values,
            session,
            &[],
        )
        .0
    };
    let mut first = Session::default();
    let answer = use_code(http, &codes[0], "first", &mut first);
    let signed_in_by_link = ok(&http.send(&get("activation-first-private", confirm, &first)));
    let works = account_works(
        http,
        users,
        "activate-after",
        &made[0],
        confirm,
        &mut out.steps,
    );
    out.steps.push(format!(
        "used the activation code ({}): the account {}{}",
        status(&answer),
        if works {
            "then signed in"
        } else {
            "still could not sign in"
        },
        if signed_in_by_link {
            ", and the link itself signed it in"
        } else {
            ""
        }
    ));
    if gated && !works {
        say(
            format!(
                "The account could not sign in before activation and still could not after its \
                 code was used through {}: check `activation` in securevibe.toml. With no \
                 activation that works, nothing about the code can be told.",
                entry.use_code.path
            ),
            out,
        );
        return;
    }
    if !gated {
        out.steps.push(
            "the account could sign in before it was activated, so activation guards nothing \
             here that a password does not"
                .to_owned(),
        );
    }

    // Guessable: from the two codes.
    activation_code_check(&codes, out);

    // Used again: only tellable when the link signs the account in.
    if signed_in_by_link {
        let mut again = Session::default();
        use_code(http, &codes[0], "again", &mut again);
        let reused = ok(&http.send(&get("activation-again-private", confirm, &again)));
        out.steps.push(format!(
            "used the same activation code again in a new session: {}",
            if reused { "signed in" } else { "not signed in" }
        ));
        if reused {
            out.findings.push(finding(
                &ACTIVATION_REUSABLE,
                "An activation link signs its account in more than once",
                Severity::High,
                format!(
                    "The activation code sent at sign-up signed the account in through {}, and \
                     then did so again from a new session after it had been used.",
                    entry.use_code.path
                ),
            ));
        }
    }
    say(
        if signed_in_by_link {
            "Two parts of V6.4.1 were not tried: whether an activation code stops working after a \
             while, which would mean waiting, and whether a system-made initial password can \
             become the lasting one."
                .to_owned()
        } else {
            "Whether an activation code works twice: using it did not sign anybody in, so a second \
             use could not be told from the first. Not tried either: whether a code stops working \
             after a while, and whether a system-made initial password can become the lasting one."
                .to_owned()
        },
        out,
    );
}

/// Whether activation codes could be guessed: too short to hold 20 bits, or counting up.
fn activation_code_check(codes: &[String], out: &mut Outcome) {
    let Some(shortest) = codes.iter().min_by_key(|c| c.chars().count()) else {
        return;
    };
    let bits = most_bits(shortest);
    if bits < 19.9 {
        out.findings.push(finding(
            &ACTIVATION_GUESSABLE,
            "The activation code is short enough to guess",
            Severity::High,
            format!(
                "The code in the sign-up email is {} characters long and can hold at most {bits:.0} \
                 bits, fewer than the 20 of six random digits.",
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
            &ACTIVATION_GUESSABLE,
            "Activation codes count up",
            Severity::High,
            format!(
                "Two sign-ups one after the other were sent codes {} apart: whoever has one code \
                 can work out the next.",
                later.abs_diff(*earlier)
            ),
        ));
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

// ------------------------------------------------------------------------------------------------
// Uploads

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
    // Clear of the end of a step: with ten seconds or fewer left, the step can end between a code
    // being worked out and being given, and a code refused for going stale reads as a code refused
    // for being used. The rest of that risk is handled below, by looking at the clock again.
    let into = http.now() % crate::totp::STEP;
    if into + 10 >= crate::totp::STEP {
        http.wait(crate::totp::STEP - into + 1);
    }
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

    // 2. The control: the current code, then 3. the same code again, in a new sign-in. A refusal of
    //    the second is evidence only when the step it was worked out for has not ended: an app that
    //    takes the current step alone refuses a code whose step is over, used or not. So when the
    //    step has moved on and the code was refused, the pair is tried once more with the new
    //    step's code; if the step ends again, nothing is said about reuse.
    let mut current = current;
    let mut step = step;
    let mut reused = false;
    let mut unsure = false;
    for round in 0..2 {
        if !signing
            .attempt(http, &current, &format!("2-{round}"), false)
            .unwrap_or(false)
        {
            let ended = http.now() / crate::totp::STEP != step;
            out.not_assessed.push((
                IDS.to_owned(),
                if ended {
                    format!(
                        "The 30-second step ended while the current code was being given through \
                         {}, so its refusal shows nothing about the code or the setup. Run it \
                         again.",
                        entry.path
                    )
                } else {
                    format!(
                        "The current code for the secret `seed` was given did not sign the \
                         two-factor account in through {}, so a refused code shows nothing. Check \
                         `totp` in securevibe.toml, and that `seed` enrolled the account with \
                         SV_TOTP_SECRET.",
                        entry.path
                    )
                },
            ));
            return;
        }
        reused = signing.attempt(http, &current, &format!("3-{round}"), false) == Some(true);
        let now_step = http.now() / crate::totp::STEP;
        if reused || now_step == step {
            unsure = false;
            break;
        }
        unsure = true;
        step = now_step;
        current = crate::totp::code_at_step(secret, step);
    }
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
        } else if id == "V6.5.1" && unsure {
            out.not_assessed.push((
                id.to_owned(),
                "The 30-second step ended between the two uses of a code, twice, so its refusal \
                 may be the code going stale rather than the app refusing a code used before."
                    .to_owned(),
            ));
        } else if works {
            out.verified.push(crate::Verified::new(
                rule.rule_id,
                rule.requirement_ids,
                if id == "V6.5.5" {
                    // What was shown is the first clause of V6.5.5, a defined lifetime; the second,
                    // at most 30 seconds, would take refusing the code from one step back, which a
                    // sensible allowance for clock drift accepts.
                    format!(
                        "{what}, refused, where a fresh code afterwards signed in: codes have a \
                         defined lifetime, shorter than two and a half minutes; that it is at most \
                         30 seconds was not shown"
                    )
                } else {
                    format!("{what}, refused, where a fresh code afterwards signed in")
                },
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
mod fake_app;

#[cfg(test)]
mod tests {
    use super::fake_app::*;
    use super::*;
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
        assert!(note.contains("invented: opened"), "{note}");
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

    /// Every reason given for not assessing `id`. V6.5.1 is also the emailed-code check's, whose
    /// reasons are not about two-factor codes, so a test looks through them all.
    fn totp_named(o: &Outcome, id: &str) -> Vec<String> {
        o.not_assessed
            .iter()
            .filter(|(ids, _)| ids.split(", ").any(|i| i == id))
            // V6.5.5 is asked of emailed codes too, and those are said apart.
            .filter(|(_, why)| !why.contains("emailed sign-in code"))
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

    // --------------------------------------------------------------------------------------------
    // How long an emailed code lasts, waited out with --slow

    fn lifetime_why(o: &Outcome) -> Vec<&str> {
        o.not_assessed
            .iter()
            .filter(|(id, why)| id == "V6.5.5" && why.contains("emailed sign-in code"))
            .map(|(_, why)| why.as_str())
            .collect()
    }

    /// The seeded fixture with `--slow` and no timeouts stated, so the only waiting is the code's.
    fn code_slow_run(flaws: Flaws, tune: impl FnOnce(&mut FakeApp)) -> Outcome {
        let mut app = FakeApp::new(flaws);
        tune(&mut app);
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        super::run_with(&mut app, &users(), &acc, true, &Default::default(), true)
    }

    #[test]
    fn a_code_refused_after_ten_minutes_is_credited_when_a_fresh_one_works() {
        let o = code_slow_run(Flaws::default(), |_| {});
        assert!(
            !rule_ids(&o).contains(&EMAIL_CODE_LONG_LIVED.rule_id),
            "{:#?}",
            o.findings
        );
        let credit = o
            .verified
            .iter()
            .find(|v| v.check_id == EMAIL_CODE_LONG_LIVED.rule_id)
            .unwrap_or_else(|| panic!("{:?}", o.steps));
        assert!(credit.scope.contains("10 minutes"), "{}", credit.scope);
        assert!(lifetime_why(&o).is_empty(), "{:?}", lifetime_why(&o));
    }

    #[test]
    fn a_code_that_never_expires_is_found() {
        for o in [
            code_slow_run(
                Flaws {
                    code_long_lived: true,
                    ..Default::default()
                },
                |_| {},
            ),
            // With sessions that end after five idle minutes: the one that asked is kept in use,
            // so the old code is judged on its age and not on a session that ended.
            code_slow_run(
                Flaws {
                    code_long_lived: true,
                    ..Default::default()
                },
                |app| {
                    app.idle_limit = Some(5 * 60);
                    app.anonymous_sessions_time_out = true;
                },
            ),
        ] {
            assert!(
                rule_ids(&o).contains(&EMAIL_CODE_LONG_LIVED.rule_id),
                "{:?}",
                o.steps
            );
            assert!(!verified_ids(&o).contains(&EMAIL_CODE_LONG_LIVED.rule_id));
        }
    }

    #[test]
    fn a_session_kept_in_use_outlives_the_wait_so_a_good_app_is_still_credited() {
        let o = code_slow_run(Flaws::default(), |app| {
            app.idle_limit = Some(5 * 60);
            app.anonymous_sessions_time_out = true;
        });
        assert!(
            verified_ids(&o).contains(&EMAIL_CODE_LONG_LIVED.rule_id),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_refusal_with_no_working_code_to_compare_is_not_assessed() {
        let o = code_slow_run(
            Flaws {
                code_does_nothing: true,
                ..Default::default()
            },
            |_| {},
        );
        assert!(!rule_ids(&o).contains(&EMAIL_CODE_LONG_LIVED.rule_id));
        assert!(!verified_ids(&o).contains(&EMAIL_CODE_LONG_LIVED.rule_id));
        assert!(
            lifetime_why(&o)
                .iter()
                .any(|w| w.contains("cannot be said to be about its age")),
            "{:?}",
            lifetime_why(&o)
        );
    }

    /// The sign-up fixture with `--slow`, in an app whose sessions end after five idle minutes,
    /// signed in or not: the lifetime check's account is made through sign-up there.
    fn code_slow_signup_run(flaws: Flaws) -> Outcome {
        let mut app = FakeApp::new(flaws);
        app.idle_limit = Some(5 * 60);
        app.anonymous_sessions_time_out = true;
        let mut acc = accounts();
        acc.admin = None;
        acc.totp = None;
        super::run_with(
            &mut app,
            &with_signup(),
            &acc,
            false,
            &Default::default(),
            true,
        )
    }

    #[test]
    fn through_sign_up_each_lifetime_outcome_is_reached() {
        let long_lived = code_slow_signup_run(Flaws {
            code_long_lived: true,
            ..Default::default()
        });
        assert!(
            rule_ids(&long_lived).contains(&EMAIL_CODE_LONG_LIVED.rule_id),
            "{:?}",
            long_lived.steps
        );
        assert!(!verified_ids(&long_lived).contains(&EMAIL_CODE_LONG_LIVED.rule_id));

        let correct = code_slow_signup_run(Flaws::default());
        assert!(
            verified_ids(&correct).contains(&EMAIL_CODE_LONG_LIVED.rule_id),
            "{:?}",
            correct.steps
        );

        let broken = code_slow_signup_run(Flaws {
            code_does_nothing: true,
            ..Default::default()
        });
        assert!(!verified_ids(&broken).contains(&EMAIL_CODE_LONG_LIVED.rule_id));
        assert!(!rule_ids(&broken).contains(&EMAIL_CODE_LONG_LIVED.rule_id));
        assert!(
            lifetime_why(&broken)
                .iter()
                .any(|w| w.contains("cannot be said to be about its age")),
            "{:?}",
            lifetime_why(&broken)
        );
    }

    #[test]
    fn without_slow_nothing_is_waited_for_and_it_says_so() {
        let mut app = FakeApp::new(Flaws {
            code_long_lived: true,
            ..Default::default()
        });
        let start = app.clock;
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        let o = run(&mut app, &users(), &acc, true, &Default::default());
        assert!(!rule_ids(&o).contains(&EMAIL_CODE_LONG_LIVED.rule_id));
        assert!(
            lifetime_why(&o).iter().any(|w| w.contains("--slow")),
            "{:?}",
            lifetime_why(&o)
        );
        assert!(app.clock - start < 5 * 60, "it waited without --slow");
    }

    #[test]
    fn with_no_email_code_entry_the_lifetime_is_not_mentioned() {
        let mut u = users();
        u.email_code = None;
        let o = run_against(Flaws::default(), &u);
        assert!(lifetime_why(&o).is_empty(), "{:?}", lifetime_why(&o));
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

    pub(super) fn timeouts(idle: Option<u32>, lifetime: Option<u32>) -> sv_manifest::PolicySection {
        sv_manifest::PolicySection {
            idle_timeout_minutes: idle,
            session_lifetime_minutes: lifetime,
            ..Default::default()
        }
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

    /// The seeded suite, starting `before` seconds ahead of a 30-second boundary, with the clock
    /// moving `per_request` seconds with every request, as it does against a real app.
    fn totp_ticking(flaws: Flaws, before: u64, per_request: u64) -> Outcome {
        let mut app = FakeApp::new(flaws);
        let step = crate::totp::STEP;
        app.clock = (app.clock / step + 10) * step - before;
        app.seconds_per_request = per_request;
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        if let Some(admin) = acc.admin.clone() {
            app.users.insert(admin.user, (admin.password, true));
        }
        let totp = acc.totp.clone().unwrap();
        app.users.insert(
            totp.account.user.clone(),
            (totp.account.password.clone(), false),
        );
        app.totp
            .insert(totp.account.user.clone(), totp.secret.clone());
        run(&mut app, &users(), &acc, true, &Default::default())
    }

    #[test]
    fn a_code_that_works_twice_is_never_credited_whenever_the_step_ends() {
        // From the review: an app that takes a code twice, and accepts only the current step, with
        // the step ending partway through the check. Every combination must end in the finding or
        // in not assessed — never in V6.5.1 credited.
        for before in [2, 4, 6, 9, 15, 25] {
            for per_request in [0, 1, 2, 3] {
                let o = totp_ticking(
                    Flaws {
                        totp_reusable: true,
                        totp_current_only: true,
                        ..Default::default()
                    },
                    before,
                    per_request,
                );
                assert!(
                    !verified_ids(&o).contains(&TOTP_REUSED.rule_id),
                    "credited, {before}s before a boundary, {per_request}s a request: {:?}",
                    o.steps
                );
            }
        }
    }

    #[test]
    fn a_correct_app_is_still_credited_with_the_clock_moving() {
        // The fix must not just stop crediting: with a step ending in the middle, the pair is
        // tried again in the new step and the refusal counts.
        // One or two seconds a request: a sign-in and a second use fit in one step. Slower than
        // that they cannot, and `a_step_that_keeps_ending_leaves_reuse_unjudged_and_says_so` holds.
        for (before, per_request) in [(25, 1), (15, 1), (9, 2), (4, 0)] {
            let o = totp_ticking(
                Flaws {
                    totp_current_only: true,
                    ..Default::default()
                },
                before,
                per_request,
            );
            assert!(
                verified_ids(&o).contains(&TOTP_REUSED.rule_id),
                "{before}s before a boundary, {per_request}s a request: {:?}\n{:?}",
                o.steps,
                totp_named(&o, "V6.5.1")
            );
        }
    }

    #[test]
    fn an_app_that_takes_a_code_twice_is_still_found_with_the_clock_moving() {
        // One or two seconds a request: a sign-in and a second use fit in one step. Slower than
        // that they cannot, and `a_step_that_keeps_ending_leaves_reuse_unjudged_and_says_so` holds.
        for (before, per_request) in [(25, 1), (15, 1), (9, 2), (4, 0)] {
            let o = totp_ticking(
                Flaws {
                    totp_reusable: true,
                    totp_current_only: true,
                    ..Default::default()
                },
                before,
                per_request,
            );
            assert!(
                rule_ids(&o).contains(&TOTP_REUSED.rule_id),
                "{before}s before a boundary, {per_request}s a request: {:?}",
                o.steps
            );
        }
    }

    #[test]
    fn a_step_that_keeps_ending_leaves_reuse_unjudged_and_says_so() {
        // Eight seconds a request: every pair of sign-ins straddles a boundary.
        let o = totp_ticking(
            Flaws {
                totp_current_only: true,
                ..Default::default()
            },
            25,
            8,
        );
        assert!(
            !verified_ids(&o).contains(&TOTP_REUSED.rule_id),
            "{:?}",
            o.steps
        );
        assert!(!rule_ids(&o).contains(&TOTP_REUSED.rule_id));
        assert!(
            totp_named(&o, "V6.5.1")
                .iter()
                .any(|w| w.contains("step ended")),
            "{:?}",
            totp_named(&o, "V6.5.1")
        );
    }

    #[test]
    fn the_lifetime_credit_says_the_thirty_second_bound_was_not_shown() {
        let o = run_against(Flaws::default(), &users());
        let credit = o
            .verified
            .iter()
            .find(|v| v.check_id == TOTP_OLD_CODE.rule_id)
            .expect("credited");
        assert!(
            credit.scope.contains("at most 30 seconds was not shown"),
            "{}",
            credit.scope
        );
    }

    #[test]
    fn the_case_from_review_is_not_credited() {
        // 15 seconds before a boundary, 3 seconds a request, an app that takes a code twice and
        // only the current step's: credited as verified before the fix.
        let o = totp_ticking(
            Flaws {
                totp_reusable: true,
                totp_current_only: true,
                ..Default::default()
            },
            15,
            3,
        );
        assert!(
            !verified_ids(&o).contains(&TOTP_REUSED.rule_id),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_control_code_refused_as_its_step_ended_does_not_blame_the_setup() {
        let o = totp_ticking(
            Flaws {
                totp_current_only: true,
                ..Default::default()
            },
            25,
            5,
        );
        let why = totp_named(&o, "V6.5.1");
        assert!(why.iter().any(|w| w.contains("step ended")), "{why:?}");
        assert!(
            !why.iter().any(|w| w.contains("Check `totp`")),
            "a clock problem blamed on the manifest: {why:?}"
        );
    }

    #[test]
    fn the_lifetime_credit_is_worded_the_same_with_the_clock_moving() {
        let o = totp_ticking(Flaws::default(), 25, 1);
        let credit = o
            .verified
            .iter()
            .find(|v| v.check_id == TOTP_OLD_CODE.rule_id)
            .expect("credited");
        assert!(credit.scope.contains("not shown"), "{}", credit.scope);
    }

    // --------------------------------------------------------------------------------------------
    // Activation codes emailed at sign-up (V6.4.1)

    const ACTIVATION_RULES: [&str; 2] = [ACTIVATION_GUESSABLE.rule_id, ACTIVATION_REUSABLE.rule_id];

    fn activation_users() -> UsersSection {
        let mut u = with_signup();
        u.activation = Some(sv_manifest::ActivationSection {
            use_code: RequestTemplate {
                method: "POST".into(),
                path: "/activate".into(),
                form: [("code", "{code}"), ("csrf_token", "{csrf}")]
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
                json: BTreeMap::new(),
            },
            code_pattern: None,
        });
        u
    }

    fn run_activation(flaws: Flaws) -> Outcome {
        let mut app = FakeApp::new(flaws);
        app.activation = true;
        let mut acc = accounts();
        acc.admin = None;
        // A and B are seeded, so every activation fixture reaches the check however broken sign-up is.
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let mut u = activation_users();
        u.seed = Some("seed".into());
        run(&mut app, &u, &acc, true, &Default::default())
    }

    /// The same app with every account, A and B included, made through sign-up.
    fn run_activation_signed_up(flaws: Flaws) -> Outcome {
        let mut app = FakeApp::new(flaws);
        app.activation = true;
        let mut acc = accounts();
        acc.admin = None;
        run(
            &mut app,
            &activation_users(),
            &acc,
            false,
            &Default::default(),
        )
    }

    fn activation_findings(o: &Outcome) -> Vec<&str> {
        rule_ids(o)
            .into_iter()
            .filter(|id| ACTIVATION_RULES.contains(id))
            .collect()
    }

    fn activation_why(o: &Outcome) -> Vec<&str> {
        o.not_assessed
            .iter()
            .filter(|(id, _)| id == "V6.4.1")
            .map(|(_, why)| why.as_str())
            .collect()
    }

    #[test]
    fn a_correct_activation_is_followed_through_and_credits_nothing() {
        let o = run_activation(Flaws::default());
        assert!(activation_findings(&o).is_empty(), "{:#?}", o.findings);
        assert!(
            !verified_ids(&o)
                .iter()
                .any(|id| ACTIVATION_RULES.contains(id))
        );
        let steps = o.steps.join("\n");
        for step in [
            "an email arrived with an activation code in it",
            "the account then signed in, and the link itself signed it in",
            "used the same activation code again in a new session: not signed in",
        ] {
            assert!(steps.contains(step), "{step}:\n{steps}");
        }
        assert!(
            activation_why(&o).iter().any(|w| w.contains("not tried")),
            "{:?}",
            activation_why(&o)
        );
    }

    #[test]
    fn each_activation_fault_is_found_by_its_own_rule() {
        for (flaws, rule) in [
            (
                Flaws {
                    activation_reusable: true,
                    ..Default::default()
                },
                ACTIVATION_REUSABLE.rule_id,
            ),
            (
                Flaws {
                    activation_short: true,
                    ..Default::default()
                },
                ACTIVATION_GUESSABLE.rule_id,
            ),
            (
                Flaws {
                    activation_counting: true,
                    ..Default::default()
                },
                ACTIVATION_GUESSABLE.rule_id,
            ),
        ] {
            let o = run_activation(flaws);
            assert_eq!(activation_findings(&o), vec![rule], "{rule}: {:?}", o.steps);
        }
    }

    #[test]
    fn an_activation_that_activates_nothing_is_not_assessed_however_else_it_is_broken() {
        let o = run_activation(Flaws {
            activation_does_nothing: true,
            activation_reusable: true,
            ..Default::default()
        });
        assert!(activation_findings(&o).is_empty(), "{:#?}", o.findings);
        assert!(
            activation_why(&o)
                .iter()
                .any(|w| w.contains("still could not after")),
            "{:?}",
            activation_why(&o)
        );
    }

    #[test]
    fn a_link_that_does_not_sign_in_leaves_reuse_unjudged() {
        let o = run_activation(Flaws {
            activation_link_does_not_sign_in: true,
            activation_reusable: true,
            ..Default::default()
        });
        assert!(
            !activation_findings(&o).contains(&ACTIVATION_REUSABLE.rule_id),
            "{:?}",
            o.steps
        );
        assert!(
            !o.steps
                .iter()
                .any(|s| s.contains("used the same activation code again")),
            "{:?}",
            o.steps
        );
        assert!(
            activation_why(&o)
                .iter()
                .any(|w| w.contains("did not sign anybody in")),
            "{:?}",
            activation_why(&o)
        );
    }

    #[test]
    fn sign_in_that_does_not_wait_for_activation_is_said_and_still_judged() {
        let o = run_activation(Flaws {
            activation_not_gating: true,
            activation_short: true,
            ..Default::default()
        });
        assert_eq!(activation_findings(&o), vec![ACTIVATION_GUESSABLE.rule_id]);
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("could sign in before it was activated")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn accounts_made_through_sign_up_are_activated_so_the_suite_can_sign_in() {
        let o = run_activation_signed_up(Flaws::default());
        let steps = o.steps.join("\n");
        assert!(
            steps.contains("signed in as A and opened /account (200)"),
            "{steps}"
        );
        assert!(activation_findings(&o).is_empty(), "{:#?}", o.findings);
        assert!(
            steps.contains("used the same activation code again in a new session: not signed in"),
            "{steps}"
        );
    }

    #[test]
    fn the_accounts_other_checks_sign_up_are_activated_too() {
        let o = run_activation_signed_up(Flaws::default());
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("signed in as control.") && s.contains("opened")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn the_faults_are_found_when_every_account_is_signed_up_too() {
        for (flaws, rule) in [
            (
                Flaws {
                    activation_reusable: true,
                    ..Default::default()
                },
                ACTIVATION_REUSABLE.rule_id,
            ),
            (
                Flaws {
                    activation_counting: true,
                    ..Default::default()
                },
                ACTIVATION_GUESSABLE.rule_id,
            ),
        ] {
            let o = run_activation_signed_up(flaws);
            assert_eq!(activation_findings(&o), vec![rule], "{rule}: {:?}", o.steps);
        }
    }

    #[test]
    fn a_short_code_is_not_judged_when_activation_activates_nothing() {
        let o = run_activation(Flaws {
            activation_does_nothing: true,
            activation_short: true,
            ..Default::default()
        });
        assert!(activation_findings(&o).is_empty(), "{:#?}", o.findings);
        assert!(
            activation_why(&o)
                .iter()
                .any(|w| w.contains("With no activation that works")),
            "{:?}",
            activation_why(&o)
        );
    }

    #[test]
    fn reuse_is_not_tried_when_the_link_signs_nobody_in() {
        let o = run_activation(Flaws {
            activation_link_does_not_sign_in: true,
            ..Default::default()
        });
        assert!(activation_findings(&o).is_empty(), "{:#?}", o.findings);
        assert!(
            !o.steps
                .iter()
                .any(|s| s.contains("used the same activation code again")),
            "{:?}",
            o.steps
        );
        assert!(
            activation_why(&o)
                .iter()
                .any(|w| w.starts_with("Whether an activation code works twice")),
            "{:?}",
            activation_why(&o)
        );
    }

    #[test]
    fn an_ungated_sign_in_is_said_beside_a_reuse_finding() {
        let o = run_activation(Flaws {
            activation_not_gating: true,
            activation_reusable: true,
            ..Default::default()
        });
        assert_eq!(activation_findings(&o), vec![ACTIVATION_REUSABLE.rule_id]);
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("could sign in before it was activated")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn with_no_mail_server_no_activation_account_is_even_signed_up() {
        let o = run_activation(Flaws {
            no_mail_sink: true,
            ..Default::default()
        });
        assert!(
            !o.steps.iter().any(|s| s.starts_with("signed up activate")),
            "{:?}",
            o.steps
        );
        assert!(
            activation_why(&o)
                .iter()
                .any(|w| w.contains("had no mail server for the app")),
            "{:?}",
            activation_why(&o)
        );
    }

    #[test]
    fn without_a_mail_server_or_a_sign_up_nothing_is_judged_and_it_says_why() {
        let o = run_activation(Flaws {
            no_mail_sink: true,
            activation_reusable: true,
            ..Default::default()
        });
        assert!(activation_findings(&o).is_empty());
        assert!(
            activation_why(&o)
                .iter()
                .any(|w| w.contains("no mail server"))
        );

        let mut app = FakeApp::new(Flaws {
            activation_reusable: true,
            ..Default::default()
        });
        app.activation = true;
        let mut u = activation_users();
        u.signup = None;
        u.seed = Some("seed".into());
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let o = run(&mut app, &u, &acc, true, &Default::default());
        assert!(activation_findings(&o).is_empty());
        assert!(activation_why(&o).iter().any(|w| w.contains("no `signup`")));
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
}
