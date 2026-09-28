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
mod codes;
mod flows;
mod forgery;
mod passwords;
mod rules;
mod sessions;
mod signin;
mod uploads;
use admin::*;
use codes::*;
use flows::*;
use forgery::*;
use passwords::*;
use rules::*;
pub(crate) use rules::{Rule, finding};
use sessions::*;
use signin::*;
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

// ------------------------------------------------------------------------------------------------
// Uploads

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
}
