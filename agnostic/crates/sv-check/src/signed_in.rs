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
//! # Judgement here, requests elsewhere
//!
//! Like `probes.rs`, this decides what to ask and how to read the answers; it talks to the app only
//! through [`Http`]. `sv-run` supplies one that speaks from inside the network fence, and the tests
//! supply a scripted app with each flaw switchable, which is how every rule here is shown to fire.

use crate::finding::{Confidence, Finding, Location, Severity};
use crate::probes::{ProbeRequest, ProbeResponse};
use sv_manifest::{RequestTemplate, UsersSection};

/// Something that can put a request to the running app and bring back its answer.
pub trait Http {
    fn send(&mut self, request: &ProbeRequest) -> Option<ProbeResponse>;
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
struct Session {
    cookies: Vec<(String, String)>,
    bearer: Option<String>,
}

impl Session {
    fn absorb(&mut self, response: &ProbeResponse) {
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
}

fn fill(text: &str, v: &Values) -> String {
    text.replace("{user}", v.user)
        .replace("{new_password}", v.new_password)
        .replace("{password}", v.password)
        .replace("{csrf}", v.csrf.as_deref().unwrap_or(""))
        .replace("{marker}", v.marker)
        .replace("{id}", v.id)
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

fn get(id: &str, path: &str, session: &Session) -> ProbeRequest {
    ProbeRequest {
        id: id.to_owned(),
        method: "GET".to_owned(),
        path: path.to_owned(),
        headers: session.headers(),
        body: None,
    }
}

fn ok(response: &Option<ProbeResponse>) -> bool {
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

fn status(response: &Option<ProbeResponse>) -> String {
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

struct Rule {
    rule_id: &'static str,
    requirement_ids: &'static [&'static str],
    cwe: &'static [&'static str],
    impact: &'static str,
    fix: &'static str,
}

fn finding(rule: &Rule, title: &str, severity: Severity, description: String) -> Finding {
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
) -> Outcome {
    let mut out = Outcome::default();
    let problems = users.problems();
    if !problems.is_empty() {
        out.not_assessed.push((
            "V8.2.1, V8.2.2, V7.2.4, V7.4.1, V3.5.1".to_owned(),
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
            "V8.2.1, V8.2.2, V7.2.4, V7.4.1, V3.5.1, V3.3.2, V3.3.4".to_owned(),
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
            "V8.2.1, V8.2.2, V7.2.4, V7.4.1, V3.5.1, V3.3.2, V3.3.4".to_owned(),
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

    // 3. A record A owns, read as B and as nobody; then the same request from another site. First
    //    among the signed-in checks because A reading back what A made is the second way to show
    //    the session works — the only way, when the private page turned out to be open to all.
    let owned_read = owned_checks(http, users, accounts, &a, &mut out);

    // 4. The session cookie, and whether signing in made a new one.
    session_checks(&a, signed_in_works || owned_read.is_some(), &mut out);

    // 5. Admin pages, as an ordinary user, confirmed against the admin.
    admin_checks(http, users, accounts, &a, &mut out);

    // 6. What sign-up and sign-in let through: passwords and default accounts. These sign in as
    //    other accounts, so A's session is untouched for the sign-out below.
    let confirm = confirm_path.clone().filter(|_| signed_in_works);
    password_checks(http, users, accounts, confirm.as_deref(), &mut out);
    default_account_check(http, users, confirm.as_deref(), &mut out);
    password_field_checks(http, users, Some(&a.session), &mut out);

    // 7. Logging out, which ends A's session.
    logout_check(
        http,
        users,
        &a,
        confirm_path.filter(|_| signed_in_works).or(owned_read),
        &mut out,
    );

    // 8. Last, because each signs A in again, and an app that allows one session per user would
    //    end the one the checks above were using.
    password_in_url_check(http, users, &accounts.a, confirm.as_deref(), &mut out);
    session_id_check(http, users, accounts, &a, signed_in_works, &mut out);
    sign_out_on_get_check(http, users, &accounts.a, confirm.as_deref(), &mut out);

    // 9. Last of all, because it changes a password: with an account made for it when there is a
    //    sign-up, and with A's own when there is not.
    change_password_checks(http, users, accounts, confirm.as_deref(), &mut out);
    delete_account_check(http, users, accounts, confirm.as_deref(), &mut out);

    out
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
    out: &mut Outcome,
) {
    const IDS: &str = "V6.2.1, V6.2.4, V6.2.5, V6.2.8, V6.2.9";
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
    ];
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

/// Whether signing out also happens on a plain page visit (V3.5.3).
///
/// A fresh sign-in, shown to open the private page; a GET to the sign-out address; then the private
/// page again. Only ever a finding: one address refusing a GET says nothing about the others.
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
        users: BTreeMap<String, (String, bool)>, // user -> (password, is admin)
        sessions: BTreeMap<String, String>,      // session id -> user ("" = not signed in)
        notes: Vec<(String, String)>,            // (owner, text)
        next: u32,
        /// Old passwords a change left working, under `change_keeps_old`.
        kept: BTreeMap<String, String>,
    }

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
    }

    const CSRF: &str = "tok-123";

    impl FakeApp {
        fn new(flaws: Flaws) -> Self {
            let mut app = FakeApp {
                flaws,
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
        fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
            // A bearer token is a session id too, for the JSON sign-in below.
            let bearer = r
                .headers
                .iter()
                .find(|(k, _)| k == "Authorization")
                .and_then(|(_, v)| v.strip_prefix("Bearer "))
                .map(str::to_owned);
            let sid = bearer.or_else(|| cookie_value(r, "sid"));
            let user = sid
                .as_ref()
                .and_then(|s| self.sessions.get(s))
                .filter(|u| !u.is_empty())
                .cloned();
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
                    let good = !self.flaws.broken_login
                        && (self
                            .users
                            .get(email)
                            .is_some_and(|(p, _)| self.password_matches(p, given))
                            || self.kept.get(email) == Some(given));
                    if !good || !token_ok {
                        return Some(Self::respond(403, vec![], "no"));
                    }
                    let who = f.get("email")?.clone();
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
                        "<input type=hidden name=csrf_token value={CSRF}>{}{}",
                        self.password_input(),
                        if self.flaws.secret_question {
                            "<label>Favourite teacher <input name=security_answer></label>"
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
                    Self::respond(303, vec![("Set-Cookie", "sid=; Max-Age=0".into())], "")
                }
                ("GET", "/account") => {
                    if user.is_some() || self.flaws.private_open {
                        Self::respond(200, vec![], "your account")
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
                        Self::respond(200, vec![], &format!("<p>{text}</p>"))
                    } else {
                        Self::respond(404, vec![], "none")
                    }
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
        run(&mut app, users, &acc, true)
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
        let o = run(&mut app, &users(), &accounts(), true);
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
        let o = run(&mut app, &u, &acc, false);
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
        let o = run(&mut app, &u, &accounts(), true);
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
        let mut app = FakeApp::new(flaws);
        let mut acc = accounts();
        acc.admin = None;
        run(&mut app, &with_signup(), &acc, false)
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
        let o = run(&mut app, &u, &acc, false);
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
}
