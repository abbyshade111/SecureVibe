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
}

fn fill(text: &str, v: &Values) -> String {
    text.replace("{user}", v.user)
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
            let values = Values {
                user: &account.user,
                password: &account.password,
                ..Default::default()
            };
            let mut session = Session::default();
            let (response, _) = send_template(
                http,
                &format!("signup-{who}"),
                signup,
                &values,
                &mut session,
                &[],
            );
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

    // 6. Logging out last, because it ends A's session.
    logout_check(
        http,
        users,
        &a,
        confirm_path.filter(|_| signed_in_works).or(owned_read),
        &mut out,
    );

    out
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
    }

    const CSRF: &str = "tok-123";

    impl FakeApp {
        fn new(flaws: Flaws) -> Self {
            FakeApp {
                flaws,
                ..Default::default()
            }
        }

        fn new_id(&mut self) -> String {
            self.next += 1;
            format!("s{:04}x{}", self.next * 7919, self.next)
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

    fn form(request: &ProbeRequest) -> BTreeMap<String, String> {
        request
            .body
            .as_deref()
            .unwrap_or("")
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| {
                (
                    k.to_owned(),
                    v.replace('+', " ").replace("%40", "@").replace("%2D", "-"),
                )
            })
            .collect()
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
            let path = r.path.clone();
            Some(match (r.method.as_str(), path.as_str()) {
                ("GET", "/login") => {
                    let id = self.new_id();
                    self.sessions.insert(id.clone(), String::new());
                    let attrs = self.cookie_attrs();
                    Self::respond(
                        200,
                        vec![("Set-Cookie", format!("sid={id}; {attrs}"))],
                        &format!(
                            "<form><input type=\"hidden\" name=\"csrf_token\" value=\"{CSRF}\"></form>"
                        ),
                    )
                }
                ("POST", "/login") => {
                    let f = form(r);
                    let good = !self.flaws.broken_login
                        && self
                            .users
                            .get(f.get("email")?)
                            .is_some_and(|(p, _)| Some(p) == f.get("password"));
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
                    let id = self.new_id();
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
                ("GET", "/signup") => Self::respond(
                    200,
                    vec![],
                    &format!("<input type=hidden name=csrf_token value={CSRF}>"),
                ),
                ("POST", "/signup") => {
                    if !token_ok {
                        return Some(Self::respond(403, vec![], "refused"));
                    }
                    let f = form(r);
                    let (email, password) = (f.get("email")?.clone(), f.get("password")?.clone());
                    self.users.insert(email, (password, false));
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
        }
    }

    fn accounts() -> Accounts {
        Accounts {
            a: Account {
                user: "a@example.test".into(),
                password: "pa".into(),
            },
            b: Account {
                user: "b@example.test".into(),
                password: "pb".into(),
            },
            admin: Some(Account {
                user: "admin@example.test".into(),
                password: "pz".into(),
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
        assert_eq!(app.users.len(), 2, "both users signed up");
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
}
