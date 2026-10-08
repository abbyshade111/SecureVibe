//! Checks made in a real browser, signed in as the first test user.
//!
//! Some questions have an answer only once a page is drawn: whether a sign-out control that is in
//! the HTML can actually be seen (V7.4.4), and whether text somebody typed is shown as text or drawn
//! as markup and run (V3.2.2). A request and its response cannot tell; a browser can. The run starts
//! a headless Chromium on the fenced network when stackvet.toml has `[stack.run.users.browser]`,
//! and this module says what to do in it and what the answers mean.
//!
//! Nothing is credited unless the browser was really signed in: each private page has to open in it
//! as it did for the plain requests, or the checks here say why they were not made.

use crate::finding::Severity;
use crate::signed_in::{Account, Http, Outcome, Rule, Session, finding};
use serde_json::{Value, json};
use sv_manifest::{BrowserSection, UsersSection};

/// One visit to the browser: what it is asked to do, in order. It starts with no cookies; a job
/// that needs some sets them with `Action::SetCookies`, whose answer says which the browser refused.
#[derive(Debug, Clone, PartialEq)]
pub struct Job {
    pub actions: Vec<Action>,
}

/// A cookie as the browser is handed it, with the attributes the app set it with, so the browser
/// keeps it as it would have kept it from the app. Handing over the name and value alone was not
/// enough: a browser refuses a `__Host-` cookie that is not `Secure`, and the browser checks then
/// said the browser was not signed in (family-hub, 3 October 2026). No `Domain` is carried: the
/// browser reaches the app at `localhost`, and the cookie is set for that.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BrowserCookie {
    pub name: String,
    pub value: String,
    pub secure: bool,
    pub http_only: bool,
    /// The `Path` the app gave, or `/` when it gave none.
    pub path: Option<String>,
    /// `SameSite`, lower case, as the app wrote it.
    pub same_site: Option<String>,
}

impl BrowserCookie {
    /// A cookie with no attributes but its name and value.
    pub fn plain(name: &str, value: &str) -> Self {
        BrowserCookie {
            name: name.to_owned(),
            value: value.to_owned(),
            ..Default::default()
        }
    }

    /// As the driver hands it to the browser (DevTools' `Network.setCookie`, less the address).
    ///
    /// A name starting `__Secure-` or `__Host-` is a promise the browser holds the app to: it keeps
    /// such a cookie only when it is `Secure`, and a `__Host-` one only with the path `/`. Those are
    /// set here whatever the app said, as the owner decided on 4 October 2026, so the prefix itself
    /// never stops the browser being signed in. Browsers match the prefixes in any case.
    pub fn to_json(&self) -> Value {
        let lower = self.name.to_ascii_lowercase();
        let host = lower.starts_with("__host-");
        let secure = self.secure || host || lower.starts_with("__secure-");
        let path = if host {
            "/"
        } else {
            self.path.as_deref().unwrap_or("/")
        };
        let mut out = json!({
            "name": self.name,
            "value": self.value,
            "path": path,
            "secure": secure,
            "httpOnly": self.http_only,
        });
        let same_site = match self.same_site.as_deref() {
            Some("strict") => Some("Strict"),
            Some("lax") => Some("Lax"),
            Some("none") => Some("None"),
            _ => None,
        };
        if let Some(same_site) = same_site {
            out["sameSite"] = json!(same_site);
        }
        out
    }
}

/// The cookies the browser refused, from a `SetCookies` answer, each as "name (the browser's
/// reason)". Empty when it kept them all.
pub(crate) fn refused_cookies(answer: &Value) -> Vec<String> {
    field(answer, "refused")
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|r| {
                    let name = r.get("name")?.as_str()?;
                    Some(match r.get("why").and_then(Value::as_str) {
                        Some(why) if !why.is_empty() => format!("{name} ({why})"),
                        _ => name.to_owned(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// "The browser refused the cookie a (why)" or "the cookies a (why) and b (why)", for a sentence.
pub(crate) fn refused_sentence(refused: &[String]) -> String {
    format!(
        "the browser refused the cookie{} {}",
        if refused.len() == 1 { "" } else { "s" },
        refused.join(" and ")
    )
}

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Opens a page: answers `{"status", "path"}`, `path` being where the browser ended up.
    Goto(String),
    /// Opens a page, types `text` into the first box in its first form that has one, and submits
    /// it as its button would: answers `{"status", "path", "found", "after": {"status", "path"}}`.
    Fill { page: String, text: String },
    /// Runs an expression in the page: answers `{"value"}`.
    Eval(String),
    /// Waits, up to five seconds: answers `{}`.
    Wait(u64),
    /// Runs an expression that does something in the page, such as clicking, and returns whether it
    /// found what to do; when it did, waits for where that leads: answers
    /// `{"found", "after": {"status", "path"}}`.
    Act(String),
    /// Sets cookies for the app, with their attributes: answers `{"refused": [{"name", "why"}]}`,
    /// each cookie the browser would not keep and the reason it gave.
    SetCookies(Vec<BrowserCookie>),
    /// Every request the tab tried to send to a host other than the app's since the job began:
    /// answers `{"requests": [{"url", "method", "type", "page", "body", "headers"}]}`.
    Outside,
}

impl Action {
    /// As the driver reads it.
    pub fn to_json(&self) -> Value {
        match self {
            Action::Goto(path) => json!({ "goto": path }),
            Action::Fill { page, text } => json!({ "fill": page, "text": text }),
            Action::Eval(expression) => json!({ "eval": expression }),
            Action::Wait(ms) => json!({ "wait": ms }),
            Action::Act(expression) => json!({ "act": expression }),
            Action::SetCookies(cookies) => {
                json!({ "cookies": cookies.iter().map(BrowserCookie::to_json).collect::<Vec<_>>() })
            }
            Action::Outside => json!({ "outside": true }),
        }
    }
}

pub(crate) const HIDDEN_SIGN_OUT: Rule = Rule {
    rule_id: "probe.sign-out-control-hidden",
    requirement_ids: &["V7.4.4"],
    cwe: &["CWE-613"],
    impact: "The sign-out control is in the page but a person cannot see it, so somebody who wants \
             to sign out cannot, and a session left open on a shared machine is the next person's \
             session.",
    fix: "Show the sign-out link or button on every page that needs signing in: not hidden, not \
          moved off the screen, not shrunk to nothing.",
};

pub(crate) const TEXT_AS_MARKUP: Rule = Rule {
    rule_id: "probe.text-rendered-as-markup",
    requirement_ids: &["V3.2.2"],
    cwe: &["CWE-79"],
    impact: "Text a person types is put into the page as markup, so anybody who can type into that \
             form can put a script into the page of whoever views it: acting as them, reading what \
             they see, sending it elsewhere.",
    fix: "Show typed text as text: let the template language escape it (and never switch that \
          off for it), and in the browser set `textContent`, not `innerHTML`. If the text really is \
          meant to carry formatting, pass it through a well-known HTML sanitizer first.",
};

pub(crate) const DETAILS_SENT_ELSEWHERE: Rule = Rule {
    rule_id: "probe.account-details-sent-elsewhere",
    requirement_ids: &["V14.2.3"],
    cwe: &["CWE-359"],
    impact: "A signed-in page sends the person's own account details to another website, such as \
             an analytics or advertising service, where they are collected outside the app's \
             control and its privacy promises.",
    fix: "Keep account details out of everything a page sends to other sites: no email address, \
          password, or session cookie in a tracking pixel's address, an analytics event, or a \
          request body, hashed or not. If a service must tell people apart, give it an identifier \
          that means nothing outside the app, and say so in the privacy notice.",
};

/// The mark put in the typed text, so it can be found again: made from the run's own randomness,
/// but not a piece of it, since pieces of that are the test accounts' passwords.
pub(crate) fn token(spare: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    ("sv-browser", spare).hash(&mut h);
    format!("{:016x}", h.finish())
}

pub(crate) const KEPT_AFTER_SIGN_OUT: Rule = Rule {
    rule_id: "probe.storage-kept-after-sign-out",
    requirement_ids: &["V14.3.1"],
    cwe: &["CWE-922"],
    impact: "What the app kept in the browser for a signed-in person is still there after they sign \
             out, where the next person to use that browser can read it: a shared computer, a \
             borrowed phone, a library.",
    fix: "Clear what the app stored for the signed-in person when they sign out: remove its keys \
          from `localStorage` and `sessionStorage` and delete its IndexedDB databases in the page's \
          sign-out code, and send `Clear-Site-Data: \"storage\"` with the sign-out response as \
          well, so it is cleared even when the page's own code does not run.",
};

/// What the browser is holding for the app: the keys in each kind of storage, and the names of its
/// IndexedDB databases. A kind that cannot be read comes back as `null`.
const STORAGE_QUESTION: &str = r#"(async () => {
  const keys = (s) => { try { return Object.keys(s); } catch { return null; } };
  let databases = null;
  try { databases = (await indexedDB.databases()).map((d) => d.name); } catch {}
  return { local: keys(localStorage), session: keys(sessionStorage), indexeddb: databases };
})()"#;

/// Clicks the first sign-out control a person could see and click: a link leading to `logout`, or
/// the button of a form that posts there.
fn sign_out_click(logout: &str) -> String {
    format!(
        r#"(() => {{
  const target = {target};
  const leads = (el, attr) => {{
    try {{ return new URL(el.getAttribute(attr), location.href).pathname === target; }}
    catch {{ return false; }}
  }};
  const seen = (el) => {{
    if (el.checkVisibility && !el.checkVisibility({{ opacityProperty: true, visibilityProperty: true }})) return false;
    const r = el.getBoundingClientRect();
    return r.width >= 2 && r.height >= 2;
  }};
  const links = [...document.querySelectorAll('a[href]')].filter((a) => leads(a, 'href'));
  const forms = [...document.querySelectorAll('form[action]')].filter((f) => leads(f, 'action'));
  const buttons = forms.flatMap((f) => [...f.querySelectorAll('button, input[type=submit], input[type=image]')]);
  const control = [...links, ...buttons].find(seen);
  if (!control) return false;
  control.click();
  return true;
}})()"#,
        target = json!(logout)
    )
}

/// What the page is asked about the sign-out control, given its path: how many links and forms
/// lead there, and whether any of them can be seen.
fn sign_out_question(logout: &str) -> String {
    format!(
        r#"(() => {{
  const target = {target};
  const leads = (el, attr) => {{
    try {{ return new URL(el.getAttribute(attr), location.href).pathname === target; }}
    catch {{ return false; }}
  }};
  const seen = (el) => {{
    if (el.checkVisibility && !el.checkVisibility({{ opacityProperty: true, visibilityProperty: true }})) return false;
    const r = el.getBoundingClientRect();
    return r.width >= 2 && r.height >= 2 && r.right > 0 && r.bottom > 0
      && r.left < Math.max(document.documentElement.scrollWidth, innerWidth);
  }};
  const links = [...document.querySelectorAll('a[href]')].filter((a) => leads(a, 'href'));
  const forms = [...document.querySelectorAll('form[action]')].filter((f) => leads(f, 'action'));
  const buttons = forms.flatMap((f) => [...f.querySelectorAll('button, input[type=submit], input[type=image]')]);
  return {{ controls: links.length + forms.length, visible: [...links, ...buttons].some(seen) }};
}})()"#,
        target = json!(logout)
    )
}

/// What the page is asked about the text typed into the form: whether the markup in it ran,
/// whether it became part of the page, and whether it is there as the text that was typed.
///
/// Whether it ran is read from a mark the script leaves on the page itself, not from a variable it
/// sets: the driver asks in a world of its own, which shares the page but not the page's script
/// variables, so `window.sv_…` set by the script was never seen, and a script that ran was reported
/// as stopped (the review of 6 October, item 10).
pub fn markup_question(token: &str) -> String {
    format!(
        r#"(() => {{
  const t = {t};
  return {{
    ran: document.documentElement.getAttribute('data-sv-ran') === t,
    element: !!document.querySelector('[data-sv="' + t + '"], [data-sv-b="' + t + '"]'),
    as_text: (document.body ? document.body.innerText : '').includes('data-sv="' + t + '"'),
    present: document.documentElement.outerHTML.includes('sv-' + t),
  }};
}})()"#,
        t = json!(token)
    )
}

/// The line typed into the form. It closes a quoted attribute first, so it gets out of one if the
/// page puts it inside one, and then carries an image whose failure to load runs a line of script,
/// and a bold tag, each marked so the page can be asked whether they became elements.
pub fn markup_line(token: &str) -> String {
    format!(
        "sv-{token} \"'><img src=x data-sv=\"{token}\" onerror=\"document.documentElement.setAttribute('data-sv-ran','{token}')\"><b data-sv-b=\"{token}\">sv</b>"
    )
}

pub(crate) fn field<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or(&Value::Null)
}

pub(crate) fn opened(v: &Value, path: &str) -> bool {
    field(v, "status")
        .as_u64()
        .is_some_and(|s| (200..300).contains(&s))
        && field(v, "path")
            .as_str()
            .map(|p| p.split('?').next().unwrap_or(p))
            == Some(path.split('?').next().unwrap_or(path))
}

/// The browser checks, with the first user's session. `works` says whether the plain requests
/// showed that session opening the private pages; without that, nothing here would mean anything.
pub(crate) fn checks(
    http: &mut dyn Http,
    users: &UsersSection,
    session: &Session,
    account: &Account,
    works: bool,
    token: &str,
    out: &mut Outcome,
) {
    let Some(section) = &users.browser else {
        return;
    };
    let ids = |section: &BrowserSection| {
        if section.text_form.is_some() {
            "V7.4.4, V3.2.2"
        } else {
            "V7.4.4"
        }
    };
    let not_made = |out: &mut Outcome, why: &str| {
        out.not_assessed
            .push((ids(section).to_owned(), format!("In a real browser: {why}")));
    };
    if !works || users.private.is_empty() {
        not_made(
            out,
            "nothing was asked, because signing in did not open a private page for the plain \
             requests either.",
        );
        return;
    }
    if session.cookies().is_empty() {
        not_made(
            out,
            "nothing was asked. The first user's sign-in gave no cookie to hand to the browser (a \
             token in JSON cannot be), so it could not be signed in.",
        );
        return;
    }

    // The cookies first, then every private page, and after them the form and the page that shows
    // what was typed.
    let mut actions: Vec<Action> = vec![Action::SetCookies(session.browser_cookies())];
    for page in &users.private {
        actions.push(Action::Goto(page.clone()));
        actions.push(Action::Eval(sign_out_question(
            users.logout.as_ref().map_or("", |l| l.path.as_str()),
        )));
    }
    if let Some(form) = &section.text_form {
        actions.push(Action::Fill {
            page: form.clone(),
            text: markup_line(token),
        });
        if let Some(shows) = &section.shows {
            actions.push(Action::Goto(shows.clone()));
        }
        // An image that fails to load does so a moment after the page has.
        actions.push(Action::Wait(700));
        actions.push(Action::Eval(markup_question(token)));
    }
    // Last, what every page above tried to send elsewhere, after a moment for a beacon sent as a
    // page settles.
    actions.push(Action::Wait(500));
    actions.push(Action::Outside);
    let job = Job { actions };
    let Some(answers) = http.browser(&job).filter(|a| a.len() == job.actions.len()) else {
        not_made(
            out,
            "nothing was asked. The browser could not be started, or did not finish what it was \
             given.",
        );
        return;
    };

    // The control first: the browser has to be signed in, as the plain requests were.
    let pages = &users.private;
    let mut answers = answers;
    let sent = answers.pop().unwrap_or(Value::Null);
    let _wait = answers.pop();
    let mut answers = answers.into_iter();
    let refused = refused_cookies(&answers.next().unwrap_or(Value::Null));
    let mut signed_in = true;
    let mut visits = Vec::new();
    for page in pages {
        let visit = answers.next().unwrap_or(Value::Null);
        let asked = answers.next().unwrap_or(Value::Null);
        if !opened(&visit, page) {
            signed_in = false;
        }
        visits.push((page.as_str(), field(&asked, "value").clone()));
    }
    if !signed_in {
        // A cookie the browser would not keep is the likeliest reason, and said by name.
        let because = if refused.is_empty() {
            String::new()
        } else {
            format!(
                " Handed the first user's cookies, {}, which may be why.",
                refused_sentence(&refused)
            )
        };
        not_made(
            out,
            &format!(
                "the private page{} did not open in the browser with the first user's cookies, \
                 though {} for the plain requests, so the browser was not really signed in.{because}",
                if pages.len() == 1 { "" } else { "s" },
                if pages.len() == 1 {
                    "it opened"
                } else {
                    "they opened"
                }
            ),
        );
        return;
    }
    out.steps.push(format!(
        "signed in a real browser with the first user's cookies: {} private page{} opened in it{}",
        pages.len(),
        if pages.len() == 1 { "" } else { "s" },
        if refused.is_empty() {
            String::new()
        } else {
            format!(", though {}", refused_sentence(&refused))
        }
    ));

    sign_out_visible(users, &visits, out);
    if let Some(form) = &section.text_form {
        let filled = answers.next().unwrap_or(Value::Null);
        if section.shows.is_some() {
            let _ = answers.next();
        }
        let _wait = answers.next();
        let asked = answers.next().unwrap_or(Value::Null);
        text_shown_as_text(
            form,
            section.shows.as_deref(),
            &filled,
            field(&asked, "value"),
            out,
        );
    }
    details_sent_elsewhere(account, session.cookies(), &sent, out);
}

/// One of the test account's details, in one of the forms a page might send it in.
struct Needle {
    /// What it is, in the owner's words: "email address", "password", "session cookie".
    what: &'static str,
    /// How it was written: "as written", "in base64", "as a SHA-256 hash".
    how: &'static str,
    text: String,
    /// Email addresses are matched without regard to case, as the services that take them do.
    any_case: bool,
}

/// The forms each detail is looked for in. A tracker is sent an email address as it is, encoded
/// into a web address (which `readable` undoes on the other side), in base64, or hashed with
/// SHA-256 after lower-casing, which is how the big advertising services ask for it.
fn needles(account: &Account, cookies: &[(String, String)]) -> Vec<Needle> {
    use sha2::{Digest, Sha256};
    let email = account.user.trim().to_lowercase();
    let hash: String = Sha256::digest(email.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut out = vec![
        Needle {
            what: "email address",
            how: "as written",
            text: email.clone(),
            any_case: true,
        },
        Needle {
            what: "email address",
            how: "as a SHA-256 hash",
            text: hash,
            any_case: true,
        },
        Needle {
            what: "password",
            how: "as written",
            text: account.password.clone(),
            any_case: false,
        },
    ];
    for (what, value) in [("email address", &email), ("password", &account.password)] {
        for text in [
            base64(value.as_bytes(), false),
            base64(value.as_bytes(), true),
        ] {
            out.push(Needle {
                what,
                how: "in base64",
                text,
                any_case: false,
            });
        }
    }
    // A cookie value short enough to turn up by chance is no evidence of anything.
    for (_, value) in cookies.iter().filter(|(_, v)| v.len() >= 12) {
        out.push(Needle {
            what: "session cookie",
            how: "as written",
            text: value.clone(),
            any_case: false,
        });
    }
    out
}

/// Base64 without padding, in the standard alphabet or the one made for web addresses.
pub(crate) fn base64(bytes: &[u8], url_safe: bool) -> String {
    let alphabet: &[u8; 64] = if url_safe {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..=chunk.len() {
            out.push(alphabet[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    out
}

/// A web address or form body as a person would read it: `%40` back to `@`, and `+` to a space.
pub(crate) fn readable(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(high), Some(low)) => {
                        out.push(high << 4 | low);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The host a request went to, without the user name, password, or port an address can carry.
fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    host.split(':').next().unwrap_or(host)
}

/// V14.2.3: the requests the signed-in pages tried to send to other hosts, looked through for the
/// test account's own details. Only ever a finding: the fence keeps a script a page loads from
/// another host from arriving, so whatever such a script would have sent is never seen, and a
/// clean list says nothing about it.
fn details_sent_elsewhere(
    account: &Account,
    cookies: &[(String, String)],
    sent: &Value,
    out: &mut Outcome,
) {
    let Some(requests) = field(sent, "requests").as_array() else {
        out.steps.push(
            "could not list what the signed-in pages tried to send to other sites: the browser did \
             not say"
                .to_owned(),
        );
        return;
    };
    let text = |r: &Value, key: &str| field(r, key).as_str().unwrap_or("").to_owned();
    let mut hosts: Vec<String> = Vec::new();
    for r in requests {
        let host = host_of(field(r, "url").as_str().unwrap_or("")).to_owned();
        if !host.is_empty() && !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    if hosts.is_empty() {
        out.steps.push(
            "no signed-in page tried to reach another site from the browser; a server that sends \
             to one itself is not seen this way"
                .to_owned(),
        );
        return;
    }
    out.steps.push(format!(
        "the signed-in pages tried to reach {} other site{}, which the fence stopped: {}. Code a \
         page loads from another site cannot arrive inside the fence, so what it would send is \
         not seen",
        hosts.len(),
        if hosts.len() == 1 { "" } else { "s" },
        hosts.join(", ")
    ));

    let needles = needles(account, cookies);
    // (what, how, host, page), once each.
    let mut seen: Vec<(&str, &str, String, String)> = Vec::new();
    for r in requests {
        let raw = format!(
            "{}\n{}\n{}",
            text(r, "url"),
            text(r, "body"),
            text(r, "headers")
        );
        let decoded = readable(&raw);
        let (raw_lower, decoded_lower) = (raw.to_lowercase(), decoded.to_lowercase());
        for n in &needles {
            let found = |hay: &str, lower: &str| {
                if n.any_case {
                    lower.contains(&n.text.to_lowercase())
                } else {
                    hay.contains(&n.text)
                }
            };
            let how = if found(&raw, &raw_lower) {
                n.how
            } else if found(&decoded, &decoded_lower) {
                if n.how == "as written" {
                    "encoded into a web address"
                } else {
                    n.how
                }
            } else {
                continue;
            };
            let key = (
                n.what,
                how,
                host_of(field(r, "url").as_str().unwrap_or("")).to_owned(),
                text(r, "page"),
            );
            if !seen.contains(&key) {
                seen.push(key);
            }
        }
    }
    if seen.is_empty() {
        return;
    }
    let severe = seen
        .iter()
        .any(|(what, ..)| *what == "password" || *what == "session cookie");
    // Never the value itself: the host, the page, what it was, and how it was written.
    let lines: Vec<String> = seen
        .iter()
        .map(|(what, how, host, page)| {
            format!(
                "its {what}, {how}, to {host}{}",
                if page.is_empty() {
                    String::new()
                } else {
                    format!(" from {page}")
                }
            )
        })
        .collect();
    out.findings.push(finding(
        &DETAILS_SENT_ELSEWHERE,
        "A signed-in page sends the account's own details to another site",
        if severe {
            Severity::High
        } else {
            Severity::Medium
        },
        format!(
            "Signed in as a test user in a real browser, the app's pages tried to send {}. The \
             fence stopped the requests, so nothing left the machine; on the live site they would \
             arrive.",
            lines.join("; ")
        ),
    ));
}

fn sign_out_visible(users: &UsersSection, visits: &[(&str, Value)], out: &mut Outcome) {
    let Some(logout) = users.logout.as_ref().map(|l| l.path.as_str()) else {
        // The plain check has already said there is nothing to look for.
        return;
    };
    let mut hidden = Vec::new();
    let mut seen = 0;
    for (page, answer) in visits {
        let controls = field(answer, "controls").as_u64();
        let visible = field(answer, "visible").as_bool();
        match (controls, visible) {
            // No control at all is the plain check's finding already; one it cannot see is ours.
            (Some(0), _) => {}
            (Some(_), Some(true)) => seen += 1,
            (Some(_), Some(false)) => hidden.push(*page),
            _ => {
                out.not_assessed.push((
                    "V7.4.4".to_owned(),
                    format!("In a real browser: {page} could not be asked about its controls."),
                ));
                return;
            }
        }
    }
    out.steps.push(format!(
        "in the browser, {seen} of {} private page{} showed a sign-out control a person can see",
        visits.len(),
        if visits.len() == 1 { "" } else { "s" }
    ));
    if !hidden.is_empty() {
        out.findings.push(finding(
            &HIDDEN_SIGN_OUT,
            "A sign-out control is on the page but cannot be seen",
            Severity::Low,
            format!(
                "Drawn in a real browser for a signed-in user, {} carried a link or form leading \
                 to {logout}, and none of them could be seen: hidden, of no size, or off the \
                 screen.",
                hidden.join(", ")
            ),
        ));
    } else if seen == visits.len() {
        out.verified.push(crate::Verified::new(
            HIDDEN_SIGN_OUT.rule_id,
            HIDDEN_SIGN_OUT.requirement_ids,
            format!(
                "{seen} private page{}, each drawn in a real browser with a sign-out control a \
                 person can see",
                if seen == 1 { "" } else { "s" }
            ),
        ));
    }
}

fn text_shown_as_text(
    form: &str,
    shows: Option<&str>,
    filled: &Value,
    answer: &Value,
    out: &mut Outcome,
) {
    let not_assessed = |out: &mut Outcome, why: String| {
        out.not_assessed
            .push(("V3.2.2".to_owned(), format!("In a real browser: {why}")));
    };
    if !opened(filled, form) {
        not_assessed(
            out,
            format!("{form} did not open for the signed-in user, so nothing was typed into it."),
        );
        return;
    }
    if field(filled, "found").as_bool() != Some(true) {
        not_assessed(
            out,
            format!("{form} has no form with a box to type text into, so nothing was typed."),
        );
        return;
    }
    let after = field(filled, "after");
    if field(after, "status").as_u64().is_none_or(|s| s >= 400) {
        not_assessed(
            out,
            format!(
                "the text typed into {form} was refused ({}), so there was nothing to look for.",
                field(after, "status")
            ),
        );
        return;
    }
    let place = shows
        .map(str::to_owned)
        .or_else(|| field(after, "path").as_str().map(str::to_owned))
        .unwrap_or_else(|| form.to_owned());
    let flag = |k: &str| field(answer, k).as_bool();
    let what = "a line of text containing an image tag with a script in its `onerror`";
    // All four answers or none: a page that says the text is there as typed, but not whether its
    // script ran, has not said enough to be credited or to be explained.
    let (Some(ran), Some(element), Some(as_text), Some(present)) = (
        flag("ran"),
        flag("element"),
        flag("as_text"),
        flag("present"),
    ) else {
        out.steps.push(format!(
            "typed {what} into {form} in the browser; {place} could not be asked about it"
        ));
        not_assessed(
            out,
            format!("{place} could not be asked about what was typed into {form}."),
        );
        return;
    };
    out.steps.push(format!(
        "typed {what} into {form} in the browser; on {place} it {}",
        match (ran, element, as_text, present) {
            (true, ..) => "ran",
            (_, true, ..) => "became part of the page without running",
            (_, _, true, _) => "was shown as the text typed",
            (_, _, _, true) => "was there, changed",
            _ => "did not appear",
        }
    ));
    match (ran, element, as_text, present) {
        (true, ..) => out.findings.push(finding(
            &TEXT_AS_MARKUP,
            "Text typed into a form runs as script on the page that shows it",
            Severity::High,
            format!(
                "In a real browser, {what}, typed into {form}, ran when {place} showed it: the \
                 text was put into the page as markup."
            ),
        )),
        (_, true, ..) => out.findings.push(finding(
            &TEXT_AS_MARKUP,
            "Text typed into a form becomes part of the page that shows it",
            Severity::Medium,
            format!(
                "In a real browser, {what}, typed into {form}, became elements of {place}. The \
                 script in it did not run, most likely because the page's \
                 Content-Security-Policy stopped it; that policy is a second line, and the text \
                 is still being put into the page as markup."
            ),
        )),
        (_, _, true, _) => out.verified.push(crate::Verified::new(
            TEXT_AS_MARKUP.rule_id,
            TEXT_AS_MARKUP.requirement_ids,
            format!(
                "{what}, typed into {form} in a real browser, shown on {place} as the text typed, \
                 neither run nor made part of the page"
            ),
        )),
        (_, _, _, true) => not_assessed(
            out,
            format!(
                "{what}, typed into {form}, was on {place} but not as it was typed, so the markup \
                 was changed or taken out on the way. That may be a sanitizer, which is what V1.3.1 \
                 asks for rich text; it is not text shown as text, so V3.2.2 is not credited."
            ),
        ),
        _ => not_assessed(
            out,
            format!(
                "{what}, typed into {form}, did not appear on {place}. Name the page that shows \
                 it in `shows`."
            ),
        ),
    }
}

/// What is kept in each kind of browser storage, as `kind: key` pairs, or `None` when the page
/// could not be asked.
fn stored(answer: &Value) -> Option<Vec<String>> {
    let value = field(answer, "value");
    let mut out = Vec::new();
    for kind in ["local", "session", "indexeddb"] {
        let list = field(value, kind).as_array()?;
        for key in list {
            out.push(format!("{kind}: {}", key.as_str()?));
        }
    }
    Some(out)
}

/// Whether signing out empties what the app kept in the browser (V14.3.1), with a sign-in made for
/// it, `session`, since signing the browser out ends that session for good.
///
/// The browser first opens the sign-in page with no cookies, and what the app keeps there is set
/// aside: a remembered color scheme is not a signed-in person's data. Then it is signed in, opens the
/// first private page, and signs out with the app's own control, as a person would. What the app
/// kept only once somebody was signed in has to be gone afterwards.
pub(crate) fn sign_out_check(
    http: &mut dyn Http,
    users: &UsersSection,
    session: Option<&Session>,
    out: &mut Outcome,
) {
    const IDS: &str = "V14.3.1";
    if users.browser.is_none() {
        return;
    }
    let not_assessed = |out: &mut Outcome, why: &str| {
        out.not_assessed
            .push((IDS.to_owned(), format!("In a real browser: {why}")));
    };
    let (Some(logout), Some(login), Some(private)) = (
        users.logout.as_ref(),
        users.login.as_ref(),
        users.private.first(),
    ) else {
        not_assessed(
            out,
            "whether signing out empties the browser's storage needs `login`, `logout`, and a \
             private page in [stack.run.users].",
        );
        return;
    };
    let Some(session) = session.filter(|s| !s.cookies().is_empty()) else {
        not_assessed(
            out,
            "whether signing out empties the browser's storage was not asked: a sign-in for it \
             gave no cookie to hand to the browser.",
        );
        return;
    };
    let job = Job {
        actions: vec![
            Action::Goto(login.path.clone()),
            Action::Eval(STORAGE_QUESTION.to_owned()),
            Action::SetCookies(session.browser_cookies()),
            Action::Goto(private.clone()),
            Action::Eval(STORAGE_QUESTION.to_owned()),
            Action::Act(sign_out_click(&logout.path)),
            Action::Eval(STORAGE_QUESTION.to_owned()),
            Action::Goto(private.clone()),
        ],
    };
    let Some(a) = http.browser(&job).filter(|a| a.len() == job.actions.len()) else {
        not_assessed(
            out,
            "whether signing out empties the browser's storage was not asked. The browser could \
             not be started, or did not finish what it was given.",
        );
        return;
    };
    if !opened(&a[3], private) {
        let refused = refused_cookies(&a[2]);
        let because = if refused.is_empty() {
            String::new()
        } else {
            format!(
                " Handed the cookies, {}, which may be why.",
                refused_sentence(&refused)
            )
        };
        not_assessed(
            out,
            &format!(
                "{private} did not open in the browser after signing in, so it was never signed \
                 in and there was nothing to sign out of.{because}"
            ),
        );
        return;
    }
    let (Some(anonymous), Some(signed_in), Some(after)) =
        (stored(&a[1]), stored(&a[4]), stored(&a[6]))
    else {
        not_assessed(
            out,
            "the browser's storage could not be read before and after signing out.",
        );
        return;
    };
    if field(&a[5], "found").as_bool() != Some(true) {
        not_assessed(
            out,
            &format!(
                "{private} showed no sign-out control a person could click, so the browser was \
                 not signed out."
            ),
        );
        return;
    }
    if opened(&a[7], private) {
        not_assessed(
            out,
            &format!(
                "after the sign-out control was clicked, {private} still opened in the browser, so \
                 it was not signed out; whether signing out ends a session is asked separately \
                 (V7.4.1)."
            ),
        );
        return;
    }
    // What the app kept for the signed-in person, and which of it is still there.
    let theirs: Vec<&String> = signed_in
        .iter()
        .filter(|k| !anonymous.contains(k))
        .collect();
    let kept: Vec<&str> = theirs
        .iter()
        .filter(|k| after.contains(k))
        .map(|k| k.as_str())
        .collect();
    out.steps.push(format!(
        "in the browser, signed in and opened {private}: the app kept {} in its storage; signed out \
         with its own control: {} left",
        if theirs.is_empty() {
            "nothing".to_owned()
        } else {
            format!("{} item{}", theirs.len(), if theirs.len() == 1 { "" } else { "s" })
        },
        kept.len()
    ));
    if !kept.is_empty() {
        out.findings.push(finding(
            &KEPT_AFTER_SIGN_OUT,
            "Signing out leaves the signed-in person's data in the browser",
            Severity::Medium,
            format!(
                "In a real browser, the app kept {} while signed in on {private}, and after \
                 signing out with its own control {} still there: {}.",
                theirs.len(),
                if kept.len() == 1 {
                    "this one is"
                } else {
                    "these are"
                },
                kept.join(", ")
            ),
        ));
    } else if theirs.is_empty() {
        not_assessed(
            out,
            &format!(
                "the app kept nothing in the browser's storage while signed in on {private}, so \
                 there was nothing for signing out to empty. That is not shown to be true of its \
                 other pages, so it is not credited here."
            ),
        );
    } else {
        out.verified.push(crate::Verified::new(
            KEPT_AFTER_SIGN_OUT.rule_id,
            KEPT_AFTER_SIGN_OUT.requirement_ids,
            format!(
                "{} item{} the app kept in the browser's storage while signed in on {private}, \
                 every one gone after signing out with its own control",
                theirs.len(),
                if theirs.len() == 1 { "" } else { "s" }
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::{ProbeRequest, ProbeResponse};
    use sv_manifest::RequestTemplate;

    /// How the fake browser's app behaves.
    #[derive(Clone, Copy)]
    struct App {
        /// The cookies do not sign the browser in: private pages send it to /login.
        signed_out: bool,
        /// "visible", "hidden", "none", or "unanswered".
        sign_out: &'static str,
        /// "escaped", "raw", "csp", "stripped", "dropped", "refused", "no-box", "unanswered",
        /// "half-answered" (shown as text, but not whether it ran), or "form-signed-out" (the
        /// form's page sends the browser to a sign-in page, which has a box of its own).
        text: &'static str,
        /// There is no browser.
        absent: bool,
        /// The browser stops after this many answers.
        gives_up_after: Option<usize>,
        /// What happens to the browser's storage on signing out: "cleared", "kept" (the
        /// signed-in person's token stays), "nothing" (only a color scheme, kept by everyone,
        /// is ever stored), "no-control" (no sign-out control to click), "still-in" (the private
        /// page still opens afterwards), or "unreadable".
        storage: &'static str,
        /// What the pages try to send to other sites: see `outside_requests`.
        sends: &'static str,
        /// A cookie the browser refuses, as Chromium answers: by name, with its reason. When it is
        /// the session cookie, `sid`, the browser is not signed in.
        refuses: Option<&'static str>,
    }

    impl Default for App {
        fn default() -> Self {
            App {
                signed_out: false,
                sign_out: "visible",
                text: "escaped",
                absent: false,
                gives_up_after: None,
                storage: "cleared",
                sends: "nothing",
                refuses: None,
            }
        }
    }

    /// The fake browser's answer to handing it cookies.
    fn cookies_answer(a: App) -> Value {
        match a.refuses {
            Some(name) => {
                json!({ "refused": [{ "name": name, "why": "Sanitizing cookie failed" }] })
            }
            None => json!({ "refused": [] }),
        }
    }

    /// The test account the pages are signed in as, and what its details look like encoded, worked
    /// out once outside the code under test, so a mistake there cannot agree with itself here.
    fn account() -> Account {
        Account {
            user: "sv-a-1f2e3d@example.test".into(),
            password: "Sv-0123456789ab-aZ9!".into(),
        }
    }
    const EMAIL_SHA256: &str = "8801c30c52e07651f48f42ebcdfa47adc3265d41c83b90e4ee87862699be19d6";
    const PASSWORD_BASE64: &str = "U3YtMDEyMzQ1Njc4OWFiLWFaOSE=";
    const OTHER_EMAIL_SHA256: &str =
        "943a46cf601d39994759063fb2bcf62be6246c445ce1e90085d3b9386032c563";
    const LONG_COOKIE: &str = "s3ss10n-7f6e5d4c3b2a";

    /// The requests the fake browser says the pages tried to send elsewhere, by scenario.
    fn outside_requests(scenario: &str) -> Value {
        let r = |url: &str, page: &str, body: &str, headers: &str| {
            json!({ "url": url, "method": if body.is_empty() { "GET" } else { "POST" },
                    "type": "Other", "page": page, "body": body, "headers": headers })
        };
        let requests = match scenario {
            "nothing" => vec![],
            "unanswered" => return json!({}),
            "hosts-only" => vec![
                r(
                    "https://cdn.tracker.example/t.js",
                    "/account",
                    "",
                    "accept: */*",
                ),
                r(
                    "https://fonts.example/css?family=Inter",
                    "/settings",
                    "",
                    "",
                ),
            ],
            "email-pixel" => vec![r(
                "https://pixel.tracker.example/p.gif?ev=view&em=sv-a-1f2e3d%40example.test",
                "/account",
                "",
                "",
            )],
            "email-upper" => vec![r(
                "https://collect.example/e",
                "/settings",
                r#"{"user":"SV-A-1F2E3D@Example.Test"}"#,
                "content-type: application/json",
            )],
            "email-hash" => vec![r(
                "https://ads.example/tr",
                "/account",
                &format!(r#"{{"ud":{{"em":"{EMAIL_SHA256}"}}}}"#),
                "",
            )],
            "password-base64" => vec![r(
                "https://collect.example/e",
                "/account",
                &format!("d={PASSWORD_BASE64}"),
                "",
            )],
            "cookie" => vec![r(
                "https://errors.example/report",
                "/settings",
                "",
                &format!("x-session: {LONG_COOKIE}"),
            )],
            "short-cookie" => vec![r("https://errors.example/report?s=abc", "/account", "", "")],
            "someone-else" => vec![r(
                "https://ads.example/tr",
                "/account",
                &format!(r#"{{"em":"{OTHER_EMAIL_SHA256}","user":"sv-b-9a8b7c@example.test"}}"#),
                "",
            )],
            other => panic!("no scenario {other}"),
        };
        json!({ "requests": requests })
    }

    struct Fake {
        app: App,
        jobs: Vec<Job>,
    }

    impl Http for Fake {
        fn send(&mut self, _: &ProbeRequest) -> Option<ProbeResponse> {
            None
        }

        fn browser(&mut self, job: &Job) -> Option<Vec<Value>> {
            self.jobs.push(job.clone());
            if self.app.absent {
                return None;
            }
            let a = self.app;
            if job.actions.iter().any(|x| matches!(x, Action::Act(_))) {
                let mut out = sign_out_job(a, job);
                if let Some(n) = a.gives_up_after {
                    out.truncate(n);
                }
                return Some(out);
            }
            let mut out: Vec<Value> = job
                .actions
                .iter()
                .map(|action| match action {
                    Action::Goto(_) if a.signed_out || a.refuses == Some("sid") => {
                        json!({ "status": 200, "path": "/login" })
                    }
                    Action::Goto(path) => json!({ "status": 200, "path": path }),
                    Action::Fill { page, .. } => {
                        let (found, status) = match a.text {
                            "no-box" => (false, 0),
                            "refused" => (true, 403),
                            _ => (true, 200),
                        };
                        let page = if a.text == "form-signed-out" {
                            "/login"
                        } else {
                            page
                        };
                        json!({ "status": 200, "path": page, "found": found,
                                "after": { "status": status, "path": "/notes/1" } })
                    }
                    Action::Eval(e) if e.contains("controls") => {
                        json!({ "value": match a.sign_out {
                            "visible" => json!({ "controls": 1, "visible": true }),
                            "hidden" => json!({ "controls": 1, "visible": false }),
                            "none" => json!({ "controls": 0, "visible": false }),
                            _ => Value::Null,
                        }})
                    }
                    Action::Eval(_) => {
                        let (ran, element, as_text, present) = match a.text {
                            "escaped" | "form-signed-out" => (false, false, true, true),
                            "half-answered" => {
                                return json!({ "value": { "as_text": true, "present": true } });
                            }
                            "raw" => (true, true, false, true),
                            "csp" => (false, true, false, true),
                            "stripped" => (false, false, false, true),
                            "dropped" => (false, false, false, false),
                            _ => return json!({ "value": null }),
                        };
                        json!({ "value": { "ran": ran, "element": element,
                                           "as_text": as_text, "present": present } })
                    }
                    Action::SetCookies(_) => cookies_answer(a),
                    Action::Wait(_) | Action::Act(_) => json!({}),
                    Action::Outside => outside_requests(a.sends),
                })
                .collect();
            if let Some(n) = a.gives_up_after {
                out.truncate(n);
            }
            Some(out)
        }
    }

    /// The fake browser, for the sign-out job: what its storage holds at each of the three looks.
    fn sign_out_job(a: App, job: &Job) -> Vec<Value> {
        let mut looks = 0;
        let mut clicked = false;
        let mut signed = false;
        job.actions
            .iter()
            .map(|action| match action {
                Action::SetCookies(c) => {
                    signed = !c.is_empty() && !a.signed_out && a.refuses != Some("sid");
                    cookies_answer(a)
                }
                Action::Goto(path) => {
                    let open = signed && !(clicked && a.storage != "still-in");
                    let at = if path == "/login" || open {
                        path.as_str()
                    } else {
                        "/login"
                    };
                    json!({ "status": 200, "path": at })
                }
                Action::Act(_) => {
                    let found = a.storage != "no-control";
                    clicked = found;
                    json!({ "found": found, "after": { "status": 200, "path": "/" } })
                }
                Action::Eval(_) => {
                    looks += 1;
                    if a.storage == "unreadable" {
                        return json!({ "value": null });
                    }
                    let mut local = vec!["theme"];
                    let theirs = a.storage != "nothing";
                    let after_kept = a.storage == "kept" || a.storage == "still-in";
                    if theirs && (looks == 2 || (looks == 3 && after_kept)) {
                        local.push("token");
                    }
                    json!({ "value": { "local": local, "session": [], "indexeddb": [] } })
                }
                _ => json!({}),
            })
            .collect()
    }

    fn run_sign_out(app: App) -> (Outcome, Vec<Job>) {
        let mut fake = Fake {
            app,
            jobs: Vec::new(),
        };
        let mut out = Outcome::default();
        sign_out_check(&mut fake, &users(None, None), Some(&signed_in()), &mut out);
        (out, fake.jobs)
    }

    #[test]
    fn signing_out_that_empties_what_was_kept_for_the_person_is_credited() {
        let (o, jobs) = run_sign_out(App::default());
        assert!(o.findings.is_empty(), "{:?}", o.findings);
        assert_eq!(credited(&o), vec![KEPT_AFTER_SIGN_OUT.rule_id]);
        // The anonymous look comes before any cookie, and the job starts with none.
        assert_eq!(jobs[0].actions[0], Action::Goto("/login".into()));
        assert!(
            !jobs[0].actions[..2]
                .iter()
                .any(|a| matches!(a, Action::SetCookies(_)))
        );
        assert!(matches!(jobs[0].actions[2], Action::SetCookies(_)));
    }

    #[test]
    fn what_the_signed_in_person_leaves_behind_is_a_finding_and_a_color_scheme_is_not() {
        let (o, _) = run_sign_out(App {
            storage: "kept",
            ..Default::default()
        });
        assert_eq!(
            found(&o),
            vec![(KEPT_AFTER_SIGN_OUT.rule_id, Severity::Medium)]
        );
        let text = &o.findings[0].description;
        assert!(text.contains("local: token"), "{text}");
        assert!(!text.contains("theme"), "{text}");
    }

    #[test]
    fn an_app_that_keeps_nothing_for_the_person_is_not_credited_from_one_page() {
        let (o, _) = run_sign_out(App {
            storage: "nothing",
            ..Default::default()
        });
        assert!(o.findings.is_empty() && o.verified.is_empty());
        assert!(unassessed(&o, "V14.3.1").unwrap().contains("kept nothing"));
    }

    #[test]
    fn nothing_is_said_about_storage_unless_the_browser_really_signed_in_and_out() {
        for (app, says) in [
            (
                App {
                    signed_out: true,
                    storage: "kept",
                    ..Default::default()
                },
                "never signed in",
            ),
            (
                App {
                    storage: "no-control",
                    ..Default::default()
                },
                "no sign-out control",
            ),
            (
                App {
                    storage: "still-in",
                    ..Default::default()
                },
                "still opened",
            ),
            (
                App {
                    storage: "unreadable",
                    ..Default::default()
                },
                "could not be read",
            ),
            (
                App {
                    storage: "kept",
                    gives_up_after: Some(7),
                    ..Default::default()
                },
                "did not finish",
            ),
            (
                App {
                    absent: true,
                    ..Default::default()
                },
                "did not finish",
            ),
        ] {
            let (o, _) = run_sign_out(app);
            assert!(o.findings.is_empty(), "{says}: {:?}", o.findings);
            assert!(o.verified.is_empty(), "{says}");
            let why = unassessed(&o, "V14.3.1").unwrap_or_default();
            assert!(why.contains(says), "{says}: {why}");
        }
        // And without a sign-in of its own to hand over, the browser is not even started.
        let mut fake = Fake {
            app: App::default(),
            jobs: Vec::new(),
        };
        let mut o = Outcome::default();
        sign_out_check(&mut fake, &users(None, None), None, &mut o);
        assert!(fake.jobs.is_empty());
        assert!(unassessed(&o, "V14.3.1").unwrap().contains("no cookie"));
    }

    fn users(text_form: Option<&str>, shows: Option<&str>) -> UsersSection {
        UsersSection {
            login: Some(RequestTemplate {
                method: "POST".into(),
                path: "/login".into(),
                form: Default::default(),
                json: Default::default(),
            }),
            logout: Some(RequestTemplate {
                method: "POST".into(),
                path: "/logout".into(),
                form: Default::default(),
                json: Default::default(),
            }),
            private: vec!["/account".into(), "/settings".into()],
            browser: Some(BrowserSection {
                text_form: text_form.map(str::to_owned),
                shows: shows.map(str::to_owned),
            }),
            ..Default::default()
        }
    }

    fn signed_in() -> Session {
        let mut s = Session::default();
        s.absorb(&ProbeResponse {
            id: String::new(),
            status: 200,
            headers: vec![("set-cookie".into(), "sid=abc; Path=/; HttpOnly".into())],
            body: String::new(),
        });
        s
    }

    fn run_on(app: App, users: &UsersSection) -> (Outcome, Vec<Job>) {
        let mut fake = Fake {
            app,
            jobs: Vec::new(),
        };
        let mut out = Outcome::default();
        checks(
            &mut fake,
            users,
            &signed_in(),
            &account(),
            true,
            "t0k",
            &mut out,
        );
        (out, fake.jobs)
    }

    fn run(app: App) -> Outcome {
        run_on(app, &users(Some("/notes"), None)).0
    }

    fn found(o: &Outcome) -> Vec<(&str, Severity)> {
        o.findings
            .iter()
            .map(|f| (f.rule_id.as_str(), f.severity))
            .collect()
    }

    fn credited(o: &Outcome) -> Vec<&str> {
        o.verified.iter().map(|v| v.check_id.as_str()).collect()
    }

    fn unassessed(o: &Outcome, id: &str) -> Option<String> {
        o.not_assessed
            .iter()
            .find(|(ids, _)| ids.split(", ").any(|i| i == id))
            .map(|(_, why)| why.clone())
    }

    #[test]
    fn an_app_that_shows_text_as_text_and_its_sign_out_is_credited_for_both() {
        let o = run(App::default());
        assert!(o.findings.is_empty(), "{:?}", o.findings);
        assert_eq!(
            credited(&o),
            vec![HIDDEN_SIGN_OUT.rule_id, TEXT_AS_MARKUP.rule_id]
        );
    }

    #[test]
    fn typed_markup_that_runs_is_a_high_finding_and_one_a_policy_stopped_is_medium() {
        let o = run(App {
            text: "raw",
            ..Default::default()
        });
        assert_eq!(found(&o), vec![(TEXT_AS_MARKUP.rule_id, Severity::High)]);
        assert!(!credited(&o).contains(&TEXT_AS_MARKUP.rule_id));

        let o = run(App {
            text: "csp",
            ..Default::default()
        });
        assert_eq!(found(&o), vec![(TEXT_AS_MARKUP.rule_id, Severity::Medium)]);
        assert!(!credited(&o).contains(&TEXT_AS_MARKUP.rule_id));
    }

    #[test]
    fn a_sign_out_control_nobody_can_see_is_a_finding_and_a_missing_one_is_left_to_the_html_check()
    {
        let o = run(App {
            sign_out: "hidden",
            ..Default::default()
        });
        assert_eq!(found(&o), vec![(HIDDEN_SIGN_OUT.rule_id, Severity::Low)]);
        assert!(!credited(&o).contains(&HIDDEN_SIGN_OUT.rule_id));

        // No control at all is `probe.no-sign-out-link`'s to say, from the HTML; saying it twice
        // would count one fault as two, and crediting it would be wrong.
        let o = run(App {
            sign_out: "none",
            ..Default::default()
        });
        assert!(found(&o).is_empty(), "{:?}", o.findings);
        assert!(!credited(&o).contains(&HIDDEN_SIGN_OUT.rule_id));
    }

    #[test]
    fn nothing_is_said_when_the_browser_is_not_really_signed_in() {
        let o = run(App {
            signed_out: true,
            text: "raw",
            sign_out: "hidden",
            ..Default::default()
        });
        assert!(o.findings.is_empty(), "{:?}", o.findings);
        assert!(o.verified.is_empty());
        let why = unassessed(&o, "V3.2.2").expect("said why");
        assert!(why.contains("not really signed in"), "{why}");
        assert!(unassessed(&o, "V7.4.4").is_some());
    }

    #[test]
    fn nothing_is_asked_without_a_working_session_a_cookie_or_a_browser() {
        let u = users(Some("/notes"), None);
        // The plain requests could not sign in.
        let mut fake = Fake {
            app: App::default(),
            jobs: Vec::new(),
        };
        let mut o = Outcome::default();
        checks(
            &mut fake,
            &u,
            &signed_in(),
            &account(),
            false,
            "t0k",
            &mut o,
        );
        assert!(fake.jobs.is_empty());
        assert!(o.verified.is_empty() && unassessed(&o, "V3.2.2").is_some());

        // A token in JSON, which a browser cannot be handed.
        let mut o = Outcome::default();
        checks(
            &mut fake,
            &u,
            &Session::default(),
            &account(),
            true,
            "t0k",
            &mut o,
        );
        assert!(fake.jobs.is_empty());
        assert!(unassessed(&o, "V7.4.4").unwrap().contains("no cookie"));

        // No browser, or one that stopped part of the way.
        for app in [
            App {
                absent: true,
                ..Default::default()
            },
            App {
                gives_up_after: Some(3),
                ..Default::default()
            },
        ] {
            let o = run(app);
            assert!(o.verified.is_empty() && o.findings.is_empty());
            assert!(unassessed(&o, "V3.2.2").is_some());
        }
    }

    #[test]
    fn text_that_did_not_come_back_as_typed_is_never_credited() {
        for (text, says) in [
            ("stripped", "V1.3.1"),
            ("dropped", "did not appear"),
            ("refused", "refused"),
            ("no-box", "no form"),
            ("unanswered", "could not be asked"),
            ("half-answered", "could not be asked"),
            ("form-signed-out", "did not open"),
        ] {
            let o = run(App {
                text,
                ..Default::default()
            });
            assert!(!credited(&o).contains(&TEXT_AS_MARKUP.rule_id), "{text}");
            assert!(found(&o).is_empty(), "{text}: {:?}", o.findings);
            let why = unassessed(&o, "V3.2.2").unwrap_or_default();
            assert!(why.contains(says), "{text}: {why}");
            // The sign-out control is still judged.
            assert!(credited(&o).contains(&HIDDEN_SIGN_OUT.rule_id), "{text}");
        }
    }

    #[test]
    fn a_browser_that_stops_part_of_the_way_is_not_taken_at_its_word_on_anything() {
        // The cookies and both private pages answered, then nothing: the sign-out answers are there, but a list
        // shorter than the job means the browser did not finish, and nothing it said is used.
        let o = run(App {
            gives_up_after: Some(5),
            ..Default::default()
        });
        assert!(o.verified.is_empty(), "{:?}", o.verified);
        assert!(o.findings.is_empty());
        assert!(unassessed(&o, "V7.4.4").unwrap().contains("did not finish"));
    }

    #[test]
    fn each_cookie_reaches_the_browser_with_the_attributes_the_app_set_it_with() {
        // family-hub's cookies (3 October 2026): a browser refuses a `__Host-` cookie that is not
        // `Secure`, and the driver used to hand over the name and value alone.
        let mut s = Session::default();
        s.absorb(&ProbeResponse {
            id: String::new(),
            status: 200,
            headers: vec![
                (
                    "set-cookie".into(),
                    "__Host-fh_session=v1; Path=/; Secure; HttpOnly; SameSite=Lax".into(),
                ),
                (
                    "set-cookie".into(),
                    "pref=dark; path=/app; samesite=Strict".into(),
                ),
                // Prefixed, but the app left out what the prefix needs: the browser is handed
                // what the prefix asks for, whatever the app said.
                ("set-cookie".into(), "__Secure-csrf=t".into()),
                ("set-cookie".into(), "__host-lower=1; Path=/app".into()),
                // A path a browser would not take is no path.
                ("set-cookie".into(), "odd=1; Path=app".into()),
                // `Secure` with no prefix to imply it: carried from the header alone.
                ("set-cookie".into(), "tracked=1; secure".into()),
            ],
            body: String::new(),
        });
        let handed: Vec<Value> = s
            .browser_cookies()
            .iter()
            .map(BrowserCookie::to_json)
            .collect();
        assert_eq!(handed.len(), 6, "{handed:?}");
        assert_eq!(
            handed[0],
            json!({ "name": "__Host-fh_session", "value": "v1", "path": "/", "secure": true,
                    "httpOnly": true, "sameSite": "Lax" })
        );
        assert_eq!(
            handed[1],
            json!({ "name": "pref", "value": "dark", "path": "/app", "secure": false,
                    "httpOnly": false, "sameSite": "Strict" })
        );
        assert_eq!(handed[2]["secure"], true, "{handed:?}");
        assert_eq!(handed[3]["secure"], true, "{handed:?}");
        assert_eq!(handed[3]["path"], "/", "{handed:?}");
        assert_eq!(handed[4]["path"], "/", "{handed:?}");
        assert_eq!(handed[5]["secure"], true, "{handed:?}");
        // No Domain is ever carried: the browser reaches the app at localhost.
        assert!(handed.iter().all(|c| c.get("domain").is_none()));

        // A cookie set again keeps only its newest attributes, and one emptied is gone.
        s.absorb(&ProbeResponse {
            id: String::new(),
            status: 200,
            headers: vec![
                ("set-cookie".into(), "pref=light".into()),
                ("set-cookie".into(), "odd=; Max-Age=0".into()),
            ],
            body: String::new(),
        });
        let pref = s
            .browser_cookies()
            .into_iter()
            .find(|c| c.name == "pref")
            .unwrap();
        assert_eq!(pref, BrowserCookie::plain("pref", "light"));
        assert!(!s.browser_cookies().iter().any(|c| c.name == "odd"));
        assert_eq!(s.browser_cookies().len(), s.cookies().len());
    }

    #[test]
    fn a_cookie_the_browser_refuses_is_named_in_the_report() {
        // The session cookie refused: the browser is not signed in, and the reason is said.
        let o = run(App {
            refuses: Some("sid"),
            ..Default::default()
        });
        assert!(o.verified.is_empty() && o.findings.is_empty(), "{o:?}");
        let why = unassessed(&o, "V7.4.4").unwrap();
        assert!(why.contains("not really signed in"), "{why}");
        assert!(
            why.contains("the browser refused the cookie sid (Sanitizing cookie failed)"),
            "{why}"
        );

        // Another cookie refused: the pages still opened, so the checks are made, and the step
        // says which cookie the browser would not keep.
        let o = run(App {
            refuses: Some("big"),
            ..Default::default()
        });
        assert_eq!(
            credited(&o),
            vec![HIDDEN_SIGN_OUT.rule_id, TEXT_AS_MARKUP.rule_id]
        );
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("signed in a real browser")
                    && s.contains("the browser refused the cookie big")),
            "{:?}",
            o.steps
        );
        // Nothing refused, nothing said about refusing.
        let o = run(App::default());
        assert!(!o.steps.iter().any(|s| s.contains("refused the cookie")));

        // The sign-out check says it too.
        let (o, _) = run_sign_out(App {
            refuses: Some("sid"),
            ..Default::default()
        });
        let why = unassessed(&o, "V14.3.1").unwrap();
        assert!(why.contains("never signed in"), "{why}");
        assert!(why.contains("the browser refused the cookie sid"), "{why}");
    }

    #[test]
    fn a_sign_out_control_that_cannot_be_asked_about_is_not_credited() {
        let o = run(App {
            sign_out: "unanswered",
            ..Default::default()
        });
        assert!(!credited(&o).contains(&HIDDEN_SIGN_OUT.rule_id));
        assert!(unassessed(&o, "V7.4.4").is_some());
    }

    #[test]
    fn the_browser_is_asked_only_what_securevibe_toml_names() {
        // No `text-form`: every private page, and nothing typed.
        let (o, jobs) = run_on(App::default(), &users(None, None));
        assert_eq!(credited(&o), vec![HIDDEN_SIGN_OUT.rule_id]);
        assert!(unassessed(&o, "V3.2.2").is_none());
        let actions = &jobs[0].actions;
        // The cookies, with what the app set them with; two pages, each opened and asked about;
        // then what they tried to send elsewhere.
        assert_eq!(actions.len(), 7);
        assert_eq!(
            actions[0],
            Action::SetCookies(vec![BrowserCookie {
                name: "sid".into(),
                value: "abc".into(),
                http_only: true,
                path: Some("/".into()),
                ..Default::default()
            }])
        );
        assert_eq!(actions[5..], [Action::Wait(500), Action::Outside]);
        assert!(!actions.iter().any(|a| matches!(a, Action::Fill { .. })));

        // With `shows`, the text is looked for there, and the report says so.
        let (o, jobs) = run_on(App::default(), &users(Some("/notes/new"), Some("/notes")));
        assert!(jobs[0].actions.contains(&Action::Goto("/notes".into())));
        assert!(
            o.verified
                .iter()
                .any(|v| v.check_id == TEXT_AS_MARKUP.rule_id
                    && v.scope.contains("shown on /notes as the text typed")),
            "{:?}",
            o.verified
        );
    }

    fn sent_elsewhere(o: &Outcome) -> Option<&crate::finding::Finding> {
        o.findings
            .iter()
            .find(|f| f.rule_id == DETAILS_SENT_ELSEWHERE.rule_id)
    }

    #[test]
    fn account_details_sent_to_another_site_are_found_in_every_form_and_never_repeated() {
        let a = account();
        for (scenario, what, severity, host, page) in [
            (
                "email-pixel",
                "its email address, encoded into a web address",
                Severity::Medium,
                "pixel.tracker.example",
                "/account",
            ),
            (
                "email-upper",
                "its email address, as written",
                Severity::Medium,
                "collect.example",
                "/settings",
            ),
            (
                "email-hash",
                "its email address, as a SHA-256 hash",
                Severity::Medium,
                "ads.example",
                "/account",
            ),
            (
                "password-base64",
                "its password, in base64",
                Severity::High,
                "collect.example",
                "/account",
            ),
        ] {
            let o = run(App {
                sends: scenario,
                ..Default::default()
            });
            let f = sent_elsewhere(&o).unwrap_or_else(|| panic!("{scenario}: {:?}", o.findings));
            assert_eq!(f.severity, severity, "{scenario}");
            assert_eq!(f.requirement_ids, vec!["V14.2.3".to_owned()]);
            assert!(
                f.description
                    .contains(&format!("{what}, to {host} from {page}")),
                "{scenario}: {}",
                f.description
            );
            // What was sent is named, never repeated.
            for secret in [
                a.user.as_str(),
                a.password.as_str(),
                EMAIL_SHA256,
                PASSWORD_BASE64.trim_end_matches('='),
                "1f2e3d",
            ] {
                assert!(
                    !f.description
                        .to_lowercase()
                        .contains(&secret.to_lowercase()),
                    "{scenario} repeats what was sent: {}",
                    f.description
                );
            }
        }
    }

    #[test]
    fn a_session_cookie_sent_elsewhere_is_found_when_it_is_long_enough_to_mean_something() {
        let mut session = Session::default();
        session.absorb(&ProbeResponse {
            id: String::new(),
            status: 200,
            headers: vec![(
                "set-cookie".into(),
                format!("sid={LONG_COOKIE}; Path=/; HttpOnly"),
            )],
            body: String::new(),
        });
        let mut fake = Fake {
            app: App {
                sends: "cookie",
                ..Default::default()
            },
            jobs: Vec::new(),
        };
        let mut o = Outcome::default();
        let u = users(Some("/notes"), None);
        checks(&mut fake, &u, &session, &account(), true, "t0k", &mut o);
        let f = sent_elsewhere(&o).expect("the session cookie, sent in a header");
        assert_eq!(f.severity, Severity::High);
        assert!(
            f.description
                .contains("its session cookie, as written, to errors.example")
        );
        assert!(!f.description.contains(LONG_COOKIE));

        // `abc` turns up in addresses by chance, and proves nothing.
        let o = run(App {
            sends: "short-cookie",
            ..Default::default()
        });
        assert!(sent_elsewhere(&o).is_none(), "{:?}", o.findings);
    }

    #[test]
    fn other_sites_reached_without_the_accounts_details_are_listed_and_are_not_a_finding() {
        // The control: the same machinery, fed requests that carry someone else's details.
        let o = run(App {
            sends: "someone-else",
            ..Default::default()
        });
        assert!(sent_elsewhere(&o).is_none(), "{:?}", o.findings);

        let o = run(App {
            sends: "hosts-only",
            ..Default::default()
        });
        assert!(sent_elsewhere(&o).is_none(), "{:?}", o.findings);
        let step = o
            .steps
            .iter()
            .find(|s| s.contains("other site"))
            .expect("the sites are listed");
        assert!(
            step.contains("2 other sites") && step.contains("cdn.tracker.example, fonts.example"),
            "{step}"
        );
        assert!(step.contains("cannot arrive inside the fence"), "{step}");
        // Nothing here is ever credited: not seeing a leak is not the app keeping data in.
        assert!(!credited(&o).contains(&DETAILS_SENT_ELSEWHERE.rule_id));

        let o = run(App::default());
        assert!(
            o.steps
                .iter()
                .any(|s| s.starts_with("no signed-in page tried to reach another site")),
            "{:?}",
            o.steps
        );

        let o = run(App {
            sends: "unanswered",
            ..Default::default()
        });
        assert!(sent_elsewhere(&o).is_none());
        assert!(
            o.steps.iter().any(|s| s.starts_with("could not list")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn web_addresses_and_base64_are_read_as_the_standards_write_them() {
        assert_eq!(readable("a%40b.test+x%2Fy"), "a@b.test x/y");
        // Not an escape, and not the end of the text either: left as it is.
        assert_eq!(readable("50%zz and 7%"), "50%zz and 7%");
        assert_eq!(readable("caf%C3%A9 é%4"), "café é%4");
        assert_eq!(base64(b"foobar", false), "Zm9vYmFy");
        assert_eq!(base64(b"fooba", false), "Zm9vYmE");
        assert_eq!(base64(&[0xfb, 0xff], false), "+/8");
        assert_eq!(base64(&[0xfb, 0xff], true), "-_8");
        assert_eq!(host_of("https://u:p@ads.example:8443/p?x=1"), "ads.example");
        assert_eq!(host_of("wss://live.example/socket"), "live.example");
    }

    #[test]
    fn the_typed_line_carries_its_mark_and_the_mark_is_not_a_piece_of_a_password() {
        let spare = "3f9c0a7e5b1d2468ace13579bdf02468";
        let t = token(spare);
        assert_eq!(t.len(), 16);
        for n in 4..=t.len() {
            assert!(!spare.contains(&t[..n]) || n < 6, "{t}");
        }
        let line = markup_line(&t);
        assert!(line.contains(&format!("data-sv=\"{t}\"")));
        assert!(markup_question(&t).contains(&format!("\"{t}\"")));
    }
}
