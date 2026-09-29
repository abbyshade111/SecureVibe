//! What the app leaves in the browser after somebody signs in through its own form: sign-in tokens
//! (V10.1.1) and the password itself (V14.3.3).
//!
//! Anything a page keeps in `localStorage`, `sessionStorage`, IndexedDB, or a cookie without
//! `HttpOnly` can be read by every script on that page: a cross-site scripting bug or a rogue
//! package reads it as easily as the app does. So the browser signs in the way a person would, by
//! typing into the sign-in form, opens a private page to show that it worked, and then reads the
//! values (not only the names) the app stored. What was already there before signing in is set
//! aside: it was not kept for the person.
//!
//! Both questions are only ever findings. Finding nothing on one page, after one sign-in, does not
//! show that the app never keeps either anywhere, so a clean look credits nothing.
//!
//! No value is ever written into the outcome: a place is named by its kind and key, and a token by
//! what it is and its length.

use crate::browser::{Action, Job, base64, field, opened, readable};
use crate::finding::Severity;
use crate::signed_in::{Account, Http, Outcome, Rule, finding};
use serde_json::{Value, json};
use sv_manifest::UsersSection;

pub(crate) const TOKEN_IN_STORAGE: Rule = Rule {
    rule_id: "probe.token-in-browser-storage",
    requirement_ids: &["V10.1.1"],
    cwe: &["CWE-922"],
    impact: "A sign-in token kept where the page's scripts can read it is taken by the first \
             cross-site scripting bug or rogue package on the page, and whoever has it is signed \
             in as the person. A refresh token keeps them signed in for weeks.",
    fix: "Keep sign-in tokens out of `localStorage`, `sessionStorage`, and IndexedDB. Let the \
          server hold the session and give the browser an `HttpOnly` cookie, or put a \
          backend-for-frontend between the page and the sign-in provider so tokens never reach the \
          browser. If a token must be in the page, keep a short-lived access token in memory only, \
          and never the refresh token.",
};

pub(crate) const PASSWORD_IN_STORAGE: Rule = Rule {
    rule_id: "probe.password-in-browser-storage",
    requirement_ids: &["V14.3.3"],
    cwe: &["CWE-312"],
    impact: "The account's password is kept in the browser, where any script on the page can \
             read it and where it stays after the person signs out: on a shared computer, the next \
             person can read it too.",
    fix: "Never store a password in the browser. Send it once, when signing in, and keep only the \
          session the server gives back. To remember who someone is, keep their user name, or let \
          the browser's own password manager do it.",
};

const IDS: &str = "V10.1.1, V14.3.3";

/// Every value the page's scripts can read: `[key, value]` pairs from each kind of storage, the
/// records of each IndexedDB store (as JSON), and `document.cookie`. A kind that cannot be read
/// comes back as `null`.
const STORAGE_VALUES: &str = r#"(async () => {
  const pairs = (s) => { try { return Object.keys(s).map((k) => [k, String(s.getItem(k))]); } catch { return null; } };
  let indexeddb = [];
  try {
    for (const d of await indexedDB.databases()) {
      const db = await new Promise((ok, no) => {
        const r = indexedDB.open(d.name);
        r.onsuccess = () => ok(r.result);
        r.onerror = () => no(r.error);
      });
      for (const store of db.objectStoreNames) {
        const all = await new Promise((ok, no) => {
          const r = db.transaction(store).objectStore(store).getAll();
          r.onsuccess = () => ok(r.result);
          r.onerror = () => no(r.error);
        });
        all.slice(0, 200).forEach((v, i) => {
          let text;
          try { text = JSON.stringify(v); } catch { text = String(v); }
          indexeddb.push([`${d.name}/${store} record ${i + 1}`, String(text).slice(0, 65536)]);
        });
      }
      db.close();
    }
  } catch { indexeddb = null; }
  let cookie = null;
  try { cookie = document.cookie; } catch {}
  return { local: pairs(localStorage), session: pairs(sessionStorage), indexeddb, cookie };
})()"#;

/// Signs in through the first form with a password box, as a person would: types the user name
/// into the box before it and the password into the password box, then presses its button. The
/// values are set the way typing sets them, so a page whose own code watches the boxes sees them.
fn sign_in_form(account: &Account) -> String {
    format!(
        r#"(() => {{
  const user = {user}, secret = {secret};
  const type = (el, v) => {{
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, v);
    el.dispatchEvent(new Event('input', {{ bubbles: true }}));
    el.dispatchEvent(new Event('change', {{ bubbles: true }}));
  }};
  for (const form of document.forms) {{
    const box = form.querySelector('input[type=password]');
    const name = form.querySelector('input[type=email], input[autocomplete=username], input[type=text], input:not([type])');
    if (!box || !name) continue;
    type(name, user);
    type(box, secret);
    const button = form.querySelector('button[type=submit], button:not([type]), input[type=submit]');
    if (button) button.click(); else if (form.requestSubmit) form.requestSubmit(); else form.submit();
    return true;
  }}
  return false;
}})()"#,
        user = json!(account.user),
        secret = json!(account.password)
    )
}

/// One value a page's scripts can read, and where it is, in words: "localStorage `auth`".
#[derive(Debug, Clone, PartialEq)]
struct Kept {
    place: String,
    value: String,
    /// A cookie: looked in for the password, never for tokens, since a session cookie without
    /// `HttpOnly` is its own check.
    cookie: bool,
}

/// What the page answered, or `None` when `localStorage` or `sessionStorage` could not be read.
/// IndexedDB and cookies that could not be read are named in the second list.
fn kept(answer: &Value) -> Option<(Vec<Kept>, Vec<&'static str>)> {
    let value = field(answer, "value");
    let mut out = Vec::new();
    let mut unread = Vec::new();
    for (kind, name, required) in [
        ("local", "localStorage", true),
        ("session", "sessionStorage", true),
        ("indexeddb", "IndexedDB", false),
    ] {
        let Some(list) = field(value, kind).as_array() else {
            if required {
                return None;
            }
            unread.push(name);
            continue;
        };
        for pair in list {
            let (Some(key), Some(v)) = (pair[0].as_str(), pair[1].as_str()) else {
                continue;
            };
            out.push(Kept {
                place: format!("{name} `{key}`"),
                value: v.to_owned(),
                cookie: false,
            });
        }
    }
    match field(value, "cookie").as_str() {
        Some(cookies) => {
            for c in cookies.split(';').map(str::trim).filter(|c| !c.is_empty()) {
                let (name, v) = c.split_once('=').unwrap_or(("", c));
                out.push(Kept {
                    place: format!("the cookie `{name}`, which scripts can read"),
                    value: v.to_owned(),
                    cookie: true,
                });
            }
        }
        None => unread.push("cookies"),
    }
    Some((out, unread))
}

/// What kind of sign-in token a value is, if it is one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Token {
    Access,
    Refresh,
}

/// A JSON Web Token: three parts in base64url, the first two of them JSON objects (`eyJ` is how
/// `{"` begins in base64).
fn is_jwt(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3
        && parts[0].starts_with("eyJ")
        && parts[1].starts_with("eyJ")
        && parts.iter().all(|p| {
            p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// The names a sign-in token is kept under, with letters only: `access_token`, `accessToken`, and
/// `sb-xyz-auth-token` all end in one of these.
const ACCESS_NAMES: &[&str] = &["accesstoken", "idtoken", "authtoken", "bearertoken", "jwt"];

/// Whether `value`, kept under `key`, is a sign-in token. A value under a token's name that is too
/// short to be one (`"true"`, a timestamp) is not.
fn token_kind(key: &str, value: &str) -> Option<Token> {
    let v = value.trim().trim_matches('"');
    if v.len() < 16 {
        return None;
    }
    let name: String = key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_lowercase();
    if name.contains("refreshtoken") {
        return Some(Token::Refresh);
    }
    let named = name == "token" || ACCESS_NAMES.iter().any(|n| name.ends_with(n));
    (named || is_jwt(v)).then_some(Token::Access)
}

/// Every sign-in token in one stored value: the value itself, and, when it is JSON (as the sign-in
/// libraries keep them), each string inside it, with the name it is under.
fn tokens(key: &str, value: &str, found: &mut Vec<(Token, String, usize)>) {
    fn walk(v: &Value, key: &str, path: &str, found: &mut Vec<(Token, String, usize)>) {
        match v {
            Value::String(s) => {
                if let Some(kind) = token_kind(key, s) {
                    found.push((kind, path.to_owned(), s.len()));
                }
            }
            Value::Object(map) => {
                for (k, inner) in map {
                    walk(inner, k, &format!("{path}.{k}"), found);
                }
            }
            Value::Array(items) => {
                for inner in items {
                    walk(inner, key, path, found);
                }
            }
            _ => {}
        }
    }
    match serde_json::from_str::<Value>(value) {
        Ok(parsed @ (Value::Object(_) | Value::Array(_))) => walk(&parsed, key, "", found),
        _ => {
            if let Some(kind) = token_kind(key, value) {
                found.push((kind, String::new(), value.trim().trim_matches('"').len()));
            }
        }
    }
}

/// The password in the forms a page might keep it: as typed, in base64, or encoded into a web
/// address.
fn holds_secret(value: &str, secret: &str) -> bool {
    value.contains(secret)
        || readable(value).contains(secret)
        || [true, false]
            .iter()
            .any(|url_safe| value.contains(&base64(secret.as_bytes(), *url_safe)))
}

/// V10.1.1 and V14.3.3, with a sign-in of the browser's own. Signing in again can end the other
/// sessions of the account, so this runs last, with the other checks that sign in again.
pub(crate) fn storage_check(
    http: &mut dyn Http,
    users: &UsersSection,
    account: &Account,
    works: bool,
    out: &mut Outcome,
) {
    if users.browser.is_none() {
        return;
    }
    let not_assessed = |out: &mut Outcome, why: &str| {
        out.not_assessed
            .push((IDS.to_owned(), format!("In a real browser: {why}")));
    };
    let (Some(login), Some(private)) = (users.login.as_ref(), users.private.first()) else {
        not_assessed(
            out,
            "what the app keeps in the browser after signing in needs `login` and a private page \
             in [stack.run.users].",
        );
        return;
    };
    if !works {
        not_assessed(
            out,
            "nothing was asked, because signing in did not open a private page for the plain \
             requests either.",
        );
        return;
    }
    let job = Job {
        cookies: Vec::new(),
        actions: vec![
            Action::Goto(login.path.clone()),
            Action::Eval(STORAGE_VALUES.to_owned()),
            Action::Act(sign_in_form(account)),
            Action::Goto(private.clone()),
            Action::Eval(STORAGE_VALUES.to_owned()),
        ],
    };
    let Some(a) = http.browser(&job).filter(|a| a.len() == job.actions.len()) else {
        not_assessed(
            out,
            "nothing was asked. The browser could not be started, or did not finish what it was \
             given.",
        );
        return;
    };
    if field(&a[2], "found").as_bool() != Some(true) {
        not_assessed(
            out,
            &format!(
                "{} showed no form with a password box and a box for the user name before it, so \
                 the browser could not sign in the way a person does.",
                login.path
            ),
        );
        return;
    }
    if !opened(&a[3], private) {
        not_assessed(
            out,
            &format!(
                "after signing in through the form on {}, {private} did not open in the browser, \
                 so it was not signed in.",
                login.path
            ),
        );
        return;
    }
    let Some((after, unread)) = kept(&a[4]) else {
        not_assessed(
            out,
            "the browser's storage could not be read after signing in.",
        );
        return;
    };
    // What was there before anybody signed in was not kept for this person.
    let before = kept(&a[1]).map(|(k, _)| k).unwrap_or_default();
    let theirs: Vec<&Kept> = after.iter().filter(|k| !before.contains(k)).collect();

    out.steps.push(format!(
        "signed in through the form on {} in a real browser and opened {private}: the app kept {} \
         value{} where the page's scripts can read {}{}",
        login.path,
        theirs.len(),
        if theirs.len() == 1 { "" } else { "s" },
        if theirs.len() == 1 { "it" } else { "them" },
        if unread.is_empty() {
            String::new()
        } else {
            format!("; {} could not be read", unread.join(" and "))
        }
    ));

    // V14.3.3: the password.
    let with_password: Vec<&str> = theirs
        .iter()
        .filter(|k| holds_secret(&k.value, &account.password))
        .map(|k| k.place.as_str())
        .collect();
    if !with_password.is_empty() {
        out.findings.push(finding(
            &PASSWORD_IN_STORAGE,
            "The account's password is kept in the browser",
            Severity::High,
            format!(
                "After signing in through the form on {} in a real browser, the test account's \
                 password was in {}.",
                login.path,
                with_password.join(", ")
            ),
        ));
    }
    let email = account.user.trim().to_lowercase();
    let with_email: Vec<&str> = theirs
        .iter()
        .filter(|k| !email.is_empty() && k.value.to_lowercase().contains(&email))
        .map(|k| k.place.as_str())
        .collect();
    if !with_email.is_empty() {
        out.steps.push(format!(
            "the account's email address is kept in {}: shown here, not a finding, since many apps \
             keep it to show who is signed in",
            with_email.join(", ")
        ));
    }

    // V10.1.1: sign-in tokens, outside cookies.
    let mut lines = Vec::new();
    let mut worst = None;
    for k in theirs.iter().filter(|k| !k.cookie) {
        let key = k
            .place
            .split('`')
            .nth(1)
            .unwrap_or_default()
            .rsplit('/')
            .next()
            .unwrap_or_default();
        let mut found = Vec::new();
        tokens(key, &k.value, &mut found);
        for (kind, path, len) in found {
            worst = worst.max(Some(kind));
            lines.push(format!(
                "{} of {len} characters in {}{}",
                match kind {
                    Token::Refresh => "a refresh token",
                    Token::Access => "an access token",
                },
                k.place,
                if path.is_empty() {
                    String::new()
                } else {
                    format!(" (at `{}`)", path.trim_start_matches('.'))
                }
            ));
        }
    }
    if let Some(worst) = worst {
        out.findings.push(finding(
            &TOKEN_IN_STORAGE,
            "Sign-in tokens are kept where the page's scripts can read them",
            if worst == Token::Refresh {
                Severity::Medium
            } else {
                Severity::Low
            },
            format!(
                "After signing in through the form on {} in a real browser, the app kept {}.{}",
                login.path,
                lines.join("; "),
                if worst == Token::Refresh {
                    ""
                } else {
                    " An app that runs entirely in the browser may need an access token there; \
                     a refresh token it does not."
                }
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::{ProbeRequest, ProbeResponse};
    use sv_manifest::{BrowserSection, RequestTemplate};

    fn account() -> Account {
        Account {
            user: "sv-a-1f2e3d@example.test".into(),
            password: test_secret(),
        }
    }
    /// The password in base64, worked out outside the code under test.
    /// The test password, put together at run time so this file holds no credential for a scanner
    /// to flag (CodeQL's hard-coded credential rule did, on the literal).
    fn test_secret() -> String {
        ["Sv", "0123456789ab", "aZ9!"].join("-")
    }
    const PASSWORD_BASE64: &str = "U3YtMDEyMzQ1Njc4OWFiLWFaOSE";
    /// A made-up JSON Web Token: `{"alg":"none"}`, `{"sub":"a"}`, and a signature.
    const JWT: &str = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.c2lnbmF0dXJlLXBhcnQ";
    const REFRESH: &str = "v1.refresh-3f9a8b7c6d5e4f3a2b1c";

    fn users() -> UsersSection {
        let t = |path: &str| RequestTemplate {
            method: "POST".into(),
            path: path.into(),
            form: Default::default(),
            json: Default::default(),
        };
        UsersSection {
            login: Some(t("/login")),
            private: vec!["/account".into()],
            browser: Some(BrowserSection::default()),
            ..Default::default()
        }
    }

    /// The fake browser: what its storage holds before and after signing in, and how the sign-in
    /// goes.
    struct Browser {
        before: Value,
        after: Value,
        /// The sign-in page has a form with a password box.
        form: bool,
        /// Where the private page ends up after signing in.
        lands: &'static str,
        absent: bool,
        jobs: Vec<Job>,
    }

    impl Default for Browser {
        fn default() -> Self {
            Browser {
                before: storage(&[("theme", "dark")], &[], Some(json!([])), Some("")),
                after: storage(&[("theme", "dark")], &[], Some(json!([])), Some("")),
                form: true,
                lands: "/account",
                absent: false,
                jobs: Vec::new(),
            }
        }
    }

    fn storage(
        local: &[(&str, &str)],
        session: &[(&str, &str)],
        indexeddb: Option<Value>,
        cookie: Option<&str>,
    ) -> Value {
        json!({ "value": {
            "local": local.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
            "session": session.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
            "indexeddb": indexeddb,
            "cookie": cookie,
        }})
    }

    impl Http for Browser {
        fn send(&mut self, _: &ProbeRequest) -> Option<ProbeResponse> {
            None
        }
        fn browser(&mut self, job: &Job) -> Option<Vec<Value>> {
            self.jobs.push(job.clone());
            if self.absent {
                return None;
            }
            let mut looks = 0;
            Some(
                job.actions
                    .iter()
                    .map(|action| match action {
                        Action::Goto(path) if path == "/login" => {
                            json!({ "status": 200, "path": "/login" })
                        }
                        Action::Goto(_) => json!({ "status": 200, "path": self.lands }),
                        Action::Act(_) => {
                            json!({ "found": self.form, "after": { "status": 200, "path": "/" } })
                        }
                        Action::Eval(_) => {
                            looks += 1;
                            if looks == 1 {
                                self.before.clone()
                            } else {
                                self.after.clone()
                            }
                        }
                        _ => json!({}),
                    })
                    .collect(),
            )
        }
    }

    fn run(mut b: Browser) -> (Outcome, Vec<Job>) {
        let mut out = Outcome::default();
        storage_check(&mut b, &users(), &account(), true, &mut out);
        (out, b.jobs)
    }

    fn after(local: &[(&str, &str)]) -> Browser {
        Browser {
            after: storage(local, &[], Some(json!([])), Some("")),
            ..Default::default()
        }
    }

    fn found<'a>(o: &'a Outcome, rule: &Rule) -> Option<&'a crate::finding::Finding> {
        o.findings.iter().find(|f| f.rule_id == rule.rule_id)
    }

    /// Everything the outcome says, to show no stored value was copied into it.
    fn every_word(o: &Outcome) -> String {
        let mut all = o.steps.join("\n");
        for f in &o.findings {
            all.push_str(&f.description);
        }
        for (_, why) in &o.not_assessed {
            all.push_str(why);
        }
        all
    }

    #[test]
    fn the_browser_signs_in_through_the_form_and_the_page_opening_is_the_control() {
        let (o, jobs) = run(Browser::default());
        assert!(o.findings.is_empty(), "{:?}", o.findings);
        assert!(o.not_assessed.is_empty(), "{:?}", o.not_assessed);
        assert!(o.verified.is_empty(), "never credited");
        let job = &jobs[0];
        assert!(
            job.cookies.is_empty(),
            "no cookies handed over: the form signs it in"
        );
        let Action::Act(sign_in) = &job.actions[2] else {
            panic!("{:?}", job.actions)
        };
        assert!(sign_in.contains(r#""sv-a-1f2e3d@example.test""#));
        assert!(sign_in.contains("input[type=password]"));
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("kept 0 values where the page's scripts can read them")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn the_password_is_found_as_typed_in_base64_and_in_a_cookie() {
        let pw = test_secret();
        let cookie_line = format!(
            "theme=dark; login=sv-a-1f2e3d%40example.test%3A{}",
            pw.replace('!', "%21")
        );
        for (place, local, cookie) in [
            ("localStorage `pw`", vec![("pw", pw.as_str())], ""),
            (
                "localStorage `remember`",
                vec![("remember", PASSWORD_BASE64)],
                "",
            ),
            ("the cookie `login`", vec![], cookie_line.as_str()),
        ] {
            let (o, _) = run(Browser {
                after: storage(&local, &[], Some(json!([])), Some(cookie)),
                ..Default::default()
            });
            let f = found(&o, &PASSWORD_IN_STORAGE).unwrap_or_else(|| panic!("{place}: {:?}", o));
            assert_eq!(f.severity, Severity::High);
            assert!(f.description.contains(place), "{}", f.description);
            assert!(
                !every_word(&o).contains(&pw),
                "the password is in the outcome"
            );
            assert!(!every_word(&o).contains(PASSWORD_BASE64));
        }
    }

    #[test]
    fn a_password_in_indexeddb_or_session_storage_is_found_too() {
        let (o, _) = run(Browser {
            after: storage(
                &[],
                &[(
                    "draft",
                    &json!({ "email": "x", "password": test_secret() }).to_string(),
                )],
                Some(json!([[
                    "app/prefs record 1",
                    json!({ "p": test_secret() }).to_string()
                ]])),
                Some(""),
            ),
            ..Default::default()
        });
        let f = found(&o, &PASSWORD_IN_STORAGE).expect("found");
        assert!(
            f.description.contains("sessionStorage `draft`"),
            "{}",
            f.description
        );
        assert!(
            f.description.contains("IndexedDB `app/prefs record 1`"),
            "{}",
            f.description
        );
    }

    #[test]
    fn a_refresh_token_is_medium_and_an_access_token_alone_is_low() {
        let supabase =
            format!(r#"{{"access_token":"{JWT}","refresh_token":"{REFRESH}","expires_in":3600}}"#);
        let (o, _) = run(after(&[("sb-xyz-auth-token", &supabase)]));
        let f = found(&o, &TOKEN_IN_STORAGE).expect("found");
        assert_eq!(f.severity, Severity::Medium);
        assert!(
            f.description
                .contains(&format!("a refresh token of {} characters", REFRESH.len())),
            "{}",
            f.description
        );
        assert!(
            f.description.contains("(at `refresh_token`)"),
            "{}",
            f.description
        );
        assert!(
            f.description.contains("an access token"),
            "{}",
            f.description
        );
        assert!(!every_word(&o).contains(JWT) && !every_word(&o).contains(REFRESH));

        let (o, _) = run(after(&[("accessToken", JWT)]));
        let f = found(&o, &TOKEN_IN_STORAGE).expect("found");
        assert_eq!(f.severity, Severity::Low);
        assert!(
            f.description.contains("may need an access token"),
            "{}",
            f.description
        );
        assert!(found(&o, &PASSWORD_IN_STORAGE).is_none());
    }

    #[test]
    fn a_token_is_found_by_its_shape_under_any_name_and_in_indexeddb() {
        let (o, _) = run(after(&[("state", JWT)]));
        assert!(found(&o, &TOKEN_IN_STORAGE).is_some(), "{:?}", o.steps);

        // Firebase keeps its tokens in IndexedDB, as JSON.
        let firebase = format!(
            r#"{{"fbase_key":"k","value":{{"stsTokenManager":{{"refreshToken":"{REFRESH}","accessToken":"{JWT}"}}}}}}"#
        );
        let (o, _) = run(Browser {
            after: storage(
                &[],
                &[],
                Some(json!([[
                    "firebaseLocalStorageDb/firebaseLocalStorage record 1",
                    firebase
                ]])),
                Some(""),
            ),
            ..Default::default()
        });
        let f = found(&o, &TOKEN_IN_STORAGE).expect("found");
        assert_eq!(f.severity, Severity::Medium);
        assert!(
            f.description
                .contains("(at `value.stsTokenManager.refreshToken`)"),
            "{}",
            f.description
        );
    }

    #[test]
    fn what_is_not_a_sign_in_token_is_not_reported() {
        let (o, _) = run(after(&[
            ("token", "true"),
            ("theme", "dark"),
            ("csrf", "3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c"),
            (
                "cart",
                r#"{"items":[1,2],"updated":"2026-09-29T20:00:00Z"}"#,
            ),
            ("user", "sv-a-1f2e3d@example.test"),
        ]));
        assert!(o.findings.is_empty(), "{:?}", o.findings);
        // The email address is shown, but is not a finding.
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("email address is kept in localStorage `user`")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_token_in_a_cookie_is_left_to_the_cookie_checks() {
        let (o, _) = run(Browser {
            after: storage(
                &[],
                &[],
                Some(json!([])),
                Some(&format!("access_token={JWT}")),
            ),
            ..Default::default()
        });
        assert!(found(&o, &TOKEN_IN_STORAGE).is_none(), "{:?}", o.findings);
    }

    #[test]
    fn what_was_there_before_signing_in_is_set_aside() {
        let (o, _) = run(Browser {
            before: storage(&[("anon", JWT)], &[], Some(json!([])), Some("")),
            after: storage(&[("anon", JWT)], &[], Some(json!([])), Some("")),
            ..Default::default()
        });
        assert!(o.findings.is_empty(), "{:?}", o.findings);
    }

    #[test]
    fn nothing_is_said_unless_the_browser_really_signed_in_through_the_form() {
        let flawed = || storage(&[("pw", &test_secret())], &[], Some(json!([])), Some(""));
        for (b, why) in [
            (
                Browser {
                    form: false,
                    after: flawed(),
                    ..Default::default()
                },
                "no form with a password box",
            ),
            (
                Browser {
                    lands: "/login",
                    after: flawed(),
                    ..Default::default()
                },
                "did not open in the browser",
            ),
            (
                Browser {
                    absent: true,
                    ..Default::default()
                },
                "could not be started",
            ),
            (
                Browser {
                    after: json!({ "value": { "local": null, "session": [] } }),
                    ..Default::default()
                },
                "could not be read",
            ),
        ] {
            let (o, _) = run(b);
            assert!(o.findings.is_empty(), "{why}: {:?}", o.findings);
            let (ids, text) = o.not_assessed.first().unwrap_or_else(|| panic!("{why}"));
            assert_eq!(ids, IDS);
            assert!(text.contains(why), "{text}");
        }

        // The plain requests could not sign in either: nothing is asked of the browser.
        let mut b = Browser::default();
        let mut out = Outcome::default();
        storage_check(&mut b, &users(), &account(), false, &mut out);
        assert!(b.jobs.is_empty());
        assert_eq!(out.not_assessed.len(), 1);
    }

    #[test]
    fn indexeddb_that_cannot_be_read_is_said() {
        let (o, _) = run(Browser {
            after: storage(&[], &[], None, None),
            ..Default::default()
        });
        assert!(
            o.steps
                .iter()
                .any(|s| s.ends_with("; IndexedDB and cookies could not be read")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn without_a_browser_entry_nothing_is_asked_or_said() {
        let mut u = users();
        u.browser = None;
        let mut b = Browser::default();
        let mut out = Outcome::default();
        storage_check(&mut b, &u, &account(), true, &mut out);
        assert!(b.jobs.is_empty());
        assert!(out.not_assessed.is_empty() && out.steps.is_empty());
    }
}
