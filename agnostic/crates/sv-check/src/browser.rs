//! Checks made in a real browser, signed in as the first test user.
//!
//! Some questions have an answer only once a page is drawn: whether a sign-out control that is in
//! the HTML can actually be seen (V7.4.4), and whether text somebody typed is shown as text or drawn
//! as markup and run (V3.2.2). A request and its response cannot tell; a browser can. The run starts
//! a headless Chromium on the fenced network when securevibe.toml has `[stack.run.users.browser]`,
//! and this module says what to do in it and what the answers mean.
//!
//! Nothing is credited unless the browser was really signed in: each private page has to open in it
//! as it did for the plain requests, or the checks here say why they were not made.

use crate::finding::Severity;
use crate::signed_in::{Http, Outcome, Rule, Session, finding};
use serde_json::{Value, json};
use sv_manifest::{BrowserSection, UsersSection};

/// One visit to the browser: the cookies it starts with, and what it is asked to do, in order.
#[derive(Debug, Clone, PartialEq)]
pub struct Job {
    pub cookies: Vec<(String, String)>,
    pub actions: Vec<Action>,
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
    /// Sets cookies for the app partway through, as the job's own are set at its start: `{}`.
    SetCookies(Vec<(String, String)>),
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
            Action::SetCookies(cookies) => json!({ "cookies": cookies }),
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
fn markup_question(token: &str) -> String {
    format!(
        r#"(() => {{
  const t = {t};
  return {{
    ran: window['sv_' + t] === 1,
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
fn markup_line(token: &str) -> String {
    format!(
        "sv-{token} \"'><img src=x data-sv=\"{token}\" onerror=\"window.sv_{token}=1\"><b data-sv-b=\"{token}\">sv</b>"
    )
}

fn field<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or(&Value::Null)
}

fn opened(v: &Value, path: &str) -> bool {
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

    // Every private page, and after them the form and the page that shows what was typed.
    let mut actions: Vec<Action> = Vec::new();
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
    let job = Job {
        cookies: session.cookies().to_vec(),
        actions,
    };
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
    let mut answers = answers.into_iter();
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
        not_made(
            out,
            &format!(
                "the private page{} did not open in the browser with the first user's cookies, \
                 though {} for the plain requests, so the browser was not really signed in.",
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
        "signed in a real browser with the first user's cookies: {} private page{} opened in it",
        pages.len(),
        if pages.len() == 1 { "" } else { "s" }
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
        cookies: Vec::new(),
        actions: vec![
            Action::Goto(login.path.clone()),
            Action::Eval(STORAGE_QUESTION.to_owned()),
            Action::SetCookies(session.cookies().to_vec()),
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
        not_assessed(
            out,
            &format!(
                "{private} did not open in the browser after signing in, so it was never signed \
                 in and there was nothing to sign out of."
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
            }
        }
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
                    Action::Goto(path) if a.signed_out => {
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
                    Action::Wait(_) | Action::Act(_) | Action::SetCookies(_) => json!({}),
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
                    signed = !c.is_empty() && !a.signed_out;
                    json!({})
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
        assert!(jobs[0].cookies.is_empty());
        assert_eq!(jobs[0].actions[0], Action::Goto("/login".into()));
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
        checks(&mut fake, users, &signed_in(), true, "t0k", &mut out);
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
        checks(&mut fake, &u, &signed_in(), false, "t0k", &mut o);
        assert!(fake.jobs.is_empty());
        assert!(o.verified.is_empty() && unassessed(&o, "V3.2.2").is_some());

        // A token in JSON, which a browser cannot be handed.
        let mut o = Outcome::default();
        checks(&mut fake, &u, &Session::default(), true, "t0k", &mut o);
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
        // Both private pages answered, then nothing: the sign-out answers are there, but a list
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
        assert_eq!(actions.len(), 4);
        assert!(!actions.iter().any(|a| matches!(a, Action::Fill { .. })));
        assert_eq!(jobs[0].cookies, vec![("sid".to_owned(), "abc".to_owned())]);

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
