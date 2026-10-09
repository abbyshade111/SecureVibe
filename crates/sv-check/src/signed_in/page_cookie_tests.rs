//! The session cookie when a signed-in page sets it again (the running-app review of 3 October 2026,
//! part 3): judged as at sign-in, since a browser keeps whichever it was given last.

use super::fake_app::*;
use super::*;

fn page_findings(o: &Outcome) -> Vec<&str> {
    o.findings
        .iter()
        .filter(|f| f.rule_id == SESSION_COOKIE.rule_id && f.title.contains("signed-in page"))
        .map(|f| f.description.as_str())
        .collect()
}

#[test]
fn a_page_that_sets_the_session_again_without_its_attributes_is_found() {
    let clean = run_against(Flaws::default(), &users());
    let o = run_against(
        Flaws {
            private_page_sets_session_bare: true,
            ..Default::default()
        },
        &users(),
    );
    let found = page_findings(&o);
    assert_eq!(found.len(), 1, "{:#?}", o.findings);
    assert!(
        found[0].starts_with("/account sets `sid` again without HttpOnly or SameSite"),
        "{}",
        found[0]
    );
    // Nothing else moves: the same rules found and credited as on the correct app, this finding
    // aside. Sign-in's own credit stands, scoped to sign-in; the finding outranks it in the report.
    let mut before = rule_ids(&clean);
    let mut after: Vec<&str> = o
        .findings
        .iter()
        .filter(|f| !f.title.contains("signed-in page"))
        .map(|f| f.rule_id.as_str())
        .collect();
    before.sort();
    after.sort();
    assert_eq!(after, before);
    let (mut a, mut b) = (verified_ids(&clean), verified_ids(&o));
    a.sort();
    b.sort();
    assert_eq!(b, a);
}

#[test]
fn a_page_that_sets_the_session_again_with_its_attributes_is_said_and_not_found() {
    let o = run_against(
        Flaws {
            private_page_sets_session: true,
            ..Default::default()
        },
        &users(),
    );
    assert!(page_findings(&o).is_empty(), "{:#?}", o.findings);
    assert!(
        o.steps.iter().any(|s| s
            == "the session cookie, set again by /account (`sid`), kept HttpOnly and SameSite"),
        "{:#?}",
        o.steps
    );
    // Setup: the correct app sets it nowhere but sign-in, and the step is not said there.
    let clean = run_against(Flaws::default(), &users());
    assert!(!clean.steps.iter().any(|s| s.contains("set again by")));
}

#[test]
fn a_cookie_not_shown_to_carry_the_session_is_not_judged_on_a_guess() {
    // The same signed-in session and the same page, which sets `sid` again with nothing but a
    // path; only what was shown about which cookie carries the session differs.
    let judged = |carried: Option<bool>| judged_on_a_page_that(carried, bare());
    assert_eq!(judged(Some(true)), 1, "shown to carry the session: judged");
    assert_eq!(judged(Some(false)), 0, "shown not to: not the session");
    assert_eq!(
        judged(None),
        0,
        "not shown either way: not judged on a guess"
    );
}

fn bare() -> Flaws {
    Flaws {
        private_page_sets_session_bare: true,
        ..Default::default()
    }
}

/// How many pages `private_page_checks` finds setting the session cookie again unprotected, with
/// a session signed in afresh against an app with `flaws`, and `carried` as what was shown.
fn judged_on_a_page_that(carried: Option<bool>, flaws: Flaws) -> usize {
    let mut app = FakeApp::new(flaws);
    let users = users();
    let accounts = accounts();
    app.users.insert(
        accounts.a.user.clone(),
        (accounts.a.password.clone(), false),
    );
    let mut steps = Vec::new();
    let a = sign_in(&mut app, &users, "a", &accounts.a, &mut steps).expect("signed in");
    // Setup: sign-in set `sid`, the cookie the page sets again.
    assert!(a.set_at_login.iter().any(|c| c.name == "sid"), "{steps:?}");
    let mut out = Outcome::default();
    private_page_checks(&mut app, &users, &a, carried, &mut out);
    page_findings(&out).len()
}

#[test]
fn a_page_that_clears_the_session_cookie_is_not_judged() {
    // An empty value leaves nothing in the browser to protect.
    let cleared = Flaws {
        private_page_clears_session: true,
        ..Default::default()
    };
    assert_eq!(judged_on_a_page_that(Some(true), cleared), 0);
}
