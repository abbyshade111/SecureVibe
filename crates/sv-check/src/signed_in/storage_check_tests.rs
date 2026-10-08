//! The browser's storage check, run by the whole suite against a correct app with a browser, the
//! path `examples/notes-with-users` takes in Docker. On 8 October 2026 the check guard (`Said::held`)
//! stopped every debug build there: `storage_check` signed in through the form, read the browser's
//! storage, found nothing kept, and returned with only a step, naming neither V10.1.1 nor V14.3.3.
//! The fake app had no browser, so sv-check's own tests never took that path.

use super::fake_app::{FakeApp, Flaws, run_seeded, users_full};
use sv_manifest::BrowserSection;

#[test]
fn a_clean_look_in_the_browser_says_what_was_looked_at_and_credits_nothing() {
    let mut users = users_full();
    users.browser = Some(BrowserSection::default());
    let mut app = FakeApp::new(Flaws::default());
    app.browser = true;
    let (out, _) = run_seeded(app, &users);

    // Setup: the browser really signed in through the form, opened the private page, and read
    // what the page keeps. Without this the rest could pass on the browser never being reached.
    assert!(
        out.steps
            .iter()
            .any(|s| s.contains("in a real browser and opened /account")
                && s.contains("kept 0 values")),
        "{:#?}",
        out.steps
    );

    let said: Vec<&(String, String)> = out
        .not_assessed
        .iter()
        .filter(|(ids, _)| ids.contains("V10.1.1") || ids.contains("V14.3.3"))
        .collect();
    assert_eq!(said.len(), 1, "{said:#?}");
    let (ids, why) = said[0];
    assert_eq!(ids, "V10.1.1, V14.3.3");
    assert!(
        !why.contains("returned without saying what it found"),
        "the check said it, not the guard: {why}"
    );
    assert!(
        why.contains("/account") && why.contains("credits nothing"),
        "{why}"
    );
    assert!(
        !out.verified.iter().any(|v| v
            .requirement_ids
            .iter()
            .any(|id| id == "V10.1.1" || id == "V14.3.3")),
        "one page after one sign-in is never a pass"
    );
}
