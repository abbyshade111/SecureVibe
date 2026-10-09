//! The session cookie a signed-in page sets again (V3.3.2, V3.3.4; backlog 0029, part 3): judged as
//! the one sign-in set, so a page that drops HttpOnly or SameSite is named, and sign-in's credit
//! does not stand beside it. A file of its own rather than the end of `sessions.rs`'s tests, so two
//! branches adding tests do not meet there.

use super::fake_app::*;
use super::*;

fn with_account_cookie(template: &'static str) -> Outcome {
    run_against(
        Flaws {
            account_set_cookie: Some(template),
            ..Flaws::default()
        },
        &users(),
    )
}

fn page_findings(o: &Outcome) -> Vec<&crate::Finding> {
    o.findings
        .iter()
        .filter(|f| f.rule_id == SESSION_COOKIE.rule_id)
        .collect()
}

#[test]
fn the_session_cookie_set_again_without_its_protection_is_named_and_unsays_the_credit() {
    // The control: the same app, setting nothing on the account page, is credited at sign-in.
    let clean = run_against(Flaws::default(), &users());
    assert!(page_findings(&clean).is_empty(), "{:#?}", clean.findings);
    assert!(
        verified_ids(&clean).contains(&SESSION_COOKIE.rule_id),
        "the setup: sign-in's cookie is credited when no page sets it again"
    );

    for (template, missing) in [
        ("sid={sid}; Path=/; SameSite=Lax", "no HttpOnly"),
        ("sid={sid}; Path=/; HttpOnly", "no SameSite"),
        ("sid={sid}; Path=/", "no HttpOnly"),
    ] {
        let o = with_account_cookie(template);
        let found = page_findings(&o);
        assert_eq!(found.len(), 1, "{template}: {:#?}", o.findings);
        assert!(
            found[0].description.contains("/account sets `sid` again")
                && found[0].description.contains(missing),
            "{template}: {}",
            found[0].description
        );
        assert!(
            !verified_ids(&o).contains(&SESSION_COOKIE.rule_id),
            "{template}: sign-in's credit stood beside the finding"
        );
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("set the session cookie again: /account")),
            "{template}: {:?}",
            o.steps
        );
    }
}

#[test]
fn a_page_that_keeps_the_protection_another_cookie_or_a_deletion_says_nothing_against_it() {
    for template in [
        // The session cookie set again with everything sign-in gave it.
        "sid={sid}; Path=/; HttpOnly; SameSite=Lax",
        // Another cookie: it does not carry the session.
        "theme=dark; Path=/",
        // The session cookie deleted, three ways a browser is told to forget one.
        "sid=; Path=/",
        "sid=deleted; Path=/; Max-Age=0",
        "sid=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
    ] {
        let o = with_account_cookie(template);
        assert!(
            page_findings(&o).is_empty(),
            "{template}: {:#?}",
            o.findings
        );
        assert!(
            verified_ids(&o).contains(&SESSION_COOKIE.rule_id),
            "{template}: sign-in's credit was taken away"
        );
    }
}
