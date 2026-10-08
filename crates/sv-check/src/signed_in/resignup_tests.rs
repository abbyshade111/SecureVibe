//! A second sign-up with an address that already has an account (V6.2.3): the account keeps its
//! password, or the check says that it did not.
//!
//! A file of its own rather than the end of `passwords.rs`'s tests, so two branches adding tests
//! do not meet there.

use super::fake_app::*;
use super::tests::{run_signing_up, with_signup};
use super::*;

#[test]
fn a_sign_up_that_leaves_a_taken_account_alone_is_not_reported() {
    let o = run_signing_up(Flaws::default());
    assert!(!rule_ids(&o).contains(&SIGNUP_REPLACES_ACCOUNT.rule_id));
    assert!(!verified_ids(&o).contains(&SIGNUP_REPLACES_ACCOUNT.rule_id));
    // Setup: the account worked first, and both passwords were tried after the second sign-up.
    assert!(
        o.steps.iter().any(|s| s
            == "signed up again with resignup.a@example.test, which has an account, and another \
                password (303): the new password was refused, the old one still signed in"),
        "{:?}",
        o.steps
    );
}

#[test]
fn a_sign_up_that_takes_a_taken_account_is_found_and_disturbs_nothing_else() {
    let clean = run_signing_up(Flaws::default());
    let o = run_signing_up(Flaws {
        signup_replaces_account: true,
        ..Default::default()
    });
    let f = o
        .findings
        .iter()
        .find(|f| f.rule_id == SIGNUP_REPLACES_ACCOUNT.rule_id)
        .unwrap_or_else(|| panic!("{:?}", o.steps));
    assert_eq!(f.requirement_ids, vec!["V6.2.3".to_owned()]);
    assert!(
        f.description.ends_with("in place of the old one."),
        "{}",
        f.description
    );
    // Every other check sees the same app as before: neither this check nor the one on telling
    // accounts apart may sign up again with A's or B's address, which this app would take.
    let mut before = rule_ids(&clean);
    let mut after: Vec<&str> = rule_ids(&o)
        .into_iter()
        .filter(|id| *id != SIGNUP_REPLACES_ACCOUNT.rule_id)
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
fn an_account_that_never_signs_in_is_not_signed_up_again() {
    // Called alone: a sign-up that does nothing would stop a whole run before it got here.
    let mut app = FakeApp::new(Flaws {
        signup_does_nothing: true,
        signup_replaces_account: true,
        ..Default::default()
    });
    let mut o = Outcome::default();
    signup_replaces_account_check(
        &mut app,
        &with_signup(),
        &accounts(),
        Some("/account"),
        &mut o,
    );
    assert!(!rule_ids(&o).contains(&SIGNUP_REPLACES_ACCOUNT.rule_id));
    assert!(
        o.steps.iter().any(
            |s| s.starts_with("made an account, resignup.a@example.test")
                && s.ends_with("so the second sign-up was not tried")
        ),
        "{:?}",
        o.steps
    );
}

#[test]
fn with_no_sign_up_no_second_sign_up_is_tried() {
    let o = run_against(
        Flaws {
            signup_replaces_account: true,
            ..Default::default()
        },
        &users(),
    );
    assert!(!o.steps.iter().any(|s| s.contains("resignup")));
    assert!(!rule_ids(&o).contains(&SIGNUP_REPLACES_ACCOUNT.rule_id));
}
