//! A role sent with an email change (the gap analysis of 7 October 2026, finding 13(a), on
//! `change-email`): found when an account refused the admin pages is let in after sending it, and
//! recorded as asked, crediting nothing, when it is not.

use super::fake_app::*;
use super::tests::with_signup;
use super::*;

/// Sign-up, an email change, and an admin page, with the admin made from `seed`.
fn users_with_admin() -> UsersSection {
    let mut u = with_signup();
    u.seed = Some("seed".into());
    u.admin = vec!["/admin".into()];
    u
}

fn email_role_finding(o: &Outcome) -> Option<&Finding> {
    o.findings
        .iter()
        .find(|f| f.title == "An account can make itself an admin by changing its email address")
}

#[test]
fn a_role_taken_from_an_email_change_is_found() {
    let o = run_against(
        Flaws {
            email_change_trusts_role: true,
            ..Default::default()
        },
        &users_with_admin(),
    );
    let f = email_role_finding(&o).unwrap_or_else(|| panic!("{:?}", o.steps));
    assert_eq!(f.rule_id, EMAIL_ROLE_FIELD.rule_id);
    assert_eq!(f.requirement_ids, ["V8.3.1", "V15.3.3", "V8.2.3"]);
    assert!(
        f.description
            .starts_with("An account refused /admin sent its email change through /account/email"),
        "{}",
        f.description
    );
    assert!(
        f.description.ends_with("let into /admin."),
        "{}",
        f.description
    );
    // Only this: the sign-up's own role check, and the email change's password check, find nothing.
    assert!(!rule_ids(&o).contains(&ROLE_FIELD.rule_id));
    assert!(!rule_ids(&o).contains(&EMAIL_CHANGE_WITHOUT_PASSWORD.rule_id));
}

#[test]
fn an_email_change_that_ignores_the_role_is_recorded_and_credits_nothing() {
    let o = run_against(Flaws::default(), &users_with_admin());
    assert!(email_role_finding(&o).is_none(), "{:?}", o.findings);
    let asked = o
        .verified
        .iter()
        .find(|v| v.check_id == EMAIL_ROLE_FIELD.rule_id)
        .unwrap_or_else(|| panic!("{:?}", o.steps));
    assert!(
        asked.requirement_ids.is_empty(),
        "{:?}",
        asked.requirement_ids
    );
    // The setup: the account was refused the admin page first, and the change went through.
    assert!(
        o.steps.iter().any(|s| s
            == "an account refused 1 admin page sent its email change with 5 role fields added (303)"),
        "{:?}",
        o.steps
    );
}

#[test]
fn without_change_email_it_is_said_to_be_unasked_and_without_sign_up_nothing_more_is_said() {
    let mut u = users_with_admin();
    u.change_email = None;
    let o = run_against(Flaws::default(), &u);
    assert!(
        o.not_assessed
            .iter()
            .any(|(_, why)| why.contains("role written into the email change")),
        "{:?}",
        o.not_assessed
    );
    // With no sign-up, the sign-up check's own reason covers these requirements: one reason, not two.
    let o = run_against(Flaws::default(), &users());
    assert!(
        !o.not_assessed
            .iter()
            .any(|(_, why)| why.contains("role written into the email change")),
        "{:?}",
        o.not_assessed
    );
    assert!(
        o.not_assessed
            .iter()
            .any(|(_, why)| why.contains("role written into the sign-up form")),
        "{:?}",
        o.not_assessed
    );
}
