//! The private and admin pages the owner lists (ADR-053, Later, group H): each listed page is
//! asked, so with two or more listed the credit stands for what the requirement asks, and with
//! one listed it is one sample and *checked in part*.

use super::fake_app::*;
use super::*;

/// The checks that ask each private or admin page the owner lists.
const PER_PAGE: [&str; 5] = [
    PRIVATE_PAGE.rule_id,
    ADMIN_PAGE.rule_id,
    PRIVATE_PAGE_CACHING.rule_id,
    PRIVATE_PAGE_HEADERS.rule_id,
    SIGN_OUT_LINK.rule_id,
];

/// `users`, with a second private page and a second admin page. The fake app reads a path without
/// its query, so each second address is a page of its own to the suite and the same to the app.
fn two_of_each() -> UsersSection {
    let mut u = users();
    u.private.push("/account?tab=2".into());
    u.admin.push("/admin?section=2".into());
    u
}

#[test]
fn one_page_listed_is_one_sample_and_credited_in_part() {
    let u = users();
    assert_eq!((u.private.len(), u.admin.len()), (1, 1), "the fixture");
    let o = run_against(Flaws::default(), &u);
    assert!(o.findings.is_empty(), "{:#?}", o.findings);
    for id in PER_PAGE {
        assert!(credited_in_part(&o, id), "{id}: {:#?}", o.verified);
    }
}

#[test]
fn two_pages_listed_are_each_asked_and_credited_in_full() {
    let o = run_against(Flaws::default(), &two_of_each());
    assert!(o.findings.is_empty(), "{:#?}", o.findings);
    // The setup: both pages really were asked and judged, as the scopes count them.
    for id in [PRIVATE_PAGE.rule_id, ADMIN_PAGE.rule_id] {
        let scope = &o
            .verified
            .iter()
            .find(|v| v.check_id == id)
            .unwrap_or_else(|| panic!("{id}: {:?}", o.not_assessed))
            .scope;
        assert!(scope.starts_with("2 "), "{id}: {scope}");
    }
    for id in PER_PAGE {
        assert!(credited_in_full(&o, id), "{id}: {:#?}", o.verified);
    }
    // The checks that rest on one sign-in or one session stay in part however many pages there are.
    for id in [SESSION_COOKIE.rule_id, LOGOUT.rule_id] {
        assert!(credited_in_part(&o, id), "{id}");
    }
}
