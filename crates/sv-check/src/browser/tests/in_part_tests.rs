//! The sign-out control drawn on each private page the owner lists (ADR-053, Later, group H): in
//! part with one page listed, whole with two.

use super::*;

fn sign_out_credits(o: &Outcome) -> Vec<&crate::Verified> {
    o.verified
        .iter()
        .filter(|v| v.check_id == HIDDEN_SIGN_OUT.rule_id)
        .collect()
}

#[test]
fn a_sign_out_control_seen_on_the_one_listed_page_is_credited_in_part() {
    let mut one = users(None, None);
    one.private.truncate(1);
    let (o, _) = run_on(App::default(), &one);
    let credits = sign_out_credits(&o);
    assert_eq!(credits.len(), 1, "{:?} {:?}", o.steps, o.not_assessed);
    assert!(credits[0].scope.starts_with("1 private page,"), "{}", credits[0].scope);
    assert!(credits[0].in_part, "{:?}", credits[0]);
}

#[test]
fn a_sign_out_control_seen_on_both_listed_pages_is_credited_in_full() {
    let two = users(None, None);
    assert_eq!(two.private.len(), 2, "the fixture");
    let (o, _) = run_on(App::default(), &two);
    let credits = sign_out_credits(&o);
    assert_eq!(credits.len(), 1, "{:?} {:?}", o.steps, o.not_assessed);
    assert!(credits[0].scope.starts_with("2 private pages,"), "{}", credits[0].scope);
    assert!(!credits[0].in_part, "{:?}", credits[0]);
}
