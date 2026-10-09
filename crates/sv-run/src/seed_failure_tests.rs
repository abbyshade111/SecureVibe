//! A failed seed's words carry no credential into the report, the app's own included (backlog 0226,
//! part 1, item 1). `sv`'s test secrets were already left out by value, before this.

use super::*;

#[test]
fn a_failed_seed_never_carries_the_apps_own_credential_into_the_report() {
    let accounts = crate::new_accounts(false, false);
    // Built from pieces, so this file holds neither.
    let key = ["sk", "ant", "api03", "Zp8Kd3Wq1Ls6Vn0Rt4Yb9Xm2Qc"].join("-");
    let password = ["Qv7r", "Lm2x", "Tz9k"].concat();
    let printed = format!(
        "psycopg.OperationalError: connection to postgres://app:{password}@db:5432/app failed \
         (ANTHROPIC_API_KEY={key})"
    );
    // The setup: the line the seed printed really carries both.
    assert!(first_line(&printed).contains(&key) && first_line(&printed).contains(&password));
    let said = seed_failed(1, &printed, &accounts);
    assert!(!said.contains(&key), "a key reached the report: {said}");
    assert!(
        !said.contains(&password),
        "a password reached the report: {said}"
    );
    // What failed is still said.
    assert!(said.contains("psycopg.OperationalError"), "{said}");
}

#[test]
fn sv_s_own_test_secrets_are_still_named_as_left_out() {
    let accounts = crate::new_accounts(true, false);
    let admin_password = accounts.admin.as_ref().unwrap().password.clone();
    let said = seed_failed(
        1,
        &format!("SV_ADMIN_PASSWORD={admin_password} rejected"),
        &accounts,
    );
    assert!(!said.contains(&admin_password), "{said}");
    assert!(
        said.contains("SV_ADMIN_PASSWORD=[a test secret, left out]"),
        "{said}"
    );
}
