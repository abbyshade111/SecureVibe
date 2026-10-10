//! The stand-ins' records reach `sv` with its test secrets blanked and no mail body (ADR-082).

use super::*;

/// A password and a two-factor secret shaped as `sv`'s are, built at run time.
fn secrets() -> Vec<String> {
    vec![
        ["Sv", "4f1c9a0b2e7d", "aZ9!"].join("-"),
        ["JBSWY3DP", "EHPK3PXP"].concat(),
    ]
}

#[test]
fn a_test_secret_anywhere_in_a_record_is_blanked_before_it_is_read() {
    let s = secrets();
    let raw = format!(
        r#"{{"seen":[{{"tag":"ab12","system":"log in with {} then","tool_result":"totp {}"}}],"fetched":[]}}"#,
        s[0], s[1]
    );
    // The setup: both are in what the stand-in handed over.
    assert!(raw.contains(&s[0]) && raw.contains(&s[1]));
    let value = read_json(&raw, &s).expect("the record parses with the blanks in it");
    let kept = value.to_string();
    for secret in &s {
        assert!(!kept.contains(secret.as_str()), "{kept}");
    }
    assert_eq!(kept.matches(TEST_SECRET).count(), 2, "{kept}");
    // The rest of what arrived is still there.
    assert!(
        kept.contains("log in with") && kept.contains("ab12"),
        "{kept}"
    );
}

#[test]
fn a_secret_that_holds_another_is_blanked_whole() {
    let long = ["Sv", "abcdef012345", "aZ9!"].join("-");
    let short = "abcdef012345".to_owned();
    let out = without_test_secrets(&format!("x {long} y"), &[short, long.clone()]);
    assert_eq!(out, format!("x {TEST_SECRET} y"));
}

#[test]
fn mail_is_kept_as_who_it_was_to_its_subject_and_when_never_its_body() {
    let code = ["48", "29", "13"].concat();
    let listing = format!(
        r#"{{"messages":[
            {{"ID":"2","To":[{{"Address":"sv-b-0a1b2c@example.test"}}],"Bcc":[{{"Address":"sv-bcc-9@example.test"}}],
              "Subject":"Your code is {code}","Created":"2026-10-10T03:00:02Z","Snippet":"Use {code} within ten minutes"}},
            {{"ID":"1","To":[{{"Address":"sv-a-0a1b2c@example.test"}}],
              "Subject":"Reset your password: http://app:8000/reset?token=Zq8","Created":"2026-10-10T03:00:01Z"}}
        ]}}"#
    );
    let mail = mail_of(&listing, &[]).expect("the listing parses");
    assert_eq!(mail.len(), 2);
    // Oldest first.
    assert_eq!(mail[0].to, ["sv-a-0a1b2c@example.test"]);
    assert_eq!(mail[0].subject, "Reset your password: [left out]");
    assert_eq!(
        mail[1].to,
        ["sv-b-0a1b2c@example.test", "sv-bcc-9@example.test"]
    );
    assert_eq!(mail[1].subject, "Your code is [left out]");
    assert_eq!(mail[1].at, "2026-10-10T03:00:02Z");
    let kept = format!("{mail:?}");
    assert!(
        !kept.contains(&code) && !kept.contains("Zq8") && !kept.contains("within"),
        "{kept}"
    );
}

#[test]
fn a_subject_keeps_short_numbers_and_everything_else() {
    assert_eq!(without_codes("Welcome to Notes 2"), "Welcome to Notes 2");
    assert_eq!(without_codes("Code: 1234."), "Code: [left out].");
    assert_eq!(without_codes("Order 12 of 2026"), "Order 12 of [left out]");
}

#[test]
fn a_test_secret_in_the_kept_log_is_blanked() {
    let s = secrets();
    let mut asked = sv_check::signed_in::Outcome {
        log_lines: vec![sv_check::logs::KeptLine {
            read_for: "the successful sign-in (V16.3.1)".to_owned(),
            line: format!("login ok user=sv-a password={}", s[0]),
        }],
        log_tail: vec![format!("totp seed {}", s[1]), "listening".to_owned()],
        ..Default::default()
    };
    blank_log(&mut asked, &s);
    let kept = format!("{asked:?}");
    for secret in &s {
        assert!(!kept.contains(secret.as_str()), "{kept}");
    }
    assert_eq!(
        asked.log_lines[0].line,
        format!("login ok user=sv-a password={TEST_SECRET}")
    );
    assert_eq!(asked.log_tail[1], "listening");
}
