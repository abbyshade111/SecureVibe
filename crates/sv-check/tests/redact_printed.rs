//! What `sv` masks in text it repeats and did not write (the review of 8 October 2026, item 6):
//! never more than a third of a value, and the names a program's output holds a credential under.
//! The values here are made up, and built from pieces so no file holds one whole.

use sv_check::Secret;
use sv_check::secrets::{SecretRules, redact_text};

fn rules() -> SecretRules {
    SecretRules::load(
        &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/secret-rules.json"),
    )
    .expect("rules load")
}

#[test]
fn a_short_value_shows_at_most_a_third_of_itself() {
    for (value, shown) in [
        ("ab", ""),
        ("abcd", "a"),
        ("abcdefgh", "ab"),
        ("abcdefghijkl", "abcd"),
        ("abcdefghijklmnopqrst", "abcd"),
    ] {
        let redacted = Secret::redact(value);
        let total = value.chars().count();
        assert_eq!(
            redacted.as_str(),
            format!("{shown}… ({} more characters)", total - shown.len()),
            "{value}"
        );
        assert_eq!(redacted.length(), total);
    }
}

#[test]
fn a_credential_under_a_name_a_program_prints_is_masked_and_a_word_inside_another_is_not() {
    let token = ["k3Jx", "9QmW", "zT4v", "Lp8N"].concat();
    for text in [
        format!("Authorization: Bearer {token}"),
        format!("authorization=Basic {token}"),
        format!("Set-Cookie: session={token}; Path=/"),
        format!("x-session-id: {token}"),
        format!("otp_code = \"{token}\""),
        format!("pin: {token}"),
    ] {
        let (out, n) = redact_text(&rules(), &text);
        assert!(n >= 1 && !out.contains(&token[4..]), "{text} -> {out}");
    }
    // The controls: words that hold `pin` and `session` inside them, and no credential.
    for text in [
        format!("spinner: {token}"),
        format!("mapping = {token}"),
        format!("sessions_total: {token}"),
    ] {
        let (out, n) = redact_text(&rules(), &text);
        assert_eq!((n, out.as_str()), (0, text.as_str()), "{text}");
    }
}
