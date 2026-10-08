//! `quoted`: a value from an app's answer, as a finding quotes it.

use super::*;

#[test]
fn a_short_value_is_quoted_as_it_came() {
    assert_eq!(quoted("max-age=31536000"), "max-age=31536000");
    let exactly = "a".repeat(QUOTED_CHARS);
    assert_eq!(quoted(&exactly), exactly);
}

#[test]
fn a_long_value_is_cut_and_says_how_long_it_was() {
    let long = "é".repeat(QUOTED_CHARS + 1);
    let q = quoted(&long);
    // Cut by characters, not bytes, so a letter of two bytes is never split.
    assert!(q.starts_with(&"é".repeat(QUOTED_CHARS)), "{q}");
    assert!(
        q.ends_with(&format!("… ({} characters in all)", QUOTED_CHARS + 1)),
        "{q}"
    );
}

#[test]
fn a_line_break_or_other_control_character_does_not_start_a_line() {
    assert_eq!(
        quoted("/login\r\nsv: all clear\t\u{1b}[2J"),
        "/login  sv: all clear  [2J"
    );
}
