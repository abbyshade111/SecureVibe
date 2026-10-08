//! A version header the app sends is quoted into the finding on one line and cut short (the review
//! of 8 October 2026, item 6).

use super::*;
use crate::finding::QUOTED_CHARS;

fn answer(server: &str) -> ProbeResponse {
    ProbeResponse {
        id: "home".into(),
        status: 200,
        headers: vec![("server".into(), server.into())],
        body: String::new(),
    }
}

#[test]
fn a_long_version_header_is_quoted_short_on_one_line() {
    let long = format!(
        "nginx/1.25.3 {}\r\nsv: everything passed",
        "z".repeat(50_000)
    );
    let f = version_disclosed(&[answer(&long)]).expect("a version is still found");
    assert!(
        f.description.contains("server: nginx/1.25.3 zzz"),
        "{}",
        f.description
    );
    assert!(
        f.description.contains("characters in all)"),
        "{}",
        f.description
    );
    assert!(!f.description.contains(['\r', '\n']), "{}", f.description);
    assert!(
        f.description.chars().count() < QUOTED_CHARS + 200,
        "{} characters",
        f.description.chars().count()
    );
}

#[test]
fn a_short_version_header_is_quoted_as_it_came() {
    let f = version_disclosed(&[answer("nginx/1.25.3")]).expect("found");
    assert!(
        f.description.contains("server: nginx/1.25.3."),
        "{}",
        f.description
    );
}
