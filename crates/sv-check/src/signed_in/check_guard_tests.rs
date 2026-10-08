//! The guard per check (the architecture assessment of 8 October 2026, item 8): every check of the
//! signed-in suite is called through `asked!` or `quiet!`, and one that speaks once it has asked
//! cannot return from asking without naming what it asked about.

use super::*;

/// The body of `run_checks`, where the suite calls its checks.
fn run_checks_source() -> String {
    let source = include_str!("mod.rs");
    let start = source.find("\nfn run_checks(").expect("run_checks");
    let end = source[start..]
        .find("\n}\n")
        .map(|n| start + n)
        .expect("its end");
    source[start..end].to_owned()
}

#[test]
fn every_check_the_suite_calls_is_one_kind_or_the_other() {
    let body = run_checks_source();
    // Setup: the body is the one that calls the checks, and both kinds are in it.
    assert!(
        body.contains("asked!(") && body.contains("quiet!("),
        "{body}"
    );
    // A statement that hands the outcome to a function, not inside either marker.
    let mut bare = Vec::new();
    for statement in body.split(';') {
        let call = statement.trim();
        if !call.contains("&mut out)") && !call.contains("&mut out,\n") {
            continue;
        }
        if call.contains("asked!(") || call.contains("quiet!(") {
            continue;
        }
        // Signing in and its helpers write steps, and are not checks.
        if call.contains("sign_in_again(") || call.contains("fn ") {
            continue;
        }
        bare.push(call.lines().last().unwrap_or_default().trim().to_owned());
    }
    assert!(
        bare.is_empty(),
        "checks called outside `asked!` and `quiet!`: {bare:#?}"
    );
}

#[test]
fn a_check_that_names_what_it_asked_about_is_left_as_it_is() {
    let mut out = Outcome::default();
    let said = Said::mark(&out, 3);
    out.not_assessed
        .push(("V6.4.1".to_owned(), "a reason".to_owned()));
    said.held(&mut out, "a check", &["V6.4.1"], 5);
    assert_eq!(out.not_assessed.len(), 1);
}

#[test]
fn a_check_that_asked_nothing_may_say_nothing() {
    let mut out = Outcome::default();
    let said = Said::mark(&out, 3);
    said.held(&mut out, "a check", &["V6.4.1"], 3);
    assert!(out.not_assessed.is_empty());
}

#[test]
#[should_panic(expected = "asked the app 2 time(s) and returned without naming any of")]
fn a_check_that_asked_and_said_nothing_stops_a_test_build() {
    let mut out = Outcome::default();
    let said = Said::mark(&out, 3);
    // Something about another requirement is not an answer about this one.
    out.not_assessed
        .push(("V7.4.2".to_owned(), "another check's".to_owned()));
    said.held(&mut out, "a check", &["V6.4.1"], 5);
}

#[test]
fn the_connection_counts_what_is_asked_of_the_app_and_nothing_else() {
    struct Nobody;
    impl Http for Nobody {
        fn send(&mut self, _: &ProbeRequest) -> Option<ProbeResponse> {
            None
        }
    }
    let mut inner = Nobody;
    let mut counted = Counted {
        inner: &mut inner,
        asked: 0,
    };
    let request = get("x", "/", &Session::default());
    counted.send(&request);
    counted.send_together(&[request.clone(), request.clone()]);
    counted.mail("a@example.test", 1);
    counted.provider(&request);
    counted.model(&request);
    counted.now();
    assert_eq!(counted.asked, 3);
}
