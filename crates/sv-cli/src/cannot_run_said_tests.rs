//! The reason a run failed never carries a credential the app printed (backlog 0226, part 1, item 1).

use super::*;
use sv_run::CannotRun;

fn rules() -> SecretRules {
    SecretRules::load(&secret_rules_path()).expect("sv's secret rules load")
}

/// A key, a password, and a crash line that prints both, built from pieces so this file holds neither.
fn planted() -> (String, String, String) {
    let key = ["sk", "ant", "api03", "Zp8Kd3Wq1Ls6Vn0Rt4Yb9Xm2Qc"].join("-");
    let password = ["Qv7r", "Lm2x", "Tz9k"].concat();
    let line = format!(
        "sqlalchemy.exc.OperationalError: could not connect to postgres://app:{password}@db:5432/app \
         (ANTHROPIC_API_KEY={key})"
    );
    (key, password, line)
}

/// Every way a run fails that quotes what the app or the backend printed.
fn every_failure_quoting(text: &str) -> Vec<CannotRun> {
    vec![
        CannotRun::NeverReady {
            waited_seconds: 60,
            detail: format!("It stopped with an error: {text}"),
            loopback: None,
            crashed: true,
        },
        CannotRun::InstallFailed {
            registry: "PyPI",
            detail: format!("it ended with: {text}."),
        },
        CannotRun::BackendFailed {
            detail: text.to_owned(),
        },
        CannotRun::InstallRefused {
            why: text.to_owned(),
        },
    ]
}

#[test]
fn a_credential_the_app_printed_never_reaches_the_reason() {
    let rules = rules();
    let (key, password, line) = planted();
    for why in every_failure_quoting(&line) {
        // The setup: the reason as the run states it really carries both, so their absence below is
        // the redaction's doing.
        let raw = why.explain();
        assert!(raw.contains(&key) && raw.contains(&password), "{raw}");
        let said = said_without_credentials(&raw, why.kind(), Some(&rules));
        assert!(!said.contains(&key), "a key reached the reason: {said}");
        assert!(
            !said.contains(&password),
            "a password reached the reason: {said}"
        );
        // The rest of what the app said is still there, so the reason still says what went wrong.
        assert!(said.contains("OperationalError"), "{said}");
    }
}

#[test]
fn without_the_rules_the_apps_words_are_left_out_whole() {
    let (key, password, line) = planted();
    for why in every_failure_quoting(&line) {
        let said = said_without_credentials(&why.explain(), why.kind(), None);
        assert!(!said.contains(&key) && !said.contains(&password), "{said}");
        assert!(!said.contains("OperationalError"), "{said}");
        assert!(said.contains(why.kind()), "{said}");
    }
}

#[test]
fn the_one_place_every_failure_passes_uses_the_real_rules() {
    let (key, password, line) = planted();
    let why = CannotRun::BackendFailed { detail: line };
    let said = cannot_run_said(&why.explain(), why.kind());
    assert!(!said.contains(&key) && !said.contains(&password), "{said}");
    assert!(said.contains("OperationalError"), "{said}");
}

/// Every failure `probe_the_running_app` returns goes through `cannot_run_said`. Read from the
/// source, because the run's own failures need a container backend to happen: a later call site
/// that hands on `explain()` whole would otherwise pass every test here.
#[test]
fn every_way_out_of_the_run_passes_the_one_place() {
    let source = include_str!("lib.rs");
    let start = source
        .find("pub fn probe_the_running_app(")
        .expect("the function is there");
    let body = &source[start..];
    let body = &body[..body.find("\n}\n").expect("the function ends")];
    // The setup: the function really is where its failures leave, three times.
    assert_eq!(body.matches(".map_err(").count(), 3, "{body}");
    assert_eq!(body.matches("cannot_run_said(").count(), 3, "{body}");
    assert!(!body.contains(".explain())?"), "{body}");
}
