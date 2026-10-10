//! A run that did not finish: never compared, shown for what it was, and the report shown said to
//! be older (ADR-083, part 2).

use super::*;

fn finished(day: &str) -> Run {
    Run {
        format: 4,
        started: format!("{day}T10:00:00Z"),
        sv: "0.1.0 (commit abc)".to_owned(),
        exit_code: Some(0),
        ..Run::default()
    }
}

fn unfinished(day: &str, outcome: Outcome, code: i32) -> Run {
    let record = crate::RunRecord {
        started: format!("{day}T11:00:00Z"),
        started_unix_ms: 1,
        securevibe_toml_sha256: String::new(),
        run_id: String::new(),
        inputs: None,
    };
    Run::unfinished(&record, "0.1.0 (commit abc)".to_owned(), outcome, code)
}

#[test]
fn a_run_that_did_not_finish_is_never_compared_either_way() {
    let (a, b) = (
        finished("2026-10-01"),
        unfinished("2026-10-02", Outcome::Failed, 3),
    );
    assert!(a.not_comparable_with(&a.clone()).is_none(), "the control");
    assert!(a.not_comparable_with(&b).is_some());
    assert!(b.not_comparable_with(&a).is_some());
}

#[test]
fn the_latest_run_that_failed_is_said_first_and_the_report_said_to_be_older() {
    let page = over_time(
        &[
            finished("2026-10-01"),
            unfinished("2026-10-02", Outcome::Failed, 3),
        ],
        0,
    );
    let note = page
        .find("The latest run, on 2026-10-02, did not finish.")
        .expect(&page);
    assert!(
        page.contains("The report shown is from the last run that did, on 2026-10-01"),
        "{page}"
    );
    // Said before the list of runs, not inside it.
    assert!(note < page.find("<ul>").unwrap(), "{page}");
    assert!(
        page.contains("Did not finish: sv stopped with an error"),
        "{page}"
    );
    assert!(page.contains("(it ended with 3)"), "{page}");
}

#[test]
fn a_stopped_run_between_two_finished_ones_is_passed_over_for_the_comparison() {
    let page = over_time(
        &[
            finished("2026-10-01"),
            unfinished("2026-10-02", Outcome::Stopped, 130),
            finished("2026-10-03"),
        ],
        0,
    );
    assert!(
        page.contains("Did not finish: it was stopped with Ctrl-C"),
        "{page}"
    );
    assert!(page.contains("Compared with 2026-10-01"), "{page}");
    assert!(
        !page.contains("The latest run"),
        "the latest finished: {page}"
    );
}

#[test]
fn a_run_with_no_finished_run_before_it_says_so() {
    let page = over_time(
        &[
            unfinished("2026-10-01", Outcome::Failed, 3),
            finished("2026-10-02"),
        ],
        0,
    );
    assert!(
        page.contains("Not compared: no run before it finished."),
        "{page}"
    );
}

#[test]
fn a_record_from_before_format_four_reads_as_finished_and_an_unfinished_one_round_trips() {
    let old: Run = serde_json::from_str(
        r#"{"format":3,"started":"2026-10-10T08:00:00Z","started_unix_ms":1,"app_name":"A",
            "target_level":1,"sv":"sv 0.1.0","securevibe_toml_sha256":"x","not_run":[],
            "counts":{},"findings":[],"requirements":[]}"#,
    )
    .expect("an older record still reads");
    assert!(old.finished());
    assert_eq!(old.exit_code, None);
    let new = unfinished("2026-10-02", Outcome::Stopped, 130);
    let text = serde_json::to_string(&new).unwrap();
    assert!(text.contains(r#""outcome":"stopped""#), "{text}");
    let back: Run = serde_json::from_str(&text).unwrap();
    assert_eq!(
        (back.outcome, back.exit_code),
        (Outcome::Stopped, Some(130))
    );
}

#[test]
fn a_record_from_a_later_sv_with_a_field_this_one_does_not_know_still_reads() {
    // ADR-083, decision 4: a later `sv` adds to the record; this one reads what it knows.
    let later: Run = serde_json::from_str(
        r#"{"format":9,"started":"2026-12-01T08:00:00Z","started_unix_ms":1,"app_name":"A",
            "target_level":1,"sv":"sv 0.9.0","securevibe_toml_sha256":"x","not_run":[],
            "counts":{},"findings":[],"requirements":[],"outcome":"finished",
            "something_new":{"kept":"by a later sv"}}"#,
    )
    .expect("a field this sv does not know is passed over");
    assert_eq!(later.format, 9);
    assert!(later.finished());
    // An outcome this sv does not know is not guessed at: the record does not read, and history
    // counts it among the files it could not show (`runs_in`).
    assert!(serde_json::from_str::<Run>(r#"{"format":9,"outcome":"crashed"}"#).is_err());
}
