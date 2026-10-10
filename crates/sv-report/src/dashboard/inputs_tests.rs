//! What else a run read that can move a requirement, and two runs that differ in it said to differ
//! for that reason (ADR-083, part 3).

use super::*;
use crate::RunInputs;

fn run(notes: Option<&str>, decisions: Option<&str>, data: Option<&str>) -> Run {
    Run {
        format: 3,
        sv: "sv 0.1.0 (commit abc)".to_owned(),
        securevibe_toml_sha256: "t".to_owned(),
        inputs: Some(RunInputs {
            security_notes_sha256: notes.map(str::to_owned),
            design_decisions_sha256: decisions.map(str::to_owned),
            sv_data_sha256: data.map(str::to_owned),
        }),
        ..Run::default()
    }
}

#[test]
fn the_same_inputs_compare() {
    let a = run(Some("n"), Some("d"), Some("x"));
    assert_eq!(a.clone().not_comparable_with(&a), None);
}

#[test]
fn each_input_that_changed_is_named_as_the_reason() {
    let then = run(Some("n"), Some("d"), Some("x"));
    let why = |now: Run| now.not_comparable_with(&then).unwrap_or("compared");
    assert!(why(run(Some("N"), Some("d"), Some("x"))).starts_with("your security notes changed"));
    assert!(why(run(Some("n"), Some("D"), Some("x"))).starts_with("your design decisions changed"));
    assert!(
        why(run(Some("n"), Some("d"), Some("X")))
            .starts_with("the same sv was given different data")
    );
    // A file there in one run and gone in the next changed too.
    assert!(why(run(None, Some("d"), Some("x"))).starts_with("your security notes changed"));
    assert!(why(run(Some("n"), None, Some("x"))).starts_with("your design decisions changed"));
}

#[test]
fn data_that_could_not_be_read_in_either_run_is_not_held_against_it() {
    let then = run(Some("n"), Some("d"), None);
    assert_eq!(
        run(Some("n"), Some("d"), Some("x")).not_comparable_with(&then),
        None
    );
    assert_eq!(
        then.not_comparable_with(&run(Some("n"), Some("d"), Some("x"))),
        None
    );
}

#[test]
fn a_run_from_before_inputs_were_kept_says_the_cause_is_not_known_when_something_moved() {
    let mut older = run(None, None, None);
    older.inputs = None;
    let mut now = run(Some("n"), None, Some("x"));
    // Still compared, as before: what it did not keep is not held against it.
    assert_eq!(now.not_comparable_with(&older), None);
    let unknown = |said: &[String]| {
        said.iter()
            .any(|l| l.starts_with("Whether the security notes"))
    };
    // Nothing moved: nothing to explain, so nothing said about it.
    assert!(
        !unknown(&now.changes_since(&older)),
        "{:?}",
        now.changes_since(&older)
    );
    // A count moved: the cause may be in what the older run did not keep, and that is said.
    now.counts.checked = 3;
    let said = now.changes_since(&older);
    assert!(said.iter().any(|l| l.starts_with("checked by")), "{said:?}");
    assert!(unknown(&said), "{said:?}");
    // Both runs kept their inputs: no such sentence.
    let mut then = run(Some("n"), None, Some("x"));
    then.counts.checked = 1;
    assert!(!unknown(&now.changes_since(&then)));
}

#[test]
fn a_record_from_before_format_three_still_reads_and_a_new_one_round_trips() {
    let old: Run = serde_json::from_str(
        r#"{"format":2,"started":"2026-10-10T08:00:00Z","started_unix_ms":1,"app_name":"A",
            "target_level":1,"sv":"sv 0.1.0","securevibe_toml_sha256":"x","not_run":[],
            "counts":{},"findings":[],"requirements":[]}"#,
    )
    .expect("an older record still reads");
    assert!(old.inputs.is_none());
    let new = run(Some("n"), None, Some("x"));
    let back: Run = serde_json::from_str(&serde_json::to_string(&new).unwrap()).unwrap();
    assert_eq!(back.inputs, new.inputs);
}
