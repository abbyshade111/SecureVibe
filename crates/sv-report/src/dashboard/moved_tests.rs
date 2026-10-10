//! Each requirement's status kept in each run, and which ones moved between two (ADR-083, part 1).

use super::*;
use crate::Status;

fn run(statuses: &[(&str, Status)]) -> Run {
    Run {
        format: 2,
        started: "2026-10-10T10:00:00Z".to_owned(),
        requirements: statuses
            .iter()
            .map(|(id, status)| KeptStatus {
                id: (*id).to_owned(),
                status: *status,
            })
            .collect(),
        ..Run::default()
    }
}

#[test]
fn a_status_that_changed_one_that_came_and_one_that_went_are_each_named() {
    let then = run(&[
        ("V1.1.1", Status::NotVerified),
        ("V2.2.2", Status::Checked),
        ("V3.3.3", Status::Documented),
    ]);
    let now = run(&[
        ("V1.1.1", Status::Checked),
        ("V2.2.2", Status::Checked),
        ("V4.4.4", Status::NeedsAttention),
    ]);
    let moved = now.moved_since(&then);
    assert_eq!(
        moved,
        [
            (
                "V1.1.1".to_owned(),
                Some(Status::NotVerified),
                Some(Status::Checked)
            ),
            ("V4.4.4".to_owned(), None, Some(Status::NeedsAttention)),
            ("V3.3.3".to_owned(), Some(Status::Documented), None),
        ]
    );
    let said = now.changes_since(&then).join("\n");
    assert!(
        said.contains("V1.1.1: not verified then, checked now"),
        "{said}"
    );
    assert!(
        said.contains("V4.4.4: did not apply then, needs attention now"),
        "{said}"
    );
    assert!(
        said.contains("V3.3.3: documented by the owner then, did not apply now"),
        "{said}"
    );
    // The one that stayed the same is not named.
    assert!(!said.contains("V2.2.2"), "{said}");
}

#[test]
fn a_run_kept_by_an_older_sv_says_which_moved_is_not_known() {
    let mut older = run(&[]);
    older.format = 1;
    older.counts.applicable = 3;
    older.counts.not_verified = 3;
    let mut now = run(&[("V1.1.1", Status::Checked)]);
    now.counts.applicable = 3;
    now.counts.checked = 1;
    now.counts.not_verified = 2;
    assert!(now.moved_since(&older).is_empty());
    let said = now.changes_since(&older).join("\n");
    assert!(
        said.contains("Which requirements moved is not known"),
        "{said}"
    );
    // The control: with the counts the same, nothing is said of it.
    let mut same = now.clone();
    same.requirements.clear();
    assert!(
        !now.changes_since(&same).join("\n").contains("not known"),
        "counts equal, nothing moved to explain"
    );
}

#[test]
fn many_moved_are_named_up_to_a_limit_and_the_rest_counted() {
    let ids: Vec<String> = (1..=20).map(|n| format!("V9.9.{n}")).collect();
    let then = run(&ids
        .iter()
        .map(|id| (id.as_str(), Status::NotVerified))
        .collect::<Vec<_>>());
    let now = run(&ids
        .iter()
        .map(|id| (id.as_str(), Status::Checked))
        .collect::<Vec<_>>());
    let said = now.changes_since(&then);
    let named = said.iter().filter(|l| l.starts_with("V9.9.")).count();
    assert_eq!(named, MOVED_SHOWN);
    assert!(
        said.iter()
            .any(|l| l == &format!("and {} more requirements moved", 20 - MOVED_SHOWN)),
        "{said:?}"
    );
}

#[test]
fn a_record_from_before_format_two_still_reads_and_a_new_one_round_trips() {
    // As history wrote it before ADR-083: no `requirements` at all.
    let old: Run = serde_json::from_str(
        r#"{"format":1,"started":"2026-10-08T08:00:00Z","started_unix_ms":1,"app_name":"A",
            "target_level":1,"sv":"sv 0.1.0","securevibe_toml_sha256":"x","not_run":[],
            "counts":{},"findings":[]}"#,
    )
    .expect("an older record still reads");
    assert!(old.requirements.is_empty());
    let new = run(&[("V1.1.1", Status::CheckedInPart)]);
    let text = serde_json::to_string(&new).unwrap();
    assert!(text.contains(r#""status":"checked-in-part""#), "{text}");
    let back: Run = serde_json::from_str(&text).unwrap();
    assert_eq!(back.requirements, new.requirements);
}
