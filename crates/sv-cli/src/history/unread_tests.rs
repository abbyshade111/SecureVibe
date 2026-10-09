//! A kept run that cannot be read is counted, not passed over (backlog 226, part 1, item 8).

use super::*;

#[test]
fn a_run_missing_a_later_field_still_reads_and_one_that_cannot_is_counted() {
    let folder = std::env::temp_dir().join(format!("sv-history-unread-{}", std::process::id()));
    std::fs::remove_dir_all(&folder).ok();
    std::fs::create_dir_all(&folder).unwrap();
    let whole = Run {
        format: 1,
        started: "2026-10-09T10:00:00Z".to_owned(),
        started_unix_ms: 2,
        ..Run::default()
    };
    std::fs::write(
        folder.join("b.json"),
        serde_json::to_string(&whole).unwrap(),
    )
    .unwrap();
    // A run written before a field was added: the field is missing, and the run is still read.
    let mut older = serde_json::to_value(&whole).unwrap();
    older["started_unix_ms"] = 1.into();
    older.as_object_mut().unwrap().remove("not_run");
    std::fs::write(folder.join("a.json"), older.to_string()).unwrap();
    // Not runs: text that is not JSON, and JSON that names no format.
    std::fs::write(folder.join("c.json"), "not json").unwrap();
    std::fs::write(folder.join("d.json"), "{}").unwrap();
    // The app's own file is not a run, and not counted as one that failed.
    std::fs::write(folder.join("app.json"), r#"{"folder":"/x"}"#).unwrap();

    let (runs, unread) = runs_in(&folder);
    let order: Vec<u64> = runs.iter().map(|(_, r)| r.started_unix_ms).collect();
    assert_eq!(
        order,
        [1, 2],
        "the older run vanished, or the order is wrong"
    );
    assert_eq!(
        unread, 2,
        "a file that is not a run was passed over silently"
    );
    std::fs::remove_dir_all(&folder).ok();
}
