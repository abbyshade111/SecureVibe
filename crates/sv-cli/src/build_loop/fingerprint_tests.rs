//! The findings' fingerprints at each check, and what came and went between the first check and
//! the last (ADR-084, decision 6).

use super::*;

#[test]
fn a_checks_fingerprints_are_sorted_each_once_and_capped() {
    let (kept, cut) = fingerprints_of(["bb", "aa", "", "bb"]);
    assert_eq!((kept, cut), (vec!["aa".to_owned(), "bb".to_owned()], false));
    let many: Vec<String> = (0..MAX_FINGERPRINTS + 1)
        .map(|n| format!("{n:016x}"))
        .collect();
    let (kept, cut) = fingerprints_of(many.iter().map(String::as_str));
    assert_eq!(kept.len(), MAX_FINGERPRINTS);
    assert!(cut);
}

#[test]
fn fingerprints_read_back_and_anything_else_is_not_sv_s() {
    let line = Line {
        time: "t".to_owned(),
        tool: "stackvet_check".to_owned(),
        counts: Some(LoopCounts::default()),
        fingerprints: Some(vec![
            "882dedc677bff5a5".to_owned(),
            "v2-61eb1668992f3990".to_owned(),
        ]),
        ..Line::default()
    };
    assert_eq!(Line::parse(&line.to_json()), Some(line));
    // Text where a hash belongs: a finding's words would be kept, so the line is not sv's.
    assert_eq!(
        Line::parse(r#"{"time":"t","tool":"stackvet_check","fingerprints":["no way to report"]}"#),
        None
    );
    let too_many = format!(
        r#"{{"time":"t","tool":"stackvet_check","fingerprints":[{}]}}"#,
        vec!["\"aa\""; MAX_FINGERPRINTS + 1].join(",")
    );
    assert_eq!(Line::parse(&too_many), None);
}

fn check(time: &str, fingerprints: &[&str], cut: bool) -> String {
    Line {
        time: time.to_owned(),
        tool: "stackvet_check".to_owned(),
        counts: Some(LoopCounts::default()),
        fingerprints: Some(fingerprints.iter().map(|f| (*f).to_owned()).collect()),
        fingerprints_cut: cut,
        ..Line::default()
    }
    .to_json()
}

#[test]
fn between_the_first_check_and_the_last_each_finding_is_counted_once() {
    let record = [
        check("1", &["aa", "bb", "cc"], false),
        r#"{"time":"2","tool":"stackvet_spec"}"#.to_owned(),
        check("3", &["ee"], false),
        check("4", &["cc", "dd"], false),
    ]
    .join("\n");
    let mut summary = summarize(record.as_bytes());
    // bb was set aside as a false alarm in the report about to be written.
    settle(&mut summary, &["bb".to_owned()]);
    assert_eq!(
        summary.findings_moved,
        Some(sv_report::FindingsMoved {
            no_longer_found: 1,
            set_aside: 1,
            new: 1,
        })
    );
}

#[test]
fn nothing_is_said_when_it_cannot_be_said() {
    let said = |record: Vec<String>| {
        let mut summary = summarize(record.join("\n").as_bytes());
        settle(&mut summary, &[]);
        summary.findings_moved
    };
    assert!(
        said(vec![check("1", &["aa"], false), check("2", &[], false)]).is_some(),
        "the control"
    );
    // One check: nothing between.
    assert_eq!(said(vec![check("1", &["aa"], false)]), None);
    // A check whose line kept only some of its findings.
    assert_eq!(
        said(vec![check("1", &["aa"], true), check("2", &[], false)]),
        None
    );
    assert_eq!(
        said(vec![check("1", &["aa"], false), check("2", &[], true)]),
        None
    );
    // A line written before fingerprints were kept.
    let older = r#"{"time":"1","tool":"stackvet_check","counts":{"findings":1,"checked":0,"needs_attention":0,"not_assessed":0}}"#;
    assert_eq!(said(vec![older.to_owned(), check("2", &[], false)]), None);
}
