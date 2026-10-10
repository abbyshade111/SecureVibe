//! The names a call asked about and what `sv` handed over, as lines keep them (ADR-084,
//! decisions 3 and 5).

use super::*;

#[test]
fn a_name_is_one_sv_could_have_defined() {
    for ok in [
        "sign-in",
        "V1.2.4",
        "read-my-report",
        "report.html",
        "C7.1.1",
    ] {
        assert!(is_name(ok), "{ok}");
    }
    for not in ["", "make it pass", "a\nb", "../x", "<b>", &"x".repeat(65)] {
        assert!(!is_name(not), "{not:?}");
    }
}

#[test]
fn asked_and_handed_read_back_and_anything_else_is_not_sv_s() {
    let line = Line {
        time: "t".to_owned(),
        tool: "stackvet_before".to_owned(),
        asked: vec!["sign-in".to_owned()],
        handed: vec![
            "instructions".to_owned(),
            "prompt:read-my-report".to_owned(),
            "report:report.html".to_owned(),
        ],
        ..Line::default()
    };
    assert_eq!(Line::parse(&line.to_json()), Some(line));
    for bad in [
        r#"{"time":"t","tool":"x","asked":["the AI tool's own words"]}"#,
        r#"{"time":"t","tool":"x","handed":["a password"]}"#,
        r#"{"time":"t","tool":"x","handed":["file:/etc/passwd"]}"#,
        r#"{"time":"t","tool":"x","handed":["report:../../x"]}"#,
    ] {
        assert_eq!(Line::parse(bad), None, "{bad}");
    }
    let too_many = format!(
        r#"{{"time":"t","tool":"x","asked":[{}]}}"#,
        vec!["\"a\""; MAX_NAMES + 1].join(",")
    );
    assert_eq!(Line::parse(&too_many), None);
}

#[test]
fn a_summary_keeps_each_name_once_in_the_order_first_seen() {
    let record = [
        r#"{"time":"1","tool":"stackvet_before","asked":["sign-in"],"handed":["instructions"]}"#,
        r#"{"time":"2","tool":"stackvet_explain","asked":["V1.2.4"]}"#,
        r#"{"time":"3","tool":"stackvet_before","asked":["sign-in"],"handed":["prompt:p","instructions"]}"#,
    ]
    .join("\n");
    let s = summarize(record.as_bytes());
    assert_eq!(s.asked, ["sign-in", "V1.2.4"]);
    assert_eq!(s.handed, ["instructions", "prompt:p"]);
}
