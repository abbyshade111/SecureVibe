//! The record's lines with how each call ended, the tool's name, and the off line (ADR-084).

use super::*;

#[test]
fn a_tool_name_is_kept_short_and_plain() {
    assert_eq!(client_name("Cursor", "1.7").as_deref(), Some("Cursor 1.7"));
    assert_eq!(client_name("Cursor", "").as_deref(), Some("Cursor"));
    assert_eq!(client_name("", "1.0"), None);
    // Nothing that could run on into the record or the page, and never longer than 40 a part.
    let said = client_name("evil\n\"},{\"tool\":\"x<script>", &"9".repeat(200)).unwrap();
    assert!(!said.contains(['\n', '"', '{', '<']), "{said}");
    assert_eq!(said, format!("eviltoolxscript {}", "9".repeat(40)));
}

#[test]
fn every_new_field_reads_back_and_an_unknown_outcome_is_not_sv_s() {
    let line = Line {
        time: "2026-10-10T10:00:00Z".to_owned(),
        tool: "stackvet_check".to_owned(),
        outcome: Some("timed-out".to_owned()),
        client: Some("Cursor 1.7".to_owned()),
        sv: Some("0.1.0".to_owned()),
        ..Line::default()
    };
    assert_eq!(Line::parse(&line.to_json()), Some(line));
    let off = Line {
        time: "2026-10-10T10:00:00Z".to_owned(),
        off: true,
        ..Line::default()
    };
    assert_eq!(
        off.to_json(),
        r#"{"off":true,"time":"2026-10-10T10:00:00Z"}"#
    );
    assert_eq!(Line::parse(&off.to_json()), Some(off));
    assert_eq!(
        Line::parse(r#"{"time":"t","tool":"stackvet_check","outcome":"passed"}"#),
        None
    );
}

#[test]
fn a_summary_counts_each_outcome_the_tools_and_the_gaps() {
    let lines = [
        r#"{"time":"1","tool":"stackvet_check","outcome":"ok","client":"A 1","sv":"0.1.0"}"#,
        r#"{"time":"2","tool":"stackvet_check","outcome":"failed","client":"A 1","sv":"0.1.0"}"#,
        r#"{"time":"3","off":true}"#,
        r#"{"time":"4","tool":"stackvet_check","outcome":"timed-out","client":"B 2","sv":"0.1.0"}"#,
        r#"{"time":"5","tool":"stackvet_check","outcome":"crashed"}"#,
        r#"{"time":"6","tool":"unknown","outcome":"refused"}"#,
        r#"{"time":"7","tool":"stackvet_spec"}"#,
    ];
    let s = summarize(lines.join("\n").as_bytes());
    assert_eq!(s.calls, 6, "an off line is not a call");
    assert_eq!((s.failed, s.timed_out, s.crashed, s.refused), (1, 1, 1, 1));
    assert_eq!(s.turned_off, 1);
    assert_eq!(s.clients, ["A 1", "B 2"]);
    assert_eq!(s.svs, ["0.1.0"]);
    assert_eq!(s.unreadable, 0);
}

/// A call that cannot be written down is counted, and the next report this process writes says so.
#[cfg(unix)]
#[test]
fn a_call_that_could_not_be_written_is_counted() {
    let dir = std::env::temp_dir().join(format!("sv-build-loop-unwritten-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("stackvet.toml"),
        "manifest-version = 1\n[app]\nname = \"t\"\n",
    )
    .unwrap();
    let folder = sv_scan::ecosystems::default_report_dir_in(&dir);
    std::fs::create_dir_all(&folder).unwrap();
    // A link where the record goes: `sv` will not write through it.
    std::os::unix::fs::symlink(
        dir.join("elsewhere"),
        folder.join(sv_scan::ecosystems::BUILD_LOOP_RECORD),
    )
    .unwrap();
    assert_eq!(read(&dir).unwritten, 0, "the control");
    let line = Line {
        time: "t".to_owned(),
        tool: "stackvet_check".to_owned(),
        ..Line::default()
    };
    assert!(record(&dir, &line).is_err());
    assert!(record(&dir, &line).is_err());
    assert_eq!(read(&dir).unwritten, 2);
    std::fs::remove_dir_all(&dir).ok();
}
