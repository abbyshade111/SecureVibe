use super::*;
use std::path::PathBuf;

fn app(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-build-loop-{tag}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("stackvet.toml"),
        "manifest-version = 1\n[app]\nname = \"t\"\n",
    )
    .unwrap();
    dir
}

fn line(time: &str, tool: &str, findings: Option<usize>) -> Line {
    Line {
        time: time.to_owned(),
        tool: tool.to_owned(),
        counts: findings.map(|findings| LoopCounts {
            findings,
            checked: 10 - findings,
            needs_attention: findings,
            not_assessed: 3,
        }),
    }
}

fn record_file(dir: &Path) -> PathBuf {
    sv_scan::ecosystems::default_report_dir_in(dir).join(sv_scan::ecosystems::BUILD_LOOP_RECORD)
}

#[test]
fn a_line_is_written_as_it_is_read_back() {
    for l in [
        line("2026-10-09 15:00", "stackvet_check", Some(4)),
        line("t", "stackvet_spec", None),
    ] {
        assert_eq!(
            Line::parse(&l.to_json()),
            Some(l.clone()),
            "{}",
            l.to_json()
        );
    }
    // Nothing of the call's arguments or the findings' text has a place in a line.
    let json = line("t", "stackvet_check", Some(1)).to_json();
    let keys: Vec<String> = serde_json::from_str::<Value>(&json)
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(keys, ["counts", "time", "tool"]);
}

#[test]
fn the_record_says_how_many_calls_and_checks_and_the_counts_at_each_end() {
    let text = [
        line("10:00", "stackvet_spec", None).to_json(),
        line("10:05", "stackvet_check", Some(6)).to_json(),
        "not a line sv writes".to_owned(),
        line("10:20", "stackvet_check", Some(2)).to_json(),
        line("10:30", "stackvet_check", Some(0)).to_json(),
    ]
    .join("\n");
    let s = summarize(&text);
    assert_eq!((s.calls, s.checks, s.unreadable), (4, 3, 1));
    assert_eq!(
        (s.first.as_deref(), s.last.as_deref()),
        (Some("10:00"), Some("10:30"))
    );
    assert_eq!(s.first_counts.unwrap().findings, 6);
    assert_eq!(s.last_counts.unwrap().findings, 0);
    assert_eq!(summarize(""), BuildLoop::default());
}

#[test]
fn a_call_is_written_down_in_the_app_s_report_folder_and_read_back() {
    let dir = app("written");
    record(&dir, &line("10:00", "stackvet_check", Some(3))).unwrap();
    record(&dir, &line("10:10", "stackvet_check", Some(1))).unwrap();
    assert_eq!(
        std::fs::read_to_string(record_file(&dir))
            .unwrap()
            .lines()
            .count(),
        2
    );
    let s = read(&dir);
    assert_eq!((s.off, s.calls, s.checks), (false, 2, 2));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn turned_off_in_the_manifest_nothing_is_written_and_the_report_is_told() {
    let dir = app("off");
    std::fs::write(
        dir.join("stackvet.toml"),
        "manifest-version = 1\n[app]\nname = \"t\"\nbuild-loop-record = false\n",
    )
    .unwrap();
    record(&dir, &line("10:00", "stackvet_check", Some(3))).unwrap();
    assert!(!record_file(&dir).exists(), "written though turned off");
    assert!(read(&dir).off);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
#[cfg(unix)]
fn a_link_where_the_record_goes_is_not_written_through() {
    let dir = app("link");
    let outside =
        std::env::temp_dir().join(format!("sv-build-loop-outside-{}", std::process::id()));
    std::fs::write(&outside, "the owner's file\n").unwrap();
    let folder = sv_scan::ecosystems::default_report_dir_in(&dir);
    std::fs::create_dir_all(&folder).unwrap();
    std::os::unix::fs::symlink(&outside, record_file(&dir)).unwrap();
    assert!(record(&dir, &line("10:00", "stackvet_check", Some(3))).is_err());
    assert_eq!(
        std::fs::read_to_string(&outside).unwrap(),
        "the owner's file\n"
    );
    // Nor is it read: a link is no record sv wrote.
    assert_eq!(read(&dir).calls, 0);
    // And a report folder that is itself a link is not made or written through.
    std::fs::remove_dir_all(&folder).unwrap();
    let elsewhere =
        std::env::temp_dir().join(format!("sv-build-loop-elsewhere-{}", std::process::id()));
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &folder).unwrap();
    assert!(record(&dir, &line("10:00", "stackvet_check", Some(3))).is_err());
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&elsewhere).ok();
    std::fs::remove_file(&outside).ok();
}
