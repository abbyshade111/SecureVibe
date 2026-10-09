//! A record `sv` cannot read whole (backlog 226, part 1, items 3 and 7): one bad byte costs one
//! line and not the record, and a record at its size limit says so.

use super::*;

fn app(tag: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("sv-build-loop-limit-{tag}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("stackvet.toml"),
        "manifest-version = 1\n[app]\nname = \"t\"\n",
    )
    .unwrap();
    dir
}

fn call(time: &str) -> String {
    Line {
        time: time.to_owned(),
        tool: "stackvet_check".to_owned(),
        counts: Some(LoopCounts::default()),
    }
    .to_json()
}

fn record_path(dir: &Path) -> std::path::PathBuf {
    let folder = sv_scan::ecosystems::default_report_dir_in(dir);
    std::fs::create_dir_all(&folder).unwrap();
    folder.join(sv_scan::ecosystems::BUILD_LOOP_RECORD)
}

#[test]
fn a_byte_that_is_not_utf8_costs_its_line_and_not_the_record() {
    let dir = app("bad-byte");
    let mut bytes = format!("{}\n", call("10:00")).into_bytes();
    bytes.extend_from_slice(b"{\"time\":\"10:05\xff\",\"tool\":\"x\"}\n");
    bytes.extend_from_slice(format!("{}\n", call("10:10")).as_bytes());
    std::fs::write(record_path(&dir), bytes).unwrap();
    let s = read(&dir);
    assert_eq!((s.calls, s.checks, s.unreadable, s.full), (2, 2, 1, false));
    assert_eq!(s.last.as_deref(), Some("10:10"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_record_at_its_limit_is_full_writes_no_more_and_leaves_no_half_line() {
    let dir = app("full");
    let one = format!("{}\n", call("2026-10-09T10:00:00Z"));
    let lines = (MAX_BYTES as usize / one.len()) + 2;
    let path = record_path(&dir);
    std::fs::write(&path, one.repeat(lines)).unwrap();
    let before = std::fs::metadata(&path).unwrap().len();
    assert!(before > MAX_BYTES && before.is_multiple_of(one.len() as u64));
    record(&dir, &Line::parse(one.trim()).unwrap()).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        before,
        "written past the limit"
    );
    let s = read(&dir);
    assert!(s.full, "a record at its limit does not say so");
    // The line the limit cuts through was written whole: left out, not unreadable.
    assert_eq!(s.unreadable, 0);
    assert_eq!(s.calls, MAX_BYTES as usize / one.len());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_record_short_of_its_limit_is_not_full() {
    let dir = app("short");
    std::fs::write(record_path(&dir), format!("{}\n", call("10:00"))).unwrap();
    assert!(!read(&dir).full);
    std::fs::remove_dir_all(&dir).ok();
}
