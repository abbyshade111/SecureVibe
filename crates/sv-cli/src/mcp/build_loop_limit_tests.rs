//! A record of the build loop that `sv` cannot read whole, as the report tells it (backlog 226,
//! part 1, items 3 and 7).

use super::tests::{call, scratch_app, text};
use super::*;

fn write_record(app: &Path, bytes: &[u8]) -> std::path::PathBuf {
    let folder = sv_scan::ecosystems::default_report_dir_in(app);
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join(sv_scan::ecosystems::BUILD_LOOP_RECORD), bytes).unwrap();
    folder
}

fn one_call() -> String {
    let line = crate::build_loop::Line {
        time: "2026-10-09T10:00:00Z".to_owned(),
        tool: "stackvet_check".to_owned(),
        counts: Some(sv_report::LoopCounts::default()),
    };
    format!("{}\n", line.to_json())
}

#[test]
fn one_bad_byte_does_not_make_the_report_say_sv_was_never_used() {
    let root = scratch_app("build-loop-bad-byte", "tested-notes");
    let app = root.join("app");
    let mut bytes = one_call().into_bytes();
    bytes.extend_from_slice(b"\xff\xfe\n");
    let folder = write_record(&app, &bytes);
    let server = Server::new(&root).unwrap();
    let written = call(&server, "stackvet_write_report", json!({ "path": "app" }));
    assert_eq!(written["isError"], false, "{}", text(&written));
    let page = std::fs::read_to_string(folder.join("report.html")).unwrap();
    assert!(
        !page.contains("Nothing shows that sv was used"),
        "one bad byte hid the record"
    );
    assert!(
        page.contains("asked sv 1 time"),
        "the call before the bad byte is lost"
    );
    assert!(page.contains("One line of the record could not be read"));
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn a_full_record_says_its_last_check_is_the_last_one_written() {
    let root = scratch_app("build-loop-full", "tested-notes");
    let app = root.join("app");
    let one = one_call();
    let folder = write_record(
        &app,
        one.repeat(crate::build_loop::MAX_BYTES as usize / one.len() + 1)
            .as_bytes(),
    );
    let server = Server::new(&root).unwrap();
    let written = call(&server, "stackvet_write_report", json!({ "path": "app" }));
    assert_eq!(written["isError"], false, "{}", text(&written));
    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(folder.join("report.json")).unwrap())
            .unwrap();
    assert_eq!(report["build_loop"]["full"], true);
    for page in ["report.html", "compliance.md"] {
        let said = std::fs::read_to_string(folder.join(page)).unwrap();
        assert!(
            said.contains("reached its size limit"),
            "{page} does not say the record is full"
        );
    }
    std::fs::remove_dir_all(&root).ok();
}
