//! The record of the build loop (ADR-076) as an AI coding tool makes it: each call written down by
//! the server, and the report written after them saying how many there were.

use super::tests::{call, scratch_app, text};
use super::*;

fn report_json(app: &Path) -> Value {
    let folder = sv_scan::ecosystems::default_report_dir_in(app);
    serde_json::from_str(&std::fs::read_to_string(folder.join("report.json")).unwrap()).unwrap()
}

fn record_lines(app: &Path) -> usize {
    std::fs::read_to_string(
        sv_scan::ecosystems::default_report_dir_in(app)
            .join(sv_scan::ecosystems::BUILD_LOOP_RECORD),
    )
    .map(|t| t.lines().count())
    .unwrap_or(0)
}

#[test]
fn the_checks_made_while_building_are_written_down_and_the_report_says_so() {
    let root = scratch_app("build-loop", "tested-notes");
    let app = root.join("app");
    let server = Server::new(&root).unwrap().recording(true);
    call(&server, "stackvet_spec", json!({}));
    for _ in 0..2 {
        let checked = call(&server, "stackvet_check", json!({ "path": "app" }));
        assert_eq!(checked["isError"], false, "{}", text(&checked));
    }
    // The spec was asked for at the root, which has no stackvet.toml: not this app's record.
    assert_eq!(record_lines(&app), 2);
    let written = call(&server, "stackvet_write_report", json!({ "path": "app" }));
    assert_eq!(written["isError"], false, "{}", text(&written));
    // The report read the record before its own call was written down.
    let loop_ = &report_json(&app)["build_loop"];
    assert_eq!(loop_["calls"], 2, "{loop_}");
    assert_eq!(loop_["checks"], 2, "{loop_}");
    assert!(
        loop_["last_counts"]["checked"].as_u64().unwrap() > 0,
        "{loop_}"
    );
    assert_eq!(record_lines(&app), 3);
    let folder = sv_scan::ecosystems::default_report_dir_in(&app);
    let page = std::fs::read_to_string(folder.join("report.html")).unwrap();
    assert!(
        page.contains("its AI coding tool asked sv 2 times"),
        "the page does not say it"
    );
    assert!(
        page.contains("it credits nothing"),
        "the page does not say what it is not"
    );
    for md in ["compliance.md", "security.md"] {
        let said = std::fs::read_to_string(folder.join(md)).unwrap();
        assert!(said.contains("asked sv 2 times"), "{md} does not say it");
    }
    // The record sits in the report folder without making it someone else's folder: the next
    // report is written there as before, and still offered as sv's.
    let again = call(&server, "stackvet_write_report", json!({ "path": "app" }));
    assert_eq!(again["isError"], false, "{}", text(&again));
    assert_eq!(report_json(&app)["build_loop"]["calls"], 3);
    assert!(
        crate::report_seal::proven(&folder).is_ok(),
        "the report folder with its record is not sealed as sv's"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn with_no_record_the_report_says_nothing_shows_sv_was_used() {
    let root = scratch_app("build-loop-none", "tested-notes");
    let app = root.join("app");
    // A server that does not write down, as the tests' own servers do not.
    let server = Server::new(&root).unwrap();
    call(&server, "stackvet_check", json!({ "path": "app" }));
    assert_eq!(record_lines(&app), 0);
    let written = call(&server, "stackvet_write_report", json!({ "path": "app" }));
    assert_eq!(written["isError"], false, "{}", text(&written));
    assert_eq!(report_json(&app)["build_loop"]["calls"], 0);
    let folder = sv_scan::ecosystems::default_report_dir_in(&app);
    let page = std::fs::read_to_string(folder.join("report.html")).unwrap();
    assert!(page.contains("Nothing shows that sv was used while this app was built"));
    assert!(page.contains("That is not a finding"));
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn turned_off_the_report_says_it_cannot_tell() {
    let root = scratch_app("build-loop-off", "tested-notes");
    let app = root.join("app");
    let manifest = std::fs::read_to_string(app.join("stackvet.toml")).unwrap();
    std::fs::write(
        app.join("stackvet.toml"),
        manifest.replacen("[app]\n", "[app]\nbuild-loop-record = false\n", 1),
    )
    .unwrap();
    let server = Server::new(&root).unwrap().recording(true);
    let checked = call(&server, "stackvet_check", json!({ "path": "app" }));
    assert_eq!(checked["isError"], false, "{}", text(&checked));
    call(&server, "stackvet_write_report", json!({ "path": "app" }));
    // Turned off, one line says so, holding the time and nothing else, so the gap is seen as one
    // (ADR-084); no call is written down, the check's or the report's.
    assert_eq!(record_lines(&app), 1, "a call written though turned off");
    let line: Value = serde_json::from_str(
        std::fs::read_to_string(
            sv_scan::ecosystems::default_report_dir_in(&app)
                .join(sv_scan::ecosystems::BUILD_LOOP_RECORD),
        )
        .unwrap()
        .trim(),
    )
    .unwrap();
    let keys: Vec<&String> = line.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["off", "time"], "{line}");
    assert_eq!(report_json(&app)["build_loop"]["off"], true);
    let folder = sv_scan::ecosystems::default_report_dir_in(&app);
    let page = std::fs::read_to_string(folder.join("report.html")).unwrap();
    assert!(page.contains("turned off in stackvet.toml"));
    std::fs::remove_dir_all(&root).ok();
}
