//! More in the record of the build loop (ADR-084, the first part): how each call ended, which AI
//! coding tool and which `sv` it was, and a line when the record is turned off, through the server
//! as an AI coding tool uses it.

use super::tests::{call, scratch_app, text};
use super::*;

fn record(app: &Path) -> Vec<Value> {
    std::fs::read_to_string(
        sv_scan::ecosystems::default_report_dir_in(app)
            .join(sv_scan::ecosystems::BUILD_LOOP_RECORD),
    )
    .unwrap_or_default()
    .lines()
    .map(|l| serde_json::from_str(l).unwrap())
    .collect()
}

fn page(app: &Path) -> String {
    std::fs::read_to_string(sv_scan::ecosystems::default_report_dir_in(app).join("report.html"))
        .unwrap()
}

fn initialize(server: &Server, client: Value) {
    server
        .handle(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": client }
        }))
        .expect("answered");
}

#[test]
fn each_call_says_how_it_ended_and_which_tool_and_sv_it_was() {
    let root = scratch_app("build-loop-outcome", "tested-notes");
    let app = root.join("app");
    let server = Server::new(&root).unwrap().recording(true);
    initialize(
        &server,
        json!({ "name": "Claude Code", "version": "2.1.0" }),
    );
    let checked = call(&server, "stackvet_check", json!({ "path": "app" }));
    assert_eq!(checked["isError"], false, "{}", text(&checked));
    // A call sv cannot do (an answer with no words): failed.
    let failed = call(
        &server,
        "stackvet_record_answer",
        json!({ "path": "app", "id": "V1.1.1" }),
    );
    assert_eq!(failed["isError"], true, "the setup: {}", text(&failed));
    // A tool sv does not have: refused, and kept under no name the AI tool wrote.
    call(&server, "stackvet_make_it_pass", json!({ "path": "app" }));
    let lines = record(&app);
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert_eq!(lines[0]["tool"], "stackvet_check");
    assert_eq!(lines[0]["outcome"], "ok");
    assert_eq!(lines[0]["client"], "Claude Code 2.1.0");
    assert_eq!(lines[0]["sv"], env!("CARGO_PKG_VERSION"));
    assert_eq!(lines[1]["tool"], "stackvet_record_answer");
    assert_eq!(lines[1]["outcome"], "failed");
    assert_eq!(lines[2]["tool"], "unknown");
    assert_eq!(lines[2]["outcome"], "refused");
    assert!(
        !lines[2].to_string().contains("make_it_pass"),
        "{}",
        lines[2]
    );

    let written = call(&server, "stackvet_write_report", json!({ "path": "app" }));
    assert_eq!(written["isError"], false, "{}", text(&written));
    let said = page(&app);
    assert!(
        said.contains("Of those calls, 1 failed and 1 was refused as a tool sv does not have"),
        "{said}"
    );
    assert!(
        said.contains("named itself Claude Code 2.1.0 when it connected"),
        "{said}"
    );
    assert!(
        said.contains(&format!("answered by sv {}", env!("CARGO_PKG_VERSION"))),
        "{said}"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn a_check_that_runs_out_of_time_is_written_down_as_that() {
    let root = scratch_app("build-loop-timed-out", "tested-notes");
    let app = root.join("app");
    let server = Server::new(&root)
        .unwrap()
        .recording(true)
        .with_time_limit(std::time::Duration::from_millis(1));
    let checked = call(&server, "stackvet_check", json!({ "path": "app" }));
    assert_eq!(
        checked["isError"], true,
        "the setup: the check did not finish in time"
    );
    let lines = record(&app);
    assert_eq!(lines.last().unwrap()["outcome"], "timed-out", "{lines:?}");
    assert!(lines.last().unwrap().get("counts").is_none());
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn turned_off_and_on_again_the_gap_is_noted_once_and_said() {
    let root = scratch_app("build-loop-gap", "tested-notes");
    let app = root.join("app");
    let manifest = std::fs::read_to_string(app.join("stackvet.toml")).unwrap();
    let server = Server::new(&root).unwrap().recording(true);
    call(&server, "stackvet_check", json!({ "path": "app" }));
    std::fs::write(
        app.join("stackvet.toml"),
        manifest.replacen("[app]\n", "[app]\nbuild-loop-record = false\n", 1),
    )
    .unwrap();
    for _ in 0..3 {
        call(&server, "stackvet_check", json!({ "path": "app" }));
    }
    std::fs::write(app.join("stackvet.toml"), &manifest).unwrap();
    call(&server, "stackvet_check", json!({ "path": "app" }));
    let lines = record(&app);
    // The first check, one line for the three made while it was off, and the check after.
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert_eq!(lines[1]["off"], true);
    assert_eq!(lines[2]["outcome"], "ok");
    call(&server, "stackvet_write_report", json!({ "path": "app" }));
    let said = page(&app);
    assert!(
        said.contains("The record was turned off once while the app was built"),
        "{said}"
    );
    std::fs::remove_dir_all(&root).ok();
}
