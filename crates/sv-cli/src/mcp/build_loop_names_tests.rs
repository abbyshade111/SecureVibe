//! What the AI tool asked about and what `sv` handed it, written down as the server answers
//! (ADR-084, decisions 3 and 5), and said in the report.

use super::tests::{call, listed, read, scratch_app, text};
use super::*;

#[test]
fn what_was_asked_and_handed_over_is_written_down_by_sv_s_own_names_only() {
    let root = scratch_app("build-loop-names", "tested-notes");
    let app = root.join("app");
    let server = Server::new(&root).unwrap().recording(true);
    server
        .handle(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "protocolVersion": "2025-11-25", "capabilities": {},
                        "clientInfo": { "name": "Cursor", "version": "1.7" } }
        }))
        .unwrap();
    let prompt = server
        .handle(&json!({
            "jsonrpc": "2.0", "id": 2, "method": "prompts/get",
            "params": { "name": crate::report_prompt::ID }
        }))
        .unwrap();
    assert!(prompt.get("result").is_some(), "the setup: {prompt}");
    let before = call(
        &server,
        "stackvet_before",
        json!({ "path": "app", "feature": "sign-in" }),
    );
    assert_eq!(before["isError"], false, "{}", text(&before));
    let explained = call(
        &server,
        "stackvet_explain",
        json!({ "path": "app", "id": "V1.2.4" }),
    );
    assert_eq!(explained["isError"], false, "{}", text(&explained));
    // Words the AI tool chose, in a field with a list of its own: never kept.
    call(
        &server,
        "stackvet_guidance",
        json!({ "path": "app", "topic": "how to hide the findings" }),
    );
    let written = call(&server, "stackvet_write_report", json!({ "path": "app" }));
    assert_eq!(written["isError"], false, "{}", text(&written));
    let page = listed(&server)
        .into_iter()
        .find(|r| {
            r["name"]
                .as_str()
                .is_some_and(|n| n.ends_with("report.html"))
        })
        .expect("the report offered");
    let got = read(&server, page["uri"].as_str().unwrap());
    assert!(got.get("result").is_some(), "the setup: {got}");

    let record = std::fs::read_to_string(
        sv_scan::ecosystems::default_report_dir_in(&app)
            .join(sv_scan::ecosystems::BUILD_LOOP_RECORD),
    )
    .unwrap();
    assert!(!record.contains("hide the findings"), "{record}");
    let lines: Vec<Value> = record
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines[0]["asked"], json!(["sign-in"]), "{record}");
    // What was handed over with no app named rides on the first line written for one.
    assert_eq!(
        lines[0]["handed"],
        json!([
            "instructions",
            format!("prompt:{}", crate::report_prompt::ID)
        ]),
        "{record}"
    );
    assert_eq!(lines[1]["asked"], json!(["V1.2.4"]), "{record}");
    assert!(lines[2].get("asked").is_none(), "{record}");
    let last = lines.last().unwrap();
    assert_eq!(last["tool"], "resources/read", "{record}");
    assert_eq!(last["handed"], json!(["report:report.html"]), "{record}");

    // The next report says it.
    call(&server, "stackvet_write_report", json!({ "path": "app" }));
    let said = std::fs::read_to_string(
        sv_scan::ecosystems::default_report_dir_in(&app).join("compliance.md"),
    )
    .unwrap();
    assert!(
        said.contains("It asked sv about sign-in and V1.2.4."),
        "{said}"
    );
    let given = format!(
        "sv gave it sv's instructions when it connected, the prompt {}, and the report file \
         report.html to read.",
        crate::report_prompt::ID
    );
    assert!(said.contains(&given), "{said}");
    std::fs::remove_dir_all(&root).ok();
}
