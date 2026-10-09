//! `sv mcp` spoken to the way an AI coding tool speaks to it: a child process, one JSON message per
//! line on stdin, one per line back on stdout, and nothing else on stdout at all.

use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn a_whole_session_over_stdio() {
    let examples = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    let mut child = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["mcp", "--root"])
        .arg(&examples)
        // The repository's own examples keep no record of this test's calls (ADR-076).
        .env("SV_BUILD_LOOP_RECORD", "off")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sv starts");
    let messages = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"stackvet_check","arguments":{"path":"tested-notes"}}}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"stackvet_check","arguments":{"path":"../.."}}}),
    ];
    {
        let stdin = child.stdin.as_mut().unwrap();
        for m in &messages {
            writeln!(stdin, "{m}").unwrap();
        }
    }
    drop(child.stdin.take());
    let output = child
        .wait_with_output()
        .expect("sv exits when stdin closes");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let replies: Vec<Value> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|_| panic!("not protocol on stdout: {l}")))
        .collect();
    // Four requests, one notification: four replies, in order.
    let ids: Vec<i64> = replies.iter().map(|r| r["id"].as_i64().unwrap()).collect();
    assert_eq!(ids, [1, 2, 3, 4]);
    assert_eq!(replies[0]["result"]["serverInfo"]["name"], "stackvet");
    // What the tool is told to have the person run names this very `sv` by its full path, so it
    // works at a terminal whether or not `sv` was ever put on the search path (the owner's first
    // build met `command not found`).
    let program = sv_frameworks::paths::canonical(env!("CARGO_BIN_EXE_sv")).unwrap();
    let instructions = replies[0]["result"]["instructions"].as_str().unwrap();
    assert!(
        instructions.contains(&format!("`{} report ", program.display())),
        "{instructions}"
    );
    assert_eq!(replies[1]["result"]["tools"].as_array().unwrap().len(), 13);
    assert!(
        instructions.contains("stackvet_guidance"),
        "the tool is told to ask for the rules before it codes: {instructions}"
    );
    let check = &replies[2]["result"];
    assert_eq!(check["isError"], false, "{check}");
    assert!(
        check["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("NOT EXAMINED")
    );
    // Appendix C, counted apart, is said in the summary the tool reads, not only in the files.
    assert!(
        check["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("OWASP AISVS Appendix C"),
        "{check}"
    );
    let escaped = &replies[3]["result"];
    assert_eq!(
        escaped["isError"], true,
        "the fence held over stdio too: {escaped}"
    );
    assert!(
        escaped["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("outside"),
        "refused for the right reason: {escaped}"
    );
}
