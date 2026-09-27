//! An app that serves tools over MCP, and has no AI of its own, is asked the server's requirements
//! of AISVS C10 — through the binary, from what `securevibe.toml` says.

use serde_json::Value;
use std::process::Command;

fn report_for(tag: &str, manifest: &str) -> Value {
    let dir = std::env::temp_dir().join(format!("sv-mcp-server-{tag}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("securevibe.toml"), manifest).unwrap();
    std::fs::write(dir.join("server.py"), "print('serving')\n").unwrap();
    let out = dir.join("report");
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args([
            "report",
            dir.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .expect("sv runs");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let report =
        serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap()).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    report
}

fn applies(report: &Value, id: &str) -> bool {
    report["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == id)
}

fn excluded(report: &Value, id: &str) -> bool {
    report["excluded"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == id)
}

#[test]
fn a_server_with_no_ai_is_asked_the_servers_requirements_and_not_the_clients() {
    let report = report_for(
        "yes",
        "manifest-version = 1\n[app]\nname = \"tools\"\n[capabilities]\nmcp-server = true\n\
         [capabilities.ai]\nenabled = false\n",
    );
    for id in ["C10.2.1", "C10.2.3", "C10.4.3", "C10.3.1"] {
        assert!(applies(&report, id), "{id} must apply to an MCP server");
    }
    for id in ["C10.4.1", "C10.1.1"] {
        assert!(excluded(&report, id), "{id} is the client's");
    }
}

#[test]
fn the_same_app_saying_it_serves_nothing_is_asked_none_of_it() {
    // The control: the answer is what moved them, not the app's files.
    let report = report_for(
        "no",
        "manifest-version = 1\n[app]\nname = \"tools\"\n[capabilities]\nmcp-server = false\n\
         [capabilities.ai]\nenabled = false\n",
    );
    for id in ["C10.2.1", "C10.4.3", "C10.3.1"] {
        assert!(excluded(&report, id), "{id} applies to an app with no MCP");
    }
}
