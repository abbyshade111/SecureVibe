//! `config.gitignore-covers-env` in a folder that is not yet a git repository, said the same way
//! by `sv check`, `sv report`, and the MCP server's `stackvet_check`.
//!
//! Found in the loop pilot (5 October 2026): `sv report`, on a copy made a repository, flagged
//! every build for nothing stopping `.env` being committed, and `sv check` during the build, in the
//! plain folder, did not say so. A builder who checks before `git init` never heard it.

use serde_json::{Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const RULE: &str = "config.gitignore-covers-env";
const TITLE: &str = "Nothing stops the environment file being committed";

/// A folder outside any repository, under a parent of its own so the MCP server's root holds only it.
fn plain_app(name: &str) -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("sv-env-plain-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let dir = root.join("app");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("stackvet.toml"),
        "manifest-version = 1\n[app]\nname = \"x\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("app.py"), "print('hi')\n").unwrap();
    std::fs::write(dir.join(".env"), "SESSION_SECRET=x\n").unwrap();
    // The setup: no folder from here up is a git repository, so this is the case the pilot met.
    let full = std::fs::canonicalize(&dir).unwrap();
    assert!(
        full.ancestors().all(|f| !f.join(".git").exists()),
        "{} is inside a repository",
        full.display()
    );
    (root, dir)
}

/// What `sv check` said: Some(true) a finding, Some(false) a pass, None neither.
fn by_check(dir: &Path) -> Option<bool> {
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("check")
        .arg(dir)
        .output()
        .expect("sv runs");
    let out = String::from_utf8_lossy(&run.stdout);
    let failed = out.contains(TITLE);
    let passed = out
        .lines()
        .any(|l| l.trim_start().starts_with(&format!("{RULE} —")));
    assert!(!(failed && passed), "{out}");
    (failed || passed).then_some(failed)
}

/// What `sv report` said, from `report.json`.
fn by_report(dir: &Path) -> Option<bool> {
    let out = dir.join("report");
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(dir)
        .arg("--out")
        .arg(&out)
        .output()
        .expect("sv runs");
    assert!(
        matches!(run.status.code(), Some(0 | 2)),
        "sv report failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap()).unwrap();
    std::fs::remove_dir_all(&out).ok();
    finding_in(&report["findings"])
        .then_some(true)
        .or(Some(false))
}

/// What the MCP server's `stackvet_check` said, spoken to over stdio as an AI tool does.
fn by_mcp(root: &Path) -> Option<bool> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["mcp", "--root"])
        .arg(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sv starts");
    {
        let stdin = child.stdin.as_mut().unwrap();
        for m in [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"stackvet_check","arguments":{"path":"app"}}}),
        ] {
            writeln!(stdin, "{m}").unwrap();
        }
    }
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("sv exits");
    let reply: Value = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|r| r["id"] == 2)
        .expect("the check is answered");
    let result = &reply["result"];
    assert_eq!(result["isError"], false, "{result}");
    finding_in(&result["structuredContent"]["findings"])
        .then_some(true)
        .or(Some(false))
}

fn finding_in(findings: &Value) -> bool {
    findings
        .as_array()
        .expect("a list of findings")
        .iter()
        .any(|f| f["rule_id"] == RULE)
}

#[test]
fn an_environment_file_in_a_folder_not_yet_in_git_is_said_by_all_three() {
    let (root, dir) = plain_app("bare");
    assert_eq!(by_check(&dir), Some(true), "sv check");
    assert_eq!(by_report(&dir), Some(true), "sv report");
    assert_eq!(by_mcp(&root), Some(true), "stackvet_check");

    // With a .gitignore that leaves it out, none of the three says it.
    std::fs::write(dir.join(".gitignore"), ".env\nreport/\n").unwrap();
    assert_eq!(by_check(&dir), Some(false), "sv check");
    assert_eq!(by_report(&dir), Some(false), "sv report");
    assert_eq!(by_mcp(&root), Some(false), "stackvet_check");

    // And with no environment file and no .gitignore, none says it either.
    std::fs::remove_file(dir.join(".gitignore")).unwrap();
    std::fs::remove_file(dir.join(".env")).unwrap();
    assert_eq!(by_check(&dir), None, "sv check");
    assert_eq!(by_report(&dir), Some(false), "sv report");
    assert_eq!(by_mcp(&root), Some(false), "stackvet_check");
    std::fs::remove_dir_all(&root).ok();
}
