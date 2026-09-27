//! Part 1 of the false-alarm work, end to end: what reaches the owner and the AI coding tool.
//!
//! One weakness reported by two tools on one line is listed once, naming both; a finding in test
//! code says so; and each finding says how sure `sv` is. None of it may hide a finding: the
//! requirement a merged finding is evidence about still needs attention.

use std::path::{Path, PathBuf};
use std::process::Command;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-false-alarms-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const APP: &str = "import sqlite3\n\ndef find(db, user_id):\n    cur = db.cursor()\n    cur.execute(\"SELECT * FROM notes WHERE owner = \" + user_id)\n    return cur.fetchall()\n";

/// A stand-in for Bandit that answers `--version` and writes a SARIF report of one result: the
/// same SQL built by hand that `sv`'s own rule finds, on the same line, tagged with the same CWE.
fn fake_bandit(bin: &Path, line: usize) {
    let sarif = format!(
        r#"{{"version":"2.1.0","runs":[{{"tool":{{"driver":{{"name":"Bandit","rules":[{{"id":"B608","properties":{{"tags":["CWE-89"]}}}}]}}}},"results":[{{"ruleId":"B608","level":"warning","message":{{"text":"Possible SQL injection vector through string-based query construction."}},"properties":{{"tags":["CWE-89"]}},"locations":[{{"physicalLocation":{{"artifactLocation":{{"uri":"app.py"}},"region":{{"startLine":{line}}}}}}}]}}]}}]}}"#
    );
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'bandit 1.9.4'; exit 0; fi\nout=''\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"--output\" ]; then out=\"$2\"; fi; shift; done\ncat > \"$out\" <<'SARIF'\n{sarif}\nSARIF\nexit 1\n"
    );
    let path = bin.join("bandit");
    std::fs::write(&path, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn report(app: &Path, bin: &Path) -> (String, String) {
    let out = app.join("report");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["report"])
        .arg(app)
        .args(["--tools", "--out"])
        .arg(&out)
        .env("PATH", path)
        .output()
        .expect("sv runs");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    (
        std::fs::read_to_string(out.join("security.md")).unwrap_or_default(),
        std::fs::read_to_string(out.join("compliance.md")).unwrap_or_default(),
    )
}

#[cfg(unix)]
#[test]
fn one_weakness_on_one_line_from_two_tools_is_listed_once_naming_both() {
    let dir = scratch("dup");
    let bin = dir.join("bin");
    let app = dir.join("app");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(app.join("app.py"), APP).unwrap();
    std::fs::write(
        app.join("securevibe.toml"),
        "manifest-version = 1\n[app]\nname = \"Dup\"\n[stack]\nlanguages = [\"python\"]\n",
    )
    .unwrap();

    // The control: on another line, the two are two findings, and Bandit really ran.
    fake_bandit(&bin, 6);
    let (security, _) = report(&app, &bin);
    assert!(
        security.contains("bandit.B608") || security.contains("Possible SQL injection"),
        "the stand-in Bandit was not run, so the rest proves nothing:\n{security}"
    );
    assert!(!security.contains("Also reported by"), "{security}");

    // On the same line: once, naming both, and still counted against V1.2.4.
    fake_bandit(&bin, 5);
    let (security, compliance) = report(&app, &bin);
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(
        security.matches("app.py` line 5").count(),
        1,
        "listed once:\n{security}"
    );
    assert!(
        security.contains("Also reported by: `bandit.B608`"),
        "{security}"
    );
    let v124 = compliance
        .lines()
        .find(|l| l.starts_with("| V1.2.4 |"))
        .expect("V1.2.4 is in the report");
    assert!(v124.contains("needs attention"), "{v124}");
}

/// An app with a finding `sv` is only possibly right about, in the app itself, and a likely one in a
/// test file: `sv`'s own rules, so nothing outside needs installing.
fn labelled_app(dir: &Path) {
    std::fs::create_dir_all(dir.join("tests")).unwrap();
    std::fs::write(
        dir.join("app.py"),
        "from flask import Flask, redirect, request\napp = Flask(__name__)\n\n@app.route(\"/go\")\ndef go():\n    return redirect(request.args.get(\"next\"))\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("tests/test_db.py"),
        "def find(db, user_id):\n    cur = db.cursor()\n    cur.execute(\"SELECT * FROM notes WHERE owner = \" + user_id)\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("securevibe.toml"),
        "manifest-version = 1\n[app]\nname = \"Labels\"\n[stack]\nlanguages = [\"python\"]\n",
    )
    .unwrap();
}

#[test]
fn every_report_says_how_sure_it_is_and_whether_it_is_test_code_and_hides_nothing() {
    let root = scratch("labels");
    let app = root.join("lab");
    labelled_app(&app);
    let out = app.join("report");
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(&app)
        .arg("--out")
        .arg(&out)
        .output()
        .expect("sv runs");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let security = std::fs::read_to_string(out.join("security.md")).unwrap();
    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("findings.sarif")).unwrap())
            .unwrap();
    let compliance = std::fs::read_to_string(out.join("compliance.md")).unwrap();
    let html = std::fs::read_to_string(out.join("report.html")).unwrap();
    assert!(
        html.contains("How sure: possible.") && html.contains("In test or sample code"),
        "the HTML report says it too"
    );

    // The owner's report.
    let redirect = security
        .split("### ")
        .find(|s| s.contains("app.py` line 6"))
        .unwrap_or_else(|| panic!("the redirect was not found:\n{security}"));
    assert!(redirect.contains("How sure: possible."), "{redirect}");
    assert!(!redirect.contains("In test or sample code"), "{redirect}");
    let in_test = security
        .split("### ")
        .find(|s| s.contains("tests/test_db.py` line 3"))
        .unwrap_or_else(|| panic!("the test file's finding was not listed:\n{security}"));
    assert!(in_test.contains("How sure: likely."), "{in_test}");
    assert!(in_test.contains("In test or sample code"), "{in_test}");
    // Neither label hides anything: both still need attention.
    for id in ["V1.2.4", "V3.7.2"] {
        let row = compliance
            .lines()
            .find(|l| l.starts_with(&format!("| {id} |")))
            .unwrap_or_else(|| panic!("no row for {id}"));
        assert!(row.contains("needs attention"), "{row}");
    }

    // The SARIF, for GitHub and other tools.
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    let props = |file: &str| {
        results
            .iter()
            .find(|r| r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == file)
            .map(|r| r["properties"].clone())
            .unwrap_or_else(|| panic!("no result in {file}"))
    };
    assert_eq!(props("app.py")["certainty"], "possible");
    assert_eq!(props("app.py")["inTestCode"], false);
    assert_eq!(props("tests/test_db.py")["inTestCode"], true);

    // What the AI coding tool is told: the possible one reaches it as one to check first.
    let mut child = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["mcp", "--root"])
        .arg(&root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("sv starts");
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().unwrap();
        for m in [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"securevibe_check","arguments":{"path":"lab"}}}"#,
        ] {
            writeln!(stdin, "{m}").unwrap();
        }
    }
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    std::fs::remove_dir_all(&root).ok();
    let reply: serde_json::Value = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .find(|r| r["id"] == 2)
        .expect("a reply to the check");
    let text = reply["result"]["content"][0]["text"].as_str().unwrap();
    let redirect = text
        .lines()
        .skip_while(|l| !l.contains("app.py:6"))
        .take(3)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(redirect.contains("[medium, possible]"), "{text}");
    assert!(
        redirect.contains("read the code before changing anything"),
        "the tool must be told to check before it rewrites: {text}"
    );
    let in_test = text
        .lines()
        .skip_while(|l| !l.contains("tests/test_db.py:3"))
        .take(3)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(in_test.contains("[high, likely]"), "{text}");
    assert!(in_test.contains("In test or sample code"), "{text}");
}
