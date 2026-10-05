//! `[repository] not-the-app` over every code file the app has (the deep review of 4 October 2026,
//! R12). Before, the folders were left out of what decides which requirements apply, the scan read
//! no code, and found nothing: a derived "no" that switched requirements to "does not apply", with
//! the report exiting 0 and saying nothing. Now nothing read is said first, the requirements the
//! code decides are not assessed, and `sv report` exits 2. Only "all": "nearly all" and an ordinary
//! `vendor/` with more files than the app are read as before, and the report counts both.

use serde_json::{Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const NOTHING_READ: &str = "the app's own code: none of it was read as the app";

fn app(name: &str, files: &[(&str, &str)], not_the_app: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-nothing-left-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    for (path, contents) in files {
        let file = dir.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, contents).unwrap();
    }
    std::fs::write(
        dir.join("securevibe.toml"),
        format!(
            "manifest-version = 1\n[app]\nname = \"Chat\"\n[stack]\nlanguages = [\"python\"]\n\
             [repository]\n{not_the_app}\n"
        ),
    )
    .unwrap();
    dir
}

/// A pinned dependency file beside the code, so something of the app is still read outside the
/// folders: the case that answered "does not apply". The code uses WebSockets.
fn chat_app(name: &str, extra: &[(&str, &str)], not_the_app: &str) -> PathBuf {
    let mut files = vec![
        ("requirements.txt", "flask==3.0.0\n"),
        ("requirements.lock", "flask==3.0.0\n"),
        ("src/app.py", "import websocket\n"),
    ];
    files.extend_from_slice(extra);
    app(name, &files, not_the_app)
}

struct Reported {
    status: i32,
    stdout: String,
    security: String,
    json: Value,
}

fn report(app: &Path) -> Reported {
    let out = app.join("report");
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(app)
        .arg("--out")
        .arg(&out)
        .output()
        .expect("sv runs");
    let security = std::fs::read_to_string(out.join("security.md")).unwrap_or_else(|_| {
        panic!(
            "no report written: {}",
            String::from_utf8_lossy(&run.stderr)
        )
    });
    Reported {
        status: run.status.code().unwrap(),
        stdout: String::from_utf8_lossy(&run.stdout).into_owned(),
        security,
        json: serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap())
            .unwrap(),
    }
}

/// Where `id` is in report.json: "applies", "excluded", or "undecided".
fn placed(json: &Value, id: &str) -> &'static str {
    let has = |key: &str| json[key].as_array().unwrap().iter().any(|r| r["id"] == id);
    match (has("requirements"), has("excluded"), has("undecided")) {
        (true, false, false) => "applies",
        (false, true, false) => "excluded",
        (false, false, true) => "undecided",
        other => panic!("{id} is in {other:?}"),
    }
}

/// The first "What was not examined" line of security.md.
fn first_gap(security: &str) -> &str {
    let at = security
        .find("## What was not examined\n\n")
        .expect("security.md lists what was not examined");
    security[at..].lines().nth(2).unwrap()
}

fn mcp_summary(app: &Path) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["mcp", "--root"])
        .arg(app)
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
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"securevibe_check","arguments":{"path":"."}}}),
        ] {
            writeln!(stdin, "{m}").unwrap();
        }
    }
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    let reply: Value = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|r| r["id"] == 2)
        .expect("a reply to the check");
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn not_the_app_over_all_the_code_is_said_first_and_decides_nothing() {
    // The control: read as the app, the code says WebSockets, and V4.4.1 applies.
    let whole = chat_app("whole", &[], "");
    let control = report(&whole);
    assert_eq!(placed(&control.json, "V4.4.1"), "applies");
    assert!(!control.security.contains(NOTHING_READ));
    std::fs::remove_dir_all(&whole).ok();

    let dir = chat_app("all", &[], "not-the-app = [\"src\"]");
    let r = report(&dir);
    // Not "does not apply" for want of anything read: not assessed.
    assert_eq!(placed(&r.json, "V4.4.1"), "undecided", "{}", r.security);
    // Said first of everything not examined, in the report the owner reads.
    assert!(
        first_gap(&r.security).contains(NOTHING_READ),
        "{}",
        first_gap(&r.security)
    );
    assert!(r.security.contains("(`src`)"), "{}", r.security);
    assert_eq!(r.json["gaps"][0]["what"], NOTHING_READ);
    // R6's path: exit 2, with the reason printed.
    assert_eq!(r.status, 2, "{}", r.stdout);
    assert!(
        r.stdout
            .contains("every code file of the app (1) is in a folder securevibe.toml's"),
        "{}",
        r.stdout
    );

    // At a terminal, `sv scope` says it before the counts.
    let scope = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("scope")
        .arg(&dir)
        .output()
        .unwrap();
    let scope = String::from_utf8_lossy(&scope.stdout);
    assert!(
        scope.contains("Nothing of the app's own code was read"),
        "{scope}"
    );
    assert!(
        scope.contains("websockets             the code read could not settle it"),
        "{scope}"
    );

    // And to the AI coding tool, first under NOT EXAMINED.
    let summary = mcp_summary(&dir);
    let not_examined = &summary[summary.find("NOT EXAMINED").expect(&summary)..];
    assert!(
        not_examined.lines().nth(1).unwrap().contains(NOTHING_READ),
        "{summary}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn not_the_app_over_nearly_all_the_code_is_counted_not_warned() {
    // One file is left outside the folder, and it is read as the app: what applies rests on it, as
    // on any one-file app. The list's own line counts both, so a person can see how much it set apart.
    let dir = chat_app(
        "nearly",
        &[
            ("main.py", "print('hello')\n"),
            ("src/more.py", "x = 1\n"),
            ("src/other.py", "y = 2\n"),
        ],
        "not-the-app = [\"src\"]",
    );
    let r = report(&dir);
    assert!(!r.security.contains(NOTHING_READ), "{}", r.security);
    assert_eq!(r.status, 0, "{}", r.stdout);
    assert_eq!(placed(&r.json, "V4.4.1"), "excluded");
    assert!(
        r.security.contains(
            "3 code files in them were left out of what is read as the app, and 1 was read as \
             the app."
        ),
        "{}",
        r.security
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn an_ordinary_tests_and_vendor_list_is_not_warned_about() {
    let mut files: Vec<(String, String)> = vec![
        ("requirements.txt".into(), "flask==3.0.0\n".into()),
        ("requirements.lock".into(), "flask==3.0.0\n".into()),
        ("app.py".into(), "print('hello')\n".into()),
        ("tests/test_app.py".into(), "import websocket\n".into()),
    ];
    // More vendored files than the app's own, as is common. Not `vendor/`: beside requirements.txt
    // the listing already leaves that out as installed code, before not-the-app is consulted.
    for i in 0..20 {
        files.push((format!("third_party/lib/m{i}.py"), format!("v = {i}\n")));
    }
    let files: Vec<(&str, &str)> = files
        .iter()
        .map(|(p, c)| (p.as_str(), c.as_str()))
        .collect();
    let dir = app(
        "vendor",
        &files,
        "not-the-app = [\"tests\", \"third_party\"]",
    );
    let r = report(&dir);
    assert!(
        r.security.contains("`tests`, `third_party`"),
        "the list was used: {}",
        r.security
    );
    assert!(!r.security.contains(NOTHING_READ), "{}", r.security);
    assert!(
        !r.stdout.contains("every code file of the app"),
        "{}",
        r.stdout
    );
    assert_eq!(r.status, 0, "{}", r.stdout);
    std::fs::remove_dir_all(&dir).ok();
}
