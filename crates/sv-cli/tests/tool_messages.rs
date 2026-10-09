//! What an outside tool says about a credential reaches nobody whole (deep review S8).
//!
//! Bandit's B105 message quotes the password it found ("Possible hardcoded password: '…'"), and until
//! 4 October 2026 a tool's words went into every report as the tool wrote them: a bundle that had left
//! out the file holding a password, so that the zip carried no secret, carried it four times inside
//! `report/`. Here a stand-in Bandit quotes a password in its finding, and every other tool `sv` knows
//! quotes it in what it says when it will not start. The password must then be in no file the report
//! writes, no entry of the bundle, no MCP reply, and nothing printed.
//!
//! The property is negative, so the setup is shown first: the search finds a copy planted where it
//! looks, the stand-in really quoted the password, and its finding and the others' words really
//! reached the report. The password is built from pieces at run time, so this file holds none.

use serde_json::{Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const SV: &str = env!("CARGO_BIN_EXE_sv");

fn password() -> String {
    ["Qv7r", "Lm2x", "Tz9k", "Wp4n", "Hd6s"].concat()
}

/// Whether `bytes` hold the password, or more of its start than the four characters a redaction
/// keeps, or the rest of it after those four.
fn leaks(bytes: &[u8]) -> bool {
    let password = password();
    [&password[..5], &password[4..]]
        .iter()
        .any(|piece| bytes.windows(piece.len()).any(|w| w == piece.as_bytes()))
}

/// Every file below `dir` that `leaks`, by its path.
fn leaking_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(leaking_files(&path));
        } else if leaks(&std::fs::read(&path).unwrap()) {
            out.push(path);
        }
    }
    out
}

/// The entries of a zip `sv` wrote (stored, never compressed), by name and contents.
fn zip_entries(zip: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0;
    while zip.len() >= at + 30 && zip[at..at + 4] == [0x50, 0x4b, 0x03, 0x04] {
        let u16_at = |i: usize| u16::from_le_bytes([zip[at + i], zip[at + i + 1]]) as usize;
        let size = u32::from_le_bytes(zip[at + 18..at + 22].try_into().unwrap()) as usize;
        let (name_len, extra_len) = (u16_at(26), u16_at(28));
        let name = String::from_utf8_lossy(&zip[at + 30..at + 30 + name_len]).into_owned();
        let start = at + 30 + name_len + extra_len;
        out.push((name, zip[start..start + size].to_vec()));
        at = start + size;
    }
    out
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-tool-messages-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn executable(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// What the stand-ins for every tool but Bandit say when asked for their version, and then fail.
const WILL_NOT_START: &str = "this stand-in will not start";

/// A stand-in Bandit whose one finding quotes the password three ways, as Bandit's B105 does in its
/// message, and in a rule description and help besides, and that keeps a copy of what it wrote in
/// `copy`; and, in front of every other tool in `data/adapters.json`, one that will not start and
/// quotes the password as it says so.
fn stand_ins(bin: &Path, copy: &Path) {
    let sarif = json!({
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "Bandit", "rules": [{
                "id": "B105",
                "shortDescription": { "text": format!("hardcoded_password_string: '{}'", password()) },
                "help": { "text": format!("Read PASSWORD={} from the environment instead.", password()) },
                "properties": { "tags": ["CWE-259"] },
            }] } },
            "results": [{
                "ruleId": "B105",
                "level": "warning",
                "message": { "text": format!("Possible hardcoded password: '{}'", password()) },
                "locations": [{ "physicalLocation": {
                    "artifactLocation": { "uri": "app.py" },
                    "region": { "startLine": 3 },
                } }],
            }],
        }],
    });
    executable(
        &bin.join("bandit"),
        &format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'bandit 1.9.4'; exit 0; fi\nout=''\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"--output\" ]; then out=\"$2\"; fi; shift; done\ncat > \"$out\" <<'SARIF'\n{sarif}\nSARIF\ncp \"$out\" '{}'\nexit 1\n",
            copy.display()
        ),
    );
    let adapters: Value = serde_json::from_str(
        &std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut commands: Vec<String> = adapters["adapters"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|a| {
            ["version", "run", "prepare"].map(|k| a[k]["command"].as_str().map(str::to_owned))
        })
        .flatten()
        .filter(|c| c != "bandit")
        .collect();
    commands.sort();
    commands.dedup();
    assert!(
        commands.iter().any(|c| c == "semgrep"),
        "the adapters were not read: {commands:?}"
    );
    for command in &commands {
        executable(
            &bin.join(command),
            &format!(
                "#!/bin/sh\necho \"{WILL_NOT_START}: password='{}'\" >&2\nexit 1\n",
                password()
            ),
        );
    }
}

/// An app with a password in `config.py`, which the credential scan finds and the bundle leaves out,
/// and code in `app.py`, where the stand-in Bandit reports, apart from any finding of `sv`'s own.
fn app(root: &Path) -> PathBuf {
    let app = root.join("app");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(
        app.join("config.py"),
        format!("PASSWORD = \"{}\"\n", password()),
    )
    .unwrap();
    std::fs::write(
        app.join("app.py"),
        "import config\n\n\ndef login(given):\n    return given == config.PASSWORD\n",
    )
    .unwrap();
    std::fs::write(
        app.join("stackvet.toml"),
        "manifest-version = 1\n[app]\nname = \"Quoted\"\n[stack]\nlanguages = [\"python\"]\n",
    )
    .unwrap();
    app
}

fn sv(args: &[&str], path: &str) -> Output {
    Command::new(SV)
        .args(args)
        .env("PATH", path)
        .output()
        .expect("sv runs")
}

fn mcp(root: &Path, messages: &[Value]) -> String {
    let mut child = Command::new(SV)
        .args(["mcp", "--root"])
        .arg(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sv starts");
    {
        let stdin = child.stdin.as_mut().unwrap();
        writeln!(stdin, "{}", json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}})).unwrap();
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .unwrap();
        for m in messages {
            writeln!(stdin, "{m}").unwrap();
        }
    }
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[cfg(unix)]
#[test]
fn a_password_a_tool_quotes_reaches_no_report_bundle_reply_or_screen() {
    let root = scratch("quoted");
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let copy = root.join("what-bandit-wrote.sarif");
    stand_ins(&bin, &copy);
    let app = app(&root);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    // The search finds a planted copy, in a file below a folder and in a zip's entries alike.
    let planted = root.join("planted/deeper");
    std::fs::create_dir_all(&planted).unwrap();
    std::fs::write(planted.join("x.txt"), format!("a {} b", password())).unwrap();
    assert_eq!(leaking_files(&root.join("planted")).len(), 1);
    std::fs::remove_dir_all(root.join("planted")).unwrap();
    assert!(leaks(format!("'{}…'", &password()[..5]).as_bytes()));
    assert!(leaks(&password().as_bytes()[4..]));
    assert!(!leaks(b"[redacted: Qv7r\xe2\x80\xa6 (16 more characters)]"));

    // The report, through `sv report --tools`, inside the app so the MCP server offers it.
    let out = app.join(sv_scan::ecosystems::DEFAULT_REPORT_DIR);
    let report = sv(
        &[
            "report",
            app.to_str().unwrap(),
            "--tools",
            "--out",
            out.to_str().unwrap(),
        ],
        &path,
    );
    assert!(report.status.success(), "{report:?}");
    // The setup: the stand-in really quoted the password, its finding reached the report on a line
    // of its own (not merged into one of `sv`'s), and so did the other tools' words.
    assert!(
        leaks(&std::fs::read(&copy).unwrap_or_default()),
        "the stand-in Bandit did not run or did not quote the password"
    );
    let security = std::fs::read_to_string(out.join("security.md")).unwrap();
    assert!(security.contains("`app.py` line 3"), "{security}");
    assert!(
        // The marker's brackets are escaped in Markdown, as all text a tool or the app supplied is
        // (R13), and read as `[redacted: …]` once shown.
        security.contains("Possible hardcoded password: '\\[redacted: Qv7r"),
        "Bandit's finding is in the report, its value redacted:\n{security}"
    );
    let compliance = std::fs::read_to_string(out.join("compliance.md")).unwrap();
    assert!(
        compliance.contains(&format!("{WILL_NOT_START}: password='\\[redacted: Qv7r")),
        "the other tools' words are in the report, redacted:\n{compliance}"
    );
    // Every file it wrote holds none of the password, and nothing printed does.
    assert_eq!(leaking_files(&out), Vec::<PathBuf>::new());
    assert!(!leaks(&report.stdout), "printed by sv report");
    assert!(!leaks(&report.stderr), "printed by sv report");

    // The bundle: `config.py` left out, and the report in it, holding none of the password either.
    let zip = root.join("quoted-bundle.zip");
    let bundle = sv(
        &[
            "bundle",
            app.to_str().unwrap(),
            "--tools",
            "--out",
            zip.to_str().unwrap(),
        ],
        &path,
    );
    assert!(bundle.status.success(), "{bundle:?}");
    let bytes = std::fs::read(&zip).unwrap();
    let entries = zip_entries(&bytes);
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"app/report/security.md"), "{names:?}");
    assert!(names.contains(&"app/app/app.py"), "{names:?}");
    assert!(!names.contains(&"app/app/config.py"), "left out: {names:?}");
    let in_bundle = entries
        .iter()
        .find(|(n, _)| n == "app/report/security.md")
        .map(|(_, b)| String::from_utf8_lossy(b).into_owned())
        .unwrap();
    assert!(
        in_bundle.contains("Possible hardcoded password: '\\[redacted: Qv7r"),
        "{in_bundle}"
    );
    for (name, data) in &entries {
        assert!(!leaks(data), "{name} in the bundle");
    }
    assert!(!leaks(&bytes), "the zip itself");
    assert!(!leaks(&bundle.stdout), "printed by sv bundle");
    assert!(!leaks(&bundle.stderr), "printed by sv bundle");

    // The MCP server: what it offers of the report on disk, and what its tools reply. It runs no
    // outside tools itself, so the report written above is how a tool's words could reach it.
    let listed = mcp(
        &root,
        &[json!({"jsonrpc":"2.0","id":1,"method":"resources/list"})],
    );
    let uris: Vec<String> = listed
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter_map(|v| v["result"]["resources"].as_array().cloned())
        .flatten()
        .filter_map(|r| r["uri"].as_str().map(str::to_owned))
        .collect();
    assert!(
        uris.iter().any(|u| u.ends_with("/security.md")),
        "the report is offered: {listed}"
    );
    let mut asks: Vec<Value> = uris
        .iter()
        .enumerate()
        .map(|(i, uri)| json!({"jsonrpc":"2.0","id":10 + i,"method":"resources/read","params":{"uri":uri}}))
        .collect();
    for (i, name) in [
        "securevibe_check",
        "securevibe_write_report",
        "securevibe_bundle",
    ]
    .iter()
    .enumerate()
    {
        asks.push(json!({"jsonrpc":"2.0","id":100 + i,"method":"tools/call","params":{"name":name,"arguments":{"path":"app"}}}));
    }
    let replies = mcp(&root, &asks);
    assert!(
        replies.contains("Possible hardcoded password: '[redacted: Qv7r"),
        "the report's Bandit finding was read back over MCP"
    );
    assert!(!leaks(listed.as_bytes()), "an MCP reply");
    assert!(!leaks(replies.as_bytes()), "an MCP reply");
    // And the files those tools wrote.
    assert_eq!(leaking_files(&out), Vec::<PathBuf>::new());
    for entry in std::fs::read_dir(&root).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".zip") {
            for (entry_name, data) in zip_entries(&std::fs::read(entry.path()).unwrap()) {
                assert!(!leaks(&data), "{name}: {entry_name}");
            }
        }
    }
    std::fs::remove_dir_all(&root).ok();
}

/// The backstop, through the command: a report that quotes a key, here from the app's own name, is not
/// zipped, and the refusal says where without the key.
#[test]
fn a_bundle_whose_report_would_hold_a_key_is_not_made() {
    let root = scratch("named");
    let app = root.join("app");
    std::fs::create_dir_all(&app).unwrap();
    // Built from pieces, so this file holds none.
    let key = ["sk", "ant", "api03", "Zp8Kd3Wq1Ls6Vn0Rt4Yb9Xm2Qc"].join("-");
    std::fs::write(app.join("app.py"), "print(1)\n").unwrap();
    std::fs::write(
        app.join("stackvet.toml"),
        format!(
            "manifest-version = 1\n[app]\nname = \"Notes {key}\"\n[stack]\nlanguages = [\"python\"]\n"
        ),
    )
    .unwrap();
    let zip = root.join("named-bundle.zip");
    let bundle = Command::new(SV)
        .args([
            "bundle",
            app.to_str().unwrap(),
            "--out",
            zip.to_str().unwrap(),
        ])
        .output()
        .expect("sv runs");
    // The setup: the report really quotes the name, so the key would have been in it.
    let report = Command::new(SV)
        .args(["report", app.to_str().unwrap(), "--out"])
        .arg(root.join("report"))
        .output()
        .expect("sv runs");
    let security = std::fs::read_to_string(root.join("report/security.md")).unwrap_or_default();
    let zipped = zip.exists();
    std::fs::remove_dir_all(&root).ok();
    assert!(report.status.success(), "{report:?}");
    assert!(
        security.contains(&key),
        "the report does not quote the name, so this proves nothing"
    );
    let stderr = String::from_utf8_lossy(&bundle.stderr);
    assert!(!bundle.status.success(), "{stderr}");
    assert!(!zipped, "no bundle is written");
    assert!(stderr.contains("so no bundle was made"), "{stderr}");
    assert!(stderr.contains("app/report/security.md line 1"), "{stderr}");
    assert!(
        !stderr.contains(&key[..12])
            && !String::from_utf8_lossy(&bundle.stdout).contains(&key[..12]),
        "the refusal quotes the key"
    );
}
