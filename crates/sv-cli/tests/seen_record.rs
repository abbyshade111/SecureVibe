//! What the running app answered is kept beside the report as `seen.json`, with no credential in it
//! (ADR-082, backlog 0229, part 1).
//!
//! `examples/notes-with-users`, copied, with its home page, the one page a visitor who has not signed in
//! is shown rather than sent to sign in, changed to show a key in its body and a header, and to set a
//! cookie whose value is a session id. Real containers and the real binary.
//! With no container backend, `seen.json` must say nothing was asked, and that is what is checked
//! instead.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// A key the secrets scan knows, and a session id no rule could tell from other letters, built from
/// pieces so this file holds neither.
fn planted() -> (String, String) {
    let key = ["sk", "ant", "api03", "Hq4Lp9Wz2Nc7Vr1Xb6Tm3Kd8"].join("-");
    let session = ["Rk7", "Pz2", "Lw9", "Qm4", "Tx1"].concat();
    (key, session)
}

/// The example, copied into Cargo's scratch folder beside the build, which every Mac backend shares
/// (see `killed_run.rs`), with its home page carrying both.
fn app(key: &str, session: &str) -> PathBuf {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/notes-with-users");
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("sv-seen-record-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    for file in ["app.py", "seed.py", "common-passwords.txt", "stackvet.toml"] {
        std::fs::copy(example.join(file), dir.join(file)).unwrap();
    }
    let code = std::fs::read_to_string(dir.join("app.py")).unwrap();
    let from = r#"return self.send(200, page("Notes", "<a href='/login'>Sign in</a>"))"#;
    // The setup has to have worked: the page is changed where it was meant to be.
    assert!(code.contains(from), "the example no longer has {from:?}");
    let to = format!(
        r#"return self.send(200, page("Notes", "<a href='/login'>Sign in</a> client = Client({key})"), (("X-Debug-Key", "{key}"), ("Set-Cookie", "trace={session}; Path=/; HttpOnly")))"#
    );
    std::fs::write(dir.join("app.py"), code.replace(from, &to)).unwrap();
    dir
}

#[test]
fn what_the_running_app_answered_is_kept_with_no_credential_in_it() {
    let (key, session) = planted();
    let app = app(&key, &session);
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(&app)
        .arg("--run")
        .output()
        .expect("sv runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let folder = app.join(sv_scan::ecosystems::DEFAULT_REPORT_DIR);
    let seen = std::fs::read_to_string(folder.join("seen.json"))
        .unwrap_or_else(|e| panic!("no seen.json ({e}): {stderr}"));
    let value: serde_json::Value = serde_json::from_str(&seen).expect("seen.json parses");
    let exchanges = value["exchanges"].as_array().expect("a list of exchanges");
    if sv_run::detect().is_err() {
        println!("no container backend here; checking the honest-absence path instead");
        assert!(exchanges.is_empty(), "{seen}");
        assert!(
            value["about"].as_str().unwrap().contains("did not ask"),
            "{seen}"
        );
        return;
    }
    println!("container backend present; running the app for real");

    // The setup worked: the app was asked, and its home page is among what it answered, with the
    // line that carried the key.
    let home = exchanges
        .iter()
        .find(|e| e["id"] == "home")
        .unwrap_or_else(|| panic!("no answer to `home`: {seen}"));
    assert_eq!(home["status"], 200, "{seen}");
    assert!(
        home["body"].as_str().unwrap().contains("client = Client("),
        "{seen}"
    );
    // Nothing of either credential reached the file, and what took their place says so.
    assert!(!seen.contains(&key), "the key reached seen.json: {seen}");
    assert!(
        !seen.contains(&session),
        "the session id reached seen.json: {seen}"
    );
    assert!(seen.contains("[redacted:"), "{seen}");
    assert!(seen.contains("trace=[removed,"), "{seen}");
    assert!(
        value["credentials_removed"].as_u64().unwrap() >= 2,
        "{seen}"
    );
    // The test model ran, since the example signs in, and what it received was read before it went
    // (backlog 0229, part 2): a record, even one with nothing sent to it, and none left unread.
    let stand_ins = &value["stand_ins"];
    assert!(
        stand_ins["model"]["seen"].is_array() && stand_ins["model"]["fetched"].is_array(),
        "{seen}"
    );
    assert!(stand_ins.get("not_read").is_none(), "{seen}");
    // And the report says the record is there.
    let report = std::fs::read_to_string(folder.join("compliance.md")).unwrap();
    assert!(
        report.contains("kept beside this report in seen.json"),
        "{report}"
    );
}
