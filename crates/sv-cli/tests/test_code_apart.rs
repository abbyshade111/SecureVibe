//! Findings in test code, listed apart from the app's own, end to end: `sv report` on a Rust app
//! whose unit tests sit in the same file as the code, as Rust's do.

use std::path::PathBuf;
use std::process::Command;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-test-code-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The same weak hash twice: on line 2 in the app, and on line 8 inside its tests.
const LIB: &str = "pub fn digest(b: &[u8]) -> [u8; 16] {\n    md5::compute(b).0\n}\n\n#[cfg(test)]\nmod tests {\n    fn old(b: &[u8]) -> [u8; 16] {\n        md5::compute(b).0\n    }\n}\n";

#[test]
fn a_finding_inside_a_rust_test_module_is_listed_apart_and_still_counts() {
    let app = scratch("rust");
    std::fs::create_dir_all(app.join("src")).unwrap();
    std::fs::write(app.join("src/lib.rs"), LIB).unwrap();
    std::fs::write(
        app.join("securevibe.toml"),
        "manifest-version = 1\n[app]\nname = \"Hashes\"\n[stack]\nlanguages = [\"rust\"]\n",
    )
    .unwrap();
    let out = app.join("report");
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["report"])
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

    // Both are really found: the rule fires on both lines, so a missing one below is not a rule
    // that never ran.
    assert!(security.contains("`src/lib.rs` line 2"), "{security}");
    assert!(security.contains("`src/lib.rs` line 8"), "{security}");

    // Two in the app: the hash on line 2, and the missing SECURITY.md every bare app is told about.
    let list = &security[security.find("## 2 things to fix").expect(&security)..];
    let apart = list.find("## 1 in test or sample code").expect(list);
    let app_line = list.find("`src/lib.rs` line 2").unwrap();
    let test_line = list.find("`src/lib.rs` line 8").unwrap();
    assert!(app_line < apart && apart < test_line, "{list}");

    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap()).unwrap();
    let marked: Vec<(u64, bool)> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["location"]["file"] == "src/lib.rs")
        .map(|f| {
            (
                f["location"]["line"].as_u64().unwrap(),
                f["marked_test_code"].as_bool().unwrap_or(false),
            )
        })
        .collect();
    assert!(
        marked.contains(&(2, false)) && marked.contains(&(8, true)),
        "{marked:?}"
    );
    std::fs::remove_dir_all(&app).ok();
}
