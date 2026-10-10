//! A package list `sv` cannot read, through a real `sv report` (backlog 0226, part 1, item 11).
//!
//! One stray comma in `package.json` turns a library the app uses into "not used": V1.3.9 is excluded
//! as not applying, and the claims table says the manifest and the code agree. That answer counting
//! for nothing is the owner's to decide (part 3, item H). What is held here: the report names the
//! file it could not read, and why, beside that answer; and with the file mended, both change back.

use serde_json::Value;
use std::process::Command;

const LOCK: &str = "{ \"name\": \"x\", \"lockfileVersion\": 3, \"packages\": { \"\": { \"name\": \"x\" }, \"node_modules/memjs\": { \"version\": \"1.3.2\" } } }\n";
const READS: &str = "{ \"name\": \"x\", \"dependencies\": { \"memjs\": \"1.3.2\" } }\n";
const DOES_NOT: &str = "{ \"name\": \"x\", \"dependencies\": { \"memjs\": \"1.3.2\", } }\n";

fn report_of(name: &str, package_json: &str) -> (Value, String) {
    let dir = std::env::temp_dir().join(format!("sv-unread-list-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    for (file, text) in [
        (
            "stackvet.toml",
            "manifest-version = 1\n[app]\nname = \"x\"\n",
        ),
        ("package.json", package_json),
        ("package-lock.json", LOCK),
        ("index.js", "console.log('hello');\n"),
    ] {
        std::fs::write(dir.join(file), text).unwrap();
    }
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(&dir)
        .output()
        .expect("sv runs");
    assert!(
        matches!(run.status.code(), Some(0 | 2)),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let json: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("stackvet-report/report.json")).unwrap(),
    )
    .unwrap();
    let compliance = std::fs::read_to_string(dir.join("stackvet-report/compliance.md")).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    (json, compliance)
}

fn excluded(report: &Value, id: &str) -> bool {
    report["excluded"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["id"] == id)
}

fn package_list_gap(report: &Value) -> Option<String> {
    report["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["what"] == "the package list package.json")
        .map(|g| g["why"].as_str().unwrap().to_owned())
}

#[test]
fn a_package_list_that_does_not_parse_is_named_beside_the_answer_it_changes() {
    let (read, _) = report_of("reads", READS);
    let (unread, compliance) = report_of("does-not", DOES_NOT);
    // The control: read, memjs is seen, V1.3.9 applies, and nothing is said of the file.
    assert!(
        !excluded(&read, "V1.3.9"),
        "V1.3.9 excluded with memjs read"
    );
    assert_eq!(package_list_gap(&read), None);
    // Not read: the wrong answer reaches the report, as it stands until the owner decides (H).
    assert!(excluded(&unread, "V1.3.9"));
    // And the report says why, beside it, in both forms.
    let why = package_list_gap(&unread).expect("the unread package list is named");
    assert!(why.contains("not valid JSON"), "{why}");
    assert!(why.contains("may be answered as not used"), "{why}");
    let examined = compliance
        .split("## What was not examined")
        .nth(1)
        .expect("a section of what was not examined");
    assert!(
        examined.contains("the package list package.json"),
        "{examined}"
    );
}

#[test]
fn sv_scope_says_the_same_at_a_terminal() {
    let dir = std::env::temp_dir().join(format!("sv-unread-list-scope-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    for (file, text) in [
        (
            "stackvet.toml",
            "manifest-version = 1\n[app]\nname = \"x\"\n",
        ),
        ("package.json", DOES_NOT),
        ("package-lock.json", LOCK),
        ("index.js", "console.log('hello');\n"),
    ] {
        std::fs::write(dir.join(file), text).unwrap();
    }
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("scope")
        .arg(&dir)
        .output()
        .expect("sv runs");
    std::fs::remove_dir_all(&dir).ok();
    let said = String::from_utf8_lossy(&run.stdout);
    assert!(run.status.success(), "{said}");
    assert!(
        said.contains("package.json was not read: it is not valid JSON"),
        "{said}"
    );
}
