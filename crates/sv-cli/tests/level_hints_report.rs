//! At level 1, the report asks about what the code shows and the answers do not, under the level
//! line, end to end through the binary (gap analysis of 7 October 2026, finding 17; ADR-024,
//! Later, 9 October 2026).

use std::path::{Path, PathBuf};
use std::process::Command;

fn app(name: &str, audience: &str, code: &str) -> PathBuf {
    app_with(
        name,
        audience,
        "[data]\ncategories = []\n",
        &[("app.py", code)],
    )
}

fn app_with(name: &str, audience: &str, data: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-level-hints-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("stackvet.toml"),
        format!(
            "manifest-version = 1\n\n[app]\nname = \"Tracker\"\ndescription = \"Tracker.\"\n\
             audience = \"{audience}\"\ndeployment = \"internet\"\n\n[stack]\nlanguages = [\"python\"]\n\n{data}"
        ),
    )
    .unwrap();
    for (path, text) in files {
        let path = dir.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    dir
}

/// The report's JSON, and its compliance page.
fn report(dir: &Path) -> (serde_json::Value, String) {
    let out = dir.join("report");
    let ran = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args([
            "report",
            dir.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .expect("sv runs");
    assert!(
        ran.status.success(),
        "{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    let json =
        serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap()).unwrap();
    let page = std::fs::read_to_string(out.join("compliance.md")).unwrap();
    std::fs::remove_dir_all(dir).ok();
    (json, page)
}

const CODE: &str = "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/signup')\ndef signup():\n    blood_pressure = 120\n    return 'ok'\n";

#[test]
fn level_one_asks_about_a_sign_up_page_and_health_fields() {
    let (json, page) = report(&app("asked", "just-me", CODE));
    assert_eq!(json["target_level"], 1, "the setup: held to level 1");
    let hints = json["level_why"]["hints"].as_array().expect("hints");
    let kinds: Vec<&str> = hints.iter().map(|h| h["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds, vec!["sign-up", "health"], "{json}");
    assert!(
        page.contains(
            "The code suggests a sign-up page open to strangers (`/signup`, app.py line 4) and \
             health information (`blood_pressure`, app.py line 6), which the answers do not say."
        ),
        "{page}"
    );
    // A question, never a finding, and the level is the answers' still.
    assert!(
        !json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule_id"].as_str().unwrap_or("").contains("level")),
        "{json}"
    );
}

#[test]
fn level_two_asks_nothing() {
    let (json, page) = report(&app("level-two", "customers", CODE));
    assert_eq!(json["target_level"], 2, "the setup: held to level 2");
    assert!(json["level_why"].get("hints").is_none(), "{json}");
    assert!(!page.contains("The code suggests"), "{page}");
}

#[test]
fn level_one_with_nothing_to_ask_says_nothing_more() {
    let (json, page) = report(&app("clean", "just-me", "print('hello')\n"));
    assert_eq!(json["target_level"], 1);
    assert!(json["level_why"].get("hints").is_none(), "{json}");
    assert!(!page.contains("The code suggests"), "{page}");
    // The setup: the level line is there for the question to have gone under.
    assert!(page.contains("Level 1 because"), "{page}");
}

#[test]
fn every_page_with_the_level_line_carries_the_question() {
    let dir = app("pages", "just-me", CODE);
    let out = dir.join("report");
    let ran = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args([
            "report",
            dir.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .expect("sv runs");
    assert!(
        ran.status.success(),
        "{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    // `security.md` has no level line, so nothing to put a question under.
    for page in ["report.html", "compliance.md"] {
        let text = std::fs::read_to_string(out.join(page)).unwrap();
        assert!(
            text.contains("Level 1 because"),
            "the setup: {page} has the level line"
        );
        assert!(
            text.contains("The code suggests"),
            "{page} lacks the question"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn level_two_from_an_unanswered_data_list_asks_nothing() {
    let (json, page) = report(&app_with("unanswered", "just-me", "", &[("app.py", CODE)]));
    assert_eq!(
        json["target_level"], 2,
        "the setup: an unanswered list is level 2"
    );
    assert!(json["level_why"].get("hints").is_none(), "{json}");
    assert!(!page.contains("The code suggests"), "{page}");
}

#[test]
fn tests_prose_and_longer_routes_are_not_asked_about() {
    let (json, page) = report(&app_with(
        "not-the-app",
        "just-me",
        "[data]\ncategories = []\n",
        &[
            (
                "app.py",
                "@app.route('/signup-help')\ndef help():\n    return 'ok'\n",
            ),
            (
                "tests/test_app.py",
                "diagnosis = 'flu'\nclient.get('/register')\n",
            ),
            ("README.md", "No diagnosis is stored. Sign up at /signup.\n"),
        ],
    ));
    assert_eq!(json["target_level"], 1, "the setup: held to level 1");
    assert!(json["level_why"].get("hints").is_none(), "{json}");
    assert!(!page.contains("The code suggests"), "{page}");
}

#[test]
fn a_folder_set_apart_as_not_the_app_is_not_asked_about() {
    let (json, page) = report(&app_with(
        "apart",
        "just-me",
        "[data]\ncategories = []\n\n[repository]\nnot-the-app = [\"legacy\"]\n",
        &[
            ("app.py", "print('hello')\n"),
            (
                "legacy/old.py",
                "diagnosis = 'flu'\n\n@app.route('/signup')\ndef signup():\n    return 'ok'\n",
            ),
        ],
    ));
    assert_eq!(json["target_level"], 1, "the setup: held to level 1");
    assert!(json["level_why"].get("hints").is_none(), "{json}");
    assert!(!page.contains("The code suggests"), "{page}");
}
