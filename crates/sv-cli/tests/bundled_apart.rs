//! A copy of another project's library kept in the app, listed apart from the app's own code, end
//! to end: `sv report` on an app with jQuery in `public/js` (Semgrep follow-up 1).

use std::path::PathBuf;
use std::process::Command;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-bundled-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The same code-running call in the app's own script and in a copy of jQuery, whose build opens
/// with its own banner.
const CALL: &str = "function run(input) {\n  return eval(input);\n}\n";

#[test]
fn a_finding_in_a_copied_library_is_listed_apart_named_for_it_and_still_counts() {
    let app = scratch("jquery");
    std::fs::create_dir_all(app.join("public/js")).unwrap();
    std::fs::write(app.join("public/js/app.js"), CALL).unwrap();
    std::fs::write(
        app.join("public/js/jquery.min.js"),
        format!(
            "/*! jQuery v3.6.1 | (c) OpenJS Foundation and other contributors | jquery.org/license */\n{CALL}"
        ),
    )
    .unwrap();
    std::fs::write(
        app.join("stackvet.toml"),
        "manifest-version = 1\n[app]\nname = \"Pages\"\n[stack]\nlanguages = [\"javascript\"]\n",
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
    let security = std::fs::read_to_string(out.join("security.md")).unwrap_or_default();
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap_or_default())
            .unwrap_or_default();
    let compliance = std::fs::read_to_string(out.join("compliance.md")).unwrap_or_default();
    let sarif: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(out.join("findings.sarif")).unwrap_or_default(),
    )
    .unwrap_or_default();
    std::fs::remove_dir_all(&app).ok();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );

    // Both are really found, so a missing one below is not a rule that never ran.
    assert!(security.contains("`public/js/app.js` line 2"), "{security}");
    assert!(
        security.contains("`public/js/jquery.min.js` line 3"),
        "{security}"
    );

    // The app's own first; the copy after, under a heading that says what it is, and named.
    let apart = security
        .find("in copies of other projects' libraries kept in the app")
        .expect(&security);
    let own = security.find("`public/js/app.js` line 2").unwrap();
    let copy = security.find("`public/js/jquery.min.js` line 3").unwrap();
    assert!(own < apart && apart < copy, "{security}");
    assert!(
        security.contains("In a copy of jQuery 3.6.1 kept in the app"),
        "{security}"
    );
    // The summary at the top counts it apart too.
    assert!(
        compliance.contains(
            "1 of them is in copies of other projects' libraries kept in the app, listed after the \
             app's own."
        ),
        "{compliance}"
    );
    // And in SARIF, for a code-scanning service: named on the copy's result, absent on the app's.
    let in_library: Vec<(String, Option<String>)> = sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["ruleId"] == "ast.dynamic-code-execution")
        .map(|r| {
            (
                r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                r["properties"]["inBundledLibrary"]
                    .as_str()
                    .map(str::to_owned),
            )
        })
        .collect();
    assert!(
        in_library.contains(&("public/js/app.js".into(), None))
            && in_library.contains(&(
                "public/js/jquery.min.js".into(),
                Some("jQuery 3.6.1".into())
            )),
        "{in_library:?}"
    );

    let named: Vec<(String, Option<String>)> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule_id"] == "ast.dynamic-code-execution")
        .map(|f| {
            (
                f["location"]["file"].as_str().unwrap().to_owned(),
                f["bundled_library"].as_str().map(str::to_owned),
            )
        })
        .collect();
    assert!(
        named.contains(&("public/js/app.js".into(), None))
            && named.contains(&(
                "public/js/jquery.min.js".into(),
                Some("jQuery 3.6.1".into())
            )),
        "{named:?}"
    );
}

#[test]
fn a_finding_only_in_a_copied_library_still_keeps_its_requirement_from_being_credited() {
    let app = scratch("only-the-copy");
    std::fs::create_dir_all(app.join("public/js")).unwrap();
    std::fs::write(app.join("public/js/app.js"), "export const page = 1;\n").unwrap();
    std::fs::write(
        app.join("public/js/jquery.min.js"),
        format!("/*! jQuery v3.6.1 | (c) OpenJS Foundation */\n{CALL}"),
    )
    .unwrap();
    std::fs::write(
        app.join("stackvet.toml"),
        "manifest-version = 1\n[app]\nname = \"Pages\"\n[stack]\nlanguages = [\"javascript\"]\n",
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
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap_or_default())
            .unwrap_or_default();
    std::fs::remove_dir_all(&app).ok();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let requirement = json["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "V1.3.2")
        .expect("V1.3.2 applies")
        .clone();
    assert_eq!(requirement["status"], "needs-attention", "{requirement}");
    assert!(
        requirement["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "ast.dynamic-code-execution"),
        "{requirement}"
    );
}
