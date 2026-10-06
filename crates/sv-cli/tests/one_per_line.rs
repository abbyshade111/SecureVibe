//! What is left on one line of code is one finding, end to end: `sv report` on an app whose one
//! line holds two problems with nothing in common (Semgrep follow-up 3; ADR-023, Later, 6 October
//! 2026).

use std::path::PathBuf;
use std::process::Command;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-one-line-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn two_problems_on_one_line_are_one_entry_naming_both_and_two_sarif_results() {
    let app = scratch("two");
    std::fs::create_dir_all(app.join("src")).unwrap();
    std::fs::write(
        app.join("src/app.js"),
        "function run(input, t) {\n  eval(input); localStorage.setItem('token', t);\n}\n\
         function other(input) {\n  return eval(input);\n}\n",
    )
    .unwrap();
    std::fs::write(
        app.join("securevibe.toml"),
        "manifest-version = 1\n[app]\nname = \"Lines\"\n[stack]\nlanguages = [\"javascript\"]\n",
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

    let findings = json["findings"]
        .as_array()
        .expect("report.json lists findings");
    let on = |line: u64| -> Vec<&serde_json::Value> {
        findings
            .iter()
            .filter(|f| f["location"]["file"] == "src/app.js" && f["location"]["line"] == line)
            .collect()
    };
    // Line 2 is one finding, led by the worse problem, holding the other whole.
    let line2 = on(2);
    assert_eq!(line2.len(), 1, "{line2:?}");
    let f = line2[0];
    assert_eq!(f["rule_id"], "ast.dynamic-code-execution");
    let others = f["also_on_this_line"]
        .as_array()
        .expect("the other is held");
    assert_eq!(others.len(), 1);
    assert_eq!(others[0]["rule_id"], "ast.token-in-browser-storage");
    assert!(
        others[0]["fingerprint"]
            .as_str()
            .is_some_and(|p| !p.is_empty())
    );
    // It names every requirement of both.
    let ids: Vec<&str> = f["requirement_ids"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(ids.contains(&"V10.1.1"), "{ids:?}");
    // Line 5 is its own, untouched.
    assert_eq!(on(5).len(), 1);
    assert!(on(5)[0].get("also_on_this_line").is_none());

    // security.md lists line 2 once, and says what else is on it, with its fingerprint.
    assert_eq!(
        security.matches("`src/app.js` line 2").count(),
        1,
        "{security}"
    );
    assert!(
        security
            .contains("Also on this line, a problem of its own: `ast.token-in-browser-storage`"),
        "{security}"
    );
    assert!(
        security.contains(others[0]["fingerprint"].as_str().unwrap()),
        "{security}"
    );

    // SARIF keeps one result per problem, for the tools that read it.
    let results = sarif["runs"][0]["results"].as_array().expect("results");
    let at_line_2: Vec<&str> = results
        .iter()
        .filter(|r| {
            r["locations"][0]["physicalLocation"]["region"]["startLine"] == 2
                && r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app.js"
        })
        .filter_map(|r| r["ruleId"].as_str())
        .collect();
    let mut at_line_2 = at_line_2;
    at_line_2.sort_unstable();
    assert_eq!(
        at_line_2,
        ["ast.dynamic-code-execution", "ast.token-in-browser-storage"]
    );
}
