//! What each outside tool was and how its run went, kept for the report (backlog 226, part 2, item
//! 14): the version line it answered on stdout, its arguments as the adapter writes them, its exit
//! code, and how long it took.

use super::*;

const TOOL: &str = r#"#!/bin/sh
if [ "$1" = --version ]; then echo "faketool 4.2.1 (build 77)"; exit 0; fi
printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Fake","rules":[]}},"results":[]}]}' > "$2"
exit 1
"#;

#[test]
fn a_tool_s_version_line_arguments_exit_code_and_time_are_kept() {
    let dir = std::env::temp_dir().join(format!("sv-tool-run-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(dir.join("app")).unwrap();
    std::fs::write(dir.join("app/app.py"), "print(1)\n").unwrap();
    let tool = dir.join("faketool");
    crate::test_support::executable(&tool, TOOL);
    let tool = tool.display().to_string();
    let adapter: Adapter = serde_json::from_value(serde_json::json!({
        "id": "fake",
        "name": "Fake",
        "language": "python",
        "version": { "command": tool, "args": ["--version"] },
        "run": { "command": tool, "args": ["{dir}", "{output}"] },
        "install": "get fake",
        "finished_exits": [0, 1],
        "rules": {},
    }))
    .unwrap();
    let rules = SecretRules::load(&sv_frameworks::data::file("secret-rules.json")).unwrap();
    let run = run_all(
        &Adapters {
            adapters: vec![adapter],
        },
        &dir.join("app"),
        &["python".to_owned()],
        &BTreeSet::new(),
        &dir,
        &rules,
    );
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(run.tools.len(), 1, "{run:?}");
    let (id, record) = &run.tools[0];
    assert_eq!(id, "fake");
    assert_eq!(record.program, "Fake");
    assert_eq!(
        record.version.as_deref(),
        Some("faketool 4.2.1 (build 77)"),
        "the version line on stdout was not kept"
    );
    assert_eq!(
        record.args,
        ["{dir}", "{output}"],
        "a path of this computer was kept"
    );
    assert_eq!(record.exit_code, Some(1));
    assert!(run.ran.contains(&"fake".to_owned()), "{run:?}");
    // The report it wrote is held for `--keep-tool-output` (backlog 0229, part 4), and never goes
    // into `report.json` with the rest of the record.
    assert!(
        record
            .output
            .as_deref()
            .is_some_and(|o| o.contains(r#""name":"Fake""#)),
        "{record:?}"
    );
    // Checked as a key of the record's own JSON object: the report is a string inside it, so its
    // text is escaped there, and a search for its own text would never find it.
    let value = serde_json::to_value(record).unwrap();
    assert!(
        value.get("output").is_none(),
        "the report leaked into the record: {value}"
    );
}
