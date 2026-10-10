//! Each outside tool says its name as it begins, so a person watching `sv report --tools` at a
//! terminal sees which one is running (backlog 226, part 2, item 15).

use super::*;
use std::cell::RefCell;

const TOOL: &str = r#"#!/bin/sh
if [ "$1" = --version ]; then echo "faketool 1.0"; exit 0; fi
printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Fake","rules":[]}},"results":[]}]}' > "$2"
exit 0
"#;

fn adapter(id: &str, name: &str, tool: &str) -> Adapter {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "name": name,
        "language": "python",
        "version": { "command": tool, "args": ["--version"] },
        "run": { "command": tool, "args": ["{dir}", "{output}"] },
        "install": "get it",
        "finished_exits": [0],
        "rules": {},
    }))
    .unwrap()
}

#[test]
fn each_tool_is_named_as_it_begins_in_the_order_they_run() {
    let dir = std::env::temp_dir().join(format!("sv-tool-progress-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(dir.join("app")).unwrap();
    std::fs::write(dir.join("app/app.py"), "print(1)\n").unwrap();
    let tool = dir.join("faketool");
    crate::test_support::executable(&tool, TOOL);
    let tool = tool.display().to_string();
    let rules = SecretRules::load(&sv_frameworks::data::file("secret-rules.json")).unwrap();
    let said = RefCell::new(Vec::new());
    let run = run_all_in(
        &Adapters {
            adapters: vec![
                adapter("one", "First", &tool),
                adapter("two", "Second", &tool),
            ],
        },
        &sv_scan::files::Listing::of(&dir.join("app")),
        &["python".to_owned()],
        &BTreeSet::new(),
        &dir,
        &rules,
        &|name| said.borrow_mut().push(name.to_owned()),
    );
    std::fs::remove_dir_all(&dir).ok();
    // The setup: both tools really ran, so the names stand for runs and not for skips.
    assert_eq!(run.ran, ["one", "two"], "{run:?}");
    assert_eq!(said.into_inner(), ["First", "Second"]);
}
