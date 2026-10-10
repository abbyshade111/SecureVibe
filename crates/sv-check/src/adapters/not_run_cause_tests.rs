//! What kind of reason an outside tool did not run (`NotRunCause`), carried beside the sentence that
//! says it, so the report can say it to a program as well as to a person.

use super::*;
use std::os::unix::fs::PermissionsExt;

/// Answers its version, and then fails with an exit code the adapter does not count as finishing.
const FAILS: &str = r#"#!/bin/sh
if [ "$1" = --version ]; then echo "faketool 1.0"; exit 0; fi
exit 7
"#;

/// Answers its version, and then finishes without writing the report it was asked for.
const SILENT: &str = r#"#!/bin/sh
if [ "$1" = --version ]; then echo "faketool 1.0"; exit 0; fi
exit 0
"#;

fn adapter(tool: &Path) -> Adapter {
    let tool = tool.display().to_string();
    serde_json::from_value(serde_json::json!({
        "id": "fake",
        "name": "Fake",
        "language": "python",
        "version": { "command": tool, "args": ["--version"] },
        "run": { "command": tool, "args": ["{dir}", "{output}"] },
        "install": "get fake",
        "finished_exits": [0, 1],
        "rules": {},
    }))
    .unwrap()
}

/// The one tool's cause, run over a one-file Python app; `script` is written as the tool first,
/// unless it is `None`, when the tool is left missing.
fn cause_of(name: &str, script: Option<&str>) -> (NotRunCause, String) {
    let dir = std::env::temp_dir().join(format!("sv-not-run-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(dir.join("app")).unwrap();
    std::fs::write(dir.join("app/app.py"), "print(1)\n").unwrap();
    let tool = dir.join("faketool");
    match script {
        Some(script) => {
            crate::test_support::executable(&tool, script);
            // The setup: the tool is there and can be run, so what follows is about how it ran.
            let mode = std::fs::metadata(&tool)
                .expect("the tool was written")
                .permissions()
                .mode();
            assert!(mode & 0o111 != 0, "the tool is not executable: {mode:o}");
        }
        None => assert!(!tool.exists(), "a tool meant to be missing is there"),
    }
    let rules = SecretRules::load(&sv_frameworks::data::file("secret-rules.json")).unwrap();
    let run = run_all(
        &Adapters {
            adapters: vec![adapter(&tool)],
        },
        &dir.join("app"),
        &["python".to_owned()],
        &BTreeSet::new(),
        &dir,
        &rules,
    );
    std::fs::remove_dir_all(&dir).ok();
    assert!(run.ran.is_empty(), "{run:?}");
    assert_eq!(run.not_run.len(), 1, "{run:?}");
    let (id, why, cause) = run.not_run[0].clone();
    assert_eq!(id, "fake");
    (cause, why)
}

#[test]
fn a_tool_that_is_not_there_is_not_installed() {
    let (cause, why) = cause_of("missing", None);
    assert_eq!(cause, NotRunCause::NotInstalled, "{why}");
    assert!(why.contains("is not installed"), "{why}");
}

#[test]
fn a_tool_that_fails_was_stopped() {
    let (cause, why) = cause_of("fails", Some(FAILS));
    assert_eq!(cause, NotRunCause::Stopped, "{why}");
    assert!(why.contains("exit code 7"), "{why}");
}

#[test]
fn a_tool_that_writes_no_report_could_not_be_read() {
    let (cause, why) = cause_of("silent", Some(SILENT));
    assert_eq!(cause, NotRunCause::CouldNotRead, "{why}");
    assert!(why.contains("wrote no report"), "{why}");
}
