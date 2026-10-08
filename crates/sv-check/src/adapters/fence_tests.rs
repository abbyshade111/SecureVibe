//! What a tool's log says, and a link in the app, decide whether it ran and whether a clean run
//! counts (the review of 8 October 2026, item 3). A stand-in script plays the tool: it writes a
//! clean report, and says on its stderr whatever the test puts in `SV_FENCE_LOG`.

use super::*;
use std::os::unix::fs::PermissionsExt;

const FENCE: &str = r#"#!/bin/sh
if [ "$1" = --version ]; then echo 1.0; exit 0; fi
printf '%s\n' "$SV_FENCE_LOG" >&2
if [ -n "$SV_FENCE_NOISE" ]; then head -c "$SV_FENCE_NOISE" /dev/zero | tr '\0' x >&2; echo >&2; fi
printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Fence","rules":[{"id":"F1"}]}},"results":[]}]}' > "$1"
"#;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-fence-unit-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn secret_rules() -> SecretRules {
    SecretRules::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/secret-rules.json"))
        .unwrap()
}

/// A Python tool given the folder (no `{files}`), with one mapped rule so a clean run has
/// something to credit, `env` on its environment, and `extra` fields on its entry.
fn fence(dir: &Path, env: &[(&str, &str)], extra: serde_json::Value) -> Adapter {
    let script = dir.join("fence");
    std::fs::write(&script, FENCE).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let script = script.display().to_string();
    let mut entry = serde_json::json!({
        "id": "fence",
        "name": "Fence",
        "language": "python",
        "version": { "command": script, "args": ["--version"] },
        "run": { "command": script, "args": ["{output}"] },
        "install": "get it",
        "finished_exits": [0],
        "env": env.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect::<BTreeMap<_, _>>(),
        "rules": { "F1": { "what": "an SQL query built by hand", "requirements": ["V1.2.4"] } },
    });
    for (key, value) in extra.as_object().unwrap() {
        entry[key] = value.clone();
    }
    serde_json::from_value(entry).unwrap()
}

/// An app of two Python files.
fn app(dir: &Path) -> PathBuf {
    let app = dir.join("app");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(app.join("a.py"), "print(1)\n").unwrap();
    std::fs::write(app.join("b.py"), "print(2)\n").unwrap();
    app
}

fn run(dir: &Path, adapter: Adapter, app: &Path) -> AdapterRun {
    run_all(
        &Adapters {
            adapters: vec![adapter],
        },
        app,
        &["python".to_owned()],
        &BTreeSet::new(),
        dir,
        &secret_rules(),
    )
}

#[test]
fn a_tool_that_follows_links_is_not_run_over_an_app_that_holds_one() {
    let dir = scratch("links");
    let app = app(&dir);
    let outside = dir.join("outside.py");
    std::fs::write(&outside, "x = 1\n").unwrap();
    std::os::unix::fs::symlink(&outside, app.join("linked.py")).unwrap();
    let out = run(
        &dir,
        fence(&dir, &[], serde_json::json!({ "follows_links": true })),
        &app,
    );
    assert!(out.ran.is_empty() && out.verified.is_empty(), "{out:?}");
    assert_eq!(out.not_run.len(), 1, "{:?}", out.not_run);
    let why = &out.not_run[0].1;
    assert!(
        why.contains("follows a link")
            && why.contains("holds 1 link (`linked.py`)")
            && why.contains("Remove it,"),
        "{why}"
    );
    // The controls: the same tool, not known to follow links, runs over the same app and is
    // credited, since `sv` hands it nothing through the link; and the tool that follows them runs
    // once the link is gone.
    let out = run(&dir, fence(&dir, &[], serde_json::json!({})), &app);
    assert_eq!(out.ran, ["fence"], "{:?}", out.not_run);
    assert_eq!(out.verified.len(), 1);
    std::fs::remove_file(app.join("linked.py")).unwrap();
    let out = run(
        &dir,
        fence(&dir, &[], serde_json::json!({ "follows_links": true })),
        &app,
    );
    assert_eq!(out.ran, ["fence"], "{:?}", out.not_run);
    // Many links: five named, the rest counted.
    for n in 1..=6 {
        std::os::unix::fs::symlink(&outside, app.join(format!("l{n}.py"))).unwrap();
    }
    let out = run(
        &dir,
        fence(&dir, &[], serde_json::json!({ "follows_links": true })),
        &app,
    );
    let why = &out.not_run[0].1;
    assert!(
        why.contains("holds 6 links (`l1.py`, `l2.py`, `l3.py`, `l4.py`, `l5.py`, and 1 more)")
            && why.contains("Remove them,"),
        "{why}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_tool_handed_the_files_cannot_claim_to_follow_links() {
    let dir = scratch("files-and-links");
    let file = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json"),
    )
    .unwrap();
    let doctored = file.replacen(
        "\"id\": \"bandit\",",
        "\"id\": \"bandit\", \"follows_links\": true,",
        1,
    );
    assert_ne!(doctored, file, "bandit is the entry to doctor");
    let path = dir.join("adapters.json");
    std::fs::write(&path, doctored).unwrap();
    let err = Adapters::load(&path).expect_err("refused at load");
    assert!(
        err.to_string()
            .contains("handed {files} and says it follows links"),
        "{err}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_tool_whose_log_names_no_file_as_read_read_nothing() {
    let dir = scratch("read-none");
    let app = app(&dir);
    let out = run(
        &dir,
        fence(
            &dir,
            &[("SV_FENCE_LOG", "[tool] starting")],
            serde_json::json!({ "read_log_prefix": "Checking file: " }),
        ),
        &app,
    );
    assert!(out.verified.is_empty() && out.ran.is_empty(), "{out:?}");
    let why = &out.not_run[0].1;
    assert!(
        why.contains("its log names none of the 2 python files in this app as read"),
        "{why}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_file_the_log_does_not_name_was_not_read_and_the_run_is_not_clean() {
    let dir = scratch("read-some");
    let app = app(&dir);
    let names = |files: &[&str]| {
        files
            .iter()
            .map(|f| {
                format!(
                    "[tool] 2026/10/08 12:00:00 Checking file: {}/{f}",
                    app.display()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let out = run(
        &dir,
        fence(
            &dir,
            &[("SV_FENCE_LOG", &names(&["a.py"]))],
            serde_json::json!({ "read_log_prefix": "Checking file: " }),
        ),
        &app,
    );
    assert!(out.verified.is_empty(), "{:?}", out.verified);
    assert_eq!(out.partly.len(), 1, "{:?}", out.partly);
    let why = &out.partly[0].1;
    assert!(
        why.contains("its log does not say it read 1 of the 2 python files in this app (`b.py`)"),
        "{why}"
    );
    // The control: a log naming both files is a clean run, credited.
    let out = run(
        &dir,
        fence(
            &dir,
            &[("SV_FENCE_LOG", &names(&["a.py", "b.py"]))],
            serde_json::json!({ "read_log_prefix": "Checking file: " }),
        ),
        &app,
    );
    assert_eq!(out.ran, ["fence"], "{:?}", out.not_run);
    assert_eq!(out.verified.len(), 1);
    assert!(out.partly.is_empty(), "{:?}", out.partly);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_log_longer_than_sv_keeps_is_not_a_record_of_what_was_read() {
    let dir = scratch("read-long");
    let app = app(&dir);
    let both = format!(
        "[tool] Checking file: {0}/a.py\n[tool] Checking file: {0}/b.py",
        app.display()
    );
    let with_noise = |bytes: &str| {
        fence(
            &dir,
            &[("SV_FENCE_LOG", &both), ("SV_FENCE_NOISE", bytes)],
            serde_json::json!({ "read_log_prefix": "Checking file: " }),
        )
    };
    let out = run(&dir, with_noise(&(STDERR_KEPT + 1000).to_string()), &app);
    assert!(out.verified.is_empty(), "{:?}", out.verified);
    assert!(
        out.partly[0]
            .1
            .contains("its log was longer than `sv` keeps, so which files it read is not known"),
        "{:?}",
        out.partly
    );
    // The control: the same lines under a little noise are read as they are.
    let out = run(&dir, with_noise("1000"), &app);
    assert_eq!(out.verified.len(), 1, "{:?}", out.partly);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_line_meaning_part_of_the_run_did_not_happen_withholds_the_clean_run() {
    let dir = scratch("unfinished");
    let app = app(&dir);
    let entry = serde_json::json!({
        "unfinished_when": [{
            "contains": "Error building the SSA representation",
            "means": "its deeper analyzers did not run over a package"
        }]
    });
    let out = run(
        &dir,
        fence(
            &dir,
            &[(
                "SV_FENCE_LOG",
                "[tool] Panic when running SSA analyser on package: main\n\
                 [tool] Error building the SSA representation of the package \"main\": %!s(<nil>)",
            )],
            entry.clone(),
        ),
        &app,
    );
    assert!(out.verified.is_empty(), "{:?}", out.verified);
    assert_eq!(
        out.partly[0].1,
        "Fence did not look at all of this app: its deeper analyzers did not run over a package.",
        "{:?}",
        out.partly
    );
    // The control: without the line, the run is clean.
    let out = run(
        &dir,
        fence(&dir, &[("SV_FENCE_LOG", "[tool] fine")], entry),
        &app,
    );
    assert_eq!(out.verified.len(), 1, "{:?}", out.partly);
    std::fs::remove_dir_all(&dir).ok();
}
