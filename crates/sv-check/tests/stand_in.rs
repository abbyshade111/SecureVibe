//! Semgrep runs with its usage reporting and version check off, and Opengrep runs in its place when
//! it is not installed.
//!
//! Two small programs play the parts, found through `PATH` under names nothing else has, because an
//! adapter's command is a plain program name and never a path. Each writes down how it was started
//! (its arguments, and whether the version check was turned off) and, asked to run, writes a report
//! with one of semgrep's mapped rules loaded and nothing found, as the real ones do on a clean app.
//! The Opengrep stand-in refuses `--metrics=off`, as Opengrep 1.30.0 does. Everything else is the
//! real semgrep entry in `adapters.json`: its arguments, its environment, its stand-in.
//!
//! `PATH` belongs to the whole test process, so this file holds one test and every case runs in it
//! in turn.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use sv_check::adapters::{self, AdapterRun, Adapters};

const SEMGREP: &str = "sv-test-fake-semgrep";
const OPENGREP: &str = "sv-test-fake-opengrep";

const FAKE: &str = r#"
import json, os, sys
args = sys.argv[1:]
with open(LOG, "a") as log:
    log.write(json.dumps({"program": NAME, "args": args,
        "version_check": os.environ.get("SEMGREP_ENABLE_VERSION_CHECK")}) + "\n")
if args == ["--version"]:
    if BROKEN:
        sys.stderr.write("cannot load its own libraries\n")
        sys.exit(1)
    print("1.30.0")
    sys.exit(0)
if REFUSES_METRICS and "--metrics=off" in args:
    sys.stderr.write("unknown option --metrics=off\n")
    sys.exit(2)
output = args[args.index("--output") + 1]
scanned = next(a for a in args if a.startswith("--json-output=")).split("=", 1)[1]
files = args[args.index("--") + 1:]
json.dump({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": NAME,
    "rules": [{"id": RULE}]}}, "results": []}]}, open(output, "w"))
json.dump({"paths": {"scanned": [f[2:] for f in files]}}, open(scanned, "w"))
"#;

fn real_adapters() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json")
}

/// The real semgrep entry with only its two program names changed, and one of its rules that a clean
/// run over Python code credits.
fn semgrep_entry(dir: &Path) -> (Adapters, String) {
    let mut file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(real_adapters()).unwrap()).unwrap();
    let mut entry = file["adapters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == "semgrep")
        .unwrap()
        .clone();
    assert_eq!(entry["run"]["command"], "semgrep");
    assert_eq!(entry["stand_in"]["command"], "opengrep");
    entry["version"]["command"] = SEMGREP.into();
    entry["run"]["command"] = SEMGREP.into();
    entry["stand_in"]["command"] = OPENGREP.into();
    let rule = entry["rules"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(_, r)| {
            r["languages"]
                .as_array()
                .is_some_and(|l| l.contains(&"python".into()))
                && r["requirements"].as_array().is_some_and(|q| !q.is_empty())
        })
        .map(|(id, _)| id.clone())
        .expect("semgrep maps a Python rule to a requirement");
    file["adapters"] = serde_json::json!([entry]);
    let path = dir.join("adapters.json");
    std::fs::write(&path, file.to_string()).unwrap();
    (Adapters::load(&path).expect("the entry loads"), rule)
}

/// Puts a fake program on the test's `PATH`, or takes it off with `None`.
fn install(bin: &Path, name: &str, log: &Path, rule: &str, how: Option<Fake>) {
    let path = bin.join(name);
    std::fs::remove_file(&path).ok();
    let Some(how) = how else { return };
    let py = |b: bool| if b { "True" } else { "False" };
    let script = format!(
        "#!/usr/bin/env python3\nLOG = {log:?}\nNAME = {name:?}\nRULE = {rule:?}\nBROKEN = {}\n\
         REFUSES_METRICS = {}\n{FAKE}",
        py(how == Fake::Broken),
        py(name == OPENGREP),
    );
    std::fs::write(&path, script).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fake {
    Works,
    Broken,
}

/// Every start of either program since the log was last cleared: (program, arguments, version check).
fn starts(log: &Path) -> Vec<(String, Vec<String>, Option<String>)> {
    let text = std::fs::read_to_string(log).unwrap_or_default();
    std::fs::remove_file(log).ok();
    text.lines()
        .map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            (
                v["program"].as_str().unwrap().to_owned(),
                v["args"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| a.as_str().unwrap().to_owned())
                    .collect(),
                v["version_check"].as_str().map(str::to_owned),
            )
        })
        .collect()
}

/// The run itself, not the question about its version.
fn runs(
    starts: &[(String, Vec<String>, Option<String>)],
) -> Vec<&(String, Vec<String>, Option<String>)> {
    starts
        .iter()
        .filter(|(_, args, _)| args != &["--version"])
        .collect()
}

#[test]
fn semgrep_runs_quietly_and_opengrep_only_in_its_place() {
    let dir = std::env::temp_dir().join(format!("sv-stand-in-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let app = dir.join("app");
    std::fs::create_dir_all(app.join("src")).unwrap();
    std::fs::write(app.join("src/app.py"), "print(1)\n").unwrap();
    let log = dir.join("starts.log");
    let (adapters, rule) = semgrep_entry(&dir);

    // SAFETY: the only test in this binary, so no other thread reads the environment meanwhile.
    let path = std::env::var("PATH").unwrap_or_default();
    unsafe { std::env::set_var("PATH", format!("{}:{path}", bin.display())) };

    let run = |semgrep: Option<Fake>, opengrep: Option<Fake>| -> AdapterRun {
        install(&bin, SEMGREP, &log, &rule, semgrep);
        install(&bin, OPENGREP, &log, &rule, opengrep);
        std::fs::remove_file(&log).ok();
        let scratch = dir.join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();
        adapters::run_all(
            &adapters,
            &app,
            &["python".to_owned()],
            &Default::default(),
            &scratch,
            &secret_rules(),
        )
    };

    // Semgrep here: it runs with both switches off, and Opengrep is never started, not even asked.
    let outcome = run(Some(Fake::Works), Some(Fake::Works));
    let seen = starts(&log);
    assert!(seen.iter().all(|(p, _, _)| p == SEMGREP), "{seen:?}");
    let ran = runs(&seen);
    assert_eq!(ran.len(), 1, "{seen:?}");
    assert!(
        ran[0].1.contains(&"--metrics=off".to_owned()),
        "{:?}",
        ran[0].1
    );
    assert!(
        seen.iter()
            .all(|(_, _, check)| check.as_deref() == Some("0")),
        "the version check was left on: {seen:?}"
    );
    assert_eq!(outcome.ran, ["semgrep"], "{:?}", outcome.not_run);
    assert!(outcome.stood_in.is_empty(), "{:?}", outcome.stood_in);
    assert_eq!(
        outcome.verified.len(),
        1,
        "a clean run with a mapped rule is credited"
    );

    // Semgrep missing: Opengrep runs with the same arguments less the one it refuses, and the
    // report says so wherever it names the program.
    let outcome = run(None, Some(Fake::Works));
    let seen = starts(&log);
    let ran = runs(&seen);
    assert_eq!(ran.len(), 1, "{seen:?}");
    assert_eq!(ran[0].0, OPENGREP);
    assert!(
        !ran[0].1.contains(&"--metrics=off".to_owned()),
        "{:?}",
        ran[0].1
    );
    for kept in ["p/security-audit", "p/default", "--sarif", "--"] {
        assert!(
            ran[0].1.contains(&kept.to_owned()),
            "{kept} dropped: {:?}",
            ran[0].1
        );
    }
    // `{files}` is this app's one file, so the only difference in count is what was left out.
    let semgrep_args = adapters.all()[0].run_args(&Default::default());
    assert_eq!(ran[0].1.len(), semgrep_args.len() - 1, "{:?}", ran[0].1);
    assert_eq!(ran[0].2.as_deref(), Some("0"));
    assert_eq!(outcome.ran, ["semgrep"], "{:?}", outcome.not_run);
    assert_eq!(
        outcome.stood_in,
        [(
            "semgrep".to_owned(),
            "Opengrep ran in place of Semgrep, which is not installed on this computer.".to_owned()
        )]
    );
    assert_eq!(outcome.verified.len(), 1, "{:?}", outcome.not_run);
    let said = format!("{:?}", outcome.verified[0]);
    assert!(said.contains("Opengrep (in place of Semgrep)"), "{said}");

    // Neither here: not run, and the reason names both.
    let outcome = run(None, None);
    assert!(starts(&log).is_empty());
    assert!(outcome.ran.is_empty() && outcome.verified.is_empty());
    let why = &outcome.not_run[0].1;
    assert!(why.contains("Semgrep is not installed"), "{why}");
    assert!(
        why.contains("Opengrep, which can run in its place, is not installed either"),
        "{why}"
    );

    // Opengrep here and broken: asked its version, never run, and its words reach the reason.
    let outcome = run(None, Some(Fake::Broken));
    let seen = starts(&log);
    assert!(runs(&seen).is_empty(), "{seen:?}");
    assert!(outcome.ran.is_empty() && outcome.stood_in.is_empty());
    let why = &outcome.not_run[0].1;
    assert!(why.contains("would not start"), "{why}");
    assert!(why.contains("cannot load its own libraries"), "{why}");

    // Semgrep here and broken: that is the owner's to fix, so Opengrep is not tried in its place.
    let outcome = run(Some(Fake::Broken), Some(Fake::Works));
    let seen = starts(&log);
    assert!(seen.iter().all(|(p, _, _)| p == SEMGREP), "{seen:?}");
    assert!(outcome.ran.is_empty() && outcome.stood_in.is_empty());
    let why = &outcome.not_run[0].1;
    assert!(
        why.starts_with("Semgrep is installed and would not start"),
        "{why}"
    );

    unsafe { std::env::set_var("PATH", path) };
    std::fs::remove_dir_all(&dir).ok();
}

/// `sv`'s own credential rules, which redact what a tool says.
fn secret_rules() -> sv_check::secrets::SecretRules {
    sv_check::secrets::SecretRules::load(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/secret-rules.json"),
    )
    .expect("the secret rules load")
}
