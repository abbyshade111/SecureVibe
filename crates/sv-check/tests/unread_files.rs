//! A tool that decides for itself which files to skip is handed the files instead.
//!
//! Given a folder, semgrep 1.178.0 leaves out `tests/`, `test/`, anything `.gitignore` covers and
//! anything the app's own `.semgrepignore` names, and its SARIF says nothing about any of it. A clean
//! run was credited as if it had read them. It is now given the app's code files by name, which it
//! reads whatever those say, and the list of files it writes is checked against the list it was
//! given.
//!
//! Semgrep is not installed where these run, so a stand-in plays it: a few lines of Python that
//! write a report with one rule loaded and nothing found, and a list of the files it was given,
//! leaving out any whose path contains `SV_FAKE_SKIP`. What is exercised is `run_all` itself.

mod scratch;

use scratch::Scratch;
use std::path::{Path, PathBuf};
use sv_check::adapters::{self, Adapters};

const RULE: &str = "python.aws-lambda.security.mysql-sqli.mysql-sqli";

/// Writes the report to argv[1], and, unless told not to, the list of files read to argv[2]. The
/// file names follow `--`.
const FAKE: &str = r#"
import json, os, sys
report, scanned = sys.argv[1], sys.argv[2]
files = sys.argv[sys.argv.index("--") + 1:]
rule = os.environ["SV_FAKE_RULE"]
json.dump({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep",
    "rules": [{"id": rule}]}}, "results": []}]}, open(report, "w"))
skip = os.environ.get("SV_FAKE_SKIP")
if os.environ.get("SV_FAKE_NO_LIST") != "1":
    read = [f[2:] for f in files if not (skip and skip in f)]
    json.dump({"paths": {"scanned": read}}, open(scanned, "w"))
"#;

fn real_adapters() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json")
}

fn scratch(name: &str) -> Scratch {
    Scratch::new(&format!("unread-{name}"))
}

/// The real semgrep entry, its rules and its arguments, with the command swapped for the stand-in.
/// Only the command and the fixed flags before `--output` change; `{output}`, `{scanned}`, `--` and
/// `{files}` are the ones in `adapters.json`.
fn stand_in(dir: &Path, env: &[(&str, &str)]) -> Adapters {
    let mut file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(real_adapters()).unwrap()).unwrap();
    let mut entry = file["adapters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == "semgrep")
        .unwrap()
        .clone();
    let real: Vec<String> = entry["run"]["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap().to_owned())
        .collect();
    assert!(real.iter().any(|a| a == "{files}"), "{real:?}");
    let output = real.iter().find(|a| a.contains("{output}")).unwrap();
    let scanned = real.iter().find(|a| a.contains("{scanned}")).unwrap();
    assert_eq!(scanned, "--json-output={scanned}");
    let script = dir.join("fake.py");
    let mut prelude = String::from("import os\n");
    for (k, v) in env {
        prelude.push_str(&format!("os.environ[{k:?}] = {v:?}\n"));
    }
    std::fs::write(&script, format!("{prelude}{FAKE}")).unwrap();
    let from = real.iter().position(|a| a == "--").unwrap();
    let mut args = vec![
        script.to_string_lossy().to_string(),
        output.clone(),
        "{scanned}".to_owned(),
    ];
    args.extend(real[from..].iter().cloned());
    // The fixed flags are gone, `--metrics=off` with them, and Opengrep plays no part here.
    entry.as_object_mut().unwrap().remove("stand_in");
    entry["version"] = serde_json::json!({ "command": "true" });
    entry["run"] = serde_json::json!({ "command": "python3", "args": args });
    file["adapters"] = serde_json::json!([entry]);
    let path = dir.join("adapters.json");
    std::fs::write(&path, file.to_string()).unwrap();
    Adapters::load(&path).expect("the stand-in loads")
}

/// A small Python app with code in `src/` and `tests/`, and a dependency folder that is not its own.
fn app(dir: &Path) -> PathBuf {
    let app = dir.join("app");
    for (path, text) in [
        ("src/app.py", "print(1)\n"),
        ("tests/test_app.py", "print(2)\n"),
        ("node_modules/x/index.js", "1\n"),
        ("README.md", "notes\n"),
    ] {
        let path = app.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    app
}

fn run(name: &str, env: &[(&str, &str)]) -> adapters::AdapterRun {
    let dir = scratch(name);
    let app = app(&dir);
    let mut env = env.to_vec();
    env.push(("SV_FAKE_RULE", RULE));
    let adapters = stand_in(&dir, &env);
    let outcome = adapters::run_all(
        &adapters,
        &app,
        &["python".to_owned()],
        &Default::default(),
        &dir,
        &secret_rules(),
    );
    std::fs::remove_dir_all(&dir).ok();
    outcome
}

#[test]
fn the_app_s_code_files_are_what_sv_itself_reads() {
    let dir = scratch("files");
    let app = app(&dir);
    let files = adapters::code_files(&app);
    std::fs::remove_dir_all(&dir).ok();
    // `tests/` is the app's, and in the list; `node_modules` is somebody else's, as it is for every
    // other check here; a README is not code.
    assert_eq!(files, ["src/app.py", "tests/test_app.py"]);
}

#[cfg(unix)]
#[test]
fn a_link_out_of_the_app_is_not_followed() {
    // The tool reads whatever it is named, so a link to a folder elsewhere would hand it files
    // that are not the app's. The link is there and resolves; nothing behind it is listed.
    let dir = scratch("link");
    let app = app(&dir);
    let elsewhere = dir.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::write(elsewhere.join("secret.py"), "x = 1\n").unwrap();
    std::os::unix::fs::symlink(&elsewhere, app.join("src/linked")).unwrap();
    std::os::unix::fs::symlink(elsewhere.join("secret.py"), app.join("src/one.py")).unwrap();
    assert!(app.join("src/linked/secret.py").exists());
    let files = adapters::code_files(&app);
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(files, ["src/app.py", "tests/test_app.py"]);
}

#[test]
fn a_run_that_read_every_file_it_was_given_is_credited() {
    // The control: without it, the tests below would pass just as well if the stand-in's clean
    // run were never credited at all.
    let outcome = run("all-read", &[]);
    assert!(outcome.not_run.is_empty(), "{:?}", outcome.not_run);
    assert_eq!(outcome.verified.len(), 1);
    assert_eq!(outcome.verified[0].requirement_ids, ["V1.2.4"]);
}

#[test]
fn a_file_it_was_given_and_did_not_read_withholds_the_clean_run() {
    let outcome = run("skipped", &[("SV_FAKE_SKIP", "tests/")]);
    assert!(outcome.verified.is_empty(), "{:?}", outcome.verified);
    let why = &outcome.not_run[0].1;
    assert!(
        why.contains(
            "did not read 1 of the 2 files it was given that a rule it loaded reads (`tests/test_app.py`)"
        ),
        "{why}"
    );
}

#[test]
fn a_run_that_says_nothing_about_what_it_read_withholds_it_too() {
    let outcome = run("no-list", &[("SV_FAKE_NO_LIST", "1")]);
    assert!(outcome.verified.is_empty(), "{:?}", outcome.verified);
    assert!(
        outcome.not_run[0].1.contains("did not write the list"),
        "{:?}",
        outcome.not_run
    );
}

#[test]
fn a_list_left_by_an_earlier_run_does_not_vouch_for_this_one() {
    // An earlier run's list, naming every file, sits where this run's would go, and this run
    // writes none. It must not be read.
    let dir = scratch("stale");
    let app = app(&dir);
    let adapters = stand_in(&dir, &[("SV_FAKE_RULE", RULE), ("SV_FAKE_NO_LIST", "1")]);
    std::fs::write(
        dir.join("sv-semgrep.scanned.json"),
        r#"{"paths":{"scanned":["src/app.py","tests/test_app.py"]}}"#,
    )
    .unwrap();
    let outcome = adapters::run_all(
        &adapters,
        &app,
        &["python".to_owned()],
        &Default::default(),
        &dir,
        &secret_rules(),
    );
    std::fs::remove_dir_all(&dir).ok();
    assert!(outcome.verified.is_empty(), "{:?}", outcome.verified);
    assert!(
        outcome.not_run[0].1.contains("did not write the list"),
        "{:?}",
        outcome.not_run
    );
}

#[test]
fn a_rule_for_templates_counts_only_when_a_template_was_handed_over() {
    // ADR-018, Later, 7 October 2026. The Django template rule reads only `*.html`. Over the app's
    // Python alone it ran over nothing; with a template among the files `sv` hands semgrep, it
    // read one, and its clean run is evidence.
    const TEMPLATE_RULE: &str =
        "python.django.security.audit.xss.template-autoescape-off.template-autoescape-off";
    let credited = |with_template: bool| {
        let dir = scratch(if with_template {
            "template"
        } else {
            "no-template"
        });
        let app = app(&dir);
        if with_template {
            std::fs::create_dir_all(app.join("templates")).unwrap();
            std::fs::write(app.join("templates/index.html"), "<p>{{ name }}</p>\n").unwrap();
        }
        let adapters = stand_in(&dir, &[("SV_FAKE_RULE", TEMPLATE_RULE)]);
        let outcome = adapters::run_all(
            &adapters,
            &app,
            &["python".to_owned(), "html".to_owned()],
            &Default::default(),
            &dir,
            &secret_rules(),
        );
        std::fs::remove_dir_all(&dir).ok();
        // The run itself was clean and read everything it was given, either way.
        assert!(outcome.not_run.is_empty(), "{:?}", outcome.not_run);
        outcome
            .verified
            .iter()
            .flat_map(|v| v.requirement_ids.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(credited(true), ["V1.2.1"]);
    assert!(credited(false).is_empty(), "{:?}", credited(false));
}

#[test]
fn unread_files_are_counted_and_the_first_few_named() {
    let given: Vec<String> = (0..8).map(|i| format!("src/m{i}.py")).collect();
    let scanned = r#"{"paths":{"scanned":["./src/m0.py","src/m1.py"]}}"#;
    let why = adapters::unread_files(&given, Some(scanned), &|_| true).unwrap();
    assert!(why.contains("did not read 6 of the 8"), "{why}");
    assert!(
        why.contains("`src/m2.py`") && why.contains("and others"),
        "{why}"
    );
    assert!(
        !why.contains("`src/m1.py`"),
        "a file it read is not named: {why}"
    );
    let all = r#"{"paths":{"scanned":["src/m0.py","src/m1.py","src/m2.py","src/m3.py","src/m4.py","src/m5.py","src/m6.py","src/m7.py"]}}"#;
    assert_eq!(adapters::unread_files(&given, Some(all), &|_| true), None);
    assert!(
        adapters::unread_files(&given, Some(r#"{"paths":{}}"#), &|_| true)
            .unwrap()
            .contains("does not say which")
    );
}

#[test]
fn file_names_are_only_ever_a_whole_argument_and_only_inside_the_app() {
    let dir = scratch("load");
    let base: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(real_adapters()).unwrap()).unwrap();
    let doctored = |change: &dyn Fn(&mut serde_json::Value)| {
        let mut file = base.clone();
        let semgrep = file["adapters"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|a| a["id"] == "semgrep")
            .unwrap();
        change(semgrep);
        let path = dir.join("adapters.json");
        std::fs::write(&path, file.to_string()).unwrap();
        Adapters::load(&path)
    };
    let glued = doctored(&|a| a["run"]["args"] = serde_json::json!(["--x={files}"]));
    let outside = doctored(&|a| {
        a.as_object_mut().unwrap().remove("working_directory");
    });
    let untouched = doctored(&|_| {});
    std::fs::remove_dir_all(&dir).ok();
    assert!(glued.unwrap_err().to_string().contains("inside another"));
    assert!(
        outside
            .unwrap_err()
            .to_string()
            .contains("not run inside the app")
    );
    assert!(untouched.is_ok());
}

fn run_over(name: &str, app: impl Fn(&Path) -> PathBuf) -> adapters::AdapterRun {
    let dir = scratch(name);
    let app = app(&dir);
    let adapters = stand_in(&dir, &[("SV_FAKE_RULE", RULE)]);
    let outcome = adapters::run_all(
        &adapters,
        &app,
        &["python".to_owned()],
        &Default::default(),
        &dir,
        &secret_rules(),
    );
    std::fs::remove_dir_all(&dir).ok();
    outcome
}

#[test]
fn an_app_with_no_code_to_name_is_not_run() {
    // Named no files, semgrep reads the folder it is started in, ignores and all; the stand-in
    // would write an empty list, which leaves nothing unread and would be credited. Neither is a
    // look at the app.
    let outcome = run_over("no-code", |dir| {
        let app = dir.join("app");
        std::fs::create_dir_all(app.join("docs")).unwrap();
        std::fs::write(app.join("docs/notes.md"), "notes\n").unwrap();
        app
    });
    assert!(outcome.verified.is_empty(), "{:?}", outcome.verified);
    assert!(
        outcome.not_run[0].1.contains("no code in this app"),
        "{:?}",
        outcome.not_run
    );
}

#[test]
fn too_many_files_to_name_is_said_rather_than_cut_short() {
    // 3,000 names of about ninety characters: past the limit, well short of what a system allows.
    let outcome = run_over("many", |dir| {
        let app = dir.join("app");
        let deep = app.join("src/a_folder_name_long_enough_to_matter/another_level_of_folders");
        std::fs::create_dir_all(&deep).unwrap();
        for i in 0..3000 {
            std::fs::write(deep.join(format!("module_number_{i:05}.py")), "").unwrap();
        }
        app
    });
    assert!(outcome.verified.is_empty(), "{:?}", outcome.verified);
    assert!(
        outcome.not_run[0].1.contains("3000 code files, too many"),
        "{:?}",
        outcome.not_run
    );
}

/// `sv`'s own credential rules, which redact what a tool says.
fn secret_rules() -> sv_check::secrets::SecretRules {
    sv_check::secrets::SecretRules::load(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/secret-rules.json"),
    )
    .expect("the secret rules load")
}

/// `run`, with more files in the app and another rule loaded.
fn run_with(
    name: &str,
    rule: &str,
    extra: &[(&str, &str)],
    env: &[(&str, &str)],
) -> adapters::AdapterRun {
    let dir = scratch(name);
    let app = app(&dir);
    for (path, text) in extra {
        let path = app.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    let mut env = env.to_vec();
    env.push(("SV_FAKE_RULE", rule));
    let adapters = stand_in(&dir, &env);
    let outcome = adapters::run_all(
        &adapters,
        &app,
        &["python".to_owned()],
        &Default::default(),
        &dir,
        &secret_rules(),
    );
    std::fs::remove_dir_all(&dir).ok();
    outcome
}

#[test]
fn a_file_no_loaded_rule_reads_is_not_called_unread() {
    // Gap analysis, item 34. Semgrep leaves out, without a word, a handed file no rule it loaded
    // reads (semgrep 1.180.0). With only a Python rule loaded, a Handlebars page and a notebook were
    // never going to be read, and the Python rule's clean run stands.
    let extra = [
        ("views/page.hbs", "<p>{{name}}</p>\n"),
        ("analysis.ipynb", "{}\n"),
    ];
    for skip in [".hbs", ".ipynb"] {
        let outcome = run_with("not-its-files", RULE, &extra, &[("SV_FAKE_SKIP", skip)]);
        assert!(outcome.not_run.is_empty(), "{skip}: {:?}", outcome.not_run);
        assert_eq!(outcome.verified.len(), 1, "{skip}");
    }
    // The Python file it does read, left out, still withholds it.
    let outcome = run_with("its-files", RULE, &extra, &[("SV_FAKE_SKIP", "src/")]);
    assert!(outcome.verified.is_empty(), "{:?}", outcome.verified);
    assert!(
        outcome.not_run[0].1.contains("`src/app.py`"),
        "{:?}",
        outcome.not_run
    );
}

#[test]
fn a_configuration_file_a_rule_names_is_handed_over_and_must_be_read() {
    // Gap analysis, item 34. The nginx rule reads only `*.conf`, which is not code, so it was never
    // handed over and ran over nothing. Now it is, and its clean run is evidence; left unread, it
    // withholds the run.
    const NGINX: &str = "generic.nginx.security.insecure-ssl-version.insecure-ssl-version";
    let extra = [("deploy/site.conf", "server { listen 443 ssl; }\n")];
    let outcome = run_with("conf-read", NGINX, &extra, &[]);
    assert!(outcome.not_run.is_empty(), "{:?}", outcome.not_run);
    let credited: Vec<String> = outcome
        .verified
        .iter()
        .flat_map(|v| v.requirement_ids.clone())
        .collect();
    assert_eq!(credited, ["V12.1.1"]);

    let outcome = run_with(
        "conf-unread",
        NGINX,
        &extra,
        &[("SV_FAKE_SKIP", "site.conf")],
    );
    assert!(outcome.verified.is_empty(), "{:?}", outcome.verified);
    assert!(
        outcome.not_run[0].1.contains("`deploy/site.conf`"),
        "{:?}",
        outcome.not_run
    );

    // Without a configuration file, the rule ran over nothing and credits nothing.
    let outcome = run_with("conf-none", NGINX, &[], &[]);
    assert!(outcome.verified.is_empty(), "{:?}", outcome.verified);
}

#[test]
fn which_files_a_loaded_rule_reads() {
    let adapters = Adapters::load(&real_adapters()).unwrap();
    let semgrep = adapters.all().iter().find(|a| a.id == "semgrep").unwrap();
    let reads = |rule: &str, file: &str| {
        let loaded = std::collections::BTreeSet::from([rule.to_owned()]);
        adapters::read_by_a_loaded_rule(semgrep, &loaded, file)
    };
    // A Python rule reads Python, and not a page or a notebook.
    assert!(reads(RULE, "src/app.py"));
    assert!(!reads(RULE, "views/page.hbs"));
    assert!(!reads(RULE, "analysis.ipynb"));
    // A rule of any language with no `paths.include` (Semgrep's `generic`) reads every file.
    const ANY: &str = "generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value";
    assert!(reads(ANY, "views/page.ejs") && reads(ANY, "analysis.ipynb"));
    // One with a `paths.include` reads what it names.
    const EJS: &str =
        "javascript.express.security.audit.xss.ejs.explicit-unescape.template-explicit-unescape";
    assert!(reads(EJS, "views/page.ejs"));
    assert!(!reads(EJS, "views/page.hbs"));
    // Semgrep's JavaScript parser reads TypeScript too, and not `.mts`.
    let js = semgrep
        .rules
        .iter()
        .find(|(_, r)| r.languages == ["javascript"] && r.targets.is_empty())
        .map(|(id, _)| id.clone())
        .expect("a JavaScript-only rule in the map");
    assert!(reads(&js, "src/a.ts") && !reads(&js, "src/a.mts"));
    // A rule it did not load reads nothing.
    let loaded = std::collections::BTreeSet::new();
    assert!(!adapters::read_by_a_loaded_rule(
        semgrep,
        &loaded,
        "src/app.py"
    ));
}
