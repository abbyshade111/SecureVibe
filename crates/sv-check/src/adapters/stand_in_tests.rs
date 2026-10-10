//! The tests of `adapters.rs` that were `mod stand_in_tests` inside it until 8 October 2026, moved out so
//! two sessions adding a test do not meet in one file (the architecture assessment of that day, item 11).

//! The stand-in, with each program a script named by its full path, so nothing here depends on
//! `PATH` (`tests/stand_in.rs` runs the real semgrep entry through it instead). The stand-in
//! refuses `--refused`, and answers or writes a report only when the adapter's environment
//! reached it.
use super::*;

const OTHER: &str = r#"#!/bin/sh
if [ "$1" = --version ]; then
  [ "$SV_TEST_SWITCH" = off ] && exit 0
  echo "the switch did not reach the version question" >&2; exit 1
fi
for a in "$@"; do [ "$a" = --refused ] && { echo "unknown option --refused" >&2; exit 2; }; done
[ "$SV_TEST_SWITCH" = off ] || exit 3
printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Other","rules":[{"id":"%s"}]}},"results":[]}]}' "$RULE" > "$1"
"#;

fn script(dir: &Path, name: &str, text: &str) -> String {
    let path = dir.join(name);
    crate::test_support::executable(&path, text);
    path.display().to_string()
}

/// An adapter named Primary whose program is `primary`, with Other standing in, and one of
/// semgrep's real mapped Python rules so a clean run has something to credit.
fn adapter(dir: &Path, primary: &str) -> (Adapter, String) {
    let file: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let semgrep = file["adapters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == "semgrep")
        .unwrap();
    let (rule, mapped) = semgrep["rules"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(_, r)| {
            r["languages"]
                .as_array()
                .is_some_and(|l| l.contains(&"python".into()))
                && r["requirements"].as_array().is_some_and(|q| !q.is_empty())
        })
        .unwrap();
    let other = script(dir, "other", &OTHER.replace("$RULE", rule));
    let adapter = serde_json::from_value(serde_json::json!({
        "id": "primary",
        "name": "Primary",
        "language": "python",
        "version": { "command": primary, "args": ["--version"] },
        "run": { "command": primary, "args": ["--refused", "{output}"] },
        "install": "get primary",
        "env": { "SV_TEST_SWITCH": "off" },
        "finished_exits": [0],
        "stand_in": { "name": "Other", "command": other, "leave_out": ["--refused"] },
        "rules": { rule: mapped },
    }))
    .unwrap();
    (adapter, rule.clone())
}

fn run(dir: &Path, adapter: Adapter) -> AdapterRun {
    let app = dir.join("app");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(app.join("app.py"), "print(1)\n").unwrap();
    run_all(
        &Adapters {
            adapters: vec![adapter],
        },
        &app,
        &["python".to_owned()],
        &BTreeSet::new(),
        dir,
        &secret_rules(),
    )
}

/// `sv`'s own credential rules, which redact what a tool says.
fn secret_rules() -> SecretRules {
    SecretRules::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/secret-rules.json"))
        .unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-stand-in-unit-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn the_stand_in_runs_in_a_missing_program_s_place_and_is_named() {
    let dir = scratch("missing");
    let (adapter, rule) = adapter(&dir, &dir.join("not-here").display().to_string());
    let outcome = run(&dir, adapter);
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(outcome.ran, ["primary"], "{:?}", outcome.not_run);
    assert_eq!(
        outcome.stood_in,
        [(
            "primary".to_owned(),
            "Other ran in place of Primary, which is not installed on this computer.".to_owned()
        )]
    );
    assert_eq!(outcome.verified.len(), 1, "{rule} credited by a clean run");
    let credit = format!("{:?}", outcome.verified[0]);
    assert!(
        credit.contains("Other (in place of Primary) over the python in this app"),
        "{credit}"
    );
}

#[test]
fn a_program_inside_the_app_is_not_run_and_the_same_one_outside_is() {
    let dir = scratch("inside");
    let (rule, _) = {
        let (adapter, rule) = adapter(&dir, "unused");
        (rule, adapter)
    };
    // The control: the tool outside the app runs and its clean report is credited.
    let outside = tool(&dir, &rule, "CLEAN");
    let outcome = run(&dir, outside.clone());
    assert_eq!(outcome.ran, ["primary"], "{:?}", outcome.not_run);
    // The same script, inside the app where an activated virtual environment would put it.
    let inside = dir.join("app/.venv/bin/tool");
    std::fs::create_dir_all(inside.parent().unwrap()).unwrap();
    std::fs::copy(&outside.run.command, &inside).unwrap();
    let mut planted = outside.clone();
    planted.version.command = inside.display().to_string();
    planted.run.command = inside.display().to_string();
    let outcome = run(&dir, planted);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        outcome.ran.is_empty() && outcome.verified.is_empty(),
        "{outcome:?}"
    );
    let why = &outcome.not_run[0].1;
    assert!(
        why.starts_with("Tool would run from inside the app (") && why.contains(".venv/bin/tool"),
        "{why}"
    );
    assert!(why.contains("Install Tool outside the app"), "{why}");
}

#[test]
fn a_tool_that_asks_for_a_settings_file_is_given_an_empty_one_of_svs_own() {
    let dir = scratch("settings");
    let (rule, _) = {
        let (adapter, rule) = adapter(&dir, "unused");
        (rule, adapter)
    };
    // The tool: refuses to run unless its `-c` names a file holding exactly the empty
    // settings, outside the app, then writes a clean report.
    let mut tool = tool(&dir, &rule, "CLEAN");
    let text = std::fs::read_to_string(&tool.run.command).unwrap().replace(
        "[ \"$1\" = --version ] && exit 0\n",
        &format!(
            "[ \"$1\" = --version ] && exit 0\n[ \"$1\" = -c ] || exit 9\n\
                 [ \"$(cat \"$2\")\" = '{}' ] || exit 9\n\
                 case \"$2\" in \"{}\"*) exit 9;; esac\nshift 2\n",
            EMPTY_SETTINGS.trim_end(),
            dir.join("app").display()
        ),
    );
    std::fs::write(&tool.run.command, text).unwrap();
    tool.run.args = vec!["-c".into(), "{config}".into(), "{output}".into()];
    tool.finished_exits = vec![0];
    let outcome = run(&dir, tool.clone());
    assert_eq!(outcome.ran, ["primary"], "{:?}", outcome.not_run);
    // The control: the same tool asked without one exits 9, which is not a finished run.
    tool.run.args = vec!["{output}".into()];
    let outcome = run(&dir, tool);
    std::fs::remove_dir_all(&dir).ok();
    assert!(outcome.ran.is_empty(), "{outcome:?}");
    assert!(
        outcome.not_run[0].1.contains("exit code 9"),
        "{:?}",
        outcome.not_run
    );
}

#[test]
fn a_broken_program_is_reported_and_its_stand_in_left_alone() {
    let dir = scratch("broken");
    let broken = script(
        &dir,
        "broken",
        "#!/bin/sh\necho 'cannot find its libraries' >&2\nexit 1\n",
    );
    let (adapter, _) = adapter(&dir, &broken);
    let outcome = run(&dir, adapter);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        outcome.ran.is_empty() && outcome.stood_in.is_empty(),
        "{outcome:?}"
    );
    let why = &outcome.not_run[0].1;
    assert!(
        why.starts_with("Primary is installed and would not start"),
        "{why}"
    );
    assert!(why.contains("cannot find its libraries"), "{why}");
}

/// A tool that writes a clean report naming `rule` and then does as `ending` says.
fn tool(dir: &Path, rule: &str, ending: &str) -> Adapter {
    let text = format!(
        "#!/bin/sh\n[ \"$1\" = --version ] && exit 0\n{ending}\n",
        ending = ending.replace(
            "CLEAN",
            &format!(
                "printf '{{\"version\":\"2.1.0\",\"runs\":[{{\"tool\":{{\"driver\":{{\"name\":\
                     \"Tool\",\"rules\":[{{\"id\":\"{rule}\"}}]}}}},\"results\":[]}}]}}' > \"$1\""
            )
        )
    );
    let path = script(dir, "tool", &text);
    let (mut adapter, _) = adapter(dir, &path);
    adapter.name = "Tool".into();
    adapter.run.args = vec!["{output}".into()];
    adapter.stand_in = None;
    adapter.finished_exits = vec![0, 1];
    adapter
}

/// An app with a Python file, a JavaScript file, Python under `vendor/`, and a link to a Python
/// file outside it, and a tool that reads Python, writes a clean report, and records what it was
/// handed. Returns the run and what the tool was handed.
fn handed(name: &str, report: &str) -> (AdapterRun, Vec<String>) {
    let dir = scratch(name);
    let (_, rule) = adapter(&dir, "unused");
    let seen = dir.join("seen");
    let write = if report == "CLEAN" {
        "CLEAN".to_owned()
    } else {
        format!("printf '%s' '{report}' > \"$1\"")
    };
    let ending = format!(
        "out=\"$1\"; shift; [ \"$1\" = -- ] && shift; printf '%s\\n' \"$@\" > '{}'; set -- \"$out\"; {write}; exit 0",
        seen.display()
    );
    let mut adapter = tool(&dir, &rule, &ending);
    adapter.run.args = vec!["{output}".into(), "--".into(), "{files}".into()];
    adapter.working_directory = Some("{dir}".into());
    let app = dir.join("app");
    std::fs::create_dir_all(app.join("vendor")).unwrap();
    std::fs::write(app.join("app.py"), "print(1)\n").unwrap();
    std::fs::write(app.join("web.js"), "console.log(1)\n").unwrap();
    std::fs::write(app.join("vendor/lib.py"), "print(2)\n").unwrap();
    // `vendor/` holds installed code beside the manifest that explains it, as in family-hub; with
    // no manifest it would be the app's own (H6).
    std::fs::write(app.join("requirements.txt"), "flask\n").unwrap();
    std::fs::write(dir.join("outside.py"), "print('outside the app')\n").unwrap();
    std::os::unix::fs::symlink(dir.join("outside.py"), app.join("linked.py")).unwrap();
    let outcome = run_all(
        &Adapters {
            adapters: vec![adapter],
        },
        &app,
        &["python".to_owned(), "javascript".to_owned()],
        &BTreeSet::new(),
        &dir,
        &secret_rules(),
    );
    let given = std::fs::read_to_string(&seen)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect();
    std::fs::remove_dir_all(&dir).ok();
    (outcome, given)
}

#[test]
fn a_tool_for_one_language_is_handed_that_language_s_files_and_nothing_else() {
    // S7 of the deep review: Bandit handed the folder followed a link out of the app and read
    // `vendor/`. Handed `sv`'s own listing, it gets the app's Python and nothing else.
    let (outcome, given) = handed("one-language", "CLEAN");
    assert_eq!(outcome.ran, ["primary"], "{outcome:?}");
    assert_eq!(given, ["./app.py"], "{given:?}");
}

#[test]
fn a_run_whose_report_says_it_could_not_read_a_file_is_not_clean() {
    // H7 of the deep review: the report says a file was skipped, so finding nothing is not a
    // clean result, and the file is named.
    let skipped = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Tool","rules":[]}},"invocations":[{"executionSuccessful":false,"toolExecutionNotifications":[{"level":"error","message":{"text":"syntax error while parsing AST from file"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"broken.py"}}}]}]}],"results":[]}]}"#;
    let (outcome, _) = handed("could-not-read", skipped);
    assert!(outcome.verified.is_empty(), "{:?}", outcome.verified);
    let partly = format!("{:?}", outcome.partly);
    assert!(
        partly.contains("`broken.py` (syntax error while parsing AST from file)"),
        "{partly}"
    );
    assert!(
        outcome
            .not_run
            .iter()
            .any(|(_, why, _)| why.contains("ran and found nothing, but it did not look at all")),
        "{:?}",
        outcome.not_run
    );

    // The control: the same tool, its report saying the run succeeded, is credited.
    let (clean, _) = handed("could-read", "CLEAN");
    assert_eq!(clean.verified.len(), 1, "{clean:?}");
}

#[test]
fn only_an_error_or_an_unsuccessful_run_counts_against_a_report() {
    let app = Path::new("/app");
    let report =
        |invocation: &str| format!(r#"{{"runs":[{{"invocations":[{invocation}],"results":[]}}]}}"#);
    // A warning is not a part of the run that failed.
    assert!(did_not_finish(&secret_rules(), &report(r#"{"executionSuccessful":true,"toolExecutionNotifications":[{"level":"warning","message":{"text":"slow"}}]}"#), app).is_empty());
    assert!(
        did_not_finish(
            &secret_rules(),
            &report(r#"{"executionSuccessful":true}"#),
            app
        )
        .is_empty()
    );
    // Unsuccessful with nothing said, and an error with no file, still count.
    let quiet = did_not_finish(
        &secret_rules(),
        &report(r#"{"executionSuccessful":false}"#),
        app,
    );
    assert_eq!(
        quiet,
        ["its report says its run did not succeed, without saying why"]
    );
    let config = did_not_finish(
        &secret_rules(),
        &report(
            r#"{"executionSuccessful":true,"toolConfigurationNotifications":[{"level":"error","message":{"text":"bad profile\nmore"}}]}"#,
        ),
        app,
    );
    assert_eq!(
        config,
        ["its report names 1 problem it could not get past: bad profile"]
    );
    // A file named by its full path is shown from the app folder.
    let full = did_not_finish(
        &secret_rules(),
        &report(
            r#"{"toolExecutionNotifications":[{"level":"error","message":{"text":"x"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///app/pkg/a.py"}}}]}]}"#,
        ),
        app,
    );
    assert!(full[0].contains("`pkg/a.py` (x)"), "{full:?}");
    // A message quoting the line it could not read is quoted with its credential redacted.
    let value = ["Xk7mQ92v", "LpR4sTzW"].concat();
    let quoted = did_not_finish(
        &secret_rules(),
        &report(&format!(
            r#"{{"toolExecutionNotifications":[{{"level":"error","message":{{"text":"could not parse: db_password = \"{value}\""}},"locations":[{{"physicalLocation":{{"artifactLocation":{{"uri":"file:///app/settings.py"}}}}}}]}}]}}"#
        )),
        app,
    );
    assert!(
        quoted[0].contains("could not parse"),
        "the setup: {quoted:?}"
    );
    // And one that names no file.
    let unfiled = did_not_finish(
        &secret_rules(),
        &report(&format!(
            r#"{{"toolExecutionNotifications":[{{"level":"error","message":{{"text":"could not parse: db_password = \"{value}\""}}}}]}}"#
        )),
        app,
    );
    assert!(
        unfiled[0].contains("could not parse"),
        "the setup: {unfiled:?}"
    );
    assert!(
        !unfiled[0].contains(&value[4..]),
        "{}",
        unfiled[0].replace(&value, "<value>")
    );
    assert!(
        !quoted[0].contains(&value[4..]),
        "{}",
        quoted[0].replace(&value, "<value>")
    );
    assert!(
        quoted[0].contains("[redacted:"),
        "{}",
        quoted[0].replace(&value, "<value>")
    );
}

#[test]
fn bandit_is_handed_the_app_s_files_and_never_the_folder() {
    let adapters =
        Adapters::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json"))
            .unwrap();
    let bandit = adapters.adapters.iter().find(|a| a.id == "bandit").unwrap();
    assert!(
        bandit.run.args.iter().any(|a| a == "{files}"),
        "{:?}",
        bandit.run.args
    );
    assert!(
        !bandit.run.args.iter().any(|a| a.contains("{dir}")),
        "{:?}",
        bandit.run.args
    );
    assert_eq!(bandit.language, "python");
}

#[test]
fn a_report_is_written_in_a_private_folder_made_for_the_run() {
    let dir = scratch("private");
    let (_, rule) = adapter(&dir, "unused");
    let seen = dir.join("seen");
    let ending = format!(
        "d=$(dirname \"$1\"); echo \"$d $(stat -c %a \"$d\" 2>/dev/null || stat -f %Lp \"$d\")\" >> '{}'; CLEAN; exit 1",
        seen.display()
    );
    let adapter = tool(&dir, &rule, &ending);
    let first = run(&dir, adapter.clone());
    let second = run(&dir, adapter);
    let seen = std::fs::read_to_string(&seen).unwrap_or_default();
    let left: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("sv-tools-"))
        .collect();
    std::fs::remove_dir_all(&dir).ok();
    // Exit code 1 is one this tool finishes with, and the report it wrote there was read.
    assert_eq!(first.verified.len(), 1, "{first:?}");
    assert_eq!(second.verified.len(), 1, "{second:?}");
    let folders: Vec<(&str, &str)> = seen.lines().filter_map(|l| l.rsplit_once(' ')).collect();
    assert_eq!(folders.len(), 2, "{seen}");
    for (folder, mode) in &folders {
        assert_eq!(*mode, "700", "{folder}");
        let name = Path::new(folder).file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("sv-tools-") && name.len() == 41, "{name}");
        assert_eq!(Path::new(folder).parent(), Some(dir.as_path()));
    }
    assert_ne!(folders[0].0, folders[1].0, "each run has its own folder");
    assert!(left.is_empty(), "removed after the run: {left:?}");
}

#[test]
fn a_tool_that_ends_with_a_failure_is_not_read_whatever_it_wrote() {
    for (ending, said) in [
        ("CLEAN; exit 2", "stopped with exit code 2"),
        ("CLEAN; kill -9 $$", "was stopped before it finished"),
    ] {
        let dir = scratch("failed");
        let (_, rule) = adapter(&dir, "unused");
        let outcome = run(&dir, tool(&dir, &rule, ending));
        std::fs::remove_dir_all(&dir).ok();
        assert!(outcome.verified.is_empty(), "{ending}: {outcome:?}");
        assert!(outcome.ran.is_empty(), "{ending}: {outcome:?}");
        let why = &outcome.not_run[0].1;
        assert!(why.starts_with(&format!("Tool {said}")), "{ending}: {why}");
    }
}

#[test]
fn only_a_report_the_tool_wrote_in_this_run_is_read() {
    let dir = scratch("fresh");
    let (_, rule) = adapter(&dir, "unused");
    // A clean report already in the report's place, from an earlier run or put there.
    let planted = dir.join("planted.sarif");
    let report = dir.join("out.sarif");
    let clean = tool(&dir, &rule, "CLEAN");
    let make = Command::new(&clean.run.command)
        .arg(&planted)
        .status()
        .unwrap();
    assert!(
        make.success() && planted.is_file(),
        "the planted report was made"
    );
    std::fs::copy(&planted, &report).unwrap();
    let app = dir.join("app");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(app.join("app.py"), "print(1)\n").unwrap();
    // The tool writes nothing.
    let silent = run_one(&tool(&dir, &rule, "exit 0"), &app, &report, &secret_rules());
    // The tool puts a link to the planted report in its report's place.
    let linked = run_one(
        &tool(
            &dir,
            &rule,
            &format!("ln -s '{}' \"$1\"", planted.display()),
        ),
        &app,
        &report,
        &secret_rules(),
    );
    std::fs::remove_dir_all(&dir).ok();
    for outcome in [silent, linked] {
        match outcome {
            Outcome::NotRun { why, .. } => {
                assert!(why.starts_with("Tool ran and wrote no report"), "{why}")
            }
            Outcome::Ran { .. } => panic!("a report the tool did not write was read"),
        }
    }
}

/// A password, built here so this file holds none, long enough that a line cut at 160 or 200
/// characters can cut through it.
fn password() -> String {
    ["Qv7r", "Lm2x", "Tz9k", "Wp4n", "Hd6s"].concat()
}

/// Whether `text` holds the password or any piece of it longer than the four characters a
/// redaction shows.
fn holds_password(text: &str) -> bool {
    let password = password();
    (5..=password.len()).any(|n| text.contains(&password[..n]))
}

/// A tool whose findings quote the password, as Bandit's B105 does: in a result's message, a
/// rule's short description, and its help.
fn quoting_tool(dir: &Path, rule: &str, copy: &Path) -> Adapter {
    let sarif = serde_json::json!({
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "Tool", "rules": [{
                "id": rule,
                "shortDescription": { "text": format!("password = '{}'", password()) },
                "help": { "text": format!("Remove PASSWORD=\"{}\" from the code.", password()) },
            }] } },
            "results": [{
                "ruleId": rule,
                "level": "error",
                "message": { "text": format!("Possible hardcoded password: '{}'", password()) },
                "locations": [{ "physicalLocation": {
                    "artifactLocation": { "uri": "app.py" },
                    "region": { "startLine": 1 },
                } }],
            }],
        }],
    });
    let source = dir.join("quoted.sarif");
    std::fs::write(&source, sarif.to_string()).unwrap();
    let text = format!(
        "#!/bin/sh\n[ \"$1\" = --version ] && exit 0\ncp '{}' \"$1\"\ncp '{}' '{}'\nexit 1\n",
        source.display(),
        source.display(),
        copy.display()
    );
    let path = script(dir, "quoting", &text);
    let (mut adapter, _) = adapter(dir, &path);
    adapter.name = "Tool".into();
    adapter.run.args = vec!["{output}".into()];
    adapter.stand_in = None;
    adapter.finished_exits = vec![0, 1];
    adapter
}

#[test]
fn a_tool_s_findings_that_quote_a_password_reach_the_result_redacted() {
    let dir = scratch("quoting");
    let (_, rule) = adapter(&dir, "unused");
    let copy = dir.join("what-the-tool-wrote.sarif");
    let outcome = run(&dir, quoting_tool(&dir, &rule, &copy));
    let wrote = std::fs::read_to_string(&copy).unwrap_or_default();
    std::fs::remove_dir_all(&dir).ok();
    // The setup: the tool ran, and what it wrote really quotes the password.
    assert!(
        holds_password(&wrote),
        "the tool's report quotes it: {wrote}"
    );
    assert_eq!(outcome.findings.len(), 1, "{outcome:?}");
    let f = &outcome.findings[0];
    for (what, text) in [
        ("title", &f.title),
        ("description", &f.description),
        ("fix", &f.fix),
        ("impact", &f.impact),
    ] {
        assert!(!holds_password(text), "{what}: {text}");
    }
    // What was found is still said, and which value, by its first four characters.
    assert!(
        f.description
            .starts_with("Possible hardcoded password: '[redacted: Qv7r"),
        "{}",
        f.description
    );
    assert!(f.title.contains("[redacted: Qv7r"), "{}", f.title);
    assert!(f.fix.contains("[redacted: Qv7r"), "{}", f.fix);
}

#[test]
fn what_a_tool_writes_to_stderr_reaches_the_reason_redacted_and_cut_after() {
    // Long enough that the 160 or 200 characters a reason quotes end eight characters into the
    // password: cut first, the closing quote would be gone and the value with it unrecognized.
    let line = |most: usize| format!("{} password='{}'", "x".repeat(most - 19), password());
    let say = |most: usize, code: u8| format!("echo \"{}\" >&2; exit {code}", line(most));
    for (case, most, version, prepare, run_ending) in [
        (
            "version",
            PRESENCE_CHARS,
            say(PRESENCE_CHARS, 1),
            None,
            "exit 0".to_owned(),
        ),
        (
            "prepare",
            LINE_CHARS,
            "exit 0".to_owned(),
            Some(say(LINE_CHARS, 1)),
            "exit 0".to_owned(),
        ),
        (
            "failure",
            LINE_CHARS,
            "exit 0".to_owned(),
            None,
            say(LINE_CHARS, 2),
        ),
        (
            "no report",
            LINE_CHARS,
            "exit 0".to_owned(),
            None,
            say(LINE_CHARS, 0),
        ),
    ] {
        // The setup: cut first, eight characters of the password would show.
        let cut: String = line(most).chars().take(most).collect();
        assert!(cut.ends_with(&password()[..8]), "{case}: {cut}");
        let dir = scratch(&format!("stderr-{}", case.replace(' ', "-")));
        let (_, rule) = adapter(&dir, "unused");
        let path = script(
            &dir,
            "talking",
            &format!(
                "#!/bin/sh\nif [ \"$1\" = --version ]; then {version}; fi\nif [ \"$1\" = prepare ]; then {}; fi\n{run_ending}\n",
                prepare.as_deref().unwrap_or("exit 0")
            ),
        );
        let mut adapter = tool(&dir, &rule, "exit 0");
        adapter.version.command = path.clone();
        adapter.run.command = path.clone();
        if prepare.is_some() {
            adapter.prepare = Some(Invocation {
                command: path.clone(),
                args: vec!["prepare".into()],
            });
        }
        let outcome = run(&dir, adapter);
        std::fs::remove_dir_all(&dir).ok();
        let why = &outcome
            .not_run
            .first()
            .unwrap_or_else(|| panic!("{case}: {outcome:?}"))
            .1;
        // The setup: the line really reached the reason.
        assert!(why.contains(&"x".repeat(100)), "{case}: {why}");
        assert!(!holds_password(why), "{case}: {why}");
    }
}

/// An app with one Python file, for a tool to be run over.
fn one_file_app(dir: &Path) -> PathBuf {
    let app = dir.join("app");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(app.join("app.py"), "print(1)\n").unwrap();
    app
}

#[test]
fn a_tool_that_does_not_finish_is_stopped_with_what_it_started_and_not_read() {
    // The deep review's improvement 3: `sv` waited for an outside tool for ever. This one starts
    // a second program, as Semgrep does, writes a clean report, and then hangs.
    let dir = scratch("stuck");
    let (_, rule) = adapter(&dir, "unused");
    let started = dir.join("started");
    let ending = format!("sleep 300 & echo $! > '{}'; CLEAN; wait", started.display());
    let mut stuck = tool(&dir, &rule, &ending);
    stuck.time_limit_seconds = Some(2);
    let app = one_file_app(&dir);
    let report = dir.join("out.sarif");
    let begun = std::time::Instant::now();
    let outcome = run_one(&stuck, &app, &report, &secret_rules());
    let took = begun.elapsed();
    let Outcome::NotRun { why, .. } = &outcome else {
        panic!("a tool stopped by the limit was read: {outcome:?}");
    };
    assert!(why.contains("was stopped after 2 seconds"), "{why}");
    assert!(took < std::time::Duration::from_secs(20), "{took:?}");
    // What it started was stopped too.
    let pid = std::fs::read_to_string(&started).expect("the tool started its second program");
    std::thread::sleep(std::time::Duration::from_millis(300));
    // Gone, or a zombie nobody has reaped yet, which runs nothing: in a container whose first
    // process does not reap orphans, a stopped one stays listed.
    let alive = match std::fs::read_to_string(format!("/proc/{}/stat", pid.trim())) {
        Ok(stat) => !stat
            .rsplit_once(')')
            .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z')),
        Err(_) if Path::new("/proc/self/stat").exists() => false,
        Err(_) => Command::new("kill")
            .args(["-0", pid.trim()])
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success()),
    };
    assert!(!alive, "the program the tool started was left running");
    // And a tool that finishes inside its limit is read as before.
    let mut quick = tool(&dir, &rule, "CLEAN");
    quick.time_limit_seconds = Some(30);
    assert!(
        !matches!(
            run_one(&quick, &app, &report, &secret_rules()),
            Outcome::NotRun { .. }
        ),
        "a tool inside its limit was not read"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_tool_is_handed_only_the_environment_it_needs() {
    // Cargo gives every test this; a tool reading somebody's code needs none of it.
    assert!(
        std::env::var_os("CARGO_MANIFEST_DIR").is_some(),
        "the test needs a variable of the owner's to look for"
    );
    let dir = scratch("environment");
    let (_, rule) = adapter(&dir, "unused");
    let seen = dir.join("environment");
    let mut probe = tool(&dir, &rule, &format!("env > '{}'; CLEAN", seen.display()));
    probe.env.insert("TOOL_OWN".into(), "1".into());
    let app = one_file_app(&dir);
    let outcome = run_one(&probe, &app, &dir.join("out.sarif"), &secret_rules());
    assert!(!matches!(outcome, Outcome::NotRun { .. }), "{outcome:?}");
    let seen = std::fs::read_to_string(&seen).unwrap();
    let names: Vec<&str> = seen.lines().filter_map(|l| l.split('=').next()).collect();
    assert!(!names.contains(&"CARGO_MANIFEST_DIR"), "{names:?}");
    assert!(names.contains(&"PATH"), "{names:?}");
    assert!(seen.lines().any(|l| l == "GOTOOLCHAIN=local"), "{seen}");
    assert!(seen.lines().any(|l| l == "TOOL_OWN=1"), "{seen}");
    // Git's `core.fsmonitor` set off, so a `git` the tool starts runs nothing the app names.
    for (name, value) in crate::git::ENV_OVERRIDES {
        assert!(
            seen.lines().any(|l| l == format!("{name}={value}")),
            "{name} was not {value}: {seen}"
        );
    }
    // Nothing beyond the list, apart from what the shell sets itself, the adapter's own, and
    // git's settings above.
    let shell_sets = ["PWD", "SHLVL", "_", "OLDPWD"];
    for name in names {
        assert!(
            PASSED_ON.contains(&name)
                || shell_sets.contains(&name)
                || name == "GOTOOLCHAIN"
                || crate::git::ENV_OVERRIDES.iter().any(|(n, _)| *n == name)
                || probe.env.contains_key(name),
            "{name} was handed on"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_tool_that_does_not_say_its_version_is_broken_not_waited_for() {
    let dir = scratch("silent-version");
    let (_, rule) = adapter(&dir, "unused");
    let mut silent = tool(&dir, &rule, "CLEAN");
    silent.version.command = script(&dir, "silent", "#!/bin/sh\nsleep 300\n");
    silent.version.args = Vec::new();
    silent.time_limit_seconds = Some(1);
    let begun = std::time::Instant::now();
    let presence = presence(&silent);
    assert!(begun.elapsed() < std::time::Duration::from_secs(20));
    assert!(
        matches!(&presence, Presence::Broken { detail } if detail.contains("did not answer within 1 second")),
        "{presence:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_tool_s_secret_rules_spare_a_stored_hash_and_keep_a_hexy_password_and_test_code() {
    // Follow-ups 2 and 4 of the Semgrep false-alarm measurement, through a run: a secret rule's
    // finding on a stored password hash is dropped, as `sv`'s own rule drops it; one on a
    // password that happens to be hex digits is kept; another rule on the hash's line is kept;
    // and one in a test file is kept and listed with test code. Values are made here.
    let dir = scratch("stored-hash");
    let (_, rule) = adapter(&dir, "unused");
    let app = dir.join("app");
    std::fs::create_dir_all(app.join("tests")).unwrap();
    let bcrypt = format!(
        "${}${}${}",
        "2b",
        "12",
        "Qm7Rz2Kv9Lp4./Wn8Hs3Jd6Tf1Gb5Yc0"
            .repeat(2)
            .get(..53)
            .unwrap()
    );
    let hex: String = "9f3a0c7e5b18d246".repeat(2);
    let password: String = "Qm7Rz2Kv9Lp4Wn8Hs3Jd6".to_owned();
    std::fs::write(
            app.join("app.py"),
            format!(
                "password_hash = \"{bcrypt}\"\npassword = \"{hex}\"\npassword_hash = \"{bcrypt}\"; k = \"{password}{password}\"\n"
            ),
        )
        .unwrap();
    std::fs::write(
        app.join("tests/test_login.py"),
        format!("password = \"{password}\"\n"),
    )
    .unwrap();
    let api_key = "generic.secrets.gitleaks.generic-api-key.generic-api-key";
    let bcrypt_rule = "generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash";
    let other = "python.lang.security.audit.hardcoded-password-hash.example";
    let result = |rule: &str, file: &str, line: u32| {
        serde_json::json!({
            "ruleId": rule,
            "message": { "text": "found" },
            "locations": [{ "physicalLocation": {
                "artifactLocation": { "uri": file },
                "region": { "startLine": line }
            }}]
        })
    };
    let sarif = serde_json::json!({
        "version": "2.1.0",
        "runs": [{ "tool": { "driver": { "name": "Semgrep", "rules": [] } }, "results": [
            result(bcrypt_rule, "app.py", 1),
            result(api_key, "app.py", 1),
            result(other, "app.py", 1),
            result(api_key, "app.py", 2),
            result(api_key, "app.py", 3),
            result(api_key, "tests/test_login.py", 1),
            result(api_key, "gone.py", 1),
        ]}]
    });
    let written = dir.join("written.sarif");
    std::fs::write(&written, sarif.to_string()).unwrap();
    let mut semgrep = tool(
        &dir,
        &rule,
        &format!("cp '{}' \"$1\"; exit 0", written.display()),
    );
    semgrep.id = "semgrep".into();
    let outcome = run_one(&semgrep, &app, &dir.join("out.sarif"), &secret_rules());

    // Bandit's rule for a password written as a string, on the same two lines.
    let bandit_sarif = serde_json::json!({
        "version": "2.1.0",
        "runs": [{ "tool": { "driver": { "name": "Bandit", "rules": [] } }, "results": [
            result("B105", "app.py", 1),
            result("B105", "app.py", 2),
        ]}]
    });
    let bandit_written = dir.join("bandit.sarif");
    std::fs::write(&bandit_written, bandit_sarif.to_string()).unwrap();
    let mut bandit = tool(
        &dir,
        &rule,
        &format!("cp '{}' \"$1\"; exit 0", bandit_written.display()),
    );
    bandit.id = "bandit".into();
    let bandit_outcome = run_one(
        &bandit,
        &app,
        &dir.join("bandit-out.sarif"),
        &secret_rules(),
    );
    std::fs::remove_dir_all(&dir).ok();
    let Outcome::Ran {
        findings: by_bandit,
        ..
    } = bandit_outcome
    else {
        panic!("bandit did not run: {bandit_outcome:?}");
    };
    let lines: Vec<usize> = by_bandit.iter().map(|f| f.location.line).collect();
    assert_eq!(lines, [2], "{by_bandit:?}");

    let Outcome::Ran { findings, .. } = outcome else {
        panic!("the tool did not run: {outcome:?}");
    };
    let mut got: Vec<(String, usize, bool)> = findings
        .iter()
        .map(|f| {
            (
                format!(
                    "{}:{}",
                    f.location.file,
                    f.rule_id.rsplit('.').next().unwrap()
                ),
                f.location.line,
                f.in_test_code(),
            )
        })
        .collect();
    got.sort();
    assert_eq!(
        got,
        [
            ("app.py:example".to_owned(), 1, false),
            ("app.py:generic-api-key".to_owned(), 2, false),
            ("app.py:generic-api-key".to_owned(), 3, false),
            ("gone.py:generic-api-key".to_owned(), 1, false),
            ("tests/test_login.py:generic-api-key".to_owned(), 1, true),
        ]
    );
}

#[test]
fn a_tool_that_runs_git_in_the_app_s_folder_runs_no_program_the_repository_names() {
    // ADR-032, "Later, 6 October 2026": a stand-in for a tool that runs `git ls-files` in the
    // app's folder, as Semgrep does for a folder it is given, started the way every tool is.
    if Command::new("git").arg("--version").output().is_err() {
        println!("no git here; this needs it");
        return;
    }
    let planted = |name: &str| {
        let dir = scratch(&format!("git-guard-{name}"));
        let mark = dir.with_extension("ran");
        std::fs::remove_file(&mark).ok();
        let git = |args: &[&str]| {
            assert!(
                Command::new("git")
                    .arg("-C")
                    .arg(&dir)
                    .args(args)
                    .output()
                    .is_ok_and(|o| o.status.success()),
                "git {args:?} failed in the test's setup"
            );
        };
        git(&["init", "-q"]);
        std::fs::write(dir.join("app.py"), "print(1)\n").unwrap();
        git(&["add", "app.py"]);
        git(&[
            "config",
            "core.fsmonitor",
            &format!("touch '{}'; false", mark.display()),
        ]);
        (dir, mark)
    };
    let adapters =
        Adapters::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json"))
            .unwrap();
    let semgrep = adapters
        .adapters
        .iter()
        .find(|a| a.id == "semgrep")
        .unwrap();
    let tool = |dir: &Path| {
        let mut command = Command::new("git");
        command.arg("ls-files").current_dir(dir);
        command
    };
    // The control: started with the environment cleared and nothing more, the planted program
    // runs, so the setup is the attack.
    let (dir, mark) = planted("control");
    let mut bare = tool(&dir);
    bare.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        bare.env("PATH", path);
    }
    assert!(bare.output().unwrap().status.success());
    assert!(
        mark.exists(),
        "plain git did not run the planted program, so this proves nothing"
    );
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_file(&mark).ok();
    // Started the way `sv` starts a tool: the program is not run.
    let (dir, mark) = planted("guarded");
    let mut guarded = tool(&dir);
    let status = prepared(&mut guarded, semgrep).status().unwrap();
    assert!(status.success(), "the stand-in tool ran");
    assert!(
        !mark.exists(),
        "a tool's git ran the program the app's repository named"
    );
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_file(&mark).ok();
    // And no adapter's own settings can undo it.
    for adapter in &adapters.adapters {
        assert!(
            adapter.env.keys().all(|k| !k.starts_with("GIT_")),
            "{} sets a GIT_ variable",
            adapter.id
        );
    }
}
