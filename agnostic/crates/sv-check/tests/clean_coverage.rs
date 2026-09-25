//! When a check may say it looked and found nothing — and, mostly, when it may not.
//!
//! A finding is a claim about something that is there and can be checked by looking at it. These are
//! claims about something that is *not* there, which are only worth the coverage behind them, and
//! which fail in a direction nobody notices: a green line in a report is not something a reader goes
//! back to question. Every test here is a way of arriving at one that was not earned.

use std::path::PathBuf;
use sv_check::{ast, probes, secrets};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-clean-{name}"));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn data(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data")
        .join(file)
}

fn ast_rules() -> ast::AstRules {
    ast::AstRules::load(&data("ast-rules.json")).expect("the rules load")
}

fn secret_rules() -> secrets::SecretRules {
    secrets::SecretRules::load(&data("secret-rules.json")).expect("the rules load")
}

fn verified_ids(verified: &[sv_check::Verified]) -> Vec<&str> {
    verified.iter().map(|v| v.check_id.as_str()).collect()
}

// ---- the rules that read code ----

#[test]
fn clean_python_lets_the_rules_that_read_it_say_so() {
    // The positive case, first, because a check that can never say anything is not a check.
    let dir = scratch("ast-clean");
    std::fs::write(
        dir.join("app.py"),
        "import sqlite3\n\ndef find(db, q):\n    return db.execute('select 1 where t = ?', [q])\n",
    )
    .unwrap();
    let scan = ast::scan_dir(&ast_rules(), &dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(scan.findings.is_empty(), "{:?}", scan.findings);
    assert!(
        !scan.verified.is_empty(),
        "a rule that read a file and found nothing must be able to say so"
    );
    for v in &scan.verified {
        assert!(
            v.scope.contains("python"),
            "the scope has to say what was read: {}",
            v.scope
        );
    }
}

#[test]
fn an_eval_inside_jsx_in_a_tsx_file_is_found_and_not_called_checked() {
    // The case that found this. `.tsx` went through the TypeScript grammar, which has no JSX: the
    // parse broke at the first tag, the `eval` in the click handler was never seen, the file still
    // counted as read, and the report listed V1.3.2 as checked over it.
    let dir = scratch("ast-tsx");
    std::fs::write(
        dir.join("App.tsx"),
        "export default function App({ q }: { q: string }) {\n  return (\n    <form>\n      \
         <button onClick={() => eval(q)}>run</button>\n    </form>\n  );\n}\n",
    )
    .unwrap();
    let scan = ast::scan_dir(&ast_rules(), &dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        scan.unparsed_files.is_empty(),
        "valid TSX has to parse cleanly, or every React app loses its clean claims: {:?}",
        scan.unparsed_files
    );
    let found: Vec<(&str, usize)> = scan
        .findings
        .iter()
        .map(|f| (f.rule_id.as_str(), f.location.line))
        .collect();
    assert!(
        found.contains(&("ast.dynamic-code-execution", 4)),
        "the eval in the handler, on its own line: {found:?}"
    );
    assert!(
        !verified_ids(&scan.verified).contains(&"ast.dynamic-code-execution"),
        "a rule that found something cannot also have checked clean"
    );
}

#[test]
fn clean_tsx_lets_the_rules_say_so() {
    // The other half: reading TSX properly has to leave room for a clean result, and it counts as
    // TypeScript, which is what the rules' coverage is written in.
    let dir = scratch("ast-tsx-clean");
    std::fs::write(
        dir.join("App.tsx"),
        "export const App = ({ n }: { n: number }) => <p className=\"n\">{n + 1}</p>;\n",
    )
    .unwrap();
    let scan = ast::scan_dir(&ast_rules(), &dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(scan.findings.is_empty(), "{:?}", scan.findings);
    assert!(scan.unparsed_files.is_empty(), "{:?}", scan.unparsed_files);
    assert!(
        scan.verified.iter().any(|v| v.scope.contains("typescript")),
        "{:?}",
        scan.verified
    );
}

#[test]
fn a_file_that_does_not_parse_silences_every_rule_and_keeps_its_findings() {
    // Whatever the grammar, a parse that comes back with an error in it has not read part of the
    // file, and says nothing about how much. The clean Python beside it is not enough: what the
    // broken file hid could be anything.
    let dir = scratch("ast-broken");
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(
        dir.join("worker.py"),
        "def run(q):\n    return eval(q)\n\ndef broken(:\n    pass\n",
    )
    .unwrap();
    let scan = ast::scan_dir(&ast_rules(), &dir);
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(scan.unparsed_files, vec!["worker.py".to_owned()]);
    assert!(
        scan.verified.is_empty(),
        "no rule may claim a clean result while a file did not parse: {:?}",
        verified_ids(&scan.verified)
    );
    assert!(
        scan.findings
            .iter()
            .any(|f| f.rule_id == "ast.dynamic-code-execution"),
        "what was found in the readable part still stands: {:?}",
        scan.findings
    );
}

#[test]
fn a_broken_file_in_one_language_silences_the_rules_about_another() {
    // The second witness, for a different reason than the first: the Go here is clean and fully
    // read, and the Go-reading rules still may not say so, because the injection they look for
    // could be in the JavaScript that did not parse. Same rule as a language with no grammar.
    let dir = scratch("ast-broken-other");
    std::fs::write(
        dir.join("main.go"),
        "package main\n\nfunc main() { println(\"hi\") }\n",
    )
    .unwrap();
    std::fs::write(dir.join("widget.js"), "export function f( {\n  return 1;\n").unwrap();
    let scan = ast::scan_dir(&ast_rules(), &dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(scan.findings.is_empty(), "{:?}", scan.findings);
    assert_eq!(scan.unparsed_files, vec!["widget.js".to_owned()]);
    assert!(
        scan.verified.is_empty(),
        "{:?}",
        verified_ids(&scan.verified)
    );
}

#[test]
fn a_parse_error_is_noticed_in_every_language_and_a_clean_file_is_not_flagged() {
    // Asked of the parser directly, so the two tests above cannot pass on an accident of the walk.
    let rules = ast_rules();
    for (file, language, clean, broken) in [
        ("a.py", "python", "x = 1\n", "def (:\n"),
        ("a.js", "javascript", "const x = 1;\n", "const = ;\n"),
        (
            "a.ts",
            "typescript",
            "const x: number = 1;\n",
            "const x: = ;\n",
        ),
        (
            "a.tsx",
            "typescript",
            "const a = <b>{1}</b>;\n",
            "const a = <b>{1</b>;\n",
        ),
        ("a.go", "go", "package a\n", "package a\nfunc {\n"),
        ("a.rb", "ruby", "x = 1\n", "def x(\n"),
        ("a.php", "php", "<?php $x = 1;\n", "<?php $x = ;\n"),
        ("A.java", "java", "class A {}\n", "class A {\n"),
    ] {
        assert!(
            !ast::read_file(&rules, language, file, clean).parse_error,
            "{file}: clean code flagged as unparsed"
        );
        assert!(
            ast::read_file(&rules, language, file, broken).parse_error,
            "{file}: a parse error went unnoticed"
        );
    }
}

#[test]
fn a_language_nothing_can_parse_silences_every_rule() {
    // The important one. The app has clean Python and a C++ file no grammar reads. The injection
    // these rules look for could be in the C++, so none of them has established anything about
    // this app — not even the ones whose own language was fully read.
    //
    // This has used Ruby and then C#, each until the language got a grammar. The list of languages
    // that silence everything is meant to shrink; what must not change is that a language still on
    // it does silence them.
    let dir = scratch("ast-unread");
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(dir.join("worker.cpp"), "int main() { return 0; }\n").unwrap();
    let scan = ast::scan_dir(&ast_rules(), &dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        !scan.unread_languages.is_empty(),
        "the setup is wrong: C++ was expected to be unread"
    );
    assert!(
        scan.verified.is_empty(),
        "nothing may be claimed while a language goes unread: {:?}",
        verified_ids(&scan.verified)
    );
}

#[test]
fn a_rule_says_nothing_about_a_language_it_never_saw() {
    // Second witness for the same principle, of a different shape: nothing unread, but a rule whose
    // languages are simply absent from the app. A SQL rule that never met a line of Python has not
    // shown that this app builds no queries by hand.
    let dir = scratch("ast-absent");
    std::fs::write(dir.join("main.go"), "package main\n\nfunc main() {}\n").unwrap();
    let scan = ast::scan_dir(&ast_rules(), &dir);
    let rules = ast_rules();
    let go_rules: Vec<&str> = rules
        .coverage()
        .into_iter()
        .filter(|(_, languages, _)| languages.contains(&"go"))
        .map(|(id, _, _)| id)
        .collect();
    std::fs::remove_dir_all(&dir).ok();
    for v in &scan.verified {
        assert!(
            go_rules.contains(&v.check_id.as_str()),
            "{} claims coverage of an app with only Go in it, and has no Go query",
            v.check_id
        );
    }
}

/// Writes the files, scans them, and removes the folder again.
fn scan_files(name: &str, files: &[(&str, &str)]) -> ast::AstScan {
    let dir = scratch(name);
    for (file, source) in files {
        std::fs::write(dir.join(file), source).unwrap();
    }
    let scan = ast::scan_dir(&ast_rules(), &dir);
    std::fs::remove_dir_all(&dir).ok();
    scan
}

fn untaught_in<'a>(scan: &'a ast::AstScan, rule_id: &str) -> Vec<&'a str> {
    scan.untaught
        .iter()
        .filter(|u| u.rule_id == rule_id)
        .flat_map(|u| u.languages.iter().map(String::as_str))
        .collect()
}

/// A rule set of two, written for these tests: every real rule is now taught every language `sv`
/// reads, so the case where one is not has to be made on purpose.
///
/// `t.python-only` has a Python query and nothing else. `t.python-and-c` has the same query, and
/// says there is nothing to find in C.
fn partly_taught_rules(name: &str) -> ast::AstRules {
    let rule = |id: &str, extra: &str| {
        format!(
            r#"{{"id": "{id}", "title": "Something is evaluated", "severity": "high",
                "confidence": "high", "requirementIds": ["V1.3.2"], "cwe": [], "description": "",
                "impact": "", "fix": "", "literalArgumentIsSafe": true,
                "functionPatterns": {{"python": "^eval$"}},
                "queries": {{"python": "(call function: (identifier) @fn arguments: (argument_list . (_) @arg)) @hit"}}
                {extra}}}"#
        )
    };
    let json = format!(
        r#"{{"rules": [{}, {}]}}"#,
        rule("t.python-only", ""),
        rule(
            "t.python-and-c",
            r#", "nothingToFind": {"c": "Said for this test."}"#
        )
    );
    let dir = scratch(&format!("rules-{name}"));
    let path = dir.join("rules.json");
    std::fs::write(&path, json).unwrap();
    let rules = ast::AstRules::load(&path).expect("the test rules load");
    std::fs::remove_dir_all(&dir).ok();
    rules
}

fn scan_with(rules: &ast::AstRules, name: &str, files: &[(&str, &str)]) -> ast::AstScan {
    let dir = scratch(name);
    for (file, source) in files {
        std::fs::write(dir.join(file), source).unwrap();
    }
    let scan = ast::scan_dir(rules, &dir);
    std::fs::remove_dir_all(&dir).ok();
    scan
}

#[test]
fn a_rule_not_taught_a_language_that_was_read_claims_nothing() {
    // The third shape. Everything parsed, the rule has a Python query and found nothing in the
    // Python — and the Rust beside it is a language the rule was never taught. What the rule looks
    // for is as possible in the Rust as ever, so it has not ruled it out.
    let rules = partly_taught_rules("rust");
    let clean_python = ("app.py", "def home():\n    return 'hi'\n");
    let alone = scan_with(&rules, "untaught-python", &[clean_python]);
    assert!(
        verified_ids(&alone.verified).contains(&"t.python-only"),
        "the setup is wrong: the rule must claim a Python-only app"
    );

    let scan = scan_with(
        &rules,
        "untaught-rust",
        &[
            clean_python,
            ("worker.rs", "fn main() { println!(\"hi\"); }\n"),
        ],
    );
    assert!(scan.findings.is_empty(), "{:?}", scan.findings);
    assert!(scan.unparsed_files.is_empty(), "{:?}", scan.unparsed_files);
    assert_eq!(
        scan.parsed_by_language.len(),
        2,
        "{:?}",
        scan.parsed_by_language
    );
    assert!(
        scan.verified.is_empty(),
        "claimed on the strength of the Python alone: {:?}",
        verified_ids(&scan.verified)
    );
    assert_eq!(untaught_in(&scan, "t.python-only"), ["rust"]);
    assert_eq!(untaught_in(&scan, "t.python-and-c"), ["rust"]);
}

#[test]
fn nothing_to_find_in_c_lets_the_claim_through_and_its_absence_does_not() {
    // A second witness, on the same app for both rules: the only difference between them is the
    // one entry, and it is the whole difference in what they claim.
    let rules = partly_taught_rules("c");
    let scan = scan_with(
        &rules,
        "untaught-c",
        &[
            ("app.py", "def home():\n    return 'hi'\n"),
            ("cgi.c", "int main(void) { return 0; }\n"),
        ],
    );
    assert!(scan.findings.is_empty(), "{:?}", scan.findings);
    assert!(scan.unparsed_files.is_empty(), "{:?}", scan.unparsed_files);
    assert_eq!(verified_ids(&scan.verified), ["t.python-and-c"]);
    assert_eq!(untaught_in(&scan, "t.python-only"), ["c"]);
    assert!(untaught_in(&scan, "t.python-and-c").is_empty());
}

#[test]
fn every_real_rule_is_taught_every_language_it_meets_here() {
    // The real rules, on an app in every language `sv` reads. None of them is left untaught, so no
    // report carries the gap today; a grammar added later without its queries brings it back.
    let files: Vec<(&str, &str)> = vec![
        ("a.py", "x = 1\n"),
        ("a.js", "let x = 1;\n"),
        ("a.ts", "let x: number = 1;\n"),
        ("a.go", "package main\n\nfunc main() {}\n"),
        ("a.rb", "x = 1\n"),
        ("a.php", "<?php $x = 1;\n"),
        ("A.java", "class A {}\n"),
        ("A.cs", "class A {}\n"),
        ("a.kt", "fun main() {}\n"),
        ("a.rs", "fn main() {}\n"),
        ("a.c", "int main(void) { return 0; }\n"),
        ("a.dart", "void main() {}\n"),
        ("a.swift", "let x = 1\n"),
        ("a.sh", "echo hi\n"),
    ];
    let scan = scan_files("every-language", &files);
    assert!(scan.unparsed_files.is_empty(), "{:?}", scan.unparsed_files);
    assert!(
        scan.unread_languages.is_empty(),
        "{:?}",
        scan.unread_languages
    );
    assert_eq!(
        scan.parsed_by_language.len(),
        files.len(),
        "{:?}",
        scan.parsed_by_language
    );
    assert!(scan.untaught.is_empty(), "{:?}", scan.untaught);
}

#[test]
fn a_language_with_nothing_to_find_does_not_hold_a_rule_back() {
    // The other side. Go has no `eval`, and the rule says so in its data, so a Go file beside the
    // Python does not stop the code-execution rule reporting the Python it read.
    let scan = scan_files(
        "ast-nothing-to-find",
        &[
            ("app.py", "def home():\n    return 'hi'\n"),
            ("main.go", "package main\n\nfunc main() {}\n"),
        ],
    );
    assert!(scan.findings.is_empty(), "{:?}", scan.findings);
    assert!(untaught_in(&scan, "ast.dynamic-code-execution").is_empty());
    let claim = scan
        .verified
        .iter()
        .find(|v| v.check_id == "ast.dynamic-code-execution")
        .unwrap_or_else(|| panic!("{:?}", verified_ids(&scan.verified)));
    // The claim names what was read with a query, and only that.
    assert!(claim.scope.contains("python"), "{}", claim.scope);
    assert!(!claim.scope.contains("go"), "{}", claim.scope);
}

#[test]
fn a_clean_dart_and_swift_app_can_say_it_was_read() {
    // A Flutter front end and an iOS client used to silence every code rule for the whole app,
    // back end included. Now both are read, and every rule is either taught them or says why there
    // is nothing to find.
    let scan = scan_files(
        "ast-dart-swift",
        &[
            (
                "main.dart",
                "import 'dart:io';\n\nFuture<String> load(Database db, String id) async {\n                   final rows = await db.rawQuery('select body from notes where id = ?', [id]);\n                   return File('config.json').readAsString();\n}\n",
            ),
            (
                "Notes.swift",
                "import Foundation\n\nfunc load(db: OpaquePointer, id: String) throws -> String {\n                     let d = SHA256.hash(data: Data(id.utf8))\n                     return try String(contentsOfFile: \"/etc/notes.conf\")\n}\n",
            ),
        ],
    );
    assert!(scan.findings.is_empty(), "{:?}", scan.findings);
    assert!(
        scan.unread_languages.is_empty(),
        "{:?}",
        scan.unread_languages
    );
    assert!(scan.unparsed_files.is_empty(), "{:?}", scan.unparsed_files);
    assert!(scan.untaught.is_empty(), "{:?}", scan.untaught);
    let verified = verified_ids(&scan.verified);
    for rule in [
        "ast.dynamic-code-execution",
        "ast.shell-command",
        "ast.sql-built-by-hand",
        "ast.unsafe-deserialization",
        "ast.file-path-from-value",
        "ast.weak-hash-function",
        "ast.weak-cipher",
        "ast.open-redirect",
    ] {
        assert!(verified.contains(&rule), "{rule} missing from {verified:?}");
    }
    // Backticks are nothing in either language, which is not the same as having looked.
    assert!(!verified.contains(&"ast.shell-command-backticks"));
}

#[test]
fn a_rule_that_found_something_does_not_also_report_itself_clean() {
    let dir = scratch("ast-dirty");
    std::fs::write(
        dir.join("app.py"),
        "def run(user):\n    q = \"select * from t where n = '\" + user + \"'\"\n    return db.execute(q)\n",
    )
    .unwrap();
    let scan = ast::scan_dir(&ast_rules(), &dir);
    let fired: Vec<String> = scan.findings.iter().map(|f| f.rule_id.clone()).collect();
    std::fs::remove_dir_all(&dir).ok();
    assert!(!fired.is_empty(), "the setup is wrong: nothing fired");
    for id in &fired {
        assert!(
            !verified_ids(&scan.verified).contains(&id.as_str()),
            "{id} found something and also reported itself clean"
        );
    }
}

// ---- the credential scan ----

#[test]
fn a_file_that_could_not_be_read_stops_the_credential_scan_claiming_anything() {
    // "48 of 52 files were clean" belongs in the gap list, not beside a requirement. The one file
    // that was skipped is exactly where a key would be.
    let dir = scratch("secrets-skipped");
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(
        dir.join("photo.png"),
        [0x89u8, 0x50, 0x4e, 0x47, 0x00, 0xff],
    )
    .unwrap();
    let scan = secrets::scan_dir(&secret_rules(), &dir);
    let skipped = scan.coverage.skipped.clone();
    let verified = scan.verified.clone();
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        !skipped.is_empty(),
        "the setup is wrong: something was expected to be skipped"
    );
    assert!(
        verified.is_empty(),
        "a scan that skipped a file has not shown the app holds no credentials"
    );
}

#[test]
fn a_credential_scan_that_read_everything_and_found_nothing_says_so() {
    let dir = scratch("secrets-clean");
    std::fs::write(dir.join("app.py"), "import os\nkey = os.environ['KEY']\n").unwrap();
    let scan = secrets::scan_dir(&secret_rules(), &dir);
    let verified = scan.verified.clone();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(verified.len(), 1, "{verified:?}");
    assert!(
        verified[0].scope.contains("credential formats"),
        "the scope must say the rules are a list and not everything: {}",
        verified[0].scope
    );
}

#[test]
fn an_empty_folder_is_not_a_clean_credential_scan() {
    // Second witness of a different shape: nothing skipped, because nothing was there. Reading no
    // files is the one case where "found no credentials" is true and means nothing at all.
    let dir = scratch("secrets-empty");
    let scan = secrets::scan_dir(&secret_rules(), &dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(scan.findings.is_empty());
    assert!(
        scan.verified.is_empty(),
        "a scan that read nothing has established nothing"
    );
}

// ---- the probes ----

fn response(id: &str, status: u16, headers: &[(&str, &str)], body: &str) -> probes::ProbeResponse {
    probes::ProbeResponse {
        id: id.into(),
        status,
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), (*v).to_owned()))
            .collect(),
        body: body.into(),
    }
}

fn careful_home() -> probes::ProbeResponse {
    response(
        "home",
        200,
        &[
            (
                "Content-Security-Policy",
                "default-src 'self'; frame-ancestors 'none'",
            ),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Set-Cookie", "session=abc; HttpOnly; SameSite=Strict"),
        ],
        "<html>hi</html>",
    )
}

#[test]
fn an_app_that_answered_correctly_gets_the_credit_for_it() {
    // The one place anything here observes the running app doing the right thing, rather than
    // failing to observe it doing the wrong one.
    let verified = probes::verified(&[careful_home()]);
    let ids = verified_ids(&verified);
    assert!(ids.contains(&"probe.security-headers"), "{ids:?}");
    assert!(ids.contains(&"probe.cookie-attributes"), "{ids:?}");
}

#[test]
fn a_probe_with_no_answer_credits_nothing() {
    // An app that never replied has not been shown to be careful. Without this, a run against an
    // app that would not start reads as a run against an app that passed.
    let verified = probes::verified(&[]);
    assert!(verified.is_empty(), "{:?}", verified_ids(&verified));
}

#[test]
fn an_app_that_sets_no_cookie_is_not_credited_with_setting_good_ones() {
    // The subtle one, and the reason the cookie arm looks for a cookie first. `cookie_attributes`
    // returns None both for an app with careful cookies and for an app with no cookies at all, so
    // reading "no finding" as "correct" hands a green line to every app that never set one.
    let home = response(
        "home",
        200,
        &[
            (
                "Content-Security-Policy",
                "default-src 'self'; frame-ancestors 'none'",
            ),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
        ],
        "hi",
    );
    let verified = probes::verified(&[home]);
    let ids = verified_ids(&verified);
    assert!(
        !ids.contains(&"probe.cookie-attributes"),
        "no cookie is not a correct cookie: {ids:?}"
    );
    // The headers were there, though, so that half is still earned.
    assert!(ids.contains(&"probe.security-headers"), "{ids:?}");
}

#[test]
fn an_app_that_never_answers_the_cors_question_is_not_credited_with_checking_origins() {
    // Second witness for the same trap, on a different rule: `reflected_origin` returns None when
    // the app sends no Access-Control-Allow-Origin at all. That app has not been shown to check
    // origins — it has been shown not to have been asked in a way it answered.
    let silent = response("cors", 200, &[], "");
    let verified = probes::verified(&[silent]);
    let ids = verified_ids(&verified);
    assert!(
        !ids.contains(&"probe.cors-any-origin"),
        "silence is not an origin check: {ids:?}"
    );
}

#[test]
fn an_app_that_gets_it_wrong_is_not_also_credited() {
    let bare = response("home", 200, &[("Set-Cookie", "session=abc")], "hi");
    let verified = probes::verified(&[bare]);
    let ids = verified_ids(&verified);
    assert!(ids.is_empty(), "{ids:?}");
}

// ---- the rule that holds across all of them ----

#[test]
fn nothing_claims_more_when_it_passes_than_it_cites_when_it_fails() {
    // The direction this whole file exists to prevent movement in. A check that names three
    // requirements on the way out and five on the way through is claiming credit for work it did
    // not do, and the report has no way to tell.
    let rules = ast_rules();
    let dir = scratch("ast-symmetry");
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    let clean = ast::scan_dir(&rules, &dir);
    std::fs::remove_dir_all(&dir).ok();

    assert!(!clean.verified.is_empty(), "the setup checks nothing");
    for v in &clean.verified {
        let (_, _, cited) = rules
            .coverage()
            .into_iter()
            .find(|(id, _, _)| *id == v.check_id)
            .expect("the rule exists");
        assert_eq!(
            v.requirement_ids, cited,
            "{} verifies a different set of requirements from the ones it cites",
            v.check_id
        );
    }

    // And the same for the probes, whose ids live in Rust rather than in the data file.
    let careful = probes::verified(&[careful_home()]);
    assert!(!careful.is_empty());
    let bare = probes::evaluate(&[response("home", 200, &[("Set-Cookie", "s=1")], "")]);
    for v in &careful {
        if let Some(f) = bare.iter().find(|f| f.rule_id == v.check_id) {
            assert_eq!(
                v.requirement_ids, f.requirement_ids,
                "{} verifies a different set from the one it cites when it fails",
                v.check_id
            );
        }
    }
}

#[test]
fn a_clean_ruby_php_and_java_app_can_now_say_it_was_read() {
    // The other half of what the grammars bought. Before them, a single Ruby file silenced every
    // rule for the whole app — the fail-closed behaviour working correctly on an app `sv` could not
    // read. Three more languages read means three fewer apps that get nothing but silence.
    let dir = scratch("polyglot-clean");
    std::fs::write(
        dir.join("worker.rb"),
        "def find(db, name)\n  db.execute(\"select * from notes where title = ?\", [name])\nend\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("index.php"),
        "<?php\n$stmt = $db->prepare(\"select * from notes where title = ?\");\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("App.java"),
        "class App { void f() { System.out.println(\"hi\"); } }\n",
    )
    .unwrap();

    let scan = ast::scan_dir(&ast_rules(), &dir);
    let unread: Vec<String> = scan.unread_languages.iter().cloned().collect();
    let verified = scan.verified.clone();
    let findings = scan.findings.clone();
    std::fs::remove_dir_all(&dir).ok();

    assert!(
        findings.is_empty(),
        "this app is written carefully: {findings:?}"
    );
    assert!(
        unread.is_empty(),
        "nothing here should be unreadable any more: {unread:?}"
    );
    assert!(
        !verified.is_empty(),
        "a fully-read app must be able to report clean coverage"
    );
    let scopes: Vec<&str> = verified.iter().map(|v| v.scope.as_str()).collect();
    for language in ["ruby", "php", "java"] {
        assert!(
            scopes.iter().any(|s| s.contains(language)),
            "{language} is read now and must appear in what was covered: {scopes:?}"
        );
    }
}

// ---- a page of markup is not a hole in the coverage ----

#[test]
fn a_plain_html_page_does_not_silence_the_rules() {
    // The case this exists for. `html` covers `.html`, `.vue` and `.svelte`, almost every web app
    // has one, and counting every page as unread silenced every rule for nearly every real app —
    // a great deal of silence bought by a file that in this case hides nothing at all.
    let dir = scratch("html-plain");
    std::fs::write(
        dir.join("app.py"),
        "def find(db, n):\n    return db.execute('select 1 where t = ?', [n])\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<html><body><h1>Notes</h1><script src=\"app.js\"></script></body></html>\n",
    )
    .unwrap();
    let scan = ast::scan_dir(&ast_rules(), &dir);
    let unread: Vec<String> = scan.unread_languages.iter().cloned().collect();
    let verified = scan.verified.clone();
    std::fs::remove_dir_all(&dir).ok();

    assert!(
        unread.is_empty(),
        "a page of markup, and a script file that is itself parsed, hide nothing: {unread:?}"
    );
    assert!(
        !verified.is_empty(),
        "so the rules that read the Python may say they read it"
    );
}

#[test]
fn a_script_written_into_a_page_is_read_and_reported() {
    // The whole point. The page used to silence every rule for the app; now its script is read,
    // and the `eval` in it is found and named against the page and the line it is really on.
    let dir = scratch("html-script");
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<html>\n<body>\n<script>\neval(location.hash)\n</script>\n</body>\n</html>\n",
    )
    .unwrap();
    let scan = ast::scan_dir(&ast_rules(), &dir);
    let unread: Vec<String> = scan.unread_languages.iter().cloned().collect();
    let findings = scan.findings.clone();
    let verified = scan.verified.clone();
    std::fs::remove_dir_all(&dir).ok();

    assert!(unread.is_empty(), "the script came out: {unread:?}");
    let found = findings
        .iter()
        .find(|f| f.rule_id == "ast.dynamic-code-execution")
        .unwrap_or_else(|| panic!("the eval in the page: {findings:?}"));
    assert_eq!(found.location.file, "index.html");
    assert_eq!(
        found.location.line, 4,
        "the line in the page, not in the fragment"
    );
    assert!(
        !verified.is_empty(),
        "and the rules may now say what they read"
    );
}

#[test]
fn a_handler_attribute_is_read_too() {
    // Second witness of a different shape: no script element at all, and code all the same.
    let dir = scratch("html-handler");
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<html>\n<body>\n<button onclick=\"eval(location.hash)\">go</button>\n</body>\n</html>\n",
    )
    .unwrap();
    let scan = ast::scan_dir(&ast_rules(), &dir);
    let unread: Vec<String> = scan.unread_languages.iter().cloned().collect();
    let findings = scan.findings.clone();
    std::fs::remove_dir_all(&dir).ok();

    assert!(unread.is_empty(), "{unread:?}");
    let found = findings
        .iter()
        .find(|f| f.rule_id == "ast.dynamic-code-execution")
        .unwrap_or_else(|| panic!("the eval in the handler: {findings:?}"));
    assert_eq!(found.location.line, 3);
}

#[test]
fn a_vue_component_is_read_like_a_page() {
    // `.vue` and `.svelte` are the same language to the scanner, and a component's whole point is
    // usually the script block.
    let dir = scratch("html-vue");
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(
        dir.join("App.vue"),
        "<template><p>hi</p></template>\n<script>export default { mounted() { eval(x) } }</script>\n",
    )
    .unwrap();
    let scan = ast::scan_dir(&ast_rules(), &dir);
    let unread: Vec<String> = scan.unread_languages.iter().cloned().collect();
    let ids: Vec<&str> = scan.findings.iter().map(|f| f.rule_id.as_str()).collect();
    std::fs::remove_dir_all(&dir).ok();
    assert!(unread.is_empty(), "{unread:?}");
    assert!(ids.contains(&"ast.dynamic-code-execution"), "{ids:?}");
}

#[test]
fn a_page_holding_something_the_extractor_cannot_take_still_silences_them() {
    // The half that keeps the other half honest. An unquoted attribute value ends at whitespace by
    // one reading and at the tag by another, so this extractor will not guess — and while anything
    // is left in the page, the page is unread. Declaring it read is the exact failure the whole
    // arrangement guards against.
    let dir = scratch("html-left-behind");
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<html><body><a href=javascript:go(location.hash)>go</a></body></html>\n",
    )
    .unwrap();
    let scan = ast::scan_dir(&ast_rules(), &dir);
    let unread: Vec<String> = scan.unread_languages.iter().cloned().collect();
    let verified = scan.verified.clone();
    std::fs::remove_dir_all(&dir).ok();

    assert_eq!(unread, vec!["html".to_owned()]);
    assert!(
        verified.is_empty(),
        "code nothing read means nothing established: {verified:?}"
    );
}

#[test]
fn a_page_that_cannot_be_opened_still_silences_them() {
    // Fail closed. Nothing is known about a file that could not be read, and that must not be the
    // case that ends the silence.
    let dir = scratch("html-unreadable");
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    let page = dir.join("index.html");
    std::fs::write(&page, "<html></html>\n").unwrap();
    // Invalid UTF-8 is the readable-but-not-as-text case, which `read_to_string` refuses.
    std::fs::write(&page, [0x3c, 0x68, 0xff, 0xfe, 0x3e]).unwrap();
    let scan = ast::scan_dir(&ast_rules(), &dir);
    let unread: Vec<String> = scan.unread_languages.iter().cloned().collect();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(unread, vec!["html".to_owned()]);
}

#[test]
fn a_script_that_is_never_closed_also_still_silences_them() {
    // Second witness for the same rule as the `javascript:` case, of a different shape: not code
    // the extractor declines to take, but code it cannot find the end of. Both mean something was
    // left in the page, and both must keep the rules quiet.
    let dir = scratch("html-unclosed");
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<html><body><script>eval(location.hash)</body></html>\n",
    )
    .unwrap();
    let scan = ast::scan_dir(&ast_rules(), &dir);
    let unread: Vec<String> = scan.unread_languages.iter().cloned().collect();
    let verified = scan.verified.clone();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(unread, vec!["html".to_owned()]);
    assert!(verified.is_empty(), "{verified:?}");
}

#[test]
fn a_handler_whose_quotes_are_entities_still_parses() {
    // Second witness for putting entities back, of a different shape: not what the string looks
    // like afterwards, but whether the result is code at all. `go(&quot;x&quot;)` left as it is
    // parses as something else entirely, and the finding inside it is lost without a sound.
    let dir = scratch("html-entities");
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<html><body><button onclick=\"eval(&quot;1&quot; + location.hash)\">go</button></body></html>\n",
    )
    .unwrap();
    let scan = ast::scan_dir(&ast_rules(), &dir);
    let ids: Vec<&str> = scan.findings.iter().map(|f| f.rule_id.as_str()).collect();
    let unread: Vec<String> = scan.unread_languages.iter().cloned().collect();
    std::fs::remove_dir_all(&dir).ok();
    assert!(unread.is_empty(), "{unread:?}");
    assert!(
        ids.contains(&"ast.dynamic-code-execution"),
        "the eval inside the entities: {ids:?}"
    );
}

#[test]
fn a_javascript_url_is_read_and_what_is_in_it_reported() {
    // The last place code could sit in a page and be named rather than read.
    let dir = scratch("html-url");
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<html>\n<body>\n<a href=\"javascript:eval(location.hash)\">go</a>\n</body>\n</html>\n",
    )
    .unwrap();
    let scan = ast::scan_dir(&ast_rules(), &dir);
    let unread: Vec<String> = scan.unread_languages.iter().cloned().collect();
    let findings = scan.findings.clone();
    std::fs::remove_dir_all(&dir).ok();

    assert!(unread.is_empty(), "{unread:?}");
    let found = findings
        .iter()
        .find(|f| f.rule_id == "ast.dynamic-code-execution")
        .unwrap_or_else(|| panic!("the eval in the URL: {findings:?}"));
    assert_eq!(found.location.file, "index.html");
    assert_eq!(found.location.line, 3);
}

#[test]
fn a_script_the_grammar_cannot_read_still_silences_them() {
    // The guard that makes the rest of this safe to trust. Tree-sitter always returns a tree, so a
    // block of some template language parses into a wreck that matches no rule and reports nothing
    // — which reads exactly like a block that was clean. A page holding one stays unread.
    let dir = scratch("html-not-js");
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<html><body>\n<script type=\"text/x-template\">\n{{#each i}}<li>{{this}}</li>{{/each}}\n</script>\n</body></html>\n",
    )
    .unwrap();
    let scan = ast::scan_dir(&ast_rules(), &dir);
    let unread: Vec<String> = scan.unread_languages.iter().cloned().collect();
    let verified = scan.verified.clone();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(unread, vec!["html".to_owned()]);
    assert!(verified.is_empty(), "{verified:?}");
}

#[test]
fn a_scheme_written_around_a_tab_still_silences_them() {
    // Second witness for noticing a disguised scheme, of a different shape: the consequence for the
    // app rather than what the extractor returns. A browser reads `java<tab>script:` and runs it;
    // this does not read it, and a page holding one must not be counted as examined.
    let dir = scratch("html-disguised");
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<html><body><a href=\"java\tscript:eval(location.hash)\">go</a></body></html>\n",
    )
    .unwrap();
    let scan = ast::scan_dir(&ast_rules(), &dir);
    let unread: Vec<String> = scan.unread_languages.iter().cloned().collect();
    let verified = scan.verified.clone();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(unread, vec!["html".to_owned()]);
    assert!(verified.is_empty(), "{verified:?}");
}

#[test]
fn a_url_whose_quotes_are_percent_escaped_still_parses() {
    // Second witness for decoding, of a different shape: not what the string equals afterwards but
    // whether the result is code at all. Left as it is, `eval(%22a%22 + x)` parses as something
    // else and the finding inside it is lost without a sound.
    let dir = scratch("html-percent");
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<html><body><a href=\"javascript:eval(%22a%22 + location.hash)\">go</a></body></html>\n",
    )
    .unwrap();
    let scan = ast::scan_dir(&ast_rules(), &dir);
    let ids: Vec<&str> = scan.findings.iter().map(|f| f.rule_id.as_str()).collect();
    let unread: Vec<String> = scan.unread_languages.iter().cloned().collect();
    std::fs::remove_dir_all(&dir).ok();
    assert!(unread.is_empty(), "{unread:?}");
    assert!(
        ids.contains(&"ast.dynamic-code-execution"),
        "the eval behind the escapes: {ids:?}"
    );
}

// ---- the bill of materials, and the comparison against advisories ----
//
// These two said nothing at all when they found nothing wrong, which reads to anybody exactly like
// a check that never ran. Saying something is the easy half; the conditions under which they must
// stay silent are the half that matters, because a green line is not something a reader questions.

use sv_check::advisories::{Advisory, audit};
use sv_check::sbom::{Component, Sbom, VersionSource, completeness_verified};

fn locked(name: &str, version: &str, ecosystem: &str) -> Component {
    Component {
        name: name.into(),
        version: version.into(),
        ecosystem: ecosystem.into(),
        source: VersionSource::Locked,
    }
}

fn one_advisory_about(ecosystem: &str, package: &str, fixed: &str) -> Advisory {
    let json = serde_json::json!({
        "id": "GHSA-test",
        "summary": "A made-up advisory",
        "affected": [{
            "package": { "ecosystem": ecosystem, "name": package },
            "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "0" }, { "fixed": fixed }] }]
        }]
    });
    serde_json::from_value(json).expect("the fixture parses")
}

#[test]
fn a_complete_bill_of_materials_says_so_and_an_empty_one_does_not() {
    let complete = Sbom {
        components: vec![locked("flask", "3.0.0", "Python")],
        unread: vec![],
    };
    let claim = completeness_verified(&complete).expect("a complete list may say it is one");
    assert_eq!(claim.requirement_ids, vec!["V15.1.2".to_string()]);

    // An app with no dependencies `sv` could find is far more often an app whose manifests were
    // never read. Claiming a complete inventory of nothing is the easiest false green line here.
    let empty = Sbom {
        components: vec![],
        unread: vec![],
    };
    assert!(completeness_verified(&empty).is_none());

    // And the two are mutually exclusive: whatever else happens, a document must never be reported
    // as both an incomplete list and a good inventory.
    for sbom in [&complete, &empty] {
        let says_incomplete = sv_check::sbom::incompleteness_finding(sbom).is_some();
        let says_complete = completeness_verified(sbom).is_some();
        assert!(!(says_incomplete && says_complete), "both at once");
    }
}

#[test]
fn an_unread_ecosystem_stops_the_bill_of_materials_claiming_anything() {
    let partial = Sbom {
        components: vec![locked("flask", "3.0.0", "Python")],
        unread: vec![("npm".into(), "package-lock.json could not be read".into())],
    };
    assert!(
        completeness_verified(&partial).is_none(),
        "a list missing a whole ecosystem is not a complete inventory"
    );
}

#[test]
fn the_advisory_comparison_claims_nothing_unless_it_really_covered_the_app() {
    let sbom = Sbom {
        components: vec![locked("flask", "3.0.0", "Python")],
        unread: vec![],
    };
    // The positive case first, because a check that can never speak is not a check.
    let database = vec![one_advisory_about("PyPI", "django", "9.9.9")];
    let result = audit(&sbom, &database);
    assert!(result.findings.is_empty(), "{:?}", result.findings);
    assert_eq!(
        verified_ids(&result.verified),
        vec!["advisories"],
        "a full comparison that found nothing may say so"
    );
    assert_eq!(
        result.verified[0].requirement_ids,
        vec!["V15.2.1".to_string()]
    );

    // Every way the coverage can be short, each of which would otherwise produce a green line.
    // An empty database compares every package against nothing at all.
    assert!(audit(&sbom, &[]).verified.is_empty(), "no database");

    // Nothing to compare is nothing examined.
    let nothing = Sbom {
        components: vec![],
        unread: vec![],
    };
    assert!(
        audit(&nothing, &database).verified.is_empty(),
        "no packages"
    );

    // An ecosystem the database says nothing about: those packages were never really checked.
    let two_ecosystems = Sbom {
        components: vec![
            locked("flask", "3.0.0", "Python"),
            locked("left-pad", "1.0.0", "npm"),
        ],
        unread: vec![],
    };
    let result = audit(&two_ecosystems, &database);
    assert!(!result.uncovered.is_empty());
    assert!(result.verified.is_empty(), "npm was never covered");

    // A component list known to be partial is a clean answer to a question nobody asked.
    let incomplete = Sbom {
        components: vec![locked("flask", "3.0.0", "Python")],
        unread: vec![("npm".into(), "no lockfile".into())],
    };
    assert!(
        audit(&incomplete, &database).verified.is_empty(),
        "the list itself was short"
    );
}

#[test]
fn a_version_that_cannot_be_compared_stops_the_claim() {
    // The subtle one. The package is in a covered ecosystem and matches no advisory, so the naive
    // reading is that it is fine — but nothing could actually be decided about it.
    let odd = Sbom {
        components: vec![locked("flask", "not-a-version", "Python")],
        unread: vec![],
    };
    let database = vec![one_advisory_about("PyPI", "flask", "3.0.0")];
    let result = audit(&odd, &database);
    assert!(
        !result.uncomparable.is_empty(),
        "this version cannot be placed in any range: {:?}",
        result.uncomparable
    );
    assert!(
        result.verified.is_empty(),
        "an undecidable version is not a clean one"
    );
}

// ---- what a clean result says it looked for ----

fn scope_of<'a>(scan: &'a ast::AstScan, rule_id: &str) -> &'a str {
    scan.verified
        .iter()
        .find(|v| v.check_id == rule_id)
        .unwrap_or_else(|| panic!("{rule_id} made no clean claim: {:?}", scan.verified))
        .scope
        .as_str()
}

#[test]
fn a_clean_result_says_what_the_rule_looked_for_and_where_it_looked_for_less() {
    // Found in review: "1 shell file" beside the path rule reads as "the shell scripts were checked
    // for path traversal", when in shell it only looks at commands given a web request variable.
    let scan = scan_files(
        "looks-for",
        &[
            ("app.py", "def home():\n    return 'hello'\n"),
            ("deploy.sh", "#!/bin/sh\ncp build/app.tar /srv/\n"),
        ],
    );
    assert_eq!(
        scope_of(&scan, "ast.file-path-from-value"),
        "a file opened, written, or deleted at a path built from a value rather than written out, \
         in 1 python file; only commands such as cat, rm, or cp given a path from a web request \
         variable (QUERY_STRING, PATH_INFO, and similar); a path from any other variable is not \
         looked at, in 1 shell file"
    );
    // A rule whose shell reach is the same kind of thing still names it in shell's own terms.
    assert!(
        scope_of(&scan, "ast.weak-hash-function")
            .ends_with("; md5sum, sha1sum, or openssl asked for MD5 or SHA-1, in 1 shell file"),
        "{}",
        scope_of(&scan, "ast.weak-hash-function")
    );
}

#[test]
fn languages_the_rule_reads_alike_share_one_phrase() {
    let scan = scan_files(
        "looks-for-alike",
        &[
            ("app.py", "def home():\n    return 'hello'\n"),
            ("util.py", "def two():\n    return 2\n"),
            ("main.go", "package main\n\nfunc main() {}\n"),
            ("tasks.rb", "def two\n  2\nend\n"),
        ],
    );
    assert_eq!(
        scope_of(&scan, "ast.sql-built-by-hand"),
        "a database query joined together from text and values, rather than sent with its values \
         kept separate, in 1 go file, 2 python files, and 1 ruby file"
    );
}

#[test]
fn every_real_rule_says_what_it_looks_for_and_what_it_looks_for_in_shell() {
    // Shell is commands and variables, not calls and arguments, so every rule that reads it says in
    // shell's own terms what it matches there.
    for rule in ast_rules().rules() {
        assert!(
            !rule.looks_for.trim().is_empty(),
            "{} says nothing",
            rule.id
        );
        if rule.queries.contains_key("shell") && rule.id != "ast.download-piped-to-shell" {
            assert!(
                rule.looks_for_in.contains_key("shell"),
                "{} reads shell and does not say what it looks for there",
                rule.id
            );
        }
    }
}

#[test]
fn a_phrase_for_a_language_the_rule_has_no_query_for_is_refused() {
    let dir = scratch("looks-for-refused");
    let path = dir.join("rules.json");
    std::fs::write(
        &path,
        r#"{"rules": [{"id": "t.x", "title": "t", "severity": "high", "confidence": "high",
            "requirementIds": ["V1.3.2"], "cwe": [], "description": "", "impact": "", "fix": "",
            "functionPatterns": {"python": "^eval$"},
            "queries": {"python": "(call function: (identifier) @fn arguments: (argument_list . (_) @arg)) @hit"},
            "looksFor": "eval", "looksForIn": {"ruby": "eval in Ruby"}}]}"#,
    )
    .unwrap();
    let loaded = ast::AstRules::load(&path);
    std::fs::remove_dir_all(&dir).ok();
    let Err(e) = loaded else {
        panic!("a phrase for a language with no query was accepted");
    };
    assert!(e.to_string().contains("has no ruby query"), "{e}");
}
