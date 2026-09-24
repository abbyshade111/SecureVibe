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
