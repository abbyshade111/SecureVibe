//! Part 2 of the false-alarm work, end to end: a person's `[[finding-review]]` entries in
//! securevibe.toml, as the report, the SARIF, and the AI coding tool see them.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

const REDIRECT: &str = "    return redirect(request.args.get(\"next\"))";
const MANIFEST: &str =
    "manifest-version = 1\n[app]\nname = \"Reviewed\"\n[stack]\nlanguages = [\"python\"]\n";

fn app(dir: &Path, redirect_line: &str) {
    std::fs::write(
        dir.join("app.py"),
        format!(
            "from flask import Flask, redirect, request\napp = Flask(__name__)\n\n@app.route(\"/go\")\ndef go():\n{redirect_line}\n\ndef find(db, user_id):\n    cur = db.cursor()\n    cur.execute(\"SELECT * FROM notes WHERE owner = \" + user_id)\n"
        ),
    )
    .unwrap();
}

struct Run {
    security: String,
    compliance: String,
    html: String,
    json: Value,
    sarif: Value,
}

fn report(dir: &Path) -> Run {
    report_exiting(dir, &[0])
}

/// `report`, which may exit with one of `codes`.
fn report_exiting(dir: &Path, codes: &[i32]) -> Run {
    let out = dir.join("report");
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .env("XDG_CONFIG_HOME", config())
        .arg("report")
        .arg(dir)
        .arg("--out")
        .arg(&out)
        .output()
        .expect("sv runs");
    assert!(
        run.status.code().is_some_and(|c| codes.contains(&c)),
        "{:?}: {}",
        run.status,
        String::from_utf8_lossy(&run.stderr)
    );
    let read = |name: &str| std::fs::read_to_string(out.join(name)).unwrap();
    Run {
        security: read("security.md"),
        compliance: read("compliance.md"),
        html: read("report.html"),
        json: serde_json::from_str(&read("report.json")).unwrap(),
        sarif: serde_json::from_str(&read("findings.sarif")).unwrap(),
    }
}

fn fingerprint(run: &Run, rule: &str) -> String {
    run.json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == rule)
        .and_then(|f| f["fingerprint"].as_str())
        .unwrap_or_else(|| {
            panic!(
                "no {rule} finding with a fingerprint: {}",
                run.json["findings"]
            )
        })
        .to_owned()
}

fn status(run: &Run, id: &str) -> String {
    run.compliance
        .lines()
        .find(|l| l.starts_with(&format!("| {id} |")))
        .unwrap_or_else(|| panic!("no row for {id}"))
        .split('|')
        .nth(2)
        .unwrap()
        .trim()
        .trim_start_matches("**")
        .to_owned()
}

/// The review key this test's runs of `sv` use, as `sv review` would have made it, so a person's
/// entry can be sealed the way `sv review` seals it.
/// Made once, since the tests here run at the same time.
fn config() -> PathBuf {
    static MADE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    MADE.get_or_init(|| {
        let dir =
            std::env::temp_dir().join(format!("sv-finding-review-config-{}", std::process::id()));
        sv_check::seal::Key::load_or_make_in(&dir.join("securevibe")).unwrap();
        dir
    })
    .clone()
}

/// The review key, sealing for the app in `dir` as `sv review` run there would.
fn key(dir: &Path) -> sv_check::seal::AppKey {
    sv_check::seal::Key::load_or_make_in(&config().join("securevibe"))
        .unwrap()
        .0
        .for_app(&sv_check::seal::App::of(dir).unwrap())
}

/// An entry of the app in `dir`; a person's is sealed as `sv review` seals it, the AI coding
/// tool's is not.
fn entry(
    dir: &Path,
    rule: &str,
    file: &str,
    fingerprint: &str,
    verdict: &str,
    by: &str,
    why: &str,
) -> String {
    let on = sv_check::advisories::Day::today().unwrap().show();
    let review = sv_manifest::FindingReview {
        rule: rule.into(),
        file: file.into(),
        fingerprint: fingerprint.into(),
        verdict: verdict.into(),
        why: why.into(),
        by: Some(by.into()),
        on: Some(on.clone()),
        seal: None,
    };
    let seal = if by == "ai-tool" {
        String::new()
    } else {
        let fields = sv_check::seal::finding_review_fields(&review);
        format!(
            "seal = \"{}\"\n",
            key(dir).seal(&sv_check::seal::as_strs(&fields))
        )
    };
    format!(
        "\n[[finding-review]]\nrule = \"{rule}\"\nfile = \"{file}\"\nfingerprint = \"{fingerprint}\"\nverdict = \"{verdict}\"\nwhy = \"{why}\"\nby = \"{by}\"\non = \"{on}\"\n{seal}"
    )
}

#[test]
fn a_persons_review_sets_findings_aside_and_the_tools_proposal_does_not() {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("sv-finding-review-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    app(&dir, REDIRECT);
    std::fs::write(dir.join("securevibe.toml"), MANIFEST).unwrap();

    // First, as found: both need attention, and each finding carries the name a review uses.
    let before = report(&dir);
    let redirect = fingerprint(&before, "ast.open-redirect");
    let sql = fingerprint(&before, "ast.sql-built-by-hand");
    let contact = fingerprint(&before, "config.security-contact");
    assert!(
        before
            .security
            .contains(&format!("Fingerprint: `{redirect}`"))
    );
    assert!(status(&before, "V3.7.2").starts_with("needs attention"));
    assert!(status(&before, "V1.2.4").starts_with("needs attention"));

    // A person sets the redirect aside as a false alarm and accepts the SQL for now; the AI tool
    // proposes that the missing SECURITY.md is a false alarm.
    let why = "The next= value is looked up in a fixed list of our own paths before redirect.";
    std::fs::write(
        dir.join("securevibe.toml"),
        format!(
            "{MANIFEST}{}{}{}",
            entry(
                &dir,
                "ast.open-redirect",
                "app.py",
                &redirect,
                "false-alarm",
                "owner",
                why
            ),
            entry(
                &dir,
                "ast.sql-built-by-hand",
                "app.py",
                &sql,
                "accepted-risk",
                "Sam Lee",
                "Internal tool behind the VPN; parameterizing it is planned for next month."
            ),
            entry(
                &dir,
                "config.security-contact",
                "SECURITY.md",
                &contact,
                "false-alarm",
                "ai-tool",
                "The app is private and nobody outside will ever report a problem to it."
            ),
        ),
    )
    .unwrap();
    let after = report(&dir);

    // The headline counts what was set aside, in both renderings, rather than leaving the reader to
    // find it further down (deep review R2).
    for page in [&after.compliance, &after.html] {
        assert!(
            page.contains("1 more was found and set aside as a false alarm in securevibe.toml"),
            "{page}"
        );
    }

    // The false alarm: off the list, in its own section with the reason, and its requirement
    // back to what else is known, not needing attention and not checked.
    let to_fix = after
        .security
        .split("things to fix")
        .nth(1)
        .unwrap_or_else(|| panic!("no list of things to fix:\n{}", after.security));
    assert!(!to_fix.contains("app.py` line 6"), "{}", after.security);
    assert!(after.security.contains("## Set aside in securevibe.toml"));
    assert!(after.security.contains(why));
    // Who set it aside is what `sv review` recorded, and the report says what its seal shows and
    // what it cannot (deep review R1).
    for page in [&after.security, &after.html] {
        assert!(
            !page.to_lowercase().contains("set aside by a person"),
            "{page}"
        );
        assert!(
            page.contains("it cannot show who was at the keyboard"),
            "{page}"
        );
    }
    assert!(
        after.security.contains(
            "Recorded through `sv review` on this computer: the owner set it aside as a false alarm on"
        ),
        "{}",
        after.security
    );
    // Reported against the rule, with only the rule's name in the link; the accepted risk is not.
    assert!(
        after.security.contains("[Report it against the rule](https://github.com/abbyshade111/SecureVibe/issues/new?template=false_alarm.yml&title=False%20alarm%3A%20ast.open-redirect&rule=ast.open-redirect&"),
        "{}",
        after.security
    );
    assert!(!after.security.contains("rule=ast.sql-built-by-hand"));
    assert!(after.security.contains("usually a rule that will misfire"));
    assert!(
        after.html.contains("Report it against the rule</a>"),
        "{}",
        after.html
    );
    // The link is built from the rule alone: nothing of the app's files leaves in it.
    let link = after
        .security
        .split("[Report it against the rule](")
        .nth(1)
        .and_then(|rest| rest.split(')').next())
        .expect("a link");
    assert!(
        !link.contains("app.py") && !link.contains("file="),
        "{link}"
    );
    let v372 = status(&after, "V3.7.2");
    assert!(
        !v372.starts_with("needs attention") && !v372.starts_with("checked"),
        "V3.7.2: {v372}"
    );

    // The accepted risk: still on the list, labeled, still needing attention.
    assert!(
        to_fix.contains("Known and accepted as a risk for now. Recorded through `sv review` on this computer: Sam Lee accepted it on"),
        "{to_fix}"
    );
    assert!(status(&after, "V1.2.4").starts_with("needs attention"));

    // The tool's proposal: not counted, shown with what it said, the finding still listed.
    assert!(
        after.security.contains("the AI coding tool's proposal")
            && after.security.contains("nobody outside will ever report"),
        "{}",
        after.security
    );
    assert!(to_fix.contains("SECURITY.md"), "{to_fix}");

    // The SARIF agrees: the false alarm is there, marked suppressed with the reason; the accepted
    // risk is not suppressed and says who accepted it; every result can be matched again.
    let results = after.sarif["runs"][0]["results"].as_array().unwrap();
    let by_rule = |rule: &str| {
        results
            .iter()
            .find(|r| r["ruleId"] == rule)
            .unwrap_or_else(|| panic!("no {rule} in the SARIF"))
    };
    let suppressed = &by_rule("ast.open-redirect")["suppressions"][0];
    assert_eq!(suppressed["kind"], "external");
    assert!(suppressed["justification"].as_str().unwrap().contains(why));
    let accepted = by_rule("ast.sql-built-by-hand");
    assert!(accepted.get("suppressions").is_none());
    assert_eq!(accepted["properties"]["acceptedRisk"]["by"], "Sam Lee");
    assert!(
        by_rule("config.security-contact")
            .get("suppressions")
            .is_none()
    );
    assert!(
        results
            .iter()
            .all(|r| r["partialFingerprints"]["svFingerprint/v1"].is_string())
    );

    // What the AI coding tool is told: what was set aside in securevibe.toml, and that its own proposal does
    // not count and is never to be signed with a person's name.
    let tool = mcp_check(&dir);
    assert!(
        tool.contains("SET ASIDE IN securevibe.toml through `sv review`")
            && tool.contains("never run it for them, and never write a `seal`")
            && tool.contains(why),
        "{tool}"
    );
    assert!(
        tool.contains("report it against the rule: https://github.com/abbyshade111/SecureVibe/issues/new?template=false_alarm.yml")
            && tool.contains(sv_report::FALSE_ALARM_TOOL_NOTE)
            && tool.contains("never file it yourself"),
        "{tool}"
    );
    assert!(
        tool.contains("NOT COUNTED in [[finding-review]]")
            && tool.contains("never run `sv review` for them, and never write a `seal` or a person's name in `by`")
            && tool.contains("the AI coding tool's proposal"),
        "{tool}"
    );

    // The flagged line changes: the false alarm no longer matches, and the finding is back.
    app(
        &dir,
        "    return redirect(request.args.get(\"next\", \"/\"))",
    );
    let changed = report(&dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(status(&changed, "V3.7.2").starts_with("needs attention"));
    assert!(
        changed.security.contains("no finding matches it any more"),
        "{}",
        changed.security
    );
}

/// `sv <command> <dir> --fail-on attention:medium`: its exit status and everything it printed.
fn exit_of(command: &str, dir: &Path) -> (i32, String) {
    let out_dir = dir.join("report");
    let mut sv = Command::new(env!("CARGO_BIN_EXE_sv"));
    sv.env("XDG_CONFIG_HOME", config())
        .arg(command)
        .arg(dir)
        .args(["--fail-on", "attention:medium"]);
    if command == "report" {
        sv.arg("--out").arg(&out_dir);
    }
    let out = sv.output().expect("sv runs");
    (
        out.status.code().expect("an exit status"),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn sv_check_counts_what_sv_report_counts_on_the_same_folder() {
    // ADR-023, Later, 8 October 2026. Until then `sv check` counted every finding toward its exit
    // status and `sv report` the findings left after a person's reviews, so `sv check --fail-on
    // attention` failed a CI pipeline on a finding the owner had set aside.
    let dir: PathBuf = std::env::temp_dir().join(format!("sv-check-agrees-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    // One finding at medium (the open redirect) and one at low (no SECURITY.md); nothing else.
    std::fs::write(
        dir.join("app.py"),
        format!(
            "from flask import Flask, redirect, request\napp = Flask(__name__)\n\n@app.route(\"/go\")\ndef go():\n{REDIRECT}\n"
        ),
    )
    .unwrap();
    std::fs::write(dir.join("securevibe.toml"), MANIFEST).unwrap();
    let before = report(&dir);
    let redirect = fingerprint(&before, "ast.open-redirect");
    let (check_before, check_said) = exit_of("check", &dir);
    let (report_before, _) = exit_of("report", &dir);
    assert_eq!(
        (check_before, report_before),
        (1, 1),
        "the setup: the redirect fails both at medium: {check_said}"
    );
    assert!(check_said.contains("[medium]"), "{check_said}");

    // The owner sets the redirect aside through `sv review`; the AI coding tool proposes that the
    // missing SECURITY.md is a false alarm, which does not count.
    let why = "The next= value is looked up in a fixed list of our own paths before redirect.";
    let contact = fingerprint(&before, "config.security-contact");
    std::fs::write(
        dir.join("securevibe.toml"),
        format!(
            "{MANIFEST}{}{}",
            entry(
                &dir,
                "ast.open-redirect",
                "app.py",
                &redirect,
                "false-alarm",
                "owner",
                why
            ),
            entry(
                &dir,
                "config.security-contact",
                "SECURITY.md",
                &contact,
                "false-alarm",
                "ai-tool",
                "The app is private and nobody outside will ever report a problem to it."
            ),
        ),
    )
    .unwrap();
    let (check_after, check_said) = exit_of("check", &dir);
    let (report_after, report_said) = exit_of("report", &dir);
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(report_after, 0, "{report_said}");
    assert_eq!(
        check_after, report_after,
        "sv check exits {check_after} where sv report exits {report_after}: {check_said}"
    );
    // Nothing is dropped quietly: the terminal says what was set aside, by whom, and why, and
    // that the tool's proposal does not count; the redirect is no longer a thing to look at.
    assert!(
        check_said.contains("In securevibe.toml, through `sv review`:")
            && check_said.contains("ast.open-redirect in app.py: a false alarm, by owner on")
            && check_said.contains(why),
        "{check_said}"
    );
    assert!(
        check_said.contains("Not counted in [[finding-review]]")
            && check_said.contains("the AI coding tool's proposal"),
        "{check_said}"
    );
    let to_look_at = check_said
        .split("thing to look at:")
        .nth(1)
        .unwrap_or_else(|| panic!("no list of things to look at:\n{check_said}"));
    assert!(!to_look_at.contains("[medium]"), "{to_look_at}");
    assert!(
        to_look_at.contains("SECURITY.md (not there)"),
        "{to_look_at}"
    );
}

/// `securevibe_check` over MCP, as the AI coding tool calls it; the text it is given.
fn mcp_check(app: &Path) -> String {
    mcp_reply(app)["result"]["content"][0]["text"]
        .as_str()
        .map(str::to_owned)
        .map(unfenced)
        .expect("a reply to the check")
}

/// What the check says with its fence's tags taken out (deep review R9): this test is about what is
/// said, and the app's text is fenced as data.
fn unfenced(text: String) -> String {
    let Some(tag) = text
        .strip_prefix("Text between <")
        .and_then(|rest| rest.split_once('>'))
        .map(|(tag, _)| tag.to_owned())
    else {
        return text;
    };
    text.replace(&format!("</{tag}>"), "")
        .replace(&format!("<{tag}>"), "")
}

/// The whole reply to `securevibe_check` over MCP, text and structured results alike.
fn mcp_reply(app: &Path) -> Value {
    use std::io::Write;
    let mut child = Command::new(env!("CARGO_BIN_EXE_sv"))
        .env("XDG_CONFIG_HOME", config())
        .args(["mcp", "--root"])
        .arg(app.parent().unwrap())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("sv starts");
    let name = app.file_name().unwrap().to_string_lossy().into_owned();
    {
        let stdin = child.stdin.as_mut().unwrap();
        writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-06-18","capabilities":{{}},"clientInfo":{{"name":"test","version":"0"}}}}}}"#).unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#
        )
        .unwrap();
        writeln!(stdin, r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"securevibe_check","arguments":{{"path":"{name}"}}}}}}"#).unwrap();
    }
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|r| r["id"] == 2)
        .expect("a reply to the check")
}

/// Deep review R3: an entry that matches no finding says which of three things happened, in the
/// report and in what the AI coding tool is told, and only the last reads as the finding gone.
/// With A2, an entry written with the fingerprint used before 5 October 2026 still counts.
#[test]
fn an_entry_that_matches_nothing_says_whether_its_rule_looked_and_an_earlier_one_still_counts() {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("sv-finding-review-r3-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(dir.join("tests")).unwrap();
    app(&dir, REDIRECT);
    // A file of the app's language that does not parse cleanly.
    std::fs::write(dir.join("broken.py"), "def broken(:\n    cur.execute(q)\n").unwrap();
    std::fs::write(
        dir.join("tests/test_notes.py"),
        "def test_v1_2_4_notes_are_found():\n    assert True\n",
    )
    .unwrap();
    std::fs::write(dir.join("securevibe.toml"), MANIFEST).unwrap();
    // 2, because `broken.py` could not be read in full.
    let before = report_exiting(&dir, &[2]);
    let redirect = fingerprint(&before, "ast.open-redirect");
    assert!(redirect.starts_with("v2-"), "{redirect}");
    // The setup: the redirect was found on app.py, and the code rules read app.py.
    let examined = before.json["examined"].as_array().unwrap();
    let state = |rules: &str| {
        examined
            .iter()
            .find(|e| e["rules"] == rules)
            .unwrap_or_else(|| panic!("no examined entry for {rules}: {examined:?}"))["state"]
            .clone()
    };
    assert_eq!(state("tests."), "not-run");
    assert_eq!(state("design."), "ran");
    assert_eq!(state("hand."), "ran");

    let why = "Looked at by the owner on the day, and the value never comes from a request.";
    let sql_line = "cur.execute(\"SELECT * FROM notes WHERE owner = \" + user_id)";
    std::fs::write(
        dir.join("securevibe.toml"),
        format!(
            "{MANIFEST}{}{}{}{}{}{}",
            // The rule ran over app.py and the line is fixed below: gone.
            entry(
                &dir,
                "ast.open-redirect",
                "app.py",
                &redirect,
                "false-alarm",
                "owner",
                why
            ),
            // Reported only when the app's tests run, which needs --run: not looked for.
            entry(
                &dir,
                "tests.name-does-not-match-requirement",
                "tests/test_notes.py",
                "v2-0123456789abcdef",
                "false-alarm",
                "owner",
                why
            ),
            // An outside tool, which runs only with --tools: not looked for.
            entry(
                &dir,
                "bandit.B608",
                "app.py",
                "v2-0123456789abcdef",
                "false-alarm",
                "owner",
                why
            ),
            // A file the code rules could not read in full: not looked for.
            entry(
                &dir,
                "ast.sql-built-by-hand",
                "broken.py",
                "v2-0123456789abcdef",
                "false-alarm",
                "owner",
                why
            ),
            // A rule this version does not have.
            entry(
                &dir,
                "ast.no-such-rule",
                "app.py",
                "v2-0123456789abcdef",
                "false-alarm",
                "owner",
                why
            ),
            // Written with the fingerprint used before 5 October 2026, on a line no other
            // finding shares: it counts, as it did.
            entry(
                &dir,
                "ast.sql-built-by-hand",
                "app.py",
                &sv_check::review::named("ast.sql-built-by-hand", "app.py", sql_line),
                "accepted-risk",
                "owner",
                why
            ),
        ),
    )
    .unwrap();
    app(&dir, "    return redirect(url_for(\"home\"))");
    let after = report_exiting(&dir, &[2]);
    let tool = mcp_check(&dir);
    std::fs::remove_dir_all(&dir).ok();

    let named = |rule: &str, file: &str| format!("`{rule}` in {file}");
    let says = |page: &str, rule: &str, file: &str, what: &str| {
        let line = page
            .lines()
            .find(|l| l.contains(&named(rule, file)))
            .unwrap_or_else(|| panic!("no line for {rule} in {file}:\n{page}"));
        assert!(line.contains(what), "{rule}: {line}");
        line.to_owned()
    };
    for page in [&after.security, &tool] {
        let gone = says(
            page,
            "ast.open-redirect",
            "app.py",
            "no finding matches it any more, and the check that reports it looked at this file",
        );
        assert!(gone.contains("can be removed"), "{gone}");
        for (rule, file, what) in [
            (
                "tests.name-does-not-match-requirement",
                "tests/test_notes.py",
                "not looked for this time (the app's own tests run only with --run)",
            ),
            (
                "bandit.B608",
                "app.py",
                "not looked for this time (outside tools run only with --tools)",
            ),
            (
                "ast.sql-built-by-hand",
                "broken.py",
                "not looked for this time (`broken.py` did not parse cleanly",
            ),
            (
                "ast.no-such-rule",
                "app.py",
                "has no rule `ast.no-such-rule`",
            ),
        ] {
            let line = says(page, rule, file, what);
            assert!(
                line.contains("not a sign the finding was fixed")
                    && !line.contains("no finding matches it")
                    && !line.contains("can be removed"),
                "{line}"
            );
        }
    }
    assert!(
        after.html.contains("not looked for this time")
            && after.html.contains("has no rule `ast.no-such-rule`"),
        "{}",
        after.html
    );
    assert!(
        tool.contains("never remove it or tell the owner the finding is gone"),
        "{tool}"
    );
    // The earlier fingerprint still names its finding.
    assert!(
        after
            .security
            .contains("Known and accepted as a risk for now"),
        "{}",
        after.security
    );
    assert!(
        !after
            .security
            .contains(&named("ast.sql-built-by-hand", "app.py")),
        "{}",
        after.security
    );
}

/// Deep review R4 with A2: no fingerprint the report or the AI coding tool is given for a credential
/// finding, today's or the earlier one given beside it, is a hash over the credential as written,
/// from which a short one could be guessed back.
#[test]
fn no_fingerprint_given_for_a_credential_is_over_its_value_as_written() {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("sv-finding-review-r4-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    // A test password built at run time, so this file holds none.
    let password: String = ["Xk7mQ92v", "LpR4sTzW"].concat();
    let line = format!("db_password = \"{password}\"");
    std::fs::write(
        dir.join("app.py"),
        format!("import sqlite3\n{line}\nconn = connect(db_password)\n"),
    )
    .unwrap();
    std::fs::write(dir.join("securevibe.toml"), MANIFEST).unwrap();
    let run = report(&dir);
    let reply = mcp_reply(&dir).to_string();
    std::fs::remove_dir_all(&dir).ok();

    let rule = "secrets.credential-assignment";
    // The fingerprint an `sv` before R4 gave this line: a hash over the password as written.
    let unsafe_hash = sv_check::review::named(rule, "app.py", &line);
    let leaks = |text: &str| text.contains(&unsafe_hash) || text.contains(&password);
    // The control: the check finds a planted unsafe hash.
    assert!(leaks(&format!("{{\"fingerprint\": \"{unsafe_hash}\"}}")));
    // The setup: the credential was found, and given a fingerprint and an earlier one.
    let found = run.json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == rule)
        .unwrap_or_else(|| panic!("no {rule} finding: {}", run.json["findings"]));
    assert!(found["fingerprint"].as_str().unwrap().starts_with("v2-"));
    assert_eq!(
        found["earlier_fingerprints"][0].as_str().unwrap(),
        sv_check::review::named(rule, "app.py", &sv_check::review::masked(&line)),
        "the earlier one given is over the masked line"
    );
    assert!(
        reply.contains(found["fingerprint"].as_str().unwrap()),
        "the setup: MCP gives fingerprints"
    );
    for (what, text) in [
        ("report.json", run.json.to_string()),
        ("findings.sarif", run.sarif.to_string()),
        ("security.md", run.security.clone()),
        ("report.html", run.html.clone()),
        ("the MCP reply", reply.clone()),
    ] {
        assert!(
            !leaks(&text),
            "{what} gives a fingerprint over the password as written"
        );
    }
}
