//! Every count of the requirements that apply adds up to how many apply, in every place a count
//! is shown (deep review R5).
//!
//! The tables, the opening sentence, the terminal's summary, and the AI coding tool's summary each
//! counted *needs attention*, *checked*, and *not verified*, and some of them *documented*, and
//! left out *attested*, *stated*, and *checked by hand*: on an app with an owner's answers the rows
//! fell short of the total by however many the owner had answered, and the requirements that rest
//! on somebody's word were in no row at all. This builds an app where every status really occurs,
//! asserts that first, and then holds each place to the sum.

use serde_json::{Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use sv_check::advisories::Day;

const PLACEHOLDER: &str = "_Nobody has written this yet._";

/// Every status an applicable requirement can have, as `report.json` spells it.
const STATUSES: [&str; 7] = [
    "needs-attention",
    "checked",
    "documented",
    "by-hand",
    "attested",
    "stated",
    "not-verified",
];

/// The `report.json` count field for each status, in `STATUSES`' order.
const COUNT_FIELDS: [&str; 7] = [
    "needs_attention",
    "checked",
    "documented",
    "by_hand",
    "attested",
    "stated",
    "not_verified",
];

fn sv(dir: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sv"));
    c.env("XDG_CONFIG_HOME", dir.join("config"));
    c
}

/// An app where each status occurs at least once: a finding, a satisfied check, a section of the
/// security notes the owner wrote, a design answer and a check by hand the owner recorded through
/// `sv review`, and a design answer nobody recorded, which is the AI coding tool's word.
fn app_with_every_status(name: &str) -> PathBuf {
    let dir: PathBuf = std::env::temp_dir().join(format!("sv-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    let example = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/tested-notes");
    std::fs::copy(example.join("app.py"), dir.join("app.py")).unwrap();
    // Something a rule finds, so a requirement needs attention for a reason of the app's own.
    std::fs::write(
        dir.join("run.py"),
        "import subprocess\n\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n",
    )
    .unwrap();
    let mut manifest = std::fs::read_to_string(example.join("securevibe.toml")).unwrap();
    assert_eq!(
        manifest.matches("[design]").count() + manifest.matches("[checked-by-hand]").count(),
        0,
        "the example grew answers of its own; this test would be adding to them"
    );
    std::fs::write(dir.join("securevibe.toml"), &manifest).unwrap();

    let key_dir = dir.join("config").join("securevibe");
    let (key, _) = sv_check::seal::Key::load_or_make_in(&key_dir).unwrap();
    // Sealed for this app, as `sv review` run in it seals.
    let key = key.for_app(&sv_check::seal::App::of(&dir).unwrap());

    // The security notes: the owner's own section, sealed as `sv review` seals it.
    let made = sv(&dir).arg("notes").arg(&dir).output().expect("sv runs");
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    let template = std::fs::read_to_string(dir.join("security-notes.md")).unwrap();
    let first = template
        .lines()
        .filter_map(|line| line.strip_prefix("## "))
        .filter_map(|rest| rest.split(" — ").next())
        .next()
        .expect("sv notes wrote at least one section")
        .to_owned();
    let prose = "Decided and written down here, with enough words to be an answer.";
    let seal = key.seal(&sv_check::seal::as_strs(&sv_check::seal::notes_fields(
        &first, prose,
    )));
    let notes = template.replacen(
        PLACEHOLDER,
        &format!(
            "Written by: owner\n{} {seal}\n\n{prose}",
            sv_check::notes::SEALED_BY
        ),
        1,
    );
    assert_ne!(
        notes, template,
        "no placeholder to fill in security-notes.md"
    );
    std::fs::write(dir.join("security-notes.md"), notes).unwrap();

    // A design answer and a check by hand, each the owner's as recorded; one design answer not
    // recorded, which is the AI coding tool's word.
    let today = Day::today().expect("a clock after 1970").show();
    let design = sv_manifest::DesignAnswer {
        answer: "yes".into(),
        r#where: Some("app.py".into()),
        by: Some("owner".into()),
        ..Default::default()
    };
    let design_seal = key.seal(&sv_check::seal::as_strs(
        &sv_check::seal::design_answer_fields("V8.3.1", &design),
    ));
    let padlock = "Opened the live site; the padlock shows a trusted certificate.";
    let hand = sv_manifest::HandCheck {
        result: "done".into(),
        on: Some(today.clone()),
        by: Some("owner".into()),
        how: Some(padlock.into()),
        ..Default::default()
    };
    let hand_seal = key.seal(&sv_check::seal::as_strs(
        &sv_check::seal::hand_check_fields("V12.2.2", &hand),
    ));
    manifest.push_str(&format!(
        r#"
[design]
"V8.3.1" = {{ answer = "yes", where = "app.py", by = "owner", seal = "{design_seal}" }}
"V15.3.1" = {{ answer = "yes", where = "app.py", by = "ai-tool" }}
"V2.2.2" = {{ answer = "yes", where = "app.py", by = "ai-tool" }}

[checked-by-hand]
"V12.2.2" = {{ result = "done", on = "{today}", by = "owner", how = "{padlock}", seal = "{hand_seal}" }}
"#
    ));
    std::fs::write(dir.join("securevibe.toml"), &manifest).unwrap();
    dir
}

/// Each count in `report.json`, with the setup asserted first: every status occurs, and each
/// count is the number of requirement rows with that status.
fn counts_from_json(report: &Value) -> (usize, [usize; 7]) {
    let rows = report["requirements"].as_array().expect("requirements");
    let counts = &report["counts"];
    let mut by_status = [0; 7];
    for (i, (status, field)) in STATUSES.iter().zip(COUNT_FIELDS).enumerate() {
        let in_rows = rows.iter().filter(|r| r["status"] == *status).count();
        assert!(
            in_rows > 0,
            "the fixture must give some requirement the status {status}; it gave none. \
             Statuses: {:?}",
            rows.iter().map(|r| &r["status"]).collect::<Vec<_>>()
        );
        let n = counts[field]
            .as_u64()
            .unwrap_or_else(|| panic!("counts.{field}")) as usize;
        assert_eq!(n, in_rows, "counts.{field} against the rows with {status}");
        by_status[i] = n;
    }
    let applicable = counts["applicable"].as_u64().unwrap() as usize;
    assert_eq!(rows.len(), applicable, "counts.applicable against the rows");
    // Two of the tool's answers and one of each of the owner's, so a table that showed one tier's
    // count in another's row would not add up by chance.
    assert_eq!((by_status[4], by_status[5]), (1, 2), "attested, stated");
    (applicable, by_status)
}

/// The integers in a piece of text, in order.
fn numbers(text: &str) -> Vec<usize> {
    text.split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().unwrap())
        .collect()
}

/// The text between `start` and the first `end` after it.
fn between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let at = text
        .find(start)
        .unwrap_or_else(|| panic!("{start:?} is not in:\n{text}"));
    let rest = &text[at + start.len()..];
    &rest[..rest.find(end).unwrap_or(rest.len())]
}

/// The number at the start of each item, bold in Markdown and `<strong>` in HTML.
fn leading_numbers<'a>(items: impl Iterator<Item = &'a str>, open: &str) -> Vec<usize> {
    items
        .filter_map(|item| item.trim_start().strip_prefix(open))
        .map(|rest| numbers(rest)[0])
        .collect()
}

#[test]
fn the_counts_add_up_to_what_applies_in_every_format() {
    let dir = app_with_every_status("counts-add-up");
    let out_dir = dir.join("report");
    let out = sv(&dir)
        .arg("report")
        .arg(&dir)
        .arg("--out")
        .arg(&out_dir)
        .output()
        .expect("sv runs");
    let terminal = String::from_utf8_lossy(&out.stdout).into_owned();
    let read = |name: &str| std::fs::read_to_string(out_dir.join(name)).unwrap_or_default();
    let (json_text, compliance, html) = (
        read("report.json"),
        read("compliance.md"),
        read("report.html"),
    );
    let mcp = mcp_check(&dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // report.json: every status occurs, and the counts are the rows.
    let report: Value = serde_json::from_str(&json_text).expect("report.json");
    let (applicable, by_status) = counts_from_json(&report);
    assert_eq!(by_status.iter().sum::<usize>(), applicable, "report.json");

    // compliance.md: the short version's list, the opening sentence, and the table.
    let short = between(
        &compliance,
        "Of the requirements that apply to this app:\n\n",
        "\n\n",
    );
    let listed = leading_numbers(short.lines(), "- **");
    assert_eq!(
        listed.iter().sum::<usize>(),
        applicable,
        "compliance.md, the short version:\n{short}"
    );
    assert_eq!(
        listed.len(),
        7,
        "one row per status, every one occurring:\n{short}"
    );
    let lede = between(
        &compliance,
        &format!("{applicable} requirements apply to this app."),
        "\n\n",
    );
    assert_eq!(
        numbers(lede).iter().sum::<usize>(),
        applicable,
        "compliance.md, the opening sentence: {lede}"
    );
    let table: Vec<usize> = compliance
        .lines()
        .filter(|l| l.starts_with("| Applies, "))
        .map(|l| *numbers(l.rsplit('|').nth(1).unwrap()).last().unwrap())
        .collect();
    assert_eq!(table.len(), 7, "a row per status in compliance.md's table");
    assert_eq!(
        table.iter().sum::<usize>(),
        applicable,
        "compliance.md's table"
    );
    // The chapter table: with both columns of somebody's word present, each row's statuses add up
    // to its "apply", and the "apply" column to the total.
    let chapters = between(&compliance, "| chapter | apply |", "\n\n");
    assert!(
        chapters.starts_with(
            " a problem found | checked | your word, not a check | your AI tool's word | \
             not verified |"
        ),
        "both columns of somebody's word are shown: {chapters}"
    );
    let mut apply_total = 0;
    for row in chapters.lines().skip(2) {
        let cells: Vec<usize> = row
            .split('|')
            .skip(2)
            .filter(|c| !c.trim().is_empty())
            .map(|c| numbers(c)[0])
            .collect();
        assert_eq!(cells.len(), 8, "{row}");
        assert_eq!(cells[1..6].iter().sum::<usize>(), cells[0], "{row}");
        apply_total += cells[0];
    }
    assert_eq!(
        apply_total, applicable,
        "compliance.md's chapter table:\n{chapters}"
    );

    // report.html: the same three.
    let tally = between(&html, "<ul class=\"tally\">\n", "</ul>");
    let listed = leading_numbers(tally.lines(), "<li><strong>");
    assert_eq!(listed.len(), 7, "report.html, the short version:\n{tally}");
    assert_eq!(
        listed.iter().sum::<usize>(),
        applicable,
        "report.html, the short version"
    );
    let lede = between(&html, "<p class=\"lede\">", "</p>");
    let lede = lede.trim_start_matches(&format!("{applicable} requirements apply to this app."));
    assert_eq!(
        numbers(lede).iter().sum::<usize>(),
        applicable,
        "report.html, the opening sentence: {lede}"
    );
    let table: Vec<usize> = html
        .lines()
        .filter(|l| l.contains(">Applies, "))
        .map(|l| numbers(between(l, "<td class=\"n\">", "</td>"))[0])
        .collect();
    assert_eq!(table.len(), 7, "a row per status in report.html's table");
    assert_eq!(
        table.iter().sum::<usize>(),
        applicable,
        "report.html's table"
    );

    // The terminal: one line per status under the total.
    let summary = between(
        &terminal,
        &format!("{applicable} requirements apply:\n"),
        "\n\n",
    );
    let listed: Vec<usize> = summary.lines().map(|l| numbers(l)[0]).collect();
    assert_eq!(listed.len(), 7, "the terminal's summary:\n{terminal}");
    assert_eq!(
        listed.iter().sum::<usize>(),
        applicable,
        "the terminal:\n{summary}"
    );

    // The AI coding tool's summary, and the counts it is given as data.
    let text = mcp["content"][0]["text"].as_str().expect("a text summary");
    let line = between(
        text,
        &format!("{applicable} requirements apply at ASVS level "),
        "Nothing here says",
    );
    // After the total: the level, then a number per status, then how many could not be placed.
    let n = numbers(line);
    assert_eq!(n.len(), 1 + 7 + 1, "{line}");
    assert_eq!(
        n[1..8].iter().sum::<usize>(),
        applicable,
        "the MCP summary: {line}"
    );
    let data = &mcp["structuredContent"]["counts"];
    assert_eq!(data["applicable"], json!(applicable));
    let sum: u64 = COUNT_FIELDS.iter().map(|f| data[f].as_u64().unwrap()).sum();
    assert_eq!(sum as usize, applicable, "the MCP counts");
}

/// `securevibe_check` on the app, over stdio as an AI coding tool calls it.
fn mcp_check(dir: &Path) -> Value {
    let mut child = sv(dir)
        .args(["mcp", "--root"])
        .arg(dir.parent().unwrap())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sv starts");
    let name = dir.file_name().unwrap().to_str().unwrap();
    let messages = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"securevibe_check","arguments":{"path":name}}}),
    ];
    {
        let stdin = child.stdin.as_mut().unwrap();
        for m in &messages {
            writeln!(stdin, "{m}").unwrap();
        }
    }
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("sv exits");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let reply: Value = stdout
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|r| r["id"] == 2)
        .unwrap_or_else(|| {
            panic!(
                "no reply to the check: {stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    reply["result"].clone()
}
