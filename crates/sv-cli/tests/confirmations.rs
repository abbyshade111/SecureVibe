//! A person confirming what the AI coding tool said, end to end: what the report says about each
//! kind of confirmation, which is what the owner reads.
//!
//! The rules are held beside them in `sv_check::confirm`; this holds that the report uses them, that
//! a confirmation that holds is shown as confirmed rather than as the owner's own word, and that one
//! that does not hold is named with its reason instead of quietly counting or quietly vanishing.

use std::path::PathBuf;
use std::process::Command;
use sv_check::advisories::Day;

/// The status column of the requirement's row in compliance.md.
fn status_of<'a>(compliance: &'a str, id: &str) -> &'a str {
    let row = compliance
        .lines()
        .find(|line| line.starts_with(&format!("| {id} |")))
        .unwrap_or_else(|| panic!("no row for {id} in the report:\n{compliance}"));
    row.split('|').nth(2).unwrap_or("").trim()
}

/// A confirmation as inline TOML, sealed as `sv review` seals it with this test's key: every rule
/// below is about what the confirmation says, so each is recorded the way a person would.
#[allow(clippy::too_many_arguments)]
fn sealed(
    key: &sv_check::seal::Key,
    section: &str,
    id: &str,
    by: &str,
    on: &str,
    answer: Option<&str>,
    location: Option<&str>,
    result: Option<&str>,
    how: Option<&str>,
) -> String {
    let c = sv_manifest::Confirmed {
        by: Some(by.into()),
        on: Some(on.into()),
        how: how.map(str::to_owned),
        answer: answer.map(str::to_owned),
        r#where: location.map(str::to_owned),
        result: result.map(str::to_owned),
        seal: None,
    };
    let fields = sv_check::seal::manifest_confirmation_fields(section, id, &c);
    let seal = key.seal(&sv_check::seal::as_strs(&fields));
    let mut parts = vec![format!("by = \"{by}\""), format!("on = \"{on}\"")];
    for (name, value) in [
        ("answer", answer),
        ("where", location),
        ("result", result),
        ("how", how),
    ] {
        if let Some(value) = value {
            parts.push(format!("{name} = \"{value}\""));
        }
    }
    parts.push(format!("seal = \"{seal}\""));
    format!("{{ {} }}", parts.join(", "))
}

#[test]
fn the_report_shows_each_confirmation_for_what_it_is() {
    let today = Day::today().expect("a clock after 1970");
    let yesterday = Day(today.0 - 1).show();
    let today = today.show();

    let dir: PathBuf =
        std::env::temp_dir().join(format!("sv-confirmations-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    // Written now, so its modification day is today: confirmed today it holds, confirmed
    // yesterday it has changed since.
    std::fs::write(dir.join("app.py"), "def home():\n    return 'hi'\n").unwrap();
    let example = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/tested-notes/securevibe.toml");
    let mut manifest = std::fs::read_to_string(example).unwrap();
    assert!(
        !manifest.contains("[design]") && !manifest.contains("[checked-by-hand]"),
        "the example grew answers of its own; this test would be adding to them"
    );
    let config = dir.join("config");
    let (key, _) = sv_check::seal::Key::load_or_make_in(&config.join("securevibe")).unwrap();
    let how = "Sent a POST to the site and got 405; only GET and HEAD work.";
    let d =
        |id: &str, by: &str, on: &str, answer: &str, location: Option<&str>, how: Option<&str>| {
            sealed(
                &key,
                "design",
                id,
                by,
                on,
                Some(answer),
                location,
                None,
                how,
            )
        };
    let hand_how = "Opened the live site; the padlock shows a trusted certificate.";
    manifest.push_str(&format!(
        r#"
[design]
"V8.3.1" = {{ answer = "yes", where = "app.py", by = "ai-tool", confirmed = {} }}
"V2.2.2" = {{ answer = "yes", where = "app.py", by = "ai-tool", confirmed = {} }}
"V15.3.1" = {{ answer = "yes", where = "app.py", by = "owner", seal = "{}" }}
"V1.1.1" = {{ answer = "yes", where = "app.py", by = "ai-tool", confirmed = {} }}
"V4.1.3" = {{ answer = "yes", by = "ai-tool", confirmed = {} }}
"V4.2.1" = {{ answer = "yes", by = "ai-tool", confirmed = {} }}

[checked-by-hand]
"V12.2.2" = {{ result = "done", on = "{today}", by = "ai-tool", how = "Fetched the live site; the certificate chain is trusted.", confirmed = {} }}
"#,
        d("V8.3.1", "owner", &today, "yes", Some("app.py"), Some(how)),
        d("V2.2.2", "owner", &today, "not-sure", Some("app.py"), Some(how)),
        key.seal(&sv_check::seal::as_strs(&sv_check::seal::design_answer_fields(
            "V15.3.1",
            &sv_manifest::DesignAnswer {
                answer: "yes".into(),
                r#where: Some("app.py".into()),
                by: Some("owner".into()),
                ..Default::default()
            }
        ))),
        d("V1.1.1", "owner", &yesterday, "yes", Some("app.py"), Some(how)),
        d("V4.1.3", "ai-tool", &today, "yes", None, Some(how)),
        d("V4.2.1", "owner", &today, "yes", None, None),
        sealed(&key, "checked-by-hand", "V12.2.2", "Sam Lee", &today, None, None, Some("done"), Some(hand_how)),
    ));
    std::fs::write(dir.join("securevibe.toml"), &manifest).unwrap();

    let out_dir = dir.join("report");
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .env("XDG_CONFIG_HOME", &config)
        .arg("report")
        .arg(&dir)
        .arg("--out")
        .arg(&out_dir)
        .output()
        .expect("sv runs");
    let compliance = std::fs::read_to_string(out_dir.join("compliance.md")).unwrap_or_default();
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!compliance.is_empty(), "the report was not written");

    // Holds: the tool's word, then the owner's, at the owner's rank and never as their own answer.
    let confirmed = status_of(&compliance, "V8.3.1");
    assert!(
        confirmed.starts_with("stated by the AI coding tool, confirmed through sv review")
            && confirmed.contains("the word of whoever confirmed it through sv review")
            && confirmed.contains("your AI coding tool answered yes")
            && confirmed.contains(&format!(
                "Recorded through `sv review` on this computer: you confirmed it on {today}"
            ))
            && confirmed.contains(how),
        "V8.3.1: {confirmed}"
    );
    // The owner's own answer is still theirs, and says so.
    let own = status_of(&compliance, "V15.3.1");
    assert!(own.starts_with("attested by the owner"), "V15.3.1: {own}");
    // A confirmation of a different answer, and one older than the file, count for nothing.
    for id in ["V2.2.2", "V1.1.1", "V4.1.3", "V4.2.1"] {
        let status = status_of(&compliance, id);
        assert!(
            status.starts_with("stated by the AI coding tool \u{2014}"),
            "{id} must stay the tool's word: {status}"
        );
    }
    assert!(
        compliance.contains("V2.2.2 (it confirms the answer not-sure, and the answer is now yes)"),
        "the reason must be named: {compliance}"
    );
    assert!(
        compliance.contains(&format!(
            "V1.1.1 (app.py changed on {today}, after it was confirmed on {yesterday})"
        )),
        "the reason must be named: {compliance}"
    );
    assert!(
        compliance.contains("V4.1.3 (the AI coding tool cannot confirm its own answer)"),
        "the reason must be named: {compliance}"
    );
    assert!(
        compliance.contains("V4.2.1 (it has no `how`"),
        "a bare confirmation is rubber-stamping, and must be named: {compliance}"
    );
    // A named person confirming a check the tool made by hand.
    let hand = status_of(&compliance, "V12.2.2");
    assert!(
        hand.starts_with("checked by the AI coding tool, confirmed through sv review")
            && hand.contains("Sam Lee confirmed it"),
        "V12.2.2: {hand}"
    );
}
