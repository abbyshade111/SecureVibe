//! design-decisions.md end to end (backlog, design-time item 9): two sections count toward Secure by
//! Design controls the way the security notes count toward ASVS ones, never as checked; a person's
//! review the file asks for is repeated where what was not examined is listed.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The status column of the row for `id` in compliance.md.
fn status_of<'a>(compliance: &'a str, id: &str) -> &'a str {
    let row = compliance
        .lines()
        .find(|line| line.starts_with(&format!("| {id} |")))
        .unwrap_or_else(|| panic!("no row for {id} in the report:\n{compliance}"));
    row.split('|').nth(2).unwrap_or("").trim()
}

fn fresh(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-decisions-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("app.py"), "def home():\n    return 'hi'\n").unwrap();
    let example =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/tested-notes/stackvet.toml");
    std::fs::copy(example, dir.join("stackvet.toml")).unwrap();
    dir
}

/// `sv report` on `dir`, with `config` as where this computer's review key lives: compliance.md and
/// report.json.
fn report(dir: &Path, config: &Path) -> (String, String) {
    let out_dir = dir.join("report");
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .env("XDG_CONFIG_HOME", config)
        .arg("report")
        .arg(dir)
        .arg("--out")
        .arg(&out_dir)
        .output()
        .expect("sv runs");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    (
        std::fs::read_to_string(out_dir.join("compliance.md")).unwrap(),
        std::fs::read_to_string(out_dir.join("report.json")).unwrap(),
    )
}

const DECISIONS: &str = "# Design decisions\n\n## When to bring in a person\n\nWritten by: AI coding tool\n\n\
     The app keeps health data, so ask someone who knows security to review the design before it \
     goes live.\n\n## What we do if something goes wrong\n\nWritten by: owner\n\nTake the app offline \
     from the hosting dashboard, rotate the database password, and email everyone affected within \
     three days.\n\n## Rules that might apply\n\nWritten by: AI coding tool\n\nHealth data of people in \
     Europe: the GDPR may apply, so ask someone qualified before going live.\n";

#[test]
fn the_two_sections_count_as_written_answers_and_the_review_is_repeated() {
    let dir = fresh("written");
    let config = dir.join("config");
    let (key, _) =
        sv_check::seal::Key::load_or_make_in(&config.join(sv_frameworks::names::CONFIG_DIR))
            .unwrap();
    // Sealed for this app, as `sv review` run in it seals.
    let key = key.for_app(&sv_check::seal::App::of(&dir).unwrap());
    // The owner's section, sealed as `sv review` would seal it.
    let catalog = sv_check::notes::Catalog::load(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/design-decisions.json"),
    )
    .unwrap();
    let prose = sv_check::notes::read_answers(&catalog, DECISIONS)
        .prose_of("SBD-MT-06")
        .expect("the setup: the section is read");
    let seal = key.seal(&sv_check::seal::as_strs(&sv_check::seal::notes_fields(
        "SBD-MT-06",
        &prose,
    )));
    let sealed = sv_check::notes::with_seal_in(&catalog, DECISIONS, "SBD-MT-06", &seal).unwrap();
    std::fs::write(dir.join(sv_check::decisions::FILE), sealed).unwrap();

    let (compliance, json) = report(&dir, &config);
    std::fs::remove_dir_all(&dir).ok();

    let plan = status_of(&compliance, "SBD-MT-06");
    assert!(
        plan.starts_with("documented by the owner") && plan.contains("rehearsed"),
        "SBD-MT-06: {plan}"
    );
    let rules = status_of(&compliance, "SBD-AC-06");
    assert!(
        rules.starts_with("stated by the AI coding tool") && rules.contains("not covered"),
        "SBD-AC-06: {rules}"
    );
    for id in ["SBD-MT-06", "SBD-AC-06"] {
        assert!(!status_of(&compliance, id).starts_with("checked"), "{id}");
    }
    assert!(
        json.contains("a person's security review of the design")
            && json.contains("The app keeps health data, so ask someone"),
        "{json}"
    );
    // The file's other sections are not reported as headings left unread.
    assert!(!json.contains("headings of your own"), "{json}");
}

#[test]
fn without_the_file_the_controls_stay_unverified_and_nothing_is_repeated() {
    let dir = fresh("absent");
    let (compliance, json) = report(&dir, &dir.join("config"));
    std::fs::remove_dir_all(&dir).ok();
    for id in ["SBD-MT-06", "SBD-AC-06"] {
        let status = status_of(&compliance, id);
        assert!(
            !status.starts_with("documented") && !status.starts_with("stated"),
            "{id}: {status}"
        );
    }
    assert!(!json.contains("a person's security review of the design"));
}

#[test]
fn safe_defaults_without_the_app_running_are_said_not_looked_at() {
    let dir = fresh("defaults");
    std::fs::write(
        dir.join(sv_check::decisions::FILE),
        "# Design decisions\n\n## Safe defaults\n\n- debug mode: off\n- cross-site access: own site only\n\
         - default accounts: some\n- uploads: maybe\n",
    )
    .unwrap();
    let (_, json) = report(&dir, &dir.join("config"));
    std::fs::remove_dir_all(&dir).ok();
    let report: serde_json::Value = serde_json::from_str(&json).unwrap();
    let gaps = report["gaps"].as_array().expect("gaps");
    let said = |what: &str| {
        gaps.iter()
            .find(|g| g["what"].as_str().is_some_and(|w| w.contains(what)))
            .map(|g| g["why"].as_str().unwrap_or("").to_owned())
    };
    // Two decided the safe way, neither looked at; the one decided "some" is the owner's call.
    let why = said("2 safe defaults decided in design-decisions.md")
        .unwrap_or_else(|| panic!("{gaps:?}"));
    assert!(why.contains("`sv report --run`"), "{why}");
    // "uploads" is not one of the three switches, so it is the section's own words, not unreadable.
    assert!(
        said("safe default in design-decisions.md").is_none(),
        "{gaps:?}"
    );
    let examined = report["examined"].as_array().unwrap();
    let decisions = examined
        .iter()
        .find(|e| e["rules"] == "decisions.")
        .unwrap_or_else(|| panic!("{examined:?}"));
    assert_eq!(decisions["state"], "partly");
    assert!(
        !json.contains("\"decisions.not-held-to\""),
        "nothing held against a check that did not run"
    );
}

#[test]
fn a_switch_written_another_way_is_named() {
    let dir = fresh("unreadable");
    std::fs::write(
        dir.join(sv_check::decisions::FILE),
        "## Safe defaults\n\n- debug mode: mostly off\n",
    )
    .unwrap();
    let (_, json) = report(&dir, &dir.join("config"));
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        json.contains("1 safe default in design-decisions.md")
            && json.contains("debug mode: mostly off"),
        "{json}"
    );
    // The two switches with no line are named too, not left out without a word.
    assert!(
        json.contains("2 safe defaults not found in design-decisions.md")
            && json.contains("cross-site access, default accounts"),
        "{json}"
    );
}

#[test]
fn the_decisions_files_own_words_are_inert_in_security_md() {
    // The review of 6 October, item 4: the "When to bring in a person" section is repeated in
    // security.md, and an image or HTML in it was left live there.
    let dir = fresh("inert");
    let config = dir.join("config");
    let decisions = "# Design decisions\n\n## When to bring in a person\n\nWritten by: AI coding tool\n\n\
         Ask a reviewer ![x](https://tracker.example/p.png) <img src=https://t.example/a> \
         [click](https://evil.example) before going live.\n";
    std::fs::write(dir.join(sv_check::decisions::FILE), decisions).unwrap();
    report(&dir, &config);
    let security = std::fs::read_to_string(dir.join("report/security.md")).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    // The setup: the section really reached security.md.
    assert!(security.contains("before going live"), "{security}");
    // Gap analysis 4.2: whose words they are is said, and the AI coding tool's are not the owner's.
    assert!(
        security.contains("in a section your AI coding tool wrote"),
        "{security}"
    );
    assert!(!security.contains("marked as written by you"), "{security}");
    for live in ["![x](", "<img", "[click]("] {
        assert!(!security.contains(live), "{live} is live in:\n{security}");
    }
}
