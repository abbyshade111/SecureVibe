//! `adapters.json` read once per report, the outside tools named from it, and a broken one said
//! (the review of 8 October 2026, items 6 and 7). Its own file, so these do not land at the end of
//! `main.rs`'s `mod tests`.

use super::*;
use sv_check::adapters::Adapters;

/// An example app, from the crate's folder, where cargo runs its tests. Not by the build folder's
/// name: `tests/moved.rs` allows that only in a test module it can see is one, and a file of tests
/// beside `main.rs` is not one it can.
fn app() -> PathBuf {
    let app = Path::new("../../examples/flask-booking").to_path_buf();
    assert!(app.join("stackvet.toml").is_file(), "the setup: {app:?}");
    app
}

/// The gap a report without `--tools` writes about the outside tools.
fn tools_gap(report: &sv_report::Report) -> String {
    report
        .gaps
        .iter()
        .find(|g| g.what == "the security tool this language already has")
        .map(|g| g.why.clone())
        .expect("a report without --tools says the tools did not run")
}

#[test]
fn every_outside_tool_in_the_file_is_named_once_by_its_own_name() {
    let adapters = Adapters::load(&adapters_path()).unwrap();
    let said = tool_names(&adapters);
    assert_eq!(said, "Bandit, gosec, Brakeman, Semgrep, and CodeQL");
    // Held to the file rather than to the list above: a tool added there is named here.
    for adapter in adapters.all() {
        let name = adapter.name.split(" (").next().unwrap();
        assert_eq!(said.matches(name).count(), 1, "{name} in {said}");
    }
}

#[test]
fn a_report_without_tools_names_them_from_the_file() {
    let loaded = Loaded::load().unwrap();
    let report = assemble_report(&app(), &ReportOptions::reading_only("a test"), &loaded).unwrap();
    let why = tools_gap(&report);
    assert!(
        why.contains(&tool_names(loaded.adapters.as_ref().unwrap())),
        "{why}"
    );
    assert!(why.contains("Semgrep"), "{why}");
    let listed = report
        .examined
        .iter()
        .filter(|e| e.state == sv_report::ExaminedState::NotRun && e.rules == "semgrep.")
        .count();
    assert_eq!(listed, 1, "each tool is listed as not run");
}

#[test]
fn a_broken_adapters_file_is_said_without_tools_and_stops_a_run_with_them() {
    let mut loaded = Loaded::load().unwrap();
    // The setup: what reading a broken file gives, in the words the loader uses.
    let dir = std::env::temp_dir().join(format!("sv-adapters-broken-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("adapters.json"), "{ not json").unwrap();
    let broken = Adapters::load(&dir.join("adapters.json")).map_err(|e| format!("{e:#}"));
    std::fs::remove_dir_all(&dir).ok();
    let why_broken = broken
        .as_ref()
        .expect_err("a broken file is refused")
        .clone();
    loaded.adapters = broken;

    let report = assemble_report(&app(), &ReportOptions::reading_only("a test"), &loaded).unwrap();
    let why = tools_gap(&report);
    assert!(
        why.contains("Which outside tools sv can run is not known") && why.contains(&why_broken),
        "{why}"
    );
    // No tool is listed, and none is named as though the list were known.
    assert!(!why.contains("Bandit"), "{why}");
    assert!(
        !report.examined.iter().any(|e| e.rules == "bandit."),
        "a tool listed from a file that could not be read"
    );

    let options = ReportOptions {
        run_tools: true,
        ..ReportOptions::reading_only("a test")
    };
    let refused = assemble_report(&app(), &options, &loaded)
        .err()
        .map(|e| format!("{e:#}"));
    assert!(
        refused.as_deref().is_some_and(|e| e.contains(&why_broken)),
        "{refused:?}"
    );
}

#[test]
fn the_exit_status_reads_the_tools_from_what_it_is_given() {
    let loaded = Loaded::load().unwrap();
    let mut report =
        assemble_report(&app(), &ReportOptions::reading_only("a test"), &loaded).unwrap();
    // The setup: Semgrep listed as having run only in part, as `--tools` would list it.
    for examined in &mut report.examined {
        if examined.rules == "semgrep." {
            examined.state = sv_report::ExaminedState::Partly;
            examined.why = Some("told to skip tests/".to_owned());
        }
    }
    let with = report_gaps(&report, &loaded.adapters, true, false);
    assert!(
        with.partly.iter().any(|g| g.contains("semgrep")),
        "{:?}",
        with.partly
    );
    let without = report_gaps(&report, &Err("unread".to_owned()), true, false);
    assert!(
        !without.partly.iter().any(|g| g.contains("semgrep")),
        "{:?}",
        without.partly
    );
}
