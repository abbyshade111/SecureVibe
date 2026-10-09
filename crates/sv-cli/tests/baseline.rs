//! `--baseline <older report folder>`: with `--fail-on attention`, exit 1 only for a finding the
//! older report did not hold, every finding still listed and counted, and the old ones marked
//! (backlog 0191, part 1; ADR-029, Later, 9 October 2026), through the binary.

use std::path::{Path, PathBuf};
use std::process::Command;

fn sv(args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(args)
        .env_remove("SV_ADVISORY_DIR")
        .output()
        .expect("sv runs");
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let root = std::env::temp_dir().join(format!("sv-baseline-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        let app = root.join("app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("stackvet.toml"), manifest("Baseline")).unwrap();
        // Two findings graded high, which the baseline will hold.
        std::fs::write(app.join("tool.py"), OLD).unwrap();
        Scratch(root)
    }
    fn app(&self) -> PathBuf {
        self.0.join("app")
    }
    fn dir(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    /// `sv report` into `out`, with `extra` options.
    fn report(&self, out: &str, extra: &[&str]) -> (Option<i32>, String) {
        let app = self.app();
        let out = self.dir(out);
        let mut args = vec!["report", s(&app), "--out", s(&out)];
        args.extend_from_slice(extra);
        sv(&args)
    }
    fn json(&self, out: &str) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(self.dir(out).join("report.json")).unwrap())
            .unwrap()
    }
    fn read(&self, out: &str, file: &str) -> String {
        std::fs::read_to_string(self.dir(out).join(file)).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn manifest(name: &str) -> String {
    format!(
        "manifest-version = 1\n[app]\nname = \"{name}\"\naudience = \"customers\"\n\
         deployment = \"internet\"\n[stack]\nlanguages = [\"python\"]\n"
    )
}

const OLD: &str =
    "import os\n\ndef run(cmd):\n    os.system(cmd)\n\ndef calc(expr):\n    return eval(expr)\n";
const NEW: &str = "def again(expr):\n    return eval(expr)\n";

fn high_findings(json: &serde_json::Value) -> usize {
    json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| matches!(f["severity"].as_str(), Some("high" | "critical")))
        .count()
}

#[test]
fn only_a_new_finding_fails_and_every_finding_is_still_listed() {
    let s = Scratch::new("new");
    let (code, out) = s.report("old", &[]);
    assert_eq!(code, Some(0), "{out}");
    let before = s.json("old");
    assert!(
        high_findings(&before) >= 2,
        "the setup: two high findings: {before}"
    );
    // The control: without a baseline, the same findings fail.
    let (code, out) = s.report("plain", &["--fail-on", "attention:high"]);
    assert_eq!(code, Some(1), "{out}");
    // With it, nothing new: 0.
    let baseline = s.dir("old");
    let (code, out) = s.report(
        "same",
        &["--fail-on", "attention:high", "--baseline", s_(&baseline)],
    );
    assert_eq!(code, Some(0), "{out}");
    let same = s.json("same");
    assert_eq!(
        high_findings(&same),
        high_findings(&before),
        "nothing was dropped"
    );
    assert_eq!(
        same["baseline"]["held"].as_array().unwrap().len(),
        same["findings"].as_array().unwrap().len(),
        "{same}"
    );
    // A new finding: 1, and the reason names it as new.
    std::fs::write(s.app().join("more.py"), NEW).unwrap();
    let (code, out) = s.report(
        "after",
        &["--fail-on", "attention:high", "--baseline", s_(&baseline)],
    );
    assert_eq!(code, Some(1), "{out}");
    assert!(
        out.contains("1 new finding(s), not in the baseline, at high or worse"),
        "{out}"
    );
    assert!(out.contains("1 finding is new since then"), "{out}");
    let after = s.json("after");
    assert_eq!(high_findings(&after), high_findings(&before) + 1);
}

fn s_(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn every_report_file_marks_the_old_findings_and_sarif_says_new_or_unchanged() {
    let s = Scratch::new("marks");
    s.report("old", &[]);
    std::fs::write(s.app().join("more.py"), NEW).unwrap();
    let baseline = s.dir("old");
    s.report("after", &["--baseline", s_(&baseline)]);
    for file in ["security.md", "report.html"] {
        let text = s.read("after", file);
        assert!(
            text.contains("Also in the baseline ("),
            "{file}: no finding marked"
        );
        assert!(
            text.contains("Compared with the baseline in"),
            "{file}: no summary line"
        );
    }
    let sarif: serde_json::Value =
        serde_json::from_str(&s.read("after", "findings.sarif")).unwrap();
    let states: Vec<&str> = sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["baselineState"].as_str())
        .collect();
    assert!(
        states.contains(&"new") && states.contains(&"unchanged"),
        "{states:?}"
    );
    // Without a baseline, no result carries a state.
    let plain: serde_json::Value = serde_json::from_str(&s.read("old", "findings.sarif")).unwrap();
    assert!(
        plain["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r.get("baselineState").is_none())
    );
}

#[test]
fn the_baseline_may_be_the_folder_the_new_report_is_written_into() {
    let s = Scratch::new("same-folder");
    s.report("reports", &[]);
    let folder = s.dir("reports");
    let (code, out) = s.report(
        "reports",
        &["--fail-on", "attention:high", "--baseline", s_(&folder)],
    );
    assert_eq!(code, Some(0), "read before it was written over: {out}");
    assert!(s.json("reports")["baseline"].is_object());
}

#[test]
fn a_baseline_that_cannot_be_read_stops_the_run() {
    let s = Scratch::new("missing");
    let nowhere = s.dir("nowhere");
    let (code, out) = s.report(
        "out",
        &["--fail-on", "attention", "--baseline", s_(&nowhere)],
    );
    assert_eq!(code, Some(3), "{out}");
    assert!(
        out.contains("there is no report.json to compare with there"),
        "{out}"
    );
    std::fs::create_dir_all(&nowhere).unwrap();
    std::fs::write(nowhere.join("report.json"), "{\"not\": \"a report\"}").unwrap();
    let (code, out) = s.report("out", &["--baseline", s_(&nowhere)]);
    assert_eq!(code, Some(3), "{out}");
    assert!(out.contains("is not a report `sv` wrote"), "{out}");
}

#[test]
fn a_baseline_for_another_app_stops_the_run() {
    let s = Scratch::new("other");
    s.report("old", &[]);
    std::fs::write(s.app().join("stackvet.toml"), manifest("Another")).unwrap();
    let baseline = s.dir("old");
    let (code, out) = s.report(
        "out",
        &["--fail-on", "attention", "--baseline", s_(&baseline)],
    );
    assert_eq!(code, Some(3), "{out}");
    assert!(
        out.contains("that report is for \"Baseline\", and this app is \"Another\""),
        "{out}"
    );
}

#[test]
fn sv_check_takes_the_same_baseline() {
    let s = Scratch::new("check");
    s.report("old", &[]);
    let app = s.app();
    let baseline = s.dir("old");
    let (code, out) = sv(&[
        "check",
        s_(&app),
        "--fail-on",
        "attention:high",
        "--baseline",
        s_(&baseline),
    ]);
    assert_eq!(code, Some(0), "{out}");
    assert!(
        out.contains("also in the baseline: it was there before"),
        "{out}"
    );
    std::fs::write(app.join("more.py"), NEW).unwrap();
    let (code, out) = sv(&[
        "check",
        s_(&app),
        "--fail-on",
        "attention:high",
        "--baseline",
        s_(&baseline),
    ]);
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("new finding(s), not in the baseline"), "{out}");
}

#[test]
fn sv_check_with_nothing_new_exits_0_at_any_bar() {
    // Every finding, low ones included, was in the baseline: the lowest bar does not fail.
    let s = Scratch::new("check-low");
    s.report("old", &[]);
    let app = s.app();
    let baseline = s.dir("old");
    let (code, out) = sv(&["check", s_(&app), "--fail-on", "attention"]);
    assert_eq!(
        code,
        Some(1),
        "the setup: it fails without a baseline: {out}"
    );
    let (code, out) = sv(&[
        "check",
        s_(&app),
        "--fail-on",
        "attention",
        "--baseline",
        s_(&baseline),
    ]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("0 of "), "{out}");
}

/// A report compared with a baseline holding its old findings, after one new finding was added.
fn compared(tag: &str) -> Scratch {
    let s = Scratch::new(tag);
    s.report("old", &[]);
    std::fs::write(s.app().join("more.py"), NEW).unwrap();
    let baseline = s.dir("old");
    let (code, out) = s.report("after", &["--baseline", s_(&baseline)]);
    assert_eq!(code, Some(0), "{out}");
    s
}

#[test]
fn security_md_marks_the_old_findings_and_not_the_new_one() {
    let s = compared("md");
    let text = s.read("after", "security.md");
    let held = text.matches("Also in the baseline (").count();
    let findings = s.json("after")["findings"].as_array().unwrap().len();
    assert_eq!(held, findings - 1, "{text}");
}

#[test]
fn report_html_marks_the_old_findings_and_not_the_new_one() {
    let s = compared("html");
    let text = s.read("after", "report.html");
    let held = text.matches("Also in the baseline (").count();
    let findings = s.json("after")["findings"].as_array().unwrap().len();
    assert_eq!(held, findings - 1);
}

#[test]
fn sarif_gives_one_new_result_and_the_rest_unchanged() {
    let s = compared("sarif");
    let sarif: serde_json::Value =
        serde_json::from_str(&s.read("after", "findings.sarif")).unwrap();
    let states: Vec<&str> = sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["baselineState"].as_str())
        .collect();
    assert_eq!(
        states.iter().filter(|s| **s == "new").count(),
        1,
        "{states:?}"
    );
    assert!(
        states.iter().all(|s| *s == "new" || *s == "unchanged"),
        "{states:?}"
    );
}

#[test]
fn sv_check_refuses_a_baseline_it_cannot_use() {
    let s = Scratch::new("check-refuse");
    let app = s.app();
    let nowhere = s.dir("nowhere");
    let (code, out) = sv(&["check", s_(&app), "--baseline", s_(&nowhere)]);
    assert_eq!(code, Some(3), "{out}");
    assert!(
        out.contains("there is no report.json to compare with there"),
        "{out}"
    );
    s.report("old", &[]);
    std::fs::write(app.join("stackvet.toml"), manifest("Another")).unwrap();
    let baseline = s.dir("old");
    let (code, out) = sv(&["check", s_(&app), "--baseline", s_(&baseline)]);
    assert_eq!(code, Some(3), "{out}");
    assert!(out.contains("this app is \"Another\""), "{out}");
}

#[test]
fn another_apps_baseline_is_refused_without_fail_on_too_and_writes_no_report() {
    // The comparison is refused whatever `--fail-on` says: a report marked against another app's
    // findings would mislead a reader as much as an exit status would.
    let s = Scratch::new("other-plain");
    s.report("old", &[]);
    std::fs::write(s.app().join("stackvet.toml"), manifest("Another")).unwrap();
    let baseline = s.dir("old");
    let (code, out) = s.report("out", &["--baseline", s_(&baseline)]);
    assert_eq!(code, Some(3), "{out}");
    assert!(
        !s.dir("out").join("report.json").exists(),
        "a report was written"
    );
}
