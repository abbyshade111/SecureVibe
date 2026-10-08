//! History (ADR-057): off until the person turns it on, kept outside every app's folder, readable
//! only by the person, small, bounded, forgettable, and never read by the reports. Every run here has
//! a home of its own, so nothing touches the real one.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

const SV: &str = env!("CARGO_BIN_EXE_sv");

struct Home {
    root: PathBuf,
}

impl Home {
    fn new(tag: &str) -> Home {
        let root = std::env::temp_dir().join(format!("sv-history-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(root.join("home")).unwrap();
        Home { root }
    }

    fn sv(&self, args: &[&str]) -> (Option<i32>, String) {
        let out = Command::new(SV)
            .args(args)
            .env("HOME", self.root.join("home"))
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_DATA_HOME")
            .env_remove("RUST_BACKTRACE")
            .output()
            .unwrap();
        (
            out.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }

    fn history(&self) -> PathBuf {
        self.root.join("home/.local/share/securevibe/history")
    }

    /// The one app folder in history, and its run files, oldest first.
    fn runs(&self) -> (PathBuf, Vec<PathBuf>) {
        let app = std::fs::read_dir(self.history())
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| p.is_dir())
            .expect("an app's history");
        let mut runs: Vec<PathBuf> = std::fs::read_dir(&app)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| !p.ends_with("app.json"))
            .collect();
        runs.sort();
        (app, runs)
    }

    /// A copy of an example app, inside this home's own folder.
    fn app(&self, example: &str) -> PathBuf {
        let from = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples")
            .join(example);
        let to = self.root.join("apps").join(example);
        copy(&from, &to);
        std::fs::remove_dir_all(to.join(sv_scan::ecosystems::DEFAULT_REPORT_DIR)).ok();
        to
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).ok();
    }
}

fn copy(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            copy(&path, &to.join(entry.file_name()));
        } else {
            std::fs::copy(&path, to.join(entry.file_name())).unwrap();
        }
    }
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn nothing_is_kept_until_the_person_turns_it_on() {
    let home = Home::new("off");
    let app = home.app("notes-with-users");
    let (code, said) = home.sv(&["report", s(&app)]);
    assert!(
        app.join(sv_scan::ecosystems::DEFAULT_REPORT_DIR)
            .join("report.json")
            .is_file(),
        "the setup: {code:?} {said}"
    );
    assert!(!said.contains("Kept a record"), "{said}");
    assert!(!home.history().exists(), "history was kept while off");

    let (on, on_said) = home.sv(&["history", "on"]);
    assert_eq!(on, Some(0), "{on_said}");
    home.sv(&["report", s(&app)]);
    let (off, _) = home.sv(&["history", "off"]);
    assert_eq!(off, Some(0));
    let (_, third) = home.sv(&["report", s(&app)]);
    let (_, runs) = home.runs();
    assert_eq!(
        runs.len(),
        1,
        "one run kept while on, none after off: {third}"
    );
    // Nothing of it in the app's folder, where the AI coding tool reads and git may publish.
    let in_app = std::fs::read_dir(&app)
        .unwrap()
        .flatten()
        .any(|e| e.file_name().to_string_lossy().contains("history"));
    assert!(!in_app);
}

#[test]
fn a_record_holds_the_counts_and_titles_and_nothing_of_the_code() {
    let home = Home::new("record");
    let app = home.app("notes-with-users");
    home.sv(&["history", "on"]);
    let (_, said) = home.sv(&["report", s(&app)]);
    assert!(said.contains("Kept a record of this run"), "{said}");
    let (folder, runs) = home.runs();
    let text = std::fs::read_to_string(&runs[0]).unwrap();
    let run: Value = serde_json::from_str(&text).unwrap();
    let report: Value = serde_json::from_str(
        &std::fs::read_to_string(
            app.join(sv_scan::ecosystems::DEFAULT_REPORT_DIR)
                .join("report.json"),
        )
        .unwrap(),
    )
    .unwrap();

    assert_eq!(run["counts"], report["counts"]);
    assert_eq!(run["app_name"], report["app_name"]);
    let findings = run["findings"].as_array().unwrap();
    assert!(!findings.is_empty(), "the setup: this app has findings");
    for f in findings {
        let keys: Vec<&String> = f.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["fingerprint", "rule_id", "severity", "title"], "{f}");
    }
    // None of the report's longer text, and nothing of the app's files.
    for word in ["description", "location", "secret", "fix", "impact"] {
        assert!(!text.contains(&format!("\"{word}\"")), "{word} in {text}");
    }
    let code = std::fs::read_to_string(app.join("app.py")).unwrap_or_default();
    for line in code.lines().filter(|l| l.trim().len() > 20) {
        assert!(
            !text.contains(line.trim()),
            "a line of the app's code: {line}"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&runs[0]), 0o600, "a record others can read");
        assert_eq!(mode(&folder), 0o700);
        assert_eq!(mode(&home.history()), 0o700);
    }
}

#[test]
fn the_dashboard_compares_only_runs_that_are_alike() {
    let home = Home::new("compare");
    let app = home.app("notes-with-users");
    home.sv(&["history", "on"]);
    home.sv(&["report", s(&app)]);
    home.sv(&["report", s(&app)]);
    // A run that tried outside tools is another kind of run.
    home.sv(&["report", s(&app), "--tools"]);
    let out = home.root.join("dashboard.html");
    // No folders given: the apps whose runs were kept.
    let (code, said) = home.sv(&["dashboard", "--out", s(&out)]);
    let page = std::fs::read_to_string(&out).unwrap_or_default();
    assert_eq!(code, Some(0), "{said}");
    assert!(page.contains("Notes with users"), "the kept app is shown");
    assert!(page.contains("<h3>Over time</h3>"), "{page}");
    assert!(
        page.contains("Compared with"),
        "two plain runs are compared"
    );
    assert!(
        page.contains("No finding appeared or went away, and no count changed."),
        "{page}"
    );
    assert!(
        page.contains("Not compared with the run before it: a different kind of run"),
        "{page}"
    );
}

#[test]
fn it_keeps_at_most_a_hundred_runs_for_an_app_and_forgets_on_request() {
    let home = Home::new("bounds");
    let app = home.app("tested-notes");
    home.sv(&["history", "on"]);
    home.sv(&["report", s(&app)]);
    let (folder, runs) = home.runs();
    let one = std::fs::read_to_string(&runs[0]).unwrap();
    let mut run: Value = serde_json::from_str(&one).unwrap();
    for i in 0..120u64 {
        run["started_unix_ms"] = Value::from(1_000 + i);
        std::fs::write(folder.join(format!("{}.json", 1_000 + i)), run.to_string()).unwrap();
    }
    home.sv(&["report", s(&app)]);
    let (_, runs) = home.runs();
    assert_eq!(runs.len(), 100, "at most a hundred");
    assert!(!folder.join("1000.json").exists(), "the oldest go first");

    let (code, said) = home.sv(&["history", "forget", s(&app)]);
    assert_eq!(code, Some(0), "{said}");
    assert!(!folder.exists(), "{said}");
    home.sv(&["report", s(&app)]);
    let (all, _) = home.sv(&["history", "forget", "--all"]);
    assert_eq!(all, Some(0));
    assert!(!home.history().exists());
}

#[test]
fn the_reports_never_read_history_and_the_dashboard_shows_it_as_text() {
    let home = Home::new("text");
    let app = home.app("tested-notes");
    home.sv(&["history", "on"]);
    home.sv(&["report", s(&app)]);
    let (_, runs) = home.runs();
    let mut run: Value = serde_json::from_str(&std::fs::read_to_string(&runs[0]).unwrap()).unwrap();
    run["findings"] = serde_json::json!([{
        "fingerprint": "planted", "severity": "high", "rule_id": "x",
        "title": "<script>PLANTED</script>"
    }]);
    std::fs::write(&runs[0], run.to_string()).unwrap();
    home.sv(&["report", s(&app)]);
    let report = std::fs::read_to_string(
        app.join(sv_scan::ecosystems::DEFAULT_REPORT_DIR)
            .join("report.html"),
    )
    .unwrap();
    assert!(!report.contains("PLANTED"), "a report read history");

    let out = home.root.join("d.html");
    home.sv(&["dashboard", s(&app), "--out", s(&out)]);
    let page = std::fs::read_to_string(&out).unwrap();
    assert!(
        page.contains("&lt;script&gt;PLANTED&lt;/script&gt;"),
        "{page}"
    );
    assert!(!page.contains("<script>PLANTED"));
}
