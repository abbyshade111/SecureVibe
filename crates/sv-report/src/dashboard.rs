//! `sv dashboard`: one page for several apps, from the `report.json` each already has.
//!
//! It reads; it never checks anything itself. Every number on it is one a report already states, and
//! each app's part says when that report was written and what kind of run it was, so a stale report
//! cannot pass for today's. The apps are in alphabetical order and are never ranked or added up:
//! apps held to different levels and checked by different runs do not add (`docs/DASHBOARD.md`,
//! ADR-057). Like `report.html`, the page is one file with no script and nothing fetched; the views
//! are sections shown by the address's `#`, which a link sets without a script.

use crate::Counts;
use crate::html::{STYLE, escape, glance_of};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Marks a page as one `sv dashboard` wrote, so it replaces only its own.
pub const MADE_BY: &str = "<meta name=\"generator\" content=\"sv dashboard\">";

/// What one app's report says, as far as the dashboard needs it.
#[derive(Debug, Clone)]
pub struct Summary {
    pub app_name: String,
    pub target_level: u8,
    /// When the report's run started, as the report records it.
    pub started: Option<String>,
    pub sv: String,
    pub counts: Counts,
    /// Each finding's severity and title, worst first.
    pub findings: Vec<(String, String)>,
    /// What the run did not do, in the report's words.
    pub not_run: Vec<String>,
    /// How many of the requirements that apply only those runs could reach.
    pub only_they_reach: usize,
    /// What the report says was not examined.
    pub gaps: Vec<String>,
}

/// One app as the dashboard shows it: its folder, and its report or why there is none to show.
#[derive(Debug, Clone)]
pub struct App {
    pub folder: PathBuf,
    /// The report's `report.html`, to link to, when there is one.
    pub report_html: Option<PathBuf>,
    pub summary: Result<Summary, String>,
    /// The runs kept for it when the person keeps history, oldest first; empty otherwise.
    pub runs: Vec<Run>,
}

/// One run as history keeps it (ADR-057, "Keeping history safely" in `docs/DASHBOARD.md`): enough to
/// say what changed and no more. Never code, a file's contents, a line of one, or a credential;
/// a finding is its fingerprint, severity, rule, and `sv`'s own title for it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Run {
    /// The format of this record, so a later `sv` can tell an older one.
    pub format: u32,
    pub started: String,
    pub started_unix_ms: u64,
    pub app_name: String,
    pub target_level: u8,
    /// `sv`'s version and commit: checks change between them, so runs by two are not compared.
    pub sv: String,
    pub securevibe_toml_sha256: String,
    /// What the run did not do, in the report's words: runs that differ here are not compared.
    pub not_run: Vec<String>,
    pub counts: Counts,
    pub findings: Vec<KeptFinding>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KeptFinding {
    pub fingerprint: String,
    pub severity: String,
    pub rule_id: String,
    pub title: String,
}

impl Run {
    /// The record of `report`'s run, or `None` when the report has no record of when it ran.
    pub fn of(report: &crate::Report) -> Option<Run> {
        let record = report.run_record.as_ref()?;
        Some(Run {
            format: 1,
            started: record.started.clone(),
            started_unix_ms: record.started_unix_ms,
            app_name: report.app_name.clone(),
            target_level: report.target_level,
            sv: report.sv.describe(),
            securevibe_toml_sha256: record.securevibe_toml_sha256.clone(),
            not_run: report
                .not_run_this_time
                .as_ref()
                .map(|n| n.kinds.clone())
                .unwrap_or_default(),
            counts: report.counts.clone(),
            findings: report
                .findings
                .iter()
                .map(|f| KeptFinding {
                    fingerprint: f.fingerprint.clone(),
                    severity: f.severity.name().to_owned(),
                    rule_id: f.rule_id.clone(),
                    title: f.title.clone(),
                })
                .collect(),
        })
    }

    /// Why `self` cannot be set against `earlier`, or `None` when it can: the same kind of run, at
    /// the same level, from the same `securevibe.toml`, by the same `sv`.
    pub fn not_comparable_with(&self, earlier: &Run) -> Option<&'static str> {
        if self.not_run != earlier.not_run {
            Some("a different kind of run, which reaches different requirements")
        } else if self.target_level != earlier.target_level {
            Some("held to a different level")
        } else if self.securevibe_toml_sha256 != earlier.securevibe_toml_sha256 {
            Some("securevibe.toml changed between them, and with it what applies")
        } else if self.sv != earlier.sv {
            Some("a different sv, whose checks may differ")
        } else {
            None
        }
    }

    /// What changed since `earlier`, in a few short sentences.
    pub fn changes_since(&self, earlier: &Run) -> Vec<String> {
        let mut out = Vec::new();
        let gone: Vec<&KeptFinding> = earlier
            .findings
            .iter()
            .filter(|f| !self.findings.iter().any(|g| g.fingerprint == f.fingerprint))
            .collect();
        let new: Vec<&KeptFinding> = self
            .findings
            .iter()
            .filter(|f| {
                !earlier
                    .findings
                    .iter()
                    .any(|g| g.fingerprint == f.fingerprint)
            })
            .collect();
        for f in &new {
            out.push(format!("New finding ({}): {}", f.severity, f.title));
        }
        for f in &gone {
            out.push(format!("No longer found ({}): {}", f.severity, f.title));
        }
        for status in crate::Status::ALL {
            let (was, now) = (earlier.counts.of(status), self.counts.of(status));
            if was != now {
                out.push(format!(
                    "{}: {was} then, {now} now",
                    status.applies_row().trim_start_matches("Applies, ")
                ));
            }
        }
        if out.is_empty() {
            out.push("No finding appeared or went away, and no count changed.".to_owned());
        }
        out
    }
}

const SEVERITIES: [&str; 5] = ["critical", "high", "medium", "low", "info"];

/// Reads one `report.json`. Anything it cannot read is said, never guessed.
pub fn read(text: &str) -> Result<Summary, String> {
    let v: Value = serde_json::from_str(text)
        .map_err(|e| format!("its report.json is not JSON `sv` can read ({e})"))?;
    let counts: Counts = serde_json::from_value(v["counts"].clone())
        .map_err(|_| "its report.json has no counts `sv` can read".to_owned())?;
    let app_name = v["app_name"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("its report.json names no app")?
        .to_owned();
    let mut findings: Vec<(String, String)> = v["findings"]
        .as_array()
        .map(|all| {
            all.iter()
                .map(|f| {
                    (
                        f["severity"].as_str().unwrap_or("unknown").to_owned(),
                        f["title"]
                            .as_str()
                            .unwrap_or("a finding with no title")
                            .to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    findings.sort_by_key(|(severity, _)| {
        SEVERITIES
            .iter()
            .position(|s| s == severity)
            .unwrap_or(SEVERITIES.len())
    });
    let not_run = &v["not_run_this_time"];
    Ok(Summary {
        app_name,
        target_level: v["target_level"].as_u64().unwrap_or(0) as u8,
        started: v["run_record"]["started"].as_str().map(str::to_owned),
        sv: format!(
            "{}{}",
            v["sv"]["version"].as_str().unwrap_or("an unknown version"),
            v["sv"]["commit"]
                .as_str()
                .map(|c| format!(" (commit {})", &c[..c.len().min(7)]))
                .unwrap_or_default()
        ),
        counts,
        findings,
        not_run: not_run["kinds"]
            .as_array()
            .map(|k| {
                k.iter()
                    .filter_map(|s| s.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        only_they_reach: not_run["only_they_reach"].as_u64().unwrap_or(0) as usize,
        gaps: v["gaps"]
            .as_array()
            .map(|g| {
                g.iter()
                    .filter_map(|x| x["what"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// A path as a `file:` address a browser opens, every character that could end the address or the
/// attribute written as `%XX`.
fn file_url(path: &Path) -> String {
    let mut url = String::from("file://");
    for b in path.to_string_lossy().bytes() {
        if b.is_ascii_alphanumeric() || b"/-_.~".contains(&b) {
            url.push(b as char);
        } else {
            url.push_str(&format!("%{b:02X}"));
        }
    }
    url
}

/// What an app is called on the page: the name its report gives, or its folder's own name.
fn label(app: &App) -> String {
    match &app.summary {
        Ok(s) => s.app_name.clone(),
        Err(_) => app
            .folder
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| app.folder.display().to_string()),
    }
}

/// Escapes `text`, and shows what the reports put between backticks as code.
fn prose(text: &str) -> String {
    escape(text)
        .split('`')
        .enumerate()
        .map(|(i, part)| {
            if i % 2 == 1 {
                format!("<code>{part}</code>")
            } else {
                part.to_owned()
            }
        })
        .collect()
}

/// The date part of a report's start time, as the page shows it.
fn day(started: &Option<String>) -> String {
    started
        .as_deref()
        .map(|s| s.get(..10).unwrap_or(s).to_owned())
        .unwrap_or_else(|| "date not recorded".to_owned())
}

/// What kind of run a report was, in a few words.
fn kind(s: &Summary) -> &'static str {
    if s.not_run.is_empty() {
        "every kind of run"
    } else if s.not_run.len() >= 2 {
        "plain run"
    } else {
        "partial run"
    }
}

/// Severity chips: how many findings of each severity, worst first.
fn chips(findings: &[(String, String)]) -> String {
    let mut s = String::from("<span class=\"chips\">");
    for severity in SEVERITIES.iter().copied().chain(["unknown"]) {
        let n = findings.iter().filter(|(sev, _)| sev == severity).count();
        if n > 0 {
            s.push_str(&format!(
                "<span class=\"sev sev-{severity}\">{n} {severity}</span> "
            ));
        }
    }
    if findings.is_empty() {
        s.push_str("<span class=\"note\">no findings</span>");
    }
    s.push_str("</span>");
    s
}

/// Each kept run, newest first, set against the last earlier run it can be compared with.
fn over_time(runs: &[Run]) -> String {
    if runs.is_empty() {
        return String::new();
    }
    let mut b = String::from(
        "<h3>Over time</h3>\n<p class=\"note\">From the history kept on this computer. A run is set \
         against the last earlier one of the same kind, at the same level, from the same securevibe.toml, \
         by the same sv; any other comparison would show the run changing, not the app.</p>\n<ul>\n",
    );
    for (i, run) in runs.iter().enumerate().rev() {
        b.push_str(&format!(
            "<li><strong>{}</strong> <span class=\"note\">{} · level {} · sv {}</span>",
            escape(&day(&Some(run.started.clone()))),
            if run.not_run.is_empty() {
                "every kind of run"
            } else if run.not_run.len() >= 2 {
                "plain run"
            } else {
                "partial run"
            },
            run.target_level,
            escape(&run.sv)
        ));
        let earlier = runs[..i]
            .iter()
            .rev()
            .find(|e| run.not_comparable_with(e).is_none());
        match (earlier, runs[..i].last()) {
            (Some(e), _) => {
                b.push_str(&format!(
                    "<br>Compared with {}:<ul>",
                    escape(&day(&Some(e.started.clone())))
                ));
                for change in run.changes_since(e) {
                    b.push_str(&format!("<li>{}</li>", escape(&change)));
                }
                b.push_str("</ul>");
            }
            (None, Some(previous)) => b.push_str(&format!(
                "<br><span class=\"note\">Not compared with the run before it: {}.</span>",
                run.not_comparable_with(previous)
                    .unwrap_or("no earlier run like it")
            )),
            (None, None) => b.push_str("<br><span class=\"note\">The first run kept.</span>"),
        }
        b.push_str("</li>\n");
    }
    b.push_str("</ul>\n");
    b
}

const DASH_STYLE: &str = "
nav.views { display: flex; flex-wrap: wrap; gap: .4rem; margin: 1rem 0; }
nav.views a { border: 1px solid var(--edge); border-radius: 5px; padding: .2rem .6rem; text-decoration: none; color: inherit; }
nav.views a:focus-visible, nav.views a:hover { outline: 2px solid currentColor; }
.view { display: none; }
.view:target, #all { display: block; }
main:has(.view:target:not(#all)) #all { display: none; }
.app { border: 1px solid var(--edge); border-radius: 6px; padding: .8rem 1rem; margin: .8rem 0; }
.app h3 { margin: 0 0 .3rem; }
.chips .sev { margin-right: .3rem; }
";

/// The page: every app in alphabetical order, then each app's own view.
pub fn page(apps: &[App], written: &str) -> String {
    let mut apps: Vec<&App> = apps.iter().collect();
    apps.sort_by_key(|a| label(a).to_lowercase());
    let mut b = String::new();
    b.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    b.push_str(crate::html::CSP_META);
    b.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    b.push_str(MADE_BY);
    b.push_str("\n<title>sv dashboard</title>\n");
    b.push_str(&format!(
        "<style>{STYLE}{DASH_STYLE}</style>\n</head>\n<body>\n"
    ));
    b.push_str("<h1>Your apps, as their last reports left them</h1>\n");
    b.push_str(&format!(
        "<p class=\"note\">Written by <code>sv dashboard</code> on {}, from the report already in each app's \
         <code>{}</code> folder. It checks nothing itself: run <code>sv report</code> on an app to \
         bring its part up to date. Apps are in alphabetical order, and are never ranked or added up, because apps \
         held to different levels and checked by different runs do not add.</p>\n",
        escape(written),
        sv_frameworks::names::REPORT_DIR
    ));

    b.push_str("<nav class=\"views\" aria-label=\"Views\"><a href=\"#all\">All apps</a>");
    for (i, app) in apps.iter().enumerate() {
        let name = label(app);
        b.push_str(&format!("<a href=\"#app-{}\">{}</a>", i + 1, escape(&name)));
    }
    b.push_str("</nav>\n<main>\n");

    // Each app's own view first, so `#all` can be the one shown when no other is chosen.
    for (i, app) in apps.iter().enumerate() {
        b.push_str(&format!("<section class=\"view\" id=\"app-{}\">\n", i + 1));
        match &app.summary {
            Err(why) => {
                b.push_str(&format!(
                    "<h2>{}</h2>\n<p>No report to show: {}. Run <code>sv report {}</code> to make one.</p>\n",
                    escape(&label(app)),
                    escape(why),
                    escape(&app.folder.display().to_string())
                ));
            }
            Ok(s) => {
                b.push_str(&format!("<h2>{}</h2>\n", escape(&s.app_name)));
                b.push_str(&format!(
                    "<p class=\"note\">Report of {}, ASVS level {}, a {}, by <code>sv</code> {}. Folder: <code>{}</code>.</p>\n",
                    escape(&day(&s.started)),
                    s.target_level,
                    kind(s),
                    escape(&s.sv),
                    escape(&app.folder.display().to_string())
                ));
                if !s.not_run.is_empty() || !s.gaps.is_empty() {
                    b.push_str("<h3>What was not examined</h3>\n<ul>\n");
                    if !s.not_run.is_empty() {
                        b.push_str(&format!(
                            "<li>Not run this time: {}. {} of the requirements that apply can only be checked that way.</li>\n",
                            prose(&s.not_run.join(", and ")),
                            s.only_they_reach
                        ));
                    }
                    for gap in &s.gaps {
                        b.push_str(&format!("<li>{}</li>\n", prose(gap)));
                    }
                    b.push_str("</ul>\n");
                }
                b.push_str(&glance_of(&s.counts, s.target_level));
                b.push_str("<h3>Findings</h3>\n");
                if s.findings.is_empty() {
                    b.push_str("<p>No findings in this report. That says what was found, not that nothing is there.</p>\n");
                } else {
                    b.push_str("<ul>\n");
                    for (severity, title) in s.findings.iter().take(10) {
                        b.push_str(&format!(
                            "<li><span class=\"sev sev-{}\">{}</span> {}</li>\n",
                            escape(severity),
                            escape(severity),
                            escape(title)
                        ));
                    }
                    if s.findings.len() > 10 {
                        b.push_str(&format!(
                            "<li class=\"note\">… and {} more, in the report's security.md, worst first</li>\n",
                            s.findings.len() - 10
                        ));
                    }
                    b.push_str("</ul>\n");
                }
                b.push_str(&over_time(&app.runs));
                if let Some(html) = &app.report_html {
                    b.push_str(&format!(
                        "<p><a href=\"{}\">Open the full report</a> for every requirement, one by one.</p>\n",
                        file_url(html)
                    ));
                }
            }
        }
        b.push_str("<p><a href=\"#all\">Back to all apps</a></p>\n</section>\n");
    }

    b.push_str("<section class=\"view\" id=\"all\">\n<h2>All apps</h2>\n");
    for (i, app) in apps.iter().enumerate() {
        b.push_str("<div class=\"app\">\n");
        match &app.summary {
            Err(why) => b.push_str(&format!(
                "<h3><a href=\"#app-{}\">{}</a></h3>\n<p class=\"note\">No report to show: {}.</p>\n",
                i + 1,
                escape(&label(app)),
                escape(why)
            )),
            Ok(s) => {
                b.push_str(&format!(
                    "<h3><a href=\"#app-{}\">{}</a></h3>\n<p class=\"note\">{} · ASVS level {} · {} · sv {}</p>\n",
                    i + 1,
                    escape(&s.app_name),
                    escape(&day(&s.started)),
                    s.target_level,
                    kind(s),
                    escape(&s.sv)
                ));
                b.push_str(&glance_of(&s.counts, s.target_level));
                b.push_str(&format!("<p>Findings: {}</p>\n", chips(&s.findings)));
            }
        }
        b.push_str("</div>\n");
    }
    b.push_str("</section>\n</main>\n</body>\n</html>\n");
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_it_cannot_read_is_said_and_never_guessed() {
        assert!(read("not json").unwrap_err().contains("not JSON"));
        assert!(
            read(r#"{"app_name":"x"}"#)
                .unwrap_err()
                .contains("no counts")
        );
        assert!(
            read(r#"{"counts":{}}"#)
                .unwrap_err()
                .contains("names no app")
        );
        let s = read(
            r#"{"app_name":"A","target_level":2,"counts":{"applicable":3,"not_verified":3},
                "findings":[{"severity":"low","title":"l"},{"severity":"critical","title":"c"},
                            {"severity":"medium","title":"m"}],
                "run_record":{"started":"2026-10-08T08:57:41Z"},
                "not_run_this_time":{"kinds":["one","two"],"only_they_reach":5}}"#,
        )
        .unwrap();
        let order: Vec<&str> = s.findings.iter().map(|(sev, _)| sev.as_str()).collect();
        assert_eq!(order, ["critical", "medium", "low"], "worst first");
        assert_eq!((s.counts.applicable, s.only_they_reach), (3, 5));
        assert_eq!(day(&s.started), "2026-10-08");
        assert_eq!(kind(&s), "plain run");
        assert_eq!(day(&None), "date not recorded");
    }

    #[test]
    fn a_file_link_cannot_end_its_own_attribute() {
        let url = file_url(Path::new("/home/a b/\"x\"<y>#z/report.html"));
        assert_eq!(url, "file:///home/a%20b/%22x%22%3Cy%3E%23z/report.html");
    }

    #[test]
    fn the_page_is_marked_as_the_dashboard_s_own() {
        let page = page(&[], "2026-10-08");
        assert!(page.contains(MADE_BY));
        assert!(!page.contains("<script"));
    }
}
