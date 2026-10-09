//! The record of the build loop (ADR-076): one line for each call an AI coding tool makes to `sv`'s
//! MCP server for an app, written in the app's report folder, and read back when a report is written
//! so the report can say how the app was built with `sv`, or that nothing shows it was.
//!
//! Each line holds the time, the tool's name, and, for a call that checked the app, how many findings
//! and requirements it came to; never an argument, a path, or a finding's text. The record is not
//! sealed: it grows between reports, and each report carries what it read from it, under the report's
//! own seal. It is evidence about how the app was built, never about the app.

use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::io::Write;
use std::path::Path;
use sv_report::{BuildLoop, LoopCounts};

/// The largest record written to or read: tens of thousands of calls. Beyond it, nothing more is
/// written, and a report reads the first part and says the rest was left out.
pub const MAX_BYTES: u64 = 4 * 1024 * 1024;

/// One call, as a line of the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub time: String,
    pub tool: String,
    pub counts: Option<LoopCounts>,
}

impl Line {
    /// The line as the record writes it: one JSON object.
    pub fn to_json(&self) -> String {
        let mut line = json!({ "time": self.time, "tool": self.tool });
        if let Some(c) = &self.counts {
            line["counts"] = json!({
                "findings": c.findings,
                "checked": c.checked,
                "needs_attention": c.needs_attention,
                "not_assessed": c.not_assessed,
            });
        }
        line.to_string()
    }

    /// A line of the record read back; `None` for one that is not a line `sv` writes.
    pub fn parse(raw: &str) -> Option<Line> {
        let v: Value = serde_json::from_str(raw).ok()?;
        let text = |key: &str| v.get(key)?.as_str().map(str::to_owned);
        let counts = match v.get("counts") {
            None => None,
            Some(c) => {
                let n = |key: &str| c.get(key)?.as_u64().and_then(|n| usize::try_from(n).ok());
                Some(LoopCounts {
                    findings: n("findings")?,
                    checked: n("checked")?,
                    needs_attention: n("needs_attention")?,
                    not_assessed: n("not_assessed")?,
                })
            }
        };
        Some(Line {
            time: text("time")?,
            tool: text("tool")?,
            counts,
        })
    }
}

/// Whether the app's `stackvet.toml` turns the record off. A manifest that cannot be read leaves it
/// on: the check says what is wrong with the file, and the record is no reason to say it twice.
pub fn off(app_dir: &Path) -> bool {
    sv_manifest::locate(app_dir)
        .ok()
        .flatten()
        .and_then(|located| sv_manifest::Manifest::load(&located.path).ok())
        .is_some_and(|m| m.app.build_loop_record == Some(false))
}

/// Writes down one call for the app at `app_dir`, unless its manifest turns the record off. The
/// report folder is made if it is not there, one level at a time and never through a link, and the
/// record is opened without following one, so a link planted in the app cannot send the line
/// anywhere else. Any failure is the caller's to ignore: the record never stops a tool's answer.
pub fn record(app_dir: &Path, line: &Line) -> Result<()> {
    if off(app_dir) {
        return Ok(());
    }
    let folder = sv_scan::ecosystems::default_report_dir_in(app_dir);
    let relative = folder
        .strip_prefix(app_dir)
        .context("the report folder is not inside the app")?;
    let (folder, _) = crate::mcp::create_below(app_dir, relative)?;
    let path = folder.join(sv_scan::ecosystems::BUILD_LOOP_RECORD);
    crate::refuse_link(
        &path,
        "Remove the link; sv writes its record only as a plain file.",
    )?;
    if std::fs::metadata(&path).is_ok_and(|m| m.len() >= MAX_BYTES) {
        return Ok(());
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    let mut text = line.to_json();
    text.push('\n');
    file.write_all(text.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

/// What the record for the app at `app_dir` shows, for a report about to be written.
pub fn read(app_dir: &Path) -> BuildLoop {
    if off(app_dir) {
        return BuildLoop {
            off: true,
            ..BuildLoop::default()
        };
    }
    let path = sv_scan::ecosystems::default_report_dir_in(app_dir)
        .join(sv_scan::ecosystems::BUILD_LOOP_RECORD);
    let text = match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_file() => read_at_most(&path),
        // A link, a folder, or nothing at all: no record sv wrote.
        _ => String::new(),
    };
    summarize(&text)
}

fn read_at_most(path: &Path) -> String {
    use std::io::Read;
    let mut text = String::new();
    if let Ok(file) = std::fs::File::open(path) {
        let _ = file.take(MAX_BYTES).read_to_string(&mut text);
    }
    text
}

/// What a record's text shows: every line read, in order; one that does not read is counted.
pub fn summarize(text: &str) -> BuildLoop {
    let mut summary = BuildLoop::default();
    for raw in text.lines().filter(|l| !l.trim().is_empty()) {
        let Some(line) = Line::parse(raw) else {
            summary.unreadable += 1;
            continue;
        };
        summary.calls += 1;
        if summary.first.is_none() {
            summary.first = Some(line.time.clone());
        }
        summary.last = Some(line.time);
        if let Some(counts) = line.counts {
            summary.checks += 1;
            if summary.first_counts.is_none() {
                summary.first_counts = Some(counts);
            }
            summary.last_counts = Some(counts);
        }
    }
    summary
}

#[cfg(test)]
mod tests;
