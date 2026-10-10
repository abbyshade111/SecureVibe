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
/// written, and a report reads the first part and says the record is full (`BuildLoop::full`).
pub const MAX_BYTES: u64 = 4 * 1024 * 1024;

/// One call, as a line of the record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Line {
    pub time: String,
    pub tool: String,
    pub counts: Option<LoopCounts>,
    /// How the call ended (ADR-084): `ok`, `failed`, `timed-out`, `crashed` (a fault in `sv`), or
    /// `refused` (a tool `sv` does not have). Never the error's words, which can
    /// quote the app. `None` in a line written before it.
    pub outcome: Option<String>,
    /// The AI coding tool, as it named itself when it connected, cut short (`client_name`).
    pub client: Option<String>,
    /// The `sv` that answered.
    pub sv: Option<String>,
    /// A line that says only that the record was turned off at this time, so the gap after it is
    /// seen as one (ADR-084); `tool` is empty.
    pub off: bool,
}

/// The outcomes a line may name, and nothing else.
pub const OUTCOMES: [&str; 5] = ["ok", "failed", "timed-out", "crashed", "refused"];

/// What an AI coding tool calls itself, as it is kept: letters, digits, spaces, and `.-_+/()`
/// only, each part at most 40 characters. The name is the tool's own, sent when it connects; it is
/// kept short and plain so nothing it sends can run on into the record or the report.
pub fn client_name(name: &str, version: &str) -> Option<String> {
    let clean = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric() || " .-_+/()".contains(*c))
            .take(40)
            .collect::<String>()
            .trim()
            .to_owned()
    };
    let (name, version) = (clean(name), clean(version));
    match (name.is_empty(), version.is_empty()) {
        (true, _) => None,
        (false, true) => Some(name),
        (false, false) => Some(format!("{name} {version}")),
    }
}

impl Line {
    /// The line as the record writes it: one JSON object.
    pub fn to_json(&self) -> String {
        if self.off {
            return json!({ "time": self.time, "off": true }).to_string();
        }
        let mut line = json!({ "time": self.time, "tool": self.tool });
        for (key, value) in [
            ("outcome", &self.outcome),
            ("client", &self.client),
            ("sv", &self.sv),
        ] {
            if let Some(value) = value {
                line[key] = json!(value);
            }
        }
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
        if v.get("off") == Some(&Value::Bool(true)) {
            return Some(Line {
                time: text("time")?,
                off: true,
                ..Line::default()
            });
        }
        // An outcome `sv` does not write makes the line one it did not write.
        let outcome = match v.get("outcome") {
            None => None,
            Some(o) => Some(o.as_str().filter(|o| OUTCOMES.contains(o))?.to_owned()),
        };
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
            outcome,
            client: text("client"),
            sv: text("sv"),
            off: false,
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
    if off(app_dir) && !line.off {
        return Ok(());
    }
    let written = append(app_dir, line);
    if written.is_err() {
        *unwritten()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(key(app_dir))
            .or_default() += 1;
    }
    written
}

/// The calls this process could not write into each app's record, by app: what the next report
/// written by this process says (ADR-084). A report written by another process, `sv report` at a
/// terminal, cannot know of them, and says nothing.
fn unwritten() -> &'static std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, usize>> {
    static UNWRITTEN: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, usize>>,
    > = std::sync::OnceLock::new();
    UNWRITTEN.get_or_init(Default::default)
}

/// The app's folder as `unwritten` keeps it: its real place, so two ways of naming it are one.
fn key(app_dir: &Path) -> std::path::PathBuf {
    sv_frameworks::paths::canonical(app_dir).unwrap_or_else(|_| app_dir.to_path_buf())
}

fn append(app_dir: &Path, line: &Line) -> Result<()> {
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
    let unwritten = unwritten()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&key(app_dir))
        .copied()
        .unwrap_or(0);
    let mut summary = read_record(app_dir);
    summary.unwritten = unwritten;
    summary
}

fn read_record(app_dir: &Path) -> BuildLoop {
    if off(app_dir) {
        return BuildLoop {
            off: true,
            ..BuildLoop::default()
        };
    }
    let path = sv_scan::ecosystems::default_report_dir_in(app_dir)
        .join(sv_scan::ecosystems::BUILD_LOOP_RECORD);
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_file() => {
            let mut summary = summarize(&read_at_most(&path));
            summary.full = meta.len() >= MAX_BYTES;
            summary
        }
        // A link, a folder, or nothing at all: no record sv wrote.
        _ => BuildLoop::default(),
    }
}

/// The record's first `MAX_BYTES`, as bytes, since one byte that is not UTF-8 must cost one line
/// and not the whole record. Cut at the limit, the line it cuts through is left out, not counted
/// as unreadable: `sv` wrote it whole.
fn read_at_most(path: &Path) -> Vec<u8> {
    use std::io::Read;
    let mut bytes = Vec::new();
    if let Ok(file) = std::fs::File::open(path) {
        let _ = file.take(MAX_BYTES).read_to_end(&mut bytes);
    }
    if bytes.len() as u64 >= MAX_BYTES {
        let whole = bytes
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |at| at + 1);
        bytes.truncate(whole);
    }
    bytes
}

/// What a record's bytes show: every line read, in order; one that is not UTF-8 or does not read
/// as a line `sv` writes is counted, not skipped quietly (ADR-076).
pub fn summarize(bytes: &[u8]) -> BuildLoop {
    let mut summary = BuildLoop::default();
    for raw in bytes.split(|&b| b == b'\n') {
        let Ok(raw) = std::str::from_utf8(raw) else {
            summary.unreadable += 1;
            continue;
        };
        if raw.trim().is_empty() {
            continue;
        }
        let Some(line) = Line::parse(raw) else {
            summary.unreadable += 1;
            continue;
        };
        if line.off {
            summary.turned_off += 1;
            continue;
        }
        summary.calls += 1;
        match line.outcome.as_deref() {
            Some("failed") => summary.failed += 1,
            Some("timed-out") => summary.timed_out += 1,
            Some("crashed") => summary.crashed += 1,
            Some("refused") => summary.refused += 1,
            _ => {}
        }
        for (seen, named) in [
            (&mut summary.clients, &line.client),
            (&mut summary.svs, &line.sv),
        ] {
            if let Some(named) = named
                && !seen.contains(named)
            {
                seen.push(named.clone());
            }
        }
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
mod limit_tests;
#[cfg(test)]
mod outcome_tests;
#[cfg(test)]
mod tests;
