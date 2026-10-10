//! `sv compare OLDER [NEWER]`: what changed between two reports of an app (ADR-083).
//!
//! It reads each report's `report.json` and lists each requirement whose status changed, with what
//! credited it or was found against it on one side and not the other, the findings that appeared
//! or went away, and the counts. It writes nothing, credits nothing, and works whether history is
//! on or not.
//!
//! # What it cannot say
//!
//! Whether a report is the one `sv` wrote, when its seal cannot be checked here: a report written on
//! another computer, or before reports were sealed. It still compares it, and says first that it
//! cannot show the report is `sv`'s and unchanged. And two runs that were not alike (a different
//! kind of run, level, `stackvet.toml`, notes, decisions, `sv`, or data) are compared too, when asked,
//! with that said first: a requirement can move for that reason alone, not because the app changed.

use anyhow::{Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};
use sv_report::dashboard::Run;

/// One report, as read.
pub struct Side {
    /// The report folder.
    pub folder: PathBuf,
    pub json: Value,
    /// Whether `sv` can show it wrote this `report.json` on this computer and nothing changed it
    /// since; otherwise why not.
    pub sealed: Result<(), String>,
}

/// The report in `folder`: a report folder, or an app folder whose `stackvet-report` holds one.
pub fn read(folder: &Path) -> Result<Side> {
    let folder = if folder.join("report.json").is_file() {
        folder.to_path_buf()
    } else {
        sv_scan::ecosystems::default_report_dir_in(folder)
    };
    let path = folder.join("report.json");
    let bytes = std::fs::read(&path).with_context(|| {
        format!(
            "{} holds no report.json: give a report folder, or an app folder with a report in its {} folder",
            folder.display(),
            sv_scan::ecosystems::DEFAULT_REPORT_DIR
        )
    })?;
    let json: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not JSON sv can read", path.display()))?;
    // Whether the folder's seal holds for its files as they are now, `report.json` among them.
    let sealed = crate::report_seal::proven(&folder).map(|_| ());
    Ok(Side {
        folder,
        json,
        sealed,
    })
}

/// A report's run, as history would keep it, from its `report.json`: what `Run` compares.
fn run_of(json: &Value) -> Run {
    let sv = format!(
        "{} (commit {})",
        json["sv"]["version"].as_str().unwrap_or(""),
        json["sv"]["commit"]
            .as_str()
            .map(|c| c.get(..12).unwrap_or(c))
            .unwrap_or("")
    );
    let record = &json["run_record"];
    let kept = serde_json::json!({
        "format": 4,
        "started": record["started"],
        "started_unix_ms": record["started_unix_ms"],
        "app_name": json["app_name"],
        "target_level": json["target_level"],
        "sv": sv,
        "securevibe_toml_sha256": record["securevibe_toml_sha256"],
        "not_run": json["not_run_this_time"]["kinds"],
        "counts": json["counts"],
        "findings": json["findings"],
        "requirements": json["requirements"],
        "inputs": record["inputs"],
    });
    // Each field has a default, so a report from an older `sv` still reads, with less in it.
    serde_json::from_value(strip_nulls(kept)).unwrap_or_default()
}

/// The object with its `null` fields left out, so each takes its default.
fn strip_nulls(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            Value::Object(map.into_iter().filter(|(_, v)| !v.is_null()).collect())
        }
        other => other,
    }
}

/// What credits a requirement, or is found against it, by the field `report.json` keeps it in.
const EVIDENCE: [(&str, &str); 8] = [
    ("checked_by", "checked by"),
    ("tested_by", "tested by the app's own test"),
    ("supported_by", "supported by"),
    ("documented_by", "answered in your notes"),
    ("by_hand", "checked by hand"),
    ("attested_by", "your answer about how the app is built"),
    ("findings", "finding"),
    ("information", "information"),
];

/// A short name for one piece of evidence: the check, rule, or file it names.
fn name_of(item: &Value) -> String {
    for key in ["check_id", "rule_id", "id", "file", "title"] {
        if let Some(s) = item[key].as_str() {
            return s.to_owned();
        }
    }
    item.as_str()
        .map_or_else(|| item.to_string(), str::to_owned)
}

/// The requirement `id` in a report's list, or `Null`.
fn requirement<'a>(json: &'a Value, id: &str) -> &'a Value {
    json["requirements"]
        .as_array()
        .and_then(|all| all.iter().find(|r| r["id"] == id))
        .unwrap_or(&Value::Null)
}

/// Each piece of evidence `newer` has for a requirement and `older` does not, as "gained", then the
/// reverse, as "lost".
fn evidence_moved(older: &Value, newer: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for (field, said) in EVIDENCE {
        let names = |r: &Value| -> Vec<String> {
            r[field]
                .as_array()
                .map(|items| items.iter().map(name_of).collect())
                .unwrap_or_default()
        };
        let (then, now) = (names(older), names(newer));
        for n in now.iter().filter(|n| !then.contains(n)) {
            out.push(format!("gained: {said} {n}"));
        }
        for n in then.iter().filter(|n| !now.contains(n)) {
            out.push(format!("lost: {said} {n}"));
        }
    }
    out
}

/// What `sv compare` prints.
pub fn text(older: &Side, newer: &Side) -> String {
    let (then, now) = (run_of(&older.json), run_of(&newer.json));
    let mut out = String::new();
    let line = |label: &str, side: &Side, run: &Run| {
        format!(
            "  {label}: {}, {} (sv {})\n",
            side.folder.display(),
            if run.started.is_empty() {
                "when it ran is not recorded"
            } else {
                &run.started
            },
            run.sv
        )
    };
    out.push_str(&format!(
        "What changed between two reports of {}:\n",
        if now.app_name.is_empty() {
            "an app"
        } else {
            &now.app_name
        }
    ));
    out.push_str(&line("older", older, &then));
    out.push_str(&line("newer", newer, &now));
    out.push('\n');

    // What could make this comparison mislead, first.
    for (which, side) in [("older", older), ("newer", newer)] {
        if let Err(why) = &side.sealed {
            out.push_str(&format!(
                "sv cannot show it wrote the {which} report: {why}. It is compared as it stands, and \
                 may have been changed.\n"
            ));
        }
    }
    if then.app_name != now.app_name {
        out.push_str(&format!(
            "The two reports name different apps ({} and {}).\n",
            then.app_name, now.app_name
        ));
    }
    if let Some(why) = now.not_comparable_with(&then) {
        out.push_str(&format!(
            "These two runs were not alike: {why}. A requirement below can have moved for that \
             reason, not because the app changed.\n"
        ));
    } else if then.inputs.is_none() || now.inputs.is_none() {
        out.push_str(
            "Whether the security notes, the design decisions, or sv's data changed between them is \
             not known: one report was written by an older sv, which did not record them.\n",
        );
    }
    if !out.ends_with("\n\n") {
        out.push('\n');
    }

    // Each requirement that moved, with what it gained and lost.
    let moved = now.moved_since(&then);
    let word = |s: Option<sv_report::Status>| s.map_or("did not apply", |s| s.label());
    if then.requirements.is_empty() || now.requirements.is_empty() {
        out.push_str(
            "Which requirements moved cannot be said: one report lists no requirements.\n",
        );
    } else if moved.is_empty() {
        out.push_str("No requirement's status changed.\n");
    } else {
        out.push_str(&format!(
            "{} requirement{} changed status:\n",
            moved.len(),
            if moved.len() == 1 { "" } else { "s" }
        ));
        for (id, was, is) in &moved {
            out.push_str(&format!("  {id}: {} then, {} now\n", word(*was), word(*is)));
            for change in evidence_moved(requirement(&older.json, id), requirement(&newer.json, id))
            {
                out.push_str(&format!("      {change}\n"));
            }
        }
    }

    // The findings that appeared or went away, and the counts.
    let fingerprints =
        |r: &Run| -> Vec<String> { r.findings.iter().map(|f| f.fingerprint.clone()).collect() };
    let (was, is) = (fingerprints(&then), fingerprints(&now));
    let new: Vec<_> = now
        .findings
        .iter()
        .filter(|f| !was.contains(&f.fingerprint))
        .collect();
    let gone: Vec<_> = then
        .findings
        .iter()
        .filter(|f| !is.contains(&f.fingerprint))
        .collect();
    out.push('\n');
    if new.is_empty() && gone.is_empty() {
        out.push_str("No finding appeared or went away.\n");
    }
    for f in new {
        out.push_str(&format!("New finding ({}): {}\n", f.severity, f.title));
    }
    for f in gone {
        out.push_str(&format!("No longer found ({}): {}\n", f.severity, f.title));
    }
    for status in sv_report::Status::ALL {
        let (a, b) = (then.counts.of(status), now.counts.of(status));
        if a != b {
            out.push_str(&format!(
                "{}: {a} then, {b} now\n",
                status.applies_row().trim_start_matches("Applies, ")
            ));
        }
    }
    out.push_str(
        "\nNothing was written. This sets two reports side by side; it checks nothing itself, and a \
         requirement that moved to checked is still not one that passed.\n",
    );
    out
}

/// `sv compare OLDER [NEWER]`, NEWER being this folder's report when it is not given.
pub fn command(args: &[String]) -> Result<()> {
    let (older, newer) = match args {
        [older] => (PathBuf::from(older), PathBuf::from(".")),
        [older, newer] => (PathBuf::from(older), PathBuf::from(newer)),
        _ => anyhow::bail!(
            "`sv compare` takes the older report's folder, and the newer one's (this folder's report \
             when it is not given), for example: sv compare ~/old-report ."
        ),
    };
    let (older, newer) = (read(&older)?, read(&newer)?);
    print!("{}", text(&older, &newer));
    Ok(())
}

#[cfg(test)]
mod tests;
