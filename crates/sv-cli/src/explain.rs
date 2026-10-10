//! `sv explain ID [--app DIR]`: one requirement, explained at the terminal (backlog item "From the
//! end-of-day write-up of 8 October 2026: ideas for `sv` itself", part 5).
//!
//! A person reading "V7.4.1 not verified" in a report needs three things the report does not put in one
//! place: what the requirement asks, what `sv` would have checked, and what to do about it. This gives
//! them, from the data `sv` already ships: the requirement's own words and level (as
//! `stackvet_explain` gives them to the AI tool), the checks that speak to it and the kind of run each
//! needs (`data/reach.json`, written by `tools/coverage.py` from the checks' own citations), the coding
//! rules and prompts that cite it, and the check by hand where only a person can look. Given an app's
//! folder, it adds what that app's last report said.
//!
//! # What it is worth
//!
//! Nothing, as evidence. It reads files only, and the app's status comes from its last report as that
//! report wrote it: a new report is the only way to see what changed since.

use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;
use sv_frameworks::Frameworks;

/// One check that speaks to a requirement, as `data/reach.json` records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckLine {
    pub id: String,
    /// The kind of run it needs, in words: "Reads the code", "The running app", and so on.
    pub run: String,
    pub looks_for: String,
    /// Only ever a finding: it can show the requirement failing, never met.
    pub finding_only: bool,
}

/// The checks `data/reach.json` records for `id`, or none.
pub fn checks_for(reach: &Value, id: &str) -> Vec<CheckLine> {
    reach["checks"][id]
        .as_array()
        .map(|list| {
            list.iter()
                .map(|c| CheckLine {
                    id: c["id"].as_str().unwrap_or_default().to_owned(),
                    run: c["run"].as_str().unwrap_or_default().to_owned(),
                    looks_for: c["looks_for"].as_str().unwrap_or_default().to_owned(),
                    finding_only: c["finding_only"].as_bool().unwrap_or(false),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A report status, in the words a person reads it in.
fn status_words(status: &str) -> &str {
    match status {
        "needs-attention" => "needs attention: a check found a problem with it",
        "checked" => {
            "checked: a check that speaks to it ran and found nothing wrong (one automated check, not a pass)"
        }
        "checked-in-part" => {
            "checked in part: checks ran and were satisfied, each trying only part of what it asks"
        }
        "app-tested" => "tested by the app's own tests, which name it and passed",
        "attested" => "answered by you in stackvet.toml, which nothing here confirms",
        "stated" => "answered by the AI coding tool, which nothing here confirms",
        "by-hand" => "checked by hand, by you, and recorded",
        "documented" => "answered in the security notes",
        "not-verified" => "not verified: nothing checked it",
        other => other,
    }
}

/// The check ids in one of a report row's lists of credits (`checked_by`, `attested_by`, ...).
fn named(row: &Value, key: &str) -> Vec<String> {
    row[key]
        .as_array()
        .map(|v| {
            v.iter()
                .filter_map(|x| x.get("check_id").and_then(Value::as_str).or(x.as_str()))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The report's own label when only the AI coding tool's word stands behind the row's status and a
/// person confirmed it, read by the report's own rule (`sv_report::confirmed_only_by`); `None` when
/// the status is somebody's own record, or not one of those kinds at all.
fn confirmed_label(row: &Value) -> Option<&'static str> {
    let status: sv_report::Status = serde_json::from_value(row["status"].clone()).ok()?;
    sv_report::confirmed_only_by(
        status,
        &named(row, "attested_by"),
        &named(row, "by_hand"),
        &named(row, "documented_by"),
    )
    .then(|| status.shown(true))
}

/// What the app's last report said about `id`: its status and what stood behind it, or that the
/// requirement was not among those that apply to the app.
fn from_report(report: &Value, id: &str, checks: &[CheckLine]) -> String {
    let app = report["app_name"].as_str().unwrap_or("the app");
    let Some(row) = report["requirements"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["id"] == id))
    else {
        return format!(
            "In {app}'s last report, {id} is not among the requirements that apply: it does not \
             apply to the app, or it is above the app's level. `sv scope` says which, and why.\n"
        );
    };
    let status = row["status"].as_str().unwrap_or("unknown");
    let words = match confirmed_label(row) {
        Some(shown) => format!(
            "{shown}: the AI coding tool gave this answer and somebody confirmed it with `sv review`; \
             nothing here checks it"
        ),
        None => status_words(status).to_owned(),
    };
    let mut out = format!("In {app}'s last report, {id} is {words}.\n");
    let checked = named(row, "checked_by");
    if !checked.is_empty() {
        out.push_str(&format!("Checked by: {}.\n", checked.join(", ")));
    }
    let findings = row["findings"].as_array().map_or(0, Vec::len);
    if findings > 0 {
        out.push_str(&format!(
            "{findings} finding{} name it; the report lists {}.\n",
            if findings == 1 { "" } else { "s" },
            if findings == 1 { "it" } else { "them" }
        ));
    }
    if status == "not-verified" {
        // What the report could not have had: a check that needs a kind of run that did not happen.
        let ran: Vec<String> = report["not_run_this_time"]["kinds"]
            .as_array()
            .map(|k| {
                k.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let waiting: Vec<&CheckLine> = checks
            .iter()
            .filter(|c| !c.finding_only && c.run != "Reads the code")
            .collect();
        if !waiting.is_empty() && !ran.is_empty() {
            out.push_str(&format!(
                "That report did not include {}; {} of the checks below need{} one of those.\n",
                ran.join(" or "),
                waiting.len(),
                if waiting.len() == 1 { "s" } else { "" }
            ));
        }
    }
    out
}

/// Whether the report read as `bytes` from `dir` is one `sv` can show it wrote on this computer and
/// nothing has changed since: its folder's seal holds (`report_seal::proven`, what the MCP server asks
/// before it offers a report, ADR-034), and the bytes read are the ones sealed, so a file swapped
/// after the check is not taken for the sealed one. Why not otherwise (backlog 0226, part 1, item 9:
/// `sv explain` repeated any `report.json` in the folder, which the AI coding tool can write).
fn sealed_as_read(dir: &Path, bytes: &[u8]) -> std::result::Result<(), String> {
    let sealed = crate::report_seal::proven(dir)?;
    match sealed.get("report.json") {
        Some(digest) if *digest == crate::bundle::sha256(bytes) => Ok(()),
        Some(_) => Err("its report.json changed after it was sealed".to_owned()),
        None => Err("its seal does not cover report.json".to_owned()),
    }
}

/// The whole explanation of `id`, with what `report` (an app's last `report.json`) said about it
/// when one is given.
pub fn explain(
    frameworks: &Frameworks,
    reach: &Value,
    rules: &sv_check::coding_rules::CodingRules,
    prompts: &sv_check::prompts::Prompts,
    human: &sv_check::human::HumanChecks,
    id: &str,
    report: Option<&Value>,
) -> Result<String> {
    let r = frameworks
        .get(id)
        .with_context(|| format!("{id} is not a requirement in any loaded framework"))?;
    let mut out = format!(
        "{id} ({}), level {}{}\n\n{}\n",
        r.chapter_name,
        r.level,
        r.level_basis
            .as_deref()
            .map(|b| format!(" — {b}"))
            .unwrap_or_default(),
        r.description
    );
    if let Some(report) = report {
        out.push('\n');
        out.push_str(&from_report(report, id, &checks_for(reach, id)));
    }

    out.push_str("\nWhat sv checks\n");
    let checks = checks_for(reach, id);
    if checks.is_empty() {
        out.push_str(
            "  No check of sv's speaks to it. It is never marked checked; it can only be answered by a \
             person, or by the app's own tests.\n",
        );
    } else {
        for c in &checks {
            out.push_str(&format!(
                "  - {} ({}{}): {}\n",
                c.id,
                c.run,
                if c.finding_only {
                    "; can show it failing, never met"
                } else {
                    ""
                },
                c.looks_for
            ));
        }
    }

    out.push_str("\nWhat to do\n");
    let mut any = false;
    for rule in rules
        .rules
        .iter()
        .filter(|rule| rule.cites.contains_key(id))
    {
        out.push_str(&format!("  - Coding rule `{}`: {}\n", rule.id, rule.rule));
        any = true;
    }
    for p in prompts.select(Some(id)) {
        out.push_str(&format!(
            "  - Prompt `{}`, \"{}\". {} (`sv prompts --requirement {id}` gives it whole)\n",
            p.id,
            p.title,
            p.status_sentence()
        ));
        any = true;
    }
    for h in human.checks.iter().filter(|h| h.id == id) {
        out.push_str(&format!("  - Check it by hand: {}\n", h.how));
        any = true;
    }
    if !any {
        out.push_str(
            "  No coding rule, prompt, or check by hand names it yet. Its own words above are what \
             it asks.\n",
        );
    }
    out.push_str(
        "\nThis explains a requirement. It credits nothing: only a report says what an app was checked \
         for.\n",
    );
    Ok(out)
}

/// `sv explain ID [PATH]`, with the data files read from where `sv` keeps them.
pub fn command(id: &str, app: Option<&Path>) -> Result<String> {
    let frameworks = crate::load_frameworks(&crate::data_dir()?)?;
    let reach_path = sv_frameworks::data::file("reach.json");
    let reach: Value = serde_json::from_str(
        &std::fs::read_to_string(&reach_path)
            .with_context(|| format!("reading {}", reach_path.display()))?,
    )
    .with_context(|| format!("parsing {}", reach_path.display()))?;
    let rules = sv_check::coding_rules::CodingRules::load(&crate::coding_rules_path())?;
    let paths = crate::prompts_paths();
    let prompts = sv_check::prompts::Prompts::load_all(&[&paths[0], &paths[1]])?;
    let human =
        sv_check::human::HumanChecks::load(&sv_frameworks::data::file("human-checks.json"))?;
    let (report, unproven) = match app {
        None => (None, None),
        Some(app) => {
            let dir = sv_scan::ecosystems::default_report_dir_in(app);
            let path = dir.join("report.json");
            let bytes = std::fs::read(&path).with_context(|| {
                format!(
                    "reading {}: no report there yet; `sv report {}` writes one",
                    path.display(),
                    app.display()
                )
            })?;
            match sealed_as_read(&dir, &bytes) {
                Ok(()) => (
                    Some(
                        serde_json::from_slice::<Value>(&bytes)
                            .with_context(|| format!("parsing {}", path.display()))?,
                    ),
                    None,
                ),
                Err(why) => (None, Some((path, why))),
            }
        }
    };
    if let Some((path, why)) = unproven {
        let mut out = explain(&frameworks, &reach, &rules, &prompts, &human, id, None)?;
        out.push_str(&format!(
            "\nWhat {} says is left out: sv cannot show it wrote that report ({why}), and a report \
             anything else wrote is not repeated as sv's. `sv report` on the app writes one it can.\n",
            path.display()
        ));
        return Ok(out);
    }
    explain(
        &frameworks,
        &reach,
        &rules,
        &prompts,
        &human,
        id,
        report.as_ref(),
    )
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod whose_word_tests;
