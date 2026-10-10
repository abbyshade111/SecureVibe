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

/// Each list of credits a report row holds, with the words `sv explain` puts before it.
const CREDIT_LISTS: &[(&str, &str)] = &[
    ("checked_by", "Checked by"),
    (
        "tested_by",
        "Tested by the app's own tests (written by the AI coding tool, not a check of sv's)",
    ),
    ("supported_by", "Supporting it, not counted for it"),
    ("documented_by", "Answered in the security notes"),
    ("by_hand", "Checked by hand"),
    ("attested_by", "Answered yes"),
];

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
fn from_report(report: &Value, which: &str, id: &str, checks: &[CheckLine]) -> String {
    let app = report["app_name"].as_str().unwrap_or("the app");
    let Some(row) = report["requirements"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["id"] == id))
    else {
        return format!(
            "In {app}'s {which}, {id} is not among the requirements that apply: it does not \
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
    let mut out = format!("In {app}'s {which}, {id} is {words}.\n");
    // Every list of credits, each with whose word an entry is when it is somebody's (backlog 226,
    // part 2, item 17): until 10 October 2026 only `checked_by` was printed.
    for (key, label) in CREDIT_LISTS {
        let entries: Vec<String> = row[*key]
            .as_array()
            .map(|v| {
                v.iter()
                    .filter_map(|x| {
                        let check = x.get("check_id")?.as_str()?;
                        Some(match x.get("whose").and_then(Value::as_str) {
                            Some(whose) => format!("{check} ({whose})"),
                            None => check.to_owned(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        if !entries.is_empty() {
            out.push_str(&format!("{label}: {}.\n", entries.join(", ")));
        }
    }
    let withheld: Vec<&str> = row["withheld_by"]
        .as_array()
        .map(|v| v.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if !withheld.is_empty() {
        out.push_str(&format!(
            "Kept from counting: {} was set aside as a false alarm, and a person's word that a rule \
             was wrong does not show the protection is in place.\n",
            withheld.join(", ")
        ));
    }
    // Each finding that names it, with its place, so it can be found without opening the report.
    let findings: Vec<String> = report["findings"]
        .as_array()
        .map(|all| {
            all.iter()
                .filter(|f| {
                    f["requirement_ids"]
                        .as_array()
                        .is_some_and(|ids| ids.iter().any(|r| r == id))
                })
                .map(|f| {
                    format!(
                        "  {} at {}:{}: {}",
                        f["rule_id"].as_str().unwrap_or("?"),
                        f["location"]["file"].as_str().unwrap_or("?"),
                        f["location"]["line"].as_u64().unwrap_or(0),
                        f["title"].as_str().unwrap_or_default()
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    if !findings.is_empty() {
        out.push_str(&format!(
            "{} finding{} name{} it{}:\n{}\n",
            findings.len(),
            if findings.len() == 1 { "" } else { "s" },
            if findings.len() == 1 { "s" } else { "" },
            if status == "needs-attention"
                && row["checked_by"].as_array().is_some_and(|c| !c.is_empty())
            {
                ", and a finding outranks every credit, so what passed does not count"
            } else {
                ""
            },
            findings.join("\n")
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
    report: Option<(&Value, &str)>,
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
    if let Some((report, which)) = report {
        out.push('\n');
        out.push_str(&from_report(report, which, id, &checks_for(reach, id)));
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

/// `sv explain ID [--app DIR] [--report FILE]`, with the data files read from where `sv` keeps
/// them. `--report` reads that report in place of the app's last one (backlog 226, part 2, item
/// 17), under the same rule: only a report `sv` can show it wrote is repeated.
pub fn command(id: &str, app: Option<&Path>, report_file: Option<&Path>) -> Result<String> {
    let frameworks = crate::load_frameworks(&crate::data_dir()?)?;
    let reach_path = sv_frameworks::data::file("reach.json");
    let reach: Value = serde_json::from_str(
        &std::fs::read_to_string(&reach_path)
            .with_context(|| format!("reading {}", reach_path.display()))?,
    )
    .with_context(|| sv_frameworks::data::not_understood(&reach_path))?;
    let rules = sv_check::coding_rules::CodingRules::load(&crate::coding_rules_path())?;
    let paths = crate::prompts_paths();
    let prompts = sv_check::prompts::Prompts::load_all(&[&paths[0], &paths[1]])?;
    let human =
        sv_check::human::HumanChecks::load(&sv_frameworks::data::file("human-checks.json"))?;
    let asked = match (report_file, app) {
        (Some(file), _) => Some((
            file.to_path_buf(),
            format!("report at {}", file.display()),
            format!("reading {}", file.display()),
        )),
        (None, Some(app)) => {
            let path = sv_scan::ecosystems::default_report_dir_in(app).join("report.json");
            let missing = format!(
                "reading {}: no report there yet; `sv report {}` writes one",
                path.display(),
                app.display()
            );
            Some((path, "last report".to_owned(), missing))
        }
        (None, None) => None,
    };
    let (report, unproven) = match &asked {
        None => (None, None),
        Some((path, _, missing)) => {
            let dir = path.parent().unwrap_or(Path::new("."));
            let bytes = std::fs::read(path).with_context(|| missing.clone())?;
            match sealed_as_read(dir, &bytes) {
                Ok(()) => (
                    Some(
                        serde_json::from_slice::<Value>(&bytes)
                            .with_context(|| format!("parsing {}", path.display()))?,
                    ),
                    None,
                ),
                Err(why) => (None, Some((path.clone(), why))),
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
    let which = asked.as_ref().map_or("", |(_, which, _)| which.as_str());
    explain(
        &frameworks,
        &reach,
        &rules,
        &prompts,
        &human,
        id,
        report.as_ref().map(|r| (r, which)),
    )
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod whose_word_tests;
