//! The reports as Markdown.
//!
//! Escaping is the whole risk here and it is not theoretical: a requirement description containing a
//! pipe breaks the table it is in, and a file path containing one breaks the row that names the file
//! a credential was found in. `cell` escapes the backslash **before** the pipe, because doing it the
//! other way turns `\` into `\\` after `|` has already become `\|`, leaving `\\|` — an escaped
//! backslash followed by a live pipe, which is the bug back again.

use crate::{Report, Status};

/// Escapes one table cell.
pub fn cell(text: &str) -> String {
    // Backslash first. See the module comment; the order is the entire point of this function.
    let escaped = text.replace('\\', "\\\\").replace('|', "\\|");
    // A newline inside a cell ends the row, whatever else has been escaped.
    escaped.replace(['\n', '\r'], " ")
}

pub fn compliance(report: &Report) -> String {
    let mut out = String::new();
    let c = &report.counts;
    out.push_str(&format!(
        "# {} — what applies, and what is known\n\n",
        report.app_name
    ));
    if let Some(when) = &report.generated {
        out.push_str(&format!(
            "Produced by `sv` on {when}. ASVS level {}.\n\n",
            report.target_level
        ));
    } else {
        out.push_str(&format!(
            "Produced by `sv`. ASVS level {}.\n\n",
            report.target_level
        ));
    }

    out.push_str("## Read this first\n\n");
    if let Some(note) = &report.run_note {
        out.push_str(&format!("{note}\n\n"));
    }
    out.push_str(&format!(
        "{} requirements apply to this app. Of those, **{} have been looked at by something** and \
         **{} have not**.\n\n",
        c.applicable,
        c.needs_attention + c.checked,
        c.not_verified
    ));
    out.push_str(
        "There is no line in this report that says a requirement passed, because nothing here is \
         able to establish that. A requirement marked *checked* had at least one automated check look \
         at it and find nothing wrong, over the coverage named beside it — which is worth having and is not the same as the requirement \
         being met. Everything else applicable is *not verified*: nothing has produced evidence \
         either way.\n\n",
    );
    if c.not_assessed > 0 {
        out.push_str(&format!(
            "A further **{} requirements could not even be placed**: nobody has answered the \
             question that decides whether they apply. They are listed at the end with the question \
             in each case. They are not exclusions and they are not passes.\n\n",
            c.not_assessed
        ));
    }

    out.push_str("| | count |\n|---|---:|\n");
    out.push_str(&format!(
        "| Applies, needs attention | {} |\n",
        c.needs_attention
    ));
    out.push_str(&format!(
        "| Applies, checked by an automated check | {} |\n",
        c.checked
    ));
    out.push_str(&format!(
        "| Applies, not verified by anything | {} |\n",
        c.not_verified
    ));
    out.push_str(&format!("| Does not apply | {} |\n", c.not_applicable));
    out.push_str(&format!(
        "| Not assessed — nobody has answered | {} |\n",
        c.not_assessed
    ));
    out.push_str(&format!(
        "| Above level {} | {} |\n\n",
        report.target_level, c.out_of_level
    ));
    if c.out_of_level_derived > 0 {
        out.push_str(&format!(
            "{} of those are Secure by Design controls. That checklist has no levels of its own, so \
             `sv` works one out from whether a control is critical and what its absence costs — that \
             number is this tool's judgement, not OWASP's.\n\n",
            c.out_of_level_derived
        ));
    }

    if !report.gaps.is_empty() {
        out.push_str("## What was not examined\n\n");
        out.push_str(
            "Each of these is a limit on what the rest of this report can mean.\n\n\
             | not examined | why |\n|---|---|\n",
        );
        for gap in &report.gaps {
            out.push_str(&format!("| {} | {} |\n", cell(&gap.what), cell(&gap.why)));
        }
        out.push('\n');
    }

    out.push_str("## Requirements that apply\n\n");
    out.push_str("| requirement | status | what it asks for |\n|---|---|---|\n");
    for line in &report.requirements {
        let status = match line.status {
            Status::NeedsAttention => {
                format!("**{}** ({})", line.status.label(), line.findings.join(", "))
            }
            Status::Checked => format!(
                "{} ({})",
                line.status.label(),
                line.checked_by
                    .iter()
                    .map(|c| format!("{} over {}", c.check_id, c.scope))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            Status::NotVerified => line.status.label().to_owned(),
        };
        out.push_str(&format!(
            "| {} | {} | {} |\n",
            cell(&line.id),
            cell(&status),
            cell(&line.description)
        ));
    }
    out.push('\n');

    if !report.excluded.is_empty() {
        out.push_str("## Requirements that do not apply, and why\n\n");
        out.push_str(
            "An exclusion resting on the manifest's word is weaker than one resting on what the \
             code actually contains. The last column says which this is.\n\n\
             | requirement | why not | rests on |\n|---|---|---|\n",
        );
        for ex in &report.excluded {
            out.push_str(&format!(
                "| {} | {} | {} ({}) |\n",
                cell(&ex.id),
                cell(&ex.reason),
                cell(ex.rests_on),
                cell(&ex.condition)
            ));
        }
        out.push('\n');
    }

    if !report.undecided.is_empty() {
        out.push_str("## Requirements nobody has placed\n\n");
        out.push_str(
            "These are not exclusions. Answering the question in the second column moves each one \
             into *applies* or *does not apply*.\n\n\
             | requirement | what has to be answered |\n|---|---|\n",
        );
        for un in &report.undecided {
            out.push_str(&format!(
                "| {} | {} |\n",
                cell(&un.id),
                cell(&un.blocked_on.join(" — or — "))
            ));
        }
        out.push('\n');
    }

    if !report.out_of_scope.is_empty() {
        out.push_str("## Findings about requirements this app is not being assessed against\n\n");
        out.push_str(
            "Something was found, and it named a requirement that is not in the list above. That \
             is worth a look either way: either the requirement was excluded when it should not \
             have been, or the check is citing a requirement that has nothing to do with it.\n\n\
             | found by | about | where that requirement ended up |\n|---|---|---|\n",
        );
        for line in &report.out_of_scope {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                cell(&line.rule_id),
                cell(&line.requirement_id),
                cell(line.landed_in)
            ));
        }
        out.push('\n');
    }

    if !report.satisfied_elsewhere.is_empty() {
        out.push_str(
            "## Checks that ran and found nothing, against nothing in the tables above\n\n",
        );
        out.push_str(
            "These were satisfied. They appear here rather than beside a requirement because what \
             they look at is not something this app is being assessed on.\n\n\
             | check | what it covered | why it is here |\n|---|---|---|\n",
        );
        for line in &report.satisfied_elsewhere {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                cell(&line.check_id),
                cell(&line.scope),
                cell(&line.why)
            ));
        }
        out.push('\n');
    }

    if !report.claims.is_empty() {
        out.push_str("## What the app says about itself\n\n");
        out.push_str(
            "| about | securevibe.toml | the code | what that means |\n|---|---|---|---|\n",
        );
        for claim in &report.claims {
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                cell(&claim.name),
                said(claim.claimed),
                said(claim.found_in_code),
                cell(&claim.note)
            ));
        }
        out.push('\n');
    }

    out
}

fn said(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "nothing",
    }
}

pub fn security(report: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# {} — what the checks found\n\n",
        report.app_name
    ));
    if let Some(when) = &report.generated {
        out.push_str(&format!("Produced by `sv` on {when}.\n\n"));
    }

    if !report.gaps.is_empty() {
        // Deliberately before the findings. A list of findings read without this reads as the whole
        // truth about the app, and it is only the truth about the part that was examined.
        out.push_str("## What was not examined\n\n");
        for gap in &report.gaps {
            out.push_str(&format!("- **{}** — {}\n", gap.what, gap.why));
        }
        out.push('\n');
    }

    if report.findings.is_empty() {
        out.push_str(
            "## Nothing was found\n\nNo check found anything wrong. Read that together with the \
             section above: it means the checks that ran found nothing, not that the app is \
             secure.\n\n",
        );
        return out;
    }

    out.push_str(&format!(
        "## {} thing{} to fix\n\nWorst first.\n\n",
        report.findings.len(),
        if report.findings.len() == 1 { "" } else { "s" }
    ));

    for finding in &report.findings {
        out.push_str(&format!(
            "### [{}] {}\n\n",
            finding.severity.name(),
            finding.title
        ));
        out.push_str(&format!(
            "**Where:** `{}` line {}\n\n",
            finding.location.file, finding.location.line
        ));
        out.push_str(&format!("{}\n\n", finding.description));
        out.push_str(&format!("**Why it matters.** {}\n\n", finding.impact));
        out.push_str(&format!("**What to do.** {}\n\n", finding.fix));
        if !finding.requirement_ids.is_empty() {
            out.push_str(&format!(
                "Evidence about: {}\n\n",
                finding.requirement_ids.join(", ")
            ));
        }
        if !finding.cwe.is_empty() {
            out.push_str(&format!("Known as: {}\n\n", finding.cwe.join(", ")));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pipe_in_a_cell_does_not_break_the_table() {
        assert_eq!(cell("a | b"), "a \\| b");
    }

    #[test]
    fn a_backslash_is_escaped_before_the_pipe_and_not_after() {
        // The order is the bug. Escaping the pipe first gives `\\|`: an escaped backslash followed
        // by a live pipe, which ends the cell — the table breaks on exactly the input the escaping
        // was added for. This is the same fault that was fixed in v1's `reports/md.ts`.
        assert_eq!(cell("a\\|b"), "a\\\\\\|b");
        let rendered = cell("a\\|b");
        // Walk it the way a Markdown reader would: a pipe is a separator only when the number of
        // backslashes immediately before it is even.
        let mut backslashes = 0;
        let mut live_separators = 0;
        for ch in rendered.chars() {
            match ch {
                '\\' => backslashes += 1,
                '|' => {
                    if backslashes % 2 == 0 {
                        live_separators += 1;
                    }
                    backslashes = 0;
                }
                _ => backslashes = 0,
            }
        }
        assert_eq!(live_separators, 0, "`{rendered}` still ends the cell early");
    }

    #[test]
    fn a_newline_in_a_cell_does_not_end_the_row() {
        assert!(!cell("one\ntwo").contains('\n'));
    }
}
