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
    let escaped = inert(text).replace('|', "\\|");
    // A newline inside a cell ends the row, whatever else has been escaped.
    escaped.replace(['\n', '\r'], " ")
}

/// Text that came from the app, or passed through it, made inert: no link, image, or HTML of its
/// own, while `sv`'s own code spans (`` `.env` ``) still read as code. Until 5 October 2026 an app
/// name, a file path, or a value the app sent back went into security.md and compliance.md as it
/// was, so `[click](https://…)`, `![](https://tracker…)`, or `<img src=…>` in any of them was live
/// wherever the Markdown was shown, and a backtick in a file name let the rest of it out of the code
/// span it was put in (R13 of the deep review). report.html already escaped them.
///
/// Code spans are found as CommonMark finds them, a run of backticks closed by the next run of the
/// same length, so what is escaped is exactly what a renderer would read as Markdown. Outside them,
/// `\`, `[`, `]`, and `<` are escaped; inside, nothing is, since nothing there is read as Markdown.
pub fn inert(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let run_at = |i: usize| chars[i..].iter().take_while(|c| **c == '`').count();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '`' {
            let n = run_at(i);
            // The closing run: the next run of exactly `n` backticks.
            let mut j = i + n;
            let mut close = None;
            // Never past the end of the line: a blank line, a list item, or a heading ends the
            // paragraph, and a span with it (the review of 6 October, item 15). Stopping at any line
            // end escapes a little more than a renderer would read, never less.
            while j < chars.len() && chars[j] != '\n' {
                if chars[j] == '`' {
                    let m = run_at(j);
                    if m == n {
                        close = Some(j);
                        break;
                    }
                    j += m;
                } else {
                    j += 1;
                }
            }
            match close {
                Some(j) => {
                    out.extend(&chars[i..j + n]);
                    i = j + n;
                }
                None => {
                    // An unclosed run is plain backticks, and must not open a span later.
                    for _ in 0..n {
                        out.push_str("\\`");
                    }
                    i += n;
                }
            }
            continue;
        }
        match c {
            '\\' => out.push_str("\\\\"),
            '[' => out.push_str("\\["),
            ']' => out.push_str("\\]"),
            '<' => out.push_str("&lt;"),
            other => out.push(other),
        }
        i += 1;
    }
    out
}

/// A file path or other value of the app's, shown as code whatever it holds: a code span opened
/// with more backticks than any run inside it, so a backtick in a file name cannot close it early.
pub fn code(text: &str) -> String {
    let longest = text.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest + 1);
    let text = text.replace(['\n', '\r'], " ");
    let pad = if text.starts_with('`') || text.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{text}{pad}{fence}")
}

/// One requirement's status, in the words the table prints. Shared so the grouped tables and
/// anything else that lists a requirement cannot drift apart in how they describe the same state.
fn status_cell(line: &crate::RequirementLine) -> String {
    let shown = match line.status {
        Status::NeedsAttention => {
            format!("**{}** ({})", line.status.label(), line.findings.join(", "))
        }
        Status::Checked => format!(
            "{} ({})",
            line.status.label(),
            line.checked_by
                .iter()
                .map(|c| format!("{}: {}", c.check_id, c.scope))
                .collect::<Vec<_>>()
                .join("; ")
        ),
        Status::ByHand => format!(
            "{} \u{2014} {}: {}",
            line.shown_label(),
            line.whose_word(),
            line.by_hand
                .iter()
                .map(|c| c.scope.clone())
                .collect::<Vec<_>>()
                .join("; ")
        ),
        Status::Attested | Status::Stated => format!(
            "{} \u{2014} {}, not a check: {}",
            line.shown_label(),
            line.whose_word(),
            line.attested_by
                .iter()
                .map(|c| c.scope.clone())
                .collect::<Vec<_>>()
                .join("; ")
        ),
        Status::Documented => format!(
            "{} \u{2014} you answered this in {}",
            line.status.label(),
            line.documented_by
                .iter()
                .map(|c| c.scope.clone())
                .collect::<Vec<_>>()
                .join("; ")
        ),
        Status::NotVerified if !line.supported_by.is_empty() => format!(
            "{} — a person has to answer it; supporting: {}",
            line.status.label(),
            line.supported_by
                .iter()
                .map(|c| format!("{}: {}", c.check_id, c.scope))
                .collect::<Vec<_>>()
                .join("; ")
        ),
        Status::NotVerified => line.status.label().to_owned(),
    };
    // Information-only findings sit beside whatever the status is, never in place of it.
    format!("{shown}{}", line.information_note())
}

pub fn compliance(report: &Report) -> String {
    let mut out = String::new();
    let c = &report.counts;
    out.push_str(&format!(
        "# {} — what applies, and what is known\n\n",
        inert(&report.app_name).replace(['\n', '\r'], " ")
    ));
    let made_by = report.sv.describe();
    if let Some(when) = &report.generated {
        out.push_str(&format!(
            "Produced by `sv` {made_by} on {when}. ASVS level {}.\n\n",
            report.target_level
        ));
    } else {
        out.push_str(&format!(
            "Produced by `sv` {made_by}. ASVS level {}.\n\n",
            report.target_level
        ));
    }

    // The short version, before any of the explaining. See `crate::bluf`.
    out.push_str("## The short version\n\n");
    out.push_str(&format!("{}\n\n", crate::bluf::headline(report)));
    let (worst, rest) = crate::bluf::worst_findings(report);
    if !worst.is_empty() {
        for f in worst {
            out.push_str(&format!(
                "- **{}** — {} ({})\n",
                cell(&f.title),
                cell(f.severity.name()),
                cell(&f.rule_id)
            ));
        }
        if rest > 0 {
            out.push_str(&format!(
                "- … and {rest} more, in security.md, worst first\n"
            ));
        }
        out.push('\n');
    }
    out.push_str("Of the requirements that apply to this app:\n\n");
    for (label, n) in crate::bluf::counted(report) {
        out.push_str(&format!("- **{n}** — {label}\n"));
    }
    out.push('\n');
    let steps = crate::bluf::next_steps(report);
    if !steps.is_empty() {
        out.push_str("### What to do next\n\n");
        for (i, step) in steps.iter().enumerate() {
            out.push_str(&format!(
                "{}. {} *({})*\n",
                i + 1,
                step.what,
                step.where_to_look
            ));
        }
        out.push('\n');
    }

    out.push_str("## Read this first\n\n");
    if let Some(note) = &report.run_note {
        out.push_str(&format!("{note}\n\n"));
    }
    if !report.run_steps.is_empty() {
        out.push_str(&format!(
            "<details>\n<summary>The {} things it did while the app ran</summary>\n\n",
            report.run_steps.len()
        ));
        for step in &report.run_steps {
            out.push_str(&format!("- {}\n", cell(step)));
        }
        out.push_str("\n</details>\n\n");
    }
    if let Some(t) = &report.test_output {
        out.push_str(&format!("{}\n\n", crate::test_output_intro(t)));
        if !t.text.is_empty() {
            // A fence longer than any run of backticks in the output, so nothing in it ends it.
            let longest = t.text.split(|c| c != '`').map(str::len).max().unwrap_or(0);
            let fence = "`".repeat(longest.max(2) + 1);
            out.push_str(&format!("{fence}text\n{}\n{fence}\n\n", t.text));
        }
    }
    out.push_str(&format!("{}\n\n", crate::lede(c, "**", "**")));
    if c.ai_process > 0 {
        out.push_str(&format!(
            "A further {} about how the app is built with an AI coding tool, from OWASP AISVS \
             Appendix C, are counted apart: see \"How the app is built with AI\", below.\n\n",
            c.ai_process
        ));
    }
    out.push_str(
        "There is no line in this report that says a requirement passed, because nothing here is \
         able to establish that. A requirement marked *checked* had at least one automated check look \
         at it and find nothing wrong, over the coverage named beside it — which is worth having and is not the same as the requirement \
         being met. One marked as answered in the security notes, checked by hand, or answered \
         yes rests on your word or your AI coding tool's, which is shown as exactly that and never \
         as checked. Everything else applicable is *not verified*: nothing has produced evidence \
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
    // Every status, so the rows add up to what applies: see `Counts::by_status`.
    for (status, n) in c.by_status() {
        out.push_str(&format!("| {} | {n} |\n", status.applies_row()));
    }
    out.push_str(&format!("| Does not apply | {} |\n", c.not_applicable));
    out.push_str(&format!(
        "| Not assessed — nobody has answered | {} |\n",
        c.not_assessed
    ));
    out.push_str(&format!(
        "| Above this app's target level (ASVS level {}) | {} |\n\n",
        report.target_level, c.out_of_level
    ));

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

    // By chapter, with what does not apply counted beside what does, and the requirements' own
    // words in an appendix at the end. See `crate::chapters` for why.
    out.push_str("## Requirements that apply\n\n");
    requirements_by_chapter(&mut out, report);

    if !report.ai_process.lines.is_empty() {
        let p = &report.ai_process;
        out.push_str("## How the app is built with AI (OWASP AISVS Appendix C)\n\n");
        out.push_str(&format!("{}\n\n", p.summary()));
        out.push_str("| requirement | what happens to it | what it asks for |\n|---|---|---|\n");
        for line in &p.lines {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                cell(&line.id),
                cell(crate::AiProcess::route_text(line.route)),
                cell(&line.description)
            ));
        }
        out.push('\n');
    }

    if !report.threats.is_empty() {
        out.push_str("## Threats\n\n");
        out.push_str(&format!("{}\n\n", crate::threats::INTRO));
        let parts: Vec<String> = report
            .threat_parts
            .iter()
            .map(|p| match p.present {
                Some(true) => p.name.clone(),
                _ => format!(
                    "{} (not known: securevibe.toml does not answer {})",
                    p.name,
                    p.unanswered
                        .iter()
                        .map(|c| format!("`{c}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            })
            .collect();
        out.push_str(&format!("Parts of the app: {}.\n\n", parts.join("; ")));
        out.push_str(&format!(
            "{}\n\n",
            crate::threats::count_line(&report.threats)
        ));
        out.push_str("| threat | status | part of the app | what could happen | the requirements that answer it |\n|---|---|---|---|---|\n");
        for line in &report.threats {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                cell(&format!(
                    "{} ({})",
                    line.id,
                    crate::threats::stride_words(&line.stride)
                )),
                cell(line.status.label()),
                cell(&line.element_name),
                cell(&line.description),
                cell(&crate::threats::evidence_words(line))
            ));
        }
        out.push('\n');
        if let Some(release) = &report.threat_atlas_release {
            let mapped: Vec<_> = report
                .threats
                .iter()
                .filter(|l| !l.atlas.is_empty())
                .collect();
            if !mapped.is_empty() {
                out.push_str("### For a security reviewer: these threats in MITRE ATLAS\n\n");
                out.push_str(&format!("{}\n\n", crate::threats::atlas_intro(release)));
                out.push_str(
                    "| threat | MITRE ATLAS technique | what the two share |\n|---|---|---|\n",
                );
                for line in mapped {
                    for r in &line.atlas {
                        out.push_str(&format!(
                            "| {} | {} | {} |\n",
                            cell(&line.id),
                            cell(&format!("{} {}", r.id, r.name)),
                            cell(&r.because)
                        ));
                    }
                }
                out.push('\n');
            }
        }
    }

    // High up, and above "Tests worth writing first": these are the ones nothing will ever settle
    // on its own, so they are the part of the work that cannot be delegated to a tool.
    if !report.only_you_can_check.is_empty() {
        out.push_str("## What only you can check\n\n");
        out.push_str(&format!(
            "{} of the requirements that apply cannot be settled by any tool: they ask what your \
             rules are, how the app is built, or what is true of it in production. Each one below \
             says what doing something about it involves. None of them is counted as met — doing \
             the thing is what would change that, not reading it here.\n\n",
            report.only_you_can_check.len()
        ));
        if report.no_instructions_yet > 0 {
            out.push_str(&format!(
                "A further {} are the Secure by Design and AISVS design-review controls, which \
                 are not listed one by one: those standards are checklists already, and repeating \
                 them here would be another wall of text. They are in the table above, and in the \
                 standards themselves.\n\n",
                report.no_instructions_yet
            ));
        }
        out.push_str("| requirement | what to do | how |\n|---|---|---|\n");
        for item in &report.only_you_can_check {
            out.push_str(&format!(
                "| {} — {} | {} | {} |\n",
                cell(&item.id),
                cell(&item.title),
                cell(item.route.what_to_do()),
                cell(&match &item.where_to_look {
                    Some(where_to_look) =>
                        format!("{} **Where to look:** {where_to_look}", item.how),
                    None => item.how.clone(),
                })
            ));
        }
        out.push('\n');
    }

    // Level 1 only. The whole list is 87 rows of requirement ids for an owner who is not a
    // programmer, and it reads as a to-do list aimed at somebody else — which it is: its real
    // audience is the AI coding tool, and `sv mcp` gives that one the complete list. What is left
    // here is the short list a person could hand to whoever writes their tests.
    let level_one: Vec<&crate::TestToWrite> = report
        .tests_to_write
        .iter()
        .filter(|t| t.level == 1)
        .collect();
    let deeper = report.tests_to_write.len() - level_one.len();
    if !level_one.is_empty() || !report.named_not_credited.is_empty() {
        out.push_str("## Tests worth writing first\n\n");
        out.push_str(
            "Nothing produced evidence about these, and no test in the app names them. A test that \
             names a requirement's id and passes is the one way to give evidence about any \
             requirement, including the ones no check here can reach. These are the level 1 ones. \
             Name only what a test really checks: nothing here can tell whether it does.\n\n",
        );
        if deeper > 0 {
            out.push_str(&format!(
                "{deeper} more are at level 2 and above. They are not listed here, because a list \
                 that long is not something a person works through; `sv mcp` gives the whole list \
                 to your AI coding tool, and report.json carries it under `tests_to_write`.\n\n"
            ));
        }
        if report.not_for_tests > 0 {
            out.push_str(&format!("{} more have no evidence and are not listed at all, because an application's own tests cannot show them: they ask for documentation, a deployment setting, a development process, or a design decision, and a person answers them.\n\n", report.not_for_tests));
        }
        if !report.named_not_credited.is_empty() {
            out.push_str(&format!(
                "Named in a test and still without evidence, because the tests were not run here or \
                 did not pass: {}.\n\n",
                report.named_not_credited.join(", ")
            ));
        }
        if !level_one.is_empty() {
            out.push_str("| requirement | what it asks for |\n|---|---|\n");
            for t in &level_one {
                out.push_str(&format!("| {} | {} |\n", cell(&t.id), cell(&t.description)));
            }
            out.push('\n');
        }
    }

    if !report.undecided.is_empty() {
        out.push_str("<details>\n<summary><strong>Requirements nobody has placed</strong> — each names the question that would place it</summary>\n\n");
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

    out.push_str("\n</details>\n\n");

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
                cell(&line.landed_in)
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

    if !report.checklist_above_level.is_empty() {
        out.push_str("## Secure by Design controls above this app's target level\n\n");
        out.push_str(
            "The checklist has no levels of its own. Each control takes the level of the ASVS \
             requirement that asks the same thing, or is shown at every level when none does; a few \
             keep the level `sv` derived from the checklist's severity, which is lower. These are \
             the ones that came out above this app's target.\n\n\
             | control | where its level came from | what it asks for |\n|---|---|---|\n",
        );
        for line in &report.checklist_above_level {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                cell(&line.id),
                cell(&line.basis),
                cell(&line.description)
            ));
        }
        out.push('\n');
    }

    if !report.excluded.is_empty() {
        out.push_str("<details>\n<summary><strong>Requirements that do not apply, and why</strong> — reference: why each was ruled out</summary>\n\n");
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

    out.push_str("\n</details>\n\n");

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

    appendix(&mut out, report);
    out
}

/// The chapter table, then each chapter's requirements that apply, by id, level, and status.
fn requirements_by_chapter(out: &mut String, report: &Report) {
    let chapters = crate::chapters::by_chapter(report);
    let any = |f: &dyn Fn(&crate::chapters::Chapter) -> usize| chapters.iter().any(|c| f(c) > 0);
    let your_word = any(&|c| c.your_word);
    let tool_word = any(&|c| c.tool_word);
    out.push_str(
        "Each chapter of the standards, with how many of its requirements apply to this app and \
         what is known about them, and how many do not apply. What each requirement asks for is in \
         the appendix at the end.\n\n",
    );
    let mut head = String::from("| chapter | apply | a problem found | checked");
    let mut rule = String::from("|---|---:|---:|---:");
    if your_word {
        head.push_str(" | your word, not a check");
        rule.push_str("|---:");
    }
    if tool_word {
        head.push_str(" | your AI tool's word");
        rule.push_str("|---:");
    }
    head.push_str(" | not verified | does not apply | not placed yet |\n");
    rule.push_str("|---:|---:|---:|\n");
    out.push_str(&head);
    out.push_str(&rule);
    for c in &chapters {
        let mut row = format!(
            "| {} | **{}** | {} | {}",
            cell(&c.title()),
            c.applies(),
            c.needs_attention,
            c.checked
        );
        if your_word {
            row.push_str(&format!(" | {}", c.your_word));
        }
        if tool_word {
            row.push_str(&format!(" | {}", c.tool_word));
        }
        row.push_str(&format!(
            " | {} | {} | {} |\n",
            c.not_verified, c.does_not_apply, c.not_placed
        ));
        out.push_str(&row);
    }
    out.push('\n');
    let apart = report.ai_process.lines.len();
    if apart > 0 {
        out.push_str(&format!(
            "Not in this table: the {apart} requirements about how the app is built with an AI coding \
             tool that nothing has reached, which are counted apart in \"How the app is built with \
             AI\", below. The Appendix C row counts only the ones that have evidence, do not apply, \
             or wait on a question.\n\n"
        ));
    }
    for c in chapters.iter().filter(|c| c.applies() > 0) {
        let mut heading = format!("### {} — **{} apply**", c.title(), c.applies());
        if c.does_not_apply > 0 {
            heading.push_str(&format!(", {} do not", c.does_not_apply));
        }
        out.push_str(&format!("{heading}\n\n"));
        out.push_str("| requirement | status | level |\n|---|---|---:|\n");
        for line in &c.lines {
            let level = if line.level == 0 {
                "—".to_owned()
            } else {
                line.level.to_string()
            };
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                cell(&line.id),
                cell(&status_cell(line)),
                level
            ));
        }
        out.push('\n');
    }
}

/// What each requirement that applies asks for, once, in the chapters' order.
fn appendix(out: &mut String, report: &Report) {
    let chapters = crate::chapters::by_chapter(report);
    if chapters.iter().all(|c| c.applies() == 0) {
        return;
    }
    out.push_str("## Appendix: what each requirement asks for\n\n");
    out.push_str(
        "The words of the standard, for every requirement that applies to this app, in the order \
         of the chapters above.\n\n\
         | requirement | what it asks for |\n|---|---|\n",
    );
    for c in &chapters {
        for line in &c.lines {
            out.push_str(&format!(
                "| {} | {} |\n",
                cell(&line.id),
                cell(&line.description)
            ));
        }
    }
    out.push('\n');
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
        inert(&report.app_name).replace(['\n', '\r'], " ")
    ));
    match &report.generated {
        Some(when) => out.push_str(&format!(
            "Produced by `sv` {} on {when}.\n\n",
            report.sv.describe()
        )),
        None => out.push_str(&format!("Produced by `sv` {}.\n\n", report.sv.describe())),
    }

    if !report.gaps.is_empty() {
        // Deliberately before the findings. A list of findings read without this reads as the whole
        // truth about the app, and it is only the truth about the part that was examined.
        out.push_str("## What was not examined\n\n");
        for gap in &report.gaps {
            // App text reaches both: a file path, the decisions file's own words.
            out.push_str(&format!(
                "- **{}** — {}\n",
                inert(&gap.what),
                inert(&gap.why)
            ));
        }
        out.push('\n');
    }

    let set_aside = crate::false_alarm_entries(report);
    if !set_aside.is_empty() || !report.reviews_not_counted.is_empty() {
        out.push_str("## Set aside in securevibe.toml\n\n");
        if !set_aside.is_empty() {
            out.push_str(&format!(
                "Found by a check, and set aside as a false alarm in securevibe.toml through \
                 `sv review`. {} They are not counted below. A requirement one of them was about is not credited \
                 for it: it is shown by whatever else is known about it, never as checked.\n\n",
                crate::SEALED_WHY
            ));
            for (line, report_it) in &set_aside {
                out.push_str(&format!(
                    "- {} [Report it against the rule]({report_it})\n",
                    inert(line)
                ));
            }
            out.push_str(&format!("\n{}\n\n", crate::FALSE_ALARM_WHY));
        }
        if !report.reviews_not_counted.is_empty() {
            out.push_str(
                "These entries in `[[finding-review]]` do not count, so the findings they name \
                 still do. Each says why. One whose finding was not looked for this time, or whose \
                 rule this version of `sv` does not have, is not a sign the finding was fixed. To \
                 record one as your decision, run `sv review` in your own terminal.\n\n",
            );
            for line in &report.reviews_not_counted {
                out.push_str(&format!("- {}\n", inert(line)));
            }
            out.push('\n');
        }
    }

    if report.findings.is_empty() {
        out.push_str(
            "## Nothing was found\n\nNo check found anything wrong. Read that together with the \
             section above: it means the checks that ran found nothing, not that the app is \
             secure.\n\n",
        );
        return out;
    }

    let (app, tests) = crate::app_then_tests(report);
    if app.is_empty() {
        out.push_str(
            "## Nothing was found in the app itself\n\nEverything below is in test or sample \
             code. Read that together with the section above: it means the checks that ran found \
             nothing in the app's own code, not that the app is secure.\n\n",
        );
    } else {
        out.push_str(&format!(
            "## {} thing{} to fix\n\nWorst first.\n\n",
            app.len(),
            if app.len() == 1 { "" } else { "s" }
        ));
        for finding in app {
            finding_section(&mut out, report, finding);
        }
    }
    if !tests.is_empty() {
        out.push_str(&format!(
            "## {} in test or sample code\n\n{}\n\n",
            tests.len(),
            crate::TEST_CODE_SECTION
        ));
        for finding in tests {
            finding_section(&mut out, report, finding);
        }
    }
    out
}

fn finding_section(out: &mut String, report: &Report, finding: &sv_check::Finding) {
    out.push_str(&format!(
        "### [{}] {}\n\n",
        finding.severity.name(),
        inert(&finding.title).replace(['\n', '\r'], " ")
    ));
    out.push_str(&format!(
        "**Where:** {} line {}\n\n",
        code(&finding.location.file),
        finding.location.line
    ));
    if let Some(accepted) = crate::accepted_note(report, finding) {
        out.push_str(&format!("**{}**\n\n", inert(&accepted)));
    }
    for note in crate::finding_notes(finding) {
        out.push_str(&format!("*{}*\n\n", inert(&note)));
    }
    out.push_str(&format!("{}\n\n", inert(&finding.description)));
    out.push_str(&format!(
        "**Why it matters.** {}\n\n",
        inert(&finding.impact)
    ));
    out.push_str(&format!("**What to do.** {}\n\n", inert(&finding.fix)));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_text_is_inert_outside_code_and_left_as_it_is_inside() {
        assert_eq!(inert("[a](https://e)"), "\\[a\\](https://e)");
        assert_eq!(inert("![](https://t)"), "!\\[\\](https://t)");
        assert_eq!(inert("<img src=x>"), "&lt;img src=x>");
        // sv's own code spans read as code, with what is inside them untouched.
        assert_eq!(
            inert("set `[[finding-review]]` here"),
            "set `[[finding-review]]` here"
        );
        assert_eq!(inert("``a`b``"), "``a`b``");
        // A backtick with no partner is plain, and cannot open a span with a later one.
        assert_eq!(inert("a`[x](y)"), "a\\`\\[x\\](y)");
        // A value that closes the span it was put in: what follows is outside, and inert.
        assert_eq!(
            inert("`Origin: x`[y](https://e)`"),
            "`Origin: x`\\[y\\](https://e)\\`"
        );
        assert_eq!(inert("C:\\path"), "C:\\\\path");
        assert_eq!(inert("plain words"), "plain words");
    }

    #[test]
    fn security_md_keeps_app_text_in_gaps_and_reviews_inert() {
        // The review of 6 October, item 4: both were written into security.md as they were.
        let live = "![x](https://t.example/p.png) <img src=x> [click](https://e.example)";
        let report = crate::Report {
            app_name: "test".into(),
            target_level: 1,
            generated: None,
            sv: Default::default(),
            run_record: None,
            run_note: None,
            run_steps: Vec::new(),
            test_output: None,
            run_status: None,
            ai_process: Default::default(),
            counts: crate::Counts::default(),
            requirements: vec![],
            excluded: vec![],
            undecided: vec![],
            claims: vec![],
            findings: vec![],
            set_aside: Vec::new(),
            reviews_not_counted: vec![format!("an entry: {live}")],
            out_of_scope: vec![],
            checklist_above_level: vec![],
            tests_to_write: vec![],
            only_you_can_check: Vec::new(),
            questions_for_you: Vec::new(),
            no_instructions_yet: 0,
            named_not_credited: vec![],
            not_for_tests: 0,
            threats: Vec::new(),
            threat_parts: Vec::new(),
            threat_atlas_release: None,
            satisfied_elsewhere: vec![],
            gaps: vec![crate::Gap {
                what: format!("a gap {live}"),
                why: format!("because {live}"),
            }],
            examined: Vec::new(),
            could_not_run: Vec::new(),
            partly_read: Vec::new(),
        };
        let md = security(&report);
        // The setup: all three reached the page.
        for reached in ["a gap", "because", "an entry:"] {
            assert!(md.contains(reached), "{reached} missing:\n{md}");
        }
        for live in ["![x](", "<img", "[click]("] {
            assert!(!md.contains(live), "{live} is live in:\n{md}");
        }
    }

    #[test]
    fn a_value_shown_as_code_cannot_close_its_span() {
        assert_eq!(code("app.py"), "`app.py`");
        assert_eq!(code("a`b.py"), "``a`b.py``");
        assert_eq!(code("a``b"), "```a``b```");
        assert_eq!(code("`x"), "`` `x ``");
        assert_eq!(code("a\nb"), "`a b`");
    }

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
