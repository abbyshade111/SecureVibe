//! The check rendered for the AI coding tool: its sections, in pages, and the structured result.

use super::*;

/// The report as a model should read it: what was not examined first, then what needs attention.
///
/// Every piece of the app's own text, and every line of the report that can quote it (a gap, a
/// finding's title and fix, a claim, a threat, an entry in securevibe.toml), is fenced as data
/// (`sv_report::fence`): an app's name opened this result as if `sv` had said it (deep review R9).
/// What `sv` itself tells the tool to do stays outside every fence.
pub(super) fn summary_with(report: &sv_report::Report, fence: &sv_report::fence::Fence) -> String {
    check_sections(report, fence)
        .iter()
        .map(crate::parts::Section::text)
        .collect()
}

/// The names of the check's sections, in the order of the whole answer, for `securevibe_check`'s `section`.
pub(super) const CHECK_SECTIONS: &[&str] = &[
    "summary",
    "not-examined",
    "questions",
    "contradicted",
    "threats",
    "tests",
    "findings",
    "set-aside",
    "not-counted",
    "claims",
    "undecided",
];

/// The sections a check's first answer starts with: what was not examined before anything else, as the
/// instructions say, then what the tool must not do with the findings set aside, then the findings, before the
/// longer lists.
pub(super) const CHECK_FIRST: &[&str] = &[
    "summary",
    "not-examined",
    "questions",
    "contradicted",
    "set-aside",
    "not-counted",
    "findings",
];

/// The check in its sections, each line with the item of the structured result it shows (`crate::parts`):
/// the whole answer is these joined. The last two are in the structured result only, as they always were.
pub(super) fn check_sections(
    report: &sv_report::Report,
    fence: &sv_report::fence::Fence,
) -> Vec<crate::parts::Section> {
    use crate::parts::{Item, Section};
    let one_line = |text: &str| fence.wrap(text);
    let c = &report.counts;

    let needs_attention: Vec<&String> = report
        .requirements
        .iter()
        .filter(|l| l.status == sv_report::Status::NeedsAttention)
        .map(|l| &l.id)
        .collect();
    let mut summary = Section::new(
        "summary",
        format!(
            "The counts, and the requirements that need attention ({})",
            needs_attention.len()
        ),
        &["needsAttention"],
    );
    // Every status, so the numbers add up to what applies (deep review R5); the four that rest on
    // somebody's word say whose, so the tool reading this cannot take them for checks.
    summary.lead = format!(
        "{}: {} requirements apply at ASVS level {}. {} need attention, {} were checked by an \
         automated check, {} were checked in part (an automated check tried some of what each asks), \
         {} were tested only by the app's own tests (written by the AI coding tool, not a \
         check of sv's), {} the owner answered in the security notes, {} the owner checked by \
         hand, {} the owner answered yes to in securevibe.toml, {} the AI coding tool answered yes \
         to (those four are somebody's word, not a check), {} were not verified by anything. {} \
         more could not be placed because nobody has answered the question that decides them. \
         Nothing here says a requirement passed.\n",
        one_line(&report.app_name),
        c.applicable,
        report.target_level,
        c.needs_attention,
        c.checked,
        c.checked_in_part,
        c.app_tested,
        c.documented,
        c.by_hand,
        c.attested,
        c.stated,
        c.not_verified,
        c.not_assessed
    );
    if !report.ai_process.lines.is_empty() {
        summary
            .lead
            .push_str(&format!("{}\n", report.ai_process.summary()));
    }
    for id in needs_attention {
        summary
            .items
            .push(Item::with(String::new(), "needsAttention", json!(id)));
    }

    let mut gaps = Section::new(
        "not-examined",
        format!("What was not examined ({})", report.gaps.len()),
        &["notExamined"],
    );
    if !report.gaps.is_empty() {
        gaps.lead = "\nNOT EXAMINED — read these before anything below:\n".to_owned();
    }
    for gap in &report.gaps {
        gaps.items.push(Item::with(
            format!("- {}\n", one_line(&format!("{}: {}", gap.what, gap.why))),
            "notExamined",
            json!(gap),
        ));
    }

    let mut questions = Section::new(
        "questions",
        format!(
            "The {} questions only the person can answer (securevibe_questions asks them)",
            report.questions_for_you.len()
        ),
        &[],
    );
    if !report.questions_for_you.is_empty() {
        questions.lead = format!(
            "\nQUESTIONS FOR THE OWNER — {} that only a person can answer (how the app is built, \
             the rules it follows, what to check by hand). Call securevibe_questions and ask the \
             person them one at a time; `sv notes` and `sv questions` in the lines above are the \
             terminal's way to the same thing.\n",
            report.questions_for_you.len()
        );
    }

    let contradicted: Vec<&sv_report::ClaimLine> = report
        .claims
        .iter()
        .filter(|c| c.state == "contradicted")
        .collect();
    let mut contradictions = Section::new(
        "contradicted",
        format!(
            "What securevibe.toml says that the code contradicts ({})",
            contradicted.len()
        ),
        &[],
    );
    if !contradicted.is_empty() {
        contradictions.lead =
            "\nsecurevibe.toml says one thing and the code another (the code wins):\n".to_owned();
    }
    for claim in contradicted {
        contradictions.items.push(Item::text(format!(
            "- {}\n",
            one_line(&format!("{}: {}", claim.name, claim.note))
        )));
    }

    let mut threats = Section::new(
        "threats",
        format!("The threats ({})", report.threats.len()),
        &[],
    );
    if !report.threats.is_empty() {
        use sv_report::threats::ThreatStatus;
        threats.lead = format!(
            "\nTHREATS — {} None is handled: a threat is only as settled as the requirements \
             that answer it.\n",
            sv_report::threats::count_line(&report.threats)
        );
        for t in report
            .threats
            .iter()
            .filter(|t| t.status == ThreatStatus::Found)
        {
            threats.items.push(Item::text(format!(
                "- found: {} {}: {} ({})\n",
                t.id,
                one_line(&t.element_name),
                one_line(&t.description),
                one_line(&t.found.join(", "))
            )));
        }
        for t in report
            .threats
            .iter()
            .filter(|t| t.status == ThreatStatus::NotVerified)
        {
            threats.items.push(Item::text(format!(
                "- not verified: {} {}: {}\n",
                t.id,
                one_line(&t.element_name),
                one_line(&t.description)
            )));
        }
    }

    let mut tests = Section::new(
        "tests",
        format!(
            "The tests to write ({}, the first {} listed)",
            report.tests_to_write.len(),
            report.tests_to_write.len().min(TESTS_SHOWN)
        ),
        &[],
    );
    if !report.tests_to_write.is_empty() {
        tests.lead = format!(
            "\nTESTS TO WRITE — {} applicable requirements have no evidence and no test naming \
             them. A test that really checks one, with its id in the test's name, is how it gets \
             evidence. Lowest level first:\n",
            report.tests_to_write.len()
        );
        for t in report.tests_to_write.iter().take(TESTS_SHOWN) {
            tests.items.push(Item::text(format!(
                "- {} (level {}): {}\n",
                t.id, t.level, t.description
            )));
        }
        if report.tests_to_write.len() > TESTS_SHOWN {
            tests.items.push(Item::text(format!(
                "- and {} more, in compliance.md\n",
                report.tests_to_write.len() - TESTS_SHOWN
            )));
        }
    }

    let mut findings = Section::new(
        "findings",
        format!(
            "The findings, each with its file, line, and fix ({})",
            report.findings.len()
        ),
        &["findings"],
    );
    if report.findings.is_empty() {
        findings.lead =
            "\nNo findings. That is not the same as secure: see what was not examined.\n"
                .to_owned();
    } else {
        let (app, in_tests) = sv_report::app_then_tests(report);
        findings.lead = format!("\n{} FINDINGS:\n", report.findings.len());
        if !in_tests.is_empty() {
            findings.lead.push_str(&format!(
                "({} in the app itself first, then {} {}. Those still count; fix a key or a copied \
                 pattern there as you would in the app, a library by a newer copy, not an edit, and \
                 read one only worth a look before changing anything.)\n",
                app.len(),
                in_tests.len(),
                sv_report::apart_named(&in_tests)
            ));
        }
        for f in app.into_iter().chain(in_tests) {
            let mut text = format!(
                "- [{}, {}] {} — {}{}\n  fix: {}\n",
                f.severity.name(),
                f.certainty(),
                one_line(&f.title),
                one_line(&format!("{}:{}", f.location.file, f.location.line)),
                if f.requirement_ids.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", f.requirement_ids.join(", "))
                },
                one_line(&f.fix)
            );
            // Said to the AI coding tool in so many words: it changes code until a warning stops, so
            // a finding `sv` is not sure of has to reach it as one to check first.
            if let Some(accepted) = sv_report::accepted_note(report, f) {
                text.push_str(&format!("  {}\n", one_line(&accepted)));
            }
            for note in sv_report::finding_notes(f).into_iter().filter(|n| {
                !n.starts_with("How sure: confirmed") && !n.starts_with("How sure: likely")
            }) {
                // `sv`'s own words about the finding, naming only its fingerprint and rule ids.
                text.push_str(&format!("  {}\n", sv_report::one_line(&note)));
            }
            findings.items.push(Item::with(text, "findings", json!(f)));
        }
    }

    let set_aside = sv_report::false_alarm_entries(report);
    let mut aside = Section::new(
        "set-aside",
        format!("Findings set aside as false alarms ({})", set_aside.len()),
        &[],
    );
    if !set_aside.is_empty() {
        aside.lead = format!(
            "\nSET ASIDE IN securevibe.toml through `sv review`, as false alarms, not counted above \
             ({}). Only the person can record these, by running `sv review` in their own terminal: \
             never run it for them, and never write a `seal` or a person's name in `by`. {}\n",
            set_aside.len(),
            sv_report::FALSE_ALARM_TOOL_NOTE
        );
        for (line, report_it) in &set_aside {
            aside.items.push(Item::text(format!(
                "- {}\n  report it against the rule: {}\n",
                one_line(line),
                one_line(report_it)
            )));
        }
    }

    let mut not_counted = Section::new(
        "not-counted",
        format!(
            "Reviews in securevibe.toml that were not counted ({})",
            report.reviews_not_counted.len()
        ),
        &[],
    );
    if !report.reviews_not_counted.is_empty() {
        not_counted.lead = "\nNOT COUNTED in [[finding-review]], so the findings they name still count. A proposal \
             of yours (by = \"ai-tool\") counts only once the owner has read the code and recorded \
             it through `sv review` in their own terminal; never run `sv review` for them, and never \
             write a `seal` or a person's name in `by`. An entry whose finding was not looked for \
             this time, or whose rule this version of `sv` does not have, is not a sign the finding \
             was fixed: never remove it or tell the owner the finding is gone. Each says which:\n"
            .to_owned();
        for line in &report.reviews_not_counted {
            not_counted
                .items
                .push(Item::text(format!("- {}\n", one_line(line))));
        }
    }

    let mut claims = Section::new(
        "claims",
        format!(
            "Every answer in securevibe.toml, with what the code showed ({})",
            report.claims.len()
        ),
        &["claims"],
    );
    for claim in &report.claims {
        claims
            .items
            .push(Item::with(String::new(), "claims", json!(claim)));
    }
    let mut undecided = Section::new(
        "undecided",
        format!(
            "The requirements not yet placed, each with the question that decides it ({})",
            report.undecided.len()
        ),
        &["undecided"],
    );
    for u in &report.undecided {
        undecided
            .items
            .push(Item::with(String::new(), "undecided", json!(u)));
    }
    vec![
        summary,
        gaps,
        questions,
        contradictions,
        threats,
        tests,
        findings,
        aside,
        not_counted,
        claims,
        undecided,
    ]
}

/// How many of the tests to write the check lists; the rest are in compliance.md.
pub(super) const TESTS_SHOWN: usize = 30;

/// The fields of the structured check every part of it carries (`crate::parts`).
pub(super) fn check_always(report: &sv_report::Report) -> serde_json::Map<String, Value> {
    let mut out = serde_json::Map::new();
    out.insert("app".to_owned(), json!(report.app_name));
    out.insert("targetLevel".to_owned(), json!(report.target_level));
    out.insert("counts".to_owned(), json!(report.counts));
    out
}

/// The same, as data, for a client that reads structured results.
pub(super) fn structured(report: &sv_report::Report) -> Value {
    json!({
        "app": report.app_name,
        "targetLevel": report.target_level,
        "counts": report.counts,
        "notExamined": report.gaps,
        "findings": report.findings,
        "needsAttention": report
            .requirements
            .iter()
            .filter(|l| l.status == sv_report::Status::NeedsAttention)
            .map(|l| &l.id)
            .collect::<Vec<_>>(),
        "claims": report.claims,
        "undecided": report.undecided,
    })
}
