//! The same report as one HTML file that opens in a browser by double-clicking it.
//!
//! One file, no links out, no scripts, no fonts fetched from anywhere: a report that needs the
//! internet to render is a report that stops working the day it matters, and a security report that
//! makes requests when opened is its own small joke.

use crate::{Report, Status};

/// Escapes text for HTML body and attribute contexts.
///
/// `&` first, for the same reason the Markdown escaper does backslashes first: replacing it later
/// would go back over the `&` in `&lt;` and produce `&amp;lt;`.
pub fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

const STYLE: &str = "\
:root { color-scheme: light dark; --edge: #d8d8d8; --dim: #666; --bad: #a11; --unknown: #8a6d00; }
@media (prefers-color-scheme: dark) { :root { --edge: #333; --dim: #999; --bad: #f77; --unknown: #d9a900; } }
body { font: 16px/1.6 system-ui, sans-serif; margin: 0 auto; max-width: 62rem; padding: 2rem 1rem; }
h1 { font-size: 1.7rem; margin-bottom: .2rem; }
h2 { font-size: 1.25rem; margin-top: 2.4rem; border-bottom: 1px solid var(--edge); padding-bottom: .3rem; }
h3 { font-size: 1.05rem; margin-top: 1.8rem; }
p.lede { font-size: 1.05rem; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { border: 1px solid var(--edge); padding: .45rem .6rem; text-align: left; vertical-align: top; }
th { font-weight: 600; }
td.n { text-align: right; width: 6rem; }
.needs-attention { color: var(--bad); font-weight: 600; }
.not-verified { color: var(--unknown); }
.checked { color: var(--dim); }
.documented { color: var(--dim); font-style: italic; }
.attested { color: var(--unknown); font-style: italic; }
.note { color: var(--dim); }
.bluf { border: 1px solid var(--edge); border-left: 4px solid var(--bad); border-radius: 6px; padding: 1rem 1.2rem; margin: 1.5rem 0 2rem; }
.bluf p.headline { font-size: 1.15rem; font-weight: 600; margin-top: 0; }
.bluf ul, .bluf ol { margin: .4rem 0; padding-left: 1.3rem; }
.bluf ul.tally li { margin: .15rem 0; }
.bluf ol.next li { margin: .35rem 0; }
.bluf ol.next .note { display: block; font-size: .9em; }
.bluf h3 { font-size: 1rem; margin: 1.1rem 0 .3rem; }
.sev { font-size: .8em; text-transform: uppercase; letter-spacing: .04em; padding: .05rem .35rem; border: 1px solid currentColor; border-radius: 3px; }
.sev-critical, .sev-high { color: var(--bad); }
.sev-medium { color: var(--unknown); }
.sev-low, .sev-info { color: var(--dim); }
details > summary { cursor: pointer; color: var(--dim); }
details.bulk { margin-top: 2.4rem; border-top: 1px solid var(--edge); padding-top: .8rem; }
details.bulk > summary strong { color: inherit; }
code { font-family: ui-monospace, monospace; font-size: .9em; }
";

pub fn page(report: &Report) -> String {
    let c = &report.counts;
    let mut b = String::new();
    b.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    b.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    b.push_str(&format!(
        "<title>{} — sv report</title>\n",
        escape(&report.app_name)
    ));
    b.push_str(&format!("<style>{STYLE}</style>\n</head>\n<body>\n"));

    b.push_str(&format!("<h1>{}</h1>\n", escape(&report.app_name)));
    b.push_str(&format!(
        "<p class=\"note\">Produced by <code>sv</code>{}. ASVS level {}.</p>\n",
        report
            .generated
            .as_ref()
            .map(|w| format!(" on {}", escape(w)))
            .unwrap_or_default(),
        report.target_level
    ));

    // The short version, before any of the explaining. See `crate::bluf`.
    b.push_str("<section class=\"bluf\">\n");
    b.push_str(&format!(
        "<p class=\"headline\">{}</p>\n",
        escape(&crate::bluf::headline(report))
    ));
    let (worst, rest) = crate::bluf::worst_findings(report);
    if !worst.is_empty() {
        b.push_str("<ul class=\"worst\">\n");
        for f in worst {
            b.push_str(&format!(
                "<li><strong>{}</strong> <span class=\"sev sev-{}\">{}</span> \
                 <code>{}</code></li>\n",
                escape(&f.title),
                escape(f.severity.name()),
                escape(f.severity.name()),
                escape(&f.rule_id)
            ));
        }
        if rest > 0 {
            b.push_str(&format!(
                "<li class=\"note\">… and {rest} more, in security.md, worst first</li>\n"
            ));
        }
        b.push_str("</ul>\n");
    }
    b.push_str("<p>Of the requirements that apply to this app:</p>\n<ul class=\"tally\">\n");
    for (label, n) in crate::bluf::counted(report) {
        b.push_str(&format!(
            "<li><strong>{n}</strong> — {}</li>\n",
            escape(&label)
        ));
    }
    b.push_str("</ul>\n");
    let steps = crate::bluf::next_steps(report);
    if !steps.is_empty() {
        b.push_str("<h3>What to do next</h3>\n<ol class=\"next\">\n");
        for step in &steps {
            b.push_str(&format!(
                "<li>{} <span class=\"note\">{}</span></li>\n",
                escape(&step.what),
                escape(&step.where_to_look)
            ));
        }
        b.push_str("</ol>\n");
    }
    b.push_str("</section>\n");

    b.push_str("<h2>Read this first</h2>\n");
    if let Some(note) = &report.run_note {
        b.push_str(&format!("<p>{}</p>\n", escape(note)));
    }
    if !report.run_steps.is_empty() {
        b.push_str(&format!(
            "<details>\n<summary>The {} things it did while the app ran</summary>\n<ol>\n",
            report.run_steps.len()
        ));
        for step in &report.run_steps {
            b.push_str(&format!("<li>{}</li>\n", escape(step)));
        }
        b.push_str("</ol>\n</details>\n");
    }
    b.push_str(&format!(
        "<p class=\"lede\">{} requirements apply to this app. \
         <strong>{} have been looked at by something</strong> and <strong>{} have not</strong>.</p>\n",
        c.applicable,
        c.needs_attention + c.checked,
        c.not_verified
    ));
    b.push_str(
        "<p>Nothing in this report says a requirement passed, because nothing here can establish \
         that. <em>Checked</em> means an automated check looked at it and found nothing wrong, \
         which is worth having and is not the same as the requirement being met. Everything else \
         that applies is <em>not verified</em>: nothing has produced evidence either way.</p>\n",
    );
    if c.not_assessed > 0 {
        b.push_str(&format!(
            "<p>A further <strong>{} requirements could not be placed at all</strong>, because \
             nobody has answered the question that decides whether they apply. They are neither \
             exclusions nor passes.</p>\n",
            c.not_assessed
        ));
    }

    b.push_str("<table>\n<tr><th>&nbsp;</th><th class=\"n\">count</th></tr>\n");
    for (label, n, class) in [
        (
            "Applies, needs attention",
            c.needs_attention,
            "needs-attention",
        ),
        (
            "Applies, checked by an automated check",
            c.checked,
            "checked",
        ),
        (
            "Applies, you answered it in the security notes",
            c.documented,
            "documented",
        ),
        (
            "Applies, not verified by anything",
            c.not_verified,
            "not-verified",
        ),
        ("Does not apply", c.not_applicable, ""),
        (
            "Not assessed — nobody has answered",
            c.not_assessed,
            "not-verified",
        ),
    ] {
        b.push_str(&format!(
            "<tr><td class=\"{class}\">{label}</td><td class=\"n\">{n}</td></tr>\n"
        ));
    }
    b.push_str(&format!(
        "<tr><td>Above this app's target level (ASVS level {})</td><td class=\"n\">{}</td></tr>\n</table>\n",
        report.target_level, c.out_of_level
    ));

    if !report.gaps.is_empty() {
        b.push_str("<h2>What was not examined</h2>\n");
        b.push_str("<p>Each of these is a limit on what the rest of this report can mean.</p>\n");
        b.push_str("<table>\n<tr><th>not examined</th><th>why</th></tr>\n");
        for gap in &report.gaps {
            b.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>\n",
                escape(&gap.what),
                escape(&gap.why)
            ));
        }
        b.push_str("</table>\n");
    }

    if !report.findings.is_empty() {
        b.push_str(&format!(
            "<h2>{} things to fix</h2>\n",
            report.findings.len()
        ));
        for f in &report.findings {
            b.push_str(&format!(
                "<h3 class=\"needs-attention\">[{}] {}</h3>\n",
                escape(f.severity.name()),
                escape(&f.title)
            ));
            b.push_str(&format!(
                "<p class=\"note\"><code>{}</code> line {}</p>\n",
                escape(&f.location.file),
                f.location.line
            ));
            b.push_str(&format!("<p>{}</p>\n", escape(&f.description)));
            b.push_str(&format!(
                "<p><strong>Why it matters.</strong> {}</p>\n",
                escape(&f.impact)
            ));
            b.push_str(&format!(
                "<p><strong>What to do.</strong> {}</p>\n",
                escape(&f.fix)
            ));
            if !f.requirement_ids.is_empty() {
                b.push_str(&format!(
                    "<p class=\"note\">Evidence about: {}</p>\n",
                    escape(&f.requirement_ids.join(", "))
                ));
            }
        }
    }

    // Split by level, level 1 first. See `crate::groups`.
    b.push_str("<h2>Requirements that apply</h2>\n");
    for group in crate::groups::by_level(&report.requirements) {
        b.push_str(&format!(
            "<h3>{} <span class=\"note\">— {} of them</span></h3>\n",
            escape(&group.heading),
            group.lines.len()
        ));
        b.push_str(
            "<table>\n<tr><th>requirement</th><th>status</th><th>what it asks for</th></tr>\n",
        );
        for line in group.lines {
            let class = match line.status {
                Status::NeedsAttention => "needs-attention",
                Status::Checked => "checked",
                Status::Documented => "documented",
                Status::Attested => "attested",
                Status::NotVerified => "not-verified",
            };
            let detail = match line.status {
                Status::NeedsAttention => format!(" ({})", line.findings.join(", ")),
                Status::Checked => format!(
                    " ({})",
                    line.checked_by
                        .iter()
                        .map(|c| format!("{}: {}", c.check_id, c.scope))
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
                Status::Attested => format!(
                    " \u{2014} your word, not a check: {}",
                    line.attested_by
                        .iter()
                        .map(|c| c.scope.clone())
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
                Status::Documented => format!(
                    " \u{2014} you answered this in {}",
                    line.documented_by
                        .iter()
                        .map(|c| c.scope.clone())
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
                Status::NotVerified if !line.supported_by.is_empty() => format!(
                    " \u{2014} a person has to answer it; supporting: {}",
                    line.supported_by
                        .iter()
                        .map(|c| format!("{}: {}", c.check_id, c.scope))
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
                Status::NotVerified => String::new(),
            };
            b.push_str(&format!(
                "<tr><td><code>{}</code></td><td class=\"{class}\">{}{}</td><td>{}</td></tr>\n",
                escape(&line.id),
                escape(line.status.label()),
                escape(&detail),
                escape(&line.description)
            ));
        }
        b.push_str("</table>\n");
    }

    if !report.threats.is_empty() {
        b.push_str("<h2>Threats</h2>\n");
        b.push_str(&format!("<p>{}</p>\n", escape(crate::threats::INTRO)));
        b.push_str("<p><strong>Parts of the app:</strong></p>\n<ul>\n");
        for p in &report.threat_parts {
            let known = match p.present {
                Some(true) => String::new(),
                _ => format!(
                    " <span class=\"note\">(not known: securevibe.toml does not answer {})</span>",
                    escape(&p.unanswered.join(", "))
                ),
            };
            b.push_str(&format!(
                "<li><strong>{}</strong>: {}{known}</li>\n",
                escape(&p.name),
                escape(&p.description)
            ));
        }
        b.push_str("</ul>\n");
        b.push_str(&format!(
            "<p>{}</p>\n",
            escape(&crate::threats::count_line(&report.threats))
        ));
        b.push_str("<table>\n<tr><th>threat</th><th>status</th><th>part of the app</th><th>what could happen</th><th>the requirements that answer it</th></tr>\n");
        for line in &report.threats {
            let class = match line.status {
                crate::threats::ThreatStatus::Found => "needs-attention",
                crate::threats::ThreatStatus::CheckedInPart => "checked",
                _ => "not-verified",
            };
            b.push_str(&format!(
                "<tr><td><code>{}</code> {}</td><td class=\"{class}\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                escape(&line.id),
                escape(crate::threats::stride_words(&line.stride)),
                escape(line.status.label()),
                escape(&line.element_name),
                escape(&line.description),
                escape(&crate::threats::evidence_words(line))
            ));
        }
        b.push_str("</table>\n");
    }

    // Level 1 only; see the note in the Markdown renderer. `sv mcp` gives the AI coding tool the
    // whole list, and report.json carries it.
    let level_one: Vec<&crate::TestToWrite> = report
        .tests_to_write
        .iter()
        .filter(|t| t.level == 1)
        .collect();
    let deeper = report.tests_to_write.len() - level_one.len();
    if !level_one.is_empty() || !report.named_not_credited.is_empty() {
        b.push_str("<h2>Tests worth writing first</h2>\n");
        b.push_str(&format!("<p>{}</p>\n", escape("Nothing produced evidence about these, and no test in the app names them. A test that names a requirement's id and passes is the one way to give evidence about any requirement, including the ones no check here can reach. These are the level 1 ones. Name only what a test really checks: nothing here can tell whether it does.")));
        if deeper > 0 {
            b.push_str(&format!(
                "<p class=\"note\">{}</p>\n",
                escape(&format!("{deeper} more are at level 2 and above. They are not listed here, because a list that long is not something a person works through; `sv mcp` gives the whole list to your AI coding tool, and report.json carries it under tests_to_write."))
            ));
        }
        if report.not_for_tests > 0 {
            b.push_str(&format!(
                "<p class=\"note\">{}</p>\n",
                escape(&format!("{} more have no evidence and are not listed at all, because an application's own tests cannot show them: they ask for documentation, a deployment setting, a development process, or a design decision, and a person answers them.", report.not_for_tests))
            ));
        }
        if !report.named_not_credited.is_empty() {
            b.push_str(&format!(
                "<p class=\"note\">{}</p>\n",
                escape(&format!(
                    "Named in a test and still without evidence, because the tests were not run here or did not pass: {}.",
                    report.named_not_credited.join(", ")
                ))
            ));
        }
        if !level_one.is_empty() {
            b.push_str("<table>\n<tr><th>requirement</th><th>what it asks for</th></tr>\n");
            for t in &level_one {
                b.push_str(&format!(
                    "<tr><td><code>{}</code></td><td>{}</td></tr>\n",
                    escape(&t.id),
                    escape(&t.description)
                ));
            }
            b.push_str("</table>\n");
        }
    }

    if !report.undecided.is_empty() {
        b.push_str("<details class=\"bulk\">\n<summary><strong>Requirements nobody has placed</strong> — each names the question that would place it</summary>\n");
        b.push_str(
            "<p>These are not exclusions. Answering the question moves each one into \
             <em>applies</em> or <em>does not apply</em>.</p>\n",
        );
        b.push_str("<table>\n<tr><th>requirement</th><th>what has to be answered</th></tr>\n");
        for un in &report.undecided {
            b.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td></tr>\n",
                escape(&un.id),
                escape(&un.blocked_on.join(" — or — "))
            ));
        }
        b.push_str("</table>\n");
    }

    if !report.satisfied_elsewhere.is_empty() {
        b.push_str(
            "<h2>Checks that ran and found nothing, against nothing in the tables above</h2>\n",
        );
        b.push_str(
            "<p>These were satisfied. They appear here rather than beside a requirement because \
             what they look at is not something this app is being assessed on.</p>\n",
        );
        b.push_str(
            "<table>\n<tr><th>check</th><th>what it covered</th><th>why it is here</th></tr>\n",
        );
        for line in &report.satisfied_elsewhere {
            b.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td></tr>\n",
                escape(&line.check_id),
                escape(&line.scope),
                escape(&line.why)
            ));
        }
        b.push_str("</table>\n");
    }

    b.push_str("</details>\n");

    if !report.out_of_scope.is_empty() {
        b.push_str("<h2>Findings about requirements this app is not being assessed against</h2>\n");
        b.push_str(
            "<p>Something was found and named a requirement that is not in the list above. Either \
             that requirement was excluded when it should not have been, or the check is citing a \
             requirement that has nothing to do with it.</p>\n",
        );
        b.push_str("<table>\n<tr><th>found by</th><th>about</th><th>where it ended up</th></tr>\n");
        for line in &report.out_of_scope {
            b.push_str(&format!(
                "<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>\n",
                escape(&line.rule_id),
                escape(&line.requirement_id),
                escape(&line.landed_in)
            ));
        }
        b.push_str("</table>\n");
    }

    if !report.checklist_above_level.is_empty() {
        b.push_str("<h2>Secure by Design controls above this app's target level</h2>\n");
        b.push_str(
            "<p>The checklist has no levels of its own. Each control takes the level of the ASVS \
             requirement that asks the same thing, or is shown at every level when none does; a few \
             keep the level <code>sv</code> derived from the checklist's severity, which is lower.</p>\n\
             <table>\n<tr><th>control</th><th>where its level came from</th><th>what it asks for</th></tr>\n",
        );
        for line in &report.checklist_above_level {
            b.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td></tr>\n",
                escape(&line.id),
                escape(&line.basis),
                escape(&line.description)
            ));
        }
        b.push_str("</table>\n");
    }

    if !report.excluded.is_empty() {
        b.push_str("<details class=\"bulk\">\n<summary><strong>Requirements that do not apply, and why</strong> — reference: why each was ruled out</summary>\n");
        b.push_str(
            "<p>An exclusion resting on the manifest's word is weaker than one resting on what the \
             code contains.</p>\n",
        );
        b.push_str("<table>\n<tr><th>requirement</th><th>why not</th><th>rests on</th></tr>\n");
        for ex in &report.excluded {
            b.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{} ({})</td></tr>\n",
                escape(&ex.id),
                escape(&ex.reason),
                escape(ex.rests_on),
                escape(&ex.condition)
            ));
        }
        b.push_str("</table>\n");
    }

    b.push_str("</details>\n");

    b.push_str("</body>\n</html>\n");
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn angle_brackets_and_quotes_cannot_escape_a_cell() {
        assert_eq!(
            escape("<script>alert(\"x\")</script>"),
            "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"
        );
    }

    #[test]
    fn the_ampersand_is_escaped_first() {
        // Doing `&` last would go back over the `&` it had just written and give `&amp;lt;`, which
        // renders as the literal text `&lt;` — the escaping visibly leaking into the page.
        assert_eq!(escape("<"), "&lt;");
        assert_eq!(escape("&lt;"), "&amp;lt;");
        assert!(!escape("&<").contains("&amp;amp;"));
    }
}
