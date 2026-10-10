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

pub(crate) const STYLE: &str = "\
:root { color-scheme: light dark; --edge: #d8d8d8; --dim: #666; --bad: #a11; --unknown: #8a6d00;
  --seg-checked: #127a74; --seg-part: #6fb3ac; --seg-tested: #4b4fb8; --seg-word: #d6b34a; --seg-none: #c9ced8;
  --seg-none-line: #aeb4c0; --seg-apply: #4a5262; --seg-out: #e4e7ec; --seg-ai: #a995cc; }
@media (prefers-color-scheme: dark) { :root { --edge: #333; --dim: #999; --bad: #f77; --unknown: #d9a900;
  --seg-checked: #3fb8ae; --seg-part: #2b7f78; --seg-tested: #9a9dff; --seg-word: #8a7124; --seg-none: #4a5260;
  --seg-none-line: #646c7a; --seg-apply: #b9c0cc; --seg-out: #2a2f38; --seg-ai: #6c5a8f; } }
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
.documented, .app-tested { color: var(--dim); font-style: italic; }
.attested, .stated, .by-hand { color: var(--unknown); font-style: italic; }
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
.glance { margin: .9rem 0; }
.glance p { margin: .2rem 0; }
.bar { display: flex; height: 1.4rem; border: 1px solid var(--edge); border-radius: 3px; overflow: hidden; }
.bar.thin { height: .8rem; }
.bar span { min-width: 2px; }
.key, .bluf ul.key { list-style: none; padding: 0; margin: .4rem 0 0; display: flex; flex-wrap: wrap; gap: .2rem 1.1rem; font-size: .9em; }
.key i { display: inline-block; width: .8rem; height: .8rem; border: 1px solid var(--edge); border-radius: 2px; margin-right: .35rem; vertical-align: -.05rem; }
.seg-needs-attention { background: var(--bad); }
.seg-checked { background: var(--seg-checked); }
.seg-checked-in-part { background: var(--seg-part); }
.seg-app-tested { background: var(--seg-tested); }
.seg-documented, .seg-attested, .seg-stated, .seg-by-hand { background: var(--seg-word); }
.seg-not-verified { background: repeating-linear-gradient(135deg, var(--seg-none) 0 6px, var(--seg-none-line) 6px 8px); }
.seg-apply { background: var(--seg-apply); }
.seg-not-apply { background: var(--seg-none); }
.seg-unplaced { background: repeating-linear-gradient(135deg, var(--seg-word) 0 6px, var(--seg-out) 6px 8px); }
.seg-above { background: var(--seg-out); }
.seg-ai { background: var(--seg-ai); }
";

/// The class a status is shown with, in the tables and the requirement lists alike.
fn status_class(status: Status) -> &'static str {
    match status {
        Status::NeedsAttention => "needs-attention",
        Status::Checked => "checked",
        Status::CheckedInPart => "checked-in-part",
        Status::AppTested => "app-tested",
        Status::Documented => "documented",
        Status::Attested => "attested",
        Status::Stated => "stated",
        Status::ByHand => "by-hand",
        Status::NotVerified => "not-verified",
    }
}

/// A status as a few words beside its color, for the bar's key.
fn short_label(status: Status) -> &'static str {
    match status {
        Status::NeedsAttention => "need attention",
        Status::Checked => "checked by an automated check",
        Status::CheckedInPart => "checked in part",
        Status::AppTested => "tested only by the app's own tests",
        Status::Documented => "answered in your security notes",
        Status::ByHand => "checked by you by hand",
        Status::Attested => "rest on your answer",
        Status::Stated => "rest on your AI coding tool's answer",
        Status::NotVerified => "not verified by anything",
    }
}

/// One bar, drawn to scale: each part's share of the bar is its count's share of the total,
/// because each part grows by its count. Parts with nothing in them are left out of the bar and
/// the key alike. The key under it gives every count in words, so the picture is never the only
/// place a number is.
fn bar(class: &str, aria: &str, parts: &[(&str, usize, String)]) -> String {
    let mut s = format!(
        "<div class=\"bar{class}\" role=\"img\" aria-label=\"{}\">",
        escape(aria)
    );
    for (seg, n, label) in parts.iter().filter(|(_, n, _)| *n > 0) {
        s.push_str(&format!(
            "<span class=\"seg-{seg}\" style=\"flex-grow: {n}\" title=\"{n} {}\"></span>",
            escape(label)
        ));
    }
    s.push_str("</div>\n<ul class=\"key\">");
    for (seg, n, label) in parts.iter().filter(|(_, n, _)| *n > 0) {
        s.push_str(&format!(
            "<li><i class=\"seg-{seg}\"></i><strong>{n}</strong> {}</li>",
            escape(label)
        ));
    }
    s.push_str("</ul>\n");
    s
}

/// The report at a glance: the requirements that apply, by what stands behind each, and apart
/// from them, where every requirement `sv` knows went, the ones that do not apply among them
/// (`docs/DASHBOARD.md`; ADR-057). No score and no percentage: two bars, to scale, with every
/// count written beside them. The two are kept apart so the requirements that do not apply are
/// never drawn in among the evidence for the ones that do.
pub fn glance(report: &Report) -> String {
    glance_of(&report.counts, report.target_level)
}

/// The same bars from the counts alone, as `sv dashboard` has them from a `report.json`.
pub fn glance_of(c: &crate::Counts, target_level: u8) -> String {
    let mut s = String::from("<div class=\"glance\">\n");
    if c.applicable > 0 {
        let parts: Vec<(&str, usize, String)> = c
            .by_status()
            .iter()
            .map(|&(status, n)| (status_class(status), n, short_label(status).to_owned()))
            .collect();
        let aria = parts
            .iter()
            .filter(|(_, n, _)| *n > 0)
            .map(|(_, n, label)| format!("{n} {label}"))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "<p><strong>The {} {} that apply, by what stands behind each</strong></p>\n",
            c.applicable,
            if c.applicable == 1 {
                "requirement"
            } else {
                "requirements"
            }
        ));
        s.push_str(&bar("", &aria, &parts));
    }
    let parts: Vec<(&str, usize, String)> = vec![
        ("apply", c.applicable, "apply to this app".to_owned()),
        (
            "not-apply",
            c.not_applicable,
            "do not apply to it, from what stackvet.toml says about the app".to_owned(),
        ),
        (
            "unplaced",
            c.not_assessed,
            "could not be placed: nobody has answered the question that decides".to_owned(),
        ),
        (
            "above",
            c.out_of_level,
            format!("are above ASVS level {target_level}"),
        ),
        (
            "ai",
            c.ai_process,
            "are about how the app is built with an AI coding tool, counted apart".to_owned(),
        ),
    ];
    let total: usize = parts.iter().map(|(_, n, _)| n).sum();
    if total > 0 {
        let aria = parts
            .iter()
            .filter(|(_, n, _)| *n > 0)
            .map(|(_, n, label)| format!("{n} {label}"))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "<p><strong>All {total} requirements, and where each went</strong></p>\n"
        ));
        s.push_str(&bar(" thin", &aria, &parts));
    }
    s.push_str("</div>\n");
    s
}

/// The content security policy both pages carry, as a `meta` tag, since a file opened from disk
/// has no server to send a header: nothing may load from anywhere (the pages fetch nothing),
/// no script may run (they have none), the one style is the inline one, and the page can neither
/// be framed into another nor submit a form. A browser that honors it would refuse a script or
/// an image that somebody edited into the saved file, which is what a report somebody hands on
/// invites (the review of 8 October 2026, item 6).
pub const CSP_META: &str = "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; \
                            style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">\n";

pub fn page(report: &Report) -> String {
    let c = &report.counts;
    let mut b = String::new();
    b.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    b.push_str(CSP_META);
    b.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    b.push_str(&format!(
        "<title>{} — sv report</title>\n",
        escape(&report.app_name)
    ));
    b.push_str(&format!("<style>{STYLE}</style>\n</head>\n<body>\n"));

    b.push_str(&format!("<h1>{}</h1>\n", escape(&report.app_name)));
    b.push_str(&format!(
        "<p class=\"note\">Produced by <code>sv</code> {}{}. ASVS level {}.</p>\n",
        escape(&report.sv.describe()),
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
    if let Some(line) = crate::baseline_line(report) {
        b.push_str(&format!("<p class=\"note\">{}</p>\n", escape(&line)));
    }
    if let Some(line) = crate::build_loop_line(report) {
        b.push_str(&format!("<p class=\"note\">{}</p>\n", escape(&line)));
    }
    if let Some(line) = crate::slowest_line(report) {
        b.push_str(&format!("<p class=\"note\">{}</p>\n", escape(&line)));
    }
    if let Some(line) = crate::advisories_line(report) {
        b.push_str(&format!("<p class=\"note\">{}</p>\n", escape(&line)));
    }
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
    b.push_str(&glance(report));
    b.push_str("<p>Of the requirements that apply to this app:</p>\n<ul class=\"tally\">\n");
    for (label, n) in crate::bluf::counted(report) {
        b.push_str(&format!(
            "<li><strong>{n}</strong> — {}</li>\n",
            escape(&label)
        ));
    }
    b.push_str("</ul>\n");
    b.push_str(&format!(
        "<p class=\"note\">{}</p>\n",
        escape(&crate::bluf::held_to(report))
    ));
    if let Some(line) = crate::bluf::not_run_line(report) {
        b.push_str(&format!("<p class=\"note\">{}</p>\n", escape(&line)));
    }
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
    if let Some(t) = &report.test_output {
        b.push_str(&format!(
            "<p>{}</p>\n",
            escape(&crate::test_output_intro(t))
        ));
        if !t.text.is_empty() {
            b.push_str(&format!("<pre>{}</pre>\n", escape(&t.text)));
        }
    }
    b.push_str(&format!(
        "<p class=\"lede\">{}</p>\n",
        crate::lede(c, "<strong>", "</strong>")
    ));
    if c.ai_process > 0 {
        b.push_str(&format!(
            "<p>A further {} about how the app is built with an AI coding tool, from OWASP AISVS \
             Appendix C, are counted apart: see <em>How the app is built with AI</em>, below.</p>\n",
            c.ai_process
        ));
    }
    b.push_str(
        "<p>Nothing in this report says a requirement passed, because nothing here can establish \
         that. <em>Checked</em> means an automated check looked at it and found nothing wrong, \
         which is worth having and is not the same as the requirement being met. One marked as \
         answered in the security notes, checked by hand, or answered yes rests on your word or \
         your AI coding tool's, which is shown as exactly that and never as checked. Everything \
         else that applies is <em>not verified</em>: nothing has produced evidence either \
         way.</p>\n",
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
    // Every status, so the rows add up to what applies: see `Counts::by_status`.
    for (status, n) in c.by_status() {
        b.push_str(&format!(
            "<tr><td class=\"{}\">{}</td><td class=\"n\">{n}</td></tr>\n",
            status_class(status),
            escape(status.applies_row())
        ));
    }
    for (label, n, class) in [
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

    let set_aside = crate::false_alarm_entries(report);
    if !set_aside.is_empty() || !report.reviews_not_counted.is_empty() {
        b.push_str("<h2>Set aside in stackvet.toml</h2>\n");
        if !set_aside.is_empty() {
            b.push_str(&format!(
                "<p>Found by a check, and set aside as a false alarm in stackvet.toml through \
                 <code>sv review</code>. {} They are not counted below, and a requirement one of them was about is never \
                 shown as checked because of it.</p>\n<ul>\n",
                escape(crate::SEALED_WHY)
            ));
            for (line, report_it) in &set_aside {
                b.push_str(&format!(
                    "<li>{} <a href=\"{}\">Report it against the rule</a></li>\n",
                    escape(line),
                    escape(report_it)
                ));
            }
            b.push_str(&format!(
                "</ul>\n<p>{}</p>\n",
                escape(crate::FALSE_ALARM_WHY)
            ));
        }
        if !report.reviews_not_counted.is_empty() {
            b.push_str(
                "<p>These entries in <code>[[finding-review]]</code> do not count, so the findings \
                 they name still do. Each says why. One whose finding was not looked for this time, \
                 or whose rule this version of <code>sv</code> does not have, is not a sign the \
                 finding was fixed. To record one as your decision, run <code>sv review</code> in \
                 your own terminal.</p>\n<ul>\n",
            );
            for line in &report.reviews_not_counted {
                b.push_str(&format!("<li>{}</li>\n", escape(line)));
            }
            b.push_str("</ul>\n");
        }
    }

    let (app, tests) = crate::app_then_tests(report);
    if !app.is_empty() {
        b.push_str(&format!(
            "<h2>{} thing{} to fix</h2>\n",
            app.len(),
            if app.len() == 1 { "" } else { "s" }
        ));
        for f in app {
            finding_section(&mut b, report, f);
        }
    }
    if !tests.is_empty() {
        b.push_str(&format!(
            "<h2>{} {}</h2>\n<p>{}</p>\n",
            tests.len(),
            crate::apart_named(&tests),
            escape(crate::TEST_CODE_SECTION)
        ));
        for f in tests {
            finding_section(&mut b, report, f);
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
            let class = status_class(line.status);
            let detail = match line.status {
                Status::NeedsAttention => format!(" ({})", line.findings.join(", ")),
                Status::Checked | Status::CheckedInPart => format!(
                    " ({})",
                    line.checked_by
                        .iter()
                        .map(|c| format!("{}: {}", c.check_id, c.scope))
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
                Status::AppTested => format!(
                    " \u{2014} written by your AI coding tool, not a check of sv's: {}",
                    line.tested_by
                        .iter()
                        .map(|c| c.scope.clone())
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
                Status::ByHand => format!(
                    " \u{2014} {}: {}",
                    line.whose_word(),
                    line.by_hand
                        .iter()
                        .map(|c| c.scope.clone())
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
                Status::Attested | Status::Stated => format!(
                    " \u{2014} {}, not a check: {}",
                    line.whose_word(),
                    line.attested_by
                        .iter()
                        .map(|c| c.scope.clone())
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
                Status::Documented => format!(
                    " \u{2014} {} {}",
                    if line.confirmed_only() {
                        "your AI coding tool wrote this, and a person confirmed it, in"
                    } else {
                        "you answered this in"
                    },
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
                escape(line.shown_label()),
                // Information-only findings sit beside the status, never in place of it.
                escape(&format!(
                    "{detail}{}{}",
                    line.credit_note(),
                    line.information_note()
                )),
                escape(&line.description)
            ));
        }
        b.push_str("</table>\n");
    }

    if !report.ai_process.lines.is_empty() {
        let p = &report.ai_process;
        b.push_str("<h2>How the app is built with AI (OWASP AISVS Appendix C)</h2>\n");
        b.push_str(&format!("<p>{}</p>\n", escape(&p.summary())));
        b.push_str(&format!(
            "<details>\n<summary>The {} requirements</summary>\n<table>\n\
             <tr><th>requirement</th><th>what happens to it</th><th>what it asks for</th></tr>\n",
            p.lines.len()
        ));
        for line in &p.lines {
            b.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td></tr>\n",
                escape(&line.id),
                escape(crate::AiProcess::route_text(line.route)),
                escape(&line.description)
            ));
        }
        b.push_str("</table>\n</details>\n");
    }

    if !report.threats.is_empty() {
        b.push_str("<h2>Threats</h2>\n");
        b.push_str(&format!("<p>{}</p>\n", escape(crate::threats::INTRO)));
        b.push_str("<p><strong>Parts of the app:</strong></p>\n<ul>\n");
        for p in &report.threat_parts {
            let known = match p.present {
                Some(true) => String::new(),
                _ => format!(
                    " <span class=\"note\">(not known: stackvet.toml does not answer {})</span>",
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
        if let Some(release) = &report.threat_atlas_release {
            let mapped: Vec<_> = report
                .threats
                .iter()
                .filter(|l| !l.atlas.is_empty())
                .collect();
            if !mapped.is_empty() {
                b.push_str("<h3>For a security reviewer: these threats in MITRE ATLAS</h3>\n");
                b.push_str(&format!(
                    "<p>{}</p>\n",
                    escape(&crate::threats::atlas_intro(release))
                ));
                b.push_str("<table>\n<tr><th>threat</th><th>MITRE ATLAS technique</th><th>what the two share</th></tr>\n");
                for line in mapped {
                    for r in &line.atlas {
                        b.push_str(&format!(
                            "<tr><td><code>{}</code></td><td><code>{}</code> {}</td><td>{}</td></tr>\n",
                            escape(&line.id),
                            escape(&r.id),
                            escape(&r.name),
                            escape(&r.because)
                        ));
                    }
                }
                b.push_str("</table>\n");
            }
        }
    }

    // High up, above the tests: nothing will ever settle these on its own.
    if !report.only_you_can_check.is_empty() {
        b.push_str("<h2>What only you can check</h2>\n");
        b.push_str(&format!(
            "<p>{}</p>\n",
            escape(&format!(
                "{} of the requirements that apply cannot be settled by any tool: they ask what your rules are, how the app is built, or what is true of it in production. Each one below says what doing something about it involves. None of them is counted as met — doing the thing is what would change that, not reading it here.",
                report.only_you_can_check.len()
            ))
        ));
        if report.no_instructions_yet > 0 {
            b.push_str(&format!(
                "<p class=\"note\">{}</p>\n",
                escape(&format!(
                    "A further {} are the Secure by Design and AISVS design-review controls, which are not listed one by one: those standards are checklists already, and repeating them here would be another wall of text.",
                    report.no_instructions_yet
                ))
            ));
        }
        b.push_str("<table>\n<tr><th>requirement</th><th>what to do</th><th>how</th></tr>\n");
        for item in &report.only_you_can_check {
            b.push_str(&format!(
                "<tr><td><code>{}</code> {}</td><td>{}</td><td>{}</td></tr>\n",
                escape(&item.id),
                escape(&item.title),
                escape(item.route.what_to_do()),
                match &item.where_to_look {
                    Some(w) => format!(
                        "{}<br><span class=\"note\"><strong>Where to look:</strong> {}</span>",
                        escape(&item.how),
                        escape(w)
                    ),
                    None => escape(&item.how),
                }
            ));
        }
        b.push_str("</table>\n");
    }

    // What only the live site can answer, for an app that will be on the internet (`crate::live`).
    if !report.before_going_live.is_empty() {
        b.push_str("<h2>Before going live</h2>\n");
        b.push_str(&format!("<p>{}</p>\n", escape("These can be answered only by the app's own live site, so nothing in this report has checked them, and none is counted as met. Once the app is on the internet at its own address, run sv probe against it: it makes a handful of read-only requests to that address and nothing else, sends no cookies or credentials, and cannot change anything. It prints its answers where it runs; they are not added to this report.")));
        b.push_str("<table>\n<tr><th>requirement</th><th>what it asks</th><th>how</th></tr>\n");
        for item in &report.before_going_live {
            let how = match (&item.command, &item.by_hand) {
                (Some(command), _) => format!("<code>{}</code> asks this.", escape(command)),
                (None, Some(by_hand)) => escape(by_hand),
                (None, None) => String::new(),
            };
            b.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td></tr>\n",
                escape(&item.id),
                escape(&item.what),
                how
            ));
        }
        b.push_str("</table>\n");
    }

    // The AI coding tool's own files (ADR-049): apart from the app's grade, and graded by nothing.
    if !report.ai_tool.notes.is_empty() || !report.ai_tool.not_read.is_empty() {
        b.push_str("<h2>What your AI coding tool's files let it do</h2>\n");
        b.push_str(&format!("<p>{}</p>\n", escape("These files in the project folder belong to the AI coding tool you build with, not to the app, so nothing here counts toward the app's grade or any requirement. Each line is something a file lets the tool do on the computer that opens this folder: run a command, send its work or its key somewhere, act without asking, or start a server. You may have set it up on purpose. If you did not, or do not know where it came from, look before you trust the folder. Claude Code asks before it uses a folder's own settings for the first time. The risk column names the OWASP Agentic Skills Top 10 risk it speaks to; that list is not one this report is graded against.")));
        if !report.ai_tool.notes.is_empty() {
            b.push_str(
                "<table>\n<tr><th>file</th><th>tool</th><th>what it lets the tool do</th><th>risk</th></tr>\n",
            );
            for note in &report.ai_tool.notes {
                b.push_str(&format!(
                    "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    escape(&note.file),
                    escape(&note.tool),
                    escape(&note.what),
                    escape(note.risk)
                ));
            }
            b.push_str("</table>\n");
        }
        if !report.ai_tool.not_read.is_empty() {
            b.push_str(&format!(
                "<p>Not read: {}.</p>\n",
                escape(&report.ai_tool.not_read.join("; "))
            ));
        }
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
        // Closed here, where it was opened: closed after the next section, the collapsed list held
        // that section too, and a report with nothing undecided had a `</details>` and no
        // `<details>` (the deep review's improvement 6).
        b.push_str("</details>\n");
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
        b.push_str("</details>\n");
    }

    b.push_str("</body>\n</html>\n");
    b
}

fn finding_section(b: &mut String, report: &Report, f: &sv_check::Finding) {
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
    if let Some(accepted) = crate::accepted_note(report, f) {
        b.push_str(&format!("<p><strong>{}</strong></p>\n", escape(&accepted)));
    }
    if let Some(held) = crate::baseline_note(report, f) {
        b.push_str(&format!(
            "<p class=\"note\"><em>{}</em></p>\n",
            escape(&held)
        ));
    }
    for note in crate::finding_notes(f) {
        b.push_str(&format!("<p class=\"note\">{}</p>\n", escape(&note)));
    }
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

    /// Every `flex-grow` in the bars of `html`, in order: the first bar's, then the second's.
    fn grows(html: &str) -> Vec<Vec<usize>> {
        html.split("<div class=\"bar")
            .skip(1)
            .map(|bar| {
                bar.split("</div>")
                    .next()
                    .unwrap()
                    .split("flex-grow: ")
                    .skip(1)
                    .map(|n| n.split('"').next().unwrap().parse().unwrap())
                    .collect()
            })
            .collect()
    }

    fn counted(f: impl FnOnce(&mut crate::Counts)) -> Report {
        let mut r = report(false, false, false);
        f(&mut r.counts);
        r
    }

    #[test]
    fn each_bar_is_drawn_to_scale_from_the_counts_written_beside_it() {
        // Clinic booking's plain run of 8 October 2026, and a run with every status in it.
        let clinic = counted(|c| {
            c.applicable = 240;
            c.checked = 10;
            c.not_verified = 230;
            c.not_applicable = 179;
            c.not_assessed = 24;
            c.out_of_level = 153;
            c.ai_process = 44;
        });
        let all = counted(|c| {
            (
                c.needs_attention,
                c.checked,
                c.checked_in_part,
                c.app_tested,
            ) = (1, 2, 3, 4);
            (
                c.documented,
                c.by_hand,
                c.attested,
                c.stated,
                c.not_verified,
            ) = (5, 6, 7, 8, 9);
            c.applicable = 45;
            c.not_applicable = 2;
        });
        for (r, first, second) in [
            (&clinic, vec![10, 230], vec![240, 179, 24, 153, 44]),
            (&all, (1..=9).collect(), vec![45, 2]),
        ] {
            let html = glance(r);
            let bars = grows(&html);
            assert_eq!(bars, vec![first.clone(), second.clone()], "{html}");
            // Each bar's parts add up to what it says it shows, and every count is in words too.
            assert_eq!(first.iter().sum::<usize>(), r.counts.applicable);
            for n in first.iter().chain(&second) {
                assert!(
                    html.contains(&format!("<strong>{n}</strong>")),
                    "{n}: {html}"
                );
            }
            assert!(html.contains(&format!(
                "All {} requirements",
                second.iter().sum::<usize>()
            )));
        }
        let html = glance(&clinic);
        assert!(html.contains("The 240 requirements that apply"), "{html}");
        assert!(
            html.contains("<strong>179</strong> do not apply to it"),
            "the owner asked to see how many do not apply: {html}"
        );
    }

    #[test]
    fn what_is_not_verified_is_drawn_as_exactly_that() {
        let r = counted(|c| {
            c.applicable = 12;
            c.needs_attention = 1;
            c.checked = 3;
            c.not_verified = 8;
        });
        let html = glance(&r);
        let first = html.split("<div class=\"bar thin").next().unwrap();
        assert!(
            first.contains("<span class=\"seg-not-verified\" style=\"flex-grow: 8\" title=\"8 not verified by anything\">"),
            "{first}"
        );
        assert!(
            first.contains("class=\"seg-checked\" style=\"flex-grow: 3\""),
            "{first}"
        );
        // Its color is its own: not the color of anything that was checked or answered.
        let rule = STYLE
            .lines()
            .find(|l| l.starts_with(".seg-not-verified"))
            .unwrap();
        for other in [
            "--seg-checked",
            "--seg-part",
            "--seg-tested",
            "--seg-word",
            "--bad",
        ] {
            assert!(!rule.contains(other), "{rule}");
        }
    }

    #[test]
    fn the_bars_say_nothing_that_reads_as_a_verdict_or_a_score() {
        let r = counted(|c| {
            c.applicable = 3;
            c.checked = 3;
            c.not_applicable = 1;
        });
        let html = glance(&r).to_lowercase();
        // Whole words, as the short version's own test reads them: `stackvet.toml` is a name.
        let words: Vec<&str> = html.split(|ch: char| !ch.is_alphanumeric()).collect();
        for word in [
            "pass",
            "passed",
            "secure",
            "secured",
            "compliant",
            "safe",
            "score",
            "grade",
        ] {
            assert!(!words.contains(&word), "{word}: {html}");
        }
        for text in ["%", "<script", "http"] {
            assert!(!html.contains(text), "{text}: {html}");
        }
        // Nothing applies, nothing counted: no bar with nothing in it, and no part of size zero.
        let none = glance(&counted(|c| c.not_applicable = 5));
        assert!(!none.contains("that apply, by what stands"), "{none}");
        assert!(!none.contains("flex-grow: 0"), "{none}");
        assert!(
            glance(&report(false, false, false))
                .matches("class=\"bar")
                .count()
                == 0
        );
    }

    #[test]
    fn the_bars_open_the_short_version_before_its_tally() {
        let r = counted(|c| {
            c.applicable = 2;
            c.not_verified = 2;
        });
        let page = page(&r);
        let bars = page.find("class=\"glance\"").expect("no bars on the page");
        let tally = page.find("Of the requirements that apply").unwrap();
        let bluf = page.find("class=\"bluf\"").unwrap();
        assert!(bluf < bars && bars < tally);
    }

    fn report(undecided: bool, elsewhere: bool, excluded: bool) -> Report {
        Report {
            level_why: None,
            baseline: None,
            build_loop: None,
            seen: None,
            timings: Vec::new(),
            app_name: "test".into(),
            target_level: 1,
            generated: None,
            sv: Default::default(),
            run_record: None,
            manifest_file: crate::default_manifest_file(),
            run_note: None,
            run_steps: Vec::new(),
            test_output: None,
            run_status: None,
            ai_process: Default::default(),
            counts: crate::Counts::default(),
            requirements: vec![],
            excluded: if excluded {
                vec![crate::ExcludedRequirement {
                    id: "V1.1.1".into(),
                    description: "d".into(),
                    chapter: "V1".into(),
                    reason: "r".into(),
                    condition: "c".into(),
                    rests_on: "claim",
                }]
            } else {
                vec![]
            },
            undecided: if undecided {
                vec![crate::UndecidedRequirement {
                    id: "V2.1.1".into(),
                    description: "d".into(),
                    chapter: "V2".into(),
                    blocked_on: vec!["q".into()],
                }]
            } else {
                vec![]
            },
            claims: vec![],
            findings: vec![],
            set_aside: Vec::new(),
            reviews_not_counted: Vec::new(),
            out_of_scope: vec![],
            checklist_above_level: vec![],
            tests_to_write: vec![],
            only_you_can_check: Vec::new(),
            before_going_live: Vec::new(),
            ai_tool: Default::default(),
            questions_for_you: Vec::new(),
            no_instructions_yet: 0,
            named_not_credited: vec![],
            not_for_tests: 0,
            threats: Vec::new(),
            threat_parts: Vec::new(),
            threat_atlas_release: None,
            satisfied_elsewhere: if elsewhere {
                vec![crate::SatisfiedElsewhere {
                    check_id: "c".into(),
                    scope: "s".into(),
                    why: "w".into(),
                }]
            } else {
                vec![]
            },
            gaps: vec![],
            examined: Vec::new(),
            could_not_run: Vec::new(),
            partly_read: Vec::new(),
            not_run_this_time: None,
        }
    }

    #[test]
    fn every_collapsed_list_is_closed_where_it_was_opened() {
        // The deep review's improvement 6: a report with nothing undecided, or nothing excluded,
        // had a `</details>` with no `<details>`, and the undecided list held the next section too.
        for undecided in [false, true] {
            for elsewhere in [false, true] {
                for excluded in [false, true] {
                    let page = page(&report(undecided, elsewhere, excluded));
                    let case = format!(
                        "undecided {undecided}, elsewhere {elsewhere}, excluded {excluded}"
                    );
                    // Every close follows an open, and the counts agree.
                    let mut open = 0i32;
                    for (i, _) in page.match_indices("details") {
                        if page[..i].ends_with("</") {
                            open -= 1;
                        } else if page[..i].ends_with('<') {
                            open += 1;
                        }
                        assert!((0..=1).contains(&open), "{case}: {page}");
                    }
                    assert_eq!(open, 0, "{case}");
                    // The section of checks found clean elsewhere is never inside a collapsed list.
                    if let Some(at) = page.find("Checks that ran and found nothing") {
                        let before = &page[..at];
                        assert_eq!(
                            before.matches("<details").count(),
                            before.matches("</details>").count(),
                            "{case}: the section is inside a collapsed list"
                        );
                    }
                }
            }
        }
    }
}
