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
.note { color: var(--dim); }
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

    b.push_str("<h2>Read this first</h2>\n");
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
        "<tr><td>Above ASVS level {}</td><td class=\"n\">{}</td></tr>\n</table>\n",
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

    b.push_str("<h2>Requirements that apply</h2>\n");
    b.push_str("<table>\n<tr><th>requirement</th><th>status</th><th>what it asks for</th></tr>\n");
    for line in &report.requirements {
        let class = match line.status {
            Status::NeedsAttention => "needs-attention",
            Status::Checked => "checked",
            Status::NotVerified => "not-verified",
        };
        let detail = match line.status {
            Status::NeedsAttention => format!(" ({})", line.findings.join(", ")),
            Status::Checked => format!(
                " ({})",
                line.checked_by
                    .iter()
                    .map(|c| format!("{} over {}", c.check_id, c.scope))
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

    if !report.undecided.is_empty() {
        b.push_str("<h2>Requirements nobody has placed</h2>\n");
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
                escape(line.landed_in)
            ));
        }
        b.push_str("</table>\n");
    }

    if !report.excluded.is_empty() {
        b.push_str("<h2>Requirements that do not apply, and why</h2>\n");
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
