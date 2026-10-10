# Gap item 11, cross-site scripting sinks: a code rule for HTML built from a value and put on the page unescaped

**Status:** done, 8 October 2026, by its own note carried from main
From "From the gap analysis of 7 October 2026", item 11 (`docs/GAP-ANALYSIS.md`, 3.3), whose other
parts were claimed and built by session securevibe-e9; this part was not. **Claimed on 8 October 2026 by session
securevibe-e2**, at the owner's word ("continue the backlog please"), in branch `claude/securevibe-e2-xss-sinks`:
`ast.html-from-value`, citing V1.2.1 and only ever a finding, for React's `dangerouslySetInnerHTML` given anything
but fixed text; `innerHTML`, `outerHTML`, `insertAdjacentHTML`, and `document.write` given a value; Python's
`Markup(...)` and Django's `mark_safe(...)` given a value; and Express's `res.send` of HTML
pieced together from a value. Finding-only, crediting nothing, so no decision record is proposed. Read on `main`
just before this claim: no other session had claimed it.
**Done the same day** (`docs/design/0302-a-value-put-on-the-page-as-html-without-escaping-8-october.md`): the rule,
also taught Go's `template.HTML(…)` and Ruby's `raw` and `html_safe`, with two new rule fields:
`safeArgumentPiecesRead` (an argument judged piece by piece, so `'<p>' + escapeHtml(x)` is not reported) and
`jsxQuery` (JSX patterns for `.tsx` files only). Not looked for yet, and named so in the rule's `nothingToFind`:
PHP, Java, C#, Kotlin, Rust, Dart, and Swift.
