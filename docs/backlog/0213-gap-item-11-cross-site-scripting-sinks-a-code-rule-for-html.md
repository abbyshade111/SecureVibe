# Gap item 11, cross-site scripting sinks: a code rule for HTML built from a value and put on the page unescaped

**Status:** claimed by securevibe-e9, as its markers read on 8 October 2026

From "From the gap analysis of 7 October 2026", item 11 (`docs/GAP-ANALYSIS.md`, 3.3), whose other
parts were claimed and built by session securevibe-e9; this part was not. **Claimed on 8 October 2026 by session
securevibe-e2**, at the owner's word ("continue the backlog please"), in branch `claude/securevibe-e2-xss-sinks`:
`ast.html-from-value`, citing V1.2.1 and only ever a finding, for React's `dangerouslySetInnerHTML` given anything
but fixed text; `innerHTML`, `outerHTML`, `insertAdjacentHTML`, and `document.write` given a value; Python's
`Markup(...)` and Django's `mark_safe(...)` given a value; and Express's `res.send` of HTML
pieced together from a value. Finding-only, crediting nothing, so no decision record is proposed. Read on `main`
just before this claim: no other session had claimed it.
