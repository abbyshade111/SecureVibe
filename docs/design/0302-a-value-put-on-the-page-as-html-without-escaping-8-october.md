# A value put on the page as HTML, without escaping (8 October 2026)


From the gap analysis of 7 October 2026, item 11 (`docs/GAP-ANALYSIS.md`, 3.3): plain `sv check` had no rule for the
commonest flaw in web apps, a value put on the page as HTML rather than as text, so whatever markup somebody typed into
it becomes part of the page (cross-site scripting). An Express and Next.js app with `dangerouslySetInnerHTML` and
`res.send('<h1>' + req.query.name)` drew no finding at all. Only the running app's `probe.reflected-unencoded`, and
the outside tools, could speak to it.

`ast.html-from-value` reads, in JavaScript and TypeScript, React's `dangerouslySetInnerHTML={{ __html: … }}`, an
element's `innerHTML` or `outerHTML` set (or added to) with a value, `insertAdjacentHTML` and `document.write` called
with one, and Express's `res.send` or `res.end` of text that holds a tag and is joined to a value; and, in Python,
`Markup(…)` and Django's `mark_safe(…)` around a value, which tell the template engine not to escape it; in Go, `template.HTML(…)` of a value; and in Ruby, Rails' `raw(…)` and `.html_safe` on one. Each finding
cites V1.2.1, output encoding for the context. It is only ever a finding: HTML built in one function and sent from
another, a template's own `| safe` or `{!! !!}`, and Vue's `v-html` are not read, so finding none credits nothing.

**What is not reported.** Fixed text, and a name the same file binds once to fixed text. A value that has been made
safe first: `DOMPurify.sanitize`, `sanitizeHtml`, `escapeHtml`, `he.encode`, `_.escape`, and `filterXSS` in JavaScript;
`escape`, `conditional_escape`, `format_html`, `bleach.clean`, `nh3.clean`, and a rendered template in Python. HTML is
written by joining fixed markup to escaped values, so a rule that judged only the whole argument would report every page
built the safe way beside the one that is not. A new rule field, `safeArgumentPiecesRead`, has the argument judged
piece by piece: the two sides of a `+`, each `${…}` of a template string, and each `{…}` of a Python f-string must each
be fixed text or made safe, and one piece that is neither is reported (`'<li>' + escapeHtml(name) + '</li>' + note`
is). `res.send` and `res.end` are reported only when their argument holds a tag (`<h1`), since `res.send({ … })` sends
JSON and `res.send(page)` sends whatever was built elsewhere. `socket.send` and `stream.write` are not a page.

**JSX in TypeScript.** No rule had read JSX before. JavaScript's grammar reads it in every file, so its patterns go in
the `javascript` query; TypeScript's own grammar has none, and a query naming `jsx_attribute` would not compile for a
`.ts` file, which stops the rule claiming anything there. A second new field, `jsxQuery`, holds patterns added to the
`typescript` query only for the files parsed with the TSX grammar (`.tsx`, and Astro's pages); a `jsxQuery` with no
`typescript` query to add it to is refused when the rules load.

**Not done.** PHP's `echo` of a value and Blade's `{!! !!}`, Java's servlets and Thymeleaf's `th:utext`, C#'s
`Html.Raw`, and the ways in for Kotlin, Rust, Dart, and Swift are not looked for yet. `sv` requires every code rule
to be taught each language it reads or to say why it has nothing to find there (a test fails otherwise), so each of
these is named in the rule's `nothingToFind` with what is not read, as `ast.template-built-from-value` does for the
languages it has not been taught. The rule only ever reports, so finding none in those languages credits nothing
either way. `res.send('Hello ' + name)` holds no tag and is not reported, though Express sends a string as HTML:
telling it from a plain message needs the value's type.

**Breaks.** Each failed `crates/sv-check/src/ast/html_tests.rs`: the pieces read whole (five cases), the JSX query
left out (two cases and its own test), the module pattern opened to every object (`socket.send`, `stream.write`), the
tag requirement for `res.send` dropped (two), `findingsOnly` off, the safe patterns removed (eight), and, in the Rust,
the `+` arm (two) and the f-string arm (one) of the piece reader; and Go's module pattern opened to any package (`html.HTML`), and Ruby's safe patterns removed (`raw(sanitize(…))`). Switching off `literalArgumentIsSafe` alone failed
nothing, since the piece reader also treats fixed text as safe; switched off in both places, six cases failed.
