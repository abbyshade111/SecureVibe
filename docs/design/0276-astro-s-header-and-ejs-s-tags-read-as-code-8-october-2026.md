# Astro's header and EJS's tags read as code (8 October 2026)

The second step ADR-054 named (BACKLOG, item 14; ADR-054, Later). Until today an `.astro` or `.ejs` file was code
nobody read, and while one was in the app no code rule claimed anything was absent. They are the code templates
AI-built apps use most. Both are now read as pages are (`read_page` in `crates/sv-check/src/ast.rs`), with their code
taken out the way Svelte's and Vue's is:

- **Astro (`astro_template`).** The `---` header at the top is TypeScript, read at its own lines. Every `{…}` in the
  markup outside scripts, styles, and comments is an expression Astro runs, and may hold JSX
  (`{items.map((i) => <li>{i}</li>)}`), so each is parsed with the TSX grammar; `{...props}` is a spread and
  `{/* … */}` a comment. The page's `<script>` elements are read as TypeScript whatever their tag says, since Astro
  compiles them that way (`page_fragments`).
- **EJS (`ejs_template`).** EJS compiles a page's tags into one JavaScript function, so they are read as one
  program, each line where it is in the page: `<% code %>` as it is, `<%= value %>` and `<%- value %>` as the value
  they write out, and `<%# … %>` and the literal `<%%` not at all. Each tag starts a statement, as in EJS's own output,
  so `<% if (user) { %> … <% } else { %> … <% } %>` reads as an `if` with its `else`. The markup around the tags is
  read as a page, each tag blanked out, so a `<script>` holding `var data = <%- JSON.stringify(data) %>;` is read
  around it.

A page whose code cannot all be taken out, or does not parse, is named as not fully read and holds back each rule
whose call could be named in it. One case is EJS's own: EJS ends each `<% %>` with a line break, and the program here
keeps the page's lines, so `<% let a = 1 // note %><% eval(x) %>` would read `eval` as part of the comment. Such a
page is not read in full.

Tests: `astro_and_ejs_code_is_read_at_its_own_lines` in `ast.rs` (twelve pages each with an `eval` on line 4, four
that hold nothing, and four not fully read) and `an_astro_or_ejs_page_read_in_full_holds_nothing_back` in
`crates/sv-check/tests/clean_coverage.rs`. Each guard was broken in turn and a test went red: EJS's `<%= %>` not
read, the `//` comment case ignored, Astro's header not read, Astro's scripts read as JavaScript, and `.ejs` not
sent to its reader.
