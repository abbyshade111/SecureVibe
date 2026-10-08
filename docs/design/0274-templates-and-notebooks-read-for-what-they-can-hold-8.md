# Templates and notebooks read for what they can hold (8 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 3.6; BACKLOG, item 14; ADR-054). The code rules give "nothing of this
kind found" only when every language in the app was read, and a file whose extension `sv` did not know was not counted
as a language at all. So a notebook calling `eval`, or an Astro page, drew nothing, and the clean results stood.
Each kind is now read for what it can hold (`language_of` in `crates/sv-scan/src/ecosystems.rs`, `scan_listing` in
`crates/sv-check/src/ast.rs`).

- **Notebooks (`.ipynb`) are read as Python.** Their code cells are taken out of the notebook's JSON and each line put
  on the line of the file it is stored on, so a finding names the right line. A notebook written on a single line is
  read cell after cell instead, and its findings' lines count the code cells. IPython's `%magic` and `!command` lines
  and `%%` cells are not Python and are blanked first; since `!` runs a shell command no rule read, a notebook holding
  one counts as not fully read and holds back each rule whose call could be named in those lines. `%matplotlib`,
  `%load_ext`, `%reload_ext`, `%autoreload`, and `%config` run nothing of the app's and are only blanked. A notebook
  whose kernel is another language is that language unread; one that is not JSON `sv` can read is a file not opened.
- **Templates that hold a general-purpose language are unread code:** `.ejs` and `.pug` (JavaScript), `.erb` (Ruby),
  `.jsp` (Java), `.cshtml` and `.razor` (C#), and `.astro` (a TypeScript header). While one is present, no code rule
  claims anything is absent, and both the terminal and the report name the files that held them back. Reading Astro's
  header and EJS's `<% %>` blocks is the next step (BACKLOG, item 14).
- **Templates whose own syntax cannot run code are read as pages:** `.hbs`, `.handlebars`, `.mustache`, `.liquid`,
  `.twig`, `.j2`, `.jinja`, `.jinja2`, and `.njk`. Their `<script>` elements and `on…=` handlers are read as
  JavaScript, as a `.html` page's are, and their `{{ }}` and `{% %}` cannot call a shell, evaluate code, or build a
  query. A script holding template syntax does not parse cleanly, and is counted as not fully read.
- **`.sql` files are named and hold nothing back.** The rules against queries built by hand look at how the app's
  code builds a query, not at a file of SQL. The terminal and the report list them as files no rule reads. They are
  recognized by extension in the code rules only and are not given a language, so they do not count as code elsewhere.

The technology scan passes over notebooks and code templates, as it did before they had names, and reads logic-free
templates as pages. Semgrep, which is handed every file with a language, is now handed templates and notebooks too, so its
rules for `*.erb`, `*.ejs`, `*.pug`, and `*.jsp` run over the app's templates and are counted (`docs/COVERAGE.md`:
twelve of the twenty-two rules that read only files `sv` never handed it). `tools/coverage.py` read `language_of`'s
extensions one line at a time, and now reads a wrapped line as well. What a notebook costs: one with a `!pip install` line now holds back the rules whose call could
be named in it, where before the whole notebook was invisible and held back nothing.

Tests: `crates/sv-check/tests/clean_coverage.rs` (`a_notebook_is_read_as_python_at_its_own_lines`, and the six after
it), and `crates/sv-cli/tests/templates.rs`. Each guard was broken in turn and its test went red: line placement
always falling back, shell lines not counted, `.ejs` read as a page, and `.ipynb` given no language.
