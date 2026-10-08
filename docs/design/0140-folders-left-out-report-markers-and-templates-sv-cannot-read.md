# Folders left out, report markers, and templates sv cannot read (4 October 2026)

H6 and H2 of the deep review, both about code `sv` never read while its report spoke as if it had.

**Folders with ordinary names.** `sv` left out any folder called `build`, `out`, `dist`, `vendor`, `coverage`, or
`target`, at any depth, and said nothing. Those names are also ordinary names for an app's own code (a `build/`
folder of deployment scripts, an `out/` folder of handlers), so a whole part of an app could go unread. Now the
names that only ever mean installed or generated code (`node_modules`, `.venv`, `__pycache__`, `.git`, and their
like) are still left out anywhere. The six ordinary names are left out only beside the manifest that explains them:
`target/` beside `Cargo.toml` or `pom.xml`, `vendor/` beside `go.mod`, `composer.json`, `Gemfile`, or a Python or
Node manifest, `dist/` beside a Node or Python package file, and so on (`OUTPUT_DIRS` in `sv-scan`'s
`ecosystems.rs`). Anywhere else they are read like any other folder. Every folder left out this way is recorded,
printed by `sv check`, and named as a gap in the report, so the owner can see what was not read and why.

**The report marker.** A folder holding `.securevibe-report` was left out, so `sv` would not read its own earlier
reports as the app's code. Anything that can write a file into the app, including an AI tool through the MCP
server's `write_report`, could plant that marker beside real code and hide it. The marker is now believed only
where the folder holds nothing but the files `sv` writes into a report folder (`REPORT_FOLDER_NAMES`, compared
without regard to capitals, plain files only). A marker beside anything else is refused: the folder is read, and
`sv check` says the marker was refused and where.

**Svelte and Vue templates.** `sv`'s rules read the code in a page's `<script>` block. A Svelte or Vue page can also
run code from its template (`on:click={() => eval(code)}`, `@click="..."`, `{{ ... }}`), and that code was never
read, yet the page counted as read, so a rule could be credited a clean result it had not earned. For now, a
`.svelte` page with any `{...}` outside its `<script>` and `<style>`, and a `.vue` page with `{{ }}` or an
attribute starting `@`, `:`, or `v-`, is named among the files not fully read, and its `<script>` is still read
and its findings still stand. A page whose template is plain markup is fully read, as before. **Corrected the same
day:** this said no rule then claims a clean result for the page, and that was not so. Naming a file as not fully
read does not hold a rule back; `hold_back` does, and this step did not call it, so the rule could still be
credited. Its test checked only that the page was named. The next section reads the template code, and holds the
rules back when it cannot.

Ten guards broken in turn, each caught: for the folders, an output folder left out wherever it is, a folder left
out without a record, the marker believed whatever the folder holds, `sv`'s own default report name forgotten,
capitals compared, and a refused marker not mentioned; for templates, templates never looked at, scripts and styles
not cut out first, and each of Vue's two signs of code ignored in turn.
