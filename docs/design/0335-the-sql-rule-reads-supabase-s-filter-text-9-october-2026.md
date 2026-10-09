# The SQL rule reads Supabase's filter text (9 October 2026)


Finding 1 of the gap analysis of 7 October 2026, the last of its first half (BACKLOG, "From the gap analysis of 7
October 2026"). Supabase's clients were the last packages on `ast.sql-built-by-hand`'s unread list (ADR-018, Later,
9 October 2026). Their unsafe form is filter text passed straight through to the database: a filter written as text
rather than as separate column, operator, and value.

**What changed.**

- **npm.** The rule reads `.or(...)` and `.filter(...)`, including in a chain, as in
  `supabase.from('users').select('*').or(...)`.
  - `.or` is judged at its one argument.
  - `.filter` is judged at its third argument, the value. A value formatted into the database's own syntax, such as
    `'(' + ids + ')'` for `in`, is where the text gets in.
- **Python.** The same for `.or_(...)` and `.filter(...)`.
- **What is reported.** Text that is built: a string joined with `+`, a template with `${…}`, an f-string, or `%`
  or `.format(…)` applied to a string.
- **What is not reported.**
  - Fixed text.
  - A name handed over, as with the rule's other `where`-like names.
  - Anything that does not start as text. That leaves an array's own `filter(fn)`, Python's built-in
    `filter(fn, rows)`, and another library's `or` alone, because a function is not filter text.
  - A `filter` call with fewer than three arguments, which is not Supabase's form.
- **The unread list is empty.** Both Supabase clients come off it. The field and the hold-back stay for any package
  added later.

**The hold-back's own tests.** `crates/sv-cli/tests/orm_held_back.rs` tested the hold-back end to end with Supabase
as a real unread package. With nothing left on the list, those tests now run `sv` on a copy of `data/` (through
`SV_DATA_DIR`) whose rule lists the Supabase clients as a stand-in.

- First they assert that the real list is empty, so the stand-in is the only thing held back.
- Their apps' filter text is fixed. The rule finds nothing in it, and only the hold-back can take the credit.
- One more test runs on the real data: filter text built from the request is now a finding from this rule, and
  nothing is held back.
- With the hold-back call switched off, the three stand-in tests fail, and the control and the real-data test still
  pass.

**What it does not read.**

- Supabase's other text-taking calls: `.not(...)`, `.match(...)`, and `.textSearch(...)`. These name a column and
  take a value, and are not the free filter text the finding named.
- Built text first put in a variable.

**Tests.** `crates/sv-check/src/ast/orm_supabase_tests.rs`. Each guard below was broken on purpose, and each break
turned a test red:

- dropping `.filter`'s position on npm;
- loosening npm's test for built text, so a function counted;
- dropping Python's position;
- putting a client back on the list;
- switching off the hold-back.
