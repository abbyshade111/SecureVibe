# The report's assembly in stages, one function each (8 October 2026)


**What was wrong.** `assemble_report_saying`, the function behind `sv report` and the MCP server's report tools, was
1,590 lines of `main.rs` (the review of 8 October 2026, item 7). Six of its seven stages had already moved out into
`static_scan` (ADR-023's "one walk of the app"); the seventh, "Putting the report together", was the rest of the
body, with some forty local variables flowing from the advisory comparison at the top to `sv_report::build` at the
bottom. Nothing in it was wrong. It was unreadable, and a change to one part meant reading all of it to know what
the part touched.

**What changed.** The function moved into a module of its own, `crates/sv-cli/src/assemble.rs`, and its one body
became eight functions along the sections its own comments already marked: `advisories` (the local advisory
database), `outside_tools` (the language's own tool, with `--tools`), `running_app` (the app behind the fence and
its own tests, with `--run`), `what_was_not_read` (every limit, said as a gap), `requirements_for_tests` (which
requirements the app's tests name, and which no test could show), `the_owners_word` (the notes, the decisions file,
the design questions and checks made by hand, and a person's confirmations), `coding_rules_cited`, and
`put_together` (what was examined completed, what a person set aside applied, the safe defaults held to the running
app, and the report built). `assemble_report_saying` itself is now the order they run in. What every stage reads is
in one struct, `Scene`: the app, the options, `sv`'s data, the manifest, the one reading of the app's files, what
the manifest's claims came to, and the seal checker. What a stage produces it returns (`Advisories`, `Tools`,
`Run`, `OwnersWord`), and the four lists every stage adds to, the findings, the credits, the gaps, and what was
examined, are passed down as they were built, so their order is the order the stages run in, as before.

**What did not change.** The report. The same findings, credits, gaps, and `examined` entries in the same order,
the same stage names reported to the MCP server in the same order, and the same words. The verdict snapshots
(`crates/sv-cli/tests/verdicts.rs`), which fail on any change to what the example apps' reports say, pass
unchanged, and so does the rest of `sv-cli`'s suite. One thing the compiler caught during the move: the first cut
of `running_app` carried over the line that made a fresh `findings` vector, so the running app's findings would
have gone into a vector nobody read. An unused-parameter warning named it, and no snapshot would have, because
the example apps are not run in CI. That is the kind of fault a split by hand makes, and why the moved code is
otherwise word for word what it was: each stage begins by taking the same names out of `Scene` that the old
body had, so the body below needed no edit.

**Open.** `main.rs` is 5,063 lines after this, down from 6,722; the commands and their helpers are still in it,
and the architecture assessment's item on `main.rs`'s size stays open for them.
