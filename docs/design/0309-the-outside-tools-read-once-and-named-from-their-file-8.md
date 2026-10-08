# The outside tools read once and named from their file (8 October)

The review of 8 October 2026 (`docs/backlog/0188-…`) found three small faults in how `sv report` handles
`data/adapters.json`, the file that lists the outside security tools `sv` can run.

**The file was read three times for one report.** It was read when the tools ran, again when they did not (to list
each as not run), and a third time after the report was written, to decide the exit status. Now it is read once, with
the rest of `sv`'s data (`Loaded`), and the same copy is handed to all three. The MCP server already reads its data
once when it starts, so it now reads this file then too, rather than once per report.

**The report wrote its own list of the tools.** Without `--tools`, the report said "bandit, gosec, brakeman, and CodeQL
each know their languages far better…". Semgrep, which reads every language, was added to the file later and never
reached the sentence. The sentence is now made from the file, a tool once each by the name a person knows it by
(the two CodeQL entries are one name): "Bandit, gosec, Brakeman, Semgrep, and CodeQL". A tool added to the file is
named without anyone remembering to.

**A broken file was silent without `--tools`.** With `--tools` it stopped the run (exit 3), as it should: the tools
were asked for and could not be known. Without `--tools` the report listed no outside tools at all and said nothing,
which reads as though there were none. It now says, in the same gap that says the tools did not run, that which tools
`sv` can run is not known, and why the file could not be read. A broken file does not stop a run that never needed
it: `sv plan`, `sv check`, and the MCP server go on, and say so.

This is not a decision in the sense of `docs/adr/README.md`: nothing about what counts as evidence, what runs, or what
a report concludes changes. The tools were not run either way; the report now says one more true thing about why.

What the tests show (`crates/sv-cli/src/adapters_once_tests.rs`), each broken on purpose to see it go red: the sentence
names every tool in the file once (the hard-coded list put back fails it); a broken file is said in the report and stops
a `--tools` run with the loader's own words (the gap taken out fails it); and the exit status reads the tools from the
copy it is handed (an empty list there fails it). That the file is read once is shown by the code, not by a test: there
is now one call to `Adapters::load` outside the tests.

`assemble_report_saying`'s length, the third part of the review's item 7, stays open.
