# sv explain: one requirement at the terminal (9 October 2026)


Part 5 of "From the end-of-day write-up of 8 October 2026: ideas for `sv` itself". A person reading "V7.4.1 not
verified" needs three things the report does not put in one place: what the requirement asks, what `sv` would have
checked, and what to do about it. The MCP server's `stackvet_explain` gave the AI tool the first. Nothing gave the
rest, and nothing gave any of it at the terminal.

**What changed.**

- **`sv explain ID [--app DIR]`** prints three parts:
  - the requirement in its framework's own words, with its level and where the level comes from, as
    `stackvet_explain` gives them;
  - **What sv checks**: each check that speaks to it, the kind of run that check needs, what it looks for, and
    whether it is only ever a finding (it can show the requirement failing, never met). A requirement no check
    speaks to says so: it is never marked checked.
  - **What to do**:
    - the coding rules that cite it;
    - the prompts for it, each with its "shown to work" status;
    - the check by hand from `human-checks.json` where only a person can look.

  With `--app`, it adds what that app's last `report.json` said: the status in words, the checks that credited it,
  and how many findings name it. When the requirement was not verified, it also names the kinds of run that report
  did not include, and how many of the requirement's checks need one of them. A requirement the report does not
  list is said not to apply or to be above the level, with `sv scope` named for which.
- **`data/reach.json` gains `checks`**. `tools/coverage.py` writes it from the same rows that make
  `docs/REQUIREMENTS.md`: each check's id, kind of run, what it looks for (cut at 240 characters), and whether it is
  only ever a finding, for every requirement any check speaks to (227 today). The binary therefore needs no
  generated document. `sv report` reads only `requirements` from the same file, as before, and ignores the new part.
- The README names the command beside `stackvet_explain`, and `data/README.md` describes the new part.

**What it is worth.** Nothing, as evidence. It reads files only. An app's status is quoted from its last report as
written, and only a new report shows what changed.

**Not done.** It is not a column in `report.html`, the item's other option: a command that reads the shipped data is
enough to answer the question where the person reads the report. `stackvet_explain` is unchanged, and still gives the
AI tool the requirement's words alone.

**Tests.** `crates/sv-cli/src/explain/tests.rs` covers four things:

- the words, every check, and its kind of run;
- that every requirement a check can settle has a check that can credit it listed (the two halves of `reach.json`
  agree);
- the coding rule, the prompt, and the check by hand;
- what a report adds.

`crates/sv-cli/tests/explain.rs` covers the command itself. Four breaks each failed a test:

- the only-a-finding mark lost;
- the checks left out of `reach.json`;
- a requirement absent from the report read as present;
- the runs that did not happen left unsaid.
