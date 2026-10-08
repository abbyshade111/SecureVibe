# Prompts the AI tool can fetch (4 October 2026)

The prompt library (`data/prompts.json`, `docs/PROMPTS.md`) is offered two more ways: `sv prompts` prints it,
and the MCP tool `securevibe_prompts` hands it to the AI coding tool, which can offer it to the person. Either
can be narrowed to one requirement (`--requirement V1.2.4`, or `"requirement": "V1.2.4"`). An id that is no
requirement at all is refused, so a mistyped one is never answered "no prompt targets it" as if it had been
looked up.

**Whether a prompt was shown to work travels with it.** A prompt is *shown to work* only when an app built
with it passed its check and the same app built without it failed; the owner asked on 4 October 2026 for the
rest to be offered too, marked. So every copy, in the terminal, the tool's text, and its structured result,
says `shown`, `not-shown` (tried, with what happened), or `untested`, right above the prompt's text, and the
ones shown to work come first. The loader refuses a prompt said to be tried that does not say what happened,
and one not tried that carries a result, so the two cannot read alike. Eight of these guards were broken in turn,
each caught; the first run found the "not tried yet" mark caught by nothing, because the library holds no untried
prompt, so a test now makes one.

**And on how many builds (8 October 2026).** "Shown to work" covered a prompt shown on one build with it and
one without as it covered one shown on ten and ten (`docs/GAP-ANALYSIS.md`, 4.6). Each shown prompt's `tested`
now holds `builds`, how many builds its status was decided on with it and without, and every copy says them:
"Shown to work, on 10 builds with it and 10 without." (`Prompt::status_sentence`), in `sv prompts`, the MCP
server's prompts and their descriptions, the offer for an app's gaps, the instructions every builder starts
with, the feature briefs, and the plan. The counts are the trial each status was first decided on; a later
trial that changed nothing is still told in its `result`. Of the ten coding prompts shown to work, eight were
shown on ten and ten, and two, `settings-file-first` and `git-from-the-start`, on one and one; the three
design prompts on one with and two without. A test holds each count to the trial's own account of who built what, so a count cannot
be written in without one. Breaks: the count left out of the words (six tests), a count changed, and a count
removed, each caught. Not done: saying when delivery through `sv`, rather than pasted, was not shown, the
other half of the gap analysis's point.

**A prompt's requirements are a citation, held like the others.** `tools/coverage.py`, which a test runs, already
knows what every rule cites. It now refuses a prompt that names a requirement none of its rules cites, a rule
that cites none of the prompt's requirements, a rule `sv` does not have, and an unknown status. Eight ways of
breaking the data were tried, each caught.

**Not evidence.** Handing the tool a prompt says nothing about what it wrote, so no requirement changes status
because a prompt was given or read; the tool's description says so.
