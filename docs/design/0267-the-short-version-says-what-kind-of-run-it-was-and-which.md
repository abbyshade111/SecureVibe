# The short version says what kind of run it was, and which level (7 October 2026)

The gap analysis (`docs/GAP-ANALYSIS.md`, 6.1 and 6.2) found that the short version gave "N not verified" without
saying why. Plain `sv check` can credit a handful of requirements, and most need the app running, signed in, or an
outside tool, but the short version never said which of those had not run. Nor did it say which level the app was
held to. A level 1 app with a clean run could read as fully checked, with the requirements above its level and the
ones not yet placed outside every number. Two sentences now follow the counted list, in `compliance.md` and
`report.html` alike:

- **"Held to ASVS level L."** When some requirements are left out, it adds "Not in these numbers: N more
  requirements at levels 2 and 3 (or level 3), and M not yet placed because nobody has answered the question that
  decides them." The counts are the report's own (`out_of_level`, `not_assessed`).
- **"Not run this time: …"** It names the running app (`--run`), signed-in checks (test accounts), or outside tools
  (`--tools`), whichever did not run, then how many applicable requirements can only be checked that way. A
  requirement counts when every kind of run with a check able to credit it is among those that did not run, and it
  was not already found failing or checked. Whether the app ran is read from the report's run status. When none was
  recorded, the line says nothing about it, rather than guess.
- **Where "only that way" comes from.** `data/reach.json` lists, for each requirement a check can settle, the kinds
  of run with a check that can credit it. Checks that only ever find a requirement failing are left out, since they
  cannot show it met. `tools/coverage.py` writes the file from the same citations as `docs/COVERAGE.md`, and its
  `--check` test fails while the file is out of date. `sv report` reads it through `sv_frameworks::data`.
- **Guards, each broken on purpose.** Each turned a test red and was put back:
  - counting a requirement when any one of its kinds of run did not happen, rather than all of them;
  - counting ones already checked;
  - treating a run without signing in as one with it;
  - the wrong levels named for a level 1 app;
  - dropping either line from either format.

### The short version opens with two bars (8 October 2026, ADR-057)

The first step of the dashboard (`docs/DASHBOARD.md`). Under the worst findings, the short version of `report.html`
now draws the requirements that apply as one bar, split by what stands behind each (needs attention, checked,
checked in part, and so on to not verified), and under it a thinner bar of where every requirement `sv` knows went:
apply, do not apply, could not be placed, above the level, and counted apart. The second is there because the owner
asked to see how many do not apply; it is a bar of its own so that those are never drawn in among the evidence for
the ones that do (`glance` in `crates/sv-report/src/html.rs`).

Each part grows by its count, so the bars are to scale without a percentage anywhere, and a key under each gives
every count in words; a part with nothing in it is left out of both. "Not verified" is striped in a color no checked
or answered part uses. Like the rest of the page, the bars are markup and style alone: no script, nothing fetched.
For the five example apps the second bar adds up to the 640 requirements `sv` loads. The tests hold the bars to
the counts (to scale, every count in words, the parts adding up), "not verified" to its own color, the words to
the short version's banned list, and the bars to their place before the tally; five deliberate breaks each failed
at least one of them. At phone width the page still scrolls sideways, as it did before, because of the
requirements table further down; the bars fit.


### `sv dashboard`: one page for several apps (8 October 2026, ADR-057)

The second step of the dashboard. `sv dashboard FOLDER... --out FILE.html` reads the `report.json` already in each
app's `securevibe-report` folder and writes one page (`crates/sv-report/src/dashboard.rs`): a view of every app, in
alphabetical order, with the two bars and its findings by severity, and one view per app with what was not examined,
the two bars, its findings worst first, and a link to its full `report.html`. The views are sections shown by the
address's `#` (CSS `:target`), so there is still no script, and the page fetches nothing.

It checks nothing itself and says so; each app's part gives the date of its report, the level, what kind of run it was,
and the `sv` that made it, so a stale report does not pass for today's. The apps are never ranked or added up. Every
number is one the report states, and what a report says (the app's name, which the AI coding tool writes into
`securevibe.toml`, and every finding's title) reaches the page escaped, as text. It writes only the file it is given:
not through a link, not over a folder, not over a file without the page's own mark, and not inside an app, where the
next check would read it as the app's code. `--out` has no default, because any default would be a place the person
did not choose.

Tried on copies of the five example apps and a folder with no report; the page in light and dark, and at phone width
with no sideways scroll. Six deliberate breaks each failed a test (backlog, dashboard build item 2).

### History: each app over time (8 October 2026, ADR-057)

The third step of the dashboard. History is off until the person types `sv history on`, which writes a file of their
own beside the review key; `securevibe.toml` cannot turn it on, because the AI coding tool writes that file. While it is
on, each `sv report` at a terminal keeps one small record of the run (`crates/sv-cli/src/history.rs`) outside every app's
folder, in `~/.local/share/securevibe/history`, readable only by the person: the counts, the kind of run, the level, the
`sv` that made it, the `securevibe.toml` fingerprint, and each finding's fingerprint, severity, rule, and title. Not the
finding's description, not where it was found, not a line of the app, and not a credential, even shortened. An app's
folder is often a public git repository, and a dated list of its weaknesses does not belong there.

`sv dashboard` then shows each app's runs, newest first. A run is set against the last earlier run of the same kind,
level, `securevibe.toml`, and `sv`, and the page lists what changed: findings that appeared or went away, by fingerprint,
and each count that moved. A run with no such earlier run says why it is not compared; without that, the first full run
after a plain one would look like the app getting worse. Given no folders, `sv dashboard` shows every app whose runs were
kept. At most 100 runs are kept for each app; `sv history forget` deletes one app's, or all of them.

History is a convenience, never evidence: the reports never read it and nothing is credited from it, and the test that
plants text in a record checks that `report.html` does not show it. An AI coding tool runs as the same person and could
rewrite it, which is why it is kept out of the app's folder and why nothing rests on it.
