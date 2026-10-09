# What the code says about the level (9 October 2026)


Gap analysis of 7 October 2026, finding 17, its second part (`docs/GAP-ANALYSIS.md`, 4.1); ADR-024, "Later, 9 October
2026: at level 1, the report asks about what the code shows".

**The gap.** Level 1 rests on two answers in `stackvet.toml`, usually the AI coding tool's: that only the owner or
their team uses the app, and that it holds nothing sensitive about people. Since this morning the report says so
under the level line. It still did not look at whether the code agrees: an app with a `/signup` route and a
`blood_pressure` column, answered "just me" and `categories = []`, was held to level 1 without a word.

**What changed.**

- `sv_check::level_hints` reads the app's code files (by extension; never a test folder, never a folder set apart as
  not the app) for two things. A sign-up route, written as a quoted path (`'/signup'`, `"/register"`, `` `/sign-up/` ``,
  `"/join?team=1"`), when the audience is the owner or their team; a longer path (`/registered-devices`) or one under
  another (`/api/register`) is not one. And field names for each sensitive category the data list does not already
  name: whole identifiers, compared without case, underscores, or dashes, so `bloodPressure` is `blood_pressure` and
  `assn` is not `ssn`.
- One hint per kind, at the first place seen: a sign-up route first, then the categories in alphabetical order.
- `LevelWhy.hints` in `report.json`, and under the level line in every report: "The code suggests a sign-up page open
  to strangers (`/signup`, app.py line 4) and health information (`blood_pressure`, app.py line 6), which the answers
  do not say. A name in the code is only a hint: if it is right, change the answer in stackvet.toml and the app is
  held to level 2."
- The names are in `data/level-hints.json`, listed in `data/README.md`.

**What it does not do.** It changes no level and makes no finding: a name is a hint, and the owner knows what the app
holds. It reads names, not data: a health app whose fields are called `value` and `note` is not found. It asks nothing
at level 2.

**Held by** `crates/sv-check/tests/level_hints.rs` (16) and `crates/sv-cli/tests/level_hints_report.rs` (7, through the
binary). Broken on purpose eleven ways, one at a time: the audience ignored (2 tests red), test files read (3), a
folder set apart read (2), a listed category asked about (2), names compared as written (3), spaces kept around a
listed category (2), a name found inside a longer one (2), a route matched without its closing quote (2), files read
whatever their extension (2), the question left out of the level line (2), and the question asked at level 2 (2).
The first time round each went red in one test only; each got a second before this was written, and two of the new
tests found faults of their own: a category written `" health "` was not taken as listed, though the manifest reads
it so (fixed), and `security.md` has no level line to put the question under (the test was wrong, and now names the
two pages that have one). One intended break, a listed category asked about only when the list is empty, turned out
to change nothing, and is not counted.
