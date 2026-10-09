# A dashboard view for `sv`: a proposal

**Status:** proposed, 8 October 2026, by session securevibe-e2, at the owner's request ("explore building out a
dashboard view for sv"). The owner agreed with the recommendations the same day and answered the questions at the
end; their answers, and what follows from them, are in the last four sections, and the decision is ADR-057
(proposed). Each part is built only under a claim of its own. The backlog item is the first under "Next" in
`docs/BACKLOG.md`.

## What `sv` has today

Facts, read from the code on 8 October 2026:

- **One report per run, overwritten by the next.** `sv report` writes five files into `<app>/stackvet-report`:
  `report.html`, `compliance.md`, `security.md`, `findings.sarif`, and `report.json`. The next run replaces them.
  Nothing keeps an earlier run (`crates/sv-cli/src/main.rs`, `write_report`; `report_lock.rs` reads the old report
  only to avoid replacing a newer one).
- **`report.html` is one file that fetches nothing.** It has no scripts, no fonts or styles from anywhere else, and
  light and dark colors (`crates/sv-report/src/html.rs`, its first lines; DESIGN, "one file, no external requests").
  Its first screen is the short version: the worst findings, the counts, which level the app was held to, what was
  not run, and what to do next. It has no charts or bars of any kind.
- **`report.json` already holds everything a dashboard would draw.** Its `counts` give, for the requirements that
  apply: how many need attention, are checked, checked in part, tested through the app's own tests, documented,
  attested, stated, to be checked by hand, and not verified, and apart from those, how many do not apply, are not
  assessed, or are above the app's level. It also names the app, the level, the date, the `sv` version, what kind of
  run it was (`not_run_this_time`, `run_status`), and a fingerprint of the `stackvet.toml` it read
  (`run_record`). It has no version number of its own format.
- **Nothing in `sv` serves a web page.** The MCP server talks to the AI coding tool over standard input and output.
- **The rules a dashboard inherits:** there is no pass (DESIGN); what was not examined comes first (DESIGN); no total
  that reads as a score, and never the words pass, secure, compliant, or safe in the short version, held by a test
  (`crates/sv-report/src/bluf.rs`); `sv` opens no network connection of its own (CLAUDE.md).

One number sets the tone for any picture of a report. For the Flask example app, a plain `sv report` finds 240
requirements that apply, 10 checked by an automated check, and 230 not verified by anything. An honest picture of
that run is mostly one color, and it is the color of "nobody has looked". A dashboard that made that look like
progress would be worse than none.

## Three things "dashboard" could mean

**A. One run at a glance.** The same report, with a picture at the top: the requirements that apply as one bar,
split by what stands behind each (needs attention, checked, checked in part, and so on to not verified), with the
number written beside every part. It needs nothing `sv` does not already have.

**B. One app over time.** What changed since the last run: findings that appeared or went away, requirements that
became checked, or stopped being checked. This needs something `sv` does not keep: earlier runs. It also has a trap.
A run without `--run` checks far fewer requirements than one with it, so a plain run after a full one would look
like the app got worse when only the run was smaller. Two runs can be compared only when they were the same kind of
run, at the same level, from the same `stackvet.toml`; otherwise the page has to say they cannot be compared, and
why. `report.json` holds enough to tell (`not_run_this_time`, `target_level`, the `stackvet.toml` fingerprint).

**C. Several apps together.** One page with a row per app: its name, when it was last checked and by which `sv`, its
level, what kind of run, how many findings need attention, and the same bar as in A. It would read the
`stackvet-report/report.json` already in each app's folder. It must never rank the apps or add their numbers up:
apps at different levels, checked by different runs, do not add.

## How it could be delivered

1. **Inside `report.html`.** A picture drawn with the page's own markup and styles, no script. It keeps every rule
   as it is: one file, nothing fetched, nothing new written.
2. **A new command, `sv dashboard`,** that reads the `report.json` of the apps it is given and writes one page,
   built the same way as `report.html`, where the owner says. It reads only; it writes one file, and only where
   told. It is a new command and a new file, so a decision with its own record.
3. **A page served while `sv` runs** (`sv dashboard --serve`, on this computer only). It could update itself, but it
   needs a script in the page and a program listening for connections, which `sv` has never had. More to secure, and
   more to get wrong, for little a reloaded file does not do. Not recommended now.

Keeping history for B is a separate choice, with three places it could live, each a decision for the owner:
a copy of each `report.json` under `stackvet-report/history/` (in the app's folder, where the AI coding tool can
read it, and committed with the app if the owner commits the report); a folder in the owner's home
(`~/.local/share/stackvet/history`), private to this computer; or none, comparing only what the owner keeps
themselves, such as the reports in the app's git history.

## How any of it stays honest

- No score, no percentage complete, and no total across apps or requirements. Counts are shown as counts, each with
  its name.
- "Not verified" and "not assessed" are parts of the picture in their own color, never green, never left out to make
  the rest look larger. The legend says in words what each color means.
- What a picture leaves out is written under it: the requirements above the app's level, those nobody could place,
  and anything not run this time.
- Every number on the page is one the report already states, and a test holds the picture to `report.json`: the
  parts add up to the requirements that apply, and each part matches its count.
- The banned-words test reaches every sentence the dashboard can print.
- Over time, only runs that can be compared are compared, and the page says when they cannot.
- Every report shows its date, so a stale one cannot pass for today's.

## Recommendation

**First, A, inside `report.html`.** One bar of the requirements that apply, by what stands behind each, with the
numbers written beside it and what it leaves out written under it, at the top of the page. It is small, it needs no
new data, no new file, and no decision about where anything is kept, and it can be tested properly: the parts add up,
"not verified" is never drawn as anything else, and the page still fetches nothing. It also shows the owner, at a
glance, the thing the reports most need understood: how much of the app nobody has examined yet.

**Then C, if the owner checks more than one app:** `sv dashboard`, writing one page from the reports already there.
It needs its own decision record before it is built.

**B last, and only once the owner has chosen where history lives.** It is the most useful of the three for watching
an app improve, and the easiest to make misleading.

## Questions for the owner

1. **Who is it for?** You, keeping an eye on your own apps, or somebody you show it to, such as the friend an app was
   built for? It changes what goes first.
2. **One app or several?** If several, roughly how many?
3. **Over time:** do you want earlier runs kept, and if so where: in each app's folder, in your home folder, or not
   at all?
4. **Is a page you open in the browser enough,** or do you want one that updates while `sv` is running?

## The owner's answers (8 October 2026)

After seeing a mock-up, built as `sv` would build it (no script, nothing fetched), with the five example apps' real
counts and the earlier runs marked as made up:

1. **Who it is for:** the owner for now, and an optional feature for anyone who uses `sv`.
2. **Views:** a high-level overview, one app in detail, and every app on this computer checked by `sv`.
3. **Over time:** wanted, if there is a safe way to keep it. The next section is the recommendation.
4. **Live:** a page in the browser first; and what an updating page would take, with its trade-offs. The section
   after next.

"Optional for anyone" settles how it is switched on: the bar at the top of `report.html` is part of every report,
and everything else is off until the person running `sv` turns it on, in a setting of their own
(`~/.config/stackvet/`). Not in `stackvet.toml`: that file is written by the AI coding tool, which should not be
the one deciding what is kept about the app's history.

## Keeping history safely

What could go wrong, and what the recommendation does about each:

- **Publishing it.** The app's folder is often a git repository, and sometimes a public one. A dated list of an app's
  weaknesses, committed there, is a gift to anybody looking for one. So history is kept outside every app's folder,
  in `~/.local/share/stackvet/history/`, beside where `tools/install.sh` already puts `sv`, with permissions that
  let only the person read it.
- **Keeping more than it needs.** Each run adds one small record: the date, the `sv` version, the level, what kind of
  run it was, the `stackvet.toml` fingerprint the report already carries, the counts, and for each finding its
  fingerprint, severity, rule, and `sv`'s own title for it. Never the app's code, a file's contents, a line of it, or a
  credential, not even its first four characters. That is enough to say what changed and no more.
- **Growing without end.** A limit on how many runs are kept for each app (the most recent 100, say), and one command
  that deletes an app's history, or all of it. The person can also delete the folder; nothing breaks.
- **Being edited to look better.** An AI coding tool runs as the same person, so it could rewrite history; outside the
  app's folder it is less in its way, not out of its reach. So history is a convenience for the person, never
  evidence: no requirement is credited from it, and the reports never read it.
- **Comparing what cannot be compared.** Two runs are set against each other only when they were the same kind of run,
  at the same level, from the same `stackvet.toml`, by the same `sv`. Otherwise the page says they are not compared,
  and why (the mock-up's 5 October run). Without this, the first full run after a plain one would look like the app
  got worse.
- **Which app is which.** An app is known by its folder, so a moved or renamed folder starts a new history, and the page
  says when an app's history begins.

The list of every app on this computer comes from the same place: an app is on it once a run of it has been kept.
Without history, `sv dashboard` can still be given the app folders to show, and reads each one's latest report.

## A page that updates while `sv` runs

Two ways, from cheapest to dearest:

1. **A page `sv` rewrites as it goes.** During a run, `sv` writes a short progress page into the report folder after
   each step, and the page asks the browser to reload it every few seconds; when the report is written, the page
   stops reloading and links to it. It needs no program listening for connections and no script: one line in the
   page's head does the reloading. Costs: the page blinks at each reload; one more file written into the report
   folder during a run (a decision with a record, as anything written into the app's folder is); and whether every
   browser reloads a page opened from a file has to be tried, not assumed. It works the same when `sv` runs in Docker,
   because the report folder is the app's own.
2. **A local server**, `sv dashboard --serve`, which the page keeps a connection to and which pushes each step as it
   happens. Smooth, and it could follow several runs at once. Costs:
   - A program listening for connections, which `sv` has never had. Other software on the computer, and web pages open
     in the browser, can send it requests. So it needs a secret in its address, a check of which site is asking,
     nothing but reading, this computer only, and stopping when it is closed. Each of those is code to get right and
     test.
   - A script in the page, which `sv`'s pages have never had.
   - A new dependency for serving web pages, or one written by hand.
   - In the Docker setup, the container would have to open a port to the computer, which it does not do today.
   - A change to what `sv` serves, and so a decision with its own record (CLAUDE.md).

**Recommendation:** the first, when a live page is wanted; the second only if the first turns out not to be enough.

## Build order

Each a backlog item of its own, claimed before it is started, with its part of ADR-057 accepted in its pull request:

1. **The bar at the top of `report.html`**, with the counts beside it and what it leaves out under it. Nothing else
   changes. **Built 8 October 2026**, with a second bar the owner asked for: where every requirement went, the ones
   that do not apply among them (ADR-057, "Later, 8 October 2026").
2. **`sv dashboard`**: one page from the reports of the app folders it is given, with every app and each app's own
   page, written where the person says. **Built 8 October 2026**: `sv dashboard FOLDER... --out FILE.html` (ADR-057, "Later, 8 October 2026:
   `sv dashboard`").
3. **History**, switched on by the person, kept as above, and the over-time view on each app's page; then every app on
   this computer listed from it. **Built 8 October 2026**: `sv history on|off|status|forget` (ADR-057, "Later, 8 October 2026:
   history").
4. **The progress page during a run**, if wanted once the first three are in use.

