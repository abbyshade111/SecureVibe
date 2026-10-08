# A dashboard view for `sv`: a proposal

**Status:** proposed, 8 October 2026, by session securevibe-e2, at the owner's request ("explore building out a
dashboard view for sv"). Nothing is built from it until the owner decides. The backlog item is the first under
"Next" in `docs/BACKLOG.md`.

## What `sv` has today

Facts, read from the code on 8 October 2026:

- **One report per run, overwritten by the next.** `sv report` writes five files into `<app>/securevibe-report`:
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
  run it was (`not_run_this_time`, `run_status`), and a fingerprint of the `securevibe.toml` it read
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
run, at the same level, from the same `securevibe.toml`; otherwise the page has to say they cannot be compared, and
why. `report.json` holds enough to tell (`not_run_this_time`, `target_level`, the `securevibe.toml` fingerprint).

**C. Several apps together.** One page with a row per app: its name, when it was last checked and by which `sv`, its
level, what kind of run, how many findings need attention, and the same bar as in A. It would read the
`securevibe-report/report.json` already in each app's folder. It must never rank the apps or add their numbers up:
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
a copy of each `report.json` under `securevibe-report/history/` (in the app's folder, where the AI coding tool can
read it, and committed with the app if the owner commits the report); a folder in the owner's home
(`~/.local/share/securevibe/history`), private to this computer; or none, comparing only what the owner keeps
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
