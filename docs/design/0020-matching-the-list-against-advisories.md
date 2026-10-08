# Matching the list against advisories

`sv audit ./app --advisories ./osv` compares what the app ships with a local OSV database.

### `sv` does not fetch anything

A deliberate decision rather than an unfinished one, for three reasons. **Checking code is not a reason to
phone home**: the list of packages an app depends on is business-confidential, and sending it to a service
to be checked is a disclosure the owner did not ask for — v1 fences generated code to loopback on the same
argument. **A fetch is a dependency on somebody else's uptime**, and a check that silently degrades when a
service is slow is a check that reports a clean result on a bad day. And **`sv` runs where there may be no
network at all** — an air-gapped review, a CI runner with egress rules, a laptop on a train.

So getting the data is the owner's step, done deliberately and visible in their shell history.

**Where to get it, named (8 October 2026, backlog item 24).** Until then the step said "download an OSV export"
and not where, which left the check out of reach for somebody who is not a programmer (`docs/GAP-ANALYSIS.md`,
5.2). `sv audit` without a database, and the report's gap about known vulnerabilities, now name the OSV zip
for each kind of package the app uses (`osv_download` in `crates/sv-check/src/advisories.rs`), and `sv audit`
adds the folder layout: one folder per download under `osv`, which works because the reader walks every
folder under the one it is given. The guide (`docs/GETTING-STARTED.md`) carries the same addresses as a table,
and a test fails when the table and `osv_download` disagree. A kind of package with no download is named as
one `sv` does not compare yet. Nothing downloads: a `sv advisories fetch` would change what `sv` connects to,
and would need a decision record of its own (ADR-027's rule).

### No data is not a clean result

With no database, `audit` reports **not assessed** and says what to do about it. It never prints "no known
vulnerabilities", because that sentence is equally true of an empty directory, a stale one and a healthy
app, and only one of those is good news. The same holds per-ecosystem: a database of npm advisories says
nothing whatever about the Python packages beside them, so those are named as unchecked rather than
counted as clean.

### Three things the comparison has to get right

* **The fixed version is not affected.** An off-by-one here reports every upgraded app as vulnerable,
  which is the fastest way to teach somebody to ignore the check. Ignoring the `fixed` event fails three
  tests.
* **A pre-release comes before its release.** `4.17.20-beta` does not contain the fix that landed in
  `4.17.20`. Treating them as equal reports a genuinely vulnerable install as clean — a false negative,
  and the worst mistake this file can make. My first version did exactly that, by dropping the
  pre-release when parsing; the unit test caught it and an end-to-end test now catches it too.
* **Same name, different ecosystem, different package.** `lodash` on PyPI is not `lodash` on npm, and
  matching on the name alone invents vulnerabilities.

A version that cannot be compared with any range — a Go commit pseudo-version against a `GIT` range, a
build tag — is listed as uncomparable rather than quietly passed.

### pnpm, and a dependency not taken

`pnpm-lock.yaml` is the last common lockfile, and it is YAML. The obvious move is a YAML crate; the
established serde one has been archived since 2024, and putting an unmaintained parser into a tool whose
subject is supply-chain hygiene is a poor trade for one file format.

The only YAML actually needed is the set of keys directly under `packages:`, so that is what is read and
nothing else is guessed at. Both key shapes are handled — `express@4.18.2` and `/express/4.18.2` — and
scoped names keep their scope, because the version is what follows the *last* separator. A peer variant
like `vite@5.0.0(terser@5.0.0)` is one package and the peer is not a second one, and `snapshots:` repeats
every key from `packages:`, so reading both blocks would double the list.

A file this reader does not understand produces no packages, and the caller turns that into "read, and no
packages could be taken from it". That guard is what makes hand-parsing acceptable: an empty list is
otherwise indistinguishable from an app with no dependencies, which is the one wrong answer available.

**It also closed a hole that had nothing to do with pnpm.** Any reader returning an empty list left the
ecosystem present and the document silent about it — `package-lock.json` holding `{"lockfileVersion":3}`
and nothing else produced a bill of materials with no components and no caveat. That is now reported, and
breaking it fails three tests.

Worth recording how it got to one guard: the first version had two, one inside the pnpm reader and one in
the caller. Deleting the inner one failed no test at all, because the outer one already covered it — a
guard that survives being deleted. It went, and the remaining one is asserted by the message it produces
rather than by the fact that something was reported.

### Yarn Berry and Bun

Two more lockfiles, each read without a new dependency.

**Bun** was not a lockfile `sv` knew at all, so every Bun app was told it had no lockfile: a wrong
statement, in the direction that sends an owner to fix something that is not broken. `bun.lock`, the text
lockfile Bun has written since 1.2, is JSON that allows a comma before a closing bracket. Those commas are
taken out, outside strings only, and the file is read as JSON. Each entry under `packages` begins with
`name@version`, and the name is taken from there rather than from the key, because a package installed
under another one is keyed by its path (`debug/ms`). The older `bun.lockb` is binary. It still pins, so
the app is not told it has no lockfile, but nothing can be listed from it, and the report says so and
names the text lockfile that `bun install --save-text-lockfile` writes instead.

**Yarn Berry** (Yarn 2 and later) keeps the name `yarn.lock`, so it was already counted as pinning, but
its list came back empty: it writes `version: 4.17.21` where classic Yarn writes `version "4.17.21"`. A
file that starts with `__metadata:` is now read as Berry. Its ranges carry a protocol,
`lodash@npm:^4.17.0`, so the name ends at the first `@` after a scope. Only `npm:` and `patch:` entries are
registry packages; the app's own `@workspace:` entry and anything linked from a folder are not, and are
left out, as Bun's `workspace:` and `github:` entries are.

Both were checked against lockfiles the real tools wrote, not only against hand-written ones: Bun 1.4.2
installed 41 packages and `sv sbom` listed 41, and Yarn 4.18.1's lockfile has 41 entries, one of them the
app itself, and `sv sbom` listed 40.

### Severity from the advisory, not from a guess

`sv audit` used to decide seriousness by looking for the word CRITICAL and for a substring of a v3.1
vector, and calling everything else medium. That is not a severity, it is a placeholder wearing one's
clothes — and a placeholder reading "medium" is believed by anyone sorting a list by how bad things are.

The vector is now parsed and the base score computed to the specification, so a finding says what the
advisory says:

    [medium] lodash 4.17.15 has a known vulnerability: GHSA-p6mc-m468-83gg (CVE-2020-8203)
       Prototype pollution in lodash. The advisory rates this 5.9 out of 10, which is medium.

Two deliberate limits. **v3.0 and v3.1 only**, because they share the base formula and v2 and v4 do not —
scoring a v4 vector with the v3 formula produces a confident number that is wrong. **Base metrics only**,
because temporal and environmental metrics describe somebody's particular deployment, which is not
something `sv` knows; a vector carrying them is scored on its base and the extras ignored rather than
refused.

Where no vector can be read, the finding says the seriousness shown is a placeholder rather than the
advisory's own rating. A genuinely low-rated advisory and an unrated one used to look identical; they are
different facts.

#### A guard with no test, and why it keeps its place

The specification defines its own rounding in integer arithmetic, because `(x * 10).ceil() / 10` can
disagree with a published score when a value lands exactly on a tenth. Replacing it with the naive
version failed no test — so the question was whether it earns its place.

Every one of the 2,592 base-metric combinations was checked, and **none distinguishes the two**. That is
why no test can catch the substitution, and the equivalence is now recorded in a test of its own so the
next reader finds the answer rather than the puzzle. The specification's version stays: it is what the
specification says, and temporal scoring — if this ever grows it — produces intermediate values the
equivalence does not cover.

### Late, not merely known: the owner's time frames

V15.2.1 asks that the app contains no component that has *breached the documented remediation time
frame*. Until 26 September 2026 every known vulnerability was counted as that breach, so an advisory
published yesterday and one left alone for two years read the same, and the requirement's own question
— is anything late? — was never asked.

The time frames are V15.1.1's document, and the owner writes them twice: in words in
security-notes.md, and as numbers in securevibe.toml, which `sv audit` can hold the packages to.

```toml
[policy]
fix-within-days = { critical = 7, high = 30, medium = 90, low = 180 }
```

Each finding is then one of three things, printed in this order:

* **Past the time frame.** A breach of V15.2.1, which the finding cites, with the day it was due and how
  far past it is.
* **Not judged.** No time frames at all, none for this severity, no publication date that can be read, or
  a clock that reads before 1970. Each is counted against V15.2.1 exactly as before, because *not shown
  to be late* is not *shown to be on time*, and the finding says which piece was missing.
* **Inside the time frame.** Still a known vulnerability and still a finding, with the day it is due. It
  no longer cites V15.2.1, because it has not breached anything yet.

Four choices, each made so that a mistake can only make something look later than it is:

* **The age is counted from the advisory's publication date.** A vulnerability can be known before its
  advisory is published, never after, so this is the shortest the age can be. It is also the one
  direction that could hide a breach, so the finding says so in as many words.
* **An advisory with no rating is held to the shortest time frame stated.** Its real severity is
  unknown, and any longer time frame could call something on time that its rating would make late.
* **A severity the owner left out is not judged**, rather than borrowing a neighbor's number.
* **The last day is inside.** Published on 1 January with 30 days is due by 31 January, and late on
  1 February.

**The one thing this could get wrong.** With the inside-the-time-frame findings no longer citing
V15.2.1, "no finding about V15.2.1" and "nothing found" became different sentences, and only the second
is a clean comparison. A package with a known vulnerability is not clean because it is not late yet.
The clean claim still asks for no findings at all, and
`a_vulnerability_inside_its_time_frame_still_stops_the_clean_claim` holds it: rewriting the condition to
"nothing cites V15.2.1" fails that test and nothing else, which is why it has a test of its own rather
than being left to others to notice.

Every guard was broken once to see what caught it. Seven in the check each failed the test written for
it; the four in `sv audit`'s printing — late and inside swapped, the not-judged group dropped, the reason
not printed, the time frames never read — each failed `crates/sv-cli/tests/audit_deadlines.rs`, which runs
the binary. A guard on the check is not a guard on what reaches the reader.

### In the report too

`sv report --advisories DIR` runs the same comparison with the same time frames, and puts its findings,
its clean result, and what it could not compare into the report. Without a database the report now says
it compared nothing: before 26 September 2026 it said nothing at all, and a report silent about known
vulnerabilities reads as a report that found none. The reason a finding was not judged against a time
frame moved into the finding's own words at the same time, so it reaches the report and SARIF rather
than only the terminal.

The report is a second place the on-time case could go wrong — a finding that cites nothing leaves
nothing marking V15.2.1, and it must not come out *checked* — so
`crates/sv-cli/tests/report_advisories.rs` holds it there too, by running the binary. Six breaks of the
wiring (no-database gap, findings, clean claim, uncovered-ecosystem gap, gaps reaching the report, time
frames read) each failed at least one of its five tests.

The MCP server does not take a database: an AI coding tool asking about an app gets the no-database gap,
and the person can run the comparison from a terminal.
