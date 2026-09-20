# Timeline

## A gap in this record, stated first because everything below depends on it

**This is not the project's full history, and the project did not begin on 18 September.**

The repository's first commit, `c85c174`, is titled *"Restore SecureVibe after iCloud eviction (fresh history)"*
and lands **687 files and 280,421 lines in one go** — a mature project appearing at once. The commits before it
were lost when iCloud evicted the working copy, and what survived was reconstructed as a single starting point.

Work demonstrably began earlier. Ten of the twelve architecture decision records are dated **16 September 2026**,
two days before the repository's first commit, and the documentation references the 17th. So at least two days
of development — including most of the foundational decisions the rest of the project rests on — happened before
any commit in this timeline.

What follows is therefore **the surviving record from 18 September onward**, not the project's life. Treat the
commit count as a measure of the last three days, and the ADRs in Part V as evidence of what came before them.
The reconstruction itself is worth noting as a finding: a project whose history can be evicted by a file-sync
service is one whose provenance rests on something outside the developer's control.

## What happened before the record, from the session that did it

The session that built SecureVibe's backbone on 17–18 September was archived, restored on 20 September, and
wrote what it knew to `docs/FIRST-SESSION-CONTEXT.md`. Its account of the lost period, which nothing in the
commit history shows:

The owner chose the order of work on **17 September** and asked for it to be carried out without further
approval: `CLAUDE.md`, then plan → approve → build → verify, then builds as durable jobs, then the evaluation
harness with its golden apps, then template upgrades, version diff, the hand-off pack and the one-page report,
then containerised generated code, then the OpenAI and Google providers. Before that list the same session had
already built save-and-resume of wizard answers, the dashboard, "Save credits", the human-checks wizard, app
previews with a one-click sign-in link, and uploading your own app for a check.

So the foundation the rest of this timeline builds on — the evidence model, the durable build, the harness, the
upgrade path — was in place before the first surviving commit. The three days below are the period in which that
foundation was used, tested by people other than the owner, and found wanting in the ways recorded here.

## The surviving record

Assembled from the repository's own history: 116 commits across 18–20 September 2026. Times are the commit
times, so they record when a change was finished rather than when it was begun. Commit subjects are reproduced
as written — they were written to say what changed and why, and several of them are the primary record of a
decision.

The project was built by an owner who is not a programmer, working with AI agents, against a fixed template and
the OWASP Secure by Design, ASVS 5.0 and AISVS 1.0 checklists. Two people other than the owner used it during
the period covered here, both on 19–20 September.


## Day 1 — 18 September

40 commits, 09:32 to 23:47.

| time | commit | change |
|---|---|---|
| 09:32 | `c85c174` | Restore SecureVibe after iCloud eviction (fresh history) |
| 09:35 | `5cfc0be` | Hand-off pack: valid run id in the API test |
| 09:37 | `92bbd29` | Tell the owner when a build finishes |
| 09:41 | `7ea4655` | Free onboarding example, free builds without AI, one-page report landing |
| 09:44 | `27b85e2` | Network fence: generated code can reach this computer only |
| 09:56 | `7ecb4c3` | OpenAI and Google providers for builds |
| 10:00 | `71fae08` | Generated apps can run their assistant on OpenAI or Google |
| 10:03 | `2d954a3` | Rebuild the test fixtures iCloud deleted |
| 10:06 | `00456fe` | Template test names carry a requirement id (caught by the evaluation harness) |
| 10:31 | `eea281f` | Link the stylesheet from index.html again (lost with the deleted file) |
| 12:17 | `4b947ac` | Choose which AI service does which step |
| 12:32 | `771a943` | Each new question starts at the top of the page |
| 13:57 | `2fad0b3` | Download the scan data, and read the code behind a finding |
| 15:23 | `1a16637` | Themes, an opt-in AI scanner, and a page for re-running the checks |
| 17:21 | `5a9c4e5` | Containers, supply-chain checks, and one scanner cache instead of one per app |
| 17:49 | `9cedf92` | SecureVibe's own supply chain, and a review that starts where it matters |
| 18:04 | `9687de2` | Merge pull request #1 from abbyshade111/themes-nano-analyzer-security-checks |
| 18:06 | `2320d1f` | Refresh the golden baselines after the Dependabot cooldown fix |
| 18:47 | `6a989df` | Carry on a stopped build, review what changed, and stop paying top rate for small steps |
| 18:57 | `e28eff1` | Merge branch 'main' into claude/great-greider-1f0a4f |
| 18:58 | `97acfb0` | Merge pull request #2 from abbyshade111/claude/great-greider-1f0a4f |
| 20:22 | `e78472b` | Repair what the two merges broke on main |
| 20:22 | `993b887` | Merge branch 'themes-nano-analyzer-security-checks' into fix-main-merge-damage |
| 20:29 | `c78ce82` | Check that a test does what its name claims |
| 21:02 | `f6b3691` | A misnamed test is a note to a person, not a failed requirement |
| 21:05 | `a6dc89c` | Say where the test-name check is blind |
| 21:47 | `d15625b` | Make the checks fail fast and say where they stall |
| 21:48 | `d8e3b7b` | Merge pull request #3 from abbyshade111/fix-main-merge-damage |
| 22:09 | `f2ed341` | Run the suites one file at a time on CI, with a stop the runner cannot ignore |
| 18:30 | `248350b` | A recipe library for the generation agent, and its first recipe |
| 19:16 | `6e33d61` | Recipe 1 proves V2.3.3 with a test that actually checks it |
| 19:23 | `c530ae1` | A hash of a generated file's content, with the run id out of the way |
| 19:51 | `0372eab` | One control per claim: the bounded-list half of TPL-DB-02 becomes its own |
| 20:57 | `5a08195` | Recipe 2: a file kept with a record |
| 21:26 | `bb5705b` | Three template tests that named the wrong requirement |
| 22:12 | `b91a36f` | Recipe 3: a report over existing records |
| 22:41 | `60d6e02` | Hold recipe test names to the screen that now runs on every build |
| 23:40 | `9bf6eca` | Recipe 4: a reminder before a date on a record |
| 23:43 | `6ee0f93` | Call vitest directly, so the flags meant for it reach it |
| 23:47 | `0d56fcb` | Git no longer waits for permission |

## Day 2 — 19 September

50 commits, 08:01 to 21:34.

| time | commit | change |
|---|---|---|
| 08:01 | `876cbe6` | Make the suite name the file it is stuck on |
| 08:05 | `6f468ac` | Check the packages against OSV instead of a check that cannot pass |
| 08:09 | `c63c354` | Put the workflow back to one run, and write down what is still broken |
| 08:13 | `c87ea08` | Start the checks by hand while the hang is unfixed |
| 08:14 | `faab9fd` | Pin the rule that keeps a carried-forward verdict honest |
| 08:17 | `703c33e` | Merge pull request #4 from abbyshade111/claude/keen-meninsky-691a27 |
| 08:19 | `3445536` | Merge the CI branch: OSV instead of a check that cannot pass, checks by hand while the hang is unfixed |
| 08:43 | `fc56b6b` | Refresh the golden baselines after the merge |
| 09:05 | `cc7372d` | Hand over on the app's own page, or the preview never signs anyone in |
| 09:05 | `d7e5837` | Let the AI be asked to fix the problems that are actually code |
| 09:14 | `69bf921` | Make the free update show the free check, not a build form |
| 09:25 | `c476464` | Free the Security page when a check died without saying so |
| 09:25 | `bfaac42` | Say what a check-only run skipped, instead of leaving it pending |
| 09:34 | `06600fb` | Stop reporting the file that stores the hashes as a changed file |
| 09:41 | `4927db5` | Show what a check actually saw, and let a person say it is wrong |
| 09:49 | `a4e4fbf` | Fix seven things the cross-review found, money first |
| 09:55 | `93a979c` | Take the ceiling off how far back the Security page looks |
| 10:01 | `5cbfca2` | Carry a verdict only when every file it read is unchanged, and say what a scan cost |
| 10:07 | `0f9d73f` | A scan that spent the owner's money is not a scan that did not run |
| 10:17 | `a341c59` | A seam for secrets, key rotation, and three pages that hid the run they started |
| 12:12 | `2a5d2e8` | Four fixes an owner found, and four the sample builds found in those |
| 10:32 | `703a719` | A security view across every app, and two bugs found by looking at it |
| 11:09 | `216a2ba` | Fix a finding from the security view, and let the check decide when it is closed |
| 12:04 | `9792f83` | A chart the app draws itself, out of whole numbers |
| 12:50 | `8e3a3c5` | Ask an outside service's address, and whether the owner has a key yet |
| 12:59 | `652c4d9` | Write down how to tell whether a branch is safe to delete |
| 14:11 | `da2d956` | Write the agreed list down where both sessions can read it |
| 14:12 | `4ebce10` | Add the antivirus scan to our own Security page, not only to apps |
| 14:14 | `68c1262` | For an uploaded app, scanning the files is part of checking them |
| 14:27 | `76d4320` | The harness should sweep up before it starts |
| 14:34 | `0d4d705` | Fold the changed-files list away by default |
| 14:41 | `40b0388` | Three the owner found by reading her own build |
| 13:01 | `a19446d` | A page can ask for a place in the menu, and charts do |
| 13:11 | `e5e952e` | One page showing what is coming up, and a field called Order that used to break the build |
| 13:45 | `d50ce89` | Two bugs the golden apps found, one of them a trap for anybody writing a template test |
| 14:13 | `1d6e22b` | Record team-inventory's new baseline |
| 15:20 | `bb7a834` | Access control was only verified for apps that called the role admin |
| 14:48 | `4b59019` | Put what an owner can do today above what waits on a hosting provider |
| 15:12 | `d7af1b7` | A colour is a setting, so the frozen design stops recording one |
| 15:16 | `71494c9` | A build only exists on the page that is watching it |
| 15:38 | `03e5983` | Show what a build has spent while it is spending it, and stop calling files evidence |
| 15:41 | `ec3d5d4` | Ask the app what role the person we are probing with actually holds |
| 16:07 | `757f1d2` | Build the golden apps two at a time, share one compile cache, and let a test wait as long as the app does |
| 16:12 | `d78d122` | Fold away 65 filenames, and stop implying that skipped tests failed |
| 17:03 | `99b9dd3` | Fill in the list of what only the owner can finish |
| 17:39 | `8fff601` | Record all five golden apps against one tree, and sweep only what is finished |
| 20:34 | `f5322bf` | A stopped build can be resumed, and an owner cannot find the way |
| 20:42 | `ae25cdc` | What two owners hit on the first night, written down |
| 20:48 | `60310aa` | The agent cannot fix a test it is not allowed to see the name of |
| 21:34 | `5f94d1c` | Let a stopped build be continued, and tell the agent which test failed |

## Day 3 — 20 September

26 commits, 12:17 to 17:32.

| time | commit | change |
|---|---|---|
| 12:17 | `eb35de0` | Settle search, filter, sort and paginate once, with the ownership clause built in |
| 12:18 | `7c692b5` | Claim work in the backlog, because a message reaches nobody who is not running |
| 12:43 | `22ddcc1` | Eight of my own tests were named after rules they do not check |
| 12:44 | `52625fb` | A file that cannot be checked for malware is refused, not stored |
| 13:00 | `ef078e2` | Record the golden apps against the query engine, and ground a fixture in reality |
| 13:21 | `68e5674` | An app refuses a file it could not check, and says so before anyone picks one |
| 13:28 | `ceb80d8` | Check the scanner code against a real scanner, and skip loudly when there is none |
| 14:31 | `cb5d5f1` | Scan an uploaded app for known-bad files, and learn what the fence actually does |
| 13:18 | `12e1514` | Every list is one query with the ownership clause built in, and no call site chooses the scope |
| 13:42 | `d46f119` | Math.random in an emitted test, and the one-profile scan that could not see it |
| 14:14 | `65bae91` | A test that could not fail, and the fallback that made it so |
| 14:18 | `67e29b5` | Write down the habit that found four things in two days |
| 14:22 | `32e5562` | Claim the harness lock, and record what we decided not to build |
| 14:52 | `aae2c26` | Write the fallback trap into the recipe contract |
| 14:57 | `c7c1f08` | Use the slow scanner when the daemon will not answer, instead of reporting nothing |
| 15:28 | `58e384c` | A dead button with no reason, and my own bad fix that caused it |
| 15:39 | `dca2e6c` | Say what was read, and stop scoring code nobody read |
| 16:14 | `7e81ada` | Semgrep has never read a single file of anybody's app, and now does |
| 15:38 | `d91eab8` | Claim the assistant-progress item, and record that UX-01 cites nothing |
| 15:46 | `7e32baa` | Tell the agent that a slow button must say so, and say plainly that nothing checks it |
| 16:26 | `cd21ea2` | Stop asking a Python app about npm, and ask the question underneath instead |
| 16:33 | `8d0c716` | Say what the check will cover before the upload, not after it |
| 17:12 | `10e83ca` | Record the golden apps against ADR-012 and the assistant-progress change |
| 17:21 | `4e1583a` | Rewriting the reports must not quietly restore the score it just removed |
| 17:22 | `027313c` | Nine findings a Python app gets for not being a SecureVibe app |
| 17:32 | `a7b5d53` | Show what a run is costing from its first second, not once it has spent |

