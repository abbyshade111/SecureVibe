# Timeline

## A gap in this record, stated first because everything below depends on it

**This is not the project's full history, and the project did not begin on 18 September.**

The repository's first commit, `c85c174`, is titled *"Restore SecureVibe after iCloud eviction (fresh history)"*
and lands **687 files and 280,421 lines in one go** — a mature project appearing at once. The commits before it
were lost when iCloud evicted the working copy, and what survived was reconstructed as a single starting point.

Work demonstrably began earlier. Ten of v1's thirteen architecture decision records (twelve when this was written;
`ADRS.md` covers all of them) are dated **16 September 2026**, two days before the repository's first commit, and
the documentation references the 17th. So at least two days of development — including most of the foundational
decisions the rest of the project rests on — happened before any commit in this timeline.

What follows is therefore **the surviving record from 18 September onward**, not the project's life. Treat the
commit count as a measure of the days it covers, and the ADRs as evidence of what came before them.
The reconstruction itself is worth noting as a finding: a project whose history can be evicted by a file-sync
service is one whose provenance rests on something outside the developer's control.

## What happened before the record, from the session that did it

The session that built SecureVibe's backbone on 17–18 September was archived, restored on 20 September, and
wrote what it knew to `docs/FIRST-SESSION-CONTEXT.md`. Its account of the lost period, which nothing in the
commit history shows:

The owner chose the order of work on **17 September** and asked for it to be carried out without further
approval: `CLAUDE.md`, then plan → approve → build → verify, then builds as durable jobs, then the evaluation
harness with its golden apps, then template upgrades, version diff, the hand-off pack and the one-page report,
then containerized generated code, then the OpenAI and Google providers. Before that list the same session had
already built save-and-resume of wizard answers, the dashboard, "Save credits", the human-checks wizard, app
previews with a one-click sign-in link, and uploading your own app for a check.

**Where the evaluation harness came from.** The owner raised it, Claude gave it its form, and the owner chose it.
At 19:48 on 17 September the owner asked how SecureVibe could be improved: "Is there architectural designs or
changes we should be considering - for example, build out/refine a harness and/or orchestrated agentic workflow,
providing access to a skill library?" In that sentence the harness sits beside an agentic workflow and a skill
library, which reads as a harness for running the AI. A minute later Claude's answer proposed a different kind,
"An evaluation harness": keep "a set of **golden apps** (five or six profiles covering the feature combinations)
and build them automatically — AI off nightly (free), AI on before a release", because "today's three template
bugs were found only because a real build ran". At 19:58 the owner chose it, with the rest of the list: "…then the
builds as durable jobs, and the evaluation harness and golden apps." It was designed at 20:37, and its first run,
at 20:42, found template faults. The quotations are from the first session's transcript ("Vibe-coding application
builder"). The two later times are from that session's recorded reasoning (`securevibe-reasoning.md`, kept with
the paper's materials).

### Day 0 — 17 September 2026, reconstructed from the first session's transcript

Commit ids are from the destroyed history and will not resolve in this repository. Their times are those
recorded in that history, preserved in the v1 git bundle kept with the paper's materials. The times of rows
without a commit are from the first session's transcript and its recorded reasoning. All times are Eastern.

| time | commit | what happened |
|---|---|---|
| 10:36 | `a9c6661` | Initial commit. The wizard, design engine, pipeline, scanners, compliance engine, reports and the template already in place. |
| morning | — | The owner asks for save/resume of wizard answers, and the red Delete button. |
| 12:55 | `6aec203` | The security log with named events, the Dashboard, "Save credits" (Sonnet, low effort, one fix round, the 55/30/15 budget split so a $5 cap always covers a build), the human-checks wizard, app previews, and uploading your own app for a check. |
| 13:10, 13:28 | `1a17857`, `8d8c0a2` | Navigation to the human checks, the Finish page, the free re-check, self-assessment fixes. |
| evening | — | The third build of a health-tracking app made for a friend: $3.81, rated at risk on AC-02 and MT-06, 88 of 159 ASVS requirements verified. The owner decides its assistant should do its own research against vetted sites — which becomes a new wizard question. |
| 19:48 | — | The owner asks how SecureVibe could be improved, "for example, build out/refine a harness and/or orchestrated agentic workflow". |
| 19:49 | — | Claude's answer proposes seven changes, among them "An evaluation harness" built on golden apps, and an order to make them in. |
| 19:58 | — | The owner chooses the order of the remaining work, including "the evaluation harness and golden apps", and asks for it to be carried out without further approval. |
| 19:59 | — | `CLAUDE.md` is written. |
| 20:37 | — | The harness is designed: golden-app profiles saved as JSON under `evals/golden/`, and a command that builds each one without AI and compares it with a saved baseline. |
| 20:42 | — | Its first run finds the template wanting: a Habit Log app built from the template alone fails its type check and 14 of 163 tests. |
| 22:02 | `af6b83f` | All of it lands at once: the plan flow, refine questions, own API keys in `.env`, durable worker builds, the evaluation harness with its golden apps, `CLAUDE.md`, and five template fixes the harness had found. |
| 22:24 to 22:49 | `1a08dca`, `8811f07`, `55f04fa`, `0ee9f1b`, `ed99750` | Baselines recorded after the template fixes, raw test output kept for readable failures, a web-search test fix, all four golden apps building clean without AI (22:39), and template upgrades (22:49). |
| 22:54 | `52ad9a8` | The repository has just been moved into a folder named "Desktop – Abby's MacBook Air". First symptom of what is coming: test paths containing `%20`. |
| 23:02 | `6576faf` | Version diff. |
| ~23:45 | — | The hand-off pack is written and tested but not yet committed when Vite begins failing with an empty module export — the first sign of iCloud eviction. It survives as `5cfc0be` in the new history. |

That night, durable builds were verified live: two free re-checks on the test app kept running through a Ctrl-C
and a server restart.

So the foundation the rest of this timeline builds on — the evidence model, the durable build, the harness, the
upgrade path — was in place before the first surviving commit. The three days below are the period in which that
foundation was used, tested by people other than the owner, and found wanting in the ways recorded here. Worth
noting that the pattern starts before them: **the foundation's own first hour was the harness finding the
template wanting.**

## The surviving record

Assembled from the repository's own history, 18 September to 4 October 2026, with `main` at `157ddc3` (11:37 on 4
October) as the cut-off. Days 1–3 list every commit, 116 of them, to 17:32 on 20 September. From the evening of the
20th each row is one change as it reached `main`: a pull request, shown by its title and number, or a commit made
directly on `main`. The commits inside each pull request are not listed; the commit id is the merge. Times are
Eastern time (the owner's) and are commit times, so they record when a change was finished rather than when it was
begun; for a pull request that is when it was merged. Subjects and pull-request titles are reproduced as written:
they were written to say what changed and why, and several of them are the primary record of a decision.

The whole record comes to 1,784 commits to the cut-off (882 when this record stopped at 10:52 on 27 September),
of which 569 reached `main` as the changes listed from the evening of 20 September onward (267 to 27 September),
528 of them as pull requests (226). Seventeen of those were rebased onto `main` rather than merged, twelve on
26 September and five on 3 October, so their commit is the change itself. Two more pull requests that GitHub
shows as merged into `main`, #308 and #383, both claims, have no change of their own: their commits reached `main`
inside other pull requests. No commit at all is dated 30 September to 2 October. `COORDINATION.md` counts over a longer window and on a
different basis: all 655 changes to `main` from 09:32 on 18 September (86 of them before the evening of the 20th),
and pull requests from GitHub's record rather than git, 551 merged, 548 of them into `main`. The 548 are these 528,
4 merged before the evening of 20 September (#1 to #4), #308 and #383, and 14 from 19 to 23 September (#5, #7 to #18, and #20)
whose commits reached `main` under other hashes. A summary figure is in `figure-timeline.html`.

The project was built by an owner who is not a programmer, working with AI agents, against a fixed template and
the OWASP Secure by Design, ASVS 5.0 and AISVS 1.0 checklists. Two people other than the owner used it, both on
19–20 September. From 22 September a second version, `sv`, was built beside it, and on 26 September `sv`
replaced it at the top of the repository. From 29 September to 3 October a comparison study, run by another
session outside this repository, used `sv` on five AI-built apps, and on 4 October the same session reviewed
`sv`'s code in depth.


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

## Day 3, continued — the evening of 20 September

22 commits, 18:12 to 20:25, all made directly on `main`.

The evening turned from building to recording. The paper's factual material was assembled from the repository
rather than from memory, the first session's lost two days were written down (`0666af1`, `714ceac`), and the
brand, the MIT license and an anonymized friend's app went in. At **20:25**, commit `7fa07d6` was `main` when
the repository was made public. The tag `v1-paper` marks it: it is SecureVibe v1 as the paper describes it.

| time | commit | pull request | change |
|---|---|---|---|
| 18:12 | `0427564` |  | Assemble the paper's factual material from the record rather than from memory |
| 18:15 | `c978034` |  | A low score is not a verdict when the app was never run |
| 18:30 | `9b292bb` |  | Five identical findings in a comparison, and no way to tell them apart |
| 18:32 | `0238a55` |  | What the golden apps can and cannot tell you, before the paper leans on them |
| 18:42 | `6ae4200` |  | What three days of real use cost, and what made it cheaper |
| 18:54 | `94c2644` |  | UX-01 cited nothing, and the check that should have caught it never saw it |
| 18:55 | `0666af1` |  | Write down what the first session knew, for the sessions after it |
| 18:56 | `507153a` |  | The repository's history is not the project's history |
| 18:59 | `6e23d61` |  | Bring back the copy-the-path row beside each finding, and offer the scan data on the Security page |
| 19:04 | `714ceac` |  | The two days the record lost, recovered from the session that lived them |
| 19:06 | `af8c995` |  | Pass the app folder to every finding card, not only the two that needed it least |
| 19:12 | `c5128c1` |  | Copy the full path as a small button on the finding's location line, not a row under every finding |
| 19:19 | `6a536aa` |  | Claim the brand-materials item |
| 19:20 | `5f11a94` |  | Give SecureVibe its face: favicon, the padlock in the top bar, and one mascot per state |
| 19:22 | `4b5b6e2` |  | Restore the self-assessment profile and triage lost with the iCloud eviction |
| 19:24 | `ef8d7aa` |  | A PDF that only exists after somebody clicks a dialog is not an archive |
| 19:28 | `d72de20` |  | Self-assessment re-run on 20 September (no AI) |
| 19:29 | `9dc8140` |  | A rate-limited anonymous probe is inconclusive, and a link from data is a link only when it is one |
| 19:30 | `3631e05` |  | The brand materials item landed; remove it from the backlog |
| 19:33 | `86ddf82` |  | Four critical and 113 high against ourselves, and almost none of it real |
| 20:11 | `d5d5719` |  | MIT licence, a note for strangers, and a friend's app made anonymous |
| 20:25 | `7fa07d6` |  | Say in the README that the commit log is candid on purpose |

## 21 September

No commits.

## Day 4 — 22 September: a second version begins

10 commits, 21:58 to 23:46.

In one evening a second SecureVibe began: **`sv`**, a language-agnostic checker written in Rust. v1 builds an
app from a fixed template and checks it; `sv` checks an app written in any language by anyone. Its first
commit (`2ff6beb`) records that 39% of the requirement exclusions it had inherited from v1 did not hold for an
arbitrary app. The same evening added the dependency scanner, the corroborators (independent evidence that
confirms or contradicts what the owner says the app does) and Docker.

The eight commits shown at 21:58 to 23:08 reached `main` together at 23:15. For them, the time shown is when
each was written.

| time | commit | pull request | change |
|---|---|---|---|
| 21:59 | `59cbc64` |  | Claim the CI hang, now that the minutes are free |
| 21:58 | `2ff6beb` |  | A language-agnostic second version, and 39% of its exclusions were inherited fiction |
| 22:15 | `3e0812a` |  | Claim the inherited-exclusions item |
| 22:24 | `b67c66c` |  | Replace the inherited exclusions, and stop reading silence as a no |
| 22:31 | `369ed10` |  | Claim the dependency scanner |
| 22:40 | `f8e0bff` |  | The dependency scanner, and the three things that stop it concluding |
| 22:51 | `9e1f94a` |  | Claim the corroborators |
| 22:57 | `108efbb` |  | Corroborators, and the asymmetry they needed that the scanner did not |
| 23:08 | `5be999d` |  | Docker is here now, so stop saying it is not |
| 23:18 | `517279a` |  | Bump the pip group across 1 directory with 4 updates |

## Day 5 — 23 September: pull requests and CodeQL

12 commits, 11:04 to 22:55.

CodeQL became a committed workflow, the Rust checks joined CI, and from 22:34 changes began to arrive as pull
requests (#19 onward) rather than as commits pushed to `main`. Every day after this is recorded mostly as pull
requests.

| time | commit | pull request | change |
|---|---|---|---|
| 11:04 | `8c39812` |  | CodeQL as a committed workflow, with the scanner fixtures excluded on purpose |
| 11:04 | `b6e9689` |  | CodeQL: run by hand first, and say the Rust leg is untested |
| 21:36 | `bd46759` |  | Run the Rust checks, so the guards against drifting apart actually run |
| 21:36 | `828dd89` |  | A backslash before a pipe rewrote the column beside it |
| 21:36 | `cd2a6f7` |  | Claim the evaluation harness while the template change is checked |
| 21:36 | `f7f7fc5` |  | Release the evaluation harness |
| 22:32 | `6d716df` |  | "Client's habit" produced an app that would not parse |
| 22:32 | `b750dbc` |  | Claim the evaluation harness for the recipe change |
| 22:32 | `b766ca7` |  | Release the evaluation harness |
| 22:34 | `16ebc72` | #19 | Say why each deliberate choice is deliberate, where CodeQL reads it as a fault |
| 22:50 | `789cbef` | #21 | Record that CodeQL suppression comments are not honoured here, and that a dismissal dies when its line moves |
| 22:55 | `5d8ba92` | #22 | Note push protection beside the CodeQL notes: test keys are built from pieces, never allow-listed |

## Day 6 — 24 September: both versions at once

37 changes reached `main`, 07:40 to 23:35: 37 pull requests out of 146 commits in all.

v1 kept changing in response to its users: carry on a stopped build (#25), check an app again (#26), take a
zip (#38), "not applicable" with an auditable reason (#42), and American English throughout (#46). At
**18:26**, `sv` reached `main` as one pull request (#35, 44 files, 11,504 lines): *the checks, the fence, the
corroborators and the reports*. By midnight it read eleven grammars (#49), had four more code rules (#55),
credited an app's own tests (#53), and had loaded the Secure by Design checklist (#54).

| time | commit | pull request | change |
|---|---|---|---|
| 07:40 | `f9a8696` | #23 | Write jsString's escape in the shape CodeQL recognises; behaviour unchanged |
| 07:43 | `bd23941` | #24 | Backlog: a check that no source file holds a raw line separator |
| 08:08 | `3ba4d3c` | #25 | Offer to carry on a stopped build from the Results page |
| 08:12 | `65f5c5d` | #26 | Check this app again from the Results page, free or with the AI review |
| 08:18 | `cc5d751` | #27 | Name the skipped tests, so 105 of 163 passing stops reading as 58 failures |
| 08:48 | `b6bba16` | #28 | The runtime probes' HTTP client refuses any host but this computer |
| 10:48 | `ea13712` | #29 | A build in progress is visible from every page, and the app record names it from the start |
| 10:55 | `3b257ec` | #30 | Let a record be blank while the owner is still typing its name |
| 17:30 | `f2ed52c` | #31 | A follow-up question can take several answers when it adds to a list |
| 18:05 | `da54c13` | #32 | Run the web test, and check for raw line separators |
| 18:12 | `0c503d9` | #33 | The rating says which standard it comes from |
| 18:21 | `1872d86` | #34 | A check for damaged saved answers |
| 18:25 | `adc2814` | #36 | Copy an application |
| 18:26 | `9613eb5` | #35 | sv: the checks, the fence, the corroborators and the reports |
| 18:29 | `1120a42` | #37 | What only you can do: a list from facts |
| 18:55 | `ef109b2` | #38 | Take a zip: unpacked here, with every path checked |
| 18:59 | `8d9493e` | #40 | The self-assessment leaves out the rules that assume a generated application |
| 18:59 | `1b16d92` | #39 | Three more finding classes that were about our conventions, not the app |
| 19:02 | `3010105` | #41 | The AI review reads every language it can, and says how many files it was handed |
| 19:12 | `8cc3d43` | #42 | Not applicable, with a reason: an answer the reports can audit |
| 19:16 | `2eb879a` | #43 | Ask whether the organisation has a central sign-in system, so AC-02 can be not applicable |
| 19:18 | `f08a7b6` | #44 | Backlog: two items that are done read as done |
| 19:27 | `194e2e5` | #45 | An uploaded app is checked as soon as it is uploaded |
| 19:32 | `5b39dfb` | #46 | One spelling standard: American English in everything a person reads |
| 19:36 | `3a66a02` | #47 | Real reports for a check made without answers |
| 19:40 | `ac65ef7` | #48 | Without the answers, the AI review reads the code against ASVS Level 1 |
| 19:52 | `d8e1675` | #49 | sv: the language's own tools, eleven grammars, and the script inside a page |
| 19:53 | `1e836e2` | #50 | Download every app's reports at once |
| 20:08 | `3a3c727` | #51 | An uploaded app is asked only what decides which rules apply |
| 20:12 | `e1408d0` | #52 | The rest of the virus scanning |
| 22:22 | `6d955ce` | #53 | Credit the app's own tests, and fix every citation they exposed |
| 22:52 | `a4df0a5` | #54 | Load the Secure by Design checklist, and say what it cannot check |
| 23:00 | `256ff3d` | #55 | sv: four more rules that read the code — file paths, weak hashes, weak ciphers, open redirects |
| 23:20 | `74d6a4a` | #56 | sv: read .tsx with the TSX grammar, and let no unparsed file support a clean claim |
| 23:23 | `6f6aec8` | #57 | Read the test runner's own report, so a suite that mostly passed counts |
| 23:26 | `1ae368d` | #58 | sv: Go dependencies that never matched, build.gradle.kts, and a corroborator for multiple-services |
| 23:35 | `181b798` | #59 | sv: keep the Secure by Design controls a single app still needs |

## Day 7 — 25 September: `sv` reaches the running app

57 changes reached `main`, 00:08 to 23:30: 57 pull requests out of 184 commits in all.

`sv` gained an MCP server, so an AI coding tool can ask it for the same report (#65); seeded test users, to
ask a running app what a signed-in person can reach (#66); Dart, Swift and shell scripts; semgrep's rules
mapped to requirements and checked against a real run; a generated coverage document (#72); and the first
Level 1 checks against the running app (#74). The first **review findings** appear: a session reading another
session's work found that a suppressed finding was credited as a clean run (#73), and that two fences were not
closed (#77). `sv` also gained a threat model in three parts (#95–#97), the security notes (questions no
tool can answer, #100), the design questions (#103), and `sv probe` for a live site (#112). v1 gained PDF
reports written without a browser (#84).

| time | commit | pull request | change |
|---|---|---|---|
| 00:08 | `c38c423` | #60 | Say what the dependency checks examined, and fix three more wrong citations |
| 00:23 | `8c30ea7` | #61 | sv: dependency manifests anywhere in the app; clean checks support design-review requirements (SBD-AC-05) |
| 00:29 | `4f6fe90` | #62 | sv: remap Brakeman's rule ids from its code table, tested against a real run |
| 01:05 | `1d1d6ea` | #64 | sv: ground the Secure by Design levels in ASVS through a crosswalk |
| 01:08 | `1a8b44b` | #65 | sv: the MCP server — the same report, offered to an AI coding tool |
| 01:31 | `1969234` | #66 | sv: seeded users — ask the running app what a signed-in user can reach |
| 02:04 | `4104011` | #67 | sv: Dart and Swift, and a rule claims nothing for a language it was not taught |
| 08:27 | `511f3f4` | #68 | sv: the last three rules untaught a language (Rust shell and ciphers, C redirects) |
| 08:32 | `8553a02` | #69 | sv: semgrep's rules mapped to requirements, checked against a real run |
| 10:36 | `dc58456` | #70 | sv: shell scripts read and checked; signed-in checks 3x faster |
| 10:42 | `d2640bd` | #71 | sv: fix an overclaim from #69; a clean semgrep run is credited only with rules it ran, for the app's languages |
| 11:16 | `4113885` | #72 | sv: a generated coverage document for ASVS, AISVS, and Secure by Design |
| 11:39 | `3ad7220` | #73 | Review finding: a suppressed finding is credited as a clean run |
| 12:04 | `bf11aa3` | #74 | sv: Level 1 checks against the running app (passwords, default accounts, session ids, .git) |
| 12:14 | `7e82b44` | #75 | sv: "Tests to write", the requirements with no evidence and no test naming them |
| 12:15 | `32d3366` | #76 | A clean scan is only evidence for a requirement some static rule looks for |
| 12:31 | `7cf35e7` | #78 | Stop tracking the node_modules symlinks two of my commits added |
| 12:50 | `06a4667` | #79 | sv: a tool told to look away is not credited with a clean run |
| 13:27 | `07fac91` | #77 | Two fences that were not closed: an MCP write and the probe fallback |
| 13:46 | `a3b18f6` | #80 | Tests for nine requirements that had no evidence, and the baselines they raise |
| 13:53 | `08c04f1` | #81 | sv: semgrep is handed the app's files by name, and checked for reading them |
| 15:55 | `fae8a4d` | #83 | sv: semgrep's AI rules count against AISVS, and never for it |
| 15:59 | `9d4cbed` | #84 | Reports as PDF files, written by SecureVibe with no browser |
| 16:11 | `83583ea` | #85 | sv: a clean result says what the rule looked for, not only what it read |
| 16:14 | `9afde3b` | #86 | Paper size for the PDF reports: US Letter by default, or A4 |
| 16:22 | `96d158d` | #87 | Backlog: release the recipe-library claims |
| 16:27 | `bcb75c0` | #88 | Claim: an assistant that is working should say so |
| 16:30 | `b0280f6` | #89 | sv: five more Level 1 questions for the running app, two for semgrep |
| 16:38 | `9cffe17` | #90 | A check for the slow button: a form that asks the assistant must say it is working |
| 16:41 | `ff2dd6b` | #91 | sv: can a password be changed, and does that need the current one |
| 17:02 | `e083ad7` | #92 | Threat modeling without the AI tool: the investigation |
| 17:08 | `7542161` | #93 | sv: account deletion ends every session, password hints, ws:// addresses |
| 17:19 | `9661ffe` | #94 | Backlog: what the remaining Level 1 and 2 requirements need |
| 17:25 | `40feb45` | #95 | Threat model, part 1: the rules as data, and each threat's status |
| 17:33 | `4680c41` | #96 | Threat model, part 2: a Threats section in the reports |
| 17:39 | `0257f2b` | #97 | Threat model, part 3: twelve threats for what v1 did not model |
| 17:45 | `4e95211` | #82 | Review finding: the report understates a gap the sbom states correctly |
| 18:03 | `69270a2` | #98 | American spelling in the agnostic variant |
| 18:45 | `7304398` | #100 | The security notes: the questions no tool can answer |
| 18:50 | `369b3df` | #101 | Correct the policy-numbers estimate in the backlog |
| 19:16 | `824022d` | #103 | The design questions: how the app is built, and the weakest tier there is |
| 19:48 | `2e67018` | #99 | Separate running an OAuth authorization server from using OAuth |
| 19:49 | `b0968d0` | #102 | Build the report's dependency gap from the bill of materials |
| 20:05 | `f445ba2` | #104 | Policy numbers: hold the app to the guessing limit you state |
| 20:16 | `d6e853d` | #105 | Three more Level 2 questions for the running app |
| 20:48 | `7a27906` | #107 | An upload entry, and four Level 1 questions about files |
| 20:53 | `11eeda4` | #106 | The short version, and an end to the wall of text |
| 21:16 | `0211434` | #109 | What only you can check |
| 21:21 | `416b16a` | #108 | Read what the app wrote down about what the probes did |
| 21:33 | `acdb11d` | #110 | A sweep of every requirement no check reaches |
| 21:41 | `63230dd` | #111 | Where to look, and the counts strongest first |
| 22:13 | `6edcb33` | #112 | sv probe: ask the live site the questions only it can answer |
| 22:36 | `355b1b5` | #114 | Hold known vulnerabilities to the owner's time frames (V15.2.1) |
| 23:11 | `4829746` | #115 | What a log line and a download carry: four Level 2 questions |
| 23:11 | `b1b0b35` | #116 | What a new tool, service, or process would reach |
| 23:20 | `68097c6` | #113 | Four more Level 1 questions, from the sweep |
| 23:30 | `ea5cc3b` | #117 | Put known vulnerabilities in the report (sv report --advisories) |

## Day 8 — 26 September: the busiest day, and the move

118 changes reached `main`, 00:00 to 23:44, all of them pull requests: 106 merged and 12 rebased onto `main`, out
of 333 commits in all.

Most of the day went on questions `sv` can ask only of a running app, each fenced inside Docker: a mail server,
for password reset and emailed codes (#120); two-factor codes (#129); a test provider for "Sign in with Google"
(#138); a real browser (#142); Encrypted Client Hello and the HSTS preload list for a live site (#139); a test model and a test
MCP server for an app's AI feature (#189, #202). Review findings kept arriving. The fence test was found to
count any failure as a block, and was given a container control on the owner's Mac (#148). Other decisions:
semgrep adopted with its `p/default` rules (#211; the owner's license decision is recorded in #184), MITRE ATLAS adopted in
part (#150), and `sv` packaged as a container image published from CI (#205, #208).

In the evening the owner decided that `sv` becomes the repository's front page. The tag `v1-paper` was made at
19:59 and given a Zenodo DOI. Sessions added their views to the backlog (#215, #217, #219). The move was
claimed (#223), `v1-final` was tagged at 20:52, and at **21:22** the move landed (#224): 1,068 files changed,
v1 moved to the `v1` branch, and `sv` moved to the top of the repository. History was not rewritten. Cleanup,
`sv`'s own security policy and `sv bundle` followed before midnight.

| time | commit | pull request | change |
|---|---|---|---|
| 00:00 | `e4c8393` | #118 | GraphQL, WebSocket, and a log line's format: four Level 2 questions |
| 00:41 | `a1a85e5` | #120 | A mail server inside the fence, and password reset |
| 01:25 | `5c1ee77` | #121 | Signing in with an emailed code: four Level 2 questions |
| 08:05 | `7850ee0` | #123 | Ask sign-up about breached passwords (V6.2.12) and context-specific words (V6.2.11) |
| 08:08 | `51a8244` | #122 | Copy the uploaded body, as the archive route does |
| 08:22 | `9898363` | #125 | Try skipping a step of a multi-step flow (V2.3.1) |
| 08:30 | `f1f805f` | #127 | Record that the V6.2.12 password is breached, and add the Pwned Passwords API item |
| 08:42 | `f8c9264` | #126 | CodeQL as an outside tool: following a value to where it is used |
| 08:52 | `7bf2b46` | #124 | Review finding: the threat model's citations cannot be guarded as they are |
| 08:54 | `07b5a99` | #129 | Check two-factor codes: once only, and only while current (V6.5.1, V6.5.5) |
| 09:01 | `f9a77f4` | #128 | Review finding: an unanswered question excludes requirements (#128) |
| 09:07 | `901e8e6` | #130 | Check whether the guessing limit believes a made-up address (V15.3.4) |
| 09:15 | `0c362a0` | #131 | Claim the slow mode (securevibe-e9) |
| 09:21 | `65020b2` | #132 | Review finding: the two-factor reuse check can credit V6.5.1 on a step boundary (#132) |
| 09:23 | `5ad525e` | #133 | An unanswered manifest question excludes nothing, whatever the scan found |
| 09:33 | `1a49800` | #135 | Guard the threat model's citations through their `because` phrases |
| 09:43 | `47659c8` | #134 | Review finding: a leaky guessing limit inverts the spoofed-address check (#134) |
| 09:46 | `988fcc7` | #136 | Session timeouts, waited out with sv run --slow (V7.3.1, V7.3.2) |
| 09:53 | `9ecff2b` | #137 | Claim the live-site TLS checks (securevibe-e9) |
| 10:03 | `860a0f6` | #138 | sv: check "Sign in with Google" against a test provider inside the fence |
| 10:12 | `92f9494` | #139 | sv probe: Encrypted Client Hello and the HSTS preload list (V12.1.5, V3.7.4) |
| 10:19 | `1b68197` | #141 | Claim the leaky-limit fix (securevibe-e9) |
| 10:22 | `00a312d` | #140 | Claim the real browser (securevibe-e8) |
| 10:31 | `74fe88c` | #142 | sv: check pages in a real browser inside the fence (V3.2.2, V7.4.4) |
| 10:36 | `8df669c` | #143 | Claim the Pwned Passwords refresh item |
| 10:37 | `3fa7f89` | #144 | The made-up-address check survives a leaky limiter (V15.3.4) |
| 10:44 | `b0a9ad4` | #146 | Claim the two-factor rollover fix (securevibe-e9) |
| 10:44 | `dcf7c80` | #147 | Claim the fence test control fix |
| 10:49 | `b341569` | #148 | sv: give the fence test a container control, and stop reading failures as blocks |
| 10:50 | `771553d` | #149 | Keep the breached-password evidence current through Pwned Passwords |
| 10:51 | `c22f983` | #145 | sv: sign out in the real browser and check its storage is emptied (V14.3.1) |
| 11:01 | `d41d004` | #151 | Claim reading Maven and Gradle version ranges |
| 11:02 | `7262a55` | #152 | Two-factor reuse check: judge a refusal only within its own step (V6.5.1) |
| 11:03 | `64c7e40` | #150 | MITRE ATLAS investigation: adopt in part (claim and recommendation) |
| 11:12 | `53751b4` | #153 | Claim V6.4.1, the emailed-code lifetime, and more probes (securevibe-e9) |
| 11:42 | `7e5a519` | #155 | Check the activation code emailed at sign-up (V6.4.1) |
| 11:43 | `1595c2b` | #154 | sv: cite MITRE ATLAS techniques on the six AI threats, for a reviewer |
| 11:49 | `e35bd90` | #156 | Read Maven and Gradle versions for the pinning check |
| 11:53 | `d83350f` | #157 | sv: ask whether a JSON request can skip the CORS preflight (V3.5.2) |
| 12:08 | `24a6bbd` | #158 | Note a possible duplicate backlog entry, and claim the Semgrep registry run |
| 12:15 | `169bcf8` | #159 | Wait out an emailed sign-in code's ten minutes with --slow (V6.5.5) |
| 12:24 | `419e852` | #160 | Ask six more questions of any running app |
| 14:12 | `d2a41fa` | #161 | Check the semgrep rule map against a real registry run |
| 15:16 | `de97e6c` | #162 | Flag the unrun semgrep rules, and ask for recommendations |
| 15:22 | `6de9ca4` | #165 | Add securevibe-e9's recommendation on semgrep's packs |
| 15:31 | `a4fa068` | #164 | Semgrep: count only the rules its packs load (with e8's recommendation and claim) |
| 15:43 | `a6eb96d` | #167 | Claim V4.4.3 and V4.4.4; record the owner's semgrep answer |
| 15:46 | `12f52b2` | #170 | Add keen-meninsky's semgrep recommendation to the backlog |
| 15:47 | `faabe34` | #168 | sv: ask whether a sign-in checks which provider it came from (V10.2.2) |
| 15:51 | `474798e` | #171 | Claim the AI pack for semgrep, step 2 |
| 16:02 | `652ae40` | #172 | sv: find ws:// addresses written into the code, as sv's own rule (V4.4.1) |
| 16:14 | `043fc79` | #174 | sv: find four more ways of writing a path or a redirect (V5.3.2, V3.7.2) |
| 16:17 | `f019542` | #173 | Run semgrep's AI pack for apps that may call a model |
| 16:22 | `53ca786` | #177 | Claim the step 3 semgrep measurements |
| 16:33 | `107c3e1` | #176 | Ask whether a private WebSocket needs a real session (V4.4.3, V4.4.4) |
| 16:34 | `a85b1d2` | #178 | Record the step 3 semgrep measurements |
| 16:44 | `28f8a79` | #179 | Record the owner's lean toward p/default, and the license question |
| 16:44 | `fdca8b1` | #180 | Mark the evaluation harness in use |
| 16:59 | `5e074d7` | #183 | Backlog: testing an app's AI feature, a fake model or garak |
| 17:05 | `84fff3f` | #175 | sv: the AI coding tool interviews the owner, and its own answers are labeled |
| 17:14 | `d2aea72` | #185 | sv: record the checks made by hand ([checked-by-hand]) |
| 17:19 | `a2082e4` | #186 | Claim the fake model; record the owner's AISVS decision |
| 17:23 | `c4e36d1` | #169 | Review finding: ten manual requirements that no catalog explains (#169) |
| 17:24 | `7d61ad1` | #187 | sv: record the checks made by hand ([checked-by-hand]) |
| 17:38 | `a352e33` | #181 | Backlog: V11.3.3 is the one no pack recovers, and could be an AST rule (#181) |
| 17:40 | `cea45df` | #188 | sv backlog: claim the ten manual-only requirements no catalog explains |
| 17:48 | `0171385` | #182 | Backlog: garak findings as Thoughts on the existing fake-model-or-garak entry (#182) |
| 17:48 | `65ac9a9` | #190 | sv: explain every requirement only a person can settle, and test that it stays so |
| 17:49 | `1f0da09` | #189 | Ask an app's AI feature through a test model inside the fence |
| 17:58 | `4ee47fa` | #191 | Claim C12.1.3 and C12.2.1 (securevibe-e9) |
| 18:06 | `b3cbb4f` | #184 | Free the evaluation harness, record the Semgrep license decision and the golden-app numbers |
| 18:08 | `5ecc47f` | #193 | Backlog: a walk-through for building from scratch in any AI tool (#193) |
| 18:08 | `12f094e` | #192 | sv backlog: claim V11.3.3 as sv's own finding-only AST rule |
| 18:13 | `9116a57` | #194 | Read the AI feature's own log lines (C12.1.3, C12.2.1) |
| 18:14 | `0538663` | #195 | Claim adopting p/default for semgrep (option B) |
| 18:24 | `cefe215` | #196 | sv: find encryption that cannot show it was changed, as sv's own rule (V11.3.3) |
| 18:28 | `5b1372c` | #197 | Claim C11.2.2, C9.6.1, C10.4.1, and C10.4.2 (securevibe-e9) |
| 18:38 | `ce03269` | #198 | Backlog: packaging sv, a container now and a download later (#198) |
| 18:44 | `6a7d3e9` | #199 | Hold the AI feature to a stated rate limit (C11.2.2) |
| 18:55 | `63e12ac` | #200 | Mark the evaluation harness in use |
| 19:00 | `55122dc` | #201 | Try the AI feature's kill switch on a second copy of the app (C9.6.1) |
| 19:17 | `0521739` | #202 | Check MCP tool results through a test MCP server (C10.4.1, C10.4.2) |
| 19:17 | `6e03060` | #203 | Free the evaluation harness |
| 19:28 | `0acfe49` | #204 | Backlog: what the owner's first build from scratch found, and a zip (#204) |
| 19:32 | `80e7d3b` | #206 | Claim the committed sv container (securevibe-e9) |
| 19:36 | `4d900c2` | #205 | sv: package sv as a container image, with a test that drives it as an AI tool would |
| 19:43 | `58b240e` | #207 | Credit the container to securevibe-e8; withdraw e9's duplicate claim |
| 19:48 | `b01d952` | #208 | sv: publish the image to GitHub's container registry from CI |
| 19:50 | `a761fbd` | #209 | Claim V4.4.2 for a private WebSocket (securevibe-e9) |
| 19:53 | `76156b3` | #210 | Backlog: promote sv to the top of the repository, keep v1 for the paper (#210) |
| 20:02 | `a5b82f3` | #212 | sv backlog: claim the walk-through; add a community-standards entry |
| 20:04 | `d3cd2e5` | #213 | Ask V4.4.2 of a private WebSocket with the signed-in session |
| 20:07 | `8ac64c6` | #215 | Thoughts on promoting sv: what v1 needs to stay usable |
| 20:07 | `8ced5fb` | #216 | Backlog: v1-paper is tagged and released (#216) |
| 20:08 | `afc8368` | #218 | sv: a walk-through for building an app with sv alongside; never cancel runs on main |
| 20:09 | `cc3c5bd` | #214 | Claim the no-referrer, Origin: null self-refusal check (securevibe-e9) |
| 20:10 | `153836a` | #211 | Adopt p/default for semgrep, and fix two template lines behind its false alarms |
| 20:17 | `e91c717` | #221 | Backlog: record what the sessions agreed about the promotion (#221) |
| 20:22 | `928e9cb` | #217 | Backlog: thoughts on promoting sv, from the test side |
| 20:28 | `756f5ce` | #220 | sv: never read sv's own report as the app; stop two false alarms that changed correct code |
| 20:29 | `a79e75c` | #222 | Say when an app refuses its own forms under no-referrer |
| 20:38 | `9861f6e` | #219 | Thoughts on promoting sv (relaxed-nobel-27acfa) |
| 20:46 | `412092d` | #223 | Claim the move: sv to the top, v1 archived |
| 21:22 | `278575a` | #224 | Promote sv to the top of the repository; v1 moves to the v1 branch |
| 21:31 | `8802048` | #225 | Claim items 5 and 9 of the owner's first build (securevibe-e9) |
| 21:35 | `d6e781c` | #226 | Dependabot: watch the Rust packages |
| 22:03 | `b111718` | #227 | Claim the post-move cleanup and sv's security policy |
| 22:14 | `07acd80` | #228 | Clean up after the move, and give sv its own security policy |
| 22:23 | `7f7ea72` | #229 | Keep a failing suite's last lines in the report, credentials cut short |
| 22:25 | `048c785` | #233 | Backlog: private vulnerability reporting is on; the owner's paths are updated |
| 22:33 | `afa098f` | #234 | Say in one line whether sv report started the app |
| 23:16 | `6b62bbb` | #235 | Getting started: VS Code as the owner tried it; backlog items from that run |
| 23:19 | `15a372d` | #237 | Claim: a zip of the whole result (sv bundle) |
| 23:23 | `c4b2868` | #236 | Claim items 3 and 4 of the owner's first build (securevibe-e9) |
| 23:27 | `82e8043` | #238 | Claim: let the owner confirm what the AI tool said (with the owner's decisions) |
| 23:35 | `d992abc` | #239 | Security notes: say who wrote each answer, and stop crediting the tool's as the owner's |
| 23:36 | `7dc9dfb` | #240 | A rate limiter is not evidence of a public API |
| 23:44 | `e4054fe` | #241 | sv bundle: the app, its report and a SHA-256 for every file in one zip, with secrets left out |

## Day 9 — 27 September: the paper, the first records, and a review

89 changes reached `main`, 00:02 to 23:44, all of them pull requests, out of 270 commits in all. (An earlier
version of this record stopped at 10:52, after 11 of them, and counted 30 commits to that time; recounted at the
cut-off, 28 commits of the day are dated before 10:52.)

A person can now confirm what the AI coding tool wrote on their behalf, and it counts at their own tier
(#242). GitHub's community-standards files went in (#245). Three things the owner tripped over in their first
build from scratch were fixed (#248), and three more items from that build followed (#249–#251).

From late morning the paper was written into the repository: this timeline and its figure (#257), figures on
security, cost, usability, and how faults were caught (#264), the two OWASP Top 10 analyses (#283, #287), the
v2 self-assessment (#292), and the analysis of the decision records (#300). `sv` wrote down its first decision
records the same day (#271, #274, #312). It gained rules for the AI coding tool to follow while it codes, from
AISVS Appendix C (#268, #276), a reader for an app's GitHub Actions workflows (#282), and a grammar for C++
(#259). After the owner's decisions on false alarms (#294), the report learned to hold one finding per weakness
and line, a person's record that a finding is a false alarm or an accepted risk, and findings in test code
listed apart (#297, #303, #316, #321). At 18:56 a session's review of `sv` added thirteen items to the backlog
(#315), and most of the evening went on them: one walk of the app (#320), options read as options (#324),
patterns compiled once (#325, #326), a release profile (#330), time limits and a Ctrl-C that cleans up (#332),
and the container image run as a user of its own (#333).

| time | commit | pull request | change |
|---|---|---|---|
| 00:02 | `d508759` | #242 | Let a person confirm what the AI coding tool said, and count it at their own tier |
| 00:09 | `a0fa9c2` | #243 | Claim: GitHub's community standards (with the owner's code-of-conduct choices) |
| 00:11 | `117b16a` | #244 | Backlog: item 4 was done by another session |
| 00:16 | `fa37315` | #245 | Community standards: code of conduct, contributing guide, issue and pull request templates |
| 00:17 | `f9ac892` | #246 | sv bundle: an MCP tool, the commit, and the data categories |
| 00:30 | `9985562` | #247 | Claim items 6, 7, and 8 of the owner's first build |
| 00:45 | `84f3d09` | #248 | Three things the owner's first build tripped on: no sv command, no git, and web search counted as rag |
| 00:57 | `7be02ef` | #249 | A corroborator for web-search (claim, then the work) |
| 01:12 | `e71bae1` | #250 | Order the interview's questions by what is most at stake (claim, then the work) |
| 01:27 | `0013da9` | #251 | Two services built from the app, read from its compose file (claim, then the work) |
| 10:52 | `c5ae4f9` | #253 | Claim: a section holding only the tool's disclaimer is not an answer (securevibe-e9) |
| 11:01 | `e56a2b3` | #252 | A generates-media question for C7.4.4, and starter capabilities that start unanswered (claim, then the work) |
| 11:08 | `18d16f4` | #254 | Claim the paper timeline update |
| 11:10 | `09f41b0` | #255 | A section holding only the tool's own byline is not an answer |
| 11:15 | `d9d0911` | #256 | Take Dependabot's three updates, with the fixes they need |
| 11:18 | `bc65b3c` | #257 | Paper: the timeline through 27 September, and a figure of the whole project |
| 11:39 | `6c7f152` | #258 | Claim the paper figures on security, usability and cost |
| 11:47 | `50eca0e` | #259 | A grammar for C++: all twelve code rules taught, or say why not |
| 11:56 | `74d2b2c` | #260 | Claim AISVS Appendix C as coding-time rules for the AI tool (securevibe-e9) |
| 12:06 | `988343f` | #261 | Say beside the code why CodeQL's four open alerts are deliberate |
| 12:08 | `ae72003` | #262 | Claim: script in a page written the way a browser reads it |
| 12:13 | `c20597e` | #264 | Paper: figures on security across both versions, cost and speed, usability, and how faults were caught |
| 12:38 | `e40a485` | #265 | An unanswered data list no longer counts as "no personal data" |
| 12:47 | `c468649` | #267 | Read a page's tags the way a browser does |
| 13:05 | `41634b7` | #268 | Give the AI coding tool rules to follow while it codes, from AISVS Appendix C |
| 13:17 | `169bc5d` | #269 | Claim: Appendix C in a section of its own in the report (securevibe-e9) |
| 13:18 | `7f262e3` | #270 | Claim: the decisions not yet written down as ADRs |
| 13:20 | `9e291ad` | #266 | The owner's three decisions, and V8.3.1 supported (not settled) by the admin-page probe |
| 13:26 | `57bc16d` | #271 | sv's first decision records, and ADR-012 named as v1's |
| 13:33 | `bbd81f1` | #263 | Poll: should CodeQL scan v1, and should sv keep v1's sample answer sets? |
| 13:45 | `1c2e4ce` | #273 | Claim: a record superseding ADR-012's ruling on other languages |
| 13:52 | `5b2a78a` | #274 | ADR-018: sv checks any language, with rules of its own |
| 13:57 | `c2b962e` | #275 | data/README.md: what each data file is and what reads it |
| 13:59 | `9a3fda5` | #276 | Count Appendix C apart from the app's own requirements, in a section of its own |
| 14:07 | `26fcb6e` | #277 | Claim: read the app's GitHub Actions workflows |
| 14:25 | `31e0b1c` | #278 | Remove the eight v1 files in data/knowledge that nothing on main reads |
| 14:25 | `dd49d56` | #279 | Claim V14.2.3: account details sent to other hosts (securevibe-e2) |
| 14:40 | `2483b4d` | #281 | Claim the OWASP Top 10 analysis for the paper |
| 14:41 | `cf7cff9` | #280 | V14.2.3: account details a signed-in page sends to another site, seen from the real browser |
| 14:44 | `139ad42` | #282 | Read the app's GitHub Actions workflows for what Appendix C warns about |
| 14:47 | `0e3a343` | #283 | Paper: the project's security faults against the OWASP Top 10:2025 |
| 14:50 | `38ccc78` | #284 | Claim the OWASP agentic Top 10 analysis for the paper |
| 14:53 | `75f7fde` | #286 | Keep the checkout token out of the job in sv's own workflows |
| 14:55 | `2a88696` | #285 | Claim reading Yarn Berry and Bun lockfiles (securevibe-e2) |
| 15:12 | `a40ca6f` | #288 | Read Yarn Berry and Bun lockfiles |
| 15:17 | `c98651d` | #289 | Claim the sv self-assessment for the paper |
| 15:27 | `96a2167` | #290 | Backlog: strike four finished entries, and record a V15.1.2 false credit |
| 15:29 | `189a942` | #287 | Paper: the project against the OWASP Top 10 for Agentic Applications |
| 15:39 | `1ffe7ac` | #291 | Claim: the report credits V15.1.2 for a lockfile it could not read |
| 15:40 | `accd67e` | #292 | The v2 self-assessment: sv checking itself, compared with v1 and added to both Top 10 analyses |
| 15:57 | `1a1ebb4` | #293 | Credit V15.1.2 only for an inventory someone has seen |
| 16:14 | `f49197d` | #295 | Backlog: send admin actions straight to the app as an ordinary user (V8.3.1) |
| 16:26 | `9683a99` | #296 | Claim: send admin actions straight to the app as an ordinary user |
| 16:31 | `100c7ad` | #294 | Backlog: false alarms, parts 1 to 3, with the owner's decisions (claims parts 1 and 2) |
| 16:42 | `7125cac` | #298 | Claim the ADR analysis for the paper |
| 16:45 | `e40d29b` | #299 | Backlog: six records that disagree with what was built, and three gaps from the v2 self-assessment |
| 16:53 | `29184ca` | #297 | False alarms, part 1: one finding per weakness and line, how sure, and test code named |
| 16:53 | `b93ed2e` | #300 | Paper: the decision records of both versions |
| 17:02 | `e75da68` | #301 | Send admin actions straight to the app as an ordinary user (V8.3.1) |
| 17:02 | `5504124` | #302 | Backlog: a weekly review of the decision records, and the harness's first run as the transcript shows it |
| 17:07 | `dd81d54` | #303 | False alarms, part 2: a person's record that a finding is a false alarm or an accepted risk |
| 17:14 | `1f2443d` | #304 | Claim: the role-field probe |
| 17:22 | `3b3dd7a` | #305 | Backlog: claim reporting test-code findings apart from the app's |
| 17:33 | `3f59285` | #306 | A role written into the sign-up form (V8.3.1, V15.3.3) |
| 17:41 | `9a6b8a4` | #307 | Claim: drop the coding rules' AC.7.4 citation (securevibe-e9) |
| 17:51 | `44bc2b3` | #309 | Drop the coding rules' AC.7.4 citation |
| 18:01 | `447300b` | #310 | The false-alarms test keeps every other scanner out, and shows it did |
| 18:13 | `1a5864b` | #311 | Claim: records items 5, 6, and the Docker half of 8 |
| 18:16 | `4bee715` | #312 | Records items 5, 6, and the Docker half of 8 |
| 18:27 | `3fa01d5` | #313 | Backlog: claim naming fixture and example folders in the manifest |
| 18:42 | `747a2eb` | #314 | Claim: say an app is an MCP server, and split AISVS C10 by side (securevibe-e9) |
| 18:56 | `4da6ee3` | #315 | Backlog: a review of sv on 27 September 2026, thirteen items |
| 19:10 | `5f24f51` | #316 | List findings in test code after the app's own, including Rust's test modules |
| 19:12 | `6715138` | #317 | Claim: review items 7, 1, and 3, one walk of the app |
| 19:40 | `84c730b` | #318 | Let a manifest say the app serves tools over MCP, and split AISVS C10 by side |
| 19:51 | `659f7b3` | #319 | Claim false alarms, part 3 (securevibe-e9) |
| 20:36 | `fadc9db` | #320 | One walk of the app, and no more following links or reading files of any size |
| 20:43 | `5d527dd` | #321 | Report each false alarm against its rule |
| 21:02 | `4e20065` | #322 | Claim: review items 4, 5, and 8 (securevibe-e9) |
| 21:14 | `14a05bb` | #323 | A broken breached-password record leaves V6.2.12 not assessed, not a panic |
| 21:20 | `30b749f` | #324 | Read options as options: --help after any command, sv --version, unknown options refused |
| 21:32 | `4b36011` | #325 | Compile each fixed pattern once, and match the AI log's words by hand |
| 22:21 | `1d84147` | #326 | Compile a code rule's queries when its language is met, and load once for the MCP server |
| 22:37 | `79bd9bb` | #327 | Let the manifest name folders that are not the app |
| 23:17 | `d73432f` | #329 | Claim: review items 2 and 11 (securevibe-e9) |
| 23:30 | `abbdb32` | #330 | A release profile: strip only, because the binary is grammars, not code |
| 23:35 | `08b8e0b` | #328 | Backlog: review item 2 was claimed twice; say where the finished work is |
| 23:41 | `5af904e` | #332 | Give sv run an end: time limits on Docker calls and tests, and Ctrl-C that cleans up |
| 23:44 | `400bdae` | #333 | Run the image as a user of its own, not root |

## Day 10 — 28 September: one file split across sessions

83 changes reached `main`, 09:53 to 23:55, all of them pull requests, out of 229 commits in all.

From this day the sessions that did most of the work (named in the backlog as `securevibe-e2`, `securevibe-e9`,
and similar) left no transcript on this machine. Their record is the commits, the pull requests, and the
backlog, and nothing below depends on more.

The largest file of checks, `signed_in.rs`, was split into eight files by several sessions at once, one slice
each, under a freeze planned in the backlog (#335, #358 to #405). Partial checks, for requirements no check had
spoken to, arrived in four parts (#377, #387, #394, #397), and every ASVS and AISVS requirement was listed
with the checks that speak to it (#349). Paper analyses of corrected claims, decisions, coordination cost, and
tests against faults went in (#372, #385), and eight places where the paper's earlier files disagreed with the
record were fixed (#392). At 18:15 the backlog recorded two limits that cato-pipeline, the session that would run
the comparison study, hit while wiring `sv` in (#400). In the evening a rate limiter's answer stopped being read
as the app's (#412, #416), and so did a crash's (#418, #420): the decision later written down as ADR-021.

| time | commit | pull request | change |
|---|---|---|---|
| 09:53 | `d77e3d2` | #335 | Backlog: plan the signed_in.rs split across sessions, and claim review item 12 |
| 09:55 | `54aec7e` | #334 | Backlog: item 2 as it ended, and claim porting its two extras |
| 10:04 | `def3c0c` | #337 | Hold sv to V15.2.1: a weekly audit of its own crates, and sv audit that respects not-the-app |
| 10:09 | `e266691` | #338 | Claim: an ecosystem counted as covered by a passing mention (securevibe-e9) |
| 10:15 | `f1c327c` | #339 | Count an ecosystem as covered only by a record about it alone |
| 10:16 | `fa4d724` | #336 | sv run: a test limit securevibe.toml can set, and cleanup after a run killed outright |
| 12:41 | `d87f070` | #341 | Claim: counting a vulnerability once, and the report's bill of materials (securevibe-e9) |
| 12:53 | `1db48c4` | #340 | Backlog: item 3 was claimed twice; say where the finished work is, and leave item 2 |
| 13:03 | `5f7e781` | #343 | Backlog: the two sessions review each other's work on the known-vulnerability entry |
| 13:10 | `3e75829` | #345 | Count a vulnerability once, however many names it goes by |
| 13:18 | `9879a6a` | #344 | Count what is set apart in sv audit again, and audit only what sv is built from |
| 14:10 | `15e2546` | #346 | Backlog: how item 3 ended, and the reviews of items 1 and 2 |
| 14:45 | `4e981f5` | #347 | Backlog: claim the test that failed once on CI, now named |
| 14:53 | `5b1dda8` | #348 | Claim: every ASVS and AISVS requirement in one list (securevibe-e9) |
| 14:58 | `c361bd1` | #349 | List every ASVS and AISVS requirement with the checks that speak to it |
| 15:08 | `be5d9a2` | #350 | Claim the harness-origin timeline fix |
| 15:11 | `52e4d43` | #351 | Make the leftovers tests take turns, so one cannot remove the other's fake leftover |
| 15:11 | `2025c87` | #352 | Timeline: where the evaluation harness came from, and Day 0 at its recorded times |
| 15:22 | `7184368` | #353 | Claim step 0 of splitting signed_in.rs |
| 15:23 | `1f83dee` | #354 | Backlog: partial checks for the requirements no check speaks to |
| 15:25 | `943a3b4` | #355 | The report's shape: each requirement's text once in report.json, and the compliance page by chapter |
| 15:35 | `6aac023` | #356 | Count outside-tool rules that already run against the requirements they find failing |
| 15:37 | `8a291fc` | #357 | Paper: a figure setting the two self-checks side by side |
| 15:38 | `2fdd11d` | #358 | Split signed_in.rs, step 0: a folder, the fake app, and the rules |
| 15:41 | `da6ea32` | #359 | Claim: partial checks item 2 (securevibe-e9) |
| 15:45 | `64c4f8c` | #360 | Claim slice e (uploads) of splitting signed_in.rs |
| 15:51 | `4b68e32` | #363 | American spelling in the paper, where the sweep missed it |
| 15:53 | `847403e` | #362 | Backlog: two faults from killed_run on Colima; claim the first |
| 15:53 | `0f42aa3` | #361 | killed_run test: put the app where Colima can see it |
| 15:55 | `2bcbe57` | #364 | Split signed_in.rs, slice e: the upload checks into uploads.rs |
| 15:59 | `12d5141` | #365 | Count the AI probes against C9.3.2 and C9.3.7, the agent requirements they already test |
| 16:00 | `e255ef6` | #366 | Claim two paper analyses and the stale ADR count |
| 16:01 | `32eff84` | #367 | Claim slice f (flows) of splitting signed_in.rs |
| 16:05 | `4d75336` | #370 | report.json names the checks only a person can make by id, instead of writing them twice |
| 16:09 | `1204fe9` | #371 | Split signed_in.rs, slice f: the multi-step flow checks into flows.rs |
| 16:11 | `94523cb` | #368 | Backlog: claim twenty of the third group of partial checks |
| 16:15 | `badd813` | #372 | Paper: corrected claims, and who decided what |
| 16:18 | `57fed49` | #373 | Claim slice h (forgery) of splitting signed_in.rs |
| 16:25 | `de1d1a3` | #374 | Claim two more paper analyses |
| 16:29 | `97136dd` | #375 | Split signed_in.rs, slice h: the request-forgery checks into forgery.rs |
| 16:36 | `273ba01` | #376 | Claim slice g (admin) of splitting signed_in.rs |
| 16:39 | `ef752c5` | #377 | Seven partial checks that read the code (group 3, part 1) |
| 16:43 | `88b59b6` | #378 | Backlog: evaluate Opengrep against semgrep |
| 16:45 | `00290c6` | #379 | OpenAI and Hugging Face key rules, and vendor fine-tuning calls as training |
| 16:46 | `0ae1ef0` | #380 | Split signed_in.rs, slice g: the admin and ownership checks into admin.rs |
| 16:47 | `8d71180` | #381 | Claim slice b (sessions) of splitting signed_in.rs |
| 16:59 | `94562ae` | #382 | Backlog: a rate limiter's 429 read as the app's answer about access |
| 17:03 | `a11a813` | #384 | Split signed_in.rs, slice b: the session checks into sessions.rs |
| 17:06 | `add801d` | #385 | Paper: coordination cost, and tests against faults |
| 17:08 | `f584494` | #386 | Claim slice c (passwords) of splitting signed_in.rs |
| 17:17 | `5117b0a` | #388 | Say in report.json what was examined, in a form a program can read |
| 17:18 | `e176eea` | #387 | Four partial checks of the running app (group 3, part 2) |
| 17:23 | `8cd082d` | #390 | Claim the eight paper inconsistencies |
| 17:24 | `f35d49c` | #389 | Split signed_in.rs, slice c: the password checks into passwords.rs |
| 17:25 | `06416ba` | #391 | Claim slice a (sign-in) of splitting signed_in.rs |
| 17:32 | `7e65be7` | #392 | Paper: fix the eight inconsistencies |
| 17:41 | `ab89622` | #393 | Split signed_in.rs, slice a: the sign-in checks into signin.rs |
| 17:42 | `de7a87a` | #394 | Six partial checks of an app's AI feature (group 3, part 3) |
| 17:53 | `592315b` | #395 | Claim merging the CI-hang fix into v1 |
| 18:05 | `ea3941f` | #397 | The app as an MCP server: C10.3.3 and C10.2.6 (group 3, part 4) |
| 18:12 | `f3519c1` | #398 | Backlog: claim the C9.5.4 citation and the empty app folder |
| 18:15 | `7eab77d` | #399 | Claim slice d (codes) of splitting signed_in.rs |
| 18:15 | `0d34d18` | #400 | Backlog: two limits cato-pipeline hit while wiring in sv |
| 18:25 | `167b618` | #401 | The Anthropic key rule no longer cites C9.5.4 |
| 18:28 | `4e946f1` | #402 | Say when the container backend cannot see the app's folder |
| 18:33 | `945aa90` | #403 | Split signed_in.rs, slice d: reset, emailed codes, activation, and two-factor into codes.rs |
| 18:50 | `4554ec3` | #404 | Claim step 2 of splitting signed_in.rs |
| 19:05 | `d718bc7` | #405 | Split signed_in.rs, step 2: codes.rs by area, a map of the files, and the freeze lifted |
| 19:20 | `cfc728c` | #406 | Claim: read requirements.lock beside pyproject.toml |
| 19:31 | `3231e6b` | #407 | A large data file no longer blocks the credential scan or the MCP check |
| 19:54 | `c8dd207` | #408 | Read requirements.lock beside pyproject.toml |
| 20:08 | `1a2fa39` | #409 | Claim: name the lockfile read when a project has several |
| 20:33 | `6bffbb4` | #410 | Name the lockfile read when a project has two of one kind |
| 20:45 | `f7b7fc1` | #411 | Claim: a rate limiter's 429 read as the app's answer about access |
| 20:55 | `546ace7` | #412 | A rate limiter's answer is not the app's: waited out once, and never credited as a refusal |
| 20:59 | `14927c6` | #413 | Claim: ast.download-piped-to-shell flags a download read as data |
| 21:19 | `2791e7c` | #415 | Claim: the anonymous probes and the rate limiter, and a limit on all the waiting |
| 21:39 | `f1f83db` | #416 | Anonymous questions wait out a rate limiter too, and all waiting stops at five minutes |
| 21:49 | `4eeb7dd` | #417 | Claim: a 500 from the app read as a refusal |
| 22:52 | `fb80cf7` | #418 | A crash is not a refusal: passes resting on one are not credited |
| 22:56 | `3fc9324` | #414 | ast.download-piped-to-shell: report an interpreter only when it runs what it is sent |
| 23:02 | `3c4bc9e` | #419 | Claim: three findings raised from a refusal, so a crash can raise them |
| 23:55 | `70dba73` | #420 | A crash does not raise a finding either |

## Day 11 — 29 September: the comparison study begins

48 changes reached `main`, 11:29 to 22:44, all of them pull requests, out of 149 commits in all.

More questions only a running app can answer: an SVG upload carrying a script and the antivirus test file
(#428), field-level access and private pages open to shared caches (#430), what a browser keeps (#432), two
people with one email address at the sign-in provider (#437), another user's record through the AI feature's
own tool (#440), and a development console that answers (#446). At 18:33 the first four issues from the owner's
comparison study, run with `sv` on AI-built apps outside this repository, were recorded (#441), and all four were
fixed eighteen minutes later (#443). A figure of how `sv` works was added to the paper (#449). Late in the
evening came ADR-020, the record of why `sv` is in Rust, with corrections to v1's records (#463), and the first
weekly review of the decision records (#464).

| time | commit | pull request | change |
|---|---|---|---|
| 11:29 | `ce586ce` | #369 | A run that fails still says what it removed first |
| 11:35 | `c87f0a3` | #422 | Backlog: OSV last_affected is ignored; claimed |
| 11:37 | `bf72477` | #421 | Claim: the bundle test that failed once |
| 11:56 | `d463721` | #423 | Read OSV's last_affected, and do not compare ranges with unknown events |
| 11:57 | `982f97e` | #424 | The bundle test looks for the whole secret, not four digits of it |
| 13:02 | `fba795e` | #425 | Claim: three signed-in partial checks, V4.1.3, V7.4.3, and V6.3.7 |
| 13:59 | `61e02e4` | #426 | Signed-in checks for V4.1.3, V7.4.3, and V6.3.7 |
| 15:44 | `a07b432` | #427 | Claim V1.3.4 and V5.4.3 (upload probe) |
| 16:26 | `c859fef` | #428 | Upload probe: an SVG with a script (V1.3.4) and the antivirus test file (V5.4.3) |
| 16:41 | `e6f37cd` | #429 | Claim V10.1.1 and V14.3.3 (browser storage) |
| 16:43 | `250f37b` | #430 | Field-level access (V8.2.3) and private pages open to shared caches (V14.2.2) |
| 16:57 | `a461d0a` | #431 | Backlog: a shell variable reference read as a credential (claimed) |
| 17:17 | `5fcde8b` | #433 | A value that is wholly a shell or build-file reference is not a credential |
| 17:28 | `f61c43e` | #432 | Browser storage: the test password (V14.3.3) and sign-in tokens (V10.1.1) |
| 17:48 | `5e0faa0` | #435 | Backlog: claim narrowing the MCP check's large-file word test |
| 17:54 | `4db4eba` | #434 | Claim V10.5.2 (two people sharing an email at the sign-in provider) |
| 18:01 | `51da06d` | #436 | The MCP check reads a large file for a command key, not the word |
| 18:05 | `a836cd7` | #437 | Two people with one email address at the sign-in provider (V10.5.2) |
| 18:19 | `0fc9749` | #438 | Backlog: claim C9.5.3 |
| 18:33 | `426aabd` | #441 | Backlog: four issues from the comparison study (claimed) |
| 18:34 | `1260f50` | #440 | Another user's record through the AI feature's own tool (C9.5.3) |
| 18:34 | `0d5c0b0` | #439 | Claim partial checks item 5: which CodeQL queries the suites run |
| 18:44 | `1f98278` | #442 | Claim two running-app halves: the model name sent, and a debug console |
| 18:51 | `5a6c5ad` | #443 | Four fixes from the owner's comparison study |
| 18:53 | `0080f13` | #445 | Claim the static half of V10.4.4: retired grants in code |
| 18:54 | `f8b8824` | #444 | Which queries the CodeQL suites run, measured, and two mapped for V15.4.2 |
| 19:20 | `0b8ff46` | #448 | The password and implicit grants, read from a sign-in server's code |
| 19:32 | `a88aa30` | #446 | A development console that answers, and the model name the app sent |
| 19:35 | `0e3e9c6` | #449 | A figure and short account of how sv works, for the paper |
| 19:53 | `bc77226` | #447 | Claim V11.4.4: a key made from a password with too little work |
| 20:12 | `d00ac08` | #450 | A key made from a password with too few rounds (V11.4.4) |
| 20:59 | `49e8451` | #452 | Claim the static half of V13.4.7: static files from the app's folder |
| 21:11 | `3e8fc20` | #453 | Static files served from the app's own folder (V13.4.7, read from the code) |
| 21:24 | `7c96bbe` | #451 | Claim: the killed_run test that failed once on CI |
| 21:35 | `05495d9` | #454 | Fix the killed_run test that failed once on CI |
| 21:37 | `8d46049` | #455 | Record why the ollama pull half of C6.1.3 is not built |
| 21:39 | `65adc0d` | #457 | Backlog: the Semgrep license question is settled |
| 21:42 | `7dc139d` | #456 | Claim the file half of C4.1.2: pickle-format model files |
| 21:47 | `3fb153a` | #459 | Claim the Opengrep evaluation and OCSP stapling (V12.1.4) |
| 21:51 | `68372cd` | #462 | Model files in the app stored in a format that can run code when loaded (C4.1.2) |
| 21:53 | `177d779` | #458 | Claim: v1 record corrections, the Rust record, and closing F-0001 |
| 21:54 | `d3876d7` | #460 | Claim: the first weekly review of the decision records |
| 22:07 | `534a03d` | #461 | Claim: the code half of V9.2.3 (token audience check switched off) |
| 22:17 | `52976d8` | #463 | ADR-020 (Rust), corrections to v1's records, and F-0001 closed |
| 22:19 | `6740e21` | #465 | OCSP stapling (V12.1.4) in sv probe, from the handshake it already makes |
| 22:33 | `ba4f1b1` | #464 | The first weekly review of the decision records |
| 22:41 | `ef87c31` | #467 | Record the Opengrep evaluation |
| 22:44 | `34ca633` | #466 | A token check told not to check who the token is for (V9.2.3) |

## 30 September to 2 October

No commits, on any branch that reached `main`. The comparison study ran outside this repository over these days
(`sv-study`, 29 September to 3 October). On 1 October a new release of Rust's lint tool began failing the Lints
check on every branch, which nobody noticed until #473 fixed it on 3 October.

Dates written inside the records of these days are often in UTC, which is four hours ahead of Eastern time: the
owner's choices "on 30 September" in the backlog and `docs/adr/README.md` were made on the evening of
29 September, Eastern, and records "written on 4 October" were committed at 21:02 on 3 October.

## Day 12 — 3 October: the running-app review and the MCP server

76 changes reached `main`, 10:32 to 22:23: 71 merged and 5 rebased onto `main`, out of 229 commits in all.

Two reviews set the day's work. One hardened and improved the MCP server (#470): nothing written through a link
(#474), every malformed request answered (#477), each tool's result described (#479), the newest protocol
versions (#483), the reports offered as resources (#488), a time limit (#498), and progress reported during a
long check (#504). The other reviewed the checks that ask the running app (#471): a fault in the counts and
sixteen items, most built the same day, among them old TLS versions on the live site (#495), text reflected into
a page without encoding (#505), a file named `../` (#508), open redirects (#513), an action sent 20 times at the
same instant (#527), where a feature that fetches addresses will go (#531), the sign-in token the app issues
itself (#544), and SQL injection on the app's own reads (#545). The app's own container now runs read-only, with
no capabilities (#496). Semgrep runs without usage reporting, with Opengrep in its place when it is absent
(#481). A manifest that disagrees with its lockfile is now said, after one in `sv`'s own example app had
disagreed unnoticed for ten days (#482, #511, #525, #530). That evening
the comparison study's fifth app, family-hub, built that day with `sv` in the loop, sent three faults (#533,
#535, #537), the AI tool's answers could be recorded through `sv` (#539), and the five records the weekly review
said were owed were written, ADR-021 to ADR-025 (#541).

| time | commit | pull request | change |
|---|---|---|---|
| 10:32 | `93b7bfa` | #472 | Claim: semgrep without usage reporting, Opengrep as a stand-in |
| 10:37 | `0bd3f91` | #473 | Fix clippy 1.99: every branch fails Lints since 1 October |
| 10:42 | `97fe041` | #470 | Backlog: hardening and improving the MCP server (items 1 to 3 claimed) |
| 10:53 | `4b3db46` | #474 | Write nothing through a link, and keep the app's text on its own line |
| 10:58 | `aeb056e` | #476 | Backlog: a prompt library from the CSA guide and lessons learned (#476) |
| 11:01 | `88422e2` | #478 | Claim: MCP improvement 3, each tool's output schema |
| 11:05 | `4a9abc6` | #475 | Claim: MCP hardening items 4, 5, 7, and the size half of 6 |
| 11:12 | `d3b9388` | #479 | Declare the shape of each MCP tool's structured result |
| 11:12 | `a2d3259` | #480 | Claim: MCP improvement 6, the newest protocol versions |
| 11:20 | `67a497a` | #482 | Example app: PyJWT 2.15.1, and a lock that matches its manifest (#482) |
| 11:24 | `1d79f89` | #477 | Answer every malformed request, and refuse to serve / or the home folder |
| 11:35 | `521240b` | #471 | The running-app checks reviewed: a fault in the counts, and sixteen items |
| 11:38 | `2d5cce0` | #483 | Speak MCP 2025-11-25 and 2026-07-28 beside the older versions |
| 11:38 | `31ba927` | #485 | Claim MCP improvement 5: the written reports as MCP resources |
| 11:45 | `182e804` | #486 | Count 21 checks that only ever raise a finding as finding-only |
| 11:46 | `5cad3e4` | #487 | Claim the checks on the app's own sign-in tokens |
| 11:49 | `53154bc` | #484 | Backlog: say when a manifest and its lockfile disagree (#484) |
| 11:53 | `038f2a4` | #481 | Semgrep without usage reporting, Opengrep in its place when absent |
| 11:56 | `0ca45dd` | #489 | Release the token-check claim, and withdraw the proposal to credit six checks |
| 12:06 | `93bb745` | #493 | Claim running the app's container read-only (#493) |
| 12:07 | `76c1eb0` | #491 | Claim: old TLS versions on the live site (V12.1.1) |
| 12:07 | `6af5f58` | #490 | Claim the time limit on an MCP check (hardening item 6, second half) |
| 12:12 | `f2809de` | #492 | Claim: headers judged on every page the run fetched |
| 12:21 | `14389ca` | #494 | Judge the browser headers on the root page and the private pages too |
| 12:27 | `1fe4622` | #496 | Run the app's container read-only, without capabilities (#496) |
| 12:34 | `738dc5e` | #497 | Claim items 9 and 10: AI agent limits and AI service failure |
| 12:35 | `1e9e18a` | #495 | sv probe: old TLS versions on the live site (V12.1.1) |
| 12:37 | `72b77e9` | #499 | Claim MCP improvement 4: progress notifications during a long check |
| 12:45 | `c01c04d` | #500 | What the app does when its AI service fails |
| 12:48 | `ab3603e` | #501 | Claim: text reflected into a page without encoding (V1.2.1, V1.2.3) |
| 12:55 | `5e72411` | #502 | An AI agent with no limit on its tool calls |
| 13:02 | `e42dc86` | #488 | Offer the written reports as MCP resources |
| 13:02 | `75d4051` | #498 | Put a time limit on a check over MCP |
| 13:12 | `74612b7` | #505 | Probe for text reflected into a page without encoding (V1.2.1, V1.2.3) |
| 13:16 | `bcc5181` | #503 | Claim: say when a manifest and its lockfile disagree |
| 13:16 | `c671a40` | #504 | Say how a check over MCP is going |
| 13:26 | `cd1f87b` | #506 | Claim: upload names with ../ (V5.3.2) and compressed bombs (V5.2.3) |
| 13:42 | `42c1011` | #507 | Claim item 14: email change without the password again |
| 14:02 | `13ad888` | #508 | Upload a file named ../ and look for where it landed (V5.3.2) |
| 14:04 | `cdba4b0` | #510 | Claim item 8: open redirect |
| 14:07 | `3c18d8e` | #511 | Say when a manifest and its lockfile disagree |
| 14:16 | `72eb125` | #512 | Record the owner's decision on compressed bombs (V5.2.3), and claim it |
| 14:18 | `f5841fd` | #509 | Check that changing the email address needs the password again (V7.5.1) |
| 14:28 | `1847eda` | #513 | Check the sign-in flow for open redirects (V3.7.2) |
| 14:48 | `3f1f2b5` | #514 | Send each request to the app as input, so a body can be any size and any bytes |
| 14:59 | `67bb297` | #515 | Claim: another user's documents reaching the AI (C5.2.2, C5.2.4, C8.1.3) |
| 15:26 | `d6bab12` | #516 | Ask whether the AI feature searches other users' notes (C5.2.2, C8.1.3, C5.2.4) |
| 15:34 | `65dc668` | #517 | Move CodeQL's init and analyze to v4.38.2 together, and group them |
| 15:35 | `f3fb561` | #518 | Claim the rest of the weak key-derivation rule (Go's crypto/pbkdf2, C#'s two-argument Rfc2898DeriveBytes) |
| 15:36 | `735ba44` | #519 | Claim: the app's own MCP server, hardened (C10.2.1, C10.4.3, C10.4.4, C10.4.5) |
| 15:47 | `8a0e4fa` | #520 | Read Go's crypto/pbkdf2 and C#'s two-argument Rfc2898DeriveBytes for too few rounds |
| 16:03 | `c9d9e37` | #521 | Claim comparing the other manifests with their lockfiles |
| 16:05 | `45b6d71` | #522 | Release item 7 unbuilt (SQL injection on the app's own records) |
| 16:14 | `0b877c7` | #523 | Claim item 13: limits and double-booking |
| 16:16 | `a4f4386` | #524 | Ask the app's MCP server about its token and the arguments it should refuse (C10.2.1, C10.4.3-5) |
| 16:27 | `3faffd7` | #525 | Hold pyproject.toml, Cargo.toml, composer.json, Gemfile, and go.mod to their lockfiles |
| 16:29 | `8ba4a5d` | #527 | Send an action 20 times at the same instant and count how often it goes through (V2.3.4) |
| 16:40 | `5cf3759` | #526 | Claim: requests the app makes for someone (V1.3.6, V15.3.2, V13.2.4) |
| 16:42 | `501145a` | #528 | Claim comparing Gradle's build files with gradle.lockfile |
| 16:47 | `b348578` | #529 | Hold creating records to a stated limit with a burst (V2.4.1) |
| 16:55 | `b26444f` | #530 | Hold Gradle's build files to gradle.lockfile |
| 17:43 | `9573c0d` | #531 | Ask where a feature that fetches addresses will go, and whether it follows redirects (V1.3.6, V13.2.4, V15.3.2) |
| 20:24 | `660e782` | #532 | Claim: the prompt library |
| 20:28 | `4b23ca3` | #533 | Backlog: three faults from family-hub; claim PEP 440 |
| 20:37 | `24c70c2` | #534 | Record the owner's decisions of 4 October, and claim the answer-recording tool |
| 20:43 | `5da838e` | #535 | Compare PyPI versions by PEP 440 in the advisory ranges |
| 20:45 | `1c99394` | #536 | Claim the other two family-hub faults |
| 20:55 | `7090598` | #537 | Read pylock.toml, and a fully hash-pinned requirements.txt, as Python lockfiles |
| 21:05 | `45d4917` | #538 | Name the sv that made a report, and give the image its commit |
| 21:07 | `a391ae3` | #540 | Claim the records owed, items 1 to 6 |
| 21:33 | `44af910` | #542 | Claim the checks on the app's own sign-in tokens (running-app item 4) |
| 21:33 | `117647c` | #541 | Write the records owed: ADR-021 to ADR-025, and a line in ADR-019 |
| 21:33 | `44395d6` | #539 | Record the AI tool's answers through sv, always marked as its own |
| 22:04 | `f0aca2f` | #543 | Claim SQL injection on the app's own reads |
| 22:05 | `22e165e` | #544 | Check the sign-in token the app issues itself |
| 22:23 | `fb1c625` | #545 | Ask the app's own reads for SQL injection |

## Day 13 — 4 October, to 11:37: the deep review

17 changes reached `main`, 09:08 to 11:37, all of them pull requests, out of 52 commits in all. This record
stops at `157ddc3`, the merge of #564 at 11:37, which is the cut-off for every count in it.

The first change of the day, `eff3f17` (#546), is the commit the cato-pipeline session's deep review read: six
reviewers, 58 findings (1 critical, 26 high, 22 medium, and 9 low). They reached the backlog at 10:04 and 10:23
(#553, #556). The one critical finding, S1, a backslash in a file name that let `sv bundle` read and zip files
outside the app, was fixed at 10:16 (#555); S2 to S5 and S12 were claimed by 11:30, and the rest were open at the
cut-off. The same morning the prompt library took shape: nine prompts tried and two shown to work (#549),
prompts from the Secure by Design checklist (#559), and `sv prompts`, which gives them to the AI coding tool,
each marked tested or not (#554). False alarms from one candidate set of Semgrep rules were measured over 25 apps
in six languages (#561).

| time | commit | pull request | change |
|---|---|---|---|
| 09:08 | `eff3f17` | #546 | Record the owner's decisions on the prompt library |
| 09:21 | `791df5f` | #547 | Record why staticcheck and phpcs-security-audit were not added |
| 09:24 | `8a59ad5` | #549 | Prompt library, first batch: nine tried, two shown to work |
| 09:24 | `fe4b7a7` | #548 | Backlog: design-time prompts from the Secure by Design checklist |
| 09:39 | `3c44931` | #550 | Keep the untested prompts in the library; claim sv prompts |
| 09:42 | `04293c1` | #551 | Claim: research into C's false alarms, every language |
| 09:52 | `ab53023` | #552 | Backlog: V9.1.3, a test key server and a code-reading rule |
| 10:04 | `7fb8c9b` | #553 | Backlog: deep review part 1; claim S1 |
| 10:16 | `47ec409` | #555 | Keep a backslash in a file name part of the name (deep review S1, critical) |
| 10:18 | `9592bb2` | #557 | Claim S2: the fence and the bridge gateway |
| 10:23 | `f62eb05` | #556 | Backlog: deep review parts 2 and 3 |
| 10:38 | `6a7d8f2` | #559 | Design-time prompts from the Secure by Design checklist, tried |
| 10:59 | `a610a09` | #560 | Claim deep review S3 to S5 |
| 11:08 | `6456331` | #561 | Option C's false alarms, measured over 25 apps in six languages |
| 11:19 | `84dcbd4` | #554 | sv prompts and securevibe_prompts: the prompt library, each marked tested or not |
| 11:30 | `4960179` | #563 | Claim deep review S12 |
| 11:37 | `157ddc3` | #564 | Claim: design-time prompts in sv prompts, and a second test brief |
