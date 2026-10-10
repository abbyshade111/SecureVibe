# Records owed, from the second weekly review of the decision records (5 October 2026)

**Status:** done, 6 October 2026

Each is a decision in
code merged in the week to 5 October with no record, costly to undo without its reasons; each is explained in
`DESIGN.md` under the heading named. **Not claimed; each can be claimed on its own**, and which are worth a record
is the owner's call. Most costly first:
1. **The SQL injection probe's limits** (#545, 3 October; DESIGN, the probe's section): read-only GET requests
   only, only against the copy of the app `sv` starts itself, and only ever a finding. The owner set them on
   4 October. A limit like this is the kind that is loosened later without its reason.
   **Part status:** done, with the item
2. **Checks on the app's own sign-in tokens, and the key source they may name** (#544, 3 October, then #710,
   5 October; DESIGN, "A sign-in token caught naming where its key is"): the owner left out `jku` and `kid` on
   4 October and then had `jku` and `x5u` built through a test key server; `kid` stays out. No record traces it.
   **Part status:** done, with the item
3. **A credential that reads like a sentence is reported low** (#597, 4 October; DESIGN, "A credential name over a
   sentence is reported low, and says so"): a default that changes what a report concludes, the owner's choice.
   **Part status:** done, with the item
4. **Cookies handed to the browser with their attributes, and a warning, not a refusal, when the start command
   looks like it weakens the app** (#605, 4 October): changes the browser checks' evidence; the owner's choice.
   **Part status:** done, with the item
5. **A run secret, `SV_ADMIN_TOTP_SECRET`, handed to the app's seed** (#600, 4 October; DESIGN, "An admin who
   signs in with a code"): what `sv` passes into the app's container; the owner's choice.
   **Part status:** done, with the item
6. **Log markers moved into the address, so the log check can pass for an app that keeps personal data out of its
   log** (#601, 4 October): when a check credits; the owner's choice.
   **Part status:** done, with the item
7. **A lock file in the report folder** (#589, 4 October; DESIGN, "One run at a time in a report folder"): a new
   file `sv` writes into the app's folder. ADR-017 lists the report folder, so this may be a line there.
   **Part status:** done, with the item
8. **Owner's choices with no code change:** V9.2.3 is not cited by the running probe (4 October); V8.3.1 stays
   checked by hand only (5 October); phpcs-security-audit is not added (5 October); and the compressed-archive check
   for V5.2.3 is to be built (3 October, archives up to about 1 GB, limits the owner sets), which should come with
   its record as `proposed` in its claim.
   **Part status:** done, with the item

**Two questions for the owner,** found by the same review:
- **Should records govern the large shared files?** Several decisions are enforced in `crates/sv-cli/src/mcp.rs`
  (ADR-022's "the tool records only as the tool", ADR-028's prompts, ADR-034's report seal, ADR-035's preflight),
  `crates/sv-cli/src/main.rs` (ADR-034, ADR-036's data check, ADR-029's code 3), and `crates/sv-check/src/config.rs`
  (ADR-037's `versions_pinned`). None is governed by any record, so the check would not ask about a change that
  undoes one. Governing them would make nearly every pull request owe a line, since those files change in most of
  them. The review added the smaller files and left these for the owner to decide.
- **Does ADR-032 reach the outside tools?** It holds `sv`'s own `git` to running no program the app's repository
  names. Semgrep and CodeQL, run by `sv report --tools` in the app's folder, may run `git` themselves; the record
  does not say, and it was not checked.
  **The owner's decision, 6 October 2026, on what was found** (Semgrep and Opengrep held only because `sv` names
  files rather than folders, CodeQL unknown): add the guard. Every outside tool's environment sets git's
  `core.fsmonitor` off, as `sv`'s own `git` does, held by a test with a planted repository; ADR-032 gets a Later
  entry. **Claimed the same day by session securevibe-e2**, in branch `claude/securevibe-e2-git-guard`.
  **Done the same day** (DESIGN, "The outside tools run no program an app's repository names"; ADR-032, "Later, 6
  October 2026"). Not run with Semgrep or CodeQL themselves, which were not installed in the session.

**The owner's decisions, 6 October 2026:**
- Records for items 1, 2, 3, and 7, the four most costly; the other four stay as their DESIGN sections.
- The large shared files stay ungoverned: governing them would make nearly every pull request owe a line, and the
  weekly review catches what slips through.
- ADR-032 and the outside tools: find out whether Semgrep and CodeQL run `git` in the app's folder, and report before
  changing anything.

**Records 1, 2, 3, and 7, and the ADR-032 question, claimed the same day by session securevibe-e2**, at the owner's
word, in branch `claude/securevibe-e2-records`. Read on `main` just before this claim: no other session had claimed
them.
**Records 1, 2, 3, and 7 done the same day:** ADR-038 (the SQL injection probe's limits), ADR-039 (the sign-in token
checks and the key addresses they may name), ADR-040 (a credential over a sentence reported low), and ADR-041 (the
report folder's lock). Each was read against its DESIGN section and the pull requests named; each names the tests
that hold it.
**The ADR-032 question, answered the same day** (read, and one part tested; nothing changed):
- `sv` clears every outside tool's environment and passes no `GIT_*` variable, so a `git` a tool starts reads the
  app's repository settings as they are. A test with git 2.43 in a repository planted with `core.fsmonitor`:
  `git ls-files`, in every form tried, ran the planted program; `git ls-remote --get-url` and `git rev-parse` did not.
- **Semgrep** (its source, develop branch): lists files with `git ls-files` only for a folder it is given, and `sv`
  names files one by one, so it does not today. Its Python front end runs `git ls-remote --get-url` on every scan,
  which ran nothing planted. `--no-git-ignore` would not stop it running git.
- **Opengrep** (its source, main branch): runs no git in a plain scan of named files.
- **CodeQL:** not determined. Its extractors run no git; the `codeql` program itself is closed, and its manual
  could not be read from the session.
- So `sv` is held to ADR-032 by the tools only because it names files rather than folders, and for CodeQL that is
  unknown. The smallest guard: set `GIT_CONFIG_COUNT=1`, `GIT_CONFIG_KEY_0=core.fsmonitor`, `GIT_CONFIG_VALUE_0=false`
  in every outside tool's environment, the override `git.rs` already passes on git's command line; shown here to beat
  the repository's own setting (git 2.31 or newer). For the owner to decide.
