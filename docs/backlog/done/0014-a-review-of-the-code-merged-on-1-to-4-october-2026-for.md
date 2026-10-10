# A review of the code merged on 1 to 4 October 2026, for faults

**Status:** done, 10 October 2026
Asked for by the owner on 6 October 2026, after
the review of 5 and 6 October found seventeen faults, four of them false passes. The same method: four reviewers read
the changes from `34ca633` to `0d5258e` in four parts, each fault is reproduced by running `sv` on a small app made for it
or confirmed by reading where noted, and goes here as its own item; those in this session's own work it fixes, and the
rest it leaves for whoever claims them. **Claimed on 6 October 2026 by session securevibe-e2**, at the owner's word,
in branch `claude/securevibe-e2-review-1to4`.
**What it found, 6 October 2026.** Each item below was confirmed against `main` as it stands by a reviewer reading
the code (or running something, where noted); items 1, 8, 9, 12, 18, 21, and 22 were read again on `main` by this
session. None was already in this backlog. "Confirmed by reading" below means the reviewer's reading unless one of
those seven. Numbered so each can be claimed on its own; none is
claimed yet. Items 8 and 11 touch a decision the owner made (ADR-026) and are the owner's to settle.
1. **`sv probe` reports a slow first answer as an untrusted certificate** (V12.2.2, high). Any failure of the verified
   request followed by an unverified one that answers is called a certificate problem; a host that sleeps when idle
   and misses the 15-second limit once is reported so. The failure is never checked to be a certificate error.
   Confirmed by reading `sv-check/src/production.rs`.
   **Part status:** done, date not recorded
2. **`sv probe` credits "no plain-HTTP way in" (V12.2.1) without asking port 80.** The plain request keeps the typed
   port, so for `https://host:443/` it goes to the TLS port, and any curl failure (an empty reply, a timeout, port 80
   blocked here) is credited. Confirmed by reading `production.rs`.
   **Part status:** done, date not recorded
3. **`sv probe` goes through this computer's proxy**, which looks the name up itself, so the pin to the one checked
   public address (ADR-027) holds only with no proxy set; with an inspecting proxy the certificate judged would be the
   proxy's. Its curl arguments carry no `--noproxy`. Confirmed by a reviewer running curl with the probe's own flags,
   and by reading.
   **Part status:** done, date not recorded
4. **The app's own MCP server checks credit a crash, a rate limit, or an unrelated error as a refusal** (C10.3.3,
   C10.2.6, C10.2.1, C10.4.3, C10.4.4). They call the app without the wait and crash list the signed-in checks use,
   and read any status of 400 or above as refused. Confirmed by reading `sv-check/src/mcp_server.rs`.
   **Part status:** done, date not recorded
5. **The fetch check credits V15.3.2 without the app's own answer** (suspected): a redirect not yet followed when `sv`
   asked the test server is credited, though the app may still be fetching. `sv-check/src/fetch.rs`.
   **Part status:** done, date not recorded
6. **The AI agent limit credits C9.1.2 for any 2xx answer** (suspected): an app that catches its own error mid-loop and
   answers 200, or answers before the loop ends, is credited. `sv-check/src/ai.rs`.
   **Part status:** done, date not recorded
7. **A limiter's 503 with `Retry-After` on the AI failure check is a finding** (V16.5.2), where ADR-021 reads it as a
   limiter's. Confirmed by reading `ai.rs`.
   **Part status:** done, date not recorded
8. **On a computer that has never run `sv review`, any well-formed seal counts as the owner's record**, and the report
   says it was "recorded through `sv review` on another computer". The AI tool can write one. Confirmed by reading
   `sv-check/src/seal.rs` (`Checker::NoKey`). The owner's decision (ADR-026); at the least the wording claims more than
   is known.
   **Part status:** done, date not recorded
9. **A `report.json` with a start time in the future blocks `sv report` in that folder for good**, and only after the
   whole run. `refuse_older` trusts the time without the report's seal. Confirmed by reading
   `sv-cli/src/report_lock.rs`.
   **Part status:** done, date not recorded
10. **Lines can be added inside a sealed notes section without breaking its seal**: bylines and `Sealed by sv review:`
    lines are left out of what is sealed wherever they appear, and `sv review` does not show them. Confirmed by
    reading `sv-check/src/notes.rs`.
   **Part status:** done, date not recorded
11. **A seal is not tied to the app it was made for**: a sealed answer copied from one app to another on the same
    computer counts there. Confirmed by reading `seal.rs`. The owner's decision.
   **Part status:** done, date not recorded
12. **The upload checks never confirm the answer fetched back is the uploaded file**, so a catch-all page credits
    V5.3.1 and raises false high findings for V3.2.1 and V1.3.4. Confirmed by reading `signed_in/uploads.rs`.
   **Part status:** done, date not recorded
13. **The cookies set at sign-in are taken to be the session, unshown** (H14's fix): an app that keeps its pre-login
    session and sets another cookie at sign-in gets a false high V7.2.1 finding and a false V7.2.4 credit. Confirmed
    by reading `signed_in/sessions.rs`.
   **Part status:** done, date not recorded
14. **A log line of plain traffic can credit V16.3.1** when the logged path is written differently from `login.path`
    (suspected). `sv-check/src/logs.rs`.
   **Part status:** done, date not recorded
15. **The app's standard output and error are joined end to end, not interleaved**, so a log window can miss an event
    on the other stream (a miss, never a false credit). Confirmed by reading `sv-run/src/lib.rs`.
   **Part status:** done, date not recorded
16. **Two untrue sentences**: the open-redirect evidence says "with `next` set" when nine parameters were, and the
    invented-session evidence says "the same length" for a cookie shorter than 16 characters. Confirmed by reading.
   **Part status:** done, date not recorded
17. **Masking is narrower than detection**: a Dockerfile `ENV NAME value`, and a YAML or properties value after a `&`
    or `,`, are found and not wholly masked, so the fingerprint hashes the credential again (R4). A reviewer tested the
    patterns with Python.
   **Part status:** done, date not recorded
18. **The SQL rule misses the usual query calls of some languages and credits V1.2.4**: Go's `QueryRowContext`,
    `Prepare`, `PrepareContext`; Kotlin's `prepareStatement`; C#'s `CommandText` assigned and then executed.
    Confirmed by reading `data/ast-rules.json`.
   **Part status:** done, 10 October 2026
19. **The open-redirect rule judges a destination safe by how it starts**: `redirect("/home" if not nxt else nxt)`
    credits V3.7.2. Confirmed by reading.
   **Part status:** done, date not recorded
20. **"The manifest and lockfile disagree" for dependencies the readers never list**: pnpm and Yarn `workspace:` and
    `file:`, npm aliases, and `pkg @ git+…` in requirements.txt. Confirmed by reading `manifest_lock.rs` and `sbom.rs`.
   **Part status:** done, date not recorded
21. **A panic on a build file**: `implementation 'g:a:['` slices `[1..0]` in `gradle_range`. Confirmed by reading.
   **Part status:** done, 10 October 2026
22. **The `shell: true` rule flags fixed argument lists in JavaScript and Python**, whose grammars call a list `array`
    and `list`. Confirmed by reading `ast.rs`.
   **Part status:** done, 10 October 2026
23. **`go.mod` is compared with itself**: since A3 its lock list comes from its own `require` lines, so the comparison
    DESIGN describes can never disagree. Confirmed by reading `sbom.rs`.
   **Part status:** done, date not recorded
24. **Smaller, suspected or narrow:** a tool's first error line quoted without masking (`adapters.rs`); names bound
    by an arrow function's bare parameter or a destructured one not recorded (`ast.rs`); a notes file with two
    sections for one requirement asked about twice in `sv review`; a lock removed on Ctrl-C without the same-file
    check where the disk cannot lock; folders left behind by a failed MCP write to `a/b/c`.
   **Part status:** done, date not recorded
**The owner's decisions, 6 October 2026:** fix all of them, the worst first, in batches. Item 8: with no key on this
computer a sealed answer is not counted as the owner's, and the report says it carries a seal this computer cannot
check and what to do (run `sv review` once here, or read the report on the computer it was sealed on). Item 11: a
seal names the app it was made for, so a copy into another app does not count; answers already sealed are sealed
again with `sv review`.
**Items 1, 2, 3, 4, 12, and 13 claimed the same day by session securevibe-e2**, at the owner's word, as the first
batch (each credits or accuses wrongly), in branch `claude/securevibe-e2-review-1to4-batch1`.
**Items 18, 20, 21, 22, and 23 claimed the same day by session securevibe-e9**, at the owner's word ("continue to
work off the backlog"), as the next batch (the code-reading rules and lockfiles), in branch
`claude/securevibe-e9-review-1to4-batch3`.
**Items 18, 20, 21, 22, and 23 done the same day by session securevibe-e9** (DESIGN, "The code-reading rules and
lockfiles: five faults from the review of 1 to 4 October"). All five were real; each fix has a case that failed
before it.
**Items 5, 6, 7, and 14 claimed the same day by session securevibe-e9**, at the owner's word ("continue to work off
the backlog"), as the next batch (each running-app check that may credit or accuse wrongly), in branch
`claude/securevibe-e9-review-1to4-batch2`.
**Item 14 done the same day by session securevibe-e9** (DESIGN, "A log line of plain traffic is not a record of a
sign-in"): every path is taken out of a log line before its words are read. Items 5, 6, and 7 were built by session
securevibe-e2 in #797, which merged first, so this session's versions of them were dropped.
**Items 8 and 11 claimed the same day by session securevibe-e2**, at the owner's word and as the owner decided
them, as the second batch (seals), in branch `claude/securevibe-e2-review-1to4-seals`.
**Items 8 and 11 done the same day** (DESIGN, "The review of 1 to 4 October, batch 2: seals"; ADR-026, "Later, 6
October 2026").
**Items 18, 19, 21, and 22 claimed the same day by session securevibe-e2**, at the owner's word, as the fourth batch
(the code-reading rules: two credit what they should not, one flags what is safe, and one stops `sv` on a build
file), in branch `claude/securevibe-e2-review-1to4-b4`. **That claim was a mistake for 18, 21, and 22**: session
securevibe-e9 had claimed them (with 20 and 23) first (#791), and securevibe-e2 did not read `main`'s
backlog again before claiming, so it built them a second time. securevibe-e9's fixes went in first (#794) and stand;
securevibe-e2's copies were dropped, and only item 19 goes in from this branch. The same happened with items 5, 6,
and 7, which securevibe-e9 had claimed (with 14) at 03:41 and securevibe-e2 claimed again at 04:27 and built (#797,
merged); securevibe-e9's open #790 is titled for item 14 alone. Two sessions working the same review at once must read
`main`'s backlog just before each claim, not only at the start.
**Item 19 done the same day by session securevibe-e2** (DESIGN, "The review of 1 to 4 October: a redirect read
whichever way it goes").

**Items 1, 2, 3, 4, 12, and 13 done the same day** (DESIGN, "The review of 1 to 4 October, batch 1").
**Items 5, 6, and 7 claimed the same day by session securevibe-e2**, at the owner's word, as the third batch (the
fetch and AI checks: each credits or accuses on an answer it did not wait for or read), in branch
`claude/securevibe-e2-review-1to4-b3`. All three were confirmed by reading `fetch.rs` and `ai.rs` on `main` first.
**Items 5, 6, and 7 done the same day** (DESIGN, "The review of 1 to 4 October, batch 3").
**Items 9, 10, 15, 16, 17, and 24 claimed the same day by session securevibe-e2**, at the owner's word, as the last
batch (a report lock, the notes seal, the run's output, two untrue sentences, masking, and the smaller ones), in
branch `claude/securevibe-e2-review-1to4-b5`. Read on `main` just before this claim: no other session had claimed
them.
**Items 9, 10, 15, 16, 17, and 24 done the same day** (DESIGN, "The review of 1 to 4 October, the last batch").
With them, every item of this review is done.

**Checked against origin/main, 10 October 2026:** every part is in the closing note as done. Parts 18, 21 and 22 checked: `QueryRowContext` in `data/ast-rules.json`, `gradle_range` guarded in `manifest_lock.rs`, and fixed argument lists treated as fixed (`crates/sv-check/src/ast/tests.rs`). Other parts spot-checked only.
