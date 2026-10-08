# The deep review of `sv` at `eff3f17`, part 3 of 3: accuracy (A1 to A6), reviews and reports (R3 to R14), and improvements

**Status:** partly done: see its done note; what remains is not yet written, as its markers read on 8 October 2026

Same sender. **Each item can be claimed on its own.** R1 and R2 are in part 1.
- **A1. Medium, Reproduced, and the pattern in the owner's study.** The SQL, redirect, and file-path rules cannot
  tell constants or checked values from input: `execute(QUERY, (uid,))`, a query with bound parameters, Go's
  `QueryContext(ctx, ...)` (the first argument is always `ctx`), `res.redirect(`/users/${id}`)`, `open(HERE /
  "data" / ...)`. Seven of family-hub's eight SQL findings were false alarms. Fix: a shared helper that treats
  ALL_CAPS module constants and names bound once to a literal as literals; bound parameters lower the confidence;
  each sink's argument position; a path starting `/` and then not `/` cannot leave the site.
  **Claimed on 4 October 2026 by session securevibe-e10**, at the owner's asking, in branch `claude/a1-constants`,
  for those four fixes, with item 1 of "Three false alarms on code that does the safe thing" (`SCHEMA`, and a
  lookup in a dictionary of fixed queries), which is the same fault. Not in this claim, and still open: that
  entry's items 2 and 3 (a path from the app's own database, a destination already checked) and the redirect half
  of the family-hub item 7, which need a judgment about the app's own functions. (Items 2 and 3 were done on
  5 October 2026 by session securevibe-e9, #738, at the owner's decision; the redirect half of item 7 is claimed
  under item 7 of "What the owner hit building family-hub".)
  **Done the same day** (DESIGN, "Names that stand for fixed text"): a per-file list of names the file binds once
  to fixed text, ALL_CAPS names bound once at the top of the module, and tables of fixed text, consulted wherever
  a rule asks whether an argument is fixed, in Python, JavaScript, TypeScript, and Go; Go's `...Context` calls
  judged on their query; a query that is only a name, with values beside it, reported low with the reason; and a
  redirect to a path opening with one slash and an ordinary character not reported. Twenty-four new witnesses and
  two tests; eleven guards broken in turn, each caught (the spread's only on a second, stronger mutation).
- **A2. Medium, Read.** Review fingerprints collide on identical lines, and survive a change to the line that
  matters. Fix: an occurrence index or the enclosing function; one entry matches one finding.
  **Claimed on 5 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
  `claude/r3-a2-review-matching`.
  **Done the same day**, with R3 (DESIGN, "A review names one finding, and says whether its rule looked"; ADR-023
  and ADR-026, "Later, 5 October 2026"): today's fingerprint (`v2-...`) also reads the lines above that set a name
  the flagged line uses, and which of the identical lines it is, so identical lines each need their own entry and
  changing `sql = "...?"` to `sql = "..." + user` ends the false alarm. An entry in the earlier form still matches
  the one finding it did; on identical lines it matches none and says so. Seals still verify (nothing rewrites a
  sealed entry); `sv review` writes today's fingerprint when it records one in the earlier form. Tested with
  identical lines, changed and unchanged lines above, an earlier-form entry sealed and unsealed, and family-hub's
  25 entries on a copy (16 match as before, 2 on identical lines say so). Guards broken in turn: each caught.
- **A3. Low to medium, Reproduced.** `go.sum` is read as the installed versions, so superseded ones are reported.
  Fix: take `go.mod`'s `require` lines.
  **Claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking, in branch
  `claude/securevibe-e9-a3`.
  **Done the same day** (DESIGN, "A Go app's modules are read from go.mod"): go.mod's `require` lines with its
  `replace` lines applied; a module replaced by a folder is named as not listed; before Go 1.17, a module in
  go.sum alone is listed at its highest version there.
- **A4. Low, Read.** Placeholder words (`xxx`, `todo`) match inside real keys, dropping about 1% of random JWTs.
  Fix: whole words only.
  **Claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking, in branch
  `claude/securevibe-e9-a4`.
  **Done the same day** (DESIGN, "A placeholder word in a key counts only where chance would not put it"): the
  short markers `todo` and `xxx` count only as words of their own, the longer ones anywhere as before (AWS's
  `AKIAEXAMPLEEXAMPLE12` shape needs it); of 20,000 random JWTs, 66 were dropped before and none now.
- **A5. Low, Read.** Secret rule data: Slack's `xapp-` promised and not matched; PGP private key blocks missed;
  `sk_test_` keys graded critical.
  **Claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking, in branch
  `claude/securevibe-e9-a5`.
  **Done the same day** (DESIGN, "The secret rules find what they promise, and grade a test key below a live
  one"): `xapp-` tokens and PGP private key blocks are found; a Stripe test key has its own rule at medium, and
  `secrets.stripe-key` is for live keys only.
- **A6. Medium, Reproduced.** The bundle's list of secret files misses `prod.env`, `.envrc`, `.pgpass`,
  `.docker/config.json`, `*.tfvars`, `*.tfstate`, `.kube/config`, and a `database.yml` with a password.
  **Claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking, in branch
  `claude/securevibe-e9-a6`.
  **Done the same day** (DESIGN, "The bundle leaves out the secret files the review named"): every file the
  review named stays out of the zip, `example.env` and the like still go in, and a `database.yml` with a password
  written in it stays out even when the credential scan does not flag it.
- **R3. Medium to high, Reproduced.** A review for a rule that did not run, or that this version lacks, is
  reported as "the finding is gone": 7 of family-hub's 25 reviews. Fix: three messages: not looked for this time,
  unknown to this version, gone.
  **Claimed on 5 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
  `claude/r3-a2-review-matching`.
  **Done the same day**, with A2 (same DESIGN section): an entry that matches nothing says "not looked for this
  time" with why (needs `--run` or `--tools`, the file did not parse, no parser, not taught), "unknown to this
  version", or, only when its rule read its file, that it is gone; the first two say they are not a sign of a fix,
  in the report and over MCP. Decided from `examined`, which gained `tests.`, `design.`, and `hand.`. Each message
  reached on purpose end to end; family-hub's 7 `tests.` entries now say "not looked for this time". Thirteen
  guards (both items) broken in turn, each caught by one to three tests. Merged with R11's rule, which decides
  duplicates and conflicts; neither is ever told its finding is gone.
- **R4. Medium, Reproduced.** The credential fingerprint is an unsalted hash of the line, and the report also
  shows the name, first four characters, and length, so a test password was recovered offline in 190 guesses.
  Fix: hash the line with the value masked, or use a key kept locally.
  **Claimed on 5 October 2026 by session securevibe-e2**, at the owner's asking to continue with the backlog, in
  branch `claude/securevibe-e2-fingerprint`.
  **Done the same day.** The fingerprint is now the hash of the line with the credential masked, as the report
  shows it, so it tells nothing the report does not; a line with no credential keeps the fingerprint it had. A
  review recorded by an older `sv` for a credential line is said to be one, and to be recorded again. See DESIGN,
  "A credential's fingerprint says nothing the report does not".
  **Merged with A2 the same day**: today's fingerprint masks the flagged line and every line above it that it
  reads, and `earlier_fingerprints` gives only the masked earlier form, never the hash an `sv` before R4 gave a
  credential's line (ADR-023, Later). Tested in `report.json`, the SARIF, both reports, and the MCP reply.
- **R5. Medium, Reproduced.** The count tables and headline leave out attested, stated, and by-hand, so they do not
  add up. Fix: every status, and a test that the rows sum to the applicable total.
  **Claimed on 5 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
  `claude/r5-counts-add-up`.
  **Done the same day** (DESIGN, "The counts add up to what applies"): every table and sentence that counts what
  applies is made from one list of all seven statuses, so compliance.md's and report.html's tables, their opening
  sentence, the terminal's summary, and the AI coding tool's summary each add up to the total, with somebody's word
  in rows of its own that say whose. report.json was already whole and is unchanged. Reproduced first on a copy of
  `examples/tested-notes` with a finding, a check, and the owner's and the tool's answers (8 + 118 of 130); tested
  end to end on that app in every format; seven guards broken in turn, each caught.
- **R6. High for CI users, Reproduced.** `sv report` and `sv check` exit 0 whatever happened. Fix: `sv audit`'s
  convention: 1 for something needing attention, 2 for something not assessed, 0 only otherwise.
  **Claimed on 4 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
  `claude/r6-exit-codes`.
  **The owner's decision, 4 October 2026:** measured first, the convention as written would have failed every
  pipeline (every app in `examples/` and from `sv init` exited 1 or 2 on a plain static run: the low security.txt
  finding, checks needing a Dockerfile or a git repository, and 121 to 230 requirements "not verified by
  anything"). So: by default `sv check` and `sv report` exit 0, and 2 only when a check could not run or no file
  was read; `--fail-on attention[:SEVERITY]`, `not-assessed`, or `any` opts in to 1 and to a wider 2, never for
  "not verified by anything"; and any run where `sv` itself fails exits 3, everywhere, `sv audit`'s errors moving
  from 1 to 3 (ADR-029).
  **Done the same day** (DESIGN, "Exit codes for CI"; ADR-029): `crates/sv-cli/src/exit.rs` holds the codes, the
  exact list of what is a check that could not run, and `--fail-on`; `main` ends every error with 3; `sv audit`
  shares the constants. Each command's `--help`, `sv --help`, the README, and GETTING-STARTED say what each code
  means. Tested through the binary (`tests/exit_codes.rs`): 0, 1, 2, and 3 reached on purpose for `sv check`,
  `sv report`, and `sv audit`. Seven guards broken in turn, each caught by one to seven tests. On the examples,
  every default run exits 0; on five real apps with a manifest, four exit 0 and one exits 2 for a web page whose
  script could not be read.
- **R7. High, Reproduced.** `sv notes` and the MCP notes tool delete the owner's own text, though the tool says it
  keeps everything. Fix: keep unrecognized text in its own section, or refuse without a backup.
  **Claimed on 4 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
  `claude/r7-notes-keep-owner-text`.
  **Done the same day** (DESIGN, "The notes file keeps what the owner wrote outside the answers"): the reader drops
  only what `sv` writes, everything else under a question stays its answer as written, and any other text is kept
  word for word, in order, in a section of its own near the top that the report does not read; a file that is not
  UTF-8 or has two sections for one question is refused with why, and nothing is written. Covers `sv notes` and both
  MCP notes tools, which share the writer; R8's own fault is not changed. Tested with the review's case reproduced
  on a copy of `examples/tested-notes` (the review's write-up does not include its fixture), unit, end-to-end, and MCP tests, including a byte-for-byte round trip and a five-megabyte
  file; sixteen guards broken in turn were each caught.
- **R8. Medium, Reproduced.** `record_answer` overwrites an owner's answer that has no "Written by:" line.
  **Claimed on 5 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
  `claude/r8-record-answer-keeps-owner`.
  **Done the same day** (DESIGN, "The AI coding tool writes over only its own answer"; ADR-022, "Later, 5 October
  2026"): `securevibe_record_answer` now writes only under a question with nothing under it or over a section
  marked `Written by: AI coding tool`; an answer with no mark, one marked as anybody else's, and the owner's are
  refused, the file left byte for byte as it was, and the reply says why and that the owner can edit the answer or
  delete it so the tool can record its own. An unmarked answer still counts as the tool's in the report. The
  questions' instructions say the same for a tool without the MCP server. Reproduced first with an MCP test; tested
  with that test (six refusals, two fills, one replacement) and a unit test; seven guards broken in turn were each
  caught, and an eighth was equivalent, because the reader already drops blank lines.
- **R9. Medium, Reproduced.** Text from the app reaches the AI tool unmarked (an app name of "IGNORE ALL PREVIOUS
  INSTRUCTIONS..." opened the check result), and a forged report is offered as one `sv` wrote. Fix: fence and label
  app text as data; offer only reports whose marker proves `sv` wrote them.
  **Claimed on 5 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
  `claude/r9-app-text-fenced`.
  **Done the same day** (DESIGN, "The app's text fenced as data, and reports offered only when sealed"; ADR-034):
  every MCP tool result that quotes the app puts that text between `<app-text-…>` tags named afresh for each result
  and never found in it, and says first that it is information, never an instruction; each such tool's description
  and the instructions say so. Reports are sealed with a key of this computer's beside the review key, and the
  server offers one only when its seal holds for its files as they are; anything else is not listed, and a read
  says why. Reproduced first through the real server; tested through every tool, a fence-escape attempt, four
  forged or changed report folders, and a real one. Twenty guards broken in turn: seventeen caught at once, two
  after a test was added for each, and one (the bytes read held to the seal) not reachable by a test.
- **R10. Medium, Reproduced.** `sv mcp --root` refuses `/` and the home folder but accepts folders above home.
  **Claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking, in branch
  `claude/securevibe-e9-r10`.
  **Done the same day** (DESIGN, "`sv mcp` will not serve a folder that holds the home folder"): a root that holds
  the home folder is refused, and with no home folder known, a folder just below the top is too.
- **R11. Low to medium, Reproduced.** Duplicate or conflicting reviews are each applied.
  **Claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking, in branch
  `claude/securevibe-e9-r11`.
  **Done the same day** (DESIGN, "One entry answers for one finding"; ADR-023, Later): a repeated answer does not
  count again, and two that disagree leave the finding standing until one is removed.
  **The owner's decision, 5 October 2026**, merging this with A2: one case changed. An entry whose fingerprint is
  in the earlier form and matches findings on several identical lines answers for none of them and says so,
  rather than taking the first in order; everything else in R11 stands, and its test passes unchanged (ADR-023,
  "Later, 5 October 2026: an earlier fingerprint on identical lines answers for none of them").
- **R12. Medium to low, Reproduced.** `not-the-app` can cover all of the app's code without a warning, turning a
  requirement from applicable to "does not apply".
  **Claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking, in branch
  `claude/securevibe-e9-r12`. Record: ADR-031 (proposed).
  **Claimed on 5 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
  `claude/r12-not-the-app-warning`.
  **The two claims crossed:** securevibe-e9's was committed at 03:48 UTC and open as #674 from 03:49, and the
  cato-pipeline session's (#677) was made at 03:55, before #674 reached `main`. securevibe-e9's was built, so it
  is the one that went in; nothing of the other had been pushed.
  **Done the same day** (DESIGN, "A `not-the-app` list that would set apart all the code is not used"; ADR-031,
  accepted): a list that would leave none of the app's code files outside it is not used, in every command, and
  the report says why; a list that is used is shown with how many of the code files it set apart.
- **R13. Low, Reproduced.** `security.md` and `compliance.md` insert app text without escaping; `report.html`
  escapes correctly.
  **Claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking, in branch
  `claude/securevibe-e9-r13`.
  **Done the same day** (DESIGN, "App text in the Markdown reports is inert"): every table cell, the app's name,
  and each finding's text are escaped outside code spans, so no link, image, or HTML of the app's is live; a file
  path is shown in a code span it cannot close; the escaped redaction marker is still read as one.
- **R14. Low, Read.** SARIF locations are not valid addresses for running-app findings or paths with spaces, and
  rule descriptions take one instance's text.
  **Claimed on 5 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
  `claude/r14-sarif-locations`.
  **Done the same day** (DESIGN, "SARIF addresses are addresses, and a rule is described in its own words"): a
  file's URI is percent-encoded as an RFC 3986 relative reference; a running-app finding points at
  `securevibe.toml`, which says how the app was run, with the place named in the location's message, a logical
  location, and `properties.place`, since GitHub shows no result without a file; a rule kept as data is described
  in its own words, any other by what all its findings share. Four tests, each failing before; six guards
  undone in turn, each caught.
- **Improvements (not faults).** 1: the shared constant helper of A1, the largest single cut in false alarms.
  2: clean claims that name their limits (the calls per language, the ecosystems, transitive and development
  dependencies). 3: time limits and a clean environment for outside tools (`GOTOOLCHAIN=local`). 4: score CVSS
  v4 (2,340 OSV records carry only v4), and count advisory files that fail to parse. 5: a random marker per run for
  helper output, two-factor codes from the container's clock, seed secrets through standard input, control
  characters stripped from app output, WebSockets and workers watched in the browser driver. 6: validate
  `manifest-version`, refuse trailing text after dates, a stray `</details>` in `report.html`, let a false alarm
  lapse when nearby lines change. 7: refuse an option value starting `--`, do not overwrite a bundle without
  asking, one error for "outside the root" and "does not exist".
  **Improvement 3 claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking to keep working
  off the backlog, in branch `claude/securevibe-e9-tool-limits`: a time limit on every outside tool, and an
  environment with only what a tool needs to run, `GOTOOLCHAIN=local` among it.
  **Done the same day** (DESIGN, "Outside tools run for at most half an hour, with only the environment they
  need"; ADR-018, Later): stopped after half an hour with everything it started, not read when stopped, and
  handed only a short list from the owner's environment, with `GOTOOLCHAIN=local`.
  **Improvement 7 claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking to keep working
  off the backlog, in branch `claude/securevibe-e9-cli-guards`: an option's value that is another option is
  refused, a bundle replaces only a zip `sv` made, and the MCP server gives one answer for a path that is
  outside its folder and one that does not exist.
  **Done the same day** (DESIGN, "An option is never a value, a bundle replaces only its own, and one answer for a
  path"; ADR-017, Later).
  **Improvement 6 claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking to keep working
  off the backlog, in branch `claude/securevibe-e9-validate`, for three of its four parts: `manifest-version`
  checked, text after a date refused, and the stray `</details>` in `report.html`. The fourth, a false alarm
  lapsing when nearby lines change, rests on the fingerprint, which #678 (R3, A2) is changing, and is left to it.
  **The fourth was done by #678** (A2 above): today's fingerprint also reads the lines above that set a name the
  flagged line uses, so changing one of them ends the false alarm. Noted on 5 October 2026 by session securevibe-e9.
  **Improvement 4 claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking to keep working
  off the backlog, in branch `claude/securevibe-e9-cvss4`: CVSS v4 vectors scored with FIRST's reference tables,
  and advisory files that fail to parse counted and said. Record: ADR-033 (proposed).
  **Done the same day** (DESIGN, "CVSS v4 scores, and advisory files that could not be read"; ADR-033, accepted):
  v4 scored with FIRST's tables and held to its calculator over every vector there is; a file that could not be
  read is named, and the comparison is not credited as whole.
  **Those three done the same day** (DESIGN, "A manifest version `sv` knows, a date with nothing after it, and
  every collapsed list closed").
  **Improvement 5 claimed in part on 5 October 2026 by session securevibe-e9**, at the owner's asking to keep
  working off the backlog, in branch `claude/securevibe-e9-markers`: a random marker per run for helper output,
  and control characters stripped from everything `sv` prints to a terminal. The other three parts (two-factor
  codes from the container's clock, seed secrets through standard input, WebSockets and workers in the browser
  driver) are not claimed.
  **Those two done the same day** (DESIGN, "Markers made fresh for each use, and no control character to the
  terminal").
  **Improvement 5's "seed secrets through standard input" claimed on 5 October 2026 by session securevibe-e9**,
  in branch `claude/securevibe-e9-seed-env`: the run's passwords and two-factor secrets, and the test provider's
  client secret, are handed to `docker` in its own environment, not on its command line, where another user of
  the computer can read them.
  **Improvement 5's "two-factor codes from the container's clock" claimed on 5 October 2026 by session
  securevibe-e9**, in branch `claude/securevibe-e9-container-clock`: the signed-in checks' clock read as the app's
  containers read it, not this computer's, where Docker runs in a virtual machine whose clock can drift.
  **Done the same day** (DESIGN, "Two-factor codes made for the containers' clock").
  **Done the same day** (DESIGN, "The run's passwords never stand on a command line").
  **Improvement 5's "WebSockets and workers watched in the browser driver" claimed on 5 October 2026 by session
  securevibe-e9**, in branch `claude/securevibe-e9-ws-workers`: what a page sends elsewhere over a WebSocket, or
  from a worker it starts, is recorded with the rest of what it sends elsewhere.
  **Done the same day** (DESIGN, "What a page sends from its workers and over WebSockets"; ADR-019, Later):
  every worker, shared worker, and service worker the page starts is held until its requests are watched, and a
  WebSocket is recorded when the page opens it. This is the last of improvement 5's five parts to be built.
  **Improvement 2 claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking to keep working off
  the backlog, in branch `claude/securevibe-e9-clean-claims`: the comparison with advisories says, when it finds
  nothing, which ecosystems and lockfiles it compared and that development packages and the packages others need
  are among them; and each code rule's "nothing found" names, for each language, the calls it reads. The SQL
  rule's part was done with H1.
  **Done the same day** (DESIGN, "A clean result names the calls it read and the lockfiles it compared"): each
  code rule's clean result names, for each language, the calls its pattern reads, and the comparison with
  advisories and the inventory name each ecosystem's count, the lockfiles, that the packages those need and
  development packages are in it, and what no lockfile lists. Improvement 1 was A1's helper, built on 4 October.
- **Found sound, for the record.** `report.html` escaping; the framework data; unanswered questions never "does
  not apply"; reviews' accepted risks, secrets, and 90-day lapse; `deny_unknown_fields` everywhere; `sv`'s own
  walker on links and sizes; report files written create-then-rename; outside tools run without a shell and with
  `--`; MCP path confinement, size caps, and batch refusal; helper containers' hardening; `sv probe`'s cap and
  TLS; the CVSS v3 arithmetic, alias grouping, withdrawn records, and version ordering; linear-time regular
  expressions.
