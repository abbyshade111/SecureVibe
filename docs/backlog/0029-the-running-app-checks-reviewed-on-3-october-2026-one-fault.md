# The running-app checks, reviewed on 3 October 2026: one fault in the counts, and what to add

**Status:** partly done: parts 9 (C9.1.1's per-tool quotas), 13 (a limit kept by a proxy in production), 14 (a run against a real app), and 15 (tar, 7z, and rar; archives whose stated sizes are false)

By session
securevibe-e9, at the owner's asking ("review them and then propose additional checks that would provide strong
evidence"). Read: every check that asks the running app (31 as a stranger, 17 of the AI feature, 83 signed in,
7 against the live site), where each gives credit and where it only raises a finding, and every level 1 and 2
ASVS and AISVS requirement no running check speaks to. **Each numbered item can be claimed on its own.**
1. **`docs/COVERAGE.md` counts 18 requirements as checkable by a clean run when nothing can credit them.** 21
   checks only ever raise a finding, and `tools/coverage.py` does not list them in `RUST_FINDINGS_ONLY`:
   `probe.directory-listing`, `probe.docs-or-monitoring-exposed`, `probe.jsonp-enabled`,
   `probe.unused-method-accepted`, `probe.version-disclosed`, `probe.account-details-sent-elsewhere`,
   `probe.activation-code-guessable`, `probe.activation-link-reusable`, `probe.default-account`,
   `probe.email-code-short`, `probe.forwarded-for-trusted`, `probe.password-in-url`, `probe.password-paste-blocked`,
   `probe.reset-code-guessable`, `probe.reset-keeps-old-password`, `probe.reset-reusable`,
   `probe.reset-reveals-account`, `probe.session-id-weak`, `probe.sign-out-on-get`,
   `probe.validation-only-in-the-browser`, and `probe.websocket-after-sign-out`. Each was confirmed by reading where
   it reports: none reaches a `Verified`. The requirements no other running check credits: V2.2.2, V3.5.3, V3.5.6,
   V4.1.4, V4.4.3, V6.2.7, V6.3.2, V6.3.8, V6.4.1, V6.4.3, V6.5.4, V7.2.3, V13.4.3, V13.4.5, V13.4.6, V14.2.1,
   V14.2.3, and V15.3.4. The reports are honest, since they never credit these; only the counts are wrong. A test
   that fails when a check that never credits is not listed would stop it happening again.
   **Claimed on 3 October 2026 by session securevibe-e9**, at the owner's asking, in branch
   `claude/securevibe-e9-findings-only-counts`.
   **Done the same day:** the 21 are in `RUST_FINDINGS_ONLY`, so `docs/COVERAGE.md` and `docs/REQUIREMENTS.md`
   mark each as "only ever as a finding". Not done: the test that would catch the next one. A check gives credit
   through helpers and tables of rules as often as by name, so reading the code for it is not reliable enough to
   fail a build on; running every check against the fake apps and collecting what each credited would be.
   **The test claimed on 6 October 2026 by session securevibe-e9**, at the owner's asking ("pick another item from
   the backlog"), in branch `claude/securevibe-e9-credit-census`: record every credit the test suite gives, by check,
   and fail when a check listed as findings-only is credited, or one never credited is not listed.
   **Done the same day:** `Verified::new` writes each credit, with the place that gave it, to `SV_CREDIT_LOG` in a
   debug build, and `tools/coverage.py --credits` holds the lists to it after CI's tests (DESIGN, "What the suite
   credits is counted"). The first census found three more: `probe.password-hints` (V6.4.2) and
   `secrets.credential-assignment` (V13.2.3) never credit and are now listed, and `probe.cors-any-origin` credits
   but no test reached it, which one now does.
   **Settled 8 October 2026** (session securevibe-e2, from the roadmap, Phase 1 item 3), read against `main`: the test
   this part asked for exists. CI runs the suite with `SV_CREDIT_LOG` and then `tools/coverage.py --credits`, which
   fails when a check credits and is listed as only ever a finding, or never credits and is not listed, so the next
   such check is caught by what it does, not by reading its code.
2. **Finding-only checks that already have a control, and could give credit.** The reset link used once and then
   refused (V6.4.3); the old password refused after a reset while the new one works (V6.4.3); the activation link
   refused the second time (V6.4.1); a WebSocket refused after sign-out where it opened before (V4.4.3); signing
   out by visiting an address leaving the session alive while the sign-out form ends it (V3.5.3); and the server
   refusing a value its own form forbids (V2.2.2). Each would credit only what it saw, as the others do.
   **Withdrawn on 3 October 2026 by session securevibe-e9, which proposed it:** read against `docs/DESIGN.md`
   before any code was kept, each of the six is finding-only on purpose, for a reason written there. A clean reset
   leaves V6.4.3's own demand, that a reset not get round two-factor sign-in, untried, as it does code expiry
   ("a clean reset credits nothing and says so"); activation leaves V6.4.1's expiry and initial passwords untried;
   V4.4.3 asks that a socket's own tokens meet every session requirement; one address refusing a GET says nothing
   of the others (V3.5.3); and the V2.2.2 check is only ever a finding by design. A test
   (`a_reset_that_works_once_is_followed_through_and_faults_nothing`) holds the reset's no-credit decision, and it
   went red when the credit was tried.
   **Settled 8 October 2026** (session securevibe-e2, from the roadmap, Phase 1 item 3): the withdrawal above is
   this part's outcome, so it is marked here in the words the backlog board reads; the board had counted it open.
3. **The stranger checks credit headers from one answer.** Security headers, cookies, and content types are
   credited from the answer on the health path, which is often a small JSON status reply rather than a page
   anyone sees. Judge every page the run fetched (the home page, the signed-in private pages) and credit only
   when all pass, naming them.
   **Claimed on 3 October 2026 by session securevibe-e9**, at the owner's asking, in branch
   `claude/securevibe-e9-headers-every-page`.
   **Done the same day** (DESIGN, "The headers a browser relies on, on more than the health path"). The root page
   is asked too and judged when it answers with a page; a finding names the page that fell short, and the credit
   needs every page judged to pass. `probe.private-page-headers` asks the same four headers of each private page
   the signed-in run opens. Five guards broken in turn, each caught. Not done: the cookies a signed-in page sets,
   which `probe.session-cookie-attributes` already judges at sign-in, and pages the run does not ask for.
   **The rest of part 3 claimed 9 October 2026 by session securevibe-e9**, from the roadmap (Phase 1, item 3, its
   first open part), in branch `claude/stackvet-e9-page-cookies`: when a private page, opened with the signed-in
   session, sets a cookie that was shown to carry that session (one sign-in set, which the page was refused
   without), it is judged as at sign-in, HttpOnly and SameSite, and a page that sets it again without them is a
   finding naming the page. Cookies that do not carry the session are not held to HttpOnly. "Pages the run does not
   ask for" gets a done note rather than a build: a page nobody asks for cannot be judged, and the credit already
   names the pages it covers. Confirmed on `main` just before this claim: only the sign-in answer's cookies are
   judged (`sessions.rs`, `session_checks`), and no other session had claimed this part.
   **Done the same day** (`docs/design/0316-a-signed-in-page-that-sets-the-session-cookie-again-9.md`): a private
   page that sets the session cookie again is held to HttpOnly and SameSite as sign-in is, and found when it drops
   either; pages the run does not ask for cannot be judged, which the credit already says by naming its pages. With
   it, part 3 is done.
4. **Sign-in tokens the app issues itself (V9.1.1, V9.1.2, V9.2.1, V9.1.3; all level 1).** When the token the
   app hands the test user is a JWT, send it back altered with the same signature, with `alg: none`, past its
   expiry, and naming a key the probe controls (`jku`, `kid`). The real token opening the page is the control, so
   a refusal is real credit. Common in apps an AI coding tool writes; no proposal was on file.
   **Claimed on 3 October 2026 by session securevibe-e9 and released the same day, not built.** The work stopped
   at the design stage; nothing was written. The item is open again, and the owner decides whether it is taken up.
   **The owner's decision, 4 October 2026: yes**, the altered contents under the same signature, `alg: none`, and
   past its expiry, with the real token as the control. Not the two forms that point the app at a key the probe
   controls (`jku`, `kid`), which would need a key server inside the fence.
   **Claimed the same day by session securevibe-e2**, at the owner's word, in branch
   `claude/securevibe-e2-app-tokens`.
   **Done the same day** (DESIGN, "The sign-in token the app issues itself"): `probe.app-token-signature-not-checked`
   (V9.1.1), `probe.app-token-alg-none` (V9.1.2), and `probe.app-token-expired-accepted` (V9.2.1), each with the
   real token alone as the control. Expiry is asked only of a token due to run out within a minute, or within 90
   minutes with `sv run --slow`; a longer-lived token leaves V9.2.1 not assessed, saying so. Twenty-four guards
   broken in turn, each caught (one only after a test was added). V9.1.3 and the `jku`/`kid` forms not done, at
   the owner's word.
   **Settled 8 October 2026** (session securevibe-e2, from the roadmap, Phase 1 item 3), read against `main`: V9.1.3
   and the `jku` and `kid` forms were built later, under "V9.1.3: a token must not choose where the app gets its keys"
   (`docs/backlog/0026-…`), with a key server inside the fence; that item is done.
5. **Text reflected into a page without encoding (V1.2.1, V1.2.3; level 1).** A unique marker with `<"'` in a
   query parameter on every page the run visits: echoed raw is a finding, echoed encoded is credit for that page,
   and the marker appearing at all is the control.
   **Done on 3 October 2026** (DESIGN, "Text reflected into a page without encoding"), as findings only: an encoded
   echo is not credited, since one value on three pages is not every place the app writes out what it was sent.
   Twelve guards broken in turn, each caught: five by two tests or more, seven by the one test written for each.
   **Claimed on 3 October 2026 by session securevibe-e10**, at the owner's asking, in branch
   `claude/reflected-text`.
6. **Requests the app makes for someone (V1.3.6, V15.3.2, V13.2.4).** For a feature that fetches an address,
   named in `securevibe.toml`, give it the test model's canary inside the fence, which already records every
   fetch; a canary that answers with a redirect shows whether the app follows it. The fence makes this safe.
   **Done on 3 October 2026** (DESIGN, "A feature that fetches an address a person gives it"), behind
   `[stack.run.fetch]`: fetched is a finding against V1.3.6 and V13.2.4 and never credit, and a followed redirect is a
   finding against V15.3.2. Eight guards broken in turn, each caught.
   **Claimed on 3 October 2026 by session securevibe-e10**, at the owner's asking to continue with the backlog,
   in branch `claude/app-fetches`.
7. **SQL injection on the app's own records and search (V1.2.4; level 1).** The same request with an always-true
   and an always-false condition added; answers that differ show the database reading the input. Only ever a
   finding, read-only payloads only.
   **Claimed on 3 October 2026 by session securevibe-e9 and released the same day, not built.** The work stopped
   during design, before any code was written; it is left for the owner to decide how, or whether, to take it up.
   **The owner's decision, 4 October 2026: yes, limited** to requests that only read (GET: searches, and pages for
   one record), and only on the copy of the app `sv` starts itself, with its throwaway data, so an always-true
   condition can never reach a request that changes data. Only ever a finding, as above.
   **Claimed the same day by session securevibe-e2**, at the owner's word, in branch
   `claude/securevibe-e2-sql-injection`.
   **Done the same day** (DESIGN, "SQL injection on the app's own reads"): `probe.sql-injection`, only ever a
   finding, asks the last part of the address of A's record and each query-string value of each private page,
   with an always-true and an always-false condition as a number, as quoted text, and as quoted text either-or,
   each sent twice. Twenty guards broken in turn, each caught (one only after a test was added). Not done:
   requests that change data, JSON bodies, and conditions read by timing or by error messages.
   **The owner's decision, 6 October 2026, on what is not done:** keep the probe as it is, reading only, on
   `sv`'s own copy of the app (ADR-038): no requests that change data and no JSON bodies ("I agree with all your recommendations", 6 October 2026).
   **Settled 8 October 2026** (session securevibe-e2, from the roadmap, Phase 1 item 3), read against `main`: the
   owner's decision of 6 October 2026 above keeps the probe as it is, so what it leaves out is decided, and nothing
   here waits on a build.
8. **Open redirect (V3.7.2).** The sign-in flow's own return parameter, and `next`, `redirect`, `returnTo`, given
   a foreign address; a `Location` header pointing there is the finding.
   **Claimed on 3 October 2026 by session securevibe-e9**, at the owner's asking to continue with the backlog,
   in branch `claude/securevibe-e9-open-redirect`.
   **Done on 3 October 2026** (DESIGN, "Open redirects in the sign-in flow"), as a finding only:
   `probe.open-redirect` gives an address on `sv-redirect.invalid`, full and beginning with `//`, in `next` and
   eight other return parameters, to the sign-in, the sign-in page opened signed in, and the sign-out. Three guards
   broken in turn, each caught. Not done: redirects outside the sign-in flow, which the app's own addresses would
   have to name, and a run against a real app.
   **The owner's decision, 6 October 2026: yes** to redirects outside the sign-in flow, through a new optional
   `securevibe.toml` field naming the app's own addresses that take a destination ("I agree with all your recommendations", 6 October 2026). **Claimed on 7 October 2026 by session securevibe-e9**, at the owner's word ("feel free to pick
   your next backlog item"), in branch `claude/securevibe-e9-redirects`: `redirects` under [stack.run.users], the
   app's own addresses that send the browser on, each given the same outside address in the same nine parameters,
   signed in as A; only ever a finding.
   **Done on 7 October 2026** (DESIGN, "Open redirects outside the sign-in flow, on the pages `redirects` names"):
   `page_redirect_check`, the same outside address and nine parameters, one finding under `probe.open-redirect`.
   **Settled 8 October 2026** (session securevibe-e2, from the roadmap, Phase 1 item 3), read against `main`:
   redirects outside the sign-in flow were built on 7 October 2026, as the note above says. A run against a real app
   is a trial, which the owner asks for when wanted, not a build.
9. **An AI agent with no limit (C9.1.2, level 1; C9.1.1).** The test model asks for a tool again on every turn;
   credit when the app stops within a bound, a finding when it is still going after, say, 50 rounds.
   **Claimed on 3 October 2026 by session securevibe-e9**, at the owner's asking, in branch
   `claude/securevibe-e9-agent-limit`.
   **Done the same day** (DESIGN, "An AI agent with no limit on its tool calls"). The test model's `MCPLOOP` asks
   for the test MCP tool again after every result, up to 40 rounds; `probe.ai-agent-unbounded` is a finding when
   only that cap ended it, and credited when the app stopped sooner with an answer, as a limit on tool rounds.
   Two guards broken in turn, each caught. Not done: the app's own tools named in `record-tool`, which may not
   be read-only, and C9.1.1's per-tool quotas and timeouts.
   **The owner's decision, 6 October 2026:** call the app's own tools to test their limits only when
   `securevibe.toml` marks them read-only ("I agree with all your recommendations", 6 October 2026). Not claimed.
   **Claimed on 7 October 2026 by session securevibe-e2**, at the owner's word ("go ahead when you're ready"), in
   branch `claude/securevibe-e2-own-tool-loop`: a `read-only = true` on the record tool, and the C9.1.2 loop asked
   through it when marked, as the MCP loop is. C9.1.1's quotas and timeouts stay unclaimed. **Record, `Status:
   proposed`: ADR-045**, which writes down the owner's decision. Read on `main` just before this claim: no other
   session had claimed it.
   **Done the same day** (DESIGN, "An AI agent's limit, asked through the app's own read-only tool"; ADR-045,
   accepted). With `read-only = true` on the record tool, the test model asks for it again after every result, and the
   rounds are judged as the MCP loop's are; without it the tool is never called in a loop.
   **C9.1.1's timeouts claimed on 9 October 2026 by session paper-facts**, at the owner's word ("go ahead with part 9,
   yes"), in branch `claude/tool-timeout`: the test MCP tool `sv_lookup` holds its answer, as the held AI message is
   held, and an app that answers by itself within the time StackVet waits, while the tool is shown to be held, is
   credited for C9.1.1 in part (execution time, one tool; CPU, memory, disk and egress cannot be seen from outside).
   No finding: no answer in time cannot tell a longer limit from none. **Record, `Status: proposed`: ADR-064.**
   Checked just before this claim: not on `main`, in no open pull request, and in no recent branch.
10. **The AI service failing (V16.5.2, V16.5.3; C7.1.1 where the app asks for a structured answer).** The test
    model answers with an error, a timeout, or malformed JSON; credit when the app shows a plain error, keeps
    working, and passes on neither the raw error nor the bad structure.
    **Claimed on 3 October 2026 by session securevibe-e9**, at the owner's asking, in branch
    `claude/securevibe-e9-ai-failure`.
    **Done the same day** (DESIGN, "When the AI service fails"). The test model's `FAIL` answers 500 in the
    service's own error shape, carrying `SVERR` and the tag; `probe.ai-service-error-shown` (V16.5.1, only ever
    a finding) and `probe.ai-service-failure-handled` (V16.5.2, credited when the app fails cleanly and keeps
    answering). Three guards broken in turn, each caught. Not done: a service that answers slowly or not at all,
    and a malformed structured answer (C7.1.1).
    **C7.1.1 claimed on 6 October 2026 by session securevibe-e2**, at the owner's word ("Please continue to work off
    the backlog when ready"), in branch `claude/securevibe-e2-structured-answers`. Read on `main` just before this
    claim: no other session had claimed it. **Record, `Status: proposed`: ADR-042.** The test model answers in the
    shape an app asks for (a JSON schema, JSON mode, or a forced tool), which today it never does, so an app that
    asks for one fails every AI question for the test model's reason; and a new kind of message answers in the
    wrong shape. The marker in the app's answer is a finding; credit only after an ordinary answer of the right shape
    was seen shown, and the wrong one refused without failing. A service that answers slowly or not at all stays
    unclaimed.
    **Done the same day** (DESIGN, "Answers in the shape the app asked for, and C7.1.1"; ADR-042, accepted). The test
    model answers in the shape asked for, through every API it speaks. `probe.ai-output-shape-unchecked` is a finding
    when the app uses an answer that does not fit. It is credited only when the app showed a reply in the right shape
    and refused the wrong one without failing. Shown with the OpenAI and Anthropic SDKs and zod against the real test
    model; not run end to end under Docker here. A service that answers slowly or not at all is still not done.
    **A service that answers slowly or not at all claimed on 7 October 2026 by session securevibe-e9**, at the
    owner's word ("Please continue to work off the backlog when ready"), in branch `claude/securevibe-e9-ai-hang`.
    Read on `main` just before this claim: no other session had claimed it. The test model takes one message and
    answers nothing for 40 seconds. Credited (V16.5.2) when the app answered that message itself within the 15
    seconds `sv` waits on any request, without the service's error, and then answered a plain message; a finding when
    the plain message after it was not answered either; not assessed when only the hanging message went unanswered,
    since an app whose own limit is longer than 15 seconds cannot be told from one with none. Asked last, and the
    hold waited out, so an app it blocks does not spoil the checks after it.
    **Done the same day** (DESIGN, "Later, 7 October 2026: a service that answers nothing"). The test model's
    `HANG` holds a message unanswered for 40 seconds; `probe.ai-service-hang-handled` judges the app as claimed. Run
    with Node against the real test model script; not run end to end under Docker here.
    **Settled 8 October 2026** (session securevibe-e2, from the roadmap, Phase 1 item 3), read against `main`: both
    parts the note names are built: the malformed structured answer (C7.1.1, ADR-042, 6 October 2026) and the service
    that answers nothing (7 October 2026), each as the notes above say.
11. **Another user's documents reaching the AI (C5.2.2, C5.2.4, C8.1.3).** A marker planted in one user's
    document, then a chat as another user; the marker arriving at the test model is the finding. The same shape
    as `probe.ai-tool-reads-others-records`. Proposed in `docs/PARTIAL-CHECKS.md` for C5.2.2.
    **Done on 3 October 2026** (DESIGN, "Another user's notes reaching the AI"), as findings only, behind
    `reads-owned = true` under [stack.run.ai]. Seven guards broken in turn, each caught: three by two tests or more.
    **Claimed on 3 October 2026 by session securevibe-e10**, at the owner's asking, in branch
    `claude/ai-others-documents`.
12. **The app's own MCP server, hardened (C10.2.1, C10.4.3, level 1; C10.4.4, C10.4.5).** No token, a junk token,
    an undeclared parameter, the wrong type, and an oversized payload, each against the ordinary call as the
    control. Proposed in `docs/PARTIAL-CHECKS.md` for C10.2.1 and C10.4.3.
    **Done on 3 October 2026** (DESIGN, "The app's own MCP server: its token, and arguments it should refuse"),
    behind `token-env`, `public`, and `probe-tool` under [stack.run.mcp-server]. Twelve guards broken in turn, each
    caught.
    **Claimed on 3 October 2026 by session securevibe-e10**, at the owner's asking to continue with the backlog,
    in branch `claude/app-mcp-hardened`.
13. **Limits and double-booking on the owner's own actions (V2.4.1, V2.3.4).** A burst, and parallel requests, at
    an action `securevibe.toml` names; more successes than its stated limit is the finding. Proposed in
    `docs/PARTIAL-CHECKS.md`.
    **Claimed on 3 October 2026 by session securevibe-e9**, at the owner's asking, in branch
    `claude/securevibe-e9-limits`.
    **V2.3.4 done on 3 October 2026** (DESIGN, "An action sent many times at the same instant"):
    `probe.action-done-twice`, through a new `once` entry, sent 20 times together by a new `send_at_once`. The
    Docker runner's script was run against a local server with and without a lock, not yet in the busybox image.
    **V2.4.1 done the same day** (DESIGN, "A burst of creations, held to a stated limit"): `probe.create-rate-unlimited`,
    one record more than a new `[policy] requests-per-minute`, created through `owned` by B. Nothing is judged without
    a stated number. Not done: functions other than `owned`, and a limit kept by a proxy in production.
    **The owner's decision, 6 October 2026: yes** to functions other than `owned`, through a new optional
    `securevibe.toml` field naming them ("I agree with all your recommendations", 6 October 2026).
    **Claimed on 7 October 2026 by session securevibe-e9**, at the owner's word ("go ahead"), in branch
    `claude/securevibe-e9-create-rate`: an optional `creates` list under [stack.run.users], each a request that
    makes a record, held to the same `[policy] requests-per-minute` as `owned`'s create.
    **Done the same day** (DESIGN, "The creation rate, beyond `owned`"): `creates`, each burst and judged on its
    own.
14. **Changing the email address without the password again (V7.5.1).** The shape of
    `probe.password-change-without-current`. Proposed in `docs/PARTIAL-CHECKS.md`.
    **Claimed on 3 October 2026 by session securevibe-e9**, at the owner's asking to continue with the backlog,
    in branch `claude/securevibe-e9-email-change`.
    **Done on 3 October 2026** (DESIGN, "Changing the email address without the password"):
    `probe.email-change-without-password`, through a new `change-email` entry, only ever on an account made for it
    through `signup`. A change counts as taken only when the new address signs in, so an app that signs in by user
    name, or that waits for the new address to be confirmed, is not assessed rather than passed. Not yet run
    against a real app: the example has no email change.
15. **Upload names with `../` (V5.3.2, level 1) and compressed bombs (V5.2.3).** Extends the upload probes: a
    file named to land outside the upload folder, then asked for where it would have landed.
    **The `../` half done on 3 October 2026** (DESIGN, "A file named to land outside the upload folder"): found one
    folder above where uploads are served is a finding; refused, or saved under its last part, is credited; found in
    neither is not assessed. Eight guards broken in turn, each caught; the one caught by nothing at first (a place
    counts only when it answers with the run's value) now has a fake app that answers every address.
    **Compressed bombs (V5.2.3) not done, and open:** the probes' bodies are text, and a compressed file that expands
    far is binary throughout; V5.2.3's limits on uncompressed size and file count also have no place in
    `securevibe.toml` yet. Either needs deciding before it is built.
    **The owner's decision, 3 October 2026, on V5.2.3:** build the check, and test all of it. (1) It is built rather
    than left to the owner. (2) The owner states the limits in `securevibe.toml`, beside `max-bytes` on the `upload`
    entry: the most an archive may unpack to and the most files it may hold (`max-unpacked-bytes`, `max-files`), and
    `sv` sends an archive just over each; `sv` sets no limits of its own. (3) The owner also says whether the app
    unpacks archives: accepted by an app that unpacks them is a finding; accepted by one that does not is nothing to
    judge; refused is credited, held back when the upload crashed rather than being refused; and nothing is sent
    while the owner has not said whether the app unpacks. (4) Each archive unpacks to just over the stated limit and
    to about 1 GB at most, and is sent after every other upload check, so an app that does unpack it and falls over
    takes no other check with it. Sending it needs the probes' request bodies to carry bytes rather than text.
    **Claimed on 3 October 2026 by session securevibe-e10 and released the same day, not built**; the owner's
    decisions above stand, and the item is open for whoever takes it up. Done in that branch first, and merged: the
    probes' request bodies are bytes, and each request reaches the probe container as input rather than as an
    argument (DESIGN, "Requests reach the app as input"), so an archive can now be sent as it is.
    **V5.2.3 (compressed bombs) claimed on 5 October 2026 by the cato-pipeline session and released the same day, not
    built**: its helper agent was stopped by a safety classifier while working on the archives that unpack past the
    owner's limit, which is the heart of the check, so this session left it rather than work around that. The
    owner's decisions above stand, and the item is open. Two points from the reading, for whoever takes it: a single
    yes/no "unpacks archives" could make a finding of an app that unpacks zip but not gzip (a list such as
    `unpacks-archives = ["zip", "gzip"]` would not), and each archive must itself stay under `max-bytes`, or a
    refusal cannot be told from a size refusal. Where the rest goes: `UploadSection` (`crates/sv-manifest/src/lib.rs`)
    and the `upload` template line (`spec.rs`, which `securevibe_spec` sends); the check in
    `crates/sv-check/src/signed_in/uploads.rs`, its rule in `rules.rs` and `RESTS_ON_A_REFUSAL`; the fake app's upload
    handler reads text today; and a place just before step 10 of `run_checks`, with a fresh sign-in, fits "takes no
    other check with it" better than step 6b.
    **V5.2.3 (compressed bombs) claimed on 7 October 2026 by session securevibe-e2**, at the owner's word ("go ahead
    when you're ready"), in branch `claude/securevibe-e2-archive-bombs`, to the owner's decisions above, with the
    list of formats: `max-unpacked-bytes`, `max-files`, and `unpacks-archives` on the `upload` entry; an ordinary small
    archive of each format first, then one just over each limit, sent after every other upload check. Read on `main`
    just before this claim: no other session had claimed it (securevibe-e9's claim of 5 October, #751, was closed
    unmerged). **Record, `Status: proposed`: ADR-046.**
    **Done the same day** (DESIGN, "Compressed files past the stated limits"; ADR-046, accepted). For each format
    listed, an ordinary small archive, then a zip and a gzip that unpack to a mebibyte past `max-unpacked-bytes` and a
    zip holding one file more than `max-files`, each at most 1 GiB unpacked and under `max-bytes`; written by `sv`
    itself, with no library, and checked against Python's own readers. `probe.archive-unchecked` (V5.2.3) is a
    finding when one is accepted, and credited when it is refused and an ordinary file after it is not. Ten guards
    broken in turn, each caught. Not done: tar, 7z, and rar; and an archive whose stated sizes are false (each file
    here says truly what it unpacks to, so an app that trusts the stated sizes is credited).
    **Claimed on 3 October 2026 by session securevibe-e10**, at the owner's asking, in branch
    `claude/upload-names`.
    **"An archive whose stated sizes are false" claimed 9 October 2026 by session securevibe-e2**, from the roadmap
    (Phase 1, item 3, the first open part in its order with a build in it), in branch `claude/securevibe-e2-lying-zip`:
    for an app that lists `"zip"` in `unpacks-archives`, one more zip after the others, whose headers say it unpacks to
    an ordinary small size while its data unpacks to a mebibyte past `max-unpacked-bytes`, within the same 1 GiB and
    `max-bytes` caps. It is judged as the others are: a refusal (4xx) is credited only with the ordinary file after it
    accepted, an ordinary acceptance (2xx) is a finding that the app took a zip it had not checked, and a crash, a 5xx,
    or no answer is held back as not assessed. Some readers (Python's `zipfile` among them) stop at the stated size
    and then fail its checksum, so for them the lie unpacks nothing; such an app answers the zip with an error, which
    is the refusal or the held-back answer above, never a finding. With it, V5.2.3's credit needs the lying zip
    refused too. Tar, 7z, and rar stay open: tar compresses nothing of its own (a `.tar.gz` is the gzip already sent),
    and 7z and rar each need a writer of their own. **Record, `Status: proposed`: a "Later" entry on ADR-046.**
    Confirmed on `main` just before this claim: not done, and no other session had claimed it.
16. **Old TLS versions on the live site (V12.1.1, level 1).** A handshake held to TLS 1.0 or 1.1 by `sv probe`.
    **The owner's decision first:** it raises `sv probe`'s limit of four requests, which `CLAUDE.md` states.
    **Done on 3 October 2026** (DESIGN, "Old TLS versions on the live site"): one handshake offering only TLS 1.0
    and 1.1, within the cap of four; accepted is a finding, refused is said and not credited, since V12.1.1 also asks
    that the newest version be preferred and curl reports no version that can be relied on. Nine guards broken in
    turn, each caught: seven by the one test written for each, two by two tests or more.
    **Claimed on 3 October 2026 by session securevibe-e10**, at the owner's asking, in branch
    `claude/old-tls-versions`. It may not raise the limit: a run of `sv probe` makes at most three requests since
    the OCSP stapling check (#465), so one handshake held to an old version is the fourth. To be confirmed in the
    code before anything else.
