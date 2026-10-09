# Partial checks for the requirements no check speaks to, from the review of 28 September 2026

**Status:** partly done: 3 of 12 parts done, 0 claimed, 2 open, as its markers read on 8 October 2026

The owner asked
on 28 September 2026 for every requirement with no check to be reviewed for a partial check: a signal that tells the
owner something useful even when it cannot settle the requirement. Session securevibe-e9 had seven reviewers go
through all 382 and wrote their proposals to `docs/PARTIAL-CHECKS.md`: 279 partial checks, 33 questions for
`securevibe.toml`, and 70 with no useful check. **The proposals are not verified unless an item below says so**, and
several rest on library defaults recalled rather than looked up. **Each numbered item can be claimed on its own**, and
any proposal in `docs/PARTIAL-CHECKS.md` can be added here as an item and claimed the same way.
1. **Outside-tool rules that already run and count for nothing (8 requirements). Verified.** Each rule is in a pack or
   tool `sv --tools` already runs, and is mapped to nothing in `data/adapters.json`. All are `findings_against`: each
   requirement asks for a control, and a pattern can show one missing but not present. V3.6.1: semgrep
   `html.security.audit.missing-integrity`. V1.4.1: semgrep `c.lang.security` `insecure-use-gets-fn`,
   `insecure-use-string-copy-fn`, `insecure-use-strcat-fn`. V1.4.3: semgrep `use-after-free`, `double-free`. V5.2.3:
   semgrep `go.lang.security.decompression_bomb`. V11.3.4: semgrep `java...gcm-nonce-reuse`, `php...openssl-cbc-static-iv`,
   and gosec G407. V12.3.3: semgrep's gRPC insecure-connection rules for Go and JavaScript. V15.4.2: bandit B306.
   V15.4.3: semgrep `trailofbits.go.missing-unlock-before-return`.
   **Claimed on 28 September 2026 by session securevibe-e9**, at the owner's asking to start with this group.
   **Done the same day:** all fifteen rules are in `data/adapters.json` under `findings_against`, and ASVS
   requirements a check can speak to go from 132 to 140. `crates/sv-check/tests/running_rules.rs` holds that a
   finding from each carries its requirement and that a clean run credits none of them; `py/insecure-temporary-file`
   stays out until item 5 measures the CodeQL suites.
2. **Existing checks that already test the requirement. Verified against each requirement's words.** V8.2.3 by
   `probe.role-field-trusted` and `probe.record-returns-secret-fields` (field-level access is what both test); C9.3.2 by
   `probe.ai-mcp-output-unvalidated`, for tools reached over MCP; C9.3.7 by `probe.ai-output-fetched`; V14.2.2 by
   `probe.private-page-cached`, extended to flag `public` and `s-maxage` on a private page. **V9.2.3 is the owner's
   call:** the existing probe checks sign-in tokens in the app as a client, and V9.2.3 is about a service accepting
   access tokens; a code rule for a switched-off audience check (`verify_aud` False, `ValidateAudience = false`) fits
   either way.
   **V8.2.3, C9.3.2, C9.3.7, and V14.2.2 claimed on 28 September 2026 by session securevibe-e9**, at the
   owner's asking to go ahead with this group; V9.2.3 stays the owner's call.
   **The owner's decision on V9.2.3, 4 October 2026: not cited by the running probe.** `probe.oidc-audience-not-checked`
   tests an app that signs people in through a provider accepting an ID token meant for another app, which is
   V10.5.4 exactly; V9.2.3 is spoken to by the code rule `ast.token-audience-not-checked` (item 12 below).
   **C9.3.2 and C9.3.7 done the same day** (`crates/sv-check/src/ai.rs`). **V8.2.3 and V14.2.2 wait for the
   `signed_in.rs` freeze to lift**, since their checks live there: add V8.2.3 to the requirement lists of
   `probe.role-field-trusted` and `probe.record-returns-secret-fields` (both only ever findings), and add a
   finding-only `probe.private-page-shared-cache` (V14.2.2) beside `probe.private-page-cached` for a private
   page whose `Cache-Control` has `public` or an `s-maxage` with neither `private` nor `no-store`. Session
   securevibe-e9 wrote and tested both before the freeze was noticed, and holds the claim; the slice's
   session may make them in its pull request instead (slices g and b).
   **V8.2.3 and V14.2.2 done on 29 September 2026**, once the freeze lifted: V8.2.3 is on
   `probe.role-field-trusted` (`signed_in/rules.rs`, writing a field) and `probe.record-returns-secret-fields`
   (reading one), both only ever findings; `probe.private-page-shared-cache` (`signed_in/sessions.rs`, V14.2.2) finds
   a private page whose `Cache-Control` has `public` or an `s-maxage` with neither `private` nor `no-store`. Found
   on the way: `probe.record-returns-secret-fields` never credits anything, yet `tools/coverage.py` did not list it as
   finding-only, so V15.3.1 read as checkable by a clean run; it is listed now. Each guard broken turned its tests red.
3. **Small new checks, the reviewers' first picks. Not verified.** Details for each are in `docs/PARTIAL-CHECKS.md`.
   Reads the code: V1.3.1 (a rich-text editor with no known sanitizer), V11.2.4 (a digest compared with `==`),
   V15.2.3 (a development server as the start command), C6.1.3 (model downloads not pinned to a commit),
   C3.2.3 (floating model names such as `-latest`), C4.1.2 (model files loaded with pickle), C10.1.1 (MCP servers
   started with an unpinned `npx -y` or `uvx`). The running app: V8.4.2 (admin pages opened by `X-Forwarded-For`),
   V10.4.4 (retired sign-in methods in the app's own published settings), V16.5.4 (the app still up after the probes),
   V13.4.7 (files that exist and should never be served), C2.1.4 (a very large message refused), C2.2.2 (the injection
   probe in other languages and base64), C7.3.4 (hidden characters in a reply), C7.3.1 (a moderation verdict ignored),
   C10.3.3 (the MCP endpoint and a foreign Origin or rebound Host), C11.3.2 (raw model metadata reaching the page),
   C12.1.1 (who and which session in the model-call log line), C10.2.6 (an MCP session reused after it was ended).
   Signed in: V1.3.4 and V5.4.3 (an SVG with a script, and the EICAR test file, built from pieces at run time, through
   the upload probe), V4.1.3 (identity headers such as `X-Remote-User` on private pages), V7.4.3 (other sessions after
   a password change), V6.3.7 (an email after a password change), V10.1.1 (tokens in browser storage), V10.5.2 (two
   people sharing an email address at the test sign-in provider), V14.3.3 (the test password in browser storage),
   C9.5.3 (another user's record through a tool the model calls).
   **The twenty that read the code or the running app claimed on 28 September 2026 by session securevibe-e9**, at
   the owner's asking to go ahead with this group, in three pull requests: the seven that read the code, then
   V8.4.2, V10.4.4, V16.5.4, and V13.4.7, then the eight about AI apps. The nine signed-in ones (V1.3.4, V5.4.3,
   V4.1.3, V7.4.3, V6.3.7, V10.1.1, V10.5.2, V14.3.3, C9.5.3) are not claimed: their checks live in
   `signed_in/`, which is frozen until the split's step 2 is done.
   **The freeze is lifted. V4.1.3, V7.4.3, and V6.3.7 claimed on 29 September 2026 by session securevibe-e2**,
   at the owner's asking to take the next backlog item, in branch `claude/securevibe-e2-signed-in-partials`: the
   three that need only the signed-in requests and the mail server. The other six (V1.3.4, V5.4.3, V10.1.1,
   V10.5.2, V14.3.3, C9.5.3) stay unclaimed.
   **V1.3.4 and V5.4.3 claimed on 29 September 2026 by session securevibe-e2**, at the owner's asking to take
   another backlog item, in branch `claude/securevibe-e2-upload-partials`: the SVG with a script and the EICAR
   test file, through the upload probe. V10.1.1, V10.5.2, V14.3.3, and C9.5.3 stay unclaimed.
   **V1.3.4 and V5.4.3 done the same day** (DESIGN, "An SVG with a script, and the antivirus test file").
   `probe.uploaded-svg-keeps-script` (V1.3.4) and `probe.upload-not-scanned` (V5.4.3) are sent after the ordinary
   GIF; each is credited when refused, and V5.4.3 only after an ordinary text file was accepted. Not done: the
   EICAR file inside a `.zip` (the probe's bodies are text, and a zip is not), and the pointers from the code
   (SVG sanitizers, antivirus packages).
   **V10.1.1 and V14.3.3 claimed on 29 September 2026 by session securevibe-e2**, at the owner's asking to take
   another backlog item, in branch `claude/securevibe-e2-browser-storage`: tokens and the test password in what
   the app leaves in the browser after sign-in. V10.5.2 and C9.5.3 stay unclaimed.
   **V10.1.1 and V14.3.3 done the same day** (DESIGN, "What the app keeps in the browser after signing in").
   The browser signs in through the app's own form and reads the values the page's scripts can reach.
   `probe.password-in-browser-storage` (V14.3.3) and `probe.token-in-browser-storage` (V10.1.1) are only ever
   findings. Not done: tokens sent to other sites (a hosted backend on another address receives them by
   design), and the pointers from the code (`setItem` calls with such key names).
   **The pointers from the code claimed on 6 October 2026 by session securevibe-e9**, at the owner's word ("keep
   going"), in branch `claude/securevibe-e9-storage-code`: two findings-only code rules for JavaScript and
   TypeScript, a token (V10.1.1) or a password (V14.3.3) written into `localStorage`, `sessionStorage`, or a cookie
   set from the page, by a key or cookie name that says so.
   **Done the same day** (DESIGN, "A token or a password written into the browser's storage, read from the code"):
   `ast.token-in-browser-storage` and `ast.password-in-browser-storage`, both only ever findings.
   **V10.5.2 claimed on 29 September 2026 by session securevibe-e2**, at the owner's asking to take another
   backlog item, in branch `claude/securevibe-e2-oidc-same-email`: two people at the test sign-in provider who
   share an email address. C9.5.3 stays unclaimed.
   **V10.5.2 done the same day** (DESIGN, "Two people with one email address at the sign-in provider").
   `probe.oidc-user-keyed-on-email`: the test provider gains `other-person` and `new-email`, and a new optional
   `create` and `shows` under [stack.run.oidc] let the probes save a mark as the first person and see whose
   account each sign-in reaches. Not done: the static companion (a user lookup keyed on the email claim in
   the sign-in callback).
   **The static companion claimed on 6 October 2026 by session securevibe-e2**, at the owner's word ("Go ahead and
   choose a backlog item when ready"), in branch `claude/securevibe-e2-oidc-email-lookup`: a findings-only code rule
   for an account looked up by the email address the sign-in provider sent, written in the call or through a name
   given it once. Read on `main` just before this claim: no other session had claimed it.
   **Done the same day** (DESIGN, "An account found by the email address the sign-in provider sent, read from the
   code"). `ast.account-found-by-provider-email` reports an account looked up by the provider's email address, in
   eight languages. In five of them it also reports that address recorded as the session's user. Either is found
   when written in place or through a name the same function sets. It is only ever a finding. Not done: a lookup
   inside a helper function, and a session reached through another name (`examples/oidc-notes` writes
   `s.user = claims.email`, which the running check finds and this rule does not).
   **A session reached through another name claimed on 7 October 2026 by session securevibe-e9**, at the owner's word
   ("please go ahead"), in branch `claude/securevibe-e9-session-alias`: a new `functionNamesRead` switch, the
   other side of `argumentNamesRead`, so `s.user = claims.email` is read as the session's user entry when the
   function around it sets `s` to the session (`s = req.session`, `s = session`, or a call that returns one, such as
   `getIronSession(...)`). `examples/oidc-notes` is the witness. Read on `main` just before this claim: no other
   session had claimed it. A lookup inside a helper function stays unclaimed.
   **Done the same day** (DESIGN, "Later, 7 October 2026: the session under another name"). `sv report` on
   `examples/oidc-notes` now reports its line 120. In PHP only `$s = &$_SESSION` counts, since an assignment copies.
   **C9.5.3 claimed on 29 September 2026 by session securevibe-e9**, at the owner's asking to continue with the
   backlog: the test model asks the app's own record tool for another user's record.
   **C9.5.3 done the same day** (DESIGN, "Another user's record, through the model's tool").
   `probe.ai-tool-reads-others-records`: a new `record-tool` under [stack.run.ai] names the app's own tool; the
   test model, chatting as the second user, asks it for the second user's record (the control) and then the
   first user's. Handed over is a finding, refused is credited. The test model is run under Node for the FETCH
   call too. Not done: the static pointer (instructions to the model asking it to enforce permissions).
   **V4.1.3, V7.4.3, and V6.3.7 done the same day** (DESIGN, "Three small signed-in checks").
   `probe.identity-header-trusted` (V4.1.3) asks each private page a stranger was refused again with one of eight
   headers naming the test user, and is only ever a finding. `probe.password-change-ends-sessions` (V7.4.3) and
   `probe.password-change-notified` (V6.3.7) are only ever credited: a second session left open, or no email, is
   not assessed, since the app may offer to end sessions or tell people another way. Not done: reading the change
   page for such an offer, or what the email says.
   **The seven that read the code done the same day**, each able only to show its requirement failing, so a
   clean run credits none of them. Four are rules in `data/ast-rules.json`: `ast.digest-compared-with-equals`
   (V11.2.4, taught fourteen languages; shell has no timing to measure), `ast.model-loaded-with-pickle`
   (C4.1.2, Python), `ast.model-download-not-pinned` (C6.1.3, Python and JavaScript), and
   `ast.floating-model-name` (C3.2.3, all fifteen). Three are checks of the files:
   `config.development-server-started` (V15.2.3, the last stage of each Dockerfile and a Procfile's `web:`
   line, following `npm start` into package.json; files named for development are left out),
   `config.mcp-server-unpinned` (C10.1.1, `npx`, `uvx`, `pipx run`, `pnpm dlx`, and `docker run` in the
   app's own configuration and code; the developer's own AI-tool settings are left out), and
   `config.rich-text-without-sanitizer` (V1.3.1, from the bill of materials and sanitizer names in the
   code; not assessed while part of the bill could not be read). Not done from the proposals: the
   running-app half of V15.2.3 (debug consoles that answer), committed model files opened by their
   contents (C4.1.2), `ollama pull` and model-server images (C6.1.3), and the model name the app really
   sent (C3.2.3), which goes with the AI checks.
   **Looked at on 30 September 2026 by session securevibe-e9, and not built:** the `ollama pull` and model-server
   image half of C6.1.3. Ollama 0.35.0's own source (`types/model/name.go`, `server/images.go`) parses a
   `model:tag@digest` name, but its pull asks the registry for the tag alone and never uses the digest, and the
   digest check is marked as removed. A finding telling the owner to pin with `@sha256:` would name a fix that
   does nothing, so nothing is checked until Ollama honors the digest. A model server's container image is
   software rather than a model artifact, so C6.1.3 ("every third-party model artifact") does not fit it; an
   image pulled by tag rather than digest belongs with the V15 supply-chain checks, if anywhere.
   **V8.4.2, V10.4.4, V13.4.7, and V16.5.4 done the same day** (`crates/sv-check/src/running.rs`), each only ever a
   finding: `probe.admin-opened-by-address` (an admin page named in `[stack.run.users]` shut to a stranger and
   open with `X-Forwarded-For: 127.0.0.1`; made in `probes`' anonymous requests, so `signed_in/` is untouched),
   `probe.retired-grants-offered` (the password or implicit grant in the sign-in settings the app publishes at
   `/.well-known/`), `probe.private-files-served` (up to sixteen settings, key, dump, build, and server-code files
   from the app's folder, asked for by name and judged by their own first 200 characters), and
   `probe.app-stopped-during-questions` (the container read after the anonymous questions and again after the
   rest; `crates/sv-run/tests/stays_up.rs` runs a fixture that a request stops, with Docker in CI). Not done from
   the proposals: the static half of V10.4.4 (grant settings in code), the static half of V13.4.7 (a static-file
   handler pointed at the app's folder), and the error-handler signals for V16.5.4.
   **Six of the eight about AI apps done the same day** (`crates/sv-check/src/ai.rs`, asked after the rate check,
   a minute after its burst). Found and credited: `probe.ai-hidden-content-passed` (C7.3.4: invisible tag and
   zero-width characters, a right-to-left override, and a misleading link in a reply, looked for in the answer
   with JSON escapes, surrogate pairs, and HTML references read) and `probe.ai-flagged-reply-shown` (C7.3.1:
   judged only when the app asked the test model's new moderation endpoint about the reply; a classifier
   elsewhere is not seen). Only ever findings: `probe.ai-input-truncated` (C2.1.4: a 40,000-character message
   with a marker at each end; the fence carries a request as one shell argument, so a message past any context
   window cannot be sent, and one arriving whole is only a step), `probe.ai-injection-other-languages` (C2.2.2:
   the injection in Zulu, Scottish Gaelic, Bengali, and base64, asked only where the English one was stopped),
   and `probe.ai-raw-response-exposed` (C11.3.2: every reply's id now carries `SVRAW` and its tag). Credited
   only: `probe.ai-call-log-session` (C12.1.1: the model-call log line of a signed-in run naming the user or a
   user or session field). `crates/sv-run/tests/model_provider.rs` runs the test model under Node for the first
   time. **C10.3.3 and C10.2.6 done the same day** (`crates/sv-check/src/mcp_server.rs`), for an app that is
   itself an MCP server and says where in a new `[stack.run.mcp-server]` section: `probe.mcp-server-origin-unchecked`
   (a foreign `Origin` and a foreign `Host`, each on its own, against an ordinary request as the control) and
   `probe.mcp-session-survives-end` (a session ended with `DELETE` and used again). Both are credited when
   refused. Not yet run against a real MCP library.
4. **Two gaps in existing checks. Not verified.** `data/secret-rules.json` has an Anthropic key rule and none for
   OpenAI or Hugging Face keys. The `training` corroborator misses vendor fine-tuning calls such as OpenAI's
   `fine_tuning.jobs.create`.
   **Claimed on 28 September 2026 by session securevibe-e10**, at the owner's asking, in branch
   `claude/key-rules-fine-tuning`.
   **Done the same day:** `secrets.openai-key` and `secrets.huggingface-token` in
   `data/secret-rules.json`, from gitleaks' published patterns, and the vendor fine-tuning calls in
   the `training` corroborator, each read from the vendor's own SDK or API definition. See DESIGN,
   "OpenAI and Hugging Face keys, and fine-tuning through a vendor".
5. **CodeQL queries that may already run.** `py/insecure-temporary-file` and `js/file-system-race` (V15.4.2) were
   proposed, but nothing records which queries the security-extended suites run, as `data/semgrep-packs.json` does for
   semgrep, so whether they run is not known. Measure the suites first. Bandit B113 (a web request with no time limit)
   was proposed for V13.1.3, which asks for documentation, so it can only ever be shown beside it, never counted.
   **Claimed on 29 September 2026 by session securevibe-e2**, at the owner's asking to take another backlog item,
   in branch `claude/securevibe-e2-codeql-suites`: list what the two security-extended suites run, measured with
   CodeQL itself, and map the two queries for V15.4.2 if they are in them.
   **Done the same day** (DESIGN, "Which queries the CodeQL suites run"). Measured with CodeQL 2.27.1: the Python
   suite selects 52 queries and the JavaScript one 105, both proposed queries among them, and all 81 queries
   already mapped too. `data/codeql-suites.json` records the lists, `tools/codeql_suites.py` writes it, and a test
   fails on a mapped query its suite does not select. `js/file-system-race` counts for V15.4.2;
   `py/insecure-temporary-file` is found-failing-only there, as bandit's B306 for the same call already was.
6. **Cautions for whoever builds these.** V12.1.4 (certificate status stapling): Let's Encrypt certificates have named
   no OCSP address since 2025, so report only when the certificate names one and the server still does not staple.
   V6.3.3 stays supporting: an account that opens with its password alone may be a test account whose two-factor setup
   failed. Most checks of an app that is itself an MCP server, or itself a sign-in service, need a new securevibe.toml
   section, and apply to few apps.
7. **Two running-app halves left from item 3.** C3.2.3: the model name the app really sent the test model,
   finding when it floats (`latest`, or a name ending `-latest`). V15.2.3: a development debug console that
   answers on the running app (Werkzeug's console and the like), judged by the page's own content, never by its
   status alone. Both only ever findings. **Claimed on 29 September 2026 by session securevibe-e9**, at the
   owner's asking to continue with the backlog, in branch `claude/securevibe-e9-running-halves`. Item 5 was
   looked at first and left: measuring the CodeQL suites needs the CodeQL bundle, which does not fit in this
   session's disk.
   **Done the same day** (DESIGN, "A development console that answers, and the model name the app really
   sent"). `probe.development-console-open` (V15.2.3, V13.4.2) asks for Werkzeug's console and Rails' information
   page and knows each by words only that page carries, read from each tool's source; Django's debug 404 page
   joins the error-page markers. `probe.ai-floating-model-sent` (C3.2.3) reads the model name the app sent the test
   model. Five guards broken in turn, each caught. Not done: other frameworks' consoles, and looking up whether a
   name without `latest` is an alias its vendor moves.
   **Other frameworks' consoles claimed on 6 October 2026 by session securevibe-e2**, at the owner's word ("Please
   continue to work off the backlog when ready"), in branch `claude/securevibe-e2-more-consoles`: Go's
   `net/http/pprof`, Laravel's Ignition, Symfony's profiler, and Phoenix's LiveDashboard, each known by words read
   from its own source, as the two there are. Read on `main` just before this claim: no other session had claimed
   it.
   **Done the same day** (DESIGN, "Four more development consoles"). Each of the four is known by words read from
   its own source, and each answers only in its tool's development or debug mode. Spring Boot's Actuator is left
   out, since exposing it is a setting rather than a debug mode.
8. **The static half of V10.4.4: the password and implicit grants switched on in a sign-in server's code.** Left
   from item 3, whose running half reads only the settings the app publishes. Each library's own names for the two
   grants, read from its source (the proposal in `docs/PARTIAL-CHECKS.md` names Doorkeeper, django-oauth-toolkit,
   Spring Authorization Server, league/oauth2-server, fosite, and node-oauth2-server), and only ever a finding.
   **Claimed on 29 September 2026 by session securevibe-e9**, at the owner's asking to continue with the backlog,
   in branch `claude/securevibe-e9-retired-grants`.
   **Done the same day** (DESIGN, "The password and implicit grants, read from a sign-in server's code").
   `config.retired-grant-enabled` reads django-oauth-toolkit, Doorkeeper, fosite, and node-oauth2-server, each by
   names read from its own source, and only where the library is among the app's packages or the file names it.
   Six guards broken in turn, each caught. Not done: league/oauth2-server (its source could not be fetched here),
   Spring (whose authorization server has no password grant to switch on), and settings kept in a database.
   **league/oauth2-server claimed on 7 October 2026 by session securevibe-e2**, at the owner's word ("please pick
   whatever you want to work on next from the backlog"), in branch `claude/securevibe-e2-league-grants`: its password
   and implicit grants switched on, read from its source, which can be fetched now. Read on `main` just before this
   claim: no other session had claimed it.
   **Done the same day** (DESIGN, "The retired grants in league/oauth2-server and Laravel Passport"), with Laravel
   Passport beside it, since most PHP apps reach league through Passport. `new PasswordGrant(` and `new
   ImplicitGrant(` for league, and `Passport::enablePasswordGrant()` and `Passport::enableImplicitGrant()` for
   Passport, each read from its own source. Not seen: Passport before 12, whose password grant had no switch.
9. **V11.4.4: an encryption key made from a password with too little work.** From `docs/PARTIAL-CHECKS.md`: a
   code rule for PBKDF2 with a literal iteration count below OWASP's figure, and a single hash of a password used
   as a key. Only ever a finding; a count read from a setting is not judged.
   **Claimed on 29 September 2026 by session securevibe-e2**, at the owner's asking to take another backlog item,
   in branch `claude/securevibe-e2-weak-kdf`.
   **Done the same day** for PBKDF2 (DESIGN, "A key made from a password with too few rounds"):
   `ast.weak-password-key-derivation` reports a count written into the code below 210,000 in all fifteen languages `sv` reads, and is
   only ever a finding. Not done: a single hash of a password used as a key, since nothing in the code says a
   hashed value is a password without guessing from its name; the standard library's `crypto/pbkdf2` in Go; C#'s
   two-argument `Rfc2898DeriveBytes`; and counts between 210,000 and 600,000 with SHA-256.
   **Go's standard-library `crypto/pbkdf2` and C#'s two-argument `Rfc2898DeriveBytes` claimed on 3 October 2026 by
   session securevibe-e2**, at the owner's asking to continue with the backlog, in branch
   `claude/securevibe-e2-weak-kdf-more`. Counts between 210,000 and 600,000 with SHA-256 stay unclaimed.
   **Done the same day** (DESIGN, "A key made from a password with too few rounds", the part added on 3 October):
   both are reported, and x/crypto's own order is never misread as the standard library's. Six guards broken in
   turn, each caught.
   **Counts between 210,000 and 600,000 with SHA-256 Claimed on 5 October 2026 by the cato-pipeline session**, at the owner's asking to continue with the backlog, in branch
   `claude/pbkdf2-mid-counts`.
   **Done the same day** (DESIGN, "A key made from a password with too few rounds", the part added on 5 October):
   the rule now ties the figure to the hash where the call names it: below 600,000 is reported with SHA-256, and
   210,000 stays the figure with SHA-512 and wherever the hash is not named or cannot be read (a variable, a
   default, or a hash set elsewhere, as Java's and Kotlin's `PBEKeySpec` and pointycastle's `Pbkdf2Parameters`
   always do), which the rule's description and what it looks for now say. The hash is read in thirteen of the
   fifteen languages; every language has a case at 300,000 with SHA-256 or with no hash it can read, and each
   that names a hash has cases at 600,000 with SHA-256 and 300,000 with SHA-512. Eight guards broken in turn,
   each caught. Not done: SHA-1 counts between 210,000 and 1,300,000.
   **SHA-1 counts between 210,000 and 1,300,000 claimed on 6 October 2026 by session securevibe-e9**, at the
   owner's word ("keep going"), in branch `claude/securevibe-e9-pbkdf2-sha1`: where the call names SHA-1, the same
   way SHA-256 is tied to 600,000.
   **Done the same day** (DESIGN, "PBKDF2 with SHA-1 is held to 1,300,000 rounds"), in the thirteen languages where
   the rule reads the hash. A hash named only by the function, or left to its default, is still held to 210,000.
10. **The static half of V13.4.7: a static-file handler pointed at the app's own folder.** Left from item 3, whose
    running half asks for private files by name. A rule that reads the code for a web framework told to serve files
    from the folder the code is in, or the current folder (Express's `static(__dirname)`, Flask's `static_folder`,
    Starlette's `StaticFiles`, Go's `http.FileServer(http.Dir("."))`, and `python -m http.server` in a script),
    which hands out the source, settings, and `.env` beside it. Only ever a finding. **Claimed on 30 September 2026
    by session securevibe-e9**, at the owner's asking to continue with the backlog, in branch
    `claude/securevibe-e9-static-root`.
    **Done the same day** (DESIGN, "Static files served from the app's own folder").
    `ast.static-files-from-app-folder` reads JavaScript, TypeScript, Python, Go, and shell, with what each handler
    serves read from its framework's source (Flask 3, Starlette, Gin 1.12, Echo 4.16, and Python's `http.server`).
    Four guards broken in turn, each caught. Not done: PHP, Ruby, Java, C#, and Rust frameworks, and a folder named
    in settings or built at run time.
    **PHP, Ruby, Java, C#, and Rust claimed on 6 October 2026 by session securevibe-e2**, at the owner's word
    ("continue to work off the backlog"), in branch `claude/securevibe-e2-static-more`: each handler read from its
    framework's own source (Sinatra, Rack, Spring, Javalin, ASP.NET Core, tower-http, actix-files, warp), and `php -S`
    with no document root in a script. A folder named in settings or built at run time stays out of reach.
    **Done the same day** (DESIGN, "Static files from the app's own folder, in five more languages"): Ruby (Sinatra's
    `public_folder`, Rack's `Static` and `Files`), Java (Spring's `addResourceLocations`, Javalin's `staticFiles.add`
    with `Location.EXTERNAL`), C# (`UseStaticFiles`, `UseFileServer`, `UseDirectoryBrowser` given a
    `PhysicalFileProvider` for the app's folder), Rust (`ServeDir::new`, actix's `Files::new`, warp's `fs::dir`), and
    `php -S` with no `-t`, or `-t .`, in a script. Each read from the project's own source. Sixteen guards broken in
    turn, each caught in the end; the one that was not at first showed the Spring pattern also matched `"file:" +`
    any folder, and was narrowed. Still not seen: Rack's `Static` with no `root:` (its default is the folder the app
    was started in, but only below the `urls:` it is given), Spark Java, Kotlin's Ktor, PHP code itself, and any
    folder named in settings or built at run time.
    **Rack's `Static` with no `root:`, Spark Java, and Kotlin's Ktor claimed on 7 October 2026 by session
    securevibe-e9**, at the owner's word ("feel free to pick your next backlog item"), in branch
    `claude/securevibe-e9-static-more`: each handler read from its framework's own source, with a found and a
    not-found witness each. PHP code itself, and a folder named in settings or built at run time, stay unclaimed.
    Read on `main` just before this claim: no other session had claimed them.
    **Done the same day** (DESIGN, "Static files from the app's folder: Rack's `Static` with no root, Spark, and
    Ktor"). Each handler is read from its framework's own source, with found and not-found witnesses in Ruby, Java,
    and Kotlin. Ktor's older `static { files(".") }` is left out, since `staticRootFolder` can make `.` a folder of
    the app's own.
11. **The file half of C4.1.2: model files committed in a format that runs code when loaded.** Left from item 3,
    whose code rule (`ast.model-loaded-with-pickle`) reads the loading calls. Model files in the app's folder
    (`.pt`, `.pth`, `.ckpt`, `.bin`, `.pkl`, `.pickle`, `.joblib`) judged by their own bytes: a pickle's opening
    opcode, or a PyTorch zip that holds `data.pkl`, rather than by name alone. Only ever a finding. **Claimed on 30
    September 2026 by session securevibe-e9**, at the owner's asking to continue with the backlog, in branch
    `claude/securevibe-e9-pickle-files`.
    **Done the same day** (DESIGN, "Model files that can run code when loaded"). `config.model-file-can-run-code`
    judges each file by its bytes, with each format read from its library's source (PyTorch 2.14's
    `serialization.py`, joblib 1.5's `compressor.py`); Git LFS pointers are counted and not judged. Seven guards
    broken in turn, each caught; one that was not (a name boundary around `data.pkl`) was taken out rather than
    kept untested. Not done: a pickle saved under another name, protocol 0 and 1 pickles, which have no opening
    opcode, and a model downloaded when the app runs.
    **A pickle under another name, and protocol 0 and 1 pickles, claimed on 6 October 2026 by session
    securevibe-e2**, at the owner's word ("continue to work off the backlog picking whatever item you want"), in
    branch `claude/securevibe-e2-pickles`: a file under any name whose bytes open as a protocol 2 to 5 pickle and end
    with its `STOP`, and a file under a model file's name that reads as a protocol 0 or 1 pickle from its first
    opcode to its `STOP`. A model downloaded when the app runs stays out of reach of reading files.
    **Done the same day** (DESIGN, "A pickle under any name, and the old pickles with nothing to know them by"):
    `walks_as_pickle` reads a file opcode by opcode, as `pickletools` describes each, and counts it only when it ends
    exactly at its `STOP`; a file under a model file's name that does not open with `PROTO` is walked with protocols
    0 and 1, and every other file that is not code is opened for two bytes and walked when they are a `PROTO`.
    Twelve guards broken in turn, each caught (one only after a witness was added). Still not seen: a protocol 0 or
    1 pickle under another name, and a model downloaded when the app runs.
12. **The code half of V9.2.3: a token check told not to check who the token is for.** From
    `docs/PARTIAL-CHECKS.md` and item 2 above, which says a code rule fits whichever way the owner decides the
    running probe. A rule for the explicit switches tutorials copy: `verify_aud` False in PyJWT and python-jose,
    `ValidateAudience = false` in ASP.NET, and their like. Only ever a finding.
    Whether `probe.oidc-audience-not-checked` should also cite V9.2.3 was the owner's call; **the owner's decision,
    4 October 2026: it does not** (see item 2 above). **Claimed on 30
    September 2026 by session securevibe-e2**, at the owner's asking to find another small check, in branch
    `claude/securevibe-e2-jwt-audience`.
    **Done the same day** (DESIGN, "A token check told not to check who the token is for"):
    `ast.token-audience-not-checked` reads Python, Ruby, C#, Rust, and Go, each switch read from its library's own
    source or documentation; the other ten languages have no known switch and say so. Broken ten ways, each caught.
    Not done: a check never given an audience, and Keycloak's JSON setting. `jsonwebtoken`'s `ignoreAudience`,
    named in `docs/PARTIAL-CHECKS.md`, does not exist; the library checks the audience only when given one.
13. **Hidden characters smuggled into the AI feature: C2.1.2, and C2.1.5 beside it. Not verified.** From
    `docs/PARTIAL-CHECKS.md`: a message to the AI feature carrying invisible Unicode tag letters that spell an
    instruction, zero-width characters and a right-to-left override (C2.1.2), and a second carrying control and
    private-use characters no language needs (C2.1.5), with the test model recording which of them arrived.
    **Claimed on 8 October 2026 by session paper-facts**, at the owner's word ("please choose the next backlog item
    once it's merged"), in branch `claude/hidden-input`. C2.1.2: a finding when the tag letters or the override
    reach the model as they were sent; credited in part when the app strips them or refuses the message, since one
    family of smuggling is tried and encodings such as base64 are not. C2.1.5: only ever a finding, when those
    characters reach the model unchanged. **Record, `Status: proposed`: ADR-065.** Checked just before this claim:
    not on `main`, in no open pull request, and in no recent branch. Session securevibe-e9's claim on the stand-in
    protocol (0187, `claude/stackvet-e9-stand-in`) moves the stand-in's shared strings into one module and changes
    no question; whichever lands second merges the other in.
    **Done on 8 October 2026** (DESIGN, "Hidden characters sent into the AI feature (8 October 2026)"; ADR-065,
    accepted). `probe.ai-hidden-input` finds an instruction in invisible tag letters, or a right-to-left override,
    reaching the model, and credits C2.1.2 in part when they are taken out or the message is refused;
    `probe.ai-input-charset-unrestricted` finds control and private-use characters reaching it, and never credits.
    Not done: smuggling by encodings such as base64 or by look-alike letters, and normalization (C2.1.1).
14. **V7.2.2: a session that is one fixed key, from the running app. Not verified.** From `docs/PARTIAL-CHECKS.md`,
    the running half: the session value given at two separate sign-ins of the first test user, and at the second
    user's, compared. `probe.session-id-weak` (V7.2.3) already finds a cookie repeated across two sign-ins of one
    user; it does not compare two users, and it skips an app that signs in with a token rather than a cookie.
    **Claimed on 8 October 2026 by session paper-facts**, at the owner's word ("please continue to work through and
    pick up new items as you merge"), in branch `claude/static-session`: a finding when any session value, cookie or
    token, is the same at two of the three sign-ins; credited when every one differs, since V7.2.2 asks exactly that
    sessions are not one static key. The static half (a key built into the browser's code) is not part of this.
    **Record, `Status: proposed`: ADR-067.** Checked just before this claim: not on `main`, in no open pull request,
    and in no recent branch.
