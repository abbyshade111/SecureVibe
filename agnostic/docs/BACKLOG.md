# SecureVibe Agnostic — what is still to do

Same rules as the v1 backlog: claim an item here, in a commit of its own, before starting it. A message to
another session is not a claim.

## Next

- ~~**A clean credential scan claims V11.1.1 and C9.5.4.**~~ Withdrawn on 25 September 2026 by session
  securevibe-e8: not a fault. V11.1.1 and V13.3.1 are on `manualOnly` in `data/knowledge/applicability.json`,
  so a clean scan supports them and checks neither (pinned by
  `the_requirements_a_clean_scan_cannot_settle_include_the_ones_it_was_settling` and
  `end_to_end_a_clean_scan_supports_the_secrets_controls_and_checks_none_of_them`); the coverage count
  that suggested otherwise had not read that list. C9.5.4 is classified `scanner-clean` on purpose, and
  stays; `docs/COVERAGE.md` says what a clean scan does and does not show about it.

- ~~**A coverage document, generated.**~~ Done on 25 September 2026 by session securevibe-e8.
  `docs/COVERAGE.md`, written by `tools/coverage.py` from the checks' own citations and the
  manual-only list, and kept current by `crates/sv-check/tests/coverage_doc.rs`, which fails when it
  is not what the script would write. The script stops if a requirement id or check name is written
  into `sv`'s code that it does not know about.

- **Level 1 checks against the running app.** From the coverage count (`docs/COVERAGE.md`, 25 September
  2026): 49 of the 70 Level 1 requirements have no check at all, and Authentication (47 requirements)
  has none. Several can be asked of a running app with the test accounts `[stack.run.users]` already
  describes: a response's Content-Type and charset (V4.1.1), a reachable `/.git/` (V13.4.1), a short or
  common password accepted at sign-up (V6.2.1, V6.2.4), a long one refused (V6.2.5), a default
  `admin`/`admin` account (V6.3.2), session ids too short to be unguessable (V7.2.3), and sign-in
  accepted in the query string (V14.2.1). Each is a finding when it fails and supporting evidence at
  most when it holds; V6.3.2 in particular can only ever try a few names.

- **AISVS, beyond applicability.** One AISVS requirement has a check (C9.5.4). semgrep's `ai.*` rules
  (user input in a system prompt, model output executed, MCP servers) could be mapped to AISVS the way
  its security rules were to ASVS, with the citation guard reading each back, and `sv`'s own code rules
  could look for the same. Most of AISVS is about training and operating models and stays out of reach.

- ~~**Shell scripts.**~~ Done on 25 September 2026 by session securevibe-e8. `.sh` and `.bash` are
  read as `shell`, every rule is taught it or says why not, and a new rule,
  `ast.download-piped-to-shell` (V15.2.4), finds `curl … | sh` and its relatives. See DESIGN, "Shell
  scripts". Left over: unquoted variables are ShellCheck's, which cannot write SARIF; a request value
  copied into another variable before it reaches a path or a redirect is not followed.

- ~~**Signed-in checks in one container.**~~ Done on 25 September 2026 by session securevibe-e8. Every
  request is now an `exec` into one sidecar started per run, not a container of its own: a signed-in run
  of `examples/notes-with-users` went from 11–13 seconds to 4.3, with the same answers. See DESIGN,
  "One sidecar per run".

- **Corroborators for the remaining claims.** `multiple-services` done on 25 September 2026: gRPC and its `.proto`
  contracts, AsyncAPI documents, message-broker clients, microservice frameworks and service discovery,
  in eight ecosystems and ten languages. A `docker-compose.yml` is deliberately not evidence — most
  single apps ship one with only a database in it — and a test pins that. Left over from it: reading a
  compose file for two or more services with their own `build:` would be the strongest evidence of all,
  and needs the scanner to read YAML contents, which it does not. Services that call each other over
  plain HTTP stay invisible. Eleven of the twelve were written on 24 September 2026;
  `shared-hostname` is recorded as uncheckable instead (`noCorroborator`), because it is a fact about
  deployment that the repository does not hold. What is left is the weaker half of what was written:
  `ai-history` and `multimodal-ai` lean almost entirely on source patterns, and `public-api` cannot see
  a key checked by hand against a query parameter. Each is a data entry, not machinery.

- ~~**A `.tsx` file is read with a grammar that has no JSX, and counts as read.**~~ Done on 25 September
  2026. `<button onClick={() => eval(q)}>` in a `.tsx` file was not found, and the report then listed
  V1.3.2 as *checked (ast.dynamic-code-execution over 1 typescript file)*. `.tsx` is now parsed with the
  TSX grammar, each rule's `typescript` query compiled a second time against it. And whatever the
  grammar, a file whose parse holds an error lands in `AstScan::unparsed_files`: its findings stand, but
  no rule that reads code may claim a clean result while it is there, and `sv check` and the report say
  which files. Breaking either half turns two or three tests red. `.jsx` needed nothing: the JavaScript
  grammar reads JSX.

- ~~**Dependencies `sv` declares it read, and cannot match.**~~ Done on 25 September 2026. A Go app
  declaring and using `github.com/gorilla/websocket` had V4.4.1–V4.4.4 excluded as "No WebSocket
  library is used": `go.mod` gives full module paths, the signatures named `gorilla/websocket`, and the
  comparison was exact, so no Go package signature had ever matched. A Go signature now matches the
  module path or its tail on a `/` boundary, with a `/vN` suffix set aside. Most Go names in both data
  files were also wrong in themselves — `goth`, `stripe-go`, `go-openai` are not what `go.mod` says —
  and are now module paths, with a test refusing a bare name; `autocert` is a package inside
  `golang.org/x/crypto` and never appears in `go.mod`, so it is found in source instead. And
  `build.gradle.kts`, the Kotlin default, is now read, for dependencies and for pinning.

- ~~**Secure by Design controls excluded on too narrow a question.**~~ Done on 25 September 2026, at
  the owner's request after review. RR-02, DM-03, AS-06, RR-03 and AC-01 each gained a second rule
  (`external-apis`, `payments`/`scheduler`, `internet`) so a single app that needs them keeps them;
  AS-07 lost its gate. Pinned per control and as the whole checklist for a single-service web shop.
  The last point from the same review — derived levels reported as ASVS ones — is the crosswalk item
  below, done the same day. (This entry was deleted by accident on 25 September
  2026 by the commit that finished the nested-manifests item, and restored.)

- ~~**SBD-AC-05's "no secrets in code" is what the credential scan checks.**~~ Done on 25 September
  2026. Every credential rule cites SBD-AC-05, so a committed secret is a finding against it, and a
  clean scan is shown beside it as *supporting* evidence while it stays not verified. That rule is
  general: a satisfied check about a manual-only requirement is never "checked". It corrected two
  overclaims already in every report — V13.3.1 (use a key vault) and V11.1.1 (a documented key policy)
  were listed as checked by a scan of source files.

- ~~**Dependency manifests are only read at the top of the repository.**~~ Done on 25 September 2026.
  `ecosystems::detect` walks the whole app folder (skipping installed dependencies and build output),
  so a `client/` + `server/` app has its dependencies read, its pinning judged per project, and its
  packages in the SBOM; every path it returns is relative to the app folder. A lockfile in a parent
  folder pins a project only when that folder is a workspace root whose member list covers it (npm and
  Yarn `workspaces`, `pnpm-workspace.yaml`, Cargo `[workspace]`, uv `[tool.uv.workspace]`): a stray
  root lockfile pinning an unrelated project below it would be a wrong statement in the direction that
  hides something. A nested project is named by its folder ("npm in server/") so two read as two.
  Left over: the adapters still look for their tool's config (`pyproject.toml` and the like) at the
  top only, and a Yarn Berry or Bun lockfile is not one `sv` reads.

- ~~**Ground the Secure by Design levels in ASVS.**~~ Done on 25 September 2026, with the owner's
  agreement to the design. `data/sbd-asvs-crosswalk.json` maps each of the thirty-six controls to the
  ASVS requirements that ask the same thing — seventeen have counterparts, thirty pairs in all — and
  each pair carries a few words naming what the two share, which the citation guard holds against
  both texts. `Frameworks::apply_crosswalk` sets a control's level to the lower of its derived level and
  its counterparts' lowest, so it can only ever come into scope sooner; a control with no counterpart
  is level 1, shown at every target. Every control records where its level came from, the report lists
  the controls above the target with that basis instead of calling them "above the ASVS level", and a
  satisfied check about a counterpart is shown beside the control as supporting evidence. Loading
  refuses a crosswalk that leaves a control out or cites an id that does not exist.

- **A suppressed finding makes a tool's run look clean, and it is credited.** Found on 25 September
  2026 while reviewing the adapter work; not claimed. `# nosec` on a line makes bandit report nothing
  about it, so `sv` sees an empty findings list, calls the run clean, and credits every requirement
  that adapter's rules map to — including V1.2.4 for a file whose `search()` concatenates user input
  straight into SQL. Verified by running bandit, not reasoned about:

      def search(db, q):
          return db.execute("select * from notes where t = '" + q + "'").fetchall()  # nosec

  Bandit's SARIF for that file holds `"results": []` and, in `runs[0].properties.metrics._totals`,
  `"nosec": 1` and `"skipped_tests": 0`. So the tool says plainly that it was told to look away, and
  nothing reads it: `grep -rn nosec crates/ data/` finds nothing at all.

  This is the missing-tool rule again, one layer in. A tool that is not installed already reports
  *not run* rather than a clean pass, because absent must never read as clean; a tool that ran with
  its mouth taped shut over the one line that matters is the same thing in a better disguise, and it
  is worse, because the report says an automated check looked.

  The fix is cheap for bandit, since the count is already in the report: read
  `metrics._totals.nosec` and `skipped_tests`, and where either is non-zero say how many suppressions
  there were and withhold that adapter's clean-run credit. gosec's `#nosec` and semgrep's
  `// nosemgrep` need the same treatment and neither could be checked here — gosec is not installed,
  and semgrep cannot start in this sandbox (`ca-certs: empty trust anchors`) — so what their reports
  carry is unverified. If it turns out they say nothing about suppressions, the honest interim is to
  count the markers in the files that were scanned.

- **Script in a page written the way a browser reads it and a parser does not.** An unquoted
  attribute value, and a scheme written around a control character, are both named as left behind —
  correct, and each keeps a page unread. Reading them means deciding where an unquoted value ends,
  which is a question with two defensible answers.

- ~~**Dart and Swift.**~~ Done on 25 September 2026 by session securevibe-e8. Both grammars, with every
  one of the nine rules either taught each language or saying why there is nothing to find in it
  (`nothingToFind`). The same change made the claim per rule: a rule that met a language it was not
  taught claims nothing and the report names it, which showed gaps in the older languages, most filled
  at once, and the last three in the entry below. See DESIGN, "Thirteen languages".

- ~~**Three rules still untaught a language.**~~ Done on 25 September 2026 by session securevibe-e8.
  Shell commands in Rust (the `Command::new("sh").arg("-c")` chain and the `.args([...])` array), weak
  ciphers in Rust (RustCrypto's types and the `openssl` crate's functions), and redirects in C (a
  `Location:` header printed by hand). Every rule is now taught every language `sv` reads, and a test
  pins it. What each misses is in DESIGN, "Thirteen languages".

- **Grammars for C++, and for HTML's embedded scripts.** C++ is the last language the scanner counts and
  cannot parse. Assessed on 25 September 2026 against what AI coding tools actually produce: C++ matters
  least of the candidates for web apps. Dart, Swift, and shell, which were worth more, are done (above). Since the claim became per rule, a grammar added without queries
  no longer turns silence into a clean claim; it moves the silence from the whole app to the rules not
  yet taught that language, and the report names them. C++ is also what the two "no grammar" tests now stand on, so whoever adds it will find
  those two failing, which is the right way round.

- ~~**More AST rules.**~~ Done on 25 September 2026 — four more in `data/ast-rules.json`, nine in
  all. `ast.file-path-from-value` (V5.3.2), `ast.weak-hash-function` (V11.4.1), `ast.weak-cipher`
  (V11.3.1, V11.3.2) and `ast.open-redirect` (V3.7.2), across eight or nine languages each. Two new
  fields made them possible without Rust per rule: `argumentPatterns` (the call is a finding only when
  its argument says so — `createHash("md5")`, not `createHash("sha256")`) and `safeArgumentPatterns`
  (named idioms that are not findings — `redirect(url_for(...))`, `secure_filename(...)`,
  `path.join(__dirname, "a.html")`, a bare ALL-CAPS constant). A pattern for a language with no
  query is refused at load. Every (rule, language) pair has a found and a not-found witness, and a
  test fails if one is missing; breaking each filter in turn turned two to seven witnesses red.
  Left over, each its own decision rather than a data entry:
  - **Predictable randomness (V11.5.1) was not written.** `Math.random()` and `random.choice` are fine
    for shuffling a list and wrong for a reset code, and what decides it is where the value goes,
    which a single query cannot see. A rule without that would mostly report shuffles.
  - Express's two-argument `res.redirect(301, url)` is missed: the first argument is the status,
    and it is a literal. `send_file`/`redirect_to` in Ruby, `Paths.get` in Java and PHP's
    `include $x` are not covered. Kotlin and C have no path or redirect query, Rust none of the four.
  - The file-path rule is low confidence on purpose: it cannot tell a request value from an internal
    one held in a lowercase variable.

- **Read Maven and Gradle version ranges.** The lockfile check reports them as not assessed, because
  pinning lives in `pom.xml` and `build.gradle` rather than a lockfile. Reading a range out of either
  would turn an open question into an answer.

- **More adapters.** Semgrep's rule map is done (25 September 2026, session securevibe-e8): 998 of the
  1,321 security rules in `semgrep/semgrep-rules`, generated by `tools/semgrep_rule_map.py` and
  checked against a real SARIF run. See DESIGN, "Semgrep: a thousand rules". Left over from it: the
  map is keyed on the registry's form of a rule id, which was reproduced rather than observed, so one
  run of `p/security-audit` on a machine that can reach semgrep.dev is owed (the fixture's README has
  the command). `eslint-plugin-security`, `staticcheck` and `phpcs-security-audit` are each a data
  entry. The shape to keep: SARIF only, not installed means not run, and a rule mapped only where it
  can be shown to be about its requirement.

- **More probes.** The first four questions are asked (`sv-check/src/probes.rs`); they are the ones that
  can be asked of any app by somebody who has not signed in. Redirects, HSTS on an HTTPS app, method
  handling per route and anything that sends data need either a manifest describing the app's routes or a
  session — both of which are their own items below.

- ~~**Seeded users.**~~ Done on 25 September 2026. `[stack.run.users]` in securevibe.toml says how
  accounts are made (`seed`, run in the app's container with the accounts in its environment, or the
  app's own `signup`), how to sign in and out, which pages are private or admin-only, and how one user
  creates a record another must not read. `crates/sv-check/src/signed_in.rs` asks seven things as two
  test users and an admin — private pages (V8.2.1), admin pages (V8.2.1), another user's records
  (V8.2.2), a forged cross-site request (V3.5.1), a new session at sign-in (V7.2.4), sign-out ending it
  (V7.4.1) and the session cookie's attributes (V3.3.2, V3.3.4) — and every one shows its own setup
  worked first or reports not assessed. Anti-forgery tokens are read from hidden fields (quoted or not),
  `<meta>` tags or cookies. Tested against a scripted app with each flaw switchable (every rule found by
  at least two tests), and under Docker against `examples/notes-with-users`: the correct app has all
  seven confirmed, and a copy with five flaws switched on had all five found. That run also found two
  bugs in the suite, both fixed: unquoted attributes hid the token, and a sign-out the app refused was
  reported as a sign-out that did not end the session. Left over: V3.3.1 (Secure) cannot be judged over
  the fence's plain HTTP; input handling (V5, V1.2) still needs knowledge of the app's forms.

- ~~**Load the Secure by Design checklist.**~~ Done on 24 September 2026. Left over: `multiple-services`
  had no corroborator until 25 September 2026 (see the corroborators item). The
  checklist's `scoring`, `processSteps`, `principles` and `escalationTriggers` are read past, not used.
  It was found on 24 September 2026 while chasing bad citations: `sv --help` had named the checklist
  since the first commit while `Frameworks::load` read ASVS, AISVS and Appendix C only.

- ~~**Clean coverage from the remaining checks.**~~ Done on 24 September 2026. Every check that can find
  something now also reports what it examined and found nothing wrong, each failing closed on its own
  coverage. Left over: `sv report` does not run the bill of materials or the advisory comparison at all
  — they live in `sv check` and `sv audit`, the latter because it needs an offline database path — so a
  report says nothing about dependencies either way. That is a bigger change than this item and is not
  what this entry asked for, but a reader of the reports would not guess it.

- ~~**Credit the app's own test suite.**~~ Done on 24 September 2026 — `crates/sv-check/src/suite.rs`.
  A test counts only for a requirement it names, and only when the suite it belongs to passed. Matching
  tests to requirements by their words was considered and refused: it would credit a requirement on the
  strength of a name somebody chose for other reasons. v1's mismatch check is ported as it was —
  reporting, never withholding credit, because about a third of its flags are honest tests phrased
  differently. What is left over from this item: the suite's coverage is still all-or-nothing on one
  exit code, so a suite with one failing test credits nothing. Reading a test runner's own report
  (JUnit XML, `pytest --junitxml`) would fix that and is its own item.

- ~~**Almost every rule-to-requirement citation is semantically wrong.**~~ Done on 24 September 2026 —
  remapped, and guarded by `crates/sv-check/tests/citations.rs`. Left over: Brakeman's rule ids had
  never been seen in a real SARIF run — done on 25 September 2026: they were mostly wrong (BRAKE0002 is
  cross-site scripting and was mapped as SQL, BRAKE0013 is eval and was mapped as OS command injection,
  BRAKE0016 is file access and was mapped as SQL, BRAKE0102 is a 2016 Rails CVE, not a secret, and
  BRAKE0000, SQL injection itself, was unmapped). Remapped from `warning_codes.rb` in Brakeman 8.0.6,
  forty ids, and tested against a real run over `crates/sv-check/tests/fixtures/brakeman/app` whose
  output is kept beside it; fifteen ids appear in that run, and the guard cannot catch a swap between requirements that
  share vocabulary. Found on 24 September 2026 by the
  test-crediting mismatch check, firing on the example app written to demonstrate it. ASVS 5.0 `V1.2.1`
  is *output encoding for an HTTP response, HTML or XML document*. It is cited by `ast.sql-built-by-hand`,
  `ast.dynamic-code-execution`, bandit's `B608` and `B307`, gosec's `G201`/`G202`, and three Brakeman
  rules — none of which have anything to do with output encoding. Parameterised queries are **V1.2.4**;
  OS command injection is **V1.2.5**, not the `V1.2.2` that nine adapter rules cite (`V1.2.2` is URL
  encoding). The pattern repeats across the file: eight rules cite `V11.3.1` (block modes and padding)
  for weak hashes, which are `V11.4.1`; `G404` (`math/rand`) cites `V11.4.1` (hash functions) when
  unpredictable randomness is `V11.5.1`; `G304` (file paths) cites `V1.2.3` (JavaScript encoding) when
  it is `V5.3.2`; `G107` (SSRF) cites `V1.2.4` (database queries) when it is `V1.3.6`; `G402`/`B501`
  (TLS verification off) cite `V13.1.1`, which asks that communication needs be *documented*.

  This is the third time this class has been found here — five checkers citing `AC-NN` ids that did not
  exist, then every probe citation being semantically wrong — and it is the failure the whole product is
  most exposed to, because a wrong citation is not visibly wrong. It puts a finding, or a green line,
  against a requirement nobody examined, and the reader has no way to tell.

  Two things are needed, and the second matters more. Remap `data/adapters.json` and `data/ast-rules.json`
  by reading each requirement's text. Then write the guard that would have caught it without an example
  app happening to exist: every citation in the data files compared against the requirement it names, by
  shared vocabulary, the same comparison `suite.rs` already makes for tests. A citation nothing checks is
  a citation that drifts.

- ~~**Read the test runner's own report.**~~ Done on 24 September 2026. Left over: matching is an exact
  identifier match, so jest — which concatenates its `describe` blocks into the reported name — mostly
  will not match and its tests stay uncredited. A runner that reports a name unlike the declaration
  loses coverage silently rather than loudly. The parser understands JUnit XML only; TAP and the
  runners that emit their own JSON are not read.

- ~~**The MCP server.**~~ Done on 25 September 2026. `sv mcp --root DIR` speaks MCP over stdio
  (`crates/sv-cli/src/mcp.rs`, no SDK) with four tools: `securevibe_spec`, `securevibe_check`,
  `securevibe_explain` and `securevibe_write_report`. `securevibe_check` is `assemble_report`, the
  function `sv report` now calls too, so a model is told exactly what the written report says, gaps first.
  Every path is resolved against `--root` and refused outside it, `..` and symlinks included; a report is
  written only below the app. Starting the app and running other people's tools are not offered: each
  runs code, and that stays the person's decision at a terminal. Left over: MCP resources (the report
  files as resources rather than paths) and progress notifications for a long check.

## Decided, not yet written down as ADRs

- Corroboration only ever moves toward more requirements applying, never fewer (`sv-manifest::resolve`).
- The OWASP data files are shared with v1, not copied.
- `sv` never writes application code, so v1's generation agent and its fence have no successor here.
