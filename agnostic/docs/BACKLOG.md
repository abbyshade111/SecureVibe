# SecureVibe Agnostic — what is still to do

Same rules as the v1 backlog: claim an item here, in a commit of its own, before starting it. A message to
another session is not a claim.

## Next

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

- **Dependency manifests are only read at the top of the repository.** Found on 25 September 2026 and
  not claimed. `ecosystems::detect` looks for `package.json`, `go.mod` and the rest in the app folder
  itself, so a full-stack app laid out as `client/` and `server/` — the usual shape of what an AI
  builder writes — has no dependency read at all, and the technology conditions fall back to source
  patterns alone. It is also the pinning check and the SBOM. Walking for manifests means deciding what
  a nested one belongs to, and skipping `node_modules` and vendored copies, which is why it is its own
  item.

- ~~**Secure by Design controls excluded on too narrow a question.**~~ Done on 25 September 2026, at
  the owner's request after review. RR-02, DM-03, AS-06, RR-03 and AC-01 each gained a second rule
  (`external-apis`, `payments`/`scheduler`, `internet`) so a single app that needs them keeps them;
  AS-07 lost its gate. Pinned per control and as the whole checklist for a single-service web shop.
  Left over from the same review, not done: the derived checklist levels are reported as "above the
  ASVS level this app targets", which is not what they are; and SBD-AC-05's "no secrets in code" is
  exactly what the credential scan checks, which the report could show beside the control.

- **Script in a page written the way a browser reads it and a parser does not.** An unquoted
  attribute value, and a scheme written around a control character, are both named as left behind —
  correct, and each keeps a page unread. Reading them means deciding where an unquoted value ends,
  which is a question with two defensible answers.

- **Grammars for C++, and for HTML's embedded scripts.** C++ is the last language the scanner counts and
  cannot parse. Assessed on 25 September 2026 against what AI coding tools actually produce: C++ matters
  least of the candidates for web apps. Worth more, in order: **Dart** (Flutter front ends, which today
  silence every code rule for the whole app, Python back end included), **Swift** (the same, for iOS
  clients), and **shell** (`.sh` deploy and setup scripts are in most generated repositories and are
  where `curl | sh` and unquoted variables live; they are not counted at all today, so they neither
  silence rules nor get read). Each grammar is only worth adding with at least the shell and
  code-execution queries written for it, or it turns silence into an unearned clean claim. It is also what the two "no grammar" tests now stand on, so whoever adds it will find
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

- **More adapters, and more of their rules mapped.** Four are listed; semgrep's rule ids are not mapped
  to requirements at all, so its findings carry none. `eslint-plugin-security`, `staticcheck` and
  `phpcs-security-audit` are each a data entry. The shape to keep: SARIF only, not installed means not
  run, and rule ids mapped one at a time.

- **More probes.** The first four questions are asked (`sv-check/src/probes.rs`); they are the ones that
  can be asked of any app by somebody who has not signed in. Redirects, HSTS on an HTTPS app, method
  handling per route and anything that sends data need either a manifest describing the app's routes or a
  session — both of which are their own items below.

- **Seeded users.** The probes sign in as nobody, so authorisation, session handling and CSRF are reported
  as *not assessed* and named as such. v1's probes sign in as users it created. Doing that for an arbitrary app means the manifest
  declaring how, or the probes running unauthenticated and saying which requirements that leaves unassessed.

- ~~**Load the Secure by Design checklist.**~~ Done on 24 September 2026. Left over: `multiple-services`
  had no corroborator until 25 September 2026 (see the corroborators item). The
  checklist's `scoring`, `processSteps`, `principles` and `escalationTriggers` are read past, not used.
  It was found on 24 September 2026 while chasing bad citations: `sv --help` had named the checklist
  since the first commit while `Frameworks::load` read ASVS, AISVS and Appendix C only.

- **Clean coverage from the remaining checks.** The credential scan, the rules that read code and the
  probes now report what they examined and found nothing wrong; the SBOM and advisory checks do not, and
  neither does the app's own test suite when `sv run` runs it. Each fails closed on its own coverage,
  which is the pattern to follow.

- ~~**Credit the app's own test suite.**~~ Done on 24 September 2026 — `crates/sv-check/src/suite.rs`.
  A test counts only for a requirement it names, and only when the suite it belongs to passed. Matching
  tests to requirements by their words was considered and refused: it would credit a requirement on the
  strength of a name somebody chose for other reasons. v1's mismatch check is ported as it was —
  reporting, never withholding credit, because about a third of its flags are honest tests phrased
  differently. What is left over from this item: the suite's coverage is still all-or-nothing on one
  exit code, so a suite with one failing test credits nothing. Reading a test runner's own report
  (JUnit XML, `pytest --junitxml`) would fix that and is its own item.

- ~~**Almost every rule-to-requirement citation is semantically wrong.**~~ Done on 24 September 2026 —
  remapped, and guarded by `crates/sv-check/tests/citations.rs`. Left over: Brakeman's rule ids have
  never been seen in a real SARIF run, and the guard cannot catch a swap between requirements that
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

- **The MCP server.** Wraps the same core so an AI coding tool can run the checks mid-conversation. Wants
  `sv check` finished first.

## Decided, not yet written down as ADRs

- Corroboration only ever moves toward more requirements applying, never fewer (`sv-manifest::resolve`).
- The OWASP data files are shared with v1, not copied.
- `sv` never writes application code, so v1's generation agent and its fence have no successor here.
