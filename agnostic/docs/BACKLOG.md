# SecureVibe Agnostic — what is still to do

Same rules as the v1 backlog: claim an item here, in a commit of its own, before starting it. A message to
another session is not a claim.

## Next

- **Corroborators for the remaining claims.** Eleven of the twelve were written on 24 September 2026;
  `shared-hostname` is recorded as uncheckable instead (`noCorroborator`), because it is a fact about
  deployment that the repository does not hold. What is left is the weaker half of what was written:
  `ai-history` and `multimodal-ai` lean almost entirely on source patterns, and `public-api` cannot see
  a key checked by hand against a query parameter. Each is a data entry, not machinery.

- **Grammars for Ruby, PHP and Java.** Named as unread today. Each is a dependency line and an entry
  per rule; the machinery does not change.

- **More AST rules.** Four cover code execution, shell, SQL and deserialization. Path traversal, weak
  cryptography and unvalidated redirects are the obvious next ones, and each is a data entry.

- **Read Maven and Gradle version ranges.** The lockfile check reports them as not assessed, because
  pinning lives in `pom.xml` and `build.gradle` rather than a lockfile. Reading a range out of either
  would turn an open question into an answer.

- **The adapter data file.** **[taken: keen-meninsky-691a27, 24 September 2026]** Per-language tooling
  driven by a manifest, not by Rust: bandit for Python, gosec for Go, brakeman for Ruby. A tool that is
  not installed reports *not run*, never a clean pass, and says how to install it. This is what makes
  "language-agnostic" mean more than four tree-sitter rules.

- **More probes.** The first four questions are asked (`sv-check/src/probes.rs`); they are the ones that
  can be asked of any app by somebody who has not signed in. Redirects, HSTS on an HTTPS app, method
  handling per route and anything that sends data need either a manifest describing the app's routes or a
  session — both of which are their own items below.

- **Seeded users.** The probes sign in as nobody, so authorisation, session handling and CSRF are reported
  as *not assessed* and named as such. v1's probes sign in as users it created. Doing that for an arbitrary app means the manifest
  declaring how, or the probes running unauthenticated and saying which requirements that leaves unassessed.

- **Load the Secure by Design checklist.** `sv --help` and the README say `sv` checks against it, and
  `Frameworks::load` reads ASVS, AISVS and Appendix C only — the checklist contributes nothing. Found on
  24 September 2026 while chasing bad citations. It is a third schema (`checklistDomains` → `controls`,
  with a `statement` and no level), so it needs a level decided per control and applicability rules
  written, which is why it is its own item and not a one-line fix. Until it is done, the help text and
  README overstate what runs.

- **Clean coverage from the remaining checks.** The credential scan, the rules that read code and the
  probes now report what they examined and found nothing wrong; the SBOM and advisory checks do not, and
  neither does the app's own test suite when `sv run` runs it. Each fails closed on its own coverage,
  which is the pattern to follow.

- **Credit the app's own test suite.** `sv run` runs the tests the manifest declares, and a passing
  suite is real evidence; `sv report --run` records that they passed and takes no credit, because
  nothing yet decides which requirement a given test is about. v1's `compliance/test-name-match.ts`
  compares a test's name and body with a requirement's wording and is honest about its limits — about a
  third of its flags are honest tests phrased differently, and it is blind to a swap between neighbouring
  requirements that share vocabulary. Port that shape, not a stricter one.

- **The MCP server.** Wraps the same core so an AI coding tool can run the checks mid-conversation. Wants
  `sv check` finished first.

## Decided, not yet written down as ADRs

- Corroboration only ever moves toward more requirements applying, never fewer (`sv-manifest::resolve`).
- The OWASP data files are shared with v1, not copied.
- `sv` never writes application code, so v1's generation agent and its fence have no successor here.
