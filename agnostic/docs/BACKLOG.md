# SecureVibe Agnostic — what is still to do

Same rules as the v1 backlog: claim an item here, in a commit of its own, before starting it. A message to
another session is not a claim.

## Next

- **Corroborators for the twelve claims that still have none**: `public-api`, `multi-tenant`, `shared-hostname`,
  `external-apis`, `tls`, `internet`, `ai-actions`, `ai-history`, `ai-moderation`, `multimodal-ai`,
  `hosted-scm`, `outside-contributors`. Several of these may have no honest corroborator at all, and saying so
  in the reports is a better answer than a weak one.

- **The rest of `sv check`.** Secrets, the universal configuration checks and the SBOM are done. Still
  missing: AST rules via tree-sitter. `sv-scan` holds the ecosystem detector and the dependency readers,
  and `sv-check` holds the finding type, the coverage-aware walk and the passed/failed/not-assessed shape,
  so these build on what is there.

- **Read `pnpm-lock.yaml`.** **[taken: keen-meninsky-691a27, 24 September 2026]** The last common lockfile `sv` names as unread. It is YAML and nothing in the
  workspace parses YAML yet, which is the decision to make rather than the work.

- **Severity from the advisory's own CVSS vector.** `sv audit` reports medium unless the record says
  CRITICAL in words, because inventing a severity from a vector it has not parsed would be worse than
  under-stating one. Parsing the vector would let the finding carry the severity the advisory actually
  gives it.

- **Read Maven and Gradle version ranges.** The lockfile check reports them as not assessed, because
  pinning lives in `pom.xml` and `build.gradle` rather than a lockfile. Reading a range out of either
  would turn an open question into an answer.

- **The adapter data file.** Per-language tooling driven by a manifest, not by Rust. A tool that is not
  installed reports *not run*, never a clean pass.

- **DAST probes.** The runner starts the app and confirms it answers; nothing probes it yet. The probes run
  from a sidecar on the fenced network — `sv-run` already does exactly that for the health check, so the
  mechanism is proven and what is missing is the probe suite itself. Port v1's `scanners/dast/probes`.

- **Seeded users.** v1's probes sign in as users it created. Doing that for an arbitrary app means the manifest
  declaring how, or the probes running unauthenticated and saying which requirements that leaves unassessed.

- **Reports.** Port `reports/` once the exclusions above are honest. Not before: a report is where a wrong
  exclusion does its damage.

- **The MCP server.** Wraps the same core so an AI coding tool can run the checks mid-conversation. Wants
  `sv check` finished first.

## Decided, not yet written down as ADRs

- Corroboration only ever moves toward more requirements applying, never fewer (`sv-manifest::resolve`).
- The OWASP data files are shared with v1, not copied.
- `sv` never writes application code, so v1's generation agent and its fence have no successor here.
