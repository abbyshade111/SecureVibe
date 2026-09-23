# SecureVibe Agnostic — what is still to do

Same rules as the v1 backlog: claim an item here, in a commit of its own, before starting it. A message to
another session is not a claim.

## Next

- **Corroborators for the ten claims that still have none**: `public-api`, `multi-tenant`, `shared-hostname`,
  `external-apis`, `tls`, `internet`, `ai-actions`, `ai-history`, `ai-moderation`, `multimodal-ai`,
  `hosted-scm`, `outside-contributors`. Several of these may have no honest corroborator at all, and saying so
  in the reports is a better answer than a weak one.

- **`sv check`.** The remaining language-agnostic scanners: secrets, config, SBOM, and AST rules via
  tree-sitter. `sv-scan` already holds the ecosystem detector and the dependency readers, so this builds on
  them rather than starting over.

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
