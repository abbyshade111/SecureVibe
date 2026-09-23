# SecureVibe Agnostic — what is still to do

Same rules as the v1 backlog: claim an item here, in a commit of its own, before starting it. A message to
another session is not a claim.

## Next

- **Corroborators for the ten claims that still have none**: `public-api`, `multi-tenant`, `shared-hostname`,
  `external-apis`, `tls`, `internet`, `ai-actions`, `ai-history`, `ai-moderation`, `multimodal-ai`,
  `hosted-scm`, `outside-contributors`. Several of these may have no honest corroborator at all, and saying so
  in the reports is a better answer than a weak one.

- **`payments` and `scheduler` gate no requirements.** They are asked about, they have reasons written for
  them, and nothing in the OWASP data keys on either. Either they earn rules in the v2 overlay, or they stop
  being conditions and become what they really are — a prompt to check the data categories. Right now `sv`
  reports a contradiction it then has to explain away.

- **`sv check`.** The remaining language-agnostic scanners: secrets, config, SBOM, and AST rules via
  tree-sitter. `sv-scan` already holds the ecosystem detector and the dependency readers, so this builds on
  them rather than starting over.

- **The adapter data file.** Per-language tooling driven by a manifest, not by Rust. A tool that is not
  installed reports *not run*, never a clean pass.

- **The container runner.** A backend is now available here (Colima 0.10.3, Docker 29.8.1, linux/aarch64), so
  this is no longer blocked. Still build the trait and the honest `not assessed` path first: a machine without a
  backend is the normal case for everyone else, and a runner that assumes one would report their apps as failing
  rather than as unrun. Colima's defaults are two CPUs and 2 GB, which a real test suite can exhaust — the
  runner has to tell a starved run apart from a broken one.

- **Reports.** Port `reports/` once the exclusions above are honest. Not before: a report is where a wrong
  exclusion does its damage.

- **The MCP server.** Wraps the same core so an AI coding tool can run the checks mid-conversation. Wants
  `sv check` finished first.

## Decided, not yet written down as ADRs

- Corroboration only ever moves toward more requirements applying, never fewer (`sv-manifest::resolve`).
- The OWASP data files are shared with v1, not copied.
- `sv` never writes application code, so v1's generation agent and its fence have no successor here.
