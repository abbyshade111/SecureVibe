# SecureVibe Agnostic — what is still to do

Same rules as the v1 backlog: claim an item here, in a commit of its own, before starting it. A message to
another session is not a claim.

## Next

- **Corroborators.** Nothing checks a claim against the code yet, so every claim resolves `unverifiable` and
  says so. First ones worth having, because they are the claims most often wrong in the safe-looking direction:
  `auth`, `payments`, `uploads`, `external-apis`, `jwt`, `oauth`. Each is a grep-plus-manifest check over
  dependency files and route definitions. The interface already exists — `resolve` takes a
  `Fn(Condition) -> Option<bool>` — and `None` must keep meaning "no corroborator", never "not found".

- **`sv check`.** The remaining language-agnostic scanners: secrets, config, SBOM, and AST rules via
  tree-sitter. `sv-scan` already holds the ecosystem detector and the dependency readers, so this builds on
  them rather than starting over.

- **The adapter data file.** Per-language tooling driven by a manifest, not by Rust. A tool that is not
  installed reports *not run*, never a clean pass.

- **The container runner.** Docker is not installed on the development machine, so `sv-run` needs its backend
  trait and an honest `not assessed` path before anything else. Build the trait and the reporting first; the
  backend can follow.

- **Reports.** Port `reports/` once the exclusions above are honest. Not before: a report is where a wrong
  exclusion does its damage.

- **The MCP server.** Wraps the same core so an AI coding tool can run the checks mid-conversation. Wants
  `sv check` finished first.

## Decided, not yet written down as ADRs

- Corroboration only ever moves toward more requirements applying, never fewer (`sv-manifest::resolve`).
- The OWASP data files are shared with v1, not copied.
- `sv` never writes application code, so v1's generation agent and its fence have no successor here.
