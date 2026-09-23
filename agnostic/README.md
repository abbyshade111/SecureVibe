# SecureVibe Agnostic (`sv`)

A second version of SecureVibe. Same workflow, same OWASP checks, same honest reports — but you write the app
in whatever AI coding tool you like, and it can be in any language.

v1 asks you to fill in a form and then writes a Node app for you. `sv` does neither. You have the back-and-forth
with your own AI tool until the app is what you wanted, and then `sv` picks up the code and grades it.

## Where it is

Early. The compliance engine is ported and runs against the real OWASP data; the scanners, the container runner
and the reports are not built yet.

Working today: `sv scope` reads the app's manifests and source, answers every technology question from the
code itself, and says which OWASP requirements apply, which do not, and which nothing has yet answered.


```bash
cargo run -p sv-cli -- init              # the securevibe.toml spec to hand to your AI tool
cargo run -p sv-cli -- scope ./my-app    # which requirements apply to this app, and why
```

Not built yet: the remaining scanners (secrets, config, SBOM, AST rules), the corroborators that check the
manifest's claims against the code, the container runner, the reports, the MCP server.

## Building

Rust 1.95 or newer.

```bash
cargo test
```

The OWASP data files are shared with v1 rather than copied — `sv` reads `../data/frameworks` and
`../data/knowledge`, so an ASVS correction fixes both products. `SV_DATA_DIR` overrides the location.

## Reading order

`docs/DESIGN.md` explains the two changes from v1, why deleting the wizard was the hard part, and what the
first run against real data turned up.
