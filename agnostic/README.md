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
cargo run -p sv-cli -- run ./my-app      # start it behind the network fence and check it answers
cargo run -p sv-cli -- check ./my-app    # credentials, configuration, and rules that read the code
cargo run -p sv-cli -- sbom ./my-app     # what the app ships, as CycloneDX JSON
cargo run -p sv-cli -- audit ./my-app --advisories ./osv   # against known vulnerabilities
```

Running the app needs a container backend (Docker or Colima). Without one, everything that needs the app
running reports *not assessed* — never a pass, and never a failure.

`sv` opens no network connection. Advisory data is something you download and point it at; the list of
packages your app depends on is yours, and a check that quietly phones out is one you did not agree to.

`sv run` also asks the running app four questions, as somebody who has not signed in: what headers it
sends, what it says when asked for a page that is not there, whether it accepts a site it has never heard
of, and whether it echoes requests back. What those questions cannot reach — anything behind a login — is
printed as *not assessed* before any finding, because a suite that only tries the front door and says
nothing reads exactly like one that found nothing wrong.

`sv report` writes the whole thing out (add `--run` to start the app behind the fence and include what
it answers): one HTML file you can open by double-clicking it, the same
thing as Markdown, the findings as SARIF for editors and CI, and the data as JSON. The reports lead with
what was **not** examined, say what each check covered when it found nothing wrong, and nothing in them
says a requirement passed — `sv` is not able to establish
that, so it does not claim it.

Not built yet: the MCP server, and the Secure by Design checklist is not yet loaded despite being named
in the help text.

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
