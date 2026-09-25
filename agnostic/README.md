# SecureVibe Agnostic (`sv`)

A second version of SecureVibe. Same workflow, same OWASP checks, same honest reports — but you write the app
in whatever AI coding tool you like, and it can be in any language.

v1 asks you to fill in a form and then writes a Node app for you. `sv` does neither. You have the back-and-forth
with your own AI tool until the app is what you wanted, and then `sv` picks up the code and grades it.

## Where it is

The compliance engine, the scanners, the container runner, the checks and the reports all run. What is not
built is listed in `docs/BACKLOG.md`, and the reports say plainly which parts of an app nothing has examined.

```bash
cargo run -p sv-cli -- init              # the securevibe.toml spec to hand to your AI tool
cargo run -p sv-cli -- scope ./my-app    # which requirements apply to this app, and why
cargo run -p sv-cli -- run ./my-app      # start it behind the network fence and ask it questions
cargo run -p sv-cli -- check ./my-app    # credentials, configuration, and rules that read the code
cargo run -p sv-cli -- sbom ./my-app     # what the app ships, as CycloneDX JSON
cargo run -p sv-cli -- audit ./my-app --advisories ./osv   # against known vulnerabilities
cargo run -p sv-cli -- report ./my-app   # the whole thing, written out to read and to keep
```

The rules that read code understand Python, JavaScript, TypeScript, Go, Ruby, PHP, Java, C#, Kotlin,
Rust and C. A language
outside that list is not guessed at: while a file `sv` cannot parse is present, no code rule claims
anything about the app at all, and the report says which language stopped it. A script written into a web page —
in a <script> block, an event handler or a javascript: link — is taken out and read as JavaScript, and anything found in it is reported against the page and the line it
is really on. A page counts as unreadable only when something in it could not be taken out that way.

Running the app needs a container backend (Docker or Colima). Without one, everything that needs the app
running reports *not assessed* — never a pass, and never a failure.

`sv` opens no network connection. Advisory data is something you download and point it at; the list of
packages your app depends on is yours, and a check that quietly phones out is one you did not agree to.

`sv run` also asks the running app four questions, as somebody who has not signed in: what headers it
sends, what it says when asked for a page that is not there, whether it accepts a site it has never heard
of, and whether it echoes requests back. What those questions cannot reach — anything behind a login — is
printed as *not assessed* before any finding, because a suite that only tries the front door and says
nothing reads exactly like one that found nothing wrong.

If your app has its own tests, they can count too — but only for requirements they name. Write the id
into the test, in its name or in a comment on the line above it:

```python
def test_V1_2_4_search_uses_bound_parameters():   # or: # covers V1.2.4
```

When the whole suite passes, `sv` reports those requirements as checked by your own tests and says which
file and line to go and look at. There is no clever matching behind this, on purpose: guessing that
`test_login` is about a particular authentication requirement would credit it on the strength of a name
somebody chose for other reasons. A test that names nothing is not evidence about anything in particular,
which is a perfectly fair thing for a test to be — most tests are.

`sv report` writes the whole thing out (add `--run` to start the app behind the fence and include what
it answers, and `--tools` to run the security tool your language already has): one HTML file you can open by double-clicking it, the same
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
