# SecureVibe Agnostic (`sv`)

A second version of SecureVibe. Same workflow, same OWASP checks, same honest reports — but you write the app
in whatever AI coding tool you like, and it can be in any language.

v1 asks you to fill in a form and then writes a Node app for you. `sv` does neither. You have the back-and-forth
with your own AI tool until the app is what you wanted, and then `sv` picks up the code and grades it.

## Where it is

The compliance engine, the scanners, the container runner, the checks and the reports all run. What is not
built is listed in `docs/BACKLOG.md`, and the reports say plainly which parts of an app nothing has examined. Which
requirements of ASVS, AISVS, and the Secure by Design checklist any check can speak to at all, and what
each check needs to run, is counted in `docs/COVERAGE.md`.

```bash
cargo run -p sv-cli -- init              # the securevibe.toml spec to hand to your AI tool
cargo run -p sv-cli -- scope ./my-app    # which requirements apply to this app, and why
cargo run -p sv-cli -- run ./my-app      # start it behind the network fence and ask it questions
cargo run -p sv-cli -- check ./my-app    # credentials, configuration, and rules that read the code
cargo run -p sv-cli -- sbom ./my-app     # what the app ships, as CycloneDX JSON
cargo run -p sv-cli -- audit ./my-app --advisories ./osv   # against known vulnerabilities
cargo run -p sv-cli -- report ./my-app   # the whole thing, written out to read and to keep
cargo run -p sv-cli -- mcp --root ~/code  # serve the checks to your AI coding tool (see below)
```

The rules that read code understand Python, JavaScript, TypeScript, Go, Ruby, PHP, Java, C#, Kotlin,
Rust, C, Dart, Swift, and shell scripts. A language
outside that list is not guessed at: while a file `sv` cannot parse is present, no code rule claims
anything about the app at all, and the report says which language stopped it. The same holds one rule at
a time: a rule that has not been taught a language in your app claims nothing, and the report names the
rule and the language. A script written into a web page —
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

When the suite passes, `sv` reports those requirements as checked by your own tests and says which file
and line to go and look at. If your runner can write a JUnit XML report, point `test-report` at it and
the tests that passed still count even when others in the suite failed — without one, `sv` sees a single
exit code and one broken test costs the credit of every other test. There is no clever matching behind this, on purpose: guessing that
`test_login` is about a particular authentication requirement would credit it on the strength of a name
somebody chose for other reasons. A test that names nothing is not evidence about anything in particular,
which is a perfectly fair thing for a test to be — most tests are.

`sv report` writes the whole thing out (add `--run` to start the app behind the fence and include what
it answers, and `--tools` to run the security tool your language already has): one HTML file you can open by double-clicking it, the same
thing as Markdown, the findings as SARIF for editors and CI, and the data as JSON. The reports lead with
what was **not** examined, say what each check covered when it found nothing wrong, and nothing in them
says a requirement passed — `sv` is not able to establish
that, so it does not claim it.

They also list the tests worth writing: every requirement that applies and has no evidence yet, and no
test in the app naming it, lowest level first. A passing test with the requirement's id in its name is
the one way to give evidence about any requirement, including the many no check here can reach.

For an app that calls an AI model, semgrep's rules about such apps are read against AISVS too: user
input placed in the system instructions, no limit on how long an answer may be, a model called in a
loop with no way out, an MCP tool that hands the model a password. Each of those, when found, marks
the AISVS requirement it breaks as needing attention. Finding none marks nothing as checked, because
the absence of one way to get it wrong is not the control AISVS asks for.

The OWASP Secure by Design checklist is read too, alongside ASVS and AISVS. Its thirty-six controls are
design review rather than scanning — whether trust zones are enforced, whether an incident response plan
is rehearsed, whether your data has named owners — so nothing here can check a single one of them, and
the reports say exactly that rather than counting them as things that were looked at. Its ids are written
`SBD-AC-01` to keep them apart from AISVS Appendix C, which numbers its own requirements `AC.1.1`.
The checklist has no levels; each control takes the level of the ASVS requirement that asks the same
thing (`data/sbd-asvs-crosswalk.json`), or is shown at every level when nothing in ASVS does.

## Signing in

`sv run` asks the running app questions as somebody who has not signed in — and, when
`securevibe.toml` says how, as signed-in users too. Under `[stack.run.users]` you say how accounts are
made (a `seed` command run inside the app's container, or the app's own `signup`), how to sign in and
out, which pages are private or admin-only, and how one user creates something another must not read.
`sv` makes two ordinary accounts and, if you list admin pages, an admin, each with a password made for
that run, and then asks:

- can somebody who has not signed in open a private page? (V8.2.1)
- can an ordinary user open an admin page? (V8.2.1)
- can one user read what another created? (V8.2.2)
- is a request from another website accepted with the user's cookies? (V3.5.1)
- does signing in issue a new session, and does signing out end it? (V7.2.4, V7.4.1)
- is the session cookie out of reach of scripts and other sites? (V3.3.4, V3.3.2)
- is the session id long enough to guess, and different each time? (V7.2.3; only ever a finding)
- does a known default account, such as `admin` / `admin`, sign in? (V6.3.2; only ever a finding)
- is a password accepted in the address rather than the body? (V14.2.1; only ever a finding)
- is the password field on the sign-in and sign-up pages masked, and can a password be pasted into it?
  (V6.2.6; V6.2.7, only ever a finding)
- does visiting the sign-out address, rather than submitting its form, sign the user out? (V3.5.3; only
  ever a finding)

When `signup` is set, `sv` also signs up through it, whether or not `seed` made the test users, and
asks what passwords the app accepts: one of 7 characters (V6.2.1), one of lowercase letters alone
(V6.2.5), a common one beside a random one of the same shape (V6.2.4), and one of 83 characters
(V6.2.9), which is then tried with only its first 72, and the strong one with its capitals swapped, to
see that the password is checked exactly as typed (V6.2.8). Each is compared with an
ordinary strong password signed up first, and whether a password was accepted is told by signing in
with it.

Each question first shows the thing it depends on actually worked — the session opens a private page,
the owner can read back what they made, the admin can open the admin page — and when it cannot show
that, the answer is *not assessed*, not a pass. `examples/notes-with-users` is a complete example.

## From inside your AI coding tool

`sv mcp` offers the same checks over the Model Context Protocol, so the tool you build with can run them
mid-conversation and work through the findings with you. Build it once (`cargo build --release -p
sv-cli`), then register it — for Claude Code:

```bash
claude mcp add securevibe -- /path/to/agnostic/target/release/sv mcp --root ~/code
```

or, for a tool configured with JSON:

```json
{ "mcpServers": { "securevibe": { "command": "/path/to/sv", "args": ["mcp", "--root", "/home/you/code"] } } }
```

It offers four tools: `securevibe_spec` (the `securevibe.toml` to write), `securevibe_check` (what
applies, what was found, and first of all what was not examined), `securevibe_explain` (a requirement in
its framework's own words) and `securevibe_write_report` (the full reports, into the app's folder).

Two limits are deliberate. It only reads apps under the folder given to `--root`; a path outside it is
refused, `..` and symbolic links included. And it never starts your app or runs other people's security
tools — each of those runs code, and that stays your decision at a terminal (`sv report --run --tools`).
The results say both were not done, the same way the written report does.

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
