<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/brand/stackvet-logo-dark.svg">
  <img alt="StackVet" src="docs/brand/stackvet-logo.svg" width="320">
</picture>

# StackVet (`sv`)

StackVet checks an app against the OWASP standards and writes reports that say plainly what was verified and
what was not. You write the app in whatever AI coding tool you like, in any language; you have the back-and-forth
with your own AI tool until the app is what you wanted, and then `sv` picks up the code and grades it.

**If you are not a programmer, start with [`docs/GETTING-STARTED.md`](docs/GETTING-STARTED.md).** It walks through
installing Docker, connecting StackVet to your AI tool, the prompt to start with, and reading the report, one step
at a time. The rest of this page is written for programmers, and its commands build StackVet from its source code.

**SecureVibe v1**, the earlier version that asked you to fill in a form and then wrote a Node app for you, is
archived, not deleted: it lives on the `v1` branch (see `ARCHIVED.md` there) and at the tags `v1-paper` and
`v1-final`. Its Zenodo version DOI, the one to cite, is 10.5281/zenodo.22984709. Until 26 September 2026 this
repository held v1 at its top and `sv` under `agnostic/`; no history was rewritten, so every commit hash cited
elsewhere still resolves.

## Where it is

The compliance engine, the scanners, the container runner, the checks and the reports all run. What is not
built is listed in `docs/backlog/` (one file per item; `docs/BACKLOG.md` is its guide and roadmap), and the reports say plainly which parts of an app nothing has examined. Which
requirements of ASVS, AISVS, and the Secure by Design checklist any check can speak to at all, and what
each check needs to run, is counted in `docs/COVERAGE.md`. `docs/REQUIREMENTS.md` lists every ASVS and AISVS requirement by level and
family, with the checks that speak to each.

```bash
cargo run -p sv-cli -- init              # the stackvet.toml spec to hand to your AI tool
cargo run -p sv-cli -- scope ./my-app    # which requirements apply to this app, and why
cargo run -p sv-cli -- run ./my-app      # start it behind the network fence and ask it questions
cargo run -p sv-cli -- check ./my-app    # credentials, configuration, and rules that read the code
cargo run -p sv-cli -- sbom ./my-app     # what the app ships, as CycloneDX JSON
cargo run -p sv-cli -- audit ./my-app --advisories ./osv   # against known vulnerabilities
cargo run -p sv-cli -- report ./my-app   # the whole thing, written out to read and to keep
cargo run -p sv-cli -- report ./my-app --advisories ./osv  # …with known vulnerabilities in it too
cargo run -p sv-cli -- bundle ./my-app   # the app, its report and a SHA-256 for every file, in one zip beside the app
cargo run -p sv-cli -- dashboard ./app-one ./app-two --out ~/sv-dashboard.html  # one page for several apps, from their reports
cargo run -p sv-cli -- mcp --root ~/code  # serve the checks to your AI coding tool (see below)
```

The rules that read code understand Python, JavaScript, TypeScript, Go, Ruby, PHP, Java, C#, Kotlin,
Rust, C, C++, Dart, Swift, and shell scripts. A language
outside that list is not guessed at: while a file `sv` cannot parse is present, no code rule claims
anything about the app at all, and the report says which language stopped it. The same holds one rule at
a time: a rule that has not been taught a language in your app claims nothing, and the report names the
rule and the language. A script written into a web page —
in a <script> block, an event handler or a javascript: link — is taken out and read as JavaScript, and anything found in it is reported against the page and the line it
is really on. A page counts as unreadable only when something in it could not be taken out that way.
Jupyter notebooks are read as Python, cell by cell. Astro and EJS pages have their code taken out and read the same
way. Templates that cannot run code (Handlebars, Mustache, Jinja, Liquid, Twig, Nunjucks) are read as pages. While a
`.pug`, `.erb`, `.jsp`, `.cshtml` or `.razor` file is present, no code rule claims anything, because nothing reads
the code in those yet, and the report names the files (ADR-054).

`sv check`, `sv report`, `sv audit` and `sv run` end with a status a CI job can act on. 3 always means `sv` itself
failed and there is no result: a folder that is not there, an option it does not know, a `stackvet.toml` that is
there and cannot be read, or, for `sv report`, none at all (`sv check` and `sv audit` run without one, and read it
when it is there; every other command uses 3 for a failure of its own too). `sv run` exits 2 when the app could not
be started or never answered. `sv audit` exits 0 when every package was compared
and none matched a known vulnerability, 1 when one did, and 2 when the comparison did not cover the whole app (no
database, an ecosystem the database holds nothing about, or a list of packages `sv` could not complete).
`sv check` and `sv report` exit 0 when they finished, and 2 when a check could not run: a file that could not be
read, a file the parser could not make sense of, a language nothing here reads, a code rule that would not
compile, no file of the app read at all, or (`sv report --run`) an app that could not be started. What a static
run cannot see by its nature, such as requirements nothing verified or a check that needs a Dockerfile the app
lacks, does not count, or every run would exit 2. Add `--fail-on attention` to exit 1 for any finding of low
severity or worse, leaving out those marked only for information (or `attention:high` for high and critical
only), `--fail-on not-assessed` to exit 2 also for a symbolic link not
followed, a `--tools` tool that did not run, or an `--advisories` comparison that did not cover the app, or
`--fail-on any` for both; 1 outranks 2. Packages
in folders `stackvet.toml` says are not the app, such as example apps and test fixtures, are listed apart
and still count: that file is written by your AI coding tool, and naming a folder there must never hide a
vulnerability. `sv` holds itself to this every week, auditing the Rust files it is built from
(`.github/workflows/audit.yml`).

Running the app needs a container backend (Docker or Colima). Without one, everything that needs the app
running reports *not assessed* — never a pass, and never a failure.

`sv run` gives the app no network, so it cannot install its own packages, and an app that needs them never starts.
Put `install = true` under `[stack.run]` and `sv` installs them first, in a container of its own that sees only the
package list, never the app's code or its `.env`: from `requirements.txt` with every line pinned (`name==1.2.3`), or
from `package.json` with its `package-lock.json`. It runs none of the packages' own install code, so a Python package
with no ready-made download cannot be installed this way (ADR-052).

`sv` opens no network connection of its own, with two exceptions you ask for by name. `sv probe <address>`
sends at most four read-only requests to the address you type (five with `--api`), through `curl`, and asks this computer's own
DNS resolver one question about that name. And with `install = true`, the install step above downloads the app's
packages from PyPI or npm before the run; the report says when it did. Advisory data is something you download and point it at; the list
of packages your app depends on is yours, and a check that quietly phones out is one you did not agree to.
Outside tools you turn on with `--tools` are other people's programs, and semgrep fetches its rules the first
time it runs; gosec is started so that it cannot download your app's modules or run a C compiler, and a tool that
would read through a link in your app is not run while the link is there. `sv run` starts containers, and Docker downloads any image it does not have yet.

`sv run` also asks the running app questions as somebody who has not signed in: among them, what headers
and cookies it sends, what it says when asked for a page that is not there, whether it accepts a site it has
never heard of, whether it echoes requests back, and whether it leaves source control, documentation, or a
development console open to anyone. What those questions cannot reach — anything behind a login — is
printed as *not assessed* before any finding, because a suite that only tries the front door and says
nothing reads exactly like one that found nothing wrong.

If your app has its own tests, they can count too — but only for requirements they name. They run only when
`sv` starts the app (`sv run`, or `sv report --run`), with the command given as `test` under `[stack.run]`.
Write the id into the test, in its name or in a comment on the line above it:

```python
def test_V1_2_4_search_uses_bound_parameters():   # or: # covers V1.2.4
```

When the suite passes, `sv` reports those requirements as *tested by the app's own tests* and says which
file and line to go and look at. That is a status of its own, below *checked*: your AI coding tool wrote
the tests, and `sv` does not read whether each one asks what its requirement asks (ADR-050). Only code is
read, so an id in a Markdown note under `tests/` counts for nothing. If your runner can write a report of its own (JUnit XML, TAP, `go test -json`, or
jest's or Vitest's JSON), point `test-report` at it and
the tests that passed still count even when others in the suite failed — without one, `sv` sees a single
exit code and one broken test costs the credit of every other test. There is no clever matching behind this, on purpose: guessing that
`test_login` is about a particular authentication requirement would credit it on the strength of a name
somebody chose for other reasons. A test that names nothing is not evidence about anything in particular,
which is a perfectly fair thing for a test to be — most tests are.

`sv report` writes the whole thing out, into a folder named `stackvet-report` inside the app's folder
unless you give `--out` (add `--run` to start the app behind the fence and include what it answers, and
`--tools` to run the outside security tools that are installed: Bandit, gosec, Brakeman, Semgrep, and CodeQL):
`report.html`, one file you can open by double-clicking it; `compliance.md` and `security.md`, the same in
Markdown; the findings as SARIF (`findings.sarif`) for editors and CI; and the data as JSON (`report.json`). The reports lead with
what was **not** examined, say what each check covered when it found nothing wrong, and nothing in them
says a requirement passed — `sv` is not able to establish
that, so it does not claim it.

Each requirement gets one of nine statuses, strongest evidence first: *needs attention* (a check found a problem),
*checked*, *checked in part* (a check ran, but tried only part of what the requirement asks, ADR-053), *tested by
the app's own tests*, *documented by the owner*, *checked by hand by the owner*, *attested by the owner*, *stated by
the AI coding tool*, and *not verified*.

They also list the tests worth writing: every requirement that applies and has no evidence yet, and no
test in the app naming it, lowest level first. A passing test that names the requirement's id is the one way
for the app itself to add evidence about the many requirements no check here reaches. It counts as *tested by
the app's own tests*, below *checked*, and never for a requirement about documents or how the app is run.

The reports also have a threat model: what could go wrong with an app like this one, by the part of it
each threat concerns (sign-in, stored data, the AI model, uploads, payments, and so on), with what the
checks showed about each: found, checked in part, not verified, or not known to apply until a question
in stackvet.toml is answered. (For a threat, *checked in part* means some of its requirements were checked; the
app's own tests and the owner's word never move one.) It is made from rules, not by asking an AI, and it never calls a threat
handled, because a threat is only as settled as the requirements that answer it. See
`docs/THREAT-MODELING.md`.

They also read your AI coding tool's own files in the app's folder, in a section of their own, apart from the app's
grade: the commands its settings run, the permissions that let it act without asking, the MCP servers it starts, and
any characters hidden in its instruction files (`AGENTS.md`, `CLAUDE.md`, and the like) that a person reading them
cannot see (ADR-049).

### The questions no tool can answer

Nineteen of the requirements at level 1 and 2 ask for a written decision and nothing else: what counts
as valid input, who may do what, how long somebody stays signed in, how soon a library with a known
vulnerability gets updated. Nothing can read those out of the code, because what they ask for is a
decision somebody made.

`sv notes` writes `security-notes.md` into your app's folder: one question per requirement, in plain words,
with what `sv` already found underneath it — the outside services by the package that showed each one,
the kinds of data you said the app holds. You write the answer. Running it again keeps everything you
have written.

An answer makes that requirement **documented by the owner** in the report. That is its own line in
the table and never *checked*: nothing reads whether your answer is right, or whether the app does
what it says. A check that found a problem always wins over what the notes say, and an answer cannot
settle a threat in the threat model — otherwise an app could talk its way out of one by describing
itself.

Some requirements are about where the app is *served from* rather than what is in it, and no amount
of reading the code settles them. `sv probe https://your-app.example.com` asks your own live site the
questions that matter most: is the certificate one browsers trust, is plain HTTP still served, does
it tell browsers to stick to HTTPS, do its cookies carry the `__Host-` prefix, does it still accept
the old TLS 1.0 or 1.1, and does it staple its certificate's revocation status.

It is deliberately narrow about what it will do. The address has to be typed at the terminal, never
read from a file. It fetches headers only, sends no cookies and no credentials, makes at most four
requests, and will not follow a redirect to any host but the one you named. It cannot sign in and
cannot change anything. `--api /path` names an address of your app's API on the same site, and adds one
request: that address over plain HTTP, asked the way a program asks, since an API should refuse plain
HTTP rather than redirect it (ASVS V4.1.2).

About fifty of the requirements that apply to a typical app at level 2 cannot be settled by any tool at all
(49 and 50 for the examples `notes-with-users` and `flask-booking`, counted on 8 October 2026), and
the report has a section for them: **what only you can check**, with a line each saying what
doing something about it involves — write it down in the notes, answer it in `[design]`, or go and
look at the live site and here is what at. Nothing on that list is counted as met. Doing the thing is
what would change that, not reading about it.

One thing you can state as a number, and `sv` will hold your app to it: how many wrong passwords in
a row it should allow before pushing back. Put `failed-sign-ins = 5` under `[policy]` in
`stackvet.toml` and the checks make seven wrong attempts, two more than you allowed, and watch what the app
does (at most 26, so a number above 24 is reported as not assessed). That settles
V6.3.1, one of the Level 1 requirements, and it is a real check rather than your word: an app that
only gives way after twenty attempts, when you said five, is reported. Say nothing and nothing is
claimed either way.

Sixteen more ask how the app is built rather than what is in it: is input checked on the server as
well as in the browser, do the app's own parts prove who they are to each other. You answer those in
the `[design]` section of `stackvet.toml` with yes, no, or not sure, and where in the code it is
done.

Answering yes makes the requirement **attested by the owner** — the weakest thing the report says of
your own word (only the AI coding tool's answer counts for less), and deliberately so. It is your word about the app, not a check of it, so the requirement stays on
the list of tests to write, and it cannot settle a threat. Answering **no** is the more useful
answer: the report says plainly that the control is missing, on your own say-so. If `where` names a
file that is not there any more, the report says that too, rather than keeping a pointer that leads
nowhere.

For an app that calls an AI model, semgrep's rules about such apps are read against AISVS too: user
input placed in the system instructions, no limit on how long an answer may be, a model called in a
loop with no way out, an MCP tool that hands the model a password. Each of those, when found, marks
the AISVS requirement it breaks as needing attention. Finding none marks nothing as checked, because
the absence of one way to get it wrong is not the control AISVS asks for.

The OWASP Secure by Design checklist is read too, alongside ASVS and AISVS. Its thirty-six controls are
design review rather than scanning — whether trust zones are enforced, whether an incident response plan
is rehearsed, whether your data has named owners — so nothing here can check a single one of them, and
the reports say exactly that rather than counting them as things that were looked at. Two of them can be
written down: SBD-MT-06 (what you do if something goes wrong) and SBD-AC-06 (the rules that might apply to
the app), as sections of a `design-decisions.md` in the app's folder, which the design-time prompts write.
A section marked as yours and recorded with `sv review` counts as *documented by the owner*; nothing in that
file ever counts as checked. Its ids are written
`SBD-AC-01` to keep them apart from AISVS Appendix C, which numbers its own requirements `AC.1.1`.
The checklist has no levels; each control takes the level of the ASVS requirement that asks the same
thing (`data/sbd-asvs-crosswalk.json`), or is shown at every level when nothing in ASVS does.

## Setting a finding aside, confirming an answer, or giving your own: `sv review`

When a finding is a false alarm, or a risk you choose to live with for now, it can be set aside under
`[[finding-review]]` in `stackvet.toml`, with a reason. When your AI coding tool answered a question
and you have looked for yourself, you can confirm its answer. Either counts only once **you** record it,
by running this in your own terminal:

```bash
sv review ./my-app
```

The same goes for your own answers: a `[design]` answer or a `[checked-by-hand]` result written with
`by = "owner"`, and a section of `security-notes.md` marked `Written by: owner`, count as yours only once
recorded this way. Until then they count as your AI coding tool's word, a step lower, and the report says
so.

It goes through every entry that is not yet yours, shows the finding's line of code (never a line that
may hold a key), and asks for your name, or `owner`. What you record is written back into
`stackvet.toml` with the date and a *seal*. Your AI coding tool may write entries too, as proposals
(`by = "ai-tool"`), and the report lists them, but a proposal counts for nothing.

Why the extra step: the tool rewrites code until a warning stops, and writing `by = "owner"` into the
file is the easiest way to stop one. `sv review` runs only in a terminal someone is typing in, which an
AI coding tool does not have, and *signs* each entry with a key of its own, kept in your own settings
folder (`~/.config/stackvet/review-signing-key`), outside the app. The first time, it makes the key and
asks whether to protect it with a passphrase. With one, nothing can sign as you without it, your AI coding
tool included, since the passphrase is only in your head; you type it each time you run `sv review`.

A signature is checked with the key's *public half*, which can check a signature but never make one. `sv
review` puts that public half, with the app it may sign for, on a list of trusted keys beside the key
(`~/.config/stackvet/allowed_signers`), and shows you one line to give any other computer that should
count what you record: CI, the container, or a second computer of yours. Give it as the variable
`SV_TRUSTED_SEALS` (on GitHub: the repository's Settings, then Secrets and variables, then Actions, then
Variables, and pass `SV_TRUSTED_SEALS: ${{ vars.SV_TRUSTED_SEALS }}` to the step that runs `sv`). The
line is not a secret: anyone can read it, and nobody can sign with it.

Wherever the report is made, it checks each signature against the list: an entry that was changed
afterwards, never signed, or signed with a key the list does not name, is a proposal again, and the
report names the key it trusted and where the list came from, so you can tell it is yours. A signature
also names the app, so an entry copied into another app is a proposal there. On your own computer that
means the app's folder: an app moved to another folder is a proposal until you run `sv review` in it. On
a computer with no list at all the signature cannot be checked, so the entry does not count, and the
report says how to make it count.

What it cannot show: who was at the keyboard, unless your key has a passphrase; and that a trusted key is
yours, since whoever can change the list, or the repository variable, can add one. A tool set on faking
it, running as you, could do either; it stops the easy way, not every way. Keep the key file private.

Entries recorded before 6 October 2026 were sealed another way, with `~/.config/securevibe/review-key`,
and count only on the computer that holds that key. The next time you run `sv review` there, it offers to
sign them all again at one yes, without asking each question again.

With the container, give it a terminal and somewhere to keep the key, made first so that it is yours
(`mkdir -p ~/.config/stackvet && chmod 700 ~/.config/stackvet`; on Linux, add `--user` as below):
`docker run --rm -it --network none -v "$PWD":"$PWD" -w "$PWD" -v "$HOME/.config/stackvet":/sv-config/stackvet -e XDG_CONFIG_HOME=/sv-config ghcr.io/abbyshade111/stackvet-sv review .`
The container that writes your reports needs only the list, and never the key beside it: pass
`-e SV_TRUSTED_SEALS="$(cat ~/.config/stackvet/allowed_signers)"`, or mount the list alone, read-only,
with `-v "$HOME/.config/stackvet/allowed_signers":/sv-config/stackvet/allowed_signers:ro -e XDG_CONFIG_HOME=/sv-config`.
For the container your AI coding tool starts, the guide (`docs/GETTING-STARTED.md`, step 5) gives the whole `.mcp.json`.

## Signing in

`sv run` asks the running app questions as somebody who has not signed in — and, when
`stackvet.toml` says how, as signed-in users too. Under `[stack.run.users]` you say how accounts are
made (a `seed` command run inside the app's container, or the app's own `signup`), how to sign in and
out, which pages are private or admin-only, and how one user creates something another must not read.
`sv` makes two ordinary accounts and, if you list admin pages, an admin, each with a password made for
that run, and then asks, among other things:

- can somebody who has not signed in open a private page? (V8.2.1)
- can an ordinary user open an admin page? (V8.2.1)
- can one user find, read, change or delete what another created? (V8.2.2; finding it on the private pages and
  at `list`, and changing and deleting it with `update` and `delete`, all under `owned`. When only reading was
  tried, it is *checked in part*, never *checked*. A change or deletion that was refused counts only when the
  owner's own request does change or delete their record, so a request that never reached a route is not taken
  for a refusal.)
- does a private page let another website read it, with the user signed in? (V3.4.2; only ever a finding)
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
- given an address outside the app as `next` (and eight other common return parameters), do sign-in and
  sign-out send the browser there? (V3.7.2; only ever a finding)
- with `change-password` set: can the password be changed, and does that need the current one?
  (V6.2.2, V6.2.3)
- with `change-email` and `signup` set: does changing the email address need the password again? (V7.5.1;
  only ever done to an account made for it)
- with `owned` set and `requests-per-minute` under [policy]: when one user creates one record more than
  that in a minute, is the last one refused? (V2.4.1)
- with `once` set: does an action that should go through once (booking the last seat, redeeming a
  one-time code) go through for two people when sent 20 times at the same instant, half by each of two
  test users? (V2.3.4)
- with `delete-account` and `signup` set: does deleting an account end its other sessions? (V7.4.2;
  only ever done to an account made for it)
- is there a password hint or secret question on the sign-up or sign-in page? (V6.4.2; only ever a
  finding)
- with `uploads` set: are files too large, of the wrong kind, or compressed beyond the limits you state
  refused? (V5.2.1, V5.2.3, and others)
- with a password reset, sign-in codes sent by email, or a code from an authenticator app (`totp`) set: can a
  reset or a code be used twice, or a code guessed? (V6.4.3, V6.5.1, V6.6.3, and others; the run gives the app a
  mail server of its own to read the emails from)

When `signup` is set, `sv` also signs up through it, whether or not `seed` made the test users, and
asks what passwords the app accepts: one of 7 characters (V6.2.1), one of lowercase letters alone
(V6.2.5), three common ones, beside a random one of the same shape (V6.2.4; all three must be
refused), one far down the common list that is known to be in breaches (V6.2.12), and one of 83 characters
(V6.2.9), which is then tried with only its first 72, and the strong one with its capitals swapped, to
see that the password is checked exactly as typed (V6.2.8). Each is compared with an
ordinary strong password signed up first, and whether a password was accepted is told by signing in
with it.

Each question first shows the thing it depends on actually worked — the session opens a private page,
the owner can read back what they made, the admin can open the admin page — and when it cannot show
that, the answer is *not assessed*, not a pass. `examples/notes-with-users` is a complete example.

## Building an app from scratch with `sv` alongside

If you are not a programmer and want to build an app with an AI coding tool, start with
[`docs/GETTING-STARTED.md`](docs/GETTING-STARTED.md): installing Docker, connecting StackVet to your
tool, a prompt to start the build with, what is and is not checked, and how to build `sv` on your own
computer for `sv report --run`, step by step.

## Rules your AI coding tool follows while it codes

`sv rules ./my-app` writes a short set of security rules into the app's `AGENTS.md`, the file many AI
coding tools read before they work in a folder: keep keys and people's data out of the chat, treat web
pages, issues, and tool results as data rather than instructions, run the check after each feature,
add only packages that really exist, never merge or deploy its own work, and write CI workflows that
keep secrets away from code from forks. Each rule names the requirement it comes from. Rules about
something your `stackvet.toml` says the app does not have, such as a CI pipeline, are left out, and
the file says how many. Anything else in `AGENTS.md` is left as it is: `sv` writes only between its
own two markers, and running it again replaces only that section. `--print` shows the rules instead
of writing them. From inside the tool, `stackvet_guidance` gives the same rules, for one topic or
all of them.

The rules are instructions for the tool, not a check. Following them is not evidence that the app
meets anything, and no requirement in the report changes because of them. The report keeps the
Appendix C requirements nothing has reached out of its headline numbers, in a section of their own,
"How the app is built with AI", which lists each one and says whether it is given to your tool as a
rule, is your decision, or is reached by nothing in `sv`.

**Where they come from.** The rules are adapted from
[OWASP AI Security Verification Standard (AISVS) 1.0, Appendix C: AI-Assisted Secure Coding](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x92-Appendix-C_AI_for_Code_Generation.md),
by the OWASP AISVS project and its contributors, licensed under
[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). Its requirements were rewritten as
instructions for an AI coding tool, and only those a coding tool can act on while it writes code are
included (18 rules, drawn from 27 of its 68 requirements; the owner's decisions among the rest are asked
through `sv questions` and the security notes). Every copy `sv` writes carries this credit and the license, and the adapted text is
shared under the same license. It does not reach your app's own code.

If your tool reads another file instead of `AGENTS.md` (Claude Code reads `CLAUDE.md`, for example),
point that file at it; for Claude Code, a line `@AGENTS.md` in `CLAUDE.md` should do it. Neither that
nor which tools read `AGENTS.md` on their own has been tried here yet.

## A zip to keep or hand on

`sv bundle ./my-app` writes one zip beside the app folder (`--out FILE.zip` puts it elsewhere, but never inside the app):
the app's files under `app/`, the report and the list of what the app ships under `report/`, a `BUNDLE.json` with which
`sv` made it, when, and a SHA-256 for every file, and a `README.txt` in plain words. It takes the same `--run`, `--tools` and
`--advisories` options as `sv report`.

**It leaves out anything that could hold a secret, and says so.** Left out, and listed with the reason in the zip and on
the screen: any file the credential scan flagged; environment files (`.env` and `.env.*`, but not `.env.example`); files named
like key stores or credential files (`.pem`, `.key`, `id_rsa`, `.npmrc`…); database files (`.sqlite`, `.db`…); links, which can
lead outside the folder; editor folders, which can hold a token; and any file the credential scan could not read, other than
plain images and fonts. What it cannot do: tell which files hold data about the app's people. It leaves out the database files
it recognizes by name and nothing else, so look through the zip before you hand it on. The zip is written stored (not
compressed) by `sv` itself, so it adds no dependency.

## From inside your AI coding tool

`sv mcp` offers the same checks over the Model Context Protocol, so the tool you build with can run them
mid-conversation and work through the findings with you. Install it once (`sh tools/install.sh`, which
builds it and puts it with its data in `~/.local/share/stackvet`, linked from `~/.local/bin/sv`), then
register it — for Claude Code:

```bash
claude mcp add stackvet -- ~/.local/bin/sv mcp --root ~/code
```

or, for a tool configured with JSON:

```json
{ "mcpServers": { "stackvet": { "command": "/path/to/sv", "args": ["mcp", "--root", "/home/you/code"] } } }
```

It offers thirteen tools: `stackvet_spec` (the `stackvet.toml` to write), `stackvet_plan` (the plan for the
app from it, below), `stackvet_preflight` (what `sv run` will need, read from the code without running it),
`stackvet_before` (one feature's brief before it is built, below), `stackvet_guidance` (the
rules to follow while coding; see "Rules your AI coding tool follows while it codes" above),
`stackvet_prompts` (prompts from [the prompt library](docs/PROMPTS.md), each saying whether it has been shown to
work; `sv prompts`, or `sv prompts --requirement V1.2.4`, prints them at a terminal; the ten coding prompts shown to
work are also given in full at the end of `sv init`, `stackvet_spec`, and the server's opening instructions, since
a prompt given where the tool starts did better than the same prompt fetched mid-build),
`stackvet_check` (what
applies, what was found, and first of all what was not examined), `stackvet_explain` (a requirement in
its framework's own words), `stackvet_write_report` (the full reports, into the app's folder),
`stackvet_questions` (the questions only you can answer, for the tool to ask you one at a time), and
`stackvet_notes_file` (the `security-notes.md` your written decisions go in), `stackvet_record_answer`
(an answer written under one of those questions, always marked as the tool's own: once you have read it and agree,
you change its `Written by:` line to `owner` yourself and record it with `sv review`), and `stackvet_bundle`
(one zip beside the app, for you to keep or hand on; see "A zip to keep or hand on" above. A tool offers it when the report
is written, if you want one).

A plan or a check too long for an AI coding tool to take in as one answer (over about 40,000 characters; Claude Code
saves anything longer to a file instead of reading it) comes in parts. The first answer starts with what to act on:
for a plan, what to decide and what `sv run` needs; for a check, what was not examined and then the findings. It ends
with a list of every section and how to ask for each (`section`, and `page` for a long one). Nothing is left out, and
`"section": "all"` still gives the whole answer at once. A short plan or check is answered whole, as before.

It also offers [the design-time prompts](docs/prompts/design-time.md) as MCP prompts, for you to choose from
your tool (where it shows them, for example as slash commands): what to decide with the tool before any code is
written, each saying whether it has been shown to work. Its instructions ask the tool, for an app with no code yet, to
write `stackvet.toml` with you first, for the app as it will be, and to go through the prompt for each feature
before writing it.

**A plan before any code.** `sv plan` (and `stackvet_plan`, for the tool) turns `stackvet.toml` into a plan:
the requirements that will apply, the design-time prompts and questions to settle before each feature, the tests
worth writing (named so they count once they pass), what the app must give `sv run` so it can be tested running
(test accounts, the sign-in and sign-out forms, the pages only a signed-in person should see, and so on, worked out
from your answers), and the threats your answers raise. It needs no code, writes nothing, and credits nothing: a plan
is what the app will be held to, not evidence that anything was built. It is built from the same parts as the report,
so the two agree about what applies.

**Before each feature.** `sv brief --feature uploads` (and `stackvet_before`, for the tool) gives one feature's brief
before it is built: sign-in, sign-in through another service, admin pages, uploads, payments, email, an AI feature,
fetching a web address, records people own or share, API keys for other programs, background jobs, or several
customer organizations in one app (`sv brief` with no feature lists them). It gives the requirements the feature brings that
apply to the app now, and, if `stackvet.toml` does not say yet that the app has the feature, those that will apply
once it does; the design-time prompts for the decisions to make first, in full; the coding rules that bear on it; the
tests to write; and the settings `sv run` needs to test it, quoted from the spec. With the coding prompts shown to
work that bear on the feature, it answers before `stackvet.toml` exists too, saying that which requirements apply
cannot be known yet. Like the plan, it writes nothing and credits nothing.

**Before `--run`.** `sv preflight` (and `stackvet_preflight`, for the tool) looks in the app's files for what
`sv run` will need from `[stack.run]`: a server listening on every address at `$PORT`, a seed that makes the test
accounts, the sign-in form at the path and with the fields the settings give, the tables the app makes for itself,
and so on. Each item says *looks right*, *look at this*, or *could not tell*. It reads text and runs nothing, so
"looks right" means the thing was found, not that it works; the point is that the AI tool can fix a wrong setting in
the same conversation, before a run is spent on it. It credits nothing.

A check that takes longer than 50 seconds is stopped waiting for, and the tool is told it did not finish and that
nothing was assessed, rather than being left waiting. Checking this whole repository takes about six seconds.
`--time-limit SECONDS` changes the limit, and `sv report` at a terminal has none. A tool that asks to hear how a check
is going is told each stage as it starts.

A `.mcp.json` in the app's folder, with the JSON above, works in tools that have no `claude` command,
such as the Claude desktop app.

### Without installing Rust: the container

`sv` is published as an image, so the only thing to install is Docker (on a Mac, Docker Desktop or
Colima):

```bash
docker pull ghcr.io/abbyshade111/stackvet-sv
```

It is built from the `Dockerfile` by CI on every change to `main`, once the image has passed its
test, and tagged `latest` and with the commit it came from. To build it yourself instead, from the
repository root: `docker build -t ghcr.io/abbyshade111/stackvet-sv .`

Until 9 October 2026 the product was called SecureVibe and the image was `ghcr.io/abbyshade111/securevibe-sv`.
That name is left as it is and gets no further pushes; the files `sv` wrote under the old names (`securevibe.toml`,
`securevibe-report`, `~/.config/securevibe`) are still read, and the report says once what to rename
(`docs/adr/ADR-062.md`).

Then the tool starts it in its `.mcp.json`. Use your own folder in all three places, and the full path
to `docker`, since an app started from the Dock often cannot see `/opt/homebrew/bin`:

```json
{ "mcpServers": { "stackvet": {
  "command": "/opt/homebrew/bin/docker",
  "args": ["run", "-i", "--rm", "--network", "none",
           "-v", "/Users/you/code:/Users/you/code",
           "ghcr.io/abbyshade111/stackvet-sv", "mcp", "--root", "/Users/you/code"] } } }
```

- The folder is mounted at the same path inside, so the paths in findings are your own.
- `--network none` means the container has no network at all, so the promise that `sv` opens no
  connection is enforced rather than only kept.
- On Linux, add `"--user", "1000:1000"` (your own `id -u` and `id -g`) before the image name, so the
  files it writes are yours. Without it the image runs as a user of its own, never root, and that user
  cannot write into your folder. On a Mac, Docker Desktop makes what it writes yours either way.
- Docker (or Colima) has to be running when the tool starts, or the stackvet tools are simply absent.
- The container never runs `sv report --run`: starting the app means starting containers, which from
  inside a container would mean handing it control of Docker on your machine. Run that step with a
  native `sv` at a terminal.

`tools/image_smoke.py` drives the image as an AI tool would, and CI runs it on every change.

Two limits are deliberate. It only reads apps under the folder given to `--root`; a path outside it is
refused, `..` and symbolic links included. And it never starts your app or runs other people's security
tools — each of those runs code, and that stays your decision at a terminal (`sv report --run --tools`).
The results say both were not done, the same way the written report does.

## Building

Rust 1.95 or newer.

```bash
cargo test
```

The OWASP data files (`data/frameworks`, `data/knowledge`) and `sv`'s own data files live together in `data/`.
`sv` looks for that folder in `SV_DATA_DIR`, then beside itself (`data`, or `../share/stackvet/data`), then
in the repository it was built from; `sv --version` names the one it uses.

To contribute, read [CONTRIBUTING.md](CONTRIBUTING.md): the checks a change must pass and the rules every change
keeps. Taking part means agreeing to the [code of conduct](CODE_OF_CONDUCT.md); a security problem in `sv` itself
goes through [SECURITY.md](SECURITY.md), not a public issue.

## Reading order

The design record, one dated entry per file in `docs/design/` (`docs/DESIGN.md` says how it is kept), explains the two changes from v1 (the design was written when the two were side by side), why deleting the wizard was the hard part, and what the
first run against real data turned up.
