# The deep review of `sv` at `eff3f17`, part 2 of 3: honesty, false cleans and coverage overclaims (H1 to H25)

**Status:** partly done: see its done note; what remains is not yet written, as its markers read on 8 October 2026

Same sender, method, and labels as part 1. **Each item can be claimed on its own.** The sender's order:
H1 to H5, then H12 to H15, then H8 to H11.
- **H1. High, Reproduced.** `ast.sql-built-by-hand` misses the usual injection calls in five languages yet marks
  V1.2.4 checked: sinks are a short name list and only the first argument is matched (better-sqlite3, sqlite3,
  Prisma `$queryRawUnsafe`; `mysqli_query($conn, ...)`, PDO `prepare`; `prepareStatement`, Spring `jdbc.query*`;
  `new SqlCommand`; Ruby `where("...#{x}")`; `pd.read_sql(f"...")`). Nine real injections gave none. Fix: sinks
  and the SQL argument's position per language; until then name the calls in the clean claim.
  **Claimed on 4 October 2026 by session securevibe-e9**, at the owner's asking, in branch
  `claude/securevibe-e9-h1`.
  **Done the same day** (DESIGN, "The query calls each language really uses"): the review's nine injections, through
  better-sqlite3, node-sqlite3, Prisma, mysqli, PDO, JDBC, Spring, `new SqlCommand`, Dapper, Active Record, and
  pandas, are each found, and each one's safe form is not. `argumentPositions` reaches past PHP's and C#'s argument
  wrappers, and a new `argumentsForCommonNames` reports `get`, `all`, `run`, `update`, and their like only when what
  they are given looks like SQL. The clean claim now says it covers the usual libraries' query calls.
- **H2. High, Reproduced.** Code in Svelte and Vue templates is never read, yet the page counts as read
  (`on:click={() => eval(code)}` gave none, V1.3.2 checked). Fix: read `{...}`, `on:*`, `@*`, `v-*`, `:*` as code,
  or mark the page left behind.
  **Claimed on 4 October 2026 by session securevibe-e10**, with H6, at the owner's asking to work through the
  review's open items, in branch `claude/h6-h2`: first, a page whose template holds code no longer counts as read;
  then, if it fits, that template code read as code.
  **First step done the same day** (DESIGN, "Folders left out, report markers, and templates sv cannot read"): a
  `.svelte` page with any `{...}` outside its `<script>` and `<style>`, or a `.vue` page with `{{ }}` or an `@`, `:`,
  or `v-` attribute, is named among the files not fully read. Four guards broken in turn, each caught. (This
  said no rule is then credited a clean result for the page. That was wrong, corrected in the rest below: naming
  the page did not hold the rules back.) **Still open:** reading that template code as code, so `on:click={() =>
  eval(code)}` is found rather than only owned up to.
  **The rest claimed on 4 October 2026 by session securevibe-e10**, at the owner's asking, in branch
  `claude/h2-template-code`: Svelte's `{...}` and Vue's `{{ }}` and directive values read as JavaScript or
  TypeScript, so the rules look at them; a page whose template code cannot be taken out stays named as not fully
  read.
  **Done the same day** (DESIGN, "Svelte and Vue template code read as code"): every Svelte `{...}` (expressions,
  `{#if}`, `{#each}` and its key, `{#await}`, `{@html}`, `{@const}`, spreads, and Svelte 5's `onclick={...}`) and
  every Vue `{{ }}`, `@`, `v-on:`, `:`, `v-bind:`, `v-if`, `v-for`, `v-html`, slot, and other `v-` value is read as
  JavaScript, or TypeScript when the page's script is, and `on:click={() => eval(code)}` is found on its line. A
  template that cannot all be taken out or read now holds back each rule whose call it names, which the first step
  claimed and did not do. **Not read:** Vue templates in Pug or another language, and directives whose names are
  worked out when the page runs; such a page is named as not fully read.
- **H3. High, Reproduced.** The credential-assignment rule (`secrets.rs`) misses most real shapes: a JSON or dict
  `"password": "..."`, `=>`, `:=`, typed declarations, unquoted YAML, `getenv("X", "<default>")`.
  **Claimed on 4 October 2026 by session practical-banach**, at the owner's asking to take an unclaimed item, in
  branch `claude/h3-credential-shapes`.
  **Done the same day** (DESIGN, "The credential rule reads the shapes credentials are written in"): JSON and dict
  keys, `=>`, `:=`, typed declarations in TypeScript, Kotlin, Swift, Rust, and Go, unquoted values in YAML,
  `.properties`, and `.ini`, and defaults given to environment settings in Python, Ruby, Node, and PHP. What only
  the new shapes find is passed over when it is text, a path, or a lower-case identifier: 90 false alarms in v1's
  `node_modules` without that, none with it. Nothing found before is lost. Twenty-four guards broken in turn, each
  caught. Not done: a passphrase with spaces written as a JSON value, and unquoted shell and Dockerfile lines.
  **The two left claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking to pick another item,
  in branch `claude/securevibe-e9-h3-rest`: unquoted values in shell scripts and Dockerfiles (`export TOKEN=…`,
  `ENV DB_PASSWORD …`), and a passphrase with spaces as a JSON value, if a way to read it can be shown not to bring
  the message catalogs back.
  **Done the same day** (DESIGN, "A shell script's and a Dockerfile's unquoted values are read; a JSON passphrase
  is still not"): `NAME=value` in shell scripts (with `export` and the like, and before a command) and `ENV` and `ARG`
  in Dockerfiles are read. The JSON passphrase was measured and left: of 201 values with spaces under credential
  names in this repository, its `node_modules`, and v1's code, none is a passphrase, and the narrowest reading tried
  still takes in 11 messages; nothing tells them apart.
- **H4. High, Reproduced.** A workflow started by `issue_comment` that checks out the pull request's code with
  secrets is credited AC.12.1 (`workflows.rs` PRIVILEGED_TRIGGERS). Fix: add `issue_comment`,
  `pull_request_review_comment`, `discussion_comment`, and dispatch events that take a ref.
  **Claimed on 4 October 2026 by session securevibe-e2**, at the owner's asking to continue with the backlog, in
  branch `claude/securevibe-e2-comment-triggers`.
  **Done the same day, in part** (DESIGN, "Workflows a comment can start"): `issue_comment` and
  `discussion_comment` are privileged triggers now, so the comment bot that checks out the pull request with the
  secrets is found, not credited. Not added: the dispatch events, which only somebody with write access or a token
  can start; and `pull_request_review_comment` and `pull_request_review`, **still open**: whether GitHub gives them
  the secrets for a pull request from a fork could not be checked, since GitHub's documentation was not reachable
  from the session. Three guards broken in turn, each caught.
  **The rest claimed on 5 October 2026 by session securevibe-e10**, at the owner's asking, in branch
  `claude/h4-review-triggers`: check against GitHub's documentation whether `pull_request_review` and
  `pull_request_review_comment` run with the secrets for a pull request from a fork, and make them privileged
  triggers if they do, or say in DESIGN why not if they do not.
  **Done the same day** (DESIGN, "The review triggers run as `pull_request` does"): GitHub's documentation says both
  run on the pull request's merge branch and, for a pull request from a fork, get no secrets but a read-only
  `GITHUB_TOKEN`, as `pull_request` does. They are not privileged, and `sv`, which already judged them as
  `pull_request`, now says why and holds it with a test; two guards broken in turn, each caught.
- **H5. High, Reproduced.** Next.js and modern Node redirect and file calls are missed (bare `redirect()`,
  `NextResponse.redirect`, `window.location = ...`, `fs/promises` `readFile`, `fs.promises.readFile`), but
  TypeScript coverage is claimed.
  **Claimed on 4 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
  `claude/h5-next-node-sinks`.
  **Also claimed on 5 October 2026 by session securevibe-e9**, in branch `claude/securevibe-e9-h5`: the earlier
  claim reached `main` after this session had checked the backlog, so both took it. securevibe-e9's was built and
  tested first, and the owner chose it on 5 October 2026; the cato-pipeline session's branch had nothing pushed.
  **Done the same day** (DESIGN, "Redirects and file calls the way Next.js and modern Node write them"): every
  form the review named is found, Next.js's bare `redirect` and `NextResponse.redirect`, the browser's
  `location` assignments and calls, `fs.promises.readFile`, and the bare `fs/promises` calls; a same-site path,
  `new URL('/path', request.url)`, and an app's own function named `download` are not.
- **H5 follow-up: five differences from a second build of H5** (the cato-pipeline session's
  `claude/h5-next-node-sinks`, closed unmerged as #642), ported onto #641's rules at the owner's asking:
  (a) `new URL("/path", base)` is safe only when the base is the request's own address (`request.url`, `req.url`,
  `request.nextUrl`), so `new URL("/path", userInput)` is reported; (b) `permanentRedirect()`, `Response.redirect`,
  Express's `res.location`, `document.location` (and `self` and `top`), and SvelteKit's status-first
  `redirect(303, x)`; (c) a bare `location.replace(...)` on a name called `location` is not reported, since a string
  has a `replace` too, while `window.location.replace(x)` still is; (d) `process.cwd()`, `import.meta.dirname`, and
  `new URL('./x', import.meta.url)` accepted as the app's own folder by the file-path guard; (e) the clean result's
  words for JavaScript and TypeScript naming the calls each rule reads.
  **Claimed on 5 October 2026 by the cato-pipeline session**, at the owner's asking, in branch `claude/h5-follow-up`.
  **Done the same day** (DESIGN, "Redirects and file calls the way Next.js and modern Node write them", its
  "Later, 5 October 2026" paragraph): all five. `new URL("/login", req.query.next)` is now found where it was a clean
  result; a string's `location.replace(...)` is no longer reported; the redirect query names its object and call
  together, so the name pattern stays plain words for H25. Forty witnesses (eighteen of them fail on #641's rules)
  and a clean-result test; eleven guards broken in turn, each caught. Nothing #641 chose was undone.
- **H6. High, Reproduced.** Folders with ordinary names (`build`, `out`, `dist`, `vendor`, `coverage` at any depth)
  or holding a `.securevibe-report` marker are silently left out of every check, and an AI tool can plant the
  marker through MCP `write_report`. Fix: record skipped folders; accept the marker only when it proves `sv` wrote
  it; skip build folders only where an ecosystem puts them.
  **Claimed on 4 October 2026 by session securevibe-e10**, with H2, at the owner's asking to work through the
  review's open items, in branch `claude/h6-h2`, for all three parts of the fix.
  **Done the same day** (DESIGN, "Folders left out, report markers, and templates sv cannot read"): `target`,
  `vendor`, `dist`, `build`, `out`, and `coverage` are left out only beside the manifest that explains them (for
  example `vendor/` beside `composer.json` or `go.mod`); anywhere else they are the app's code and are read. Every
  folder left out is named in `sv check`'s output and as a gap in the report. A report marker is believed only in a
  folder that holds nothing but the files `sv` writes, so a marker planted beside code leaves the code read, and
  `sv check` says the marker was refused. Six guards broken in turn, each caught.
- **H7. High, Reproduced.** Bandit skipped a file it could not parse and the clean result was credited: SARIF
  `toolConfigurationNotifications` and `executionSuccessful` are ignored.
  **Claimed on 4 October 2026 by session securevibe-e10**, with S7, in branch `claude/s7-h7-bandit`.
  **Done the same day** (same DESIGN section): a tool's SARIF that marks its run unsuccessful, or names an
  error-level problem in `toolExecutionNotifications` or `toolConfigurationNotifications`, keeps the run from
  counting as clean, for every outside tool; the findings stand, and the report names up to five problems.
- **H8. High, Reproduced.** PyPI names are not normalized (PEP 503) in the advisory comparison: `jupyter_server`
  never matches `jupyter-server`. A normalizer exists in `manifest_lock.rs`.
  **Claimed on 4 October 2026 by session securevibe-e2**, with H8, H10, and H11, at the owner's asking to continue
  with the backlog, in branch `claude/securevibe-e2-advisory-match`.
  **Done on 4 October 2026** (DESIGN, "Advisories: Python names, nested npm copies, and declared packages"):
  PyPI names are compared through `manifest_lock::python_name`, the normalizer already there.
- **H9. High, Reproduced.** Pipenv apps (`Pipfile` and `Pipfile.lock` only) are invisible, yet the advisories ran
  and V15.2.1 was credited. Also detect `setup.py`, `setup.cfg`, `requirements*.txt`, at least as unread.
  **Claimed on 4 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
  `claude/h9-pipenv`.
  **Done the same day** (DESIGN, "Pipenv apps, and Python dependency files `sv` does not read"): `Pipfile` is a
  manifest with `Pipfile.lock` its lockfile, read from every section, with a package that has no version named
  rather than dropped (H21, for this reader only); a `Pipfile` alone lists its exact pins as asked for and names
  the rest; `setup.py`, `setup.cfg`, other requirements files, and Conda's `environment.yml` are found and named
  as unread (a hashed requirements file is read), so V15.2.1 is not credited and `sv audit` and the report say
  which file and why. Tested end to end with Django 2.2.0 found through `Pipfile.lock`, a clean Pipenv app
  credited, and five not-credited cases; eleven guards broken in turn, each caught. Still open: a range in a
  `requirements.txt` without a lockfile is left out unnamed, and a `setup.py`-only app is not called unpinned.
  **The rest claimed on 5 October 2026 by session securevibe-e10**, at the owner's asking, in branch
  `claude/h9-ranges-and-setup-py`: a requirement given as a range is named as not checked against the advisories,
  and an app whose Python dependencies are declared only in `setup.py` or `setup.cfg` is said to have none pinned.
  **Done the same day** (DESIGN, "What a `requirements.txt` leaves out is named, and a `setup.py` with no lockfile
  does not pin"): a `requirements.txt` read without a lockfile names everything it installs that it does not pin to
  one version (ranges, bare names, wildcards, addresses, folders, and files pulled in with `-r`), read as pip reads
  it; and a `setup.py` or `setup.cfg` that names packages, with no Python lockfile in its folder, is reported by the
  pinning check (V15.1.2) and in the scan's list of unpinned projects. Twelve guards broken in turn, each caught.
  **Still open:** a requirements file under another name without hashes is not judged by the pinning check, and a
  `Pipfile.lock` with no `Pipfile` beside it is not found.
  **These two claimed on 6 October 2026 by session securevibe-e2**, at the owner's asking to continue with the
  backlog, in branch `claude/securevibe-e2-h9-rest`.
  **Done the same day** (DESIGN, "A lone `Pipfile.lock`, and requirements files under other names"): a `Pipfile.lock`
  with no `Pipfile` or `requirements.txt` beside it is a Python project of its own, read for the bill of materials,
  the advisories, and the pinning check; a requirements file under another name is judged by the pinning check, as
  its own lockfile when every package in it is pinned and hashed and as pinning nothing otherwise, whatever lockfile
  is beside it. Eleven guards broken in turn, each caught.
- **H10. High, Reproduced.** npm lockfile v1 is read only at the top level; nested copies are dropped.
  **Claimed on 4 October 2026 by session securevibe-e2**, with H8, H10, and H11, at the owner's asking to continue
  with the backlog, in branch `claude/securevibe-e2-advisory-match`.
  **Done on 4 October 2026** (same DESIGN section): a lockfile v1 is read at every depth.
- **H11. High, Reproduced.** V15.2.1 is credited while the package list is incomplete (`complete_enough` ignores
  declared-only packages). Fix: require `sbom.is_complete()`.
  **Claimed on 4 October 2026 by session securevibe-e2**, with H8, H10, and H11, at the owner's asking to continue
  with the backlog, in branch `claude/securevibe-e2-advisory-match`.
  **Done on 4 October 2026** (same DESIGN section): `complete_enough` requires `sbom.is_complete()`.
- **H12. High, Read.** A plain-HTTP redirect to plain HTTP, or to a relative path, is credited as sending the
  browser to HTTPS (V12.2.1). Fix: only an absolute `https://` on the same host.
  **Claimed on 4 October 2026 by session securevibe-e2**, with H12 and H13, at the owner's asking to continue with
  the backlog, in branch `claude/securevibe-e2-https-redirect-hsts`.
  **Done on 4 October 2026** (DESIGN, "HTTPS redirects and HSTS, held to what they say"): only a redirect to an
  absolute `https://` address on the same host is credited; any other redirect is not assessed.
- **H13. High, Read.** HSTS is credited whatever its value, `max-age=0` included, even on error answers (V3.4.1).
  **Claimed on 4 October 2026 by session securevibe-e2**, with H12 and H13, at the owner's asking to continue with
  the backlog, in branch `claude/securevibe-e2-https-redirect-hsts`.
  **Done on 4 October 2026** (same DESIGN section): credited only for a max-age of a year or more with
  includeSubDomains, read as a browser reads it, and only on an ordinary answer.
- **H14. High, Read.** The invented-session check alters whichever cookie came first, often the anti-forgery one,
  and credits V7.2.1. Fix: alter only a cookie set at sign-in, keep the rest, with a control.
  **Claimed on 4 October 2026 by session securevibe-e2**, at the owner's asking to continue with the backlog, in
  branch `claude/securevibe-e2-session-cookie`.
  **Done the same day** (DESIGN, "A made-up session changes the session cookie, and only that"): each cookie set
  at sign-in gets a made-up value, every other cookie is kept, and the real session is sent just before as the
  control. Five guards broken in turn, each caught.
- **H15. High, Read; triggers plausible.** The burst treats any 4xx as a limit (V2.4.1), and the upload checks
  credit any refusal: a duplicate-value 409, a single-use token, or a quota earns credit. Fix: require 429 (or 503
  with `Retry-After`), a unique marker and a fresh token per request, and a control just before each credited
  refusal.
  **Claimed on 4 October 2026 by session securevibe-e2**, at the owner's asking to continue with the backlog, in
  branch `claude/securevibe-e2-refusals-that-count`.
  **Done the same day** (DESIGN, "A refusal is credited only for the reason it is about"): the burst gives each
  record its own marker and credits only a 429, or a 503 with `Retry-After`; each upload has a fresh token and its
  own marker, and a refusal is credited only when an ordinary file is accepted straight after it. Seven guards
  broken in turn, each caught.
- **H16. Medium, Plausible.** Brute-force (V6.3.1) and code-guessing (V6.6.3) credit rests on one timing sample
  that includes `docker exec`'s own time.
  **Claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking, in branch
  `claude/securevibe-e9-h16`.
  **Done the same day** (DESIGN, "A delay counts only when every attempt past the limit shows it"; ADR-021, Later):
  the quickest attempt within the limit is the baseline, both attempts past it must be markedly slower, the
  sign-in page is timed beside them as a control, and times that disagree are not assessed.
- **H17. Medium, Read.** The error-page leak check (V13.4.2, V16.5.1) is credited after reading only the first
  4,000 characters. Fix: search the whole answer before cutting it.
  **Claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking, in branch
  `claude/securevibe-e9-h17`.
  **Done the same day** (DESIGN, "An error page is searched whole before it is cut"): the whole answer is searched
  for each sign of a stack trace, and the text around any found past the first 4,000 characters is kept, so the
  check sees it; a long page with no trace is still credited.
- **H18. Medium, Reproduced.** OSV range events are read in file order, not version order (PYSEC-2024-265 reports
  1.2.1 clean; 86 real ranges are out of order). Fix: sort by version; ties give "could not compare".
  **Claimed on 4 October 2026 by session securevibe-e2**, with H18, H19, and H20, at the owner's asking to continue
  with the backlog, in branch `claude/securevibe-e2-advisory-versions`.
  **Done on 4 October 2026** (DESIGN, "Advisory versions: in order, gaps kept, gems as gems"): a range's events are
  read in version order; two at one version are not compared.
- **H19. Medium, Read.** A matching advisory clears the "could not compare" flag earlier advisories left.
  **Claimed on 4 October 2026 by session securevibe-e2**, with H18, H19, and H20, at the owner's asking to continue
  with the backlog, in branch `claude/securevibe-e2-advisory-versions`.
  **Done on 4 October 2026** (same DESIGN section): the could-not-compare is kept per advisory.
- **H20. Medium, Reproduced.** RubyGems platform versions (`1.15.4-x86_64-linux`) are compared as semver.
  **Claimed on 4 October 2026 by session securevibe-e2**, with H18, H19, and H20, at the owner's asking to continue
  with the backlog, in branch `claude/securevibe-e2-advisory-versions`.
  **Done on 4 October 2026** (same DESIGN section): the platform is taken off a gem's version, and RubyGems
  versions are compared by `Gem::Version`'s rules.
- **H21. Medium, Read.** Packages with no version are dropped silently from `Pipfile.lock`, pnpm v9, and Yarn,
  and the list still counts as complete. Fix: name them as unread, as the `pylock.toml` reader does.
  **`Pipfile.lock` done with H9 on 4 October 2026**: its packages with no version are named. pnpm v9 and Yarn
  are still open.
  **Claimed on 5 October 2026 by session securevibe-e2**, with H21 and H24, at the owner's asking to continue with
  the backlog, in branch `claude/securevibe-e2-lockfile-gaps`.
  **Done the same day** (DESIGN, "pnpm 5 and 6 told apart, and packages without a version named"): pnpm v9 and
  Yarn name their packages with no registry version as not listed, as `Pipfile.lock` and `pylock.toml` do.
- **H22. Medium, Reproduced.** One image or binary file leaves the credential scan for ever partial, and text that
  is not UTF-8 (UTF-16, Latin-1) is never read, by any code rule either.
  **Seen in my-first-app on 4 October 2026** (added the same day by the cato-pipeline session, usability analysis
  for `docs/paper`): the one file was a Finder `.DS_Store`. The report's gap says only "1 file not read while
  looking for credentials" (`crates/sv-cli/src/main.rs`, lines 3344 to 3356), without the name or the reason, so
  the AI tool searched for large files and then ran `sv check` to learn it was `.DS_Store — not a text file`. A
  fix could name the files and why in the report, and say plainly when a file is one that holds no text a
  person writes, such as `.DS_Store`, so nobody chases it.
  **Claimed on 5 October 2026 by session securevibe-e2**, at the owner's asking to continue with the backlog, in
  branch `claude/securevibe-e2-files-not-text`.
  **Done the same day** (DESIGN, "Files that are not text named, and text that is not UTF-8 read"): text in UTF-16,
  with its mark or without, and in Latin-1 is read; an image, a font, or a `.DS_Store`, known by its contents, is
  named as holding no text a person writes and no longer keeps the credential scan partial; and the report's gap
  names each file not read, and why.
- **H23. Medium, Reproduced.** The `.gitignore` check fails on `/.env` and passes on `.env` followed by `!.env`;
  `.well-known/security.txt` and other spellings are not recognized.
  **Claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking, in branch
  `claude/securevibe-e9-h23`.
  **Done the same day** (DESIGN, "A .gitignore read the way git reads it, and a security contact however it is
  spelled"): `/.env` passes, `.env` then `!.env` fails, and `.env.*` alone, which git does not apply to `.env`
  and which used to pass, now fails; a `SECURITY` file in any spelling at the root, in `.github/` or `docs/`, and a
  `security.txt` in `.well-known/` (also under `public/` or `static/`) or at the root count as a contact.
- **H24. Medium, Reproduced.** pnpm lockfile v6.0 (`/name@version`) is not read; the "v6" test uses v5's format.
  **Claimed on 5 October 2026 by session securevibe-e2**, with H21 and H24, at the owner's asking to continue with
  the backlog, in branch `claude/securevibe-e2-lockfile-gaps`.
  **Done the same day** (same DESIGN section): the reader takes the lockfile's own version line, and reads 6.0's
  `/name@version` and 5.x's `/name/version`; the "v6" test now uses v6's format, and 5.x has a test of its own.
- **H25. Low to medium, Read.** One parse error in any file silences every code rule for the whole app.
  **Claimed on 4 October 2026 by session securevibe-e9**, at the owner's asking, in branch
  `claude/securevibe-e9-h25`.
  **Done the same day** (DESIGN, "A broken file holds back only the rules it could hide something from"; ADR-018,
  Later): a file that did not parse cleanly now holds back only the rules whose call it names anywhere, judged
  word by word and only for name patterns made of words; everything else is held back as before.
