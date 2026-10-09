# From the gap analysis of 7 October 2026: findings for any session to pick up

**Status:** partly done: 22 of 34 parts done, 1 claimed, 10 open, as its markers read on 8 October 2026

Asked for by the owner on 7
October 2026 ("please include everything else on the backlog for other sessions to pick up as they can"). Each
numbered item is one finding of `docs/GAP-ANALYSIS.md`, by its section number there, where the evidence is;
**each can be claimed on its own**, in this file, before it is started. The four the owner chose to do first are
listed apart, below this item.
1. **V1.2.4 is credited for apps that build queries through an ORM.** (`docs/GAP-ANALYSIS.md`, 1.4.) Read each
   ORM's raw-query calls (GORM `Raw`/`Where` with built text, TypeORM, knex `whereRaw`, Laravel
   `DB::select`/`whereRaw` as static calls, Django `.extra`/`RawSQL`, Supabase filter strings, MongoDB `$where`),
   and do not credit V1.2.4 while the bill of materials shows an ORM whose raw calls the rule does not read. The
   second half changes what counts as evidence: a record (ADR-018, Later).
   **The second half claimed 9 October 2026 by session securevibe-e2**, from the roadmap (Phase 4, item 4, the first
   open finding in its list), in branch `claude/securevibe-e2-orm-held-back`: a rule may name, per ecosystem, the
   packages whose own query calls it does not read (a new `AstRule` field, listed in `data/README.md`), and while the
   bill of materials shows one, the rule's credit is held back with a reason that names the package, as a broken file
   holds back the rules it could hide something from. `ast.sql-built-by-hand` names the ORMs this finding lists whose
   raw calls it does not read today: knex, TypeORM, Sequelize, Drizzle, Mongoose and the MongoDB driver, and Supabase's
   client (npm); Django, PyMongo, and Supabase's client (Python); GORM and the MongoDB driver (Go); and Laravel
   (PHP). Each ORM's raw calls taught later comes off the list in the pull request that teaches them; the first
   half stays open. **`Status: proposed`: ADR-018, Later, 9 October 2026** (a requirement is not credited from a
   rule that cannot see how the app builds its queries). Confirmed on `main` just before this claim: V1.2.4 is
   credited for an app whose only queries go through knex's `whereRaw`, and no other session holds this finding.
   **The second half done the same day** (`docs/design/0321-a-rule-that-cannot-see-an-orm-s-queries-credits-nothing-9.md`;
   ADR-018, Later, 9 October 2026, accepted): `unreadPackages` on `ast.sql-built-by-hand`, read against the names the
   app's lockfiles list and its manifests declare, and a gap naming the package and its calls. The knex app now reads
   V1.2.4 *not verified*. Held by `crates/sv-cli/tests/orm_held_back.rs`, broken four ways. Not done: the first half,
   teaching the rule each ORM's raw calls, which takes that ORM off the list.
   **The first half's first part, knex and GORM, claimed 9 October 2026 by session securevibe-e2**, from the roadmap
   (Phase 4, item 4, this finding's open half), in branch `claude/securevibe-e2-orm-raw`: `ast.sql-built-by-hand`
   taught knex's `...Raw` calls (`whereRaw`, `orderByRaw`, and the rest) in JavaScript and TypeScript, and GORM's
   `Raw`, its clause methods (`Where`, `Or`, `Not`, `Order`, `Group`, `Having`, `Joins`, `Select`) when given text
   built in the call, and its inline conditions (`Find(&users, "id = " + id)`); each comes off `unreadPackages` only
   once every one of its calls named here is read, with a test of each, and stays on otherwise. Confirmed on `main`
   just before this claim: knex and `gorm.io/gorm` are on the list, and no other session holds this part.
   **That part done the same day** (`docs/design/0323-the-sql-rule-reads-knex-s-and-gorm-s-own-calls-9-october.md`):
   both read, both off the list, each call with a case that must be found and one that must not
   (`crates/sv-check/src/ast/orm_raw_tests.rs`). TypeORM, Sequelize, Drizzle, Mongoose and the MongoDB drivers,
   Supabase's clients, Django, PyMongo, and Laravel remain, each still holding V1.2.4's credit back.
   **The first half's second part, TypeORM, Sequelize, and Drizzle, claimed 9 October 2026 by session securevibe-e2**,
   in branch `claude/securevibe-e2-orm-npm`: TypeORM's query builder (`where`, `andWhere`, `orWhere`, `having`,
   `andHaving`, `orHaving`, `orderBy`, `addOrderBy`, `groupBy`, `addGroupBy`) and Sequelize's `literal`, each only
   when the text is built in the call, so an object of conditions or fixed text is not reported; and Drizzle, whose
   one unsafe call, `sql.raw`, the rule may already read, shown by a test before it comes off the list. `select` is
   left out: `d3.select("#" + id)` would be a false alarm in every page that draws a chart. Each package comes off
   `unreadPackages` only with a test of each of its calls. Confirmed on `main` just before this claim: all three are on
   the list, and no other session holds this part.
   **That part done the same day** (`docs/design/0324-the-sql-rule-reads-typeorm-sequelize-and-drizzle-9-october.md`):
   all three read and off the list (`crates/sv-check/src/ast/orm_npm_tests.rs`); Drizzle's `sql` template, which keeps
   values apart, is no longer a false alarm at `db.execute`. Mongoose and the MongoDB drivers, Supabase's clients,
   Django, PyMongo, and Laravel remain.
   **The first half's third part, Django and Laravel, claimed 9 October 2026 by session securevibe-e2**, in branch
   `claude/securevibe-e2-orm-django-laravel`: Django's `.extra(...)` when the text is built in the call (`%`, `+`,
   `.format(`, an f-string), and `RawSQL(...)`, a bare call the Python query does not reach today (so a bare
   `read_sql(...)` imported from pandas is read too); Laravel's `DB::select`, `DB::statement`, `DB::unprepared`, and
   `DB::raw`, static calls the PHP query does not reach today, and the `...Raw` methods (`whereRaw`, `orderByRaw`,
   `selectRaw`, and the rest), with the common names (`select`, `insert`, `update`, `delete`) reported only for text
   built with `.`, `"$var"`, or `sprintf`, so `$model->update([...])` is not. Each comes off `unreadPackages` only
   with a test of each call. Confirmed on `main` just before this claim: `django`, `laravel/framework`, and
   `illuminate/database` are on the list, and no other session holds this part.
   **That part done the same day** (`docs/design/0325-the-sql-rule-reads-django-and-laravel-9-october.md`): both read
   and off the list (`crates/sv-check/src/ast/orm_django_laravel_tests.rs`). Left on the list: Mongoose and the
   MongoDB drivers, Supabase's clients, and PyMongo, whose unsafe forms are a `$where` written into a query object or
   filter text, not a call the rule reads; the first half stays open for them.
2. **Dependencies in .NET, Dart, Swift, Elixir, and Deno are invisible, and V15.2.1 is credited anyway.**
   (`docs/GAP-ANALYSIS.md`, 1.5.) Detect `*.csproj`, `packages.lock.json`, `pubspec.yaml`/`.lock`,
   `Package.swift`/`.resolved`, `mix.exs`, and `deno.json`/`.lock` as ecosystems `sv` does not read, so they hold
   back V15.2.1's credit and the "No package manifest" message stops being wrong.
   **Claimed 8 October 2026 by session securevibe-e9** ("pick your next backlog item"), in branch
   `claude/securevibe-e9-unread-ecosystems`: each named in the bill of materials as unread, which holds back
   V15.2.1, and in the pinning check, which then cannot pass V15.1.2 either. Recorded as a Later entry on ADR-037.
   **Done the same day** (DESIGN, "Dependencies `sv` does not read are named, and hold back the credit"; ADR-037,
   Later).
3. **"Debug mode off" and "generic error messages" are credited from a 404 alone.** (`docs/GAP-ANALYSIS.md`, 1.6.)
   `probe.error-detail-leak` credits V13.4.2 and V16.5.1 from a missing page's answer. Provoke a real error
   (malformed JSON to a create request, a non-number id) and credit only when an error answer was seen and was
   clean. Changes what counts as evidence: a record.
   **Claimed 8 October 2026 by session securevibe-e9** ("pick your next backlog item"), in branch
   `claude/securevibe-e9-error-answers`: a body that does not parse, sent signed out to the routes securevibe.toml
   names and to the health path; V16.5.1 credited only from a clean error answer, V13.4.2 only from a clean server
   error. **`Status: proposed`: ADR-056.**
   **Done the same day** (DESIGN, "An error answer is credited only when the app was made to give one"; ADR-056,
   accepted).
4. **One read earns "checked" for one user reaching another's data (V8.2.2).** (`docs/GAP-ANALYSIS.md`, 1.7.) Have
   user B also open every private page and the record's list (A's marker there is a finding); optional `update` and
   `delete` templates under `[stack.run.users] owned` that B sends and A reads back; and "checked in part" wording
   in the counts for checks that rest on one sample. The wording part changes how a report concludes: a record.
   **Claimed on 7 October 2026 by session paper-facts**, at the owner's word ("go ahead with items 7 and 4"), in
   branch `claude/owned-depth`: all three parts. **`Status: proposed`: ADR-053.** Read on `main` just before this
   claim: no other session had claimed it.
   **Done the same day** (ADR-053, accepted; DESIGN, "Another user's records: lists, changes, deletions, and
   'checked in part'"): lists and private pages, `update` and `delete` judged by the owner's read-back, and
   *checked in part* as a status of its own. Not done: "checked in part" for checks other than V8.2.2 that rest on one
   sample, each to be read on its own.
5. **The coverage documents count requirements that can never be credited as "can settle".**
   (`docs/GAP-ANALYSIS.md`, 1.8.) Add a "can be credited" column to COVERAGE.md's summary, level, and chapter
   tables; label finding-only requirements "can only be found failing" in REQUIREMENTS.md; repeat the AISVS
   section's sentence about them for ASVS (`tools/coverage.py`).
   **Claimed on 7 October 2026 by session securevibe-e2**, at the owner's word ("please continue to work off the
   backlog"), in branch `claude/securevibe-e2-can-be-credited`.
   **Done the same day** (DESIGN, "The coverage documents count what can be credited"): a **Can be credited**
   column (ASVS 119 of 345, 34%; level 1, 43 of 70), the sentence for ASVS, and the label "Can only be found
   failing". Left for whoever next updates the paper's `figure-security.html`: it quotes "can settle" only.
6. **The development-server check passes `python app.py` that starts Flask's debugger.** (`docs/GAP-ANALYSIS.md`,
   1.9.) A code rule for `app.run(debug=True)`, `app.debug = True`, and Django's `DEBUG = True` (finding only), or
   have `config.development-server-started` say the script it runs decides, instead of passing.
   **Claimed on 7 October 2026 by session securevibe-e9**, at the owner's word ("pick your next backlog item
   whenever you're ready"), in branch `claude/securevibe-e9-debug-mode`. Both halves: a code rule, findings only,
   citing V13.4.2, for Python's debug switches (Flask's and Werkzeug's debugger, FastAPI's and Starlette's
   `debug=True`, `app.debug`, `app.config["DEBUG"]`, and Django's `DEBUG = True` at the top of a module) and for
   `FLASK_DEBUG=1` or `flask --debug` in shell scripts; other languages' debug switches are named as not looked for.
   And the start-command check no longer says a command that runs a script starts no development server. A rule
   that only raises findings changes no requirement's status, so no ADR is proposed.
   **Done the same day** (DESIGN, "A web framework's debug mode switched on in the code"): `ast.debug-mode-on`,
   findings only, citing V13.4.2, and the start-command check naming the file a command runs.
7. **Token-based apps get false "request from another site accepted" findings.** (`docs/GAP-ANALYSIS.md`, 2.1.) The
   forged requests in `signed_in/forgery.rs` keep the session's `Authorization: Bearer` header, which another
   website cannot send. When the session's token is not a cookie, send them without it; a refusal then means
   another site cannot send the token (not a finding). Add a fixture: a token-based JSON API that accepts any
   Origin.
   **Claimed on 7 October 2026 by session securevibe-e9**, at the owner's word ("pick your next backlog item
   whenever you're ready"), in branch `claude/securevibe-e9-token-forgery`. Both requests sent as another site
   (`probe.cross-site-request-accepted`, V3.5.1, and `probe.preflight-skipped`, V3.5.2) lose the `Authorization` header a browser
   would not send; a refusal then credits nothing, since without the token it may only mean "not signed in".
   **`Status: proposed`**: a Later entry on ADR-021, made accepted in the pull request that builds it.
   **Done the same day** (DESIGN, "A request from another site carries no `Authorization` header"; ADR-021, Later,
   7 October 2026, accepted): both requests go with the session's cookies only; with no cookie neither is sent and
   both are not assessed; a refusal with the token left off is not credited.
8. **Single-page apps get a false "private page open to anyone".** (`docs/GAP-ANALYSIS.md`, 2.2.) An anonymous 2xx
   counts as served (`signed_in/mod.rs`), so a React or Vite app's page shell for `/dashboard` is reported high.
   Treat an answer identical to the root page's as a shell, not judged; tell builders in the spec to list API
   addresses (`/api/me`) as private pages for such apps.
   **Claimed on 7 October 2026 by session securevibe-e9**, at the owner's word ("pick your next backlog item -
   there are new backlog items from a gap analysis to choose from"), in branch `claude/securevibe-e9-spa-shell`.
   An answer that is only the app's page shell is neither the private page served nor refused, which is ADR-021's
   question (which answers count as the app's): **`Status: proposed`**, a Later entry on ADR-021, made accepted in
   the pull request that builds it.
   **Done the same day** (DESIGN, "A single-page app's page shell is not its private page"; ADR-021, Later, 7
   October 2026, accepted): a private page answering nobody exactly as the front page does is set aside, not
   judged, and every later check is given the pages that are left; the spec says to list `/api/me`-style addresses.
9. **Apps that install packages cannot be run by `sv run`.** (`docs/GAP-ANALYSIS.md`, 3.1.) Now: fix
   `examples/flask-booking/securevibe.toml` (its `pip install` build cannot run read-only, and it listens on
   127.0.0.1) and the starter's `build` example; have the preflight warn about `pip`/`npm`/`yarn`/`pnpm install` in
   `build`; document building your own image and setting `image`. Later, as a decision with its own record (what
   `sv` runs): an `image-build` option, or an install step outside the fence before the app starts inside it.
   **The "Later" part claimed on 7 October 2026 by session paper-facts**, at the owner's word ("I agree with your
   recommendation, please go ahead and write it up as proposed"), in branch `claude/install-step`: an install step
   before the run, in its own container that sees only the dependency files, with no package code run while the
   network is open, and the result mounted read-only into the fenced run. **`Status: proposed`: ADR-052.** Nothing
   is built until the owner has read the record. The "Now" part stays unclaimed. Read on `main` just before this
   claim: no other session had claimed either.
   **The "Later" part done the same day** (ADR-052, accepted; DESIGN, "Packages installed before the run, outside
   the fence"): `install = true` installs Python and Node packages before the run as the record says, tested with a
   real backend. The starter's `build` example no longer suggests `pip install`, and an app whose build step tries
   one is told about `install = true`. Still open from the "Now" part: `examples/flask-booking`, the preflight
   warning, and the guide's page on building your own image.
   **The rest of the "Now" part claimed 9 October 2026 by session securevibe-e2** ("please continue to work through
   and pick up new items as you merge"), in branch `claude/securevibe-e2-build-install`: `sv preflight` warns, before
   any run, when `build` installs packages (`pip install`, `npm install` or `ci`, `yarn`, `pnpm install`, and the
   like), naming `install = true` and the image as the two ways that work; and `docs/GETTING-STARTED.md` says how to
   build an image of your own that holds the packages and name it in `image`. `examples/flask-booking` is already
   fixed (`install = true`; its `127.0.0.1` is kept on purpose for the preflight's own test), so it wants no build. A
   warning changes no evidence, so no record is proposed. Read on `main` and the open pull requests just before this
   claim: no other session had claimed it.
   **That part done the same day**
   (`docs/design/0326-a-build-step-that-downloads-packages-said-before-the-run-9.md`): the preflight's
   `build-install` item, and "An image of your own" in `docs/GETTING-STARTED.md`. Finding 9 is done.
10. **Supabase and Firebase access rules are never read.** (`docs/GAP-ANALYSIS.md`, 3.2.) Rules files
   (`firestore.rules`, `storage.rules`, `database.rules.json`: `if true`, no `request.auth`, no owner check);
   Supabase migrations (a table without `enable row level security`, grants to `anon`); a secret, service-role, or
   admin key under a `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, or `REACT_APP_` name; and, when the dependencies show
   such a service, a line in the run summary that its sign-in and data are outside what the fence can test. Each
   part can be claimed on its own.
   **The rules files and the migrations (the first two parts) claimed 8 October 2026 by session securevibe-e9**
   ("choose the next backlog item"), in branch `claude/securevibe-e9-hosted-rules`: findings only, crediting nothing.
   The public-name key and the run summary's line stay open.
   **Those two parts done the same day** (DESIGN, "Firebase rules and Supabase migrations are read"):
   `config.firebase-rules-open`, `config.supabase-table-without-rls`, and `config.supabase-policy-allows-all`.
   **The public-name key (the third part) claimed 8 October 2026 by session securevibe-e9** ("choose the next
   backlog item"), in branch `claude/securevibe-e9-public-keys`: a secret, service-role, or admin key under a name
   the build hands to the browser, only ever a finding. Read on `main` just before this claim: no other session had
   claimed it. The run summary's line stays open.
   **The third part done the same day** (DESIGN, "A server's key under a name the browser is given"):
   `config.secret-under-public-name`.
   **The run summary's line (the fourth part) claimed 8 October 2026 by session securevibe-e9** ("choose the next
   backlog item"), in branch `claude/securevibe-e9-hosted-gap`: when the bill of materials shows a Firebase or
   Supabase package, `sv run` and the report name sign-in and the hosted data as not assessed by asking the running
   app. Read on `main` just before this claim: no other session had claimed it.
   **The fourth part done the same day** (DESIGN, "A hosted backend is named as out of the running app's reach").
   With it, every part of item 10 is done.
11. **Plain `sv check` has no rule for the commonest web flaws.** (`docs/GAP-ANALYSIS.md`, 3.3.) Code rules, mostly
   finding-only, each claimable on its own: cross-site-scripting sinks by framework (`dangerouslySetInnerHTML`,
   `innerHTML`, `Markup`, `| safe`, `res.send` of built HTML); a template built from a value
   (`render_template_string`); request data flowing into an outgoing request (`requests.get`, `fetch`, `http.Get`);
   a token decoded without verification, or with `none` allowed; cross-origin settings that reflect any origin with
   credentials; CSRF protection switched off; the request body passed whole to an update or create.
   **The unverified token claimed 8 October 2026 by session securevibe-e9** ("pick your next backlog item whenever
   you're ready"), in branch `claude/securevibe-e9-token-signature`: a code rule, `ast.token-signature-not-checked`,
   for a token's signature check switched off where the library has a switch for it (V9.1.1), only ever a finding.
   The `none` algorithm and the other rules of this item stay open. Read on `main` just before this claim: no other
   session had claimed any part of this item.
   **The unverified token done the same day** (DESIGN, "A token read with its signature check switched off").
   **CSRF protection switched off claimed 8 October 2026 by session securevibe-e9** ("pick your next backlog item
   whenever you're ready"), in branch `claude/securevibe-e9-csrf-off`: a code rule, `ast.csrf-protection-off`, for the
   framework switches that turn request-forgery protection off (Django's `csrf_exempt`, Flask-WTF's
   `WTF_CSRF_ENABLED = False`, Spring's `csrf().disable()`, Rails' `skip_forgery_protection`, and their like; V3.5.1),
   only ever a finding. Read on `main` just before this claim: no other session had claimed it.
   **A template built from a value claimed 8 October 2026 by session securevibe-e9** ("pick your next backlog item
   whenever you're ready"), in branch `claude/securevibe-e9-template`: a code rule, `ast.template-built-from-value`,
   for a template made from anything but fixed text (`render_template_string`, Jinja's `Template(...)` and
   `from_string`, and their like in other languages; V1.3.7), only ever a finding. Read on `main` just before this
   claim: no other session had claimed it.
   **A template built from a value done the same day** (DESIGN, "A page template built from a value"); Jinja's bare
   `Template(...)` is left out, since it cannot be told from Python's own `string.Template`.
   **Cross-origin settings that let any site in with credentials claimed 8 October 2026 by session securevibe-e9**
   ("pick your next backlog item whenever you're ready"), in branch `claude/securevibe-e9-cors`: a code rule,
   `ast.cors-any-origin-with-credentials`, for CORS settings that accept every origin and send cookies too
   (flask-cors, Express's and Fastify's `cors`, Spring, ASP.NET Core; V3.4.2), only ever a finding. Read on `main`
   just before this claim: no other session had claimed it.
   **CSRF protection switched off done the same day** (DESIGN, "Protection against forged requests switched off").
   **CORS with any site and credentials done the same day** (DESIGN, "Cross-origin settings that let any site in with
   credentials").
   **Request data in an outgoing request's address claimed 9 October 2026 by session securevibe-e9**, from the
   roadmap (Phase 4, item 4, the next unclaimed part of this finding), in branch `claude/stackvet-e9-fetch-from-request`:
   a code rule, `ast.fetch-address-from-request`, only ever a finding, citing what the running check of the same flaw
   cites (V1.3.6, V13.2.4; `probe.fetch-goes-anywhere`), for an outgoing request whose address is taken straight from
   the incoming one (`requests.get(request.args["url"])`, `fetch(req.query.url)`, `http.Get(r.URL.Query().Get("url"))`,
   and their usual siblings in Python, JavaScript and TypeScript, and Go), and not for an address built from the app's
   own settings, which is how every API client is written. Confirmed on `main` and in the open pull requests just
   before this claim: no rule reads it, and no other session holds this part.
   **That part done the same day** (`docs/design/0324-an-outgoing-request-s-address-taken-from-the-incoming-one-9.md`):
   `ast.fetch-address-from-request` in Python, JavaScript and TypeScript, and Go, only ever a finding, with an address
   from the app's settings or a written-out host left alone; six guards broken in turn, each caught. Of this finding,
   the request body passed whole to an update or create is still open.
   **The request body passed whole to an update or create claimed 9 October 2026 by session securevibe-e9**, from the
   roadmap (Phase 4, item 4, the last unclaimed part of this finding), in branch `claude/stackvet-e9-body-whole`: a code
   rule, `ast.request-body-passed-whole`, only ever a finding, citing V15.3.3 (mass assignment), for the whole request
   body handed to a model's create or update as it came (`User.create(req.body)`, `Object.assign(user, req.body)`,
   Prisma's `data: req.body`, `new Model(req.body)`; `User(**request.json)`, `.objects.create(**request.data)`,
   `.update(**request.get_json())`), in Python, JavaScript, and TypeScript; one field picked out of the body, or the
   body checked by a schema first, is not reported. Confirmed on `main` and in the open pull requests just before this
   claim: no rule reads it, and no other session holds this part.
   **That part done the same day** (`docs/design/0325-the-whole-request-body-saved-as-it-came-9-october-2026.md`):
   `ast.request-body-passed-whole` in Python, JavaScript, and TypeScript, only ever a finding, with the fields picked
   out or the body checked by a schema left alone; four guards broken in turn, each caught. Every part of this finding
   is now done.
12. **Bandit and gosec findings for injection, XSS, and SSRF carry no requirement.** (`docs/GAP-ANALYSIS.md`, 3.4.)
   Map Bandit B610, B611, B701, B703, B704, B310, B614, B615 and gosec G203, G106, G108 in `data/adapters.json`,
   and add a test that fails when a tool rule whose description names injection or XSS maps to no requirement.
   **Claimed on 7 October 2026 by session securevibe-e9**, at the owner's word ("pick your next backlog item
   whenever you're ready"), in branch `claude/securevibe-e9-tool-citations`. Mapped under `findings_against`, so a
   finding names the requirement it shows failing and a clean run credits nothing new: B610 and B611 (V1.2.4), B701,
   B702, B703, B704, and G203 (V1.2.1), B601 (V1.2.5), G108 (V13.4.2), B614 (C4.1.2), and B615 (C6.1.3), each as
   `sv`'s own rule or Semgrep's equivalent cites it. B310 and G106 are named with no requirement, saying why: B310
   fires on every `urlopen`, fixed addresses included, and G106 is about SSH, which the TLS requirements do not
   cover. No credit changes, so no ADR is proposed.
   **Done the same day** (DESIGN, "Bandit's and gosec's findings for injection and unescaped output name their
   requirement"), with two tests in `crates/sv-check/tests/citations.rs`.
13. **Running checks an attacker would try first.** (`docs/GAP-ANALYSIS.md`, 3.5.) Each claimable on its own: (a)
   mass assignment beyond sign-up: B sends `owner`/`user_id`/`role` on `owned.create`, `creates`, and
   `change-email`; (b) stored cross-site scripting: a second `owned` record with `<sv-x>` in its marker, and a
   test-model reply carrying an `<img onerror>`; (c) which accounts exist, through sign-in and sign-up (V6.3.8);
   (d) a reset code returned in the reset request's own answer; (e) prompt injection through a stored note with
   `reads-owned`; (f) a sign-in token signed with a placeholder secret (`secret`, `changeme`), offline; (g) the
   Gemini request shape in the test model.
   **(f) claimed 8 October 2026 by session securevibe-e9** ("pick your next backlog item whenever you're ready"), in
   branch `claude/securevibe-e9-weak-token-secret`: the app's own sign-in token, when it is signed with a shared
   secret (HS256, HS384, HS512), checked offline against a list of placeholder secrets; a match is a finding citing
   V9.1.1, and no match credits nothing. The secret is never printed. Read on `main` just before this claim: no other
   session had claimed any part of this item.
   **(d) claimed 8 October 2026 by session securevibe-e9** ("pick your next backlog item whenever you're ready"), in
   branch `claude/securevibe-e9-reset-code-answer`: once the reset check has found the code in the email, it looks
   for that same code in the answers to the reset requests themselves (body and headers). Found there, anybody can
   reset any account by asking; a finding citing V6.4.3, and its absence credits nothing. The code is never printed.
   Read on `main` just before this claim: no other session had claimed (d).
   **(c), through sign-in, claimed 8 October 2026 by session securevibe-e9** ("pick your next backlog item whenever
   you're ready"), in branch `claude/securevibe-e9-signin-reveals`: two sign-ins with a wrong password for a real
   account and one for an address with none, compared as the reset check compares its answers (status, then words
   with what varies between identical requests set aside). A difference is a finding citing V6.3.8; none credits
   nothing. Run just before the guessing check, and not judged when any answer was a rate limit. Sign-up's half of
   (c) stays unclaimed. Read on `main` just before this claim: no other session had claimed (c).
   **(d) done the same day** (DESIGN, "A reset code handed back in the reset request's own answer"):
   `probe.reset-code-in-answer`.
   **(f) done the same day** (DESIGN, "A sign-in token signed with a placeholder secret"):
   `probe.app-token-placeholder-key`.
   **(c) through sign-in done the same day** (DESIGN, "A failed sign-in that tells which accounts exist"):
   `probe.signin-reveals-account`.
   **(c), through sign-up, claimed 8 October 2026 by session securevibe-e9** ("pick your next backlog item whenever
   you're ready"), in branch `claude/securevibe-e9-signup-reveals`: an account made for it, then two sign-ups with its
   address and one with an address nobody has, compared by the same `reveals_account_check`. A difference is a finding
   citing V6.3.8; none credits nothing. Never with A's or B's address, since an app that lets a second sign-up replace
   an account would change a password the other checks rely on. Read on `main` just before this claim: no other session
   had claimed it.
   **(c) through sign-up done the same day**
   (`docs/design/0301-a-sign-up-that-tells-which-accounts-exist-8-october-2026.md`): `probe.signup-reveals-account`.
   **(a), on `owned.create`, claimed 9 October 2026 by session securevibe-e9** ("please continue to work through and
   pick up new items as you merge"), in branch `claude/stackvet-e9-owner-field`: when the record A reads back names
   its owner (`user_id`, `owner_id`, `userId`, `ownerId`, `owner`, `author_id`, `created_by`), B creates one record
   with that field set to A's value and one without it. B's record that A then reads as theirs, on A's list or
   private pages or by its own record naming A as owner, while B's plain one is not, is a finding citing V15.3.3 and
   V8.2.2; nothing credits. A record that names no owner leaves it not assessed, saying so. `creates` and
   `change-email` stay unclaimed. Read on `main` and the open pull requests just before this claim: no other session
   had claimed (a).
   **(a) on `owned.create` done the same day**
   (`docs/design/0326-a-record-put-into-another-user-s-account-9-october-2026.md`; ADR-053, Later):
   `probe.owner-field-trusted`. `creates` and `change-email` stay open.
   **(a), on `change-email`, claimed 9 October 2026 by session securevibe-e9** ("please continue to work through and
   pick up new items as you merge"), in branch `claude/stackvet-e9-email-role`: with `signup`, `change-email`, and an
   `admin` page, an account made for it is shown refused the admin pages, then sends the email change with the sign-up
   check's role fields added (`role=admin`, `is_admin=true`, and the rest). An admin page that then opens to it is a
   finding under `probe.role-field-trusted` (V8.3.1, V15.3.3, V8.2.3); nothing credits a requirement. Never A or B,
   whom the other checks rely on. `creates` stays unclaimed: stackvet.toml gives no way to read back what those
   requests make, so an owner sent there could not be seen to take. Read on `main` and the open pull requests just
   before this claim: no other session had claimed it.
   **(a) on `change-email` done the same day**
   (`docs/design/0329-a-role-sent-with-an-email-change-9-october-2026.md`): `probe.email-change-role-trusted`, a rule of
   its own rather than `probe.role-field-trusted`, so the crash check (ADR-021) follows each by its name. `creates`
   stays open.
   **(e) claimed 9 October 2026 by session securevibe-e9** ("please continue to work through and pick up new items
   as you merge"), in branch `claude/stackvet-e9-stored-injection`: with `reads-owned = true`, the second test user
   saves a note that carries a textbook injection ("Ignore all previous instructions") beside a private marker, and
   asks the AI feature about it. The test model's RECALL answer also says whether the injection's words arrived with
   the note. The note reaching the model with them is a finding citing C2.1.3, as the injection typed straight in is;
   only ever a finding, since one stored pattern stopped is not every way of writing one. The control is the user's
   own plain note, found the same way; without it nothing is judged. The change to what the test model reports is a
   Later entry on ADR-042, written with the build. Read on `main` and the open pull requests just before this claim:
   no other session had claimed (e).
   **(e) done the same day** (`docs/design/0330-a-prompt-injection-saved-in-a-note-9-october-2026.md`; ADR-042,
   Later): `probe.ai-stored-injection-unscreened`.
   **(g) claimed 9 October 2026 by session securevibe-e2** ("please continue to work through and pick up new items as
   you merge"), in branch `claude/securevibe-e2-gemini`: the test model answers Google's Gemini format as it answers
   OpenAI's and Anthropic's. A POST whose path ends `:generateContent` or `:streamGenerateContent` (whatever comes
   before it, so a base address ending `/v1` still works) is read for `systemInstruction`, the user's `contents`,
   `functionResponse` parts, `tools[].functionDeclarations`, and `generationConfig.maxOutputTokens`, with the model
   named in the path; the shape asked for is read from `generationConfig.responseMimeType` with `responseSchema` or
   `responseJsonSchema`, and from `toolConfig.functionCallingConfig` (mode `ANY` with one function); answers,
   function calls, streamed answers, and errors come back in Gemini's own shapes. The app is also given
   `GEMINI_API_KEY` and `GOOGLE_API_KEY` set to the same placeholder key as the others, and `GOOGLE_GEMINI_BASE_URL`
   set to the test model's address, which Google's own client library reads. An app that writes Google's address
   into its code is still not reached, and says so as now. **`Status: proposed`: ADR-019, Later, 9 October 2026**
   (what the app is given inside the fence) **and ADR-042, Later, 9 October 2026** (the shape read from a Gemini
   request). Read on `main` and the open pull requests just before this claim: no other session had claimed (g).
   **(g) done the same day** (`docs/design/0327-the-test-model-speaks-gemini-9-october-2026.md`; ADR-019 and ADR-042,
   Later, accepted). `GOOGLE_GEMINI_BASE_URL` was confirmed in the source of Google's own libraries for Python
   (`google-genai` 2.29.0) and JavaScript (`@google/genai` 2.28.0), since their documentation names only the key.
   Vertex AI's addresses and sign-in stay outside it.

   **(b), the stored record's half, claimed 9 October 2026 by session securevibe-e9** ("please continue to work
   through and pick up new items as you merge"), in branch `claude/stackvet-e9-stored-markup`: the first user saves a
   second `owned` record whose text carries `<"'` between the marks the reflection probes use, then opens the record
   and the pages that list it. An HTML page that writes the `<` back as it is, is a finding citing V1.2.1, as the
   reflected check's is; only ever a finding, since one page escaping it says nothing of the others. A JSON answer is
   not judged. The test model's reply carrying HTML stays unclaimed. Read on `main` and the open pull requests just
   before this claim: no other session had claimed (b).
   **(b), the stored record's half, done the same day**
   (`docs/design/0328-saved-text-written-into-a-page-unencoded-9-october-2026.md`): `probe.stored-unencoded`. The
   test model's half stays open.
   **(b), the test model's half, claimed 9 October 2026 by session securevibe-e9** ("please continue to work through
   and pick up new items as you merge"), in branch `claude/stackvet-e9-model-html`: a new test-model reply kind whose
   reply carries an `<img src=x onerror=...>` tag with a marker. When the app's answer to the chat is HTML and holds
   that tag as it is, the model's reply was written into the page unencoded: a finding citing V1.2.1, only ever a
   finding. An answer in JSON is not judged, since the page drawing it decides, which the browser checks ask. The new
   kind is a Later entry on ADR-042, written with the build. Read on `main` and the open pull requests just before
   this claim: no other session had claimed it.
   **(b), the test model's half, done the same day**
   (`docs/design/0331-the-model-s-reply-written-into-the-page-as-html-9-october.md`; ADR-042, Later):
   `probe.ai-reply-html-unencoded`.
14. **Template and notebook files are skipped without saying so.** (`docs/GAP-ANALYSIS.md`, 3.6.) Name `.astro`,
   `.ejs`, `.erb`, `.hbs`, `.pug`, `.twig`, `.j2`, `.njk`, `.liquid`, `.cshtml`, `.razor`, `.jsp`, `.ipynb`, and
   `.sql` as unread code; read notebook code cells as Python and Astro's frontmatter as TypeScript.
   **The owner's decision, 7 October 2026:** each kind read for what it can hold (ADR-054). **Claimed the same day
   by session securevibe-e9** ("yes, go ahead with item 14 as you recommended"), in branch
   `claude/securevibe-e9-templates`: notebooks read as Python; templates embedding a general-purpose language named
   as unread code; logic-free templates read as pages; `.sql` named and holding nothing back. **`Status: proposed`:
   ADR-054.** Reading Astro's header and EJS's blocks is a second pull request.
   **The second pull request claimed 8 October 2026 by session securevibe-e9** ("pick your next backlog item"; the
   owner approved it with item 14 on 7 October), in branch `claude/securevibe-e9-astro-ejs`: Astro's `---` header read
   as TypeScript and its markup as a page; EJS's `<% %>`, `<%= %>`, and `<%- %>` blocks read as JavaScript at their
   own lines. A file whose code is not all taken out stays unread. Recorded as a "Later" entry on ADR-054.
   **Done 8 October 2026** (DESIGN, "Templates and notebooks read for what they can hold"; ADR-054 accepted), with
   tests in `crates/sv-check/tests/clean_coverage.rs` and `crates/sv-cli/tests/templates.rs`. Still open: reading
   Astro's header and EJS's `<% %>` blocks, so that the commonest code templates stop holding every rule back.
   **The second half done 8 October 2026** (DESIGN, "Astro's header and EJS's tags read as code"; ADR-054, Later):
   Astro's header, `{…}`, and scripts read as TypeScript, and EJS's tags as one JavaScript program, each at its own
   lines. `.pug`, `.erb`, `.jsp`, `.cshtml`, and `.razor` are still unread code.
15. **The secrets scan misses passwords in web addresses and many AI-app providers.** (`docs/GAP-ANALYSIS.md`,
   3.7.) A rule for `scheme://user:password@host` (placeholders skipped; `secrets.rs` now skips any value with
   `://`); the published patterns for SendGrid, Groq, Resend, Supabase, Twilio, Mailgun, Postmark, Replicate,
   OpenRouter, Mistral, and Pinecone; keys inside a notebook's escaped JSON.
   **Claimed on 7 October 2026 by session securevibe-e9**, at the owner's word ("pick your next backlog item
   whenever you're ready"), in branch `claude/securevibe-e9-secret-formats`: a password in a web address's user part,
   placeholders skipped and the password redacted like every other secret; and each provider's published key format,
   taken from gitleaks' rules rather than recalled, for those whose keys carry a prefix of their own (a provider whose
   keys are plain letters and digits is named as not looked for, since a pattern for it would match ordinary text).
   A notebook's escaped JSON is not part of this. More formats find more and credit nothing new, so no ADR is proposed.
   **Done the same day** (DESIGN, "Passwords in web addresses, and the key formats of the providers AI-built apps
   use"): `secrets.password-in-url`, and ten provider formats.
16. **Smaller static gaps: workflows, and where infrastructure and CI files are looked for.**
   (`docs/GAP-ANALYSIS.md`, 3.8.) Workflows: a pull request's title or branch pasted into a `run:` line, and
   third-party actions pinned to a tag rather than a commit (finding only). Corroborators: match `Dockerfile`,
   compose files, and charts at any depth, and add `compose.yaml`, `Containerfile`, `cdk.json`, `.travis.yml`,
   `cloudbuild.yaml`, `.buildkite/`.
   **The workflows half claimed on 7 October 2026 by session securevibe-e9**, at the owner's word ("pick your next
   backlog item whenever you're ready"), in branch `claude/securevibe-e9-workflow-injection`: a pull request's or
   issue's title, body, or branch name pasted into a `run:` line (citing AC.12.1 only in a workflow a privileged
   trigger starts, and nothing elsewhere), and a third-party action pinned to a tag or branch rather than a commit
   (citing nothing, as `config.workflow-token-permissions` does). Both only ever findings, so no ADR is proposed. The
   corroborators half is not claimed.
   **The workflows half done the same day** (DESIGN, "A stranger's text in a workflow's commands, and actions not
   pinned to a commit").
   **The corroborators half claimed 9 October 2026 by session securevibe-e2**, in branch
   `claude/securevibe-e2-corroborators`: a file pattern written `**/name` matches that name at any depth (the app's
   listing already leaves out `.git` and `node_modules`), used for `Dockerfile`, `Containerfile`, the compose files,
   and `Chart.yaml` in `iac`; and `compose.yaml`, `compose.yml`, `Containerfile`, and `cdk.json` added to `iac`, and
   `.travis.yml`, `cloudbuild.yaml`, and `.buildkite` to `ci-cd`. Both conditions take a missing file as agreeing
   with an owner's "no", so a `deploy/Dockerfile` or a `compose.yaml` that was not looked for let a "no" stand and
   took requirements out of the report. **`Status: proposed`: ADR-015, Later, 9 October 2026** (what a missing
   file can agree with). Confirmed on `main` just before this claim: patterns match at the top of the folder only,
   none of the seven names is listed, and no other session holds this half.
   **The corroborators half done the same day** (`docs/design/0326-infrastructure-and-ci-files-at-any-depth-9-october-2026.md`;
   ADR-015, Later, 9 October 2026, accepted), with `cloudbuild.yml` beside `cloudbuild.yaml`. Finding 16 is done.
17. **The answers that set the app's level are the AI tool's, never sealed, and the report does not say so.**
   (`docs/GAP-ANALYSIS.md`, 4.1.) Under the level line, say why and on whose word; let `sv review` seal the scope
   (`audience`, `[data]`); until sealed, show the level 2 count beside it; compare `audience = "just-me"` with a
   public sign-up page, and a health-like app with `categories = []`. Changes what a report concludes: a record
   (ADR-024, Later, or a new one).
   **Its first part claimed 9 October 2026 by session securevibe-e2** ("please continue to work through and pick up
   new items as you merge"), in branch `claude/securevibe-e2-level-why`: under the level line, every report says why
   the app is held to that level (the audience, or the sensitive data named, or the data list left unanswered), and
   on whose word: answers in `stackvet.toml` that the AI coding tool usually writes and nobody has confirmed. At level
   1, it also says how many more requirements level 2 would bring, so a level 1 resting on an unconfirmed
   `audience = "just-me"` does not read as settled. Sealing the scope through `sv review`, and comparing the answers
   with what the code shows (a public sign-up page, health-like fields), stay open. **`Status: proposed`: ADR-024,
   Later, 9 October 2026** (what the report says about the level and on whose word). Read on `main` and the open pull
   requests just before this claim: no other session had claimed any part of finding 17.
   **The first part done the same day** (`docs/design/0330-why-the-level-and-on-whose-word-9-october-2026.md`; ADR-024, Later, accepted): `level_why` in
   `report.json`, and the sentence under the level line in every report. Still open: sealing the scope through
   `sv review`, and comparing the answers with what the code shows.
18. **The AI tool's "when to bring in a person" text is shown as the owner's.** (`docs/GAP-ANALYSIS.md`, 4.2.) A
   `design-decisions.md` section the AI tool wrote saying no outside review is needed comes out as "Your
   design-decisions.md says …" in every report file (`main.rs`, near the escalation text). Name who wrote it, and
   keep the standing line that no tool can make this judgment.
   **Claimed on 8 October 2026 by session securevibe-e2**, with item 20, at the owner's word ("feel free to pick
   another item from the backlog"), in branch `claude/securevibe-e2-loop-lessons`.
   **Done the same day** (DESIGN, "Whose "bring in a person" text it is, and two lessons for the AI tool"): the
   report names who wrote the section, from its `Written by:` line.
19. **`not-the-app` can switch off one capability's requirements.** (`docs/GAP-ANALYSIS.md`, 4.3.) List each
   condition found only inside a not-the-app folder as a question in the report, and refuse a folder holding the
   start command's file. A change to ADR-031: a Later entry.
   **Claimed 8 October 2026 by session securevibe-e9** ("pick the next backlog item when ready"), in branch
   `claude/securevibe-e9-not-the-app`: a condition the scan finds only inside a not-the-app folder is not read as
   "no", and the report asks it, naming the file; an entry holding the file the start command runs is refused.
   **Done the same day** (DESIGN, "A folder set apart cannot switch a capability off"; ADR-031, Later).
20. **Two lessons from the owner's first build never reached the AI tool.** (`docs/GAP-ANALYSIS.md`, 4.4.) "Never
   rewrite working code to silence a finding" and "name a requirement in a test only where the test proves it": add
   both to `data/coding-rules.json`, and the second to the brief's test line (`brief.rs`) and the spec's test
   section.
   **Claimed on 8 October 2026 by session securevibe-e2**, with item 18, in branch
   `claude/securevibe-e2-loop-lessons`.
   **Done the same day** (the same DESIGN section): the first lesson in `never-weaken-a-check`, the second at the
   top of the feature brief's "Tests to write".
21. **The loop trials cannot tell fixing from dodging.** (`docs/GAP-ANALYSIS.md`, 4.5.) Add to the trial measures
   how each finding went away, and credit-seeking edits (ids added to tests, `by = "owner"`, finding reviews,
   `not-the-app` or scope changes); run an outside tool as an independent check of the loop arm.
22. **Smaller trust gaps in the build loop.** (`docs/GAP-ANALYSIS.md`, 4.6.) Each claimable on its own: (a) the
   seal key's passphrase on by default, and the report saying when a seal's key has none (a change to ADR-043); (b)
   reports read back as MCP resources fenced as app text; (c) a "drafted by your AI tool, adopted by you" label for
   security notes; (d) a record of the MCP calls made while building, or the report saying nothing shows the loop
   happened (a decision); (e) instruction-file lines that mention `sv`'s own marks (`Written by:`, `by = "owner"`,
   `finding-review`, `not-the-app`) noticed (a change to ADR-049); (f) feature briefs for owned or shared records,
   API keys, background jobs, and several customer organizations; (g) "shown to work" giving each prompt's sample
   size, and saying when delivery through `sv` was not shown.
   **(g), its first half, claimed on 8 October 2026 by session securevibe-e2**, at the owner's word ("please
   continue to work off the backlog"), in branch `claude/securevibe-e2-prompt-sample`: each prompt shown to work
   says how many builds it was shown on, with it and without, wherever its status is given (`sv prompts`, the
   MCP server's prompts and offers, the instructions the AI tool reads first), so a prompt shown on one pair no
   longer reads the same as one shown on ten. The counts are read from each prompt's own trial record. The
   second half, saying when delivery through `sv` was not shown, stays unclaimed.
   **That half done the same day** (DESIGN, "And on how many builds"): `builds` in each shown prompt's `tested`,
   said in every copy of its status. Breaks: the count left out of the words, a count changed, and a count
   removed each failed a test (`crates/sv-check/tests/prompts.rs` holds each count to its trial's account).
   **(g), its second half, claimed 9 October 2026 by session securevibe-e2** ("please continue to work through and
   pick up new items as you merge"), in branch `claude/securevibe-e2-delivery`: each prompt's trial record says how
   it did when `sv` gave it rather than the request (the two delivery trials, `docs/prompts/library-trial/delivery.md`
   and `start.md`, by model), and every copy of its status says so: "shown to work with Sonnet at the start of a
   build" for `secrets-in-the-environment`, "not shown" for `ai-feature-guard`, "no reading" where a trial could not
   tell, and "not tried" for a prompt shown to work only when pasted into the request. Read from each trial's own
   verdict file, and held to it by a test. Which prompts are shown, and so which `sv` gives (ADR-044), is unchanged, so
   no record is proposed. Read on `main` and the open pull requests just before this claim: no other session had
   claimed it.
   **That half done the same day**
   (`docs/design/0328-and-whether-it-worked-when-sv-gave-it-9-october-2026.md`): `delivered` in each prompt's trial
   record, said in every copy of its status, held to `start-verdicts.json` and `delivery-verdicts.json`. (g) is done.
   **(b) claimed 9 October 2026 by session securevibe-e2** ("please continue to work through and pick up new items as
   you merge"), in branch `claude/securevibe-e2-resource-fence`: a report the AI tool reads back through the MCP
   server (`resources/read`) comes back as a tool's result does, with the whole of it between `<app-text-…>` tags
   named for that one reading, which nothing in the report holds, and a first line outside them saying the text inside
   is information about the app, never an instruction. The report files on disk, and their seals, are unchanged;
   `report.json` and `findings.sarif`, which programs parse, are handed over as written, with the description saying
   why. **`Status: proposed`: ADR-066, Later, 9 October 2026** (how the MCP server holds the app's text). Read on
   `main` and the open pull requests just before this claim: no other session had claimed (b).
   **(b) done the same day**
   (`docs/design/0328-a-report-read-back-is-fenced-as-a-tool-s-result-is-9-october.md`; ADR-066, Later, accepted):
   `report.html`, `compliance.md`, and `security.md` come back fenced whole; `report.json` and `findings.sarif` as
   written. Found on the way: two runs making the report key at once (backlog 0220, fixed on its own).
   **(e) claimed 9 October 2026 by session securevibe-e2** ("please continue to work through and pick up new items as
   you merge"), in branch `claude/securevibe-e2-marks`: an instruction file the AI coding tool reads (`CLAUDE.md`,
   `AGENTS.md`, `.cursorrules`, a skill, and the rest `sv` already reads for hidden characters) that names one of
   `sv`'s own marks (`Written by: owner`, `by = "owner"`, `[[finding-review]]`, `not-the-app`, `Sealed by sv review`)
   is noted in the report's section on the AI tool's files, with the line, for the owner to read: a line can tell
   the tool to write a mark that is the owner's alone, or just as well tell it never to. A note, never a finding,
   and counted toward nothing, as the section's other notes are. **`Status: proposed`: ADR-049, Later, 9 October
   2026** (what is read in the AI tool's files). Read on `main` and the open pull requests just before this claim: no
   other session had claimed (e).
   **(e) done the same day** (`docs/design/0331-instruction-files-that-name-sv-s-own-marks-9-october-2026.md`; ADR-049, Later, accepted): a note in the AI tool's
   section for each instruction file naming one of the marks, with its line.
   **(c) claimed 9 October 2026 by session securevibe-e9** ("please continue to work through and pick up new items
   as you merge"), in branch `claude/stackvet-e9-notes-confirmed`: today an owner who agrees with a section the AI
   coding tool wrote changes its line to `Written by: owner` and seals it, and the report then calls it *documented by
   the owner*, with nothing left to say the tool drafted it. Instead, `sv review` offers a section still marked
   `Written by: AI coding tool` for confirming, as it does a design answer or a check made by hand (ADR-022), and seals
   it with who wrote it among what the seal covers, so changing the line to `owner` afterwards breaks the seal rather
   than making the tool's draft the owner's own. Such a section counts at the documented tier and is shown as
   "written by the AI coding tool, confirmed through sv review", never as the owner's. Sections the owner wrote, and
   their seals, are unchanged. **`Status: proposed`: ADR-022, Later, 9 October 2026** (a person confirming a
   security notes section the tool wrote). (a), the passphrase on by default, is left for the owner: it reverses
   ADR-043's "offered, not required", which the owner chose. Read on `main` and the open pull requests just before
   this claim: no other session had claimed (c).
   **(c) done the same day** (`docs/design/0332-a-notes-section-the-tool-wrote-confirmed-by-a-person-9.md`;
   ADR-022, Later, accepted): `notes.confirmed`, shown as "written by the AI coding tool, confirmed through sv review".
   **(f) claimed 9 October 2026 by session securevibe-e9** ("please continue to work through and pick up new items
   as you merge"), in branch `claude/stackvet-e9-feature-briefs`: four entries in `data/feature-briefs.json`, each
   naming the conditions and requirements it brings, the design-time prompts, coding-rule topics, and `stackvet.toml`
   settings that already exist for it: records each person owns or shares, API keys for other programs, background
   jobs, and several customer organizations in one app. Only what `sv` already has is named, so no new requirement is
   credited and nothing counts for more. (d), a record of the MCP calls made while building, is left for the owner:
   the backlog marks it a decision, and recording them would add to what `sv` writes. Read on `main` and the open
   pull requests just before this claim: no other session had claimed (f).
   **(f) done the same day** (DESIGN, "Feature briefs for records, API keys, background jobs, and organizations"):
   `sv brief` and `stackvet_before` give briefs for `owned-records`, `api-keys`, `background-jobs`, and
   `organizations`. A brief now names only a condition that brings a requirement, so `api-keys` names none:
   `public-api` is asked and no applicability rule keys on it. Whether it should is left open.
   **(a) claimed 9 October 2026 by session securevibe-e2** ("please continue to work through and pick up new items as
   you merge"), in branch `claude/securevibe-e2-passphrase`: when `sv review` makes the signing key, a passphrase is
   what pressing Enter chooses, and having none takes typing `none`; still offered, never required (ADR-043's third
   choice). And each entry a signed seal counts for says, where the key that made it is on this computer, whether
   that key has a passphrase: without one, anything that can run as the owner, the AI coding tool included, could
   have signed it, and the entry says so. Where the key is not on this computer (CI, with `SV_TRUSTED_SEALS`), the
   entry says that cannot be told there. What counts as sealed is unchanged. **`Status: proposed`: ADR-043, Later,
   9 October 2026** (the default answer, and what a seal's entry says about its key). Read on `main` and the open
   pull requests just before this claim: no other session had claimed (a).
   **(a) done the same day** (`docs/design/0332-a-passphrase-unless-you-say-none-9-october-2026.md`; ADR-043, Later,
   accepted): Enter chooses a passphrase and `none` goes without; each signed entry says "a key on this computer
   with a passphrase", "… with no passphrase, so anything that can run as you … could have signed it", or that it
   cannot be told here.


23. **`sv check` at a terminal never reads securevibe.toml.** (`docs/GAP-ANALYSIS.md`, 5.1.) A broken file gets no
   warning and exit 0. Read it when present and exit 2 on a parse error; say plainly in its help and in the coding
   rule that the terminal command is the narrower scan.
   **Claimed on 7 October 2026 by session securevibe-e9**, at the owner's word ("pick your next backlog item
   whenever you're ready"), in branch `claude/securevibe-e9-check-manifest`. A securevibe.toml that is there and
   cannot be read stops `sv check` with exit 3, as it stops `sv report` (exit 3 is "a manifest it cannot read" in
   `crates/sv-cli/src/exit.rs`, where the gap analysis proposed 2); its help says it is the narrower scan; and the
   coding rule names `sv report` as the terminal's form of `securevibe_check`, which builds the whole report.
   **Done the same day** (DESIGN, "`sv check` reads securevibe.toml when it is there"; ADR-029, Later, 7 October
   2026).
24. **The known-vulnerability check is out of reach for the owner.** (`docs/GAP-ANALYSIS.md`, 5.2.) Give the exact
   OSV download address per ecosystem and the folder layout in `sv audit`'s message and the guide. A command that
   downloads them (`sv advisories fetch`) would change what `sv` connects to: only as a decision with its own
   record (ADR-027's rule).
   **Claimed on 8 October 2026 by session securevibe-e2**, at the owner's word ("please continue to work off the
   backlog"), in branch `claude/securevibe-e2-osv-addresses`: the addresses and the folder layout only, in `sv
   audit`'s message, the report's gap, and the guide. Nothing that downloads.
   **Done on 8 October 2026** (session securevibe-e2): `sv audit` with no database names the OSV zip for each
   kind of package the app uses and how to lay the folder out; the report's gap names the same addresses; and
   `docs/GETTING-STARTED.md` has a table of all six, held to the code by a test. Breaks: a wrong address format
   failed three tests; the report not naming the address, the audit message not saying how, and a row missing
   from the guide each failed the test written for it. Nothing downloads.
25. **Silent failures while setting up.** (`docs/GAP-ANALYSIS.md`, 5.3.) Each claimable on its own: (a) a "did it
   connect" step for every tool in the guide, and a coding rule telling the AI tool to stop and say so when the
   `securevibe_` tools are missing; (b) the container form of `sv review` in the guide, and an `.mcp.json` example
   with the key folder mounted; (c) `sv report --tools` saying on screen which tools did not run, per-platform
   install hints, and the CodeQL hint's grammar; (d) MCP errors keeping `sv`'s own remedy outside the app-text
   fence, and naming the MCP tool, not `sv init`; (e) how to update the container image; (f) `sv init`'s prose kept
   out of what a redirect writes to a file; (g) no "Checked and fine" block when nothing was read; (h) the README
   pointing a non-programmer to the guide first, `--locked` in `tools/install.sh`, and the guide saying the build
   folder can be deleted.
   **(h) claimed on 8 October 2026 by session securevibe-e2**, at the owner's word ("please go ahead"), in
   branch `claude/securevibe-e2-readme-first`: the README's opening sends somebody who is not a programmer to
   `docs/GETTING-STARTED.md` first, `tools/install.sh` builds with `--locked`, and the guide says which build
   folder can be deleted afterwards, how large it is, and that deleting it does not remove `sv`.
   **(h) done the same day** (ADR-036, "Later, 8 October 2026"; DESIGN, "A copy of `sv` reads the data beside it"):
   all three. Breaks: `--locked` removed, and the build skipped, each failed the new test, which runs the script
   with a stand-in `cargo`.
   **(f) claimed on 8 October 2026 by session securevibe-e2**, at the owner's word ("please continue to work off
   the backlog"), in branch `claude/securevibe-e2-init-redirect`: when `sv init`'s output goes straight into a
   file, it prints only the starter `securevibe.toml`, which `sv` can read, and says on screen that the
   instructions for the AI coding tool were left out and how to see them. Status: proposed, as a "Later" entry
   on ADR-017 (what lands in the owner's folder), accepted in the pull request that builds it.
   **(f) done the same day** (ADR-017, "Later, 8 October 2026"; DESIGN, "`sv init` into a file"): into a file,
   `sv init` writes only the starter, which `sv scope` then reads, and says on screen what it left out; through a
   pipe, everything as before. Breaks: the file never recognized, and every output treated as a file, each failed
   the new test.
   **(c), its first two parts, claimed on 8 October 2026 by session securevibe-e2**, at the owner's word ("please
   continue to work off the backlog"), in branch `claude/securevibe-e2-tools-on-screen`: `sv report --tools` says on
   screen which tools did not run and why, whatever its exit status, and the install hint reads as a sentence for
   CodeQL as for the others. Per-platform install hints stay unclaimed.
   **Those two parts done the same day** (DESIGN, "The language's own tool"): the tools that did not run are listed
   on screen before the closing line, and not again when the exit status already lists them; the hint is a
   sentence for a command and for CodeQL's steps alike. Breaks: the screen list switched off, the old hint, every
   hint quoted as a command, and the list said twice each failed a test written for it.
   **(c)'s per-platform install hints claimed on 8 October 2026 by session securevibe-e2**, at the owner's word
   ("please continue to work off the backlog"), in branch `claude/securevibe-e2-install-hints`: an outside tool's
   install hint can differ on a Mac and on Linux, because `pip install` is refused by the Python Homebrew installs
   and by recent Debian and Ubuntu; so Semgrep and gosec through Homebrew on a Mac, and Bandit (with its SARIF
   formatter) and Semgrep through `pipx` where `pip` is refused. Only for packages checked to exist; Brakeman and
   CodeQL keep today's hint, since Homebrew has no Brakeman and its CodeQL lacks the query packs `sv` runs.
   **Done the same day** (DESIGN, "The language's own tool", the paragraph after "The hint reads as a sentence"):
   `install_on` in `data/adapters.json`, chosen by the computer `sv` runs on. Breaks: the computer ignored, and
   the per-platform hints ignored, each failed a test (`tools_on_screen.rs`, and a unit test in
   `adapters.rs` that holds every hint to `run` a command, never `pip install`, and to name Bandit's formatter).
   **(g) claimed on 8 October 2026 by session securevibe-e2**, at the owner's word ("please continue to work off
   the backlog"), in branch `claude/securevibe-e2-nothing-read`: `sv check` on a folder where no file of the app
   was read prints no "Checked and fine" block, and a finding about a file that is missing is not shown at line 1
   of it. Wording on screen only: `sv report` already credits nothing for such a folder (checked: 137 not
   verified, none verified).
   **(g) done the same day** (DESIGN, "Saying a check looked and found nothing", the paragraph "On screen too"):
   with nothing read, `sv check` says none is listed as checked and fine and why, and a finding about a missing
   file names the file as not there rather than a line of it. Breaks: the "nothing read" test switched off, a
   missing file shown at its line, and every run treated as nothing read each failed the new test.
   **(d) claimed on 8 October 2026 by session securevibe-e2**, at the owner's word ("please continue to work off
   the backlog"), in branch `claude/securevibe-e2-mcp-remedy`: when an MCP tool cannot do its job, what `sv` itself
   says to do next (call `securevibe_spec`, write the file, check again) is written outside the fence that marks
   the app's text, and only what quotes the app (a path, a line that does not parse) stays inside it; and a remedy
   the MCP server gives names the MCP tool, not `sv init`, which the AI tool cannot run.
   **(d) done the same day** (DESIGN, "`sv`'s own next step, outside the fence"): an error that carries `sv`'s
   next step ends with "What to do: …" outside the fence, and what went wrong stays inside it; the preflight's
   missing-file error names `securevibe_spec`, not `sv init`. Breaks: the next step fenced again, and the
   preflight's own check removed, each failed a test written for it.
   **(e) claimed on 8 October 2026 by session securevibe-e2**, at the owner's word ("please continue to work off
   the backlog"), in branch `claude/securevibe-e2-image-update`: a section of the guide on keeping SecureVibe up
   to date, both the container image the AI tool runs and a copy built on this computer, how to tell which
   version each is, and that the AI tool picks up a new image only when it starts the server again. Held to the
   workflow that publishes the image by a test.
   **(e) done the same day** (`docs/GETTING-STARTED.md`, "Keeping SecureVibe up to date"): `docker pull` again, then
   restart the AI tool or its SecureVibe server; `--version` on each copy, with the commit it was built from;
   both copies updated together; a version held to by its commit's own image; and `docker image prune` for the
   old ones. Breaks: the image renamed in step 1, the update's pull renamed, and the per-commit image no longer
   pushed by the workflow each failed `crates/sv-cli/tests/guide_update.rs`.
   **(a) claimed on 8 October 2026 by session securevibe-e2**, at the owner's word ("please continue to work off
   the backlog"), in branch `claude/securevibe-e2-did-it-connect`: a "did it connect" step for every tool in the
   guide, the one that works in any tool being to ask it to list the `securevibe_` tools it can call; and the
   instruction to stop and say so when they are missing, in the prompt the guide gives and in the rules `sv rules`
   writes into `AGENTS.md`, which a tool reads whether or not SecureVibe is connected.
   **(a) done the same day** (`docs/GETTING-STARTED.md`, "Did it connect?" and step 4; ADR-017, Later): ask the tool
   to list the `securevibe_` tools, with the count held to what the server lists, and what to check when it lists
   none; the prompt and `AGENTS.md` both tell the tool to stop and say so. Breaks: the line left out of
   `AGENTS.md`, the prompt's line removed, and the count in the guide wrong each failed
   `crates/sv-cli/tests/did_it_connect.rs`.
   **(b) claimed on 8 October 2026 by session securevibe-e2**, at the owner's word ("please continue to work off
   the backlog"), in branch `claude/securevibe-e2-review-container`: the guide's step 5 gives the container form
   of `sv review` itself, for someone who has only Docker, and a whole `.mcp.json` for the AI tool's container
   that passes the list of trusted keys as `SV_TRUSTED_SEALS` rather than mounting the key folder, so the private
   signing key never enters the container the AI tool drives. Held to the README and the code by a test.
   **(b) done the same day** (`docs/GETTING-STARTED.md`, step 5; README, "Setting a finding aside"): the container
   `sv review`, with the folder made first; and a whole `.mcp.json` that mounts the list of trusted keys alone,
   read-only, rather than the key folder. Mounting the one file rather than passing `SV_TRUSTED_SEALS`, because
   the list's line holds quotation marks a person would have to escape by hand in JSON, and because `sv review`
   adds to the same file, so the container sees each new app. Breaks: the whole folder given to the AI tool's
   container, the list not made first, and an empty list each failed `crates/sv-cli/tests/review_container.rs`,
   whose third test makes natively what that container sees and shows a signed answer still counts.
26. **The short version never says what kind of run it was.** (`docs/GAP-ANALYSIS.md`, 6.1.) One line naming what
   was not run (the running app, signed-in testing, outside tools) and how many applicable requirements only that
   could reach (`sv-report`'s short version).
   **Done 7 October 2026 with item 27**, by session securevibe-e2 (its claim and done note are under item 27): the
   short version's "Not run this time" line (DESIGN, "The short version says what kind of run it was, and which
   level").
27. **The short version does not say which level the app was held to.** (`docs/GAP-ANALYSIS.md`, 6.2.) "Held to
   ASVS level 1: N more at levels 2 and 3, and M not yet placed, are not in these numbers."
   **Items 26 and 27 claimed together on 7 October 2026 by session securevibe-e2**, at the owner's word ("please
   continue to work off the backlog"), in branch `claude/securevibe-e2-short-version-scope`. Wording in the short
   version only; what counts as evidence does not change.
   **Done the same day** (DESIGN, "The short version says what kind of run it was, and which level"): after the
   counted list, "Held to ASVS level L" with what that leaves out, and "Not run this time" with how many
   requirements only those runs could check, from `data/reach.json`.
28. **Smaller report points.** (`docs/GAP-ANALYSIS.md`, 6.3.) "passed" in the short version's next steps, and the
   banned-word test extended past the headline; the spec and the MCP instructions recommending `--fail-on
   attention:high` for a CI workflow.
   **Claimed on 7 October 2026 by session securevibe-e2**, at the owner's word ("feel free to pick something
   else from the backlog"), in branch `claude/securevibe-e2-report-points`.
   **Done the same day** (DESIGN, "Smaller report points from the gap analysis"; ADR-029, Later): the wording
   fixed, every sentence of the short version held to the banned words, and `--fail-on attention:high` named in
   the specification and the MCP instructions.
29. **Requirements nobody is told how to check by hand.** (`docs/GAP-ANALYSIS.md`, 6.4.) Add hand instructions
   (`data/human-checks.json`) for V2.2.1, V1.3.3, V1.3.5, V1.3.8, V6.5.2, V6.5.3, V8.4.1, V11.6.1, V13.3.2,
   V16.3.4, and the AISVS level 1 requirements no check settles, starting with C2, C7, C9, and C10.
   **Claimed on 7 October 2026 by session securevibe-e2**, at the owner's word ("please continue to work off the
   backlog"), in branch `claude/securevibe-e2-hand-instructions`: the ten ASVS requirements named, first; the AISVS
   ones after, as far as they go.
   **Done the same day** (DESIGN, "Hand instructions for requirements nobody was told how to check"): all ten ASVS
   requirements, and the 16 AISVS level 1 ones in C2, C7, C9, and C10 with no instruction, in
   `data/human-checks.json`, each held by a test.
30. **The fence tests pass without testing the fence when there is no container backend.** (`docs/GAP-ANALYSIS.md`,
   7.2.) `SV_REQUIRE_BACKEND=1`, set in `rust.yml`, turns each test's "no container backend here" branch into a
   failure, so a broken Docker on the runner turns CI red.
   **Claimed on 7 October 2026 by session securevibe-e9**, at the owner's word ("feel free to pick another item from
   the backlog whenever you're ready"), in branch `claude/securevibe-e9-require-backend`: one test that, with
   `SV_REQUIRE_BACKEND=1`, fails when no container backend answers, and `rust.yml` setting it for the test job, so the
   38 "no container backend here" branches can no longer all pass on a runner whose Docker broke.
   **Done the same day** (DESIGN, "CI requires a container backend"; ADR-051, Later, 7 October 2026).
31. **The files that decide what counts as evidence are governed by no record.** (`docs/GAP-ANALYSIS.md`, 7.3.) Add
   `crates/sv-check/src/suite.rs`, `data/applicability-v2.json`, `data/human-checks.json`, and `tools/coverage.py`
   to the Governs lists of the records they carry out, and confirm the weekly decision-record review runs.
   **Claimed 8 October 2026 by session securevibe-e9** ("choose the next backlog item after that"), in branch
   `claude/securevibe-e9-governs`. `suite.rs` is already governed (ADR-050).
   **The governed half done the same day:** `data/applicability-v2.json` under ADR-015, `tools/coverage.py` under
   ADR-018, and `data/human-checks.json` under ADR-022, each with a dated Later entry saying why.
   **The weekly review, as found the same day, left to the owner:** two routines do it, "Weekly decision-record
   review" (Mondays 8:45, New York time, made 4 October) and "Weekly ADR review" (8:59, made 28 September), both
   enabled and next due 12 October. Each ran once, on 5 October, and each run ended after about 50 seconds with
   about 1,800 words written, too little to read 40 records, which matches the review leaving no trace. Neither
   routine has the repository attached, so each run would have to add it itself. Changing a routine is the owner's
   to decide: attach the repository to one, and turn the other off.
   **Fixed the same day, at the owner's asking** ("please do fix the routine issues"): a session made for it,
   "Weekly decision-record review", with the repository attached and three thousand commits of history, and one
   routine that wakes it on Mondays at 8:45, New York time, with the same instructions and a first step that brings
   the checkout up to date. Both old routines are turned off, not deleted. Its first run is due 12 October.
   **Still needed: a setup script for the review's environment** (added 8 October 2026, at the owner's asking: "can
   you add to the backlog that the weekly decision-record review needs a setup script as well"). Step 7 of the
   review runs `cargo fmt`, `cargo clippy`, `cargo test --workspace`, and `tools/adr_check.py --self-test`, and a
   fresh cloud session has no promise of the Rust toolchain this repository pins, its `clippy` and `rustfmt`, or
   Python 3. The environment's setup script, which runs before each new session starts, should install those, so
   the review can run its checks rather than report that it could not. The script lives in the environment's
   settings (the cloud environment menu, then Edit, then Setup script), which only the owner can change; a session
   can draft it. A test firing on 8 October also showed that a routine fired by hand starts a fresh session without
   the repository rather than waking the review's own session; whether the Monday run wakes the right one is to be
   checked after 12 October.
32. **Every check that can credit should be seen not crediting somewhere in the suite.** (`docs/GAP-ANALYSIS.md`,
   7.4.) Extend `tools/coverage.py --credits` (and the census) so a check that credits in the test suite must also
   be seen giving a finding or "not assessed" there, turning "break your own rule" into a CI gate.
   **Claimed on 8 October 2026 by session securevibe-e2**, at the owner's word ("that sounds good, yes, please
   proceed"), in three steps, each its own pull request, of which this claim covers the first:
   (1) *measure*, in branch `claude/securevibe-e2-withhold-census`: each finding a check makes in the code that
   ships is written, with the check's id and the place in the code, to a log beside the credit log
   (`SV_CREDIT_LOG` plus `.withheld`), and `tools/coverage.py --withheld` lists every check the suite saw credit and
   never saw withhold; a list, failing nothing; (2) *fill the gaps*, a test for each check on that list in which
   the thing it guards is broken and it says no, in batches the owner hears about first; (3) *the gate*: the list
   empty, or down to named exceptions each with its reason, and `--credits` failing on any crediting check with no
   withholding test. **Status: proposed**, for (3): it changes what CI enforces, so its record (a new decision
   record, governing `tools/coverage.py`'s census) is written as proposed with step 2 and accepted in the pull
   request that builds the gate. "Not assessed" as a way of withholding is counted from step 2 if the list shows
   checks that can only withhold that way.
   **Step 1 done the same day** (DESIGN, "And what it withholds"): `finding::found` at the 45 places a finding is
   made, and `tools/coverage.py --withheld`. First count: 125 checks seen crediting, 115 seen withholding, 10 not;
   all ten withhold by design with "not assessed" or no credit, and each already has a test asserting so. Step 2
   becomes: those checks mark where they withhold, so the census sees it. Breaks: nothing written, and a test's
   own finding counted, each failed `crates/sv-check/tests/withheld_log.rs`.
   **Step 2 claimed the same day by session securevibe-e2**, at the owner's word ("yes, please go ahead with step
   2"), in branch `claude/securevibe-e2-withhold-step2`: a marker, `verified::withheld`, that a check calls where it
   gives no credit without a finding ("not assessed", or nothing), written to the same `.withheld` log, and put in
   the ten checks the first count listed, so the tests they already have are seen; and the gate's decision record
   written as proposed.
   **Step 2 done the same day** (DESIGN, "Step 2: a credit not given is written down too"; ADR-059, proposed):
   `verified::unless_credited` in the ten checks. Break: the marker writing nothing failed
   `crates/sv-check/tests/withheld_log.rs`.
   **Step 3 claimed the same day by session securevibe-e2**, at the owner's word ("go ahead with step 3 when it's
   merged"), in branch `claude/securevibe-e2-withhold-gate`: `tools/coverage.py --credits` fails on any check the
   suite saw credit and never saw withhold, with a named list of exceptions for any that cannot be made to, each
   with its reason; a check that every place in shipping code that builds a finding hands it through
   `finding::found`; and ADR-059 accepted.
   **Step 3 done the same day, and with it item 32** (DESIGN, "Step 3: the gate"; ADR-059, accepted):
   `check_withheld` in `--credits`, `NEVER_WITHHELD` empty, and `unrecorded_findings` in `--check`. Breaks: a
   finding built without `found`, a check's marker removed, and the gate switched off, each caught.

33. **The backlog is too large to read reliably.** (`docs/GAP-ANALYSIS.md`, 7.5.) Move done items to a file of
   their own; track claims as GitHub issues with assignees, or have CI refuse a claim for an item already claimed
   on `main`; list the remote branches already merged into `main` for the owner, who decides whether any is
   deleted.
34. **Hand Semgrep the app's templates and configuration files too.** (`docs/GAP-ANALYSIS.md`, the rest of 1.2.)
   Today 22 loaded rules read only files `sv` never hands Semgrep: templates (`*.erb`, `*.ejs`, `*.pug`, `*.jsp`,
   `*.mustache`), nginx's and Scala Play's `*.conf`, and `web.config`. They count for nothing, which is honest but
   leaves template escaping and server TLS settings unread. Hand Semgrep those files as well, and teach the "did
   not read every file it was given" check (`unread_files`) which of them a loaded rule reads, so a template no
   rule reads is not called unread. Changes what `sv` gives an outside tool: ADR-018, Later. Added 7 October 2026
   when the first half was built.
   **Claimed 8 October 2026 by session securevibe-e9** ("pick your next backlog item"), in branch
   `claude/securevibe-e9-semgrep-files`. Since item 14 (8 October) templates and notebooks are handed to Semgrep
   already. Measured with semgrep 1.180.0: Semgrep leaves out, without a word, a handed file no loaded rule reads,
   and a `generic` rule with no `paths.include` reads every file; the packs `sv` runs load 45 such rules, so today
   every handed file is read. The plan: hand the configuration files a rule in the map names (`*.conf`,
   `web.config`, `*.tf`); and count a handed file as unread only when a loaded rule in the map reads it (its
   language's extensions, as Semgrep's own parsers take them, or its `paths.include`), so the check stays right
   when a pack changes.
   **Done 8 October 2026** (DESIGN, "Semgrep is handed the files its rules name"; ADR-018, Later), with three tests
   in `crates/sv-check/tests/unread_files.rs`.
