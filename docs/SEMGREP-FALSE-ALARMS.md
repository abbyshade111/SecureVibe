# Option C's false alarms: where they come from and what would cut them

Research measurement for SecureVibe (`sv`), 4 October 2026, by a session working for session securevibe-e9 at the
owner's asking ("I definitely still want to look into reducing false alarms from tool C; more research into reducing
false alarms for all languages would be great as well"). Option C is the one in `docs/BACKLOG.md`'s Semgrep comparison:
every rule the `semgrep` adapter's map names, from `semgrep/semgrep-rules` at `a84ff9c`. One row per finding, with its
verdict and cause, is `docs/semgrep-false-alarms.csv`. Not kept here: the copy of the rules (the Semgrep Rules License
does not allow redistributing them, and allows using them only for internal business purposes, so `sv` may use them
only while nothing built on them is sold), the clones of the apps, Semgrep's raw output, and the throwaway scripts that made
the numbers. Every number below is as measured, and the verdicts are one reader's.

**Option C is not what `sv` runs.** The adapter runs the packs `p/security-audit` and `p/default` (and
`p/ai-best-practices` for an app that may call a model), which load 691 of the map's 1,035 rules (`data/semgrep-packs.json`,
measured on 26 September 2026). Read against those two base packs, 440 of the 868 findings below came from rules `sv`
runs (268 true, 164 false, 8 unsure), and 391 of the 555 false alarms came from rules it does not. Several rules
discussed by name, such as `unsafe-dynamic-method`, `generic-api-key`, `prohibit-jquery-html`, and
`html-in-template-string`, are in none of those packs. (Added 6 October 2026.)

**What has changed since, and what has not (added 8 October 2026).** Since ADR-054, `sv`'s own code rules read
notebooks as Python and read templates that cannot run code as pages; templates that embed a language are named as
unread. That is `sv`'s own rules, not Semgrep: `sv` still hands Semgrep only the files it handed it here, so the
templates and the nginx and `web.config` files some loaded rules read are still not given to it. Handing them over is
backlog item 34, claimed by session securevibe-e9 on 8 October 2026. Every number below is still the 4 October
measurement.

## The short version

- **Clean, well-kept apps are quiet under option C.** Eleven real apps and `sv`'s five examples gave
  **31 findings in all**: 24 false alarms, 5 true, 2 unsure. Seven of the eleven apps got 0 to 1
  finding. The earlier 148-finding measurement came from apps built from v1's template; its two
  biggest rules there (`var-in-href` 68, `generic-api-key` 57) gave 6 and 1 here on the clean apps.
- **The noise lives in a few places, not spread thinly.** Across all 868 findings, 555 were false
  alarms. **317 (57%) were in third-party JavaScript libraries kept inside the app** (jQuery,
  Bootstrap, Moment, DataTables and so on, not under `vendor/` or `node_modules/`), and **112 (20%)
  were in test code.** Together that is 429 of 555 (77%).
- **The same line is often reported by two or three rules.** 309 of the 868 findings repeat a
  file and line another finding already names (for example `tainted-sql-string`,
  `sequelize-raw-query` and `express-sequelize-injection` on one query).
- **Applied together, three changes that lose no true finding** (drop library files, keep test
  findings apart, one finding per line) **take the corpus from 868 findings to 359**, false alarms
  from 555 to 104, and keep all 239 true-positive lines on the vulnerable apps. Adding two more
  narrow filters (documentation/sample paths, hash-shaped values in password fields) brings it to
  341 findings and 86 false alarms, still with no true finding lost.
- **Two things that look attractive lose real findings:** running Django rules only on Django
  apps (loses 6 true findings), and a blanket hash filter on secret rules (loses a real hard-coded
  token secret).

## How it was run

- **Semgrep 1.179.0** from PyPI in a local virtual environment, `--metrics=off`,
  `SEMGREP_ENABLE_VERSION_CHECK=0`, local rule file only (semgrep.dev was not contacted).
  The earlier measurements used 1.176.0.
- **Rules:** `semgrep/semgrep-rules` at `a84ff9c` (22 September 2026, its HEAD). The measurement script
  walks it exactly as `tools/semgrep_rule_map.py` does (lowercased path plus the rule's own id),
  and writes one file holding every rule whose id is a key in the `semgrep` adapter's `rules` map,
  with the id rewritten to the registry form.
  - The map today has **1,035** keys (it was 1,022 at the earlier measurement; it has grown since).
  - **1,034** were found in the commit. The one missing is the single `trailofbits.*` key, which
    comes from Trail of Bits' rule repository, not `semgrep-rules`.
  - **Every SARIF lists 1,034 loaded rules**, and every reported rule id is a map key as written.
- **Files:** each app was given the file list `sv` itself would give: every file whose extension
  `sv`'s `language_of` knows (`.py .js .ts .go .rb .php .java .cs .kt .html .vue` and the rest),
  outside `sv`'s `SKIP_DIRS` (`node_modules`, `vendor`, `dist`, `build`, `out`, `target`, `.venv`,
  `coverage` and the rest, as they were on 4 October; since H6, `vendor`, `dist`, `build`, `out`, `target`, and
  `coverage` are left out only beside the manifest that explains them), by name, as the adapter's `{files}` does. So test folders were scanned
  (semgrep would skip them if given the folder), and `.json`, `.erb`, `.ejs`, `.jsp`, `.yml`,
  lockfiles and `.env` files were **not** given. Semgrep's own scanned-file list matched the list
  given for every app.
- **Verdicts:** I read the flagged code for **every finding in first-party code** (all 868 rows
  have a verdict; none is a default). Findings inside bundled library files were judged per file
  after reading at least 3 per rule (the flagged lines are library internals such as
  `data[action]()` in Bootstrap's carousel). "True" means the flagged code really does what the
  rule says and it is a weakness on reading the code, not on what the app's documentation
  promises. Where I could not tell, the verdict is "unsure" (12 rows).

### Corpus and what changed from the plan

- **Java vulnerable:** `ScaleSec/vulnado` would not clone (GitHub asked for credentials, so it is
  gone or private). **Substituted `CSPF-Founder/JavaVulnerableLab`** (82 `.java`/`.jsp` files; 20 of
  them are files `sv` reads, since `.jsp` is not one of its languages).
- **Added:** `juice-shop/juice-shop` (JS/TS vulnerable), and four more clean apps because the first
  clean set was so quiet: `miguelgrinberg/microblog` (Python, server-rendered Jinja), and three
  front ends (`react-redux-`, `angular-realworld-example-app`, `sveltejs/realworld`).
- **C#:** `gothinkster/aspnetcore-realworld-example-app` (clean) and `appsecco/dvcsharp-api`
  (vulnerable). **Kotlin:** no app run (nothing small found quickly; the map has only 10 Kotlin
  rules).
- **Not available here:** the golden apps and v1's template, which produced the earlier 148
  findings. So this corpus says nothing directly about those apps; see "What this means for the
  golden apps" below.

## 1. Per app

| App | Source (commit) | Language | Kind | Rules loaded | Files given / scanned | Time (s) | Findings | Parse/timeout warnings |
|---|---|---|---|---|---|---|---|---|
| flask-realworld | gothinkster/flask-realworld-example-app (4b95fb2) | Python | clean | 1034 | 30 / 30 | 16.5 | 1 | 0 |
| microblog | miguelgrinberg/microblog (a975ef6) | Python | clean | 1034 | 53 / 53 | 16.9 | 15 | 8 |
| pygoat | adeyosemanputra/pygoat (19d17cc) | Python | vulnerable | 1034 | 205 / 205 | 20.1 | 158 | 83 |
| vuln-flask | we45/Vulnerable-Flask-App (b6a4f97) | Python | vulnerable | 1034 | 9 / 9 | 30.6 | 31 | 0 |
| node-express-realworld | gothinkster/node-express-realworld-example-app (30b68e1) | JS/TS | clean | 1034 | 39 / 39 | 15.5 | 0 | 0 |
| react-redux-realworld | gothinkster/react-redux-realworld-example-app (ee72eba) | JS/TS | clean | 1034 | 39 / 39 | 14.9 | 2 | 0 |
| angular-realworld | gothinkster/angular-realworld-example-app (dd99ed2) | JS/TS | clean | 1034 | 61 / 61 | 15.4 | 4 | 0 |
| svelte-realworld | sveltejs/realworld (df79670) | JS/TS | clean | 1034 | 43 / 43 | 15.9 | 1 | 0 |
| nodegoat | OWASP/NodeGoat (c5cb68a) | JS/TS | vulnerable | 1034 | 68 / 68 | 16.2 | 23 | 14 |
| juice-shop | juice-shop/juice-shop (1618a61) | JS/TS | vulnerable | 1034 | 738 / 738 | 74.5 | 179 | 43 |
| gin-realworld | gothinkster/golang-gin-realworld-example-app (626c372) | Go | clean | 1034 | 23 / 23 | 15.4 | 1 | 0 |
| govwa | 0c34/govwa (4058f79) | Go | vulnerable | 1034 | 40 / 40 | 32.0 | 83 | 14 |
| rails-realworld | gothinkster/rails-realworld-example-app (a2ae4ff) | Ruby | clean | 1034 | 54 / 54 | 14.8 | 1 | 0 |
| railsgoat | OWASP/railsgoat (f5951f1) | Ruby | vulnerable | 1034 | 146 / 146 | 46.0 | 212 | 1 |
| laravel-realworld | gothinkster/laravel-realworld-example-app (e45c37c) | Php | clean | 1034 | 112 / 112 | 45.8 | 1 | 3 |
| dvwa | digininja/DVWA (43b0f8b) | Php | vulnerable | 1034 | 180 / 180 | 17.3 | 77 | 1 |
| spring-realworld | gothinkster/spring-boot-realworld-example-app (ee17e31) | Java | clean | 1034 | 116 / 116 | 16.3 | 3 | 0 |
| javavulnlab | CSPF-Founder/JavaVulnerableLab (626a106) | Java | vulnerable | 1034 | 20 / 20 | 27.7 | 66 | 0 |
| aspnet-realworld | gothinkster/aspnetcore-realworld-example-app (a397d11) | C# | clean | 1034 | 78 / 78 | 15.2 | 0 | 17 |
| dvcsharp | appsecco/dvcsharp-api (76c1de3) | C# | vulnerable | 1034 | 25 / 25 | 14.2 | 8 | 0 |
| ex-flask-booking | securevibe examples/flask-booking | Python | example | 1034 | 1 / 1 | 14.9 | 1 | 0 |
| ex-notes-with-users | securevibe examples/notes-with-users | Python/JS | example | 1034 | 2 / 2 | 15.8 | 0 | 0 |
| ex-oidc-notes | securevibe examples/oidc-notes | Python/JS | example | 1034 | 1 / 1 | 15.3 | 0 | 0 |
| ex-partly-passing | securevibe examples/partly-passing | Python/JS | example | 1034 | 3 / 3 | 14.8 | 1 | 0 |
| ex-tested-notes | securevibe examples/tested-notes | Python/JS | example | 1034 | 2 / 2 | 14.3 | 0 | 0 |

Notes:
- Roughly **14 to 15 seconds of every run is loading the 1,034 rules**: an example with one file
  took 14.3 to 15.8 s. Larger apps took 16 to 46 s; juice-shop (738 files) took 74.5 s.
- "Warnings" are semgrep's own, all at warning level: partial parses of HTML files that are really
  Django/Jinja/Swig/Go templates (pygoat 83, nodegoat 14, govwa 14, microblog 8, juice-shop 43),
  17 C# files in aspnet-realworld its C# parser could only partly read (a coverage gap for C#),
  and in laravel-realworld three rules **timing out on `public/js/app.js`**, a compiled bundle
  that `sv`'s file list hands over because `public/` is not a skipped folder.

### Totals

| | Findings | True | False | Unsure |
|---|---|---|---|---|
| Clean apps (11) and `sv` examples (5) | 31 | 5 | 24 | 2 |
| Vulnerable apps (9) | 837 | 296 | 531 | 10 |
| All | 868 | 301 | 555 | 12 |

The five true findings on clean apps: a JWT signing secret written as a constant
(`golang-gin-realworld-example-app` `common/utils.go:41`, used at line 51; value starts `A St`), and four
`missing-integrity` findings (CDN stylesheets without Subresource Integrity in the three front
ends). The two unsure: microblog's `next` redirect check (`app/auth/routes.py:26`, a netloc check
that a backslash-prefixed path may slip past in some browsers), and the `flask-booking` example's
XML import line (request XML parsed with ElementTree; stdlib ElementTree does not fetch external
entities, and entity-expansion risk depends on the expat version).

## 2. Per rule

All rules with 3 or more findings (108 rules fired in all; the rest are in `docs/semgrep-false-alarms.csv`).
"First-party precision" is true / (true + false) over findings outside library and test files.

| Rule | Total | On clean apps | On vulnerable apps | In library files | In test files | True | False | Unsure | First-party precision |
|---|---|---|---|---|---|---|---|---|---|
| `unsafe-dynamic-method` | 192 | 0 | 192 | 189 | 0 | 0 | 192 | 0 | 0/3 |
| `generic-api-key` | 59 | 1 | 58 | 0 | 46 | 4 | 54 | 1 | 4/12 |
| `prohibit-jquery-html` | 39 | 0 | 39 | 39 | 0 | 0 | 39 | 0 | - |
| `missing-integrity` | 36 | 4 | 32 | 0 | 0 | 36 | 0 | 0 | 36/36 |
| `insecure-document-method` | 32 | 0 | 32 | 22 | 0 | 4 | 26 | 2 | 4/8 |
| `insecure-innerhtml` | 29 | 0 | 29 | 20 | 0 | 4 | 24 | 1 | 4/8 |
| `detect-non-literal-regexp` | 29 | 0 | 29 | 27 | 0 | 0 | 29 | 0 | 0/2 |
| `django-no-csrf-token` | 27 | 4 | 23 | 0 | 0 | 18 | 9 | 0 | 18/27 |
| `no-csrf-exempt` | 25 | 0 | 25 | 0 | 0 | 25 | 0 | 0 | 25/25 |
| `tainted-sql-string` | 25 | 0 | 25 | 0 | 0 | 21 | 4 | 0 | 21/25 |
| `detected-generic-secret` | 18 | 0 | 18 | 0 | 17 | 1 | 17 | 0 | 1/1 |
| `detected-jwt-token` | 17 | 2 | 15 | 0 | 15 | 2 | 15 | 0 | 2/2 |
| `tainted-exec` | 17 | 0 | 17 | 0 | 0 | 13 | 4 | 0 | 13/17 |
| `html-in-template-string` | 17 | 0 | 17 | 0 | 11 | 4 | 13 | 0 | 4/6 |
| `jwt` | 16 | 2 | 14 | 0 | 14 | 2 | 14 | 0 | 2/2 |
| `eval-detected` | 13 | 0 | 13 | 5 | 1 | 6 | 7 | 0 | 6/7 |
| `tainted-filename` | 12 | 1 | 11 | 0 | 0 | 10 | 2 | 0 | 10/12 |
| `django-secure-set-cookie` | 10 | 0 | 10 | 0 | 0 | 8 | 2 | 0 | 8/10 |
| `var-in-href` | 10 | 6 | 4 | 0 | 0 | 1 | 9 | 0 | 1/10 |
| `plaintext-http-link` | 10 | 0 | 10 | 0 | 0 | 0 | 10 | 0 | 0/10 |
| `exec-use` | 9 | 0 | 9 | 0 | 0 | 7 | 2 | 0 | 7/9 |
| `detect-redos` | 8 | 0 | 8 | 7 | 0 | 1 | 7 | 0 | 1/1 |
| `jdbc-sqli` | 8 | 0 | 8 | 0 | 0 | 6 | 0 | 2 | 6/6 |
| `dangerous-subprocess-use-audit` | 7 | 1 | 6 | 0 | 0 | 2 | 5 | 0 | 2/7 |
| `template-unescaped-with-safe` | 7 | 0 | 7 | 0 | 0 | 4 | 3 | 0 | 4/7 |
| `raw-html-format` | 6 | 0 | 6 | 0 | 0 | 6 | 0 | 0 | 6/6 |
| `cookie-missing-httponly` | 6 | 0 | 6 | 0 | 0 | 5 | 1 | 0 | 5/6 |
| `unsafe-template-type` | 6 | 0 | 6 | 0 | 0 | 6 | 0 | 0 | 6/6 |
| `weak-hashes-md5` | 6 | 0 | 6 | 0 | 2 | 4 | 2 | 0 | 4/4 |
| `mvc-missing-antiforgery` | 6 | 0 | 6 | 0 | 0 | 0 | 6 | 0 | 0/6 |
| `sequelize-raw-query` | 6 | 0 | 6 | 0 | 0 | 2 | 4 | 0 | 2/6 |
| `express-sequelize-injection` | 6 | 0 | 6 | 0 | 0 | 2 | 4 | 0 | 2/6 |
| `insecure-hash-algorithm-md5` | 5 | 1 | 4 | 0 | 0 | 4 | 1 | 0 | 4/5 |
| `var-in-script-tag` | 5 | 0 | 5 | 0 | 0 | 1 | 4 | 0 | 1/5 |
| `use-defused-xml` | 5 | 2 | 3 | 0 | 1 | 3 | 1 | 1 | 3/3 |
| `formatted-sql-string` | 5 | 0 | 5 | 0 | 0 | 5 | 0 | 0 | 5/5 |
| `avoid-pickle` | 4 | 0 | 4 | 0 | 0 | 2 | 2 | 0 | 2/4 |
| `md5-used-as-password` | 4 | 0 | 4 | 0 | 0 | 4 | 0 | 0 | 4/4 |
| `direct-use-of-httpresponse` | 4 | 0 | 4 | 0 | 0 | 0 | 4 | 0 | 0/4 |
| `disabled-cert-validation` | 4 | 0 | 4 | 0 | 4 | 0 | 4 | 0 | - |
| `code-string-concat` | 4 | 0 | 4 | 0 | 0 | 4 | 0 | 0 | 4/4 |
| `use-of-md5` | 4 | 0 | 4 | 0 | 0 | 2 | 0 | 2 | 2/2 |
| `formatted-template-string` | 4 | 0 | 4 | 0 | 0 | 4 | 0 | 0 | 4/4 |
| `cookie-missing-secure-flag` | 4 | 0 | 4 | 0 | 0 | 4 | 0 | 0 | 4/4 |
| `express-res-sendfile` | 4 | 0 | 4 | 0 | 0 | 2 | 2 | 0 | 2/4 |
| `insecure-deserialization` | 3 | 0 | 3 | 0 | 0 | 2 | 1 | 0 | 2/3 |
| `unquoted-attribute-var` | 3 | 0 | 3 | 0 | 0 | 0 | 3 | 0 | 0/3 |
| `detected-bcrypt-hash` | 3 | 0 | 3 | 0 | 0 | 0 | 3 | 0 | 0/3 |
| `check-unsafe-reflection` | 3 | 0 | 3 | 0 | 0 | 3 | 0 | 0 | 3/3 |
| `no-direct-response-writer` | 3 | 0 | 3 | 0 | 0 | 3 | 0 | 0 | 3/3 |
| `tainted-sql-from-http-request` | 3 | 0 | 3 | 0 | 0 | 3 | 0 | 0 | 3/3 |

How the rules named in the brief came out:

| Rule | Here | Verdict |
|---|---|---|
| `unsafe-dynamic-method` | 192, all on vulnerable apps | 189 in bundled libraries; the 3 in first-party code are false (a fixed method list, a contract ABI). **0 true.** |
| `generic-api-key` | 59 | 46 in test files (juice-shop's test passwords and TOTP seeds, one Angular spec). First-party: 4 true (pygoat's pasted session cookie twice, NodeGoat's ZAP key in dev config, dvcsharp's token secret), 8 false (7 hex password digests in pygoat, 1 help-page example in DVWA), 1 unsure (juice-shop's expected OAuth password in `routes/login.ts:64`). |
| `detect-non-literal-regexp` | 29 | 27 in bundled libraries, 2 on juice-shop's own challenge keys. **0 true.** |
| `html-in-template-string` | 17 | 11 in tests; 4 true (juice-shop's documented XSS, each next to `bypassSecurityTrustHtml`); 2 false (config values). |
| `var-in-href` | 10 | 6 on microblog (links built by `url_for`), 3 on links built from config or the app's own routes; **1 true** (NodeGoat's profile link, documented). |

## 3. Why the false alarms happen

All 555 false alarms, by cause (the column on the right is how many fell on the clean apps and
examples):

| Cause | False alarms | Of which on clean apps |
|---|---|---|
| Third-party library or minified/obfuscated file kept in the app | 317 | 0 |
| Test or fixture code | 112 | 6 |
| Value comes from the app's own config, constants, or an allowlist, not a visitor | 33 | 6 |
| Documentation, tutorial, sample, or dead/commented code that does not run | 30 | 0 |
| The framework or template engine already escapes or protects it | 20 | 6 |
| Secret rule matched a hash or a public identifier, not a secret | 11 | 0 |
| Not a security use (MD5 for a Gravatar URL, a cookie being deleted, pickling the app's own object) | 10 | 1 |
| Input is validated or restricted in a way the rule does not see | 8 | 0 |
| Rule does not apply to this kind of app (CSRF rules on a bearer-token JSON API) | 7 | 1 |
| Developer or install tooling, not reachable from a request | 5 | 3 |
| Rule misfire (the protection is on the flagged lines) | 2 | 1 |

What the main ones look like:
- **Library files:** railsgoat keeps 16 libraries in `app/assets/javascripts/` (191 false alarms, plus 2 in an
  IcoMoon icon-font helper; its own Ruby code got 17 true findings and no false alarm outside tests); govwa keeps jQuery and Bootstrap in `public/js/` (43);
  JavaVulnerableLab keeps jQuery 1.6.4 in `src/main/webapp/` (32); Vulnerable-Flask-App keeps
  Google's chart loader in `app/static/` (13); juice-shop keeps `dat.gui.min.js` and `three.js` in
  `frontend/src/assets/private/` (28). None of these folders is in `SKIP_DIRS`. (Old jQuery
  versions have real published flaws, but that is a dependency finding; these rules flag
  unrelated internal lines.)
- **Test code:** juice-shop's API tests log in with fixed passwords and TOTP seeds and carry
  sample JWTs (99 findings across `generic-api-key`, `detected-generic-secret`, `jwt`,
  `detected-jwt-token`, `html-in-template-string`); the clean apps' JWT service tests do the same.
- **Escaping the rule cannot see:** Flask-WTF's `form.hidden_tag()` (microblog, flagged by a
  *Django* CSRF rule), Django's `render_to_string`, Angular interpolation, Go's `html/template`.
- **Not applicable:** CSRF rules on APIs that take a bearer token in a header
  (`spring-csrf-disabled` on spring-realworld, `mvc-missing-antiforgery` six times on dvcsharp).

Overlap is separate from cause: 309 findings repeat a file and line another finding already names
(two to three rules on one line, and in a few cases one rule twice on the same line, such as
`tainted-exec` in DVWA).

## 4. Reductions `sv` could apply, simulated

Each filter was applied to the judged findings. "True lost" counts true findings on the vulnerable
apps that would no longer be shown in the main list.

| Filter | Removed | Clean-app false alarms removed | Vulnerable-app false alarms removed | True lost |
|---|---|---|---|---|
| A. Treat bundled library files as not the app's code (`*.min.js`, any line of 500+ characters, or a license/author banner on a file named like a known library) | 315 | 0 | 315 | **0** |
| B. Test files listed apart (`sv` already does this) | 112 | 6 | 106 | **0** |
| G. One finding per file and line, other rules folded in | 309 | 2 | 249 | **0** (the line is still shown) |
| E. Paths named `docs`, `tutorial`, `help`, `codefixes`, `examples`, `samples` | 20 | 0 | 20 | **0** |
| C2. Secret rules skip a hex digest or bcrypt hash assigned to something named password/hash/digest | 7 | 0 | 7 | **0** |
| C. Secret rules skip any hex-digest-shaped value | 10 | 0 | 8 | **2** (dvcsharp's real token secret, `Models/User.cs:17`, value starts `f449`: a 32-hex-character string that is a key, not a hash) |
| D. `python.django.*` rules only for apps that use Django | 10 | 4 | 0 | **6** (Django's taint rules caught Flask SQL injection and XSS in Vulnerable-Flask-App; `django-no-csrf-token` caught missing CSRF tokens in NodeGoat and govwa) |
| D2. Only `django-no-csrf-token` gated to Django apps | 8 | 4 | 0 | **4** |
| F. A broad "worth a look" tier (`unsafe-dynamic-method`, `prohibit-jquery-html`, `detect-non-literal-regexp`, `plaintext-http-link`, `var-in-href`, `missing-integrity`, `detect-non-literal-require`, `unquoted-attribute-var`) | 321 | 6 | 278 | **33** (mostly `missing-integrity`, which was right every time) |
| F2. A narrow "worth a look" tier: `unsafe-dynamic-method`, `detect-non-literal-regexp`, `prohibit-jquery-html`, `plaintext-http-link`, `var-in-href` | 280 | 6 | 273 | **1** (NodeGoat's `profile.html:78`) |

Combined (each set includes G):

| Combination | Findings left | False left (clean / vulnerable) | True lines on vulnerable apps kept |
|---|---|---|---|
| None (as run) | 868 | 24 / 531 | 239 of 239 |
| A + B + G | 359 | 18 / 86 | 239 of 239 |
| A + B + C2 + E + G | 341 | 18 / 68 | 239 of 239 |
| A + B + C2 + E + G + F2 | 321 | 12 / 55 | 238 of 239 |

(Findings are 296 true on the vulnerable apps; folded to one per line they are 239 lines.)

By language, findings judged false before and after A + B + C2 + E + G:

| Language | Clean apps: false before → after | Vulnerable apps: false before → after | Vulnerable apps: true before → after (lines) |
|---|---|---|---|
| Python (flask-realworld, microblog, examples / pygoat, Vulnerable-Flask-App) | 16 → 15 | 50 → 26 | 136 → 121 |
| JS/TS (4 clean / NodeGoat, juice-shop) | 3 → 0 | 166 → 14 | 35 → 26 |
| Go (gin / govwa) | 0 → 0 | 59 → 13 | 22 → 17 |
| Ruby (rails / railsgoat) | 1 → 1 | 195 → 1 | 17 → 16 |
| PHP (laravel / DVWA) | 1 → 1 | 23 → 8 | 53 → 36 |
| Java (spring / JavaVulnerableLab) | 3 → 1 | 32 → 0 | 31 → 22 |
| C# (aspnetcore / dvcsharp) | 0 → 0 | 6 → 6 | 2 → 1 |

The drop in "true" there is only folding: every true line is still shown once.

What is left after the safe filters is mostly the long tail: values from the app's own config (21),
escaping the rule cannot see (13), documentation and links (10), CSRF rules on token APIs (6).
Each is a handful of findings spread over many rules, which a per-rule switch does not fix well.

## 5. Recommendation, ranked

1. **Treat bundled library files as not the app's code** (filter A). By far the biggest cut: 315
   false alarms, none on a real fault. It matters most for Ruby (191 of railsgoat's 195 false alarms), Java,
   Go, and any app that keeps jQuery or Bootstrap in `public/`, `static/` or `assets/`. Detect by
   `*.min.js`, very long lines, and a known library's banner; better still, by matching a known
   library's file (the way retire.js does) so a first-party file with a long line is never hidden.
   Show them apart ("in bundled third-party code"), not silently dropped, and leave the dependency
   question to the dependency scan. It also removes the timeouts on built bundles such as
   Laravel's `public/js/app.js`.
2. **Keep test-code findings apart, including the secret rules** (filter B, already `sv`'s
   practice): 112 false alarms, none real. Make sure the secret rules' findings in tests are
   included in that split.
3. **Fold findings on the same line into one**, listing every rule and requirement it touches
   (G): 309 fewer rows and nothing lost. Two or three rules on one SQL query read as three faults
   today.
4. **Narrow secret-rule exceptions** (C2), and look at what `sv` hands semgrep: a hex digest or
   bcrypt hash assigned to a password or hash field is not a key (7 false, 0 lost). Do not skip
   every hex-shaped value: that hides a real 32-character token secret.
5. **Then, if more is wanted, a narrow "worth a look" tier** for `unsafe-dynamic-method`,
   `detect-non-literal-regexp`, `prohibit-jquery-html`, `plaintext-http-link` and `var-in-href`
   (F2): of their 274 findings on the vulnerable apps, 1 was true and 273 false, and all 6 on the
   clean apps were false. It costs one real XSS (NodeGoat's profile link). Keep `missing-integrity` out of
   that tier: it was right 36 times out of 36 (though it carries no requirement in the map, only
   `findings_against` V3.6.1).
6. **Do not gate the Django rules by framework.** Their taint rules found real Flask SQL injection
   and XSS, and the CSRF-token rule found real missing tokens in Express and Go templates.

**Since (6 October 2026):** (1) is built: a copy of a known library kept in the app has its findings listed after the
app's own, named for the library, and still counted (DESIGN, "A copy of another project's library is listed apart").
(2) needed no change, since the secret rules' findings in test code were already kept apart, and (4) is built narrower
than C2: it spares a stored bcrypt hash and a hex digest under a name that says hash or digest, but not a hex value
under a name that says only password, so it removes 3 of C2's 7 false alarms (DESIGN, "Semgrep follow-ups 2 and 4").
(3), one finding per line, is not built.

Per language: Ruby, Java and Go need only (1); JS/TS needs (1) and (2); Python's remaining noise is
the long tail on microblog (6 `var-in-href`, 4 Django CSRF on a Flask-WTF app, 3 developer CLI
commands) and is best served by (5) and, later, a "this app uses Flask-WTF/Jinja autoescape" hint;
PHP and C# are small either way.

## What this means for the golden apps

The earlier 148 findings on the golden apps were mostly `var-in-href` (68) and `generic-api-key`
(57, on the hashes in `securevibe.provenance.json`). Two things from this run bear on that, and
neither could be checked against those apps here:
- **`sv`'s own file list does not include `.json` files** (`language_of` has no JSON), so if `sv`
  hands semgrep its code files by name, `securevibe.provenance.json` is never scanned and those 57
  cannot occur in a real `sv` run. If the earlier measurement scanned the folder instead, it
  counted findings `sv` would not produce. Worth confirming before designing a lockfile/provenance
  exclusion: under `sv`'s file list there was nothing for such an exclusion to do in this corpus.
- `var-in-href` behaved here as it did there: 9 of 10 false, all on links the server builds.

## Limits

- The verdicts are one reader's. 12 are "unsure". Vulnerable apps are full of planted faults, so
  precision measured on them flatters every rule; the clean apps are the fairer test of noise, and
  they gave too few findings (31) for per-rule rates.
- The library-file test was written with this corpus in view (it needed `@author` and the names
  `three` and `dat.gui` added to catch juice-shop's files). A shipped version should be checked on
  apps it has not seen.
- Filter E's path names include `codefixes`, which is juice-shop's own folder; without it E removes
  fewer.
- Kotlin was not run; the C# clean app was partly unparsed (17 files).
- Semgrep 1.179.0, not the 1.176.0 of the earlier runs.
