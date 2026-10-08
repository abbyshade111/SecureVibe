# Protection against forged requests switched off (8 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 3.3; BACKLOG, item 11, one of its rules). Plain `sv check` had no rule
for the line an AI coding tool most often writes when a form or a fetch fails with "CSRF token missing": the one that
switches the framework's request-forgery protection off.

`ast.csrf-protection-off`, in `data/ast-rules.json`, finds the explicit switches: `@csrf_exempt` and `csrf_exempt(view)`
in Django and `@csrf.exempt` in Flask-WTF; `WTF_CSRF_ENABLED = False` in Flask-WTF, however it is set (a class attribute,
`app.config[...]`, `config.update(...)`, a dictionary); `skip_forgery_protection` and `skip_before_action
:verify_authenticity_token` in Rails; `csrf().disable()`, `csrf(c -> c.disable())`, and `csrf(AbstractHttpConfigurer::disable)`
in Spring Security; `[IgnoreAntiforgeryToken]` and `DisableAntiforgery()` in ASP.NET Core; and `checkOrigin: false` in
SvelteKit and Astro. Medium severity and medium confidence, citing V3.5.1, and only ever a finding: an API that signs
people in with a token in a header rather than a cookie has no use for the protection, and the finding's fix says so.

Each language's match is judged on the whole text of the node it captures (a decorator, a call, an assignment, a pair),
so one pattern can tell `= False` from `= True` and `skip_before_action :verify_authenticity_token` from
`skip_before_action :authenticate_user!`. Not looked for: Rails' `allow_forgery_protection = false`, which Rails itself
writes into every app's test settings; Laravel's lists of excepted paths, where a webhook's path cannot be told from a
form's in one file; Spring's Kotlin syntax; and protection that was never turned on, in Go's and Express's libraries
among others.

Tests: twenty-eight cases in the AST rules' table, each switch found and its safe neighbor left alone (`@csrf_protect`,
`= True`, the `csrf_exempt` import, a `csrf_exempt_paths` list, `before_action :verify_authenticity_token`,
`http.cors().disable()`, `[ValidateAntiForgeryToken]`, `checkOrigin: true`). `sv check` on a small app gave one finding
for each switched-off line and none twice. Nine guards broken in turn: the decorator never matched, `= True` counted,
`csrf_exempt(view)` missed, any `skip_before_action` counted, Rails' bare `skip_forgery_protection` missed, any Java
`disable()` counted, `[ValidateAntiForgeryToken]` counted, and `checkOrigin: true` counted were each caught at once; the
ninth, `csrf_exempt` matched anywhere in the text rather than as the whole name, went uncaught until the
`csrf_exempt_paths` case was added, and is caught now.
