# Cross-origin settings that let any site in with credentials (8 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 3.3; BACKLOG, item 11, one of its rules). `sv run` finds an app that
answers any origin with credentials (`probe.cors-any-origin`), but only when the app runs; plain `sv check` did not read
the settings that make it do so.

`ast.cors-any-origin-with-credentials`, in `data/ast-rules.json`, finds CORS settings that accept every origin and also
allow credentials, which together send back whatever origin asked: flask-cors' `CORS(app, supports_credentials=True)`
(or `cross_origin`) with no `origins` or `resources`; `origin: true` or `/.*/` with `credentials: true` for Express's
`cors` or Fastify's plugin; Spring's `allowedOriginPatterns("*")`, `addAllowedOriginPattern("*")`, or
`originPatterns = "*"` with `allowCredentials(true)` in the same method or annotation, chained or set one by one; and
ASP.NET Core's `SetIsOriginAllowed(_ => true)` with `AllowCredentials()`. High severity, citing V3.4.2, and only ever a
finding.

Not looked for: `origin: "*"` with credentials, which browsers refuse, and the pairs frameworks refuse at start
(`AllowAnyOrigin().AllowCredentials()` in ASP.NET Core, `origins '*'` with `credentials: true` in rack-cors); Django's
two settings, which sit on separate lines; Go's libraries; headers set by hand; and a list of origins built at run time.

Tests: twenty-one cases in the AST rules' table, each permissive setting found and its safe twin left alone (a named
origin, no credentials, `credentials: false`, `allowedOrigins` with one site, `WithOrigins`). Ten guards broken in turn,
each caught: flask-cors' list of origins ignored, its credentials not required, JavaScript's credentials not required or
`false` counted, Fastify missed, TypeScript never matched, Spring's credentials not required, its setters missed, its
annotation missed, and ASP.NET Core's credentials not required.
