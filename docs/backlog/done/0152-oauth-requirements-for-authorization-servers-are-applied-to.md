# OAuth requirements for authorization servers are applied to OAuth clients

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Done on 25 September
2026 by session securevibe-e9. A second condition, `authorization-server`, gates V10.4, V10.6, and
V10.7, so an app with "Sign in with Google" keeps the client's requirements (V10.1, V10.2, V10.3,
V10.5) and is no longer asked about a server it does not run. Running one is a way of using OAuth, so
`oauth = false` answers it without anyone rewriting a manifest, while an explicit yes always wins over
that entailment. It has a corroborator, from which dual-purpose libraries — Authlib above all — are
deliberately absent: putting `authlib` back in its package list undid the fix and passed the entire
suite, so there is now a test that writes a `requirements.txt`. See DESIGN, "Using OAuth and being the
authorization server". For v1 no requirement moves buckets; only the exclusion reason changes.
