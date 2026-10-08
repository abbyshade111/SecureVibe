# A `ws://` address written into the code (V4.4.1)

V4.4.1 asks that every WebSocket is encrypted (`wss://`). It had been reached through semgrep's
`detect-insecure-websocket`, which is in no pack the adapter runs, so the honest count took it away.
It is now a rule of `sv`'s own, `ast.plaintext-websocket-url`, and needs no outside tool.

Two things were missing, and neither turned out to need Rust per rule:

- **A rule over a string literal.** The backlog said every rule matches a call, so a literal
  "would mean a new kind of rule". The engine already takes any query, and applies
  `argumentPatterns` to whatever `@arg` captures; a query that captures the literal itself as both
  `@hit` and `@arg` matches literals. One per language, over its grammar's string nodes (Python's
  `string`, Go's two string literals, JavaScript's quoted and template strings, a shell word as well
  as a quoted one, and so on), in all fourteen languages `sv` reads.
- **A rule that is only ever a finding.** A code rule that finds nothing is credited, and here that
  would be wrong: the address is usually built at run time from the page's own, and no rule can see
  it. `findingsOnly` on an AST rule keeps it out of the clean results, and `coverage.py` shows it
  "only ever as a finding", as it does for an outside tool's rule.

The pattern is a `ws://` address with something after it that starts a host name. A bare `"ws://"`,
as in `url.replace("ws://", "wss://")`, is not one; `localhost`, `127.0.0.1`, `[::1]`, and `0.0.0.0`
are left out, since they never leave the computer. A template that builds the address from a value
is left out too: it may be `wss://` when served over HTTPS. Level 1 goes from 52 to 53 of 70.

Every language has a found case and a not-found case, with the localhost, bare-scheme, and template
cases beside them. Each part was removed in turn: crediting a clean run, the localhost exception, the
host in the pattern, the coverage annotation, and one language's query; every one was caught.
