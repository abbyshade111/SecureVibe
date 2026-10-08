# An app that serves tools over MCP (27 September 2026)

`sv`'s self-assessment (`docs/paper/SELF-ASSESSMENT-V2.md`) found that a manifest could not say
"this app is an MCP server". AISVS C10, the Model Context Protocol chapter, hung whole on `mcp`, which
asks whether the app's AI *uses* MCP tools. So an app that serves tools to AI models, and may have no
AI of its own (`sv` is one), was never asked about the server's side: whether it validates the access
token on every request, checks the Origin and Host headers, rejects parameters it does not know,
limits payloads. That is the surface of `sv`'s one tool-misuse incident (#77).

- **A question of its own,** `mcp-server` under `[capabilities]`, and deliberately not under
  `[capabilities.ai]`, where every question reads "no" once the app says it has no AI. A server needs
  no AI, and answering "no AI" must not answer this. `sv`'s own `securevibe.toml` answers yes.
- **C10 split by side,** with rules at the requirement or section level, which win over the chapter's:
  the server's requirements (C10.2, C10.3.3, C10.4.3, C10.4.4, C10.4.6) turn on `mcp-server`; the
  client's stay on the chapter's `mcp`; and the four about the connection between the two (C10.3.1,
  C10.3.2, C10.3.5, C10.4.5) carry one rule for each side, which are OR-ed, so they apply when either
  is true. Unanswered stays *not assessed*.
- **Evidence from the code,** only ever toward applying: a FastMCP or McpServer object, the SDK's
  server module, `server.NewMCPServer(` or `mcp.NewServer(` in Go, `rmcp::handler::server` or an
  `impl ServerHandler for` in Rust. Only the server's side is listed, so an app whose AI calls MCP tools
  is not taken for a server. A server written by hand over JSON-RPC, as `sv`'s is, leaves nothing to
  tell it apart, so absence settles nothing.

On a bare app that answers `mcp-server = true` with no AI, the server's requirements and the shared
ones apply and the client's are set aside, where before all of C10 was. On `sv`'s own repository the
count does not move yet: a test fixture containing `from mcp` already switches `mcp` on for it and
brings in the whole chapter, which is the self-assessment's first finding, and a separate entry.

Tested in the applicability engine (a server with no AI, a client, both, neither, and unanswered), in
the manifest (the answer kept when the app has no AI, and unanswered left unanswered), and in the
scanner (FastMCP and TypeScript servers found, two Python clients not taken for one), and through the
binary on a bare app, with its own control. Seven breaks were made in turn, and each turned two or more
tests red.
