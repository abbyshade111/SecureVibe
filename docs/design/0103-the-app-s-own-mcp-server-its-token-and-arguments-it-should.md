# The app's own MCP server: its token, and arguments it should refuse (3 October 2026)

Three new settings under `[stack.run.mcp-server]`:
- **`token-env`.** For a server that takes one fixed access token, the variable it reads it from. Each run makes a
  new random token, gives it to the app in that variable, and sends it as `Authorization: Bearer` with every request
  (the control). The token goes only to the app and to these requests, and is written nowhere.
- **`public = true`.** The server is meant to answer anyone, so whether it checks a token is not asked.
- **`probe-tool`.** A tool that is safe to call again and again, and arguments it accepts.

**C10.2.1, the token.** With the run's token, a session starts and the tools are listed. Then come three requests
without it: a session started with no token, one with a made-up token, and the tools listed with no token inside a
session the token started. The last asks whether the server checks the token on every request, not only when a
session starts. Any of the three answered is `probe.mcp-server-token-unchecked` (high). All three refused is
credited. A server error, or no answer, is not a refusal. A server that checks tokens from a sign-in service
(OAuth) cannot be given one yet.

**C10.4.3, C10.4.4, and C10.4.5, the tool.** The tool is called as `probe-tool` says (the control). It must answer
with a result, or nothing else is asked. Then:
- with an argument it never declared, and with one argument a million characters long. Either answered with a result
  is `probe.mcp-server-takes-unknown-or-oversized-arguments` (C10.4.3), and both refused is credited;
- with an object where its listed schema declares a string, a value no library would coerce. Answered is
  `probe.mcp-server-takes-wrong-types` (C10.4.4), and refused is credited;
- last, the control call inside a request of eight megabytes. Answered is `probe.mcp-server-no-size-limit`
  (C10.4.5). It is only ever a finding, since the requirement names no size; a refusal is said. It goes last, so a
  server with no limit that falls over takes no other question with it.

A refusal is an HTTP error below 500, a JSON-RPC error, or the tool's own error (`isError: true`). A server error,
or no answer, is neither a result nor a refusal. The existing session-end question (C10.2.6) ends its session on
purpose, so the tool questions start their own.

Tried on 3 October 2026 with `sv report --run` against two small MCP servers written in Python's standard library.
The careful one (checks the token, the schema, and a 2 MB limit) was credited for C10.2.1, C10.4.3, and C10.4.4, and
for the existing C10.3.3 and C10.2.6, which a token-taking server could not be asked before. Its refusal of the large
request was said, not credited. The careless one was found for all five. The first try of the careful one was
reported as not assessed, rightly: its own host check refused the run's container name. Twelve guards broken in turn,
each caught. One was caught by nothing at first: the `public` setting's test passed whatever the code did, because
the message it looked for appeared in another message too.
