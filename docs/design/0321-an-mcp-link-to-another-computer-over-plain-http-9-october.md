# An MCP link to another computer over plain HTTP (9 October 2026)


AISVS C10.3.1 asks that a link to a remote MCP server is authenticated, encrypted streamable HTTP (ADR-068).
`config.mcp-transport-unencrypted` reads the files `config.mcp-server-unpinned` reads, in the same pass: the app's
configuration and code, not the AI coding tool's own files, which ADR-049 grades apart. It finds an `http://`
address in two places. The first is the first argument of a known MCP client transport, in the ways the SDKs and
agent libraries open one: `new StreamableHTTPClientTransport(new URL("…"))`, `SSEClientTransport`,
`streamablehttp_client("…")`, `sse_client`, `MCPServerStreamableHttp`, `MCPServerSse`. The second is a `url`,
`serverUrl` or `server_url` with MCP named within the 400 characters before it, which is how a configuration file's
`mcpServers` table and the agent libraries' server tables write one.

An address counts only when it leaves the app's own computer and network: loopback, private and link-local
addresses, names under `.localhost`, `.local` and `.internal`, and any name with no dot (which is `localhost`, a
service on the same Docker network, or a name built at run time) are left out. It is only ever a finding (medium): an
`https://` address shows neither that the link asks for a token nor that it is the app's only one, so a clean reading
credits nothing, and `tools/coverage.py` lists the check as finding only. The old SSE transport is not found as such:
over `https://` it is encrypted.

Checked: the launch tests, with each kind of address found and each kind left alone. Fifteen breaks, one at a time.
The first nine found that the private-address rule, the no-dot rule, the MCP-word rule, both patterns, and the
developer-file filter were each caught, and that three were not. A loopback IP had no case; it was added and is
caught. The `localhost` and `${HOST}` rules could never fire, because the no-dot rule already drops both, so they
were taken out. Five more breaks followed, after cases were added for `.localhost` and `.internal` names: those two
rules and the loopback rule were caught. Widening either pattern to `https://` alone was not caught, because
`https://` is kept out twice, by the patterns and by the address reader, so the reader now says so on purpose. A
fifteenth break, widening a pattern and the reader together, is caught.
