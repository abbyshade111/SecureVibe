# The newer protocol versions, 2025-11-25 and 2026-07-28 (3 October 2026)

The MCP server spoke versions up to 2025-06-18. Two later ones are published, read this day from the specification's
own repository (`schema/<version>/schema.ts` and each version's changelog), and the server now speaks both (BACKLOG,
"Improving the MCP server", item 6).

**2025-11-25** changes little for a server that offers only tools over stdio. It is now the version a client gets when
it opens with `initialize` and asks for it, or asks for one the server does not know. One change applies: arguments
that are wrong are to be answered as a tool's result, which the model reads and can correct, rather than as a protocol
error. Arguments that are not an object are now answered that way. The tool names already keep to its guidance
(letters, digits, `_`, `-`, `.`; at most 128), and a test holds them to it. Its other changes are about sign-in,
elicitation, sampling, tasks, and the HTTP transport, none of which this server uses.

**2026-07-28** makes the protocol stateless. There is no `initialize`: each request names its version (and the
client's capabilities) in `_meta`, every result carries `resultType`, and the server names itself in each result's
`_meta`. A server must answer `server/discover` with the versions it supports. `ping` is gone. `tools/list` says how
long it may be kept (`ttlMs`) and by whom (`cacheScope`). A version the server does not speak is answered with
`UnsupportedProtocolVersionError` (-32022), naming the version asked for and the ones supported.

The server speaks both, as the 2026-07-28 text allows: a request that names its version in `_meta`, or a
`server/discover` probe, is answered statelessly; any other is answered as a client that opened with `initialize`
expects, exactly as before, with nothing of the stateless protocol added to its results. The tool list may be kept an
hour by anyone, since it is the same for everyone who runs this version of `sv`; the discovery result only by the one
client, since its instructions name where this `sv` is on this computer. The unsupported-version error lists every
version the server speaks, as the specification's own example does.

One test sends the stateless requests (discovery with and without a version, the tool list, a tool call, a version
it does not know, `ping`, `initialize`) and an initializing client's, and checks each answer. Nine ways broken, each
caught: any version served, results not marked complete, results not signed, a probe without a version not answered,
`ping` kept, 2025-11-25 not offered, the tool list without how long to keep it, the discovery result cacheable by
anyone, and wrong arguments answered as a protocol error.

**Not done here.** The client's capabilities, which 2026-07-28 makes required on every request, are not demanded:
this server needs none of them, so a request without them is still answered. The tasks extension is not offered.
Progress notifications were not offered then either; they are now (see "Saying how a check is going").
