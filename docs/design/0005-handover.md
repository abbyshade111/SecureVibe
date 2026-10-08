# Handover

`sv check ./my-app` is the primitive: any tool, any editor, CI. An MCP server wrapping the same core comes
second, so an AI coding tool can run the checks mid-conversation and work the findings without the user leaving
the chat. The CLI is what makes it tool-agnostic; MCP is what makes the loop tight.


### As built (25 September 2026)

`sv mcp` is a module of the CLI rather than a crate of its own, because what it serves is the CLI's
report: `assemble_report` was pulled out of `sv report` so both call one function, and a model is told
exactly what a person reads — not a second summary that drifts. It speaks JSON-RPC over stdio with no SDK;
the surface it needs is four methods. It reads only below the folder it was started for, resolving `..`
and symbolic links before checking, because a model can be talked into asking for `~/.ssh` by text it
read somewhere. It does not offer `--run` or `--tools`: both run code, and a model deciding to run code in
a loop is exactly the decision that should stay with a person. The tool result lists what was not
examined before any finding, for the reason every report here does.
