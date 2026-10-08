# Who set a finding aside: what securevibe.toml says, not "a person" (4 October 2026)

The deep review's R1. A `[[finding-review]]` entry, or a `confirmed` entry under `[design]`, counts only when its `by`
names somebody other than the AI coding tool, and the report then said the finding was "set aside by a person" or the
answer "confirmed by a person". But `sv` only reads the name in the file: an AI coding tool that writes
`by = "owner"` was shown as the owner's decision, and the report vouched for a person nobody had seen.

Now every report says where the decision is recorded and what the entry says, never that a person made it:

- The section is "Set aside in securevibe.toml", and opens by saying that each entry names who decided, that `sv` reads
  that name and cannot tell who really wrote the entry, and that an AI coding tool can write one as easily as a person.
- Each false alarm reads "securevibe.toml says the owner set it aside as a false alarm on (date)", and each accepted
  risk "securevibe.toml says (name) accepted it on (date)", with "sv cannot tell who wrote that entry".
- A confirmed answer is "stated by the AI coding tool, confirmed in securevibe.toml", resting on "the word of whoever
  securevibe.toml says confirmed it, which sv cannot check", and its evidence line reads "securevibe.toml says you
  confirmed it on (date)".
- What the AI coding tool is told through MCP is headed "SET ASIDE IN securevibe.toml" and says never to write an entry
  naming the person in `by` itself.

Twelve wordings put back in turn, and each was caught.

Not done, and left for the owner to decide: the review's better fix, an interactive `sv review` that refuses input that is
not a terminal and keeps its record outside the app's folder, with entries in securevibe.toml then counting only as
proposals. That changes how the owner records every decision, so it is the owner's call. Showing the entry's git author
was considered and left out: an AI coding tool commits under the owner's own git name, so the author would vouch for the
owner just as `by` does, and look like more evidence than it is.
