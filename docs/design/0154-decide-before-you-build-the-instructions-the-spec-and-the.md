# Decide before you build: the instructions, the spec, and the design-time prompts as MCP prompts (4 October 2026)

Items 1, 2, and 8 of the backlog's "Design-time help before any code", as the owner decided the same day; the decision
is ADR-028.

**The instructions and the spec.** The MCP server's opening instructions now begin with the design: for an app with no
code yet, write `securevibe.toml` first, for the app as it will be, deciding each answer with the person, then work
through the design-time prompt for each feature before writing its code. The spec (`sv init`, `securevibe_spec`) says
the same, and its third rule now has two cases. Before any code, a capability the app is planned to have is true;
once there is code, the file describes the code, and a capability planned and then dropped is false. The rule as it
was made every capability false for an empty folder, which is how a real requirement gets switched off.

**The design-time prompts as MCP prompts.** The server now answers `prompts/list` and `prompts/get`, in the initializing
protocol and the stateless one (with `ttlMs` and a public `cacheScope`, as for the tools), and declares `prompts` among
its capabilities in both. It offers every prompt in `data/design-prompts.json`, and only those. A prompt comes back as
the person's message: its text, then the line saying whether it was shown to work, that a prompt is an instruction and
not evidence, and the file's credit. An unknown name, a missing one, and a coding prompt's id are refused as invalid
parameters. Which clients list MCP prompts for the person has not been tried.

**Eight more design-time prompts.** Items 8 to 15 of "Design-time prompts from the Secure by Design checklist", each
`untested`, with a check of kind `none` that says why no check in `sv` can show it working. None names an ASVS
requirement. Six name the Secure by Design controls whose statements fit: MT-03, DM-01 and DM-05, AS-01 and AC-01,
MT-06, AC-06, and MT-05. Two name none, because they draw on the checklist's escalation triggers and principles, which
are not controls.

**A heading in the notes is a section, or it is part of one.** The notes reader (`read_answers`) ends a section only
at a heading that starts with a requirement id; any other heading, and what follows it, is read as part of the
answer above. So the new prompts write under the notes' own headings where one fits ("How each kind of sensitive data
is protected", "Everything the app talks to"), and otherwise into `design-decisions.md`, which `sv` does not read. A
test reads every prompt in both files for the headings it asks for in `security-notes.md`, and refuses one `sv` does
not write. Whether a stray heading can make an unanswered section count as answered was tried on
`examples/flask-booking` and not settled: in that setup even a properly written answer was not counted, so the
reproduction is in the backlog rather than here.

**Broken in turn.** Twelve guards in the server and the instructions: the "not tried yet" and "tried, not shown"
marks each made "shown", the credit and the mark each left off the message, the coding prompts offered too, an
unknown name answered with the first prompt, the capability left out at `initialize` and at `server/discover`, the
stateless methods not answered, and two phrases of the instructions changed. Each was caught. The first run found
the "not tried yet" mark caught by nothing, because every design-time prompt then had been tried; with the eight new
ones it is caught by two tests. The headings guard was broken twice (the incident plan written into the notes, and a
heading misspelled), and each was caught.
