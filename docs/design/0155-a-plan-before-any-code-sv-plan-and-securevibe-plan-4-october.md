# A plan before any code: `sv plan` and `securevibe_plan` (4 October 2026)

Item 3 of the backlog's "Design-time help before any code"; the decision is ADR-030, written first as `proposed` with
the claim (#659) and accepted with the build.

`sv plan [PATH]` prints, and the MCP tool `securevibe_plan` returns, the plan for an app from its `securevibe.toml`:
the requirements that will apply, grouped by chapter; the design-time prompts for the decisions before each feature,
marked shown to work or not tested, with the questions only the person can answer; the tests worth writing, named by
requirement id; what the app must give `sv run`, worked out from the brief's answers; and the threats those answers
raise. It writes nothing, ends clean (a plan is not a check), and credits nothing, which it says in its first lines
and in `creditsNothing` in the tool's result.

**Built from the report.** `plan::from_report` takes the parts `assemble_report` already makes (`requirements`,
`tests_to_write`, `questions_for_you`, `threats`), so the plan and a later report cannot disagree about what
applies; two tests compare them, one through `sv report`'s `report.json` and one through `securevibe_check`. The
report's assembly reads the app's files when there are any, which only ever adds requirements; on a folder holding
only the brief it reads nothing. The MCP tool goes through the same time limit and progress as a check.

**What `sv run` needs.** `plan::run_needs` maps the brief's answers to the settings each check of the running app
reads: `image`, `start`, `health`, and `test` always; for sign-in, `seed`, `login`, `logout`, `private`, `owned`, and
`admin` under `[stack.run.users]`; and `[stack.run.oidc]`, `upload`, `reset`, `once`, `[stack.run.ai]`,
`[stack.run.fetch]`, and `[stack.run.mcp-server]` for the answers that bring them. An unanswered capability is planned
for, as the spec's rule 2 asks; one answered no asks for nothing; one the brief already gives is marked given. Each
reason was read against the checks it serves (the upload entry, for one, says what is really sent: a file over
`max-bytes`, a page, a script, an SVG with a script, a name that climbs out of its folder), and a test refuses a table
or setting the spec does not describe.

**Text from the app.** The app's name comes from its folder, so it is written on one line, with its line breaks and
invisible characters as escapes, as everywhere else such text reaches the AI coding tool.

**Broken in turn.** Thirteen guards: a requirement or a test left out of the plan (each caught by a comparison with the
report), the plan not saying it credits nothing (in its text, and in its result), the plan ending as a failed check or
writing into the app's folder, an unanswered capability read as no, sign-in asked of an app without it, a setting the
spec does not have, a given setting not marked, no design-time prompt given, the app's name not put on one line, and
the instructions not naming the plan. Each was caught.
