# Design-time help before any code: keeping what v1 did best

**Status:** partly done: parts 5, 6, 9 (backlog 0228's conversion read them as not done)

Proposed on 4 October 2026 by session paper-facts,
at the owner's asking, after comparing v1 and `sv` for the paper. v1 made the decisions first (the wizard, the design
freeze, plan → approve → build, eight decision records per app) and then held the build to them. `sv` has the
pieces (the design questions, the design-time prompts, the coding rules, the manifest spec), but its MCP
server's instructions and the spec are written for an app that already exists, and nothing puts the decisions in
front of the AI tool before it writes code. The prompts trial showed the lever: when `securevibe.toml` already held
the limits, builds with no prompt enforced them, so a decision written down first steers any tool. None of these
changes credits anything: a plan, a brief, or a decision is still checked only through what the running app shows.
**The owner's decision, 4 October 2026: all eight, yes.** Each numbered item can be claimed on its own.
1. **Design first, in the MCP server's instructions and the spec.** The instructions name the spec, the rules, and
   the check, in that order, and never the design-time prompts; the spec says to describe "what the app really
   does". For a folder with no code yet, they should say to write the design brief first, and to fetch the
   design-time prompt for a feature before building it; and the spec should have wording for an app not yet
   written ("what the app will do"), with a claim the code later contradicts still reported.
   **Part status:** done, 4 October 2026
2. **The design-time prompts as MCP prompts.** The server answers `prompts/list` with "method not found" (a test
   holds it). MCP prompts are what a client shows a person to choose (in Claude Code, as slash commands), so offering
   the design-time prompts there keeps the choice with the person and works with any client that supports them;
   `sv prompts` stays for the rest. Which clients show MCP prompts is to be tried before it is written down, as for
   `AGENTS.md`.
   **Part status:** done, 4 October 2026
3. **A plan before any code (`sv plan`, and `securevibe_plan`).** From the manifest alone: the requirements that
   will apply, the threat model, the tests worth writing named by requirement id, the decisions to make for the
   app's features, and the `[stack.run]` and `[stack.run.users]` entries the app must give so `sv run` can test it.
   Mostly the report's own parts, which already come back for an empty folder. Building the app to be testable from
   the start is what gave v1 its strong evidence, and its lack is `sv`'s largest gap in the comparison.
   **Claimed on 4 October 2026 by session paper-facts**, at the owner's word, in branch `claude/plan-before-code`,
   with its record as `proposed` (ADR-030).
   **Done the same day** (ADR-030, accepted; DESIGN, "A plan before any code: `sv plan` and `securevibe_plan`"):
   `sv plan` and `securevibe_plan`, built from the report's own parts, with what the app must give `sv run` worked
   out from the brief. Whether builds given the plan come out testable is item 7's question.
   **Part status:** done, 4 October 2026
4. **Feature briefs, in place of v1's template features (`securevibe_before`).** For a feature about to be built
   (sign-in, uploads, payments, an AI feature, fetching a web address, admin pages, email): the requirements it
   brings, its design-time prompt, the coding-rules topic, the manifest block to fill, and the tests to write named
   by requirement id. `securevibe_guidance` takes topics of process (secrets, dependencies, CI), not features.
   **Claimed on 5 October 2026 by session securevibe-e2**, at the owner's asking to continue with the backlog, in
   branch `claude/securevibe-e2-feature-briefs`.
   **Done the same day** (DESIGN, "Before each feature: `sv brief` and `securevibe_before`"): eight features in
   `data/feature-briefs.json`, each with the conditions and requirements it brings, its design-time prompts, the
   coding-rule topics that bear on it, and its `securevibe.toml` settings. A brief gives what applies now, what will
   once `securevibe.toml` says the app has the feature, the prompts in full, the rules, the tests to write, and the
   settings quoted from the spec; it credits nothing. Uploads and email have no design-time prompt yet, and admin
   pages and fetching name no coding-rule topic: each brief says so.
   **Part status:** done, 5 October 2026
5. **Decisions as planned, then held to.** A design answer of "yes, planned" before there is a file to point to,
   which becomes a finding when the code exists and nothing does it: decided, never built. Item 15 of the
   design-time prompts above, made a check; and a per-app record of decisions like v1's.
   **Claimed on 5 October 2026 by session securevibe-e2**, at the owner's word, in branch
   `claude/securevibe-e2-planned-decisions`. **The owner's decisions, 5 October 2026:** a fourth design answer,
   `planned`, with an optional `where` naming the file it will be in, which credits nothing; and `sv` does not read
   `design-decisions.md` in this item (a separate item below).
   **Done the same day** (ADR-022 and ADR-028, "Later, 5 October 2026"; DESIGN, "`planned`: decisions held to the
   code"). `planned` credits nothing. With no code yet (no source file and no dependency manifest read) it is listed
   as planned, not built yet; with code, a named file that is not there is a low finding,
   `design.planned-never-built`, one that is there asks for yes or no, and one with no `where` is reported as one
   `sv` cannot follow. Nine guards broken in turn, each caught. Not done: the design-time prompts do not ask for
   `planned` (the third trial tested their present wording), and v1's per-app record of decisions is item 9.
   **Part status:** partly done: the design-time prompts do not yet ask for `planned` (read on 10 October 2026)
6. **The owner's answers asked by the server itself, where the client allows it.** MCP elicitation shows the person a
   form the AI tool cannot fill, so a design brief answered that way could count as the owner's word rather than the
   tool's. DESIGN lists elicitation as unused, not rejected. Client support varies, and the stateless 2026-07-28
   protocol may change it, so it is to be tried first; `sv review` at a terminal stays the sure path.
   **The owner's decision, 5 October 2026:** research it first: which AI tools support elicitation today, what the protocol says it
   may be used for, and whether an answer given through it could fairly count as the owner's.
   **Claimed the same day by session securevibe-e2**, at the owner's word, for that research only, in branch
   `claude/securevibe-e2-elicitation-research`; nothing is built until the owner has read it.
   **Researched the same day** (DESIGN, "Asking the owner through the AI tool's own form: research, not built"). An
   answer given through elicitation cannot count as the owner's word: nothing lets `sv` tell a person from the AI tool
   answering, and Claude Code documents settings that answer the form with no person shown it. Claude Code and VS Code
   support it; Cursor and Codex CLI by secondary sources; Zed and Gemini CLI do not. Waiting on the owner: whether to
   try a middle tier, "confirmed in the AI tool's form, not sealed", which would never stand in for `sv review`.
   **The owner's decision, 6 October 2026: no, not for now.** Elicitation stays unused; `sv review` is the only way
   an answer counts as the owner's.
   **Part status:** claimed by securevibe-e2, 6 October 2026
7. **A larger prompts trial.** One test app, one model, one build each so far. To say the help works with any tool:
   at least two AI tools or models and about three builds each, and a trial of the MCP flow itself (whether a tool
   with the server attached fetches the plan and briefs unasked, and whether the app comes out more testable).
   Spends the owner's AI credit: ask before each run.
   **The owner's decision, 5 October 2026:** run it, medium size: two models (Sonnet 5.5 and Haiku 4.5, as helper
   agents of this session, not the owner's API key), two builds per arm, on the first trial's brief. Arms: no prompt;
   each of the six design-time prompts that has a check; the plan in the loop (the builder is given `sv plan`'s
   output); and the MCP flow approximated (the builder is given the MCP server's instructions and the `sv` command
   line, since a helper agent cannot be given an MCP server without changing the session's configuration). The last
   shows whether the instructions work when read, not whether a tool reads them unasked, and is reported as that.
   About 36 builds. One tool, two models: it cannot speak for other vendors' tools.
   **Claimed on 5 October 2026 by session paper-facts**, at the owner's word, in branch `claude/prompts-trial-3`.
   **Done the same day** (`docs/prompts/trial-3/README.md`; DESIGN, "The prompts trial, a third time"). Thirty-nine
   builds. Prompts 3, 6, and 7 held with Sonnet 5.5 on every check they were shown on, and 6 also on V16.3.2; with
   Haiku 4.5, 6 and 7 held and 3 did not. Prompts 1 and 4 made no difference with either model. The plan made both
   Sonnet builds testable to the same high level; with Haiku, `sv` could not sign in to either plan build. Given the
   MCP instructions and the command line, both Haiku builds came out testable. Two builds a cell: enough to see,
   not to generalize.
   **Part status:** done, 5 October 2026
8. **The design-time prompts not yet written,** items 8 to 15 of "Design-time prompts from the Secure by Design
   checklist" above, which the owner approved on 4 October and nobody has claimed.
   **Part status:** done, 4 October 2026
9. **Decisions in `design-decisions.md`, held to the code.** Split from item 5 by the owner on 5 October 2026. Four
   design-time prompts write decisions there (who to bring in, safe defaults, what we do if, which rules apply) and
   a fifth reads them before a change, and `sv` reads none of it. A per-app record like v1's eight, read by `sv`, could say which
   decisions are written down and, where a decision names something the code can show (a debug switch off, a page
   removed), whether the code agrees. What the file's sections must look like for that, and which decisions a check
   can speak to at all, is for whoever builds it to propose to the owner first.
   **Claimed on 5 October 2026 by session securevibe-e2**, at the owner's word ("Yes please", to drafting the
   proposal), in branch `claude/securevibe-e2-decisions-file`: the proposal first, for the owner to choose from;
   nothing is built until they have.
   **The owner's decisions, 5 October 2026**, on the proposal (the four headings the prompts write stay as they are;
   who wrote a section is read as in `security-notes.md`, ADR-022):
   - "What we do if something goes wrong" and "Rules that might apply" count toward SBD-MT-06 and SBD-AC-06 as
     *documented* (or *stated by the AI coding tool*), never *checked*; the report says what is not covered (the
     plan rehearsed, the design following the rules). SBD-MT-05 (records kept current) is not credited.
   - "Safe defaults" gets a short fixed list of lines (debug mode, cross-site access, default accounts), each held
     to the check `sv` already has; decided off and found on is a finding, *decided, not held to*. The safe-defaults
     prompt changes to write those lines (it has never been tried).
   - "When to bring in a person": a recommended review is repeated in the report as a reminder, crediting nothing.
   **The first part done the same day** (DESIGN, "`design-decisions.md`: two sections as written answers, and a
   review repeated"): the two sections count toward SBD-MT-06 and SBD-AC-06, read by the security notes' reader with
   `data/design-decisions.json`, sealed through `sv review`, each saying what it does not cover; what the file says
   about bringing in a person is repeated in the report. Twelve guards broken in turn, each caught. Safe defaults
   held to the code is the second part.
   **The second part done the same day** (the same DESIGN section, "Later the same day: safe defaults, held to the
   running app"): the safe-defaults prompt writes three fixed lines, each held to one check of the running app; a
   switch decided the safe way that the check finds otherwise is `decisions.not-held-to`, and without `--run` the
   report says the decisions were not looked at. Twelve guards broken in turn, each caught; the line joining the
   finding to the report needs Docker to run and is untested here.
   **Part status:** claimed by securevibe-e2, 5 October 2026
**Items 1, 2, and 8 claimed on 4 October 2026 by session paper-facts**, at the owner's word, in branch
`claude/design-time-first`.
**Items 1, 2, and 8 done the same day** (ADR-028; DESIGN, "Decide before you build: the instructions, the spec, and
the design-time prompts as MCP prompts"). The instructions and the spec put the brief first for an app with no code,
and the spec's third rule now keeps a planned capability true until it is dropped; the server answers `prompts/list`
and `prompts/get` in both protocols with the design-time prompts, each marked and credited; and the eight prompts
below are written, each not tried and naming no requirement. Which clients list MCP prompts is not yet tried.
Fourteen guards broken in turn, each caught.
**Marked done 9 October 2026 by session securevibe-e9**, from the roadmap (Phase 4, item 3), read against `main`: items 1, 2, 3, 4, 5, 7, 8, and 9 are each done above, and item 6 was researched and the owner decided on 6 October not to build it.
