# What the owner's first build from scratch found in `sv`

**Status:** partly done: 6 of 9 parts done, 0 claimed, 3 open, as its markers read on 8 October 2026

All nine numbered items done by 27 September
2026; what each one left over is noted under it. 26 September 2026: the owner built
an app from an empty folder in Claude Code with `sv` connected over MCP — a catalog site with a weekly
AI refresh that now needs the owner's approval to publish — and session keen-meninsky-691a27 read the
whole session (886 messages) afterwards. **Not claimed; each numbered item can be claimed on its
own.** Every item was checked against the code or reproduced before it was written down, not taken
from the building tool's account of it.

**Faults in `sv`:**

1. **`sv`'s own report stops its next run from checking the code.** **Claimed on 27 September 2026 by session securevibe-e8.** **Done the same day:** every folder `sv report` writes carries `.securevibe-report`, every walk of the app leaves a marked folder out (and `securevibe-report` by name, for reports written before the marker), and the two skip lists are one, `sv_scan::ecosystems::skip_dir`, with the credential scan still reading `.vscode` and `.idea` on purpose. `crates/sv-check/tests/own_output.rs` holds it, including the control: the same files in an unmarked folder are read and found. `sv report` writes to
   `<app>/securevibe-report` unless told otherwise (`crates/sv-cli/src/main.rs`, `out_dir`), and
   `securevibe_write_report` writes there by design (`crates/sv-cli/src/mcp.rs`). Nothing skips that
   folder: it is in neither `SKIP_DIRS` in `crates/sv-scan/src/ecosystems.rs` — shared by the code
   rules, the outside tools' file list and the test finder — nor the separate copy in
   `crates/sv-check/src/secrets.rs`. So the next run reads `report.html` as the app's own code, and
   while a page it cannot fully read is present, no code rule claims anything. On the owner's app the
   count of requirements checked fell **from 9 to 1**, twice, and the building tool found the cause
   only by undoing its own changes one at a time. Fix: skip `securevibe-report`, and whatever folder
   `--out` names, wherever the app is walked. Worth also making the two `SKIP_DIRS` one list, since
   two copies of it can drift.
2. **Two false alarms, both rated high, that made the tool change correct code.** **Claimed on 27 September 2026 by session securevibe-e8.** **Done the same day:** in JavaScript and TypeScript, `ast.shell-command` counts a member call only on `child_process`, `childProcess`, `cp`, `shell`, `shelljs`, or `require('child_process')` (a bare `exec(...)` still counts), and `ast.sql-built-by-hand` only a call made directly on a name or a property, never on another call's result, which leaves out `request(app).get('/').query({...})` and, knowingly, `getDb().query(sql)` too. Text conditions such as `#not-match?` were the first idea; the engine refuses them at load, because the Rust binding parses them and does not apply them. Reproduced on
   three-line files:
   - `re.exec(code)`, a regular expression, is reported as *A shell command is built from a value*
     (V1.2.5). `ast.shell-command` matches any JavaScript call named `exec` (`^(exec|execSync)$`,
     with no module named), and `RegExp.prototype.exec` is one of the language's commonest calls.
   - `request(app).get('/').query({ q: term })` in a supertest test is reported as *A database query
     is built by joining text together* (V1.2.4), in an app with no database. `ast.sql-built-by-hand`
     matches any JavaScript call named `query`, `execute`, `raw` or `unsafe`.

   The tool "fixed" both by rewriting working code until the warnings stopped. With an AI in the
   loop a false alarm is not noise: it changes the code. Each rule needs the call's receiver or its
   module taken into account, and each needs a not-found witness for exactly these two cases.
3. **A rate limiter counts as evidence of a public API.** `claim-corroborators.json` lists
   `express-rate-limit`, `@fastify/rate-limit`, `flask-limiter`, `slowapi` and `rack-attack` under
   `public-api`. Limiting requests is ordinary for any web app, and one of the usual ways to build the
   brute-force controls V6.3.1 asks for, so an app that adds it is handed the API requirements, over
   the manifest's own "no" (corroboration only ever adds). The owner's app has no sign-in at all. A rate limiter shows requests are limited, not who is calling. **Claimed on 27 September 2026 by session securevibe-e9.** **Done the same day:** the five are gone from `public-api`, and two tests keep them out. See DESIGN, "A rate limiter is not an API".
4. **Security notes the AI tool wrote are credited to the owner.** `security-notes.md` records no
   author, so the report counted all 12 answers as *documented by the owner*; the tool had written 8
   of them from the code. It marked them "Written by the AI coding tool" in the prose and warned the
   owner itself, which `sv` cannot see. The interview already tells the tool to write a note only once
   the owner agrees; this run shows an instruction is not enough. Design answers solved the same
   problem with `by`, and notes need the same, with an answer that does not say who wrote it counting
   as the tool's. **Claimed on 27 September 2026 by session securevibe-e9**, at the owner's asking.
   This also covers the "first thing to fix" in the entry on confirming what the AI coding tool said
   (pull request #235): the tool's own "Written by the AI coding tool" line being thrown away with
   `sv`'s italic lines. **Done the same day by another session** (commit b1aec2f, step 1 of the
   entry on confirming what the AI coding tool said): each answer starts with `Written by: owner`
   or `Written by: AI coding tool`, and an answer without the line counts as the tool's. Session
   securevibe-e9 had built the same thing with an `Answered by:` line and withdraws it unpublished,
   since it added nothing that one does not. One thing it does not do: a section holding nothing but the tool's own
   line, *Written by the AI coding tool from the code; review before relying on it.*, has no colon,
   so it is not a `Written by:` line; it is long enough to pass the forty-character floor, and the
   section reads as *stated by the AI coding tool* with no answer in it. Reproduced on `main` with
   `sv notes` and `sv report`. **Claimed on 27 September 2026 by session securevibe-e9**, at the
   owner's asking: such a line says who, not what, and should not count toward an answer's length. **Done the same day;** see DESIGN, "Who wrote each section of the security notes", on a byline alone.
5. **When the app's own tests fail under `--run`, their output is lost.** Only the exit code is kept
   (`crates/sv-run`, which says "only the exit code is known"). One test failed in `sv`'s Node 22
   image and not under the owner's Node 26, which cost every test its credit, and the tool had to
   rebuild `sv`'s environment by hand to find which. The last lines of the runner's output belong in
   the report whenever the suite fails. **Claimed on 27 September 2026 by session securevibe-e9.** **Done the same day:** the last 30 lines, as a terminal
   showed them and with anything that looks like a credential cut short, in the report, `report.json`,
   and `sv run`'s output. See DESIGN, "What a failing suite printed".

**Friction for somebody who is not technical** (see the walk-through entry above):

**Items 6, 7, and 8 claimed on 27 September 2026 by session securevibe-e8**, at the owner's asking
("continue to work off items in the backlog, your choice"). **Done the same day** (DESIGN, "Three
things the owner's first build tripped on"): the command the MCP server gives names `sv` by its
full path, or `sv` on the computer when it runs in the container; the not-in-git message says to put
the app in git with a `.gitignore` first; and a web search is its own answer, `web-search`, which
brings in C7.4.1 to C7.4.3 and C12.1.4 and not the vector-database requirements. Left over: the
`rag` rule for all of C7.4 still covers C7.4.4 (watermarking generated media), which has nothing to
do with retrieval and probably belongs with `multimodal-ai`; and no package names `web-search` yet,
so nothing corroborates the answer from the code.
**The owner's decision, 27 September 2026:** a question of its own, "does the AI make images, audio,
or video?" (`generates-media`), which alone decides C7.4.4. **Claimed the same day by session
securevibe-e8.** **Done the same day**, with one fact found while building it: C7.4.4 is a level 3
requirement, so the answer decides nothing for an app held to level 1 or 2, and the starter file
says so.

6. **The tool told the owner to run `sv`, and there was no `sv`.** The MCP results say to run
   `sv report --run --tools` at a terminal; the owner got `command not found`, ran it by its full
   path, and then added the build folder to their shell's PATH in `~/.zshrc` at the tool's
   suggestion. The results should say how `sv` was started, or the walk-through should install it as
   a command.
7. **The app was never put in git, so the check that matters most never ran.** Whether a secrets
   file was ever committed is *not assessed* when the folder is not a repository, honestly, and
   nothing suggested making it one. A beginner's app will usually start this way.
8. **The `rag` question** — "does it search a document store or vector database?" — led the tool to
   count a web search as one, which brought in the C8 vector-database requirements for an app with
   no database. The question should say what it means by search.
9. **The terminal summary does not say whether `--run` started the app.** The tool had to infer it
   from the counts. One line — started, answered N requests, or could not start and why — would do.
   **Claimed on 27 September 2026 by session securevibe-e9.** **Done the same day:** the first line after the files
   written says which of the three happened, and `report.json` carries it as `run_status`. See
   DESIGN, "Whether the app was started, in one line".

**What worked, for the record:** the `.mcp.json` connection worked first time in the desktop app,
and the tool described all six tools accurately; the interview went one question at a time and kept
the tool's answers apart from the owner's; once the report was out of the app folder, `--run`
started the app, sent it 29 requests, and requirements checked rose from 9 to 23. And the list of
requirements with no evidence did its job: it pointed at human approval for AI-published content
(C9.2.1), which led to the approval step the owner chose.

**To keep in mind rather than fix:** 18 of the 40 requirements checked came from tests the same tool
wrote and labeled with the requirement each proves. It checked the wording before labelling, and
those tests run and pass, but it is the author vouching for its own work through the name.
