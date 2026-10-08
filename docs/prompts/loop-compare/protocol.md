# Apps built with `sv` against apps built without it: protocol, written before it runs

Backlog 38, "The loop trials cannot compare security with the arms that have no `sv`". On 5 October 2026 the owner
chose how: a tester writes the settings file for the builds that never saw `sv`, so the comparison is of the apps.
The loop trials did not do it: from item 6 on, every arm's request carried `sv`'s specification (the loop protocol's
Amendment 3), so they compared what the loop adds beyond it. This trial does what was chosen. Asked for by the owner
on 8 October 2026 ("Haiku 5.5"), after the Haiku 5.5 trial showed its apps can be started and tried. Fixed before any
build; a change after a result is seen goes in "Amendments", dated, with its reason.

## The question

Built from the same request by the same model, **does an app built with `sv` attached have fewer security problems
than one built without `sv` at all?** Measured on the apps alone: both arms' settings files are written by the same
blind tester, so how well a builder describes its app to `sv` is not what is compared.

## How a build is made

As in `docs/prompts/library-trial/haiku55-protocol.md`: headless Claude Code 2.1.293 with Claude Haiku 5.5
(`claude-haiku-5-5`), on the owner's API credit, a fresh folder under the home folder, `git` allowed, `pip` refused,
the owner-away sentence, and a cap of $1.50 a build. The request is `brief.md` in this folder: the recipe trial's brief
(`docs/prompts/trial-4/recipe-brief.md`) with its one line about SecureVibe taken out, so the arm without `sv` hears
nothing of it. No arm is given `sv init`'s specification in its request.

| Arm | `sv` | Builds |
|---|---|---|
| **none** | nothing: not attached, not named | 10 |
| **loop** | `sv mcp` attached for this run, every tool, as the loop protocol's **loop** arm; what to do with it comes from the server's own instructions | 10 |

## The tester

Every app of both arms is given to one tester in the same way, so the settings file is never the builder's:

1. **Blind copies.** Each build's folder is copied to a folder named by a code drawn at random; the table from code to
   build is written apart and not read until scoring. From each copy are removed, in both arms alike:
   `securevibe.toml`, `securevibe-report/`, `security-notes.md`, `design-decisions.md`, `.mcp.json`, the section `sv
   rules` writes into `AGENTS.md` (between its markers), `.git/` (its messages may name `sv`), `.claude/`, and the
   transcript, which is never in the folder. The app's code, its tests, its seed script if it wrote one, and its
   `requirements.txt` stay. **Known limit:** a comment in the code that names SecureVibe, or a test named after a
   requirement, can still show the tester which arm an app came from; nothing in the code is rewritten to hide it.
2. **The tester:** headless Claude Code 2.1.293 with Claude Haiku 5.5, no MCP server, the file tools only (`Read`,
   `Write`, `Edit`, `Glob`, `Grep`; no shell), $0.50 cap. Its request: `sv init`'s specification, then: *"The app in
   this folder is finished. Write `securevibe.toml` for it, describing the code that is there, so SecureVibe can start
   it and sign in to it as the specification says: set `install = true` for its packages. If the app has no way to
   make the test accounts the specification describes, you may also write `sv_seed.py` to make them. Change no other
   file."*
3. **Held to it:** every file's SHA-256 is taken before and after; a copy where any file other than `securevibe.toml`
   and `sv_seed.py` was added, changed or removed is restored and tried once more, and on a second failure left out
   and reported.
4. Then `sv report --run` on every copy, from one release build of `main`, its commit recorded.

## The measures

From `report.json`, the same script for every copy, the code-to-build table read only after every copy is scored:

1. **Security**, the loop protocol's measure 3: the running-app findings (`probe.*`), and the own-code findings at high
   or critical, counted per app; and, for each of the twelve problems the recipe brief tempts, whether the app has it,
   among the apps its check could ask (as `library-trial/protocol.md` defines it).
2. **Testability:** started; `sv` signed in (as corrected by the Haiku 5.5 trial's Amendment 1: not when `sv` says the
   seed failed, or when no `[stack.run.users]` was written); running-app checks answered.
3. **Use**, for the loop arm: every `sv` tool call, by name and order, from the transcript.
4. **Cost and time**, builders and tester apart.

## What may be said

Every app's value is given, by arm, with the middle one. As the loop protocol fixes: **a difference in a count is
called one only when every app in one arm is above every app in the other.** For each of the twelve problems, by the
recipe trial's rule: the loop arm is **shown** to prevent it when the arm without `sv` had it in at least 5 of the apps
asked and the loop arm in at most 1; **not shown** when the loop arm had it in 2 or more; **no reading** when the arm
without `sv` had it in fewer than 5. An app that did not start says nothing about security and is left out of it, and
counted in testability. Ten builds an arm, one model, one brief, one tool: nothing here speaks for another.

## Cost

Haiku 5.5 builds cost $0.125 each in its trial, with the specification in the request. The arm without `sv` has a
shorter request; the loop arm calls `sv`'s tools, which costs more. Estimated: builds $2.50 to $4, testers about $1
(20 copies, short requests), in all about $3.50 to $5. The arm without `sv` runs first; if its ten average more than
$0.40, the run stops before the loop arm and the owner is asked. The owner gives the word before anything is spent.

## Amendments
