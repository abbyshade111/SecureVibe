# The loop trials: protocol, written before they run

Item 1 of the backlog's "The loop: `sv` as the MCP server an AI tool uses while it builds" (5 October 2026). This is
fixed before the first build of items 2 to 4 and 6. A change made after any result has been seen goes in
"Amendments" at the end, dated and with its reason, and where it can be, the result is reported both ways. The third
prompts trial changed its scoring twice after seeing results (`trial-3/README.md`); this is how the next ones avoid it.

## The questions

1. **Does an AI coding tool with `sv mcp` attached use it without being asked,** and in what order: the brief and the
   plan before any code, the check after features?
2. **Does the loop make an app `sv run` can test, and a safer one,** than the same tool with no `sv`?
3. **Which part does the work:** the server's instructions, `sv check`'s feedback, or the plan?

## How a build is made

- **The request** is `trial-3/plain-brief.md`: the club app as an owner would describe it, with the environment's
  fixed facts and no hint of what a tester needs. It says nothing about `sv`: in the arms with the server, the server
  is the only source of anything about it.
- **The builder** is a headless AI coding tool given the request as its prompt, in a fresh folder of its own under the
  home folder (Colima shares only that): for Claude, `claude -p` with `--output-format stream-json`, and the server
  attached for that run only with `--mcp-config` naming `sv mcp --root <the folder>`. No user or project settings are
  changed. Tools are limited with `--allowedTools` to file reading and writing, and the shell, in the build's folder;
  the exact list is set in the pilot and then fixed.
- **`sv`** is one release build from `main`, its commit recorded with the results, and the same for every build.
- **The check** is `sv report --run`, through `tools/prompt_trial.py`'s `run`, with `docs/prompts/trial/policy.toml`
  standing in for any [policy] number a build did not write. Not `--slow`: session times are not a question here.

## The arms

| Arm | The server | What the builder can use of it |
|---|---|---|
| **none** | not attached | nothing |
| **loop** | attached | every tool |
| **instructions** | not attached; the server's opening instructions are put at the top of the request | nothing |
| **check** | attached | `securevibe_spec` and `securevibe_check` only (`--allowedTools`) |
| **plan** | attached | `securevibe_spec` and `securevibe_plan` only |

The pilot (item 2) is the **loop** arm alone. Item 3 runs all five.

## The measures

Each is computed by one script from the transcript and the report, the same for every build.

1. **Use, from the transcript:** every `sv` tool call, by name and order; whether `securevibe_spec` or
   `securevibe_plan` came before the first write of the app's code; how many times `securevibe_check` was called; the
   findings each call returned.
2. **Testability, from `report.json`:** whether the app started; whether `sv` could sign in; and how many distinct
   running-app checks (`probe.*`) answered, credited or found, as in the third trial.
3. **Security, from `report.json`:** the running-app findings, and the own-code findings at high or critical.
4. **Cost, from the transcript's last message:** tokens and time.

## What makes a build unusable, decided now

- **It could not start under `sv run`:** testability counts it as it is, with no checks answered (an app that
  cannot be tested is the outcome being measured); security leaves it out, since nothing about it was seen.
- **`sv` could not sign in:** testability counts it as it is; the security measures that need a signed-in user leave
  it out, and the rest count.
- **The builder stopped before writing an app, or wrote outside its folder:** left out of everything, and reported.

## What may be said

Results are given per model and per arm, every build's value and the middle one. No arm is said to be better from
fewer than five builds a cell; the pilot and item 3 at its first size describe what was seen, as the third trial did.
A difference is called one only when every build in one arm is above every build in the other.

## Cost

Before each run, the owner is told the number of builds and an estimate, and the run waits for their word (approved
in principle on 5 October 2026). A pilot build that passes 400,000 tokens stops the pilot, to look at why before
spending more.

## Amendments

1. **5 October 2026, after the pilot's first four builds: a request with no owner to answer.** Both Haiku builds
   followed the server's instruction to settle the design with the owner, asked their questions, and ended before
   writing an app. A headless build has no owner. From then on every build's request, in every arm, ends with: *"I
   won't be around to answer questions while you build; where something needs deciding, choose the safer option and
   write down what you chose."* The two Haiku builds were made again with it, and the pilot reports both
   (`loop-pilot/README.md`). The Sonnet builds were not made again: neither had stopped to ask.
2. **5 October 2026, before the first build ran: the builds use the owner's API credit, not a sign-in.** The Claude
   program run from a terminal had no sign-in of its own. At the owner's word the builds use the Anthropic key from
   `.env`, handed to the program by an `apiKeyHelper` (`loop-pilot/key_helper.sh`) so it is in no other program's
   environment, and every transcript is searched for it afterwards. The cost each build reports is then what it was
   charged.
