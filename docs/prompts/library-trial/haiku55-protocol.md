# Claude Haiku 5.5 against Haiku 4.5: protocol, written before it runs

At the owner's word of 8 October 2026 ("yes, please go ahead. let's include the Haiku 4.5 control as well"), after
asking whether a limited run with Claude Haiku 5.5 was worth doing "to evaluate if those same inconsistencies and
issues still exist". Fixed before any build; a change after a result is seen goes in "Amendments", dated, with its
reason.

## Why

Through the trials of 5 to 7 October, Claude Haiku 4.5 was the model whose apps could least often be tested: a third
of its settings files could not be read in the first trials; in the recipe trial (`recipe.md`, stage 1) 9 of its 10
builds wrote an app, 8 wrote a settings file `sv` could read, only 2 started under `sv run`, and `sv` signed in to 1.
Two pinned package versions that do not exist, and three crashed. With so few apps running, most of its prompt
comparisons had no reading. Claude Haiku 5.5 (`claude-haiku-5-5`) has since been released. This trial asks one
question: **with the same brief and the same checks, does Haiku 5.5 build apps that can be tested, where Haiku 4.5
could not?** It is not a prompt trial; that would be stage 2, below, and only with the owner's yes.

## How a build is made

As in `recipe-protocol.md`, with two differences, both so the two arms differ only in the model:

- **One Claude Code for both arms:** 2.1.293, headless, on the owner's API credit, no MCP server, a fresh folder
  under the home folder, `git` allowed, `pip` refused, the owner-away sentence, `sv init`'s specification from `main`
  at the top, and the recipe brief (`docs/prompts/trial-4/recipe-brief.md`). The recipe trial used 2.1.286.
- **Each model named by its full id,** since the short name `haiku` may now resolve to the newer model:
  `claude-haiku-4-5-20251001` (the model every earlier Haiku build used, as their transcripts record) and
  `claude-haiku-5-5`. The builds are labelled `haiku45` and `haiku55`.

Every build is checked by `sv report --run` from one release build of `main`, its commit recorded.

## Stage 1: 10 builds of each

20 builds, no prompt pasted, preceded by one smoke build of Haiku 5.5 that only shows the model name is accepted and
no transcript holds the key; it is not counted. Measured, per model, by the recipe trial's stage 1 scorer:

1. **Whether the app can be tested** (the question): wrote an app; a settings file `sv` could read; `requirements.txt`
   present, its install refused or failed; started under `sv run`; `sv` signed in.
2. **Stalls:** a build that asked a question and wrote no app.
3. **Each prompt's problem,** among the builds its check could be asked of, as `protocol.md` and the recipe trial's
   Amendment 1 define it.
4. **Cost and time** per build.

**The rule, fixed now,** for measure 1, as for the prompts: Haiku 5.5 is **shown to make apps testable** when the
Haiku 4.5 control fails a step (no readable settings, did not start, or not signed in) in at least 5 of 10 builds and
Haiku 5.5 in at most 1; **not shown** when Haiku 5.5 fails it in 2 or more; **no reading** when the control fails it in
fewer than 5. The recipe trial's recorded Haiku 4.5 builds are reported beside the control, not counted in it: they
were made by another Claude Code and checked by an older `sv`.

## Stage 2: not run without the owner's yes

If stage 1 shows Haiku 5.5 makes apps that start, the comparisons where Haiku 4.5 had no reading or was not shown
could be run again with Haiku 5.5, by the recipe trial's rule (an arm for each prompt whose problem stage 1 finds in at
least 5 of the Haiku 5.5 builds asked). The arms and their cost are brought to the owner first.

## Cost

Haiku 4.5 recipe builds cost $0.376 each (`recipe.md`): about $3.80 for the control. Haiku 5.5 costs a tenth as much
a token, but thinks by default, so a build is estimated at $0.05 to $0.20: about $0.50 to $2 for its arm, and $0.20 at
most for the smoke build. In all, about $4.50 to $6. Each build is capped at $1.50. The Haiku 5.5 arm runs first; if
its ten average more than $0.30, the run stops before the control and the owner is asked.

## Amendments
