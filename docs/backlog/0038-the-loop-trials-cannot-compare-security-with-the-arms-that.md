# The loop trials cannot compare security with the arms that have no `sv`

**Status:** done, 8 October 2026

Found on 5 October 2026 by session
paper-facts, in item 3: a build that never saw `sv`'s specification writes no manifest `sv` can read, so it cannot
be run, and the protocol's security measures leave it out. Two ways, for the owner to choose before item 6: a
tester writes the manifest for those builds from the code, as trial 3 did, so the comparison is of the apps; or
every arm's request includes the specification, so the comparison is of what the loop adds beyond it.
**The owner's decision, 5 October 2026:** the first, a tester writes the manifest for those builds from the code, so the comparison
is of the apps. For session paper-facts, which runs the trials.
**Claimed 8 October 2026 by session paper-facts**, at the owner's word ("please pick a backlog item when you're
ready", then "Haiku 5.5" for the model), in branch `claude/loop-compare`: 10 Claude Haiku 5.5 builds without `sv` and
10 with it attached, on the recipe brief with its line about SecureVibe taken out; every app's settings file written by
one blind tester from the code alone, so the comparison is of the apps, as the owner chose on 5 October.
Protocol, written before any build: `docs/prompts/loop-compare/protocol.md`. About $3.50 to $5; nothing spent before
the owner's word. Read on `main` just before this claim: open, and no other session had claimed it.
**Done the same day** (`docs/prompts/loop-compare/results.md`): 20 builds and 20 blind-tester runs, $3.57. Of the
apps that started, every one built with `sv` had fewer running-app findings than every one built without (middle 3.5
against 12), across headers, passwords, sessions and limits; own-code findings at high or critical, no difference by
the rule. Four apps built with `sv` did not start, three pinning a version of the password package its prompt names
that does not exist, so the measure rests on six; and the tester was not fully blind (eight of the ten copies built
with `sv` still named it). The paper's `TRIALS.md` has it as the eleventh trial.
