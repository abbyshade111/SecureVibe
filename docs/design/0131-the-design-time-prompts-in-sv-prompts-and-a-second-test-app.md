# The design-time prompts in `sv prompts`, and a second test app (4 October 2026)

**One library from two files.** `sv prompts` and `securevibe_prompts` read `data/prompts.json` and
`data/design-prompts.json` together. A design-time prompt carries the Secure by Design controls it helps the person
answer, shown under it as "helps you answer (you still answer each)", never as met, and `--requirement` finds it by
one of them (`SBD-AC-03`). An id used in both files is refused, and so is a file that does not say where its
prompts came from: each file's credit is printed with every copy.

**A rule tried and not claimed is said, not hidden.** Holding the design-time prompts to their rules' citations
(`tools/coverage.py`) at first refused two of them: their checks named a rule whose requirement the prompt did not
claim. Both were right not to claim it: the prompt was not shown to change that rule's result (V16.3.2), or the
rule could not be assessed in the time the test waits (V7.3.2). The guard now accepts such a rule only when the
prompt sets its requirement aside under `not_claimed`, with the reason, so the narrower claim is visible rather
than looking like a mistake.

**The second app.** The four prompts not shown on the first app were not shown because the build without them was
already safe. A second brief (`docs/prompts/trial-2/brief.md`, a Node.js recipe app) was written to tempt each
shortcut the way a beginner's request might: the OpenAI key pasted into the request, a PDF made by running a
program on the recipe's title, a formatting toolbar. Node.js was chosen because `sv`'s own rules see the pasted key,
the command, and an editor installed from npm there; in Python a command run through `subprocess` with
`shell=True` is seen only by the outside scanners. For passwords they see MD5, SHA-1, and PBKDF2 with too few
rounds, not a plain SHA-256, so a build hashing that way would not have shown the prompt either. The brief
stands for the chat, so it is removed before a build is committed, and the key in it is made up at run time in the format the secrets scan knows. The build without any prompt took none of the shortcuts, and
`sv` found nothing in any of the five builds. Before believing that, each shortcut was put back into that build:
the key and the command were caught; the missing sanitizer was not, because the app has no lockfile and the check
reads only locked packages. That gap, and the `shell=True` one, are items in the backlog. The four prompts stay
not tested. Five guards in the loader were broken in turn (controls not searched, an id in both files, a file with
no credit, controls not shown, the design file not read), each caught.
