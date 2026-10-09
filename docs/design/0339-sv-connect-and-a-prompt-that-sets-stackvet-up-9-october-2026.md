# sv connect and a prompt that sets StackVet up (9 October 2026)


Backlog 0217, part 1, as the owner chose on 9 October 2026 ("as recommended"). Built by session securevibe-e2.

**The problem.** Connecting an AI coding tool to StackVet meant writing a settings file with the app folder's full
path typed into three places and `docker`'s full path in a fourth. A wrong path fails without a word: the tool simply
has no `stackvet_` tools. Most of the tools StackVet is for can run terminal commands, so they can find the paths
themselves; what they need is the settings text, and a copy of it written into a prompt would drift from the guide.

**What was built.**
- `sv connect TOOL [--docker PATH] [--user UID:GID] [--folder DIR]` prints the settings block for Claude
  (`.mcp.json`), VS Code (`.vscode/mcp.json`), or Cursor (`.cursor/mcp.json`) on standard output, and on standard
  error the name of the file it goes in. It writes nothing, so it adds nothing to what `sv` writes into someone's
  folder; the AI tool or the person writes the file. The folder is named by its real place (a link or a relative
  name is resolved), in all three places the container needs it.
- With `--docker`, the block starts the container exactly as the guide's own example does: `--network none`, the
  folder mounted at its own path, and, with `--user`, the person's user and group before the image (Docker reads an
  option after the image as the program's). `docker`'s path must be a full path: an app started from the Dock often
  cannot find a bare `docker`, which the guide already warns about.
- Without `--docker`, the block starts this copy of `sv` by its real place, for a copy installed with Homebrew or
  `tools/install.sh`. Inside the container that place means nothing to the tool outside it, so there `sv connect`
  stops and asks for `--docker` rather than print a path that cannot work. It knows it is inside by Docker's
  `/.dockerenv`; `SV_CONNECT_IN_CONTAINER` stands in for it in tests.
- `docs/prompts/setup.md`: a prompt the person pastes into their AI tool, which checks Docker, pulls the image,
  runs `git init`, finds `docker`'s path, runs `sv connect` through the container, shows the person the file
  before writing it, and asks them to restart and list the tools. It asks before installing anything or changing
  anything outside the folder, and stops on Windows, where StackVet is untried. The guide offers it at the top and
  shows `sv connect` in step 3.

**What it is worth.** Nothing as evidence: it reads no file of the app's and credits nothing. Neither the command
through the container nor the prompt has been tried in an AI coding tool; the guide and the prompt say so. What the
tests hold is the shape: `crates/sv-cli/src/connect/tests.rs` (7) and `crates/sv-cli/tests/connect.rs` (10), the
second running the real `sv` and holding the prompt to the published image name, to the container options, and to
the options `sv connect` takes, by running the prompt's own command for each tool, with and without `--user`.

**Broken on purpose, each put back** (`cbreaks.py` in the session's scratchpad), with the tests that went red:
no `--network none` (2), the folder not resolved to its real place (2, after the link test was changed to name the
link rather than enter it: the system already gives a folder entered through a link by its real place, so the first
version of that test could not see the break), VS Code's `type` left out (2), `--user` after the image (2), never
knowing it is inside the container (2, after a second case was added to the refusals), any `--user` accepted (2), a
bare `docker` accepted (2, after a unit test was added), and no line naming the file (3).

**Not done here.** Parts 7 (a glossary), 5 (the report read with you), and 3 (`sv doctor`) of 0217, in that order;
trying the prompt in Claude Code, VS Code, and Cursor from an empty folder, which needs the owner or a paid trial.
