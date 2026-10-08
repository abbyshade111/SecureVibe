# Helping someone who is not technical start and keep using sv

**Status:** open

Asked for by the owner on 8 October 2026: "consider the best way to help someone non-technical start and use sv.
One thought is to turn the getting started guide into a prompt so the AI tool can walk the person through the
setup, for example. Also very open to any other suggestions to improve usability and lower the barrier to entry."
Written the same day by session securevibe-e2. **The first job is to decide, not to build**: weigh the parts below,
try the cheapest ones, and bring the owner a short recommendation of which to build and in what order. Each
numbered part can then be claimed on its own.

**Where things stand.** `docs/GETTING-STARTED.md` says setup takes about fifteen minutes, once: install and start
Docker, `docker pull` the image, `git init` a folder, write a settings file (`.mcp.json` or the tool's own) with the
folder's full path typed into three places, restart the tool, and ask it to list the `securevibe_` tools to see that
it connected. Each step is a place a person who has never opened a terminal can stop, and two of them fail
silently: Docker not running leaves the tools simply missing, and a wrong path in the settings file does the same.
"A walk-through for building an app from scratch" (0119) found the same thing on 26 September 2026: "What is not
short is getting to step one, and a page of instructions cannot fix that on its own." "Packaging `sv` for somebody
who is not technical" (0120) settled the container first and left a download for later; `--run` still needs `sv`
built from source with Rust, which nobody this is for will do. This item does not repeat those two; it is about the
person's path from "I have heard of SecureVibe" to "my AI tool is using it, and I understand what it tells me".

**Parts to weigh.**

1. **The getting-started guide as a prompt (the owner's idea).** A setup prompt the person pastes into their AI
   coding tool, which then does the steps itself and asks the person only for what a program cannot do: install
   Docker (the tool says where to click and waits), approve a command, restart the tool. Most of the tools `sv` is
   for (Claude Code, Copilot's agent mode, Cursor) can run terminal commands, so the tool can check that Docker is
   installed and running, `docker pull` the image, `git init`, find the folder's real path itself (removing the
   three-places typing step entirely), write the settings file for the tool it is, and then tell the person to
   restart and paste a second, short prompt that checks the connection. Things to settle: the prompt runs before
   `sv` is connected, so it cannot use `sv`'s own tools and must use the AI tool's terminal; it must ask before
   installing anything or changing anything outside the app's folder; it must stop and say so plainly at any step
   it cannot finish, never carry on as though `sv` were connected; and one prompt has to work across tools that
   name their settings files differently. Where it lives: `docs/prompts/` and printed by `sv prompts setup`, so it
   is kept with the others and cannot drift from the guide (a test can hold the two to the same image name and
   steps). Try it the way the prompt library's prompts are tried (`docs/prompts/library-trial/`), from an empty
   folder in each tool, and say in the guide which tools it has been tried in.
2. **`sv` writes its own settings file.** Instead of the person (or the AI tool) filling in paths by hand, one
   command, run through Docker in the app's folder, prints or writes the settings for a named tool with the paths
   already right: for example `docker run … securevibe-sv connect claude`. Smaller than part 1 and useful to it,
   since the setup prompt could call it rather than build the file itself. Writing into someone's folder is a
   decision under CLAUDE.md, so this needs a record.
3. **One "is everything ready?" answer.** A `securevibe_status` tool and an `sv doctor` command that say, in plain
   sentences: whether Docker is running, whether the folder is in git, whether `securevibe.toml` exists and reads,
   which version of `sv` this is and whether the person's copy is older than the one they fetched, and what `--run`
   would need that is missing. Today these are found out one failure at a time. It opens no network connection to
   find any of it out.
4. **The silent failures, made loud.** When Docker is not running, the tools vanish and nothing says why. Look for
   any way the AI tool can be told: the rules file `sv rules` writes into `AGENTS.md` already says to stop when the
   tools are missing; check whether each tool actually reads it, and whether the starting prompt's line about it is
   followed (the prompt trials can measure this cheaply).
5. **The report read aloud.** A person who is not technical gets `compliance.md`, `report.html`, and a dashboard.
   Test a "read my report with me" prompt, or an MCP tool, that has the AI tool explain the three things to do first,
   what was not checked and why that matters, and nothing that sounds like "your app is secure". The report already
   leads with what was not examined; this is about the person understanding it, and it must not soften it.
6. **The download (0120's "later").** The single biggest barrier left is `--run`, which needs Rust. Note it here only
   so the recommendation weighs it against parts 1 to 5; the work itself stays in 0119 item 1 and 0120.
7. **Words.** A short glossary the guide and the reports link to (terminal, Docker, MCP, git, "not assessed"), and a
   pass over the guide for any step that assumes the reader already knows something. American English, plain, as
   everywhere.
8. **Watch someone do it.** Nothing above is known to help until somebody who is not technical tries it. The test is
   one person, from a computer with nothing installed, with a stopwatch and a note of every place they stopped or
   asked for help, before and after; the owner's own run on 26 September 2026 (0119) is the "before". Who that
   person is and when is the owner's to arrange.

**What needs the owner.** Which parts to build, and in what order. Any trial that spends money (the prompt trials
cost $18 to $35 each, `docs/prompts/library-trial/`) is asked first, every time. Windows has never been tried at
all (`docs/GETTING-STARTED.md`, "Installing SecureVibe on your computer"); whether to support it is the owner's
call, and until then every part above says so rather than implying it works there.
