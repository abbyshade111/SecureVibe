# Helping someone who is not technical start and keep using sv

**Status:** partly done: part 4 is measured in the next paid prompt trial that runs anyway; part 8 (watching someone who is not technical set it up) is the owner's to arrange; part 6 stays in 0120. Nothing built here has yet been tried by someone who is not technical.

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
   **Part status:** claimed by securevibe-e2, 9 October 2026: part 3 (sv doctor) is to build; parts 1, 5, and 7 are built (9 and 10 October 2026), none yet tried by someone who is not technical
2. **`sv` writes its own settings file.** Instead of the person (or the AI tool) filling in paths by hand, one
   command, run through Docker in the app's folder, prints or writes the settings for a named tool with the paths
   already right: for example `docker run … securevibe-sv connect claude`. Smaller than part 1 and useful to it,
   since the setup prompt could call it rather than build the file itself. Writing into someone's folder is a
   decision under CLAUDE.md, so this needs a record.
   **Part status:** claimed by securevibe-e2, 9 October 2026: part 3 (sv doctor) is to build; parts 1, 5, and 7 are built (9 and 10 October 2026), none yet tried by someone who is not technical
3. **One "is everything ready?" answer.** A `securevibe_status` tool and an `sv doctor` command that say, in plain
   sentences: whether Docker is running, whether the folder is in git, whether `securevibe.toml` exists and reads,
   which version of `sv` this is and whether the person's copy is older than the one they fetched, and what `--run`
   would need that is missing. Today these are found out one failure at a time. It opens no network connection to
   find any of it out.
   **Part status:** claimed by securevibe-e2, 9 October 2026: part 3 (sv doctor) is to build; parts 1, 5, and 7 are built (9 and 10 October 2026), none yet tried by someone who is not technical
4. **The silent failures, made loud.** When Docker is not running, the tools vanish and nothing says why. Look for
   any way the AI tool can be told: the rules file `sv rules` writes into `AGENTS.md` already says to stop when the
   tools are missing; check whether each tool actually reads it, and whether the starting prompt's line about it is
   followed (the prompt trials can measure this cheaply).
   **Part status:** claimed by securevibe-e2, 9 October 2026: part 3 (sv doctor) is to build; parts 1, 5, and 7 are built (9 and 10 October 2026), none yet tried by someone who is not technical
5. **The report read aloud.** A person who is not technical gets `compliance.md`, `report.html`, and a dashboard.
   Test a "read my report with me" prompt, or an MCP tool, that has the AI tool explain the three things to do first,
   what was not checked and why that matters, and nothing that sounds like "your app is secure". The report already
   leads with what was not examined; this is about the person understanding it, and it must not soften it.
   **Part status:** claimed by securevibe-e2, 9 October 2026: part 3 (sv doctor) is to build; parts 1, 5, and 7 are built (9 and 10 October 2026), none yet tried by someone who is not technical
6. **The download (0120's "later").** The single biggest barrier left is `--run`, which needs Rust. Note it here only
   so the recommendation weighs it against parts 1 to 5; the work itself stays in 0119 item 1 and 0120.
   **Part status:** claimed by securevibe-e2, 9 October 2026: part 3 (sv doctor) is to build; parts 1, 5, and 7 are built (9 and 10 October 2026), none yet tried by someone who is not technical
7. **Words.** A short glossary the guide and the reports link to (terminal, Docker, MCP, git, "not assessed"), and a
   pass over the guide for any step that assumes the reader already knows something. American English, plain, as
   everywhere.
   **Part status:** claimed by securevibe-e2, 9 October 2026: part 3 (sv doctor) is to build; parts 1, 5, and 7 are built (9 and 10 October 2026), none yet tried by someone who is not technical
8. **Watch someone do it.** Nothing above is known to help until somebody who is not technical tries it. The test is
   one person, from a computer with nothing installed, with a stopwatch and a note of every place they stopped or
   asked for help, before and after; the owner's own run on 26 September 2026 (0119) is the "before". Who that
   person is and when is the owner's to arrange.
   **Part status:** claimed by securevibe-e2, 9 October 2026: part 3 (sv doctor) is to build; parts 1, 5, and 7 are built (9 and 10 October 2026), none yet tried by someone who is not technical

**What needs the owner.** Which parts to build, and in what order. Any trial that spends money (the prompt trials
cost $18 to $35 each, `docs/prompts/library-trial/`) is asked first, every time. Windows has never been tried at
all (`docs/GETTING-STARTED.md`, "Installing SecureVibe on your computer"); whether to support it is the owner's
call, and until then every part above says so rather than implying it works there.

**The recommendation, 9 October 2026, by session securevibe-e2.** Read against `main` that day; nothing was built or
paid for. "Checked" means looked up in the code or the guide; "not checked" is said where it applies.

What reading the code settled, which the parts above did not know:

- **The container cannot find `docker` for the settings file.** The settings file's `command` must be the full path
  to `docker` on the person's computer (`/opt/homebrew/bin/docker` or `/usr/local/bin/docker`), because an app
  started from the Dock often has no search path (the guide, step 3). A program running *inside* the container
  cannot see that path. It can see the app folder's real path, when started with `-v "$PWD":"$PWD" -w "$PWD"` as the
  guide's own copy-and-paste lines are. So part 2 cannot work alone: something on the person's computer has to say
  where `docker` is, either the person (which is the step that fails today) or the AI tool, running `which docker`
  in its terminal. That is what part 1 does well and part 2 does not.
- **An "is everything ready?" tool cannot answer the question people most need answered.** When Docker is not
  running, `sv`'s tools are missing, so a `stackvet_status` tool is missing with them; and inside the container,
  `sv` has no way to tell whether the person's copy of the image is older than the latest one without opening a
  network connection, which it does not do. What it *can* say offline is narrower: whether the folder is in git,
  whether `securevibe.toml` reads, which version this is (the image already records its commit for `sv --version`),
  and what `--run` would need. Useful, but it is not the fix for setup.
- **The rules file reaches only tools that read `AGENTS.md`.** `sv rules` writes `AGENTS.md` and nothing else. Which
  tools read it on their own is not checked here (it is each tool's documentation, and it changes); Claude Code
  reads `CLAUDE.md`, so whether it also reads `AGENTS.md` needs checking before part 4 claims anything for it.

**Recommended order.**

1. **Part 1, the setup prompt, first, with a small piece of part 2 inside it.** The AI tool runs the steps the
   person stops at today: it checks that Docker is installed and running (and, if not, says where to click and
   waits), runs `docker pull`, `git init`, `pwd`, and `which docker`, and writes the settings file for the tool it
   is, with the paths it found. It asks before installing anything or writing outside the app's folder, and it
   stops and says so at any step it cannot finish. The settings text comes from `sv` itself, so the prompt never
   holds a copy that can drift: a new `sv connect <tool> --docker <path>` prints (never writes) the settings block
   for Claude, VS Code, or Cursor, with the folder's path from where it was started. Printing, not writing, keeps
   it outside the "writes into someone's folder" decision; the AI tool writes the file, with the person's
   approval, as it writes every other file. Kept in `docs/prompts/setup.md`, printed by `sv prompts setup`, and
   held by a test to the guide's image name and to `sv connect`'s output. **Cost:** one or two pull requests; no
   money. **Trying it:** the owner, once, in the tool they use, from an empty folder; a paid trial is not needed
   for a first answer.
   **Part status:** claimed by securevibe-e2, 9 October 2026: part 3 (sv doctor) is to build; parts 1, 5, and 7 are built (9 and 10 October 2026), none yet tried by someone who is not technical
2. **Part 7, the words.** A glossary of a dozen terms (terminal, Docker, image, MCP, git, folder path, "not
   assessed", "finding"), linked from the guide's first use of each, and a pass over the guide for a step that
   assumes knowledge. Cheap, and it helps whatever else is built.
   **Part status:** claimed by securevibe-e2, 9 October 2026: part 3 (sv doctor) is to build; parts 1, 5, and 7 are built (9 and 10 October 2026), none yet tried by someone who is not technical
3. **Part 5, the report read with you.** A prompt (`sv prompts report`), not a new tool: the AI tool can
   already read `compliance.md`; the prompt tells it to start with what was not checked and why that matters, then the
   three things to do first, and never to say the app is secure. A test holds the prompt to those three
   instructions. No money.
   **Part status:** claimed by securevibe-e2, 9 October 2026: part 3 (sv doctor) is to build; parts 1, 5, and 7 are built (9 and 10 October 2026), none yet tried by someone who is not technical
4. **Part 3, narrowed to what it can know:** `sv doctor` and a `stackvet_status` tool that answer git,
   `securevibe.toml`, version, and `--run` readiness in plain sentences. Worth building after 1, because the setup
   prompt's last step can call it to show the connection works.
   **Part status:** claimed by securevibe-e2, 9 October 2026: part 3 (sv doctor) is to build; parts 1, 5, and 7 are built (9 and 10 October 2026), none yet tried by someone who is not technical
5. **Part 4, measured, not built.** Add one line to the next paid prompt trial that is already happening: remove
   the tools partway and see whether the AI tool says so. No trial of its own.
   **Part status:** claimed by securevibe-e2, 9 October 2026: part 3 (sv doctor) is to build; parts 1, 5, and 7 are built (9 and 10 October 2026), none yet tried by someone who is not technical
6. **Part 8 is the test of all of the above,** and it is the owner's to arrange; until it happens, the guide says
   which tools each step was tried in, and by whom.
   **Part status:** claimed by securevibe-e2, 9 October 2026: part 3 (sv doctor) is to build; parts 1, 5, and 7 are built (9 and 10 October 2026), none yet tried by someone who is not technical
7. **Part 6 stays in 0120.** The download is the biggest barrier left for `--run`, but it needs signed releases
   (0191 part 4), and Mac notarization costs money, so it is the owner's decision there.
   **Part status:** claimed by securevibe-e2, 9 October 2026: part 3 (sv doctor) is to build; parts 1, 5, and 7 are built (9 and 10 October 2026), none yet tried by someone who is not technical

Windows: nothing above is tried there, and every part says so until the owner decides whether to support it.

**For the owner:** say which of these to build, or "as recommended", and the first is claimed the same day.

**The owner's decision, 9 October 2026: as recommended.** Parts 1 (the setup prompt, with `sv connect` printing the settings block), 7 (the glossary), 5 (the report read with you), and 3 narrowed (`sv doctor` and a status tool) are built in that order, each claimed on its own; part 4 is measured in the next paid prompt trial that runs anyway; part 8 is the owner's to arrange; part 6 stays in 0120.

**Part 1 done 9 October 2026 by session securevibe-e2** (`docs/design/0339-sv-connect-and-a-prompt-that-sets-stackvet-up-9-october-2026.md`): `sv connect TOOL [--docker PATH] [--user UID:GID]` prints the settings block for Claude, VS Code, or Cursor with the folder's real path filled in, and writes nothing; `docs/prompts/setup.md` is the setup prompt, offered at the top of the guide. Neither has been tried in an AI coding tool yet.

**Part 7 done 9 October 2026 by session securevibe-e2** (`docs/GLOSSARY.md`, linked from the guide; design entry "A glossary for the guide and the reports"). Not yet read by someone who is not technical.

**Part 5 done 10 October 2026 by session securevibe-e2** (`docs/prompts/report.md`; design entry "A prompt that reads the report with the person"): `sv prompts report` prints a prompt that has the AI tool read the report with the person, starting with what was not checked, and the MCP server offers it as `read-my-report`. Not yet tried in an AI coding tool. Part 3 (`sv doctor`, narrowed) is next.

**Part 3 done 10 October 2026 by session securevibe-e2**, on the command line (design entry "sv doctor: is everything ready?"): `sv doctor [PATH]` says in one line each whether the folder is in git, whether `stackvet.toml` reads and says how to start the app, and whether Docker can start it. The MCP status tool is left for a pull request of its own.

**Part 3 finished 10 October 2026 by session securevibe-e2:** the MCP status tool, `stackvet_status`, listed first (ADR-066, Later, 10 October 2026). Every part the owner chose to build (1, 3, 5, 7) is built.
