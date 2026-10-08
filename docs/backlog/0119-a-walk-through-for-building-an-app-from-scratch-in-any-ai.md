# A walk-through for building an app from scratch in any AI coding tool, with `sv` alongside

**Status:** partly done: 0 of 7 parts done, 0 claimed, 6 open, as its markers read on 8 October 2026

Asked for by the owner on 26 September 2026: "it can't be too difficult, since the whole idea is
making it easy for people who aren't technical or security experts to vibe code safely." **Claimed
on 26 September 2026 by session securevibe-e8**, at the owner's asking, now the container is done.
**Done on 27 September 2026:** `docs/GETTING-STARTED.md`, linked from the README. It covers Docker
(start it before the tool), a git folder (so the committed-secrets check runs), the `.mcp.json`
for Claude with the published image, the settings files for Cursor and VS Code marked *not yet
tried* (VS Code tried by the owner the same day, start to finish, and written up; see below), the copy-and-paste path for a tool without MCP
(`sv init`, `check`, `questions` through Docker, each tried), a starting prompt (which tells the tool
to delete a capability line it is unsure of rather than leave it `false`, to keep reports out of
the app's folder, and to ask before rewriting code a finding may have got wrong), and a plain section
on what is not checked without `--run`. Its "Known problems" lists items 1 to 4 of the entry on the
owner's first build; each line comes out as its fix lands. The walk-through itself is short — describe the app, have the tool write
`securevibe.toml` from `securevibe_spec`, build, run `securevibe_check` after each feature, let
`securevibe_questions` interview the owner, then `sv report --run` — and it is set down with a starter
prompt in the conversation that produced this entry. **VS Code, tried by the owner on 27 September
2026:** it worked start to finish — Copilot's agent asked every question from `securevibe_questions`,
patched the path findings and re-ran the check to confirm, with `sv` installed directly (the container
form is untried in VS Code). The answers were saved in the app's folder, and a fresh `sv report` showed
both them and the fix. The one stumble was setup: a hand-made
`.vscode/mcp.json` was not listed under *MCP: List Servers*, so the guide now has VS Code write it
(*MCP: Add Server…*). Cursor is still untried. **What is not short is getting to step one**,
and a page of instructions cannot fix that on its own. Found by trying it the same day, as the owner,
from an empty folder in Claude Code; each of these stopped the attempt:

1. **`sv` has to be built from source, so step one is "install Rust".** README: "Rust 1.95 or newer",
   then `cargo build`. Nobody the product is for has a Rust toolchain, a git checkout, or a reason to
   get either. This is the real obstacle, and the walk-through should not be written until it is
   gone: a download for each platform, built by CI.
2. **A built `sv` cannot be moved.** It reads a dozen of its own data files at run time —
   `ast-rules.json`, `applicability-v2.json`, `sbd-asvs-crosswalk.json`, `tech-signatures.json` and
   others — from the folder it was built in, found through `env!("CARGO_MANIFEST_DIR")`, which is
   fixed when it is compiled. `SV_DATA_DIR` moves only the shared OWASP folder, not these. So a copy
   in `~/.local/bin` works until the build folder goes away and then fails with "cannot find the OWASP
   data folder" or worse. The test run needed a permanent git worktree just to have somewhere `sv`
   could live. A downloadable `sv` needs its data either compiled in (`include_str!`, as
   `atlas-references.json` and `breached-password-evidence.json` already are) or found beside the
   binary.
   **A new form of it, in my-first-app on 28 September and 4 October 2026** (added on 4 October 2026 by the
   cato-pipeline session, usability analysis for `docs/paper`, from the build's transcript). The owner's PATH line
   and the app's `.mcp.json` both pointed at `sv` inside a build folder (`…/sv-tool-main/target/release/sv`). That
   folder was later removed (the transcript does not say by whom), so on 28 September `which sv` printed "sv not
   found", and on 4 October the AI tool's MCP connection to `sv` failed at startup. The AI tool found another build
   on the Desktop, and the owner edited `~/.zshrc` by hand again and had the tool edit `.mcp.json`,
   which only takes effect in a new session. Compiling the data in would not have helped here: the program itself
   went with its folder. What helps is an install that does not live in a folder somebody works in. Still the case
   on `main` at 6d4ce3f (`crates/sv-cli/src/main.rs`, lines 264 to 350 and others, read data through
   `CARGO_MANIFEST_DIR`).
   **Claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking, in branch
   `claude/securevibe-e9-movable`: every data file found through one place, `SV_DATA_DIR`, then beside the program,
   then the build folder; and an install script that keeps `sv` and its data out of any working folder. Record:
   ADR-036 (proposed).
   **Done the same day** (DESIGN, "A copy of `sv` reads the data beside it, and installs outside the build
   folder"; ADR-036, accepted): every file found through `sv_frameworks::data`; `sv --version` names the data
   folder; `tools/install.sh` puts `sv` and its data in `~/.local/share/securevibe`, linked from `~/.local/bin/sv`,
   and the guide installs that way. Not done: compiling the data into the program, which a single downloadable
   file would need.
3. **The README's MCP instructions assume a command the desktop app does not install.** It gives
   `claude mcp add securevibe -- …`; in the desktop app that fails with `zsh: command not found:
   claude`. A `.mcp.json` in the app's folder works instead and needs nothing installed. Other tools
   keep their MCP settings in other files, and not all under the same key, so the walk-through needs
   one short, checked section per tool — each one tried, not written from memory.
4. **`--root` has to exist, and the app has to be inside it.** Nothing says so until the tool is
   refused. The walk-through should create the folder in its first step.
5. **The starter manifest answers "no" to everything** — every capability in `sv init` reads
   `false`, so a tool that leaves a line as it found it has told `sv` the app has no sign-in, no
   uploads, no email. See "Hand the three question lists to the AI coding tool", above, where it is
   recorded and left for its own decision. For this audience it is the most dangerous line in the
   product: a beginner's tool will leave most of them alone. Until it changes, the starter prompt has
   to say "delete a capability you are not sure of rather than leaving it `false`."
6. **The deepest checks need Docker.** `sv report --run` starts the app behind the fence, and that
   needs Docker or Colima — a second install for somebody who is not technical, and on a Mac, a
   virtual machine. Without it the running-app and signed-in checks are *not assessed*, which is
   honest; the walk-through has to say plainly what is missed without it, not bury it.
7. Smaller: the README says `sv mcp` offers four tools; it offers six (`securevibe_questions` and
   `securevibe_notes_file` were added the same day).

So the order is: `sv` in a container, which settles 1 and 2 with no change to the code (decided the
same day; see "Packaging `sv`", below), then the walk-through, with
one checked page per AI tool (3, 4), the starter prompt (5), and an honest line about Docker (6). A
tool without MCP can still follow it by pasting `sv init` and `sv questions` into its chat, and the
walk-through should say so, since that is the path that works in every tool.
