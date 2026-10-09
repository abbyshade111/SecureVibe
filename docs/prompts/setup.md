# A prompt that sets StackVet up for you

Setting StackVet up by hand takes about fifteen minutes and a terminal: install Docker, fetch StackVet, put the app's
folder in git, and write a settings file with the folder's full path typed into three places. Two of those steps fail
without a word: if Docker is not running, or a path is wrong, your AI coding tool simply has no StackVet tools.

This prompt hands those steps to your AI coding tool. Most of them (Claude Code, GitHub Copilot's agent mode, Cursor)
can run commands in a terminal, so they can check that Docker is running, fetch StackVet, and find the paths
themselves. The settings text comes from StackVet itself (`sv connect`), so the prompt holds no copy of it that could
go out of date. You are asked before anything is installed or changed outside the app's folder, and the tool stops
and tells you at any step it cannot finish.

**Tried so far:** not yet in any AI coding tool. A test holds the prompt to the image name StackVet is published
under and to the options `sv connect` takes (`crates/sv-cli/tests/connect.rs`). Until someone has run it from an
empty folder, follow [the guide](../GETTING-STARTED.md) if anything here goes wrong. **Windows:** StackVet has not
been tried there; the prompt says so and stops.

Open an empty folder for your app in your AI coding tool, and paste this:

<!-- setup-prompt:start -->
> Please set up StackVet in this folder so you can use its tools while we build. StackVet runs in Docker. Work
> through these steps in order, using your terminal. Ask me before you install anything, and before you change
> anything outside this folder. If a step fails or you are unsure, stop and tell me what happened in plain words:
> do not carry on as though StackVet were set up.
>
> 1. Tell me which computer this is (Mac, Linux, or Windows). If it is Windows, stop: StackVet has not been
>    tried on Windows yet, and I will follow the guide instead.
> 2. Check that Docker is installed and running with `docker info`. If it is not installed, tell me where to get
>    Docker Desktop and wait for me. If it is installed but not running, ask me to start it and wait.
> 3. Fetch StackVet: `docker pull ghcr.io/abbyshade111/stackvet-sv`
> 4. If this folder is not a git repository yet, run `git init` here.
> 5. Find docker's full path with `command -v docker`.
> 6. Print the settings for yourself. Use `claude` if you are Claude, `vscode` if you are GitHub Copilot in VS Code,
>    or `cursor` if you are Cursor, and put docker's full path from step 5 after `--docker`:
>    `docker run --rm --network none -v "$PWD":"$PWD" -w "$PWD" ghcr.io/abbyshade111/stackvet-sv connect TOOL --docker DOCKER_PATH`
>    On Linux, also add `--user "$(id -u):$(id -g)"` at the end, so the files StackVet writes are mine.
> 7. It names the settings file to put this in (`.mcp.json`, `.vscode/mcp.json`, or `.cursor/mcp.json`). Show me
>    the file, then write it into this folder exactly as printed. If the file already exists, show me both and ask
>    before changing it.
> 8. Tell me to restart you (or, in VS Code, to click **Start** above `stackvet` in `.vscode/mcp.json`), and to
>    paste this when you are back: "Which `stackvet_` tools can you call? List their names." If you list none,
>    StackVet is not connected: say so, and check Docker is running and the path in the settings file.
<!-- setup-prompt:end -->

After the restart, if your AI coding tool lists the `stackvet_` tools, go on to step 4 of
[the guide](../GETTING-STARTED.md), "Start the build with this prompt".

**Already have `sv` installed** (for example with Homebrew)? Then the settings can use it directly instead of Docker:
`sv connect claude` (or `vscode`, or `cursor`) in the app's folder prints them, starting your installed copy by its
own path.
