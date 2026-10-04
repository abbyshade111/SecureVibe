# Building an app with SecureVibe alongside

This is for building an app from an empty folder with an AI coding tool, with SecureVibe checking it as
you go. You do not need to know how to program, and you do not need to know about security: the tool
writes the code, SecureVibe checks it against the OWASP security standards, and the two of them ask you
the questions only you can answer.

It takes about fifteen minutes to set up, once.

## What SecureVibe will and will not tell you

It never says your app is secure. It says what it checked, what it found, and, first of all, what it
did not look at. A short report is not a good sign unless the part saying what was not examined is
short too.

## 1. Install Docker, and start it

SecureVibe runs inside Docker, so there is nothing else to install.

- **On a Mac:** Docker Desktop (docker.com), or Colima if you prefer something smaller.
- **On Windows or Linux:** Docker Desktop, or Docker itself on Linux.

**Docker has to be running before you open your AI tool.** If it is not, the SecureVibe tools are
simply missing from the tool, and nothing tells you why. After a restart, start Docker first.

Then fetch SecureVibe, in a terminal:

```bash
docker pull ghcr.io/abbyshade111/securevibe-sv
```

## 2. Make a folder for the app, and put it in git

Make an empty folder for the app, for example `~/code/my-app`. Then, in a terminal in that folder:

```bash
git init
```

(Or ask your AI tool to do it.) This matters more than it looks: the check for a password or key that
was ever saved into your project's history only runs in a git folder. Without it, that check is
reported as *not assessed*.

## 3. Connect SecureVibe to your AI tool

Your AI tool talks to SecureVibe over MCP, a standard way for AI tools to use other programs. You add
one small file to the app's folder. In each example, replace `/Users/you/code/my-app` with your app
folder's full path, in all three places. On a Mac, `pwd` in a terminal in that folder prints it.

### Claude (the desktop app and Claude Code)

A file named `.mcp.json` in the app's folder. A `.mcp.json` like this was tried in the Claude
desktop app with SecureVibe installed directly; this container version of it has been tried by a
test that talks to it the way the tool does, not yet in the app itself.

```json
{ "mcpServers": { "securevibe": {
  "command": "/opt/homebrew/bin/docker",
  "args": ["run", "-i", "--rm", "--network", "none",
           "-v", "/Users/you/code/my-app:/Users/you/code/my-app",
           "ghcr.io/abbyshade111/securevibe-sv", "mcp", "--root", "/Users/you/code/my-app"] } } }
```

- `command` is the full path to `docker`, because an app started from the Dock often cannot find it.
  `which docker` in a terminal prints yours. With Docker Desktop it is often `/usr/local/bin/docker`.
- The first time you open the folder, the tool asks whether to use the new server. Say yes.
- On Linux, add `"--user", "1000:1000"` (your own `id -u` and `id -g`) before the image name, so the
  files it writes are yours. Without it the image runs as a user of its own, never root, and that user
  cannot write into your folder. On a Mac, Docker Desktop makes what it writes yours either way.

### VS Code (GitHub Copilot)

**Tried on 27 September 2026, by the owner, start to finish:** Copilot's agent called SecureVibe's
tools, asked every question from `securevibe_questions` one at a time, wrote a fix for the path
findings `securevibe_check` reported, and checked the fix by running the check again. The answers were
saved in the app's folder, and a fresh report showed them and the fix. That was with `sv` installed
directly; the container settings below have not been tried in VS Code yet.

You need the GitHub Copilot Chat extension, with the chat in **Agent** mode (the mode that can use
other programs), and VS Code 1.102 or newer. If you use a paid Copilot plan, each request may count
against its monthly allowance.

**Let VS Code write the settings file for you.** A file typed or pasted by hand was not picked up the
first time it was tried: a wrong folder, or quotes turned curly by a text editor, breaks it without any
message. Instead:

1. Open the app's folder in VS Code (*File → Open Folder*).
2. Open the Command Palette (Cmd-Shift-P on a Mac, Ctrl-Shift-P elsewhere), and choose
   **MCP: Add Server…**, then **Command (stdio)**.
3. For the command, give SecureVibe's full path, then `mcp --root ${workspaceFolder}`. With `sv`
   installed: `/full/path/to/sv mcp --root ${workspaceFolder}` (`which sv` in a terminal prints the
   path). VS Code fills in `${workspaceFolder}` with the open folder, so there is no path to type.
4. Name it `securevibe`, and save it for the **Workspace** (this app only).
5. In the `.vscode/mcp.json` it opens, click **Start** above `securevibe`. In the chat, the tools
   button should now list the six `securevibe_` tools.

The file it writes looks like this:

```json
{ "servers": { "securevibe": {
  "type": "stdio",
  "command": "/full/path/to/sv",
  "args": ["mcp", "--root", "${workspaceFolder}"] } } }
```

For the container instead (not yet tried in VS Code), `command` is the full path to `docker` and `args` are
`["run", "-i", "--rm", "--network", "none", "-v", "${workspaceFolder}:${workspaceFolder}",
"ghcr.io/abbyshade111/securevibe-sv", "mcp", "--root", "${workspaceFolder}"]`.

If **MCP: Add Server…** is not in the list, check the VS Code version (*Code → About*), search Settings
for `mcp` in case it is switched off, and, if your Copilot comes through work or school, ask whether
your organization has turned these tools off. If SecureVibe does not appear or will not start,
**MCP: List Servers → securevibe → Show Output** says why.

### Other tools

The same `command` and `args` go in the tool's own MCP settings file. **Cursor has not been tried
with SecureVibe yet**, so if it does not work, tell us:

- **Cursor:** `.cursor/mcp.json` in the app's folder, with the same `mcpServers` block as for Claude, above.

### A tool without MCP

Every step still works by copying and pasting. Instead of the tool calling SecureVibe, you run it in a
terminal in the app's folder and paste what it prints into the chat:

```bash
docker run --rm ghcr.io/abbyshade111/securevibe-sv init
docker run --rm --network none -v "$PWD":"$PWD" -w "$PWD" ghcr.io/abbyshade111/securevibe-sv check .
docker run --rm --network none -v "$PWD":"$PWD" -w "$PWD" ghcr.io/abbyshade111/securevibe-sv questions .
docker run --rm --network none -v "$PWD":"$PWD" -w "$PWD" ghcr.io/abbyshade111/securevibe-sv rules .
```

On Linux, add `--user "$(id -u):$(id -g)"` after `docker run` in each line, for the same reason as
above. The last one writes the security rules for your tool into `AGENTS.md` in the app's folder, which many
tools read on their own; see "Rules your AI coding tool follows while it codes" in the README.

## 4. Start the build with this prompt

Open the app's folder in your AI tool and paste this, with your app described at the top:

> I want to build: *(describe the app in a few sentences: who uses it, what they do, what it keeps
> about them)*.
>
> We are using SecureVibe to check it as we go. Before writing any code:
> 1. Call `securevibe_spec` and write `securevibe.toml` for this app, from what it will really do.
>    Its capability lines start commented out: answer each one you can with true or false, and
>    **leave a line commented out rather than guessing `false`**. A line left out is reported as not
>    assessed; a wrong `false` switches whole sets of checks off.
> 2. Call `securevibe_guidance` and follow the rules it gives while you write code. Call it again
>    with a topic before work in that area: adding a package, a CI workflow, anything with keys.
>
> Then, as we build:
> 3. After each feature, call `securevibe_check`. Read what it says was not examined first. Fix what
>    it finds that is real. If a finding looks wrong, tell me instead of rewriting working code to
>    make it go away.
> 4. Never tell me the app is secure. Tell me what was checked and what was not.
> 5. When the first version works, call `securevibe_questions` and ask me the questions one at a time.
>    Record only what I actually answer as mine.

## 5. Answer the questions

The tool will ask you things no program can know: how long someone may stay signed in, what the app
should do with a file that is too big, who may see what. It offers what it found in the code as a
tip. "I'm not sure" is a fine answer. If you ask the tool to answer for you, the report says so, and
counts it for less than your own answer.

The answers to the questions about the app's rules go in `security-notes.md`. The tool writes them there, and
every one it writes starts with `Written by: AI coding tool`, even when it is writing down what you told it:
`sv` cannot tell your words from the tool's. Read what it wrote, and where it says what you decided, change
that line to `Written by: owner` yourself. Only then does the report count it as yours.

Some questions are checks to make by hand, such as opening the live site and looking at the padlock.
The tool walks you through them and records what you saw.

## 6. What you get without anything more, and what you do not

With the steps above, SecureVibe reads the code, the settings, and the list of packages the app uses,
and asks you the questions. **It does not start the app.** The checks that need a running app, such
as what it sends to a browser, whether signing out really ends the session, and whether one person
can see another's data, are reported as *not assessed*. That is honest, not a pass.

Those checks need `sv report --run` at a terminal, with SecureVibe installed directly rather than in
Docker, because starting your app means starting containers of its own. That install is not yet
something this guide can make easy.

## Known problems while this is new

Found in the first real build. Each is in `docs/BACKLOG.md`. The two listed here before, a rate limiter
counted as a public API and security notes the AI tool wrote counted as yours, were fixed on
27 September 2026. Nothing from that build is known to be open.
