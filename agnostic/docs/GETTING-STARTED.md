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
  files it writes are yours rather than root's.

### Other tools

The same `command` and `args` go in the tool's own MCP settings file. **These have not been tried
with SecureVibe yet**, so if one does not work, tell us:

- **Cursor:** `.cursor/mcp.json` in the app's folder, with the same `mcpServers` block as above.
- **VS Code (Copilot):** `.vscode/mcp.json`, where the block is called `servers` instead of
  `mcpServers`, and each server has `"type": "stdio"`.

The owner has offered to try VS Code; this section will say what was found once that is done.

### A tool without MCP

Every step still works by copying and pasting. Instead of the tool calling SecureVibe, you run it in a
terminal in the app's folder and paste what it prints into the chat:

```bash
docker run --rm ghcr.io/abbyshade111/securevibe-sv init
docker run --rm --network none -v "$PWD":"$PWD" -w "$PWD" ghcr.io/abbyshade111/securevibe-sv check .
docker run --rm --network none -v "$PWD":"$PWD" -w "$PWD" ghcr.io/abbyshade111/securevibe-sv questions .
```

## 4. Start the build with this prompt

Open the app's folder in your AI tool and paste this, with your app described at the top:

> I want to build: *(describe the app in a few sentences: who uses it, what they do, what it keeps
> about them)*.
>
> We are using SecureVibe to check it as we go. Before writing any code:
> 1. Call `securevibe_spec` and write `securevibe.toml` for this app, from what it will really do.
>    If you are not sure whether a capability applies, **delete that line rather than leaving it
>    `false`**: a line left as `false` tells SecureVibe the app does not do it, and whole sets of
>    checks are then switched off.
>
> Then, as we build:
> 2. After each feature, call `securevibe_check`. Read what it says was not examined first. Fix what
>    it finds that is real. If a finding looks wrong, tell me instead of rewriting working code to
>    make it go away.
> 3. Never tell me the app is secure. Tell me what was checked and what was not.
> 4. When the first version works, call `securevibe_questions` and ask me the questions one at a time.
>    Record only what I actually answer as mine.
> 5. Keep `securevibe-report`, or any report SecureVibe writes, out of the app's folder.

## 5. Answer the questions

The tool will ask you things no program can know: how long someone may stay signed in, what the app
should do with a file that is too big, who may see what. It offers what it found in the code as a
tip. "I'm not sure" is a fine answer. If you ask the tool to answer for you, the report says so, and
counts it for less than your own answer.

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

Found in the first real build, and not yet fixed. Each is in `docs/BACKLOG.md`.

- **A report written inside the app's folder breaks the next check.** SecureVibe then reads its own
  report as your app's code, and the number of requirements it can check falls sharply. That is why
  the prompt says to keep reports out of the app's folder.
- **Two kinds of false alarm are rated high.** A pattern-matching call named `exec`, and a test tool's
  `.query(...)`, are reported as a shell command and a database query. If one appears, ask the tool
  whether it is really a shell command or a database query before it changes anything.
- **A rate limiter counts as a sign of a public API**, which adds requirements an app without one does
  not need. Harmless beyond the extra list.
- **Security notes the AI tool wrote are counted as yours.** Only let it write a note you agree with.
