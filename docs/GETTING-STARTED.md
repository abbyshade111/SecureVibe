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

SecureVibe runs inside Docker, so there is nothing else to install. (One later step, which starts
your app to check it while it runs, needs SecureVibe installed on the computer itself; section 6 says
how, and it is optional.)

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
   button should now list the thirteen `securevibe_` tools.

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

More prompts like these, each for one thing SecureVibe checks, are in [the prompt library](PROMPTS.md).
The ones shown to work are already given to your AI tool, at the end of the instructions it reads first, so you
need not paste them. The rest, not yet shown to work, are there too: `sv prompts` prints them, and your AI tool can
fetch them with `securevibe_prompts`. Each says whether it has been shown to work.

SecureVibe also helps before code is written, and its own instructions tell your AI tool when: a plan of
what to decide before building (`securevibe_plan`, or `sv plan` at a terminal), a short brief before
building one feature such as sign-in, uploads, or payments (`securevibe_before`, or `sv brief`), and a
look at the settings `--run` will use, before it is run (`securevibe_preflight`, or `sv preflight`). None
of these checks anything or counts toward the report; they say what to decide and what to write.

## 5. Answer the questions

The tool will ask you things no program can know: how long someone may stay signed in, what the app
should do with a file that is too big, who may see what. It offers what it found in the code as a
tip. "I'm not sure" is a fine answer. If you ask the tool to answer for you, the report says so, and
counts it for less than your own answer.

The answers to the questions about the app's rules go in `security-notes.md`. The tool writes them there, and
every one it writes starts with `Written by: AI coding tool`, even when it is writing down what you told it:
`sv` cannot tell your words from the tool's. Read what it wrote, and where it says what you decided, change
that line to `Written by: owner` yourself. Then record it, in your own terminal:

```bash
sv review ~/code/my-app
```

It goes through each answer that does not yet count as yours, shows it, asks your name or `owner`, and
signs it with a key of its own, kept in your own settings folder. The first time, it makes that key and
asks whether to protect it with a passphrase; with one, nothing can sign as you without it. Only then does the report count it as yours: a line
saying `owner` that was never recorded this way still counts as the tool's word, because a tool trying to
quiet a warning could write that line too. The same goes for an answer the tool confirmed and you looked
at yourself, and for a finding set aside as a false alarm. `sv review` needs a terminal someone is typing
in, so your AI tool cannot run it for you. The README ("Setting a finding aside, confirming an answer, or
giving your own") says more, including how to run it from the container, with `-it` and your key folder.

**If your AI tool uses the container** (section 3), the report it writes cannot check those signatures
unless it can see your list of trusted keys, which `sv review` keeps in the same folder. Add `"-v", "/Users/you/.config/securevibe:/sv-config/securevibe", "-e",
"XDG_CONFIG_HOME=/sv-config"` to `args`, before the image name, with your own home folder (this has not
been tried in an AI tool yet). Without it, recorded answers count as the tool's word in those reports.
CI is the same: give it the one line `sv review` showed you as the variable `SV_TRUSTED_SEALS` (the README
says where). That line can check a signature but never make one, so it is safe to share.

Some questions are checks to make by hand, such as opening the live site and looking at the padlock.
The tool walks you through them and records what you saw; that record, too, counts as yours once you
have recorded it with `sv review`.

## 6. What you get without anything more, and what you do not

With the steps above, SecureVibe reads the code, the settings, and the list of packages the app uses,
and asks you the questions. It lists those packages but does not compare them with known vulnerabilities:
that needs a downloaded copy of the list of known ones, at a terminal ("Checking the packages against known
vulnerabilities", below). **It does not start the app.** The checks that need a running app, such
as what it sends to a browser, whether signing out really ends the session, and whether one person
can see another's data, are reported as *not assessed*, and so are your app's own tests, which run only when
the app is started. That is honest, not a pass.

Those checks need `sv report --run` at a terminal, with SecureVibe installed directly on your computer
rather than in Docker, because starting your app means starting containers of its own. There is no
download for that yet, so it means building SecureVibe yourself. The steps are at the end of this
section, under "Installing SecureVibe on your computer, for `--run`".

If your app uses packages, which most do, starting it also needs the line `install = true` under `[stack.run]` in
`securevibe.toml`. The app runs with no internet, so it cannot fetch its own packages; this line lets SecureVibe
download them first, in a separate box that sees only the list of packages, never your code. That download is the
one time SecureVibe uses the internet for your app, and the report says when it did. Without it, an app that needs
packages does not start, and everything that needs it running is *not assessed*.

**Where the report is.** When your AI tool writes the report (`securevibe_write_report`), or you run
`sv report`, it goes in a folder named `securevibe-report` inside the app's folder. Open `report.html` in
a browser; `compliance.md` and `security.md` say the same in plain text for your AI tool.

Each requirement in it has one of these words, strongest first:

- *needs attention*: something was found wrong;
- *checked*: a check of SecureVibe's own looked, and found nothing wrong in what it tried;
- *checked in part*: a check looked at only part of what the requirement asks;
- *tested by the app's own tests*: a test your AI tool wrote names it, and passed;
- *documented by the owner*: you wrote down your decision;
- *checked by hand by the owner*: you looked for yourself, and said what you saw;
- *attested by the owner*: you said yes to a question about how the app is built;
- *stated by the AI coding tool*: the tool answered, and you have not made the answer yours;
- *not verified*: nothing speaks to it yet.

None of them means "passed": even *checked* means one check found nothing wrong, not that the whole requirement
is met.

If you later run SecureVibe in an automatic check (CI) whenever the code changes, the number it ends with
says what happened. 0: it finished. 2: some check could not run, such as a file it could not read or a
language it does not read, so that run left part of the app unchecked. 3: SecureVibe itself failed (an
option it does not know, a folder that is not there, a `securevibe.toml` it cannot read, or, for `sv report`,
none at all), so there is no result at all. 1 comes only from `sv audit` (a
known vulnerability) or when you ask for it: `sv check . --fail-on attention:high` stops the check when
anything high or critical is found. Without `--fail-on`, findings alone never fail it. The README says
exactly what each number covers.

### Checking the packages against known vulnerabilities

Whether any package the app uses has a published vulnerability is *not assessed* until you give
SecureVibe a copy of the list of known ones. It never downloads that list itself: the names of the
packages your app depends on are yours, and a check that quietly sends them somewhere is one you did not
agree to. The list comes from OSV, a free public database, as one zip file per kind of package:

| Kind of package | Download |
|---|---|
| JavaScript (npm) | https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip |
| Python | https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip |
| Rust | https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip |
| Ruby | https://osv-vulnerabilities.storage.googleapis.com/RubyGems/all.zip |
| PHP | https://osv-vulnerabilities.storage.googleapis.com/Packagist/all.zip |
| Go | https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip |

You do not need to work out which ones your app needs: run `sv audit .` without anything more and it
names the kinds your app uses, with the address of each download. Make a folder called `osv` beside
the app, unpack each download into a folder of its own inside it (for example `osv/PyPI`), and run
`sv audit . --advisories ./osv`, or `sv report . --advisories ./osv` to put the result in the report.
The list grows every day, so download it again before a check you rely on; a copy from last month says
nothing about what was found since. A kind of package with no download here is reported as not assessed.

### Installing SecureVibe on your computer, for `--run`

You only need this for `sv report --run`. Everything in steps 1 to 5 keeps working through Docker as it
is, and your AI tool keeps using the container: the copy you build here is for typing at a terminal.

SecureVibe has no ready-made download yet, so you build it from its source code (the program written
out as text, which a builder turns into a program you can run). It is done once and takes a few
commands. These steps were tried on a Mac on 5 October 2026, from a fresh copy of SecureVibe. The Linux
steps have not been tried by hand, though SecureVibe is built on Linux every time its code changes.
**Windows:** SecureVibe has never been built or tried on Windows, so nothing here is known to work
there; use the Docker steps above, and leave `--run` out for now.

**1. The basic tools.** On a Mac, in a terminal:

```bash
xcode-select --install
```

This installs Apple's command-line tools, which include `git` and the parts Rust needs to finish
building a program. If it says they are already installed, go on. On Linux (Debian or Ubuntu):
`sudo apt install build-essential git curl`.

**2. Install Rust.** Rust is the programming language SecureVibe is written in. Installing it gives you
`cargo`, the program that builds SecureVibe. The official installer, from rust-lang.org:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

When it asks how to install, press Enter for the standard choice. Then close the terminal window and
open a new one, so it sees what was installed, and type `cargo --version`. It should print a version
number: SecureVibe needs 1.95 or newer. If yours is older, `rustup update` brings it up to date.

**3. Get SecureVibe's source code**, into a folder named `securevibe` in your home folder:

```bash
cd ~
git clone https://github.com/abbyshade111/SecureVibe.git securevibe
```

Or, without `git`: on SecureVibe's GitHub page, choose **Code**, then **Download ZIP**, unzip it,
rename the folder it makes (`SecureVibe-main`) to `securevibe`, and move it into your home folder.
Built that way, `sv --version` says `commit unknown` rather than which version of the code it is, and
updating means downloading it again.

**4. Build and install it:**

```bash
cd ~/securevibe
sh tools/install.sh
```

The first time, `cargo` downloads the pieces SecureVibe is made from, and the build takes a few
minutes. Then the script copies the program and the files it reads into a folder of their own,
`~/.local/share/securevibe`, and puts a link to the program at `~/.local/bin/sv`. It ends by printing
the version and `Installed.` If `~/.local/bin/sv` is already there and is not its own link, it stops
and says so rather than replace it.

**5. Let the terminal find it.** When you type a command, the terminal looks for it in a list of
folders called your `PATH`. This adds the folder with the link to that list, for every terminal you
open from now on. On a Mac:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
```

On Linux, the same line with `~/.bashrc` at the end instead of `~/.zshrc`. Then close the terminal
window and open a new one.

**6. Check it:**

```bash
sv --version
sv check ~/securevibe/examples/flask-booking
```

The first prints `sv 0.1.0` and the version of the code it was built from, and on a second line the
folder of files it reads (`data: …/.local/share/securevibe/data`). The second checks one of the example apps that come with it: it
should say what it read and what it found, not `Error`. If it says `command not found: sv`, step 5 has
not taken effect: open a new terminal window, or look for the line at the end of `~/.zshrc`.

**The installed copy does not need the `securevibe` folder.** Each time SecureVibe runs, it reads more
than a dozen of its own files (the security standards and its rules). The installed copy reads the ones
the script put beside it, so moving, renaming, or deleting the folder you built it in does not stop it.
Use `~/.local/bin/sv` wherever a full path is asked for, as in your AI tool's settings; it stays the same
when you build again. A copy of the program on its own, without its `data` folder beside it, falls back to
the folder it was built in; once that is gone, it cannot find those files and says where it looked. Before 5 October 2026 the guide had you use the program in
the build folder; if your `PATH` or your AI tool's settings name `…/securevibe/target/release/sv`, change
them to `~/.local/bin/sv`.

**The build folder can be deleted.** Building leaves a folder named `target` inside `~/securevibe`, of 1 to 7 GB,
which the installed copy does not use. To get the space back:

```bash
rm -rf ~/securevibe/target
```

That removes only the build's leftovers: `sv` keeps working, and so does your AI tool's link to it. The next
time you update SecureVibe, the build takes its few minutes again, as it did the first time.

**Docker or Colima has to be running** for `--run`, as in step 1 of this guide, because that is what
starts your app. With Colima on a Mac, your app's folder has to be inside your home folder (Colima
shares only that unless you tell it otherwise); if it is not, the report says so and why.

Your AI tool tells you the exact command to type. It looks like this, with your own app folder:

```bash
sv report /Users/you/code/my-app --run
```

To update SecureVibe later: `cd ~/securevibe`, then `git pull`, then `sh tools/install.sh` again. It
replaces the program and its files together.

## Known problems while this is new

Found in the first real build. Each is in `docs/BACKLOG.md`. The two listed here before, a rate limiter
counted as a public API and security notes the AI tool wrote counted as yours, were fixed on
27 September 2026. Nothing from that build is known to be open.
