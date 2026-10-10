<picture>
  <source media="(prefers-color-scheme: dark)" srcset="brand/stackvet-logo-dark.svg">
  <img alt="StackVet" src="brand/stackvet-logo.svg" width="320">
</picture>

# Building an app with StackVet alongside

This is for building an app from an empty folder with an AI coding tool, with StackVet checking it as
you go. You do not need to know how to program, and you do not need to know about security: the tool
writes the code, StackVet checks it against the OWASP security standards, and the two of them ask you
the questions only you can answer.

It takes about fifteen minutes to set up, once. A word here you do not know is probably in
[the glossary](GLOSSARY.md).

**Or let your AI coding tool do steps 1 to 3.** [The setup prompt](prompts/setup.md) asks it to check Docker, fetch
StackVet, put the folder in git, and write the settings file with the paths already filled in, asking you before
it installs or changes anything outside the folder. It is new and has not yet been tried in any AI coding tool, so
the steps below are still the way that is known to work.

## What StackVet will and will not tell you

It never says your app is secure. It says what it checked, what it found, and, first of all, what it
did not look at. A short report is not a good sign unless the part saying what was not examined is
short too.

## 1. Install Docker, and start it

StackVet runs inside [Docker](GLOSSARY.md#docker), so there is nothing else to install. (One later step, which starts
your app to check it while it runs, needs StackVet installed on the computer itself; section 6 says
how, and it is optional.)

- **On a Mac:** Docker Desktop (docker.com), or Colima if you prefer something smaller.
- **On Windows or Linux:** Docker Desktop, or Docker itself on Linux.

**Docker has to be running before you open your AI tool.** If it is not, the StackVet tools are
simply missing from the tool, and nothing tells you why. After a restart, start Docker first.

Then fetch StackVet, in a [terminal](GLOSSARY.md#terminal):

```bash
docker pull ghcr.io/abbyshade111/stackvet-sv
```

## 2. Make a folder for the app, and put it in git

Make an empty folder for the app, for example `~/code/my-app`. Then, in a terminal in that folder, start
[git](GLOSSARY.md#git) there:

```bash
git init
```

(Or ask your AI tool to do it.) This matters more than it looks: the check for a password or key that
was ever saved into your project's history only runs in a git folder. Without it, that check is
reported as [*not assessed*](GLOSSARY.md#not-assessed).

## 3. Connect StackVet to your AI tool

Your AI tool talks to StackVet over [MCP](GLOSSARY.md#mcp), a standard way for AI tools to use other programs. You add
one small file to the app's folder. In each example, replace `/Users/you/code/my-app` with your app
folder's full path, in all three places. On a Mac, `pwd` in a terminal in that folder prints it.

StackVet can print the file for you with the paths already right. In a terminal in the app's folder (put
`claude`, `vscode`, or `cursor` for your tool):

```bash
docker run --rm --network none -v "$PWD":"$PWD" -w "$PWD" ghcr.io/abbyshade111/stackvet-sv connect claude --docker "$(command -v docker)"
```

It prints the settings and the name of the file they go in, and writes nothing itself. On Linux, add
`--user "$(id -u):$(id -g)"` at the end. The examples below show what it prints.

### Claude (the desktop app and Claude Code)

A file named `.mcp.json` in the app's folder. A `.mcp.json` like this was tried in the Claude
desktop app with StackVet installed directly; this container version of it has been tried by a
test that talks to it the way the tool does, not yet in the app itself.

```json
{ "mcpServers": { "stackvet": {
  "command": "/opt/homebrew/bin/docker",
  "args": ["run", "-i", "--rm", "--network", "none",
           "-v", "/Users/you/code/my-app:/Users/you/code/my-app",
           "ghcr.io/abbyshade111/stackvet-sv", "mcp", "--root", "/Users/you/code/my-app"] } } }
```

- `command` is the full path to `docker`, because an app started from the Dock often cannot find it.
  `which docker` in a terminal prints yours. With Docker Desktop it is often `/usr/local/bin/docker`.
- The first time you open the folder, the tool asks whether to use the new server. Say yes.
- On Linux, add `"--user", "1000:1000"` (your own `id -u` and `id -g`) before the image name, so the
  files it writes are yours. Without it the image runs as a user of its own, never root, and that user
  cannot write into your folder. On a Mac, Docker Desktop makes what it writes yours either way.

### VS Code (GitHub Copilot)

**Tried on 27 September 2026, by the owner, start to finish:** Copilot's agent called StackVet's
tools, asked every question from `stackvet_questions` one at a time, wrote a fix for the path
findings `stackvet_check` reported, and checked the fix by running the check again. The answers were
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
3. For the command, give StackVet's full path, then `mcp --root ${workspaceFolder}`. With `sv`
   installed: `/full/path/to/sv mcp --root ${workspaceFolder}` (`which sv` in a terminal prints the
   path). VS Code fills in `${workspaceFolder}` with the open folder, so there is no path to type.
4. Name it `stackvet`, and save it for the **Workspace** (this app only).
5. In the `.vscode/mcp.json` it opens, click **Start** above `stackvet`. In the chat, the tools
   button should now list the twelve `stackvet_` tools.

The file it writes looks like this:

```json
{ "servers": { "stackvet": {
  "type": "stdio",
  "command": "/full/path/to/sv",
  "args": ["mcp", "--root", "${workspaceFolder}"] } } }
```

For the container instead (not yet tried in VS Code), `command` is the full path to `docker` and `args` are
`["run", "-i", "--rm", "--network", "none", "-v", "${workspaceFolder}:${workspaceFolder}",
"ghcr.io/abbyshade111/stackvet-sv", "mcp", "--root", "${workspaceFolder}"]`.

If **MCP: Add Server…** is not in the list, check the VS Code version (*Code → About*), search Settings
for `mcp` in case it is switched off, and, if your Copilot comes through work or school, ask whether
your organization has turned these tools off. If StackVet does not appear or will not start,
**MCP: List Servers → stackvet → Show Output** says why.

### Other tools

The same `command` and `args` go in the tool's own MCP settings file. **Cursor has not been tried
with StackVet yet**, so if it does not work, tell us:

- **Cursor:** `.cursor/mcp.json` in the app's folder, with the same `mcpServers` block as for Claude, above.

### Did it connect?

Check before you start building, in whichever tool you use. If StackVet is not connected, the tool
does not say so: it simply builds without it, and nothing gets checked. In the tool's chat, ask:

> Which `stackvet_` tools can you call? List their names.

It should list twelve, among them `stackvet_spec` and `stackvet_check`. If it lists none, or says it
has no such tools, StackVet is not connected. If it lists them, `stackvet_status` says whether the rest
is ready: the folder in git, `stackvet.toml`, and how to start the app. Then, in this order: make sure Docker is running (step
1); check the app folder's path in the settings file, in all three places; and restart the tool, since
most read their MCP settings only when they start. In Claude Code, `/mcp` lists each server and
whether it connected. In VS Code, **MCP: List Servers → stackvet → Show Output** says why it did
not start.

If the tool stops mentioning StackVet later, ask again: after a restart, Docker may not have
started yet.
The prompt in step 4 tells the tool to stop and tell you when the tools are missing, and the rules
file below (`sv rules`) says the same to any tool that reads `AGENTS.md`, so a tool that finds them
gone later should say so rather than carry on.

### A tool without MCP

Every step still works by copying and pasting. Instead of the tool calling StackVet, you run it in a
terminal in the app's folder and paste what it prints into the chat:

```bash
docker run --rm ghcr.io/abbyshade111/stackvet-sv init
docker run --rm --network none -v "$PWD":"$PWD" -w "$PWD" ghcr.io/abbyshade111/stackvet-sv check .
docker run --rm --network none -v "$PWD":"$PWD" -w "$PWD" ghcr.io/abbyshade111/stackvet-sv questions .
docker run --rm --network none -v "$PWD":"$PWD" -w "$PWD" ghcr.io/abbyshade111/stackvet-sv rules .
```

On Linux, add `--user "$(id -u):$(id -g)"` after `docker run` in each line, for the same reason as
above. The last one writes the security rules for your tool into `AGENTS.md` in the app's folder, which many
tools read on their own; see "Rules your AI coding tool follows while it codes" in the README.

## 4. Start the build with this prompt

Open the app's folder in your AI tool and paste this, with your app described at the top:

> I want to build: *(describe the app in a few sentences: who uses it, what they do, what it keeps
> about them)*.
>
> We are using StackVet to check it as we go. If you cannot call the `stackvet_` tools, stop
> and tell me before writing any code: it means StackVet is not connected. Before writing any code:
> 1. Call `stackvet_spec` and write `stackvet.toml` for this app, from what it will really do.
>    Its capability lines start commented out: answer each one you can with true or false, and
>    **leave a line commented out rather than guessing `false`**. A line left out is reported as not
>    assessed; a wrong `false` switches whole sets of checks off.
> 2. Call `stackvet_guidance` and follow the rules it gives while you write code. Call it again
>    with a topic before work in that area: adding a package, a CI workflow, anything with keys.
>
> Then, as we build:
> 3. After each feature, call `stackvet_check`. Read what it says was not examined first. Fix what
>    it finds that is real. If a finding looks wrong, tell me instead of rewriting working code to
>    make it go away.
> 4. Never tell me the app is secure. Tell me what was checked and what was not.
> 5. When the first version works, call `stackvet_check` with section `questions` and ask me the
>    questions one at a time. Record my answers with `stackvet_record_answer`, and only what I
>    actually answer as mine.

More prompts like these, each for one thing StackVet checks, are in [the prompt library](PROMPTS.md).
The ones shown to work are already given to your AI tool, at the end of the instructions it reads first, so you
need not paste them. The rest, not yet shown to work, are there too: `sv prompts` prints them, and your AI tool can
fetch them with `stackvet_prompts`. Each says whether it has been shown to work.

StackVet also helps before code is written, and its own instructions tell your AI tool when: a plan of
what to decide before building (`stackvet_plan`, or `sv plan` at a terminal), a short brief before
building one feature such as sign-in, uploads, or payments (`stackvet_before`, or `sv brief`), and a
look at the settings `--run` will use, before it is run (`stackvet_preflight`, or `sv preflight`). None
of these checks anything or counts toward the report; they say what to decide and what to write.

## 5. Answer the questions

The tool will ask you things no program can know: how long someone may stay signed in, what the app
should do with a file that is too big, who may see what. It offers what it found in the code as a
tip. "I'm not sure" is a fine answer. If you ask the tool to answer for you, the report says so, and
counts it for less than your own answer.

The answers to the questions about the app's rules go in `security-notes.md`. The tool writes them there, and
every one it writes starts with `Written by: AI coding tool`, even when it is writing down what you told it:
`sv` cannot tell your words from the tool's. Read what it wrote, and where it says what you decided, change
that line to `Written by: owner` yourself. Where the tool worked an answer out from the code and you have
checked it and agree, leave its line as it is: `sv review` offers it for you to confirm, and the report then
shows it as the tool's words a person confirmed, never as your own. Then record it, in your own terminal:

```bash
sv review ~/code/my-app
```

**With only Docker** (you have not built StackVet on your computer), run it from the container instead.
Once, make the folder it keeps its key in, so that the folder is yours and only yours:

```bash
mkdir -p ~/.config/stackvet && chmod 700 ~/.config/stackvet && touch ~/.config/stackvet/allowed_signers
```

Then, each time, in a terminal in the app's folder:

```bash
docker run --rm -it --network none -v "$PWD":"$PWD" -w "$PWD" -v "$HOME/.config/stackvet":/sv-config/stackvet -e XDG_CONFIG_HOME=/sv-config ghcr.io/abbyshade111/stackvet-sv review .
```

`-it` gives it your terminal to ask its questions in, and the second `-v` lets it keep its key in that
folder on your computer rather than inside the container, which is thrown away when it ends. On Linux,
add `--user "$(id -u):$(id -g)"` after `docker run`, as in section 3.

It goes through each answer that does not yet count as yours, shows it, asks your name or `owner`, and
signs it with a key of its own, kept in your own settings folder. The first time, it makes that key and
asks for a passphrase to protect it with (press Enter to choose one, or type `none`); with one, nothing can sign as you
without it, and without one the report says so beside each entry. Only then does the report count it as yours: a line
saying `owner` that was never recorded this way still counts as the tool's word, because a tool trying to
quiet a warning could write that line too. The same goes for an answer the tool confirmed and you looked
at yourself, and for a finding set aside as a false alarm. `sv review` needs a terminal someone is typing
in, so your AI tool cannot run it for you. The README ("Setting a finding aside, confirming an answer, or
giving your own") says more.

**If your AI tool uses the container** (section 3), the report it writes cannot check those signatures
unless it can see your list of trusted keys, `allowed_signers`, which `sv review` keeps beside its key.
Give the container that one file, read-only, and not the folder: the folder also holds the key that
signs as you, and the container your AI tool drives has no need of it. The `.mcp.json` from section 3
becomes, with your own paths (this has not been tried in an AI tool yet):

```json
{ "mcpServers": { "stackvet": {
  "command": "/opt/homebrew/bin/docker",
  "args": ["run", "-i", "--rm", "--network", "none",
           "-v", "/Users/you/code/my-app:/Users/you/code/my-app",
           "-v", "/Users/you/.config/stackvet/allowed_signers:/sv-config/stackvet/allowed_signers:ro",
           "-e", "XDG_CONFIG_HOME=/sv-config",
           "ghcr.io/abbyshade111/stackvet-sv", "mcp", "--root", "/Users/you/code/my-app"] } } }
```

Make the file first, with the `mkdir` line above: if it is not there when the container starts, Docker
makes a folder in its place, and `sv review` can no longer add to it. `sv review` adds to the same file,
so the container sees each app you add without a change here. Without this line, recorded answers count
as the tool's word in those reports. CI is the same, by another route: give it the one line `sv review`
showed you as the variable `SV_TRUSTED_SEALS` (the README says where). That line can check a signature
but never make one, so it is safe to share.

Some questions are checks to make by hand, such as opening the live site and looking at the padlock.
The tool walks you through them and records what you saw; that record, too, counts as yours once you
have recorded it with `sv review`.

## 6. What you get without anything more, and what you do not

With the steps above, StackVet reads the code, the settings, and the list of packages the app uses,
and asks you the questions. It lists those packages but does not compare them with known vulnerabilities:
that needs a downloaded copy of the list of known ones, at a terminal ("Checking the packages against known
vulnerabilities", below). **It does not start the app.** The checks that need a running app, such
as what it sends to a browser, whether signing out really ends the session, and whether one person
can see another's data, are reported as *not assessed*, and so are your app's own tests, which run only when
the app is started. That is honest, not a pass.

Those checks need `sv report --run` at a terminal, with StackVet installed directly on your computer
rather than in Docker, because starting your app means starting containers of its own. There is no
download for that yet, so it means building StackVet yourself. The steps are at the end of this
section, under "Installing StackVet on your computer, for `--run`".

If your app uses packages, which most do, starting it also needs the line `install = true` under `[stack.run]` in
`stackvet.toml`. The app runs with no internet, so it cannot fetch its own packages; this line lets StackVet
download them first, in a separate box that sees only the list of packages, never your code. That download is the
one time StackVet uses the internet for your app, and the report says when it did. Without it, an app that needs
packages does not start, and everything that needs it running is *not assessed*.

**Where the report is.** When your AI tool writes the report (`stackvet_write_report`), or you run
`sv report`, it goes in a folder named `stackvet-report` inside the app's folder. Open `report.html` in
a browser; `compliance.md` and `security.md` say the same in plain text for your AI tool. To have your AI tool
read it with you, starting with what was not checked, give it [the report prompt](prompts/report.md) (not yet tried
in an AI tool).

Each requirement in it has one of these words, strongest first:

- *needs attention*: something was found wrong;
- *checked*: a check of StackVet's own looked, and found nothing wrong in what it tried;
- *checked in part*: a check looked at only part of what the requirement asks;
- *tested by the app's own tests*: a test your AI tool wrote names it, and passed;
- *documented by the owner*: you wrote down your decision;
- *checked by hand by the owner*: you looked for yourself, and said what you saw;
- *attested by the owner*: you said yes to a question about how the app is built;
- *stated by the AI coding tool*: the tool answered, and you have not made the answer yours;
- *not verified*: nothing speaks to it yet.

None of them means "passed": even *checked* means one check found nothing wrong, not that the whole requirement
is met.

If you later run StackVet in an automatic check (CI) whenever the code changes, the number it ends with
says what happened. 0: it finished. 2: some check could not run, such as a file it could not read or a
language it does not read, so that run left part of the app unchecked. 3: StackVet itself failed (an
option it does not know, a folder that is not there, a `stackvet.toml` it cannot read, or, for `sv report`,
none at all, or a fault in StackVet itself), so there is no result at all. 1 comes only from `sv audit` (a
known vulnerability) or when you ask for it: `sv check . --fail-on attention:high` stops the check when
anything high or critical is found. Without `--fail-on`, findings alone never fail it. The README says
exactly what each number covers.

### An image of your own

`install = true` downloads Python packages (from `requirements.txt`) and Node packages (from `package.json`)
only. An app in another language, or one that needs something else installed first, can instead start from
an image of its own: a ready-made box that already holds the language and the packages. You make it once,
with Docker, and name it in `stackvet.toml`.

Do not put the download in `build` (for example `build = "pip install -r requirements.txt"` or
`build = "npm ci"`). The build step runs inside the same fence as the app, with no internet, so it fails, and
`sv preflight` says so before you try.

To make the image, ask your AI tool to write a file named `Dockerfile` in the app's folder that starts from the
language's own image and installs the packages, and nothing more. For a Python app it reads:

```
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
```

Then, in a terminal in the app's folder, run `docker build -t my-app-packages .` (any name will do), and in
`stackvet.toml` name it under `[stack.run]`: `image = "my-app-packages"`, with no `install = true` line. StackVet
still puts the app's own files in and runs it behind the fence; the image only brings the packages. Build the
image again whenever the list of packages changes, since StackVet runs whatever the image holds.

### All your apps on one page

Once each app has a report, `sv dashboard` puts them on one page you open in a browser: every app in alphabetical
order, each with its own view of what was found, what was not examined, and where its requirements went. It reads
the reports already there and checks nothing itself, so run `sv report` on an app first to bring its part up to
date. Give it the app folders, and the file to write:

```bash
sv dashboard ~/code/app-one ~/code/app-two --out ~/sv-dashboard.html
```

It writes only that file, never inside an app's folder, and never over a file it did not make.

To see how each app changes from one check to the next, turn on history once: `sv history on`. From then on, each
`sv report` you run keeps a small record of the run in your home folder, readable only by you and never your code, and
`sv dashboard --out ~/sv-dashboard.html` shows every app you have checked, each with its runs over time. A run is only
compared with an earlier one of the same kind, so a quick check after a full one does not make the app look worse.
`sv history off` stops it, and `sv history forget --all` deletes what was kept.

To see what changed between two particular reports, history on or not, keep a copy of the older report folder and run
`sv compare`:

```bash
cp -R stackvet-report ~/report-before   # before the change
sv report .                             # after it
sv compare ~/report-before              # the newer is this folder's report
```

It lists each requirement whose status moved, with what it gained or lost (a check that now credits it, a finding
that went away), the findings that came or went, and the counts. It writes nothing. It says first when it cannot show
that a report is one StackVet wrote on this computer, or when the two runs were not alike (a different kind of run,
level, `stackvet.toml`, security notes, or version of StackVet), since a requirement can then move for that reason
alone.

### Checking the packages against known vulnerabilities

Whether any package the app uses has a published vulnerability is *not assessed* until you give
StackVet a copy of the list of known ones. It never downloads that list itself: the names of the
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

### Installing StackVet on your computer, for `--run`

You only need this for `sv report --run`. Everything in steps 1 to 5 keeps working through Docker as it
is, and your AI tool keeps using the container: the copy you build here is for typing at a terminal.

StackVet has no ready-made download yet, so you build it from its source code (the program written
out as text, which a builder turns into a program you can run). It is done once and takes a few
commands. These steps were tried on a Mac on 5 October 2026, from a fresh copy of StackVet. The Linux
steps have not been tried by hand, though StackVet is built on Linux every time its code changes.
**Windows:** StackVet has never been built or tried on Windows, so nothing here is known to work
there; use the Docker steps above, and leave `--run` out for now.

**The quickest way, on a Mac or on Linux: Homebrew.** If you have [Homebrew](https://brew.sh), one command builds
StackVet on your computer, fetching what the build needs by itself, and puts `sv` on your path with its data beside
it. The first install takes a few minutes:

```bash
brew install --HEAD abbyshade111/stackvet/sv
sv --version
```

`--HEAD` means the latest StackVet, since it has no numbered release yet; `brew upgrade --fetch-HEAD sv` updates it.
This is tried automatically on a Mac and on Linux every week and on every change to the formula
([github.com/abbyshade111/homebrew-stackvet](https://github.com/abbyshade111/homebrew-stackvet)), but not yet by hand
on a person's own computer. If it fails, the steps below do the same thing by hand.

**1. The basic tools.** On a Mac, in a terminal:

```bash
xcode-select --install
```

This installs Apple's command-line tools, which include `git` and the parts Rust needs to finish
building a program. If it says they are already installed, go on. On Linux (Debian or Ubuntu):
`sudo apt install build-essential git curl`.

**2. Install Rust.** Rust is the programming language StackVet is written in. Installing it gives you
`cargo`, the program that builds StackVet. The official installer, from rust-lang.org:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

When it asks how to install, press Enter for the standard choice. Then close the terminal window and
open a new one, so it sees what was installed, and type `cargo --version`. It should print a version
number: StackVet needs 1.95 or newer. If yours is older, `rustup update` brings it up to date.

**3. Get StackVet's source code**, into a folder named `stackvet` in your home folder:

```bash
cd ~
git clone https://github.com/abbyshade111/StackVet.git stackvet
```

Or, without `git`: on StackVet's GitHub page, choose **Code**, then **Download ZIP**, unzip it,
rename the folder it makes (`StackVet-main`) to `stackvet`, and move it into your home folder.
Built that way, `sv --version` says `commit unknown` rather than which version of the code it is, and
updating means downloading it again.

**4. Build and install it:**

```bash
cd ~/stackvet
sh tools/install.sh
```

The first time, `cargo` downloads the pieces StackVet is made from, and the build takes a few
minutes. Then the script copies the program and the files it reads into a folder of their own,
`~/.local/share/stackvet`, and puts a link to the program at `~/.local/bin/sv`. It ends by printing
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
sv check ~/stackvet/examples/flask-booking
```

The first prints `sv 0.1.0` and the version of the code it was built from, and on a second line the
folder of files it reads (`data: …/.local/share/stackvet/data`). The second checks one of the example apps that come with it: it
should say what it read and what it found, not `Error`. If it says `command not found: sv`, step 5 has
not taken effect: open a new terminal window, or look for the line at the end of `~/.zshrc`.

Then, in your app's folder, `sv doctor` says in one line each whether everything `--run` needs is in
place: the folder in git, `stackvet.toml` there and readable, how to start the app written in it, and
Docker running. It writes nothing and opens no network connection, so it cannot say whether a newer
StackVet is out.

**The installed copy does not need the `stackvet` folder.** Each time StackVet runs, it reads more
than a dozen of its own files (the security standards and its rules). The installed copy reads the ones
the script put beside it, so moving, renaming, or deleting the folder you built it in does not stop it.
Use `~/.local/bin/sv` wherever a full path is asked for, as in your AI tool's settings; it stays the same
when you build again. A copy of the program on its own, without its `data` folder beside it, falls back to
the folder it was built in; once that is gone, it cannot find those files and says where it looked. Before 5 October 2026 the guide had you use the program in
the build folder; if your `PATH` or your AI tool's settings name `…/stackvet/target/release/sv`, change
them to `~/.local/bin/sv`.

**The build folder can be deleted.** Building leaves a folder named `target` inside `~/stackvet`, of 1 to 7 GB,
which the installed copy does not use. To get the space back:

```bash
rm -rf ~/stackvet/target
```

That removes only the build's leftovers: `sv` keeps working, and so does your AI tool's link to it. The next
time you update StackVet, the build takes its few minutes again, as it did the first time.

**Docker or Colima has to be running** for `--run`, as in step 1 of this guide, because that is what
starts your app. With Colima on a Mac, your app's folder has to be inside your home folder (Colima
shares only that unless you tell it otherwise); if it is not, the report says so and why.

Your AI tool tells you the exact command to type. It looks like this, with your own app folder:

```bash
sv report /Users/you/code/my-app --run
```

To update StackVet later: `cd ~/stackvet`, then `git pull`, then `sh tools/install.sh` again. It
replaces the program and its files together.

## Keeping StackVet up to date

StackVet changes often, and a new container image is published each time a change is added to it.
Your computer keeps the copy it fetched until you fetch again. To get the newest, in a terminal:

```bash
docker pull ghcr.io/abbyshade111/stackvet-sv
```

**Then restart your AI tool, or at least StackVet inside it.** The tool starts StackVet's container
when it starts the StackVet server, and keeps the one it started until the server starts again. In the
Claude desktop app, quit it and open it again; in Claude Code, end the session and start a new one. In VS Code, open the Command Palette (Cmd+Shift+P on a
Mac, Ctrl+Shift+P elsewhere), choose "MCP: List Servers", pick `stackvet`, and choose Restart.

**To see which version you have**, ask the copy itself:

```bash
docker run --rm ghcr.io/abbyshade111/stackvet-sv --version
```

It prints a line such as `sv 0.1.0 (commit 3f9c…)`, the commit being 40 letters and digits long: it is
the exact version of StackVet's code the copy was built from, and is what to quote if you report a problem. If you also built StackVet on
your computer (for `--run`, above), `sv --version` prints the same line for that copy.

**Keep the two at the same version.** The container your AI tool uses and a copy built on your
computer are updated separately, and two versions can disagree: a check one of them has, or a fix, the
other may not. When you update one, update the other: `docker pull` as above, and for the copy on your
computer, `cd ~/stackvet`, then `git pull`, then `sh tools/install.sh`. Compare the two `--version`
lines afterwards. They can still differ for a short while after a change, because the image is
published only once the change has passed its tests.

**To stay on one version on purpose**, for example while you finish an app, use the commit's own
image instead of the newest. Every image is also published under the commit it was built from, so
`ghcr.io/abbyshade111/stackvet-sv:` followed by the whole commit that `--version` prints always
means the same version. Put that name in place of
`ghcr.io/abbyshade111/stackvet-sv` in your `.mcp.json` and in the commands above, and nothing
changes until you change it back.

**Old copies take up space.** Each `docker pull` that fetches a new version keeps the old one on your
disk, no longer named. `docker image prune` deletes the ones no longer named, and asks first; it
does not touch the copy you are using.

## Known problems while this is new

Found in the first real build. Each is in `docs/BACKLOG.md`. The two listed here before, a rate limiter
counted as a public API and security notes the AI tool wrote counted as yours, were fixed on
27 September 2026. Nothing from that build is known to be open.
