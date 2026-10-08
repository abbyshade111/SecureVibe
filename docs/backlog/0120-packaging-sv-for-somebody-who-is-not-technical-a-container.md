# Packaging `sv` for somebody who is not technical: a container now, a download later

**Status:** open

**The
owner's decision, 26 September 2026: build the container now, and keep the downloadable program
here for later.** Other sessions are welcome to add ideas on packaging `sv` in the long run under
"Thoughts", below, each under its own name, as its own commit. **The committed image claimed on
26 September 2026 by session securevibe-e8**; a working version was built and tested locally the
same day, and what it taught is here.

**Why a container first.** It settles the two obstacles in the walk-through entry above that a
page of instructions cannot — `sv` must be built from source, and a built `sv` cannot be moved —
with **no change to the code**. `sv` finds a dozen of its data files through the folder it was
compiled in (`env!("CARGO_MANIFEST_DIR")`); inside an image that folder is the same path for
everyone. The AI tool starts it with one entry in `.mcp.json`:

```json
"command": "/opt/homebrew/bin/docker",
"args": ["run", "-i", "--rm", "--network", "none",
         "-v", "/Users/you/code:/Users/you/code",
         "securevibe/sv", "mcp", "--root", "/Users/you/code"]
```

and `--network none` turns the README's promise that `sv` opens no network connection into
something the container enforces.

**What it must not do: `sv report --run`.** That starts the app in containers of its own, which from
inside a container means handing `sv` the Docker socket — control of Docker on the owner's machine,
which is control of the machine. `sv run` also mounts the app by its host path (`-v` in
`crates/sv-run/src/docker.rs`), which the host's Docker resolves on the host. So the container is for
the MCP tools, `check`, `scope`, `notes`, `questions` and `report` without `--run`; `--run` stays a
step at the terminal with the native `sv`.

**The tested recipe**, built and run on the owner's Mac under Colima (image 334 MB):

```dockerfile
FROM rust:1-slim-trixie AS build
WORKDIR /src
COPY agnostic ./agnostic
COPY data ./data
RUN cd agnostic && cargo build --release -p sv-cli

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && git config --system --add safe.directory '*'
COPY --from=build /src/agnostic/crates /src/agnostic/crates
COPY --from=build /src/agnostic/data /src/agnostic/data
COPY --from=build /src/agnostic/examples /src/agnostic/examples
COPY --from=build /src/data /src/data
COPY --from=build /src/agnostic/target/release/sv /usr/local/bin/sv
ENTRYPOINT ["sv"]
```

It was tested over MCP as an AI tool would use it: six tools offered, `securevibe_spec` answered,
`securevibe_check` on a git repository with a committed `.env` ran the history check and found it,
the native `sv` gave the same answer on the same app (a control that counted only because both
actually ran), and `securevibe_notes_file` wrote into the app's folder as a file the owner owns.
What building it found:
- **Keep `crates/` in the runtime image**, not only `data/`. The data paths are
  `crates/<crate>/../../data/…`, and `..` only resolves through a directory that exists.
- **`git` is needed at run time** (`crates/sv-check/src/config.rs`) for whether a secrets file was
  ever committed, and git refuses a repository owned by another user. When git cannot answer, `sv`
  reports the check *not assessed* rather than failing, so without `safe.directory` it would
  quietly stop happening. **On the owner's Mac it had no witness**: with it switched off the check
  still ran, because Colima hands the files over as the owner's. It is kept for Linux, where the
  ownership differs; that part is reasoned, not shown.
- **Colima's Docker has no BuildKit**, so it falls back to the legacy builder, which ignores a
  `<Dockerfile>.dockerignore` beside the recipe and sends the whole repository, `target/` included.
  The committed version needs its `.dockerignore` at the root of the build context.
- **Give the absolute path to `docker`.** An app started from the Dock often cannot see
  `/opt/homebrew/bin`.
- **Mount the apps folder at the same path inside**, so the paths in findings and reports are the
  owner's own.
- **Colima has to be running when the AI tool starts**, or the securevibe tools are simply absent
  and nothing says why. After a restart a beginner will meet this. The walk-through has to say
  "start Colima first", or Colima has to start at login.
- The first test run passed its control vacuously: the check had not run in either version (the
  test app had no `securevibe.toml`, which `securevibe_check` requires), and "no answer" matched "no
  answer". The committed test for the image should assert that the check ran before comparing
  anything.

Left for whoever claims it: the recipe committed with a `.dockerignore`, CI that builds and
publishes the image, a test in the shape above, and the walk-through's MCP section written for it.
**Built on 26 September 2026 by session securevibe-e8** (#205). Session securevibe-e9 claimed it
the same day (#206) without seeing that #205 was about to merge, built a second version, and did not
merge it once it saw the first; nothing of it is in `main`.

**Done the same day, except publishing.** `agnostic/Dockerfile` (the recipe above), `.dockerignore` at
the repository root, `tools/image_smoke.py` (the test in the shape above: it asserts the committed
`.env` was found in the image, and in a native `sv`, before comparing them, and runs once as root over
a folder root does not own, which is `safe.directory`'s witness on Linux), a CI job in
`.github/workflows/rust.yml` that builds the image from scratch and runs it, and the README's MCP
section for the container. What was tested where:
- **Here**, Docker Hub refused the build image (429) and Debian's package servers were out of reach,
  so the build stage could not run. The runtime stage was built from a natively built `sv` without
  `git`, and the smoke test passed in its `--no-git` form: six tools, the check answered, the
  committed `.env` reported *not assessed* rather than passed, the notes file written, no network,
  and the same findings as the native `sv`. Leaving out `crates/` failed it ("cannot find the OWASP
  data folder"), and running the git-less image as if it had git failed both guards that the check
  ran, and refused to compare.
- **In CI**, the whole recipe: the build stage, `git` and `safe.directory`, and the file-ownership
  check as an ordinary user. This session runs as root, so those three are shown there, not here.
- **Not done: publishing the image.** Where it lives (GitHub's container registry, Docker Hub) and
  under what name is the owner's to decide, and publishing from CI needs a write permission on the
  workflow. Until then an owner builds it with one command, in the README.
**The owner's decision, 26 September 2026: publish it to GitHub's container registry.** **Claimed
the same day by session securevibe-e8.**
**Done the same day:** a `publish` job in `.github/workflows/rust.yml` pushes
`ghcr.io/abbyshade111/securevibe-sv` (`latest` and the commit) on a push to `main`, only after `test`
and `image` pass on that commit; it alone may write packages, with the workflow's own token and no
third-party action. The README now pulls the published image. Whether the package can be pulled
without signing in to GitHub depends on its visibility, which is set in the package's settings on
GitHub, and is the owner's to set.
**The owner's decision, 5 October 2026:** let it be pulled without signing in. GitHub's API cannot change a package's visibility,
so the owner sets it in the package's settings on GitHub.

**The downloadable program, for later.** Gentler for somebody without Docker, who still gets
everything except `--run`. It needs the data either compiled in (`include_str!`, as
`atlas-references.json` and `breached-password-evidence.json` already are) or found beside the
binary, and a build per platform in CI. One obstacle is easy to miss: **on a Mac, a program
downloaded from the web and not notarized by Apple is blocked** with a warning that the developer
cannot be verified, which somebody who is not technical will not get past. Notarizing needs an Apple
developer account. Homebrew is the usual way command-line tools are installed without that warning
— believed rather than checked, and it asks the owner to use Homebrew.

**Met again on 3 October 2026, in family-hub** (added on 4 October 2026 by the cato-pipeline session, usability
analysis for `docs/paper`, from the build's transcript). The owner connected `sv` over MCP from the published
image, as the guide says, and ran `sv report --run --tools` at a terminal: `zsh: command not found: sv`. The MCP
result had told the AI tool that `--run` needs `sv` "installed on the computer itself rather than this container
... (docs/GETTING-STARTED.md says how to install it)" (`crates/sv-cli/src/mcp.rs`, `terminal_command`, lines
120 to 125). The guide does not say how: its section 6 says that install "is not yet something this guide can
make easy" (`docs/GETTING-STARTED.md`, lines 187 to 189). The AI tool found the steps in the README instead, and
the owner cloned the repository and built `sv` from source with `cargo build`, which worked only because Rust was
already on the Mac. So the first build's "install Rust" is still step one for `--run`. Until the download exists,
the message should not point at a guide that does not answer it: either the guide gets the build steps, or the
message gives them. Still the case on `main` at 6d4ce3f.
**Claimed on 5 October 2026 by the cato-pipeline session**, at the owner's asking to continue with the backlog, in branch `claude/install-steps-for-run`:
the guide gets the build steps; the message is left as it is.
**Done the same day** (DESIGN, "The guide says how to install `sv` for `--run`"): section 6 of
`docs/GETTING-STARTED.md` now walks somebody who is not a programmer through it: Apple's command-line tools (or
`build-essential` on Linux), Rust through rustup, the source by `git clone` or a ZIP, `cargo build --release -p
sv-cli`, a `PATH` line for zsh and for bash, `sv --version` and a check of a bundled example, that the folder must
stay where it was built (a built `sv` still cannot be moved: item 2 above is open on `main`), and that Docker or
Colima must be running. Windows is said plainly to be untried. Every command was run on the Mac from a fresh clone
of `main` at aa4d371, and from the ZIP, and `sv report --run` then started an example app; the Linux steps were not
tried by hand. A test (`the_guide_the_container_points_at_says_how_to_install_sv`, `crates/sv-cli/src/mcp.rs`)
holds the container message's pointer to the guide: putting back the old guide failed it, and so did putting back
only the old "not yet something this guide can make easy" sentence.

**Thoughts.**

- *Session relaxed-nobel-27acfa.* In favor, and with the plan's order. Three things the list above
  does not name yet, found while working in `agnostic/` today:
  1. **`docs/` collides by file name.** `agnostic/docs/` and the root `docs/` both hold `BACKLOG.md`
     and `DESIGN.md`. `data/` merges cleanly (no two files share a name), and so does everything
     else except `README.md` and `.gitignore`, which the plan already covers. For `docs/`, the
     simplest honest move is to keep v1's two under a name that says so (`docs/v1/`, beside
     `docs/paper/`), since `v1-final` holds them anyway and the paper may cite their paths.
  2. **Two Python tools find the shared folder the same way the Rust does.** `tools/coverage.py` and
     `tools/pwned_passwords.py` set `ROOT = AGNOSTIC.parent` and read `data/knowledge` from there;
     after the move `ROOT` is the repository itself. `coverage.py --check` runs in the Rust test
     suite (`coverage_doc.rs`), so a wrong path fails the build, which is the test watching this.
     `pwned_passwords.py` has no test and would only fail when somebody runs it.
  3. **The evaluation harness still earns its place while `templates/` is used.** It was the only
     check able to confirm today's template change (semgrep option B changed two lines of v1's
     template). If `templates/` is archived with v1, the harness goes with it; if `sv` keeps using
     the template's built apps as its measuring targets, the harness stays, and so does `server/`,
     which builds them.

  **Timing of my own work:** option B, the one open pull request here that touches `agnostic/` and
  `templates/`, is on its checks now and lands within the hour. After it I will open nothing else
  that touches `agnostic/`, `CLAUDE.md`, or CI until the move lands, so the freeze can start any time
  after that.
