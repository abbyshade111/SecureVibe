# The guide says how to install `sv` for `--run` (5 October 2026)

In the container, the MCP server's command for `sv report --run` tells the AI tool that `sv` must be installed on the
computer itself and that `docs/GETTING-STARTED.md` says how (`terminal_command`, `crates/sv-cli/src/mcp.rs`). The
guide said the opposite: that install "is not yet something this guide can make easy". In family-hub on 3 October
2026 the AI tool found the steps in the README instead, and they worked only because Rust was already on the Mac.
The claim chose to make the message true rather than change it: the guide now holds the steps, at the end of its
section 6, for somebody who is not a programmer.

- **What the steps are**, each run on a Mac from a fresh clone of `main` (aa4d371): Apple's command-line tools
  (`xcode-select --install`, for `git` and the linker Rust needs; `build-essential` on Linux), Rust through the
  official rustup installer, the source by `git clone` into `~/securevibe` (or the ZIP from GitHub, which builds as
  well but reports `commit unknown`, since `build.rs` reads the commit through git), `cargo build --release -p
  sv-cli`, a `PATH` line appended to `~/.zshrc` (Mac) or `~/.bashrc` (Linux), tried in a fresh shell of each kind,
  and `sv --version`.
- **`sv --version` alone is not the check.** It printed its version with the source folder moved away, while `sv
  check` on the same copy stopped with `Error: reading …/data/secret-rules.json`. So the guide checks a bundled
  example too (`sv check ~/securevibe/examples/flask-booking`), which reads the data.
- **The folder stays where it was built.** A built `sv` still reads its data through `CARGO_MANIFEST_DIR` (item 2 of
  "the owner's first build", still open), so the guide says not to move, rename, or delete the folder, not to copy
  the program out on its own, and to keep it out of the Desktop, Downloads, and the app's folder, where the my-first-app
  build lost it.
- **Docker or Colima must be running**, and with Colima the app has to sit under the home folder. Tried: an app under
  `/private/tmp` was refused with `sv`'s own explanation; the same app under the home folder started, and `sv report --run`
  finished in under a minute without saying it could not.
- **Windows** is said to be untried, because nothing in CI or by hand has built `sv` there. The Linux steps are
  reasoned from CI's Ubuntu build, not tried by hand.

How it is held: `the_guide_the_container_points_at_says_how_to_install_sv` reads the guide the message names and
asks for the steps in it, and for the old sentence to be gone. Putting back the old guide failed it, and so did
putting back only the old sentence; one test, as it is the one place that holds the pointer.
