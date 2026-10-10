# From the review of 8 October 2026: the four things to fix first

**Status:** partly done: 2 of 4 parts done, 0 claimed, 0 open, as its markers read on 8 October 2026

A read-only review of `sv` at `7371e76` (six
readings: the container fence, `sv probe`, the MCP server and the files `sv` writes, secrets and reports, the
outside tools and the CLI, and the test suite; `cargo fmt`, `clippy`, and 2,355 tests clean). The areas the 4
October deep review fixed held. Four findings rated high, **all four claimed on 8 October 2026 by session
securevibe-review**, at the owner's word ("Yes please, go ahead"), one pull request each; read on `main` just before
this claim, none was claimed by another session. The rest of that review (ten medium, sixteen low) is in the owner's
hands to add here as they choose.
1. **The install step runs the manifest's own image with the network open** (`crates/sv-run/src/install.rs`,
   `docker.rs`). ADR-052 says no package's own code runs there, and that holds; but the `sh`, `pip`, and `npm` that
   run are the image's, and `image` is whatever `securevibe.toml` names, so an app that names its own image runs
   that image's code with the internet, the owner's LAN, and the container backend's bridge reachable. Branch
   `claude/securevibe-review-install-image`: `install = true` is honored only when `image` is one of Docker's own
   `python` or `node` images, which is also the only case where the packages fit the interpreter that runs them;
   any other image is refused in plain words, naming the route that stays (build the packages into your own
   image). Changes what `sv` runs with the network open: a Later entry on ADR-052.
   **Done the same day** (DESIGN, "Packages installed before the run, outside the fence", the paragraph "Only in
   Docker's own `python` and `node` images"; ADR-052, Later, 8 October 2026): `install::official_image`, and `plan`
   refusing any other image before the folder is read. Not done: a terminal confirmation for other images, since
   the MCP server has no terminal to ask at; building the packages into your own image stays the route.
   **Part status:** partly done: unclear, needs a look
2. **Brakeman reads `config/brakeman.yml` from the app, and that file can name Ruby files Brakeman loads**
   (`data/adapters.json`, the brakeman entry passes no config of its own; `additional_checks_path` is a documented
   option whose `*.rb` files Brakeman requires). A Rails app handed to the owner runs Ruby on their computer under
   `--tools`. Branch `claude/securevibe-review-brakeman-config`: a `{config}` placeholder that `sv` fills with an
   empty settings file in the tool's private folder, passed as `-c`, so the app's file is never read. The spirit of
   ADR-032 (a program the app names is not run): a Later entry there.
   **Done the same day, and the finding corrected** (DESIGN, "The outside tools run no program an app's repository
   names", the paragraph "Brakeman's settings file"; ADR-032, Later, 8 October 2026): tried with Brakeman 8.1.0,
   the settings file could *not* make Brakeman load Ruby, since Brakeman has ignored `additional_checks_path`
   there since 3.6.2 (2017) unless asked to allow it; the review's "high" was wrong. What was built is the smaller
   thing that stood: Brakeman now reads an empty settings file of `sv`'s own and never the app's, so a clean run
   over an app with `config/brakeman.yml` is credited rather than withheld.
   **Part status:** done, 8 October 2026
3. **`sv review` writes `securevibe.toml` and `security-notes.md` through a link the app planted, and not
   atomically** (`crates/sv-cli/src/review.rs`, `save_text`): the one writer left on a plain write after S3 fixed
   `sv notes` and `sv rules`. Branch `claude/securevibe-review-links`: `refuse_link` and `write_without_following`,
   and a test that plants the link and shows the file it points at left alone.
   **Done the same day** (DESIGN, "Writing nothing through a link", the `sv review` paragraph): both names looked
   at before anything is asked, a link at either refused, and each file written under a new name renamed into
   place; the test lives in `review_terminal.rs`, which has the terminal `sv review` needs.
   **Part status:** done, date not recorded
4. **A `--tools` program is whatever `PATH` says, and `PATH` can point inside the app** (`crates/sv-check/src/adapters.rs`
   spawns by bare name with the owner's `PATH` passed on, in the app's folder): `source .venv/bin/activate` before
   `sv report --tools` runs the app's own `.venv/bin/bandit`. Branch `claude/securevibe-review-tool-path`: the
   program is found through `PATH` by `sv` first, a relative entry is skipped, one under the app folder is refused
   as not run, saying which and why.
   **Done the same day** (DESIGN, "The outside tools run no program an app's repository names", the paragraph
   "The program itself"): `adapters::located`, with a program found nowhere still run by name, so "not installed"
   reads as it did. Not done: naming the program's path in the report, since the path can hold the owner's home
   folder and a report may be shared; the refusal names it instead.
   **Part status:** partly done: unclear, needs a look
