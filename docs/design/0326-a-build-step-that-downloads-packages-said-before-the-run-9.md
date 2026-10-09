# A build step that downloads packages, said before the run (9 October 2026)

The rest of the "Now" part of the gap analysis's finding 9 (7 October 2026). `install = true` (ADR-052) is the way
an app's packages reach it, but an AI tool's first guess is still `build = "pip install -r requirements.txt"` or
`build = "npm ci"`. The build step runs inside the fence, where nothing can be downloaded and nothing outside `/tmp`
written, so it fails whatever it prints. Until now `sv` said so only after a run had failed and waited out the
app's start (`never_ready_detail` in `crates/sv-run/src/docker.rs`).

**Before the run.** `sv preflight` reads the build step a command at a time (split at `&&`, `||`, `;`, `|`, and
quotes, so `cd api && pip install ...` and `sh -c "npm ci"` are both read) and, when one of them downloads packages,
says "look at this", names the command, and gives the two ways that work: `install = true`, or an image of the
owner's own named in `image`. Read: `pip`/`pip3 install`, `python -m pip install`, `uv pip install`, `uv sync`,
`poetry`/`pipenv install`, `npm install`/`i`/`ci`, `pnpm install`/`i`, `yarn` with no command or `yarn install`,
`bundle install`, and `composer install`. Not read: `npm run build`, `yarn build`, `pip --version`. A message such as
`echo "pip install"` is read as run too; a warning to look costs less than a missed step. A warning credits nothing
and changes no evidence.

**The guide.** `docs/GETTING-STARTED.md` has "An image of your own": for an app `install = true` does not cover, a
`Dockerfile` that installs the packages, `docker build`, and `image = "..."`, and why the download must not go in
`build`.

`examples/flask-booking` needed nothing: it already says `install = true`, and its `127.0.0.1` stays on purpose for
the preflight's own test.

Held by `crates/sv-cli/src/preflight/build_install_tests.rs`: sixteen installers named, six build steps that download
nothing left unsaid, and the preflight of an app folder through `of`. Broken three ways: the item never added to the
preflight (caught only by the test through `of`, which was added for that reason), the item never made (two tests),
and quotes no longer ending a command (the `sh -c` cases).
