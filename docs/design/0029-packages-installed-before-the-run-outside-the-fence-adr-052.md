# Packages installed before the run, outside the fence (ADR-052)

The app's folder is read-only and its network has no way out, so `build` cannot install anything, and an app that needs
Flask or Express never started: every running check read "not assessed". The gap analysis (3.1) counted every trial
build ever made as standard-library only for this reason. With `install = true` under `[stack.run]`, a container runs
first, in `crates/sv-run/src/install.rs`:

- **Given only the dependency files**, each mounted read-only on its own: `requirements.txt`, or `package.json` with
  `package-lock.json`. Never the app's code or its `.env`: the one container of a run that can reach the internet holds
  nothing worth sending.
- **Exact versions only**: every line of `requirements.txt` names one version (`name==1.2.3`, with extras, markers
  and `--hash` allowed); `-r`, `-e`, other indexes, addresses and ranges are refused in plain words. Node needs its
  lockfile. pip still chooses the versions of what those packages need at the first install, unless the file pins them.
- **No package's own code runs** while it is online: `--only-binary=:all:` (no `setup.py`) and `npm ci
  --ignore-scripts`. A package that needs either is refused by the tool itself, and the report says to build an image.
- **Into a Docker volume** named from a fingerprint of the image and the files, so a second run downloads nothing; a
  finished install writes a mark last, and a half-filled volume is filled again.

The app then runs as before, fenced, with the volume mounted read-only (`/sv-deps` on `PYTHONPATH` for Python,
`/node_modules` for Node) and the packages' commands first on its `PATH`. The report adds one sentence saying the
packages were downloaded, from where, and that the container was given only the dependency files.

Tested with a real backend (`crates/sv-run/tests/install.rs`): a fixture that imports `six` starts only with the step,
shows the installed version, and reuses the download on a second run; without the step it fails, naming `six`. Six
safeguards were broken in turn and each was caught, one of them only by the test with a real backend.

**Only in Docker's own `python` and `node` images (8 October 2026).** The review of `sv` that day found the hole the
record's "no package's own code runs" did not close: the `sh`, `pip`, or `npm` that run in the install container are
the *image's*, and `image` is whatever `securevibe.toml` names. An app that named an image of its own had that image's
code run with the internet, the owner's local network, and the container backend's bridge address reachable, which is
what the fence exists to deny; the hardening (read-only, no capabilities, an empty environment) kept the host's files
out of reach, not the network. Now `install::official_image` admits only Docker's own `python` or `node` images (with
or without a tag, a digest, or Docker Hub's own prefix), and `plan` refuses any other image before the folder is looked
at, naming the image and the route that stays: build the packages into your own image and leave `install` out. Those
two images are also the only ones where the packages are sure to fit the interpreter the app then runs them with.
Held by `the_install_runs_only_in_dockers_own_python_or_node_images` (`sv_run::install`), with nine names admitted
and twelve refused, `--privileged` among them.
