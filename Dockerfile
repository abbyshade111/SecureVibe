# sv in a container, for somebody who is not going to install Rust.
#
#   docker pull ghcr.io/abbyshade111/securevibe-sv                              (the published one)
#   docker build -t ghcr.io/abbyshade111/securevibe-sv .   (or build it, from the repository root)
#
# The build context is the repository root; the `.dockerignore` beside this file keeps everything but the
# Rust workspace, `data/` and the examples out of it.
#
# `sv` finds its data files through the folder it was compiled in (`env!("CARGO_MANIFEST_DIR")`), so the
# runtime image keeps that folder at the same path, `crates/` included: the paths are
# `crates/<crate>/../../data/...`, and `..` only resolves through a folder that exists. Nothing in the code
# changes for the container.
#
# What this image is for: `sv mcp` for an AI coding tool, and `check`, `scope`, `notes`, `questions`,
# and `report` without `--run`. Not `--run`: that starts the app in containers of its own, which from
# in here would mean handing `sv` the Docker socket, and with it the owner's machine. Run it without a
# network (`--network none`) and the promise that `sv` opens no connection is enforced, not only kept.
# See docs/BACKLOG.md, "Packaging `sv` for somebody who is not technical".
#
# Both base images are pinned to an exact fingerprint (the `@sha256:` part) as well as a name, as the
# workflow steps are: a name like `trixie-slim` can be moved to point at a different image, a fingerprint
# cannot. Dependabot proposes a new fingerprint each week (.github/dependabot.yml), which is how security
# fixes to the system underneath `sv` still arrive, and CI builds and drives the image before it merges.

FROM rust:1-slim-trixie@sha256:4cd829461bd5c4d511c32e269da9cb8929223b666519d8004e35fc8d1d771ab7 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY data ./data
COPY examples ./examples
# The build context has no `.git`, so the commit is given here for `sv --version` and the reports to name
# (crates/sv-cli/build.rs). The workflows pass `github.sha`; built by hand without it, `sv` says `unknown`.
ARG SV_GIT_COMMIT=
RUN SV_GIT_COMMIT="$SV_GIT_COMMIT" cargo build --release --locked -p sv-cli

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
# git answers whether a secrets file was ever committed. It refuses a repository owned by another
# user, which a mounted folder often is on Linux, and then that check is quietly not assessed.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && git config --system --add safe.directory '*'
COPY --from=build /src/crates /src/crates
COPY --from=build /src/data /src/data
COPY --from=build /src/examples /src/examples
COPY --from=build /src/target/release/sv /usr/local/bin/sv
# Tells `sv` it is in this container, so what it tells an AI coding tool to have the person run
# (`--run`, which cannot work from in here) names `sv` installed on the computer instead.
ENV SV_IN_CONTAINER=1
# Not root. The image reads the owner's folder and writes reports into it, and as root a mistake
# could write anywhere in it, as root. An unprivileged user of its own, by number so a platform that
# refuses root images can tell. On Linux, `--user "$(id -u):$(id -g)"` in the `docker run` line
# replaces it with the owner's own, so what it writes is theirs; Docker Desktop on a Mac makes what
# any user writes the owner's.
RUN useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin sv
USER 10001:10001
ENTRYPOINT ["sv"]
