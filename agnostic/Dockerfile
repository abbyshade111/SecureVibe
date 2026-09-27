# sv in a container, for somebody who is not going to install Rust.
#
#   docker pull ghcr.io/abbyshade111/securevibe-sv                              (the published one)
#   docker build -f agnostic/Dockerfile -t ghcr.io/abbyshade111/securevibe-sv .   (or build it, from the repository root)
#
# The build context is the repository root, because `sv` reads the shared OWASP data in `data/` beside
# `agnostic/`; the `.dockerignore` at the root keeps the rest of the repository out of it.
#
# `sv` finds a dozen of its own data files through the folder it was compiled in
# (`env!("CARGO_MANIFEST_DIR")`), so the runtime image keeps that folder at the same path, `crates/`
# included: the paths are `crates/<crate>/../../data/...`, and `..` only resolves through a folder that
# exists. Nothing in the code changes for the container.
#
# What this image is for: `sv mcp` for an AI coding tool, and `check`, `scope`, `notes`, `questions`,
# and `report` without `--run`. Not `--run`: that starts the app in containers of its own, which from
# in here would mean handing `sv` the Docker socket, and with it the owner's machine. Run it without a
# network (`--network none`) and the promise that `sv` opens no connection is enforced, not only kept.
# See docs/BACKLOG.md, "Packaging `sv` for somebody who is not technical".

FROM rust:1-slim-trixie AS build
WORKDIR /src
COPY agnostic ./agnostic
COPY data ./data
RUN cd agnostic && cargo build --release --locked -p sv-cli

FROM debian:trixie-slim
# git answers whether a secrets file was ever committed. It refuses a repository owned by another
# user, which a mounted folder often is on Linux, and then that check is quietly not assessed.
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
