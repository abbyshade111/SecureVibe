#!/bin/sh
# Copies the starting inputs for each fuzzing target from what the repository already holds, into
# fuzz/corpus/<target>/, which is not committed (ADR-077). Nothing is downloaded. Run from the
# repository's top folder: `sh fuzz/seed.sh`, then `cd fuzz && cargo +nightly fuzz run <target>`.
set -eu
top=$(pwd)
corpus="$top/fuzz/corpus"
mkdir -p "$corpus/manifest" "$corpus/lockfiles" "$corpus/tool_reports" "$corpus/mcp_line"
n=0
copy() { # copy FILE TARGET: each under a name of its own
    n=$((n + 1))
    cp "$1" "$corpus/$2/seed-$n-$(basename "$1")"
}
# Without the build folders, the fuzzing crate's own, and anything installed.
files() {
    find "$top/examples" "$top/crates" "$top/data" -type d \( -name target -o -name node_modules \) -prune -o \
        -type f "$@" -print
}
for f in $(files -name stackvet.toml); do copy "$f" manifest; done
for f in $(files \( -name package-lock.json -o -name yarn.lock -o -name poetry.lock -o -name Pipfile.lock \
    -o -name Pipfile -o -name Gemfile.lock -o -name go.sum -o -name go.mod -o -name pnpm-lock.yaml \
    -o -name composer.lock -o -name Cargo.lock -o -name uv.lock -o -name bun.lock -o -name pylock.toml \
    -o -name gradle.lockfile -o -name 'requirements*.txt' -o -name '*.xml' -o -name '*.tap' \)); do
    copy "$f" lockfiles
done
for f in $(files -name '*.sarif'); do copy "$f" tool_reports; done
# The MCP server's input: a session as a client opens one, and a tool call, one message a line.
printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"seed","version":"0"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
    '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"stackvet_check","arguments":{"path":"."}}}' \
    '{"jsonrpc":"2.0","id":4,"method":"resources/list"}' \
    > "$corpus/mcp_line/seed-session"
echo "seeded: $(ls "$corpus/manifest" | wc -l) manifests, $(ls "$corpus/lockfiles" | wc -l) lockfiles and test reports, $(ls "$corpus/tool_reports" | wc -l) tool reports, 1 MCP session"
