#!/bin/sh
# Builds sv and installs it, with its data, in a folder of its own, so it keeps working when the folder it was
# built in is moved or removed (ADR-036).
#
#     sh tools/install.sh
#
# Puts the program and its data in ~/.local/share/securevibe and links ~/.local/bin/sv to it. Put ~/.local/bin on
# your PATH once, and point your AI coding tool's settings at ~/.local/bin/sv: neither changes when you build again.
# Run it again after pulling a newer sv; it replaces the program and the data together.
#
# SV_PREFIX installs under another folder than ~/.local. SV_BINARY installs a program already built, without
# building one. It never replaces a file at bin/sv that it did not put there: it stops and says so.
set -eu

repository=$(cd "$(dirname "$0")/.." && pwd)
prefix=${SV_PREFIX:-$HOME/.local}
home="$prefix/share/securevibe"
link="$prefix/bin/sv"

if [ -e "$link" ] || [ -L "$link" ]; then
    if [ "$(readlink "$link" 2>/dev/null)" != "$home/sv" ]; then
        echo "$link is already there and is not this installer's link, so it is left as it is." >&2
        echo "Move it out of the way (or remove it) and run this again." >&2
        exit 1
    fi
fi

if [ -n "${SV_BINARY:-}" ]; then
    binary=$SV_BINARY
else
    # --locked: the versions in Cargo.lock, the ones every test ran with, and never newer ones chosen today.
    cargo build --release --locked --manifest-path "$repository/Cargo.toml" -p sv-cli
    binary="$repository/target/release/sv"
fi

mkdir -p "$home" "$prefix/bin"
# Copied beside, then put in place, so a copy cut short never leaves half a data folder in use.
rm -rf "$home/data.new"
cp -R "$repository/data" "$home/data.new"
rm -rf "$home/data"
mv "$home/data.new" "$home/data"
cp "$binary" "$home/sv.new"
chmod 755 "$home/sv.new"
mv "$home/sv.new" "$home/sv"
ln -sf "$home/sv" "$link"

"$link" --version
echo "Installed. Use $link; it reads the data in $home/data."
