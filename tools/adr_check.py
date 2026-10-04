#!/usr/bin/env python3
"""Fails a pull request that changes what a decision record governs without saying what that means for the record.

Each of `sv`'s decision records (docs/adr/ADR-015.md onward) lists, on its `**Governs:**` line, the files whose
change can change the decision. A pull request that touches one of them must either change that record (a new
"Later" entry, a correction, a superseding record named in it) or say in its description, on a line of its own:

    ADR-026: unchanged, because the change only renames a test helper

with a reason of at least ten characters. The point is not to slow small changes down: it is that every change to a
decision's code is a moment somebody looks at the record, so the record stops falling behind what was built (the
owner's decision of 4 October 2026; BACKLOG, "Decision records written with the change, not after it").

A `*` in a pattern matches any run of characters, `/` included.

Usage:
    python3 tools/adr_check.py --base origin/main --head HEAD --event "$GITHUB_EVENT_PATH"
    python3 tools/adr_check.py --base origin/main --head HEAD --body-file description.md
    python3 tools/adr_check.py --self-test
"""

import argparse
import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADR_DIR = "docs/adr"
UNCHANGED = re.compile(r"^\s*[-*]?\s*`?ADR-(\d{3})`?:\s*unchanged,\s*because\s+(.+?)\s*$", re.IGNORECASE | re.MULTILINE)


def governs(text):
    """The patterns on a record's **Governs:** paragraph."""
    start = text.find("**Governs:**")
    if start < 0:
        return []
    paragraph = text[start:].split("\n\n")[0]
    listed = paragraph.split(". A pull request")[0]
    return re.findall(r"`([^`]+)`", listed)


def records(read):
    """Record number to its patterns, for `sv`'s records. `read(path)` gives a file's text, or None."""
    out = {}
    for path in read.listing(ADR_DIR):
        m = re.fullmatch(r"docs/adr/ADR-(\d{3})\.md", path)
        if m and int(m.group(1)) >= 15:
            out[int(m.group(1))] = governs(read(path) or "")
    return out


def owed(changed, patterns_by_record, body):
    """The records a change touches and neither changes nor explains, with the files that touched each."""
    stated = {}
    for number, reason in UNCHANGED.findall(body or ""):
        if len(reason.strip()) >= 10:
            stated[int(number)] = reason.strip()
    out = {}
    for number, patterns in sorted(patterns_by_record.items()):
        record = f"{ADR_DIR}/ADR-{number:03d}.md"
        touched = [f for f in changed if any(fnmatch.fnmatchcase(f, p) for p in patterns)]
        if touched and record not in changed and number not in stated:
            out[number] = touched
    return out


class Git:
    """Reads files as they are at `head`."""

    def __init__(self, head):
        self.head = head

    def __call__(self, path):
        r = subprocess.run(["git", "show", f"{self.head}:{path}"], cwd=ROOT, capture_output=True, text=True)
        return r.stdout if r.returncode == 0 else None

    def listing(self, folder):
        r = subprocess.run(["git", "ls-tree", "--name-only", f"{self.head}:{folder}"], cwd=ROOT,
                           capture_output=True, text=True, check=True)
        return [f"{folder}/{name}" for name in r.stdout.split()]


def changed_files(base, head):
    r = subprocess.run(["git", "diff", "--name-only", f"{base}...{head}"], cwd=ROOT, capture_output=True,
                       text=True, check=True)
    return [line for line in r.stdout.splitlines() if line]


def report(missing, patterns_by_record):
    lines = ["This pull request changes what a decision record governs, and does not say what that means for it:", ""]
    for number, files in missing.items():
        lines.append(f"  ADR-{number:03d} (docs/adr/ADR-{number:03d}.md) governs: " + ", ".join(files))
    lines += [
        "",
        "For each, either change the record (a dated \"Later\" entry, a correction, or a new record that replaces it),",
        "or add a line to the pull request's description, such as:",
        "",
    ]
    for number in missing:
        lines.append(f"  ADR-{number:03d}: unchanged, because <what this change does, and why the decision stands>")
    lines += ["", "The reason needs at least ten characters. See docs/adr/README.md."]
    return "\n".join(lines)


def self_test():
    patterns = {19: ["crates/sv-run/src/docker.rs"], 20: ["Cargo.toml", "crates/*/Cargo.toml"], 26: ["crates/sv-check/src/seal.rs"]}
    # Nothing governed: nothing owed.
    assert owed(["docs/BACKLOG.md"], patterns, "") == {}
    # A governed file, with nothing said: owed.
    assert owed(["crates/sv-run/src/docker.rs"], patterns, "") == {19: ["crates/sv-run/src/docker.rs"]}
    # The record changed with it: not owed.
    assert owed(["crates/sv-run/src/docker.rs", "docs/adr/ADR-019.md"], patterns, "") == {}
    # Said why, at length: not owed.
    assert owed(["crates/sv-run/src/docker.rs"], patterns, "ADR-019: unchanged, because only a log line moved") == {}
    assert owed(["crates/sv-run/src/docker.rs"], patterns, "- `ADR-019`: Unchanged, because only a log line moved") == {}
    # Said why too briefly, or about another record: still owed.
    assert 19 in owed(["crates/sv-run/src/docker.rs"], patterns, "ADR-019: unchanged, because ok")
    assert 19 in owed(["crates/sv-run/src/docker.rs"], patterns, "ADR-026: unchanged, because only a log line moved")
    # A pattern's `*` crosses folders, and each record is owed separately.
    got = owed(["crates/sv-cli/Cargo.toml", "crates/sv-check/src/seal.rs"], patterns, "")
    assert set(got) == {20, 26}, got
    # A record that changes is never owed, even when it governs itself.
    assert owed(["docs/adr/ADR-026.md"], {26: ["docs/adr/*"]}, "") == {}
    # Reading the list off a record.
    text = "**Status:** x.\n\n**Governs:** `a/b.rs`, `c/*`. A pull request that changes any of these.\n\n`d/e.rs`"
    assert governs(text) == ["a/b.rs", "c/*"], governs(text)
    assert governs("no list here") == []
    print("adr_check self-test: ok")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--event", help="the GitHub event file, for the pull request's description")
    parser.add_argument("--body-file", help="a file holding the pull request's description")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.base:
        parser.error("--base is needed")
    body = ""
    if args.event:
        event = json.loads(Path(args.event).read_text())
        body = (event.get("pull_request") or {}).get("body") or ""
    elif args.body_file:
        body = Path(args.body_file).read_text()
    patterns = records(Git(args.head))
    missing = owed(changed_files(args.base, args.head), patterns, body)
    if missing:
        print(report(missing, patterns))
        return 1
    print(f"Decision records: nothing owed ({len(patterns)} records read).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
