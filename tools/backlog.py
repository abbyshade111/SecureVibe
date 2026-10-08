#!/usr/bin/env python3
"""A status board for docs/BACKLOG.md: which items are open, claimed, done, or partly done, read from the items' own
markers.

The backlog is one long file, and its "Next" section holds every item ever written there, done or not: on 8 October
2026 it held 145 items, about 100 of them finished and never moved, with no "Done" section. This prints what a
person would otherwise read 8,000 lines to learn. The status is a reading of prose, not a record: an item is `done`
when it carries a `**Done` marker and no "Not done" (or "not built", "left for", "still open") beside it, `part` when
it carries both, `claimed` when it carries `**Claimed` and no `**Done`, and `open` otherwise. An item with numbered
sub-items (`  1. **...**`) is read sub-item by sub-item, and shown as `mixed` with its counts when they disagree. A
marker written another way is read as open, which errs on the side of showing work rather than hiding it.

    python3 tools/backlog.py list                  # every item of "Next", in the file's order
    python3 tools/backlog.py list --open           # items with anything open (open and mixed)
    python3 tools/backlog.py list --claimed        # items with a claim and nothing done yet
    python3 tools/backlog.py list --done           # items whose every part is done
    python3 tools/backlog.py list --mixed          # items with parts in more than one state
    python3 tools/backlog.py summary               # the counts alone
    python3 tools/backlog.py --self-test

Each line: the item's first line in the file, its status, the sub-items' counts (open, claimed, part, done), the
session named in its claim when there is one, and its title. The one-file-per-item layout proposed on 8 October 2026
(BACKLOG, "Backlog management") would make the status a line in each file and this script a reader of that line.
"""

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKLOG = ROOT / "docs" / "BACKLOG.md"

ITEM = re.compile(r"(?=^- \*\*)", re.M)
TITLE = re.compile(r"- \*\*(.*?)\*\*", re.S)
SUB = re.compile(r"^\s{2,5}(\d+)\.\s(.*?)(?=^\s{2,5}\d+\.\s|\Z)", re.S | re.M)
DONE = re.compile(r"\*\*(Done|Built|Fixed|Mended|Written|Answered|Settled)\b")
NOT_DONE = re.compile(r"\b(Not done|not done|Not built|not built|left for|still open|remains open|Not yet)\b")
CLAIMED = re.compile(r"\*\*Claimed\b")
SESSION = re.compile(r"\bby session ([A-Za-z0-9_-]+)")


def status_of(text):
    """One part's status from its markers: done, part, claimed, or open."""
    if DONE.search(text):
        return "part" if NOT_DONE.search(text) else "done"
    if CLAIMED.search(text):
        return "claimed"
    return "open"


def next_section(text):
    """The "Next" section's body and the line number its body starts on."""
    m = re.search(r"^## Next\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    if not m:
        raise SystemExit("no '## Next' section")
    return m.group(1), text[: m.start(1)].count("\n") + 1


def items(text):
    """Each top-level item of "Next": (line, title, status, counts, sessions)."""
    body, first = next_section(text)
    out = []
    offset = 0
    for chunk in ITEM.split(body):
        if not chunk.startswith("- **"):
            offset += chunk.count("\n")
            continue
        line = first + offset
        offset += chunk.count("\n")
        title = re.sub(r"\s+", " ", TITLE.match(chunk).group(1))
        subs = SUB.findall(chunk)
        counts = {"open": 0, "claimed": 0, "part": 0, "done": 0}
        if subs:
            for _, sub in subs:
                counts[status_of(sub)] += 1
            states = {k for k, v in counts.items() if v}
            status = next(iter(states)) if len(states) == 1 else "mixed"
        else:
            status = status_of(chunk)
            counts[status] += 1
        sessions = sorted(set(SESSION.findall(chunk)))
        out.append((line, title, status, counts, sessions))
    return out


def wanted(status, args):
    if args.open:
        return status in ("open", "mixed")
    if args.claimed:
        return status == "claimed"
    if args.done:
        return status == "done"
    if args.mixed:
        return status == "mixed"
    return True


def show(rows, args):
    for line, title, status, c, sessions in rows:
        if not wanted(status, args):
            continue
        counts = f"o{c['open']} c{c['claimed']} p{c['part']} d{c['done']}"
        who = ",".join(sessions)[:28]
        print(f"{line:5d}  {status:7s} {counts:16s} {who:28s} {title[:84]}")


def summary(rows):
    by = {}
    parts = {"open": 0, "claimed": 0, "part": 0, "done": 0}
    for _, _, status, c, _ in rows:
        by[status] = by.get(status, 0) + 1
        for k in parts:
            parts[k] += c[k]
    print(f"{len(rows)} items in Next: " + ", ".join(f"{by.get(k, 0)} {k}" for k in ("open", "claimed", "mixed", "part", "done")))
    print("parts (items without sub-items count as one): " + ", ".join(f"{parts[k]} {k}" for k in parts))


def self_test():
    sample = """# x

intro

## Next

- **An open item.** Nothing has happened.

- **A claimed item.** Text. **Claimed 8 October 2026 by session alpha**, in branch `b`.

- **A done item.** Text. **Claimed by session beta.** **Done the same day** (DESIGN, "x").

- **A partly done item.** **Done the same day**: most of it. Not done: the rest.

- **A mixed item.** Intro.
  1. **First.** **Done the same day.**
  2. **Second.** **Claimed 8 October 2026 by session gamma**.
  3. **Third.** Open still.
     More text of the third, indented.
  10. **Tenth.** Open.

- **A done item with parts.**
  1. **One.** **Done**.
  2. **Two.** **Built the same day**.

## Decided

- **Not an item of Next.**
"""
    rows = items(sample)
    got = [(r[1], r[2], r[3], r[4]) for r in rows]
    assert [g[0] for g in got] == [
        "An open item.", "A claimed item.", "A done item.", "A partly done item.", "A mixed item.",
        "A done item with parts.",
    ], got
    assert [g[1] for g in got] == ["open", "claimed", "done", "part", "mixed", "done"], [g[1] for g in got]
    assert got[4][2] == {"open": 2, "claimed": 1, "part": 0, "done": 1}, got[4][2]
    assert got[1][3] == ["alpha"] and got[4][3] == ["gamma"] and got[2][3] == ["beta"], got
    assert rows[0][0] == 7, rows[0][0]  # the first item's line in the sample
    assert status_of("**Done the same day**, but Not done: the tail") == "part"
    assert status_of("**Claimed** and **Done**") == "done"
    assert status_of("plain words, claimed in lowercase prose") == "open"
    print("backlog self-test: ok")


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("command", nargs="?", choices=["list", "summary"], default="list")
    parser.add_argument("--open", action="store_true")
    parser.add_argument("--claimed", action="store_true")
    parser.add_argument("--done", action="store_true")
    parser.add_argument("--mixed", action="store_true")
    parser.add_argument("--file", default=str(BACKLOG))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    rows = items(Path(args.file).read_text())
    if args.command == "summary":
        summary(rows)
    else:
        show(rows, args)
        print()
        summary(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
