#!/usr/bin/env python3
"""The backlog, one file per item (docs/adr/ADR-061.md): what is open, claimed, done, or partly done, and the
commands that keep it so.

Each item is a file under docs/backlog/, named by a four-digit number and its title made into a file name
(`0150-one-file-per-backlog-item-with-a-status-line.md`), whose first line is `# ` and the title, which the code and
the documents cite (`BACKLOG, "title"`) and which is never changed once written, and whose third line is the status,
in one of four forms:

    **Status:** open
    **Status:** claimed by <session>, <date>
    **Status:** done, <date>
    **Status:** partly done: <what remains>

The rest is the item's text, its numbered parts included. Parts are not files: a part claimed or done on its own is
marked in its text (`**Claimed ... by session x**`, `**Done ...**`), the item's status says `partly done` with what
remains, and `list` counts the parts' markers beside the item's own status. The numbers keep the order the items stood
in the old single file when it was split on 8 October 2026, and are an identity, not a date; two pull requests open
at once may take the same number, which harms nothing. docs/BACKLOG.md holds the rules and the roadmap, and no item
and no list of items: a list every item adds a line to would bring back the conflicts this layout is for.

    python3 tools/backlog.py list                     # every item, in number order
    python3 tools/backlog.py list --open              # only the open ones (--claimed, --done, --partly likewise)
    python3 tools/backlog.py summary                  # the counts alone
    python3 tools/backlog.py new "A title"            # writes an open item, numbered one past the highest; prints its path
    python3 tools/backlog.py claim 0150 --by <session>          # sets the status line (refused when another session holds it, or it is done)
    python3 tools/backlog.py done 0150                # sets `done, <today>`; with --remains "..." sets `partly done: ...`
    python3 tools/backlog.py show 0150                # prints the item
    python3 tools/backlog.py --check                  # fails on a misnamed file, a missing title or status, two files with
                                                      # one title, or an item left in docs/BACKLOG.md
    python3 tools/backlog.py move FILE                # makes an item of each `- **title.**` entry of FILE, a backlog in the
                                                      # old single-file layout, whose title is not an item yet; an entry
                                                      # that is an item with lines added has them carried into its file
    python3 tools/backlog.py --self-test

An item may be named by its number or by its exact title. A branch written before the split conflicts in
docs/BACKLOG.md once it merges `main`. To mend it:

    git show HEAD:docs/BACKLOG.md > /tmp/old-backlog.md    # the branch's own copy
    git checkout MERGE_HEAD -- docs/BACKLOG.md             # main's rules and roadmap
    python3 tools/backlog.py move /tmp/old-backlog.md      # the branch's new items, as files

An item the branch only added lines to (a claim or a done note inside it) has those lines carried into its file by
`move`, which says so; set its status line, since that is where the note now lives. An item whose lines the branch
changed is named and not written: carry the change by hand.
"""

import datetime
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FOLDER = ROOT / "docs" / "backlog"
BACKLOG = ROOT / "docs" / "BACKLOG.md"

NAME = re.compile(r"^(\d{4})-[a-z0-9]+(?:-[a-z0-9]+)*\.md$")
STATUS = re.compile(r"^\*\*Status:\*\* (?P<text>.+?)[ \t]*$", re.M)
FORMS = re.compile(r"^(open|claimed by [^,\n]+, \S.*|done, \S.*|partly done: \S.*)$")
ITEM = re.compile(r"(?=^- (?:~~)?\*\*)", re.M)
TITLE = re.compile(r"^- (?:~~)?\*\*(.*?)\*\*(?:~~)?", re.S)
PART = re.compile(r"^\s{0,5}(\d+)\.\s(.*?)(?=^\s{0,5}\d+\.\s|\Z)", re.S | re.M)
DONE = re.compile(r"\*\*(Done|Built|Fixed|Mended|Written|Answered|Settled)\b")
NOT_DONE = re.compile(r"\b(Not done|not done|Not built|not built|left for|still open|remains open|Not yet)\b")
CLAIMED = re.compile(r"\*\*Claimed\b")
SESSION = re.compile(r"\bby session ([A-Za-z0-9_-]+)")


def today():
    d = datetime.date.today()
    return f"{d.day} {d.strftime('%B %Y')}"


def slug(title):
    """A title made into a file name: lowercase letters and digits joined by hyphens, whole words up to 60
    characters (the first word cut at 60 when it alone is longer), as design entries are named."""
    words = [w for w in re.split(r"[^a-z0-9]+", title.lower()) if w]
    name = ""
    for word in words:
        if name and len(name) + 1 + len(word) > 60:
            break
        name = f"{name}-{word}" if name else word
    return (name or "item")[:60]


def marker_status(text):
    """A part's status from the markers in its prose: done, part, claimed, or open."""
    if DONE.search(text):
        return "part" if NOT_DONE.search(text) else "done"
    if CLAIMED.search(text):
        return "claimed"
    return "open"


def part_counts(body):
    """The numbered parts of an item's text, counted by their markers."""
    counts = {"open": 0, "claimed": 0, "part": 0, "done": 0}
    for _, part in PART.findall(body):
        counts[marker_status(part)] += 1
    return counts


class Item:
    def __init__(self, path):
        self.path = path
        text = path.read_text(encoding="utf-8")
        self.text = text
        m = NAME.match(path.name)
        self.number = int(m.group(1)) if m else None
        first = text.split("\n", 1)[0]
        self.title = first[2:].strip() if first.startswith("# ") else None
        s = STATUS.search(text)
        self.status_text = s.group("text") if s else None
        self.kind = None
        if self.status_text and FORMS.match(self.status_text):
            self.kind = "partly done" if self.status_text.startswith("partly") else self.status_text.split(" ", 1)[0].rstrip(",")
        self.body = text[s.end():] if s else text
        self.counts = part_counts(self.body)
        self.sessions = sorted(set(SESSION.findall(text)))
        if self.kind == "claimed":
            who = re.match(r"claimed by ([^,]+),", self.status_text).group(1).strip()
            self.sessions = sorted(set(self.sessions) | {who})

    def set_status(self, text):
        self.text = STATUS.sub(lambda _: f"**Status:** {text}", self.text, count=1)
        self.path.write_text(self.text, encoding="utf-8")
        self.status_text, self.kind = text, ("partly done" if text.startswith("partly") else text.split(" ", 1)[0].rstrip(","))


def items(folder=FOLDER):
    return [Item(p) for p in sorted(folder.glob("*.md"))]


def find(folder, key):
    """The item named by a number ("0150", "150") or an exact title."""
    found = items(folder)
    if re.fullmatch(r"\d{1,4}", key):
        hits = [i for i in found if i.number == int(key)]
    else:
        hits = [i for i in found if i.title == key]
    if len(hits) != 1:
        raise SystemExit(f"{len(hits)} items match {key!r}; name one by its number or its exact title")
    return hits[0]


def text_of(title, status, body):
    return f"# {title}\n\n**Status:** {status}\n\n{body.strip()}\n" if body.strip() else f"# {title}\n\n**Status:** {status}\n"


def write(folder, number, title, status, body):
    path = folder / f"{number:04d}-{slug(title)}.md"
    path.write_text(text_of(title, status, body), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------------------------------------------
# The old single-file layout, read for the split and for a branch written before it.

def old_items(text):
    """Each `- **title.**` item of an old-layout backlog, section by section: (title, body, status). Prose in a
    section before its first item becomes an item titled after the section, so nothing is lost; a section with no
    item (the rules, the roadmap) is left alone."""
    out = []
    for m in re.finditer(r"^## (?P<head>[^\n]+)\n(?P<body>.*?)(?=^## |\Z)", text, re.S | re.M):
        body = m.group("body")
        chunks = ITEM.split(body)
        if not any(c.startswith("- **") or c.startswith("- ~~**") for c in chunks):
            continue
        for chunk in chunks:
            if not chunk.strip():
                continue
            if chunk.startswith("- **") or chunk.startswith("- ~~**"):
                t = TITLE.match(chunk)
                title = re.sub(r"\s+", " ", t.group(1)).strip()
                rest = chunk[t.end():]
                lines = rest.split("\n")
                first = lines[0].lstrip()
                others = [ln[2:] if ln.startswith("  ") else ln for ln in lines[1:]]
                item_body = "\n".join([first] + others)
            else:
                title = m.group("head").strip()
                item_body = chunk
            title = title[:-1] if title.endswith(".") else title
            out.append((title, item_body, split_status(chunk)))
    return out


def split_status(chunk):
    """An old item's status line, read from its markers once, at the split; the reading is dated so nobody takes
    it for a person's word."""
    when = "as its markers read on 8 October 2026"
    if chunk.startswith("- ~~") and marker_status(chunk) != "done":
        return f"done, struck through in the old file, {when}"
    counts = part_counts(chunk)
    parts = sum(counts.values())
    if parts:
        if counts["done"] == parts:
            return f"done, {when}"
        if counts["open"] == parts:
            return "open"
        return f"partly done: {counts['done']} of {parts} parts done, {counts['claimed']} claimed, {counts['open']} open, {when}"
    own = marker_status(chunk)
    if own == "done":
        return f"done, {when}"
    if own == "part":
        return f"partly done: see its done note; what remains is not yet written, {when}"
    if own == "claimed":
        who = " and ".join(sorted(set(SESSION.findall(chunk)))) or "a session not named"
        return f"claimed by {who}, {when}"
    return "open"


def carried(mine, theirs):
    """The item's text with the lines `theirs` adds to `mine` added in place, when `theirs` is `mine` with lines
    added and nothing else (a claim or a done note written inside the item on a branch); else None."""
    import difflib
    a, b = mine.strip("\n").split("\n"), theirs.strip("\n").split("\n")
    out = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == "equal":
            out.extend(a[i1:i2])
        elif tag == "insert":
            out.extend(b[j1:j2])
        else:
            return None
    return "\n".join(out)


def move(source, folder):
    """Makes an item of each entry of `source` (old layout) whose title is not an item yet. An entry that is an item
    already, and whose text is the item's with lines added (a note written inside it on a branch), has those lines
    carried into the item's file, its status line left for a person. Returns (written, carried_into, differing): the
    paths written, the paths lines were carried into, and (title, path) for titles whose text differs otherwise."""
    folder.mkdir(parents=True, exist_ok=True)
    known = {i.title: i for i in items(folder) if i.title}
    number = max((i.number for i in items(folder) if i.number), default=0)
    written, carried_into, differing = [], [], []
    for title, body, status in old_items(source.read_text(encoding="utf-8")):
        if title in known:
            item = known[title]
            if item.body.strip() != body.strip():
                merged = carried(item.body, body)
                if merged is None:
                    differing.append((title, item.path))
                else:
                    head = item.text[: len(item.text) - len(item.body)]
                    item.path.write_text(head.rstrip("\n") + "\n\n" + merged.strip("\n") + "\n", encoding="utf-8")
                    carried_into.append(item.path)
            continue
        number += 1
        path = write(folder, number, title, status, body)
        known[title] = Item(path)
        written.append(path)
    return written, carried_into, differing


# ---------------------------------------------------------------------------------------------------------------

def problems(backlog, folder):
    found = []
    titles = {}
    for path in sorted(folder.glob("*")):
        if path.name.startswith("."):
            continue
        if not NAME.match(path.name):
            found.append(f"{path.name} is not named NNNN-title.md")
            continue
        item = Item(path)
        if not item.title:
            found.append(f"{path.name} does not open with `# ` and its title")
            continue
        if not item.status_text:
            found.append(f"{path.name} has no `**Status:**` line")
        elif not item.kind:
            found.append(f"{path.name}: the status {item.status_text!r} is in none of the four forms")
        if item.title in titles:
            found.append(f"{path.name} and {titles[item.title]} share the title {item.title!r}")
        titles[item.title] = path.name
    if backlog.exists():
        for n, line in enumerate(backlog.read_text(encoding="utf-8").split("\n"), 1):
            if line.startswith("- **") or line.startswith("- ~~**"):
                found.append(f"{backlog.name} line {n} is an item; items are files under {folder.name}/")
    return found


def show_list(found, only):
    for i in found:
        if only and (i.kind or "?") != only:
            continue
        c = i.counts
        parts = f"o{c['open']} c{c['claimed']} p{c['part']} d{c['done']}" if sum(c.values()) else ""
        who = ",".join(i.sessions)[:28]
        print(f"{i.number:04d}  {(i.kind or '?'):12s} {parts:16s} {who:28s} {(i.title or '?')[:80]}")


def summary(found):
    by = {}
    for i in found:
        by[i.kind or "?"] = by.get(i.kind or "?", 0) + 1
    print(f"{len(found)} items: " + ", ".join(f"{by.get(k, 0)} {k}" for k in ("open", "claimed", "partly done", "done")))


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        folder, backlog = tmp / "backlog", tmp / "BACKLOG.md"
        old = tmp / "OLD.md"
        old.write_text("""# x

rules

## Roadmap

1. "An open item" first.

## Next

- **An open item.** Nothing has happened.

- **A claimed item.** Text. **Claimed 8 October 2026 by session alpha**, in branch `b`.

- **A done item.** Text. **Done the same day** (DESIGN, "x").
  A second line of it.

- **A mixed item.** Intro.
  1. **First.** **Done the same day.**
  2. **Second.** **Claimed by session gamma**.
  3. **Third.** Open still.

## Decided, not yet written down as ADRs

**All three written down.** Prose before any item.

- **A decided item.** **Done** on the day.

- ~~**A struck item.**~~ **Done the same day.** It was.
""", encoding="utf-8")
        written, carried_into, differing = move(old, folder)
        names = [p.name for p in written]
        assert names == ["0001-an-open-item.md", "0002-a-claimed-item.md", "0003-a-done-item.md", "0004-a-mixed-item.md",
                         "0005-decided-not-yet-written-down-as-adrs.md", "0006-a-decided-item.md",
                         "0007-a-struck-item.md"], names
        assert differing == [] and carried_into == []
        got = {i.title: i for i in items(folder)}
        assert got["An open item"].kind == "open"
        assert got["A claimed item"].kind == "claimed" and got["A claimed item"].sessions == ["alpha"], got["A claimed item"].status_text
        assert got["A done item"].kind == "done" and "A second line of it." in got["A done item"].body
        assert got["A done item"].body.lstrip().startswith("Text."), got["A done item"].body
        assert got["A mixed item"].kind == "partly done" and got["A mixed item"].counts == {"open": 1, "claimed": 1, "part": 0, "done": 1}
        assert got["Decided, not yet written down as ADRs"].kind == "open" and "Prose before any item" in got["Decided, not yet written down as ADRs"].body
        assert got["A decided item"].kind == "done"
        assert got["A struck item"].kind == "done" and got["A struck item"].body.strip().startswith("**Done the same day.**")
        # The roadmap's numbered lines are not parts of anything, and the rules are not an item.
        assert "An open item" in got and len(got) == 7
        # Moving again writes nothing; an item with lines added since has them carried in; one whose lines changed
        # is named, not overwritten.
        assert move(old, folder) == ([], [], [])
        old.write_text(old.read_text(encoding="utf-8")
                       .replace("Nothing has happened.", "Nothing has happened.\n  **Claimed later by session delta.**")
                       .replace("A second line of it.", "A line that was rewritten.")
                       + "\n- **A new item.** New.\n", encoding="utf-8")
        written, carried_into, differing = move(old, folder)
        assert [p.name for p in written] == ["0008-a-new-item.md"], written
        assert [p.name for p in carried_into] == ["0001-an-open-item.md"], carried_into
        assert [t for t, _ in differing] == ["A done item"], differing
        text = got["An open item"].path.read_text(encoding="utf-8")
        assert "**Status:** open" in text and "Claimed later by session delta" in text, text
        assert "rewritten" not in got["A done item"].path.read_text(encoding="utf-8")
        assert carried("a\nb\n", "a\nx\nb\n") == "a\nx\nb" and carried("a\nb\n", "a\nc\n") is None
        # claim and done write the status line, and a claim refuses a held or done item.
        item = find(folder, "1")
        item.set_status("claimed by beta, 9 October 2026")
        assert find(folder, "An open item").kind == "claimed" and "beta" in find(folder, "0001").sessions
        assert claim(folder, "1", "gamma", "9 October 2026") is False
        assert claim(folder, "1", "beta", "9 October 2026") is True
        assert claim(folder, "3", "gamma", "9 October 2026") is False
        assert mark_done(folder, "1", "9 October 2026", None) is True and find(folder, "1").kind == "done"
        # The blank line after the status stays: `\s*` once ate the line's own newline and joined the two.
        assert "**Status:** done, 9 October 2026\n\nNothing" in find(folder, "1").path.read_text(encoding="utf-8")
        assert mark_done(folder, "8", "9 October 2026", "the tail") is True
        assert find(folder, "8").status_text == "partly done: the tail"
        # new, and the checks.
        path = new(folder, "A brand new item")
        assert path.name == "0009-a-brand-new-item.md" and find(folder, "9").kind == "open"
        backlog.write_text("# Backlog\n\nrules\n\n## Roadmap\n\n1. first\n", encoding="utf-8")
        assert problems(backlog, folder) == [], problems(backlog, folder)
        backlog.write_text("# Backlog\n\n- **An item left here.** text\n", encoding="utf-8")
        assert any("line 3 is an item" in p for p in problems(backlog, folder))
        backlog.write_text("# Backlog\n", encoding="utf-8")
        (folder / "notes.md").write_text("# Notes\n\n**Status:** open\n", encoding="utf-8")
        (folder / "0010-untitled.md").write_text("no heading\n", encoding="utf-8")
        (folder / "0011-no-status.md").write_text("# No status\n\ntext\n", encoding="utf-8")
        (folder / "0012-odd-status.md").write_text("# Odd status\n\n**Status:** finished\n", encoding="utf-8")
        (folder / "0013-twin.md").write_text("# A done item\n\n**Status:** open\n", encoding="utf-8")
        found = problems(backlog, folder)
        for want in ("notes.md is not named", "0010-untitled.md does not open", "has no `**Status:**` line",
                     "is in none of the four forms", "share the title"):
            assert any(want in p for p in found), (want, found)
        assert slug("One file per backlog item, with a status line.") == "one-file-per-backlog-item-with-a-status-line"
    print("backlog self-test: ok")


def claim(folder, key, session, date):
    item = find(folder, key)
    if item.kind == "done":
        print(f"{item.path.name} is done; nothing to claim")
        return False
    if item.kind == "claimed" and session not in item.sessions:
        print(f"{item.path.name} is {item.status_text}; a claim by another session is refused")
        return False
    item.set_status(f"claimed by {session}, {date}")
    print(f"{item.path.name}: {item.status_text}")
    return True


def mark_done(folder, key, date, remains):
    item = find(folder, key)
    item.set_status(f"partly done: {remains}" if remains else f"done, {date}")
    print(f"{item.path.name}: {item.status_text}")
    return True


def new(folder, title):
    title = title.strip()
    if any(i.title == title for i in items(folder)):
        raise SystemExit(f"an item is already titled {title!r}")
    folder.mkdir(parents=True, exist_ok=True)
    number = max((i.number for i in items(folder) if i.number), default=0) + 1
    return write(folder, number, title, "open", "")


def main(argv):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("command", nargs="?", default="list",
                        choices=["list", "summary", "new", "claim", "done", "show", "move"])
    parser.add_argument("args", nargs="*")
    parser.add_argument("--open", action="store_true")
    parser.add_argument("--claimed", action="store_true")
    parser.add_argument("--done", action="store_true")
    parser.add_argument("--partly", action="store_true")
    parser.add_argument("--by", help="the session making a claim")
    parser.add_argument("--date", default=today())
    parser.add_argument("--remains", help="with done: what remains, making the item partly done")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    a = parser.parse_args(argv)
    if a.self_test:
        self_test()
        return 0
    if a.check:
        found = problems(BACKLOG, FOLDER)
        for p in found:
            print(p)
        return 1 if found else 0
    if a.command == "list":
        only = "open" if a.open else "claimed" if a.claimed else "done" if a.done else "partly done" if a.partly else None
        found = items()
        show_list(found, only)
        print()
        summary(found)
        return 0
    if a.command == "summary":
        summary(items())
        return 0
    if a.command == "new" and len(a.args) == 1:
        print(new(FOLDER, a.args[0]).relative_to(ROOT))
        return 0
    if a.command == "claim" and len(a.args) == 1 and a.by:
        return 0 if claim(FOLDER, a.args[0], a.by, a.date) else 1
    if a.command == "done" and len(a.args) == 1:
        return 0 if mark_done(FOLDER, a.args[0], a.date, a.remains) else 1
    if a.command == "show" and len(a.args) == 1:
        print(find(FOLDER, a.args[0]).text)
        return 0
    if a.command == "move" and len(a.args) == 1:
        written, carried_into, differing = move(Path(a.args[0]), FOLDER)
        for path in written:
            print(f"wrote {path.relative_to(ROOT)}")
        for path in carried_into:
            print(f"carried added lines into {path.relative_to(ROOT)}: read them, and set its status line")
        for title, path in differing:
            print(f"\"{title}\" is already {path.relative_to(ROOT)}, and its text differs: carry the change into "
                  f"that file by hand, and set its status line")
        return 1 if differing else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
