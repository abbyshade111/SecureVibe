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

The rest is the item's text, its numbered parts included. A part is a line `N. **Its title.**` and the indented lines
under it, and has a status line of its own among them, in the same four forms (backlog 0228; ADR-061, Later, 9
October 2026):

    1. **A finding.** What is wrong, and what to do.
       **Part status:** claimed by <session>, <date>

set by `claim 0226.1` and `done 0226.1` as an item's is, and read by `list`, `--check`, and the board in the docs
set from that line alone, never from the prose. A note written at the item's end, at the left margin, belongs to no
part; `--check` fails when one names a part ("**Part 1, item 3 claimed", "**Items 3 and 7 done") that the part's own
line disagrees with, when a part has no line, and when an item is `done` with a part that is not, or `open` with one
begun. A done item's file is under docs/backlog/done/, the rest beside it, so the folder lists live work alone (backlog
0228, part 6); `done` moves an item there and rewrites any path to it in the repository, and `tidy` puts every item where
its status says. `--check` warns, without failing, of a live item past 300 lines (part 8). The numbers keep the order the items stood
in the old single file when it was split on 8 October 2026, and are an identity, not a date; two pull requests open
at once may take the same number, which harms nothing. docs/BACKLOG.md holds the rules and the roadmap, and no item
and no list of items: a list every item adds a line to would bring back the conflicts this layout is for.

    python3 tools/backlog.py list                     # every item, in number order
    python3 tools/backlog.py list --open              # only the open ones (--claimed, --done, --partly likewise)
    python3 tools/backlog.py summary                  # the counts alone
    python3 tools/backlog.py board                    # the board: in progress, partly done, open, latest done
    python3 tools/backlog.py board --html board.html  # the same board as one page, for a browser or a phone
    python3 tools/backlog.py new "A title"            # writes an open item, numbered one past the highest; prints its path
    python3 tools/backlog.py claim 0150 --by <session>          # sets the status line (refused when another session holds it, or it is done)
    python3 tools/backlog.py claim 0226.3 --by <session>        # the same for part 3 of item 0226
    python3 tools/backlog.py done 0150                # sets `done, <today>`; with --remains "..." sets `partly done: ...`
    python3 tools/backlog.py done 0226.3              # the same for a part
    python3 tools/backlog.py convert                  # gives every part with no status line one, once (run on 9 October 2026)
    python3 tools/backlog.py tidy                     # puts each item's file under done/ or beside it, as its status says
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


def write_text(path, text):
    """Writes `text` as UTF-8 with Unix line endings on every system. Path.write_text uses the
    system's own encoding and, on Windows, CRLF, which would make a generated file differ from the
    one committed (backlog 0120)."""
    with open(path, "w", encoding="utf-8", newline="\n") as out:
        out.write(text)

ROOT = Path(__file__).resolve().parent.parent
FOLDER = ROOT / "docs" / "backlog"
BACKLOG = ROOT / "docs" / "BACKLOG.md"
# A done item's file moves here, keeping its number and name, so the folder above holds only live work (backlog 0228,
# part 6). Everything that reads items reads both.
DONE_DIR = "done"
# An item past this many lines is named by --check as one to split, a warning and not a failure (backlog 0228, part 8).
LONG_ITEM = 300

NAME = re.compile(r"^(\d{4})-[a-z0-9]+(?:-[a-z0-9]+)*\.md$")
STATUS = re.compile(r"^\*\*Status:\*\* (?P<text>.+?)[ \t]*$", re.M)
FORMS = re.compile(r"^(open|claimed by [^,\n]+, \S.*|done, \S.*|partly done: \S.*)$")
ITEM = re.compile(r"(?=^- (?:~~)?\*\*)", re.M)
TITLE = re.compile(r"^- (?:~~)?\*\*(.*?)\*\*(?:~~)?", re.S)
PART = re.compile(r"^\s{0,5}(\d+)\.\s(.*?)(?=^\s{0,5}\d+\.\s|\Z)", re.S | re.M)
DONE = re.compile(r"\*\*(Done|Built|Fixed|Mended|Written|Answered|Settled)\b")
NOT_DONE = re.compile(r"\b(Not done|not done|Not built|not built|left for|still open|remains open|Not yet)\b")
CLAIMED = re.compile(r"\*\*Claimed\b")
# A numbered part: `N. **Its title.**` at the start of a line, and the lines under it that are blank or indented. Its
# status is a line of its own among them, in an item's four forms (ADR-061, Later, 9 October 2026; backlog 0228).
PART_HEAD = re.compile(r"^ {0,5}(\d+)\. \*\*")
PART_STATUS = re.compile(r"^[ \t]+\*\*Part status:\*\* (?P<text>.+?)[ \t]*$", re.M)
# A note at an item's end naming parts: "**Part 1, item 3 claimed", "**Part 1, items 9 and 10 claimed", "**Items 3 and
# 7 done". What it says must agree with the parts' own lines.
NOTE = re.compile(r"\*\*(?:Part \d+, )?[Ii]tems? ((?:\d+(?:, | and |, and ))*\d+)(?: \w+)? (claimed|done)\b")
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


def marker_counts(text):
    """The numbered parts of an item in the old single-file layout, counted by the markers in their prose: what `move`
    read when the items were split, kept for a branch from before then. Items now read their parts' own lines."""
    counts = {"open": 0, "claimed": 0, "part": 0, "done": 0}
    for _, part in PART.findall(text):
        counts[marker_status(part)] += 1
    return counts


def kind_of(status_text):
    """The kind of a status in one of the four forms: open, claimed, partly done, or done; None otherwise."""
    if not status_text or not FORMS.match(status_text):
        return None
    return "partly done" if status_text.startswith("partly") else status_text.split(" ", 1)[0].rstrip(",")


class Part:
    """A numbered part of an item: its number, its lines in the item's text, and its own status line."""

    def __init__(self, number, start, end, text):
        self.number, self.start, self.end, self.text = number, start, end, text
        s = PART_STATUS.search(text)
        self.status_text = s.group("text") if s else None
        self.kind = kind_of(self.status_text)
        self.lines = len(PART_STATUS.findall(text))
        self.head = text.split("\n", 1)[0].strip()


def parts_of(body):
    """The numbered parts of an item's text, each running from its `N. **` line over the blank and indented lines
    under it, so a note at the item's end, written at the left margin, belongs to no part."""
    lines = body.split("\n")
    offsets, at = [], 0
    for line in lines:
        offsets.append(at)
        at += len(line) + 1
    found, n = [], 0
    while n < len(lines):
        head = PART_HEAD.match(lines[n])
        if not head:
            n += 1
            continue
        end = n + 1
        while end < len(lines) and not PART_HEAD.match(lines[end]) and (
            not lines[end].strip() or lines[end][:1] in " \t"
        ):
            end += 1
        while end > n + 1 and not lines[end - 1].strip():
            end -= 1
        start, stop = offsets[n], offsets[end - 1] + len(lines[end - 1])
        found.append(Part(int(head.group(1)), start, stop, body[start:stop]))
        n = end
    return found


def part_counts(parts):
    """How many parts are of each kind, from their own status lines; `unread` for one that has none."""
    counts = {"open": 0, "claimed": 0, "part": 0, "done": 0, "unread": 0}
    for part in parts:
        counts[{"partly done": "part", None: "unread"}.get(part.kind, part.kind)] += 1
    return counts


def notes_of(body):
    """What the notes in an item's text say of its parts by number: `claimed` or `done`, the last word for each."""
    said = {}
    for m in NOTE.finditer(body):
        for number in re.findall(r"\d+", m.group(1)):
            said[int(number)] = m.group(2)
    return said


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
        self.parts = parts_of(self.body)
        self.counts = part_counts(self.parts)
        self.sessions = sorted(set(SESSION.findall(text)))
        if self.kind == "claimed":
            who = re.match(r"claimed by ([^,]+),", self.status_text).group(1).strip()
            self.sessions = sorted(set(self.sessions) | {who})

    def set_part_status(self, number, text):
        """Sets part `number`'s own status line, adding it as the part's last line when it has none."""
        self.set_part_status_at(self.parts.index(self.part(number)), text)

    def set_part_status_at(self, index, text):
        """`set_part_status` for the part at `index` among the item's parts in order, for an item whose lists number
        their parts afresh (two parts numbered 1), which a number alone cannot name."""
        part = self.parts[index]
        if part.status_text is None:
            line = f"\n   **Part status:** {text}"
            body = self.body[: part.end] + line + self.body[part.end :]
        else:
            new_text = PART_STATUS.sub(lambda m: m.group(0).replace(m.group("text"), text), part.text, count=1)
            body = self.body[: part.start] + new_text + self.body[part.end :]
        self.text = self.text[: len(self.text) - len(self.body)] + body
        write_text(self.path, self.text)
        self.body = body
        self.parts = parts_of(body)
        self.counts = part_counts(self.parts)

    def part(self, number):
        hits = [p for p in self.parts if p.number == number]
        if len(hits) != 1:
            raise SystemExit(f"{self.path.name} has {len(hits)} parts numbered {number}")
        return hits[0]

    def set_status(self, text):
        self.text = STATUS.sub(lambda _: f"**Status:** {text}", self.text, count=1)
        write_text(self.path, self.text)
        self.status_text, self.kind = text, ("partly done" if text.startswith("partly") else text.split(" ", 1)[0].rstrip(","))


def items(folder=FOLDER):
    """Every item, live and done, in number order."""
    paths = list(folder.glob("*.md")) + list((folder / DONE_DIR).glob("*.md"))
    return [Item(p) for p in sorted(paths, key=lambda p: p.name)]


def where_for(folder, item):
    """The file an item belongs in: under `done/` when it is done, beside the others when it is not."""
    return (folder / DONE_DIR if item.kind == "done" else folder) / item.path.name


def root_of(folder):
    """The repository a backlog folder belongs to: this one for `docs/backlog`, and the folder's own parent for one
    elsewhere (the self-test's), so a rewrite never reaches past the backlog's own tree."""
    folder = folder.resolve()
    return ROOT.resolve() if folder.is_relative_to(ROOT.resolve()) else folder.parent


def moved(folder, item, root=None):
    """Moves an item's file to where its status says it belongs, and rewrites every path to it in the repository's
    text, so a reference to the old place is never left pointing at nothing. Returns the files rewritten."""
    to = where_for(folder, item)
    if to == item.path:
        return []
    root = root or root_of(folder)
    to.parent.mkdir(parents=True, exist_ok=True)
    old_rel = item.path.resolve().relative_to(root).as_posix()
    new_rel = to.resolve().parent.relative_to(root).as_posix() + "/" + to.name
    item.path.rename(to)
    item.path = to
    rewritten = []
    for path in root.rglob("*"):
        if (not path.is_file() or path.suffix not in (".md", ".rs", ".py", ".toml", ".json", ".yml", ".html", ".txt")
                or {".git", "target", "node_modules"} & set(path.relative_to(root).parts)):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if old_rel in text:
            write_text(path, text.replace(old_rel, new_rel))
            rewritten.append(path)
    return rewritten


def tidy(folder, root=None):
    """Puts every item's file where its status says it belongs; run once when `done/` was made, on 10 October 2026,
    and by `done` for one item ever after."""
    changes = []
    for item in items(folder):
        before = item.path
        rewritten = moved(folder, item, root)
        if item.path != before:
            changes.append((item, rewritten))
    return changes


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
    """Writes an item, under `done/` when its status is done."""
    place = folder / DONE_DIR if kind_of(status) == "done" else folder
    place.mkdir(parents=True, exist_ok=True)
    path = place / f"{number:04d}-{slug(title)}.md"
    write_text(path, text_of(title, status, body))
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
    counts = marker_counts(chunk)
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
                    write_text(item.path, head.rstrip("\n") + "\n\n" + merged.strip("\n") + "\n")
                    carried_into.append(item.path)
            continue
        number += 1
        path = write(folder, number, title, status, body)
        known[title] = Item(path)
        written.append(path)
    return written, carried_into, differing


# ---------------------------------------------------------------------------------------------------------------

def part_problems(item):
    """What is wrong with an item's parts: a part with no status line or one in none of the forms, an item `done` with
    a part not done or `open` with a part under way, and a note that names a part its own line disagrees with."""
    found = []
    for part in item.parts:
        if part.status_text is None:
            found.append(f"{item.path.name}, part {part.number}, has no `**Part status:**` line")
        elif part.kind is None:
            found.append(f"{item.path.name}, part {part.number}: the status {part.status_text!r} is in none of the four forms")
        if part.lines > 1:
            # The board reads only the first, so a stale claim a merge left above a later line hides it (0226, part 13,
            # on 10 October 2026).
            found.append(f"{item.path.name}, part {part.number}, has {part.lines} `**Part status:**` lines; keep one")
    heads = [part.head for part in item.parts]
    for head in sorted({h for h in heads if heads.count(h) > 1}):
        number = next(part.number for part in item.parts if part.head == head)
        found.append(f"{item.path.name}: part {number} is written {heads.count(head)} times over; keep one")
    kinds = {part.kind for part in item.parts}
    if item.kind == "done" and kinds - {"done"}:
        found.append(f"{item.path.name} is done, and not all of its parts are")
    if item.kind == "open" and kinds & {"claimed", "partly done", "done"}:
        found.append(f"{item.path.name} is open, and some of its parts are under way or done")
    numbers = {part.number: part for part in item.parts}
    for number, said in notes_of(item.body).items():
        part = numbers.get(number)
        if part is None or part.kind is None:
            continue
        if said == "done" and part.kind not in ("done", "partly done"):
            found.append(f"{item.path.name}: a note says part {number} is done, and its line says {part.status_text!r}")
        if said == "claimed" and part.kind == "open":
            found.append(f"{item.path.name}: a note says part {number} is claimed, and its line says it is open")
    return found


def problems(backlog, folder):
    found = []
    titles = {}
    paths = [p for p in folder.glob("*") if p.name != DONE_DIR] + list((folder / DONE_DIR).glob("*"))
    for path in sorted(paths, key=lambda p: p.name):
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
        found.extend(part_problems(item))
        if item.kind and where_for(folder, item) != item.path:
            found.append(f"{path.name} is {item.kind} and in the wrong folder: a done item belongs under {DONE_DIR}/, and only "
                         f"a done one (`backlog.py tidy` puts each where its status says)")
        if item.title in titles:
            found.append(f"{path.name} and {titles[item.title]} share the title {item.title!r}")
        titles[item.title] = path.name
    if backlog.exists():
        for n, line in enumerate(backlog.read_text(encoding="utf-8").split("\n"), 1):
            if line.startswith("- **") or line.startswith("- ~~**"):
                found.append(f"{backlog.name} line {n} is an item; items are files under {folder.name}/")
    return found


def warnings(folder):
    """An item long enough to be worth splitting: named, never failed on (backlog 0228, part 8)."""
    return [f"{i.path.name} is {i.text.count(chr(10))} lines; past {LONG_ITEM}, think of making its next findings items "
            f"of their own" for i in items(folder) if i.kind != "done" and i.text.count("\n") > LONG_ITEM]


def show_list(found, only):
    for i in found:
        if only and (i.kind or "?") != only:
            continue
        c = i.counts
        parts = f"o{c['open']} c{c['claimed']} p{c['part']} d{c['done']}" if sum(c.values()) else ""
        if c["unread"]:
            parts += f" ?{c['unread']}"
        who = ",".join(i.sessions)[:28]
        print(f"{i.number:04d}  {(i.kind or '?'):12s} {parts:16s} {who:28s} {(i.title or '?')[:80]}")


def summary(found):
    by = {}
    for i in found:
        by[i.kind or "?"] = by.get(i.kind or "?", 0) + 1
    print(f"{len(found)} items: " + ", ".join(f"{by.get(k, 0)} {k}" for k in ("open", "claimed", "partly done", "done")))


STALE_DAYS = 14
BOARD_DONE = 15


def date_in(text):
    """The day written in a status line ("9 October 2026"), or None when it names none."""
    m = DATE.search(text or "")
    return datetime.datetime.strptime(m.group(1), "%d %B %Y").date() if m else None


def held_by(text):
    """Who a claim's status line names: the words after "claimed by", up to the first comma."""
    m = re.match(r"claimed by ([^,:]+)", text or "")
    return m.group(1).strip() if m else "?"


def board_rows(found, now):
    """The board's lists, read from the status lines alone (never the prose): what is claimed, as an item or a
    numbered part of one; what is partly done and what remains; what is open; what is done, latest first; and any
    item with no readable status line. A claim is flagged for the owner to check when no session is named, when it
    names no date, or when it is older than STALE_DAYS, since a claim left by a session that has ended is the usual
    way two sessions end up on one item."""
    progress, partly, open_, done, unread = [], [], [], [], []

    def claim_row(label, title, text):
        day = date_in(text)
        check = []
        if "not named" in text:
            check.append("no session named")
        if day is None:
            check.append("no date recorded")
        elif (now - day).days > STALE_DAYS:
            check.append(f"{(now - day).days} days old")
        return (label, title, held_by(text), day.strftime("%d %b %Y") if day else "not recorded", "; ".join(check))

    for i in found:
        if i.kind == "done":
            done.append((date_in(i.status_text) or datetime.date.min, i))
            continue
        if i.kind == "claimed":
            progress.append(claim_row(f"{i.number:04d}", i.title, i.status_text))
        elif i.kind == "partly done":
            partly.append((i, i.status_text[len("partly done: "):]))
        elif i.kind == "open":
            open_.append(i)
        else:
            unread.append(i)
        for p in i.parts:
            if p.kind == "claimed":
                title = re.sub(r"^\d+\.\s*|\*\*", "", p.head)[:110]
                progress.append(claim_row(f"{i.number:04d}.{p.number}", title, p.status_text))
    done.sort(key=lambda pair: pair[0], reverse=True)
    return progress, partly, open_, [i for _, i in done], unread


def table(headers, rows):
    """A Markdown table, with any pipe in a cell escaped so a title cannot break it."""
    cell = lambda v: str(v).replace("|", "\\|")
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(cell(v) for v in row) + " |" for row in rows]
    return "\n".join(out)


def board_markdown(found, now):
    """The board as Markdown: the counts, then each list, read from the items' status lines by `board_rows`."""
    progress, partly, open_, done, unread = board_rows(found, now)
    counts = f"{len(found)} items: " + ", ".join(
        f"{sum(1 for i in found if i.kind == k)} {k}" for k in ("open", "claimed", "partly done", "done"))
    flagged = sum(1 for row in progress if row[4])
    parts = [
        f"# StackVet backlog board, {now.day} {now.strftime('%B %Y')}",
        "",
        f"{counts}. Read from each item's status line by `tools/backlog.py board`; reading it changes nothing.",
        "",
        f"## In progress ({len(progress)}, {flagged} to check)",
        "",
        "A claim is to check when no session is named, no date is recorded, or it is older than "
        f"{STALE_DAYS} days: the owner says whether it still holds, and releases it if not.",
        "",
        table(["Item", "What", "Held by", "Since", "To check"], progress) if progress else "Nothing is claimed.",
        "",
        f"## Partly done, with what remains ({len(partly)})",
        "",
        table(["Item", "What", "What remains"], [(f"{i.number:04d}", i.title, remains) for i, remains in partly]),
        "",
        f"## Open, not started ({len(open_)})",
        "",
        table(["Item", "What"], [(f"{i.number:04d}", i.title) for i in open_]),
        "",
        f"## Done, latest {BOARD_DONE} of {len(done)}",
        "",
        table(["Item", "What", "Done"], [
            (f"{i.number:04d}", i.title, (date_in(i.status_text) or "not recorded")) for i in done[:BOARD_DONE]
        ]),
    ]
    if unread:
        parts += ["", f"## No readable status line ({len(unread)})", "",
                  table(["Item", "What"], [(f"{i.number:04d}", i.title) for i in unread])]
    return "\n".join(parts) + "\n"


def board_html(found, now):
    """The same board as one HTML page with no outside requests, so it opens in any browser and can be kept or
    sent. Its colors follow the reader's light or dark setting."""
    import html

    progress, partly, open_, done, unread = board_rows(found, now)

    def section(title, headers, rows, empty):
        if not rows:
            return f"<h2>{html.escape(title)}</h2><p class=\"none\">{html.escape(empty)}</p>"
        head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
        body = "".join(
            "<tr>" + "".join(f"<td>{html.escape(str(v))}</td>" for v in row) + "</tr>" for row in rows)
        return f"<h2>{html.escape(title)}</h2><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"

    counts = "".join(
        f"<span class=\"chip {k.replace(' ', '-')}\">{sum(1 for i in found if i.kind == k)} {html.escape(k)}</span>"
        for k in ("open", "claimed", "partly done", "done"))
    sections = [
        section(f"In progress ({len(progress)})", ["Item", "What", "Held by", "Since", "To check"], progress,
                "Nothing is claimed."),
        section(f"Partly done, with what remains ({len(partly)})", ["Item", "What", "What remains"],
                [(f"{i.number:04d}", i.title, remains) for i, remains in partly], "Nothing is partly done."),
        section(f"Open, not started ({len(open_)})", ["Item", "What"],
                [(f"{i.number:04d}", i.title) for i in open_], "Nothing is open."),
        section(f"Done, latest {BOARD_DONE} of {len(done)}", ["Item", "What", "Done"],
                [(f"{i.number:04d}", i.title, date_in(i.status_text) or "not recorded")
                 for i in done[:BOARD_DONE]], "Nothing is done yet."),
    ]
    if unread:
        sections.append(section(f"No readable status line ({len(unread)})", ["Item", "What"],
                                [(f"{i.number:04d}", i.title) for i in unread], ""))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>StackVet backlog board</title>
<style>
:root {{ --bg: #fbfaf7; --ink: #1d1d1b; --muted: #6b6a64; --line: #dcd9d0; --chip: #efece4; }}
@media (prefers-color-scheme: dark) {{ :root:not([data-theme="light"]) {{ --bg: #161614; --ink: #ece9e1; --muted: #9c9a92; --line: #3a3934; --chip: #262520; }} }}
:root[data-theme="dark"] {{ --bg: #161614; --ink: #ece9e1; --muted: #9c9a92; --line: #3a3934; --chip: #262520; }}
body {{ background: var(--bg); color: var(--ink); font: 15px/1.5 system-ui, sans-serif; margin: 0; padding: 16px; }}
h1 {{ font-size: 22px; margin: 8px 0; }} h2 {{ font-size: 17px; margin: 28px 0 8px; }}
.chip {{ display: inline-block; background: var(--chip); border-radius: 12px; padding: 2px 10px; margin: 2px 4px 2px 0; color: var(--muted); }}
table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
th, td {{ text-align: left; vertical-align: top; border-bottom: 1px solid var(--line); padding: 6px 8px; }}
th {{ color: var(--muted); font-weight: 600; }}
.none {{ color: var(--muted); }}
@media (max-width: 600px) {{ table, thead, tbody, tr, td, th {{ display: block; }} thead {{ display: none; }}
  td {{ border: 0; padding: 2px 0; }} tr {{ border-bottom: 1px solid var(--line); padding: 6px 0; }} }}
</style></head>
<body>
<h1>StackVet backlog board, {now.day} {now.strftime('%B %Y')}</h1>
<p>{counts}</p>
<p class="none">Read from each item's status line by <code>tools/backlog.py board --html</code>. Reading it changes nothing.</p>
{''.join(sections)}
</body></html>
"""


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        folder, backlog = tmp / "backlog", tmp / "BACKLOG.md"
        old = tmp / "OLD.md"
        write_text(old, """# x

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
""")
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
        assert got["A mixed item"].kind == "partly done" and got["A mixed item"].counts["unread"] == 3
        assert got["Decided, not yet written down as ADRs"].kind == "open" and "Prose before any item" in got["Decided, not yet written down as ADRs"].body
        assert got["A decided item"].kind == "done"
        assert got["A struck item"].kind == "done" and got["A struck item"].body.strip().startswith("**Done the same day.**")
        # The roadmap's numbered lines are not parts of anything, and the rules are not an item.
        assert "An open item" in got and len(got) == 7
        # Moving again writes nothing; an item with lines added since has them carried in; one whose lines changed
        # is named, not overwritten.
        assert move(old, folder) == ([], [], [])
        write_text(old, old.read_text(encoding="utf-8")
                       .replace("Nothing has happened.", "Nothing has happened.\n  **Claimed later by session delta.**")
                       .replace("A second line of it.", "A line that was rewritten.")
                       + "\n- **A new item.** New.\n")
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
        write_text(backlog, "# Backlog\n\nrules\n\n## Roadmap\n\n1. first\n")
        # Moved, its parts have no lines of their own yet, which the check names; the conversion gives each one from
        # its markers, once.
        assert any("part 1, has no `**Part status:**` line" in p for p in problems(backlog, folder))
        convert(folder)
        mixed = find(folder, "A mixed item")
        assert mixed.counts == {"open": 1, "claimed": 1, "part": 0, "done": 1, "unread": 0}, mixed.counts
        assert mixed.part(2).status_text.startswith("claimed by gamma"), mixed.part(2).status_text
        assert convert(folder) == [], "the conversion is done once"
        assert problems(backlog, folder) == [], problems(backlog, folder)
        write_text(backlog, "# Backlog\n\n- **An item left here.** text\n")
        assert any("line 3 is an item" in p for p in problems(backlog, folder))
        write_text(backlog, "# Backlog\n")
        write_text((folder / "notes.md"), "# Notes\n\n**Status:** open\n")
        write_text((folder / "0010-untitled.md"), "no heading\n")
        write_text((folder / "0011-no-status.md"), "# No status\n\ntext\n")
        write_text((folder / "0012-odd-status.md"), "# Odd status\n\n**Status:** finished\n")
        write_text((folder / "0013-twin.md"), "# A done item\n\n**Status:** open\n")
        found = problems(backlog, folder)
        for want in ("notes.md is not named", "0010-untitled.md does not open", "has no `**Status:**` line",
                     "is in none of the four forms", "share the title"):
            assert any(want in p for p in found), (want, found)
        assert slug("One file per backlog item, with a status line.") == "one-file-per-backlog-item-with-a-status-line"
    # Parts (backlog 0228): each has its own line, set by claim and done, and the check holds them to it.
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp) / "backlog"
        folder.mkdir()
        write_text(folder / "0001-a-review.md", """# A review

**Status:** partly done: two findings

1. **A finding.** What is wrong.
   More of it.
   **Part status:** open

2. **Another.** Also wrong.
   **Part status:** open

**Part 1, item 2 claimed on 9 October 2026 by session alpha**, in branch `b`. A note at the item's end, in no part.
""")
        item = find(folder, "1")
        assert [part.number for part in item.parts] == [1, 2]
        assert "A note at the item" not in item.part(2).text, "a note at the left margin belongs to no part"
        # The note says part 2 is claimed, and its line says open: the check says so.
        assert any("a note says part 2 is claimed" in p for p in part_problems(item)), part_problems(item)
        assert claim(folder, "1.2", "alpha", "9 October 2026") is True
        assert claim(folder, "1.2", "beta", "9 October 2026") is False, "a part another session holds is refused"
        assert part_problems(find(folder, "1")) == [], part_problems(find(folder, "1"))
        assert mark_done(folder, "1.1", "9 October 2026", None) is True
        item = find(folder, "1")
        assert item.part(1).status_text == "done, 9 October 2026" and "More of it." in item.part(1).text
        assert claim(folder, "1.1", "alpha", "9 October 2026") is False, "a done part is not claimed again"
        assert item.counts == {"open": 0, "claimed": 1, "part": 0, "done": 1, "unread": 0}, item.counts
        # A part with no line, or one in no form, and an item whose own status disagrees with its parts.
        text = item.path.read_text(encoding="utf-8")
        write_text(item.path, text.replace("   **Part status:** claimed by alpha, 9 October 2026", "   **Part status:** soon"))
        assert any("is in none of the four forms" in p for p in part_problems(find(folder, "1")))
        write_text(item.path, text.replace("\n   **Part status:** claimed by alpha, 9 October 2026", ""))
        assert any("has no `**Part status:**` line" in p for p in part_problems(find(folder, "1")))
        write_text(item.path, text.replace("partly done: two findings", "done, 9 October 2026"))
        assert any("is done, and not all of its parts are" in p for p in part_problems(find(folder, "1")))
        write_text(item.path, text.replace("partly done: two findings", "open"))
        assert any("is open, and some of its parts are under way" in p for p in part_problems(find(folder, "1")))
        # A merge that leaves two lines on one part, or one part written twice, is named (0226, 10 October 2026).
        write_text(item.path, text.replace("   **Part status:** claimed by alpha, 9 October 2026",
                                           "   **Part status:** claimed by alpha, 9 October 2026\n   **Part status:** done, 9 October 2026"))
        assert any("part 2, has 2 `**Part status:**` lines" in p for p in part_problems(find(folder, "1"))), part_problems(find(folder, "1"))
        twice = "2. **Another.** Also wrong.\n   **Part status:** done, 9 October 2026\n"
        write_text(item.path, text.replace("\n**Part 1, item 2", "\n" + twice + "\n**Part 1, item 2"))
        assert any("part 2 is written 2 times over" in p for p in part_problems(find(folder, "1"))), part_problems(find(folder, "1"))
        assert part_problems(find(folder, "1")) and not any("lines; keep one" in p for p in part_problems(find(folder, "1")))
    # The done folder (backlog 0228, part 6): `done` moves an item there and rewrites the paths to it; an item given
    # what remains moves back; the check names one in the wrong folder; a long item draws a warning, never a failure.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        folder = root / "backlog"
        folder.mkdir()
        write_text(folder / "0001-a-thing.md", "# A thing\n\n**Status:** open\n\nText.\n")
        cites = root / "notes.md"
        write_text(cites, "See `backlog/0001-a-thing.md` for it.\n")
        assert mark_done(folder, "1", "10 October 2026", None) is True
        assert (folder / DONE_DIR / "0001-a-thing.md").exists() and not (folder / "0001-a-thing.md").exists()
        assert cites.read_text(encoding="utf-8") == "See `backlog/done/0001-a-thing.md` for it.\n", cites.read_text(encoding="utf-8")
        assert find(folder, "1").kind == "done" and [i.number for i in items(folder)] == [1]
        assert problems(root / "NONE.md", folder) == []
        assert mark_done(folder, "1", "10 October 2026", "one more piece") is True
        assert (folder / "0001-a-thing.md").exists(), "a done item given what remains is live again"
        assert "backlog/0001-a-thing.md" in cites.read_text(encoding="utf-8")
        # Put by hand in the wrong folder, it is named, and `tidy` puts it back.
        (folder / "0001-a-thing.md").rename(folder / DONE_DIR / "0001-a-thing.md")
        assert any("in the wrong folder" in p for p in problems(root / "NONE.md", folder))
        assert [i.path.parent.name for i, _ in tidy(folder)] == ["backlog"] and problems(root / "NONE.md", folder) == []
        # A new item takes the number after the highest, done ones counted.
        write_text(folder / DONE_DIR / "0009-old.md", "# Old\n\n**Status:** done, 1 October 2026\n")
        assert new(folder, "Newer").name == "0010-newer.md"
        write_text(folder / "0011-long.md", "# Long\n\n**Status:** open\n\n" + "a line\n" * (LONG_ITEM + 1))
        assert any("0011-long.md is" in w for w in warnings(folder)) and problems(root / "NONE.md", folder) == []
    print("backlog self-test: ok")


def split_key(key):
    """An item and, after a dot, one of its parts: "0226" or "226.3"."""
    item, _, part = key.partition(".")
    if part and not part.isdigit():
        raise SystemExit(f"{key!r}: a part is named by its number, as 226.3")
    return item, int(part) if part else None


def claim(folder, key, session, date):
    key, number = split_key(key)
    item = find(folder, key)
    if number is not None:
        part = item.part(number)
        if part.kind == "done":
            print(f"{item.path.name}, part {number}, is done; nothing to claim")
            return False
        held = re.match(r"claimed by ([^,]+),", part.status_text or "")
        if held and held.group(1).strip() != session:
            print(f"{item.path.name}, part {number}, is {part.status_text}; a claim by another session is refused")
            return False
        item.set_part_status(number, f"claimed by {session}, {date}")
        print(f"{item.path.name}, part {number}: claimed by {session}, {date}")
        return True
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
    key, number = split_key(key)
    item = find(folder, key)
    text = f"partly done: {remains}" if remains else f"done, {date}"
    if number is not None:
        item.set_part_status(number, text)
        print(f"{item.path.name}, part {number}: {text}")
        return True
    item.set_status(text)
    rewritten = moved(folder, item)
    print(f"{item.path.name}: {item.status_text}" + (f", now in {DONE_DIR}/" if item.kind == "done" else ""))
    for path in rewritten:
        print(f"  rewrote its path in {path}")
    return True


DATE = re.compile(r"\b(\d{1,2} (?:January|February|March|April|May|June|July|August|September|October|November|December) \d{4})\b")
UNCLEAR = "partly done: unclear, needs a look"


def first_line_for(item, part):
    """The status line a part with none is given once (backlog 0228), from what its prose and the item's notes say;
    where they leave it in doubt, that it needs a look, never a guess."""
    said = notes_of(item.body).get(part.number)
    marked = marker_status(part.text)
    # The date: the part's own last one, or, when a note settles it, the notes' (a done note "the same day" is the
    # claim's day).
    notes = [m for m in NOTE.finditer(item.body) if str(part.number) in re.findall(r"\d+", m.group(1))]
    noted = [d for m in notes for d in DATE.findall(item.body[m.start():m.end() + 120])]
    dates = (noted if said else []) or DATE.findall(part.text)
    when = dates[-1] if dates else "date not recorded"
    if said == "done" or marked == "done":
        return f"done, {when}"
    if marked == "part":
        return UNCLEAR
    if said == "claimed" or marked == "claimed":
        who = SESSION.findall(part.text)
        if not who:
            notes = [m for m in NOTE.finditer(item.body) if str(part.number) in re.findall(r"\d+", m.group(1))]
            tail = item.body[notes[-1].end():][:300] if notes else ""
            who = SESSION.findall(tail)
        return f"claimed by {who[-1]}, {when}" if who else UNCLEAR
    if item.kind == "done":
        return "done, with the item"
    if item.kind == "claimed":
        return item.status_text
    return "open"


def convert(folder):
    """Gives every part with no status line one (backlog 0228), and an item `done` whose parts are not all done the
    status `partly done`, naming them. Run once, on 9 October 2026; afterwards every part has a line and this does
    nothing."""
    changed = []
    for item in items(folder):
        missing = [n for n, part in enumerate(item.parts) if part.status_text is None]
        for index in missing:
            item.set_part_status_at(index, first_line_for(item, item.parts[index]))
        left = [part.number for part in item.parts if part.kind != "done"]
        if item.kind == "done" and left:
            item.set_status(f"partly done: parts {', '.join(map(str, left))} (backlog 0228's conversion read them as not done)")
        if item.kind == "open" and any(part.kind in ("claimed", "partly done", "done") for part in item.parts):
            item.set_status(f"partly done: parts {', '.join(map(str, left))} (backlog 0228's conversion read the rest as begun or done)")
        if missing or (item.kind == "partly done" and not left and item.parts):
            changed.append(item)
    return changed


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
                        choices=["list", "summary", "board", "new", "claim", "done", "show", "move", "convert", "tidy"])
    parser.add_argument("args", nargs="*")
    parser.add_argument("--open", action="store_true")
    parser.add_argument("--claimed", action="store_true")
    parser.add_argument("--done", action="store_true")
    parser.add_argument("--partly", action="store_true")
    parser.add_argument("--by", help="the session making a claim")
    parser.add_argument("--date", default=today())
    parser.add_argument("--remains", help="with done: what remains, making the item partly done")
    parser.add_argument("--html", help="with board: write the board as one HTML page to this path")
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
        for w in warnings(FOLDER):
            print(f"warning: {w}")
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
    if a.command == "board":
        now = datetime.date.today()
        if a.html:
            write_text(Path(a.html), board_html(items(), now))
            print(f"wrote {a.html}")
        else:
            print(board_markdown(items(), now), end="")
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
    if a.command == "tidy":
        for item, rewritten in tidy(FOLDER):
            print(f"{item.path.relative_to(ROOT)}" + (f" ({len(rewritten)} references rewritten)" if rewritten else ""))
        return 0
    if a.command == "convert":
        for item in convert(FOLDER):
            print(f"{item.path.name}: {len(item.parts)} parts, {item.status_text}")
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
