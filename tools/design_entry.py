#!/usr/bin/env python3
"""The design record, one file per entry (docs/adr/ADR-060.md).

Each design entry is a file of its own under docs/design/, named by a four-digit number and its title made into a file
name (`0297-a-failed-sign-in-that-tells-which-accounts-exist.md`), whose first line is `# ` and the title. The title is
what the code and the documents cite (`DESIGN, "Section title"`), so it is never changed once written. The numbers
keep the order the entries were written in; two pull requests open at once may take the same number, which harms
nothing. docs/DESIGN.md is the introduction only, and holds no entry and no list of entries: a list every new entry
adds a line to would make two pull requests collide on it, which is what this layout is for.

    python3 tools/design_entry.py new "A title (8 October 2026)"
        writes a new entry, numbered one past the highest, with the title and nothing else, and prints its path
    python3 tools/design_entry.py move FILE
        makes an entry of each `## ` section of FILE, a design record in the old single-file layout, whose title is not
        an entry yet; a section whose title is an entry already and whose text differs from it is named and left for a
        person, and the script fails. Used once for the split, and by a branch written before it (see below)
    python3 tools/design_entry.py list
        prints the entries in order, number and title
    python3 tools/design_entry.py --check
        fails when docs/DESIGN.md holds a section, or an entry is misnamed, has no title, or shares its title
    python3 tools/design_entry.py --self-test

A branch that added a section to the old docs/DESIGN.md conflicts there once it merges `main`. To mend it:

    git show HEAD:docs/DESIGN.md > /tmp/old-design.md      # the branch's own copy, with its new sections
    git checkout MERGE_HEAD -- docs/DESIGN.md              # main's introduction
    python3 tools/design_entry.py move /tmp/old-design.md  # the branch's sections, as entries
"""

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
NAME = re.compile(r"^(\d{4})-[a-z0-9]+(?:-[a-z0-9]+)*\.md$")


def slug(title):
    """A title made into a file name: lowercase letters and digits, joined by hyphens, whole words up to 60
    characters (the first word cut at 60 when it alone is longer)."""
    words = [w for w in re.split(r"[^a-z0-9]+", title.lower()) if w]
    name = ""
    for word in words:
        if name and len(name) + 1 + len(word) > 60:
            break
        name = f"{name}-{word}" if name else word[:60]
    return name or "entry"


def sections(text):
    """The `## ` sections of a design record in the old layout, in order: (title, body), the body without its heading.
    A `## ` line inside a fenced code block is not a heading."""
    out, fence, title, body = [], False, None, []
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            fence = not fence
        if not fence and line.startswith("## "):
            if title is not None:
                out.append((title, "\n".join(body)))
            title, body = line[3:].strip(), []
        elif title is not None:
            body.append(line)
    if title is not None:
        out.append((title, "\n".join(body)))
    return out


def entries(folder):
    """The entries in a folder, in order: (number, path, title)."""
    out = []
    for path in sorted(folder.glob("*.md")):
        m = NAME.match(path.name)
        first = path.read_text(encoding="utf-8").split("\n", 1)[0]
        title = first[2:].strip() if first.startswith("# ") else None
        out.append((int(m.group(1)) if m else -1, path, title))
    return out


def text_of(title, body):
    """An entry's text: its title as the page's heading, and the body as it was."""
    return f"# {title}\n{body.rstrip()}\n"


def write(folder, number, title, body):
    path = folder / f"{number:04d}-{slug(title)}.md"
    write_text(path, text_of(title, body))
    return path


def move(source, folder):
    """Makes an entry of each section of `source` not yet an entry. Returns (written, differing): the paths written,
    and the titles already entries whose text in `source` differs."""
    folder.mkdir(parents=True, exist_ok=True)
    known = {title: path for _, path, title in entries(folder) if title}
    number = max((n for n, _, _ in entries(folder)), default=0)
    written, differing = [], []
    for title, body in sections(source.read_text(encoding="utf-8")):
        if title in known:
            if known[title].read_text(encoding="utf-8") != text_of(title, body):
                differing.append((title, known[title]))
            continue
        number += 1
        path = write(folder, number, title, body)
        known[title] = path
        written.append(path)
    return written, differing


def problems(design, folder):
    """What is wrong with the layout: a section left in DESIGN.md, a misnamed or untitled entry, a shared title."""
    out = []
    for title, _ in sections(design.read_text(encoding="utf-8")):
        out.append(f"{design.name} holds a section, \"{title}\": write it as an entry of its own "
                   f"(python3 tools/design_entry.py new \"...\"), or move it (python3 tools/design_entry.py move FILE)")
    seen = {}
    for number, path, title in entries(folder):
        if number < 0:
            out.append(f"{path.name} is not named NNNN-title.md")
        if not title:
            out.append(f"{path.name} does not open with `# ` and its title")
        elif title in seen:
            out.append(f"{path.name} and {seen[title].name} share the title \"{title}\", which the documents cite by")
        else:
            seen[title] = path
    return out


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        folder = tmp / "design"
        old = tmp / "OLD.md"
        write_text(old, "# Intro\n\nopening\n\n## First (1 Oct)\n\none\n\n```\n## not a heading\n```\n\n"
                       "## Second\n\ntwo\n")
        written, differing = move(old, folder)
        names = [p.name for p in written]
        assert names == ["0001-first-1-oct.md", "0002-second.md"], names
        assert differing == []
        first = (folder / "0001-first-1-oct.md").read_text(encoding="utf-8")
        assert first.startswith("# First (1 Oct)\n") and "## not a heading" in first, first
        # Moving the same file again writes nothing; a section edited since is named, not overwritten.
        assert move(old, folder) == ([], [])
        write_text(old, old.read_text(encoding="utf-8").replace("two", "two, and a later note")
                       + "\n## Third\n\nthree\n")
        written, differing = move(old, folder)
        assert [p.name for p in written] == ["0003-third.md"], written
        assert [t for t, _ in differing] == ["Second"], differing
        assert "later note" not in (folder / "0002-second.md").read_text(encoding="utf-8")
        # The checks: an introduction with no section and well-named entries pass; each fault is named.
        design = tmp / "DESIGN.md"
        write_text(design, "# Intro\n\nno sections here\n```\n## inside a fence\n```\n")
        assert problems(design, folder) == [], problems(design, folder)
        write_text(design, "# Intro\n\n## Appended\n\ntext\n")
        assert any("Appended" in p for p in problems(design, folder))
        write_text(design, "# Intro\n")
        write_text((folder / "notes.md"), "# Notes\n")
        write_text((folder / "0004-untitled.md"), "no heading\n")
        write_text((folder / "0005-second-again.md"), "# Second\n")
        found = problems(design, folder)
        assert any("notes.md is not named" in p for p in found), found
        assert any("0004-untitled.md does not open" in p for p in found), found
        assert any("share the title" in p for p in found), found
        assert slug("A sign-in token signed with a placeholder secret (8 October 2026)") == \
            "a-sign-in-token-signed-with-a-placeholder-secret-8-october"
        assert slug("`sv` — ünïcode!") == "sv-n-code"
    print("design_entry self-test: ok")


def main(argv):
    design, folder = ROOT / "docs" / "DESIGN.md", ROOT / "docs" / "design"
    if argv[:1] == ["--self-test"]:
        self_test()
        return 0
    if argv[:1] == ["--check"]:
        found = problems(design, folder)
        for p in found:
            print(p)
        return 1 if found else 0
    if argv[:1] == ["list"]:
        for number, _, title in entries(folder):
            print(f"{number:04d}  {title}")
        return 0
    if len(argv) == 2 and argv[0] == "new":
        number = max((n for n, _, _ in entries(folder)), default=0) + 1
        title = argv[1].strip()
        if any(t == title for _, _, t in entries(folder)):
            print(f"an entry is already titled \"{title}\"")
            return 1
        folder.mkdir(parents=True, exist_ok=True)
        print(write(folder, number, title, "").relative_to(ROOT))
        return 0
    if len(argv) == 2 and argv[0] == "move":
        written, differing = move(Path(argv[1]), folder)
        for path in written:
            print(f"wrote {path.relative_to(ROOT)}")
        for title, path in differing:
            print(f"\"{title}\" is already {path.relative_to(ROOT)}, and its text differs: "
                  f"carry the change into that file by hand")
        return 1 if differing else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
