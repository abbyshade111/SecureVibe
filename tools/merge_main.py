#!/usr/bin/env python3
"""Brings `main` into the current branch, and settles the one kind of conflict every session resolved by hand.

Until 8 October 2026 every claim and every done note was an addition to docs/BACKLOG.md, and any two open pull
requests added at the same place, so a branch an hour old conflicted with `main` there; each such conflict was
resolved the same way, by hand, at the cost of a CI round: both sides kept, `main`'s first. ADR-060 and ADR-061 then
made each design entry and each backlog item a file, and what is left for this script is any Markdown file where
both sides still add at the same place (a line in docs/adr/README.md's index, for one). It does that, and nothing
else:

- It merges `origin/main` into the current branch (fetching first), with Git asked to show the merge base in each
  conflict (`diff3`), and leaves the merge for you to commit, so the commit carries your message and trailers.
- A conflict in a Markdown file whose every block has an empty base, which is to say both sides added text at the
  same place and neither changed what was there, is settled by keeping `main`'s text and then the branch's, with a
  blank line between them when the branch's text starts a list item or a heading. The file is staged.
- Any other conflict, in any file, is left exactly as Git left it and named, and the script fails, so a person
  resolves it; the settled files stay staged.

It refuses to start on `main`, or with uncommitted changes, since a merge on top of either is hard to undo.

    python3 tools/merge_main.py                 # then: git commit
    python3 tools/merge_main.py --from REF      # another branch than origin/main (the self-test uses a local one)
    python3 tools/merge_main.py --no-fetch
    python3 tools/merge_main.py --self-test
"""

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def write_text(path, text):
    """Writes `text` as UTF-8 with Unix line endings on every system. Path.write_text uses the
    system's own encoding and, on Windows, CRLF, which would make a generated file differ from the
    one committed (backlog 0120)."""
    with open(path, "w", encoding="utf-8", newline="\n") as out:
        out.write(text)

BLOCK = re.compile(
    r"^<<<<<<< [^\n]*\n(?P<ours>.*?)^\|\|\|\|\|\|\| [^\n]*\n(?P<base>.*?)^=======\n(?P<theirs>.*?)^>>>>>>> [^\n]*\n",
    re.S | re.M,
)
MARKER = re.compile(r"^(<<<<<<< |\|\|\|\|\|\|\| |=======$|>>>>>>> )", re.M)


def git(repo, *args, check=True):
    out = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, encoding="utf-8")
    if check and out.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed:\n{out.stdout}{out.stderr}")
    return out


def joined(theirs, ours):
    """`main`'s text, then the branch's, with a blank line between when the branch's starts an item or a heading
    and `main`'s does not end in one."""
    if not theirs.strip():
        return ours
    if not ours.strip():
        return theirs
    starts_block = ours.lstrip("\n")[:1] in "-#" or ours.lstrip("\n").startswith("* ")
    gap = "\n" if starts_block and not theirs.endswith("\n\n") else ""
    return theirs + gap + ours


def settle(text):
    """The text with every both-added block settled, or None when any block has a non-empty base (one side
    changed lines the other side also changed) or the file has no block at all."""
    blocks = list(BLOCK.finditer(text))
    if not blocks or any(m.group("base").strip() for m in blocks):
        return None
    settled = BLOCK.sub(lambda m: joined(m.group("theirs"), m.group("ours")), text)
    return None if MARKER.search(settled) else settled


def merge_main(repo, ref="origin/main", fetch=True):
    """Merges `ref` into the current branch of `repo`. Returns (settled, left): the Markdown files settled and
    staged, and the conflicted files left for a person. Raises SystemExit on a refusal."""
    repo = Path(repo)
    branch = git(repo, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    if branch in ("main", "HEAD"):
        raise SystemExit(f"on {branch}: check out the branch to bring main into first")
    if git(repo, "status", "--porcelain").stdout.strip():
        raise SystemExit("uncommitted changes: commit or stash them first, so the merge can be undone cleanly")
    if fetch:
        remote, _, name = ref.partition("/")
        git(repo, "fetch", remote, name)
    merged = git(repo, "-c", "merge.conflictStyle=diff3", "merge", "--no-commit", "--no-ff", ref, check=False)
    if merged.returncode == 0:
        if "Already up to date" in merged.stdout:
            print(f"{branch} already holds {ref}: nothing to merge")
            return [], []
        print(f"{ref} merged into {branch} with no conflict: staged, not committed")
        return [], []
    conflicted = [p for p in git(repo, "diff", "--name-only", "--diff-filter=U").stdout.split("\n") if p]
    settled, left = [], []
    for name in conflicted:
        path = repo / name
        text = settle(path.read_text(encoding="utf-8")) if name.endswith(".md") else None
        if text is None:
            left.append(name)
            continue
        write_text(path, text)
        git(repo, "add", name)
        settled.append(name)
    for name in settled:
        print(f"settled {name}: both sides kept, {ref}'s first (staged)")
    for name in left:
        print(f"left for you {name}: a conflict this script does not settle")
    return settled, left


def self_test():
    """A repository with a base, a branch, and a `main` that moved: a both-added backlog conflict is settled with
    `main`'s text first; a conflict where both sides changed the same line is left, as is one in a Rust file."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        git(repo, "init", "-q", "-b", "main")
        git(repo, "config", "user.email", "test@example.invalid")
        git(repo, "config", "user.name", "merge_main self-test")
        docs = repo / "docs"
        docs.mkdir()
        backlog = docs / "BACKLOG.md"
        write_text(backlog, "## Next\n\n- **Item A.** Open.\n\n- **Item B.** Open.\n\n## Done\n")
        write_text((repo / "notes.md"), "one\ntwo\nthree\n")
        write_text((repo / "lib.rs"), "fn a() {}\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "base")

        git(repo, "checkout", "-q", "-b", "work")
        write_text(backlog, backlog.read_text(encoding="utf-8").replace("## Done", "- **Item D, the branch's claim.** Open.\n\n## Done"))
        git(repo, "commit", "-q", "-am", "the branch claims D")
        git(repo, "checkout", "-q", "main")
        write_text(backlog, backlog.read_text(encoding="utf-8").replace("## Done", "- **Item C, another session's claim.** Open.\n\n## Done"))
        git(repo, "commit", "-q", "-am", "main claims C")
        git(repo, "checkout", "-q", "work")

        settled, left = merge_main(repo, ref="main", fetch=False)
        assert settled == ["docs/BACKLOG.md"] and left == [], (settled, left)
        text = backlog.read_text(encoding="utf-8")
        assert "<<<<<<<" not in text, text
        assert text.index("Item C") < text.index("Item D"), text
        assert "Item A" in text and "Item B" in text and text.count("## Done") == 1, text
        assert "Open.\n\n- **Item D" in text, text
        staged = git(repo, "diff", "--cached", "--name-only").stdout.split()
        assert "docs/BACKLOG.md" in staged, staged
        git(repo, "commit", "-q", "--no-edit")

        # Both sides changed the same line of a Markdown file, and both added to a Rust file: left for a person.
        write_text((repo / "notes.md"), "one\nTWO on the branch\nthree\n")
        write_text((repo / "lib.rs"), "fn a() {}\nfn branch() {}\n")
        git(repo, "commit", "-q", "-am", "the branch edits")
        git(repo, "checkout", "-q", "main")
        write_text((repo / "notes.md"), "one\nTWO on main\nthree\n")
        write_text((repo / "lib.rs"), "fn a() {}\nfn main_side() {}\n")
        git(repo, "commit", "-q", "-am", "main edits")
        git(repo, "checkout", "-q", "work")
        settled, left = merge_main(repo, ref="main", fetch=False)
        assert settled == [] and sorted(left) == ["lib.rs", "notes.md"], (settled, left)
        assert "<<<<<<<" in (repo / "notes.md").read_text(encoding="utf-8")
        assert "<<<<<<<" in (repo / "lib.rs").read_text(encoding="utf-8")
        git(repo, "merge", "--abort")

        # Refusals: uncommitted changes, and being on main.
        write_text((repo / "notes.md"), "dirty\n")
        try:
            merge_main(repo, ref="main", fetch=False)
            raise AssertionError("merged over uncommitted changes")
        except SystemExit as e:
            assert "uncommitted" in str(e), e
        git(repo, "checkout", "-q", "--", "notes.md")
        git(repo, "checkout", "-q", "main")
        try:
            merge_main(repo, ref="work", fetch=False)
            raise AssertionError("merged on main")
        except SystemExit as e:
            assert "on main" in str(e), e

    # The joining rule on its own.
    assert joined("- a\n", "- b\n") == "- a\n\n- b\n"
    assert joined("- a\n\n", "- b\n") == "- a\n\n- b\n"
    assert joined("  text\n", "  more\n") == "  text\n  more\n"
    assert settle("no conflict here\n") is None
    assert settle("<<<<<<< HEAD\nx\n||||||| base\nold\n=======\ny\n>>>>>>> main\n") is None
    print("merge_main self-test: ok")


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--from", dest="ref", default="origin/main", help="the branch to bring in (origin/main)")
    parser.add_argument("--no-fetch", action="store_true", help="do not fetch first")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    repo = git(Path.cwd(), "rev-parse", "--show-toplevel").stdout.strip()
    settled, left = merge_main(repo, ref=args.ref, fetch=not args.no_fetch)
    if left:
        print(f"{len(left)} file(s) left: resolve by hand, `git add` each, then `git commit`", file=sys.stderr)
        return 1
    if git(repo, "rev-parse", "-q", "--verify", "MERGE_HEAD", check=False).returncode == 0:
        print("now: git commit  (the merge message is ready; add your trailers)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
