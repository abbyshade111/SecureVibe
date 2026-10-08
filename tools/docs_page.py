#!/usr/bin/env python3
"""Writes a private set of pages, for the owner's browser, holding all of sv's documentation.

    python3 tools/docs_page.py                 # writes ~/securevibe-docs/, then open index.html
    python3 tools/docs_page.py --out DIR       # writes DIR instead
    python3 tools/docs_page.py --self-test     # checks the Markdown reader against small samples

The owner asked for it on 8 October 2026 ("a private page (just for me on this computer) that makes it easy for me
to navigate through all the documentation and view it"), and chose its home folder and to leave the paper's drafts
out (ADR-058). What it holds: the documents git tracks in this repository, by section, each with its own headings as a
table of contents, the links between them working, and a search box. What it leaves out: `docs/paper/`, the example
apps, and anything git does not track (so no `.env`, nothing in `target/`). It fetches nothing from the internet, and
writes only into its own folder, which it marks as its own; a folder it did not make is left alone. Run it again
after a pull to bring the pages up to date.

Markdown is read by the small reader below (Python's standard library has none, and no dependency was wanted):
headings, paragraphs, lists, tables, code, block quotes, rules, links, emphasis. Anything written as HTML in a
document is shown as text, never run.
"""

import argparse
import html
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARK = ".securevibe-docs"
LEFT_OUT = ("docs/paper/", "examples/", "target/", "crates/", "v1/")

# The sections the index lists, in order: (title, test on the document's path).
SECTIONS = [
    ("Start here", lambda p: p in ("README.md", "docs/GETTING-STARTED.md")),
    ("Decision records", lambda p: p.startswith("docs/adr/")),
    ("Prompts", lambda p: p.startswith("docs/prompts/") or p == "docs/PROMPTS.md"),
    # The backlog, one item per file (docs/adr/ADR-061.md), and the design record, one entry per file (ADR-060),
    # apart from the long documents beside them.
    ("Backlog, item by item", lambda p: p.startswith("docs/backlog/")),
    ("Design record, entry by entry", lambda p: p.startswith("docs/design/")),
    ("Design, plans, and coverage", lambda p: p.startswith("docs/")),
    ("Notes for AI coding sessions and data", lambda p: True),
]


# ---------------------------------------------------------------------------------------------------------------
# Markdown, as far as these documents use it.

def slug(text, seen):
    """An id for a heading, unique on its page."""
    base = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "section"
    name, n = base, 2
    while name in seen:
        name, n = f"{base}-{n}", n + 1
    seen.add(name)
    return name


def link_target(target, here):
    """A link in a document, pointed at the page this tool writes for it when it is another document."""
    if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I) or target.startswith("#"):
        return target
    path, _, anchor = target.partition("#")
    if path.endswith(".md"):
        resolved = os.path.normpath(os.path.join(os.path.dirname(here), path))
        rel = os.path.relpath(resolved[:-3] + ".html", os.path.dirname(here) or ".")
        return rel + ("#" + anchor if anchor else "")
    return target


def inline(text, here):
    """Escapes a line and turns code, links, bold, and italics into markup. Code is set aside first, so
    nothing inside it is read as emphasis, and bold can run across it."""
    codes = []

    def hold(m):
        codes.append("<code>" + html.escape(m.group(1), quote=False) + "</code>")
        return f"\x00{len(codes) - 1}\x00"

    text = spans(re.sub(r"`([^`]+)`", hold, text.replace("\x00", "")), here)
    return re.sub(r"\x00(\d+)\x00", lambda m: codes[int(m.group(1))], text)


def spans(text, here):
    text = html.escape(text, quote=False)

    def a(m):
        href = html.escape(link_target(html.unescape(m.group(2)), here), quote=True)
        return f'<a href="{href}">{m.group(1)}</a>'

    text = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", a, text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<em>\1</em>", text)
    text = re.sub(r"(?<![\w_])_(?!\s)(.+?)(?<!\s)_(?![\w_])", r"<em>\1</em>", text)
    return text


def render(md, here):
    """Markdown to HTML, and the page's headings as (level, id, text) for its table of contents."""
    lines = md.replace("\t", "    ").split("\n")
    out, headings, seen = [], [], set()
    i = 0
    para = []

    def flush():
        if para:
            out.append("<p>" + inline(" ".join(para), here) + "</p>")
            para.clear()

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith("```"):
            flush()
            code = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code.append(lines[i])
                i += 1
            out.append("<pre><code>" + html.escape("\n".join(code), quote=False) + "</code></pre>")
            i += 1
            continue
        m = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", line)
        if m:
            flush()
            level, text = len(m.group(1)), m.group(2)
            ident = slug(text, seen)
            headings.append((level, ident, text))
            out.append(f'<h{level} id="{ident}">{inline(text, here)}</h{level}>')
            i += 1
            continue
        if re.match(r"^\s*([-*_])(\s*\1){2,}\s*$", line):
            flush()
            out.append("<hr>")
            i += 1
            continue
        if stripped.startswith("|") and i + 1 < len(lines) and re.match(r"^\s*\|?\s*:?-+", lines[i + 1]):
            flush()
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(lines[i])
                i += 1
            cells = lambda r: [c.strip() for c in r.strip().strip("|").split("|")]
            table = ['<div class="table"><table><thead><tr>']
            table += [f"<th>{inline(c, here)}</th>" for c in cells(rows[0])]
            table.append("</tr></thead><tbody>")
            for r in rows[2:]:
                table.append("<tr>" + "".join(f"<td>{inline(c, here)}</td>" for c in cells(r)) + "</tr>")
            table.append("</tbody></table></div>")
            out.append("".join(table))
            continue
        if stripped.startswith(">"):
            flush()
            quote = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                quote.append(re.sub(r"^\s*>\s?", "", lines[i]))
                i += 1
            inner, _ = render("\n".join(quote), here)
            out.append("<blockquote>" + inner + "</blockquote>")
            continue
        if re.match(r"^\s*([-*+]|\d+[.)])\s+", line):
            flush()
            block = []
            while i < len(lines) and (
                re.match(r"^\s*([-*+]|\d+[.)])\s+", lines[i])
                or (lines[i].startswith("  ") and lines[i].strip())
            ):
                block.append(lines[i])
                i += 1
            out.append(render_list(block, here))
            continue
        if not stripped:
            flush()
        else:
            para.append(stripped)
        i += 1
    flush()
    return "\n".join(out), headings


def render_list(block, here):
    """A list, nested by indentation; a line that is not an item continues the item above it."""
    indent = len(block[0]) - len(block[0].lstrip())
    ordered = bool(re.match(r"^\s*\d+[.)]\s", block[0]))
    items, current = [], None
    for line in block:
        own = len(line) - len(line.lstrip())
        m = re.match(r"^\s*([-*+]|\d+[.)])\s+(.*)$", line)
        if m and own <= indent + 1:
            current = [m.group(2), []]
            items.append(current)
        elif current is not None:
            current[1].append(line)
    tag = "ol" if ordered else "ul"
    out = [f"<{tag}>"]
    for text, rest in items:
        body = inline(text, here)
        sub = [l for l in rest if re.match(r"^\s*([-*+]|\d+[.)])\s+", l)]
        if sub:
            start = rest.index(sub[0])
            body += " " + inline(" ".join(l.strip() for l in rest[:start]), here) if start else ""
            body += render_list(rest[start:], here)
        elif rest:
            body += " " + inline(" ".join(l.strip() for l in rest), here)
        out.append(f"<li>{body}</li>")
    out.append(f"</{tag}>")
    return "".join(out)


# ---------------------------------------------------------------------------------------------------------------
# Which documents, and the pages.

def documents():
    """The Markdown files git tracks, less what is left out on purpose."""
    try:
        listed = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z", "--", "*.md"],
            capture_output=True, check=True,
        ).stdout.decode().split("\0")
    except (OSError, subprocess.CalledProcessError):
        sys.exit("This needs git and the SecureVibe repository: run it from inside your copy of SecureVibe.")
    return sorted(p for p in listed if p and not p.startswith(LEFT_OUT) and (ROOT / p).is_file())


def section(path):
    return next(title for title, test in SECTIONS if test(path))


STYLE = """
:root { color-scheme: light dark; --bg: #f7f8fa; --panel: #fff; --fg: #1b1f27; --dim: #5b6372; --edge: #dde1e8; --accent: #2f5bd3; }
@media (prefers-color-scheme: dark) { :root { --bg: #12151b; --panel: #1a1e26; --fg: #e6e9ef; --dim: #9aa3b2; --edge: #2c323d; --accent: #8aa8ff; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg); font: 16px/1.6 system-ui, sans-serif; }
a { color: var(--accent); }
.layout { display: grid; grid-template-columns: 17rem minmax(0, 1fr); min-height: 100vh; }
nav.site { border-right: 1px solid var(--edge); padding: 1rem; position: sticky; top: 0; height: 100vh; overflow-y: auto; font-size: .9rem; background: var(--panel); }
nav.site h2 { font-size: .75rem; text-transform: uppercase; letter-spacing: .06em; color: var(--dim); margin: 1.2rem 0 .3rem; }
nav.site ul { list-style: none; margin: 0; padding: 0; }
nav.site li { margin: .1rem 0; }
nav.site a { text-decoration: none; color: var(--fg); }
nav.site a.here { color: var(--accent); font-weight: 600; }
main { padding: 1.5rem clamp(1rem, 4vw, 3rem); max-width: 60rem; }
.toc { border: 1px solid var(--edge); border-radius: 6px; padding: .6rem 1rem; background: var(--panel); font-size: .9rem; margin-bottom: 1.5rem; }
.toc ul { margin: .2rem 0; padding-left: 1.1rem; }
pre { background: var(--panel); border: 1px solid var(--edge); border-radius: 6px; padding: .8rem; overflow-x: auto; }
code { font-family: ui-monospace, monospace; font-size: .9em; }
.table { overflow-x: auto; }
table { border-collapse: collapse; margin: 1rem 0; }
th, td { border: 1px solid var(--edge); padding: .35rem .6rem; text-align: left; vertical-align: top; }
blockquote { margin: 1rem 0; padding-left: 1rem; border-left: 3px solid var(--edge); color: var(--dim); }
.note { color: var(--dim); font-size: .9rem; }
input[type=search] { width: 100%; padding: .5rem .7rem; font: inherit; border: 1px solid var(--edge); border-radius: 6px; background: var(--panel); color: var(--fg); }
#results li { margin: .5rem 0; }
#results .where { color: var(--dim); font-size: .85rem; }
@media (max-width: 760px) { .layout { grid-template-columns: 1fr; } nav.site { position: static; height: auto; border-right: 0; border-top: 1px solid var(--edge); order: 2; } }
"""


def page(title, nav, body, depth):
    up = "../" * depth
    return (
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"<title>{html.escape(title)} · SecureVibe docs</title>\n<style>{STYLE}</style>\n</head>\n<body>\n"
        f"<div class=\"layout\">\n<nav class=\"site\"><a href=\"{up}index.html\"><strong>SecureVibe docs</strong></a>"
        f"{nav}</nav>\n<main>\n{body}\n</main>\n</div>\n</body>\n</html>\n"
    )


def nav_for(docs, titles, here):
    """Every document, by section, linked relative to the page `here`."""
    out = []
    for name, _ in SECTIONS:
        mine = [d for d in docs if section(d) == name]
        if not mine:
            continue
        out.append(f"<h2>{html.escape(name)}</h2><ul>")
        for d in mine:
            href = os.path.relpath(d[:-3] + ".html", os.path.dirname(here) or ".")
            cls = ' class="here"' if d == here else ""
            out.append(f'<li><a{cls} href="{html.escape(href)}">{html.escape(titles[d])}</a></li>')
        out.append("</ul>")
    return "".join(out)


SEARCH = """
<script>
// Searches the headings and text embedded in this page; nothing is fetched.
const all = JSON.parse(document.getElementById('index').textContent);
const box = document.getElementById('q'), list = document.getElementById('results');
box.addEventListener('input', () => {
  const words = box.value.toLowerCase().split(/\\s+/).filter(Boolean);
  list.replaceChildren();
  if (!words.length) return;
  const hits = all.filter(s => words.every(w => s.l.includes(w))).slice(0, 60);
  for (const s of hits) {
    const li = document.createElement('li'), a = document.createElement('a'), where = document.createElement('div');
    a.href = s.u; a.textContent = s.h;
    const at = s.t.toLowerCase().indexOf(words[0]);
    where.className = 'where';
    where.textContent = s.d + (at >= 0 ? ' · …' + s.t.slice(Math.max(0, at - 60), at + 120) + '…' : '');
    li.append(a, where); list.append(li);
  }
  if (!hits.length) list.textContent = 'Nothing found.';
});
</script>
"""


def build(out):
    out = Path(out).expanduser()
    if out.is_symlink():
        sys.exit(f"{out} is a link; nothing is written through it.")
    if out.exists() and not (out / MARK).is_file():
        if any(out.iterdir()):
            sys.exit(f"{out} is already there and was not made by this tool, so it is left as it is. Choose --out.")
    if out.resolve().is_relative_to(ROOT):
        sys.exit(f"{out} is inside the repository; the pages are kept outside it, so they are never committed.")
    out.mkdir(parents=True, exist_ok=True)
    (out / MARK).write_text("Made by tools/docs_page.py. Run it again to bring these pages up to date.\n")

    docs = documents()
    texts = {d: (ROOT / d).read_text(encoding="utf-8", errors="replace") for d in docs}
    titles = {}
    for d in docs:
        first = re.search(r"^#\s+(.+?)\s*$", texts[d], re.M)
        titles[d] = first.group(1).replace("`", "") if first else d

    written, index = set(), []
    for d in docs:
        body, headings = render(texts[d], d)
        toc = [h for h in headings if h[0] in (2, 3)]
        top = ""
        if len(toc) > 2:
            top = "<div class=\"toc\"><strong>On this page</strong><ul>" + "".join(
                f'<li style="margin-left:{(lvl - 2) * 1.1}rem"><a href="#{i}">{inline(t, d)}</a></li>'
                for lvl, i, t in toc
            ) + "</ul></div>"
        source = f'<p class="note">From <code>{html.escape(d)}</code> in the repository.</p>'
        lead = source + top
        body = re.sub(r"(</h1>)", lambda m: m.group(1) + lead, body, count=1) if "</h1>" in body else lead + body
        target = out / (d[:-3] + ".html")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(page(titles[d], nav_for(docs, titles, d), body, d.count("/")), encoding="utf-8")
        written.add(target.resolve())
        # The search index: each section of each document, by its heading.
        for part in re.split(r"(?m)^(?=#{1,4}\s)", texts[d]):
            h = re.match(r"^#{1,4}\s+(.+)", part)
            heading = h.group(1).strip() if h else titles[d]
            ident = next((i for _, i, t in headings if t == heading), "")
            text = re.sub(r"\s+", " ", re.sub(r"[`*_#>|]", "", part)).strip()
            index.append({"d": titles[d], "h": heading.replace("`", ""), "u": d[:-3] + ".html" + (f"#{ident}" if ident else ""),
                          "t": text[:3000], "l": text.lower()[:3000] + " " + heading.lower()})

    listing = []
    for name, _ in SECTIONS:
        mine = [d for d in docs if section(d) == name]
        if mine:
            listing.append(f"<h2>{html.escape(name)}</h2><ul>" + "".join(
                f'<li><a href="{html.escape(d[:-3])}.html">{html.escape(titles[d])}</a> '
                f'<span class="note">{html.escape(d)}</span></li>' for d in mine) + "</ul>")
    # Not one `<` inside the script element: the documents quote `<script` and `<!--`, which would end it.
    data = json.dumps(index).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    body = (
        "<h1>SecureVibe's documentation</h1>\n"
        f"<p class=\"note\">{len(docs)} documents from your copy of the repository, written by "
        "<code>tools/docs_page.py</code> for this computer only. The paper's drafts are left out. Run it again after a "
        "pull to bring these pages up to date.</p>\n"
        "<p><input type=\"search\" id=\"q\" placeholder=\"Search every document\" aria-label=\"Search every document\"></p>\n"
        "<ul id=\"results\"></ul>\n" + "".join(listing)
        + f'\n<script type="application/json" id="index">{data}</script>\n' + SEARCH
    )
    (out / "index.html").write_text(page("SecureVibe docs", nav_for(docs, titles, "index.md"), body, 0), encoding="utf-8")
    written.add((out / "index.html").resolve())

    # Pages of documents that are gone, in its own folder only.
    for old in out.rglob("*.html"):
        if old.resolve() not in written:
            old.unlink()
    print(f"Wrote {len(docs)} documents to {out}. Open {out / 'index.html'} in a browser.")


# ---------------------------------------------------------------------------------------------------------------

def self_test():
    body, heads = render("# Title\n\nSome *text* and `<b>` with [a link](OTHER.md#part).\n\n"
                         "## Two\n\n- one\n  - nested\n- two\n\n| a | b |\n|---|---|\n| 1 | <i>2</i> |\n\n"
                         "```\n<script>x</script>\n```\n\n> quoted\n", "docs/X.md")
    checks = [
        ('<h1 id="title">Title</h1>' in body, "a heading with an id"),
        ("<em>text</em>" in body, "italics"),
        ("<code>&lt;b&gt;</code>" in body, "code is escaped"),
        ('href="OTHER.html#part"' in body, "a link to another document points at its page"),
        ("<ul><li>one<ul><li>nested</li></ul></li><li>two</li></ul>" in body, "a nested list"),
        ("<td>&lt;i&gt;2&lt;/i&gt;</td>" in body, "HTML in a table is text"),
        ("&lt;script&gt;x&lt;/script&gt;" in body and "<script>" not in body, "HTML in code is text"),
        ("<blockquote><p>quoted</p></blockquote>" in body, "a block quote"),
        (inline("**`a` b**", "X.md") == "<strong><code>a</code> b</strong>", "bold across code"),
        (inline("`**x**`", "X.md") == "<code>**x**</code>", "nothing in code is emphasis"),
        ([h[1] for h in heads] == ["title", "two"], "the table of contents"),
        (link_target("https://example.org/a.md", "docs/X.md") == "https://example.org/a.md", "outside links kept"),
        (link_target("adr/ADR-001.md", "docs/X.md") == "adr/ADR-001.html", "a relative link"),
        (link_target("../../README.md", "docs/adr/A.md") == "../../README.html", "a link up two folders"),
        (all(not d.startswith("docs/paper/") for d in documents()), "the paper's drafts are left out"),
    ]
    failed = [what for ok, what in checks if not ok]
    for what in failed:
        print("FAILED:", what)
    print(f"{len(checks) - len(failed)} of {len(checks)} checks passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", default="~/securevibe-docs", help="where to write the pages (default ~/securevibe-docs)")
    parser.add_argument("--self-test", action="store_true", help="check the Markdown reader and stop")
    args = parser.parse_args()
    sys.exit(self_test() if args.self_test else build(args.out))
