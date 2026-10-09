#!/usr/bin/env python3
"""Writes docs/paper/figure-trials.html: the eleven trials of 5 to 8 October 2026, and every pasted-prompt comparison.

Every comparison is read from the trials' committed results files in docs/prompts/library-trial/. Only the trial
list's dates, sizes and costs are typed here, each taken from that trial's own write-up, which is named beside it.
Run from anywhere; it reads and writes inside the repository only:

    python3 docs/paper/trials/make_figure.py
"""
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TRIAL = ROOT / "docs" / "prompts" / "library-trial"
OUT = ROOT / "docs" / "paper" / "figure-trials.html"

# (name, dates, builds, dollars, the write-up both numbers are from, the question it asked)
TRIALS = [
    ("Loop pilot", "5 Oct", 6, 1.86, "docs/prompts/loop-pilot/README.md",
     "Does a builder use sv's tools when they are attached, and can its app be tested?"),
    ("Loop arms", "5 Oct", 18, 4.78, "docs/prompts/loop-arms/README.md",
     "Which part of the loop does the work: the specification, the check, the plan?"),
    ("Loop at scale", "5–6 Oct", 70, 21.34, "docs/prompts/loop-scale/README.md",
     "The same, five builds a cell, with the specification in every request"),
    ("Prompt library", "6 Oct", 90, 21.12, "docs/prompts/library-trial/README.md",
     "Does pasting a library prompt remove the problem it is for?"),
    ("Delivery test", "6 Oct", 60, 19.36, "docs/prompts/library-trial/delivery.md",
     "Do two new sentences make settings readable, and does sv deliver prompts that work?"),
    ("Prompts at the start", "7 Oct", 40, 18.11, "docs/prompts/library-trial/start.md",
     "Do the shown prompts work given at the start of every build?"),
    ("Revision trial", "7 Oct", 110, 35.28, "docs/prompts/library-trial/revision.md",
     "Do the reviews' revisions keep working, and do five new prompts work?"),
    ("Recipe trial", "7 Oct", 40, 18.09, "docs/prompts/library-trial/recipe.md",
     "A Flask brief that tempts the prompts never fairly tried"),
    ("Three sentences", "7 Oct", 30, 10.59, "docs/prompts/library-trial/sentences.md",
     "Do the three sentences added from the trials work?"),
    ("Haiku 5.5", "8 Oct", 21, 6.16, "docs/prompts/library-trial/haiku55.md",
     "Does Claude Haiku 5.5 build apps that can be tested, where Haiku 4.5 could not? (20 and a smoke build)"),
    ("With and without sv", "8 Oct", 20, 3.57, "docs/prompts/loop-compare/results.md",
     "Does an app built with sv attached have fewer security problems than one built without it? (and 20 tester runs)"),
]


def comparisons():
    """Every pasted-prompt comparison with builds on both sides: (prompt, model, trial, without, with, verdict)."""
    out = []

    def pair(v):
        return (v["without"]["problem"], v["without"]["asked"]), (v["with"]["problem"], v["with"]["asked"])

    for pid, v in json.loads((TRIAL / "verdicts.json").read_text()).items():
        out.append((pid, v["model"], "prompt library", *pair(v), v["verdict"]))
    for name, trial in (("revision-verdicts.json", "revision"), ("recipe-stage2.json", "recipe")):
        for key, v in json.loads((TRIAL / name).read_text()).items():
            pid, model = key.split("@")
            out.append((pid, model, trial, *pair(v), v["verdict"]))
    for key, v in json.loads((TRIAL / "sentences-verdicts.json").read_text()).items():
        pid, model = key.split("@")
        out.append((pid, model, "three sentences", tuple(v["without"]), tuple(v["with"]), v["verdict"]))
    return [c for c in out if c[3][1] and c[4][1]]


def pct(k, n):
    return 100 * k / n


def main():
    rows = comparisons()
    builds = sum(t[2] for t in TRIALS)
    cost = sum(t[3] for t in TRIALS)
    counts = {v: sum(1 for r in rows if r[5] == v) for v in ("shown", "not shown", "no reading")}
    e = html.escape

    trial_rows = "\n".join(
        f"<tr><td>{e(n)}</td><td>{e(d)}</td><td>{b}</td><td>${c:.2f}</td><td class=q>{e(q)}</td>"
        f"<td class=q><code>{e(src)}</code></td></tr>"
        for n, d, b, c, src, q in TRIALS
    )
    dots = []
    for pid, model, trial, (wk, wn), (k, n), verdict in rows:
        a, b = pct(wk, wn), pct(k, n)
        lo, hi = min(a, b), max(a, b)
        cls = verdict.replace(" ", "-")
        dots.append(
            f'<div class=lab>{e(pid)}<small>{e(model.title())} · {e(trial)}</small></div>'
            f'<div class=track title="{e(pid)}, {e(model)}, {e(trial)}: {wk} of {wn} without, {k} of {n} with; {e(verdict)}">'
            f'<span class="bar {cls}" style="left:{lo:.1f}%;width:{hi - lo:.1f}%"></span>'
            f'<span class="dot open" style="left:{a:.1f}%"></span>'
            f'<span class="dot {cls}" style="left:{b:.1f}%"></span></div>'
            f'<div class="ver {cls}">{e(verdict)}</div>'
        )
    table = "\n".join(
        f"<tr><td>{e(pid)}</td><td>{e(model.title())}</td><td>{e(trial)}</td><td>{wk} of {wn}</td>"
        f"<td>{k} of {n}</td><td>{e(verdict)}</td></tr>"
        for pid, model, trial, (wk, wn), (k, n), verdict in rows
    )

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Prompt Trials</title>
<style>
  .viz-root {{
    color-scheme: light;
    --surface-1: #fcfcfb; --surface-2: #f3f2ee;
    --text-primary: #0b0b0b; --text-secondary: #52514e; --text-muted: #77766f;
    --grid: #e3e2dd; --shown: #2a78d6; --not: #eb6834; --none: #a3a29b;
  }}
  @media (prefers-color-scheme: dark) {{
    :root:where(:not([data-theme="light"])) .viz-root {{
      color-scheme: dark;
      --surface-1: #1a1a19; --surface-2: #242320; --text-primary: #fff;
      --text-secondary: #c3c2b7; --text-muted: #96958c; --grid: #35342f;
      --shown: #3987e5; --not: #d95926; --none: #77766f;
    }}
  }}
  :root[data-theme="dark"] .viz-root {{
    color-scheme: dark;
    --surface-1: #1a1a19; --surface-2: #242320; --text-primary: #fff;
    --text-secondary: #c3c2b7; --text-muted: #96958c; --grid: #35342f;
    --shown: #3987e5; --not: #d95926; --none: #77766f;
  }}
  body {{ margin: 0; background: var(--surface-1); }}
  .viz-root {{ background: var(--surface-1); color: var(--text-primary);
    font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    padding: 24px 16px; max-width: 900px; margin: 0 auto; }}
  h1 {{ font-size: 1.25rem; margin: 0 0 4px; }}
  h2 {{ font-size: 1rem; margin: 24px 0 4px; }}
  .sub {{ color: var(--text-secondary); margin: 0 0 14px; font-size: .9rem; }}
  .hero {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 0 0 12px; }}
  .stat {{ background: var(--surface-2); border-radius: 10px; padding: 12px 16px; flex: 1 1 150px; }}
  .stat b {{ display: block; font-size: 1.7rem; line-height: 1.1; }}
  .stat span {{ color: var(--text-secondary); font-size: .82rem; }}
  .legend {{ display: flex; gap: 16px; flex-wrap: wrap; font-size: .8rem; color: var(--text-secondary); margin: 4px 0 6px; }}
  .key {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 5px; vertical-align: -1px; }}
  .key.open {{ box-shadow: inset 0 0 0 2px var(--text-secondary); }}
  .rows {{ display: grid; grid-template-columns: minmax(120px, 210px) 1fr 76px; gap: 8px 12px; align-items: center; }}
  .lab {{ font-size: .84rem; overflow-wrap: anywhere; }}
  .lab small {{ display: block; color: var(--text-muted); font-size: .74rem; }}
  .track {{ position: relative; height: 18px; border-left: 1px solid var(--grid); border-right: 1px solid var(--grid);
    background: linear-gradient(to right, transparent calc(50% - .5px), var(--grid) calc(50% - .5px), var(--grid) calc(50% + .5px), transparent calc(50% + .5px)); }}
  .bar {{ position: absolute; top: 8px; height: 2px; }}
  .dot {{ position: absolute; top: 4px; width: 10px; height: 10px; margin-left: -5px; border-radius: 50%;
    box-shadow: 0 0 0 2px var(--surface-1); }}
  .dot.open {{ background: var(--surface-1); box-shadow: inset 0 0 0 2px var(--text-secondary), 0 0 0 2px var(--surface-1); }}
  .shown {{ background: var(--shown); }} .not-shown {{ background: var(--not); }} .no-reading {{ background: var(--none); }}
  .ver {{ background: none; font-size: .78rem; color: var(--text-secondary); }}
  .axis {{ display: grid; grid-template-columns: minmax(120px, 210px) 1fr 76px; gap: 12px; font-size: .72rem; color: var(--text-muted); }}
  .axis div:nth-child(2) {{ display: flex; justify-content: space-between; }}
  @media (max-width: 560px) {{
    .rows, .axis {{ grid-template-columns: 1fr 70px; }}
    .rows .lab {{ grid-column: 1 / -1; margin-bottom: -6px; }}
    .axis div:first-child {{ display: none; }}
  }}
  .wrap {{ overflow-x: auto; }}
  table {{ border-collapse: collapse; width: 100%; font-size: .8rem; min-width: 560px; }}
  th, td {{ text-align: right; padding: 6px 8px; border-bottom: 1px solid var(--grid); vertical-align: top; }}
  th:first-child, td:first-child, td.q {{ text-align: left; }}
  th {{ color: var(--text-muted); font-weight: 600; font-size: .72rem; text-transform: uppercase; letter-spacing: .04em; }}
  tr.tot td {{ font-weight: 600; }}
  code {{ font-size: .74rem; }}
  .note {{ color: var(--text-muted); font-size: .8rem; margin-top: 14px; }}
</style>
</head>
<body>
<div class="viz-root">
  <h1>The prompt trials, 5 to 8 October 2026</h1>
  <p class="sub">Apps built by Claude Haiku 4.5 and Claude Sonnet 5.5 (and, in the tenth and eleventh trials, Claude Haiku 5.5) from one request, each checked by <code>sv</code>. A
  prompt is <b>shown</b> when its problem was in at least 5 of the builds without it and at most 1 with it; <b>not
  shown</b> when it stayed in 2 or more; <b>no reading</b> when fewer than 5 builds had the problem without it.</p>
  <div class="hero">
    <div class="stat"><b>{len(TRIALS)}</b><span>trials</span></div>
    <div class="stat"><b>{builds}</b><span>builds</span></div>
    <div class="stat"><b>${cost:.2f}</b><span>of the owner's API credit</span></div>
    <div class="stat"><b>{counts["shown"]} of {len(rows)}</b><span>pasted-prompt comparisons shown</span></div>
  </div>

  <h2>Every pasted-prompt comparison</h2>
  <p class="sub">The share of builds with the problem without the prompt (open circle) and with it (filled). The
  library's status can differ by the owner's decision; <code>docs/PROMPTS.md</code> says where.</p>
  <div class="legend">
    <span><i class="key open"></i>without the prompt</span>
    <span><i class="key shown"></i>with it: shown</span>
    <span><i class="key not-shown"></i>not shown</span>
    <span><i class="key no-reading"></i>no reading</span>
  </div>
  <div class="axis"><div></div><div><span>0%</span><span>50%</span><span>100% of builds with the problem</span></div><div></div></div>
  <div class="rows">
{chr(10).join(dots)}
  </div>

  <h2>The same, as a table</h2>
  <div class="wrap"><table>
    <tr><th>Prompt</th><th>Model</th><th>Trial</th><th>Without</th><th>With</th><th>Verdict</th></tr>
{table}
  </table></div>

  <h2>The trials</h2>
  <div class="wrap"><table>
    <tr><th>Trial</th><th>When</th><th>Builds</th><th>Cost</th><th>Question</th><th>Write-up</th></tr>
{trial_rows}
    <tr class="tot"><td>All</td><td></td><td>{builds}</td><td>${cost:.2f}</td><td></td><td></td></tr>
  </table></div>

  <p class="note">Made by <code>docs/paper/trials/make_figure.py</code> from <code>verdicts.json</code>,
  <code>revision-verdicts.json</code>, <code>recipe-stage2.json</code> and <code>sentences-verdicts.json</code> in
  <code>docs/prompts/library-trial/</code>. The loop trials, the delivery test and the start test compared ways of
  working or of delivering prompts, not one pasted prompt against none, so they are in the trial table and not the
  chart. "Builds with the problem" counts only builds where the check could ask, as each trial's protocol defines it.</p>
</div>
</body>
</html>
"""
    OUT.write_text(page)
    print(f"wrote {OUT.relative_to(ROOT)}: {len(rows)} comparisons, {counts}")


if __name__ == "__main__":
    main()
