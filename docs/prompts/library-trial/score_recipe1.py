#!/usr/bin/env python3
"""Scores stage 1 of the recipe trial (docs/prompts/library-trial/recipe-protocol.md) and names stage 2's arms by its
rule: a prompt gets an arm for a model when its problem was in at least 5 of that model's baseline builds asked, out
of at least 5 asked.

    python3 score_recipe1.py OUT REPO [--json FILE]
"""
import json, os, re, sys, glob, importlib.util
OUT, REPO = sys.argv[1], sys.argv[2]
# The revision trial's scorer's helpers (its "could be asked" as protocol.md defines it), without its own table.
source = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "score_revision.py")).read()
saved = sys.argv[:]
sys.argv = [saved[0], OUT, REPO]
r = type(sys)("r")
exec(compile(source[:source.index("verdicts = {}")], "score_revision.py", "exec"), r.__dict__)
sys.argv = saved
PROMPTS = ["password-rules", "password-hashing", "same-site-redirects", "sanitize-rich-text", "check-every-request",
           "changes-from-own-pages", "database-placeholders", "files-under-own-names", "no-shell-with-input",
           "cross-site-access", "plain-error-pages", "production-server"]


def log(b):
    p = os.path.join(OUT, "runs", b + ".log")
    return open(p).read() if os.path.exists(p) else ""


out = {"arms": [], "prompts": {}, "builds": {}}
for model in ("haiku", "sonnet"):
    names = r.builds(model, None)
    reports = {b: r.report(b) for b in names}
    rows = []
    for b in names:
        rep, text = reports[b], log(b)
        why = ((rep or {}).get("run_status") or {}).get("why", "")
        req = os.path.join(OUT, b, "requirements.txt")
        rows.append({
            "build": b, "wrote_app": r.wrote_app(b), "report": rep is not None,
            "unreadable": rep is None and bool(re.search(r"TOML parse error|is not a field|parsing .*securevibe.toml", text)),
            "has_requirements": os.path.exists(req),
            "install_refused": "asks for the app's packages to be installed before the run, and they were not" in why,
            "install_failed": "Installing the app's packages from" in why,
            "started": r.started(rep),
            "signed_in": r.signed_in(rep),
        })
    out["builds"][model] = rows
    print(f"== {model}: {len(rows)} builds; wrote an app {sum(x['wrote_app'] for x in rows)}; "
          f"report {sum(x['report'] for x in rows)}; settings unreadable {sum(x['unreadable'] for x in rows)}; "
          f"requirements.txt {sum(x['has_requirements'] for x in rows)}; install refused "
          f"{sum(x['install_refused'] for x in rows)}, failed {sum(x['install_failed'] for x in rows)}; "
          f"started {sum(x['started'] for x in rows)}; signed in {sum(x['signed_in'] for x in rows)}")
    for pid in PROMPTS:
        prompt = r.LIB[pid]
        asked = [b for b in names if r.wrote_app(b) and r.asked(reports[b], prompt)]
        problem = [b for b in asked if r.has_problem(reports[b], prompt)]
        arm = len(asked) >= 5 and len(problem) >= 5
        out["prompts"][f"{pid}@{model}"] = {"asked": len(asked), "problem": len(problem), "arm": arm,
                                           "with_problem": problem}
        if arm:
            out["arms"].append([model, pid])
        print(f"   {pid:24} {len(problem)} of {len(asked)} asked{'  -> ARM' if arm else ''}")
print("stage 2 arms:", out["arms"])
if "--json" in sys.argv:
    json.dump(out, open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=1)
