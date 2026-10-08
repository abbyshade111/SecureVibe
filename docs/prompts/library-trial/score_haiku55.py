#!/usr/bin/env python3
"""Scores the Haiku 5.5 trial (docs/prompts/library-trial/haiku55-protocol.md): for each of `haiku45` and `haiku55`,
whether the apps can be tested, stalls, each prompt's problem, and cost; then the protocol's rule for each step.

    python3 score_haiku55.py OUT REPO [--json FILE]

The per-build measures are the recipe trial's stage 1 scorer's (score_recipe1.py), run for these two labels.
"""
import json, os, sys

OUT, REPO = sys.argv[1], sys.argv[2]
HERE = os.path.dirname(os.path.abspath(__file__))
source = open(os.path.join(HERE, "score_revision.py")).read()
saved = sys.argv[:]
sys.argv = [saved[0], OUT, REPO]
r = type(sys)("r")
exec(compile(source[:source.index("verdicts = {}")], "score_revision.py", "exec"), r.__dict__)
sys.argv = saved
PROMPTS = ["password-rules", "password-hashing", "same-site-redirects", "sanitize-rich-text", "check-every-request",
           "changes-from-own-pages", "database-placeholders", "files-under-own-names", "no-shell-with-input",
           "cross-site-access", "plain-error-pages", "production-server"]
MODELS = ("haiku45", "haiku55")


def result(b):
    """The transcript's final result line: cost, time, and the last thing the builder said."""
    last = {}
    for line in open(os.path.join(OUT, b + ".jsonl")):
        if '"type":"result"' in line:
            last = json.loads(line)
    return last


def log(b):
    p = os.path.join(OUT, "runs", b + ".log")
    return open(p).read() if os.path.exists(p) else ""


out = {"builds": {}, "prompts": {}, "steps": {}, "cost": {}}
for model in MODELS:
    rows = []
    for b in r.builds(model, None):
        rep, end = r.report(b), result(b)
        why = ((rep or {}).get("run_status") or {}).get("why", "")
        wrote = r.wrote_app(b)
        rows.append({
            "build": b, "wrote_app": wrote, "report": rep is not None,
            "has_requirements": os.path.exists(os.path.join(OUT, b, "requirements.txt")),
            "install_refused": "asks for the app's packages to be installed before the run, and they were not" in why,
            "install_failed": "Installing the app's packages from" in why,
            "started": r.started(rep), "signed_in": r.signed_in(rep),
            # A stall: no app written, and the builder's last words end in a question to the owner.
            "stalled": not wrote and str(end.get("result", "")).rstrip().endswith("?"),
            "cost": end.get("total_cost_usd") or 0, "seconds": round((end.get("duration_ms") or 0) / 1000),
        })
    out["builds"][model] = rows
    n = len(rows)
    out["cost"][model] = {"builds": n, "total": round(sum(x["cost"] for x in rows), 2),
                          "mean": round(sum(x["cost"] for x in rows) / max(n, 1), 3)}
    print(f"== {model}: {n} builds, ${out['cost'][model]['total']} (${out['cost'][model]['mean']} a build); "
          + "; ".join(f"{k} {sum(x[k] for x in rows)}" for k in
                      ("wrote_app", "report", "has_requirements", "install_refused", "install_failed", "started",
                       "signed_in", "stalled")))
    reports = {x["build"]: r.report(x["build"]) for x in rows}
    for pid in PROMPTS:
        asked = [b for b in reports if r.wrote_app(b) and r.asked(reports[b], r.LIB[pid])]
        problem = [b for b in asked if r.has_problem(reports[b], r.LIB[pid])]
        out["prompts"][f"{pid}@{model}"] = {"asked": len(asked), "problem": len(problem)}
        print(f"   {pid:24} {len(problem)} of {len(asked)} asked")

# The protocol's rule, for each step a build can fail: shown when the control fails it in at least 5 of 10 and Haiku
# 5.5 in at most 1; not shown when Haiku 5.5 fails it in 2 or more; no reading when the control fails it in under 5.
print("== the rule")
for step, failed in (("readable settings", lambda x: not x["report"]),
                     ("started", lambda x: not x["started"]),
                     ("signed in", lambda x: not x["signed_in"])):
    control = sum(failed(x) for x in out["builds"]["haiku45"])
    new = sum(failed(x) for x in out["builds"]["haiku55"])
    unchecked = [x["build"] for m in MODELS for x in out["builds"][m] if not log(x["build"])]
    if len(out["builds"]["haiku45"]) < 10 or len(out["builds"]["haiku55"]) < 10 or unchecked:
        # Never a verdict from fewer builds than the protocol fixed, or from builds `sv` has not run yet: a build
        # with no run log has no report because nothing looked, not because its settings could not be read.
        verdict = "incomplete"
    elif control < 5:
        verdict = "no reading"
    elif new <= 1:
        verdict = "shown"
    elif new >= 2:
        verdict = "not shown"
    out["steps"][step] = {"haiku45_failed": control, "haiku55_failed": new, "verdict": verdict}
    print(f"   {step:18} Haiku 4.5 failed {control} of 10, Haiku 5.5 {new} of 10: {verdict}")

if "--json" in sys.argv:
    json.dump(out, open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=1)
