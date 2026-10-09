#!/usr/bin/env python3
"""Scores docs/prompts/loop-compare/protocol.md: apps built with `sv` against apps built without it, every app's
settings file written by one blind tester.

    python3 score_loop_compare.py OUT BLIND REPO [--json FILE]

Reads each blind copy's report (BLIND/runs/<code>-out/report.json, from tools/prompt_trial.py), and only then the
code-to-build table (OUT/blind-map.json). The measures are the loop protocol's (`loop_measures.py`'s definitions):
running-app findings (`probe.*`) and own-code findings at high or critical per app, testability, and each of the recipe
brief's twelve problems by the recipe trial's rule. Signed in as corrected by the Haiku 5.5 trial's Amendment 1.
"""
import json, os, statistics, sys

OUT, BLIND, REPO = sys.argv[1], sys.argv[2], sys.argv[3]
HERE = os.path.dirname(os.path.abspath(__file__))
source = open(os.path.join(REPO, "docs/prompts/library-trial/score_revision.py")).read()
saved = sys.argv[:]
sys.argv = [saved[0], BLIND, REPO]
r = type(sys)("r")
exec(compile(source[:source.index("verdicts = {}")], "score_revision.py", "exec"), r.__dict__)
sys.argv = saved
NOT_SIGNED_IN = ("Signing in as the first test user did not open", "nobody to sign in as",
                 "`sv` signs in only when securevibe")


def signed_in(rep):
    return r.started(rep) and not any(any(m in g["why"] for m in NOT_SIGNED_IN) for g in rep["gaps"])


r.signed_in = signed_in
PROMPTS = ["password-rules", "password-hashing", "same-site-redirects", "sanitize-rich-text", "check-every-request",
           "changes-from-own-pages", "database-placeholders", "files-under-own-names", "no-shell-with-input",
           "cross-site-access", "plain-error-pages", "production-server"]

left_out = set(json.load(open(os.path.join(BLIND, "left-out.json")))["left_out"])
codes = sorted(d for d in os.listdir(BLIND) if d.startswith("app") and os.path.isdir(os.path.join(BLIND, d)))
unchecked = [c for c in codes if c not in left_out and not os.path.exists(os.path.join(BLIND, "runs", c + ".log"))]
if unchecked:
    sys.exit(f"not every copy has been checked yet: {unchecked}; no result from a partial run")

apps = {}
for c in codes:
    if c in left_out:
        continue
    rep = r.report(c)
    started = r.started(rep)
    findings = (rep or {}).get("findings", [])
    credited = {x["check_id"] for q in (rep or {}).get("requirements", []) for x in q.get("checked_by", [])
                if x["check_id"].startswith("probe.")}
    found = {f["rule_id"] for f in findings if f["rule_id"].startswith("probe.")}
    apps[c] = {
        "report": rep is not None, "started": started, "signed_in": signed_in(rep) if rep else False,
        "answered": len(credited | found),
        "running_findings": len([f for f in findings if f["rule_id"].startswith("probe.")]),
        "own_high": sum(1 for f in findings if not f["rule_id"].startswith("probe.")
                        and f.get("severity") in ("critical", "high")),
        "problems": {pid: (r.asked(rep, r.LIB[pid]), bool(rep) and r.asked(rep, r.LIB[pid])
                           and r.has_problem(rep, r.LIB[pid])) for pid in PROMPTS},
    }

# Only now is it known which app came from which arm.
codes_of = json.load(open(os.path.join(OUT, "blind-map.json")))
arm_of = {code: build.split("-")[1] for build, code in codes_of.items()}
out = {"arms": {}, "differences": {}, "problems": {}, "left_out": sorted(left_out)}
for arm in ("none", "loop"):
    mine = {c: a for c, a in apps.items() if arm_of.get(c) == arm}
    started = {c: a for c, a in mine.items() if a["started"]}
    out["arms"][arm] = {
        "apps": len(mine), "report": sum(a["report"] for a in mine.values()),
        "started": len(started), "signed_in": sum(a["signed_in"] for a in mine.values()),
        "answered": sorted(a["answered"] for a in mine.values()),
        # Security leaves out an app that did not start: nothing about it was seen.
        "running_findings": sorted(a["running_findings"] for a in started.values()),
        "own_high": sorted(a["own_high"] for a in mine.values() if a["report"]),
    }
    a = out["arms"][arm]
    print(f"== {arm}: {a['apps']} apps; report {a['report']}; started {a['started']}; signed in {a['signed_in']}")
    for k in ("answered", "running_findings", "own_high"):
        print(f"   {k:17} {a[k]} (middle {statistics.median(a[k]) if a[k] else '-'})")
for k in ("running_findings", "own_high"):
    n, l = out["arms"]["none"][k], out["arms"]["loop"][k]
    # The loop protocol: a difference only when every app in one arm is above every app in the other.
    if n and l and min(n) > max(l):
        said = "fewer with sv: every app built with it below every app built without"
    elif n and l and min(l) > max(n):
        said = "more with sv: every app built with it above every app built without"
    else:
        said = "no difference by the rule (the two arms overlap)"
    out["differences"][k] = said
    print(f"== {k}: {said}")
print("== the twelve problems (without sv / with sv, problem of asked)")
for pid in PROMPTS:
    counts = {}
    for arm in ("none", "loop"):
        rows = [a["problems"][pid] for c, a in apps.items() if arm_of.get(c) == arm]
        counts[arm] = (sum(p for _, p in rows), sum(asked for asked, _ in rows))
    (np_, na), (lp, la) = counts["none"], counts["loop"]
    if np_ < 5:
        verdict = "no reading"
    elif lp <= 1:
        verdict = "shown"
    else:
        verdict = "not shown"
    out["problems"][pid] = {"none": counts["none"], "loop": counts["loop"], "verdict": verdict}
    print(f"   {pid:24} {np_} of {na} / {lp} of {la}: {verdict}")
if "--json" in sys.argv:
    json.dump(out, open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=1)
