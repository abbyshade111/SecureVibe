#!/usr/bin/env python3
"""Scores the three sentences (docs/prompts/library-trial/sentences-protocol.md): each arm's builds against the
baseline the protocol names, read from the earlier trials' committed results.

    python3 score_sentences.py OUT REPO [--json FILE]
"""
import json, os, sys, re
OUT, REPO = sys.argv[1], sys.argv[2]
source = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "score_revision.py")).read()
saved = sys.argv[:]
sys.argv = [saved[0], OUT, REPO]
r = type(sys)("r")
exec(compile(source[:source.index("verdicts = {}")], "score_revision.py", "exec"), r.__dict__)
sys.argv = saved
LT = os.path.join(REPO, "docs/prompts/library-trial")
recipe2 = json.load(open(os.path.join(LT, "recipe-stage2.json")))
revision = json.load(open(os.path.join(LT, "revision-verdicts.json")))
BASE = {
    ("sonnet", "password-rules"): (recipe2["password-rules@sonnet"]["without"], "the recipe trial's Sonnet baseline"),
    ("sonnet", "production-server"): (recipe2["production-server@sonnet"]["without"], "the recipe trial's Sonnet baseline"),
    ("haiku", "isolate-the-window"): (revision["isolate-the-window@haiku"]["without"], "the revision trial's Haiku baseline"),
}
EARLIER = {("sonnet", "password-rules"): recipe2["password-rules@sonnet"]["with"],
           ("sonnet", "production-server"): recipe2["production-server@sonnet"]["with"],
           ("haiku", "isolate-the-window"): revision["isolate-the-window@haiku"]["with"]}
out = {}
for (model, pid), (base, where) in BASE.items():
    arm = r.arm_summary(model, pid, r.LIB[pid])
    if arm["asked"] == 0:
        verdict = "not scored: no build of the arm could be asked"
    elif base["problem"] < 5:
        verdict = "no reading"
    else:
        verdict = "shown" if arm["problem"] <= 1 else "not shown"
    locked = 0
    for b in arm["builds"]:
        log = os.path.join(OUT, "runs", b["build"] + ".log")
        rep = r.report(b["build"])
        why = ((rep or {}).get("run_status") or {}).get("why", "")
        if "database is locked" in why:
            locked += 1
    early = EARLIER[(model, pid)]
    out[f"{pid}@{model}"] = {"verdict": verdict, "baseline": where, "without": [base["problem"], base["asked"]],
                             "with": [arm["problem"], arm["asked"]], "earlier_text": [early["problem"], early["asked"]],
                             "started": arm["started"], "signed_in": arm["signed_in"], "usable": arm["usable"],
                             "database_locked": locked, "builds": arm["builds"]}
    print(f"== {pid} ({model}): {verdict.upper()}  without {base['problem']}/{base['asked']} ({where}); with the "
          f"new sentence {arm['problem']}/{arm['asked']}; earlier text {early['problem']}/{early['asked']}; wrote an app "
          f"{arm['usable']}, started {arm['started']}, signed in {arm['signed_in']}; database locked {locked}")
if "--json" in sys.argv:
    json.dump(out, open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=1)
