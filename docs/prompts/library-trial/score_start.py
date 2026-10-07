#!/usr/bin/env python3
"""Scores Part B of docs/prompts/library-trial/delivery-protocol.md: for each prompt and model, the share of builds
with its problem, today's sv (B-old) against the delivering sv (B-new), among the builds its check could be asked of."""
import json, os, sys, importlib.util
spec = importlib.util.spec_from_file_location("s", "/tmp/claude-502/loop/score_prompt_trial.py")
REPO = "/tmp/claude-502/pas-run"
sys.argv = ["x", os.path.expanduser("~/sv-start/today"), REPO]
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)  # loads the library; prints nothing useful
PROMPTS = {"sonnet": ["ai-feature-guard", "security-headers", "private-pages-no-store", "secrets-in-the-environment"],
           "haiku": ["security-headers", "private-pages-no-store", "secrets-in-the-environment"]}
out = {}
for model, pids in PROMPTS.items():
    for pid in pids:
        prompt = s.LIB[pid]; side = {}
        for arm in ("today", "at-start"):
            s.OUT = os.path.expanduser(f"~/sv-start/{arm}")
            side[arm] = s.arm_summary(model, "loop", prompt) if False else None
            rows = []
            for n in range(1, 11):
                b = f"{model}-loop-{n}"; r = s.report(b)
                rows.append({"build": b, "asked": s.asked(r, prompt), "problem": bool(r) and s.asked(r, prompt) and s.has_problem(r, prompt),
                             "started": s.started(r), "signed_in": s.signed_in(r), "answered": s.answered(r)})
            side[arm] = {"asked": sum(x["asked"] for x in rows), "problem": sum(x["problem"] for x in rows),
                         "started": sum(x["started"] for x in rows), "signed_in": sum(x["signed_in"] for x in rows), "builds": rows}
        o, n_ = side["today"], side["at-start"]
        if o["asked"] == 0 or o["problem"] * 2 < o["asked"]: verdict = "no reading"
        elif n_["asked"] and n_["problem"] * 10 <= n_["asked"]: verdict = "works"
        else: verdict = "not shown"
        out[f"{model}:{pid}"] = {"verdict": verdict, "today": o, "delivering": n_}
        print(f"{model:6} {pid:28} today {o['problem']}/{o['asked']}  delivering {n_['problem']}/{n_['asked']}  -> {verdict}"
              f"   (started {o['started']}/{n_['started']}, signed in {o['signed_in']}/{n_['signed_in']})")
json.dump(out, open("/tmp/claude-502/loop/results/start-verdicts.json", "w"), indent=1)
