#!/usr/bin/env python3
"""Scores the revision trial by docs/prompts/library-trial/revision-protocol.md, decided before any build.

    python3 score_revision.py OUT REPO [--json FILE]

OUT is the trial's folder (builds, transcripts, runs/<build>-out/report.json); REPO a checkout holding
data/prompts.json and data/design-prompts.json, whose `check.rules` say what each prompt is for. Prints one block a
prompt and writes the verdicts as JSON.
"""
import json, os, re, sys, glob, math, statistics, collections

OUT, REPO = sys.argv[1], sys.argv[2]
LIB = {p["id"]: p for f in ("data/prompts.json", "data/design-prompts.json")
       for p in json.load(open(os.path.join(REPO, f)))["prompts"]}
ARMS = {"haiku": ["limits-without-asking", "production-server", "isolate-the-window", "security-contact",
                  "secrets-in-the-environment", "security-headers", "git-from-the-start"],
        "sonnet": ["ai-feature-guard", "isolate-the-window"]}
# The protocol counts `config.security-contact` for this prompt, though the library cites no rule for it (it credits
# nothing): scored as a static check of that one rule.
LIB["security-contact"] = dict(LIB["security-contact"], check={"kind": "static", "rules": ["config.security-contact"]})
REVISED = {"secrets-in-the-environment", "security-headers", "git-from-the-start", "ai-feature-guard"}
# An app that would not start because a key it wanted was not set: what `sv run` cannot give it (the protocol's harm).
KEY_REFUSAL = re.compile(r"(environment variable|env var|is not set|must be set|missing|required)[^.]{0,80}"
                         r"|(SECRET|KEY|TOKEN)[A-Z_]*\b[^.]{0,40}(not set|must be set|required|missing)", re.I)


def builds(model, arm):
    label = "none" if arm is None else "p_" + arm.replace("-", "_")
    return sorted({os.path.basename(f)[:-6] for f in glob.glob(os.path.join(OUT, f"{model}-{label}-*.jsonl"))},
                  key=lambda b: int(b.rsplit("-", 1)[1]))


def report(build):
    p = os.path.join(OUT, "runs", build + "-out", "report.json")
    return json.load(open(p)) if os.path.exists(p) else None


def wrote_app(build):
    folder = os.path.join(OUT, build)
    return any(os.path.isfile(os.path.join(folder, f)) and f.endswith((".py", ".js", ".ts", ".rb", ".go"))
               for f in os.listdir(folder)) if os.path.isdir(folder) else False


def matches(rule_id, rules):
    return any(rule_id == r or (r.endswith(".") and rule_id.startswith(r)) for r in rules)


def started(r):
    return bool(r) and (r.get("run_status") or {}).get("state") == "started"


def signed_in(r):
    return started(r) and not any(g["why"].startswith("Signing in as the first test user did not open")
                                  for g in r["gaps"])


def answered(r):
    if not started(r):
        return 0
    credited = {c["check_id"] for q in r["requirements"] for c in q["checked_by"] if c["check_id"].startswith("probe.")}
    found = {f["rule_id"] for f in r["findings"] if f["rule_id"].startswith("probe.")}
    return len(credited | found)


def asked(r, prompt):
    """Whether the prompt's check could be asked of this build (protocol, "The measures", 1)."""
    if not r:
        return False
    kind, rules = prompt["check"]["kind"], prompt["check"]["rules"]
    if kind == "static":
        return True
    if not started(r):
        return False
    # protocol.md, "The measures", 1: a running check could be asked when the app started, a signed-in one when `sv`
    # signed in, the AI checks when the AI feature answered (one of their rules gave an answer, credited or found).
    # Counting "a rule answered" for the others, as the earlier scorer did, leaves out every fixed build of a rule that
    # only ever reports a finding: it shrinks the totals, though never the counts of builds with the problem.
    if all(x.startswith("probe.ai-") for x in rules):
        credited = {c["check_id"] for q in r["requirements"] for c in q["checked_by"]}
        found = {f["rule_id"] for f in r["findings"]}
        return any(matches(x, rules) for x in credited | found)
    return signed_in(r) if kind == "signed-in" else True


def has_problem(r, prompt):
    return any(matches(f["rule_id"], prompt["check"]["rules"]) for f in r["findings"])


def refused_for_key(r):
    st = (r or {}).get("run_status") or {}
    return st.get("state") == "could-not-start" and bool(KEY_REFUSAL.search(st.get("why", "").split(" One common cause")[0]))


def refused_own_forms(r):
    return bool(r) and any(f["rule_id"] == "probe.own-forms-refused" for f in r["findings"])


def other_findings(r, prompt):
    return sum(1 for f in r["findings"] if f.get("severity") in ("critical", "high", "medium")
               and not matches(f["rule_id"], prompt["check"]["rules"]))


def fisher(a, b, c, d):
    """Two-sided Fisher's exact test for [[a, b], [c, d]]."""
    n, r1, c1 = a + b + c + d, a + b, a + c
    def p(x):
        return math.comb(r1, x) * math.comb(n - r1, c1 - x) / math.comb(n, c1)
    obs = p(a)
    return min(1.0, sum(p(x) for x in range(max(0, c1 - (n - r1)), min(r1, c1) + 1) if p(x) <= obs + 1e-12))


def arm_summary(model, arm, prompt):
    rows = []
    for b in builds(model, arm):
        r = report(b)
        rows.append({"build": b, "wrote_app": wrote_app(b), "report": r is not None, "started": started(r),
                     "signed_in": signed_in(r), "answered": answered(r), "asked": asked(r, prompt),
                     "problem": bool(r) and asked(r, prompt) and has_problem(r, prompt),
                     "other": other_findings(r, prompt) if r else None,
                     "key_refusal": refused_for_key(r), "own_forms_refused": refused_own_forms(r)})
    usable = [x for x in rows if x["wrote_app"]]
    askd = [x for x in usable if x["asked"]]
    return {"builds": rows, "usable": len(usable), "asked": len(askd), "problem": sum(x["problem"] for x in askd),
            "started": sum(x["started"] for x in usable), "signed_in": sum(x["signed_in"] for x in usable),
            "answered_median": statistics.median([x["answered"] for x in usable]) if usable else 0,
            "other_median": statistics.median([x["other"] for x in usable if x["other"] is not None] or [0]),
            "key_refusal": sum(x["key_refusal"] for x in usable),
            "own_forms_refused": sum(x["own_forms_refused"] for x in usable)}


verdicts = {}
for model, prompts in ARMS.items():
    for pid in prompts:
        prompt = LIB[pid]
        base, arm = arm_summary(model, None, prompt), arm_summary(model, pid, prompt)
        if base["problem"] < 5:
            verdict = "no reading"
        elif arm["problem"] <= 1:
            verdict = "shown"
        else:
            verdict = "not shown"
        harm = []
        if base["started"] - arm["started"] >= 3:
            harm.append(f"started {arm['started']} against {base['started']}")
        if base["signed_in"] - arm["signed_in"] >= 3:
            harm.append(f"signed in {arm['signed_in']} against {base['signed_in']}")
        if base["answered_median"] - arm["answered_median"] >= 5:
            harm.append(f"checks answered, median {arm['answered_median']} against {base['answered_median']}")
        p = fisher(base["problem"], base["asked"] - base["problem"], arm["problem"], arm["asked"] - arm["problem"])
        if arm["key_refusal"] > base["key_refusal"]:
            harm.append(f"would not start for a key: {arm['key_refusal']} against {base['key_refusal']}")
        if arm["own_forms_refused"] > base["own_forms_refused"]:
            harm.append(f"refused its own forms: {arm['own_forms_refused']} against {base['own_forms_refused']}")
        keep = None
        if pid in REVISED:
            keep = verdict == "shown" or (base["problem"] < 5 and arm["problem"] <= 1)
        verdicts[f"{pid}@{model}"] = {"prompt": pid, "keeps_revision": keep, "model": model, "verdict": verdict, "harm": harm, "fisher_p": round(p, 4),
                         "without": base, "with": arm}
        print(f"== {pid} ({model}): {verdict.upper()}{'; HARM: ' + '; '.join(harm) if harm else ''}"
              + ("" if keep is None else f"; revision {'KEPT' if keep else 'UNDONE'}"))
        print(f"   problem without: {base['problem']} of {base['asked']} asked ({base['usable']} wrote an app); "
              f"with: {arm['problem']} of {arm['asked']} ({arm['usable']}); Fisher p = {p:.4f}")
        print(f"   started {base['started']} / {arm['started']}; signed in {base['signed_in']} / {arm['signed_in']}; "
              f"checks answered (median) {base['answered_median']} / {arm['answered_median']}; "
              f"other medium+ findings (median) {base['other_median']} / {arm['other_median']}")
if "--json" in sys.argv:
    json.dump(verdicts, open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=1)
