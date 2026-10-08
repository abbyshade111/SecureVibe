#!/usr/bin/env python3
"""Recounts "signed in" in the trials of 6 and 7 October 2026 (backlog 214), from their committed run summaries.

    python3 recount_signed_in.py [--json FILE]

Every scorer from the first prompt-library trial on counted a started app as signed in unless `sv` said signing in had
failed ("Signing in as the first test user did not open"). That also counted an app whose seed crashed ("nobody to sign
in as") and one `sv` never signed in to because securevibe.toml set no `[stack.run.users]` (the summary's run status
then says `'signed_in': False`, `sv`'s own record of whether its signed-in checks ran). The Haiku 5.5 trial's
Amendment 1 corrected the test; this applies it to the earlier trials.

The build folders are gone, so this reads the run summaries (`*-summaries.txt`), which keep each build's run status and
the gaps `sv` gave against the access checks, where both sign-in messages appear. First it reproduces the old test from
them and compares it build by build with the signed_in each results file recorded; a trial where they differ is
reported, not recounted. Then, for each comparison: the corrected signed-in counts, the signed-in checks' "asked"
(a build counts as asked of a signed-in check only when signed in), and the trial's own rule applied again.
"""
import json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
FAILED = "Signing in as the first test user did not open"
NOBODY = "nobody to sign in as"
# A build's line: `run {...}` with its run status, or `no report: ...` when `sv` wrote none (it did not start).
HEADER = re.compile(r"^(?:\[(?P<group>[^\]]+)\] )?== (?P<build>\S+) \(exit (?P<exit>-?\d+), (?P<run>.*)$")

KINDS = {q["id"]: q["check"]["kind"]
         for f in ("data/prompts.json", "data/design-prompts.json")
         for q in json.load(open(os.path.join(REPO, f)))["prompts"] if "check" in q}


def summaries(name):
    """{(group, build): {"started", "ran", "failed", "nobody"}} from one summaries file."""
    out, cur = {}, None
    for line in open(os.path.join(HERE, name)):
        m = HEADER.match(line)
        if m:
            run = m["run"]
            cur = {"started": "'state': 'started'" in run, "ran": "'signed_in': True" in run,
                   "failed": False, "nobody": False}
            out[(m["group"], m["build"])] = cur
        elif cur is not None:
            cur["failed"] |= FAILED in line
            cur["nobody"] |= NOBODY in line
    return out


def old(s):
    return s["started"] and not s["failed"]


def new(s):
    return s["started"] and s["ran"] and not s["failed"] and not s["nobody"]


def find(table, build, groups):
    hits = [table[(g, build)] for g in groups if (g, build) in table]
    if len(hits) != 1:
        raise KeyError(f"{build}: found {len(hits)} times in groups {groups}")
    return hits[0]


report = {"trials": {}}
problems = []


def side(rows, table, groups, kind):
    """Old and new totals of one side of a comparison, and builds whose recorded signed_in differs from the old test."""
    o = {"started": 0, "signed_in": 0, "asked": 0, "problem": 0}
    n = dict(o)
    mismatch = []
    for b in rows:
        s = find(table, b["build"], groups)
        if bool(b.get("signed_in")) != old(s):
            mismatch.append(b["build"])
        asked_old = bool(b.get("asked"))
        # A signed-in check is asked only of a build `sv` signed in to; any other check is unchanged.
        asked_new = asked_old and (kind != "signed-in" or new(s))
        for t, signed, asked in ((o, old(s), asked_old), (n, new(s), asked_new)):
            t["started"] += bool(b.get("started"))
            t["signed_in"] += signed
            t["asked"] += asked
            t["problem"] += bool(b.get("problem")) and asked
    return o, n, mismatch


def count_rule(base, arm):
    if base["problem"] < 5:
        return "no reading"
    return "shown" if arm["problem"] <= 1 else "not shown"


def share_rule(base, arm):
    if base["asked"] == 0 or base["problem"] * 2 < base["asked"]:
        return "no reading"
    if arm["asked"] and arm["problem"] * 10 <= arm["asked"]:
        return "works"
    return "not shown"


def harm(base, arm):
    return [f"signed in {arm['signed_in']} against {base['signed_in']}"] if base["signed_in"] - arm["signed_in"] >= 3 else []


TRIALS = [
    # (name, results file, summaries file, base side, arm side, rule, groups of base, groups of arm)
    ("prompt library", "verdicts.json", "run-summaries.txt", "without", "with", count_rule, [None], [None]),
    ("delivery, part B", "delivery-verdicts.json", "delivery-summaries.txt", "today", "delivering", share_rule,
     ["B-old"], ["B-new"]),
    ("prompts at the start", "start-verdicts.json", "start-summaries.txt", "today", "delivering", share_rule,
     ["today"], ["at-start"]),
    ("revision", "revision-verdicts.json", "revision-summaries.txt", "without", "with", count_rule, [None], [None]),
    ("recipe, stage 2", "recipe-stage2.json", "recipe-summaries.txt", "without", "with", count_rule, [None], [None]),
]

for name, results, summ, bk, ak, rule, bg, ag in TRIALS:
    table = summaries(summ)
    groups = sorted({g for g, _ in table}, key=str)
    data = json.load(open(os.path.join(HERE, results)))
    trial = {"comparisons": {}, "mismatches": []}
    for key, v in data.items():
        pid = key.split(":")[-1].split("@")[0]
        kind = KINDS.get(pid, "?")
        # Delivery and start label their builds by group; a build is found in whichever group holds it, and a name in
        # more than one group stops the recount rather than guess (find).
        bo, bn, bm = side(v[bk]["builds"], table, bg or groups, kind)
        ao, an, am = side(v[ak]["builds"], table, ag or groups, kind)
        trial["mismatches"] += bm + am
        before, after = rule(bo, ao), rule(bn, an)
        trial["comparisons"][key] = {
            "kind": kind, "recorded_verdict": v.get("verdict"),
            "old": {"base": bo, "arm": ao, "verdict": before, "harm": harm(bo, ao)},
            "new": {"base": bn, "arm": an, "verdict": after, "harm": harm(bn, an)},
        }
    report["trials"][name] = trial
    moved = [k for k, c in trial["comparisons"].items()
             if c["old"]["verdict"] != c["new"]["verdict"] or c["old"]["harm"] != c["new"]["harm"]
             or c["old"]["base"]["signed_in"] != c["new"]["base"]["signed_in"]
             or c["old"]["arm"]["signed_in"] != c["new"]["arm"]["signed_in"]]
    print(f"== {name}: {len(trial['comparisons'])} comparisons; builds whose recorded signed_in differs from the old "
          f"test read from the summaries: {len(set(trial['mismatches']))}")
    for k, c in trial["comparisons"].items():
        o, n = c["old"], c["new"]
        flag = ""
        if o["verdict"] != c["recorded_verdict"] and c["recorded_verdict"] is not None:
            flag = f"  [the old test gives {o['verdict']}, the file records {c['recorded_verdict']}]"
        print(f"   {k:40} {c['kind']:9} signed in {o['base']['signed_in']}/{o['arm']['signed_in']} -> "
              f"{n['base']['signed_in']}/{n['arm']['signed_in']}; asked {o['base']['asked']}/{o['arm']['asked']} -> "
              f"{n['base']['asked']}/{n['arm']['asked']}; verdict {o['verdict']} -> {n['verdict']}; "
              f"harm {o['harm'] or '-'} -> {n['harm'] or '-'}{flag}")

# The recipe trial's stage 1 and the sentences trial keep counts, not comparisons of this shape.
table = summaries("recipe-summaries.txt")
s1 = json.load(open(os.path.join(HERE, "recipe-stage1.json")))
for model, rows in s1["builds"].items():
    o = sum(old(find(table, b["build"], [None])) for b in rows)
    n = sum(new(find(table, b["build"], [None])) for b in rows)
    rec = sum(bool(b["signed_in"]) for b in rows)
    report["trials"].setdefault("recipe, stage 1", {})[model] = {"recorded": rec, "old": o, "new": n}
    print(f"== recipe, stage 1, {model}: signed in recorded {rec}, old test {o}, corrected {n}")
table = summaries("sentences-summaries.txt")
for key, v in json.load(open(os.path.join(HERE, "sentences-verdicts.json"))).items():
    model, pid = key.split("@")[1], key.split("@")[0]
    label = f"{model}-p_{pid.replace('-', '_')}-"
    rows = [s for (g, b), s in table.items() if b.startswith(label)]
    o, n = sum(old(s) for s in rows), sum(new(s) for s in rows)
    report["trials"].setdefault("three sentences", {})[key] = {"recorded": v["signed_in"], "old": o, "new": n,
                                                               "builds": len(rows)}
    print(f"== three sentences, {key}: {len(rows)} builds; signed in recorded {v['signed_in']}, old test {o}, "
          f"corrected {n}")

if "--json" in sys.argv:
    json.dump(report, open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=1)
