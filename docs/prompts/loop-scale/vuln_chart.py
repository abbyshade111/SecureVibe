"""Item 6's findings by group: problems in the code (what sv check reads) and in the running app (what only
sv run sees), per build, for both models. Every value from item6-findings.json and loop-measures.json, in this folder."""
import json, os, statistics
os.environ.setdefault("MPLCONFIGDIR", "/tmp/claude-502/mpl")
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
HERE = os.path.dirname(os.path.abspath(__file__))
def load(n):
    p = os.path.join(HERE, n)
    return json.load(open(p if os.path.exists(p) else os.path.join(HERE, "data", n)))
SURFACE, INK, INK2, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9"
COL = {"sonnet": "#2a78d6", "haiku": "#eb6834"}
plt.rcParams.update({"font.family": "Helvetica", "font.size": 8, "text.color": INK, "axes.edgecolor": MUTED,
                     "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
                     "figure.facecolor": SURFACE, "savefig.facecolor": SURFACE, "axes.facecolor": SURFACE})
d = load("item6-findings.json")
answered = {r["build"]: r["answered"] for r in load("loop-measures.json")}
arms = ["none", "instructions", "check", "checkhidden", "plan", "planhidden", "loop"]
labels = ["spec\nonly", "spec +\ninstr.", "check,\nrefused", "check,\nhidden", "plan,\nrefused", "plan,\nhidden", "whole\nloop"]
SEVERE = ("critical", "high", "medium", "low")

def code_per_build(arm, model):
    bs = [x for x in d if x["arm"] == arm and x["model"] == model]
    return statistics.mean(sum(1 for f in x["findings"] if not f["running"] and f["sev"] in SEVERE) for x in bs)

def run_per_10(arm, model):
    bs = [x for x in d if x["arm"] == arm and x["model"] == model and x["started"] and answered[x["build"]]]
    return statistics.mean(10 * sum(1 for f in x["findings"] if f["running"] and f["sev"] in ("critical", "high", "medium"))
                           / answered[x["build"]] for x in bs)

fig, (a1, a2) = plt.subplots(1, 2, figsize=(7.2, 3.1))
for ax, fn, title, ylabel in ((a1, code_per_build, "In the code: what sv check can see", "findings per build (low and above)"),
                              (a2, run_per_10, "In the running app: what only sv run sees", "findings per 10 checks answered (medium and above)")):
    for i, arm in enumerate(arms):
        for model, dx in (("sonnet", -0.19), ("haiku", 0.19)):
            v = fn(arm, model)
            ax.bar(i + dx, v, 0.36, color=COL[model], edgecolor=SURFACE, linewidth=1)
            ax.text(i + dx, v + 0.06, f"{v:.1f}", ha="center", fontsize=5.8, color=INK2)
    ax.set_xticks(range(len(arms)))
    ax.set_xticklabels(labels, fontsize=6.6)
    ax.set_title(title, loc="left", fontsize=8.6)
    ax.set_ylabel(ylabel, fontsize=7)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.grid(axis="y", color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    ax.axvspan(5.55, 6.45, color="#f1f0eb", zorder=0)
fig.legend(handles=[Patch(color=COL["sonnet"], label="Sonnet 5.5"), Patch(color=COL["haiku"], label="Haiku 4.5")],
           frameon=False, fontsize=7, loc="lower center", ncol=2, bbox_to_anchor=(0.5, -0.04))
fig.suptitle("Item 6: the loop removed the code problems the check could see; the running-app problems stayed",
             x=0.01, ha="left", fontsize=9.4, y=1.02)
fig.tight_layout()
fig.savefig(os.path.join(HERE, "fig8-findings-by-group.png"), dpi=200, bbox_inches="tight")
print("written")
