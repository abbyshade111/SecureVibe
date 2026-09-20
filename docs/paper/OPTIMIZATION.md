# Cost, time and optimization

Measured over the three days the repository's surviving history covers (18–20 September; earlier work was lost
in the iCloud eviction described in the timeline, and its AI spend is not in this log either): **51 successful runs, 823 AI calls, $63.46 of Anthropic credit**. Every
figure here comes from `workspace/llm-audit.jsonl`, which records each call with its purpose, tokens, cache use
and cost, and from the runs' own `startedAt`/`finishedAt`.

## What a run costs and how long it takes

| run type | runs | median time | median cost | max cost |
|---|---|---|---|---|
| Full build, AI writing code | 8 | **44.9 min** | **$4.28** | $5.36 |
| Full build, no AI (starter app from the answers) | 9 | 4.1 min | $0.00 | — |
| Check only, AI review on | 6 | 12.0 min | $2.38 | $9.01 |
| Check only, no AI | 28 | **0.6 min** | $0.00 | — |

The free check-only run takes about **36 seconds** and is the one an owner will do most often. The expensive
path is eleven times slower and is the only one that writes code.

**The result this bears on**: SecureFit verified 104 of 159 applicable ASVS requirements on a **free, 4-minute,
no-AI check**. The uploaded copy of the same code spent $2.38 on an AI review and verified nothing. Cost did not
buy verification; running the app did.

## Where the money goes

| step | calls | cost | share |
|---|---|---|---|
| ai-review | 386 | $37.88 | 60% |
| generate | 372 | $24.29 | 38% |
| fix | 48 | $0.85 | 1.3% |
| plan, peer-review, refine, summarize | 17 | $0.44 | 0.7% |

Two steps are 98% of the bill. Everything else is rounding.

## The optimizations, and what each is worth

**Prompt caching — the largest single effect.** Of 87.1M input tokens across all calls, **84.6M were served from
cache: 97%**. Only 2.5M were fresh. The generation agent and the reviewer work over the same app files
repeatedly, so the files are written to cache once and read back many times. Without it the bill would be
several times larger; cache reads are billed at a fraction of fresh input.

**"Save credits" on by default.** Sonnet rather than Opus, low reasoning effort, one fix round instead of
several. Visible in the model mix: **692 of 823 calls on Sonnet, 131 on Opus**.

**The two steps that decide nothing always run on the cheapest model of their service**, whether or not Save
credits is on (`SMALL_STEPS` = `classify`, `summarize`). A step whose output is a label should never be priced
like a step whose output is code — and `summarize` cost $0.00 across the whole project.

**The spending cap is split before it is spent**, not consumed first-come: 55% writing, 30% review, 15% fixes
(`BUDGET_SHARES`). Without a split, the writing step exhausts the cap and the review — the only check the owner
is paying for — never runs.

**The AI review is ordered by risk** (`reviewOrder`), highest-consequence requirements first, so a review stopped
by the spending limit loses the least. The stop is designed for rather than treated as a failure.

**Verdicts are carried forward when the file has not changed.** On a rebuild, an AI review verdict is reused only
when the file it cited is **byte-identical by hash** to the one assessed before, so money goes on what changed.
The strictness is the point: a looser rule would quietly weaken the one check being paid for.

**Scanner caches are shared across the workspace.** Trivy downloads a ~1.3 GB vulnerability database; per-project
caches meant four apps held five gigabytes of the same file. One cache folder for the workspace fixed it.

**The evaluation harness builds two apps at once and shares one compile cache.** Five golden apps take about
13 minutes rather than 25.

## Optimizations that are about attention rather than money

Worth separating, because they cost nothing and were the ones that changed how the work went.

- **`--only <name>` on the harness**: one golden app in ~4.5 minutes against ~14 for five. Three full runs were
  spent on 20 September chasing a single failing test that appeared identically in all five — about half an hour,
  and three chances to attribute a failure to the wrong change.
- **Testing sandbox behaviour with a four-line script** under `node --permission --allow-fs-read=<dir>` answers
  in two seconds what a golden-app run answers in thirteen minutes.
- **Failing test *names* passed to the fixing agent**, not just a count. Without them an agent re-ran the suite
  twice, spent budget, and told the owner to run it again with verbose output — the information existed and was
  being withheld.

## A caveat about these figures

The $63.46 is development spend across three days of building SecureVibe itself, not the cost of using it. An
owner building one app pays for one build. The honest per-app figure is the **$4.28 median full build with AI**,
or **nothing at all** for the free path — and the free path produced the best verification result in the
comparison.
