# Cost, time and optimization

v1's figures below are fixed: they measure 18–20 September, and v1 is archived. The section on `sv` at the end runs
to the cut-off, `main` at `157ddc3` (11:37 on 4 October 2026), from the pull requests that measured what they
changed.

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
- **Testing sandbox behavior with a four-line script** under `node --permission --allow-fs-read=<dir>` answers
  in two seconds what a golden-app run answers in thirteen minutes.
- **Failing test *names* passed to the fixing agent**, not just a count. Without them an agent re-ran the suite
  twice, spent budget, and told the owner to run it again with verbose output — the information existed and was
  being withheld.

## A caveat about these figures

The $63.46 is development spend across three days of building SecureVibe itself, not the cost of using it. An
owner building one app pays for one build. The honest per-app figure is the **$4.28 median full build with AI**,
or **nothing at all** for the free path — and the free path produced the best verification result in the
comparison.

## `sv`: speed and cost, 27 September to 4 October

**Cost.** `sv` still makes no AI calls: at the cut-off its `Cargo.lock` holds no HTTP client, so the money in a
build with `sv` is the owner's own AI coding tool, which `sv` does not see. What the sessions that built `sv` spent
is not recorded anywhere this paper can read. v1 kept `workspace/llm-audit.jsonl`; `sv`'s sessions kept no such
log, and from 28 September their transcripts are not on this machine.

**Speed.** A review of `sv` on 27 September (#315) timed it first: `sv check` took about 1 second on a five-file
example and about 3 on this repository, and nothing bounded a run. What followed, each measured on release builds
with the same inputs before and after:

| what | before | after | change |
|---|---|---|---|
| The AI checks reading 20,000 lines of the app's output | 16.7 s | 0.05 s | each pattern compiled once, and a word matched by hand rather than by a pattern built per line (#325) |
| The credential scan, 2,000 small files | 3.4 s | 0.04 s | the same (#325) |
| `sv check` on an empty app | 957 ms | 30 ms | a rule's queries compiled when a file in its language is first met, not all 143 at start (#326) |
| `sv check` on this repository | 2.33 s | 1.93 s | the same (#326) |
| The release binary | 35.7 MB | 34.5 MB | symbols stripped (#330) |
| A clean release build | 41 s | 30 s | the same (#330) |

Two of these corrected the review's premise rather than following it. The review blamed reloading the JSON data on
every command; measured, the JSON took 5 ms and compiling tree-sitter queries took 873 ms of the 957 (#326). It
also expected the usual release settings to halve the binary; measured, 27 MB of it is the fifteen grammars' parse
tables, and link-time optimization saved 1.4 MB more than stripping alone while making every clean build half a
minute longer, with no measurable gain in speed, so it was not adopted (#330). Only the first row was a wait a
person would notice, and only for an app that writes a lot while `sv run` watches it.

**Limits, so that a run always ends.** None of these existed on 27 September:

- every Docker call, 20 minutes, generous because a first run downloads images; the app's tests, 10 minutes, and a
  suite stopped at its limit credits nothing (#332, ADR-025);
- all the waiting for a rate limiter in one run, 5 minutes (#416);
- a check over MCP, 50 seconds by default, because checking this whole repository takes about 6 seconds and many
  clients give up after a minute; a check that runs out says nothing was assessed (#498);
- a file the checks read, 2 MB at first (#320), then read in 1 MB pieces up to 256 MB, after the comparison study's
  pipeline met a 10 MB data file that left the credential scan partial (#400, #407).

**A cost that is not money.** Semgrep, the one outside tool that connects to the internet, was run with its
usage reporting as it came until 3 October. Measured that day, three runs each way, the reporting was a second
connection, to an Amazon server in Oregon, besides fetching its rules; turning it off removed it every time and
changed none of the 1,074 rules loaded or what they found. It now runs with usage reporting off, and Opengrep,
which has none, runs in its place when Semgrep is absent (#481).

The faster paths are not shown to be safer ones: each change above kept its existing tests. #325 added one that compares the new matcher with
the pattern it replaced, and #326 one that compiles every query in every language, so a broken query still fails
in CI rather than when an app in that language first arrives.
