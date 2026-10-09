# A deep review of sv for observability: what it can show of itself, and what it should

**Status:** claimed by paper-facts, 9 October 2026

Asked for by the owner on 9 October 2026, when choosing a record of the build loop for finding 22(d) of the gap
analysis: "observability is really important, so let's go with the first option and also please add a review task
to the backlog to do a deep review of sv and how we can build in observability throughout".

A review, not a build: read `sv` end to end and write down what a person (the owner, someone they help, or a later
session) can see of what `sv` did and why, and where they cannot. Among the questions:

- **A run.** What each command and MCP tool call leaves behind: which checks ran, which were skipped and why, how
  long each took, what each outside tool was given and gave back, and where a run that stopped part way leaves its
  trace. Whether a report can always be traced to the run, the `sv` version, and the data files that made it.
- **The build loop.** ADR-076's record of the MCP calls, once built: what else the loop needs written down, such as
  the findings fixed between two checks and the ones set aside.
- **Credit.** Whether every requirement's status can be followed back to the check, the evidence, and the rule that
  gave it (`sv explain` and `data/reach.json` go part of the way), and whether a credit that changed between two
  reports says why.
- **The running app.** What the fence, the stand-in services, and the probes record of what they saw, and what is
  kept after the containers are gone.
- **Failures.** Whether every error a person can meet says what failed, what it means for the report, and what to do;
  and whether a check that could not run is always visible, never silent.
- **Over time.** What the dashboard's history (ADR-057), the weekly review, and the paper's figures could read from
  these records.

It ends in a write-up in this item with findings ranked by what each costs and buys, each claimable on its own, and
the owner's decisions called out. It writes nothing that leaves the person's computer and adds no network connection;
anything it proposes that would is the owner's decision. Read the day's write-ups in the backlog first ("From the
review of" and "From the architecture assessment of"), so it does not find again what they found.

**Claimed on 9 October 2026 by session paper-facts**, at the owner's word ("please go ahead"), in branch
`claude/observability-review`. A review: it reads `sv` and writes its findings here; it builds nothing.
