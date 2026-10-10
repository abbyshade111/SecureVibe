# Build ADR-083: history that can show a trend (0226, part 3, item C)

**Status:** done, 10 October 2026

Item C of the observability review's part 3 (backlog 0226), which the owner said yes to on 9 October 2026 ("please go
ahead and yes to A, C, and D as well"). The plan is ADR-083, `Status: proposed`: the dashboard's history keeps each
requirement's status in each run, not only the counts and findings, and says why two runs differ, so a trend can be
shown. It extends ADR-057. The record is made accepted in the pull request that builds it, which says where the build
differs from the plan. Made an item of its own on 10 October 2026, so the build has a claim others can see; item 0226
still holds the review's write-up.

**Decision 1 built 10 October 2026 by session securevibe-e2** (design entry "History keeps each requirement's status,
and names the ones that moved"): each kept run holds each requirement's status, and the dashboard names the ones that
moved. Decisions 2 to 4 (a failed run's record, more in the comparison key, records that stay readable) and `sv
compare` remain.

**Decision 3 built 10 October 2026 by session securevibe-e2** (design entry "History says which input changed between
two runs"): each run records the hashes of the security notes, the design decisions, and `sv`'s data, and the
dashboard names which changed when two runs are not compared. Decision 2 (a failed run's record), what remains of
decision 4, and `sv compare` remain.

**Decision 2 built 10 October 2026 by session securevibe-e2** (design entry "History keeps a run that did not
finish"): a run that failed or was stopped with Ctrl-C is kept as such, and the dashboard says when the report shown is
older than the latest run. What remains of decision 4, and `sv compare`, remain.

**Decision 4 and `sv compare` built 10 October 2026 by session securevibe-e2** (design entry "sv compare, and what
history keeps from a later sv"). ADR-083 is accepted in full; nothing of this item remains.
