# A rate limiter's 429 may be read as the app's answer about access

**Status:** done, as its markers read on 8 October 2026

Reported to the owner on 28 September
2026 by an agent in another project that was integrating `sv`: an open CRITICAL it listed as "F-0001, the
anonymous user denied runtime probe" had got HTTP 429 from the app's rate limiter rather than a refusal to sign in,
and may be a false positive. **Not claimed.** Their report was not available here, and no check of `sv`'s matches
that name at CRITICAL, so the first step is to get the report (rule id, the request, the answer) from the owner.
Found while looking: `probe.private-page-anonymous` (`signed_in/mod.rs`, step 1 of `run_with`) counts anything
but 2xx as refused. It raises a finding only on 2xx, so a 429 cannot cause a false alarm there, but a 429 **is
credited as a pass**: V8.2.1 "refused to somebody not signed in" when the rate limiter said no and the page's own
check never ran. That is the opposite fault, a false pass, and the same reading may be elsewhere (`ok()` and
`accepted()` are used throughout the signed-in checks, and 429 is already handled on its own in the sign-in
guessing checks). A fix would treat 429 (and 503 with `Retry-After`) as "the app did not answer the question":
wait out `Retry-After` once and ask again, else not assessed, never refused. The file is frozen for the split
until step 2; this waits for it, or for the session holding slice b (private pages).
**Claimed on 29 September 2026 by session securevibe-e2**, at the owner's asking to pick a backlog item, in
branch `claude/securevibe-e2-rate-limited`, now that the split is done. The claim covers the false pass found
while looking (a 429 or a 503 with `Retry-After` read as the app's own answer, in the signed-in checks and any
other probe that reads a status the same way); the reported CRITICAL still needs the other project's report
from the owner, and stays open until it is read.
**The false pass claimed on 28 September 2026 by session securevibe-e10**, at the owner's asking, in branch
`claude/rate-limited-not-refused`: 429, and 503 with `Retry-After`, read as no answer rather than a refusal,
wherever the signed-in checks read one. F-0001 itself still needs the other project's report.
**The owner, on 30 September 2026: close F-0001** without the report. Claimed for closing the same day by
session securevibe-e2, in branch `claude/securevibe-e2-adr-notes`.
**Closed the same day**, at the owner's word, without the report. What came of it stays: the false passes from
a rate limiter's or a crash's answer are fixed (the entries around this one). If the report turns up, it is a new
entry.
**Claimed twice.** securevibe-e10's claim was made at 00:19 UTC on 29 September but pushed only to its own
branch, never merged; securevibe-e2 found the item unclaimed on `main` and claimed it at 00:38 UTC (#411), as
the rule says it should. **The owner's decision, the same day: securevibe-e10's finished work (#412) is merged,
and securevibe-e2 stands down or takes the part #412 left, the anonymous probes outside `signed_in/`** (the
entry below). The lesson is the rule's own: a claim counts when it is on `main`, so open its pull request at once.
**Done the same day:** every signed-in request goes through `Patient`, which waits out a 429, or a 503 with
`Retry-After`, once, as long as the app asks and at most a minute, except the guessing checks' own requests.
A limiter still answering after that withdraws every credit of the run into not assessed, naming the
requests, and keeps the findings with a note. See DESIGN, "A rate limiter's answer is not the app's".
Two things found and not changed are the entries below.
