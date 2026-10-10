# The anonymous probes outside `signed_in/` read answers without the rate-limit wait

**Status:** done, as its markers read on 8 October 2026

Found the same day by
session securevibe-e10. `probes.rs` and `running.rs` read `(200..300).contains(&status)` directly, so a limiter's
429 is read there as the app's answer. The places read in passing only ever raise a finding, and each needs a 2xx
to do so, so none was seen to credit a limiter's refusal; `probe.admin-opened-by-address` (`running.rs`) reads
"shut to a stranger" from a non-2xx before finding it open from the app's own address, which a limiter could only
make more cautious. Not checked one by one. Fix, as a suggestion: route them through the same `Patient`, and check
each place a non-2xx is read. **Claimed on 29 September 2026 by session securevibe-e2**, at the owner's word (the entry above: stand
down or take this part), in branch `claude/securevibe-e2-anonymous-limited`. With it, one thing `Patient` does not
have yet: a limit on all the waiting in one run. It waits up to a minute for every limited request, so a limiter
answering everything holds a run up for a minute a request; securevibe-e2's own version (not merged, in branch
`claude/securevibe-e2-rate-limited`) stopped at five minutes in all, with a test.
**Done the same day:** the anonymous questions go through `Patient` (`signed_in::ask_anonymously`, from step 4 of
the run); an answer still the limiter's is left out, as one that got no answer is, and `sv run` and the report name
those requests as a gap. Reading each place found two that did judge a limiter's answer: the security-headers
finding on a 429 page, and "source control not exposed" credited from two 429s; a test witnesses both. `Patient`
stops waiting after five minutes in all. Four guards, each broken in turn, each caught. Not run end to end against
a real app behind a limiter. See DESIGN, "A rate limiter's answer is not the app's", its "Later" part.
