# The threat model's 101 citations are outside the citation guard, and it cannot be pointed at them

**Status:** done, as its markers read on 8 October 2026

Done on 26 September 2026 (see the end of the entry). Found on 26 September 2026 reviewing the threat model. `data/knowledge/threats.json`
cites 101 distinct requirements across 42 threats. Every one resolves — the `AC-NN` class is clean —
but nothing compares a threat with the requirement it cites, and this is the fifth citation surface
in a codebase where four of them were wrong when first read.

Extending `crates/sv-check/tests/citations.rs` to cover it does not work, and that is the useful
part. Running its own comparison over the file flags **52 of the 101 pairs**, and every one that was
read is correct — T-02 "a signed-in person opens administrator pages" against V8.2.1 "function-level
access is restricted to consumers with explicit permissions"; T-03 "someone denies having signed in"
against V16.3.1 "all authentication operations are logged". The guard assumes a right citation shares
vocabulary with its requirement, and that assumption breaks here by design: a threat is written in
plain language for somebody who is not a programmer, and ASVS is written in formal terms for
somebody who is. Turning the guard on would mean 52 false alarms, which is how a guard gets switched
off.

The crosswalk already solved this exact shape. `data/sbd-asvs-crosswalk.json` pairs a terse control
with an ASVS requirement it could not share words with, so each pair carries a few words naming what
the two ask in common, and the guard holds that phrase against *both* texts — a stricter test than
either side alone. The same per-pair phrase would work here, and would make the 101 citations
checkable without asking plain English and ASVS to use the same words.

All 52 flagged pairs were read by hand on 26 September 2026 and none is wrong; this is about what
happens to the hundred and second.

**Claimed on 26 September 2026 by session securevibe-e8**, at the owner's asking. **Done the same
day, without a new file:** every citation already carries a `because`, and all 115 of them (101
distinct requirements) share vocabulary with both the requirement and the threat under the
guard's own comparison. The guard now reads them, and holds each against its threat as well. It
also found that an empty or wordless phrase passed every guard, here and in the crosswalk, which a
third test now refuses. See DESIGN, "The threat model's citations, and the bridge phrases already
written".
