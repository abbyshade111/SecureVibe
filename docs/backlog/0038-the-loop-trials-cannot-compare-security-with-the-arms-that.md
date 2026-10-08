# The loop trials cannot compare security with the arms that have no `sv`

**Status:** open

Found on 5 October 2026 by session
paper-facts, in item 3: a build that never saw `sv`'s specification writes no manifest `sv` can read, so it cannot
be run, and the protocol's security measures leave it out. Two ways, for the owner to choose before item 6: a
tester writes the manifest for those builds from the code, as trial 3 did, so the comparison is of the apps; or
every arm's request includes the specification, so the comparison is of what the loop adds beyond it.
**The owner's decision, 5 October 2026:** the first, a tester writes the manifest for those builds from the code, so the comparison
is of the apps. For session paper-facts, which runs the trials.
