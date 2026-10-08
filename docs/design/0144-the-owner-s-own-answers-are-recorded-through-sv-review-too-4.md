# The owner's own answers are recorded through `sv review` too (4 October 2026)

The rest of the deep review's R1, as the owner decided the same day. After `sv review` sealed set-aside findings and
confirmations, three more places still took "the owner" on one line anyone could write: a `[design]` answer and a
`[checked-by-hand]` result written `by = "owner"` (*attested by the owner*, *checked by hand by the owner*), and a
section of security-notes.md marked `Written by: owner` (*documented by the owner*). Each now counts as the owner's only
when `sv review` recorded it.

- **What is sealed.** A design answer: its requirement, answer, `where`, and `by`. A check made by hand: its
  requirement, result, `on`, `by`, and `how`. A notes section: its requirement and its answer as the report reads it,
  without the `Written by:` line and without the seal. The seal goes in a `seal` field in securevibe.toml, and in
  security-notes.md on a line `Sealed by sv review: …` straight under `Written by: owner`. That line is never part of
  the answer, so it can never make one, and the AI coding tool cannot record it through `securevibe_record_answer`.
- **Without a seal that holds**, the answer drops one tier, to *stated by the AI coding tool*, and the report says
  "securevibe.toml says you answered yes, … but it was not recorded through `sv review` …, so it counts as your AI coding
  tool's word", with how to make it the owner's. A `no` or a `problem` is still a finding, worded as what the file says;
  reporting a missing control never overstates the app. With no key to check with (CI), a sealed answer counts as the
  owner's and says it was recorded on another computer.
- **`sv review`** now also offers each answer given as the owner's and not recorded on this computer, shows it, and asks
  for `owner`: only the app's owner gives these answers, so a name is refused, with a pointer to confirming instead. It
  writes only the seal (in securevibe.toml through `toml_edit`; in security-notes.md one line under `Written by:`, any
  earlier seal line in the section taken out), and reads the file back. Answers the AI coding tool gave are not offered:
  the person confirms those, as before.
- **The instructions** in the securevibe.toml spec, the interview, the notes template, and the MCP tools say that an
  answer marked as the owner's counts once they run `sv review`, and that the tool must never run it for them.

Tests that wrote `by = "owner"` and expected the owner's tier now seal the answer as `sv review` would. One of them runs
the MCP server inside the test process, so `sv_check::seal::key_folder_for_tests` lets such a test fix the key folder
once, keeping its result the same whether or not the computer running it has a review key; nothing outside a test can
reach it.

Thirteen guards undone in turn, each caught: the three judgments, the report's wiring for design answers and for
checks made by hand, two of the sealed fields, the seal line kept out of the answer and out of what the tool may record,
an old seal replaced, only `owner` accepted, and only the answers given as the owner's offered.
