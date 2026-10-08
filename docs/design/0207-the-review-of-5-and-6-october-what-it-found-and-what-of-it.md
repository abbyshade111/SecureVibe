# The review of 5 and 6 October: what it found, and what of it was fixed (6 October 2026)

At the owner's asking, once every backlog item an agent could take alone was done or claimed: four reviewers read the
code merged on 5 and 6 October in four parts (the signed-in checks, the static scanners, the command line and MCP
server, and the reports and review records), and each fault they named was then reproduced by running `sv` on a small
app made for it, or confirmed by reading where running needed Docker. Seventeen are in the backlog under "A review of the
code merged on 5 and 6 October 2026". The nine in this session's own work, and one beside them in the same function,
are fixed here; the rest are left for whoever claims them.

- **No file read by name through a link (item 1).** The MCP server refuses `securevibe.toml`, `security-notes.md`, and
  `design-decisions.md` when they are links, as it already refused to write a report or notes through one. Reproduced
  first: a manifest linked to a file outside the root holding a key-shaped line came back to the AI tool in the parse
  error from `securevibe_preflight`, `securevibe_check`, and `securevibe_plan`; after the fix each is refused and the
  value is nowhere in the answer.
- **Letters are not a signature (item 2).** A signature made only of letters (`WEBP`, `OTTO`, `wOFF`, `wOF2`, `GIF87a`,
  `GIF89a`) counts only in a file that is not text, and WebP only after `RIFF`. Reproduced first: a `.env` whose first
  line was `IMG_FMT=WEBP` was skipped as an image and the secrets scan credited; after the fix the key on its next line
  is found.
- **The stated version first (item 3).** `manifest-version` is read before the fields, so a stated 0 is refused and a
  later version's own field is reported as an unknown version, not as a field to move.
- **security.md as inert as compliance.md (items 4 and 15).** The gaps, the set-aside lines, and the reviews not
  counted go through `inert`, and a code span in app text never crosses a line end.
- **One booking, or not credited (item 5).** `probe.action-done-twice` credits only exactly one copy going through.
  Several for one user cannot be told from one said again, and the other user's refusals do not show they could have
  taken it. This takes back part of 4 October's fix: a repeat answered "Booked" again is still never a finding, but is
  now not assessed rather than credited, and the spec says to choose words only a first taking shows.
- **The sign-in limit's gap names only what it held back (item 6).** The first user's checks only when that sign-in was
  refused; with nothing to name, it says so in words.
- **A decision's finding before the reviews (item 7).** `decisions_then_reviews` makes the not-held-to findings, then
  applies what a person set aside, then drops a decision's finding whose running-app finding was set aside.
- **Switches written another way (item 8).** Bold names and a dash are read, the first line for a switch counts even
  when it cannot be read, and a switch the section has no line for is named in a gap.
- **Code `sv` cannot read is code (item 9).** A `planned` answer is held to the code once the app has source in any
  language.

Broken on purpose sixteen ways, one or more per fix, and each caught by a test written for it. The first run missed one:
the test for item 15 had not been written (an edit had failed without a word), and was added. Not tested: the booking
change and the sign-in limit against a real app, as no test here runs one.
