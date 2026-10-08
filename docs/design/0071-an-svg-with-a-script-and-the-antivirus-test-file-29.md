# An SVG with a script, and the antivirus test file (29 September 2026)

Two more questions for the upload probe, each asked after the ordinary GIF has shown that uploading works at all.

**V1.3.4, an SVG image carrying a script.** An SVG is a picture written as text, and it can carry a script. Opened
from the app's own address, the script runs as the app for whoever opens it. The probe uploads `sv-probe.svg`, which
has two ways to run code (a `<script>` and a `<foreignObject>` holding HTML) and one harmless drawing (a `<circle>`),
and fetches it back from `serves-at`.

- Refused: credited, `probe.uploaded-svg-keeps-script`. An app that takes no SVG has nothing to clean.
- Back with the drawing and neither of the two: credited, and the credit says it covers those two and not every
  dangerous SVG feature.
- Back with either one still in it: a finding. It is High when the file is served for the browser to show, and
  Medium when it is served as an attachment or with a sandbox policy, since opening the address then does not run
  it, though the file was still not cleaned.
- Back without the drawing either (made into a picture, say): not assessed, since there is no SVG left to judge.
- Accepted with no `serves-at`, or not found there: not assessed.

**V5.4.3, the antivirus test file.** EICAR is a harmless line of 68 characters that every antivirus scanner is built to
recognize, made for checking that a scanner is there. The probe first uploads an ordinary text file, then the test
file under a `.txt` name.

- The ordinary text file refused: not assessed. An app that takes no `.txt` files would refuse the test file too, and
  that says nothing about scanning.
- The test file refused: credited, `probe.upload-not-scanned`.
- Accepted, and served back unchanged, and still unchanged 10 seconds later: a finding (Medium). The wait is for a
  scanner that runs just after the file is stored; the finding says that one slower than that would not show.
- Accepted and then gone, or served back changed (a scanner that cleans files), or accepted with nowhere to fetch it
  from: not assessed, each saying why.

The test file is not in the repository or in the `sv` program. It is kept as three pieces, each written backwards,
and put together only while the check runs, because a scanner on the owner's computer would otherwise set aside the
repository or `sv` itself. It is never written into a report, a step, or a test's output, for the same reason. A test
checks its length and the sum of its characters without printing it, checks that neither source file holds it, and
checks that no word of the outcome contains it.

Both credits rest on a refusal, so `upload-svg` and `upload-eicar` are in `RESTS_ON_A_REFUSAL`, and the crash sweep's
uploads setup now keeps SVG scripts and has no scanner, so both are tried.

Broken on purpose fourteen ways, each caught by a test: the SVG verdict inverted, `<script>` not looked for,
`<foreignObject>` not looked for, the severity blind to how the file is served, the drawing not required, a refused
SVG not credited, the text-file control dropped, no wait, no second look, "served back" not requiring "unchanged",
the test file written into the finding, one piece of it wrong, and each of the two `RESTS_ON_A_REFUSAL` rows removed
(caught by the crash sweep). Two fake-app settings were added so that two of these had anything to catch them: an SVG
turned into a picture, and a scanner that cleans the file instead of refusing it. The mutations were run against
`sv-check`'s own tests.

**Not done here.** The test file inside a `.zip`: the probe's request bodies are text, and a zip file is not. The
pointers from the code the backlog entry names (SVG sanitizer packages, antivirus packages, and `accept` attributes)
are not added. SVG features other than the two tried (event attributes such as `onload`, links to `javascript:`
addresses) are not looked for, so a credit does not cover them.
