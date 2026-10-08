# The review of 1 to 4 October, the last batch: items 9, 10, 15, 16, 17, and 24 (6 October 2026)

The last of the review of the code merged on 1 to 4 October (BACKLOG). None of these credited or accused an app; each
let something through that should not have, or kept something from working.

- **A report from the future does not hold its folder for good (item 9).** `sv report` keeps a report in the folder
  when it came from a run that started after this one, so a slow run does not replace a newer report. It believed the
  start time written in `report.json`, so a report saying its run started in 2099 kept every later run from writing
  there. A start more than a minute ahead of this computer's clock is no longer believed: no run started then. A report
  from a run that started a little after this one is still kept. The time is still not checked against the report's
  seal, because the reports written before seals, and on other computers, carry none.
- **A line added inside a sealed notes section breaks its seal (item 10).** The lines that say who wrote a section
  (`Written by: owner`), its seal (`Sealed by sv review: …`), and the tool's own byline were left out of what is sealed
  wherever they stood. So the AI coding tool could add a line beginning with one of them anywhere in a section the owner
  sealed, and the seal still held. Now each is left out only when it can carry nothing else:
  - a `Written by:` line naming one of the two writers;
  - a seal line holding a well-formed seal and nothing more;
  - a byline only above the answer, before its first line.
  
  Anything else is part of the answer, sealed and shown with it. A line that only begins like a seal is never taken
  for the seal, and is kept when the section is sealed again.
- **The app's output and errors are read in the order it wrote them (item 15).** `docker logs` gives the two apart, and
  they were read one after the other, so a window between two markers on one held nothing written to the other in
  between. Docker now stamps each line with its time, and the lines are put back in that order. The miss could only
  hide a logged event, never credit one.
- **Two sentences of evidence say what was done (item 16).** The open-redirect evidence said "with `next` set" when
  `next` and eight other return parameters were. The made-up-session evidence said "of the same length" when a cookie
  shorter than 16 characters was given a 16-character value; it now says so.
- **A value is masked as far as the scan finds it (item 17).** The scan reads a file's values in that file's own
  shapes: YAML's `password: v&w`, `.properties`' `secret=v,w`, a Dockerfile's `ENV TOKEN v`, a shell script's
  `export TOKEN=v`. The masking did not know which file a line came from, so it stopped at the `&` or `,`, or masked
  nothing, and the fingerprint hashed the rest (deep review R4). Masking now gets the file's name, and masks exactly
  what the scan found there.
- **The smaller ones (item 24):**
  - A tool's error note in its own report (a file it could not read, quoting the line) is redacted, as everything
    else a tool says is.
  - A JavaScript parameter written without brackets (`sql => db.query(sql)`), or unpacked from an object or list
    (`({ sql }) => …`), is a parameter. Before, a constant of the same name made it look fixed.
  - A requirement with two sections in the notes is asked about once in `sv review`, by its first section.
  - Ctrl-C removes a report folder's lock only when it is still the file this run locked. Where the disk cannot
    lock, it may be another run's.
  - A report write through the MCP server that fails takes away the folders it made, so `out: "a/b/c"` leaves no
    `a/b`.

Broken on purpose nineteen ways, each caught by a test written for it. The first run found two breaks no test caught:
a seal taken from any line that begins like one, and a tool note that names no file. Each now has its own test. Two
other breaks were badly written and were run again. Item 15's ordering is tested on Docker's stamped output; the
`--timestamps` request itself runs only on CI, where Docker is.
