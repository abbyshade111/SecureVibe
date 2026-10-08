# The dependency scanner

The 17 not-assessed requirements are now answered. `sv-scan` reads the app's dependency manifests **and** its
source, and answers the eleven `derived` conditions with evidence attached — which dependency, in which
manifest, or which pattern, in which file.

Reading source as well as manifests is not thoroughness for its own sake. Python's `xml.etree` and Java's JAXB
are XML parsers that nothing declares; a dependency-only scan would answer "no XML parser is used" and switch
off V1.5.1 — an XXE requirement — for an app that parses attacker-supplied XML in its first route. That is the
same class of wrong statement as the inherited v1 reasons, arriving from a different direction, so the example
app now carries exactly that shape: `requirements.txt` names Flask, gunicorn, Authlib and PyJWT, and the XML
comes from the standard library.

### When "not found" is allowed to become "not there"

Only when everything that could have carried it was actually read. Three things stop the scanner concluding:

* **Files it cannot read.** A Swift or Scala file means `sv` has seen part of the app, and "I did not find it"
  is not "it is not there".
* **An ecosystem that pins nothing.** `^4.18.0` is a range, so the declared tree is not the installed one and an
  absent name proves nothing. v1's `ecosystems.ts` already made this point.
* **Having read nothing at all.** An empty folder, or one where everything was skipped, must not come back as
  "none of these technologies are used" — that reads exactly like a thorough scan that found none. A scan that
  did not run is not a clean result.

Matching is case-insensitive substring, which over-matches rather than under-matches. An over-match makes a
condition *true*, which only ever adds requirements — the same safe direction the manifest claims run in.

Each of those three guards was broken on purpose to see what caught it. Each had exactly one witness at first,
which under this project's rule means the coverage was accidental, so each now has a second that fails for a
different reason: a Go standard-library XML parser beside the Python one, a general property that nothing is
ever answered `false` while files go unread, an unpinned npm app beside the unpinned Python one, and a
skipped-directories folder beside the empty one.

### The example app, end to end

    Read 1 source files in python; package manifests: Python.

    274 apply, 177 do not, 0 not assessed, 153 above this level (604 loaded).

    Read from the code, so nobody had to be believed:
      xml              `xml.etree` in app.py
      format-strings   the app contains python

    Does not apply: 177 in total — 162 because the manifest says so, 15 read from the code.

Two bugs surfaced while wiring it up, both worth recording. `resolve` only ever iterated the manifest's claims,
so the scanner's answers — which are not claims — reached nothing downstream: it found the XML parser and the
requirement stayed not-assessed with the evidence sitting right there. And the scanner was willing to conclude
from reading zero files, which is the rule above being broken by its own author.
