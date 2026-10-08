# Files that are not text named, and text that is not UTF-8 read (5 October 2026)

The deep review of `sv` at `eff3f17` (BACKLOG, part 2, H22) found two things, and the cato-pipeline session saw the
first in my-first-app: one Finder `.DS_Store` left the credential scan partial for good, and the report's gap said
only "1 file not read while looking for credentials", so the AI tool searched for large files and then ran `sv check`
to learn which file it was. The second: text that was not UTF-8 was never read, by the credential scan or any code
rule.

**Reading text.** Every check reads a file through `files::decode`, which now tries, in order:

- **A kind of file that holds no text a person writes, by its first bytes.** PNG, JPEG, GIF, and WebP images, icons,
  fonts, and `.DS_Store`. By contents, never by name: a `logo.png` holding text is read as text. First, because a
  small `.DS_Store` is valid UTF-8.
- **UTF-8 with no zero byte**, as nearly everything is. A zero byte is a character in UTF-8, but text a person
  writes has none; before, UTF-16 saved without its mark was read this way, with a zero between each letter, and a
  key written in it was missed while the file counted as read.
- **UTF-16**, with its mark (as Windows tools write it) or without it (nearly every other byte zero). Taken only
  when what it reads as is mostly ASCII with no control characters: two bytes can look like the mark by chance at
  the start of a binary file, and read as UTF-16 a key written in it as plain letters would read as nonsense and be
  missed. An app's own UTF-16 files, scripts and settings saved by Windows tools, are mostly ASCII.
- **Not text, if a zero byte is left.**
- **Latin-1 otherwise**, where every byte is one character, so letters, digits, and punctuation read as written and
  a credential written in them is found where it is.

A file over 2 MB, read in pieces, is still read as UTF-8 only.

**Saying what was not read.** A file of a kind that holds no text a person writes is named, by `sv check` and in the
credential scan's evidence ("2 more not read, being images, fonts, or other files that hold no text a person
writes"), and does not keep the scan from being complete: there is no text in it for a credential to be written in.
Any other file not read stays a gap, and the report's gap now names each, with why, up to five, and says how many
more `sv check` lists. `sv bundle` holds these files to the rule it had: in when the name says image or font, out
otherwise, with what the file is.

Two tests used bytes standing for "a file nothing reads" that the new reading reads; they now use bytes nothing
reads. Nine guards broken in turn, each caught, by between one and five tests. One first looked uncaught: the disk was
full, so the bundle tests never ran; run again with room, it was caught. The mutation run now counts a suite that did
not run as no answer rather than as a pass.
