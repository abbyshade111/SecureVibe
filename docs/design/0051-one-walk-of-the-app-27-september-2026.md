# One walk of the app (27 September 2026)

The review of 27 September found the same three questions answered six different ways. Every check
walked the app folder for itself — the credential scan, the code rules, the corroborators, the outside
tools' file list, the test finder, and the ecosystem detection, which the bill of materials, the
dependency reader, and the pinning check each called again — and each walk decided on its own whether to
follow a symbolic link, whether to read a file of any size, and which folders to leave out. Two refused
links; five followed them. One capped file size; two read anything, and one held every source file in
memory for the run. Reproduced on a fixture: an app with a link to a folder outside it and a link
`src/loop -> ..`, on which `sv check` read the outside folder's file and reported it about thirty times
under paths four hundred characters long, stopping only where the operating system refuses a chain of
links past thirty-two.

`sv_scan::files::Listing` is now the one walk. It records every regular file with its size, extension,
and language; every folder entered; every symbolic link met, not followed; and every folder that could
not be opened. `sv report` and `sv check` build it once and hand it to each check, and build the bill of
materials once from it. Each check keeps its old function that takes a folder, as a thin wrapper, for
the callers and tests that have only one question to ask.

Three rules live in the listing and nowhere else:

- **A link is not followed**, to a file or a folder, and is named once. The report lists the links as
  a gap, so a linked `vendor/` is something the owner can see rather than something the checks
  quietly did or did not read. The kind is taken from the directory entry before anything resolves
  the link, since `Path::is_dir` answers for wherever the link leads.
- **A file over 2 MB is not read**, by any check. The credential scan already said so; the code rules
  now name such a file too, and claim nothing while it stands, the same way they treat a file whose
  parse failed. A generated bundle that size is not something a person typed.
- **Editor folders are for the credential scan alone.** `.idea` and `.vscode` are entered and their
  files marked, because a settings file holds a token as easily as any other file; every other check
  takes `app_files`, which leaves them out, as their walks did. This was the one regression on the
  way: the first listing skipped them for everyone, and the existing test for the credential scan
  reading `.vscode` caught it.

The corroborators changed shape to fit. They used to read every source file into memory, then for each
of about thirty signatures lowercase every file again and search it. Now each file is read once and
lowercased once, and every signature's patterns for its language are tried against it there; the first
file to match, in path order, is the evidence. The listing is in path order where the old walks were in
disk order, so on an app where a pattern appears in several files the corroborator may now name a
different one. Both are true; the new one is the same on every run.

**Measured**, with release builds of `main` and of this change, five runs each, best and median: `sv
check` is unchanged (0.98 s on the five-file example, 2.3 s on this repository, both within a few
hundredths of a second of before) and `sv report` on this repository goes from 2.86 s to 2.73 s, about
five percent. That is the honest result and worth recording: on trees this size the walks were never
where the time went. The startup cost the review names as item 6 (everything loaded and every query
compiled on each command) is most of that second, and this change does not touch it. Both builds write
the same security report on this repository, byte for byte; the compliance report differs only in the
corroborator's choice of file, described above. (An earlier measurement said 15 percent; it compared
against a `main` binary two days old, and is withdrawn.)

**Broken on purpose, four ways, each caught:** the kind read through the link (the loop fixture goes
red twice, in the listing's own test and end to end); the size cap off (twice); editor folders skipped
for the credential scan (twice, one of them the older test written when the two skip lists were made
one); editor files handed to every check (once, the listing's test). The end-to-end test runs both `sv
check` and `sv report` on the link fixture and on an app with a 2.4 MB source file, and asserts the
setup each time: the app's own file was read, so an absence is not the scan having read nothing.
