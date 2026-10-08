# Compressed files past the stated limits (7 October 2026)

V5.2.3 (ASVS, level 2) asks that an app which takes compressed files checks, before it unpacks one, how much the files
inside add up to and how many there are. A zip of a megabyte can hold a gigabyte of zeros; an app that unpacks it
without counting fills its disk or its memory. `sv` cannot see from outside whether an app unpacks anything, or what
its limits are, so the owner says, as decided on 3 October 2026 (ADR-046):

- **The settings,** on the `upload` entry beside `max-bytes`: `unpacks-archives`, the formats the app unpacks (`"zip"`,
  `"gzip"`; anything else is refused by name when the settings are read); `max-unpacked-bytes`, the most one may unpack
  to; and `max-files`, the most files one zip may hold. Left out, nothing is sent and the report asks for them; an
  empty list says the app unpacks none, and nothing is sent or asked. With formats and no limit, the report asks for
  the limits: `sv` sets none of its own.
- **What is sent,** for each format listed, with a sign-in of A's own, after every other check that uses A's session
  and before the password changes (step 9g of the run): first an ordinary small archive holding one text file, which
  must be accepted, or that format is not assessed, since a refusal would say nothing; then one that unpacks to a
  mebibyte more than `max-unpacked-bytes`, and, for zip, one holding one file more than `max-files`. A gzip holds one
  file, so `max-files` is never sent as one.
- **The caps,** so the check stays a check: an archive unpacks to at most 1 GiB, a zip holds at most 65,535 files (the
  most it can without the 64-bit extension, which `sv` does not write), and the archive itself is at most 8 MiB and no
  larger than `max-bytes`. A limit past any of them is not assessed, and the report says which.
- **The verdict,** `probe.archive-unchecked`: accepted is a finding, since the owner says the app unpacks that format.
  Refused (a 4xx answer) is credited only when an ordinary file sent straight after is accepted (a full quota refuses
  both), and only when `max-bytes` is stated (without it, the refusal may be of the archive's own size). A crash or no
  answer is held back by the run's rule for refusals, as every upload refusal is.

**The archives are written by `sv` itself** (`crates/sv-check/src/signed_in/archives.rs`), with no new dependency. A
run of zeros is one deflate block with codes of its own: a copy of 258 bytes from one byte back costs two bits, which
is about a thousand to one, the most deflate allows, so a gibibyte of zeros is a little over a megabyte. Its CRC-32 is
worked out without going through the bytes (one zero byte is a linear step on the CRC, raised to the power by
squaring). The zip and gzip wrappers are a few dozen lines. The tests unpack every archive with Python's own `zipfile`
and `gzip`, which check each CRC and length, at sizes around each multiple of 258 and at the full gibibyte.

**Ten guards broken in turn, each caught:** the ordinary archive skipped (two tests), an acceptance not reported (four),
a refusal credited with no `max-bytes` (one), an archive larger than `max-bytes` sent (one), the file count sent as a
gzip (six), an archive that unpacks exactly to the limit (seven), a refusal credited without the ordinary file after it
(one, the full-quota test), one copy short in the deflate stream (two), a wrong CRC of zeros (three), and a crash not
held back (one, besides the run's own sweep of crashes). Not caught by any test: the check moved ahead of the other
upload checks, since the test app does not fall over; the place in the run is held by the comment beside it.

**What it does not show.** Every archive here says truly what it unpacks to, so an app that reads the sizes an archive
states, and trusts them, is credited; one that stops while unpacking is credited too, rightly. An archive that lies
about its sizes, and tar, 7z, and rar, are not sent.
