# The rest of the review of 5 and 6 October (6 October 2026)

Items 13, 14, 16, and 17, at the owner's word ("take the remaining review items next"). With these, every item that
review found is done.

- **Both answers past the limit (item 13).** The password- and code-guessing checks send two attempts past the number
  stated and read the status of only the first. An app that answered that one as it answered the first of all, and
  pushed back only at the next, was said to have "answered the same every time", which was untrue. The second is read
  now: pushed back only there, the app let one more through than was stated, and the finding says so, at medium.
- **Whole names (item 14).** The preflight found `SV_ADMIN` inside `SV_ADMIN_PASSWORD`, so a seed that read only the
  admin's password and made up the admin's name was said to read the accounts. A variable is now found only as a whole
  name.
- **Plain SARIF words (item 16).** Three texts in `findings.sarif` ended a line with `\\` where `\` was meant, which
  left a backslash and a run of spaces in what GitHub shows.
- **The seal of what was written, and env between dots (item 17).** A report seal was made from the files read back
  after writing, so a file changed in that moment would have been sealed as `sv`'s. It is made from the bytes `sv`
  wrote, and the next read finds any change. A bundle now leaves out `prod.env.local` and the like, `env` between dots,
  unless a part of the name says it shows the form (`example`, `sample`, `template`, `dist`) or it ends in code.

Broken on purpose ten ways, each caught. The first run missed two, the SARIF fallback words and the seal itself, which
no test reached; each now has a test of its own.
