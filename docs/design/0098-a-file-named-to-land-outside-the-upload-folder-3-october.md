# A file named to land outside the upload folder (3 October 2026)

The upload checks now send one more file, named `../sv-probe-escaped-<value>.gif`, a real GIF holding the same value
(V5.3.2, level 1). The value is made for each run, so a file an earlier run left behind cannot answer for this one.
Where the file ends up decides what is said:

- **Refused**, where an ordinary GIF of the same shape was accepted, is credited: the app would not use that name.
  Like the other upload refusals, the credit is held back when the upload crashed rather than being refused
  (`RESTS_ON_A_REFUSAL`).
- **Found one folder above where uploads are served** is `probe.upload-path-traversal` (CWE-22, high). The `../` was
  used to build the path the file was saved at, so whoever uploads can write where the app keeps its own files. One
  folder above is worked out from `serves-at`: `/files/{name}` gives `/{name}`, and `/static/uploads/{name}` gives
  `/static/{name}`. When `serves-at` puts the name in a query, or there is no folder above, this place is not asked.
- **Found where uploads are served, under its last part** is credited: the name was reduced to `sv-probe-escaped-…`,
  as `secure_filename` and `path.basename` do.
- **Found in neither place** is not assessed. An app that saves uploads under names of its own looks exactly like
  this, and that is the safest arrangement of all, but nothing outside the app can see it.

A place counts as holding the file only when it answers with the run's value. An app that answers every address
with its own page, as one that hands every path to a page in the browser does, is otherwise read as holding it
everywhere. Breaking that rule was caught by nothing until a fake app that does exactly that was added to the tests.

Tried on 3 October 2026 with `sv report --run`. `examples/notes-with-users`, which keeps only the last part of a
name, was credited. A copy changed to save a `../` name one folder up was found at once, with a high finding.

**Not done: compressed bombs (V5.2.3, level 2).** The backlog item put them beside this. The probes' request bodies
are text, which is why the upload checks send GIFs and not PNGs, and a compressed file that expands far is binary
throughout. V5.2.3 also asks about limits on the uncompressed size and the number of files, which `securevibe.toml`
has no way to state. Both are left for a later item.
