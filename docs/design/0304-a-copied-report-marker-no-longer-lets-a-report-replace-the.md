# A copied report marker no longer lets a report replace the app's files (8 October 2026)


From the review of 8 October 2026, item 4 (`docs/backlog/0188-…`). `sv` writes a report into a folder only when it
holds nothing but what `sv` writes, or carries `sv`'s marker, `.securevibe-report`. The marker let anything else in
the folder be kept, so that a file the owner adds beside a report survives the next one (DESIGN, "Files sv writes
never through a link, and never over the app"). But a marker is a short text file anyone can copy: an app whose
`docs/` held a `README.md`, a `security.md` of its own, and a copied marker let `securevibe_write_report` with
`out: "docs"` replace that `security.md` with `sv`'s report, and add four files beside it.

**What changed.** A marked folder that also holds files `sv` did not write takes a report only when this computer can
show, by the marker's seal, that `sv` wrote the report there (`report_seal::sealed_here`: the seal holds under this
computer's report key for every file of the last report). A seal cannot be made without that key, so a copied
marker, or one with a seal line of someone else's making, is refused with the reason and "give an empty folder".
Nothing else changed: a new folder, an empty one, one holding only `sv`'s file names, and the default
`securevibe-report` are written to as before, and the seal is checked only when there is something besides `sv`'s
files to protect.

**A second fault, found by the first test.** `claim_report_folder`, which takes a folder for a run, wrote a fresh
marker without the seal before the report was written, so the check that comes just before the writing never saw
the seal, and a folder `sv` had sealed was refused the moment the owner put a file in it. The marker is now written
there only when there is none; the report's own writing and sealing replace it at the end.

**Breaks.** Each failed `crates/sv-cli/src/mcp/marker_tests.rs`: the marker alone taken as enough again (the bare
marker), the seal not checked at all (the bare marker), the seal's key check skipped (the forged seal over a folder
holding every report file, added when the first forged case turned out to be refused only because files were
missing), and the claim rewriting the marker (a sealed folder with a file of the owner's, and the existing
`writing_through_links.rs` test of the same case).

**Not done.** A folder holding only files under `sv`'s names, with no marker (an app's `docs/` with just a
`security.md`), is still taken as a report folder from before the marker existed and written to, as the deep review's
S5 decided. Narrowing that is a decision of its own: it would refuse the old report folders the rule was made for.
