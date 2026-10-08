# A backslash in a file name (4 October 2026)

The deep review of `sv` at `eff3f17`, sent by the cato-pipeline session, found that `sv bundle` read and zipped files
outside the app (S1, critical). On macOS and Linux a `\` is an ordinary character in a file name. The bundle's walk,
and the shared file listing, built each relative path by turning every `\` in its text into `/`. So a file in the app
named `..\outside\deploy_key.txt` became `../outside/deploy_key.txt`:
- the bundle read that path, a file beside the app folder;
- it put the file in the zip under a name that climbs out of whatever folder the zip is unpacked into;
- enough `..\` parts reached `/etc/hosts`.

The same paths fed Semgrep's list of files, the compose reader, and the Gradle catalog reader.

It is held three ways now, each tested on its own:
1. **Paths are built from their parts.** A relative path is the path's own parts joined with `/`, so a name with a
   `\` stays one name, and joined back on to the app folder it is the file it came from. On Windows, where `\` is
   the separator, the parts are the same as before. This is in `sv_scan::files::relative`, which the listing and the
   bundle both use, so every check reading through the listing gets it.
2. **The bundle carries no such name.** A name with a `\`, or bytes that are not text, is left out and listed with
   the reason: an archive's names are read on other systems, where `\` separates folders.
3. **The archive refuses a name that is not a plain path inside it.** Before anything is written, `zip` checks every
   entry name part by part: no empty part, no `.` or `..`, no `\`, no NUL, and no leading `/`. A colon is allowed,
   since it is an ordinary character in a name on macOS and Linux, and the first part is always the bundle's own
   folder.

The test is the review's own fixture: a file named `..\outside\deploy_key.txt` in the app, beside a real
`outside/deploy_key.txt` holding a marker. Each layer was broken on its own and caught. With the first two broken,
the third refused the bundle, naming the zip-slip entry. With all three broken, the test failed on the outside text in
the zip, as the review reproduced it.
