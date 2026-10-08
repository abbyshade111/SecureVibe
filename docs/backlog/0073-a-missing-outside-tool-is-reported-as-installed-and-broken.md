# A missing outside tool is reported as installed and broken under amd64 emulation

**Status:** done, as its markers read on 8 October 2026

Reported on 29 September 2026 by the cato-pipeline session, from the owner's comparison study (`sv report
--tools --advisories` on three apps, in CI under amd64 emulation and on the owner's Mac, `main` at `a836cd7`). `presence()` in
`crates/sv-check/src/adapters.rs` reads a spawn that failed as missing and one that exited non-zero as broken;
under QEMU on an ARM Mac, spawning a program that does not exist succeeds and the child exits 127, so Semgrep and
CodeQL, absent from the image, read as "installed and would not start". Fix: exit status 127 with nothing on
stderr is missing, the shell's own meaning of 127. **Claimed on 29 September 2026 by session securevibe-e9**, at that session's report on the owner's behalf.
**Done the same day:** a silent 127 is missing; a 127 that says something on stderr stays broken, since a program
that exists can exit 127 too. Tested with a real adapter whose version command is a stand-in script; breaking it
turned two tests red. Not run under QEMU here.
