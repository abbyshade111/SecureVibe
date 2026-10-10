# `sv init`'s blank template trips its own credential check

**Status:** done, as its markers read on 8 October 2026

Reported on 29 September 2026 by the cato-pipeline session, from the owner's comparison study (`sv report
--tools --advisories` on three apps, in CI under amd64 emulation and on the owner's Mac, `main` at `a836cd7`). Every app using the template gets a HIGH
`secrets.credential-assignment` at its commented `reset = { … password = "{new_password}" … }` example:
`looks_like_placeholder` knows `${VAR}`, `<name>`, and `{{ var }}` but not the single-brace `{name}` `sv`'s own
manifest uses. Fix: a value that is entirely one `{identifier}` is a placeholder; `"{new_password}x9Q2vL"` is
still judged. A test that `sv init`'s own output raises no findings would catch a return. **Claimed on 29 September 2026 by session securevibe-e9**, at that session's report on the owner's behalf.
**Done the same day:** a value that is wholly one `{identifier}` is a placeholder, and one with anything around the
braces is still judged. A test scans `sv init`'s real template and fails on any credential finding; breaking the
rule turned it and a unit test red.
