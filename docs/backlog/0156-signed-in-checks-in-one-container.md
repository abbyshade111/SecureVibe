# Signed-in checks in one container

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Done on 25 September 2026 by session securevibe-e8. Every
request is now an `exec` into one sidecar started per run, not a container of its own: a signed-in run
of `examples/notes-with-users` went from 11–13 seconds to 4.3, with the same answers. See DESIGN,
"One sidecar per run".
