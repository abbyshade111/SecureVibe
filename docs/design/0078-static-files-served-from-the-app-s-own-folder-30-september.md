# Static files served from the app's own folder (30 September 2026)

V13.4.7 asks that the web tier serves only files with the extensions it should, so that source, settings, and
backups are never handed out. `probe.private-files-served` asks a running app for such files by name; the rule
`ast.static-files-from-app-folder` reads the code for the usual cause, a static-file handler pointed at the folder
the code is in or the folder the app was started from, where everything beside the code can be downloaded:
Express's and serve-static's `static(...)` given `.`, `__dirname`, or `process.cwd()`; Flask's `static_folder` and
Starlette's `StaticFiles(directory=...)` set to `.`, the code's own folder, or the current folder;
`http.FileServer(http.Dir("."))` and Gin's or Echo's `Static(prefix, ".")` in Go; and `python -m http.server` with
no `--directory` in a script. What each one serves was read from its own source this day: Flask 3 joins
`static_folder` to the folder of the app's module (so `.` and an empty string both mean that folder); Starlette's
`directory` can only be passed by name; Gin 1.12 and Echo 4.16 both take the folder second; and `http.server`
serves the current folder unless given `-d`.

It is only ever a finding, and its confidence is medium: `__dirname` in a file that sits in a folder holding
only public files is not a leak, and nothing here can tell that from the code alone. A handler given a folder of
its own (`public`, `dist`, `static`) is not reported. Four guards broken in turn, each caught by its witnesses.
