# More questions for the running app, and an `upload` entry

**Status:** open

Asked with what `[stack.run.users]`
already says. Three are done on 25 September 2026 by session securevibe-e9: `Cache-Control:
no-store` on private pages (V14.3.2), a visible sign-out link on private pages (V7.4.4), and
directory listings (V13.4.3). The first two are signed-in checks on the pages `private` names; the
third is an anonymous probe beside V13.4.1, because it needs no account, and it is only ever a
finding — six guessed paths and three server signatures cannot show that nothing lists. Level 2
goes from 30 to 33 of 183. See DESIGN, "Three more questions for the running app".

The logging question is **done on 26 September 2026 by session securevibe-e9**. The probes plant
three markers — a sign-in for an account that does not exist, a sign-in that works by an account
used for nothing else, and a private page asked for by nobody with a marker in its address — and
the container's output is read for them afterwards. Finding them credits V16.3.1 and V16.3.2;
*not* finding them is not assessed and never a finding, because an app that logs to a file or a
service writes nothing there and is not logging any less for it. V16.3.1 needs both sign-ins
found, since the requirement asks for both. Level 2 goes from 33 to 35 of 183. See DESIGN, "What
the app wrote down". Password reset is done on 26 September 2026 by session securevibe-e9,
on the mail server from the new-tools list below. An `upload` entry lets the probes send an oversized file, a file whose contents do not match
its extension, and a script, which reaches V5.2.1, V5.2.2, V5.3.1, and V3.2.1 at Level 1.
**The `upload` entry is done on 26 September 2026 by session securevibe-e9.** `[stack.run.users]`
takes an `upload` entry — the path, the file field, the other form fields, an optional
`serves-at` saying where an upload can be fetched back, and `max-bytes`, the size the owner
states and the app is held to. The probes send an ordinary GIF first to show the upload works at
all, then one larger than the stated size (V5.2.1), one named `.gif` that is not a GIF (V5.2.2),
a `.php` fetched back to see whether the server ran it (V5.3.1), and an `.html` fetched back to
see whether a browser would render it as part of the app (V3.2.1). Level 1 goes from 41 to 45 of
70. See DESIGN, "The upload entry". Left over from it: V5.3.2 (paths built from submitted names)
and V5.4.1/V5.4.2 (what the app sends back) are reachable the same way and were not written.
**Since done** (noted on 6 October 2026 by session securevibe-e9): V5.3.2 by `probe.upload-path-traversal`, and
V5.4.1 and V5.4.2 by `probe.download-unnamed` and `probe.download-name-injected` (`docs/COVERAGE.md`).
