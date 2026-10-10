# Two prompts assume a framework that a standard-library app does not have

**Status:** done, as its markers read on 8 October 2026

Found on 7 October 2026 by session
paper-facts, in the revision trial (`docs/prompts/library-trial/revision.md`). Told to use only Python's standard
library, Haiku kept the built-in server, which (1) sends its version in a `Server` header on every answer unless the
request handler's `server_version` and `sys_version` are set, so `production-server` left the version in every build;
and (2) writes its own error pages through `send_error`, outside the helper that sets the security headers, so
`isolate-the-window` missed the window header on 403 and 404 pages in Haiku's builds. One sentence for each prompt,
then a trial on a brief whose baseline has the problem. `security-headers` and `private-pages-no-store` say "every
response" and may miss the same pages.
**Claimed on 7 October 2026 by session paper-facts**, at the owner's word ("go ahead with step 1"), in branch
`claude/step1-fixes`. Read on `main` just before this claim: no other session had claimed it.
**Done the same day:** `production-server` now says how to keep the version out of Python's built-in server
(`server_version`, `sys_version`; tried by hand: the header becomes `app`, which `probe.version-disclosed` passes), and
`isolate-the-window` how to give Python's own error pages the headers. Both sentences are untried, and the library
says so. `security-headers` and `private-pages-no-store` are left as they are until a trial shows the same miss.
