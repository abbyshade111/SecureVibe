# The app's own container is not run read-only

**Status:** done, as its markers read on 8 October 2026

Found on 30 September 2026 by the first weekly review of the
decision records (ADR-019, "Later, 30 September 2026"). The app's folder is mounted read-only and every helper
container runs `--read-only`, but the app's container does not, so the app can write anywhere in its own file
system outside `/app`; and the in-memory report folder has no size limit. Running the app `--read-only` with an
in-memory `/tmp` would close that, at the cost of failing an app, or a build step, that writes elsewhere; a size
for the report folder is simpler. **The owner's decision, 3 October 2026: yes**, read-only with an in-memory
`/tmp`, no capabilities and no new privileges, and a size for the report folder, tested against the example
apps first. **Claimed on 3 October 2026 by session practical-banach-b1faa1** (the session that was
keen-meninsky-691a27). **Done the same day:** read-only, no capabilities, no new privileges, an in-memory
`/tmp` of 256 MB and a report folder of 16 MB, measured on every example app and on an app that starts only
when contained. See ADR-019, "Later, 3 October 2026".
