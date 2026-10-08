# A shell variable reference is reported as a hard-coded credential

**Status:** done, as its markers read on 8 October 2026

Reported on 29 September 2026 by the
cato-pipeline session, from its CI run against `sv` at `982f97e`: `export CF_ZONE_API_TOKEN="$CF_DNS_API_TOKEN"`
was a HIGH `secrets.credential-assignment`, telling the owner to rotate a credential that was never in the file.
`assignment_findings` (`crates/sv-check/src/secrets.rs`) skips a value that is all capitals and underscores, and
`looks_like_placeholder` skips `${NAME}`, but `$NAME` passes both. Fix: a value that is entirely one reference is
not a credential: `$NAME`, `$(command)` or backticks, `%NAME%`, and PowerShell's `$env:NAME`; a value that only
contains one (`$NAME-extra`, `pa$$w0rd…`) is still judged. **Claimed on 29 September 2026 by session
securevibe-e9**, at the cato-pipeline session's report on the owner's behalf.
**Done the same day:** `is_whole_reference` in `secrets.rs` passes over those five shapes, `${NAME}` included,
and nothing else. The report's table is a test, with the two values that only contain a reference as controls
that are still reported; skipping the check, or loosening it to "contains a `$`", turns it red.
