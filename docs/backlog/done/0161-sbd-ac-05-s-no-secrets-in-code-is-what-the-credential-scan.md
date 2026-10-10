# SBD-AC-05's "no secrets in code" is what the credential scan checks

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Done on 25 September
2026. Every credential rule cites SBD-AC-05, so a committed secret is a finding against it, and a
clean scan is shown beside it as *supporting* evidence while it stays not verified. That rule is
general: a satisfied check about a manual-only requirement is never "checked". It corrected two
overclaims already in every report — V13.3.1 (use a key vault) and V11.1.1 (a documented key policy)
were listed as checked by a scan of source files.
