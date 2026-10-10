# An app folder given with a trailing `/.` leaves outside tools' paths absolute, and their fingerprints change

**Status:** done, as its markers read on 8 October 2026

Reported on 29 September 2026 by the cato-pipeline session, from the owner's comparison study (`sv report
--tools --advisories` on three apps, in CI under amd64 emulation and on the owner's Mac, `main` at `a836cd7`). `sv report app/.` reported every Bandit finding at an absolute path, because `relative_to` in
`adapters.rs` strips the folder as text and `…/app/.` is not a prefix of `…/app/backend/…`; the fingerprints
differed from the same scan of `app`, so a reviewed finding stops matching. Fix: normalize the folder once, where
`sv` receives it, so `app`, `app/`, `app/.`, `./app`, and its absolute path give the same report. **Claimed on 29 September 2026 by session securevibe-e9**, at that session's report on the owner's behalf.
**Done the same day:** the command line cleans the folder of `.` parts and trailing separators, and `relative_to`
tries the folder as given, cleaned, and canonical, only where the match ends at a separator (so `app-other` is
not under `app`). Each guard broken in turn turned its test red.
