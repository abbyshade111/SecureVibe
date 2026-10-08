# The review of 1 to 4 October, batch 2: seals (6 October 2026)

Items 8 and 11 of the review of the code merged on 1 to 4 October (BACKLOG) touched a decision the owner made
(ADR-026), so the owner settled them before they were built. ADR-026 has a "Later, 6 October 2026" entry.

- **No key, no credit (item 8).** On a computer where `sv review` had never run (CI, a container without the key, a
  teammate's computer), any seal of the right form counted as the owner's, and the report said it was "recorded through
  `sv review` on another computer". Such a computer cannot tell the owner's seal from one the AI coding tool wrote, so
  that claimed more than was known. Now the entry is a proposal there. The report says it carries a seal this computer
  cannot check, and what to do: run `sv review` once on this computer, or read the report on the computer that sealed
  it. `Sealed::Unchecked` is gone, and with it the "on another computer" wording in the reports.
- **A seal names its app (item 11).** A sealed answer copied from one app's `securevibe.toml` or `security-notes.md`
  into another app's on the same computer counted there. A seal is now `v2:<key id>:<app id>:<mac>`:
  - The app id is 16 hex characters of a SHA-256 of the app's folder, with every link followed, so the same folder
    reached another way is the same app.
  - The MAC covers the app id, so writing another app's id into a seal breaks it.
  - A seal for another folder does not count, and the report says it was sealed for an app in another folder and to
    run `sv review` there.
  - It is the folder, not the name in `[app]`, because the AI coding tool can change the name to match.
- **Seals made before this** (`v1:`) do not count, and the report says to run `sv review` once in the app. `sv review`
  asks about every entry whose seal does not hold, so that one run seals them again. An app moved to another folder is
  sealed again the same way.

What it costs: an owner whose report is written on CI sees their recorded answers as proposals there unless the key is
given to it, as the README already says to do for the container. That is the owner's decision. Report seals
(ADR-034) are unchanged and still `v1:`.
Broken on purpose nine ways, each caught by a test written for it: a seal counted with no key, the app's id left
unchecked or out of the MAC, an old seal read as malformed, the folder not resolved, the app id not read as hex, the
report or `sv review` given the wrong folder, and a folder that cannot be found taken for no key. One of the first runs
did not compile and was run again. Not tried on CI with a real owner's key.
