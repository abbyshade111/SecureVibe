# Two more mistakes in the settings files Haiku writes

**Status:** done, as its markers read on 8 October 2026

Found on 7 October 2026 by session paper-facts, in the
revision trial: of the 12 files of 80 `sv` could not read, six put `admin` or `seed` under `[stack.run]` (they belong
under `[stack.run.users]`) and three wrote `ai = true` under `[capabilities]` (it is `enabled = true` under
`[capabilities.ai]`, already an item above). A sentence in the specification for each, as the two of 6 October did.
**Claimed on 7 October 2026 by session paper-facts**, at the owner's word ("go ahead with step 1"), in branch
`claude/step1-fixes`. Read on `main` just before this claim: no other session had claimed it.
**Done the same day:** the specification's `[stack.run]` says `seed`, `admin` and the other sign-in keys go under
`[stack.run.users]`, and that its header line must be uncommented too. Whether it works is for the next trial that
counts unreadable files.
