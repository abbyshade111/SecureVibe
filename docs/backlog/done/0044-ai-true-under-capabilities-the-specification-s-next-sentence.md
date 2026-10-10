# `ai = true` under `[capabilities]`: the specification's next sentence

**Status:** done, as its markers read on 8 October 2026

Found on 6 October 2026 by session
paper-facts, in the delivery test: after the two new sentences, the commonest unreadable settings file left was
`ai = true` written straight under `[capabilities]` (one Part A build and one Part B build), where `sv` wants
`enabled = true` under `[capabilities.ai]`. A line under `[capabilities]` saying the AI feature's answers go in
`[capabilities.ai]`, and the starter file's own `[capabilities.ai]` example saying `enabled`, would be measured as
Part A was. Two builds also wrote the same key twice; `sv`'s message for that already says which.
**Claimed on 7 October 2026 by session securevibe-e2**, at the owner's word ("go ahead and pick the next backlog
item"), in branch `claude/securevibe-e2-capabilities-ai`. Not a decision by CLAUDE.md's list (the spec's wording,
and a clearer refusal message; nothing counted changes), so no ADR is proposed; ADR-028 gets a Later line.
**Done the same day** (DESIGN, "`ai = true` under `[capabilities]`, said in the spec and in the refusal"): the spec
says among the `[capabilities]` answers that whether the app has an AI feature is `enabled` under
`[capabilities.ai]`, and `sv`'s refusal says the same in plain words, for `ai = true` alone and for `ai = true` with a
`[capabilities.ai]` header below it (toml's "duplicate key"). Whether the sentence works is for the next trial that
counts unreadable files.
