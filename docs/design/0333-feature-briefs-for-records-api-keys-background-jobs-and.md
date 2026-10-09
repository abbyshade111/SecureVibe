# Feature briefs for records, API keys, background jobs, and organizations (9 October 2026)


Finding 22(f) of the gap analysis of 7 October 2026 (BACKLOG, "From the gap analysis of 7 October 2026").
`stackvet.toml` asks whether an app has API keys for other programs, background jobs, and several customer
organizations, and its `owned` setting tests records each person keeps, but `sv brief` and `stackvet_before` had no
brief for any of them. An AI coding tool about to build one was given nothing to decide first and nothing to be held
to.

**What changed.** Four briefs in `data/feature-briefs.json`, each naming only conditions, requirements, prompts,
coding-rule topics, and settings that already exist:

- `owned-records`, records each person owns or shares: who may open and change each record and each of its fields
  (V8.1.1, V8.2.2, V8.2.3, V8.3.1), the fields a request may set (V15.3.3) and an answer may give back (V15.3.1),
  saved text written back into a page (V1.2.1), and the limit on how fast records are made (V2.4.1). It names no
  condition: `auth`, the only one near it, would bring all of sign-in, which has its own brief. Its settings are the
  test accounts, `owned`, `creates`, `browser`, and `requests-per-minute`.
- `api-keys`: who a key lets in, to what, and how fast (V8.2.1, V8.2.2, V8.3.1, V2.4.1), and a key made
  unguessable (V11.5.1). It names no condition either: `public-api` is asked, and no applicability rule keys on it,
  so naming it would promise requirements that never come. Its one setting is that answer, `public-api`.
- `background-jobs`: the three Secure by Design controls gated on `scheduler` (durable messaging, a job safe to run
  twice, defined delivery), with whole-or-nothing changes (V2.3.3), work that cannot starve the app (V15.2.2), and a
  job acting with the permissions of the person it acts for (V8.3.3, level 3).
- `organizations`: what `multi-tenant` gates (V8.4.1, and AISVS C5.3 for an assistant the organizations share), with
  the authorization rules written down (V8.1.1) and record-level access (V8.2.2). Its settings are the answer and the
  two test accounts with `owned`. Those accounts may well belong to one organization, so the cross-user check is the
  nearest `sv run` comes, not a test that organizations are kept apart.

The MCP tool's list, its description, the server's instructions, and the README name the four.

**A new rule for every brief.** A condition a brief names must gate at least one requirement, and a requirement a
brief lists by hand must not be one its conditions already bring, so the list says only what a condition cannot.

**What it does not change.** A brief credits nothing, as before. No requirement is cited by a check that was not
before, and no applicability rule changed: whether `public-api` should bring requirements of its own is a separate
question, left open here.
