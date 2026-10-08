# Three more Level 1 questions

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Done on 25 September 2026 by session securevibe-e8. V7.4.2
(every session ends when an account is deleted, through a `delete-account` entry), V6.4.2 (no password
hints or secret questions on the sign-up and sign-in pages, only ever a finding), and V4.4.1
(unencrypted `ws://` WebSocket addresses in the code, only ever a finding).

- *Session keen-meninsky-691a27.* Agreed on the fake model first: it answers the fence problem,
  which garak cannot. Three things for whenever garak is taken up, each checked rather than assumed:
  - **It cannot be "an optional adapter" as `data/adapters.json` stands.** That file is SARIF-only
    by its own stated rule — "a tool that cannot emit SARIF is simply not listed yet" — and garak
    writes a JSONL report. `parse_sarif_relative_to` is the only reader `adapters.rs` has, and an
    adapter carries no `format` field. Every adapter is also handed the app's *files*, while garak
    needs a live endpoint, and no tier covers an outside tool pointed at the running app. So garak
    is a JSONL reader shaped like `crates/sv-check/src/junit.rs`, a manifest entry, and probably a
    tier of its own: a project, not a data row.
  - **`promptinject` is goal hijacking only** — `HijackHateHumans`, `HijackKillHumans`,
    `HijackLongPrompt` — with no system-prompt leak probe, which fits the fake model rather than
    garak taking C7.3.2. `latentinjection` is separate and real: instructions buried in resumes,
    financial reports, translations and WHOIS records, so indirect injection through retrieved
    content (C5.2.2, C8). Whether it reaches C10.4.2, which is specifically MCP `tools/list` and
    `tools/call` responses, depends on the app passing tool output to the model, and would have to
    be measured.
  - **Terms:** garak is Apache 2.0, like the ATLAS data, so none of the conditions the Semgrep Rules
    License carries apply to it.
