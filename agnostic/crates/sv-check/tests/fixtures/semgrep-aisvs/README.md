# Semgrep's AI rules, run for AISVS

`semgrep-1.178.0.sarif` is the real output of Semgrep OSS 1.178.0 over `app/`: `assistant.py`, a small
help-desk assistant written with one of each fault, `assistant.js`, part of it again in JavaScript, and
`careful.py`, the same calls written the careful way. `crates/sv-check/tests/aisvs.rs` checks the AISVS half of the semgrep map against it.

The rules came from semgrep-rules a84ff9c (22 September 2026), each rule file copied into a folder of
its own name so that semgrep's prefixing gives the registry's form of the id, as for the kept run in
`../semgrep/` (whose README explains why). Eleven rule files were loaded:

    openai-user-input-in-system-prompt-python   openai-missing-max-tokens-python
    agent-unbounded-loop                        openai-missing-moderation
    langchain-dangerous-exec                    mcp-credential-in-response
    mcp-unsanitized-return                      openai-user-input-in-system-prompt-js
    anthropic-user-input-in-system-prompt-js    anthropic-missing-max-tokens-javascript
    cohere-safety-mode-off-javascript

    semgrep scan --config <each rule folder> --metrics=off --disable-version-check \
      --sarif --output semgrep-1.178.0.sarif --quiet app

run from a folder outside `tests/`, which semgrep skips when given a folder. Twelve results, eight in
`assistant.py` and four in `assistant.js`; none in `careful.py`.
