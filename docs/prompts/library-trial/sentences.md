# The three sentences (7 October 2026)

Run to `sentences-protocol.md`, fixed before any build: the three sentences added to prompts on 7 October 2026, each
from what an earlier trial found, ten builds an arm. Every build was checked by `sv report --run` from one release
build of `main`, `7339e017`. **$10.59** of the owner's API credit ($4.36, $3.91, $2.33). No transcript holds the key.

## Results, by the protocol's rule

| Prompt, with its new sentence | Model | Without it | With the earlier text | With the new sentence | Verdict |
|---|---|---|---|---|---|
| `password-rules`: use `zxcvbn`'s list | Sonnet 5.5 | 10 of 10 | 8 of 10 | **0 of 10** | **shown** |
| `production-server`: one worker with SQLite | Sonnet 5.5 | 5 of 10 | 0 of 9 | **0 of 9** | **shown** |
| `isolate-the-window`: headers on Python's own error pages | Haiku 4.5 | 7 of 7 | 4 of 10 | **0 of 9** | **shown** |

"Without it" is the baseline the protocol names: the recipe trial's Sonnet builds and the revision trial's Haiku
builds, made with an earlier `sv`. "With the earlier text" is the same prompt before its sentence, from the same
trials. **Harm: none by the rule**, which looks for an arm three or more below its baseline. Apps started and signed in
to: `password-rules` 10 and 10 (baseline 10 and 10), `production-server` 9 and 9 (baseline 10 and 10, the one short a
crash of the app's own), `isolate-the-window` 9 and 6 (baseline 7 and 5).

## What lies under the verdicts

- **`password-rules`: every build pinned `zxcvbn`**, and every app refused all three common passwords `sv` now tries
  (ADR-055), with a random one of the same shape accepted. The check was stricter than the baseline's, which tried one
  word, so the comparison is harder for the prompt, not easier. The earlier text, which asked for a list and named no
  source, was followed in every build of the recipe trial, from memory, and left 8 of 10 short.
- **`production-server`: the sentence did what it was for.** No app stopped for "database is locked", which stopped
  one of ten with the earlier text. The one app that did not start crashed on a fault of its own code
  (`TypeError: 'NoneType' object is not subscriptable`). The server's version was given away in none.
- **`isolate-the-window`: read by hand in builds 1, 4, and 7.** Builds 4 and 7 overrode `send_error` to send the same
  headers; build 1 never used `send_error` and wrote its own error pages. Both are what the sentence offers. Build 7's
  settings file could not be read (`ai = true` under `[capabilities]`, which `sv`'s refusal names and says how to fix),
  so it is not in the counts.

## What follows

- **`password-rules` is shown**, at the owner's word (7 October 2026), and now reaches every builder at the start
  (ADR-044).
- **`production-server` and `isolate-the-window` keep their new sentences**: each sentence is now tried and kept.
- **One arm a prompt, ten builds, against an earlier baseline** is the smallest trial the rule can read. The three
  agree with what each sentence was written to fix, and each comparison is said with its baseline.

## Files

`sentences-protocol.md`; `run_sentences.sh`; `score_sentences.py`; `sentences-verdicts.json`;
`sentences-summaries.txt` (each checked build's summary).
