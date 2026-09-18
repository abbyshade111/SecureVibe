# AI Usage Policy for SecureVibe (AISVS Appendix C — AC.1.1 / AC.1.2)

This policy describes when and how SecureVibe uses AI (Claude, via the Anthropic API) to generate, review and fix code,
which data may be sent to it, and which security gates stay mandatory whether or not AI was involved.

## Approved tool

* **Claude** through the official Anthropic API only (`@anthropic-ai/sdk`). Default model `claude-opus-5`; the served
  model (including any server-side fallback) is recorded for every call.
* No other AI tools, plugins or MCP servers are used by SecureVibe.

## Where AI may be used

| Phase | AI use | Mandatory gate that does not depend on AI |
|---|---|---|
| Design (SbD steps 1–7) | infer a profile from a description (quick mode); a second-opinion design review; a STRIDE threat model | the profile's closed enums drive every security decision; inferences may only raise the posture; the owner confirms the summary |
| Implementation (step 9) | generate feature code inside the writable paths of the hardened template; fix P1/P2 findings | protected security files, tests, manifest and dependencies are not writable; hashes are re-verified; typecheck, lint, tests, static analysis, dependency scan, runtime scan run regardless |
| Verification | review code against applicable requirements with verbatim citations | AI evidence never produces a verified "pass"; citations are string-matched; deterministic checks decide |
| Reporting | none (reports are rendered from data) | — |

## Data that may be sent to the AI

* The design brief (derived from your answers), the security contract, the template's API reference.
* Source files of the generated application (`src/`, `tests/`, `docs/`), never its `data/` directory, `.env` files,
  keys or databases.
* Scanner findings and test output, wrapped as untrusted data.

Not allowed: your Anthropic API key, generated secrets, personal data stored by a running app, other projects on your
computer. Wizard free text is screened for prompt-injection phrases and length-limited before it is sent.

## Prohibited uses

* Running any command supplied by the model (the only checks are `typecheck`, `lint`, `test`, chosen by SecureVibe).
* Installing packages named by the model.
* Marking a requirement as verified on the model's word.
* Treating the AI second opinion as a human peer review, or the AI review as a human code review.

## Human involvement

* You approve every build explicitly, with a spending cap.
* Every generated file carries provenance (origin, run id, correlation ids, model, prompt hash).
* Reports state that AI-generated code has not been reviewed by a qualified human engineer until you record such a review.

## Adversarial scenarios this policy guards against (AC.1.3)

Prompt injection through wizard text or generated file contents; the agent weakening its own guard-rails; AI-generated
supply-chain payloads (blocked by the locked dependency set); the model approving its own work (impossible: deterministic
gates decide); leakage of secrets into prompts (deny-lists and redaction); runaway cost (budgets and caps).
See `docs/THREAT-MODEL.md`.
