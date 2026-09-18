# SecureVibe — Incident Response Plan

SecureVibe runs on one person's computer. This plan is written for that person (the owner) and covers both ordinary
security incidents and the AI-in-pipeline scenarios described by OWASP AISVS Appendix C (AC.14.1).

## Roles

* **Owner** — the person running SecureVibe. Decides, contains, and records.
* **Developer (optional)** — anyone the owner asks for help. Gets the security report and run logs.
* **Anthropic support** — for suspected misuse of the API key: revoke the key in the Anthropic console first.

## What counts as an incident

* Your Anthropic API key was exposed (in a screenshot, a shared file, a log you posted, a compromised machine).
* A generated application behaved unexpectedly during a build (tried to reach the network, wrote outside its folder,
  ran for a very long time) or a build produced code you did not ask for.
* A report or the audit log shows prompt-injection attempts you did not write (in wizard text, in generated files).
* A dependency vulnerability with a known exploit is reported for an app you are already using.
* Someone else used SecureVibe on your computer, or a web page tried to talk to it (look for `403` entries with
  `host_mismatch`/`origin_mismatch` in the server log).

## Steps

1. **Stop.** Cancel any running build in the UI (Stop button) or close SecureVibe. This aborts the AI request and kills
   any generated-app processes.
2. **Revoke and rotate secrets that touched the run.**
   * Anthropic API key: revoke it in the Anthropic console and create a new one. Update your `.env`.
   * Generated app secrets (`workspace/projects/<id>/app/.env`): run `npm run gen-secrets` inside the app folder and
     restart the app; users will need to sign in again.
3. **Quarantine artifacts.** Move the affected project folder (`workspace/projects/<id>`) to a folder called
   `quarantine/` and do not run the app from it. Keep it for investigation; do not delete it.
4. **Preserve evidence.** Copy `workspace/llm-audit.jsonl`, the run folder `workspace/projects/<id>/pipeline/<runId>/`
   (stage logs, stored prompts/responses, fixes) and the reports. Note the time and what you observed.
5. **Identify what was produced under suspicion.** `securevibe.provenance.json` in the app folder lists every file with
   its origin (template / expanded / AI-generated / AI-fixed / user), correlation ids and the model that served it. Use
   the run id and correlation ids to find the exact prompts in the run folder.
6. **Notify** anyone who uses an affected generated application. Tell them what happened, whether their data may be
   affected, and when it is safe to use the app again. If personal data may have been exposed and a law applies to you
   (for example GDPR in the EU/UK), you may need to notify a regulator within a deadline — check with an adviser.
7. **Recover.** Rebuild the application from the design with a fresh API key (Rebuild in the UI) or verify a manual fix
   with `npm run verify`. Compare the new provenance with the quarantined one.
8. **Learn.** Add what you learned as a note in the project's attestations, and if a wizard answer was wrong, correct it —
   the design-drift watch will flag what changes.

## Time targets

* Revoke a leaked API key: within 1 hour of noticing.
* Rotate generated-app secrets and restart: within 1 day.
* Re-run the full verification pipeline on any app you keep using: within 7 days.

## Rehearsal

Once a year (or before you rely on an app for something important), walk through steps 1–7 with a throw-away project
and record the date in the project's attestations ("Incident plan rehearsed on …"). The compliance report's Secure by
Design control **MT-06** turns from "No" to "Yes" only when this attestation exists.
