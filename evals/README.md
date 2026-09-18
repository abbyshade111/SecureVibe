# Evaluation harness

A fixed set of "golden apps" that SecureVibe builds and checks the same way every time, so a change to the
template, the pipeline or the prompts can be judged by its effect on real builds rather than by hope.

- `golden/*.json` — one saved set of wizard answers per app (a `DesignProfile`). Add a file to add a golden app;
  keep them varied (with and without sign-in, uploads, AI features, payments) so template branches are exercised.
- `baselines/<app>.<no-ai|ai>.json` — the metrics of the last accepted build of each app. Committed.
- `results/` — the full record of every harness run, one file per run. Not committed.

## Running it

```bash
npm run eval
```

builds every golden app **without AI** (free; the template only) and compares each with its baseline. Good for a
nightly run. Options:

- `--only <app>` — one app (the file name without `.json`), may repeat
- `--update` — save this run's metrics as the new baselines (do this after a change you meant to make)
- `--ai` — let Claude write the features too. Costs money (`--max-usd <n>` caps each app); for before a release.
- `--keep` — keep the scratch workspace so the built apps can be looked at

The exit code is 1 when any app regressed or did not finish. What counts as a regression is in
`server/src/eval/metrics.ts` (`compareMetrics`): the build no longer succeeds, a step fails, more open
critical/high/medium problems, verified ASVS/AISVS coverage drops, more failing requirements, fewer passing app
tests, or planned features that were built before and are not now. Cost and time changes are reported as notes.
