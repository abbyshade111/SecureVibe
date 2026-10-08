# Claims nothing can check

Every capability in `securevibe.toml` is a claim, and `data/claim-corroborators.json` says how each one
is checked against the code. Twenty-six claims have a corroborator. One does not, and that is written
down rather than left to look like a search that found nothing.

`shared-hostname` asks whether another application answers on the same address. That is a fact about
where the app is deployed: the same repository is one site on its own hostname in one deployment and one
of five behind a shared proxy in another, and the reverse-proxy configuration that would settle it is
almost never in the app's own repository. A signature that went looking would report "nothing found" on
every app, forever, which reads as a search rather than as a question nobody here can answer. So the
signature carries `noCorroborator` and a reason, `sv` reports it as *no check for this is possible*, and
a test refuses any such signature that also names things to look for.

The corroborators are checked three ways, because a corroborator that never matches anything fails
silently: every language and ecosystem key must be one the scanner actually dispatches on (a misspelled
key is simply skipped, leaving a dead rule that looks like an honest "not found"); every corroborator
must have a witness; and each witness is a file written the way somebody would really write it, not a
copy of the pattern out of the data file.

Writing those witnesses found a fault older than this work. Files with no extension — `Dockerfile`,
`Jenkinsfile`, `CODEOWNERS`, `Procfile` — were skipped by the walk *before* their path was recorded, so
no signature naming one could ever match. For `iac`, which is allowed to rule itself out by absence, that
turned "I did not look" into `Some(false)`: an app whose only infrastructure configuration was a
Dockerfile sitting beside its source was reported as having none at all.
