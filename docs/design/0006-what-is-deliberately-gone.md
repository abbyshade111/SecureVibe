# What is deliberately gone

`templates/secure-web-app`, `generator/`, the recipes, the wizard, the React UI, the upgrade path. `sv` never
writes application code, so the generation agent and its fence go with them. Uploaded apps in v1 are "only ever
scanned, never run"; in `sv` every app is that app, except that a declared run command lets it be run in a
container the user consented to.
