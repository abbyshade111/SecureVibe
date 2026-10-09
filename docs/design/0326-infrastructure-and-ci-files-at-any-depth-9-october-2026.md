# Infrastructure and CI files at any depth (9 October 2026)

The corroborators half of the gap analysis's finding 16 (7 October 2026). `iac` and `ci-cd` are the two claims a
missing file answers: "nothing found" agrees with an owner who said "no". So a file looked for in the wrong place
turns into a "no" the app's own repository contradicts.

**Where.** `Dockerfile`, the compose files, and `Chart.yaml` were looked for only at the root. Many apps keep them a
folder down: `deploy/Dockerfile`, `docker/compose.yml`, `charts/app/Chart.yaml`. A file pattern written `**/name` now
matches a file or folder of exactly that name at any depth. `docs/MyDockerfile` does not match, and a Dockerfile
inside `node_modules` is not counted, because the scan does not enter that folder.

**What.** Added to `iac`: `compose.yaml`, `compose.yml`, `Containerfile` (Podman's name for a Dockerfile), all at any
depth, and `cdk.json` (the AWS Cloud Development Kit). Added to `ci-cd`: `.travis.yml`, `cloudbuild.yaml` and
`cloudbuild.yml` (Google Cloud Build), and the `.buildkite` folder.

Held by `crates/sv-scan/tests/corroborators_any_depth.rs`, with a control app that has none of the files and is still
answered "nothing found". Broken two ways: matching `**/` at the root only failed the two any-depth tests; matching
any path that ends in the name failed the look-alike test. Recorded in ADR-015, Later, 9 October 2026.
