# Find the asked! check that falls silent against a real app in CI, and make it say what it found

**Status:** done, 8 October 2026

The guard added on 8 October 2026 (`Said::held`, `docs/design/0310-a-check-that-asked-says-what-it-found-8-october-2026.md`)
panicked in CI's `test` job, which starts the example apps in Docker, until the panic was limited to sv-check's own
tests. So at least one check marked `asked!` sends a real app requests and then names none of its requirements, by a
path the fake app never takes. The report now says "A check asked the app about this and returned without saying what
it found" there, which is honest, but the check itself should say what it found.

To do: run the tests that start real apps with a container backend, find the check the report names, make its silent
return path say what it found (a finding, a credit, or a not-assessed entry with a specific reason), and add a fake-app
test that takes the same path, so sv-check's own tests catch it from then on.
