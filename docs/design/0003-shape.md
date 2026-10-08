# Shape

```
sv-cli          the `sv` binary: check, init, report, explain
sv-manifest     securevibe.toml — parse, validate, the spec `sv init` prints
sv-frameworks   loads the OWASP JSON; the applicability engine
sv-corroborate  claims vs. code; the four states above
sv-scan         language-agnostic scanners: secrets, config, lockfiles/SBOM, tree-sitter AST rules
sv-adapters     per-language tooling, driven by a data file and not by Rust
sv-compliance   evaluation, evidence tiers, traceability, test-name matching
sv-run          the container runner and the DAST probes
sv-report       compliance and security reports, SARIF
```

### Why the adapters are a data file

Adding Python support should be adding a manifest entry, not writing a crate. An adapter says what tool to run,
how to recognize it is installed, how to parse its output into the common finding shape, and which ASVS
requirements its findings bear on:

```toml
[[adapter]]
id = "ruff"
ecosystem = "Python"
detect = { file = "pyproject.toml" }
probe = ["ruff", "--version"]
run = ["ruff", "check", "--output-format", "json", "."]
parse = "ruff-json"
stage = "lint"
```

A tool that is not installed is reported as **not run**, never as a clean pass. That is v1's ADR-012 rule applied
to tooling instead of to ecosystems.

### Running the code

v1 gets its strongest evidence by running the app: seeded users, DAST probes, the generated test suite. Keeping
that across arbitrary stacks means the manifest declares build/start/test, and `sv` runs them in a container with
the network fenced to loopback, exactly as `pipeline/net-fence.ts` does for a child process today.

A container backend is available on this machine as of 22 September 2026: Colima 0.10.3 with Docker 29.8.1,
serving a linux/aarch64 daemon on two CPUs and 2 GB of memory. Those are Colima's defaults and they are modest —
an app whose test suite wants more will need `colima start --cpu 4 --memory 8`, and `sv-run` should say that a
run was resource-starved rather than report it as a failing one.

`sv-run` is still built behind a trait, because a machine with no backend is the normal case for anyone else
running `sv`. Where none is present, every dynamic requirement reports `not assessed` — not `pass`, and not
`fail` — and the reports say which applied, as v1's do.
