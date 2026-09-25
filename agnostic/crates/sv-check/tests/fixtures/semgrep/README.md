# Semgrep fixture

`semgrep-1.178.0.sarif` is the real output of Semgrep OSS 1.178.0 run over `app/`, a small Flask app
and Go program with one of each kind of fault in it. `crates/sv-check/tests/adapters.rs` checks the
semgrep rule map in `data/adapters.json` against it, so the map is tested against what the tool writes
rather than what its documentation was read to say.

## How it was made, and the one thing it could not observe

The adapter runs the registry pack `p/security-audit`. The registry could not be reached from where
this was written, so the rules came from a checkout of https://github.com/semgrep/semgrep-rules
(commit a84ff9c, 22 September 2026), the source the registry is built from.

Rule ids differ by how rules are loaded, and that was measured, not assumed:

- Loaded from a folder, semgrep prefixes each rule's own id with the folder it sits in, so the file's
  name drops out: `go/lang/security/audit/crypto/use_of_weak_crypto.yaml` holding `use-of-DES` is
  reported as `go.lang.security.audit.crypto.use-of-DES`.
- The registry names a rule by its file's path and its id together:
  `go.lang.security.audit.crypto.use_of_weak_crypto.use-of-DES`, and
  `python.lang.security.audit.eval-detected.eval-detected` for a file holding one rule of the same
  name. This form is what the registry's rule pages use, and it is what the map is keyed on.

So each rule file was copied into a folder of its own name
(`…/use_of_weak_crypto/use_of_weak_crypto.yaml`), which makes semgrep's own prefixing produce the
registry's form. Semgrep did the matching; only the folder layout was arranged. Run against the
registry, this should give the same ids, and that is worth confirming once on a machine that can
reach it:

    cd app && semgrep scan --config p/security-audit --sarif --output /tmp/registry.sarif --quiet .

The run behind the kept file, from a folder holding the rearranged rules and a copy of `app/` (semgrep
skips anything under a `tests/` folder, so it cannot be run in place):

    semgrep scan --config <each rule folder that fired> --metrics=off --disable-version-check \
      --sarif --output semgrep-1.178.0.sarif --quiet app

Only the rule folders that produced a result were loaded for the kept run, because SARIF carries the
full description of every rule loaded: with all of Python's and Go's it was 725 KB, and gave the same
35 results.
