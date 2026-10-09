# The published image signed (9 October 2026)


Backlog 0191, part 4 (the end-of-day write-up of 8 October 2026); ADR-080. The owner's decision of 9 October 2026:
yes to part 4, "with GitHub's own keyless signing, which costs nothing", and "as recommended" to the plan for part 6,
which puts it first.

**The problem.** `ghcr.io/abbyshade111/stackvet-sv` is pushed by CI on every change to `main`, and nothing let
somebody who pulled it check that it came from that run, rather than from whoever held a token that can push
packages. The GitHub Action (part 6) will pull it into other people's builds on every pull request.

**What is done.** The `publish` job in `.github/workflows/rust.yml` takes the digest of the image it just pushed and
hands it to `actions/attest` (GitHub's own, pinned to the commit of v4.2.2). That writes a SLSA build provenance
statement for the digest (this repository, the workflow, the commit), signs it with a short-lived Sigstore certificate
issued against the run's OIDC token, keeps it with the repository's attestations, and pushes it to the registry beside
the image. Both tags name the same image, so one statement covers `latest` and the commit's tag. The job gains
`id-token: write` and `attestations: write`; every other job stays read-only. The README says how to check it:
`gh attestation verify oci://ghcr.io/abbyshade111/stackvet-sv:latest --owner abbyshade111`.

**Where it differs from the plan.** `actions/attest` itself rather than `actions/attest-build-provenance`, whose own
README now says it is only a wrapper on `actions/attest` and that new setups should use that. No storage record
(`create-storage-record: false`): GitHub keeps those only for a repository an organization owns, and this one is a
person's, so asking would fail the job; that also leaves out the `artifact-metadata: write` permission they need.

**Not done.** No binary of `sv` is published, so none is signed; one that is published gets the same statement in the
pull request that publishes it. Images pushed before this carry nothing to check.

**How it was tried.** The job runs only for a push to `main`, so the first signing is that of the merge itself; the
statement is then read back from the repository's attestations for the digest `latest` names.
