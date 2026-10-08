# Say when a manifest and its lockfile disagree

**Status:** done, as its markers read on 8 October 2026

Found on 3 October 2026. **Claimed the same day by session
securevibe-e2**, at the owner's asking to continue with the backlog, in branch
`claude/securevibe-e2-manifest-lock`. **Done the same day** (DESIGN, "When a manifest and its lockfile
disagree"): `requirements.txt` and `package.json` are held to their lockfiles, package by package; a disagreement
is named in the bill of materials, `sv sbom`, `sv audit`, and the report, and withholds the clean known-vulnerability
claim. Not a finding. Other manifests are not compared yet. Nineteen guards broken in turn, each caught.
**The other manifests (`pyproject.toml`, `Cargo.toml`, `go.mod`, `composer.json`, and `Gemfile`) claimed the same
day by session securevibe-e2**, at the owner's asking to continue with the backlog, in branch
`claude/securevibe-e2-more-manifests`. **Done the same day** (DESIGN, "When a manifest and its lockfile
disagree", its last part): all five are held to their lockfiles, each with its own package manager's range rules.
Gradle's files are not compared yet. Thirty guards broken in turn, each caught.
**Gradle's `build.gradle` and `build.gradle.kts` claimed the same day by session securevibe-e2**, at the owner's
asking to continue with the backlog, in branch `claude/securevibe-e2-gradle-lock`. **Done the same day** (DESIGN,
"When a manifest and its lockfile disagree", "Gradle, added last"): a plain version is the least Gradle uses, so
only an older locked version disagrees. Thirteen guards broken in turn, each caught. On
23 September Dependabot bumped `examples/flask-booking/requirements.txt` (`517279a9`) and left
`requirements.lock` alone. GitHub reads only the manifest; `sv` reads the lockfile when there is one
(`crates/sv-check/src/sbom.rs`). So for ten days the two described different apps: GitHub saw PyJWT
2.13.0 and opened 13 alerts against it on 2 October, while `sv` checked flask 3.0.0, gunicorn
21.2.0, authlib 1.3.0 and pyjwt 2.8.0. Nothing noticed until a person asked. Fixed for the example
in #482; nothing stops it happening in an owner's app.

**Why it matters to the owner.** A known-vulnerability result describes the file it was read from.
When the manifest and the lock disagree, whoever deploys from the other one runs versions the
report never looked at. The error runs both ways: a vulnerability in what is really installed goes
unreported, or one is reported in versions nobody runs.

**What exists already.** `passed_over` in `crates/sv-scan/src/ecosystems.rs` names a second
lockfile that was not read, "because two lockfiles can disagree". Nothing compares a manifest with
the lockfile beside it.

**What to build.** For each package the manifest pins exactly (`==`), compare it with the
lockfile's version, and say so beside the bill of materials when they differ: which file the
report describes, and each package where the other file says something else. A range in the
manifest (`flask>=3`) disagrees only when the lock's version falls outside it. Whether a
disagreement is also a finding, and against what, is for whoever builds it to decide. V15.1.2 — an
inventory "of all third-party libraries in use" — is the closest fit, but a lock that disagrees
with its manifest shows the inventory may be wrong, not that it is missing.

It is likeliest where nothing keeps the two in step: a `requirements.lock` compiled once and then
forgotten, as here. Witnesses needed in both directions — the lock older than the manifest, and the
manifest older than the lock — plus a range the lock satisfies, which must stay quiet.
