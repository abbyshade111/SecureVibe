# `sv check`: the first findings

`sv check ./app` looks for credentials left in the code. It is the first part of `sv` that produces findings
rather than scope, which makes it the first part where being wrong costs an owner something directly.

Two kinds of rule, split on purpose. The **pattern** rules live in `data/secret-rules.json` — ported from
v1's `scanners/secrets/rules.ts`, with their ASVS, AISVS and SbD ids intact — because a well-known credential
format is data, and adding Azure or Twilio should be a data-file entry rather than a Rust change. The
**judgment** rules are Rust, because deciding whether a high-entropy string is a credential or a content
hash is not something a regex can do.

### What stops it being noise

A scanner people ignore is worse than no scanner, so three things are load-bearing:

* **A placeholder is not a secret.** `your-api-key-here`, `changeme`, `${SESSION_SECRET}`, `<your token>` are
  what a template looks like. An owner whose first run shouts at `.env.example` learns on day one that the
  findings are noise. There is a test that runs a whole realistic example file and requires silence.
* **`.env` is meant to hold real credentials**, so the judgment rules do not run there. The pattern rules
  still do, because a vendor key is exactly what matters if that file turns out to be committed.
* **One secret is one finding.** A vendor key assigned to a well-named variable matches both the vendor rule
  and the generic assignment rule; the vendor rule wins, because it can say what the credential is and how to
  revoke it. This showed up on the first real run, reporting the same Stripe key twice.

### Two things it refuses to do

**A secret never travels in a finding.** `Secret` cannot be built with the value visible — it redacts on
construction and there is no accessor that gives the original back, so a report, a log or a SARIF file
cannot carry the credential onward. Removing the redaction fails five tests.

**Nothing unread is counted as clean.** Files that are binary, too large, or unreadable are listed with the
reason, and `sv check` prints that list *before* the findings, because a short list of findings under a long
list of skipped files is a different result from a short list of findings. Where nothing is found at all it
says so in as many words: these rules know a list of formats and one heuristic, and a credential in a shape
nobody listed would not be found.

### What it looked like on a planted key

    Read 5 files looking for credentials, against 8 known formats plus the assignment rule.

    1 file was not read, so nothing is claimed about it:
      src/logo.png — not a text file

    2 things to look at:

      [critical] Stripe key found in a file
         src/config.py:5
         found: sk_l… (32 more characters)
         evidence about: V13.3.1, AC-05, AC-06

### Configuration checks, and the one that matters most

v1 has nineteen configuration checks and most are about its own template: whether `package.json` was
modified, whether the session policy matches the profile, how many proxy hops to trust. None of that means
anything for an app somebody else wrote. What survives being language-agnostic is small, and one of it is
worth more than everything in the secrets scanner:

**A credential in a file is a problem. A credential in version control is a different problem.** History
keeps it after the file is fixed, and every clone, fork and backup already has a copy. `sv check` can find
a key in `.env`; only git can say whether `.env` was ever committed — so it asks, and the finding's fix
leads with *change the credential*, because that is the part that actually protects anybody.

Three checks so far: a secrets file in version control (critical), nothing in `.gitignore` stopping one
getting there (high), and no way to report a security problem (low).

### A check reports one of three things

Passed, failed, or **not assessed** — never two, and never the third folded into the first. A folder that
is not a git repository is the ordinary case for an app somebody handed over, not an error, and answering
"no committed secrets" there would be a claim about history nobody read. `sv check` prints what could not
be checked *before* what was found, for the same reason the secrets scanner prints skipped files first.

Both ways the question can go unanswered have their own test — a missing `.git`, and a `.git` that git
refuses to read — because they are different code paths and the first one alone left the second untested.

An app can be a folder inside a larger repository, so the `.git` is looked for in the app's folder and every
folder above it. Only the files under the app's folder count: git is asked from inside it, and lists just
those. A secrets file committed elsewhere in the same repository belongs to something else and is not
reported against this app. The `.gitignore` check reads only the app's own `.gitignore`, so an app in a
subfolder with none of its own is not assessed rather than failed, since one in a folder above it may
already leave out `.env`.

### The lockfile check, and the wrong statement it was one call away from

`sv-scan::ecosystems::unpinned` already worked out which ecosystems have no lockfile, so reporting it
looked like wiring. It was not. Maven has no lockfile to be missing — versions live in `pom.xml` — so
`unpinned` returned "Java (Maven)" for every Maven project, and a check that asked "is there a lockfile?"
would have told every Java owner their app pins nothing.

That is not a coverage gap, which is honest and visible. It is a wrong statement in a report, and an owner
acting on it would go looking for a lockfile Maven does not have. The same shape as telling a Flask app it
was missing `package-lock.json`, which is the incident v1's ADR-012 was written for.

So `DetectedEcosystem` now carries `pins_with_lockfile`, `unpinned` only returns ecosystems that pin with
one, and Maven comes back **not assessed** with a reason: versions live in the manifest and `sv` does not
read ranges out of it yet. Removing that distinction fails two tests — one that Maven produces no finding,
and one that it does not silently pass either, because not reporting something must not mean approving it.

### Reading Maven and Gradle versions

Done on 26 September 2026 (session relaxed-nobel-27acfa). The "yet" above is answered: `sv-scan::jvm`
reads the versions a `pom.xml`, `build.gradle`, or `build.gradle.kts` names, and `ecosystems::pinning`
says for each project how it pins, if it does.

Doing it turned up the same wrong statement a second time, in Gradle. Its `gradle.lockfile` is something
a project turns on, not something every project has, so a Gradle build with only exact versions and no
lockfile — which installs the same thing every time — was reported as pinning nothing, with a Medium
finding telling the owner to commit a lockfile. Now each version lands in one of three places:

* **Exact:** `1.2.3`, `[1.2.3]`, or Gradle's `1.2.3!!`. The same goes for a version given by something
  exact: a parent POM, a BOM, a Gradle platform, Spring's dependency-management plugin, or the Kotlin
  plugin for Kotlin's own libraries. A reference to the project's own version is a dependency on one of
  its own modules and counts as exact too. Every one exact is a **pass** for V15.1.2.
* **Floating:** a range, Maven's `LATEST` and `RELEASE`, Gradle's `1.+` and `latest.release`, and a
  `-SNAPSHOT`, which is republished under the same number. Any one is a **finding** at its line, naming
  the dependency and the version as written and as resolved (`${lib.version} = [1,2)`). The fix says to
  write exact versions, or for Gradle to turn on dependency locking. A Gradle build with a lockfile
  passes as before, whatever it names, because the lockfile is what pins it.
* **Unsettled:** a property set in a parent outside the folder or on the command line, a variable `sv`
  cannot find, a catalog entry that is not there, a dependency with no version and nothing to give one,
  or a line that names a coordinate in a way it does not read (`add("implementation", …)`). This stays
  **not assessed**, and the reason lists up to three of them with their lines.

What is read: properties from the POM and from its parents while they are inside the app folder (the
file at `relativePath` counts only if it is the project the parent section names); Gradle variables
from the build file and from `gradle.properties` up to the app folder; and the version catalog
`gradle/libs.versions.toml`, through its aliases, `version.ref`, rich versions, and bundles. Comments are
blanked before anything is read, keeping line numbers, so a commented-out `LATEST` is not a finding.

What is not, and is said here rather than claimed away:

* **Only the versions this build names.** A library that asks for a range of another library can still
  move underneath an app whose own versions are all exact. That is rare on Maven Central, where
  published POMs do not change, but it is why a lockfile is still the stronger answer and the fix for
  Gradle mentions one.
* **Build plugins are left out:** Maven's `<build>` and `<reporting>`, including a plugin's own
  dependencies, and Gradle's `plugins {}` and `classpath`. They build the app and are not shipped in it.
* **Gradle is read as text,** line by line inside `dependencies {}` blocks, not run. A build that
  computes its coordinates in code is not guessed at. The guard is that any line in those blocks that
  names a coordinate `sv` did not read is *unsettled*, never skipped.

Eleven breaks, each now caught by a test written for it: a range, a `+`, and a snapshot counted as
exact; an unknown property counted as exact; comments read; Gradle judged by its lockfile alone;
unread lines skipped; build plugins read; a platform ignored; and a missing version counted as exact,
in Gradle and in Maven. Three got through the first time. Build plugins were caught by nothing, because
the fixture's plugin had a version but no dependency of its own, so the guard had nothing to guard. A
snapshot was caught only by a unit test. A missing Gradle version was caught by nothing. Each has a
fixture now.
