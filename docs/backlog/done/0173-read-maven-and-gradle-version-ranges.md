# Read Maven and Gradle version ranges

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

The lockfile check reports them as not assessed, because
pinning lives in `pom.xml` and `build.gradle` rather than a lockfile. Reading a range out of either
would turn an open question into an answer. **Claimed on 26 September 2026 by session relaxed-nobel-27acfa.
Done the same day.** `sv-scan::jvm` reads each build's versions, including properties, parents in the
folder, Gradle variables, and version catalogs. All exact passes V15.1.2, a range, `LATEST`, `1.+`, or
a snapshot is a finding at its line, and a version `sv` cannot work out stays not assessed, with the
line. The entry was also wrong about Gradle: only Maven was not assessed. A Gradle build without
`gradle.lockfile` was reported as pinning nothing even when every version was exact, and that finding
is gone. See DESIGN, "Reading Maven and Gradle versions".
