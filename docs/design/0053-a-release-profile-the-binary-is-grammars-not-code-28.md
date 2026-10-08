# A release profile: the binary is grammars, not code (28 September 2026)

Review item 10 said `Cargo.toml` sets no release profile, the binary is 35.6 MB, and the usual
settings for a shipped tool (`lto`, `codegen-units = 1`, `strip = true`) "typically halve the size".
Measured before anything was changed, that expectation was for a different kind of program. A clean
release build of `sv` on the owner's Mac takes about 40 s and gives a 35.7 MB binary, of which 4.9 MB
is code (`__text`) and 27.2 MB is constant data (`__const`). The constants are the parse tables of the
fifteen tree-sitter grammars: compiled, their libraries total 34.9 MB, C# alone 5.6 MB, Swift 5.3, C++
3.8, Kotlin 3.6, TypeScript 3.4. The JSON compiled in is two small files (the breached-password
evidence and the ATLAS references); the frameworks and the rules are read from `data/` when `sv` runs.
Nothing a compiler setting does to the code can halve a binary that is four-fifths tables.

**Measured**, each a clean build, the same commit, seven runs of each binary on the same inputs,
median:

| Profile | Binary | Clean build | `sv check`, five-file app | `sv check`, this repository |
|---|---|---|---|---|
| None (before) | 35.7 MB | 41 s | 45 ms | 1608 ms |
| `lto`, `codegen-units = 1`, `strip` | 33.3 MB | 71 s | 43 ms | 1607 ms |
| `strip` only (chosen) | 34.5 MB | 30 s | 45 ms | 1606 ms |

Link-time optimization took 1.4 MB more off than stripping alone and made every clean build, on CI and
in the Docker image, half a minute longer, for no change in speed anyone could measure. The time `sv`
spends is in tree-sitter and in reading files, not in calls between crates, which is what link-time
optimization removes. So the profile keeps `strip = true`, which costs nothing, and nothing else. The
difference between 41 s and 30 s for the two builds without it is the variance of a clean build, not a
gain. Panics still unwind: `sv-run` tears a run's containers down in a `Drop`, which `panic = "abort"`
would skip.

**What would make it smaller.** Only fewer grammars, or the grammars loaded from files beside the
binary instead of compiled into it. Both are product decisions, not build settings: `sv` checks an app
in any of the fifteen languages without being told which, and the Docker image and the "download
later" packaging carry `data/` already, so grammars on disk are possible. Neither is proposed here; 35
MB is a small download, and a smaller one was the whole of the item's reason.

**What holds it.** Nothing to break: a profile is not a check, and there is no test that reads
`Cargo.toml`. CI's image job builds the release binary and drives it (`tools/image_smoke.py`), so a
profile that produced a binary that does not run would fail there.
