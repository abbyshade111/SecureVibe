# Dependencies `sv` does not read are named, and hold back the credit (8 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 1.5; BACKLOG, item 2; ADR-037, Later). `sv` reads the dependency files
of npm, Python, Go, Rust, Ruby, PHP, and Java. A .NET, Dart, Swift, Elixir, or Deno app's were not even found: a .NET
app was told "No package manifest was found", and a mixed app had V15.2.1 (no component with a known vulnerability)
credited on its npm half while an old Newtonsoft.Json was pinned in its `.csproj`.

- **Found, not read.** `unread_declarations_in` (`crates/sv-scan/src/ecosystems.rs`) finds `*.csproj`, `*.fsproj`,
  `*.vbproj`, `packages.config`, `Directory.Packages.props`, `pubspec.yaml`, `Package.swift`, `mix.exs`, `deno.json`,
  and `deno.jsonc` anywhere `sv` reads, naming the ecosystem's lockfile when one is beside it. Reading them is not
  part of this.
- **The bill of materials** names each as unread: "`Api/Api.csproj` declares .NET (NuGet) dependencies, and `sv` does
  not read that file, so none of its packages is listed or compared with known vulnerabilities". The list is then not
  complete, which already holds back V15.2.1 and raises "The list of what this app ships is not complete".
- **The pinning check** says which file declares dependencies it does not read, and does not pass while one is there,
  so V15.1.2 is not credited on the ecosystems it did read.

Tests: `dependency_files_sv_does_not_read_are_found` (`crates/sv-scan/tests/scan.rs`) and
`dependencies_sv_does_not_read_are_named_and_never_pass` (`crates/sv-check/src/config.rs`), each ecosystem beside a
locked npm app and alone, with the locked npm app alone as the control. Five guards broken in turn, each caught: not
named in the bill of materials, the pinning check passing beside one, "No package manifest" when alone, a `*` that may
match nothing, and Deno left out.
