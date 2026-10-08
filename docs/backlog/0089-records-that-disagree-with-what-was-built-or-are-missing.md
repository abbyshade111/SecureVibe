# Records that disagree with what was built, or are missing, found by the ADR analysis

**Status:** open

Found on 27 September 2026 by
session admiring-murdock-875699 while reading every decision record for the paper; the owner asked for each one
to be put here so it gets fixed. **Not claimed; each item can be claimed on its own.** **Items 5, 6, and the
Docker half of 8 claimed on 27 September 2026 by session securevibe-e8**, at the owner's asking to pick the
next item; the Rust half of 8 needs the owner's reasons, which nothing records. **Done the same day:** item 5 names
`sv probe` as the one exception in `README.md`, ADR-017, and `CLAUDE.md` (and the README adds the images
Docker downloads for `sv run`); item 6 restates the evidence rule in `sv`'s terms in `DESIGN.md`; and
ADR-019 records the container fence, replacing ADR-010's choice for `sv`. Items 1 to 4 are in v1's
records, which live on the `v1` branch: a fix there is a new commit on that branch (the tags `v1-paper` and
`v1-final` stay as they are, and history is not rewritten). Alternatively `docs/adr/README.md` here can record
the correction, as it already does for ADR-014's file name. Which of the two is the owner's call.
**The owner's answer, 30 September 2026: the note in `docs/adr/README.md`; and the Rust half of 8 is
written from the owner's reason, memory safety.** Items 1 to 4, 7, and the Rust half of 8 **claimed the same day
by session securevibe-e2**, at the owner's asking, in branch `claude/securevibe-e2-adr-notes`.
**Done the same day:** `docs/adr/README.md` has a section, "Where v1's records disagree with what v1 built", with
items 1 to 4 and 7, each checked again against the `v1` branch; and ADR-020 records Rust from the owner's reason,
with what memory safety does not cover in `sv` (five `unsafe` blocks, the C code parsers, and integer overflow in
the release build). Every item of this entry is now done.
1. **v1's ADR-012 cites "ADR-011's sibling change", and no record carries the number ADR-011.** The file named
   `ADR-011.md` is titled ADR-014, which `docs/adr/README.md` already explains, but the dangling ADR-011 in
   ADR-012 is not mentioned there. The change it means is `dca2e6c` ("Say what was read, and stop scoring code
   nobody read").
2. **v1's ADR-010 says generated code's network access is not restricted, and rejects `sandbox-exec`.** Two
   days later the network fence (`27b85e2`, 18 September) used `sandbox-exec` on macOS and a network namespace
   on Linux, and v1's `docs/CONTRACTS.md` describes it. ADR-010 was never updated, and v1's `README.md` still
   says "Network access is **not** restricted — the reports say so."
3. **v1's ADR-008 lists three AI providers** (`anthropic`, `null`, `scripted`). OpenAI and Google providers
   were added on 18 September (`7ecb4c3`, `71fae08`), with a choice of service per step (`4b947ac`), and the
   record was not updated.
4. **v1's ADR-013 contradicts itself on paper size.** Its decision says the PDF writer "lays it out on A4
   pages". Its cost section, updated by `2ef4149`, says US Letter is the default and A4 is a setting.
5. **`sv`'s `README.md` says "`sv` opens no network connection", and ADR-017 and `CLAUDE.md` say it opens
   none "of its own".** `sv probe <address>` has `curl` make a handful of read-only requests to the address the
   owner types (`crates/sv-cli/src/main.rs`, `cmd_probe`). That is deliberate, and it is the only exception,
   but none of the three says so. Name the exception in each.
6. **`DESIGN.md` says v1's evidence rule carries over "word for word" as "AI review alone is `ai-assessed`,
   never `pass`".** `sv`'s reports have neither status (they say *checked*, *needs attention*, *stated*, and so
   on), and `sv` has no AI review. Restate the rule in `sv`'s own terms: an AI tool's word is `stated`, the
   weakest tier, and nothing a model says makes a requirement *checked*.
7. **v1's ADR-001 cites a requirement that does not fit it.** It gives V15.1.2 (keep an inventory of
   third-party libraries, such as an SBOM) for the choice of "TypeScript everywhere with a single npm install".
   A language choice is not an inventory. ADR-007 cites the same requirement correctly, since it ships the SBOM.
   The other 15 citations in v1's records fit their decisions (checked against `data/frameworks` on
   27 September 2026).
8. **`sv`'s two largest technical choices have no record, and each reverses a v1 decision.**
   - **Rust.** v1's ADR-001 chose "TypeScript everywhere". `DESIGN.md` says only "Written in Rust.", and no
     reason is recorded anywhere.
   - **Running apps in Docker behind an `--internal` network.** v1's ADR-010 rejected Docker because it "is not
     available on the target machine". `DESIGN.md` argues the fence at length and says what changed ("A container
     backend is available on this machine as of 22 September 2026"). No record names it as replacing ADR-010's
     choice, and ADR-010 itself says nothing of it.

   Both are candidates for records of their own, the way ADR-018 replaced ADR-012's ruling.
