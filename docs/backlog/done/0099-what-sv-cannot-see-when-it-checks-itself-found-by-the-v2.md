# What `sv` cannot see when it checks itself, found by the v2 self-assessment

**Status:** done, as its markers read on 8 October 2026

Found on 27 September 2026
(`docs/paper/SELF-ASSESSMENT-V2.md`, "Three things `sv` could do about this"). **Not claimed.**
1. **Test fixtures and example apps are read as part of the app.** On `sv`'s own repository they overruled the
   manifest 19 times and added 547 findings. A manifest could name folders that are fixtures or examples: still
   read, but unable to overrule the manifest, and with their findings listed apart.
   **Claimed on 27 September 2026 by session securevibe-e2**, at the owner's asking to pick another item. **Done the
   same day:** `[repository] not-the-app` names such folders. Their code is still checked and its findings
   still count, listed with test and sample code; nothing in them is evidence about what the app uses; and
   the report names the folders. See DESIGN, "Folders the manifest says are not the app".
   **Part status:** done, 27 September 2026
2. **Findings inside Rust `#[cfg(test)]` modules, and in test files in any language, are mixed with the
   product's.** They were 189 of the 252 findings on `sv`'s product code. Report them apart.
   **Claimed on 27 September 2026 by session securevibe-e2**, at the owner's asking to pick a backlog item. **Done
   the same day:** findings inside Rust test code (`#[cfg(test)]`, `#[test]`, `#[tokio::test]`, and a file
   that starts `#![cfg(test)]`) are marked as test code, and every report lists findings in test code after
   the app's own, still counted. See DESIGN, "Findings in test code, listed after the app's own".
   **Part status:** done, 27 September 2026
3. **A manifest cannot say "this app is an MCP server".** So the requirements about serving tools to a model are
   never asked, of `sv` itself or of any app that serves tools. That is the surface of `sv`'s one tool-misuse
   incident (#77).
   **Claimed on 27 September 2026 by session securevibe-e9**, at the owner's asking to continue with the
   backlog: a claim condition `mcp-server` asked in `securevibe.toml`, and AISVS C10 split by side, since the
   whole chapter hangs today on `mcp`, which asks whether the app's AI *uses* MCP. The server's requirements
   (C10.2.1–C10.2.7, C10.3.3, C10.4.3, C10.4.4, C10.4.6) turn on the new question, the client's stay on `mcp`,
   and the four about the transport between the two (C10.3.1, C10.3.2, C10.3.5, C10.4.5) apply when either
   is true. **Done the same day;** see DESIGN, "An app that serves tools over MCP". `sv`'s own count does
   not move until item 1 is done: a fixture's `from mcp` already brings in the whole chapter.
   **Part status:** done, 27 September 2026
