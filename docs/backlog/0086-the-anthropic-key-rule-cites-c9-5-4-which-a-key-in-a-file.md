# The Anthropic key rule cites C9.5.4, which a key in a file does not speak to

**Status:** done, as its markers read on 8 October 2026

Found on 28 September 2026
by session securevibe-e10 while writing the OpenAI and Hugging Face rules beside it. C9.5.4 asks that
"secrets and credentials required by an agent at runtime are not exposed within the model's observable
context, including the context window, system prompts, or tool call parameters". `secrets.anthropic-key`
in `data/secret-rules.json` cites it, so every Anthropic key found in a file is a finding against a
requirement about the model's context, which the file says nothing about. The new rules leave it out. The
semgrep rule `mcp-credential-in-response` also cites C9.5.4, and there it fits: a tool returning a
credential into the model's context is what C9.5.4 is about. Fix: take C9.5.4 off the Anthropic rule,
regenerate `docs/COVERAGE.md`, and see what else moves. **Claimed on 28 September 2026 by session
securevibe-e9**, at the owner's asking to continue with the backlog.
**Done the same day:** C9.5.4 is off `secrets.anthropic-key`, and it is now only ever found failing, by
semgrep's `mcp-credential-in-response`. Nothing else moved. The note in `tools/coverage.py` explaining why
a clean credential scan counted for it is gone with it. `no_rule_that_reads_files_for_keys_cites_the_model_context_requirement`
in `crates/sv-check/tests/citations.rs` holds it, beside the coverage document; putting the citation back
turns both red. Left as it is: `data/knowledge/applicability.json` still classes C9.5.4 as `scanner-clean`,
which no code reads and which no clean scan now backs.
