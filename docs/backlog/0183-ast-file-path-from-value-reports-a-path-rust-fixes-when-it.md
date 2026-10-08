# `ast.file-path-from-value` reports a path Rust fixes when it compiles

**Status:** done, as its markers read on 8 October 2026

Found on 6 October 2026 by session
securevibe-e2, writing witnesses for the static-file rule: `ServeDir::new(env!("CARGO_MANIFEST_DIR"))` is reported
as a file path built from a value, though `env!` is read when the code is compiled and no visitor can change it.
The same is likely for `concat!` and `include_str!`. A fix teaches the rule that these macros give fixed text, with a
witness each way. **Claimed on 6 October 2026 by session securevibe-e2**, at the owner's word ("feel free to pick
the next backlog item you want"), in branch `claude/securevibe-e2-rust-fixed-macros`: Rust's macros that are read
when the code is compiled count as fixed text wherever a rule asks whether an argument is, and `concat!` when what
it joins is; the static-file rule then takes `ServeDir::new(env!("CARGO_MANIFEST_DIR"))` back.
**Done the same day** (DESIGN, "Rust's compile-time macros are fixed text"): `is_literal` counts `env!`,
`option_env!`, `include_str!`, `include_bytes!`, `file!`, `line!`, `column!`, `module_path!`, `stringify!`, and
`concat!` as fixed, by name or by a path ending in it; `format!` stays a value. The static-file rule reports
`ServeDir::new(env!("CARGO_MANIFEST_DIR"))`. Six guards broken in turn, each caught.
