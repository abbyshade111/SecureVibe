# Rust's compile-time macros are fixed text (6 October 2026)

Every code rule that asks whether an argument is fixed text uses `ast::is_literal`. Two examples:
- the file-path rule: a path written in the code is fine, and one built from a value is the fault;
- the query and command rules.

In Rust a macro call such as `env!("CARGO_MANIFEST_DIR")` is not a literal node, so `is_literal` called it a value.
Writing witnesses for the static-file rule showed `File::open`'s neighbor `ServeDir::new(env!("CARGO_MANIFEST_DIR"))`
reported by `ast.file-path-from-value`. No visitor can change that text: the compiler reads it from the build's
environment and writes it into the program.

`is_literal` now counts a `macro_invocation` as fixed when its macro is one the compiler expands into fixed text
(`COMPILE_TIME_MACROS`). The macro may be named on its own or by a path ending in it (`std::env!`). The list:
- `env!` and `option_env!`: the build's environment;
- `include_str!` and `include_bytes!`: a file's contents;
- `file!`, `line!`, `column!`, and `module_path!`: where the call is;
- `stringify!`: a token written out;
- `concat!`, which the compiler accepts only when everything it joins is literal.

`format!` is not on the list. It builds its text when the program runs, and the file-path rule still reports
`File::open(format!("{}/data.json", dir))`. The change reaches every rule that reads Rust this way, which is what it
should do: `query(include_str!("report.sql"))` is a query written in the program too.

With that, the static-file rule takes back the form left out of it: `ServeDir::new(env!("CARGO_MANIFEST_DIR"))`, the
crate's own folder, is reported, with its witness.

Broken on purpose six ways, each caught:
- macros never counted fixed;
- `env!` left off the list;
- `concat!` left off;
- a path to the macro not read;
- `format!` counted fixed;
- the static-file rule's `CARGO_MANIFEST_DIR` form removed.
