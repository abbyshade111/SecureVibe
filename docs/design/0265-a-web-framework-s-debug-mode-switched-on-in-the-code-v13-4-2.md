# A web framework's debug mode switched on in the code (V13.4.2, 7 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 1.9). `config.development-server-started` reads the command that starts
the app. `python app.py` is not a development server's command, so it read "none starts a development server" even
when `app.py` ends in `app.run(debug=True)`. That one argument starts Werkzeug's debugger, whose error page runs any
Python it is sent on the server. Django's generated `settings.py` starts with `DEBUG = True` the same way. Bandit's
B201 finds Flask's case, but only when the outside tools run.

**`ast.debug-mode-on`** (`data/ast-rules.json`; high, medium confidence, findings only, citing V13.4.2):

- **Python.** `app.run(debug=True)` and any `.run(debug=True)` but `asyncio.run`'s; a bare `run(debug=True)`, as
  Bottle's is; Werkzeug's `run_simple(..., use_debugger=True)`; `FastAPI(debug=True)` and `Starlette(debug=True)`;
  `app.debug = True` but `self.debug`; `app.config["DEBUG"] = True`, and `app.config.update(DEBUG=True)` or any
  other call on `config` given `DEBUG=True`; and `DEBUG = True` at the top of a module, as Django's settings write it.
  Inside a class (Flask's configuration classes) or a function it is not reported.
- **Shell scripts.** `FLASK_DEBUG` set to `1` or `true`, exported or not, and `flask --debug`. A Dockerfile's
  `FLASK_DEBUG=1` was already the start-command check's.
- **What it does not tell apart.** A value written as `True` is reported; one read from a setting is not. A settings
  file meant only for development (`settings/dev.py`) is reported like any other, which a finding review can set
  aside. Finding none credits nothing.
- **Other languages.** Each says it is not looked at, naming its own switch where one is well known: Express's
  `errorhandler`, PHP's `display_errors`, Rails' `consider_all_requests_local` and Sinatra's `show_exceptions`, ASP.NET
  Core's `UseDeveloperExceptionPage()` outside a development-only branch, and Gin's debug mode. C and C++ have no
  common framework with such a switch.
- **How the queries filter.** This codebase refuses tree-sitter's text predicates (`#eq?`, `#match?`), which the Rust
  binding parses and does not apply. Every Python pattern captures the name as `@fn` and the setting as `@kw`, one node
  holding both where they are the same word (`DEBUG = True`), and the object as `@arg` where `asyncio` or `self` sets
  it aside through `safeArgumentPatterns`, which a pattern without `@arg` never meets.

**The start-command check.** Its clean reading credits nothing, as before, and now names the files a command runs
(`python app.py`, `node server.js`, flags before the name allowed): "`app.py` runs the app's own code, which decides
for itself whether it starts a development server or a debug mode (`ast.debug-mode-on` reads Python's)".

Eight guards broken in turn, each caught: the six in the rule by the witnesses in `crates/sv-check/src/ast.rs` (29 for
this rule, found and not found), the two in the start-command check by its tests in `launch.rs`:
- `asyncio.run` and `self.debug` not set aside;
- any keyword taken for `debug`;
- Django's `DEBUG` not looked for;
- `DEBUG = True` read anywhere, not only at the top of a module;
- `FLASK_DEBUG=0` taken as on;
- `flask --debug` not looked for;
- the start-command check saying nothing of the app's own file;
- a flag before the file name (`python -u app.py`) stopping the file being named.
