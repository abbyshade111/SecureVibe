# A development console that answers, and the model name the app really sent (29 September 2026)

Two halves the first partial checks left, each read from the running app rather than the code.

**A development console (V15.2.3, V13.4.2).** `probe.development-console-open` asks, as somebody not signed
in, for two pages a development tool serves only in its development mode: Werkzeug's interactive console at
`/console`, which exists only when its debugger may run code, and Rails' information page at
`/rails/info/properties`, which Rails adds only in the development environment. Each is judged by words only
that page carries, read from the tool's own source on this date (Werkzeug 3.1.9, Rails 8.1.4), never by its
status: an app that answers every path with its home page is not a console, and neither is one of Werkzeug's
traceback pages, which shares half the console's title. It is only ever a finding, since two guesses are two
guesses. On the way, Django's debug 404 page joins the error-page markers (`probe.error-detail-leak`): with
debug on, Django lists the app's routes and prints no trace, so none of the old markers matched it.

**The model name sent (C3.2.3).** The test model already recorded which model each request asked for. A
name that moves on its own (`latest`, or one ending `-latest`, `:latest`, or `@latest`) is
`probe.ai-floating-model-sent`; unlike the code rule `ast.floating-model-name`, it need not begin with a
vendor's family, since the name really went to a model service. Any other name is only a step, and credits
nothing: a name without `latest` may still be an alias the vendor moves (`gpt-4o`), which is not looked up,
and a dated name today says nothing of how the app will choose its model tomorrow.
