# A template filling in its own token is not a credential (7 October 2026)

Found by session paper-facts in the start-of-build test: one Haiku app drew eight high `secrets.credential-assignment`
findings at lines like `<input type=hidden name=csrf_token value="{html.escape(csrf_token)}">`, an f-string writing
the anti-forgery token the app made for that page into its form, which is the protection V3.5.1 asks for. The rule saw
a name that says "token" and a value that was not on its list of placeholders, and told the owner to change a
credential that was never in the file. Reproduced with `sv check` on a one-line app.

`{name}`, the single-brace blank of `sv`'s own settings file, was already a placeholder. The same test now takes in a
whole value that is one `{...}` holding only names, dots, calls, indexes, commas, and spaces, starting with a letter
or `_`: `{html.escape(csrf_token)}`, `{session.csrf_token}`, `{tokens[0]}`, `{escape(make_token(request, 32))}`. Three
things keep a value judged: a quote inside the braces (it could hold a literal), any text outside them (`{x}` and then
a key), and a first character that is not a letter (a key that happens to sit in braces). `{{ ... }}`, `${...}`, and
`<...>` were placeholders already, so Jinja, Go, shell, ERB, and PHP templates were never affected. The two checks for
braces are one now, since the new one takes in everything the old one did.

**Four guards broken in turn, each caught:** the brace expression not a placeholder (three tests, `sv init`'s own
template among them), a quote allowed inside, text after the braces allowed (two), and the first character not held.
That last was caught by nothing at first, so a case of a key in braces starting with a digit was added.
