# A server's key under a name the browser is given (8 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 3.2; BACKLOG, item 10, its third part). Next.js, Vite, Expo, and Create
React App copy every variable whose name starts `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, or `REACT_APP_` into the
JavaScript each visitor downloads. That is how an app built with Lovable, Bolt, and the like gives the browser its
Supabase address and public key, and it is easy to put the other key beside them: Supabase's service-role key, which
passes every row-level security policy, or a Stripe or OpenAI secret key. The secrets scan finds a key by its shape or
its name, and says it should not be in the code; it did not say that a key under such a name is in every visitor's page,
wherever the file that holds it is kept, including a `.env` that is never committed.

`crates/sv-check/src/public_keys.rs`, run with the configuration checks, adds `config.secret-under-public-name`: high
severity, citing V13.3.1 (backend secrets kept where only the backend can reach them) and SBD-AC-05. Two things are read,
and either is a finding, one for each name in a file, at its first line:

- **A public name that says it holds a secret**, wherever it is written, since code that reads it puts it in the page:
  `SERVICE_ROLE` in the name, or a word for a secret (`SECRET`, `PRIVATE`, `ADMIN`, `PASSWORD`) with a last word for a
  key (`KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `JWT`, `CREDENTIALS`). `NEXT_PUBLIC_ADMIN_EMAIL` is an address, and
  `VITE_STRIPE_PUBLISHABLE_KEY` and `NEXT_PUBLIC_SUPABASE_ANON_KEY` are meant to be public. Medium confidence: the name
  is what the app's author called it.
- **A value given to any public name that is, by its shape, a key only a server holds:** a Supabase token whose `role`
  is `service_role` (the token is decoded; an `anon` one is left alone), a Supabase `sb_secret_` key, a Stripe
  `sk_` or `rk_` key, an OpenAI or Anthropic key, or a GitHub token, each with at least 16 characters after its prefix.
  High confidence.

The value is never quoted, not even its first four characters: the finding names the variable and the kind of key.
Comment lines and prose files (`.md`, `.mdx`, `.txt`, `.rst`) are not read, so a README that warns against the name is not
the app using it. It only ever finds: a public name that says nothing of a secret may still hold a key of a shape this
does not know.

Not done: the fourth part of item 10, a line in the run summary when the dependencies show Firebase or Supabase.

Tests: four in `public_keys.rs`, one of them through `config::check_dir`; the keys in them are made at run time from
pieces. Nine guards broken in turn, each caught: the check not called, no name counted as a secret, a secret word
counted without a key word, any token's role counted, comments read, prose read, no value shapes, a name found twice
in one file reported twice, and a placeholder as short as `sk-your-key` taken for a key.
