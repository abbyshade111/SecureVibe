# The preflight says what `sv run` will look for (6 October 2026)

Decided by the owner on 6 October 2026 (ADR-035, Later; the loop protocol's amendment 6). In the loop's item 6 the
builders fixed nearly everything `securevibe_check` named, and their running apps had as many problems as anyone's,
because only `sv run` sees them. Four of the commonest leave a trace in the code when they are handled, and `ahead`
(`crates/sv-cli/src/preflight.rs`) reads for them:

| Look | Asked when | Read as handled when the code names |
|---|---|---|
| `wrong-passwords` | there is a sign-in | a rate limiter (express-rate-limit, Flask-Limiter, django-ratelimit, Rails' `rate_limit`, Laravel's `throttle`, Rack::Attack), a count of failed attempts, a lockout, or "too many attempts" |
| `headers` | there is a start command | helmet, Flask-Talisman, Django's SecurityMiddleware, secure_headers, or the header names themselves |
| `session-cookie` | there is a sign-in | `SameSite` |
| `ai-screening` | `[stack.run.ai]` is set | a moderation call, a guardrail library (NeMo Guardrails, LLM Guard), or a check for prompt injection or a jailbreak |

They are listed in a section of their own, after what `sv run` needs to start the app and sign in, and the count at
the top stays the count of those: a missing rate limiter does not stop `sv run`. The MCP output carries them as
`willLookFor`, and the server's instructions tell the AI coding tool to look at each before it says the work is done.
"Looks right" names the file and says "Not that it works."; nothing is credited.

Two signs were left out for want of real code to witness them (`llmguard`, `prompt-injection`). Each of the 28 kept
has a realistic line in `each_way_of_handling_it_is_found_in_the_file_that_names_it`; each was taken out in turn and
caught, as were the six structural guards (when each look applies, the section, the JSON, and "Not that it works.").
