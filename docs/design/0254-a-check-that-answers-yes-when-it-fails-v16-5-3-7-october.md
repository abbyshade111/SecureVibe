# A check that answers "yes" when it fails (V16.5.3, 7 October 2026)

V16.5.3 asks that an app fail securely when something goes wrong, "preventing fail-open conditions". No check spoke
to it. `docs/PARTIAL-CHECKS.md` proposed the narrowest form a reading of the code can show: a function whose job is to
decide whether someone may go on, and whose error handler says they may.

**`ast.check-passes-on-error`** (high, medium confidence, only ever a finding) reports an error handler that answers
"yes" directly, inside a function whose name says it checks something:

| Language | What is looked for |
|---|---|
| Python | `return True` in an `except` block |
| JavaScript, TypeScript | `return true` in a `catch` block, or `next()` with nothing (Express passes the request on) |
| Ruby | `true` as the last line of a `rescue`, or `return true` in one |
| PHP, Java, C#, C++, Swift, Dart | `return true` in a `catch` block (Dart's `on X { … }` too) |
| Kotlin | `return true` in a `catch`, or `true` as the value of the `catch` of a `try` expression |
| Go | `return true` (first of the values) under `if err != nil` |
| Rust | `.unwrap_or(true)`, and `Err(_) => true` or `Err(_) => return true` in a `match` |
| Shell | `\|\| return 0` in a function |

C has nothing to find, and the rule says so: C has no exceptions, and whether a returned value means yes or no is
only the function's own business.

**Which functions.** Whether `except: return True` is a fault depends on what the function is for: in
`verify_token` it lets anyone in whose token cannot be read, and in `is_cached` it is ordinary. A query cannot say
how far down a function a handler sits, since a pattern matches only the children it names, so the rule engine gained
`enclosingFunctionPatterns`: per language, a pattern over the name of the function around the match. The name is read
as lower-case words (`verifyToken`, `VerifyToken`, and `verify_token` are all `verify_token`; `isJWTValid` is
`is_jwt_valid`; Ruby's `authorized?` is `authorized`), so one pattern serves every language. The words that count are
the ones the proposal named and their forms: auth, authenticate, authorize, verify, validate, valid, check, allow,
permit, permission, guard, and a few whole names (`can_activate`, NestJS's guard method; `has_role`, `is_admin`,
`login_required`). They are matched as whole words, so `invalidate_session` and `checkout` are not checks. A function
with no name of its own (a lambda, a callback) is passed over for the one around it, or the name it is given:
`const requireAuth = (req, res, next) => …`, `exports.verify = …`, `{ isAllowed: function … }`. C++'s `Auth::check` is
read as `check`, and Dart's name comes through its signature.

**What it does not see.** A handler that swallows the error (`except: pass`) and lets the function go on to a `return
True` further down; a fail-open spread over two functions; a promise's `.catch(() => true)`; a check whose name says
nothing. Finding none says nothing about the app's error handling, so the rule credits nothing, and its "looks for"
sentence says so beside a clean result. A false alarm is likeliest in a function named `check…` that is not a
security check (a health check answering "up" when its probe throws).

**Break and watch.** Witnesses in `ast.rs`'s table, both ways for every language, and a test of the word splitting.
Fifteen guards broken in turn, each caught: the name not judged at all (six cases red: `is_cached`, `loadPrefs`,
`warm_cache`, `loadConfig`, `cleanup`, and `invalidate_session`), no name ever found (every found case in every
language), the name from an assignment not read (two JavaScript cases), Dart's signature not read (both Dart cases),
C++'s declarator not read (the C++ case), and capitals not splitting words (most languages, and the word test).
Then each per-language setting in the rules file taken out, each caught by its language's case that should stay
quiet: JavaScript's argument pattern (`next(e)`, which passes the error on, reported), Go's error name (`if r != nil {
return true }` reported), Rust's `Err` and `unwrap_or` names (`Ok(_) => true` reported), Rust's, C#'s, Swift's, PHP's,
and Kotlin's `true` (each language's `return false` reported), and the shell's `0` (`|| return 1` reported). Ruby's
and Kotlin's "last line of the handler" anchor has no case: a bare `true` that is not the handler's last line is not
something anyone writes.
