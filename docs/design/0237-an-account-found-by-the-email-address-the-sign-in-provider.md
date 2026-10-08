# An account found by the email address the sign-in provider sent, read from the code (6 October 2026)

`probe.oidc-user-keyed-on-email` (DESIGN, "Two people with one email address at the sign-in provider") shows V10.5.2
failing in a running app, when the owner's settings let it sign in through the test provider. The backlog left its
static companion undone: the same fault read from the code, for apps the run cannot sign in to.

`ast.account-found-by-provider-email` is that rule. It is only ever a finding, so finding nothing credits nothing.
It reports two shapes:
- **An account looked up by the provider's email address.** A call that finds a record (`filter_by`, `findUnique`,
  `find_by`, `Where`, `FindByEmailAsync`, `findByEmail`, a SQL `execute`, and their like) is given the address the
  provider sent:
  - Python's `userinfo["email"]` (Authlib) or `idinfo.get("email")` (google-auth);
  - JavaScript's and TypeScript's `profile.emails[0].value` (Passport), `claims.email`, or
    `ticket.getPayload().email`;
  - Ruby's `auth.info.email` (OmniAuth);
  - Go's `claims.Email` (go-oidc);
  - PHP's `$googleUser->getEmail()` (Socialite);
  - Java's `oidcUser.getEmail()` or `principal.getAttribute("email")` (Spring Security);
  - C#'s `info.Principal.FindFirstValue(ClaimTypes.Email)` (ASP.NET Core).
- **The address recorded as who is signed in.** In Python, JavaScript, TypeScript, Ruby, and PHP, an assignment to the
  session's user entry: `session["user"]`, `req.session.userId`, `session[:user_id]`, or `$_SESSION['user_id']`. Only
  entries that name the user count, so `session["email"] = …`, kept for showing the address, is not reported.

Either one is found when the address is written in place or **through a name**: `email = userinfo["email"]` and then
`filter_by(email=email)`, which is the usual way it is written. That is a new switch any rule can use,
`argumentNamesRead`. A name in the argument counts when the function around the call (or the file, outside any
function) sets it to text the pattern matches. It reads an assignment or a declaration in any of the eight languages:
- `x = v`, `$x = v`, and `x := v`;
- `let x = v`, `String x = v`, and `var x = v`;
- tuple targets (`sub, email = …`).

Names after a dot (`User.email`) and keyword names (`email=` in Python) are not taken for variables. JavaScript's
shorthand `{ email }` is.

What it does not look for, as its `looksFor` says:
- a lookup made inside a helper function;
- a session reached through another name;
- a value set in another function.

`examples/oidc-notes`, with its `email` flaw, writes `s.user = claims.email`, where `s` is the session under another
name. The rule does not find it, and the running check does. Kotlin, Rust, Swift, Dart, C, and C++ each say no sign-in
library of theirs is looked for. Shell says a script does not handle a provider's answer.

**Later, 7 October 2026: the session under another name.** A second switch, `functionNamesRead`, is the other side
of `argumentNamesRead`. When a rule's `@fn` does not match as written, the name it begins with is read as each value
the function around it sets that name to, and the pattern is tried again with the value in its place. With
`s = req.session`, `s.user = claims.email` is tried as `req.session.user`, and found.

- **The witness.** `examples/oidc-notes` gets its session from a helper of its own, `const s = session(req, res)`. So
  the JavaScript and TypeScript patterns now also take a session that a call returns, such as `session(...)`,
  `getSession(...)`, or iron-session's `await getIronSession(cookies(), options)`. `sv report` on the example now
  reports line 120 (`s.user = … claims.email …`), which the running check had found alone.
- **Python and Ruby.** `s = session` is the same session object, so `s["user"]` counts. `s = dict(session)` is a copy,
  and does not.
- **PHP.** Only a reference counts. `$s = &$_SESSION` is the session under another name. `$s = $_SESSION` copies the
  array, and writing to the copy changes nothing in the session, so reading it as the session would be a false alarm.
- **Where the name is read.** Only in the function around the line, as `argumentNamesRead` reads it. A name set in
  another function is another variable.

The first version only read a name followed by `.`, `[`, or `->`. Taking that out turned no test red. A bare alias,
`const find = findOne`, read as `findOne` is a correct finding anyway, so the condition went rather than stay
untested. So did a step that took the `&` off PHP's reference, since the grammar keeps it out of the value already.
Six guards broken in turn, each caught by the witnesses: the switch off in the rule, the name never read, a PHP
copy counted, the whole file read instead of the function, and either part of the call-returning session pattern
taken out. A lookup inside a helper function is still not followed.

What is left alone:
- the same lookups keyed on `sub`, `uid`, `googleId`, `getId()`, or `FindByLoginAsync`;
- a sign-in form's own email address;
- the address sent in an email or shown on a page;
- the address saved beside an account that is found by `sub`.

The first run caught one false alarm, Express's `app.get('/callback', handler)`: a call named `get` whose argument is
the whole handler. So `get` is not a lookup name in JavaScript and TypeScript, and that case is now a witness.

Why a provider's verified flag (`email_verified`) is no defense is said in the rule's impact, as the running check
says it.

Broken on purpose 23 ways. Each of these 22 was caught by the witness written for it:
- names never followed;
- JavaScript's shorthand `{ email }` not taken for a name;
- names after a dot taken for variables;
- the whole file read in place of the function;
- declarations (`let`, `var`, `String x =`) not read;
- Go's `:=` not read;
- tuple targets not split;
- PHP's `$` kept on a name;
- `get` put back among JavaScript's lookups;
- each of the four session forms removed;
- each of the eight languages' email patterns made to match nothing.

The 23rd, a guard against reading a node as both the name and its value, was caught by nothing. A bare name never
matches an email pattern, so it could not change a result, and it was taken out.
