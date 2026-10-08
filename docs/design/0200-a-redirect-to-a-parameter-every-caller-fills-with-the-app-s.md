# A redirect to a parameter every caller fills with the app's own route says so (5 October 2026)

The redirect half of family-hub's item 7 (BACKLOG, "What the owner hit building family-hub"), the last of A1.
`ast.open-redirect` flagged `redirect(destination)` in `familyhub/signin.py`, where `destination` was a parameter
that every caller filled with `url_for("home.index")`. The finding said "possible" and to read the code first; the
AI tool offered to remove the parameter, "which ... clears the finding", and the owner agreed. The removal did no
harm there, but it was working code changed to quiet a rule.

As for a destination a function checked (the section above), the finding stays, at the rule's own low confidence,
and says what it found, as the owner decided on 5 October 2026 for that case. When the destination is a bare name
that is a parameter of the Python function the redirect sits in, and the function does not give it another value,
`scan_listing` looks, once every file is read, at every use of that function's name across the app's Python. When
every use is a call, its own definition, or an import, there is at least one call, and every call passes, by
position or by name, or leaves to a default, a value the rule already counts as safe on its own (`url_for(...)`,
`reverse(...)`, a path on this site), the finding says so: "The value here is `destination`, a parameter of
`finish_sign_in`, and each of its 2 calls in this app's Python passes the app's own route or a path on this site
(`views.py` line 5 and `views.py` line 8), so it may already be safe: check that nothing else calls
`finish_sign_in`, such as code `sv` did not read or another function of the same name, before changing anything.
Removing the parameter only to make this finding go away is not a fix."

It says nothing more when a call passes anything else, the name is handed on to be called elsewhere (`HOOKS =
[finish_sign_in]`), nobody calls the function (a Flask view, whose arguments come from the address), a call spreads
its arguments (`*args`), or the parameter can only be passed by name and a call leaves it out. A method's `self` or
`cls` is not counted among the arguments, since `auth.go(...)` does not pass it.

What it does not know, and says: a call by another name, a call from code `sv` did not read, and a different
function of the same name, whose calls are counted as this one's. Python only; JavaScript and TypeScript keep the
plain finding.

How it is held: `a_destination_every_caller_fills_with_the_apps_own_route_says_so` (`crates/sv-check/src/ast.rs`),
with three cases that say so and seven that must not. Ten guards broken in turn, each caught: the callers never
looked up, a reassigned parameter believed, a name handed on taken as called, an import taken as another use, a
spread believed (caught only by a fixture added for it, a spread over a safe default), a keyword-only parameter
taken by position, a method's `self` counted, a default ignored, a keyword argument not read, and any value taken
as the app's own route.
