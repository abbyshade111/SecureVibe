# Signing in (25 September 2026)

The probes signed in as nobody, so authorization and sessions were always *not assessed*. v1 knew how
to sign in because it wrote the app; `sv` is told, in `[stack.run.users]`, by the same manifest that
already says how to start the app, and makes its own accounts with passwords made for the run.

The rule every check follows is the one from this project's `CLAUDE.md` about tests whose setup can fail
quietly. B being refused A's note proves nothing if A was refused it too; a session surviving sign-out
proves nothing if the sign-out was refused. So each check shows what it relies on first. That rule was
tested against the real example app and caught the suite itself: the example's `/logout` has no page to
take an anti-forgery token from, the sign-out went without one, the app correctly refused it, and the
first run reported "signing out does not end the session". A sign-out that did not happen is now not
assessed, and the token is looked for on the user's other pages, as a sign-out button's would be.

### Level 1, asked of the running app

The coverage count showed 49 of the 70 Level 1 requirements with no check at all, and Authentication
with none. Eight of them can be asked of a running app with what `[stack.run.users]` already says, and
now are, which takes Level 1 from 21 to 29.

Two need no account: a Content-Type on responses with a body, with a charset on text (V4.1.1), and
`/.git/HEAD` and `/.git/config` not served (V13.4.1). The Content-Type check is credited only when both
the page and the error answer had a body; an app whose error is a redirect has shown one answer, and
one answer does not stand for its responses. The `.git` check needs git's own contents in the answer,
so a single-page app answering every path with its page is not mistaken for one serving its history.

The password rules are asked through `signup` and answered by signing in, because how an app words a
refusal is its own business and a sign-in is not. A control goes first: an ordinary strong password,
32 characters of every kind. If that account cannot sign in, nothing is asked. Each password after it
differs from the control in one thing, so a refusal is about that thing: 7 characters (V6.2.1), lowercase
letters alone (V6.2.5), and a password from the 3000 most common (V6.2.4) beside a random one of the same
length and kinds of character, because an app that wants a capital refuses the common one for that and
not for being common. That case is not assessed, rather than credited. `signup` works beside `seed`, so
an app can have its admin made by `seed` and still have its passwords asked.

Three can only ever find something. Four default accounts that do not sign in are four, not none
(V6.3.2). A password refused in the address shows one address refuses it (V14.2.1). And a session id
can be shown too short to hold 128 bits, or the same at two sign-ins, but its value never shows it came
from a secure generator (V7.2.3): the length measure is an upper bound, and a run of one letter passes
it. A clean answer to any of the three is credited with nothing.

Run against `examples/notes-with-users`, which gained a sign-up page that refuses short and common
passwords and nothing else: 14 checks confirmed where there were 10, nothing found, in 11 seconds
rather than 4, most of the difference being the app's own password hashing. Three copies with faults
switched on found every one: a short password, a common one, `admin`/`admin`, a password in the address
and an 8-character session id in the first; a rule wanting a capital and a digit in the second, with
V6.2.4 not assessed beside it as intended; a served `/.git/HEAD` and text without a charset in the
third.

### Level 1 again: the password as typed, the field, and sign-out by visiting

A second pass over the Level 1 requirements nothing reached, on 25 September 2026, found five more that
the running app can answer from what `[stack.run.users]` already says, and two semgrep can speak to.
Level 1 went from 29 of 70 to 35.

Whether the password is checked exactly as typed (V6.2.8) is asked twice, each against an account first
shown to work with its real password. The control account with its capitals swapped: an app that
lowercases passwords lets it in. And an account signed up with an 83-character password, signed into
with its first 72: an app that hashes with bcrypt, which stops reading at 72 bytes, lets that in. Both
refused is credited; either accepted is one finding naming what worked. Signing that account up at all
is V6.2.9, passwords of at least 64 characters allowed, credited or found beside it. An app that refuses
the long password has left the truncation question unasked, and V6.2.8 is not assessed rather than
credited on the case question alone.

Whether the password field is masked (V6.2.6) is read from the HTML of the sign-in and sign-up pages.
The field looked at is the one securevibe.toml sends `{password}` in, so a search box on the same page
is not mistaken for it, and a page whose form is built by script has no such field and says so. The
same field with an `onpaste` handler is a finding for V6.2.7; a handler attached by script cannot be
seen, so a clean answer is credited with nothing. Sign-out by visiting its address (V3.5.3) is asked
last, after a fresh sign-in shown to work: a GET to the sign-out path, then the private page again with
the session as it was. Also only ever a finding, since one address refusing a GET says nothing of the
others.

`examples/notes-with-users` had no password field in its HTML at all, only the hidden token, so V6.2.6
came back not assessed, which was correct; its form now has the fields a browser would show. Run for
real: V6.2.6, V6.2.8, and V6.2.9 confirmed, sign-out by visiting refused. A copy with a text field for
the password, an `onpaste` handler, and `GET /logout` ending the session found all three.

Changing a password (V6.2.2, and V6.2.3, needing the current one to do it) takes a new entry,
`change-password`, with `{password}` for the current password and `{new_password}` for the new. It is
asked last, since it changes a password: with an account made for it when there is a `signup`, with A
when there is not. The wrong current password first: if the new password then signs in, that is the
finding, and the change taking has also shown a password can be changed. Otherwise the same change with
the right current password has to take, the new password signing in and the old one refused, before the
refusal means anything; a change that never takes leaves both not assessed. The old password still
signing in afterwards is a finding against V6.2.2. The change page is read signed in for V6.2.6, both of
its password fields. Run for real against the example, which gained a change page: both confirmed; a
copy that skips the current-password check found it.

Three more, from the same pass. Whether deleting an account ends every session it had (V7.4.2) takes a
`delete-account` entry, and is asked only of an account made for it through `signup`: A and B, which
every other question stands on, are never deleted, and without `signup` it is not assessed. The account
is signed in twice, as two browsers would be, both sessions shown to open the private page, and deleted
from the first. The deletion is shown to have happened (its password no longer signs in) before the
second session is asked for the private page; still opening it is the finding. The anti-forgery token for
the request is looked for where sign-out looks for it, on the private pages, since a delete button is
usually on the account's own page and not at the address it posts to; the change of password does the
same now. A password hint or secret question (V6.4.2) is looked for on the pages already read for the
password field, by its words ("security question", "mother's maiden name") or a field's name (`hint`,
`security_answer`), and is only ever a finding. And semgrep's `detect-insecure-websocket`, already
V12.3.1, counts against V4.4.1 too, as a finding only, since an address assembled at run time is not
text a pattern can see. Run for real against the example, which gained an account deletion that ends
every session: V7.4.2 confirmed; a copy that ends only the current session, with a password hint on
its forms, found both. Level 1: 40 of 70.

Semgrep's rules for text written into a page as HTML (`innerHTML`, `document.write`,
`dangerouslySetInnerHTML`, `v-html`) now count against V3.2.2, and C#'s token validation with expiry
turned off against V9.2.1, through `findings_against`: a finding marks them, a clean run does not.

### Tests to write

The coverage count said 290 ASVS requirements have no check in `sv`, and that the one route to evidence
for every requirement is the app's own passing test naming it. Nothing turned that into something to act
on: a requirement nobody had written a test for read exactly like one whose test did not run.

The report now has a section, "Tests to write": every applicable requirement with no evidence of any
kind and no test in the app naming it, lowest level first, ASVS before AISVS. The test files are read
whether or not the tests ran, so a requirement named in a test that did not run here is listed apart,
as named and not credited, rather than as a test to write. `sv mcp` gives the AI coding tool the same
list, the first 30 lines of it, because the tool is the one that writes the tests; `sv init` tells it to
work down the list, fixing what the app does not yet meet before writing the test that shows it.

What a test of the application cannot show is left out and counted: a requirement classed as
documentation or a deployment setting, design review, the AISVS appendix on the development process,
and any whose own words ask for documentation. Leaving something off a to-do list credits nothing, so
this can err only towards a shorter list. On `examples/tested-notes`: 71 tests to write, 18 at level 1,
and 84 left out with the reason.
