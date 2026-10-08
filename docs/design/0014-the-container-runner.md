# The container runner

`sv run ./app` starts the app behind a network fence and checks it answers. The fence design was
**measured rather than reasoned about**, and the measurement overturned the obvious translation of v1's.

v1 fences a child process with `sandbox-exec` or a network namespace and probes it over `127.0.0.1`. The
obvious container equivalent — publish a port to loopback, probe from the host — does not work:

| | `--internal` network | default bridge |
|---|---|---|
| sidecar on the same network reaches the app | yes | yes |
| app can reach `1.1.1.1:53` | **blocked** | succeeded |
| host reaches a published port | **no** | yes |

An `--internal` network is exactly the fence wanted, and is unreachable from the host whether or not a port is
published. Moving to a bridge to make host probing work removes the fence entirely. So the probes run from a
**sidecar container on the same internal network**, and nothing is published to this computer at all.

Two earlier attempts at that measurement proved nothing, which is the more useful half of the story. The first
used `alpine:3`, whose busybox has no `httpd` applet: every container exited immediately and dutifully reported
"outbound blocked" while not running. The second used `example.com`'s old address, decommissioned in 2024, which
made the *default bridge* look fenced too. The table above comes from a run with a live target and a host
baseline confirming this machine can reach the outside at all — without that line, "blocked" means nothing.

### One sidecar per run, not one per request

The sidecar used to be a new container for every request: `docker run --rm` into the fence, one
request, gone. That is simple and each request is clean, and it cost about half a second a request.
The anonymous probes are four requests, so nobody noticed. The signed-in checks are twenty-odd, made
one after another because each depends on the cookies the last one returned, and a run of
`examples/notes-with-users` took 11 to 13 seconds on the machine that measured it, 22 on a busy one, and
by an earlier estimate about a minute on a slow one. Logging every Docker call showed where the time
went: 26 throwaway containers were 13 of those seconds, and nothing else was more than a quarter of one.

Now the sidecar is started once, just before the health check, and every request is an `exec` into it:
0.11 seconds against 0.48 measured side by side. It is removed as soon as the last request is made,
before the tests run, and by the teardown whatever happens. It has nothing to write and nothing to be
allowed, so it is given neither: a read-only file system, no capabilities, no way to gain privileges.
It runs `sleep` with `--rm` and a 15-minute limit, so a run that dies without its teardown leaves
nothing behind for longer than that. If it cannot be started, each request starts its own container
as before: slower, the same answers.

The same run, three times each way: 11 to 13 seconds before, 4.3 after, the same ten checks confirmed,
and a text-identical report. A copy of the example with five flaws switched on had all five found in 4.2
seconds, and no container or network was left behind by any of it.

### What the probes ask, and what they cannot

Four requests, made from the sidecar over a plain socket rather than through an HTTP client. `wget` was
tried first and rejected for two reasons found by trying it: it returns no body at all for a 404 or a 500,
which is exactly the response the error-page probe has to read, and it cannot send a method other than GET
or POST, which rules out the TRACE question. `nc` returns the raw response whatever the status and whatever
the verb.

| question | what a wrong answer means |
|---|---|
| the health path, plain | missing `Content-Security-Policy`, `X-Content-Type-Options`, framing rule or `Referrer-Policy`; a cookie without `HttpOnly` or `SameSite` |
| the health path with an `Origin` that does not exist | the app echoing it back, or `*` — worse if credentials are allowed with it |
| a path that is not there | a stack trace naming the framework, its version and the file layout |
| `TRACE`, carrying a header this probe invented | that header coming back in the body |

**The probes sign in as nobody.** `sv` does not know how to log in to an app it did not write. So
authorization, session handling, CSRF and anything that needs data sent into a form are **not assessed**,
and `unassessed_requirements()` names each one with the reason. The CLI prints that list *before* any
finding. A suite that quietly covers only the front door, and reports nothing, reads exactly like one that
found nothing wrong.

The request is built by `request_bytes`, which **refuses to send anything** whose method, path, header name
or header value carries a newline, rather than stripping it. The path is the app's own `health_path`, out
of its manifest, so it is not text `sv` wrote; a stripped path is a different request from the one asked
for, and a probe with no answer is already reported as unanswered. The finished request is base64-encoded
before it reaches the sidecar's shell, so nothing in a header value can end the command it travels in — a
scanner that can be made to run a shell command by the app it is scanning would be a poor advertisement.

### Three more questions for the running app

Three Level 2 requirements that the questions already being asked were one response away from
answering, with no new manifest entry between them.

**`Cache-Control: no-store` on private pages (V14.3.2).** The signed-in session already opens every
page `private` names; this reads the headers that came back with it. `no-store` is the only value
that answers the requirement, and the check says so by matching the directive exactly rather than
looking for the text: `no-cache` permits the browser to keep the copy and asks it to revalidate, and
`private` only rules out a shared cache. Both are the half-right answer an app is most likely to
have, and both leave the page on a shared machine after the person signs out. A looser reading turns
two tests red.

**A visible sign-out link on private pages (V7.4.4).** The same responses, read for a link or a form
pointing at the `logout` address. It reads `href` and `action` attributes rather than searching the
page for the address, because a page that names `/logout` in a script string or a comment offers the
person nothing — and the fake app's flawed page now does exactly that, so the end-to-end flaw test
catches the loose reading too. What it cannot tell is whether the control is *visible*: a link
inside a collapsed menu counts here, which is why finding one is worth no more than it says.

Both need `private` to have opened for the signed-in user first. When it did not, they report *not
assessed* rather than a pass or a finding — and because a page that never opens ends the run before
these checks are reached, the three earlier bail-outs now name V14.3.2 and V7.4.4 too. A requirement
nothing asked about has to be said out loud wherever the asking stopped.

**Directory listings (V13.4.3).** This one is an anonymous probe, beside the `.git` check for
V13.4.1, rather than a signed-in one: a folder that lists its contents does so for anybody, and
putting it behind `[stack.run.users]` would have meant asking it only of apps with sign-in. Six
common folder paths are requested with a trailing slash, and a listing is recognized by what the
three servers that produce one actually write — Apache and nginx both head the page "Index of /x",
Python's `http.server` writes "Directory listing for /x".

That precision is also the limit, and it is why this **only ever produces a finding**. Six guesses
are six guesses, three signatures miss a listing a framework renders in its own words, and finding
nothing would be a statement about what was guessed rather than about the app. Matching "a page with
several links in it" instead — the obvious alternative — turns three tests red, because every real
page is a page with several links in it.

The request id and the check have to agree, or the probe is dead: the request goes out, the response
comes back, and nothing reads it, with nothing failing anywhere. Both sides call one `listing_id`
function, and a test builds its responses from the real request list rather than from ids typed into
the test, so drift between them is caught rather than silently tolerated.

### Six more questions for anybody

Asked of every app, signed in or not, beside the questions above: a Level 2 requirement and five
Level 3 ones, each answered from what the app says back.

| question | what a wrong answer means | credits |
|---|---|---|
| the health path with `DELETE` and with `PROPFIND` | either answered as a success: a page that is only read takes methods it has no use for (V4.1.4) | never |
| the health path with `callback=svProbeJsonp` | an answer, not HTML, calling that function: JSONP (V3.5.6) | never |
| fourteen documentation and monitoring paths | OpenAPI, Swagger UI, Redoc, Spring's actuator, Prometheus metrics, Go's expvar and profiler, Apache's and nginx's status, or `phpinfo()`, served to anybody (V13.4.5) | never |
| every answer's `Server`, `X-Powered-By`, and like headers, and every error page | a product with its version number (V13.4.6) | never |
| the page and the error page, when they are HTML | no `Cross-Origin-Opener-Policy` of `same-origin` or `same-origin-allow-popups` (V3.4.8) | the pages seen |
| the page's `Content-Security-Policy` | neither `report-to` nor `report-uri` (V3.4.7) | the policy seen |

Four of these are only ever findings. Two methods on one path, one path asked for JSONP, fourteen
guesses, and the headers and error pages seen are not the whole app, and finding nothing would be a
statement about what was asked. V13.4.5 also allows what is "explicitly intended", which only the
owner can say, so the finding tells them to say it. The two header checks credit, as the other
header checks do, and name what they read. Neither credits on nothing: no HTML page means no
opener-policy credit, and no policy means no reporting credit — a missing policy is already the
security-headers finding.

Each is judged by what comes back, not by an answer arriving. A single-page app answers every path
with its front page, so a documentation path is open only when the page says what it is; a search
page that repeats `svProbeJsonp(` is not JSONP, because it is HTML; and a version on a page that
worked is the app's own content, not a leak. A product named without a version (`nginx`, `Express`,
`ASP.NET`, `Next.js`) is not one either. Each of those negatives is a test, and the break round
found no guard with fewer than two once the second witnesses were added; before that, the digit
check on version headers had none, because every negative fixture also lacked a dot.

Verified end to end with a scratch Python app: the careful one (`Cross-Origin-Opener-Policy`,
`report-uri`, 405 for unused methods, no version) had no findings and was credited for both headers;
the careless one raised all six. The fourteen new paths are asked like the others, from the sidecar,
and every answer with a body is also held to the Content-Type check.

### The `upload` entry

Four Level 1 requirements turn on what an app does with a file somebody sends it, and all four are
about behavior rather than code, so the probes can reach them once `securevibe.toml` says how to
upload:

```toml
upload = { path = "/upload", field = "file", form = { csrf_token = "{csrf}" },
           serves-at = "/files/{name}", max-bytes = 1048576 }
```

`max-bytes` is the documented policy for V5.2.1, in the same shape as `[policy] failed-sign-ins`:
prose cannot be checked, a number can. `serves-at` is optional, and its absence is an answer rather
than a gap — an app that stores uploads where no URL reaches them is the safest arrangement there
is, so V5.3.1 and V3.2.1 come back *not assessed* rather than failed.

**An ordinary file goes first, and everything else is read against it.** Each of these checks is
looking for a refusal, and an app whose upload path is not what the manifest says refuses
everything. Without the ordinary file, the least working app imaginable would score four passes —
the most flattering possible result for the app that deserves it least. So a real GIF is uploaded
first, and if that fails all four are not assessed, naming why.

**The files are GIFs because the body has to be text.** A probe request carries a `String`, so a
real PNG header cannot be written into one: `\x89PNG` is not valid UTF-8. `GIF87a` is ASCII, which
is why the good file is a GIF — a convenience of the harness, not a claim about what apps accept.
The mismatched file claims `.gif` as well, so that both halves of the comparison share an extension
and a refusal can only be about the contents.

**What "executed" means is one distinction, and it is not the marker.** Both the safe and the unsafe
answer contain the marker string the file was given: served as-is, it is inside the source; run, it
is the output. The check reads whether `<?php` came back, not whether the marker did. A check keyed
on the marker alone cannot tell the two apart at all, and two tests hold that.

**Rendering is judged by any of three answers**, because ASVS names several: `Content-Disposition:
attachment`, a `Content-Security-Policy` with `sandbox`, or a content type that is not HTML.
Insisting on one would report apps that chose another; accepting none of them would credit every
app. Both halves are tested.

There is a cap on what is sent. A stated limit above 8 MB is not tested, and says so: the point is
to find an app that takes anything, not to turn one check into a denial-of-service attempt against
somebody's own app. The fake app records the largest body it was ever sent, because that promise is
about what goes over the wire and no finding or note can show it.

Left over, reachable the same way and not written: V5.3.2 (a path built from a submitted file name)
and V5.4.1 with V5.4.2 (the file name and disposition the app sends back).

### What the app wrote down

V16.3.1 and V16.3.2 ask that authentication and failed authorization are logged. The run already
does both to the app — it signs in, it fails to sign in, it is refused a private page — so the only
missing piece was reading what the app said about it.

**This check can credit and never fault, which is the opposite of most here.** The only output `sv`
can see is the container's. An app that logs to a file, to syslog, or to a logging service writes
nothing there and is not logging any less for it, so finding the events is evidence and not finding
them is evidence of nothing. Silence is *not assessed*, with the reason spelled out.

**The probes plant markers rather than search for words.** "The log mentions `admin`" says nothing:
every log mentions `admin`. So three things happen that no other traffic could have done, each
carrying a string nothing else contains:

| planted | what finding it proves |
|---|---|
| a sign-in for an account that does not exist | a *failed* authentication was written down |
| a sign-in that works, by an account used for nothing else | a *successful* one was |
| a private page asked for by nobody, with a marker in its address | the refusal was |

V16.3.1 is credited only when **both** sign-in names are found. One of the two is not the
requirement — an app that records only the sign-ins that worked is precisely the app it is aimed at
— and crediting on half would be the overstatement this project exists to refuse. When only one is
found, the report says which, because "logs successes but perhaps not failures" is something the
owner can act on.

**A status has to be a status.** For V16.3.2 the marker alone only shows the request reached a log;
the status on the same line is what makes it a record of the *decision* rather than of traffic. The
status travels with the marker rather than being matched against a fixed list of refusal codes —
an app that sends people to the sign-in page answers 302, which no list of "refused" codes would
have contained, and it is a refusal all the same.

Matching that status is where writing the test found a real fault in the check. Three digits turn up
inside byte counts (`14039`), request ids (`req=a401b9`), durations (`took=403ms`) and paths
(`/invoices/40312`), and the first version split the line on non-digits — which read `req=a401b9` as
a 401. A status is now a whole token: what follows its last `=` or `:`, trimmed of punctuation, and
equal to the code. The fixture that caught it is a table of lines real servers write.

### What a log line and a download carry

Four Level 2 requirements, each read off something a check already had in hand.

**V16.2.1 and V16.2.2 read the line the log check already found** — the one naming the refused
sign-in for an account that does not exist. That line's *what* and *who* are known by how it was
found; what is left to read is *when* and *where*. V16.2.1 is credited when it also carries a
timestamp and a source address or path; V16.2.2 when that timestamp states its zone.

This is where the log check stops being credit-only, and the line between the two cases is the
point. A **missing** timestamp is *not assessed*: writing to standard output and letting the
platform stamp each line — `docker logs -t`, journald, a log shipper — is sound and common, and
faulting it would be crying wolf. A timestamp the app **wrote without a zone** is a finding: no
platform repairs that, it is Python's logging default, and it is exactly what V16.2.2 asks about.
Both are read only from the line that records the event; a well-formed line elsewhere in the log
is somebody else's.

Timestamps are read in the shapes servers actually write: ISO 8601 with `Z`, an offset, or `UTC`,
and the common log format's `[26/Sep/2026:10:00:03 +0000]`. A version number, a date with no time,
and a duration are not timestamps, and a test says so.

**V5.4.1 reads the name the ordinary upload comes back under.** An upload fetched back is a
download, and the requirement asks that it be served under a name rather than leaving the browser
to take one from the address.

**V5.4.2 uploads a name built to break the header**: `sv-probe;svinjected=1.gif`, a legal file
name whose `;` and `=` start a new parameter if the app writes the name into `Content-Disposition`
unquoted. Nothing else sets a parameter called `svinjected`, so the question becomes exact: after
the round trip, does the header have one?

Reading that needs the header split the way RFC 6266 means it — never inside a quoted string, and
with `\"` inside one taken as a quote rather than its end. A naive split on `;` would *be* the bug
V5.4.2 is about. So the fake app has a correct variant that quotes the name without cleaning it,
`filename="sv-probe;svinjected=1.gif"`, which RFC 6266 allows; a check splitting on every `;` would
accuse that app of the exact fault it avoided, and two tests go red when it does.

Breaking each rule found two places where one witness was all there was, and one place where my
first attempt to break it proved nothing. Forcing `named` true *inside* `.any()` left the check
intact, because a header with no parameters never calls the closure at all; the break that shows
the rule is `named = true` outright. A break that cannot fail is not evidence of anything, which is
the same lesson as a test that cannot.

### Four more Level 1 questions

From the sweep of everything no check reached. Each reads something the run already has, or sends
one more request.

**V2.2.2 — the rules the form states, applied again on the server.** A form's own HTML is a list of
what the app says it wants: `maxlength`, `type=number`, `pattern`. Every one of those is something a
browser applies and anybody sending the request directly does not have to. So the probe reads one
off the sign-up page and sends a value that breaks it. A correct sign-up has to be accepted first,
or "refused" means only that sign-up does not work, and it is **only ever a finding**: an app that
refuses the broken value might be refusing it for some other reason.

**V7.2.1 — a session value this check invented.** The app's own cookie says what a session looks
like; this sends one of the same name and length that no session store could have issued. A private
page that opens for it is an app taking the cookie's word. Different from V7.2.3, which asks whether
a real session id could be *guessed*: this asks whether anything is checked at all.

That flaw is deliberately **not** in the table that asserts "this flaw and no other". An app that
believes any session id does not fail one check — default accounts sign in, sign-out ends nothing, a
password change needs no current password — because every one of those is asked with a cookie the
app now believes. Asserting isolation would be asserting something untrue, so it has a test of its
own saying why.

**V15.3.1 — fields that should not leave the server.** The record A reads back is exactly the place
to look for `password_hash`, `salt`, `api_key`. Only ever a finding: not seeing them proves nothing
about the columns this app happens to have.

The whole check turns on one distinction, and it is the one that would have sunk it: **a secret name
has to be a field, not a word.** Nearly every app has a page saying "change your password", and
matching the bare word makes a finding out of all of them. So `"password"`, `'password'` and
`password=` count, and prose does not. The fake app's *correct* record page now carries "Change your
password in Account" for that reason, which is why matching the bare word turns **seventeen** tests
red rather than one.

**V14.3.1 — `Clear-Site-Data` when signing out.** Read off the sign-out response already in hand.
Credit on presence only: the requirement names the header as something that "may be able to help",
and an app whose own script clears storage has met it without one, so absence is *not assessed*
rather than a failure. `"cookies"` alone does not count either — the session ending already cleared
the cookie, and what is left is everything the page kept.

**V1.2.2 was attempted and withdrawn**, and the reason is worth keeping: every rule in
`data/ast-rules.json` matches a *call*, with patterns for the function and the module. A
`javascript:` URL is a string literal that may simply be assigned, and nothing here scans literals on
their own. The plan that said "a rule in the same shape as `ast.download-piped-to-shell`" had not
checked that, and it was wrong.

### GraphQL, WebSocket, and a log line's format

Four more Level 2 requirements, from the first item of the new-tools list. Two new optional entries
under `[stack.run]` say where the app answers GraphQL and WebSocket connections; everything else was
already in hand.

**V4.3.2, introspection.** An introspection query for the schema. Whether an answer is a fault
depends on whether other programs are meant to use the API, which is the `public-api` claim, so the
claim travels into the run: introspection answered is a finding when the manifest says the API is
private, credited when it says it is public, and *not assessed* when the manifest is silent.

**V4.3.1, amount.** One request of a thousand aliases of `__typename`, which needs no knowledge of
the schema and costs a server nothing. The obvious alternative, a too-deep query, needs the schema
— which introspection being off withholds, so it would fail precisely for the apps doing the right
thing. And the answer is read from its start, not its end: probe bodies are kept to their first four
thousand characters, far short of `a999`, but servers apply amount and cost limits before running
anything, so `a0` coming back with no errors means the whole request was allowed. A test builds the
answer and cuts it the way real bodies are cut, to prove the check never needs the end.

**V4.4.2, WebSocket origin.** A handshake with no `Origin`, which is how non-browser clients connect
and how nearly every server accepts one, then one from a site the app has never heard of. The first
has to upgrade or the second proves nothing. A `101` needs no special handling: the raw socket the
probes speak over reads until five idle seconds pass, so an upgraded connection just ends there.

**V16.2.4, a common format.** The line the log check already finds is read for JSON, logfmt, or the
common log format. Credit on presence only: a processor can be taught any consistent line, and a
log shipper often structures lines on the way, so free text is *not assessed*. Logfmt needs at least
three `key=value` pairs making up half the line, so a sentence with one equals sign is a sentence.

Left out here: V15.3.5, type confusion, was on the list and is not built: a probe for it sends
sign-in requests shaped to get in without the password. V4.4.3 and V4.4.4 were left out at first
because a WebSocket's own session is only a fault if the connection is meant to be private, and
nothing said so; they are now asked, below.

**V4.4.3 and V4.4.4, a private WebSocket's session.** The owner says which socket needs a sign-in
with `private-websocket = "/ws"` under `[stack.run.users]`. The check signs A in afresh, so the
socket is asked with a session nothing else is using, and runs after the checks that need A's first
session. In order:

- **The signed-in handshake first.** It has to upgrade (`101`), or the path is not the socket or the
  socket refuses everybody, and the rest is *not assessed*.
- **V4.4.4, no real session.** The same handshake with no session, and with a cookie of the session's
  name and length and a made-up value. Either upgrading is a finding. Both refused is credited: the
  channel opens only through the signed-in session. When the session is not a cookie (a bearer token),
  a value cannot be made up that way, and a refusal with none is half the answer, so it is *not
  assessed* and says so.
- **V4.4.3, signed out.** The session is signed out with `logout`, and its old cookie sent in another
  handshake. Upgrading is a finding. It is asked only when the step before showed a real session is
  needed: a socket that lets anybody in lets in a signed-out cookie too, and the first version raised
  that as a second finding for the same fault. The fake app's socket for anybody is what caught it. A
  refusal is not credited: V4.4.3 asks that a socket's own tokens meet every session requirement, and
  ending at sign-out is one of them, which the report says.

Only the handshake is judged, and it is the handshake that carries the session; what the socket does
once open is not asked. The anonymous V4.4.2 check still sends its foreign-origin handshake with no
session, so for a private socket it now reports *not assessed*: the plain handshake is refused, so
there is no accepted handshake to compare the foreign one with. So the signed-in check asks V4.4.2
itself: once the signed-in handshake has upgraded, the same handshake from a site the app has never
heard of must be refused, and upgrading is a finding under the anonymous probe's rule. The fake app's
socket that checks the session and not the origin is its witness, beside the one open to anybody;
end to end, a scratch app that never read `Origin` was found and a copy that refused a foreign one was
credited.

Verified end to end with a scratch Python app answering the handshake itself: the careful one was
credited for V4.4.4 and said V4.4.3 was partial; one that lets a handshake with no cookie in raised
V4.4.4 and did not ask about sign-out; one that remembers signed-out sessions raised V4.4.3. The break
round found two guards with no witness — a handshake with no session let in while a made-up one was
refused, and a credit given when no value could be made up — and four with one; each now has two or
more.

### A mail server inside the fence, and password reset

A password reset is the one sign-in flow that cannot be followed without reading an email, so until
now it was a person's job. The run now gives the app a mail server — Mailpit, pinned to a minor
release like the probe image — on the same fenced network, whenever `[stack.run.users]` has a
`reset` entry. The app is told where it is in `SMTP_HOST`, `SMTP_PORT`, and `SMTP_URL`; it takes any
user name and password over plain SMTP, because there is nothing behind it to protect, and it is
hardened as the sidecar is, with one in-memory place to write. Mail sent to it goes no further. The
probes read it through Mailpit's HTTP interface, from the sidecar, matching every recipient field.

`reset` has two requests: `request`, with `{user}`, and `use`, with `{code}` and `{new_password}`.
The code is found in the email as a link's `token`, `code`, or `key`, or the last part of a link's
path under `reset`; `code-pattern` names any other place.

The setup is shown to work before anything is judged. The account (made for the purpose through
`signup`, or B) signs in; the email arrives; a code is found in it; using the newest code sets a
password that then signs in. Each failure is *not assessed* with its own reason, and the tests hold
the case the rule exists for: an app whose reset does nothing, which would otherwise read as "the old
password still works" and "a second use changed nothing".

Then four findings, and no credit:

- **V6.4.3, used twice.** The same code sets a second password, which signs in.
- **V6.4.3, the old password.** It still signs in after the reset.
- **V6.4.3, guessable.** Shorter than 20 bits by `most_bits` (six random digits is the least ASVS
  names), or two codes asked for one after the other that count up.
- **V6.3.8, whether an account exists.** Two requests for the account and one for an address nobody
  has. A different status is a finding. Different words are one only when the two requests for the
  same account were answered alike, after setting aside field values, long random-looking runs, and
  the address itself; an answer that changes between identical requests leaves the wording unjudged.

V6.4.3 also asks that a reset does not get round two-factor sign-in, and a safe reset code expires.
Neither is tried, so a clean reset credits nothing and says so. The rest of the mail-sink list —
V6.5.1, V6.5.4, V6.5.5, V6.6.2, V6.6.3 — is about codes sent to sign *in*, not to reset, and needs
its own entry; a reset code is not an out-of-band authenticator and is not counted as one.

Verified end to end with a scratch app sending through Python's `smtplib`: the correct one raised
nothing and its steps show the email arriving, the code working once, and being refused the second
time; the careless one (a four-digit code, reusable, 404 for an unknown address) raised all three.

### Signing in with an emailed code

The same mail server serves a second entry, `email-code`: an app that offers to email a sign-in
code or link beside the password. `request` asks for one with `{user}`; `use` sends `{code}`. Each
code is asked for and used in a browser session of its own, and a code counts as working when that
session then opens the private page. The code is found as for a reset, with the sign-in words
(`login`, `magic`, `verify`, `auth`, …) in place of `reset`, and a code written out after the word
"code".

In order, with the setup proven first — a code used where it was asked for signs in, or nothing is
judged:

- **V6.6.2, bound to its request.** Two sessions each ask for a code, and the first one's code is
  used in the second. Signing in is a finding. A refusal is credited only when the second session's
  own code then works, so the refusal is known to be about where the code came from and not, say, a
  session already locked.
- **V6.5.1, used once.** The first code again, from a new session. Signing in is a finding. A
  refusal is credited only when the step above showed codes working outside the session that asked:
  a code tied to its session is refused in a new one used or not, and the session it belonged to is
  already signed in. So an app with bound codes gets V6.6.2 and *not assessed* for V6.5.1, with
  that reason. This was caught by the fake app, not reasoned out: the first version credited single
  use for every bound-code app on a refusal that proved nothing.
- **V6.5.4, long enough.** Finding only, by `most_bits` over every code seen: under 20 bits.
- **V6.6.3, guessing.** Held to a number, `[policy] failed-codes`, as V6.3.1 is held to
  `failed-sign-ins`: one more wrong code than that, then the right one. Pushing back is any of
  refusing the right code afterwards, or answering the wrong ones differently, outright, or slowly.
  Run last of all, after the password guessing, and *not assessed* when the app was refusing before
  the first wrong code. It first shows a fresh code signing in, in a session of its own: without
  that, an app whose codes sign nobody in had its right code "refused after the guesses", and the
  first version credited that as pushing back. A second fixture, added only to give each guard two
  witnesses, is what caught it.

A form page is opened first in a session that has nothing yet, as a browser would. The first run
against a real app, a scratch Python app whose forms carry no anti-forgery token, reported it for
V6.6.2: with no `{csrf}` nothing made the probe visit a page, so both codes were asked for with no
session at all, and the app had nothing to tie them to. After the fix, the correct app got V6.6.2
and V6.6.3 checked and V6.5.1 not assessed, and the careless one (four digits, reusable, any
session, no limit) raised all four findings.

V6.5.5, a code's lifetime, needs waiting, and is asked only with `--slow` (below).

#### How long an emailed code lasts

V6.5.5 allows an out-of-band code ten minutes at most. With `sv run --slow` a code is asked for,
ten minutes and five seconds are let pass, and the code is used in the session that asked for it.
Signing in is a finding, `probe.email-code-long-lived`. A refusal is credited only when a code asked
for then, in a new session, signs in at once: the control that shows the old code was refused for
its age, and not because codes do nothing or the app stopped answering. The credit says how long
after asking the code was refused, to the second.

The session that asked is kept in use while it waits, a request for the code's page every two
minutes. A code tied to its session dies with the session, so an app whose sessions end after five
idle minutes would otherwise refuse a code that never expires, and a code that never expires would
be credited. The fake app's version of that is one of the witnesses. The sidecar's time limit grows
by twelve minutes when there is an `email-code` entry. Without `--slow` nothing is waited for, and
V6.5.5 says so for emailed codes, apart from what the two-factor check says about its own.

Verified end to end with the email-code scratch app under `sv run --slow`: the correct one, whose
codes expire after ten minutes, had its code refused 10 minutes 6 seconds after asking and a fresh one
sign in, and was credited; the careless one, whose codes never expire, signed in with the old code
and raised the finding. The break round found three guards with one witness each — the finding, the
session kept in use, and the control — and a sign-up fixture, in an app whose sessions end after five
idle minutes, is now the second witness for all three.

### An activation code emailed at sign-up

V6.4.1 asks that an initial secret sent to a new user, an activation code among them, be random,
used once, and short-lived. An app that emails one at sign-up says so with an `activation` entry
under `[stack.run.users]`: `use` sends `{code}`, and `code-pattern` finds the code when the usual
link places (`activate`, `verify`, `confirm`, `welcome`) do not. It needs `signup` and the mail
server, and says so when either is missing.

Everything the suite makes through sign-up would otherwise be locked out, so `sign_up` reads each new
account's email and uses its code quietly before going on; A, B, and every account the password
checks make are activated that way. The check itself uses plain sign-up, twice, so it sees the
accounts before activation:

- **The setup first.** Whether the first account could sign in before its code was used is asked
  and said. If it could not, and still cannot after the code, activation does nothing the probe can
  see and nothing is judged, however else it is broken. If it could, that is said: activation then
  guards nothing a password does not.
- **Guessable.** Finding only, from the two codes: under 20 bits, as for other codes, or two
  numbers fewer than a thousand apart, since whoever has one can work out the next.
- **Used again.** Only when using the code signed its account in, in a session of its own: then
  the same code from a second new session. Signing in is a finding. When the link signs nobody in,
  a second use cannot be told from the first, and V6.4.1 says that is not assessed.

Nothing is credited: whether a code expires would mean waiting, and whether a system-made initial
password can become the lasting one is not tried, and each run says both.

Verified end to end with a scratch Python app sending through `smtplib`: the correct one (a
24-byte random code, used once) raised nothing, and its steps show the account refused before
activation, signed in after, and the second use refused. The careless one (a counter, never marked
used) raised both findings. The break round found five guards with one witness each and one — that
reuse is tried only when the link signs in — with none; each now has two.

### Session timeouts, waited out

V7.3.1 and V7.3.2 ask for an idle timeout and an absolute session lifetime "according to documented
security decisions". As with `failed-sign-ins`, prose cannot be held to anything and a number can, so
the owner states two under `[policy]`: `idle-timeout-minutes` and `session-lifetime-minutes`. Checking
them means waiting, so it happens only with `sv run --slow` (or `sv report --run --slow`), and it waits
at most 90 minutes in all; a larger number is said and not waited for.

Two new sessions of A's, both shown to open the private page first. One is left alone. The other is
kept busy — a request every third of the idle timeout, never more than two minutes apart. After the
idle timeout and a minute more, the idle session has to be refused while the busy one still opens the
page; the busy one is the control that says the idle one ended for being idle, not because every
session died or the app stopped answering. After the lifetime and a minute more, the busy one has to
be refused too, and a sign-in begun then has to work — the control that says the app is still letting
people in. A refusal without its control is *not assessed*, and says why.

It runs early, straight after signing in is shown to work, because A's password is still the one it was
made with there; later checks change it when there is no sign-up. An idle timeout no shorter than the
lifetime is not judged: the busy session would end too, and the two could not be told apart. The
sidecar's time limit grows by the waiting.

### Verified against a real container

`tests/fixtures/probe-app` is a busybox CGI script that does two careless things on purpose: it sets
`session=abc` with neither `HttpOnly` nor `SameSite`, and it echoes back whatever `Origin` it is given,
with credentials. The second is what makes the end-to-end test a test of the *transport*: the fixture
only sends that header if the request really carried one, and it sends back the value it was given. On
24 September 2026 the run reported the cookie, the reflected origin and the missing headers, with the
fence verified as `--internal`.

Breaking the transport three ways confirms the test is what catches it, each at a different assertion:
`probe()` answering nothing, the header loop removed from `request_bytes`, and the response body
discarded in `parse_response` — all three go red.

Running the suite on more than one thread also found a real defect the single-threaded run had hidden:
the network and container names were the process id alone, so a second run in the same process asked
the daemon for a network that already existed and failed. A process that checks two apps, or rebuilds
one, hit it the same way. The names now carry a per-run counter, and a test runs the same app twice in
one process so that is checked deliberately rather than by how the tests happen to be invoked.

Two checks are **not** exercised end to end, and the test asserts they stay silent rather than guess:
busybox's own error page carries no stack trace, and busybox does not echo a `TRACE`. The `E404:`
directive that would have supplied a traceback is read from the config file and then ignored by this
build — asked directly in a throw-away container rather than reasoned about, which took two minutes and
settled it. Both checks are exercised against recorded answers in `sv-check`.

### Not trusting the flag

The runner asks the daemon whether the network really is internal before starting any untrusted code, and
refuses the run if the answer is anything but `true`. Passing `--internal` and verifying `--internal` are
different claims, and only the second survives a future edit that drops the flag.

Removing the flag was tried: the runner refuses to run at all and two tests fail. The failure mode is "refuses
to start" rather than "runs unfenced and reports a clean result", which is the fail-secure principle v1 lists
and the only acceptable direction for this particular mistake.

### Everything that cannot run is not assessed

No backend, no run command in the manifest, a backend that refuses, an app that never answers — every one
reports **not assessed**, never `pass` and never `fail`. A test enforces that each reason says so in those
words, because an app that will not start under `sv` has not been shown to be insecure. That test failed on its
first run against a message reading "could not be attempted", and the message was changed rather than the test.

The empty strings `sv init` prints (`image = ""`) are treated as unanswered, not as commands, so an AI tool that
leaves the placeholders produces "not assessed" rather than a container failing for reasons nobody can read.
