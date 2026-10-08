# A request another site can send without asking (V3.5.2)

A page on one site can make a browser send a request to another, with that person's cookies, but
only a "simple" one: a form, multipart, or `text/plain`. Anything else, such as a JSON request, makes
the browser ask the app first (a CORS preflight), and an app that answers no is safe from it. Many
JSON APIs rely on exactly that and have no anti-forgery token. V3.5.2 asks that such an app cannot be
reached the simple way instead. Level 1 goes from 53 to 54 of 70.

The `owned` create request, when securevibe.toml writes it as JSON, is sent three more times after
the cross-site check: its fields as `text/plain` (the JSON itself, which many servers parse whatever
the header says), as a form, and as multipart. Each carries the first user's cookies, another site's
`Origin`, and no token. It runs only after the ordinary create has worked and been read back, so a
refusal is not the endpoint being broken.

- **Taken in any form** is a finding, naming which, rated as the cross-site check rates its own: High,
  or Medium when the session cookie's SameSite would keep a browser from sending it at all.
- **Refused in all three** is credit, for that request.
- **Only a 2xx counts as taken and only a 4xx as refused.** The cross-site check counts a redirect
  as taken; here a redirect, a server error, or no answer says neither, and two refusals and a
  redirect is not three refusals.
- **A create request written as a form** is not assessed: a browser sends a form from any site without
  asking, so no preflight is being relied on, and whether the app refuses it is V3.5.1's question.

The two checks answer different questions about the same JSON request. The cross-site check sends it
as JSON from another origin, which a browser would only do after asking; an app with no token and no
look at the `Origin` is a V3.5.1 finding there even when the preflight would have stopped a browser.
This one asks whether the preflight can be walked around.

Tested against a fake JSON API in each shape: taking JSON only (credited), reading a JSON body
whatever its type (`text/plain` named in the finding), taking forms and multipart too (both named),
checking the `Origin` (credited even when it would parse anything), redirecting what it will not take
(nothing said), and redirecting only multipart (not three refusals). Each guard was removed in turn
and every one was caught; the last, crediting on fewer than three refusals, only after the
redirect-only-multipart case was added. Not run against a real app in Docker: the transport already
frames a body by its length, and the multipart header is an ordinary header value.
