# An app that refuses its own forms (no requirement)

Found on the way to the browser checks: under `Referrer-Policy: no-referrer`, the Fetch standard has
a browser send `Origin: null`, and no `Referer`, with every request that is not a GET or a HEAD,
including the app's own forms. An app that also refuses `Origin: null`, which a strict cross-site
defense reasonably might, refuses its own forms in every real browser. A test client that sends no
`Origin` at all never sees it, and the usual fix someone reaches for is to switch the defense off.
Nothing in ASVS asks an app to accept its own forms, so this is a finding with no requirement behind
it (`probe.own-forms-refused`, Low), and it credits nothing.

After the cross-site checks, signed in as the first user, the page the `owned` create request is
made from (its own path, else the first of the `private` pages that answers) is read for its
`Referrer-Policy` header, taking the last value a browser knows, as a list is read. Only when that
is `no-referrer` is the create request sent again as a browser would then send it: the page's token
in it, `Origin: null`, no `Referer`. The same request is sent straight after without an `Origin`, as
the other checks send it, for the control.

- **Refused (4xx) with `Origin: null`, and taken without it**, is the finding, naming the page and
  both answers.
- **Taken** is a line in the steps, and nothing else.
- **Anything else**, the control refused too included, is a line in the steps saying it shows
  nothing about the `Origin`.
- **Not read:** a `<meta name="referrer">` in the page, or a `referrerpolicy` on the form itself.
  Either would make a browser send the same thing, and neither is seen here.

Tested against the fake app with the policy and a refusal of `Origin: null` together (found), each
alone (nothing), and a create request without its token (the control refused too, nothing); and
against a one-form app whose policy is a list ending in `same-origin` (not asked). Each of six breaks
(the check not run, the `Origin` left alone, the control ignored, the token left out, the policy not
required, the first value of a list taken) turns two or three tests red.
