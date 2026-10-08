# HTTPS redirects and HSTS, held to what they say (4 October 2026)

The deep review of `sv` at `eff3f17` (BACKLOG, part 2, H12 and H13) found `sv probe` crediting two things on their form
alone.

- **H12, the redirect from plain HTTP (V12.2.1).** A 301 or 308 was credited as "sent the browser to HTTPS" wherever
  it pointed: to `http://` again, or to a relative address such as `/login`, which keeps the browser on plain HTTP.
  Now only a redirect to an absolute `https://` address on the host the owner named is credited, and a temporary one
  of that kind is still the finding it was. Any other redirect is not assessed, permanent or temporary, with the
  address it named: where the browser ends up would take following it, and `sv probe` asks only the addresses the
  owner gave, never one an answer points to. The scheme and the host are compared without regard to case, as browsers
  compare them.
- **H13, Strict-Transport-Security (V3.4.1).** Any value was credited, `max-age=0` included, which tells a browser to
  forget the site's policy, and it was credited on error answers too, whose headers the code had already set aside as
  not the site's own. V3.4.1 asks for a max-age of at least a year, and from level 2 for the policy to cover every
  subdomain. The header is now read the way a browser reads it (RFC 6797): directive names in any case, a quoted
  number allowed, and a header with no readable max-age, or a directive given twice, ignored. Less than a year, `0`,
  or a header browsers ignore is a finding that says which. A year or more with includeSubDomains is credited. A year
  or more without it is not assessed: it is what level 1 asks and not what level 2 asks, and `sv probe` is not told
  which level applies. An error answer's header is neither credited nor found.

Eight guards were broken in turn: accepting any max-age above zero, ignoring includeSubDomains, reading error answers,
accepting a directive given twice, accepting a max-age that is not a number, crediting any redirect, crediting any
scheme, and comparing hosts letter for letter. Each was caught by the test written for it, and reading error answers
by an earlier test as well.
