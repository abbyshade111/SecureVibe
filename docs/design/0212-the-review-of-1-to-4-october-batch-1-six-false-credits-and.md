# The review of 1 to 4 October, batch 1: six false credits and accusations (6 October 2026)

The review of the code merged on 1 to 4 October found 24 faults (BACKLOG, "A review of the code merged on 1 to 4
October 2026"). At the owner's word they are fixed in batches, the worst first. This batch is the six where `sv` credited
something it had not seen, or accused a correct app.

- **A slow first answer is not a certificate problem (item 1).** `sv probe` asks HTTPS with verification on and, when
  that fails, once more without, to tell an untrusted certificate from a host that is not there. Any failure followed
  by an answer was called an untrusted certificate, a high finding. A host waking from sleep misses the 15-second limit
  once and answers the retry. A failure is now a certificate problem only when curl says so (its message names the
  certificate); otherwise the certificate, the stapled status, and the headers are not assessed, and the probe says to
  run it again. Where it is a certificate problem, the stapled status and headers are now said not to have been read.
- **Plain HTTP asked on its own port, and credited only for a refusal (item 2).** The plain request kept the port the
  HTTPS address named, so `https://host:443/` had its "plain HTTP" asked of the TLS port; and any curl failure, a
  timeout or an empty reply among them, was credited as "no plain-HTTP way in". It is now asked on port 80, held to the
  checked address there too, and credited only for a refused connection; any other failure is not assessed.
- **No proxy (item 3).** curl read this computer's proxy settings, and a proxy looks the name up itself, so the request
  was not held to the address that was checked (ADR-027's pin). Shown here: with `HTTPS_PROXY` set, curl with the probe's
  flags connected to the proxy; with `--noproxy '*'`, to the pinned address. curl is now always told to use no proxy.
- **The app's own MCP server: a refusal must be one (item 4).** A rate limiter's 429 counted as the server refusing,
  for five checks; it is now no answer, as ADR-021 reads it. Origin and Host (C10.3.3) are credited only when both
  foreign requests were really refused and an ordinary request sent just after still starts a session, so a server
  that refuses every second session is not credited for checking where requests come from. An ended session (C10.2.6) is
  credited only for a real refusal, not a crash.
- **An upload fetched back must be the upload (item 12).** The three checks that fetch an uploaded file back judged
  whatever the address answered, so an app that keeps uploads under names of its own and answers every address with its
  page was credited for not running the `.php`, and found to render the `.html` and keep the SVG's script (the page's
  own `<script>`). Each now judges only an answer that carries the file's own mark; the SVG carries a second mark on
  its drawing, which a cleaner that removes the script keeps.
- **The cookie set at sign-in is the session only when the page needs it (item 13).** The checks took the cookies set at
  sign-in to be the session. An app that keeps its session from before sign-in and sets an unrelated cookie at sign-in
  was found to accept a made-up session (that cookie, altered) and credited for issuing a new session at sign-in. One
  request now asks the private page with the cookies sign-in set left out: refused, they are the session and the checks
  stand; opened, the session from before sign-in is the signed-in one, which is the renewal finding, and the cookie
  checks are not assessed; not answered, nothing is judged on the guess.

Broken on purpose twelve ways, each caught by a test written for it; two of the first run did not count (one would not
compile, one had moved when the file was formatted) and were run again. Not tested against a real site or app.
