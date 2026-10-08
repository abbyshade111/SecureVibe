# `sv probe`: the questions only the live site can answer

Some requirements are about deployment rather than code, and reading a repository will never settle
them. `sv probe https://your-app.example.com` asks four: is the certificate one browsers trust
(V12.2.2), is plain HTTP still served (V12.2.1), is HSTS set (V3.4.1), and do cookies carry the
`__Host-` prefix (V3.3.3). Level 1 goes from 45 to 47 of 70.

### What it may do is most of the design

This is the first thing in `sv` that reaches outside the machine it runs on. Everything else reads
files, or talks to an app inside a fence that cannot route anywhere. A tool that fetches an address
somebody supplies is a tool that can be pointed at a stranger, so each limit is narrow and each one
has a test:

- **The address comes from the command line and nowhere else.** Not from securevibe.toml: a file can
  be committed and then run by CI against a host its author never meant, while an argument was typed
  by somebody looking at the terminal. That is the only consent available, because nothing here can
  prove who owns a domain.
- **Read-only.** `--head`, so no body is even downloaded. No cookies, no `Authorization`, no form.
- **A hard cap of four requests**, enforced in the fetcher rather than the caller, so a caller that
  loops cannot turn a look into a scan.
- **One host.** A redirect to a different host is reported and not followed — otherwise the owner's
  own address could hand the probe somewhere they never named.
- **No path guessing.** It asks for the address it was given, which is the line between a look and a
  scan.

`curl` rather than a Rust HTTP client, for the reason the tool adapters are external programs: it is
everywhere, it uses the platform's trust store, and its TLS is maintained by people who do nothing
else. Absent, the check says so and settles nothing.

**Verification is never disabled to get a result.** The handshake failing *is* the answer to V12.2.2.
The one place `--insecure` appears is to tell an untrusted certificate apart from a host that is not
there, and the outcome is a finding either way, never a pass.

### Two more things about the live site

Encrypted Client Hello (V12.1.5) and the HSTS preload list (V3.7.4), both Level 3, and neither sends
the site anything.

**ECH** is advertised in DNS: a browser learns a site offers it from the `ech` parameter of the site's
HTTPS record (RFC 9460). So `sv probe` asks this computer's own resolver, from `/etc/resolv.conf`, for
that record — one UDP question, the same one any browser visiting the site asks. The DNS is spoken
directly, about a hundred lines, and read against real answers kept as fixtures: a name that offers
ECH, one with an HTTPS record without it, and one with none. A record offering ECH is credited; a
record without it, or no record, is a finding. An answer that cannot be read — another question's,
cut short, truncated, a server failure — is *not assessed*, never "no records", because an empty list
is what the finding is made of. A record that only points at another name (an alias) is not followed,
and its parameters are not read, since an alias's mean nothing.

**The preload list** is Chromium's `transport_security_state_static.json`, which the owner downloads
and passes with `--hsts-preload FILE`. `sv` never fetches it and never asks a lookup service, because
either tells a third party which site is being checked. It is JSON once its `//` comment lines are
removed. A name is covered by its own entry, or by an entry above it that includes subdomains —
which is how a whole top-level domain such as `.dev` is preloaded, and how `api.github.com` is
covered by `github.com`. Checked against the full list as downloaded on 26 September 2026, 94,778
entries: `github.com` on it, `crypto.cloudflare.com` covered by `cloudflare.com`.

OCSP stapling (V12.1.4) was on the same list and is not done: the machine this was built on reaches
the internet only through a proxy that replaces every certificate, so a stapled answer could never be
seen there, and a check tested only against the text a tool prints was not worth shipping. Level 3 goes
from 4 to 6 of 92.

### Two faults found by running it against real sites

Neither would have been found by reasoning about the code, and both were on the flattering side.

**It reported a missing header on a site that sends one.** Through a proxy, `github.com` answered
`400`, which carries none of the site's own headers — and the check read that as the site failing to
send HSTS. An error answer is not what a visitor gets, so the header questions now require an
ordinary answer first and say so when they do not get one. The certificate question is unaffected,
because the handshake is the evidence there whatever the status.

**A proxy's `HTTP/1.1 200 Connection Established` was parsed as the site's answer.** It is the
tunnel's own status line, and counting it clears the headers that arrive after it.

And one in the terminal output: with nothing reachable, it printed "Nothing it asked about came back
wrong", which reads as a pass for a site it never touched. It now says it could not reach the address
and has nothing to say either way.
