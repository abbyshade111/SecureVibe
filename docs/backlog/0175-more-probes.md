# More probes

**Status:** claimed by securevibe-e9, as its markers read on 8 October 2026

**Claimed on 26 September 2026 by session securevibe-e9.** The first four questions are asked (`sv-check/src/probes.rs`); they are the ones that
can be asked of any app by somebody who has not signed in. Redirects, HSTS on an HTTPS app, method
handling per route and anything that sends data need either a manifest describing the app's routes or a
session — both of which are their own items below.
**Six more done on 26 September 2026**, all asked of any app by somebody not signed in: unused methods
on the health path (V4.1.4), JSONP (V3.5.6), documentation and monitoring pages (V13.4.5), version
numbers in headers and error pages (V13.4.6), `Cross-Origin-Opener-Policy` (V3.4.8), and a
Content-Security-Policy that reports nowhere (V3.4.7). Level 2 goes from 63 to 64 of 183, Level 3 from
6 to 11 of 92. Redirects and HSTS stay open: inside the fence the app is reached over plain HTTP, so
whether it redirects to HTTPS, or sends HSTS there, is `sv probe`'s to ask of the live site. See
DESIGN, "Six more questions for anybody".
**Closed on 4 October 2026 by session securevibe-e9, which held the claim:** nothing in this entry is left. Redirects
and HSTS are `sv probe`'s (and since #595 are credited only when they hold); method handling per route and
anything that sends data need the app's routes or a session, which this entry already said are their own items.
A new probe is an entry of its own.
