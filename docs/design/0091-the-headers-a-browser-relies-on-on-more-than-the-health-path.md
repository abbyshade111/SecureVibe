# The headers a browser relies on, on more than the health path (3 October 2026)

`probe.security-headers` and `probe.cookie-attributes` used to judge one answer: the one on the health path, which
is often a small JSON status reply nobody sees. They now also ask for the root page, `/`, when the health path is
something else, and judge it whenever it answers with a page of its own (a root that answers 404, as an app that
is only an API does, is not judged). A finding names the page that fell short, and the credit is given only
when every page judged passes, naming them, so a health path with every header no longer speaks for a root page
without them. The content-type and opener-policy checks read the root page too.

The pages a signed-in person sees are the ones that show their own data, so `probe.private-page-headers` asks
the same four headers of every private page `[stack.run.users]` lists that opened for the test user, beside the
caching and sign-out checks that already read those answers. It cites the same requirements as
`probe.security-headers` under its own name: a private page missing a header is a finding even when the public
pages pass, and a finding outranks any credit for the same requirement, so one cannot hide the other.
