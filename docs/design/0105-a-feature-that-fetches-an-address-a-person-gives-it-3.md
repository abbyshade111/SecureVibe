# A feature that fetches an address a person gives it (3 October 2026)

`[stack.run.fetch]` names a feature that fetches a web address it is given, such as a link preview or an import
from a web address. `request` is the request with `{url}` where the address goes; `signed-in` and
`follows-redirects` are optional. The run starts the test model for this too. Its server records each request to
`/_sv/fetch/<tag>`, and `/_sv/redirect/<tag>` answers with a redirect to `/_sv/fetch/<tag>-after`.

- **V1.3.6 and V13.2.4.** The feature is given an address on the test server, on the app's own private network: a
  host nobody listed, on a port no service uses. Fetched is `probe.fetch-goes-anywhere` (CWE-918, high): nothing
  stopped the server going there. Not fetched is said and **never credited**. The fence has no address that should be
  allowed, so there is no control: a feature that refused the address cannot be told from one that did not work.
- **V15.3.2.** Only when the first address was fetched, the feature is given one that redirects. Its target fetched
  too is `probe.fetch-follows-redirect` (medium). Fetched without the target is credited: the first fetch is the
  control. When the owner says following a redirect is what the feature is for (`follows-redirects = true`), it is
  not asked.

Each run's addresses carry values made for it, so a fetch an earlier run caused cannot answer for this one.

Tried on 3 October 2026 with `sv report --run` on three small Python link-preview apps:
- one that fetches anything and follows redirects (`urllib`'s default): both findings;
- one that fetches anything and does not follow redirects: the fetch finding, and V15.3.2 credited;
- one that fetches only `example.com`: nothing found or credited, and the report says the address was refused (400)
  and why that is not credit.

Eight guards broken in turn, each caught, two of them in the test server's own Node test. Not held by a test: that
the run starts the test model for `fetch` when there is no `[stack.run.ai]`. That code runs only with Docker, and
the runs above are what show it.
