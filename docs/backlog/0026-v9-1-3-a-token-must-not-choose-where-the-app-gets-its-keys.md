# V9.1.3: a token must not choose where the app gets its keys (level 1)

**Status:** done, as its markers read on 8 October 2026

Left out of item 4 below by the owner's
word, then taken up on 4 October 2026: the owner asked session securevibe-e9 what a test key server would take and
give, and decided **both options are to be built**: "I think it's worth building the key server for the stronger
evidence since this is such an important check, and it can't hurt to have the code-reading rule as well." **Each
can be claimed on its own.**
1. **A test key server inside the fence, for the running app.** The test server the run already starts for
   `[stack.run.fetch]` and `[stack.run.ai]` records every request to a tagged address. It would answer one more
   tagged address as a set of keys, and the token check (`crates/sv-check/src/signed_in/tokens.rs`) would send the
   test user's token once more, pointing at that address, then ask the server whether the app came for it.
   - **Fetched is the finding.** The app let a token choose where its keys come from. That shows the fault without
     the app having to accept anything, so the check never needs a token the app would accept.
   - **Not fetched is never credit,** and is said: an app that ignores that part of a token cannot be told from one
     that checks it against a list. The same reasoning as `probe.fetch-goes-anywhere`.
   - **The test server would start for any run that signs in,** since `sv` only learns the app uses tokens after
     signing in: one more small container per run.
   - **Covers the `jku` form, and `x5u` the same way.** Not `kid`, which misuses the app's own key lookup, needs no
     key server, and stays out by the owner's word on item 4.
   - About the size of item 6 (`[stack.run.fetch]`): the server's new address, one more request in the token check,
     a flaw switch in the scripted app, break tests, and the crash-sweep scenario.
   - Expected to fire rarely, but to be strong evidence when it does. The common token libraries for Node, Python,
     and Go are thought not to fetch from an address in the token unless the app's own code wires it up; this was
     not checked library by library.
   **Claimed on 5 October 2026 by session securevibe-e2**, at the owner's word ("go ahead"), in branch
   `claude/securevibe-e2-key-server`.
   **Done the same day** (DESIGN, "A sign-in token caught naming where its key is"): when the app's own token is a
   JWT, the token checks send it twice more with its header naming an address on the test model's server, as `jku`
   and as `x5u`, and ask the server whether the app came for either. Fetched is `probe.app-token-key-source-followed`
   (high); not fetched is not assessed, never credit. Any run that signs in now starts the test model. Eleven guards
   broken in turn, each caught. Not shown in a real run: no container backend was available, so starting the test
   model for a signed-in run is read in the code, not seen working.
2. **A code-reading rule.** It flags an app that passes the token's own key address (`jku`, `x5u`, or a `jwk` in
   the header) to whatever fetches its keys. Cheaper, and it runs in every check without Docker, but it is weaker
   evidence than the app seen fetching. Today only Semgrep speaks to V9.1.3 by reading the code. Like the other code
   rules: a finding where the pattern matches, never credit where it does not.
   **Claimed on 5 October 2026 by session securevibe-e2**, at the owner's asking to continue with the backlog, in
   branch `claude/securevibe-e2-v913-rule`.
   **Done the same day** (DESIGN, "A token that says where its own key comes from"): `ast.token-key-source-from-token`
   reports a token header's `jku`, `x5u`, or `jwk` handed, in the same call, to something that fetches a key or
   makes one, in each of the fourteen languages `sv` reads code in; shell has nothing to find, and says why. Only
   ever a finding, at medium confidence: a check against a list on an earlier line is not seen, and a value saved
   to a variable first is not followed.
