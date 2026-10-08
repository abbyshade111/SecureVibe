# A token that says where its own key comes from (5 October 2026)

V9.1.3 asks that the key used to check a signed token come from a source set up ahead of time for its issuer, never
from the token. A JWT's header can carry `jku` (the address of a set of keys), `x5u` (the address of a certificate),
or `jwk` (a key written into the token itself). An app that follows any of them lets whoever made the token choose the
key it is checked with: make a key, sign a token as anybody, point the header at the key, and the signature checks
out. The owner decided on 4 October that both ways of looking for it are to be built (BACKLOG, "V9.1.3"); this is the
second, the code-reading rule. The first, a test key server the running app can be caught fetching from, is not yet
built.

`ast.token-key-source-from-token` reports a read of the token header's `jku`, `x5u`, or `jwk` handed, in the same
call, to something that fetches a key or makes one. Both halves are needed. The read is any of the forms the common
libraries give it in: `header["jku"]`, `header.get("x5u")`, `header[:jku]`, `getHeaderClaim("jku")`,
`GetHeaderValue<string>("jwk")`, `header.jku`, `$header->jku`, `header.jwk`, Nimbus's and jjwt's getters
(`getJWKURL()`, `getJwkSetUrl()`, `getJWK()`, and the rest) and their Kotlin property names (`header.jwkurl`), and
C's `jwt_get_header(jwt, "jku")` (libjwt) and `cjose_header_get(header, "jwk", ...)` (cjose). The call is named per language: HTTP clients (`requests.get`,
`urlopen`, `fetch`, `axios`, `http.Get`, `Net::HTTP.get`, `file_get_contents`, `HttpClient.GetStringAsync`,
`reqwest::get`, URLSession's `data`, `cpr::Get`, `curl_easy_setopt`), and what turns a key set's address or a key into a key (`PyJWKClient`, `PyJWK`, `jwk.construct`,
`jwksClient`, `createRemoteJWKSet`, `importJWK`, `jwkToPem`, `jwk.Fetch`, `JWT::JWK.import`, `JWK::parseKey`,
`RemoteJWKSet`, `UrlJwkProvider`, `RSASSAVerifier`, `JsonWebKey`, `DecodingKey::from_jwk`, `JWTKey.fromJWK`,
`cjose_jwk_import`). Kotlin's grammar reads `RemoteJWKSet<SecurityContext>(x)` as two comparisons, so its query also
takes that reading, and a call with type arguments is found. The names come from each
library's interface as known when it was written, not read again from each library's source this day. A call
outside that list is not reported whatever it is given, which is what keeps the safe forms quiet: a check against a
list (`TRUSTED.includes(header.jku)`), an address parsed to read its host, a log line, a function of the app's own
such as `is_trusted(header["jku"])`, and a key chosen by `kid` from the app's own table. A token being made with a
`jku` of the app's own is a dictionary written, not a header read, and is not reported either.

It is only ever a finding, at high severity and medium confidence, and the finding says why it may be wrong: a check
against a fixed list on an earlier line is not seen, and the advice says to record that with `sv review` if so. What it
misses is said in `looksFor`: the address saved to a variable first and fetched on a later line is not followed, so
finding none credits nothing. Every language `sv` reads code in has a query; shell has nothing to find, and says
why. Semgrep's rules still speak to V9.1.3 as before.

The test table has, for each of the fourteen languages, the read handed to a fetch or a key maker and the safe
forms beside it: 77 cases. Thirteen guards broken in turn, each caught: the call list dropped (13 cases), any header
name read (6), each of the eight forms of the read left out (between 1 and 11), Python's `decode` (1), Java's `new`
(3), and Kotlin's reading of a call with type arguments (2). The first version taught nine languages; the test that
holds every rule to every language `sv` reads failed on it, and the other five were written then. A first run of six
of the guards broke the pattern with a form Rust's regular expressions refuse, so every rule failed to load
and every test failed; that said nothing about the rule, and they were run again with a pattern that loads and
matches nothing.
