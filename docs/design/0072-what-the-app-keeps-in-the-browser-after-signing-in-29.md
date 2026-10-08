# What the app keeps in the browser after signing in (29 September 2026)

Two requirements about what a page's own scripts can read: V14.3.3 (no sensitive data, such as the password, in
browser storage) and V10.1.1 (sign-in tokens only where they are needed). Anything in `localStorage`,
`sessionStorage`, IndexedDB, or a cookie without `HttpOnly` can be read by every script on the page, so a cross-site
scripting bug or a rogue package takes it as easily as the app reads it.

**Signing in the way a person does.** The other browser checks hand the browser the cookies of a sign-in the plain
requests made. That cannot show this: a page that keeps the password does so in the sign-in page's own code, which
then never runs. So this check opens the sign-in page, types the first test user's name and password into the first
form with a password box (setting each box the way typing does, so a page whose code watches its boxes sees them),
presses its button, and opens the first private page. That page opening is the control: if it does not, or there was
no such form, nothing is said and the report says why. The test password reaches the browser the way the session
cookies already do, in the job handed to the browser's driver inside the fence.

**What is read.** The values, not only the names: every `localStorage` and `sessionStorage` entry, up to 200 records
of each IndexedDB store, and `document.cookie`. It is read once on the sign-in page before signing in and once after,
and what was there before is set aside. A kind of storage that could not be read is named in the step.

**V14.3.3.** The test password in any of those, as typed, in base64, or encoded into a web address, is a finding
(High), `probe.password-in-browser-storage`, naming where. The account's email address is shown in a step and is not a
finding: many apps keep it to show who is signed in.

**V10.1.1.** In storage (not cookies: a session cookie without `HttpOnly` is its own check), a value is a sign-in
token when it is kept under a token's name (`access_token`, `accessToken`, `id_token`, `sb-…-auth-token`, `jwt`,
`token`) or has a JSON Web Token's shape, and is at least 16 characters. Values that are JSON, as sign-in libraries
keep them, are looked inside, so Supabase's `refresh_token` in `localStorage` and Firebase's `refreshToken` in
IndexedDB are found. A refresh token is a finding at Medium; an access token alone at Low, and the finding says that an
app running entirely in the browser may need one there. `probe.token-in-browser-storage`.

Both are only ever findings: one page after one sign-in is not the whole app. No stored value is ever written into
the outcome; a place is named by its kind and key, and a token by its kind and length. A test checks that neither the
password nor a token appears in anything the outcome says.

Broken on purpose fifteen ways, each caught: each of the three controls (the form found, the page opened, the plain
requests' sign-in) dropped, the before-and-after comparison dropped, the encoded password missed, the base64 password
missed, refresh tokens not told apart, JSON not looked inside, short values taken as tokens, the JSON Web Token shape
not looked at, cookies searched for tokens, one severity for both, the stored value written into the finding,
unreadable storage not said, and the suite not calling the check.

**Not done here.** Tokens sent to other sites, which the backlog entry also named: an app built on a hosted backend
at another address (a hosted database service, say) sends its sign-in token there by design, so a finding would be a
false alarm for exactly the apps most likely to keep tokens in the browser. The pointers from the code (`setItem`
calls whose key names a token or a password) are not added.
