# A real browser inside the fence

Some answers exist only once a page is drawn. Whether a sign-out control can be seen is not in the
HTML: the control can be there with `hidden` on it, or moved off the screen. Whether text somebody
typed is shown as text or run as part of the page is not in the response either, when the page puts
it together with script. `[stack.run.users.browser]` starts a headless Chromium on the fenced network
and asks both, signed in as the first test user. V3.2.2 (content meant as text is not rendered as
markup) can now be credited; before, a semgrep finding was all that could ever name it. V7.4.4 is
checked by what is drawn, beside the older check of what is in the HTML.

### Three containers, and none of them new to the fence

- **The browser** is `chromedp/headless-shell`, pinned to one Chromium version, so a run today and a
  run next month draw the same page the same way. It is hardened like the sidecar and the mail
  server: read-only, no capabilities, no new privileges, and memory for the one place it writes
  (`/tmp`). Chromium's own sandbox is off, as it must be in a container, so the container is the
  sandbox.
- **The driver** is a short script of `sv`'s own (`crates/sv-run/assets/browser-driver.mjs`) in the
  same stock Node image as the test provider, using Node's built-in WebSocket to speak the DevTools
  protocol. It has no network of its own: it joins the browser's (`--network container:…`), where
  the DevTools port is on 127.0.0.1 and the app is reached by its name, and nothing else is. It
  takes a list of plain actions (open a page, type into a form, ask the page a question, wait) and
  prints one answer for each. A list shorter than the job means it did not finish, and then nothing
  it said is used.
- **A forwarder** inside the browser's container (`socat`, which the image carries) makes the app
  reachable at `http://localhost:<port>`, the way a person runs an app on their own computer.

The last one was not in the first design. The browser first reached the app by its container
name, and the example app refused the typed note as a forgery: its own origin, as it knows it, is
`http://localhost:8080`, not `http://sv-…-app:8080`. Reaching it as `localhost` also makes Chromium
treat the page as secure, so `Secure` and `__Host-` cookies are kept over plain HTTP, as they are on
a developer's computer.

### Signed in with the plain requests' cookies, and checked to be

The browser is not signed in through the sign-in form. It is handed the first user's session
cookies, at the point in the run where that session is known to work and nothing has yet changed a
password, tripped a limiter, or signed the user in elsewhere. Then every private page has to open in
it, at its own address rather than a sign-in page, or nothing here says anything. An app that signs
in with a token in JSON gives no cookie to hand over, and the checks say so.

### What the typed line is, and how its answers are read

One line goes into the first box in the first form on `text-form`. It closes a quoted attribute,
then carries an image whose failure to load runs a line of script, and a bold tag, each marked with
a value made fresh for the run. The page that shows it (`shows`, or wherever the form leads) is then
asked four things: did the script run, did the marked tags become elements, is the line there as
the text typed, and is the mark there at all.

- **It ran:** a finding, High.
- **It became elements but did not run:** a finding, Medium. The usual reason is the page's
  Content-Security-Policy, which is a second line; the text is still going into the page as markup.
- **It is there as typed:** V3.2.2 is credited, for that form and that page.
- **The mark is there but the line is not as typed:** not credited, and not a finding. Something
  changed it on the way, perhaps a sanitizer, which is V1.3.1's business for rich text; it is not
  text shown as text.
- **Not there at all,** or any of the four not answered: nothing is said but why.

The mark is made from the run's randomness through a hash, not cut from it, because pieces of that
randomness are the test accounts' passwords, and the typed line is stored by the app.

### What running it for real found

- **The example refused its own forms in a real browser.** `examples/notes-with-users` sent
  `Referrer-Policy: no-referrer`, and under that policy Chromium posts a page's own forms with
  `Origin: null`, which the app's origin check refuses. No plain request could have shown it: the
  probes set `Origin` themselves. The example now sends `same-origin`, which keeps its addresses from
  other sites just the same, and trusts its origin with its port. A check for this in any app is on
  the backlog.
- **A test copy "hid" its sign-out button with an inline style, and the browser drew it anyway.**
  The app's policy (`default-src 'self'`) blocks inline styles, so the button was in plain sight,
  and the check was right to credit it. The broken copies now hide it with the `hidden` attribute,
  and move it off the screen with the policy removed; both are found.
- Against broken copies of the example: a note shown unescaped is High with no policy and Medium
  with one, and a note put inside an attribute is High. Each finding came from its own copy and no
  other.

### What the guards caught

Every guard in `browser.rs` was removed in turn and the tests run. Three survived the first time: a
form page that sent the browser to sign in (whose own form has a box to type into) was not noticed; a
browser that stopped part of the way was believed on what it had answered; and a page that said the
line was there as typed, but not whether its script ran, was credited. The third was a fault in the
code as well as in the tests: it was being explained as "changed on the way". Each now has a test,
and a page that does not answer all four questions is not judged.

V14.3.1, which needs the browser signed out, came next; see below.

### Signing out in the browser (V14.3.1)

V14.3.1 asks that a signed-in person's data kept in the browser is gone once they sign out.
The older check reads the sign-out response for `Clear-Site-Data`, credits its presence, and says
plainly when it is absent that nothing saw the storage being emptied. The browser now watches it
happen.

It runs late, after the plain checks have signed the first user out, and with a sign-in made for it:
clicking sign-out ends that session for good, so no later check can be using it. The job:

1. Open the sign-in page with no cookies, and note what the app keeps in `localStorage`,
   `sessionStorage`, and IndexedDB for anybody. A remembered color scheme is not a person's data.
2. Set the new session's cookies, open the first private page, and note what is kept now. What is
   new since step 1 is what the app kept for the signed-in person.
3. Click the first sign-out control a person could see, as they would, and look again.
4. Open the private page once more. It has to be shut, or the browser was never signed out.

Anything the app kept for the person that is still there is a finding, Medium, naming the keys.
All of it gone is credited, for that page. Nothing kept for the person is not credited: one page
keeping nothing says nothing about the others, and the header check still stands for what it is.
The browser never signed in, no sign-out control to click, a private page still open afterwards,
storage that could not be read, or a driver that did not finish: each is said, and nothing judged.

The example's account page now loads a small script that remembers when the notes were last opened,
and its sign-out's `Clear-Site-Data: "storage"` empties it, so it is credited. A copy without the
header is found, naming the key. A copy that stores the same thing for everybody, the sign-in page
included, is set aside as nobody's in particular and not credited. Removing each guard in turn, every
one was caught; the one that first looked uncaught was a mutation that changed nothing (the job has
exactly as many answers as the length it was relaxed to).

### What the signed-in pages send to other sites (V14.2.3)

V14.2.3 asks that sensitive data is not sent to untrusted parties, such as the services that track
visitors. The real browser already opens every private page signed in as the first test user, so it
also records every request those pages try to send to a host other than the app's own. The fence stops
each one from leaving; Chromium records the request before it tries (`Network.requestWillBeSent`), so
the address, the body, and the headers are all there to read. The driver's `outside` action hands the
list back, capped at 200 requests.

`sv` looks in that list for the test account's own details, in the forms a tracker is actually sent
them: the email address as written in any case, encoded into a web address, in base64, or as the
SHA-256 hash of the lowercased address, which is how the large advertising services ask for it; the
password as written or in base64; and the session cookie, when it is long enough (twelve characters)
that turning up by chance is not a possibility. Any of these found is a finding against V14.2.3, rated
high for a password or a session cookie and medium for an email address. The finding names what was
sent, how it was written, the host, and the page, and never the value itself.

It is only ever a finding. **Code a page loads from another site cannot arrive inside the fence**, so a
tracker's script from its own server never runs, and whatever it would have sent is never seen. What
is seen is what the app's own code sends: a tracking pixel written into the page, a request made by
the app's own scripts, and an analytics library bundled into them. So the run lists every other site
the pages tried to reach, scripts included, and the hand check for V14.2.3 says the rest is still the
owner's to look at. A server that sends to another site itself is not seen this way either. And base64
is matched only when the detail was encoded on its own: inside a larger encoded object its letters
shift with its position, and it is not found.
