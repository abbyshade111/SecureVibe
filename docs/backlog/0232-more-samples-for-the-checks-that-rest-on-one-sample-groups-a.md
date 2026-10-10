# More samples for the checks that rest on one sample (groups A to H)

**Status:** open

The owner's word, 10 October 2026, asked with the three other open decisions of that day: "go with your recommendation and add to the backlog to add more checks to each of these."

The running checks that rest on one sample are being marked *checked in part* (ADR-053, Later, accepted the same
day; backlog 0006 part 4). This item is the other half: try more of each, so a check can earn plain *checked* again
by speaking for what its requirement names. One part per group of the inventory in
`docs/design/0359-one-action-one-race-one-redirect-one-svg-checked-in-part-10.md`; each is claimed on its own.

1. **A. Every response, not one or two.** Headers, cookies, content types, and error pages asked of every page the
   app answers and every route `stackvet.toml` names, not one or two anonymous responses.
   **Part status:** open
2. **B. Every private page and session path.** Session handling tried on each private page the owner lists and
   after each way of signing in, not one.
   **Part status:** open
3. **C. Each form, flow, and connection.** Cross-site requests tried on each changing route the app answers, each
   step of a flow, and each WebSocket path, not one request.
   **Part status:** open
4. **D. Each upload route, more than one file.** Every upload route the manifest names, with a small set of files
   per check rather than one.
   **Part status:** open
5. **E. Each kind of event.** Each event the requirement names made to happen and looked for in the log, not one
   line.
   **Part status:** open
6. **F. Each browser page and form.** The browser-driven checks run on each page and form the owner lists.
   **Part status:** open
7. **G. Each operation the requirement names.** Phone, two-factor, and recovery changes beside the email change
   (V7.5.1); password change beside sign-up for the password checks; both TOTP and an emailed code where both
   exist (V6.5.1, V6.5.5); one manifest key per operation.
   **Part status:** open
8. **H. More than one listed page.** The owner is asked, where only one private or admin page is listed, to list
   more; `sv init` and the prompts say why.
   **Part status:** open
