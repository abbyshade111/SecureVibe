# Send admin actions straight to the app as an ordinary user (V8.3.1, V8.2.1)

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

**The admin actions are
done on 27 September 2026:** `[[stack.run.users.admin-actions]]`, judged by a `check` page and a
marker per send, confirmed by the admin, after both sessions are shown signed in. See DESIGN, "Admin
actions, sent straight to the app". **The role-field probe below is done the same day** (claimed by
session securevibe-e8, at the owner's asking): findings only, against V8.3.1 and V15.3.3. See DESIGN,
"A role written into the sign-up form". Proposed on 27 September
2026 by session securevibe-e8, at the owner's asking. **Claimed the same day by session securevibe-e8**,
at the owner's asking, for the admin actions; the role-field probe below is not part of the claim.
Today V8.3.1 (authorization enforced
on the server, not in the browser) has supporting evidence only: an ordinary user is refused each admin
*page*. The owner's reasons that this does not settle it were that one page refused is not every rule
enforced, and that actions sent straight to an API are not tried (DESIGN, "The admin page, as support
for V8.3.1"). This probe answers the second reason. The first stays, and whether V8.3.1 can ever leave
`manualOnly` is the owner's decision, not this probe's.
**The owner's decision, 5 October 2026:** leave V8.3.1 on `manualOnly`.

**What the owner writes.** A list under `[stack.run.users]`, `admin-actions`, each entry a request only
an admin should be able to make, in the same shape as the other requests there (method, path, form or
JSON fields), for example changing another user's role, deleting a record, or publishing something.
It needs `seed`, which is already the only way to make an admin account. The run's container is
thrown away afterwards, so an action that changes data is safe to send, but the entry should say
so, and say that each action is sent twice.

**What the probe does, for each action,** following the admin-page check (`admin_checks` in
`crates/sv-check/src/signed_in.rs`) and sending through `send_filled`, as the other requests do:
1. Signed in as ordinary user A, send the action. Accepted means a finding against V8.2.1 and V8.3.1,
   rated high: the server acted on a request only an admin should be able to make.
2. Signed in as the admin, send the same action. This is the control. A's refusal counts only when
   the admin's request is accepted, because a refusal the admin also gets says the request was wrong,
   not that the rule was enforced. The rule this repository keeps: a refusal is evidence only when it
   can have no other cause.
3. Order matters: A goes first, so the admin's own success cannot have changed what A was refused.

**Open questions to settle while building it:**
- **What "accepted" means for an action.** For pages, a 2xx is the answer. An API can answer 200 with an
  error in the body, or 302 either way. An optional `check` request per action, a page that shows
  whether the action took effect, would let the probe judge the outcome by its effect instead of its
  status. It is worth deciding whether that is required or optional before the first line is written.
- **Tokens the form needs.** If an action needs a CSRF token from a page, check how `send_filled`
  already handles that for `change_password` and `owned` before inventing anything.
- **A second, smaller probe in the same area:** sign up with a made-up role field (`role=admin`,
  `is_admin=true`, `admin=1`) added to the sign-up request, then ask for an admin page. If it opens,
  the server trusted a value the browser sent, which is V8.3.1's own example and, arguably, V15.3.3
  (mass assignment: a field set that the action was never meant to take). Needs `signup`. Check the
  V15.3.3 citation against its wording before using it; it is Level 2.

**Evidence, stated plainly.** Refused actions confirmed by the admin control are more support for
V8.3.1 and are evidence for V8.2.1, which is already credited by the page check. They are still a
sample the owner chose, so V8.3.1 stays on `manualOnly` unless the owner decides otherwise. An accepted
action is a finding either way.

**Break it before calling it done:** no control (a refusal credited without the admin succeeding);
the admin sent first; an accepted action not reported; a 200 with an error body counted as accepted
(if `check` is built); the role-field probe run without `signup`.
