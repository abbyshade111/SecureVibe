# An action sent many times at the same instant (3 October 2026)

V2.3.4 asks that an action which should happen once cannot happen twice when two requests arrive together: the last
seat booked twice, or a one-time code redeemed twice. The usual cause is a gap between reading ("is one left?") and
writing ("taken"), which requests one after another never hit. So this is the first check that sends requests at
the same instant.

- **The owner names the action.** A new optional `once` entry under `[stack.run.users]` gives the request and its
  `completed` text, in the page or the address it sends the browser on to, as `flow` does. The app has to start the
  run with exactly one of the thing to take, set up by `seed`, and nothing else in the run takes it.
- **What is sent.** A signs in, reads the page's token once, and the same request goes out 20 times together, each
  over its own connection.
- **What is read.**
  - Two or more answers carrying `completed` is `probe.action-done-twice` (CWE-362, high).
  - Exactly one, with every other copy answered and refused, is credited for V2.3.4, scoped as "one race, tried once".
  - None going through leaves it not assessed, since a refusal then shows nothing.
  - One going through beside a copy that crashed or got no answer is not assessed. That is held twice: in the check
    itself, and through `RESTS_ON_A_REFUSAL`, which `Patient` feeds.
  - One going through beside copies a rate limit turned away (429) is not assessed either. Those copies never reached
    the action, so the race was not run between them, and a limit is not a lock.
- **Sending at once.** `Http` gained `send_at_once`. Its default says the runner cannot, which leaves V2.3.4 not
  assessed, rather than sending the copies one after another and crediting a race that never ran. The Docker runner
  does it with one script inside the fence: every `nc` is started in the background before any is waited for, each
  answer goes to its own file, and all are printed in order, behind a mark of their own.

**How the sending was tried.** This environment had no Docker daemon, so the script `sv` builds was run on its own:
- with a stand-in for busybox's `nc -e`, against a local server holding a 200 ms gap between reading and writing;
- all 20 copies arrived within 51 ms of each other, and all 20 booked the one seat;
- the same script against the same server with a lock booked one and refused 19;
- the runner's own parser read both sets of answers back correctly.

The busybox image itself has not run it yet.

**Break tests.** The scripted app gained `POST /book` with one seat, and three flaws: booking that races, booking that
never works, and a rate limit on copies after the first. Each guard was broken in turn:
- two going through not treated as a finding;
- the rate limit ignored;
- the count cut to one.

Each was caught by a test. The crash guard was caught only with both of its holds removed, as expected for a guard
held twice.

### Later, 5 October 2026: two users, not one

The check sent every copy as A and counted the answers carrying `completed`. Testing the design-time prompts, it
reported a booking that went through once as twenty: the build made with the "actions that must happen once" prompt
took the seat in one step and answered a repeat from the member who already held it with "Booked" again, changing
nothing, which is what that prompt asks for. An app's answer cannot tell "taken now" from "already yours". The owner
chose, of the two ways out, to send the copies as two users.

- **What is sent.** A and B each sign in and read the page's token, and the 20 copies go out together, A's and B's
  taking turns, so neither user's all leave first.
- **What is read.** `completed` in answers to both users is the finding: two people cannot both have the one thing there
  was. `completed` for one user only, however many of their copies say so, with every copy from the other answered and
  refused, is credited. The rest of the rules hold as before: nothing going through, a crash, or a rate limit's 429
  leaves it not assessed.
- **What a refusal has to show.** The crash sweep found the hole two users open: if B's sign-in or B's token silently
  failed, B's copies were refused for that, not because the seat was taken, and were credited. So both users are shown
  signed in (the first `private` page opens) before the copies go; each request must carry the token when the
  template asks for one; and the user whose copies were refused must still open that page afterwards. Each failing is
  not assessed, saying which. A `private` page is now needed for credit.
- **Sending together.** `Http::send_at_once(request, times)` became `send_together(requests)`. The container script
  takes the different requests one after another on its input, cuts each into a file of its own from the file it saved
  (never from the pipe, so no request takes bytes of the next), and starts copy `i` with request `which[i]`. It was run
  with busybox 1.36, the sidecar's own, against a local server that waits 300 ms on each request: the 20 copies were
  all answered in 1.4 seconds (one after another would take 6), each carrying its own user's cookie in the order
  given, and each body arrived whole.
- **Tested.** Ten guards broken in turn, each caught: the old rule (any two completions), every copy sent as A, both
  counts read from A's copies, no sign-in shown before or after, the check after asked of the holder, no token guard,
  the container sending the first request for every copy or cutting the second from the start, and the fake app's
  correct repeat removed. The token guard was caught only by the crash sweep at first, so a test aimed at it was
  added, and it fails alone when the guard goes.
