# A burst of creations, held to a stated limit (3 October 2026)

V2.4.1 asks for limits against excessive calls to the app's functions. `probe.create-rate-unlimited` (CWE-770, medium)
takes the shape of the AI feature's limit (C11.2.2) and applies it to the one action the manifest already names for
creating things, `owned`:

- **The owner states the number.** A new `[policy] requests-per-minute` gives the records a minute one user should
  be able to create. Without it nothing is sent or judged. A limit kept by a proxy in production is not in the fenced
  run, so "no limit seen here" alone would accuse apps that have one. That is why the backlog's proposal to report every
  app with no limit as a finding was not taken up. Numbers of 0, or of 100 and above, are not tested.
- **What is sent.**
  1. B signs in and is shown a private page.
  2. After a minute's wait, one more than the stated number of records is created, inside a minute.
  3. The private page is asked for again.
  4. Then another minute's wait, so the limit this set off no longer refuses the checks after it.

  This runs before the password questions, which can change both A's and B's passwords: without `signup`, the
  password change uses A, and a reset uses B. A first version ran it last, and its sign-in failed for exactly that
  reason.
- **Session checked before and after.** An app answers a request from somebody signed out with a redirect to its
  sign-in page, and a redirect reads as the record going through. If the session stops opening the private page, the
  burst is not judged.
- **The requests are not waited out.** Their ids begin `burst-`, which `Patient` now treats like the guessing checks'.
  A limiter's 429 is the answer being measured, and waiting it out would send one more than counted.
- **What is read.**
  - Every record going through is the finding.
  - The first going through and the last refused is credit for that one action, scoped as such: V2.4.1 names many
    functions, and this tries one.
  - It is not assessed when the first is refused, when the burst took over 55 seconds, when one crashed, or when the
    last went through after others were refused, which is not a limit that stayed shut.

The scripted app gained a per-user limit on notes, off by default, and a variant that lets every other note through
past it. These guards were broken in turn, and each was caught:
- the session check;
- the last going through;
- the first refused;
- the finding needing every record through.

The "last going through" break was missed at first, which is what led to the leaking variant. The burst's credit is
listed in `RESTS_ON_A_REFUSAL`, and the crash test's "signed up" scenario states a limit the app does not keep.
