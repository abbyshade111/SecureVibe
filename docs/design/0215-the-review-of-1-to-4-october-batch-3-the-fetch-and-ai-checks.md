# The review of 1 to 4 October, batch 3: the fetch and AI checks wait for and read the answer (6 October 2026)

Items 5, 6, and 7 of the review of the code merged on 1 to 4 October (BACKLOG). Each check credited, or found, on an
answer it had not waited for or had not read.

- **A redirect not followed yet is not a redirect refused (item 5, V15.3.2).** `sv` asked the test server whether the
  app had gone on from the redirecting address the moment the app answered. An app that answers first and fetches
  afterwards, or whose fetch was still on its way, was credited for not following redirects. Now a redirect not followed
  is asked about again three times, three seconds apart, before it counts as not followed. The credit also needs an
  answer of the app's own: no answer, a crash (5xx), or a limiter (429, or 503 with `Retry-After`) says nothing about
  whether the app chose not to follow, and is not assessed.
- **A loop that ended on an error is not a limit (item 6, C9.1.2).** The agent limit was credited for any 2xx answer
  with fewer than 40 tool rounds. That included an app that caught its own error part-way through the loop and answered
  200 "Sorry, something went wrong". It also included an app that answered at once and ran the loop afterwards, read
  part-way through. Now the rounds are read again, three seconds apart, until two reads agree; if they are still growing
  after fifteen seconds, it is not assessed. An answer whose words say something went wrong ("went wrong", "error",
  "exception", "failed", "failure", "timed out", "timeout", "traceback") is not taken for a limit either, and the
  report quotes the word. A careful app whose ordinary answer happens to contain one of these words loses the credit
  too: a lower bar would let the error through.
- **A busy service is not a broken one (item 7, V16.5.2).** After the AI service fails on one message, a plain
  message follows. A bare 429 on it was excused, but a 503 with `Retry-After`, which ADR-021 reads as a limiter's too,
  was a Medium finding. Now either is waited out (the `Retry-After`, at most 60 seconds) and the message sent once
  more; a limiter's answer again is not assessed, never a finding.

Broken on purpose ten ways, each caught by a test written for it; the re-reads are on a fake clock in the tests, so
no test waits for real. Not run against a real app here: the Docker tests that drive these checks run on CI.
