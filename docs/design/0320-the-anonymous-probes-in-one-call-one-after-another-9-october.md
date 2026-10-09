# The anonymous probes in one call, one after another (9 October 2026)

The fifth part of item 12 of the architecture assessment of 8 October 2026 (BACKLOG, "From the architecture
assessment of 8 October 2026: the four costs worth paying down"). The anonymous probes, the questions `sv run` asks
the app as a stranger before anyone signs in, were each a container call of their own: `docker exec` into the
sidecar, one request, one answer, and the next call. The assessment put the cost at about three seconds a run and
suggested `probe_together`, which already hands several requests to the sidecar in one call.

**Not `probe_together` as it stands.** It starts every connection at the same moment, which is what a race check
needs and what these probes must not do: an app that falters under thirty connections at once would have been
reported as crashing, and its answers judged as though it had been asked one thing at a time. So there is a second
script beside it, `in_turn_script`. It takes the requests in one call, cut apart as `probe_together` cuts them, and
then sends them one after another, each waiting for its answer before the next starts. The answers are marked as
`probe_together` marks them, with a marker made fresh for each call, so an app cannot forge the next one's place. Each
answer goes straight out rather than to a file, so a large one cannot fill the sidecar's 16 MB memory folder and cut
the rest short. The two scripts share the cutting (`cut_and_pairs`).

**The waiting for a rate limiter is what it was.** `Http::send_in_turn` is a new way to the app that a run may offer;
`ask_anonymously_within` uses it when it is there, and keeps each answer up to the first one a rate limiter gave
(a 429, or a 503 with `Retry-After`). From that request on it asks one at a time as before: that answer is waited out
and the request asked again, and so is each after it. Without the cut, every later request in the one go would have
had a limiter's answer too, and each would have been waited out in turn. The requests after the first limited one
were also asked in the one go, which the limiter counts; it was already saying no. A way to the app that cannot ask in
one go (`None`, as every test fake answers) gets one at a time, unchanged.

**Measured with Docker**, on this computer, the real fence test that sends the fixed anonymous suite to the probe
fixture app (`the_probes_reach_the_app_through_the_fence_or_sv_says_it_was_not_assessed`), three runs each: 6.87, 6.50,
and 6.56 seconds before; 2.25, 2.42, and 2.10 after. About 4.3 seconds a run, more than the assessment's three, and
more again for a run whose `stackvet.toml` adds GraphQL, WebSocket, admin-page, and private-file questions.

How it is held:

- `crates/sv-check/src/signed_in/in_turn_tests.rs`: every question asked in one go and none alone; the same answers
  as one at a time, a question with no answer left out either way; from the first limited answer on, each asked alone
  and waited for, with the same waiting as one at a time; and an answer still limited after the wait left out as
  before.
- `requests_in_turn_reach_a_real_server_one_at_a_time_and_come_back_in_order` (`crates/sv-run/src/docker.rs`), with
  Docker: a Node server that takes 300 ms over each answer and says how many it was answering at once, asked through
  `ask_anonymously` over the run's own `DockerHttp`, counted. One call, none alone, five answers in order, and never two
  at once. Its first version slept a fixed two seconds for the server to start and once lost the first answer; it now
  waits until the server answers.
- `requests_in_turn_wait_for_each_answer_and_keep_none_in_a_file`: the script starts nothing in the background, waits
  for nothing after, prints the marker before each answer, and writes no answer to a file.

Four guards broken in turn, each caught:

- `ask_anonymously_within` ignoring the one go: two of the unit tests, and the Docker test on its count. The full
  fence test still passed, as it should: that is the one-at-a-time way, still there.
- A limiter's answer kept from the one go: two of the unit tests.
- The script's requests started in the background, all at once: the script test, the Docker test (two at once), and
  the full fence test.
- `DockerHttp` never asking in one go: the Docker test, on its count.

The fence test that checks containers cannot reach the internet fails on this computer whatever the change, at its
control step: this sandbox lets no container reach 1.1.1.1, so the open network it compares against is closed too.
The other eight fence tests pass with Docker here.
