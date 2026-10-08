# When the AI service fails (3 October 2026)

V16.5.2 asks that the app keeps working safely when something it depends on fails, and an app with an AI feature
depends on the AI service on every message. The test model now has a `FAIL` kind: it answers 500 with an error in
the service's own shape (OpenAI's `error` object, or Anthropic's `type: error`), whose message carries `SVERR` and
the tag, as a real outage would. Client libraries retry an outage, so the test model counts the attempts, and more
than one is the library at work.

The AI check sends one message the test model fails on, then a plain one. The failure has to reach the test model,
or it was not the service failing, and nothing is judged. `probe.ai-service-error-shown` (V16.5.1, only ever a
finding) is the app's answer carrying the service's error or a trace. `probe.ai-service-failure-handled` (V16.5.2)
is a finding when the plain message after it is not answered, and credited when the failing message was answered
without the error and the plain one after it was answered with its reply. A 429 on the plain message is a limiter
and says nothing, so it is not assessed. Not done: a service that answers slowly or not at all, which would hold
the run for as long as the app waits, and a malformed structured answer (C7.1.1).

**Later, 7 October 2026: a service that answers nothing.** The test model has a `HANG` kind: it takes the message
and writes nothing back, not even a status line, for 40 seconds (`HANG_SECONDS`), then closes the connection, as a
service that has stopped responding does. The run did not need a longer wait of its own: `sv` already gives up on
any request to the app after 15 seconds (the exchange script's `timeout 15`), so the held message tells the app
with a time limit of its own, shorter than that, from the rest. `probe.ai-service-hang-handled` (V16.5.2):

- **Credited** when the app answered the held message by itself within those 15 seconds, without a trace, and then
  answered a plain message with its reply.
- **A finding** when the plain message after it was not answered either: the feature stopped while its service did
  not answer, which is what an app with one worker and no time limit does.
- **Not assessed** when only the held message went unanswered. An app whose own limit is 30 seconds cannot be told
  from one with none, and the OpenAI and Anthropic libraries wait up to ten minutes unless told otherwise, so an
  accusation here would often be wrong.
- **A trace** in the app's answer to the held message is `probe.ai-service-error-shown`, as for a service that fails.

It is asked last of the AI questions, and when the app may still be waiting on the test model, the run waits until
the hold has ended (45 seconds from the held message, at most), so an app it held answers the checks after it. A
slow service that does answer in the end is not asked separately: to the person waiting, a reply after the app's
limit and no reply are the same.

Seven guards broken in turn, each caught: the wait for the hold, an unanswered held message credited or made a
finding, the plain message after it not judged, a trace ignored, the question never asked (four tests), and the test
model answering at once instead of holding (the test that runs the real script).
