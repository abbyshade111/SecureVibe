# The AI service's failure in the app's own output (9 October 2026)


ASVS V16.3.4 asks that the app logs unexpected errors and security control failures (ADR-071). The AI checks already
make the test model fail one message on purpose, answering 500 with an error in the service's own shape whose message
carries `SVERR` and the message's tag, and after the run they read what the app wrote to its output. The failure
question now hands that tag on, as `LogMarkers.failure`, and the output is searched for `SVERR` with it.

`probe.ai-service-failure-logged` is credited in part when it is there: one service's failure, not every unexpected
error or security control failure. Its absence is said and never a finding, since an app that logs to a file or a
logging service writes nothing to its output. When the failure never reached the test model, that is said too. The
search is for this message's own tag, so another message's error, or the word `SVERR` alone, credits nothing. It is
asked first among the output checks, before any of them can return, whenever the AI checks ran.

Checked: the AI checks' tests, with a fake app that writes the service's error to its output, one that writes other
lines or nothing, another message's error, and a failure that never reached the model. Five guards broken one at a
time, each caught. Not run end to end against an app under `sv run`, which needs Docker.
