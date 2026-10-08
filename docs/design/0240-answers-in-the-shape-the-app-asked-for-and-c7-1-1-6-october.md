# Answers in the shape the app asked for, and C7.1.1 (6 October 2026)

An app can ask its AI service for an answer in a set shape:
- a JSON schema (OpenAI's `response_format` or the Responses API's `text.format`, Anthropic's structured outputs);
- plain JSON mode;
- a tool the model is made to call (`tool_choice`), which is how Instructor, the Vercel AI SDK, and LangChain get
  structured answers.

The test model `sv run` puts in place of the service answered all of these in plain text. An app that asked for a
shape cannot read that, so its AI questions failed for the test model's reason. And where the check reads a failure
as the app's own, it was a false finding: after the service failed, the plain message that followed came back with
no reply, and that is `probe.ai-service-failure-handled`'s finding.

**The test model answers in the shape asked for (ADR-042).** `shapeOf` in `assets/model-provider.mjs` reads it from
any of the three APIs, and `fit` builds the answer:
- with a JSON schema: JSON that fits it, with the reply's text in every text field, the first value of an enum, and
  a number of zero where the schema allows it (else the nearest it does: zod writes a whole number's minimum as
  -(2^53 - 1));
- in JSON mode: `{"reply": …}`;
- with a forced tool: a call to that tool, with arguments that fit its schema.

`$ref`s are followed, and `anyOf` takes its first branch that is not null. Every kind of message keeps its meaning:
LEAK's instructions and HIDDEN's characters are in the text fields as they were in the text.

**C7.1.1 (AISVS, level 1)** asks that the app checks every answer from the model against the shape it defined, and
refuses one that does not match. A new kind of message, `BADSHAPE`, answers in the wrong shape:
- every field the wrong type, each carrying `SVBAD<tag>` (text where text goes is put in a list, so an app that uses
  the field as it came shows the marker);
- one field the schema does not have;
- in JSON mode, text that is not JSON at all.

What was seen says which shape the app asked for, and how many times it asked, since a library that checks may ask
again.

`probe.ai-output-shape-unchecked` (C7.1.1):
- **A finding** when the marker is in the app's answer: it used what did not fit.
- **Credit** when the app answered without the marker and without failing, but only where it showed the test
  model's plain reply in the right shape. An app that never shows a reply says nothing by not showing this one.
- **Not assessed:**
  - when the app asked for no shape (an app reading plain text has no schema for this to hold it to);
  - when it crashed (a 5xx rejects the answer, but not by checking it);
  - when a limiter answered;
  - when the message never reached the test model.

The question is asked before the service is made to fail, so an app the failure leaves broken does not lose it.

Shown working with real client libraries, against the real test model under Node, outside `sv`:
- The OpenAI SDK's `parse` with a zod schema read the right shape, over chat completions (plain and streamed) and
  the Responses API, and refused the wrong one with zod's own error.
- The Anthropic SDK, with a forced tool, did the same, plain and streamed.
- An app that called `JSON.parse` and used the field as it came showed the marker.

Not run end to end with an app under `sv run`, which needs Docker. Pydantic was not tried.

Broken on purpose 17 ways, each caught.

In the check (each by the test of the wrong shape, and the fifth by three more):
- the marker never looked for;
- a crash credited;
- an app that hides replies credited;
- a limiter's answer credited;
- an app with no shape taken for one with a schema;
- a message that never arrived not said;
- the question never asked.

In the test model (each by the test that runs it under Node):
- the shape never read;
- an enum ignored;
- text not put in a list;
- no extra field;
- JSON mode's wrong shape written as valid JSON;
- a `$ref` not followed;
- a minimum not kept;
- a forced tool not answered;
- the shape not recorded;
- zod's minimum used as written.

Not done: a service that answers slowly or not at all.
