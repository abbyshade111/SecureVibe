# The test model speaks Gemini (9 October 2026)

The gap analysis of 7 October 2026, finding 13(g). `sv run` hands an app with an AI feature a test model of its own
instead of the real service, and the test model spoke OpenAI's and Anthropic's formats only. An app that called
Google's Gemini reached nothing, and every AI check came out "not assessed" for it.

**Where the app finds it.** The app is also given `GOOGLE_GEMINI_BASE_URL` (the test model's address) and
`GEMINI_API_KEY` and `GOOGLE_API_KEY` (the same placeholder key as the others). Google's own libraries, for Python
and for JavaScript, read all three; this was checked in their source, since Google's documentation names only the
key (ADR-019, Later).

**What it answers.** A POST whose address ends in `models/<model>:generateContent` or `:streamGenerateContent`, with
anything before it, so an address given through `ai.base-url-env`, which ends in `/v1`, works too. It reads the
instructions (`systemInstruction`), the person's turns (`contents`), a function's results (`functionResponse`), the
functions offered (`tools[].functionDeclarations`), whether the reply's length was limited
(`generationConfig.maxOutputTokens`), and the model named in the address. It answers with one candidate in Google's
shape, carrying the reply's tag in `responseId` as the others carry it in their ids. Streamed, it sends events when the
app asks for them (`alt=sse`, as Google's libraries do) and one JSON list otherwise. A function call is a
`functionCall` part, and an outage is Google's error shape (`{ error: { code, message, status } }`). Every probe the
other formats answer (LEAK, IMAGE, FETCH, FAIL, HANG, BADSHAPE, and the rest) works the same, since they were written
over the request read, not over its format.

**The shape asked for** (ADR-042, Later): JSON with a schema, JSON alone, or one function the model must call. Google's
schemas write types in capitals, so types are read in either case.

Held by `crates/sv-run/tests/model_provider_gemini.rs`, which runs the real script with Node: a message answered and
recorded (with the model from the address, the instructions, and the length limit), the `/v1`-prefixed address, a
path of Google's that is not a message refused, streaming both ways, each shape and its BADSHAPE, a function call and
its result, and an outage. Broken four ways, each caught by the test written for it: types read only in lower case,
the shape not read, a function's result not read, and the model not taken from the address. The variables given to
the app are held by `docker.rs`'s own test. The words that name the variables (the spec, the manifest's
documentation, and the AI checks' "never reached the test model" line) name the new one.

Not done: Vertex AI's addresses (`projects/.../locations/.../publishers/google/models/...`), which the same path match
answers, but whose variables (`GOOGLE_VERTEX_BASE_URL`, and Google Cloud's own sign-in) are not given.
