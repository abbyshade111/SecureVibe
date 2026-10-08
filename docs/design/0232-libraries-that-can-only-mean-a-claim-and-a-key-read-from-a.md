# Libraries that can only mean a claim, and a key read from a query parameter (6 October 2026)

The backlog's "Corroborators for the remaining claims" left three claims leaning almost entirely on patterns in the
source: `multimodal-ai`, `ai-history`, and `public-api`. Each now also has libraries that can only mean it
(`data/claim-corroborators.json`), and `public-api` has the gap the backlog named, a key read by hand from a query
parameter.

- **`multimodal-ai`:** speech-to-text services, beside the Whisper packages already listed: AssemblyAI, Deepgram, and
  Google Cloud Speech-to-Text, for Python and npm. An app that sends what a person said to a model takes audio.
- **`ai-history`:** memory stores whose only job is keeping a conversation: Mem0, Zep, and LangGraph's Postgres and
  SQLite checkpointers for JavaScript.
- **`public-api`:** API description libraries in the ecosystems that lacked them (`drf-yasg`, `connexion`,
  `flask-smorest`, `@fastify/swagger`, `express-openapi-validator`, `grape-swagger`, `nelmio/api-doc-bundle`, and
  springdoc's WebFlux starter), and `?api_key=` read the way each framework reads it: `request.args.get('api_key')`,
  `req.query.api_key`, `searchParams.get('api_key')`, Gin's `c.Query("api_key")`, `params[:api_key]`, and
  `$_GET['api_key']`.

Each is an answer of "yes", never "no": finding nothing still settles nothing, so a claim is never ruled out by these.
A library that is only a model client (`openai`) or a web framework (`flask`) is not listed, and neither is a bare
`api_key`, which every app that calls somebody else's API reads from its own environment.

How it is held:
- `the_weaker_claims_are_answered_by_libraries_that_can_only_mean_them` (`crates/sv-scan/tests/scan.rs`): each
  library, declared in the manifest an app would use, answers its claim on its own; an app with only `openai` and
  `flask` answers none of the three.
- `a_key_read_from_a_query_parameter_is_a_public_api`: each pattern on a line an app would write; reading
  `API_KEY` from the environment, in Python, JavaScript, and Go, is the control.

Each of the 43 new entries was taken out in turn, and each was caught. Adding `openai`, `flask`, a bare `api_key`, or
a Go `"api_key")` turned a control red.
