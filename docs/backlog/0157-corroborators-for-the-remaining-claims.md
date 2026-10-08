# Corroborators for the remaining claims

**Status:** done, as its markers read on 8 October 2026

`multiple-services` done on 25 September 2026: gRPC and its `.proto`
contracts, AsyncAPI documents, message-broker clients, microservice frameworks and service discovery,
in eight ecosystems and ten languages. A `docker-compose.yml` is deliberately not evidence — most
single apps ship one with only a database in it — and a test pins that. Left over from it: reading a
compose file for two or more services with their own `build:` would be the strongest evidence of all,
and needs the scanner to read YAML contents, which it does not. **Claimed on 27 September 2026 by session
securevibe-e8**, at the owner's asking ("continue to work off items in the backlog, your choice"),
as a narrow reading of the compose file rather than a YAML library. **Done the same day:** a `docker-compose.yml`,
`docker-compose.yaml`, `compose.yml`, or `compose.yaml` with two or more indented `build:` lines
answers `multiple-services`, naming the file; one build beside a database image still does not, and a
commented-out `build:` is not counted. Read as lines, so a service written on one line (`web: {build:
.}`) is missed, which only leaves the answer where it was. Allowing one build, never reading the file,
and counting a comment are each caught. Services that call each other over
plain HTTP stay invisible. Eleven of the twelve were written on 24 September 2026;
`shared-hostname` is recorded as uncheckable instead (`noCorroborator`), because it is a fact about
deployment that the repository does not hold. What is left is the weaker half of what was written:
`ai-history` and `multimodal-ai` lean almost entirely on source patterns, and `public-api` cannot see
a key checked by hand against a query parameter. Each is a data entry, not machinery.
**The weaker half claimed on 6 October 2026 by session securevibe-e9**, at the owner's word ("Please continue to
work off the backlog"), in branch `claude/securevibe-e9-corroborators`: libraries that can only mean each claim
(speech-to-text services for `multimodal-ai`, memory stores for `ai-history`, API documentation and key libraries for
`public-api`), and a key read from a query parameter, each with a witness.
**Done the same day** (DESIGN, "Libraries that can only mean a claim, and a key read from a query parameter"): 21
library entries and 22 ways of reading `?api_key=`, each answering its claim on its own, with controls for a model
client, a web framework, and a key read from the environment.
**A corroborator for `web-search`** (the answer added on 27 September 2026, which nothing reads from
the code yet): **claimed on 27 September 2026 by session securevibe-e8. Done the same day:** the
search services' libraries (Tavily, Exa, SerpApi, DuckDuckGo) and, in the code, `web_search` and
`web_fetch`, the tool types Anthropic's and OpenAI's APIs use, which is how the owner's app does it.
The pattern also matches an app's own function of that name; that error adds the four requirements
rather than removing any. Its witness is the owner's kind of call; dropping the entry, the
`web_search` pattern, or the witness each turns a test red.
