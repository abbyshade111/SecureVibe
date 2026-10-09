# V14.2.1 in the api-keys brief (9 October 2026)


Backlog 0006, finding 22(f), a follow-up asked by the owner on 9 October 2026 ("I agree, go ahead and add it").

**The question.** The `api-keys` feature brief, built earlier the same day, named no requirement that speaks of API
keys themselves, and `public-api` brings none, since no applicability rule reads it. The owner asked whether one
should be cited.

**The answer.** ASVS 5.0 names API keys in two requirements. V14.2.1 (level 1): sensitive data, "such as an API key or
session token", travels only in the body or a header, never in the address or its query string. V13.2.1 (level 2)
names them only to rule them out between the app's own back-end parts, which is not about keys the app hands to other
programs. So the brief now names V14.2.1 among what the feature is held to. It already applies to every app, so the
brief adds it as the thing to get right, and `public-api` still brings no requirement of its own.

**What changed.** `data/feature-briefs.json`: `V14.2.1` in the `api-keys` brief's requirements. The brief's test
(`crates/sv-cli/src/brief/four_features_tests.rs`) holds it there; taking it out of the data failed that test.
Nothing is credited by a brief, so no count moves.
