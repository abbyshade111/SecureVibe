# `secrets-in-the-environment` makes an app refuse to start without a key `sv run` cannot give it

**Status:** done, as its markers read on 8 October 2026

Found on 6
October 2026 by session paper-facts, in the delivery test: a Haiku app given the prompt through the guidance
stopped with "SECRET_KEY environment variable must be set", as the prompt asks ("stop with a clear message if one is
missing"), and `sv run` gives an app none of its own keys, so it could not be tested. For a key the app makes for
itself, such as a session secret, the prompt could say to create a random one at first start and keep it in the
app's data folder, and stop only for keys from outside (an AI service's). A change to a shown prompt's text is a
new test of it.
**Done on 7 October 2026**, found by session securevibe-e2 when it came to claim this: the prompt library's revision
after the independent reviews (`f78f5ea`) changed the prompt to say this. A missing key for an outside service
starts the app with that feature off, and a missing session key is made at random when the app starts. The revised
text is tried again in `docs/prompts/library-trial/revision-protocol.md` (the `secrets-in-the-environment` arm), and
its status as shown stands only once that trial agrees.
