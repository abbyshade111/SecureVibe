# OpenAI and Hugging Face keys, and fine-tuning through a vendor (28 September 2026)

Item 4 of the partial checks: two gaps in checks that already run.

**The credential rules had Anthropic's key and no other AI vendor's.** An OpenAI key or a Hugging
Face token in the code was found only when it happened to be assigned, in quotes, to a variable
whose name says "key" or "token", with enough entropy: the assignment rule. It is not found in
`.env.production` or any other env file (the assignment rule skips them on purpose, since holding
values is what they are for), in a shell `export` or a Dockerfile `ENV` line, or anywhere unquoted.
`secrets.openai-key` and `secrets.huggingface-token` now find them by shape, and because
`redact_text` runs every rule, they are also cut from the failing-test output a report quotes.

The shapes are gitleaks' `openai-api-key`, `huggingface-access-token`, and
`huggingface-organization-api-token` rules, read from gitleaks' published `config/gitleaks.toml` on
28 September 2026, not recalled. An OpenAI key is `sk-`, then `proj-`, `svcacct-`, or `admin-` and
58 or 74 characters, or 20 characters for the older keys, then the marker `T3BlbkFJ` (`OpenAI` in
base64), then the same again; a Hugging Face token is `hf_` or `api_org_` and 34 letters. Two
changes from gitleaks, both forced: `sv`'s regex crate has no lookaround, and a finding shows the
first four characters and the length of exactly what matched, so gitleaks' check of the character
after the key (which it consumes) is left out. For OpenAI's newer keys that means no word boundary
at the end either, since a key can end in `-` and a boundary after `-` fails before a quote or a
space; the fixed lengths and the marker make one unnecessary. The rules cite V13.3.1 and SBD-AC-05.
They do not cite C9.5.4, which the Anthropic rule does: C9.5.4 asks that an agent's credentials stay
out of the model's own context, and a key in a file says nothing about that. The Anthropic rule's
citation is a backlog entry of its own.

**The `training` corroborator knew the frameworks and not the vendors.** An app that fine-tunes a
model with one call to a vendor installs no torch or transformers, and its source matched none of
the signatures, so a manifest saying "no training" read as consistent with code that trains. The
Python, JavaScript, and TypeScript signatures now include each vendor's call as its own SDK or API
definition spells it, each read from that definition the same day: OpenAI's
`client.fine_tuning.jobs.create` (Python) and `client.fineTuning.jobs.create` (Node), from each
SDK's `api.md`, and the `/fine_tuning/jobs` endpoint for an app that calls it over plain HTTP;
Vertex AI's `sft.train`, which `vertexai/tuning/sft.py` exports; Google's genai `tunings.tune`; and
Amazon Bedrock's `CreateModelCustomizationJob` operation from botocore's service definition, which
boto3 calls `create_model_customization_job`, and its `/model-customization-jobs` endpoint. Nothing
found still proves nothing for this claim: an app that only asks a hosted model questions is left
"could not tell", and a test holds that.

**Broken on purpose eight ways.** Each rule's pattern disabled: three tests each (found by shape,
cut from output, one key one rule). OpenAI's marker made optional: two (the near misses, and one
key one rule, since a pattern without the marker also claims Anthropic's `sk-ant-` keys). A word
boundary added after OpenAI's key: three. Hugging Face organization tokens dropped: three. Hugging
Face's end boundary dropped: one, the near-miss test written for it (a token one letter too long).
The OpenAI Python call dropped from the signatures, and all the Python vendor calls dropped: two
each, the scan test and an end-to-end report in which a manifest that denies training is
contradicted by the code. The first pass had one test each for four of these; the one-key-one-rule
test and the end-to-end report were added for three of them, and the end boundary stays with the
test written for it. It also showed that renaming a rule's id is not
removing it, since its pattern still ran and the redaction test stayed green; the breaks above
disable the pattern itself.
