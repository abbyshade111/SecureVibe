# A feature brief before securevibe.toml (7 October 2026)

Found by session paper-facts in the delivery test of 6 October 2026: with the specification in the request, most
builders asked for a feature's brief (`securevibe_before`) before writing `securevibe.toml`, were told to write the file
and ask again, and few asked again. So the brief for the AI feature, which carries the AI-feature prompt shown to work,
reached 2 of 10 Sonnet builds and 3 of 10 Haiku builds.

Most of a brief does not depend on the app: what a feature can bring, the decisions to make first, the prompts shown to
work, the coding rules on its topics, and the settings `sv run` needs. Only which requirements apply, at the app's level,
and so which tests to write, need the file. Now, with no `securevibe.toml`, the brief (`securevibe_before`, and `sv brief`
at the command line) gives:

- **every requirement the feature can bring, at every level**, under a sentence saying that which of them apply, and at
  which level, cannot be said until the file is written, and to ask again then;
- the feature's design-time prompts, coding rules, and settings, exactly as an app with the file is given them;
- the coding prompts shown to work for any of those requirements: as many as an app with the file is given, or more,
  since no level narrows them;
- for the tests, that they wait for the file.

Its structured result carries `waiting: true` (and `false` in a brief built from a report), declared in the tool's
output schema. The heading says "no securevibe.toml yet". No report is built and no check started for it. A brief still
credits nothing.

**Tested** on every feature, against the same example app with its settings file and without it: everything the app
with the file is told applies, or will, is in the list; the decisions, rules, conditions, and settings are the same; and
the AI feature's brief carries `ai-feature-guard`. Also at the command line, on an empty folder. **Seven guards broken in
turn, each caught:** the server refusing without the file, the command doing so, only level-1 requirements listed, the
brief not marked as waiting, no prompts shown to work, the tests not said to wait, and `waiting` left out of the schema.

Whether more builders then get the prompt is for the next delivery trial to measure.
