# Before each feature: `sv brief` and `securevibe_before` (5 October 2026)

Item 4 of "Decide before you build" (BACKLOG), in place of v1's template features. The plan speaks for the whole app;
a brief speaks for one feature about to be built, and gathers in one place what the plan and the guidance spread
over the app: `sv brief [PATH] --feature FEATURE`, and the MCP tool `securevibe_before`, which the server's
instructions now name after the plan and before the coding rules.

**The features** are in `data/feature-briefs.json`: sign-in, sign-in through another service, admin pages, uploads,
payments, email, an AI feature, and fetching a web address. Each names the conditions whose requirements it brings
(every requirement an applicability rule gates on one of them, through a new
`applicability::requirement_ids_gated_on`), the requirements it brings that no condition gates, its design-time
prompts, the coding-rule topics that bear on building it, and the table and key of each setting `sv run` needs. Two
features have no condition that gates them: `payments` gates no ASVS requirement at all (only SBD-DM-03), and admin
pages have none, since V8 always applies; each names its requirements itself (V2.3.4; V8.2.1, V8.2.2, V8.3.1), as
does fetching a web address (V1.3.6, V13.2.4, V15.3.2, the requirements the fetch check asks about). Tests hold every
id to the frameworks, every prompt to `design-prompts.json`, every topic to `coding-rules.json`, every table and key
to the starter `securevibe.toml`, and the tool's list of features to the file.

**A brief** is built from the same report as the plan, so the two cannot disagree. It has five parts:

1. **The requirements it brings that apply to the app now**, the report's own. A requirement gated on several
   conditions applies for any of them, so an app that sends email already has V12.3's encryption requirements before
   it has an AI feature, and the AI feature's brief shows them as applying. Then, when `securevibe.toml` does not say
   yet that the app has the feature, **the requirements that will apply once it does**: those gated on the feature's
   own conditions, within the app's level, that do not apply now, named with the conditions to answer. The first
   version showed only what applied, which for a feature not yet declared, the usual case before it is built, was
   almost nothing: a test of the Flask example, which has no AI feature, found the AI brief listing eight
   requirements that apply because the app sends email, and none of the AI feature's own.
2. **The design-time prompts**, in full, for the AI coding tool to work through with the person. Uploads and email
   have none written yet, and the brief says so.
3. **The coding rules that bear on it.** The coding rules cite AISVS Appendix C, how the AI coding tool works, never a
   requirement of the app, so no rule can be matched to a feature by what it cites; the first version tried, and every
   brief came out with none. A feature instead names the topics that bear on building it: `secrets` (keys, passwords,
   and people's data, uploads named among them) for sign-in, uploads, payments, email, and an AI feature. Admin pages
   and fetching a web address name none, and the brief points to `securevibe_guidance` for the rules for all the work.
4. **The tests to write**, the report's own, for the requirements that apply now; those for the pending ones come
   with them once they apply, and `sv plan` lists them.
5. **The settings `sv run` needs**, quoted from the starter `securevibe.toml`: each key's own line and the lines
   that go on explaining it, so a brief cannot drift from the spec.

It credits nothing (`creditsNothing` in the structured result), writes nothing, and never starts the app. A feature
the data file does not name is refused with the list of those it does, before any check is started.

Tested in `brief.rs` (the data file held to the frameworks, prompts, topics, and spec; settings quoted whole and only
from their own table; what a condition brings), through the MCP server (every result to its declared shape; the
brief's requirements and tests are the plan's and its own feature's; for the example's AI feature nothing pending is
in the plan, nothing is above its level, and its rules are the `secrets` topic's; an unknown feature refused before a
check given no time to run), and at the command line (`crates/sv-cli/tests/brief.rs`). Eleven guards broken in turn, each caught, by between one and
three tests: conditions bringing nothing, a feature's own list left out, every applying requirement shown, the pending
list repeating what applies, pending requirements above the app's level, every test shown, every coding-rule topic
shown, a setting quoted without its explanation, a setting found in any table, an unknown feature checked only after
the report, and the instructions not naming the tool.
